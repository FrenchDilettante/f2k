//! The kernel's IDE disk: the primary master behind IRQ 14, and the block device the rest of the
//! kernel reads sectors through.
//!
//! The disk is one device extension: its interrupt object, the deferred completion, the completion
//! event, the latch, what IDENTIFY reported, and the channel under the lock that serializes
//! requests. The interrupt object claims the vector at the [`IDE`] level. Its service routine reads
//! the status register once (the acknowledgment), records it in the latch, and defers the
//! completion to a DPC; the DPC signals the completion event and the caller blocked on it wakes. A
//! thread blocks through the wait discipline; the boot context runs as the idle thread, which has
//! nothing to switch to, so it halts until the same event is signaled — the same interrupt, the
//! same deferred completion, no polling for the data.
//!
//! [`IDE`]: crate::interrupt::irql::IDE

#[cfg(target_arch = "x86")]
use super::channel::Channel;
#[cfg(test)]
use super::latch::Latch;
use crate::sched::dispatcher::Dispatcher;
use crate::sched::wait::WaitableId;

/// The priority increment a disk completion grants the thread it wakes.
pub const DISK_WAKE_INCREMENT: i8 = 1;

/// How long a caller waits for one interrupt before failing the read: 100 ticks, about one second
/// at the platform rate.
pub const COMPLETION_TIMEOUT_TICKS: u64 = 100;

/// The deferred completion's body: signal the completion event `event`, readying its waiter.
pub fn complete(event: WaitableId, dispatcher: &mut Dispatcher) {
    dispatcher.set_event(event, DISK_WAKE_INCREMENT);
}

#[cfg(target_arch = "x86")]
mod target {
    use core::cell::UnsafeCell;

    use super::*;
    use crate::block::lock::DeviceLock;
    use crate::block::{check_request, BlockDevice, BusType, DeviceInfo, DeviceKind};
    use crate::hw::ide::identify::{self, Identity};
    use crate::hw::ide::latch::{Completion, Latch};
    use crate::hw::ide::read;
    use crate::hw::ide::regs::{PRIMARY_BASE, PRIMARY_CONTROL, PRIMARY_VECTOR, SECTOR_SIZE};
    use crate::hw::ide::write;
    use crate::hw::portio::Ports;
    use crate::interrupt::dpc::{self, Dpc};
    use crate::interrupt::InterruptObject;
    use crate::level::{At, Dispatch, Ide};
    use crate::pcr::pcr;
    use crate::sched::event::{Event, EventKind};
    use crate::sched::wait::{WaitReason, Waitable};
    use crate::serial_println;
    use crate::status::{NtStatus, STATUS_SUCCESS};
    use crate::sync::InitOnce;

    /// The disk's device extension, as Windows 2000's disk driver keeps one per device: the
    /// interrupt object and the completion it defers, the completion event, the latch the service
    /// routine fills, what IDENTIFY reported, and the channel's registers under the lock that
    /// serializes requests.
    pub struct IdeExtension {
        /// The disk's interrupt: IRQ 14, served at the IDE level.
        interrupt: InterruptObject,
        /// The completion the service routine defers to the dispatch level.
        dpc: Dpc,
        /// The event the deferred completion signals and the caller waits on.
        event: CompletionEvent,
        /// The status the service routine acknowledged, for the waiting caller.
        latch: Latch,
        /// What IDENTIFY reported, set once at bring-up: none when no usable disk answered.
        identity: InitOnce<Option<Identity>>,
        /// The channel's registers, held by one request at a time, across its interrupt waits.
        channel: DeviceLock<Channel<Ports>>,
    }

    /// The primary master.
    static IDE: IdeExtension = IdeExtension {
        interrupt: InterruptObject::at_ide(service, 0, PRIMARY_VECTOR, false, false),
        dpc: Dpc::new(completion_routine, 0),
        event: CompletionEvent::new(),
        latch: Latch::new(),
        identity: InitOnce::new(),
        channel: DeviceLock::new(Channel::new(Ports, PRIMARY_BASE, PRIMARY_CONTROL)),
    };

    /// The service routine: runs claimed at the IDE level. One status read acknowledges INTRQ; an
    /// armed wait's completion is deferred to the DPC.
    fn service(ide: &mut At<Ide>, _context: usize) -> bool {
        if IDE.latch.service(&mut Ports, PRIMARY_BASE) {
            dpc::enqueue_at(ide, &IDE.dpc, 0, 0);
        }
        true
    }

    /// The DPC: signal the completion event (at the dispatch level, from the drain).
    fn completion_routine(
        dispatch: &mut At<Dispatch>,
        _: &Dpc,
        _context: usize,
        _: usize,
        _: usize,
    ) {
        IDE.event.signal(dispatch);
    }

    impl IdeExtension {
        /// Bring the disk up: name the event, then detect the primary master, connect its
        /// interrupt, IDENTIFY it, and record what it reported, or that there is no usable disk.
        fn init(&'static self) {
            self.event.init();
            self.channel.init();
            let identity = self.channel.with(|channel| self.bring_up(channel));
            self.identity.set(identity);
        }

        /// The bring-up proper, on the held channel; reports the outcome on COM1.
        fn bring_up(&'static self, channel: &mut Channel<Ports>) -> Option<Identity> {
            if !channel.detect() {
                serial_println!("F2K: ide: no disk on the primary master");
                return None;
            }
            // Acknowledge anything the firmware left asserted before the line is enabled.
            channel.status();
            assert!(
                crate::interrupt::connect(&self.interrupt),
                "connecting the IDE interrupt failed"
            );
            match identify::bring_up(channel, &self.latch, &mut EventWait(&self.event)) {
                Ok(identity) => {
                    serial_println!(
                        "F2K: ide: primary master: LBA28, {} sectors",
                        identity.sectors
                    );
                    Some(identity)
                }
                Err(absent) => {
                    serial_println!("F2K: ide: primary master unusable ({:?})", absent);
                    None
                }
            }
        }

        /// The disk's identity, if bring-up found a usable disk.
        fn identity(&self) -> Option<Identity> {
            *self.identity.get()
        }

        /// The disk's LBA28 sector count; 0 when there is no usable disk.
        fn capacity(&self) -> u32 {
            self.identity().map_or(0, |identity| identity.sectors)
        }
    }

    /// A transfer's status as a result: success, or the failure status itself.
    fn completed(status: NtStatus) -> Result<(), NtStatus> {
        if status.is_success() {
            Ok(())
        } else {
            Err(status)
        }
    }

    impl BlockDevice for IdeExtension {
        fn info(&self) -> DeviceInfo {
            DeviceInfo {
                kind: DeviceKind::Disk,
                bus: BusType::Ata,
                sector_size: SECTOR_SIZE as u32,
                sectors: self.capacity() as u64,
                removable: false,
                read_only: false,
            }
        }

        /// Read the run, holding the channel until the transfer completes. Fails with
        /// no-such-device (no usable disk), I/O timeout, or device error.
        fn read(&self, lba: u64, buffer: &mut [u8]) -> Result<(), NtStatus> {
            check_request(&self.info(), lba, buffer)?;
            // The run is on the disk, whose LBA28 capacity fits in 32 bits.
            completed(self.channel.with(|channel| {
                read::read(
                    channel,
                    &self.latch,
                    &mut EventWait(&self.event),
                    self.capacity(),
                    lba as u32,
                    buffer,
                )
            }))
        }

        /// Write the run, holding the channel until the transfer completes (the read's failures).
        fn write(&self, lba: u64, buffer: &[u8]) -> Result<(), NtStatus> {
            check_request(&self.info(), lba, buffer)?;
            completed(self.channel.with(|channel| {
                write::write(
                    channel,
                    &self.latch,
                    &mut EventWait(&self.event),
                    self.capacity(),
                    lba as u32,
                    buffer,
                )
            }))
        }
    }

    /// The completion event: a synchronization event embedded in the extension, as a device
    /// extension embeds a KEVENT, and named in the dispatcher database by its address
    /// ([`WaitableId::Embedded`]).
    struct CompletionEvent(UnsafeCell<Event>);

    // SAFETY: one processor. The event is reached only through `with`, which holds its reference
    // with interrupts masked and ends it before returning, so neither the deferred completion nor
    // the dispatcher (which reaches the header by its address, at the dispatch level or masked)
    // runs while one is alive. The extension is a static, so the address the event is named by
    // stays valid.
    unsafe impl Sync for CompletionEvent {}

    impl CompletionEvent {
        /// A clear event, named once it is in place ([`CompletionEvent::init`]).
        const fn new() -> Self {
            CompletionEvent(UnsafeCell::new(Event::new(
                EventKind::Synchronization,
                false,
            )))
        }

        /// Run `f` on the event with interrupts masked.
        fn with<R>(&self, f: impl FnOnce(&mut Event) -> R) -> R {
            let _masked = pcr().mask_guard();
            // SAFETY: see the `Sync` impl: interrupts stay masked until `_masked` drops, after
            // `f`, and the reference ends with `f`.
            f(unsafe { &mut *self.0.get() })
        }

        /// Name the event by its address; once, at bring-up, before the interrupt is connected.
        fn init(&self) {
            self.with(Event::init);
        }

        /// Signal the event from the deferred completion: its waiter is readied. No reference to
        /// the event is held while the dispatcher reaches its header.
        fn signal(&self, dispatch: &mut At<Dispatch>) {
            let id = self.with(|event| event.waitable.id());
            complete(id, crate::sched::DISPATCHER.get(dispatch));
        }

        /// Take a pending signal: whether the event was signaled, leaving it clear.
        fn take_signal(&self) -> bool {
            self.with(|event| event.reset() > 0)
        }

        /// The idle thread's wait (the boot context, before any user thread exists): halt between
        /// interrupts until the event is signaled, then take the signal. Every interrupt wakes the
        /// halt (the tick bounds the wait).
        fn halt_until_signaled(&self) -> bool {
            let deadline = crate::interrupt::clock::ticks() + COMPLETION_TIMEOUT_TICKS;
            let pcr = pcr();
            // Put back as found once the wait is over; each pass below masks for its test.
            let _masked = pcr.mask_guard();
            loop {
                pcr.mask_interrupts();
                if self.take_signal() {
                    return true;
                }
                if crate::interrupt::clock::ticks() >= deadline {
                    return false;
                }
                // Enable and halt as one step: a completion landing after the check above still
                // wakes this halt.
                pcr.unmask_and_halt();
            }
        }

        /// A thread's wait: block on the event with the timeout (see [`wait_current`]).
        ///
        /// [`wait_current`]: crate::sched::wait::wait_current
        fn block_until_signaled(&self) -> bool {
            let timeout =
                COMPLETION_TIMEOUT_TICKS as i64 * crate::interrupt::clock::INTERVAL_100NS as i64;
            let waitable: *mut Waitable = self.with(Event::waitable);
            let status =
                crate::sched::wait::wait_current(waitable, WaitReason::Executive, Some(timeout));
            status == STATUS_SUCCESS
        }
    }

    /// The kernel's completion wait: block on the completion event, by thread wait or, in the boot
    /// context, by halting until it is signaled. A signal left over from an interrupt that landed
    /// after an earlier wait gave up is taken and ignored: only the latch's own armed interrupt
    /// completes the wait.
    struct EventWait<'a>(&'a CompletionEvent);

    impl Completion<Ports> for EventWait<'_> {
        fn wait(&mut self, _io: &mut Ports, latch: &Latch) -> bool {
            let on_idle = crate::sched::idle::on_idle_thread();
            loop {
                let signaled = if on_idle {
                    self.0.halt_until_signaled()
                } else {
                    self.0.block_until_signaled()
                };
                if !signaled || latch.fired() {
                    return latch.fired();
                }
            }
        }
    }

    /// Bring the disk up: detect the primary master, connect its interrupt, IDENTIFY it, and record
    /// what it reported. Runs after the interrupt core, before the first user process; reports the
    /// outcome on COM1. A missing or unusable disk is a normal outcome (the kernel-path boot has
    /// none): there is then no disk block device.
    pub fn init() {
        IDE.init();
    }

    /// The disk as a block device, if bring-up found a usable disk.
    pub fn block_device() -> Option<&'static dyn BlockDevice> {
        IDE.identity().map(|_| &IDE as &'static dyn BlockDevice)
    }

    /// The disk's identity, if bring-up found a usable disk.
    #[cfg(feature = "disk-smoke")]
    pub fn identity() -> Option<Identity> {
        IDE.identity()
    }

    /// Interrupts that completed an armed wait.
    #[cfg(feature = "disk-smoke")]
    pub fn serviced() -> u32 {
        IDE.latch.serviced()
    }

    /// Interrupts the service routine acknowledged with no wait armed for them.
    #[cfg(any(feature = "nest-smoke", feature = "disk-smoke"))]
    pub fn unsolicited() -> u32 {
        IDE.latch.unsolicited()
    }

    /// The `nest-smoke` diagnostic's disk interrupt: CHECK POWER MODE, a command without data
    /// whose completion asserts the line with no wait armed for it — the service routine
    /// acknowledges it and counts it unsolicited ([`unsolicited`]).
    #[cfg(feature = "nest-smoke")]
    pub fn request_interrupt() {
        use crate::hw::ide::regs::{CHECK_POWER_MODE, COMMAND};
        use crate::hw::portio::Io;
        // Bring-up left the master selected and the interrupt enabled.
        IDE.channel
            .with(|channel| channel.io().out(PRIMARY_BASE + COMMAND, CHECK_POWER_MODE));
    }
}

/// IRQ 14's vector.
#[cfg(feature = "nest-smoke")]
pub const VECTOR: u8 = super::regs::PRIMARY_VECTOR;

#[cfg(all(target_arch = "x86", feature = "nest-smoke"))]
pub use target::request_interrupt;
#[cfg(all(
    target_arch = "x86",
    any(feature = "nest-smoke", feature = "disk-smoke")
))]
pub use target::unsolicited;
#[cfg(target_arch = "x86")]
pub use target::{block_device, init};
#[cfg(all(target_arch = "x86", feature = "disk-smoke"))]
pub use target::{identity, serviced};

#[cfg(test)]
mod tests {
    use super::super::regs::{
        COMMAND,
        IDENTIFY_DEVICE,
        PRIMARY_BASE,
        PRIMARY_CONTROL,
        PRIMARY_VECTOR,
    };
    use super::super::sim::{SimChannel, DISK};
    use super::*;
    use crate::hw::portio::Io;
    use crate::status::STATUS_SUCCESS;

    /// The interrupt path end to end on the host: the object connected at the IDE vector and
    /// level, the claim raising to that level, the service routine's single acknowledging status
    /// read, the completion deferred (not run) inside the interrupt, then the DPC's drain
    /// signaling the event — which readies the thread blocked on it with success.
    #[test]
    fn the_claim_defers_the_completion_and_the_dpc_wakes_the_waiter() {
        use crate::interrupt::dpc::{retire, Dpc, ProcessorQueue};
        use crate::interrupt::irql::{Irql, IrqlState, OldIrql, IDE, PASSIVE};
        use crate::interrupt::{
            initialize,
            service_interrupt,
            Claim,
            Controller,
            InterruptObject,
            Outcome,
            VectorTable,
        };
        use crate::level::{raised, At, Dispatch, High};
        use crate::sched::dispatcher::Dispatcher;
        use crate::sched::event::{Event, EventKind};
        use crate::sched::process::SchedProcess;
        use crate::sched::thread::ThreadState;
        use crate::sched::wait::{ClockStamp, WaitDisposition, WaitMode, WaitReason};

        /// A controller whose line is in service once the test acknowledges it.
        struct Line {
            irql: IrqlState,
            in_service: bool,
            ended: u32,
        }
        impl Controller for Line {
            fn claim(&mut self, _vector: u8, level: Irql) -> Claim {
                if self.in_service {
                    Claim::Accepted(self.irql.raise(level))
                } else {
                    Claim::Spurious
                }
            }

            fn end(&mut self, previous: OldIrql, _vector: u8) {
                self.irql.lower(previous);
                self.in_service = false;
                self.ended += 1;
            }

            fn enable(&mut self, _vector: u8) -> bool {
                true
            }

            fn disable(&mut self, _vector: u8) {}

            fn is_enabled(&mut self, _vector: u8) -> bool {
                true
            }

            fn in_service_clear(&mut self) -> bool {
                !self.in_service
            }
        }

        /// What the service routine reaches through its context word.
        struct Harness {
            sim: SimChannel,
            latch: Latch,
            queue: &'static ProcessorQueue,
            dpc: &'static Dpc,
            controller: *const Line,
            level_seen: Option<Irql>,
        }

        fn service(_object: &InterruptObject, context: usize) -> bool {
            // SAFETY: the context is the test's live harness.
            let harness = unsafe { &mut *(context as *mut Harness) };
            harness.level_seen = Some(unsafe { (*harness.controller).irql.current() });
            if harness.latch.service(&mut harness.sim, PRIMARY_BASE) {
                raised::<High, _>(|high| {
                    harness
                        .queue
                        .with(high, |queue| queue.insert(harness.dpc, 0, 0))
                });
            }
            true
        }

        /// The completion DPC: its context word points at the event and dispatcher pair.
        fn completion(_: &mut At<Dispatch>, _: &Dpc, context: usize, _: usize, _: usize) {
            // SAFETY: the context is the test's live pair.
            let (event, dispatcher) =
                unsafe { &mut *(context as *mut (&mut Event, &mut Dispatcher)) };
            super::complete(event.waitable.id(), dispatcher);
        }

        // The scheduler side: a thread blocked on the completion event.
        let dispatcher = crate::sched::testkit::dispatcher();
        let process = Box::leak(Box::new(SchedProcess::new(0x0090_0000, 8)));
        let mut thread = crate::sched::testkit::thread(process);
        thread.state = ThreadState::Running;
        dispatcher.enter(thread.id());
        let event = Box::leak(Box::new(Event::new(EventKind::Synchronization, false)));
        event.init();
        let stamp = ClockStamp {
            interrupt_time: 0,
            tick: 0,
        };
        assert_eq!(
            dispatcher.wait_single(
                thread,
                event.waitable(),
                WaitReason::Executive,
                WaitMode::Kernel,
                false,
                None,
                stamp
            ),
            WaitDisposition::Yield
        );
        assert_eq!(thread.state(), ThreadState::Waiting);

        // The device side: a command in flight, its data ready and INTRQ asserted.
        let mut line = Box::new(Line {
            irql: IrqlState::new(),
            in_service: false,
            ended: 0,
        });
        let mut pair: (&mut Event, &mut Dispatcher) = (event, dispatcher);
        let mut harness = Box::new(Harness {
            sim: SimChannel::with_disk(DISK),
            latch: Latch::new(),
            queue: Box::leak(Box::new(ProcessorQueue::new(4, 0))),
            dpc: Box::leak(Box::new(Dpc::new(completion, &mut pair as *mut _ as usize))),
            controller: &*line as *const Line,
            level_seen: None,
        });
        harness.sim.out(PRIMARY_CONTROL, 0);
        harness.latch.arm();
        harness.sim.out(PRIMARY_BASE + COMMAND, IDENTIFY_DEVICE);
        assert!(harness.sim.line());

        // Connected at the IDE vector and level.
        let table = VectorTable::zeroed();
        let object = Box::leak(Box::new(InterruptObject::zeroed()));
        initialize(
            object,
            service,
            &mut *harness as *mut Harness as usize,
            PRIMARY_VECTOR,
            IDE,
            IDE,
            false,
            false,
        );
        assert!(table.connect(object, &mut *line));
        assert_eq!(PRIMARY_VECTOR, 0x3E);

        // The interrupt: claimed, served at the IDE level, ended.
        line.in_service = true;
        let outcome = service_interrupt(&table, &mut *line, PRIMARY_VECTOR);
        assert!(matches!(outcome, Outcome::Served));
        assert_eq!(harness.level_seen, Some(IDE));
        assert_eq!((line.ended, line.irql.current()), (1, PASSIVE));
        assert!(
            !harness.sim.line(),
            "the service routine's status read acknowledged INTRQ"
        );
        assert_eq!(harness.latch.serviced(), 1);
        assert_eq!(
            raised::<High, _>(|high| harness.queue.with(high, |queue| queue.depth())),
            1,
            "the completion is deferred"
        );
        assert!(!pair.0.signaled());
        assert_eq!(pair.1.current(), Some(thread.id()));

        // The drain at the dispatch level runs the DPC: the event is signaled into the waiter.
        raised::<Dispatch, _>(|dispatch| retire(harness.queue, dispatch));
        assert!(raised::<High, _>(|high| harness
            .queue
            .with(high, |queue| queue.is_empty())));
        let thread = pair.1.thread(thread.id());
        assert_ne!(
            thread.state(),
            ThreadState::Waiting,
            "the blocked caller is readied"
        );
        assert_eq!(thread.wait_status(), STATUS_SUCCESS);
        assert!(
            !pair.0.signaled(),
            "the auto-reset signal went to the waiter"
        );
    }
}
