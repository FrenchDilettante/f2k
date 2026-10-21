//! The kernel's IDE disk: the primary master behind IRQ 14, and the block-read API the rest of the
//! kernel reads sectors through.
//!
//! The interrupt object claims the vector at the [`IDE`] level. Its service routine reads the
//! status register once (the acknowledgment), records it in the latch, and defers the completion
//! to a DPC; the DPC signals the completion event and the caller blocked on it wakes. A thread
//! blocks through the wait discipline; the boot context runs as the idle thread, which has nothing
//! to switch to, so it halts until the same event is signaled — the same interrupt, the same
//! deferred completion, no polling for the data.
//!
//! [`IDE`]: crate::interrupt::irql::IDE

#[cfg(target_arch = "x86")]
use super::channel::Channel;
use super::latch::Latch;
use crate::sched::dispatcher::Dispatcher;
use crate::sched::event::Event;

/// The priority increment a disk completion grants the thread it wakes.
pub const DISK_WAKE_INCREMENT: i8 = 1;

/// How long a caller waits for one interrupt before failing the read: 100 ticks, about one second
/// at the platform rate.
pub const COMPLETION_TIMEOUT_TICKS: u64 = 100;

/// The latch the service routine fills for the waiting caller.
pub static LATCH: Latch = Latch::new();

/// The deferred completion's body: signal the completion event, readying its waiter.
pub fn complete(event: &mut Event, dispatcher: &mut Dispatcher) {
    event.set(dispatcher, DISK_WAKE_INCREMENT);
}

#[cfg(target_arch = "x86")]
mod target {
    use core::ptr::addr_of_mut;
    use core::sync::atomic::{AtomicBool, Ordering};

    use super::*;
    use crate::block::lock::DeviceLock;
    use crate::block::{check_request, BlockDevice, BusType, DeviceInfo, DeviceKind};
    use crate::hw::ide::identify::{self, Identity};
    use crate::hw::ide::latch::Completion;
    use crate::hw::ide::read;
    use crate::hw::ide::regs::{PRIMARY_BASE, PRIMARY_CONTROL, PRIMARY_VECTOR, SECTOR_SIZE};
    use crate::hw::ide::write;
    use crate::hw::portio::Ports;
    use crate::interrupt::dpc::{self, Dpc};
    use crate::interrupt::irql;
    use crate::interrupt::InterruptObject;
    use crate::sched::event::EventKind;
    use crate::sched::wait::WaitReason;
    use crate::serial_println;
    use crate::status::NtStatus;

    static mut CHANNEL: Channel<Ports> = Channel::new(Ports, PRIMARY_BASE, PRIMARY_CONTROL);
    static mut OBJECT: InterruptObject = InterruptObject::zeroed();
    static mut DPC: Dpc = Dpc::new(completion_routine, 0);
    static mut EVENT: Event = Event::new(EventKind::Synchronization, false);
    /// The disk's LBA28 sector count; 0 until bring-up finds a usable disk.
    static mut CAPACITY: u32 = 0;
    /// The disk's identity, once brought up.
    static mut IDENTITY: Option<Identity> = None;
    /// A read is in progress: the driver has one request slot (the latch and the event).
    static IN_FLIGHT: AtomicBool = AtomicBool::new(false);

    /// The service routine: runs claimed at the IDE level. One status read acknowledges INTRQ; an
    /// armed wait's completion is deferred to the DPC.
    fn service(_object: &InterruptObject, _context: usize) -> bool {
        if LATCH.service(&mut Ports, PRIMARY_BASE) {
            // SAFETY: single CPU; the DPC is a static the queue links through, and the enqueue is
            // single-flight.
            unsafe { dpc::enqueue(&mut *addr_of_mut!(DPC), 0, 0) };
        }
        true
    }

    /// The DPC: signal the completion event (at the dispatch level, from the drain).
    fn completion_routine(_dpc: &Dpc, _context: usize, _argument1: usize, _argument2: usize) {
        // SAFETY: the drain runs DPCs serialized at the dispatch level, where the dispatcher's
        // state and the event are touched.
        unsafe { complete(&mut *addr_of_mut!(EVENT), crate::sched::idle::dispatcher()) };
    }

    /// The kernel's completion wait: block on the completion event, by thread wait or, in the boot
    /// context, by halting until it is signaled. A signal left over from an interrupt that landed
    /// after an earlier wait gave up is taken and ignored: only the latch's own armed interrupt
    /// completes the wait.
    struct EventWait;

    impl Completion<Ports> for EventWait {
        fn wait(&mut self, _io: &mut Ports, latch: &Latch) -> bool {
            let on_idle = crate::sched::idle::on_idle_thread();
            loop {
                let signaled = if on_idle {
                    halt_until_signaled()
                } else {
                    block_until_signaled()
                };
                if !signaled || latch.fired() {
                    return latch.fired();
                }
            }
        }
    }

    /// The idle thread's wait (the boot context, before any user thread exists): halt
    /// between interrupts until the event is signaled, then take the signal. Every interrupt wakes
    /// the halt (the tick bounds the wait).
    fn halt_until_signaled() -> bool {
        let deadline = crate::interrupt::clock::ticks() + COMPLETION_TIMEOUT_TICKS;
        let state = irql::state_mut();
        let enabled = state.interrupts_enabled();
        let signaled = loop {
            state.mask_interrupts();
            // SAFETY: interrupts are masked; nothing else touches the event now.
            let event = unsafe { &mut *addr_of_mut!(EVENT) };
            if event.signaled() {
                event.reset();
                break true;
            }
            if crate::interrupt::clock::ticks() >= deadline {
                break false;
            }
            // Enable and halt as one step: a completion landing after the check above still
            // wakes this halt.
            state.unmask_and_halt();
        };
        restore_interrupts(enabled);
        signaled
    }

    /// Put the interrupt flag back the way the wait found it.
    fn restore_interrupts(enabled: bool) {
        if enabled {
            irql::state_mut().unmask_interrupts();
        } else {
            irql::state_mut().mask_interrupts();
        }
    }

    /// A thread's wait: block on the event with the timeout (see [`wait_current`]).
    ///
    /// [`wait_current`]: crate::sched::wait::wait_current
    fn block_until_signaled() -> bool {
        let timeout =
            COMPLETION_TIMEOUT_TICKS as i64 * crate::interrupt::clock::INTERVAL_100NS as i64;
        // SAFETY: the event is a static, initialized at bring-up.
        let waitable = unsafe { (*addr_of_mut!(EVENT)).waitable() };
        let status =
            crate::sched::wait::wait_current(waitable, WaitReason::Executive, Some(timeout));
        status == crate::status::STATUS_SUCCESS
    }

    /// Bring the disk up: detect the primary master, connect its interrupt, IDENTIFY it, and record
    /// its sector count. Runs after the interrupt core, before the first user process; reports the
    /// outcome on COM1. A missing or unusable disk is a normal outcome (the kernel-path boot has
    /// none): reads then fail with no-such-device.
    pub fn init() {
        // SAFETY: boot context, before any read; sole access to the driver statics.
        unsafe {
            (*addr_of_mut!(EVENT)).init();
            let channel = &mut *addr_of_mut!(CHANNEL);
            if !channel.detect() {
                serial_println!("F2K: ide: no disk on the primary master");
                return;
            }
            // Acknowledge anything the firmware left asserted before the line is enabled.
            channel.status();
            let object = &mut *addr_of_mut!(OBJECT);
            crate::interrupt::initialize(
                object,
                service,
                0,
                PRIMARY_VECTOR,
                irql::IDE,
                irql::IDE,
                false,
                false,
            );
            assert!(
                crate::interrupt::connect(object),
                "connecting the IDE interrupt failed"
            );
            match identify::bring_up(channel, &LATCH, &mut EventWait) {
                Ok(identity) => {
                    *addr_of_mut!(IDENTITY) = Some(identity);
                    *addr_of_mut!(CAPACITY) = identity.sectors;
                    IDE_DISK.lock.init();
                    serial_println!(
                        "F2K: ide: primary master: LBA28, {} sectors",
                        identity.sectors
                    );
                }
                Err(absent) => {
                    serial_println!("F2K: ide: primary master unusable ({:?})", absent);
                }
            }
        }
    }

    /// Read `buffer.len() / 512` contiguous sectors starting at `lba` into `buffer`, blocking until
    /// the transfer completes. Returns an NT status: success, no-such-device (no usable disk),
    /// invalid-parameter (the run leaves the disk), I/O timeout, or device error. The buffer must
    /// hold whole sectors.
    #[must_use]
    pub fn read(lba: u32, buffer: &mut [u8]) -> NtStatus {
        assert!(
            !IN_FLIGHT.swap(true, Ordering::SeqCst),
            "overlapping disk reads: the driver has one request slot"
        );
        // SAFETY: single CPU; the in-flight flag makes this the only request touching the
        // channel, the latch, and the event.
        let status = unsafe {
            read::read(
                &mut *addr_of_mut!(CHANNEL),
                &LATCH,
                &mut EventWait,
                *addr_of_mut!(CAPACITY),
                lba,
                buffer,
            )
        };
        IN_FLIGHT.store(false, Ordering::SeqCst);
        status
    }

    /// Write `buffer.len() / 512` contiguous sectors starting at `lba` from `buffer`, blocking
    /// until the transfer completes (the read's statuses).
    #[must_use]
    pub fn write(lba: u32, buffer: &[u8]) -> NtStatus {
        assert!(
            !IN_FLIGHT.swap(true, Ordering::SeqCst),
            "overlapping disk requests: the driver has one request slot"
        );
        // SAFETY: as the read's.
        let status = unsafe {
            write::write(
                &mut *addr_of_mut!(CHANNEL),
                &LATCH,
                &mut EventWait,
                *addr_of_mut!(CAPACITY),
                lba,
                buffer,
            )
        };
        IN_FLIGHT.store(false, Ordering::SeqCst);
        status
    }

    /// The disk's identity, if bring-up found a usable disk.
    pub fn identity() -> Option<Identity> {
        // SAFETY: written once at bring-up.
        unsafe { *addr_of_mut!(IDENTITY) }
    }

    /// The disk as a block device. Its lock queues concurrent readers ahead of the driver's one
    /// request slot (whose assert stays as the backstop).
    pub struct IdeDisk {
        lock: DeviceLock,
    }

    static IDE_DISK: IdeDisk = IdeDisk {
        lock: DeviceLock::new(),
    };

    impl BlockDevice for IdeDisk {
        fn info(&self) -> DeviceInfo {
            DeviceInfo {
                kind: DeviceKind::Disk,
                bus: BusType::Ata,
                sector_size: SECTOR_SIZE as u32,
                // SAFETY: written once at bring-up.
                sectors: unsafe { *addr_of_mut!(CAPACITY) } as u64,
                removable: false,
                read_only: false,
            }
        }

        fn read(&self, lba: u64, buffer: &mut [u8]) -> NtStatus {
            if let Err(status) = check_request(&self.info(), lba, buffer) {
                return status;
            }
            // The run is on the disk, whose LBA28 capacity fits in 32 bits.
            self.lock.with(|| read(lba as u32, buffer))
        }

        fn write(&self, lba: u64, buffer: &[u8]) -> NtStatus {
            if let Err(status) = check_request(&self.info(), lba, buffer) {
                return status;
            }
            self.lock.with(|| write(lba as u32, buffer))
        }
    }

    /// The disk as a block device, if bring-up found a usable disk.
    pub fn block_device() -> Option<&'static dyn BlockDevice> {
        identity().map(|_| &IDE_DISK as &'static dyn BlockDevice)
    }
}

#[cfg(target_arch = "x86")]
#[allow(unused_imports)]
pub use target::{block_device, identity, init, read};

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
        use crate::interrupt::dpc::{Dpc, DpcQueue};
        use crate::interrupt::irql::{Irql, IrqlState, DISPATCH, IDE, PASSIVE};
        use crate::interrupt::{
            initialize,
            service_interrupt,
            Claim,
            Controller,
            InterruptObject,
            Outcome,
            VectorTable,
        };
        use crate::sched::dispatcher::Dispatcher;
        use crate::sched::event::{Event, EventKind};
        use crate::sched::process::SchedProcess;
        use crate::sched::thread::{Thread, ThreadState};
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

            fn end(&mut self, previous: Irql, _vector: u8) {
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
            queue: DpcQueue,
            dpc: Dpc,
            controller: *const Line,
            level_seen: Option<Irql>,
        }

        fn service(_object: &InterruptObject, context: usize) -> bool {
            // SAFETY: the context is the test's live harness.
            let harness = unsafe { &mut *(context as *mut Harness) };
            harness.level_seen = Some(unsafe { (*harness.controller).irql.current() });
            if harness.latch.service(&mut harness.sim, PRIMARY_BASE) {
                let mut irql = IrqlState::new();
                harness.queue.insert(&mut harness.dpc, 0, 0, &mut irql);
            }
            true
        }

        /// The completion DPC: its context word points at the event and dispatcher pair.
        fn completion(_dpc: &Dpc, context: usize, _argument1: usize, _argument2: usize) {
            // SAFETY: the context is the test's live pair.
            let (event, dispatcher) =
                unsafe { &mut *(context as *mut (&mut Event, &mut Dispatcher)) };
            super::complete(event, dispatcher);
        }

        // The scheduler side: a thread blocked on the completion event.
        let dispatcher = Box::leak(Box::new(Dispatcher::zeroed()));
        dispatcher.init();
        let process = Box::leak(Box::new(SchedProcess::new(0x0090_0000, 8)));
        process.init();
        let thread = Box::leak(Box::new(Thread::empty()));
        // SAFETY: both records are leaked at their final addresses.
        unsafe { thread.attach_to(process) };
        thread.state = ThreadState::Running;
        dispatcher.enter(thread as *mut Thread);
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
            queue: DpcQueue::zeroed(),
            dpc: Dpc::new(completion, &mut pair as *mut _ as usize),
            controller: &*line as *const Line,
            level_seen: None,
        });
        harness.queue.init(4, 0);
        harness.sim.out(PRIMARY_CONTROL, 0);
        harness.latch.arm();
        harness.sim.out(PRIMARY_BASE + COMMAND, IDENTIFY_DEVICE);
        assert!(harness.sim.line());

        // Connected at the IDE vector and level.
        let mut table = VectorTable::zeroed();
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
        let mut connect_irql = IrqlState::new();
        assert!(table.connect(object, &mut *line, &mut connect_irql));
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
        assert_eq!(harness.queue.depth(), 1, "the completion is deferred");
        assert!(!pair.0.signaled());
        assert_eq!(pair.1.current_thread(), thread as *mut Thread);

        // The drain at the dispatch level runs the DPC: the event is signaled into the waiter.
        let mut drain_irql = IrqlState::new();
        let previous = drain_irql.raise(DISPATCH);
        harness.queue.retire(&mut drain_irql);
        drain_irql.lower(previous);
        assert!(harness.queue.is_empty());
        let thread = unsafe { &*(pair.1.current_thread()) };
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
