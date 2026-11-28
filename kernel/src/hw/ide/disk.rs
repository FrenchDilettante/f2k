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
//! Where the controller has a bus master (a PCI IDE controller's BAR 4) and the drive does
//! multiword DMA, bring-up sets the drive's transfer mode, and every request whose buffer the
//! engine reaches moves by READ DMA / WRITE DMA: the buffer's physical runs ([`crate::mem::dma`]'s
//! scatter/gather over the page tables) written to a descriptor table in a common buffer, one
//! interrupt per command, as Windows 2000's atapi/pciidex do. A buffer the engine cannot reach (a
//! run above 4 GiB, an odd address, a user address) moves by PIO, as before.
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
    use core::sync::atomic::{fence, Ordering};

    use super::*;
    use crate::block::lock::DeviceLock;
    use crate::block::{check_request, BlockDevice, BusType, CacheFlush, DeviceInfo, DeviceKind};
    use crate::hal::Ports;
    use crate::hw::ide::busmaster::{descriptors, Descriptor};
    use crate::hw::ide::flush;
    use crate::hw::ide::identify::{self, Identity};
    use crate::hw::ide::latch::{Completion, Latch};
    use crate::hw::ide::read;
    use crate::hw::ide::regs::{
        MAX_SECTORS_PER_COMMAND,
        PRIMARY_BASE,
        PRIMARY_CONTROL,
        PRIMARY_VECTOR,
        SECTOR_SIZE,
        SET_TRANSFER_MODE,
    };
    use crate::hw::ide::taskfile::pack_lba28;
    use crate::hw::ide::write;
    use crate::interrupt::dpc::{self, Dpc};
    use crate::interrupt::InterruptObject;
    use crate::level::{At, Dispatch, Ide};
    use crate::mem::dma::{scatter_gather, CommonBuffer, PlatformBus, ScatterGatherElement};
    use crate::pcr::pcr;
    use crate::sched::event::{Event, EventKind};
    use crate::sched::wait::WaitReason;
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
        /// The channel's bus master, set once at bring-up: none when the controller has none, the
        /// drive does no DMA, or setting its mode failed.
        bus_master: InitOnce<Option<BusMaster>>,
        /// The channel's registers, held by one request at a time, across its interrupt waits.
        channel: DeviceLock<Channel<Ports>>,
    }

    /// The channel's bus master: its ports, and the common buffer holding its descriptor table.
    #[derive(Clone, Copy)]
    struct BusMaster {
        port: u16,
        table: CommonBuffer,
    }

    /// The descriptor table's common buffer: one page.
    const TABLE_BYTES: usize = 4096;

    /// The most descriptors one command's table holds: a 256-sector buffer spans at most 33
    /// pages, each run split at most once more at a 64 KiB boundary.
    const MAX_DESCRIPTORS: usize = 72;

    /// The bytes one DMA command moves at most: 256 sectors.
    const PER_COMMAND: usize = MAX_SECTORS_PER_COMMAND as usize * SECTOR_SIZE;

    /// One command's descriptor table, built before it is installed.
    #[derive(Clone, Copy)]
    struct Table {
        entries: [Descriptor; MAX_DESCRIPTORS],
        count: usize,
    }

    impl Table {
        const EMPTY: Table = Table {
            entries: [Descriptor {
                address: 0,
                count_and_end: 0,
            }; MAX_DESCRIPTORS],
            count: 0,
        };

        /// The table for the `len` bytes at kernel address `va`: its pages' physical runs; none
        /// when a page is not mapped or the engine cannot reach a run.
        fn of(va: u32, len: usize) -> Option<Table> {
            let mut elements = [ScatterGatherElement {
                address: 0,
                length: 0,
                reserved: 0,
            }; MAX_DESCRIPTORS / 2];
            let count = scatter_gather(&PlatformBus, va, len, &mut elements)?;
            let mut table = Table::EMPTY;
            table.count = descriptors(
                elements[..count]
                    .iter()
                    .map(|element| (element.address, element.length)),
                &mut table.entries,
            )?;
            Some(table)
        }

        /// Write the table into the bus master's common buffer, under the channel's lock (the
        /// engine reads it only inside a command, which runs under the lock).
        fn install(&self, bus_master: &BusMaster) {
            // SAFETY: the common buffer bring-up allocated for the bus master alone, TABLE_BYTES
            // long and mapped for the system's life; its one writer is this, under the channel's
            // lock, and the engine reads it only while a command runs under that same lock.
            let bytes = unsafe {
                core::slice::from_raw_parts_mut(bus_master.table.va as *mut u8, TABLE_BYTES)
            };
            for (index, entry) in self.entries[..self.count].iter().enumerate() {
                bytes[8 * index..8 * index + 8].copy_from_slice(&entry.bytes());
            }
            fence(Ordering::SeqCst);
        }
    }

    /// The PCI command register's bus-master enable (bit 2).
    const PCI_BUS_MASTER: u32 = 0x4;

    /// The primary master.
    static IDE: IdeExtension = IdeExtension {
        interrupt: InterruptObject::at_ide(service, 0, PRIMARY_VECTOR, false, false),
        dpc: Dpc::new(completion_routine, 0),
        event: CompletionEvent::new(),
        latch: Latch::new(),
        identity: InitOnce::new(),
        bus_master: InitOnce::new(),
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
            let bus_master = identity.and_then(|identity| {
                self.channel
                    .with(|channel| self.bring_up_dma(channel, &identity))
            });
            self.bus_master.set(bus_master);
        }

        /// The bus master, when the controller has one and the drive takes a DMA mode: the PCI
        /// IDE controller's BAR 4 (its primary channel's eight ports), its bus mastering enabled,
        /// a descriptor table in a common buffer, and the drive set to its fastest multiword DMA
        /// mode. Reported on COM1.
        fn bring_up_dma(
            &'static self,
            channel: &mut Channel<Ports>,
            identity: &Identity,
        ) -> Option<BusMaster> {
            use crate::hw::pci::{self, Bar, ConfigAddress, ConfigIo, PortsConfig};
            let mode = identity.dma_mode()?;
            // A PCI mass-storage IDE controller (class 01, subclass 01) whose programming
            // interface says it bus-masters (bit 7), its BAR 4 the bus master's ports.
            let controller = pci::devices().iter().find(|device| {
                device.class() == 0x01 && device.subclass() == 0x01 && device.class_code & 0x80 != 0
            })?;
            let Bar::Io(base) = controller.bars[4] else {
                return None;
            };
            let port = u16::try_from(base).ok()?;
            let table = crate::mem::dma::allocate(TABLE_BYTES as u32)?;
            let mut config = PortsConfig::new(Ports);
            let command = ConfigAddress::new(controller.bus, controller.dev, controller.func, 4);
            let value = config.read_config(command);
            config.write_config(command, value | PCI_BUS_MASTER);
            let set = channel.set_features(
                &self.latch,
                &mut EventWait(&self.event),
                SET_TRANSFER_MODE,
                mode,
            );
            if !set.is_success() {
                crate::klog!(
                    Debug,
                    "ide",
                    "ide: DMA mode {:#04x} refused, PIO only",
                    mode
                );
                crate::mem::dma::free(table.length, table.bus, table.va);
                return None;
            }
            crate::klog!(
                Debug,
                "ide",
                "ide: bus master at port {:#06x}, multiword DMA mode {}",
                port,
                mode & 0x07
            );
            Some(BusMaster { port, table })
        }

        /// The bus master, if bring-up set one up.
        fn bus_master(&self) -> Option<BusMaster> {
            *self.bus_master.get()
        }

        /// Move a run of one command's sectors (at most 256) by DMA, the descriptor table written
        /// from the buffer's physical runs first; none, nothing done, when the engine cannot reach
        /// the buffer (a user address, an unmapped page, a run above 4 GiB, an odd address): the
        /// caller moves it by PIO. Under the channel's lock.
        fn dma_command(
            &self,
            channel: &mut Channel<Ports>,
            bus_master: &BusMaster,
            lba: u32,
            buffer: *const u8,
            len: usize,
            to_memory: bool,
        ) -> Option<NtStatus> {
            let va = buffer as u32;
            if va < crate::mem::paging::KERNEL_BASE {
                return None;
            }
            let table = Table::of(va, len)?;
            table.install(bus_master);
            let status = channel.dma(
                &self.latch,
                &mut EventWait(&self.event),
                bus_master.port,
                bus_master.table.bus as u32,
                pack_lba28(lba, (len / SECTOR_SIZE) as u32),
                to_memory,
            );
            // The engine wrote the buffer behind the compiler's back.
            fence(Ordering::SeqCst);
            core::hint::black_box(buffer);
            Some(status)
        }

        /// The bring-up proper, on the held channel; reports the outcome on COM1.
        fn bring_up(&'static self, channel: &mut Channel<Ports>) -> Option<Identity> {
            if !channel.detect() {
                crate::klog!(Debug, "ide", "ide: no disk on the primary master");
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
                    crate::klog!(
                        Debug,
                        "ide",
                        "ide: primary master: LBA28, {} sectors",
                        identity.sectors
                    );
                    Some(identity)
                }
                Err(absent) => {
                    crate::klog!(Screen, "ide", "ide: primary master unusable ({:?})", absent);
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

        /// The sectors moved per interrupt: the multiple block bring-up set, else 1.
        fn block(&self) -> u8 {
            self.identity().map_or(1, |identity| identity.block)
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
            if let Some(bus_master) = self.bus_master() {
                return self.channel.with(|channel| {
                    for (index, run) in buffer.chunks_mut(PER_COMMAND).enumerate() {
                        let at = lba as u32 + (index * PER_COMMAND / SECTOR_SIZE) as u32;
                        let status = match self.dma_command(
                            channel,
                            &bus_master,
                            at,
                            run.as_ptr(),
                            run.len(),
                            true,
                        ) {
                            Some(status) => status,
                            None => read::read(
                                channel,
                                &self.latch,
                                &mut EventWait(&self.event),
                                self.capacity(),
                                self.block(),
                                at,
                                run,
                            ),
                        };
                        completed(status)?;
                    }
                    Ok(())
                });
            }
            // The run is on the disk, whose LBA28 capacity fits in 32 bits.
            completed(self.channel.with(|channel| {
                read::read(
                    channel,
                    &self.latch,
                    &mut EventWait(&self.event),
                    self.capacity(),
                    self.block(),
                    lba as u32,
                    buffer,
                )
            }))
        }

        /// Write the run, holding the channel until the transfer completes (the read's failures).
        fn write(&self, lba: u64, buffer: &[u8]) -> Result<(), NtStatus> {
            check_request(&self.info(), lba, buffer)?;
            if let Some(bus_master) = self.bus_master() {
                return self.channel.with(|channel| {
                    for (index, run) in buffer.chunks(PER_COMMAND).enumerate() {
                        let at = lba as u32 + (index * PER_COMMAND / SECTOR_SIZE) as u32;
                        let status = match self.dma_command(
                            channel,
                            &bus_master,
                            at,
                            run.as_ptr(),
                            run.len(),
                            false,
                        ) {
                            Some(status) => status,
                            None => write::write(
                                channel,
                                &self.latch,
                                &mut EventWait(&self.event),
                                self.capacity(),
                                self.block(),
                                at,
                                run,
                            ),
                        };
                        completed(status)?;
                    }
                    Ok(())
                });
            }
            completed(self.channel.with(|channel| {
                write::write(
                    channel,
                    &self.latch,
                    &mut EventWait(&self.event),
                    self.capacity(),
                    self.block(),
                    lba as u32,
                    buffer,
                )
            }))
        }

        /// Flush the drive's write cache by the command IDENTIFY named, holding the channel until
        /// the drive is done (the read's failures); nothing to do on a drive whose IDENTIFY names
        /// none.
        fn flush_cache(&self) -> Result<CacheFlush, NtStatus> {
            let Some(command) = self.identity().and_then(|identity| identity.flush) else {
                return Ok(CacheFlush::Unsupported);
            };
            completed(self.channel.with(|channel| {
                flush::flush(channel, &self.latch, &mut EventWait(&self.event), command)
            }))
            .map(|()| CacheFlush::Flushed)
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
        fn with<R>(&self, f: impl FnOnce(&Event) -> R) -> R {
            let _masked = pcr().mask_guard();
            // SAFETY: see the `Sync` impl: interrupts stay masked until `_masked` drops, after
            // `f`. The reference is shared, as every reference to an embedded header must be
            // while something may wait on it (see `Waitable`).
            f(unsafe { &*self.0.get() })
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

        /// A thread's wait: block on the event with the timeout (see [`wait_current_for`]).
        ///
        /// [`wait_current_for`]: crate::sched::wait::wait_current_for
        fn block_until_signaled(&self) -> bool {
            let timeout =
                COMPLETION_TIMEOUT_TICKS as i64 * crate::interrupt::clock::INTERVAL_100NS as i64;
            let event = self.with(|event| event.id());
            let status =
                crate::sched::wait::wait_current_for(event, WaitReason::Executive, Some(timeout));
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
        use crate::hal::Io;
        use crate::hw::ide::regs::{CHECK_POWER_MODE, COMMAND};
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
    use crate::hal::Io;
    use crate::status::STATUS_SUCCESS;

    /// The interrupt path end to end on the host: the object connected at the IDE vector and
    /// level, the claim raising to that level, the service routine's single acknowledging status
    /// read, the completion deferred (not run) inside the interrupt, then the DPC's drain
    /// signaling the event — which readies the thread blocked on it with success.
    #[test]
    fn the_claim_defers_the_completion_and_the_dpc_wakes_the_waiter() {
        use core::cell::Cell;

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

        /// A controller whose line is in service once the test acknowledges it. Its level is
        /// published in a cell of its own, for the service routine to read while the interrupt
        /// core holds the controller borrowed.
        struct Line {
            irql: IrqlState,
            level: &'static Cell<Irql>,
            in_service: bool,
            ended: u32,
        }
        impl Controller for Line {
            fn claim(&mut self, _vector: u8, level: Irql) -> Claim {
                if self.in_service {
                    let previous = self.irql.raise(level);
                    self.level.set(self.irql.current());
                    Claim::Accepted(previous)
                } else {
                    Claim::Spurious
                }
            }

            fn end(&mut self, previous: OldIrql, _vector: u8) {
                self.irql.lower(previous);
                self.level.set(self.irql.current());
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
            level: &'static Cell<Irql>,
            level_seen: Option<Irql>,
        }

        fn service(_object: &InterruptObject, context: usize) -> bool {
            // SAFETY: the context is the test's live harness.
            let harness = unsafe { &mut *(context as *mut Harness) };
            harness.level_seen = Some(harness.level.get());
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
            let (event, dispatcher) = unsafe { &mut *(context as *mut (&Event, &mut Dispatcher)) };
            super::complete(event.waitable.id(), dispatcher);
        }

        // The scheduler side: a thread blocked on the completion event.
        let mut dispatcher = crate::sched::testkit::dispatcher();
        let process = Box::leak(Box::new(SchedProcess::new(
            crate::mem::phys::PhysAddr::new(0x0090_0000),
            8,
        )));
        let mut thread = crate::sched::testkit::thread(process);
        thread.state = ThreadState::Running;
        dispatcher.enter(thread.id());
        // Shared from its naming on: the dispatcher reaches it through the name `init` made.
        let event = crate::sched::testkit::event(EventKind::Synchronization, false);
        let stamp = ClockStamp {
            interrupt_time: 0,
            tick: 0,
        };
        assert_eq!(
            dispatcher.wait_single(
                thread,
                event.id(),
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
        let level = Box::leak(Box::new(Cell::new(PASSIVE)));
        let mut line = Box::new(Line {
            irql: IrqlState::new(),
            level,
            in_service: false,
            ended: 0,
        });
        let mut pair: (&Event, &mut Dispatcher) = (event, &mut dispatcher);
        let mut harness = Box::new(Harness {
            sim: SimChannel::with_disk(DISK),
            latch: Latch::new(),
            queue: Box::leak(Box::new(ProcessorQueue::new(4, 0))),
            dpc: Box::leak(Box::new(Dpc::new(completion, &mut pair as *mut _ as usize))),
            level,
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
