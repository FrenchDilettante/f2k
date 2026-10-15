//! The interrupt handoff: the latch the service routine fills for the waiting caller, and the
//! completion wait the caller blocks in.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU8, Ordering::SeqCst};

use super::regs::STATUS;
use crate::hw::portio::Io;

/// What the service routine hands the waiting caller: the status its acknowledging read saw, and
/// whether a wait was armed for it. One processor, but the routine runs between any two caller
/// instructions, so the fields are atomics.
pub struct Latch {
    armed: AtomicBool,
    status: AtomicU8,
    serviced: AtomicU32,
    unsolicited: AtomicU32,
}

impl Latch {
    pub const fn new() -> Self {
        Latch {
            armed: AtomicBool::new(false),
            status: AtomicU8::new(0),
            serviced: AtomicU32::new(0),
            unsolicited: AtomicU32::new(0),
        }
    }

    /// Expect the next interrupt. Armed before the write that can trigger it: the command write,
    /// or the drain whose last word starts the next sector.
    pub fn arm(&self) {
        self.status.store(0, SeqCst);
        self.armed.store(true, SeqCst);
    }

    /// Stop expecting it (a wait that gave up).
    pub fn disarm(&self) {
        self.armed.store(false, SeqCst);
    }

    /// Whether the armed interrupt has been serviced.
    pub fn fired(&self) -> bool {
        !self.armed.load(SeqCst)
    }

    /// The service routine's body: read the status register once, which acknowledges INTRQ, and
    /// record it for an armed wait. Returns whether a waiter is owed its completion (the routine
    /// defers it); an interrupt nobody armed for is acknowledged and counted, nothing more.
    pub fn service<IoT: Io>(&self, io: &mut IoT, base: u16) -> bool {
        let status = io.read(base + STATUS);
        if self.armed.swap(false, SeqCst) {
            self.status.store(status, SeqCst);
            self.serviced.fetch_add(1, SeqCst);
            true
        } else {
            self.unsolicited.fetch_add(1, SeqCst);
            false
        }
    }

    /// The status the last serviced interrupt acknowledged.
    pub fn status(&self) -> u8 {
        self.status.load(SeqCst)
    }

    /// Interrupts that completed an armed wait.
    pub fn serviced(&self) -> u32 {
        self.serviced.load(SeqCst)
    }

    /// Interrupts that arrived with nothing armed.
    pub fn unsolicited(&self) -> u32 {
        self.unsolicited.load(SeqCst)
    }
}

/// How a caller blocks until its armed interrupt has been serviced and the completion delivered.
/// The kernel blocks on the driver's completion event; the host tests deliver the simulated
/// channel's interrupt here, which is why the port access and the latch are passed in.
pub trait Completion<IoT: Io> {
    /// Block until the armed interrupt's completion arrives; false if it did not within the
    /// wait's bound.
    fn wait(&mut self, io: &mut IoT, latch: &Latch) -> bool;
}

#[cfg(test)]
mod tests {
    use super::super::regs::{COMMAND, DRQ, IDENTIFY_DEVICE, PRIMARY_BASE, PRIMARY_CONTROL};
    use super::super::sim::{SimChannel, DISK};
    use super::*;

    /// An interrupt with nothing armed is acknowledged and counted, and owes nobody a completion.
    #[test]
    fn an_unsolicited_interrupt_is_acknowledged_and_counted() {
        let mut sim = SimChannel::with_disk(DISK);
        sim.out(PRIMARY_CONTROL, 0);
        sim.out(PRIMARY_BASE + COMMAND, IDENTIFY_DEVICE);
        let latch = Latch::new();
        assert!(!latch.service(&mut sim, PRIMARY_BASE));
        assert!(!sim.line());
        assert_eq!((latch.serviced(), latch.unsolicited()), (0, 1));

        latch.arm();
        sim.out(PRIMARY_BASE + COMMAND, 0x00); // ignored: DRQ is set
        sim.intrq = true;
        assert!(latch.service(&mut sim, PRIMARY_BASE));
        assert!(latch.fired());
        assert_eq!(
            latch.status() & DRQ,
            DRQ,
            "the acknowledged status is recorded"
        );
    }
}
