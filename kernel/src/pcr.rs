//! The processor control region: the state that belongs to the processor rather than to a thread
//! or a subsystem (Windows 2000's KPCR and its KPRCB).
//!
//! It holds the interrupt-level ledger and the DPC queue. The ledger is what level tokens are
//! built on, so it cannot be a level cell itself: it is reached only through the operations here,
//! each of which masks interrupts before it touches the ledger. The DPC queue is a cell at the
//! high level, as Windows 2000 keeps its DPC list (interrupt service routines insert into it), with
//! its depth published for the readers that hold no token. The current, next and idle threads join
//! them when the dispatcher is split.
//!
//! The operations are the kernel's only way to change the interrupt flag outside the assembly
//! entries: raise and lower, the gates' entry and return, masking and unmasking, the idle halt and
//! the interrupt window, and the context switch's handover of the ledger ([`Pcr::capture`],
//! [`Pcr::restore`]). [`MaskGuard`] is the one form of "mask, then put the flag back as found".

use core::cell::UnsafeCell;
use core::marker::PhantomData;

use crate::interrupt::dpc::ProcessorQueue;
use crate::interrupt::irql::{Irql, IrqlState, LevelSnapshot};

/// One processor's control region.
pub struct Pcr {
    /// The level ledger. Private: every operation below masks interrupts before it reaches it.
    ledger: UnsafeCell<IrqlState>,
    /// The processor's deferred procedure calls (KPRCB's DpcListHead, DpcQueueDepth and their
    /// counters).
    pub dpc_queue: ProcessorQueue,
}

// SAFETY: one processor. The ledger is reached only through the operations below, which mask
// interrupts first and never hold the reference across an instruction that takes one, so no
// interrupt handler's operation can land inside another's; the DPC queue is `Sync` on its own
// terms (a level cell and an atomic).
unsafe impl Sync for Pcr {}

/// The boot processor's control region.
#[cfg(target_arch = "x86")]
static PCR: Pcr = Pcr::new(IrqlState::at_boot());

/// The processor's control region.
#[cfg(target_arch = "x86")]
#[inline]
pub fn pcr() -> &'static Pcr {
    &PCR
}

/// The processor's control region. On the host every test thread is a processor of its own,
/// starting at the passive level with interrupts enabled, so tests do not share a ledger.
#[cfg(not(target_arch = "x86"))]
pub fn pcr() -> &'static Pcr {
    std::thread_local! {
        static PCR: &'static Pcr =
            std::boxed::Box::leak(std::boxed::Box::new(Pcr::new(IrqlState::new())));
    }
    PCR.with(|pcr| *pcr)
}

impl Pcr {
    /// A control region whose ledger starts as `ledger`, with an empty DPC queue. The queue's
    /// request gate: a low-importance DPC is requested once four are queued.
    const fn new(ledger: IrqlState) -> Self {
        Pcr {
            ledger: UnsafeCell::new(ledger),
            dpc_queue: ProcessorQueue::new(4, 0),
        }
    }

    /// Read the ledger with interrupts masked, then put the flag back as it was found.
    #[inline]
    fn inspect<R>(&self, read: impl FnOnce(&IrqlState) -> R) -> R {
        let flags = mask_saving();
        // SAFETY: interrupts are masked, so no handler's ledger operation runs until the restore,
        // and the reference ends with `read`.
        let result = read(unsafe { &*self.ledger.get() });
        restore(flags);
        result
    }

    /// Change the ledger: interrupts masked first, then the transition, which leaves the flag as
    /// the level it reaches wants it (below the hardware floor, enabled).
    #[inline]
    fn change<R>(&self, transition: impl FnOnce(&mut IrqlState) -> R) -> R {
        mask_saving();
        // SAFETY: interrupts are masked until the transition itself sets the flag, its last step,
        // and the reference ends with `transition`.
        transition(unsafe { &mut *self.ledger.get() })
    }

    /// Change the ledger's record without touching the interrupt flag: masked for the change, then
    /// the flag put back as it was found.
    #[inline]
    fn update<R>(&self, change: impl FnOnce(&mut IrqlState) -> R) -> R {
        let flags = mask_saving();
        // SAFETY: as in `inspect`; the change leaves the flag alone, and the restore puts it back.
        let result = change(unsafe { &mut *self.ledger.get() });
        restore(flags);
        result
    }

    /// The current level.
    pub fn current(&self) -> Irql {
        self.inspect(IrqlState::current)
    }

    /// Whether the ledger has interrupts enabled.
    // Read by the performance trace and the host tests.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn interrupts_enabled(&self) -> bool {
        self.inspect(IrqlState::interrupts_enabled)
    }

    /// The transition audit (see [`IrqlState::audit`]).
    // Read by the interrupt diagnostics' audit and the host tests.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn audit(&self) -> Result<(), &'static str> {
        self.inspect(IrqlState::audit)
    }

    /// Raise to `level`, returning the previous level (see [`IrqlState::raise`]).
    pub fn raise(&self, level: Irql) -> Irql {
        self.change(|ledger| ledger.raise(level))
    }

    /// Raise to `level` if the processor is below it, returning the previous level; none, and
    /// nothing changed, if it is already at or above. The test and the raise are one masked step.
    pub fn raise_from_below(&self, level: Irql) -> Option<Irql> {
        let flags = mask_saving();
        // SAFETY: as in `inspect`; the raise, when it happens, sets the flag itself.
        let ledger = unsafe { &mut *self.ledger.get() };
        if ledger.current() >= level {
            restore(flags);
            return None;
        }
        Some(ledger.raise(level))
    }

    /// Lower back to `level` (see [`IrqlState::lower`]).
    pub fn lower(&self, level: Irql) {
        self.change(|ledger| ledger.lower(level));
    }

    /// End a hardware interrupt's claim (see [`IrqlState::end_claim`]).
    pub fn end_claim(&self, level: Irql, acknowledge: impl FnOnce()) {
        self.change(|ledger| ledger.end_claim(level, |_| acknowledge()));
    }

    /// Mask interrupts, the ledger recording it.
    pub fn mask_interrupts(&self) {
        self.change(IrqlState::mask_interrupts);
    }

    /// Unmask interrupts, the ledger recording it.
    pub fn unmask_interrupts(&self) {
        self.change(IrqlState::unmask_interrupts);
    }

    /// Mask interrupts until the guard is dropped, which puts the flag back as this found it: the
    /// one form of "mask, then restore as found".
    ///
    /// The ledger must agree with the processor's flag here (checked in debug builds): the drop
    /// puts back what the ledger says, and a ledger that disagreed would leave interrupts enabled
    /// where the code before the guard had them masked, or the reverse.
    pub fn mask_guard(&self) -> MaskGuard {
        let flags = mask_saving();
        // SAFETY: as in `change`: interrupts are masked from `mask_saving` on, and the mask below
        // keeps them so; the reference ends with this block.
        let enabled = unsafe {
            let ledger = &mut *self.ledger.get();
            let enabled = ledger.interrupts_enabled();
            #[cfg(target_arch = "x86")]
            debug_assert_eq!(
                enabled,
                flags & EFLAGS_IF != 0,
                "the level ledger disagrees with the interrupt flag"
            );
            ledger.mask_interrupts();
            enabled
        };
        let _ = flags;
        MaskGuard {
            enabled,
            _here: PhantomData,
        }
    }

    /// Enable interrupts and halt until the next one, as one step; the ledger records the enable
    /// first. The caller decided to halt with interrupts masked, and nothing may run between that
    /// decision and the halt.
    pub fn unmask_and_halt(&self) {
        self.update(|ledger| ledger.record_interrupts(true));
        halt_enabled();
    }

    /// Open a one-instruction interrupt window from masked code and close it again: an interrupt
    /// held pending meanwhile (a tick that fell inside a long service) is taken here, with every
    /// consequence an interrupt exit has; a quantum it ends may switch the processor away and
    /// back. The ledger records the window's enable before it and the mask after it.
    pub fn interrupt_window(&self) {
        self.update(|ledger| ledger.record_interrupts(true));
        interrupt_window();
        self.update(|ledger| ledger.record_interrupts(false));
    }

    /// A gate's entry: the gate masked interrupts, and the ledger is told (see
    /// [`IrqlState::enter_gate`]).
    pub fn enter_gate(&self) {
        self.change(IrqlState::enter_gate);
    }

    /// A gate's return: the ledger takes the flag the `iretd` puts back, without touching it (see
    /// [`IrqlState::leave_gate`]).
    pub fn leave_gate(&self, enabled: bool) {
        self.update(|ledger| ledger.leave_gate(enabled));
    }

    /// Capture the running thread's ledger: the switching-out half of a context switch (see
    /// [`IrqlState::capture`]).
    pub fn capture(&self) -> LevelSnapshot {
        self.inspect(IrqlState::capture)
    }

    /// Restore a resumed thread's ledger (see [`IrqlState::restore`]). The interrupt flag is the
    /// one the switch put back.
    pub fn restore(&self, snapshot: LevelSnapshot) {
        self.update(|ledger| ledger.restore(snapshot));
    }

    /// Write off a dying thread's outstanding raises (see [`IrqlState::write_off_thread`]).
    pub fn write_off_thread(&self) {
        self.update(IrqlState::write_off_thread);
    }

    /// A fresh thread adopts an empty ledger, interrupts enabled (see
    /// [`IrqlState::begin_thread`]).
    pub fn begin_thread(&self) {
        self.change(IrqlState::begin_thread);
    }
}

/// Interrupts masked from [`Pcr::mask_guard`] to the drop, which puts the flag back as the take
/// found it: enabled again if it was, masked if it was not. The code inside may open them and close
/// them again (a halt, a wait's switch away and back).
#[must_use = "the guard masks interrupts only until it is dropped"]
pub struct MaskGuard {
    /// Whether the ledger had interrupts enabled at the take.
    enabled: bool,
    /// Not `Send`: the flag it puts back is the one this thread's timeline found.
    _here: PhantomData<*mut ()>,
}

impl Drop for MaskGuard {
    fn drop(&mut self) {
        if self.enabled {
            pcr().unmask_interrupts();
        } else {
            pcr().mask_interrupts();
        }
    }
}

/// EFLAGS' interrupt flag.
#[cfg(target_arch = "x86")]
const EFLAGS_IF: u32 = 1 << 9;

/// Save the flags and mask interrupts: the first step of every ledger operation. Not `nomem`: the
/// ledger access must stay between this and the restore.
#[inline]
fn mask_saving() -> u32 {
    #[cfg(target_arch = "x86")]
    {
        let flags: u32;
        // SAFETY: `pushfd`, `pop` and `cli` are legal at CPL 0, where the kernel runs; masking only
        // defers interrupts, and the caller restores or replaces the flag.
        unsafe { core::arch::asm!("pushfd", "pop {}", "cli", out(reg) flags) };
        flags
    }
    #[cfg(not(target_arch = "x86"))]
    0
}

/// Put back the flags [`mask_saving`] found.
#[inline]
fn restore(flags: u32) {
    #[cfg(target_arch = "x86")]
    // SAFETY: restores exactly the EFLAGS `mask_saving` captured on this same execution, so the
    // interrupt flag returns to the state the ledger's model already describes.
    unsafe {
        core::arch::asm!("push {}", "popfd", in(reg) flags)
    };
    #[cfg(not(target_arch = "x86"))]
    let _ = flags;
}

/// Set the interrupt flag and halt until the next interrupt, as one pair: the interrupt shadow
/// after `sti` (interrupts are only taken after the next instruction) makes the `hlt` the first
/// interruptible point, so no interrupt is taken between the enable and the halt, which would
/// leave the processor sleeping a full tick after a wake it missed. Nothing on the host.
#[inline]
fn halt_enabled() {
    // SAFETY: `sti` and `hlt` are legal at CPL 0, where the kernel runs, and boot loads the IDT
    // before anything enables interrupts, so every vector the enable lets in has its gate; with
    // interrupts enabled the next one wakes the halt. Not `nomem`: the interrupt writes memory the
    // code after the halt reads, so this must be a compiler barrier.
    #[cfg(target_arch = "x86")]
    unsafe {
        core::arch::asm!("sti", "hlt", options(nostack, preserves_flags));
    }
}

/// Take any interrupt held pending through a one-instruction window, then mask again. The NOP is
/// the window: STI's shadow would hold the interrupt across a CLI right behind it. Nothing on the
/// host.
#[inline]
fn interrupt_window() {
    // SAFETY: the window runs the interrupt exit's own paths, which the caller's state must admit
    // (no dispatcher state half-updated, no ledger reference held: the caller records the enable
    // before and the mask after); the asm is a compiler barrier.
    #[cfg(target_arch = "x86")]
    unsafe {
        core::arch::asm!("sti", "nop", "cli", options(nostack));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interrupt::irql;

    /// The guard masks, and its drop puts the flag back the way the take found it: enabled from an
    /// enabled processor, masked from a masked one, whatever the inside did meanwhile.
    #[test]
    fn the_mask_guard_restores_the_flag_as_found() {
        let pcr = pcr();
        assert!(pcr.interrupts_enabled());
        {
            let _masked = pcr.mask_guard();
            assert!(!pcr.interrupts_enabled());
        }
        assert!(pcr.interrupts_enabled());

        pcr.mask_interrupts();
        {
            let _masked = pcr.mask_guard();
            // The inside opens them (a halt); the drop closes them again.
            pcr.unmask_interrupts();
        }
        assert!(!pcr.interrupts_enabled());
        pcr.unmask_interrupts();
        assert_eq!(pcr.audit(), Ok(()));
    }

    /// The idle halt and the interrupt window are recorded in the ledger: the halt leaves it
    /// enabled, the window closes again.
    #[test]
    fn the_halt_and_the_window_are_recorded() {
        let pcr = pcr();
        pcr.mask_interrupts();
        pcr.interrupt_window();
        assert!(!pcr.interrupts_enabled());
        pcr.unmask_and_halt();
        assert!(pcr.interrupts_enabled());
    }

    /// The switch's handover: a captured ledger restored puts back the level and its pending
    /// pairs, and a fresh thread starts from an empty one.
    #[test]
    fn the_ledger_hands_over_through_capture_and_restore() {
        let pcr = pcr();
        let previous = pcr.raise(irql::DISPATCH);
        let snapshot = pcr.capture();
        pcr.write_off_thread();
        pcr.begin_thread();
        assert_eq!(pcr.current(), irql::PASSIVE);
        pcr.restore(snapshot);
        assert_eq!(pcr.current(), irql::DISPATCH);
        pcr.lower(previous);
        assert_eq!(pcr.current(), irql::PASSIVE);
    }
}
