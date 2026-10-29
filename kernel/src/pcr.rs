//! The processor control region: the state that belongs to the processor rather than to a thread
//! or a subsystem (Windows 2000's KPCR and its KPRCB).
//!
//! It holds the interrupt-level ledger, the DPC queue, the processor's threads and its own tables
//! (the GDT, the task state segment and the IDT: [`ProcessorTables`]). The ledger is
//! what level tokens are built on, so it cannot be a level cell itself: it is reached only through
//! the operations here, each of which masks interrupts before it touches the ledger. The DPC queue
//! is a cell at the high level, as Windows 2000 keeps its DPC list (interrupt service routines
//! insert into it), with its depth published for the readers that hold no token. The processor's
//! threads — the current, next and idle threads, the running thread's quantum and the quantum-end
//! request — are the dispatcher's per-processor slots ([`ThreadSlots`]), which the clock interrupt
//! reaches without the dispatcher.
//!
//! A lower that crosses below the dispatch level runs what waited for it, as Windows 2000's
//! KeLowerIrql does through the DISPATCH software interrupt: the DPCs queued meanwhile, and a
//! dispatch decision requested meanwhile.
//!
//! The operations are the kernel's only way to change the interrupt flag outside the assembly
//! entries: raise and lower, the gates' entry and return, masking and unmasking, the idle halt and
//! the interrupt window. A context switch needs none of its own: it runs at the dispatch level, and
//! what each raise found stays on the stack of the thread that raised ([`OldIrql`]).
//! [`MaskGuard`] is the one form of "mask, then put the flag back as found".

use core::cell::UnsafeCell;
use core::marker::PhantomData;

use crate::cpu::ProcessorTables;
use crate::interrupt::dpc::ProcessorQueue;
use crate::interrupt::irql::{Irql, IrqlState, OldIrql, DISPATCH};
use crate::sched::processor::ThreadSlots;

/// One processor's control region.
pub struct Pcr {
    /// The level ledger. Private: every operation below masks interrupts before it reaches it.
    ledger: UnsafeCell<IrqlState>,
    /// The processor's deferred procedure calls (KPRCB's DpcListHead, DpcQueueDepth and their
    /// counters).
    pub dpc_queue: ProcessorQueue,
    /// The processor's threads (KPRCB's CurrentThread, NextThread, IdleThread and QuantumEnd), and
    /// the running thread's quantum.
    pub threads: ThreadSlots,
    /// The processor's GDT, task state segment and IDT (KPCR's GDT, TSS and IDT).
    pub tables: ProcessorTables,
}

// SAFETY: one processor. The ledger is reached only through the operations below, which mask
// interrupts first and never hold the reference across an instruction that takes one, so no
// interrupt handler's operation can land inside another's; the DPC queue, the thread slots and the
// processor's tables are `Sync` on their own terms (a level cell, atomics, and the tables' one
// build).
unsafe impl Sync for Pcr {}

/// The boot processor's control region. Named directly only by the context switch's assembly,
/// which addresses the processor's tables through it; Rust code reaches it through [`pcr`].
#[cfg(target_arch = "x86")]
pub(crate) static PCR: Pcr = Pcr::new(IrqlState::at_boot());

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
    /// A control region whose ledger starts as `ledger`, with an empty DPC queue, no threads, and
    /// its tables not built yet. The queue's request gate: a low-importance DPC is requested once
    /// four are queued.
    const fn new(ledger: IrqlState) -> Self {
        Pcr {
            ledger: UnsafeCell::new(ledger),
            dpc_queue: ProcessorQueue::new(4, 0),
            threads: ThreadSlots::new(),
            tables: ProcessorTables::new(),
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

    /// Raise to `level`, returning what the raise found (see [`IrqlState::raise`]).
    pub fn raise(&self, level: Irql) -> OldIrql {
        self.change(|ledger| ledger.raise(level))
    }

    /// Raise to `level` if the processor is below it, returning what the raise found; none, and
    /// nothing changed, if it is already at or above. The test and the raise are one masked step.
    pub fn raise_from_below(&self, level: Irql) -> Option<OldIrql> {
        let flags = mask_saving();
        // SAFETY: as in `inspect`; the raise, when it happens, sets the flag itself.
        let ledger = unsafe { &mut *self.ledger.get() };
        if ledger.current() >= level {
            restore(flags);
            return None;
        }
        Some(ledger.raise(level))
    }

    /// Lower back to what a raise found (see [`IrqlState::lower`]). A lower from the dispatch level
    /// or above to below it then runs the dispatch-level work that waited for it (see
    /// [`crate::sched::dispatcher::dispatch_on_lower`]): Windows 2000's KeLowerIrql, whose
    /// DISPATCH software interrupt fires as the level drops.
    pub fn lower(&self, to: OldIrql) {
        let crossed = self.change(|ledger| {
            let from = ledger.current();
            ledger.lower(to);
            from >= DISPATCH && to.level() < DISPATCH
        });
        if crossed {
            crate::sched::dispatcher::dispatch_on_lower();
        }
    }

    /// Lower back to what a raise found, without the dispatch-level work [`Pcr::lower`] runs: the
    /// lower of that work's own raise, which has just run it.
    pub(crate) fn lower_only(&self, to: OldIrql) {
        self.change(|ledger| ledger.lower(to));
    }

    /// End a hardware interrupt's claim (see [`IrqlState::end_claim`]).
    pub fn end_claim(&self, to: OldIrql, acknowledge: impl FnOnce()) {
        self.change(|ledger| ledger.end_claim(to, |_| acknowledge()));
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

    /// A raise from a masked context is paid back masked: what the raise found travels with the
    /// caller, and the lower puts it back.
    #[test]
    fn a_lower_puts_back_what_its_raise_found() {
        let pcr = pcr();
        pcr.mask_interrupts();
        let previous = pcr.raise(irql::DISPATCH);
        assert!(pcr.interrupts_enabled(), "the dispatch level runs enabled");
        assert_eq!(previous.level(), irql::PASSIVE);
        pcr.lower(previous);
        assert_eq!(pcr.current(), irql::PASSIVE);
        assert!(!pcr.interrupts_enabled());
        pcr.unmask_interrupts();
        assert_eq!(pcr.audit(), Ok(()));
    }
}
