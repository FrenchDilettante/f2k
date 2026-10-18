//! The interrupt request level: the kernel's ranking of "what kind of context is running".
//!
//! Levels 0-2 are the software levels (passive, APC, dispatch); 27-31 are the hardware levels
//! (profile, clock, inter-processor, power, high). A hardware interrupt claims its level on entry
//! and lowers back on exit, so the level is balanced at rest; nesting is safe because a second
//! interrupt at or below the current level is not accepted while the first is being served.
//!
//! The level slots live in one [`IrqlState`]: raise returns the previous level, lower restores it.
//! The same state carries the interrupt-flag discipline: transitions at or above the clock level
//! run with interrupts masked, transitions below it leave them enabled — the dispatch software
//! level must not block the tick, and the tick must block everything.

/// One interrupt request level. Ordered: a higher value preempts.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct Irql(pub u8);

/// Ordinary kernel code and user processes.
pub const PASSIVE: Irql = Irql(0);
/// Asynchronous procedure calls (thread-tied; reserved for later).
pub const APC: Irql = Irql(1);
/// Deferred procedure calls run at this level.
pub const DISPATCH: Irql = Irql(2);
/// The IDE disk interrupt (IRQ 14): a device level between dispatch and the hardware levels.
pub const IDE: Irql = Irql(13);
/// Profiling interrupts.
pub const PROFILE: Irql = Irql(27);
/// The interval clock interrupt.
pub const CLOCK: Irql = Irql(28);
/// Inter-processor interrupts.
pub const IPI: Irql = Irql(29);
/// Power-fail interrupts.
pub const POWER: Irql = Irql(30);
/// The synchronization level (one below IPI; same numeric value as the clock level on this
/// platform).
pub const SYNCH: Irql = Irql(28);
/// Everything masks below this.
pub const HIGH: Irql = Irql(31);

/// The lowest hardware level: at or above it, interrupts stay masked across transitions; below it
/// they run enabled.
pub const HARDWARE_FLOOR: Irql = CLOCK;

/// How deep raise/lower pairs may nest (a hardware claim, a deferred-work drain, a dispatcher lock:
/// a handful, bounded).
const NESTING: usize = 8;

/// One CPU's level slot and interrupt-flag discipline.
///
/// A raise/lower pair is a save/restore: raising masks interrupts, records the interrupted flag
/// state, and re-enables only below the hardware floor; lowering restores the recorded flag state —
/// a pair entered with interrupts masked leaves them masked, so code that runs inside a handler (a
/// deferred-work enqueue, for example) cannot accidentally re-enable the world.
pub struct IrqlState {
    current: u8,
    interrupts: bool,
    /// The interrupt-flag state captured at each raise.
    saved: [bool; NESTING],
    depth: usize,
    raises: u32,
    lowers: u32,
}

impl IrqlState {
    /// Fresh state: passive level, interrupts enabled, no transitions recorded.
    pub const fn new() -> Self {
        Self {
            current: 0,
            interrupts: true,
            saved: [false; NESTING],
            depth: 0,
            raises: 0,
            lowers: 0,
        }
    }

    /// The current level.
    pub fn current(&self) -> Irql {
        Irql(self.current)
    }

    /// Whether the interrupt flag is set in the model.
    pub fn interrupts_enabled(&self) -> bool {
        self.interrupts
    }

    /// Raise to `level`, returning the previous level. The interrupted flag state is captured
    /// first; interrupts are then masked for the transition and re-enabled only below the hardware
    /// floor.
    pub fn raise(&mut self, level: Irql) -> Irql {
        assert!(self.depth < NESTING, "interrupt level nesting overflow");
        self.saved[self.depth] = self.interrupts;
        self.depth += 1;
        self.mask_interrupts();
        let previous = self.current;
        self.current = level.0;
        if level < HARDWARE_FLOOR {
            self.unmask_interrupts();
        }
        self.raises = self.raises.wrapping_add(1);
        Irql(previous)
    }

    /// Lower back to `level`, restoring the interrupt-flag state the matching raise captured.
    /// Lowering above the entry level is a bug and is refused.
    pub fn lower(&mut self, level: Irql) {
        self.mask_interrupts();
        assert!(level.0 <= self.current, "lowering above the current level");
        assert!(self.depth > 0, "lower without a raise");
        self.depth -= 1;
        let restore = self.saved[self.depth];
        self.current = level.0;
        if restore {
            self.unmask_interrupts();
        }
        self.lowers = self.lowers.wrapping_add(1);
    }

    /// Set the interrupt flag. Not `nomem`, here or at the other flag changes: an interrupt
    /// writes memory the code after the enable (or before the mask) reads, so each must be a
    /// compiler barrier — an optimizing build otherwise hoists such a read out of a halt loop.
    pub fn unmask_interrupts(&mut self) {
        self.interrupts = true;
        #[cfg(target_arch = "x86")]
        unsafe {
            core::arch::asm!("sti", options(nostack, preserves_flags));
        }
    }

    /// Set the interrupt flag and halt until the next interrupt, as one pair: the interrupt
    /// shadow after `sti` (interrupts are only taken after the next instruction) makes the `hlt`
    /// the first interruptible point, so no interrupt can be taken between the enable and the
    /// halt — and then leave the processor sleeping a full tick after a wake it missed.
    #[cfg(target_arch = "x86")]
    pub fn unmask_and_halt(&mut self) {
        self.interrupts = true;
        unsafe {
            core::arch::asm!("sti", "hlt", options(nostack, preserves_flags));
        }
    }

    /// Clear the interrupt flag.
    pub fn mask_interrupts(&mut self) {
        self.interrupts = false;
        #[cfg(target_arch = "x86")]
        unsafe {
            core::arch::asm!("cli", options(nostack, preserves_flags));
        }
    }
}

/// A thread's level ledger: the state the raise/lower pairs of one continuous execution are
/// recorded against. Pairs belong to the thread whose stack their lowering code lives on, so a
/// context switch captures and restores the ledger per thread.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct LevelSnapshot {
    /// The level the thread was running at.
    current: u8,
    /// The interrupt-flag state the model carried.
    interrupts: bool,
    /// The unbalanced raises whose lowering code is on this thread's stack.
    depth: usize,
    /// The flag state each of those raises captured.
    saved: [bool; NESTING],
}

impl LevelSnapshot {
    /// An empty ledger: passive, interrupts enabled, no pending pairs. A thread record's initial
    /// value; a fresh thread's first instructions adopt exactly this.
    pub const fn empty() -> Self {
        LevelSnapshot {
            current: 0,
            interrupts: true,
            depth: 0,
            saved: [false; NESTING],
        }
    }
}

impl IrqlState {
    /// The transition audit: every raise has been paid back by a lower, and the level is back where
    /// it started.
    pub fn audit(&self) -> Result<(), &'static str> {
        if self.raises != self.lowers {
            return Err("interrupt level transitions unbalanced");
        }
        if self.current != 0 {
            return Err("interrupt level stuck above passive");
        }
        Ok(())
    }

    /// Capture the level ledger (the context switch's switching-out half). Read-only: the CPU state
    /// itself is untouched.
    pub fn capture(&self) -> LevelSnapshot {
        LevelSnapshot {
            current: self.current,
            interrupts: self.interrupts,
            depth: self.depth,
            saved: self.saved,
        }
    }

    /// Restore a captured ledger (the resumed thread's half). The real interrupt flag is not
    /// touched (the switch's popfd restored it); the counters are not touched either — the recorded
    /// pairs still balance on this thread's stack.
    pub fn restore(&mut self, snapshot: LevelSnapshot) {
        assert!(snapshot.depth <= NESTING, "corrupt level snapshot");
        self.current = snapshot.current;
        self.interrupts = snapshot.interrupts;
        self.depth = snapshot.depth;
        self.saved = snapshot.saved;
    }

    /// A dying thread's last switch: its outstanding raises are never lowered — the thread's stack
    /// is abandoned with their lowering code on it — so they are counted as paid, keeping the
    /// transition audit balanced across thread exits. The ledger itself is the next thread's to
    /// replace.
    pub fn write_off_thread(&mut self) {
        self.lowers = self.lowers.wrapping_add(self.depth as u32);
    }

    /// A fresh thread's first instructions adopt an empty ledger: passive, no pending pairs,
    /// interrupts enabled. The previous thread's pending pairs live on its own stack and ledger.
    pub fn begin_thread(&mut self) {
        self.current = 0;
        self.interrupts = true;
        self.depth = 0;
        self.saved = [false; NESTING];
        self.unmask_interrupts();
    }
}

// --- The kernel's level state (target) -------------------------------------

/// The one level state (single processor).
#[cfg(target_arch = "x86")]
static mut STATE: IrqlState = IrqlState::new();

/// The kernel's level state. Mutating it performs the real interrupt-flag transitions.
///
/// # Safety (target)
///
/// Single CPU; access is serialized by the level discipline and the interrupt gates.
#[cfg(target_arch = "x86")]
pub fn state_mut() -> &'static mut IrqlState {
    // SAFETY: single CPU; every caller runs serialized.
    unsafe { &mut *core::ptr::addr_of_mut!(STATE) }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The level ordering table: the software levels, the hardware levels, and the aliases — the
    /// clock level sits above the dispatch level, so a tick never runs a deferred routine on top of
    /// itself.
    #[test]
    fn level_ordering_matches_the_platform() {
        assert_eq!(PASSIVE, Irql(0));
        assert_eq!(APC, Irql(1));
        assert_eq!(DISPATCH, Irql(2));
        assert_eq!(PROFILE, Irql(27));
        assert_eq!(CLOCK, Irql(28));
        assert_eq!(IPI, Irql(29));
        assert_eq!(POWER, Irql(30));
        assert_eq!(HIGH, Irql(31));
        assert_eq!(SYNCH, Irql(28));
        assert!(CLOCK > DISPATCH);
        assert_eq!(IDE, Irql(13));
        assert!(IDE > DISPATCH && IDE < PROFILE, "a device level");
        assert!(HIGH > POWER);
        assert!(PASSIVE < APC && APC < DISPATCH);
    }

    /// A raise/lower pair is balanced: the sequence raise(X) then lower(previous) leaves the level
    /// (and the audit) unchanged, for every X above the entry level.
    #[test]
    fn raise_lower_pairs_are_balanced() {
        for x in [APC, DISPATCH, PROFILE, CLOCK, IPI, POWER, HIGH] {
            let mut irql = IrqlState::new();
            let old = irql.raise(x);
            assert_eq!(old, PASSIVE);
            assert_eq!(irql.current(), x);
            irql.lower(old);
            assert_eq!(irql.current(), PASSIVE);
            assert_eq!(irql.audit(), Ok(()));
        }
    }

    /// Nested claims stack: raising from an already-raised level returns the intermediate level,
    /// and lowering unwinds it.
    #[test]
    fn nested_claims_stack_and_unwind() {
        let mut irql = IrqlState::new();
        let first = irql.raise(DISPATCH);
        let second = irql.raise(CLOCK);
        assert_eq!(first, PASSIVE);
        assert_eq!(second, DISPATCH);
        assert_eq!(irql.current(), CLOCK);
        irql.lower(second);
        assert_eq!(irql.current(), DISPATCH);
        irql.lower(first);
        assert_eq!(irql.current(), PASSIVE);
        assert_eq!(irql.audit(), Ok(()));
    }

    /// Interrupt-flag discipline: transitions at or above the clock level keep interrupts masked;
    /// below it they run enabled. A pair entered with interrupts masked (inside a handler, say)
    /// leaves them masked — the restore is what the pair promised.
    #[test]
    fn hardware_levels_mask_software_levels_enable() {
        let mut irql = IrqlState::new();
        assert!(irql.interrupts_enabled());

        irql.raise(CLOCK);
        assert!(!irql.interrupts_enabled(), "the tick must run masked");

        irql.lower(DISPATCH);
        assert!(
            irql.interrupts_enabled(),
            "dispatch must not block the tick"
        );

        irql.raise(HIGH);
        assert!(!irql.interrupts_enabled());

        irql.lower(PASSIVE);
        assert!(irql.interrupts_enabled());
        assert_eq!(irql.audit(), Ok(()));
    }

    /// A raise/lower pair entered with interrupts masked leaves them masked: code that runs inside
    /// a handler cannot accidentally re-enable the world on its way out.
    #[test]
    fn a_pair_entered_masked_leaves_masked() {
        let mut irql = IrqlState::new();
        irql.mask_interrupts();
        // A software-level pair inside a masked context: still masked coming out, whatever the
        // level.
        let inner = irql.raise(DISPATCH);
        irql.lower(inner);
        assert!(!irql.interrupts_enabled());
        // A hardware-level pair likewise.
        let outer = irql.raise(HIGH);
        irql.lower(outer);
        assert!(!irql.interrupts_enabled());
        assert_eq!(irql.current(), PASSIVE);
        assert_eq!(irql.audit(), Ok(()));
    }

    /// Lowering above the current level is a bug: the state refuses, so a mispaired exit cannot
    /// silently corrupt the stack of levels.
    #[test]
    fn lowering_above_current_is_refused() {
        let mut irql = IrqlState::new();
        irql.raise(DISPATCH);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            irql.raise(PASSIVE); // still at DISPATCH
            irql.lower(CLOCK); // above current: must refuse
        }));
        assert!(result.is_err());
    }

    /// An unbalanced audit is detectable: a raise without its lower leaves the level stuck and the
    /// audit failing.
    #[test]
    fn unbalanced_transitions_fail_the_audit() {
        let mut irql = IrqlState::new();
        irql.raise(DISPATCH);
        assert_eq!(irql.audit(), Err("interrupt level transitions unbalanced"));
        // Restore balance so the guard does not leak into other tests.
        irql.lower(PASSIVE);
        assert_eq!(irql.audit(), Ok(()));
    }

    /// A dying thread's write-off: its outstanding raises are never lowered, and the audit still
    /// balances once the next thread's pairs are paid.
    #[test]
    fn a_dying_threads_raises_are_written_off() {
        let mut cpu = IrqlState::new();
        let resumed = cpu.raise(DISPATCH);
        let ledger = cpu.capture();

        // The dying thread: a raise left outstanding (a service's), then the exit's own.
        cpu.begin_thread();
        cpu.raise(APC);
        cpu.raise(DISPATCH);
        cpu.write_off_thread();
        assert_eq!(cpu.audit(), Err("interrupt level transitions unbalanced"));

        // The resumed thread pays its own pair.
        cpu.restore(ledger);
        cpu.lower(resumed);
        assert_eq!(cpu.audit(), Ok(()));
    }

    /// The ledger handover: one state plays the CPU, the timelines interleave on it, and every
    /// raised pair is paid back on its owning thread's ledger.
    #[test]
    fn capture_and_restore_hand_the_ledger_over() {
        let mut cpu = IrqlState::new();

        // Thread A raises two pairs, captures its ledger, and is switched away from mid-raise.
        let a_inner = cpu.raise(DISPATCH);
        let a_outer = cpu.raise(CLOCK);
        let ledger_a = cpu.capture();
        assert_eq!(ledger_a.depth, 2);

        // A fresh thread takes the processor: it adopts an empty ledger, raises one pair, and
        // switches out mid-raise.
        cpu.begin_thread();
        let b_inner = cpu.raise(CLOCK);
        let ledger_b = cpu.capture();
        assert_eq!(ledger_b.depth, 1);

        // Thread B resumes: its ledger replaces the CPU's (the real interrupt flag came back with
        // the switch's popfd), and its pending pair completes against its own ledger.
        cpu.restore(ledger_b);
        assert_eq!(cpu.current(), CLOCK);
        cpu.lower(b_inner);
        assert_eq!(cpu.current(), PASSIVE);

        // Later thread A resumes and completes its own pair.
        cpu.restore(ledger_a);
        cpu.lower(a_outer);
        cpu.lower(a_inner);
        assert_eq!(cpu.current(), PASSIVE);
        assert_eq!(cpu.audit(), Ok(()));
    }

    /// A fresh thread adopts an empty ledger: passive, no pending pairs, interrupts enabled —
    /// whatever the previous thread had pending is voided for it (the pending pairs live on that
    /// thread's stack and its own ledger).
    #[test]
    fn a_fresh_thread_begins_with_an_empty_ledger() {
        let mut irql = IrqlState::new();
        irql.raise(DISPATCH);
        irql.raise(HIGH);
        assert!(!irql.interrupts_enabled());

        irql.begin_thread();
        assert_eq!(irql.current(), PASSIVE);
        assert_eq!(irql.depth, 0);
        assert!(irql.interrupts_enabled());

        // Its first raise/lower pair works against the fresh ledger. The audit stays unbalanced:
        // the two voided raises are still owed on the previous thread's stack — they balance when
        // it resumes, not here.
        let inner = irql.raise(DISPATCH);
        irql.lower(inner);
        assert_eq!(irql.current(), PASSIVE);
        assert_eq!(irql.audit(), Err("interrupt level transitions unbalanced"));
    }
}
