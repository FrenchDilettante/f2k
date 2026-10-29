//! The interrupt request level: the kernel's ranking of "what kind of context is running".
//!
//! Levels 0-2 are the software levels (passive, APC, dispatch); 27-31 are the hardware levels
//! (profile, clock, inter-processor, power, high). A hardware interrupt claims its level on entry
//! and lowers back on exit, so the level is balanced at rest; nesting is safe because a second
//! interrupt at or below the current level is not accepted while the first is being served.
//!
//! The level slots live in one [`IrqlState`], the processor control region's ledger
//! ([`crate::pcr`]): raise returns what it found ([`OldIrql`]: the level and the interrupt flag),
//! which the caller keeps and lower restores. Level tokens
//! ([`crate::level`]) are built on it.
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
/// The PS/2 keyboard interrupt (IRQ 1): the device levels rank as the lines do (27 less the IRQ),
/// so the keyboard ranks above the disk, below profiling.
pub const KEYBOARD: Irql = Irql(26);
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

/// What a raise found, and what the matching lower puts back (Windows 2000's OldIrql): the level,
/// and whether interrupts were enabled. It lives on the stack of the code that raised, so a raise
/// that spans a context switch is paid back on the raising thread's own timeline with its own
/// values, whatever the threads that ran meanwhile did with theirs; the ledger itself keeps only
/// the processor's present.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[must_use = "a raise is paid back by lowering to what it found"]
pub struct OldIrql {
    /// The level the raise started from.
    level: Irql,
    /// Whether interrupts were enabled when the raise started.
    interrupts: bool,
}

impl OldIrql {
    /// What a fresh thread's first instructions lower to: the passive level, interrupts enabled.
    /// The switch into the thread ran at the dispatch level, on the switching thread's raise; the
    /// fresh thread lowers on its own timeline, as Windows 2000's thread startup does.
    pub const THREAD_START: OldIrql = OldIrql {
        level: PASSIVE,
        interrupts: true,
    };

    /// The level the raise started from.
    pub fn level(self) -> Irql {
        self.level
    }
}

/// One CPU's level slot and interrupt-flag discipline.
///
/// A raise/lower pair is a save/restore: raising masks interrupts, returns the level and the flag
/// state it found, and re-enables only below the hardware floor; lowering restores the returned
/// flag state — a pair entered with interrupts masked leaves them masked, so code that runs inside
/// a handler (a deferred-work enqueue, for example) cannot accidentally re-enable the world. What
/// a raise found travels with the caller, never in the ledger: the ledger is the processor's, not
/// a thread's, and needs no handover at a context switch.
pub struct IrqlState {
    current: u8,
    interrupts: bool,
    raises: u32,
    lowers: u32,
}

impl IrqlState {
    /// Fresh state: passive level, interrupts enabled, no transitions recorded.
    pub const fn new() -> Self {
        Self {
            current: 0,
            interrupts: true,
            raises: 0,
            lowers: 0,
        }
    }

    /// The boot processor's state at the kernel's entry: passive, interrupts masked — the loader
    /// hands over with the flag clear, and it stays clear until the interrupt subsystem enables it.
    /// A model that said enabled there would have the boot's masked sections (a raise/lower pair,
    /// a scratch-window use) set the flag on their way out, before the vectors are wired.
    pub const fn at_boot() -> Self {
        Self {
            interrupts: false,
            ..Self::new()
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

    /// Raise to `level`, returning what the raise found: the previous level and the interrupted
    /// flag state. Interrupts are masked for the transition and re-enabled only below the hardware
    /// floor. Raising below the current level is a bug and is refused, here where it happens
    /// rather than at the lower of the pair it interrupted, which it would break: an interrupt
    /// claimed below the level it lands on, say.
    pub fn raise(&mut self, level: Irql) -> OldIrql {
        assert!(level.0 >= self.current, "raising below the current level");
        let found = OldIrql {
            level: Irql(self.current),
            interrupts: self.interrupts,
        };
        self.mask_interrupts();
        self.current = level.0;
        if level < HARDWARE_FLOOR {
            self.unmask_interrupts();
        }
        self.raises = self.raises.wrapping_add(1);
        found
    }

    /// Lower back to what a raise found: its level, and the interrupt-flag state it captured.
    /// Lowering above the current level is a bug and is refused.
    pub fn lower(&mut self, to: OldIrql) {
        self.mask_interrupts();
        assert!(
            to.level.0 <= self.current,
            "lowering above the current level"
        );
        self.current = to.level.0;
        if to.interrupts {
            self.unmask_interrupts();
        }
        self.lowers = self.lowers.wrapping_add(1);
    }

    /// End a hardware interrupt's claim: mask interrupts, run `acknowledge` (the controller's
    /// end-of-interrupt), then lower back to what the claim's raise found, restoring its flag
    /// state.
    ///
    /// The order is the point. A device level below the hardware floor runs its service with
    /// interrupts enabled, the lines below it held off only by the controller's in-service state;
    /// the acknowledgment clears that state, and a line it was holding (the disk's, behind the
    /// keyboard's) is delivered at the first instruction the flag allows. Acknowledged masked, it
    /// waits for the lower and is claimed from the level the ended claim interrupted, not on top
    /// of the claim's own level — where its raise would go below the current level.
    pub fn end_claim(&mut self, to: OldIrql, acknowledge: impl FnOnce(&Self)) {
        self.mask_interrupts();
        acknowledge(self);
        self.lower(to);
    }

    /// Set the interrupt flag. Not `nomem`, here or at the other flag changes: an interrupt
    /// writes memory the code after the enable (or before the mask) reads, so each must be a
    /// compiler barrier — an optimizing build otherwise hoists such a read out of a halt loop.
    pub fn unmask_interrupts(&mut self) {
        self.interrupts = true;
        // SAFETY: the kernel runs at CPL 0, where `sti` is legal, and boot loads the IDT before
        // anything enables interrupts, so every vector the enable lets in has its gate. The ledger
        // records the change in the same step.
        #[cfg(target_arch = "x86")]
        unsafe {
            core::arch::asm!("sti", options(nostack, preserves_flags));
        }
    }

    /// Clear the interrupt flag.
    pub fn mask_interrupts(&mut self) {
        self.interrupts = false;
        // SAFETY: `cli` is legal at CPL 0, where the kernel runs, and masking is always sound: it
        // only defers interrupts. The ledger records the change in the same step.
        #[cfg(target_arch = "x86")]
        unsafe {
            core::arch::asm!("cli", options(nostack, preserves_flags));
        }
    }

    /// A gate's entry: the kernel's interrupt gates (exceptions, system services) clear the
    /// interrupt flag as they enter, and the model must say so. Left as the interrupted context had
    /// it (user mode's enabled, say), the first wait or raise/lower pair inside the handler would
    /// restore that state and run the rest of the handler preemptible, another thread free to
    /// interleave inside the structures it is changing.
    pub fn enter_gate(&mut self) {
        self.mask_interrupts();
    }

    /// A gate's return to the context it interrupted: the `iretd` that follows puts back the
    /// interrupt flag the entry saved (`enabled`: the saved EFLAGS' interrupt flag), so the model
    /// takes that state without touching the hardware flag — enabling it here would open a window
    /// on the gate's own frame before the return.
    pub fn leave_gate(&mut self, enabled: bool) {
        self.interrupts = enabled;
    }

    /// Record the interrupt flag without touching it: the model's half of an instruction sequence
    /// that takes interrupts in its middle (an enable-and-halt, an interrupt window). The
    /// processor control region runs those instructions itself, outside its hold on the ledger,
    /// because an interrupt taken inside them runs its own ledger operations.
    pub fn record_interrupts(&mut self, enabled: bool) {
        self.interrupts = enabled;
    }

    /// The transition audit: every raise has been paid back by a lower, and the level is back where
    /// it started. Context switches keep the count even: the switching thread's raise is paid by
    /// its own lower when it resumes, a fresh thread's start is a lower with no raise of its own
    /// before it, and a dying thread's last raise is never lowered — each thread starts once and
    /// dies once, so the two cancel by the time it has ended.
    pub fn audit(&self) -> Result<(), &'static str> {
        if self.raises != self.lowers {
            return Err("interrupt level transitions unbalanced");
        }
        if self.current != 0 {
            return Err("interrupt level stuck above passive");
        }
        Ok(())
    }
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
            assert_eq!(old.level(), PASSIVE);
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
        assert_eq!(first.level(), PASSIVE);
        assert_eq!(second.level(), DISPATCH);
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

        let from_passive = irql.raise(DISPATCH);
        let from_dispatch = irql.raise(CLOCK);
        assert!(!irql.interrupts_enabled(), "the tick must run masked");

        irql.lower(from_dispatch);
        assert!(
            irql.interrupts_enabled(),
            "dispatch must not block the tick"
        );

        let high = irql.raise(HIGH);
        assert!(!irql.interrupts_enabled());

        irql.lower(high);
        irql.lower(from_passive);
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

    /// A gate entered from an enabled context (user mode, or kernel code running enabled): without
    /// the entry's step, a raise/lower pair inside the handler — a frame allocation's, a wait's —
    /// restores the enabled state the model still carries, and the rest of the handler runs
    /// preemptible though the gate masked it.
    #[test]
    fn a_pair_inside_a_gate_reenables_without_the_entry_step() {
        let mut irql = IrqlState::new();
        let previous = irql.raise(DISPATCH);
        irql.lower(previous);
        assert!(irql.interrupts_enabled(), "the stale model re-enables");
    }

    /// With the entry's step, the handler stays masked through its raise/lower pairs; its return
    /// takes the interrupted context's flag (the `iretd` restores the hardware's), at the level
    /// the gate found.
    #[test]
    fn a_gate_keeps_its_handler_masked_until_the_return() {
        for interrupted in [true, false] {
            let mut irql = IrqlState::new();
            if !interrupted {
                irql.mask_interrupts();
            }
            irql.enter_gate();
            assert!(!irql.interrupts_enabled());
            let previous = irql.raise(DISPATCH);
            irql.lower(previous);
            let previous = irql.raise(HIGH);
            irql.lower(previous);
            assert!(!irql.interrupts_enabled(), "a pair re-enabled the handler");
            irql.leave_gate(interrupted);
            assert_eq!(irql.interrupts_enabled(), interrupted);
            assert_eq!(irql.current(), PASSIVE);
            assert_eq!(irql.audit(), Ok(()));
        }
    }

    /// The boot's state is masked, as the loader hands the processor over: a raise/lower pair
    /// before the interrupt subsystem's enable leaves it masked.
    #[test]
    fn the_boot_state_stays_masked_until_enabled() {
        let mut irql = IrqlState::at_boot();
        assert!(!irql.interrupts_enabled());
        let previous = irql.raise(SYNCH);
        irql.lower(previous);
        assert!(!irql.interrupts_enabled(), "a boot pair enabled interrupts");
        irql.unmask_interrupts();
        assert!(irql.interrupts_enabled());
        assert_eq!(irql.audit(), Ok(()));
    }

    /// Lowering above the current level is a bug: the state refuses, so a mispaired exit cannot
    /// silently corrupt the stack of levels.
    #[test]
    fn lowering_above_current_is_refused() {
        let mut irql = IrqlState::new();
        let _ = irql.raise(DISPATCH);
        let above = OldIrql {
            level: CLOCK,
            interrupts: false,
        };
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            irql.lower(above); // above current: must refuse
        }));
        assert!(result.is_err());
    }

    /// Raising below the current level is a bug too, refused where it happens: the pair it opens
    /// would record the higher level as its previous one, and the outer pair's lower would refuse
    /// later, far from the cause. A raise to the current level is no raise below it.
    #[test]
    fn raising_below_current_is_refused() {
        let mut irql = IrqlState::new();
        let _ = irql.raise(KEYBOARD);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = irql.raise(IDE);
        }));
        assert!(result.is_err());

        let mut irql = IrqlState::new();
        let first = irql.raise(KEYBOARD);
        let second = irql.raise(KEYBOARD);
        irql.lower(second);
        irql.lower(first);
        assert_eq!(irql.audit(), Ok(()));
    }

    /// A model of the interrupt controller, enough for the order of a claim's end: the lines
    /// requesting service and the lines in service, each named by its level. The controller ranks
    /// the connected lines as their levels do (the clock, the keyboard, then the cascade the disk
    /// arrives through), and a line in service holds off every line not above it.
    struct Lines {
        requested: Vec<Irql>,
        in_service: Vec<Irql>,
    }

    impl Lines {
        /// The line the processor takes now: the highest requested one the in-service lines do not
        /// hold off, if the interrupt flag is set.
        fn deliverable(&self, irql: &IrqlState) -> Option<Irql> {
            let line = *self.requested.iter().max()?;
            let held = self.in_service.iter().any(|&busy| busy >= line);
            (irql.interrupts_enabled() && !held).then_some(line)
        }

        /// Claim `line` (the processor took it): in service, raised to its level.
        fn claim(&mut self, irql: &mut IrqlState, line: Irql) -> OldIrql {
            self.requested.retain(|&requested| requested != line);
            self.in_service.push(line);
            irql.raise(line)
        }

        /// Take every interrupt the controller and the flag let through, each claimed, served
        /// (a higher line nesting inside, the flag permitting), and ended.
        fn take(&mut self, irql: &mut IrqlState) {
            while let Some(line) = self.deliverable(irql) {
                let previous = self.claim(irql, line);
                self.take(irql);
                self.end(irql, previous);
            }
        }

        /// A claim's end through the level state's order: the acknowledgment clears the line in
        /// service, releasing the lines it held, and nothing it released may be taken before the
        /// lower — at the ended claim's level, its raise would go below the current one.
        fn end(&mut self, irql: &mut IrqlState, previous: OldIrql) {
            let mut acknowledged = false;
            irql.end_claim(previous, |irql| {
                self.in_service.pop();
                acknowledged = true;
                assert_eq!(
                    self.deliverable(irql),
                    None,
                    "an interrupt taken before the lower"
                );
            });
            assert!(acknowledged);
        }
    }

    /// The disk's interrupt, requested while the keyboard's is in service, is held by the
    /// controller until the keyboard's acknowledgment, and must not be taken between that and the
    /// keyboard's lower: claimed at the keyboard's level, its raise would go below it (and, before
    /// raises were checked, the keyboard's lower refused instead: "lowering above the current
    /// level", the panic a `dir` hit when a key's release came in during its disk reads). Ended in
    /// this order, the disk is claimed after the lower, from the level the keyboard interrupted.
    #[test]
    fn a_held_disk_interrupt_waits_for_the_keyboards_lower() {
        let mut irql = IrqlState::new();
        let mut lines = Lines {
            requested: vec![KEYBOARD],
            in_service: Vec::new(),
        };
        assert_eq!(lines.deliverable(&irql), Some(KEYBOARD));
        let previous = lines.claim(&mut irql, KEYBOARD);
        assert!(
            irql.interrupts_enabled(),
            "a device level below the hardware floor runs enabled"
        );
        // Inside the keyboard's service the disk requests, and is held.
        lines.requested.push(IDE);
        assert_eq!(lines.deliverable(&irql), None);

        lines.end(&mut irql, previous);
        assert_eq!(irql.current(), PASSIVE);
        assert_eq!(lines.deliverable(&irql), Some(IDE));
        lines.take(&mut irql);
        assert!(lines.requested.is_empty() && lines.in_service.is_empty());
        assert_eq!(irql.current(), PASSIVE);
        assert_eq!(irql.audit(), Ok(()));
    }

    /// The order the level state replaced, shown to fail: acknowledged with the flag still set,
    /// the held disk interrupt is taken on top of the keyboard's level, and its claim is refused.
    #[test]
    fn acknowledging_enabled_takes_the_disk_interrupt_too_early() {
        let mut irql = IrqlState::new();
        let mut lines = Lines {
            requested: vec![KEYBOARD],
            in_service: Vec::new(),
        };
        let _ = lines.claim(&mut irql, KEYBOARD);
        lines.requested.push(IDE);
        // The acknowledgment alone, the flag still set.
        lines.in_service.pop();
        assert_eq!(
            lines.deliverable(&irql),
            Some(IDE),
            "taken before the lower"
        );
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = lines.claim(&mut irql, IDE);
        }));
        assert!(
            result.is_err(),
            "a claim below the current level is refused"
        );
    }

    /// A clock tick nests inside a device's service (its line outranks the device's), and the
    /// disk interrupt the keyboard holds still waits for the keyboard's lower.
    #[test]
    fn a_tick_nests_inside_a_device_service() {
        let mut irql = IrqlState::new();
        let mut lines = Lines {
            requested: vec![KEYBOARD],
            in_service: Vec::new(),
        };
        let previous = lines.claim(&mut irql, KEYBOARD);
        lines.requested.push(IDE);
        lines.requested.push(CLOCK);
        lines.take(&mut irql);
        assert_eq!(lines.requested, vec![IDE], "the tick taken, the disk held");
        assert_eq!(irql.current(), KEYBOARD);

        lines.end(&mut irql, previous);
        lines.take(&mut irql);
        assert!(lines.requested.is_empty() && lines.in_service.is_empty());
        assert_eq!(irql.audit(), Ok(()));
    }

    /// An unbalanced audit is detectable: a raise without its lower leaves the level stuck and the
    /// audit failing.
    #[test]
    fn unbalanced_transitions_fail_the_audit() {
        let mut irql = IrqlState::new();
        let previous = irql.raise(DISPATCH);
        assert_eq!(irql.audit(), Err("interrupt level transitions unbalanced"));
        // Restore balance so the guard does not leak into other tests.
        irql.lower(previous);
        assert_eq!(irql.audit(), Ok(()));
    }

    /// A context switch needs no handover of the ledger: one state plays the processor, two
    /// threads' timelines interleave on it at the dispatch level, and each pays its raise back
    /// with what it found, kept on its own side — the masked service's raise re-masks, the
    /// enabled one's re-enables, whichever ran last.
    #[test]
    fn each_timeline_lowers_with_what_its_raise_found() {
        let mut cpu = IrqlState::new();

        // Thread A, in a service that masked interrupts, raises to switch away.
        cpu.mask_interrupts();
        let a = cpu.raise(DISPATCH);
        assert!(cpu.interrupts_enabled(), "the dispatch level runs enabled");

        // Thread B resumes, was switched away from an enabled context, and lowers.
        let b = OldIrql {
            level: PASSIVE,
            interrupts: true,
        };
        cpu.lower(b);
        assert!(cpu.interrupts_enabled());

        // Later B raises to switch back to A; A resumes and lowers with its own.
        let _b_again = cpu.raise(DISPATCH);
        cpu.lower(a);
        assert_eq!(cpu.current(), PASSIVE);
        assert!(!cpu.interrupts_enabled(), "a masked service resumes masked");
    }

    /// The audit across thread lives: a fresh thread's start lowers with no raise of its own, a
    /// dying thread's last raise is never lowered, and once both have happened the count balances.
    #[test]
    fn a_thread_start_and_its_death_balance_the_audit() {
        let mut cpu = IrqlState::new();

        // The resting thread raises to switch to a fresh one, which starts by lowering.
        let resting = cpu.raise(DISPATCH);
        cpu.lower(OldIrql::THREAD_START);
        assert_eq!(cpu.current(), PASSIVE);
        assert!(cpu.interrupts_enabled());

        // The fresh thread ends: its raise is never lowered, and the resting thread resumes.
        let _dying = cpu.raise(DISPATCH);
        assert_eq!(cpu.audit(), Err("interrupt level transitions unbalanced"));
        cpu.lower(resting);
        assert_eq!(cpu.audit(), Ok(()));
    }
}
