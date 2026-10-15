//! The idle thread: the processor's resting thread and its loop.
//!
//! Priority 0 (never queued — selection reaches it only as the
//! fallback), the kernel's own process as owner, the boot stack
//! (mapped in every address space, hence no gate-window slot), no
//! TEB. The processor is already executing it at install, so it is
//! entered directly, never through the startup frame.
//!
//! The loop: the deferred-work queue drains first, then the
//! next-thread check, then the idle call — interrupts disabled
//! going into a decision pass, enabled coming out, and the halt
//! never reached with them disabled.

use super::dispatcher::Dispatcher;
use super::process::SchedProcess;
use super::thread::{Thread, ThreadState};

/// Install `idle` as the processor's idle thread: attach it to the
/// kernel's own process record, set its stack to `stack_top`, mark
/// it Running (the processor is executing it), and hand it to the
/// dispatcher. Host-tested; the loop itself is target-only.
pub fn install(
    idle: &mut Thread,
    process: &mut SchedProcess,
    dispatcher: &mut Dispatcher,
    stack_top: u32,
) {
    // SAFETY: both records are at their final addresses (the boot
    // statics, or the test's leaked boxes), and the process's thread
    // list is initialized.
    unsafe { idle.attach_to(process) };

    // The boot stack: the idle thread runs under any address space,
    // so its stack must be one that is mapped in all of them.
    idle.initial_stack = stack_top;
    idle.kernel_stack = stack_top;
    // No user mode, no TEB: a switch to the idle thread rewrites
    // the TEB descriptor's base to null — harmless, nothing in ring
    // 0 reads FS and the idle thread never enters ring 3.
    idle.teb_va = 0;
    // The processor is executing this very thread: Running at
    // install, straight past the Initialized state attach leaves.
    idle.state = ThreadState::Running;

    dispatcher.install_idle_thread(idle as *mut Thread);
}

/// One decision of the idle loop, in the decided order: the drain
/// first, then the next-thread check, then the idle call.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum IdleAction {
    /// Drain the deferred-work queue (a drain may ready a thread;
    /// the caller re-steps after it).
    DrainDpc,
    /// A thread is schedulable: leave the loop toward the switch
    /// (the switch's own interrupt discipline takes over).
    SwitchToNext,
    /// The idle call: enable interrupts, then halt — the interrupt
    /// return is the wake.
    IdleCall,
}

/// The idle loop's decision order as a pure function: the drain
/// precedes the next-thread check, which precedes the idle call.
/// `dpc_pending` and `schedulable` are the loop's two inputs.
pub fn idle_step(dpc_pending: bool, schedulable: bool) -> IdleAction {
    if dpc_pending {
        IdleAction::DrainDpc
    } else if schedulable {
        IdleAction::SwitchToNext
    } else {
        IdleAction::IdleCall
    }
}

// --- The kernel's scheduler statics (target) --------------------------------

#[cfg(target_arch = "x86")]
mod target {
    use super::super::dispatcher::Dispatcher;
    use super::super::process::SchedProcess;
    use super::super::thread::Thread;
    use super::{idle_step, install, IdleAction};
    use crate::interrupt::irql;
    use core::ptr::{addr_of_mut, eq};

    /// The one dispatcher (single processor).
    static mut DISPATCHER: Dispatcher = Dispatcher::zeroed();
    /// The idle thread's record.
    static mut IDLE_THREAD: Thread = Thread::empty();
    /// The kernel's own process record: the idle thread's owner, and
    /// the directory base a cross-process switch to the idle thread
    /// loads.
    static mut IDLE_PROCESS: SchedProcess = SchedProcess::new(0, 0);

    // The boot stack's top, exported by the entry stub's assembly.
    unsafe extern "C" {
        static boot_stack_top: u8;
    }

    /// The kernel's dispatcher.
    pub(crate) fn dispatcher() -> &'static mut Dispatcher {
        // SAFETY: single CPU; the scheduler's accessors run
        // serialized by the level discipline.
        unsafe { &mut *addr_of_mut!(DISPATCHER) }
    }

    /// Arm the scheduler's resting state: close the statics'
    /// sentinels, bind the idle process to the boot directory (the
    /// one active now), and install the idle thread. Call once,
    /// before interrupts fly; nothing is schedulable yet.
    pub(crate) fn boot() {
        // SAFETY: single CPU, ring 0, interrupts disabled; sole
        // access to the scheduler statics.
        unsafe {
            let dispatcher = &mut *addr_of_mut!(DISPATCHER);
            dispatcher.init();
            let process = &mut *addr_of_mut!(IDLE_PROCESS);
            // The idle process owns the boot directory: a switch to
            // the idle thread across a process boundary loads it.
            process.set_dir_phys(crate::mem::paging::boot_directory_phys());
            process.init();
            let idle = &mut *addr_of_mut!(IDLE_THREAD);
            let stack_top = core::ptr::addr_of!(boot_stack_top) as u32;
            install(idle, process, dispatcher, stack_top);
        }
    }

/// The idle loop: the kernel's resting state once no thread is
/// schedulable. Never returns. The decision passes run with
/// interrupts masked; the idle call enables them before halting,
/// so the wake always comes back to an enabled machine.
    pub(crate) fn idle_loop() -> ! {
        loop {
            irql::state_mut().mask_interrupts();
            match idle_step(
                crate::interrupt::dpc::has_pending(),
                dispatcher().has_schedulable(),
            ) {
                IdleAction::DrainDpc => {
                    // The drain may ready a thread: the next pass
                    // re-steps.
                    crate::interrupt::dpc::drain();
                }
                IdleAction::SwitchToNext => {
                    switch_away_from_idle();
                }
                IdleAction::IdleCall => {
                    // Enabled coming out, through the model so it
                    // stays in step with the flag; then halt.
                    irql::state_mut().unmask_interrupts();
                    // SAFETY: interrupts are enabled; the halt wakes
                    // on the next interrupt.
                    unsafe {
                        core::arch::asm!("hlt", options(nomem, nostack, preserves_flags));
                    }
                }
            }
        }
    }

/// The switch away from the idle thread: the dispatch level around
/// the switch, the level-ledger handover, the caller-side install,
/// then the swap. Nothing readies a thread in this boot (no
/// thread-creation surface), so the smoke boots exercise it.
    fn switch_away_from_idle() {
        let previous = irql::state_mut().raise(irql::DISPATCH);
        let dispatch = dispatcher();
        // SAFETY: the running thread (the idle thread), live and
        // exclusive here.
        let old = dispatch.current_thread();
        // SAFETY: as above.
        unsafe { (*old).level = irql::state_mut().capture() };
        let selected = dispatch.select_next();
        // The step said something was schedulable; if the selection
        // raced empty anyway, this pass simply returns to the loop.
        let idle = idle_thread();
        if selected.is_null() || eq(selected, idle) {
            // SAFETY: the running thread, live.
            unsafe { irql::state_mut().restore((*dispatch.current_thread()).level) };
            irql::state_mut().lower(previous);
            return;
        }
        dispatch.enter(selected);
        // SAFETY: the selected thread's frame is planted (fresh) or
        // saved (resumed) — the selection discipline guarantees it —
        // and the dispatch level masks the dispatcher context.
        unsafe { super::super::switch::swap_context(old, selected) };
        // The running thread's timeline resumes here: restore its
        // level ledger, then pay the raise this site made.
        let current = dispatcher().current_thread();
        // SAFETY: the running thread, live.
        unsafe { irql::state_mut().restore((*current).level) };
        irql::state_mut().lower(previous);
    }

    /// The idle thread's address (the static's).
    fn idle_thread() -> *mut Thread {
        addr_of_mut!(IDLE_THREAD)
    }
}

#[cfg(target_arch = "x86")]
pub(crate) use target::{boot, dispatcher, idle_loop};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sched::thread::ThreadState;

    fn setup(stack_top: u32) -> (&'static mut Thread, &'static mut SchedProcess, &'static mut Dispatcher) {
        let process = Box::leak(Box::new(SchedProcess::new(0x0090_0000, 0)));
        process.init();
        let dispatcher = Box::leak(Box::new(Dispatcher::zeroed()));
        dispatcher.init();
        let idle = Box::leak(Box::new(Thread::empty()));
        install(idle, process, dispatcher, stack_top);
        (idle, process, dispatcher)
    }

    // D1: the idle thread's record and install.

    /// The idle thread: priority 0 (never queued — selection reaches
    /// it only as the fallback), the kernel's own process as owner,
    /// the boot stack for both stack pointers, no TEB, Running at
    /// install, and the dispatcher holding it as current and idle.
    #[test]
    fn the_idle_thread_record_and_install() {
        const STACK: u32 = 0x8010_0000;
        let (idle, process, dispatcher) = setup(STACK);

        assert_eq!(idle.priority(), 0);
        assert_eq!(idle.state(), ThreadState::Running);
        assert_eq!(idle.teb_va(), 0);
        assert_eq!(idle.initial_stack(), STACK);
        assert_eq!(idle.kernel_stack(), STACK);
        // The kernel's own process: base priority 0.
        assert_eq!(process.base_priority(), 0);

        // The dispatcher's install: current, idle flag, and the
        // fallback that selection reaches when nothing is ready.
        assert!(core::ptr::eq(dispatcher.current_thread(), idle as *mut Thread));
        assert!(dispatcher.processor_idle());
        assert!(!dispatcher.has_schedulable());
        let selected = dispatcher.select_next();
        assert!(core::ptr::eq(selected, idle as *mut Thread));
        assert!(dispatcher.processor_idle());

        // The idle thread's quantum is never charged (the fallback
        // is exempt).
        assert!(!dispatcher.tick_quantum(idle));
    }

    /// The idle thread's priority field is pinned at 0, the idle
    /// process's base: the idle thread is never queued, so the field
    /// has no scheduling effect — it only documents that the thread
    /// never competes.
    #[test]
    fn the_idle_priority_is_pinned_at_zero() {
        let (idle, _process, _dispatcher) = setup(0x8010_0000);
        assert_eq!(idle.priority(), 0);
        assert_eq!(idle.base_priority(), 0);
    }

    // D2: the loop's decision order.

    /// The decision order: the drain precedes the next-thread check,
    /// which precedes the idle call — and the idle call is reached
    /// only with nothing pending.
    #[test]
    fn the_idle_loop_decision_order() {
        use IdleAction::*;

        // The drain always comes first: a drain may ready a thread,
        // so the check order matters even when both inputs are set.
        assert_eq!(idle_step(true, true), DrainDpc);
        assert_eq!(idle_step(true, false), DrainDpc);

        // After the drain (re-stepped with the queue empty): the
        // next-thread check, then the idle call.
        assert_eq!(idle_step(false, true), SwitchToNext);
        assert_eq!(idle_step(false, false), IdleCall);
    }
}
