//! The idle thread: the processor's resting thread and its loop.
//!
//! Priority 0 (never queued — selection reaches it only as the fallback), the kernel's own process
//! as owner, the boot stack (mapped in every address space, hence no gate-window slot), no TEB. The
//! processor is already executing it at install, so it is entered directly, never through the
//! startup frame. Its record is the dispatcher database's last thread record, which no thread
//! object names.
//!
//! The loop: the deferred-work queue drains first, then an ended process is reaped, then the
//! next-thread check, then the idle call — interrupts disabled going into a decision pass, enabled
//! coming out, and the halt never reached with them disabled. The reap runs here because the idle
//! thread's stack and address space survive every process: a process's last thread switches to
//! it, and it tears the process down (and, on a suite boot, creates the next).

use super::dispatcher::Dispatcher;
use super::process::SchedProcess;
use super::thread::{ThreadId, ThreadState};

/// Install `idle` as the processor's idle thread: attach it to the kernel's own process record, set
/// its stack to `stack_top`, mark it Running (the processor is executing it), and hand it to the
/// dispatcher. Host-tested; the loop itself is target-only.
///
/// # Safety
///
/// `process` is at its final address and outlives the idle thread (the boot's static, or a test's
/// leaked record).
pub unsafe fn install(
    idle: ThreadId,
    process: &mut SchedProcess,
    dispatcher: &mut Dispatcher,
    stack_top: u32,
) {
    // SAFETY: the caller's contract.
    unsafe { dispatcher.attach(idle, process) };

    let record = dispatcher.thread_mut(idle);
    // The boot stack: the idle thread runs under any address space, so its stack must be one that
    // is mapped in all of them.
    record.initial_stack = stack_top;
    record.kernel_stack = stack_top;
    // No user mode, no TEB: a switch to the idle thread rewrites the TEB descriptor's base to null
    // — harmless, nothing in ring 0 reads FS and the idle thread never enters ring 3.
    record.teb_va = 0;
    // The processor is executing this very thread: Running at install, straight past the
    // Initialized state attach leaves.
    record.state = ThreadState::Running;

    dispatcher.install_idle_thread(idle);
}

/// One decision of the idle loop, in the decided order: the drain first, then the reap, then the
/// next-thread check, then the idle call.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum IdleAction {
    /// Drain the deferred-work queue (a drain may ready a thread; the caller re-steps after it).
    DrainDpc,
    /// Tear down the process whose last thread has ended (a suite boot's next leg may be readied
    /// by it; the caller re-steps after it).
    Reap,
    /// A thread is schedulable: leave the loop toward the switch (the switch's own interrupt
    /// discipline takes over).
    SwitchToNext,
    /// The idle call: enable interrupts, then halt — the interrupt return is the wake.
    IdleCall,
}

/// The idle loop's decision order as a pure function: the drain precedes the reap, which precedes
/// the next-thread check, which precedes the idle call — a dead process is gone before anything
/// else runs. `dpc_pending`, `reap_pending` and `schedulable` are the loop's three inputs.
pub fn idle_step(dpc_pending: bool, reap_pending: bool, schedulable: bool) -> IdleAction {
    if dpc_pending {
        IdleAction::DrainDpc
    } else if reap_pending {
        IdleAction::Reap
    } else if schedulable {
        IdleAction::SwitchToNext
    } else {
        IdleAction::IdleCall
    }
}

// --- The kernel's idle thread (target) --------------------------------------

#[cfg(target_arch = "x86")]
mod target {
    use super::super::database::IDLE_THREAD;
    use super::super::process::PinnedProcess;
    use super::super::DISPATCHER;
    use super::{idle_step, install, IdleAction};
    use crate::level::{self, At, Dispatch};
    use crate::pcr::pcr;

    /// The kernel's own process record: the idle thread's owner, and the directory base a
    /// cross-process switch to the idle thread loads.
    static IDLE_PROCESS: PinnedProcess = PinnedProcess::new(0, 0);

    // The boot stack's top, exported by the entry stub's assembly.
    unsafe extern "C" {
        static boot_stack_top: u8;
    }

    /// Arm the scheduler's resting state: build the dispatcher, bind the idle process to the boot
    /// directory (the one active now), and install the idle thread, at the dispatch level. Call
    /// once, once the interrupt subsystem is up (the raise enables interrupts) and before anything
    /// is schedulable.
    pub(crate) fn boot() {
        // SAFETY: the boot, once, before any thread exists: nothing else has reached the idle
        // process's record, and from here on only the dispatcher and the switch do, through the
        // address the install links.
        let process = unsafe { &mut *IDLE_PROCESS.as_ptr() };
        // The idle process owns the boot directory: a switch to the idle thread across a process
        // boundary loads it.
        process.set_dir_phys(crate::mem::paging::boot_directory_phys());
        let stack_top = core::ptr::addr_of!(boot_stack_top) as u32;
        level::raised::<Dispatch, _>(|dispatch| {
            // SAFETY: the idle process is a static, at its final address for the kernel's life.
            unsafe { install(IDLE_THREAD, process, DISPATCHER.get(dispatch), stack_top) };
        });
    }

    /// The idle loop: the kernel's resting state once no thread is schedulable. Never returns. The
    /// decision passes run with interrupts masked; the idle call enables them before halting, so
    /// the wake always comes back to an enabled machine.
    pub(crate) fn idle_loop() -> ! {
        loop {
            pcr().mask_interrupts();
            let schedulable =
                level::raised::<Dispatch, _>(|dispatch| DISPATCHER.get(dispatch).has_schedulable());
            match idle_step(
                crate::interrupt::dpc::has_pending(),
                crate::process::reap_pending(),
                schedulable,
            ) {
                IdleAction::DrainDpc => {
                    // The drain may ready a thread: the next pass re-steps.
                    crate::interrupt::dpc::drain();
                }
                IdleAction::Reap => {
                    // On the boot stack and, after the switch from the process's last thread, the
                    // boot address space. The next pass re-steps.
                    crate::process::reap();
                }
                IdleAction::SwitchToNext => {
                    level::raised::<Dispatch, _>(switch_away_from_idle);
                }
                IdleAction::IdleCall => {
                    // The schedulable check ran at the dispatch level, enabled: the lower that
                    // ended it drained what arrived meanwhile, and a thread a DPC readied there
                    // took the standby slot (the processor is idle), which reads without the
                    // dispatcher. Masked from that read on, the halt cannot miss what follows it.
                    if pcr().threads.next().is_some() || crate::interrupt::dpc::has_pending() {
                        continue;
                    }
                    // Enabled through the model, so the flag stays in step with the hardware, and
                    // halted in the same step: the step's decision was taken masked, and nothing
                    // may run between the enable and the halt.
                    pcr().unmask_and_halt();
                }
            }
        }
    }

    /// The switch away from the idle thread, at the dispatch level: select, then switch. The
    /// idle thread resumes here when nothing else is schedulable, and the raise is paid back.
    fn switch_away_from_idle(dispatch: &mut At<Dispatch>) {
        // The step said something was schedulable; if the selection raced empty anyway, this pass
        // simply returns to the loop.
        let dispatcher = DISPATCHER.get(dispatch);
        let idle = dispatcher.current().expect("the idle thread runs");
        let selected = dispatcher
            .select_next()
            .filter(|&selected| selected != IDLE_THREAD);
        if let Some(selected) = selected {
            super::super::switch::switch_to(dispatch, idle, selected);
        }
    }

    /// Whether the processor is on the idle thread, which never blocks: kernel code that may block
    /// (the disk path) checks first. User code never runs on the idle thread — every user context
    /// is a thread of its process.
    pub(crate) fn on_idle_thread() -> bool {
        super::super::try_current_thread() == Some(IDLE_THREAD)
    }
}

#[cfg(target_arch = "x86")]
pub(crate) use target::{boot, idle_loop, on_idle_thread};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sched::database::IDLE_THREAD;
    use crate::sched::testkit::{record, Rec};
    use crate::sched::thread::{Thread, ThreadState};

    fn setup(
        stack_top: u32,
    ) -> (
        Rec<Thread>,
        &'static mut SchedProcess,
        &'static mut Dispatcher,
    ) {
        let process = Box::leak(Box::new(SchedProcess::new(0x0090_0000, 0)));
        let dispatcher = crate::sched::testkit::dispatcher();
        // SAFETY: the process record is leaked at its final address.
        unsafe { install(IDLE_THREAD, process, dispatcher, stack_top) };
        (record(IDLE_THREAD), process, dispatcher)
    }

    // D1: the idle thread's record and install.

    /// The idle thread: priority 0 (never queued — selection reaches it only as the fallback), the
    /// kernel's own process as owner, the boot stack for both stack pointers, no TEB, Running at
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

        // The dispatcher's install: current, idle flag, and the fallback that selection reaches
        // when nothing is ready.
        assert_eq!(dispatcher.current(), Some(idle.id()));
        assert!(dispatcher.processor_idle());
        assert!(!dispatcher.has_schedulable());
        assert_eq!(dispatcher.select_next(), Some(idle.id()));
        assert!(dispatcher.processor_idle());

        // The idle thread's quantum is never charged (the fallback is exempt).
        assert!(!dispatcher.tick_quantum(idle));
    }

    /// The idle thread's priority field is pinned at 0, the idle process's base: the idle thread is
    /// never queued, so the field has no scheduling effect — it only documents that the thread
    /// never competes.
    #[test]
    fn the_idle_priority_is_pinned_at_zero() {
        let (idle, _process, _dispatcher) = setup(0x8010_0000);
        assert_eq!(idle.priority(), 0);
        assert_eq!(idle.base_priority(), 0);
    }

    // D2: the loop's decision order.

    /// The decision order: the drain precedes the reap, which precedes the next-thread check, which
    /// precedes the idle call — and the idle call is reached only with nothing pending.
    #[test]
    fn the_idle_loop_decision_order() {
        use IdleAction::*;

        // The drain always comes first: a drain may ready a thread, so the check order matters even
        // when every input is set.
        for reap in [false, true] {
            for schedulable in [false, true] {
                assert_eq!(idle_step(true, reap, schedulable), DrainDpc);
            }
        }

        // After the drain: an ended process is torn down before any thread runs.
        assert_eq!(idle_step(false, true, true), Reap);
        assert_eq!(idle_step(false, true, false), Reap);

        // Then the next-thread check, then the idle call.
        assert_eq!(idle_step(false, false, true), SwitchToNext);
        assert_eq!(idle_step(false, false, false), IdleCall);
    }
}
