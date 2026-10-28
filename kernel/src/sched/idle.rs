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

// --- The kernel's scheduler statics (target) --------------------------------

#[cfg(target_arch = "x86")]
mod target {
    use core::mem::MaybeUninit;
    use core::ptr::addr_of_mut;

    use super::super::database::IDLE_THREAD;
    use super::super::dispatcher::Dispatcher;
    use super::super::process::SchedProcess;
    use super::{idle_step, install, IdleAction};
    use crate::interrupt::irql;
    use crate::pcr::pcr;

    /// The one dispatcher (single processor), with its database: built in place at first use (by
    /// value it would pass through the boot stack, which is smaller than it).
    static mut DISPATCHER: MaybeUninit<Dispatcher> = MaybeUninit::uninit();
    /// Whether [`DISPATCHER`] is built.
    static mut BUILT: bool = false;
    /// The kernel's own process record: the idle thread's owner, and the directory base a
    /// cross-process switch to the idle thread loads.
    static mut IDLE_PROCESS: SchedProcess = SchedProcess::new(0, 0);

    // The boot stack's top, exported by the entry stub's assembly.
    unsafe extern "C" {
        static boot_stack_top: u8;
    }

    /// The kernel's dispatcher.
    pub(crate) fn dispatcher() -> &'static mut Dispatcher {
        // SAFETY: single CPU; the scheduler's accessors run serialized by the level discipline.
        // The dispatcher is built once, in place, before its first use (the boot's, with
        // interrupts disabled).
        unsafe {
            let dispatcher = (*addr_of_mut!(DISPATCHER)).as_mut_ptr();
            if !BUILT {
                Dispatcher::write_empty(dispatcher);
                BUILT = true;
            }
            &mut *dispatcher
        }
    }

    /// Arm the scheduler's resting state: build the dispatcher, bind the idle process to the boot
    /// directory (the one active now), and install the idle thread. Call once, before interrupts
    /// fly; nothing is schedulable yet.
    pub(crate) fn boot() {
        let dispatcher = dispatcher();
        // SAFETY: single CPU, ring 0, interrupts disabled; sole access to the idle process static.
        let process = unsafe { &mut *addr_of_mut!(IDLE_PROCESS) };
        // The idle process owns the boot directory: a switch to the idle thread across a process
        // boundary loads it.
        process.set_dir_phys(crate::mem::paging::boot_directory_phys());
        let stack_top = core::ptr::addr_of!(boot_stack_top) as u32;
        // SAFETY: the idle process is a static, at its final address for the kernel's life.
        unsafe { install(IDLE_THREAD, process, dispatcher, stack_top) };
    }

    /// The idle loop: the kernel's resting state once no thread is schedulable. Never returns. The
    /// decision passes run with interrupts masked; the idle call enables them before halting, so
    /// the wake always comes back to an enabled machine.
    pub(crate) fn idle_loop() -> ! {
        loop {
            pcr().mask_interrupts();
            match idle_step(
                crate::interrupt::dpc::has_pending(),
                crate::process::reap_pending(),
                dispatcher().has_schedulable(),
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
                    switch_away_from_idle();
                }
                IdleAction::IdleCall => {
                    // Enabled through the model, so the flag stays in step with the hardware, and
                    // halted in the same step: the step's decision was taken masked, and nothing
                    // may run between the enable and the halt.
                    pcr().unmask_and_halt();
                }
            }
        }
    }

    /// The switch away from the idle thread: the dispatch level around the switch, the level-ledger
    /// handover, the caller-side install, then the swap.
    fn switch_away_from_idle() {
        let previous = pcr().raise(irql::DISPATCH);
        let dispatch = dispatcher();
        let old = dispatch.current().expect("the idle thread runs");
        dispatch.thread_mut(old).level = pcr().capture();
        // The step said something was schedulable; if the selection raced empty anyway, this pass
        // simply returns to the loop.
        let Some(selected) = dispatch
            .select_next()
            .filter(|&selected| selected != IDLE_THREAD)
        else {
            let current = dispatch.current().expect("the idle thread runs");
            pcr().restore(dispatch.thread(current).level);
            pcr().lower(previous);
            return;
        };
        dispatch.enter(selected);
        let (from, to) = (
            dispatch.thread_address(old),
            dispatch.thread_address(selected),
        );
        // SAFETY: both records are the database's, pinned; the selected thread's frame is planted
        // (fresh) or saved (resumed) — the selection discipline guarantees it — and the dispatch
        // level masks the dispatcher context.
        unsafe { super::super::switch::swap_context(from, to) };
        // The running thread's timeline resumes here: restore its level ledger, then pay the raise
        // this site made.
        let dispatch = dispatcher();
        let current = dispatch
            .current()
            .expect("a resumed thread is the running one");
        pcr().restore(dispatch.thread(current).level);
        pcr().lower(previous);
    }

    /// Whether the processor is on the idle thread, which never blocks: kernel code that may block
    /// (the disk path) checks first. User code never runs on the idle thread — every user context
    /// is a thread of its process.
    pub(crate) fn on_idle_thread() -> bool {
        dispatcher().current() == Some(IDLE_THREAD)
    }
}

#[cfg(target_arch = "x86")]
pub(crate) use target::{boot, dispatcher, idle_loop, on_idle_thread};

// --- The host's dispatcher --------------------------------------------------

/// The host builds have no boot: each test thread installs a dispatcher of its own, which the
/// code that reaches the kernel's one dispatcher (the object directory's accessors) finds here.
#[cfg(not(target_arch = "x86"))]
mod host {
    extern crate std;

    use core::cell::Cell;

    use super::super::dispatcher::Dispatcher;

    std::thread_local! {
        static INSTALLED: Cell<*mut Dispatcher> = const { Cell::new(core::ptr::null_mut()) };
    }

    /// Make `dispatcher` this thread's: what [`dispatcher`] returns from now on.
    pub fn install(dispatcher: &'static mut Dispatcher) {
        INSTALLED.with(|installed| installed.set(dispatcher));
    }

    /// This thread's dispatcher.
    ///
    /// # Panics
    ///
    /// None is installed.
    pub fn dispatcher() -> &'static mut Dispatcher {
        let installed = INSTALLED.with(Cell::get);
        assert!(!installed.is_null(), "a host dispatcher is installed");
        // SAFETY: an installed dispatcher is leaked (`'static`), and only its thread reaches it.
        unsafe { &mut *installed }
    }
}

#[cfg(not(target_arch = "x86"))]
pub use host::{dispatcher, install as install_host};

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
        assert_eq!(dispatcher.current_thread(), idle.as_ptr());
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
