//! The thread surface: child-thread creation, the process's thread and event records, and the
//! thread-exit path.
//!
//! NtCreateThread behind kernel32's CreateThread and CreateProcess: a thread takes a thread record
//! from the pool, a gate stack from the system's kernel stacks (mapped in every address space), an
//! ordinal from its process (which places its own TEB page in the per-thread region), and a
//! startup ladder the context switch enters — the same machinery the main thread's boot entry
//! uses. Its user stack and initial context are its creator's (kernel32's BaseCreateStack and
//! BaseInitializeContext, as on Windows 2000): a created thread enters user mode at kernel32's
//! BaseThreadStartThunk, which calls the start routine and hands its return value to ExitThread.
//! The first thread of a process another process created (NtCreateProcess makes none) is that
//! process's main thread: it takes ordinal 0, the fixed TEB page, and kernel32's CreateProcess
//! starts it at BaseProcessStartThunk, the image's entry point in EAX, as a boot's program's.
//! Every thread's first user-mode work is ntdll's LdrInitializeThunk, which initializes the
//! process on its first thread.
//!
//! A process ends with no thread of its own running its end in two cases: another process
//! terminates it (NtTerminateProcess through a handle), or it never had a thread and its last
//! handle closes (Windows deletes the process object then). Its threads, if any, are terminated
//! from the terminating thread, and its end's steps — its handles closed, its object signalled —
//! run there too ([`end_unattended`]), unless one of them finishes a critical region first and
//! ends the process from its own exit.
//!
//! The exit path, in its order: the process-ending service's or a fault's terminations of the
//! process's other threads first (both end the whole process); then the thread object signals and
//! its waiters wake, and the thread leaves the process list and is Terminated; then the
//! last-thread check routes either to the thread's end or the process's — the last thread's exit is
//! the process's exit, which the idle thread tears down. Its gate stack, the one the exit runs on,
//! is parked last, just before the switch away, for release from another stack (and the stack
//! parked before it is released).
//!
//! A thread inside a critical region ([`critical_region`]) is not terminated where it stands: it
//! may hold the boot volume with its drive mid-command. Its termination is deferred — it finishes
//! the region, releasing what it holds, and ends itself as it leaves — and the process's end passes
//! to the last such thread.

use crate::level::{raised, Dispatch};
use crate::mem::paging;
use crate::process::exit::{self, Fault, ProcessEnd, ThreadEnd};
use crate::process::Process;
use crate::sched::dispatcher::Termination;
use crate::sched::thread::{Thread, ThreadId, ThreadState};
use crate::sched::DISPATCHER;

/// A fresh thread object for a thread created in `process` over the user stack reserved at
/// `stack`, with its record and its ordinal in the process, or none (the program-visible create
/// failure): every ordinal of the process held by a thread something still references, or every
/// record of the pool in use. The record is any free one of the pool; the ordinal is the main
/// thread's for a process that has none yet (its first thread), else the process's lowest free
/// one, which places the thread's TEB — an ordinal a terminated thread held has its pages released
/// first, in this process. The object holds the thread's own reference.
fn free_thread(process: &mut Process, stack: u32) -> Option<(crate::ob::ObjectId, ThreadId, u16)> {
    let directory = crate::ob::directory();
    let (id, ordinal) = if !process.has_main_thread() {
        let id = directory.create_thread()?;
        process.hold_main_thread(id, stack);
        (id, crate::process::ordinals::MAIN)
    } else {
        let ordinal = process.ordinals.free(|id| directory.is_live(id))?;
        let id = directory.create_thread()?;
        if let Some(leftover) = process.ordinals.hold(ordinal, id, stack) {
            release_thread_pages(process, leftover);
        }
        (id, ordinal)
    };
    Some((id, directory.renew_thread(id), ordinal))
}

/// Release the user pages a terminated thread left mapped at an ordinal of `process` that is about
/// to be reused — its TEB page and its stack reservation — through the process's address space: a
/// TEB the program made inaccessible gives its frame back too. The thread is created in the
/// process, so its address space is the live one (the creator's own, or one it attached to).
fn release_thread_pages(process: &mut Process, leftover: crate::process::ordinals::Leftover) {
    use crate::mem::vm::CurrentPages;
    assert!(
        core::ptr::eq(crate::process::pool::address_space(), process),
        "a reused ordinal's pages are released in its own process"
    );
    let space = process.vm();
    let _ = space.decommit(&mut CurrentPages, leftover.teb, paging::PAGE_SIZE);
    if leftover.stack != 0 {
        let _ = space.release(&mut CurrentPages, leftover.stack);
    }
}

/// Create a thread over its creator's stack and initial user context (NtCreateThread's
/// INITIAL_TEB and CONTEXT): a pooled record attached to `process`, its gate-stack slot and TEB
/// page mapped, its startup ladder planted — but not readied: the service readies it once the
/// caller's handle exists, so a thread never runs before its creator holds a way to wait on it.
/// The first thread of a process with none is its main thread (see [`free_thread`]). Returns the
/// thread's object (holding the thread's own reference), its record, and its identifier (its
/// client id, never reused within the boot). None is the program-visible failure: no free ordinal
/// in the process, no free record in the pool, or no free slot in the kernel stack region.
/// `process`'s address space is the live one: the caller's own, or one it attached to.
pub fn create(
    process: &mut Process,
    user: crate::sched::startup::UserStart,
    stack: crate::sched::startup::InitialStack,
) -> Option<(crate::ob::ObjectId, ThreadId, u32)> {
    // An exited thread's stack is released before a slot is taken, so its slot is free to reuse
    // (unmapped, not merely marked free).
    crate::mem::kstacks::release_parked();
    // The gate stack: this thread's kernel stack, mapped in every address space, taken first — a
    // release undoes it when the record or the ordinal is not to be had.
    let (slot, frames) = crate::mem::kstacks::create()?;
    let Some((object, thread, ordinal)) = free_thread(process, stack.allocation_base) else {
        crate::mem::kstacks::release((slot, frames));
        return None;
    };

    // The TEB page: the per-thread region, one page, carrying the thread's identity and the stack
    // its creator made.
    let teb_va = crate::user::thread_teb_va(ordinal as u32);
    let thread_id = crate::process::new_client_id();
    // The startup ladder: the stub calls the system routine (the startup's deliveries), then
    // enters ring 3 in the creator's context.
    let params = crate::sched::startup::StartParams {
        system_routine: user_thread_startup as u32,
        start_routine: user.eip,
        start_context: 0,
        user: Some(user),
    };
    raised::<Dispatch, _>(|dispatch| {
        // Attach: the scheduling data and the process-list membership.
        let dispatcher = DISPATCHER.get(dispatch);
        // SAFETY: the process record is the pool's, at its final address, and outlives its
        // threads (its teardown follows the last one's end).
        unsafe { dispatcher.attach(thread, &mut process.sched) };
        let record = dispatcher.thread_mut(thread);
        record.ordinal = ordinal;
        record.gate_slot = slot;
        record.gate_frames = frames;
        record.initial_stack = paging::gate_slot_top(slot as u32);
        record.teb_va = teb_va;
        record.thread_id = thread_id;
        // SAFETY: the thread's `initial_stack` names its freshly mapped, empty kernel-stack slot.
        unsafe { crate::sched::startup::plant(record, &params) };
    });

    // Its TLS is user memory: ntdll's thread initialization makes the implicit-TLS block, and
    // TlsSetValue the expansion slots on first use (both on the process heap).
    let init = crate::user::teb::TebInit {
        teb: teb_va,
        stack_base: stack.base,
        stack_limit: stack.limit,
        deallocation_stack: stack.allocation_base,
        process_id: process.id(),
        thread_id,
        peb: crate::user::PEB_PAGE,
    };
    crate::user::teb::map_teb(process.vm(), &init);

    Some((object, thread, thread_id))
}

/// A user thread's system routine: the kernel function the startup stub calls before entering the
/// thread's user context. A never-run thread has had no delivery window, so a kernel APC queued on
/// it before its first dispatch — a suspend, or a creation suspended — runs here, before its first
/// user instruction; the stub's tail then carries the thread into its user code — through ntdll's
/// LdrInitializeThunk first, whose NtContinue delivers the user APCs queued before the thread ran
/// (a process without the system DLLs delivers them here instead).
unsafe extern "C" fn user_thread_startup(_start: u32, _parameter: u32) {
    crate::sched::apc::deliver_pending_apcs();
    // Past its suspends: the thread has reached user mode.
    let thread = crate::sched::current_thread();
    raised::<Dispatch, _>(|dispatch| {
        DISPATCHER.get(dispatch).thread_mut(thread).user_started = true;
    });
    if !crate::user::apc::deliver_initialization() {
        crate::user::apc::deliver_at_startup();
    }
}

/// The thread-exit path: the exit status in hand, end the calling thread — and its process, when
/// it is the last thread. Never returns.
pub fn exit_thread(exit_status: i32) -> ! {
    end_thread(ThreadEnd::Exit(exit_status))
}

/// The process-exit path: every other thread of the process is terminated without running again
/// (a thread inside a critical region finishes it first), then the calling thread ends, and the
/// process with `code` — from the last thread. Never returns.
pub fn exit_process(code: u32) -> ! {
    end_thread(ThreadEnd::ExitProcess(code))
}

/// A fault raised on the running thread's behalf ends its process: every other thread of the
/// process is terminated without running again (a thread inside a critical region finishes it
/// first), then this thread ends. Never returns.
pub fn fault_exit(fault: Fault) -> ! {
    end_thread(ThreadEnd::Fault(fault))
}

/// Run `body` inside a critical region of the running thread: normal kernel APCs (a suspend)
/// neither break its waits nor deliver until it leaves, and a termination requested meanwhile waits
/// for it too. The body releases what it holds before the region ends, so a thread whose
/// termination is pending ends here, as it leaves the outermost region, holding nothing.
pub fn critical_region<R>(body: impl FnOnce() -> R) -> R {
    let current = crate::sched::current_thread();
    raised::<Dispatch, _>(|dispatch| {
        DISPATCHER
            .get(dispatch)
            .thread_mut(current)
            .enter_critical_region()
    });
    let result = body();
    // The body's waits return on this same thread.
    let ends = raised::<Dispatch, _>(|dispatch| {
        let thread = DISPATCHER.get(dispatch).thread_mut(current);
        (thread.leave_critical_region() && thread.termination_pending() && !thread.exiting)
            .then(|| thread.exit_status())
    });
    if let Some(exit_status) = ends {
        // A process's end the termination was deferred for, or one thread's termination
        // (TerminateThread), whose status the record carries.
        match crate::process::current().handed_end() {
            Some(end) => end_thread(ThreadEnd::Terminated(end)),
            None => end_thread(ThreadEnd::Exit(exit_status as i32)),
        }
    }
    result
}

/// The one exit path, in its order: NtTerminateProcess's or a fault's terminations of the other
/// threads first (the process's end passing to any that finish a critical region first); then the
/// per-thread teardown (the gate stack is parked for release from another stack, and an earlier
/// exit's parked stack is released), and for the last thread its process's handles closed; then
/// the thread object signals and its waiters wake, the thread leaves the process list and is
/// Terminated; then, for the last thread, the process object signals with the exit code and its
/// waiters wake; then, for the last thread, the report and the end recorded for the idle thread's
/// reap (which only frees the address space and the record); then the next thread is selected
/// among them all, in the window that switches to it. The switch away ends the thread's timeline.
fn end_thread(end: ThreadEnd) -> ! {
    let current = crate::sched::current_thread();
    // The ending thread's process, resolved once, for the whole exit.
    let process = crate::process::current_mut();
    let others = process.sched.stack_count() - 1;
    let mut plan = exit::plan(end, others);
    // The thread's exit status, for GetExitCodeThread: its own, or the process's end.
    let status = match end {
        ThreadEnd::Exit(status) => status as u32,
        ThreadEnd::ExitProcess(code) => code,
        ThreadEnd::Fault(fault) => fault.status,
        ThreadEnd::Terminated(end) => end.exit_status(),
    };
    // From here on the thread runs its own exit: the critical regions of its exit's own volume
    // work do not end it again.
    raised::<Dispatch, _>(|dispatch| {
        let record = DISPATCHER.get(dispatch).thread_mut(current);
        record.exit_status = status;
        record.exiting = true;
        assert!(
            !record.in_critical_region(),
            "a thread ends outside critical regions"
        );
    });

    // The process's end, step 1 (see `process`'s notes on its order): every other thread is
    // terminated, without running again.
    if plan.terminate_others {
        let deferred = terminate_others(process, Some(current), |_| status);
        let (after, handed) = exit::hand_over(plan, deferred);
        plan = after;
        if let Some(end) = handed {
            process.hand_end(end);
        }
    }

    // The process's end, step 2: every handle closes while this thread still runs, as CloseHandle
    // would — the objects go with their last references (a timer leaves the timer table, an owned
    // mutex its owner's list).
    if plan.process_end.is_some() {
        process.release_handles();
    }

    // The timers whose completion APC targets this thread are cancelled, then the APC queue
    // closes, both before the scheduler teardown.
    run_down_timers(current);
    raised::<Dispatch, _>(|dispatch| {
        let dispatcher = DISPATCHER.get(dispatch);
        dispatcher.close_apc_queue(current);
        // The thread object signals and its waiters wake, and the thread leaves the process list.
        dispatcher.retire_current();
    });
    // The process's end, step 3: with its threads ended and their objects signalled, the process
    // object signals with the exit code and its waiters wake — now, not at the idle thread's
    // reap, which a busy sibling process would hold off.
    if let Some(end) = plan.process_end {
        process.signal_end(end);
    }
    // The thread has ended: its own reference on its object goes (the record is reused only once
    // nothing holds it, and never before this code is off its stack: a record is renewed by a
    // create, which no thread runs before the switch away).
    crate::ob::end_thread_references(current);

    // The last-thread route: a process with no threads must not linger — the last thread's end is
    // the process's end, reported and recorded here. The idle thread frees what is left once this
    // thread is off its stack.
    if let Some(end) = plan.process_end {
        assert_eq!(
            process.sched.stack_count(),
            0,
            "the process ends with its last thread"
        );
        let identity = crate::process::runner::identity(process);
        crate::serial_println!("{}", exit::EndReport { end, identity });
        process.set_end(end);
    }

    // The switch away, at the dispatch level, from the passive level the exit runs at. The gate
    // stack is the one this code runs on, so it cannot be unmapped here: it is parked, last,
    // released by whoever next runs on another stack, and the stack parked before it is released
    // now (it is not this one); the record is renewed only by a create, which no thread runs
    // before the switch away. Then the processor's next thread is selected — among the waiters
    // the signals woke, or the idle thread when a process ends, for its reap — and takes the
    // current slot at the switch. The exiting thread's timeline ends at the swap, its raise never
    // lowered.
    raised::<Dispatch, _>(|dispatch| {
        let dispatcher = DISPATCHER.get(dispatch);
        let record = dispatcher.thread(current);
        crate::mem::kstacks::park((record.gate_slot, record.gate_frames));
        // A process's last thread hands the processor to the idle thread, whatever else is ready:
        // the idle thread reaps the process before it switches to the next thread, so the process's
        // record and address space never wait for the processor to fall idle on its own (with
        // interrupts open in the system services, a busy parent may never let it).
        let selected = match plan.process_end {
            Some(_) => dispatcher
                .idle_thread()
                .expect("the idle thread is installed"),
            None => dispatcher
                .select_next()
                .expect("selection always yields the idle fallback"),
        };
        crate::sched::switch::exit_to(dispatch, current, selected);
    });
    unreachable!("a terminated thread never resumes")
}

/// Terminate every thread of `process` but `current` (the running thread, when it is one of the
/// process's), none of them running again, each with the exit status `status` gives it: each is
/// taken off whatever holds it and retired, then its gate stack — not the one this code runs on —
/// is released here. A thread inside a critical region is the exception: it runs on to the region's
/// end and ends itself there. Returns how many are still finishing a region so — this call's
/// deferrals, and an earlier one's (a TerminateThread's, or an ExitProcess's first
/// NtTerminateProcess, whose threads the process's end must still wait for).
fn terminate_others(
    process: &mut Process,
    current: Option<ThreadId>,
    status: impl Fn(&Thread) -> u32,
) -> u16 {
    loop {
        let other = raised::<Dispatch, _>(|dispatch| {
            let dispatcher = DISPATCHER.get(dispatch);
            let other = dispatcher.first_thread_except(&mut process.sched, current)?;
            let record = dispatcher.thread_mut(other);
            record.exit_status = status(record);
            Some(other)
        });
        let Some(other) = other else {
            // Only the threads whose termination is pending are still attached beside this one.
            return process.sched.stack_count() - u16::from(current.is_some());
        };
        run_down_timers(other);
        terminate(other);
    }
}

/// Terminate `thread`, another thread than the running one, its exit status recorded and its
/// timers run down (see [`crate::sched::dispatcher::Dispatcher::request_termination`]); once it is
/// terminated (not deferred to a critical region's end), its gate stack — not the one this code
/// runs on — is released, and its wait's references and its own go.
fn terminate(thread: ThreadId) {
    let stack = raised::<Dispatch, _>(|dispatch| {
        let dispatcher = DISPATCHER.get(dispatch);
        (dispatcher.request_termination(thread) == Termination::Done).then(|| {
            let record = dispatcher.thread(thread);
            (record.gate_slot, record.gate_frames)
        })
    });
    if let Some(stack) = stack {
        crate::mem::kstacks::release(stack);
        // It never returns from whatever it was in: its wait's references and its own go.
        crate::ob::end_thread_references(thread);
    }
}

/// NtTerminateProcess with no process handle, ExitProcess's first step on Windows 2000: every other
/// thread of the current process is terminated with `status`, without running again (a thread
/// inside a critical region finishes it first and ends itself as it leaves), and the calling thread
/// runs on — its process's own end comes with its next call. `process` is the caller's.
pub fn terminate_other_threads(process: &mut Process, status: u32) {
    let current = crate::sched::try_current_thread();
    let _ = terminate_others(process, current, |_| status);
}

/// NtTerminateProcess on another process: every thread of `process` is terminated, without
/// running again, and the process ends with exit code `status` — from here, its end's steps run
/// by the calling thread ([`end_unattended`]), or, when some of its threads are finishing a
/// critical region, from the last of them as it leaves (the end handed on, as an exit's is). A
/// thread terminated before it reached user mode ends with STATUS_THREAD_IS_TERMINATING, and a
/// process none of whose threads it terminates had reached it with exit code 0, as the spawn
/// fixture's capture shows Windows 2000's do (a suspended child that never ran, terminated with
/// 44: its thread's code 0xC000004B, the process's 0). Runs inside a critical region of the
/// caller's (an end's handles may close through the volume): the caller is never terminated
/// half-way through.
///
/// # Panics
///
/// The process is the caller's own (it ends through [`exit_process`]), or it is terminating
/// already (the service refuses it first).
pub fn terminate_process(process: &mut Process, status: u32) {
    use crate::status::STATUS_THREAD_IS_TERMINATING;
    assert!(
        !core::ptr::eq(crate::process::current(), process),
        "the calling process ends through its own exit"
    );
    assert!(!process.terminating(), "a process is terminated once");
    critical_region(|| {
        let started = core::cell::Cell::new(false);
        let deferred = terminate_others(process, None, |thread| {
            if thread.user_started {
                started.set(true);
                status
            } else {
                STATUS_THREAD_IS_TERMINATING.0
            }
        });
        let end = ProcessEnd::Exited(if started.get() { status } else { 0 });
        if deferred != 0 {
            process.hand_end(end);
        } else {
            end_unattended(process, end, true);
        }
    });
}

/// A process object's handle has closed: when it was the last and the process never had a thread
/// (NtCreateProcess makes a process with none, and its creator may close it unstarted), the
/// process ends — its handles closed, its object signalled — and goes to the idle thread's reap
/// for its teardown, as Windows deletes such a process with its object. Nothing reports its end:
/// it never ran. A process ending already, or one whose object went, is left alone.
pub fn forsake_if_abandoned(id: crate::ob::ObjectId) {
    if crate::ob::directory().handle_count(id) != Some(0) {
        return;
    }
    let Some(process) = crate::process::pool::of_object(id) else {
        return;
    };
    if process.has_main_thread() || process.terminating() || process.end.is_some() {
        return;
    }
    critical_region(|| end_unattended(process, ProcessEnd::Exited(0), false));
}

/// The end of a process none of whose threads runs it, steps 2 and 3 of its end (see `process`'s
/// notes) from another process's thread — or none, for a process that never had one: its handles
/// close, its object signals with `end`'s exit code, the end is reported on COM1 when `report`
/// says so, and recorded for the idle thread's reap. The process is marked ending first: nothing
/// creates a thread in it meanwhile, and its handles' closing cannot end it twice.
///
/// # Panics
///
/// A thread of the process is still attached: its end is that thread's to run.
pub fn end_unattended(process: &mut Process, end: ProcessEnd, report: bool) {
    assert_eq!(
        process.sched.stack_count(),
        0,
        "an unattended end follows the process's last thread"
    );
    process.ending = true;
    process.release_handles();
    process.signal_end(end);
    if report {
        let identity = crate::process::runner::identity(process);
        crate::serial_println!("{}", exit::EndReport { end, identity });
    }
    process.set_end(end);
}

/// Whether the calling thread is its process's only one (ThreadAmILastThread): no other thread is
/// attached, a terminated one finishing a critical region included.
pub fn is_last_thread() -> bool {
    crate::process::current().sched.stack_count() == 1
}

/// Cancel the current process's timers whose completion APC targets `thread`, which is ending:
/// nothing may queue to it any more (the platform's timer rundown at thread exit).
fn run_down_timers(thread: ThreadId) {
    crate::ob::directory().run_down_timers(thread);
}

/// Why TerminateThread refuses a target.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TerminateError {
    /// The thread has already ended (Windows reports ERROR_INVALID_PARAMETER).
    Ended,
}

/// TerminateThread on a thread other than the caller: it ends with `status`, without running
/// again — at once, or, inside a critical region, as it leaves the region (holding nothing). Its
/// handle signals and its waiters wake. The last thread of another process ends that process with
/// it, as any last thread's end does: the process is terminated with `status`
/// ([`terminate_process`]'s rule, so a thread that never reached user mode ends with
/// STATUS_THREAD_IS_TERMINATING and its process with 0, as the spawn fixture's capture shows).
/// A thread of the current process is never its last (the caller is alive). The calling thread
/// ends through [`exit_thread`] instead. The target's gate stack is released from the shared
/// tables, whatever address space is current.
pub fn terminate_thread(target: ThreadId, status: u32) -> Result<(), TerminateError> {
    let owner = raised::<Dispatch, _>(|dispatch| {
        let record = DISPATCHER.get(dispatch).thread(target);
        let ended = record.state() == ThreadState::Terminated || record.termination_pending();
        (!ended).then_some(record.process)
    })
    .ok_or(TerminateError::Ended)?;
    let owner = crate::process::pool::owner_of(owner).expect("a user thread's process");
    if !core::ptr::eq(owner, crate::process::current()) && owner.sched.stack_count() == 1 {
        terminate_process(owner, status);
        return Ok(());
    }
    raised::<Dispatch, _>(|dispatch| {
        DISPATCHER.get(dispatch).thread_mut(target).exit_status = status;
    });
    run_down_timers(target);
    // Not the stack this code runs on: it is released now.
    terminate(target);
    Ok(())
}

/// Give `process`'s main thread its initial context `user` (see
/// [`crate::user::main_thread_start`]): plant its startup ladder (the same frame shape a child
/// gets), without readying it ([`ready_main_thread`] does). Part of the process's load, under any
/// address space: the ladder goes onto the thread's gate stack (mapped in every address space).
pub fn start_main_thread(process: &mut Process, user: crate::sched::startup::UserStart) {
    // The main thread's gate slot, TEB page and stack top were taken at process start; only the
    // ladder is missing.
    let thread = process
        .main_thread()
        .expect("a started process has its main thread");
    let params = crate::sched::startup::StartParams {
        system_routine: user_thread_startup as u32,
        start_routine: user.eip,
        start_context: 0,
        user: Some(user),
    };
    raised::<Dispatch, _>(|dispatch| {
        let record = DISPATCHER.get(dispatch).thread_mut(thread);
        // SAFETY: the thread's `initial_stack` names its mapped, empty kernel-stack slot (nothing
        // has entered a gate on it yet), mapped in every directory.
        unsafe { crate::sched::startup::plant(record, &params) };
    });
}

/// Make `process`'s main thread, its ladder planted ([`start_main_thread`]), schedulable: the next
/// switch away from the idle thread can enter it, whatever address space is live now (the switch
/// loads the process's own).
///
/// The readying runs at the dispatch level, as every dispatcher change does, and inside a span with
/// interrupts masked, the flag put back as found: the idle thread may call this with them enabled
/// (the boot's runner, before the idle loop), and the lower out of an enabled caller's raise would
/// take the dispatch decision at once — switching to the readied thread before the runner readies
/// the next leg. Masked, the decision waits for the idle loop, or the next interrupt.
pub fn ready_main_thread(process: &mut Process) {
    let thread = process
        .main_thread()
        .expect("a started process has its main thread");
    let _masked = crate::pcr::pcr().mask_guard();
    raised::<Dispatch, _>(|dispatch| DISPATCHER.get(dispatch).make_ready(thread));
}

/// The fault-test boots' ring-3 entry: start `process`'s main thread in `user` and ready it, then
/// enter the idle loop — the first switch away from idle is into this thread. Never returns.
pub fn enter_as_main_thread(process: &mut Process, user: crate::sched::startup::UserStart) -> ! {
    start_main_thread(process, user);
    ready_main_thread(process);
    crate::sched::idle::idle_loop()
}
