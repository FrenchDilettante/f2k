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
//! Windows 2000 never ends a thread from outside: a termination queues an exit APC on the thread
//! ([`crate::sched::dispatcher::Dispatcher::request_termination`]), and the thread runs its own
//! exit at its next window for a normal kernel APC — a wait it may be woken from, the service
//! boundary, the first dispatch of one that never ran (before its first user instruction). A
//! thread inside a critical region ([`critical_region`]) may hold the boot volume with its drive
//! mid-command: its exit APC waits for the region's end, where the thread holds nothing the region
//! took. A thread holding or waiting for a short lock is at the APC level: its exit waits for it
//! to lower. The thread calling for its own end (ExitThread, ExitProcess, a fault) ends at once.
//!
//! As on Windows 2000, only a process's last thread ending ends the process: its object signals and
//! takes its exit code then. A process that never had a thread never ends: another process
//! terminating it only closes it to new threads, and it goes, unsignalled, when its object's last
//! reference beside its own does ([`delete_if_abandoned`]). Otherwise a termination's end is
//! decided and held for whichever of its threads exits last.
//!
//! The exit path, in its order: the thread's APC queue closes; the process-ending service's or a
//! fault's end is decided for the process and every other thread is terminated (both end the whole
//! process); then the last-thread check. A thread that is not its process's last retires — the
//! thread object signals and its waiters wake, it leaves the process list and is Terminated — and
//! switches away. The last thread runs its process's end first: its handles close and its views
//! go, its end is reported and recorded, then it retires and the process object signals, and it
//! hands the processor to the idle thread, which tears the process down. Its gate stack, the one
//! the exit runs on, is parked last, just before the switch away, for release from another stack
//! (and the stack parked before it is released). From its retire on, the thread takes no lock and
//! is switched away by its exit's own switch alone.

use crate::level::{raised, Dispatch};
use crate::mem::paging;
use crate::process::exit::{self, Fault, ProcessEnd, ThreadEnd};
use crate::process::Process;
use crate::sched::thread::{Thread, ThreadId, ThreadState};
use crate::sched::DISPATCHER;

/// A fresh thread object for a thread created in `process` over the user stack reserved at
/// `stack`, with its record attached to the process and its ordinal in it. The record is any free
/// one of the pool; the ordinal is the main thread's for a process that has none yet (its first
/// thread), else the process's lowest free one, which places the thread's TEB — an ordinal a
/// terminated thread held has its pages released first, in this process. The object holds the
/// thread's own reference.
///
/// The program-visible create failures: a process that takes no new thread (its end is decided, or
/// its last thread is ending it: STATUS_PROCESS_IS_TERMINATING), every ordinal of the process held
/// by a thread something still references, or every record of the pool in use (STATUS_NO_MEMORY).
fn free_thread(
    process: &Process,
    stack: u32,
) -> Result<(crate::ob::ObjectId, ThreadId, u16), crate::status::NtStatus> {
    use crate::status::{STATUS_NO_MEMORY, STATUS_PROCESS_IS_TERMINATING};
    // The ordinal, the record and the attach are one hold of the directory, which keeps the
    // process's ordinals with its object: the last-thread check of an ending thread, in a hold of
    // its own, counts the new thread, or closes the process before it (see `end_thread`). The
    // pages a reused ordinal left are released after the hold.
    let object = process.object();
    let (id, thread, ordinal, leftover) = crate::ob::locked(|directory| {
        let ordinals = directory.ordinals(object).ok_or(STATUS_NO_MEMORY)?;
        if ordinals.closed() {
            return Err(STATUS_PROCESS_IS_TERMINATING);
        }
        let has_main = ordinals.has_main();
        let (id, ordinal, leftover) = if !has_main {
            let id = directory.create_thread().ok_or(STATUS_NO_MEMORY)?;
            directory
                .ordinals(object)
                .ok_or(STATUS_NO_MEMORY)?
                .hold_main(id, stack);
            (id, crate::process::ordinals::MAIN, None)
        } else {
            let ordinal = directory.free_ordinal(object).ok_or(STATUS_NO_MEMORY)?;
            let id = directory.create_thread().ok_or(STATUS_NO_MEMORY)?;
            let leftover = directory
                .ordinals(object)
                .ok_or(STATUS_NO_MEMORY)?
                .hold(ordinal, id, stack);
            (id, ordinal, leftover)
        };
        let thread = directory.renew_thread(id);
        raised::<Dispatch, _>(|dispatch| {
            // SAFETY: the scheduling record is the pool's, at its final address, reached only
            // through this borrow of the dispatcher meanwhile, and it outlives its threads (its
            // teardown follows the last one's end).
            unsafe { DISPATCHER.get(dispatch).attach(thread, process.sched_ptr()) };
        });
        Ok((id, thread, ordinal, leftover))
    })?;
    if let Some(leftover) = leftover {
        release_thread_pages(process, leftover);
    }
    Ok((id, thread, ordinal))
}

/// Release the user pages a terminated thread left mapped at an ordinal of `process` that is about
/// to be reused — its TEB page and its stack reservation — through the process's address space: a
/// TEB the program made inaccessible gives its frame back too. The thread is created in the
/// process, so its address space is the live one (the creator's own, or one it attached to).
fn release_thread_pages(process: &Process, leftover: crate::process::ordinals::Leftover) {
    use crate::mem::vm::CurrentPages;
    assert!(
        core::ptr::eq(crate::process::pool::address_space(), process),
        "a reused ordinal's pages are released in its own process"
    );
    process.with_space(|space| {
        let _ = space.decommit(&mut CurrentPages, leftover.teb, paging::PAGE_SIZE);
        if leftover.stack != 0 {
            let _ = space.release(&mut CurrentPages, leftover.stack);
        }
    });
}

/// Create a thread over its creator's stack and initial user context (NtCreateThread's
/// INITIAL_TEB and CONTEXT): a pooled record attached to `process`, its gate-stack slot and TEB
/// page mapped, its startup ladder planted — but not readied: the service readies it once the
/// caller's handle exists, so a thread never runs before its creator holds a way to wait on it.
/// The first thread of a process with none is its main thread (see [`free_thread`]). Returns the
/// thread's object (holding the thread's own reference), its record, and its identifier (its
/// client id, never reused within the boot). The program-visible failures: a process that takes
/// no new thread (STATUS_PROCESS_IS_TERMINATING), no free ordinal in the process, no free record in
/// the pool, or no free slot in the kernel stack region (STATUS_NO_MEMORY). `process`'s address
/// space is the live one: the caller's own, or one it attached to.
pub fn create(
    process: &Process,
    user: crate::sched::startup::UserStart,
    stack: crate::sched::startup::InitialStack,
) -> Result<(crate::ob::ObjectId, ThreadId, u32), crate::status::NtStatus> {
    // An exited thread's stack is released before a slot is taken, so its slot is free to reuse
    // (unmapped, not merely marked free).
    crate::mem::kstacks::release_parked();
    // The gate stack: this thread's kernel stack, mapped in every address space, taken first — a
    // release undoes it when the record or the ordinal is not to be had.
    let (slot, frames) = crate::mem::kstacks::create().ok_or(crate::status::STATUS_NO_MEMORY)?;
    let (object, thread, ordinal) = match free_thread(process, stack.allocation_base) {
        Ok(made) => made,
        Err(status) => {
            crate::mem::kstacks::release((slot, frames));
            return Err(status);
        }
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
        // The record, attached to the process (see `free_thread`), takes its stack and identity.
        let dispatcher = DISPATCHER.get(dispatch);
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
    process.with_space(|space| crate::user::teb::map_teb(space, &init));

    Ok((object, thread, thread_id))
}

/// A user thread's system routine: the kernel function the startup stub calls before entering the
/// thread's user context. A never-run thread has had no delivery window, so a kernel APC queued on
/// it before its first dispatch — a suspend, a creation suspended, or a termination's exit APC —
/// runs here, before its first user instruction; a termination's exit then ends the thread here,
/// on its way to user mode, as every return to user mode ends a terminated thread. The stub's tail
/// carries the thread into its user code — through ntdll's LdrInitializeThunk first, whose
/// NtContinue delivers the user APCs queued before the thread ran (a process without the system
/// DLLs delivers them here instead).
unsafe extern "C" fn user_thread_startup(_start: u32, _parameter: u32) {
    crate::sched::apc::deliver_pending_apcs();
    crate::user::apc::deliver_exit();
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

/// The process-exit path: the process's end is decided — exit code `code` — and every other thread
/// of the process is terminated (each runs its own exit); then the calling thread ends, and the
/// process with its last thread. Never returns.
pub fn exit_process(code: u32) -> ! {
    end_thread(ThreadEnd::ExitProcess(code))
}

/// A fault raised on the running thread's behalf ends its process: the fault is the process's end,
/// every other thread of the process is terminated (each runs its own exit), then this thread
/// ends. Never returns.
pub fn fault_exit(fault: Fault) -> ! {
    end_thread(ThreadEnd::Fault(fault))
}

/// Run `body` inside a critical region of the running thread (Windows 2000's KeEnterCriticalRegion
/// and KeLeaveCriticalRegion): normal kernel APCs — a suspend, a termination's exit APC — neither
/// break its waits nor deliver until it leaves. The body releases what it holds before the region
/// ends, and leaving the outermost region opens a window for what it held off: a thread whose
/// termination was requested meanwhile ends here, holding nothing the body took.
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
    if raised::<Dispatch, _>(|dispatch| {
        DISPATCHER
            .get(dispatch)
            .thread_mut(current)
            .leave_critical_region()
    }) {
        crate::sched::apc::deliver_pending_apcs();
    }
    result
}

/// The exit APC's normal half, the first of its two stages (Windows 2000's PspExitNormalApc), on
/// the terminated thread at its window: the exit APC becomes a user-mode APC at the head of the
/// thread's user queue, its user APCs pending. The thread runs on to its return to user mode,
/// unwinding whatever it is doing in the kernel — a user-mode wait it is in, or enters, completes
/// at once (STATUS_USER_APC) — so the references and locks its frames hold go as they would on any
/// return; the return then runs the second stage ([`exit_apc_user`]) before anything else.
fn exit_apc_normal(thread: ThreadId, status: usize, _argument1: usize, _argument2: usize) {
    raised::<Dispatch, _>(|dispatch| {
        let dispatcher = DISPATCHER.get(dispatch);
        debug_assert!(
            !dispatcher.thread(thread).exiting,
            "an exiting thread takes no exit APC"
        );
        dispatcher.queue_user_exit(
            thread,
            exit_apc_user,
            crate::user::apc::user_normal_routine,
            status,
        );
    });
}

/// The exit APC's second stage, its user-mode kernel routine (Windows 2000's PsExitSpecialApc):
/// the terminated thread, on its way back to user mode with nothing of the kernel's held, runs its
/// own exit with the status its termination recorded, the APC's context.
fn exit_apc_user(_apc: crate::sched::apc::ApcId, args: &mut crate::sched::apc::ApcArgs) {
    end_thread(ThreadEnd::Terminated(args.normal_context as u32))
}

/// The one exit path (Windows 2000's PspExitThread), in its order: the thread's APC queue closes;
/// NtTerminateProcess's or a fault's end is decided for the process and every other thread is
/// terminated; the thread's timers are cancelled. Then the last-thread check, in one hold with a
/// thread's retire when others remain: it retires — its object signals and its waiters wake, it
/// leaves the process list and is Terminated — and its own reference on its object goes. The last
/// thread first closes its process's handles and unmaps its views, reports the end and records it
/// for the idle thread's reap (which only frees the address space and the record), then retires
/// the same way, the process object signalling with the exit code right after its own. Then the
/// gate stack is parked for release from another stack (and an earlier exit's parked stack is
/// released), and the next thread is selected, in the window that switches to it. The switch away
/// ends the thread's timeline.
fn end_thread(end: ThreadEnd) -> ! {
    let current = crate::sched::current_thread();
    // The ending thread's process, resolved once, for the whole exit.
    let process = crate::process::current();
    let status = end.status();
    // From here on the thread runs its own exit: nothing more is queued on it, what is queued goes
    // (a kernel APC that had no window yet: a suspend, or a termination's exit APC this exit
    // supersedes), and no termination is requested for it again.
    let started = raised::<Dispatch, _>(|dispatch| {
        let dispatcher = DISPATCHER.get(dispatch);
        let record = dispatcher.thread_mut(current);
        assert!(
            !record.in_critical_region(),
            "a thread ends outside critical regions"
        );
        record.exit_status = status;
        record.exiting = true;
        record.terminate_pending = true;
        let started = record.user_started;
        dispatcher.close_apc_queue(current);
        started
    });

    // The process's end, step 1 (see `process`'s notes on its order): NtTerminateProcess's and a
    // fault's end is decided for the whole process — it takes no new thread from here on — and
    // every other thread is terminated.
    if let Some(decided) = end.ends_process() {
        process.decide_end(decided);
        terminate_others(process, Some(current), |_| status);
    }

    // The timers whose completion APC targets this thread are cancelled, before the scheduler
    // teardown.
    run_down_timers(current);

    // The last-thread check (PspExitThread's count of the process's active threads), in one hold
    // with the retire of a thread that is not the last: a thread that finds others is gone from the
    // process's list before another can look, so exactly one finds none. The last closes its
    // process to new threads in the same hold: a create, whose attach is one hold of the directory
    // too (see `free_thread`), either came first — and this thread is not the last — or is
    // refused.
    let last = crate::ob::locked(|directory| {
        let last = raised::<Dispatch, _>(|dispatch| {
            let dispatcher = DISPATCHER.get(dispatch);
            let last = process.sched(dispatcher).stack_count() == 1;
            if !last {
                dispatcher.retire_current();
            }
            last
        });
        if last {
            if let Some(ordinals) = directory.ordinals(process.object()) {
                ordinals.close();
            }
        } else {
            // Its own reference goes in the same hold: a retired thread waits for nothing, and
            // its record is renewed by a create only once nothing holds its object — never before
            // its switch away, as no other thread runs until then.
            directory.end_thread_references(current);
        }
        last
    });

    // The last thread's route: a process with no threads must not linger — the last thread's end
    // is the process's end.
    let process_end = last.then(|| {
        let end = end.last_thread_end(process.handed_end(), started);
        // The process's end, step 2: every handle closes while this thread still runs, as
        // CloseHandle would — the objects go with their last references (a timer leaves the timer
        // table, an owned mutex its owner's list); then its views are unmapped, on its own address
        // space (a thread ends detached), each one's section or image segment losing its
        // reference.
        process.release_handles();
        debug_assert!(
            !crate::sched::attach::running_attached(),
            "a thread ends on its own address space"
        );
        process.unmap_views();
        // The end is reported and recorded before the retire, as nothing after it takes a lock;
        // the reap waits for the retire all the same (see `pool`).
        let name = process.name();
        let identity = crate::process::runner::identity(process, &name);
        crate::serial_println!("{}", exit::EndReport { end, identity });
        process.set_end(end);
        // The process's end, step 3, in one hold with the retire: the thread object signals, then
        // the process object with the exit code, and their waiters wake — now, not at the idle
        // thread's reap, which a busy sibling process would hold off. The process's signal reaches
        // the dispatcher database alone: the process's own reference keeps its object.
        crate::ob::locked(|directory| {
            raised::<Dispatch, _>(|dispatch| {
                let dispatcher = DISPATCHER.get(dispatch);
                dispatcher.retire_current();
                assert_eq!(
                    process.sched(dispatcher).stack_count(),
                    0,
                    "the process ends with its last thread"
                );
            });
            process.signal_end(end);
            directory.end_thread_references(current);
        });
        end
    });

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
        // interrupts open in the system services, a busy parent may never let it). Not while a
        // preempted thread holds a short lock, which the idle thread could not wait for: the reap
        // waits for the processor to fall idle then.
        let selected = match process_end {
            Some(_) if crate::sync::short_locks_free() => dispatcher
                .idle_thread()
                .expect("the idle thread is installed"),
            _ => dispatcher
                .select_next()
                .expect("selection always yields the idle fallback"),
        };
        crate::sched::switch::exit_to(dispatch, current, selected);
    });
    unreachable!("a terminated thread never resumes")
}

/// Terminate every thread of `process` but `current` (the running thread, when it is one of the
/// process's) that is not terminating already, each with the exit status `status` gives it: each
/// takes its exit APC and runs its own exit at its next window (see
/// [`crate::sched::dispatcher::Dispatcher::request_termination`]). Every request is made in one
/// step: none of the threads runs before the last is requested.
fn terminate_others(process: &Process, current: Option<ThreadId>, status: impl Fn(&Thread) -> u32) {
    raised::<Dispatch, _>(|dispatch| {
        let dispatcher = DISPATCHER.get(dispatch);
        while let Some(other) = dispatcher.first_thread_except(process.sched_ptr(), current) {
            let status = status(dispatcher.thread(other));
            dispatcher.request_termination(other, exit_apc_normal, status);
        }
    });
}

/// NtTerminateProcess with no process handle, ExitProcess's first step on Windows 2000: every other
/// thread of the current process is terminated with `status` (each runs its own exit), and the
/// calling thread runs on — its process's own end comes with its next call. `process` is the
/// caller's.
pub fn terminate_other_threads(process: &Process, status: u32) {
    let current = crate::sched::try_current_thread();
    terminate_others(process, current, |_| status);
}

/// Why NtTerminateProcess refuses a process: its end is under way or decided already, by another
/// termination or its own threads (Windows 2000's STATUS_PROCESS_IS_TERMINATING).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Terminating;

/// NtTerminateProcess on another process: the process's end is decided — exit code `status` — and
/// every thread of it is terminated; the last of them to exit ends the process. A thread
/// terminated before it reached user mode ends with STATUS_THREAD_IS_TERMINATING, and a process
/// none of whose threads had reached it ends with exit code 0, as the spawn fixture's capture
/// shows Windows 2000's do (a suspended child that never ran, terminated with 44: its thread's code
/// 0xC000004B, the process's 0). A process with no thread does not end: as the spawn fixture's
/// nothread block shows Windows 2000's, the termination succeeds and the process takes no new
/// thread, while its object stays unsignalled with exit code STILL_ACTIVE (it goes with its
/// object). Runs inside a critical region of the caller's: the caller is never terminated
/// half-way through. Refused when the process is terminated or its end decided already: the
/// decision is taken once, whichever of two racing terminations (a TerminateProcess and a
/// TerminateThread of the process's last thread, say) takes it first.
///
/// # Panics
///
/// The process is the caller's own (it ends through [`exit_process`]).
pub fn terminate_process(process: &Process, status: u32) -> Result<(), Terminating> {
    use crate::status::STATUS_THREAD_IS_TERMINATING;
    assert!(
        !core::ptr::eq(crate::process::current(), process),
        "the calling process ends through its own exit"
    );
    critical_region(|| {
        let (threads, started) = raised::<Dispatch, _>(|dispatch| {
            let dispatcher = DISPATCHER.get(dispatch);
            (
                !process.sched(dispatcher).has_no_threads(),
                dispatcher.any_thread_of(process.sched_ptr(), |thread| thread.user_started),
            )
        });
        if !threads {
            // A process that had threads and has none left is ending by its last one.
            let first = !process.has_main_thread() && process.mark_terminated();
            return first.then_some(()).ok_or(Terminating);
        }
        let end = ProcessEnd::Exited(if started { status } else { 0 });
        // The end first, for whichever thread exits last to find.
        if !process.decide_end(end) {
            return Err(Terminating);
        }
        terminate_others(process, None, |thread| {
            if thread.user_started {
                status
            } else {
                STATUS_THREAD_IS_TERMINATING.0
            }
        });
        Ok(())
    })
}

/// A reference to the process object `id` has gone (a handle's among them): when what is left is
/// the process's own and the process never had a thread (NtCreateProcess makes a process with
/// none, and its creator may close it unstarted, terminated or not), the process is deleted, as
/// Windows 2000 deletes such a process with its object (see [`Process::delete_threadless`]).
/// Nothing signals and nothing reports: it never ran. A process that had a thread, or whose object
/// went, is left alone.
pub fn delete_if_abandoned(id: crate::ob::ObjectId) {
    if !crate::ob::locked(|directory| directory.only_its_own_reference(id)) {
        return;
    }
    let Some(process) = crate::process::pool::of_object(id) else {
        return;
    };
    if process.has_main_thread() {
        return;
    }
    critical_region(|| process.delete_threadless());
}

/// Whether the calling thread is its process's only one (ThreadAmILastThread): no other thread is
/// attached, a terminated one that has not run its exit yet included.
pub fn is_last_thread() -> bool {
    crate::process::current().stack_count() == 1
}

/// Cancel the current process's timers whose completion APC targets `thread`, which is ending:
/// nothing may queue to it any more (the platform's timer rundown at thread exit).
fn run_down_timers(thread: ThreadId) {
    crate::ob::locked(|directory| directory.run_down_timers(thread));
}

/// Why TerminateThread refuses a target.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TerminateError {
    /// The thread has already ended (Windows reports ERROR_INVALID_PARAMETER).
    Ended,
}

/// TerminateThread on a thread other than the caller: it ends with `status`, by its own exit (see
/// [`crate::sched::dispatcher::Dispatcher::request_termination`]: inside a critical region, as it
/// leaves the region, holding nothing), and its handle signals and its waiters wake then. A thread
/// that can run its exit at once — its wait broken, or ready — is handed the processor, so it has
/// ended by the time the caller's TerminateThread returns, as the threads fixture's lateexit block
/// shows Windows 2000's terminated thread has (its exit code and a zero-timeout wait on it, at
/// once). The last thread of another process ends that process with it, as any last thread's end
/// does: the process is terminated with `status` ([`terminate_process`]'s rule, so a thread that
/// never reached user mode ends with STATUS_THREAD_IS_TERMINATING and its process with 0, as the
/// spawn fixture's capture shows). A thread already ending, or whose process's end is decided or
/// under way meanwhile, is refused as one that has ended. A thread of the current process is never
/// its last (the caller is alive). The calling thread ends through [`exit_thread`] instead.
pub fn terminate_thread(target: ThreadId, status: u32) -> Result<(), TerminateError> {
    let owner = raised::<Dispatch, _>(|dispatch| {
        let record = DISPATCHER.get(dispatch).thread(target);
        let ended = record.state() == ThreadState::Terminated || record.termination_pending();
        (!ended).then(|| record.process().pool_index())
    })
    .ok_or(TerminateError::Ended)?;
    let owner = crate::process::pool::record(owner.expect("a user thread's process is pooled"));
    if !core::ptr::eq(owner, crate::process::current()) && owner.stack_count() == 1 {
        return terminate_process(owner, status).map_err(|Terminating| TerminateError::Ended);
    }
    raised::<Dispatch, _>(|dispatch| {
        let dispatcher = DISPATCHER.get(dispatch);
        if !dispatcher.request_termination(target, exit_apc_normal, status) {
            return Err(TerminateError::Ended);
        }
        dispatcher.hand_processor_to(target);
        Ok(())
    })
}

/// Give `process`'s main thread its initial context `user` (see
/// [`crate::user::main_thread_start`]): plant its startup ladder (the same frame shape a child
/// gets), without readying it ([`ready_main_thread`] does). Part of the process's load, under any
/// address space: the ladder goes onto the thread's gate stack (mapped in every address space).
pub fn start_main_thread(process: &Process, user: crate::sched::startup::UserStart) {
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
pub fn ready_main_thread(process: &Process) {
    let thread = process
        .main_thread()
        .expect("a started process has its main thread");
    let _masked = crate::pcr::pcr().mask_guard();
    raised::<Dispatch, _>(|dispatch| DISPATCHER.get(dispatch).make_ready(thread));
}

/// The fault-test boots' ring-3 entry: start `process`'s main thread in `user` and ready it, then
/// enter the idle loop — the first switch away from idle is into this thread. Never returns.
pub fn enter_as_main_thread(process: &Process, user: crate::sched::startup::UserStart) -> ! {
    start_main_thread(process, user);
    ready_main_thread(process);
    crate::sched::idle::idle_loop()
}
