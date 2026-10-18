//! The smoke-subset thread surface: child-thread creation, the thread records, and the thread-exit
//! path.
//!
//! CreateThread behind the synthesized kernel32: a child takes a thread record from the object
//! manager's thread pool (its object holding the thread's own reference until its end), a
//! gate-stack slot from the process's window, its own TEB page and user stack from the per-thread
//! regions, and a startup ladder the context switch enters — the same machinery the main thread's
//! boot entry uses. The child's user function receives its parameter per the calling convention
//! (planted at [esp+4] under a return address that is the kernel's thread-exit trampoline), so
//! returning from the function terminates the thread with the return value as the exit status.
//!
//! The exit path, in its order: the exit service's or a fault's terminations of the process's
//! other threads first (both end the whole process); then the per-thread teardown (the gate stack
//! is parked for release from another stack, and an earlier exit's parked stack is released); then
//! the thread object signals and its waiters wake, and the thread leaves the process list and is
//! Terminated;
//! then the last-thread check routes either to the thread's end or the process's — the last
//! thread's exit is the process's exit, which the idle thread tears down.
//!
//! A thread inside a critical region ([`critical_region`]) is not terminated where it stands: it
//! may hold the boot volume with its drive mid-command. Its termination is deferred — it finishes
//! the region, releasing what it holds, and ends itself as it leaves — and the process's end passes
//! to the last such thread.

use crate::mem::paging;
use crate::process::exit::{self, Fault, ThreadEnd};
use crate::process::Process;
use crate::sched::dispatcher::{Dispatcher, Termination};
use crate::sched::thread::{Thread, ThreadState};

/// A fresh thread object for a created thread, with its record and ordinal, or none (the
/// program-visible create failure): a record never used, or one whose thread has terminated and
/// that nothing references any more (nothing can reach it again). The ordinal (the record's index)
/// places the thread's TEB and user stack, so a reused record's pages are released before they are
/// mapped afresh. The object holds the thread's own reference.
fn free_thread(
    space: &mut crate::mem::vm::AddressSpace,
) -> Option<(crate::ob::ObjectId, &'static mut Thread, u32)> {
    let directory = crate::ob::directory();
    let id =
        directory.create_thread_in(crate::process::MAIN_THREAD as usize + 1..crate::ob::THREADS)?;
    let thread = directory.threads.record(id.index);
    let ordinal = id.index as u32;
    if thread.state() == ThreadState::Terminated {
        release_thread_pages(space, ordinal);
    }
    *thread = Thread::empty();
    Some((id, thread, ordinal))
}

/// Release the user pages a terminated thread at `ordinal` left mapped — its TEB page and its user
/// stack — through the address space (the record is about to be reused). Their regions stay: they
/// are the system's per-ordinal areas.
fn release_thread_pages(space: &mut crate::mem::vm::AddressSpace, ordinal: u32) {
    use crate::mem::vm::CurrentPages;
    let decommitted = space.decommit(
        &mut CurrentPages,
        crate::user::thread_teb_va(ordinal),
        paging::PAGE_SIZE,
    );
    debug_assert!(decommitted.is_ok(), "a thread's TEB lies in its region");
    let stack_pages = crate::user::THREAD_STACK_PAGES * paging::PAGE_SIZE;
    let decommitted = space.decommit(
        &mut CurrentPages,
        thread_stack_top(ordinal) - stack_pages,
        stack_pages,
    );
    debug_assert!(decommitted.is_ok(), "a thread's stack lies in its region");
}

/// The top of the user stack of the thread at `ordinal`: the per-thread region's slot for it,
/// growing down.
fn thread_stack_top(ordinal: u32) -> u32 {
    crate::user::THREAD_STACK_REGION
        + ordinal * (crate::user::THREAD_STACK_PAGES * paging::PAGE_SIZE)
}

/// Create a child thread: a pooled record attached to the current process, its gate-stack slot, TEB
/// page and user stack mapped, its startup ladder planted — but not readied: the service readies it
/// once the caller's handle exists, so a thread never runs before its creator holds a way to wait
/// on it. Returns the thread's object (holding the thread's own reference), its record, and its
/// identifier (its pool ordinal, nonzero and stable for the thread's life). None is the
/// program-visible failure: no free record.
pub fn spawn(
    process: &mut Process,
    start: u32,
    parameter: u32,
) -> Option<(crate::ob::ObjectId, *mut Thread, u32)> {
    let (object, thread, ordinal) = free_thread(process.vm())?;
    // An exited thread's stack is released before a slot is taken, so its slot is free to reuse
    // (unmapped, not merely marked free).
    if let Some(dead) = process.dead_stack.take() {
        release_gate_stack(process, dead);
    }

    // Attach: the scheduling data, the process-list membership, and the wait discipline's fixed
    // wiring.
    // SAFETY: the record is static (its final address), and the process's thread list is
    // initialized.
    unsafe { thread.attach_to(&mut process.sched) };

    // The gate-stack slot: this thread's kernel stack.
    let slot = process.gate_slots.allocate();
    // SAFETY: the slot pages map into the current address space, above the slot's unmapped guard
    // page.
    let frames = unsafe { paging::map_gate_slot(slot as u32) };
    thread.gate_slot = slot;
    thread.gate_frames = frames;
    thread.initial_stack = paging::gate_slot_top(slot as u32);

    // The TEB page: the per-thread region, one page, zeroed.
    use crate::mem::vm::{self, PAGE_READWRITE};
    thread.teb_va = crate::user::thread_teb_va(ordinal);
    vm::map_zeroed(process.vm(), thread.teb_va, PAGE_READWRITE);

    // The user stack: two zeroed pages, growing down from the per-thread region's top for this
    // ordinal.
    let stack_top = thread_stack_top(ordinal);
    let mut top_frame = 0;
    for page in 0..crate::user::THREAD_STACK_PAGES {
        let base = stack_top - (page + 1) * 0x1000;
        let frame = vm::map_zeroed(process.vm(), base, PAGE_READWRITE);
        if page == 0 {
            top_frame = frame;
        }
    }

    // The trampoline's return address and the parameter, planted under the entry stack: the user
    // function sees its LPVOID at [esp+4] per the calling convention, and its `ret` lands on the
    // thread-exit trampoline, never in the void.
    let trampoline = crate::compat::kernel32::thread_exit_trampoline();
    paging::write_frame(top_frame, 0xFF8, &trampoline.to_le_bytes());
    paging::write_frame(top_frame, 0xFFC, &parameter.to_le_bytes());

    // The startup ladder: the stub calls the system routine (a no-op — nothing between thread start
    // and its user code exists yet), then enters ring 3 at the start address.
    let params = crate::sched::startup::StartParams {
        system_routine: user_thread_startup as u32,
        start_routine: start,
        start_context: parameter,
        user: Some(crate::sched::startup::UserStart {
            eip: start,
            esp: stack_top - 8,
        }),
    };
    // SAFETY: the thread's `initial_stack` names its freshly mapped, empty kernel-stack slot.
    unsafe { crate::sched::startup::plant(thread, &params) };

    Some((object, thread as *mut Thread, ordinal))
}

/// A user thread's system routine: the kernel function the startup stub calls before entering the
/// thread's user context. A never-run thread has had no delivery window, so a kernel APC queued on
/// it before its first dispatch — a suspend, or a creation suspended — runs here, before its first
/// user instruction; the stub's tail then carries the thread into its user code.
unsafe extern "C" fn user_thread_startup(_start: u32, _parameter: u32) {
    crate::sched::idle::dispatcher().deliver_pending_apcs();
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
    // SAFETY: the running thread, live; the body's waits return on this same thread.
    unsafe { (*crate::sched::idle::dispatcher().current_thread()).enter_critical_region() };
    let result = body();
    // SAFETY: as above.
    let thread = unsafe { &mut *crate::sched::idle::dispatcher().current_thread() };
    if thread.leave_critical_region() && thread.termination_pending() {
        let end = crate::process::current()
            .handed_end()
            .expect("a deferred termination has the process's end to hand on");
        end_thread(ThreadEnd::Terminated(end))
    }
    result
}

/// The one exit path, in its order: the exit service's or a fault's terminations of the other
/// threads first (the process's end passing to any that finish a critical region first); then the
/// per-thread teardown (the gate stack is parked for release from another stack, and an earlier
/// exit's parked stack is released); then, for the last thread, every handle closes; then the
/// thread object signals and its waiters wake, the thread leaves the process list and is
/// Terminated, and its own reference on its object goes; then, for the last thread, the process's
/// end — the report, the end recorded for the idle thread's reap. The switch away ends the
/// thread's timeline.
fn end_thread(end: ThreadEnd) -> ! {
    let dispatcher = crate::sched::idle::dispatcher();
    // SAFETY: the running thread, live and exclusive in the gate.
    let current = dispatcher.current_thread();
    // The ending thread's process, resolved once: past the switch-away bookkeeping below, the
    // running thread is no longer this one.
    let process = crate::process::current_mut();
    let others = process.sched.stack_count() - 1;
    let mut plan = exit::plan(end, others);
    // SAFETY: the running thread, live.
    assert!(
        !unsafe { &*current }.in_critical_region(),
        "a thread ends outside critical regions"
    );

    // The process's end, step 1 (see `process`'s notes on its order): every other thread is
    // terminated, without running again.
    if plan.terminate_others {
        let deferred = terminate_others(process, current);
        let (after, handed) = exit::hand_over(plan, deferred);
        plan = after;
        if let Some(end) = handed {
            process.hand_end(end);
        }
    }

    // The per-thread teardown first. The gate stack is the one this code runs on, so it cannot be
    // unmapped here: it is parked as the process's dead stack, released by whoever next runs on
    // another stack. An earlier exit's parked stack is released now (it is not this one).
    {
        // SAFETY: the running thread, live.
        let thread = unsafe { &*current };
        if let Some(previous) = process
            .dead_stack
            .park((thread.gate_slot, thread.gate_frames))
        {
            release_gate_stack(process, previous);
        }
    }

    // The process's end, step 2: every handle closes while this thread still runs, as CloseHandle
    // would — the objects go with their last references.
    if plan.process_end.is_some() {
        process.release_handles();
    }

    // The APC queue closes before the scheduler teardown.
    // SAFETY: the running thread, live and exclusive in the gate.
    unsafe { crate::sched::apc::close_apc_queue(&mut *current) };

    // The thread object signals and its waiters wake (the satisfy step inside terminate), the
    // thread leaves the process list, and the processor's next thread is selected and takes the
    // current slot before the switch (the swap's caller-side install).
    let selected = dispatcher.terminate();
    dispatcher.enter(selected);
    // The thread has ended: its own reference on its object goes (the record is reused only once
    // nothing holds it, and never before this code is off its stack: a record is renewed by a
    // create, which no thread runs before the switch away).
    crate::ob::end_thread_references(current);

    // The last-thread route: a process with no threads must not linger — the last thread's end is
    // the process's end. The idle thread tears it down once this thread is off its stack.
    if let Some(end) = plan.process_end {
        assert_eq!(
            process.sched.stack_count(),
            0,
            "the process ends with its last thread"
        );
        crate::serial_println!("{}", exit::EndReport { end, leg: leg() });
        process.set_end(end);
    }

    // The switch away, at the dispatch level; the exiting thread's timeline ends at the swap, so
    // its outstanding raises — this one included — are written off.
    let _previous = crate::interrupt::irql::state_mut().raise(crate::interrupt::irql::DISPATCH);
    crate::interrupt::irql::state_mut().write_off_thread();
    // SAFETY: the selected thread is the selection discipline's own (a woken waiter, a ready
    // thread, or the idle fallback).
    unsafe { crate::sched::switch::swap_context(current, selected) };
    unreachable!("a terminated thread never resumes")
}

/// Terminate every thread of `process` (the current one) but `current` (the running thread), none
/// of them running again: each is taken off whatever holds it and retired, then its gate stack —
/// not the one this code runs on — is released here, and its references go (a wait it was in never
/// returns). A thread inside a critical region is the exception: it runs on to the region's end and
/// ends itself there. Returns how many were deferred so.
fn terminate_others(process: &mut Process, current: *mut Thread) -> u16 {
    let dispatcher = crate::sched::idle::dispatcher();
    let mut deferred = 0;
    loop {
        let other = process.sched.first_thread_except(current);
        if other.is_null() {
            return deferred;
        }
        // SAFETY: an attached thread of this process, off the processor; the record outlives its
        // termination (it is renewed only by a create, which nothing runs here).
        let other = unsafe { &mut *other };
        match dispatcher.request_termination(other) {
            Termination::Done => {
                release_gate_stack(process, (other.gate_slot, other.gate_frames));
                // It never returns from whatever it was in: its wait's references and its own go.
                crate::ob::end_thread_references(other);
            }
            Termination::Deferred => deferred += 1,
        }
    }
}

/// The suite leg the current process runs as, for its report; none on a one-process boot.
fn leg() -> Option<exit::Leg> {
    #[cfg(feature = "run-process-suite")]
    {
        Some(crate::process::runner::current_leg())
    }
    #[cfg(not(feature = "run-process-suite"))]
    {
        None
    }
}

/// Whether the running thread is its process's main thread — the thread the process was entered
/// on, whose stack carries no thread-exit trampoline.
pub fn on_main_thread() -> bool {
    let current = crate::sched::idle::dispatcher().current_thread();
    core::ptr::eq(current, crate::process::current().main_thread())
}

/// Release an exited thread's gate stack: unmap the slot's pages from the (current) process
/// directory, return the frames to the frame database, and the slot to the ledger. Never the stack
/// the processor runs on: a stack is parked by its own exit and released only from another stack.
fn release_gate_stack(process: &mut Process, (slot, frames): crate::process::GateStack) {
    use crate::mem::frame::FrameState;
    let mapped = paging::unmap_gate_slot(slot as u32);
    debug_assert_eq!(
        mapped, frames,
        "the slot maps the frames its thread recorded"
    );
    process.gate_slots.release(slot);
    for frame in frames {
        crate::mem::bootmem::with_frame_db(|db| {
            db.release(frame / paging::PAGE_SIZE, FrameState::Free);
        });
    }
}

/// Make the current process's main thread schedulable at `entry`: plant its startup ladder (the
/// same frame shape a child gets) and ready it. The next switch away from the idle thread enters
/// it.
pub fn start_main_thread(entry: u32, user_esp: u32) {
    // The main thread's gate slot, TEB page and stack top were taken at process start; only the
    // ladder is missing.
    let thread = crate::process::current().main_thread();
    let params = crate::sched::startup::StartParams {
        system_routine: user_thread_startup as u32,
        start_routine: entry,
        start_context: 0,
        user: Some(crate::sched::startup::UserStart {
            eip: entry,
            esp: user_esp,
        }),
    };
    // SAFETY: the thread's `initial_stack` names its mapped, empty kernel-stack slot (nothing has
    // entered a gate on it yet).
    unsafe { crate::sched::startup::plant(thread, &params) };

    let dispatcher: &'static mut Dispatcher = crate::sched::idle::dispatcher();
    dispatcher.make_ready(thread);
}

/// The boot's ring-3 entry, the only one: start the current process's main thread and enter the
/// idle loop — the first switch away from idle is into this thread. Never returns.
pub fn enter_as_main_thread(entry: u32, user_esp: u32) -> ! {
    start_main_thread(entry, user_esp);
    crate::sched::idle::idle_loop()
}
