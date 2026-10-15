//! The smoke-subset thread surface: child-thread creation, the object pools, and the thread-exit
//! path.
//!
//! CreateThread behind the synthesized kernel32: a child takes a thread record from the pool, a
//! gate-stack slot from the process's window, its own TEB page and user stack from the per-thread
//! regions, and a startup ladder the context switch enters — the same machinery the main thread's
//! boot entry uses. The child's user function receives its parameter per the calling convention
//! (planted at [esp+4] under a return address that is the kernel's thread-exit trampoline), so
//! returning from the function terminates the thread with the return value as the exit status.
//!
//! The exit path, in its order: the per-thread teardown first (the gate stack is parked for
//! release from another stack, and an earlier exit's parked stack is released), then the thread
//! object signals and its waiters wake, then the thread leaves the process list and
//! is Terminated, then the last-thread check routes either to the thread's end or the process's —
//! the last thread's exit is the process's exit.

use core::ptr::addr_of_mut;

use crate::mem::paging;
use crate::process::Process;
use crate::sched::dispatcher::Dispatcher;
use crate::sched::thread::{Thread, ThreadState};

/// The child-thread pool: fixed, one record per live child. Only never-used records are handed out;
/// a terminated child's record is not reused (nothing reclaims it yet).
static mut THREAD_POOL: [Thread; 3] = [const { Thread::empty() }; 3];

/// The number of pages a per-thread user stack spans (the same two pages the main thread's stack
/// has).
const THREAD_STACK_PAGES: u32 = 2;

/// A free child-thread record from the pool, or none (the program-visible create failure).
fn free_thread() -> Option<(&'static mut Thread, u32)> {
    // SAFETY: single CPU; the pool is kernel state whose accessors run serialized by the gate.
    let pool = unsafe { &mut *addr_of_mut!(THREAD_POOL) };
    pool.iter_mut()
        .enumerate()
        .find(|(_, thread)| thread.state() == ThreadState::Initialized)
        .map(|(index, thread)| (thread, index as u32 + 1))
}

/// The event pool: fixed, one record per created event. Events live until the process's teardown (a
/// close releases only the table's claim), so allocation is a bump and exhaustion is the
/// program-visible create failure.
static mut EVENT_POOL: [crate::sched::event::Event; 8] = [const {
    crate::sched::event::Event::new(crate::sched::event::EventKind::Notification, false)
}; 8];

/// The event pool's next-free index.
static mut EVENT_POOL_NEXT: usize = 0;

/// A fresh event from the pool, initialized for `kind` and `signaled`, or none (the pool is
/// exhausted).
pub fn new_event(
    kind: crate::sched::event::EventKind,
    signaled: bool,
) -> Option<&'static mut crate::sched::event::Event> {
    // SAFETY: single CPU; the pool and its index are kernel state whose accessors run serialized by
    // the gate.
    let next = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(EVENT_POOL_NEXT)) };
    if next >= 8 {
        return None;
    }
    // SAFETY: as above; the index advances by exactly one per event, never past the pool.
    unsafe {
        core::ptr::write_volatile(core::ptr::addr_of_mut!(EVENT_POOL_NEXT), next + 1);
        let event = &mut *addr_of_mut!(EVENT_POOL);
        let event = &mut event[next];
        *event = crate::sched::event::Event::new(kind, signaled);
        event.init();
        Some(event)
    }
}

/// Create a child thread: a pooled record attached to the current process, its gate-stack slot, TEB
/// page and user stack mapped, its startup ladder planted — but not readied: the service readies it
/// once the caller's handle exists, so a thread never runs before its creator holds a way to wait
/// on it. Returns the thread and its identifier (its pool ordinal, stable and nonzero for the
/// thread's life). None is the program-visible failure: no free record.
pub fn spawn(start: u32, parameter: u32) -> Option<(*mut Thread, u32)> {
    let (thread, ordinal) = free_thread()?;
    let process = crate::process::current_mut();
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
    thread.teb_va = crate::user::thread_teb_va(ordinal);
    let teb_frame = paging::allocate_frame_phys();
    paging::init_frame(teb_frame, 0, &[]);
    paging::map_user_page(thread.teb_va, teb_frame, true);

    // The user stack: two zeroed pages, growing down from the per-thread region's top for this
    // ordinal.
    let stack_top = crate::user::THREAD_STACK_REGION + ordinal * (THREAD_STACK_PAGES * 0x1000);
    let mut top_frame = 0;
    for page in 0..THREAD_STACK_PAGES {
        let base = stack_top - (page + 1) * 0x1000;
        let frame = paging::allocate_frame_phys();
        if page == 0 {
            top_frame = frame;
        }
        paging::init_frame(frame, 0, &[]);
        paging::map_user_page(base, frame, true);
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

    Some((thread as *mut Thread, ordinal))
}

/// A user thread's system routine: the kernel function the startup stub calls before entering the
/// thread's user context. Nothing needs to happen here yet; the stub's tail carries the thread
/// straight into its user code.
unsafe extern "C" fn user_thread_startup(_start: u32, _parameter: u32) {}

/// The thread-exit path: the exit status in hand, tear the calling thread down, signal its waiters,
/// and switch to the next thread — never returning. The last thread's exit routes to the process's
/// exit.
pub fn exit_thread(exit_status: i32) -> ! {
    let dispatcher = crate::sched::idle::dispatcher();
    // SAFETY: the running thread, live and exclusive in the gate.
    let current = dispatcher.current_thread();

    // The per-thread teardown first. The gate stack is the one this code runs on, so it cannot be
    // unmapped here: it is parked as the process's dead stack, released by whoever next runs on
    // another stack. An earlier exit's parked stack is released now (it is not this one).
    {
        let process = crate::process::current_mut();
        // SAFETY: the running thread, live.
        let thread = unsafe { &*current };
        if let Some(previous) = process
            .dead_stack
            .park((thread.gate_slot, thread.gate_frames))
        {
            release_gate_stack(process, previous);
        }
    }

    // The thread object signals and its waiters wake (the satisfy step inside terminate), the
    // thread leaves the process list, and the processor's next thread is selected and takes the
    // current slot before the switch (the swap's caller-side install).
    let selected = dispatcher.terminate();
    dispatcher.enter(selected);

    // The last-thread route: a process with no threads must not linger — the last exit is the
    // process's exit.
    let process = crate::process::current_mut();
    let last = process.sched.stack_count() == 0;
    if last {
        crate::serial_println!(
            "F2K: user process exited normally (exit code={})",
            exit_status as u32
        );
        process.handles_mut().clear();
    }

    // The switch away, at the dispatch level; the exiting thread's timeline ends at the swap.
    let _previous = crate::interrupt::irql::state_mut().raise(crate::interrupt::irql::DISPATCH);
    // SAFETY: the selected thread is the selection discipline's own (a woken waiter, a ready
    // thread, or the idle fallback).
    unsafe { crate::sched::switch::swap_context(current, selected) };
    unreachable!("a terminated thread never resumes")
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

/// The smoke boot's ring-3 entry: plant the main thread's startup ladder (the same frame shape a
/// child gets), make it schedulable, and enter the idle loop — the first switch away from idle is
/// into this thread. Never returns.
pub fn enter_as_main_thread(entry: u32, user_esp: u32) -> ! {
    let process: &'static mut Process = crate::process::current_mut();
    // The main thread's gate slot, TEB page and stack top were taken at process start; only the
    // ladder is missing.
    let thread = &mut process.main_thread;
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
    // entered a gate yet in this boot).
    unsafe { crate::sched::startup::plant(thread, &params) };

    let dispatcher: &'static mut Dispatcher = crate::sched::idle::dispatcher();
    dispatcher.make_ready(thread);
    crate::sched::idle::idle_loop()
}
