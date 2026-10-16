//! Threads / sync: thread creation, suspension, and priority; unnamed events; waits and sleeps in
//! milliseconds over the kernel's 100 ns intervals; the millisecond tick count. The scenarios pin
//! how each export translates onto the boundary, and the fixtures' captured outputs where the
//! translation shows (the sleep and wait spans, the suspend counts).

use crate::compat::harness::boundary::{EventType, KernelBoundary};
use crate::compat::harness::fake::Call;
use crate::compat::harness::surface::{assert_argument_blocks, Fixture};

pub const MEMBERS: &[&str] = &[
    "CreateThread",
    "CreateEventA",
    "SetEvent",
    "Sleep",
    "WaitForSingleObject",
    "GetTickCount",
    "SetThreadPriority",
    "SuspendThread",
    "ResumeThread",
    "GetCurrentThreadId",
    "GetCurrentProcessId",
    "GetCurrentThread",
    "InterlockedIncrement",
    "InterlockedDecrement",
    "InterlockedExchange",
    "InterlockedExchangeAdd",
    "InterlockedCompareExchange",
    "DuplicateHandle",
    "ExitThread",
    "GetExitCodeThread",
    "GetPriorityClass",
    "GetThreadPriority",
    "GetThreadPriorityBoost",
    "SetPriorityClass",
    "SetThreadPriorityBoost",
    "TerminateThread",
    "TlsAlloc",
    "TlsFree",
    "TlsGetValue",
    "TlsSetValue",
    "DeleteCriticalSection",
    "EnterCriticalSection",
    "InitializeCriticalSection",
    "LeaveCriticalSection",
    "TryEnterCriticalSection",
];

const INFINITE: u32 = 0xFFFF_FFFF;
const WAIT_OBJECT_0: u32 = 0;
const WAIT_TIMEOUT: u32 = 0x102;
const WAIT_FAILED: u32 = 0xFFFF_FFFF;
const CREATE_SUSPENDED: u32 = 0x4;
const STACK_SIZE_PARAM_IS_A_RESERVATION: u32 = 0x1_0000;
const STDOUT: u32 = 0x7;
const START: u32 = 0x0040_1000;

/// A thread created through the boundary (setup, not under test).
fn thread(fixture: &mut Fixture) -> u32 {
    let (handle, _) = fixture.kernel.nt_create_thread(START, 0, false).unwrap();
    fixture.kernel.clear_calls();
    handle
}

/// An event created through the boundary (setup, not under test).
fn event(fixture: &mut Fixture, event_type: EventType, signaled: bool) -> u32 {
    let handle = fixture
        .kernel
        .nt_create_event(event_type, signaled)
        .unwrap();
    fixture.kernel.clear_calls();
    handle
}

/// Every member pops the block its callers push. Ledger: threads.
#[test]
#[ignore = "ledger threads: not switched on"]
fn threads_argument_blocks_match_the_prototypes() {
    assert_argument_blocks(MEMBERS);
}

/// CreateEventA: bManualReset picks the type, bInitialState the state; the attributes are ignored.
/// The return is the new handle. Ledger: threads/CreateEventA.
#[test]
#[ignore = "ledger threads/CreateEventA: the existing path creates in the live handle table \
            (target-only)"]
fn create_event_a_creates_by_type_and_state() {
    let mut fixture = Fixture::new();
    let attributes = fixture.buffer(12);
    let auto = fixture.call("CreateEventA", &[0, 0, 0, 0]);
    let manual = fixture.call("CreateEventA", &[attributes, 1, 1, 0]);
    assert_eq!((auto, manual), (4, 8));
    assert_eq!(
        fixture.kernel.calls(),
        [
            Call::CreateEvent {
                event_type: EventType::Synchronization,
                initial_state: false
            },
            Call::CreateEvent {
                event_type: EventType::Notification,
                initial_state: true
            },
        ]
    );
    assert!(!fixture.kernel.event_signaled(auto));
    assert!(fixture.kernel.event_signaled(manual));
}

/// CreateEventA refuses a name (no named objects on this surface) before the kernel is asked, and
/// a full handle table; both return NULL. Ledger: threads/CreateEventA.
#[test]
#[ignore = "ledger threads/CreateEventA: the existing path creates in the live handle table \
            (target-only)"]
fn create_event_a_refuses_names_and_a_full_table() {
    let mut fixture = Fixture::new();
    let name = fixture.c_string(b"ping");
    assert_eq!(fixture.call("CreateEventA", &[0, 0, 0, name]), 0);
    assert_eq!(fixture.kernel.calls(), []);
    for _ in 1..crate::sched::object::HANDLE_SLOTS {
        assert_ne!(fixture.call("CreateEventA", &[0, 0, 0, 0]), 0);
    }
    assert_eq!(fixture.call("CreateEventA", &[0, 0, 0, 0]), 0);
}

/// SetEvent signals the event and returns TRUE; a thread, a closed or foreign value, and a console
/// handle — even one whose bits name the event's slot — are FALSE and signal nothing. Ledger:
/// threads/SetEvent.
#[test]
#[ignore = "ledger threads/SetEvent: the existing path signals through the live handle table \
            (target-only)"]
fn set_event_signals_events_only() {
    let mut fixture = Fixture::new();
    let event = event(&mut fixture, EventType::Synchronization, false);
    assert_eq!(event >> 2, STDOUT >> 2);
    let thread = thread(&mut fixture);
    for handle in [STDOUT, thread, 0x40, 0] {
        assert_eq!(fixture.call("SetEvent", &[handle]), 0, "{handle:#x}");
    }
    assert!(!fixture.kernel.event_signaled(event));
    assert_eq!(fixture.call("SetEvent", &[event]), 1);
    assert!(fixture.kernel.event_signaled(event));
}

/// WaitForSingleObject returns the wait status raw: WAIT_OBJECT_0 on a signaled object (an
/// auto-reset event's signal consumed), WAIT_TIMEOUT when the timeout elapses first. Milliseconds
/// become 100 ns intervals; INFINITE waits forever. Ledger: threads/WaitForSingleObject.
#[test]
#[ignore = "ledger threads/WaitForSingleObject: the existing path waits in the scheduler \
            (target-only)"]
fn wait_for_single_object_converts_timeouts_and_returns_raw_statuses() {
    let mut fixture = Fixture::new();
    let auto = event(&mut fixture, EventType::Synchronization, true);
    let manual = event(&mut fixture, EventType::Notification, true);
    assert_eq!(
        fixture.call("WaitForSingleObject", &[auto, 0]),
        WAIT_OBJECT_0
    );
    assert_eq!(
        fixture.call("WaitForSingleObject", &[auto, 0]),
        WAIT_TIMEOUT
    );
    assert_eq!(
        fixture.call("WaitForSingleObject", &[auto, 100]),
        WAIT_TIMEOUT
    );
    assert_eq!(
        fixture.call("WaitForSingleObject", &[manual, INFINITE]),
        WAIT_OBJECT_0
    );
    assert_eq!(
        fixture.kernel.calls(),
        [
            Call::WaitForSingleObject {
                handle: auto,
                timeout: Some(0)
            },
            Call::WaitForSingleObject {
                handle: auto,
                timeout: Some(0)
            },
            Call::WaitForSingleObject {
                handle: auto,
                timeout: Some(1_000_000)
            },
            Call::WaitForSingleObject {
                handle: manual,
                timeout: None
            },
        ]
    );
}

/// A wait on a thread completes once the thread has exited (the pingpong fixture's final wait
/// returned 0). Ledger: threads/WaitForSingleObject.
#[test]
#[ignore = "ledger threads/WaitForSingleObject: the existing path waits in the scheduler \
            (target-only)"]
fn wait_for_single_object_on_an_exited_thread() {
    let mut fixture = Fixture::new();
    let thread = thread(&mut fixture);
    assert_eq!(
        fixture.call("WaitForSingleObject", &[thread, 0]),
        WAIT_TIMEOUT
    );
    fixture.kernel.exit_thread(thread);
    assert_eq!(
        fixture.call("WaitForSingleObject", &[thread, INFINITE]),
        WAIT_OBJECT_0
    );
}

/// WaitForSingleObject fails — WAIT_FAILED — on anything that names no waitable object: a file, a
/// closed or foreign value, a console handle whose bits name a live event's slot. Ledger:
/// threads/WaitForSingleObject.
#[test]
#[ignore = "ledger threads/WaitForSingleObject: the existing path waits in the scheduler \
            (target-only)"]
fn wait_for_single_object_fails_on_non_waitables() {
    let mut fixture = Fixture::new();
    let event = event(&mut fixture, EventType::Notification, true);
    assert_eq!(event >> 2, STDOUT >> 2);
    let file = fixture.kernel.nt_create_file(b"fileio.exe").unwrap();
    for handle in [STDOUT, file, 0x40, 0, 0xFFFF_FFFF] {
        assert_eq!(
            fixture.call("WaitForSingleObject", &[handle, 0]),
            WAIT_FAILED,
            "{handle:#x}"
        );
    }
    assert!(fixture.kernel.event_signaled(event), "the event untouched");
}

/// The sleep fixture's timed wait on a never-signaled event: WAIT_TIMEOUT after 100 ms by
/// GetTickCount. Ledger: threads/WaitForSingleObject.
#[test]
#[ignore = "ledger threads/WaitForSingleObject: the existing path waits in the scheduler \
            (target-only)"]
fn a_timed_wait_spans_its_timeout() {
    let mut fixture = Fixture::new();
    let never = event(&mut fixture, EventType::Synchronization, false);
    let before = fixture.call("GetTickCount", &[]);
    assert_eq!(
        fixture.call("WaitForSingleObject", &[never, 100]),
        WAIT_TIMEOUT
    );
    assert_eq!(fixture.call("GetTickCount", &[]) - before, 100);
}

/// Sleep parks for milliseconds as 100 ns intervals: 0 is the pure yield, INFINITE the longest
/// interval there is. The return is void (EAX zero). Ledger: threads/Sleep.
#[test]
#[ignore = "ledger threads/Sleep: the existing path delays in the scheduler (target-only)"]
fn sleep_converts_milliseconds() {
    let mut fixture = Fixture::new();
    for milliseconds in [200, 0, 5, INFINITE] {
        assert_eq!(fixture.call("Sleep", &[milliseconds]), 0);
    }
    assert_eq!(
        fixture.kernel.calls(),
        [
            Call::DelayExecution(2_000_000),
            Call::DelayExecution(0),
            Call::DelayExecution(50_000),
            Call::DelayExecution(i64::MIN),
        ]
    );
}

/// The sleep fixture's capture: Sleep(200) spans exactly 200 ms of GetTickCount. Ledger:
/// threads/Sleep.
#[test]
#[ignore = "ledger threads/Sleep: the existing path delays in the scheduler (target-only)"]
fn a_sleep_spans_its_milliseconds() {
    let mut fixture = Fixture::new();
    let before = fixture.call("GetTickCount", &[]);
    fixture.call("Sleep", &[200]);
    assert_eq!(fixture.call("GetTickCount", &[]) - before, 200);
}

/// GetTickCount: the tick count times the clock's interval, in milliseconds, floored once at the
/// read — a hair ahead of the round number (a tick is 10.0144 ms), never behind. Ledger:
/// threads/GetTickCount.
#[test]
#[ignore = "ledger threads/GetTickCount: the existing path reads the live clock (target-only)"]
fn get_tick_count_floors_ticks_to_milliseconds() {
    let mut fixture = Fixture::new();
    for (ticks, milliseconds) in [(0, 0), (1, 10), (9, 100), (90, 1001)] {
        fixture.kernel.advance(ticks);
        assert_eq!(
            fixture.call("GetTickCount", &[]),
            milliseconds,
            "{} ticks",
            fixture.kernel.ticks()
        );
    }
}

/// CreateThread starts a thread at the start address with the parameter and returns its handle;
/// the identifier is written when asked for; the attributes and the stack size are ignored, and so
/// is every creation flag but CREATE_SUSPENDED. Ledger: threads/CreateThread.
#[test]
#[ignore = "ledger threads/CreateThread: the existing path spawns in the scheduler (target-only)"]
fn create_thread_starts_the_thread() {
    let mut fixture = Fixture::new();
    let id = fixture.stage(&[0xCC; 4]);
    let attributes = fixture.buffer(12);
    let handle = fixture.call(
        "CreateThread",
        &[
            attributes,
            0x10_0000,
            START,
            0x1234,
            STACK_SIZE_PARAM_IS_A_RESERVATION,
            id,
        ],
    );
    assert_eq!(handle, 4);
    let record = fixture.kernel.thread(handle).expect("a thread handle");
    assert_eq!((record.start, record.parameter), (START, 0x1234));
    assert_eq!(record.suspend_count, 0);
    let written = record.id;
    assert_eq!(fixture.memory().u32_at(id), written);
    assert_ne!(written, 0);
    let second = fixture.call("CreateThread", &[0, 0, START, 0, 0, 0]);
    assert_ne!(second, 0);
    assert_ne!(fixture.kernel.thread(second).unwrap().id, written);
}

/// CREATE_SUSPENDED starts the thread with one suspend outstanding. Ledger: threads/CreateThread.
#[test]
#[ignore = "ledger threads/CreateThread: the existing path spawns in the scheduler (target-only)"]
fn create_thread_suspended() {
    let mut fixture = Fixture::new();
    let handle = fixture.call("CreateThread", &[0, 0, START, 0, CREATE_SUSPENDED, 0]);
    assert_eq!(fixture.kernel.thread(handle).unwrap().suspend_count, 1);
    assert_eq!(fixture.call("ResumeThread", &[handle]), 1);
}

/// CreateThread refuses, creating nothing, when the identifier pointer is not a user address or the
/// handle table is full; both return NULL. Ledger: threads/CreateThread.
#[test]
#[ignore = "ledger threads/CreateThread: the existing path spawns in the scheduler (target-only)"]
fn create_thread_refuses_bad_id_pointers_and_a_full_table() {
    let mut fixture = Fixture::new();
    assert_eq!(
        fixture.call("CreateThread", &[0, 0, START, 0, 0, 0x8000_0000]),
        0
    );
    assert_eq!(fixture.kernel.threads().len(), 0);
    for _ in 1..crate::sched::object::HANDLE_SLOTS {
        event(&mut fixture, EventType::Notification, false);
    }
    assert_eq!(fixture.call("CreateThread", &[0, 0, START, 0, 0, 0]), 0);
    assert_eq!(fixture.kernel.threads().len(), 0);
}

/// SetThreadPriority: the five band values (-2..=2) are base-priority increments as given;
/// THREAD_PRIORITY_TIME_CRITICAL (15) and THREAD_PRIORITY_IDLE (-15) are the saturation pins (+16,
/// -16). TRUE on success. Ledger: threads/SetThreadPriority.
#[test]
#[ignore = "ledger threads/SetThreadPriority: the existing path sets priorities in the scheduler \
            (target-only)"]
fn set_thread_priority_converts_values_to_increments() {
    let mut fixture = Fixture::new();
    let thread = thread(&mut fixture);
    for (value, increment) in [
        (0, 0),
        (1, 1),
        (-1, -1),
        (2, 2),
        (-2, -2),
        (15, 16),
        (-15, -16),
    ] {
        assert_eq!(
            fixture.call("SetThreadPriority", &[thread, value as u32]),
            1
        );
        assert_eq!(
            fixture.kernel.thread(thread).unwrap().base_priority,
            increment
        );
    }
}

/// SetThreadPriority refuses — FALSE, before the kernel is asked — any other value; and a handle
/// that names no thread. Ledger: threads/SetThreadPriority.
#[test]
#[ignore = "ledger threads/SetThreadPriority: the existing path sets priorities in the scheduler \
            (target-only)"]
fn set_thread_priority_refusals() {
    let mut fixture = Fixture::new();
    let thread = thread(&mut fixture);
    for value in [3, -3, 7, 14, 16, -16, i32::MAX, i32::MIN] {
        assert_eq!(
            fixture.call("SetThreadPriority", &[thread, value as u32]),
            0,
            "{value}"
        );
    }
    assert_eq!(fixture.kernel.calls(), []);
    let event = event(&mut fixture, EventType::Notification, false);
    for handle in [event, STDOUT, 0x40] {
        assert_eq!(fixture.call("SetThreadPriority", &[handle, 1]), 0);
    }
    assert_eq!(fixture.kernel.thread(thread).unwrap().base_priority, 0);
}

/// The suspend fixture's counts: SuspendThread on a running thread returns 0 (the previous count),
/// a resume after a second suspend returns 1; a thread nobody suspended resumes with 0. Ledger:
/// threads/SuspendThread.
#[test]
#[ignore = "ledger threads/SuspendThread: the existing path suspends in the scheduler \
            (target-only)"]
fn suspend_and_resume_return_previous_counts() {
    let mut fixture = Fixture::new();
    let worker = thread(&mut fixture);
    assert_eq!(fixture.call("ResumeThread", &[worker]), 0);
    assert_eq!(fixture.call("SuspendThread", &[worker]), 0);
    assert_eq!(fixture.call("SuspendThread", &[worker]), 1);
    assert_eq!(fixture.call("ResumeThread", &[worker]), 2);
    assert_eq!(fixture.call("ResumeThread", &[worker]), 1);
    assert_eq!(fixture.kernel.thread(worker).unwrap().suspend_count, 0);
}

/// SuspendThread refuses with (DWORD)-1: a handle naming no thread, an exited thread, and a thread
/// at the maximum suspend count. Ledger: threads/SuspendThread.
#[test]
#[ignore = "ledger threads/SuspendThread: the existing path suspends in the scheduler \
            (target-only)"]
fn suspend_thread_refusals() {
    let mut fixture = Fixture::new();
    let event = event(&mut fixture, EventType::Notification, false);
    let worker = thread(&mut fixture);
    let ended = thread(&mut fixture);
    fixture.kernel.exit_thread(ended);
    for handle in [event, STDOUT, 0x40, ended] {
        assert_eq!(
            fixture.call("SuspendThread", &[handle]),
            u32::MAX,
            "{handle:#x}"
        );
    }
    for count in 0..crate::sched::apc::MAX_SUSPEND_COUNT as u32 {
        assert_eq!(fixture.call("SuspendThread", &[worker]), count);
    }
    assert_eq!(fixture.call("SuspendThread", &[worker]), u32::MAX);
}

/// ResumeThread refuses with (DWORD)-1 on the same shapes: a handle naming no thread, an exited
/// thread. Ledger: threads/ResumeThread.
#[test]
#[ignore = "ledger threads/ResumeThread: the existing path resumes in the scheduler (target-only)"]
fn resume_thread_refusals() {
    let mut fixture = Fixture::new();
    let event = event(&mut fixture, EventType::Notification, false);
    let ended = thread(&mut fixture);
    fixture.kernel.exit_thread(ended);
    for handle in [event, STDOUT, 0x40, ended] {
        assert_eq!(
            fixture.call("ResumeThread", &[handle]),
            u32::MAX,
            "{handle:#x}"
        );
    }
}

/// ResumeThread's count: the suspend fixture's resume of a suspended worker returns 1. Ledger:
/// threads/ResumeThread.
#[test]
#[ignore = "ledger threads/ResumeThread: the existing path resumes in the scheduler (target-only)"]
fn resume_thread_releases_one_suspend() {
    let mut fixture = Fixture::new();
    let worker = thread(&mut fixture);
    fixture.call("SuspendThread", &[worker]);
    assert_eq!(fixture.call("ResumeThread", &[worker]), 1);
    assert_eq!(fixture.call("ResumeThread", &[worker]), 0);
}
