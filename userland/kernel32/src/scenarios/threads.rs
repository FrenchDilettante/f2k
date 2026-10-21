//! The threads group's thread and process exports: creation and termination,
//! suspension, the exit code, the priorities and boosts, the priority class and affinity, the TLS
//! indexes, and SetErrorMode — over the stand-in kernel's thread and process records
//! (`nt::threads`) and its virtual memory (`nt::host`).

use crate::base::last_error;
use crate::nt::threads::{process, HostThread, ENDED_THREAD, THREAD, THREADS, ZEROED_TLS};
use crate::process::{
    get_priority_class,
    set_error_mode,
    set_priority_class,
    set_process_affinity_mask,
    terminate_process,
};
use crate::thread::*;

const CURRENT_PROCESS: u32 = 0xFFFF_FFFF;
const CURRENT_THREAD: u32 = 0xFFFF_FFFE;
/// A handle naming nothing.
const BOGUS: u32 = 0x1234;
/// The sentinel the fixtures arm the last error with ("-" when it survives).
const UNTOUCHED: u32 = 0xF2F2_F2F2;

fn arm() {
    crate::base::set_last_error(UNTOUCHED);
}

fn thread(handle: u32) -> HostThread {
    THREADS.with(|threads| {
        threads
            .borrow()
            .iter()
            .find(|(h, _)| *h == handle)
            .unwrap()
            .1
    })
}

/// SuspendThread and ResumeThread return the previous count; an ended thread refuses a suspend
/// (ERROR_ACCESS_DENIED) and resumes as never suspended (0, the last error untouched); a bad handle
/// is (DWORD)-1 with ERROR_INVALID_HANDLE — the threads fixture's suspend block.
#[test]
fn suspend_counts_and_refusals() {
    assert_eq!((suspend_thread(THREAD), suspend_thread(THREAD)), (0, 1));
    assert_eq!(
        (
            resume_thread(THREAD),
            resume_thread(THREAD),
            resume_thread(THREAD)
        ),
        (2, 1, 0)
    );
    arm();
    assert_eq!(suspend_thread(ENDED_THREAD), u32::MAX);
    assert_eq!(last_error(), 5);
    arm();
    assert_eq!(resume_thread(ENDED_THREAD), 0);
    assert_eq!(last_error(), UNTOUCHED);
    assert_eq!((suspend_thread(BOGUS), last_error()), (u32::MAX, 6));
    assert_eq!((resume_thread(BOGUS), last_error()), (u32::MAX, 6));
}

/// GetExitCodeThread: STILL_ACTIVE for a live thread, the status an ended one ended with; FALSE
/// with ERROR_INVALID_HANDLE for a bad handle, the code untouched.
#[test]
fn exit_codes_come_from_the_basic_information() {
    let mut code = 0;
    assert_eq!(
        unsafe { get_exit_code_thread(CURRENT_THREAD, &mut code) },
        1
    );
    assert_eq!(code, 259);
    assert_eq!(unsafe { get_exit_code_thread(ENDED_THREAD, &mut code) }, 1);
    assert_eq!(code, 7);
    code = 0xAA;
    assert_eq!(unsafe { get_exit_code_thread(BOGUS, &mut code) }, 0);
    assert_eq!((last_error(), code), (6, 0xAA));
}

/// The threads fixture's priority block: every documented level round-trips, TIME_CRITICAL and IDLE
/// as the saturation values; 3, -3 and 7 are ERROR_INVALID_PARAMETER and change nothing; 16 and -16
/// pass as given. A bad handle is THREAD_PRIORITY_ERROR_RETURN.
#[test]
fn priorities_round_trip() {
    for level in [-15, -2, -1, 0, 1, 2, 15] {
        assert_eq!(set_thread_priority(CURRENT_THREAD, level), 1);
        assert_eq!(get_thread_priority(CURRENT_THREAD), level);
    }
    assert_eq!(
        thread(CURRENT_THREAD).base,
        16,
        "TIME_CRITICAL is the saturation value"
    );
    for invalid in [3, -3, 7] {
        arm();
        assert_eq!(set_thread_priority(CURRENT_THREAD, invalid), 0);
        assert_eq!(last_error(), 87);
    }
    assert_eq!(get_thread_priority(CURRENT_THREAD), 15);
    for saturation in [16, -16] {
        arm();
        assert_eq!(set_thread_priority(CURRENT_THREAD, saturation), 1);
        assert_eq!(last_error(), UNTOUCHED);
    }
    assert_eq!((get_thread_priority(BOGUS), last_error()), (0x7FFF_FFFF, 6));
    assert_eq!((set_thread_priority(BOGUS, 0), last_error()), (0, 6));
}

/// The boosts: enabled at the start, disabled and re-enabled; a bad handle fails, the value
/// untouched.
#[test]
fn boosts_disable_and_enable() {
    let mut disabled = 7;
    assert_eq!(
        unsafe { get_thread_priority_boost(CURRENT_THREAD, &mut disabled) },
        1
    );
    assert_eq!(disabled, 0);
    assert_eq!(set_thread_priority_boost(CURRENT_THREAD, 5), 1);
    assert_eq!(
        unsafe { get_thread_priority_boost(CURRENT_THREAD, &mut disabled) },
        (1)
    );
    assert_eq!(disabled, 1, "any nonzero BOOL disables");
    assert_eq!(set_thread_priority_boost(CURRENT_THREAD, 0), 1);
    assert!(!thread(CURRENT_THREAD).disable_boost);
    disabled = 7;
    assert_eq!(
        unsafe { get_thread_priority_boost(BOGUS, &mut disabled) },
        0
    );
    assert_eq!((last_error(), disabled), (6, 7));
    assert_eq!((set_thread_priority_boost(BOGUS, 1), last_error()), (0, 6));
}

/// The priority class: normal at the start, high once set, the first class flag of a bogus value
/// (0x12345 carries IDLE's), ERROR_INVALID_PARAMETER for a value naming none; another process's
/// handle is ERROR_INVALID_HANDLE.
#[test]
fn priority_classes_round_trip() {
    assert_eq!(get_priority_class(CURRENT_PROCESS), 0x20);
    arm();
    assert_eq!(set_priority_class(CURRENT_PROCESS, 0x80), 1);
    assert_eq!(
        (get_priority_class(CURRENT_PROCESS), last_error()),
        (0x80, UNTOUCHED)
    );
    assert_eq!(set_priority_class(CURRENT_PROCESS, 0x12345), 1);
    assert_eq!(get_priority_class(CURRENT_PROCESS), 0x40);
    assert_eq!(
        (set_priority_class(CURRENT_PROCESS, 1), last_error()),
        (0, 87)
    );
    assert_eq!((set_priority_class(BOGUS, 0x20), last_error()), (0, 6));
    assert_eq!((get_priority_class(BOGUS), last_error()), (0, 6));
}

/// SetProcessAffinityMask: the one processor's mask; an empty mask or one naming a processor the
/// system lacks is ERROR_INVALID_PARAMETER, another handle ERROR_INVALID_HANDLE.
#[test]
fn affinity_is_the_one_processor() {
    assert_eq!(set_process_affinity_mask(CURRENT_PROCESS, 1), 1);
    for mask in [0, 2, 3] {
        assert_eq!(
            (
                set_process_affinity_mask(CURRENT_PROCESS, mask),
                last_error()
            ),
            (0, 87),
            "{mask:#x}"
        );
    }
    assert_eq!((set_process_affinity_mask(BOGUS, 1), last_error()), (0, 6));
}

/// SetErrorMode returns the previous mode: zero at the start (the process's hard-error mode 1,
/// SEM_FAILCRITICALERRORS inverted), then what was set — the process stores it with that bit
/// inverted, as Windows 2000's does.
#[test]
fn error_modes_round_trip() {
    use crate::nt::threads::HARD_ERROR_MODE;
    assert_eq!(set_error_mode(0x8003), 0);
    assert_eq!(HARD_ERROR_MODE.with(|mode| mode.get()), 0x8002);
    assert_eq!(set_error_mode(0), 0x8003);
    assert_eq!(HARD_ERROR_MODE.with(|mode| mode.get()), 1);
}

/// The TLS indexes: the lowest free first, the caller's slot cleared; all 1088, then
/// TLS_OUT_OF_INDEXES with ERROR_NOT_ENOUGH_MEMORY; a free clears the index's slot in every thread
/// (ThreadZeroTlsCell) and gives it back; an index not allocated is ERROR_INVALID_PARAMETER. Each
/// call holds the PEB lock, and releases it.
#[test]
fn tls_indexes_allocate_and_free() {
    let teb = process().teb;
    crate::base::write(teb + 0xE10, 0x1111);
    arm();
    assert_eq!(tls_alloc(), 0);
    assert_eq!(
        (crate::base::read(teb + 0xE10), last_error()),
        (0, UNTOUCHED),
        "the caller's slot cleared"
    );
    for expected in 1..1088 {
        assert_eq!(tls_alloc(), expected);
    }
    assert_eq!((tls_alloc(), last_error()), (0xFFFF_FFFF, 8));
    crate::base::write(teb + 0xE10 + 4 * 5, 0x5555);
    arm();
    assert_eq!(tls_free(5), 1);
    assert_eq!(last_error(), UNTOUCHED);
    assert_eq!(crate::base::read(teb + 0xE10 + 4 * 5), 0);
    assert_eq!(ZEROED_TLS.with(|zeroed| zeroed.borrow().clone()), [5]);
    assert_eq!((tls_free(5), last_error()), (0, 87), "a double free");
    assert_eq!(tls_free(70), 1);
    for unallocated in [1088, 5000, u32::MAX] {
        assert_eq!(
            (tls_free(unallocated), last_error()),
            (0, 87),
            "{unallocated}"
        );
    }
    assert_eq!(
        (tls_alloc(), tls_alloc(), tls_alloc()),
        (5, 70, 0xFFFF_FFFF)
    );
    let depth = crate::nt::PEB_LOCK_DEPTH.with(|depth| depth.get());
    assert_eq!(depth, 0, "the PEB lock released");
}

/// The CreateThread the threads, memory and sched fixtures run on, as Windows 2000's
/// CreateRemoteThread makes it: the stack reserved (1 MiB by default), its top two pages committed
/// with a guard page below them; the CONTEXT starting at BaseThreadStartThunk with EAX the start
/// address, EBX the parameter and ESP one dword below the stack's base; NtCreateThread suspended,
/// on the INITIAL_TEB of that stack, then resumed; the thread id written back.
#[test]
fn create_thread_builds_the_stack_and_the_context() {
    use crate::nt::host::{vm_calls, BASE};
    use crate::nt::threads::{CREATED, CREATED_ID, CREATED_THREAD};
    let _ = vm_calls();
    CREATED.with(|created| created.borrow_mut().clear());
    let mut id = 0;
    let handle = unsafe { create_thread(core::ptr::null(), 0, 0x0040_1000, 0x1234, 0, &mut id) };
    assert_eq!((handle, id), (CREATED_THREAD, CREATED_ID as u32));
    let top = BASE + 0x10_0000;
    assert_eq!(
        vm_calls(),
        [
            ("allocate", 0, 0x10_0000, 0x2000),
            ("allocate", top - 0x3000, 0x3000, 0x1000),
            ("protect", top - 0x3000, 0x1000, 0x104),
        ]
    );
    let created = CREATED.with(|created| created.borrow_mut().pop().unwrap());
    assert_eq!(
        (
            created.access,
            created.inherit,
            created.process,
            created.suspended
        ),
        (0x001F_03FF, false, CURRENT_PROCESS, true)
    );
    let stack = InitialTeb {
        old_stack_base: 0,
        old_stack_limit: 0,
        stack_base: top,
        stack_limit: top - 0x2000,
        allocation_base: BASE,
    };
    assert_eq!(created.stack, stack);
    let word = |offset: usize| created.context[offset / 4];
    assert_eq!(word(0), 0x0001_0007, "CONTEXT_FULL");
    assert_eq!(
        (word(0xB8), word(0xB0), word(0xA4)),
        (0x7C4E_1000, 0x0040_1000, 0x1234),
        "EIP the thunk, EAX the start, EBX the parameter"
    );
    assert_eq!(
        (word(0xC4), word(0xC0)),
        (top as u32 - 4, 0x200),
        "ESP, EFLAGS"
    );
    assert_eq!(
        (word(0xBC), word(0xC8), word(0x98), word(0x94), word(0x90)),
        (0x1B, 0x23, 0x23, 0x23, 0x3B)
    );
    assert_eq!(thread(CREATED_THREAD).suspend_count, 0, "resumed");
}

/// CREATE_SUSPENDED leaves the thread suspended; an inheritable SECURITY_ATTRIBUTES makes an
/// inheritable handle; a null identifier pointer is not written; the stack size sizes the
/// reservation.
#[test]
fn create_thread_honours_its_flags() {
    use crate::nt::host::vm_calls;
    use crate::nt::threads::{CREATED, CREATED_THREAD};
    let _ = vm_calls();
    let security = crate::base::SecurityAttributes {
        length: 12,
        security_descriptor: core::ptr::null(),
        inherit_handle: 1,
    };
    let handle = unsafe {
        create_thread(
            &security,
            0x40_0000,
            0x0040_1000,
            0,
            4,
            core::ptr::null_mut(),
        )
    };
    assert_eq!(handle, CREATED_THREAD);
    let created = CREATED.with(|created| created.borrow_mut().pop().unwrap());
    assert!(created.inherit && created.suspended);
    assert_eq!(
        THREADS.with(|threads| threads
            .borrow()
            .iter()
            .rev()
            .find(|(h, _)| *h == CREATED_THREAD)
            .unwrap()
            .1
            .suspend_count),
        1
    );
    assert_eq!(vm_calls()[0], ("allocate", 0, 0x40_0000, 0x2000));
}

/// A refused create gives the stack back and returns NULL with the status's error: no room for the
/// stack (ERROR_NOT_ENOUGH_MEMORY), or NtCreateThread's refusal (a full handle table's
/// STATUS_INSUFFICIENT_RESOURCES).
#[test]
fn create_thread_refusals_give_the_stack_back() {
    use crate::nt::host::{vm_calls, BASE, FAIL_NEXT};
    use crate::nt::threads::CREATE_FAILS;
    let _ = vm_calls();
    FAIL_NEXT.with(|fail| fail.set(0xC000_0017));
    assert_eq!(
        unsafe {
            create_thread(
                core::ptr::null(),
                0,
                0x0040_1000,
                0,
                0,
                core::ptr::null_mut(),
            )
        },
        0
    );
    assert_eq!(last_error(), 8);
    assert_eq!(vm_calls().len(), 1, "nothing reserved, nothing to free");
    CREATE_FAILS.with(|fail| fail.set(0xC000_009A));
    assert_eq!(
        unsafe {
            create_thread(
                core::ptr::null(),
                0,
                0x0040_1000,
                0,
                0,
                core::ptr::null_mut(),
            )
        },
        0
    );
    assert_eq!(last_error(), 1450);
    assert_eq!(vm_calls().last(), Some(&("free", BASE, 0, 0x8000)));
}

/// TerminateThread: TRUE for a live thread; an ended one is ERROR_INVALID_PARAMETER (the threads
/// fixture's exit block), a handle naming nothing ERROR_INVALID_HANDLE, and a null handle names no
/// thread (never the caller). TerminateProcess reaches only the calling process.
#[test]
fn terminations_reach_what_their_handles_name() {
    use crate::nt::threads::TERMINATED;
    TERMINATED.with(|terminated| terminated.borrow_mut().clear());
    assert_eq!(terminate_thread(THREAD, 88), 1);
    assert_eq!(thread(THREAD).exit_status, 88);
    assert_eq!((terminate_thread(THREAD, 89), last_error()), (0, 87));
    assert_eq!((terminate_thread(BOGUS, 1), last_error()), (0, 6));
    assert_eq!((terminate_thread(0, 1), last_error()), (0, 6));
    assert_eq!((terminate_process(BOGUS, 3), last_error()), (0, 6));
    assert_eq!((terminate_process(0, 3), last_error()), (0, 6));
    assert_eq!(terminate_process(CURRENT_PROCESS, 3), 1);
    let calls = TERMINATED.with(|terminated| terminated.borrow().clone());
    assert_eq!(
        calls,
        [
            ("thread", THREAD, 88),
            ("thread", THREAD, 89),
            ("thread", BOGUS, 1),
            ("process", BOGUS, 3),
            ("process", CURRENT_PROCESS, 3)
        ]
    );
}
