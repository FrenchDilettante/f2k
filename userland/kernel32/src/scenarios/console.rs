//! The console: the standard handles (the process parameters'), and the console calls kernel32
//! sends to the console server (CsrClientCallServer), against the host's stand-in, which serves the
//! console server's own rules (`rtl::console`) and records what the screen shows. The runtime
//! fixture's console block is the contract on the machine; these pin kernel32's side and the
//! server's answers.

use super::last_error;
use crate::console::*;
use crate::nt::LAST_WAITED;
use crate::sync::{
    close_handle, duplicate_handle, signal_object_and_wait, wait_for_multiple_objects,
    wait_for_single_object,
};

const STD_INPUT_HANDLE: u32 = -10i32 as u32;
const STD_OUTPUT_HANDLE: u32 = -11i32 as u32;
const STD_ERROR_HANDLE: u32 = -12i32 as u32;
const STDIN: u32 = 0x3;
const STDOUT: u32 = 0x7;
const STDERR: u32 = 0xB;
const INVALID_HANDLE_VALUE: u32 = 0xFFFF_FFFF;
const CURRENT_PROCESS: u32 = 0xFFFF_FFFF;
const DUPLICATE_SAME_ACCESS: u32 = 2;

/// The hello fixture's one console write: the CRT's text-mode stdout hands WriteFile CR LF.
const HELLO: &[u8] = b"Hello, world!\r\n";

/// GetStdHandle: the process parameters' handles — the capture's stdin 3, stdout 7, stderr 0xB.
#[test]
fn get_std_handle_replays_the_captured_handles() {
    for (which, handle) in [
        (STD_INPUT_HANDLE, STDIN),
        (STD_OUTPUT_HANDLE, STDOUT),
        (STD_ERROR_HANDLE, STDERR),
    ] {
        assert_eq!(get_std_handle(which), handle);
    }
}

/// GetStdHandle refuses any other type: INVALID_HANDLE_VALUE with ERROR_INVALID_HANDLE (Windows
/// 2000's BaseSetLastNTError(STATUS_INVALID_HANDLE); the runtime fixture's GetStdHandle(42)).
#[test]
fn get_std_handle_refuses_an_unknown_type_with_invalid_handle() {
    for which in [0, 42, -13i32 as u32, -9i32 as u32] {
        crate::base::set_last_error(0);
        assert_eq!(get_std_handle(which), INVALID_HANDLE_VALUE, "{which:#x}");
        assert_eq!(last_error(), 6, "{which:#x}");
    }
}

/// SetStdHandle replaces the parameters' handle, which GetStdHandle and the file calls'
/// pseudo-values then name; any other type is FALSE with ERROR_INVALID_HANDLE.
#[test]
fn set_std_handle_replaces_the_parameters_handle() {
    assert_eq!(set_std_handle(STD_OUTPUT_HANDLE, STDERR), 1);
    assert_eq!(get_std_handle(STD_OUTPUT_HANDLE), STDERR);
    console_writes();
    // SAFETY: the buffer and its length.
    assert_eq!(
        unsafe {
            crate::files::handle::write_file(
                STD_OUTPUT_HANDLE,
                HELLO.as_ptr(),
                5,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            )
        },
        1
    );
    assert_eq!(console_writes(), [(STDERR, HELLO[..5].to_vec())]);
    crate::base::set_last_error(0);
    assert_eq!(set_std_handle(42, STDOUT), 0);
    assert_eq!(last_error(), 6);
}

/// SetHandleCount reports the count it was given (the CRT's 0x20).
#[test]
fn set_handle_count_reports_its_argument() {
    assert_eq!(set_handle_count(0x20), 0x20);
    assert_eq!(set_handle_count(0), 0);
}

/// GetConsoleCP and GetConsoleOutputCP: the console's code pages, the OEM one (the runtime
/// fixture's 437 437).
#[test]
fn the_console_code_pages_are_the_oem_one() {
    assert_eq!((get_console_cp(), get_console_output_cp()), (437, 437));
}

/// GetConsoleMode: a fresh console's modes — the input handle's processed, line, echo and mouse
/// input, the output handles' processed output wrapping at the line's end; a handle naming no
/// console object is FALSE with ERROR_INVALID_HANDLE, the mode untouched.
#[test]
fn get_console_mode_answers_per_handle() {
    let mut mode = 0;
    for (handle, expected) in [(STDIN, 0x17), (STDOUT, 0x3), (STDERR, 0x3)] {
        // SAFETY: a dword.
        assert_eq!(unsafe { get_console_mode(handle, &mut mode) }, 1);
        assert_eq!(mode, expected, "{handle:#x}");
    }
    mode = 0xCC;
    for handle in [0xF, 0x13, STD_OUTPUT_HANDLE] {
        crate::base::set_last_error(0);
        // SAFETY: a dword.
        assert_eq!(
            unsafe { get_console_mode(handle, &mut mode) },
            0,
            "{handle:#x}"
        );
        assert_eq!((mode, last_error()), (0xCC, 6), "{handle:#x}");
    }
}

/// WriteConsoleA on stdout or stderr hands the bytes to the console, stores the full count, and
/// returns TRUE.
#[test]
fn write_console_a_writes_to_the_console() {
    console_writes();
    for handle in [STDOUT, STDERR] {
        let mut written = 0xCCCC_CCCC;
        // SAFETY: the buffer and its length, a dword.
        assert_eq!(
            unsafe {
                write_console_a(
                    handle,
                    HELLO.as_ptr(),
                    HELLO.len() as u32,
                    &mut written,
                    core::ptr::null(),
                )
            },
            1
        );
        assert_eq!(written, HELLO.len() as u32);
    }
    assert_eq!(
        console_writes(),
        [(STDOUT, HELLO.to_vec()), (STDERR, HELLO.to_vec())]
    );
}

/// WriteConsoleA without a count pointer still writes; a zero-length write succeeds, shows
/// nothing, and stores zero.
#[test]
fn write_console_a_count_pointer_and_empty_writes() {
    console_writes();
    // SAFETY: the buffer and its length.
    assert_eq!(
        unsafe {
            write_console_a(
                STDOUT,
                HELLO.as_ptr(),
                HELLO.len() as u32,
                core::ptr::null_mut(),
                core::ptr::null(),
            )
        },
        1
    );
    let mut written = 0xCCCC_CCCC;
    // SAFETY: as above, a dword.
    assert_eq!(
        unsafe { write_console_a(STDERR, HELLO.as_ptr(), 0, &mut written, core::ptr::null()) },
        1
    );
    assert_eq!(written, 0);
    assert_eq!(console_writes(), [(STDOUT, HELLO.to_vec())]);
}

/// WriteConsoleA refuses — FALSE, the count pointer untouched — stdin and every handle that names no
/// open output handle (ERROR_INVALID_HANDLE), and a reserved argument (WriteFile's OVERLAPPED:
/// ERROR_INVALID_PARAMETER).
#[test]
fn write_console_a_refuses_other_handles_and_reserved_arguments() {
    console_writes();
    let overlapped = [0u32; 5];
    let count = HELLO.len() as u32;
    for (handle, reserved, error) in [
        (STDIN, core::ptr::null(), 6),
        (INVALID_HANDLE_VALUE, core::ptr::null(), 6),
        (4, core::ptr::null(), 6),
        (0, core::ptr::null(), 6),
        (0xF, core::ptr::null(), 6),
        (STDOUT, overlapped.as_ptr() as *const u8, 87),
    ] {
        let mut written = 0xCCCC_CCCC;
        // SAFETY: the buffer and its length, a dword.
        assert_eq!(
            unsafe { write_console_a(handle, HELLO.as_ptr(), count, &mut written, reserved) },
            0,
            "{handle:#x}"
        );
        assert_eq!((written, last_error()), (0xCCCC_CCCC, error), "{handle:#x}");
    }
    assert!(console_writes().is_empty());
}

/// Console handles are the server's: CloseHandle closes one there (a second close, or a write on
/// it, is ERROR_INVALID_HANDLE), a standard handle's pseudo-value closing the parameters' handle;
/// DuplicateHandle makes a new one on the same console object in the calling process (the next
/// free one, 0xF first) and refuses another process (ERROR_INVALID_PARAMETER).
#[test]
fn console_handles_close_and_duplicate_at_their_server() {
    let mut target = 0;
    // SAFETY: a writable slot.
    assert_eq!(
        unsafe {
            duplicate_handle(
                CURRENT_PROCESS,
                STDOUT,
                CURRENT_PROCESS,
                &mut target,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            )
        },
        1
    );
    assert_eq!(target, 0xF);
    assert_eq!(close_handle(STD_OUTPUT_HANDLE), 1);
    crate::base::set_last_error(0);
    assert_eq!(close_handle(STDOUT), 0);
    assert_eq!(last_error(), 6);
    console_writes();
    let mut written = 0;
    // SAFETY: the buffer and its length, a dword.
    assert_eq!(
        unsafe { write_console_a(STDOUT, HELLO.as_ptr(), 1, &mut written, core::ptr::null()) },
        0
    );
    assert_eq!(
        unsafe { write_console_a(target, HELLO.as_ptr(), 1, &mut written, core::ptr::null()) },
        1
    );
    assert_eq!(console_writes(), [(0xF, HELLO[..1].to_vec())]);
    // SAFETY: a writable slot.
    assert_eq!(
        unsafe {
            duplicate_handle(
                0x44,
                STDERR,
                CURRENT_PROCESS,
                &mut target,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            )
        },
        0
    );
    assert_eq!(last_error(), 87);
    // SAFETY: as above.
    assert_eq!(
        unsafe {
            duplicate_handle(
                CURRENT_PROCESS,
                STDOUT,
                CURRENT_PROCESS,
                &mut target,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            )
        },
        0
    );
    assert_eq!(last_error(), 6, "a closed console handle names nothing");
}

/// WriteConsoleA's buffer the console server cannot read: an address the caller cannot name
/// (the kernel's) is ERROR_NOACCESS, one that passed the probe but names no page
/// ERROR_INVALID_USER_BUFFER — the bare/badptr fixture's two answers — the count untouched.
#[test]
fn write_console_a_reports_buffers_it_cannot_read() {
    console_writes();
    for (buffer, error) in [(0x8000_0000usize, 998), (0x10, 1784)] {
        let mut written = 0xCCCC_CCCC;
        crate::base::set_last_error(0);
        // SAFETY: the stand-in screen refuses the address before reading it; a dword.
        assert_eq!(
            unsafe {
                write_console_a(
                    STDOUT,
                    buffer as *const u8,
                    4,
                    &mut written,
                    core::ptr::null(),
                )
            },
            0
        );
        assert_eq!((written, last_error()), (0xCCCC_CCCC, error), "{buffer:#x}");
    }
    assert!(console_writes().is_empty());
}

/// CloseHandle of a kernel handle is NtClose's: TRUE, or FALSE with the status's error
/// (ERROR_INVALID_HANDLE for a handle naming nothing: the runtime fixture's CloseHandle(bogus)).
#[test]
fn close_handle_closes_kernel_handles_through_nt_close() {
    crate::nt::CLOSED.with(|closed| closed.borrow_mut().clear());
    assert_eq!(close_handle(0x44), 1);
    crate::nt::FAIL_NEXT.with(|fail| fail.set(0xC000_0008));
    crate::base::set_last_error(0);
    assert_eq!(close_handle(0x1234), 0);
    assert_eq!(last_error(), 6);
    crate::nt::CLOSED.with(|closed| assert_eq!(*closed.borrow(), [0x44, 0x1234]));
}

/// DuplicateHandle of a kernel handle is NtDuplicateObject's: the new handle where asked.
#[test]
fn duplicate_handle_duplicates_kernel_handles() {
    let mut target = 0;
    // SAFETY: a writable slot.
    assert_eq!(
        unsafe {
            duplicate_handle(
                CURRENT_PROCESS,
                0x44,
                CURRENT_PROCESS,
                &mut target,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            )
        },
        1
    );
    assert_ne!(target, 0);
}

/// A wait on a console handle naming a console object waits on the console's input-wait event
/// (made once, unsignaled: F2K's console has no keyboard), a standard handle's pseudo-value through
/// the parameters' handle; a console handle naming nothing is waited on as itself (the kernel
/// refuses it), as is every other handle.
#[test]
fn waits_on_console_handles_wait_for_input() {
    use crate::nt::host::HANDLE;
    let waited = || LAST_WAITED.with(|cell| cell.borrow().clone());
    wait_for_single_object(STDIN, 0);
    assert_eq!(waited(), [HANDLE], "the event the stand-in made");
    wait_for_single_object(STD_OUTPUT_HANDLE, 0);
    assert_eq!(waited(), [HANDLE]);
    wait_for_single_object(0x13, 0);
    assert_eq!(waited(), [0x13]);
    let handles = [0x40, STDERR, 0xF];
    // SAFETY: three handles.
    unsafe { wait_for_multiple_objects(3, handles.as_ptr(), 0, 0) };
    assert_eq!(waited(), [0x40, HANDLE, 0xF]);
    signal_object_and_wait(0x40, STDIN, 0, 0);
    assert_eq!(waited(), [HANDLE]);
}
