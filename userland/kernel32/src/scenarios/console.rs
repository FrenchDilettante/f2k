//! The console: the standard handles (the process parameters'), and the console calls kernel32
//! sends to the console server (CsrClientCallServer), against the host's stand-in, which serves the
//! console server's own rules (`rtl::console`) and records what the screen shows. The runtime
//! fixture's console block is the contract on the machine; these pin kernel32's side and the
//! server's answers.

use super::last_error;
use crate::console::*;
use crate::nt::LAST_WAITED;
use crate::sync::{
    close_handle,
    duplicate_handle,
    signal_object_and_wait,
    wait_for_multiple_objects,
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
///
/// Pins: kernel32.GetStdHandle
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
///
/// Pins: kernel32.GetStdHandle
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
///
/// Pins: kernel32.SetStdHandle
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
///
/// Pins: kernel32.SetHandleCount
#[test]
fn set_handle_count_reports_its_argument() {
    assert_eq!(set_handle_count(0x20), 0x20);
    assert_eq!(set_handle_count(0), 0);
}

/// GetConsoleCP and GetConsoleOutputCP: the console's code pages, the OEM one (the runtime
/// fixture's 437 437).
///
/// Pins: kernel32.GetConsoleCP, kernel32.GetConsoleOutputCP
#[test]
fn the_console_code_pages_are_the_oem_one() {
    assert_eq!((get_console_cp(), get_console_output_cp()), (437, 437));
}

/// GetConsoleMode: a fresh console's modes — the input handle's 0xE7 (processed, line and echoed
/// input, with the insert, quick-edit and extended-flags bits: Windows 2000's console capture),
/// the output handles' processed output wrapping at the line's end; a handle naming no console
/// object is FALSE with ERROR_INVALID_HANDLE, the mode untouched.
///
/// Pins: kernel32.GetConsoleMode
#[test]
fn get_console_mode_answers_per_handle() {
    let mut mode = 0;
    for (handle, expected) in [(STDIN, 0xE7), (STDOUT, 0x3), (STDERR, 0x3)] {
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
///
/// Pins: kernel32.WriteConsoleA
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
///
/// Pins: kernel32.WriteConsoleA
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

/// WriteConsoleA refuses — FALSE, the count pointer untouched — stdin and every handle that names
/// no open output handle (ERROR_INVALID_HANDLE), and a reserved argument (WriteFile's OVERLAPPED:
/// ERROR_INVALID_PARAMETER).
///
/// Pins: kernel32.WriteConsoleA
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
///
/// Pins: kernel32.CloseHandle, kernel32.DuplicateHandle
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
///
/// Pins: kernel32.WriteConsoleA
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
///
/// Pins: kernel32.CloseHandle
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
///
/// Pins: kernel32.DuplicateHandle
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
/// (the console server's, asked for once), a standard handle's pseudo-value through
/// the parameters' handle; a console handle naming nothing is waited on as itself (the kernel
/// refuses it), as is every other handle.
///
/// Pins: kernel32.WaitForSingleObject, kernel32.SignalObjectAndWait
/// Pins: kernel32.WaitForMultipleObjects
#[test]
fn waits_on_console_handles_wait_for_input() {
    use crate::nt::host::HANDLE;
    let waited = || LAST_WAITED.with(|cell| cell.borrow().clone());
    wait_for_single_object(STDIN, 0);
    assert_eq!(waited(), [HANDLE], "the event the stand-in server handed");
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

/// CONIN$ and CONOUT$ name the console: CreateFileA opens a handle on its input buffer and on its
/// screen buffer at the console server (the next free ones, the last error cleared), never the
/// file system.
///
/// Pins: kernel32.CreateFileA
#[test]
fn create_file_opens_the_console_by_name() {
    const OPEN_EXISTING: u32 = 3;
    const READ_WRITE: u32 = 0xC000_0000;
    crate::base::set_last_error(0xBEEF);
    // SAFETY: NUL-terminated names, no security attributes.
    let (input, output) = unsafe {
        (
            crate::files::handle::create_file_a(
                c"CONIN$".as_ptr().cast(),
                READ_WRITE,
                3,
                core::ptr::null(),
                OPEN_EXISTING,
                0,
                0,
            ),
            crate::files::handle::create_file_a(
                c"conout$".as_ptr().cast(),
                READ_WRITE,
                3,
                core::ptr::null(),
                OPEN_EXISTING,
                0,
                0,
            ),
        )
    };
    assert_eq!((input, output, last_error()), (0xF, 0x13, 0));
    let mut mode = 0;
    // SAFETY: a dword.
    assert_eq!(unsafe { get_console_mode(input, &mut mode) }, 1);
    assert_eq!(mode, 0xE7, "the input buffer's");
    // SAFETY: a dword.
    assert_eq!(unsafe { get_console_mode(output, &mut mode) }, 1);
    assert_eq!(mode, 0x3, "the screen buffer's");
}

/// GetConsoleScreenBufferInfo: Windows 2000's default console, an 80 x 300 buffer behind an 80 x
/// 25 window, the cursor inside, attributes 0x07; an input handle, or one naming nothing, is
/// FALSE with ERROR_INVALID_HANDLE. A one-character write moves the cursor one column.
///
/// Pins: kernel32.GetConsoleScreenBufferInfo, kernel32.WriteConsoleW
#[test]
fn the_screen_buffer_info_describes_the_default_console() {
    let info = |handle: u32| {
        let mut bytes = [0u8; 22];
        // SAFETY: a CONSOLE_SCREEN_BUFFER_INFO's bytes.
        let answer = unsafe { get_console_screen_buffer_info(handle, bytes.as_mut_ptr()) };
        let half = |index: usize| i16::from_le_bytes([bytes[2 * index], bytes[2 * index + 1]]);
        (answer, (0..11).map(half).collect::<std::vec::Vec<_>>())
    };
    let (answer, fields) = info(STDOUT);
    assert_eq!(answer, 1);
    assert_eq!((fields[0], fields[1]), (80, 300), "the buffer");
    assert_eq!(fields[4], 0x07, "the attributes");
    assert_eq!(
        (fields[5], fields[6], fields[7], fields[8]),
        (0, 0, 79, 24),
        "the window"
    );
    assert_eq!((fields[9], fields[10]), (80, 25), "the largest window");
    let before = fields[2];
    let mut written = 0;
    // SAFETY: one unit, a dword.
    assert_eq!(
        unsafe {
            write_console_w(
                STDOUT,
                [0x78u16].as_ptr(),
                1,
                &mut written,
                core::ptr::null(),
            )
        },
        1
    );
    assert_eq!((written, info(STDOUT).1[2]), (1, before + 1));
    for handle in [STDIN, 0x1234, 0xF] {
        crate::base::set_last_error(0);
        assert_eq!(info(handle).0, 0, "{handle:#x}");
        assert_eq!(last_error(), 6, "{handle:#x}");
    }
}

/// SetConsoleMode: values the input buffer takes, read back (0x20 with the extended-flags bit);
/// echo without line input and undefined bits are ERROR_INVALID_PARAMETER, the mode kept; a handle
/// naming no console object ERROR_INVALID_HANDLE.
///
/// Pins: kernel32.SetConsoleMode, kernel32.GetConsoleMode
#[test]
fn set_console_mode_checks_and_stores() {
    let mut mode = 0;
    for (set, read) in [(0x1, 0x1), (0x1F, 0x1F), (0x20, 0xA0), (0xE7, 0xE7)] {
        assert_eq!(set_console_mode(STDIN, set), 1, "{set:#x}");
        // SAFETY: a dword.
        unsafe { get_console_mode(STDIN, &mut mode) };
        assert_eq!(mode, read, "{set:#x}");
    }
    for (handle, bad, error) in [
        (STDIN, 0x4, 87),
        (STDIN, 0x8000, 87),
        (STDOUT, 0x8000, 87),
        (0x1234, 0, 6),
    ] {
        crate::base::set_last_error(0);
        assert_eq!(set_console_mode(handle, bad), 0, "{bad:#x}");
        assert_eq!(last_error(), error, "{bad:#x}");
    }
    // SAFETY: a dword.
    unsafe { get_console_mode(STDIN, &mut mode) };
    assert_eq!(mode, 0xE7, "kept");
}

/// The key events of `text` as typed, a keydown and a keyup per character, as INPUT_RECORDs.
fn typed(text: &str) -> std::vec::Vec<[u8; 20]> {
    let mut records = std::vec::Vec::new();
    for character in text.bytes() {
        for down in [1u32, 0] {
            let mut record = [0u8; 20];
            record[0] = 1;
            record[4..8].copy_from_slice(&down.to_le_bytes());
            record[8] = 1;
            record[10] = character.to_ascii_uppercase();
            record[14] = character;
            records.push(record);
        }
    }
    records
}

/// ReadConsoleW and ReadConsoleA in line mode over key events queued with WriteConsoleInputW and
/// WriteConsoleInputA: the line and its CR LF, the Enter's keyup left waiting; a short buffer
/// leaves the rest for the next read; FlushConsoleInputBuffer drops what waits.
///
/// Pins: kernel32.ReadConsoleW, kernel32.ReadConsoleA, kernel32.WriteConsoleInputW
/// Pins: kernel32.WriteConsoleInputA, kernel32.GetNumberOfConsoleInputEvents
/// Pins: kernel32.FlushConsoleInputBuffer
#[test]
fn line_mode_reads_take_queued_lines() {
    assert_eq!(set_console_mode(STDIN, 0x3), 1);
    let records = typed("dir\r");
    let mut written = 0;
    // SAFETY: the records, a dword.
    assert_eq!(
        unsafe { write_console_input_w(STDIN, records.as_ptr().cast(), 8, &mut written) },
        1
    );
    let mut count = 0;
    // SAFETY: a dword.
    assert_eq!(
        unsafe { get_number_of_console_input_events(STDIN, &mut count) },
        1
    );
    assert_eq!((written, count), (8, 8));
    let mut wide = [0u16; 3];
    let mut read = 0;
    // SAFETY: three units, a dword.
    assert_eq!(
        unsafe { read_console_w(STDIN, wide.as_mut_ptr(), 3, &mut read, core::ptr::null()) },
        1
    );
    assert_eq!((read, wide), (3, [0x64, 0x69, 0x72]));
    let mut narrow = [0u8; 8];
    // SAFETY: eight bytes, a dword.
    assert_eq!(
        unsafe { read_console_a(STDIN, narrow.as_mut_ptr(), 8, &mut read, core::ptr::null()) },
        1
    );
    assert_eq!(&narrow[..read as usize], b"\r\n", "the rest of the line");
    // SAFETY: a dword.
    unsafe { get_number_of_console_input_events(STDIN, &mut count) };
    assert_eq!(count, 1, "the Enter's keyup");
    let records = typed("ok\r");
    // SAFETY: the records, a dword.
    unsafe { write_console_input_a(STDIN, records.as_ptr().cast(), 6, &mut written) };
    // SAFETY: eight bytes, a dword.
    unsafe { read_console_a(STDIN, narrow.as_mut_ptr(), 8, &mut read, core::ptr::null()) };
    assert_eq!(&narrow[..read as usize], b"ok\r\n");
    assert_eq!(flush_console_input_buffer(STDIN), 1);
    // SAFETY: a dword.
    unsafe { get_number_of_console_input_events(STDIN, &mut count) };
    assert_eq!(count, 0);
    crate::base::set_last_error(0);
    assert_eq!(flush_console_input_buffer(STDOUT), 0);
    assert_eq!(last_error(), 6);
}

/// PeekConsoleInputA copies waiting records and leaves them; ReadConsoleInputA takes them — the
/// calls msvcrt's _kbhit and _getch make.
///
/// Pins: kernel32.PeekConsoleInputA, kernel32.ReadConsoleInputA, kernel32.PeekConsoleInputW
/// Pins: kernel32.ReadConsoleInputW
#[test]
fn input_records_peek_and_read() {
    let records = typed("ab");
    let mut count = 0;
    // SAFETY: the records, a dword.
    unsafe { write_console_input_w(STDIN, records.as_ptr().cast(), 4, &mut count) };
    let mut out = [[0u8; 20]; 4];
    // SAFETY: four records' room, a dword.
    assert_eq!(
        unsafe { peek_console_input_a(STDIN, out.as_mut_ptr().cast(), 4, &mut count) },
        1
    );
    assert_eq!((count, out[0][14], out[2][14]), (4, b'a', b'b'));
    // SAFETY: as above.
    assert_eq!(
        unsafe { peek_console_input_w(STDIN, out.as_mut_ptr().cast(), 1, &mut count) },
        1
    );
    assert_eq!(count, 1);
    // SAFETY: as above.
    assert_eq!(
        unsafe { read_console_input_a(STDIN, out.as_mut_ptr().cast(), 3, &mut count) },
        1
    );
    assert_eq!((count, out[2][14]), (3, b'b'));
    // SAFETY: as above.
    assert_eq!(
        unsafe { read_console_input_w(STDIN, out.as_mut_ptr().cast(), 4, &mut count) },
        1
    );
    assert_eq!(count, 1, "b's keyup, the last");
}

/// SetConsoleTitleW and GetConsoleTitleW, then the A forms, as Windows 2000's console capture
/// answers them: W truncates to the buffer with its terminator, A answers the whole title or 0;
/// an empty title is 0 with nothing written. The last error is left alone.
///
/// Pins: kernel32.SetConsoleTitleW, kernel32.GetConsoleTitleW, kernel32.SetConsoleTitleA
/// Pins: kernel32.GetConsoleTitleA
#[test]
fn the_title_is_set_and_read_back() {
    let title: std::vec::Vec<u16> = "F2K title\0".encode_utf16().collect();
    crate::base::set_last_error(0xBEEF);
    // SAFETY: a NUL-terminated title.
    assert_eq!(unsafe { set_console_title_w(title.as_ptr()) }, 1);
    let mut wide = [0x23u16; 12];
    assert_eq!(get_console_title_w(wide.as_mut_ptr(), 9), 8);
    assert_eq!(
        &wide[..10],
        &[0x46, 0x32, 0x4B, 0x20, 0x74, 0x69, 0x74, 0x6C, 0, 0x23]
    );
    let mut narrow = [b'#'; 12];
    assert_eq!(get_console_title_a(narrow.as_mut_ptr(), 9), 0);
    assert_eq!(narrow, [b'#'; 12], "nothing written");
    assert_eq!(get_console_title_a(narrow.as_mut_ptr(), 10), 9);
    assert_eq!(&narrow[..11], b"F2K title\0#");
    // SAFETY: a NUL-terminated title.
    assert_eq!(unsafe { set_console_title_a(c"".as_ptr().cast()) }, 1);
    assert_eq!(get_console_title_w(wide.as_mut_ptr(), 12), 0);
    assert_eq!(last_error(), 0xBEEF);
}

/// SetConsoleCtrlHandler: a handler added twice is removed twice, a third removal (or one of a
/// handler never added) is ERROR_INVALID_PARAMETER; NULL turns the ignoring of Ctrl+C on and off
/// and never fails.
///
/// Pins: kernel32.SetConsoleCtrlHandler
#[test]
fn control_handlers_register_and_unregister() {
    const HANDLER: u32 = 0x40_1000;
    assert_eq!(set_console_ctrl_handler(HANDLER, 1), 1);
    assert_eq!(set_console_ctrl_handler(HANDLER, 1), 1);
    assert_eq!(set_console_ctrl_handler(HANDLER, 0), 1);
    assert_eq!(set_console_ctrl_handler(HANDLER, 0), 1);
    crate::base::set_last_error(0);
    assert_eq!(set_console_ctrl_handler(HANDLER, 0), 0);
    assert_eq!(last_error(), 87);
    assert_eq!(set_console_ctrl_handler(0x40_2000, 0), 0);
    for add in [1, 0, 0] {
        assert_eq!(set_console_ctrl_handler(0, add), 1);
    }
    for _ in 0..20 {
        set_console_ctrl_handler(HANDLER, 1);
    }
    let removed = (0..40)
        .take_while(|_| set_console_ctrl_handler(HANDLER, 0) == 1)
        .count();
    assert_eq!(removed, 20);
}
