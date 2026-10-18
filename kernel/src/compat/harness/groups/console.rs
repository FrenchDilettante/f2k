//! Console handles: the three standard handles (replayed console handles, tagged so they never name
//! a handle-table slot), console writes, handle closing, and file positioning. Where the target's
//! console is the serial line, the contract is the bytes the service hands the console.

use crate::compat::harness::surface::Fixture;

const STD_INPUT_HANDLE: u32 = -10i32 as u32;
const STD_OUTPUT_HANDLE: u32 = -11i32 as u32;
const STD_ERROR_HANDLE: u32 = -12i32 as u32;
const STDIN: u32 = 0x3;
const STDOUT: u32 = 0x7;
const STDERR: u32 = 0xB;
const INVALID_HANDLE_VALUE: u32 = 0xFFFF_FFFF;
const INVALID_SET_FILE_POINTER: u32 = 0xFFFF_FFFF;
const FILE_BEGIN: u32 = 0;
const FILE_CURRENT: u32 = 1;
const FILE_END: u32 = 2;

/// The hello fixture's one console write, as the trace counts it: 15 bytes — the CRT's text-mode
/// stdout hands WriteFile the line feed as CR LF.
const HELLO: &[u8] = b"Hello, world!\r\n";

/// GetStdHandle: the captured handles — stdin 3, stdout 7, stderr 0xB — and INVALID_HANDLE_VALUE
/// for anything else.
#[test]
fn get_std_handle_replays_the_captured_handles() {
    let mut fixture = Fixture::new();
    for (which, handle) in [
        (STD_INPUT_HANDLE, STDIN),
        (STD_OUTPUT_HANDLE, STDOUT),
        (STD_ERROR_HANDLE, STDERR),
    ] {
        assert_eq!(fixture.call("GetStdHandle", &[which]), handle);
    }
    for which in [0, 42, -13i32 as u32] {
        assert_eq!(fixture.call("GetStdHandle", &[which]), INVALID_HANDLE_VALUE);
    }
}

/// GetFileType: FILE_TYPE_CHAR (2) — the standard handles are character devices, and so is every
/// handle on this surface.
#[test]
fn get_file_type_reports_a_character_device() {
    let mut fixture = Fixture::new();
    for handle in [STDIN, STDOUT, STDERR, 4, INVALID_HANDLE_VALUE] {
        assert_eq!(fixture.call("GetFileType", &[handle]), 2, "{handle:#x}");
    }
}

/// SetHandleCount reports the count it was given (the CRT's 0x20).
#[test]
fn set_handle_count_reports_its_argument() {
    let mut fixture = Fixture::new();
    assert_eq!(fixture.call("SetHandleCount", &[0x20]), 0x20);
    assert_eq!(fixture.call("SetHandleCount", &[0]), 0);
}

/// WriteFile on stdout or stderr hands the bytes to the console, stores the full count, and
/// returns TRUE.
#[test]
fn write_file_writes_to_the_console() {
    let mut fixture = Fixture::new();
    let text = fixture.stage(HELLO);
    let written = fixture.stage(&[0xCC; 4]);
    for handle in [STDOUT, STDERR] {
        assert_eq!(
            fixture.call("WriteFile", &[handle, text, HELLO.len() as u32, written, 0]),
            1
        );
        assert_eq!(fixture.memory().u32_at(written), HELLO.len() as u32);
    }
}

/// WriteFile without a count pointer still writes; a zero-length write succeeds, writes nothing,
/// and stores zero.
#[test]
fn write_file_count_pointer_and_empty_writes() {
    let mut fixture = Fixture::new();
    let text = fixture.stage(HELLO);
    assert_eq!(
        fixture.call("WriteFile", &[STDOUT, text, HELLO.len() as u32, 0, 0]),
        1
    );
    let written = fixture.stage(&[0xCC; 4]);
    assert_eq!(fixture.call("WriteFile", &[STDERR, text, 0, written, 0]), 1);
    assert_eq!(fixture.memory().u32_at(written), 0);
}

/// WriteFile refuses — FALSE before the buffer or the count pointer is touched — stdin, every
/// handle that is not stdout or stderr, and any overlapped request.
#[test]
fn write_file_refuses_other_handles_and_overlapped_requests() {
    let mut fixture = Fixture::new();
    let text = fixture.stage(HELLO);
    let written = fixture.stage(&[0xCC; 4]);
    let overlapped = fixture.buffer(20);
    let count = HELLO.len() as u32;
    for args in [
        [STDIN, text, count, written, 0],
        [INVALID_HANDLE_VALUE, text, count, written, 0],
        [4, text, count, written, 0],
        [0, text, count, written, 0],
        [STDOUT, text, count, written, overlapped],
    ] {
        assert_eq!(fixture.call("WriteFile", &args), 0, "{args:x?}");
    }
    assert_eq!(fixture.memory().bytes(written, 4), [0xCC; 4]);
}

/// FlushFileBuffers succeeds on any handle: console writes are never buffered.
#[test]
fn flush_file_buffers_succeeds() {
    let mut fixture = Fixture::new();
    for handle in [STDOUT, STDERR, 0xF] {
        assert_eq!(fixture.call("FlushFileBuffers", &[handle]), 1);
    }
}

/// SetStdHandle's floor: zero (FALSE), and the standard handles stay as replayed.
#[test]
fn set_std_handle_answers_with_the_floor() {
    let mut fixture = Fixture::new();
    assert_eq!(fixture.call("SetStdHandle", &[STD_OUTPUT_HANDLE, 4]), 0);
    assert_eq!(fixture.call("GetStdHandle", &[STD_OUTPUT_HANDLE]), STDOUT);
}

/// SetFilePointer on a handle that names no open file — a standard handle, a closed or foreign
/// value — is INVALID_SET_FILE_POINTER.
#[test]
fn set_file_pointer_refuses_non_file_handles() {
    let mut fixture = Fixture::new();
    for handle in [STDIN, STDOUT, 0x40, INVALID_HANDLE_VALUE, 0] {
        assert_eq!(
            fixture.call("SetFilePointer", &[handle, 0, 0, FILE_BEGIN]),
            INVALID_SET_FILE_POINTER,
            "{handle:#x}"
        );
    }
}
