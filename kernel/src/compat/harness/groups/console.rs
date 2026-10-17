//! Console handles: the three standard handles (replayed console handles, tagged so they never name
//! a handle-table slot), console writes, handle closing, and file positioning. Where the target's
//! console is the serial line, the contract is the bytes the service hands the console.

use crate::compat::harness::boundary::{EventType, KernelBoundary};
use crate::compat::harness::fake::Call;
use crate::compat::harness::surface::{assert_argument_blocks, Fixture};

pub const MEMBERS: &[&str] = &[
    "GetStdHandle",
    "GetFileType",
    "SetHandleCount",
    "WriteFile",
    "CloseHandle",
    "FlushFileBuffers",
    "GetLastError",
    "SetLastError",
    "SetFilePointer",
    "SetStdHandle",
];

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

/// Every member pops the block its callers push. Ledger: console.
#[test]
#[ignore = "ledger console: not switched on"]
fn console_argument_blocks_match_the_prototypes() {
    assert_argument_blocks(MEMBERS);
}

/// GetStdHandle: the captured handles — stdin 3, stdout 7, stderr 0xB — and INVALID_HANDLE_VALUE
/// for anything else. Ledger: console/GetStdHandle.
#[test]
#[ignore = "ledger console/GetStdHandle: not switched on"]
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
    assert_eq!(fixture.kernel.calls(), []);
}

/// GetFileType: FILE_TYPE_CHAR (2) — the standard handles are character devices, and so is every
/// handle on this surface. Ledger: console/GetFileType.
#[test]
#[ignore = "ledger console/GetFileType: not switched on"]
fn get_file_type_reports_a_character_device() {
    let mut fixture = Fixture::new();
    for handle in [STDIN, STDOUT, STDERR, 4, INVALID_HANDLE_VALUE] {
        assert_eq!(fixture.call("GetFileType", &[handle]), 2, "{handle:#x}");
    }
}

/// SetHandleCount reports the count it was given (the CRT's 0x20). Ledger: console/SetHandleCount.
#[test]
#[ignore = "ledger console/SetHandleCount: not switched on"]
fn set_handle_count_reports_its_argument() {
    let mut fixture = Fixture::new();
    assert_eq!(fixture.call("SetHandleCount", &[0x20]), 0x20);
    assert_eq!(fixture.call("SetHandleCount", &[0]), 0);
}

/// WriteFile on stdout or stderr hands the bytes to the console, stores the full count, and
/// returns TRUE. Ledger: console/WriteFile.
#[test]
#[ignore = "ledger console/WriteFile: the existing path reads caller memory (target-only)"]
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
        assert_eq!(fixture.kernel.console_output(handle), HELLO);
    }
}

/// WriteFile without a count pointer still writes; a zero-length write succeeds, writes nothing,
/// and stores zero. Ledger: console/WriteFile.
#[test]
#[ignore = "ledger console/WriteFile: the existing path reads caller memory (target-only)"]
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
    assert_eq!(fixture.kernel.console_output(STDOUT), HELLO);
    assert_eq!(fixture.kernel.console_output(STDERR), b"");
}

/// WriteFile refuses — FALSE before the buffer or the count pointer is touched — stdin, every
/// handle that is not stdout or stderr, and any overlapped request. Ledger: console/WriteFile.
#[test]
#[ignore = "ledger console/WriteFile: not switched on"]
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
    assert_eq!(fixture.kernel.calls(), []);
}

/// CloseHandle on a standard handle succeeds and changes nothing — it reaches no table slot, even
/// when the slot its bits would name is live. Ledger: console/CloseHandle.
#[test]
#[ignore = "ledger console/CloseHandle: the existing path closes in the live handle table \
            (target-only)"]
fn close_handle_on_a_console_handle_changes_nothing() {
    let mut fixture = Fixture::new();
    let event = fixture
        .kernel
        .nt_create_event(EventType::Synchronization, false)
        .unwrap();
    assert_eq!(
        event >> 2,
        STDOUT >> 2,
        "stdout's bits name the event's slot"
    );
    fixture.kernel.clear_calls();
    for handle in [STDIN, STDOUT, STDERR] {
        assert_eq!(fixture.call("CloseHandle", &[handle]), 1);
    }
    assert_eq!(fixture.kernel.calls(), []);
    assert_eq!(fixture.kernel.live_handles(), 1);
}

/// CloseHandle on an object handle ends the table's claim once: TRUE, then FALSE for the same
/// value; a value naming nothing is FALSE. Ledger: console/CloseHandle.
#[test]
#[ignore = "ledger console/CloseHandle: the existing path closes in the live handle table \
            (target-only)"]
fn close_handle_closes_object_handles_once() {
    let mut fixture = Fixture::new();
    let event = fixture
        .kernel
        .nt_create_event(EventType::Notification, false)
        .unwrap();
    assert_eq!(fixture.call("CloseHandle", &[event]), 1);
    assert_eq!(fixture.kernel.live_handles(), 0);
    assert_eq!(fixture.call("CloseHandle", &[event]), 0);
    assert_eq!(fixture.call("CloseHandle", &[0x40]), 0);
    assert_eq!(fixture.call("CloseHandle", &[INVALID_HANDLE_VALUE]), 0);
    assert_eq!(fixture.call("CloseHandle", &[0]), 0);
}

/// CloseHandle on a file handle releases the open file with it: the handle reads nothing after.
/// Ledger: console/CloseHandle.
#[test]
#[ignore = "ledger console/CloseHandle: the existing path closes in the live handle table \
            (target-only)"]
fn close_handle_releases_an_open_file() {
    let mut fixture = Fixture::new();
    let file = fixture.kernel.nt_create_file(b"hello.exe").unwrap();
    assert_eq!(fixture.call("CloseHandle", &[file]), 1);
    assert!(fixture.kernel.calls().contains(&Call::Close(file)));
    assert!(fixture.kernel.nt_query_information_file(file).is_err());
}

/// FlushFileBuffers succeeds on any handle: console writes are never buffered. Ledger:
/// console/FlushFileBuffers.
#[test]
#[ignore = "ledger console/FlushFileBuffers: not switched on"]
fn flush_file_buffers_succeeds() {
    let mut fixture = Fixture::new();
    for handle in [STDOUT, STDERR, 0xF] {
        assert_eq!(fixture.call("FlushFileBuffers", &[handle]), 1);
    }
    assert_eq!(fixture.kernel.calls(), []);
}

/// SetStdHandle's floor: zero (FALSE), and the standard handles stay as replayed. Ledger:
/// console/SetStdHandle.
#[test]
#[ignore = "ledger console/SetStdHandle: unpinned floor"]
fn set_std_handle_answers_with_the_floor() {
    let mut fixture = Fixture::new();
    assert_eq!(fixture.call("SetStdHandle", &[STD_OUTPUT_HANDLE, 4]), 0);
    assert_eq!(fixture.call("GetStdHandle", &[STD_OUTPUT_HANDLE]), STDOUT);
}

/// SetFilePointer moves an open file's position from the start, the current position, or the end,
/// and returns the new position — past the end included. Ledger: console/SetFilePointer.
#[test]
#[ignore = "ledger console/SetFilePointer: the existing path seeks in the live process's files \
            (target-only)"]
fn set_file_pointer_moves_by_each_method() {
    let mut fixture = Fixture::new();
    let file = fixture.kernel.nt_create_file(b"hello.exe").unwrap();
    let size = crate::compat::harness::fake::IMAGE.len() as u32;
    let seek = |fixture: &mut Fixture, distance: i32, method: u32| {
        fixture.call("SetFilePointer", &[file, distance as u32, 0, method])
    };
    assert_eq!(seek(&mut fixture, 0x3C, FILE_BEGIN), 0x3C);
    assert_eq!(seek(&mut fixture, 4, FILE_CURRENT), 0x40);
    assert_eq!(seek(&mut fixture, -0x40, FILE_CURRENT), 0);
    assert_eq!(seek(&mut fixture, 0, FILE_END), size);
    assert_eq!(seek(&mut fixture, -2, FILE_END), size - 2);
    assert_eq!(seek(&mut fixture, 16, FILE_END), size + 16);
    assert_eq!(
        fixture
            .kernel
            .nt_query_information_file(file)
            .unwrap()
            .position,
        (size + 16) as u64
    );
}

/// SetFilePointer honors the high-word pointer: the distance is the 64-bit (high, low) pair, the
/// return its new low dword, and the new high dword is written back. Ledger:
/// console/SetFilePointer.
#[test]
#[ignore = "ledger console/SetFilePointer: the existing path seeks in the live process's files \
            (target-only)"]
fn set_file_pointer_honors_the_high_word() {
    let mut fixture = Fixture::new();
    let file = fixture.kernel.nt_create_file(b"hello.exe").unwrap();
    let high = fixture.stage(&5u32.to_le_bytes());
    assert_eq!(
        fixture.call("SetFilePointer", &[file, 0x80, high, FILE_BEGIN]),
        0x80
    );
    assert_eq!(fixture.memory().u32_at(high), 5);
}

/// SetFilePointer returns INVALID_SET_FILE_POINTER, the position unmoved, for a target before the
/// start and for a move method the ABI does not name. Ledger: console/SetFilePointer.
#[test]
#[ignore = "ledger console/SetFilePointer: the existing path seeks in the live process's files \
            (target-only)"]
fn set_file_pointer_refuses_bad_targets_and_methods() {
    let mut fixture = Fixture::new();
    let file = fixture.kernel.nt_create_file(b"hello.exe").unwrap();
    assert_eq!(
        fixture.call("SetFilePointer", &[file, 0x10, 0, FILE_BEGIN]),
        0x10
    );
    for (distance, method) in [(-1i32, FILE_BEGIN), (-0x11, FILE_CURRENT), (0, 3)] {
        assert_eq!(
            fixture.call("SetFilePointer", &[file, distance as u32, 0, method]),
            INVALID_SET_FILE_POINTER
        );
    }
    assert_eq!(
        fixture
            .kernel
            .nt_query_information_file(file)
            .unwrap()
            .position,
        0x10
    );
}

/// SetFilePointer on a handle that names no open file — a standard handle, an event, a closed or
/// foreign value — is INVALID_SET_FILE_POINTER. Ledger: console/SetFilePointer.
#[test]
#[ignore = "ledger console/SetFilePointer: not switched on"]
fn set_file_pointer_refuses_non_file_handles() {
    let mut fixture = Fixture::new();
    let event = fixture
        .kernel
        .nt_create_event(EventType::Notification, false)
        .unwrap();
    for handle in [STDIN, STDOUT, event, 0x40, INVALID_HANDLE_VALUE, 0] {
        assert_eq!(
            fixture.call("SetFilePointer", &[handle, 0, 0, FILE_BEGIN]),
            INVALID_SET_FILE_POINTER,
            "{handle:#x}"
        );
    }
}
