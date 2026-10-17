//! File handles: read-only opens of existing files on the boot volume (root-relative, 8.3,
//! case-folded paths) and synchronous reads from the file position. The scenarios follow the
//! retired fileio smoke: open its own image by the path GetModuleFileNameA reports, read the MZ and PE
//! signatures across seeks, read the MZ again.

use crate::compat::harness::boundary::{EventType, KernelBoundary};
use crate::compat::harness::fake::{Call, IMAGE};
use crate::compat::harness::surface::{assert_argument_blocks, Fixture, UNMAPPED};

pub const MEMBERS: &[&str] = &[
    "CreateFileA",
    "ReadFile",
    "CreateFileMappingA",
    "FileTimeToLocalFileTime",
    "FileTimeToSystemTime",
    "FindClose",
    "FindFirstFileA",
    "OpenFileMappingA",
    "CopyFileA",
    "CreateDirectoryA",
    "DeleteFileA",
    "MoveFileA",
    "RemoveDirectoryA",
    "SetFileAttributesA",
    "SetFileTime",
    "SystemTimeToFileTime",
    "FindNextFileA",
    "GetCurrentDirectoryA",
    "GetDiskFreeSpaceA",
    "GetDriveTypeA",
    "GetFileAttributesA",
    "GetFileAttributesExA",
    "GetFileInformationByHandle",
    "GetFileSize",
    "GetFileTime",
    "GetFullPathNameA",
    "GetShortPathNameA",
    "GetVolumeInformationA",
    "MapViewOfFile",
    "SetCurrentDirectoryA",
    "SetEndOfFile",
    "UnmapViewOfFile",
];

const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const FILE_SHARE_READ: u32 = 0x1;
const CREATE_ALWAYS: u32 = 2;
const OPEN_EXISTING: u32 = 3;
const OPEN_ALWAYS: u32 = 4;
const FILE_FLAG_OVERLAPPED: u32 = 0x4000_0000;
const INVALID_HANDLE_VALUE: u32 = 0xFFFF_FFFF;
const FILE_BEGIN: u32 = 0;

/// CreateFileA as the fileio smoke opened: read access, shared for reading, an existing file, no
/// flags or attributes.
fn open(fixture: &mut Fixture, path: u32) -> u32 {
    fixture.call(
        "CreateFileA",
        &[path, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0],
    )
}

/// ReadFile of `count` bytes; the return, the stored count, and the bytes.
fn read(fixture: &mut Fixture, handle: u32, count: u32) -> (u32, u32, Vec<u8>) {
    let buffer = fixture.buffer(count);
    let moved = fixture.stage(&[0xCC; 4]);
    let result = fixture.call("ReadFile", &[handle, buffer, count, moved, 0]);
    let moved = fixture.memory().u32_at(moved);
    let bytes = fixture.memory().bytes(buffer, moved.min(count));
    (result, moved, bytes)
}

/// Every member pops the block its callers push. Ledger: files.
#[test]
#[ignore = "ledger files: not switched on"]
fn files_argument_blocks_match_the_prototypes() {
    assert_argument_blocks(MEMBERS);
}

/// CreateFileA opens the image by the path GetModuleFileNameA reports — the loader's volume path,
/// verbatim — and returns a new handle; the kernel is asked for exactly that path. Ledger:
/// files/CreateFileA.
#[test]
#[ignore = "ledger files/CreateFileA: the existing path opens on the live boot volume \
            (target-only)"]
fn create_file_opens_the_image_by_its_module_path() {
    let mut fixture = Fixture::new();
    let path = fixture.buffer(260);
    assert_eq!(fixture.call("GetModuleFileNameA", &[0, path, 260]), 10);
    let handle = open(&mut fixture, path);
    assert_eq!(handle, 4);
    assert!(fixture
        .kernel
        .calls()
        .contains(&Call::CreateFile(b"hello.exe".to_vec())));
}

/// CreateFileA resolves paths case-insensitively. Ledger: files/CreateFileA.
#[test]
#[ignore = "ledger files/CreateFileA: the existing path opens on the live boot volume \
            (target-only)"]
fn create_file_folds_case() {
    let mut fixture = Fixture::new();
    for name in [&b"HELLO.EXE"[..], b"HeLlO.ExE"] {
        let path = fixture.c_string(name);
        assert_ne!(open(&mut fixture, path), INVALID_HANDLE_VALUE, "{name:?}");
    }
}

/// CreateFileA serves exactly read access to an existing file, synchronously: any other access, any
/// other disposition, and the overlapped flag return INVALID_HANDLE_VALUE before the path is read
/// or the kernel asked. Ledger: files/CreateFileA.
#[test]
#[ignore = "ledger files/CreateFileA: not switched on"]
fn create_file_refuses_unsupported_requests_first() {
    let mut fixture = Fixture::new();
    for (access, disposition, flags) in [
        (GENERIC_WRITE, OPEN_EXISTING, 0),
        (GENERIC_READ | GENERIC_WRITE, OPEN_EXISTING, 0),
        (0, OPEN_EXISTING, 0),
        (GENERIC_READ, CREATE_ALWAYS, 0),
        (GENERIC_READ, OPEN_ALWAYS, 0),
        (GENERIC_READ, OPEN_EXISTING, FILE_FLAG_OVERLAPPED),
    ] {
        assert_eq!(
            fixture.call(
                "CreateFileA",
                &[UNMAPPED, access, 0, 0, disposition, flags, 0]
            ),
            INVALID_HANDLE_VALUE,
            "{access:#x} {disposition} {flags:#x}"
        );
    }
    assert_eq!(fixture.kernel.calls(), []);
}

/// CreateFileA returns INVALID_HANDLE_VALUE for a path that does not resolve (missing, not 8.3,
/// empty, an empty component), one that names a directory, and one of MAX_PATH (260) bytes or more — that one before the
/// kernel is asked. Ledger: files/CreateFileA.
#[test]
#[ignore = "ledger files/CreateFileA: the existing path opens on the live boot volume \
            (target-only)"]
fn create_file_refuses_unresolvable_paths_and_directories() {
    let mut fixture = Fixture::new();
    let good = fixture.c_string(b"hello.exe");
    let opened = open(&mut fixture, good);
    assert_ne!(opened, INVALID_HANDLE_VALUE, "the control opens");
    assert_eq!(fixture.call("CloseHandle", &[opened]), 1);
    for name in [
        &b"missing.exe"[..],
        b"toolongname.exe",
        b"\\hello.exe",
        b"boot",
        b"",
    ] {
        let path = fixture.c_string(name);
        assert_eq!(open(&mut fixture, path), INVALID_HANDLE_VALUE, "{name:?}");
    }
    fixture.kernel.clear_calls();
    let long = fixture.c_string(&[b'a'; 260]);
    assert_eq!(open(&mut fixture, long), INVALID_HANDLE_VALUE);
    assert_eq!(fixture.kernel.calls(), []);
    assert_eq!(fixture.kernel.live_handles(), 0);
}

/// CreateFileA returns INVALID_HANDLE_VALUE once the handle table is full. Ledger:
/// files/CreateFileA.
#[test]
#[ignore = "ledger files/CreateFileA: the existing path opens on the live boot volume \
            (target-only)"]
fn create_file_refuses_when_the_table_is_full() {
    let mut fixture = Fixture::new();
    let path = fixture.c_string(b"hello.exe");
    assert_ne!(
        open(&mut fixture, path),
        INVALID_HANDLE_VALUE,
        "the control opens"
    );
    for _ in 2..crate::sched::object::HANDLE_SLOTS {
        fixture
            .kernel
            .nt_create_event(EventType::Notification, false)
            .unwrap();
    }
    assert_eq!(open(&mut fixture, path), INVALID_HANDLE_VALUE);
}

/// The fileio smoke's reads: the MZ signature at 0, e_lfanew at 0x3C, the PE signature there, the
/// MZ again after seeking back — each read TRUE, the full count stored. Ledger: files/ReadFile.
#[test]
#[ignore = "ledger files/ReadFile: the existing path reads the live boot volume (target-only)"]
fn read_file_reads_the_image_signatures() {
    let mut fixture = Fixture::new();
    let path = fixture.c_string(b"hello.exe");
    let file = open(&mut fixture, path);
    assert_eq!(read(&mut fixture, file, 2), (1, 2, b"MZ".to_vec()));
    fixture.call("SetFilePointer", &[file, 0x3C, 0, FILE_BEGIN]);
    let (result, moved, bytes) = read(&mut fixture, file, 4);
    assert_eq!((result, moved), (1, 4));
    let e_lfanew = u32::from_le_bytes(bytes.try_into().unwrap());
    assert_eq!(
        e_lfanew,
        u32::from_le_bytes(IMAGE[0x3C..0x40].try_into().unwrap())
    );
    fixture.call("SetFilePointer", &[file, e_lfanew, 0, FILE_BEGIN]);
    assert_eq!(read(&mut fixture, file, 4), (1, 4, b"PE\0\0".to_vec()));
    fixture.call("SetFilePointer", &[file, 0, 0, FILE_BEGIN]);
    assert_eq!(read(&mut fixture, file, 2), (1, 2, b"MZ".to_vec()));
}

/// ReadFile advances the position by what it read: consecutive reads continue the file. Ledger:
/// files/ReadFile.
#[test]
#[ignore = "ledger files/ReadFile: the existing path reads the live boot volume (target-only)"]
fn read_file_advances_the_position() {
    let mut fixture = Fixture::new();
    let path = fixture.c_string(b"hello.exe");
    let file = open(&mut fixture, path);
    let mut whole = Vec::new();
    for _ in 0..3 {
        let (result, moved, bytes) = read(&mut fixture, file, 700);
        assert_eq!((result, moved), (1, 700));
        whole.extend(bytes);
    }
    assert_eq!(whole, IMAGE[..2100]);
}

/// ReadFile near the end moves what remains and succeeds; at or past the end it moves nothing and
/// still succeeds. Ledger: files/ReadFile.
#[test]
#[ignore = "ledger files/ReadFile: the existing path reads the live boot volume (target-only)"]
fn read_file_at_the_end_moves_what_remains() {
    let mut fixture = Fixture::new();
    let path = fixture.c_string(b"hello.exe");
    let file = open(&mut fixture, path);
    let size = IMAGE.len() as u32;
    fixture.call("SetFilePointer", &[file, size - 4, 0, FILE_BEGIN]);
    assert_eq!(
        read(&mut fixture, file, 16),
        (1, 4, IMAGE[size as usize - 4..].to_vec())
    );
    assert_eq!(read(&mut fixture, file, 16), (1, 0, Vec::new()));
    fixture.call("SetFilePointer", &[file, size + 100, 0, FILE_BEGIN]);
    assert_eq!(read(&mut fixture, file, 16), (1, 0, Vec::new()));
}

/// ReadFile without a count pointer still reads. Ledger: files/ReadFile.
#[test]
#[ignore = "ledger files/ReadFile: the existing path reads the live boot volume (target-only)"]
fn read_file_without_a_count_pointer() {
    let mut fixture = Fixture::new();
    let path = fixture.c_string(b"hello.exe");
    let file = open(&mut fixture, path);
    let buffer = fixture.buffer(2);
    assert_eq!(fixture.call("ReadFile", &[file, buffer, 2, 0, 0]), 1);
    assert_eq!(fixture.memory().bytes(buffer, 2), b"MZ");
}

/// ReadFile refuses — FALSE, the count pointer untouched — an overlapped request and every handle
/// that names no open file: the standard handles, an event, a closed or foreign value. Ledger:
/// files/ReadFile.
#[test]
#[ignore = "ledger files/ReadFile: not switched on"]
fn read_file_refuses_overlapped_requests_and_non_files() {
    let mut fixture = Fixture::new();
    let event = fixture
        .kernel
        .nt_create_event(EventType::Notification, false)
        .unwrap();
    let file = fixture.kernel.nt_create_file(b"hello.exe").unwrap();
    let buffer = fixture.buffer(16);
    let moved = fixture.stage(&[0xCC; 4]);
    let overlapped = fixture.buffer(20);
    for args in [
        [file, buffer, 2, moved, overlapped],
        [0x3, buffer, 2, moved, 0],
        [0x7, buffer, 2, moved, 0],
        [event, buffer, 2, moved, 0],
        [0x40, buffer, 2, moved, 0],
        [INVALID_HANDLE_VALUE, buffer, 2, moved, 0],
    ] {
        assert_eq!(fixture.call("ReadFile", &args), 0, "{args:x?}");
    }
    assert_eq!(fixture.memory().bytes(moved, 4), [0xCC; 4]);
}
