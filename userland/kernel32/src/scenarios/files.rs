//! The file API: kernel32's calls over ntdll's file services, against the stand-in file
//! ([`crate::nt::files`]: one file named by its handle, the calls recorded) and the stand-in
//! console. The files and fswrite fixtures are the contract on the machine; these pin what kernel32
//! itself decides — the services it asks and how, the errors it sets on its own, the console's
//! routing.

use super::last_error;
use crate::files::handle::*;
use crate::files::names::*;
use crate::nt::files::{calls, Call, CURRENT_DIRECTORY, CURRENT_DIRECTORY_HANDLE, FILE};
use crate::nt::host::{console_writes, FAIL_NEXT, HANDLE};

const STDIN: u32 = 0x3;
const STDOUT: u32 = 0x7;
const STDERR: u32 = 0xB;
const INVALID_HANDLE_VALUE: u32 = 0xFFFF_FFFF;
const INVALID_SET_FILE_POINTER: u32 = 0xFFFF_FFFF;
const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;

/// The hello fixture's one console write: the CRT's text-mode stdout hands WriteFile CR LF.
const HELLO: &[u8] = b"Hello, world!\r\n";

fn fail_next(status: u32) {
    FAIL_NEXT.with(|next| next.set(status));
}

/// The stand-in file at `size` bytes, its position at `position`.
fn file_at(size: u64, position: u64) {
    FILE.with(|file| {
        let mut file = file.borrow_mut();
        file.size = size;
        file.position = position;
        file.opened = 1;
    });
    calls();
}

fn open_call() -> (u32, u32, String, u32, u32, u32) {
    match calls()
        .into_iter()
        .find(|call| matches!(call, Call::Open { .. }))
    {
        Some(Call::Open {
            access,
            root,
            name,
            share,
            disposition,
            options,
            ..
        }) => (access, root, name, share, disposition, options),
        other => panic!("no open: {other:?}"),
    }
}

/// CreateFileA asks NtCreateFile for the access with SYNCHRONIZE and FILE_READ_ATTRIBUTES, the
/// disposition mapped, synchronous I/O and no directory without backup semantics, a relative name
/// against the current directory's handle; OPEN_ALWAYS finding the file is ERROR_ALREADY_EXISTS,
/// a created one clears the last error.
#[test]
fn create_file_maps_its_arguments_onto_nt_create_file() {
    CURRENT_DIRECTORY
        .with(|current| *current.borrow_mut() = "C:\\CORPUS\\".encode_utf16().collect());
    file_at(0, 0);
    crate::base::set_last_error(0xDEAD);
    let handle = unsafe {
        create_file_a(
            b"DATA\\SMALL.TXT\0".as_ptr(),
            GENERIC_READ,
            1,
            core::ptr::null(),
            4,
            0,
            0,
        )
    };
    assert_eq!(handle, HANDLE);
    assert_eq!(last_error(), 183, "OPEN_ALWAYS found it");
    let (access, root, name, share, disposition, options) = open_call();
    assert_eq!(access, GENERIC_READ | 0x0010_0000 | 0x80);
    assert_eq!(
        (root, name.as_str()),
        (CURRENT_DIRECTORY_HANDLE, "DATA\\SMALL.TXT")
    );
    assert_eq!((share, disposition, options), (1, 3, 0x20 | 0x40));

    FILE.with(|file| file.borrow_mut().opened = 2);
    let flags = 0x0200_0000 | 0x0400_0000 | 0x4000_0000;
    assert_eq!(
        unsafe {
            create_file_a(
                b"C:\\X.TMP\0".as_ptr(),
                GENERIC_WRITE,
                0,
                core::ptr::null(),
                2,
                flags,
                0,
            )
        },
        HANDLE
    );
    assert_eq!(last_error(), 0, "created");
    let (access, root, name, _, disposition, options) = open_call();
    assert_eq!(
        (root, name.as_str(), disposition),
        (0, "\\??\\C:\\X.TMP", 5)
    );
    assert_eq!(
        access & 0x0001_0000,
        0x0001_0000,
        "delete-on-close asks DELETE"
    );
    assert_eq!(
        options,
        0x4000 | 0x1000,
        "backup intent, delete on close, no synchronous I/O for an overlapped open"
    );
}

/// The refusals kernel32 makes itself: a bad disposition and TRUNCATE_EXISTING without
/// GENERIC_WRITE are ERROR_INVALID_PARAMETER before any service; an empty path
/// ERROR_PATH_NOT_FOUND; a name past MAX_PATH ERROR_FILENAME_EXCED_RANGE; CREATE_NEW's collision
/// ERROR_FILE_EXISTS where the status maps to ERROR_ALREADY_EXISTS.
#[test]
fn create_file_refuses_as_windows_2000_does() {
    file_at(0, 0);
    for (disposition, access) in [(0, GENERIC_READ), (9, GENERIC_WRITE), (5, GENERIC_READ)] {
        assert_eq!(
            unsafe {
                create_file_a(
                    b"X\0".as_ptr(),
                    access,
                    0,
                    core::ptr::null(),
                    disposition,
                    0,
                    0,
                )
            },
            INVALID_HANDLE_VALUE
        );
        assert_eq!(last_error(), 87);
    }
    assert!(calls().is_empty(), "no service asked");
    assert_eq!(
        unsafe { create_file_a(b"\0".as_ptr(), GENERIC_READ, 0, core::ptr::null(), 3, 0, 0) },
        INVALID_HANDLE_VALUE
    );
    assert_eq!(last_error(), 3);
    let long = [b'A'; 300].iter().copied().chain([0]).collect::<Vec<u8>>();
    assert_eq!(
        unsafe { create_file_a(long.as_ptr(), GENERIC_READ, 0, core::ptr::null(), 3, 0, 0) },
        INVALID_HANDLE_VALUE
    );
    assert_eq!(last_error(), 206);
    fail_next(0xC000_0035);
    assert_eq!(
        unsafe {
            create_file_a(
                b"X\0".as_ptr(),
                GENERIC_WRITE,
                0,
                core::ptr::null(),
                1,
                0,
                0,
            )
        },
        INVALID_HANDLE_VALUE
    );
    assert_eq!(last_error(), 80, "CREATE_NEW on an existing file");
    fail_next(0xC000_0034);
    assert_eq!(
        unsafe { create_file_a(b"X\0".as_ptr(), GENERIC_READ, 0, core::ptr::null(), 3, 0, 0) },
        INVALID_HANDLE_VALUE
    );
    assert_eq!(last_error(), 2);
}

/// TRUNCATE_EXISTING opens the file and cuts it (its allocation set to zero).
#[test]
fn truncate_existing_cuts_the_file_once_open() {
    file_at(12, 0);
    assert_eq!(
        unsafe {
            create_file_a(
                b"X\0".as_ptr(),
                GENERIC_WRITE,
                0,
                core::ptr::null(),
                5,
                0,
                0,
            )
        },
        HANDLE
    );
    let recorded = calls();
    assert!(matches!(recorded[0], Call::Open { disposition: 1, .. }));
    assert_eq!(
        recorded[1],
        Call::Set {
            handle: HANDLE,
            class: 19,
            bytes: vec![0; 8]
        }
    );
}

/// ReadFile zeroes the count first; a read at the end succeeds with nothing (STATUS_END_OF_FILE);
/// a console handle's read is the console's (ReadConsoleA): stdin's input ends at once (TRUE,
/// nothing read: F2K's console has no keyboard), an output handle is ERROR_INVALID_HANDLE.
#[test]
fn read_file_counts_what_moved() {
    file_at(10, 6);
    let mut buffer = [0u8; 16];
    let mut read = 0xCCu32;
    assert_eq!(
        unsafe {
            read_file(
                HANDLE,
                buffer.as_mut_ptr(),
                16,
                &mut read,
                core::ptr::null_mut(),
            )
        },
        1
    );
    assert_eq!(read, 4);
    read = 7;
    crate::base::set_last_error(0xDEAD);
    assert_eq!(
        unsafe {
            read_file(
                HANDLE,
                buffer.as_mut_ptr(),
                16,
                &mut read,
                core::ptr::null_mut(),
            )
        },
        1
    );
    assert_eq!(
        (read, last_error()),
        (0, 0xDEAD),
        "at the end: TRUE, nothing, the last error kept"
    );
    read = 7;
    crate::base::set_last_error(0xDEAD);
    assert_eq!(
        unsafe {
            read_file(
                STDIN,
                buffer.as_mut_ptr(),
                1,
                &mut read,
                core::ptr::null_mut(),
            )
        },
        1
    );
    assert_eq!((read, last_error()), (0, 0xDEAD));
    read = 7;
    assert_eq!(
        unsafe {
            read_file(
                -11i32 as u32,
                buffer.as_mut_ptr(),
                1,
                &mut read,
                core::ptr::null_mut(),
            )
        },
        0
    );
    assert_eq!((read, last_error()), (0, 6));
    read = 7;
    assert_eq!(
        unsafe {
            read_file(
                0x40,
                buffer.as_mut_ptr(),
                1,
                &mut read,
                core::ptr::null_mut(),
            )
        },
        0
    );
    assert_eq!((read, last_error()), (0, 6), "a handle naming no file");
}

/// WriteFile on stdout or stderr (or their pseudo-handles) hands the bytes to the console and
/// stores the count.
#[test]
fn write_file_writes_to_the_console() {
    console_writes();
    for handle in [STDOUT, STDERR, -11i32 as u32] {
        let mut written = 0xCCCC_CCCCu32;
        assert_eq!(
            unsafe {
                write_file(
                    handle,
                    HELLO.as_ptr(),
                    HELLO.len() as u32,
                    &mut written,
                    core::ptr::null_mut(),
                )
            },
            1
        );
        assert_eq!(written, HELLO.len() as u32);
    }
    let writes = console_writes();
    assert_eq!(
        writes.iter().map(|(handle, _)| *handle).collect::<Vec<_>>(),
        [STDOUT, STDERR, STDOUT]
    );
    assert!(writes.iter().all(|(_, bytes)| bytes == HELLO));
}

/// WriteFile without a count pointer still writes; a zero-length write succeeds and stores zero.
#[test]
fn write_file_count_pointer_and_empty_writes() {
    console_writes();
    assert_eq!(
        unsafe {
            write_file(
                STDOUT,
                HELLO.as_ptr(),
                HELLO.len() as u32,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            )
        },
        1
    );
    let mut written = 0xCCCC_CCCCu32;
    assert_eq!(
        unsafe {
            write_file(
                STDERR,
                HELLO.as_ptr(),
                0,
                &mut written,
                core::ptr::null_mut(),
            )
        },
        1
    );
    assert_eq!(written, 0);
    assert_eq!(console_writes(), [(STDOUT, HELLO.to_vec())]);
    file_at(0, 0);
    written = 0xCCCC_CCCC;
    assert_eq!(
        unsafe {
            write_file(
                HANDLE,
                HELLO.as_ptr(),
                5,
                &mut written,
                core::ptr::null_mut(),
            )
        },
        1
    );
    assert_eq!(written, 5);
    assert_eq!(
        calls(),
        [Call::Write {
            handle: HANDLE,
            bytes: HELLO[..5].to_vec(),
            offset: None
        }]
    );
}

/// WriteFile refuses stdin and the console's overlapped requests (WriteConsoleA's rules:
/// ERROR_INVALID_HANDLE, ERROR_INVALID_PARAMETER) and any handle naming no file (NtWriteFile's
/// STATUS_INVALID_HANDLE), the count zeroed first as Windows 2000's WriteFile zeroes it
/// (unverified).
#[test]
fn write_file_refuses_other_handles_and_overlapped_requests() {
    console_writes();
    calls();
    let mut overlapped = [0u32; 5];
    let count = HELLO.len() as u32;
    for (handle, overlapped, error) in [
        (STDIN, core::ptr::null_mut(), 6),
        (0xF, core::ptr::null_mut(), 6),
        (INVALID_HANDLE_VALUE, core::ptr::null_mut(), 6),
        (4, core::ptr::null_mut(), 6),
        (0, core::ptr::null_mut(), 6),
        (STDOUT, overlapped.as_mut_ptr() as *mut Overlapped, 87),
    ] {
        let mut written = 0xCCCC_CCCCu32;
        assert_eq!(
            unsafe { write_file(handle, HELLO.as_ptr(), count, &mut written, overlapped) },
            0,
            "{handle:#x}"
        );
        assert_eq!((written, last_error()), (0, error), "{handle:#x}");
    }
    assert!(console_writes().is_empty());
}

/// FlushFileBuffers: a console handle's input buffer flushed at the console server
/// (FlushConsoleInputBuffer, as Windows 2000's: stdin TRUE, an output handle or one naming nothing
/// ERROR_INVALID_HANDLE), no file service asked; a file's through NtFlushBuffersFile.
#[test]
fn flush_file_buffers_succeeds() {
    file_at(0, 0);
    assert_eq!(flush_file_buffers(STDIN), 1);
    assert_eq!(flush_file_buffers(-10i32 as u32), 1);
    for handle in [STDOUT, STDERR, 0xF] {
        crate::base::set_last_error(0);
        assert_eq!(flush_file_buffers(handle), 0, "{handle:#x}");
        assert_eq!(last_error(), 6, "{handle:#x}");
    }
    assert!(calls().is_empty());
    assert_eq!(flush_file_buffers(HANDLE), 1);
    assert_eq!(calls(), [Call::Flush { handle: HANDLE }]);
    assert_eq!(flush_file_buffers(0x40), 0);
    assert_eq!(last_error(), 6);
}

/// GetFileType: a console handle naming a console object is a character device (FILE_TYPE_CHAR:
/// VerifyConsoleIoHandle); a file's device decides (a disk: FILE_TYPE_DISK); a handle naming
/// nothing — a console handle too — is FILE_TYPE_UNKNOWN with ERROR_INVALID_HANDLE.
#[test]
fn get_file_type_answers_the_device_type() {
    for handle in [STDIN, STDOUT, STDERR, -10i32 as u32] {
        assert_eq!(get_file_type(handle), 2, "{handle:#x}");
    }
    assert_eq!(get_file_type(HANDLE), 1);
    for handle in [4, INVALID_HANDLE_VALUE, 0, 0xF] {
        crate::base::set_last_error(0);
        assert_eq!(get_file_type(handle), 0, "{handle:#x}");
        assert_eq!(last_error(), 6, "{handle:#x}");
    }
}

/// SetFilePointer on a handle that names no open file — a console handle, a closed or foreign
/// value — is INVALID_SET_FILE_POINTER with ERROR_INVALID_HANDLE; a bad move method
/// ERROR_INVALID_PARAMETER before the handle is looked at.
#[test]
fn set_file_pointer_refuses_non_file_handles() {
    for handle in [STDIN, STDOUT, 0x40, INVALID_HANDLE_VALUE, 0] {
        crate::base::set_last_error(0);
        assert_eq!(
            unsafe { set_file_pointer(handle, 0, core::ptr::null_mut(), 0) },
            INVALID_SET_FILE_POINTER,
            "{handle:#x}"
        );
        assert_eq!(last_error(), 6, "{handle:#x}");
    }
    assert_eq!(
        unsafe { set_file_pointer(HANDLE, 0, core::ptr::null_mut(), 3) },
        INVALID_SET_FILE_POINTER
    );
    assert_eq!(last_error(), 87);
}

/// SetFilePointer's arithmetic, Windows 2000's: from the start, the position or the end; the
/// sign-extended low dword without a high one, the 64-bit pair with; a target before the start
/// ERROR_NEGATIVE_SEEK and one past 4 GiB without a high dword ERROR_INVALID_PARAMETER, the
/// position kept; a success reading as INVALID_SET_FILE_POINTER clears the last error.
#[test]
fn set_file_pointer_moves_from_each_base() {
    file_at(150_000, 100);
    let position = || FILE.with(|file| file.borrow().position);
    assert_eq!(
        unsafe { set_file_pointer(HANDLE, 50, core::ptr::null_mut(), 1) },
        150
    );
    assert_eq!(
        unsafe { set_file_pointer(HANDLE, -10i32 as u32, core::ptr::null_mut(), 2) },
        149_990
    );
    assert_eq!(
        unsafe { set_file_pointer(HANDLE, -1i32 as u32, core::ptr::null_mut(), 0) },
        INVALID_SET_FILE_POINTER
    );
    assert_eq!((last_error(), position()), (131, 149_990));
    let mut high = 1i32;
    crate::base::set_last_error(0xDEAD);
    assert_eq!(unsafe { set_file_pointer(HANDLE, 0, &mut high, 0) }, 0);
    assert_eq!((high, position(), last_error()), (1, 1 << 32, 0xDEAD));
    assert_eq!(
        unsafe { set_file_pointer(HANDLE, 0, core::ptr::null_mut(), 1) },
        INVALID_SET_FILE_POINTER
    );
    assert_eq!(last_error(), 87, "past 4 GiB without a high dword");
    let mut high = 0i32;
    assert_eq!(
        unsafe { set_file_pointer(HANDLE, 0xFFFF_FFFF, &mut high, 0) },
        INVALID_SET_FILE_POINTER
    );
    assert_eq!(
        (high, last_error()),
        (0, 0),
        "a success reading as the failure value"
    );
}

/// DeleteFileA opens the file for DELETE alone (sharing everything, no directory) and marks it
/// for deletion; RemoveDirectoryA the same of a directory; the open's failure is the call's.
#[test]
fn deletes_open_for_delete_then_dispose() {
    file_at(0, 0);
    assert_eq!(unsafe { delete_file_a(b"C:\\F.TXT\0".as_ptr()) }, 1);
    let recorded = calls();
    assert!(
        matches!(&recorded[0], Call::Open { access: 0x0001_0000, share: 7, options, .. } if options & 0x41 == 0x40)
    );
    assert_eq!(
        recorded[1],
        Call::Set {
            handle: HANDLE,
            class: 13,
            bytes: vec![1]
        }
    );
    assert_eq!(unsafe { remove_directory_a(b"C:\\D\0".as_ptr()) }, 1);
    assert!(matches!(&calls()[0], Call::Open { options, .. } if options & 0x41 == 0x1));
    fail_next(0xC000_00BA);
    assert_eq!(unsafe { delete_file_a(b"C:\\D\0".as_ptr()) }, 0);
    assert_eq!(last_error(), 5, "STATUS_FILE_IS_A_DIRECTORY");
}

/// MoveFileA renames to the new name's whole NT path (no replace, no root).
#[test]
fn move_file_renames_to_the_nt_path() {
    file_at(0, 0);
    assert_eq!(
        unsafe { move_file_a(b"C:\\A.TXT\0".as_ptr(), b"C:\\SUB\\B.TXT\0".as_ptr()) },
        1
    );
    let recorded = calls();
    assert!(
        matches!(&recorded[0], Call::Open { access, share: 3, .. } if access & 0x0001_0000 != 0)
    );
    let Call::Set {
        class: 10, bytes, ..
    } = &recorded[1]
    else {
        panic!("{recorded:?}")
    };
    assert_eq!(&bytes[..12], &[0, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0]);
    let name: Vec<u16> = bytes[12..]
        .chunks(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect();
    assert_eq!(String::from_utf16(&name).unwrap(), "\\??\\C:\\SUB\\B.TXT");
}

/// GetFullPathNameA: the length and the file part when it fits, else the size needed; an empty
/// path ERROR_PATH_NOT_FOUND.
#[test]
fn get_full_path_name_folds_against_the_current_directory() {
    CURRENT_DIRECTORY
        .with(|current| *current.borrow_mut() = "C:\\CORPUS\\".encode_utf16().collect());
    let mut buffer = [0xCCu8; 64];
    let mut part = core::ptr::null_mut();
    let length = unsafe {
        get_full_path_name_a(
            b"DATA\\SUB\\..\\SMALL.TXT\0".as_ptr(),
            64,
            buffer.as_mut_ptr(),
            &mut part,
        )
    };
    assert_eq!(
        &buffer[..length as usize + 1],
        b"C:\\CORPUS\\DATA\\SMALL.TXT\0"
    );
    assert_eq!(part as usize - buffer.as_ptr() as usize, 15);
    assert_eq!(
        unsafe { get_full_path_name_a(b"X\0".as_ptr(), 4, buffer.as_mut_ptr(), &mut part) },
        12,
        "the size it needs"
    );
    let length =
        unsafe { get_full_path_name_a(b"C:\\\0".as_ptr(), 64, buffer.as_mut_ptr(), &mut part) };
    assert_eq!(
        (length, part.is_null()),
        (3, true),
        "the root has no file part"
    );
    assert_eq!(
        unsafe { get_full_path_name_a(b"\0".as_ptr(), 64, buffer.as_mut_ptr(), &mut part) },
        0
    );
    assert_eq!(last_error(), 3);
}

/// FindClose of INVALID_HANDLE_VALUE or null is ERROR_INVALID_HANDLE, and so is FindNextFile of
/// INVALID_HANDLE_VALUE.
#[test]
fn find_handles_refuse_the_invalid_value() {
    for handle in [INVALID_HANDLE_VALUE, 0] {
        assert_eq!(unsafe { crate::files::find::find_close_export(handle) }, 0);
        assert_eq!(last_error(), 6);
    }
    let mut data = [0u8; 320];
    assert_eq!(
        unsafe { crate::files::find::find_next_file_a(INVALID_HANDLE_VALUE, data.as_mut_ptr()) },
        0
    );
    assert_eq!(last_error(), 6);
}
