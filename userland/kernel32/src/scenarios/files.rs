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
///
/// Pins: kernel32.CreateFileA
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
///
/// Pins: kernel32.CreateFileA
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
///
/// Pins: kernel32.CreateFileA
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
/// a console handle's read is the console's (ReadConsoleA): stdin's line, as typed (here queued
/// with WriteConsoleInputA), an output handle is ERROR_INVALID_HANDLE.
///
/// Pins: kernel32.ReadFile
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
    // x and Enter, each a keydown and a keyup.
    let mut typed = [[0u8; 20]; 4];
    for (record, (down, character)) in
        typed
            .iter_mut()
            .zip([(1, b'x'), (0, b'x'), (1, b'\r'), (0, b'\r')])
    {
        record[0] = 1;
        record[4] = down;
        record[8] = 1;
        record[14] = character;
    }
    let mut queued = 0;
    // SAFETY: four records, a dword.
    unsafe { crate::console::write_console_input_a(STDIN, typed.as_ptr().cast(), 4, &mut queued) };
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
    assert_eq!((read, buffer[0], last_error()), (1, b'x', 0xDEAD));
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
///
/// Pins: kernel32.WriteFile
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
///
/// Pins: kernel32.WriteFile
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
///
/// Pins: kernel32.WriteFile
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
///
/// Pins: kernel32.FlushFileBuffers
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
///
/// Pins: kernel32.GetFileType
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
///
/// Pins: kernel32.SetFilePointer
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
///
/// Pins: kernel32.SetFilePointer
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
///
/// Pins: kernel32.DeleteFileA, kernel32.RemoveDirectoryA
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
///
/// Pins: kernel32.MoveFileA
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

/// MoveFileExA: MOVEFILE_REPLACE_EXISTING is the rename's ReplaceIfExists; a NULL new name is
/// ERROR_PATH_NOT_FOUND once the source opened; a move until the reboot is the stub's.
///
/// Pins: kernel32.MoveFileExA
#[test]
fn move_file_ex_replaces_when_asked() {
    file_at(0, 0);
    let (from, to) = (b"C:\\A.TXT\0".as_ptr(), b"C:\\B.TXT\0".as_ptr());
    assert_eq!(unsafe { move_file_ex_a(from, to, 0x1 | 0x2 | 0x8) }, 1);
    let recorded = calls();
    let Call::Set {
        class: 10, bytes, ..
    } = &recorded[1]
    else {
        panic!("{recorded:?}")
    };
    assert_eq!(bytes[0], 1, "ReplaceIfExists");
    assert_eq!(unsafe { move_file_ex_a(from, core::ptr::null(), 0) }, 0);
    assert_eq!(last_error(), 3);
    assert_eq!(calls().len(), 1, "the source opened, nothing renamed");
    assert_eq!(unsafe { move_file_ex_a(from, core::ptr::null(), 0x4) }, 0);
    assert_eq!(last_error(), 120);
    assert!(calls().is_empty());
}

/// SearchPathA: each directory of the list in turn (a missing one passed over), the extension added
/// to a name without one, the path found made full with its file part; the size needed when the
/// buffer cannot hold it; an empty name ERROR_INVALID_PARAMETER, one found nowhere
/// ERROR_FILE_NOT_FOUND; a name with a path of its own tried alone.
///
/// Pins: kernel32.SearchPathA
#[test]
fn search_path_tries_each_directory() {
    use crate::files::search::search_path_a;
    use crate::nt::files::{EXISTENCE_ASKED, EXISTING_PATHS};
    CURRENT_DIRECTORY
        .with(|current| *current.borrow_mut() = "C:\\CORPUS\\".encode_utf16().collect());
    EXISTING_PATHS
        .with(|existing| *existing.borrow_mut() = vec!["C:\\CORPUS\\DATA\\SMALL.TXT".into()]);
    EXISTENCE_ASKED.with(|asked| asked.borrow_mut().clear());
    let mut buffer = [0xCCu8; 64];
    let mut part = core::ptr::null_mut();
    let list = b"C:\\NODIR;;DATA\\\0".as_ptr();
    let length = unsafe {
        search_path_a(
            list,
            b"SMALL\0".as_ptr(),
            b".TXT\0".as_ptr(),
            64,
            buffer.as_mut_ptr(),
            &mut part,
        )
    };
    assert_eq!(length, 24);
    assert_eq!(&buffer[..25], b"C:\\CORPUS\\DATA\\SMALL.TXT\0");
    assert_eq!(part as usize, buffer.as_ptr() as usize + 15);
    EXISTENCE_ASKED
        .with(|asked| assert_eq!(*asked.borrow(), ["C:\\NODIR\\SMALL.TXT", "DATA\\SMALL.TXT"]));
    let name = b"SMALL.TXT\0".as_ptr();
    let null = core::ptr::null_mut();
    let needed = unsafe {
        search_path_a(
            list,
            name,
            b".BIN\0".as_ptr(),
            24,
            buffer.as_mut_ptr(),
            null,
        )
    };
    assert_eq!(needed, 25, "the size needed, the extension not added");
    assert_eq!(
        unsafe {
            search_path_a(
                list,
                b"\0".as_ptr(),
                null.cast(),
                64,
                buffer.as_mut_ptr(),
                null,
            )
        },
        0
    );
    assert_eq!(last_error(), 87);
    assert_eq!(
        unsafe {
            search_path_a(
                list,
                b"NONE.TXT\0".as_ptr(),
                null.cast(),
                64,
                buffer.as_mut_ptr(),
                null,
            )
        },
        0
    );
    assert_eq!(last_error(), 2);
    EXISTENCE_ASKED.with(|asked| asked.borrow_mut().clear());
    let absolute = b"C:\\CORPUS\\DATA\\SMALL.TXT\0".as_ptr();
    assert_eq!(
        unsafe { search_path_a(list, absolute, null.cast(), 64, buffer.as_mut_ptr(), null) },
        24
    );
    EXISTENCE_ASKED.with(|asked| assert_eq!(*asked.borrow(), ["C:\\CORPUS\\DATA\\SMALL.TXT"]));
}

/// GetFullPathNameA: the length and the file part when it fits, else the size needed; an empty
/// path ERROR_PATH_NOT_FOUND.
///
/// Pins: kernel32.GetFullPathNameA
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
///
/// Pins: kernel32.FindClose, kernel32.FindNextFileA
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

/// Set (or, for none, delete) an environment variable for the temporary path's calls.
fn set_variable(name: &str, value: Option<&str>) {
    let name = format!("{name}\0");
    let value = value.map(|value| format!("{value}\0"));
    let value = value
        .as_ref()
        .map_or(core::ptr::null(), |value| value.as_ptr());
    unsafe { crate::env::set_environment_variable_a(name.as_ptr(), value) };
}

/// GetTempPathA, its answer and the path, as text.
fn temp_path_a() -> (u32, String) {
    let mut buffer = [0u8; 64];
    let length = unsafe { crate::files::temp::get_temp_path_a(64, buffer.as_mut_ptr()) };
    let end = buffer.iter().position(|&byte| byte == 0).unwrap();
    (length, String::from_utf8(buffer[..end].to_vec()).unwrap())
}

/// GetTempPath, as the utility fixture's capture shows it: TMP's directory, else TEMP's, else
/// USERPROFILE's, else the Windows directory, made full (a relative one under the current
/// directory) with a trailing backslash added where it has none. An empty TMP stops the search:
/// the answer is 1, the A form writing the empty string, the W form nothing. A buffer too small
/// gets the size it needs: the A form's untouched, the W form's holding the full path's first
/// units (all of them, without the backslash, when only the backslash does not fit).
///
/// Pins: kernel32.GetTempPathA, kernel32.GetTempPathW
#[test]
fn the_temporary_path_is_tmp_then_temp_then_the_profile_then_windows() {
    use crate::files::temp::{get_temp_path_a, get_temp_path_w};

    let root = b"C:\\WINNT\0\0";
    for (at, pair) in root.chunks(2).enumerate() {
        crate::shared::host::set(
            crate::shared::NT_SYSTEM_ROOT + 4 * at,
            u32::from(pair[0]) | u32::from(pair[1]) << 16,
        );
    }
    CURRENT_DIRECTORY
        .with(|current| *current.borrow_mut() = "C:\\CORPUS\\".encode_utf16().collect());
    assert_eq!(temp_path_a(), (9, "C:\\WINNT\\".into()));
    set_variable("USERPROFILE", Some("C:\\PROF"));
    assert_eq!(temp_path_a(), (8, "C:\\PROF\\".into()));
    set_variable("TEMP", Some("C:\\T2"));
    assert_eq!(temp_path_a(), (6, "C:\\T2\\".into()));
    set_variable("TMP", Some("C:\\T1"));
    assert_eq!(temp_path_a(), (6, "C:\\T1\\".into()));
    set_variable("TMP", Some("C:\\T1\\"));
    assert_eq!(temp_path_a(), (6, "C:\\T1\\".into()));
    set_variable("TMP", Some("rel"));
    assert_eq!(temp_path_a(), (14, "C:\\CORPUS\\rel\\".into()));

    set_variable("TMP", Some(""));
    let mut buffer = [0x5Au8; 16];
    assert_eq!(unsafe { get_temp_path_a(16, buffer.as_mut_ptr()) }, 1);
    assert_eq!(&buffer[..2], b"\0Z");
    let mut wide = [0x5A5Au16; 16];
    assert_eq!(unsafe { get_temp_path_w(16, wide.as_mut_ptr()) }, 1);
    assert_eq!(wide, [0x5A5A; 16]);

    set_variable("TMP", Some("C:\\NOWHERE\\..\\T3"));
    assert_eq!(temp_path_a(), (6, "C:\\T3\\".into()));
    for size in [0, 3, 6] {
        let mut buffer = [0x5Au8; 16];
        assert_eq!(unsafe { get_temp_path_a(size, buffer.as_mut_ptr()) }, 7);
        assert_eq!(buffer, [0x5A; 16], "size {size}");
    }
    let mut buffer = [0x5Au8; 16];
    assert_eq!(unsafe { get_temp_path_a(7, buffer.as_mut_ptr()) }, 6);
    assert_eq!(&buffer[..8], b"C:\\T3\\\0Z");

    let wide_of = |text: &str| -> Vec<u16> { text.encode_utf16().collect() };
    for (size, written) in [(0, ""), (3, "C:\0"), (6, "C:\\T3\0")] {
        let mut wide = [0x5A5Au16; 16];
        assert_eq!(unsafe { get_temp_path_w(size, wide.as_mut_ptr()) }, 7);
        let written = wide_of(written);
        assert_eq!(wide[..written.len()], written[..], "size {size}");
        assert!(wide[written.len()..].iter().all(|&unit| unit == 0x5A5A));
    }
    let mut wide = [0x5A5Au16; 16];
    assert_eq!(unsafe { get_temp_path_w(7, wide.as_mut_ptr()) }, 6);
    assert_eq!(wide[..8], wide_of("C:\\T3\\\0\u{5A5A}")[..]);
}

/// The stand-in file's attributes: a directory (GetTempFileName's path), or a file.
fn stand_in_attributes(attributes: u32) {
    FILE.with(|file| file.borrow_mut().attributes = attributes);
}

const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
const FILE_ATTRIBUTE_ARCHIVE: u32 = 0x20;

/// GetTempFileName with a number of the caller's, as the utility fixture's capture shows it:
/// `<path>\<three prefix characters><its low 16 bits in uppercase hexadecimal>.tmp`, no backslash
/// doubled, those 16 bits answered, no file made (the path's attributes asked, nothing created).
///
/// Pins: kernel32.GetTempFileNameA, kernel32.GetTempFileNameW
#[test]
fn a_temporary_file_name_with_the_caller_s_number_makes_no_file() {
    use crate::files::temp::{get_temp_file_name_a, get_temp_file_name_w};

    stand_in_attributes(FILE_ATTRIBUTE_DIRECTORY);
    calls();
    for (path, prefix, unique, number, name) in [
        ("C:\\TF", "abc", 0x1234, 0x1234, "C:\\TF\\abc1234.tmp"),
        ("C:\\TF", "abcdef", 0x1234, 0x1234, "C:\\TF\\abc1234.tmp"),
        ("C:\\TF", "", 0xABCD, 0xABCD, "C:\\TF\\ABCD.tmp"),
        ("C:\\TF", "abc", 0xA, 0xA, "C:\\TF\\abcA.tmp"),
        ("C:\\TF", "abc", 0x12345, 0x2345, "C:\\TF\\abc2345.tmp"),
        ("C:\\TF\\", "abc", 0x1234, 0x1234, "C:\\TF\\abc1234.tmp"),
    ] {
        let mut buffer = [0x5Au8; 260];
        let (path_z, prefix_z) = (format!("{path}\0"), format!("{prefix}\0"));
        let answer = unsafe {
            get_temp_file_name_a(
                path_z.as_ptr(),
                prefix_z.as_ptr(),
                unique,
                buffer.as_mut_ptr(),
            )
        };
        assert_eq!(answer, number, "{path} {prefix} {unique:#x}");
        assert_eq!(&buffer[..name.len() + 1], format!("{name}\0").as_bytes());

        let mut wide = [0x5A5Au16; 260];
        let path_w: Vec<u16> = path.encode_utf16().chain([0]).collect();
        let prefix_w: Vec<u16> = prefix.encode_utf16().chain([0]).collect();
        let answer = unsafe {
            get_temp_file_name_w(
                path_w.as_ptr(),
                prefix_w.as_ptr(),
                unique,
                wide.as_mut_ptr(),
            )
        };
        assert_eq!(answer, number);
        let expected: Vec<u16> = name.encode_utf16().chain([0]).collect();
        assert_eq!(wide[..expected.len()], expected[..]);
    }
    assert_eq!(created(), [], "no file made");
}

/// GetTempFileName in a path that is not an existing directory, with the caller's number or none:
/// 0 and ERROR_DIRECTORY, nothing created; the A form's buffer untouched, the W form's holding the
/// path, terminated (the utility fixture's capture). A file's path is refused the same way.
///
/// Pins: kernel32.GetTempFileNameA, kernel32.GetTempFileNameW
#[test]
fn a_temporary_file_name_needs_an_existing_directory() {
    use crate::files::temp::{get_temp_file_name_a, get_temp_file_name_w};

    const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
    let none: Vec<u16> = "C:\\NONE\0".encode_utf16().collect();
    let prefix: Vec<u16> = "abc\0".encode_utf16().collect();
    stand_in_attributes(FILE_ATTRIBUTE_DIRECTORY);
    for unique in [0x1234, 0] {
        calls();
        let mut untouched = [0x5Au8; 260];
        fail_next(STATUS_OBJECT_NAME_NOT_FOUND);
        let answer = unsafe {
            get_temp_file_name_a(
                b"C:\\NONE\0".as_ptr(),
                b"abc\0".as_ptr(),
                unique,
                untouched.as_mut_ptr(),
            )
        };
        assert_eq!((answer, last_error()), (0, 267), "{unique:#x}");
        assert_eq!(untouched, [0x5A; 260]);

        let mut wide = [0x5A5Au16; 260];
        fail_next(STATUS_OBJECT_NAME_NOT_FOUND);
        let answer = unsafe {
            get_temp_file_name_w(none.as_ptr(), prefix.as_ptr(), unique, wide.as_mut_ptr())
        };
        assert_eq!((answer, last_error()), (0, 267), "{unique:#x}");
        assert_eq!(wide[..none.len()], none[..]);
        assert!(wide[none.len()..].iter().all(|&unit| unit == 0x5A5A));
        assert_eq!(created(), [], "nothing created");
    }

    stand_in_attributes(FILE_ATTRIBUTE_ARCHIVE);
    let mut wide = [0x5A5Au16; 260];
    let answer =
        unsafe { get_temp_file_name_w(none.as_ptr(), prefix.as_ptr(), 0, wide.as_mut_ptr()) };
    assert_eq!((answer, last_error()), (0, 267));
    assert_eq!(created(), []);
}

/// The file names of a self-numbered GetTempFileName's creates, in order (the attribute queries,
/// which ask no access, left out).
fn created() -> Vec<(String, u32)> {
    calls()
        .into_iter()
        .filter_map(|call| match call {
            Call::Open {
                access,
                name,
                disposition,
                ..
            } if access != 0 => Some((name, disposition)),
            _ => None,
        })
        .collect()
}

/// GetTempFileName numbering the name itself (a number of 0): from the tick count's low 16 bits
/// (zero skipped), the file made (NtCreateFile's FILE_CREATE, then closed), the last error cleared
/// and the number answered; a name taken moves on to the next number; another failure is the
/// call's (0 and its error), the W form's buffer holding the name tried, the A form's untouched.
///
/// Pins: kernel32.GetTempFileNameA, kernel32.GetTempFileNameW
#[test]
fn a_self_numbered_temporary_file_name_makes_the_file() {
    use crate::files::temp::{get_temp_file_name_a, get_temp_file_name_w};
    use crate::nt::files::FAIL_AFTER;
    use crate::nt::host::CLOSED;
    use crate::shared::{self, host};

    const FILE_CREATE: u32 = 2;
    const STATUS_OBJECT_NAME_COLLISION: u32 = 0xC000_0035;
    const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
    host::set(shared::TICK_COUNT_MULTIPLIER, 0x0100_0000);
    host::set(shared::TICK_COUNT_LOW, 0x3_0ABC);
    stand_in_attributes(FILE_ATTRIBUTE_DIRECTORY);
    calls();
    CLOSED.with(|closed| closed.borrow_mut().clear());

    let mut buffer = [0x5Au8; 260];
    crate::base::set_last_error(0x0F2F_2F2F);
    let answer = unsafe {
        get_temp_file_name_a(
            b"C:\\TF\0".as_ptr(),
            b"abc\0".as_ptr(),
            0,
            buffer.as_mut_ptr(),
        )
    };
    assert_eq!((answer, last_error()), (0xABC, 0));
    assert_eq!(&buffer[..17], b"C:\\TF\\abcABC.tmp\0");
    assert_eq!(
        created(),
        [("\\??\\C:\\TF\\abcABC.tmp".into(), FILE_CREATE)]
    );
    CLOSED.with(|closed| assert_eq!(*closed.borrow(), [HANDLE]));

    // The path's attributes pass, the first create collides.
    FAIL_AFTER.with(|fail| fail.set((1, STATUS_OBJECT_NAME_COLLISION)));
    let answer = unsafe {
        get_temp_file_name_a(
            b"C:\\TF\0".as_ptr(),
            b"abc\0".as_ptr(),
            0,
            buffer.as_mut_ptr(),
        )
    };
    assert_eq!(answer, 0xABD);
    assert_eq!(&buffer[..17], b"C:\\TF\\abcABD.tmp\0");
    assert_eq!(
        created(),
        [
            ("\\??\\C:\\TF\\abcABC.tmp".into(), FILE_CREATE),
            ("\\??\\C:\\TF\\abcABD.tmp".into(), FILE_CREATE)
        ]
    );

    let mut untouched = [0x5Au8; 260];
    FAIL_AFTER.with(|fail| fail.set((1, STATUS_ACCESS_DENIED)));
    let answer = unsafe {
        get_temp_file_name_a(
            b"C:\\TF\0".as_ptr(),
            b"abc\0".as_ptr(),
            0,
            untouched.as_mut_ptr(),
        )
    };
    assert_eq!((answer, last_error()), (0, 5));
    assert_eq!(untouched, [0x5A; 260]);
    assert_eq!(created().len(), 1, "no other number tried");

    let mut wide = [0x5A5Au16; 260];
    let directory: Vec<u16> = "C:\\TF\0".encode_utf16().collect();
    let prefix: Vec<u16> = "abc\0".encode_utf16().collect();
    FAIL_AFTER.with(|fail| fail.set((1, STATUS_ACCESS_DENIED)));
    let answer =
        unsafe { get_temp_file_name_w(directory.as_ptr(), prefix.as_ptr(), 0, wide.as_mut_ptr()) };
    assert_eq!((answer, last_error()), (0, 5));
    let tried: Vec<u16> = "C:\\TF\\abcABC.tmp\0".encode_utf16().collect();
    assert_eq!(wide[..tried.len()], tried[..]);

    host::set(shared::TICK_COUNT_LOW, 0x5_0000);
    calls();
    let answer =
        unsafe { get_temp_file_name_w(directory.as_ptr(), prefix.as_ptr(), 0, wide.as_mut_ptr()) };
    assert_eq!(answer, 1, "a tick count of zero's low bits starts at 1");
    assert_eq!(created(), [("\\??\\C:\\TF\\abc1.tmp".into(), FILE_CREATE)]);
}
