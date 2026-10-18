//! The handle-level file calls' console branches: WriteFile, FlushFileBuffers and GetFileType, a
//! console handle (or a standard handle's pseudo-value) going to the console server. Their file
//! halves come with the NT file services (B8, B9).

use super::last_error;
use crate::files::handle::*;
use crate::nt::host::console_writes;

const STDIN: u32 = 0x3;
const STDOUT: u32 = 0x7;
const STDERR: u32 = 0xB;
const INVALID_HANDLE_VALUE: u32 = 0xFFFF_FFFF;

/// The hello fixture's one console write: the CRT's text-mode stdout hands WriteFile CR LF.
const HELLO: &[u8] = b"Hello, world!\r\n";

/// WriteFile on stdout or stderr (or their pseudo-handles) hands the bytes to the console and
/// stores the count.
#[test]
fn write_file_writes_to_the_console() {
    console_writes();
    for handle in [STDOUT, STDERR, -11i32 as u32] {
        let mut written = 0xCCCC_CCCCu32;
        // SAFETY: the buffer and its length, a dword.
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
    // SAFETY: the buffer and its length.
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
    // SAFETY: as above, a dword.
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
}

/// WriteFile refuses stdin and the console's overlapped requests (WriteConsoleA's rules:
/// ERROR_INVALID_HANDLE, ERROR_INVALID_PARAMETER), the count zeroed first as Windows 2000's
/// WriteFile zeroes it (FS-17); a file handle's write waits for the write side (B9).
#[test]
fn write_file_refuses_other_handles_and_overlapped_requests() {
    console_writes();
    let mut overlapped = [0u32; 5];
    let count = HELLO.len() as u32;
    for (handle, overlapped, error) in [
        (STDIN, core::ptr::null_mut(), 6),
        (0xF, core::ptr::null_mut(), 6),
        (INVALID_HANDLE_VALUE, core::ptr::null_mut(), 120),
        (4, core::ptr::null_mut(), 120),
        (0, core::ptr::null_mut(), 120),
        (STDOUT, overlapped.as_mut_ptr() as *mut u8, 87),
    ] {
        let mut written = 0xCCCC_CCCCu32;
        // SAFETY: the buffer and its length, a dword, an OVERLAPPED or none.
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
/// ERROR_INVALID_HANDLE); a file's writes are already on the volume.
#[test]
fn flush_file_buffers_succeeds() {
    assert_eq!(flush_file_buffers(STDIN), 1);
    assert_eq!(flush_file_buffers(-10i32 as u32), 1);
    for handle in [STDOUT, STDERR, 0xF] {
        crate::base::set_last_error(0);
        assert_eq!(flush_file_buffers(handle), 0, "{handle:#x}");
        assert_eq!(last_error(), 6, "{handle:#x}");
    }
    assert_eq!(flush_file_buffers(0x40), 1);
}

/// GetFileType: a console handle naming a console object is a character device (FILE_TYPE_CHAR:
/// VerifyConsoleIoHandle — the runtime fixture's console block's 2 2 2); a console handle naming
/// nothing, and a null handle, are FILE_TYPE_UNKNOWN with ERROR_INVALID_HANDLE; any other handle
/// a disk's file until its device can be asked (B8).
#[test]
fn get_file_type_answers_the_device_type() {
    for handle in [
        STDIN,
        STDOUT,
        STDERR,
        -10i32 as u32,
        -11i32 as u32,
        -12i32 as u32,
    ] {
        assert_eq!(get_file_type(handle), 2, "{handle:#x}");
    }
    for handle in [0xF, 0] {
        crate::base::set_last_error(0);
        assert_eq!((get_file_type(handle), last_error()), (0, 6), "{handle:#x}");
    }
    assert_eq!(get_file_type(0x40), 1);
}
