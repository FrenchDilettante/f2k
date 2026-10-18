//! The handle-level file calls whose console branches kernel32 serves: WriteFile, FlushFileBuffers
//! and GetFileType. A standard handle's pseudo-value names the process parameters' handle, and a
//! console handle goes to the console server (WriteConsoleA, FlushConsoleInputBuffer,
//! VerifyConsoleIoHandle), as Windows 2000's hands them. The file halves are the NT file services'
//! (NtWriteFile and NtFlushBuffersFile with the write side, B9; NtQueryVolumeInformationFile with
//! the read side, B8): until then a file handle is answered as the comments say. ReadFile, whose
//! file half the kernel still serves, keeps its console branch for its move (B8):
//! `console::read_console`.

use crate::base::{is_console_handle, set_last_error, standard_handle};
use crate::console;

const ERROR_INVALID_HANDLE: u32 = 6;
const ERROR_CALL_NOT_IMPLEMENTED: u32 = 120;

/// GetFileType's answers.
const FILE_TYPE_UNKNOWN: u32 = 0;
const FILE_TYPE_DISK: u32 = 1;
const FILE_TYPE_CHAR: u32 = 2;

/// Store `value` where the caller asked (a null pointer asks for nothing).
///
/// # Safety
///
/// `at` is null or points at a dword.
unsafe fn put(at: *mut u32, value: u32) {
    if !at.is_null() {
        // SAFETY: the caller's dword.
        unsafe { at.write_unaligned(value) };
    }
}

/// WriteFile: `count` bytes of the caller's, the count written stored (zeroed first, so a failure
/// reports none). A console handle's bytes go to the console (WriteConsoleA, the OVERLAPPED its
/// reserved argument), as Windows 2000's WriteFile hands them. A file handle's write is the
/// FAT32 write side's (NtWriteFile, B9): until then it fails with ERROR_CALL_NOT_IMPLEMENTED.
///
/// # Safety
///
/// `buffer` holds `count` bytes; `written` is null or points at a dword; `overlapped` is null or
/// points at an OVERLAPPED.
#[unsafe(export_name = "f2k_export_WriteFile")]
pub unsafe extern "system" fn write_file(
    file: u32,
    buffer: *const u8,
    count: u32,
    written: *mut u32,
    overlapped: *mut u8,
) -> u32 {
    // SAFETY: the caller's slot.
    unsafe { put(written, 0) };
    let file = standard_handle(file);
    if is_console_handle(file) {
        // SAFETY: the caller's arguments.
        return unsafe { console::write_console_a(file, buffer, count, written, overlapped) };
    }
    set_last_error(ERROR_CALL_NOT_IMPLEMENTED);
    0
}

/// FlushFileBuffers: a console handle's input buffer emptied (FlushConsoleInputBuffer, as Windows
/// 2000's hands it — an output handle is ERROR_INVALID_HANDLE there: the console's writes are
/// never buffered). A file's writes reach the volume as they are made (F2K writes no file yet:
/// NtFlushBuffersFile comes with the write side, B9), so a file handle's flush succeeds.
#[unsafe(export_name = "f2k_export_FlushFileBuffers")]
pub extern "system" fn flush_file_buffers(file: u32) -> u32 {
    let file = standard_handle(file);
    if is_console_handle(file) {
        return console::flush_console_input_buffer(file);
    }
    1
}

/// GetFileType: a console handle naming a console object is a character device (VerifyConsoleIoHandle,
/// as Windows 2000's asks the console; one naming none is FILE_TYPE_UNKNOWN with
/// ERROR_INVALID_HANDLE); a null handle FILE_TYPE_UNKNOWN with ERROR_INVALID_HANDLE. Any other
/// handle's device type is FileFsDeviceInformation's (NtQueryVolumeInformationFile, B8): until
/// then it is a disk's file — the only other handles the C runtime asks about are its files'.
#[unsafe(export_name = "f2k_export_GetFileType")]
pub extern "system" fn get_file_type(file: u32) -> u32 {
    let file = standard_handle(file);
    if is_console_handle(file) {
        if console::verify_console_io_handle(file) {
            return FILE_TYPE_CHAR;
        }
        set_last_error(ERROR_INVALID_HANDLE);
        return FILE_TYPE_UNKNOWN;
    }
    if file == 0 {
        set_last_error(ERROR_INVALID_HANDLE);
        return FILE_TYPE_UNKNOWN;
    }
    FILE_TYPE_DISK
}
