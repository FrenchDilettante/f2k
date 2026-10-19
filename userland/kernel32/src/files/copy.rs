//! CopyFileA: kernel32's own loop, as Windows 2000's BaseCopyStream is — the source opened for
//! reading (sharing reads), the target made (CREATE_NEW when it must not exist, else
//! CREATE_ALWAYS) for writing and delete with the source's attributes and sharing nothing, the bytes
//! moved through a buffer, the source's last-write time set on the target. A copy that fails once
//! the target exists takes the target back (its delete). A target that is the source, under any
//! spelling, is refused by the sharing (ERROR_SHARING_VIOLATION).

use rtl::status::nt_success;

use super::handle::create_file_w;
use super::*;
use crate::base::set_last_nt_error;

/// CreateFileA's dispositions and the flag the copy opens its files with.
const CREATE_NEW: u32 = 1;
const CREATE_ALWAYS: u32 = 2;
const OPEN_EXISTING: u32 = 3;
const FILE_FLAG_SEQUENTIAL_SCAN: u32 = 0x0800_0000;

/// The buffer the bytes move through.
const COPY_CHUNK: usize = 0x1_0000;

/// The copy's work once both files are open: the bytes, then the last-write time. The status that
/// failed it.
fn copy_stream(source: u32, target: u32, buffer: &mut [u8], last_write: u64) -> Result<(), u32> {
    loop {
        let mut io_status = IoStatus::default();
        // SAFETY: ntdll's export, into the buffer.
        let status = unsafe {
            nt::NtReadFile(source, 0, 0, 0, &mut io_status, buffer.as_mut_ptr(), buffer.len() as u32, core::ptr::null(), core::ptr::null())
        };
        if status == STATUS_END_OF_FILE || (nt_success(status) && io_status.information == 0) {
            break;
        }
        if !nt_success(status) {
            return Err(status);
        }
        let read = io_status.information;
        // SAFETY: ntdll's export, from the bytes just read.
        let status = unsafe {
            nt::NtWriteFile(target, 0, 0, 0, &mut io_status, buffer.as_ptr(), read, core::ptr::null(), core::ptr::null())
        };
        if !nt_success(status) {
            return Err(status);
        }
    }
    let mut basic = [0u8; 40];
    basic[16..24].copy_from_slice(&last_write.to_le_bytes());
    let status = set(target, FILE_BASIC_INFORMATION, &basic);
    if nt_success(status) {
        Ok(())
    } else {
        Err(status)
    }
}

/// CopyFileA (see the module's): TRUE with the last error cleared; FALSE with the error — a target
/// that exists under fail-if-exists ERROR_FILE_EXISTS, a read-only one or a directory
/// ERROR_ACCESS_DENIED.
///
/// # Safety
///
/// Both names are NUL-terminated strings.
#[unsafe(export_name = "f2k_export_CopyFileA")]
pub unsafe extern "system" fn copy_file_a(from: *const u8, to: *const u8, fail_if_exists: u32) -> u32 {
    // SAFETY: the caller's strings.
    let (Some(from), Some(to)) = (unsafe { widen(from) }, unsafe { widen(to) }) else {
        return 0;
    };
    // SAFETY: no security attributes.
    let source = unsafe { create_file_w(&from, GENERIC_READ, FILE_SHARE_READ, core::ptr::null(), OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN) };
    if source == INVALID_HANDLE_VALUE {
        return 0;
    }
    let mut basic = [0u8; 40];
    let status = query(source, FILE_BASIC_INFORMATION, &mut basic);
    if !nt_success(status) {
        close(source);
        set_last_nt_error(status);
        return 0;
    }
    let disposition = if fail_if_exists != 0 { CREATE_NEW } else { CREATE_ALWAYS };
    // SAFETY: as above.
    let target = unsafe {
        create_file_w(&to, GENERIC_WRITE | DELETE, 0, core::ptr::null(), disposition, word(&basic, 32) | FILE_FLAG_SEQUENTIAL_SCAN)
    };
    if target == INVALID_HANDLE_VALUE {
        close(source);
        return 0;
    }
    // SAFETY: ntdll's export: the copy's buffer.
    let buffer = unsafe { nt::RtlAllocateHeap(process_heap(), 0, COPY_CHUNK) };
    let copied = if buffer.is_null() {
        Err(0xC000_0017)
    } else {
        // SAFETY: the fresh block.
        let result = copy_stream(source, target, unsafe { core::slice::from_raw_parts_mut(buffer, COPY_CHUNK) }, quad(&basic, 16));
        // SAFETY: ntdll's export, over its block.
        unsafe { nt::RtlFreeHeap(process_heap(), 0, buffer) };
        result
    };
    if let Err(status) = copied {
        set(target, FILE_DISPOSITION_INFORMATION, &[1]);
        close(target);
        close(source);
        set_last_nt_error(status);
        return 0;
    }
    close(target);
    close(source);
    set_last_error(0);
    1
}
