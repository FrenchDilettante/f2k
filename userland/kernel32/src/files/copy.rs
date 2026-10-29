//! CopyFileA and CopyFileW: kernel32's own loop, as Windows 2000's BaseCopyStream is — the source
//! opened for reading (sharing reads), the target made (CREATE_NEW when it must not exist, else
//! CREATE_ALWAYS) for writing and delete with the source's attributes and sharing nothing, the
//! bytes moved through a buffer, the source's last-write time set on the target. A copy that fails
//! once the target exists takes the target back (its delete). A target that is the source, under
//! any spelling, is refused by the sharing (ERROR_SHARING_VIOLATION).

use rtl::status::nt_success;

use super::handle::create_file_w;
use super::*;
use crate::base::set_last_error;
use crate::error::bool_answer;
use crate::heap::HeapArray;
use crate::nt::IoStatus;
use crate::ntcall::{Destination, Source, Transfer};

/// CreateFileA's dispositions and the flag the copy opens its files with.
const CREATE_NEW: u32 = 1;
const CREATE_ALWAYS: u32 = 2;
const OPEN_EXISTING: u32 = 3;
const FILE_FLAG_SEQUENTIAL_SCAN: u32 = 0x0800_0000;

/// The buffer the bytes move through.
const COPY_CHUNK: usize = 0x1_0000;

/// STATUS_NO_MEMORY: no room on the process heap for the buffer.
const STATUS_NO_MEMORY: u32 = 0xC000_0017;

/// The copy's work once both files are open: the bytes, then the last-write time. The status that
/// failed it.
fn copy_stream(source: u32, target: u32, buffer: &mut [u8], last_write: u64) -> Result<(), u32> {
    loop {
        let mut io_status = IoStatus::default();
        let status = ntcall::read_file(
            source,
            Transfer::AtPosition,
            &mut Out::from(&mut io_status),
            Destination::of(buffer),
        );
        if status == STATUS_END_OF_FILE || (nt_success(status) && io_status.information == 0) {
            break;
        }
        if !nt_success(status) {
            return Err(status);
        }
        let read = &buffer[..io_status.information as usize];
        let status = ntcall::write_file(
            target,
            Transfer::AtPosition,
            &mut Out::from(&mut io_status),
            Source::of(read),
        );
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

/// CopyFileA: both names converted first, then the copy ([`copy_file`]).
///
/// # Safety
///
/// Both names are NUL-terminated strings.
#[unsafe(export_name = "f2k_export_CopyFileA")]
pub unsafe extern "system" fn copy_file_a(
    from: *const u8,
    to: *const u8,
    fail_if_exists: u32,
) -> u32 {
    // SAFETY: the caller's strings (null: the empty one).
    let (from, to) = unsafe { (InStr::optional(from), InStr::optional(to)) };
    let names = both(widen(from.as_ref()), widen(to.as_ref()));
    bool_answer(names.and_then(|(from, to)| copy_file(&from, &to, fail_if_exists)))
}

/// CopyFileW (as [`copy_file_a`]).
///
/// # Safety
///
/// Both names are NUL-terminated UTF-16 strings.
#[unsafe(export_name = "f2k_export_CopyFileW")]
pub unsafe extern "system" fn copy_file_w(
    from: *const u16,
    to: *const u16,
    fail_if_exists: u32,
) -> u32 {
    // SAFETY: the caller's strings.
    let (from, to) = unsafe { (InWStr::new(from), InWStr::new(to)) };
    let names = both(wide(&from), wide(&to));
    bool_answer(names.and_then(|(from, to)| copy_file(&from, &to, fail_if_exists)))
}

/// The copy (see the module's): TRUE with the last error cleared; FALSE with the error — a target
/// that exists under fail-if-exists ERROR_FILE_EXISTS, a read-only one or a directory
/// ERROR_ACCESS_DENIED.
fn copy_file(from: &Wide, to: &Wide, fail_if_exists: u32) -> Result<(), Failure> {
    let source = create_file_w(
        from,
        GENERIC_READ,
        FILE_SHARE_READ,
        None,
        OPEN_EXISTING,
        FILE_FLAG_SEQUENTIAL_SCAN,
    )?;
    let mut basic = [0u8; 40];
    let status = query(source, FILE_BASIC_INFORMATION, &mut basic);
    if !nt_success(status) {
        close(source);
        return Err(Failure::Status(status));
    }
    let disposition = if fail_if_exists != 0 {
        CREATE_NEW
    } else {
        CREATE_ALWAYS
    };
    let target = match create_file_w(
        to,
        GENERIC_WRITE | DELETE,
        0,
        None,
        disposition,
        word(&basic, 32) | FILE_FLAG_SEQUENTIAL_SCAN,
    ) {
        Ok(target) => target,
        Err(failure) => {
            close(source);
            return Err(failure);
        }
    };
    let copied = match HeapArray::<u8>::new(COPY_CHUNK) {
        Err(_) => Err(STATUS_NO_MEMORY),
        Ok(mut buffer) => copy_stream(source, target, &mut buffer, quad(&basic, 16)),
    };
    if let Err(status) = copied {
        set(target, FILE_DISPOSITION_INFORMATION, &[1]);
        close(target);
        close(source);
        return Err(Failure::Status(status));
    }
    close(target);
    close(source);
    set_last_error(0);
    Ok(())
}
