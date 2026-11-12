//! NtLockFile and NtUnlockFile: a disk file's byte-range locks, FastFat's IRP_MJ_LOCK_CONTROL over
//! FsRtl's lock package (see [`crate::fs::file`]'s notes: a lock's owner is the file object and its
//! process, an exclusive lock refuses other owners' reads and writes, a file object's cleanup
//! releases its locks). kernel32's LockFile and UnlockFile are Win32 code over these, as on Windows
//! 2000.
//!
//! The I/O manager's checks come first: the handle (a file object), its rights (a lock asks for
//! read or write access: STATUS_ACCESS_DENIED for neither), the I/O status block, an APC routine
//! (not supported), the range, the event (reset); then the object's device serves the request: a
//! disk file's record takes the lock, a directory's open refuses it (FastFat's
//! STATUS_INVALID_PARAMETER: only a file's open takes locks), and the other devices — a pipe's
//! end, the null device — have no lock control (STATUS_INVALID_DEVICE_REQUEST).

use super::super::call::{Handle, NtCall, NtResult, UserAddr, UserPtr};
use super::common::{complete, completion_event, file_object, signal};
use crate::fs::file::{rights, with_records, Context, FileObject, LockError, LockOwner};
use crate::fs::io;
use crate::ob::Referenced;
use crate::status::*;

/// The owner a call through `object` acts as: the object, in the calling process.
pub(super) fn owner_of(object: &Referenced<FileObject>) -> LockOwner {
    LockOwner {
        object: object.id(),
        process: crate::process::current().id(),
    }
}

/// The checks NtLockFile and NtUnlockFile share, in the I/O manager's order (see the module notes):
/// the object, and the range, (offset, length).
fn lock_request(
    handle: Handle,
    io_status: UserAddr,
    offset: UserPtr<u64>,
    length: UserPtr<u64>,
) -> Result<(Referenced<FileObject>, (u64, u64)), NtStatus> {
    let object = file_object(handle.raw())?;
    if object.granted & (rights::FILE_READ_DATA | rights::FILE_WRITE_DATA) == 0 {
        return Err(STATUS_ACCESS_DENIED);
    }
    io_status.probe(8)?;
    let range = (offset.read()?, length.read()?);
    Ok((object, range))
}

/// The open file a lock call's object names on the disk: a file's open's record (a directory's is
/// STATUS_INVALID_PARAMETER, another device's STATUS_INVALID_DEVICE_REQUEST).
fn locked_file(object: &FileObject) -> Result<crate::fs::file::FileRecordId, NtStatus> {
    match object.context {
        Context::Disk(record) if io::file_at(record).directory => Err(STATUS_INVALID_PARAMETER),
        Context::Disk(record) => Ok(record),
        Context::Pipe(_) | Context::Null => Err(STATUS_INVALID_DEVICE_REQUEST),
    }
}

/// NtLockFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, ByteOffset, Length, Key,
/// FailImmediately, ExclusiveLock): a byte-range lock of the file the handle's object opens, of
/// `Length` bytes at `ByteOffset`, exclusive or shared, for the object in the calling process (see
/// the module notes for the checks). A lock in place overlapping it is STATUS_LOCK_NOT_GRANTED
/// under FailImmediately; without it Windows 2000 waits until the range is free, which F2K does not
/// (logged, STATUS_NOT_IMPLEMENTED). A full lock table is STATUS_INSUFFICIENT_RESOURCES. The I/O
/// status block takes the answer and the event is signaled once the call completes.
#[allow(clippy::too_many_arguments)]
pub fn lock_file(
    _call: &mut NtCall,
    handle: Handle,
    event: Handle,
    routine: UserAddr,
    _context: UserAddr,
    io_status: UserAddr,
    offset: UserPtr<u64>,
    length: UserPtr<u64>,
    key: u32,
    fail_immediately: bool,
    exclusive: bool,
) -> NtResult {
    let (object, range) = lock_request(handle, io_status, offset, length)?;
    if !routine.is_null() {
        return Err(STATUS_NOT_IMPLEMENTED);
    }
    let event = completion_event(event.raw())?;
    let owner = owner_of(&object);
    let result = locked_file(&object).and_then(|record| {
        let taken = with_records(|records| records.lock(record, owner, key, range, exclusive));
        match taken {
            Ok(()) => Ok(STATUS_SUCCESS),
            Err(LockError::Conflict) if fail_immediately => Err(STATUS_LOCK_NOT_GRANTED),
            Err(LockError::Conflict) => {
                crate::dbgprint::unhandled(
                    "ntoskrnl",
                    "NtLockFile",
                    format_args!(
                        "FileHandle={:#x}, ByteOffset={:#x}, Length={:#x}, FailImmediately=FALSE",
                        handle.raw(),
                        range.0,
                        range.1
                    ),
                    format_args!("waiting for a lock in place to go is not yet implemented"),
                );
                Err(STATUS_NOT_IMPLEMENTED)
            }
            Err(LockError::Full) => Err(STATUS_INSUFFICIENT_RESOURCES),
        }
    });
    let status = result.unwrap_or_else(|status| status);
    complete(io_status, status, 0);
    signal(event);
    result
}

/// NtUnlockFile(FileHandle, IoStatusBlock, ByteOffset, Length, Key): the lock of exactly `Length`
/// bytes at `ByteOffset` with `Key` that the handle's object holds in the calling process released
/// (see the module notes for the checks); STATUS_RANGE_NOT_LOCKED when it holds none such (a range
/// never locked, part of one, another owner's).
pub fn unlock_file(
    _call: &mut NtCall,
    handle: Handle,
    io_status: UserAddr,
    offset: UserPtr<u64>,
    length: UserPtr<u64>,
    key: u32,
) -> NtResult {
    let (object, range) = lock_request(handle, io_status, offset, length)?;
    let owner = owner_of(&object);
    let result = locked_file(&object).and_then(|record| {
        if with_records(|records| records.unlock(record, owner, key, range)) {
            Ok(STATUS_SUCCESS)
        } else {
            Err(STATUS_RANGE_NOT_LOCKED)
        }
    });
    complete(io_status, result.unwrap_or_else(|status| status), 0);
    result
}
