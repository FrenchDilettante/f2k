//! NtReadFile, NtWriteFile and NtFlushBuffersFile: the I/O manager's checks (see [`transfer`]),
//! then the device the file object is open on moves the bytes.
//!
//! A disk file's bytes move through its record, the object's synchronous-I/O lock held for the
//! call (one position, one call at a time), and through a kernel chunk: a read takes it off the
//! volume inside the volume's locked section and copies it out once the volume is released, a
//! write the reverse. A chunk the caller's memory refuses ends the call with
//! STATUS_ACCESS_VIOLATION, what moved before it counted. The disk's arm is one critical region (it
//! holds the object across the volume's).
//!
//! A disk file's byte-range locks refuse the bytes another owner's lock holds before any moves
//! (STATUS_FILE_LOCK_CONFLICT, the position left where it was): a read where another owner holds an
//! exclusive lock, a write where another owner holds any lock or a shared lock is held (see
//! [`crate::fs::file`]'s notes).
//!
//! A pipe's bytes move through the named-pipe file system ([`crate::fs::pipes`]), the object's
//! lock held for the call as Windows 2000 holds a synchronous file object's while a pipe's read
//! waits, outside any critical region: the call may wait as long as the other end decides, and a
//! termination interrupts the wait (for the lock, or for the pipe), the call cancelled.

use super::super::call::{Handle, NtCall, NtResult, UserAddr, UserPtr};
use super::common::{check_access, complete, completion_event, file_object, signal};
use crate::fs::fat32::write;
use crate::fs::file::{rights, with_records, Context, FileObject, FileRecordId};
use crate::fs::io;
use crate::status::*;
use crate::user::syscall::{read_user, write_user};

/// The chunk bytes move through.
const CHUNK: usize = 4096;

/// ByteOffset's special values: the object's position, and (a write's) the end of the file.
const FILE_USE_FILE_POINTER_POSITION: u64 = 0xFFFF_FFFF_FFFF_FFFE;
const FILE_WRITE_TO_END_OF_FILE: u64 = 0xFFFF_FFFF_FFFF_FFFF;

/// What a read or write was asked: its object, its completion event, where it starts.
struct Transfer {
    object: crate::ob::Referenced<FileObject>,
    event: Option<crate::ob::ObRef>,
    /// The offset asked for; none for the object's position.
    offset: Option<u64>,
}

/// The checks a read and a write share, the I/O manager's before it hands the request to the
/// object's device, in its order: the handle and its rights, the I/O status block, an APC routine
/// (not supported), the offset (an object without a position needs one), and the event, reset.
fn transfer(
    handle: Handle,
    event: Handle,
    routine: UserAddr,
    io_status: UserAddr,
    offset: UserPtr<u64>,
    needs: u32,
) -> Result<Transfer, NtStatus> {
    let object = file_object(handle.raw())?;
    check_access(&object, needs)?;
    io_status.probe(8)?;
    if !routine.is_null() {
        return Err(STATUS_NOT_IMPLEMENTED);
    }
    let offset = if offset.is_null() {
        None
    } else {
        Some(offset.read()?)
    };
    let offset = offset.filter(|&at| at != FILE_USE_FILE_POINTER_POSITION);
    if offset.is_none() && !object.synchronous {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let event = completion_event(event.raw())?;
    Ok(Transfer {
        object,
        event,
        offset,
    })
}

/// Finish a transfer: its I/O status, its event, and its answer.
fn finish(transfer: Transfer, io_status: UserAddr, result: Result<u32, NtStatus>) -> NtResult {
    let (code, moved) = match result {
        Ok(moved) => (STATUS_SUCCESS, moved),
        Err(code) => (code, 0),
    };
    complete(io_status, code, moved);
    signal(transfer.event);
    result.map(|_| STATUS_SUCCESS)
}

/// A disk transfer's own refusal: a directory has no data (FastFat's
/// STATUS_INVALID_DEVICE_REQUEST).
fn disk_data(record: FileRecordId) -> Result<(), NtStatus> {
    if io::file_at(record).directory {
        return Err(STATUS_INVALID_DEVICE_REQUEST);
    }
    Ok(())
}

/// NtReadFile: the I/O manager's checks ([`transfer`]; a handle without read access is
/// STATUS_ACCESS_DENIED), then the object's device reads (see [`read_disk`]), the I/O status's
/// Information the count.
#[allow(clippy::too_many_arguments)]
fn read_file_held(
    _call: &mut NtCall,
    handle: Handle,
    event: Handle,
    routine: UserAddr,
    _context: UserAddr,
    io_status: UserAddr,
    buffer: UserAddr,
    length: u32,
    offset: UserPtr<u64>,
    _key: UserPtr<u32>,
) -> NtResult {
    let transfer = transfer(
        handle,
        event,
        routine,
        io_status,
        offset,
        rights::FILE_READ_DATA,
    )?;
    let result = match transfer.object.context {
        Context::Disk(record) => crate::process::threads::critical_region(|| {
            disk_data(record)?;
            Ok::<_, NtStatus>(read_disk(&transfer, record, buffer, length))
        })?,
        Context::Pipe(end) => {
            buffer.probe(length)?;
            io::serialized_interruptible(&transfer.object, |_| {
                crate::fs::pipes::read(end, buffer, length)
            })
            .and_then(|read| read)
        }
        // The null device holds nothing: every read is at its end.
        Context::Null => Err(STATUS_END_OF_FILE),
    };
    finish(transfer, io_status, result)
}

/// A disk file's read: up to `length` bytes from the offset (the object's position when none is
/// given, and the position then moves past them) into the caller's buffer: what remains before the
/// end, at most `length`. A read at or past the end is STATUS_END_OF_FILE and moves nothing; a
/// zero-length read succeeds anywhere. Returns the count.
fn read_disk(
    transfer: &Transfer,
    record: FileRecordId,
    buffer: UserAddr,
    length: u32,
) -> Result<u32, NtStatus> {
    let at = transfer.offset;
    let object = &transfer.object;
    let owner = super::lock::owner_of(object);
    io::serialized(object, |held| {
        let start = at.unwrap_or(held.position);
        if length == 0 {
            return Ok(0);
        }
        let range = (start, u64::from(length));
        if !with_records(|records| records.may_access(record, owner, range, false)) {
            return Err(STATUS_FILE_LOCK_CONFLICT);
        }
        let size = io::file_at(record).size;
        let wanted = crate::fs::file::available(start, size, length);
        if wanted == 0 {
            return Err(STATUS_END_OF_FILE);
        }
        let mut moved = 0u32;
        let mut failure = None;
        while moved < wanted {
            let take = (wanted - moved).min(CHUNK as u32) as usize;
            let mut chunk = [0u8; CHUNK];
            // `wanted` is nonzero only below the end, so the offset is within the 32-bit file.
            if let Err(error) = io::read_record(record, start as u32 + moved, &mut chunk[..take]) {
                failure = Some(error);
                break;
            }
            if write_user(buffer.raw().wrapping_add(moved), &chunk[..take]).is_err() {
                failure = Some(STATUS_ACCESS_VIOLATION);
                break;
            }
            moved += take as u32;
        }
        // The position moves by what reached the caller.
        if object.synchronous {
            held.position = start + moved as u64;
        }
        failure.map_or(Ok(moved), Err)
    })
}

/// NtReadFile (see [`read_file_held`]): a disk file's read is one critical region, inside the
/// device's arm.
#[allow(clippy::too_many_arguments)]
pub fn read_file(
    call: &mut NtCall,
    handle: Handle,
    event: Handle,
    routine: UserAddr,
    context: UserAddr,
    io_status: UserAddr,
    buffer: UserAddr,
    length: u32,
    offset: UserPtr<u64>,
    key: UserPtr<u32>,
) -> NtResult {
    read_file_held(
        call, handle, event, routine, context, io_status, buffer, length, offset, key,
    )
}

/// NtWriteFile: the I/O manager's checks ([`transfer`]; a handle without write access is
/// STATUS_ACCESS_DENIED), then the object's device writes (see [`write_disk`]), the I/O status's
/// Information the count.
#[allow(clippy::too_many_arguments)]
fn write_file_held(
    _call: &mut NtCall,
    handle: Handle,
    event: Handle,
    routine: UserAddr,
    _context: UserAddr,
    io_status: UserAddr,
    buffer: UserAddr,
    length: u32,
    offset: UserPtr<u64>,
    _key: UserPtr<u32>,
) -> NtResult {
    let needs = rights::FILE_WRITE_DATA | rights::FILE_APPEND_DATA;
    let transfer = transfer(handle, event, routine, io_status, offset, needs)?;
    let result = match transfer.object.context {
        Context::Disk(record) => crate::process::threads::critical_region(|| {
            disk_data(record)?;
            Ok::<_, NtStatus>(write_disk(&transfer, record, buffer, length))
        })?,
        Context::Pipe(end) => {
            buffer.probe(length)?;
            io::serialized_interruptible(&transfer.object, |_| {
                crate::fs::pipes::write(end, buffer, length)
            })
            .and_then(|written| written)
        }
        // The null device takes every byte and keeps none.
        Context::Null => {
            buffer.probe(length)?;
            Ok(length)
        }
    };
    finish(transfer, io_status, result)
}

/// A disk file's write: `length` bytes of the caller's at the offset (the object's position when
/// none is given, the end for FILE_WRITE_TO_END_OF_FILE or a handle with append access alone), the
/// file growing as needed (a gap reads as zeros) and its last write stamped. A write past FAT32's
/// 4 GiB is STATUS_DISK_FULL. Returns the count.
fn write_disk(
    transfer: &Transfer,
    record: FileRecordId,
    buffer: UserAddr,
    length: u32,
) -> Result<u32, NtStatus> {
    let at = transfer.offset;
    let object = &transfer.object;
    let owner = super::lock::owner_of(object);
    io::serialized(object, |held| {
        let append = object.granted & rights::FILE_WRITE_DATA == 0;
        let start = match at {
            Some(FILE_WRITE_TO_END_OF_FILE) => io::file_at(record).size as u64,
            _ if append => io::file_at(record).size as u64,
            Some(at) => at,
            None => held.position,
        };
        if length == 0 {
            return Ok(0);
        }
        let range = (start, u64::from(length));
        if !with_records(|records| records.may_access(record, owner, range, true)) {
            return Err(STATUS_FILE_LOCK_CONFLICT);
        }
        if start + length as u64 > u32::MAX as u64 {
            return Err(STATUS_DISK_FULL);
        }
        let mut chunk = [0u8; CHUNK];
        let mut done = 0u32;
        let mut failure = None;
        while done < length {
            let take = (length - done).min(CHUNK as u32) as usize;
            if read_user(buffer.raw().wrapping_add(done), &mut chunk[..take]).is_err() {
                failure = Some(STATUS_ACCESS_VIOLATION);
                break;
            }
            let position = start as u32 + done;
            let written = io::with_volume(|volume| {
                let mut file = io::file_at(record);
                let stamp = io::now();
                file.times.write_date = stamp.write_date;
                file.times.write_time = stamp.write_time;
                write::write_at(volume, &mut file, position, &chunk[..take])?;
                io::store_file(record, file);
                Ok(())
            });
            if let Err(error) = written {
                failure = Some(error);
                break;
            }
            done += take as u32;
        }
        if object.synchronous {
            held.position = start + done as u64;
        }
        failure.map_or(Ok(done), Err)
    })
}

/// NtWriteFile (see [`write_file_held`]): as NtReadFile's, a disk file's write is one critical
/// region, inside the device's arm.
#[allow(clippy::too_many_arguments)]
pub fn write_file(
    call: &mut NtCall,
    handle: Handle,
    event: Handle,
    routine: UserAddr,
    context: UserAddr,
    io_status: UserAddr,
    buffer: UserAddr,
    length: u32,
    offset: UserPtr<u64>,
    key: UserPtr<u32>,
) -> NtResult {
    write_file_held(
        call, handle, event, routine, context, io_status, buffer, length, offset, key,
    )
}

/// NtFlushBuffersFile: the I/O manager's checks (a handle without write access is
/// STATUS_ACCESS_DENIED), then the object's device flushes: a disk file's writes are already on
/// the volume (F2K's writes go through); a pipe's end waits until the other end has read what it
/// wrote (see [`crate::fs::pipes::flush`]), under the object's lock as its writes.
pub fn flush_buffers_file(_call: &mut NtCall, handle: Handle, io_status: UserAddr) -> NtResult {
    let object = file_object(handle.raw())?;
    check_access(&object, rights::FILE_WRITE_DATA | rights::FILE_APPEND_DATA)?;
    io_status.probe(8)?;
    match object.context {
        Context::Disk(_) | Context::Null => {}
        Context::Pipe(end) => {
            io::serialized_interruptible(&object, |_| crate::fs::pipes::flush(end))
                .and_then(|flushed| flushed)?;
        }
    }
    complete(io_status, STATUS_SUCCESS, 0);
    Ok(STATUS_SUCCESS)
}
