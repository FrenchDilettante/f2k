//! NtReadFile, NtWriteFile and NtFlushBuffersFile: a file's bytes through its record, the object's
//! synchronous-I/O lock held for the call (one position, one call at a time).
//!
//! The bytes move through a kernel chunk: a read takes it off the volume inside the volume's locked
//! section and copies it out once the volume is released, a write the reverse. A chunk the caller's
//! memory refuses ends the call with STATUS_ACCESS_VIOLATION, what moved before it counted.

use super::super::call::{Handle, NtCall, NtResult, Status, UserAddr, UserPtr, STATUS_INVALID_PARAMETER, STATUS_SUCCESS};
use super::common::{check_access, complete, completion_event, file_object, probe, signal};
use super::{status, STATUS_DISK_FULL, STATUS_END_OF_FILE, STATUS_INVALID_DEVICE_REQUEST, STATUS_NOT_IMPLEMENTED};
use crate::fs::fat32::write;
use crate::fs::file::{records, rights, FileObject};
use crate::fs::io;
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

/// The checks a read and a write share, in the I/O manager's order: the handle and its rights, the
/// I/O status block, an APC routine (not supported), the event, a directory (no data:
/// STATUS_INVALID_DEVICE_REQUEST), and the offset (an object without a position needs one).
fn transfer(handle: Handle, event: Handle, routine: UserAddr, io_status: UserAddr, offset: UserPtr<u64>, needs: u32) -> Result<Transfer, Status> {
    let object = file_object(handle.raw())?;
    check_access(&object, needs)?;
    probe(io_status, 8)?;
    if !routine.is_null() {
        return Err(STATUS_NOT_IMPLEMENTED);
    }
    if io::file_of(&object).directory {
        return Err(STATUS_INVALID_DEVICE_REQUEST);
    }
    let offset = if offset.is_null() { None } else { Some(offset.read()?) };
    let offset = offset.filter(|&at| at != FILE_USE_FILE_POINTER_POSITION);
    if offset.is_none() && !object.synchronous {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let event = completion_event(event.raw())?;
    Ok(Transfer { object, event, offset })
}

/// Finish a transfer: its I/O status, its event, and its answer.
fn finish(transfer: Transfer, io_status: UserAddr, result: Result<u32, Status>) -> NtResult {
    let (code, moved) = match result {
        Ok(moved) => (STATUS_SUCCESS, moved),
        Err(Status(code)) => (code, 0),
    };
    complete(io_status, code, moved);
    signal(transfer.event);
    result.map(|_| STATUS_SUCCESS)
}

/// NtReadFile: up to `length` bytes from the offset (the object's position when none is given, and
/// the position then moves past them) into the caller's buffer: what remains before the end, at
/// most `length`, the I/O status's Information the count. A read at or past the end is
/// STATUS_END_OF_FILE and moves nothing; a zero-length read succeeds anywhere. A handle without
/// read access is STATUS_ACCESS_DENIED.
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
    let mut transfer = transfer(handle, event, routine, io_status, offset, rights::FILE_READ_DATA)?;
    let at = transfer.offset;
    let result = io::serialized(&mut transfer.object, |object| {
        let start = at.unwrap_or(object.position);
        if length == 0 {
            return Ok(0);
        }
        let size = records().get(object.record).file.size;
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
            if let Err(error) = io::read_record(object.record, start as u32 + moved, &mut chunk[..take]) {
                failure = Some(status(error));
                break;
            }
            if write_user(buffer.raw().wrapping_add(moved), &chunk[..take]).is_err() {
                failure = Some(super::super::call::STATUS_ACCESS_VIOLATION);
                break;
            }
            moved += take as u32;
        }
        // The position moves by what reached the caller.
        if object.synchronous {
            object.position = start + moved as u64;
        }
        failure.map_or(Ok(moved), Err)
    });
    finish(transfer, io_status, result)
}

/// NtReadFile (see [`read_file_held`]), as one critical region.
#[allow(clippy::too_many_arguments)]
pub fn read_file(call: &mut NtCall, handle: Handle, event: Handle, routine: UserAddr, context: UserAddr, io_status: UserAddr, buffer: UserAddr, length: u32, offset: UserPtr<u64>, key: UserPtr<u32>) -> NtResult {
    // The call holds its file object (a reference) across the volume's critical regions: run it
    // inside one of its own, so a termination requested meanwhile ends the thread only once the
    // reference has gone (an inner region's end would end it with the reference still held).
    crate::process::threads::critical_region(|| read_file_held(call, handle, event, routine, context, io_status, buffer, length, offset, key))
}

/// NtWriteFile: `length` bytes of the caller's at the offset (the object's position when none is
/// given, the end for FILE_WRITE_TO_END_OF_FILE or a handle with append access alone), the file
/// growing as needed (a gap reads as zeros) and its last write stamped; the I/O status's
/// Information the count. A handle without write access is STATUS_ACCESS_DENIED; a write past
/// FAT32's 4 GiB is STATUS_DISK_FULL.
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
    let mut transfer = transfer(handle, event, routine, io_status, offset, needs)?;
    let at = transfer.offset;
    let result = io::serialized(&mut transfer.object, |object| {
        let record = object.record;
        let append = object.granted & rights::FILE_WRITE_DATA == 0;
        let start = match at {
            Some(FILE_WRITE_TO_END_OF_FILE) => records().get(record).file.size as u64,
            _ if append => records().get(record).file.size as u64,
            Some(at) => at,
            None => object.position,
        };
        if length == 0 {
            return Ok(0);
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
                failure = Some(super::super::call::STATUS_ACCESS_VIOLATION);
                break;
            }
            let position = start as u32 + done;
            let written = io::with_volume(|volume| {
                let mut file = records().get(record).file;
                let stamp = io::now();
                file.times.write_date = stamp.write_date;
                file.times.write_time = stamp.write_time;
                write::write_at(volume, &mut file, position, &chunk[..take])?;
                records().get_mut(record).file = file;
                Ok(())
            });
            if let Err(error) = written {
                failure = Some(status(error));
                break;
            }
            done += take as u32;
        }
        if object.synchronous {
            object.position = start + done as u64;
        }
        failure.map_or(Ok(done), Err)
    });
    finish(transfer, io_status, result)
}

/// NtWriteFile (see [`write_file_held`]), as one critical region.
#[allow(clippy::too_many_arguments)]
pub fn write_file(call: &mut NtCall, handle: Handle, event: Handle, routine: UserAddr, context: UserAddr, io_status: UserAddr, buffer: UserAddr, length: u32, offset: UserPtr<u64>, key: UserPtr<u32>) -> NtResult {
    // As NtReadFile's: the call holds its file object across the volume's critical regions.
    crate::process::threads::critical_region(|| write_file_held(call, handle, event, routine, context, io_status, buffer, length, offset, key))
}

/// NtFlushBuffersFile: every write is already on the volume (F2K's writes go through); a handle
/// without write access is STATUS_ACCESS_DENIED.
pub fn flush_buffers_file(_call: &mut NtCall, handle: Handle, io_status: UserAddr) -> NtResult {
    let object = file_object(handle.raw())?;
    check_access(&object, rights::FILE_WRITE_DATA | rights::FILE_APPEND_DATA)?;
    probe(io_status, 8)?;
    complete(io_status, STATUS_SUCCESS, 0);
    Ok(STATUS_SUCCESS)
}
