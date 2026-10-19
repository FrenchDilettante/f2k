//! NtQueryInformationFile and NtSetInformationFile over an open file, and NtQueryAttributesFile
//! and NtQueryFullAttributesFile by name (no open: no share check).
//!
//! The I/O manager's order: the class and the buffer's length (STATUS_INVALID_INFO_CLASS,
//! STATUS_INFO_LENGTH_MISMATCH), the buffer's probe, then the handle and the rights the class needs
//! (the basic times and attributes FILE_READ_ATTRIBUTES to read, FILE_WRITE_ATTRIBUTES to write; a
//! rename or a delete DELETE; the size FILE_WRITE_DATA; the rest none). The file system acts on the
//! file as its record holds it. The read side sets the position alone: the classes that change the
//! file's entry (its times and attributes, its name, its pending delete, its size) are the FAT32
//! write side's, refused meanwhile as a volume that takes no writes
//! (STATUS_MEDIA_WRITE_PROTECTED) once their checks pass — a mapped file's cut first
//! (STATUS_USER_MAPPED_FILE).

use super::super::attributes::{STATUS_OBJECT_NAME_INVALID, STATUS_OBJECT_NAME_NOT_FOUND};
use super::super::call::{
    Handle, NtCall, NtResult, Status, UserAddr, STATUS_INVALID_HANDLE, STATUS_INVALID_PARAMETER, STATUS_SUCCESS,
};
use super::common::{check_access, cluster_bytes, complete, file_object, probe, target, walk, Found};
use super::info::{self, Open};
use super::{status, STATUS_DELETE_PENDING, STATUS_INFO_LENGTH_MISMATCH, STATUS_INVALID_INFO_CLASS, STATUS_USER_MAPPED_FILE};
use crate::fs::fat32::lookup::File;
use crate::fs::file::{records, rights};
use crate::fs::io;
use crate::status::STATUS_MEDIA_WRITE_PROTECTED;

/// FileModeInformation's synchronous-I/O mode.
const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x20;

/// The rights a query of `class` needs.
fn query_rights(class: u32) -> u32 {
    match class {
        info::FILE_BASIC_INFORMATION | info::FILE_ALL_INFORMATION | info::FILE_NETWORK_OPEN_INFORMATION => {
            rights::FILE_READ_ATTRIBUTES
        }
        _ => 0,
    }
}

/// The rights a set of `class` needs.
fn set_rights(class: u32) -> u32 {
    match class {
        info::FILE_BASIC_INFORMATION => rights::FILE_WRITE_ATTRIBUTES,
        info::FILE_RENAME_INFORMATION | info::FILE_DISPOSITION_INFORMATION => rights::DELETE,
        info::FILE_ALLOCATION_INFORMATION | info::FILE_END_OF_FILE_INFORMATION => rights::FILE_WRITE_DATA,
        _ => 0,
    }
}

/// The class and length checks: the class's least size.
fn sized(size: Option<usize>, length: u32) -> Result<usize, Status> {
    let size = size.ok_or(STATUS_INVALID_INFO_CLASS)?;
    if (length as usize) < size {
        return Err(STATUS_INFO_LENGTH_MISMATCH);
    }
    Ok(size)
}

/// NtQueryInformationFile: one of the classes [`info::query`] answers, of the open file.
fn query_information_file_held(
    _call: &mut NtCall,
    handle: Handle,
    io_status: UserAddr,
    information: UserAddr,
    length: u32,
    class: u32,
) -> NtResult {
    let size = sized(info::query_size(class), length)?;
    probe(io_status, 8)?;
    probe(information, length)?;
    let object = file_object(handle.raw())?;
    check_access(&object, query_rights(class))?;
    let file = io::file_of(&object);
    let open = Open {
        allocation: info::allocation(&file, cluster_bytes()),
        delete_pending: records().delete_pending(object.record),
        position: object.position,
        granted: object.granted,
        mode: if object.synchronous { FILE_SYNCHRONOUS_IO_NONALERT } else { 0 },
    };
    let mut answer = [0u8; info::ALL_SIZE];
    let written = info::query(class, &file, &open, &mut answer[..size]).ok_or(STATUS_INVALID_INFO_CLASS)?;
    information.write(&answer[..written])?;
    complete(io_status, STATUS_SUCCESS, written as u32);
    Ok(STATUS_SUCCESS)
}

/// A size change (FileEndOfFileInformation, or FileAllocationInformation when it cuts the file):
/// a directory has none to change (STATUS_INVALID_HANDLE, an assumption, unverified); a mapped file
/// is not cut (STATUS_USER_MAPPED_FILE); a change of size is the write side's (past 4 GiB
/// STATUS_DISK_FULL), refused meanwhile (STATUS_MEDIA_WRITE_PROTECTED).
fn resize(record: u16, size: u64, allocation_only: bool) -> Result<(), Status> {
    let file = records().get(record).file;
    if file.directory {
        return Err(STATUS_INVALID_HANDLE);
    }
    if allocation_only && size >= file.size as u64 || size == file.size as u64 {
        return Ok(());
    }
    if io::mapped(record) && size < file.size as u64 {
        return Err(STATUS_USER_MAPPED_FILE);
    }
    Err(status(STATUS_MEDIA_WRITE_PROTECTED))
}

/// NtSetInformationFile: the position; the allocation and the end of file when they leave the size
/// as it is (a mapped file's cut is STATUS_USER_MAPPED_FILE). The basic times and attributes, a
/// rename, the pending delete and a change of size are the write side's (see the module notes),
/// refused once the class's rights are checked.
pub fn set_information_file(
    _call: &mut NtCall,
    handle: Handle,
    io_status: UserAddr,
    information: UserAddr,
    length: u32,
    class: u32,
) -> NtResult {
    let size = sized(info::set_size(class), length)?;
    probe(io_status, 8)?;
    let mut bytes = [0u8; info::BASIC_SIZE];
    information.read(&mut bytes[..size])?;
    let mut object = file_object(handle.raw())?;
    check_access(&object, set_rights(class))?;
    let record = object.record;
    let quad = |at: usize| u64::from_le_bytes(bytes[at..at + 8].try_into().expect("eight bytes"));
    match class {
        info::FILE_POSITION_INFORMATION => {
            let position = quad(0);
            if (position as i64) < 0 {
                return Err(STATUS_INVALID_PARAMETER);
            }
            object.position = position;
        }
        info::FILE_ALLOCATION_INFORMATION => resize(record, quad(0), true)?,
        info::FILE_END_OF_FILE_INFORMATION => resize(record, quad(0), false)?,
        // The write side: FILE_BASIC_INFORMATION (the times, the settable attributes), FILE_RENAME_INFORMATION
        // (the move, its record re-keyed) and FILE_DISPOSITION_INFORMATION (the record's
        // delete-pending: `records().set_delete_pending`, refused for a read-only, mapped or root
        // entry and a non-empty directory).
        info::FILE_BASIC_INFORMATION | info::FILE_RENAME_INFORMATION | info::FILE_DISPOSITION_INFORMATION => {
            return Err(status(STATUS_MEDIA_WRITE_PROTECTED));
        }
        _ => return Err(STATUS_INVALID_INFO_CLASS),
    }
    complete(io_status, STATUS_SUCCESS, 0);
    Ok(STATUS_SUCCESS)
}

/// The file a name names, for the attribute queries: STATUS_OBJECT_NAME_NOT_FOUND when it is
/// missing, STATUS_DELETE_PENDING while it is being deleted, STATUS_OBJECT_NAME_INVALID for a file
/// named with a trailing separator.
fn named(attributes: UserAddr, out: UserAddr, size: u32) -> Result<File, Status> {
    let target = target(attributes)?;
    probe(out, size)?;
    let file = io::with_volume(|volume| {
        if target.name.volume {
            return Ok(crate::fs::fat32::lookup::root(volume));
        }
        match walk(volume, target.start, &target.name)? {
            Found::Existing(file) => Ok(file),
            Found::Missing { .. } => Err(STATUS_OBJECT_NAME_NOT_FOUND.0 as i32),
        }
    })
    .map_err(status)?;
    if target.name.trailing && !file.directory {
        return Err(STATUS_OBJECT_NAME_INVALID);
    }
    if records().find(&file).is_some_and(|index| records().delete_pending(index)) {
        return Err(STATUS_DELETE_PENDING);
    }
    Ok(file)
}

/// NtQueryAttributesFile: the file's FILE_BASIC_INFORMATION, by name.
pub fn query_attributes_file(_call: &mut NtCall, attributes: UserAddr, information: UserAddr) -> NtResult {
    let file = named(attributes, information, info::BASIC_SIZE as u32)?;
    information.write(&info::basic(&file))?;
    Ok(STATUS_SUCCESS)
}

/// NtQueryFullAttributesFile: the file's FILE_NETWORK_OPEN_INFORMATION, by name.
pub fn query_full_attributes_file(_call: &mut NtCall, attributes: UserAddr, information: UserAddr) -> NtResult {
    let file = named(attributes, information, info::NETWORK_OPEN_SIZE as u32)?;
    information.write(&info::network_open(&file, info::allocation(&file, cluster_bytes())))?;
    Ok(STATUS_SUCCESS)
}

/// NtQueryInformationFile (see [`query_information_file_held`]), as one critical region.
#[allow(clippy::too_many_arguments)]
pub fn query_information_file(call: &mut NtCall, handle: Handle, io_status: UserAddr, information: UserAddr, length: u32, class: u32) -> NtResult {
    // The call holds its file object (a reference) across the volume's critical regions: run it
    // inside one of its own, so a termination requested meanwhile ends the thread only once the
    // reference has gone (an inner region's end would end it with the reference still held).
    crate::process::threads::critical_region(|| query_information_file_held(call, handle, io_status, information, length, class))
}
