//! NtCreateFile and NtOpenFile: the I/O manager's checks of the arguments, then FastFat's create —
//! the walk, the disposition's decision against what the name names, and the open (its share
//! check).
//!
//! The volume is read-only until the FAT32 write side: a disposition that would make a missing
//! name or overwrite an existing file is refused with STATUS_MEDIA_WRITE_PROTECTED (the platform's
//! answer for a volume that takes no writes, ERROR_WRITE_PROTECT); every disposition that only
//! opens is served.

use super::super::call::{NtCall, NtResult, Status, UserAddr, UserPtr, STATUS_INVALID_PARAMETER, STATUS_SUCCESS};
use super::common::{complete, deliver, probe, target, walk, Found, Target};
use super::{
    status, STATUS_ACCESS_DENIED, STATUS_DIRECTORY_NOT_EMPTY, STATUS_FILE_IS_A_DIRECTORY, STATUS_NOT_A_DIRECTORY,
    STATUS_OBJECT_NAME_COLLISION, STATUS_USER_MAPPED_FILE,
};
use crate::fs::fat32::dir::is_empty;
use crate::fs::fat32::dirent::{ATTR_HIDDEN, ATTR_READ_ONLY, ATTR_SYSTEM};
use crate::fs::fat32::lookup::File;
use crate::fs::fat32::volume::Volume;
use crate::fs::file::{records, rights};
use crate::fs::io;
use crate::nt::attributes::{STATUS_OBJECT_NAME_INVALID, STATUS_OBJECT_NAME_NOT_FOUND};
use crate::status::{NtStatus, STATUS_MEDIA_WRITE_PROTECTED};

/// The dispositions.
const FILE_SUPERSEDE: u32 = 0;
const FILE_OPEN: u32 = 1;
const FILE_CREATE: u32 = 2;
const FILE_OPEN_IF: u32 = 3;
const FILE_OVERWRITE: u32 = 4;
const FILE_OVERWRITE_IF: u32 = 5;

/// The IO_STATUS_BLOCK's Information an open answers with (the read side's opens only open).
const FILE_OPENED: u32 = 1;

/// The create options F2K reads, and every one the platform defines.
const FILE_DIRECTORY_FILE: u32 = 0x1;
const FILE_SYNCHRONOUS_IO_ALERT: u32 = 0x10;
const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x20;
const FILE_NON_DIRECTORY_FILE: u32 = 0x40;
const FILE_DELETE_ON_CLOSE: u32 = 0x1000;
const FILE_VALID_OPTION_FLAGS: u32 = 0x00FF_FFFF;
/// The attributes a create may carry (FILE_ATTRIBUTE_VALID_FLAGS), and the share modes' bits.
const FILE_ATTRIBUTE_VALID_FLAGS: u32 = 0x7FB7;
const FILE_SHARE_VALID_FLAGS: u32 = 0x7;

/// The rights that change a file, which a read-only one refuses.
const CHANGES: u32 = rights::FILE_WRITE_DATA | rights::FILE_APPEND_DATA | rights::DELETE;

/// What the caller asks of an open.
struct Request {
    /// The rights as asked (MAXIMUM_ALLOWED among them), and as mapped.
    access: u32,
    granted: u32,
    disposition: u32,
    options: u32,
    /// The attributes asked for (an overwrite's; a creation's, the write side's).
    attributes: u32,
}

/// The I/O manager's checks (IoCreateFile), before any name is read: a disposition or an option,
/// attribute or share bit the platform does not define, both synchronous modes, a synchronous mode
/// without SYNCHRONIZE, delete-on-close without DELETE, a directory asked for and refused at once
/// or with a disposition that cannot make one — each STATUS_INVALID_PARAMETER.
fn check_arguments(access: u32, attributes: u32, share: u32, disposition: u32, options: u32) -> Result<(), Status> {
    let synchronous = options & (FILE_SYNCHRONOUS_IO_ALERT | FILE_SYNCHRONOUS_IO_NONALERT);
    let invalid = disposition > FILE_OVERWRITE_IF
        || options & !FILE_VALID_OPTION_FLAGS != 0
        || attributes & !FILE_ATTRIBUTE_VALID_FLAGS != 0
        || share & !FILE_SHARE_VALID_FLAGS != 0
        || synchronous == FILE_SYNCHRONOUS_IO_ALERT | FILE_SYNCHRONOUS_IO_NONALERT
        || (synchronous != 0 && access & rights::SYNCHRONIZE == 0)
        || (options & FILE_DELETE_ON_CLOSE != 0 && access & rights::DELETE == 0)
        || (options & FILE_DIRECTORY_FILE != 0
            && (options & FILE_NON_DIRECTORY_FILE != 0
                || !matches!(disposition, FILE_CREATE | FILE_OPEN | FILE_OPEN_IF)));
    if invalid {
        return Err(STATUS_INVALID_PARAMETER);
    }
    Ok(())
}

/// The decision on an existing entry: the file (the open goes ahead), its I/O status information,
/// whether it is overwritten once open, and the rights granted (MAXIMUM_ALLOWED leaves a read-only
/// file's write rights out).
fn existing(volume: &mut Volume, target: &Target, file: File, request: &Request) -> Result<(File, u32, bool, u32), NtStatus> {
    let mut granted = request.granted;
    if request.disposition == FILE_CREATE {
        return Err(STATUS_OBJECT_NAME_COLLISION.0 as NtStatus);
    }
    if file.directory {
        if request.options & FILE_NON_DIRECTORY_FILE != 0 {
            return Err(STATUS_FILE_IS_A_DIRECTORY.0 as NtStatus);
        }
        // A directory only opens (an assumption, unverified against FastFat's collision answer).
        if !matches!(request.disposition, FILE_OPEN | FILE_OPEN_IF) {
            return Err(STATUS_ACCESS_DENIED.0 as NtStatus);
        }
        // The root is never deleted (it has no entry).
        if (target.name.volume || file.parent_cluster == 0) && granted & rights::DELETE != 0 {
            return Err(STATUS_ACCESS_DENIED.0 as NtStatus);
        }
        if request.options & FILE_DELETE_ON_CLOSE != 0 && !is_empty(volume, file.first_cluster)? {
            return Err(STATUS_DIRECTORY_NOT_EMPTY.0 as NtStatus);
        }
        return Ok((file, FILE_OPENED, false, granted));
    }
    if request.options & FILE_DIRECTORY_FILE != 0 {
        return Err(STATUS_NOT_A_DIRECTORY.0 as NtStatus);
    }
    // A file named with a trailing separator is no name.
    if target.name.trailing {
        return Err(STATUS_OBJECT_NAME_INVALID.0 as NtStatus);
    }
    let overwrite = matches!(request.disposition, FILE_SUPERSEDE | FILE_OVERWRITE | FILE_OVERWRITE_IF);
    if file.attributes & ATTR_READ_ONLY != 0 {
        if request.access & rights::MAXIMUM_ALLOWED != 0 {
            granted &= !CHANGES;
        }
        if granted & CHANGES != 0 || overwrite {
            return Err(STATUS_ACCESS_DENIED.0 as NtStatus);
        }
    }
    if !overwrite {
        return Ok((file, FILE_OPENED, false, granted));
    }
    // An overwrite keeps a hidden or system file's attribute only when asked to (CreateFile's
    // documented refusal).
    let keeps = |bit: u8| file.attributes & bit == 0 || request.attributes & bit as u32 != 0;
    if !keeps(ATTR_HIDDEN) || !keeps(ATTR_SYSTEM) {
        return Err(STATUS_ACCESS_DENIED.0 as NtStatus);
    }
    // The overwrite's Information (FILE_SUPERSEDED or FILE_OVERWRITTEN) is the write side's: it never succeeds
    // here (see `overwrite`).
    Ok((file, FILE_OPENED, true, granted))
}

/// Overwrite the open file at `record`: a mapped file is not cut (STATUS_USER_MAPPED_FILE); any
/// other is, with the FAT32 write side — until then the volume takes no writes
/// (STATUS_MEDIA_WRITE_PROTECTED).
fn overwrite(record: u16) -> NtStatus {
    if io::mapped(record) && records().get(record).file.size > 0 {
        return STATUS_USER_MAPPED_FILE.0 as NtStatus;
    }
    STATUS_MEDIA_WRITE_PROTECTED
}

/// The decision on a missing name: an opening disposition finds nothing
/// (STATUS_OBJECT_NAME_NOT_FOUND); a creating one (FILE_CREATE, FILE_OPEN_IF, FILE_OVERWRITE_IF,
/// FILE_SUPERSEDE) would make the file or directory, and the volume is read-only until the write side
/// (STATUS_MEDIA_WRITE_PROTECTED; a file named with a trailing separator is no name first).
fn missing(target: &Target, request: &Request) -> NtStatus {
    if !matches!(request.disposition, FILE_CREATE | FILE_OPEN_IF | FILE_OVERWRITE_IF | FILE_SUPERSEDE) {
        return STATUS_OBJECT_NAME_NOT_FOUND.0 as NtStatus;
    }
    if request.options & FILE_DIRECTORY_FILE == 0 && target.name.trailing {
        return STATUS_OBJECT_NAME_INVALID.0 as NtStatus;
    }
    STATUS_MEDIA_WRITE_PROTECTED
}

/// The create both services share.
#[allow(clippy::too_many_arguments)]
fn create(
    slot: UserPtr<u32>,
    access: u32,
    attributes: UserAddr,
    io_status: UserAddr,
    file_attributes: u32,
    share: u32,
    disposition: u32,
    options: u32,
) -> NtResult {
    check_arguments(access, file_attributes, share, disposition, options)?;
    let target = target(attributes)?;
    probe(slot.addr(), 4)?;
    probe(io_status, 8)?;
    let request = Request { access, granted: rights::mapped(access), disposition, options, attributes: file_attributes };
    // The walk and the decision are one locked section (with the write side, the create joins them:
    // no other create can take the name between the look and the entry).
    let (file, information, overwrites, granted) = io::with_volume(|volume| {
        if target.name.volume {
            let root = crate::fs::fat32::lookup::root(volume);
            return existing(volume, &target, root, &request);
        }
        match walk(volume, target.start, &target.name)? {
            Found::Existing(file) => existing(volume, &target, file, &request),
            Found::Missing { .. } => Err(missing(&target, &request)),
        }
    })
    .map_err(status)?;
    let open = io::Open {
        granted,
        share: share as u8,
        inherit: target.inherit,
        synchronous: options & (FILE_SYNCHRONOUS_IO_ALERT | FILE_SYNCHRONOUS_IO_NONALERT) != 0,
        delete_on_close: options & FILE_DELETE_ON_CLOSE != 0,
    };
    let handle = io::open(file, &open).map_err(status)?;
    if overwrites {
        let record = io::object_of(handle).expect("just opened").record;
        let failure = overwrite(record);
        crate::user::args::calling_process().close_handle(handle);
        return Err(status(failure));
    }
    deliver(slot, handle)?;
    complete(io_status, STATUS_SUCCESS, information);
    Ok(STATUS_SUCCESS)
}

/// NtCreateFile: open the file or directory the name names as the disposition says (FILE_SUPERSEDE,
/// FILE_OPEN, FILE_CREATE, FILE_OPEN_IF, FILE_OVERWRITE, FILE_OVERWRITE_IF), its handle written back
/// with the rights asked for and the I/O status's Information what happened (FILE_OPENED; making or
/// overwriting a file is the write side's: STATUS_MEDIA_WRITE_PROTECTED). A name already taken is
/// STATUS_OBJECT_NAME_COLLISION for FILE_CREATE; a missing one STATUS_OBJECT_NAME_NOT_FOUND for the
/// opening dispositions (STATUS_OBJECT_PATH_NOT_FOUND when its directory is missing).
/// FILE_DIRECTORY_FILE asks a directory (STATUS_NOT_A_DIRECTORY for a file), FILE_NON_DIRECTORY_FILE
/// a file (STATUS_FILE_IS_A_DIRECTORY for a directory); a read-only file refuses write and delete
/// rights and an overwrite (STATUS_ACCESS_DENIED). The allocation size and the extended attributes
/// are not consulted.
#[allow(clippy::too_many_arguments)]
pub fn create_file(
    _call: &mut NtCall,
    slot: UserPtr<u32>,
    access: u32,
    attributes: UserAddr,
    io_status: UserAddr,
    _allocation: UserPtr<u64>,
    file_attributes: u32,
    share: u32,
    disposition: u32,
    options: u32,
    _ea: UserAddr,
    _ea_length: u32,
) -> NtResult {
    create(slot, access, attributes, io_status, file_attributes, share, disposition, options)
}

/// NtOpenFile: NtCreateFile's FILE_OPEN of an existing file or directory.
pub fn open_file(
    _call: &mut NtCall,
    slot: UserPtr<u32>,
    access: u32,
    attributes: UserAddr,
    io_status: UserAddr,
    share: u32,
    options: u32,
) -> NtResult {
    create(slot, access, attributes, io_status, 0, share, FILE_OPEN, options)
}
