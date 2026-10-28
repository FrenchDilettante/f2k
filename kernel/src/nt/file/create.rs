//! NtCreateFile and NtOpenFile: the I/O manager's checks of the arguments, then FastFat's create —
//! the walk, the disposition's decision against what the name names, a new file or directory made,
//! the open (its share check), and an overwrite's truncation.

use super::super::call::{NtCall, NtResult, UserAddr, UserPtr};
use super::common::{complete, deliver, target, walk, Found, Target};
use crate::fs::fat32::dir::is_empty;
use crate::fs::fat32::dirent::{ATTR_HIDDEN, ATTR_READ_ONLY, ATTR_SYSTEM};
use crate::fs::fat32::lookup::File;
use crate::fs::fat32::volume::Volume;
use crate::fs::fat32::write;
use crate::fs::file::{records, rights};
use crate::fs::io::{self, ATTRIBUTE_ARCHIVE, SETTABLE_ATTRIBUTES};
use crate::status::*;

/// The dispositions.
const FILE_SUPERSEDE: u32 = 0;
const FILE_OPEN: u32 = 1;
const FILE_CREATE: u32 = 2;
const FILE_OPEN_IF: u32 = 3;
const FILE_OVERWRITE: u32 = 4;
const FILE_OVERWRITE_IF: u32 = 5;

/// The IO_STATUS_BLOCK's Information an open answers with.
const FILE_SUPERSEDED: u32 = 0;
const FILE_OPENED: u32 = 1;
const FILE_CREATED: u32 = 2;
const FILE_OVERWRITTEN: u32 = 3;

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
    attributes: u32,
}

/// The I/O manager's checks (IoCreateFile), before any name is read: a disposition or an option,
/// attribute or share bit the platform does not define, both synchronous modes, a synchronous mode
/// without SYNCHRONIZE, delete-on-close without DELETE, a directory asked for and refused at once
/// or with a disposition that cannot make one — each STATUS_INVALID_PARAMETER.
fn check_arguments(
    access: u32,
    attributes: u32,
    share: u32,
    disposition: u32,
    options: u32,
) -> Result<(), NtStatus> {
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
fn existing(
    volume: &mut Volume,
    target: &Target,
    file: File,
    request: &Request,
) -> Result<(File, u32, bool, u32), NtStatus> {
    let mut granted = request.granted;
    if request.disposition == FILE_CREATE {
        return Err(STATUS_OBJECT_NAME_COLLISION);
    }
    if file.directory {
        if request.options & FILE_NON_DIRECTORY_FILE != 0 {
            return Err(STATUS_FILE_IS_A_DIRECTORY);
        }
        // A directory only opens (an assumption, unverified against FastFat's collision answer).
        if !matches!(request.disposition, FILE_OPEN | FILE_OPEN_IF) {
            return Err(STATUS_ACCESS_DENIED);
        }
        // The root is never deleted (it has no entry).
        if (target.name.volume || file.parent_cluster == 0) && granted & rights::DELETE != 0 {
            return Err(STATUS_ACCESS_DENIED);
        }
        if request.options & FILE_DELETE_ON_CLOSE != 0 && !is_empty(volume, file.first_cluster)? {
            return Err(STATUS_DIRECTORY_NOT_EMPTY);
        }
        return Ok((file, FILE_OPENED, false, granted));
    }
    if request.options & FILE_DIRECTORY_FILE != 0 {
        return Err(STATUS_NOT_A_DIRECTORY);
    }
    // A file named with a trailing separator is no name.
    if target.name.trailing {
        return Err(STATUS_OBJECT_NAME_INVALID);
    }
    let overwrite = matches!(
        request.disposition,
        FILE_SUPERSEDE | FILE_OVERWRITE | FILE_OVERWRITE_IF
    );
    if file.attributes & ATTR_READ_ONLY != 0 {
        if request.access & rights::MAXIMUM_ALLOWED != 0 {
            granted &= !CHANGES;
        }
        if granted & CHANGES != 0 || overwrite {
            return Err(STATUS_ACCESS_DENIED);
        }
    }
    if !overwrite {
        return Ok((file, FILE_OPENED, false, granted));
    }
    // An overwrite keeps a hidden or system file's attribute only when asked to (CreateFile's
    // documented refusal).
    let keeps = |bit: u8| file.attributes & bit == 0 || request.attributes & bit as u32 != 0;
    if !keeps(ATTR_HIDDEN) || !keeps(ATTR_SYSTEM) {
        return Err(STATUS_ACCESS_DENIED);
    }
    let information = if request.disposition == FILE_SUPERSEDE {
        FILE_SUPERSEDED
    } else {
        FILE_OVERWRITTEN
    };
    Ok((file, information, true, granted))
}

/// The decision on a missing name: made (a directory when asked, else a file with the attributes
/// asked for and the archive bit, stamped now) when the disposition creates.
fn missing(
    volume: &mut Volume,
    target: &Target,
    parent: File,
    request: &Request,
) -> Result<File, NtStatus> {
    if !matches!(
        request.disposition,
        FILE_CREATE | FILE_OPEN_IF | FILE_OVERWRITE_IF | FILE_SUPERSEDE
    ) {
        return Err(STATUS_OBJECT_NAME_NOT_FOUND);
    }
    let name = target.name.last();
    if request.options & FILE_DIRECTORY_FILE != 0 {
        return write::make_directory(volume, parent.first_cluster, name, io::now());
    }
    if target.name.trailing {
        return Err(STATUS_OBJECT_NAME_INVALID);
    }
    let mut file = File::plain(0, 0, false);
    file.attributes = request.attributes as u8 & SETTABLE_ATTRIBUTES | ATTRIBUTE_ARCHIVE;
    file.times = io::now();
    write::create_entry(volume, parent.first_cluster, name, &mut file)?;
    Ok(file)
}

/// Overwrite the open file at `record`: cut to nothing, the attributes asked for (and the archive
/// bit) in place of its own, its last write now. A mapped file is not cut
/// (STATUS_USER_MAPPED_FILE).
fn overwrite(record: u16, attributes: u32) -> Result<(), NtStatus> {
    if io::mapped(record) && records().get(record).file.size > 0 {
        return Err(STATUS_USER_MAPPED_FILE);
    }
    io::with_volume(|volume| {
        let mut file = records().get(record).file;
        file.attributes = attributes as u8 & SETTABLE_ATTRIBUTES | ATTRIBUTE_ARCHIVE;
        let stamp = io::now();
        file.times.write_date = stamp.write_date;
        file.times.write_time = stamp.write_time;
        write::set_size(volume, &mut file, 0)?;
        records().get_mut(record).file = file;
        Ok(())
    })
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
    slot.addr().probe(4)?;
    io_status.probe(8)?;
    let request = Request {
        access,
        granted: rights::mapped(access),
        disposition,
        options,
        attributes: file_attributes,
    };
    // The walk, the decision and a create are one locked section: no other create can take the name
    // between the look and the entry.
    let (file, information, overwrites, granted) = io::with_volume(|volume| {
        if target.name.volume {
            let root = crate::fs::fat32::lookup::root(volume);
            return existing(volume, &target, root, &request);
        }
        match walk(volume, target.start, &target.name)? {
            Found::Existing(file) => existing(volume, &target, file, &request),
            Found::Missing { parent } => missing(volume, &target, parent, &request)
                .map(|file| (file, FILE_CREATED, false, request.granted)),
        }
    })?;
    let open = io::Open {
        granted,
        share: share as u8,
        inherit: target.inherit,
        synchronous: options & (FILE_SYNCHRONOUS_IO_ALERT | FILE_SYNCHRONOUS_IO_NONALERT) != 0,
        delete_on_close: options & FILE_DELETE_ON_CLOSE != 0,
    };
    let handle = io::open(file, &open)?;
    if overwrites {
        let record = io::object_of(handle).expect("just opened").record;
        if let Err(failure) = overwrite(record, file_attributes) {
            crate::user::args::calling_process().close_handle(handle);
            return Err(failure);
        }
    }
    deliver(slot, handle)?;
    complete(io_status, STATUS_SUCCESS, information);
    Ok(STATUS_SUCCESS)
}

/// NtCreateFile: open the file or directory the name names, or make it, as the disposition says
/// (FILE_SUPERSEDE, FILE_OPEN, FILE_CREATE, FILE_OPEN_IF, FILE_OVERWRITE, FILE_OVERWRITE_IF), its
/// handle written back with the rights asked for and the I/O status's Information what happened
/// (FILE_OPENED, FILE_CREATED, FILE_OVERWRITTEN, FILE_SUPERSEDED). A name already taken is
/// STATUS_OBJECT_NAME_COLLISION for FILE_CREATE; a missing one STATUS_OBJECT_NAME_NOT_FOUND for the
/// opening dispositions (STATUS_OBJECT_PATH_NOT_FOUND when its directory is missing).
/// FILE_DIRECTORY_FILE asks a directory (STATUS_NOT_A_DIRECTORY for a file),
/// FILE_NON_DIRECTORY_FILE a file (STATUS_FILE_IS_A_DIRECTORY for a directory); a read-only file
/// refuses write and delete rights and an overwrite (STATUS_ACCESS_DENIED). The allocation size and
/// the extended attributes are not consulted.
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
    create(
        slot,
        access,
        attributes,
        io_status,
        file_attributes,
        share,
        disposition,
        options,
    )
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
    create(
        slot, access, attributes, io_status, 0, share, FILE_OPEN, options,
    )
}
