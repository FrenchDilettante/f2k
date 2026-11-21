//! NtCreateFile and NtOpenFile: the I/O manager's checks of the arguments, then the create of the
//! device the name is on: FastFat's — the walk, the disposition's decision against what the name
//! names, a new file or directory made, the open (its share check), and an overwrite's truncation
//! — or the named-pipe file system's, a pipe's client end connected ([`super::pipe`]), or the null
//! device's.

use super::super::call::{NtCall, NtResult, UserAddr, UserPtr};
use super::common::{complete, deliver, named, walk, Found, Named, Target};
use super::{
    check_arguments,
    implied_access,
    make_missing,
    new_attributes,
    open_existing,
    Existing,
    Making,
    Request,
    FILE_CREATED,
    FILE_DELETE_ON_CLOSE,
    FILE_OPEN,
    FILE_OPENED,
    FILE_SYNCHRONOUS_IO_ALERT,
    FILE_SYNCHRONOUS_IO_NONALERT,
};
use crate::fs::fat32::dir::is_empty;
use crate::fs::fat32::lookup::File;
use crate::fs::fat32::volume::Volume;
use crate::fs::fat32::write;
use crate::fs::file::{rights, Context, FileRecordId};
use crate::fs::io;
use crate::status::*;

/// The decision on an existing entry ([`open_existing`]): the file (the open goes ahead), its I/O
/// status information, whether it is overwritten once open, and the rights granted; a directory
/// opened for delete-on-close with entries left is STATUS_DIRECTORY_NOT_EMPTY.
fn existing(
    volume: &mut Volume,
    target: &Target,
    file: File,
    request: &Request,
) -> Result<(File, u32, bool, u32), NtStatus> {
    let entry = Existing {
        directory: file.directory,
        // The root is never deleted (it has no entry).
        root: target.name.volume || file.parent_cluster == 0,
        attributes: file.attributes,
    };
    let opening = open_existing(entry, target.name.trailing, request)?;
    if opening.must_be_empty && !is_empty(volume, file.first_cluster)? {
        return Err(STATUS_DIRECTORY_NOT_EMPTY);
    }
    Ok((
        file,
        opening.information,
        opening.overwrite,
        opening.granted,
    ))
}

/// The decision on a missing name ([`make_missing`]): made (a directory when asked, else a file
/// with the attributes asked for and the archive bit, stamped now) when the disposition creates.
fn missing(
    volume: &mut Volume,
    target: &Target,
    parent: File,
    request: &Request,
) -> Result<File, NtStatus> {
    let name = target.name.last();
    match make_missing(target.name.trailing, request)? {
        Making::Directory => write::make_directory(volume, parent.first_cluster, name, io::now()),
        Making::File(attributes) => {
            let mut file = File::plain(0, 0, false);
            file.attributes = attributes;
            file.times = io::now();
            write::create_entry(volume, parent.first_cluster, name, &mut file)?;
            Ok(file)
        }
    }
}

/// Overwrite the open file at `record`: cut to nothing, the attributes asked for (and the archive
/// bit) in place of its own, its last write now. A mapped file is not cut
/// (STATUS_USER_MAPPED_FILE).
fn overwrite(record: FileRecordId, attributes: u32) -> Result<(), NtStatus> {
    if io::mapped(record) && io::file_at(record).size > 0 {
        return Err(STATUS_USER_MAPPED_FILE);
    }
    io::with_volume(|volume| {
        let mut file = io::file_at(record);
        file.attributes = new_attributes(attributes);
        let stamp = io::now();
        file.times.write_date = stamp.write_date;
        file.times.write_time = stamp.write_time;
        write::set_size(volume, &mut file, 0)?;
        io::store_file(record, file);
        Ok(())
    })
}

/// Take back the file or directory a create made when its open then failed (a full handle,
/// record or object table), as FastFat unwinds the entry it made when its create cannot complete:
/// the entry and its clusters gone, so a retry does not find the name taken. Best effort, and not
/// when another open has found the new entry meanwhile.
fn unmake(file: File) {
    let _ = io::with_volume(|volume| {
        if crate::fs::file::with_records(|records| records.find(&file).is_some()) {
            return Ok(());
        }
        write::delete(volume, &file)
    });
}

/// The null device opened, whatever the disposition asks: there is one, always there, and every
/// open of it shares it. Its handle has the rights asked for; the I/O status says FILE_OPENED.
fn open_null(
    access: u32,
    share: u32,
    options: u32,
    inherit: bool,
    slot: UserPtr<u32>,
    io_status: UserAddr,
) -> NtResult {
    let process = crate::user::args::calling_process();
    if process.handles_full() {
        return Err(STATUS_INSUFFICIENT_RESOURCES);
    }
    let open = io::Open {
        granted: rights::mapped(access),
        share: share as u8,
        inherit,
        synchronous: options & (FILE_SYNCHRONOUS_IO_ALERT | FILE_SYNCHRONOUS_IO_NONALERT) != 0,
        delete_on_close: false,
    };
    let access = rights::share_access(open.granted);
    let handle = io::insert(process, Context::Null, access, &open, || {})?;
    deliver(slot, handle)?;
    complete(io_status, STATUS_SUCCESS, FILE_OPENED);
    Ok(STATUS_SUCCESS)
}

/// What a device's open asks.
struct DeviceOpen {
    access: u32,
    file_attributes: u32,
    share: u32,
    disposition: u32,
    options: u32,
    inherit: bool,
}

/// A loaded driver's device opened: IRP_MJ_CREATE sent down to its driver (the I/O manager's,
/// [`crate::dev::io::create`]), and a file object made for the open with its handle. The driver's
/// refusal is the open's; its I/O status's Information is the open's. No share check: a device's
/// driver makes its own (IoCheckShareAccess), as on Windows 2000.
#[inline(never)]
fn open_device(
    device: crate::dev::io::Referenced,
    request: &DeviceOpen,
    slot: UserPtr<u32>,
    io_status: UserAddr,
) -> NtResult {
    let process = crate::user::args::calling_process();
    if process.handles_full() {
        return Err(STATUS_INSUFFICIENT_RESOURCES);
    }
    let granted = rights::mapped(request.access);
    let synchronous =
        request.options & (FILE_SYNCHRONOUS_IO_ALERT | FILE_SYNCHRONOUS_IO_NONALERT) != 0;
    let (file, information) = crate::dev::io::create(
        device,
        &crate::dev::io::OpenRequest {
            desired_access: granted,
            disposition: request.disposition,
            options: request.options,
            file_attributes: request.file_attributes as u16,
            share_access: request.share as u16,
            synchronous,
        },
    )?;
    let open = io::Open {
        granted,
        share: request.share as u8,
        inherit: request.inherit,
        synchronous,
        delete_on_close: false,
    };
    let access = rights::share_access(open.granted);
    let handle = io::insert(process, Context::Device(file), access, &open, || {
        crate::dev::io::cleanup(file);
        crate::dev::io::close(file);
    })?;
    deliver(slot, handle)?;
    complete(io_status, STATUS_SUCCESS, information);
    Ok(STATUS_SUCCESS)
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
    let target = match named(attributes)? {
        Named::Disk(target) => target,
        Named::Pipe { name, inherit } => {
            slot.addr().probe(4)?;
            io_status.probe(8)?;
            let open = super::pipe::ClientOpen {
                granted: rights::mapped(access),
                share,
                disposition,
                options,
                inherit,
            };
            return super::pipe::open_client(&name, &open, slot, io_status);
        }
        Named::Null { inherit } => {
            slot.addr().probe(4)?;
            io_status.probe(8)?;
            return open_null(access, share, options, inherit, slot, io_status);
        }
        Named::Device { device, inherit } => {
            slot.addr().probe(4)?;
            io_status.probe(8)?;
            let request = DeviceOpen {
                access,
                file_attributes,
                share,
                disposition,
                options,
                inherit,
            };
            return open_device(device, &request, slot, io_status);
        }
    };
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
    // An overwrite cuts the file, a supersede replaces it: each is share-checked for that too.
    let implied = implied_access(overwrites, disposition);
    let handle = match io::open(file, &open, implied) {
        Ok(handle) => handle,
        Err(failure) => {
            if information == FILE_CREATED {
                unmake(file);
            }
            return Err(failure);
        }
    };
    if overwrites {
        let record = io::object_of(handle)
            .and_then(|object| object.disk())
            .expect("a disk file just opened");
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
