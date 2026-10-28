//! NtQueryInformationFile and NtSetInformationFile over an open file, and NtQueryAttributesFile
//! and NtQueryFullAttributesFile by name (no open: no share check).
//!
//! The I/O manager's order: the class and the buffer's length (STATUS_INVALID_INFO_CLASS,
//! STATUS_INFO_LENGTH_MISMATCH), the buffer's probe, then the handle and the rights the class needs
//! (the basic times and attributes FILE_READ_ATTRIBUTES to read, FILE_WRITE_ATTRIBUTES to write; a
//! rename or a delete DELETE; the size FILE_WRITE_DATA; the rest none). The file system acts on the
//! file as its record holds it, every change written to its entry inside the volume's locked
//! section.

use rtl::pod::Pod;

use super::super::attributes::MAX_NAME;
use super::super::call::{Handle, NtCall, NtResult, UserAddr};
use super::common::{check_access, cluster_bytes, complete, file_object, target, walk, Found};
use super::info::{self, Open};
use super::name::{self, FileName};
use crate::fs::fat32::dir::is_empty;
use crate::fs::fat32::dirent::{Times, ATTR_DIRECTORY, ATTR_READ_ONLY};
use crate::fs::fat32::lookup::File;
use crate::fs::fat32::write;
use crate::fs::file::{records, rights, same_entry};
use crate::fs::io::{self, times_at, SETTABLE_ATTRIBUTES};
use crate::status::*;

/// FileModeInformation's synchronous-I/O mode.
const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x20;

/// The rights a query of `class` needs.
fn query_rights(class: u32) -> u32 {
    match class {
        info::FILE_BASIC_INFORMATION
        | info::FILE_ALL_INFORMATION
        | info::FILE_NETWORK_OPEN_INFORMATION => rights::FILE_READ_ATTRIBUTES,
        _ => 0,
    }
}

/// The rights a set of `class` needs.
fn set_rights(class: u32) -> u32 {
    match class {
        info::FILE_BASIC_INFORMATION => rights::FILE_WRITE_ATTRIBUTES,
        info::FILE_RENAME_INFORMATION | info::FILE_DISPOSITION_INFORMATION => rights::DELETE,
        info::FILE_ALLOCATION_INFORMATION | info::FILE_END_OF_FILE_INFORMATION => {
            rights::FILE_WRITE_DATA
        }
        _ => 0,
    }
}

/// The class and length checks: the class's least size.
fn sized(size: Option<usize>, length: u32) -> Result<usize, NtStatus> {
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
    io_status.probe(8)?;
    information.probe(length)?;
    let object = file_object(handle.raw())?;
    check_access(&object, query_rights(class))?;
    let file = io::file_of(&object);
    let open = Open {
        allocation: info::allocation(&file, cluster_bytes()),
        delete_pending: records().delete_pending(object.record),
        position: object.position,
        granted: object.granted,
        mode: if object.synchronous {
            FILE_SYNCHRONOUS_IO_NONALERT
        } else {
            0
        },
    };
    let mut answer = [0u8; info::ALL_SIZE];
    let written =
        info::query(class, &file, &open, &mut answer[..size]).ok_or(STATUS_INVALID_INFO_CLASS)?;
    information.write(&answer[..written])?;
    complete(io_status, STATUS_SUCCESS, written as u32);
    Ok(STATUS_SUCCESS)
}

/// The times a basic set names (zero: leave it), applied to `file`.
fn set_times(file: &mut File, created: u64, accessed: u64, written: u64) {
    let stamp = |time: u64| (time != 0).then(|| times_at(time));
    if let Some(Times {
        create_date,
        create_time,
        create_hundredths,
        ..
    }) = stamp(created)
    {
        (
            file.times.create_date,
            file.times.create_time,
            file.times.create_hundredths,
        ) = (create_date, create_time, create_hundredths);
    }
    if let Some(Times { access_date, .. }) = stamp(accessed) {
        file.times.access_date = access_date;
    }
    if let Some(Times {
        write_date,
        write_time,
        ..
    }) = stamp(written)
    {
        (file.times.write_date, file.times.write_time) = (write_date, write_time);
    }
}

/// Where a rename's target name starts.
enum Start {
    /// A directory's (its root directory's file object), or the volume's root (an absolute path).
    At(Option<File>),
    /// The file's own directory (a bare name).
    Own,
}

/// FILE_RENAME_INFORMATION's fixed part: ReplaceIfExists (a BOOLEAN, padded to the handle's
/// alignment), RootDirectory, and FileNameLength in bytes. The name's units follow it.
#[repr(C)]
#[derive(Clone, Copy)]
struct RenameHeader {
    replace_if_exists: u8,
    padding: [u8; 3],
    root_directory: u32,
    file_name_length: u32,
}

// SAFETY: integers and a byte array, 12 bytes without padding (asserted below); any bytes make a
// value.
unsafe impl Pod for RenameHeader {}

/// Where FileName starts: FILE_RENAME_INFORMATION's fixed part is 12 bytes on x86.
const RENAME_NAME_OFFSET: usize = size_of::<RenameHeader>();
const _: () = assert!(RENAME_NAME_OFFSET == 12);

/// A rename's target name (FILE_RENAME_INFORMATION's, `length` bytes at `information`, its fixed
/// part `header`): relative to its root directory's file object, an absolute NT path, or a bare
/// name in the file's own directory.
fn rename_target(
    header: &RenameHeader,
    length: u32,
    information: UserAddr,
) -> Result<(FileName, Start), NtStatus> {
    let (root, name_length) = (header.root_directory, header.file_name_length as usize / 2);
    if name_length == 0
        || name_length > MAX_NAME
        || RENAME_NAME_OFFSET + 2 * name_length > length as usize
    {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let mut units = [0u16; MAX_NAME];
    let units = &mut units[..name_length];
    information
        .offset(RENAME_NAME_OFFSET as u32)
        .read_units(units)?;
    let units = &*units;
    if root != 0 {
        let directory = file_object(root)?;
        let directory = io::file_of(&directory);
        if !directory.directory {
            return Err(STATUS_INVALID_PARAMETER);
        }
        return Ok((name::relative(units)?, Start::At(Some(directory))));
    }
    if units.contains(&u16::from(b'\\')) {
        return Ok((name::absolute(units)?, Start::At(None)));
    }
    Ok((name::relative(units)?, Start::Own))
}

/// FileRenameInformation's work: the file's entry moved to the target's name (an existing one
/// replaced only when asked, and only a file that is not read-only, nor a directory:
/// STATUS_OBJECT_NAME_COLLISION otherwise, as when not asked; and only one no one holds open:
/// STATUS_ACCESS_DENIED), its record following it.
fn rename(record: u16, replace: bool, target: (FileName, Start)) -> Result<(), NtStatus> {
    let (name, start) = target;
    io::with_volume(|volume| {
        let file = records().get(record).file;
        if file.parent_cluster == 0 {
            return Err(STATUS_ACCESS_DENIED);
        }
        if name.trailing && !file.directory {
            return Err(STATUS_OBJECT_NAME_INVALID);
        }
        let start = match start {
            Start::At(start) => start,
            Start::Own => Some(File::plain(file.parent_cluster, 0, true)),
        };
        let parent = match walk(volume, start, &name)? {
            // A case-only rename names the file itself (refused as a collision).
            Found::Existing(existing) if !replace || same_entry(&existing, &file) => {
                return Err(STATUS_OBJECT_NAME_COLLISION)
            }
            Found::Existing(existing) => {
                // A directory or a read-only file is never replaced: the name stays taken (the
                // fswrite capture's MoveFileEx answers ERROR_ALREADY_EXISTS for both).
                if existing.directory || existing.attributes & ATTR_READ_ONLY != 0 {
                    return Err(STATUS_OBJECT_NAME_COLLISION);
                }
                if records().find(&existing).is_some() {
                    return Err(STATUS_ACCESS_DENIED);
                }
                write::delete(volume, &existing)?;
                File::plain(existing.parent_cluster, 0, true)
            }
            Found::Missing { parent } => parent,
        };
        let moved = write::rename(volume, &file, parent.first_cluster, name.last())?;
        records().refresh(&file, &moved);
        Ok(())
    })
}

/// A size change (FileEndOfFileInformation, or FileAllocationInformation when it cuts the file):
/// a directory has none to change (STATUS_INVALID_HANDLE, an assumption, unverified); past 4 GiB
/// is STATUS_DISK_FULL; a mapped file is not cut (STATUS_USER_MAPPED_FILE).
fn resize(record: u16, size: u64, allocation_only: bool) -> Result<(), NtStatus> {
    let file = records().get(record).file;
    if file.directory {
        return Err(STATUS_INVALID_HANDLE);
    }
    let size = u32::try_from(size).map_err(|_| STATUS_DISK_FULL)?;
    if allocation_only && size >= file.size {
        return Ok(());
    }
    if io::mapped(record) && size < file.size {
        return Err(STATUS_USER_MAPPED_FILE);
    }
    io::with_volume(|volume| {
        let mut file = records().get(record).file;
        write::set_size(volume, &mut file, size)?;
        records().get_mut(record).file = file;
        Ok(())
    })
}

/// NtSetInformationFile: the basic times and attributes (zero leaves one as it is; the directory
/// bit stays the entry's), a rename, the pending delete (a read-only file, a mapped one or the root
/// is STATUS_CANNOT_DELETE, a directory with entries STATUS_DIRECTORY_NOT_EMPTY: it goes with the
/// last open's cleanup), the position, the allocation (cutting the file when smaller) and the end
/// of file.
fn set_information_file_held(
    _call: &mut NtCall,
    handle: Handle,
    io_status: UserAddr,
    information: UserAddr,
    length: u32,
    class: u32,
) -> NtResult {
    let size = sized(info::set_size(class), length)?;
    io_status.probe(8)?;
    let mut bytes = [0u8; info::BASIC_SIZE];
    information.read(&mut bytes[..size])?;
    let mut object = file_object(handle.raw())?;
    check_access(&object, set_rights(class))?;
    let record = object.record;
    let quad = |at: usize| u64::from_le_bytes(bytes[at..at + 8].try_into().expect("eight bytes"));
    let word = |at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().expect("four bytes"));
    match class {
        info::FILE_BASIC_INFORMATION => {
            let (created, accessed, written, attributes) = (quad(0), quad(8), quad(16), word(32));
            let file = records().get(record).file;
            if file.parent_cluster == 0 {
                return Err(STATUS_ACCESS_DENIED);
            }
            if attributes & ATTR_DIRECTORY as u32 != 0 && !file.directory {
                return Err(STATUS_INVALID_PARAMETER);
            }
            io::with_volume(|volume| {
                let mut file = records().get(record).file;
                set_times(&mut file, created, accessed, written);
                if attributes != 0 {
                    file.attributes =
                        file.attributes & ATTR_DIRECTORY | attributes as u8 & SETTABLE_ATTRIBUTES;
                }
                write::update_entry(volume, &file)?;
                records().get_mut(record).file = file;
                Ok(())
            })?;
        }
        info::FILE_RENAME_INFORMATION => {
            let header = information.cast::<RenameHeader>().read()?;
            let target = rename_target(&header, length, information)?;
            rename(record, header.replace_if_exists != 0, target)?;
        }
        info::FILE_DISPOSITION_INFORMATION => {
            let delete = bytes[0] != 0;
            if delete {
                let file = records().get(record).file;
                if file.parent_cluster == 0
                    || file.attributes & ATTR_READ_ONLY != 0
                    || io::mapped(record)
                {
                    return Err(STATUS_CANNOT_DELETE);
                }
                if file.directory
                    && !io::with_volume(|volume| is_empty(volume, file.first_cluster))?
                {
                    return Err(STATUS_DIRECTORY_NOT_EMPTY);
                }
            }
            records().set_delete_pending(record, delete);
        }
        info::FILE_POSITION_INFORMATION => {
            let position = quad(0);
            if (position as i64) < 0 {
                return Err(STATUS_INVALID_PARAMETER);
            }
            object.position = position;
        }
        info::FILE_ALLOCATION_INFORMATION => resize(record, quad(0), true)?,
        info::FILE_END_OF_FILE_INFORMATION => resize(record, quad(0), false)?,
        _ => return Err(STATUS_INVALID_INFO_CLASS),
    }
    complete(io_status, STATUS_SUCCESS, 0);
    Ok(STATUS_SUCCESS)
}

/// The file a name names, for the attribute queries: STATUS_OBJECT_NAME_NOT_FOUND when it is
/// missing, STATUS_DELETE_PENDING while it is being deleted, STATUS_OBJECT_NAME_INVALID for a file
/// named with a trailing separator.
fn named(attributes: UserAddr, out: UserAddr, size: u32) -> Result<File, NtStatus> {
    let target = target(attributes)?;
    out.probe(size)?;
    let file = io::with_volume(|volume| {
        if target.name.volume {
            return Ok(crate::fs::fat32::lookup::root(volume));
        }
        match walk(volume, target.start, &target.name)? {
            Found::Existing(file) => Ok(file),
            Found::Missing { .. } => Err(STATUS_OBJECT_NAME_NOT_FOUND),
        }
    })?;
    if target.name.trailing && !file.directory {
        return Err(STATUS_OBJECT_NAME_INVALID);
    }
    if records()
        .find(&file)
        .is_some_and(|index| records().delete_pending(index))
    {
        return Err(STATUS_DELETE_PENDING);
    }
    Ok(file)
}

/// NtQueryAttributesFile: the file's FILE_BASIC_INFORMATION, by name.
pub fn query_attributes_file(
    _call: &mut NtCall,
    attributes: UserAddr,
    information: UserAddr,
) -> NtResult {
    let file = named(attributes, information, info::BASIC_SIZE as u32)?;
    information.write(&info::basic(&file))?;
    Ok(STATUS_SUCCESS)
}

/// NtQueryFullAttributesFile: the file's FILE_NETWORK_OPEN_INFORMATION, by name.
pub fn query_full_attributes_file(
    _call: &mut NtCall,
    attributes: UserAddr,
    information: UserAddr,
) -> NtResult {
    let file = named(attributes, information, info::NETWORK_OPEN_SIZE as u32)?;
    information.write(&info::network_open(
        &file,
        info::allocation(&file, cluster_bytes()),
    ))?;
    Ok(STATUS_SUCCESS)
}

/// NtQueryInformationFile (see [`query_information_file_held`]), as one critical region.
#[allow(clippy::too_many_arguments)]
pub fn query_information_file(
    call: &mut NtCall,
    handle: Handle,
    io_status: UserAddr,
    information: UserAddr,
    length: u32,
    class: u32,
) -> NtResult {
    // The call holds its file object (a reference) across the volume's critical regions: run it
    // inside one of its own, so a termination requested meanwhile ends the thread only once the
    // reference has gone (an inner region's end would end it with the reference still held).
    crate::process::threads::critical_region(|| {
        query_information_file_held(call, handle, io_status, information, length, class)
    })
}

/// NtSetInformationFile (see [`set_information_file_held`]), as one critical region: like the
/// query, it holds its file object across the volume's critical regions.
#[allow(clippy::too_many_arguments)]
pub fn set_information_file(
    call: &mut NtCall,
    handle: Handle,
    io_status: UserAddr,
    information: UserAddr,
    length: u32,
    class: u32,
) -> NtResult {
    crate::process::threads::critical_region(|| {
        set_information_file_held(call, handle, io_status, information, length, class)
    })
}
