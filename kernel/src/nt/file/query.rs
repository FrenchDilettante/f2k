//! NtQueryInformationFile and NtSetInformationFile over an open file, and NtQueryAttributesFile
//! and NtQueryFullAttributesFile by name (no open: no share check).
//!
//! The I/O manager's order: the class and the buffer's length (STATUS_INVALID_INFO_CLASS,
//! STATUS_INFO_LENGTH_MISMATCH), the buffer's probe, then the handle and the rights the class needs
//! (the basic times and attributes FILE_READ_ATTRIBUTES to read, FILE_WRITE_ATTRIBUTES to write; a
//! rename or a delete DELETE; the size FILE_WRITE_DATA; the rest none). Then the device the object
//! is open on answers, one arm per device; the position is the object's alike for every device
//! (Windows 2000's I/O manager answers a synchronous object's itself). A disk file's file system
//! acts on the file as its record holds it, every change written to its entry inside the volume's
//! locked section.

use rtl::nt::info::{
    FileAllInformation,
    FileAllocationInformation,
    FileBasicInformation,
    FileDispositionInformation,
    FileEndOfFileInformation,
    FileNetworkOpenInformation,
    FilePositionInformation,
    FileRenameInformation,
    FileStandardInformation,
    VariableSize,
};

use super::super::attributes::MAX_NAME;
use super::super::call::{Handle, NtCall, NtResult, UserAddr};
use super::common::{check_access, cluster_bytes, complete, file_object, target, walk, Found};
use super::info::{self, Open, QueryClass, SetClass};
use super::name::{self, FileName};
use crate::fs::fat32::dir::is_empty;
use crate::fs::fat32::dirent::{Times, ATTR_DIRECTORY, ATTR_READ_ONLY};
use crate::fs::fat32::lookup::File;
use crate::fs::fat32::write;
use crate::fs::file::{same_entry, with_records, Context, FileObject, FileRecordId};
use crate::fs::io::{self, times_at, SETTABLE_ATTRIBUTES};
use crate::fs::pipes::{self, PipeEnd};
use crate::ob::Referenced;
use crate::status::*;

/// FileModeInformation's synchronous-I/O mode.
const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x20;

/// The length check: a buffer shorter than the class's least size is
/// STATUS_INFO_LENGTH_MISMATCH.
fn sized(size: usize, length: u32) -> Result<(), NtStatus> {
    if (length as usize) < size {
        return Err(STATUS_INFO_LENGTH_MISMATCH);
    }
    Ok(())
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
    let class = QueryClass::try_from(class)?;
    sized(class.min_size(), length)?;
    io_status.probe(8)?;
    information.probe(length)?;
    let object = file_object(handle.raw())?;
    check_access(&object, class.rights())?;
    let mut answer = [0u8; size_of::<FileAllInformation>()];
    // The position as the object's lock has it: a read or write through another handle to the
    // object moves it under the lock. A disk file's answer is one critical region (it holds the
    // object across the volume's); a pipe's waits for the lock outside any, as its reads do.
    let written = match object.context {
        Context::Disk(record) => crate::process::threads::critical_region(|| {
            let position = io::serialized(&object, |held| held.position);
            match class {
                QueryClass::Position => info::position(position, &mut answer),
                _ => query_disk(&object, record, position, class, &mut answer),
            }
        }),
        Context::Pipe(end) => {
            let position = io::serialized_interruptible(&object, |held| held.position)?;
            match class {
                QueryClass::Position => info::position(position, &mut answer),
                _ => query_pipe(end, class, &mut answer)?,
            }
        }
        Context::Null => {
            let position = io::serialized_interruptible(&object, |held| held.position)?;
            match class {
                QueryClass::Position => info::position(position, &mut answer),
                // Empty, as the null device always is: a file of no bytes.
                QueryClass::Standard => info::put(
                    &mut answer,
                    &FileStandardInformation {
                        number_of_links: 1,
                        ..Default::default()
                    },
                ),
                _ => return Err(STATUS_NOT_IMPLEMENTED),
            }
        }
    };
    information.write(&answer[..written])?;
    complete(io_status, STATUS_SUCCESS, written as u32);
    Ok(STATUS_SUCCESS)
}

/// A pipe's answer to a query of `class` into `answer` (the position is the I/O manager's): its
/// standard information — the allocation both queues' quotas, the end of file the bytes in the
/// pipe (the capture's GetFileSize), one link, no delete pending, no directory. The pipe's other
/// classes are not served yet (STATUS_NOT_IMPLEMENTED).
fn query_pipe(end: PipeEnd, class: QueryClass, answer: &mut [u8]) -> Result<usize, NtStatus> {
    match class {
        QueryClass::Standard => {
            let (allocation_size, end_of_file) = pipes::sizes(end);
            let standard = FileStandardInformation {
                allocation_size,
                end_of_file,
                number_of_links: 1,
                ..Default::default()
            };
            Ok(info::put(answer, &standard))
        }
        _ => Err(STATUS_NOT_IMPLEMENTED),
    }
}

/// A disk file's answer to a query of `class` (see [`info::query`]) into `answer`: the bytes
/// written.
fn query_disk(
    object: &FileObject,
    record: FileRecordId,
    position: u64,
    class: QueryClass,
    answer: &mut [u8],
) -> usize {
    let file = io::file_at(record);
    let open = Open {
        allocation: info::allocation(&file, cluster_bytes()),
        delete_pending: with_records(|records| records.delete_pending(record)),
        position,
        granted: object.granted,
        mode: if object.synchronous {
            FILE_SYNCHRONOUS_IO_NONALERT
        } else {
            0
        },
    };
    info::query(class, &file, &open, answer)
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

/// A rename's target name (FILE_RENAME_INFORMATION's, `length` bytes at `information`, its fixed
/// part read as `header`): relative to its root directory's file object, an absolute NT path, or a
/// bare name in the file's own directory. A root that is a file's, or another device's object than
/// the disk's, is STATUS_INVALID_PARAMETER; a pipe's name STATUS_NOT_SAME_DEVICE.
fn rename_target(
    header: &FileRenameInformation,
    length: u32,
    information: UserAddr,
) -> Result<(FileName, Start), NtStatus> {
    const NAME: usize = FileRenameInformation::FIXED_SIZE;
    let (root, name_length) = (header.root_directory, header.file_name_length as usize / 2);
    if name_length == 0 || name_length > MAX_NAME || NAME + 2 * name_length > length as usize {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let mut units = [0u16; MAX_NAME];
    let units = &mut units[..name_length];
    information.offset(NAME as u32).read_units(units)?;
    let units = &*units;
    if root != 0 {
        let directory = file_object(root)?;
        let directory = io::file_at(directory.disk().ok_or(STATUS_INVALID_PARAMETER)?);
        if !directory.directory {
            return Err(STATUS_INVALID_PARAMETER);
        }
        return Ok((name::relative(units)?, Start::At(Some(directory))));
    }
    if units.contains(&u16::from(b'\\')) {
        return match name::absolute(units)? {
            name::Absolute::Disk(name) => Ok((name, Start::At(None))),
            // A disk file's name never moves onto another device.
            name::Absolute::Pipe(_) => Err(STATUS_NOT_SAME_DEVICE),
        };
    }
    Ok((name::relative(units)?, Start::Own))
}

/// FileRenameInformation's work: the file's entry moved to the target's name (an existing one
/// replaced only when asked, and only a file that is not read-only, nor a directory:
/// STATUS_OBJECT_NAME_COLLISION otherwise, as when not asked; and only one no one holds open:
/// STATUS_ACCESS_DENIED), its record following it.
fn rename(record: FileRecordId, replace: bool, target: (FileName, Start)) -> Result<(), NtStatus> {
    let (name, start) = target;
    io::with_volume(|volume| {
        let file = io::file_at(record);
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
                if with_records(|records| records.find(&existing).is_some()) {
                    return Err(STATUS_ACCESS_DENIED);
                }
                write::delete(volume, &existing)?;
                File::plain(existing.parent_cluster, 0, true)
            }
            Found::Missing { parent } => parent,
        };
        let moved = write::rename(volume, &file, parent.first_cluster, name.last())?;
        with_records(|records| records.refresh(&file, &moved));
        Ok(())
    })
}

/// A size change (FileEndOfFileInformation, or FileAllocationInformation when it cuts the file):
/// a directory has none to change (STATUS_INVALID_HANDLE, an assumption, unverified); past 4 GiB
/// is STATUS_DISK_FULL; a mapped file is not cut (STATUS_USER_MAPPED_FILE).
fn resize(record: FileRecordId, size: u64, allocation_only: bool) -> Result<(), NtStatus> {
    let file = io::file_at(record);
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
        let mut file = io::file_at(record);
        write::set_size(volume, &mut file, size)?;
        io::store_file(record, file);
        Ok(())
    })
}

/// What a set asks: its class's structure, read from the caller's buffer.
enum Setting {
    Basic(FileBasicInformation),
    Rename(FileRenameInformation),
    Disposition(FileDispositionInformation),
    Position(FilePositionInformation),
    Allocation(FileAllocationInformation),
    EndOfFile(FileEndOfFileInformation),
}

impl Setting {
    /// The structure a set of `class` takes, read whole from `information`.
    fn read(class: SetClass, information: UserAddr) -> Result<Setting, NtStatus> {
        Ok(match class {
            SetClass::Basic => Setting::Basic(information.cast().read()?),
            SetClass::Rename => Setting::Rename(information.cast().read()?),
            SetClass::Disposition => Setting::Disposition(information.cast().read()?),
            SetClass::Position => Setting::Position(information.cast().read()?),
            SetClass::Allocation => Setting::Allocation(information.cast().read()?),
            SetClass::EndOfFile => Setting::EndOfFile(information.cast().read()?),
        })
    }
}

/// NtSetInformationFile: the basic times and attributes (zero leaves one as it is; the directory
/// bit stays the entry's), a rename, the pending delete (a read-only file, a mapped one or the root
/// is STATUS_CANNOT_DELETE, a directory with entries STATUS_DIRECTORY_NOT_EMPTY: it goes with the
/// last open's cleanup), the position, the allocation (cutting the file when smaller) and the end
/// of file. The class's structure is read before the handle is looked at.
fn set_information_file_held(
    _call: &mut NtCall,
    handle: Handle,
    io_status: UserAddr,
    information: UserAddr,
    length: u32,
    class: u32,
) -> NtResult {
    let class = SetClass::try_from(class)?;
    sized(class.min_size(), length)?;
    io_status.probe(8)?;
    let setting = Setting::read(class, information)?;
    let object = file_object(handle.raw())?;
    check_access(&object, class.rights())?;
    match object.context {
        // One critical region: it holds the object across the volume's.
        Context::Disk(record) => crate::process::threads::critical_region(|| {
            set_disk(&object, record, setting, length, information)
        })?,
        Context::Pipe(_) | Context::Null => set_pipe(&object, setting)?,
    }
    complete(io_status, STATUS_SUCCESS, 0);
    Ok(STATUS_SUCCESS)
}

/// A pipe's set, and the null device's: the position (the I/O manager's, as for any device; neither
/// reads it, and the capture's SetFilePointer reads back what it set). Their other classes are not
/// served yet (STATUS_NOT_IMPLEMENTED).
fn set_pipe(object: &Referenced<FileObject>, setting: Setting) -> Result<(), NtStatus> {
    match setting {
        Setting::Position(position) => set_position(object, position),
        _ => Err(STATUS_NOT_IMPLEMENTED),
    }
}

/// FilePositionInformation's set, the same for every device's object (Windows 2000's I/O manager
/// sets a synchronous object's position itself): a negative offset is STATUS_INVALID_PARAMETER;
/// the position moves under the object's lock, as a read or write moves it — a disk file's inside
/// a critical region, a pipe's waiting for the lock outside any (see [`io::serialized`] and
/// [`io::serialized_interruptible`]).
fn set_position(
    object: &Referenced<FileObject>,
    position: FilePositionInformation,
) -> Result<(), NtStatus> {
    let position = position.current_byte_offset;
    if (position as i64) < 0 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    match object.context {
        Context::Disk(_) => io::serialized(object, |held| held.position = position),
        Context::Pipe(_) | Context::Null => {
            io::serialized_interruptible(object, |held| held.position = position)?
        }
    }
    Ok(())
}

/// A disk file's set (see [`set_information_file_held`]): `setting` applied to the file at
/// `record` through `object`, the class's structure read from `information`, `length` bytes.
fn set_disk(
    object: &Referenced<FileObject>,
    record: FileRecordId,
    setting: Setting,
    length: u32,
    information: UserAddr,
) -> Result<(), NtStatus> {
    match setting {
        Setting::Basic(basic) => {
            let attributes = basic.file_attributes;
            let file = io::file_at(record);
            if file.parent_cluster == 0 {
                return Err(STATUS_ACCESS_DENIED);
            }
            if attributes & ATTR_DIRECTORY as u32 != 0 && !file.directory {
                return Err(STATUS_INVALID_PARAMETER);
            }
            io::with_volume(|volume| {
                let mut file = io::file_at(record);
                set_times(
                    &mut file,
                    basic.creation_time,
                    basic.last_access_time,
                    basic.last_write_time,
                );
                if attributes != 0 {
                    file.attributes =
                        file.attributes & ATTR_DIRECTORY | attributes as u8 & SETTABLE_ATTRIBUTES;
                }
                write::update_entry(volume, &file)?;
                io::store_file(record, file);
                Ok(())
            })?;
        }
        Setting::Rename(rename_information) => {
            let target = rename_target(&rename_information, length, information)?;
            rename(record, rename_information.replace_if_exists != 0, target)?;
        }
        Setting::Disposition(disposition) => {
            let delete = disposition.delete_file != 0;
            if delete {
                let file = io::file_at(record);
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
            with_records(|records| records.set_delete_pending(record, delete));
        }
        Setting::Position(position) => set_position(object, position)?,
        Setting::Allocation(allocation) => resize(record, allocation.allocation_size, true)?,
        Setting::EndOfFile(end) => resize(record, end.end_of_file, false)?,
    }
    Ok(())
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
    if with_records(|records| {
        records
            .find(&file)
            .is_some_and(|record| records.delete_pending(record))
    }) {
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
    let information = information.cast::<FileBasicInformation>();
    let file = named(
        attributes,
        information.addr(),
        size_of::<FileBasicInformation>() as u32,
    )?;
    information.write(info::basic(&file))?;
    Ok(STATUS_SUCCESS)
}

/// NtQueryFullAttributesFile: the file's FILE_NETWORK_OPEN_INFORMATION, by name.
pub fn query_full_attributes_file(
    _call: &mut NtCall,
    attributes: UserAddr,
    information: UserAddr,
) -> NtResult {
    let information = information.cast::<FileNetworkOpenInformation>();
    let size = size_of::<FileNetworkOpenInformation>() as u32;
    let file = named(attributes, information.addr(), size)?;
    information.write(info::network_open(
        &file,
        info::allocation(&file, cluster_bytes()),
    ))?;
    Ok(STATUS_SUCCESS)
}

/// NtQueryInformationFile (see [`query_information_file_held`]): a disk file's answer is one
/// critical region, inside the device's arm.
#[allow(clippy::too_many_arguments)]
pub fn query_information_file(
    call: &mut NtCall,
    handle: Handle,
    io_status: UserAddr,
    information: UserAddr,
    length: u32,
    class: u32,
) -> NtResult {
    query_information_file_held(call, handle, io_status, information, length, class)
}

/// NtSetInformationFile (see [`set_information_file_held`]): like the query, a disk file's set is
/// one critical region, inside the device's arm.
#[allow(clippy::too_many_arguments)]
pub fn set_information_file(
    call: &mut NtCall,
    handle: Handle,
    io_status: UserAddr,
    information: UserAddr,
    length: u32,
    class: u32,
) -> NtResult {
    set_information_file_held(call, handle, io_status, information, length, class)
}
