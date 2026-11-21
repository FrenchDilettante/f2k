//! The file services: NtCreateFile and NtOpenFile, NtReadFile and NtWriteFile,
//! NtFlushBuffersFile, NtLockFile and NtUnlockFile, NtQueryInformationFile and
//! NtSetInformationFile, NtQueryDirectoryFile,
//! NtQueryAttributesFile and NtQueryFullAttributesFile, NtQueryVolumeInformationFile,
//! NtCreateNamedPipeFile and NtFsControlFile — FastFat's answers over the boot volume and the
//! named-pipe file system's over its pipes (`fs`), in NTSTATUS. kernel32's Win32 file calls are
//! user-mode code over these, as on Windows 2000: a Win32 error is the status's mapping, or one of
//! kernel32's own special cases.
//!
//! Names are NT paths (see [`name`]), absolute or relative to a directory's file object. A file
//! object keeps the rights its open was granted (the generic ones mapped to the file rights), and
//! names the device it is open on ([`crate::fs::file::Context`]). Each service makes the I/O
//! manager's checks first, the rights it needs among them, then serves the request by the object's
//! device, one match arm per device (the disk's, FastFat's, and a pipe's, the named-pipe file
//! system's). Every call completes in the caller's thread: a disk file's at once, a pipe's once the
//! other end lets it (a read waits for data, a write for room), the wait inside the service. A
//! synchronous object keeps the position a read or write without an offset uses; an event handed
//! to a read, write or listing is reset first and signaled once it completes. An APC routine
//! (ReadFileEx's completion) is not supported.

pub mod info;
pub mod name;

#[cfg(target_arch = "x86")]
mod create;
#[cfg(target_arch = "x86")]
mod device;
#[cfg(target_arch = "x86")]
mod directory;
#[cfg(target_arch = "x86")]
mod io;
#[cfg(target_arch = "x86")]
mod lock;
#[cfg(target_arch = "x86")]
mod pipe;
#[cfg(target_arch = "x86")]
mod query;
#[cfg(target_arch = "x86")]
mod volume;

#[cfg(target_arch = "x86")]
use common::device_request;
#[cfg(target_arch = "x86")]
pub use common::read_whole_file;
#[cfg(target_arch = "x86")]
pub use create::{create_file, open_file};
#[cfg(target_arch = "x86")]
pub use device::device_io_control_file;
#[cfg(target_arch = "x86")]
pub use directory::query_directory_file;
#[cfg(target_arch = "x86")]
pub use io::{flush_buffers_file, read_file, write_file};
#[cfg(target_arch = "x86")]
pub use lock::{lock_file, unlock_file};
#[cfg(target_arch = "x86")]
pub use pipe::{create_named_pipe_file, fs_control_file};
#[cfg(target_arch = "x86")]
pub use query::{
    query_attributes_file,
    query_full_attributes_file,
    query_information_file,
    set_information_file,
};
#[cfg(target_arch = "x86")]
pub use volume::query_volume_information_file;

/// ByteOffset's special values: the object's position, and (a write's) the end of the file.
pub(crate) const FILE_USE_FILE_POINTER_POSITION: u64 = 0xFFFF_FFFF_FFFF_FFFE;
pub(crate) const FILE_WRITE_TO_END_OF_FILE: u64 = 0xFFFF_FFFF_FFFF_FFFF;

/// The offset a read or a write starts at, as the I/O manager takes ByteOffset (`offset`, none for
/// a null pointer) before it hands the request to the device: none (the object's position) for no
/// offset or FILE_USE_FILE_POINTER_POSITION, which only a synchronous object has (an asynchronous
/// one's is STATUS_INVALID_PARAMETER). Negative offsets are illegal (STATUS_INVALID_PARAMETER) but
/// a write's FILE_WRITE_TO_END_OF_FILE, so every offset a device sees is below 2^63 and an offset
/// plus a 32-bit length cannot overflow.
#[cfg_attr(not(target_arch = "x86"), allow(dead_code))]
pub(crate) fn transfer_offset(
    offset: Option<u64>,
    synchronous: bool,
    write: bool,
) -> Result<Option<u64>, crate::status::NtStatus> {
    use crate::status::STATUS_INVALID_PARAMETER;
    match offset.filter(|&at| at != FILE_USE_FILE_POINTER_POSITION) {
        None if synchronous => Ok(None),
        None => Err(STATUS_INVALID_PARAMETER),
        Some(FILE_WRITE_TO_END_OF_FILE) if write => Ok(Some(FILE_WRITE_TO_END_OF_FILE)),
        Some(at) if (at as i64) < 0 => Err(STATUS_INVALID_PARAMETER),
        Some(at) => Ok(Some(at)),
    }
}

/// The dispositions.
#[cfg_attr(not(target_arch = "x86"), allow(dead_code))]
const FILE_SUPERSEDE: u32 = 0;
const FILE_OPEN: u32 = 1;
const FILE_CREATE: u32 = 2;
const FILE_OPEN_IF: u32 = 3;
#[cfg_attr(not(target_arch = "x86"), allow(dead_code))]
const FILE_OVERWRITE: u32 = 4;
const FILE_OVERWRITE_IF: u32 = 5;

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

/// The I/O manager's checks of a create (IoCreateFile), before any name is read: a disposition or
/// an option, attribute or share bit the platform does not define, both synchronous modes, a
/// synchronous mode without SYNCHRONIZE, delete-on-close without DELETE, a directory asked for and
/// refused at once or with a disposition that cannot make one — each STATUS_INVALID_PARAMETER.
#[cfg_attr(not(target_arch = "x86"), allow(dead_code))]
fn check_arguments(
    access: u32,
    attributes: u32,
    share: u32,
    disposition: u32,
    options: u32,
) -> Result<(), crate::status::NtStatus> {
    use crate::fs::file::rights;
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
        return Err(crate::status::STATUS_INVALID_PARAMETER);
    }
    Ok(())
}

/// The IO_STATUS_BLOCK's Information an open answers with.
const FILE_SUPERSEDED: u32 = 0;
const FILE_OPENED: u32 = 1;
const FILE_CREATED: u32 = 2;
const FILE_OVERWRITTEN: u32 = 3;

/// What the caller asks of a disk file's open.
#[cfg_attr(not(target_arch = "x86"), allow(dead_code))]
struct Request {
    /// The rights as asked (MAXIMUM_ALLOWED among them), and as mapped.
    access: u32,
    granted: u32,
    disposition: u32,
    options: u32,
    attributes: u32,
}

/// What a create's name names on the disk, as the disposition's decision reads it: a directory or
/// a file, whether it is the volume's root, and its FAT attributes.
#[derive(Clone, Copy)]
#[cfg_attr(not(target_arch = "x86"), allow(dead_code))]
struct Existing {
    directory: bool,
    root: bool,
    attributes: u8,
}

/// The decision on an existing entry: the open goes ahead, with its I/O status's Information,
/// whether the file is overwritten once open, and the rights granted (MAXIMUM_ALLOWED leaves a
/// read-only file's write rights out); a directory opened for delete-on-close must be empty
/// still, which the volume answers.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(not(target_arch = "x86"), allow(dead_code))]
struct Opening {
    information: u32,
    overwrite: bool,
    granted: u32,
    must_be_empty: bool,
}

/// The disposition's decision on an existing entry (`trailing`: named with a trailing separator):
/// FILE_CREATE is STATUS_OBJECT_NAME_COLLISION. A directory refuses FILE_NON_DIRECTORY_FILE
/// (STATUS_FILE_IS_A_DIRECTORY), and only opens (FILE_OPEN, FILE_OPEN_IF: STATUS_ACCESS_DENIED
/// otherwise, an assumption, unverified against FastFat's answer), the root never for DELETE (it
/// has no entry: STATUS_ACCESS_DENIED). A file refuses FILE_DIRECTORY_FILE
/// (STATUS_NOT_A_DIRECTORY) and a trailing separator (STATUS_OBJECT_NAME_INVALID); a read-only
/// one refuses write and delete rights and every overwrite (STATUS_ACCESS_DENIED); an overwrite of
/// a hidden or system file must keep the attribute (CreateFile's documented refusal,
/// STATUS_ACCESS_DENIED). An overwrite answers FILE_OVERWRITTEN, a supersede FILE_SUPERSEDED, an
/// open FILE_OPENED.
#[cfg_attr(not(target_arch = "x86"), allow(dead_code))]
fn open_existing(
    entry: Existing,
    trailing: bool,
    request: &Request,
) -> Result<Opening, crate::status::NtStatus> {
    use crate::fs::fat32::dirent::{ATTR_HIDDEN, ATTR_READ_ONLY, ATTR_SYSTEM};
    use crate::fs::file::rights;
    use crate::status::*;
    /// The rights that change a file, which a read-only one refuses.
    const CHANGES: u32 = rights::FILE_WRITE_DATA | rights::FILE_APPEND_DATA | rights::DELETE;
    let mut granted = request.granted;
    if request.disposition == FILE_CREATE {
        return Err(STATUS_OBJECT_NAME_COLLISION);
    }
    if entry.directory {
        if request.options & FILE_NON_DIRECTORY_FILE != 0 {
            return Err(STATUS_FILE_IS_A_DIRECTORY);
        }
        if !matches!(request.disposition, FILE_OPEN | FILE_OPEN_IF) {
            return Err(STATUS_ACCESS_DENIED);
        }
        if entry.root && granted & rights::DELETE != 0 {
            return Err(STATUS_ACCESS_DENIED);
        }
        return Ok(Opening {
            information: FILE_OPENED,
            overwrite: false,
            granted,
            must_be_empty: request.options & FILE_DELETE_ON_CLOSE != 0,
        });
    }
    if request.options & FILE_DIRECTORY_FILE != 0 {
        return Err(STATUS_NOT_A_DIRECTORY);
    }
    if trailing {
        return Err(STATUS_OBJECT_NAME_INVALID);
    }
    let overwrite = matches!(
        request.disposition,
        FILE_SUPERSEDE | FILE_OVERWRITE | FILE_OVERWRITE_IF
    );
    if entry.attributes & ATTR_READ_ONLY != 0 {
        if request.access & rights::MAXIMUM_ALLOWED != 0 {
            granted &= !CHANGES;
        }
        if granted & CHANGES != 0 || overwrite {
            return Err(STATUS_ACCESS_DENIED);
        }
    }
    let opening = |information| Opening {
        information,
        overwrite,
        granted,
        must_be_empty: false,
    };
    if !overwrite {
        return Ok(opening(FILE_OPENED));
    }
    let keeps = |bit: u8| entry.attributes & bit == 0 || request.attributes & u32::from(bit) != 0;
    if !keeps(ATTR_HIDDEN) || !keeps(ATTR_SYSTEM) {
        return Err(STATUS_ACCESS_DENIED);
    }
    Ok(opening(if request.disposition == FILE_SUPERSEDE {
        FILE_SUPERSEDED
    } else {
        FILE_OVERWRITTEN
    }))
}

/// What a create makes for a missing name.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(not(target_arch = "x86"), allow(dead_code))]
enum Making {
    /// A directory (FILE_DIRECTORY_FILE).
    Directory,
    /// A file, with these FAT attributes.
    File(u8),
}

/// The disposition's decision on a missing name (`trailing`: named with a trailing separator):
/// the opening dispositions (FILE_OPEN, FILE_OVERWRITE) are STATUS_OBJECT_NAME_NOT_FOUND; the
/// others make a directory when asked, else a file (STATUS_OBJECT_NAME_INVALID for a file's name
/// with a trailing separator) with the attributes asked for ([`new_attributes`]).
#[cfg_attr(not(target_arch = "x86"), allow(dead_code))]
fn make_missing(trailing: bool, request: &Request) -> Result<Making, crate::status::NtStatus> {
    use crate::status::{STATUS_OBJECT_NAME_INVALID, STATUS_OBJECT_NAME_NOT_FOUND};
    if !matches!(
        request.disposition,
        FILE_CREATE | FILE_OPEN_IF | FILE_OVERWRITE_IF | FILE_SUPERSEDE
    ) {
        return Err(STATUS_OBJECT_NAME_NOT_FOUND);
    }
    if request.options & FILE_DIRECTORY_FILE != 0 {
        return Ok(Making::Directory);
    }
    if trailing {
        return Err(STATUS_OBJECT_NAME_INVALID);
    }
    Ok(Making::File(new_attributes(request.attributes)))
}

/// The FAT attributes a file made or overwritten takes from a create's FileAttributes: the ones a
/// program may set (read-only, hidden, system, archive), and the archive bit.
#[cfg_attr(not(target_arch = "x86"), allow(dead_code))]
fn new_attributes(attributes: u32) -> u8 {
    use crate::fs::io::{ATTRIBUTE_ARCHIVE, SETTABLE_ATTRIBUTES};
    attributes as u8 & SETTABLE_ATTRIBUTES | ATTRIBUTE_ARCHIVE
}

/// The access an open's disposition uses beyond what it asks, which the share check counts too: an
/// overwrite writes the file (FILE_WRITE_DATA), a supersede replaces it (DELETE), as FastFat adds
/// them; an open uses nothing more.
#[cfg_attr(not(target_arch = "x86"), allow(dead_code))]
fn implied_access(overwrite: bool, disposition: u32) -> u32 {
    use crate::fs::file::rights;
    match (overwrite, disposition) {
        (false, _) => 0,
        (true, FILE_SUPERSEDE) => rights::DELETE,
        (true, _) => rights::FILE_WRITE_DATA,
    }
}

/// Where a disk file's write starts, `offset` as [`transfer_offset`] left it: the end of the file
/// (`size`) for FILE_WRITE_TO_END_OF_FILE or a handle with append access alone (`append`), else
/// the offset given, else the object's `position`.
#[cfg_attr(not(target_arch = "x86"), allow(dead_code))]
fn write_start(offset: Option<u64>, append: bool, size: u64, position: u64) -> u64 {
    match offset {
        Some(FILE_WRITE_TO_END_OF_FILE) => size,
        _ if append => size,
        Some(at) => at,
        None => position,
    }
}

/// The rights a read (FILE_READ_DATA) or a write (FILE_WRITE_DATA or FILE_APPEND_DATA) needs of its
/// handle, any of them.
#[cfg_attr(not(target_arch = "x86"), allow(dead_code))]
fn transfer_rights(write: bool) -> u32 {
    use crate::fs::file::rights::{FILE_APPEND_DATA, FILE_READ_DATA, FILE_WRITE_DATA};
    if write {
        FILE_WRITE_DATA | FILE_APPEND_DATA
    } else {
        FILE_READ_DATA
    }
}

/// A disk transfer's own refusal: a directory has no data (FastFat's
/// STATUS_INVALID_DEVICE_REQUEST).
#[cfg_attr(not(target_arch = "x86"), allow(dead_code))]
fn check_data(directory: bool) -> Result<(), crate::status::NtStatus> {
    if directory {
        return Err(crate::status::STATUS_INVALID_DEVICE_REQUEST);
    }
    Ok(())
}

/// How many bytes a disk read of `length` at `start` moves in a file of `size`: none for a
/// zero-length read, anywhere, no lock asked; STATUS_FILE_LOCK_CONFLICT when `may_read` refuses
/// its range (another owner's exclusive lock); STATUS_END_OF_FILE at or past the end; else what
/// remains before the end, at most `length`.
#[cfg_attr(not(target_arch = "x86"), allow(dead_code))]
fn read_count(
    start: u64,
    size: u32,
    length: u32,
    may_read: impl FnOnce((u64, u64)) -> bool,
) -> Result<u32, crate::status::NtStatus> {
    use crate::status::{STATUS_END_OF_FILE, STATUS_FILE_LOCK_CONFLICT};
    if length == 0 {
        return Ok(0);
    }
    if !may_read((start, u64::from(length))) {
        return Err(STATUS_FILE_LOCK_CONFLICT);
    }
    match crate::fs::file::available(start, size, length) {
        0 => Err(STATUS_END_OF_FILE),
        wanted => Ok(wanted),
    }
}

/// How many bytes a disk write of `length` at `start` (see [`write_start`]) moves: none for a
/// zero-length write, no lock asked; STATUS_FILE_LOCK_CONFLICT when `may_write` refuses its range;
/// STATUS_DISK_FULL when it would end past FAT32's largest file (4 GiB less a byte); else all of
/// it.
#[cfg_attr(not(target_arch = "x86"), allow(dead_code))]
fn write_count(
    start: u64,
    length: u32,
    may_write: impl FnOnce((u64, u64)) -> bool,
) -> Result<u32, crate::status::NtStatus> {
    use crate::status::{STATUS_DISK_FULL, STATUS_FILE_LOCK_CONFLICT};
    if length == 0 {
        return Ok(0);
    }
    if !may_write((start, u64::from(length))) {
        return Err(STATUS_FILE_LOCK_CONFLICT);
    }
    if start
        .checked_add(u64::from(length))
        .is_none_or(|end| end > u64::from(u32::MAX))
    {
        return Err(STATUS_DISK_FULL);
    }
    Ok(length)
}

/// A transfer's I/O status: STATUS_SUCCESS and the count moved, or the failure and nothing.
#[cfg_attr(not(target_arch = "x86"), allow(dead_code))]
fn transfer_status(result: Result<u32, crate::status::NtStatus>) -> (crate::status::NtStatus, u32) {
    match result {
        Ok(moved) => (crate::status::STATUS_SUCCESS, moved),
        Err(code) => (code, 0),
    }
}

/// What a rename's target name is relative to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(not(target_arch = "x86"), allow(dead_code))]
enum RenameRoot {
    /// Its root directory's file object (RootDirectory, a handle).
    Directory,
    /// The volume's root: an absolute NT path.
    Absolute,
    /// The file's own directory: a bare name.
    Own,
}

/// A rename's target name, as FILE_RENAME_INFORMATION carries it (FileNameLength bytes after its
/// fixed part, in a buffer of `length` bytes): its length in units, none (STATUS_INVALID_PARAMETER)
/// when it is empty, longer than a name, or past the buffer.
#[cfg_attr(not(target_arch = "x86"), allow(dead_code))]
fn rename_name_length(
    file_name_length: u32,
    length: u32,
) -> Result<usize, crate::status::NtStatus> {
    use rtl::nt::info::{FileRenameInformation, VariableSize};
    const NAME: usize = FileRenameInformation::FIXED_SIZE;
    let name_length = file_name_length as usize / 2;
    if name_length == 0
        || name_length > super::attributes::MAX_NAME
        || NAME + 2 * name_length > length as usize
    {
        return Err(crate::status::STATUS_INVALID_PARAMETER);
    }
    Ok(name_length)
}

/// What a rename's target name (`units`) is relative to: its root directory's when it names one
/// (`root`, a handle), the volume's root for a name with a separator, else the file's own
/// directory.
#[cfg_attr(not(target_arch = "x86"), allow(dead_code))]
fn rename_root(root: u32, units: &[u16]) -> RenameRoot {
    if root != 0 {
        RenameRoot::Directory
    } else if units.contains(&u16::from(b'\\')) {
        RenameRoot::Absolute
    } else {
        RenameRoot::Own
    }
}

/// FileBasicInformation's checks of a disk file (`root`: the volume's root, `directory`: a
/// directory) before anything changes: the root has no entry to stamp (STATUS_ACCESS_DENIED); the
/// directory bit asked for a file is STATUS_INVALID_PARAMETER.
#[cfg_attr(not(target_arch = "x86"), allow(dead_code))]
fn check_basic(
    root: bool,
    directory: bool,
    attributes: u32,
) -> Result<(), crate::status::NtStatus> {
    use crate::fs::fat32::dirent::ATTR_DIRECTORY;
    use crate::status::{STATUS_ACCESS_DENIED, STATUS_INVALID_PARAMETER};
    if root {
        return Err(STATUS_ACCESS_DENIED);
    }
    if attributes & u32::from(ATTR_DIRECTORY) != 0 && !directory {
        return Err(STATUS_INVALID_PARAMETER);
    }
    Ok(())
}

/// The FAT attributes a basic set leaves an entry with (`current`): zero asks nothing (they stay);
/// otherwise the settable ones asked for, in place of the entry's (FILE_ATTRIBUTE_NORMAL alone
/// clears them), the entry's directory bit kept.
#[cfg_attr(not(target_arch = "x86"), allow(dead_code))]
fn basic_attributes(current: u8, asked: u32) -> u8 {
    use crate::fs::fat32::dirent::ATTR_DIRECTORY;
    use crate::fs::io::SETTABLE_ATTRIBUTES;
    if asked == 0 {
        return current;
    }
    current & ATTR_DIRECTORY | asked as u8 & SETTABLE_ATTRIBUTES
}

/// FileDispositionInformation's delete of a disk file: the root, a read-only file and a mapped one
/// are STATUS_CANNOT_DELETE (a directory's entries, which the volume answers, come after).
#[cfg_attr(not(target_arch = "x86"), allow(dead_code))]
fn check_delete(root: bool, read_only: bool, mapped: bool) -> Result<(), crate::status::NtStatus> {
    if root || read_only || mapped {
        return Err(crate::status::STATUS_CANNOT_DELETE);
    }
    Ok(())
}

/// FilePositionInformation's offset, any device's: a negative one is STATUS_INVALID_PARAMETER.
#[cfg_attr(not(target_arch = "x86"), allow(dead_code))]
fn new_position(offset: u64) -> Result<u64, crate::status::NtStatus> {
    if (offset as i64) < 0 {
        return Err(crate::status::STATUS_INVALID_PARAMETER);
    }
    Ok(offset)
}

/// A size change of a disk file of `size` bytes (FileEndOfFileInformation, or
/// FileAllocationInformation: `allocation_only`) to `asked`: the size to set, none when nothing
/// changes (an allocation at or past the size: F2K allocates as it writes). A directory has none to
/// change (STATUS_INVALID_HANDLE, an assumption, unverified); past FAT32's 4 GiB is
/// STATUS_DISK_FULL; a mapped file is not cut (STATUS_USER_MAPPED_FILE), though it grows.
#[cfg_attr(not(target_arch = "x86"), allow(dead_code))]
fn resize_to(
    directory: bool,
    size: u32,
    mapped: bool,
    asked: u64,
    allocation_only: bool,
) -> Result<Option<u32>, crate::status::NtStatus> {
    use crate::status::{STATUS_DISK_FULL, STATUS_INVALID_HANDLE, STATUS_USER_MAPPED_FILE};
    if directory {
        return Err(STATUS_INVALID_HANDLE);
    }
    let asked = u32::try_from(asked).map_err(|_| STATUS_DISK_FULL)?;
    if allocation_only && asked >= size {
        return Ok(None);
    }
    if mapped && asked < size {
        return Err(STATUS_USER_MAPPED_FILE);
    }
    Ok(Some(asked))
}

/// A rename's checks of the file it moves (`root`, `directory`) and its target name (`trailing`: a
/// trailing separator): the root has no entry to move (STATUS_ACCESS_DENIED); a file's new name
/// takes no trailing separator (STATUS_OBJECT_NAME_INVALID).
#[cfg_attr(not(target_arch = "x86"), allow(dead_code))]
fn check_rename(
    root: bool,
    directory: bool,
    trailing: bool,
) -> Result<(), crate::status::NtStatus> {
    use crate::status::{STATUS_ACCESS_DENIED, STATUS_OBJECT_NAME_INVALID};
    if root {
        return Err(STATUS_ACCESS_DENIED);
    }
    if trailing && !directory {
        return Err(STATUS_OBJECT_NAME_INVALID);
    }
    Ok(())
}

/// A rename onto a name taken by `existing`: replaced only when asked (`replace`) and only a file
/// that is not read-only, nor a directory, nor the renamed file itself (`same`: a case-only
/// rename) — STATUS_OBJECT_NAME_COLLISION otherwise (the fswrite capture's MoveFileEx answers
/// ERROR_ALREADY_EXISTS for each); and only one no one holds open (`open`: STATUS_ACCESS_DENIED).
#[cfg_attr(not(target_arch = "x86"), allow(dead_code))]
fn rename_over(
    replace: bool,
    same: bool,
    existing: Existing,
    open: bool,
) -> Result<(), crate::status::NtStatus> {
    use crate::fs::fat32::dirent::ATTR_READ_ONLY;
    use crate::status::{STATUS_ACCESS_DENIED, STATUS_OBJECT_NAME_COLLISION};
    if !replace || same || existing.directory || existing.attributes & ATTR_READ_ONLY != 0 {
        return Err(STATUS_OBJECT_NAME_COLLISION);
    }
    if open {
        return Err(STATUS_ACCESS_DENIED);
    }
    Ok(())
}

/// The right a byte-range lock or unlock needs of its handle: read or write data
/// (STATUS_ACCESS_DENIED for neither).
#[cfg_attr(not(target_arch = "x86"), allow(dead_code))]
fn check_lock_access(granted: u32) -> Result<(), crate::status::NtStatus> {
    use crate::fs::file::rights::{FILE_READ_DATA, FILE_WRITE_DATA};
    if granted & (FILE_READ_DATA | FILE_WRITE_DATA) == 0 {
        return Err(crate::status::STATUS_ACCESS_DENIED);
    }
    Ok(())
}

/// The disk file a lock call's object opens, by what it is open on (`disk`: none for another
/// device than the disk, else its file and whether that is a directory): only a disk file's open
/// takes locks (FastFat's STATUS_INVALID_PARAMETER for a directory's; STATUS_INVALID_DEVICE_REQUEST
/// for a device without lock control).
#[cfg_attr(not(target_arch = "x86"), allow(dead_code))]
fn lockable<F>(disk: Option<(F, bool)>) -> Result<F, crate::status::NtStatus> {
    use crate::status::{STATUS_INVALID_DEVICE_REQUEST, STATUS_INVALID_PARAMETER};
    match disk {
        None => Err(STATUS_INVALID_DEVICE_REQUEST),
        Some((_, true)) => Err(STATUS_INVALID_PARAMETER),
        Some((file, false)) => Ok(file),
    }
}

/// NtLockFile's answer to the lock table's: STATUS_SUCCESS for a lock taken,
/// STATUS_LOCK_NOT_GRANTED for a conflict under FailImmediately, STATUS_INSUFFICIENT_RESOURCES for
/// a full table; none for a conflict the caller would wait out (not supported).
#[cfg_attr(not(target_arch = "x86"), allow(dead_code))]
fn lock_answer(
    taken: Result<(), crate::fs::file::LockError>,
    fail_immediately: bool,
) -> Option<Result<crate::status::NtStatus, crate::status::NtStatus>> {
    use crate::fs::file::LockError;
    use crate::status::*;
    match taken {
        Ok(()) => Some(Ok(STATUS_SUCCESS)),
        Err(LockError::Conflict) if fail_immediately => Some(Err(STATUS_LOCK_NOT_GRANTED)),
        Err(LockError::Conflict) => None,
        Err(LockError::Full) => Some(Err(STATUS_INSUFFICIENT_RESOURCES)),
    }
}

/// NtUnlockFile's answer: STATUS_SUCCESS when the owner held the lock named (`found`),
/// STATUS_RANGE_NOT_LOCKED otherwise.
#[cfg_attr(not(target_arch = "x86"), allow(dead_code))]
fn unlock_answer(found: bool) -> Result<crate::status::NtStatus, crate::status::NtStatus> {
    if found {
        Ok(crate::status::STATUS_SUCCESS)
    } else {
        Err(crate::status::STATUS_RANGE_NOT_LOCKED)
    }
}

/// A listing query's search, `held` the object's: the one the first query made, back to the
/// directory's start under RestartScan (`restart`; its expression kept, the query's name not
/// consulted), or, for the first query, the one `make` makes of its name (RestartScan then changes
/// nothing). The search as the query starts it.
#[cfg_attr(not(target_arch = "x86"), allow(dead_code))]
fn resume_search(
    held: &mut Option<crate::fs::search::Search>,
    restart: bool,
    make: impl FnOnce() -> Result<crate::fs::search::Search, crate::status::NtStatus>,
) -> Result<crate::fs::search::Search, crate::status::NtStatus> {
    match held {
        Some(search) => {
            if restart {
                search.restart();
            }
            Ok(*search)
        }
        None => Ok(*held.insert(make()?)),
    }
}

/// The units of a listing query's FileName (a UNICODE_STRING of `length` bytes, an odd one rounded
/// down): STATUS_OBJECT_NAME_INVALID past the longest expression a search keeps.
#[cfg_attr(not(target_arch = "x86"), allow(dead_code))]
fn expression_length(length: u16) -> Result<usize, crate::status::NtStatus> {
    let count = usize::from(length) / 2;
    if count > crate::fs::search::MAX_EXPRESSION {
        return Err(crate::status::STATUS_OBJECT_NAME_INVALID);
    }
    Ok(count)
}

/// The create options a server's create takes (FILE_VALID_PIPE_OPTION_FLAGS, wdm.h): the
/// synchronous modes and write-through.
const FILE_VALID_PIPE_OPTION_FLAGS: u32 = 0x32;

/// The share bits: FILE_SHARE_READ and FILE_SHARE_WRITE make a pipe's configuration;
/// FILE_SHARE_DELETE no pipe takes.
const FILE_SHARE_READ_WRITE: u32 = 3;
const FILE_SHARE_DELETE: u32 = 4;

/// The pipe types, read modes and completion modes (ntifs.h's FILE_PIPE_*): byte streams that wait
/// are served, messages and non-blocking calls are the stub path.
const FILE_PIPE_BYTE_STREAM: u32 = 0;
const FILE_PIPE_MESSAGE: u32 = 1;
const FILE_PIPE_QUEUE_OPERATION: u32 = 0;
const FILE_PIPE_COMPLETE_OPERATION: u32 = 1;

/// NtCreateNamedPipeFile's checks, before its name: each STATUS_INVALID_PARAMETER — a pipe type,
/// read mode or completion mode (`modes`) past the defined ones, FILE_SHARE_DELETE or no share at
/// all, a disposition other than FILE_CREATE, FILE_OPEN or FILE_OPEN_IF, an option past
/// FILE_VALID_PIPE_OPTION_FLAGS, both synchronous modes or one without SYNCHRONIZE, no instance
/// allowed, a byte stream read as messages; then a message pipe or a non-blocking one, not served
/// (STATUS_NOT_IMPLEMENTED).
#[cfg_attr(not(target_arch = "x86"), allow(dead_code))]
fn check_pipe_arguments(
    access: u32,
    share: u32,
    disposition: u32,
    options: u32,
    (pipe_type, read_mode, completion_mode): (u32, u32, u32),
    max_instances: u32,
) -> Result<(), crate::status::NtStatus> {
    use crate::fs::file::rights;
    use crate::status::{STATUS_INVALID_PARAMETER, STATUS_NOT_IMPLEMENTED};
    let both = FILE_SYNCHRONOUS_IO_ALERT | FILE_SYNCHRONOUS_IO_NONALERT;
    let invalid = pipe_type > FILE_PIPE_MESSAGE
        || read_mode > FILE_PIPE_MESSAGE
        || completion_mode > FILE_PIPE_COMPLETE_OPERATION
        || share & !FILE_SHARE_READ_WRITE != 0
        || share == 0
        || !matches!(disposition, FILE_CREATE | FILE_OPEN | FILE_OPEN_IF)
        || options & !FILE_VALID_PIPE_OPTION_FLAGS != 0
        || options & both == both
        || (options & both != 0 && access & rights::SYNCHRONIZE == 0)
        || max_instances == 0
        || (pipe_type == FILE_PIPE_BYTE_STREAM && read_mode == FILE_PIPE_MESSAGE);
    if invalid {
        return Err(STATUS_INVALID_PARAMETER);
    }
    if pipe_type != FILE_PIPE_BYTE_STREAM || completion_mode != FILE_PIPE_QUEUE_OPERATION {
        return Err(STATUS_NOT_IMPLEMENTED);
    }
    Ok(())
}

/// A create or open of a pipe's name (its client end): only an open's dispositions (FILE_OPEN,
/// FILE_OPEN_IF) are served (STATUS_NOT_IMPLEMENTED); a directory asked for is
/// STATUS_NOT_A_DIRECTORY.
#[cfg_attr(not(target_arch = "x86"), allow(dead_code))]
fn check_client(disposition: u32, options: u32) -> Result<(), crate::status::NtStatus> {
    use crate::status::{STATUS_NOT_A_DIRECTORY, STATUS_NOT_IMPLEMENTED};
    if !matches!(disposition, FILE_OPEN | FILE_OPEN_IF) {
        return Err(STATUS_NOT_IMPLEMENTED);
    }
    if options & FILE_DIRECTORY_FILE != 0 {
        return Err(STATUS_NOT_A_DIRECTORY);
    }
    Ok(())
}

/// A control code's required access (its bits 14 and 15, NtFsControlFile's and
/// NtDeviceIoControlFile's): FILE_READ_ACCESS asks FILE_READ_DATA of the handle, FILE_WRITE_ACCESS
/// FILE_WRITE_DATA.
#[cfg_attr(not(target_arch = "x86"), allow(dead_code))]
fn control_rights(code: u32) -> u32 {
    use crate::fs::file::rights;
    let mut needs = 0;
    if code & 0x4000 != 0 {
        needs |= rights::FILE_READ_DATA;
    }
    if code & 0x8000 != 0 {
        needs |= rights::FILE_WRITE_DATA;
    }
    needs
}

/// Whether `granted` holds every right of `needs`; STATUS_ACCESS_DENIED otherwise.
#[cfg_attr(not(target_arch = "x86"), allow(dead_code))]
fn check_all(granted: u32, needs: u32) -> Result<(), crate::status::NtStatus> {
    if granted & needs != needs {
        return Err(crate::status::STATUS_ACCESS_DENIED);
    }
    Ok(())
}

/// METHOD_BUFFERED, a control code's transfer type (its low two bits): the one F2K serves.
#[cfg_attr(not(target_arch = "x86"), allow(dead_code))]
const METHOD_BUFFERED: u32 = 0;

/// A METHOD_BUFFERED device control's lengths, a null buffer's none whatever its length says: the
/// input's and the output's, and the system buffer's (the larger, none for no buffer at all).
#[cfg_attr(not(target_arch = "x86"), allow(dead_code))]
fn buffered_lengths(input: Option<u32>, output: Option<u32>) -> (u32, u32, usize) {
    let input = input.unwrap_or(0);
    let output = output.unwrap_or(0);
    (input, output, input.max(output) as usize)
}

/// The bytes a device's answer copies back into a caller's buffer of `length` bytes: none for an
/// error status (a warning's or a success's are copied), else as many as its Information says, at
/// most the buffer's length.
#[cfg_attr(not(target_arch = "x86"), allow(dead_code))]
fn copied_back(status: crate::status::NtStatus, information: u32, length: u32) -> Option<u32> {
    if crate::dev::io::nt_error(status) {
        return None;
    }
    Some(information.min(length))
}

/// The services' shared pieces on the target: a handle's file object, the start of a name, the
/// walk, and the completion.
#[cfg(target_arch = "x86")]
mod common {
    use rtl::nt::IoStatusBlock;

    use super::super::attributes::{self, Root};
    use super::super::call::{UserAddr, UserPtr};
    use super::name::{self, Absolute, FileName};
    use crate::fs::fat32::lookup::{find, root, File, LookupError};
    use crate::fs::fat32::volume::Volume;
    use crate::fs::file::{with_records, FileObject};
    use crate::fs::pipes::PipeName;
    use crate::ob::{ObjectType, Referenced};
    use crate::status::*;

    /// A file object as a handle names it: the object, referenced, and the access the handle was
    /// granted. The handle's access is what the services check, as Windows 2000's do (their
    /// ObReferenceObjectByHandle hands them the handle's GrantedAccess): a duplicate made with
    /// less access than its source's open reaches the same object with less. `granted` shadows
    /// the object's own (the open's), which the value otherwise reads as.
    pub struct FileHandle {
        object: Referenced<FileObject>,
        /// The handle's access, the file rights the generic ones map to.
        pub granted: u32,
    }

    impl core::ops::Deref for FileHandle {
        type Target = Referenced<FileObject>;

        fn deref(&self) -> &Referenced<FileObject> {
            &self.object
        }
    }

    /// The file object `handle` names in the calling process, referenced, with the handle's access:
    /// STATUS_INVALID_HANDLE for a handle naming nothing (a console handle included),
    /// STATUS_OBJECT_TYPE_MISMATCH for another kind of object.
    pub fn file_object(handle: u32) -> Result<FileHandle, NtStatus> {
        let mut granted = 0;
        let reference = super::super::sync::object_granting(handle, ObjectType::File, |access| {
            granted = ObjectType::File.granted(access);
            true
        })?;
        Ok(FileHandle {
            object: crate::ob::file_object(reference),
            granted,
        })
    }

    /// Whether a handle was granted any of `rights`; STATUS_ACCESS_DENIED otherwise. None asks
    /// for nothing.
    pub fn check_access(object: &FileHandle, rights: u32) -> Result<(), NtStatus> {
        if rights != 0 && object.granted & rights == 0 {
            return Err(STATUS_ACCESS_DENIED);
        }
        Ok(())
    }

    /// Write an IO_STATUS_BLOCK: the status and the information (a fault there is the caller's,
    /// past the call's own work: not reported).
    pub fn complete(io_status: UserAddr, status: NtStatus, information: u32) {
        let _ = io_status.cast::<IoStatusBlock<u32>>().write(IoStatusBlock {
            status: status.0,
            information,
        });
    }

    /// The new handle into the caller's slot; a slot that faults takes the handle back
    /// (STATUS_ACCESS_VIOLATION).
    pub fn deliver(slot: UserPtr<u32>, handle: u32) -> Result<(), NtStatus> {
        if slot.write(handle).is_err() {
            crate::user::args::calling_process().close_handle(handle);
            return Err(STATUS_ACCESS_VIOLATION);
        }
        Ok(())
    }

    /// What an OBJECT_ATTRIBUTES names on the boot volume for the file services: the name, the
    /// directory it starts at (none: the volume's root), and whether a handle made for it is
    /// inheritable.
    pub struct Target {
        pub name: FileName,
        pub start: Option<File>,
        pub inherit: bool,
    }

    /// What an OBJECT_ATTRIBUTES names, by the device the name is on: a path on the boot volume, or
    /// a pipe (and whether a handle made for it is inheritable).
    // Made once per call and matched at once, never kept: the variants' sizes do not matter.
    #[allow(clippy::large_enum_variant)]
    pub enum Named {
        Disk(Target),
        Pipe {
            name: PipeName,
            inherit: bool,
        },
        /// The null device (whether a handle made for it is inheritable).
        Null {
            inherit: bool,
        },
        /// A device a loaded driver made, referenced for the open, and the rest of the name after
        /// its own (see [`crate::dev::io`]).
        Device {
            device: crate::dev::io::Referenced,
            inherit: bool,
        },
    }

    /// Read the OBJECT_ATTRIBUTES at `attributes` for a file service (see [`named`]), for a
    /// service that serves the boot volume's names alone: a pipe's name, or the null device's, is
    /// not served yet (STATUS_NOT_IMPLEMENTED).
    pub fn target(attributes: UserAddr) -> Result<Target, NtStatus> {
        match named(attributes)? {
            Named::Disk(target) => Ok(target),
            Named::Pipe { .. } | Named::Null { .. } | Named::Device { .. } => {
                Err(STATUS_NOT_IMPLEMENTED)
            }
        }
    }

    /// Read the OBJECT_ATTRIBUTES at `attributes` for a file service: an absolute name (a path on
    /// the boot volume, or a pipe's: see [`name::absolute`]), or one relative to a directory's file
    /// object (ntdll names files under the current directory against its handle).
    /// STATUS_OBJECT_NAME_INVALID without a name; a root that is no file object is
    /// STATUS_OBJECT_TYPE_MISMATCH, a file's (not a directory's, or another device's than the
    /// disk) STATUS_INVALID_PARAMETER.
    pub fn named(attributes: UserAddr) -> Result<Named, NtStatus> {
        if attributes.is_null() {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let mut name = attributes::Name::new();
        let read = attributes::read(attributes, &mut name)?;
        let units = read.units();
        let (name, start) = match attributes::root_of(read.root)? {
            Root::None if units.is_empty() => return Err(STATUS_OBJECT_NAME_INVALID),
            Root::None if name::null_device(units) => return null(read.inherit()),
            Root::None if is_device(units) => return device(units, read.inherit()),
            Root::None => match name::absolute(units)? {
                Absolute::Disk(name) => (name, None),
                Absolute::Pipe(name) => {
                    return Ok(Named::Pipe {
                        name,
                        inherit: read.inherit(),
                    });
                }
            },
            Root::File(id) => {
                let reference = crate::ob::reference(id).ok_or(STATUS_INVALID_HANDLE)?;
                let object = crate::ob::file_object(reference);
                // A name starts only at a disk directory: another device's object is refused as
                // a file is.
                let record = object.disk().ok_or(STATUS_INVALID_PARAMETER)?;
                let directory = crate::fs::io::file_at(record);
                if !directory.directory {
                    return Err(STATUS_INVALID_PARAMETER);
                }
                (name::relative(units)?, Some(directory))
            }
            Root::NamedObjects | Root::Other => return Err(STATUS_OBJECT_TYPE_MISMATCH),
        };
        Ok(Named::Disk(Target {
            name,
            start,
            inherit: read.inherit(),
        }))
    }

    /// Whether a name is one of the I/O manager's (a loaded driver's device, or a link to one), not
    /// the file systems'.
    fn is_device(units: &[u16]) -> bool {
        crate::dev::io::is_device_name(units)
    }

    /// A device's answer: the device referenced for the open (see [`Named::Device`]).
    #[inline(never)]
    fn device(units: &[u16], inherit: bool) -> Result<Named, NtStatus> {
        match crate::dev::io::reference_device(units) {
            Some(Ok(device)) => Ok(Named::Device { device, inherit }),
            Some(Err(status)) => Err(status),
            None => Err(STATUS_OBJECT_NAME_NOT_FOUND),
        }
    }

    /// The null device's answer, made here so that [`named`]'s frame keeps no slot for it.
    #[inline(never)]
    fn null(inherit: bool) -> Result<Named, NtStatus> {
        Ok(Named::Null { inherit })
    }

    /// What a walk found: the entry the name names, or the directory its last component would be
    /// made in.
    pub enum Found {
        Existing(File),
        Missing { parent: File },
    }

    /// A lookup's failure, as its status.
    fn lookup_status(error: LookupError) -> NtStatus {
        match error {
            LookupError::Corrupt => STATUS_FILE_CORRUPT_ERROR,
            LookupError::Device(status) => status,
            LookupError::Invalid => STATUS_OBJECT_NAME_INVALID,
            LookupError::NotFound | LookupError::NotADirectory => STATUS_OBJECT_PATH_NOT_FOUND,
        }
    }

    /// Walk `name` from `start` (none: the volume's root) on a volume the caller holds: a directory
    /// on the way that is missing, or a file, is STATUS_OBJECT_PATH_NOT_FOUND. An open file's entry
    /// is its record's (the current copy).
    pub fn walk(
        volume: &mut Volume,
        start: Option<File>,
        name: &FileName,
    ) -> Result<Found, NtStatus> {
        let mut directory = start.unwrap_or_else(|| root(volume));
        let mut components = name.components().peekable();
        while let Some(component) = components.next() {
            if !directory.directory {
                return Err(STATUS_OBJECT_PATH_NOT_FOUND);
            }
            let listed = find(volume, directory.first_cluster, component).map_err(lookup_status)?;
            let last = components.peek().is_none();
            match listed {
                Some(listed) => directory = File::of(&listed, directory.first_cluster),
                None if last => return Ok(Found::Missing { parent: directory }),
                None => return Err(STATUS_OBJECT_PATH_NOT_FOUND),
            }
        }
        let current = with_records(|records| records.current(directory));
        Ok(Found::Existing(current))
    }

    /// The boot volume's cluster size in bytes (a file's allocation unit).
    pub fn cluster_bytes() -> u32 {
        crate::fs::fat32::volume::with_boot_volume(|volume| {
            volume.layout().sectors_per_cluster * 512
        })
        .unwrap_or(512)
    }

    /// The event a read, write or listing signals once it completes, reset now; none for a null
    /// handle. STATUS_INVALID_HANDLE or STATUS_OBJECT_TYPE_MISMATCH for a handle naming no event,
    /// STATUS_ACCESS_DENIED for one not granted EVENT_MODIFY_STATE (Windows 2000's I/O manager
    /// references the event for it).
    pub fn completion_event(handle: u32) -> Result<Option<crate::ob::ObRef>, NtStatus> {
        if handle == 0 {
            return Ok(None);
        }
        let event = super::super::sync::object_needing(
            handle,
            ObjectType::Event,
            crate::ob::access::EVENT_MODIFY_STATE,
        )?;
        let body = event.event();
        crate::level::raised::<crate::level::Dispatch, _>(|dispatch| {
            crate::sched::DISPATCHER.get(dispatch).reset_event(body)
        });
        Ok(Some(event))
    }

    /// A request a driver's device would answer through an IRP F2K does not send yet: the stub
    /// path (logged; STATUS_NOT_IMPLEMENTED).
    pub fn device_request(service: &str) -> NtStatus {
        crate::dbgprint::unhandled(
            "ntdll",
            service,
            format_args!("FileHandle=<a driver's device>"),
            format_args!("the request's IRP to a loaded driver is not yet implemented"),
        );
        STATUS_NOT_IMPLEMENTED
    }

    /// The whole of the boot volume's file `units` names (an absolute NT path), read into a pool
    /// block: a driver's image, for NtLoadDriver. The open's statuses (a missing file is
    /// STATUS_OBJECT_NAME_NOT_FOUND), STATUS_FILE_IS_A_DIRECTORY for a directory,
    /// STATUS_INSUFFICIENT_RESOURCES when the pool has no room for it.
    pub fn read_whole_file(units: &[u16]) -> Result<crate::mem::pool::Block, NtStatus> {
        let name = match name::absolute(units)? {
            Absolute::Disk(name) => name,
            Absolute::Pipe(_) => return Err(STATUS_OBJECT_NAME_NOT_FOUND),
        };
        let file = crate::fs::io::with_volume(|volume| match walk(volume, None, &name)? {
            Found::Existing(file) => Ok(file),
            Found::Missing { .. } => Err(STATUS_OBJECT_NAME_NOT_FOUND),
        })?;
        if file.directory {
            return Err(STATUS_FILE_IS_A_DIRECTORY);
        }
        let mut block =
            crate::mem::pool::allocate(file.size as usize).ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        let bytes = &mut block.as_mut()[..file.size as usize];
        crate::fs::io::read_file_at(&file, 0, bytes).ok_or(STATUS_IO_DEVICE_ERROR)?;
        Ok(block)
    }

    /// Signal a completion's event.
    pub fn signal(event: Option<crate::ob::ObRef>) {
        if let Some(event) = event {
            let body = event.event();
            crate::level::raised::<crate::level::Dispatch, _>(|dispatch| {
                crate::sched::DISPATCHER.get(dispatch).set_event(body, 0)
            });
        }
    }
}

/// The host builds' file services: the table names them, the volume and the objects they act on are
/// the target's (the host tests exercise their pure parts: [`name`], [`info`]).
#[cfg(not(target_arch = "x86"))]
mod host {
    use super::super::call::{Handle, NtCall, NtResult, UserAddr, UserPtr};

    unserved! {
        create_file(UserPtr<u32>, u32, UserAddr, UserAddr, UserPtr<u64>, u32, u32, u32, u32, UserAddr, u32);
        open_file(UserPtr<u32>, u32, UserAddr, UserAddr, u32, u32);
        read_file(Handle, Handle, UserAddr, UserAddr, UserAddr, UserAddr, u32, UserPtr<u64>, UserPtr<u32>);
        write_file(Handle, Handle, UserAddr, UserAddr, UserAddr, UserAddr, u32, UserPtr<u64>, UserPtr<u32>);
        flush_buffers_file(Handle, UserAddr);
        lock_file(Handle, Handle, UserAddr, UserAddr, UserAddr, UserPtr<u64>, UserPtr<u64>, u32, bool, bool);
        unlock_file(Handle, UserAddr, UserPtr<u64>, UserPtr<u64>, u32);
        query_information_file(Handle, UserAddr, UserAddr, u32, u32);
        set_information_file(Handle, UserAddr, UserAddr, u32, u32);
        query_directory_file(Handle, Handle, UserAddr, UserAddr, UserAddr, UserAddr, u32, u32, bool, UserAddr, bool);
        query_attributes_file(UserAddr, UserAddr);
        query_full_attributes_file(UserAddr, UserAddr);
        query_volume_information_file(Handle, UserAddr, UserAddr, u32, u32);
        create_named_pipe_file(UserPtr<u32>, u32, UserAddr, UserAddr, u32, u32, u32, u32, u32, u32, u32, u32, u32, UserPtr<u64>);
        fs_control_file(Handle, Handle, UserAddr, UserAddr, UserAddr, u32, UserAddr, u32, UserAddr, u32);
        device_io_control_file(Handle, Handle, UserAddr, UserAddr, UserAddr, u32, UserAddr, u32, UserAddr, u32);
    }
}

#[cfg(not(target_arch = "x86"))]
pub use host::*;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::status::STATUS_INVALID_PARAMETER;

    /// ByteOffset as the I/O manager takes it: the position for none or -2 on a synchronous
    /// object only; -1 a write's end of file, refused for a read; any other negative offset
    /// refused (one near 2^64 used to overflow the write's end and panic); the largest positive
    /// one kept.
    #[test]
    fn a_transfer_offset_is_never_negative() {
        assert_eq!(transfer_offset(None, true, false), Ok(None));
        assert_eq!(
            transfer_offset(None, false, false),
            Err(STATUS_INVALID_PARAMETER)
        );
        let position = Some(FILE_USE_FILE_POINTER_POSITION);
        assert_eq!(transfer_offset(position, true, true), Ok(None));
        assert_eq!(
            transfer_offset(position, false, true),
            Err(STATUS_INVALID_PARAMETER)
        );
        let end = Some(FILE_WRITE_TO_END_OF_FILE);
        assert_eq!(transfer_offset(end, false, true), Ok(end));
        assert_eq!(
            transfer_offset(end, true, false),
            Err(STATUS_INVALID_PARAMETER)
        );
        for wild in [0xFFFF_FFFF_FFFF_FFF0, 1 << 63, 0x8000_0000_0000_1000] {
            assert_eq!(
                transfer_offset(Some(wild), true, true),
                Err(STATUS_INVALID_PARAMETER)
            );
            assert_eq!(
                transfer_offset(Some(wild), true, false),
                Err(STATUS_INVALID_PARAMETER)
            );
        }
        let last = Some(i64::MAX as u64);
        assert_eq!(transfer_offset(last, false, true), Ok(last));
        assert!(i64::MAX as u64 + u64::from(u32::MAX) > i64::MAX as u64);
        assert_eq!(transfer_offset(Some(0), false, false), Ok(Some(0)));
    }

    /// IoCreateFile's checks: each undefined disposition, option, attribute or share bit, and each
    /// inconsistent pair, is STATUS_INVALID_PARAMETER; a plain open, a synchronous open with
    /// SYNCHRONIZE, a delete-on-close with DELETE and a directory made or opened pass.
    #[test]
    fn a_create_s_arguments_are_checked_before_its_name() {
        use crate::fs::file::rights::{DELETE, FILE_READ_DATA, SYNCHRONIZE};
        let check = |access, attributes, share, disposition, options| {
            check_arguments(access, attributes, share, disposition, options)
        };
        let read = FILE_READ_DATA;
        let ok = Ok(());
        let invalid = Err(STATUS_INVALID_PARAMETER);

        for disposition in FILE_SUPERSEDE..=FILE_OVERWRITE_IF {
            assert_eq!(check(read, 0, 0, disposition, 0), ok);
        }
        assert_eq!(check(read, 0, 0, FILE_OVERWRITE_IF + 1, 0), invalid);
        assert_eq!(check(read, 0, 0, FILE_OPEN, 0x0100_0000), invalid);
        assert_eq!(
            check(read | DELETE, 0x7FB7, 0x7, FILE_OPEN, 0x00FF_FF8F),
            ok
        );
        assert_eq!(check(read, 0x0008, 0, FILE_OPEN, 0), invalid);
        assert_eq!(check(read, 0, 0x8, FILE_OPEN, 0), invalid);

        let both = FILE_SYNCHRONOUS_IO_ALERT | FILE_SYNCHRONOUS_IO_NONALERT;
        assert_eq!(check(read | SYNCHRONIZE, 0, 0, FILE_OPEN, both), invalid);
        for mode in [FILE_SYNCHRONOUS_IO_ALERT, FILE_SYNCHRONOUS_IO_NONALERT] {
            assert_eq!(check(read, 0, 0, FILE_OPEN, mode), invalid);
            assert_eq!(check(read | SYNCHRONIZE, 0, 0, FILE_OPEN, mode), ok);
        }

        assert_eq!(check(read, 0, 0, FILE_OPEN, FILE_DELETE_ON_CLOSE), invalid);
        assert_eq!(check(DELETE, 0, 0, FILE_OPEN, FILE_DELETE_ON_CLOSE), ok);

        let directory = FILE_DIRECTORY_FILE;
        for disposition in [FILE_CREATE, FILE_OPEN, FILE_OPEN_IF] {
            assert_eq!(check(read, 0, 0, disposition, directory), ok);
        }
        for disposition in [FILE_SUPERSEDE, FILE_OVERWRITE, FILE_OVERWRITE_IF] {
            assert_eq!(check(read, 0, 0, disposition, directory), invalid);
        }
        let neither = FILE_DIRECTORY_FILE | FILE_NON_DIRECTORY_FILE;
        assert_eq!(check(read, 0, 0, FILE_OPEN, neither), invalid);
        assert_eq!(
            check(read, 0, 0, FILE_OVERWRITE, FILE_NON_DIRECTORY_FILE),
            ok
        );
    }

    /// A create's request of `disposition` with `options`, asking `access` (mapped).
    fn request(access: u32, disposition: u32, options: u32, attributes: u32) -> Request {
        Request {
            access,
            granted: crate::fs::file::rights::mapped(access),
            disposition,
            options,
            attributes,
        }
    }

    /// The dispositions against what the name names: each answers a plain file, a directory and a
    /// missing name as the platform's table has it, with the Information FILE_SUPERSEDED,
    /// FILE_OPENED, FILE_OVERWRITTEN or (made) FILE_CREATED.
    #[test]
    fn the_dispositions_against_what_the_name_names() {
        use crate::fs::file::rights::{FILE_READ_DATA, FILE_WRITE_DATA};
        use crate::status::*;
        let access = FILE_READ_DATA | FILE_WRITE_DATA;
        let file = Existing {
            directory: false,
            root: false,
            attributes: 0x20,
        };
        let directory = Existing {
            directory: true,
            root: false,
            attributes: 0x10,
        };
        let opened = |information, overwrite| {
            Ok(Opening {
                information,
                overwrite,
                granted: access,
                must_be_empty: false,
            })
        };
        let made = Ok(Making::File(0x20));
        let table = [
            (
                FILE_SUPERSEDE,
                opened(FILE_SUPERSEDED, true),
                Err(STATUS_ACCESS_DENIED),
                made,
            ),
            (
                FILE_OPEN,
                opened(FILE_OPENED, false),
                opened(FILE_OPENED, false),
                Err(STATUS_OBJECT_NAME_NOT_FOUND),
            ),
            (
                FILE_CREATE,
                Err(STATUS_OBJECT_NAME_COLLISION),
                Err(STATUS_OBJECT_NAME_COLLISION),
                made,
            ),
            (
                FILE_OPEN_IF,
                opened(FILE_OPENED, false),
                opened(FILE_OPENED, false),
                made,
            ),
            (
                FILE_OVERWRITE,
                opened(FILE_OVERWRITTEN, true),
                Err(STATUS_ACCESS_DENIED),
                Err(STATUS_OBJECT_NAME_NOT_FOUND),
            ),
            (
                FILE_OVERWRITE_IF,
                opened(FILE_OVERWRITTEN, true),
                Err(STATUS_ACCESS_DENIED),
                made,
            ),
        ];
        for (disposition, on_file, on_directory, on_missing) in table {
            let asked = request(access, disposition, 0, 0);
            assert_eq!(open_existing(file, false, &asked), on_file, "{disposition}");
            assert_eq!(
                open_existing(directory, false, &asked),
                on_directory,
                "{disposition}"
            );
            assert_eq!(make_missing(false, &asked), on_missing, "{disposition}");
        }
        assert_eq!(FILE_SUPERSEDED, 0);
        assert_eq!(
            (FILE_OPENED, FILE_CREATED, FILE_OVERWRITTEN),
            (1, 2, 3),
            "ntifs.h's numbers"
        );
    }

    /// FILE_DIRECTORY_FILE and FILE_NON_DIRECTORY_FILE against what the name names, a trailing
    /// separator (a directory's alone), the root's delete, and a directory's delete-on-close,
    /// which the volume checks for entries.
    #[test]
    fn a_create_asks_a_directory_or_a_file() {
        use crate::fs::file::rights::{DELETE, FILE_READ_DATA};
        use crate::status::*;
        let file = Existing {
            directory: false,
            root: false,
            attributes: 0,
        };
        let directory = Existing {
            directory: true,
            ..file
        };
        let root = Existing {
            root: true,
            ..directory
        };
        let read = FILE_READ_DATA;

        let asked = request(read, FILE_OPEN, FILE_DIRECTORY_FILE, 0);
        assert_eq!(
            open_existing(file, false, &asked),
            Err(STATUS_NOT_A_DIRECTORY)
        );
        assert!(
            open_existing(directory, true, &asked).is_ok(),
            "a trailing separator"
        );
        assert_eq!(
            make_missing(false, &asked),
            Err(STATUS_OBJECT_NAME_NOT_FOUND)
        );
        for disposition in [FILE_CREATE, FILE_OPEN_IF] {
            let asked = request(read, disposition, FILE_DIRECTORY_FILE, 0);
            assert_eq!(make_missing(true, &asked), Ok(Making::Directory));
        }

        let asked = request(read, FILE_OPEN_IF, FILE_NON_DIRECTORY_FILE, 0);
        assert_eq!(
            open_existing(directory, false, &asked),
            Err(STATUS_FILE_IS_A_DIRECTORY)
        );
        assert_eq!(
            open_existing(file, true, &asked),
            Err(STATUS_OBJECT_NAME_INVALID)
        );
        assert_eq!(make_missing(true, &asked), Err(STATUS_OBJECT_NAME_INVALID));
        assert_eq!(
            open_existing(file, true, &request(read, FILE_OPEN, 0, 0)),
            Err(STATUS_OBJECT_NAME_INVALID)
        );

        let delete = request(DELETE, FILE_OPEN, FILE_DELETE_ON_CLOSE, 0);
        assert_eq!(
            open_existing(root, false, &delete),
            Err(STATUS_ACCESS_DENIED)
        );
        assert_eq!(
            open_existing(root, false, &request(DELETE, FILE_OPEN, 0, 0)),
            Err(STATUS_ACCESS_DENIED)
        );
        assert!(open_existing(root, false, &request(read, FILE_OPEN, 0, 0)).is_ok());
        assert_eq!(
            open_existing(directory, false, &delete),
            Ok(Opening {
                information: FILE_OPENED,
                overwrite: false,
                granted: DELETE,
                must_be_empty: true,
            })
        );
        assert_eq!(
            open_existing(file, false, &delete).map(|opening| opening.must_be_empty),
            Ok(false),
            "a file's delete-on-close waits for no listing"
        );
    }

    /// A read-only file opens for reading alone: write and delete rights are refused, or left out
    /// under MAXIMUM_ALLOWED, and every overwrite is refused. An overwrite keeps a hidden or system
    /// file's attribute only when asked to; an open of one is not an overwrite.
    #[test]
    fn a_read_only_hidden_or_system_file() {
        use crate::fs::fat32::dirent::{ATTR_HIDDEN, ATTR_READ_ONLY, ATTR_SYSTEM};
        use crate::fs::file::rights::*;
        use crate::status::*;
        let read_only = Existing {
            directory: false,
            root: false,
            attributes: ATTR_READ_ONLY,
        };
        let granted = |access, disposition| {
            open_existing(read_only, false, &request(access, disposition, 0, 0))
                .map(|opening| opening.granted)
        };
        assert_eq!(granted(FILE_READ_DATA, FILE_OPEN), Ok(FILE_READ_DATA));
        assert_eq!(granted(GENERIC_READ, FILE_OPEN_IF), Ok(FILE_GENERIC_READ));
        for refused in [
            FILE_WRITE_DATA,
            FILE_APPEND_DATA,
            DELETE,
            GENERIC_WRITE,
            GENERIC_ALL,
        ] {
            assert_eq!(
                granted(refused, FILE_OPEN),
                Err(STATUS_ACCESS_DENIED),
                "{refused:#x}"
            );
        }
        assert_eq!(
            granted(MAXIMUM_ALLOWED, FILE_OPEN),
            Ok(FILE_ALL_ACCESS & !(FILE_WRITE_DATA | FILE_APPEND_DATA | DELETE))
        );
        for overwrite in [FILE_SUPERSEDE, FILE_OVERWRITE, FILE_OVERWRITE_IF] {
            assert_eq!(
                granted(FILE_READ_DATA, overwrite),
                Err(STATUS_ACCESS_DENIED)
            );
            assert_eq!(
                granted(MAXIMUM_ALLOWED, overwrite),
                Err(STATUS_ACCESS_DENIED)
            );
        }

        for bit in [ATTR_HIDDEN, ATTR_SYSTEM] {
            let kept = Existing {
                attributes: bit | 0x20,
                ..read_only
            };
            for disposition in [FILE_SUPERSEDE, FILE_OVERWRITE, FILE_OVERWRITE_IF] {
                let without = request(FILE_WRITE_DATA, disposition, 0, 0x80);
                assert_eq!(
                    open_existing(kept, false, &without),
                    Err(STATUS_ACCESS_DENIED),
                    "{bit:#x} {disposition}"
                );
                let with = request(FILE_WRITE_DATA, disposition, 0, u32::from(bit));
                assert!(open_existing(kept, false, &with).is_ok_and(|opening| opening.overwrite));
            }
            let open = request(FILE_WRITE_DATA, FILE_OPEN, 0, 0);
            assert!(open_existing(kept, false, &open).is_ok());
        }
        let both = Existing {
            attributes: ATTR_HIDDEN | ATTR_SYSTEM,
            ..read_only
        };
        let hidden_only = request(FILE_WRITE_DATA, FILE_OVERWRITE, 0, u32::from(ATTR_HIDDEN));
        assert_eq!(
            open_existing(both, false, &hidden_only),
            Err(STATUS_ACCESS_DENIED)
        );
        let both_kept = request(FILE_WRITE_DATA, FILE_OVERWRITE, 0, 0x6);
        assert!(open_existing(both, false, &both_kept).is_ok());
    }

    /// A made or overwritten file's attributes: the settable ones asked for, always the archive
    /// bit; FILE_ATTRIBUTE_NORMAL, the directory bit and the attributes FAT does not keep add
    /// nothing. An overwrite share-checks the write it implies, a supersede the delete.
    #[test]
    fn a_made_file_s_attributes_and_an_overwrite_s_implied_access() {
        use crate::fs::file::rights::{DELETE, FILE_WRITE_DATA};
        assert_eq!(new_attributes(0), 0x20);
        assert_eq!(new_attributes(0x80), 0x20, "FILE_ATTRIBUTE_NORMAL");
        assert_eq!(new_attributes(0x1), 0x21);
        assert_eq!(new_attributes(0x7), 0x27);
        assert_eq!(new_attributes(0x10), 0x20, "the directory bit");
        assert_eq!(
            new_attributes(0x100 | 0x2),
            0x22,
            "FILE_ATTRIBUTE_TEMPORARY"
        );
        assert_eq!(new_attributes(0x7FB7), 0x27);
        let missing = request(0, FILE_CREATE, 0, 0x3);
        assert_eq!(make_missing(false, &missing), Ok(Making::File(0x23)));

        assert_eq!(implied_access(false, FILE_SUPERSEDE), 0);
        assert_eq!(implied_access(false, FILE_OPEN), 0);
        assert_eq!(implied_access(true, FILE_SUPERSEDE), DELETE);
        assert_eq!(implied_access(true, FILE_OVERWRITE), FILE_WRITE_DATA);
        assert_eq!(implied_access(true, FILE_OVERWRITE_IF), FILE_WRITE_DATA);
    }

    /// NtSetInformationFile's checks of a disk file: a basic set's root and directory bit and the
    /// attributes it leaves; a delete's root, read-only and mapped file; a position's sign.
    #[test]
    fn a_set_s_checks() {
        use crate::status::*;
        assert_eq!(check_basic(false, false, 0x27), Ok(()));
        assert_eq!(check_basic(false, true, 0x10), Ok(()));
        assert_eq!(
            check_basic(false, false, 0x10),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(
            check_basic(true, true, 0),
            Err(STATUS_ACCESS_DENIED),
            "the root"
        );
        assert_eq!(check_basic(true, true, 0x10), Err(STATUS_ACCESS_DENIED));

        assert_eq!(basic_attributes(0x21, 0), 0x21, "zero leaves them");
        assert_eq!(
            basic_attributes(0x21, 0x80),
            0,
            "FILE_ATTRIBUTE_NORMAL clears them"
        );
        assert_eq!(
            basic_attributes(0x30, 0x80),
            0x10,
            "the directory bit stays"
        );
        assert_eq!(basic_attributes(0x30, 0x02), 0x12);
        assert_eq!(basic_attributes(0x20, 0x10 | 0x01), 0x01, "never added");
        assert_eq!(basic_attributes(0x00, 0x7), 0x7);
        assert_eq!(
            basic_attributes(0x00, 0x100),
            0,
            "TEMPORARY: nothing FAT keeps"
        );

        assert_eq!(check_delete(false, false, false), Ok(()));
        for (root, read_only, mapped) in [
            (true, false, false),
            (false, true, false),
            (false, false, true),
            (true, true, true),
        ] {
            assert_eq!(
                check_delete(root, read_only, mapped),
                Err(STATUS_CANNOT_DELETE)
            );
        }

        assert_eq!(new_position(0), Ok(0));
        assert_eq!(new_position(i64::MAX as u64), Ok(i64::MAX as u64));
        for negative in [1 << 63, u64::MAX, FILE_USE_FILE_POINTER_POSITION] {
            assert_eq!(new_position(negative), Err(STATUS_INVALID_PARAMETER));
        }
    }

    /// A size change: a directory's none; past 4 GiB the disk is full; an allocation at or past
    /// the size changes nothing and one below it cuts the file; a mapped file grows but is not
    /// cut.
    #[test]
    fn a_size_change() {
        use crate::status::*;
        let (end, allocation) = (false, true);
        assert_eq!(
            resize_to(true, 0, false, 10, end),
            Err(STATUS_INVALID_HANDLE)
        );
        assert_eq!(
            resize_to(true, 0, false, 0, allocation),
            Err(STATUS_INVALID_HANDLE)
        );
        assert_eq!(resize_to(false, 100, false, 50, end), Ok(Some(50)));
        assert_eq!(resize_to(false, 100, false, 100, end), Ok(Some(100)));
        assert_eq!(resize_to(false, 100, false, 500, end), Ok(Some(500)));
        assert_eq!(resize_to(false, 100, false, 0, end), Ok(Some(0)));
        let largest = u64::from(u32::MAX);
        assert_eq!(resize_to(false, 0, false, largest, end), Ok(Some(u32::MAX)));
        assert_eq!(
            resize_to(false, 0, false, largest + 1, end),
            Err(STATUS_DISK_FULL)
        );
        assert_eq!(
            resize_to(false, 0, false, u64::MAX, allocation),
            Err(STATUS_DISK_FULL)
        );

        assert_eq!(resize_to(false, 100, false, 100, allocation), Ok(None));
        assert_eq!(resize_to(false, 100, false, 4096, allocation), Ok(None));
        assert_eq!(resize_to(false, 100, false, 99, allocation), Ok(Some(99)));

        assert_eq!(
            resize_to(false, 100, true, 99, end),
            Err(STATUS_USER_MAPPED_FILE)
        );
        assert_eq!(
            resize_to(false, 100, true, 0, allocation),
            Err(STATUS_USER_MAPPED_FILE)
        );
        assert_eq!(resize_to(false, 100, true, 100, end), Ok(Some(100)));
        assert_eq!(resize_to(false, 100, true, 200, end), Ok(Some(200)));
        assert_eq!(resize_to(false, 100, true, 200, allocation), Ok(None));
    }

    /// A rename: the root never moves, a file's new name takes no trailing separator; a taken
    /// name is replaced only when asked, never a directory, a read-only file or the file itself,
    /// and never while open.
    #[test]
    fn a_rename_s_checks() {
        use crate::status::*;
        assert_eq!(check_rename(false, false, false), Ok(()));
        assert_eq!(check_rename(false, true, true), Ok(()));
        assert_eq!(
            check_rename(false, false, true),
            Err(STATUS_OBJECT_NAME_INVALID)
        );
        assert_eq!(check_rename(true, true, false), Err(STATUS_ACCESS_DENIED));

        let file = Existing {
            directory: false,
            root: false,
            attributes: 0x20,
        };
        let directory = Existing {
            directory: true,
            ..file
        };
        let read_only = Existing {
            attributes: 0x21,
            ..file
        };
        let collision = Err(STATUS_OBJECT_NAME_COLLISION);
        assert_eq!(rename_over(true, false, file, false), Ok(()));
        assert_eq!(rename_over(false, false, file, false), collision);
        assert_eq!(
            rename_over(false, false, file, true),
            collision,
            "not asked"
        );
        assert_eq!(rename_over(true, true, file, false), collision, "itself");
        assert_eq!(rename_over(true, false, directory, false), collision);
        assert_eq!(rename_over(true, false, read_only, false), collision);
        assert_eq!(rename_over(true, false, read_only, true), collision);
        assert_eq!(
            rename_over(true, false, file, true),
            Err(STATUS_ACCESS_DENIED)
        );
    }

    /// A lock call: the handle's data rights, the object's device and kind, and the answers to
    /// the lock table's verdicts.
    #[test]
    fn a_lock_call_s_checks_and_answers() {
        use crate::fs::file::rights::*;
        use crate::fs::file::LockError;
        use crate::status::*;
        assert_eq!(check_lock_access(FILE_READ_DATA), Ok(()));
        assert_eq!(check_lock_access(FILE_WRITE_DATA), Ok(()));
        assert_eq!(check_lock_access(FILE_GENERIC_READ), Ok(()));
        for refused in [
            0,
            FILE_APPEND_DATA,
            FILE_READ_ATTRIBUTES,
            SYNCHRONIZE,
            DELETE,
        ] {
            assert_eq!(
                check_lock_access(refused),
                Err(STATUS_ACCESS_DENIED),
                "{refused:#x}"
            );
        }

        assert_eq!(lockable(Some((7, false))), Ok(7));
        assert_eq!(lockable(Some((7, true))), Err(STATUS_INVALID_PARAMETER));
        assert_eq!(lockable::<u32>(None), Err(STATUS_INVALID_DEVICE_REQUEST));

        for fail_immediately in [false, true] {
            assert_eq!(
                lock_answer(Ok(()), fail_immediately),
                Some(Ok(STATUS_SUCCESS))
            );
            assert_eq!(
                lock_answer(Err(LockError::Full), fail_immediately),
                Some(Err(STATUS_INSUFFICIENT_RESOURCES))
            );
        }
        assert_eq!(
            lock_answer(Err(LockError::Conflict), true),
            Some(Err(STATUS_LOCK_NOT_GRANTED))
        );
        assert_eq!(lock_answer(Err(LockError::Conflict), false), None, "a wait");

        assert_eq!(unlock_answer(true), Ok(STATUS_SUCCESS));
        assert_eq!(unlock_answer(false), Err(STATUS_RANGE_NOT_LOCKED));
    }

    /// NtCreateNamedPipeFile's checks: a byte-stream server that waits passes; each undefined or
    /// inconsistent argument is STATUS_INVALID_PARAMETER, checked before a message or non-blocking
    /// pipe's STATUS_NOT_IMPLEMENTED.
    #[test]
    fn a_pipe_server_s_arguments() {
        use crate::fs::file::rights::{FILE_READ_DATA, SYNCHRONIZE};
        use crate::status::*;
        let access = FILE_READ_DATA | SYNCHRONIZE;
        let byte = (
            FILE_PIPE_BYTE_STREAM,
            FILE_PIPE_BYTE_STREAM,
            FILE_PIPE_QUEUE_OPERATION,
        );
        let check = |access, share, disposition, options, modes, instances| {
            check_pipe_arguments(access, share, disposition, options, modes, instances)
        };
        let ok = Ok(());
        let invalid = Err(STATUS_INVALID_PARAMETER);
        let unserved = Err(STATUS_NOT_IMPLEMENTED);
        for share in [1, 2, 3] {
            for disposition in [FILE_CREATE, FILE_OPEN, FILE_OPEN_IF] {
                assert_eq!(check(access, share, disposition, 0, byte, 1), ok);
            }
        }
        assert_eq!(
            check(access, 3, FILE_CREATE, 0x32 & !0x10, byte, u32::MAX),
            ok
        );
        assert_eq!(
            check(access, 0, FILE_CREATE, 0, byte, 1),
            invalid,
            "no share"
        );
        assert_eq!(
            check(access, 7, FILE_CREATE, 0, byte, 1),
            invalid,
            "FILE_SHARE_DELETE"
        );
        for disposition in [FILE_SUPERSEDE, FILE_OVERWRITE, FILE_OVERWRITE_IF, 6] {
            assert_eq!(check(access, 3, disposition, 0, byte, 1), invalid);
        }
        assert_eq!(
            check(access, 3, FILE_CREATE, FILE_DIRECTORY_FILE, byte, 1),
            invalid
        );
        let both = FILE_SYNCHRONOUS_IO_ALERT | FILE_SYNCHRONOUS_IO_NONALERT;
        assert_eq!(check(access, 3, FILE_CREATE, both, byte, 1), invalid);
        for mode in [FILE_SYNCHRONOUS_IO_ALERT, FILE_SYNCHRONOUS_IO_NONALERT] {
            assert_eq!(check(access, 3, FILE_CREATE, mode, byte, 1), ok);
            assert_eq!(
                check(FILE_READ_DATA, 3, FILE_CREATE, mode, byte, 1),
                invalid
            );
        }
        assert_eq!(
            check(access, 3, FILE_CREATE, 0, byte, 0),
            invalid,
            "no instance"
        );
        assert_eq!(check(access, 3, FILE_CREATE, 0, (2, 0, 0), 1), invalid);
        assert_eq!(check(access, 3, FILE_CREATE, 0, (0, 2, 0), 1), invalid);
        assert_eq!(check(access, 3, FILE_CREATE, 0, (0, 0, 2), 1), invalid);
        assert_eq!(
            check(access, 3, FILE_CREATE, 0, (0, 1, 0), 1),
            invalid,
            "a byte stream read as messages"
        );
        assert_eq!(check(access, 3, FILE_CREATE, 0, (1, 1, 0), 1), unserved);
        assert_eq!(check(access, 3, FILE_CREATE, 0, (1, 0, 0), 1), unserved);
        assert_eq!(check(access, 3, FILE_CREATE, 0, (0, 0, 1), 1), unserved);
        assert_eq!(
            check(access, 0, FILE_CREATE, 0, (1, 1, 1), 1),
            invalid,
            "first"
        );

        assert_eq!(check_client(FILE_OPEN, 0), ok);
        assert_eq!(check_client(FILE_OPEN_IF, FILE_NON_DIRECTORY_FILE), ok);
        for disposition in [
            FILE_SUPERSEDE,
            FILE_CREATE,
            FILE_OVERWRITE,
            FILE_OVERWRITE_IF,
        ] {
            assert_eq!(check_client(disposition, 0), unserved);
        }
        assert_eq!(
            check_client(FILE_OPEN, FILE_DIRECTORY_FILE),
            Err(STATUS_NOT_A_DIRECTORY)
        );
    }

    /// A control code's required access, from its bits 14 and 15 (CTL_CODE's Access), held whole
    /// by the handle; a buffered control's lengths and the bytes its answer copies back.
    #[test]
    fn a_control_s_access_and_buffers() {
        use crate::fs::file::rights::{FILE_READ_DATA, FILE_WRITE_DATA};
        use crate::status::*;
        const FSCTL_PIPE_PEEK: u32 = 0x0011_400C;
        let any = 0x0022_0000;
        assert_eq!(control_rights(FSCTL_PIPE_PEEK), FILE_READ_DATA);
        assert_eq!(control_rights(any), 0, "FILE_ANY_ACCESS");
        assert_eq!(control_rights(any | 0x8000), FILE_WRITE_DATA);
        assert_eq!(
            control_rights(any | 0xC000),
            FILE_READ_DATA | FILE_WRITE_DATA
        );
        assert_eq!(control_rights(u32::MAX & !0xC000), 0);
        let both = FILE_READ_DATA | FILE_WRITE_DATA;
        assert_eq!(check_all(both, both), Ok(()));
        assert_eq!(check_all(0, 0), Ok(()));
        assert_eq!(
            check_all(FILE_READ_DATA, both),
            Err(STATUS_ACCESS_DENIED),
            "every one"
        );
        assert_eq!(
            check_all(FILE_WRITE_DATA, FILE_READ_DATA),
            Err(STATUS_ACCESS_DENIED)
        );
        assert_eq!(any & 3, METHOD_BUFFERED);

        assert_eq!(buffered_lengths(Some(8), Some(32)), (8, 32, 32));
        assert_eq!(buffered_lengths(Some(64), Some(4)), (64, 4, 64));
        assert_eq!(buffered_lengths(None, Some(4)), (0, 4, 4), "a null input");
        assert_eq!(
            buffered_lengths(Some(64), None),
            (64, 0, 64),
            "a null output"
        );
        assert_eq!(buffered_lengths(None, None), (0, 0, 0));
        assert_eq!(buffered_lengths(Some(0), Some(0)), (0, 0, 0));

        assert_eq!(copied_back(STATUS_SUCCESS, 10, 32), Some(10));
        assert_eq!(
            copied_back(STATUS_SUCCESS, 100, 32),
            Some(32),
            "at most the buffer"
        );
        assert_eq!(
            copied_back(STATUS_BUFFER_OVERFLOW, 32, 32),
            Some(32),
            "a warning"
        );
        assert_eq!(copied_back(STATUS_PENDING, 4, 32), Some(4));
        assert_eq!(copied_back(STATUS_INVALID_DEVICE_REQUEST, 10, 32), None);
        assert_eq!(copied_back(STATUS_ACCESS_DENIED, 0, 0), None);
    }

    /// A listing's search: the first query makes it of its name, RestartScan then changing nothing;
    /// a later query continues it, RestartScan taking it back to the start with its expression
    /// (the later query's name is never read). A name longer than an expression is refused.
    #[test]
    fn a_listing_s_search() {
        use crate::fs::search::{Search, MAX_EXPRESSION};
        use crate::status::*;
        let pattern = rtl::testing::wide("*.TXT");
        let mut held = None;
        let made = resume_search(&mut held, true, || Ok(Search::new(Some(&pattern))));
        assert_eq!(
            made.map(|search| search.expression().to_vec()),
            Ok(pattern.clone())
        );
        let kept = held.as_mut().unwrap();
        (kept.next, kept.answered) = (7, true);

        let never = || -> Result<Search, NtStatus> { panic!("a later query's name is not read") };
        let resumed = resume_search(&mut held, false, never).unwrap();
        assert_eq!((resumed.next, resumed.answered), (7, true));
        let restarted = resume_search(&mut held, true, never).unwrap();
        assert_eq!((restarted.next, restarted.answered), (0, false));
        assert_eq!(restarted.expression(), &pattern[..]);
        assert_eq!(held.map(|search| search.next), Some(0), "the object's own");

        let mut fresh = None;
        assert_eq!(
            resume_search(&mut fresh, false, || Err(STATUS_ACCESS_VIOLATION)).map(|_| ()),
            Err(STATUS_ACCESS_VIOLATION)
        );
        assert!(fresh.is_none(), "a failed first query makes no search");
        let every = resume_search(&mut fresh, false, || Ok(Search::new(None))).unwrap();
        assert_eq!(every.expression(), &[u16::from(b'*')]);

        assert_eq!(expression_length(0), Ok(0));
        assert_eq!(expression_length(1), Ok(0), "an odd byte rounds down");
        assert_eq!(expression_length(11), Ok(5));
        let most = 2 * MAX_EXPRESSION as u16;
        assert_eq!(expression_length(most), Ok(MAX_EXPRESSION));
        assert_eq!(expression_length(most + 1), Ok(MAX_EXPRESSION));
        assert_eq!(expression_length(most + 2), Err(STATUS_OBJECT_NAME_INVALID));
        assert_eq!(expression_length(u16::MAX), Err(STATUS_OBJECT_NAME_INVALID));
    }

    /// A disk write starts at the end for FILE_WRITE_TO_END_OF_FILE or an append-only handle
    /// (whatever offset it gives), at the offset given, else at the object's position.
    #[test]
    fn a_write_starts_where_its_offset_and_its_access_say() {
        let (size, position) = (1000, 40);
        let end = Some(FILE_WRITE_TO_END_OF_FILE);
        assert_eq!(write_start(end, false, size, position), size);
        assert_eq!(write_start(end, true, size, position), size);
        assert_eq!(write_start(Some(7), true, size, position), size);
        assert_eq!(write_start(None, true, size, position), size);
        assert_eq!(write_start(Some(7), false, size, position), 7);
        assert_eq!(write_start(Some(5000), false, size, position), 5000);
        assert_eq!(write_start(None, false, size, position), position);
    }

    /// A transfer's rights by direction, a directory's refusal, and its I/O status.
    #[test]
    fn a_transfer_s_rights_and_status() {
        use crate::fs::file::rights::*;
        use crate::status::*;
        assert_eq!(transfer_rights(false), FILE_READ_DATA);
        assert_eq!(transfer_rights(true), FILE_WRITE_DATA | FILE_APPEND_DATA);
        assert_eq!(check_data(false), Ok(()));
        assert_eq!(check_data(true), Err(STATUS_INVALID_DEVICE_REQUEST));
        assert_eq!(transfer_status(Ok(12)), (STATUS_SUCCESS, 12));
        assert_eq!(transfer_status(Ok(0)), (STATUS_SUCCESS, 0));
        assert_eq!(
            transfer_status(Err(STATUS_END_OF_FILE)),
            (STATUS_END_OF_FILE, 0)
        );
    }

    /// A disk read: a zero-length one moves nothing anywhere and asks no lock; a locked range
    /// refuses it; at or past the end it is STATUS_END_OF_FILE; else it moves what remains, at
    /// most its length.
    #[test]
    fn a_disk_read_s_count() {
        use crate::status::*;
        let free = |_| true;
        let never = |_: (u64, u64)| -> bool { panic!("a zero-length read asks no lock") };
        assert_eq!(read_count(0, 100, 0, never), Ok(0));
        assert_eq!(read_count(5000, 100, 0, never), Ok(0));
        assert_eq!(read_count(0, 100, 40, free), Ok(40));
        assert_eq!(read_count(60, 100, 40, free), Ok(40));
        assert_eq!(read_count(90, 100, 40, free), Ok(10));
        assert_eq!(read_count(99, 100, u32::MAX, free), Ok(1));
        assert_eq!(read_count(100, 100, 1, free), Err(STATUS_END_OF_FILE));
        assert_eq!(
            read_count(u64::MAX >> 1, 100, 1, free),
            Err(STATUS_END_OF_FILE)
        );
        assert_eq!(read_count(0, 0, 1, free), Err(STATUS_END_OF_FILE));
        let mut asked = None;
        let locked = read_count(10, 100, 5, |range| {
            asked = Some(range);
            false
        });
        assert_eq!(locked, Err(STATUS_FILE_LOCK_CONFLICT));
        assert_eq!(asked, Some((10, 5)), "the range asked of the locks");
        assert_eq!(
            read_count(200, 100, 5, |_| false),
            Err(STATUS_FILE_LOCK_CONFLICT),
            "the locks are asked before the end"
        );
    }

    /// A disk write: a zero-length one moves nothing and asks no lock; a locked range refuses it;
    /// one ending past 4 GiB less a byte is STATUS_DISK_FULL, one ending there fits.
    #[test]
    fn a_disk_write_s_count() {
        use crate::status::*;
        let free = |_| true;
        let never = |_: (u64, u64)| -> bool { panic!("a zero-length write asks no lock") };
        let largest = u64::from(u32::MAX);
        assert_eq!(write_count(0, 0, never), Ok(0));
        assert_eq!(write_count(largest + 5, 0, never), Ok(0));
        assert_eq!(write_count(0, 10, free), Ok(10));
        assert_eq!(
            write_count(5000, 10, free),
            Ok(10),
            "past the end: the file grows"
        );
        assert_eq!(write_count(largest - 1, 1, free), Ok(1));
        assert_eq!(write_count(largest, 1, free), Err(STATUS_DISK_FULL));
        assert_eq!(write_count(0, u32::MAX, free), Ok(u32::MAX));
        assert_eq!(write_count(1, u32::MAX, free), Err(STATUS_DISK_FULL));
        assert_eq!(write_count(i64::MAX as u64, 1, free), Err(STATUS_DISK_FULL));
        assert_eq!(
            write_count(10, 5, |_| false),
            Err(STATUS_FILE_LOCK_CONFLICT)
        );
        assert_eq!(
            write_count(largest, 1, |_| false),
            Err(STATUS_FILE_LOCK_CONFLICT),
            "the locks are asked before the size"
        );
    }

    /// A rename's name: one unit at least, a name's length at most, and inside the buffer after
    /// FILE_RENAME_INFORMATION's fixed part (an odd byte count rounds down); relative to its root
    /// directory when it names one, else to the volume's root with a separator, else to the
    /// file's own directory.
    #[test]
    fn a_rename_s_name_is_measured_and_placed() {
        use rtl::nt::info::{FileRenameInformation, VariableSize};
        let fixed = FileRenameInformation::FIXED_SIZE as u32;
        let invalid = Err(STATUS_INVALID_PARAMETER);
        assert_eq!(rename_name_length(2, fixed + 2), Ok(1));
        assert_eq!(rename_name_length(3, fixed + 2), Ok(1));
        assert_eq!(rename_name_length(0, fixed + 2), invalid);
        assert_eq!(rename_name_length(1, fixed + 2), invalid);
        assert_eq!(rename_name_length(4, fixed + 2), invalid);
        assert_eq!(rename_name_length(4, fixed + 4), Ok(2));
        let most = 2 * super::super::attributes::MAX_NAME as u32;
        assert_eq!(
            rename_name_length(most, fixed + most),
            Ok(super::super::attributes::MAX_NAME)
        );
        assert_eq!(rename_name_length(most + 2, u32::MAX), invalid);
        assert_eq!(rename_name_length(u32::MAX, u32::MAX), invalid);

        let units = rtl::testing::wide;
        assert_eq!(rename_root(0x10, &units("b.txt")), RenameRoot::Directory);
        assert_eq!(
            rename_root(0x10, &units("\\??\\C:\\b")),
            RenameRoot::Directory
        );
        assert_eq!(rename_root(0, &units("\\??\\C:\\b")), RenameRoot::Absolute);
        assert_eq!(rename_root(0, &units("sub\\b.txt")), RenameRoot::Absolute);
        assert_eq!(rename_root(0, &units("b.txt")), RenameRoot::Own);
    }
}
