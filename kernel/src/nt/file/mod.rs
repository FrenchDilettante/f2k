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

        let units = |text: &str| text.encode_utf16().collect::<std::vec::Vec<u16>>();
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
