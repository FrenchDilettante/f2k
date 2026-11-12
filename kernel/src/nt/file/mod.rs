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
pub use create::{create_file, open_file};
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

    /// The file object `handle` names in the calling process, referenced: STATUS_INVALID_HANDLE for
    /// a handle naming nothing (a console handle included), STATUS_OBJECT_TYPE_MISMATCH for another
    /// kind of object.
    pub fn file_object(handle: u32) -> Result<Referenced<FileObject>, NtStatus> {
        let reference = super::super::sync::object_of(handle, ObjectType::File)?;
        Ok(crate::ob::file_object(reference))
    }

    /// Whether an object was granted any of `rights`; STATUS_ACCESS_DENIED otherwise. None asks
    /// for nothing.
    pub fn check_access(object: &FileObject, rights: u32) -> Result<(), NtStatus> {
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
    }

    /// Read the OBJECT_ATTRIBUTES at `attributes` for a file service (see [`named`]), for a
    /// service that serves the boot volume's names alone: a pipe's name, or the null device's, is
    /// not served yet (STATUS_NOT_IMPLEMENTED).
    pub fn target(attributes: UserAddr) -> Result<Target, NtStatus> {
        match named(attributes)? {
            Named::Disk(target) => Ok(target),
            Named::Pipe { .. } | Named::Null { .. } => Err(STATUS_NOT_IMPLEMENTED),
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
    /// handle. STATUS_INVALID_HANDLE or STATUS_OBJECT_TYPE_MISMATCH for a handle naming no event.
    pub fn completion_event(handle: u32) -> Result<Option<crate::ob::ObRef>, NtStatus> {
        if handle == 0 {
            return Ok(None);
        }
        let event = super::super::sync::object_of(handle, ObjectType::Event)?;
        let body = event.event();
        crate::level::raised::<crate::level::Dispatch, _>(|dispatch| {
            crate::sched::DISPATCHER.get(dispatch).reset_event(body)
        });
        Ok(Some(event))
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
    }
}

#[cfg(not(target_arch = "x86"))]
pub use host::*;
