//! What the file system services share over the open files: the stored attributes and times as the
//! services report them, a handle's file object, the synchronous-I/O lock, opening a file (its
//! record counted, an object made, a handle published), the cleanup and close the object manager
//! leaves its caller, and reads through a file's record — each inside the boot volume's locked
//! section, so every open sees the one current copy of the file (see [`super::file`]).
//!
//! The volume is taken only once the call's user arguments are copied in: a fault in a user copy
//! ends the process, which must not happen while it holds the volume. The FAT timestamps are local
//! time, which is UTC here; a FILETIME is the stored time itself.

use super::fat32::dirent::Times;
use super::fat32::lookup::File;

/// FILE_ATTRIBUTE_ARCHIVE, and the attributes a program may set (read-only, hidden, system,
/// archive).
pub const ATTRIBUTE_ARCHIVE: u8 = 0x20;
pub const SETTABLE_ATTRIBUTES: u8 = 0x27;

/// FILE_ATTRIBUTE_NORMAL: a file with no other attribute.
pub const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
/// The stored attribute bits reported as they are (read-only, hidden, system, directory, archive).
const REPORTED_ATTRIBUTES: u8 = 0x37;

/// The attributes stored bits report: the bits, FILE_ATTRIBUTE_NORMAL standing in for none.
pub fn attributes(stored: u8) -> u32 {
    match stored & REPORTED_ATTRIBUTES {
        0 => FILE_ATTRIBUTE_NORMAL,
        bits => bits as u32,
    }
}

/// A file's three FILETIMEs: creation, last access, last write.
pub fn file_times(file: &File) -> [u64; 3] {
    use crate::time::fat_filetime;
    let t = &file.times;
    [
        fat_filetime(t.create_date, t.create_time, t.create_hundredths),
        fat_filetime(t.access_date, 0, 0),
        fat_filetime(t.write_date, t.write_time, 0),
    ]
}

/// Times stamped at `filetime`: all three, the creation's hundredths included.
pub fn times_at(filetime: u64) -> Times {
    let (date, time, hundredths) = crate::time::fat_from_filetime(filetime);
    Times {
        create_hundredths: hundredths,
        create_time: time,
        create_date: date,
        access_date: date,
        write_time: time,
        write_date: date,
    }
}

#[cfg(target_arch = "x86")]
mod target {
    use super::*;
    use crate::fs::fat32::dir::is_empty;
    use crate::fs::fat32::volume::{with_boot_volume, Volume};
    use crate::fs::fat32::write;
    use crate::fs::file::{with_records, FileObject, FileRecordId, IoState, OpenError};
    use crate::ob::Referenced;
    use crate::status::{
        NtStatus,
        STATUS_DELETE_PENDING,
        STATUS_INSUFFICIENT_RESOURCES,
        STATUS_IO_DEVICE_ERROR,
        STATUS_OBJECT_PATH_NOT_FOUND,
        STATUS_SHARING_VIOLATION,
        STATUS_TOO_MANY_OPENED_FILES,
    };

    /// The current time's stamps.
    pub fn now() -> Times {
        times_at(crate::time::system_filetime())
    }

    /// Run `body` on the boot volume: one locked section. A boot without a volume has no path.
    pub fn with_volume<R>(
        body: impl FnOnce(&mut Volume) -> Result<R, NtStatus>,
    ) -> Result<R, NtStatus> {
        with_boot_volume(body).ok_or(STATUS_OBJECT_PATH_NOT_FOUND)?
    }

    /// An open refused, as its status.
    pub fn open_status(error: OpenError) -> NtStatus {
        match error {
            OpenError::Sharing => STATUS_SHARING_VIOLATION,
            OpenError::DeletePending => STATUS_DELETE_PENDING,
            OpenError::Full => STATUS_TOO_MANY_OPENED_FILES,
        }
    }

    /// The file object `handle` names in the calling process, referenced; none for a handle naming
    /// anything else (a console handle included: it names no table slot).
    pub fn object_of(handle: u32) -> Option<Referenced<FileObject>> {
        if crate::nt::object::is_console_handle(handle) {
            return None;
        }
        crate::ob::reference_by_handle(handle, Some(crate::ob::ObjectType::File))
            .map(crate::ob::file_object)
    }

    /// The file an object opens, as its record holds it now.
    pub fn file_of(object: &FileObject) -> File {
        file_at(object.record)
    }

    /// The open file `record`, as its record holds it now.
    pub fn file_at(record: FileRecordId) -> File {
        with_records(|records| records.get(record).file)
    }

    /// The open file `record` changed into `file` (a write, a resize, a change of its entry).
    pub fn store_file(record: FileRecordId, file: File) {
        with_records(|records| records.get_mut(record).file = file);
    }

    /// Run `body` on the object's position and search, holding its synchronous-I/O lock: one call
    /// at a time moves them (see [`FileObject::serialized`]). The call is a critical region: its
    /// holder may block under the lock (the disk's reads), and a termination requested meanwhile
    /// waits for it to finish, holding nothing.
    pub fn serialized<R>(
        object: &Referenced<FileObject>,
        body: impl FnOnce(&mut IoState) -> R,
    ) -> R {
        crate::process::threads::critical_region(|| object.serialized(body))
    }

    /// How a new open's object starts: its rights, the sharing it allows, and its options.
    pub struct Open {
        pub granted: u32,
        pub share: u8,
        pub inherit: bool,
        pub synchronous: bool,
        pub delete_on_close: bool,
    }

    /// Open the file or directory `file`: its record counted for the open (the share check), a file
    /// object made and a handle to it inserted with the rights granted. STATUS_SHARING_VIOLATION
    /// when an open in place excludes it, STATUS_DELETE_PENDING while its delete is pending,
    /// STATUS_INSUFFICIENT_RESOURCES when the handle table is full, STATUS_TOO_MANY_OPENED_FILES
    /// when the records or the objects are.
    pub fn open(file: File, open: &Open) -> Result<u32, NtStatus> {
        let process = crate::user::args::calling_process();
        if process.handles_full() {
            return Err(STATUS_INSUFFICIENT_RESOURCES);
        }
        let access = crate::fs::file::rights::share_access(open.granted);
        let record =
            with_records(|records| records.open(file, access, open.share)).map_err(open_status)?;
        let made = crate::ob::locked(|directory| {
            let id = directory.create_file(record, access, open.granted, open.share)?;
            let object = directory.file(id).expect("just made");
            object.synchronous = open.synchronous;
            object.delete_on_close = open.delete_on_close;
            Some(id)
        });
        let Some(id) = made else {
            with_records(|records| {
                let _ = records.cleanup(record, access, open.share, false);
                records.close(record);
            });
            return Err(STATUS_TOO_MANY_OPENED_FILES);
        };
        // The table had room: the publication cannot fail.
        crate::ob::publish(process, id, open.granted, open.inherit)
            .map(core::num::NonZeroU32::get)
            .ok_or(STATUS_INSUFFICIENT_RESOURCES)
    }

    /// Whether the open file `record` is mapped (a section holds it): it cannot be cut short nor
    /// deleted.
    pub fn mapped(record: FileRecordId) -> bool {
        with_records(|records| records.get(record).user_mapped > 0)
    }

    /// A file object's cleanup (its last handle closed): its share access leaves the record, and
    /// the last cleanup of a delete-pending file deletes it — a directory only while empty, a file
    /// only while no mapping of it exists (the memory manager keeps a mapped file).
    pub fn cleanup(record: FileRecordId, access: u8, share: u8, delete_on_close: bool) {
        let deleted =
            with_records(|records| records.cleanup(record, access, share, delete_on_close));
        if let Some(file) = deleted {
            if mapped(record) {
                return;
            }
            let _ = with_volume(|volume| {
                if file.directory && !is_empty(volume, file.first_cluster)? {
                    return Ok(());
                }
                write::delete(volume, &file)
            });
        }
    }

    /// A file object's close (its last reference went): its record's reference goes.
    pub fn close(record: FileRecordId) {
        with_records(|records| records.close(record));
    }

    /// Read `out.len()` bytes of the open file `record` from `offset`, the file as its record holds
    /// it inside the volume's locked section (a write racing the read cannot leave it reading a
    /// stale chain). STATUS_IO_DEVICE_ERROR when the read fails or comes up short.
    pub fn read_record(record: FileRecordId, offset: u32, out: &mut [u8]) -> Result<(), NtStatus> {
        with_volume(|volume| {
            let file = file_at(record);
            match crate::fs::fat32::read::read_at(volume, &file, offset, out) {
                Ok(got) if got == out.len() => Ok(()),
                Ok(_) => Err(STATUS_IO_DEVICE_ERROR),
                Err(status) => Err(status),
            }
        })
    }

    /// Read `out.len()` bytes of `file` from `offset` off the boot volume (a mapping's pages); none
    /// when the read fails or comes up short (the size said the bytes were there).
    pub fn read_file_at(file: &File, offset: u32, out: &mut [u8]) -> Option<usize> {
        let read =
            with_boot_volume(|volume| crate::fs::fat32::read::read_at(volume, file, offset, out))?;
        read.ok().filter(|&got| got == out.len())
    }

    /// The name `file`'s entry shows in its directory (its long name, else its 8.3 name), read off
    /// the boot volume into `out`: its length, or none when the directory cannot be read or no
    /// longer holds the entry.
    pub fn entry_name(
        file: &File,
        out: &mut [u8; crate::fs::fat32::path::MAX_NAME],
    ) -> Option<usize> {
        let mut length = None;
        let walked = with_boot_volume(|volume| {
            crate::fs::fat32::dir::walk(volume, file.parent_cluster, |listed| {
                if listed.index != file.index {
                    return true;
                }
                length = Some(listed.name(out));
                false
            })
        })?;
        walked.ok()?;
        length
    }
}

#[cfg(target_arch = "x86")]
pub use target::*;

#[cfg(test)]
mod tests {
    use super::*;

    /// Attributes: the stored bits, or FILE_ATTRIBUTE_NORMAL for none.
    #[test]
    fn attributes_report_the_stored_bits() {
        assert_eq!(attributes(0x20), 0x20);
        assert_eq!(attributes(0x21), 0x21);
        assert_eq!(attributes(0x10), 0x10);
        assert_eq!(attributes(0), 0x80);
        assert_eq!(
            attributes(0x08),
            0x80,
            "a volume label's bit is not reported"
        );
    }

    /// A stamp's times read back as the FILETIME they were stamped at (to the FAT encoding's
    /// resolution: two seconds for the write time, hundredths for the creation).
    #[test]
    fn stamps_read_back_as_their_filetime() {
        let at = crate::time::FALLBACK_BOOT + 3 * 10_000_000 + 2_500_000;
        let mut file = File::plain(3, 1, false);
        file.times = times_at(at);
        let [created, accessed, written] = file_times(&file);
        assert_eq!(
            created, at,
            "the hundredths carry the odd second and the rest"
        );
        assert_eq!(written, at - 10_000_000 - 2_500_000, "two-second units");
        assert_eq!(accessed, crate::time::FALLBACK_BOOT, "the date alone");
    }
}
