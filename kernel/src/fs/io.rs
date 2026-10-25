//! What the file system services share over the open files: the stored attributes and times as the
//! services report them, a handle's file object, the synchronous-I/O lock, opening a file (its
//! record counted, an object made, a handle published), the cleanup and close the object manager
//! leaves to the process, and reads through a file's record — each inside the boot volume's locked
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
    use crate::fs::file::{records, FileObject, OpenError};
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
        let reference = crate::ob::reference_by_handle(handle, Some(crate::ob::ObjectType::File))?;
        let object = crate::ob::directory()
            .file(reference.id())
            .expect("a referenced file object lives");
        Some(Referenced::new(reference, object))
    }

    /// The file an object opens, as its record holds it now.
    pub fn file_of(object: &FileObject) -> File {
        records().get(object.record).file
    }

    /// Run `body` holding the object's synchronous-I/O lock: one call at a time moves its position.
    /// The call is a critical region: a termination requested meanwhile waits for it to finish,
    /// holding nothing.
    pub fn serialized<R>(object: &mut FileObject, body: impl FnOnce(&mut FileObject) -> R) -> R {
        crate::process::threads::critical_region(|| {
            let lock = object.lock.waitable();
            crate::sched::wait::wait_current_with(|dispatcher, thread, stamp, _replay| {
                dispatcher.wait_single(
                    thread,
                    lock,
                    crate::sched::wait::WaitReason::Executive,
                    crate::sched::wait::WaitMode::Kernel,
                    false,
                    None,
                    stamp,
                )
            });
            let result = body(object);
            object.lock.set(crate::sched::idle::dispatcher(), 0);
            result
        })
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
        if process.handles().is_full() {
            return Err(STATUS_INSUFFICIENT_RESOURCES);
        }
        let access = crate::fs::file::rights::share_access(open.granted);
        let record = records()
            .open(file, access, open.share)
            .map_err(open_status)?;
        let Some(id) = crate::ob::directory().create_file(record, access, open.granted, open.share)
        else {
            let _ = records().cleanup(record, access, open.share, false);
            records().close(record);
            return Err(STATUS_TOO_MANY_OPENED_FILES);
        };
        let object = crate::ob::directory().file(id).expect("just made");
        object.synchronous = open.synchronous;
        object.delete_on_close = open.delete_on_close;
        // The table had room: the publication cannot fail.
        crate::ob::publish(process, id, open.granted, open.inherit, None)
            .ok_or(STATUS_INSUFFICIENT_RESOURCES)
    }

    /// Whether the open file at `record` is mapped (a section holds it): it cannot be cut short nor
    /// deleted.
    pub fn mapped(record: u16) -> bool {
        records().get(record).user_mapped > 0
    }

    /// A file object's cleanup (its last handle closed): its directory search goes, its share
    /// access leaves the record, and the last cleanup of a delete-pending file deletes it — a
    /// directory only while empty, a file only while no mapping of it exists (the memory manager
    /// keeps a mapped file).
    pub fn cleanup(record: u16, access: u8, share: u8, delete_on_close: bool, search: u16) {
        crate::fs::search::searches().close(search);
        if let Some(file) = records().cleanup(record, access, share, delete_on_close) {
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
    pub fn close(record: u16) {
        records().close(record);
    }

    /// Read `out.len()` bytes of the open file at `record` from `offset`, the file as its record
    /// holds it inside the volume's locked section (a write racing the read cannot leave it reading
    /// a stale chain). STATUS_IO_DEVICE_ERROR when the read fails or comes up short.
    pub fn read_record(record: u16, offset: u32, out: &mut [u8]) -> Result<(), NtStatus> {
        with_volume(|volume| {
            let file = records().get(record).file;
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
