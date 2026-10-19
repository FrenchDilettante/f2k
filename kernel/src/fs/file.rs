//! Open files: the file objects behind file handles over the shared records of the files they
//! open, the rights an open is granted, and the read arithmetic over them.
//!
//! The platform's split, three levels deep. A file object (an object-manager kind, see
//! [`crate::ob`]) is one CreateFile: its position, the access it was granted and the sharing it
//! allows, its delete-on-close flag — duplicated handles name the same object and share its
//! position. A file record (NT's FCB) is one file, shared by every open of it: the authoritative
//! copy of its entry (first cluster, size, attributes, times — every write updates it, so no open
//! ever works from a stale copy), its share-access counts, how many opens are still to be cleaned
//! up, and whether a delete is pending. Records are keyed by the entry's identity (its directory
//! and its record there; the root's is its own) and global, not a process's.
//!
//! The share check is NT's IoCheckShareAccess: only opens asking to read, write or delete take
//! part — an open for attributes alone neither checks nor counts — and a new open is refused when
//! it asks for what an existing open does not share, or shares less than an existing open uses.
//! An open's last handle is its cleanup: its share access goes, its delete-on-close marks the file
//! delete-pending, and the last cleanup of a delete-pending file deletes it. While a delete is
//! pending, new opens are refused (STATUS_DELETE_PENDING). The object's last reference releases the
//! record (a mapping can hold an object past its cleanup).
//!
//! A directory opens too (backup semantics), for its metadata. Positions are 64-bit, as Win32 file
//! pointers are; files themselves stay within FAT32's 32-bit sizes.

use super::fat32::lookup::File;
use crate::sched::event::{Event, EventKind};

/// How many file objects can exist at once (across processes). Exhaustion is a program-visible
/// failure (the open returns no handle), not a bug.
pub const OPEN_FILES: usize = 128;

/// How many files can be open at once.
pub const FILE_RECORDS: usize = 128;

/// The access an open asks for, as the share check reads it; the share mode uses the same bits
/// (FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_SHARE_DELETE).
pub const ACCESS_READ: u8 = 1;
pub const ACCESS_WRITE: u8 = 2;
pub const ACCESS_DELETE: u8 = 4;

/// Every share bit.
pub const SHARE_ALL: u8 = ACCESS_READ | ACCESS_WRITE | ACCESS_DELETE;

/// The file access rights (winnt.h), and the generic rights' mapping onto them.
pub mod rights {
    pub const FILE_READ_DATA: u32 = 0x0001;
    pub const FILE_WRITE_DATA: u32 = 0x0002;
    pub const FILE_APPEND_DATA: u32 = 0x0004;
    pub const FILE_READ_EA: u32 = 0x0008;
    pub const FILE_WRITE_EA: u32 = 0x0010;
    pub const FILE_EXECUTE: u32 = 0x0020;
    pub const FILE_READ_ATTRIBUTES: u32 = 0x0080;
    pub const FILE_WRITE_ATTRIBUTES: u32 = 0x0100;
    pub const DELETE: u32 = 0x0001_0000;
    pub const READ_CONTROL: u32 = 0x0002_0000;
    pub const SYNCHRONIZE: u32 = 0x0010_0000;
    pub const MAXIMUM_ALLOWED: u32 = 0x0200_0000;
    pub const GENERIC_ALL: u32 = 0x1000_0000;
    pub const GENERIC_EXECUTE: u32 = 0x2000_0000;
    pub const GENERIC_WRITE: u32 = 0x4000_0000;
    pub const GENERIC_READ: u32 = 0x8000_0000;
    pub const FILE_ALL_ACCESS: u32 = 0x001F_01FF;
    pub const FILE_GENERIC_READ: u32 = READ_CONTROL | FILE_READ_DATA | FILE_READ_ATTRIBUTES | FILE_READ_EA | SYNCHRONIZE;
    pub const FILE_GENERIC_WRITE: u32 =
        READ_CONTROL | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA | FILE_APPEND_DATA | SYNCHRONIZE;
    pub const FILE_GENERIC_EXECUTE: u32 = READ_CONTROL | FILE_READ_ATTRIBUTES | FILE_EXECUTE | SYNCHRONIZE;

    /// The specific rights an access mask asks for: the generic rights mapped (the file object's
    /// GENERIC_MAPPING), MAXIMUM_ALLOWED as every right (no security descriptors are kept).
    pub fn mapped(access: u32) -> u32 {
        let mut mapped = access & 0x00FF_FFFF;
        if access & GENERIC_READ != 0 {
            mapped |= FILE_GENERIC_READ;
        }
        if access & GENERIC_WRITE != 0 {
            mapped |= FILE_GENERIC_WRITE;
        }
        if access & GENERIC_EXECUTE != 0 {
            mapped |= FILE_GENERIC_EXECUTE;
        }
        if access & (GENERIC_ALL | MAXIMUM_ALLOWED) != 0 {
            mapped |= FILE_ALL_ACCESS;
        }
        mapped
    }

    /// The share check's view of granted rights (IoCheckShareAccess): reading (read data, execute),
    /// writing (write or append data), deleting.
    pub fn share_access(granted: u32) -> u8 {
        let mut access = 0;
        if granted & (FILE_READ_DATA | FILE_EXECUTE) != 0 {
            access |= super::ACCESS_READ;
        }
        if granted & (FILE_WRITE_DATA | FILE_APPEND_DATA) != 0 {
            access |= super::ACCESS_WRITE;
        }
        if granted & DELETE != 0 {
            access |= super::ACCESS_DELETE;
        }
        access
    }
}

/// How many bytes a read of `count` at `position` moves in a file of `size`: what remains before
/// the end, at most `count`; nothing at or past the end.
pub fn available(position: u64, size: u32, count: u32) -> u32 {
    (size as u64).saturating_sub(position).min(count as u64) as u32
}

/// One open as the file API's readers see it: the file as its record holds it now, with the
/// open's own position, access and sharing (the tests' view of an open).
#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct OpenFile {
    /// The file, as its record holds it.
    pub file: File,
    /// Where the next read starts; may lie past the end (a read there moves nothing).
    pub position: u64,
    /// The access the open was granted ([`ACCESS_READ`] and kin).
    pub access: u8,
    /// The sharing the open allows others (the same bits).
    pub share: u8,
    /// Whether the file goes when its last open closes (FILE_FLAG_DELETE_ON_CLOSE).
    pub delete_on_close: bool,
}

#[cfg(test)]
impl OpenFile {
    /// A file opened at its start for reading, shared every way.
    #[cfg(test)]
    pub fn new(file: File) -> OpenFile {
        OpenFile { file, position: 0, access: ACCESS_READ, share: SHARE_ALL, delete_on_close: false }
    }

    /// How many bytes a read of `count` at the position moves (see [`available`]).
    #[cfg(test)]
    pub fn available(&self, count: u32) -> u32 {
        available(self.position, self.file.size, count)
    }
}

/// A file object's body: one open of one file.
pub struct FileObject {
    /// The file's record.
    pub record: u16,
    /// Where the next read or write starts.
    pub position: u64,
    /// The access granted, as the share check reads it.
    pub access: u8,
    /// The access granted, the file rights the generic ones map to (FILE_READ_DATA,
    /// FILE_WRITE_ATTRIBUTES, DELETE, ...): what each service checks.
    pub granted: u32,
    /// The sharing allowed others.
    pub share: u8,
    /// Whether the file goes with this open's cleanup (FILE_DELETE_ON_CLOSE).
    pub delete_on_close: bool,
    /// Whether the object keeps a position (opened for synchronous I/O): a read or write without an
    /// offset uses and moves it.
    pub synchronous: bool,
    /// The directory search the object's queries continue (its number in [`super::search`]; zero
    /// for none yet).
    pub search: u16,
    /// The synchronous-I/O lock: a call reading or writing through the object holds it, so the
    /// position moves one call at a time (FO_SYNCHRONOUS_IO's serialization). Signaled while free.
    pub lock: Event,
}

impl FileObject {
    /// A file object of `record`, at its start, synchronous; call [`FileObject::init`] at its final
    /// address.
    pub const fn new(record: u16, access: u8, granted: u32, share: u8) -> Self {
        FileObject {
            record,
            position: 0,
            access,
            granted,
            share,
            delete_on_close: false,
            synchronous: true,
            search: 0,
            lock: Event::new(EventKind::Synchronization, true),
        }
    }

    /// Close the lock's waiters sentinel; call once at the final address.
    pub fn init(&mut self) {
        self.lock.init();
    }
}

/// NT's SHARE_ACCESS: how many opens take part in the share check, how many of them read, write
/// and delete, and how many share each.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub struct ShareAccess {
    opens: u16,
    readers: u16,
    writers: u16,
    deleters: u16,
    shared_read: u16,
    shared_write: u16,
    shared_delete: u16,
}

impl ShareAccess {
    /// Whether an open asking `access` and allowing `share` is compatible with the opens in place
    /// (IoCheckShareAccess). An open asking none of the three neither checks nor counts.
    pub fn allows(&self, access: u8, share: u8) -> bool {
        let (read, write, delete) =
            (access & ACCESS_READ != 0, access & ACCESS_WRITE != 0, access & ACCESS_DELETE != 0);
        if !(read || write || delete) {
            return true;
        }
        let (shares_read, shares_write, shares_delete) =
            (share & ACCESS_READ != 0, share & ACCESS_WRITE != 0, share & ACCESS_DELETE != 0);
        !((read && self.shared_read < self.opens)
            || (write && self.shared_write < self.opens)
            || (delete && self.shared_delete < self.opens)
            || (self.readers != 0 && !shares_read)
            || (self.writers != 0 && !shares_write)
            || (self.deleters != 0 && !shares_delete))
    }

    /// Count an open asking `access` and allowing `share` (IoUpdateShareAccess / IoSetShareAccess).
    pub fn add(&mut self, access: u8, share: u8) {
        self.adjust(access, share, true);
    }

    /// Uncount it (IoRemoveShareAccess).
    pub fn remove(&mut self, access: u8, share: u8) {
        self.adjust(access, share, false);
    }

    fn adjust(&mut self, access: u8, share: u8, add: bool) {
        if access & SHARE_ALL == 0 {
            return;
        }
        let step = |count: &mut u16, on: bool| {
            if on {
                *count = if add { *count + 1 } else { *count - 1 };
            }
        };
        step(&mut self.opens, true);
        step(&mut self.readers, access & ACCESS_READ != 0);
        step(&mut self.writers, access & ACCESS_WRITE != 0);
        step(&mut self.deleters, access & ACCESS_DELETE != 0);
        step(&mut self.shared_read, share & ACCESS_READ != 0);
        step(&mut self.shared_write, share & ACCESS_WRITE != 0);
        step(&mut self.shared_delete, share & ACCESS_DELETE != 0);
    }
}

/// One open file's shared record.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct FileRecord {
    /// The file's entry as it stands: every write, resize, rename and attribute change through any
    /// open (or by path) updates it.
    pub file: File,
    share: ShareAccess,
    /// How many opens have not been cleaned up (their last handle is still open).
    cleanups: u16,
    /// How many file objects reference the record.
    references: u16,
    /// Whether the file goes with its last cleanup.
    delete_pending: bool,
    /// How many mappings of the file exist (a section holds its file object).
    pub user_mapped: u16,
}

/// Why an open found no record.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum OpenError {
    /// An open of the same file excludes it (ERROR_SHARING_VIOLATION).
    Sharing,
    /// The file is being deleted: it goes with its last open's cleanup (ERROR_ACCESS_DENIED).
    DeletePending,
    /// Every record or object is taken.
    Full,
}

/// Whether `a` and `b` are the same entry (its directory and its record index there; a file's
/// first cluster changes as it is written).
pub fn same_entry(a: &File, b: &File) -> bool {
    a.parent_cluster == b.parent_cluster && a.index == b.index
}

/// The open files' records.
pub struct FileRecords {
    records: [Option<FileRecord>; FILE_RECORDS],
}

impl FileRecords {
    /// No file open (the tests build records by value; the kernel writes them in place).
    #[cfg(test)]
    pub const fn empty() -> Self {
        FileRecords { records: [None; FILE_RECORDS] }
    }

    /// Write the empty set at `records`, record by record (by value it would pass the caller's
    /// stack).
    ///
    /// # Safety
    ///
    /// `records` is valid for writes and aligned; its previous contents are overwritten.
    pub unsafe fn write_empty(records: *mut FileRecords) {
        // SAFETY: the caller's contract; every record is written.
        unsafe {
            let slots = core::ptr::addr_of_mut!((*records).records) as *mut Option<FileRecord>;
            for index in 0..FILE_RECORDS {
                slots.add(index).write(None);
            }
        }
    }

    /// The record of the entry `file` names, if it is open.
    pub fn find(&self, file: &File) -> Option<u16> {
        self.records
            .iter()
            .position(|record| record.is_some_and(|record| same_entry(&record.file, file)))
            .map(|index| index as u16)
    }

    /// Open the entry `file` names for `access`, allowing `share`: its record (made when the file
    /// is not open yet), counted for one more open. Refused while a delete is pending, when an open
    /// in place excludes it, or when every record is taken.
    pub fn open(&mut self, file: File, access: u8, share: u8) -> Result<u16, OpenError> {
        let index = match self.find(&file) {
            Some(index) => {
                let record = self.records[index as usize].as_ref().expect("found");
                if record.delete_pending {
                    return Err(OpenError::DeletePending);
                }
                if !record.share.allows(access, share) {
                    return Err(OpenError::Sharing);
                }
                index
            }
            None => {
                let index = self.records.iter().position(Option::is_none).ok_or(OpenError::Full)? as u16;
                self.records[index as usize] = Some(FileRecord {
                    file,
                    share: ShareAccess::default(),
                    cleanups: 0,
                    references: 0,
                    delete_pending: false,
                    user_mapped: 0,
                });
                index
            }
        };
        let record = self.records[index as usize].as_mut().expect("just taken");
        record.share.add(access, share);
        record.cleanups += 1;
        record.references += 1;
        Ok(index)
    }

    /// The record at `index` (a live object names it).
    pub fn get(&self, index: u16) -> &FileRecord {
        self.records[index as usize].as_ref().expect("an open names a live record")
    }

    /// The record at `index`, mutably.
    pub fn get_mut(&mut self, index: u16) -> &mut FileRecord {
        self.records[index as usize].as_mut().expect("an open names a live record")
    }

    /// The entry `old` named changed into `new` (a change made by path, or a rename): an open
    /// record of it follows.
    pub fn refresh(&mut self, old: &File, new: &File) {
        if let Some(index) = self.find(old) {
            self.get_mut(index).file = *new;
        }
    }

    /// Set or clear the pending delete of the open file at `index` (FileDispositionInformation):
    /// it goes with its last open's cleanup.
    pub fn set_delete_pending(&mut self, index: u16, pending: bool) {
        self.get_mut(index).delete_pending = pending;
    }

    /// Whether the open file at `index` goes with its last cleanup.
    pub fn delete_pending(&self, index: u16) -> bool {
        self.get(index).delete_pending
    }

    /// An open's last handle closed (its cleanup): its share access goes, its delete-on-close marks
    /// the file delete-pending. Returns the file to delete now: the last cleanup of a
    /// delete-pending file.
    pub fn cleanup(&mut self, index: u16, access: u8, share: u8, delete_on_close: bool) -> Option<File> {
        let record = self.get_mut(index);
        record.share.remove(access, share);
        record.cleanups -= 1;
        record.delete_pending |= delete_on_close;
        (record.cleanups == 0 && record.delete_pending).then_some(record.file)
    }

    /// An open's last reference went: the record goes with the last one.
    pub fn close(&mut self, index: u16) {
        let record = self.get_mut(index);
        record.references -= 1;
        if record.references == 0 {
            self.records[index as usize] = None;
        }
    }

    /// Forget every record (the process's end, after every open was closed), returning how many
    /// were still taken.
    pub fn clear(&mut self) -> usize {
        let live = self.live();
        for record in self.records.iter_mut() {
            *record = None;
        }
        live
    }

    /// How many records are taken.
    pub fn live(&self) -> usize {
        self.records.iter().filter(|record| record.is_some()).count()
    }
}

/// The kernel's file records, built in place at first use.
#[cfg(target_arch = "x86")]
static mut RECORDS: core::mem::MaybeUninit<FileRecords> = core::mem::MaybeUninit::uninit();

/// Whether [`RECORDS`] is built.
#[cfg(target_arch = "x86")]
static mut RECORDS_BUILT: bool = false;

/// The kernel's file records.
#[cfg(target_arch = "x86")]
pub fn records() -> &'static mut FileRecords {
    // SAFETY: single CPU; services run serialized (the gate masks interrupts), and a record's
    // changes that span a volume I/O are made under the volume lock. Built once, in place.
    unsafe {
        let records = (*core::ptr::addr_of_mut!(RECORDS)).as_mut_ptr();
        if !RECORDS_BUILT {
            FileRecords::write_empty(records);
            RECORDS_BUILT = true;
        }
        &mut *records
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(size: u32) -> File {
        File::plain(3, size, false)
    }

    fn entry(index: u32) -> File {
        let mut file = File::plain(3, 10, false);
        file.index = index;
        file
    }

    /// A read moves what remains before the end, at most the request: all of it, the prefix that
    /// fits, or nothing at the end.
    #[test]
    fn reads_take_what_remains() {
        let mut open = OpenFile::new(file(100));
        assert_eq!(open.available(40), 40);
        open.position = 90;
        assert_eq!(open.available(40), 10, "the prefix before the end");
        open.position = 100;
        assert_eq!(open.available(40), 0, "at the end");
        assert_eq!(OpenFile::new(file(0)).available(4), 0, "an empty file");
    }

    /// The share check: an open without sharing excludes any second open that reads, writes or
    /// deletes, and a second open that shares nothing is excluded by any first; reads that share
    /// reads coexist; other entries are never consulted.
    #[test]
    fn opens_respect_each_others_sharing() {
        let mut records = FileRecords::empty();
        let first = records.open(entry(1), ACCESS_READ, 0).unwrap();
        assert_eq!(records.open(entry(1), ACCESS_READ, SHARE_ALL), Err(OpenError::Sharing));
        assert!(records.cleanup(first, ACCESS_READ, 0, false).is_none());
        records.close(first);
        let reader = records.open(entry(1), ACCESS_READ, ACCESS_READ).unwrap();
        assert_eq!(records.open(entry(1), ACCESS_READ, ACCESS_READ), Ok(reader), "one record");
        assert_eq!(records.open(entry(1), ACCESS_READ, 0), Err(OpenError::Sharing), "exclusive");
        assert_eq!(records.open(entry(1), ACCESS_WRITE, SHARE_ALL), Err(OpenError::Sharing), "not shared");
        assert!(records.open(entry(9), ACCESS_READ, 0).is_ok(), "another entry");
    }

    /// CopyFileA onto the source's own entry under another spelling. The target's open (for
    /// writing and delete, sharing nothing) finds the source's record — the same entry, however
    /// its lookup filled the rest — and is refused by the source's open (reading, sharing reads)
    /// before the overwrite can cut the file: ERROR_SHARING_VIOLATION.
    #[test]
    fn a_copy_onto_its_own_source_is_a_sharing_violation() {
        let mut records = FileRecords::empty();
        let source = records.open(entry(1), ACCESS_READ, ACCESS_READ).unwrap();
        let mut spelled = entry(1);
        spelled.size = 0;
        assert_eq!(records.find(&spelled), Some(source), "the same entry");
        assert_eq!(records.open(spelled, ACCESS_WRITE | ACCESS_DELETE, 0), Err(OpenError::Sharing));
    }

    /// An open asking no data access (attributes only) neither checks nor counts, whichever
    /// comes first.
    #[test]
    fn opens_without_data_access_take_no_part() {
        let mut records = FileRecords::empty();
        let reader = records.open(entry(1), ACCESS_READ, 0).unwrap();
        assert_eq!(records.open(entry(1), 0, 0), Ok(reader), "an attributes open beside an exclusive one");
        let mut other = FileRecords::empty();
        other.open(entry(1), 0, 0).unwrap();
        assert!(other.open(entry(1), ACCESS_READ | ACCESS_WRITE, 0).is_ok(), "and before one");
    }

    /// IoCheckShareAccess both ways: a new open must share what existing opens use, and must use
    /// only what they all share.
    #[test]
    fn the_share_check_runs_both_ways() {
        let mut access = ShareAccess::default();
        access.add(ACCESS_READ, ACCESS_READ | ACCESS_WRITE);
        assert!(access.allows(ACCESS_WRITE, ACCESS_READ), "a writer sharing the reader's read");
        assert!(!access.allows(ACCESS_WRITE, ACCESS_WRITE), "but not sharing read");
        assert!(!access.allows(ACCESS_DELETE, SHARE_ALL), "delete is not shared");
        access.add(ACCESS_WRITE, ACCESS_READ);
        assert!(!access.allows(ACCESS_WRITE, SHARE_ALL), "the writer does not share writes");
        access.remove(ACCESS_WRITE, ACCESS_READ);
        assert!(access.allows(ACCESS_WRITE, SHARE_ALL));
        access.remove(ACCESS_READ, ACCESS_READ | ACCESS_WRITE);
        assert_eq!(access, ShareAccess::default());
    }

    /// Delete-on-close is the file's, not the handle's: the flagged open's cleanup marks it
    /// pending, new opens are refused meanwhile, and the last cleanup — whichever open's — deletes.
    #[test]
    fn delete_on_close_waits_for_the_last_cleanup() {
        let mut records = FileRecords::empty();
        let flagged = records.open(entry(1), ACCESS_READ | ACCESS_DELETE, SHARE_ALL).unwrap();
        let other = records.open(entry(1), ACCESS_READ, SHARE_ALL).unwrap();
        assert_eq!(flagged, other);
        assert_eq!(records.cleanup(flagged, ACCESS_READ | ACCESS_DELETE, SHARE_ALL, true), None, "another open remains");
        assert_eq!(records.open(entry(1), ACCESS_READ, SHARE_ALL), Err(OpenError::DeletePending));
        assert!(records.delete_pending(flagged));
        assert_eq!(records.cleanup(other, ACCESS_READ, SHARE_ALL, false), Some(entry(1)), "the last cleanup deletes");
        records.close(flagged);
        records.close(other);
        assert_eq!(records.live(), 0);
    }

    /// A disposition marks an open file pending (it goes with the last open's cleanup) and can take
    /// the mark back.
    #[test]
    fn a_disposition_marks_the_file_pending() {
        let mut records = FileRecords::empty();
        let open = records.open(entry(1), ACCESS_DELETE, SHARE_ALL).unwrap();
        let other = records.open(entry(1), ACCESS_READ, SHARE_ALL).unwrap();
        records.set_delete_pending(open, true);
        records.set_delete_pending(open, false);
        assert_eq!(records.cleanup(open, ACCESS_DELETE, SHARE_ALL, false), None, "taken back");
        records.set_delete_pending(other, true);
        assert_eq!(records.cleanup(other, ACCESS_READ, SHARE_ALL, false), Some(entry(1)), "the last cleanup deletes");
    }

    /// The record is the one copy of the file every open sees: a write through one open shows
    /// to the others, and a rename by path re-keys the record.
    #[test]
    fn every_open_sees_the_records_file() {
        let mut records = FileRecords::empty();
        let a = records.open(entry(1), ACCESS_WRITE, SHARE_ALL).unwrap();
        let b = records.open(entry(1), ACCESS_WRITE, SHARE_ALL).unwrap();
        records.get_mut(a).file.size = 4096;
        records.get_mut(a).file.first_cluster = 9;
        assert_eq!((records.get(b).file.size, records.get(b).file.first_cluster), (4096, 9));
        let mut moved = records.get(a).file;
        moved.parent_cluster = 7;
        moved.index = 4;
        let old = records.get(a).file;
        records.refresh(&old, &moved);
        assert_eq!(records.find(&moved), Some(a));
        assert_eq!(records.find(&old), None);
    }

    /// The record goes with its last reference, which a mapping can hold past the cleanups.
    #[test]
    fn a_record_lives_while_referenced() {
        let mut records = FileRecords::empty();
        let index = records.open(entry(1), ACCESS_READ, SHARE_ALL).unwrap();
        assert_eq!(records.cleanup(index, ACCESS_READ, SHARE_ALL, false), None);
        assert_eq!(records.live(), 1, "an object still references it");
        assert!(records.open(entry(1), ACCESS_WRITE, 0).is_ok(), "its share access went with the cleanup");
        records.close(index);
        records.close(index);
        assert_eq!(records.live(), 0);
    }

    /// The generic rights map onto the file rights, and the share check reads data access alone.
    #[test]
    fn generic_rights_map_onto_file_rights() {
        use rights::*;
        assert_eq!(mapped(GENERIC_READ), 0x0012_0089);
        assert_eq!(mapped(GENERIC_WRITE), 0x0012_0116);
        assert_eq!(mapped(GENERIC_EXECUTE), 0x0012_00A0);
        assert_eq!(mapped(GENERIC_ALL), FILE_ALL_ACCESS);
        assert_eq!(mapped(MAXIMUM_ALLOWED), FILE_ALL_ACCESS);
        assert_eq!(mapped(DELETE | SYNCHRONIZE), DELETE | SYNCHRONIZE);
        assert_eq!(share_access(mapped(GENERIC_READ)), ACCESS_READ);
        assert_eq!(share_access(mapped(GENERIC_WRITE)), ACCESS_WRITE);
        assert_eq!(share_access(FILE_EXECUTE | SYNCHRONIZE), ACCESS_READ, "a current directory's traverse");
        assert_eq!(share_access(DELETE), ACCESS_DELETE);
        assert_eq!(share_access(FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES | SYNCHRONIZE), 0);
    }

    /// The records exhaust at their capacity.
    #[test]
    fn the_records_exhaust() {
        let mut records = FileRecords::empty();
        for index in 0..FILE_RECORDS as u32 {
            records.open(entry(index + 1), ACCESS_READ, SHARE_ALL).unwrap();
        }
        assert_eq!(records.open(entry(1000), ACCESS_READ, SHARE_ALL), Err(OpenError::Full));
        assert_eq!(records.clear(), FILE_RECORDS);
    }
}
