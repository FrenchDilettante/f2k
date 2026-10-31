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

use core::cell::UnsafeCell;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};

use super::fat32::lookup::File;
use super::search::Search;
#[cfg(target_arch = "x86")]
use crate::level::{self, High, LevelCell};
use crate::sched::dispatcher::Dispatcher;
use crate::sched::event::{Event, EventKind};
use crate::sched::thread::ThreadId;
use crate::sched::wait::{ClockStamp, WaitDisposition, WaitMode, WaitReason, WaitableId};

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
    pub const FILE_GENERIC_READ: u32 =
        READ_CONTROL | FILE_READ_DATA | FILE_READ_ATTRIBUTES | FILE_READ_EA | SYNCHRONIZE;
    pub const FILE_GENERIC_WRITE: u32 = READ_CONTROL
        | FILE_WRITE_DATA
        | FILE_WRITE_ATTRIBUTES
        | FILE_WRITE_EA
        | FILE_APPEND_DATA
        | SYNCHRONIZE;
    pub const FILE_GENERIC_EXECUTE: u32 =
        READ_CONTROL | FILE_READ_ATTRIBUTES | FILE_EXECUTE | SYNCHRONIZE;

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
        OpenFile {
            file,
            position: 0,
            access: ACCESS_READ,
            share: SHARE_ALL,
            delete_on_close: false,
        }
    }

    /// How many bytes a read of `count` at the position moves (see [`available`]).
    #[cfg(test)]
    pub fn available(&self, count: u32) -> u32 {
        available(self.position, self.file.size, count)
    }
}

/// A file object's body: one open of one file.
///
/// What its open set (its record, its access and rights, its sharing, its options) is never written
/// again once the object is published, and reads freely through a shared reference. What its calls
/// move, the position and the directory search ([`IoState`]), sits in a cell its lock guards: only
/// the lock's holder reaches it ([`FileObject::serialized`]).
pub struct FileObject {
    /// The file's record.
    pub record: FileRecordId,
    /// The access granted, as the share check reads it.
    pub access: u8,
    /// The access granted, the file rights the generic ones map to (FILE_READ_DATA,
    /// FILE_WRITE_ATTRIBUTES, DELETE, ...): what each service checks.
    pub granted: u32,
    /// The sharing allowed others.
    pub share: u8,
    /// Whether the file goes with this open's cleanup (FILE_DELETE_ON_CLOSE).
    pub delete_on_close: bool,
    /// Whether the object keeps a position (opened for synchronous I/O): a read or write without
    /// an offset uses and moves it.
    pub synchronous: bool,
    /// The synchronous-I/O lock: a call reading, writing or moving the position through the
    /// object holds it, so the position moves one call at a time (FO_SYNCHRONOUS_IO's
    /// serialization).
    pub lock: FileLock,
    /// The position and the search, reached by the lock's holder only.
    io: UnsafeCell<IoState>,
}

/// What a file object's calls move under its lock.
pub struct IoState {
    /// Where the next read or write starts.
    pub position: u64,
    /// The directory search the object's queries continue (none before the first query): the
    /// file object's own, as Windows 2000 keeps it in the object's context block, so it goes with
    /// the object.
    pub search: Option<Search>,
}

impl FileObject {
    /// A file object of `record`, at its start, synchronous; call [`FileObject::init`] at its final
    /// address.
    pub const fn new(record: FileRecordId, access: u8, granted: u32, share: u8) -> Self {
        FileObject {
            record,
            access,
            granted,
            share,
            delete_on_close: false,
            synchronous: true,
            lock: FileLock::new(),
            io: UnsafeCell::new(IoState {
                position: 0,
                search: None,
            }),
        }
    }

    /// A pool's fresh record: overwritten by the object manager's create before any use, so its
    /// record is never read.
    pub const fn none() -> Self {
        FileObject::new(FileRecordId(0), 0, 0, 0)
    }

    /// Name the lock's event by its address; call once at the final address.
    pub fn init(&mut self) {
        self.lock.init();
    }

    /// Run `body` on the position and the search, holding the object's lock: taken first (blocking
    /// while another call holds it), released once `body` is done. The caller is inside a critical
    /// region, as for any lock held across a wait (the body's disk reads): see
    /// [`crate::fs::io::serialized`].
    #[cfg(target_arch = "x86")]
    pub fn serialized<R>(&self, body: impl FnOnce(&mut IoState) -> R) -> R {
        self.lock.acquire();
        // SAFETY: the running thread holds the lock, and every way to the cell goes through it, so
        // this is the only reference to the state until the release below.
        let result = body(unsafe { &mut *self.io.get() });
        self.lock.release();
        result
    }
}

/// The priority increment a release grants the waiter its event wakes: none, as
/// IopReleaseFileObjectLock's KeSetEvent grants.
const RELEASE_INCREMENT: i8 = 0;

/// A file object's synchronous-I/O lock, in Windows 2000's shape: a busy flag, a count of the
/// threads waiting, and a synchronization event (FILE_OBJECT's Busy, Waiters and Lock).
///
/// Taking it sets the busy flag when it is clear (IopAcquireFastLock); otherwise the taker counts
/// itself among the waiters and loops: try the flag again, else wait on the event
/// (IopAcquireFileObjectLock). Releasing clears the flag and, when anyone waits, sets the event
/// with no priority increment (IopReleaseFileObjectLock). The release hands nothing over: the
/// waiter the event readies takes its chance when it runs, and the releasing thread may take the
/// lock straight back before then; a waiter that finds it taken again waits again. A signal set
/// while its waiter is not parked yet stays on the event and lets the next wait through, to try
/// the flag once more.
///
/// The holder may block under the lock (a read's disk waits), so it is taken only inside a
/// critical region. The holder is recorded, and a holder taking the lock again is refused: it
/// would wait for itself.
pub struct FileLock {
    busy: AtomicBool,
    waiters: AtomicU32,
    /// The holding thread ([`crate::block::lock::identity`]); 0 while the lock is free.
    owner: AtomicUsize,
    event: UnsafeCell<Event>,
}

impl FileLock {
    /// A free lock, its event clear (KeInitializeEvent(SynchronizationEvent, FALSE)). Call
    /// [`FileLock::init`] once it is at its final address.
    pub const fn new() -> Self {
        FileLock {
            busy: AtomicBool::new(false),
            waiters: AtomicU32::new(0),
            owner: AtomicUsize::new(0),
            event: UnsafeCell::new(Event::new(EventKind::Synchronization, false)),
        }
    }

    /// Name the event by its address; once, at the lock's final address.
    pub fn init(&mut self) {
        self.event.get_mut().init();
    }

    /// Whether a thread holds the lock.
    #[cfg(test)]
    fn is_busy(&self) -> bool {
        self.busy.load(Ordering::SeqCst)
    }

    /// The event's name, as the dispatcher takes it: its header's address. No reference to the
    /// event is formed: the dispatcher may be walking its waiters meanwhile.
    fn event(&self) -> WaitableId {
        // SAFETY: a projection inside the lock's own cell, live as long as `self`: it computes the
        // header's address and reads nothing.
        let header = unsafe { core::ptr::addr_of_mut!((*self.event.get()).waitable) };
        WaitableId::Embedded(NonNull::new(header).expect("a lock is not null"))
    }

    /// Set the busy flag for `taker` if it is clear: whether `taker` holds the lock now.
    fn take(&self, taker: ThreadId) -> bool {
        let taker = crate::block::lock::identity(taker);
        assert_ne!(
            self.owner.load(Ordering::SeqCst),
            taker,
            "a file object's lock taken again by its owner"
        );
        if self.busy.swap(true, Ordering::SeqCst) {
            return false;
        }
        self.owner.store(taker, Ordering::SeqCst);
        true
    }

    /// Park `thread` on the event, or let it through at once when a signal waits there (the switch
    /// away is the caller's business, as with any wait).
    fn wait_for(
        &self,
        dispatcher: &mut Dispatcher,
        thread: ThreadId,
        stamp: ClockStamp,
    ) -> WaitDisposition {
        dispatcher.wait_for(
            thread,
            self.event(),
            WaitReason::Executive,
            WaitMode::Kernel,
            false,
            None,
            stamp,
        )
    }

    /// Clear the busy flag: whether anyone waits, so the event is to be set.
    fn free(&self) -> bool {
        self.owner.store(0, Ordering::SeqCst);
        assert!(
            self.busy.swap(false, Ordering::SeqCst),
            "releasing a file object's lock nobody holds"
        );
        self.waiters.load(Ordering::SeqCst) != 0
    }

    /// Give the lock up, setting the event when anyone waits (see [`FileLock`]).
    #[cfg(test)]
    fn release_with(&self, dispatcher: &mut Dispatcher) {
        if self.free() {
            dispatcher.set_event(self.event(), RELEASE_INCREMENT);
        }
    }

    /// Take the lock for the running thread, blocking while another holds it.
    #[cfg(target_arch = "x86")]
    fn acquire(&self) {
        let running = crate::sched::current_thread();
        if self.take(running) {
            return;
        }
        self.waiters.fetch_add(1, Ordering::SeqCst);
        while !self.take(running) {
            // A non-alertable kernel wait ends by the event's signal (a kernel APC's break
            // re-enters the same wait); the flag is tried again either way.
            let _ = crate::sched::wait::wait_current_with(|dispatcher, thread, stamp, _replay| {
                self.wait_for(dispatcher, thread, stamp)
            });
        }
        self.waiters.fetch_sub(1, Ordering::SeqCst);
    }

    /// Give up the lock the running thread holds; the dispatcher is needed only to set the event.
    #[cfg(target_arch = "x86")]
    fn release(&self) {
        if self.free() {
            crate::level::raised::<crate::level::Dispatch, _>(|dispatch| {
                crate::sched::DISPATCHER
                    .get(dispatch)
                    .set_event(self.event(), RELEASE_INCREMENT);
            });
        }
    }
}

impl Default for FileLock {
    fn default() -> Self {
        FileLock::new()
    }
}

/// An open file's record, as the file objects of its opens name it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct FileRecordId(u16);

#[cfg(test)]
impl FileRecordId {
    /// The record at `index`, for the object manager's tests, which make file objects without
    /// records.
    pub(crate) const fn at(index: u16) -> Self {
        FileRecordId(index)
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
        let (read, write, delete) = (
            access & ACCESS_READ != 0,
            access & ACCESS_WRITE != 0,
            access & ACCESS_DELETE != 0,
        );
        if !(read || write || delete) {
            return true;
        }
        let (shares_read, shares_write, shares_delete) = (
            share & ACCESS_READ != 0,
            share & ACCESS_WRITE != 0,
            share & ACCESS_DELETE != 0,
        );
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
    /// How many mappings of the file exist (a data section, or the file's image segment, holds
    /// its file object).
    pub user_mapped: u16,
    /// The file's image segment, which every image section of the file shares (NT's section
    /// object pointers): none, or a stale id, until an image section of the file makes one.
    pub image: Option<crate::ob::SegmentId>,
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
    /// No file open: a constant, so the kernel's records are built at compile time.
    pub const fn empty() -> Self {
        FileRecords {
            records: [None; FILE_RECORDS],
        }
    }

    /// The record of the entry `file` names, if it is open.
    pub fn find(&self, file: &File) -> Option<FileRecordId> {
        self.records
            .iter()
            .position(|record| record.is_some_and(|record| same_entry(&record.file, file)))
            .map(|index| FileRecordId(index as u16))
    }

    /// The entry `file` names as its record holds it, when it is open (the current copy); else
    /// `file` itself.
    pub fn current(&self, file: File) -> File {
        self.find(&file)
            .map_or(file, |record| self.get(record).file)
    }

    /// Open the entry `file` names for `access`, allowing `share`: its record (made when the file
    /// is not open yet), counted for one more open. Refused while a delete is pending, when an open
    /// in place excludes it, or when every record is taken.
    pub fn open(&mut self, file: File, access: u8, share: u8) -> Result<FileRecordId, OpenError> {
        let index = match self.find(&file) {
            Some(FileRecordId(index)) => {
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
                let index = self
                    .records
                    .iter()
                    .position(Option::is_none)
                    .ok_or(OpenError::Full)? as u16;
                self.records[index as usize] = Some(FileRecord {
                    file,
                    share: ShareAccess::default(),
                    cleanups: 0,
                    references: 0,
                    delete_pending: false,
                    user_mapped: 0,
                    image: None,
                });
                index
            }
        };
        let record = self.records[index as usize].as_mut().expect("just taken");
        record.share.add(access, share);
        record.cleanups += 1;
        record.references += 1;
        Ok(FileRecordId(index))
    }

    /// The record `record` (a live object names it).
    pub fn get(&self, record: FileRecordId) -> &FileRecord {
        self.records[record.0 as usize]
            .as_ref()
            .expect("an open names a live record")
    }

    /// The record `record`, mutably.
    pub fn get_mut(&mut self, record: FileRecordId) -> &mut FileRecord {
        self.records[record.0 as usize]
            .as_mut()
            .expect("an open names a live record")
    }

    /// The entry `old` named changed into `new` (a change made by path, or a rename): an open
    /// record of it follows.
    pub fn refresh(&mut self, old: &File, new: &File) {
        if let Some(record) = self.find(old) {
            self.get_mut(record).file = *new;
        }
    }

    /// Set or clear the pending delete of the open file `record` (FileDispositionInformation): it
    /// goes with its last open's cleanup.
    pub fn set_delete_pending(&mut self, record: FileRecordId, pending: bool) {
        self.get_mut(record).delete_pending = pending;
    }

    /// Whether the open file `record` goes with its last cleanup.
    pub fn delete_pending(&self, record: FileRecordId) -> bool {
        self.get(record).delete_pending
    }

    /// An open's last handle closed (its cleanup): its share access goes, its delete-on-close marks
    /// the file delete-pending. Returns the file to delete now: the last cleanup of a
    /// delete-pending file.
    pub fn cleanup(
        &mut self,
        record: FileRecordId,
        access: u8,
        share: u8,
        delete_on_close: bool,
    ) -> Option<File> {
        let record = self.get_mut(record);
        record.share.remove(access, share);
        record.cleanups -= 1;
        record.delete_pending |= delete_on_close;
        (record.cleanups == 0 && record.delete_pending).then_some(record.file)
    }

    /// An open's last reference went: the record goes with the last one.
    pub fn close(&mut self, record: FileRecordId) {
        let entry = self.get_mut(record);
        entry.references -= 1;
        if entry.references == 0 {
            self.records[record.0 as usize] = None;
        }
    }

    /// Forget every record (at quiescence, once every process's opens were closed), returning how
    /// many were still taken.
    pub fn clear(&mut self) -> usize {
        let live = self.live();
        for record in self.records.iter_mut() {
            *record = None;
        }
        live
    }

    /// How many records are taken.
    pub fn live(&self) -> usize {
        self.records
            .iter()
            .filter(|record| record.is_some())
            .count()
    }
}

/// The kernel's file records (Windows 2000's FCB table).
///
/// No interrupt and no DPC reaches them: their callers are system services and the idle thread's
/// reap, which run with interrupts masked. Each step is short: a record copied out, written back or
/// counted, never across a wait (a disk read, the volume's lock, a file object's lock), a copy of
/// caller memory or other high-level state. A change that spans a volume I/O is made under the
/// volume's lock, the record read before the I/O and written back after it, each in a step of its
/// own. So the records live at the high level, reached through the bridge: each step masks
/// interrupts for its own length, as its callers have already, which keeps the interrupt exposure
/// as it was, and a step reaching the records from inside another's borrow is refused.
// Note: Windows 2000 keeps the FCB table under the volume's lock (the VCB's ERESOURCE), a
// passive-level lock. That is the faithful protection, to adopt together with the object
// directory's lock.
#[cfg(target_arch = "x86")]
static RECORDS: LevelCell<High, FileRecords> = LevelCell::new(FileRecords::empty());

/// Run `step` on the kernel's file records (see [`RECORDS`]), through the bridge to the high level.
///
/// # Panics
///
/// The processor is already at the high level: `step`, or code it calls, reaching the records
/// again from inside its own borrow, or the caller holding other high-level state.
#[cfg(target_arch = "x86")]
pub fn with_records<R>(step: impl FnOnce(&mut FileRecords) -> R) -> R {
    level::raised::<High, _>(|high| step(RECORDS.get(high)))
}

#[cfg(test)]
mod lock_tests {
    use super::*;
    use crate::sched::process::SchedProcess;
    use crate::sched::testkit::Rec;
    use crate::sched::thread::{Thread, ThreadState};

    const NOW: ClockStamp = ClockStamp {
        interrupt_time: 0,
        tick: 0,
    };

    fn dispatcher() -> &'static mut Dispatcher {
        crate::sched::testkit::dispatcher()
    }

    fn lock() -> &'static FileLock {
        let lock = Box::leak(Box::new(FileLock::new()));
        lock.init();
        lock
    }

    /// A running thread of the installed dispatcher, and its name.
    fn thread() -> (Rec<Thread>, ThreadId) {
        let process = Box::leak(Box::new(SchedProcess::new(0x0090_0000, 8)));
        let mut thread = crate::sched::testkit::thread(process);
        thread.state = ThreadState::Running;
        let id = ThreadId::from(&*thread);
        (thread, id)
    }

    /// The readied `thread` (the only one) selected and running.
    fn run(d: &mut Dispatcher, thread: &mut Rec<Thread>, id: ThreadId) {
        assert_eq!(d.select_next(), Some(id));
        thread.state = ThreadState::Running;
    }

    fn signaled(lock: &FileLock) -> bool {
        // SAFETY: a test's lock, on one thread: nothing else reaches the event meanwhile.
        unsafe { (*lock.event.get()).signaled() }
    }

    /// The acquisition's slow path up to its wait: the taker counted among the waiters, the flag
    /// tried, and the wait on the event entered.
    fn contend(d: &mut Dispatcher, lock: &FileLock, taker: ThreadId) -> WaitDisposition {
        lock.waiters.fetch_add(1, Ordering::SeqCst);
        assert!(!lock.take(taker), "the flag is set");
        lock.wait_for(d, taker, NOW)
    }

    /// A free lock is taken at once and leaves the event alone; a second taker finds the flag set
    /// and parks on the event.
    #[test]
    fn a_held_lock_parks_the_second_taker() {
        let d = dispatcher();
        let lock = lock();
        let (_holder, h) = thread();
        let (waiter, w) = thread();
        assert!(!lock.is_busy());
        assert!(lock.take(h));
        assert!(lock.is_busy());
        assert!(!signaled(lock));
        assert_eq!(contend(d, lock, w), WaitDisposition::Yield);
        assert_eq!(waiter.state(), ThreadState::Waiting);
    }

    /// Windows 2000's release hands nothing over: it frees the lock and readies the waiter, and
    /// the releasing thread may take the lock straight back before the waiter runs; the waiter
    /// then finds it taken and waits again. A release with nobody waiting leaves the event clear.
    #[test]
    fn the_release_readies_a_waiter_without_handing_it_the_lock() {
        let d = dispatcher();
        let lock = lock();
        let (_holder, h) = thread();
        let (mut waiter, w) = thread();
        assert!(lock.take(h));
        assert_eq!(contend(d, lock, w), WaitDisposition::Yield);

        lock.release_with(d);
        assert_ne!(waiter.state(), ThreadState::Waiting, "the event readies it");
        assert!(!lock.is_busy(), "and the lock is left free");
        assert!(!signaled(lock), "the signal served the waiter");
        assert!(lock.take(h), "the releasing thread takes it straight back");

        // The waiter runs: the flag is set again, so it waits again.
        run(d, &mut waiter, w);
        assert!(!lock.take(w));
        assert_eq!(lock.wait_for(d, w, NOW), WaitDisposition::Yield);

        lock.release_with(d);
        run(d, &mut waiter, w);
        assert!(lock.take(w), "the woken waiter takes the free lock");
        lock.waiters.fetch_sub(1, Ordering::SeqCst);
        lock.release_with(d);
        assert!(!lock.is_busy());
        assert!(!signaled(lock), "nobody waits: the event is not set");
    }

    /// A release while its waiter is counted but not parked yet leaves the signal on the event:
    /// the waiter takes the free flag without waiting, and the signal lets the next wait through
    /// once, to try the flag again.
    #[test]
    fn a_signal_left_on_the_event_lets_one_wait_through() {
        let d = dispatcher();
        let lock = lock();
        let (_first, a) = thread();
        let (_second, b) = thread();
        assert!(lock.take(a));
        lock.waiters.fetch_add(1, Ordering::SeqCst);
        assert!(!lock.take(b));
        lock.release_with(d);
        assert!(signaled(lock), "nobody parked: the signal stays");
        assert!(lock.take(b), "the counted waiter finds the flag clear");
        lock.waiters.fetch_sub(1, Ordering::SeqCst);

        assert!(matches!(contend(d, lock, a), WaitDisposition::Complete(_)));
        assert!(!signaled(lock), "the wait consumed the signal");
        assert!(!lock.take(a), "the flag is still set");
        assert_eq!(lock.wait_for(d, a, NOW), WaitDisposition::Yield);
    }

    /// The holder taking the lock again would wait for itself: refused.
    #[test]
    #[should_panic(expected = "taken again by its owner")]
    fn the_holder_taking_the_lock_again_is_refused() {
        let _d = dispatcher();
        let lock = lock();
        let (_holder, h) = thread();
        assert!(lock.take(h));
        lock.take(h);
    }

    #[test]
    #[should_panic(expected = "nobody holds")]
    fn releasing_a_free_lock_is_a_contract_violation() {
        lock().release_with(dispatcher());
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
        assert_eq!(
            records.open(entry(1), ACCESS_READ, SHARE_ALL),
            Err(OpenError::Sharing)
        );
        assert!(records.cleanup(first, ACCESS_READ, 0, false).is_none());
        records.close(first);
        let reader = records.open(entry(1), ACCESS_READ, ACCESS_READ).unwrap();
        assert_eq!(
            records.open(entry(1), ACCESS_READ, ACCESS_READ),
            Ok(reader),
            "one record"
        );
        assert_eq!(
            records.open(entry(1), ACCESS_READ, 0),
            Err(OpenError::Sharing),
            "exclusive"
        );
        assert_eq!(
            records.open(entry(1), ACCESS_WRITE, SHARE_ALL),
            Err(OpenError::Sharing),
            "not shared"
        );
        assert!(
            records.open(entry(9), ACCESS_READ, 0).is_ok(),
            "another entry"
        );
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
        assert_eq!(
            records.open(spelled, ACCESS_WRITE | ACCESS_DELETE, 0),
            Err(OpenError::Sharing)
        );
    }

    /// An open asking no data access (attributes only) neither checks nor counts, whichever
    /// comes first.
    #[test]
    fn opens_without_data_access_take_no_part() {
        let mut records = FileRecords::empty();
        let reader = records.open(entry(1), ACCESS_READ, 0).unwrap();
        assert_eq!(
            records.open(entry(1), 0, 0),
            Ok(reader),
            "an attributes open beside an exclusive one"
        );
        let mut other = FileRecords::empty();
        other.open(entry(1), 0, 0).unwrap();
        assert!(
            other.open(entry(1), ACCESS_READ | ACCESS_WRITE, 0).is_ok(),
            "and before one"
        );
    }

    /// IoCheckShareAccess both ways: a new open must share what existing opens use, and must use
    /// only what they all share.
    #[test]
    fn the_share_check_runs_both_ways() {
        let mut access = ShareAccess::default();
        access.add(ACCESS_READ, ACCESS_READ | ACCESS_WRITE);
        assert!(
            access.allows(ACCESS_WRITE, ACCESS_READ),
            "a writer sharing the reader's read"
        );
        assert!(
            !access.allows(ACCESS_WRITE, ACCESS_WRITE),
            "but not sharing read"
        );
        assert!(
            !access.allows(ACCESS_DELETE, SHARE_ALL),
            "delete is not shared"
        );
        access.add(ACCESS_WRITE, ACCESS_READ);
        assert!(
            !access.allows(ACCESS_WRITE, SHARE_ALL),
            "the writer does not share writes"
        );
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
        let flagged = records
            .open(entry(1), ACCESS_READ | ACCESS_DELETE, SHARE_ALL)
            .unwrap();
        let other = records.open(entry(1), ACCESS_READ, SHARE_ALL).unwrap();
        assert_eq!(flagged, other);
        assert_eq!(
            records.cleanup(flagged, ACCESS_READ | ACCESS_DELETE, SHARE_ALL, true),
            None,
            "another open remains"
        );
        assert_eq!(
            records.open(entry(1), ACCESS_READ, SHARE_ALL),
            Err(OpenError::DeletePending)
        );
        assert!(records.delete_pending(flagged));
        assert_eq!(
            records.cleanup(other, ACCESS_READ, SHARE_ALL, false),
            Some(entry(1)),
            "the last cleanup deletes"
        );
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
        assert_eq!(
            records.cleanup(open, ACCESS_DELETE, SHARE_ALL, false),
            None,
            "taken back"
        );
        records.set_delete_pending(other, true);
        assert_eq!(
            records.cleanup(other, ACCESS_READ, SHARE_ALL, false),
            Some(entry(1)),
            "the last cleanup deletes"
        );
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
        assert_eq!(
            (records.get(b).file.size, records.get(b).file.first_cluster),
            (4096, 9)
        );
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
        assert!(
            records.open(entry(1), ACCESS_WRITE, 0).is_ok(),
            "its share access went with the cleanup"
        );
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
        assert_eq!(
            share_access(FILE_EXECUTE | SYNCHRONIZE),
            ACCESS_READ,
            "a current directory's traverse"
        );
        assert_eq!(share_access(DELETE), ACCESS_DELETE);
        assert_eq!(
            share_access(FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES | SYNCHRONIZE),
            0
        );
    }

    /// The records exhaust at their capacity.
    #[test]
    fn the_records_exhaust() {
        let mut records = FileRecords::empty();
        for index in 0..FILE_RECORDS as u32 {
            records
                .open(entry(index + 1), ACCESS_READ, SHARE_ALL)
                .unwrap();
        }
        assert_eq!(
            records.open(entry(1000), ACCESS_READ, SHARE_ALL),
            Err(OpenError::Full)
        );
        assert_eq!(records.clear(), FILE_RECORDS);
    }
}
