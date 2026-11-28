//! The dispatcher database: the records the dispatcher owns, and how its lists reach them.
//!
//! Windows 2000 keeps its dispatcher objects — the thread records (KTHREAD) and the bodies of the
//! objects threads wait on (DISPATCHER_HEADER and their type's fields) — in one database the
//! dispatcher lock guards. Here that database lives inside the [`Dispatcher`]: the event,
//! semaphore, mutex and waitable-timer bodies in side tables ([`SideTable`]) that grow a page at a
//! time from the nonpaged pool, made at an index before the object directory hands that index out
//! ([`Dispatcher::ensure_body`]) and kept at their peak, so a body never moves. A process object's
//! body and its process's user-APC records are side tables' too, keyed by the process object's
//! index, made with the object: Windows 2000 keeps a process's KPROCESS and its APCs with its
//! EPROCESS, in the nonpaged pool. The thread records (KTHREAD) are a side table too, keyed by the
//! thread object's index, made before the object directory hands the index out
//! ([`Dispatcher::ensure_thread`]): no cap but memory, as Windows 2000's threads have none. The
//! system threads, which no object names, hold its first indices ([`SYSTEM_THREADS`]). The object
//! directory keeps the objects' headers (liveness, generation, counts) and names a body by its
//! index, which is the same in both.
//!
//! Every list the dispatcher keeps links these records by name, and the dispatcher resolves the
//! names: an [`Arena`] for each list kind. Two kinds of record are reached by address instead, as
//! the context switch reaches them: a process's scheduling record (the process pool's, pinned),
//! which a thread names as its owner, and a waitable header embedded in a structure of its own
//! (see [`WaitableId::Embedded`]).

use core::ptr::NonNull;

use super::apc::{Apc, ApcId, ApcQueue};
use super::dispatcher::{Dispatcher, ReadyQueue};
use super::event::{Event, EventKind};
use super::list::{Arena, IndexList, Link};
use super::mutex::{Mutex, MutexId, OwnedMutexes};
use super::process::{ProcessObject, ProcessThreads};
use super::semaphore::Semaphore;
use super::thread::{Thread, ThreadId};
use super::timer::{TimerId, TimerList};
use super::wait::{BlockId, Header, Timer, WaitBlock, Waitable, WaitableId, Waiters, WaitingList};
use super::waitable_timer::WaitableTimer;
use crate::slots::{entries_per_page, Exhausted, Pages, Record, SideTable};

/// The idle thread's record, which no object names: the first of the system threads'.
pub const IDLE_THREAD: ThreadId = ThreadId(0);

/// The console's control thread's record (see `crate::csr::ctrl`): a system thread's, which no
/// object names either.
pub const CONSOLE_CONTROL_THREAD: ThreadId = ThreadId(1);

/// win32k's raw input thread's record (see `crate::win32k::input`): a system thread's.
pub const RAW_INPUT_THREAD: ThreadId = ThreadId(2);

/// How many thread records the system threads hold, from index 0: the thread objects' indices
/// start past them (the object directory never hands these out), so no object names one.
pub const SYSTEM_THREADS: u16 = 3;

/// The thread records to a chunk: a page-aligned run of 16 (15 pages).
const THREADS_PER_CHUNK: usize = 16;

/// The thread records the directory names: one for every u16 index, the object directory's
/// representation limit, so the directory is no cap.
const THREAD_INDICES: usize = u16::MAX as usize + 1;

/// The thread records (Windows 2000's KTHREADs): chunks of [`THREADS_PER_CHUNK`] records from the
/// nonpaged pool, made as thread objects first take their indices ([`Dispatcher::ensure_thread`])
/// and kept at their peak, so a record never moves (the context switch is handed records by
/// address). No cap but the u16 index (the object directory's representation limit) and memory.
///
/// Every switch and wait resolves records by index, many times, so the directory is an array of
/// every index's record address, in the dispatcher: a resolution is one load (and the made
/// check), as the fixed pool's array was a bound check and a multiply. It is 256 KiB, a record's
/// address an index, where the fixed pool held 128 records in 480 KiB; written only through the
/// dispatcher's exclusive borrow. Measured against the fixed pool (slot-pool slice 21), the
/// alternatives cost every wait more: a tree, a fifth more instructions; a directory of chunks, a
/// tenth; a directory grown in the pool, a tenth; the first 4,096 indices' array and a chunk
/// directory past them, a twentieth. This one costs none.
pub struct ThreadRecords {
    records: [Option<NonNull<Thread>>; THREAD_INDICES],
}

impl ThreadRecords {
    /// The pages one chunk takes.
    const CHUNK_PAGES: usize =
        (THREADS_PER_CHUNK * core::mem::size_of::<Thread>()).div_ceil(crate::slots::PAGE);

    /// Write an empty table at `records`: no record made, no page held.
    ///
    /// # Safety
    ///
    /// `records` is valid for writes and aligned.
    unsafe fn write_empty(records: *mut ThreadRecords) {
        let _ = Self::CHUNK_PAGES;
        // SAFETY: the caller's contract; `None` is all zeroes in an `Option<NonNull>`.
        unsafe { records.write_bytes(0, 1) };
    }

    /// Record `index`'s address; none if it is not made.
    #[inline(always)]
    fn address(&self, index: u16) -> Option<NonNull<Thread>> {
        self.records[index as usize]
    }

    /// Make the chunk holding record `index` if it is not made, every record fresh, named by its
    /// index, with its pages from `pages`. On failure the table is as it was.
    fn ensure(&mut self, index: u16, pages: &impl Pages) -> Result<(), Exhausted> {
        if self.address(index).is_some() {
            return Ok(());
        }
        let first = index as usize / THREADS_PER_CHUNK * THREADS_PER_CHUNK;
        let at = pages
            .take(Self::CHUNK_PAGES)
            .ok_or(Exhausted::NoPages)?
            .cast::<Thread>();
        let chunk = &mut self.records[first..first + THREADS_PER_CHUNK];
        for (offset, slot) in chunk.iter_mut().enumerate() {
            // SAFETY: the pages hold the chunk's records, page-aligned (a thread record's
            // alignment divides a page's), ours alone until published here.
            unsafe {
                let record = at.add(offset);
                <Thread as Record>::write_fresh(record.as_ptr(), (first + offset) as u32);
                *slot = Some(record);
            }
        }
        Ok(())
    }
}

const _: () = assert!(
    core::mem::align_of::<Thread>() <= crate::slots::PAGE,
    "a chunk's pages align its records"
);

/// How many user-APC records each process has (QueueUserAPC's, across its threads).
pub const USER_APCS: usize = 64;

/// One process's user-APC records, at its process object's index: the record `k` of them is
/// [`ApcId::User`]`(process, k)`.
pub struct UserApcs(pub(crate) [Apc; USER_APCS]);

/// The process objects' bodies to a chunk: a page's worth.
const PROCESS_BODIES: usize = entries_per_page::<ProcessObject>();

/// The records the dispatcher owns.
pub struct Database {
    pub(crate) threads: ThreadRecords,
    pub(crate) events: SideTable<Event, { entries_per_page::<Event>() }>,
    pub(crate) semaphores: SideTable<Semaphore, { entries_per_page::<Semaphore>() }>,
    pub(crate) mutexes: SideTable<Mutex, { entries_per_page::<Mutex>() }>,
    pub(crate) timers: SideTable<WaitableTimer, { entries_per_page::<WaitableTimer>() }>,
    pub(crate) processes: SideTable<ProcessObject, PROCESS_BODIES>,
    pub(crate) user_apcs: SideTable<UserApcs, 1>,
}

impl Database {
    /// Write an empty database at `database`: the side tables empty, no page held.
    ///
    /// # Safety
    ///
    /// `database` is valid for writes, aligned, and the records' final address; its previous
    /// contents are overwritten, not dropped.
    pub unsafe fn write_empty(database: *mut Database) {
        use core::ptr::addr_of_mut;
        // SAFETY: the caller's contract; every field is written.
        unsafe {
            ThreadRecords::write_empty(addr_of_mut!((*database).threads));
            addr_of_mut!((*database).events).write(SideTable::new());
            addr_of_mut!((*database).semaphores).write(SideTable::new());
            addr_of_mut!((*database).mutexes).write(SideTable::new());
            addr_of_mut!((*database).timers).write(SideTable::new());
            addr_of_mut!((*database).processes).write(SideTable::new());
            addr_of_mut!((*database).user_apcs).write(SideTable::new());
        }
    }
}

// The side tables' records: a body is written fresh, named by its index, when its chunk is made,
// and renewed by its object's create.

// SAFETY: writes a whole record.
unsafe impl Record for Thread {
    unsafe fn write_fresh(at: *mut Self, index: u32) {
        // SAFETY: the caller's contract.
        unsafe { at.write(Thread::new(ThreadId(index as u16))) };
    }
}

// SAFETY: writes a whole record.
unsafe impl Record for Event {
    unsafe fn write_fresh(at: *mut Self, index: u32) {
        // SAFETY: the caller's contract.
        unsafe { at.write(Event::record(index as u16, EventKind::Notification, false)) };
    }
}

// SAFETY: writes a whole record.
unsafe impl Record for Semaphore {
    unsafe fn write_fresh(at: *mut Self, index: u32) {
        // SAFETY: the caller's contract.
        unsafe { at.write(Semaphore::with_id(0, WaitableId::Semaphore(index as u16))) };
    }
}

// SAFETY: writes a whole record.
unsafe impl Record for Mutex {
    unsafe fn write_fresh(at: *mut Self, index: u32) {
        // SAFETY: the caller's contract.
        unsafe { at.write(Mutex::new(MutexId(index as u16))) };
    }
}

// SAFETY: writes a whole record.
unsafe impl Record for ProcessObject {
    unsafe fn write_fresh(at: *mut Self, index: u32) {
        // SAFETY: the caller's contract.
        unsafe { at.write(ProcessObject::new(index as u16)) };
    }
}

// SAFETY: writes every record of the array.
unsafe impl Record for UserApcs {
    unsafe fn write_fresh(at: *mut Self, index: u32) {
        let records = at.cast::<Apc>();
        for k in 0..USER_APCS {
            // SAFETY: the caller's contract: the array's every element, in place (by value it
            // would pass through the stack).
            unsafe {
                records
                    .add(k)
                    .write(Apc::new(ApcId::User(index as u16, k as u8)))
            };
        }
    }
}

// SAFETY: writes a whole record.
unsafe impl Record for WaitableTimer {
    unsafe fn write_fresh(at: *mut Self, index: u32) {
        // SAFETY: the caller's contract.
        unsafe { at.write(WaitableTimer::new(index as u16, true)) };
    }
}

/// A thread record, made before any thread was handed its index.
#[inline(always)]
fn made_thread<T>(record: Option<T>) -> T {
    match record {
        Some(record) => record,
        None => unmade_thread(),
    }
}

#[cold]
#[inline(never)]
fn unmade_thread() -> ! {
    panic!("a thread record made before its id")
}

/// A side table's record at `index`, which its object's create made first.
///
/// # Panics
///
/// The record was never made: no object of the kind was ever handed `index`.
fn made<T>(record: Option<T>) -> T {
    record.expect("a dispatcher body made before its object's id")
}

// --- Resolving names -------------------------------------------------------------------------

impl Dispatcher {
    /// The thread record `thread`.
    ///
    /// # Panics
    ///
    /// The record was never made: no thread was ever handed `thread`.
    #[inline]
    pub fn thread(&self, thread: ThreadId) -> &Thread {
        // SAFETY: a made record, written whole at its chunk's making; changed only through the
        // dispatcher's exclusive borrow (or by the context switch and the running thread's own
        // code through its address, with the dispatcher unborrowed), so this borrow's.
        unsafe { made_thread(self.db.threads.address(thread.0)).as_ref() }
    }

    /// The thread record `thread`, to change.
    #[inline]
    pub fn thread_mut(&mut self, thread: ThreadId) -> &mut Thread {
        // SAFETY: as in `thread`, the borrow being exclusive.
        unsafe { made_thread(self.db.threads.address(thread.0)).as_mut() }
    }

    /// The address of the thread record `thread`: what the context switch is handed. Records are
    /// never given back, so it stays the record's for the kernel's life.
    pub fn thread_address(&self, thread: ThreadId) -> *mut Thread {
        made_thread(self.db.threads.address(thread.0)).as_ptr()
    }

    /// Whether the thread record `thread` is made: every thread object's and system thread's is.
    pub fn has_thread(&self, thread: ThreadId) -> bool {
        self.db.threads.address(thread.0).is_some()
    }

    /// Make the thread record `thread` (fresh, and its chunk's with it) if it is not made, with
    /// any page its table needs from `pages`: before a thread object is handed the index, and for
    /// the system threads at the boot. Takes no page once made; no record is ever given back, so
    /// the context switch's addresses stay good. Fails with the table as it was when no page is
    /// left.
    pub fn ensure_thread(&mut self, thread: ThreadId, pages: &impl Pages) -> Result<(), Exhausted> {
        self.db.threads.ensure(thread.0, pages)
    }

    /// Start the thread record `thread` over, as fresh as the pool made it.
    pub fn renew_thread(&mut self, thread: ThreadId) -> &mut Thread {
        let record = self.thread_mut(thread);
        *record = Thread::new(thread);
        record
    }

    /// The waitable header `object` names.
    pub fn waitable(&self, object: WaitableId) -> &Waitable {
        match object {
            WaitableId::Event(index) => &made(self.db.events.get(index.into())).waitable,
            WaitableId::Semaphore(index) => &made(self.db.semaphores.get(index.into())).waitable,
            WaitableId::Mutex(index) => &made(self.db.mutexes.get(index.into())).waitable,
            WaitableId::Timer(index) => &made(self.db.timers.get(index.into())).timer.waitable,
            WaitableId::Process(index) => &made(self.db.processes.get(index.into())).waitable,
            WaitableId::Thread(thread) => &self.thread(thread).waitable,
            WaitableId::ThreadTimer(thread) => &self.thread(thread).timer.waitable,
            WaitableId::Suspend(thread) => &self.thread(thread).suspend_semaphore.waitable,
            // SAFETY: an embedded header's embedder keeps it at the address its name carries,
            // alive, while anything waits on it or signals it — the only times its name is
            // resolved — and reaches it through shared borrows only meanwhile; a shared reference
            // to the header is a shared reference to its cell (see `Waitable`).
            WaitableId::Embedded(header) => unsafe { header.as_ref() },
        }
    }

    /// The contents of the waitable header `object` names, for the dispatcher to read: reached
    /// through the header's cell, for no longer than this borrow of the dispatcher (see
    /// [`Waitable`]).
    pub fn header(&self, object: WaitableId) -> &Header {
        // SAFETY: the header is live (as in `waitable`), and the serialized dispatcher is the only
        // one to form references to a header's contents: none to change them is live while this
        // borrow of the dispatcher is.
        unsafe { &*self.waitable(object).as_ptr() }
    }

    /// The contents of the waitable header `object` names, to change: reached through the
    /// header's cell, for no longer than this exclusive borrow of the dispatcher, the dispatcher
    /// lock's hold (see [`Waitable`]).
    pub fn header_mut(&mut self, object: WaitableId) -> &mut Header {
        // SAFETY: as in `header`; the exclusive borrow of the dispatcher makes this the only
        // reference to the contents while it lives: owners touch a header by value only.
        unsafe { &mut *self.waitable(object).as_ptr() }
    }

    /// The wait block `block` names.
    pub fn block(&self, block: BlockId) -> &WaitBlock {
        self.thread(block.thread).block(block.slot)
    }

    /// The wait block `block` names, to change.
    pub fn block_mut(&mut self, block: BlockId) -> &mut WaitBlock {
        self.thread_mut(block.thread).block_mut(block.slot)
    }

    /// The timer `timer` names.
    pub fn timer(&self, timer: TimerId) -> &Timer {
        match timer {
            TimerId::Thread(thread) => &self.thread(thread).timer,
            TimerId::Waitable(index) => &made(self.db.timers.get(index.into())).timer,
        }
    }

    /// The timer `timer` names, to change.
    pub fn timer_mut(&mut self, timer: TimerId) -> &mut Timer {
        match timer {
            TimerId::Thread(thread) => &mut self.thread_mut(thread).timer,
            TimerId::Waitable(index) => &mut made(self.db.timers.get_mut(index.into())).timer,
        }
    }

    /// The APC record `apc` names.
    pub fn apc(&self, apc: ApcId) -> &Apc {
        match apc {
            ApcId::Suspend(thread) => &self.thread(thread).suspend_apc,
            ApcId::Exit(thread) => &self.thread(thread).exit_apc,
            ApcId::Timer(index) => &made(self.db.timers.get(index.into())).apc,
            ApcId::User(process, k) => &made(self.db.user_apcs.get(process.into())).0[k as usize],
        }
    }

    /// The APC record `apc` names, to change.
    pub fn apc_mut(&mut self, apc: ApcId) -> &mut Apc {
        match apc {
            ApcId::Suspend(thread) => &mut self.thread_mut(thread).suspend_apc,
            ApcId::Exit(thread) => &mut self.thread_mut(thread).exit_apc,
            ApcId::Timer(index) => &mut made(self.db.timers.get_mut(index.into())).apc,
            ApcId::User(process, k) => {
                &mut made(self.db.user_apcs.get_mut(process.into())).0[k as usize]
            }
        }
    }

    /// The mutex record `mutex`.
    pub fn mutex(&self, mutex: MutexId) -> &Mutex {
        made(self.db.mutexes.get(mutex.0.into()))
    }

    /// The mutex record `mutex`, to change.
    pub fn mutex_mut(&mut self, mutex: MutexId) -> &mut Mutex {
        made(self.db.mutexes.get_mut(mutex.0.into()))
    }

    /// The event body at pool `index`, to change.
    pub fn event_mut(&mut self, index: u16) -> &mut Event {
        made(self.db.events.get_mut(index.into()))
    }

    /// The semaphore body at pool `index`, to change.
    pub fn semaphore_mut(&mut self, index: u16) -> &mut Semaphore {
        made(self.db.semaphores.get_mut(index.into()))
    }

    /// The waitable timer body at pool `index`, to change.
    pub fn waitable_timer_mut(&mut self, index: u16) -> &mut WaitableTimer {
        made(self.db.timers.get_mut(index.into()))
    }

    /// The process object body at pool `index`, to change.
    pub fn process_object_mut(&mut self, index: u16) -> &mut ProcessObject {
        made(self.db.processes.get_mut(index.into()))
    }

    /// The address of the user-APC record `apc` names, made with its process; none for another
    /// kind of APC, or a process index never made. Takes no borrow beyond the call.
    pub fn user_apc_address(&self, apc: ApcId) -> Option<core::ptr::NonNull<Apc>> {
        let ApcId::User(process, k) = apc else {
            return None;
        };
        let records = self.db.user_apcs.address(process.into())?;
        // SAFETY: a made record's element: only the address is taken.
        Some(unsafe {
            core::ptr::NonNull::new_unchecked(records.as_ptr().cast::<Apc>().add(k as usize))
        })
    }

    // --- Fresh bodies for new objects ---

    /// Make the body record `object` names, with any page its side table needs from `pages`,
    /// before an object is handed its index: an event's, a semaphore's, a mutex's, a waitable
    /// timer's, or a process object's with its process's user-APC records; a thread's (all three
    /// of its names: its object, its timer, its suspend semaphore) through
    /// [`Dispatcher::ensure_thread`].
    /// Takes no page once the record is made; no record is ever given back. Fails with the table as
    /// it was when no page is left (or, never before memory, the index is past the table's reach).
    pub fn ensure_body(&mut self, object: WaitableId, pages: &impl Pages) -> Result<(), Exhausted> {
        match object {
            WaitableId::Event(index) => self.db.events.ensure(index.into(), pages),
            WaitableId::Semaphore(index) => self.db.semaphores.ensure(index.into(), pages),
            WaitableId::Mutex(index) => self.db.mutexes.ensure(index.into(), pages),
            WaitableId::Timer(index) => self.db.timers.ensure(index.into(), pages),
            WaitableId::Process(index) => {
                // Either may be made and the other not: what is made stays, for the next process
                // at the index.
                self.db.processes.ensure(index.into(), pages)?;
                self.db.user_apcs.ensure(index.into(), pages)
            }
            WaitableId::Thread(thread)
            | WaitableId::ThreadTimer(thread)
            | WaitableId::Suspend(thread) => self.ensure_thread(thread, pages),
            WaitableId::Embedded(_) => Ok(()),
        }
    }

    /// A fresh event object of `kind` at `signaled` in the event record `index`.
    pub fn renew_event(&mut self, index: u16, kind: EventKind, signaled: bool) -> &mut Event {
        let event = made(self.db.events.get_mut(index.into()));
        *event = Event::record(index, kind, signaled);
        event
    }

    /// A fresh semaphore object at `initial` with ceiling `limit` in the semaphore record `index`.
    pub fn renew_semaphore(&mut self, index: u16, initial: i32, limit: i32) -> &mut Semaphore {
        let semaphore = made(self.db.semaphores.get_mut(index.into()));
        *semaphore = Semaphore::with_id(limit, WaitableId::Semaphore(index));
        semaphore.waitable.get_mut().signal_state = initial;
        semaphore
    }

    /// A fresh, free mutex object in the mutex record `index`.
    pub fn renew_mutex(&mut self, index: u16) -> &mut Mutex {
        let mutex = made(self.db.mutexes.get_mut(index.into()));
        *mutex = Mutex::new(MutexId(index));
        mutex
    }

    /// A fresh, unarmed, unsignaled waitable timer object in the timer record `index`.
    pub fn renew_waitable_timer(&mut self, index: u16, manual_reset: bool) -> &mut WaitableTimer {
        let timer = made(self.db.timers.get_mut(index.into()));
        *timer = WaitableTimer::new(index, manual_reset);
        timer
    }

    /// A fresh process object body, unsignaled and still active, in the record `index`.
    pub fn renew_process_object(&mut self, index: u16) -> &mut ProcessObject {
        let process = made(self.db.processes.get_mut(index.into()));
        *process = ProcessObject::new(index);
        process
    }
}

// --- The lists' arenas -------------------------------------------------------------------------

impl Arena<ReadyQueue> for Dispatcher {
    fn list(&self, list: ReadyQueue) -> &IndexList<ReadyQueue> {
        &self.ready[list.0 as usize]
    }

    fn list_mut(&mut self, list: ReadyQueue) -> &mut IndexList<ReadyQueue> {
        &mut self.ready[list.0 as usize]
    }

    fn link(&self, entry: ThreadId) -> &Link<ReadyQueue> {
        &self.thread(entry).ready_link
    }

    fn link_mut(&mut self, entry: ThreadId) -> &mut Link<ReadyQueue> {
        &mut self.thread_mut(entry).ready_link
    }
}

impl Arena<WaitingList> for Dispatcher {
    fn list(&self, _list: WaitingList) -> &IndexList<WaitingList> {
        &self.waiting
    }

    fn list_mut(&mut self, _list: WaitingList) -> &mut IndexList<WaitingList> {
        &mut self.waiting
    }

    fn link(&self, entry: ThreadId) -> &Link<WaitingList> {
        &self.thread(entry).wait_link
    }

    fn link_mut(&mut self, entry: ThreadId) -> &mut Link<WaitingList> {
        &mut self.thread_mut(entry).wait_link
    }
}

impl Arena<ProcessThreads> for Dispatcher {
    fn list(&self, list: ProcessThreads) -> &IndexList<ProcessThreads> {
        // SAFETY: the reference lives as long as this borrow of the dispatcher, which serializes
        // every use of the process's thread list.
        unsafe { &list.0.get().threads }
    }

    fn list_mut(&mut self, list: ProcessThreads) -> &mut IndexList<ProcessThreads> {
        // SAFETY: as in `list`, the borrow being exclusive.
        unsafe { &mut list.0.get_mut().threads }
    }

    fn link(&self, entry: ThreadId) -> &Link<ProcessThreads> {
        &self.thread(entry).process_link
    }

    fn link_mut(&mut self, entry: ThreadId) -> &mut Link<ProcessThreads> {
        &mut self.thread_mut(entry).process_link
    }
}

impl Arena<Waiters> for Dispatcher {
    fn list(&self, list: Waiters) -> &IndexList<Waiters> {
        &self.header(list.0).waiters
    }

    fn list_mut(&mut self, list: Waiters) -> &mut IndexList<Waiters> {
        &mut self.header_mut(list.0).waiters
    }

    fn link(&self, entry: BlockId) -> &Link<Waiters> {
        &self.block(entry).link
    }

    fn link_mut(&mut self, entry: BlockId) -> &mut Link<Waiters> {
        &mut self.block_mut(entry).link
    }
}

impl Arena<TimerList> for Dispatcher {
    fn list(&self, list: TimerList) -> &IndexList<TimerList> {
        self.timer_table.list(list)
    }

    fn list_mut(&mut self, list: TimerList) -> &mut IndexList<TimerList> {
        self.timer_table.list_mut(list)
    }

    fn link(&self, entry: TimerId) -> &Link<TimerList> {
        &self.timer(entry).link
    }

    fn link_mut(&mut self, entry: TimerId) -> &mut Link<TimerList> {
        &mut self.timer_mut(entry).link
    }
}

impl Arena<ApcQueue> for Dispatcher {
    fn list(&self, list: ApcQueue) -> &IndexList<ApcQueue> {
        self.thread(list.thread).apc_queue(list.mode)
    }

    fn list_mut(&mut self, list: ApcQueue) -> &mut IndexList<ApcQueue> {
        self.thread_mut(list.thread).apc_queue_mut(list.mode)
    }

    fn link(&self, entry: ApcId) -> &Link<ApcQueue> {
        &self.apc(entry).link
    }

    fn link_mut(&mut self, entry: ApcId) -> &mut Link<ApcQueue> {
        &mut self.apc_mut(entry).link
    }
}

impl Arena<OwnedMutexes> for Dispatcher {
    fn list(&self, list: OwnedMutexes) -> &IndexList<OwnedMutexes> {
        &self.thread(list.0).owned_mutexes
    }

    fn list_mut(&mut self, list: OwnedMutexes) -> &mut IndexList<OwnedMutexes> {
        &mut self.thread_mut(list.0).owned_mutexes
    }

    fn link(&self, entry: MutexId) -> &Link<OwnedMutexes> {
        &self.mutex(entry).owner_link
    }

    fn link_mut(&mut self, entry: MutexId) -> &mut Link<OwnedMutexes> {
        &mut self.mutex_mut(entry).owner_link
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sched::testkit;
    use crate::slots::HostPages;

    /// A fresh dispatcher holds no body: each kind's record is made at its index on demand, named
    /// by it, from the pages given, and making it again takes nothing.
    #[test]
    fn bodies_are_made_at_their_index_on_demand() {
        let mut d = testkit::dispatcher();
        let pages = HostPages::new();
        for body in [
            WaitableId::Event(3),
            WaitableId::Semaphore(3),
            WaitableId::Mutex(3),
            WaitableId::Timer(3),
        ] {
            let held = pages.held();
            d.ensure_body(body, &pages).unwrap();
            assert_eq!(pages.held(), held + 1, "{body:?}: one page");
            assert_eq!(d.waitable(body).id(), body, "named by its index");
            d.ensure_body(body, &pages).unwrap();
            assert_eq!(pages.held(), held + 1, "{body:?}: made once");
        }
        assert_eq!(d.mutex(MutexId(3)).id(), MutexId(3));
        assert_eq!(d.timer(TimerId::Waitable(3)).id(), TimerId::Waitable(3));
        assert_eq!(d.apc(ApcId::Timer(3)).id(), ApcId::Timer(3));
        let fixed = [
            WaitableId::Thread(ThreadId(0)),
            WaitableId::ThreadTimer(ThreadId(0)),
            WaitableId::Suspend(ThreadId(0)),
        ];
        for body in fixed {
            d.ensure_body(body, &pages).unwrap();
        }
        assert_eq!(
            pages.held(),
            4,
            "the rig made the first threads' records with the dispatcher"
        );
    }

    /// A process object's body is made with its process's user-APC records, at its index, past
    /// the fixed pools' old 64 processes; each APC record named by its process and its place.
    #[test]
    fn a_process_body_comes_with_its_user_apcs() {
        let mut d = testkit::dispatcher();
        let pages = HostPages::new();
        d.ensure_body(WaitableId::Process(300), &pages).unwrap();
        let held = pages.held();
        assert!(
            held > SideTable::<UserApcs, 1>::CHUNK_PAGES,
            "a chunk of bodies, the process's APCs, their directories' pages"
        );
        d.ensure_body(WaitableId::Process(300), &pages).unwrap();
        assert_eq!(pages.held(), held, "made once");
        d.renew_process_object(300);
        assert_eq!(
            d.waitable(WaitableId::Process(300)).id(),
            WaitableId::Process(300)
        );
        let last = ApcId::User(300, USER_APCS as u8 - 1);
        assert_eq!(d.apc(last).id(), last);
        assert_eq!(
            d.user_apc_address(last),
            Some(core::ptr::NonNull::from(d.apc_mut(last)))
        );
        assert!(
            d.user_apc_address(ApcId::User(301, 0)).is_none(),
            "not made"
        );
        pages.set_budget(0);
        assert_eq!(
            d.ensure_body(WaitableId::Process(301), &pages),
            Err(Exhausted::NoPages),
            "the bodies' chunk is made, the APCs' finds no page"
        );
        assert!(d.user_apc_address(ApcId::User(301, 0)).is_none());
    }

    /// The tables grow past the caps the fixed pools had (256 events, 64 semaphores), a body
    /// keeping its address while later chunks are made.
    #[test]
    fn bodies_grow_past_the_old_caps_and_stay_put() {
        let mut d = testkit::dispatcher();
        let pages = HostPages::new();
        d.ensure_body(WaitableId::Event(0), &pages).unwrap();
        let first = d.db.events.address(0).unwrap();
        for index in 0..1_000u16 {
            d.ensure_body(WaitableId::Event(index), &pages).unwrap();
            d.ensure_body(WaitableId::Semaphore(index), &pages).unwrap();
        }
        assert_eq!(d.db.events.address(0), Some(first), "never moved");
        d.renew_event(999, EventKind::Synchronization, true);
        d.renew_semaphore(999, 2, 5);
        assert_eq!(d.waitable(WaitableId::Event(999)).signal_state(), 1);
        assert_eq!(d.waitable(WaitableId::Semaphore(999)).signal_state(), 2);
        assert_eq!(d.semaphore_mut(999).limit, 5);
    }

    /// A body that finds no page is not made, and the table is as it was: what was made before
    /// still resolves, and the index is made once a page is there.
    #[test]
    fn a_body_without_a_page_leaves_the_table_as_it_was() {
        let mut d = testkit::dispatcher();
        let pages = HostPages::new();
        d.ensure_body(WaitableId::Timer(0), &pages).unwrap();
        let per = entries_per_page::<WaitableTimer>() as u16;
        pages.set_budget(0);
        assert_eq!(
            d.ensure_body(WaitableId::Timer(per), &pages),
            Err(Exhausted::NoPages)
        );
        assert!(d.db.timers.get(per.into()).is_none());
        assert_eq!(d.timer(TimerId::Waitable(0)).id(), TimerId::Waitable(0));
        pages.set_budget(usize::MAX);
        d.ensure_body(WaitableId::Timer(per), &pages).unwrap();
        assert_eq!(d.timer(TimerId::Waitable(per)).id(), TimerId::Waitable(per));
    }
}
