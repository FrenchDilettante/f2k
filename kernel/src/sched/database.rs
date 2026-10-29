//! The dispatcher database: the records the dispatcher owns, and how its lists reach them.
//!
//! Windows 2000 keeps its dispatcher objects — the thread records (KTHREAD) and the bodies of the
//! objects threads wait on (DISPATCHER_HEADER and their type's fields) — in one database the
//! dispatcher lock guards. Here that database is a set of fixed pools inside the [`Dispatcher`]:
//! the thread records, the event, semaphore, mutex and waitable-timer bodies, the process objects'
//! bodies, and the user-APC records. The object directory keeps the objects' headers (liveness,
//! generation, counts) and names a body by its index, which is the same in both.
//!
//! Every list the dispatcher keeps links these records by name, and the dispatcher resolves the
//! names: an [`Arena`] for each list kind. Two kinds of record are reached by address instead, as
//! the context switch reaches them: a process's scheduling record (the process pool's, pinned),
//! which a thread names as its owner, and a waitable header embedded in a structure of its own
//! (see [`WaitableId::Embedded`]).

use super::apc::{Apc, ApcId, ApcQueue};
use super::dispatcher::{Dispatcher, ReadyQueue};
use super::event::{Event, EventKind};
use super::list::{Arena, IndexList, Link};
use super::mutex::{Mutex, MutexId, OwnedMutexes};
use super::pool::Pool;
use super::process::{ProcessObject, ProcessThreads};
use super::semaphore::Semaphore;
use super::thread::{Thread, ThreadId};
use super::timer::{TimerId, TimerList};
use super::wait::{BlockId, Timer, WaitBlock, Waitable, WaitableId, Waiters, WaitingList};
use super::waitable_timer::WaitableTimer;
use crate::ob::{EVENTS, MUTEXES, PROCESSES, SEMAPHORES, THREADS, TIMERS};

/// How many thread records the pool holds: one per thread object, and the idle thread's.
pub const THREAD_RECORDS: usize = THREADS + 1;

/// The idle thread's record: the one past the thread objects', which no object names.
pub const IDLE_THREAD: ThreadId = ThreadId(THREADS as u16);

/// How many user-APC records each process has (QueueUserAPC's, across its threads).
pub const USER_APCS: usize = 64;

/// How many user-APC records the pool holds: each process record's share, at its index.
pub const USER_APC_RECORDS: usize = USER_APCS * PROCESSES;

/// The records the dispatcher owns.
pub struct Database {
    pub(crate) threads: Pool<Thread, THREAD_RECORDS>,
    pub(crate) events: Pool<Event, EVENTS>,
    pub(crate) semaphores: Pool<Semaphore, SEMAPHORES>,
    pub(crate) mutexes: Pool<Mutex, MUTEXES>,
    pub(crate) timers: Pool<WaitableTimer, TIMERS>,
    pub(crate) processes: Pool<ProcessObject, PROCESSES>,
    pub(crate) user_apcs: Pool<Apc, USER_APC_RECORDS>,
}

impl Database {
    /// Write an empty database at `database`, record by record: every record fresh, named by its
    /// index.
    ///
    /// # Safety
    ///
    /// `database` is valid for writes, aligned, and the records' final address; its previous
    /// contents are overwritten, not dropped.
    pub unsafe fn write_empty(database: *mut Database) {
        use core::ptr::addr_of_mut;
        // SAFETY: the caller's contract; every field is written.
        unsafe {
            Pool::write_empty(addr_of_mut!((*database).threads), |index| {
                Thread::new(ThreadId(index))
            });
            Pool::write_empty(addr_of_mut!((*database).events), |index| {
                Event::record(index, EventKind::Notification, false)
            });
            Pool::write_empty(addr_of_mut!((*database).semaphores), |index| {
                Semaphore::with_id(0, WaitableId::Semaphore(index))
            });
            Pool::write_empty(addr_of_mut!((*database).mutexes), |index| {
                Mutex::new(MutexId(index))
            });
            Pool::write_empty(addr_of_mut!((*database).timers), |index| {
                WaitableTimer::new(index, true)
            });
            Pool::write_empty(addr_of_mut!((*database).processes), ProcessObject::new);
            Pool::write_empty(addr_of_mut!((*database).user_apcs), |index| {
                Apc::new(ApcId::User(index))
            });
        }
    }
}

// --- Resolving names -------------------------------------------------------------------------

impl Dispatcher {
    /// The thread record `thread`.
    pub fn thread(&self, thread: ThreadId) -> &Thread {
        self.db.threads.get(thread.0)
    }

    /// The thread record `thread`, to change.
    pub fn thread_mut(&mut self, thread: ThreadId) -> &mut Thread {
        self.db.threads.get_mut(thread.0)
    }

    /// The address of the thread record `thread`: what the context switch is handed.
    pub fn thread_address(&self, thread: ThreadId) -> *mut Thread {
        self.db.threads.address(thread.0)
    }

    /// The id of the thread record at `record`, for the callers that still name a record by its
    /// address; none for an address that is no thread record of the pool.
    pub fn thread_at(&self, record: *const Thread) -> Option<ThreadId> {
        self.db.threads.index_of(record).map(ThreadId)
    }

    /// Every thread record, by id.
    pub fn threads(&self) -> impl Iterator<Item = (ThreadId, &Thread)> {
        self.db
            .threads
            .iter()
            .map(|(index, thread)| (ThreadId(index), thread))
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
            WaitableId::Event(index) => &self.db.events.get(index).waitable,
            WaitableId::Semaphore(index) => &self.db.semaphores.get(index).waitable,
            WaitableId::Mutex(index) => &self.db.mutexes.get(index).waitable,
            WaitableId::Timer(index) => &self.db.timers.get(index).timer.waitable,
            WaitableId::Process(index) => &self.db.processes.get(index).waitable,
            WaitableId::Thread(thread) => &self.thread(thread).waitable,
            WaitableId::ThreadTimer(thread) => &self.thread(thread).timer.waitable,
            WaitableId::Suspend(thread) => &self.thread(thread).suspend_semaphore.waitable,
            // SAFETY: an embedded header's embedder keeps it at the address its init named, alive,
            // while anything waits on it or signals it — the only times its name is resolved —
            // and the dispatcher reaches it serialized.
            WaitableId::Embedded(header) => unsafe { header.as_ref() },
        }
    }

    /// The waitable header `object` names, to change.
    pub fn waitable_mut(&mut self, object: WaitableId) -> &mut Waitable {
        match object {
            WaitableId::Event(index) => &mut self.db.events.get_mut(index).waitable,
            WaitableId::Semaphore(index) => &mut self.db.semaphores.get_mut(index).waitable,
            WaitableId::Mutex(index) => &mut self.db.mutexes.get_mut(index).waitable,
            WaitableId::Timer(index) => &mut self.db.timers.get_mut(index).timer.waitable,
            WaitableId::Process(index) => &mut self.db.processes.get_mut(index).waitable,
            WaitableId::Thread(thread) => &mut self.thread_mut(thread).waitable,
            WaitableId::ThreadTimer(thread) => &mut self.thread_mut(thread).timer.waitable,
            WaitableId::Suspend(thread) => &mut self.thread_mut(thread).suspend_semaphore.waitable,
            // SAFETY: as in `waitable`; the serialized dispatcher makes this the header's only use
            // while the reference lives.
            WaitableId::Embedded(mut header) => unsafe { header.as_mut() },
        }
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
            TimerId::Waitable(index) => &self.db.timers.get(index).timer,
        }
    }

    /// The timer `timer` names, to change.
    pub fn timer_mut(&mut self, timer: TimerId) -> &mut Timer {
        match timer {
            TimerId::Thread(thread) => &mut self.thread_mut(thread).timer,
            TimerId::Waitable(index) => &mut self.db.timers.get_mut(index).timer,
        }
    }

    /// The APC record `apc` names.
    pub fn apc(&self, apc: ApcId) -> &Apc {
        match apc {
            ApcId::Suspend(thread) => &self.thread(thread).suspend_apc,
            ApcId::Exit(thread) => &self.thread(thread).exit_apc,
            ApcId::Timer(index) => &self.db.timers.get(index).apc,
            ApcId::User(index) => self.db.user_apcs.get(index),
        }
    }

    /// The APC record `apc` names, to change.
    pub fn apc_mut(&mut self, apc: ApcId) -> &mut Apc {
        match apc {
            ApcId::Suspend(thread) => &mut self.thread_mut(thread).suspend_apc,
            ApcId::Exit(thread) => &mut self.thread_mut(thread).exit_apc,
            ApcId::Timer(index) => &mut self.db.timers.get_mut(index).apc,
            ApcId::User(index) => self.db.user_apcs.get_mut(index),
        }
    }

    /// The mutex record `mutex`.
    pub fn mutex(&self, mutex: MutexId) -> &Mutex {
        self.db.mutexes.get(mutex.0)
    }

    /// The mutex record `mutex`, to change.
    pub fn mutex_mut(&mut self, mutex: MutexId) -> &mut Mutex {
        self.db.mutexes.get_mut(mutex.0)
    }

    /// The event body at pool `index`, to change.
    pub fn event_mut(&mut self, index: u16) -> &mut Event {
        self.db.events.get_mut(index)
    }

    /// The semaphore body at pool `index`, to change.
    pub fn semaphore_mut(&mut self, index: u16) -> &mut Semaphore {
        self.db.semaphores.get_mut(index)
    }

    /// The waitable timer body at pool `index`, to change.
    pub fn waitable_timer_mut(&mut self, index: u16) -> &mut WaitableTimer {
        self.db.timers.get_mut(index)
    }

    /// The process object body at pool `index`, to change.
    pub fn process_object_mut(&mut self, index: u16) -> &mut ProcessObject {
        self.db.processes.get_mut(index)
    }

    /// The user-APC record at pool `index`, to change.
    pub fn user_apc_mut(&mut self, index: u16) -> &mut Apc {
        self.db.user_apcs.get_mut(index)
    }

    // --- Fresh bodies for new objects ---

    /// A fresh event object of `kind` at `signaled` in the event record `index`.
    pub fn renew_event(&mut self, index: u16, kind: EventKind, signaled: bool) -> &mut Event {
        let event = self.db.events.get_mut(index);
        *event = Event::record(index, kind, signaled);
        event
    }

    /// A fresh semaphore object at `initial` with ceiling `limit` in the semaphore record `index`.
    pub fn renew_semaphore(&mut self, index: u16, initial: i32, limit: i32) -> &mut Semaphore {
        let semaphore = self.db.semaphores.get_mut(index);
        *semaphore = Semaphore::with_id(limit, WaitableId::Semaphore(index));
        semaphore.waitable.signal_state = initial;
        semaphore
    }

    /// A fresh, free mutex object in the mutex record `index`.
    pub fn renew_mutex(&mut self, index: u16) -> &mut Mutex {
        let mutex = self.db.mutexes.get_mut(index);
        *mutex = Mutex::new(MutexId(index));
        mutex
    }

    /// A fresh, unarmed, unsignaled waitable timer object in the timer record `index`.
    pub fn renew_waitable_timer(&mut self, index: u16, manual_reset: bool) -> &mut WaitableTimer {
        let timer = self.db.timers.get_mut(index);
        *timer = WaitableTimer::new(index, manual_reset);
        timer
    }

    /// A fresh process object body, unsignaled and still active, in the record `index`.
    pub fn renew_process_object(&mut self, index: u16) -> &mut ProcessObject {
        let process = self.db.processes.get_mut(index);
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
        &self.waitable(list.0).waiters
    }

    fn list_mut(&mut self, list: Waiters) -> &mut IndexList<Waiters> {
        &mut self.waitable_mut(list.0).waiters
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
