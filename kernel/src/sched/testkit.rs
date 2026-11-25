//! The host tests' rig: a fresh dispatcher per scenario, and records taken from its pools.
//!
//! Records live in the dispatcher database for as long as the dispatcher does, so the rig hands
//! them out as [`Rec`]s: copyable handles that read as the record and name it to the scheduler's
//! entry points, which take a record by its id at once. A test names a record and the dispatcher
//! that holds it side by side, as the kernel's statics do. Every dispatcher a test thread makes
//! lives until the thread ends; the newest is the thread's installed one, which the records below
//! are taken from and the object directory's accessors reach.

extern crate std;

use core::cell::{Cell, RefCell};
use std::boxed::Box;
use std::vec::Vec;

use super::apc::{Apc, ApcId};
use super::database::IDLE_THREAD;
use super::dispatcher::Dispatcher;
use super::event::{Event, EventKind};
use super::mutex::{Mutex, MutexId};
use super::process::SchedProcess;
use super::thread::{Thread, ThreadId};
use super::timer::TimerId;
use super::wait::Timer;
use super::waitable_timer::WaitableTimer;
use crate::level::{Dispatch, LevelCell};

/// The dispatchers a thread made, held by their raw pointers (from `Box::into_raw`): moving a
/// `Box` would assert its uniqueness, invalidating the references the thread's tests hold.
struct Made(Vec<*mut LevelCell<Dispatch, Dispatcher>>);

impl Drop for Made {
    fn drop(&mut self) {
        for cell in self.0.drain(..) {
            // SAFETY: each came from `Box::into_raw` and is given back once, as the thread ends.
            drop(unsafe { Box::from_raw(cell) });
        }
    }
}

std::thread_local! {
    /// The dispatchers this thread made, kept until it ends.
    static MADE: RefCell<Made> = const { RefCell::new(Made(Vec::new())) };
    /// The next free records of the installed dispatcher: thread, mutex, timer, user APC.
    static NEXT: Cell<[u16; 4]> = const { Cell::new([0; 4]) };
}

/// A record kind the rig hands out, and the name each record of it has.
pub trait Record {
    type Id: Copy;

    /// The record's name.
    fn record_id(&self) -> Self::Id;
}

impl Record for Thread {
    type Id = ThreadId;

    fn record_id(&self) -> ThreadId {
        Thread::id(self)
    }
}

impl Record for Mutex {
    type Id = MutexId;

    fn record_id(&self) -> MutexId {
        Mutex::id(self)
    }
}

impl Record for WaitableTimer {
    type Id = TimerId;

    fn record_id(&self) -> TimerId {
        self.timer.id()
    }
}

impl Record for Timer {
    type Id = TimerId;

    fn record_id(&self) -> TimerId {
        Timer::id(self)
    }
}

impl Record for Apc {
    type Id = ApcId;

    fn record_id(&self) -> ApcId {
        Apc::id(self)
    }
}

/// A record of a test's dispatcher, by its address: it reads as the record, and names it.
///
/// The name is kept beside the address, so that naming the record to the dispatcher (an
/// argument the dispatcher's own borrow converts) reads nothing of the record meanwhile.
pub struct Rec<T: Record>(*mut T, T::Id);

impl<T: Record> Clone for Rec<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T: Record> Copy for Rec<T> {}

impl<T: Record> Rec<T> {
    /// The record's address.
    pub fn as_ptr(self) -> *mut T {
        self.0
    }

    /// The record's name, as it was handed out (records keep their names).
    pub fn id(self) -> T::Id {
        self.1
    }
}

impl<T: Record> core::ops::Deref for Rec<T> {
    type Target = T;

    fn deref(&self) -> &T {
        // SAFETY: a record of a dispatcher the test thread keeps until it ends.
        unsafe { &*self.0 }
    }
}

impl<T: Record> core::ops::DerefMut for Rec<T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: as `deref`; the rig's tests use one reference at a time.
        unsafe { &mut *self.0 }
    }
}

impl From<Rec<Thread>> for ThreadId {
    fn from(thread: Rec<Thread>) -> Self {
        thread.id()
    }
}

impl From<Rec<Mutex>> for MutexId {
    fn from(mutex: Rec<Mutex>) -> Self {
        mutex.id()
    }
}

impl From<Rec<WaitableTimer>> for TimerId {
    fn from(timer: Rec<WaitableTimer>) -> Self {
        timer.id()
    }
}

impl From<Rec<Timer>> for TimerId {
    fn from(timer: Rec<Timer>) -> Self {
        timer.id()
    }
}

impl From<Rec<Apc>> for ApcId {
    fn from(apc: Rec<Apc>) -> Self {
        apc.id()
    }
}

/// A test's dispatcher: a handle that reads as the dispatcher, each use a fresh borrow of it.
///
/// The code under test reaches the same dispatcher through [`super::DISPATCHER`], its own
/// borrow at a time; a test holding a `&mut Dispatcher` across such a call would hold a
/// reference that call invalidates. The handle holds the dispatcher's address instead, and
/// borrows it only for the expression that uses it.
pub struct Disp(*mut Dispatcher);

impl Clone for Disp {
    fn clone(&self) -> Self {
        *self
    }
}

impl Copy for Disp {}

impl core::ops::Deref for Disp {
    type Target = Dispatcher;

    fn deref(&self) -> &Dispatcher {
        // SAFETY: the installed dispatcher lives until the thread ends; the borrow lasts the
        // expression that uses it.
        unsafe { &*self.0 }
    }
}

impl core::ops::DerefMut for Disp {
    fn deref_mut(&mut self) -> &mut Dispatcher {
        // SAFETY: as `deref`; no other borrow of the dispatcher is live across a test's own uses.
        unsafe { &mut *self.0 }
    }
}

/// The installed dispatcher's address: what every handle and record is derived from, so that no
/// borrow of the dispatcher (the rig's or the code's) invalidates another's pointer.
fn root() -> *mut Dispatcher {
    super::DISPATCHER.as_ptr()
}

/// `record`, an address inside the installed dispatcher, rederived from the dispatcher's own
/// address (a pointer a borrow gave out lives only as long as that borrow).
fn rebased<T: Record>(record: *mut T) -> Rec<T> {
    let root = root();
    let offset = record as usize - root as usize;
    let record = root.cast::<u8>().wrapping_add(offset).cast::<T>();
    // SAFETY: a record of the installed dispatcher, no borrow of which is live.
    let id = unsafe { &*record }.record_id();
    Rec(record, id)
}

/// A fresh dispatcher, built in place and installed as this thread's.
pub fn dispatcher() -> Disp {
    // SAFETY: `write_empty` writes a whole dispatcher at the address it is handed, and reaches no
    // level cell.
    let cell = Box::into_raw(unsafe { LevelCell::boxed_in_place(Dispatcher::write_empty) });
    MADE.with(|all| all.borrow_mut().0.push(cell));
    NEXT.with(|next| next.set([0; 4]));
    // SAFETY: the cell lives until the thread ends, at its address.
    let cell = unsafe { &*cell };
    super::install_host(cell);
    installed()
}

/// The installed dispatcher. The rig's tests reach it beside the code under test, which reaches it
/// through the dispatch token, one reference at a time.
pub fn installed() -> Disp {
    Disp(root())
}

/// Take the next record of kind `kind` (0 threads, 1 mutexes, 2 timers, 3 user APCs).
fn take(kind: usize) -> u16 {
    NEXT.with(|next| {
        let mut all = next.get();
        let index = all[kind];
        all[kind] += 1;
        next.set(all);
        index
    })
}

/// A process record, leaked at its final address, on directory 0x0090_0000 with base priority
/// `base`.
pub fn process(base: i8) -> *mut SchedProcess {
    process_on(0x0090_0000, base)
}

/// A process record, leaked at its final address, on directory `dir` with base priority `base`.
pub fn process_on(dir: u32, base: i8) -> *mut SchedProcess {
    Box::leak(Box::new(SchedProcess::new(dir, base)))
}

/// The installed dispatcher's record `thread`.
pub fn record(thread: ThreadId) -> Rec<Thread> {
    rebased(installed().thread_address(thread))
}

/// A fresh thread of the installed dispatcher, attached to `process`.
pub fn thread(process: *mut SchedProcess) -> Rec<Thread> {
    let id = ThreadId(take(0));
    assert!(
        id != IDLE_THREAD,
        "the rig's threads stay below the idle record"
    );
    attached(id, process)
}

/// The installed dispatcher's idle record, attached to `process` but not installed.
pub fn idle_record(process: *mut SchedProcess) -> Rec<Thread> {
    attached(IDLE_THREAD, process)
}

/// The record `id`, renewed and attached to `process`.
fn attached(id: ThreadId, process: *mut SchedProcess) -> Rec<Thread> {
    let mut dispatcher = installed();
    dispatcher.renew_thread(id);
    // SAFETY: the process record is leaked at its final address.
    unsafe { dispatcher.attach(id, process) };
    record(id)
}

/// An event to embed, leaked at its final address and named there.
pub fn event(kind: EventKind, signaled: bool) -> &'static mut Event {
    let event = Box::leak(Box::new(Event::new(kind, signaled)));
    event.init();
    event
}

/// A fresh, free mutex object of the installed dispatcher.
pub fn mutex() -> Rec<Mutex> {
    let index = take(1);
    rebased(installed().renew_mutex(index))
}

/// A fresh waitable timer object of the installed dispatcher.
pub fn waitable_timer(manual_reset: bool) -> Rec<WaitableTimer> {
    let index = take(2);
    rebased(installed().renew_waitable_timer(index, manual_reset))
}

/// A fresh timer of the installed dispatcher, uninserted and unsignaled: a fresh manual-reset
/// waitable timer's.
pub fn timer() -> Rec<Timer> {
    let index = take(2);
    rebased(&mut installed().renew_waitable_timer(index, true).timer)
}

/// A fresh user-APC record of the installed dispatcher, unbound.
pub fn apc() -> Rec<Apc> {
    let index = take(3);
    let apc = installed().user_apc_mut(index) as *mut Apc;
    let apc = rebased(apc);
    // SAFETY: a record of the installed dispatcher, no borrow of which is live.
    unsafe { *apc.as_ptr() = Apc::new(ApcId::User(index)) };
    apc
}
