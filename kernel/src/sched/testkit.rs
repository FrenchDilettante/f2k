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

std::thread_local! {
    /// The dispatchers this thread made, kept until it ends.
    static MADE: RefCell<Vec<Box<LevelCell<Dispatch, Dispatcher>>>> =
        const { RefCell::new(Vec::new()) };
    /// The next free records of the installed dispatcher: thread, mutex, timer, user APC.
    static NEXT: Cell<[u16; 4]> = const { Cell::new([0; 4]) };
}

/// A record of a test's dispatcher, by its address: it reads as the record, and names it.
pub struct Rec<T>(*mut T);

impl<T> Clone for Rec<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for Rec<T> {}

impl<T> Rec<T> {
    /// The record's address.
    pub fn as_ptr(self) -> *mut T {
        self.0
    }
}

impl<T> core::ops::Deref for Rec<T> {
    type Target = T;

    fn deref(&self) -> &T {
        // SAFETY: a record of a dispatcher the test thread keeps until it ends.
        unsafe { &*self.0 }
    }
}

impl<T> core::ops::DerefMut for Rec<T> {
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
        timer.timer.id()
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

/// A fresh dispatcher, built in place and installed as this thread's.
pub fn dispatcher() -> &'static mut Dispatcher {
    // SAFETY: `write_empty` writes a whole dispatcher at the address it is handed, and reaches no
    // level cell.
    let made = unsafe { LevelCell::boxed_in_place(Dispatcher::write_empty) };
    let cell: *const LevelCell<Dispatch, Dispatcher> = &*made;
    MADE.with(|all| all.borrow_mut().push(made));
    NEXT.with(|next| next.set([0; 4]));
    // SAFETY: the box lives until the thread ends, at its address (moving a box keeps its heap).
    let cell = unsafe { &*cell };
    super::install_host(cell);
    installed()
}

/// The installed dispatcher. The rig's tests reach it beside the code under test, which reaches it
/// through the dispatch token, one reference at a time.
pub fn installed() -> &'static mut Dispatcher {
    // SAFETY: the installed cell lives until the thread ends; the tests use one reference at a
    // time.
    unsafe { &mut *super::DISPATCHER.as_ptr() }
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
    Rec(installed().thread_address(thread))
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
    let dispatcher = installed();
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
    Rec(installed().renew_mutex(index))
}

/// A fresh waitable timer object of the installed dispatcher.
pub fn waitable_timer(manual_reset: bool) -> Rec<WaitableTimer> {
    let index = take(2);
    Rec(installed().renew_waitable_timer(index, manual_reset))
}

/// A fresh timer of the installed dispatcher, uninserted and unsignaled: a fresh manual-reset
/// waitable timer's.
pub fn timer() -> Rec<Timer> {
    let index = take(2);
    Rec(&mut installed().renew_waitable_timer(index, true).timer)
}

/// A fresh user-APC record of the installed dispatcher, unbound.
pub fn apc() -> Rec<Apc> {
    let index = take(3);
    let apc = installed().user_apc_mut(index);
    *apc = Apc::new(ApcId::User(index));
    Rec(apc)
}
