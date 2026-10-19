//! The mutex object (the NT mutant): a waitable a thread owns, recursively.
//!
//! The signal state counts down from one: a free mutex is signaled at one; each acquisition takes
//! one unit, so an owner holding it `n` times leaves it at `1 - n`. The owner's own waits are
//! satisfied whatever the state — that is the recursion — and every other thread's park until the
//! last release puts the state back at one and clears the owner. A mutex is on its owner's list
//! for as long as it is owned: a thread that ends holding mutexes abandons each one — the state
//! goes back to one, the owner clears, and the next acquisition reports the abandonment.

use core::ptr::{addr_of_mut, null_mut};

use super::dispatcher::Dispatcher;
use super::thread::Thread;
use super::wait::{WaitKind, Waitable};
use super::{unlink, Links};
use crate::status::{NtStatus, STATUS_ABANDONED, STATUS_MUTANT_NOT_OWNED};

/// The priority increment a release grants the waiter it wakes.
pub const MUTEX_WAKE_INCREMENT: i8 = 1;

/// A mutex.
#[repr(C)]
pub struct Mutex {
    /// The waitable header: one when free, `1 - n` while held `n` times.
    pub(crate) waitable: Waitable,
    /// The owning thread; null while free.
    pub(crate) owner: *mut Thread,
    /// Whether the previous owner ended holding it: the next acquisition reports it and clears it.
    pub(crate) abandoned: bool,
    /// The owner's owned-mutex list membership.
    pub(crate) owner_links: Links,
}

impl Mutex {
    /// A fresh, free mutex; call [`Mutex::init`] once it is at its final address.
    pub const fn new() -> Self {
        Mutex {
            waitable: Waitable::new(WaitKind::Mutant, 1),
            owner: null_mut(),
            abandoned: false,
            owner_links: Links::detached(),
        }
    }

    /// Close the waiters sentinel; call once at the final address.
    pub fn init(&mut self) {
        self.waitable.init();
    }

    /// The waitable header, as the wait entries take it.
    pub fn waitable(&mut self) -> *mut Waitable {
        addr_of_mut!(self.waitable)
    }

    /// The owning thread, null while free.
    pub fn owner(&self) -> *mut Thread {
        self.owner
    }

    /// The mutex a waitable header belongs to: the header leads the record.
    pub fn from_waitable(waitable: *mut Waitable) -> *mut Mutex {
        waitable as *mut Mutex
    }
}

impl Default for Mutex {
    fn default() -> Self {
        Mutex::new()
    }
}

/// Whether `thread` may take `mutex` now: it is free, or `thread` already owns it.
pub(crate) fn available_to(mutex: &Mutex, thread: *const Thread) -> bool {
    mutex.waitable.signal_state > 0 || core::ptr::eq(mutex.owner, thread)
}

/// Take one unit of `mutex` for `thread` (it must be [`available_to`] it). The first unit makes
/// `thread` the owner and puts the mutex on its list; an abandoned mutex reports the abandonment
/// once, as the status the take returns (success otherwise).
pub(crate) fn acquire(mutex: &mut Mutex, thread: &mut Thread) -> NtStatus {
    mutex.waitable.signal_state -= 1;
    if mutex.waitable.signal_state != 0 {
        return 0;
    }
    mutex.owner = thread as *mut Thread;
    // SAFETY: a free mutex is on no owner list; the thread's list is initialized at attach.
    unsafe {
        thread
            .owned_mutexes
            .push_back(addr_of_mut!(mutex.owner_links))
    };
    if mutex.abandoned {
        mutex.abandoned = false;
        STATUS_ABANDONED
    } else {
        0
    }
}

impl Dispatcher {
    /// Release one unit of `mutex` on behalf of `thread`: refused unless `thread` owns it. The last
    /// unit frees it — off the owner's list, the owner cleared — and wakes the oldest waiter, which
    /// takes it. Returns the previous signal state.
    pub fn release_mutex(
        &mut self,
        mutex: &mut Mutex,
        thread: *const Thread,
    ) -> Result<i32, NtStatus> {
        if !core::ptr::eq(mutex.owner, thread) {
            return Err(STATUS_MUTANT_NOT_OWNED);
        }
        let previous = mutex.waitable.signal_state;
        mutex.waitable.signal_state += 1;
        if mutex.waitable.signal_state == 1 {
            self.free_mutex(mutex);
        }
        Ok(previous)
    }

    /// Abandon every mutex `thread` owns: each goes back to free, marked abandoned, and its oldest
    /// waiter takes it. The thread's end runs this, before its object signals.
    pub(crate) fn abandon_mutexes(&mut self, thread: &mut Thread) {
        while !thread.owned_mutexes.is_empty() {
            // SAFETY: the list is initialized and non-empty; its entries are owned mutexes' links.
            let entry = unsafe { thread.owned_mutexes.first() };
            let mutex = (entry as usize - core::mem::offset_of!(Mutex, owner_links)) as *mut Mutex;
            // SAFETY: the entry names a live, owned mutex.
            let mutex = unsafe { &mut *mutex };
            mutex.waitable.signal_state = 1;
            mutex.abandoned = true;
            self.free_mutex(mutex);
        }
    }

    /// The mutex object is being deleted (its last reference went, so no thread waits on it): an
    /// owned mutex leaves its owner's list, which then has nothing of it to abandon.
    pub(crate) fn forget_mutex(&mut self, mutex: &mut Mutex) {
        debug_assert!(
            mutex.waitable.waiters.is_empty(),
            "a deleted mutex has no waiters"
        );
        if !mutex.owner.is_null() {
            // SAFETY: an owned mutex is linked on its owner's list.
            unsafe { unlink(addr_of_mut!(mutex.owner_links)) };
            mutex.owner = null_mut();
            mutex.waitable.signal_state = 1;
        }
    }

    /// The free step: off the owner's list, no owner, and the waiters satisfied.
    fn free_mutex(&mut self, mutex: &mut Mutex) {
        // SAFETY: an owned mutex is linked on its owner's list.
        unsafe { unlink(addr_of_mut!(mutex.owner_links)) };
        mutex.owner = null_mut();
        if !mutex.waitable.waiters.is_empty() {
            let waitable = addr_of_mut!(mutex.waitable);
            self.satisfy_waiters(waitable, MUTEX_WAKE_INCREMENT);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sched::event::{Event, EventKind, EVENT_WAKE_INCREMENT};
    use crate::sched::process::SchedProcess;
    use crate::sched::thread::ThreadState;
    use crate::sched::wait::{ClockStamp, WaitDisposition, WaitMode, WaitReason};
    use crate::status::{STATUS_TIMEOUT, STATUS_USER_APC};

    // The rig: the same leaked-objects style as the scheduler's other test modules.

    fn dispatcher() -> &'static mut Dispatcher {
        let d = Box::leak(Box::new(Dispatcher::zeroed()));
        d.init();
        d
    }

    fn process() -> *mut SchedProcess {
        let p = Box::leak(Box::new(SchedProcess::new(0x0090_0000, 8)));
        p.init();
        p as *mut SchedProcess
    }

    fn thread(p: *mut SchedProcess) -> &'static mut Thread {
        let t = Box::leak(Box::new(Thread::empty()));
        // SAFETY: both objects are leaked at their final addresses.
        unsafe { t.attach_to(&mut *p) };
        t
    }

    fn mutex() -> &'static mut Mutex {
        let m = Box::leak(Box::new(Mutex::new()));
        m.init();
        m
    }

    fn event(kind: EventKind, signaled: bool) -> &'static mut Event {
        let e = Box::leak(Box::new(Event::new(kind, signaled)));
        e.init();
        e
    }

    const STAMP: ClockStamp = ClockStamp {
        interrupt_time: 10_000,
        tick: 5,
    };

    fn wait(d: &mut Dispatcher, t: &mut Thread, object: *mut Waitable) -> WaitDisposition {
        d.wait_single(
            t,
            object,
            WaitReason::UserRequest,
            WaitMode::User,
            false,
            None,
            STAMP,
        )
    }

    /// The owner's waits are satisfied however often it holds the mutex; another thread parks, and
    /// its release is refused; the owner's last release hands the mutex to the oldest waiter.
    #[test]
    fn ownership_is_recursive_and_the_last_release_hands_it_over() {
        let d = dispatcher();
        let p = process();
        let (owner, other) = (thread(p), thread(p));
        let m = mutex();

        assert_eq!(wait(d, owner, m.waitable()), WaitDisposition::Complete(0));
        assert_eq!(wait(d, owner, m.waitable()), WaitDisposition::Complete(0));
        assert_eq!(m.waitable.signal_state, -1, "held twice");
        assert!(core::ptr::eq(m.owner(), owner));

        assert_eq!(wait(d, other, m.waitable()), WaitDisposition::Yield);
        assert_eq!(
            d.release_mutex(m, other),
            Err(STATUS_MUTANT_NOT_OWNED),
            "a non-owner's release is refused"
        );
        assert_eq!(d.release_mutex(m, owner), Ok(-1));
        assert_eq!(other.state(), ThreadState::Waiting, "still held once");
        assert_eq!(d.release_mutex(m, owner), Ok(0));
        assert_eq!(other.state(), ThreadState::Ready, "the waiter took it");
        assert!(core::ptr::eq(m.owner(), other));
        assert_eq!(m.waitable.signal_state, 0);
        assert!(owner.owned_mutexes.is_empty());
        assert_eq!(
            d.release_mutex(m, owner),
            Err(STATUS_MUTANT_NOT_OWNED),
            "the old owner no longer owns it"
        );
    }

    /// An owner's end abandons what it holds: a parked waiter takes it with the abandonment status;
    /// with nobody parked, the next take reports it once.
    #[test]
    fn an_owners_end_abandons_its_mutexes() {
        let d = dispatcher();
        let p = process();
        let (owner, waiter, late) = (thread(p), thread(p), thread(p));
        let (m1, m2) = (mutex(), mutex());
        assert_eq!(wait(d, owner, m1.waitable()), WaitDisposition::Complete(0));
        assert_eq!(wait(d, owner, m2.waitable()), WaitDisposition::Complete(0));
        assert_eq!(wait(d, waiter, m1.waitable()), WaitDisposition::Yield);

        d.terminate_other(owner);
        assert_eq!(waiter.state(), ThreadState::Ready);
        assert_eq!(waiter.wait_status(), STATUS_ABANDONED);
        assert!(core::ptr::eq(m1.owner(), waiter));
        assert!(!m1.abandoned, "the take reported it");

        assert!(m2.owner().is_null());
        assert_eq!(
            wait(d, late, m2.waitable()),
            WaitDisposition::Complete(STATUS_ABANDONED)
        );
        assert_eq!(d.release_mutex(m2, late), Ok(0));
        assert_eq!(
            wait(d, late, m2.waitable()),
            WaitDisposition::Complete(0),
            "reported once"
        );
    }

    /// Wait-any: the lowest signaled index wins and only its signal is consumed; parked, the
    /// object that signals first completes the wait with its index and every block unwinds.
    #[test]
    fn wait_any_reports_the_lowest_signaled_index() {
        let d = dispatcher();
        let p = process();
        let t = thread(p);
        let mut events = [
            event(EventKind::Synchronization, false),
            event(EventKind::Synchronization, true),
            event(EventKind::Synchronization, true),
        ];
        let objects: Vec<*mut Waitable> = events.iter_mut().map(|e| e.waitable()).collect();
        let any = |d: &mut Dispatcher, t: &mut Thread, timeout| {
            d.wait_multiple(
                t,
                &objects,
                false,
                WaitReason::UserRequest,
                WaitMode::User,
                false,
                timeout,
                STAMP,
            )
        };
        assert_eq!(any(d, t, Some(0)), WaitDisposition::Complete(1));
        assert_eq!(any(d, t, Some(0)), WaitDisposition::Complete(2));
        assert_eq!(
            any(d, t, Some(0)),
            WaitDisposition::Complete(STATUS_TIMEOUT)
        );

        assert_eq!(any(d, t, None), WaitDisposition::Yield);
        events[2].set(d, EVENT_WAKE_INCREMENT);
        assert_eq!(t.state(), ThreadState::Ready);
        assert_eq!(t.wait_status(), 2);
        for e in events.iter() {
            assert!(e.waitable.waiters.is_empty(), "every block unwound");
        }
    }

    /// Wait-all: nothing is consumed until every object is signaled for the thread — a mutex it
    /// owns counts — and then all are taken at once.
    #[test]
    fn wait_all_takes_everything_at_once() {
        let d = dispatcher();
        let p = process();
        let t = thread(p);
        let (e0, e1) = (
            event(EventKind::Synchronization, true),
            event(EventKind::Synchronization, false),
        );
        let m = mutex();
        assert_eq!(wait(d, t, m.waitable()), WaitDisposition::Complete(0));
        let objects = [e0.waitable(), e1.waitable(), m.waitable()];
        let all = |d: &mut Dispatcher, t: &mut Thread, timeout| {
            d.wait_multiple(
                t,
                &objects,
                true,
                WaitReason::UserRequest,
                WaitMode::User,
                false,
                timeout,
                STAMP,
            )
        };
        assert_eq!(
            all(d, t, Some(0)),
            WaitDisposition::Complete(STATUS_TIMEOUT)
        );
        assert!(e0.signaled(), "nothing consumed");

        assert_eq!(all(d, t, None), WaitDisposition::Yield);
        e1.set(d, EVENT_WAKE_INCREMENT);
        assert_eq!(t.state(), ThreadState::Ready);
        assert_eq!(t.wait_status(), 0);
        assert!(!e0.signaled() && !e1.signaled(), "both taken");
        assert_eq!(m.waitable.signal_state, -1, "the mutex taken again");
    }

    /// The alert test: an alertable user wait with a user APC queued completes at once with the
    /// user-APC status and arms the delivery; a non-alertable one ignores the queue.
    #[test]
    fn an_alertable_wait_with_user_apcs_queued_completes_at_once() {
        let d = dispatcher();
        let p = process();
        let t = thread(p);
        let e = event(EventKind::Notification, false);
        let apc = Box::leak(Box::new(crate::sched::apc::Apc::detached()));
        fn marker(_: &mut Dispatcher, _: &mut Thread, _: usize, _: usize, _: usize) {}
        apc.init(
            t,
            crate::sched::apc::nop_kernel_routine,
            Some(marker),
            crate::sched::apc::ApcMode::User,
            0,
        );
        assert!(d.queue_apc(apc, 0, 0, 0));
        assert!(!t.user_apc_pending, "not waiting: only queued");

        let alertable = d.wait_single(
            t,
            e.waitable(),
            WaitReason::UserRequest,
            WaitMode::User,
            true,
            None,
            STAMP,
        );
        assert_eq!(alertable, WaitDisposition::Complete(STATUS_USER_APC));
        assert!(t.user_apc_pending);
        assert!(e.waitable.waiters.is_empty(), "nothing parked");

        t.user_apc_pending = false;
        assert_eq!(
            d.delay(t, WaitMode::User, true, 10_000, STAMP),
            WaitDisposition::Complete(STATUS_USER_APC)
        );
        assert_eq!(
            wait(d, t, e.waitable()),
            WaitDisposition::Yield,
            "non-alertable"
        );
    }
}
