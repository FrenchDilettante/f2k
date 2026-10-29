//! The mutex object (the NT mutant): a waitable a thread owns, recursively.
//!
//! The signal state counts down from one: a free mutex is signaled at one; each acquisition takes
//! one unit, so an owner holding it `n` times leaves it at `1 - n`. The owner's own waits are
//! satisfied whatever the state — that is the recursion — and every other thread's park until the
//! last release puts the state back at one and clears the owner. A mutex is on its owner's list
//! for as long as it is owned: a thread that ends holding mutexes abandons each one — the state
//! goes back to one, the owner clears, and the next acquisition reports the abandonment.

use super::dispatcher::Dispatcher;
use super::list::{self, Link, ListKind};
use super::thread::ThreadId;
use super::wait::{WaitKind, Waitable, WaitableId};
use crate::status::{NtStatus, STATUS_ABANDONED, STATUS_MUTANT_NOT_OWNED, STATUS_SUCCESS};

/// The priority increment a release grants the waiter it wakes.
pub const MUTEX_WAKE_INCREMENT: i8 = 1;

/// A mutex record's name: its index in the dispatcher database's mutex pool.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MutexId(pub u16);

/// A mutex record names itself: the entry points take the record or its id alike.
impl From<&mut Mutex> for MutexId {
    fn from(mutex: &mut Mutex) -> Self {
        mutex.id()
    }
}

/// The mutexes one thread owns.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct OwnedMutexes(pub ThreadId);

impl ListKind for OwnedMutexes {
    type Entry = MutexId;
}

/// A mutex.
pub struct Mutex {
    /// The waitable header: one when free, `1 - n` while held `n` times.
    pub(crate) waitable: Waitable,
    /// The owning thread; none while free.
    pub(crate) owner: Option<ThreadId>,
    /// Whether the previous owner ended holding it: the next acquisition reports it and clears it.
    pub(crate) abandoned: bool,
    /// The owner's owned-mutex list membership.
    pub(crate) owner_link: Link<OwnedMutexes>,
}

impl Mutex {
    /// A fresh, free mutex: the record `id` of the pool.
    pub const fn new(id: MutexId) -> Self {
        Mutex {
            waitable: Waitable::with_id(WaitKind::Mutant, 1, WaitableId::Mutex(id.0)),
            owner: None,
            abandoned: false,
            owner_link: Link::detached(),
        }
    }

    /// The record's name.
    pub fn id(&self) -> MutexId {
        match self.waitable.id() {
            WaitableId::Mutex(index) => MutexId(index),
            other => unreachable!("a mutex's header is a mutex record's, not {other:?}"),
        }
    }

    /// The waitable header, as the wait entries take it.
    pub fn waitable(&mut self) -> *mut Waitable {
        &mut self.waitable
    }

    /// The owning thread, none while free.
    pub fn owner(&self) -> Option<ThreadId> {
        self.owner
    }
}

/// Whether `thread` may take `mutex` now: it is free, or `thread` already owns it.
pub(crate) fn available_to(mutex: &Mutex, thread: ThreadId) -> bool {
    mutex.waitable.signal_state > 0 || mutex.owner == Some(thread)
}

impl Dispatcher {
    /// Take one unit of `mutex` for `thread` (it must be [`available_to`] it). The first unit makes
    /// `thread` the owner and puts the mutex on its list; an abandoned mutex reports the
    /// abandonment once, as the status the take returns (success otherwise).
    pub(crate) fn acquire_mutex(&mut self, mutex: MutexId, thread: ThreadId) -> NtStatus {
        let record = self.mutex_mut(mutex);
        record.waitable.signal_state -= 1;
        if record.waitable.signal_state != 0 {
            return STATUS_SUCCESS;
        }
        record.owner = Some(thread);
        let abandoned = core::mem::replace(&mut record.abandoned, false);
        list::push_back(self, OwnedMutexes(thread), mutex);
        if abandoned {
            STATUS_ABANDONED
        } else {
            STATUS_SUCCESS
        }
    }

    /// Release one unit of `mutex` on behalf of `thread` (the running thread): refused unless
    /// that thread owns it. The last unit frees it — off the owner's list, the owner cleared — and
    /// wakes the oldest waiter, which takes it. Returns the previous signal state.
    pub fn release_mutex(
        &mut self,
        mutex: impl Into<MutexId>,
        thread: impl Into<ThreadId>,
    ) -> Result<i32, NtStatus> {
        let (mutex, thread) = (mutex.into(), thread.into());
        let owned = self.mutex(mutex).owner == Some(thread);
        if !owned {
            return Err(STATUS_MUTANT_NOT_OWNED);
        }
        let header = &mut self.mutex_mut(mutex).waitable;
        let previous = header.signal_state;
        header.signal_state += 1;
        if header.signal_state == 1 {
            self.free_mutex(mutex);
        }
        Ok(previous)
    }

    /// Abandon every mutex `thread` owns: each goes back to free, marked abandoned, and its oldest
    /// waiter takes it. The thread's end runs this, before its object signals.
    pub(crate) fn abandon_mutexes(&mut self, thread: ThreadId) {
        while let Some(mutex) = list::first(self, OwnedMutexes(thread)) {
            let record = self.mutex_mut(mutex);
            record.waitable.signal_state = 1;
            record.abandoned = true;
            self.free_mutex(mutex);
        }
    }

    /// The mutex object is being deleted (its last reference went, so no thread waits on it): an
    /// owned mutex leaves its owner's list, which then has nothing of it to abandon.
    pub(crate) fn forget_mutex(&mut self, mutex: MutexId) {
        let record = self.mutex_mut(mutex);
        debug_assert!(
            !record.waitable.has_waiters(),
            "a deleted mutex has no waiters"
        );
        if let Some(owner) = record.owner.take() {
            record.waitable.signal_state = 1;
            list::remove(self, OwnedMutexes(owner), mutex);
        }
    }

    /// The free step: off the owner's list, no owner, and the waiters satisfied.
    fn free_mutex(&mut self, mutex: MutexId) {
        let record = self.mutex_mut(mutex);
        let owner = record.owner.take().expect("a freed mutex was owned");
        let waited = record.waitable.has_waiters();
        list::remove(self, OwnedMutexes(owner), mutex);
        if waited {
            self.satisfy_waiters(WaitableId::Mutex(mutex.0), MUTEX_WAKE_INCREMENT);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sched::event::{Event, EventKind, EVENT_WAKE_INCREMENT};
    use crate::sched::process::SchedProcess;
    use crate::sched::thread::Thread;
    use crate::sched::thread::ThreadState;
    use crate::sched::wait::{ClockStamp, WaitDisposition, WaitMode, WaitReason};
    use crate::status::{STATUS_TIMEOUT, STATUS_USER_APC};

    // The rig: the same leaked-objects style as the scheduler's other test modules.

    fn dispatcher() -> &'static mut Dispatcher {
        crate::sched::testkit::dispatcher()
    }

    fn process() -> *mut SchedProcess {
        let p = Box::leak(Box::new(SchedProcess::new(0x0090_0000, 8)));
        p as *mut SchedProcess
    }

    fn thread(p: *mut SchedProcess) -> crate::sched::testkit::Rec<Thread> {
        crate::sched::testkit::thread(p)
    }

    fn mutex() -> crate::sched::testkit::Rec<Mutex> {
        crate::sched::testkit::mutex()
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

    fn wait(
        d: &mut Dispatcher,
        t: crate::sched::testkit::Rec<Thread>,
        object: *mut Waitable,
    ) -> WaitDisposition {
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
        let mut m = mutex();

        assert_eq!(
            wait(d, owner, m.waitable()),
            WaitDisposition::Complete(STATUS_SUCCESS)
        );
        assert_eq!(
            wait(d, owner, m.waitable()),
            WaitDisposition::Complete(STATUS_SUCCESS)
        );
        assert_eq!(m.waitable.signal_state, -1, "held twice");
        assert_eq!(m.owner(), Some(owner.id()));

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
        assert_eq!(m.owner(), Some(other.id()));
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
        let (mut m1, mut m2) = (mutex(), mutex());
        assert_eq!(
            wait(d, owner, m1.waitable()),
            WaitDisposition::Complete(STATUS_SUCCESS)
        );
        assert_eq!(
            wait(d, owner, m2.waitable()),
            WaitDisposition::Complete(STATUS_SUCCESS)
        );
        assert_eq!(wait(d, waiter, m1.waitable()), WaitDisposition::Yield);

        d.terminate_other(owner);
        assert_eq!(waiter.state(), ThreadState::Ready);
        assert_eq!(waiter.wait_status(), STATUS_ABANDONED);
        assert_eq!(m1.owner(), Some(waiter.id()));
        assert!(!m1.abandoned, "the take reported it");

        assert!(m2.owner().is_none());
        assert_eq!(
            wait(d, late, m2.waitable()),
            WaitDisposition::Complete(STATUS_ABANDONED)
        );
        assert_eq!(d.release_mutex(m2, late), Ok(0));
        assert_eq!(
            wait(d, late, m2.waitable()),
            WaitDisposition::Complete(STATUS_SUCCESS),
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
        let any = |d: &mut Dispatcher, t: crate::sched::testkit::Rec<Thread>, timeout| {
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
        assert_eq!(any(d, t, Some(0)), WaitDisposition::Complete(NtStatus(1)));
        assert_eq!(any(d, t, Some(0)), WaitDisposition::Complete(NtStatus(2)));
        assert_eq!(
            any(d, t, Some(0)),
            WaitDisposition::Complete(STATUS_TIMEOUT)
        );

        assert_eq!(any(d, t, None), WaitDisposition::Yield);
        d.set_event(events[2].id(), EVENT_WAKE_INCREMENT);
        assert_eq!(t.state(), ThreadState::Ready);
        assert_eq!(t.wait_status(), NtStatus(2));
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
        let mut m = mutex();
        assert_eq!(
            wait(d, t, m.waitable()),
            WaitDisposition::Complete(STATUS_SUCCESS)
        );
        let objects = [e0.waitable(), e1.waitable(), m.waitable()];
        let all = |d: &mut Dispatcher, t: crate::sched::testkit::Rec<Thread>, timeout| {
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
        d.set_event(e1.id(), EVENT_WAKE_INCREMENT);
        assert_eq!(t.state(), ThreadState::Ready);
        assert_eq!(t.wait_status(), STATUS_SUCCESS);
        assert!(!e0.signaled() && !e1.signaled(), "both taken");
        assert_eq!(m.waitable.signal_state, -1, "the mutex taken again");
    }

    /// The alert test: an alertable user wait with a user APC queued completes at once with the
    /// user-APC status and arms the delivery; a non-alertable one ignores the queue.
    #[test]
    fn an_alertable_wait_with_user_apcs_queued_completes_at_once() {
        let d = dispatcher();
        let p = process();
        let mut t = thread(p);
        let e = event(EventKind::Notification, false);
        let mut apc = crate::sched::testkit::apc();
        fn marker(_: crate::sched::thread::ThreadId, _: usize, _: usize, _: usize) {}
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
