//! The semaphore object: a waitable whose signal state is a count.
//!
//! One satisfied waiter consumes exactly one count, so a release wakes as many waiters as it adds.
//! The thread's builtin suspend semaphore is one (the suspend APC's normal routine parks on it, a
//! kernel-internal object); the object manager's semaphore objects, which handles name, are the
//! others.

use super::dispatcher::Dispatcher;
use super::thread::ThreadId;
use super::wait::{WaitKind, Waitable, WaitableId};

/// A counting semaphore.
pub struct Semaphore {
    /// The count as a waitable signal state: positive means `count` units available.
    pub(crate) waitable: Waitable,
    /// The count's ceiling. A release past it is refused outright.
    pub(crate) limit: i32,
}

impl Semaphore {
    /// A fresh semaphore to embed, at count zero with the ceiling `limit`; call
    /// [`Semaphore::init`] once it is at its final address.
    pub const fn new(limit: i32) -> Self {
        Semaphore {
            waitable: Waitable::new(WaitKind::Semaphore, 0),
            limit,
        }
    }

    /// A fresh semaphore of the database, at count zero with the ceiling `limit`, its header the
    /// record `id`.
    pub const fn with_id(limit: i32, id: WaitableId) -> Self {
        Semaphore {
            waitable: Waitable::with_id(WaitKind::Semaphore, 0, id),
            limit,
        }
    }

    /// Name an embedded semaphore by its address; call once at its final address.
    pub fn init(&mut self) {
        self.waitable.init();
    }

    /// The waitable header, as the wait entry takes it.
    pub(crate) fn waitable(&mut self) -> *mut Waitable {
        &mut self.waitable
    }

    /// The current count.
    pub fn count(&self) -> i32 {
        self.waitable.signal_state
    }
}

impl Dispatcher {
    /// Release a semaphore: add `adjustment` to the count and satisfy as many waiters as the
    /// addition allows, waking each with `increment`. Refused outright when the new count would
    /// pass the ceiling or wrap — the count is left untouched. Returns the previous count.
    pub fn release_semaphore(
        &mut self,
        semaphore: &mut Semaphore,
        adjustment: i32,
        increment: i8,
    ) -> Result<i32, crate::status::NtStatus> {
        // The record is read for its ceiling and its name; the release works through the name.
        let (limit, semaphore) = (semaphore.limit, semaphore.waitable.id());
        let header = self.waitable_mut(semaphore);
        let old = header.signal_state;
        let new = old.wrapping_add(adjustment);
        if new > limit || new < old {
            return Err(crate::status::STATUS_SEMAPHORE_LIMIT_EXCEEDED);
        }
        header.signal_state = new;
        // Waiters can only be parked while the count is zero, so a release from zero is the only
        // one that can satisfy anyone.
        if old == 0 && header.has_waiters() {
            self.satisfy_waiters(semaphore, increment);
        }
        Ok(old)
    }

    /// The suspend semaphore's release: one count, no ceiling check (the suspend count table
    /// bounds it), and the satisfy runs regardless of the previous count — a forced resume can
    /// release with nobody parked, and the count it leaves is the residue the next suspend's
    /// satisfied wait consumes. This is the wake half of resume.
    pub(crate) fn release_suspend_semaphore(&mut self, thread: ThreadId) {
        self.thread_mut(thread)
            .suspend_semaphore
            .waitable
            .signal_state += 1;
        self.satisfy_waiters(
            WaitableId::Suspend(thread),
            super::apc::SUSPEND_WAKE_INCREMENT,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sched::dispatcher::Dispatcher;
    use crate::sched::process::SchedProcess;
    use crate::sched::thread::Thread;
    use crate::sched::wait::{WaitDisposition, WaitMode, WaitReason};

    // The rig: the same leaked-objects style as the scheduler's other test modules.

    fn dispatcher() -> &'static mut Dispatcher {
        crate::sched::testkit::dispatcher()
    }

    fn process(base: i8) -> *mut SchedProcess {
        let p = Box::leak(Box::new(SchedProcess::new(0x0090_0000, base)));
        p as *mut SchedProcess
    }

    fn thread(p: *mut SchedProcess) -> crate::sched::testkit::Rec<Thread> {
        crate::sched::testkit::thread(p)
    }

    /// Park `t` on `semaphore`, asserting the wait blocked.
    fn park_on(
        d: &mut Dispatcher,
        t: crate::sched::testkit::Rec<Thread>,
        semaphore: &mut Semaphore,
    ) {
        let stamp = crate::sched::wait::ClockStamp {
            interrupt_time: 10_000,
            tick: 5,
        };
        match d.wait_single(
            t,
            semaphore.waitable(),
            WaitReason::Executive,
            WaitMode::Kernel,
            false,
            None,
            stamp,
        ) {
            WaitDisposition::Yield => {}
            _ => panic!("expected the wait to park the thread"),
        }
    }

    /// F5: the satisfy arithmetic — one waiter per count, the count consumed per take; a residue
    /// count serves as many waiters as it covers.
    #[test]
    fn a_release_serves_one_waiter_per_count() {
        let d = dispatcher();
        let p = process(8);
        let mut semaphore = Semaphore::new(2);
        semaphore.init();
        let w1 = thread(p);
        let w2 = thread(p);
        park_on(d, w1, &mut semaphore);
        park_on(d, w2, &mut semaphore);

        assert_eq!(
            d.release_semaphore(&mut semaphore, 1, 0),
            Ok(0),
            "the previous count"
        );
        assert_eq!(
            w1.state(),
            crate::sched::thread::ThreadState::Ready,
            "the first waiter woke"
        );
        assert_eq!(
            semaphore.count(),
            0,
            "the satisfied take consumed the count"
        );
        assert_eq!(
            w2.state(),
            crate::sched::thread::ThreadState::Waiting,
            "the second waiter stays parked"
        );

        // The second release wakes the second waiter likewise.
        assert_eq!(d.release_semaphore(&mut semaphore, 1, 0), Ok(0));
        assert_eq!(w2.state(), crate::sched::thread::ThreadState::Ready);
        assert_eq!(semaphore.count(), 0);

        // The multi-count variant: a release of two serves both waiters, one count each.
        let w3 = thread(p);
        let w4 = thread(p);
        park_on(d, w3, &mut semaphore);
        park_on(d, w4, &mut semaphore);
        assert_eq!(d.release_semaphore(&mut semaphore, 2, 0), Ok(0));
        assert_eq!(
            w3.state(),
            crate::sched::thread::ThreadState::Ready,
            "the residue count served the first waiter"
        );
        assert_eq!(
            w4.state(),
            crate::sched::thread::ThreadState::Ready,
            "and the second"
        );
        assert_eq!(semaphore.count(), 0);
    }

    /// F6: the release's bound — past the ceiling or a wrap refuses, the count untouched, nobody
    /// woken.
    #[test]
    fn the_release_bound_refuses_past_the_ceiling() {
        let d = dispatcher();
        let p = process(8);
        let mut semaphore = Semaphore::new(2);
        semaphore.init();
        let t = thread(p);
        park_on(d, t, &mut semaphore);

        semaphore.waitable.signal_state = 2;
        assert_eq!(
            d.release_semaphore(&mut semaphore, 1, 0),
            Err(crate::status::STATUS_SEMAPHORE_LIMIT_EXCEEDED)
        );
        assert_eq!(semaphore.count(), 2, "unchanged");
        assert_eq!(
            t.state(),
            crate::sched::thread::ThreadState::Waiting,
            "nobody woken"
        );

        semaphore.waitable.signal_state = 1;
        assert_eq!(
            d.release_semaphore(&mut semaphore, 2, 0),
            Err(crate::status::STATUS_SEMAPHORE_LIMIT_EXCEEDED),
            "the adjustment would pass the ceiling"
        );
        assert_eq!(semaphore.count(), 1);
    }
}
