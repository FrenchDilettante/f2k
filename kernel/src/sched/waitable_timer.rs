//! Waitable timers: the timer object a program creates, sets, waits on, and cancels.
//!
//! A waitable timer is the same timer the wait timeouts use — a waitable header, a due time, a
//! timer-table link — plus what only a program's timer carries: a period and a completion APC.
//! A manual-reset timer is the notification kind (it stays signaled once due, until it is set
//! again); an auto-reset timer is the synchronization kind (the wait it satisfies consumes the
//! signal).
//!
//! A set cancels whatever the timer was doing, resets its signal, and arms it at the due time. A
//! due time already past expires the timer at once — it signals, satisfies its waiters, queues its
//! APC, and a periodic one re-arms — the same steps the clock's expiry walk takes. Each expiry
//! queues the APC to the thread that set the timer, unless the previous expiry's APC is still
//! queued (one outstanding at a time); it runs when that thread next waits alertably. A periodic
//! timer re-arms one period after each expiry, its signal standing.
//!
//! A cancel takes the timer out of the table, drops its period, and takes a queued APC back; the
//! signal stays as it was. The timer is cancelled as well when its last handle closes, when its
//! process ends, and when the thread its APC targets ends — nothing then outlives what it points
//! at.

use core::ptr::addr_of_mut;

use super::apc::Apc;
use super::dispatcher::Dispatcher;
use super::wait::{Timer, WaitKind, Waitable};

/// A waitable timer record: the timer, then the APC record its expiries queue.
#[repr(C)]
pub struct WaitableTimer {
    /// The timer itself; its waitable header leads the record.
    pub(crate) timer: Timer,
    /// The completion APC, bound to the setting thread by each set that names a routine.
    pub(crate) apc: Apc,
}

impl WaitableTimer {
    /// A fresh, unsignaled, unarmed timer; call [`WaitableTimer::init`] at its final address.
    pub const fn new(manual_reset: bool) -> Self {
        WaitableTimer {
            timer: Timer::of_kind(if manual_reset {
                WaitKind::TimerNotification
            } else {
                WaitKind::TimerSynchronization
            }),
            apc: Apc::detached(),
        }
    }

    /// Close the header's waiters sentinel.
    pub fn init(&mut self) {
        self.timer.init();
    }

    /// The waitable header, as the wait entries take it.
    pub fn waitable(&mut self) -> *mut Waitable {
        addr_of_mut!(self.timer.waitable)
    }

    /// The record a waitable header leads.
    pub fn from_waitable(waitable: *mut Waitable) -> *mut WaitableTimer {
        waitable as *mut WaitableTimer
    }

    /// Whether the timer is armed (the table holds it).
    pub fn armed(&self) -> bool {
        self.timer.inserted
    }

    /// Whether the record is still referenced by the scheduler: armed, or its APC queued.
    pub fn busy(&self) -> bool {
        self.timer.inserted || self.apc.inserted
    }

    /// The thread the completion APC targets, null when the timer has none.
    pub fn apc_thread(&self) -> *mut super::thread::Thread {
        if self.timer.apc.is_null() {
            core::ptr::null_mut()
        } else {
            self.apc.thread
        }
    }
}

impl Dispatcher {
    /// Set `timer`: cancel it, reset its signal, and arm it at `due` (a clock reading, 100 ns
    /// units) with `period` (100 ns units, zero for a one-shot). With `completion`, its expiries
    /// queue the record's APC, which the caller has bound to the setting thread and its routine. A
    /// due time at or before `now` expires the timer at once, `signal_time` (the wall clock's
    /// reading at `now`, a FILETIME) the time its APC is given. Returns whether the timer was
    /// signaled before the set.
    pub fn set_waitable_timer(
        &mut self,
        timer: &mut WaitableTimer,
        due: u64,
        now: u64,
        period: u64,
        completion: bool,
        signal_time: u64,
    ) -> bool {
        let previous = self.cancel_timer(&mut timer.timer);
        timer.timer.period = period;
        if completion {
            timer.timer.apc = addr_of_mut!(timer.apc);
        }
        if !self.timer_table.insert(&mut timer.timer, due, now) {
            let header = addr_of_mut!(timer.timer);
            self.expire_timer(header);
            self.timer_fired(&mut timer.timer, now, signal_time);
        }
        previous
    }

    /// Cancel `timer` (see the module notes). Returns whether it was signaled.
    pub fn cancel_waitable_timer(&mut self, timer: &mut WaitableTimer) -> bool {
        self.cancel_timer(&mut timer.timer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sched::process::SchedProcess;
    use crate::sched::thread::{Thread, ThreadState};
    use crate::sched::wait::{ClockStamp, WaitDisposition, WaitMode, WaitReason};
    use crate::status::{STATUS_SUCCESS, STATUS_TIMEOUT, STATUS_USER_APC};

    const INCREMENT: u64 = crate::interrupt::clock::INTERVAL_100NS as u64;

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

    fn timer(manual_reset: bool) -> &'static mut WaitableTimer {
        let t = Box::leak(Box::new(WaitableTimer::new(manual_reset)));
        t.init();
        t
    }

    fn stamp(now: u64) -> ClockStamp {
        ClockStamp {
            interrupt_time: now,
            tick: now / INCREMENT,
        }
    }

    fn wait(
        d: &mut Dispatcher,
        t: &mut Thread,
        object: *mut Waitable,
        now: u64,
    ) -> WaitDisposition {
        d.wait_single(
            t,
            object,
            WaitReason::UserRequest,
            WaitMode::User,
            true,
            Some(0),
            stamp(now),
        )
    }

    /// A wall-clock reading at a timer's signal: 2001-02-03 04:05:06.789 UTC.
    const SIGNALED_AT: u64 = 126_256_467_067_890_000;

    /// Run the clock's expiry walk at tick `n`.
    fn expire_at(d: &mut Dispatcher, n: u64) {
        d.expire_timers(n * INCREMENT, n as u32, 0, SIGNALED_AT);
    }

    /// A manual-reset timer stays signaled once due; a new set resets it.
    #[test]
    fn a_manual_timer_stays_signaled_until_set_again() {
        let d = dispatcher();
        let t = thread(process());
        let m = timer(true);
        assert!(!d.set_waitable_timer(m, 10 * INCREMENT, 0, 0, false, SIGNALED_AT));
        assert!(m.armed());
        assert_eq!(
            wait(d, t, m.waitable(), 0),
            WaitDisposition::Complete(STATUS_TIMEOUT)
        );
        expire_at(d, 10);
        assert!(!m.armed());
        let now = 10 * INCREMENT;
        assert_eq!(
            wait(d, t, m.waitable(), now),
            WaitDisposition::Complete(STATUS_SUCCESS)
        );
        assert_eq!(
            wait(d, t, m.waitable(), now),
            WaitDisposition::Complete(STATUS_SUCCESS),
            "still signaled"
        );
        assert!(
            d.set_waitable_timer(m, now + 5 * INCREMENT, now, 0, false, SIGNALED_AT),
            "was signaled"
        );
        assert_eq!(
            wait(d, t, m.waitable(), now),
            WaitDisposition::Complete(STATUS_TIMEOUT)
        );
    }

    /// An auto-reset periodic timer: each expiry signals once, the wait consumes it, and the timer
    /// re-arms one period on; a cancel stops it.
    #[test]
    fn an_auto_reset_periodic_timer_rearms_and_cancels() {
        let d = dispatcher();
        let t = thread(process());
        let a = timer(false);
        d.set_waitable_timer(a, 5 * INCREMENT, 0, 5 * INCREMENT, false, SIGNALED_AT);
        for period in 1..=3u64 {
            let n = 5 * period;
            expire_at(d, n);
            assert!(a.armed(), "re-armed");
            assert_eq!(a.timer.due_time, (n + 5) * INCREMENT);
            let now = n * INCREMENT;
            assert_eq!(
                wait(d, t, a.waitable(), now),
                WaitDisposition::Complete(STATUS_SUCCESS)
            );
            assert_eq!(
                wait(d, t, a.waitable(), now),
                WaitDisposition::Complete(STATUS_TIMEOUT),
                "consumed"
            );
        }
        assert!(!d.cancel_waitable_timer(a));
        assert!(!a.armed());
        expire_at(d, 20);
        assert_eq!(
            a.timer.waitable.signal_state, 0,
            "a cancelled timer never fires"
        );
    }

    /// A due time already past expires the timer at the set: signaled, its waiters satisfied.
    #[test]
    fn a_past_due_time_expires_at_once() {
        let d = dispatcher();
        let m = timer(true);
        d.set_waitable_timer(m, 100, 200, 0, false, SIGNALED_AT);
        assert!(!m.armed());
        assert_eq!(m.timer.waitable.signal_state, 1);
    }

    /// A due time already past with a completion routine queues the APC at the set itself, the
    /// wall clock's reading then its signal time.
    #[test]
    fn a_past_due_completion_is_queued_at_the_set() {
        let d = dispatcher();
        let setter = thread(process());
        let m = timer(true);
        crate::user::apc::init(&mut m.apc, setter, 0x0040_1000, 7);
        d.set_waitable_timer(m, 100, 200, 0, true, SIGNALED_AT);
        assert!(m.apc.inserted);
        assert_eq!(
            (m.apc.system_argument1, m.apc.system_argument2),
            (SIGNALED_AT as u32 as usize, (SIGNALED_AT >> 32) as usize)
        );
    }

    /// The completion APC: queued to the setting thread at the expiry, it breaks that thread's
    /// alertable wait; a cancel takes a queued one back. Its routine gets the context and the
    /// FILETIME the timer was signaled at, low dword then high.
    #[test]
    fn the_completion_apc_breaks_an_alertable_wait() {
        let d = dispatcher();
        let p = process();
        let setter = thread(p);
        let m = timer(false);
        crate::user::apc::init(&mut m.apc, setter, 0x0040_1000, 7);
        d.set_waitable_timer(m, 5 * INCREMENT, 0, 0, true, SIGNALED_AT);

        // The setter sleeps alertably; the expiry's APC wakes it with the user-APC status.
        assert_eq!(
            d.delay(
                setter,
                WaitMode::User,
                true,
                (100 * INCREMENT) as i64,
                stamp(0)
            ),
            WaitDisposition::Yield
        );
        d.expire_timers(5 * INCREMENT, 5, 0, SIGNALED_AT);
        assert_eq!(setter.state(), ThreadState::Ready);
        assert_eq!(setter.wait_status, STATUS_USER_APC);
        assert!(m.apc.inserted);
        assert_eq!(m.apc.user_routine, 0x0040_1000);
        assert_eq!(m.apc.normal_context, 7);
        assert_eq!(
            (m.apc.system_argument1, m.apc.system_argument2),
            (SIGNALED_AT as u32 as usize, (SIGNALED_AT >> 32) as usize)
        );

        assert!(d.cancel_waitable_timer(m), "signaled: nobody waited on it");
        assert!(!m.apc.inserted, "the cancel took the queued APC back");
        assert!(!m.busy());
    }
}
