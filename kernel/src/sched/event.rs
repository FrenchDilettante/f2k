//! The event object: the smallest waitable kernel object.
//!
//! An event is its waitable header plus nothing else — the
//! smallest waitable kernel object. Two
//! flavors share every path: a notification (manual-reset) event
//! signals until cleared and one signal wakes every waiter, a
//! synchronization (auto-reset) event's signal serves exactly one
//! waiter. Which flavor an event is decides only what a satisfied
//! wait does to the signal — the wait discipline is one code.

use super::dispatcher::Dispatcher;
use super::wait::{entry_to_block, WaitKind, Waitable};
use core::ptr::addr_of_mut;

/// The priority increment a set grants the waiters it wakes.
pub const EVENT_WAKE_INCREMENT: i8 = 1;

/// The two event flavors.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EventKind {
    /// Manual-reset: signaled until cleared; one signal wakes
    /// every waiter present.
    Notification,
    /// Auto-reset: one signal wakes exactly one waiter, and the
    /// satisfy consumes the signal.
    Synchronization,
}

/// An event: a waitable object with no state beyond its header.
#[repr(C)]
pub struct Event {
    /// The waitable header — the whole object.
    pub(crate) waitable: Waitable,
}

impl Event {
    /// A fresh event of `kind` with the given initial signal
    /// state. Call [`Event::init`] once the event is at its final
    /// address.
    pub const fn new(kind: EventKind, signaled: bool) -> Self {
        let wait_kind = match kind {
            EventKind::Notification => WaitKind::NotificationEvent,
            EventKind::Synchronization => WaitKind::SynchronizationEvent,
        };
        let signal_state = if signaled { 1 } else { 0 };
        Event { waitable: Waitable::new(wait_kind, signal_state) }
    }

    /// Close the waiters sentinel; call once at the final address.
    pub fn init(&mut self) {
        self.waitable.init();
    }

    /// The event's flavor.
    pub fn kind(&self) -> EventKind {
        match self.waitable.kind {
            WaitKind::SynchronizationEvent => EventKind::Synchronization,
            _ => EventKind::Notification,
        }
    }

    /// The signal state: positive means signaled.
    pub fn signal_state(&self) -> i32 {
        self.waitable.signal_state
    }

    /// Whether the event is signaled.
    pub fn signaled(&self) -> bool {
        self.waitable.signal_state > 0
    }

    /// The event's waitable header, as the wait entry takes it.
    pub fn waitable(&mut self) -> *mut Waitable {
        addr_of_mut!(self.waitable)
    }

    /// Clear the event: the write-only fast form. Clearing wakes
    /// nobody — a waiter parked on the event stays parked until a
    /// later signal or its own timeout.
    pub fn clear(&mut self) {
        self.waitable.signal_state = 0;
    }

    /// Reset the event, returning its previous signal state.
    pub fn reset(&mut self) -> i32 {
        let previous = self.waitable.signal_state;
        self.waitable.signal_state = 0;
        previous
    }

    /// Signal the event, granting its waiters a wake boost of
    /// `increment`, and return the previous signal state.
    ///
    /// With no waiters the signal parks on the event — for both
    /// flavors — until a waiter consumes it. With waiters: a
    /// notification event signals and wakes every waiter present;
    /// a synchronization event wakes exactly one, the oldest — and
    /// with a single waiter it does so directly, leaving the
    /// signal state unwritten (it stays clear, which a one-waiter
    /// walk would have produced anyway).
    pub fn set(&mut self, dispatcher: &mut Dispatcher, increment: i8) -> i32 {
        let previous = self.waitable.signal_state;
        if self.waitable.waiters.is_empty() {
            self.waitable.signal_state = 1;
            return previous;
        }

        // SAFETY: the waiters list is initialized and non-empty;
        // its first entry is a live wait block.
        let head = entry_to_block(unsafe { self.waitable.waiters.first() });
        // SAFETY: the head block's wait-all flag is a plain read.
        let head_wait_all = unsafe { (*head).wait_all };

        if self.waitable.kind == WaitKind::NotificationEvent || head_wait_all {
            if previous == 0 {
                self.waitable.signal_state = 1;
                let waitable = addr_of_mut!(self.waitable);
                dispatcher.satisfy_waiters(waitable, increment);
            }
        } else {
            // The synchronization fast path: exactly one waiter,
            // served directly.
            // SAFETY: the head block's thread and key are live;
            // the thread is a waiting thread.
            let (thread, key) = unsafe { ((*head).thread, (*head).key) };
            dispatcher.unwait(unsafe { &mut *thread }, key, increment);
        }
        previous
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sched::dispatcher::Dispatcher;
    use crate::sched::wait::{WaitKind, WAIT_KIND_MASK};

    fn dispatcher() -> &'static mut Dispatcher {
        let d = Box::leak(Box::new(Dispatcher::zeroed()));
        d.init();
        d
    }

    fn event(kind: EventKind, signaled: bool) -> &'static mut Event {
        let ev = Box::leak(Box::new(Event::new(kind, signaled)));
        ev.init();
        ev
    }

    /// Initialization, both flavors, both initial states: the
    /// flavor lands on the kind, the initial state on the signal,
    /// the waiters list starts closed and empty — and an event
    /// created signaled stays signaled until something consumes
    /// it; no flavor resets at creation.
    #[test]
    fn events_initialize_both_flavors() {
        let notification = event(EventKind::Notification, false);
        assert_eq!(notification.kind(), EventKind::Notification);
        assert_eq!(notification.signal_state(), 0);
        assert!(notification.waitable.waiters.is_empty());

        let synchronization = event(EventKind::Synchronization, false);
        assert_eq!(synchronization.kind(), EventKind::Synchronization);
        assert_eq!(synchronization.signal_state(), 0);

        let signaled_notification = event(EventKind::Notification, true);
        let signaled_synchronization = event(EventKind::Synchronization, true);
        assert_eq!(signaled_notification.signal_state(), 1);
        assert_eq!(signaled_synchronization.signal_state(), 1);
        assert!(signaled_notification.signaled());
        assert!(signaled_synchronization.signaled());
    }

    /// Read, clear, reset: read reports the current state, clear
    /// is the write-only fast form, reset returns the previous
    /// state. None of the three touches the waiters — clearing an
    /// event wakes nobody.
    #[test]
    fn read_clear_reset_report_the_state() {
        let d = dispatcher();
        let ev = event(EventKind::Notification, true);

        assert_eq!(ev.signal_state(), 1);
        ev.clear();
        assert_eq!(ev.signal_state(), 0);
        assert_eq!(ev.set(d, EVENT_WAKE_INCREMENT), 0, "set returns the previous state");
        assert_eq!(ev.reset(), 1, "reset returns the previous state");
        assert_eq!(ev.signal_state(), 0);
        assert_eq!(ev.reset(), 0, "a second reset reports the already-clear state");
        assert!(ev.waitable.waiters.is_empty());
    }

    /// A set with no waiters parks the signal on the event, for
    /// both flavors: the reset happens at a satisfied wait (the
    /// auto-reset take), never at the set.
    #[test]
    fn a_set_with_no_waiters_parks_the_signal() {
        let d = dispatcher();
        let notification = event(EventKind::Notification, false);
        let synchronization = event(EventKind::Synchronization, false);

        assert_eq!(notification.set(d, EVENT_WAKE_INCREMENT), 0);
        assert_eq!(synchronization.set(d, EVENT_WAKE_INCREMENT), 0);
        assert_eq!(notification.signal_state(), 1);
        assert_eq!(synchronization.signal_state(), 1, "an auto-reset event with no waiters holds its signal");
    }

    /// The kind ordinals: the events, the thread object, the timer
    /// flavors, and the mask that folds the timer kinds onto the
    /// event rule — stable kernel data the satisfy dispatch reads.
    #[test]
    fn the_kind_ordinals_and_mask() {
        assert_eq!(WaitKind::NotificationEvent as u8, 0);
        assert_eq!(WaitKind::SynchronizationEvent as u8, 1);
        assert_eq!(WaitKind::Thread as u8, 6);
        assert_eq!(WaitKind::TimerNotification as u8, 8);
        assert_eq!(WaitKind::TimerSynchronization as u8, 9);
        assert_eq!(WAIT_KIND_MASK, 0x7);

        // The masked rule: the timer kinds sit on the event rule.
        assert!(!WaitKind::NotificationEvent.consumes_signal());
        assert!(WaitKind::SynchronizationEvent.consumes_signal());
        assert!(!WaitKind::Thread.consumes_signal());
        assert!(!WaitKind::TimerNotification.consumes_signal());
        assert!(WaitKind::TimerSynchronization.consumes_signal());
    }
}
