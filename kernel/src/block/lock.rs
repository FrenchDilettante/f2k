//! The per-device lock: concurrent readers of one device queue instead of colliding in its driver.
//!
//! The lock is a synchronization event created signaled. Acquiring it is a wait on the event (the
//! satisfied wait consumes the signal); releasing it sets the event, which hands the lock straight
//! to the oldest waiter, or leaves it free when nobody waits. A partition's reads land on its
//! disk, so they take the disk's lock.
//!
//! The idle thread cannot block — and a lock held by a parked thread would never come back while
//! the idle thread halts — so on the idle thread (the boot context) the lock must be free: taking
//! a held one there is a contract violation.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::sched::dispatcher::Dispatcher;
use crate::sched::event::{Event, EventKind};
use crate::sched::thread::Thread;
use crate::sched::wait::{ClockStamp, WaitDisposition, WaitMode, WaitReason};

/// The priority increment a release grants the waiter it hands the lock to: none.
const HANDOFF_INCREMENT: i8 = 0;

/// One device's lock.
pub struct DeviceLock {
    event: UnsafeCell<Event>,
    initialized: AtomicBool,
}

// SAFETY: one processor; every access to the event runs with interrupts masked or inside the wait
// discipline, which serializes it.
unsafe impl Sync for DeviceLock {}

impl DeviceLock {
    /// A free lock. Call [`DeviceLock::init`] once it is at its final address.
    pub const fn new() -> Self {
        DeviceLock {
            event: UnsafeCell::new(Event::new(EventKind::Synchronization, true)),
            initialized: AtomicBool::new(false),
        }
    }

    /// Close the event's waiters list; once, at the lock's final address.
    pub fn init(&self) {
        assert!(
            !self.initialized.swap(true, Ordering::SeqCst),
            "device lock initialized twice"
        );
        // SAFETY: nothing can wait on the lock before it is initialized.
        unsafe { (*self.event.get()).init() };
    }

    #[allow(clippy::mut_from_ref)]
    fn event(&self) -> &mut Event {
        assert!(
            self.initialized.load(Ordering::SeqCst),
            "device lock used before init"
        );
        // SAFETY: see the Sync impl — accesses are serialized.
        unsafe { &mut *self.event.get() }
    }

    /// Whether nobody holds the lock.
    pub fn is_free(&self) -> bool {
        self.event().signaled()
    }

    /// Take the lock for `thread`: at once if it is free, otherwise park `thread` on it (the
    /// switch away is the caller's business, as with any wait).
    pub fn acquire_for(
        &self,
        dispatcher: &mut Dispatcher,
        thread: &mut Thread,
        stamp: ClockStamp,
    ) -> WaitDisposition {
        dispatcher.wait_single(
            thread,
            self.event().waitable(),
            WaitReason::Executive,
            WaitMode::Kernel,
            false,
            None,
            stamp,
        )
    }

    /// Give the lock up: the oldest waiter gets it, or it is left free.
    pub fn release_with(&self, dispatcher: &mut Dispatcher) {
        assert!(!self.is_free(), "releasing a device lock nobody holds");
        self.event().set(dispatcher, HANDOFF_INCREMENT);
    }

    /// Run `body` holding the lock.
    #[cfg(target_arch = "x86")]
    pub fn with<R>(&self, body: impl FnOnce() -> R) -> R {
        self.acquire();
        let result = body();
        self.release();
        result
    }

    /// Take the lock for the running thread, blocking while another holds it.
    #[cfg(target_arch = "x86")]
    fn acquire(&self) {
        if crate::sched::idle::on_idle_thread() {
            masked(|| {
                assert!(
                    self.is_free(),
                    "the idle thread cannot wait for a held device lock"
                );
                self.event().reset();
            });
            return;
        }
        let status = crate::sched::wait::wait_current_with(
            |dispatcher, thread, stamp, replay| {
                // An untimed lock wait never replays differently: the APC break re-enters the same
                // acquisition attempt.
                let _ = replay;
                self.acquire_for(dispatcher, thread, stamp)
            },
        );
        assert_eq!(
            status,
            crate::status::STATUS_SUCCESS,
            "an untimed lock wait completes only by the handoff"
        );
    }

    /// Release the lock held by the running thread.
    #[cfg(target_arch = "x86")]
    fn release(&self) {
        masked(|| self.release_with(crate::sched::idle::dispatcher()));
    }
}

/// Run `body` with interrupts masked, then put the flag back as found.
#[cfg(target_arch = "x86")]
fn masked<R>(body: impl FnOnce() -> R) -> R {
    let state = crate::interrupt::irql::state_mut();
    let enabled = state.interrupts_enabled();
    state.mask_interrupts();
    let result = body();
    if enabled {
        state.unmask_interrupts();
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sched::process::SchedProcess;
    use crate::sched::thread::ThreadState;
    use crate::status::STATUS_SUCCESS;

    fn dispatcher() -> &'static mut Dispatcher {
        let dispatcher = Box::leak(Box::new(Dispatcher::zeroed()));
        dispatcher.init();
        dispatcher
    }

    fn thread() -> &'static mut Thread {
        let process = Box::leak(Box::new(SchedProcess::new(0x0090_0000, 8)));
        process.init();
        let thread = Box::leak(Box::new(Thread::empty()));
        // SAFETY: both records are leaked at their final addresses.
        unsafe { thread.attach_to(process) };
        thread.state = ThreadState::Running;
        thread
    }

    fn lock() -> &'static DeviceLock {
        let lock = Box::leak(Box::new(DeviceLock::new()));
        lock.init();
        lock
    }

    const NOW: ClockStamp = ClockStamp {
        system_time: 0,
        tick: 0,
    };

    /// A free lock is taken at once; a second taker parks behind the holder.
    #[test]
    fn a_held_lock_parks_the_second_taker() {
        let d = dispatcher();
        let lock = lock();
        let first = thread();
        let second = thread();
        assert!(lock.is_free());

        assert_eq!(
            lock.acquire_for(d, first, NOW),
            WaitDisposition::Complete(STATUS_SUCCESS)
        );
        assert!(!lock.is_free());
        assert_eq!(first.state(), ThreadState::Running);

        assert_eq!(lock.acquire_for(d, second, NOW), WaitDisposition::Yield);
        assert_eq!(second.state(), ThreadState::Waiting);
    }

    /// The release hands the lock to the oldest waiter, which wakes holding it; the last release
    /// leaves it free.
    #[test]
    fn the_release_hands_the_lock_to_the_oldest_waiter() {
        let d = dispatcher();
        let lock = lock();
        let (first, second, third) = (thread(), thread(), thread());
        assert!(matches!(
            lock.acquire_for(d, first, NOW),
            WaitDisposition::Complete(_)
        ));
        assert_eq!(lock.acquire_for(d, second, NOW), WaitDisposition::Yield);
        assert_eq!(lock.acquire_for(d, third, NOW), WaitDisposition::Yield);

        lock.release_with(d);
        assert_ne!(
            second.state(),
            ThreadState::Waiting,
            "the oldest waiter wakes"
        );
        assert_eq!(second.wait_status(), STATUS_SUCCESS);
        assert_eq!(
            third.state(),
            ThreadState::Waiting,
            "the next one keeps waiting"
        );
        assert!(!lock.is_free(), "handed over, never free in between");

        lock.release_with(d);
        assert_ne!(third.state(), ThreadState::Waiting);
        assert!(!lock.is_free());

        lock.release_with(d);
        assert!(lock.is_free(), "the last release frees it");
    }

    #[test]
    #[should_panic(expected = "nobody holds")]
    fn releasing_a_free_lock_is_a_contract_violation() {
        lock().release_with(dispatcher());
    }

    #[test]
    #[should_panic(expected = "before init")]
    fn an_uninitialized_lock_is_a_contract_violation() {
        let lock = Box::leak(Box::new(DeviceLock::new()));
        lock.is_free();
    }
}
