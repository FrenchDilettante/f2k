//! The wait lock: state its holder may keep across a wait (a device's commands, a volume's FAT
//! cache, the loader's stagings), as Windows 2000 keeps such state under a KMUTEX or an ERESOURCE.
//! Concurrent users of one device queue instead of colliding in its driver.
//!
//! The lock owns the state it guards, reached only while it is held. Its owner is recorded, and an
//! owner that takes it again is refused: the second acquisition would wait for itself.
//!
//! The lock is a synchronization event created signaled. Acquiring it is a wait on the event (the
//! satisfied wait consumes the signal); releasing it sets the event, which hands the lock straight
//! to the oldest waiter, or leaves it free when nobody waits. A partition's reads land on its
//! disk, so they take the disk's lock.
//!
//! The idle thread cannot block — and a lock held by a parked thread would never come back while
//! the idle thread halts — so on the idle thread (the boot context) the lock must be free: taking
//! a held one there is a contract violation.
//!
//! Any other thread takes the lock only inside a critical region: its holder blocks under it (the
//! drive's commands), and a termination must wait for it to release the lock rather than end it
//! holding one.

use core::cell::UnsafeCell;
#[cfg(target_arch = "x86")]
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

#[cfg(target_arch = "x86")]
use crate::level::{At, Passive};
use crate::sched::dispatcher::Dispatcher;
use crate::sched::event::{Event, EventKind};
use crate::sched::thread::Thread;
use crate::sched::wait::{ClockStamp, WaitDisposition, WaitMode, WaitReason};

/// The priority increment a release grants the waiter it hands the lock to: none.
const HANDOFF_INCREMENT: i8 = 0;

/// A wait lock over `T` (nothing, for a lock that guards a device rather than data).
pub struct DeviceLock<T = ()> {
    event: UnsafeCell<Event>,
    initialized: AtomicBool,
    /// The holding thread (its record's address); 0 when nobody holds the lock, or while a release
    /// hands it to a waiter that has not run yet.
    owner: AtomicUsize,
    value: UnsafeCell<T>,
}

// SAFETY: one processor; every access to the event runs with interrupts masked or inside the wait
// discipline, which serializes it, and the value is reached only by the thread holding the lock,
// which the event grants to one thread at a time. `T: Send`: the value is reached from whichever
// thread holds the lock.
unsafe impl<T: Send> Sync for DeviceLock<T> {}

impl<T> DeviceLock<T> {
    /// A free lock holding `value`. Call [`DeviceLock::init`] once it is at its final address.
    pub const fn new(value: T) -> Self {
        DeviceLock {
            event: UnsafeCell::new(Event::new(EventKind::Synchronization, true)),
            initialized: AtomicBool::new(false),
            owner: AtomicUsize::new(0),
            value: UnsafeCell::new(value),
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

    /// Run `f` on the event, once the lock is initialized.
    fn with_event<R>(&self, f: impl FnOnce(&mut Event) -> R) -> R {
        assert!(
            self.initialized.load(Ordering::SeqCst),
            "device lock used before init"
        );
        // SAFETY: see the Sync impl: accesses are serialized, and the reference ends with `f`.
        f(unsafe { &mut *self.event.get() })
    }

    /// Whether nobody holds the lock.
    pub fn is_free(&self) -> bool {
        self.with_event(|event| event.signaled())
    }

    /// Take the lock for `thread`, which must be inside a critical region: at once if it is free,
    /// otherwise park `thread` on it (the switch away is the caller's business, as with any wait).
    pub fn acquire_for(
        &self,
        dispatcher: &mut Dispatcher,
        thread: &mut Thread,
        stamp: ClockStamp,
    ) -> WaitDisposition {
        assert!(
            thread.in_critical_region(),
            "a device lock taken outside a critical region"
        );
        let taker = identity(thread);
        assert_ne!(
            self.owner.load(Ordering::SeqCst),
            taker,
            "a wait lock taken again by its owner"
        );
        let waitable = self.with_event(|event| event.waitable());
        let disposition = dispatcher.wait_single(
            thread,
            waitable,
            WaitReason::Executive,
            WaitMode::Kernel,
            false,
            None,
            stamp,
        );
        if let WaitDisposition::Complete(_) = disposition {
            self.owner.store(taker, Ordering::SeqCst);
        }
        disposition
    }

    /// Give the lock up: the oldest waiter gets it, or it is left free.
    pub fn release_with(&self, dispatcher: &mut Dispatcher) {
        assert!(!self.is_free(), "releasing a device lock nobody holds");
        self.owner.store(0, Ordering::SeqCst);
        self.with_event(|event| event.set(dispatcher, HANDOFF_INCREMENT));
    }

    /// Run `body` on the value, holding the lock.
    #[cfg(target_arch = "x86")]
    pub fn with<R>(&self, body: impl FnOnce(&mut T) -> R) -> R {
        self.acquire();
        // SAFETY: the running thread holds the lock, so this is the only reference to the value
        // until the release.
        let result = body(unsafe { &mut *self.value.get() });
        self.release();
        result
    }

    /// Take the lock, blocking while another thread holds it; the guard may be kept across a wait.
    /// The passive token is the proof that the caller may block: unlike a short lock's guard, this
    /// one does not keep it borrowed.
    // No caller holds a passive token on the paths that take a wait lock yet: they use `with`.
    #[cfg(target_arch = "x86")]
    #[allow(dead_code)]
    pub fn lock(&self, _passive: &mut At<Passive>) -> WaitGuard<'_, T> {
        self.acquire();
        WaitGuard { lock: self }
    }

    /// Take the lock for the running thread, blocking while another holds it.
    #[cfg(target_arch = "x86")]
    fn acquire(&self) {
        let running = crate::sched::idle::dispatcher().current_thread() as usize;
        assert_ne!(
            self.owner.load(Ordering::SeqCst),
            running,
            "a wait lock taken again by its owner"
        );
        if crate::sched::idle::on_idle_thread() {
            masked(|| {
                assert!(
                    self.is_free(),
                    "the idle thread cannot wait for a held device lock"
                );
                self.with_event(|event| event.reset());
            });
            self.owner.store(running, Ordering::SeqCst);
            return;
        }
        let status = crate::sched::wait::wait_current_with(|dispatcher, thread, stamp, replay| {
            // An untimed lock wait never replays differently: the APC break re-enters the same
            // acquisition attempt.
            let _ = replay;
            self.acquire_for(dispatcher, thread, stamp)
        });
        assert_eq!(
            status,
            crate::status::STATUS_SUCCESS,
            "an untimed lock wait completes only by the handoff"
        );
        // Taken at once, or handed over by a release: either way this thread holds it now.
        self.owner.store(running, Ordering::SeqCst);
    }

    /// Release the lock held by the running thread.
    #[cfg(target_arch = "x86")]
    fn release(&self) {
        masked(|| self.release_with(crate::sched::idle::dispatcher()));
    }
}

/// A thread's identity for the owner check: its record's address.
fn identity(thread: &Thread) -> usize {
    thread as *const Thread as usize
}

/// A held [`DeviceLock`]: derefs to the value, and releases the lock when dropped.
#[cfg(target_arch = "x86")]
pub struct WaitGuard<'a, T> {
    lock: &'a DeviceLock<T>,
}

#[cfg(target_arch = "x86")]
impl<T> Deref for WaitGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        // SAFETY: the guard's thread holds the lock (see the `Sync` impl), and the guard's borrow
        // ties the reference to it.
        unsafe { &*self.lock.value.get() }
    }
}

#[cfg(target_arch = "x86")]
impl<T> DerefMut for WaitGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: as in `deref`; `&mut self` makes this the only reference through the guard.
        unsafe { &mut *self.lock.value.get() }
    }
}

#[cfg(target_arch = "x86")]
impl<T> Drop for WaitGuard<'_, T> {
    fn drop(&mut self) {
        self.lock.release();
    }
}

/// Run `body` with interrupts masked, then put the flag back as found.
#[cfg(target_arch = "x86")]
fn masked<R>(body: impl FnOnce() -> R) -> R {
    let _masked = crate::pcr::pcr().mask_guard();
    body()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sched::process::SchedProcess;
    use crate::sched::thread::ThreadState;
    use crate::status::STATUS_SUCCESS;

    fn dispatcher() -> &'static mut Dispatcher {
        crate::sched::testkit::dispatcher()
    }

    /// A running thread outside any critical region.
    fn bare_thread() -> crate::sched::testkit::Rec<Thread> {
        let process = Box::leak(Box::new(SchedProcess::new(0x0090_0000, 8)));
        let mut thread = crate::sched::testkit::thread(process);
        thread.state = ThreadState::Running;
        thread
    }

    /// A running thread inside a critical region, as every taker of the lock must be.
    fn thread() -> crate::sched::testkit::Rec<Thread> {
        let mut thread = bare_thread();
        thread.enter_critical_region();
        thread
    }

    fn lock() -> &'static DeviceLock {
        let lock = Box::leak(Box::new(DeviceLock::new(())));
        lock.init();
        lock
    }

    const NOW: ClockStamp = ClockStamp {
        interrupt_time: 0,
        tick: 0,
    };

    /// A free lock is taken at once; a second taker parks behind the holder.
    #[test]
    fn a_held_lock_parks_the_second_taker() {
        let d = dispatcher();
        let lock = lock();
        let mut first = thread();
        let mut second = thread();
        assert!(lock.is_free());

        assert_eq!(
            lock.acquire_for(d, &mut first, NOW),
            WaitDisposition::Complete(STATUS_SUCCESS)
        );
        assert!(!lock.is_free());
        assert_eq!(first.state(), ThreadState::Running);

        assert_eq!(
            lock.acquire_for(d, &mut second, NOW),
            WaitDisposition::Yield
        );
        assert_eq!(second.state(), ThreadState::Waiting);
    }

    /// The release hands the lock to the oldest waiter, which wakes holding it; the last release
    /// leaves it free.
    #[test]
    fn the_release_hands_the_lock_to_the_oldest_waiter() {
        let d = dispatcher();
        let lock = lock();
        let (mut first, mut second, mut third) = (thread(), thread(), thread());
        assert!(matches!(
            lock.acquire_for(d, &mut first, NOW),
            WaitDisposition::Complete(_)
        ));
        assert_eq!(
            lock.acquire_for(d, &mut second, NOW),
            WaitDisposition::Yield
        );
        assert_eq!(lock.acquire_for(d, &mut third, NOW), WaitDisposition::Yield);

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

    /// A thread holding the lock may block under it (the drive's commands): it must be inside a
    /// critical region, so a termination waits for it to release the lock.
    #[test]
    #[should_panic(expected = "outside a critical region")]
    fn taking_the_lock_outside_a_critical_region_is_a_contract_violation() {
        lock().acquire_for(dispatcher(), &mut bare_thread(), NOW);
    }

    #[test]
    #[should_panic(expected = "nobody holds")]
    fn releasing_a_free_lock_is_a_contract_violation() {
        lock().release_with(dispatcher());
    }

    #[test]
    #[should_panic(expected = "before init")]
    fn an_uninitialized_lock_is_a_contract_violation() {
        let lock = Box::leak(Box::new(DeviceLock::new(())));
        lock.is_free();
    }

    /// The owner taking the lock again would wait for itself: refused.
    #[test]
    #[should_panic(expected = "taken again by its owner")]
    fn the_owner_taking_the_lock_again_is_refused() {
        let d = dispatcher();
        let lock = lock();
        let mut owner = thread();
        assert!(matches!(
            lock.acquire_for(d, &mut owner, NOW),
            WaitDisposition::Complete(_)
        ));
        lock.acquire_for(d, &mut owner, NOW);
    }

    /// The release clears the owner: the same thread may take the lock again afterwards.
    #[test]
    fn the_release_clears_the_owner() {
        let d = dispatcher();
        let lock = lock();
        let mut owner = thread();
        assert!(matches!(
            lock.acquire_for(d, &mut owner, NOW),
            WaitDisposition::Complete(_)
        ));
        lock.release_with(d);
        assert!(matches!(
            lock.acquire_for(d, &mut owner, NOW),
            WaitDisposition::Complete(_)
        ));
    }
}
