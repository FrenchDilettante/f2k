//! The wait lock: state its holder may keep across a wait (a device's commands, a volume's FAT
//! cache, the loader's stagings), as Windows 2000 keeps such state under a KMUTEX or an ERESOURCE.
//! Concurrent users of one device queue instead of colliding in its driver.
//!
//! The lock owns the state it guards, reached only while it is held. Its owner is recorded, and an
//! owner that takes it again is refused: the second acquisition would wait for itself.
//!
//! The lock is Windows 2000's fast mutex, kept across waits: a count and a synchronization event.
//! The count is 1 when the lock is free, 0 when it is held, and one lower for each thread waiting
//! for it. A take decrements it in one interlocked step (ExAcquireFastMutex's
//! InterlockedDecrement), and finding it was 1 is the whole of an uncontended take: no dispatcher,
//! no wait. A take that finds it held waits on the event. A release increments it
//! (ExReleaseFastMutex's InterlockedIncrement), and when that finds waiters it sets the event
//! under the dispatcher lock, which hands the lock straight to the oldest. The waiter may not have
//! parked yet (it decremented on another processor and is on its way to the wait): the set then
//! leaves the event signaled, and the wait consumes it at once. Between the release that hands
//! over and the waiter's wake the lock is never free: the count stays below 1. A partition's reads
//! land on its disk, so they take the disk's lock.
//!
//! The idle thread cannot block — and a lock held by a parked thread would never come back while
//! the idle thread halts — so on the idle thread (the boot context) the lock must be free: taking
//! a held one there is a contract violation.
//!
//! Any other thread takes the lock only inside a critical region: its holder blocks under it (the
//! drive's commands), and a termination must wait for it to release the lock rather than end it
//! holding one.
//!
//! The event is reached only through the dispatcher (the wait, the set), as Windows 2000's
//! KeWaitForSingleObject and KeSetEvent take KiDispatcherLock: raising the level excludes only the
//! running processor, and the dispatcher's borrow is what excludes the others once its cell takes
//! a spin lock (phase 1's level-cell slice).

use core::cell::UnsafeCell;
#[cfg(target_arch = "x86")]
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicI32, AtomicU8, AtomicUsize, Ordering};

#[cfg(target_arch = "x86")]
use crate::level::{At, Dispatch, Passive};
use crate::sched::dispatcher::Dispatcher;
use crate::sched::event::{Event, EventKind};
use crate::sched::thread::ThreadId;
#[cfg(target_arch = "x86")]
use crate::sched::wait::WaitableId;
use crate::sched::wait::{ClockStamp, WaitDisposition, WaitMode, WaitReason};

/// The priority increment a release grants the waiter it hands the lock to: none.
const HANDOFF_INCREMENT: i8 = 0;

/// The event is not named yet: nothing may reach it.
const UNNAMED: u8 = 0;
/// [`DeviceLock::init`] is naming the event.
const NAMING: u8 = 1;
/// The event is named, for good.
const NAMED: u8 = 2;

/// A wait lock over `T` (nothing, for a lock that guards a device rather than data).
pub struct DeviceLock<T = ()> {
    /// 1 when free; 0 when held; one lower for each thread waiting for it (FAST_MUTEX's Count).
    count: AtomicI32,
    /// The event the waiters wait on: a synchronization event, created clear, set by a release
    /// that finds waiters, which hands the lock to the oldest.
    event: UnsafeCell<Event>,
    /// [`UNNAMED`], [`NAMING`] or [`NAMED`]: the event's naming ([`DeviceLock::init`]), published
    /// only once it is done, so no processor reaches the event half-named.
    initialized: AtomicU8,
    /// The holding thread ([`identity`]); 0 when nobody holds the lock, or while a release hands
    /// it to a waiter that has not run yet.
    owner: AtomicUsize,
    value: UnsafeCell<T>,
}

// SAFETY: the value is reached only by the thread holding the lock, which the count grants to one
// thread at a time: every change to it is one interlocked read-modify-write, so two processors'
// takes cannot both find it free. The take's acquire and the release's release ordering on the
// count, or the handoff through the dispatcher lock, order one holder's writes before the next
// holder's reads. The event is named once (`init`, published before any use reads it) and
// afterwards reached only through the dispatcher (the waiter's wait, the release's set), whose
// lock serializes it with every other processor's reach into the header. `T: Send`: the value is
// reached from whichever thread holds the lock.
unsafe impl<T: Send> Sync for DeviceLock<T> {}

impl<T> DeviceLock<T> {
    /// A free lock holding `value`. Call [`DeviceLock::init`] once it is at its final address.
    pub const fn new(value: T) -> Self {
        DeviceLock {
            count: AtomicI32::new(1),
            event: UnsafeCell::new(Event::new(EventKind::Synchronization, false)),
            initialized: AtomicU8::new(UNNAMED),
            owner: AtomicUsize::new(0),
            value: UnsafeCell::new(value),
        }
    }

    /// Close the event's waiters list; once, at the lock's final address (KeInitializeEvent, as
    /// ExInitializeFastMutex runs it). The lock reads as initialized only once the naming is done
    /// (a release store, which every use's acquire load pairs with), so a use on another processor
    /// never finds the event half-named.
    pub fn init(&self) {
        assert!(
            self.initialized
                .compare_exchange(UNNAMED, NAMING, Ordering::Acquire, Ordering::Relaxed)
                .is_ok(),
            "device lock initialized twice"
        );
        // SAFETY: nothing can wait on the lock before it is initialized: every use checks for
        // NAMED first, and this is the one naming (the exchange above).
        unsafe { (*self.event.get()).init() };
        self.initialized.store(NAMED, Ordering::Release);
    }

    /// Refuse a lock whose event [`DeviceLock::init`] has not named yet.
    fn check_named(&self) {
        assert_eq!(
            self.initialized.load(Ordering::Acquire),
            NAMED,
            "device lock used before init"
        );
    }

    /// The event's name, for the dispatcher: what every reach into the event goes through (see
    /// the `Sync` impl).
    fn event(&self) -> crate::sched::wait::WaitableId {
        self.check_named();
        // SAFETY: named (checked above), and read for that name only; nothing writes the name
        // again while the lock lives.
        unsafe { (*self.event.get()).id() }
    }

    /// Whether nobody holds the lock: the count reads 1.
    pub fn is_free(&self) -> bool {
        self.check_named();
        self.count.load(Ordering::Acquire) == 1
    }

    /// Count the taker in: true when the lock was free and is now its, false when another holds
    /// it and the taker must wait for the handoff.
    fn claim(&self) -> bool {
        self.count.fetch_sub(1, Ordering::AcqRel) == 1
    }

    /// Give the lock up: true when a waiter is owed the handoff (the event's set), false when the
    /// lock is free again.
    ///
    /// # Panics
    ///
    /// The lock was free.
    fn unclaim(&self) -> bool {
        self.owner.store(0, Ordering::SeqCst);
        let count = self.count.fetch_add(1, Ordering::AcqRel);
        assert!(count < 1, "releasing a device lock nobody holds");
        count != 0
    }

    /// Take the lock for `thread`, which must be inside a critical region: at once if it is free,
    /// otherwise park `thread` on its event (the switch away is the caller's business, as with any
    /// wait). Counts the taker in, so a taker parked here is not to come back through it: its
    /// wake is the handoff.
    // The dispatcher-borrowing forms of the take and the release: what the host tests drive. The
    // target's own paths split the count from the dispatcher (`acquire`, `release`).
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn acquire_for(
        &self,
        dispatcher: &mut Dispatcher,
        thread: impl Into<ThreadId>,
        stamp: ClockStamp,
    ) -> WaitDisposition {
        let thread = thread.into();
        assert!(
            dispatcher.thread(thread).in_critical_region(),
            "a device lock taken outside a critical region"
        );
        let taker = identity(thread);
        assert_ne!(
            self.owner.load(Ordering::SeqCst),
            taker,
            "a wait lock taken again by its owner"
        );
        let event = self.event();
        if self.claim() {
            self.owner.store(taker, Ordering::SeqCst);
            return WaitDisposition::Complete(crate::status::STATUS_SUCCESS);
        }
        let disposition = dispatcher.wait_single(
            thread,
            event,
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

    /// Give the lock up, the dispatcher borrowed: the oldest waiter gets it, or it is left free.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn release_with(&self, dispatcher: &mut Dispatcher) {
        let event = self.event();
        if self.unclaim() {
            dispatcher.set_event(event, HANDOFF_INCREMENT);
        }
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
        let running = identity(crate::sched::current_thread());
        assert_ne!(
            self.owner.load(Ordering::SeqCst),
            running,
            "a wait lock taken again by its owner"
        );
        let event = self.event();
        if crate::sched::idle::on_idle_thread() {
            assert!(
                self.count
                    .compare_exchange(1, 0, Ordering::AcqRel, Ordering::Relaxed)
                    .is_ok(),
                "the idle thread cannot wait for a held device lock"
            );
            self.owner.store(running, Ordering::SeqCst);
            return;
        }
        // Checked in debug builds only: the check raises to the dispatch level and lowers again,
        // which a `debug_assert!` argument may not (a release build compiles it out).
        if cfg!(debug_assertions) {
            let critical = crate::level::raised::<Dispatch, _>(|dispatch| {
                let dispatcher = crate::sched::DISPATCHER.get(dispatch);
                dispatcher
                    .current()
                    .is_some_and(|thread| dispatcher.thread(thread).in_critical_region())
            });
            assert!(critical, "a device lock taken outside a critical region");
        }
        // A free lock is taken by the count alone, without entering the wait: a wait satisfied at
        // once is charged against the quantum, so entering one for every uncontended take ran a
        // thread doing file reads off its quantum in a handful of them, an equal-priority thread
        // taking the processor at each sixth.
        if !self.claim() {
            self.wait_for_handoff(event);
        }
        // Taken at once, or handed over by a release: either way this thread holds it now.
        self.owner.store(running, Ordering::SeqCst);
    }

    /// Wait on the event until a release hands the lock over. The count already holds this
    /// thread's place: an APC break re-enters the wait alone, never the count.
    #[cfg(target_arch = "x86")]
    fn wait_for_handoff(&self, event: WaitableId) {
        let status = crate::sched::wait::wait_current_with(|dispatcher, thread, stamp, replay| {
            // An untimed lock wait never replays differently.
            let _ = replay;
            dispatcher.wait_single(
                thread,
                event,
                WaitReason::Executive,
                WaitMode::Kernel,
                false,
                None,
                stamp,
            )
        });
        assert_eq!(
            status,
            crate::status::STATUS_SUCCESS,
            "an untimed lock wait completes only by the handoff"
        );
    }

    /// Release the lock held by the running thread: with nobody waiting, the count alone frees it
    /// (no dispatcher); with a waiter, the event's set under the dispatcher lock hands it over
    /// (ExReleaseFastMutex's KeSetEventBoostPriority).
    #[cfg(target_arch = "x86")]
    fn release(&self) {
        let event = self.event();
        if self.unclaim() {
            crate::level::raised::<Dispatch, _>(|dispatch| {
                crate::sched::DISPATCHER
                    .get(dispatch)
                    .set_event(event, HANDOFF_INCREMENT);
            });
        }
    }
}

/// A thread's identity for the owner check: its record's index, one up (0 is nobody).
pub(crate) fn identity(thread: ThreadId) -> usize {
    thread.index() as usize + 1
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sched::process::SchedProcess;
    use crate::sched::thread::Thread;
    use crate::sched::thread::ThreadState;
    use crate::status::STATUS_SUCCESS;

    fn dispatcher() -> crate::sched::testkit::Disp {
        crate::sched::testkit::dispatcher()
    }

    /// A running thread outside any critical region.
    fn bare_thread() -> crate::sched::testkit::Rec<Thread> {
        let process = Box::leak(Box::new(SchedProcess::new(
            crate::mem::phys::PhysAddr::new(0x0090_0000),
            8,
        )));
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
        let mut d = dispatcher();
        let lock = lock();
        let first = thread();
        let second = thread();
        assert!(lock.is_free());

        assert_eq!(
            lock.acquire_for(&mut d, first, NOW),
            WaitDisposition::Complete(STATUS_SUCCESS)
        );
        assert!(!lock.is_free());
        assert_eq!(first.state(), ThreadState::Running);

        assert_eq!(
            lock.acquire_for(&mut d, second, NOW),
            WaitDisposition::Yield
        );
        assert_eq!(second.state(), ThreadState::Waiting);
    }

    /// The release hands the lock to the oldest waiter, which wakes holding it; the last release
    /// leaves it free.
    #[test]
    fn the_release_hands_the_lock_to_the_oldest_waiter() {
        let mut d = dispatcher();
        let lock = lock();
        let (first, second, third) = (thread(), thread(), thread());
        assert!(matches!(
            lock.acquire_for(&mut d, first, NOW),
            WaitDisposition::Complete(_)
        ));
        assert_eq!(
            lock.acquire_for(&mut d, second, NOW),
            WaitDisposition::Yield
        );
        assert_eq!(lock.acquire_for(&mut d, third, NOW), WaitDisposition::Yield);

        lock.release_with(&mut d);
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

        lock.release_with(&mut d);
        assert_ne!(third.state(), ThreadState::Waiting);
        assert!(!lock.is_free());

        lock.release_with(&mut d);
        assert!(lock.is_free(), "the last release frees it");
    }

    /// A waiter counts itself in, and the release hands off before it has parked (it is on its way
    /// to the wait on another processor): the set leaves the event signaled, and the wait that
    /// follows completes at once, holding the lock.
    #[test]
    fn a_handoff_before_the_waiter_parks_is_kept_for_it() {
        let mut d = dispatcher();
        let lock = lock();
        let (first, second) = (thread(), thread());
        assert!(matches!(
            lock.acquire_for(&mut d, first, NOW),
            WaitDisposition::Complete(_)
        ));
        assert!(
            !lock.claim(),
            "held: the second taker is counted in to wait"
        );
        lock.release_with(&mut d);
        assert!(!lock.is_free(), "handed over, never free in between");
        let event = lock.event();
        assert_eq!(
            d.wait_single(
                second,
                event,
                WaitReason::Executive,
                WaitMode::Kernel,
                false,
                None,
                NOW
            ),
            WaitDisposition::Complete(STATUS_SUCCESS)
        );
        assert_eq!(second.state(), ThreadState::Running);
        lock.release_with(&mut d);
        assert!(lock.is_free());
    }

    /// A thread holding the lock may block under it (the drive's commands): it must be inside a
    /// critical region, so a termination waits for it to release the lock.
    #[test]
    #[should_panic(expected = "outside a critical region")]
    fn taking_the_lock_outside_a_critical_region_is_a_contract_violation() {
        let mut d = dispatcher();
        let thread = bare_thread();
        lock().acquire_for(&mut d, thread, NOW);
    }

    #[test]
    #[should_panic(expected = "nobody holds")]
    fn releasing_a_free_lock_is_a_contract_violation() {
        lock().release_with(&mut dispatcher());
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
        let mut d = dispatcher();
        let lock = lock();
        let owner = thread();
        assert!(matches!(
            lock.acquire_for(&mut d, owner, NOW),
            WaitDisposition::Complete(_)
        ));
        lock.acquire_for(&mut d, owner, NOW);
    }

    /// The release clears the owner: the same thread may take the lock again afterwards.
    #[test]
    fn the_release_clears_the_owner() {
        let mut d = dispatcher();
        let lock = lock();
        let owner = thread();
        assert!(matches!(
            lock.acquire_for(&mut d, owner, NOW),
            WaitDisposition::Complete(_)
        ));
        lock.release_with(&mut d);
        assert!(matches!(
            lock.acquire_for(&mut d, owner, NOW),
            WaitDisposition::Complete(_)
        ));
    }
}
