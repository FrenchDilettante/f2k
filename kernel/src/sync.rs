//! Kernel state that is not a level cell's: values set once at boot ([`InitOnce`]), static buffers
//! handed out once ([`StaticBuf`]), and the short lock for passive-level state ([`ShortLock`],
//! Windows 2000's fast mutex). The wait lock, which its holder may keep across a wait, is
//! [`crate::block::lock::DeviceLock`].
//!
//! # The short lock
//!
//! State touched by preemptible code (the object directory, the handle tables, an address space)
//! cannot live in a level cell: at the passive and APC levels the clock may switch threads, and
//! another thread at the same level could reach it. Windows 2000 guards such state with a fast
//! mutex: ExAcquireFastMutex raises to APC_LEVEL, takes the mutex, and waits on the mutex's event
//! when another thread holds it; ExReleaseFastMutex hands it to a waiter and lowers. Its holders
//! keep it briefly, and never across a wait.
//!
//! [`ShortLock::lock`] is that, with the "never across a wait" made static: it takes the caller's
//! passive token, and the guard keeps it borrowed, so nothing that takes the passive token (a wait,
//! a user-memory copy, a switch) can be called while the guard lives. The guard lends the APC token
//! instead, so the holder may still raise further, to the dispatch level, as Windows 2000 allows a
//! spin lock under a fast mutex.
//!
//! Interrupts and their deferred work run while a short lock is held, and the holder may be
//! preempted, as Windows 2000 preempts a fast mutex's: another thread may then find the lock held
//! and wait for it, at the APC level. Nothing ends a holder or a waiter where it stands: a thread
//! is terminated by a kernel APC (see
//! [`crate::sched::dispatcher::Dispatcher::request_termination`]), which cannot land at the APC
//! level — the holder releases, the waiter takes the lock and releases it, and the exit comes at
//! the thread's next window once it lowers.
//!
//! The one thread that cannot wait for a short lock is the idle thread, which reaps an ended
//! process on its stack. It runs on its own only when no other thread is ready, and so when no
//! thread holds a short lock; a process's last thread hands it the processor directly only while
//! none is held (see [`short_locks_free`]).
//!
//! ```compile_fail,E0499
//! use f2k_kernel::level::{At, Passive};
//! use f2k_kernel::sync::ShortLock;
//! fn wait(_: &mut At<Passive>) {}
//! fn misuse(lock: &ShortLock<u32>, passive: &mut At<Passive>) {
//!     let mut guard = lock.lock(passive);
//!     wait(passive);
//!     *guard += 1;
//! }
//! ```

use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU8, Ordering};

use crate::level::{Apc, At, Passive, Raised};
use crate::pcr::pcr;
use crate::sched::event::{Event, EventKind};

/// A value set once, at boot, then read freely: `get` hands out `&T` for the kernel's lifetime.
///
/// Setting it twice panics, and so does reading it before it is set: both are boot-order bugs.
pub struct InitOnce<T> {
    /// [`EMPTY`], [`SETTING`] or [`SET`].
    state: AtomicU8,
    value: UnsafeCell<MaybeUninit<T>>,
}

/// Nothing set yet.
const EMPTY: u8 = 0;
/// A set is writing the value.
const SETTING: u8 = 1;
/// The value is set, and never changes again.
const SET: u8 = 2;

// SAFETY: the value is written once, by the one `set` that moved the state from EMPTY, before the
// state reads SET (release); `get` hands out shared references only once it reads SET (acquire), so
// no reference to the value is alive during the write. `T: Sync` because the value is shared;
// `T: Send` because the setter's value is reached from every thread.
unsafe impl<T: Send + Sync> Sync for InitOnce<T> {}

impl<T> InitOnce<T> {
    /// An unset value.
    pub const fn new() -> Self {
        InitOnce {
            state: AtomicU8::new(EMPTY),
            value: UnsafeCell::new(MaybeUninit::uninit()),
        }
    }

    /// Set the value.
    ///
    /// # Panics
    ///
    /// It was set already.
    pub fn set(&self, value: T) {
        let claimed =
            self.state
                .compare_exchange(EMPTY, SETTING, Ordering::Acquire, Ordering::Relaxed);
        assert!(claimed.is_ok(), "a set-once value set twice");
        // SAFETY: the exchange above made this the one setter, and no `get` hands out a reference
        // before the state reads SET, below: this is the only reference to the slot.
        unsafe { (*self.value.get()).write(value) };
        self.state.store(SET, Ordering::Release);
    }

    /// The value.
    ///
    /// # Panics
    ///
    /// It is not set yet.
    pub fn get(&self) -> &T {
        assert_eq!(
            self.state.load(Ordering::Acquire),
            SET,
            "a set-once value read before it was set"
        );
        // SAFETY: the state reads SET, so the value was written and is never written again.
        unsafe { (*self.value.get()).assume_init_ref() }
    }
}

impl<T> Drop for InitOnce<T> {
    fn drop(&mut self) {
        if *self.state.get_mut() == SET {
            // SAFETY: the state reads SET, so the value was written; `&mut self` makes this the
            // only reference, and the value is dropped once.
            unsafe { self.value.get_mut().assume_init_drop() };
        }
    }
}

/// A static buffer handed out once, as a `&'static mut`: a table or a buffer the boot fills and one
/// owner keeps (the frame table, the page colour tables).
///
/// A second [`StaticBuf::take`] panics.
pub struct StaticBuf<T> {
    taken: AtomicBool,
    value: UnsafeCell<T>,
}

// SAFETY: the value is reached only through the one `take` that flips `taken`, which hands out the
// only reference to it; `T: Send` because that reference may be taken on any thread.
unsafe impl<T: Send> Sync for StaticBuf<T> {}

impl<T> StaticBuf<T> {
    /// A buffer holding `value`, not taken yet.
    pub const fn new(value: T) -> Self {
        StaticBuf {
            taken: AtomicBool::new(false),
            value: UnsafeCell::new(value),
        }
    }

    /// The buffer, exclusively, for good.
    ///
    /// # Panics
    ///
    /// It was taken already.
    // The `&mut` from `&self` is the point: the swap below lets exactly one caller through, so the
    // reference it hands out is the only one there will ever be.
    #[allow(clippy::mut_from_ref)]
    pub fn take(&'static self) -> &'static mut T {
        assert!(
            !self.taken.swap(true, Ordering::AcqRel),
            "a static buffer taken twice"
        );
        // SAFETY: the swap above made this the one take, so this is the only reference to the
        // value, and the buffer lives for 'static.
        unsafe { &mut *self.value.get() }
    }
}

/// How many short locks are held, by whichever threads hold them (a holder may be preempted, so
/// they need not be the running thread's).
static HOLDS: AtomicU32 = AtomicU32::new(0);

/// Whether no thread holds a short lock: the idle thread, which cannot wait for one, may then take
/// any of them (see the module notes).
#[cfg_attr(not(target_arch = "x86"), allow(dead_code))]
pub fn short_locks_free() -> bool {
    HOLDS.load(Ordering::SeqCst) == 0
}

/// The priority increment a release grants the waiter it hands the lock to: none, as the device
/// lock's.
#[cfg_attr(not(test), allow(dead_code))]
const HANDOFF_INCREMENT: i8 = 0;

/// A short lock: passive-level state held briefly, never across a wait (Windows 2000's
/// FAST_MUTEX). See the module notes.
#[cfg_attr(not(any(test, target_arch = "x86")), allow(dead_code))]
pub struct ShortLock<T> {
    /// 1 when free; 0 when held; one lower for each thread waiting for it (FAST_MUTEX's Count).
    count: AtomicI32,
    /// How many acquisitions found the lock held (FAST_MUTEX's Contention).
    contention: AtomicU32,
    /// The thread holding the lock, as its record's index one up (FAST_MUTEX's Owner); 0 while it
    /// is free, or held where no thread runs (the host's tests). Read by the re-entry check only.
    owner: AtomicU32,
    /// The event the waiters wait on: a synchronization event, set by a release that finds
    /// waiters, which hands the lock to the oldest.
    event: UnsafeCell<Event>,
    value: UnsafeCell<MaybeUninit<T>>,
    /// What builds the value at the first acquisition; none once it is built (from the start, for
    /// a lock made with its value). Reached only by the lock's holder, as the value is.
    build: UnsafeCell<Option<unsafe fn(*mut T)>>,
}

// SAFETY: the value and its build slot are reached only through a guard, and a guard exists only
// while its thread holds the lock, which the count (changed with interrupts masked, on one
// processor) grants to one thread at a time. The event is touched only with interrupts masked or
// inside the wait discipline, which serializes it. `T: Send`: the value is reached from whichever
// thread holds the lock.
unsafe impl<T: Send> Sync for ShortLock<T> {}

#[cfg_attr(not(any(test, target_arch = "x86")), allow(dead_code))]
impl<T> ShortLock<T> {
    /// A free lock holding `value`.
    #[cfg_attr(not(test), allow(dead_code))]
    pub const fn new(value: T) -> Self {
        ShortLock {
            count: AtomicI32::new(1),
            contention: AtomicU32::new(0),
            owner: AtomicU32::new(0),
            event: UnsafeCell::new(Event::new(EventKind::Synchronization, false)),
            value: UnsafeCell::new(MaybeUninit::new(value)),
            build: UnsafeCell::new(None),
        }
    }

    /// A free lock whose value `build` writes in place at the first acquisition, at the value's
    /// final address: the shape for state too large to pass through a stack by value (the object
    /// directory).
    ///
    /// # Safety
    ///
    /// `build`, handed a pointer valid for writes and aligned for a `T`, leaves a valid `T` there,
    /// and does not take this lock itself (it runs inside the first acquisition).
    pub const unsafe fn in_place(build: unsafe fn(*mut T)) -> Self {
        ShortLock {
            count: AtomicI32::new(1),
            contention: AtomicU32::new(0),
            owner: AtomicU32::new(0),
            event: UnsafeCell::new(Event::new(EventKind::Synchronization, false)),
            value: UnsafeCell::new(MaybeUninit::uninit()),
            build: UnsafeCell::new(Some(build)),
        }
    }

    /// Take the lock: raise to the APC level, then take it, waiting while another thread holds it.
    /// The guard keeps the passive token borrowed; dropping it releases the lock and lowers.
    ///
    /// # Panics
    ///
    /// In debug builds, the calling thread holds the lock already: the lock is not re-entrant, and
    /// the second acquisition would wait for itself.
    pub fn lock<'a>(&'a self, passive: &'a mut At<Passive>) -> ShortGuard<'a, T> {
        let apc = passive.raise::<Apc>();
        let me = holder_identity();
        debug_assert!(
            me == 0 || self.owner.load(Ordering::SeqCst) != me,
            "a short lock taken again by the thread holding it"
        );
        if self.claim() {
            // Handed over: held from here on, the hold counted by the release that handed it.
            self.wait_for_handoff();
        }
        self.owner.store(me, Ordering::SeqCst);
        // SAFETY: this thread holds the lock now (see the `Sync` impl), so this is the only
        // reference to the build slot and the value; a pending build writes the value here, the
        // build `in_place`'s caller vouched for, before any guard reads it.
        unsafe {
            if let Some(write) = (*self.build.get()).take() {
                write((*self.value.get()).as_mut_ptr());
            }
        }
        ShortGuard { lock: self, apc }
    }

    /// Whether nobody holds the lock.
    pub fn is_free(&self) -> bool {
        self.count.load(Ordering::SeqCst) == 1
    }

    /// How many acquisitions have found the lock held.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn contention(&self) -> u32 {
        self.contention.load(Ordering::SeqCst)
    }

    /// Count this thread in, masked: true when another holds the lock and this thread must wait for
    /// the handoff. A lock taken at once counts as held in the same masked step: no dispatch
    /// decision comes between the two.
    fn claim(&self) -> bool {
        let _masked = pcr().mask_guard();
        let count = self.count.load(Ordering::SeqCst);
        self.count.store(count - 1, Ordering::SeqCst);
        if count == 1 {
            HOLDS.fetch_add(1, Ordering::SeqCst);
            return false;
        }
        if count == 0 {
            // The first waiter: nobody is on the event's waiters list, and the lock cannot move
            // while it is borrowed, so the list is closed here, where the lock is now.
            // SAFETY: interrupts are masked, and no thread waits on the event (the count was 0:
            // a holder and no waiter), so this is the only reference to it.
            unsafe { (*self.event.get()).init() };
        }
        self.contention.fetch_add(1, Ordering::SeqCst);
        true
    }

    /// Give the lock up, masked: hand it to the oldest waiter — the hold passes to it, still
    /// counted, before it runs — or leave it free.
    fn release(&self) {
        self.owner.store(0, Ordering::SeqCst);
        let _masked = pcr().mask_guard();
        let count = self.count.load(Ordering::SeqCst) + 1;
        self.count.store(count, Ordering::SeqCst);
        if count != 1 {
            self.hand_off();
        } else {
            HOLDS.fetch_sub(1, Ordering::SeqCst);
        }
    }

    /// Wait on the event until a release hands the lock over.
    #[cfg(target_arch = "x86")]
    fn wait_for_handoff(&self) {
        assert!(
            !crate::sched::idle::on_idle_thread(),
            "the idle thread cannot wait for a held short lock"
        );
        // SAFETY: the event was named at its address by the first waiter's claim, and is read for
        // that name only; nothing writes the name again while the lock lives.
        let event = unsafe { (*self.event.get()).id() };
        let status = crate::sched::wait::wait_current_with(|dispatcher, thread, stamp, _replay| {
            dispatcher.wait_for(
                thread,
                event,
                crate::sched::wait::WaitReason::Executive,
                crate::sched::wait::WaitMode::Kernel,
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

    /// The host has one thread per processor and no dispatcher: a lock is never contended there.
    #[cfg(not(target_arch = "x86"))]
    fn wait_for_handoff(&self) {
        unreachable!("a short lock contended on the host");
    }

    /// Set the event for the oldest waiter, from the release (interrupts masked by the caller): at
    /// the dispatch level, where nothing else runs on the processor until the set is done.
    #[cfg(target_arch = "x86")]
    fn hand_off(&self) {
        // SAFETY: interrupts are masked (the caller's guard), and the event's name was written by
        // the first waiter's claim, before any release could hand off; it is read, nothing more.
        let event = unsafe { (*self.event.get()).id() };
        crate::level::raised::<crate::level::Dispatch, _>(|dispatch| {
            crate::sched::DISPATCHER
                .get(dispatch)
                .set_event(event, HANDOFF_INCREMENT);
        });
    }

    /// See the host's [`ShortLock::wait_for_handoff`].
    #[cfg(not(target_arch = "x86"))]
    fn hand_off(&self) {
        let _ = HANDOFF_INCREMENT;
        unreachable!("a short lock contended on the host");
    }
}

impl<T> Drop for ShortLock<T> {
    fn drop(&mut self) {
        if self.build.get_mut().is_none() {
            // SAFETY: no build is pending, so the value was written (`new`'s, or the build's at the
            // first acquisition); `&mut self` makes this the only reference, and it is dropped
            // once.
            unsafe { self.value.get_mut().assume_init_drop() };
        }
    }
}

/// The running thread as a short lock's owner field names it: its record's index one up, or 0 where
/// no thread runs (the host's tests).
fn holder_identity() -> u32 {
    crate::sched::try_current_thread().map_or(0, |thread| u32::from(thread.index()) + 1)
}

/// A held [`ShortLock`]: derefs to the value, lends the APC token, and releases the lock and lowers
/// when dropped.
#[cfg_attr(not(any(test, target_arch = "x86")), allow(dead_code))]
pub struct ShortGuard<'a, T> {
    lock: &'a ShortLock<T>,
    /// The raise to the APC level, which keeps the passive token borrowed and lowers when the
    /// guard's fields drop, after the release.
    apc: Raised<'a, Passive, Apc>,
}

#[cfg_attr(not(any(test, target_arch = "x86")), allow(dead_code))]
impl<T> ShortGuard<'_, T> {
    /// The APC-level token, for raising further while the lock is held.
    pub fn apc(&mut self) -> &mut At<Apc> {
        &mut self.apc
    }
}

impl<T> Deref for ShortGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        // SAFETY: the guard's thread holds the lock (see the `Sync` impl), and the guard's borrows
        // tie the reference to it; the acquisition built the value if a build was pending.
        unsafe { (*self.lock.value.get()).assume_init_ref() }
    }
}

impl<T> DerefMut for ShortGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: as in `deref`; `&mut self` makes this the only reference through the guard.
        unsafe { (*self.lock.value.get()).assume_init_mut() }
    }
}

impl<T> Drop for ShortGuard<'_, T> {
    fn drop(&mut self) {
        self.lock.release();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interrupt::irql;
    use crate::level::{passive_for_test, Dispatch};

    /// The value is set once and read freely afterwards.
    #[test]
    fn a_set_once_value_reads_back() {
        let value = InitOnce::new();
        value.set([1u32, 2, 3]);
        assert_eq!(value.get(), &[1, 2, 3]);
        assert_eq!(value.get()[1], 2);
    }

    #[test]
    #[should_panic(expected = "set twice")]
    fn a_second_set_is_refused() {
        let value = InitOnce::new();
        value.set(1u32);
        value.set(2u32);
    }

    #[test]
    #[should_panic(expected = "before it was set")]
    fn a_read_before_the_set_is_refused() {
        let value: InitOnce<u32> = InitOnce::new();
        value.get();
    }

    /// A set value is dropped with its holder.
    #[test]
    fn a_set_value_is_dropped() {
        let counted = std::rc::Rc::new(());
        {
            let value = InitOnce::new();
            value.set(std::rc::Rc::clone(&counted));
            assert_eq!(std::rc::Rc::strong_count(&counted), 2);
        }
        assert_eq!(std::rc::Rc::strong_count(&counted), 1);
    }

    /// The buffer is handed out once, and what its owner writes stays written.
    #[test]
    fn a_static_buffer_is_taken_once() {
        let buffer: &'static StaticBuf<[u8; 4]> = Box::leak(Box::new(StaticBuf::new([0; 4])));
        let taken = buffer.take();
        taken[2] = 7;
        assert_eq!(taken, &[0, 0, 7, 0]);
    }

    #[test]
    #[should_panic(expected = "taken twice")]
    fn a_second_take_is_refused() {
        let buffer: &'static StaticBuf<u32> = Box::leak(Box::new(StaticBuf::new(0)));
        let _first = buffer.take();
        let _second = buffer.take();
    }

    /// The holder runs at the APC level with the value; the drop releases the lock and lowers.
    #[test]
    fn a_short_lock_raises_to_apc_for_its_hold() {
        let lock = ShortLock::new(5u32);
        let mut passive = passive_for_test();
        {
            let mut guard = lock.lock(&mut passive);
            assert_eq!(pcr().current(), irql::APC);
            assert!(!lock.is_free());
            *guard += 1;
        }
        assert_eq!(pcr().current(), irql::PASSIVE);
        assert!(lock.is_free());
        assert_eq!(*lock.lock(&mut passive), 6);
        assert_eq!(lock.contention(), 0);
        assert_eq!(pcr().audit(), Ok(()));
    }

    /// The holder may raise further, to the dispatch level, from the guard's APC token, and comes
    /// back to the APC level.
    #[test]
    fn a_short_lock_holder_may_raise_to_dispatch() {
        let lock = ShortLock::new(());
        let mut passive = passive_for_test();
        let mut guard = lock.lock(&mut passive);
        {
            let _dispatch = guard.apc().raise::<Dispatch>();
            assert_eq!(pcr().current(), irql::DISPATCH);
        }
        assert_eq!(pcr().current(), irql::APC);
        drop(guard);
        assert_eq!(pcr().current(), irql::PASSIVE);
    }

    /// A lock built in place builds its value at the first hold, once, where it lives; what the
    /// holders write stays written, and the value drops with the lock.
    #[test]
    fn a_short_lock_built_in_place_builds_at_its_first_hold() {
        thread_local! {
            static BUILDS: core::cell::Cell<u32> = const { core::cell::Cell::new(0) };
        }
        /// The build: a counted value written at `at`.
        ///
        /// # Safety
        ///
        /// `at` is valid for writes and aligned.
        unsafe fn build(at: *mut std::rc::Rc<core::cell::Cell<u32>>) {
            BUILDS.with(|builds| builds.set(builds.get() + 1));
            // SAFETY: the caller's contract.
            unsafe { at.write(std::rc::Rc::new(core::cell::Cell::new(7))) };
        }
        // SAFETY: `build` writes a whole value and takes no lock.
        let lock = unsafe { ShortLock::in_place(build) };
        let mut passive = passive_for_test();
        assert_eq!(
            BUILDS.with(core::cell::Cell::get),
            0,
            "nothing built before the hold"
        );
        let kept = {
            let guard = lock.lock(&mut passive);
            guard.set(guard.get() + 1);
            std::rc::Rc::clone(&guard)
        };
        assert_eq!(lock.lock(&mut passive).get(), 8);
        assert_eq!(BUILDS.with(core::cell::Cell::get), 1, "built once");
        assert_eq!(std::rc::Rc::strong_count(&kept), 2);
        drop(lock);
        assert_eq!(std::rc::Rc::strong_count(&kept), 1, "dropped with the lock");
    }
}
