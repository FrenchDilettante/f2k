//! The spin lock: Windows 2000's KSPIN_LOCK, the lock that excludes other processors where raising
//! the interrupt level excludes only the local one.
//!
//! # Windows 2000's model
//!
//! KeAcquireSpinLock raises to DISPATCH_LEVEL, then takes the lock; KeReleaseSpinLock frees it,
//! then lowers to the level the acquire found. Code already at DISPATCH_LEVEL (a DPC, the
//! dispatcher) takes the lock alone with KeAcquireSpinLockAtDpcLevel and frees it with
//! KeReleaseSpinLockFromDpcLevel. An interrupt's lock (KeSynchronizeExecution) is the same lock
//! taken after a raise to the interrupt's synchronize level rather than DISPATCH_LEVEL. In every
//! form the raise comes first, so the holder cannot be preempted on its own processor or
//! interrupted by code that takes the same lock there (which would spin forever), and the free
//! comes before the lower, so the lock is never held below its level.
//!
//! The take is a test-and-test-and-set: one interlocked exchange (`lock cmpxchg`), and while that
//! finds the lock held, plain reads with `pause` until it reads free, then the exchange again. The
//! reads keep the waiting processor off the bus while the holder works; the exchange is what grants
//! the lock. Acquire ordering on the grant and release ordering on the free make the holder's
//! writes visible to the next holder.
//!
//! On one processor the take never finds the lock held: the raise already excludes every other
//! holder there is. Finding it held by the processor itself is a deadlock (Windows 2000's checked
//! build stops on it, SPIN_LOCK_ALREADY_OWNED); the lock word names the holding processor, so the
//! spin's first read catches it and panics rather than spinning forever.
//!
//! On the host each test thread is a processor of its own (see [`crate::pcr::pcr`]), so the tests
//! below run the lock as a multiprocessor would.

use core::marker::PhantomData;
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::interrupt::irql::{Irql, OldIrql, DISPATCH};
use crate::pcr::pcr;

/// A spin lock (KSPIN_LOCK). Holds no data: what it guards is its users' contract, as Windows
/// 2000's is; [`SpinLock::acquire`] and [`SpinLock::acquire_at_dpc_level`] hand out guards that
/// free it when dropped.
pub struct SpinLock {
    /// [`FREE`], or the holding processor ([`holder`]).
    word: AtomicUsize,
}

/// The lock word of a free lock.
const FREE: usize = 0;

/// The running processor as a lock word names it: its control region's address with the low bit
/// set (never [`FREE`]), as Windows 2000's checked build stores the holder's identity there.
#[inline]
fn holder() -> usize {
    core::ptr::from_ref(pcr()) as usize | 1
}

impl SpinLock {
    /// A free lock (KeInitializeSpinLock).
    pub const fn new() -> Self {
        SpinLock {
            word: AtomicUsize::new(FREE),
        }
    }

    /// Whether some processor holds the lock: a snapshot, for assertions.
    pub fn is_held(&self) -> bool {
        self.word.load(Ordering::Relaxed) != FREE
    }

    /// Whether the running processor holds the lock.
    pub fn is_held_here(&self) -> bool {
        self.word.load(Ordering::Relaxed) == holder()
    }

    /// KeAcquireSpinLock: raise to the dispatch level, then take the lock. Returns what the raise
    /// found, which [`SpinLock::release`] lowers back to.
    ///
    /// # Panics
    ///
    /// The processor is above the dispatch level (a raise cannot go down), or holds the lock
    /// already.
    #[inline]
    #[must_use = "the lock is freed by `release` with the level returned"]
    pub fn acquire_raw(&self) -> OldIrql {
        self.acquire_raised_raw(DISPATCH)
    }

    /// The lock taken after a raise to `level` at or above the dispatch level: an interrupt's
    /// synchronize level for the lock its service routine shares (KeSynchronizeExecution's take),
    /// or a level cell's own level. Returns what the raise found.
    ///
    /// # Panics
    ///
    /// As [`SpinLock::acquire_raw`], for `level`.
    #[inline]
    #[must_use = "the lock is freed by `release` with the level returned"]
    pub fn acquire_raised_raw(&self, level: Irql) -> OldIrql {
        debug_assert!(
            level >= DISPATCH,
            "a spin lock held below the dispatch level"
        );
        let old = pcr().raise(level);
        self.take();
        old
    }

    /// KeReleaseSpinLock: free the lock, then lower to `old`, what its acquire's raise found.
    ///
    /// # Safety
    ///
    /// The running processor holds the lock, taken by [`SpinLock::acquire_raw`] or
    /// [`SpinLock::acquire_raised_raw`] whose raise returned `old`, and nothing reaches what the
    /// lock guards after this call on the strength of that acquisition.
    #[inline]
    pub unsafe fn release_raw(&self, old: OldIrql) {
        self.free();
        pcr().lower(old);
    }

    /// KeAcquireSpinLockAtDpcLevel: take the lock without raising, from code already at or above
    /// the dispatch level.
    ///
    /// # Panics
    ///
    /// In debug builds, the processor is below the dispatch level (the holder could be preempted
    /// and another thread spin on the processor for it). In every build, the processor holds the
    /// lock already.
    #[inline]
    pub fn acquire_at_dpc_level_raw(&self) {
        debug_assert!(
            pcr().current() >= DISPATCH,
            "a spin lock taken at its level below the dispatch level"
        );
        self.take();
    }

    /// KeReleaseSpinLockFromDpcLevel: free the lock, staying at the level.
    ///
    /// # Safety
    ///
    /// The running processor holds the lock, taken by [`SpinLock::acquire_at_dpc_level_raw`], and
    /// nothing reaches what it guards after this call on the strength of that acquisition.
    #[inline]
    pub unsafe fn release_from_dpc_level_raw(&self) {
        self.free();
    }

    /// [`SpinLock::acquire_raw`] behind a guard, whose drop frees the lock and lowers.
    #[inline]
    pub fn acquire(&self) -> SpinGuard<'_> {
        let old = self.acquire_raw();
        SpinGuard {
            lock: self,
            old: Some(old),
            _here: PhantomData,
        }
    }

    /// [`SpinLock::acquire_at_dpc_level_raw`] behind a guard, whose drop frees the lock and leaves
    /// the level alone.
    #[inline]
    pub fn acquire_at_dpc_level(&self) -> SpinGuard<'_> {
        self.acquire_at_dpc_level_raw();
        SpinGuard {
            lock: self,
            old: None,
            _here: PhantomData,
        }
    }

    /// Take the lock: the interlocked exchange, and while it finds the lock held, read until it is
    /// free (with `pause`), then exchange again.
    #[inline]
    fn take(&self) {
        let me = holder();
        if self
            .word
            .compare_exchange(FREE, me, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            self.spin(me);
        }
    }

    /// The contended take, out of line: the uncontended one is the exchange alone.
    #[cold]
    #[inline(never)]
    fn spin(&self, me: usize) {
        loop {
            loop {
                let word = self.word.load(Ordering::Relaxed);
                if word == FREE {
                    break;
                }
                assert_ne!(
                    word, me,
                    "a spin lock taken again on the processor holding it"
                );
                core::hint::spin_loop();
            }
            if self
                .word
                .compare_exchange_weak(FREE, me, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                return;
            }
        }
    }

    /// Free the lock: a release store, which publishes the holder's writes to the next holder.
    #[inline]
    fn free(&self) {
        debug_assert_eq!(
            self.word.load(Ordering::Relaxed),
            holder(),
            "a spin lock freed by a processor that does not hold it"
        );
        self.word.store(FREE, Ordering::Release);
    }
}

impl Default for SpinLock {
    fn default() -> Self {
        Self::new()
    }
}

/// A held [`SpinLock`]: frees it when dropped, then lowers to what its acquire's raise found (none
/// for an at-dispatch-level acquisition). Stays on the processor that took the lock (not `Send`).
#[must_use = "dropping the guard frees the lock at once"]
pub struct SpinGuard<'a> {
    lock: &'a SpinLock,
    /// What the acquire's raise found; none when the acquisition raised nothing.
    old: Option<OldIrql>,
    /// Neither `Send` nor `Sync`: the lock word names this processor, and the lower is its.
    _here: PhantomData<*mut ()>,
}

impl Drop for SpinGuard<'_> {
    #[inline]
    fn drop(&mut self) {
        // SAFETY: this guard's acquisition holds the lock on this processor (the guard cannot
        // leave it), and the guard ends here.
        unsafe {
            match self.old {
                Some(old) => self.lock.release_raw(old),
                None => self.lock.release_from_dpc_level_raw(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use core::cell::UnsafeCell;
    use std::sync::Arc;

    use super::*;
    use crate::interrupt::irql;

    /// A counter changed by plain (non-atomic) reads and writes, guarded by the lock: what the
    /// mutual exclusion test races.
    struct Guarded {
        lock: SpinLock,
        count: UnsafeCell<u64>,
    }

    // SAFETY: `count` is reached only with `lock` held.
    unsafe impl Sync for Guarded {}

    impl Guarded {
        fn new() -> Self {
            Guarded {
                lock: SpinLock::new(),
                count: UnsafeCell::new(0),
            }
        }

        /// A read, a yield-sized window, and a write, so an unexcluded second processor loses
        /// updates.
        fn bump(&self) {
            // SAFETY: called with the lock held.
            unsafe {
                let seen = core::hint::black_box(*self.count.get());
                core::hint::spin_loop();
                *self.count.get() = seen + 1;
            }
        }
    }

    /// How many processors (host threads) race, and how many takes each makes. Fewer under Miri,
    /// which interprets every step.
    const PROCESSORS: usize = if cfg!(miri) { 3 } else { 8 };
    const TAKES: u64 = if cfg!(miri) { 50 } else { 20_000 };

    /// Every processor takes the lock in turn, raised to the dispatch level: no update is lost,
    /// and each processor's level is back where it was afterwards.
    #[test]
    fn processors_racing_for_the_lock_exclude_each_other() {
        let shared = Arc::new(Guarded::new());
        let threads: Vec<_> = (0..PROCESSORS)
            .map(|_| {
                let shared = Arc::clone(&shared);
                std::thread::spawn(move || {
                    for _ in 0..TAKES {
                        let _held = shared.lock.acquire();
                        assert_eq!(pcr().current(), irql::DISPATCH);
                        assert!(shared.lock.is_held_here());
                        shared.bump();
                    }
                    assert_eq!(pcr().current(), irql::PASSIVE);
                    assert_eq!(pcr().audit(), Ok(()));
                })
            })
            .collect();
        for thread in threads {
            thread.join().expect("a racing processor panicked");
        }
        assert!(!shared.lock.is_held());
        // SAFETY: every racer has ended.
        assert_eq!(unsafe { *shared.count.get() }, PROCESSORS as u64 * TAKES);
    }

    /// The at-dispatch-level take excludes the raising take's holders, and the raw forms balance
    /// their own raise and lower.
    #[test]
    fn every_form_of_the_take_excludes_the_others() {
        let shared = Arc::new(Guarded::new());
        let threads: Vec<_> = (0..PROCESSORS)
            .map(|which| {
                let shared = Arc::clone(&shared);
                std::thread::spawn(move || {
                    for _ in 0..TAKES {
                        match which % 3 {
                            0 => {
                                crate::level::raised::<crate::level::Dispatch, _>(|_| {
                                    let _held = shared.lock.acquire_at_dpc_level();
                                    assert_eq!(pcr().current(), irql::DISPATCH);
                                    shared.bump();
                                });
                            }
                            1 => {
                                let old = shared.lock.acquire_raw();
                                shared.bump();
                                // SAFETY: taken just above with the raise that returned `old`.
                                unsafe { shared.lock.release_raw(old) };
                            }
                            _ => {
                                let old = shared.lock.acquire_raised_raw(irql::CLOCK);
                                assert_eq!(pcr().current(), irql::CLOCK);
                                shared.bump();
                                // SAFETY: as above.
                                unsafe { shared.lock.release_raw(old) };
                            }
                        }
                    }
                    assert_eq!(pcr().current(), irql::PASSIVE);
                    assert_eq!(pcr().audit(), Ok(()));
                })
            })
            .collect();
        for thread in threads {
            thread.join().expect("a racing processor panicked");
        }
        // SAFETY: every racer has ended.
        assert_eq!(unsafe { *shared.count.get() }, PROCESSORS as u64 * TAKES);
    }

    /// The acquire raises to the dispatch level and the release lowers back to what it found, the
    /// guard's way and the raw way; the at-level take leaves the level alone.
    #[test]
    fn the_acquire_raises_and_the_release_lowers() {
        let lock = SpinLock::new();
        {
            let _held = lock.acquire();
            assert_eq!(pcr().current(), irql::DISPATCH);
            assert!(lock.is_held_here());
        }
        assert_eq!(pcr().current(), irql::PASSIVE);
        assert!(!lock.is_held());

        crate::level::raised::<crate::level::Clock, _>(|_| {
            let held = lock.acquire_at_dpc_level();
            assert_eq!(pcr().current(), irql::CLOCK, "no raise, no lower");
            drop(held);
            assert_eq!(pcr().current(), irql::CLOCK);
        });
        assert_eq!(pcr().audit(), Ok(()));
    }

    /// Taking a lock the processor holds already would spin forever: refused.
    #[test]
    #[should_panic(expected = "taken again on the processor holding it")]
    fn a_second_take_on_the_holding_processor_is_refused() {
        let lock = SpinLock::new();
        let _first = lock.acquire();
        let _second = lock.acquire_at_dpc_level();
    }

    /// A raise cannot go down: the acquire from above the dispatch level is refused, as
    /// KeAcquireSpinLock's raise is.
    #[test]
    #[should_panic(expected = "raising below")]
    fn the_acquire_above_the_dispatch_level_is_refused() {
        let lock = SpinLock::new();
        crate::level::raised::<crate::level::Clock, _>(|_| {
            let _held = lock.acquire();
        });
    }
}
