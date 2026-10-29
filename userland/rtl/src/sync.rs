//! State shared by a process's threads, behind a lock: [`Locked`] owns its value and hands it out
//! only to a closure run with the lock held, once at a time. The lock is the DLL's own
//! ([`RawLock`]): a critical section, entered as the DLL's layering allows (msvcrt through
//! kernel32's EnterCriticalSection, ntdll over [`crate::critsec`] directly).
//!
//! A critical section is recursive: the thread that holds it enters again without waiting. So the
//! lock alone cannot stop a closure from reaching the same value again (a callback, a nested call
//! through an export) and holding two `&mut` to it. A busy flag, set while a closure runs, makes
//! that re-entry a panic instead.
//!
//! An exception's unwind abandons the frames it passes without running their drops (SEH, not a
//! Rust panic). A lock held while its closure reads or writes a caller's memory, where such an
//! unwind can start, arms its release around the closure ([`RawLock::on_abandon`]), so the value
//! and the lock are let go all the same.
//!
//! A word a DLL makes at its first need and keeps for the process's life (a handle, a block's
//! address) is a [`OnceWord`]: read without the lock once made, made under it.

use core::cell::{Cell, UnsafeCell};
use core::sync::atomic::AtomicUsize;
use core::sync::atomic::Ordering::{Acquire, Release};

/// A lock as a critical section is one: one thread holds it at a time, and the holder may take it
/// again (each `lock` matched by an `unlock`).
///
/// # Safety
///
/// `lock` returns only once the calling thread holds the lock, which no other thread then holds
/// until the caller's matching `unlock`; `lock` acquires and `unlock` releases (what one holder
/// wrote is seen by the next). [`Locked`] relies on it for the exclusive access it hands out.
///
/// `on_abandon` runs `body` once and answers what it answers. It calls `release` at most once, and
/// only while an unwind is abandoning `body`: its frames, still in place, are never resumed, and no
/// reference they hold is used after `release`.
pub unsafe trait RawLock {
    /// Take the lock, waiting while another thread holds it.
    fn lock(&self);
    /// Let one taking of the lock go.
    fn unlock(&self);

    /// Run `body`, with `release` armed to run if an unwind abandons it without running its drops
    /// (an exception's unwind passing the call): what `body` answers. The default arms nothing,
    /// for a lock whose closures touch no memory such an unwind can start in.
    fn on_abandon<R>(&self, release: &dyn Fn(), body: impl FnOnce() -> R) -> R {
        let _ = release;
        body()
    }
}

/// A value behind a lock: reached only through [`Locked::with`].
pub struct Locked<T, L: RawLock> {
    lock: L,
    /// Whether a closure has the value: read and written only with the lock held.
    busy: Cell<bool>,
    value: UnsafeCell<T>,
}

// SAFETY: the value and the busy flag are touched only by the thread holding the lock (`with`
// takes it first, and `RawLock`'s contract admits one thread at a time with acquire and release
// ordering between holders), and only one `&mut T` is out at a time (the busy flag turns the
// holder's re-entry into a panic before a second is made). So sharing the `Locked` between threads
// moves the value between them, which `T: Send` allows, and shares the lock, which `L: Sync` does.
unsafe impl<T: Send, L: RawLock + Sync> Sync for Locked<T, L> {}

impl<T, L: RawLock> Locked<T, L> {
    /// `value`, behind `lock`.
    pub const fn new(lock: L, value: T) -> Self {
        Self {
            lock,
            busy: Cell::new(false),
            value: UnsafeCell::new(value),
        }
    }

    /// Run `body` over the value with the lock held, and answer what it answers; the value and the
    /// lock are let go when `body` returns or unwinds, or when the lock's [`RawLock::on_abandon`]
    /// sees an unwind abandon it.
    ///
    /// # Panics
    ///
    /// When `body` (or something it calls) reaches the same value again: the lock lets its holder
    /// in, but the value is already lent.
    pub fn with<R>(&self, body: impl FnOnce(&mut T) -> R) -> R {
        self.lock.lock();
        if self.busy.replace(true) {
            self.lock.unlock();
            panic!("Locked::with re-entered");
        }
        let lent = Lent {
            locked: self,
            out: Cell::new(true),
        };
        let answer = self.lock.on_abandon(&|| lent.give_back(), || {
            // SAFETY: the lock is held, and the busy flag was clear, so no other `&mut` to the
            // value exists (on this thread or another) until `lent` clears it: after `body`
            // returns or unwinds, or while an unwind abandons `body`'s frames, which then never
            // use the borrow again (`RawLock`'s contract for `on_abandon`).
            body(unsafe { &mut *self.value.get() })
        });
        drop(lent);
        answer
    }

    /// The value, through an exclusive borrow of the whole: no lock needed.
    pub fn get_mut(&mut self) -> &mut T {
        self.value.get_mut()
    }

    /// The value, the lock given back.
    pub fn into_inner(self) -> T {
        self.value.into_inner()
    }
}

/// Lets a taking of the lock go when dropped.
struct Unlock<'a, L: RawLock>(&'a L);

impl<L: RawLock> Drop for Unlock<'_, L> {
    fn drop(&mut self) {
        self.0.unlock();
    }
}

/// The value of a [`Locked`], lent to a closure: given back once, when dropped or when the lock's
/// [`RawLock::on_abandon`] releases it first, the busy flag cleared before the lock is let go.
struct Lent<'a, T, L: RawLock> {
    locked: &'a Locked<T, L>,
    /// Whether the value is still out.
    out: Cell<bool>,
}

impl<T, L: RawLock> Lent<'_, T, L> {
    fn give_back(&self) {
        if self.out.replace(false) {
            self.locked.busy.set(false);
            self.locked.lock.unlock();
        }
    }
}

impl<T, L: RawLock> Drop for Lent<'_, T, L> {
    fn drop(&mut self) {
        self.give_back();
    }
}

/// A word made at its first need, under the DLL's lock, then kept: zero until it is made. Its
/// readers check it without the lock first (the double-checked pattern, with acquire and release
/// ordering between the maker and the readers), so only the first uses wait.
pub struct OnceWord<L: RawLock> {
    lock: L,
    value: AtomicUsize,
}

impl<L: RawLock> OnceWord<L> {
    /// A word not made yet, made under `lock`.
    pub const fn new(lock: L) -> Self {
        Self {
            lock,
            value: AtomicUsize::new(0),
        }
    }

    /// The word, made by `make` if it is not yet; zero when `make` could not make it (zero), and
    /// the next use tries again.
    pub fn get_or_make(&self, make: impl FnOnce() -> usize) -> usize {
        let made = self.value.load(Acquire);
        if made != 0 {
            return made;
        }
        self.lock.lock();
        let _held = Unlock(&self.lock);
        let made = self.value.load(Acquire);
        if made != 0 {
            return made;
        }
        let made = make();
        self.value.store(made, Release);
        made
    }

    /// The word as it is: zero when it is not made yet.
    pub fn get(&self) -> usize {
        self.value.load(Acquire)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering::SeqCst};
    use std::sync::{Condvar, Mutex};
    use std::thread::{self, ThreadId};

    use super::*;

    /// A recursive lock over a std mutex, as a critical section is one: the owner and its count.
    #[derive(Default)]
    struct Recursive {
        state: Mutex<Option<(ThreadId, u32)>>,
        free: Condvar,
        takings: AtomicU32,
    }

    // SAFETY: one owner at a time, under the mutex, which orders the holders' accesses.
    unsafe impl RawLock for Recursive {
        fn lock(&self) {
            let me = thread::current().id();
            let mut state = self.state.lock().unwrap();
            loop {
                match &mut *state {
                    Some((owner, count)) if *owner == me => {
                        *count += 1;
                        break;
                    }
                    Some(_) => state = self.free.wait(state).unwrap(),
                    None => {
                        *state = Some((me, 1));
                        break;
                    }
                }
            }
            self.takings.fetch_add(1, SeqCst);
        }

        fn unlock(&self) {
            let mut state = self.state.lock().unwrap();
            let (_, count) = state.as_mut().expect("unlocked while free");
            *count -= 1;
            if *count == 0 {
                *state = None;
                self.free.notify_one();
            }
        }
    }

    impl Recursive {
        fn is_free(&self) -> bool {
            self.state.lock().unwrap().is_none()
        }
    }

    #[test]
    fn the_value_is_reached_under_the_lock() {
        let locked = Locked::new(Recursive::default(), 5u32);
        let answer = locked.with(|value| {
            assert!(!locked.lock.is_free());
            *value += 1;
            *value * 2
        });
        assert_eq!(answer, 12);
        assert!(locked.lock.is_free());
        assert_eq!(locked.lock.takings.load(SeqCst), 1);
        assert_eq!(locked.into_inner(), 6);
    }

    #[test]
    fn threads_take_turns() {
        let locked = Locked::new(Recursive::default(), Vec::new());
        thread::scope(|scope| {
            for thread in 0..4 {
                let locked = &locked;
                scope.spawn(move || {
                    for step in 0..100 {
                        locked.with(|values| values.push((thread, step)));
                    }
                });
            }
        });
        let mut locked = locked;
        let values = locked.get_mut();
        assert_eq!(values.len(), 400);
        for thread in 0..4 {
            let steps: Vec<_> = values
                .iter()
                .filter(|v| v.0 == thread)
                .map(|v| v.1)
                .collect();
            assert_eq!(steps, (0..100).collect::<Vec<_>>());
        }
    }

    #[test]
    #[should_panic(expected = "re-entered")]
    fn re_entry_panics() {
        let locked = Locked::new(Recursive::default(), 0u32);
        locked.with(|_| locked.with(|value| *value += 1));
    }

    #[test]
    fn a_word_is_made_once() {
        let word = OnceWord::new(Recursive::default());
        assert_eq!(word.get(), 0);
        assert_eq!(word.get_or_make(|| 0), 0, "not made: tried again later");
        assert_eq!(word.get_or_make(|| 7), 7);
        assert_eq!(word.get_or_make(|| unreachable!("made already")), 7);
        assert_eq!(word.get(), 7);
        assert_eq!(
            word.lock.takings.load(SeqCst),
            2,
            "the lock taken until it was made"
        );
    }

    #[test]
    fn threads_make_a_word_once() {
        let word = OnceWord::new(Recursive::default());
        let made = AtomicU32::new(0);
        thread::scope(|scope| {
            for _ in 0..4 {
                scope.spawn(|| {
                    let value = word.get_or_make(|| {
                        made.fetch_add(1, SeqCst);
                        9
                    });
                    assert_eq!(value, 9);
                });
            }
        });
        assert_eq!(made.load(SeqCst), 1);
        assert!(word.lock.is_free());
    }

    /// A recursive lock whose closures an unwind abandons: a panic stands in for the exception,
    /// caught where the unwind passes the call, the release run there, then the panic resumed (as
    /// the C runtime's host tests model an SEH unwind).
    #[derive(Default)]
    struct Abandoning(Recursive);

    // SAFETY: `Recursive`'s, and `release` runs once the panic has left `body` for good.
    unsafe impl RawLock for Abandoning {
        fn lock(&self) {
            self.0.lock();
        }

        fn unlock(&self) {
            self.0.unlock();
        }

        fn on_abandon<R>(&self, release: &dyn Fn(), body: impl FnOnce() -> R) -> R {
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(body)) {
                Ok(answer) => answer,
                Err(panic) => {
                    release();
                    std::panic::resume_unwind(panic)
                }
            }
        }
    }

    /// The release an abandoned closure's lock runs lets the value and the lock go once: the drops
    /// the resumed unwind then runs give nothing back again.
    #[test]
    fn an_abandoned_closure_lets_the_value_go_once() {
        let locked = Locked::new(Abandoning::default(), 0u32);
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            locked.with(|value| {
                *value = 3;
                panic!("a fault in the caller's memory");
            })
        }));
        assert!(caught.is_err());
        assert!(locked.lock.0.is_free());
        assert_eq!(locked.with(|value| *value), 3, "the busy flag clear");
        assert_eq!(
            locked.with(|value| *value + 1),
            4,
            "and a return still lets it go"
        );
        assert!(locked.lock.0.is_free());
    }

    #[test]
    fn a_panic_lets_the_lock_go() {
        let locked = Locked::new(Recursive::default(), 0u32);
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            locked.with(|value| {
                *value = 1;
                locked.with(|_| ());
            })
        }));
        assert!(caught.is_err());
        assert!(locked.lock.is_free());
        assert_eq!(locked.with(|value| *value), 1);
    }
}
