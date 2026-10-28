//! State shared by a process's threads, behind a lock: [`Locked`] owns its value and hands it out
//! only to a closure run with the lock held, once at a time. The lock is the DLL's own
//! ([`RawLock`]): a critical section, entered as the DLL's layering allows (msvcrt through
//! kernel32's EnterCriticalSection, ntdll over [`crate::critsec`] directly).
//!
//! A critical section is recursive: the thread that holds it enters again without waiting. So the
//! lock alone cannot stop a closure from reaching the same value again (a callback, a nested call
//! through an export) and holding two `&mut` to it. A busy flag, set while a closure runs, makes
//! that re-entry a panic instead.

use core::cell::{Cell, UnsafeCell};

/// A lock as a critical section is one: one thread holds it at a time, and the holder may take it
/// again (each `lock` matched by an `unlock`).
///
/// # Safety
///
/// `lock` returns only once the calling thread holds the lock, which no other thread then holds
/// until the caller's matching `unlock`; `lock` acquires and `unlock` releases (what one holder
/// wrote is seen by the next). [`Locked`] relies on it for the exclusive access it hands out.
pub unsafe trait RawLock {
    /// Take the lock, waiting while another thread holds it.
    fn lock(&self);
    /// Let one taking of the lock go.
    fn unlock(&self);
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

    /// Run `body` over the value with the lock held, and answer what it answers; the lock is let go
    /// when `body` returns or unwinds.
    ///
    /// # Panics
    ///
    /// When `body` (or something it calls) reaches the same value again: the lock lets its holder
    /// in, but the value is already lent.
    pub fn with<R>(&self, body: impl FnOnce(&mut T) -> R) -> R {
        self.lock.lock();
        let _held = Unlock(&self.lock);
        assert!(!self.busy.replace(true), "Locked::with re-entered");
        let _busy = Free(&self.busy);
        // SAFETY: the lock is held, and the busy flag was clear, so no other `&mut` to the value
        // exists (on this thread or another) until `_busy` clears it after `body`.
        body(unsafe { &mut *self.value.get() })
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

/// Clears the busy flag when dropped (before the lock is let go).
struct Free<'a>(&'a Cell<bool>);

impl Drop for Free<'_> {
    fn drop(&mut self) {
        self.0.set(false);
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
