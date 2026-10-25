//! The audited wrapper for kernel globals: one value the whole system shares, reached only through
//! a closure that holds it exclusively.
//!
//! The kernel runs on one processor, so a global is shared with two things only: an interrupt that
//! lands while it is in use, and a thread switch such an interrupt can cause. [`Global::with`]
//! masks interrupts for the closure's run (through the level ledger, putting the flag back as it
//! found it), which shuts out both, and it refuses re-entry (a closure that reached the same global
//! again), the one way left to alias the value. The closure's `&mut` is then the only reference to
//! the value alive.

use core::cell::{Cell, UnsafeCell};

/// A kernel global: a value reached only through [`Global::with`].
pub struct Global<T> {
    value: UnsafeCell<T>,
    /// Whether a closure holds the value now (re-entry is refused).
    busy: Cell<bool>,
}

// SAFETY: one processor; `with` masks interrupts for the closure and refuses re-entry, so no two
// references to the value are ever alive at once.
unsafe impl<T> Sync for Global<T> {}

impl<T> Global<T> {
    /// A global holding `value`.
    pub const fn new(value: T) -> Self {
        Global {
            value: UnsafeCell::new(value),
            busy: Cell::new(false),
        }
    }

    /// Run `f` on the value, with interrupts masked for its run.
    ///
    /// # Panics
    ///
    /// `f` (or anything it calls) reaches the same global again.
    pub fn with<R>(&self, f: impl FnOnce(&mut T) -> R) -> R {
        let _masked = Masked::take();
        assert!(!self.busy.replace(true), "a kernel global re-entered");
        // SAFETY: interrupts are masked and re-entry was refused just above: this is the only
        // reference to the value until `f` returns.
        let result = f(unsafe { &mut *self.value.get() });
        self.busy.set(false);
        result
    }
}

/// Interrupts masked through the level ledger, from the take to the drop, then put back as the take
/// found them. Nothing to mask on the host.
struct Masked {
    #[cfg(target_arch = "x86")]
    enabled: bool,
}

impl Masked {
    fn take() -> Self {
        #[cfg(target_arch = "x86")]
        {
            let state = crate::interrupt::irql::state_mut();
            let enabled = state.interrupts_enabled();
            state.mask_interrupts();
            Masked { enabled }
        }
        #[cfg(not(target_arch = "x86"))]
        Masked {}
    }
}

impl Drop for Masked {
    fn drop(&mut self) {
        #[cfg(target_arch = "x86")]
        if self.enabled {
            crate::interrupt::irql::state_mut().unmask_interrupts();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The closure gets the value, and what it changes stays changed.
    #[test]
    fn the_closure_holds_the_value() {
        let global = Global::new(1u32);
        global.with(|value| *value += 1);
        assert_eq!(global.with(|value| *value), 2);
    }

    /// A closure that reaches the same global again is refused.
    #[test]
    #[should_panic(expected = "a kernel global re-entered")]
    fn re_entry_is_refused() {
        let global = Global::new(0u32);
        global.with(|_| global.with(|_| ()));
    }
}
