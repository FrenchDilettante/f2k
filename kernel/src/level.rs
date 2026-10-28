//! Level tokens: the processor's interrupt level as a type, and the kernel state each level owns.
//!
//! # The model
//!
//! A token [`At<L>`] is a zero-sized proof that the processor runs at exactly level `L` (a marker
//! type: [`Passive`], [`Apc`], [`Dispatch`], [`Ide`], [`Keyboard`], [`Clock`], [`High`]), held by
//! the code that put it there. It is neither `Copy` nor `Send`, so it cannot be duplicated or
//! carried to another thread. There are two ways to get one. An entry point that the hardware or
//! the kernel runs at a known level makes it: the interrupt dispatch after the claim, the DPC drain
//! after its raise. Or code holding a lower token raises: [`At::raise`] borrows the lower token
//! and returns a guard that derefs to the higher one and lowers when dropped. Raises only go up,
//! which the compiler checks ([`Above`]).
//!
//! State is kept in a [`LevelCell<L, T>`]. [`LevelCell::get`] hands out `&mut T` for as long as it
//! borrows the caller's `At<L>` mutably. That borrow is the whole mechanism: while the state is
//! borrowed, the token cannot be used for anything else, so the same cell cannot be borrowed
//! twice, a raise cannot start with the borrow alive (its guard borrows the token too), and a call
//! that takes the token cannot be made with the borrow alive. A token of another level opens
//! nothing: access is at exactly the cell's level, never "at or above" it.
//!
//! # Why exact-level access is sound on one processor
//!
//! F2K runs on one processor. Code at level L can be interrupted only by an interrupt above L, and
//! an interrupt handler only ever holds tokens for its own level and the levels it raises to,
//! which are above L as well. It cannot get an `At<L>`: the entries refuse to make one when the
//! processor is already at or above their level, and raising never goes down. So while an `At<L>`
//! is held, nothing else running on the processor can hold one, and the `&mut T` a cell hands out
//! is the only reference to its value.
//!
//! That argument needs one more thing: no thread switch while a cell is borrowed. At the dispatch
//! level and above that holds by construction, because the clock cannot preempt a thread there and
//! code at those levels does not wait. At the passive and APC levels it does not: a tick can end
//! the quantum and the interrupt exit switches to another thread at the same level, which could
//! then make its own token. So a cell exists only for the levels that implement [`NoPreempt`]
//! (dispatch and above). The passive and APC tokens still exist: they prove "may block", and they
//! are what code raises from. State at those levels needs a lock, not a level.
//!
//! # Windows 2000's rules
//!
//! This is Windows 2000's IRQL discipline, made static. KeRaiseIrql may not lower, KeLowerIrql
//! restores the caller's saved level (the guard's drop). Data a given IRQL protects is touched
//! only at that IRQL: the DPC queue with interrupts disabled (here [`High`], because interrupt
//! service routines insert), the clock's counters in the clock interrupt ([`Clock`]), the
//! dispatcher database at DISPATCH_LEVEL ([`Dispatch`]). An interrupt service routine never
//! touches dispatch-level data; it queues a DPC, which runs at DISPATCH_LEVEL with the dispatch
//! token. The one exception Windows makes, the clock interrupt reading the timer table's bucket
//! heads unlocked, stays an exception here too, behind its own narrow interface.
//!
//! # The bridge
//!
//! Code that does not hold tokens yet reaches level state through [`raised`]: it raises to the
//! level, runs a closure with the token, and lowers. It checks at run time what tokens check at
//! compile time: it refuses (panics) when the processor is already at or above the level, which
//! is both the "touching lower state from above" case and the "same cell reached again from inside
//! its own borrow" case.
//!
//! # What the compiler rejects
//!
//! A cell borrowed across a call that takes the same token:
//!
//! ```compile_fail,E0499
//! use f2k_kernel::level::{At, Dispatch, LevelCell};
//! fn switch(_: &mut At<Dispatch>) {}
//! fn misuse(cell: &LevelCell<Dispatch, u32>, dispatch: &mut At<Dispatch>) {
//!     let value = cell.get(dispatch);
//!     switch(dispatch);
//!     *value += 1;
//! }
//! ```
//!
//! A device level's token on dispatch-level state:
//!
//! ```compile_fail,E0308
//! use f2k_kernel::level::{At, Dispatch, Ide, LevelCell};
//! fn misuse(cell: &LevelCell<Dispatch, u32>, ide: &mut At<Ide>) {
//!     *cell.get(ide) += 1;
//! }
//! ```
//!
//! Raising downward:
//!
//! ```compile_fail,E0277
//! use f2k_kernel::level::{At, Clock, Dispatch};
//! fn misuse(clock: &mut At<Clock>) {
//!     let _lowered = clock.raise::<Dispatch>();
//! }
//! ```
//!
//! A cell at a level where the thread can be preempted:
//!
//! ```compile_fail,E0277
//! use f2k_kernel::level::{LevelCell, Passive};
//! static STATE: LevelCell<Passive, u32> = LevelCell::new(0);
//! ```

use core::cell::UnsafeCell;
use core::marker::PhantomData;
use core::ops::{Deref, DerefMut};

use crate::interrupt::irql::{self, Irql};
use crate::pcr::pcr;

mod sealed {
    pub trait Sealed {}
}

/// An interrupt level as a type: one of the marker types below, each with its ledger value.
pub trait Level: sealed::Sealed {
    /// The level's value in the ledger.
    const IRQL: Irql;
}

/// The levels at which a thread cannot be preempted: dispatch and above. Only these have cells.
#[diagnostic::on_unimplemented(
    message = "`{Self}` can be preempted: level cells exist only at Dispatch and above",
    note = "a thread at this level can be switched away from, and another thread at the same level \
            could make its own token; state here needs a lock"
)]
pub trait NoPreempt: Level {}

/// `Self` is a higher level than `L`: a token at `L` may raise to `Self`.
#[diagnostic::on_unimplemented(
    message = "a level token can only raise: `{Self}` is not above `{L}`"
)]
pub trait Above<L: Level>: Level {}

macro_rules! levels {
    ($($(#[$doc:meta])* $name:ident = $irql:expr;)*) => {
        $(
            $(#[$doc])*
            pub enum $name {}
            impl sealed::Sealed for $name {}
            impl Level for $name {
                const IRQL: Irql = $irql;
            }
        )*
    };
}

levels! {
    /// Ordinary kernel code and user mode: a thread may block here.
    Passive = irql::PASSIVE;
    /// Asynchronous procedure calls are held off; a thread may still be preempted.
    Apc = irql::APC;
    /// Deferred procedure calls and the dispatcher: no preemption, no waits.
    Dispatch = irql::DISPATCH;
    /// The IDE disk's interrupt.
    Ide = irql::IDE;
    /// The PS/2 keyboard's interrupt.
    Keyboard = irql::KEYBOARD;
    /// The interval clock's interrupt.
    Clock = irql::CLOCK;
    /// Every interrupt masked.
    High = irql::HIGH;
}

/// Each listed level is above every one listed before it.
macro_rules! ordered {
    ($low:ident $(, $high:ident)*) => {
        $(impl Above<$low> for $high {})*
        ordered!($($high),*);
    };
    () => {};
}

ordered!(Passive, Apc, Dispatch, Ide, Keyboard, Clock, High);

impl NoPreempt for Dispatch {}
impl NoPreempt for Ide {}
impl NoPreempt for Keyboard {}
impl NoPreempt for Clock {}
impl NoPreempt for High {}

/// The proof that the processor runs at exactly level `L`, held by the code that put it there.
///
/// Zero-sized. Not `Copy`, so it is lent rather than duplicated; not `Send` or `Sync` (the raw
/// pointer in its marker), so it stays with the execution that made it.
pub struct At<L: Level> {
    _level: PhantomData<*mut L>,
}

impl<L: Level> At<L> {
    /// Make the token at an entry point that has just put the processor at exactly `L`.
    ///
    /// # Safety
    ///
    /// Only at such an entry: the interrupt dispatch once the claim has raised to the object's
    /// level, the DPC drain once it has raised to the dispatch level from below, and [`raised`]
    /// once it has raised from below. The ledger must read `L`, it must have been below `L` before
    /// the entry's own raise (so no other token for `L` is live on the processor), and the token
    /// must be dropped before the entry lowers.
    ///
    /// The passive level is the exception, because nothing is exclusive there (no cell exists at
    /// it): its entries are where a thread starts running kernel code at the passive level, the
    /// system-call entry and, once they need one, a thread's startup and the boot. Every thread may
    /// hold its own passive token; the ledger must read the passive level, and the token must stay
    /// on the thread that made it.
    #[inline]
    pub(crate) unsafe fn enter() -> Self {
        At {
            _level: PhantomData,
        }
    }

    /// Raise to `M`, a higher level. The guard derefs to the `M` token and lowers back to `L` when
    /// dropped; until then it borrows this token, so nothing at `L` can run meanwhile.
    #[inline]
    pub fn raise<M: Above<L>>(&mut self) -> Raised<'_, L, M> {
        let previous = pcr().raise(M::IRQL);
        debug_assert_eq!(previous, L::IRQL, "a token outlived its level");
        // SAFETY: the processor was at exactly `L` (this token) and the raise just put it at `M`,
        // above `L`, so no other token for `M` is live; the guard drops the token as it lowers.
        let at = unsafe { At::enter() };
        Raised {
            at,
            _lower: PhantomData,
        }
    }
}

/// A raise from `L` to `M`: derefs to the `M` token, lowers back to `L` when dropped.
pub struct Raised<'a, L: Level, M: Level> {
    at: At<M>,
    _lower: PhantomData<&'a mut At<L>>,
}

impl<L: Level, M: Level> Deref for Raised<'_, L, M> {
    type Target = At<M>;

    #[inline]
    fn deref(&self) -> &At<M> {
        &self.at
    }
}

impl<L: Level, M: Level> DerefMut for Raised<'_, L, M> {
    #[inline]
    fn deref_mut(&mut self) -> &mut At<M> {
        &mut self.at
    }
}

impl<L: Level, M: Level> Drop for Raised<'_, L, M> {
    #[inline]
    fn drop(&mut self) {
        pcr().lower(L::IRQL);
    }
}

/// The bridge for code that holds no token yet: raise to `L`, run `f` with the `L` token, lower.
///
/// # Panics
///
/// The processor is already at or above `L`: either lower code reaching up-level state from above,
/// or `f` (or something it calls) reaching state at `L` again from inside its own borrow.
pub fn raised<L: Level, R>(f: impl FnOnce(&mut At<L>) -> R) -> R {
    let Some(previous) = pcr().raise_from_below(L::IRQL) else {
        panic!("a level bridge entered at or above its level");
    };
    let _lower = Lower(previous);
    // SAFETY: an entry: `raise_from_below` found the ledger below `L` and raised it there, with
    // interrupts masked across the test and the raise; the token is dropped before `_lower`
    // lowers.
    let mut at = unsafe { At::enter() };
    f(&mut at)
}

/// Lowers the ledger back to the level it holds when dropped: the bridge's half of a raise.
struct Lower(Irql);

impl Drop for Lower {
    #[inline]
    fn drop(&mut self) {
        pcr().lower(self.0);
    }
}

/// State that belongs to level `L`: reached only with the `L` token.
pub struct LevelCell<L: NoPreempt, T> {
    value: UnsafeCell<T>,
    _level: PhantomData<L>,
}

// SAFETY: one processor, and `get` needs an `At<L>`: only one of those is live at a time (see the
// module's model), and the `&mut T` it hands out lives no longer than that token's borrow, so no
// two references to the value are ever alive at once, whichever thread of the kernel makes them.
// `T: Send`, as for a lock: the value is reached from whichever thread holds the token.
unsafe impl<L: NoPreempt, T: Send> Sync for LevelCell<L, T> {}

impl<L: NoPreempt, T> LevelCell<L, T> {
    /// A cell holding `value`.
    pub const fn new(value: T) -> Self {
        LevelCell {
            value: UnsafeCell::new(value),
            _level: PhantomData,
        }
    }

    /// The value, for as long as the token is lent.
    #[inline]
    pub fn get<'a>(&'a self, _at: &'a mut At<L>) -> &'a mut T {
        // SAFETY: the caller holds the one live `At<L>` (see the `Sync` impl), lent mutably for
        // `'a`, so this is the only reference to the value for `'a`.
        unsafe { &mut *self.value.get() }
    }

    /// The value, through exclusive ownership of the cell (no token needed).
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn get_mut(&mut self) -> &mut T {
        self.value.get_mut()
    }
}

/// A passive token for a host test, which runs on a processor of its own, at the passive level.
#[cfg(test)]
pub(crate) fn passive_for_test() -> At<Passive> {
    assert_eq!(
        pcr().current(),
        irql::PASSIVE,
        "a passive token made above the passive level"
    );
    // SAFETY: a passive entry (see `At::enter`): the test's processor is at the passive level, and
    // the token stays on the test's thread (it is neither `Send` nor `Sync`).
    unsafe { At::enter() }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The marker values are the ledger's, in its order.
    #[test]
    fn markers_carry_the_ledger_values() {
        assert_eq!(Passive::IRQL, irql::PASSIVE);
        assert_eq!(Apc::IRQL, irql::APC);
        assert_eq!(Dispatch::IRQL, irql::DISPATCH);
        assert_eq!(Ide::IRQL, irql::IDE);
        assert_eq!(Keyboard::IRQL, irql::KEYBOARD);
        assert_eq!(Clock::IRQL, irql::CLOCK);
        assert_eq!(High::IRQL, irql::HIGH);
    }

    /// The token and the guard take no space.
    #[test]
    fn tokens_are_zero_sized() {
        assert_eq!(core::mem::size_of::<At<Dispatch>>(), 0);
        assert_eq!(core::mem::size_of::<Raised<'static, Dispatch, High>>(), 0);
    }

    /// Raises nest and unwind: each guard puts the ledger at its level and back at the one below
    /// when dropped, and the transitions balance.
    #[test]
    fn raises_nest_and_lower_in_order() {
        raised::<Dispatch, _>(|dispatch| {
            assert_eq!(pcr().current(), irql::DISPATCH);
            {
                let mut clock = dispatch.raise::<Clock>();
                assert_eq!(pcr().current(), irql::CLOCK);
                {
                    let _high = clock.raise::<High>();
                    assert_eq!(pcr().current(), irql::HIGH);
                    assert!(!pcr().interrupts_enabled(), "high masks");
                }
                assert_eq!(pcr().current(), irql::CLOCK);
                assert!(!pcr().interrupts_enabled(), "the clock level masks");
            }
            assert_eq!(pcr().current(), irql::DISPATCH);
            assert!(pcr().interrupts_enabled(), "dispatch runs enabled");
        });
        assert_eq!(pcr().current(), irql::PASSIVE);
        assert_eq!(pcr().audit(), Ok(()));
    }

    /// The bridge refuses to run at or above its level: the level it would hand a token for is
    /// already someone else's.
    #[test]
    fn the_bridge_refuses_from_above() {
        let refused = std::panic::catch_unwind(|| {
            raised::<Dispatch, _>(|dispatch| {
                let _clock = dispatch.raise::<Clock>();
                raised::<Dispatch, _>(|_| ());
            })
        });
        assert!(refused.is_err());
    }

    /// The bridge refuses its own level too: a cell reached again from inside its borrow.
    #[test]
    fn the_bridge_refuses_its_own_level() {
        let refused = std::panic::catch_unwind(|| {
            raised::<High, _>(|_| raised::<High, _>(|_| ()));
        });
        assert!(refused.is_err());
    }

    /// A cell's value is reached with its level's token, and what is changed stays changed.
    #[test]
    fn a_cell_is_reached_with_its_token() {
        let cell: LevelCell<Dispatch, u32> = LevelCell::new(1);
        raised::<Dispatch, _>(|dispatch| *cell.get(dispatch) += 1);
        raised::<Dispatch, _>(|dispatch| assert_eq!(*cell.get(dispatch), 2));

        // A raise's guard reaches cells at its own level.
        let high_cell: LevelCell<High, u32> = LevelCell::new(5);
        raised::<Dispatch, _>(|dispatch| {
            let mut high = dispatch.raise::<High>();
            *high_cell.get(&mut high) *= 2;
        });
        let mut high_cell = high_cell;
        assert_eq!(*high_cell.get_mut(), 10);
    }
}
