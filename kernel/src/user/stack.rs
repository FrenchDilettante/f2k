//! User stacks that grow on demand, the way NT's do.
//!
//! A thread's stack is a reservation, `[deallocation, base)` as its TEB records it
//! (DeallocationStack, StackBase), of which only the top is committed. The committed run ends at a
//! guard page: touching it fires the guard (the page stays, committed and now accessible), and the
//! stack grows by that page — the TEB's StackLimit moves down to it and a new guard is planted just
//! below — so a stack grows one page at a time, as it is used (the reason compilers probe large
//! frames page by page, `_chkstk`). Any guard page firing inside the reservation grows the stack
//! this way, one the program planted itself included (the C runtime's `_resetstkoflw` re-arms an
//! overflowed stack so). A touch below the guard, in a page never committed, is an access
//! violation. The reservation's lowest page is never committed: a guard firing with only that page
//! left below it cannot plant another, and that is the stack overflow (STATUS_STACK_OVERFLOW).
//!
//! The rule reads the thread's TEB — user memory, through the fault-tolerant copy — as the
//! platform's does: a TEB the program made unreadable or rewrote decides only where its own stack
//! grows.

use crate::mem::paging::PAGE_SIZE;

/// What a guard page that fired at an address means for a stack.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum GuardFault {
    /// Inside the stack: `page`, the fired guard's, is the new limit; `next_guard` is the page to
    /// guard below it — none when only the reservation's never-committed bottom page is left (the
    /// overflow).
    Grow { page: u32, next_guard: Option<u32> },
    /// Outside the stack's reservation.
    NotStack,
}

/// Classify a guard page firing at `address` for the stack reserved at `[deallocation, base)`.
pub fn on_guard(address: u32, deallocation: u32, base: u32) -> GuardFault {
    if address < deallocation || address >= base {
        return GuardFault::NotStack;
    }
    let page = address & !(PAGE_SIZE - 1);
    let next_guard = page
        .checked_sub(PAGE_SIZE)
        .filter(|&below| below > deallocation);
    GuardFault::Grow { page, next_guard }
}

/// What the page-fault path did for a guard page that fired.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Growth {
    /// The running thread's stack grew by the page: the faulting access resumes.
    Grown,
    /// The stack's last page is committed (or no next guard could be planted): the stack has
    /// overflowed.
    Overflow,
    /// Not the running thread's stack: an ordinary guard page.
    NotStack,
}

/// Plant a stack's guard page at `page`: committed, read-write and guarded (PAGE_GUARD), so the
/// first touch fires it — and grows the stack. Nothing is planted without a frame to spare: the
/// stack then cannot grow past its committed pages.
#[cfg(target_arch = "x86")]
pub fn plant_guard(space: &mut crate::mem::vm::AddressSpace, page: u32) {
    let _ = space.plant_guard(&mut crate::mem::vm::CurrentPages, page);
}

/// A guard page fired at `address` (its guard already spent): when it lies in the running thread's
/// stack, as its TEB records it, grow the stack by its page — the TEB's StackLimit moved to it, the
/// next guard planted below — or report the overflow.
#[cfg(target_arch = "x86")]
pub fn grow_on_guard(address: u32) -> Growth {
    use crate::mem::vm::CurrentPages;
    use crate::user::syscall::{read_user, write_user};
    use crate::user::teb::teb_offset;
    // SAFETY: the running thread's record, live while it runs.
    let teb = unsafe { (*crate::sched::idle::dispatcher().current_thread()).teb_va() };
    if teb == 0 {
        return Growth::NotStack;
    }
    let word = |offset: u32| {
        let mut bytes = [0u8; 4];
        read_user(teb + offset, &mut bytes)
            .ok()
            .map(|()| u32::from_le_bytes(bytes))
    };
    let (Some(deallocation), Some(base)) = (
        word(teb_offset::DEALLOCATION_STACK),
        word(teb_offset::STACK_BASE),
    ) else {
        return Growth::NotStack;
    };
    let GuardFault::Grow { page, next_guard } = on_guard(address, deallocation, base) else {
        return Growth::NotStack;
    };
    let _ = write_user(teb + teb_offset::STACK_LIMIT, &page.to_le_bytes());
    let Some(guard) = next_guard else {
        return Growth::Overflow;
    };
    // The address space whose tables are live: the faulting thread's own here (an attached
    // thread's guard is never its stack's).
    let space = crate::process::pool::address_space().vm();
    // The page below already committed (the program committed it itself) needs no guard: the stack
    // runs into it.
    if space.frame_at(&CurrentPages, guard).is_some() || space.plant_guard(&mut CurrentPages, guard)
    {
        Growth::Grown
    } else {
        // No frame to guard with: the stack cannot grow further.
        Growth::Overflow
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOP: u32 = 0x0013_0000;
    const BOTTOM: u32 = TOP - 0x10_0000;

    /// A guard firing inside the reservation is the stack's: its page becomes the limit and the
    /// page below it the next guard.
    #[test]
    fn a_guard_inside_the_stack_grows_it() {
        assert_eq!(
            on_guard(TOP - 0x2001, BOTTOM, TOP),
            GuardFault::Grow {
                page: TOP - 0x3000,
                next_guard: Some(TOP - 0x4000)
            }
        );
        // Anywhere inside the reservation: a guard the program re-planted higher up (after an
        // overflow, `_resetstkoflw`) grows the stack the same way.
        assert_eq!(
            on_guard(TOP - 0x8_0000, BOTTOM, TOP),
            GuardFault::Grow {
                page: TOP - 0x8_0000,
                next_guard: Some(TOP - 0x8_1000)
            }
        );
    }

    /// Outside the reservation a guard is not the stack's.
    #[test]
    fn a_guard_outside_is_not_the_stacks() {
        assert_eq!(on_guard(BOTTOM - 1, BOTTOM, TOP), GuardFault::NotStack);
        assert_eq!(on_guard(TOP, BOTTOM, TOP), GuardFault::NotStack);
        assert_eq!(
            on_guard(0x1000, 0, 0),
            GuardFault::NotStack,
            "no stack recorded"
        );
    }

    /// Growing page by page ends in the overflow with the bottom page left uncommitted.
    #[test]
    fn growth_ends_in_the_overflow() {
        let mut guard = TOP - 0x3000; // two committed pages, the guard below them
        let mut pages = 0;
        loop {
            match on_guard(guard, BOTTOM, TOP) {
                GuardFault::Grow { page, next_guard } => {
                    assert_eq!(page, guard);
                    pages += 1;
                    match next_guard {
                        Some(next) => guard = next,
                        None => break,
                    }
                }
                GuardFault::NotStack => panic!("left the stack at {guard:#x}"),
            }
        }
        assert_eq!(
            guard,
            BOTTOM + PAGE_SIZE,
            "the last page committed sits above the bottom page"
        );
        assert_eq!(pages, 0x100 - 2 - 1);
    }
}
