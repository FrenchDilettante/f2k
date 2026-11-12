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
//! violation. The reservation's lowest page is never committed: it is the hard barrier below the
//! stack. Windows 2000 never moves the guard into the page just above it either: a guard firing
//! with only those two pages left below it is the stack overflow (STATUS_STACK_OVERFLOW). The page
//! above the barrier is then committed as an ordinary page, unguarded, and becomes the TEB's
//! StackLimit — the room the overflow's handlers run in — and nothing guards the stack any more
//! (the C runtime's `_resetstkoflw` plants a guard again).
//!
//! The rule reads the thread's TEB — user memory, through the fault-tolerant copy — as the
//! platform's does: a TEB the program made unreadable or rewrote decides only where its own stack
//! grows.

use crate::mem::paging::PAGE_SIZE;

/// What a guard page that fired at an address means for a stack.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum GuardFault {
    /// Inside the stack, with room below: `page`, the fired guard's, is the new limit, and
    /// `next_guard`, the page below it, is guarded.
    Grow { page: u32, next_guard: u32 },
    /// Inside the stack, without room for another guard (the page below `page` is the one above
    /// the reservation's never-committed bottom page, or that page itself): the overflow. `last`
    /// is the page above the bottom one, committed unguarded as the stack's last room and its new
    /// limit — none when `page` is that page already, or the bottom one (`page` is then the
    /// limit).
    Overflow { page: u32, last: Option<u32> },
    /// Outside the stack's reservation.
    NotStack,
}

/// Classify a guard page firing at `address` for the stack reserved at `[deallocation, base)`.
pub fn on_guard(address: u32, deallocation: u32, base: u32) -> GuardFault {
    if address < deallocation || address >= base {
        return GuardFault::NotStack;
    }
    let page = address & !(PAGE_SIZE - 1);
    // Saturating: the TEB is the program's to rewrite, a reservation at the top of the space
    // included.
    let barrier_top = deallocation.saturating_add(PAGE_SIZE);
    match page.checked_sub(PAGE_SIZE) {
        Some(below) if below > barrier_top => GuardFault::Grow {
            page,
            next_guard: below,
        },
        below => GuardFault::Overflow {
            page,
            last: below.filter(|&below| below == barrier_top),
        },
    }
}

/// What the page-fault path did for a guard page that fired.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Growth {
    /// The running thread's stack grew by the page: the faulting access resumes.
    Grown,
    /// No guard can go below the page (only the reservation's last two pages are left, or there is
    /// no frame to guard with): the stack has overflowed.
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
/// next guard planted below — or report the overflow, the page above the reservation's bottom one
/// committed unguarded and made the limit (see the module notes).
#[cfg(target_arch = "x86")]
pub fn grow_on_guard(address: u32) -> Growth {
    use crate::mem::vm::CurrentPages;
    use crate::user::teb::teb_field;
    let thread = crate::sched::current_thread();
    let teb = crate::level::raised::<crate::level::Dispatch, _>(|dispatch| {
        crate::sched::DISPATCHER
            .get(dispatch)
            .thread(thread)
            .teb_va()
    });
    if teb == 0 {
        return Growth::NotStack;
    }
    let (Ok(deallocation), Ok(base)) = (
        teb_field!(deallocation_stack).of(teb).read(),
        teb_field!(stack_base).of(teb).read(),
    ) else {
        return Growth::NotStack;
    };
    // The address space whose tables are live: the faulting thread's own here (an attached
    // thread's guard is never its stack's). Its lock is the one the fault path takes, the TEB read
    // and written before it. A page below already committed (the program committed it itself)
    // needs nothing planted: the stack runs into it.
    let process = crate::process::pool::address_space();
    let committed_or_planted = |page: u32, guarded: bool| {
        process.with_space(|space| {
            space.frame_at(&CurrentPages, page).is_some()
                || space.plant_page(&mut CurrentPages, page, guarded)
        })
    };
    let limit = teb_field!(stack_limit).of(teb);
    match on_guard(address, deallocation, base) {
        GuardFault::NotStack => Growth::NotStack,
        GuardFault::Grow { page, next_guard } => {
            let _ = limit.write(page);
            if committed_or_planted(next_guard, true) {
                Growth::Grown
            } else {
                // No frame to guard with: the stack cannot grow further.
                Growth::Overflow
            }
        }
        GuardFault::Overflow { page, last } => {
            let last = last.filter(|&last| committed_or_planted(last, false));
            let _ = limit.write(last.unwrap_or(page));
            Growth::Overflow
        }
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
                next_guard: TOP - 0x4000
            }
        );
        // Anywhere inside the reservation: a guard the program re-planted higher up (after an
        // overflow, `_resetstkoflw`) grows the stack the same way.
        assert_eq!(
            on_guard(TOP - 0x8_0000, BOTTOM, TOP),
            GuardFault::Grow {
                page: TOP - 0x8_0000,
                next_guard: TOP - 0x8_1000
            }
        );
    }

    /// The guard is never moved into the page above the bottom one: a guard firing two pages above
    /// the reservation's end is the overflow, the page below it committed unguarded as the last
    /// room and the limit. A guard the program planted lower still overflows, with nothing to
    /// commit.
    #[test]
    fn the_guard_stops_above_the_last_two_pages() {
        assert_eq!(
            on_guard(BOTTOM + 0x3000, BOTTOM, TOP),
            GuardFault::Grow {
                page: BOTTOM + 0x3000,
                next_guard: BOTTOM + 0x2000
            }
        );
        assert_eq!(
            on_guard(BOTTOM + 0x2FFF, BOTTOM, TOP),
            GuardFault::Overflow {
                page: BOTTOM + 0x2000,
                last: Some(BOTTOM + PAGE_SIZE)
            }
        );
        assert_eq!(
            on_guard(BOTTOM + 0x1000, BOTTOM, TOP),
            GuardFault::Overflow {
                page: BOTTOM + 0x1000,
                last: None
            }
        );
        assert_eq!(
            on_guard(BOTTOM, BOTTOM, TOP),
            GuardFault::Overflow {
                page: BOTTOM,
                last: None
            }
        );
        assert_eq!(
            on_guard(0, 0, 0x10_0000),
            GuardFault::Overflow {
                page: 0,
                last: None
            },
            "a reservation at zero"
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

    /// Growing page by page ends in the overflow at the guard two pages above the reservation's
    /// end (the vmedge capture's deepest frame sits in the page above it), the page below it the
    /// last room, the bottom page left uncommitted.
    #[test]
    fn growth_ends_in_the_overflow() {
        let mut guard = TOP - 0x3000; // two committed pages, the guard below them
        let mut pages = 0;
        let last = loop {
            match on_guard(guard, BOTTOM, TOP) {
                GuardFault::Grow { page, next_guard } => {
                    assert_eq!(page, guard);
                    pages += 1;
                    guard = next_guard;
                }
                GuardFault::Overflow { page, last } => {
                    assert_eq!(page, guard);
                    break last;
                }
                GuardFault::NotStack => panic!("left the stack at {guard:#x}"),
            }
        };
        assert_eq!(guard, BOTTOM + 2 * PAGE_SIZE, "the overflow's guard");
        assert_eq!(last, Some(BOTTOM + PAGE_SIZE), "the last room");
        // Every page grown into but the two committed at the start and the reservation's last
        // three (the overflow's guard, the last room, the barrier).
        assert_eq!(pages, 0x100 - 2 - 3);
    }
}
