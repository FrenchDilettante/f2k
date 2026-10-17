//! User stacks that grow on demand, the way NT's do.
//!
//! A thread's stack is a reservation, `[base, top)`, of which only `[limit, top)` is committed.
//! The page just below the limit is the guard: touching it commits it and the limit moves down a
//! page, so a stack grows one page at a time, as a stack is used — the reason compilers probe large
//! frames page by page (`_chkstk`). A touch further below the guard is an access violation (the page
//! in between was never committed). The reservation's lowest page is never committed: committing
//! the page above it, the last one, is the stack overflow (STATUS_STACK_OVERFLOW).

use crate::mem::paging::PAGE_SIZE;

/// A thread's user stack: its reservation and the committed limit.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct UserStack {
    /// The reservation's lowest address (its never-committed bottom page).
    pub base: u32,
    /// One past the stack's top.
    pub top: u32,
    /// The lowest committed address (the TEB's StackLimit).
    pub limit: u32,
}

/// What a fault at an address means for a stack.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StackFault {
    /// The guard page: commit `page`; `overflow` when it was the last page the reservation can
    /// commit.
    Grow { page: u32, overflow: bool },
    /// Inside the reservation below the guard: an access violation.
    BelowGuard,
    /// Not this stack's.
    NotStack,
}

impl UserStack {
    /// No stack: nothing classifies as its fault.
    pub const fn none() -> UserStack {
        UserStack {
            base: 0,
            top: 0,
            limit: 0,
        }
    }

    /// A stack of `reserve` bytes ending at `top`, with `committed` bytes committed below the top.
    pub const fn new(top: u32, reserve: u32, committed: u32) -> UserStack {
        UserStack {
            base: top - reserve,
            top,
            limit: top - committed,
        }
    }

    /// Classify a fault at `address`.
    pub fn classify(&self, address: u32) -> StackFault {
        if address < self.base || address >= self.limit {
            return StackFault::NotStack;
        }
        let guard = self.limit - PAGE_SIZE;
        if address < guard || guard <= self.base {
            return StackFault::BelowGuard;
        }
        StackFault::Grow {
            page: guard,
            overflow: guard - PAGE_SIZE <= self.base,
        }
    }

    /// The stack after its guard page at `page` is committed.
    pub fn grown(self, page: u32) -> UserStack {
        UserStack {
            limit: page,
            ..self
        }
    }
}

/// What the page-fault path did for a fault on the running thread's stack.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Growth {
    /// The guard page is committed: the faulting access resumes.
    Grown,
    /// The last page is committed: the stack has overflowed.
    Overflow,
    /// Not a guard-page fault.
    NotGrown,
}

/// Plant a stack's guard page at `page`: committed, read-write and guarded (PAGE_GUARD), so the
/// first touch faults — and grows the stack. Without a frame to spare the stack has no guard; the
/// touch below its limit still grows it.
#[cfg(target_arch = "x86")]
pub fn plant_guard(page: u32) {
    use crate::mem::vm::{self, Pages, PAGE_GUARD, PAGE_READWRITE};
    let mut pages = vm::CurrentPages;
    if pages.entry(page) != 0 {
        return;
    }
    if let Some(frame) = pages.zeroed_frame() {
        pages.set_entry(page, vm::encode(frame, PAGE_READWRITE | PAGE_GUARD));
    }
}

/// Grow the running thread's stack for a fault at `address`, when it is the guard page's: commit
/// the page (the guard's own frame, or a fresh one), plant the next guard below it, move the limit,
/// and record it in the TEB's StackLimit.
#[cfg(target_arch = "x86")]
pub fn grow_on_fault(address: u32) -> Growth {
    use crate::mem::vm::{self, Pages, PAGE_READWRITE};
    // SAFETY: the running thread's record, live while it runs.
    let thread = unsafe { &mut *crate::sched::idle::dispatcher().current_thread() };
    let StackFault::Grow { page, overflow } = thread.user_stack.classify(address) else {
        return Growth::NotGrown;
    };
    let mut pages = vm::CurrentPages;
    let frame = match vm::decode(pages.entry(page)) {
        Some((frame, _)) => Some(frame),
        None => pages.zeroed_frame(),
    };
    let Some(frame) = frame else {
        // No memory to grow into: the stack has overflowed as far as the program can tell.
        return Growth::Overflow;
    };
    pages.set_entry(page, vm::encode(frame, PAGE_READWRITE));
    if !overflow {
        plant_guard(page - PAGE_SIZE);
    }
    thread.user_stack = thread.user_stack.grown(page);
    let teb = thread.teb_va();
    if teb != 0 {
        // SAFETY: the thread's own TEB page, mapped writable in the current address space.
        unsafe {
            core::ptr::write_volatile(
                (teb + crate::user::teb::teb_offset::STACK_LIMIT) as *mut u32,
                page,
            )
        };
    }
    if overflow {
        Growth::Overflow
    } else {
        Growth::Grown
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOP: u32 = 0x0030_1000;

    /// A fresh 1 MiB stack with two committed pages: the guard is the page below them.
    fn stack() -> UserStack {
        UserStack::new(TOP, 0x10_0000, 2 * PAGE_SIZE)
    }

    #[test]
    fn the_guard_page_grows_the_stack() {
        let s = stack();
        assert_eq!(s.limit, TOP - 0x2000);
        assert_eq!(
            s.classify(TOP - 0x2001),
            StackFault::Grow {
                page: TOP - 0x3000,
                overflow: false
            }
        );
        assert_eq!(
            s.classify(TOP - 0x3000),
            StackFault::Grow {
                page: TOP - 0x3000,
                overflow: false
            }
        );
        let s = s.grown(TOP - 0x3000);
        assert_eq!(s.limit, TOP - 0x3000);
        assert_eq!(
            s.classify(TOP - 0x3000),
            StackFault::NotStack,
            "committed now"
        );
    }

    /// Skipping the guard is an access violation; outside the reservation is not the stack's.
    #[test]
    fn below_the_guard_and_outside() {
        let s = stack();
        assert_eq!(s.classify(TOP - 0x3001), StackFault::BelowGuard);
        assert_eq!(s.classify(s.base), StackFault::BelowGuard);
        assert_eq!(s.classify(s.base - 1), StackFault::NotStack);
        assert_eq!(s.classify(TOP), StackFault::NotStack);
        assert_eq!(s.classify(TOP - 4), StackFault::NotStack, "committed");
        assert_eq!(UserStack::none().classify(0x1000), StackFault::NotStack);
    }

    /// Growing page by page reaches the overflow at the last committable page; the bottom page is
    /// never committed.
    #[test]
    fn growth_ends_in_the_overflow() {
        let mut s = stack();
        let mut pages = 0;
        loop {
            match s.classify(s.limit - 1) {
                StackFault::Grow { page, overflow } => {
                    s = s.grown(page);
                    pages += 1;
                    if overflow {
                        break;
                    }
                }
                other => panic!("unexpected {other:?} at {:#x}", s.limit - 1),
            }
        }
        assert_eq!(
            s.limit,
            s.base + PAGE_SIZE,
            "the bottom page stays uncommitted"
        );
        assert_eq!(pages, 0x100 - 2 - 1);
        assert_eq!(s.classify(s.limit - 1), StackFault::BelowGuard);
    }

    /// A stack with nothing to grow into (reservation == commit) has no guard.
    #[test]
    fn a_fixed_stack_has_no_guard() {
        let s = UserStack::new(TOP, 0x2000, 0x2000);
        assert_eq!(s.classify(TOP - 0x2001), StackFault::NotStack);
    }
}
