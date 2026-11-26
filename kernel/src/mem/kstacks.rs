//! The kernel stacks: every thread's ring-0 ("gate") stack, one ledger and one parked stack for the
//! whole system.
//!
//! Every thread's gate stack is a slot of the kernel stack region ([`layout::KERNEL_STACKS`]): a
//! guard page, never mapped, under the stack's [`paging::GATE_STACK_PAGES`]. The region's page
//! tables are made at boot and shared by every directory, as Windows keeps its kernel stacks in
//! system space: a stack is mapped in every address space from its creation to its release, so a
//! thread can build or enter another process's address space on its own stack. Slots are numbered
//! across the whole region, the lowest free first; the ledger records occupancy, and each slot's
//! frames are recorded by the thread that owns it, released exactly once.
//!
//! A GUI thread trades its stack for a large one at its first win32k service (Windows 2000's
//! PsConvertToGuiThread, [`create_large`]): a run of [`paging::LARGE_STACK_SLOTS`] consecutive
//! slots, its top the run's top, the guard pages inside the run free for the stack to grow into.
//! It starts with the ordinary stack's pages mapped at its top and grows down, a page at a time,
//! to [`paging::LARGE_STACK_PAGES`], as the user-mode callbacks nesting on it need room ([`grow`],
//! Windows 2000's MmGrowKernelStack); the run's lowest guard page is never mapped. The slot-pool
//! plan's slice 17 (the region grown to its whole span, tables made on demand) leaves this as it
//! is: a run is consecutive slots wherever the ledger finds them.
//!
//! A thread cannot release the stack it runs on, so its exit parks it instead, as its last act
//! before the switch away, and whoever next runs on another stack releases it: the next exit (which
//! gets the earlier stack back from the park), the next thread creation, or the next process
//! teardown (on the idle thread's boot stack). One parked stack serves the whole system: its owner
//! has left it for good, whatever process the code releasing it runs in, and the release unmaps it
//! from the shared tables, not from one process's directory. A process's teardown, run after its
//! last thread's exit, finds that exit's stack parked or already released.

#[cfg(target_arch = "x86")]
use super::phys::PhysAddr;
#[cfg(target_arch = "x86")]
use super::{frame::FrameDb, with_database, Parts};
use super::{layout, paging};

/// How many slots the ledger tracks: every slot of the region.
pub const SLOTS: usize = paging::GATE_SLOT_CAPACITY;

/// How many occupancy words the ledger holds.
const SLOT_WORDS: usize = SLOTS.div_ceil(64);

/// One gate stack: the lowest slot of its run and how many slots the run spans (1, or
/// [`paging::LARGE_STACK_SLOTS`] for a GUI thread's large stack), how many pages are mapped down
/// from its top, and their frames by physical address, the top page's first, as raw words (the
/// thread record keeps them so).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GateStack {
    pub slot: u16,
    pub slots: u8,
    pub pages: u8,
    pub frames: [u32; paging::LARGE_STACK_PAGES],
}

impl GateStack {
    /// No stack: a thread record's before its creation.
    pub const NONE: GateStack = GateStack {
        slot: crate::sched::thread::NO_GATE_SLOT,
        slots: 1,
        pages: 0,
        frames: [0; paging::LARGE_STACK_PAGES],
    };

    /// The stack's top: the thread's stack top and `esp0` (the top of its run's highest slot).
    pub const fn top(&self) -> u32 {
        paging::gate_slot_top(self.slot as u32 + self.slots as u32 - 1)
    }

    /// Its lowest mapped byte: below it, unmapped pages (the guard, or room to grow into).
    pub const fn limit(&self) -> u32 {
        self.top() - self.pages as u32 * paging::PAGE_SIZE
    }

    /// The most pages it may have mapped: the large stack's, or the ordinary one's.
    pub const fn capacity(&self) -> usize {
        if self.slots > 1 {
            paging::LARGE_STACK_PAGES
        } else {
            paging::GATE_STACK_PAGES
        }
    }

    /// Whether it is a GUI thread's large stack.
    pub const fn is_large(&self) -> bool {
        self.slots > 1
    }

    /// The frames mapped in it.
    pub fn mapped(&self) -> &[u32] {
        &self.frames[..self.pages as usize]
    }
}

/// Which slots of the kernel stack region threads hold, and which of them are the lower slots of
/// a large stack's run (their top page is not the stack's).
pub struct GateSlots {
    occupied: [u64; SLOT_WORDS],
    lower: [u64; SLOT_WORDS],
}

impl GateSlots {
    /// An empty ledger: every slot free.
    pub const fn empty() -> Self {
        GateSlots {
            occupied: [0; SLOT_WORDS],
            lower: [0; SLOT_WORDS],
        }
    }

    /// Take the lowest run of `count` free consecutive slots: its lowest index; none when the
    /// region has no such run.
    pub fn allocate_run(&mut self, count: u16) -> Option<u16> {
        if count <= 1 {
            return self.allocate();
        }
        let start = (0..=SLOTS as u16 - count)
            .find(|&first| (first..first + count).all(|index| !self.is_taken(index)))?;
        for index in start..start + count {
            self.occupied[(index / 64) as usize] |= 1 << (index % 64);
            if index + 1 < start + count {
                self.lower[(index / 64) as usize] |= 1 << (index % 64);
            }
        }
        Some(start)
    }

    /// Free the run of `count` slots from `index` ([`GateSlots::allocate_run`]'s), each as
    /// [`GateSlots::release`] frees one.
    pub fn release_run(&mut self, index: u16, count: u16) {
        for slot in index..index + count.max(1) {
            self.lower[(slot / 64) as usize] &= !(1 << (slot % 64));
            self.release(slot);
        }
    }

    /// Whether `index` is a lower slot of a large stack's run.
    pub fn is_lower(&self, index: u16) -> bool {
        self.lower[(index / 64) as usize] & (1 << (index % 64)) != 0
    }

    /// Take the lowest free slot index; none when every slot of the region is taken.
    pub fn allocate(&mut self) -> Option<u16> {
        let (word_index, word) = self
            .occupied
            .iter_mut()
            .enumerate()
            .find(|(_, word)| **word != u64::MAX)?;
        let bit = word.trailing_ones();
        let index = word_index * 64 + bit as usize;
        if index >= SLOTS {
            return None;
        }
        *word |= 1 << bit;
        Some(index as u16)
    }

    /// Free slot `index`. Panics on a double release (the frames would be released twice — the
    /// frame database's own discipline makes that a panic on target).
    pub fn release(&mut self, index: u16) {
        let bit = index % 64;
        let word = &mut self.occupied[(index / 64) as usize];
        assert!(
            *word & (1 << bit) != 0,
            "double release of gate slot {index}"
        );
        *word &= !(1 << bit);
    }

    /// Whether `index` is taken.
    pub fn is_taken(&self, index: u16) -> bool {
        let bit = index % 64;
        self.occupied[(index / 64) as usize] & (1 << bit) != 0
    }

    /// The taken slots, lowest first.
    pub fn taken(&self) -> impl Iterator<Item = u16> + '_ {
        (0..SLOTS as u16).filter(|&index| self.is_taken(index))
    }

    /// Whether every slot is free.
    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.occupied.iter().all(|word| *word == 0)
    }
}

/// The system's kernel stacks: the slot ledger, and the stack of the thread that exited last, not
/// yet released.
pub struct KernelStacks {
    slots: GateSlots,
    parked: Option<GateStack>,
}

impl KernelStacks {
    /// Every slot free, nothing parked.
    pub const fn empty() -> Self {
        KernelStacks {
            slots: GateSlots::empty(),
            parked: None,
        }
    }

    /// Park `stack` (the exiting thread's own) and return the previously parked one, which the
    /// caller can release: it is not the stack the caller runs on. A parked stack keeps its slot
    /// until its release.
    pub fn park(&mut self, stack: GateStack) -> Option<GateStack> {
        self.parked.replace(stack)
    }

    /// Take the parked stack for release, if any.
    pub fn take_parked(&mut self) -> Option<GateStack> {
        self.parked.take()
    }
}

// Every slot lies inside the region, and a slot index fits the thread record's field.
const _: () = {
    assert!(paging::gate_slot_top(SLOTS as u32 - 1) as u64 <= layout::KERNEL_STACKS.end());
    assert!(SLOTS < crate::sched::thread::NO_GATE_SLOT as usize);
};

// --- The system's kernel stacks (target) ----------------------------------
//
// The stacks are part of the memory manager's database (`super::Database`), with the frame
// database their frames come from. Each step runs whole inside one borrow of it at the high level
// (interrupts masked), so the ledger and the shared tables agree wherever anything else can look:
// a taken slot is mapped, a free one is not.

/// A fresh gate stack: the system's lowest free slot, mapped in the shared tables (in every address
/// space at once); none when the region is full, or when the frame database has not the stack's
/// frames left (the tables the slots map through are all made at boot): a thread's creation fails
/// then, rather than the kernel.
#[cfg(target_arch = "x86")]
pub fn create() -> Option<GateStack> {
    create_spanning(1)
}

/// A GUI thread's large stack (see the module notes): the system's lowest run of
/// [`paging::LARGE_STACK_SLOTS`] free slots, the ordinary stack's pages mapped at its top; none
/// when the region has no such run or the frame database not the frames (the thread keeps its
/// ordinary stack then).
#[cfg(target_arch = "x86")]
pub fn create_large() -> Option<GateStack> {
    create_spanning(paging::LARGE_STACK_SLOTS as u8)
}

/// [`create`]'s work, over a run of `slots` slots.
#[cfg(target_arch = "x86")]
fn create_spanning(slots: u8) -> Option<GateStack> {
    with_database(|database| {
        let Parts {
            frames,
            stacks,
            scratch,
            ..
        } = database.parts();
        if frames.available() < paging::GATE_STACK_PAGES as u32 {
            return None;
        }
        let slot = stacks.slots.allocate_run(slots as u16)?;
        let mut stack = GateStack {
            slot,
            slots,
            pages: paging::GATE_STACK_PAGES as u8,
            frames: [0; paging::LARGE_STACK_PAGES],
        };
        let top = stack.top();
        paging::map_gate_pages(
            frames,
            scratch,
            top,
            0,
            paging::GATE_STACK_PAGES,
            &mut stack.frames,
        );
        Some(stack)
    })
}

/// Grow `stack` (a large one's; the running thread's own) down until `low` is mapped: the pages
/// between its limit and `low`'s page mapped in the shared tables. False when `low` lies past what
/// it may grow to, or the frame database has not the frames: nothing is mapped then.
#[cfg(target_arch = "x86")]
pub fn grow(stack: &mut GateStack, low: u32) -> bool {
    let Some(span) = stack.top().checked_sub(low) else {
        return false;
    };
    let wanted = (span as usize).div_ceil(paging::PAGE_SIZE as usize);
    let have = stack.pages as usize;
    if wanted <= have {
        return true;
    }
    if wanted > stack.capacity() {
        return false;
    }
    with_database(|database| {
        let Parts {
            frames, scratch, ..
        } = database.parts();
        if frames.available() < (wanted - have) as u32 {
            return false;
        }
        let top = stack.top();
        paging::map_gate_pages(frames, scratch, top, have, wanted, &mut stack.frames);
        stack.pages = wanted as u8;
        true
    })
}

/// Release a gate stack whose thread has left it for good: unmap the slot from the shared tables,
/// return the frames to the frame database, and the slot to the ledger. Never the stack the
/// processor runs on (see [`park`]).
#[cfg(target_arch = "x86")]
pub fn release(stack: GateStack) {
    with_database(|database| {
        let Parts { frames, stacks, .. } = database.parts();
        release_in(stacks, frames, stack);
    });
}

/// Park the exiting thread's own stack, releasing the one parked before it.
#[cfg(target_arch = "x86")]
pub fn park(stack: GateStack) {
    with_database(|database| {
        let Parts { frames, stacks, .. } = database.parts();
        if let Some(previous) = stacks.park(stack) {
            release_in(stacks, frames, previous);
        }
    });
}

/// Release the parked stack, if any: from code running on another stack.
#[cfg(target_arch = "x86")]
pub fn release_parked() {
    with_database(|database| {
        let Parts { frames, stacks, .. } = database.parts();
        if let Some(stack) = stacks.take_parked() {
            release_in(stacks, frames, stack);
        }
    });
}

/// Whether every taken slot is mapped in the current directory — in every directory, the tables
/// being shared. A debug check of a new address space against the stacks of the threads that run
/// in the others.
#[cfg(target_arch = "x86")]
pub fn every_stack_mapped_here() -> bool {
    with_database(|database| {
        // A large stack's lower slots are its room to grow: only its top slot's top page is
        // sure to be mapped.
        let slots = &database.stacks.slots;
        slots
            .taken()
            .filter(|&slot| !slots.is_lower(slot))
            .all(|slot| paging::gate_stack_mapped(paging::gate_slot_top(slot as u32), 1))
    })
}

/// [`release`]'s work, on the stacks and the frame database the caller holds.
#[cfg(target_arch = "x86")]
fn release_in(stacks: &mut KernelStacks, frames: &mut FrameDb, stack: GateStack) {
    use crate::mem::frame::FrameState;
    let mapped = paging::unmap_gate_pages(stack.top(), stack.pages as usize).map(PhysAddr::get);
    debug_assert_eq!(
        &mapped[..stack.pages as usize],
        stack.mapped(),
        "the stack maps the frames its thread recorded"
    );
    for &frame in stack.mapped() {
        frames.release(PhysAddr::new(frame).pfn(), FrameState::Free);
    }
    stacks.slots.release_run(stack.slot, stack.slots as u16);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mem::paging::{gate_slot_base, gate_slot_top, GATE_SLOT_STRIDE, PAGE_SIZE};

    /// The ledger hands out the lowest free index, and never one slot twice.
    #[test]
    fn the_ledger_hands_out_distinct_slots() {
        let mut ledger = GateSlots::empty();
        assert!(ledger.is_empty());
        assert_eq!((ledger.allocate(), ledger.allocate()), (Some(0), Some(1)));
        assert!(ledger.is_taken(0) && ledger.is_taken(1));
        assert!(!ledger.is_taken(2));
        assert!(!ledger.is_empty());
        assert_eq!(ledger.taken().collect::<Vec<_>>(), [0, 1]);
    }

    /// A released index is free again, and the next allocation takes the lowest free index; a
    /// double release is refused.
    #[test]
    fn a_release_frees_the_lowest_index_for_reuse() {
        let mut ledger = GateSlots::empty();
        for _ in 0..3 {
            ledger.allocate();
        }
        ledger.release(1);
        assert!(!ledger.is_taken(1));
        assert_eq!(ledger.taken().collect::<Vec<_>>(), [0, 2]);
        assert_eq!(ledger.allocate(), Some(1));
        assert_eq!(ledger.allocate(), Some(3));

        ledger.release(3);
        let refused = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| ledger.release(3)));
        assert!(refused.is_err(), "a double release is refused");
    }

    /// The ledger spans the whole region: every slot can be taken, and one more is refused as a
    /// status, not a panic. A release makes room again.
    #[test]
    fn a_full_ledger_refuses_the_next_allocation() {
        let mut ledger = GateSlots::empty();
        for expected in 0..SLOTS {
            assert_eq!(ledger.allocate(), Some(expected as u16));
        }
        assert_eq!(ledger.allocate(), None);
        assert_eq!(ledger.allocate(), None, "still full");
        assert_eq!(ledger.taken().count(), SLOTS);
        ledger.release(200);
        assert_eq!(ledger.allocate(), Some(200));
        assert_eq!(ledger.allocate(), None);
    }

    /// The region holds 455 slots (16 MiB at the 36 KiB stride), more than every thread record of
    /// the object manager, each a GUI thread's large stack, needs: the ledger fills only once a
    /// slot outlives its thread.
    #[test]
    fn the_ledger_is_sized_to_the_region() {
        assert!(SLOTS > crate::ob::THREADS * paging::LARGE_STACK_SLOTS as usize);
        assert_eq!(SLOTS, 455);
        assert_eq!(
            SLOTS,
            (layout::KERNEL_STACKS.size() / GATE_SLOT_STRIDE) as usize
        );
        assert!(SLOTS > crate::ob::THREADS);
    }

    /// Slot addresses are unique in the system: every slot lies inside the region, its guard page
    /// at its base, and no two slots overlap — the first's at the region's start, the last's top
    /// inside its end.
    #[test]
    fn every_slot_has_a_system_unique_address() {
        let region = layout::KERNEL_STACKS;
        assert_eq!(gate_slot_base(0), region.start);
        for index in 0..SLOTS as u32 {
            let (base, top) = (gate_slot_base(index), gate_slot_top(index));
            assert!(region.holds(base) && region.holds(top - 1), "slot {index}");
            assert_eq!(top - base, GATE_SLOT_STRIDE);
            assert_eq!(base % PAGE_SIZE, 0);
            if index > 0 {
                assert_eq!(base, gate_slot_top(index - 1), "slots {index} and before");
            }
        }
        assert!(gate_slot_top(SLOTS as u32 - 1) as u64 <= region.end());
        assert!(
            gate_slot_top(SLOTS as u32) as u64 > region.end(),
            "one more would not fit"
        );
    }

    /// An ordinary stack at `slot`, its frames numbered from `first`.
    fn stack(slot: u16, first: u32) -> GateStack {
        let mut frames = [0; paging::LARGE_STACK_PAGES];
        for (i, frame) in frames.iter_mut().enumerate().take(paging::GATE_STACK_PAGES) {
            *frame = first + i as u32;
        }
        GateStack {
            slot,
            slots: 1,
            pages: paging::GATE_STACK_PAGES as u8,
            frames,
        }
    }

    /// A run of slots is the lowest free consecutive run, its slots but the top one marked lower;
    /// its release frees them all, and a slot alone fits the holes a run cannot.
    #[test]
    fn a_run_takes_the_lowest_consecutive_free_slots() {
        let mut ledger = GateSlots::empty();
        for _ in 0..4 {
            ledger.allocate();
        }
        ledger.release(1);
        assert_eq!(ledger.allocate_run(3), Some(4), "slot 1 alone is too short");
        assert!(ledger.is_taken(4) && ledger.is_taken(5) && ledger.is_taken(6));
        assert!(ledger.is_lower(4) && ledger.is_lower(5) && !ledger.is_lower(6));
        assert_eq!(ledger.allocate(), Some(1));
        ledger.release(2);
        ledger.release(3);
        assert_eq!(ledger.allocate_run(2), Some(2));
        ledger.release_run(4, 3);
        assert!(!ledger.is_taken(4) && !ledger.is_taken(6) && !ledger.is_lower(4));
        assert_eq!(ledger.allocate_run(1), Some(4));
        // No run left at the region's end: refused.
        let mut full = GateSlots::empty();
        for _ in 0..SLOTS - 1 {
            full.allocate();
        }
        assert_eq!(full.allocate_run(2), None);
        assert_eq!(full.allocate_run(1), Some(SLOTS as u16 - 1));
    }

    /// A large stack's top is its run's top, it starts with the ordinary stack's pages, may grow to
    /// 104 KiB, and stays clear of its run's lowest guard page; an ordinary stack is its slot.
    #[test]
    fn a_large_stack_spans_its_run() {
        let ordinary = stack(3, 0);
        assert_eq!(ordinary.top(), gate_slot_top(3));
        assert_eq!(ordinary.limit(), gate_slot_base(3) + PAGE_SIZE);
        assert_eq!(ordinary.capacity(), paging::GATE_STACK_PAGES);
        assert!(!ordinary.is_large());
        let large = GateStack {
            slot: 6,
            slots: paging::LARGE_STACK_SLOTS as u8,
            ..ordinary
        };
        assert!(large.is_large());
        assert_eq!(large.top(), gate_slot_top(8));
        assert_eq!(large.limit(), gate_slot_top(8) - 8 * PAGE_SIZE);
        assert_eq!(large.capacity(), 26);
        let grown = GateStack { pages: 26, ..large };
        assert_eq!(grown.top() - grown.limit(), 104 * 1024);
        assert!(
            grown.limit() > gate_slot_base(6),
            "the run's lowest guard stays unmapped"
        );
        assert_eq!(GateStack::NONE.mapped(), &[] as &[u32]);
    }

    // --- The parked stack ----------------------------------------------------

    /// An exit parks its own stack and hands back the one parked before it, whichever process's;
    /// a release takes whatever is parked. At most one stack waits at any time.
    #[test]
    fn the_park_holds_one_and_hands_back_the_previous() {
        let mut stacks = KernelStacks::empty();
        assert_eq!(stacks.take_parked(), None);
        assert_eq!(stacks.park(stack(1, 10)), None);
        assert_eq!(stacks.park(stack(2, 20)), Some(stack(1, 10)));
        assert_eq!(stacks.take_parked(), Some(stack(2, 20)));
        assert_eq!(stacks.take_parked(), None);
    }

    /// The exit-then-create sequence the respawn fixture drives: an exited thread's slot stays
    /// taken while its stack is parked (its pages are still mapped), and the next creation's
    /// release frees it before the allocation, so the thread after it gets the same slot back —
    /// unmapped first, never double-mapped.
    #[test]
    fn a_creation_after_an_exit_reuses_the_released_slot() {
        let mut stacks = KernelStacks::empty();
        let main = stacks.slots.allocate().unwrap();
        let first = stacks.slots.allocate().unwrap();
        assert_eq!((main, first), (0, 1));

        // The thread exits: its stack is parked, its slot still taken.
        assert_eq!(stacks.park(stack(first, 1)), None);
        assert!(stacks.slots.is_taken(first));

        // The next creation releases the parked stack before it allocates.
        let parked = stacks
            .take_parked()
            .expect("the exited thread's stack is parked");
        stacks.slots.release_run(parked.slot, parked.slots as u16);
        assert_eq!(stacks.slots.allocate(), Some(first));
        assert_eq!(stacks.take_parked(), None);
    }
}
