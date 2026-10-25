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
//! A thread cannot release the stack it runs on, so its exit parks it instead, as its last act
//! before the switch away, and whoever next runs on another stack releases it: the next exit (which
//! gets the earlier stack back from the park), the next thread creation, or the next process
//! teardown (on the idle thread's boot stack). One parked stack serves the whole system: its owner
//! has left it for good, whatever process the code releasing it runs in, and the release unmaps it
//! from the shared tables, not from one process's directory. A process's teardown, run after its
//! last thread's exit, finds that exit's stack parked or already released.

use super::{layout, paging};

/// How many slots the ledger tracks: every slot of the region.
pub const SLOTS: usize = paging::GATE_SLOT_CAPACITY;

/// How many occupancy words the ledger holds.
const SLOT_WORDS: usize = SLOTS.div_ceil(64);

/// One gate stack: its slot index and the frames mapped in it.
pub type GateStack = (u16, [u32; paging::GATE_STACK_PAGES]);

/// Which slots of the kernel stack region threads hold.
pub struct GateSlots {
    occupied: [u64; SLOT_WORDS],
}

impl GateSlots {
    /// An empty ledger: every slot free.
    pub const fn empty() -> Self {
        GateSlots {
            occupied: [0; SLOT_WORDS],
        }
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
// Each step runs whole inside the global's closure (interrupts masked), so the ledger and the
// shared tables agree wherever anything else can look: a taken slot is mapped, a free one is not.

/// The system's kernel stacks.
#[cfg(target_arch = "x86")]
static STACKS: crate::global::Global<KernelStacks> =
    crate::global::Global::new(KernelStacks::empty());

/// A fresh gate stack: the system's lowest free slot, mapped in the shared tables (in every address
/// space at once); none when the region is full.
#[cfg(target_arch = "x86")]
pub fn create() -> Option<GateStack> {
    STACKS.with(|stacks| {
        let slot = stacks.slots.allocate()?;
        Some((slot, paging::map_gate_slot(slot as u32)))
    })
}

/// Release a gate stack whose thread has left it for good: unmap the slot from the shared tables,
/// return the frames to the frame database, and the slot to the ledger. Never the stack the
/// processor runs on (see [`park`]).
#[cfg(target_arch = "x86")]
pub fn release(stack: GateStack) {
    STACKS.with(|stacks| release_in(stacks, stack));
}

/// Park the exiting thread's own stack, releasing the one parked before it.
#[cfg(target_arch = "x86")]
pub fn park(stack: GateStack) {
    STACKS.with(|stacks| {
        if let Some(previous) = stacks.park(stack) {
            release_in(stacks, previous);
        }
    });
}

/// Release the parked stack, if any: from code running on another stack.
#[cfg(target_arch = "x86")]
pub fn release_parked() {
    STACKS.with(|stacks| {
        if let Some(stack) = stacks.take_parked() {
            release_in(stacks, stack);
        }
    });
}

/// Whether every taken slot is mapped in the current directory — in every directory, the tables
/// being shared. A debug check of a new address space against the stacks of the threads that run
/// in the others.
#[cfg(target_arch = "x86")]
pub fn every_stack_mapped_here() -> bool {
    STACKS.with(|stacks| {
        stacks
            .slots
            .taken()
            .all(|slot| paging::gate_slot_mapped(slot as u32))
    })
}

/// [`release`]'s work, on the stacks the caller holds.
#[cfg(target_arch = "x86")]
fn release_in(stacks: &mut KernelStacks, (slot, frames): GateStack) {
    use crate::mem::frame::FrameState;
    let mapped = paging::unmap_gate_slot(slot as u32);
    debug_assert_eq!(
        mapped, frames,
        "the slot maps the frames its thread recorded"
    );
    for frame in frames {
        crate::mem::bootmem::with_frame_db(|db| {
            db.release(frame / paging::PAGE_SIZE, FrameState::Free);
        });
    }
    stacks.slots.release(slot);
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
    /// the object manager: the ledger fills only once a slot outlives its thread.
    #[test]
    fn the_ledger_is_sized_to_the_region() {
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

    // --- The parked stack ----------------------------------------------------

    /// An exit parks its own stack and hands back the one parked before it, whichever process's;
    /// a release takes whatever is parked. At most one stack waits at any time.
    #[test]
    fn the_park_holds_one_and_hands_back_the_previous() {
        let mut stacks = KernelStacks::empty();
        assert_eq!(stacks.take_parked(), None);
        assert_eq!(stacks.park((1, [10, 11, 12, 13, 14, 15, 16, 17])), None);
        assert_eq!(
            stacks.park((2, [20, 21, 22, 23, 24, 25, 26, 27])),
            Some((1, [10, 11, 12, 13, 14, 15, 16, 17]))
        );
        assert_eq!(
            stacks.take_parked(),
            Some((2, [20, 21, 22, 23, 24, 25, 26, 27]))
        );
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
        assert_eq!(stacks.park((first, [1, 2, 3, 4, 5, 6, 7, 8])), None);
        assert!(stacks.slots.is_taken(first));

        // The next creation releases the parked stack before it allocates.
        let (slot, _) = stacks
            .take_parked()
            .expect("the exited thread's stack is parked");
        stacks.slots.release(slot);
        assert_eq!(stacks.slots.allocate(), Some(first));
        assert_eq!(stacks.take_parked(), None);
    }
}
