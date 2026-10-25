//! The kernel stack slots: one ledger for the whole system.
//!
//! Every thread's ring-0 ("gate") stack is a slot of the kernel stack region
//! ([`layout::KERNEL_STACKS`]): a guard page, never mapped, under the stack's
//! [`paging::GATE_STACK_PAGES`]. Slots are numbered across the whole region, so a slot's address is
//! unique in the system, whatever process its thread belongs to: the ledger here says which slots
//! threads hold, the lowest free first. It records occupancy only — each slot's frames are recorded
//! by the thread that owns it, released exactly once.

use super::{layout, paging};

/// How many slots the ledger tracks: every slot of the region.
pub const SLOTS: usize = paging::GATE_SLOT_CAPACITY;

/// How many occupancy words the ledger holds.
const SLOT_WORDS: usize = SLOTS.div_ceil(64);

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
    #[cfg(test)]
    pub fn is_taken(&self, index: u16) -> bool {
        let bit = index % 64;
        self.occupied[(index / 64) as usize] & (1 << bit) != 0
    }

    /// Whether every slot is free.
    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.occupied.iter().all(|word| *word == 0)
    }
}

// Every slot lies inside the region, and a slot index fits the thread record's field.
const _: () = {
    assert!(paging::gate_slot_top(SLOTS as u32 - 1) as u64 <= layout::KERNEL_STACKS.end());
    assert!(SLOTS < crate::sched::thread::NO_GATE_SLOT as usize);
};

// --- The system's ledger (target) -----------------------------------------

/// The system's slot ledger.
#[cfg(target_arch = "x86")]
static LEDGER: crate::global::Global<GateSlots> = crate::global::Global::new(GateSlots::empty());

/// Take the lowest free slot of the system's ledger; none when the region is full.
#[cfg(target_arch = "x86")]
pub fn allocate_slot() -> Option<u16> {
    LEDGER.with(GateSlots::allocate)
}

/// Give slot `index` back to the system's ledger, once its pages are unmapped (or gone with the
/// directory that mapped them).
#[cfg(target_arch = "x86")]
pub fn release_slot(index: u16) {
    LEDGER.with(|slots| slots.release(index));
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
}
