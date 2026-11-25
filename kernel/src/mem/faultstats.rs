//! Fault-kind counters: the vector-14 dispatch notes each user page fault and its resolution
//! kind here, and the system performance-information class reports the counts.

use core::sync::atomic::{AtomicU32, Ordering};

use super::fault::Resolution;

/// The counts since boot. Each wraps at 2^32 — the class reads them for nonzero, not exact.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub struct FaultCounts {
    /// Every user-mode page fault (vector 14).
    pub page_faults: u32,
    /// A committed page's first touch: a zeroed frame brought in.
    pub demand_zero: u32,
    /// A page back from a backing list: its named frame made present, no I/O.
    pub transition: u32,
    /// A copy-on-write page written: the copy severed.
    pub copy_on_write: u32,
    /// A section's page brought in from its backing store.
    pub section: u32,
    /// A private page's paging-file slot read back.
    pub page_file: u32,
    /// A guard page touched.
    pub guard: u32,
}

static PAGE_FAULTS: AtomicU32 = AtomicU32::new(0);
static DEMAND_ZERO: AtomicU32 = AtomicU32::new(0);
static TRANSITION: AtomicU32 = AtomicU32::new(0);
static COPY_ON_WRITE: AtomicU32 = AtomicU32::new(0);
static SECTION: AtomicU32 = AtomicU32::new(0);
static PAGE_FILE: AtomicU32 = AtomicU32::new(0);
static GUARD: AtomicU32 = AtomicU32::new(0);

/// Note one user page fault: the total, plus the kind its entry resolves to. Entries that
/// resolve to nothing (a raised access violation) count toward the total only.
pub fn note_fault(entry: u32, write: bool, user: bool) {
    PAGE_FAULTS.fetch_add(1, Ordering::Relaxed);
    let bump = |slot: &AtomicU32| {
        slot.fetch_add(1, Ordering::Relaxed);
    };
    match super::fault::resolve(entry, write, user) {
        Resolution::DemandZero => bump(&DEMAND_ZERO),
        Resolution::Transition => bump(&TRANSITION),
        Resolution::CopyOnWrite => bump(&COPY_ON_WRITE),
        Resolution::Section => bump(&SECTION),
        Resolution::PageFile => bump(&PAGE_FILE),
        Resolution::Guard => bump(&GUARD),
        Resolution::Raise => {}
    };
}

/// The counts since boot.
pub fn counts() -> FaultCounts {
    FaultCounts {
        page_faults: PAGE_FAULTS.load(Ordering::Relaxed),
        demand_zero: DEMAND_ZERO.load(Ordering::Relaxed),
        transition: TRANSITION.load(Ordering::Relaxed),
        copy_on_write: COPY_ON_WRITE.load(Ordering::Relaxed),
        section: SECTION.load(Ordering::Relaxed),
        page_file: PAGE_FILE.load(Ordering::Relaxed),
        guard: GUARD.load(Ordering::Relaxed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mem::pte::{self, PteKind};
    use crate::mem::vm::PAGE_READWRITE;

    /// A demand-zero entry: committed, protected, no frame, no backing tag.
    fn demand_zero_entry() -> u32 {
        pte::encode(PteKind::DemandZero, 0, PAGE_READWRITE)
    }

    #[test]
    fn a_fault_notes_the_total_and_its_kind() {
        let before = counts();
        note_fault(demand_zero_entry(), false, true);
        let after = counts();
        assert_eq!(after.page_faults, before.page_faults.wrapping_add(1));
        assert_eq!(after.demand_zero, before.demand_zero.wrapping_add(1));
        assert_eq!(after.transition, before.transition);
    }

    #[test]
    fn an_unresolved_entry_counts_toward_the_total_only() {
        let before = counts();
        note_fault(0, true, true);
        let after = counts();
        assert_eq!(after.page_faults, before.page_faults.wrapping_add(1));
        assert_eq!(after.demand_zero, before.demand_zero);
        assert_eq!(after.copy_on_write, before.copy_on_write);
    }

    /// A transition entry — a page back from a backing list, its frame named — notes the
    /// transition kind, the one the performance class's TransitionCount reports.
    #[test]
    fn a_transition_entry_counts_the_transition_kind() {
        let entry = crate::mem::pte::encode_backing(
            crate::mem::pte::TRANSITION,
            0x0050_0000,
            PAGE_READWRITE,
        );
        let before = counts();
        note_fault(entry, false, true);
        note_fault(entry, true, true);
        let after = counts();
        assert_eq!(after.transition, before.transition.wrapping_add(2));
        assert_eq!(after.page_faults, before.page_faults.wrapping_add(2));
        assert_eq!(after.demand_zero, before.demand_zero);
        assert_eq!(after.page_file, before.page_file);
        assert_eq!(after.section, before.section);
    }
}
