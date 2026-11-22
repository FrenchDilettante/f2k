//! Page-table entries: the states a user page's entry can hold, and the encode/decode between
//! them and the raw 32-bit word.
//!
//! The word's layout is the one the address-space manager writes today, so the two swap over
//! without a change of convention: bit 0 is present; bit 1 is the write bit on a present entry
//! and the committed marker on a non-present one; bit 2 is the user bit on a present entry and
//! the guard flag on a non-present one; bits 9-11 hold the protection index; bits 12-31 hold the
//! frame's physical address. Bits 3-8 stay clear — they are software bits a later page state may
//! need — and [`classify`] ignores them.
//!
//! The kinds:
//! - [`PteKind::Present`] — mapped now; the write bit says whether the hardware may write it.
//! - [`PteKind::CopyOnWrite`] — present but held copy-on-write: its protection index is a
//!   copy-on-write one, so the hardware reads only and the first write severs the page.
//! - [`PteKind::Guard`] — committed, not present, the guard flag set; touching it raises a guard
//!   violation instead of faulting a frame in.
//! - [`PteKind::DemandZero`] — committed, not present, no frame; the first touch faults a zeroed
//!   frame in.
//! - [`PteKind::Transition`] — not present, but the frame is named: the page was evicted and its
//!   contents wait on the backing store.
//! - [`PteKind::Uncommitted`] — no entry, or one without the committed marker: reserved or free.

// Pure module: the address-space manager's encode/decode swaps over to it when the demand-paging
// slices land, so nothing on target calls it yet; the host tests do.
#![cfg_attr(not(test), allow(dead_code))]

use super::vm::{
    PAGE_EXECUTE,
    PAGE_EXECUTE_READ,
    PAGE_EXECUTE_READWRITE,
    PAGE_EXECUTE_WRITECOPY,
    PAGE_GUARD,
    PAGE_NOACCESS,
    PAGE_READONLY,
    PAGE_READWRITE,
    PAGE_WRITECOPY,
};

/// Bit 0: the page is present, mapped to its frame now.
const PRESENT: u32 = 1 << 0;
/// Bit 1: the write bit on a present entry, the committed marker on a non-present one.
const WRITE_OR_COMMITTED: u32 = 1 << 1;
/// Bit 2: the user bit on a present entry, the guard flag on a non-present one.
const USER_OR_GUARD: u32 = 1 << 2;
/// Bits 3-8: software bits, kept clear by [`encode`] and ignored by [`classify`].
const RESERVED: u32 = 0x1F8;
/// Bits 9-11: the protection index's place.
const INDEX_SHIFT: u32 = 9;
const INDEX_MASK: u32 = 7;
/// Bits 12-31: the frame's physical address.
const FRAME_MASK: u32 = 0xFFFF_F000;

/// What a page's entry says about the page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PteKind {
    /// No entry, or one without the committed marker: the page is reserved or free.
    Uncommitted,
    /// Present and mapped to its frame; the write bit says whether the hardware may write.
    Present,
    /// Present but held copy-on-write: read-only to the hardware, the first write severs it.
    CopyOnWrite,
    /// Committed, not present, the guard flag set; touching it raises a guard violation.
    Guard,
    /// Committed, not present, no frame: the first touch faults a zeroed frame in.
    DemandZero,
    /// Not present, but the frame is named: the contents wait on the backing store.
    Transition,
}

/// The kind of page `entry` describes.
pub fn classify(entry: u32) -> PteKind {
    if entry & PRESENT != 0 {
        // A present entry with a copy-on-write protection index is held copy-on-write; the
        // write bit on any other present entry is read through `writable` instead.
        match (entry >> INDEX_SHIFT) & INDEX_MASK {
            3 | 7 => PteKind::CopyOnWrite,
            _ => PteKind::Present,
        }
    } else if entry & WRITE_OR_COMMITTED == 0 {
        // Without the committed marker the entry is not ours, however its other bits read.
        PteKind::Uncommitted
    } else if entry & USER_OR_GUARD != 0 {
        PteKind::Guard
    } else if entry & FRAME_MASK != 0 {
        PteKind::Transition
    } else {
        PteKind::DemandZero
    }
}

/// The entry for a page of `kind` backed by `frame` (a physical address) with `protect`.
///
/// The kind and the protection must agree: a present page takes a readable or writable
/// protection, a copy-on-write page a copy-on-write one, a demand-zero page no frame at all,
/// and a transition page a named frame.
pub fn encode(kind: PteKind, frame: u32, protect: u32) -> u32 {
    let base = protect & 0xFF;
    let index = index_of(base) << INDEX_SHIFT;
    match kind {
        PteKind::Uncommitted => 0,
        PteKind::Present => {
            debug_assert!(
                frame != 0 && frame & !FRAME_MASK == 0,
                "a present page names a frame"
            );
            debug_assert!(
                !matches!(
                    base,
                    PAGE_NOACCESS | PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY
                ),
                "a present page is neither no-access nor copy-on-write"
            );
            frame
                | PRESENT
                | USER_OR_GUARD
                | if base_writable(base) {
                    WRITE_OR_COMMITTED
                } else {
                    0
                }
                | index
        }
        PteKind::CopyOnWrite => {
            debug_assert!(
                frame != 0 && frame & !FRAME_MASK == 0,
                "a copy-on-write page names a frame"
            );
            debug_assert!(
                matches!(base, PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY),
                "a copy-on-write page takes a copy-on-write protection"
            );
            // Read-only to the hardware: the first write faults into the copy.
            frame | PRESENT | USER_OR_GUARD | index
        }
        PteKind::Guard => {
            debug_assert!(frame & !FRAME_MASK == 0, "the frame is page-aligned");
            debug_assert!(
                protect & PAGE_GUARD != 0,
                "a guard page carries the guard flag"
            );
            frame | WRITE_OR_COMMITTED | USER_OR_GUARD | index
        }
        PteKind::DemandZero => {
            debug_assert!(frame == 0, "a demand-zero page names no frame");
            WRITE_OR_COMMITTED | index
        }
        PteKind::Transition => {
            debug_assert!(
                frame != 0 && frame & !FRAME_MASK == 0,
                "a transition page names a frame"
            );
            frame | WRITE_OR_COMMITTED | index
        }
    }
}

/// A page's kind, frame and protection, from its entry; none for an uncommitted page.
pub fn decode(entry: u32) -> Option<(PteKind, u32, u32)> {
    let kind = classify(entry);
    if kind == PteKind::Uncommitted {
        return None;
    }
    let frame = entry & FRAME_MASK;
    let index = (entry >> INDEX_SHIFT) & INDEX_MASK;
    let protect = match kind {
        // A present entry written before the protection was recorded carries index 0: it reads
        // as read-write when the write bit is set, read-only otherwise.
        PteKind::Present => match index {
            0 if entry & WRITE_OR_COMMITTED != 0 => PAGE_READWRITE,
            0 => PAGE_READONLY,
            index => base_of(index),
        },
        PteKind::CopyOnWrite => base_of(index),
        PteKind::Guard => base_of(index) | PAGE_GUARD,
        PteKind::DemandZero | PteKind::Transition => base_of(index),
        PteKind::Uncommitted => unreachable!("classified above"),
    };
    Some((kind, frame, protect))
}

/// Whether the hardware write bit is set: a present page the CPU may write. Every non-present
/// entry reads false, whatever its committed marker says.
pub fn writable(entry: u32) -> bool {
    entry & PRESENT != 0 && entry & WRITE_OR_COMMITTED != 0
}

/// Whether the entry says the page is committed: present, or marked committed while not
/// present (guard, demand-zero and transition pages all keep their commit charge).
pub fn committed(entry: u32) -> bool {
    entry & (PRESENT | WRITE_OR_COMMITTED) != 0
}

/// The protection index of a base protection (1-7 present, 0 no-access).
fn index_of(base: u32) -> u32 {
    match base {
        PAGE_READONLY => 1,
        PAGE_READWRITE => 2,
        PAGE_WRITECOPY => 3,
        PAGE_EXECUTE => 4,
        PAGE_EXECUTE_READ => 5,
        PAGE_EXECUTE_READWRITE => 6,
        PAGE_EXECUTE_WRITECOPY => 7,
        _ => 0,
    }
}

/// The base protection of a protection index.
fn base_of(index: u32) -> u32 {
    match index {
        1 => PAGE_READONLY,
        2 => PAGE_READWRITE,
        3 => PAGE_WRITECOPY,
        4 => PAGE_EXECUTE,
        5 => PAGE_EXECUTE_READ,
        6 => PAGE_EXECUTE_READWRITE,
        7 => PAGE_EXECUTE_WRITECOPY,
        _ => PAGE_NOACCESS,
    }
}

/// Whether a base protection lets the hardware write: a copy-on-write page does not, its first
/// write faulting into the copy.
fn base_writable(base: u32) -> bool {
    matches!(base, PAGE_READWRITE | PAGE_EXECUTE_READWRITE)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FRAME: u32 = 0x0050_0000;
    const OTHER: u32 = 0x0070_0000;

    /// The (kind, frame, protection) cases every other test reuses.
    const CASES: &[(PteKind, u32, u32)] = &[
        (PteKind::Present, FRAME, PAGE_READONLY),
        (PteKind::Present, FRAME, PAGE_READWRITE),
        (PteKind::Present, FRAME, PAGE_EXECUTE),
        (PteKind::Present, FRAME, PAGE_EXECUTE_READ),
        (PteKind::Present, FRAME, PAGE_EXECUTE_READWRITE),
        (PteKind::CopyOnWrite, FRAME, PAGE_WRITECOPY),
        (PteKind::CopyOnWrite, FRAME, PAGE_EXECUTE_WRITECOPY),
        (PteKind::Guard, OTHER, PAGE_READWRITE | PAGE_GUARD),
        (PteKind::Guard, 0, PAGE_READONLY | PAGE_GUARD),
        (PteKind::DemandZero, 0, PAGE_READWRITE),
        (PteKind::DemandZero, 0, PAGE_READONLY),
        (PteKind::DemandZero, 0, PAGE_NOACCESS),
        (PteKind::Transition, OTHER, PAGE_READWRITE),
        (PteKind::Transition, OTHER, PAGE_READONLY),
    ];

    /// Every kind round trips: encode then classify gives the kind back, and decode gives the
    /// kind, the frame and the protection.
    #[test]
    fn every_kind_round_trips() {
        for &(kind, frame, protect) in CASES {
            let entry = encode(kind, frame, protect);
            assert_eq!(
                classify(entry),
                kind,
                "{kind:?} of frame {frame:#x} with {protect:#x}"
            );
            assert_eq!(
                decode(entry),
                Some((kind, frame, protect)),
                "{kind:?} of frame {frame:#x} with {protect:#x}"
            );
        }
        // An uncommitted page has no entry at all.
        assert_eq!(encode(PteKind::Uncommitted, FRAME, PAGE_READWRITE), 0);
        assert_eq!(classify(0), PteKind::Uncommitted);
        assert_eq!(decode(0), None);
    }

    /// Present pages split by the write bit: a writable one and a read-only one decode to their
    /// protections, and only the writable one answers [`writable`].
    #[test]
    fn present_pages_classify_by_write_and_read() {
        let rw = encode(PteKind::Present, FRAME, PAGE_READWRITE);
        let ro = encode(PteKind::Present, FRAME, PAGE_READONLY);
        let xrw = encode(PteKind::Present, FRAME, PAGE_EXECUTE_READWRITE);
        assert!(writable(rw));
        assert!(writable(xrw));
        assert!(!writable(ro));
        assert_eq!(rw & WRITE_OR_COMMITTED, WRITE_OR_COMMITTED);
        assert_eq!(ro & WRITE_OR_COMMITTED, 0);
        assert_eq!(decode(rw), Some((PteKind::Present, FRAME, PAGE_READWRITE)));
        assert_eq!(decode(ro), Some((PteKind::Present, FRAME, PAGE_READONLY)));
        assert_eq!(
            decode(xrw),
            Some((PteKind::Present, FRAME, PAGE_EXECUTE_READWRITE))
        );
        // A copy-on-write page is present but never hardware-writable, and so is every
        // non-present entry.
        assert!(!writable(encode(
            PteKind::CopyOnWrite,
            FRAME,
            PAGE_WRITECOPY
        )));
        assert!(!writable(encode(PteKind::DemandZero, 0, PAGE_READWRITE)));
        assert!(!writable(encode(
            PteKind::Transition,
            OTHER,
            PAGE_READWRITE
        )));
        assert!(!writable(encode(
            PteKind::Guard,
            OTHER,
            PAGE_READWRITE | PAGE_GUARD
        )));
    }

    /// Copy-on-write is its own kind: a present entry whose protection index is a copy-on-write
    /// one, whatever its write bit says.
    #[test]
    fn copy_on_write_is_a_present_page_held_back() {
        let cow = encode(PteKind::CopyOnWrite, FRAME, PAGE_WRITECOPY);
        assert_eq!(cow & PRESENT, PRESENT);
        assert_eq!(classify(cow), PteKind::CopyOnWrite);
        assert_eq!(
            decode(FRAME | PRESENT | USER_OR_GUARD | (3 << INDEX_SHIFT)),
            Some((PteKind::CopyOnWrite, FRAME, PAGE_WRITECOPY))
        );
        assert_eq!(
            decode(FRAME | PRESENT | USER_OR_GUARD | (7 << INDEX_SHIFT)),
            Some((PteKind::CopyOnWrite, FRAME, PAGE_EXECUTE_WRITECOPY))
        );
        // Any other present entry is a plain present page.
        assert_eq!(
            classify(encode(PteKind::Present, FRAME, PAGE_EXECUTE)),
            PteKind::Present
        );
    }

    /// Demand-zero, transition and guard are all committed and not present; the guard flag and
    /// the frame field are what tell them apart, and the guard flag wins over a named frame.
    #[test]
    fn demand_zero_transition_and_guard_tell_apart() {
        assert_eq!(classify(WRITE_OR_COMMITTED), PteKind::DemandZero);
        assert_eq!(classify(WRITE_OR_COMMITTED | OTHER), PteKind::Transition);
        assert_eq!(classify(WRITE_OR_COMMITTED | USER_OR_GUARD), PteKind::Guard);
        assert_eq!(
            classify(WRITE_OR_COMMITTED | USER_OR_GUARD | OTHER),
            PteKind::Guard,
            "the guard flag wins over a named frame"
        );
        assert_eq!(
            decode(WRITE_OR_COMMITTED | OTHER),
            Some((PteKind::Transition, OTHER, PAGE_NOACCESS))
        );
        assert_eq!(
            decode(WRITE_OR_COMMITTED | (2 << INDEX_SHIFT)),
            Some((PteKind::DemandZero, 0, PAGE_READWRITE))
        );
        // All three keep the commit charge.
        for entry in [
            WRITE_OR_COMMITTED,
            WRITE_OR_COMMITTED | OTHER,
            WRITE_OR_COMMITTED | USER_OR_GUARD,
        ] {
            assert!(committed(entry));
        }
        assert!(committed(encode(PteKind::Present, FRAME, PAGE_READONLY)));
        assert!(!committed(0));
        assert!(!committed(1 << 5), "stray software bits are not a commit");
    }

    /// The zero entry and the reserved bits: an entry without the committed marker is
    /// uncommitted however its other bits read, the encoder keeps bits 3-8 clear, and a present
    /// entry wins over the marker in the shared bit.
    #[test]
    fn zero_entry_and_reserved_bit_edges() {
        assert_eq!(classify(0), PteKind::Uncommitted);
        assert_eq!(decode(0), None);
        assert_eq!(
            classify(FRAME),
            PteKind::Uncommitted,
            "a frame alone names nothing"
        );
        assert_eq!(classify(1 << 5), PteKind::Uncommitted);
        assert_eq!(classify(1 << 8), PteKind::Uncommitted);
        // Reserved bits do not change a kind.
        assert_eq!(classify(WRITE_OR_COMMITTED | (1 << 5)), PteKind::DemandZero);
        assert_eq!(classify(FRAME | PRESENT | (1 << 6)), PteKind::Present);
        // The encoder never sets them.
        for &(kind, frame, protect) in CASES {
            assert_eq!(encode(kind, frame, protect) & RESERVED, 0, "{kind:?}");
        }
        // Bit 0 decides: a present entry is present even with bit 1 set too.
        assert_eq!(
            classify(FRAME | PRESENT | WRITE_OR_COMMITTED),
            PteKind::Present
        );
    }

    /// Entries written before the protection was recorded: a present entry with protection
    /// index 0 reads as read-write when the write bit is set, read-only otherwise.
    #[test]
    fn an_unrecorded_protection_reads_from_the_write_bit() {
        assert_eq!(
            decode(FRAME | PRESENT | USER_OR_GUARD | WRITE_OR_COMMITTED),
            Some((PteKind::Present, FRAME, PAGE_READWRITE))
        );
        assert_eq!(
            decode(FRAME | PRESENT | USER_OR_GUARD),
            Some((PteKind::Present, FRAME, PAGE_READONLY))
        );
    }

    /// A demand-zero page takes no frame: the encoder refuses one.
    #[test]
    #[should_panic]
    fn demand_zero_takes_no_frame() {
        encode(PteKind::DemandZero, FRAME, PAGE_READWRITE);
    }

    /// A transition page names a frame: the encoder refuses none.
    #[test]
    #[should_panic]
    fn transition_names_a_frame() {
        encode(PteKind::Transition, 0, PAGE_READWRITE);
    }

    /// A present page is not held copy-on-write: the encoder refuses the mix.
    #[test]
    #[should_panic]
    fn a_present_page_is_not_copy_on_write() {
        encode(PteKind::Present, FRAME, PAGE_WRITECOPY);
    }
}
