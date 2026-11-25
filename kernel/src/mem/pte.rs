//! Page-table entries: the one place their format is written down, for the processor's entries and
//! for the states the address-space manager keeps in a user page's entry.
//!
//! **The hardware's bits** (32-bit paging, one word per entry): bit 0 present, bit 1 writable, bit
//! 2 user, bit 3 [`CACHE_DISABLE`], bit 5 accessed, bit 6 dirty, bit 8 global, bits 12-31 the
//! frame's physical address ([`FRAME_MASK`]). [`Pte`] builds and reads the kernel's own directory
//! and table entries from them; every other reader and writer of an entry takes its bits from here.
//!
//! **A user page's entry** ([`classify`], [`encode`], [`decode`]): bit 0 is present; bit 1 is the
//! write bit on a present entry and the committed marker ([`COMMITTED`]) on a non-present one; bit
//! 2 is the user bit on a present entry and the guard flag ([`GUARD`]) on a non-present one; bits
//! 9-11 hold the protection index ([`protection_index`]); bits 12-31 hold the frame's physical
//! address. A non-present entry is one the processor ignores, so its free bits 3-5 name where the
//! page is ([`TRANSITION`], [`PROTOTYPE`], [`PAGE_FILE`]): a soft entry ([`encode_backing`]), whose
//! payload in bits 12-31 is a frame, a section page's index or a paging-file slot. Bits 3-8 of an
//! entry without a tag stay clear, and [`classify`] ignores them.
//!
//! PAE (64-bit entries, frame bits 12-35) changes this module and [`super::phys`]'s width, and the
//! self-map arithmetic in [`super::paging::self_map`]; nothing else spells an entry's layout out.
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

// The kind-based encode/decode is pure and host-tested: the address-space manager's own
// (`vm::encode`/`vm::decode`) swaps over to it when the demand-paging slices land. The hardware
// bits and the soft-entry API below are the target's.
#![cfg_attr(not(test), allow(dead_code))]

use super::phys::PhysAddr;
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

// --- The hardware's bits ---------------------------------------------------------------------

/// Bit 0: the entry maps its frame (or, in a directory, its page table) now.
pub const PRESENT: u32 = 1 << 0;
/// Bit 1: the hardware may write through the entry.
pub const WRITE: u32 = 1 << 1;
/// Bit 2: ring 3 may reach the page (supervisor-only when clear).
pub const USER: u32 = 1 << 2;
/// Bit 3, set on device memory (the display's framebuffer, an uncached MMIO range) so its writes
/// reach the device. The processor's manual names bit 3 PWT (write-through) and bit 4 PCD (cache
/// disable); F2K sets bit 3 alone, as it always has.
pub const CACHE_DISABLE: u32 = 1 << 3;
/// Bit 5: the processor has read through the entry.
pub const ACCESSED: u32 = 1 << 5;
/// Bit 6: the processor has written the page (a table entry's; a directory entry's is ignored).
/// A writable page with it clear is clean: its frame's contents are the page's only copy, so the
/// frame may go to standby without a page-out.
pub const DIRTY: u32 = 1 << 6;
/// Bit 8: the translation survives a CR3 reload. No F2K entry sets it.
pub const GLOBAL: u32 = 1 << 8;
/// Bits 12-31: the frame's physical address (or a soft entry's payload).
pub const FRAME_MASK: u32 = 0xFFFF_F000;
/// The payload field's shift: a soft entry's slot or index sits this far up.
pub const FRAME_SHIFT: u32 = super::phys::PAGE_SHIFT;

/// The frame field of `entry`, raw: the frame's physical address, or a soft entry's payload.
pub const fn frame_bits(entry: u32) -> u32 {
    entry & FRAME_MASK
}

/// A page-directory or page-table entry, as the processor reads it: the frame (or page table) it
/// names and its flag bits.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Pte(u32);

impl Pte {
    /// The entry that maps nothing.
    pub const EMPTY: Pte = Pte(0);

    /// The entry whose bits are `raw`, as the processor reads them.
    pub const fn from_raw(raw: u32) -> Pte {
        Pte(raw)
    }

    /// The entry's bits, as the processor reads them.
    pub const fn raw(self) -> u32 {
        self.0
    }

    /// An entry for `frame` with the flag bits `flags`.
    pub const fn new(frame: PhysAddr, flags: u32) -> Pte {
        Pte(frame.get() & FRAME_MASK | flags & !FRAME_MASK)
    }

    /// Whether the entry maps anything.
    pub const fn present(self) -> bool {
        self.0 & PRESENT != 0
    }

    /// Whether the hardware may write through the entry.
    pub const fn writable(self) -> bool {
        self.0 & WRITE != 0
    }

    /// Whether ring 3 may reach the page.
    pub const fn user(self) -> bool {
        self.0 & USER != 0
    }

    /// Whether the page's caches are disabled ([`CACHE_DISABLE`]).
    pub const fn cache_disabled(self) -> bool {
        self.0 & CACHE_DISABLE != 0
    }

    /// Whether the processor has read through the entry.
    pub const fn accessed(self) -> bool {
        self.0 & ACCESSED != 0
    }

    /// Whether the processor has written the page.
    pub const fn dirty(self) -> bool {
        self.0 & DIRTY != 0
    }

    /// Whether the translation survives a CR3 reload.
    pub const fn global(self) -> bool {
        self.0 & GLOBAL != 0
    }

    /// The frame (or page table) the entry names, present or not.
    pub const fn frame(self) -> PhysAddr {
        PhysAddr::new(frame_bits(self.0))
    }

    /// A present, writable, supervisor-only entry for `frame`: the kernel's own pages and tables,
    /// and the runtime access windows' directory entries.
    pub const fn kernel_rw(frame: PhysAddr) -> Pte {
        Pte(frame.get() | PRESENT | WRITE)
    }

    /// A present, writable, supervisor-only, uncached entry for `frame`: device memory such as the
    /// display's framebuffer (see [`CACHE_DISABLE`]).
    pub const fn kernel_rw_uncached(frame: PhysAddr) -> Pte {
        Pte(frame.get() | PRESENT | WRITE | CACHE_DISABLE)
    }

    /// A present entry ring 3 can reach for `frame`, with the further `flags` ([`WRITE`] for a
    /// writable one).
    pub const fn user_page(frame: PhysAddr, flags: u32) -> Pte {
        Pte(frame.get() | PRESENT | USER | flags)
    }
}

// --- A user page's entry: the software's bits -----------------------------------------------

/// A non-present entry's committed marker: bit 1, the write bit's place (the processor ignores a
/// non-present entry's bits).
pub const COMMITTED: u32 = WRITE;
/// A non-present entry's guard flag: bit 2, the user bit's place.
pub const GUARD: u32 = USER;
/// Bit 1: the write bit on a present entry, the committed marker on a non-present one.
const WRITE_OR_COMMITTED: u32 = WRITE;
/// Bit 2: the user bit on a present entry, the guard flag on a non-present one.
const USER_OR_GUARD: u32 = USER;
/// Bits 3-8: kept clear by [`encode`] and ignored by [`classify`]; a soft entry's tags sit in 3-5.
const RESERVED: u32 = 0x1F8;
/// Bits 9-11: the protection index's place.
pub const INDEX_SHIFT: u32 = 9;
/// The protection index's width, as a mask once shifted down.
pub const INDEX_MASK: u32 = 7;

/// A non-present entry naming a frame on a backing list: the page is in memory still, off its
/// working set, and making it present again takes no I/O. The frame rides in bits 12-31.
pub const TRANSITION: u32 = 1 << 3;
/// A non-present entry naming a page of a section, its slot in the section's frame table (bits
/// 12-31): the page comes in from the section — its file, or a copy-on-write sever of a shared
/// frame — not from private memory.
pub const PROTOTYPE: u32 = 1 << 4;
/// A non-present entry naming a private page's slot in the paging file, counted from one (bits
/// 12-31): the page comes back with a read.
pub const PAGE_FILE: u32 = 1 << 5;
/// All the backing tags.
pub const SOFT_TAGS: u32 = TRANSITION | PROTOTYPE | PAGE_FILE;

/// The protection index an entry's bits 9-11 record for a base protection (1-7, 0 no-access).
pub const fn protection_index(base: u32) -> u32 {
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
pub const fn protection_of_index(index: u32) -> u32 {
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

/// The protection index `entry` records in its bits 9-11.
pub const fn index_bits(entry: u32) -> u32 {
    (entry >> INDEX_SHIFT) & INDEX_MASK
}

/// The entry's backing tag: one of [`TRANSITION`], [`PROTOTYPE`] and [`PAGE_FILE`], or zero for a
/// hard (present, committed or uncommitted) entry. On a present entry bits 3-5 are the hardware's
/// cache and accessed bits, not a tag, so the tags read only on a non-present one — a soft entry is
/// never present.
pub const fn backing_tag(entry: u32) -> u32 {
    if entry & PRESENT != 0 {
        0
    } else {
        entry & SOFT_TAGS
    }
}

/// A soft entry's payload (bits 12-31): the named frame, or the paging-file slot / section page
/// index shifted up into the field.
pub const fn backing_payload(entry: u32) -> u32 {
    frame_bits(entry)
}

/// The base protection a soft entry records in its protection index bits.
pub const fn soft_protect(entry: u32) -> u32 {
    protection_of_index(index_bits(entry))
}

/// The soft entry for a page backed by `tag` with `payload` (a frame, or a slot/index shifted up)
/// and `protect`: the processor ignores a non-present entry's bits, so they carry the page's state.
pub fn encode_backing(tag: u32, payload: u32, protect: u32) -> u32 {
    debug_assert!(tag != 0 && tag & !SOFT_TAGS == 0, "one backing tag");
    debug_assert!(payload & !FRAME_MASK == 0, "the payload is page-aligned");
    tag | payload | (protection_index(protect & 0xFF) << INDEX_SHIFT)
}

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
        match index_bits(entry) {
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
    let index = protection_index(base) << INDEX_SHIFT;
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
    let index = index_bits(entry);
    let protect = match kind {
        // A present entry written before the protection was recorded carries index 0: it reads
        // as read-write when the write bit is set, read-only otherwise.
        PteKind::Present => match index {
            0 if entry & WRITE_OR_COMMITTED != 0 => PAGE_READWRITE,
            0 => PAGE_READONLY,
            index => protection_of_index(index),
        },
        PteKind::CopyOnWrite => protection_of_index(index),
        PteKind::Guard => protection_of_index(index) | PAGE_GUARD,
        PteKind::DemandZero | PteKind::Transition => protection_of_index(index),
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

/// Whether a base protection lets the hardware write: a copy-on-write page does not, its first
/// write faulting into the copy.
fn base_writable(base: u32) -> bool {
    matches!(base, PAGE_READWRITE | PAGE_EXECUTE_READWRITE)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The hardware's bits sit where the processor's manual puts them (32-bit paging).
    #[test]
    fn the_hardware_bits_are_the_processors() {
        assert_eq!(PRESENT, 1);
        assert_eq!(WRITE, 1 << 1);
        assert_eq!(USER, 1 << 2);
        assert_eq!(
            CACHE_DISABLE,
            1 << 3,
            "set as F2K always has: the manual's PWT"
        );
        assert_eq!(ACCESSED, 1 << 5);
        assert_eq!(DIRTY, 1 << 6);
        assert_eq!(GLOBAL, 1 << 8);
        assert_eq!(FRAME_MASK, 0xFFFF_F000);
        assert_eq!(1 << FRAME_SHIFT, 4096);
        // The software's bits fold onto them: the markers on the write and user bits, the tags
        // on 3-5, the protection index on 9-11 — none on the frame field.
        assert_eq!((COMMITTED, GUARD), (WRITE, USER));
        assert_eq!(SOFT_TAGS, 0x38);
        assert_eq!(INDEX_MASK << INDEX_SHIFT, 0xE00);
        assert_eq!((SOFT_TAGS | INDEX_MASK << INDEX_SHIFT) & FRAME_MASK, 0);
    }

    /// Every field of an entry reads back as it was set, alone and together, and the frame
    /// field holds any frame of the 32-bit space whatever the flags.
    #[test]
    fn every_field_of_an_entry_round_trips() {
        type Read = fn(Pte) -> bool;
        let fields: [(u32, Read); 7] = [
            (PRESENT, Pte::present),
            (WRITE, Pte::writable),
            (USER, Pte::user),
            (CACHE_DISABLE, Pte::cache_disabled),
            (ACCESSED, Pte::accessed),
            (DIRTY, Pte::dirty),
            (GLOBAL, Pte::global),
        ];
        for frame in [0, 0x1000, 0x0090_0000, 0xFFFF_F000] {
            let frame = PhysAddr::new(frame);
            for set in 0..1u32 << fields.len() {
                let flags = fields
                    .iter()
                    .enumerate()
                    .filter(|&(i, _)| set & 1 << i != 0)
                    .fold(0, |flags, (_, &(bit, _))| flags | bit);
                let entry = Pte::new(frame, flags);
                assert_eq!(entry.frame(), frame);
                assert_eq!(entry.raw(), frame.get() | flags);
                assert_eq!(Pte::from_raw(entry.raw()), entry);
                for (i, &(_, read)) in fields.iter().enumerate() {
                    assert_eq!(read(entry), set & 1 << i != 0, "field {i} of {flags:#x}");
                }
            }
        }
        // The constructors are those fields.
        let frame = PhysAddr::new(0x0090_0000);
        assert_eq!(Pte::kernel_rw(frame), Pte::new(frame, PRESENT | WRITE));
        assert_eq!(
            Pte::kernel_rw_uncached(frame),
            Pte::new(frame, PRESENT | WRITE | CACHE_DISABLE)
        );
        assert_eq!(Pte::user_page(frame, 0), Pte::new(frame, PRESENT | USER));
        assert_eq!(
            Pte::user_page(frame, WRITE),
            Pte::new(frame, PRESENT | USER | WRITE)
        );
        assert_eq!(Pte::EMPTY.raw(), 0);
        assert_eq!(frame_bits(0x0090_0FFF), 0x0090_0000);
    }

    /// Every protection index round trips through its base protection, and an entry's index
    /// bits read back whatever else the entry holds.
    #[test]
    fn protection_indexes_round_trip() {
        for index in 1..=INDEX_MASK {
            assert_eq!(protection_index(protection_of_index(index)), index);
            let entry = FRAME_MASK | SOFT_TAGS | PRESENT | WRITE | USER | index << INDEX_SHIFT;
            assert_eq!(index_bits(entry), index);
        }
        assert_eq!(protection_of_index(0), PAGE_NOACCESS);
        assert_eq!(protection_index(PAGE_NOACCESS), 0);
    }

    /// A soft entry gives back its tag, its payload and its protection, and is never present;
    /// a present entry's bits 3-5 are no tag.
    #[test]
    fn soft_entries_round_trip() {
        for tag in [TRANSITION, PROTOTYPE, PAGE_FILE] {
            for payload in [0, 0x1000, 7 << FRAME_SHIFT, 0xFFFF_F000] {
                for protect in [PAGE_READONLY, PAGE_READWRITE, PAGE_EXECUTE_WRITECOPY] {
                    let entry = encode_backing(tag, payload, protect);
                    assert_eq!(backing_tag(entry), tag);
                    assert_eq!(backing_payload(entry), payload);
                    assert_eq!(soft_protect(entry), protect);
                    assert_eq!(entry & PRESENT, 0);
                }
            }
        }
        assert_eq!(backing_tag(PRESENT | ACCESSED | CACHE_DISABLE), 0);
        assert_eq!(backing_tag(COMMITTED), 0);
    }

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
