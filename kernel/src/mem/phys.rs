//! Physical memory's two coordinates: a frame's number ([`Pfn`]) and a byte's physical address
//! ([`PhysAddr`]), each its own type so the two never mix, and the one conversion between them.
//!
//! Both are [`PhysWord`] wide. 32-bit paging reaches 4 GiB of physical memory, so that is `u32`
//! today: a frame number takes 20 bits, an address 32. PAE (Windows 2000's ntkrnlpa) reaches 64
//! GiB through 36-bit addresses held in 64-bit entries; adding it widens [`PhysWord`] here, the one
//! place that says how wide a physical address is, and the compiler then names every caller that
//! narrows one. Code that hands an address to a device keeps its own explicit width check (the DMA
//! layer's below-4 GiB constraint, [`crate::mem::dma`]), whatever this width is.
//!
//! **Where PAE stands.** Every physical address the kernel keeps is a [`PhysAddr`] or a [`Pfn`]:
//! process directories (the scheduler's `dir_phys`), gate-stack frames, the address-space
//! manager's frames ([`crate::mem::vm::Pages`]) and a section's frame tables (a page of
//! [`PhysWord`]s, [`crate::mem::vm::TABLE_SLOTS`] of them), MMIO reservations, the RAM disk's
//! module, the framebuffer. Every page-table entry is a [`crate::mem::pte::EntryWord`], and the
//! frame field converts to and from an address only in [`crate::mem::pte`]. Widening the two words
//! to `u64` is then a type change; what stops compiling is what needs a decision.
//!
//! u32 by design, whatever the mode: virtual addresses (a 32-bit address space either way); CR3
//! ([`crate::mem::paging::directory_cr3`]: a 32-bit register, which under PAE holds the
//! directory-pointer table's address below 4 GiB); bus addresses a device takes in 32 bits (the
//! DMA layer checks them, its own width being `u64`); the boot hand-off — the Multiboot 1
//! structure and its module and memory records (`crate::mem::multiboot`, `boot::cmdline`), the VBE
//! mode block's framebuffer field, the real-mode trampoline below 1 MiB — whose formats are 32-bit
//! (the HAL plan's Multiboot 2 / UEFI hand-off replaces them, and a framebuffer above 4 GiB arrives
//! that way).
//!
//! What a PAE mode still needs: the page-directory-pointer table (four entries, 32-byte aligned,
//! below 4 GiB, what CR3 names) and CR4.PAE; three-level walks with 512 entries per table and 2 MiB
//! per directory entry ([`crate::mem::paging`]'s geometry derives its entry count from
//! `EntryWord`, but the window span, `directory_index` and the walks are 32-bit paging's); the
//! self-map grown to 8 MiB (four directory entries, one per directory page) and the windows laid
//! out around it ([`crate::mem::layout`]); a frame database sized for frames past 4 GiB; and the
//! context switch's directory load (it reads `dir_phys` as one 32-bit word,
//! `crate::sched::switch`).

use core::fmt;
use core::ops::{Add, Range, Sub};

/// The width of a physical address and of a frame number: the one place to widen for PAE.
pub type PhysWord = u32;

/// log2 of the page size: a frame's number is its address shifted down by this.
pub const PAGE_SHIFT: u32 = 12;

/// The page size, in the physical width.
const PAGE_BYTES: PhysWord = 1 << PAGE_SHIFT;

/// A physical frame's number: its address over the page size. Frame 0 is reserved and never
/// allocated.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Pfn(PhysWord);

impl Pfn {
    /// Frame 0: reserved, never allocated (a list link's "none").
    pub const ZERO: Pfn = Pfn(0);

    /// Frame number `number`.
    pub const fn new(number: PhysWord) -> Pfn {
        Pfn(number)
    }

    /// The frame's number.
    pub const fn get(self) -> PhysWord {
        self.0
    }

    /// The frame's number as an index (into the frame database, or a per-frame table).
    pub const fn index(self) -> usize {
        self.0 as usize
    }

    /// The frame's first byte.
    pub const fn addr(self) -> PhysAddr {
        PhysAddr(self.0 << PAGE_SHIFT)
    }

    /// The frame `count` frames past this one.
    pub const fn plus(self, count: PhysWord) -> Pfn {
        Pfn(self.0 + count)
    }
}

impl Add<PhysWord> for Pfn {
    type Output = Pfn;

    fn add(self, count: PhysWord) -> Pfn {
        self.plus(count)
    }
}

impl Sub<PhysWord> for Pfn {
    type Output = Pfn;

    fn sub(self, count: PhysWord) -> Pfn {
        Pfn(self.0 - count)
    }
}

/// The frames from one to another: how many lie between them.
impl Sub for Pfn {
    type Output = PhysWord;

    fn sub(self, other: Pfn) -> PhysWord {
        self.0 - other.0
    }
}

impl From<Pfn> for u64 {
    fn from(frame: Pfn) -> u64 {
        u64::from(frame.0)
    }
}

impl fmt::Debug for Pfn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Pfn({:#x})", self.0)
    }
}

/// The frames of `run`, in order (a range of frame numbers does not iterate by itself).
pub fn frames(run: Range<Pfn>) -> impl DoubleEndedIterator<Item = Pfn> + Clone {
    (run.start.0..run.end.0).map(Pfn)
}

/// The frame numbers `run` names, as frames: the tests' shorthand.
#[cfg(test)]
pub const fn frame_run(run: Range<PhysWord>) -> Range<Pfn> {
    Pfn(run.start)..Pfn(run.end)
}

/// A byte's physical address.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct PhysAddr(PhysWord);

impl PhysAddr {
    /// Physical address 0.
    pub const ZERO: PhysAddr = PhysAddr(0);

    /// Physical address `address`.
    pub const fn new(address: PhysWord) -> PhysAddr {
        PhysAddr(address)
    }

    /// The address's bits.
    pub const fn get(self) -> PhysWord {
        self.0
    }

    /// The address, widened: what a bus address is compared against.
    pub const fn as_u64(self) -> u64 {
        self.0 as u64
    }

    /// The frame holding the byte.
    pub const fn pfn(self) -> Pfn {
        Pfn(self.0 >> PAGE_SHIFT)
    }

    /// The byte's offset in its frame.
    pub const fn page_offset(self) -> PhysWord {
        self.0 & (PAGE_BYTES - 1)
    }

    /// Whether the address is a frame's first byte.
    pub const fn is_page_aligned(self) -> bool {
        self.page_offset() == 0
    }

    /// The address `bytes` past this one.
    pub const fn plus(self, bytes: PhysWord) -> PhysAddr {
        PhysAddr(self.0 + bytes)
    }
}

impl Add<PhysWord> for PhysAddr {
    type Output = PhysAddr;

    fn add(self, bytes: PhysWord) -> PhysAddr {
        self.plus(bytes)
    }
}

/// The bytes from one address to another.
impl Sub for PhysAddr {
    type Output = PhysWord;

    fn sub(self, other: PhysAddr) -> PhysWord {
        self.0 - other.0
    }
}

impl fmt::Debug for PhysAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PhysAddr({:#010x})", self.0)
    }
}

impl fmt::LowerHex for PhysAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::LowerHex::fmt(&self.0, f)
    }
}

impl fmt::LowerHex for Pfn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::LowerHex::fmt(&self.0, f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Both types are their word and no more: a field of either lays out as the raw word did (the
    /// context switch reads a directory's address at a fixed offset).
    #[test]
    fn both_are_one_word_wide() {
        assert_eq!(
            core::mem::size_of::<Pfn>(),
            core::mem::size_of::<PhysWord>()
        );
        assert_eq!(
            core::mem::size_of::<PhysAddr>(),
            core::mem::size_of::<PhysWord>()
        );
        assert_eq!(PAGE_BYTES, 4096);
    }

    /// A frame's address and back: every frame of the 32-bit space round trips, and an address
    /// inside a frame names that frame and its offset.
    #[test]
    fn frames_and_addresses_round_trip() {
        for number in [0, 1, 0x90, 0x400, 0x3_0000, 0xF_FFFF] {
            let frame = Pfn::new(number);
            assert_eq!(frame.get(), number);
            assert_eq!(frame.index(), number as usize);
            assert_eq!(frame.addr().get(), number * 4096);
            assert!(frame.addr().is_page_aligned());
            assert_eq!(frame.addr().pfn(), frame);
            let inside = frame.addr().plus(0x123);
            assert_eq!(inside.pfn(), frame);
            assert_eq!(inside.page_offset(), 0x123);
            assert!(!inside.is_page_aligned());
        }
        assert_eq!(Pfn::new(0xF_FFFF).addr(), PhysAddr::new(0xFFFF_F000));
        assert_eq!(PhysAddr::new(0xFFFF_FFFF).pfn(), Pfn::new(0xF_FFFF));
        assert_eq!(PhysAddr::new(0xFFFF_FFFF).as_u64(), 0xFFFF_FFFF);
    }

    /// Counting between frames and stepping by counts.
    #[test]
    fn frame_arithmetic_counts_frames() {
        let start = Pfn::new(0x100);
        assert_eq!(start + 5, Pfn::new(0x105));
        assert_eq!(start.plus(5), Pfn::new(0x105));
        assert_eq!(start - 1, Pfn::new(0xFF));
        assert_eq!(Pfn::new(0x105) - start, 5);
        assert_eq!(u64::from(Pfn::new(0xF_FFFF)), 0xF_FFFF);
        assert_eq!(PhysAddr::new(0x5000) - PhysAddr::new(0x3000), 0x2000);
        assert_eq!(PhysAddr::new(0x5000) + 0x10, PhysAddr::new(0x5010));
        let run: Vec<Pfn> = frames(frame_run(3..6)).collect();
        assert_eq!(run, [Pfn::new(3), Pfn::new(4), Pfn::new(5)]);
        assert_eq!(frames(frame_run(6..6)).count(), 0);
        assert_eq!(frames(frame_run(3..6)).rev().next(), Some(Pfn::new(5)));
    }

    /// Debug and hex output name the type and the value.
    #[test]
    fn they_print_as_hex() {
        assert_eq!(format!("{:?}", Pfn::new(0x90)), "Pfn(0x90)");
        assert_eq!(
            format!("{:?}", PhysAddr::new(0x9_0000)),
            "PhysAddr(0x00090000)"
        );
        assert_eq!(format!("{:#x}", PhysAddr::new(0x9_0000)), "0x90000");
        assert_eq!(format!("{:x}", Pfn::new(0x90)), "90");
    }
}
