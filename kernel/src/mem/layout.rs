//! The kernel half's layout: every region of `[0x80000000, 4 GiB)` the kernel maps, in one place.
//!
//! Each region is a run of whole page-directory entries (4 MiB windows), so a region owns its page
//! tables outright and no two regions ever share one. Where F2K keeps the same thing Windows 2000
//! does, it keeps it at Windows 2000's address (the x86 system space as Windows 2000 lays it out
//! without the /3GB switch):
//!
//! | Region             | Address      | Entries   | Windows 2000 there                        |
//! |--------------------|--------------|-----------|-------------------------------------------|
//! | [`KERNEL_IMAGE`]   | `0x80000000` | 512-515   | system code (the kernel, the HAL)         |
//! | [`KERNEL_STACKS`]  | `0xA4000000` | 656-659   | additional system PTEs                    |
//! | [`PAGE_TABLES`]    | `0xC0000000` | 768       | the process page tables (self-map)        |
//! | [`HYPERSPACE`]     | `0xC0400000` | 769       | hyperspace                                |
//! | [`SHARED_DATA`]    | `0xFFC00000` | 1023      | HAL usage (the shared data page's view)   |
//!
//! The kernel image window is the only region mapped from the first instruction on: the boot stub
//! maps it over physical `[0, 16 MiB)`, and the kernel image (loaded at physical 1 MiB: its code
//! and every fixed-size table, the frame table and the process pool among them) must end inside it
//! (the linker script and the boot both check). The other regions get their tables at runtime.
//!
//! Kernel stacks sit in a region of their own, as Windows 2000's do: it takes them from its system
//! PTEs, the pool of kernel address space for mappings that come and go, and its published x86 map
//! places a range of those ("additional system PTEs") at `0xA4000000`, between session space and
//! the page tables. F2K's region takes the start of that range. It is sized for every thread record
//! ([`crate::ob::THREADS`]) at the slot stride of a 32 KiB stack plus its guard page (36 KiB: 4.5
//! MiB, two entries), with as much again to grow into: four entries, 16 MiB. It sits far from the
//! image window, so the image can keep growing without meeting it.

/// One page-directory entry's span: the 4 MiB a page table maps.
pub const ENTRY_SPAN: u32 = 0x0040_0000;

/// A run of whole page-directory entries in the kernel half: `entries` windows of [`ENTRY_SPAN`]
/// from `start`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Region {
    /// The first address, on a directory-entry boundary.
    pub start: u32,
    /// How many directory entries the region spans.
    pub entries: usize,
}

impl Region {
    /// The region's first directory entry.
    pub const fn first_entry(self) -> usize {
        (self.start / ENTRY_SPAN) as usize
    }

    /// The directory entry just past the region.
    pub const fn end_entry(self) -> usize {
        self.first_entry() + self.entries
    }

    /// The region's size in bytes.
    pub const fn size(self) -> u32 {
        self.entries as u32 * ENTRY_SPAN
    }

    /// The address just past the region (a region may end at 4 GiB, hence the width).
    pub const fn end(self) -> u64 {
        self.start as u64 + self.size() as u64
    }

    /// Whether directory entry `entry` belongs to the region.
    pub const fn holds_entry(self, entry: usize) -> bool {
        entry >= self.first_entry() && entry < self.end_entry()
    }

    /// Whether `address` lies inside the region.
    pub const fn holds(self, address: u32) -> bool {
        address >= self.start && (address as u64) < self.end()
    }
}

/// The kernel image window: the image (the entry stub, code, statics, the boot stack) and the rest
/// of physical `[0, 16 MiB)` (the VGA text page among it), mapped by the boot tables at a fixed
/// offset (virtual = physical + `0x80000000`). Shared by every address space.
pub const KERNEL_IMAGE: Region = Region {
    start: 0x8000_0000,
    entries: 4,
};

/// The kernel stacks: each thread's ring-0 stack, a guard page below every one. Each process maps
/// its own threads' stacks at the region's start, in a table of its own.
pub const KERNEL_STACKS: Region = Region {
    start: 0xA400_0000,
    entries: 4,
};

/// The page tables: the directory maps itself here, so the current directory's page tables (and the
/// directory itself) are reachable at fixed addresses.
pub const PAGE_TABLES: Region = Region {
    start: 0xC000_0000,
    entries: 1,
};

/// Hyperspace: the scratch window, where the kernel aliases whichever frame it is initializing or
/// reading, one at a time.
pub const HYPERSPACE: Region = Region {
    start: 0xC040_0000,
    entries: 1,
};

/// The kernel's view of the shared data page (KUSER_SHARED_DATA) at `0xFFDF0000`, Windows 2000's
/// address for it, in the table of the last directory entry.
pub const SHARED_DATA: Region = Region {
    start: 0xFFC0_0000,
    entries: 1,
};

// Checked whenever the kernel builds, not by the host tests alone: the addresses other modules fix
// lie in their regions, and the stack region stays clear of the image window's growth.
const _: () = {
    assert!(SHARED_DATA.holds(crate::user::shared::KERNEL_ADDRESS));
    assert!(KERNEL_STACKS.start as u64 >= KERNEL_IMAGE.end());
};

#[cfg(test)]
mod tests {
    use super::*;

    const REGIONS: [(&str, Region); 5] = [
        ("kernel image", KERNEL_IMAGE),
        ("kernel stacks", KERNEL_STACKS),
        ("page tables", PAGE_TABLES),
        ("hyperspace", HYPERSPACE),
        ("shared data", SHARED_DATA),
    ];

    /// Every region sits where the module doc says, on directory-entry boundaries, in the kernel
    /// half.
    #[test]
    fn regions_sit_where_stated() {
        assert_eq!(
            (KERNEL_IMAGE.first_entry(), KERNEL_IMAGE.end_entry()),
            (512, 516)
        );
        assert_eq!(KERNEL_IMAGE.end(), 0x8100_0000);
        assert_eq!(
            (KERNEL_STACKS.first_entry(), KERNEL_STACKS.end_entry()),
            (656, 660)
        );
        assert_eq!(KERNEL_STACKS.end(), 0xA500_0000);
        assert_eq!(PAGE_TABLES.first_entry(), 768);
        assert_eq!(HYPERSPACE.first_entry(), 769);
        assert_eq!(SHARED_DATA.first_entry(), 1023);
        assert_eq!(SHARED_DATA.end(), 0x1_0000_0000);
        for (name, region) in REGIONS {
            assert_eq!(region.start % ENTRY_SPAN, 0, "{name} is not entry-aligned");
            assert!(
                region.start >= KERNEL_IMAGE.start,
                "{name} is below the kernel half"
            );
            assert!(region.entries > 0, "{name} is empty");
            assert!(region.end_entry() <= 1024, "{name} runs past 4 GiB");
        }
    }

    /// No two regions share a directory entry (and so never a page table).
    #[test]
    fn regions_do_not_overlap() {
        for (i, (a_name, a)) in REGIONS.iter().enumerate() {
            for (b_name, b) in &REGIONS[i + 1..] {
                for entry in a.first_entry()..a.end_entry() {
                    assert!(
                        !b.holds_entry(entry),
                        "{a_name} and {b_name} share entry {entry}"
                    );
                }
            }
        }
    }

    /// The image window maps physical `[0, 16 MiB)`: the kernel's load address and the VGA text
    /// page lie inside it.
    #[test]
    fn the_image_window_covers_the_load_address() {
        assert_eq!(KERNEL_IMAGE.size(), 16 * 0x10_0000);
        assert!(KERNEL_IMAGE.holds(KERNEL_IMAGE.start + crate::mem::paging::KERNEL_PHYS_BASE));
        assert!(KERNEL_IMAGE.holds(crate::hw::vga::VIRT_BASE));
    }

    /// The stack region holds a slot for every thread record at today's stride, with room to
    /// spare, and stays clear of the image window above which the image grows.
    #[test]
    fn the_stack_region_holds_every_thread_record() {
        let stride = crate::mem::paging::GATE_SLOT_STRIDE;
        let needed = crate::ob::THREADS as u32 * stride;
        assert!(
            needed > ENTRY_SPAN,
            "one entry would do: revisit the region's size"
        );
        assert!(needed <= 2 * ENTRY_SPAN);
        assert!(KERNEL_STACKS.size() / stride >= 2 * crate::ob::THREADS as u32);
        assert!(KERNEL_STACKS.start as u64 > KERNEL_IMAGE.end());
        assert!(KERNEL_STACKS.end() <= PAGE_TABLES.start as u64);
    }

    /// The shared data page's kernel view lies in its region.
    #[test]
    fn the_shared_data_view_lies_in_its_region() {
        assert!(SHARED_DATA.holds(crate::user::shared::KERNEL_ADDRESS));
        assert!(!SHARED_DATA.holds(0xFFBF_F000));
        assert!(SHARED_DATA.holds(0xFFFF_F000));
    }

    #[test]
    fn region_bounds_are_exclusive() {
        assert!(KERNEL_IMAGE.holds(0x80FF_FFFF));
        assert!(!KERNEL_IMAGE.holds(0x8100_0000));
        assert!(!KERNEL_IMAGE.holds(0x7FFF_FFFF));
        assert!(KERNEL_IMAGE.holds_entry(515) && !KERNEL_IMAGE.holds_entry(516));
    }
}
