//! The kernel half's layout: every region of `[0x80000000, 4 GiB)` the kernel maps, in one place.
//!
//! Each region is a run of whole page-directory entries (4 MiB windows), so a region owns its page
//! tables outright and no two regions ever share one. Where F2K keeps the same thing Windows 2000
//! does, it keeps it at Windows 2000's address (the x86 system space as Windows 2000 lays it out
//! without the /3GB switch):
//!
//! | Region              | Address      | Entries  | Windows 2000 there                         |
//! |---------------------|--------------|----------|--------------------------------------------|
//! | [`KERNEL_IMAGE`]    | `0x80000000` | 512-515  | system code (the kernel, the HAL)          |
//! | [`KERNEL_STACKS`]   | `0xA4000000` | 656-767  | additional system PTEs                     |
//! | [`PAGE_TABLES`]     | `0xC0000000` | 768      | the process page tables (self-map)         |
//! | [`HYPERSPACE`]      | `0xC0400000` | 769      | hyperspace                                 |
//! | [`FRAMEBUFFER`]     | `0xC0800000` | 770-777  | the display's linear framebuffer           |
//! | [`MMIO`]            | `0xC2800000` | 778-793  | device MMIO mappings (MmMapIoSpace)        |
//! | [`MODULES`]         | `0xC6800000` | 794-825  | loaded driver images (the .sys loader)     |
//! | [`DIRECTORY_LINKS`] | `0xCE800000` | 826-827  | (never mapped: the directory list's links) |
//! | [`FRAME_DATABASE`]  | `0xEDC00000` | 951-958  | nonpaged pool (the PFN database's home)    |
//! | [`NONPAGED_POOL`]   | `0xEFC00000` | 959-1022 | nonpaged pool expansion                    |
//! | [`SHARED_DATA`]     | `0xFFC00000` | 1023     | HAL usage (the shared data page's view)    |
//!
//! The kernel image window is the only region mapped from the first instruction on: the boot
//! loader maps it over physical `[0, 16 MiB)`. Its first directory entry's span, the entry span
//! (`[0x80000000, 0x80400000)`), is the boot's: the first megabyte's firmware areas and the VGA
//! text page, and from 1 MiB the boot loader (`kernel/loader`). The kernel's image, ntoskrnl.exe,
//! sits behind it, at [`NTOSKRNL_BASE`], `0x80400000`, Windows 2000's kernel base (physical 4 MiB):
//! its headers' page, its code and every fixed-size table, the process pool among them, then its
//! export directory and base relocations. It must end inside the window (the linker scripts and
//! the boot loader check). The other regions get their tables at runtime.
//!
//! Kernel stacks sit in a region of their own, as Windows 2000's do: it takes them from its system
//! PTEs, the pool of kernel address space for mappings that come and go, and its published x86 map
//! places a range of those ("additional system PTEs") at `0xA4000000`, between session space and
//! the page tables. F2K's region is that whole range, 112 entries (448 MiB) up to the page tables:
//! 12,743 slots at the stride of a 32 KiB stack plus its guard page (36 KiB). No thread cap hides
//! there: 12,743 stacks would take 398 MiB of frames, more than F2K's 256 MiB of memory, so frames
//! run out first. Its page tables are made on demand, as a stack first reaches a 4 MiB window, and
//! installed in every directory before the stack is handed out ([`crate::mem::ktables`]); a table
//! once made is kept. It sits far from the image window, so the image can keep growing without
//! meeting it.
//!
//! The nonpaged pool: kernel memory that comes and goes with what holds it (a pipe's data queues,
//! the slot pools' chunks), shared by every address space as the kernel stacks are, its frames
//! mapped when a block is taken and given back with it ([`crate::mem::pool`]). Windows 2000 grows
//! its nonpaged pool's expansion down from `0xFFBE0000`, just under the HAL's area, to at most
//! 256 MB on x86; F2K's region is the 64 entries below the shared data page's, 256 MiB. Its page
//! tables are made on demand, as blocks first reach a 4 MiB window, and installed in every
//! directory at once ([`crate::mem::ktables`]); a table once made is kept.
//!
//! [`DIRECTORY_LINKS`] is a region of address space nothing ever maps: its two directory entries
//! hold, in each process directory, the links of the list of live directories (never present, so
//! the processor ignores them), which a new kernel table is installed through.
//!
//! The frame database ([`crate::mem::frame`]), one entry per physical frame, is sized at boot from
//! the memory map and mapped into its own region, [`FRAME_DATABASE`], right below the nonpaged
//! pool's: Windows 2000 builds its PFN database (MmPfnDatabase) at boot the same way, in nonpaged
//! system space, from the loader's memory descriptors. The region is sized for every frame a
//! 32-bit physical address reaches ([`crate::mem::frame::PHYSICAL_FRAME_LIMIT`], 4 GiB: 28 MiB of
//! entries in the region's 32 MiB), and the boot maps only what the machine's memory needs
//! (1.75 MiB for 256 MiB), its page tables made before the boot directory, which carries them
//! ([`crate::mem::bootmem`]).
//!
//! Device MMIO ranges map into their own reserved region, [`MMIO`], right behind the framebuffer's:
//! Windows 2000 takes MmMapIoSpace mappings from its system PTEs wherever they fit; F2K keeps a
//! fixed 64 MiB window (16 entries) for them, page tables made at boot and shared by every address
//! space like the pool's, so a device register range mapped in it ([`crate::mem::dma`]) is
//! reachable from any thread, with the caches disabled for uncached mappings (PCD) as device memory
//! requires.
//!
//! Loaded driver images (the kernel-side `.sys` loader, [`crate::dev::loader`]) map into their own
//! reserved region, [`MODULES`], behind the MMIO region's: Windows 2000 loads drivers into its
//! system PTEs wherever they fit; F2K keeps a fixed 128 MiB window (32 entries) for them, page
//! tables made at boot and shared by every address space, so a loaded module is reachable from any
//! thread. The loader hands the region's pages out lowest free run first.

use super::paging::{PAGE_SIZE, PT_ENTRIES};

/// One page-directory entry's span: the 4 MiB a page table maps, its entries' pages.
pub const ENTRY_SPAN: u32 = PT_ENTRIES as u32 * PAGE_SIZE;

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

/// The kernel image window: the entry span and the kernel's image behind it (code, statics, the
/// boot stack), and the rest of physical `[0, 16 MiB)` (the VGA text page among it), mapped by the
/// boot tables at a fixed offset (virtual = physical + `0x80000000`). Shared by every address
/// space.
pub const KERNEL_IMAGE: Region = Region {
    start: 0x8000_0000,
    entries: 4,
};

/// The kernel's image base, where ntoskrnl.exe is linked and runs: right behind the window's entry
/// span, as Windows 2000's kernel sits at `0x80400000`. The linker script's `__ImageBase`.
pub const NTOSKRNL_BASE: u32 = KERNEL_IMAGE.start + ENTRY_SPAN;

/// The kernel stacks: each thread's ring-0 stack, a guard page below every one, numbered across the
/// region and mapped in every address space ([`crate::mem::kstacks`]). 112 entries, 448 MiB, from
/// Windows 2000's additional system PTEs' start up to the page tables; its page tables are made as
/// stacks first reach each entry's window ([`crate::mem::ktables`]).
pub const KERNEL_STACKS: Region = Region {
    start: 0xA400_0000,
    entries: 112,
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

/// The display's linear framebuffer (the VBE mode's LFB), mapped when the graphics mode is set.
/// Its page tables are made at boot like the pool's, so every address space shares them; the frames
/// are filled from the mode information, never assumed. Eight entries: 32 MiB of video memory.
pub const FRAMEBUFFER: Region = Region {
    start: 0xC080_0000,
    entries: 8,
};

/// Device MMIO mappings (MmMapIoSpace): a reserved kernel region a device's register range maps
/// into, page tables made at boot and shared by every address space. Sixteen
/// entries: 64 MiB, enough for every BAR the PCI scan reports on the development machine. A range
/// larger than what remains goes unmapped (the caller fails the mapping).
pub const MMIO: Region = Region {
    start: 0xC280_0000,
    entries: 16,
};

/// Loaded driver images (`.sys` modules): the region the kernel-side loader maps a module into,
/// page tables made at boot and shared by every address space like the MMIO region's. Thirty-two
/// entries: 128 MiB. A module larger than what remains is not loaded.
pub const MODULES: Region = Region {
    start: 0xC680_0000,
    entries: 32,
};

/// Two directory entries no region maps, ever: in each process directory they hold the links of
/// the list of live directories ([`crate::mem::ktables`]), never present, so the processor ignores
/// them. Kept apart from every region so that no table can ever be installed over them.
pub const DIRECTORY_LINKS: Region = Region {
    start: 0xCE80_0000,
    entries: 2,
};

/// The frame database: one [`crate::mem::frame::FrameEntry`] per physical frame, sized at boot from
/// the memory map and mapped from the region's start, page tables made at boot and shared by every
/// address space. Eight entries: 32 MiB, room for a database over 4 GiB. Right below the nonpaged
/// pool, as Windows 2000's PFN database sits at its nonpaged pool's start.
pub const FRAME_DATABASE: Region = Region {
    start: 0xEDC0_0000,
    entries: 8,
};

/// The nonpaged pool: blocks of kernel memory taken and released at runtime, mapped in every
/// address space ([`crate::mem::pool`]). 64 entries, 256 MiB, Windows 2000's x86 maximum; its page
/// tables are made as blocks first reach each entry's window ([`crate::mem::ktables`]).
pub const NONPAGED_POOL: Region = Region {
    start: 0xEFC0_0000,
    entries: 64,
};

/// The kernel's view of the shared data page (KUSER_SHARED_DATA) at `0xFFDF0000`, Windows 2000's
/// address for it, in the table of the last directory entry.
pub const SHARED_DATA: Region = Region {
    start: 0xFFC0_0000,
    entries: 1,
};

// Checked whenever the kernel builds, not by the host tests alone: the addresses other modules fix
// lie in their regions, the image sits in its window past the entry span, and the stack region
// stays clear of the image window's growth.
const _: () = {
    assert!(SHARED_DATA.holds(crate::user::shared::KERNEL_ADDRESS));
    assert!(KERNEL_IMAGE.holds(NTOSKRNL_BASE) && NTOSKRNL_BASE.is_multiple_of(ENTRY_SPAN));
    assert!(NTOSKRNL_BASE / ENTRY_SPAN == KERNEL_IMAGE.first_entry() as u32 + 1);
    assert!(KERNEL_STACKS.start as u64 >= KERNEL_IMAGE.end());
    assert!(KERNEL_STACKS.end() == PAGE_TABLES.start as u64);
    assert!(
        crate::mem::frame::PHYSICAL_FRAME_LIMIT * crate::mem::frame::FRAME_ENTRY_BYTES
            <= FRAME_DATABASE.size() as usize
    );
};

#[cfg(test)]
mod tests {
    use super::*;

    const REGIONS: [(&str, Region); 11] = [
        ("kernel image", KERNEL_IMAGE),
        ("kernel stacks", KERNEL_STACKS),
        ("page tables", PAGE_TABLES),
        ("hyperspace", HYPERSPACE),
        ("framebuffer", FRAMEBUFFER),
        ("mmio", MMIO),
        ("modules", MODULES),
        ("directory links", DIRECTORY_LINKS),
        ("frame database", FRAME_DATABASE),
        ("nonpaged pool", NONPAGED_POOL),
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
            (656, 768)
        );
        assert_eq!(KERNEL_STACKS.end(), 0xC000_0000);
        assert_eq!(KERNEL_STACKS.end(), PAGE_TABLES.start as u64);
        assert_eq!(PAGE_TABLES.first_entry(), 768);
        assert_eq!(HYPERSPACE.first_entry(), 769);
        assert_eq!(
            (FRAMEBUFFER.first_entry(), FRAMEBUFFER.end_entry()),
            (770, 778)
        );
        assert_eq!(FRAMEBUFFER.end(), 0xC280_0000);
        assert_eq!((MMIO.first_entry(), MMIO.end_entry()), (778, 794));
        assert_eq!(MMIO.start, FRAMEBUFFER.end() as u32);
        assert_eq!(MMIO.end(), 0xC680_0000);
        assert_eq!((MODULES.first_entry(), MODULES.end_entry()), (794, 826));
        assert_eq!(MODULES.start, MMIO.end() as u32);
        assert_eq!(MODULES.end(), 0xCE80_0000);
        assert_eq!(
            (DIRECTORY_LINKS.first_entry(), DIRECTORY_LINKS.end_entry()),
            (826, 828)
        );
        assert_eq!(DIRECTORY_LINKS.start, MODULES.end() as u32);
        assert_eq!(
            (FRAME_DATABASE.first_entry(), FRAME_DATABASE.end_entry()),
            (951, 959)
        );
        assert_eq!(FRAME_DATABASE.end(), NONPAGED_POOL.start as u64);
        assert_eq!(
            (NONPAGED_POOL.first_entry(), NONPAGED_POOL.end_entry()),
            (959, 1023)
        );
        assert_eq!(NONPAGED_POOL.size(), 256 * 0x10_0000);
        assert_eq!(NONPAGED_POOL.end(), SHARED_DATA.start as u64);
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

    /// The image window maps physical `[0, 16 MiB)`: the boot loader's load address and the VGA
    /// text page lie in its entry span, the kernel's image right behind it.
    #[test]
    fn the_image_window_covers_the_load_address() {
        assert_eq!(KERNEL_IMAGE.size(), 16 * 0x10_0000);
        let entry_span = KERNEL_IMAGE.start..NTOSKRNL_BASE;
        assert!(
            entry_span.contains(&(KERNEL_IMAGE.start + crate::mem::paging::LOADER_PHYS_BASE.get()))
        );
        assert!(entry_span.contains(&crate::hw::vga::VIRT_BASE));
        assert_eq!(entry_span.len() as u32, ENTRY_SPAN);
    }

    /// The kernel's image base is Windows 2000's, the window's second directory entry, physical 4
    /// MiB.
    #[test]
    fn the_image_sits_behind_the_entry_span() {
        assert_eq!(NTOSKRNL_BASE, 0x8040_0000);
        assert_eq!(NTOSKRNL_BASE >> 22, 513);
        assert!(KERNEL_IMAGE.holds(NTOSKRNL_BASE));
        assert_eq!(NTOSKRNL_BASE - KERNEL_IMAGE.start, 0x40_0000);
    }

    /// The stack region spans Windows 2000's additional system PTEs up to the page tables: 448 MiB,
    /// 12,743 slots at today's stride, a slot for every thread record many times over, its frames
    /// more than the machine's memory; it stays clear of the image window above which the image
    /// grows.
    #[test]
    fn the_stack_region_spans_up_to_the_page_tables() {
        let stride = crate::mem::paging::GATE_SLOT_STRIDE;
        assert_eq!(KERNEL_STACKS.size(), 448 * 0x10_0000);
        assert_eq!(KERNEL_STACKS.size() / stride, 12_743);
        assert!(KERNEL_STACKS.size() / stride >= 2 * crate::ob::THREADS as u32);
        // Every slot's stack pages backed: more frames than 256 MiB of memory holds.
        let frames = (KERNEL_STACKS.size() / stride) as u64
            * crate::mem::paging::GATE_STACK_PAGES as u64
            * crate::mem::paging::PAGE_SIZE as u64;
        assert!(frames > 256 * 0x10_0000);
        assert!(KERNEL_STACKS.start as u64 > KERNEL_IMAGE.end());
        assert_eq!(KERNEL_STACKS.end(), PAGE_TABLES.start as u64);
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
