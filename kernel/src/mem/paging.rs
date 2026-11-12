//! Paging: the kernel window and the runtime user mappings.
//!
//! 32-bit x86 two-level paging, 4 KiB pages. The kernel half's regions are laid out in
//! [`crate::mem::layout`]. The kernel's image is linked at [`layout::NTOSKRNL_BASE`] and runs
//! there. The boot directory maps:
//!
//! - `[0, 16 MiB)`: physical identity, the boot transition window (the boot loader, the Multiboot
//!   info) until [`teardown_low_identity`] removes it;
//! - `[KERNEL_BASE, KERNEL_BASE + 16 MiB)`: the kernel image window ([`layout::KERNEL_IMAGE`]) over
//!   physical `[0, 16 MiB)`.
//!
//! Two directories carry that picture in turn. The boot loader (`kernel/loader`) builds the first
//! in its own memory before it enters the kernel. As soon as the frame database exists,
//! [`install_boot_directory`] builds the same directory and tables in frames of the kernel's own
//! ([`BootTables`]) and switches to it; the loader's are never walked again, so the processor's
//! accessed and dirty bits land only in tables the kernel owns outright, and the loader's memory
//! can be given back ([`crate::mem::bootmem`]). Everything below `KERNEL_BASE` is unmapped after
//! the teardown; user pages and their tables are created at runtime ([`init_frame`],
//! [`set_user_pte`]). The user entries' only writer is the address-space manager
//! ([`crate::mem::vm`]): the raw entry access here serves it alone.

#[cfg(target_arch = "x86")]
use core::arch::asm;
#[cfg(target_arch = "x86")]
use core::sync::atomic::{AtomicBool, Ordering};

use super::frame::{FrameDb, FrameHooks};
use super::layout;
#[cfg(target_arch = "x86")]
use super::{frame::PRIMARY_COLOR, with_database, Parts};

/// Virtual base of kernel space (user space is the low 2 GiB): the kernel image window's start.
pub const KERNEL_BASE: u32 = layout::KERNEL_IMAGE.start;

/// Physical load address of the boot loader, 1 MiB: the start of its memory, in the kernel image
/// window's entry span, which the kernel keeps until it no longer pages through the loader's
/// tables.
pub const LOADER_PHYS_BASE: u32 = 0x0010_0000;

/// Page-table flag: page/directory entry is present.
pub const PAGE_PRESENT: u32 = 1 << 0;
/// Entry bit 1: writable.
pub const PAGE_WRITE: u32 = 1 << 1;
/// Entry bit 2: user-accessible (supervisor-only when clear).
pub const PAGE_USER: u32 = 1 << 2;
/// Entry bit 3: the page's caches disabled (PCD) — for device memory such as the display's
/// framebuffer, whose writes must reach the device rather than sit in a cache line.
pub const PAGE_CACHE_DISABLE: u32 = 1 << 3;
/// Mask selecting the address bits of a page-table entry.
pub const PAGE_ADDR_MASK: u32 = 0xFFFF_F000;

/// Page-table entries per table (32-bit paging: 1024).
pub const PT_ENTRIES: usize = 1024;

/// Page size (32-bit paging: 4 KiB).
pub const PAGE_SIZE: u32 = 4096;

/// The identity entry for page `page`: present, writable, mapping physical page `page`.
const fn identity_entry(page: usize) -> u32 {
    (page * 4096) as u32 | PAGE_PRESENT | PAGE_WRITE
}

/// Fill `table` with the identity mapping of the 1024 pages from `first_page`: page `first_page +
/// i` to physical page `first_page + i`.
fn fill_identity_table(table: &mut [u32; PT_ENTRIES], first_page: usize) {
    for (i, entry) in table.iter_mut().enumerate() {
        *entry = identity_entry(first_page + i);
    }
}

/// 4 KiB-aligned wrapper: CR3 and directory entries require page-aligned tables.
#[repr(align(4096))]
pub struct Aligned<T>(pub T);

/// How many boot page tables there are: one per directory entry of the kernel image window, each
/// mapping 4 MiB of physical `[0, 16 MiB)`.
pub const BOOT_TABLE_COUNT: usize = layout::KERNEL_IMAGE.entries;

/// The boot directory and the tables it owns, each in a frame of its own taken from the frame
/// database, by physical address: the directory the kernel runs in between processes, and whose
/// kernel half every process directory inherits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BootTables {
    /// The directory.
    pub directory: u32,
    /// The identity tables over physical `[0, 16 MiB)`, 4 MiB apiece: the kernel image window's,
    /// and the low identity window's while it lasts.
    pub identity: [u32; BOOT_TABLE_COUNT],
    /// The scratch window's table ([`SCRATCH_SLOT`]), shared by every directory.
    pub scratch: u32,
}

impl BootTables {
    /// The frames for the directory and its tables, from `allocate` (each call one page-aligned
    /// physical address): the directory first, then the identity tables in order, then the
    /// scratch table.
    pub fn allocate(mut allocate: impl FnMut() -> u32) -> BootTables {
        let directory = allocate();
        let mut identity = [0; BOOT_TABLE_COUNT];
        for table in &mut identity {
            *table = allocate();
        }
        let scratch = allocate();
        BootTables {
            directory,
            identity,
            scratch,
        }
    }

    /// Fill `directory` (the directory's frame) as the boot loader fills its own, the self-map
    /// added: the low identity window's entries and the kernel image window's point at the identity
    /// tables, in order, and the self-map entry ([`SELF_MAP_SLOT`]) at the directory itself, so the
    /// directory is reached through the self-map from its first load on, like every other. Every
    /// other entry is empty, the scratch window's included ([`init_table_access`] installs it).
    pub fn fill_directory(&self, directory: &mut [u32; PT_ENTRIES]) {
        directory.fill(0);
        let image = layout::KERNEL_IMAGE.first_entry();
        for (i, &table) in self.identity.iter().enumerate() {
            directory[i] = Pte::kernel_rw(table).raw();
            directory[image + i] = Pte::kernel_rw(table).raw();
        }
        directory[SELF_MAP_SLOT] = Pte::kernel_rw(self.directory).raw();
    }

    /// Fill `table` (identity table `index`'s frame): pages `[index * 1024, (index + 1) * 1024)`
    /// mapped to themselves, as the boot loader's table `index` maps them.
    pub fn fill_identity(index: usize, table: &mut [u32; PT_ENTRIES]) {
        fill_identity_table(table, index * PT_ENTRIES);
    }
}

/// The boot directory and its tables, set once by [`install_boot_directory`].
#[cfg(target_arch = "x86")]
static BOOT_DIRECTORY: crate::sync::InitOnce<BootTables> = crate::sync::InitOnce::new();

/// The boot directory and its tables.
///
/// # Panics
///
/// Called before [`install_boot_directory`].
#[cfg(target_arch = "x86")]
fn boot_directory() -> &'static BootTables {
    BOOT_DIRECTORY.get()
}

/// The frames the kernel image window maps: physical `[0, 16 MiB)`, reachable at `KERNEL_BASE +
/// phys` from the boot loader's directory on.
const IMAGE_WINDOW_FRAMES: u32 = layout::KERNEL_IMAGE.size() / PAGE_SIZE;

/// Take the highest free frame below `limit` out of the frame database's free lists: a frame the
/// kernel image window maps (with `limit` its frame count), so it can be written before any runtime
/// access window exists. The highest first: the low frames serve the firmware and the real-mode
/// trampoline. Physical address; none when no frame below `limit` is free.
pub fn take_window_frame<H: FrameHooks>(frames: &mut FrameDb<H>, limit: u32) -> Option<u32> {
    let frame = (1..limit)
        .rev()
        .find(|&frame| frames.entry(frame).state.has_color_chain())?;
    frames.take(frame);
    Some(frame * PAGE_SIZE)
}

/// Build the boot directory and its tables in frames of their own and switch to it, once, right
/// after the frame database is built and before [`teardown_low_identity`]: the same picture the
/// boot loader set up ([`BootTables::fill_directory`]), so execution carries on unchanged, and from
/// here on the processor never walks the loader's tables again.
///
/// The frames are taken from the frame database below the kernel image window's end
/// ([`take_window_frame`]) and filled through that window, the one mapping that reaches them
/// before the self-map exists; they are never released. Once the directory is loaded, it is
/// reached only through the self-map.
///
/// # Panics
///
/// Called twice, or the window holds no free frame for a table.
#[cfg(target_arch = "x86")]
pub fn install_boot_directory() {
    let tables = with_database(|database| {
        let frames = database.frames();
        let tables = BootTables::allocate(|| {
            take_window_frame(frames, IMAGE_WINDOW_FRAMES)
                .expect("no free frame in the kernel image window for the boot tables")
        });
        fill_new_table(tables.directory, |directory| {
            tables.fill_directory(directory)
        });
        for (index, &table) in tables.identity.iter().enumerate() {
            fill_new_table(table, |table| BootTables::fill_identity(index, table));
        }
        fill_new_table(tables.scratch, |scratch| scratch.fill(0));
        tables
    });
    BOOT_DIRECTORY.set(tables);
    activate_address_space(tables.directory);
}

/// Run `fill` on the boot table at `frame_phys`, through the kernel image window, while it is
/// built.
///
/// # Panics
///
/// The frame is not page-aligned or lies outside the kernel image window.
#[cfg(target_arch = "x86")]
fn fill_new_table(frame_phys: u32, fill: impl FnOnce(&mut [u32; PT_ENTRIES])) {
    assert!(
        frame_phys.is_multiple_of(PAGE_SIZE) && frame_phys / PAGE_SIZE < IMAGE_WINDOW_FRAMES,
        "a boot table outside the kernel image window"
    );
    // SAFETY: the frame lies in the kernel image window (checked above), which maps physical
    // `[0, 16 MiB)` at `KERNEL_BASE + phys` from the boot loader on; page-aligned, so aligned for
    // words. `install_boot_directory` just took it out of the free lists, so no other owner holds
    // it, and no directory names it yet, so the processor does not walk it: the reference, which
    // `fill` cannot keep, is the only access to it.
    fill(unsafe { &mut *((KERNEL_BASE + frame_phys) as *mut [u32; PT_ENTRIES]) });
}

/// A page-directory or page-table entry: the frame (or page table) it names and its flag bits.
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

    /// Whether the entry maps anything.
    pub const fn present(self) -> bool {
        self.0 & PAGE_PRESENT != 0
    }

    /// The frame (or page table) the entry names, present or not.
    pub const fn frame(self) -> u32 {
        self.0 & PAGE_ADDR_MASK
    }

    /// A present, writable, supervisor-only entry for `frame`: the kernel's own pages and tables,
    /// and the runtime access windows' directory entries.
    pub const fn kernel_rw(frame: u32) -> Pte {
        Pte(frame | PAGE_PRESENT | PAGE_WRITE)
    }

    /// A present, writable, supervisor-only, uncached entry for `frame`: device memory such as the
    /// display's framebuffer (see [`PAGE_CACHE_DISABLE`]).
    pub const fn kernel_rw_uncached(frame: u32) -> Pte {
        Pte(frame | PAGE_PRESENT | PAGE_WRITE | PAGE_CACHE_DISABLE)
    }

    /// A present entry ring 3 can reach for `frame`, with the further `flags` ([`PAGE_WRITE`] for a
    /// writable one).
    pub const fn user(frame: u32, flags: u32) -> Pte {
        Pte(frame | PAGE_PRESENT | PAGE_USER | flags)
    }
}

/// Remove the boot directory's low identity window (called once the Multiboot info is consumed),
/// through the self-map: clears entries `[0, BOOT_TABLE_COUNT)` and flushes the TLB via a CR3
/// reload. User space is unmapped from here on.
///
/// # Panics
///
/// The boot directory is not the current one ([`install_boot_directory`] has not run), its kernel
/// window does not point at its identity tables, or the low window is gone already.
#[cfg(target_arch = "x86")]
pub fn teardown_low_identity() {
    let tables = boot_directory();
    assert_eq!(
        current_directory_phys(),
        tables.directory,
        "the low identity window torn down outside the boot directory"
    );
    // The kernel window must be established before the low window goes away.
    let image = layout::KERNEL_IMAGE.first_entry();
    for (i, &table) in tables.identity.iter().enumerate() {
        assert_eq!(
            self_map::pde(image + i).frame(),
            table,
            "kernel window is not mapped"
        );
    }
    assert!(
        self_map::pde(0).present(),
        "low identity window is already gone"
    );
    remove_low_identity();
}

// --- Runtime table access (user mappings) ---------------------------------
//
// Two directory entries give the kernel access to its own tables and to arbitrary frames, without a
// direct map of physical memory:
//
// - the self-map ([`SELF_MAP_SLOT`]): the directory maps itself, so directory entry i sits at
//   SELF_MAP_VA + i*4 and window i's page table at SELF_MAP_VA + i*4096;
// - the scratch table ([`SCRATCH_SLOT`]): entry 0 aliases whichever frame the kernel is
//   initializing, so fresh frames can be zeroed and written before they are mapped anywhere else.

/// Directory entry that maps the directory into its own window (NT-style: self-map at 0xC0000000,
/// [`layout::PAGE_TABLES`]).
pub const SELF_MAP_SLOT: usize = layout::PAGE_TABLES.first_entry();
/// Virtual address of the self-mapped directory (SELF_MAP_SLOT << 22).
pub const SELF_MAP_VA: u32 = (SELF_MAP_SLOT as u32) << 22;
/// Directory entry that holds the scratch page table (NT-style: scratch/hyperspace at 0xC0400000,
/// [`layout::HYPERSPACE`]).
pub const SCRATCH_SLOT: usize = layout::HYPERSPACE.first_entry();
/// Virtual address of scratch entry 0: the one-page alias of the frame being initialized.
pub const SCRATCH_VA: u32 = (SCRATCH_SLOT as u32) << 22;
/// First directory entry of the kernel half (KERNEL_BASE's own window): entries below it belong to
/// user space.
pub const KERNEL_HALF_START: usize = (KERNEL_BASE >> 22) as usize;
/// Virtual address of directory entry 0 through the self-map's own window: the directory doubles as
/// window `SELF_MAP_SLOT`'s page table (its entry `SELF_MAP_SLOT` points at itself), so entry `i`
/// sits at `DIRECTORY_ENTRY_VA + i*4`. Distinct from the table window below, which addresses any
/// window's page *table*.
pub const DIRECTORY_ENTRY_VA: u32 = SELF_MAP_VA + ((SELF_MAP_SLOT as u32) << 12);
/// The ring-0 gate stacks' window: the kernel stack region ([`layout::KERNEL_STACKS`], entries
/// 656-659), its tables made at boot and shared by every directory, sub-allocated into per-thread
/// slots numbered across the whole region (one ledger for the system, [`crate::mem::kstacks`]),
/// each a guard page plus the 32 KiB stack. Slot 0's top is [`GATE_STACK_TOP`].
pub const GATE_STACK_WINDOW: u32 = layout::KERNEL_STACKS.start;
/// Gate stack pages, one frame each (32 KiB): room for the file system's walks under the debug
/// build's frames.
pub const GATE_STACK_PAGES: usize = 8;
/// Slot 0's top, pinned by the layout tests (the switch installs every thread's top from its
/// record, so nothing else reads it).
#[cfg(test)]
pub const GATE_STACK_TOP: u32 = gate_slot_top(0);
/// One thread's slot: a guard page plus the stack pages.
pub const GATE_SLOT_STRIDE: u32 = ((GATE_STACK_PAGES + 1) as u32) * PAGE_SIZE;
/// How many slots the region (four directory entries, 16 MiB) holds: the system's capacity for
/// kernel stacks. A slot may straddle two of the region's page tables.
pub const GATE_SLOT_CAPACITY: usize = (layout::KERNEL_STACKS.size() / GATE_SLOT_STRIDE) as usize;

/// Slot `index`'s base: its guard page, never mapped.
pub const fn gate_slot_base(index: u32) -> u32 {
    GATE_STACK_WINDOW + index * GATE_SLOT_STRIDE
}

/// Slot `index`'s top: the owning thread's `esp0` / stack top.
pub const fn gate_slot_top(index: u32) -> u32 {
    gate_slot_base(index) + GATE_SLOT_STRIDE
}

/// Install the scratch table in the boot directory, once, right after [`teardown_low_identity`],
/// through the self-map the directory carries from its construction ([`BootTables`]); the table
/// was zeroed there too. No TLB flush needed: the window was not mapped before.
///
/// # Panics
///
/// The boot directory's self-map is not in place, or the scratch table is installed already.
#[cfg(target_arch = "x86")]
pub fn init_table_access() {
    let tables = boot_directory();
    // The frame only: the processor sets accessed and dirty bits in the entry as it walks it.
    let self_entry = self_map::pde(SELF_MAP_SLOT);
    assert!(
        self_entry.present() && self_entry.frame() == tables.directory,
        "the boot directory's self-map is not in place"
    );
    assert!(
        !self_map::pde(SCRATCH_SLOT).present(),
        "scratch table already installed"
    );
    self_map::set_pde(SCRATCH_SLOT, Pte::kernel_rw(tables.scratch));
}

/// The current directory's entries and page tables, reached through its self-map: the directory
/// maps itself at [`SELF_MAP_SLOT`], so its entry `i` sits at `DIRECTORY_ENTRY_VA + i*4` and the
/// page-table entry for an address `va` at `SELF_MAP_VA + (va >> 12)*4`. Both go through the
/// **current** directory, the one CR3 points at, so they reach the active address space. The
/// processor sets accessed and dirty bits in these entries as a side effect of ordinary memory
/// traffic, so every access is volatile.
///
/// Every directory holds the self-map from its construction: the boot's ([`BootTables`],
/// [`install_boot_directory`]) and each process's ([`assemble_process_directory`]). The writers own
/// the entries they write: the address-space manager ([`crate::mem::vm`]) its process's user
/// windows; the boot, and steps under the memory manager's database (the kernel stacks, the scratch
/// window), the kernel half's.
#[cfg(target_arch = "x86")]
mod self_map {
    use super::{Pte, DIRECTORY_ENTRY_VA, PT_ENTRIES, SELF_MAP_VA};

    /// Where directory entry `window` sits, on the directory's view of itself.
    fn directory_slot(window: usize) -> *mut u32 {
        assert!(window < PT_ENTRIES, "directory index past the directory");
        (DIRECTORY_ENTRY_VA + window as u32 * 4) as *mut u32
    }

    /// Where the page-table entry for `va` sits, in its window's table through the self-map window.
    fn table_slot(va: u32) -> *mut u32 {
        (SELF_MAP_VA + (va >> 12) * 4) as *mut u32
    }

    /// The current directory's entry `window`.
    pub fn pde(window: usize) -> Pte {
        // SAFETY: the self-map is installed in every directory (see the module notes), so the
        // directory's view page is mapped, and the slot lies on it (the index is checked).
        Pte(unsafe { directory_slot(window).read_volatile() })
    }

    /// Set the current directory's entry `window`.
    pub fn set_pde(window: usize, entry: Pte) {
        // SAFETY: as in `pde`; the caller owns the entry (see the module notes).
        unsafe { directory_slot(window).write_volatile(entry.0) }
    }

    /// The current directory's page-table entry for `va`; none when `va`'s window has no table.
    pub fn pte(va: u32) -> Option<Pte> {
        if !pde((va >> 22) as usize).present() {
            return None;
        }
        // SAFETY: the window's table is present, so the self-map window maps it, and the slot is
        // the address's entry in it.
        Some(Pte(unsafe { table_slot(va).read_volatile() }))
    }

    /// Set the current directory's page-table entry for `va`.
    ///
    /// # Panics
    ///
    /// `va`'s window has no table.
    pub fn set_pte(va: u32, entry: Pte) {
        assert!(
            pde((va >> 22) as usize).present(),
            "a page-table entry set in a window with no table"
        );
        // SAFETY: as in `pte`; the caller owns the entry (see the module notes).
        unsafe { table_slot(va).write_volatile(entry.0) }
    }
}

/// Make the kernel stack region's page tables, once, at boot, after [`init_table_access`] and
/// before the first process directory: zeroed frames installed in the boot directory, which every
/// process directory inherits with the rest of the kernel half. The tables are then shared: a gate
/// stack mapped in them ([`map_gate_slot`]) is mapped in every address space. They are never
/// released.
#[cfg(target_arch = "x86")]
pub fn init_kernel_stack_tables() {
    assert!(
        !KERNEL_HALF_FROZEN.load(Ordering::Relaxed),
        "the kernel stack tables made after the first process directory"
    );
    with_database(|database| {
        let Parts {
            frames, scratch, ..
        } = database.parts();
        for window in layout::KERNEL_STACKS.first_entry()..layout::KERNEL_STACKS.end_entry() {
            install_kernel_table(window, new_table_in(frames, scratch));
        }
    });
}

/// Make the nonpaged pool's page tables, once, at boot, as [`init_kernel_stack_tables`] makes the
/// kernel stacks': zeroed frames installed in the boot directory, which every process directory
/// inherits, so a pool page mapped in them ([`map_pool_page`]) is mapped in every address space.
/// They are never released.
#[cfg(target_arch = "x86")]
pub fn init_pool_tables() {
    assert!(
        !KERNEL_HALF_FROZEN.load(Ordering::Relaxed),
        "the nonpaged pool's tables made after the first process directory"
    );
    with_database(|database| {
        let Parts {
            frames, scratch, ..
        } = database.parts();
        for window in layout::NONPAGED_POOL.first_entry()..layout::NONPAGED_POOL.end_entry() {
            install_kernel_table(window, new_table_in(frames, scratch));
        }
    });
}

/// Make the framebuffer region's page tables, shared by every address space like the pool's: the
/// display's linear framebuffer is mapped into them when the graphics mode is set (its frames come
/// from the VBE mode information, not from here).
#[cfg(target_arch = "x86")]
pub fn init_framebuffer_tables() {
    assert!(
        !KERNEL_HALF_FROZEN.load(Ordering::Relaxed),
        "the framebuffer's tables made after the first process directory"
    );
    with_database(|database| {
        let Parts {
            frames, scratch, ..
        } = database.parts();
        for window in layout::FRAMEBUFFER.first_entry()..layout::FRAMEBUFFER.end_entry() {
            install_kernel_table(window, new_table_in(frames, scratch));
        }
    });
}

/// Make the MMIO region's page tables, once, at boot, as [`init_kernel_stack_tables`] makes the
/// kernel stacks': zeroed frames installed in the boot directory, which every process directory
/// inherits, so a device range mapped in them ([`map_mmio_page`]) is mapped in every address space.
/// They are never released.
#[cfg(target_arch = "x86")]
pub fn init_mmio_tables() {
    assert!(
        !KERNEL_HALF_FROZEN.load(Ordering::Relaxed),
        "the MMIO region's tables made after the first process directory"
    );
    with_database(|database| {
        let Parts {
            frames, scratch, ..
        } = database.parts();
        for window in layout::MMIO.first_entry()..layout::MMIO.end_entry() {
            install_kernel_table(window, new_table_in(frames, scratch));
        }
    });
}

/// Make the modules region's page tables, once, at boot, as [`init_kernel_stack_tables`] makes the
/// kernel stacks': zeroed frames installed in the boot directory, which every process directory
/// inherits, so a driver image mapped in them ([`crate::dev::loader`]) is mapped in every address
/// space. They are never released.
#[cfg(target_arch = "x86")]
pub fn init_module_tables() {
    assert!(
        !KERNEL_HALF_FROZEN.load(Ordering::Relaxed),
        "the modules region's tables made after the first process directory"
    );
    with_database(|database| {
        let Parts {
            frames, scratch, ..
        } = database.parts();
        for window in layout::MODULES.first_entry()..layout::MODULES.end_entry() {
            install_kernel_table(window, new_table_in(frames, scratch));
        }
    });
}

/// Try to allocate one frame, physical address, through the database; none when the frame database
/// has none left (a status for the caller, not a panic). The bridge to [`try_allocate_frame`].
#[cfg(target_arch = "x86")]
pub fn try_allocate_frame_phys() -> Option<u32> {
    with_database(|database| try_allocate_frame(database.frames()))
}

/// Release the frame at `frame_phys` back to the frame database as free (its mapping is the
/// caller's to remove first). The bridge to [`FrameDb::release`].
#[cfg(target_arch = "x86")]
pub fn release_frame_phys(frame_phys: u32) {
    assert!(frame_phys % PAGE_SIZE == 0, "frame not page-aligned");
    with_database(|database| {
        database
            .frames()
            .release(frame_phys / PAGE_SIZE, super::frame::FrameState::Free)
    });
}

/// Point the current directory's entry `window` at the page table `table_phys`: present, writable,
/// supervisor, not global. Nothing maps through the entry before it is written.
///
/// # Panics
///
/// The entry is already present.
#[cfg(target_arch = "x86")]
fn install_kernel_table(window: usize, table_phys: u32) {
    assert!(
        !self_map::pde(window).present(),
        "kernel-half table already installed"
    );
    self_map::set_pde(window, Pte::kernel_rw(table_phys));
}

/// Set once the first process directory is assembled: from then on the kernel half is frozen, every
/// directory holding its own copy of the kernel-half directory entries. Nothing propagates a later
/// one, so a table created afterwards would map its pages in one directory and leave them missing
/// from the others: the kernel half's tables are all created at boot (the shared data page's, the
/// kernel stack region's), and only mappings into existing tables come later.
#[cfg(target_arch = "x86")]
static KERNEL_HALF_FROZEN: AtomicBool = AtomicBool::new(false);

/// Invalidate the TLB entry for `vaddr`.
#[cfg(target_arch = "x86")]
fn invlpg(vaddr: u32) {
    // SAFETY: invlpg only drops the page's cached translation, whether or not one is cached; it
    // changes no register and no memory.
    unsafe {
        asm!("invlpg [{va}]", va = in(reg) vaddr, options(nostack, preserves_flags));
    }
}

/// Bytes per page, as a length.
const PAGE_BYTES: usize = PAGE_SIZE as usize;

/// The scratch window (Windows' hyperspace): one page of kernel address space, [`SCRATCH_VA`],
/// that aliases whichever frame the kernel is reading or writing, so a fresh frame can be zeroed
/// and filled before it is mapped anywhere else, and a dead process's tables read without mapping
/// them.
///
/// The system has one, in the memory manager's database ([`crate::mem`]): its borrow keeps
/// interrupts masked (the database's level is the high one) and makes it the window's only user,
/// as Windows uses its per-processor windows at a raised level. Nothing runs between pointing the
/// window at a frame and the last access through it, and the page [`ScratchWindow::map`] hands
/// out lives no longer than that borrow. A frame's contents come in or go out through the caller's
/// buffers, never across a wait (a disk read).
#[cfg(target_arch = "x86")]
pub struct ScratchWindow {
    _one: (),
}

#[cfg(target_arch = "x86")]
impl ScratchWindow {
    /// The window: one exists, the memory manager's database's.
    pub(super) const fn new() -> Self {
        ScratchWindow { _one: () }
    }

    /// Point the window at `frame_phys` and flush its old translation. The hardware flag is
    /// checked, not only the level.
    ///
    /// # Panics
    ///
    /// `frame_phys` is not page-aligned, or interrupts are enabled.
    fn point_at(&mut self, frame_phys: u32) {
        assert!(frame_phys & (PAGE_SIZE - 1) == 0, "frame not page-aligned");
        assert!(
            interrupts_masked(),
            "the scratch window used with interrupts enabled"
        );
        self_map::set_pte(SCRATCH_VA, Pte::kernel_rw(frame_phys));
        invlpg(SCRATCH_VA);
    }

    /// The frame at `frame_phys`, as bytes, until the window is next used.
    pub fn map(&mut self, frame_phys: u32) -> &mut [u8; PAGE_BYTES] {
        self.point_at(frame_phys);
        // SAFETY: the window maps exactly `frame_phys`, page-aligned and page-length, at
        // SCRATCH_VA from the line above. The result borrows the system's one window mutably, so
        // no other reference into the window exists while it lives, and nothing re-points the
        // window meanwhile (that takes the window too).
        unsafe { &mut *(SCRATCH_VA as *mut [u8; PAGE_BYTES]) }
    }

    /// The frame at `frame_phys`, as words (a directory or a page table), until the window is next
    /// used.
    pub fn map_words(&mut self, frame_phys: u32) -> &mut [u32; PT_ENTRIES] {
        self.point_at(frame_phys);
        // SAFETY: as in `map`; the window's address is page-aligned, so aligned for words.
        unsafe { &mut *(SCRATCH_VA as *mut [u32; PT_ENTRIES]) }
    }

    /// Zero the frame at `frame_phys`, then copy `bytes` in at `offset` (tables: empty slice; image
    /// pages: bytes; data pages: zero fill).
    pub fn init_frame(&mut self, frame_phys: u32, offset: usize, bytes: &[u8]) {
        assert!(
            offset + bytes.len() <= PAGE_BYTES,
            "write past the end of the frame"
        );
        let page = self.map(frame_phys);
        // A zero fill compiles to one call of the string-instruction `memset`, a debug build
        // included; a byte loop would stretch every page allocation there.
        *page = [0; PAGE_BYTES];
        page[offset..][..bytes.len()].copy_from_slice(bytes);
    }

    /// Copy `bytes` into the frame at `frame_phys` at `offset`, without zeroing the rest (unlike
    /// [`ScratchWindow::init_frame`]).
    pub fn write_frame(&mut self, frame_phys: u32, offset: usize, bytes: &[u8]) {
        assert!(
            offset + bytes.len() <= PAGE_BYTES,
            "write past the end of the frame"
        );
        self.map(frame_phys)[offset..][..bytes.len()].copy_from_slice(bytes);
    }

    /// Copy `out.len()` bytes of the frame at `frame_phys`, from `offset`, into `out`.
    pub fn read_frame(&mut self, frame_phys: u32, offset: usize, out: &mut [u8]) {
        assert!(
            offset + out.len() <= PAGE_BYTES,
            "read past the end of the frame"
        );
        out.copy_from_slice(&self.map(frame_phys)[offset..][..out.len()]);
    }

    /// Word `index` of the frame at `frame_phys`.
    ///
    /// # Panics
    ///
    /// `index` past the frame's end.
    pub fn read_word(&mut self, frame_phys: u32, index: usize) -> u32 {
        assert!(index < PT_ENTRIES, "word index past the end of the frame");
        self.map_words(frame_phys)[index]
    }
}

/// Whether the processor's interrupt flag is clear (EFLAGS, read through the stack).
#[cfg(target_arch = "x86")]
fn interrupts_masked() -> bool {
    let flags: u32;
    // SAFETY: pushes EFLAGS and pops it into a register; nothing else changes.
    unsafe {
        asm!("pushfd", "pop {}", out(reg) flags, options(preserves_flags));
    }
    flags & (1 << 9) == 0
}

/// Zero a freshly allocated frame through the scratch window, then copy `bytes` at `offset`: the
/// bridge to [`ScratchWindow::init_frame`] for code that does not hold the memory manager's
/// database.
#[cfg(target_arch = "x86")]
pub fn init_frame(frame_phys: u32, offset: usize, bytes: &[u8]) {
    with_database(|database| database.scratch.init_frame(frame_phys, offset, bytes));
}

/// Patch `bytes` into a frame at `offset` without zeroing (unlike [`init_frame`]); for building a
/// page in pieces. The bridge to [`ScratchWindow::write_frame`].
#[cfg(target_arch = "x86")]
pub fn write_frame(frame_phys: u32, offset: usize, bytes: &[u8]) {
    with_database(|database| database.scratch.write_frame(frame_phys, offset, bytes));
}

/// Read `out.len()` bytes of a frame at `offset`, through the scratch window. The bridge to
/// [`ScratchWindow::read_frame`].
#[cfg(target_arch = "x86")]
pub fn read_frame(frame_phys: u32, offset: usize, out: &mut [u8]) {
    with_database(|database| database.scratch.read_frame(frame_phys, offset, out));
}

/// Copy a whole frame's contents into another (a copy-on-write's private copy), through the
/// scratch window a chunk at a time.
#[cfg(target_arch = "x86")]
pub fn copy_frame(from_phys: u32, to_phys: u32) {
    let mut chunk = [0u8; 512];
    for offset in (0..PAGE_BYTES).step_by(chunk.len()) {
        read_frame(from_phys, offset, &mut chunk);
        write_frame(to_phys, offset, &chunk);
    }
}

/// Allocate one frame, physical address. Quirk: the database never zeroes frames, so the contents
/// are undefined until the caller runs [`init_frame`] — every frame handed to user space does.
///
/// # Panics
///
/// The frame database is empty.
#[cfg(target_arch = "x86")]
pub fn allocate_frame_phys() -> u32 {
    crate::mem::bootmem::with_frame_db(allocate_in)
}

/// [`allocate_frame_phys`]'s work, on the frame database the caller holds.
#[cfg(target_arch = "x86")]
fn allocate_in(frames: &mut FrameDb) -> u32 {
    frames.allocate(PRIMARY_COLOR) * PAGE_SIZE
}

/// A fresh page table: a frame from `frames`, zeroed through `scratch` while it is still
/// unreachable, so no garbage entry ever becomes walkable.
#[cfg(target_arch = "x86")]
fn new_table_in(frames: &mut FrameDb, scratch: &mut ScratchWindow) -> u32 {
    let table_phys = allocate_in(frames);
    scratch.init_frame(table_phys, 0, &[]);
    table_phys
}

/// The current directory's page-table entry for user address `vaddr`, raw (present or not); 0 when
/// its window has no table. The entry is the active process's (see [`self_map`]).
#[cfg(target_arch = "x86")]
pub fn user_pte(vaddr: u32) -> u32 {
    assert!(
        vaddr < KERNEL_BASE,
        "user entries live below the kernel window"
    );
    self_map::pte(vaddr).map_or(0, Pte::raw)
}

/// Write the current directory's page-table entry for user address `vaddr` — any value, present or
/// not (the address-space manager keeps committed but inaccessible pages as non-present entries
/// that still name their frame) — and flush it. The window's table is allocated on first use. The
/// address-space manager is the only writer of user windows.
///
/// # Panics
///
/// Unaligned or kernel-window `vaddr`.
#[cfg(target_arch = "x86")]
pub fn set_user_pte(vaddr: u32, entry: u32) {
    assert!(vaddr % PAGE_SIZE == 0, "user address not page-aligned");
    assert!(
        vaddr < KERNEL_BASE,
        "user entries live below the kernel window"
    );
    let window = (vaddr >> 22) as usize;
    if !self_map::pde(window).present() {
        if entry == 0 {
            return;
        }
        // Quirk: the table is zeroed while it is still unreachable — present garbage entries must
        // never become speculatively walkable. A user window must be traversable by ring 3; the
        // per-page user/supervisor and read/write bits decide the rest.
        let table_phys = with_database(|database| {
            let Parts {
                frames, scratch, ..
            } = database.parts();
            new_table_in(frames, scratch)
        });
        self_map::set_pde(window, Pte::user(table_phys, PAGE_WRITE));
    }
    self_map::set_pte(vaddr, Pte::from_raw(entry));
    invlpg(vaddr);
}

// --- Per-process address spaces --------------------------------------------
//
// A process owns a page-directory frame. Creation inherits the kernel half from the current
// directory (the kernel window and the kernel stacks must stay mapped wherever CR3 points: every
// kernel-half table is shared by every directory), zeroes the user half, points
// the self-map entry at the new directory itself, and installs the shared scratch table. The new
// directory is built through the scratch window — its own self-map is unreachable until CR3 loads
// it. Activation is a single CR3 load, which is also the full TLB flush (no F2K mapping is global,
// so nothing survives the reload).

/// Assemble a fresh process directory in `dir`: user half zeroed, kernel half inherited through
/// `read_base_entry` (called for each entry in `[KERNEL_HALF_START, PT_ENTRIES)` of the base
/// directory, which is only ever read), self-map entry pointing at the new directory's own frame
/// `own_phys`, scratch entry at the shared scratch table `scratch_phys`. The kernel stack region's
/// entries are inherited like the rest: its tables are shared, so every thread's gate stack is
/// mapped in the new directory as in every other.
///
/// Pure over the entries: the caller supplies how base entries are read (a volatile self-map read
/// on target, a plain array read in tests).
pub fn assemble_process_directory(
    dir: &mut [u32; PT_ENTRIES],
    own_phys: u32,
    scratch_phys: u32,
    mut read_base_entry: impl FnMut(usize) -> u32,
) {
    for entry in dir.iter_mut() {
        *entry = 0;
    }
    for i in KERNEL_HALF_START..PT_ENTRIES {
        dir[i] = read_base_entry(i);
    }
    // Present and writable, and nothing else: no user bit (the self-map and scratch windows are
    // kernel-only) and no global bit (every entry must drop out of the TLB when CR3 reloads).
    dir[SELF_MAP_SLOT] = Pte::kernel_rw(own_phys).raw();
    dir[SCRATCH_SLOT] = Pte::kernel_rw(scratch_phys).raw();
}

/// The value CR3 takes for a directory at `dir_phys`: the address bits only, so a sloppy caller's
/// low flag bits cannot leak into the load.
pub const fn directory_cr3(dir_phys: u32) -> u32 {
    dir_phys & PAGE_ADDR_MASK
}

/// The shared scratch table's physical address (one of the boot's tables, never released).
#[cfg(target_arch = "x86")]
pub fn scratch_table_phys() -> u32 {
    boot_directory().scratch
}

/// The boot directory's physical address: the address space the kernel returns to between
/// processes.
#[cfg(target_arch = "x86")]
pub fn boot_directory_phys() -> u32 {
    boot_directory().directory
}

/// Create a fresh process address space and return its directory's physical address. The directory
/// inherits the current address space's kernel half; it is not active until the caller loads it
/// with [`activate_address_space`].
///
/// # Panics
///
/// The frame database is empty (allocation happens before anything is written, so nothing is left
/// half-built).
#[cfg(target_arch = "x86")]
pub fn create_address_space() -> u32 {
    let dir_phys = with_database(|database| {
        let Parts {
            frames, scratch, ..
        } = database.parts();
        // Allocated first: exhaustion fails before any write.
        let dir_phys = allocate_in(frames);
        // The directory is assembled in its own frame, through the scratch window: every entry is
        // written (user half zero, kernel half copied, both special entries set), so no separate
        // zeroing pass is needed. The base directory's kernel half is read through the current
        // directory's view of itself.
        assemble_process_directory(
            scratch.map_words(dir_phys),
            dir_phys,
            scratch_table_phys(),
            |i| self_map::pde(i).raw(),
        );
        dir_phys
    });
    // From here on, a kernel-half table created in one directory would be missing from this one.
    KERNEL_HALF_FROZEN.store(true, Ordering::Relaxed);
    dir_phys
}

/// Make the directory at `dir_phys` the current address space: one CR3 load. The load itself
/// invalidates every non-global TLB entry (no F2K mapping is global), so the switch is also the
/// flush — no other TLB action belongs here.
#[cfg(target_arch = "x86")]
pub fn activate_address_space(dir_phys: u32) {
    let cr3 = directory_cr3(dir_phys);
    // SAFETY: `dir_phys` is a frame this kernel built (page-aligned CR3 value); the kernel half is
    // present in it, so execution continues on a mapped kernel window.
    unsafe {
        asm!("mov cr3, {cr3}", cr3 = in(reg) cr3, options(nostack, preserves_flags));
    }
}

/// Map `vaddr` to `frame_phys` for the kernel only: present, writable, supervisor (no user bit —
/// ring 3 must not reach these pages). The window's table is allocated on first use, like
/// [`set_user_pte`]'s, which only the boot may do; every kernel-half table is shared by every
/// directory, so the mapping lands in all of them. The bridge to [`map_kernel_page_in`] for code
/// that does not hold the memory manager's database: the boot's.
///
/// # Panics
///
/// As [`map_kernel_page_in`].
#[cfg(target_arch = "x86")]
pub fn map_kernel_page(vaddr: u32, frame_phys: u32) {
    with_database(|database| {
        let Parts {
            frames, scratch, ..
        } = database.parts();
        map_kernel_page_in(frames, scratch, vaddr, frame_phys);
    });
}

/// [`map_kernel_page`]'s work, on the frame database and the scratch window the caller holds (a
/// new table's frame comes from them).
///
/// Past the boot (before any thread runs), the kernel windows change only here and in
/// [`unmap_kernel_page`], at every thread create and exit, from [`map_gate_slot`] and
/// [`unmap_gate_slot`], and at every nonpaged pool block's allocation and release, from
/// [`map_pool_page`] and [`unmap_pool_page`], each under the memory manager's database borrow,
/// which masks interrupts: on one processor nothing else touches the entry between the check and
/// the store. Only the boot creates a table (the frozen-half assertion).
///
/// # Panics
///
/// Unaligned `vaddr`/`frame_phys`, `vaddr` outside the kernel half, `vaddr` in a window the
/// kernel owns for other purposes (the static kernel image window, the self-map, the scratch
/// window), `vaddr` already mapped, or a window whose table would be created after the first
/// process directory (see [`KERNEL_HALF_FROZEN`]).
#[cfg(target_arch = "x86")]
fn map_kernel_page_in(
    frames: &mut FrameDb,
    scratch: &mut ScratchWindow,
    vaddr: u32,
    frame_phys: u32,
) {
    assert!(frame_phys % PAGE_SIZE == 0, "frame not page-aligned");
    map_kernel_page_pte_in(frames, scratch, vaddr, Pte::kernel_rw(frame_phys));
}

/// [`map_kernel_page_in`]'s work with the entry to install given directly (uncached for the
/// framebuffer): the frame it names must be page-aligned.
#[cfg(target_arch = "x86")]
fn map_kernel_page_pte_in(
    frames: &mut FrameDb,
    scratch: &mut ScratchWindow,
    vaddr: u32,
    entry: Pte,
) {
    assert!(vaddr % PAGE_SIZE == 0, "kernel address not page-aligned");
    assert!(entry.frame() % PAGE_SIZE == 0, "frame not page-aligned");
    let window = (vaddr >> 22) as usize;
    assert!(
        vaddr >= KERNEL_BASE,
        "kernel mappings live in the kernel half"
    );
    assert!(
        !layout::KERNEL_IMAGE.holds_entry(window),
        "kernel mapping collides with the static kernel image window"
    );
    assert!(
        window != SELF_MAP_SLOT && window != SCRATCH_SLOT,
        "kernel mapping collides with the runtime access windows"
    );

    if !self_map::pde(window).present() {
        assert!(
            !KERNEL_HALF_FROZEN.load(Ordering::Relaxed),
            "a kernel-half table created after the first process directory"
        );
        install_kernel_table(window, new_table_in(frames, scratch));
    }
    assert!(
        !self_map::pte(vaddr).is_some_and(Pte::present),
        "kernel page already mapped"
    );
    self_map::set_pte(vaddr, entry);
    invlpg(vaddr);
}

/// Map the frame `frame_phys` at the kernel-half page `vaddr` with the caches disabled: the
/// display's framebuffer, whose writes must reach the device. Like [`map_kernel_page`] otherwise.
#[cfg(target_arch = "x86")]
pub fn map_kernel_page_uncached(vaddr: u32, frame_phys: u32) {
    with_database(|database| {
        let Parts {
            frames, scratch, ..
        } = database.parts();
        map_kernel_page_pte_in(frames, scratch, vaddr, Pte::kernel_rw_uncached(frame_phys));
    });
}

/// Map `bytes` of physical memory from `base_phys` into the framebuffer region
/// ([`layout::FRAMEBUFFER`]), uncached, starting at the region's first page; the region's tables
/// exist from boot, so this works in any address space. The region's virtual start is returned.
/// The size comes from the VBE mode information, so the page count is computed, never assumed.
///
/// # Panics
///
/// `base_phys` is not page-aligned, `bytes` is zero, the range runs past the region's end, or a
/// page of it is mapped already.
#[cfg(target_arch = "x86")]
pub fn map_framebuffer(base_phys: u32, bytes: u32) -> u32 {
    assert!(
        base_phys % PAGE_SIZE == 0,
        "framebuffer base not page-aligned"
    );
    assert!(bytes > 0, "an empty framebuffer");
    let pages = (bytes as u64).div_ceil(PAGE_SIZE as u64);
    assert!(
        pages * PAGE_SIZE as u64 <= layout::FRAMEBUFFER.size() as u64,
        "the framebuffer ({pages} pages) does not fit its region"
    );
    for page in 0..pages as u32 {
        map_kernel_page_uncached(
            layout::FRAMEBUFFER.start + page * PAGE_SIZE,
            base_phys + page * PAGE_SIZE,
        );
    }
    layout::FRAMEBUFFER.start
}

/// Re-install the low identity window (physical `[0, 16 MiB)` at its own addresses) in the current
/// directory, pointing its first entries at the boot directory's identity tables again: the
/// real-mode trampoline runs with paging off, where addresses are physical. Removed by
/// [`remove_low_identity`] before ring 3 runs again. The boot's own install lives in the boot
/// directory's construction ([`BootTables::fill_directory`]); this is the runtime form.
#[cfg(target_arch = "x86")]
pub fn install_low_identity() {
    for (i, &table) in boot_directory().identity.iter().enumerate() {
        self_map::set_pde(i, Pte::kernel_rw(table));
    }
    reload_cr3();
}

/// Remove the low identity window from the current directory (the trampoline's
/// [`install_low_identity`]): entries `[0, BOOT_TABLE_COUNT)` cleared, TLB flushed.
#[cfg(target_arch = "x86")]
pub fn remove_low_identity() {
    for entry in 0..BOOT_TABLE_COUNT {
        self_map::set_pde(entry, Pte::EMPTY);
    }
    reload_cr3();
}

/// The current directory's physical address (CR3's frame).
#[cfg(target_arch = "x86")]
pub fn current_directory_phys() -> u32 {
    let cr3: u32;
    // SAFETY: reading CR3 changes nothing.
    unsafe { asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags)) };
    directory_cr3(cr3)
}

/// Reload CR3 with the current directory, flushing the TLB.
#[cfg(target_arch = "x86")]
fn reload_cr3() {
    let cr3: u32;
    // SAFETY: reading CR3 changes nothing; reloading it with the current directory keeps every
    // present mapping (the kernel half above all) in place.
    unsafe {
        asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags));
        asm!("mov cr3, {}", in(reg) cr3, options(nostack, preserves_flags));
    }
}

/// Remove the kernel-half mapping at `vaddr` from the current directory and flush it from the TLB,
/// returning the frame it named. The frame itself is the caller's to release. The callers,
/// [`unmap_gate_slot`] and [`unmap_pool_page`], run under the memory manager's database borrow with
/// interrupts masked, so nothing else touches the entry meanwhile.
///
/// # Panics
///
/// The same window rules as [`map_kernel_page`], or nothing mapped at `vaddr`.
#[cfg(target_arch = "x86")]
pub fn unmap_kernel_page(vaddr: u32) -> u32 {
    assert!(vaddr % PAGE_SIZE == 0, "kernel address not page-aligned");
    let window = (vaddr >> 22) as usize;
    assert!(
        vaddr >= KERNEL_BASE,
        "kernel mappings live in the kernel half"
    );
    assert!(
        !layout::KERNEL_IMAGE.holds_entry(window),
        "kernel unmapping collides with the static kernel image window"
    );
    assert!(
        window != SELF_MAP_SLOT && window != SCRATCH_SLOT,
        "kernel unmapping collides with the runtime access windows"
    );

    let pte = self_map::pte(vaddr)
        .filter(|pte| pte.present())
        .expect("kernel page not mapped");
    self_map::set_pte(vaddr, Pte::EMPTY);
    invlpg(vaddr);
    pte.frame()
}

/// Unmap gate-stack slot `index`'s pages from the shared tables, so from every address space: the
/// inverse of [`map_gate_slot`]. Each page's TLB entry is flushed here; one cached under another
/// directory goes with the CR3 load that switches back to it (one processor, and no F2K mapping is
/// global). Returns the frames that were mapped, for the owner to release. Never call it on the
/// slot the processor is running on.
///
/// # Panics
///
/// The index is past the region's capacity, or a slot page is not mapped.
#[cfg(target_arch = "x86")]
pub fn unmap_gate_slot(index: u32) -> [u32; GATE_STACK_PAGES] {
    assert!(
        (index as usize) < GATE_SLOT_CAPACITY,
        "gate-slot index past the region's capacity"
    );
    let base = gate_slot_base(index);
    let mut frames = [0u32; GATE_STACK_PAGES];
    for (i, slot) in frames.iter_mut().enumerate() {
        *slot = unmap_kernel_page(base + ((i + 1) as u32) * PAGE_SIZE);
    }
    frames
}

/// Map a fresh gate-stack slot `index` into the shared tables, so into every address space at once:
/// one frame per page from `frames`, zeroed through `scratch`, supervisor-only, above the slot's
/// unmapped guard page. Returns the frames for the owner thread to release at its exit.
///
/// # Panics
///
/// The index is past the region's capacity, or the region's tables are not made yet
/// ([`init_kernel_stack_tables`]).
#[cfg(target_arch = "x86")]
pub fn map_gate_slot(
    frames: &mut FrameDb,
    scratch: &mut ScratchWindow,
    index: u32,
) -> [u32; GATE_STACK_PAGES] {
    assert!(
        (index as usize) < GATE_SLOT_CAPACITY,
        "gate-slot index past the region's capacity"
    );
    assert!(
        kernel_stack_tables_installed(),
        "a gate stack mapped before the kernel stack tables are made"
    );
    let base = gate_slot_base(index);
    let mut stack = [0u32; GATE_STACK_PAGES];
    for (i, slot) in stack.iter_mut().enumerate() {
        let frame = allocate_in(frames);
        scratch.init_frame(frame, 0, &[]);
        map_kernel_page_in(frames, scratch, base + ((i + 1) as u32) * PAGE_SIZE, frame);
        *slot = frame;
    }
    stack
}

/// A frame for a nonpaged pool page, from `frames`; none when the frame database has none left
/// (the pool's caller answers that as a status, not a panic).
#[cfg(target_arch = "x86")]
pub fn try_allocate_frame(frames: &mut FrameDb) -> Option<u32> {
    frames
        .try_allocate(PRIMARY_COLOR)
        .map(|frame| frame * PAGE_SIZE)
}

/// Map the frame `frame_phys`, zeroed through `scratch` first, at the nonpaged pool's page
/// `vaddr` in the shared tables, so into every address space at once (supervisor-only).
///
/// # Panics
///
/// `vaddr` lies outside the pool's region, or is mapped already.
#[cfg(target_arch = "x86")]
pub fn map_pool_page(
    frames: &mut FrameDb,
    scratch: &mut ScratchWindow,
    vaddr: u32,
    frame_phys: u32,
) {
    assert!(
        layout::NONPAGED_POOL.holds(vaddr),
        "a pool page outside the nonpaged pool"
    );
    scratch.init_frame(frame_phys, 0, &[]);
    map_kernel_page_in(frames, scratch, vaddr, frame_phys);
}

/// Unmap the nonpaged pool's page `vaddr` from the shared tables, so from every address space:
/// the frame it mapped, for the caller to release.
///
/// # Panics
///
/// `vaddr` lies outside the pool's region, or is not mapped.
#[cfg(target_arch = "x86")]
pub fn unmap_pool_page(vaddr: u32) -> u32 {
    assert!(
        layout::NONPAGED_POOL.holds(vaddr),
        "a pool page outside the nonpaged pool"
    );
    unmap_kernel_page(vaddr)
}

/// Map the physical page at `phys` (a device register range's page) at the MMIO region's page
/// `vaddr` in the shared tables, so into every address space at once (supervisor-only); uncached
/// (PCD) unless `cache_enable`. The frame is device memory already owned by the caller — no frame
/// is allocated or released here, only the entry. The bridge to [`map_mmio_page_in`].
///
/// # Panics
///
/// `vaddr` lies outside the MMIO region, is mapped already, or `phys` is not page-aligned.
#[cfg(target_arch = "x86")]
pub fn map_mmio_page(vaddr: u32, phys: u32, cache_enable: bool) {
    with_database(|database| {
        let Parts {
            frames, scratch, ..
        } = database.parts();
        map_mmio_page_in(frames, scratch, vaddr, phys, cache_enable);
    });
}

/// [`map_mmio_page`]'s work, on the parts the caller holds (a new table's frame would come from
/// them; the region's tables are made at boot, so none is needed in practice).
#[cfg(target_arch = "x86")]
pub fn map_mmio_page_in(
    frames: &mut FrameDb,
    scratch: &mut ScratchWindow,
    vaddr: u32,
    phys: u32,
    cache_enable: bool,
) {
    assert!(
        layout::MMIO.holds(vaddr),
        "an MMIO page outside the MMIO region"
    );
    let entry = if cache_enable {
        Pte::kernel_rw(phys)
    } else {
        Pte::kernel_rw_uncached(phys)
    };
    map_kernel_page_pte_in(frames, scratch, vaddr, entry);
}

/// Unmap the MMIO region's page `vaddr` from the shared tables, so from every address space; the
/// physical page it named (device memory, the caller's to keep). The MmUnmapIoSpace entry will
/// call it; nothing does yet.
///
/// # Panics
///
/// `vaddr` lies outside the MMIO region, or is not mapped.
#[cfg(target_arch = "x86")]
#[cfg_attr(not(test), allow(dead_code))]
pub fn unmap_mmio_page(vaddr: u32) -> u32 {
    assert!(
        layout::MMIO.holds(vaddr),
        "an MMIO page outside the MMIO region"
    );
    unmap_kernel_page(vaddr)
}

/// The physical address a kernel-half virtual address maps to, through the current directory's
/// page tables (the kernel half's tables are shared, so this is every directory's answer): the
/// bus address of the byte on this platform, where no IOMMU sits between the devices and memory
/// (identity). None when the address is not mapped present.
#[cfg(target_arch = "x86")]
pub fn translate_kernel_address(vaddr: u32) -> Option<u32> {
    assert!(vaddr >= KERNEL_BASE, "a user address has no kernel mapping");
    let pte = self_map::pte(vaddr)?;
    if !pte.present() {
        return None;
    }
    Some(pte.frame() | (vaddr & (PAGE_SIZE - 1)))
}

/// Whether the current directory holds every table of the kernel stack region.
#[cfg(target_arch = "x86")]
fn kernel_stack_tables_installed() -> bool {
    (layout::KERNEL_STACKS.first_entry()..layout::KERNEL_STACKS.end_entry())
        .all(|window| self_map::pde(window).present())
}

/// Whether gate-stack slot `index` is mapped in the current directory as [`map_gate_slot`] leaves
/// it: every stack page present, the guard page below them not.
#[cfg(target_arch = "x86")]
pub fn gate_slot_mapped(index: u32) -> bool {
    let base = gate_slot_base(index);
    let present = |vaddr: u32| self_map::pte(vaddr).is_some_and(Pte::present);
    !present(base) && (1..=GATE_STACK_PAGES as u32).all(|page| present(base + page * PAGE_SIZE))
}

/// Read word `index` of `frame_phys` through the scratch window: the one-page alias of any frame,
/// used by the teardown walk to read a dead process's directory and tables without mapping them.
/// The bridge to [`ScratchWindow::read_word`].
///
/// # Panics
///
/// `index` past the frame's end.
#[cfg(target_arch = "x86")]
pub fn read_frame_word(frame_phys: u32, index: usize) -> u32 {
    with_database(|database| database.scratch.read_word(frame_phys, index))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Identity table `index` as the boot builds it, over a frame holding garbage.
    fn identity(index: usize) -> Box<[u32; PT_ENTRIES]> {
        let mut table = Box::new([0xDEAD_BEEFu32; PT_ENTRIES]);
        BootTables::fill_identity(index, &mut table);
        table
    }

    /// One boot table per entry of the kernel image window: four, 16 MiB.
    #[test]
    fn the_boot_tables_cover_the_image_window() {
        assert_eq!(BOOT_TABLE_COUNT, 4);
        assert_eq!(
            (BOOT_TABLE_COUNT * PT_ENTRIES) as u32 * PAGE_SIZE,
            layout::KERNEL_IMAGE.size()
        );
    }

    #[test]
    fn the_first_table_maps_the_low_4mib_identity() {
        let low = identity(0);
        assert_eq!(low[0], 0x0000_0000 | PAGE_PRESENT | PAGE_WRITE);
        assert_eq!(low[256], 0x0010_0000 | PAGE_PRESENT | PAGE_WRITE);
        assert_eq!(low[1023], 0x003F_F000 | PAGE_PRESENT | PAGE_WRITE);
    }

    #[test]
    fn the_later_tables_map_the_next_4mib_each() {
        assert_eq!(identity(1)[0], 0x0040_0000 | PAGE_PRESENT | PAGE_WRITE);
        assert_eq!(identity(1)[1023], 0x007F_F000 | PAGE_PRESENT | PAGE_WRITE);
        assert_eq!(identity(2)[0], 0x0080_0000 | PAGE_PRESENT | PAGE_WRITE);
        assert_eq!(identity(3)[1023], 0x00FF_F000 | PAGE_PRESENT | PAGE_WRITE);
    }

    #[test]
    fn every_entry_is_present_writable_and_in_window() {
        for t in 0..BOOT_TABLE_COUNT {
            for (i, &entry) in identity(t).iter().enumerate() {
                assert_eq!(entry & PAGE_ADDR_MASK, ((t * PT_ENTRIES + i) * 4096) as u32);
                assert_eq!(entry & !PAGE_ADDR_MASK, PAGE_PRESENT | PAGE_WRITE);
            }
        }
    }

    /// The boot tables from a frame-allocator stand-in handing out the frames `frames` names, in
    /// order.
    fn allocated(frames: &[u32]) -> BootTables {
        let mut next = frames.iter().copied();
        BootTables::allocate(|| next.next().expect("the stand-in ran out of frames"))
    }

    /// The frames are taken in order: the directory, the identity tables, the scratch table.
    #[test]
    fn the_boot_tables_take_their_frames_in_order() {
        let tables = allocated(&[
            0x7F_0000, 0x7E_0000, 0x7D_0000, 0x10_5000, 0x20_0000, 0x3000,
        ]);
        assert_eq!(
            tables,
            BootTables {
                directory: 0x7F_0000,
                identity: [0x7E_0000, 0x7D_0000, 0x10_5000, 0x20_0000],
                scratch: 0x3000,
            }
        );
    }

    /// The built directory holds exactly the boot loader's picture plus the self-map: the low
    /// identity window's entries and the kernel image window's at the allocated identity
    /// tables, in order, the self-map entry at the directory's own frame, and nothing else
    /// (whatever the frame held before).
    #[test]
    fn the_boot_directory_names_its_own_tables_and_nothing_else() {
        let tables = allocated(&[
            0xFF_F000, 0xFF_E000, 0xFF_D000, 0xFF_C000, 0xFF_B000, 0xFF_A000,
        ]);
        let mut directory = Box::new([0xDEAD_BEEFu32; PT_ENTRIES]);
        tables.fill_directory(&mut directory);

        let image = layout::KERNEL_IMAGE.first_entry();
        assert_eq!(image, 512);
        let mut expected = [0u32; PT_ENTRIES];
        for (i, table) in [0xFF_E000, 0xFF_D000, 0xFF_C000, 0xFF_B000]
            .into_iter()
            .enumerate()
        {
            expected[i] = table | PAGE_PRESENT | PAGE_WRITE;
            expected[image + i] = table | PAGE_PRESENT | PAGE_WRITE;
        }
        expected[SELF_MAP_SLOT] = 0xFF_F000 | PAGE_PRESENT | PAGE_WRITE;
        assert_eq!(*directory, expected);
        // The scratch table is installed later, by the table access's own step.
        assert_eq!(directory[SCRATCH_SLOT], 0);
        // No user bit anywhere: the low window is the kernel's until its teardown.
        assert!(directory.iter().all(|&entry| entry & PAGE_USER == 0));
    }

    /// A process directory built over the boot directory inherits its kernel window, with the
    /// identity tables the boot allocated.
    #[test]
    fn process_directories_inherit_the_boot_directorys_kernel_window() {
        let tables = allocated(&[
            0x50_0000, 0x51_0000, 0x52_0000, 0x53_0000, 0x54_0000, 0x55_0000,
        ]);
        let mut boot = Box::new([0u32; PT_ENTRIES]);
        tables.fill_directory(&mut boot);
        let process = assembled(&boot, 0x60_0000, tables.scratch);
        let image = layout::KERNEL_IMAGE.first_entry();
        for (i, &table) in tables.identity.iter().enumerate() {
            assert_eq!(Pte::from_raw(process[image + i]).frame(), table);
            assert_eq!(process[i], 0, "the low window is not inherited");
        }
        assert_eq!(process[SELF_MAP_SLOT], Pte::kernel_rw(0x60_0000).raw());
        assert_eq!(process[SCRATCH_SLOT], Pte::kernel_rw(0x55_0000).raw());
    }

    /// The boot's frames come from below the window's end, the highest free one first, and leave
    /// the free lists; none when the window holds no free frame.
    #[test]
    fn window_frames_are_the_highest_free_ones_below_the_limit() {
        use crate::mem::frame::{
            ColorTables,
            FrameEntry,
            FrameState,
            NoHooks,
            DEFAULT_COLOR_COUNT,
        };
        let table: &'static mut [FrameEntry] =
            Box::leak(vec![FrameEntry::new(); 0x2000].into_boxed_slice());
        let buckets: &'static mut ColorTables = Box::leak(Box::new(ColorTables::new()));
        let mut db = FrameDb::new(table, buckets, DEFAULT_COLOR_COUNT, NoHooks);
        for frame in [5, 9, 0xFFE, 0x1000, 0x1800] {
            db.release(frame, FrameState::Free);
        }
        let available = db.available();

        assert_eq!(take_window_frame(&mut db, 0x1000), Some(0xFFE * PAGE_SIZE));
        assert_eq!(db.entry(0xFFE).state, FrameState::Active);
        assert_eq!(take_window_frame(&mut db, 0x1000), Some(9 * PAGE_SIZE));
        assert_eq!(take_window_frame(&mut db, 0x1000), Some(5 * PAGE_SIZE));
        assert_eq!(take_window_frame(&mut db, 0x1000), None);
        assert_eq!(db.available(), available - 3);
        // The frames past the window stay free.
        assert_eq!(db.entry(0x1000).state, FrameState::Free);
        assert_eq!(db.entry(0x1800).state, FrameState::Free);
        assert_eq!(db.audit(), Ok(()));
    }

    /// The image window's frame count is its 16 MiB.
    #[test]
    fn the_image_window_holds_4096_frames() {
        assert_eq!(IMAGE_WINDOW_FRAMES, 4096);
    }

    /// Independent bit check: entry bit 0 is present, bit 1 is R/W, bit 2 is user/supervisor. The
    /// constants must name exactly those.
    #[test]
    fn flag_bits_match_the_x86_entry_layout() {
        assert_eq!(PAGE_PRESENT, 1);
        assert_eq!(PAGE_WRITE, 1 << 1);
        assert_eq!(PAGE_USER, 1 << 2);
        // Read-only user page, the strictest mapping a user entry carries: present + user.
        assert_eq!(PAGE_PRESENT | PAGE_USER, 0x5);
        // Writable user page: present + R/W + user.
        assert_eq!(PAGE_PRESENT | PAGE_WRITE | PAGE_USER, 0x7);
    }

    /// The entry type builds the bits above: the kernel's entries present and writable without the
    /// user bit, a user entry present with it, and the frame read back from the address bits
    /// whether the entry is present or not.
    #[test]
    fn entries_carry_their_frame_and_flags() {
        let kernel = Pte::kernel_rw(0x0090_0000);
        assert_eq!(kernel.raw(), 0x0090_0000 | PAGE_PRESENT | PAGE_WRITE);
        assert!(kernel.present());
        assert_eq!(kernel.frame(), 0x0090_0000);

        assert_eq!(Pte::user(0x0050_0000, 0).raw(), 0x0050_0005);
        assert_eq!(Pte::user(0x0050_0000, PAGE_WRITE).raw(), 0x0050_0007);

        let committed = Pte::from_raw(0x0070_0000 | PAGE_WRITE);
        assert!(!committed.present());
        assert_eq!(committed.frame(), 0x0070_0000);
        assert!(!Pte::EMPTY.present());
        assert_eq!(Pte::EMPTY.raw(), 0);
    }

    /// The self-map and scratch slots sit at the NT-style addresses (0xC0000000 and 0xC0400000,
    /// where Windows executables and tooling expect them), in the kernel half, distinct from the
    /// image window's entries (512-515) and from each other.
    #[test]
    fn runtime_access_slots_are_well_placed() {
        assert_eq!(SELF_MAP_SLOT, 768);
        assert_eq!(SCRATCH_SLOT, 769);
        assert_eq!(SELF_MAP_VA, 0xC000_0000);
        assert_eq!(SCRATCH_VA, 0xC040_0000);
        assert!(SELF_MAP_VA >= KERNEL_BASE);
        assert!(SCRATCH_VA > SELF_MAP_VA);
        for slot in [SELF_MAP_SLOT, SCRATCH_SLOT] {
            assert!(!layout::KERNEL_IMAGE.holds_entry(slot) && slot < PT_ENTRIES);
        }
    }

    /// Directory-entry arithmetic the runtime code relies on: SELF_MAP_VA + window*4096 addresses
    /// that window's page table, and DIRECTORY_ENTRY_VA + index*4 addresses a directory entry of
    /// the current directory.
    #[test]
    fn self_map_addresses_directory_and_tables() {
        for window in [0usize, 1, 2, 511, 512, 1021] {
            let table_va = SELF_MAP_VA + ((window as u32) << 12);
            assert_eq!(table_va, 0xC000_0000 + (window as u32) * 4096);
            // The table page stays inside the self-map's own 4 MiB.
            assert!(table_va >= SELF_MAP_VA);
            assert!(table_va < SELF_MAP_VA + (1 << 22));
        }
        assert_eq!(DIRECTORY_ENTRY_VA, 0xC030_0000);
        for index in [0usize, 512, 767, 1023] {
            let entry_va = DIRECTORY_ENTRY_VA + (index as u32) * 4;
            // The entry word stays on the directory's view page.
            assert!(entry_va >= DIRECTORY_ENTRY_VA);
            assert!(entry_va < DIRECTORY_ENTRY_VA + 4096);
        }
    }

    /// Assemble a directory from `base` into a buffer pre-filled with garbage: creation must not
    /// depend on the target frame's prior contents.
    fn assembled(base: &[u32; PT_ENTRIES], own: u32, scratch: u32) -> [u32; PT_ENTRIES] {
        let mut dir = [0xDEAD_BEEF; PT_ENTRIES];
        assemble_process_directory(&mut dir, own, scratch, |i| base[i]);
        dir
    }

    /// The kernel half is inherited wholesale except the two runtime slots, the kernel stack
    /// region's shared tables included; the user half starts zero no matter what the target frame
    /// held before.
    #[test]
    fn process_directory_inherits_the_kernel_half_and_zeroes_the_user_half() {
        let stacks = layout::KERNEL_STACKS;
        let mut base = [0u32; PT_ENTRIES];
        base[512] = 0x0010_1000 | PAGE_PRESENT | PAGE_WRITE;
        base[513] = 0x0050_1000 | PAGE_PRESENT | PAGE_WRITE;
        base[700] = 0x0090_0000 | PAGE_PRESENT | PAGE_WRITE | PAGE_USER;
        for (i, entry) in (stacks.first_entry()..stacks.end_entry()).enumerate() {
            base[entry] = (0x00C0_0000 + i as u32 * PAGE_SIZE) | PAGE_PRESENT | PAGE_WRITE;
        }
        base[1023] = 0x00B0_0000 | PAGE_PRESENT | PAGE_WRITE;
        let dir = assembled(&base, 0x9000, 0xB000);

        for i in 0..PT_ENTRIES {
            if i == SELF_MAP_SLOT || i == SCRATCH_SLOT {
                continue;
            }
            let expected = if i < KERNEL_HALF_START { 0 } else { base[i] };
            assert_eq!(dir[i], expected, "entry {i}");
        }
    }

    /// The self-map entry points at the directory's own frame; the scratch entry at the shared
    /// scratch table. Both carry exactly present+writable: no user bit (kernel-only windows) and no
    /// global bit (every entry must leave the TLB on a CR3 reload).
    #[test]
    fn runtime_slots_point_at_the_directory_and_the_shared_scratch_table() {
        let dir = assembled(&[0; PT_ENTRIES], 0x0090_0000, 0x00B0_0000);
        assert_eq!(dir[SELF_MAP_SLOT], 0x0090_0000 | PAGE_PRESENT | PAGE_WRITE);
        assert_eq!(dir[SCRATCH_SLOT], 0x00B0_0000 | PAGE_PRESENT | PAGE_WRITE);
    }

    /// The directory doubles as window 768's own page table (its self-map entry points at itself),
    /// so it is reachable at a second fixed window: directory entry i resolves at
    /// DIRECTORY_ENTRY_VA + i*4, which is how `create_address_space` reads the base and
    /// `set_user_pte` writes window entries — going through the self-map entry itself, never
    /// through user windows that may be unmapped.
    #[test]
    fn the_directory_is_reachable_through_its_own_window() {
        assert_eq!(
            DIRECTORY_ENTRY_VA,
            SELF_MAP_VA + ((SELF_MAP_SLOT as u32) << 12)
        );
        assert_eq!(DIRECTORY_ENTRY_VA, 0xC030_0000);
        assert_eq!(KERNEL_HALF_START, (KERNEL_BASE >> 22) as usize);
        assert_eq!(KERNEL_HALF_START, 512);
        // The view stays inside the self-map's 4 MiB, above the user window tables and below the
        // scratch window's tables.
        assert!(DIRECTORY_ENTRY_VA >= SELF_MAP_VA + (KERNEL_HALF_START as u32) * 4096);
        assert!(DIRECTORY_ENTRY_VA < SCRATCH_VA);
    }

    /// Two directories from the same base share the kernel half (the same user VAs resolve through
    /// different tables) but each self-map points at its own directory. This is the layout root of
    /// two processes linking at the same image base.
    #[test]
    fn sibling_directories_share_the_kernel_half_but_not_their_self_maps() {
        let mut base = [0u32; PT_ENTRIES];
        base[512] = 0x0010_1000 | PAGE_PRESENT | PAGE_WRITE;
        base[513] = 0x0050_1000 | PAGE_PRESENT | PAGE_WRITE;
        let first = assembled(&base, 0x0090_0000, 0x00B0_0000);
        let second = assembled(&base, 0x0095_0000, 0x00B0_0000);

        for i in KERNEL_HALF_START..PT_ENTRIES {
            if i == SELF_MAP_SLOT {
                assert_eq!(first[i] & PAGE_ADDR_MASK, 0x0090_0000);
                assert_eq!(second[i] & PAGE_ADDR_MASK, 0x0095_0000);
            } else {
                assert_eq!(first[i], second[i], "entry {i}");
            }
        }
        for i in 0..KERNEL_HALF_START {
            assert_eq!(first[i], 0);
            assert_eq!(second[i], 0);
        }
    }

    /// The kernel stack region's tables, made at boot in the base, are every directory's: two
    /// processes' directories assembled from it name the same four tables, so a stack mapped for a
    /// thread of the first is mapped in the second — a slot straddling two tables included.
    #[test]
    fn every_directory_inherits_the_kernel_stack_tables() {
        let stacks = layout::KERNEL_STACKS;
        let mut base = [0u32; PT_ENTRIES];
        base[512] = 0x0010_1000 | PAGE_PRESENT | PAGE_WRITE;
        let tables: Vec<u32> = (0..stacks.entries as u32)
            .map(|i| 0x00C0_0000 + i * PAGE_SIZE)
            .collect();
        for (entry, table) in (stacks.first_entry()..stacks.end_entry()).zip(&tables) {
            base[entry] = table | PAGE_PRESENT | PAGE_WRITE;
        }
        let first = assembled(&base, 0x0090_0000, 0x00B0_0000);
        let second = assembled(&base, 0x0095_0000, 0x00B0_0000);

        for (entry, table) in (stacks.first_entry()..stacks.end_entry()).zip(&tables) {
            for dir in [&first, &second] {
                assert_eq!(
                    dir[entry],
                    table | PAGE_PRESENT | PAGE_WRITE,
                    "entry {entry}"
                );
            }
        }
        let straddling = (0..GATE_SLOT_CAPACITY as u32)
            .find(|&index| gate_slot_base(index) >> 22 != (gate_slot_top(index) - 1) >> 22)
            .expect("a slot straddles a table boundary");
        for vaddr in [gate_slot_base(straddling), gate_slot_top(straddling) - 1] {
            let window = (vaddr >> 22) as usize;
            assert!(stacks.holds_entry(window));
            assert_eq!(first[window], second[window]);
            assert_ne!(first[window] & PAGE_PRESENT, 0);
        }
    }

    /// The CR3 value is the directory's address bits only: low flag bits from a sloppy caller must
    /// not reach the load.
    #[test]
    fn directory_cr3_masks_the_flag_bits() {
        assert_eq!(directory_cr3(0x0090_0000), 0x0090_0000);
        assert_eq!(directory_cr3(0x0090_0007), 0x0090_0000);
        assert_eq!(directory_cr3(0xFFFF_F005), 0xFFFF_F000);
        assert_eq!(directory_cr3(0), 0);
    }

    /// The gate stack window: the kernel stack region (entries 656-659, from 0xA4000000: clear of
    /// the image window and the runtime access slots), with an unmapped guard page at each slot's
    /// base and the 32 KiB stack above it — a gate-stack overflow faults into the guard instead of
    /// corrupting whatever lies below.
    #[test]
    fn gate_stack_window_layout() {
        assert_eq!(GATE_STACK_WINDOW, 0xA400_0000);
        assert_eq!((GATE_STACK_WINDOW >> 22) as usize, 656);
        assert_eq!(
            (GATE_STACK_WINDOW >> 22) as usize,
            layout::KERNEL_STACKS.first_entry()
        );
        assert!(!layout::KERNEL_IMAGE.holds(GATE_STACK_WINDOW));
        for reserved in [SELF_MAP_SLOT, SCRATCH_SLOT] {
            assert_ne!((GATE_STACK_WINDOW >> 22) as usize, reserved);
        }
        assert_eq!(GATE_STACK_PAGES, 8);
        assert_eq!(GATE_STACK_TOP, GATE_STACK_WINDOW + 9 * PAGE_SIZE);
        assert_eq!(GATE_STACK_TOP, 0xA400_9000);
        // Every thread record of the system fits.
        assert!(GATE_SLOT_CAPACITY > crate::ob::THREADS);
        // Everything (guard + stack) stays inside the region.
        assert!(gate_slot_top(GATE_SLOT_CAPACITY as u32 - 1) as u64 <= layout::KERNEL_STACKS.end());
    }
}
