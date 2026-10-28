//! Paging: the kernel window and the runtime user mappings.
//!
//! 32-bit x86 two-level paging, 4 KiB pages. The kernel half's regions are laid out in
//! [`crate::mem::layout`]. The kernel is linked at `KERNEL_BASE + 1 MiB` and runs there; the boot
//! trampoline builds the initial directory:
//!
//! - `[0, 16 MiB)`: physical identity, the boot transition window (entry stub, Multiboot info)
//!   until [`teardown_low_identity`] removes it;
//! - `[KERNEL_BASE, KERNEL_BASE + 16 MiB)`: the kernel image window ([`layout::KERNEL_IMAGE`]) over
//!   physical `[0, 16 MiB)`.
//!
//! The boot tables are link-time identity constants; the directory is filled by the entry stub,
//! which addresses it physically before paging is on. Everything below `KERNEL_BASE` is unmapped
//! after the teardown; user pages and their tables are created at runtime ([`init_frame`],
//! [`set_user_pte`]). The user entries' only writer is the address-space manager
//! ([`crate::mem::vm`]): the raw entry access here serves it alone.

#[cfg(target_arch = "x86")]
use core::arch::asm;
#[cfg(target_arch = "x86")]
use core::sync::atomic::{AtomicBool, Ordering};

use super::layout;

/// Virtual base of kernel space (user space is the low 2 GiB): the kernel image window's start.
pub const KERNEL_BASE: u32 = layout::KERNEL_IMAGE.start;

/// Physical load address of the kernel image (also the start of the frames the kernel occupies).
pub const KERNEL_PHYS_BASE: u32 = 0x0010_0000;

/// Page-table flag: page/directory entry is present.
pub const PAGE_PRESENT: u32 = 1 << 0;
/// Entry bit 1: writable.
pub const PAGE_WRITE: u32 = 1 << 1;
/// Entry bit 2: user-accessible (supervisor-only when clear).
pub const PAGE_USER: u32 = 1 << 2;
/// Mask selecting the address bits of a page-table entry.
pub const PAGE_ADDR_MASK: u32 = 0xFFFF_F000;

/// Page-table entries per table (32-bit paging: 1024).
pub const PT_ENTRIES: usize = 1024;

/// Page size (32-bit paging: 4 KiB).
pub const PAGE_SIZE: u32 = 4096;

/// Build one page table mapping `first_page + i` to physical page `first_page + i` (identity), for
/// i in 0..1024.
const fn identity_page_table(first_page: usize) -> [u32; PT_ENTRIES] {
    let mut table = [0u32; PT_ENTRIES];
    let mut i = 0;
    while i < PT_ENTRIES {
        table[i] = ((first_page + i) * 4096) as u32 | PAGE_PRESENT | PAGE_WRITE;
        i += 1;
    }
    table
}

/// 4 KiB-aligned wrapper: CR3 and directory entries require page-aligned tables.
#[repr(align(4096))]
pub struct Aligned<T>(pub T);

/// How many boot page tables there are: one per directory entry of the kernel image window, each
/// mapping 4 MiB of physical `[0, 16 MiB)`.
pub const BOOT_TABLE_COUNT: usize = layout::KERNEL_IMAGE.entries;

/// The boot tables' contents: table `t` maps pages `[t * 1024, (t + 1) * 1024)` to themselves.
const fn boot_tables() -> [[u32; PT_ENTRIES]; BOOT_TABLE_COUNT] {
    let mut tables = [[0u32; PT_ENTRIES]; BOOT_TABLE_COUNT];
    let mut t = 0;
    while t < BOOT_TABLE_COUNT {
        tables[t] = identity_page_table(t * PT_ENTRIES);
        t += 1;
    }
    tables
}

/// The boot page tables, mapping physical `[0, 16 MiB)` 4 MiB apiece. The entry stub points the
/// low identity window's entries and the kernel image window's at them, in order; each table is
/// one page, so every one of them is page-aligned.
#[no_mangle]
pub static BOOT_TABLES: Aligned<[[u32; PT_ENTRIES]; BOOT_TABLE_COUNT]> = Aligned(boot_tables());

/// The boot page directory. Zero-initialized; the entry stub fills entries `[0, BOOT_TABLE_COUNT)`
/// (low identity window) and the kernel image window's, all pointing at [`BOOT_TABLES`].
#[no_mangle]
pub static mut BOOT_PD: Aligned<[u32; PT_ENTRIES]> = Aligned([0; PT_ENTRIES]);

/// Remove the low identity window (called once the Multiboot info is consumed): clears entries
/// `[0, BOOT_TABLE_COUNT)` and flushes the TLB via a CR3 reload. User space is unmapped from here
/// on.
#[cfg(target_arch = "x86")]
pub fn teardown_low_identity() {
    // SAFETY: the boot context is the only mutator of the directory; paging is on and the kernel
    // window entries are live.
    let pd = &mut unsafe { &mut *core::ptr::addr_of_mut!(BOOT_PD) }.0;

    // The kernel window must be established before the low window goes away; this also catches a
    // directory the stub never filled.
    let image = layout::KERNEL_IMAGE.first_entry();
    for (i, table) in BOOT_TABLES.0.iter().enumerate() {
        assert_eq!(
            pd[image + i] & PAGE_ADDR_MASK,
            table.as_ptr() as u32 - KERNEL_BASE,
            "kernel window is not mapped"
        );
    }
    assert_ne!(pd[0], 0, "low identity window is already gone");

    for entry in &mut pd[..BOOT_TABLE_COUNT] {
        *entry = 0;
    }

    let pd_phys = pd.as_ptr() as u32 - KERNEL_BASE;
    // SAFETY: paging is on; reloading CR3 with the (same) directory flushes non-global TLB entries,
    // dropping the low mappings.
    unsafe {
        asm!("mov cr3, {pd}", pd = in(reg) pd_phys, options(nostack, preserves_flags));
    }
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

/// Install the self-map and the scratch table, once, right after [`teardown_low_identity`]. No TLB
/// flushes needed: neither window was mapped before.
#[cfg(target_arch = "x86")]
pub fn init_table_access() {
    // SAFETY: the boot context is the only mutator of the directory.
    let pd = &mut unsafe { &mut *core::ptr::addr_of_mut!(BOOT_PD) }.0;
    let pd_phys = pd.as_ptr() as u32 - KERNEL_BASE;
    assert_eq!(pd[SELF_MAP_SLOT], 0, "self-map already installed");
    assert_eq!(pd[SCRATCH_SLOT], 0, "scratch table already installed");

    // The scratch table is a kernel static (its frame is part of the image and never enters the
    // frame database), so it can be zeroed directly through the kernel window before it is
    // reachable through its own window. BSS is loader-zeroed in theory; zeroing explicitly keeps
    // that from being load-bearing.
    // SAFETY: the boot context is the only accessor.
    unsafe {
        let scratch = &mut *core::ptr::addr_of_mut!(SCRATCH_TABLE);
        for i in 0..PT_ENTRIES {
            scratch.0[i] = 0;
        }
        let scratch_table_phys = (scratch.0.as_mut_ptr() as u32) - KERNEL_BASE;

        // Both slots were asserted empty above.
        pd[SELF_MAP_SLOT] = pd_phys | PAGE_PRESENT | PAGE_WRITE;
        pd[SCRATCH_SLOT] = scratch_table_phys | PAGE_PRESENT | PAGE_WRITE;
    }
}

/// The scratch table: a kernel static (its frame never enters the frame database).
#[cfg(target_arch = "x86")]
static mut SCRATCH_TABLE: Aligned<[u32; PT_ENTRIES]> = Aligned([0; PT_ENTRIES]);

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
    for window in layout::KERNEL_STACKS.first_entry()..layout::KERNEL_STACKS.end_entry() {
        // Zeroed while still unreachable: no garbage entry may become walkable.
        let table_phys = allocate_frame_phys();
        init_frame(table_phys, 0, &[]);
        install_kernel_table(window, table_phys);
    }
}

/// Point the current directory's entry `window` at the page table `table_phys`: present, writable,
/// supervisor, not global.
///
/// # Panics
///
/// The entry is already present.
#[cfg(target_arch = "x86")]
fn install_kernel_table(window: usize, table_phys: u32) {
    assert_eq!(
        kernel_pde(window) & PAGE_PRESENT,
        0,
        "kernel-half table already installed"
    );
    // SAFETY: the self-map window is live in every directory, and the entry stays on the
    // directory's view page (`kernel_pde` checked the index); nothing maps through the entry
    // before it is written. Volatile: the CPU sets accessed bits on directory entries.
    unsafe {
        ((DIRECTORY_ENTRY_VA + (window as u32) * 4) as *mut u32)
            .write_volatile(table_phys | PAGE_PRESENT | PAGE_WRITE);
    }
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
unsafe fn invlpg(vaddr: u32) {
    // SAFETY: invlpg has no register side effects; the page's entry may or may not be cached, the
    // instruction tolerates both.
    unsafe {
        asm!("invlpg [{va}]", va = in(reg) vaddr, options(nostack, preserves_flags));
    }
}

/// One use of the scratch window: interrupts masked from the claim to its drop, then put back as
/// the claim found them. The window is one per processor, shared by every thread and by the idle
/// thread's loads, so nothing may run between pointing it at a frame and the last access through
/// it — as Windows uses its per-processor windows (hyperspace) at a raised level. A claim covers
/// one function's accesses and never a wait (a disk read): the frame's contents come in or go out
/// through the caller's buffer, never through a pointer into the window.
#[cfg(target_arch = "x86")]
struct ScratchClaim {
    /// Whether interrupts were enabled at the claim, in the level ledger.
    enabled: bool,
}

#[cfg(target_arch = "x86")]
impl ScratchClaim {
    /// Mask interrupts through the level ledger for the window's use. The ledger must agree with
    /// the processor's flag: the drop puts back what the ledger says, and a ledger that disagreed
    /// would leave interrupts enabled where the code before the claim had them masked, or the
    /// reverse.
    fn take() -> Self {
        let state = crate::interrupt::irql::state_mut();
        let enabled = state.interrupts_enabled();
        assert_eq!(
            enabled,
            !interrupts_masked(),
            "the level ledger disagrees with the interrupt flag"
        );
        state.mask_interrupts();
        ScratchClaim { enabled }
    }

    /// Point the window at `frame_phys` (page-aligned) and return its address: the frame,
    /// page-length, until the next `map` or the claim's drop.
    fn map(&self, frame_phys: u32) -> u32 {
        install_scratch(self, frame_phys);
        SCRATCH_VA
    }
}

#[cfg(target_arch = "x86")]
impl Drop for ScratchClaim {
    fn drop(&mut self) {
        if self.enabled {
            crate::interrupt::irql::state_mut().unmask_interrupts();
        }
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

/// Point scratch entry 0 at `frame_phys` and flush it, under `_claim` (interrupts masked: the
/// hardware flag is checked, not only the ledger).
#[cfg(target_arch = "x86")]
fn install_scratch(_claim: &ScratchClaim, frame_phys: u32) {
    assert!(
        interrupts_masked(),
        "the scratch window used with interrupts enabled"
    );
    // The scratch table's entry 0, reached through the self-map.
    // SAFETY: the self-map window is live in every directory; the claim makes this the window's
    // only user until it drops, and every use rewrites and flushes the entry.
    unsafe {
        let scratch_pte0 = (SELF_MAP_VA + ((SCRATCH_SLOT as u32) << 12)) as *mut u32;
        scratch_pte0.write_volatile(frame_phys | PAGE_PRESENT | PAGE_WRITE);
        invlpg(SCRATCH_VA);
    }
}

/// Zero a freshly allocated frame through the scratch alias, then copy `bytes` at `offset` (tables:
/// empty slice; image pages: bytes; data pages: zero fill).
#[cfg(target_arch = "x86")]
pub fn init_frame(frame_phys: u32, offset: usize, bytes: &[u8]) {
    assert!(frame_phys & (PAGE_SIZE - 1) == 0, "frame not page-aligned");
    assert!(
        offset + bytes.len() <= PAGE_SIZE as usize,
        "write past the end of the frame"
    );
    let claim = ScratchClaim::take();
    let window = claim.map(frame_phys);
    // SAFETY: the window aliases exactly this frame, page-length, for the claim's duration.
    unsafe {
        // One string store: a word loop is slow enough in a debug build to stretch every page
        // allocation. The asm is opaque to the compiler, so the stores cannot be elided.
        core::arch::asm!(
            "rep stosd",
            inout("ecx") PT_ENTRIES => _,
            inout("edi") window => _,
            in("eax") 0u32,
            options(nostack, preserves_flags),
        );
        let dst = window as *mut u8;
        for (i, &byte) in bytes.iter().enumerate() {
            dst.add(offset + i).write_volatile(byte);
        }
    }
}

/// Patch `bytes` into a frame at `offset` without zeroing (unlike [`init_frame`]); for building a
/// page in pieces.
#[cfg(target_arch = "x86")]
pub fn write_frame(frame_phys: u32, offset: usize, bytes: &[u8]) {
    assert!(frame_phys & (PAGE_SIZE - 1) == 0, "frame not page-aligned");
    assert!(
        offset + bytes.len() <= PAGE_SIZE as usize,
        "write past the end of the frame"
    );
    let claim = ScratchClaim::take();
    let window = claim.map(frame_phys);
    // SAFETY: the window aliases exactly this frame, page-length, for the claim's duration.
    unsafe {
        let dst = window as *mut u8;
        for (i, &byte) in bytes.iter().enumerate() {
            dst.add(offset + i).write_volatile(byte);
        }
    }
}

/// Read `out.len()` bytes of a frame at `offset`, through the scratch alias.
#[cfg(target_arch = "x86")]
pub fn read_frame(frame_phys: u32, offset: usize, out: &mut [u8]) {
    assert!(frame_phys & (PAGE_SIZE - 1) == 0, "frame not page-aligned");
    assert!(
        offset + out.len() <= PAGE_SIZE as usize,
        "read past the end of the frame"
    );
    let claim = ScratchClaim::take();
    let window = claim.map(frame_phys);
    // SAFETY: the window aliases exactly this frame, page-length, for the claim's duration.
    unsafe {
        let src = window as *const u8;
        for (i, slot) in out.iter_mut().enumerate() {
            *slot = src.add(offset + i).read_volatile();
        }
    }
}

/// Copy a whole frame's contents into another (a copy-on-write's private copy), through the
/// scratch alias a chunk at a time.
#[cfg(target_arch = "x86")]
pub fn copy_frame(from_phys: u32, to_phys: u32) {
    let mut chunk = [0u8; 512];
    for offset in (0..PAGE_SIZE as usize).step_by(chunk.len()) {
        read_frame(from_phys, offset, &mut chunk);
        write_frame(to_phys, offset, &chunk);
    }
}

/// Allocate one frame, physical address. Quirk: the database never zeroes frames, so the contents
/// are undefined until the caller runs [`init_frame`] — every frame handed to user space does.
#[cfg(target_arch = "x86")]
pub fn allocate_frame_phys() -> u32 {
    let frame =
        crate::mem::bootmem::with_frame_db(|db| db.allocate(crate::mem::frame::PRIMARY_COLOR));
    frame * PAGE_SIZE
}

/// The current directory's page-table entry for user address `vaddr`, raw (present or not); 0 when
/// its window has no table.
///
/// Both the window's directory entry (DIRECTORY_ENTRY_VA + window*4, through the directory's own
/// self-map slot) and its page table (SELF_MAP_VA + window*4096, through the self-map window) are
/// reached through the **current** directory — the one CR3 points at — so the access targets the
/// active process's address space. The CPU may set accessed/dirty bits on any entry as a side
/// effect of ordinary memory traffic, so all reads and writes are volatile.
#[cfg(target_arch = "x86")]
pub fn user_pte(vaddr: u32) -> u32 {
    assert!(
        vaddr < KERNEL_BASE,
        "user entries live below the kernel window"
    );
    let window = vaddr >> 22;
    let index = (vaddr >> 12) & 0x3FF;
    // SAFETY: the self-map window is live in every directory; the table is read only when its
    // directory entry is present.
    unsafe {
        let pde = (DIRECTORY_ENTRY_VA + window * 4) as *const u32;
        if pde.read_volatile() & PAGE_PRESENT == 0 {
            return 0;
        }
        ((SELF_MAP_VA + (window << 12)) as *const u32)
            .add(index as usize)
            .read_volatile()
    }
}

/// Write the current directory's page-table entry for user address `vaddr` — any value, present or
/// not (the address-space manager keeps committed but inaccessible pages as non-present entries
/// that still name their frame) — and flush it. The window's table is allocated on first use.
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
    let window = vaddr >> 22;
    let index = (vaddr >> 12) & 0x3FF;
    // SAFETY: as `user_pte`; the address-space manager is the only mutator of user windows.
    unsafe {
        let pde = (DIRECTORY_ENTRY_VA + window * 4) as *mut u32;
        if pde.read_volatile() & PAGE_PRESENT == 0 {
            if entry == 0 {
                return;
            }
            let table_phys = allocate_frame_phys();
            // Quirk: zero the table while it is still unreachable — present garbage entries must
            // never become speculatively walkable. A user window must be traversable by ring 3; the
            // per-page user/supervisor and read/write bits decide the rest.
            init_frame(table_phys, 0, &[]);
            pde.write_volatile(table_phys | PAGE_PRESENT | PAGE_WRITE | PAGE_USER);
        }
        ((SELF_MAP_VA + (window << 12)) as *mut u32)
            .add(index as usize)
            .write_volatile(entry);
        invlpg(vaddr);
    }
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
    dir[SELF_MAP_SLOT] = own_phys | PAGE_PRESENT | PAGE_WRITE;
    dir[SCRATCH_SLOT] = scratch_phys | PAGE_PRESENT | PAGE_WRITE;
}

/// The value CR3 takes for a directory at `dir_phys`: the address bits only, so a sloppy caller's
/// low flag bits cannot leak into the load.
pub const fn directory_cr3(dir_phys: u32) -> u32 {
    dir_phys & PAGE_ADDR_MASK
}

/// The shared scratch table's physical address (its frame is part of the kernel image and never
/// enters the frame database).
#[cfg(target_arch = "x86")]
pub fn scratch_table_phys() -> u32 {
    (core::ptr::addr_of!(SCRATCH_TABLE) as u32) - KERNEL_BASE
}

/// The boot directory's physical address: the address space the kernel returns to between
/// processes.
#[cfg(target_arch = "x86")]
pub fn boot_directory_phys() -> u32 {
    (core::ptr::addr_of!(BOOT_PD) as u32) - KERNEL_BASE
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
    // Allocated first: exhaustion fails before any write.
    let dir_phys = allocate_frame_phys();

    // The directory is assembled in its own frame, through the scratch window: every entry is
    // written (user half zero, kernel half copied, both special entries set), so no separate
    // zeroing pass is needed.
    let claim = ScratchClaim::take();
    let window = claim.map(dir_phys);
    // SAFETY: the window aliases exactly the new directory's frame, page-length and page-aligned,
    // for the claim's duration; nothing else references the fresh frame.
    let dir = unsafe { &mut *(window as *mut [u32; PT_ENTRIES]) };
    // The base directory's kernel half, read through the current directory's view of itself
    // (DIRECTORY_ENTRY_VA): the directory page reached through its own self-map slot, one entry per
    // word. Volatile: the CPU sets accessed/dirty bits on these entries as a side effect of
    // ordinary memory traffic.
    assemble_process_directory(dir, dir_phys, scratch_table_phys(), |i| {
        // SAFETY: the view page is exactly the current directory (installed at boot, inherited by
        // every process directory), and the reads stay inside it.
        unsafe { ((DIRECTORY_ENTRY_VA + (i as u32) * 4) as *const u32).read_volatile() }
    });
    drop(claim);
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
/// directory, so the mapping lands in all of them.
///
/// # Panics
///
/// Unaligned `vaddr`/`frame_phys`, `vaddr` outside the kernel half, `vaddr` in a window the
/// kernel owns for other purposes (the static kernel image window, the self-map, the scratch
/// window), or a window whose table would be created after the first process directory (see
/// [`KERNEL_HALF_FROZEN`]).
#[cfg(target_arch = "x86")]
pub fn map_kernel_page(vaddr: u32, frame_phys: u32) {
    assert!(vaddr % PAGE_SIZE == 0, "kernel address not page-aligned");
    assert!(frame_phys % PAGE_SIZE == 0, "frame not page-aligned");
    let window = (vaddr >> 22) as usize;
    let index = ((vaddr >> 12) & 0x3FF) as usize;
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

    // SAFETY: the self-map and directory windows are installed, so both addresses reach the
    // current directory and the window's table. Past the boot (before any thread runs), these
    // windows change only here and in `unmap_kernel_page`, at every thread create and exit, from
    // `map_gate_slot`/`unmap_gate_slot` inside the kernel-stack ledger's `Global` closure
    // (`STACKS` in mem/kstacks.rs), which masks interrupts: on one processor nothing else
    // touches the entry between the check and the store. Only the boot creates a table (the
    // frozen-half assertion). Entries are CPU-mutated (accessed/dirty), so access is volatile.
    unsafe {
        let pde = (DIRECTORY_ENTRY_VA + (window as u32) * 4) as *mut u32;
        if pde.read_volatile() & PAGE_PRESENT == 0 {
            assert!(
                !KERNEL_HALF_FROZEN.load(Ordering::Relaxed),
                "a kernel-half table created after the first process directory"
            );
            let table_phys = allocate_frame_phys();
            init_frame(table_phys, 0, &[]);
            install_kernel_table(window, table_phys);
        }
        let table = (SELF_MAP_VA + ((window as u32) << 12)) as *mut u32;
        assert_eq!(
            table.add(index).read_volatile() & PAGE_PRESENT,
            0,
            "kernel page already mapped"
        );
        table
            .add(index)
            .write_volatile(frame_phys | PAGE_PRESENT | PAGE_WRITE);
        invlpg(vaddr);
    }
}

/// Remove the kernel-half mapping at `vaddr` from the current directory and flush it from the TLB,
/// returning the frame it named. The frame itself is the caller's to release.
///
/// # Panics
///
/// The same window rules as [`map_kernel_page`], or nothing mapped at `vaddr`.
#[cfg(target_arch = "x86")]
pub fn unmap_kernel_page(vaddr: u32) -> u32 {
    assert!(vaddr % PAGE_SIZE == 0, "kernel address not page-aligned");
    let window = (vaddr >> 22) as usize;
    let index = ((vaddr >> 12) & 0x3FF) as usize;
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

    // SAFETY: as `map_kernel_page`: the caller, `unmap_gate_slot`, runs inside the kernel-stack
    // ledger's closure with interrupts masked, so nothing else touches the entry meanwhile. The
    // table exists because a mapping in it does.
    unsafe {
        let pde = (DIRECTORY_ENTRY_VA + (window as u32) * 4) as *const u32;
        assert!(
            pde.read_volatile() & PAGE_PRESENT != 0,
            "kernel page not mapped"
        );
        let table = (SELF_MAP_VA + ((window as u32) << 12)) as *mut u32;
        let pte = table.add(index).read_volatile();
        assert!(pte & PAGE_PRESENT != 0, "kernel page not mapped");
        table.add(index).write_volatile(0);
        invlpg(vaddr);
        pte & PAGE_ADDR_MASK
    }
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
/// one frame per page, supervisor-only, above the slot's unmapped guard page. Returns the frames
/// for the owner thread to release at its exit.
///
/// # Panics
///
/// The index is past the region's capacity, or the region's tables are not made yet
/// ([`init_kernel_stack_tables`]).
#[cfg(target_arch = "x86")]
pub fn map_gate_slot(index: u32) -> [u32; GATE_STACK_PAGES] {
    assert!(
        (index as usize) < GATE_SLOT_CAPACITY,
        "gate-slot index past the region's capacity"
    );
    assert!(
        kernel_stack_tables_installed(),
        "a gate stack mapped before the kernel stack tables are made"
    );
    let base = gate_slot_base(index);
    let mut frames = [0u32; GATE_STACK_PAGES];
    for (i, slot) in frames.iter_mut().enumerate() {
        let frame = allocate_frame_phys();
        init_frame(frame, 0, &[]);
        map_kernel_page(base + ((i + 1) as u32) * PAGE_SIZE, frame);
        *slot = frame;
    }
    frames
}

/// Whether the current directory holds every table of the kernel stack region.
#[cfg(target_arch = "x86")]
fn kernel_stack_tables_installed() -> bool {
    (layout::KERNEL_STACKS.first_entry()..layout::KERNEL_STACKS.end_entry())
        .all(|window| kernel_pde(window) & PAGE_PRESENT != 0)
}

/// Whether gate-stack slot `index` is mapped in the current directory as [`map_gate_slot`] leaves
/// it: every stack page present, the guard page below them not.
#[cfg(target_arch = "x86")]
pub fn gate_slot_mapped(index: u32) -> bool {
    let base = gate_slot_base(index);
    let present = |vaddr: u32| kernel_pte(vaddr) & PAGE_PRESENT != 0;
    !present(base) && (1..=GATE_STACK_PAGES as u32).all(|page| present(base + page * PAGE_SIZE))
}

/// The current directory's entry `window`, raw.
#[cfg(target_arch = "x86")]
fn kernel_pde(window: usize) -> u32 {
    assert!(window < PT_ENTRIES, "directory index past the directory");
    // SAFETY: the self-map window is live in every directory; the read stays on the directory's
    // view page. Volatile: the CPU sets accessed bits on directory entries.
    unsafe { ((DIRECTORY_ENTRY_VA + (window as u32) * 4) as *const u32).read_volatile() }
}

/// The current directory's page-table entry for kernel address `vaddr`, raw; 0 when its window has
/// no table.
#[cfg(target_arch = "x86")]
fn kernel_pte(vaddr: u32) -> u32 {
    let window = (vaddr >> 22) as usize;
    if kernel_pde(window) & PAGE_PRESENT == 0 {
        return 0;
    }
    let index = ((vaddr >> 12) & 0x3FF) as usize;
    // SAFETY: the window's table is present, reached through the self-map, and the index is inside
    // it. Volatile: the CPU sets accessed/dirty bits on table entries.
    unsafe {
        ((SELF_MAP_VA + ((window as u32) << 12)) as *const u32)
            .add(index)
            .read_volatile()
    }
}

/// Read word `index` of `frame_phys` through the scratch window: the one-page alias of any frame,
/// used by the teardown walk to read a dead process's directory and tables without mapping them.
///
/// # Panics
///
/// `index` past the frame's end.
#[cfg(target_arch = "x86")]
pub fn read_frame_word(frame_phys: u32, index: usize) -> u32 {
    assert!(index < PT_ENTRIES, "word index past the end of the frame");
    let claim = ScratchClaim::take();
    let window = claim.map(frame_phys);
    // SAFETY: the window aliases exactly this frame, page-length, for the claim's duration, and the
    // index is in bounds.
    unsafe { (window as *const u32).add(index).read_volatile() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tables_are_page_aligned() {
        for table in &BOOT_TABLES.0 {
            assert_eq!(table.as_ptr() as usize % 4096, 0);
        }
        // SAFETY: read-only access before any boot code runs.
        assert_eq!(
            unsafe { &*core::ptr::addr_of!(BOOT_PD) }.0.as_ptr() as usize % 4096,
            0
        );
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
        let low = &BOOT_TABLES.0[0];
        assert_eq!(low[0], 0x0000_0000 | PAGE_PRESENT | PAGE_WRITE);
        assert_eq!(low[256], 0x0010_0000 | PAGE_PRESENT | PAGE_WRITE);
        assert_eq!(low[1023], 0x003F_F000 | PAGE_PRESENT | PAGE_WRITE);
    }

    #[test]
    fn the_later_tables_map_the_next_4mib_each() {
        assert_eq!(BOOT_TABLES.0[1][0], 0x0040_0000 | PAGE_PRESENT | PAGE_WRITE);
        assert_eq!(
            BOOT_TABLES.0[1][1023],
            0x007F_F000 | PAGE_PRESENT | PAGE_WRITE
        );
        assert_eq!(BOOT_TABLES.0[2][0], 0x0080_0000 | PAGE_PRESENT | PAGE_WRITE);
        assert_eq!(
            BOOT_TABLES.0[3][1023],
            0x00FF_F000 | PAGE_PRESENT | PAGE_WRITE
        );
    }

    #[test]
    fn every_entry_is_present_writable_and_in_window() {
        for (t, table) in BOOT_TABLES.0.iter().enumerate() {
            for (i, &entry) in table.iter().enumerate() {
                assert_eq!(entry & PAGE_ADDR_MASK, ((t * PT_ENTRIES + i) * 4096) as u32);
                assert_eq!(entry & !PAGE_ADDR_MASK, PAGE_PRESENT | PAGE_WRITE);
            }
        }
    }

    #[test]
    fn boot_directory_starts_empty() {
        // SAFETY: read-only access before any boot code runs.
        let pd = unsafe { &*core::ptr::addr_of!(BOOT_PD) };
        assert!(pd.0.iter().all(|&e| e == 0));
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
