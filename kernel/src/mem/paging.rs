//! Paging: the kernel window and the runtime user mappings.
//!
//! 32-bit x86 two-level paging, 4 KiB pages. The kernel is linked at `KERNEL_BASE + 1 MiB` and runs
//! there; the boot trampoline builds the initial directory:
//!
//! - `[0, 8 MiB)`: physical identity, the boot transition window (entry stub, Multiboot info) until
//!   [`teardown_low_identity`] removes it;
//! - `[KERNEL_BASE, KERNEL_BASE + 8 MiB)`: the kernel window over physical `[0, 8 MiB)`.
//!
//! The boot tables are link-time identity constants; the directory is filled by the entry stub,
//! which addresses it physically before paging is on. Everything below `KERNEL_BASE` is unmapped
//! after the teardown; user pages and their tables are created at runtime ([`init_frame`],
//! [`map_user_page`]).

#[cfg(target_arch = "x86")]
use core::arch::asm;

/// Virtual base of kernel space (user space is the low 2 GiB).
pub const KERNEL_BASE: u32 = 0x8000_0000;

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

/// Page table for physical/virtual pages `[0, 1024)`: the low 4 MiB.
#[no_mangle]
pub static BOOT_PT_LO: Aligned<[u32; PT_ENTRIES]> = Aligned(identity_page_table(0));

/// Page table for physical/virtual pages `[1024, 2048)`: 4-8 MiB.
#[no_mangle]
pub static BOOT_PT_HI: Aligned<[u32; PT_ENTRIES]> = Aligned(identity_page_table(PT_ENTRIES));

/// The boot page directory. Zero-initialized; the entry stub fills entries 0, 1 (low identity
/// window) and 512, 513 (kernel window), all pointing at the two tables above.
#[no_mangle]
pub static mut BOOT_PD: Aligned<[u32; PT_ENTRIES]> = Aligned([0; PT_ENTRIES]);

/// Remove the low identity window (called once the Multiboot info is consumed): clears entries 0-1
/// and flushes the TLB via a CR3 reload. User space is unmapped from here on.
#[cfg(target_arch = "x86")]
pub fn teardown_low_identity() {
    // SAFETY: the boot context is the only mutator of the directory; paging is on and the kernel
    // window entries are live.
    let pd = unsafe { &mut *core::ptr::addr_of_mut!(BOOT_PD) }
        .0
        .as_mut_ptr();

    // The kernel window must be established before the low window goes away; this also catches a
    // directory the stub never filled.
    let pt_lo_phys = (BOOT_PT_LO.0.as_ptr() as u32) - KERNEL_BASE;
    assert_eq!(
        unsafe { *pd.add(512) } & PAGE_ADDR_MASK,
        pt_lo_phys,
        "kernel window is not mapped"
    );
    assert_ne!(
        unsafe { *pd.add(0) },
        0,
        "low identity window is already gone"
    );

    unsafe {
        *pd.add(0) = 0;
        *pd.add(1) = 0;
    }

    let pd_phys = pd as u32 - KERNEL_BASE;
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

/// Directory entry that maps the directory into its own window (NT-style: self-map at 0xC0000000).
pub const SELF_MAP_SLOT: usize = 768;
/// Virtual address of the self-mapped directory (SELF_MAP_SLOT << 22).
pub const SELF_MAP_VA: u32 = (SELF_MAP_SLOT as u32) << 22;
/// Directory entry that holds the scratch page table (NT-style: scratch/hyperspace at 0xC0400000).
pub const SCRATCH_SLOT: usize = 769;
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
/// The per-process ring-0 gate stack window (directory entry 514): sub-allocated into per-thread
/// slots, each a guard page plus the 16 KiB stack. Slot 0's top is [`GATE_STACK_TOP`], a main
/// thread's stack.
pub const GATE_STACK_WINDOW: u32 = KERNEL_BASE + 2 * 0x0040_0000;
/// Gate stack pages, one frame each (16 KiB).
pub const GATE_STACK_PAGES: usize = 4;
/// Slot 0's top: the main thread's stack, pinned by the layout tests (the switch installs every
/// thread's top from its record, so nothing else reads it).
#[cfg(test)]
pub const GATE_STACK_TOP: u32 = gate_slot_top(0);
/// One thread's slot: a guard page plus the stack pages.
pub const GATE_SLOT_STRIDE: u32 = ((GATE_STACK_PAGES + 1) as u32) * PAGE_SIZE;
/// How many slots the window (one directory entry, 4 MiB) holds. The binding per-thread capacity of
/// the process: an allocation past it is a bug, not a wrap.
pub const GATE_SLOT_CAPACITY: usize = (0x0040_0000 / GATE_SLOT_STRIDE) as usize;

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
    let pd = unsafe { &mut *core::ptr::addr_of_mut!(BOOT_PD) }
        .0
        .as_mut_ptr();
    let pd_phys = pd as u32 - KERNEL_BASE;
    assert_eq!(
        unsafe { *pd.add(SELF_MAP_SLOT) },
        0,
        "self-map already installed"
    );
    assert_eq!(
        unsafe { *pd.add(SCRATCH_SLOT) },
        0,
        "scratch table already installed"
    );

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

        // SAFETY: both slots were asserted empty; the boot context is the only mutator.
        *pd.add(SELF_MAP_SLOT) = pd_phys | PAGE_PRESENT | PAGE_WRITE;
        *pd.add(SCRATCH_SLOT) = scratch_table_phys | PAGE_PRESENT | PAGE_WRITE;
    }
}

/// The scratch table: a kernel static (its frame never enters the frame database).
#[cfg(target_arch = "x86")]
static mut SCRATCH_TABLE: Aligned<[u32; PT_ENTRIES]> = Aligned([0; PT_ENTRIES]);

/// Staging where a new process directory is assembled before it is written to its frame (the loader
/// runs on the small boot stack; a 4 KiB directory must not live in a stack frame).
#[cfg(target_arch = "x86")]
static mut DIRECTORY_STAGING: Aligned<[u32; PT_ENTRIES]> = Aligned([0; PT_ENTRIES]);

/// Invalidate the TLB entry for `vaddr`.
#[cfg(target_arch = "x86")]
unsafe fn invlpg(vaddr: u32) {
    // SAFETY: invlpg has no register side effects; the page's entry may or may not be cached, the
    // instruction tolerates both.
    unsafe {
        asm!("invlpg [{va}]", va = in(reg) vaddr, options(nostack, preserves_flags));
    }
}

/// Point scratch entry 0 at `frame_phys` and flush it.
///
/// # Safety
///
/// Sole scratch user; every call rewrites and flushes.
#[cfg(target_arch = "x86")]
unsafe fn install_scratch(frame_phys: u32) {
    // The scratch table's entry 0, reached through the self-map.
    // SAFETY: see above.
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
    // SAFETY: the boot context is the only scratch-slot user.
    unsafe { install_scratch(frame_phys) };
    // SAFETY: SCRATCH_VA now aliases exactly this frame, page-length.
    unsafe {
        let words = SCRATCH_VA as *mut u32;
        for i in 0..PT_ENTRIES {
            words.add(i).write_volatile(0);
        }
        let dst = SCRATCH_VA as *mut u8;
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
    // SAFETY: the boot context is the only scratch-slot user.
    unsafe { install_scratch(frame_phys) };
    // SAFETY: SCRATCH_VA now aliases exactly this frame, page-length.
    unsafe {
        let dst = SCRATCH_VA as *mut u8;
        for (i, &byte) in bytes.iter().enumerate() {
            dst.add(offset + i).write_volatile(byte);
        }
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

/// Map `vaddr` to `frame_phys`: present, user, writable if asked. The window's table is allocated
/// on first use; double mappings panic.
///
/// The mapping lands in the **current** directory — the one CR3 points at — reached through its
/// self-map window, so it targets the active process's address space, not any particular static.
///
/// # Panics
///
/// Unaligned `vaddr`/`frame_phys`, kernel-window `vaddr`, already mapped.
#[cfg(target_arch = "x86")]
pub fn map_user_page(vaddr: u32, frame_phys: u32, writable: bool) {
    assert!(vaddr % PAGE_SIZE == 0, "user address not page-aligned");
    assert!(frame_phys % PAGE_SIZE == 0, "frame not page-aligned");
    assert!(
        vaddr < KERNEL_BASE,
        "user mappings live below the kernel window"
    );
    let window = (vaddr >> 22) as usize;
    let index = ((vaddr >> 12) & 0x3FF) as usize;

    // Both the window's directory entry (DIRECTORY_ENTRY_VA + window*4, through the directory's own
    // self-map slot) and its page table (SELF_MAP_VA + window*4096, through the self-map window)
    // are reached through the current directory: the entries live wherever CR3 points. The CPU may
    // set accessed/dirty bits on any entry as a side effect of ordinary memory traffic, so all
    // reads and writes are volatile.
    // SAFETY: the boot context is the only mutator of user windows.
    unsafe {
        let pde = (DIRECTORY_ENTRY_VA + (window as u32) * 4) as *mut u32;
        if pde.read_volatile() & PAGE_PRESENT == 0 {
            let table_phys = allocate_frame_phys();
            // Quirk: zero the table while it is still unreachable — present garbage entries must
            // never become speculatively walkable.
            init_frame(table_phys, 0, &[]);
            // A user window must be traversable by ring 3; the per-page user/supervisor and
            // read/write bits decide the rest.
            pde.write_volatile(table_phys | PAGE_PRESENT | PAGE_WRITE | PAGE_USER);
        }
        let table = (SELF_MAP_VA + ((window as u32) << 12)) as *mut u32;
        assert_eq!(
            table.add(index).read_volatile() & PAGE_PRESENT,
            0,
            "user page already mapped"
        );
        let entry = frame_phys | PAGE_PRESENT | PAGE_USER | if writable { PAGE_WRITE } else { 0 };
        table.add(index).write_volatile(entry);
        invlpg(vaddr);
    }
}

// --- Per-process address spaces --------------------------------------------
//
// A process owns a page-directory frame. Creation inherits the kernel half from the current
// directory (the kernel window must stay mapped wherever CR3 points), zeroes the user half, points
// the self-map entry at the new directory itself, and installs the shared scratch table. The new
// directory is built through the scratch window — its own self-map is unreachable until CR3 loads
// it. Activation is a single CR3 load, which is also the full TLB flush (no F2K mapping is global,
// so nothing survives the reload).

/// Assemble a fresh process directory in `dir`: user half zeroed, kernel half inherited through
/// `read_base_entry` (called for each entry in `[KERNEL_HALF_START, PT_ENTRIES)` of the base
/// directory, which is only ever read), self-map entry pointing at the new directory's own frame
/// `own_phys`, scratch entry at the shared scratch table `scratch_phys`.
///
/// One kernel-half entry is deliberately *not* inherited: the gate stack window
/// ([`GATE_STACK_WINDOW`]) is per-process — each process maps its own stack there, so the base's
/// entry (whatever it maps) must not leak into a new directory.
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
    dir[(GATE_STACK_WINDOW >> 22) as usize] = 0;
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

    // SAFETY: single-threaded boot context; the staging static's only user is this function.
    let staging = unsafe { &mut *core::ptr::addr_of_mut!(DIRECTORY_STAGING) };
    // The base directory's kernel half, read through the current directory's view of itself
    // (DIRECTORY_ENTRY_VA): the directory page reached through its own self-map slot, one entry per
    // word. Volatile: the CPU sets accessed/dirty bits on these entries as a side effect of
    // ordinary memory traffic.
    // SAFETY: the view page is exactly the current directory (installed at boot, inherited by every
    // process directory), and the reads stay inside it.
    unsafe {
        assemble_process_directory(&mut staging.0, dir_phys, scratch_table_phys(), |i| {
            ((DIRECTORY_ENTRY_VA + (i as u32) * 4) as *const u32).read_volatile()
        });
    }

    // One full-page write through the scratch window; the staging is complete (user half zero,
    // kernel half copied, both special entries set), so no separate zeroing pass is needed.
    // SAFETY: the staging static's contents were just fully written by the assembly above (4096
    // bytes); the scratch window is installed in the current directory, and this is its sole user.
    unsafe {
        let staging_bytes: &[u8] = core::slice::from_raw_parts(
            core::ptr::addr_of!(DIRECTORY_STAGING).cast::<u8>(),
            core::mem::size_of::<[u32; PT_ENTRIES]>(),
        );
        write_frame(dir_phys, 0, staging_bytes);
    }
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
/// [`map_user_page`]; the mapping lands in the current directory.
///
/// # Panics
///
/// Unaligned `vaddr`/`frame_phys`, `vaddr` outside the kernel half, or `vaddr` in a window the
/// kernel owns for other purposes (the static kernel image window, the self-map, the scratch
/// window).
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
        window != 512 && window != 513,
        "kernel mapping collides with the static kernel image window"
    );
    assert!(
        window != SELF_MAP_SLOT && window != SCRATCH_SLOT,
        "kernel mapping collides with the runtime access windows"
    );

    // SAFETY: the boot context is the only mutator of these windows; entries are CPU-mutated
    // (accessed/dirty), so access is volatile.
    unsafe {
        let pde = (DIRECTORY_ENTRY_VA + (window as u32) * 4) as *mut u32;
        if pde.read_volatile() & PAGE_PRESENT == 0 {
            let table_phys = allocate_frame_phys();
            init_frame(table_phys, 0, &[]);
            pde.write_volatile(table_phys | PAGE_PRESENT | PAGE_WRITE);
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

/// Remove the user mapping at `vaddr` from the current directory and flush it from the TLB,
/// returning the frame it named (the caller's to release); none when nothing is mapped there.
#[cfg(target_arch = "x86")]
pub fn unmap_user_page(vaddr: u32) -> Option<u32> {
    assert!(vaddr % PAGE_SIZE == 0, "user address not page-aligned");
    assert!(
        vaddr < KERNEL_BASE,
        "user mappings live below the kernel window"
    );
    let window = (vaddr >> 22) as usize;
    let index = ((vaddr >> 12) & 0x3FF) as usize;
    // SAFETY: as `map_user_page`; the table is read only when its directory entry is present.
    unsafe {
        let pde = (DIRECTORY_ENTRY_VA + (window as u32) * 4) as *const u32;
        if pde.read_volatile() & PAGE_PRESENT == 0 {
            return None;
        }
        let table = (SELF_MAP_VA + ((window as u32) << 12)) as *mut u32;
        let pte = table.add(index).read_volatile();
        if pte & PAGE_PRESENT == 0 {
            return None;
        }
        table.add(index).write_volatile(0);
        invlpg(vaddr);
        Some(pte & PAGE_ADDR_MASK)
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
        window != 512 && window != 513,
        "kernel unmapping collides with the static kernel image window"
    );
    assert!(
        window != SELF_MAP_SLOT && window != SCRATCH_SLOT,
        "kernel unmapping collides with the runtime access windows"
    );

    // SAFETY: as `map_kernel_page`; the table exists because a mapping in it does.
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

/// Unmap gate-stack slot `index`'s pages from the current address space: the inverse of
/// [`map_gate_slot`]. Returns the frames that were mapped, for the owner to release. Never call it
/// on the slot the processor is running on.
///
/// # Panics
///
/// The index is past the window's capacity, or a slot page is not mapped.
#[cfg(target_arch = "x86")]
pub fn unmap_gate_slot(index: u32) -> [u32; GATE_STACK_PAGES] {
    assert!(
        (index as usize) < GATE_SLOT_CAPACITY,
        "gate-slot index past the window's capacity"
    );
    let base = gate_slot_base(index);
    let mut frames = [0u32; GATE_STACK_PAGES];
    for (i, slot) in frames.iter_mut().enumerate() {
        *slot = unmap_kernel_page(base + ((i + 1) as u32) * PAGE_SIZE);
    }
    frames
}

/// Map a fresh gate-stack slot `index` into the current address space: one frame per page,
/// supervisor-only, above the slot's unmapped guard page. Returns the frames for the owner thread
/// to release at its exit.
///
/// # Panics
///
/// The index is past the window's capacity.
#[cfg(target_arch = "x86")]
pub fn map_gate_slot(index: u32) -> [u32; GATE_STACK_PAGES] {
    assert!(
        (index as usize) < GATE_SLOT_CAPACITY,
        "gate-slot index past the window's capacity"
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

/// Read word `index` of `frame_phys` through the scratch window: the one-page alias of any frame,
/// used by the teardown walk to read a dead process's directory and tables without mapping them.
///
/// # Panics
///
/// `index` past the frame's end.
#[cfg(target_arch = "x86")]
pub fn read_frame_word(frame_phys: u32, index: usize) -> u32 {
    assert!(index < PT_ENTRIES, "word index past the end of the frame");
    // SAFETY: the boot context is the only scratch-slot user; every call rewrites and flushes.
    unsafe { install_scratch(frame_phys) };
    // SAFETY: SCRATCH_VA aliases exactly this frame, page-length, and the index is in bounds.
    unsafe { (SCRATCH_VA as *const u32).add(index).read_volatile() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tables_are_page_aligned() {
        assert_eq!(BOOT_PT_LO.0.as_ptr() as usize % 4096, 0);
        assert_eq!(BOOT_PT_HI.0.as_ptr() as usize % 4096, 0);
        // SAFETY: read-only access before any boot code runs.
        assert_eq!(
            unsafe { &*core::ptr::addr_of!(BOOT_PD) }.0.as_ptr() as usize % 4096,
            0
        );
    }

    #[test]
    fn low_table_maps_the_first_4mib_identity() {
        assert_eq!(BOOT_PT_LO.0[0], 0x0000_0000 | PAGE_PRESENT | PAGE_WRITE);
        assert_eq!(BOOT_PT_LO.0[256], 0x0010_0000 | PAGE_PRESENT | PAGE_WRITE);
        assert_eq!(BOOT_PT_LO.0[1023], 0x003F_F000 | PAGE_PRESENT | PAGE_WRITE);
    }

    #[test]
    fn high_table_maps_the_second_4mib_identity() {
        assert_eq!(BOOT_PT_HI.0[0], 0x0040_0000 | PAGE_PRESENT | PAGE_WRITE);
        assert_eq!(BOOT_PT_HI.0[1023], 0x007F_F000 | PAGE_PRESENT | PAGE_WRITE);
    }

    #[test]
    fn every_entry_is_present_writable_and_in_window() {
        for (i, &entry) in BOOT_PT_LO.0.iter().enumerate() {
            assert_eq!(entry & PAGE_ADDR_MASK, (i * 4096) as u32);
            assert_eq!(entry & !PAGE_ADDR_MASK, PAGE_PRESENT | PAGE_WRITE);
        }
        for (i, &entry) in BOOT_PT_HI.0.iter().enumerate() {
            assert_eq!(entry & PAGE_ADDR_MASK, ((PT_ENTRIES + i) * 4096) as u32);
            assert_eq!(entry & !PAGE_ADDR_MASK, PAGE_PRESENT | PAGE_WRITE);
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
        // Read-only user page, the strictest mapping map_user_page builds: present + user.
        assert_eq!(PAGE_PRESENT | PAGE_USER, 0x5);
        // Writable user page: present + R/W + user.
        assert_eq!(PAGE_PRESENT | PAGE_WRITE | PAGE_USER, 0x7);
    }

    /// The self-map and scratch slots sit at the NT-style addresses (0xC0000000 and 0xC0400000,
    /// where Windows executables and tooling expect them), in the kernel window, distinct from the
    /// boot entries (512, 513) and from each other.
    #[test]
    fn runtime_access_slots_are_well_placed() {
        assert_eq!(SELF_MAP_SLOT, 768);
        assert_eq!(SCRATCH_SLOT, 769);
        assert_eq!(SELF_MAP_VA, 0xC000_0000);
        assert_eq!(SCRATCH_VA, 0xC040_0000);
        assert!(SELF_MAP_VA >= KERNEL_BASE);
        assert!(SCRATCH_VA > SELF_MAP_VA);
        for slot in [SELF_MAP_SLOT, SCRATCH_SLOT] {
            assert!(slot != 512 && slot != 513 && slot < PT_ENTRIES);
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

    /// The kernel half is inherited wholesale except the two runtime slots and the gate stack
    /// window (per-process: never inherited); the user half starts zero no matter what the target
    /// frame held before.
    #[test]
    fn process_directory_inherits_the_kernel_half_and_zeroes_the_user_half() {
        let mut base = [0u32; PT_ENTRIES];
        base[512] = 0x0010_1000 | PAGE_PRESENT | PAGE_WRITE;
        base[513] = 0x0050_1000 | PAGE_PRESENT | PAGE_WRITE;
        base[700] = 0x0090_0000 | PAGE_PRESENT | PAGE_WRITE | PAGE_USER;
        base[(GATE_STACK_WINDOW >> 22) as usize] = 0x00C0_0000 | PAGE_PRESENT | PAGE_WRITE;
        base[1023] = 0x00B0_0000 | PAGE_PRESENT | PAGE_WRITE;
        let dir = assembled(&base, 0x9000, 0xB000);

        for i in 0..PT_ENTRIES {
            if i == SELF_MAP_SLOT || i == SCRATCH_SLOT {
                continue;
            }
            if i == (GATE_STACK_WINDOW >> 22) as usize {
                // Per-process: the base's entry must not leak in.
                assert_eq!(dir[i], 0, "gate stack window inherited");
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
    /// `map_user_page` writes window entries — going through the self-map entry itself, never
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

    /// The CR3 value is the directory's address bits only: low flag bits from a sloppy caller must
    /// not reach the load.
    #[test]
    fn directory_cr3_masks_the_flag_bits() {
        assert_eq!(directory_cr3(0x0090_0000), 0x0090_0000);
        assert_eq!(directory_cr3(0x0090_0007), 0x0090_0000);
        assert_eq!(directory_cr3(0xFFFF_F005), 0xFFFF_F000);
        assert_eq!(directory_cr3(0), 0);
    }

    /// The gate stack window: the first kernel window above the 8 MiB kernel image mapping
    /// (directory entry 514, clear of the static window and the runtime access slots), with an
    /// unmapped guard page at the window base and the 16 KiB stack above it — a gate-stack overflow
    /// faults into the guard instead of corrupting the kernel window below.
    #[test]
    fn gate_stack_window_layout() {
        assert_eq!(GATE_STACK_WINDOW, KERNEL_BASE + 8 * 0x0010_0000);
        assert_eq!((GATE_STACK_WINDOW >> 22) as usize, 514);
        for reserved in [512usize, 513, SELF_MAP_SLOT, SCRATCH_SLOT] {
            assert_ne!((GATE_STACK_WINDOW >> 22) as usize, reserved);
        }
        assert_eq!(GATE_STACK_PAGES, 4);
        assert_eq!(GATE_STACK_TOP, GATE_STACK_WINDOW + 5 * PAGE_SIZE);
        assert_eq!(GATE_STACK_TOP, 0x8080_5000);
        // Everything (guard + stack) stays inside window 514.
        assert!(GATE_STACK_TOP < GATE_STACK_WINDOW + 0x0040_0000);
    }
}
