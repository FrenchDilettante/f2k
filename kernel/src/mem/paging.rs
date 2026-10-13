//! Boot-time paging: the kernel's virtual memory window.
//!
//! 32-bit x86 two-level paging (CR3 -> page directory -> page tables,
//! 4 KiB pages). The kernel is linked at `KERNEL_BASE + 1 MiB` and
//! runs there; the entry trampoline in `boot` builds a boot page
//! directory while still executing at the physical load address:
//!
//! - `[0x00000000, 0x00800000)`: physical identity — the boot
//!   transition window: the entry stub, then the Multiboot
//!   information, until [`teardown_low_identity`] removes it;
//! - `[0x80000000, 0x80800000)`: the kernel window, mapping physical
//!   `[0, 8 MiB)` — the kernel image, its statics, and (later)
//!   everything the kernel maps on demand.
//!
//! The two page tables are link-time constants (identity mappings);
//! the directory is zero-initialized and filled by the entry stub,
//! which addresses it physically before paging is on.
//!
//! User space is `[0, 0x80000000)`: with the low window removed,
//! nothing below `KERNEL_BASE` is mapped at all. User pages and their
//! page tables are created at runtime by the kernel
//! ([`init_self_map`], [`init_frame`], [`map_user_page`]).

#[cfg(target_arch = "x86")]
use core::arch::asm;

/// Virtual base of kernel space (top 2 GiB of the 32-bit address
/// space; user space is the low 2 GiB).
pub const KERNEL_BASE: u32 = 0x8000_0000;

/// Physical load address of the kernel image (also the start of the
/// frames the kernel occupies).
pub const KERNEL_PHYS_BASE: u32 = 0x0010_0000;

/// Page-table flag: page/directory entry is present.
pub const PAGE_PRESENT: u32 = 1 << 0;
/// Page-table flag: page/directory is writable (R/W is entry bit 1).
pub const PAGE_WRITE: u32 = 1 << 1;
/// Page-table flag: page/directory is accessible from ring 3
/// (user/supervisor is entry bit 2; supervisor-only when clear).
pub const PAGE_USER: u32 = 1 << 2;
/// Mask selecting the address bits of a page-table entry.
pub const PAGE_ADDR_MASK: u32 = 0xFFFF_F000;

/// Page-table entries per table (32-bit paging: 1024).
pub const PT_ENTRIES: usize = 1024;

/// Page size (32-bit paging: 4 KiB).
pub const PAGE_SIZE: u32 = 4096;

/// Build one page table mapping `first_page + i` to physical page
/// `first_page + i` (identity), for i in 0..1024.
const fn identity_page_table(first_page: usize) -> [u32; PT_ENTRIES] {
    let mut table = [0u32; PT_ENTRIES];
    let mut i = 0;
    while i < PT_ENTRIES {
        table[i] = ((first_page + i) * 4096) as u32 | PAGE_PRESENT | PAGE_WRITE;
        i += 1;
    }
    table
}

/// 4 KiB-aligned wrapper: CR3 and directory entries require
/// page-aligned tables.
#[repr(align(4096))]
pub struct Aligned<T>(pub T);

/// Page table for physical/virtual pages `[0, 1024)`: the low 4 MiB.
#[no_mangle]
pub static BOOT_PT_LO: Aligned<[u32; PT_ENTRIES]> = Aligned(identity_page_table(0));

/// Page table for physical/virtual pages `[1024, 2048)`: 4-8 MiB.
#[no_mangle]
pub static BOOT_PT_HI: Aligned<[u32; PT_ENTRIES]> = Aligned(identity_page_table(PT_ENTRIES));

/// The boot page directory. Zero-initialized; the entry stub fills
/// entries 0, 1 (low identity window) and 512, 513 (kernel window),
/// all pointing at the two tables above.
#[no_mangle]
pub static mut BOOT_PD: Aligned<[u32; PT_ENTRIES]> = Aligned([0; PT_ENTRIES]);

/// Remove the low identity window.
///
/// Called once from the boot context, after the Multiboot information
/// has been consumed (it lives in low memory): entries 0 and 1 are
/// cleared and the CR3 reload flushes the TLB. From this point the
/// whole user space range is unmapped.
#[cfg(target_arch = "x86")]
pub fn teardown_low_identity() {
    // SAFETY: the boot context is the only mutator of the directory;
    // paging is on and the kernel window entries are live.
    let pd = unsafe { &mut *core::ptr::addr_of_mut!(BOOT_PD) }.0.as_mut_ptr();

    // The kernel window must be established before the low window
    // goes away; this also catches a directory the stub never filled.
    let pt_lo_phys = (BOOT_PT_LO.0.as_ptr() as u32) - KERNEL_BASE;
    assert_eq!(
        unsafe { *pd.add(512) } & PAGE_ADDR_MASK,
        pt_lo_phys,
        "kernel window is not mapped"
    );
    assert_ne!(unsafe { *pd.add(0) }, 0, "low identity window is already gone");

    unsafe {
        *pd.add(0) = 0;
        *pd.add(1) = 0;
    }

    let pd_phys = pd as u32 - KERNEL_BASE;
    // SAFETY: paging is on; reloading CR3 with the (same) directory
    // flushes non-global TLB entries, dropping the low mappings.
    unsafe {
        asm!("mov cr3, {pd}", pd = in(reg) pd_phys, options(nostack, preserves_flags));
    }
}

// --- Runtime table access (user mappings) ---------------------------------
//
// The boot tables are link-time statics, but user space is built at
// runtime and its page tables come from the frame database. Two
// directory entries give the kernel permanent access to its own tables
// and to arbitrary frames, without a direct map of physical memory:
//
// - the self-map ([`SELF_MAP_SLOT`], VA [`SELF_MAP_VA`]): the directory
//   maps itself, so directory entry i sits at SELF_MAP_VA + i*4 and the
//   page table of 4 MiB window i is the page at SELF_MAP_VA + i*4096;
// - the scratch page table ([`SCRATCH_SLOT`], VAs starting at
//   [`SCRATCH_VA`]): a dedicated table whose entry 0 aliases whichever
//   physical frame the kernel is initializing, so freshly allocated
//   frames can be zeroed and written before they are mapped anywhere
//   else. (The scratch table's own entries are written through the
//   self-map.)

/// Directory entry that maps the directory into its own window.
pub const SELF_MAP_SLOT: usize = 1022;
/// Virtual address of the self-mapped directory (SELF_MAP_SLOT << 22).
pub const SELF_MAP_VA: u32 = (SELF_MAP_SLOT as u32) << 22;
/// Directory entry that holds the scratch page table.
pub const SCRATCH_SLOT: usize = 1023;
/// Virtual address of scratch entry 0: the one-page alias of the frame
/// being initialized.
pub const SCRATCH_VA: u32 = (SCRATCH_SLOT as u32) << 22;

/// Install the runtime table access: the self-map and the scratch page
/// table (one frame, zeroed). Called once from the boot context, right
/// after [`teardown_low_identity`]. No TLB flushes are needed: neither
/// window was mapped before, so no entry for them can be cached.
#[cfg(target_arch = "x86")]
pub fn init_table_access() {
    // SAFETY: the boot context is the only mutator of the directory.
    let pd = unsafe { &mut *core::ptr::addr_of_mut!(BOOT_PD) }.0.as_mut_ptr();
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

    // The scratch table is a kernel static (its frame is part of the
    // image and never enters the frame database), so it can be zeroed
    // directly through the kernel window before it is reachable
    // through its own window. BSS is loader-zeroed in theory; zeroing
    // explicitly keeps that from being load-bearing.
    // SAFETY: the boot context is the only accessor.
    unsafe {
        let scratch = &mut *core::ptr::addr_of_mut!(SCRATCH_TABLE);
        for i in 0..PT_ENTRIES {
            scratch.0[i] = 0;
        }
        let scratch_table_phys = (scratch.0.as_mut_ptr() as u32) - KERNEL_BASE;

        // SAFETY: both slots were asserted empty; the boot context is
        // the only mutator.
        *pd.add(SELF_MAP_SLOT) = pd_phys | PAGE_PRESENT | PAGE_WRITE;
        *pd.add(SCRATCH_SLOT) = scratch_table_phys | PAGE_PRESENT | PAGE_WRITE;
    }
}

/// The scratch page table: a kernel static whose entry 0 aliases
/// whichever frame the kernel is initializing. Never allocated from
/// the frame database; its frame belongs to the kernel image.
#[cfg(target_arch = "x86")]
static mut SCRATCH_TABLE: Aligned<[u32; PT_ENTRIES]> = Aligned([0; PT_ENTRIES]);

/// Invalidate the TLB entry for `vaddr`.
#[cfg(target_arch = "x86")]
unsafe fn invlpg(vaddr: u32) {
    // SAFETY: invlpg has no register side effects; the page's entry may
    // or may not be cached, the instruction tolerates both.
    unsafe {
        asm!("invlpg [{va}]", va = in(reg) vaddr, options(nostack, preserves_flags));
    }
}

/// Point scratch entry 0 at `frame_phys` and flush the stale entry.
///
/// # Safety
///
/// The boot context must be the only scratch user; every call rewrites
/// the entry and flushes, so the alias is never stale.
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

/// Initialize a freshly allocated frame through the scratch alias:
/// zero the whole page, then copy `bytes` at `offset`.
///
/// Used for page tables (empty slice), user code pages (image bytes)
/// and user data pages (zero fill). `offset + bytes.len()` must stay
/// inside the page.
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

/// Allocate one frame from the boot frame database, return its physical
/// address. This is the frame allocator's first runtime consumer.
///
/// The database never zeroes what it hands out here (its zeroing hook
/// is a no-op until a zeroing worker exists, and the plain allocation
/// path requests none), so the frame's contents are undefined until
/// the caller initializes them — [`init_frame`] does that, and every
/// frame handed to user space goes through it.
#[cfg(target_arch = "x86")]
pub fn allocate_frame_phys() -> u32 {
    let frame = crate::mem::bootmem::with_frame_db(|db| {
        db.allocate(crate::mem::frame::PRIMARY_COLOR)
    });
    frame * PAGE_SIZE
}

/// Map the page at user virtual address `vaddr` to physical frame
/// `frame_phys`: present, user-accessible, writable if `writable`.
///
/// The 4 MiB window's page table is allocated from the frame database
/// on first use. Double mappings are contract violations and panic.
///
/// # Panics
///
/// Panics if `vaddr` is not page-aligned, lies in (or above) the kernel
/// window, or is already mapped; if `frame_phys` is not page-aligned.
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

    // Directory entries are read and written through the static
    // directory (always mapped in the kernel window): the self-map
    // aliases a window's page table only once its directory entry
    // exists, so an absent window cannot be probed through it.
    // SAFETY: the boot context is the only mutator of user windows.
    unsafe {
        let dir = unsafe { &mut *core::ptr::addr_of_mut!(BOOT_PD) }.0.as_mut_ptr();
        if *dir.add(window) & PAGE_PRESENT == 0 {
            let table_phys = allocate_frame_phys();
            // Zero the frame while it is still unreachable from the
            // window: until then its contents are whatever the frame
            // held, and present garbage entries must never become
            // speculatively walkable.
            init_frame(table_phys, 0, &[]);
            // A user window must be traversable by ring 3; the per-page
            // user/supervisor and read/write bits decide the rest.
            *dir.add(window) = table_phys | PAGE_PRESENT | PAGE_WRITE | PAGE_USER;
        }
        let table = (SELF_MAP_VA + ((window as u32) << 12)) as *mut u32;
        assert_eq!(
            table.add(index).read_volatile() & PAGE_PRESENT,
            0,
            "user page already mapped"
        );
        let entry =
            frame_phys | PAGE_PRESENT | PAGE_USER | if writable { PAGE_WRITE } else { 0 };
        table.add(index).write_volatile(entry);
        invlpg(vaddr);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tables_are_page_aligned() {
        assert_eq!(BOOT_PT_LO.0.as_ptr() as usize % 4096, 0);
        assert_eq!(BOOT_PT_HI.0.as_ptr() as usize % 4096, 0);
        // SAFETY: read-only access before any boot code runs.
        assert_eq!(unsafe { &*core::ptr::addr_of!(BOOT_PD) }.0.as_ptr() as usize % 4096, 0);
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

    /// Independent bit oracle: entry bit 0 is present, bit 1 is R/W,
    /// bit 2 is user/supervisor. The constants must name exactly those.
    #[test]
    fn flag_bits_match_the_x86_entry_layout() {
        assert_eq!(PAGE_PRESENT, 1);
        assert_eq!(PAGE_WRITE, 1 << 1);
        assert_eq!(PAGE_USER, 1 << 2);
        // Read-only user page, the strictest mapping map_user_page
        // builds: present + user.
        assert_eq!(PAGE_PRESENT | PAGE_USER, 0x5);
        // Writable user page: present + R/W + user.
        assert_eq!(PAGE_PRESENT | PAGE_WRITE | PAGE_USER, 0x7);
    }

    /// The self-map and scratch slots are the two highest directory
    /// entries, in the kernel window, distinct from the boot entries
    /// (512, 513) and from each other.
    #[test]
    fn runtime_access_slots_are_well_placed() {
        assert_eq!(SELF_MAP_SLOT, 1022);
        assert_eq!(SCRATCH_SLOT, 1023);
        assert_eq!(SELF_MAP_VA, 0xFF80_0000);
        assert_eq!(SCRATCH_VA, 0xFFC0_0000);
        assert!(SELF_MAP_VA >= KERNEL_BASE);
        assert!(SCRATCH_VA > SELF_MAP_VA);
        for slot in [SELF_MAP_SLOT, SCRATCH_SLOT] {
            assert!(slot != 512 && slot != 513 && slot < PT_ENTRIES);
        }
    }

    /// Directory-entry arithmetic the runtime code relies on:
    /// SELF_MAP_VA + window*4096 addresses that window's table, and
    /// SELF_MAP_VA + index*4 addresses a directory entry.
    #[test]
    fn self_map_addresses_directory_and_tables() {
        for window in [0usize, 1, 2, 511, 512, 1021] {
            let table_va = SELF_MAP_VA + ((window as u32) << 12);
            assert_eq!(table_va, 0xFF80_0000 + (window as u32) * 4096);
            // The table page stays inside the self-map's own 4 MiB.
            assert!(table_va >= SELF_MAP_VA);
            assert!(table_va < SELF_MAP_VA + (1 << 22));
        }
        for index in [0usize, 512, 1023] {
            let entry_va = SELF_MAP_VA + (index as u32) * 4;
            assert!(entry_va >= SELF_MAP_VA);
            assert!(entry_va < SELF_MAP_VA + 4096);
        }
    }
}
