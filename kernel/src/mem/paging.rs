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
//! nothing below `KERNEL_BASE` is mapped at all.

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
/// Page-table flag: page/directory is writable.
pub const PAGE_WRITE: u32 = 1 << 2;
/// Mask selecting the address bits of a page-table entry.
pub const PAGE_ADDR_MASK: u32 = 0xFFFF_F000;

/// Page-table entries per table (32-bit paging: 1024).
pub const PT_ENTRIES: usize = 1024;

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
}
