//! Kernel-side image loader: run a PE32 file as the user process.
//!
//! [`run_image`] chains the host-testable pieces of `pe.rs` onto the
//! runtime machinery: parse and validate, stage the in-memory image
//! (headers, section bytes, zero tails), snap the IAT against the
//! kernel-synthesized kernel32 ([`crate::kernel32`]), map the staged
//! pages at the fixed image base with per-page write protection, map
//! the user stack, and enter ring 3 at the image's entry point.
//!
//! The image is built in a staging buffer in the kernel window —
//! a borrowed static, not a stack frame — because the loader runs on
//! the boot stack and the image can be tens of KiB. The snap happens
//! in staging, before mapping: once mapped, the image pages carry
//! their final protection and ring-0 writes must not touch them.

use crate::pe::{self, Image};

/// The first corpus fixture: no CRT, one import (`ExitProcess`).
pub const EXIT0: &[u8] = include_bytes!("../../tests/exit0/exit0.exe");

/// The staging buffer size: the largest image the loader will build
/// (the corpus's largest `SizeOfImage`). An image past it is a load
/// contract violation and panics.
const STAGING_SIZE: usize = 0x6000;

/// Staging for the in-memory image: the kernel-window static the image
/// is assembled and snapped in, before each page is copied into its
/// own frame as it is mapped.
#[cfg(target_arch = "x86")]
static mut IMAGE_STAGING: crate::mem::paging::Aligned<[u8; STAGING_SIZE]> =
    crate::mem::paging::Aligned([0; STAGING_SIZE]);

/// A page's write permission: a page is writable when any section
/// mapped into it is writable (a page shared by sections combines
/// their protections). Pages no section covers — the header page —
/// are read-only.
fn page_writable(image: &Image, page_rva: u32) -> bool {
    let start = page_rva;
    let end = page_rva + crate::mem::paging::PAGE_SIZE;
    (0..image.num_sections()).any(|i| {
        let s = image.section(i);
        s.virtual_address < end
            && start < s.virtual_address + image.section_extent(i)
            && s.protection().1
    })
}

/// Load `file` as the user process and enter ring 3 at its entry
/// point. Never returns: single tasking, run to completion — the
/// exit service (or a fault) ends the process and halts the kernel.
#[cfg(target_arch = "x86")]
pub fn run_image(file: &[u8]) -> ! {
    use crate::mem::paging::{self, PAGE_SIZE};
    use crate::user::{USER_STACK_PAGE, USER_STACK_TOP};

    // Identity question: bytes this loader does not accept are
    // reported, not panicked on.
    let image = match Image::parse(file) {
        Ok(image) => image,
        Err(reject) => {
            crate::serial_println!("F2K: image rejected by the loader: {:?}", reject);
            crate::halt()
        }
    };
    assert!(
        image.size_of_image as usize <= STAGING_SIZE,
        "image 0x{:x} exceeds the staging buffer 0x{:x}",
        image.size_of_image,
        STAGING_SIZE
    );

    // Stage the in-memory image. BSS is loader-zeroed in theory;
    // zeroing explicitly keeps that from being load-bearing (any
    // gap the image does not describe must read as zero, not as
    // stale staging bytes).
    // SAFETY: single-threaded boot, the only staging user.
    let staging = unsafe {
        let buffer = &mut *core::ptr::addr_of_mut!(IMAGE_STAGING);
        &mut buffer.0[..image.size_of_image as usize]
    };
    staging.fill(0);
    image.map_into(file, staging);

    // The thunk stubs must be reachable before the snap: IAT slots
    // receive user-space addresses.
    crate::kernel32::init();
    let snap = image.snap_imports(file, staging, crate::kernel32::MODULE_NAME, crate::kernel32::resolve);

    // Map the staged image at the fixed base, one frame per page,
    // writable exactly where a mapped section is writable.
    let pages = image.size_of_image.div_ceil(PAGE_SIZE);
    for page in 0..pages {
        let offset = (page * PAGE_SIZE) as usize;
        let end = (offset + PAGE_SIZE as usize).min(staging.len());
        let frame = paging::allocate_frame_phys();
        paging::init_frame(frame, 0, &staging[offset..end]);
        paging::map_user_page(
            pe::IMAGE_BASE + page * PAGE_SIZE,
            frame,
            page_writable(&image, page * PAGE_SIZE),
        );
    }

    // The user stack: one zeroed, writable page in its own window.
    let stack_frame = paging::allocate_frame_phys();
    paging::init_frame(stack_frame, 0, &[]);
    paging::map_user_page(USER_STACK_PAGE, stack_frame, true);

    crate::serial_println!(
        "F2K: image loaded (entry {:#010x}, {} pages, {} imports snapped)",
        image.entry_va(),
        pages,
        snap.thunks
    );
    crate::serial_println!(
        "F2K: entering ring 3 (entry {:#010x}, stack {:#010x})",
        image.entry_va(),
        USER_STACK_TOP
    );
    // SAFETY: the image and stack pages are mapped with their final
    // protections, the thunk page is reachable from ring 3, the
    // syscall gate is installed at DPL 3, and the TSS carries the
    // ring-0 stack.
    unsafe { crate::user::enter_ring3(image.entry_va(), USER_STACK_TOP) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mem::paging::PAGE_SIZE;

    const RET0: &[u8] = include_bytes!("../../tests/ret0/ret0.exe");

    /// Both fixtures fit the staging buffer, page-aligned.
    #[test]
    fn fixtures_fit_staging() {
        for file in [EXIT0, RET0] {
            let image = Image::parse(file).expect("fixture parses");
            assert_eq!(image.size_of_image % PAGE_SIZE, 0);
            assert!(image.size_of_image as usize <= STAGING_SIZE);
        }
    }

    /// exit0: three read-only pages (headers, .text, .rdata) — the
    /// image maps entirely without the write bit; the entry lies in
    /// the executable section, one page in.
    #[test]
    fn exit0_pages_are_all_read_only() {
        let image = Image::parse(EXIT0).expect("exit0 parses");
        assert_eq!(image.size_of_image, 0x3000);
        assert_eq!(image.entry_va(), 0x0040_1000);
        for page in 0..image.size_of_image / PAGE_SIZE {
            assert!(!page_writable(&image, page * PAGE_SIZE));
        }
    }

    /// ret0: six pages, only the .data page writable.
    #[test]
    fn ret0_marks_its_data_pages_writable() {
        let image = Image::parse(RET0).expect("ret0 parses");
        assert_eq!(image.size_of_image, 0x6000);
        let writable: Vec<u32> = (0..image.size_of_image / PAGE_SIZE)
            .filter(|&page| page_writable(&image, page * PAGE_SIZE))
            .collect();
        assert_eq!(writable, vec![0x5000 / PAGE_SIZE]);
    }

    /// The header page of an image is read-only (no section covers
    /// it), and only .data's own page is writable — the page before
    /// it stays read-only.
    #[test]
    fn page_protection_rules() {
        let ret0 = Image::parse(RET0).expect("ret0 parses");
        assert!(!page_writable(&ret0, 0));
        assert!(page_writable(&ret0, 0x5000));
        assert!(!page_writable(&ret0, 0x4000));
    }
}
