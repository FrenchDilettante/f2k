//! Kernel-side image loader: run a PE32 file as the user process.
//!
//! [`run_image`] parses, stages the in-memory image, snaps the IAT
//! against the kernel-synthesized kernel32, maps the pages with their
//! final protections, and enters ring 3 at the entry point.
//!
//! Quirk: the image is built in a staging buffer — a borrowed static,
//! not a stack frame — because the loader runs on the small boot
//! stack. The snap happens in staging, before mapping: mapped pages
//! carry their final protection and ring-0 writes must not touch them.

use crate::pe::{self, Image};

/// The first corpus fixture: no CRT, one import (`ExitProcess`).
pub const EXIT0: &[u8] = include_bytes!("../../tests/exit0/exit0.exe");

/// The second corpus fixture: full CRT startup, 35 KERNEL32.dll
/// imports (run with the `run-ret0` feature).
pub const RET0: &[u8] = include_bytes!("../../tests/ret0/ret0.exe");

/// The staging buffer size: the largest image the loader accepts.
const STAGING_SIZE: usize = 0x6000;

/// Staging for the in-memory image (see the module doc).
#[cfg(target_arch = "x86")]
static mut IMAGE_STAGING: crate::mem::paging::Aligned<[u8; STAGING_SIZE]> =
    crate::mem::paging::Aligned([0; STAGING_SIZE]);

/// A page's write permission: writable when any section in it is
/// writable (shared pages combine protections); uncovered pages (the
/// header page) are read-only.
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
/// point; `name` stages the parameters page. Never returns.
#[cfg(target_arch = "x86")]
pub fn run_image(file: &[u8], name: &str) -> ! {
    use crate::mem::paging::{self, PAGE_SIZE};
    use crate::user::{TEB_PAGE, USER_STACK_LOW_PAGE, USER_STACK_PAGE, USER_STACK_TOP};

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

    // Zero the staging explicitly: gaps the image does not describe
    // must read as zero, not stale staging bytes.
    // SAFETY: single-threaded boot, the only staging user.
    let staging = unsafe {
        let buffer = &mut *core::ptr::addr_of_mut!(IMAGE_STAGING);
        &mut buffer.0[..image.size_of_image as usize]
    };
    staging.fill(0);
    image.map_into(file, staging);

    // The process's own address space: a fresh directory sharing this
    // kernel's kernel half, active from here on, so every mapping
    // below (thunk page, image, stack, TEB, params) lands in it and
    // not in the boot directory.
    let address_space = paging::create_address_space();
    paging::activate_address_space(address_space);

    // The thunks must be mapped before the snap: IAT slots receive
    // user-space addresses.
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

    // The user stack: two zeroed, writable pages below the entry ESP.
    for stack_page in [USER_STACK_PAGE, USER_STACK_LOW_PAGE] {
        let stack_frame = paging::allocate_frame_phys();
        paging::init_frame(stack_frame, 0, &[]);
        paging::map_user_page(stack_page, stack_frame, true);
    }

    // The thread block page, reached through the TEB segment.
    let teb_frame = paging::allocate_frame_phys();
    paging::init_frame(teb_frame, 0, &[]);
    paging::map_user_page(TEB_PAGE, teb_frame, true);

    // The process parameters page (staged replays).
    crate::kernel32::init_params(name);

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
    // SAFETY: image, stack, TEB and thunk pages are mapped with
    // their final protections; the gate is DPL 3; the TSS carries
    // the ring-0 stack.
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

    /// exit0 maps entirely read-only; the entry is one page in.
    #[test]
    fn exit0_pages_are_all_read_only() {
        let image = Image::parse(EXIT0).expect("exit0 parses");
        assert_eq!(image.size_of_image, 0x3000);
        assert_eq!(image.entry_va(), 0x0040_1000);
        for page in 0..image.size_of_image / PAGE_SIZE {
            assert!(!page_writable(&image, page * PAGE_SIZE));
        }
    }

    /// ret0: only the .data page is writable.
    #[test]
    fn ret0_marks_its_data_pages_writable() {
        let image = Image::parse(RET0).expect("ret0 parses");
        assert_eq!(image.size_of_image, 0x6000);
        let writable: Vec<u32> = (0..image.size_of_image / PAGE_SIZE)
            .filter(|&page| page_writable(&image, page * PAGE_SIZE))
            .collect();
        assert_eq!(writable, vec![0x5000 / PAGE_SIZE]);
    }

    /// Uncovered pages (the header) are read-only; only .data's own
    /// page is writable.
    #[test]
    fn page_protection_rules() {
        let ret0 = Image::parse(RET0).expect("ret0 parses");
        assert!(!page_writable(&ret0, 0));
        assert!(page_writable(&ret0, 0x5000));
        assert!(!page_writable(&ret0, 0x4000));
    }
}
