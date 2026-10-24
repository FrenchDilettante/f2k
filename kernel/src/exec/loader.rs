//! Kernel-side image loader: run a PE32 file from the boot volume as the user process.
//!
//! [`load_path`] reads the program's file off the boot volume by its path into a raw-file staging
//! buffer; [`load_image`] then parses it, checks that its preferred base places it clear of the
//! system's fixed user regions, stages the in-memory image, maps the system DLLs
//! ([`map_system_dlls`]), snaps the IAT through the module table ([`resolve_import`]), maps the
//! pages at the preferred base with their final protections, and returns the entry point: the
//! caller enters the process as its main thread, which the scheduler starts there.
//!
//! Images are never relocated: an image maps at its preferred base or is refused. The module table
//! holds the system DLLs, ntdll and kernel32 (`exec::modules`); an import naming any other module
//! fails the snap. A DLL loaded at run time maps through the same parse and page protections, as
//! an image section's view (`nt::section`, page by page: [`Image::map_page`]).
//!
//! Quirk: the file and the image are built in staging buffers — borrowed statics, not stack frames
//! — because the loader runs on the small boot stack. The snap happens in staging, before mapping:
//! mapped pages carry their final protection and ring-0 writes must not touch them.

use core::fmt;

use crate::exec::pe::{Image, Unresolved};
use crate::fs::fat32::lookup::{lookup, LookupError};
use crate::fs::fat32::read::read;
use crate::fs::fat32::volume::Volume;
use crate::status::{nt_success, NtStatus};

/// The raw-file staging size: the largest file the loader reads. Room for the era's system binaries
/// (a few hundred KiB each); the corpus's biggest fixture file is 0x7000 bytes.
const FILE_STAGING_SIZE: usize = 0x8_0000;

/// Staging for the program's file as read off the volume (see the module doc).
#[cfg(target_arch = "x86")]
static mut FILE_STAGING: crate::mem::paging::Aligned<[u8; FILE_STAGING_SIZE]> =
    crate::mem::paging::Aligned([0; FILE_STAGING_SIZE]);

/// Why a program's file could not be read off the volume.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FileError {
    /// The path did not resolve.
    Lookup(LookupError),
    /// The path names a directory.
    Directory,
    /// The file (its size in bytes) is larger than the raw staging buffer.
    TooLarge(u32),
    /// The chain read failed: corruption, or the device.
    Read(NtStatus),
}

impl fmt::Display for FileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            FileError::Lookup(error) => write!(
                f,
                "lookup failed ({:?}, status {:#010x})",
                error,
                error.status() as u32
            ),
            FileError::Directory => write!(f, "a directory, not a file"),
            FileError::TooLarge(size) => write!(
                f,
                "{} bytes exceed the file staging ({} bytes)",
                size, FILE_STAGING_SIZE
            ),
            FileError::Read(status) => write!(f, "read failed (status {:#010x})", status as u32),
        }
    }
}

/// Read the file at `path` (root-relative, see the FAT path layer) into the start of `buffer`,
/// which bounds the size accepted. Returns the file's length.
pub fn read_image_file(
    volume: &mut Volume,
    path: &[u8],
    buffer: &mut [u8],
) -> Result<usize, FileError> {
    let file = lookup(volume, path).map_err(FileError::Lookup)?;
    if file.directory {
        return Err(FileError::Directory);
    }
    if file.size as usize > buffer.len() {
        return Err(FileError::TooLarge(file.size));
    }
    let status = read(volume, &file, buffer);
    if !nt_success(status) {
        return Err(FileError::Read(status));
    }
    Ok(file.size as usize)
}

/// Load the program at `path` on the boot volume as the new current process (see [`load_image`]),
/// with `command_line` as what its GetCommandLineA reports, and return its entry point. A file that
/// cannot be read is reported on COM1 and halts, as a rejected image does. The read blocks on the
/// disk: the boot context halts between interrupts until it completes.
#[cfg(target_arch = "x86")]
pub fn load_path(path: &[u8], name: &'static str, command_line: &[u8]) -> u32 {
    // SAFETY: single-threaded boot (or the idle thread's reap step), the only staging user.
    let staging = unsafe { &mut (*core::ptr::addr_of_mut!(FILE_STAGING)).0 };
    let shown = core::str::from_utf8(path).unwrap_or("(not ASCII)");
    let read = crate::fs::fat32::volume::with_boot_volume(|volume| {
        read_image_file(volume, path, &mut staging[..])
    });
    let length = match read {
        Some(Ok(length)) => length,
        Some(Err(error)) => {
            crate::serial_println!("F2K: image file {} not loaded: {}", shown, error);
            crate::halt()
        }
        None => {
            crate::serial_println!("F2K: image file {} not loaded: no boot volume", shown);
            crate::halt()
        }
    };
    load_image(&staging[..length], path, name, command_line)
}

/// The image staging size: the largest in-memory image the loader accepts. Sized like the file
/// staging; the corpus's biggest fixture image is 0x8000 bytes.
const STAGING_SIZE: usize = 0x8_0000;

/// Staging for the in-memory image (see the module doc).
#[cfg(target_arch = "x86")]
static mut IMAGE_STAGING: crate::mem::paging::Aligned<[u8; STAGING_SIZE]> =
    crate::mem::paging::Aligned([0; STAGING_SIZE]);

/// The system's fixed user regions, as (name, start, end): an image may cover none of them. Images
/// map at their preferred base (nothing is relocated), so one that would land on a region is
/// refused, not moved. The main thread's stack is its whole reservation (1 MiB, committed on
/// demand below its two top pages, see `user::stack`).
const SYSTEM_REGIONS: [(&str, u32, u32); 9] = {
    use crate::user::{
        PARAMS_PAGE,
        PEB_PAGE,
        TEB_PAGE,
        THREAD_TEB_REGION,
        USER_STACK_BASE,
        USER_STACK_TOP,
    };
    const PAGE: u32 = crate::mem::paging::PAGE_SIZE;
    const CHILDREN: u32 = crate::process::CHILD_THREADS as u32;
    use crate::exec::modules::{KERNEL32_BASE, KERNEL32_SIZE, NTDLL_BASE, NTDLL_SIZE};
    [
        ("main thread stack", USER_STACK_BASE, USER_STACK_TOP),
        ("main thread TEB", TEB_PAGE, TEB_PAGE + PAGE),
        (
            "process parameters",
            PARAMS_PAGE,
            PARAMS_PAGE + crate::user::params::PAGES * PAGE,
        ),
        ("process environment block", PEB_PAGE, PEB_PAGE + PAGE),
        (
            "environment block",
            crate::user::params::ENVIRONMENT_BLOCK,
            crate::user::params::ENVIRONMENT_BLOCK
                + crate::user::params::ENVIRONMENT_BLOCK_PAGES * PAGE,
        ),
        (
            "child thread TEBs",
            THREAD_TEB_REGION,
            THREAD_TEB_REGION + CHILDREN * PAGE,
        ),
        ("ntdll.dll image", NTDLL_BASE, NTDLL_BASE + NTDLL_SIZE),
        (
            "kernel32.dll image",
            KERNEL32_BASE,
            KERNEL32_BASE + KERNEL32_SIZE,
        ),
        (
            SHARED_DATA_REGION,
            crate::user::shared::USER_ADDRESS,
            crate::user::shared::USER_ADDRESS + PAGE,
        ),
    ]
};

/// The shared data page's name among the system regions (KUSER_SHARED_DATA, read-only).
const SHARED_DATA_REGION: &str = "shared data";

/// The first system region that an image of `size` bytes at `base` would cover, if any.
pub fn system_region_overlapping(base: u32, size: u32) -> Option<&'static str> {
    let (start, end) = (base as u64, base as u64 + size as u64);
    SYSTEM_REGIONS
        .iter()
        .find(|&&(_, region_start, region_end)| {
            start < region_end as u64 && (region_start as u64) < end
        })
        .map(|&(name, ..)| name)
}

/// The module table: resolve `name` in `module` (as an import descriptor or a forwarder spells it)
/// to the address an IAT slot receives. The system DLLs are the only modules; any other name is not
/// loaded.
pub fn resolve_import(module: &str, name: &str) -> Result<u32, Unresolved> {
    crate::exec::modules::resolve(module, name)
}

/// A page's protection, as a query reports it: the combined access of the sections in it (an
/// image's writable pages are copy-on-write, PAGE_WRITECOPY until written, as Windows 2000 maps
/// them); uncovered pages (the header page) are read-only.
pub(crate) fn page_protect(image: &Image, page_rva: u32) -> u32 {
    use crate::mem::vm::{
        PAGE_EXECUTE,
        PAGE_EXECUTE_READ,
        PAGE_EXECUTE_WRITECOPY,
        PAGE_READONLY,
        PAGE_WRITECOPY,
    };
    let end = page_rva + crate::mem::paging::PAGE_SIZE;
    let (mut read, mut write, mut execute) = (false, false, false);
    for i in 0..image.num_sections() {
        let s = image.section(i);
        if s.virtual_address < end && page_rva < s.virtual_address + image.section_extent(i) {
            let (r, w, x) = s.protection();
            read |= r;
            write |= w;
            execute |= x;
        }
    }
    match (read, write, execute) {
        (_, true, true) => PAGE_EXECUTE_WRITECOPY,
        (true, false, true) => PAGE_EXECUTE_READ,
        (false, false, true) => PAGE_EXECUTE,
        (_, true, false) => PAGE_WRITECOPY,
        // A section granting nothing still reads: no-access image pages are not served.
        (_, false, false) => PAGE_READONLY,
    }
}

/// Record the process's address space as a query reports it: the image of `image_size` bytes at
/// `image_base` (one allocation, its pages carrying their sections' protections), and the areas the
/// kernel maps itself, the system DLLs' images among them (MEM_IMAGE allocations, as the program's
/// own). Every user page the kernel maps lies in one of these regions.
pub fn seed_regions(space: &mut crate::mem::vm::AddressSpace, image_base: u32, image_size: u32) {
    use crate::mem::vm::{Kind, Region, PAGE_EXECUTE_WRITECOPY, PAGE_READWRITE};
    space
        .insert(Region {
            base: image_base,
            size: image_size.next_multiple_of(crate::mem::paging::PAGE_SIZE),
            alloc_protect: PAGE_EXECUTE_WRITECOPY,
            kind: Kind::Image,
        })
        .expect("a fresh address space takes the image");
    for &(name, start, end) in SYSTEM_REGIONS.iter() {
        let image = name.ends_with(".dll image");
        let alloc_protect = match name {
            _ if image => PAGE_EXECUTE_WRITECOPY,
            SHARED_DATA_REGION => crate::mem::vm::PAGE_READONLY,
            _ => PAGE_READWRITE,
        };
        space
            .insert(Region {
                base: start,
                size: end - start,
                alloc_protect,
                kind: if image { Kind::Image } else { Kind::Private },
            })
            .expect("the system regions are disjoint from each other and the image");
    }
}

/// Staging for a system DLL's image while it is mapped (the program's image is staged separately,
/// and is in staging while the DLLs map).
#[cfg(target_arch = "x86")]
static mut DLL_STAGING: crate::mem::paging::Aligned<[u8; DLL_STAGING_SIZE]> =
    crate::mem::paging::Aligned([0; DLL_STAGING_SIZE]);

/// The largest system DLL image the staging holds.
#[cfg(target_arch = "x86")]
const DLL_STAGING_SIZE: usize = 0x4_0000;

/// The pages a system DLL image may span: what the staging holds.
#[cfg(target_arch = "x86")]
const DLL_PAGES: usize = DLL_STAGING_SIZE / crate::mem::paging::PAGE_SIZE as usize;

/// The system DLLs' pages, made once at boot ([`prepare_system_dlls`]): each DLL's frames, page by
/// page — the kernel's, every process mapping them as one more holder.
#[cfg(target_arch = "x86")]
static mut DLL_FRAMES: [[u32; DLL_PAGES]; crate::exec::modules::SYSTEM_DLLS.len()] =
    [[0; DLL_PAGES]; crate::exec::modules::SYSTEM_DLLS.len()];

/// Make the system DLLs' pages (`exec::modules`), once, before the first process: each image staged
/// from its embedded file, its imports snapped against the module table (the bases are fixed, so
/// the snapped pages are every process's), then copied into frames of the kernel's, one per page.
#[cfg(target_arch = "x86")]
pub fn prepare_system_dlls() {
    use crate::mem::paging::{self, PAGE_SIZE};
    for (index, dll) in crate::exec::modules::SYSTEM_DLLS.iter().enumerate() {
        let image = dll.image();
        assert!(
            image.size_of_image as usize <= DLL_STAGING_SIZE,
            "{} exceeds the DLL staging",
            dll.file_name
        );
        // SAFETY: single-threaded boot, the only staging user.
        let staging = unsafe {
            let buffer = &mut *core::ptr::addr_of_mut!(DLL_STAGING);
            &mut buffer.0[..image.size_of_image as usize]
        };
        staging.fill(0);
        image.map_into(dll.file, staging);
        image.snap_imports(dll.file, staging, resolve_import);
        for page in 0..image.size_of_image.div_ceil(PAGE_SIZE) {
            let offset = (page * PAGE_SIZE) as usize;
            let end = (offset + PAGE_SIZE as usize).min(staging.len());
            let frame = paging::allocate_frame_phys();
            paging::init_frame(frame, 0, &staging[offset..end]);
            // SAFETY: single-threaded boot; read-only once made.
            unsafe { (*core::ptr::addr_of_mut!(DLL_FRAMES))[index][page as usize] = frame };
        }
    }
}

/// Map the system DLLs into the current process at their bases, each page with its sections'
/// protections inside the DLL's own MEM_IMAGE region (seeded with the system areas): the kernel's
/// frames ([`prepare_system_dlls`]), shared — a page the process makes writable is copy-on-write,
/// its writes its own (`mem::vm`).
#[cfg(target_arch = "x86")]
pub fn map_system_dlls(space: &mut crate::mem::vm::AddressSpace) {
    use crate::mem::paging::PAGE_SIZE;
    use crate::mem::vm::CurrentPages;
    for (index, dll) in crate::exec::modules::SYSTEM_DLLS.iter().enumerate() {
        let image = dll.image();
        for page in 0..image.size_of_image.div_ceil(PAGE_SIZE) {
            // SAFETY: made at boot, read-only afterwards.
            let frame = unsafe { (*core::ptr::addr_of!(DLL_FRAMES))[index][page as usize] };
            assert_ne!(frame, 0, "the system DLLs are prepared at boot");
            let va = image.image_base + page * PAGE_SIZE;
            space
                .map_shared(
                    &mut CurrentPages,
                    va,
                    frame,
                    page_protect(&image, page * PAGE_SIZE),
                )
                .expect("a system DLL maps once, inside its region");
        }
    }
}

/// A page's write permission: writable when any section in it is writable (shared pages combine
/// protections); uncovered pages (the header page) are read-only. The mapping takes it from
/// [`page_protect`]; the tests pin the two together.
#[cfg(test)]
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

/// Load `file` as the new current process — parse, stage, create the process, snap the imports,
/// map the image, stack, TEB, parameters and PEB pages — and return its entry point for the main
/// thread's ladder. `name` names the process; `command_line` is the process parameters' command
/// line, and `path`, the file's volume path, their image path (in its Win32 form, `C:\...`).
#[cfg(target_arch = "x86")]
pub fn load_image(file: &[u8], path: &[u8], name: &'static str, command_line: &[u8]) -> u32 {
    use crate::mem::paging::{self, PAGE_SIZE};
    use crate::mem::vm;
    use crate::user::{
        TEB_PAGE,
        USER_STACK_BASE,
        USER_STACK_LOW_PAGE,
        USER_STACK_PAGE,
        USER_STACK_TOP,
    };

    // Identity questions: bytes this loader does not accept, an image it cannot stage, and a
    // preferred base it cannot honor are reported, not panicked on.
    let image = match Image::parse_program(file) {
        Ok(image) => image,
        Err(reject) => {
            crate::serial_println!("F2K: image rejected by the loader: {:?}", reject);
            crate::halt()
        }
    };
    if image.size_of_image as usize > STAGING_SIZE {
        crate::serial_println!(
            "F2K: image rejected by the loader: image {:#x} exceeds the staging {:#x}",
            image.size_of_image,
            STAGING_SIZE
        );
        crate::halt()
    }
    if let Some(region) = system_region_overlapping(image.image_base, image.size_of_image) {
        crate::serial_println!(
            "F2K: image rejected by the loader: [{:#010x}, {:#010x}) covers the {}",
            image.image_base,
            image.image_base as u64 + image.size_of_image as u64,
            region
        );
        crate::halt()
    }

    // Zero the staging explicitly: gaps the image does not describe must read as zero, not stale
    // staging bytes.
    // SAFETY: single-threaded boot, the only staging user.
    let staging = unsafe {
        let buffer = &mut *core::ptr::addr_of_mut!(IMAGE_STAGING);
        &mut buffer.0[..image.size_of_image as usize]
    };
    staging.fill(0);
    image.map_into(file, staging);

    // The process's own state, all in one place: a fresh address space (kernel half inherited,
    // active on CR3) and the main thread's ring-0 gate stack (mapped supervisor-only with its guard
    // page; the switch into the thread installs it as the TSS esp0). Every mapping below (system
    // DLLs, image, stack, TEB, params) lands in this process's directory.
    let process = crate::process::Process::start(name);
    let (process_id, thread_id) = (process.id(), process.main_thread().thread_id());
    let space = process.vm();
    // The regions first: every user page the kernel maps lies in one.
    seed_regions(space, image.image_base, image.size_of_image);

    // The system DLLs, in load order, before the snap: IAT slots receive their user-space
    // addresses.
    map_system_dlls(space);
    // KUSER_SHARED_DATA, read-only, the kernel's page.
    crate::user::shared::map_into(space);
    let snap = image.snap_imports(file, staging, resolve_import);

    // Map the staged image at its preferred base, one frame per page, each with its sections'
    // protection (writable exactly where a mapped section is writable).
    let pages = image.size_of_image.div_ceil(PAGE_SIZE);
    for page in 0..pages {
        let offset = (page * PAGE_SIZE) as usize;
        let end = (offset + PAGE_SIZE as usize).min(staging.len());
        let frame = paging::allocate_frame_phys();
        paging::init_frame(frame, 0, &staging[offset..end]);
        let va = image.image_base + page * PAGE_SIZE;
        vm::map_prepared(space, va, frame, page_protect(&image, page * PAGE_SIZE));
    }

    // The user stack: two zeroed, writable pages committed at the top of the main thread's
    // reservation, below the entry ESP (the rest commits on demand).
    for stack_page in [USER_STACK_PAGE, USER_STACK_LOW_PAGE] {
        vm::map_zeroed(space, stack_page, vm::PAGE_READWRITE);
    }
    // The guard page below them: the stack's first touch past its committed pages grows it.
    crate::user::stack::plant_guard(space, USER_STACK_LOW_PAGE - PAGE_SIZE);

    // The main thread's TEB, reached through the TEB segment: its stack, its client id and its
    // process's, the PEB.
    crate::user::teb::map_teb(
        space,
        &crate::user::teb::TebInit {
            teb: TEB_PAGE,
            stack_base: USER_STACK_TOP,
            stack_limit: USER_STACK_LOW_PAGE,
            deallocation_stack: USER_STACK_BASE,
            process_id,
            thread_id,
            peb: crate::user::PEB_PAGE,
        },
    );

    // The process parameters (the command line, the image's path, the standard handles, the empty
    // environment block) and the loader's module lists (the image, then the system DLLs), and the
    // PEB pointing at them: the system's version and the image's subsystem.
    let module = crate::user::ldr::Module {
        base: image.image_base,
        entry_point: image.entry_va(),
        size: image.size_of_image,
        time_date_stamp: image.time_date_stamp,
        dll: false,
    };
    crate::user::params::map(space, command_line, path, module);
    crate::user::teb::map_peb(
        space,
        &crate::user::teb::PebInit {
            image_base: image.image_base,
            parameters: crate::user::PARAMS_PAGE,
            subsystem: image.subsystem,
            subsystem_version: image.subsystem_version,
        },
    );

    crate::serial_println!(
        "F2K: image loaded (base {:#010x}, entry {:#010x}, {} pages, {} imports snapped)",
        image.image_base,
        image.entry_va(),
        pages,
        snap.thunks
    );
    crate::serial_println!(
        "F2K: entering ring 3 (entry {:#010x}, stack {:#010x})",
        image.entry_va(),
        USER_STACK_TOP
    );
    image.entry_va()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::fat32::fixtures::{record, Crafted};
    use crate::mem::paging::PAGE_SIZE;
    use crate::status::{STATUS_FILE_CORRUPT_ERROR, STATUS_NO_SUCH_FILE};

    const EXIT0: &[u8] = include_bytes!("../../../tests/core/exit0/exit0.exe");
    const RET0: &[u8] = include_bytes!("../../../tests/core/ret0/ret0.exe");

    /// The corpus the disk carries (see the Makefile's disk target), by fixture name.
    const CORPUS: [(&str, &[u8]); 3] = [
        (
            "hello",
            include_bytes!("../../../tests/core/hello/hello.exe"),
        ),
        ("exit0", EXIT0),
        ("ret0", RET0),
    ];

    /// Every corpus file fits the file staging, and every image it describes fits the image
    /// staging, page-aligned.
    #[test]
    fn fixtures_fit_staging() {
        for (name, file) in CORPUS {
            assert!(file.len() <= FILE_STAGING_SIZE, "{name}'s file");
            let image = Image::parse(file).expect("fixture parses");
            assert_eq!(image.size_of_image % PAGE_SIZE, 0, "{name}");
            assert!(
                image.size_of_image as usize <= STAGING_SIZE,
                "{name}'s image"
            );
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

    /// Uncovered pages (the header) are read-only; each section's page carries its section's
    /// access, the writable one copy-on-write (memory/image's `.data: protect 0x8`).
    #[test]
    fn image_pages_carry_their_sections_protections() {
        use crate::mem::vm::{PAGE_EXECUTE_READ, PAGE_READONLY, PAGE_WRITECOPY};
        let image = Image::parse(RET0).unwrap();
        assert_eq!(page_protect(&image, 0), PAGE_READONLY, "the header page");
        let rva = |i| image.section(i).virtual_address;
        assert_eq!(page_protect(&image, rva(0)), PAGE_EXECUTE_READ);
        assert_eq!(page_protect(&image, rva(1)), PAGE_READONLY);
        assert_eq!(page_protect(&image, rva(2)), PAGE_WRITECOPY);
    }

    /// Every corpus image seeds its address space: the image one allocation, each system area its
    /// own region.
    #[test]
    fn the_corpus_seeds_its_regions() {
        use crate::mem::vm::{AddressSpace, Kind, MEM_IMAGE, MEM_PRIVATE};
        for (name, file) in CORPUS {
            let image = Image::parse_program(file).expect("fixture parses as a program");
            let mut space = Box::new(AddressSpace::new());
            seed_regions(&mut space, image.image_base, image.size_of_image);
            let region = space
                .region_at(image.entry_va())
                .expect("the image's region");
            assert_eq!(
                (region.base, region.kind),
                (image.image_base, Kind::Image),
                "{name}"
            );
            for &(area, start, end) in SYSTEM_REGIONS.iter() {
                let region = space.region_at(start).expect(area);
                assert_eq!((region.base, region.size), (start, end - start), "{area}");
            }
            let fake = NoPages;
            assert_eq!(space.query(&fake, image.image_base).mem_type, MEM_IMAGE);
            assert_eq!(
                space.query(&fake, crate::user::TEB_PAGE).mem_type,
                MEM_PRIVATE
            );
        }
    }

    /// Page tables with no entries (a query of a freshly seeded space).
    struct NoPages;

    impl crate::mem::vm::Pages for NoPages {
        fn entry(&self, _va: u32) -> u32 {
            0
        }

        fn set_entry(&mut self, _va: u32, _entry: u32) {}

        fn zeroed_frame(&mut self) -> Option<u32> {
            None
        }

        fn free_frame(&mut self, _frame: u32) {}

        fn share_frame(&mut self, _frame: u32) {}

        fn frame_shared(&self, _frame: u32) -> bool {
            false
        }

        fn copy_frame(&mut self, _from: u32, _to: u32) {}

        fn frame_word(&self, _frame: u32, _index: u32) -> u32 {
            0
        }

        fn set_frame_word(&mut self, _frame: u32, _index: u32, _value: u32) {}
    }

    /// The mapping's protection and the write permission agree on every page of the corpus: a page
    /// is copy-on-write exactly where a section is writable, and the hardware writes none of them
    /// until the first write makes the page the process's own.
    #[test]
    fn page_protections_are_writable_where_their_sections_are() {
        use crate::mem::vm::{decode, encode};
        for (name, file) in CORPUS {
            let image = Image::parse(file).expect("fixture parses");
            for page in 0..image.size_of_image.div_ceil(PAGE_SIZE) {
                let protect = page_protect(&image, page * PAGE_SIZE);
                let entry = encode(0x0050_0000, protect);
                assert_eq!(decode(entry), Some((0x0050_0000, protect)), "{name}");
                assert_eq!(
                    matches!(
                        protect,
                        crate::mem::vm::PAGE_WRITECOPY | crate::mem::vm::PAGE_EXECUTE_WRITECOPY
                    ),
                    page_writable(&image, page * PAGE_SIZE),
                    "{name} page {page}"
                );
                assert_eq!(
                    entry & crate::mem::paging::PAGE_WRITE,
                    0,
                    "{name} page {page}"
                );
            }
        }
    }

    /// Uncovered pages (the header) are read-only; only .data's own page is writable.
    #[test]
    fn page_protection_rules() {
        let ret0 = Image::parse(RET0).expect("ret0 parses");
        assert!(!page_writable(&ret0, 0));
        assert!(page_writable(&ret0, 0x5000));
        assert!(!page_writable(&ret0, 0x4000));
    }

    /// The system regions are ordered, disjoint, page-aligned and in user space.
    #[test]
    fn system_regions_are_ordered_and_disjoint() {
        for (index, &(name, start, end)) in SYSTEM_REGIONS.iter().enumerate() {
            assert!(start < end, "{name}");
            assert_eq!(start % PAGE_SIZE, 0, "{name}");
            assert_eq!(end % PAGE_SIZE, 0, "{name}");
            assert!(end <= crate::exec::pe::USER_SPACE_END, "{name}");
            if let Some(&(next, next_start, _)) = SYSTEM_REGIONS.get(index + 1) {
                assert!(end <= next_start, "{name} runs into {next}");
            }
        }
    }

    /// Every corpus program places at its own preferred base, clear of the system regions.
    #[test]
    fn the_corpus_places_at_its_preferred_bases() {
        for (name, file) in CORPUS {
            let image = Image::parse_program(file).expect("fixture parses as a program");
            assert_eq!(image.image_base, 0x0040_0000, "{name}");
            assert_eq!(
                system_region_overlapping(image.image_base, image.size_of_image),
                None,
                "{name}"
            );
        }
    }

    /// The era's system binaries place at their preferred bases (the images' measured bases, with a
    /// generous size: none comes near a system region).
    #[test]
    fn system_binary_bases_place_cleanly() {
        assert_eq!(
            system_region_overlapping(0x7C4E_0000, 0x1000),
            Some("kernel32.dll image")
        );
        assert_eq!(
            system_region_overlapping(0x77F8_0000, 0x1000),
            Some("ntdll.dll image")
        );
        for base in [0x4AD0_0000, 0x7800_0000, 0x77E1_0000, 0x7C2D_0000] {
            assert_eq!(
                system_region_overlapping(base, 0x0010_0000),
                None,
                "{base:#x}"
            );
        }
    }

    /// An image covering any page of a region is refused, edges included; one ending exactly where
    /// a region starts is not.
    #[test]
    fn images_covering_a_system_region_are_refused() {
        use crate::exec::modules::{KERNEL32_BASE, KERNEL32_SIZE, NTDLL_BASE};
        const REGION: Option<&str> = Some("kernel32.dll image");
        assert_eq!(system_region_overlapping(KERNEL32_BASE, 0x1000), REGION);
        // The image's last page.
        assert_eq!(
            system_region_overlapping(KERNEL32_BASE + KERNEL32_SIZE - 0x1000, 0x1000),
            REGION
        );
        assert_eq!(
            system_region_overlapping(KERNEL32_BASE + KERNEL32_SIZE, 0x1000),
            None
        );
        assert_eq!(
            system_region_overlapping(KERNEL32_BASE - 0x1_0000, 0x1_0000),
            None
        );
        assert_eq!(
            system_region_overlapping(KERNEL32_BASE - 0x1_0000, 0x1_1000),
            REGION
        );
        assert_eq!(
            system_region_overlapping(NTDLL_BASE, 0x1000),
            Some("ntdll.dll image")
        );
        // A 16 MiB image at the corpus base reaches the child-thread regions.
        assert_eq!(
            system_region_overlapping(0x0040_0000, crate::exec::pe::MAX_IMAGE_SIZE),
            Some("child thread TEBs")
        );
        // The low window holds the main thread's pages.
        assert_eq!(
            system_region_overlapping(0x0001_0000, 0x0030_0000),
            Some("main thread stack")
        );
        assert_eq!(
            system_region_overlapping(0x0035_2000, 0x1_0000),
            Some("environment block")
        );
        assert_eq!(
            system_region_overlapping(0x0200_0000, 0x1_0000),
            None,
            "the heaps' reservations are the program's own (NtAllocateVirtualMemory)"
        );
    }

    /// The module table: the system DLLs' exports, under any spelling of the module's name; nothing
    /// else.
    #[test]
    fn imports_resolve_through_the_module_table() {
        let exit = crate::exec::modules::kernel32_export("ExitProcess");
        assert!(exit.is_some());
        for module in ["KERNEL32.dll", "kernel32.DLL", "KERNEL32"] {
            assert_eq!(resolve_import(module, "ExitProcess").ok(), exit, "{module}");
        }
        assert_eq!(
            resolve_import("KERNEL32.dll", "NoSuchExport"),
            Err(Unresolved::NoEntry)
        );
        // Export names are case-sensitive.
        assert_eq!(
            resolve_import("KERNEL32.dll", "exitprocess"),
            Err(Unresolved::NoEntry)
        );
        // kernel32's RtlUnwind forwards into ntdll.
        assert_eq!(
            resolve_import("KERNEL32.dll", "RtlUnwind"),
            resolve_import("ntdll.dll", "RtlUnwind")
        );
        for module in ["MSVCRT.dll", "USER32.dll", "KERNEL32.exe"] {
            assert_eq!(
                resolve_import(module, "ExitProcess"),
                Err(Unresolved::NoModule),
                "{module}"
            );
        }
    }

    const FILE: u8 = 0x20;
    const DIR: u8 = 0x10;

    /// A crafted volume (1-sector clusters) whose root holds `EXIT0.EXE` — the real fixture, along
    /// clusters 3.. — a subdirectory, and `EMPTY.BIN`.
    fn volume_with_exit0() -> (Crafted, u32) {
        let clusters = EXIT0.len().div_ceil(512) as u32;
        let chain: Vec<u32> = (3..3 + clusters).collect();
        let mut crafted = Crafted::new(1, 2 + clusters as usize + 1);
        crafted.chain(&chain);
        for (cluster, piece) in chain.iter().zip(EXIT0.chunks(512)) {
            crafted.cluster(*cluster, piece);
        }
        let sub = 3 + clusters;
        crafted.directory(
            2,
            &[
                record(b"EXIT0   EXE", FILE, 3, EXIT0.len() as u32),
                record(b"SUB        ", DIR, sub, 0),
                record(b"EMPTY   BIN", FILE, 0, 0),
            ],
        );
        (crafted, sub)
    }

    /// The loader's read: the path as the boots spell it (lowercase; the stored name is uppercase)
    /// delivers the fixture's bytes, which parse as the image.
    #[test]
    fn a_program_is_read_by_its_path() {
        let (crafted, _) = volume_with_exit0();
        let mut volume = Volume::mount(crafted.device()).unwrap();
        let mut buffer = vec![0u8; FILE_STAGING_SIZE];
        let length = read_image_file(&mut volume, b"exit0.exe", &mut buffer).unwrap();
        assert_eq!(&buffer[..length], EXIT0);
        assert_eq!(
            Image::parse(&buffer[..length]).unwrap().entry_va(),
            0x0040_1000
        );

        let empty = read_image_file(&mut volume, b"EMPTY.BIN", &mut buffer);
        assert_eq!(
            empty,
            Ok(0),
            "an empty file reads as nothing (the parse refuses it)"
        );
    }

    /// The refusals, each distinct: a missing file (by its 8.3 or its long name), a malformed path,
    /// a directory, a file larger than the staging, and a corrupt chain.
    #[test]
    fn unreadable_programs_are_refused() {
        let (mut crafted, _) = volume_with_exit0();
        let mut volume = Volume::mount(crafted.device()).unwrap();
        let mut buffer = vec![0u8; FILE_STAGING_SIZE];
        assert_eq!(
            read_image_file(&mut volume, b"missing.exe", &mut buffer),
            Err(FileError::Lookup(LookupError::NotFound))
        );
        assert_eq!(
            read_image_file(&mut volume, b"not-an-8.3-name.exe", &mut buffer),
            Err(FileError::Lookup(LookupError::NotFound)),
            "a long name the directory does not hold"
        );
        assert_eq!(
            read_image_file(&mut volume, b"what?.exe", &mut buffer),
            Err(FileError::Lookup(LookupError::Invalid))
        );
        assert_eq!(
            read_image_file(&mut volume, b"sub", &mut buffer),
            Err(FileError::Directory)
        );
        assert_eq!(
            read_image_file(&mut volume, b"exit0.exe", &mut buffer[..EXIT0.len() - 1]),
            Err(FileError::TooLarge(EXIT0.len() as u32))
        );

        crafted.fat(5, 0);
        let mut broken = Volume::mount(crafted.device()).unwrap();
        assert_eq!(
            read_image_file(&mut broken, b"exit0.exe", &mut buffer),
            Err(FileError::Read(STATUS_FILE_CORRUPT_ERROR))
        );
    }

    /// An image section's pages, as a mapping builds them off the volume: exit0, stored as a DLL
    /// on a crafted volume, parses from its first page alone (the file's length known), and each
    /// page read through the file's chain is the page the whole-image mapping holds.
    #[test]
    fn an_image_maps_page_by_page_off_the_volume() {
        use crate::fs::fat32::lookup::lookup;
        use crate::fs::fat32::read::read_at;
        let mut dll = EXIT0.to_vec();
        let characteristics = u32::from_le_bytes(dll[0x3C..0x40].try_into().unwrap()) as usize + 22;
        dll[characteristics + 1] |= 0x20; // IMAGE_FILE_DLL
        let clusters = dll.len().div_ceil(512) as u32;
        let chain: Vec<u32> = (3..3 + clusters).collect();
        let mut crafted = Crafted::new(1, 2 + clusters as usize);
        crafted.chain(&chain);
        for (cluster, piece) in chain.iter().zip(dll.chunks(512)) {
            crafted.cluster(*cluster, piece);
        }
        crafted.directory(2, &[record(b"COMPANIODLL", FILE, 3, dll.len() as u32)]);
        let mut volume = Volume::mount(crafted.device()).unwrap();
        let file = lookup(&mut volume, b"companio.dll").unwrap();

        let mut headers = vec![0u8; 0x1000];
        assert_eq!(read_at(&mut volume, &file, 0, &mut headers), Ok(0x1000));
        let image = Image::parse_headers(&headers, file.size as usize).unwrap();
        assert!(image.is_dll());
        let mut whole = vec![0u8; image.size_of_image as usize];
        image.map_into(&dll, &mut whole);
        let mut page = vec![0u8; PAGE_SIZE as usize];
        for (index, expected) in whole.chunks(PAGE_SIZE as usize).enumerate() {
            let built = image.map_page(index as u32 * PAGE_SIZE, &mut page, |offset, out| {
                read_at(&mut volume, &file, offset, out) == Ok(out.len())
            });
            assert!(built, "page {index}");
            assert_eq!(&page[..], expected, "page {index}");
        }
    }

    /// The COM1 wording of each refusal carries its status.
    #[test]
    fn refusals_report_their_status() {
        assert_eq!(
            FileError::Lookup(LookupError::NotFound).to_string(),
            format!(
                "lookup failed (NotFound, status {:#010x})",
                STATUS_NO_SUCH_FILE as u32
            )
        );
        assert_eq!(FileError::Directory.to_string(), "a directory, not a file");
        assert_eq!(
            FileError::TooLarge(600_000).to_string(),
            "600000 bytes exceed the file staging (524288 bytes)"
        );
        assert_eq!(
            FileError::Read(STATUS_FILE_CORRUPT_ERROR).to_string(),
            "read failed (status 0xc0000102)"
        );
    }
}
