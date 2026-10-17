//! Kernel-side image loader: run a PE32 file from the boot volume as the user process.
//!
//! [`load_path`] reads the program's file off the boot volume by its path into a raw-file staging
//! buffer; [`load_image`] then parses it, checks that its preferred base places it clear of the
//! system's fixed user regions, stages the in-memory image, snaps the IAT through the module table
//! ([`resolve_import`]), maps the pages at the preferred base with their final protections, and
//! returns the entry point: the caller enters the process as its main thread, which the scheduler
//! starts there.
//!
//! Images are never relocated: an image maps at its preferred base or is refused. The module table
//! holds one module today, the kernel-synthesized kernel32; an import naming any other module fails
//! the snap.
//!
//! Quirk: the file and the image are built in staging buffers — borrowed statics, not stack frames
//! — because the loader runs on the small boot stack. The snap happens in staging, before mapping:
//! mapped pages carry their final protection and ring-0 writes must not touch them.

use core::fmt;

use crate::exec::pe::{same_module, Image, Unresolved};
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
/// with `command_line` as what its GetCommandLineA reports, and return its entry point. A file that cannot be read is reported on COM1 and halts, as a
/// rejected image does. The read blocks on the disk: the boot context halts between interrupts
/// until it completes.
#[cfg(target_arch = "x86")]
pub fn load_path(path: &'static [u8], name: &'static str, command_line: &[u8]) -> u32 {
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
/// refused, not moved. Quirk: the CRT region is open-ended — a NULL reservation starts at its base
/// and extends as far as the request asks — so only its 64 KiB minimum is reserved here; a larger
/// reservation that reaches an image's pages is not yet detected (no address-space bookkeeping
/// exists).
const SYSTEM_REGIONS: [(&str, u32, u32); 10] = {
    use crate::user::{
        PARAMS_PAGE, PEB_PAGE, TEB_PAGE,
        THREAD_TEB_REGION, USER_STACK_BASE, USER_STACK_TOP,
    };
    const PAGE: u32 = crate::mem::paging::PAGE_SIZE;
    const CHILDREN: u32 = crate::process::CHILD_THREADS as u32;
    const THUNK_PAGE: u32 = crate::compat::kernel32::THUNK_PAGE;
    [
        ("main thread stack", USER_STACK_BASE, USER_STACK_TOP),
        ("main thread TEB", TEB_PAGE, TEB_PAGE + PAGE),
        ("process parameters", PARAMS_PAGE, PARAMS_PAGE + PAGE),
        ("process environment block", PEB_PAGE, PEB_PAGE + PAGE),
        (
            "environment block (narrow)",
            crate::compat::envapi::BLOCK_A,
            crate::compat::envapi::BLOCK_A + crate::compat::envapi::BLOCK_A_PAGES * PAGE,
        ),
        (
            "environment block (wide)",
            crate::compat::envapi::BLOCK_W,
            crate::compat::envapi::BLOCK_W + crate::compat::envapi::BLOCK_W_PAGES * PAGE,
        ),
        (
            "child thread TEBs",
            THREAD_TEB_REGION,
            THREAD_TEB_REGION + CHILDREN * PAGE,
        ),
        (
            "thread TLS pages",
            crate::user::tls::TLS_REGION,
            crate::user::tls::TLS_REGION + (CHILDREN + 1) * 2 * PAGE,
        ),
        (
            "kernel32 thunk and native pages",
            THUNK_PAGE,
            THUNK_PAGE + 2 * PAGE,
        ),
        (
            "kernel32 module headers",
            crate::compat::modules::KERNEL32_BASE,
            crate::compat::modules::KERNEL32_BASE + PAGE,
        ),
    ]
};

/// The implicit-TLS template of the image staged in `staging` (none without a TLS directory),
/// after writing index 0 to the image's index variable. A directory or template outside the image,
/// or a block larger than a thread's implicit-TLS page holds, is refused.
fn tls_template(
    image: &Image,
    staging: &mut [u8],
) -> Result<Option<crate::user::tls::Template>, &'static str> {
    use crate::user::tls;
    let Some((rva, _)) = image.directory(crate::exec::pe::DIR_TLS) else {
        return Ok(None);
    };
    let directory = staging
        .get(rva as usize..)
        .and_then(tls::parse_directory)
        .ok_or("the TLS directory lies outside the image")?;
    let (start, end, index_address, _callbacks, zero_fill) = directory;
    let base = image.image_base;
    let inside = |va: u32, length: u32| {
        va >= base && (va - base) as u64 + length as u64 <= staging.len() as u64
    };
    if start > end || !inside(start, end - start) || !inside(index_address, 4) {
        return Err("the TLS template lies outside the image");
    }
    let template = tls::Template {
        start,
        end,
        zero_fill,
    };
    if template.size() > tls::IMPLICIT_ROOM as u64 {
        return Err("the TLS block exceeds a thread's implicit-TLS page");
    }
    let index = (index_address - base) as usize;
    staging[index..index + 4].copy_from_slice(&0u32.to_le_bytes());
    Ok(Some(template))
}

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
/// to the address an IAT slot receives. The kernel-synthesized kernel32 is the only module; any
/// other name is not loaded.
pub fn resolve_import(module: &str, name: &str) -> Result<u32, Unresolved> {
    if same_module(module, crate::compat::kernel32::MODULE_NAME) {
        return crate::compat::kernel32::resolve(name).ok_or(Unresolved::NoEntry);
    }
    Err(Unresolved::NoModule)
}

/// A page's protection, as VirtualQuery reports it: the combined access of the sections in it (an
/// image's writable pages are copy-on-write); uncovered pages (the header page) are read-only.
fn page_protect(image: &Image, page_rva: u32) -> u32 {
    use crate::mem::vm::{
        PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_WRITECOPY, PAGE_READONLY, PAGE_WRITECOPY,
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

#[cfg(target_arch = "x86")]
/// Record the process's address space as VirtualQuery reports it: the image (one allocation, its
/// pages carrying their sections' protections), and the areas the kernel maps itself.
fn seed_regions(image: &Image) {
    use crate::mem::vm::{Kind, Region, PAGE_EXECUTE_WRITECOPY, PAGE_READWRITE};
    let space = crate::process::current_mut().vm();
    space
        .insert(Region {
            base: image.image_base,
            size: image.size_of_image.next_multiple_of(crate::mem::paging::PAGE_SIZE),
            alloc_protect: PAGE_EXECUTE_WRITECOPY,
            kind: Kind::Image,
        })
        .expect("a fresh address space takes the image");
    for &(name, start, end) in SYSTEM_REGIONS.iter() {
        let image = name == "kernel32 module headers";
        space
            .insert(Region {
                base: start,
                size: end - start,
                alloc_protect: if image { PAGE_EXECUTE_WRITECOPY } else { PAGE_READWRITE },
                kind: if image { Kind::Image } else { Kind::Private },
            })
            .expect("the system regions are disjoint from each other and the image");
    }
}

/// A page's write permission: writable when any section in it is writable (shared pages combine
/// protections); uncovered pages (the header page) are read-only.
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
/// map the image, stack, TEB and parameters pages — and return its entry point for the main
/// thread's ladder. `name` names the process and stages the command line; `path`, the file's volume
/// path, stages the module file name.
#[cfg(target_arch = "x86")]
pub fn load_image(file: &[u8], path: &[u8], name: &'static str, command_line: &[u8]) -> u32 {
    use crate::mem::paging::{self, PAGE_SIZE};
    use crate::user::{TEB_PAGE, USER_STACK_LOW_PAGE, USER_STACK_PAGE, USER_STACK_TOP};

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

    // Implicit TLS: the image's index variable reads 0 (its block is the first and only entry of
    // every thread's array), and its template is recorded for the threads' blocks.
    let tls_template = match tls_template(&image, staging) {
        Ok(template) => template,
        Err(reason) => {
            crate::serial_println!("F2K: image rejected by the loader: {}", reason);
            crate::halt()
        }
    };

    // The process's own state, all in one place: a fresh address space (kernel half inherited,
    // active on CR3), the main thread's ring-0 gate stack (mapped supervisor-only with its guard
    // page; the switch into the thread installs it as the TSS esp0), and fresh heap bookkeeping.
    // Every mapping below (thunk page, image, stack, TEB, params) lands in this process's
    // directory and its services see this process's heap.
    crate::process::Process::start(name);

    // The thunks must be mapped before the snap: IAT slots receive user-space addresses.
    crate::compat::kernel32::init();
    let snap = image.snap_imports(file, staging, resolve_import);
    seed_regions(&image);

    // Map the staged image at its preferred base, one frame per page, writable exactly where a
    // mapped section is writable.
    let pages = image.size_of_image.div_ceil(PAGE_SIZE);
    for page in 0..pages {
        let offset = (page * PAGE_SIZE) as usize;
        let end = (offset + PAGE_SIZE as usize).min(staging.len());
        let frame = paging::allocate_frame_phys();
        paging::init_frame(frame, 0, &staging[offset..end]);
        let va = image.image_base + page * PAGE_SIZE;
        paging::map_user_page(va, frame, page_writable(&image, page * PAGE_SIZE));
        paging::set_user_pte(va, crate::mem::vm::encode(frame, page_protect(&image, page * PAGE_SIZE)));
    }

    // The user stack: two zeroed, writable pages committed at the top of the main thread's
    // reservation (the rest commits on demand), the entry point's return address — the thread-exit
    // trampoline — in the top dword.
    for stack_page in [USER_STACK_PAGE, USER_STACK_LOW_PAGE] {
        let stack_frame = paging::allocate_frame_phys();
        paging::init_frame(stack_frame, 0, &[]);
        if stack_page == USER_STACK_PAGE {
            let trampoline = crate::compat::kernel32::thread_exit_trampoline();
            paging::write_frame(
                stack_frame,
                (crate::user::USER_ENTRY_ESP - USER_STACK_PAGE) as usize,
                &trampoline.to_le_bytes(),
            );
        }
        paging::map_user_page(stack_page, stack_frame, true);
    }
    // The guard page below them: the stack's first touch past its committed pages commits it.
    crate::user::stack::plant_guard(USER_STACK_LOW_PAGE - PAGE_SIZE);

    // The main thread's TLS pages (ordinal 0), the block copied from the now-mapped template.
    crate::process::current_mut().set_tls_template(tls_template);
    let (tls_pointer, tls_expansion) = crate::user::tls::map_thread_pages(0, tls_template);

    // The thread block page, reached through the TEB segment, and the process block it points at.
    let process = crate::process::current();
    crate::user::teb::map_teb(&crate::user::teb::TebInit {
        teb: TEB_PAGE,
        stack_base: USER_STACK_TOP,
        stack_limit: USER_STACK_LOW_PAGE,
        process_id: process.id(),
        thread_id: process.main_thread().thread_id(),
        peb: crate::user::PEB_PAGE,
        tls_pointer,
        tls_expansion,
    });
    let process_heap = {
        let (heaps, space) = crate::process::current_mut().heaps_and_vm();
        heaps.create_process_heap(space)
    };
    crate::user::teb::map_peb(image.image_base, process_heap);

    // The process parameters page: the command line, the environment, the module's own path.
    crate::compat::kernel32::init_params(command_line, path);

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
        crate::user::USER_ENTRY_ESP
    );
    image.entry_va()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::fat32::fixtures::{record, Crafted};
    use crate::mem::paging::PAGE_SIZE;
    use crate::status::{STATUS_FILE_CORRUPT_ERROR, STATUS_NO_SUCH_FILE};

    const EXIT0: &[u8] = include_bytes!("../../../tests/exit0/exit0.exe");
    const RET0: &[u8] = include_bytes!("../../../tests/ret0/ret0.exe");

    /// The corpus the disk carries (see the Makefile's disk target), by fixture name: the legacy
    /// smokes, then the sectioned fixtures.
    const CORPUS: [(&str, &[u8]); 11] = [
        ("hello", include_bytes!("../../../tests/hello/hello.exe")),
        ("exit0", EXIT0),
        ("ret0", RET0),
        ("bare", include_bytes!("../../../tests/bare/bare.exe")),
        (
            "runtime",
            include_bytes!("../../../tests/runtime/runtime.exe"),
        ),
        ("memory", include_bytes!("../../../tests/memory/memory.exe")),
        (
            "threads",
            include_bytes!("../../../tests/threads/threads.exe"),
        ),
        ("sync", include_bytes!("../../../tests/sync/sync.exe")),
        ("sched", include_bytes!("../../../tests/sched/sched.exe")),
        ("files", include_bytes!("../../../tests/files/files.exe")),
        (
            "fswrite",
            include_bytes!("../../../tests/fswrite/fswrite.exe"),
        ),
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

    /// Uncovered pages (the header) are read-only; only .data's own page is writable.
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

    /// The threads fixture's `__declspec(thread)` data: a template inside the image, small enough
    /// for a thread's page, its index variable set to 0; an image without a TLS directory has none.
    #[test]
    fn implicit_tls_templates() {
        let file: &[u8] = include_bytes!("../../../tests/threads/threads.exe");
        let image = Image::parse_program(file).expect("threads parses");
        let mut staging = vec![0xAAu8; image.size_of_image as usize];
        image.map_into(file, &mut staging);
        let (rva, _) = image
            .directory(crate::exec::pe::DIR_TLS)
            .expect("threads has TLS");
        let (_, _, index_address, ..) =
            crate::user::tls::parse_directory(&staging[rva as usize..]).unwrap();
        let index = (index_address - image.image_base) as usize;
        staging[index..index + 4].copy_from_slice(&[0xAA; 4]);
        let template = tls_template(&image, &mut staging)
            .unwrap()
            .expect("a template");
        assert!(template.start >= image.image_base && template.start <= template.end);
        assert!(template.size() > 0 && template.size() <= crate::user::tls::IMPLICIT_ROOM as u64);
        assert_eq!(&staging[index..index + 4], &[0; 4]);

        let mut staging = vec![0u8; Image::parse_program(EXIT0).unwrap().size_of_image as usize];
        let exit0 = Image::parse_program(EXIT0).unwrap();
        exit0.map_into(EXIT0, &mut staging);
        assert_eq!(tls_template(&exit0, &mut staging), Ok(None));
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
    /// generous size: none comes near a system region) — but kernel32, which is the surface itself:
    /// its measured base holds its module headers.
    #[test]
    fn system_binary_bases_place_cleanly() {
        assert_eq!(
            system_region_overlapping(0x7C4E_0000, 0x1000),
            Some("kernel32 module headers")
        );
        for base in [0x4AD0_0000, 0x7800_0000, 0x77E1_0000, 0x7C2D_0000] {
            assert_eq!(
                system_region_overlapping(base, 0x0010_0000),
                None,
                "{base:#x}"
            );
        }
    }

    /// An image covering any page of a region is refused, edges included; one ending exactly where a
    /// region starts is not.
    #[test]
    fn images_covering_a_system_region_are_refused() {
        use crate::compat::kernel32::THUNK_PAGE;
        const REGION: Option<&str> = Some("kernel32 thunk and native pages");
        assert_eq!(system_region_overlapping(THUNK_PAGE, 0x1000), REGION);
        // The native page, the region's second.
        assert_eq!(
            system_region_overlapping(THUNK_PAGE + 0x1000, 0x1000),
            REGION
        );
        assert_eq!(system_region_overlapping(THUNK_PAGE + 0x2000, 0x1000), None);
        assert_eq!(
            system_region_overlapping(THUNK_PAGE - 0x1_0000, 0x1_0000),
            None
        );
        assert_eq!(
            system_region_overlapping(THUNK_PAGE - 0x1_0000, 0x1_1000),
            REGION
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
        // The heaps are reservations of their own now: no fixed region to collide with.
        assert_eq!(system_region_overlapping(0x0200_0000, 0x1_0000), None);
    }

    /// The module table: kernel32's registry, under any spelling of its name; nothing else.
    #[test]
    fn imports_resolve_through_the_module_table() {
        let exit = crate::compat::kernel32::resolve("ExitProcess");
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

    /// The refusals, each distinct: a missing file (by either kind of name), a malformed path, a
    /// directory, a file larger than the staging, and a corrupt chain.
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
            Err(FileError::Lookup(LookupError::NotFound))
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
