//! Kernel-side image loader: run a PE32 file from the boot volume as the user process.
//!
//! [`load_path`] reads the program's file off the boot volume by its path into a raw-file staging
//! buffer; [`load_image`] then parses it, stages the in-memory image, snaps the IAT against the
//! kernel-synthesized kernel32, maps the pages with their final protections, and returns the
//! entry point: the caller enters the process as its main thread, which the scheduler starts there.
//!
//! Quirk: the file and the image are built in staging buffers — borrowed statics, not stack frames
//! — because the loader runs on the small boot stack. The snap happens in staging, before mapping:
//! mapped pages carry their final protection and ring-0 writes must not touch them.

use core::fmt;

use crate::exec::pe::{self, Image};
use crate::fs::fat32::lookup::{lookup, LookupError};
use crate::fs::fat32::read::read;
use crate::fs::fat32::volume::Volume;
use crate::status::{nt_success, NtStatus};

/// The raw-file staging size: the largest program file the loader reads (the corpus's biggest
/// fixture file is 0x7000 bytes).
const FILE_STAGING_SIZE: usize = 0x8000;

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

/// Load the program at `path` on the boot volume as the new current process (see [`load_image`])
/// and return its entry point. A file that cannot be read is reported on COM1 and halts, as a
/// rejected image does. The read blocks on the disk: the boot context halts between interrupts
/// until it completes.
#[cfg(target_arch = "x86")]
pub fn load_path(path: &'static [u8], name: &'static str) -> u32 {
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
    load_image(&staging[..length], path, name)
}

/// The staging buffer size: the largest image the loader accepts (the corpus's biggest fixture is
/// 0x8000).
const STAGING_SIZE: usize = 0x8000;

/// Staging for the in-memory image (see the module doc).
#[cfg(target_arch = "x86")]
static mut IMAGE_STAGING: crate::mem::paging::Aligned<[u8; STAGING_SIZE]> =
    crate::mem::paging::Aligned([0; STAGING_SIZE]);

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
pub fn load_image(file: &[u8], path: &[u8], name: &'static str) -> u32 {
    use crate::mem::paging::{self, PAGE_SIZE};
    use crate::user::{TEB_PAGE, USER_STACK_LOW_PAGE, USER_STACK_PAGE, USER_STACK_TOP};

    // Identity question: bytes this loader does not accept are reported, not panicked on.
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
    // active on CR3), the main thread's ring-0 gate stack (mapped supervisor-only with its guard
    // page; the switch into the thread installs it as the TSS esp0), and fresh heap bookkeeping.
    // Every mapping below (thunk page, image, stack, TEB, params) lands in this process's
    // directory and its services see this process's heap.
    crate::process::Process::start(name);

    // The thunks must be mapped before the snap: IAT slots receive user-space addresses.
    crate::compat::kernel32::init();
    let snap = image.snap_imports(
        file,
        staging,
        crate::compat::kernel32::MODULE_NAME,
        crate::compat::kernel32::resolve,
    );

    // Map the staged image at the fixed base, one frame per page, writable exactly where a mapped
    // section is writable.
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
    crate::compat::kernel32::init_params(name, path);

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

    /// The corpus the disk carries (see the Makefile's disk target), by fixture name.
    const CORPUS: [(&str, &[u8]); 11] = [
        ("hello", include_bytes!("../../../tests/hello/hello.exe")),
        ("exit0", EXIT0),
        ("ret0", RET0),
        (
            "pingpong",
            include_bytes!("../../../tests/pingpong/pingpong.exe"),
        ),
        ("sleep", include_bytes!("../../../tests/sleep/sleep.exe")),
        ("spin", include_bytes!("../../../tests/spin/spin.exe")),
        (
            "suspend",
            include_bytes!("../../../tests/suspend/suspend.exe"),
        ),
        (
            "respawn",
            include_bytes!("../../../tests/respawn/respawn.exe"),
        ),
        (
            "bsscheck",
            include_bytes!("../../../tests/bsscheck/bsscheck.exe"),
        ),
        ("crash", include_bytes!("../../../tests/crash/crash.exe")),
        ("fileio", include_bytes!("../../../tests/fileio/fileio.exe")),
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
    fn page_protection_rules() {
        let ret0 = Image::parse(RET0).expect("ret0 parses");
        assert!(!page_writable(&ret0, 0));
        assert!(page_writable(&ret0, 0x5000));
        assert!(!page_writable(&ret0, 0x4000));
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

    /// The refusals, each distinct: a missing file, a malformed path, a directory, a file larger
    /// than the staging, and a corrupt chain.
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
            FileError::TooLarge(40_000).to_string(),
            "40000 bytes exceed the file staging (32768 bytes)"
        );
        assert_eq!(
            FileError::Read(STATUS_FILE_CORRUPT_ERROR).to_string(),
            "read failed (status 0xc0000102)"
        );
    }
}
