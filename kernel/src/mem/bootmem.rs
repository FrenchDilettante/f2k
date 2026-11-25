//! Boot-time initialization of the physical frame database.
//!
//! Reads the Multiboot information structure the loader pointed EBX at, sizes the frame database
//! from it (one entry per frame up to the highest usable one: [`DatabasePlacement`]), places and
//! maps the database in frames of its own, turns every available region into usable frame ranges,
//! and releases all of them to the [`FrameDb`], a run of consecutive frames at a time, except:
//! - frame 0 (never allocatable),
//! - the frames the kernel's image occupies: from its base to the end of its last section, as its
//!   own headers give its size, and
//! - the boot loader's memory, from its load address to the kernel's image: its page tables are the
//!   ones the processor walks until the kernel's own boot directory replaces them. The boot gives
//!   those frames back then ([`release_loader_memory`]), as Windows 2000 frees its loader's memory
//!   once the kernel no longer needs it, and
//! - the disk image a boot loader loaded as a module ([`multiboot::DISK_MODULE`]): the RAM disk
//!   reads and writes its frames for the kernel's lifetime ([`disk_module`]), and
//! - the frame database's own storage and page tables, kept for the kernel's lifetime.
//!
//! The database then lives in the memory manager's database ([`super::Database`]), and serves the
//! rest of the kernel through [`with_frame_db`].

use core::ops::Range;
use core::sync::atomic::{AtomicBool, Ordering};

use rtl::image::{nt_headers_offset, ImageNtHeaders32, NT_SIGNATURE, PE32_MAGIC};
use rtl::pod::Pod;

use super::frame::{
    self,
    ColorTables,
    FrameDb,
    FrameEntry,
    FrameState,
    NoHooks,
    PHYSICAL_FRAME_LIMIT,
};
use super::layout::{FRAME_DATABASE, KERNEL_IMAGE, NTOSKRNL_BASE};
use super::multiboot::{
    self,
    BootMemoryPlan,
    DatabasePlacement,
    InfoBytes,
    MemorySource,
    Module,
    MultibootInfo,
};
use super::paging::{KERNEL_BASE, LOADER_PHYS_BASE, PAGE_SIZE};
use crate::sync::{InitOnce, StaticBuf};

/// The first frame of the run of conventional memory the real-mode trampoline owns (physical
/// 0x90000, below the extended BIOS data area and the VGA hole): its code, its save area and the
/// BIOS's reply blocks, its real-mode stack and the mode-info buffer (see
/// `hw::vbe::trampoline`). Fixed, because the trampoline's real-mode segment is derived from it.
pub const TRAMPOLINE_FIRST_FRAME: u32 = 0x90;
/// How many frames the trampoline's run holds: 0x90000-0x9AFFF.
pub const TRAMPOLINE_FRAMES: u32 = 11;

/// Whether the trampoline's run was taken out of the free lists at boot: then no other owner ever
/// has those frames, and the trampoline and the BIOS write them freely. False when a frame of the
/// run was not free (a firmware reservation, or a boot without a memory map, whose low frames
/// never enter the database), which leaves the VBE mode set unservable.
pub static TRAMPOLINE_RESERVED: AtomicBool = AtomicBool::new(false);

/// Color chain heads, kept beside the database the same way.
static COLOR_TABLES: StaticBuf<ColorTables> = StaticBuf::new(ColorTables::new());

/// The kernel's image's first frame: its base's, its headers' page.
const IMAGE_FIRST_FRAME: u32 = (NTOSKRNL_BASE - KERNEL_BASE) / PAGE_SIZE;

/// The boot loader's frames: from its load address to the kernel's image, the rest of the kernel
/// image window's entry span.
const LOADER_FRAMES: Range<u32> = LOADER_PHYS_BASE / PAGE_SIZE..IMAGE_FIRST_FRAME;

/// Which of the boot loader's frames are memory to release once the loader's tables are no longer
/// walked: the ones the memory picture releases (usable, not reserved), one bit per frame of
/// [`LOADER_FRAMES`].
struct LoaderMemory([u32; LOADER_WORDS]);

/// The words of [`LoaderMemory`]'s bits.
const LOADER_WORDS: usize = (LOADER_FRAMES.end - LOADER_FRAMES.start).div_ceil(32) as usize;

impl LoaderMemory {
    fn holds(&self, frame: u32) -> bool {
        let bit = frame - LOADER_FRAMES.start;
        self.0[(bit / 32) as usize] & 1 << (bit % 32) != 0
    }
}

/// The boot loader's frames to release, recorded by [`boot_init`].
static LOADER_MEMORY: InitOnce<LoaderMemory> = InitOnce::new();

/// The disk image's module, physical bytes, recorded by [`boot_init`]: none when the boot loader
/// loaded none.
static DISK_MODULE: InitOnce<Option<Range<u32>>> = InitOnce::new();

/// The pages of physical memory the boot's memory picture describes, recorded by [`boot_init`]
/// ([`BootMemoryPlan::physical_pages`]).
static PHYSICAL_PAGES: InitOnce<u32> = InitOnce::new();

/// The size of an image in memory (its SizeOfImage), from its headers' bytes: none when they are
/// not a PE32 image's.
fn image_size(headers: &[u8]) -> Option<u32> {
    let offset = nt_headers_offset(&Pod::from_bytes(headers)?)?;
    let nt: ImageNtHeaders32 = Pod::from_bytes(headers.get(offset..)?)?;
    (nt.signature == NT_SIGNATURE && nt.optional_header.magic == PE32_MAGIC)
        .then_some(nt.optional_header.size_of_image)
}

/// The frames the kernel's image occupies: from its base to the end of its last section, its
/// export directory and base relocations past its statics included, as its own headers give its
/// size.
///
/// # Panics
///
/// The headers are not a PE32 image's, or the image ends past the kernel image window (the boot
/// loader checks the same before it enters the kernel): its last pages would be unmapped.
fn image_frames() -> Range<u32> {
    // SAFETY: the boot loader mapped the image at its base, its headers in its first page, inside
    // the kernel image window; nothing writes the headers.
    let headers =
        unsafe { core::slice::from_raw_parts(NTOSKRNL_BASE as *const u8, PAGE_SIZE as usize) };
    let size = image_size(headers).expect("the kernel's image headers are not a PE32 image's");
    let end = NTOSKRNL_BASE as u64 + size as u64;
    assert!(
        end <= KERNEL_IMAGE.end(),
        "the kernel image ends at {end:#010x}, past its window's end {:#010x}",
        KERNEL_IMAGE.end()
    );
    IMAGE_FIRST_FRAME..(end as u32 - KERNEL_BASE).div_ceil(PAGE_SIZE)
}

/// The end of the boot identity window: until the low identity mapping is torn down, physical
/// `[0, 16 MiB)` (the span of the kernel image window) reads at its own address. The Multiboot
/// structures are read through it.
pub(crate) const BOOT_IDENTITY_LIMIT: u64 = KERNEL_IMAGE.size() as u64;

/// Run `read` on the loader memory `[addr, addr + len)` cut at the boot identity window's end (see
/// [`multiboot::readable_len`]): an empty slice when `addr` lies outside the window. Nothing past
/// the window is read, whatever the loader's values say, and the slice does not outlive the call.
pub(crate) fn with_identity_bytes<R>(addr: u32, len: usize, read: impl FnOnce(&[u8]) -> R) -> R {
    let len = multiboot::readable_len(addr, len, BOOT_IDENTITY_LIMIT);
    if len == 0 {
        return read(&[]);
    }
    // SAFETY: `[addr, addr + len)` lies inside the boot identity window (cut above), where physical
    // memory reads at its own address: the boot reads loader memory only in `boot::memory`'s steps
    // that run before the window's teardown. The single-threaded boot writes none of it while the
    // slice, which `read` cannot keep, is borrowed (the frame database's releases write no frame).
    read(unsafe { core::slice::from_raw_parts(addr as *const u8, len) })
}

/// The module the boot loader loaded with the name [`multiboot::DISK_MODULE`], the first so named:
/// none when the structure offers no module list, or no module of it carries the name. The list
/// and each command line are read through the boot identity window, so a list or a command line
/// past it names nothing.
fn find_disk_module(info: InfoBytes) -> Option<Module> {
    let (addr, count) = info.modules()?;
    let len = count.min(multiboot::MODULE_LIMIT) as usize * multiboot::MODULE_RECORD;
    with_identity_bytes(addr, len, |list| {
        multiboot::module_records(list).find(|module| {
            with_identity_bytes(
                module.string,
                multiboot::MODULE_COMMAND_LINE_LIMIT,
                |line| multiboot::names(line, multiboot::DISK_MODULE),
            )
        })
    })
}

/// Build the frame database from the Multiboot information at `multiboot_info_addr`.
///
/// Every read of loader memory is cut at the boot identity window before it is made, and the
/// decisions are the pure plan's ([`multiboot::memory_source`], [`BootMemoryPlan`]): the memory map
/// when the structure offers a sound one, the `mem_upper` size hint otherwise. The disk image's
/// module, when the boot loader loaded one, is found first, and its frames are withheld as the
/// kernel image's are. The database is sized from the plan, one entry per frame up to the highest
/// usable one below 4 GiB, placed in frames the plan then withholds ([`DatabasePlacement`]), and
/// mapped at its region before its first entry is written ([`map_database`]).
///
/// # Panics
///
/// The structure carries no usable memory information, or lies outside the window: without a
/// memory picture the kernel cannot manage frames at all. Or the memory holds no room for the
/// database.
pub fn boot_init(multiboot_info_addr: u32) {
    let image = image_frames();

    let info_len = core::mem::size_of::<MultibootInfo>();
    let (source, module) = with_identity_bytes(multiboot_info_addr, info_len, |info| {
        (
            multiboot::memory_source(InfoBytes(info), BOOT_IDENTITY_LIMIT),
            find_disk_module(InfoBytes(info)),
        )
    });
    // A module holding no bytes is no disk; one that does is withheld whole, every frame holding
    // any of its bytes.
    let module = module.filter(|module| module.bytes().is_some());
    let withheld = module.map_or(0..0, |module| module.frames());
    DISK_MODULE.set(module.and_then(|module| module.bytes()));
    let Some(source) = source else {
        panic!("Multiboot info carries no memory information");
    };
    // The map's range, already inside the window (the source vouches for it), so the read returns
    // it whole; nothing is read for the fallback.
    let (map_addr, map_len) = match source {
        MemorySource::Map { addr, len } => (addr, len),
        MemorySource::UpperMemory { .. } => (0, 0),
    };
    with_identity_bytes(map_addr, map_len, |map| {
        // The loader's frames and the image's are kept; which of the loader's to release once its
        // tables are no longer walked is the plan the image's frames alone would make.
        let plan = BootMemoryPlan::new(
            source,
            map,
            LOADER_FRAMES.start..image.end,
            PHYSICAL_FRAME_LIMIT,
        )
        .withholding(withheld.clone());
        PHYSICAL_PAGES.set(plan.physical_pages());
        // The database, sized from the plan and placed in frames the plan then withholds.
        let placement = DatabasePlacement::new(&plan)
            .expect("no room for the frame database in the boot's memory");
        let plan = plan
            .withholding(placement.tables.clone())
            .withholding(placement.storage.clone());
        let mut db = FrameDb::new(
            map_database(&placement),
            COLOR_TABLES.take(),
            frame::DEFAULT_COLOR_COUNT,
            NoHooks,
        );
        for run in plan.released_runs() {
            db.release_run(run, FrameState::Free);
        }
        let after = BootMemoryPlan::new(source, map, image.clone(), PHYSICAL_FRAME_LIMIT)
            .withholding(withheld)
            .withholding(placement.tables)
            .withholding(placement.storage);
        let mut loader = LoaderMemory([0; LOADER_WORDS]);
        for run in after.released_runs() {
            for frame in run.start.max(LOADER_FRAMES.start)..run.end.min(LOADER_FRAMES.end) {
                let bit = frame - LOADER_FRAMES.start;
                loader.0[(bit / 32) as usize] |= 1 << (bit % 32);
            }
        }
        LOADER_MEMORY.set(loader);
        // Reserve the trampoline's run for the real-mode VBE mode set, all or none: every byte the
        // trampoline and the BIOS write while it runs is in it, so they write no frame another
        // owner holds. Without a memory map the low frames never entered the database, and the
        // mode set reports none.
        let run = TRAMPOLINE_FIRST_FRAME..TRAMPOLINE_FIRST_FRAME + TRAMPOLINE_FRAMES;
        if plan.reserves(run.clone()) {
            for frame in run {
                db.take(frame);
            }
            TRAMPOLINE_RESERVED.store(true, Ordering::Relaxed);
        }
        super::with_database(|database| {
            assert!(database.frames.is_none(), "the frame database built twice");
            database.frames = Some(db);
        });
    });
}

/// Map the database's storage at its region ([`super::paging::map_frame_database`]) and hand its
/// entries over, every one fresh: the frames come from the firmware as they are, so they are
/// zeroed through the mapping (a fresh entry is all zero bits, [`FrameEntry::new`]).
fn map_database(placement: &DatabasePlacement) -> &'static mut [FrameEntry] {
    super::paging::map_frame_database(placement.tables.clone(), placement.storage.clone());
    let entries = FRAME_DATABASE.start as *mut FrameEntry;
    let len = placement.frames as usize;
    // SAFETY: the region maps the storage from its start, `DatabasePlacement::pages(frames)`
    // pages, enough for `len` entries; the storage's frames are withheld from the frame database
    // for the kernel's lifetime, so nothing else ever writes them. The region is aligned for
    // entries (a page boundary). Zeroed first, every entry is a valid fresh one, and the slice,
    // made once, is the only reference to them.
    unsafe {
        entries.write_bytes(0, len);
        core::slice::from_raw_parts_mut(entries, len)
    }
}

/// The pages of physical memory: the usable frames the boot's memory picture describes, whatever
/// holds them (SystemBasicInformation's NumberOfPhysicalPages).
///
/// # Panics
///
/// Called before [`boot_init`].
pub fn physical_pages() -> u32 {
    *PHYSICAL_PAGES.get()
}

/// Give the boot loader's memory back to the frame database: the frames of it the memory picture
/// releases ([`boot_init`] recorded them). Called once, as soon as the kernel's own boot directory
/// has replaced the loader's: nothing walks the loader's tables or runs on its stack from then on,
/// and the boot reads none of its structures.
///
/// # Panics
///
/// Called before [`boot_init`], or twice.
pub fn release_loader_memory() {
    let loader = LOADER_MEMORY.get();
    with_frame_db(|db| {
        for frame in LOADER_FRAMES.filter(|&frame| loader.holds(frame)) {
            db.release(frame, FrameState::Free);
        }
    });
}

/// The disk image's module, physical bytes `[start, end)`: the frames [`boot_init`] withheld for
/// it. None when the boot loader loaded no module named [`multiboot::DISK_MODULE`].
///
/// # Panics
///
/// Called before [`boot_init`].
pub fn disk_module() -> Option<Range<u32>> {
    DISK_MODULE.get().clone()
}

/// Run `f` against the frame database: the bridge for code that does not hold the memory manager's
/// database, which it borrows for the call (see [`super::with_database`]), interrupts masked.
///
/// # Panics
///
/// Called before [`boot_init`], or from inside a borrow of the memory manager's database.
pub fn with_frame_db<R>(f: impl FnOnce(&mut FrameDb<NoHooks>) -> R) -> R {
    super::with_database(|database| f(database.frames()))
}

#[cfg(test)]
mod tests {
    use rtl::image::{ImageDosHeader, DOS_MAGIC};

    use super::*;

    /// A headers' page: the DOS header pointing at NT headers of `signature` and `magic`, whose
    /// SizeOfImage is `size`.
    fn headers(signature: u32, magic: u16, size: u32) -> Vec<u8> {
        let dos = ImageDosHeader {
            e_magic: DOS_MAGIC,
            e_dos: [0; 29],
            e_lfanew: 0x80,
        };
        let mut nt = ImageNtHeaders32::zeroed();
        nt.signature = signature;
        nt.optional_header.magic = magic;
        nt.optional_header.size_of_image = size;
        let mut page = vec![0; PAGE_SIZE as usize];
        page[..dos.as_bytes().len()].copy_from_slice(dos.as_bytes());
        page[0x80..0x80 + nt.as_bytes().len()].copy_from_slice(nt.as_bytes());
        page
    }

    /// The image's size comes from its PE32 headers, and nothing else passes for them.
    #[test]
    fn the_image_size_is_its_headers() {
        assert_eq!(
            image_size(&headers(NT_SIGNATURE, PE32_MAGIC, 0x8C_5000)),
            Some(0x8C_5000)
        );
        assert_eq!(image_size(&headers(0, PE32_MAGIC, 0x8C_5000)), None);
        assert_eq!(image_size(&headers(NT_SIGNATURE, 0x20B, 0x8C_5000)), None);
        let mut not_mz = headers(NT_SIGNATURE, PE32_MAGIC, 0x8C_5000);
        not_mz[0] = 0;
        assert_eq!(image_size(&not_mz), None);
        assert_eq!(image_size(&[0x4D, 0x5A]), None);
    }

    /// The boot loader's frames are the entry span's past its load address: from 1 MiB to the
    /// image, which starts on the window's second directory entry.
    #[test]
    fn the_loader_frames_lead_up_to_the_image() {
        assert_eq!(LOADER_FRAMES, 0x100..0x400);
        assert_eq!(IMAGE_FIRST_FRAME, LOADER_FRAMES.end);
        assert_eq!(
            LOADER_WORDS * 32,
            (LOADER_FRAMES.end - LOADER_FRAMES.start) as usize
        );
        let mut loader = LoaderMemory([0; LOADER_WORDS]);
        loader.0[1] = 1 << 3;
        assert!(loader.holds(0x100 + 35));
        assert!(!loader.holds(0x100 + 34) && !loader.holds(0x100));
    }
}
