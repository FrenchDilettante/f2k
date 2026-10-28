//! Boot-time initialization of the physical frame database.
//!
//! Reads the Multiboot information structure the loader pointed EBX at, turns every available
//! region into usable frame ranges, and releases all of them to the [`FrameDb`] except:
//! - frame 0 (never allocatable), and
//! - the frames the kernel image itself occupies, [`_kernel_start`, `_kernel_end`) from the linker
//!   script.
//!
//! The database then lives in the memory manager's database ([`super::Database`]), and serves the
//! rest of the kernel through [`with_frame_db`].

use super::frame::{self, ColorTables, FrameDb, FrameEntry, FrameState, NoHooks, MAX_FRAMES};
use super::layout::KERNEL_IMAGE;
use super::multiboot::{self, MultibootInfo, UsableRange};
use super::paging::{KERNEL_BASE, KERNEL_PHYS_BASE};
use crate::sync::StaticBuf;

/// The per-frame bookkeeping table. Sized for the full development memory; frames past the highest
/// usable frame stay unreleased.
static FRAME_TABLE: StaticBuf<[FrameEntry; MAX_FRAMES]> =
    StaticBuf::new([FrameEntry::new(); MAX_FRAMES]);

/// Color chain heads, kept beside the database the same way.
static COLOR_TABLES: StaticBuf<ColorTables> = StaticBuf::new(ColorTables::new());

// Kernel image end, exported by the linker script (4 KiB aligned, a kernel-window address).
extern "C" {
    static _kernel_end: u8;
}

/// Frames in [first, end) are occupied by the kernel image: from the physical load address up to
/// the aligned end of the image.
///
/// # Panics
///
/// The image ends past the kernel image window (the linker script checks the same at link time):
/// its last statics would be unmapped.
fn kernel_frame_bounds() -> (u32, u32) {
    let start = KERNEL_PHYS_BASE / 4096;
    // SAFETY: taking the address of a linker-provided symbol; a constant fixed at link time.
    let image_end = unsafe { &_kernel_end as *const u8 as u32 };
    assert!(
        image_end as u64 <= KERNEL_IMAGE.end(),
        "the kernel image ends at {image_end:#010x}, past its window's end {:#010x}",
        KERNEL_IMAGE.end()
    );
    let end = (image_end - KERNEL_BASE).div_ceil(4096);
    (start, end)
}

/// The end of the boot identity window: until the low identity mapping is torn down, physical
/// `[0, 16 MiB)` (the span of the kernel image window) reads at its own address. The Multiboot
/// structures are read through it.
pub(crate) const BOOT_IDENTITY_LIMIT: u64 = KERNEL_IMAGE.size() as u64;

/// Release every frame of `range` except those the kernel occupies, those a reserved record of
/// `map` covers, and those an earlier (overlapping) available record already released.
fn release_range(
    db: &mut FrameDb<NoHooks>,
    range: UsableRange,
    kernel: (u32, u32),
    map: Option<&[u8]>,
) {
    for frame in range.frames() {
        if frame >= kernel.0 && frame < kernel.1 {
            continue;
        }
        if db.entry(frame).state.is_list_state() {
            continue;
        }
        if map.is_some_and(|map| multiboot::frame_is_reserved(map, frame)) {
            continue;
        }
        db.release(frame, FrameState::Free);
    }
}

/// Panic unless `[addr, addr + len)` lies inside the boot identity window, naming `what`: a loader
/// may place its structures anywhere below 4 GiB, and reading one past the window would fault with
/// no diagnostic.
pub(crate) fn assert_identity_readable(what: &str, addr: u32, len: usize) {
    let end = addr as u64 + len as u64;
    assert!(
        end <= BOOT_IDENTITY_LIMIT,
        "{what} at {addr:#010x} (+{len:#x}) lies outside the boot identity window"
    );
}

/// Build the frame database from the Multiboot information at `multiboot_info_addr`.
///
/// Prefers the memory map (flags bit 6); falls back to the `mem_upper` size hint (flags bit 0).
/// Panics on a structure that provides neither: without a memory picture the kernel cannot manage
/// frames at all.
pub fn boot_init(multiboot_info_addr: u32) {
    assert_identity_readable(
        "the Multiboot information",
        multiboot_info_addr,
        core::mem::size_of::<MultibootInfo>(),
    );
    // SAFETY: the address is the one the Multiboot loader left in EBX, inside the boot identity
    // window (checked above), where physical == linear; the Multiboot contract guarantees the
    // structure is readable. Single-threaded boot.
    let mbi: &MultibootInfo = unsafe { &*(multiboot_info_addr as *const MultibootInfo) };
    // The database holds the frame table and the color tables for the kernel's lifetime.
    let table: &'static mut [FrameEntry] = FRAME_TABLE.take();
    // The frame table lives in BSS; loaders are required to zero it, but this table is large enough
    // that leftover loader data would be indistinguishable from live state, so zero it explicitly.
    for entry in table.iter_mut() {
        *entry = FrameEntry::new();
    }
    let mut db = FrameDb::new(
        table,
        COLOR_TABLES.take(),
        frame::DEFAULT_COLOR_COUNT,
        NoHooks,
    );

    let kernel = kernel_frame_bounds();

    if mbi.flags & multiboot::flags::MMAP != 0
        && mbi.mmap_addr != 0
        && mbi.mmap_length != 0
        && (mbi.mmap_length as usize) < 0x10_0000
    {
        assert_identity_readable("the memory map", mbi.mmap_addr, mbi.mmap_length as usize);
        // SAFETY: mmap_addr/mmap_length describe the loader-owned memory-map record stream, inside
        // the boot identity window (checked above); the parser bounds-checks every record before
        // reading it.
        let map: &[u8] = unsafe {
            core::slice::from_raw_parts(mbi.mmap_addr as *const u8, mbi.mmap_length as usize)
        };
        for range in multiboot::usable_ranges(map, MAX_FRAMES) {
            release_range(&mut db, range, kernel, Some(map));
        }
    } else if mbi.flags & multiboot::flags::MEM_INFO != 0 && mbi.mem_upper != 0 {
        // No memory map: usable memory is one region starting at 1 MiB.
        if let Some(range) =
            multiboot::usable_frames_in(0x100000, mbi.mem_upper as u64 * 1024, MAX_FRAMES)
        {
            release_range(&mut db, range, kernel, None);
        }
    } else {
        panic!("Multiboot info carries no memory information");
    }

    super::with_database(|database| {
        assert!(database.frames.is_none(), "the frame database built twice");
        database.frames = Some(db);
    });
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
