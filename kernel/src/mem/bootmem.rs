//! Boot-time initialization of the physical frame database.
//!
//! Reads the Multiboot information structure the loader pointed EBX
//! at, turns every available region into usable frame ranges, and
//! releases all of them to the [`FrameDb`] except:
//! - frame 0 (never allocatable), and
//! - the frames the kernel image itself occupies,
//!   [`_kernel_start`, `_kernel_end`) from the linker script.
//!
//! The database then serves the rest of the kernel through
//! [`with_frame_db`].

use super::frame::{
    self, ColorTables, FrameDb, FrameEntry, FrameState, NoHooks, MAX_FRAMES,
};
use super::multiboot::{self, MultibootInfo, UsableRange};

/// The per-frame bookkeeping table. Sized for the full development
/// memory; frames past the highest usable frame stay unreleased.
static mut FRAME_TABLE: [FrameEntry; MAX_FRAMES] = [FrameEntry::new(); MAX_FRAMES];

/// Color chain heads, kept beside the database the same way.
static mut COLOR_TABLES: ColorTables = ColorTables::new();

/// The boot frame database; built once by [`boot_init`].
static mut BOOT_FRAME_DB: Option<FrameDb<NoHooks>> = None;

// Kernel image bounds, exported by the linker script (4 KiB aligned).
extern "C" {
    static _kernel_start: u8;
    static _kernel_end: u8;
}

/// Frames in [first, end) are occupied by the kernel image.
fn kernel_frame_bounds() -> (u32, u32) {
    // SAFETY: taking the addresses of linker-provided symbols; the
    // values are constants fixed at link time.
    let start = unsafe { &_kernel_start as *const u8 as u32 } / 4096;
    let end = (unsafe { &_kernel_end as *const u8 as u32 } + 4095) / 4096;
    (start, end)
}

/// Release every frame of `range` except those the kernel occupies.
fn release_range(db: &mut FrameDb<NoHooks>, range: UsableRange, kernel: (u32, u32)) {
    for frame in range.frames() {
        if frame >= kernel.0 && frame < kernel.1 {
            continue;
        }
        db.release(frame, FrameState::Free);
    }
}

/// Build the frame database from the Multiboot information at
/// `multiboot_info_addr`.
///
/// Prefers the memory map (flags bit 6); falls back to the
/// `mem_upper` size hint (flags bit 0). Panics on a structure that
/// provides neither: without a memory picture the kernel cannot
/// manage frames at all.
pub fn boot_init(multiboot_info_addr: u32) {
    // SAFETY: the address is the one the Multiboot loader left in EBX;
    // paging is off, so physical == linear; the Multiboot contract
    // guarantees the structure is readable. Single-threaded boot.
    let mbi: &MultibootInfo = unsafe { &*(multiboot_info_addr as *const MultibootInfo) };
    // SAFETY: the frame table is a static owned by this module; handing
    // its only reference to the database for the kernel's lifetime.
    // Single-threaded boot.
    let table: &'static mut [FrameEntry] = unsafe {
        core::slice::from_raw_parts_mut(
            core::ptr::addr_of_mut!(FRAME_TABLE) as *mut FrameEntry,
            MAX_FRAMES,
        )
    };
    // The frame table lives in BSS; loaders are required to zero it,
    // but this table is large enough that leftover loader data would
    // be indistinguishable from live state, so zero it explicitly.
    for entry in table.iter_mut() {
        *entry = FrameEntry::new();
    }
    // SAFETY: the color tables are a static owned by this module; the
    // database holds their only reference. Single-threaded boot.
    let buckets: &'static mut ColorTables = unsafe { &mut *core::ptr::addr_of_mut!(COLOR_TABLES) };
    let mut db = FrameDb::new(table, buckets, frame::DEFAULT_COLOR_COUNT, NoHooks);

    let kernel = kernel_frame_bounds();

    if mbi.flags & multiboot::flags::MMAP != 0
        && mbi.mmap_addr != 0
        && mbi.mmap_length != 0
        && (mbi.mmap_length as usize) < 0x10_0000
    {
        // SAFETY: mmap_addr/mmap_length describe the loader-owned
        // memory-map record stream, within mapped RAM; the parser
        // bounds-checks every record before reading it.
        let map: &[u8] = unsafe {
            core::slice::from_raw_parts(mbi.mmap_addr as *const u8, mbi.mmap_length as usize)
        };
        for range in multiboot::usable_ranges(map, MAX_FRAMES) {
            release_range(&mut db, range, kernel);
        }
    } else if mbi.flags & multiboot::flags::MEM_INFO != 0 && mbi.mem_upper != 0 {
        // No memory map: usable memory is one region starting at 1 MiB.
        if let Some(range) =
            multiboot::usable_frames_in(0x100000, mbi.mem_upper as u64 * 1024, MAX_FRAMES)
        {
            release_range(&mut db, range, kernel);
        }
    } else {
        panic!("Multiboot info carries no memory information");
    }

    // SAFETY: single-threaded boot; boot_init runs exactly once, before
    // any call to with_frame_db.
    unsafe {
        BOOT_FRAME_DB = Some(db);
    }
}

/// Run `f` against the boot frame database.
///
/// Contract: called from the single-threaded boot context only (one
/// caller at a time). Panics if called before [`boot_init`].
pub fn with_frame_db<R>(f: impl FnOnce(&mut FrameDb<NoHooks>) -> R) -> R {
    // SAFETY: single-threaded boot; the boot context is the only caller,
    // so the mutable reference handed to `f` is never aliased. boot_init
    // runs exactly once, before any call to with_frame_db.
    let db = unsafe {
        (*core::ptr::addr_of_mut!(BOOT_FRAME_DB))
            .as_mut()
            .expect("frame database not initialized")
    };
    f(db)
}
