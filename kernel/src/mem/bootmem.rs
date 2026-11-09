//! Boot-time initialization of the physical frame database.
//!
//! Reads the Multiboot information structure the loader pointed EBX at, turns every available
//! region into usable frame ranges, and releases all of them to the [`FrameDb`] except:
//! - frame 0 (never allocatable), and
//! - the frames the kernel occupies: from the boot's load address (its entry stub) to the end of
//!   the kernel's image (`_kernel_end` from the linker script).
//!
//! The database then lives in the memory manager's database ([`super::Database`]), and serves the
//! rest of the kernel through [`with_frame_db`].

use core::sync::atomic::{AtomicBool, Ordering};

use super::frame::{self, ColorTables, FrameDb, FrameEntry, FrameState, NoHooks, MAX_FRAMES};
use super::layout::KERNEL_IMAGE;
use super::multiboot::{self, BootMemoryPlan, InfoBytes, MemorySource, MultibootInfo, UsableRange};
use super::paging::{KERNEL_BASE, KERNEL_PHYS_BASE};
use crate::sync::StaticBuf;

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
    // The linker-provided symbol's address (fixed at link time); its byte is never read.
    let image_end = core::ptr::addr_of!(_kernel_end) as u32;
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

/// Release every frame of `range` the plan releases (see [`BootMemoryPlan::releases`]), except
/// those an earlier (overlapping) range already released.
fn release_range(db: &mut FrameDb<NoHooks>, range: UsableRange, plan: &BootMemoryPlan) {
    for frame in range.frames() {
        if db.entry(frame).state.is_list_state() || !plan.releases(frame) {
            continue;
        }
        db.release(frame, FrameState::Free);
    }
}

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

/// Build the frame database from the Multiboot information at `multiboot_info_addr`.
///
/// Every read of loader memory is cut at the boot identity window before it is made, and the
/// decisions are the pure plan's ([`multiboot::memory_source`], [`BootMemoryPlan`]): the memory map
/// when the structure offers a sound one, the `mem_upper` size hint otherwise.
///
/// # Panics
///
/// The structure carries no usable memory information, or lies outside the window: without a
/// memory picture the kernel cannot manage frames at all.
pub fn boot_init(multiboot_info_addr: u32) {
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

    let (kernel_first, kernel_end) = kernel_frame_bounds();

    let info_len = core::mem::size_of::<MultibootInfo>();
    let source = with_identity_bytes(multiboot_info_addr, info_len, |info| {
        multiboot::memory_source(InfoBytes(info), BOOT_IDENTITY_LIMIT)
    });
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
        let plan = BootMemoryPlan::new(source, map, kernel_first..kernel_end, MAX_FRAMES);
        for range in plan.ranges() {
            release_range(&mut db, range, &plan);
        }
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
    });

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
