//! Boot-time initialization of the physical frame database.
//!
//! Reads the Multiboot information structure the loader pointed EBX at, turns every available
//! region into usable frame ranges, and releases all of them to the [`FrameDb`] except:
//! - frame 0 (never allocatable), and
//! - the frames the kernel image itself occupies, [`_kernel_start`, `_kernel_end`) from the linker
//!   script.
//!
//! The database then serves the rest of the kernel through [`with_frame_db`].

use super::frame::{self, ColorTables, FrameDb, FrameEntry, FrameState, NoHooks, MAX_FRAMES};
use super::heap::KernelHeap;
use super::multiboot::{self, MultibootInfo, UsableRange};
use super::paging::{KERNEL_BASE, KERNEL_PHYS_BASE};

/// The per-frame bookkeeping table. Sized for the full development memory; frames past the highest
/// usable frame stay unreleased.
static mut FRAME_TABLE: [FrameEntry; MAX_FRAMES] = [FrameEntry::new(); MAX_FRAMES];

/// Color chain heads, kept beside the database the same way.
static mut COLOR_TABLES: ColorTables = ColorTables::new();

/// The boot frame database; built once by [`boot_init`].
static mut BOOT_FRAME_DB: Option<FrameDb<NoHooks>> = None;

// Kernel image end, exported by the linker script (4 KiB aligned, a kernel-window address).
extern "C" {
    static _kernel_end: u8;
}

/// Frames in [first, end) are occupied by the kernel image: from the physical load address up to
/// the aligned end of the image.
fn kernel_frame_bounds() -> (u32, u32) {
    let start = KERNEL_PHYS_BASE / 4096;
    // SAFETY: taking the address of a linker-provided symbol; a constant fixed at link time.
    let end = (unsafe { &_kernel_end as *const u8 as u32 } - KERNEL_BASE).div_ceil(4096);
    (start, end)
}

/// The end of the boot identity window: until the low identity mapping is torn down, physical
/// `[0, 8 MiB)` reads at its own address. The Multiboot structures are read through it.
const BOOT_IDENTITY_LIMIT: u64 = 0x80_0000;

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
fn assert_identity_readable(what: &str, addr: u32, len: usize) {
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
    // SAFETY: the frame table is a static owned by this module; handing its only reference to the
    // database for the kernel's lifetime. Single-threaded boot.
    let table: &'static mut [FrameEntry] = unsafe {
        core::slice::from_raw_parts_mut(
            core::ptr::addr_of_mut!(FRAME_TABLE) as *mut FrameEntry,
            MAX_FRAMES,
        )
    };
    // The frame table lives in BSS; loaders are required to zero it, but this table is large enough
    // that leftover loader data would be indistinguishable from live state, so zero it explicitly.
    for entry in table.iter_mut() {
        *entry = FrameEntry::new();
    }
    // SAFETY: the color tables are a static owned by this module; the database holds their only
    // reference. Single-threaded boot.
    let buckets: &'static mut ColorTables = unsafe { &mut *core::ptr::addr_of_mut!(COLOR_TABLES) };
    let mut db = FrameDb::new(table, buckets, frame::DEFAULT_COLOR_COUNT, NoHooks);

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

    // SAFETY: single-threaded boot; boot_init runs exactly once, before any call to with_frame_db.
    unsafe {
        BOOT_FRAME_DB = Some(db);
    }
}

/// Kernel heap pool: a fixed region inside the kernel image.
pub const HEAP_POOL_SIZE: usize = 256 * 1024;

/// Quirk: the aligned wrapper — a bare `[u8; N]` is only 1-byte aligned, but the heap's 8-aligned
/// `NonNull` writes must not depend on link order.
#[repr(align(8))]
struct HeapPool([u8; HEAP_POOL_SIZE]);

static mut HEAP_POOL: HeapPool = HeapPool([0; HEAP_POOL_SIZE]);

/// The kernel heap; built once by [`heap_init`].
static mut KERNEL_HEAP: Option<KernelHeap> = None;

/// Build the kernel heap over its static pool.
pub fn heap_init() {
    // SAFETY: the pool is a static owned by this module; the heap holds its only reference.
    // Single-threaded boot.
    let pool: &'static mut [u8] = unsafe {
        core::slice::from_raw_parts_mut(
            core::ptr::addr_of_mut!(HEAP_POOL).cast::<u8>(),
            HEAP_POOL_SIZE,
        )
    };
    // SAFETY: single-threaded boot; heap_init runs once, before any call to with_heap.
    unsafe {
        KERNEL_HEAP = Some(KernelHeap::new(pool));
    }
}

/// Run `f` against the kernel heap.
///
/// Contract: called from the single-threaded boot context only (one caller at a time). Panics if
/// called before [`heap_init`].
pub fn with_heap<R>(f: impl FnOnce(&mut KernelHeap) -> R) -> R {
    // SAFETY: the boot context is the only caller, so the mutable reference handed to `f` is never
    // aliased.
    let heap = unsafe {
        (*core::ptr::addr_of_mut!(KERNEL_HEAP))
            .as_mut()
            .expect("kernel heap not initialized")
    };
    f(heap)
}

/// Run `f` against the boot frame database.
///
/// Contract: called from the single-threaded boot context only (one caller at a time). Panics if
/// called before [`boot_init`].
pub fn with_frame_db<R>(f: impl FnOnce(&mut FrameDb<NoHooks>) -> R) -> R {
    // SAFETY: single-threaded boot; the boot context is the only caller, so the mutable reference
    // handed to `f` is never aliased. boot_init runs exactly once, before any call to
    // with_frame_db.
    let db = unsafe {
        (*core::ptr::addr_of_mut!(BOOT_FRAME_DB))
            .as_mut()
            .expect("frame database not initialized")
    };
    f(db)
}

#[cfg(test)]
mod tests {
    /// The heap pool's address is 8-byte aligned regardless of link order (the `NonNull` writes are
    /// alignment-checked).
    #[test]
    fn heap_pool_is_aligned() {
        assert_eq!(core::mem::align_of::<HeapPool>(), 8);
        // SAFETY: read-only address check before any boot code runs.
        let addr = unsafe { core::ptr::addr_of!(super::HEAP_POOL) } as usize;
        assert_eq!(addr % 8, 0);
    }
}
