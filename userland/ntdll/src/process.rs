//! ntdll's own per-process data, as Windows 2000's ntdll keeps it in its data section (every
//! process its own copy: the kernel maps ntdll's writable pages copy-on-write): the PEB lock, the
//! loader lock, the heap list's lock and the TLS bitmaps' RTL_BITMAP headers. The process's first
//! thread initializes them and points the PEB's fields at them (FastPebLock and its routines,
//! LoaderLock, TlsBitmap and TlsExpansionBitmap), as LdrpInitializeProcess does, before anything
//! else takes them.

use core::sync::atomic::Ordering::Relaxed;
use core::sync::atomic::{AtomicPtr, AtomicU32};

use rtl::bitmap::RtlBitmap;
use rtl::critsec::CriticalSection;
use rtl::heap::Process;
use rtl::sys::{self, Native};

/// The PEB lock (FastPebLock): what serializes the process-wide state's changes (the TLS bitmaps,
/// the environment, the current directory, kernel32's lazily made state).
///
/// It is kept in `.data` with file bytes (zero-initialized data would go to the section's
/// uninitialized tail): a data section with none would have no bytes in the file, and the sections
/// after it would no longer sit at their RVAs in the file, which the kernel reads as ntdll's mapped
/// image.
#[unsafe(link_section = ".data")]
static PEB_LOCK: CriticalSection = CriticalSection::new();

/// The loader lock (LdrpLoaderLock): what the loader holds while it reads or changes the module
/// lists.
static LOADER_LOCK: CriticalSection = CriticalSection::new();

/// The lock over the PEB's heap list.
static HEAP_LIST_LOCK: CriticalSection = CriticalSection::new();

/// An RTL_BITMAP header in ntdll's data: its size and buffer set once, by the process's first
/// thread, then read by the bitmap calls through the PEB's pointer.
#[repr(C)]
struct BitmapHeader {
    size_of_bit_map: AtomicU32,
    buffer: AtomicPtr<u32>,
}

const _: () = {
    // RTL_BITMAP's layout, which the bitmap calls read the header with.
    assert!(size_of::<BitmapHeader>() == size_of::<RtlBitmap>());
    assert!(
        core::mem::offset_of!(BitmapHeader, buffer) == core::mem::offset_of!(RtlBitmap, buffer)
    );
};

impl BitmapHeader {
    const fn new() -> Self {
        Self {
            size_of_bit_map: AtomicU32::new(0),
            buffer: AtomicPtr::new(core::ptr::null_mut()),
        }
    }

    /// RtlInitializeBitMap: the header over `size` bits at `buffer`.
    fn initialize(&self, buffer: *mut u32, size: u32) {
        self.buffer.store(buffer, Relaxed);
        self.size_of_bit_map.store(size, Relaxed);
    }

    fn address(&'static self) -> usize {
        core::ptr::from_ref(self) as usize
    }
}

/// The TLS bitmaps' headers: TlsBitmap over the PEB's TlsBitmapBits (the TEB's 64 slots),
/// TlsExpansionBitmap over its TlsExpansionBitmapBits (the 1024 expansion slots).
static TLS_BITMAP: BitmapHeader = BitmapHeader::new();
static TLS_EXPANSION_BITMAP: BitmapHeader = BitmapHeader::new();

/// The TLS indexes each bitmap covers.
const TLS_SLOTS: u32 = 64;
const TLS_EXPANSION_SLOTS: u32 = 1024;

/// The PEB lock.
pub fn peb_lock() -> &'static CriticalSection {
    &PEB_LOCK
}

/// The loader lock.
pub fn loader_lock() -> &'static CriticalSection {
    &LOADER_LOCK
}

/// The process's heaps: the PEB's list and the lock over it.
pub fn heaps() -> Process {
    Process {
        list: sys::heap_list(),
        lock: &HEAP_LIST_LOCK,
    }
}

/// The heap list's lock made (the process's first thread, before its process heap is made).
pub fn initialize_heap_list_lock() {
    let _ = HEAP_LIST_LOCK.initialize(&Native, 0);
}

/// The PEB lock and the loader lock made, and the TLS bitmaps' headers, with the PEB's fields
/// pointing at them (the process's first thread, before anything takes them): FastPebLock with the
/// routines that take and release it (`enter`, `leave`: RtlEnterCriticalSection and
/// RtlLeaveCriticalSection), LoaderLock, TlsBitmap and TlsExpansionBitmap.
pub fn initialize(enter: usize, leave: usize) {
    let _ = PEB_LOCK.initialize(&Native, 0);
    sys::set_fast_peb_lock(&PEB_LOCK, enter, leave);
    let _ = LOADER_LOCK.initialize(&Native, 0);
    sys::set_loader_lock(&LOADER_LOCK);
    let (slots, expansion) = sys::tls_bitmap_bits();
    TLS_BITMAP.initialize(slots, TLS_SLOTS);
    TLS_EXPANSION_BITMAP.initialize(expansion, TLS_EXPANSION_SLOTS);
    sys::set_tls_bitmaps(TLS_BITMAP.address(), TLS_EXPANSION_BITMAP.address());
}
