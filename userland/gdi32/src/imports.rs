//! gdi32's seam to the rest of the system: what its code calls, imported by name as Windows 2000's
//! gdi32 imports it (ntdll, kernel32 and user32), win32k's services through gdi32's own stubs (as
//! Windows 2000's gdi32 enters the kernel itself), the process heap through the PEB, and the
//! memory probe its stub routine reads arguments through. The host tests replace the imports with
//! stand-ins of the same shape ([`host`]).
//!
//! Each import is wrapped once here in a safe function over references and slices, a service's
//! failure an `Err` of its status; the only `unsafe` the rest of the DLL's code reaches for an
//! import is here. The caller's memory a service reads or writes is handed to the kernel by
//! address, unread (a [`Caller`]): the kernel reaches it through its fault-tolerant copies.
//!
//! A failed service's status becomes the last error through rtl's table (Windows 2000's gdi32
//! imports no RtlNtStatusToDosError: its win32k sets the last error itself). One import is not
//! Windows 2000's: ntdll's DbgPrint, which the stub routine logs through (`scripts/compat.py`
//! tolerates exactly that one, for the stubs' log line).

use core::ffi::CStr;
use core::ptr::NonNull;

use rtl::gdi::{Size, TextMetricW};
use rtl::heap::HEAP_ZERO_MEMORY;
use rtl::status::NtStatus;

#[cfg(all(target_arch = "x86", not(test)))]
mod raw {
    use rtl::gdi::{Rect, Size, TextMetricW};

    #[link(
        name = "kernel32",
        kind = "raw-dylib",
        import_name_type = "undecorated"
    )]
    unsafe extern "system" {
        /// SetLastError: the calling thread's last error.
        pub fn SetLastError(code: u32);
    }

    #[link(name = "user32", kind = "raw-dylib", import_name_type = "undecorated")]
    unsafe extern "system" {
        /// GetSystemMetrics: a system metric (the screen's size among them).
        pub fn GetSystemMetrics(index: i32) -> i32;
    }

    #[link(name = "ntdll", kind = "raw-dylib", import_name_type = "undecorated")]
    unsafe extern "C" {
        /// DbgPrint: the text the format makes, to the debugger (F2K: COM1, as `F2K: debug:`
        /// lines).
        pub fn DbgPrint(format: *const u8, ...) -> u32;
    }

    #[link(name = "ntdll", kind = "raw-dylib", import_name_type = "undecorated")]
    unsafe extern "system" {
        /// RtlAllocateHeap and RtlFreeHeap: a block of the heap, and its release.
        pub fn RtlAllocateHeap(heap: usize, flags: u32, size: usize) -> *mut u8;
        pub fn RtlFreeHeap(heap: usize, flags: u32, block: *mut u8) -> u32;
        /// RtlUnicodeToMultiByteN: UTF-16 to the ANSI code page, what fits.
        pub fn RtlUnicodeToMultiByteN(
            multi_byte: *mut u8,
            max_bytes: u32,
            bytes_written: *mut u32,
            unicode: *const u16,
            unicode_bytes: u32,
        ) -> u32;
        /// RtlMultiByteToUnicodeN: the ANSI code page to UTF-16, what fits.
        pub fn RtlMultiByteToUnicodeN(
            unicode: *mut u16,
            max_bytes: u32,
            bytes_written: *mut u32,
            multi_byte: *const u8,
            multi_byte_bytes: u32,
        ) -> u32;
    }

    // win32k's services: gdi32's own stubs (generated from its spec's internal syscall records),
    // each raising the gate on its Windows 2000 number. Their symbols are the stubs' labels,
    // undecorated: the leading \u{1} keeps the compiler from adding stdcall's `@<bytes>`.
    core::arch::global_asm!(
        include_str!(concat!(env!("OUT_DIR"), "/consts.s")),
        include_str!(concat!(env!("OUT_DIR"), "/stubs.s")),
    );

    unsafe extern "system" {
        #[link_name = "\u{1}_f2k_nt_NtGdiOpenDCW"]
        pub fn NtGdiOpenDCW(device: *const u16, dc: *mut u32) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtGdiDeleteObjectApp"]
        pub fn NtGdiDeleteObjectApp(object: usize) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtGdiGetStockObject"]
        pub fn NtGdiGetStockObject(index: u32, object: *mut u32) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtGdiSelectBrush"]
        pub fn NtGdiSelectBrush(dc: usize, object: usize, previous: *mut u32) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtGdiSelectPen"]
        pub fn NtGdiSelectPen(dc: usize, object: usize, previous: *mut u32) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtGdiSelectFont"]
        pub fn NtGdiSelectFont(dc: usize, object: usize, previous: *mut u32) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtGdiGetDCDword"]
        pub fn NtGdiGetDCDword(dc: usize, index: u32, value: *mut u32) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtGdiGetAndSetDCDword"]
        pub fn NtGdiGetAndSetDCDword(dc: usize, index: u32, value: u32, previous: *mut u32) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtGdiExtTextOutW"]
        pub fn NtGdiExtTextOutW(
            dc: usize,
            x: i32,
            y: i32,
            options: u32,
            rect: *const Rect,
            string: *const u16,
            count: u32,
            dx: *const i32,
        ) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtGdiGetTextMetricsW"]
        pub fn NtGdiGetTextMetricsW(dc: usize, metric: *mut TextMetricW) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtGdiGetTextExtent"]
        pub fn NtGdiGetTextExtent(
            dc: usize,
            string: *const u16,
            count: u32,
            size: *mut Size,
        ) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtGdiSetPixel"]
        pub fn NtGdiSetPixel(dc: usize, x: i32, y: i32, color: u32, set: *mut u32) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtGdiGetPixel"]
        pub fn NtGdiGetPixel(dc: usize, x: i32, y: i32, color: *mut u32) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtGdiCreateSolidBrush"]
        pub fn NtGdiCreateSolidBrush(color: u32, brush: *mut u32) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtGdiPatBlt"]
        pub fn NtGdiPatBlt(dc: usize, x: i32, y: i32, width: i32, height: i32, rop: u32) -> u32;
    }

    /// The process heap (the PEB's ProcessHeap).
    pub fn process_heap() -> usize {
        rtl::sys::process_heap_handle()
    }
}

#[cfg(test)]
use host as raw;
#[cfg(test)]
pub use host::Probed;
/// The caller's memory as the stub routine reads it: probed byte by byte.
#[cfg(all(target_arch = "x86", not(test)))]
pub use rtl::probe::Probed;

/// A service's answer: success for a status of success, information or warning severity, an
/// error's status its failure.
fn checked(status: u32) -> Result<(), NtStatus> {
    if (status as i32) < 0 {
        Err(NtStatus(status))
    } else {
        Ok(())
    }
}

/// An address in the caller's memory (or this DLL's own, lent for the call), handed to a service
/// unread: the kernel reads or writes it through its fault-tolerant copies (a bad address fails
/// the service), and nothing here dereferences it. Zero for none.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Caller(pub usize);

impl Caller {
    /// No memory: a null address.
    pub const NONE: Caller = Caller(0);

    /// This DLL's own `value`, lent to the service for the call.
    pub fn of<T>(value: &T) -> Caller {
        Caller(value as *const T as usize)
    }

    /// This DLL's own `value`, lent to the service to write.
    pub fn of_mut<T>(value: &mut T) -> Caller {
        Caller(value as *mut T as usize)
    }
}

/// A zeroed block of the process heap, freed when dropped.
pub struct HeapBlock {
    at: NonNull<u8>,
    size: usize,
}

impl HeapBlock {
    /// `size` bytes, zeroed: none when the heap has no room.
    pub fn new(size: usize) -> Option<HeapBlock> {
        // SAFETY: a plain allocation of at least a byte.
        let at =
            unsafe { raw::RtlAllocateHeap(raw::process_heap(), HEAP_ZERO_MEMORY, size.max(1)) };
        NonNull::new(at).map(|at| HeapBlock { at, size })
    }

    /// The block's bytes as UTF-16 units, to write (an odd last byte left out).
    pub fn units_mut(&mut self) -> &mut [u16] {
        // SAFETY: the heap's blocks are 8-aligned (its granularity); the block holds `size`
        // initialized (zeroed) bytes, ours alone while it lives, any of which make a unit.
        unsafe { core::slice::from_raw_parts_mut(self.at.as_ptr().cast(), self.size / 2) }
    }
}

impl Drop for HeapBlock {
    fn drop(&mut self) {
        // SAFETY: our own block, freed once.
        unsafe { raw::RtlFreeHeap(raw::process_heap(), 0, self.at.as_ptr()) };
    }
}

// --- kernel32 ------------------------------------------------------------------------------------

/// SetLastError: the calling thread's last error.
pub fn set_last_error(code: u32) {
    // SAFETY: no pointers; it writes the thread's own TEB.
    unsafe { raw::SetLastError(code) }
}

// --- user32 --------------------------------------------------------------------------------------

/// GetSystemMetrics: the system metric `index` names (winuser.h's SM_*), 0 for one it does not.
pub fn system_metric(index: i32) -> i32 {
    // SAFETY: no pointers.
    unsafe { raw::GetSystemMetrics(index) }
}

// --- ntdll ---------------------------------------------------------------------------------------

/// DbgPrint of `text`, as is (through `"%s"`).
pub fn debug_print(text: &CStr) {
    // SAFETY: the format and the text are NUL-terminated; the format takes the one string.
    unsafe { raw::DbgPrint(c"%s".as_ptr().cast(), text.as_ptr()) };
}

/// RtlUnicodeToMultiByteN: as many of `source`'s units as `destination` holds, converted: the bytes
/// written.
pub fn unicode_to_multi_byte(destination: &mut [u8], source: &[u16]) -> usize {
    let mut written = 0u32;
    // SAFETY: the call reads the source's units and writes at most the destination's bytes, and
    // the count into the local.
    unsafe {
        raw::RtlUnicodeToMultiByteN(
            destination.as_mut_ptr(),
            destination.len() as u32,
            &mut written,
            source.as_ptr(),
            2 * source.len() as u32,
        )
    };
    written as usize
}

/// RtlMultiByteToUnicodeN: as much of `source` as `destination` holds, from the ANSI code page to
/// UTF-16: the units written.
pub fn multi_byte_to_unicode(destination: &mut [u16], source: &[u8]) -> usize {
    let mut written = 0u32;
    // SAFETY: the call reads the source's bytes and writes at most the destination's units, and
    // the count into the local.
    unsafe {
        raw::RtlMultiByteToUnicodeN(
            destination.as_mut_ptr(),
            2 * destination.len() as u32,
            &mut written,
            source.as_ptr(),
            source.len() as u32,
        )
    };
    written as usize / 2
}

// --- win32k --------------------------------------------------------------------------------------

/// NtGdiOpenDCW: a DC of the display the NUL-terminated UTF-16 name at `device` names (none for
/// the primary display).
pub fn open_dc(device: Caller) -> Result<u32, NtStatus> {
    let mut dc = 0u32;
    // SAFETY: the kernel reads the name to its terminator through its fault-tolerant copies, and
    // writes the handle into the local.
    checked(unsafe { raw::NtGdiOpenDCW(device.0 as *const u16, &mut dc) })?;
    Ok(dc)
}

/// NtGdiDeleteObjectApp: `object` deleted (a DC's handle closed; a stock object stays).
pub fn delete_object(object: usize) -> Result<(), NtStatus> {
    // SAFETY: no pointers.
    checked(unsafe { raw::NtGdiDeleteObjectApp(object) })
}

/// NtGdiGetStockObject: stock object `index`'s handle.
pub fn stock_object(index: u32) -> Result<u32, NtStatus> {
    let mut object = 0u32;
    // SAFETY: the service writes the handle into the local.
    checked(unsafe { raw::NtGdiGetStockObject(index, &mut object) })?;
    Ok(object)
}

/// The kinds of objects a DC selects, each through its own service.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Selected {
    Brush,
    Pen,
    Font,
}

/// NtGdiSelectBrush, NtGdiSelectPen or NtGdiSelectFont, by `kind`: `object` selected into `dc`,
/// the object of its kind it replaces answered.
pub fn select(kind: Selected, dc: usize, object: usize) -> Result<u32, NtStatus> {
    let service: unsafe extern "system" fn(usize, usize, *mut u32) -> u32 = match kind {
        Selected::Brush => raw::NtGdiSelectBrush,
        Selected::Pen => raw::NtGdiSelectPen,
        Selected::Font => raw::NtGdiSelectFont,
    };
    let mut previous = 0u32;
    // SAFETY: the service writes the previous object into the local.
    checked(unsafe { service(dc, object, &mut previous) })?;
    Ok(previous)
}

/// NtGdiGetDCDword: `dc`'s attribute `index` (rtl::gdi's DC_ indexes).
pub fn dc_dword(dc: usize, index: u32) -> Result<u32, NtStatus> {
    let mut value = 0u32;
    // SAFETY: the service writes the value into the local.
    checked(unsafe { raw::NtGdiGetDCDword(dc, index, &mut value) })?;
    Ok(value)
}

/// NtGdiGetAndSetDCDword: `dc`'s attribute `index` set to `value`, the value it had answered.
pub fn set_dc_dword(dc: usize, index: u32, value: u32) -> Result<u32, NtStatus> {
    let mut previous = 0u32;
    // SAFETY: the service writes the previous value into the local.
    checked(unsafe { raw::NtGdiGetAndSetDCDword(dc, index, value, &mut previous) })?;
    Ok(previous)
}

/// NtGdiExtTextOutW: `count` UTF-16 units at `string` drawn into `dc` at (`x`, `y`), with
/// ExtTextOut's `options`, its rectangle at `rect` and its advances at `dx` (none for either: a
/// null address).
#[allow(clippy::too_many_arguments)]
pub fn ext_text_out(
    dc: usize,
    x: i32,
    y: i32,
    options: u32,
    rect: Caller,
    string: Caller,
    count: u32,
    dx: Caller,
) -> Result<(), NtStatus> {
    // SAFETY: the kernel reads the rectangle, the string and the advances through its
    // fault-tolerant copies, before the call returns; it writes no memory.
    checked(unsafe {
        raw::NtGdiExtTextOutW(
            dc,
            x,
            y,
            options,
            rect.0 as *const _,
            string.0 as *const u16,
            count,
            dx.0 as *const i32,
        )
    })
}

/// NtGdiGetTextMetricsW: `dc`'s font's TEXTMETRICW, into the structure at `metric`.
pub fn text_metrics(dc: usize, metric: Caller) -> Result<(), NtStatus> {
    // SAFETY: the kernel writes the structure through its fault-tolerant copies.
    checked(unsafe { raw::NtGdiGetTextMetricsW(dc, metric.0 as *mut TextMetricW) })
}

/// NtGdiGetTextExtent: the SIZE of `count` UTF-16 units at `string` in `dc`'s font, into the
/// structure at `size`.
pub fn text_extent(dc: usize, string: Caller, count: u32, size: Caller) -> Result<(), NtStatus> {
    // SAFETY: the kernel reads the string and writes the SIZE through its fault-tolerant copies.
    checked(unsafe {
        raw::NtGdiGetTextExtent(dc, string.0 as *const u16, count, size.0 as *mut Size)
    })
}

/// NtGdiSetPixel: the pixel at (`x`, `y`) of `dc` set to `color`, the color set answered
/// (CLR_INVALID outside the DC's clipping region).
pub fn set_pixel(dc: usize, x: i32, y: i32, color: u32) -> Result<u32, NtStatus> {
    let mut set = 0u32;
    // SAFETY: the service writes the color into the local.
    checked(unsafe { raw::NtGdiSetPixel(dc, x, y, color, &mut set) })?;
    Ok(set)
}

/// NtGdiGetPixel: the color of the pixel at (`x`, `y`) of `dc` (CLR_INVALID outside the DC's
/// clipping region).
pub fn get_pixel(dc: usize, x: i32, y: i32) -> Result<u32, NtStatus> {
    let mut color = 0u32;
    // SAFETY: the service writes the color into the local.
    checked(unsafe { raw::NtGdiGetPixel(dc, x, y, &mut color) })?;
    Ok(color)
}

/// NtGdiCreateSolidBrush: a brush object of `color`, its handle.
pub fn create_solid_brush(color: u32) -> Result<u32, NtStatus> {
    let mut brush = 0u32;
    // SAFETY: the service writes the handle into the local.
    checked(unsafe { raw::NtGdiCreateSolidBrush(color, &mut brush) })?;
    Ok(brush)
}

/// NtGdiPatBlt: the rectangle at (`x`, `y`), `width` by `height`, of `dc` painted with its brush
/// by the raster operation `rop`.
pub fn pat_blt(
    dc: usize,
    x: i32,
    y: i32,
    width: i32,
    height: i32,
    rop: u32,
) -> Result<(), NtStatus> {
    // SAFETY: no pointers.
    checked(unsafe { raw::NtGdiPatBlt(dc, x, y, width, height, rop) })
}

/// The host tests' imports: stand-ins with the imports' shapes, recording what they were given.
/// The services keep one screen DC's state ([`HOST_DC`], its handle [`DC`]) with the kernel's
/// rules, and record the text they are asked to draw.
#[cfg(test)]
#[allow(non_snake_case)]
pub mod host {
    use std::cell::{Cell, RefCell};

    use rtl::gdi::*;

    /// The one DC the stand-ins know.
    pub const DC: usize = 0x7C;
    /// A handle that names nothing.
    pub const BAD: usize = 0x80;
    /// The stand-ins' screen, the DC's clipping region and the size GetSystemMetrics answers: its
    /// pixels other than (100, 100) are white.
    pub const SCREEN_WIDTH: i32 = 640;
    pub const SCREEN_HEIGHT: i32 = 480;

    /// One NtGdiExtTextOutW call, as the stand-in read it.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct TextCall {
        pub dc: usize,
        pub x: i32,
        pub y: i32,
        pub options: u32,
        pub rect: Option<Rect>,
        pub units: std::vec::Vec<u16>,
        pub dx: Option<std::vec::Vec<i32>>,
    }

    /// The DC's state, as the kernel keeps it: its attributes and selected objects.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct HostDc {
        pub text_color: u32,
        pub bk_color: u32,
        pub bk_mode: u32,
        pub brush: u32,
        pub pen: u32,
        pub font: u32,
        /// The pixel at (100, 100), the one the stand-in's screen has.
        pub pixel: u32,
        pub open: bool,
    }

    impl HostDc {
        pub fn new() -> Self {
            HostDc {
                text_color: DEFAULT_TEXT_COLOR,
                bk_color: DEFAULT_BK_COLOR,
                bk_mode: DEFAULT_BK_MODE,
                brush: stock_handle(WHITE_BRUSH).unwrap(),
                pen: stock_handle(BLACK_PEN).unwrap(),
                font: stock_handle(SYSTEM_FONT).unwrap(),
                pixel: 0x00A5_6E3A,
                open: true,
            }
        }
    }

    std::thread_local! {
        /// The calling thread's last error, as SetLastError left it.
        pub static LAST_ERROR: Cell<u32> = const { Cell::new(0) };
        /// The text each DbgPrint printed, in order.
        pub static DEBUG_PRINTS: RefCell<std::vec::Vec<std::string::String>> = const { RefCell::new(std::vec::Vec::new()) };
        /// The DC's state.
        pub static HOST_DC: RefCell<HostDc> = RefCell::new(HostDc::new());
        /// The display names NtGdiOpenDCW was given (none for a null name), in order.
        pub static OPENED: RefCell<std::vec::Vec<Option<std::vec::Vec<u16>>>> = const { RefCell::new(std::vec::Vec::new()) };
        /// The text NtGdiExtTextOutW and NtGdiGetTextExtent were asked about, in order.
        pub static TEXT: RefCell<std::vec::Vec<TextCall>> = const { RefCell::new(std::vec::Vec::new()) };
        /// How many win32k services were called.
        pub static SERVICES: Cell<u32> = const { Cell::new(0) };
        /// The brush objects NtGdiCreateSolidBrush made and NtGdiDeleteObjectApp has not deleted:
        /// their handles and colors.
        pub static BRUSHES: RefCell<std::vec::Vec<(u32, u32)>> = const { RefCell::new(std::vec::Vec::new()) };
        /// The fills NtGdiPatBlt was asked for, in order.
        pub static FILLS: RefCell<std::vec::Vec<Fill>> = const { RefCell::new(std::vec::Vec::new()) };
    }

    /// One NtGdiPatBlt call, as the stand-in read it, with the brush the DC had selected.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Fill {
        pub x: i32,
        pub y: i32,
        pub width: i32,
        pub height: i32,
        pub rop: u32,
        pub brush: u32,
    }

    /// The first brush object's handle (the brush kind's bits over a handle-table handle): each
    /// next one 4 past the one before.
    pub const FIRST_BRUSH: u32 = 0x0002_0400;

    const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
    const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
    const STATUS_OBJECT_TYPE_MISMATCH: u32 = 0xC000_0024;

    /// Whether `handle` names a live brush object.
    fn is_brush_object(handle: u32) -> bool {
        BRUSHES.with(|brushes| brushes.borrow().iter().any(|&(brush, _)| brush == handle))
    }

    fn served() {
        SERVICES.with(|count| count.set(count.get() + 1));
    }

    /// Run `f` on the DC `dc` names; STATUS_INVALID_HANDLE for another handle or a deleted DC.
    fn with_dc(dc: usize, f: impl FnOnce(&mut HostDc) -> u32) -> u32 {
        served();
        HOST_DC.with(|state| {
            let mut state = state.borrow_mut();
            if dc != DC || !state.open {
                return STATUS_INVALID_HANDLE;
            }
            f(&mut state)
        })
    }

    /// Write `value` through the caller's out-pointer, then succeed.
    fn answer(out: *mut u32, value: u32) -> u32 {
        // SAFETY: the tests' own out-pointer.
        unsafe { out.write(value) };
        0
    }

    pub unsafe extern "system" fn SetLastError(code: u32) {
        LAST_ERROR.with(|error| error.set(code));
    }

    /// GetSystemMetrics: the screen's width (SM_CXSCREEN) and height (SM_CYSCREEN), 0 for another
    /// index.
    pub unsafe extern "system" fn GetSystemMetrics(index: i32) -> i32 {
        match index {
            crate::dc::SM_CXSCREEN => SCREEN_WIDTH,
            crate::dc::SM_CYSCREEN => SCREEN_HEIGHT,
            _ => 0,
        }
    }

    /// DbgPrint, as the stub routine calls it: `"%s"` and the text (the stand-in serves that
    /// format alone), kept.
    pub unsafe extern "C" fn DbgPrint(format: *const u8, text: *const core::ffi::c_char) -> u32 {
        // SAFETY: the caller's NUL-terminated format and text.
        let (format, text) = unsafe {
            (
                core::ffi::CStr::from_ptr(format.cast()).to_bytes(),
                core::ffi::CStr::from_ptr(text.cast()),
            )
        };
        assert_eq!(format, b"%s", "the stand-in serves \"%s\" alone");
        DEBUG_PRINTS.with(|prints| {
            prints
                .borrow_mut()
                .push(text.to_string_lossy().into_owned())
        });
        0
    }

    /// The heap: the host's allocator, a block zeroed, its size kept before it.
    pub unsafe extern "system" fn RtlAllocateHeap(
        _heap: usize,
        _flags: u32,
        size: usize,
    ) -> *mut u8 {
        let layout = std::alloc::Layout::from_size_align(size + 8, 8).unwrap();
        // SAFETY: a non-zero layout; the size goes in the first word.
        unsafe {
            let block = std::alloc::alloc_zeroed(layout);
            (block as *mut usize).write(size);
            block.add(8)
        }
    }

    pub unsafe extern "system" fn RtlFreeHeap(_heap: usize, _flags: u32, block: *mut u8) -> u32 {
        // SAFETY: a block RtlAllocateHeap made.
        unsafe {
            let start = block.sub(8);
            let size = (start as *const usize).read();
            std::alloc::dealloc(
                start,
                std::alloc::Layout::from_size_align(size + 8, 8).unwrap(),
            );
        }
        1
    }

    pub unsafe extern "system" fn RtlMultiByteToUnicodeN(
        unicode: *mut u16,
        max_bytes: u32,
        bytes_written: *mut u32,
        multi_byte: *const u8,
        multi_byte_bytes: u32,
    ) -> u32 {
        // SAFETY: the caller's buffers, of the sizes given.
        let written = unsafe {
            rtl::string::multi_byte_to_unicode(
                core::slice::from_raw_parts_mut(unicode, max_bytes as usize / 2),
                core::slice::from_raw_parts(multi_byte, multi_byte_bytes as usize),
            )
        };
        if !bytes_written.is_null() {
            // SAFETY: the caller's count.
            unsafe { bytes_written.write(2 * written as u32) };
        }
        0
    }

    pub unsafe extern "system" fn RtlUnicodeToMultiByteN(
        multi_byte: *mut u8,
        max_bytes: u32,
        bytes_written: *mut u32,
        unicode: *const u16,
        unicode_bytes: u32,
    ) -> u32 {
        // SAFETY: the caller's buffers, of the sizes given.
        let written = unsafe {
            rtl::string::unicode_to_multi_byte(
                core::slice::from_raw_parts_mut(multi_byte, max_bytes as usize),
                core::slice::from_raw_parts(unicode, unicode_bytes as usize / 2),
            )
        };
        if !bytes_written.is_null() {
            // SAFETY: the caller's count.
            unsafe { bytes_written.write(written as u32) };
        }
        0
    }

    /// The primary display, by a null name or `\\.\DISPLAY1`: the DC reopened at its defaults.
    pub unsafe extern "system" fn NtGdiOpenDCW(device: *const u16, dc: *mut u32) -> u32 {
        served();
        // SAFETY: the tests' own NUL-terminated name.
        let name =
            (!device.is_null()).then(|| unsafe { rtl::cstr::units_until_nul(device) }.to_vec());
        OPENED.with(|opened| opened.borrow_mut().push(name.clone()));
        if name.is_some_and(|name| String::from_utf16_lossy(&name) != "\\\\.\\DISPLAY1") {
            return STATUS_INVALID_PARAMETER;
        }
        HOST_DC.with(|state| *state.borrow_mut() = HostDc::new());
        answer(dc, DC as u32)
    }

    pub unsafe extern "system" fn NtGdiDeleteObjectApp(object: usize) -> u32 {
        if global_object_kind(object as u32).is_some() {
            served();
            return 0;
        }
        if is_brush_object(object as u32) {
            served();
            BRUSHES.with(|brushes| {
                brushes
                    .borrow_mut()
                    .retain(|&(brush, _)| brush as usize != object)
            });
            return 0;
        }
        with_dc(object, |state| {
            state.open = false;
            0
        })
    }

    pub unsafe extern "system" fn NtGdiGetStockObject(index: u32, object: *mut u32) -> u32 {
        served();
        match stock_handle(index) {
            Some(handle) => answer(object, handle),
            None => STATUS_INVALID_PARAMETER,
        }
    }

    /// The kernel's rule: a global object of the kind, or a brush object for a brush, is selected;
    /// another object is STATUS_OBJECT_TYPE_MISMATCH, a handle that names none
    /// STATUS_INVALID_HANDLE.
    fn select(dc: usize, kind: u32, object: usize, previous: *mut u32) -> u32 {
        with_dc(dc, |state| {
            let slot = match kind {
                OBJ_BRUSH => &mut state.brush,
                OBJ_PEN => &mut state.pen,
                _ => &mut state.font,
            };
            let object = object as u32;
            let live = global_object_kind(object).is_some() || is_brush_object(object);
            match object_kind(object) {
                Some(found) if found == kind && live => {
                    answer(previous, core::mem::replace(slot, object))
                }
                Some(_) if live => STATUS_OBJECT_TYPE_MISMATCH,
                _ => STATUS_INVALID_HANDLE,
            }
        })
    }

    pub unsafe extern "system" fn NtGdiCreateSolidBrush(color: u32, brush: *mut u32) -> u32 {
        served();
        let handle = BRUSHES.with(|brushes| {
            let mut brushes = brushes.borrow_mut();
            let handle = brushes.last().map_or(FIRST_BRUSH, |&(last, _)| last + 4);
            brushes.push((handle, color & RGB_MASK));
            handle
        });
        answer(brush, handle)
    }

    pub unsafe extern "system" fn NtGdiPatBlt(
        dc: usize,
        x: i32,
        y: i32,
        width: i32,
        height: i32,
        rop: u32,
    ) -> u32 {
        with_dc(dc, |state| {
            if !rop_is_sourceless(rop) {
                return STATUS_INVALID_PARAMETER;
            }
            let fill = Fill {
                x,
                y,
                width,
                height,
                rop,
                brush: state.brush,
            };
            FILLS.with(|fills| fills.borrow_mut().push(fill));
            0
        })
    }

    pub unsafe extern "system" fn NtGdiSelectBrush(dc: usize, object: usize, out: *mut u32) -> u32 {
        select(dc, OBJ_BRUSH, object, out)
    }

    pub unsafe extern "system" fn NtGdiSelectPen(dc: usize, object: usize, out: *mut u32) -> u32 {
        select(dc, OBJ_PEN, object, out)
    }

    pub unsafe extern "system" fn NtGdiSelectFont(dc: usize, object: usize, out: *mut u32) -> u32 {
        select(dc, OBJ_FONT, object, out)
    }

    pub unsafe extern "system" fn NtGdiGetDCDword(dc: usize, index: u32, value: *mut u32) -> u32 {
        with_dc(dc, |state| match index {
            DC_TEXT_COLOR => answer(value, state.text_color),
            DC_BK_COLOR => answer(value, state.bk_color),
            DC_BK_MODE => answer(value, state.bk_mode),
            _ => STATUS_INVALID_PARAMETER,
        })
    }

    pub unsafe extern "system" fn NtGdiGetAndSetDCDword(
        dc: usize,
        index: u32,
        value: u32,
        previous: *mut u32,
    ) -> u32 {
        with_dc(dc, |state| {
            let field = match index {
                DC_TEXT_COLOR => &mut state.text_color,
                DC_BK_COLOR => &mut state.bk_color,
                DC_BK_MODE if matches!(value, TRANSPARENT | OPAQUE) => &mut state.bk_mode,
                _ => return STATUS_INVALID_PARAMETER,
            };
            answer(previous, core::mem::replace(field, value))
        })
    }

    pub unsafe extern "system" fn NtGdiExtTextOutW(
        dc: usize,
        x: i32,
        y: i32,
        options: u32,
        rect: *const Rect,
        string: *const u16,
        count: u32,
        dx: *const i32,
    ) -> u32 {
        with_dc(dc, |_| {
            // SAFETY: the tests' own rectangle, string and advances, of the lengths given.
            let call = unsafe {
                TextCall {
                    dc,
                    x,
                    y,
                    options,
                    rect: (!rect.is_null()).then(|| rect.read()),
                    units: std::slice::from_raw_parts(string, count as usize).to_vec(),
                    dx: (!dx.is_null())
                        .then(|| std::slice::from_raw_parts(dx, count as usize).to_vec()),
                }
            };
            TEXT.with(|text| text.borrow_mut().push(call));
            0
        })
    }

    pub unsafe extern "system" fn NtGdiGetTextMetricsW(dc: usize, metric: *mut TextMetricW) -> u32 {
        with_dc(dc, |_| {
            // SAFETY: the tests' own structure.
            unsafe {
                metric.write(TextMetricW {
                    height: 16,
                    ave_char_width: 8,
                    first_char: 0x20,
                    last_char: 0x20AC,
                    ..TextMetricW::default()
                })
            };
            0
        })
    }

    pub unsafe extern "system" fn NtGdiGetTextExtent(
        dc: usize,
        string: *const u16,
        count: u32,
        size: *mut Size,
    ) -> u32 {
        with_dc(dc, |_| {
            // SAFETY: the tests' own string and SIZE.
            unsafe {
                let units = std::slice::from_raw_parts(string, count as usize).to_vec();
                TEXT.with(|text| {
                    text.borrow_mut().push(TextCall {
                        dc,
                        x: 0,
                        y: 0,
                        options: 0,
                        rect: None,
                        units,
                        dx: None,
                    })
                });
                size.write(Size {
                    cx: 8 * count as i32,
                    cy: 16,
                });
            }
            0
        })
    }

    pub unsafe extern "system" fn NtGdiSetPixel(
        dc: usize,
        x: i32,
        y: i32,
        color: u32,
        set: *mut u32,
    ) -> u32 {
        with_dc(dc, |state| {
            if (x, y) != (100, 100) {
                return answer(set, CLR_INVALID);
            }
            state.pixel = color & RGB_MASK;
            answer(set, state.pixel)
        })
    }

    pub unsafe extern "system" fn NtGdiGetPixel(dc: usize, x: i32, y: i32, color: *mut u32) -> u32 {
        with_dc(dc, |state| {
            answer(
                color,
                match (x, y) {
                    (100, 100) => state.pixel,
                    (0..SCREEN_WIDTH, 0..SCREEN_HEIGHT) => DEFAULT_BK_COLOR,
                    _ => CLR_INVALID,
                },
            )
        })
    }

    pub fn process_heap() -> usize {
        0x0014_0000
    }

    /// The host process's memory: every address the tests hand over is their own.
    pub struct Probed;

    impl rtl::stub::Memory for Probed {
        fn readable(&self, _address: usize) -> bool {
            true
        }
    }
}
