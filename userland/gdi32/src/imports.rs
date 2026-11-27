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

use rtl::gdi::{Abc, FontEnumRecord, LogFontW, Point, Size, TextMetricW};
use rtl::heap::HEAP_ZERO_MEMORY;
use rtl::status::{checked, NtStatus};

#[cfg(all(target_arch = "x86", not(test)))]
mod raw {
    use rtl::dib::BitmapDesc;
    use rtl::gdi::{Abc, FontEnumRecord, LogFontW, Point, Rect, Size, TextMetricW};

    #[link(
        name = "kernel32",
        kind = "raw-dylib",
        import_name_type = "undecorated"
    )]
    unsafe extern "system" {
        /// SetLastError: the calling thread's last error.
        pub fn SetLastError(code: u32);
        /// SearchPathW: a file's full path, looked for in a directory or along the search path.
        pub fn SearchPathW(
            path: *const u16,
            file: *const u16,
            extension: *const u16,
            length: u32,
            buffer: *mut u16,
            file_part: *mut *mut u16,
        ) -> u32;
        /// GetSystemWindowsDirectoryW: the system root, where the Fonts directory is.
        pub fn GetSystemWindowsDirectoryW(buffer: *mut u16, size: u32) -> u32;
    }

    #[link(name = "ntdll", kind = "raw-dylib", import_name_type = "undecorated")]
    unsafe extern "system" {
        /// RtlDosPathNameToNtPathName_U: a DOS path's NT form, its buffer from the process heap.
        pub fn RtlDosPathNameToNtPathName_U(
            dos: *const u16,
            nt: *mut super::UnicodeString,
            file_part: *mut *mut u16,
            relative: *mut u8,
        ) -> u8;
        /// NtOpenFile and NtClose: a font file opened for reading, and its handle closed.
        pub fn NtOpenFile(
            handle: *mut u32,
            access: u32,
            attributes: *const super::ObjectAttributes,
            io_status: *mut rtl::nt::IoStatusBlock<u32>,
            share: u32,
            options: u32,
        ) -> u32;
        pub fn NtClose(handle: u32) -> u32;
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
        #[link_name = "\u{1}_f2k_nt_NtGdiGetDCObject"]
        pub fn NtGdiGetDCObject(dc: usize, kind: u32, object: *mut u32) -> u32;
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
        #[link_name = "\u{1}_f2k_nt_NtGdiCreateRectRgn"]
        pub fn NtGdiCreateRectRgn(
            left: i32,
            top: i32,
            right: i32,
            bottom: i32,
            region: *mut u32,
        ) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtGdiPolyPolyDraw"]
        pub fn NtGdiPolyPolyDraw(
            dc: u32,
            points: *const u8,
            counts: *const u32,
            count: u32,
            function: u32,
            result: *mut u32,
        ) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtGdiSetRectRgn"]
        pub fn NtGdiSetRectRgn(region: usize, left: i32, top: i32, right: i32, bottom: i32) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtGdiCombineRgn"]
        pub fn NtGdiCombineRgn(
            dest: usize,
            first: usize,
            second: usize,
            mode: u32,
            complexity: *mut u32,
        ) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtGdiOffsetRgn"]
        pub fn NtGdiOffsetRgn(region: usize, x: i32, y: i32, complexity: *mut u32) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtGdiGetRgnBox"]
        pub fn NtGdiGetRgnBox(region: usize, rect: *mut Rect, complexity: *mut u32) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtGdiEqualRgn"]
        pub fn NtGdiEqualRgn(first: usize, second: usize, equal: *mut u32) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtGdiPtInRegion"]
        pub fn NtGdiPtInRegion(region: usize, x: i32, y: i32, inside: *mut u32) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtGdiGetRegionData"]
        pub fn NtGdiGetRegionData(
            region: usize,
            count: u32,
            buffer: *mut u8,
            size: *mut u32,
        ) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtGdiFillRgn"]
        pub fn NtGdiFillRgn(dc: usize, region: usize, brush: usize, result: *mut u32) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtGdiFlush"]
        pub fn NtGdiFlush() -> u32;
        #[link_name = "\u{1}_f2k_nt_NtGdiExtSelectClipRgn"]
        pub fn NtGdiExtSelectClipRgn(
            dc: usize,
            region: usize,
            mode: u32,
            complexity: *mut u32,
        ) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtGdiIntersectClipRect"]
        pub fn NtGdiIntersectClipRect(
            dc: usize,
            left: i32,
            top: i32,
            right: i32,
            bottom: i32,
            complexity: *mut u32,
        ) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtGdiExcludeClipRect"]
        pub fn NtGdiExcludeClipRect(
            dc: usize,
            left: i32,
            top: i32,
            right: i32,
            bottom: i32,
            complexity: *mut u32,
        ) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtGdiOffsetClipRgn"]
        pub fn NtGdiOffsetClipRgn(dc: usize, x: i32, y: i32, complexity: *mut u32) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtGdiGetAppClipBox"]
        pub fn NtGdiGetAppClipBox(dc: usize, rect: *mut Rect, complexity: *mut u32) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtGdiGetRandomRgn"]
        pub fn NtGdiGetRandomRgn(dc: usize, region: usize, which: u32, result: *mut u32) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtGdiPtVisible"]
        pub fn NtGdiPtVisible(dc: usize, x: i32, y: i32, visible: *mut u32) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtGdiRectVisible"]
        pub fn NtGdiRectVisible(dc: usize, rect: *const Rect, visible: *mut u32) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtGdiPatBlt"]
        pub fn NtGdiPatBlt(dc: usize, x: i32, y: i32, width: i32, height: i32, rop: u32) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtGdiCreatePen"]
        pub fn NtGdiCreatePen(style: i32, width: i32, color: u32, pen: *mut u32) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtGdiExtCreatePen"]
        pub fn NtGdiExtCreatePen(
            style: u32,
            width: u32,
            brush_style: u32,
            color: u32,
            hatch: u32,
            count: u32,
            entries: *const u32,
            pen: *mut u32,
        ) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtGdiMoveTo"]
        pub fn NtGdiMoveTo(dc: usize, x: i32, y: i32, previous: *mut Point) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtGdiGetDCPoint"]
        pub fn NtGdiGetDCPoint(dc: usize, which: u32, point: *mut Point) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtGdiLineTo"]
        pub fn NtGdiLineTo(dc: usize, x: i32, y: i32) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtGdiRectangle"]
        pub fn NtGdiRectangle(dc: usize, left: i32, top: i32, right: i32, bottom: i32) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtGdiEllipse"]
        pub fn NtGdiEllipse(dc: usize, left: i32, top: i32, right: i32, bottom: i32) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtGdiRoundRect"]
        pub fn NtGdiRoundRect(
            dc: usize,
            left: i32,
            top: i32,
            right: i32,
            bottom: i32,
            width: i32,
            height: i32,
        ) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtGdiCreateCompatibleDC"]
        pub fn NtGdiCreateCompatibleDC(dc: usize, memory_dc: *mut u32) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtGdiCreateBitmap"]
        pub fn NtGdiCreateBitmap(desc: *const BitmapDesc, bitmap: *mut u32) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtGdiSelectBitmap"]
        pub fn NtGdiSelectBitmap(dc: usize, bitmap: usize, previous: *mut u32) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtGdiBitBlt"]
        pub fn NtGdiBitBlt(
            dc: usize,
            x: i32,
            y: i32,
            width: i32,
            height: i32,
            source: usize,
            source_x: i32,
            source_y: i32,
            rop: u32,
        ) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtGdiStretchBlt"]
        pub fn NtGdiStretchBlt(
            dc: usize,
            x: i32,
            y: i32,
            width: i32,
            height: i32,
            source: usize,
            source_x: i32,
            source_y: i32,
            source_width: i32,
            source_height: i32,
            rop: u32,
        ) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtGdiCreatePatternBrushInternal"]
        pub fn NtGdiCreatePatternBrushInternal(bitmap: usize, brush: *mut u32) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtGdiAddFontResourceW"]
        pub fn NtGdiAddFontResourceW(file: usize, flags: u32, faces: *mut u32) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtGdiRemoveFontResourceW"]
        pub fn NtGdiRemoveFontResourceW(file: usize, flags: u32, removed: *mut u32) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtGdiHfontCreate"]
        pub fn NtGdiHfontCreate(log_font: *const LogFontW, font: *mut u32) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtGdiExtGetObjectW"]
        pub fn NtGdiExtGetObjectW(
            object: usize,
            count: u32,
            buffer: *mut u8,
            size: *mut u32,
        ) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtGdiGetTextFaceW"]
        pub fn NtGdiGetTextFaceW(dc: usize, count: u32, buffer: *mut u16, length: *mut u32) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtGdiGetOutlineTextMetricsInternalW"]
        pub fn NtGdiGetOutlineTextMetricsInternalW(
            dc: usize,
            size: u32,
            buffer: *mut u8,
            needed: *mut u32,
        ) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtGdiGetCharWidthW"]
        pub fn NtGdiGetCharWidthW(
            dc: usize,
            first: u32,
            count: u32,
            characters: *const u16,
            widths: *mut i32,
        ) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtGdiGetCharABCWidthsW"]
        pub fn NtGdiGetCharABCWidthsW(
            dc: usize,
            first: u32,
            count: u32,
            characters: *const u16,
            abc: *mut Abc,
        ) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtGdiGetFontData"]
        pub fn NtGdiGetFontData(
            dc: usize,
            table: u32,
            offset: u32,
            buffer: *mut u8,
            count: u32,
            answer: *mut u32,
        ) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtGdiGetGlyphOutline"]
        pub fn NtGdiGetGlyphOutline(
            dc: usize,
            character: u32,
            format: u32,
            metrics: *mut u8,
            size: u32,
            buffer: *mut u8,
            answer: *mut u32,
        ) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtGdiEnumFontChunk"]
        pub fn NtGdiEnumFontChunk(
            dc: usize,
            face: *const u16,
            char_set: u32,
            flags: u32,
            index: u32,
            record: *mut FontEnumRecord,
        ) -> u32;
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

/// The process heap, through this DLL's imports (RtlAllocateHeap and RtlFreeHeap on the PEB's
/// ProcessHeap).
pub struct ProcessHeap;

impl rtl::heap::ProcessHeap for ProcessHeap {
    fn allocate(size: usize) -> *mut u8 {
        // SAFETY: a plain allocation.
        unsafe { raw::RtlAllocateHeap(raw::process_heap(), HEAP_ZERO_MEMORY, size) }
    }

    unsafe fn free(block: *mut u8) {
        // SAFETY: the caller's contract: a block of the process heap this DLL took, freed once.
        unsafe { raw::RtlFreeHeap(raw::process_heap(), 0, block) };
    }
}

/// A zeroed block of the process heap, freed when dropped.
pub type HeapBlock = rtl::heap::Block<ProcessHeap>;

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
    unsafe { raw::DbgPrint(c"%s".as_ptr().cast(), text.as_ptr().cast::<u8>()) };
}

/// RtlUnicodeToMultiByteN: as many of `source`'s units as `destination` holds, converted: the bytes
/// written.
pub fn unicode_to_multi_byte(destination: &mut [u8], source: &[u16]) -> usize {
    // SAFETY: the import is the conversion itself (ntdll's, or its stand-in).
    unsafe {
        rtl::string::unicode_to_multi_byte_with(raw::RtlUnicodeToMultiByteN, destination, source)
    }
}

/// RtlMultiByteToUnicodeN: as much of `source` as `destination` holds, from the ANSI code page to
/// UTF-16: the units written.
pub fn multi_byte_to_unicode(destination: &mut [u16], source: &[u8]) -> usize {
    // SAFETY: the import is the conversion itself (ntdll's, or its stand-in).
    unsafe {
        rtl::string::multi_byte_to_unicode_with(raw::RtlMultiByteToUnicodeN, destination, source)
    }
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

/// NtGdiGetDCObject: the object of `kind` (OBJ_BRUSH, OBJ_PEN, OBJ_FONT) selected into `dc`.
pub fn dc_object(dc: usize, kind: u32) -> Result<u32, NtStatus> {
    let mut object = 0u32;
    // SAFETY: the service writes the handle into the local.
    checked(unsafe { raw::NtGdiGetDCObject(dc, kind, &mut object) })?;
    Ok(object)
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

// --- win32k's pens, lines and shapes -------------------------------------------------------------

/// NtGdiCreatePen: a pen of `style`, `width` and `color`, its handle.
pub fn create_pen(style: i32, width: i32, color: u32) -> Result<u32, NtStatus> {
    let mut pen = 0u32;
    // SAFETY: the service writes the handle into the local.
    checked(unsafe { raw::NtGdiCreatePen(style, width, color, &mut pen) })?;
    Ok(pen)
}

/// NtGdiExtCreatePen: an extended pen of `style` and `width`, its brush's fields, and `count` user
/// style entries at `entries`; its handle.
pub fn ext_create_pen(
    style: u32,
    width: u32,
    brush: rtl::dib::LogBrush,
    count: u32,
    entries: Caller,
) -> Result<u32, NtStatus> {
    let mut pen = 0u32;
    // SAFETY: the kernel reads the entries through its fault-tolerant copies, and writes the
    // handle into the local.
    checked(unsafe {
        raw::NtGdiExtCreatePen(
            style,
            width,
            brush.style,
            brush.color,
            brush.hatch,
            count,
            entries.0 as *const u32,
            &mut pen,
        )
    })?;
    Ok(pen)
}

/// NtGdiMoveTo: `dc`'s current position moved to (`x`, `y`), the one it had into the POINT at
/// `previous` (none: a null address).
pub fn move_to(dc: usize, x: i32, y: i32, previous: Caller) -> Result<(), NtStatus> {
    // SAFETY: the kernel writes the POINT through its fault-tolerant copies.
    checked(unsafe { raw::NtGdiMoveTo(dc, x, y, previous.0 as *mut Point) })
}

/// NtGdiGetDCPoint: `dc`'s point `which` (rtl::gdi's DCPT_ indexes) into the POINT at `point`.
pub fn dc_point(dc: usize, which: u32, point: Caller) -> Result<(), NtStatus> {
    // SAFETY: the kernel writes the POINT through its fault-tolerant copies.
    checked(unsafe { raw::NtGdiGetDCPoint(dc, which, point.0 as *mut Point) })
}

/// NtGdiLineTo: a line from `dc`'s current position to (`x`, `y`), its new current position.
pub fn line_to(dc: usize, x: i32, y: i32) -> Result<(), NtStatus> {
    // SAFETY: no pointers.
    checked(unsafe { raw::NtGdiLineTo(dc, x, y) })
}

/// NtGdiRectangle, NtGdiEllipse and NtGdiRoundRect (`corner` its corners' ellipse's size): the
/// shape drawn in the box.
pub fn shape(
    kind: ShapeKind,
    dc: usize,
    left: i32,
    top: i32,
    right: i32,
    bottom: i32,
) -> Result<(), NtStatus> {
    // SAFETY: no pointers.
    checked(unsafe {
        match kind {
            ShapeKind::Rectangle => raw::NtGdiRectangle(dc, left, top, right, bottom),
            ShapeKind::Ellipse => raw::NtGdiEllipse(dc, left, top, right, bottom),
            ShapeKind::RoundRect(width, height) => {
                raw::NtGdiRoundRect(dc, left, top, right, bottom, width, height)
            }
        }
    })
}

/// The shapes a box makes, as [`shape`] draws them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShapeKind {
    Rectangle,
    Ellipse,
    RoundRect(i32, i32),
}

/// NtGdiPolyPolyDraw's I_POLYPOLYGON or I_POLYPOLYLINE (`function`): the figures whose point
/// counts are `counts` drawn into `dc`, their points at `points`.
pub fn poly_poly_draw(
    dc: usize,
    points: Caller,
    counts: &[u32],
    function: u32,
) -> Result<(), NtStatus> {
    let mut result = 0u32;
    // SAFETY: the kernel reads the points through its fault-tolerant copies, the counts from the
    // slice, and writes the result into the local.
    checked(unsafe {
        raw::NtGdiPolyPolyDraw(
            dc as u32,
            points.0 as *const u8,
            counts.as_ptr(),
            counts.len() as u32,
            function,
            &mut result,
        )
    })
}

// --- win32k's regions ----------------------------------------------------------------------------

/// NtGdiCreateRectRgn: a region of the rectangle, its handle.
pub fn create_rect_rgn(left: i32, top: i32, right: i32, bottom: i32) -> Result<u32, NtStatus> {
    let mut region = 0u32;
    // SAFETY: the service writes the handle into the local.
    checked(unsafe { raw::NtGdiCreateRectRgn(left, top, right, bottom, &mut region) })?;
    Ok(region)
}

/// NtGdiPolyPolyDraw's I_POLYPOLYRGN: a region of the polygons whose point counts are at
/// `counts` (`count` of them), their points at `points`, under the fill `mode`; its handle.
pub fn create_poly_polygon_rgn(points: Caller, counts: &[u32], mode: u32) -> Result<u32, NtStatus> {
    /// NtGdiPolyPolyDraw's function that makes a region.
    const I_POLYPOLYRGN: u32 = 6;
    let mut region = 0u32;
    // SAFETY: the kernel reads the points through its fault-tolerant copies, the counts from the
    // slice, and writes the handle into the local.
    checked(unsafe {
        raw::NtGdiPolyPolyDraw(
            mode,
            points.0 as *const u8,
            counts.as_ptr(),
            counts.len() as u32,
            I_POLYPOLYRGN,
            &mut region,
        )
    })?;
    Ok(region)
}

/// NtGdiSetRectRgn: `region` made the rectangle.
pub fn set_rect_rgn(
    region: usize,
    left: i32,
    top: i32,
    right: i32,
    bottom: i32,
) -> Result<(), NtStatus> {
    // SAFETY: no memory changes hands.
    checked(unsafe { raw::NtGdiSetRectRgn(region, left, top, right, bottom) })
}

/// NtGdiCombineRgn: `dest` made `mode`'s combination of `first` and `second`; its complexity.
pub fn combine_rgn(dest: usize, first: usize, second: usize, mode: u32) -> Result<i32, NtStatus> {
    let mut complexity = 0u32;
    // SAFETY: the service writes the complexity into the local.
    checked(unsafe { raw::NtGdiCombineRgn(dest, first, second, mode, &mut complexity) })?;
    Ok(complexity as i32)
}

/// NtGdiOffsetRgn: `region` moved; its complexity.
pub fn offset_rgn(region: usize, x: i32, y: i32) -> Result<i32, NtStatus> {
    let mut complexity = 0u32;
    // SAFETY: the service writes the complexity into the local.
    checked(unsafe { raw::NtGdiOffsetRgn(region, x, y, &mut complexity) })?;
    Ok(complexity as i32)
}

/// NtGdiGetRgnBox: `region`'s complexity and box.
pub fn rgn_box(region: usize) -> Result<(i32, rtl::gdi::Rect), NtStatus> {
    let (mut complexity, mut rect) = (0u32, rtl::gdi::Rect::EMPTY);
    // SAFETY: the service writes the locals.
    checked(unsafe { raw::NtGdiGetRgnBox(region, &mut rect, &mut complexity) })?;
    Ok((complexity as i32, rect))
}

/// NtGdiEqualRgn: whether the two regions hold the same rectangles.
pub fn equal_rgn(first: usize, second: usize) -> Result<bool, NtStatus> {
    let mut equal = 0u32;
    // SAFETY: the service writes the local.
    checked(unsafe { raw::NtGdiEqualRgn(first, second, &mut equal) })?;
    Ok(equal != 0)
}

/// NtGdiPtInRegion: whether the point lies in `region`.
pub fn pt_in_region(region: usize, x: i32, y: i32) -> Result<bool, NtStatus> {
    let mut inside = 0u32;
    // SAFETY: the service writes the local.
    checked(unsafe { raw::NtGdiPtInRegion(region, x, y, &mut inside) })?;
    Ok(inside != 0)
}

/// NtGdiGetRegionData: `region`'s RGNDATA into the `count` bytes at `buffer` (none: its size
/// alone); its size.
pub fn region_data(region: usize, count: u32, buffer: Caller) -> Result<u32, NtStatus> {
    let mut size = 0u32;
    // SAFETY: the kernel writes at most `count` bytes at `buffer` through its fault-tolerant
    // copies, and the size into the local.
    checked(unsafe { raw::NtGdiGetRegionData(region, count, buffer.0 as *mut u8, &mut size) })?;
    Ok(size)
}

/// NtGdiFillRgn: `region` painted with `brush` on `dc`; whether it painted (the null brush does
/// not).
pub fn fill_rgn(dc: usize, region: usize, brush: usize) -> Result<bool, NtStatus> {
    let mut painted = 0u32;
    // SAFETY: the service writes the local.
    checked(unsafe { raw::NtGdiFillRgn(dc, region, brush, &mut painted) })?;
    Ok(painted != 0)
}

/// NtGdiFlush: nothing but the win32k service the dispatcher runs the GDI batch before.
pub fn flush() {
    // SAFETY: no memory changes hands.
    unsafe { raw::NtGdiFlush() };
}

/// NtGdiExtSelectClipRgn: `dc`'s clipping region made `mode`'s combination of it and `region`
/// (zero: none); the final region's complexity.
pub fn ext_select_clip_rgn(dc: usize, region: usize, mode: u32) -> Result<i32, NtStatus> {
    let mut complexity = 0u32;
    // SAFETY: the service writes the local.
    checked(unsafe { raw::NtGdiExtSelectClipRgn(dc, region, mode, &mut complexity) })?;
    Ok(complexity as i32)
}

/// NtGdiIntersectClipRect: `dc`'s clipping region cut to the logical rectangle; its complexity.
pub fn intersect_clip_rect(dc: usize, rect: rtl::gdi::Rect) -> Result<i32, NtStatus> {
    let mut complexity = 0u32;
    // SAFETY: the service writes the local.
    checked(unsafe {
        raw::NtGdiIntersectClipRect(
            dc,
            rect.left,
            rect.top,
            rect.right,
            rect.bottom,
            &mut complexity,
        )
    })?;
    Ok(complexity as i32)
}

/// NtGdiExcludeClipRect: the logical rectangle taken out of `dc`'s clipping region; the final
/// region's complexity.
pub fn exclude_clip_rect(dc: usize, rect: rtl::gdi::Rect) -> Result<i32, NtStatus> {
    let mut complexity = 0u32;
    // SAFETY: the service writes the local.
    checked(unsafe {
        raw::NtGdiExcludeClipRect(
            dc,
            rect.left,
            rect.top,
            rect.right,
            rect.bottom,
            &mut complexity,
        )
    })?;
    Ok(complexity as i32)
}

/// NtGdiOffsetClipRgn: `dc`'s clipping region moved; the final region's complexity.
pub fn offset_clip_rgn(dc: usize, x: i32, y: i32) -> Result<i32, NtStatus> {
    let mut complexity = 0u32;
    // SAFETY: the service writes the local.
    checked(unsafe { raw::NtGdiOffsetClipRgn(dc, x, y, &mut complexity) })?;
    Ok(complexity as i32)
}

/// NtGdiGetAppClipBox: `dc`'s final region's complexity and box (logical coordinates).
pub fn clip_box(dc: usize) -> Result<(i32, rtl::gdi::Rect), NtStatus> {
    let (mut complexity, mut rect) = (0u32, rtl::gdi::Rect::EMPTY);
    // SAFETY: the service writes the locals.
    checked(unsafe { raw::NtGdiGetAppClipBox(dc, &mut rect, &mut complexity) })?;
    Ok((complexity as i32, rect))
}

/// NtGdiGetRandomRgn: `region` made a copy of `dc`'s region of kind `which`; 1, or 0 when the DC
/// has none.
pub fn random_rgn(dc: usize, region: usize, which: u32) -> Result<i32, NtStatus> {
    let mut result = 0u32;
    // SAFETY: the service writes the local.
    checked(unsafe { raw::NtGdiGetRandomRgn(dc, region, which, &mut result) })?;
    Ok(result as i32)
}

/// NtGdiPtVisible: whether the logical point is inside `dc`'s final region.
pub fn pt_visible(dc: usize, x: i32, y: i32) -> Result<bool, NtStatus> {
    let mut visible = 0u32;
    // SAFETY: the service writes the local.
    checked(unsafe { raw::NtGdiPtVisible(dc, x, y, &mut visible) })?;
    Ok(visible != 0)
}

/// NtGdiRectVisible: whether any of the logical rectangle is inside `dc`'s final region.
pub fn rect_visible(dc: usize, rect: &rtl::gdi::Rect) -> Result<bool, NtStatus> {
    let mut visible = 0u32;
    // SAFETY: the service reads the caller's rectangle and writes the local.
    checked(unsafe { raw::NtGdiRectVisible(dc, rect, &mut visible) })?;
    Ok(visible != 0)
}

// --- win32k's bitmaps ----------------------------------------------------------------------------

/// NtGdiCreateCompatibleDC: a memory DC compatible with `dc` (0: the screen), its handle.
pub fn create_compatible_dc(dc: usize) -> Result<u32, NtStatus> {
    let mut memory_dc = 0u32;
    // SAFETY: the service writes the handle into the local.
    checked(unsafe { raw::NtGdiCreateCompatibleDC(dc, &mut memory_dc) })?;
    Ok(memory_dc)
}

/// NtGdiCreateBitmap: a bitmap object `desc` describes (its pixels in this process's memory), its
/// handle.
pub fn create_bitmap(desc: &rtl::dib::BitmapDesc) -> Result<u32, NtStatus> {
    let mut bitmap = 0u32;
    // SAFETY: the kernel reads the local description through its fault-tolerant copies, and writes
    // the handle into the local.
    checked(unsafe { raw::NtGdiCreateBitmap(desc, &mut bitmap) })?;
    Ok(bitmap)
}

/// NtGdiSelectBitmap: `bitmap` selected into the memory DC `dc`, the bitmap it replaces answered
/// (0: another DC holds it).
pub fn select_bitmap(dc: usize, bitmap: usize) -> Result<u32, NtStatus> {
    let mut previous = 0u32;
    // SAFETY: the service writes the previous bitmap into the local.
    checked(unsafe { raw::NtGdiSelectBitmap(dc, bitmap, &mut previous) })?;
    Ok(previous)
}

/// NtGdiBitBlt: the rectangle at (`x`, `y`), `width` by `height`, of `dc` combined with the one
/// of its size at (`source_x`, `source_y`) of `source` and the DC's brush by the raster operation
/// `rop`.
pub fn bit_blt(
    dc: usize,
    (x, y, width, height): (i32, i32, i32, i32),
    source: usize,
    (source_x, source_y): (i32, i32),
    rop: u32,
) -> Result<(), NtStatus> {
    // SAFETY: no pointers.
    checked(unsafe { raw::NtGdiBitBlt(dc, x, y, width, height, source, source_x, source_y, rop) })
}

/// NtGdiStretchBlt: the rectangle at (`x`, `y`), `width` by `height`, of `dc` combined with the
/// one at (`source_x`, `source_y`), `source_width` by `source_height`, of `source` (stretched)
/// and the DC's brush by the raster operation `rop`.
#[allow(clippy::too_many_arguments)]
pub fn stretch_blt(
    dc: usize,
    (x, y, width, height): (i32, i32, i32, i32),
    source: usize,
    (source_x, source_y, source_width, source_height): (i32, i32, i32, i32),
    rop: u32,
) -> Result<(), NtStatus> {
    // SAFETY: no pointers.
    checked(unsafe {
        raw::NtGdiStretchBlt(
            dc,
            x,
            y,
            width,
            height,
            source,
            source_x,
            source_y,
            source_width,
            source_height,
            rop,
        )
    })
}

/// NtGdiCreatePatternBrushInternal: a pattern brush of `bitmap`'s pixels, its handle.
pub fn create_pattern_brush(bitmap: usize) -> Result<u32, NtStatus> {
    let mut brush = 0u32;
    // SAFETY: the service writes the handle into the local.
    checked(unsafe { raw::NtGdiCreatePatternBrushInternal(bitmap, &mut brush) })?;
    Ok(brush)
}

/// A zeroed block of `size` bytes of the process heap, kept until [`heap_free`]: its address; none
/// when the heap has no room.
pub fn heap_alloc(size: usize) -> Option<usize> {
    let at = <ProcessHeap as rtl::heap::ProcessHeap>::allocate(size.max(1));
    (!at.is_null()).then_some(at as usize)
}

/// Free a block [`heap_alloc`] answered.
pub fn heap_free(block: usize) {
    // SAFETY: a block of the process heap this DLL took, freed once (its owner's contract).
    unsafe { <ProcessHeap as rtl::heap::ProcessHeap>::free(block as *mut u8) };
}

// --- The font files: found through kernel32, opened through ntdll ------------------------------

/// The UNICODE_STRING and OBJECT_ATTRIBUTES ntdll takes here.
pub type UnicodeString = rtl::nt::UnicodeString<*mut u16>;
pub type ObjectAttributes = rtl::nt::ObjectAttributes<u32, *const UnicodeString, *const u8>;

// NtOpenFile's rights, sharing, options and attributes for reading a font file: FILE_READ_DATA
// and SYNCHRONIZE, FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT and FILE_NON_DIRECTORY_FILE,
// OBJ_CASE_INSENSITIVE.
use rtl::file::{FILE_NON_DIRECTORY_FILE, FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT};
use rtl::nt::access::{FILE_READ_DATA, SYNCHRONIZE};
use rtl::nt::OBJ_CASE_INSENSITIVE;

/// SearchPathW: the full path of the file `name` (NUL-terminated) in the directory `directory`
/// (NUL-terminated; none: the search path, the current directory on it) into `out`: its length,
/// 0 with SearchPathW's last error when it is not there (or does not fit).
pub fn search_path(directory: Option<&[u16]>, name: &[u16], out: &mut [u16]) -> usize {
    debug_assert_eq!(name.last(), Some(&0), "a terminated name");
    let directory = directory.map_or(core::ptr::null(), <[u16]>::as_ptr);
    // SAFETY: the names are NUL-terminated (the contract above); the call writes at most the
    // buffer's units; no extension, no file part.
    let length = unsafe {
        raw::SearchPathW(
            directory,
            name.as_ptr(),
            core::ptr::null(),
            out.len() as u32,
            out.as_mut_ptr(),
            core::ptr::null_mut(),
        )
    } as usize;
    if length >= out.len() {
        0
    } else {
        length
    }
}

/// An open file, its handle closed when dropped.
pub struct OpenFile(u32);

impl OpenFile {
    /// The file at the full DOS path `path` (NUL-terminated), opened for reading through ntdll, as
    /// Windows 2000's gdi32 opens a font file: no last error is touched. The open's status for a
    /// path that does not convert or a file that does not open.
    pub fn open(path: &[u16]) -> Result<OpenFile, NtStatus> {
        debug_assert_eq!(path.last(), Some(&0), "a terminated path");
        let mut name = UnicodeString {
            length: 0,
            maximum_length: 0,
            buffer: core::ptr::null_mut(),
        };
        // SAFETY: the path is NUL-terminated; the call writes the name (its buffer the process
        // heap's), with no file part or relative name asked for.
        let converted = unsafe {
            raw::RtlDosPathNameToNtPathName_U(
                path.as_ptr(),
                &mut name,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            )
        };
        if converted == 0 {
            return Err(NtStatus(rtl::status::STATUS_OBJECT_NAME_INVALID));
        }
        let attributes = ObjectAttributes {
            length: core::mem::size_of::<ObjectAttributes>() as u32,
            root_directory: 0,
            object_name: &name,
            attributes: OBJ_CASE_INSENSITIVE,
            security_descriptor: core::ptr::null(),
            security_quality_of_service: core::ptr::null(),
        };
        let mut handle = 0u32;
        let mut io_status = rtl::nt::IoStatusBlock::<u32>::default();
        // SAFETY: the attributes and their name are ours, alive for the call; the call writes the
        // handle and the status block, both ours.
        let status = unsafe {
            raw::NtOpenFile(
                &mut handle,
                FILE_READ_DATA | SYNCHRONIZE,
                &attributes,
                &mut io_status,
                FILE_SHARE_READ,
                FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
            )
        };
        // SAFETY: the name's buffer, the process heap's block the conversion made, freed once.
        unsafe { raw::RtlFreeHeap(raw::process_heap(), 0, name.buffer.cast()) };
        checked(status)?;
        Ok(OpenFile(handle))
    }

    /// The handle, for a service to read the file through.
    pub fn handle(&self) -> usize {
        self.0 as usize
    }
}

impl Drop for OpenFile {
    fn drop(&mut self) {
        // SAFETY: our own handle, closed once.
        unsafe { raw::NtClose(self.0) };
    }
}

/// GetSystemWindowsDirectoryW: the system root (`C:\WINNT`) into `buffer`, its length in units;
/// 0 when it does not fit.
pub fn system_windows_directory(buffer: &mut [u16]) -> usize {
    // SAFETY: the call writes at most the buffer's units.
    let length =
        unsafe { raw::GetSystemWindowsDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) };
    if length as usize >= buffer.len() {
        0
    } else {
        length as usize
    }
}

// --- win32k's fonts ------------------------------------------------------------------------------

/// NtGdiAddFontResourceW: a load of the open font file `file` (FR_PRIVATE in `flags`: the
/// process's alone), the faces it holds.
pub fn add_font_resource(file: &OpenFile, flags: u32) -> Result<u32, NtStatus> {
    let mut faces = 0u32;
    // SAFETY: the service writes the count into the local.
    checked(unsafe { raw::NtGdiAddFontResourceW(file.handle(), flags, &mut faces) })?;
    Ok(faces)
}

/// NtGdiRemoveFontResourceW: a load of the open font file `file` removed; whether there was one.
pub fn remove_font_resource(file: &OpenFile, flags: u32) -> Result<bool, NtStatus> {
    let mut removed = 0u32;
    // SAFETY: the service writes the answer into the local.
    checked(unsafe { raw::NtGdiRemoveFontResourceW(file.handle(), flags, &mut removed) })?;
    Ok(removed != 0)
}

/// NtGdiHfontCreate: a font object of the LOGFONTW at `log_font`, its handle.
pub fn create_font(log_font: Caller) -> Result<u32, NtStatus> {
    let mut font = 0u32;
    // SAFETY: the kernel reads the LOGFONTW through its fault-tolerant copies, and writes the
    // handle into the local.
    checked(unsafe { raw::NtGdiHfontCreate(log_font.0 as *const LogFontW, &mut font) })?;
    Ok(font)
}

/// NtGdiExtGetObjectW: the first `count` bytes of the font object `object`'s LOGFONTW into
/// `buffer` (none: its size alone), the bytes answered.
pub fn object(object: usize, count: u32, buffer: Caller) -> Result<u32, NtStatus> {
    let mut size = 0u32;
    // SAFETY: the kernel writes at most `count` bytes at `buffer` through its fault-tolerant
    // copies, and the size into the local.
    checked(unsafe { raw::NtGdiExtGetObjectW(object, count, buffer.0 as *mut u8, &mut size) })?;
    Ok(size)
}

/// NtGdiGetTextFaceW: `dc`'s font's face name, at most `count` units with its terminator, into
/// `buffer` (none: its length alone); the units answered.
pub fn text_face(dc: usize, count: u32, buffer: Caller) -> Result<u32, NtStatus> {
    let mut length = 0u32;
    // SAFETY: the kernel writes at most `count` units at `buffer`, and the length into the local.
    checked(unsafe { raw::NtGdiGetTextFaceW(dc, count, buffer.0 as *mut u16, &mut length) })?;
    Ok(length)
}

/// NtGdiGetOutlineTextMetricsInternalW: `dc`'s font's OUTLINETEXTMETRICW and its names, at most
/// `size` bytes of them into `buffer` (none: their size alone); the bytes answered (0: no
/// outline font).
pub fn outline_text_metrics(dc: usize, size: u32, buffer: Caller) -> Result<u32, NtStatus> {
    let mut needed = 0u32;
    // SAFETY: the kernel writes at most `size` bytes at `buffer`, and the size into the local.
    checked(unsafe {
        raw::NtGdiGetOutlineTextMetricsInternalW(dc, size, buffer.0 as *mut u8, &mut needed)
    })?;
    Ok(needed)
}

/// NtGdiGetCharWidthW: `count` characters' advances (from `first`, or the units at `characters`)
/// into the INTs at `widths`.
pub fn char_widths(
    dc: usize,
    first: u32,
    count: u32,
    characters: Caller,
    widths: Caller,
) -> Result<(), NtStatus> {
    // SAFETY: the kernel reads the characters and writes the widths through its fault-tolerant
    // copies.
    checked(unsafe {
        raw::NtGdiGetCharWidthW(
            dc,
            first,
            count,
            characters.0 as *const u16,
            widths.0 as *mut i32,
        )
    })
}

/// NtGdiGetCharABCWidthsW: `count` characters' ABC spacing (from `first`, or the units at
/// `characters`) into the ABCs at `abc`.
pub fn char_abc_widths(
    dc: usize,
    first: u32,
    count: u32,
    characters: Caller,
    abc: Caller,
) -> Result<(), NtStatus> {
    // SAFETY: as for `char_widths`.
    checked(unsafe {
        raw::NtGdiGetCharABCWidthsW(
            dc,
            first,
            count,
            characters.0 as *const u16,
            abc.0 as *mut Abc,
        )
    })
}

/// NtGdiGetFontData: GetFontData's answer (GDI_ERROR included), the bytes into `buffer`.
pub fn font_data(
    dc: usize,
    table: u32,
    offset: u32,
    buffer: Caller,
    count: u32,
) -> Result<u32, NtStatus> {
    let mut answer = 0u32;
    // SAFETY: the kernel writes at most `count` bytes at `buffer`, and the answer into the local.
    checked(unsafe {
        raw::NtGdiGetFontData(dc, table, offset, buffer.0 as *mut u8, count, &mut answer)
    })?;
    Ok(answer)
}

/// NtGdiGetGlyphOutline: GetGlyphOutlineW's answer (GDI_ERROR included), the GLYPHMETRICS into
/// `metrics` and the bitmap into `buffer`.
pub fn glyph_outline(
    dc: usize,
    character: u32,
    format: u32,
    metrics: Caller,
    size: u32,
    buffer: Caller,
) -> Result<u32, NtStatus> {
    let mut answer = 0u32;
    // SAFETY: the kernel writes the metrics and at most `size` bytes at `buffer` through its
    // fault-tolerant copies, and the answer into the local.
    checked(unsafe {
        raw::NtGdiGetGlyphOutline(
            dc,
            character,
            format,
            metrics.0 as *mut u8,
            size,
            buffer.0 as *mut u8,
            &mut answer,
        )
    })?;
    Ok(answer)
}

/// NtGdiEnumFontChunk: the enumeration's `index`th face (of those named by the face name at
/// `face`, every face for none) into `record`; none past the last.
pub fn enum_font(
    dc: usize,
    face: Option<&[u16; rtl::gdi::LF_FACESIZE]>,
    char_set: u8,
    flags: u32,
    index: u32,
    record: &mut FontEnumRecord,
) -> Result<bool, NtStatus> {
    let face = face.map_or(core::ptr::null(), |face| face.as_ptr());
    // SAFETY: the kernel reads the face name and writes the record, both ours, before the call
    // returns.
    let status =
        unsafe { raw::NtGdiEnumFontChunk(dc, face, char_set as u32, flags, index, record) };
    if status == rtl::status::STATUS_NO_MORE_ENTRIES {
        return Ok(false);
    }
    checked(status)?;
    Ok(true)
}

/// The host tests' imports: stand-ins with the imports' shapes, recording what they were given.
/// The services keep one screen DC's state ([`HOST_DC`], its handle [`DC`]) with the kernel's
/// rules, and record the text they are asked to draw. The ones every system DLL shares (the last
/// error, DbgPrint, the heap, the code page's conversions, the memory probe) are rtl's
/// ([`rtl::host`]).
#[cfg(test)]
#[allow(non_snake_case)]
pub mod host {
    use std::cell::{Cell, RefCell};

    use rtl::display::{SM_CXSCREEN, SM_CYSCREEN};
    use rtl::gdi::*;
    use rtl::host::items;
    pub use rtl::host::{
        process_heap,
        DbgPrint,
        Probed,
        RtlAllocateHeap,
        RtlFreeHeap,
        RtlMultiByteToUnicodeN,
        RtlUnicodeToMultiByteN,
        SetLastError,
        DEBUG_PRINTS,
        LAST_ERROR,
    };

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

    use rtl::status::{
        STATUS_INVALID_HANDLE,
        STATUS_INVALID_PARAMETER,
        STATUS_OBJECT_TYPE_MISMATCH,
    };

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

    /// GetSystemMetrics: the screen's width (SM_CXSCREEN) and height (SM_CYSCREEN), 0 for another
    /// index.
    pub unsafe extern "system" fn GetSystemMetrics(index: i32) -> i32 {
        match index {
            SM_CXSCREEN => SCREEN_WIDTH,
            SM_CYSCREEN => SCREEN_HEIGHT,
            _ => 0,
        }
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
            if kind == OBJ_FONT && font_object(object).is_some() {
                fonts(|fonts| fonts.selected = Some(object));
                return answer(previous, core::mem::replace(&mut state.font, object as u32));
            }
            if kind == OBJ_FONT {
                fonts(|fonts| fonts.selected = None);
            }
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

    // The bitmap services: none on the host (the kernel's tests drive the surfaces and blits).
    use rtl::status::STATUS_NOT_IMPLEMENTED;

    pub unsafe extern "system" fn NtGdiCreateCompatibleDC(_: usize, _: *mut u32) -> u32 {
        served();
        STATUS_NOT_IMPLEMENTED
    }

    pub unsafe extern "system" fn NtGdiCreateBitmap(
        _: *const rtl::dib::BitmapDesc,
        _: *mut u32,
    ) -> u32 {
        served();
        STATUS_NOT_IMPLEMENTED
    }

    pub unsafe extern "system" fn NtGdiSelectBitmap(_: usize, _: usize, _: *mut u32) -> u32 {
        served();
        STATUS_NOT_IMPLEMENTED
    }

    #[allow(clippy::too_many_arguments)]
    pub unsafe extern "system" fn NtGdiBitBlt(
        _: usize,
        _: i32,
        _: i32,
        _: i32,
        _: i32,
        _: usize,
        _: i32,
        _: i32,
        _: u32,
    ) -> u32 {
        served();
        STATUS_NOT_IMPLEMENTED
    }

    #[allow(clippy::too_many_arguments)]
    pub unsafe extern "system" fn NtGdiStretchBlt(
        _: usize,
        _: i32,
        _: i32,
        _: i32,
        _: i32,
        _: usize,
        _: i32,
        _: i32,
        _: i32,
        _: i32,
        _: u32,
    ) -> u32 {
        served();
        STATUS_NOT_IMPLEMENTED
    }

    pub unsafe extern "system" fn NtGdiCreatePatternBrushInternal(_: usize, _: *mut u32) -> u32 {
        served();
        STATUS_NOT_IMPLEMENTED
    }

    // The region services: none on the host (the kernel's tests drive the algebra).

    pub unsafe extern "system" fn NtGdiCreateRectRgn(
        _: i32,
        _: i32,
        _: i32,
        _: i32,
        _: *mut u32,
    ) -> u32 {
        served();
        STATUS_NOT_IMPLEMENTED
    }

    pub unsafe extern "system" fn NtGdiPolyPolyDraw(
        _: u32,
        _: *const u8,
        _: *const u32,
        _: u32,
        _: u32,
        _: *mut u32,
    ) -> u32 {
        served();
        STATUS_NOT_IMPLEMENTED
    }

    // The pens and shapes: none on the host (the kernel's tests drive the rasterizer).
    pub unsafe extern "system" fn NtGdiCreatePen(_: i32, _: i32, _: u32, _: *mut u32) -> u32 {
        served();
        STATUS_NOT_IMPLEMENTED
    }

    #[allow(clippy::too_many_arguments)]
    pub unsafe extern "system" fn NtGdiExtCreatePen(
        _: u32,
        _: u32,
        _: u32,
        _: u32,
        _: u32,
        _: u32,
        _: *const u32,
        _: *mut u32,
    ) -> u32 {
        served();
        STATUS_NOT_IMPLEMENTED
    }

    pub unsafe extern "system" fn NtGdiMoveTo(_: usize, _: i32, _: i32, _: *mut Point) -> u32 {
        served();
        STATUS_NOT_IMPLEMENTED
    }

    pub unsafe extern "system" fn NtGdiGetDCPoint(_: usize, _: u32, _: *mut Point) -> u32 {
        served();
        STATUS_NOT_IMPLEMENTED
    }

    pub unsafe extern "system" fn NtGdiLineTo(_: usize, _: i32, _: i32) -> u32 {
        served();
        STATUS_NOT_IMPLEMENTED
    }

    pub unsafe extern "system" fn NtGdiRectangle(_: usize, _: i32, _: i32, _: i32, _: i32) -> u32 {
        served();
        STATUS_NOT_IMPLEMENTED
    }

    pub unsafe extern "system" fn NtGdiEllipse(_: usize, _: i32, _: i32, _: i32, _: i32) -> u32 {
        served();
        STATUS_NOT_IMPLEMENTED
    }

    pub unsafe extern "system" fn NtGdiRoundRect(
        _: usize,
        _: i32,
        _: i32,
        _: i32,
        _: i32,
        _: i32,
        _: i32,
    ) -> u32 {
        served();
        STATUS_NOT_IMPLEMENTED
    }

    pub unsafe extern "system" fn NtGdiSetRectRgn(_: usize, _: i32, _: i32, _: i32, _: i32) -> u32 {
        served();
        STATUS_NOT_IMPLEMENTED
    }

    pub unsafe extern "system" fn NtGdiCombineRgn(
        _: usize,
        _: usize,
        _: usize,
        _: u32,
        _: *mut u32,
    ) -> u32 {
        served();
        STATUS_NOT_IMPLEMENTED
    }

    pub unsafe extern "system" fn NtGdiOffsetRgn(_: usize, _: i32, _: i32, _: *mut u32) -> u32 {
        served();
        STATUS_NOT_IMPLEMENTED
    }

    pub unsafe extern "system" fn NtGdiGetRgnBox(_: usize, _: *mut Rect, _: *mut u32) -> u32 {
        served();
        STATUS_NOT_IMPLEMENTED
    }

    pub unsafe extern "system" fn NtGdiEqualRgn(_: usize, _: usize, _: *mut u32) -> u32 {
        served();
        STATUS_NOT_IMPLEMENTED
    }

    pub unsafe extern "system" fn NtGdiPtInRegion(_: usize, _: i32, _: i32, _: *mut u32) -> u32 {
        served();
        STATUS_NOT_IMPLEMENTED
    }

    pub unsafe extern "system" fn NtGdiGetRegionData(
        _: usize,
        _: u32,
        _: *mut u8,
        _: *mut u32,
    ) -> u32 {
        served();
        STATUS_NOT_IMPLEMENTED
    }

    pub unsafe extern "system" fn NtGdiFillRgn(_: usize, _: usize, _: usize, _: *mut u32) -> u32 {
        served();
        STATUS_NOT_IMPLEMENTED
    }

    pub unsafe extern "system" fn NtGdiFlush() -> u32 {
        served();
        0
    }

    pub unsafe extern "system" fn NtGdiExtSelectClipRgn(
        _: usize,
        _: usize,
        _: u32,
        _: *mut u32,
    ) -> u32 {
        served();
        STATUS_NOT_IMPLEMENTED
    }

    pub unsafe extern "system" fn NtGdiIntersectClipRect(
        _: usize,
        _: i32,
        _: i32,
        _: i32,
        _: i32,
        _: *mut u32,
    ) -> u32 {
        served();
        STATUS_NOT_IMPLEMENTED
    }

    pub unsafe extern "system" fn NtGdiExcludeClipRect(
        _: usize,
        _: i32,
        _: i32,
        _: i32,
        _: i32,
        _: *mut u32,
    ) -> u32 {
        served();
        STATUS_NOT_IMPLEMENTED
    }

    pub unsafe extern "system" fn NtGdiOffsetClipRgn(_: usize, _: i32, _: i32, _: *mut u32) -> u32 {
        served();
        STATUS_NOT_IMPLEMENTED
    }

    pub unsafe extern "system" fn NtGdiGetAppClipBox(_: usize, _: *mut Rect, _: *mut u32) -> u32 {
        served();
        STATUS_NOT_IMPLEMENTED
    }

    pub unsafe extern "system" fn NtGdiGetRandomRgn(
        _: usize,
        _: usize,
        _: u32,
        _: *mut u32,
    ) -> u32 {
        served();
        STATUS_NOT_IMPLEMENTED
    }

    pub unsafe extern "system" fn NtGdiPtVisible(_: usize, _: i32, _: i32, _: *mut u32) -> u32 {
        served();
        STATUS_NOT_IMPLEMENTED
    }

    pub unsafe extern "system" fn NtGdiRectVisible(_: usize, _: *const Rect, _: *mut u32) -> u32 {
        served();
        STATUS_NOT_IMPLEMENTED
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

    pub unsafe extern "system" fn NtGdiGetDCObject(dc: usize, kind: u32, object: *mut u32) -> u32 {
        with_dc(dc, |state| match kind {
            OBJ_BRUSH => answer(object, state.brush),
            OBJ_PEN => answer(object, state.pen),
            OBJ_FONT => answer(object, state.font),
            _ => STATUS_INVALID_PARAMETER,
        })
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
                    units: items(string, count as usize).to_vec(),
                    dx: (!dx.is_null()).then(|| items(dx, count as usize).to_vec()),
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
                let units = items(string, count as usize).to_vec();
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

    // --- The font calls' stand-ins: one font file, the font objects made, the faces' names. ---

    /// The one font file the stand-ins' volume holds, by the name CreateFileW is given.
    pub const FONT_FILE: &str = "f2ktahom.ttf";
    /// Its handle while open.
    pub const FILE_HANDLE: usize = 0x5C;
    /// The first font object's handle: the font kind's bits over a GDI table handle (a slot and
    /// its uniqueness), as the kernel hands one out (rtl::gdi's `object_handle`).
    pub const FIRST_FONT: usize = object_handle(OBJ_FONT, 0x0100_0100) as usize;

    /// The font calls' state: the names CreateFileW was given, how many opens are not closed,
    /// the loads of the file (public and private), the font objects made (their LOGFONTs, by
    /// handle less FIRST_FONT), the DC's selected font object, and the characters, glyph calls
    /// and enumeration calls the services were asked about.
    #[derive(Default)]
    pub struct HostFonts {
        pub opened: std::vec::Vec<std::string::String>,
        pub open: i32,
        pub loads: [u32; 2],
        pub fonts: std::vec::Vec<LogFontW>,
        pub selected: Option<usize>,
        pub characters: std::vec::Vec<u16>,
        pub glyphs: std::vec::Vec<(u32, u32)>,
        pub enumerated: std::vec::Vec<(std::string::String, u8, u32)>,
    }

    std::thread_local! {
        pub static FONTS: RefCell<HostFonts> = RefCell::new(HostFonts::default());
    }

    fn fonts<R>(f: impl FnOnce(&mut HostFonts) -> R) -> R {
        FONTS.with(|fonts| f(&mut fonts.borrow_mut()))
    }

    /// The font file's full path, where the stand-ins' search path finds it.
    pub const FONT_PATH: &str = "C:\\CORPUS\\f2ktahom.ttf";

    /// SearchPathW: the font file along the search path (by its name alone), as `C:\CORPUS`
    /// holds it; any other file, and any file in a directory named, is not there
    /// (ERROR_FILE_NOT_FOUND). The search is kept as "<directory>|<name>".
    pub unsafe extern "system" fn SearchPathW(
        path: *const u16,
        file: *const u16,
        _extension: *const u16,
        length: u32,
        buffer: *mut u16,
        _file_part: *mut *mut u16,
    ) -> u32 {
        // SAFETY: the caller's NUL-terminated names.
        let (directory, name) = unsafe {
            (
                (!path.is_null())
                    .then(|| String::from_utf16_lossy(rtl::cstr::units_until_nul(path))),
                String::from_utf16_lossy(rtl::cstr::units_until_nul(file)),
            )
        };
        fonts(|fonts| {
            let searched = format!("{}|{name}", directory.clone().unwrap_or_default());
            fonts.opened.push(searched)
        });
        if directory.is_some() || name != FONT_FILE {
            LAST_ERROR.with(|error| error.set(2));
            return 0;
        }
        let found: std::vec::Vec<u16> = FONT_PATH.encode_utf16().chain([0]).collect();
        if (length as usize) < found.len() {
            return found.len() as u32;
        }
        // SAFETY: the caller's buffer of `length` units.
        unsafe { buffer.copy_from_nonoverlapping(found.as_ptr(), found.len()) };
        found.len() as u32 - 1
    }

    /// RtlDosPathNameToNtPathName_U: `\??\` and the path, in a block of the stand-ins' heap.
    pub unsafe extern "system" fn RtlDosPathNameToNtPathName_U(
        dos: *const u16,
        nt: *mut super::UnicodeString,
        _file_part: *mut *mut u16,
        _relative: *mut u8,
    ) -> u8 {
        // SAFETY: the caller's NUL-terminated path.
        let path = unsafe { rtl::cstr::units_until_nul(dos) };
        let units: std::vec::Vec<u16> = "\\??\\"
            .encode_utf16()
            .chain(path.iter().copied())
            .collect();
        // SAFETY: a fresh block of the stand-ins' heap, as large as the units; the caller's
        // UNICODE_STRING.
        unsafe {
            let buffer = RtlAllocateHeap(0, 0, 2 * units.len()) as *mut u16;
            buffer.copy_from_nonoverlapping(units.as_ptr(), units.len());
            nt.write(super::UnicodeString {
                length: 2 * units.len() as u16,
                maximum_length: 2 * units.len() as u16,
                buffer,
            });
        }
        1
    }

    /// NtOpenFile: the font file's NT path opens (its handle FILE_HANDLE), any other is
    /// STATUS_OBJECT_NAME_NOT_FOUND.
    pub unsafe extern "system" fn NtOpenFile(
        handle: *mut u32,
        _access: u32,
        attributes: *const super::ObjectAttributes,
        _io_status: *mut rtl::nt::IoStatusBlock<u32>,
        _share: u32,
        _options: u32,
    ) -> u32 {
        // SAFETY: the caller's attributes and name.
        let name = unsafe {
            let name = (*attributes).object_name.read();
            String::from_utf16_lossy(std::slice::from_raw_parts(
                name.buffer,
                name.length as usize / 2,
            ))
        };
        if name != format!("\\??\\{FONT_PATH}") {
            return 0xC000_0034;
        }
        fonts(|fonts| fonts.open += 1);
        answer(handle, FILE_HANDLE as u32)
    }

    pub unsafe extern "system" fn NtClose(handle: u32) -> u32 {
        assert_eq!(handle as usize, FILE_HANDLE);
        fonts(|fonts| fonts.open -= 1);
        0
    }

    /// GetSystemWindowsDirectoryW: `C:\WINNT`.
    pub unsafe extern "system" fn GetSystemWindowsDirectoryW(buffer: *mut u16, size: u32) -> u32 {
        let root: std::vec::Vec<u16> = "C:\\WINNT".encode_utf16().collect();
        if size as usize <= root.len() {
            return root.len() as u32 + 1;
        }
        // SAFETY: the caller's buffer of `size` units.
        unsafe {
            buffer.copy_from_nonoverlapping(root.as_ptr(), root.len());
            buffer.add(root.len()).write(0);
        }
        root.len() as u32
    }

    fn load_slot(flags: u32) -> usize {
        (flags & 0x10 != 0) as usize
    }

    pub unsafe extern "system" fn NtGdiAddFontResourceW(
        file: usize,
        flags: u32,
        faces: *mut u32,
    ) -> u32 {
        served();
        assert_eq!(file, FILE_HANDLE);
        fonts(|fonts| fonts.loads[load_slot(flags)] += 1);
        answer(faces, 1)
    }

    pub unsafe extern "system" fn NtGdiRemoveFontResourceW(
        file: usize,
        flags: u32,
        removed: *mut u32,
    ) -> u32 {
        served();
        assert_eq!(file, FILE_HANDLE);
        let was = fonts(|fonts| {
            let loads = &mut fonts.loads[load_slot(flags)];
            let was = *loads > 0;
            *loads = loads.saturating_sub(1);
            was
        });
        answer(removed, was as u32)
    }

    pub unsafe extern "system" fn NtGdiHfontCreate(
        log_font: *const LogFontW,
        font: *mut u32,
    ) -> u32 {
        served();
        // SAFETY: the tests' or the DLL's own LOGFONTW.
        let log_font = unsafe { log_font.read() };
        let handle = fonts(|fonts| {
            fonts.fonts.push(log_font);
            FIRST_FONT + 4 * (fonts.fonts.len() - 1)
        });
        answer(font, handle as u32)
    }

    /// The LOGFONT of the font object `handle`.
    pub fn font_object(handle: usize) -> Option<LogFontW> {
        let index = handle.checked_sub(FIRST_FONT)? / 4;
        fonts(|fonts| fonts.fonts.get(index).copied())
    }

    pub unsafe extern "system" fn NtGdiExtGetObjectW(
        object: usize,
        count: u32,
        buffer: *mut u8,
        size: *mut u32,
    ) -> u32 {
        served();
        let color = BRUSHES.with(|brushes| {
            let brushes = brushes.borrow();
            brushes
                .iter()
                .find(|&&(brush, _)| brush as usize == object)
                .map(|&(_, color)| color)
        });
        let log_brush;
        let log_font;
        let bytes = if let Some(color) = color {
            // The kernel's rule: a solid brush's LOGBRUSH.
            log_brush = rtl::dib::LogBrush {
                style: rtl::dib::BS_SOLID,
                color,
                hatch: 0,
            };
            rtl::pod::Pod::as_bytes(&log_brush)
        } else if let Some(font) = font_object(object) {
            log_font = font;
            rtl::pod::Pod::as_bytes(&log_font)
        } else {
            return STATUS_INVALID_HANDLE;
        };
        let written = if buffer.is_null() {
            bytes.len()
        } else {
            let length = bytes.len().min(count as usize);
            // SAFETY: the caller's buffer of `count` bytes.
            unsafe { buffer.copy_from_nonoverlapping(bytes.as_ptr(), length) };
            length
        };
        answer(size, written as u32)
    }

    /// The face name the DC's font answers: the selected font object's face name, else "System".
    fn face_name() -> std::vec::Vec<u16> {
        let selected = fonts(|fonts| fonts.selected);
        match selected.and_then(font_object) {
            Some(log_font) => log_font.face().to_vec(),
            None => "System".encode_utf16().collect(),
        }
    }

    pub unsafe extern "system" fn NtGdiGetTextFaceW(
        dc: usize,
        count: u32,
        buffer: *mut u16,
        length: *mut u32,
    ) -> u32 {
        with_dc(dc, |_| {
            let mut name = face_name();
            name.push(0);
            let written = if buffer.is_null() {
                name.len()
            } else {
                let length = name.len().min(count as usize);
                if length > 0 {
                    name[length - 1] = 0;
                    // SAFETY: the caller's buffer of `count` units.
                    unsafe { buffer.copy_from_nonoverlapping(name.as_ptr(), length) };
                }
                length
            };
            answer(length, written as u32)
        })
    }

    /// The outline metrics the stand-in answers: OUTLINETEXTMETRICW with a few numbers set, and
    /// the names "Family", "Face", "Style" and "Full name".
    pub fn outline_metric() -> std::vec::Vec<u8> {
        let mut metric = OutlineTextMetricW {
            text_metrics: TextMetricW {
                height: 13,
                first_char: 0x20,
                last_char: 0xFEFC,
                default_char: 0x1F,
                break_char: 0x20,
                pitch_and_family: 0x27,
                ..TextMetricW::default()
            },
            panose: [2, 11, 6, 4, 3, 5, 4, 4, 2, 4],
            ..OutlineTextMetricW::default()
        };
        metric.fields.em_square = 2048;
        metric.fields.ascent = 8;
        let mut strings = std::vec::Vec::new();
        let mut offsets = [0u32; 4];
        for (offset, name) in offsets
            .iter_mut()
            .zip(["Family", "Face", "Style", "Full name"])
        {
            *offset = (216 + strings.len()) as u32;
            for unit in name.encode_utf16().chain([0]) {
                strings.extend_from_slice(&unit.to_le_bytes());
            }
        }
        [
            metric.fields.family_name,
            metric.fields.face_name,
            metric.fields.style_name,
            metric.fields.full_name,
        ] = offsets;
        metric.size = (216 + strings.len()) as u32;
        let mut bytes = rtl::pod::Pod::as_bytes(&metric).to_vec();
        bytes.extend(strings);
        bytes
    }

    pub unsafe extern "system" fn NtGdiGetOutlineTextMetricsInternalW(
        dc: usize,
        size: u32,
        buffer: *mut u8,
        needed: *mut u32,
    ) -> u32 {
        with_dc(dc, |_| {
            let bytes = outline_metric();
            if buffer.is_null() || size == 0 {
                return answer(needed, bytes.len() as u32);
            }
            let length = bytes.len().min(size as usize);
            // SAFETY: the caller's buffer of `size` bytes.
            unsafe { buffer.copy_from_nonoverlapping(bytes.as_ptr(), length) };
            answer(needed, length as u32)
        })
    }

    /// The characters a widths call names: from `first`, or the caller's.
    fn characters(first: u32, count: u32, characters: *const u16) -> std::vec::Vec<u16> {
        let units = if characters.is_null() {
            (first..first + count).map(|unit| unit as u16).collect()
        } else {
            // SAFETY: the caller's `count` units.
            unsafe { items(characters, count as usize) }.to_vec()
        };
        fonts(|fonts| fonts.characters.extend(&units));
        units
    }

    /// Each character's width: its code's last decimal digit, plus one.
    pub fn width_of(unit: u16) -> i32 {
        (unit % 10) as i32 + 1
    }

    pub unsafe extern "system" fn NtGdiGetCharWidthW(
        dc: usize,
        first: u32,
        count: u32,
        units: *const u16,
        widths: *mut i32,
    ) -> u32 {
        with_dc(dc, |_| {
            for (index, unit) in characters(first, count, units).into_iter().enumerate() {
                // SAFETY: the caller's `count` widths.
                unsafe { widths.add(index).write(width_of(unit)) };
            }
            0
        })
    }

    pub unsafe extern "system" fn NtGdiGetCharABCWidthsW(
        dc: usize,
        first: u32,
        count: u32,
        units: *const u16,
        abc: *mut Abc,
    ) -> u32 {
        with_dc(dc, |_| {
            for (index, unit) in characters(first, count, units).into_iter().enumerate() {
                let spacing = Abc {
                    a: 1,
                    b: width_of(unit) as u32,
                    c: -1,
                };
                // SAFETY: the caller's `count` ABCs.
                unsafe { abc.add(index).write(spacing) };
            }
            0
        })
    }

    pub unsafe extern "system" fn NtGdiGetFontData(
        dc: usize,
        _table: u32,
        offset: u32,
        buffer: *mut u8,
        count: u32,
        out: *mut u32,
    ) -> u32 {
        with_dc(dc, |_| {
            if offset >= 54 {
                return answer(out, GDI_ERROR);
            }
            if buffer.is_null() {
                return answer(out, 54);
            }
            let length = count.min(54 - offset);
            // SAFETY: the caller's buffer of `count` bytes.
            unsafe { buffer.write_bytes(0xAB, length as usize) };
            answer(out, length)
        })
    }

    pub unsafe extern "system" fn NtGdiGetGlyphOutline(
        dc: usize,
        character: u32,
        format: u32,
        _metrics: *mut u8,
        _size: u32,
        _buffer: *mut u8,
        out: *mut u32,
    ) -> u32 {
        with_dc(dc, |_| {
            fonts(|fonts| fonts.glyphs.push((character, format)));
            answer(out, 32)
        })
    }

    /// The enumeration: two character sets of "F2K Tahoma" (one for the families'
    /// enumeration), none of another face.
    pub unsafe extern "system" fn NtGdiEnumFontChunk(
        dc: usize,
        face: *const u16,
        char_set: u32,
        flags: u32,
        index: u32,
        record: *mut FontEnumRecord,
    ) -> u32 {
        with_dc(dc, |_| {
            // SAFETY: the DLL's own face name.
            let name = (!face.is_null())
                .then(|| String::from_utf16_lossy(unsafe { rtl::cstr::units_until_nul(face) }))
                .unwrap_or_default();
            if index == 0 {
                fonts(|fonts| fonts.enumerated.push((name.clone(), char_set as u8, flags)));
            }
            let count = if !name.is_empty() && name != "F2K Tahoma" {
                0
            } else if flags & 1 != 0 {
                1
            } else {
                2
            };
            if index >= count {
                return rtl::status::STATUS_NO_MORE_ENTRIES;
            }
            let mut entry: FontEnumRecord = rtl::pod::Pod::zeroed();
            let set = [0u8, 204][index as usize];
            entry.log_font.log_font.height = 39;
            entry.log_font.log_font.char_set = set;
            for (unit, value) in entry
                .log_font
                .log_font
                .face_name
                .iter_mut()
                .zip("F2K Tahoma".encode_utf16())
            {
                *unit = value;
            }
            for (unit, value) in entry
                .log_font
                .full_name
                .iter_mut()
                .zip("F2K Tahoma".encode_utf16())
            {
                *unit = value;
            }
            for (unit, value) in entry
                .log_font
                .style
                .iter_mut()
                .zip("Regular".encode_utf16())
            {
                *unit = value;
            }
            let script = ["Western", "Cyrillic"][index as usize];
            for (unit, value) in entry.log_font.script.iter_mut().zip(script.encode_utf16()) {
                *unit = value;
            }
            entry.metric.metric.text_metric = TextMetricW {
                height: 39,
                first_char: 0x20,
                last_char: 0xFEFC,
                default_char: 0x1F,
                break_char: 0x20,
                pitch_and_family: 0x27,
                char_set: set,
                ..TextMetricW::default()
            };
            entry.metric.metric.size_em = 2048;
            entry.font_type = TRUETYPE_FONTTYPE;
            // SAFETY: the DLL's own record.
            unsafe { record.write(entry) };
            0
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The conversion fakes take NULL with no length, as a caller may pass it, and convert
    /// nothing.
    #[test]
    fn conversions_take_null_with_no_length() {
        let mut written = 7u32;
        // SAFETY: no buffers, of no length; the count goes into the local.
        unsafe {
            host::RtlMultiByteToUnicodeN(
                core::ptr::null_mut(),
                0,
                &mut written,
                core::ptr::null(),
                0,
            )
        };
        assert_eq!(written, 0);
        written = 7;
        // SAFETY: as above.
        unsafe {
            host::RtlUnicodeToMultiByteN(
                core::ptr::null_mut(),
                0,
                &mut written,
                core::ptr::null(),
                0,
            )
        };
        assert_eq!(written, 0);
    }
}
