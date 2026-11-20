//! Bitmaps: memory DCs (CreateCompatibleDC), device-dependent bitmaps (CreateBitmap,
//! CreateCompatibleBitmap, CreateDIBitmap) and DIB sections (CreateDIBSection), GetObject of
//! them, their pixels read and written as DIBs (GetDIBits, SetDIBits), DIBs drawn into a DC
//! (SetDIBitsToDevice, StretchDIBits), the blits (BitBlt, StretchBlt) and their stretch mode,
//! pattern brushes and the brush origin, and GetObjectType of every kind of object, over win32k's
//! bitmap services ([`imports`]; the kernel's side is in kernel/src/win32k/bitmap.rs).
//!
//! gdi32 makes a bitmap's memory itself, a block of the process heap: a device-dependent bitmap's
//! rows top-down, each a whole number of words, and a DIB section's color table (two to its bits
//! per pixel of RGBQUADs, up to 8 bits; the entries the header does not give zero) and then its
//! rows as its header lays them out. NtGdiCreateBitmap makes the object over it
//! ([`rtl::dib::BitmapDesc`]); DeleteObject frees the block once the kernel has deleted the object
//! ([`crate::dc`]). GetDIBits and SetDIBits read and write the pixels here, through the
//! description NtGdiExtGetObjectW answers; SetDIBitsToDevice and StretchDIBits make a bitmap object
//! over the caller's DIB itself (no copy) and blit it from a memory DC.
//!
//! What the calls answer, as the bitmaps capture shows Windows 2000's:
//!
//! - a bitmap of no pixels (CreateBitmap's or CreateCompatibleBitmap's 0 by 0) is the default
//!   bitmap, the one a new memory DC holds;
//! - CreateBitmap rounds its planes times its bits up to 1, 4, 8, 16, 24 or 32 (2 bits make 4), and
//!   refuses more than 32 or a negative extent with ERROR_INVALID_PARAMETER;
//! - CreateDIBSection refuses a header it cannot lay out (no depth, no width) with NULL and the
//!   last error untouched, a usage that is neither DIB_RGB_COLORS nor DIB_PAL_COLORS with
//!   ERROR_INVALID_PARAMETER, and leaves the last error ERROR_NOT_ENOUGH_MEMORY when it succeeds
//!   (as Windows 2000's does: CreateCompatibleBitmap of a DC holding a DIB section, which makes one
//!   too, and LoadImage's LR_CREATEDIBSECTION show it);
//! - GetDIBits of no bits and a header of no depth fills the header (a 32-bit device-dependent
//!   bitmap's compression BI_BITFIELDS) and answers 1; with bits, it answers the scan lines it
//!   wrote, the color table the default one of the depth (1 bit black and white, 4 bits the VGA's,
//!   8 bits the system palette's), each pixel the table's nearest entry, biClrUsed 0;
//! - SetDIBits answers the scan lines it wrote; a color going to a monochrome bitmap is 1 when it
//!   is the DC's background color and 0 otherwise;
//! - SetDIBitsToDevice answers the scan lines from the first it was handed to the top of the
//!   rectangle it drew; StretchDIBits answers the DIB's height.

use core::mem::size_of;

use rtl::dib::*;
use rtl::gdi::*;
use rtl::pod::Pod;

use crate::imports::{self, Caller};
use crate::{
    answered,
    failed,
    ERROR_INVALID_HANDLE,
    ERROR_INVALID_PARAMETER,
    ERROR_NOT_ENOUGH_MEMORY,
};

/// The largest block of pixels gdi32 makes for one bitmap: 64 MiB.
const MAX_PIXEL_BYTES: usize = 64 << 20;

// --- Descriptions and memory ---------------------------------------------------------------------

/// The description of the bitmap `bitmap` (the kernel's); none for a handle that names no bitmap,
/// the last error untouched.
pub(crate) fn describe(bitmap: usize) -> Option<BitmapDesc> {
    let mut desc = BitmapDesc::default();
    let size = imports::object(
        bitmap,
        size_of::<BitmapDesc>() as u32,
        Caller::of_mut(&mut desc),
    )
    .ok()?;
    (size as usize == size_of::<BitmapDesc>()).then_some(desc)
}

/// A pixel format with its colors: a table's (up to 8 bits) or its masks.
#[derive(Clone, Copy)]
struct Colors {
    bpp: u32,
    table: [u32; 256],
    masks: [u32; 3],
}

impl Colors {
    /// The colors of a depth with its default table (a device-dependent bitmap's, GetDIBits'
    /// answers): black and white, the VGA's, the system palette's; 5-5-5 and 8-8-8 masks.
    fn default_of(bpp: u32) -> Colors {
        let mut table = [0u32; 256];
        for (index, entry) in table.iter_mut().take(table_size(bpp)).enumerate() {
            *entry = match bpp {
                1 => MONO_COLORS[index],
                4 => VGA_COLORS[index],
                _ => default_color_8(index),
            };
        }
        Colors {
            bpp,
            table,
            masks: default_masks(bpp),
        }
    }

    /// The colors of the bitmap `desc` describes: a DIB section's own table (in this process's
    /// memory) or masks, a device-dependent bitmap's defaults.
    fn of_desc(desc: &BitmapDesc) -> Colors {
        let mut colors = Colors::default_of(desc.bpp);
        colors.masks = desc.pixel_masks();
        if desc.is_dib() && desc.colors != 0 {
            let count = (desc.color_count as usize).min(table_size(desc.bpp));
            colors.table = [0; 256];
            // SAFETY: a DIB section's table, this process's own memory gdi32 made (its block).
            let quads =
                unsafe { core::slice::from_raw_parts(desc.colors as *const [u8; 4], count) };
            for (entry, &quad) in colors.table.iter_mut().zip(quads) {
                *entry = rgb_of_quad(quad);
            }
        }
        colors
    }

    fn format(&self) -> Format<'_> {
        Format {
            bpp: self.bpp,
            table: &self.table[..table_size(self.bpp)],
            masks: self.masks,
        }
    }
}

/// A DIB the caller hands a call: its header, its color table's address and entries (or its
/// masks), and how its rows lie.
#[derive(Clone, Copy)]
struct Dib {
    header: BitmapInfoHeader,
    colors: usize,
    color_count: u32,
    masks: [u32; 3],
    bitfields: bool,
}

impl Dib {
    /// The DIB the BITMAPINFO at `info` describes; none for a header F2K cannot lay out (no
    /// depth it takes, no width, no height, a compression other than BI_RGB, or BI_BITFIELDS
    /// past 16 and 32 bits).
    ///
    /// # Safety
    ///
    /// `info` is the caller's BITMAPINFO, its header and its color table or masks readable.
    unsafe fn read(info: usize) -> Option<Dib> {
        if info == 0 {
            return None;
        }
        // SAFETY: the caller's header (any alignment).
        let header = unsafe { core::ptr::read_unaligned(info as *const BitmapInfoHeader) };
        let bpp = header.bit_count as u32;
        let bitfields = header.compression == BI_BITFIELDS;
        let laid_out = header.size >= HEADER_SIZE
            && header.width > 0
            && header.height != 0
            && is_dib_depth(bpp)
            && (header.compression == BI_RGB || (bitfields && matches!(bpp, 16 | 32)));
        if !laid_out {
            return None;
        }
        let colors = info + header.size as usize;
        let masks = if bitfields {
            // SAFETY: the caller's three masks after the header.
            let read = |index: usize| unsafe {
                core::ptr::read_unaligned((colors + 4 * index) as *const u32)
            };
            [read(0), read(1), read(2)]
        } else {
            default_masks(bpp)
        };
        let size = table_size(bpp) as u32;
        let color_count = if header.clr_used == 0 || header.clr_used > size {
            size
        } else {
            header.clr_used
        };
        Some(Dib {
            header,
            colors,
            color_count,
            masks,
            bitfields,
        })
    }

    fn bpp(&self) -> u32 {
        self.header.bit_count as u32
    }

    fn height(&self) -> i32 {
        self.header.height.saturating_abs()
    }

    fn top_down(&self) -> bool {
        self.header.height < 0
    }

    fn stride(&self) -> u32 {
        dword_stride(self.header.width, self.bpp())
    }

    /// Its colors: its table's RGBQUADs (DIB_RGB_COLORS), the system palette's entries its
    /// table's indexes name (DIB_PAL_COLORS), or its masks.
    ///
    /// # Safety
    ///
    /// As for [`Dib::read`]: its table readable.
    unsafe fn colors(&self, usage: u32) -> Colors {
        let mut colors = Colors::default_of(self.bpp());
        colors.masks = self.masks;
        let count = self.color_count as usize;
        if count != 0 {
            colors.table = [0; 256];
            for (index, entry) in colors.table.iter_mut().take(count).enumerate() {
                *entry = if usage == DIB_PAL_COLORS {
                    // SAFETY: the caller's table of WORD indexes.
                    let at = unsafe {
                        core::ptr::read_unaligned((self.colors + 2 * index) as *const u16)
                    };
                    default_color_8(at as usize & 0xFF)
                } else {
                    // SAFETY: the caller's table of RGBQUADs.
                    let quad = unsafe {
                        core::ptr::read_unaligned((self.colors + 4 * index) as *const [u8; 4])
                    };
                    rgb_of_quad(quad)
                };
            }
        }
        colors
    }

    /// A bitmap object's description over this DIB's `lines` rows at `bits` (the caller's memory:
    /// no block of gdi32's), its colors at its table.
    fn view(&self, bits: usize, lines: i32) -> BitmapDesc {
        let mut flags = DESC_DIB;
        if self.top_down() {
            flags |= DESC_TOP_DOWN;
        }
        if self.bitfields {
            flags |= DESC_BITFIELDS;
        }
        BitmapDesc {
            width: self.header.width,
            height: lines,
            bpp: self.bpp(),
            flags,
            masks: if self.bitfields { self.masks } else { [0; 3] },
            stride: self.stride(),
            bits: bits as u32,
            colors: if self.color_count != 0 {
                self.colors as u32
            } else {
                0
            },
            color_count: self.color_count,
            block: 0,
        }
    }
}

/// A bitmap object made over a new block of the process heap: `table`'s colors (a DIB section's,
/// all `table_size` entries), then `desc`'s rows, which `init` fills; its handle and its final
/// description. None with the last error (the block freed) when the heap or the kernel has no
/// room.
fn new_bitmap(
    mut desc: BitmapDesc,
    table: Option<&[u32]>,
    init: impl FnOnce(&mut [u8]),
) -> Option<(usize, BitmapDesc)> {
    let pixels = (desc.stride as usize).checked_mul(desc.height as usize);
    let Some(pixels) = pixels.filter(|&bytes| bytes <= MAX_PIXEL_BYTES) else {
        return failed(ERROR_NOT_ENOUGH_MEMORY);
    };
    let entries = table.map_or(0, |_| table_size(desc.bpp));
    let Some(block) = imports::heap_alloc(4 * entries + pixels) else {
        return failed(ERROR_NOT_ENOUGH_MEMORY);
    };
    // SAFETY: the block just taken, ours alone, of that many bytes.
    let memory = unsafe { core::slice::from_raw_parts_mut(block as *mut u8, 4 * entries + pixels) };
    let (quads, rows) = memory.split_at_mut(4 * entries);
    if let Some(table) = table {
        let (quads, _) = quads.as_chunks_mut::<4>();
        for (quad, &rgb) in quads.iter_mut().zip(table) {
            *quad = quad_of_rgb(rgb);
        }
    }
    init(rows);
    desc.block = block as u32;
    desc.colors = if entries != 0 { block as u32 } else { 0 };
    desc.color_count = entries as u32;
    desc.bits = (block + 4 * entries) as u32;
    match answered(imports::create_bitmap(&desc)) {
        Some(handle) => Some((handle as usize, desc)),
        None => {
            imports::heap_free(block);
            None
        }
    }
}

/// A device-dependent bitmap of `width` by `height` at `bpp` bits, its rows zeroed or `init`'s.
fn new_ddb(width: i32, height: i32, bpp: u32, init: impl FnOnce(&mut [u8])) -> usize {
    let desc = BitmapDesc {
        width,
        height,
        bpp,
        flags: 0,
        masks: [0; 3],
        stride: word_stride(width, bpp),
        bits: 0,
        colors: 0,
        color_count: 0,
        block: 0,
    };
    new_bitmap(desc, None, init).map_or(0, |(handle, _)| handle)
}

/// A DIB section of `width` by `height` (negative: top-down) at `bpp` bits with `table`'s colors
/// or `masks` (BI_BITFIELDS), its rows zeroed: its handle and its bits' address. The last error is
/// ERROR_NOT_ENOUGH_MEMORY when it succeeds (Windows 2000's own leftover).
fn new_dib_section(
    width: i32,
    height: i32,
    bpp: u32,
    table: &[u32],
    masks: Option<[u32; 3]>,
) -> Option<(usize, usize)> {
    let mut flags = DESC_DIB;
    if height < 0 {
        flags |= DESC_TOP_DOWN;
    }
    if masks.is_some() {
        flags |= DESC_BITFIELDS;
    }
    let desc = BitmapDesc {
        width,
        height: height.saturating_abs(),
        bpp,
        flags,
        masks: masks.unwrap_or([0; 3]),
        stride: dword_stride(width, bpp),
        bits: 0,
        colors: 0,
        color_count: 0,
        block: 0,
    };
    let mut full = [0u32; 256];
    let size = table_size(bpp);
    for (entry, &rgb) in full.iter_mut().zip(table.iter().take(size)) {
        *entry = rgb;
    }
    let (handle, desc) = new_bitmap(desc, (size != 0).then_some(&full[..size]), |_| {})?;
    imports::set_last_error(ERROR_NOT_ENOUGH_MEMORY);
    Some((handle, desc.bits as usize))
}

/// The rows of the bitmap `desc` describes, in this process's memory (none for the default
/// bitmap, which has none).
fn rows_of(desc: &BitmapDesc) -> Option<&'static mut [u8]> {
    if desc.bits == 0 {
        return None;
    }
    // SAFETY: the bitmap's rows, this process's memory that gdi32 made for it (or the caller's DIB
    // a view names), `stride` bytes for each of its rows; nothing else holds a reference to them
    // while the call works.
    Some(unsafe {
        core::slice::from_raw_parts_mut(
            desc.bits as *mut u8,
            desc.stride as usize * desc.height as usize,
        )
    })
}

/// The kind of DC `dc` is (OBJ_DC or OBJ_MEMDC); none with the last error for a handle that names
/// none.
fn dc_kind(dc: usize) -> Option<u32> {
    answered(imports::dc_dword(dc, DC_OBJECT_TYPE))
}

/// The description of the bitmap a memory DC holds.
fn selected_desc(dc: usize) -> Option<BitmapDesc> {
    let bitmap = answered(imports::dc_object(dc, OBJ_BITMAP))?;
    describe(bitmap as usize)
}

// --- Memory DCs and bitmaps ----------------------------------------------------------------------

/// CreateCompatibleDC: a memory DC holding the default bitmap; NULL with the last error for a DC
/// that is none.
#[unsafe(export_name = "f2k_export_CreateCompatibleDC")]
pub extern "system" fn create_compatible_dc(dc: usize) -> usize {
    answered(imports::create_compatible_dc(dc)).map_or(0, |dc| dc as usize)
}

/// GdiFlush: TRUE (F2K batches no drawing: every call has drawn when it returns).
#[unsafe(export_name = "f2k_export_GdiFlush")]
pub extern "system" fn gdi_flush() -> u32 {
    1
}

/// CreateBitmap: see the module notes; the rows at `bits` (word-aligned, as GetBitmapBits lays
/// them out) copied in when given.
///
/// # Safety
///
/// `bits`, when not null, holds the bitmap's rows.
#[unsafe(export_name = "f2k_export_CreateBitmap")]
pub unsafe extern "system" fn create_bitmap(
    width: i32,
    height: i32,
    planes: u32,
    bits_per_pixel: u32,
    bits: *const u8,
) -> usize {
    let depth = planes.checked_mul(bits_per_pixel).and_then(rounded_bpp);
    let Some(depth) = depth.filter(|_| width >= 0 && height >= 0) else {
        return failed(ERROR_INVALID_PARAMETER).unwrap_or(0);
    };
    if width == 0 || height == 0 {
        return DEFAULT_BITMAP as usize;
    }
    new_ddb(width, height, depth, |rows| {
        if !bits.is_null() {
            // SAFETY: the caller's rows, as many as the bitmap holds.
            let source = unsafe { core::slice::from_raw_parts(bits, rows.len()) };
            rows.copy_from_slice(source);
        }
    })
}

/// A bitmap compatible with `dc` of `width` by `height`: the screen's 32 bits for a screen DC, a
/// memory DC's bitmap's depth (a DIB section of its format when it holds one and `dib`); 0 with the
/// last error for a DC that is none.
fn compatible(dc: usize, width: i32, height: i32, dib: bool) -> usize {
    match dc_kind(dc) {
        Some(OBJ_MEMDC) => {
            let Some(desc) = selected_desc(dc) else {
                return 0;
            };
            if desc.is_dib() && dib {
                let colors = Colors::of_desc(&desc);
                let masks = (desc.flags & DESC_BITFIELDS != 0).then_some(desc.masks);
                let height = if desc.top_down() { -height } else { height };
                new_dib_section(width, height, desc.bpp, &colors.table, masks)
                    .map_or(0, |(handle, _)| handle)
            } else {
                new_ddb(width, height, desc.bpp, |_| {})
            }
        }
        Some(_) => new_ddb(width, height, 32, |_| {}),
        None => 0,
    }
}

/// CreateCompatibleBitmap: see the module notes and [`compatible`].
#[unsafe(export_name = "f2k_export_CreateCompatibleBitmap")]
pub extern "system" fn create_compatible_bitmap(dc: usize, width: i32, height: i32) -> usize {
    if width == 0 || height == 0 {
        return DEFAULT_BITMAP as usize;
    }
    if width < 0 || height < 0 {
        return failed(ERROR_INVALID_PARAMETER).unwrap_or(0);
    }
    compatible(dc, width, height, true)
}

/// CreateDIBSection: see the module notes; the bits' address into `bits` (when given). F2K takes
/// no section (`section` is not looked at).
///
/// # Safety
///
/// `info` is the caller's BITMAPINFO; `bits`, when not null, a pointer's room.
#[unsafe(export_name = "f2k_export_CreateDIBSection")]
pub unsafe extern "system" fn create_dib_section(
    _dc: usize,
    info: usize,
    usage: u32,
    bits: *mut usize,
    _section: usize,
    _offset: u32,
) -> usize {
    if !bits.is_null() {
        // SAFETY: the caller's pointer's room.
        unsafe { bits.write_unaligned(0) };
    }
    // SAFETY: the caller's BITMAPINFO.
    let Some(dib) = (unsafe { Dib::read(info) }) else {
        return 0;
    };
    if usage > DIB_PAL_COLORS {
        return failed(ERROR_INVALID_PARAMETER).unwrap_or(0);
    }
    // SAFETY: as above, its table.
    let colors = unsafe { dib.colors(usage) };
    let table = &colors.table[..dib.color_count as usize];
    let masks = dib.bitfields.then_some(dib.masks);
    let Some((handle, address)) =
        new_dib_section(dib.header.width, dib.header.height, dib.bpp(), table, masks)
    else {
        return 0;
    };
    if !bits.is_null() {
        // SAFETY: as above.
        unsafe { bits.write_unaligned(address) };
    }
    handle
}

/// CreateDIBitmap: a device-dependent bitmap compatible with `dc` of the header's size, its pixels
/// the DIB's at `bits` (SetDIBits) with CBM_INIT; ERROR_INVALID_PARAMETER for a usage that is
/// neither DIB_RGB_COLORS nor DIB_PAL_COLORS.
///
/// # Safety
///
/// `header` the caller's BITMAPINFOHEADER; with CBM_INIT, `bits` its rows and `info` its
/// BITMAPINFO.
#[unsafe(export_name = "f2k_export_CreateDIBitmap")]
pub unsafe extern "system" fn create_di_bitmap(
    dc: usize,
    header: usize,
    init: u32,
    bits: usize,
    info: usize,
    usage: u32,
) -> usize {
    if usage > DIB_PAL_COLORS {
        return failed(ERROR_INVALID_PARAMETER).unwrap_or(0);
    }
    if header == 0 {
        return failed(ERROR_INVALID_PARAMETER).unwrap_or(0);
    }
    // SAFETY: the caller's header.
    let header = unsafe { core::ptr::read_unaligned(header as *const BitmapInfoHeader) };
    let (width, height) = (header.width, header.height.saturating_abs());
    if width < 0 {
        return failed(ERROR_INVALID_PARAMETER).unwrap_or(0);
    }
    if width == 0 || height == 0 {
        return DEFAULT_BITMAP as usize;
    }
    let bitmap = compatible(dc, width, height, false);
    if bitmap != 0 && init & CBM_INIT != 0 && bits != 0 && info != 0 {
        // SAFETY: the caller's DIB (the contract above).
        unsafe { set_di_bits(dc, bitmap, 0, height as u32, bits, info, usage) };
    }
    bitmap
}

/// GetObjectW and GetObjectA of a bitmap: its DIBSECTION (a DIB section's, for a buffer that
/// holds one) or its BITMAP into `buffer`, their size; BITMAP's size for no buffer; 0 for a buffer
/// too small for a BITMAP (the last error untouched) or with the last error for a handle that
/// names no bitmap.
pub(crate) fn get_object(object: usize, size: i32, buffer: usize) -> i32 {
    let Some(desc) = describe(object) else {
        return failed(ERROR_INVALID_HANDLE).unwrap_or(0);
    };
    if buffer == 0 {
        return size_of::<Bitmap>() as i32;
    }
    let dib_section;
    let bitmap;
    let bytes: &[u8] = if desc.is_dib() && size >= size_of::<DibSection>() as i32 {
        dib_section = desc.dib_section();
        dib_section.as_bytes()
    } else if size >= size_of::<Bitmap>() as i32 {
        bitmap = desc.bitmap();
        bitmap.as_bytes()
    } else {
        return 0;
    };
    // SAFETY: the caller's buffer of `size` bytes, at least these.
    unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), buffer as *mut u8, bytes.len()) };
    bytes.len() as i32
}

// --- The pixels as DIBs --------------------------------------------------------------------------

/// GetDIBits: see the module notes.
///
/// # Safety
///
/// `info` the caller's BITMAPINFO, its color table's room writable; `bits`, when not null, room
/// for the scan lines asked for.
#[unsafe(export_name = "f2k_export_GetDIBits")]
pub unsafe extern "system" fn get_di_bits(
    _dc: usize,
    bitmap: usize,
    start: u32,
    lines: u32,
    bits: usize,
    info: usize,
    _usage: u32,
) -> i32 {
    if bitmap == 0 || info == 0 {
        return 0;
    }
    let Some(desc) = describe(bitmap) else {
        return 0;
    };
    let header_at = info as *mut BitmapInfoHeader;
    // SAFETY: the caller's header.
    let mut header = unsafe { header_at.read_unaligned() };
    if bits == 0 && header.bit_count == 0 {
        header.width = desc.width;
        header.height = desc.height;
        header.planes = 1;
        header.bit_count = desc.bpp as u16;
        header.compression = if desc.bpp == 32 && !desc.is_dib() {
            BI_BITFIELDS
        } else {
            BI_RGB
        };
        header.size_image = dword_stride(desc.width, desc.bpp) * desc.height as u32;
        header.clr_used = table_size(desc.bpp) as u32;
        header.clr_important = header.clr_used;
        // SAFETY: as above.
        unsafe { header_at.write_unaligned(header) };
        return 1;
    }
    // SAFETY: the caller's BITMAPINFO.
    let Some(dib) = (unsafe { Dib::read(info) }) else {
        return 0;
    };
    let to = Colors {
        masks: dib.masks,
        ..Colors::default_of(dib.bpp())
    };
    // The table: the depth's default one.
    for (index, &rgb) in to.table.iter().take(table_size(dib.bpp())).enumerate() {
        let at = (info + header.size as usize + 4 * index) as *mut [u8; 4];
        // SAFETY: the caller's table's room.
        unsafe { at.write_unaligned(quad_of_rgb(rgb)) };
    }
    header.size_image = dib.stride() * dib.height() as u32;
    header.clr_used = 0;
    // SAFETY: as above.
    unsafe { header_at.write_unaligned(header) };
    if bits == 0 {
        return 1;
    }
    let from = Colors::of_desc(&desc);
    let source = rows_of(&desc);
    let stride = dib.stride() as usize;
    let end = (start as u64 + lines as u64).min(desc.height as u64) as u32;
    let mut done = 0;
    for line in start..end {
        let y = if dib.top_down() {
            line as i32
        } else {
            desc.height - 1 - line as i32
        };
        // SAFETY: the caller's room for this scan line.
        let out = unsafe {
            core::slice::from_raw_parts_mut(
                (bits + stride * (line - start) as usize) as *mut u8,
                stride,
            )
        };
        let row = source.as_deref().map(|rows| {
            let at = desc.row_offset(y) as usize;
            &rows[at..at + desc.stride as usize]
        });
        convert_row(row, &from, out, &to, desc.width.min(dib.header.width), None);
        done += 1;
    }
    done
}

/// One row of `width` pixels from `row` (none: the default bitmap's, all 0) in `from`'s format
/// to `out` in `to`'s: each color to `to`'s nearest pixel, or for a monochrome bitmap's row
/// (`mono`, the DC's background color) 1 for that color and 0 for any other.
fn convert_row(
    row: Option<&[u8]>,
    from: &Colors,
    out: &mut [u8],
    to: &Colors,
    width: i32,
    mono: Option<u32>,
) {
    let (from_format, to_format) = (from.format(), to.format());
    for x in 0..width.max(0) as usize {
        let pixel = row.map_or(0, |row| get_packed(row, x, from.bpp));
        let rgb = from_format.rgb(pixel);
        let value = match mono {
            Some(background) => (rgb == background) as u32,
            None => to_format.pixel(rgb),
        };
        set_packed(out, x, to.bpp, value);
    }
}

/// SetDIBits: see the module notes.
///
/// # Safety
///
/// `bits` holds the scan lines handed, `info` is the caller's BITMAPINFO.
#[unsafe(export_name = "f2k_export_SetDIBits")]
pub unsafe extern "system" fn set_di_bits(
    dc: usize,
    bitmap: usize,
    start: u32,
    lines: u32,
    bits: usize,
    info: usize,
    usage: u32,
) -> i32 {
    if lines == 0 || bits == 0 || bitmap == 0 {
        return 0;
    }
    let Some(desc) = describe(bitmap) else {
        return 0;
    };
    // SAFETY: the caller's BITMAPINFO.
    let Some(dib) = (unsafe { Dib::read(info) }) else {
        return 0;
    };
    // SAFETY: as above, its table.
    let from = unsafe { dib.colors(usage) };
    let to = Colors::of_desc(&desc);
    let mono = desc.is_mono().then(|| {
        let background = imports::dc_dword(dc, DC_BK_COLOR).unwrap_or(DEFAULT_BK_COLOR);
        rgb_of_colorref(background)
    });
    let Some(rows) = rows_of(&desc) else {
        return 0;
    };
    let stride = dib.stride() as usize;
    let end = (start as u64 + lines as u64).min(dib.height() as u64) as u32;
    let mut done = 0;
    for line in start..end {
        let y = if dib.top_down() {
            line as i32
        } else {
            dib.height() - 1 - line as i32
        };
        if y >= desc.height {
            continue;
        }
        // SAFETY: the caller's scan line.
        let row = unsafe {
            core::slice::from_raw_parts(
                (bits + stride * (line - start) as usize) as *const u8,
                stride,
            )
        };
        let at = desc.row_offset(y) as usize;
        let out = &mut rows[at..at + desc.stride as usize];
        convert_row(
            Some(row),
            &from,
            out,
            &to,
            desc.width.min(dib.header.width),
            mono,
        );
        done += 1;
    }
    done
}

/// A memory DC holding a bitmap object over the caller's DIB (`dib`'s `lines` rows at `bits`), for
/// `f` to blit from: its handle; the DC and the object deleted after. None (with the last error)
/// when either could not be made.
fn with_view<R>(dib: &Dib, bits: usize, lines: i32, f: impl FnOnce(usize) -> R) -> Option<R> {
    let view = answered(imports::create_bitmap(&dib.view(bits, lines)))? as usize;
    let Some(dc) = answered(imports::create_compatible_dc(0)) else {
        let _ = imports::delete_object(view);
        return None;
    };
    let dc = dc as usize;
    let answer = answered(imports::select_bitmap(dc, view)).map(|_| f(dc));
    let _ = imports::select_bitmap(dc, DEFAULT_BITMAP as usize);
    let _ = imports::delete_object(dc);
    let _ = imports::delete_object(view);
    answer
}

/// SetDIBitsToDevice: the DIB's scan lines `start` to `start + lines` (bottom-up: from the bottom)
/// that the rectangle at (`x_src`, `y_src`) of the DIB (from its bottom left, for a bottom-up one)
/// covers, drawn at (`x`, `y`); see the module notes for the answer.
///
/// # Safety
///
/// `bits` holds the scan lines handed, `info` is the caller's BITMAPINFO.
#[unsafe(export_name = "f2k_export_SetDIBitsToDevice")]
pub unsafe extern "system" fn set_di_bits_to_device(
    dc: usize,
    x: i32,
    y: i32,
    width: u32,
    height: u32,
    x_src: i32,
    y_src: i32,
    start: u32,
    lines: u32,
    bits: usize,
    info: usize,
    _usage: u32,
) -> i32 {
    if lines == 0 || bits == 0 {
        return 0;
    }
    // SAFETY: the caller's BITMAPINFO.
    let Some(dib) = (unsafe { Dib::read(info) }) else {
        return 0;
    };
    let (width, height) = (width as i32, height as i32);
    let (start, lines) = (start as i32, lines as i32);
    let first = y_src.max(start);
    let end = y_src
        .saturating_add(height)
        .min(start.saturating_add(lines));
    if end <= first {
        return 0;
    }
    let (to_y, from_y) = if dib.top_down() {
        (y + first - y_src, first - start)
    } else {
        (y + y_src + height - end, start + lines - end)
    };
    let drawn = with_view(&dib, bits, lines, |source| {
        answered(imports::bit_blt(
            dc,
            (x, to_y, width, end - first),
            source,
            (x_src, from_y),
            SRCCOPY,
        ))
    });
    match drawn {
        Some(Some(())) => end - start,
        _ => 0,
    }
}

/// StretchDIBits: the DIB's rectangle at (`x_src`, `y_src`) (from its bottom left, for a bottom-up
/// one), `src_width` by `src_height`, stretched onto the DC's at (`x`, `y`), `width` by `height`,
/// by the raster operation; the DIB's height answered (0 with the last error when nothing was
/// drawn).
///
/// # Safety
///
/// `bits` holds the DIB's rows, `info` is the caller's BITMAPINFO.
#[unsafe(export_name = "f2k_export_StretchDIBits")]
pub unsafe extern "system" fn stretch_di_bits(
    dc: usize,
    x: i32,
    y: i32,
    width: i32,
    height: i32,
    x_src: i32,
    y_src: i32,
    src_width: i32,
    src_height: i32,
    bits: usize,
    info: usize,
    _usage: u32,
    rop: u32,
) -> i32 {
    if bits == 0 {
        return 0;
    }
    // SAFETY: the caller's BITMAPINFO.
    let Some(dib) = (unsafe { Dib::read(info) }) else {
        return 0;
    };
    let rows = dib.height();
    let from_y = if dib.top_down() {
        y_src
    } else {
        rows - y_src - src_height
    };
    let drawn = with_view(&dib, bits, rows, |source| {
        answered(imports::stretch_blt(
            dc,
            (x, y, width, height),
            source,
            (x_src, from_y, src_width, src_height),
            rop,
        ))
    });
    match drawn {
        Some(Some(())) => rows,
        _ => 0,
    }
}

// --- Blits ---------------------------------------------------------------------------------------

/// BitBlt: see kernel/src/win32k/blit.rs; FALSE without an error for a raster operation that reads
/// a source when there is no source DC, with the service's error for a DC that is none.
#[unsafe(export_name = "f2k_export_BitBlt")]
pub extern "system" fn bit_blt(
    dc: usize,
    x: i32,
    y: i32,
    width: i32,
    height: i32,
    source: usize,
    x_src: i32,
    y_src: i32,
    rop: u32,
) -> u32 {
    if source == 0 && rop_uses_source(rop) {
        return 0;
    }
    answered(imports::bit_blt(
        dc,
        (x, y, width, height),
        source,
        (x_src, y_src),
        rop,
    ))
    .map_or(0, |()| 1)
}

/// StretchBlt: BitBlt's, the source's rectangle stretched onto the destination's under the
/// destination DC's stretch mode.
#[unsafe(export_name = "f2k_export_StretchBlt")]
pub extern "system" fn stretch_blt(
    dc: usize,
    x: i32,
    y: i32,
    width: i32,
    height: i32,
    source: usize,
    x_src: i32,
    y_src: i32,
    src_width: i32,
    src_height: i32,
    rop: u32,
) -> u32 {
    if source == 0 && rop_uses_source(rop) {
        return 0;
    }
    answered(imports::stretch_blt(
        dc,
        (x, y, width, height),
        source,
        (x_src, y_src, src_width, src_height),
        rop,
    ))
    .map_or(0, |()| 1)
}

/// SetStretchBltMode: the DC's stretch mode set (any value, as Windows 2000 takes it), the one it
/// had answered; 0 with the last error for a DC that is none.
#[unsafe(export_name = "f2k_export_SetStretchBltMode")]
pub extern "system" fn set_stretch_blt_mode(dc: usize, mode: i32) -> i32 {
    answered(imports::set_dc_dword(dc, DC_STRETCH_MODE, mode as u32)).map_or(0, |mode| mode as i32)
}

/// GetStretchBltMode: the DC's stretch mode (BLACKONWHITE for a new DC).
#[unsafe(export_name = "f2k_export_GetStretchBltMode")]
pub extern "system" fn get_stretch_blt_mode(dc: usize) -> i32 {
    answered(imports::dc_dword(dc, DC_STRETCH_MODE)).map_or(0, |mode| mode as i32)
}

// --- Pattern brushes -----------------------------------------------------------------------------

/// CreatePatternBrush: a brush of the bitmap's pixels (up to 8 by 8 of them), which it keeps;
/// NULL with ERROR_INVALID_HANDLE for a handle that names no bitmap.
#[unsafe(export_name = "f2k_export_CreatePatternBrush")]
pub extern "system" fn create_pattern_brush(bitmap: usize) -> usize {
    answered(imports::create_pattern_brush(bitmap)).map_or(0, |brush| brush as usize)
}

/// A POINT, as the brush origin's calls take one.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Point {
    x: i32,
    y: i32,
}

/// SetBrushOrgEx: the DC's brush origin set, the one it had into `previous` (when given); FALSE
/// with the last error for a DC that is none.
///
/// # Safety
///
/// `previous`, when not null, a POINT's room.
#[unsafe(export_name = "f2k_export_SetBrushOrgEx")]
pub unsafe extern "system" fn set_brush_org_ex(
    dc: usize,
    x: i32,
    y: i32,
    previous: *mut u8,
) -> u32 {
    let Some(old_x) = answered(imports::set_dc_dword(dc, DC_BRUSH_ORG_X, x as u32)) else {
        return 0;
    };
    let Some(old_y) = answered(imports::set_dc_dword(dc, DC_BRUSH_ORG_Y, y as u32)) else {
        return 0;
    };
    if !previous.is_null() {
        let point = Point {
            x: old_x as i32,
            y: old_y as i32,
        };
        // SAFETY: the caller's POINT's room.
        unsafe { (previous as *mut Point).write_unaligned(point) };
    }
    1
}

/// GetBrushOrgEx: the DC's brush origin into `point`; FALSE with the last error for a DC that is
/// none.
///
/// # Safety
///
/// `point`, when not null, a POINT's room.
#[unsafe(export_name = "f2k_export_GetBrushOrgEx")]
pub unsafe extern "system" fn get_brush_org_ex(dc: usize, point: *mut u8) -> u32 {
    let Some(x) = answered(imports::dc_dword(dc, DC_BRUSH_ORG_X)) else {
        return 0;
    };
    let Some(y) = answered(imports::dc_dword(dc, DC_BRUSH_ORG_Y)) else {
        return 0;
    };
    if !point.is_null() {
        let at = Point {
            x: x as i32,
            y: y as i32,
        };
        // SAFETY: the caller's POINT's room.
        unsafe { (point as *mut Point).write_unaligned(at) };
    }
    1
}

// --- Object types --------------------------------------------------------------------------------

/// GetObjectType: the kind of object `object` is: a global object's by its handle, a process's
/// object's by its handle once the kernel finds it (0 for one deleted), a DC's OBJ_DC or OBJ_MEMDC
/// (0 for one deleted); 0 with ERROR_INVALID_HANDLE for NULL, and 0 with the last error untouched
/// for any other handle that names nothing.
#[unsafe(export_name = "f2k_export_GetObjectType")]
pub extern "system" fn get_object_type(object: usize) -> u32 {
    if object == 0 {
        return failed(ERROR_INVALID_HANDLE).unwrap_or(0);
    }
    let handle = object as u32;
    if let Some(kind) = global_object_kind(handle) {
        return kind;
    }
    match object_of(handle) {
        Some((kind, _)) => match imports::object(object, 0, Caller::NONE) {
            Ok(_) => kind,
            Err(_) => 0,
        },
        None => imports::dc_dword(object, DC_OBJECT_TYPE).unwrap_or(0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn colors(bpp: u32, table: &[u32]) -> Colors {
        let mut colors = Colors::default_of(bpp);
        colors.table[..table.len()].copy_from_slice(table);
        colors
    }

    /// GetDIBits' conversions of the dibits capture's 32-bit row: as 16 (5-5-5), 8 (the system
    /// palette), 4 (the VGA's) and 1 bit (black and white).
    #[test]
    fn rows_convert_to_each_depth() {
        let top = [0xFF0000u32, 0x00FF00, 0x0000FF, 0xFFFFFF];
        let bottom = [0x000000u32, 0x808080, 0xC0C0C0, 0x800000];
        let row_of = |pixels: &[u32]| {
            pixels
                .iter()
                .flat_map(|pixel| pixel.to_le_bytes())
                .collect::<std::vec::Vec<u8>>()
        };
        let from = Colors::default_of(32);
        let run = |pixels: &[u32], bpp: u32| {
            let mut out = std::vec![0u8; 8];
            let row = row_of(pixels);
            convert_row(
                Some(&row),
                &from,
                &mut out,
                &Colors::default_of(bpp),
                4,
                None,
            );
            out
        };
        assert_eq!(
            run(&top, 16),
            [0x00, 0x7C, 0xE0, 0x03, 0x1F, 0x00, 0xFF, 0x7F]
        );
        assert_eq!(
            run(&bottom, 16),
            [0x00, 0x00, 0x10, 0x42, 0x18, 0x63, 0x00, 0x40]
        );
        assert_eq!(run(&top, 8)[..4], [0xF9, 0xFA, 0xFC, 0xFF]);
        assert_eq!(run(&bottom, 8)[..4], [0x00, 0xA4, 0x07, 0x01]);
        assert_eq!(run(&top, 4)[..2], [0x9A, 0xCF]);
        assert_eq!(run(&bottom, 4)[..2], [0x07, 0x81]);
        assert_eq!(run(&top, 1)[0], 0x10);
        assert_eq!(run(&bottom, 1)[0], 0x60);
    }

    /// SetDIBits into a monochrome bitmap: only the DC's background color (white) is 1.
    #[test]
    fn colors_go_to_monochrome_by_the_background() {
        let pixels = [
            0xFFFFFFu32,
            0x000000,
            0xFF0000,
            0x00FF00,
            0x0000FF,
            0x808080,
            0xC0C0C0,
            0x00FFFF,
        ];
        let row: std::vec::Vec<u8> = pixels
            .iter()
            .flat_map(|pixel| pixel.to_le_bytes())
            .collect();
        let mut out = [0u8; 2];
        convert_row(
            Some(&row),
            &Colors::default_of(32),
            &mut out,
            &Colors::default_of(1),
            8,
            Some(0xFFFFFF),
        );
        assert_eq!(out[0], 0x80);
    }

    /// An 8-bit DIB's table colors a 32-bit row: the dibits capture's navy, olive, teal, purple.
    #[test]
    fn a_tables_colors_convert() {
        let from = colors(8, &[0x000080, 0x808000, 0x008080, 0x800080]);
        let mut out = [0u8; 16];
        convert_row(
            Some(&[0, 1, 2, 3]),
            &from,
            &mut out,
            &Colors::default_of(32),
            4,
            None,
        );
        assert_eq!(
            out,
            [0x80, 0, 0, 0, 0, 0x80, 0x80, 0, 0x80, 0x80, 0, 0, 0x80, 0, 0x80, 0]
        );
        let mut out = [0u8; 4];
        convert_row(None, &from, &mut out, &Colors::default_of(32), 1, None);
        assert_eq!(
            out,
            [0x80, 0, 0, 0],
            "the default bitmap's 0: the table's first"
        );
    }
}
