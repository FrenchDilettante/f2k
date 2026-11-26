//! Bitmaps: win32k's bitmap objects, the surface a memory DC draws on, and the services that blit
//! between DCs (BitBlt, StretchBlt) and make a pattern brush of a bitmap.
//!
//! A bitmap is an object of the object manager ([`crate::ob`]'s Bitmap type), its body a
//! [`Bitmap`]: its description ([`rtl::dib::BitmapDesc`]), which says where its pixels are in its
//! owner's memory and how they are laid out. gdi32 makes that memory (a block of the process
//! heap: a DIB section's bits are memory the program writes itself, as Windows 2000's are) and
//! hands the description to NtGdiCreateBitmap; gdi32's GetDIBits and SetDIBits read and write the
//! pixels themselves, and the kernel reaches them through its fault-tolerant copies
//! ([`UserBits`]) when a DC draws, always from a service of the owner process (a memory DC and its
//! bitmaps are the process's own objects), and never holding the directory. Its creator's process
//! holds it through an entry of the GDI handle table ([`super::gdi`]), as a brush is held
//! ([`super::brush`]), the handle carrying the bitmap kind in its high word
//! ([`rtl::gdi::object_handle`]). Beside the bitmap objects there is the
//! default bitmap ([`rtl::gdi::DEFAULT_BITMAP`]): the 1 by 1 monochrome bitmap every new memory DC
//! holds, a global object with no memory (its pixel reads as 0 and takes no writes).
//!
//! A memory DC ([`super::dc::Dc::memory`]) draws on its selected bitmap: [`with_surface`] hands
//! the drawing services the surface a DC draws on, the screen's or a [`BitmapSurface`] over the
//! selected bitmap's pixels. A bitmap is selected into one DC at a time: selecting one another DC
//! holds answers NULL without an error, as Windows 2000's SelectObject does, and deleting a bitmap
//! a DC holds fails.
//!
//! The services (F2K's argument lists, see [`crate::win32k`]):
//!
//! - NtGdiCreateBitmap(ptr Desc, ptr<u32> Bitmap): a bitmap of the description at `Desc`, its
//!   handle in the calling process; STATUS_INVALID_PARAMETER for a description that holds no bitmap
//!   (no pixels, a depth that is none, rows shorter than the width);
//! - NtGdiSelectBitmap(handle Dc, handle Bitmap, ptr<u32> Previous): the bitmap selected into the
//!   memory DC, the one it replaces answered (0 when another DC holds it); STATUS_INVALID_PARAMETER
//!   for a DC that is no memory DC;
//! - NtGdiBitBlt(handle Dc, i32 X, i32 Y, i32 Width, i32 Height, handle Source, i32 XSrc, i32 YSrc,
//!   u32 Rop) and NtGdiStretchBlt(..., i32 WidthSrc, i32 HeightSrc, u32 Rop): the blit
//!   ([`super::blit`]), in each DC's logical coordinates; the source DC is read only when the
//!   raster operation reads a source; the null brush paints nothing where the operation reads the
//!   pattern;
//! - NtGdiCreatePatternBrushInternal(handle Bitmap, ptr<u32> Brush): a pattern brush of the
//!   bitmap's top left 8 by 8 pixels (the brush keeps them: the bitmap may go), a monochrome
//!   bitmap's as its bits, which the DC's text and background colors paint;
//! - NtGdiExtGetObjectW(handle Object, u32 Count, ptr Buffer, ptr<u32> Size): a bitmap's
//!   description, a brush's LOGBRUSH, or a font's LOGFONTW ([`super::fonts`]), at most `Count`
//!   bytes of it into `Buffer` (none: its size alone).

use rtl::dib::*;
use rtl::gdi::*;
use rtl::pod::Pod;

use super::blit::{blit, Blit, Source};
use super::dc::Dc;
use super::raster::{screen_rgb, FormatKey, PatternBits, Surface};
use crate::nt::call::{Handle, NtCall, NtResult, UserAddr, UserPtr};
use crate::status::*;

/// A bitmap object's body: its description.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bitmap {
    pub desc: BitmapDesc,
}

impl Bitmap {
    /// A record holding no bitmap (a pool's fresh record).
    pub const fn none() -> Self {
        Bitmap {
            desc: BitmapDesc::DEFAULT,
        }
    }
}

/// Whether `desc` describes a bitmap NtGdiCreateBitmap takes: a positive extent, a depth that is
/// one, rows at least as long as the width (a device-dependent bitmap's exactly its words, a DIB
/// section's its dwords), and no more colors than the depth has room for.
pub fn valid(desc: &BitmapDesc) -> bool {
    let sized = desc.width > 0
        && desc.height > 0
        && desc.width <= 0x0100_0000
        && desc.height <= 0x0100_0000
        && is_dib_depth(desc.bpp);
    if !sized || desc.color_count as usize > table_size(desc.bpp) {
        return false;
    }
    if desc.is_dib() {
        desc.stride >= dword_stride(desc.width, desc.bpp)
            && desc.flags & !(DESC_DIB | DESC_TOP_DOWN | DESC_BITFIELDS) == 0
    } else {
        desc.stride == word_stride(desc.width, desc.bpp) && desc.flags == 0
    }
}

/// Where a bitmap surface's pixels are read and written: by address.
pub trait BitsMemory {
    /// Read `bytes.len()` bytes at `address`; whether they could be.
    fn read(&mut self, address: u32, bytes: &mut [u8]) -> bool;
    /// Write `bytes` at `address`; whether they could be.
    fn write(&mut self, address: u32, bytes: &[u8]) -> bool;
}

/// The calling process's memory, through the kernel's fault-tolerant copies: a bitmap's owner's
/// (its services run in it). An address that is not mapped fails the copy: the pixel reads as 0,
/// a write is lost.
pub struct UserBits;

impl BitsMemory for UserBits {
    fn read(&mut self, address: u32, bytes: &mut [u8]) -> bool {
        crate::user::syscall::read_user(address, bytes).is_ok()
    }

    fn write(&mut self, address: u32, bytes: &[u8]) -> bool {
        crate::user::syscall::write_user(address, bytes).is_ok()
    }
}

/// A bitmap's pixels as a surface: its description, its colors (a DIB section's table, read once
/// from its owner's memory, or the default table of its depth), and the memory it is in.
pub struct BitmapSurface<M: BitsMemory> {
    desc: BitmapDesc,
    table: [u32; 256],
    memory: M,
}

impl<M: BitsMemory> BitmapSurface<M> {
    /// The surface of the bitmap `desc` describes, its pixels in `memory`.
    pub fn new(desc: BitmapDesc, mut memory: M) -> Self {
        let mut table = [0u32; 256];
        let size = table_size(desc.bpp);
        if desc.is_dib() && size != 0 {
            let count = (desc.color_count as usize).min(size);
            let mut quads = [0u8; 4 * 256];
            if desc.colors != 0 && memory.read(desc.colors, &mut quads[..4 * count]) {
                let (quads, _) = quads[..4 * count].as_chunks::<4>();
                for (entry, &quad) in table.iter_mut().zip(quads) {
                    *entry = rgb_of_quad(quad);
                }
            }
        } else {
            for (index, entry) in table.iter_mut().take(size).enumerate() {
                *entry = match desc.bpp {
                    1 => MONO_COLORS[index],
                    4 => VGA_COLORS[index],
                    _ => default_color_8(index),
                };
            }
        }
        BitmapSurface {
            desc,
            table,
            memory,
        }
    }

    fn colors(&self) -> Format<'_> {
        Format {
            bpp: self.desc.bpp,
            table: &self.table[..table_size(self.desc.bpp)],
            masks: self.desc.pixel_masks(),
        }
    }

    /// The pixel at (`x`, `y`)'s first byte's address, its bytes, and its place in a byte (the
    /// column of a narrow pixel within its byte).
    fn place(&self, x: i32, y: i32) -> (u32, usize, usize) {
        let bpp = self.desc.bpp;
        let bit = x as u32 * bpp;
        let address = self
            .desc
            .bits
            .wrapping_add(self.desc.row_offset(y))
            .wrapping_add(bit / 8);
        if bpp < 8 {
            (address, 1, ((bit % 8) / bpp) as usize)
        } else {
            (address, (bpp / 8) as usize, 0)
        }
    }
}

impl<M: BitsMemory> Surface for BitmapSurface<M> {
    fn extent(&self) -> (i32, i32) {
        (self.desc.width, self.desc.height)
    }

    fn format(&self) -> FormatKey {
        FormatKey {
            bpp: self.desc.bpp,
            masks: self.desc.pixel_masks(),
            table: if self.desc.is_dib() {
                self.desc.colors
            } else {
                0
            },
        }
    }

    fn is_mono(&self) -> bool {
        self.desc.is_mono()
    }

    fn load(&mut self, x: i32, y: i32) -> u32 {
        if self.desc.bits == 0 {
            return 0;
        }
        let (address, bytes, column) = self.place(x, y);
        let mut buffer = [0u8; 4];
        if !self.memory.read(address, &mut buffer[..bytes]) {
            return 0;
        }
        get_packed(&buffer[..bytes], column, self.desc.bpp)
    }

    fn store(&mut self, x: i32, y: i32, pixel: u32) {
        if self.desc.bits == 0 {
            return;
        }
        let (address, bytes, column) = self.place(x, y);
        let mut buffer = [0u8; 4];
        if self.desc.bpp < 8 && !self.memory.read(address, &mut buffer[..1]) {
            return;
        }
        set_packed(&mut buffer[..bytes], column, self.desc.bpp, pixel);
        self.memory.write(address, &buffer[..bytes]);
    }

    fn rgb(&self, pixel: u32) -> u32 {
        self.colors().rgb(pixel)
    }

    fn pixel(&self, rgb: u32) -> u32 {
        self.colors().pixel(rgb)
    }
}

/// The surface of the bitmap a memory DC holds.
pub fn bitmap_surface(dc: &Dc) -> BitmapSurface<UserBits> {
    BitmapSurface::new(desc_of(dc.bitmap_object), UserBits)
}

/// Run `f` against the surface `dc` draws on: a memory DC's bitmap, or the screen once the
/// graphics mode is set (none before it).
pub fn with_surface<R>(dc: &Dc, f: impl FnOnce(&mut dyn Surface) -> R) -> Option<R> {
    if dc.memory {
        let mut surface = bitmap_surface(dc);
        Some(f(&mut surface))
    } else {
        super::dc::with_screen(|screen| f(screen))
    }
}

/// Run `f` against the surface `destination` draws on and the source `source` reads from (the
/// destination itself when both DCs are the screen's or hold the same bitmap).
fn with_two<R>(
    destination: &Dc,
    source: Option<&Dc>,
    f: impl FnOnce(&mut dyn Surface, Source) -> R,
) -> Option<R> {
    let Some(source) = source else {
        return with_surface(destination, |surface| f(surface, Source::None));
    };
    let same = destination.memory == source.memory
        && (!destination.memory
            || (destination.bitmap == source.bitmap
                && destination.bitmap_object == source.bitmap_object));
    if same {
        return with_surface(destination, |surface| f(surface, Source::Same));
    }
    match (destination.memory, source.memory) {
        (true, true) => {
            let mut to = bitmap_surface(destination);
            let mut from = bitmap_surface(source);
            Some(f(&mut to, Source::Other(&mut from)))
        }
        (true, false) => {
            let mut to = bitmap_surface(destination);
            super::dc::with_screen(|screen| f(&mut to, Source::Other(screen)))
        }
        _ => {
            let mut from = bitmap_surface(source);
            super::dc::with_screen(|screen| f(screen, Source::Other(&mut from)))
        }
    }
}

// --- The services --------------------------------------------------------------------------------

/// NtGdiCreateBitmap(Desc, Bitmap): see the module notes.
pub fn create_bitmap(call: &mut NtCall, desc: UserAddr, out: UserPtr<u32>) -> NtResult {
    let desc = desc.cast::<BitmapDesc>().read()?;
    if !valid(&desc) {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let handle = publish_bitmap(call, Bitmap { desc })?;
    if out.write(handle).is_err() {
        close_handle(call, handle);
        return Err(STATUS_ACCESS_VIOLATION);
    }
    Ok(STATUS_SUCCESS)
}

/// NtGdiSelectBitmap(Dc, Bitmap, Previous): see the module notes.
pub fn select_bitmap(call: &mut NtCall, dc: Handle, bitmap: Handle, out: UserPtr<u32>) -> NtResult {
    let (reference, state) = super::dc::dc_of(call, dc)?;
    if !state.memory {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let (object, desc) = bitmap_of(call, bitmap)?;
    if let Some(object) = object {
        if selected_elsewhere(object, &reference) {
            out.write(0)?;
            return Ok(STATUS_SUCCESS);
        }
    }
    drop(reference);
    let previous = super::dc::update_dc(call, dc, |dc| {
        dc.select_bitmap(bitmap.raw(), object, desc.width, desc.height)
    })?;
    out.write(previous)?;
    Ok(STATUS_SUCCESS)
}

/// NtGdiBitBlt(Dc, X, Y, Width, Height, Source, XSrc, YSrc, Rop): StretchBlt's, the source's
/// extent the destination's.
#[allow(clippy::too_many_arguments)]
pub fn bit_blt(
    call: &mut NtCall,
    dc: Handle,
    x: i32,
    y: i32,
    width: i32,
    height: i32,
    source: Handle,
    source_x: i32,
    source_y: i32,
    rop: u32,
) -> NtResult {
    stretch_blt(
        call, dc, x, y, width, height, source, source_x, source_y, width, height, rop,
    )
}

/// NtGdiStretchBlt(Dc, X, Y, Width, Height, Source, XSrc, YSrc, WidthSrc, HeightSrc, Rop): see
/// the module notes.
#[allow(clippy::too_many_arguments)]
pub fn stretch_blt(
    call: &mut NtCall,
    dc: Handle,
    x: i32,
    y: i32,
    width: i32,
    height: i32,
    source: Handle,
    source_x: i32,
    source_y: i32,
    source_width: i32,
    source_height: i32,
    rop: u32,
) -> NtResult {
    let (_reference, destination) = super::dc::dc_of(call, dc)?;
    let source_dc = if rop_uses_source(rop) {
        Some(super::dc::dc_of(call, source)?)
    } else {
        None
    };
    let source = source_dc.as_ref().map(|(_, dc)| &**dc);
    let pattern = destination.brush_fill.pattern(
        destination.text_color,
        destination.bk_color,
        destination.pattern_origin(),
        super::display::sys_color,
    );
    if pattern.is_none() && rop_uses_pattern(rop) {
        return Ok(STATUS_SUCCESS);
    }
    let (x, y) = destination.screen_point(x, y);
    let (source_x, source_y) = source.map_or((0, 0), |dc| dc.screen_point(source_x, source_y));
    let job = Blit {
        x,
        y,
        width,
        height,
        source_x,
        source_y,
        source_width,
        source_height,
        clip: destination.clip(),
        rop,
        mode: destination.stretch_mode,
        text: screen_rgb(destination.text_color),
        background: screen_rgb(destination.bk_color),
        source_background: source.map_or(0, |dc| screen_rgb(dc.bk_color)),
    };
    with_two(&destination, source, |surface, source| {
        blit(surface, source, pattern.as_ref(), &job)
    });
    Ok(STATUS_SUCCESS)
}

/// NtGdiCreatePatternBrushInternal(Bitmap, Brush): see the module notes.
pub fn create_pattern_brush(call: &mut NtCall, bitmap: Handle, out: UserPtr<u32>) -> NtResult {
    let (_, desc) = bitmap_of(call, bitmap)?;
    let mut surface = BitmapSurface::new(desc, UserBits);
    let mut bits = PatternBits {
        width: desc.width.min(8) as u8,
        height: desc.height.min(8) as u8,
        mono: desc.is_mono(),
        pixels: [0; 64],
    };
    for y in 0..bits.height as i32 {
        for x in 0..bits.width as i32 {
            let pixel = surface.load(x, y);
            bits.pixels[(y * 8 + x) as usize] = if bits.mono {
                pixel & 1
            } else {
                surface.rgb(pixel)
            };
        }
    }
    super::brush::create_brush(
        call,
        super::brush::Brush {
            fill: super::brush::Fill::Pattern(bits),
            bitmap: bitmap.raw(),
        },
        out,
    )
}

/// NtGdiExtGetObjectW(Object, Count, Buffer, Size): see the module notes.
pub fn ext_get_object_w(
    call: &mut NtCall,
    object: Handle,
    count: u32,
    buffer: UserAddr,
    out: UserPtr<u32>,
) -> NtResult {
    let mut bytes = [0u8; 64];
    let length = match object_kind(object.raw()) {
        Some(OBJ_BITMAP) => {
            let (_, desc) = bitmap_of(call, object)?;
            let answer = desc.as_bytes();
            bytes[..answer.len()].copy_from_slice(answer);
            answer.len()
        }
        Some(OBJ_BRUSH) if global_brush(object.raw()).is_none() => {
            let brush = super::brush::brush_of(call, object)?;
            let answer = brush.log_brush();
            let answer = answer.as_bytes();
            bytes[..answer.len()].copy_from_slice(answer);
            answer.len()
        }
        _ => return super::fonts::ext_get_object_w(call, object, count, buffer, out),
    };
    let written = if buffer.is_null() {
        length
    } else {
        let written = length.min(count as usize);
        buffer.write(&bytes[..written])?;
        written
    };
    out.write(written as u32)?;
    Ok(STATUS_SUCCESS)
}

// --- The target's side: the objects --------------------------------------------------------------

/// The bitmap `handle` names: its object (none for the default bitmap) and its description;
/// STATUS_INVALID_HANDLE for a handle that names no bitmap of the calling process.
#[cfg(target_arch = "x86")]
pub fn bitmap_of(
    _call: &mut NtCall,
    handle: Handle,
) -> Result<(Option<crate::ob::ObjectId>, BitmapDesc), NtStatus> {
    if handle.raw() == DEFAULT_BITMAP {
        return Ok((None, BitmapDesc::DEFAULT));
    }
    let reference = super::gdi::reference(handle.raw(), OBJ_BITMAP).ok_or(STATUS_INVALID_HANDLE)?;
    let id = reference.id();
    let desc = crate::ob::locked(|directory| directory.bitmap(id).map(|bitmap| bitmap.desc))
        .ok_or(STATUS_INVALID_HANDLE)?;
    Ok((Some(id), desc))
}

/// The description of the bitmap object `object` (the default bitmap's for none, or for one that
/// is gone).
#[cfg(target_arch = "x86")]
fn desc_of(object: Option<crate::ob::ObjectId>) -> BitmapDesc {
    object
        .and_then(|id| {
            crate::ob::locked(|directory| directory.bitmap(id).map(|bitmap| bitmap.desc))
        })
        .unwrap_or(BitmapDesc::DEFAULT)
}

/// Whether a DC other than the one `reference` holds selects the bitmap `object`.
#[cfg(target_arch = "x86")]
fn selected_elsewhere(object: crate::ob::ObjectId, reference: &crate::ob::ObRef) -> bool {
    let dc = reference.id();
    crate::ob::locked(|directory| directory.bitmap_selected(object, Some(dc)))
}

/// A bitmap of state `bitmap` made, its GDI handle the calling process's ([`super::gdi`]);
/// STATUS_INSUFFICIENT_RESOURCES when the bitmaps' pool or the GDI table is full.
#[cfg(target_arch = "x86")]
fn publish_bitmap(_call: &mut NtCall, bitmap: Bitmap) -> Result<u32, NtStatus> {
    let id = crate::ob::locked(|directory| directory.create_bitmap(bitmap))
        .ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
    super::gdi::insert(id).ok_or(STATUS_INSUFFICIENT_RESOURCES)
}

/// Delete the calling process's bitmap `handle` (one this service just made).
#[cfg(target_arch = "x86")]
fn close_handle(_call: &mut NtCall, handle: u32) {
    super::gdi::delete(handle, OBJ_BITMAP);
}

/// DeleteObject of a bitmap: the calling process's bitmap `handle` deleted; STATUS_INVALID_HANDLE
/// for one that names no bitmap, STATUS_CANNOT_DELETE for a bitmap a DC holds (Windows 2000's
/// DeleteObject fails then).
#[cfg(target_arch = "x86")]
pub fn delete_bitmap(_call: &mut NtCall, handle: u32) -> Result<(), NtStatus> {
    let reference = super::gdi::reference(handle, OBJ_BITMAP).ok_or(STATUS_INVALID_HANDLE)?;
    let id = reference.id();
    if crate::ob::locked(|directory| directory.bitmap_selected(id, None)) {
        return Err(STATUS_CANNOT_DELETE);
    }
    drop(reference);
    if super::gdi::delete(handle, OBJ_BITMAP) {
        Ok(())
    } else {
        Err(STATUS_INVALID_HANDLE)
    }
}

// The host builds have no processes: no bitmap object is made or found (the host tests drive the
// surfaces and the blits themselves).

#[cfg(not(target_arch = "x86"))]
pub fn bitmap_of(
    _: &mut NtCall,
    handle: Handle,
) -> Result<(Option<crate::ob::ObjectId>, BitmapDesc), NtStatus> {
    if handle.raw() == DEFAULT_BITMAP {
        Ok((None, BitmapDesc::DEFAULT))
    } else {
        Err(STATUS_INVALID_HANDLE)
    }
}

#[cfg(not(target_arch = "x86"))]
fn desc_of(_: Option<crate::ob::ObjectId>) -> BitmapDesc {
    BitmapDesc::DEFAULT
}

#[cfg(not(target_arch = "x86"))]
fn selected_elsewhere(_: crate::ob::ObjectId, _: &()) -> bool {
    false
}

#[cfg(not(target_arch = "x86"))]
fn publish_bitmap(_: &mut NtCall, _: Bitmap) -> Result<u32, NtStatus> {
    Err(STATUS_NOT_IMPLEMENTED)
}

#[cfg(not(target_arch = "x86"))]
fn close_handle(_: &mut NtCall, _: u32) {}

#[cfg(test)]
mod tests {
    use std::vec::Vec;

    use super::*;

    /// A process's memory: `bytes` from `base`.
    struct Memory {
        base: u32,
        bytes: Vec<u8>,
    }

    impl BitsMemory for &mut Memory {
        fn read(&mut self, address: u32, bytes: &mut [u8]) -> bool {
            let Some(at) = address.checked_sub(self.base) else {
                return false;
            };
            let at = at as usize;
            match self.bytes.get(at..at + bytes.len()) {
                Some(found) => {
                    bytes.copy_from_slice(found);
                    true
                }
                None => false,
            }
        }

        fn write(&mut self, address: u32, bytes: &[u8]) -> bool {
            let Some(at) = address.checked_sub(self.base) else {
                return false;
            };
            let at = at as usize;
            match self.bytes.get_mut(at..at + bytes.len()) {
                Some(found) => {
                    found.copy_from_slice(bytes);
                    true
                }
                None => false,
            }
        }
    }

    fn desc(width: i32, height: i32, bpp: u32, flags: u32, colors: u32) -> BitmapDesc {
        let stride = if flags & DESC_DIB != 0 {
            dword_stride(width, bpp)
        } else {
            word_stride(width, bpp)
        };
        BitmapDesc {
            width,
            height,
            bpp,
            flags,
            masks: [0; 3],
            stride,
            bits: 0x1_0000 + 1024,
            colors: 0x1_0000,
            color_count: colors,
            block: 0x1_0000,
        }
    }

    /// The dibsect capture's 32-bit DIB sections: GetPixel reads row y from the top, whichever way
    /// the rows go, and a pixel past the row is none.
    #[test]
    fn a_32_bit_dib_section_reads_by_rows() {
        for flags in [DESC_DIB | DESC_TOP_DOWN, DESC_DIB] {
            let mut memory = Memory {
                base: 0x1_0000,
                bytes: std::vec![0; 1024 + 48],
            };
            for y in 0..3u32 {
                for x in 0..4u32 {
                    let at = 1024 + (y * 16 + x * 4) as usize;
                    let value = 0x0010_0000 * (y + 1) + 0x100 * (x + 1);
                    memory.bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
                }
            }
            let mut surface = BitmapSurface::new(desc(4, 3, 32, flags, 0), &mut memory);
            let first = colorref_of_rgb(surface.get_pixel(0, 0).unwrap());
            let last = colorref_of_rgb(surface.get_pixel(3, 2).unwrap());
            if flags & DESC_TOP_DOWN != 0 {
                assert_eq!((first, last), (0x0000_0110, 0x0000_0430));
            } else {
                assert_eq!((first, last), (0x0000_0130, 0x0000_0410));
            }
            assert_eq!(surface.get_pixel(4, 0), None);
            surface.store(0, 0, 0);
            surface.store(1, 0, 0);
            drop(surface);
            let row0 = if flags & DESC_TOP_DOWN != 0 { 0 } else { 32 };
            assert_eq!(memory.bytes[1024 + row0..1024 + row0 + 8], [0; 8]);
        }
    }

    /// The dibsect capture's palettized DIB sections: a color goes to the table's nearest entry
    /// (the 8-bit table four colors and zeros), a 1-bit pixel to its bit.
    #[test]
    fn palettized_pixels_take_the_nearest_entry() {
        let mut memory = Memory {
            base: 0x1_0000,
            bytes: std::vec![0; 1024 + 8],
        };
        for (index, rgb) in [0x000000u32, 0xFF0000, 0x00FF00, 0xFFFFFF]
            .iter()
            .enumerate()
        {
            memory.bytes[4 * index..4 * index + 4].copy_from_slice(&quad_of_rgb(*rgb));
        }
        memory.bytes[1024..1032].copy_from_slice(&[0, 1, 2, 3, 3, 2, 1, 0]);
        let mut surface =
            BitmapSurface::new(desc(4, 2, 8, DESC_DIB | DESC_TOP_DOWN, 256), &mut memory);
        assert_eq!(surface.get_pixel(1, 1), Some(0x00FF00));
        surface.put_pixel(0, 0, 0x00FF00);
        surface.put_pixel(2, 1, 0xC01010);
        drop(surface);
        assert_eq!(memory.bytes[1024..1032], [2, 1, 2, 3, 3, 2, 1, 0]);

        let mut memory = Memory {
            base: 0x1_0000,
            bytes: std::vec![0; 1024 + 8],
        };
        memory.bytes[..4].copy_from_slice(&quad_of_rgb(0xFF0000));
        memory.bytes[4..8].copy_from_slice(&quad_of_rgb(0xFFFFFF));
        memory.bytes[1024] = 0xA5;
        memory.bytes[1028] = 0x0F;
        let mut surface =
            BitmapSurface::new(desc(8, 2, 1, DESC_DIB | DESC_TOP_DOWN, 2), &mut memory);
        assert_eq!(surface.get_pixel(0, 0), Some(0xFFFFFF));
        assert_eq!(surface.get_pixel(1, 1), Some(0xFF0000));
        for x in 0..4 {
            surface.put_pixel(x, 0, 0);
        }
        assert!(!surface.is_mono(), "a DIB section has its table");
        drop(surface);
        assert_eq!(memory.bytes[1024], 0x05);
    }

    /// A 16-bit BI_BITFIELDS 5-6-5 pixel: red is F800, 0x808080 is 8410 and reads 0x848284; a
    /// device-dependent bitmap's rows are words, top-down, its 1-bit pixels monochrome.
    #[test]
    fn masked_and_device_dependent_pixels() {
        let mut memory = Memory {
            base: 0x1_0000,
            bytes: std::vec![0; 1024 + 4],
        };
        let mut bitfields = desc(2, 1, 16, DESC_DIB | DESC_BITFIELDS, 0);
        bitfields.masks = [0xF800, 0x07E0, 0x001F];
        let mut surface = BitmapSurface::new(bitfields, &mut memory);
        surface.put_pixel(0, 0, 0xFF0000);
        surface.put_pixel(1, 0, 0x808080);
        assert_eq!(surface.get_pixel(1, 0), Some(0x848284));
        drop(surface);
        assert_eq!(memory.bytes[1024..1028], [0x00, 0xF8, 0x10, 0x84]);

        let mut memory = Memory {
            base: 0x1_0000,
            bytes: std::vec![0; 1024 + 4],
        };
        memory.bytes[1024..1028].copy_from_slice(&[0xA5, 0x00, 0x3C, 0x00]);
        let mut surface = BitmapSurface::new(desc(8, 2, 1, 0, 0), &mut memory);
        assert!(surface.is_mono());
        assert_eq!(surface.load(0, 1), 0);
        assert_eq!(surface.load(2, 1), 1);
        assert_eq!(surface.get_pixel(0, 0), Some(0xFFFFFF));
        assert!(valid(&desc(8, 2, 1, 0, 0)));
        assert!(!valid(&desc(8, 2, 3, 0, 0)), "no such depth");
        assert!(!valid(&desc(0, 2, 1, 0, 0)), "no pixels");
    }

    /// The default bitmap has no memory: its pixel reads 0 and takes no write.
    #[test]
    fn the_default_bitmap_holds_nothing() {
        let mut memory = Memory {
            base: 0x1_0000,
            bytes: Vec::new(),
        };
        let mut surface = BitmapSurface::new(BitmapDesc::DEFAULT, &mut memory);
        surface.store(0, 0, 1);
        assert_eq!(surface.load(0, 0), 0);
        assert_eq!(surface.extent(), (1, 1));
    }
}
