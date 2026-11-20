//! Bitmaps' shared shapes: what gdi32's bitmap calls, user32's bitmap loading and win32k's blits
//! agree on. The public structures as Windows 2000's wingdi.h lays them out on x86 (BITMAP,
//! BITMAPINFOHEADER, DIBSECTION, LOGBRUSH: [`Bitmap`], [`BitmapInfoHeader`], [`DibSection`],
//! [`LogBrush`]), the description of a bitmap object F2K's NtGdiCreateBitmap takes and
//! NtGdiExtGetObjectW answers ([`BitmapDesc`]), and the pixel arithmetic every side shares: rows
//! and their strides, a pixel packed in a row ([`get_packed`], [`set_packed`]), a pixel format's
//! colors ([`Format`]: a color table's nearest entry, BI_BITFIELDS' masks), the default color
//! tables a device-dependent bitmap's pixels and GetDIBits' answers take ([`VGA_COLORS`],
//! [`default_color_8`]), the ternary raster operations ([`rop3`]) and StretchBlt's sampling
//! ([`sample`], [`span`]).
//!
//! A color here is `0x00RRGGBB`, as a 32-bit DIB stores it and the framebuffer takes it (a
//! COLORREF is `0x00BBGGRR`: [`rgb_of_colorref`]).
//!
//! A bitmap's pixels live in its owner's memory: a device-dependent bitmap's rows top-down, each a
//! whole number of words (CreateBitmap's and GetBitmapBits' layout), a DIB section's as its header
//! says, each a whole number of dwords, bottom-up unless its height is negative, its color table
//! (the RGBQUADs, two to the bits per pixel of them for up to 8 bits) beside them. The kernel's
//! bitmap object records where ([`BitmapDesc`]); gdi32 made the memory, and reads and writes it
//! itself for GetDIBits and SetDIBits.

use crate::pod::Pod;

/// GetObjectType's answers for a bitmap and a memory DC (a DC's is [`crate::gdi::OBJ_DC`]).
pub const OBJ_BITMAP: u32 = 7;
pub const OBJ_MEMDC: u32 = 10;

/// BITMAPINFOHEADER's compressions F2K takes: none, and 16- or 32-bit masks (after the header).
pub const BI_RGB: u32 = 0;
pub const BI_BITFIELDS: u32 = 3;

/// The usages a DIB's color table may have: RGBQUADs, or indexes into the DC's palette.
pub const DIB_RGB_COLORS: u32 = 0;
pub const DIB_PAL_COLORS: u32 = 1;

/// CreateDIBitmap's flag: the bitmap initialized from the DIB's bits.
pub const CBM_INIT: u32 = 4;

/// The stretch modes (SetStretchBltMode): the eliminated pixels ANDed (black wins), ORed (white
/// wins), dropped, or averaged (F2K drops them, as COLORONCOLOR does).
pub const BLACKONWHITE: u32 = 1;
pub const WHITEONBLACK: u32 = 2;
pub const COLORONCOLOR: u32 = 3;
pub const HALFTONE: u32 = 4;

/// LOGBRUSH's styles: a solid brush, the null brush, a hatch, a pattern of a bitmap.
pub const BS_SOLID: u32 = 0;
pub const BS_NULL: u32 = 1;
pub const BS_HATCHED: u32 = 2;
pub const BS_PATTERN: u32 = 3;

/// The raster operations that read a source (wingdi.h's ROP3 codes) beside rtl::gdi's PATCOPY,
/// PATINVERT, DSTINVERT, BLACKNESS and WHITENESS.
pub const SRCCOPY: u32 = 0x00CC_0020;
pub const SRCPAINT: u32 = 0x00EE_0086;
pub const SRCAND: u32 = 0x0088_00C6;
pub const SRCINVERT: u32 = 0x0066_0046;
pub const SRCERASE: u32 = 0x0044_0328;
pub const NOTSRCCOPY: u32 = 0x0033_0008;
pub const NOTSRCERASE: u32 = 0x0011_00A6;
pub const MERGECOPY: u32 = 0x00C0_00CA;
pub const MERGEPAINT: u32 = 0x00BB_0226;

/// BITMAP, Windows 2000's (24 bytes): `bits` a pointer, NULL for a device-dependent bitmap.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Bitmap {
    pub kind: i32,
    pub width: i32,
    pub height: i32,
    pub width_bytes: i32,
    pub planes: u16,
    pub bits_pixel: u16,
    pub bits: u32,
}

/// BITMAPINFOHEADER, Windows 2000's (40 bytes).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BitmapInfoHeader {
    pub size: u32,
    pub width: i32,
    pub height: i32,
    pub planes: u16,
    pub bit_count: u16,
    pub compression: u32,
    pub size_image: u32,
    pub x_pels_per_meter: i32,
    pub y_pels_per_meter: i32,
    pub clr_used: u32,
    pub clr_important: u32,
}

/// The size of a BITMAPINFOHEADER: what its `size` field says, and where its color table starts.
pub const HEADER_SIZE: u32 = 40;

/// DIBSECTION, Windows 2000's (84 bytes).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DibSection {
    pub bm: Bitmap,
    pub bmih: BitmapInfoHeader,
    pub bitfields: [u32; 3],
    pub section: u32,
    pub offset: u32,
}

/// LOGBRUSH, Windows 2000's (12 bytes): `hatch` a pattern brush's bitmap's handle.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LogBrush {
    pub style: u32,
    pub color: u32,
    pub hatch: u32,
}

/// [`BitmapDesc`]'s flags: a DIB section (not a device-dependent bitmap), its rows top-down,
/// its pixels laid out by its masks (BI_BITFIELDS).
pub const DESC_DIB: u32 = 1;
pub const DESC_TOP_DOWN: u32 = 2;
pub const DESC_BITFIELDS: u32 = 4;

/// A bitmap object's description, F2K's own: what gdi32 hands NtGdiCreateBitmap and
/// NtGdiExtGetObjectW answers for a bitmap. The pixels are in the owner process's memory: `stride`
/// bytes a row from `bits` (top-down for a device-dependent bitmap; as `flags` says for a DIB
/// section), the color table's `color_count` RGBQUADs at `colors` (a DIB section's of up to 8 bits
/// per pixel; a device-dependent bitmap takes the default tables), all of it inside the heap block
/// at `block`, which gdi32 frees when the bitmap is deleted. The default bitmap has no memory: its
/// `bits` and `block` are 0.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BitmapDesc {
    pub width: i32,
    pub height: i32,
    pub bpp: u32,
    pub flags: u32,
    pub masks: [u32; 3],
    pub stride: u32,
    pub bits: u32,
    pub colors: u32,
    pub color_count: u32,
    pub block: u32,
}

// SAFETY: integers and arrays of them, laid out with no padding (the 16-bit pairs fill a dword),
// and every bit pattern is a value.
unsafe impl Pod for Bitmap {}
// SAFETY: as above.
unsafe impl Pod for BitmapInfoHeader {}
// SAFETY: as above.
unsafe impl Pod for DibSection {}
// SAFETY: as above.
unsafe impl Pod for LogBrush {}
// SAFETY: as above.
unsafe impl Pod for BitmapDesc {}

impl BitmapDesc {
    /// The default bitmap's: 1 by 1, monochrome, device-dependent, no memory.
    pub const DEFAULT: BitmapDesc = BitmapDesc {
        width: 1,
        height: 1,
        bpp: 1,
        flags: 0,
        masks: [0; 3],
        stride: 2,
        bits: 0,
        colors: 0,
        color_count: 0,
        block: 0,
    };

    /// Whether it is a DIB section.
    pub fn is_dib(&self) -> bool {
        self.flags & DESC_DIB != 0
    }

    /// Whether it is a monochrome device-dependent bitmap: one whose pixels take a DC's text and
    /// background colors in a blit (a 1-bit DIB section has its color table instead).
    pub fn is_mono(&self) -> bool {
        self.bpp == 1 && !self.is_dib()
    }

    /// Whether its rows are stored top-down.
    pub fn top_down(&self) -> bool {
        !self.is_dib() || self.flags & DESC_TOP_DOWN != 0
    }

    /// The offset of the row `y` (from the top) from `bits`.
    pub fn row_offset(&self, y: i32) -> u32 {
        let row = if self.top_down() {
            y
        } else {
            self.height - 1 - y
        };
        row as u32 * self.stride
    }

    /// The masks its 16- or 32-bit pixels are laid out by: its own (BI_BITFIELDS), or the
    /// defaults (5-5-5, 8-8-8).
    pub fn pixel_masks(&self) -> [u32; 3] {
        if self.flags & DESC_BITFIELDS != 0 {
            self.masks
        } else {
            default_masks(self.bpp)
        }
    }

    /// Its BITMAP, as GetObject answers it: the bits' address a DIB section's alone.
    pub fn bitmap(&self) -> Bitmap {
        Bitmap {
            kind: 0,
            width: self.width,
            height: self.height,
            width_bytes: word_stride(self.width, self.bpp) as i32,
            planes: 1,
            bits_pixel: self.bpp as u16,
            bits: if self.is_dib() { self.bits } else { 0 },
        }
    }

    /// Its DIBSECTION, as GetObject answers a DIB section's: the header's height positive
    /// whichever way its rows go, its color count two to its bits per pixel (up to 8), its masks
    /// only for BI_BITFIELDS.
    pub fn dib_section(&self) -> DibSection {
        let bitfields = self.flags & DESC_BITFIELDS != 0;
        let colors = table_size(self.bpp) as u32;
        DibSection {
            bm: self.bitmap(),
            bmih: BitmapInfoHeader {
                size: HEADER_SIZE,
                width: self.width,
                height: self.height,
                planes: 1,
                bit_count: self.bpp as u16,
                compression: if bitfields { BI_BITFIELDS } else { BI_RGB },
                size_image: dword_stride(self.width, self.bpp) * self.height as u32,
                x_pels_per_meter: 0,
                y_pels_per_meter: 0,
                clr_used: colors,
                clr_important: colors,
            },
            bitfields: if bitfields { self.masks } else { [0; 3] },
            section: 0,
            offset: 0,
        }
    }
}

/// The bits per pixel a bitmap of `bits` (a plane's bits times the planes) is made at: 1, 4, 8,
/// 16, 24 or 32 (CreateBitmap's rounding up); none past 32 or for none.
pub const fn rounded_bpp(bits: u32) -> Option<u32> {
    Some(match bits {
        1 => 1,
        2..=4 => 4,
        5..=8 => 8,
        9..=16 => 16,
        17..=24 => 24,
        25..=32 => 32,
        _ => return None,
    })
}

/// Whether `bpp` is a DIB's bits per pixel F2K takes.
pub const fn is_dib_depth(bpp: u32) -> bool {
    matches!(bpp, 1 | 4 | 8 | 16 | 24 | 32)
}

/// A row of `width` pixels of `bpp` bits, rounded up to whole words (a device-dependent
/// bitmap's, BITMAP's bmWidthBytes).
pub const fn word_stride(width: i32, bpp: u32) -> u32 {
    ((width as u32 * bpp).div_ceil(16)) * 2
}

/// A row of `width` pixels of `bpp` bits, rounded up to whole dwords (a DIB's).
pub const fn dword_stride(width: i32, bpp: u32) -> u32 {
    ((width as u32 * bpp).div_ceil(32)) * 4
}

/// The entries of the color table a DIB of `bpp` bits has room for: two to the `bpp` up to 8, none
/// past it.
pub const fn table_size(bpp: u32) -> usize {
    if bpp <= 8 {
        1 << bpp
    } else {
        0
    }
}

/// The masks a 16- or 32-bit DIB of BI_RGB is laid out by: 5-5-5 and 8-8-8 (none for another
/// depth).
pub const fn default_masks(bpp: u32) -> [u32; 3] {
    match bpp {
        16 => [0x7C00, 0x03E0, 0x001F],
        24 | 32 => [0x00FF_0000, 0x0000_FF00, 0x0000_00FF],
        _ => [0; 3],
    }
}

/// The pixel at column `x` of a row of `bpp`-bit pixels (bit 7 of a byte its leftmost pixel, a
/// 16- or 32-bit pixel little-endian, a 24-bit pixel its blue byte first); 0 past the row.
pub fn get_packed(row: &[u8], x: usize, bpp: u32) -> u32 {
    let byte = |index: usize| row.get(index).copied().unwrap_or(0) as u32;
    match bpp {
        1 => (byte(x / 8) >> (7 - x % 8)) & 1,
        4 => (byte(x / 2) >> if x % 2 == 0 { 4 } else { 0 }) & 0xF,
        8 => byte(x),
        16 => byte(2 * x) | byte(2 * x + 1) << 8,
        24 => byte(3 * x) | byte(3 * x + 1) << 8 | byte(3 * x + 2) << 16,
        32 => byte(4 * x) | byte(4 * x + 1) << 8 | byte(4 * x + 2) << 16 | byte(4 * x + 3) << 24,
        _ => 0,
    }
}

/// Set the pixel at column `x` of a row of `bpp`-bit pixels to `value` (its low `bpp` bits);
/// nothing past the row.
pub fn set_packed(row: &mut [u8], x: usize, bpp: u32, value: u32) {
    let mut put = |index: usize, mask: u8, bits: u8| {
        if let Some(byte) = row.get_mut(index) {
            *byte = (*byte & !mask) | (bits & mask);
        }
    };
    match bpp {
        1 => {
            let shift = 7 - x % 8;
            put(x / 8, 1 << shift, ((value & 1) as u8) << shift);
        }
        4 => {
            let shift = if x % 2 == 0 { 4 } else { 0 };
            put(x / 2, 0xF << shift, ((value & 0xF) as u8) << shift);
        }
        8 | 16 | 24 | 32 => {
            let bytes = (bpp / 8) as usize;
            for index in 0..bytes {
                put(bytes * x + index, 0xFF, (value >> (8 * index)) as u8);
            }
        }
        _ => {}
    }
}

/// The bits of a pixel of `bpp` bits (all 32 for 32).
pub const fn depth_mask(bpp: u32) -> u32 {
    if bpp >= 32 {
        u32::MAX
    } else {
        (1 << bpp) - 1
    }
}

/// The `0x00RRGGBB` of a COLORREF (`0x00BBGGRR`; its high byte, a palette's flags, set aside).
pub const fn rgb_of_colorref(color: u32) -> u32 {
    ((color & 0xFF) << 16) | (color & 0xFF00) | ((color >> 16) & 0xFF)
}

/// The COLORREF of a `0x00RRGGBB` color.
pub const fn colorref_of_rgb(rgb: u32) -> u32 {
    rgb_of_colorref(rgb)
}

/// The `0x00RRGGBB` of an RGBQUAD's bytes (blue, green, red, reserved).
pub const fn rgb_of_quad(quad: [u8; 4]) -> u32 {
    (quad[2] as u32) << 16 | (quad[1] as u32) << 8 | quad[0] as u32
}

/// The RGBQUAD's bytes of a `0x00RRGGBB` color, its reserved byte 0.
pub const fn quad_of_rgb(rgb: u32) -> [u8; 4] {
    [rgb as u8, (rgb >> 8) as u8, (rgb >> 16) as u8, 0]
}

/// The 16 colors of a 4-bit device-dependent bitmap and GetDIBits' 4-bit table: the VGA's, in
/// Windows 2000's order (dark gray before light gray).
pub const VGA_COLORS: [u32; 16] = [
    0x000000, 0x800000, 0x008000, 0x808000, 0x000080, 0x800080, 0x008080, 0x808080, 0xC0C0C0,
    0xFF0000, 0x00FF00, 0xFFFF00, 0x0000FF, 0xFF00FF, 0x00FFFF, 0xFFFFFF,
];

/// The two colors of a monochrome bitmap and GetDIBits' 1-bit table: black, white.
pub const MONO_COLORS: [u32; 2] = [0x000000, 0xFFFFFF];

/// The system palette's static colors: the first ten and the last ten entries of the 8-bit table.
const STATIC_FIRST: [u32; 10] = [
    0x000000, 0x800000, 0x008000, 0x808000, 0x000080, 0x800080, 0x008080, 0xC0C0C0, 0xC0DCC0,
    0xA6CAF0,
];
const STATIC_LAST: [u32; 10] = [
    0xFFFBF0, 0xA0A0A4, 0x808080, 0xFF0000, 0x00FF00, 0xFFFF00, 0x0000FF, 0xFF00FF, 0x00FFFF,
    0xFFFFFF,
];

/// Entry `index` of the 256 colors of an 8-bit device-dependent bitmap and GetDIBits' 8-bit
/// table: the twenty static colors at either end, and between them the cube whose index's bits
/// 0-2 are the red's top three bits, bits 3-5 the green's, bits 6-7 the blue's (the capture's
/// table: its CRC-32 is D7280939).
pub const fn default_color_8(index: usize) -> u32 {
    match index {
        0..=9 => STATIC_FIRST[index],
        246..=255 => STATIC_LAST[index - 246],
        _ => {
            let index = index as u32;
            ((index & 0x07) << 5) << 16 | ((index & 0x38) << 2) << 8 | (index & 0xC0)
        }
    }
}

/// The square distance between two colors, by their components.
pub const fn distance(a: u32, b: u32) -> u32 {
    let mut sum = 0;
    let mut shift = 0;
    while shift < 24 {
        let x = ((a >> shift) & 0xFF) as i32 - ((b >> shift) & 0xFF) as i32;
        sum += (x * x) as u32;
        shift += 8;
    }
    sum
}

/// The index of the entry of `table` nearest `rgb` (the first of equals); 0 for no table.
pub fn nearest(table: &[u32], rgb: u32) -> u32 {
    let mut best = (0u32, u32::MAX);
    for (index, &color) in table.iter().enumerate() {
        let far = distance(color, rgb & 0xFF_FFFF);
        if far < best.1 {
            best = (index as u32, far);
            if far == 0 {
                break;
            }
        }
    }
    best.0
}

/// A component `value` of `bits` bits widened to 8 bits, its high bits repeated below it (5 bits
/// 10000 is 0x84).
const fn widen(value: u32, bits: u32) -> u32 {
    if bits == 0 {
        return 0;
    }
    if bits >= 8 {
        return (value >> (bits - 8)) & 0xFF;
    }
    let mut result = 0;
    let mut filled = 0;
    while filled < 8 {
        let shift = 8 - filled as i32 - bits as i32;
        result |= if shift >= 0 {
            value << shift
        } else {
            value >> -shift
        };
        filled += bits;
    }
    result & 0xFF
}

/// A mask's shift (its lowest set bit) and width.
const fn mask_shape(mask: u32) -> (u32, u32) {
    if mask == 0 {
        return (0, 0);
    }
    let shift = mask.trailing_zeros();
    (shift, (mask >> shift).trailing_ones())
}

/// The `0x00RRGGBB` of a pixel laid out by `masks` (red, green, blue).
pub const fn rgb_of_masked(pixel: u32, masks: [u32; 3]) -> u32 {
    let mut rgb = 0;
    let mut index = 0;
    while index < 3 {
        let (shift, bits) = mask_shape(masks[index]);
        let value = (pixel & masks[index]) >> shift;
        rgb |= widen(value, bits) << (16 - 8 * index as u32);
        index += 1;
    }
    rgb
}

/// The pixel laid out by `masks` (red, green, blue) of a `0x00RRGGBB` color: each component's
/// high bits.
pub const fn masked_of_rgb(rgb: u32, masks: [u32; 3]) -> u32 {
    let mut pixel = 0;
    let mut index = 0;
    while index < 3 {
        let (shift, bits) = mask_shape(masks[index]);
        let value = (rgb >> (16 - 8 * index as u32)) & 0xFF;
        let narrowed = if bits >= 8 {
            value << (bits - 8)
        } else {
            value >> (8 - bits)
        };
        pixel |= (narrowed << shift) & masks[index];
        index += 1;
    }
    pixel
}

/// A pixel format: its bits per pixel, and its colors: a color table's (up to 8 bits; `table`
/// its entries as `0x00RRGGBB`), or its masks' (16 and 32 bits; 24 bits is blue, green, red).
#[derive(Clone, Copy, Debug)]
pub struct Format<'a> {
    pub bpp: u32,
    pub table: &'a [u32],
    pub masks: [u32; 3],
}

impl Format<'_> {
    /// The `0x00RRGGBB` of the pixel `pixel`: its table's entry (black past the table), or its
    /// masks' components.
    pub fn rgb(&self, pixel: u32) -> u32 {
        match self.bpp {
            1 | 4 | 8 => self.table.get(pixel as usize).copied().unwrap_or(0),
            24 => pixel & 0xFF_FFFF,
            _ => rgb_of_masked(pixel, self.masks),
        }
    }

    /// The pixel of the color `rgb`: its table's nearest entry, or its masks' components.
    pub fn pixel(&self, rgb: u32) -> u32 {
        match self.bpp {
            1 | 4 | 8 => nearest(self.table, rgb),
            24 => rgb & 0xFF_FFFF,
            _ => masked_of_rgb(rgb, self.masks),
        }
    }
}

/// A ternary raster operation (`code`, its truth table: bit `p << 2 | s << 1 | d` the result for
/// pattern bit `p`, source bit `s`, destination bit `d`) applied to every bit of the three
/// words.
pub const fn rop3(code: u8, pattern: u32, source: u32, destination: u32) -> u32 {
    let mut result = 0;
    let mut minterm = 0;
    while minterm < 8 {
        if code & (1 << minterm) != 0 {
            let p = if minterm & 4 != 0 { pattern } else { !pattern };
            let s = if minterm & 2 != 0 { source } else { !source };
            let d = if minterm & 1 != 0 {
                destination
            } else {
                !destination
            };
            result |= p & s & d;
        }
        minterm += 1;
    }
    result
}

/// Whether a raster operation reads its source (its result differs for the source's bits).
pub const fn rop_uses_source(rop: u32) -> bool {
    !crate::gdi::rop_is_sourceless(rop)
}

/// The source's pixel StretchBlt samples for destination pixel `index` of `destination` pixels
/// stretched from `source` pixels: the one under the destination pixel's center.
pub const fn sample(index: i32, destination: i32, source: i32) -> i32 {
    ((2 * index as i64 + 1) * source as i64 / (2 * destination as i64)) as i32
}

/// The source's pixels a shrinking stretch eliminates into destination pixel `index` (of
/// `destination` from `source`): from the first to past the last, at least one.
pub const fn span(index: i32, destination: i32, source: i32) -> (i32, i32) {
    let start = (index as i64 * source as i64 / destination as i64) as i32;
    let end = ((index as i64 + 1) * source as i64 / destination as i64) as i32;
    (start, if end > start { end } else { start + 1 })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The structures are Windows 2000's sizes.
    #[test]
    fn the_structures_are_windows_2000s() {
        assert_eq!(core::mem::size_of::<Bitmap>(), 24);
        assert_eq!(core::mem::size_of::<BitmapInfoHeader>(), 40);
        assert_eq!(core::mem::size_of::<DibSection>(), 84);
        assert_eq!(core::mem::size_of::<LogBrush>(), 12);
    }

    /// The bitmaps capture's strides: a BITMAP's word-aligned bmWidthBytes, a DIB's dword rows,
    /// and CreateBitmap's depths rounded up.
    #[test]
    fn strides_and_depths() {
        let words: std::vec::Vec<u32> = [1, 4, 8, 16, 24, 32]
            .iter()
            .map(|&bpp| word_stride(5, bpp))
            .collect();
        assert_eq!(words, [2, 4, 6, 10, 16, 20]);
        assert_eq!(
            word_stride(3, 24),
            10,
            "a 3-pixel 24-bit DIB section's bmWidthBytes"
        );
        assert_eq!(dword_stride(3, 24), 12);
        assert_eq!(dword_stride(8, 1), 4);
        assert_eq!(dword_stride(5, 4), 4);
        assert_eq!(rounded_bpp(2), Some(4));
        assert_eq!(rounded_bpp(4), Some(4));
        assert_eq!(rounded_bpp(33), None);
        assert_eq!(rounded_bpp(0), None);
    }

    /// Pixels pack into their rows: bit 7 the leftmost of a 1-bit row, the high nibble the left of
    /// a 4-bit one, little-endian wider pixels; past the row nothing.
    #[test]
    fn pixels_pack_into_rows() {
        let row = [0xA5u8, 0x00];
        let bits: std::vec::Vec<u32> = (0..8).map(|x| get_packed(&row, x, 1)).collect();
        assert_eq!(bits, [1, 0, 1, 0, 0, 1, 0, 1]);
        let mut row = [0u8; 4];
        set_packed(&mut row, 1, 4, 0xC);
        set_packed(&mut row, 2, 4, 0x3);
        assert_eq!(row, [0x0C, 0x30, 0, 0]);
        assert_eq!(get_packed(&row, 1, 4), 0xC);
        let mut row = [0u8; 6];
        set_packed(&mut row, 1, 24, 0x0011_2233);
        assert_eq!(row, [0, 0, 0, 0x33, 0x22, 0x11]);
        assert_eq!(get_packed(&row, 1, 24), 0x11_2233);
        set_packed(&mut row, 9, 16, 0xFFFF);
        assert_eq!(get_packed(&row, 9, 16), 0, "past the row");
        let mut row = [0u8; 8];
        set_packed(&mut row, 1, 32, 0xFF12_3456);
        assert_eq!(get_packed(&row, 1, 32), 0xFF12_3456);
    }

    /// The default 8-bit table is the capture's: its CRC-32 and its first entries.
    #[test]
    fn the_default_8_bit_table_is_windows_2000s() {
        let mut bytes = std::vec::Vec::new();
        for index in 0..256 {
            bytes.extend_from_slice(&quad_of_rgb(default_color_8(index)));
        }
        let mut crc = 0xFFFF_FFFFu32;
        for byte in bytes {
            crc ^= byte as u32;
            for _ in 0..8 {
                crc = (crc >> 1) ^ (0xEDB8_8320 & 0u32.wrapping_sub(crc & 1));
            }
        }
        assert_eq!(crc ^ 0xFFFF_FFFF, 0xD728_0939);
        let table: std::vec::Vec<u32> = (0..256).map(default_color_8).collect();
        // GetDIBits' 8-bit answer: red, green, blue, white / black, gray, silver, maroon.
        let pixels: std::vec::Vec<u32> = [
            0xFF0000, 0x00FF00, 0x0000FF, 0xFFFFFF, 0x000000, 0x808080, 0xC0C0C0, 0x800000,
        ]
        .iter()
        .map(|&rgb| nearest(&table, rgb))
        .collect();
        assert_eq!(pixels, [0xF9, 0xFA, 0xFC, 0xFF, 0x00, 0xA4, 0x07, 0x01]);
        let vga: std::vec::Vec<u32> = [0x808080, 0xC0C0C0, 0x800000]
            .iter()
            .map(|&rgb| nearest(&VGA_COLORS, rgb))
            .collect();
        assert_eq!(vga, [7, 8, 1]);
    }

    /// Nearest colors to black and white: gray goes white, red black, yellow white (LoadImage's
    /// LR_MONOCHROME rows).
    #[test]
    fn nearest_black_or_white() {
        let to_mono = |rgb| nearest(&MONO_COLORS, rgb);
        assert_eq!(to_mono(0x808080), 1);
        assert_eq!(to_mono(0x7F7F7F), 0);
        assert_eq!(to_mono(0xFF0000), 0);
        assert_eq!(to_mono(0xFFFF00), 1);
        assert_eq!(to_mono(0x008080), 0);
        assert_eq!(nearest(&[], 0x123456), 0);
    }

    /// Masks convert both ways: 5-6-5 red is F800, 0x808080 is 8410 and reads back 0x848284; 5-5-5
    /// is GetDIBits' 16 bits.
    #[test]
    fn masks_convert_colors() {
        let m565 = [0xF800, 0x07E0, 0x001F];
        assert_eq!(masked_of_rgb(0xFF0000, m565), 0xF800);
        assert_eq!(masked_of_rgb(0x808080, m565), 0x8410);
        assert_eq!(rgb_of_masked(0x8410, m565), 0x848284);
        let m555 = default_masks(16);
        assert_eq!(masked_of_rgb(0xFF0000, m555), 0x7C00);
        assert_eq!(masked_of_rgb(0xC0C0C0, m555), 0x6318);
        assert_eq!(masked_of_rgb(0xFFFFFF, m555), 0x7FFF);
        assert_eq!(rgb_of_masked(0x7FFF, m555), 0xFFFFFF);
        let m888 = default_masks(32);
        assert_eq!(rgb_of_masked(0xFF12_3456, m888), 0x12_3456);
        assert_eq!(masked_of_rgb(0x12_3456, m888), 0x12_3456);
        let format = Format {
            bpp: 16,
            table: &[],
            masks: m565,
        };
        assert_eq!(format.rgb(format.pixel(0x808080)), 0x848284);
    }

    /// The raster operations of the blit capture, on its fixed values: destination F0CC0F, source
    /// 0F33F0, pattern 204080.
    #[test]
    fn raster_operations_combine_three_words() {
        let (p, s, d) = (0x0020_4080u32, 0x000F_33F0u32, 0x00F0_CC0Fu32);
        let apply = |rop: u32| rop3((rop >> 16) as u8, p, s, d);
        assert_eq!(apply(SRCCOPY), s);
        assert_eq!(apply(SRCPAINT), 0x00FF_FFFF);
        assert_eq!(apply(SRCAND), 0);
        assert_eq!(apply(SRCERASE), 0x000F_33F0);
        assert_eq!(apply(NOTSRCCOPY), 0xFFF0_CC0F);
        assert_eq!(apply(MERGECOPY), 0x0000_0080);
        assert_eq!(apply(crate::gdi::PATINVERT), 0x00D0_8C8F);
        assert_eq!(apply(crate::gdi::DSTINVERT), 0xFF0F_33F0);
        assert_eq!(apply(crate::gdi::WHITENESS), u32::MAX);
        assert!(rop_uses_source(SRCCOPY));
        assert!(!rop_uses_source(crate::gdi::PATCOPY));
    }

    /// StretchBlt's sampling: 3 to 7 takes 0 0 1 1 1 2 2, 5 to 8 takes 0 0 1 2 2 3 4 4, 8 to 4 the
    /// odd pixels; a shrink eliminates pairs.
    #[test]
    fn stretching_samples_centers() {
        let take = |d, s| {
            (0..d)
                .map(|i| sample(i, d, s))
                .collect::<std::vec::Vec<_>>()
        };
        assert_eq!(take(7, 3), [0, 0, 1, 1, 1, 2, 2]);
        assert_eq!(take(5, 2), [0, 0, 1, 1, 1]);
        assert_eq!(take(8, 5), [0, 0, 1, 2, 2, 3, 4, 4]);
        assert_eq!(take(6, 4), [0, 1, 1, 2, 3, 3]);
        assert_eq!(take(4, 8), [1, 3, 5, 7]);
        assert_eq!(span(1, 4, 8), (2, 4));
        assert_eq!(span(2, 7, 3), (0, 1));
    }

    /// A DIB section's DIBSECTION: positive height, the full table's count, masks for BI_BITFIELDS
    /// alone; a 24-bit one's bmWidthBytes word-aligned and its image dword-aligned.
    #[test]
    fn a_dib_sections_description() {
        let desc = BitmapDesc {
            width: 3,
            height: 2,
            bpp: 24,
            flags: DESC_DIB,
            masks: [0; 3],
            stride: 12,
            bits: 0x1000,
            colors: 0,
            color_count: 0,
            block: 0x1000,
        };
        let ds = desc.dib_section();
        assert_eq!(ds.bm.width_bytes, 10);
        assert_eq!(ds.bm.bits, 0x1000);
        assert_eq!(ds.bmih.size_image, 24);
        assert_eq!(ds.bmih.clr_used, 0);
        assert_eq!(desc.row_offset(0), 12, "bottom-up");
        let ddb = BitmapDesc { flags: 0, ..desc };
        assert_eq!(ddb.bitmap().bits, 0);
        assert_eq!(ddb.row_offset(0), 0);
        let eight = BitmapDesc {
            bpp: 8,
            flags: DESC_DIB | DESC_TOP_DOWN,
            ..desc
        };
        assert_eq!(eight.dib_section().bmih.clr_used, 256);
        assert!(!eight.is_mono());
        assert!(BitmapDesc::DEFAULT.is_mono());
    }
}
