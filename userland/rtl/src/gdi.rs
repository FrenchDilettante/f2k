//! GDI's shared shapes: the constants gdi32's exports and win32k's DC services agree on (colors,
//! background modes, ExtTextOut's options, the stock objects and their handles, the DC attributes
//! the services get and set), and TEXTMETRICA and TEXTMETRICW as Windows 2000's wingdi.h lays them
//! out on x86 ([`TextMetricA`], [`TextMetricW`]). gdi32's narrow GetTextMetricsA converts the wide
//! answer win32k gives ([`narrow_text_metric`]).

use crate::pod::Pod;

/// A COLORREF's failure value (CLR_INVALID): SetPixel's and GetPixel's answer for a pixel outside
/// the DC's clipping region, SetTextColor's and SetBkColor's for a DC that is none.
pub const CLR_INVALID: u32 = 0xFFFF_FFFF;

/// The colors' RGB part: a COLORREF's low three bytes (0x00BBGGRR).
pub const RGB_MASK: u32 = 0x00FF_FFFF;

/// The background modes (SetBkMode): TRANSPARENT leaves the background as it is, OPAQUE fills it
/// with the background color.
pub const TRANSPARENT: u32 = 1;
pub const OPAQUE: u32 = 2;

/// ExtTextOut's options: the rectangle filled with the background color (ETO_OPAQUE), the text
/// clipped to it (ETO_CLIPPED).
pub const ETO_OPAQUE: u32 = 0x0002;
pub const ETO_CLIPPED: u32 = 0x0004;

/// GetObjectType's answers for the kinds of objects there are: a pen, a brush, a DC, a palette, a
/// font.
pub const OBJ_PEN: u32 = 1;
pub const OBJ_BRUSH: u32 = 2;
pub const OBJ_DC: u32 = 3;
pub const OBJ_PAL: u32 = 5;
pub const OBJ_FONT: u32 = 6;

/// The stock objects GetStockObject names (wingdi.h's indexes; 9 is none).
pub const WHITE_BRUSH: u32 = 0;
pub const LTGRAY_BRUSH: u32 = 1;
pub const GRAY_BRUSH: u32 = 2;
pub const DKGRAY_BRUSH: u32 = 3;
pub const BLACK_BRUSH: u32 = 4;
pub const NULL_BRUSH: u32 = 5;
pub const WHITE_PEN: u32 = 6;
pub const BLACK_PEN: u32 = 7;
pub const NULL_PEN: u32 = 8;
pub const OEM_FIXED_FONT: u32 = 10;
pub const ANSI_FIXED_FONT: u32 = 11;
pub const ANSI_VAR_FONT: u32 = 12;
pub const SYSTEM_FONT: u32 = 13;
pub const DEVICE_DEFAULT_FONT: u32 = 14;
pub const DEFAULT_PALETTE: u32 = 15;
pub const SYSTEM_FIXED_FONT: u32 = 16;
pub const DEFAULT_GUI_FONT: u32 = 17;
pub const DC_BRUSH: u32 = 18;
pub const DC_PEN: u32 = 19;

/// The stock objects' handles: F2K's own constant per index, the kind of object in bits 16-18 and
/// the stock bit (bit 23) above them, the index in the low bits. No handle-table handle reaches
/// that high, so gdi32 and win32k tell a stock object from a DC by its value alone, as Windows
/// 2000's GDI handles carry their type and their stock bit in their own bits.
const STOCK_BIT: u32 = 0x0080_0000;
const KIND_SHIFT: u32 = 16;
const KIND_MASK: u32 = 0x7;
const INDEX_MASK: u32 = 0xFF;

/// The kind of object stock object `index` is (its GetObjectType answer); none for an index
/// GetStockObject does not know.
pub const fn stock_kind(index: u32) -> Option<u32> {
    Some(match index {
        WHITE_BRUSH..=NULL_BRUSH | DC_BRUSH => OBJ_BRUSH,
        WHITE_PEN..=NULL_PEN | DC_PEN => OBJ_PEN,
        OEM_FIXED_FONT..=DEVICE_DEFAULT_FONT | SYSTEM_FIXED_FONT | DEFAULT_GUI_FONT => OBJ_FONT,
        DEFAULT_PALETTE => OBJ_PAL,
        _ => return None,
    })
}

/// Stock object `index`'s handle; none for an index GetStockObject does not know.
pub const fn stock_handle(index: u32) -> Option<u32> {
    match stock_kind(index) {
        Some(kind) => Some(STOCK_BIT | (kind << KIND_SHIFT) | index),
        None => None,
    }
}

/// The stock object `handle` is, as its index and its kind; none for a handle that is no stock
/// object's.
pub const fn stock_object(handle: u32) -> Option<(u32, u32)> {
    let index = handle & INDEX_MASK;
    match stock_handle(index) {
        Some(stock) if stock == handle => Some((index, (handle >> KIND_SHIFT) & KIND_MASK)),
        _ => None,
    }
}

/// The DC attributes win32k's NtGdiGetDCDword reads and NtGdiGetAndSetDCDword sets (F2K's own
/// indexes): the text color, the background color, the background mode.
pub const DC_TEXT_COLOR: u32 = 0;
pub const DC_BK_COLOR: u32 = 1;
pub const DC_BK_MODE: u32 = 2;

/// A DC's attributes as it starts (the platform's defaults): black text on a white background,
/// OPAQUE.
pub const DEFAULT_TEXT_COLOR: u32 = 0x0000_0000;
pub const DEFAULT_BK_COLOR: u32 = 0x00FF_FFFF;
pub const DEFAULT_BK_MODE: u32 = OPAQUE;

/// TEXTMETRICW, Windows 2000's (60 bytes: 57 of fields, then the structure's padding to its
/// alignment).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TextMetricW {
    pub height: i32,
    pub ascent: i32,
    pub descent: i32,
    pub internal_leading: i32,
    pub external_leading: i32,
    pub ave_char_width: i32,
    pub max_char_width: i32,
    pub weight: i32,
    pub overhang: i32,
    pub digitized_aspect_x: i32,
    pub digitized_aspect_y: i32,
    pub first_char: u16,
    pub last_char: u16,
    pub default_char: u16,
    pub break_char: u16,
    pub italic: u8,
    pub underlined: u8,
    pub struck_out: u8,
    pub pitch_and_family: u8,
    pub char_set: u8,
    pub padding: [u8; 3],
}

/// TEXTMETRICA, Windows 2000's (56 bytes: 53 of fields, then the padding).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TextMetricA {
    pub height: i32,
    pub ascent: i32,
    pub descent: i32,
    pub internal_leading: i32,
    pub external_leading: i32,
    pub ave_char_width: i32,
    pub max_char_width: i32,
    pub weight: i32,
    pub overhang: i32,
    pub digitized_aspect_x: i32,
    pub digitized_aspect_y: i32,
    pub first_char: u8,
    pub last_char: u8,
    pub default_char: u8,
    pub break_char: u8,
    pub italic: u8,
    pub underlined: u8,
    pub struck_out: u8,
    pub pitch_and_family: u8,
    pub char_set: u8,
    pub padding: [u8; 3],
}

// SAFETY: integers and byte arrays, laid out with no padding (the trailing bytes are a field), and
// every bit pattern is a value.
unsafe impl Pod for TextMetricW {}
// SAFETY: as above.
unsafe impl Pod for TextMetricA {}

/// The narrow form of the wide `metric`, as GetTextMetricsA answers it: every field as it is, the
/// four characters converted through `convert` (a unit to its byte in the ANSI code page).
pub fn narrow_text_metric(metric: &TextMetricW, mut convert: impl FnMut(u16) -> u8) -> TextMetricA {
    TextMetricA {
        height: metric.height,
        ascent: metric.ascent,
        descent: metric.descent,
        internal_leading: metric.internal_leading,
        external_leading: metric.external_leading,
        ave_char_width: metric.ave_char_width,
        max_char_width: metric.max_char_width,
        weight: metric.weight,
        overhang: metric.overhang,
        digitized_aspect_x: metric.digitized_aspect_x,
        digitized_aspect_y: metric.digitized_aspect_y,
        first_char: convert(metric.first_char),
        last_char: convert(metric.last_char),
        default_char: convert(metric.default_char),
        break_char: convert(metric.break_char),
        italic: metric.italic,
        underlined: metric.underlined,
        struck_out: metric.struck_out,
        pitch_and_family: metric.pitch_and_family,
        char_set: metric.char_set,
        padding: [0; 3],
    }
}

/// SIZE: a text extent, as GetTextExtentPoint32 answers it.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Size {
    pub cx: i32,
    pub cy: i32,
}

// SAFETY: two integers.
unsafe impl Pod for Size {}

/// RECT: a rectangle, its right and bottom edges outside it.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Rect {
    pub left: i32,
    pub top: i32,
    pub right: i32,
    pub bottom: i32,
}

// SAFETY: four integers.
unsafe impl Pod for Rect {}

#[cfg(test)]
mod tests {
    use core::mem::{offset_of, size_of};

    use super::*;

    /// The structures' sizes and the offsets past the LONGs, as wingdi.h lays them out on x86.
    #[test]
    fn the_layouts_are_windows_2000s() {
        assert_eq!(size_of::<TextMetricW>(), 60);
        assert_eq!(size_of::<TextMetricA>(), 56);
        assert_eq!(offset_of!(TextMetricW, first_char), 44);
        assert_eq!(offset_of!(TextMetricW, italic), 52);
        assert_eq!(offset_of!(TextMetricW, char_set), 56);
        assert_eq!(offset_of!(TextMetricA, first_char), 44);
        assert_eq!(offset_of!(TextMetricA, italic), 48);
        assert_eq!(offset_of!(TextMetricA, char_set), 52);
        assert_eq!(size_of::<Size>(), 8);
        assert_eq!(size_of::<Rect>(), 16);
    }

    /// Every stock index GetStockObject knows has a handle that names it back, with its kind; 9
    /// and the indexes past DC_PEN have none, and no small value (a handle table's) is a stock
    /// object's.
    #[test]
    fn the_stock_handles_name_their_objects() {
        for index in 0..=DC_PEN {
            let Some(handle) = stock_handle(index) else {
                assert_eq!(index, 9);
                continue;
            };
            let kind = stock_kind(index).unwrap();
            assert_eq!(stock_object(handle), Some((index, kind)));
            assert!(handle > 0xFFFF);
        }
        assert_eq!(stock_handle(9), None);
        assert_eq!(stock_handle(20), None);
        assert_eq!(stock_kind(WHITE_BRUSH), Some(OBJ_BRUSH));
        assert_eq!(stock_kind(BLACK_PEN), Some(OBJ_PEN));
        assert_eq!(stock_kind(SYSTEM_FONT), Some(OBJ_FONT));
        assert_eq!(stock_kind(DEFAULT_PALETTE), Some(OBJ_PAL));
        assert_eq!(stock_object(0), None);
        assert_eq!(stock_object(0x7C), None);
        assert_eq!(
            stock_object(stock_handle(WHITE_BRUSH).unwrap() + 0x100),
            None
        );
    }

    /// The narrow metrics keep every number and convert the four characters.
    #[test]
    fn the_narrow_metrics_convert_the_characters() {
        let wide = TextMetricW {
            height: 16,
            ave_char_width: 8,
            first_char: 0x20,
            last_char: 0x20AC,
            default_char: u16::from(b'?'),
            break_char: 0x20,
            char_set: 255,
            ..TextMetricW::default()
        };
        let narrow =
            narrow_text_metric(&wide, |unit| if unit == 0x20AC { 0x80 } else { unit as u8 });
        assert_eq!(narrow.height, 16);
        assert_eq!(narrow.ave_char_width, 8);
        assert_eq!(
            (
                narrow.first_char,
                narrow.last_char,
                narrow.default_char,
                narrow.break_char
            ),
            (0x20, 0x80, b'?', 0x20)
        );
        assert_eq!(narrow.char_set, 255);
    }
}
