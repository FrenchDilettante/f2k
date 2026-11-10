//! GDI's shared shapes: the constants gdi32's exports and win32k's DC services agree on (colors,
//! background modes, ExtTextOut's options, the stock objects and their handles, the DC attributes
//! the services get and set), and TEXTMETRICA and TEXTMETRICW as Windows 2000's wingdi.h lays them
//! out on x86 ([`TextMetricA`], [`TextMetricW`]). gdi32's narrow GetTextMetricsA converts the wide
//! answer win32k gives ([`narrow_text_metric`]). The fonts' structures follow: LOGFONT, ABC,
//! OUTLINETEXTMETRIC, and the enumeration's ENUMLOGFONTEX and NEWTEXTMETRICEX, each in its wide and
//! narrow forms, and the record win32k's enumeration service answers ([`FontEnumRecord`]).

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

/// The first index past the stock objects' of the system colors' brushes (GetSysColorBrush's):
/// system color `i`'s brush has the stock objects' shape, a brush's kind and the stock bit, with
/// the index `SYS_COLOR_BRUSH_FIRST + i`. Like the stock objects, they are global: every process
/// names them by the same handle, and they are never deleted. Their color is the system color's
/// as it is when they draw, so SetSysColors recolors them (Windows 2000's own system brushes keep
/// their handles across SetSysColors too).
pub const SYS_COLOR_BRUSH_FIRST: u32 = 0x40;

/// user32's gray brush (Windows 2000's `gpsi->hbrGray`, which win32k makes and user32 reads from
/// the shared information): an 8x8 checkerboard pattern, its pixels alternately the DC's
/// background and text colors, the background's at the brush origin. DrawFocusRect's dotted frame
/// is drawn with it. A global brush as the system colors' are, in the stock objects' shape.
pub const HALFTONE_BRUSH: u32 = STOCK_BIT | (OBJ_BRUSH << KIND_SHIFT) | 0x60;

/// The rows of [`HALFTONE_BRUSH`]'s pattern, from the brush origin's row: a set bit (bit 7 the
/// leftmost pixel) is the DC's background color, a clear one its text color (a monochrome
/// pattern's colors, as a pattern brush made from a monochrome bitmap takes them).
pub const HALFTONE_ROWS: [u8; 8] = [0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55];

/// System color `index`'s brush (see [`SYS_COLOR_BRUSH_FIRST`]); none for an index past the
/// system colors.
pub const fn sys_color_brush(index: u32) -> Option<u32> {
    if index < crate::display::SYSTEM_COLORS as u32 {
        Some(STOCK_BIT | (OBJ_BRUSH << KIND_SHIFT) | (SYS_COLOR_BRUSH_FIRST + index))
    } else {
        None
    }
}

/// A global brush: one every process names by the same constant handle, never deleted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GlobalBrush {
    /// A stock brush, by its GetStockObject index.
    Stock(u32),
    /// A system color's brush, by the color's index.
    SysColor(u32),
    /// user32's gray brush ([`HALFTONE_BRUSH`]).
    Halftone,
}

/// The global brush `handle` names; none for another handle.
pub const fn global_brush(handle: u32) -> Option<GlobalBrush> {
    if let Some((index, OBJ_BRUSH)) = stock_object(handle) {
        return Some(GlobalBrush::Stock(index));
    }
    if handle == HALFTONE_BRUSH {
        return Some(GlobalBrush::Halftone);
    }
    let index = (handle & INDEX_MASK).wrapping_sub(SYS_COLOR_BRUSH_FIRST);
    match sys_color_brush(index) {
        Some(brush) if brush == handle => Some(GlobalBrush::SysColor(index)),
        _ => None,
    }
}

/// The kind of object (OBJ_BRUSH, OBJ_PEN, OBJ_FONT, OBJ_PAL) a global object's handle names — a
/// stock object, or a global brush — read from the handle alone; none for another handle.
pub const fn global_object_kind(handle: u32) -> Option<u32> {
    match stock_object(handle) {
        Some((_, kind)) => Some(kind),
        None if global_brush(handle).is_some() => Some(OBJ_BRUSH),
        None => None,
    }
}

/// The handles of the process's GDI objects (a brush CreateSolidBrush made) are the kernel's
/// handle-table handles, below 0x10000, with the object's kind in bits 16-18 and no stock bit, as
/// Windows 2000's GDI handles carry their type in their high word: a program's handle never
/// collides with the small values FillRect takes as COLOR_* + 1, and gdi32 reads an object's kind
/// from its handle. (A DC's handle is the handle table's own, its kind bits clear.)
const TABLE_MASK: u32 = 0xFFFF;

/// The handle of the object of `kind` the handle table's `table` names.
pub const fn object_handle(kind: u32, table: u32) -> u32 {
    (kind << KIND_SHIFT) | (table & TABLE_MASK)
}

/// The kind of the object an object's handle names, and its handle-table handle; none for a
/// handle with no kind bits (a DC's), a global object's, or one past the shape.
pub const fn object_of(handle: u32) -> Option<(u32, u32)> {
    let kind = (handle >> KIND_SHIFT) & KIND_MASK;
    if kind == 0 || handle >> (KIND_SHIFT + 3) != 0 {
        return None;
    }
    Some((kind, handle & TABLE_MASK))
}

/// The kind of object a handle's own bits say it names: a global object's, or a process's
/// object's ([`object_of`]); none for another handle.
pub const fn object_kind(handle: u32) -> Option<u32> {
    match global_object_kind(handle) {
        Some(kind) => Some(kind),
        None => match object_of(handle) {
            Some((kind, _)) => Some(kind),
            None => None,
        },
    }
}

/// The raster operations PatBlt takes (wingdi.h's ROP3 codes): the destination painted with the
/// pattern, inverted where the pattern is set, inverted, black, white.
pub const PATCOPY: u32 = 0x00F0_0021;
pub const PATINVERT: u32 = 0x005A_0049;
pub const DSTINVERT: u32 = 0x0055_0009;
pub const BLACKNESS: u32 = 0x0000_0042;
pub const WHITENESS: u32 = 0x00FF_0062;

/// A ternary raster operation's truth table (its code's byte 2): bit `p << 2 | s << 1 | d` is the
/// result for pattern bit `p`, source bit `s` and destination bit `d`.
pub const fn rop3(rop: u32) -> u8 {
    (rop >> 16) as u8
}

/// Whether a raster operation reads no source (its result is the same for either source bit):
/// one PatBlt can do.
pub const fn rop_is_sourceless(rop: u32) -> bool {
    let table = rop3(rop);
    (table >> 2) & 0x33 == table & 0x33
}

/// Whether a raster operation's result depends on the pattern.
pub const fn rop_uses_pattern(rop: u32) -> bool {
    let table = rop3(rop);
    table >> 4 != table & 0x0F
}

/// Whether a raster operation's result depends on the destination.
pub const fn rop_uses_destination(rop: u32) -> bool {
    let table = rop3(rop);
    (table >> 1) & 0x55 != table & 0x55
}

/// A sourceless raster operation applied to every bit of a pattern word `pattern` and a
/// destination word `destination` (the source taken as zero).
pub const fn apply_rop(rop: u32, pattern: u32, destination: u32) -> u32 {
    let table = rop3(rop);
    let (p, d) = (pattern, destination);
    let mut result = 0;
    if table & (1 << 0b000) != 0 {
        result |= !p & !d;
    }
    if table & (1 << 0b001) != 0 {
        result |= !p & d;
    }
    if table & (1 << 0b100) != 0 {
        result |= p & !d;
    }
    if table & (1 << 0b101) != 0 {
        result |= p & d;
    }
    result
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

// --- Fonts ---------------------------------------------------------------------------------------

/// LF_FACESIZE: a face name's room in a LOGFONT, its terminator included.
pub const LF_FACESIZE: usize = 32;
/// LF_FULLFACESIZE: a full name's room in an ENUMLOGFONT.
pub const LF_FULLFACESIZE: usize = 64;

/// The character sets (LOGFONT's lfCharSet) this module names.
pub const ANSI_CHARSET: u8 = 0;
pub const DEFAULT_CHARSET: u8 = 1;
pub const SYMBOL_CHARSET: u8 = 2;

/// LOGFONT's lfWeight: normal and bold.
pub const FW_NORMAL: i32 = 400;
pub const FW_BOLD: i32 = 700;

/// TEXTMETRIC's tmPitchAndFamily bits: a variable-pitch font (the bit's name says the opposite, as
/// wingdi.h owns), an outline font, a TrueType font.
pub const TMPF_FIXED_PITCH: u8 = 0x01;
pub const TMPF_VECTOR: u8 = 0x02;
pub const TMPF_TRUETYPE: u8 = 0x04;

/// LOGFONT's lfPitchAndFamily pitches.
pub const FIXED_PITCH: u8 = 1;
pub const VARIABLE_PITCH: u8 = 2;

/// The font families: lfPitchAndFamily's and tmPitchAndFamily's high nibble.
pub const FF_DONTCARE: u8 = 0x00;
pub const FF_ROMAN: u8 = 0x10;
pub const FF_SWISS: u8 = 0x20;
pub const FF_MODERN: u8 = 0x30;
pub const FF_SCRIPT: u8 = 0x40;
pub const FF_DECORATIVE: u8 = 0x50;

/// EnumFontFamilies' FontType for a TrueType font.
pub const TRUETYPE_FONTTYPE: u32 = 0x0004;
/// NEWTEXTMETRIC's ntmFlags: an italic face, a bold one, a regular one.
pub const NTM_ITALIC: u32 = 0x0000_0001;
pub const NTM_BOLD: u32 = 0x0000_0020;
pub const NTM_REGULAR: u32 = 0x0000_0040;

/// GetFontData's and GetGlyphOutline's failure value (GDI_ERROR).
pub const GDI_ERROR: u32 = 0xFFFF_FFFF;

/// GetGlyphOutline's formats: the metrics alone, and the monochrome bitmap.
pub const GGO_METRICS: u32 = 0;
pub const GGO_BITMAP: u32 = 1;

/// LOGFONTW, Windows 2000's (92 bytes).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LogFontW {
    pub height: i32,
    pub width: i32,
    pub escapement: i32,
    pub orientation: i32,
    pub weight: i32,
    pub italic: u8,
    pub underline: u8,
    pub strike_out: u8,
    pub char_set: u8,
    pub out_precision: u8,
    pub clip_precision: u8,
    pub quality: u8,
    pub pitch_and_family: u8,
    pub face_name: [u16; LF_FACESIZE],
}

/// LOGFONTA, Windows 2000's (60 bytes).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LogFontA {
    pub height: i32,
    pub width: i32,
    pub escapement: i32,
    pub orientation: i32,
    pub weight: i32,
    pub italic: u8,
    pub underline: u8,
    pub strike_out: u8,
    pub char_set: u8,
    pub out_precision: u8,
    pub clip_precision: u8,
    pub quality: u8,
    pub pitch_and_family: u8,
    pub face_name: [u8; LF_FACESIZE],
}

// SAFETY: integers and arrays of them, the eight bytes filling the LONGs' alignment: no padding,
// and any bits make one.
unsafe impl Pod for LogFontW {}
// SAFETY: as above.
unsafe impl Pod for LogFontA {}

impl LogFontW {
    /// The face name: its units up to the terminator (all of them, when unterminated).
    pub fn face(&self) -> &[u16] {
        let end = self.face_name.iter().position(|&unit| unit == 0);
        &self.face_name[..end.unwrap_or(LF_FACESIZE)]
    }
}

/// The narrow LOGFONT of the wide `font`: every field as it is, the face name converted through
/// `convert` (the units into the bytes' room, answering how many bytes it wrote), NUL-padded.
pub fn narrow_log_font(
    font: &LogFontW,
    convert: impl FnOnce(&mut [u8], &[u16]) -> usize,
) -> LogFontA {
    let mut face_name = [0u8; LF_FACESIZE];
    let written = convert(&mut face_name[..LF_FACESIZE - 1], font.face());
    face_name[written.min(LF_FACESIZE - 1)..].fill(0);
    LogFontA {
        height: font.height,
        width: font.width,
        escapement: font.escapement,
        orientation: font.orientation,
        weight: font.weight,
        italic: font.italic,
        underline: font.underline,
        strike_out: font.strike_out,
        char_set: font.char_set,
        out_precision: font.out_precision,
        clip_precision: font.clip_precision,
        quality: font.quality,
        pitch_and_family: font.pitch_and_family,
        face_name,
    }
}

/// The wide LOGFONT of the narrow `font`, its face name converted through `convert` (the bytes
/// into the units' room, answering how many units it wrote), NUL-padded.
pub fn wide_log_font(
    font: &LogFontA,
    convert: impl FnOnce(&mut [u16], &[u8]) -> usize,
) -> LogFontW {
    let end = font.face_name.iter().position(|&byte| byte == 0);
    let face = &font.face_name[..end.unwrap_or(LF_FACESIZE)];
    let mut face_name = [0u16; LF_FACESIZE];
    let written = convert(&mut face_name[..LF_FACESIZE - 1], face);
    face_name[written.min(LF_FACESIZE - 1)..].fill(0);
    LogFontW {
        height: font.height,
        width: font.width,
        escapement: font.escapement,
        orientation: font.orientation,
        weight: font.weight,
        italic: font.italic,
        underline: font.underline,
        strike_out: font.strike_out,
        char_set: font.char_set,
        out_precision: font.out_precision,
        clip_precision: font.clip_precision,
        quality: font.quality,
        pitch_and_family: font.pitch_and_family,
        face_name,
    }
}

/// ABC: a character's A, B and C spacing (GetCharABCWidths).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Abc {
    pub a: i32,
    pub b: u32,
    pub c: i32,
}

// SAFETY: three 32-bit integers.
unsafe impl Pod for Abc {}

/// POINT.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Point {
    pub x: i32,
    pub y: i32,
}

// SAFETY: two integers.
unsafe impl Pod for Point {}

/// OUTLINETEXTMETRIC's members after its TEXTMETRIC and its PANOSE number, the same in the wide
/// and narrow forms. The four names' members are offsets from the structure's start to the
/// strings, which follow it in the caller's buffer.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OutlineFields {
    pub fs_selection: u32,
    pub fs_type: u32,
    pub char_slope_rise: i32,
    pub char_slope_run: i32,
    pub italic_angle: i32,
    pub em_square: u32,
    pub ascent: i32,
    pub descent: i32,
    pub line_gap: u32,
    pub cap_em_height: u32,
    pub x_height: u32,
    pub font_box: Rect,
    pub mac_ascent: i32,
    pub mac_descent: i32,
    pub mac_line_gap: u32,
    pub minimum_ppem: u32,
    pub subscript_size: Point,
    pub subscript_offset: Point,
    pub superscript_size: Point,
    pub superscript_offset: Point,
    pub strikeout_size: u32,
    pub strikeout_position: i32,
    pub underscore_size: i32,
    pub underscore_position: i32,
    pub family_name: u32,
    pub face_name: u32,
    pub style_name: u32,
    pub full_name: u32,
}

/// OUTLINETEXTMETRICW, Windows 2000's (216 bytes, its strings after them): its size, its
/// TEXTMETRICW, a filler byte, the PANOSE number, a byte of padding, then the outline members.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OutlineTextMetricW {
    pub size: u32,
    pub text_metrics: TextMetricW,
    pub filler: u8,
    pub panose: [u8; 10],
    pub padding: u8,
    pub fields: OutlineFields,
}

/// OUTLINETEXTMETRICA, Windows 2000's (212 bytes, its strings after them).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OutlineTextMetricA {
    pub size: u32,
    pub text_metrics: TextMetricA,
    pub filler: u8,
    pub panose: [u8; 10],
    pub padding: u8,
    pub fields: OutlineFields,
}

// SAFETY: integers, arrays and structures of them; the padding byte is a member of its own, so no
// byte is padding, and any bits make one.
unsafe impl Pod for OutlineFields {}
// SAFETY: as above.
unsafe impl Pod for OutlineTextMetricW {}
// SAFETY: as above.
unsafe impl Pod for OutlineTextMetricA {}

/// FONTSIGNATURE: the Unicode ranges and the code pages a font covers (its OS/2 table's bits).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FontSignature {
    pub usb: [u32; 4],
    pub csb: [u32; 2],
}

/// NEWTEXTMETRICW: TEXTMETRICW's members, then the face's flags and its design metrics.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NewTextMetricW {
    pub text_metric: TextMetricW,
    pub flags: u32,
    pub size_em: u32,
    pub cell_height: u32,
    pub avg_width: u32,
}

/// NEWTEXTMETRICA.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NewTextMetricA {
    pub text_metric: TextMetricA,
    pub flags: u32,
    pub size_em: u32,
    pub cell_height: u32,
    pub avg_width: u32,
}

/// NEWTEXTMETRICEXW: NEWTEXTMETRICW and the font's signature.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NewTextMetricExW {
    pub metric: NewTextMetricW,
    pub signature: FontSignature,
}

/// NEWTEXTMETRICEXA.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NewTextMetricExA {
    pub metric: NewTextMetricA,
    pub signature: FontSignature,
}

/// ENUMLOGFONTEXW: a LOGFONTW, the face's full name, its style and the script of the character
/// set it is enumerated in. ENUMLOGFONTW is its first three members.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EnumLogFontExW {
    pub log_font: LogFontW,
    pub full_name: [u16; LF_FULLFACESIZE],
    pub style: [u16; LF_FACESIZE],
    pub script: [u16; LF_FACESIZE],
}

/// ENUMLOGFONTEXA.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EnumLogFontExA {
    pub log_font: LogFontA,
    pub full_name: [u8; LF_FULLFACESIZE],
    pub style: [u8; LF_FACESIZE],
    pub script: [u8; LF_FACESIZE],
}

/// One face an enumeration answers, as win32k's NtGdiEnumFontChunk hands it to gdi32 (F2K's own
/// record): what EnumFontFamiliesExW's callback receives, and its FontType.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FontEnumRecord {
    pub log_font: EnumLogFontExW,
    pub metric: NewTextMetricExW,
    pub font_type: u32,
}

// SAFETY: integers, arrays and structures of them, each member's size a multiple of the 32-bit
// alignment (or closing it): no padding, and any bits make one.
unsafe impl Pod for FontSignature {}
// SAFETY: as above.
unsafe impl Pod for NewTextMetricW {}
// SAFETY: as above.
unsafe impl Pod for NewTextMetricA {}
// SAFETY: as above.
unsafe impl Pod for NewTextMetricExW {}
// SAFETY: as above.
unsafe impl Pod for NewTextMetricExA {}
// SAFETY: as above.
unsafe impl Pod for EnumLogFontExW {}
// SAFETY: as above.
unsafe impl Pod for EnumLogFontExA {}
// SAFETY: as above.
unsafe impl Pod for FontEnumRecord {}

/// The narrow TEXTMETRIC of a TrueType font's wide `metric`, as GetTextMetricsA answers it: every
/// number as it is, and the four characters as the ANSI code page sees the font rather than
/// converted: the default character the wide one, the first one below it, the last one 0xFF at
/// most, the break character the wide one. (The capture of Windows 2000 on the fixtures' font
/// answers its wide 0x20, 0xFEFC, 0x1F and 0x20 as 0x1E, 0xFF, 0x1F and 0x20.)
pub fn narrow_truetype_metric(metric: &TextMetricW) -> TextMetricA {
    let byte = |unit: u16| unit.min(0xFF) as u8;
    let mut narrow = narrow_text_metric(metric, byte);
    narrow.default_char = byte(metric.default_char);
    narrow.first_char = narrow.default_char.saturating_sub(1);
    narrow.last_char = byte(metric.last_char);
    narrow.break_char = byte(metric.break_char);
    narrow
}

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
        assert_eq!(size_of::<LogFontW>(), 92);
        assert_eq!(size_of::<LogFontA>(), 60);
        assert_eq!(size_of::<Abc>(), 12);
        assert_eq!(size_of::<OutlineTextMetricW>(), 216);
        assert_eq!(size_of::<OutlineTextMetricA>(), 212);
        assert_eq!(offset_of!(OutlineTextMetricW, panose), 65);
        assert_eq!(offset_of!(OutlineTextMetricW, fields), 76);
        assert_eq!(offset_of!(OutlineTextMetricA, fields), 72);
        assert_eq!(size_of::<NewTextMetricW>(), 76);
        assert_eq!(size_of::<NewTextMetricA>(), 72);
        assert_eq!(size_of::<NewTextMetricExW>(), 100);
        assert_eq!(size_of::<NewTextMetricExA>(), 96);
        assert_eq!(size_of::<EnumLogFontExW>(), 348);
        assert_eq!(size_of::<EnumLogFontExA>(), 188);
    }

    /// A TrueType font's narrow metrics: the characters as the capture shows them, 0x20, 0xFEFC,
    /// 0x1F and 0x20 answered as 0x1E, 0xFF, 0x1F and 0x20.
    #[test]
    fn a_truetype_fonts_narrow_characters() {
        let wide = TextMetricW {
            height: 13,
            first_char: 0x20,
            last_char: 0xFEFC,
            default_char: 0x1F,
            break_char: 0x20,
            ..TextMetricW::default()
        };
        let narrow = narrow_truetype_metric(&wide);
        assert_eq!(narrow.height, 13);
        assert_eq!(
            (
                narrow.first_char,
                narrow.last_char,
                narrow.default_char,
                narrow.break_char
            ),
            (0x1E, 0xFF, 0x1F, 0x20)
        );
    }

    /// A LOGFONT's face name converts both ways, and the rest of its fields go as they are.
    #[test]
    fn log_fonts_convert() {
        let mut wide = LogFontW::zeroed();
        wide.height = -11;
        wide.weight = FW_BOLD;
        wide.char_set = DEFAULT_CHARSET;
        for (unit, byte) in wide.face_name.iter_mut().zip(b"F2K Tahoma") {
            *unit = u16::from(*byte);
        }
        assert_eq!(wide.face().len(), 10);
        let narrow = narrow_log_font(&wide, |out, units| {
            for (byte, &unit) in out.iter_mut().zip(units) {
                *byte = unit as u8;
            }
            units.len().min(out.len())
        });
        assert_eq!(&narrow.face_name[..11], b"F2K Tahoma\0");
        assert_eq!(
            (narrow.height, narrow.weight, narrow.char_set),
            (-11, 700, 1)
        );
        let back = wide_log_font(&narrow, |out, bytes| {
            for (unit, &byte) in out.iter_mut().zip(bytes) {
                *unit = u16::from(byte);
            }
            bytes.len().min(out.len())
        });
        assert_eq!(back, wide);
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

    /// The global brushes: the stock brushes, the system colors' and the gray one, each named by
    /// its handle alone, of the brush kind; a stock pen, a past-the-table color and a handle
    /// table's handle are none.
    #[test]
    fn the_global_brushes_name_themselves() {
        let white = stock_handle(WHITE_BRUSH).unwrap();
        assert_eq!(global_brush(white), Some(GlobalBrush::Stock(WHITE_BRUSH)));
        assert_eq!(global_brush(stock_handle(BLACK_PEN).unwrap()), None);
        for index in 0..crate::display::SYSTEM_COLORS as u32 {
            let brush = sys_color_brush(index).unwrap();
            assert_eq!(global_brush(brush), Some(GlobalBrush::SysColor(index)));
            assert_eq!(global_object_kind(brush), Some(OBJ_BRUSH));
            assert_eq!(stock_object(brush), None, "no stock object");
            assert_ne!(brush, HALFTONE_BRUSH);
        }
        assert_eq!(sys_color_brush(29), None);
        assert_eq!(global_brush(sys_color_brush(0).unwrap() + 29), None);
        assert_eq!(global_brush(HALFTONE_BRUSH), Some(GlobalBrush::Halftone));
        assert_eq!(global_object_kind(HALFTONE_BRUSH), Some(OBJ_BRUSH));
        assert_eq!(
            global_object_kind(stock_handle(SYSTEM_FONT).unwrap()),
            Some(OBJ_FONT)
        );
        assert_eq!(global_brush(0x7C), None);
        assert_eq!(global_object_kind(0x7C), None);
        // GetSysColorBrush's handles before brushes were objects: the same values.
        assert_eq!(sys_color_brush(5), Some(0x0082_0045));
    }

    /// A process's object handle carries its kind above the handle table's handle, and gives both
    /// back; a DC's bare handle, a global object's and a value past the shape carry none.
    #[test]
    fn object_handles_carry_their_kind() {
        let brush = object_handle(OBJ_BRUSH, 0x1C);
        assert_eq!(brush, 0x0002_001C);
        assert!(
            brush as usize > crate::display::SYSTEM_COLORS,
            "no COLOR_* + 1"
        );
        assert_eq!(object_of(brush), Some((OBJ_BRUSH, 0x1C)));
        assert_eq!(object_kind(brush), Some(OBJ_BRUSH));
        assert_eq!(
            object_of(object_handle(OBJ_FONT, 0xFFC)),
            Some((OBJ_FONT, 0xFFC))
        );
        assert_eq!(object_of(0x1C), None, "a DC's handle");
        assert_eq!(object_kind(0x1C), None);
        assert_eq!(object_of(stock_handle(WHITE_BRUSH).unwrap()), None);
        assert_eq!(
            object_kind(stock_handle(WHITE_BRUSH).unwrap()),
            Some(OBJ_BRUSH)
        );
        assert_eq!(object_of(HALFTONE_BRUSH), None);
        assert_eq!(object_of(0x0102_001C), None);
    }

    /// The raster operations PatBlt takes evaluate as their names say, bit by bit; a source's
    /// operation (SRCCOPY) is no PatBlt's.
    #[test]
    fn the_raster_operations_evaluate_their_tables() {
        let (p, d) = (0x00FF_00F0u32, 0x00F0_F0F0u32);
        assert_eq!(apply_rop(PATCOPY, p, d) & RGB_MASK, p);
        assert_eq!(apply_rop(PATINVERT, p, d) & RGB_MASK, p ^ d);
        assert_eq!(apply_rop(DSTINVERT, p, d) & RGB_MASK, !d & RGB_MASK);
        assert_eq!(apply_rop(BLACKNESS, p, d) & RGB_MASK, 0);
        assert_eq!(apply_rop(WHITENESS, p, d) & RGB_MASK, RGB_MASK);
        for rop in [PATCOPY, PATINVERT, DSTINVERT, BLACKNESS, WHITENESS] {
            assert!(rop_is_sourceless(rop), "{rop:#x}");
        }
        const SRCCOPY: u32 = 0x00CC_0020;
        assert!(!rop_is_sourceless(SRCCOPY));
        assert!(rop_uses_pattern(PATCOPY) && rop_uses_pattern(PATINVERT));
        assert!(!rop_uses_pattern(DSTINVERT) && !rop_uses_pattern(BLACKNESS));
        assert!(rop_uses_destination(PATINVERT) && rop_uses_destination(DSTINVERT));
        assert!(!rop_uses_destination(PATCOPY) && !rop_uses_destination(WHITENESS));
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
