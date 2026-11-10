//! A face's metrics at a size, as GDI answers them for a TrueType font: its TEXTMETRIC
//! ([`text_metric`]), OUTLINETEXTMETRIC's members ([`outline_fields`]), the character sets and
//! signature an enumeration reports ([`char_sets`], [`signature`]), and a glyph's advance and ABC
//! spacing with the emboldening GDI synthesises for a bold request of a face that has no bold of
//! its own ([`embolden`], [`abc`]).
//!
//! The capture of Windows 2000 on the fixtures' font (tests/gdi32/ttfont/output.txt) settles what
//! the public documentation leaves open:
//! - a metric is the font-unit value scaled to the size and rounded to the nearest pixel (a half
//!   up); at an em size, through 26.6 as the outlines are scaled;
//! - the ascent and descent are OS/2's Windows pair (hhea's when the font has no OS/2), the
//!   internal leading what the cell holds beyond the em, the widest character the head table's
//!   bounding box;
//! - the default character is the one before the first, and the cap height and x-height
//!   OUTLINETEXTMETRIC answers are half and a quarter of the em, not OS/2's version-2 fields (the
//!   capture's 6 and 3 at 11 pixels per em, 12 and 6 at 24, where the font says 1489 and 1120
//!   units);
//! - a synthesised bold advances every character a pixel further, its ink a pixel wider (each
//!   glyph's black box, the average and widest widths), its ascent, descent and overhang unchanged;
//! - an enumeration describes the face at a cell of 39 pixels (an em of 32, in the cell's
//!   proportion): see [`ENUMERATION_CELL`].

use super::glyph::{stride, GlyphMetrics, Rendered};
use super::header::{Os2, Post};
use super::scale::{round_pixel, Scale};
use super::{Error, Font};
use crate::gdi::{
    Abc,
    FontSignature,
    OutlineFields,
    Point,
    Rect,
    TextMetricW,
    FF_DECORATIVE,
    FF_DONTCARE,
    FF_MODERN,
    FF_ROMAN,
    FF_SCRIPT,
    FF_SWISS,
    FW_BOLD,
    TMPF_FIXED_PITCH,
    TMPF_TRUETYPE,
    TMPF_VECTOR,
};

/// The size a face is realised at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Size {
    /// An em of this many pixels (a realised font's: [`super::glyph::ppem_for_height`]).
    Em(u16),
    /// A cell (ascent plus descent) of this many pixels, the em in proportion (the
    /// enumeration's).
    Cell(u16),
}

/// The cell height an enumeration describes a face at: the capture's 39 for the fixtures' font,
/// whose cell is 2472 units of a 2048-unit em, so an em of 32 pixels. Its ascent of 32, descent of
/// 7, average width of 14 and widest character of 47 come from scaling by 39/2472; at an em of 32
/// pixels the widest would be 46.
pub const ENUMERATION_CELL: u16 = 39;

/// The weight from which a request of a face whose own weight is below it is emboldened:
/// FW_SEMIBOLD.
pub const EMBOLDEN_FROM: i32 = 600;

/// The ascent and descent a face's cell is made of, in font units: OS/2's Windows pair, else
/// hhea's.
fn cell_units(font: &Font, os2: Option<&Os2>) -> (i32, i32) {
    match os2 {
        Some(os2) if os2.us_win_ascent as u32 + os2.us_win_descent as u32 > 0 => {
            (os2.us_win_ascent as i32, os2.us_win_descent as i32)
        }
        _ => (font.hhea.ascender as i32, -(font.hhea.descender as i32)),
    }
}

/// A size's scaling of font units to whole pixels.
#[derive(Clone, Copy, Debug)]
struct Scaler {
    size: Size,
    units_per_em: u16,
    cell: i32,
}

impl Scaler {
    fn new(font: &Font, os2: Option<&Os2>, size: Size) -> Self {
        let (ascent, descent) = cell_units(font, os2);
        Scaler {
            size,
            units_per_em: font.head.units_per_em,
            cell: (ascent + descent).max(1),
        }
    }

    /// `units` font units in whole pixels, to the nearest (a half up).
    fn pixels(&self, units: i32) -> i32 {
        match self.size {
            Size::Em(ppem) => round_pixel(Scale::pixels(ppem, self.units_per_em).apply(units)),
            Size::Cell(cell) => rounded(units as i64 * cell as i64, self.cell as i64),
        }
    }

    /// The em, in whole pixels.
    fn em(&self) -> i32 {
        match self.size {
            Size::Em(ppem) => ppem as i32,
            Size::Cell(cell) => rounded(self.units_per_em as i64 * cell as i64, self.cell as i64),
        }
    }
}

/// `numerator / denominator` to the nearest whole number, a half up (`denominator` positive).
fn rounded(numerator: i64, denominator: i64) -> i32 {
    (2 * numerator + denominator)
        .div_euclid(2 * denominator)
        .clamp(i32::MIN as i64, i32::MAX as i64) as i32
}

/// The family a face belongs to (tmPitchAndFamily's high nibble), from its OS/2 family class
/// (IBM's classes: serifs of every kind are roman, the sans serifs swiss, the scripts script, the
/// ornamentals and the symbols decorative), else its PANOSE number's family and serif style.
pub fn family(os2: Option<&Os2>) -> u8 {
    let Some(os2) = os2 else {
        return FF_DONTCARE;
    };
    match os2.s_family_class >> 8 {
        1..=5 | 7 => return FF_ROMAN,
        8 => return FF_SWISS,
        9 | 12 => return FF_DECORATIVE,
        10 => return FF_SCRIPT,
        _ => {}
    }
    match (os2.panose[0], os2.panose[1]) {
        (2, 11..=13) => FF_SWISS,
        (2, 2..=10) => FF_ROMAN,
        (3, _) => FF_SCRIPT,
        (4 | 5, _) => FF_DECORATIVE,
        _ if os2.panose[3] == 9 => FF_MODERN,
        _ => FF_DONTCARE,
    }
}

/// Whether the face's characters all advance alike (post's isFixedPitch).
pub fn fixed_pitch(post: Option<&Post>) -> bool {
    post.is_some_and(|post| post.is_fixed_pitch != 0)
}

/// The face's own weight: OS/2's weight class, FW_BOLD for a face the head table marks bold.
pub fn weight(font: &Font, os2: Option<&Os2>) -> i32 {
    match os2 {
        Some(os2) if os2.us_weight_class != 0 => os2.us_weight_class as i32,
        _ if font.head.mac_style & 1 != 0 => FW_BOLD,
        _ => crate::gdi::FW_NORMAL,
    }
}

/// Whether a request of `requested` weight emboldens the face (a face lighter than semibold asked
/// for semibold or more).
pub fn emboldens(font: &Font, os2: Option<&Os2>, requested: i32) -> bool {
    requested >= EMBOLDEN_FROM && weight(font, os2) < EMBOLDEN_FROM
}

/// The face's TEXTMETRICW at `size`, emboldened when `bold`, its character set `char_set`. See the
/// module notes.
pub fn text_metric(
    font: &Font,
    size: Size,
    bold: bool,
    char_set: u8,
) -> Result<TextMetricW, Error> {
    let os2 = font.os2()?;
    let post = font.post()?;
    let scaler = Scaler::new(font, os2.as_ref(), size);
    let (ascent_units, descent_units) = cell_units(font, os2.as_ref());
    let ascent = scaler.pixels(ascent_units);
    let descent = scaler.pixels(descent_units);
    let height = ascent + descent;
    // The OpenType specification's Windows external leading: hhea's line gap less what the
    // Windows pair holds beyond hhea's ascender and descender, never below zero.
    let hhea = &font.hhea;
    let extra = (ascent_units + descent_units) - (hhea.ascender as i32 - hhea.descender as i32);
    let external = scaler.pixels((hhea.line_gap as i32 - extra).max(0));
    let widen = bold as i32;
    let average = match &os2 {
        Some(os2) if os2.x_avg_char_width > 0 => os2.x_avg_char_width as i32,
        _ => font.hhea.advance_width_max as i32 / 2,
    };
    let widest = font.head.x_max as i32 - font.head.x_min as i32;
    let (first, last, break_char) = match &os2 {
        Some(os2) => (
            os2.us_first_char_index,
            os2.us_last_char_index,
            if os2.us_break_char != 0 {
                os2.us_break_char
            } else {
                0x20
            },
        ),
        None => (0x20, 0xFFFF, 0x20),
    };
    let italic =
        os2.as_ref().is_some_and(|os2| os2.fs_selection & 1 != 0) || font.head.mac_style & 2 != 0;
    let mut pitch_and_family = family(os2.as_ref()) | TMPF_TRUETYPE | TMPF_VECTOR;
    if !fixed_pitch(post.as_ref()) {
        pitch_and_family |= TMPF_FIXED_PITCH;
    }
    Ok(TextMetricW {
        height,
        ascent,
        descent,
        internal_leading: height - scaler.em(),
        external_leading: external,
        ave_char_width: scaler.pixels(average) + widen,
        max_char_width: scaler.pixels(widest) + widen,
        weight: if bold {
            FW_BOLD
        } else {
            weight(font, os2.as_ref())
        },
        overhang: 0,
        digitized_aspect_x: 96,
        digitized_aspect_y: 96,
        first_char: first,
        last_char: last,
        default_char: first.saturating_sub(1),
        break_char,
        italic: if italic { 0xFF } else { 0 },
        underlined: 0,
        struck_out: 0,
        pitch_and_family,
        char_set,
        padding: [0; 3],
    })
}

/// OUTLINETEXTMETRIC's members after the TEXTMETRIC and PANOSE (the PANOSE number is the OS/2
/// table's: [`panose`]) at `size`; the four names' offsets are the caller's to fill. See the
/// module notes.
pub fn outline_fields(font: &Font, size: Size) -> Result<OutlineFields, Error> {
    let os2 = font.os2()?;
    let post = font.post()?;
    let scaler = Scaler::new(font, os2.as_ref(), size);
    let px = |units: i32| scaler.pixels(units);
    let hhea = &font.hhea;
    let head = &font.head;
    let units_per_em = head.units_per_em as i32;
    let (typo_ascent, typo_descent, typo_gap) = match &os2 {
        Some(os2) => (
            os2.s_typo_ascender as i32,
            os2.s_typo_descender as i32,
            os2.s_typo_line_gap as i32,
        ),
        None => (
            hhea.ascender as i32,
            hhea.descender as i32,
            hhea.line_gap as i32,
        ),
    };
    let os2_value = |value: fn(&Os2) -> i16| os2.as_ref().map_or(0, |os2| value(os2) as i32);
    let (underline_position, underline_thickness) = post.as_ref().map_or((0, 0), |post| {
        (
            post.underline_position as i32,
            post.underline_thickness as i32,
        )
    });
    let point = |x: i32, y: i32| Point { x: px(x), y: px(y) };
    Ok(OutlineFields {
        fs_selection: os2.as_ref().map_or(0, |os2| os2.fs_selection as u32),
        fs_type: os2.as_ref().map_or(0, |os2| os2.fs_type as u32),
        char_slope_rise: hhea.caret_slope_rise as i32,
        char_slope_run: hhea.caret_slope_run as i32,
        italic_angle: post
            .as_ref()
            .map_or(0, |post| ((post.italic_angle as i64 * 10) >> 16) as i32),
        em_square: units_per_em as u32,
        ascent: px(typo_ascent),
        descent: px(typo_descent),
        line_gap: px(typo_gap).max(0) as u32,
        cap_em_height: px(units_per_em / 2).max(0) as u32,
        x_height: px(units_per_em / 4).max(0) as u32,
        font_box: Rect {
            left: px(head.x_min as i32),
            top: px(head.y_max as i32),
            right: px(head.x_max as i32),
            bottom: px(head.y_min as i32),
        },
        mac_ascent: px(hhea.ascender as i32),
        mac_descent: px(hhea.descender as i32),
        mac_line_gap: px(hhea.line_gap as i32).max(0) as u32,
        minimum_ppem: head.lowest_rec_ppem as u32,
        subscript_size: point(
            os2_value(|os2| os2.y_subscript_x_size),
            os2_value(|os2| os2.y_subscript_y_size),
        ),
        subscript_offset: point(
            os2_value(|os2| os2.y_subscript_x_offset),
            os2_value(|os2| os2.y_subscript_y_offset),
        ),
        superscript_size: point(
            os2_value(|os2| os2.y_superscript_x_size),
            os2_value(|os2| os2.y_superscript_y_size),
        ),
        superscript_offset: point(
            os2_value(|os2| os2.y_superscript_x_offset),
            os2_value(|os2| os2.y_superscript_y_offset),
        ),
        strikeout_size: px(os2_value(|os2| os2.y_strikeout_size)).max(0) as u32,
        strikeout_position: px(os2_value(|os2| os2.y_strikeout_position)),
        underscore_size: px(underline_thickness),
        underscore_position: px(underline_position),
        family_name: 0,
        face_name: 0,
        style_name: 0,
        full_name: 0,
    })
}

/// The face's PANOSE number (zeros without an OS/2 table).
pub fn panose(font: &Font) -> Result<[u8; 10], Error> {
    Ok(font.os2()?.map_or([0; 10], |os2| os2.panose))
}

/// The face's signature: its OS/2 table's Unicode ranges and code-page ranges (the code pages
/// ANSI's alone without them).
pub fn signature(font: &Font) -> Result<FontSignature, Error> {
    let os2 = font.os2()?;
    Ok(match os2 {
        Some(os2) if os2.version >= 1 => FontSignature {
            usb: os2.ul_unicode_range,
            csb: os2.ul_code_page_range,
        },
        Some(os2) => FontSignature {
            usb: os2.ul_unicode_range,
            csb: [1, 0],
        },
        None => FontSignature {
            usb: [0; 4],
            csb: [1, 0],
        },
    })
}

/// The character sets a face's code pages give, as an enumeration lists them: the code-page
/// bit, the character set, its script's name.
///
/// The order is Windows 2000's as far as the capture shows it (Western, Arabic, Turkish, Central
/// European, Cyrillic, for the fixtures' font); the character sets it does not show follow in the
/// code-page bits' order, an assumption.
pub const CHAR_SETS: [(u32, u8, &str); 16] = [
    (0, 0, "Western"),
    (6, 178, "Arabic"),
    (4, 162, "Turkish"),
    (1, 238, "Central European"),
    (2, 204, "Cyrillic"),
    (3, 161, "Greek"),
    (5, 177, "Hebrew"),
    (7, 186, "Baltic"),
    (8, 163, "Vietnamese"),
    (16, 222, "Thai"),
    (17, 128, "Japanese"),
    (18, 134, "CHINESE_GB2312"),
    (19, 129, "Hangul"),
    (20, 136, "CHINESE_BIG5"),
    (21, 130, "Johab"),
    (31, 2, "Symbol"),
];

/// The character sets the face covers, in enumeration order: (character set, script name).
pub fn char_sets(signature: &FontSignature) -> impl Iterator<Item = (u8, &'static str)> + '_ {
    CHAR_SETS
        .iter()
        .filter(|(bit, _, _)| signature.csb[0] & (1 << bit) != 0)
        .map(|&(_, char_set, script)| (char_set, script))
}

/// The character set a realised font answers for a request of `requested`: that one when the face
/// covers it, else the face's first (ANSI's for a Western font); DEFAULT_CHARSET asks for the
/// first.
pub fn realised_char_set(signature: &FontSignature, requested: u8) -> u8 {
    let mut sets = char_sets(signature);
    let first = sets.next().map_or(0, |(set, _)| set);
    if requested == first || char_sets(signature).any(|(set, _)| set == requested) {
        requested
    } else {
        first
    }
}

/// A glyph's GGO_BITMAP rendering emboldened as GDI synthesises a bold: its ink a pixel wider (the
/// bitmap ORed with itself a pixel to the right, in place when `bits` holds it; a blank glyph
/// keeps its 1-by-1 box), its advance a pixel longer. The answer's size is the widened bitmap's;
/// `bits` must hold it (none otherwise, the bitmap left).
pub fn embolden(rendered: Rendered, bits: Option<&mut [u8]>) -> Option<Rendered> {
    let mut wider = rendered;
    wider.metrics.cell_inc_x = rendered.metrics.cell_inc_x.saturating_add(1);
    if rendered.size == 0 {
        return Some(wider);
    }
    let old = rendered.metrics;
    let width = old.black_box_x + 1;
    let height = old.black_box_y as usize;
    wider.metrics.black_box_x = width;
    wider.size = stride(width) * height;
    let Some(bits) = bits else {
        return Some(wider);
    };
    if bits.len() < wider.size {
        return None;
    }
    let (from, to) = (stride(old.black_box_x), stride(width));
    // Rows from the last, so a wider stride never overwrites a row not yet moved.
    for row in (0..height).rev() {
        let mut carry = 0u8;
        for column in 0..to {
            let byte = if column < from {
                bits[row * from + column]
            } else {
                0
            };
            bits[row * to + column] = byte | (byte >> 1) | carry;
            carry = byte << 7;
        }
    }
    Some(wider)
}

/// The A, B and C spacing of a glyph whose GetGlyphOutline metrics are `metrics`: A the black
/// box's left, B its width, C what the advance leaves after them.
pub fn abc(metrics: &GlyphMetrics) -> Abc {
    let a = metrics.origin_x;
    let b = metrics.black_box_x;
    Abc {
        a,
        b,
        c: metrics.cell_inc_x as i32 - a - b as i32,
    }
}

/// GetGlyphOutline's answer for GGO_METRICS: the size of the glyph as Windows 2000's glyph cache
/// keeps its bits, a 16-byte header and the black box's rows each in whole bytes, rounded up to
/// 32 bits (the capture's 24 for an 'A' of 6 by 8, 20 for the blank space).
pub fn metrics_size(metrics: &GlyphMetrics) -> u32 {
    let row = metrics.black_box_x.div_ceil(8);
    (16 + row * metrics.black_box_y).next_multiple_of(4)
}

#[cfg(test)]
mod tests {
    use std::string::String;
    use std::vec::Vec;
    use std::{format, vec};

    use super::super::glyf::Point as OutlinePoint;
    use super::super::glyph::{self, Options, Workspace};
    use super::super::raster::Crossing;
    use super::super::tests::{capture_section, fixture_font};
    use super::*;

    /// A field of a capture line, `name=value`.
    fn field(line: &str, name: &str) -> String {
        let at = line
            .find(&format!(" {name}="))
            .unwrap_or_else(|| panic!("{name} in {line}"))
            + name.len()
            + 2;
        line[at..].split(' ').next().unwrap().into()
    }

    fn number(line: &str, name: &str) -> i32 {
        let text = field(line, name);
        match text.strip_prefix("0x") {
            Some(hex) => i32::from_str_radix(hex, 16).unwrap(),
            None => text.parse().unwrap(),
        }
    }

    /// The capture's TEXTMETRICW lines for each height and weight: GetTextMetricsW's three lines
    /// after each `-- lfHeight` heading.
    fn captured_metrics() -> Vec<(i32, i32, String)> {
        let mut found = Vec::new();
        let mut heading = None;
        let mut lines = capture_section("metrics").into_iter();
        while let Some(line) = lines.next() {
            if let Some(rest) = line.strip_prefix("-- lfHeight ") {
                let (height, weight) = rest.split_once(", lfWeight ").unwrap();
                heading = Some((height.parse().unwrap(), weight.parse().unwrap()));
            } else if line.starts_with("GetTextMetricsW") {
                let joined: Vec<String> = (0..3).map(|_| lines.next().unwrap()).collect();
                let (height, weight) = heading.unwrap();
                found.push((height, weight, joined.join(" ")));
            }
        }
        found
    }

    /// Every TEXTMETRICW field the capture shows, at every height and both weights.
    #[test]
    fn text_metrics_match_the_capture() {
        let data = fixture_font();
        let font = Font::new(&data).unwrap();
        let os2 = font.os2().unwrap();
        let captured = captured_metrics();
        assert_eq!(captured.len(), 10);
        for (height, weight, line) in captured {
            let ppem = glyph::ppem_for_height(&font, height).unwrap();
            let bold = emboldens(&font, os2.as_ref(), weight);
            assert_eq!(bold, weight == 700);
            let metric = text_metric(&font, Size::Em(ppem), bold, 0).unwrap();
            let name = format!("lfHeight {height}, lfWeight {weight}");
            for (label, ours) in [
                ("tmHeight", metric.height),
                ("tmAscent", metric.ascent),
                ("tmDescent", metric.descent),
                ("tmInternalLeading", metric.internal_leading),
                ("tmExternalLeading", metric.external_leading),
                ("tmAveCharWidth", metric.ave_char_width),
                ("tmMaxCharWidth", metric.max_char_width),
                ("tmWeight", metric.weight),
                ("tmOverhang", metric.overhang),
                ("tmDigitizedAspectX", metric.digitized_aspect_x),
                ("tmDigitizedAspectY", metric.digitized_aspect_y),
                ("tmFirstChar", metric.first_char as i32),
                ("tmLastChar", metric.last_char as i32),
                ("tmDefaultChar", metric.default_char as i32),
                ("tmBreakChar", metric.break_char as i32),
                ("tmItalic", metric.italic as i32),
                ("tmUnderlined", metric.underlined as i32),
                ("tmStruckOut", metric.struck_out as i32),
                ("tmPitchAndFamily", metric.pitch_and_family as i32),
                ("tmCharSet", metric.char_set as i32),
            ] {
                assert_eq!(ours, number(&line, label), "{name}: {label}");
            }
        }
    }

    /// GetOutlineTextMetricsW's numbers at -11 and -24.
    #[test]
    fn outline_metrics_match_the_capture() {
        let data = fixture_font();
        let font = Font::new(&data).unwrap();
        let lines = capture_section("metrics");
        let mut checked = 0;
        for (height, ppem) in [(-11, 11), (-24, 24)] {
            let heading = format!("-- lfHeight {height}, lfWeight 400");
            let at = lines.iter().position(|line| *line == heading).unwrap();
            let block: Vec<&String> = lines[at..]
                .iter()
                .skip_while(|line| !line.starts_with("  otmSize="))
                .take(8)
                .collect();
            let joined = block
                .iter()
                .map(|line| line.as_str())
                .collect::<Vec<_>>()
                .join(" ");
            let fields = outline_fields(&font, Size::Em(ppem)).unwrap();
            let pair = |name: &str| -> (i32, i32) {
                let text = field(&joined, name);
                let (x, y) = text.split_once(',').unwrap();
                (x.parse().unwrap(), y.parse().unwrap())
            };
            assert_eq!(
                fields.fs_selection as i32,
                number(&joined, "otmfsSelection")
            );
            assert_eq!(fields.fs_type as i32, number(&joined, "otmfsType"));
            assert_eq!(fields.char_slope_rise, number(&joined, "otmsCharSlopeRise"));
            assert_eq!(fields.char_slope_run, number(&joined, "otmsCharSlopeRun"));
            assert_eq!(fields.italic_angle, number(&joined, "otmItalicAngle"));
            assert_eq!(fields.em_square as i32, number(&joined, "otmEMSquare"));
            assert_eq!(fields.ascent, number(&joined, "otmAscent"));
            assert_eq!(fields.descent, number(&joined, "otmDescent"));
            assert_eq!(fields.line_gap as i32, number(&joined, "otmLineGap"));
            assert_eq!(
                fields.cap_em_height as i32,
                number(&joined, "otmsCapEmHeight")
            );
            assert_eq!(fields.x_height as i32, number(&joined, "otmsXHeight"));
            let at = joined.find("otmrcFontBox=").unwrap() + "otmrcFontBox=".len();
            let rect: Vec<i32> = joined[at..]
                .split(' ')
                .take(4)
                .map(|value| value.parse().unwrap())
                .collect();
            let font_box = fields.font_box;
            assert_eq!(
                rect,
                [font_box.left, font_box.top, font_box.right, font_box.bottom]
            );
            assert_eq!(fields.mac_ascent, number(&joined, "otmMacAscent"));
            assert_eq!(fields.mac_descent, number(&joined, "otmMacDescent"));
            assert_eq!(fields.mac_line_gap as i32, number(&joined, "otmMacLineGap"));
            assert_eq!(
                fields.minimum_ppem as i32,
                number(&joined, "otmusMinimumPPEM")
            );
            let as_pair = |point: Point| (point.x, point.y);
            assert_eq!(as_pair(fields.subscript_size), pair("otmptSubscriptSize"));
            assert_eq!(
                as_pair(fields.subscript_offset),
                pair("otmptSubscriptOffset")
            );
            assert_eq!(
                as_pair(fields.superscript_size),
                pair("otmptSuperscriptSize")
            );
            assert_eq!(
                as_pair(fields.superscript_offset),
                pair("otmptSuperscriptOffset")
            );
            assert_eq!(
                fields.strikeout_size as i32,
                number(&joined, "otmsStrikeoutSize")
            );
            assert_eq!(
                fields.strikeout_position,
                number(&joined, "otmsStrikeoutPosition")
            );
            assert_eq!(
                fields.underscore_size,
                number(&joined, "otmsUnderscoreSize")
            );
            assert_eq!(
                fields.underscore_position,
                number(&joined, "otmsUnderscorePosition")
            );
            let panose_at = joined.find("otmPanoseNumber=").unwrap() + "otmPanoseNumber=".len();
            let captured: Vec<u8> = joined[panose_at..]
                .split(' ')
                .take(10)
                .map(|value| value.parse().unwrap())
                .collect();
            assert_eq!(captured, panose(&font).unwrap());
            checked += 1;
        }
        assert_eq!(checked, 2);
    }

    /// The enumeration's TEXTMETRIC (its cell of 39 pixels), signature and character sets.
    #[test]
    fn the_enumeration_matches_the_capture() {
        let data = fixture_font();
        let font = Font::new(&data).unwrap();
        let metric = text_metric(&font, Size::Cell(ENUMERATION_CELL), false, 0).unwrap();
        assert_eq!(
            (
                metric.height,
                metric.ascent,
                metric.descent,
                metric.internal_leading,
                metric.ave_char_width,
                metric.max_char_width
            ),
            (39, 32, 7, 7, 14, 47)
        );
        let signature = signature(&font).unwrap();
        assert_eq!(signature.usb, [0x8000_22EF, 0xC000_205A, 0x0000_0008, 0]);
        assert_eq!(signature.csb, [0x2000_0057, 0x0008_0000]);
        let sets: Vec<(u8, &str)> = char_sets(&signature).collect();
        assert_eq!(
            sets,
            [
                (0, "Western"),
                (178, "Arabic"),
                (162, "Turkish"),
                (238, "Central European"),
                (204, "Cyrillic")
            ]
        );
        assert_eq!(realised_char_set(&signature, 1), 0);
        assert_eq!(realised_char_set(&signature, 204), 204);
        assert_eq!(realised_char_set(&signature, 128), 0);
        assert_eq!(family(font.os2().unwrap().as_ref()), FF_SWISS);
    }

    fn rendered(font: &Font, character: u32, ppem: u16) -> (Rendered, Vec<u8>) {
        let mut points = vec![OutlinePoint::default(); 512];
        let mut ends = vec![0u16; 64];
        let mut crossings = vec![Crossing::default(); 256];
        let mut workspace = Workspace {
            points: &mut points,
            contour_ends: &mut ends,
            crossings: &mut crossings,
        };
        let glyph = font
            .cmap()
            .unwrap()
            .unicode()
            .unwrap()
            .unwrap()
            .glyph(character);
        let options = Options::new(ppem);
        let sized = glyph::render(font, glyph, &options, &mut workspace, &mut []).unwrap();
        let mut bits = vec![0; sized.size + 64];
        let done = glyph::render(font, glyph, &options, &mut workspace, &mut bits).unwrap();
        (done, bits)
    }

    /// GetCharABCWidthsW at every weight-400 height: A, B and C from each glyph's metrics; and
    /// the bold rows at -11 and -24 from the emboldened metrics.
    #[test]
    fn abc_widths_match_the_capture() {
        let data = fixture_font();
        let font = Font::new(&data).unwrap();
        let mut heading = None;
        let mut checked = 0;
        let mut in_abc = false;
        let mut values: Vec<i32> = Vec::new();
        let mut finish = |heading: Option<(i32, i32)>, values: &mut Vec<i32>| {
            let Some((height, weight)) = heading else {
                return;
            };
            if values.is_empty() {
                return;
            }
            assert_eq!(values.len(), 95 * 3);
            let ppem = glyph::ppem_for_height(&font, height).unwrap();
            for (index, triple) in values.chunks(3).enumerate() {
                let character = 0x20 + index as u32;
                let (mut done, mut bits) = rendered(&font, character, ppem);
                if weight == 700 {
                    done = embolden(done, Some(&mut bits)).unwrap();
                }
                let ours = abc(&done.metrics);
                assert_eq!(
                    [ours.a, ours.b as i32, ours.c],
                    triple,
                    "lfHeight {height} lfWeight {weight} {character:#x}"
                );
                checked += 1;
            }
            values.clear();
        };
        for line in capture_section("widths") {
            if let Some(rest) = line.strip_prefix("-- lfHeight ") {
                finish(heading, &mut values);
                let (height, weight) = rest.split_once(", lfWeight ").unwrap();
                heading = Some((height.parse().unwrap(), weight.parse().unwrap()));
                in_abc = false;
            } else if line.starts_with("GetCharABCWidthsW") {
                in_abc = true;
            } else if line.starts_with("GetCharABCWidthsA") {
                in_abc = false;
            } else if in_abc {
                let (_, numbers) = line.split_once(": ").unwrap();
                values.extend(
                    numbers
                        .split(' ')
                        .map(|value| value.parse::<i32>().unwrap()),
                );
            }
        }
        finish(heading, &mut values);
        // Five heights at weight 400, two at 700.
        assert_eq!(checked, 95 * 7);
    }

    /// Emboldening widens a glyph's rows by a pixel, the ink ORed a pixel to the right, across a
    /// row's 32-bit boundary too; a blank glyph keeps its box and advances a pixel further.
    #[test]
    fn emboldening_widens_the_ink() {
        let one_row = Rendered {
            metrics: GlyphMetrics {
                black_box_x: 32,
                black_box_y: 1,
                origin_x: 0,
                origin_y: 1,
                cell_inc_x: 33,
                cell_inc_y: 0,
            },
            source: glyph::Source::Outline,
            size: 4,
        };
        let mut bits = vec![0x81, 0x00, 0x00, 0x01, 0xEE, 0xEE, 0xEE, 0xEE];
        let wider = embolden(one_row, Some(&mut bits)).unwrap();
        assert_eq!(
            (wider.metrics.black_box_x, wider.metrics.cell_inc_x),
            (33, 34)
        );
        assert_eq!(wider.size, 8);
        assert_eq!(bits, [0xC1, 0x80, 0x00, 0x01, 0x80, 0, 0, 0]);
        let blank = Rendered {
            size: 0,
            metrics: GlyphMetrics {
                black_box_x: 1,
                black_box_y: 1,
                cell_inc_x: 3,
                ..GlyphMetrics::default()
            },
            ..one_row
        };
        let wider = embolden(blank, None).unwrap();
        assert_eq!(
            (
                wider.metrics.black_box_x,
                wider.metrics.cell_inc_x,
                wider.size
            ),
            (1, 4, 0)
        );
        assert!(embolden(one_row, Some(&mut [0; 4])).is_none(), "too small");
    }

    /// GGO_METRICS' answer is the glyph cache's size of the glyph: the capture's at -11 and -24.
    #[test]
    fn the_metrics_size_matches_the_capture() {
        let data = fixture_font();
        let font = Font::new(&data).unwrap();
        let mut height = 0;
        let mut checked = 0;
        let lines = capture_section("glyphs");
        for (index, line) in lines.iter().enumerate() {
            if let Some(rest) = line.strip_prefix("-- lfHeight ") {
                height = rest.split(',').next().unwrap().parse().unwrap_or(0);
                continue;
            }
            let Some(rest) = line.strip_prefix("U+") else {
                continue;
            };
            if !rest.contains("(GGO_METRICS)") {
                continue;
            }
            let character = u32::from_str_radix(&rest[..4], 16).unwrap();
            let answer: u32 = field(line, "ret").parse().unwrap();
            let ppem = glyph::ppem_for_height(&font, height).unwrap();
            let (done, _) = rendered(&font, character, ppem);
            assert_eq!(
                metrics_size(&done.metrics),
                answer,
                "{height} U+{character:04X}"
            );
            assert!(lines[index + 1].contains("gmBlackBoxX"));
            checked += 1;
        }
        assert_eq!(checked, 26);
    }
}
