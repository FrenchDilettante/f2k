//! Bitmap-only faces: TrueType files whose embedded strikes are all they draw, their outlines
//! empty (Wine's System and MS Sans Serif, which stand in for Windows 2000's raster fonts of those
//! names). GDI realises such a face as it realises a raster font: at one of its strikes' sizes,
//! never scaled, its metrics the strike's own.
//!
//! - **The size.** The strike nearest the requested height: the largest whose height is not above
//!   it, else the smallest above it, as the font mapper chooses among a raster font's sizes ("as
//!   large as possible without being taller than the requested height": Ron Gery, "Windows Font
//!   Mapping", MSDN, 1992; [MS-WMF] 2.2.1.2, "the largest physical font that does not exceed the
//!   requested size"). A negative LOGFONT height is matched against each strike's em height (its
//!   pixels per em), a positive one against its cell height (its ascent plus its descent), as
//!   [MS-WMF] 2.2.1.2 describes the two.
//! - **The metrics.** A strike's horizontal line metrics give the cell: its ascender the ascent,
//!   its descender the descent. The internal leading is what the cell holds beyond the em. These
//!   files declare an em as tall as the cell, so it is 0 (Windows 2000's own MS Sans Serif answers
//!   2 at 8 points: the stand-in's deviation). There is no external leading. The widest character
//!   is the strike's own `widthMax`, and the average width the strike's weighted average of the
//!   lowercase letters and the space, as the OpenType specification defines OS/2's xAvgCharWidth
//!   for its versions 0 to 2 (16 pixels of System average 6.5, so 7, the stock SYSTEM_FONT's
//!   tmAveCharWidth in the guidc capture; 13 of MS Sans Serif 5, the raster font's at 8 points).
//! - **The character range.** OS/2's first and last characters when it gives them in order; these
//!   files give 0xFFFF and 0, and a raster font of the ANSI character set covers 0x20 to 0xFF, so
//!   that range stands in.

use super::embedded::{LineMetrics, Strike};
use super::metrics::{self, Size};
use super::{Error, Font};
use crate::gdi::{TextMetricW, FW_BOLD, TMPF_FIXED_PITCH};

/// One strike's size: its em and its cell, in pixels.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StrikeSize {
    pub ppem: u16,
    pub ascent: i32,
    pub descent: i32,
    /// The widest glyph's width (the strike's `widthMax`).
    pub width_max: i32,
}

impl StrikeSize {
    fn of(strike: &Strike) -> Self {
        let LineMetrics {
            ascender,
            descender,
            width_max,
            ..
        } = strike.hori;
        StrikeSize {
            ppem: strike.ppem_y as u16,
            ascent: ascender as i32,
            descent: -(descender as i32),
            width_max: width_max as i32,
        }
    }

    /// The cell's height: the ascent and the descent.
    pub fn cell(&self) -> i32 {
        self.ascent + self.descent
    }
}

/// The weights the OpenType specification gives the lowercase letters and the space for OS/2's
/// xAvgCharWidth (versions 0 to 2), in thousandths.
const AVERAGE_WEIGHTS: [(u8, u32); 27] = [
    (b'a', 64),
    (b'b', 14),
    (b'c', 27),
    (b'd', 35),
    (b'e', 100),
    (b'f', 20),
    (b'g', 14),
    (b'h', 42),
    (b'i', 63),
    (b'j', 3),
    (b'k', 6),
    (b'l', 35),
    (b'm', 20),
    (b'n', 56),
    (b'o', 56),
    (b'p', 17),
    (b'q', 4),
    (b'r', 49),
    (b's', 56),
    (b't', 71),
    (b'u', 31),
    (b'v', 10),
    (b'w', 18),
    (b'x', 3),
    (b'y', 18),
    (b'z', 2),
    (b' ', 166),
];

/// The character range a raster font of the ANSI character set covers, for a face whose OS/2
/// table gives none.
const ANSI_FIRST: u16 = 0x20;
const ANSI_LAST: u16 = 0xFF;

/// The one-bit strikes the engine draws, square ones, in the table's order.
fn strikes<'a>(font: &Font<'a>) -> Result<impl Iterator<Item = Strike<'a>>, Error> {
    let all = font
        .strikes()?
        .into_iter()
        .flat_map(|strikes| strikes.all());
    Ok(all
        .filter_map(Result::ok)
        .filter(|strike| strike.bit_depth == 1 && strike.ppem_x == strike.ppem_y))
}

/// Whether `font` is bitmap-only: it has a one-bit strike, and no glyph but the missing glyph
/// (glyph 0, which these files keep an outline for) has an outline.
pub fn is_bitmap_only(font: &Font) -> bool {
    if !strikes(font).is_ok_and(|mut strikes| strikes.next().is_some()) {
        return false;
    }
    let Ok(glyphs) = font.glyphs() else {
        // No outlines at all.
        return true;
    };
    (1..glyphs.len()).all(|glyph| glyphs.data(glyph).is_ok_and(|data| data.is_empty()))
}

/// The sizes of `font`'s strikes, in the table's order.
pub fn sizes<'a>(font: &Font<'a>) -> Result<impl Iterator<Item = StrikeSize> + 'a, Error> {
    Ok(strikes(font)?.map(|strike| StrikeSize::of(&strike)))
}

/// The size of the strike of `ppem` pixels per em, if the font has one.
pub fn size(font: &Font, ppem: u16) -> Result<Option<StrikeSize>, Error> {
    Ok(sizes(font)?.find(|size| size.ppem == ppem))
}

/// The em of the strike the font mapper realises a LOGFONT height of `height` at (see the module
/// notes): a negative height matched against the strikes' ems, a positive one against their
/// cells; none for a face without strikes. 0 asks for the mapper's default size, which the caller
/// resolves first: it is matched as a cell of 0, the smallest strike.
pub fn strike_for_height(font: &Font, height: i32) -> Result<Option<u16>, Error> {
    let wanted = height.unsigned_abs() as i64;
    let measure = |size: &StrikeSize| -> i64 {
        if height < 0 {
            size.ppem as i64
        } else {
            size.cell() as i64
        }
    };
    let mut below: Option<StrikeSize> = None;
    let mut above: Option<StrikeSize> = None;
    for size in sizes(font)? {
        let at = measure(&size);
        if at <= wanted {
            if below.is_none_or(|best| at > measure(&best)) {
                below = Some(size);
            }
        } else if above.is_none_or(|best| at < measure(&best)) {
            above = Some(size);
        }
    }
    Ok(below.or(above).map(|size| size.ppem))
}

/// The advance of the character `code` in the strike `strike`: its glyph's image's, none when the
/// face maps it to no glyph or the strike has no image for it.
fn strike_advance(font: &Font, strike: &Strike, code: u32) -> Option<i32> {
    let subtable = font.cmap().ok()?.unicode().ok()??;
    let glyph = subtable.glyph(code);
    if glyph == 0 {
        return None;
    }
    let image = strike.glyph(glyph).ok()??;
    Some(image.metrics.advance as i32)
}

/// The strike's weighted average width (see the module notes), to the nearest pixel (a half up);
/// none when it lacks one of the characters weighed.
fn average_width(font: &Font, strike: &Strike) -> Option<i32> {
    let mut sum = 0u32;
    for (character, weight) in AVERAGE_WEIGHTS {
        sum += weight * strike_advance(font, strike, character as u32)? as u32;
    }
    Some(((2 * sum + 1000) / 2000) as i32)
}

/// The TEXTMETRICW of the bitmap-only `font` at its strike of `ppem` pixels per em, emboldened as
/// GDI synthesises a bold when `bold` (each character a pixel wider, as for a TrueType face), its
/// character set `char_set`; [`Error::Unsupported`] for a size it has no strike for. See the
/// module notes.
pub fn text_metric(font: &Font, ppem: u16, bold: bool, char_set: u8) -> Result<TextMetricW, Error> {
    let strike = strikes(font)?
        .find(|strike| strike.ppem_y as u16 == ppem)
        .ok_or(Error::Unsupported)?;
    let size = StrikeSize::of(&strike);
    // The face's own fields (its weight, family, style and characters) as a TrueType face's; the
    // sizes are the strike's.
    let mut metric = metrics::text_metric(font, Size::Em(ppem), false, char_set)?;
    let os2 = font.os2()?;
    let post = font.post()?;
    let height = size.cell();
    let widen = bold as i32;
    let average = average_width(font, &strike).unwrap_or(metric.ave_char_width);
    metric.height = height;
    metric.ascent = size.ascent;
    metric.descent = size.descent;
    metric.internal_leading = (height - ppem as i32).max(0);
    metric.external_leading = 0;
    metric.ave_char_width = average + widen;
    metric.max_char_width = size.width_max + widen;
    if bold {
        metric.weight = FW_BOLD;
    }
    if metric.first_char > metric.last_char {
        metric.first_char = ANSI_FIRST;
        metric.last_char = ANSI_LAST;
        metric.default_char = ANSI_FIRST - 1;
    }
    // A raster font's pitch and family: neither TrueType nor vector.
    metric.pitch_and_family = metrics::family(os2.as_ref());
    if !metrics::fixed_pitch(post.as_ref()) {
        metric.pitch_and_family |= TMPF_FIXED_PITCH;
    }
    Ok(metric)
}

#[cfg(test)]
mod tests {
    use super::super::tests::repository_file;
    use super::*;

    fn system() -> std::vec::Vec<u8> {
        repository_file("fonts/system.ttf")
    }

    fn sans_serif() -> std::vec::Vec<u8> {
        repository_file("fonts/ms_sans_serif.ttf")
    }

    /// System and MS Sans Serif are bitmap-only; Tahoma and Tahoma Bold have outlines, and Marlett
    /// has no strikes.
    #[test]
    fn the_bitmap_only_faces_are_told_apart() {
        for (path, bitmap_only) in [
            ("fonts/system.ttf", true),
            ("fonts/ms_sans_serif.ttf", true),
            ("fonts/tahoma.ttf", false),
            ("fonts/tahomabd.ttf", false),
            ("fonts/marlett.ttf", false),
        ] {
            let data = repository_file(path);
            let font = Font::new(&data).unwrap();
            assert_eq!(is_bitmap_only(&font), bitmap_only, "{path}");
        }
    }

    /// The strikes' sizes: System's 16 and 18, MS Sans Serif's 13, 16 and 20, each cell its em.
    #[test]
    fn the_strikes_have_their_sizes() {
        let data = system();
        let font = Font::new(&data).unwrap();
        let found: std::vec::Vec<_> = sizes(&font).unwrap().collect();
        assert_eq!(
            found,
            [
                StrikeSize {
                    ppem: 16,
                    ascent: 13,
                    descent: 3,
                    width_max: 15
                },
                StrikeSize {
                    ppem: 18,
                    ascent: 16,
                    descent: 2,
                    width_max: 15
                },
            ]
        );
        let data = sans_serif();
        let font = Font::new(&data).unwrap();
        let cells: std::vec::Vec<_> = sizes(&font).unwrap().map(|size| size.cell()).collect();
        assert_eq!(cells, [13, 16, 20]);
    }

    /// The nearest strike: the largest not above the request, else the smallest above it; a
    /// negative height an em, a positive one a cell.
    #[test]
    fn the_nearest_strike_is_not_above_the_request() {
        let data = sans_serif();
        let font = Font::new(&data).unwrap();
        for (height, ppem) in [
            (-11, 13),
            (-13, 13),
            (-15, 13),
            (-16, 16),
            (-19, 16),
            (-20, 20),
            (-40, 20),
            (8, 13),
            (13, 13),
            (17, 16),
            (21, 20),
            (0, 13),
        ] {
            assert_eq!(
                strike_for_height(&font, height).unwrap(),
                Some(ppem),
                "{height}"
            );
        }
        let data = repository_file("fonts/marlett.ttf");
        let marlett = Font::new(&data).unwrap();
        assert_eq!(strike_for_height(&marlett, -11).unwrap(), None);
    }

    /// The System font's metrics at 16: the guidc capture's tmHeight of 16 and tmAveCharWidth of
    /// 7 for the stock SYSTEM_FONT, a raster font's pitch and family, its own weight.
    #[test]
    fn system_answers_the_stock_font_s_metrics() {
        let data = system();
        let font = Font::new(&data).unwrap();
        let metric = text_metric(&font, 16, false, 0).unwrap();
        assert_eq!(
            (
                metric.height,
                metric.ascent,
                metric.descent,
                metric.internal_leading,
                metric.external_leading
            ),
            (16, 13, 3, 0, 0)
        );
        assert_eq!((metric.ave_char_width, metric.max_char_width), (7, 15));
        assert_eq!(metric.weight, 700);
        assert_eq!(metric.pitch_and_family, 0x21, "FF_SWISS, variable pitch");
        assert_eq!(
            (metric.first_char, metric.last_char, metric.default_char),
            (0x20, 0xFF, 0x1F)
        );
        let bold = text_metric(&font, 16, true, 0).unwrap();
        assert_eq!((bold.ave_char_width, bold.max_char_width), (8, 16));
        assert_eq!(text_metric(&font, 17, false, 0), Err(Error::Unsupported));
    }

    /// MS Sans Serif at 13, the 8-point size: a cell of 13 and an average of 5, Windows 2000's
    /// raster font's.
    #[test]
    fn ms_sans_serif_at_eight_points() {
        let data = sans_serif();
        let font = Font::new(&data).unwrap();
        let metric = text_metric(&font, 13, false, 0).unwrap();
        assert_eq!((metric.height, metric.ascent, metric.descent), (13, 11, 2));
        assert_eq!((metric.ave_char_width, metric.max_char_width), (5, 11));
        assert_eq!(metric.weight, 400);
    }
}
