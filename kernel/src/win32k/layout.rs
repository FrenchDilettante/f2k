//! Text layout: where a DC's text goes and how far each character moves the pen, as Windows 2000's
//! text calls lay it out over the DC's text attributes ([`super::dc::Dc`]'s `text_align`,
//! `char_extra`, `break_extra` and `break_count`, which gdi32's SetTextAlign,
//! SetTextCharacterExtra and SetTextJustification set through NtGdiGetAndSetDCDword).
//!
//! - Each character's advance is its glyph's ([`base_advances`]: the built-in font's cell, a
//!   TrueType font's glyph's), or the caller's (ExtTextOut's `Dx`, which takes the place of the
//!   spacing below), then the spacing ([`Spacing`]): the character extra after every character, and
//!   the justification's extra spread over the break characters (the font's tmBreakChar),
//!   `break_extra / break_count` each, the remainder a pixel each to the first breaks of the string
//!   (the txlayout capture's SetTextJustification(11, 2): "a b" 6 pixels wider, "a b c" 11). A
//!   break count of 0 spreads nothing. The text's extents (GetTextExtentPoint32,
//!   GetTextExtentExPoint) and its drawing (ExtTextOut) take the same advances, so a justified line
//!   is as wide drawn as measured, and its cells' background fills the extra pixels too.
//! - The alignment places the reference point ([`aligned`], in device coordinates): TA_LEFT,
//!   TA_RIGHT and TA_CENTER put it at the text's left, right or middle (its width halved, rounded
//!   toward zero), TA_TOP, TA_BOTTOM and TA_BASELINE at the cell's top, bottom or the baseline (the
//!   font's ascent below the top).
//! - TA_UPDATECP draws from the current position, ExtTextOut's own point ignored, and moves it
//!   ([`moved_position`]): past the text under TA_LEFT, back before it under TA_RIGHT, nowhere
//!   under TA_CENTER; its y never moves.
//!
//! The services (F2K's argument lists, see [`crate::win32k`]; a DC handle that names no DC is
//! STATUS_INVALID_HANDLE):
//!
//! - NtGdiGetTextExtentExW(handle Dc, ptr String, u32 Count, u32 MaxExtent, ptr<u32> Fit, ptr Dx,
//!   ptr Size, u32 Flags): the string's SIZE, each character's partial extent (the advances summed
//!   up to and including it) into `Dx` and how many of them are within `MaxExtent` (taken unsigned:
//!   -1 fits them all) into `Fit`, either pointer null for none; with GTEEFL_INDICES the units are
//!   glyph indices;
//! - NtGdiGetGlyphIndicesW(handle Dc, ptr String, u32 Count, ptr Glyphs, u32 Flags, ptr<u32>
//!   Converted): each character's glyph index in the DC's font (0xFFFF for one it lacks under
//!   GGI_MARK_NONEXISTING_GLYPHS, its missing glyph's otherwise), the count converted; the built-in
//!   font's are its code page 437 cells;
//! - NtGdiGetTextCharsetInfo(handle Dc, ptr Signature, u32 Flags, ptr<u32> CharSet): the font's
//!   character set, its FONTSIGNATURE into `Signature` when it is not null (zeros for the built-in
//!   font and a raster-style face, as for Windows 2000's raster fonts).

use rtl::gdi::*;
use rtl::pod::{slice_bytes, Pod};

use super::dc::{dc_of, Dc};
use super::font;
use super::fonts::table::Realization;
use super::mapping::Mapping;
use crate::nt::call::{Handle, NtCall, NtResult, UserAddr, UserPtr};
use crate::status::*;

/// The units, advances or glyphs a service copies to or from the caller at a time.
pub const CHUNK: usize = 64;

/// The spacing a run of text takes beyond its glyphs' advances: the character extra after each
/// character, and the justification's extra after each break character (see the module notes).
/// A string's layout takes one, its remainder spent as the breaks go by.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Spacing {
    char_extra: i32,
    break_char: u16,
    per_break: i32,
    /// The pixels still to spread, one per break, from the first: as signed as the extra.
    remainder: i32,
}

impl Spacing {
    /// No spacing: ExtTextOut's with an advances array.
    pub const NONE: Spacing = Spacing {
        char_extra: 0,
        break_char: 0,
        per_break: 0,
        remainder: 0,
    };

    /// The spacing of `char_extra` after every character and `break_extra` spread over
    /// `break_count` breaks (none for a count that is not positive), `break_char` the break.
    pub fn new(char_extra: i32, break_extra: i32, break_count: i32, break_char: u16) -> Self {
        let (per_break, remainder) = if break_count > 0 {
            let per_break = break_extra / break_count;
            (per_break, break_extra - per_break * break_count)
        } else {
            (0, 0)
        };
        Spacing {
            char_extra,
            break_char,
            per_break,
            remainder,
        }
    }

    /// The spacing of the DC's text attributes, in a font whose break character is `break_char`.
    pub fn of(dc: &Dc, break_char: u16) -> Self {
        Spacing::new(dc.char_extra, dc.break_extra, dc.break_count, break_char)
    }

    /// The spacing added to `advances`, the advances of `units` (the next of the string).
    pub fn apply(&mut self, units: &[u16], advances: &mut [i32]) {
        for (&unit, advance) in units.iter().zip(advances.iter_mut()) {
            *advance = advance.saturating_add(self.char_extra);
            if unit != self.break_char || (self.per_break == 0 && self.remainder == 0) {
                continue;
            }
            *advance = advance.saturating_add(self.per_break);
            if self.remainder > 0 {
                *advance = advance.saturating_add(1);
                self.remainder -= 1;
            } else if self.remainder < 0 {
                *advance = advance.saturating_sub(1);
                self.remainder += 1;
            }
        }
    }
}

/// What the layout needs of a realised font: its ascent, its cell's height and its break
/// character.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FontLayout {
    pub ascent: i32,
    pub height: i32,
    pub break_char: u16,
}

impl FontLayout {
    /// The layout of the realised font `realization`; none when its face is gone.
    pub fn of(realization: &Realization) -> Option<FontLayout> {
        let metric = match realization {
            Realization::BuiltIn { .. } => font::text_metric(),
            Realization::TrueType { key, char_set, .. } => {
                super::fonts::text_metric(*key, *char_set)?
            }
        };
        Some(FontLayout {
            ascent: metric.ascent,
            height: metric.height,
            break_char: metric.break_char,
        })
    }
}

/// The advances of `units` (glyph indices when `indices`) in the realised font, into `out`.
pub fn base_advances(realization: &Realization, units: &[u16], indices: bool, out: &mut [i32]) {
    match realization {
        Realization::BuiltIn { .. } => out.fill(font::WIDTH),
        Realization::TrueType { key, .. } => super::fonts::advances(*key, units, indices, out),
    }
}

/// The reference point (`x`, `y`) of a text `width` wide, in a font of `ascent` and `height`,
/// moved to the text's cells' top left as the alignment `align` places it (device coordinates).
pub fn aligned(align: u32, (x, y): (i32, i32), width: i32, ascent: i32, height: i32) -> (i32, i32) {
    let x = match align & TA_CENTER {
        TA_CENTER => x.saturating_sub(width / 2),
        TA_RIGHT => x.saturating_sub(width),
        _ => x,
    };
    let y = match align & TA_BASELINE {
        TA_BASELINE => y.saturating_sub(ascent),
        TA_BOTTOM => y.saturating_sub(height),
        _ => y,
    };
    (x, y)
}

/// The current position after a text `width` device pixels wide drawn from `current` (logical)
/// under TA_UPDATECP and the alignment `align`, through `mapping`: past the text (TA_LEFT), back
/// before it (TA_RIGHT), or where it was (TA_CENTER); y unchanged.
pub fn moved_position(align: u32, mapping: Mapping, current: (i32, i32), width: i32) -> (i32, i32) {
    let by = match align & TA_CENTER {
        TA_LEFT => width,
        TA_RIGHT => width.saturating_neg(),
        _ => return current,
    };
    let (x, y) = mapping.to_device(current.0, current.1);
    (mapping.to_logical(x.saturating_add(by), y).0, current.1)
}

/// The advances of the caller's `count` units at `string` (glyph indices when `indices`), a chunk
/// at a time, each chunk handed to `f` with its advances: the caller's at `dx` when it is not
/// null, the font's spaced by `spacing` otherwise.
pub fn runs(
    string: UserAddr,
    count: u32,
    dx: UserAddr,
    realization: &Realization,
    indices: bool,
    spacing: &mut Spacing,
    mut f: impl FnMut(&[u16], &[i32]) -> Result<(), NtStatus>,
) -> Result<(), NtStatus> {
    let mut units = [0u16; CHUNK];
    let mut advances = [0i32; CHUNK];
    let mut done = 0usize;
    while done < count as usize {
        let length = (count as usize - done).min(CHUNK);
        if !dx.is_null() {
            dx.offset(4 * done as u32)
                .read(&mut advances.as_bytes_mut()[..4 * length])?;
        }
        let units = &mut units[..length];
        let advances = &mut advances[..length];
        string.offset(2 * done as u32).read_units(units)?;
        if dx.is_null() {
            base_advances(realization, units, indices, advances);
            spacing.apply(units, advances);
        }
        f(units, advances)?;
        done += length;
    }
    Ok(())
}

/// The sum of `advances` from `width`.
pub fn widened(width: i32, advances: &[i32]) -> i32 {
    advances
        .iter()
        .fold(width, |width, &advance| width.saturating_add(advance))
}

/// The height of a string of `count` characters' extent in the realised font: the built-in
/// font's cell's whatever the count; a TrueType font's cell's, 0 for no characters.
pub fn extent_height(realization: &Realization, count: u32) -> Result<i32, NtStatus> {
    Ok(match realization {
        Realization::BuiltIn { .. } => font::HEIGHT,
        Realization::TrueType { .. } if count == 0 => 0,
        Realization::TrueType { key, char_set, .. } => {
            super::fonts::text_metric(*key, *char_set)
                .ok_or(STATUS_INVALID_HANDLE)?
                .height
        }
    })
}

/// The width of `count` characters at `string` in `dc`'s font, laid out with its spacing.
pub fn text_width(
    dc: &Dc,
    realization: &Realization,
    string: UserAddr,
    count: u32,
    indices: bool,
) -> Result<i32, NtStatus> {
    let break_char = FontLayout::of(realization).map_or(0x20, |layout| layout.break_char);
    let mut spacing = Spacing::of(dc, break_char);
    let mut width = 0i32;
    runs(
        string,
        count,
        UserAddr(0),
        realization,
        indices,
        &mut spacing,
        |_, advances| {
            width = widened(width, advances);
            Ok(())
        },
    )?;
    Ok(width)
}

/// How many partial extents of `partials` (from `fitted` before them) are within `max`.
pub fn fitting(fitted: u32, partials: &[i32], max: u32) -> u32 {
    fitted
        + partials
            .iter()
            .take_while(|&&partial| i64::from(partial) <= i64::from(max))
            .count() as u32
}

/// NtGdiGetTextExtentExW(Dc, String, Count, MaxExtent, Fit, Dx, Size, Flags): see the module
/// notes.
#[allow(clippy::too_many_arguments)]
pub fn get_text_extent_ex_w(
    call: &mut NtCall,
    dc: Handle,
    string: UserAddr,
    count: u32,
    max: u32,
    fit: UserAddr,
    dx: UserAddr,
    size: UserAddr,
    flags: u32,
) -> NtResult {
    let (_reference, dc) = dc_of(call, dc)?;
    let realization = super::fonts::realize_selected(call, &dc);
    let indices = flags & GTEEFL_INDICES != 0;
    let break_char = FontLayout::of(&realization).map_or(0x20, |layout| layout.break_char);
    let mut spacing = Spacing::of(&dc, break_char);
    let mut width = 0i32;
    let mut fitted = 0u32;
    let mut done = 0u32;
    let mut partials = [0i32; CHUNK];
    runs(
        string,
        count,
        UserAddr(0),
        &realization,
        indices,
        &mut spacing,
        |_, advances| {
            let partials = &mut partials[..advances.len()];
            for (partial, &advance) in partials.iter_mut().zip(advances) {
                width = width.saturating_add(advance);
                *partial = width;
            }
            if fitted == done {
                fitted = fitting(fitted, partials, max);
            }
            if !dx.is_null() {
                dx.offset(4 * done).write(slice_bytes(partials))?;
            }
            done += advances.len() as u32;
            Ok(())
        },
    )?;
    let cy = extent_height(&realization, count)?;
    if !fit.is_null() {
        fit.cast::<u32>().write(fitted)?;
    }
    size.cast::<Size>().write(Size { cx: width, cy })?;
    Ok(STATUS_SUCCESS)
}

/// NtGdiGetGlyphIndicesW(Dc, String, Count, Glyphs, Flags, Converted): see the module notes.
pub fn get_glyph_indices_w(
    call: &mut NtCall,
    dc: Handle,
    string: UserAddr,
    count: u32,
    glyphs: UserAddr,
    flags: u32,
    out: UserPtr<u32>,
) -> NtResult {
    let (_reference, dc) = dc_of(call, dc)?;
    let realization = super::fonts::realize_selected(call, &dc);
    let mut units = [0u16; CHUNK];
    let mut indices = [0u16; CHUNK];
    let mut done = 0usize;
    while done < count as usize {
        let length = (count as usize - done).min(CHUNK);
        let units = &mut units[..length];
        let indices = &mut indices[..length];
        string.offset(2 * done as u32).read_units(units)?;
        match realization {
            Realization::BuiltIn { .. } => {
                for (&unit, index) in units.iter().zip(indices.iter_mut()) {
                    *index = u16::from(font::glyph_index(unit));
                }
            }
            Realization::TrueType { key, .. } => {
                if !super::fonts::glyph_indices(key, units, indices) {
                    indices.fill(0);
                }
                if flags & GGI_MARK_NONEXISTING_GLYPHS != 0 {
                    for index in indices.iter_mut().filter(|index| **index == 0) {
                        *index = 0xFFFF;
                    }
                }
            }
        }
        glyphs.offset(2 * done as u32).write(slice_bytes(indices))?;
        done += length;
    }
    out.write(count)?;
    Ok(STATUS_SUCCESS)
}

/// NtGdiGetTextCharsetInfo(Dc, Signature, Flags, CharSet): see the module notes. The flags are
/// Windows 2000's reserved ones, ignored.
pub fn get_text_charset_info(
    call: &mut NtCall,
    dc: Handle,
    signature: UserAddr,
    _flags: u32,
    out: UserPtr<u32>,
) -> NtResult {
    let (_reference, dc) = dc_of(call, dc)?;
    let (char_set, answer) = match super::fonts::realize_selected(call, &dc) {
        Realization::BuiltIn { .. } => (font::text_metric().char_set, FontSignature::default()),
        Realization::TrueType { key, char_set, .. } => (char_set, super::fonts::signature(key)),
    };
    if !signature.is_null() {
        signature.cast::<FontSignature>().write(answer)?;
    }
    out.write(u32::from(char_set))?;
    Ok(STATUS_SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SPACE: u16 = 0x20;

    fn units(text: &str) -> std::vec::Vec<u16> {
        text.encode_utf16().collect()
    }

    /// The advances of `text` in a font whose characters are all `width` wide, spaced.
    fn spaced(text: &str, width: i32, spacing: &mut Spacing) -> std::vec::Vec<i32> {
        let units = units(text);
        let mut advances = std::vec![width; units.len()];
        spacing.apply(&units, &mut advances);
        advances
    }

    /// The txlayout capture's character extra: "Hello" (34 pixels in the system font) 49 with 3,
    /// 24 with -2; every character takes it, the last too.
    #[test]
    fn the_character_extra_follows_every_character() {
        // The system font's "Hello": 10, 8, 4, 4, 8.
        let hello = [10, 8, 4, 4, 8];
        let mut advances = hello;
        Spacing::new(3, 0, 0, SPACE).apply(&units("Hello"), &mut advances);
        assert_eq!(widened(0, &advances), 49);
        let mut advances = hello;
        Spacing::new(-2, 0, 0, SPACE).apply(&units("Hello"), &mut advances);
        assert_eq!(widened(0, &advances), 24);
        assert_eq!(advances, [8, 6, 2, 2, 6]);
    }

    /// The capture's justification over "a b c" (31 pixels): 10 over 2 breaks is 41, 5 a break;
    /// 11 over 2 is 42, the first break taking the odd pixel ("a b" 26 of 20); a break count of 0
    /// spreads nothing; -4 over 2 is 27; the spacing goes to the break character alone.
    #[test]
    fn justification_spreads_over_the_breaks() {
        let abc = |spacing: Spacing| {
            let mut spacing = spacing;
            // a 8, b 8, c 7, the space 4.
            let mut advances = [8, 4, 8, 4, 7];
            spacing.apply(&units("a b c"), &mut advances);
            advances
        };
        assert_eq!(abc(Spacing::new(0, 10, 2, SPACE)), [8, 9, 8, 9, 7]);
        assert_eq!(widened(0, &abc(Spacing::new(0, 10, 2, SPACE))), 41);
        assert_eq!(abc(Spacing::new(0, 11, 2, SPACE)), [8, 10, 8, 9, 7]);
        assert_eq!(widened(0, &abc(Spacing::new(0, 11, 2, SPACE))), 42);
        let mut spacing = Spacing::new(0, 11, 2, SPACE);
        assert_eq!(widened(0, &spaced("a b", 8, &mut spacing)), 8 + 8 + 8 + 6);
        assert_eq!(widened(0, &abc(Spacing::new(0, 6, 0, SPACE))), 31);
        assert_eq!(widened(0, &abc(Spacing::new(0, -4, 2, SPACE))), 27);
        assert_eq!(widened(0, &abc(Spacing::new(0, 0, 0, SPACE))), 31);
        // A negative remainder takes a pixel from the first breaks.
        assert_eq!(abc(Spacing::new(0, -5, 2, SPACE)), [8, 1, 8, 2, 7]);
    }

    /// A string's spacing goes on across its chunks: the remainder spent once, on the first break
    /// of the string rather than of each chunk.
    #[test]
    fn the_remainder_is_spent_once_per_string() {
        let mut spacing = Spacing::new(1, 3, 2, SPACE);
        assert_eq!(spaced("a ", 5, &mut spacing), [6, 6 + 1 + 1]);
        assert_eq!(spaced(" b", 5, &mut spacing), [6 + 1, 6]);
        assert_eq!(Spacing::NONE, {
            let mut none = Spacing::NONE;
            assert_eq!(spaced("a b", 5, &mut none), [5, 5, 5]);
            none
        });
    }

    /// The capture's alignments of "Ab" (16 wide, the system font's ascent 13 and height 16) at
    /// (48, 24): its cells' top left.
    #[test]
    fn the_alignment_places_the_cells() {
        let at = |align| aligned(align, (48, 24), 16, 13, 16);
        assert_eq!(at(TA_LEFT | TA_TOP), (48, 24));
        assert_eq!(at(TA_CENTER | TA_TOP), (40, 24));
        assert_eq!(at(TA_RIGHT | TA_TOP), (32, 24));
        assert_eq!(at(TA_LEFT | TA_BASELINE), (48, 11));
        assert_eq!(at(TA_LEFT | TA_BOTTOM), (48, 8));
        assert_eq!(at(TA_CENTER | TA_BASELINE), (40, 11));
        assert_eq!(at(TA_RIGHT | TA_BOTTOM), (32, 8));
        // The flags beyond the alignment's (TA_UPDATECP, TA_RTLREADING, others) place nothing.
        assert_eq!(at(TA_UPDATECP | TA_RTLREADING | 0x1000), (48, 24));
        // An odd width's half rounds toward zero.
        assert_eq!(aligned(TA_CENTER, (10, 0), 7, 0, 0), (7, 0));
    }

    /// The capture's TA_UPDATECP from (40, 10) after "Ab" (16): 56 under TA_LEFT, 24 under
    /// TA_RIGHT, 40 under TA_CENTER; the y kept; through a scaled mapping, the width in logical
    /// units.
    #[test]
    fn the_current_position_moves_past_the_text() {
        let text = Mapping::TEXT;
        assert_eq!(moved_position(TA_LEFT, text, (40, 10), 16), (56, 10));
        assert_eq!(moved_position(TA_RIGHT, text, (40, 10), 16), (24, 10));
        assert_eq!(moved_position(TA_CENTER, text, (40, 10), 16), (40, 10));
        assert_eq!(
            moved_position(TA_LEFT | TA_BASELINE | TA_UPDATECP, text, (56, 10), 16),
            (72, 10)
        );
        let mut scaled = Mapping::TEXT;
        scaled.mode = MM_ANISOTROPIC;
        scaled.window_ext = (1, 1);
        scaled.viewport_ext = (2, 2);
        assert_eq!(moved_position(TA_LEFT, scaled, (10, 3), 16), (18, 3));
    }

    /// GetTextExtentExPoint's fit over the capture's "Hello world" partial extents: 0 within 0, 2
    /// within 20, 6 within 40, all within 1000 and within -1 (taken unsigned); counted on across
    /// chunks.
    #[test]
    fn the_fit_counts_the_partials_within_the_maximum() {
        let partials = [10, 18, 22, 26, 34, 38, 48, 56, 61, 65, 73];
        assert_eq!(fitting(0, &partials, 0), 0);
        assert_eq!(fitting(0, &partials, 20), 2);
        assert_eq!(fitting(0, &partials, 40), 6);
        assert_eq!(fitting(0, &partials, 1000), 11);
        assert_eq!(fitting(0, &partials, u32::MAX), 11);
        assert_eq!(fitting(6, &partials[6..], 1000), 11);
    }
}
