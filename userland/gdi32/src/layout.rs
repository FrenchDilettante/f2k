//! Text layout: the DC's text attributes (SetTextAlign, SetTextCharacterExtra,
//! SetTextJustification, kept by win32k as NtGdiGetAndSetDCDword's DC_ attributes, where Windows
//! 2000's gdi32 writes them into the DC's user-mode attributes), the extents with a maximum and
//! their partial extents (GetTextExtentExPoint, and the glyph-index forms), GetCharacterPlacement
//! over them, and PolyTextOut over ExtTextOut. win32k lays the text out by the attributes
//! (kernel/src/win32k/layout.rs): the extents and the drawing alike.
//!
//! The failures are Windows 2000's, as the txlayout capture shows them: GetTextAlign and
//! GetTextCharacterExtra of a DC that is none answer GDI_ERROR and 0x80000000 and leave the last
//! error; SetTextAlign's is ERROR_INVALID_HANDLE, SetTextCharacterExtra's ERROR_INVALID_PARAMETER,
//! and SetTextJustification answers FALSE without one.

use rtl::edge::{InBuf, Out, OutBuf};
use rtl::gdi::*;

use crate::imports::{self, Caller, HeapBlock};
use crate::text::{ext_text_out_a, ext_text_out_w};
use crate::{answered, failed, with_wide, ERROR_INVALID_PARAMETER, ERROR_NOT_ENOUGH_MEMORY};

/// GetCharacterPlacement's flag: the string laid out up to the maximum extent alone.
pub const GCP_MAXEXTENT: u32 = 0x0010_0000;

/// SetTextCharacterExtra's and GetTextCharacterExtra's failure (0x80000000).
const EXTRA_FAILED: i32 = i32::MIN;

/// GCP_RESULTSW (and GCP_RESULTSA, its out string bytes): GetCharacterPlacement's arrays, each
/// null for none, and the counts.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GcpResults {
    pub struct_size: u32,
    pub out_string: usize,
    pub order: usize,
    pub dx: usize,
    pub caret_pos: usize,
    pub class: usize,
    pub glyphs: usize,
    pub glyph_count: u32,
    pub max_fit: i32,
}

/// POLYTEXTW (and POLYTEXTA, its string bytes): one string of PolyTextOut's, ExtTextOut's
/// arguments.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PolyText {
    pub x: i32,
    pub y: i32,
    pub count: u32,
    pub string: usize,
    pub options: u32,
    pub rect: Rect,
    pub dx: usize,
}

// --- the attributes ------------------------------------------------------------------------------

/// GetTextAlign: the DC's alignment, as SetTextAlign set it; GDI_ERROR for a DC that is none, the
/// last error untouched.
#[unsafe(export_name = "f2k_export_GetTextAlign")]
pub extern "system" fn get_text_align(dc: usize) -> u32 {
    imports::dc_dword(dc, DC_TEXT_ALIGN).unwrap_or(GDI_ERROR)
}

/// SetTextAlign: the alignment set, every bit as given; the previous one answered, GDI_ERROR with
/// ERROR_INVALID_HANDLE for a DC that is none.
#[unsafe(export_name = "f2k_export_SetTextAlign")]
pub extern "system" fn set_text_align(dc: usize, mode: u32) -> u32 {
    answered(imports::set_dc_dword(dc, DC_TEXT_ALIGN, mode)).unwrap_or(GDI_ERROR)
}

/// GetTextCharacterExtra: the DC's character extra; 0x80000000 for a DC that is none, the last
/// error untouched.
#[unsafe(export_name = "f2k_export_GetTextCharacterExtra")]
pub extern "system" fn get_text_character_extra(dc: usize) -> i32 {
    imports::dc_dword(dc, DC_CHAR_EXTRA).map_or(EXTRA_FAILED, |extra| extra as i32)
}

/// SetTextCharacterExtra: the extra set, the previous one answered; 0x80000000 with
/// ERROR_INVALID_PARAMETER for the extra 0x80000000 or a DC that is none.
#[unsafe(export_name = "f2k_export_SetTextCharacterExtra")]
pub extern "system" fn set_text_character_extra(dc: usize, extra: i32) -> i32 {
    if extra == EXTRA_FAILED {
        return failed(ERROR_INVALID_PARAMETER).unwrap_or(EXTRA_FAILED);
    }
    match imports::set_dc_dword(dc, DC_CHAR_EXTRA, extra as u32) {
        Ok(previous) => previous as i32,
        Err(_) => failed(ERROR_INVALID_PARAMETER).unwrap_or(EXTRA_FAILED),
    }
}

/// SetTextJustification: the extra and the break count set (win32k spreads the one over the
/// other's breaks); FALSE for a DC that is none, the last error untouched.
#[unsafe(export_name = "f2k_export_SetTextJustification")]
pub extern "system" fn set_text_justification(dc: usize, extra: i32, breaks: i32) -> u32 {
    let set = imports::set_dc_dword(dc, DC_BREAK_EXTRA, extra as u32)
        .and_then(|_| imports::set_dc_dword(dc, DC_BREAK_COUNT, breaks as u32));
    u32::from(set.is_ok())
}

// --- the extents ---------------------------------------------------------------------------------

/// The extents of `count` units at `string` (glyph indices with GTEEFL_INDICES): TRUE, or FALSE
/// with ERROR_INVALID_PARAMETER for a count that is not positive, the service's last error
/// otherwise.
#[allow(clippy::too_many_arguments)]
fn extent_ex(
    dc: usize,
    string: Caller,
    count: i32,
    max: i32,
    fit: *mut i32,
    dx: *mut i32,
    size: *mut Size,
    flags: u32,
) -> u32 {
    if count <= 0 {
        return failed(ERROR_INVALID_PARAMETER).unwrap_or(0);
    }
    answered(imports::text_extent_ex(
        dc,
        string,
        count as u32,
        max as u32,
        Caller(fit as usize),
        Caller(dx as usize),
        Caller(size as usize),
        flags,
    ))
    .map_or(0, |()| 1)
}

/// GetTextExtentExPointW: the string's SIZE, each character's partial extent into `dx` (when not
/// null), and how many of them are within `max` (taken unsigned) into `fit` (when not null).
#[unsafe(export_name = "f2k_export_GetTextExtentExPointW")]
pub extern "system" fn get_text_extent_ex_point_w(
    dc: usize,
    string: *const u16,
    count: i32,
    max: i32,
    fit: *mut i32,
    dx: *mut i32,
    size: *mut Size,
) -> u32 {
    extent_ex(dc, Caller(string as usize), count, max, fit, dx, size, 0)
}

/// GetTextExtentExPointA: the string converted to its wide form (a unit per byte, the ANSI code
/// page being single-byte, so the partial extents keep their meaning), then
/// GetTextExtentExPointW's.
///
/// # Safety
///
/// The caller's string of `count` bytes, as for the platform's.
#[unsafe(export_name = "f2k_export_GetTextExtentExPointA")]
pub unsafe extern "system" fn get_text_extent_ex_point_a(
    dc: usize,
    string: *const u8,
    count: i32,
    max: i32,
    fit: *mut i32,
    dx: *mut i32,
    size: *mut Size,
) -> u32 {
    if count <= 0 {
        return failed(ERROR_INVALID_PARAMETER).unwrap_or(0);
    }
    // SAFETY: the caller's `count` bytes.
    let bytes = unsafe { InBuf::new(string, count as usize) }.bytes();
    with_wide(bytes, |units| {
        extent_ex(
            dc,
            Caller(units.as_ptr() as usize),
            units.len() as i32,
            max,
            fit,
            dx,
            size,
            0,
        )
    })
    .unwrap_or(0)
}

/// GetTextExtentExPointI: GetTextExtentExPointW's over glyph indices.
#[unsafe(export_name = "f2k_export_GetTextExtentExPointI")]
pub extern "system" fn get_text_extent_ex_point_i(
    dc: usize,
    glyphs: *const u16,
    count: i32,
    max: i32,
    fit: *mut i32,
    dx: *mut i32,
    size: *mut Size,
) -> u32 {
    extent_ex(
        dc,
        Caller(glyphs as usize),
        count,
        max,
        fit,
        dx,
        size,
        GTEEFL_INDICES,
    )
}

/// GetTextExtentPointI: the glyphs' SIZE (0 by 0 for none); FALSE with ERROR_INVALID_PARAMETER
/// for a negative count.
#[unsafe(export_name = "f2k_export_GetTextExtentPointI")]
pub extern "system" fn get_text_extent_point_i(
    dc: usize,
    glyphs: *const u16,
    count: i32,
    size: *mut Size,
) -> u32 {
    if count < 0 {
        return failed(ERROR_INVALID_PARAMETER).unwrap_or(0);
    }
    answered(imports::text_extent_ex(
        dc,
        Caller(glyphs as usize),
        count as u32,
        u32::MAX,
        Caller::NONE,
        Caller::NONE,
        Caller(size as usize),
        GTEEFL_INDICES,
    ))
    .map_or(0, |()| 1)
}

/// GetTextExtentPointA: GetTextExtentPoint32A's SIZE.
///
/// # Safety
///
/// The caller's string of `count` bytes, as for the platform's.
#[unsafe(export_name = "f2k_export_GetTextExtentPointA")]
pub unsafe extern "system" fn get_text_extent_point_a(
    dc: usize,
    string: *const u8,
    count: i32,
    size: *mut Size,
) -> u32 {
    // SAFETY: the caller's contract, passed on.
    unsafe { crate::text::get_text_extent_point32_a(dc, string, count, size) }
}

/// GetGlyphIndicesW: each character's glyph index in the DC's font into `glyphs`; how many were
/// converted, GDI_ERROR with the last error for a negative count or a DC that is none.
#[unsafe(export_name = "f2k_export_GetGlyphIndicesW")]
pub extern "system" fn get_glyph_indices_w(
    dc: usize,
    string: *const u16,
    count: i32,
    glyphs: *mut u16,
    flags: u32,
) -> u32 {
    if count < 0 {
        return failed(ERROR_INVALID_PARAMETER).unwrap_or(GDI_ERROR);
    }
    answered(imports::glyph_indices(
        dc,
        Caller(string as usize),
        count as u32,
        Caller(glyphs as usize),
        flags,
    ))
    .unwrap_or(GDI_ERROR)
}

// --- GetCharacterPlacement -----------------------------------------------------------------------

/// What GetCharacterPlacement writes for left-to-right text of `count` characters whose partial
/// extents are `partials`, `fit` of them within the maximum: how many it lays out (all, or under
/// GCP_MAXEXTENT the fit, no more than the arrays hold), each one's advance (`dx`), its caret
/// position (its left: the partial extent before it) and its place in the order (its own).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Placement {
    pub glyphs: usize,
    pub max_fit: i32,
}

impl Placement {
    /// The placement of `count` characters, `fit` of them within the maximum, into arrays of
    /// `room`.
    pub fn new(count: usize, fit: usize, flags: u32, room: usize) -> Self {
        let laid = if flags & GCP_MAXEXTENT != 0 {
            fit
        } else {
            count
        };
        Placement {
            glyphs: laid.min(room),
            max_fit: laid as i32,
        }
    }

    /// Character `index`'s advance.
    pub fn advance(partials: &[i32], index: usize) -> i32 {
        partials[index] - Placement::caret(partials, index)
    }

    /// Character `index`'s caret position.
    pub fn caret(partials: &[i32], index: usize) -> i32 {
        index.checked_sub(1).map_or(0, |before| partials[before])
    }
}

/// The partial extents of the `count` units at `string` into `partials`, the SIZE answered and
/// how many are within `max` (ignored without GCP_MAXEXTENT); none with the last error.
fn partial_extents(
    dc: usize,
    string: Caller,
    partials: &mut [i32],
    max: i32,
    flags: u32,
) -> Option<(Size, usize)> {
    let max = if flags & GCP_MAXEXTENT != 0 {
        max as u32
    } else {
        u32::MAX
    };
    let mut size = Size::default();
    let mut fit = 0u32;
    answered(imports::text_extent_ex(
        dc,
        string,
        partials.len() as u32,
        max,
        Caller::of_mut(&mut fit),
        Caller(partials.as_mut_ptr() as usize),
        Caller::of_mut(&mut size),
        0,
    ))?;
    Some((size, fit as usize))
}

/// GetCharacterPlacement's work over the wide string at `wide` of `count` units (its out string
/// written by `out_string`, the narrow or the wide form's): the whole string's SIZE as
/// MAKELONG(cx, cy); 0 with ERROR_INVALID_PARAMETER for a count that is not positive. Left-to-right
/// text alone: the order is the string's, and nothing is reordered, ligated, kerned or classed
/// (lpClass is left).
fn placement(
    dc: usize,
    wide: Caller,
    count: i32,
    max: i32,
    results: *mut GcpResults,
    flags: u32,
    out_string: impl FnOnce(usize, usize),
) -> u32 {
    if count <= 0 {
        return failed(ERROR_INVALID_PARAMETER).unwrap_or(0);
    }
    let count = count as usize;
    let Some(mut block) = HeapBlock::new(4 * count) else {
        return failed(ERROR_NOT_ENOUGH_MEMORY).unwrap_or(0);
    };
    // SAFETY: the block's bytes, 8-aligned (the heap's alignment), viewed as `count` ints.
    let partials = unsafe {
        core::slice::from_raw_parts_mut(block.bytes_mut().as_mut_ptr().cast::<i32>(), count)
    };
    let Some((size, fit)) = partial_extents(dc, wide, partials, max, flags) else {
        return 0;
    };
    let answer = (size.cx as u32 & 0xFFFF) | ((size.cy as u32) << 16);
    // SAFETY: the caller's GCP_RESULTS, or null.
    let Some(mut results) = (unsafe { Out::optional(results) }) else {
        return answer;
    };
    let mut got = results.get();
    let laid = Placement::new(count, fit, flags, got.glyph_count as usize);
    let n = laid.glyphs;
    out_string(got.out_string, n);
    // SAFETY: the caller's arrays, each null or of `nGlyphs` elements at least.
    unsafe {
        if let Some(mut order) = OutBuf::optional(got.order as *mut u32, n) {
            (0..n).for_each(|index| order.set(index, index as u32));
        }
        if let Some(mut dx) = OutBuf::optional(got.dx as *mut i32, n) {
            (0..n).for_each(|index| dx.set(index, Placement::advance(partials, index)));
        }
        if let Some(mut caret) = OutBuf::optional(got.caret_pos as *mut i32, n) {
            (0..n).for_each(|index| caret.set(index, Placement::caret(partials, index)));
        }
    }
    if got.glyphs != 0 {
        let _ = imports::glyph_indices(dc, wide, n as u32, Caller(got.glyphs), 0);
    }
    got.glyph_count = n as u32;
    got.max_fit = laid.max_fit;
    results.set(got);
    answer
}

/// GetCharacterPlacementW: see [`placement`]; the out string the string's first units.
///
/// # Safety
///
/// The caller's string of `count` units and its GCP_RESULTSW, as for the platform's.
#[unsafe(export_name = "f2k_export_GetCharacterPlacementW")]
pub unsafe extern "system" fn get_character_placement_w(
    dc: usize,
    string: *const u16,
    count: i32,
    max: i32,
    results: *mut GcpResults,
    flags: u32,
) -> u32 {
    placement(
        dc,
        Caller(string as usize),
        count,
        max,
        results,
        flags,
        |out, n| {
            // SAFETY: the caller's string of `count` units, and its out string of `nGlyphs`
            // units at least (or null); `n` is no more than either.
            unsafe {
                if let Some(mut out) = OutBuf::optional(out as *mut u16, n) {
                    let units = InBuf::new(string, n);
                    (0..n).for_each(|index| out.set(index, units.get(index)));
                }
            }
        },
    )
}

/// GetCharacterPlacementA: the string converted to its wide form for the layout, the out string
/// its own bytes.
///
/// # Safety
///
/// The caller's string of `count` bytes and its GCP_RESULTSA, as for the platform's.
#[unsafe(export_name = "f2k_export_GetCharacterPlacementA")]
pub unsafe extern "system" fn get_character_placement_a(
    dc: usize,
    string: *const u8,
    count: i32,
    max: i32,
    results: *mut GcpResults,
    flags: u32,
) -> u32 {
    if count <= 0 {
        return failed(ERROR_INVALID_PARAMETER).unwrap_or(0);
    }
    // SAFETY: the caller's `count` bytes.
    let bytes = unsafe { InBuf::new(string, count as usize) }.bytes();
    with_wide(bytes, |units| {
        placement(
            dc,
            Caller(units.as_ptr() as usize),
            units.len() as i32,
            max,
            results,
            flags,
            |out, n| {
                // SAFETY: the caller's out string of `nGlyphs` bytes at least (or null).
                if let Some(mut out) = unsafe { OutBuf::optional(out as *mut u8, n) } {
                    out.put(&bytes[..n]);
                }
            },
        )
    })
    .unwrap_or(0)
}

// --- PolyTextOut ---------------------------------------------------------------------------------

/// PolyTextOut's work: each of the `count` strings at `texts` drawn by `draw` (ExtTextOutA's or
/// ExtTextOutW's), until one fails; TRUE for none, FALSE with ERROR_INVALID_PARAMETER for a
/// negative count.
fn poly_text_out(texts: *const PolyText, count: i32, draw: impl Fn(&PolyText) -> u32) -> u32 {
    if count < 0 {
        return failed(ERROR_INVALID_PARAMETER).unwrap_or(0);
    }
    if count == 0 {
        return 1;
    }
    // SAFETY: the caller's `count` POLYTEXTs.
    let texts = unsafe { InBuf::new(texts, count as usize) };
    for text in texts.iter() {
        if draw(&text) == 0 {
            return 0;
        }
    }
    1
}

/// PolyTextOutW: each POLYTEXTW's string ExtTextOutW's, at its point, with its options, its
/// rectangle and its advances.
#[unsafe(export_name = "f2k_export_PolyTextOutW")]
pub extern "system" fn poly_text_out_w(dc: usize, texts: *const PolyText, count: i32) -> u32 {
    poly_text_out(texts, count, |text| {
        ext_text_out_w(
            dc,
            text.x,
            text.y,
            text.options,
            &text.rect as *const Rect as usize,
            text.string as *const u16,
            text.count,
            text.dx as *const i32,
        )
    })
}

/// PolyTextOutA: each POLYTEXTA's string ExtTextOutA's.
///
/// # Safety
///
/// The caller's POLYTEXTAs and their strings, as for the platform's.
#[unsafe(export_name = "f2k_export_PolyTextOutA")]
pub unsafe extern "system" fn poly_text_out_a(
    dc: usize,
    texts: *const PolyText,
    count: i32,
) -> u32 {
    poly_text_out(texts, count, |text| {
        // SAFETY: the caller's string of `n` bytes, its advances and the POLYTEXTA's rectangle.
        unsafe {
            ext_text_out_a(
                dc,
                text.x,
                text.y,
                text.options,
                &text.rect as *const Rect as usize,
                text.string as *const u8,
                text.count,
                text.dx as *const i32,
            )
        }
    })
}

#[cfg(test)]
mod tests {
    use rtl::testing::wide;

    use super::*;
    use crate::imports::host::{TextCall, BAD, DC, HOST_DC, LAST_ERROR, TEXT};
    use crate::ERROR_INVALID_HANDLE;

    fn last_error() -> u32 {
        LAST_ERROR.with(|error| error.get())
    }

    fn untouched() {
        LAST_ERROR.with(|error| error.set(0xF2F2));
    }

    fn reset() {
        HOST_DC.with(|dc| *dc.borrow_mut() = crate::imports::host::HostDc::new());
        TEXT.with(|text| text.take());
        untouched();
    }

    /// The capture's alignment: TA_LEFT|TA_TOP|TA_NOUPDATECP on a new DC; every bit kept
    /// (TA_RTLREADING, 0x1000); the previous value answered; a DC that is none GDI_ERROR, with
    /// ERROR_INVALID_HANDLE from SetTextAlign alone.
    ///
    /// Pins: gdi32.GetTextAlign gdi32.SetTextAlign
    #[test]
    fn the_alignment_is_kept_as_set() {
        reset();
        assert_eq!(get_text_align(DC), TA_LEFT | TA_TOP | TA_NOUPDATECP);
        assert_eq!(set_text_align(DC, TA_CENTER | TA_BASELINE), 0);
        assert_eq!(get_text_align(DC), TA_CENTER | TA_BASELINE);
        assert_eq!(set_text_align(DC, 0x1000), TA_CENTER | TA_BASELINE);
        assert_eq!(set_text_align(DC, TA_RTLREADING), 0x1000);
        assert_eq!(get_text_align(DC), TA_RTLREADING);
        assert_eq!(last_error(), 0xF2F2);
        assert_eq!(get_text_align(BAD), GDI_ERROR);
        assert_eq!(last_error(), 0xF2F2, "GetTextAlign sets no error");
        assert_eq!(set_text_align(BAD, TA_CENTER), GDI_ERROR);
        assert_eq!(last_error(), ERROR_INVALID_HANDLE);
    }

    /// The capture's character extra: 0 on a new DC, 3 then -2 answered back; a DC that is none
    /// 0x80000000, SetTextCharacterExtra's with ERROR_INVALID_PARAMETER, GetTextCharacterExtra's
    /// with none; the extra 0x80000000 refused.
    ///
    /// Pins: gdi32.GetTextCharacterExtra gdi32.SetTextCharacterExtra
    #[test]
    fn the_character_extra_answers_the_previous_one() {
        reset();
        assert_eq!(get_text_character_extra(DC), 0);
        assert_eq!(set_text_character_extra(DC, 3), 0);
        assert_eq!(set_text_character_extra(DC, -2), 3);
        assert_eq!(get_text_character_extra(DC), -2);
        assert_eq!(get_text_character_extra(BAD), EXTRA_FAILED);
        assert_eq!(last_error(), 0xF2F2);
        assert_eq!(set_text_character_extra(BAD, 1), EXTRA_FAILED);
        assert_eq!(last_error(), ERROR_INVALID_PARAMETER);
        untouched();
        assert_eq!(set_text_character_extra(DC, EXTRA_FAILED), EXTRA_FAILED);
        assert_eq!(last_error(), ERROR_INVALID_PARAMETER);
        assert_eq!(get_text_character_extra(DC), -2, "the DC untouched");
    }

    /// SetTextJustification sets the extra and the break count, negative ones too; a DC that is
    /// none is FALSE without an error.
    ///
    /// Pins: gdi32.SetTextJustification
    #[test]
    fn the_justification_is_set() {
        reset();
        assert_eq!(set_text_justification(DC, -4, 2), 1);
        HOST_DC.with(|dc| {
            let dc = dc.borrow();
            assert_eq!((dc.break_extra as i32, dc.break_count), (-4, 2));
        });
        assert_eq!(set_text_justification(BAD, 10, 2), 0);
        assert_eq!(last_error(), 0xF2F2);
    }

    /// GetTextExtentExPoint over the stand-in's font ("Hello": 8, 8, 4, 4, 8): the partial
    /// extents and the fit within 20 ("Hel", exactly 20); a NULL fit or array; a count of 0 refused
    /// with ERROR_INVALID_PARAMETER, nothing written; the narrow form alike.
    ///
    /// Pins: gdi32.GetTextExtentExPointW gdi32.GetTextExtentExPointA
    #[test]
    fn the_extent_with_a_maximum() {
        reset();
        let hello = wide("Hello");
        let mut dx = [0i32; 5];
        let mut fit = -1;
        let mut size = Size::default();
        assert_eq!(
            get_text_extent_ex_point_w(
                DC,
                hello.as_ptr(),
                5,
                20,
                &mut fit,
                dx.as_mut_ptr(),
                &mut size
            ),
            1
        );
        assert_eq!(
            (fit, dx, size),
            (3, [8, 16, 20, 24, 32], Size { cx: 32, cy: 16 })
        );
        let mut dx = [0i32; 5];
        // SAFETY: the tests' own string and structures.
        unsafe {
            assert_eq!(
                get_text_extent_ex_point_a(
                    DC,
                    b"Hello".as_ptr(),
                    5,
                    -1,
                    core::ptr::null_mut(),
                    dx.as_mut_ptr(),
                    &mut size
                ),
                1
            );
            assert_eq!(dx, [8, 16, 20, 24, 32]);
            fit = -1;
            size = Size { cx: -1, cy: -1 };
            assert_eq!(
                get_text_extent_ex_point_a(
                    DC,
                    b"Hello".as_ptr(),
                    0,
                    20,
                    &mut fit,
                    dx.as_mut_ptr(),
                    &mut size
                ),
                0
            );
        }
        assert_eq!(last_error(), ERROR_INVALID_PARAMETER);
        assert_eq!((fit, size), (-1, Size { cx: -1, cy: -1 }));
        untouched();
        assert_eq!(
            get_text_extent_ex_point_w(
                DC,
                hello.as_ptr(),
                5,
                -1,
                &mut fit,
                core::ptr::null_mut(),
                &mut size
            ),
            1
        );
        assert_eq!(fit, 5, "a negative maximum fits everything");
    }

    /// The glyph-index forms: GetGlyphIndicesW's indices measured by GetTextExtentPointI as the
    /// characters are; a count of 0 is 0 by 0; GetTextExtentPointA as GetTextExtentPoint32A.
    ///
    /// Pins: gdi32.GetGlyphIndicesW gdi32.GetTextExtentPointI gdi32.GetTextExtentExPointI
    /// gdi32.GetTextExtentPointA
    #[test]
    fn the_glyph_index_extents() {
        reset();
        let text = wide("Hello world");
        let mut glyphs = [0u16; 11];
        assert_eq!(
            get_glyph_indices_w(DC, text.as_ptr(), 11, glyphs.as_mut_ptr(), 0),
            11
        );
        assert_eq!(glyphs[2], glyphs[3]);
        let (mut by_glyph, mut by_char) = (Size::default(), Size::default());
        assert_eq!(
            get_text_extent_point_i(DC, glyphs.as_ptr(), 11, &mut by_glyph),
            1
        );
        assert_eq!(
            get_text_extent_ex_point_w(
                DC,
                text.as_ptr(),
                11,
                0,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                &mut by_char
            ),
            1
        );
        assert_eq!(by_glyph, by_char);
        let mut fit = 0;
        assert_eq!(
            get_text_extent_ex_point_i(
                DC,
                glyphs.as_ptr(),
                11,
                40,
                &mut fit,
                core::ptr::null_mut(),
                &mut by_glyph
            ),
            1
        );
        assert_eq!(fit, 6);
        assert_eq!(
            get_text_extent_point_i(DC, glyphs.as_ptr(), 0, &mut by_glyph),
            1
        );
        assert_eq!(by_glyph, Size::default());
        let mut size = Size::default();
        // SAFETY: the tests' own string.
        assert_eq!(
            unsafe { get_text_extent_point_a(DC, b"Hello".as_ptr(), 5, &mut size) },
            1
        );
        assert_eq!(
            get_glyph_indices_w(BAD, text.as_ptr(), 1, glyphs.as_mut_ptr(), 0),
            GDI_ERROR
        );
        assert_eq!(last_error(), ERROR_INVALID_HANDLE);
    }

    /// GetCharacterPlacement's arithmetic: each advance the difference of the partial extents,
    /// each caret the one before; GCP_MAXEXTENT lays out the fit alone, no more than the arrays
    /// hold.
    #[test]
    fn placement_from_partial_extents() {
        // The capture's "Hello" in the system font.
        let partials = [10, 18, 22, 26, 34];
        let advances: std::vec::Vec<_> = (0..5).map(|i| Placement::advance(&partials, i)).collect();
        let carets: std::vec::Vec<_> = (0..5).map(|i| Placement::caret(&partials, i)).collect();
        assert_eq!(advances, [10, 8, 4, 4, 8]);
        assert_eq!(carets, [0, 10, 18, 22, 26]);
        assert_eq!(
            Placement::new(5, 0, 0, 16),
            Placement {
                glyphs: 5,
                max_fit: 5
            }
        );
        assert_eq!(
            Placement::new(5, 2, GCP_MAXEXTENT, 16),
            Placement {
                glyphs: 2,
                max_fit: 2
            }
        );
        assert_eq!(
            Placement::new(5, 5, 0, 3),
            Placement {
                glyphs: 3,
                max_fit: 5
            }
        );
    }

    /// GetCharacterPlacementW and A over the stand-in's font: the whole SIZE answered as
    /// MAKELONG(cx, cy), the out string, advances, carets and order; GCP_MAXEXTENT's three
    /// characters within 20; no results; a count of 0 refused.
    ///
    /// Pins: gdi32.GetCharacterPlacementW gdi32.GetCharacterPlacementA
    #[test]
    fn character_placement() {
        reset();
        let hello = wide("Hello");
        let (mut out, mut order, mut dx, mut caret) = ([0u16; 8], [9u32; 8], [0i32; 8], [0i32; 8]);
        let mut results = GcpResults {
            struct_size: 36,
            out_string: out.as_mut_ptr() as usize,
            order: order.as_mut_ptr() as usize,
            dx: dx.as_mut_ptr() as usize,
            caret_pos: caret.as_mut_ptr() as usize,
            glyph_count: 8,
            ..GcpResults::default()
        };
        // SAFETY: the tests' own string and results.
        let answer =
            unsafe { get_character_placement_w(DC, hello.as_ptr(), 5, 0, &mut results, 0) };
        assert_eq!(answer, 32 | (16 << 16));
        assert_eq!((results.glyph_count, results.max_fit), (5, 5));
        assert_eq!(&out[..6], &[0x48, 0x65, 0x6C, 0x6C, 0x6F, 0]);
        assert_eq!(&order[..6], &[0, 1, 2, 3, 4, 9]);
        assert_eq!(&dx[..5], &[8, 8, 4, 4, 8]);
        assert_eq!(&caret[..5], &[0, 8, 16, 20, 24]);
        let mut narrow = [0u8; 8];
        results.out_string = narrow.as_mut_ptr() as usize;
        results.glyph_count = 8;
        dx = [0; 8];
        // SAFETY: the tests' own string and results.
        let answer = unsafe {
            get_character_placement_a(DC, b"Hello".as_ptr(), 5, 20, &mut results, GCP_MAXEXTENT)
        };
        assert_eq!(answer, 32 | (16 << 16), "the whole string's SIZE");
        assert_eq!((results.glyph_count, results.max_fit), (3, 3));
        assert_eq!(&narrow[..4], b"Hel\0");
        assert_eq!(&dx[..4], &[8, 8, 4, 0]);
        // SAFETY: the tests' own string and results.
        unsafe {
            assert_eq!(
                get_character_placement_w(DC, hello.as_ptr(), 5, 0, core::ptr::null_mut(), 0),
                32 | (16 << 16)
            );
            untouched();
            assert_eq!(
                get_character_placement_w(DC, hello.as_ptr(), 0, 0, &mut results, 0),
                0
            );
        }
        assert_eq!(last_error(), ERROR_INVALID_PARAMETER);
    }

    /// PolyTextOut draws each string as ExtTextOut does, the narrow ones converted; a count of 0
    /// draws nothing and succeeds.
    ///
    /// Pins: gdi32.PolyTextOutW gdi32.PolyTextOutA
    #[test]
    fn poly_text_out_draws_each_string() {
        reset();
        let ab = wide("Ab");
        let abc = wide("abc");
        let rect = Rect {
            left: 20,
            top: 24,
            right: 90,
            bottom: 46,
        };
        let texts = [
            PolyText {
                x: 4,
                y: 2,
                count: 2,
                string: ab.as_ptr() as usize,
                ..PolyText::default()
            },
            PolyText {
                x: 30,
                y: 26,
                count: 3,
                string: abc.as_ptr() as usize,
                options: ETO_OPAQUE,
                rect,
                ..PolyText::default()
            },
        ];
        assert_eq!(poly_text_out_w(DC, texts.as_ptr(), 2), 1);
        let narrow = [
            PolyText {
                string: b"Ab".as_ptr() as usize,
                ..texts[0]
            },
            PolyText {
                string: b"abc".as_ptr() as usize,
                ..texts[1]
            },
        ];
        // SAFETY: the tests' own strings.
        assert_eq!(unsafe { poly_text_out_a(DC, narrow.as_ptr(), 2) }, 1);
        assert_eq!(poly_text_out_w(DC, texts.as_ptr(), 0), 1);
        let call = |x, y, options, units: &[u16]| TextCall {
            dc: DC,
            x,
            y,
            options,
            rect: Some(if options == 0 { Rect::default() } else { rect }),
            units: units.to_vec(),
            dx: None,
        };
        let expected = [call(4, 2, 0, &ab), call(30, 26, ETO_OPAQUE, &abc)];
        let made = TEXT.with(|text| text.take());
        assert_eq!(made, [expected.clone(), expected].concat());
    }
}
