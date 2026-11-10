//! Text: TextOut and ExtTextOut, GetTextMetrics and GetTextExtentPoint32, each over its win32k
//! service ([`imports`]). The wide forms hand the caller's string (and rectangle, advances and
//! structures) to the kernel unread; the narrow ones convert the string to its wide form first, in
//! the ANSI code page ([`crate::with_wide`]), and GetTextMetricsA the answer's characters back.
//! The font is the kernel's one built-in font, whatever font the DC has selected.

use rtl::edge::InBuf;
use rtl::gdi::{narrow_text_metric, Size, TextMetricA, TextMetricW};

use crate::imports::{self, Caller};
use crate::{answered, failed, with_wide, Out, ERROR_INVALID_PARAMETER};

/// ExtTextOutW's drawing over `count` units at `string` (an address handed to the kernel): TRUE,
/// or FALSE with the last error.
#[allow(clippy::too_many_arguments)]
fn draw(
    dc: usize,
    x: i32,
    y: i32,
    options: u32,
    rect: Caller,
    string: Caller,
    count: u32,
    dx: Caller,
) -> u32 {
    answered(imports::ext_text_out(
        dc, x, y, options, rect, string, count, dx,
    ))
    .map_or(0, |()| 1)
}

/// ExtTextOutW: the string drawn at (`x`, `y`) in the DC's colors and background mode, with
/// ETO_OPAQUE's fill and ETO_CLIPPED's clip over the rectangle, each character's cell `dx[i]`
/// after the one before when `dx` is given; FALSE with the last error for a DC that is none or
/// memory the kernel cannot read.
#[unsafe(export_name = "f2k_export_ExtTextOutW")]
pub extern "system" fn ext_text_out_w(
    dc: usize,
    x: i32,
    y: i32,
    options: u32,
    rect: usize,
    string: *const u16,
    count: u32,
    dx: *const i32,
) -> u32 {
    draw(
        dc,
        x,
        y,
        options,
        Caller(rect),
        Caller(string as usize),
        count,
        Caller(dx as usize),
    )
}

/// ExtTextOutA: the string converted to its wide form (a character per byte, the ANSI code page
/// being single-byte, so `dx` keeps its meaning), then ExtTextOutW's drawing.
///
/// # Safety
///
/// The caller's string of `count` bytes, as for the platform's.
#[unsafe(export_name = "f2k_export_ExtTextOutA")]
pub unsafe extern "system" fn ext_text_out_a(
    dc: usize,
    x: i32,
    y: i32,
    options: u32,
    rect: usize,
    string: *const u8,
    count: u32,
    dx: *const i32,
) -> u32 {
    // SAFETY: the caller's `count` bytes.
    let bytes = unsafe { InBuf::new(string, count as usize) }.bytes();
    with_wide(bytes, |units| {
        draw(
            dc,
            x,
            y,
            options,
            Caller(rect),
            Caller(units.as_ptr() as usize),
            units.len() as u32,
            Caller(dx as usize),
        )
    })
    .unwrap_or(0)
}

/// TextOutW: ExtTextOutW's drawing without options; FALSE with ERROR_INVALID_PARAMETER for a
/// negative length.
#[unsafe(export_name = "f2k_export_TextOutW")]
pub extern "system" fn text_out_w(
    dc: usize,
    x: i32,
    y: i32,
    string: *const u16,
    count: i32,
) -> u32 {
    if count < 0 {
        return failed(ERROR_INVALID_PARAMETER).unwrap_or(0);
    }
    draw(
        dc,
        x,
        y,
        0,
        Caller::NONE,
        Caller(string as usize),
        count as u32,
        Caller::NONE,
    )
}

/// TextOutA: the string converted to its wide form, then TextOutW's drawing.
///
/// # Safety
///
/// The caller's string of `count` bytes, as for the platform's.
#[unsafe(export_name = "f2k_export_TextOutA")]
pub unsafe extern "system" fn text_out_a(
    dc: usize,
    x: i32,
    y: i32,
    string: *const u8,
    count: i32,
) -> u32 {
    if count < 0 {
        return failed(ERROR_INVALID_PARAMETER).unwrap_or(0);
    }
    // SAFETY: the caller's `count` bytes.
    let bytes = unsafe { InBuf::new(string, count as usize) }.bytes();
    with_wide(bytes, |units| {
        text_out_w(dc, x, y, units.as_ptr(), units.len() as i32)
    })
    .unwrap_or(0)
}

/// GetTextMetricsW: the DC's font's TEXTMETRICW into `metric`; FALSE with the last error for a DC
/// that is none or a structure the kernel cannot write.
#[unsafe(export_name = "f2k_export_GetTextMetricsW")]
pub extern "system" fn get_text_metrics_w(dc: usize, metric: *mut TextMetricW) -> u32 {
    answered(imports::text_metrics(dc, Caller(metric as usize))).map_or(0, |()| 1)
}

/// GetTextMetricsA: GetTextMetricsW's answer, its four characters converted to the ANSI code page;
/// FALSE with ERROR_INVALID_PARAMETER for no structure.
///
/// # Safety
///
/// The caller's TEXTMETRICA (or null), as for the platform's.
#[unsafe(export_name = "f2k_export_GetTextMetricsA")]
pub unsafe extern "system" fn get_text_metrics_a(dc: usize, metric: *mut TextMetricA) -> u32 {
    // SAFETY: the caller's structure, or null.
    let Some(mut out) = (unsafe { Out::optional(metric) }) else {
        return failed(ERROR_INVALID_PARAMETER).unwrap_or(0);
    };
    let mut wide = TextMetricW::default();
    if answered(imports::text_metrics(dc, Caller::of_mut(&mut wide))).is_none() {
        return 0;
    }
    out.set(narrow_text_metric(&wide, |unit| {
        let mut byte = [0u8];
        imports::unicode_to_multi_byte(&mut byte, &[unit]);
        byte[0]
    }));
    1
}

/// GetTextExtentPoint32W: the SIZE of `count` characters of the string in the DC's font into
/// `size`; FALSE with ERROR_INVALID_PARAMETER for a negative length, with the last error for a DC
/// that is none or memory the kernel cannot reach.
#[unsafe(export_name = "f2k_export_GetTextExtentPoint32W")]
pub extern "system" fn get_text_extent_point32_w(
    dc: usize,
    string: *const u16,
    count: i32,
    size: *mut Size,
) -> u32 {
    if count < 0 {
        return failed(ERROR_INVALID_PARAMETER).unwrap_or(0);
    }
    answered(imports::text_extent(
        dc,
        Caller(string as usize),
        count as u32,
        Caller(size as usize),
    ))
    .map_or(0, |()| 1)
}

/// GetTextExtentPointW: GetTextExtentPoint32W's SIZE. (Its documentation calls it the 16-bit
/// Windows form, GetTextExtentPoint32W's computation the more accurate; over the built-in font's
/// fixed cells they answer alike.) user32's DrawText measures through it, as Windows 2000's
/// user32 imports it.
#[unsafe(export_name = "f2k_export_GetTextExtentPointW")]
pub extern "system" fn get_text_extent_point_w(
    dc: usize,
    string: *const u16,
    count: i32,
    size: *mut Size,
) -> u32 {
    get_text_extent_point32_w(dc, string, count, size)
}

/// GetTextExtentPoint32A: the string converted to its wide form, then GetTextExtentPoint32W's
/// SIZE.
///
/// # Safety
///
/// The caller's string of `count` bytes, as for the platform's.
#[unsafe(export_name = "f2k_export_GetTextExtentPoint32A")]
pub unsafe extern "system" fn get_text_extent_point32_a(
    dc: usize,
    string: *const u8,
    count: i32,
    size: *mut Size,
) -> u32 {
    if count < 0 {
        return failed(ERROR_INVALID_PARAMETER).unwrap_or(0);
    }
    // SAFETY: the caller's `count` bytes.
    let bytes = unsafe { InBuf::new(string, count as usize) }.bytes();
    with_wide(bytes, |units| {
        get_text_extent_point32_w(dc, units.as_ptr(), units.len() as i32, size)
    })
    .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use rtl::gdi::{Rect, ETO_OPAQUE};

    use super::*;
    use crate::imports::host::{TextCall, BAD, DC, LAST_ERROR, TEXT};
    use crate::ERROR_INVALID_HANDLE;

    fn calls() -> std::vec::Vec<TextCall> {
        TEXT.with(|text| text.take())
    }

    fn last_error() -> u32 {
        LAST_ERROR.with(|error| error.get())
    }

    fn units(text: &str) -> std::vec::Vec<u16> {
        text.encode_utf16().collect()
    }

    /// The guidc capture's text calls: TextOutA and TextOutW of "Hi", ExtTextOutA and ExtTextOutW
    /// of "abc" with ETO_OPAQUE over a rectangle, each TRUE; the narrow forms reach the kernel as
    /// the same wide string, the rectangle and the options as given.
    #[test]
    fn text_reaches_the_kernel_wide() {
        calls();
        LAST_ERROR.with(|error| error.set(0xF2F2));
        let hi = units("Hi");
        let abc = units("abc");
        let rect = Rect {
            left: 0,
            top: 40,
            right: 100,
            bottom: 60,
        };
        // SAFETY: the tests' own strings and rectangle.
        unsafe {
            assert_eq!(text_out_a(DC, 5, 5, b"Hi".as_ptr(), 2), 1);
            assert_eq!(text_out_w(DC, 5, 25, hi.as_ptr(), 2), 1);
            let at = &rect as *const Rect as usize;
            assert_eq!(
                ext_text_out_a(
                    DC,
                    0,
                    40,
                    ETO_OPAQUE,
                    at,
                    b"abc".as_ptr(),
                    3,
                    core::ptr::null()
                ),
                1
            );
            assert_eq!(
                ext_text_out_w(
                    DC,
                    0,
                    40,
                    ETO_OPAQUE,
                    at,
                    abc.as_ptr(),
                    3,
                    core::ptr::null()
                ),
                1
            );
        }
        assert_eq!(last_error(), 0xF2F2, "a success leaves the last error");
        let text = |x, y, options, rect, units: &[u16]| TextCall {
            dc: DC,
            x,
            y,
            options,
            rect,
            units: units.to_vec(),
            dx: None,
        };
        assert_eq!(
            calls(),
            [
                text(5, 5, 0, None, &hi),
                text(5, 25, 0, None, &hi),
                text(0, 40, ETO_OPAQUE, Some(rect), &abc),
                text(0, 40, ETO_OPAQUE, Some(rect), &abc),
            ]
        );
    }

    /// The A-to-W conversion: ANSI bytes become their Unicode characters (0x80 the euro sign, 0xE9
    /// é), a long string through the heap; the advances go along unchanged.
    #[test]
    fn narrow_text_converts_through_the_code_page() {
        calls();
        let advances = [10, 11, 12];
        // SAFETY: the tests' own strings and advances.
        unsafe {
            assert_eq!(
                ext_text_out_a(DC, 1, 2, 0, 0, b"\x80\xE9z".as_ptr(), 3, advances.as_ptr()),
                1
            );
            let long = std::vec![b'q'; 700];
            assert_eq!(text_out_a(DC, 0, 0, long.as_ptr(), 700), 1);
        }
        let made = calls();
        assert_eq!(made[0].units, [0x20AC, 0x00E9, 0x007A]);
        assert_eq!(made[0].dx.as_deref(), Some(&advances[..]));
        assert_eq!(made[1].units.len(), 700);
        assert!(made[1].units.iter().all(|&unit| unit == u16::from(b'q')));
    }

    /// A negative length is ERROR_INVALID_PARAMETER before any service; a DC that is none the
    /// service's ERROR_INVALID_HANDLE; an empty string draws nothing and succeeds.
    #[test]
    fn text_refuses_bad_arguments() {
        calls();
        // SAFETY: the tests' own strings.
        unsafe {
            assert_eq!(text_out_a(DC, 0, 0, b"x".as_ptr(), -1), 0);
            assert_eq!(last_error(), ERROR_INVALID_PARAMETER);
            assert_eq!(text_out_w(DC, 0, 0, core::ptr::null(), -2), 0);
            assert_eq!(text_out_a(BAD, 0, 0, b"x".as_ptr(), 1), 0);
            assert_eq!(last_error(), ERROR_INVALID_HANDLE);
            assert_eq!(text_out_a(DC, 0, 0, b"".as_ptr(), 0), 1);
        }
        assert_eq!(
            calls().len(),
            1,
            "the empty string's call alone reached the kernel"
        );
    }

    /// The extents and the metrics, wide and narrow: "Hello" 5 cells of 8 by 16; the metrics'
    /// height and width, the narrow characters converted (the euro sign is 0x80).
    #[test]
    fn extents_and_metrics() {
        calls();
        let hello = units("Hello");
        let mut size = Size::default();
        // SAFETY: the tests' own strings and structures.
        unsafe {
            assert_eq!(
                get_text_extent_point32_a(DC, b"Hello".as_ptr(), 5, &mut size),
                1
            );
            assert_eq!(size, Size { cx: 40, cy: 16 });
            size = Size::default();
            assert_eq!(
                get_text_extent_point32_w(DC, hello.as_ptr(), 5, &mut size),
                1
            );
            assert_eq!(size, Size { cx: 40, cy: 16 });
            assert_eq!(
                get_text_extent_point32_w(DC, hello.as_ptr(), -1, &mut size),
                0
            );
            assert_eq!(last_error(), ERROR_INVALID_PARAMETER);
        }
        assert_eq!(
            calls()
                .iter()
                .map(|call| call.units.clone())
                .collect::<std::vec::Vec<_>>(),
            [hello.clone(), hello]
        );
        let mut wide = TextMetricW::default();
        assert_eq!(get_text_metrics_w(DC, &mut wide), 1);
        assert_eq!((wide.height, wide.ave_char_width), (16, 8));
        let mut narrow = TextMetricA::default();
        // SAFETY: the tests' own structure, and null.
        unsafe {
            assert_eq!(get_text_metrics_a(DC, &mut narrow), 1);
            assert_eq!((narrow.height, narrow.ave_char_width), (16, 8));
            assert_eq!((narrow.first_char, narrow.last_char), (0x20, 0x80));
            assert_eq!(get_text_metrics_a(DC, core::ptr::null_mut()), 0);
            assert_eq!(last_error(), ERROR_INVALID_PARAMETER);
            assert_eq!(get_text_metrics_a(BAD, &mut narrow), 0);
            assert_eq!(last_error(), ERROR_INVALID_HANDLE);
        }
    }
}
