//! The formats group: GetDateFormatA/W, GetTimeFormatA/W and GetNumberFormatA/W, each pair one
//! body ([`crate::nlsformat`]'s unit tests pin the formats themselves). These pin what the A form
//! does differently: its strings (the picture, the value, NUMBERFMTA's separators) converted from
//! the ANSI code page and its answer narrowed into it (0x80 is the euro sign, U+20AC), its counts
//! and sizes in bytes where the W form's are characters (one byte a character in code page 1252),
//! and the same refusals and last errors; the stub path logs the form's own entry.

use rtl::testing::wide_z;

use super::last_error;
use crate::nlsformat::{
    get_date_format_a,
    get_date_format_w,
    get_number_format_a,
    get_number_format_w,
    get_time_format_a,
    get_time_format_w,
    NumberFmt,
};
use crate::nt::host::DEBUG_PRINTS;

/// The locale the formats describe.
const EN_US: u32 = 0x0409;

/// A locale Windows 2000 supports whose formats this surface lacks (German).
const DE_DE: u32 = 0x0407;

/// ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_PARAMETER and ERROR_INVALID_FLAGS.
const INSUFFICIENT_BUFFER: u32 = 122;
const INVALID_PARAMETER: u32 = 87;
const INVALID_FLAGS: u32 = 1004;

/// ERROR_CALL_NOT_IMPLEMENTED, the stub path's.
const CALL_NOT_IMPLEMENTED: u32 = 120;

/// 2001-02-03, a Saturday, at 13:07:08.
const WHEN: [u16; 8] = [2001, 2, 6, 3, 13, 7, 8, 0];

/// `text` in code page 1252, NUL-terminated.
fn encode_z(text: &str) -> Vec<u8> {
    wide_z(text)
        .into_iter()
        .map(rtl::cp1252::wc_to_mb)
        .collect()
}

/// Code page 1252 bytes as text.
fn decode(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .iter()
        .map(|&byte| rtl::cp1252::MB_TO_WC[usize::from(byte)])
        .collect();
    String::from_utf16_lossy(&units)
}

/// A call's answer, its last error (when it failed), and the text written (to the terminator).
type Answer = (i32, u32, String);

fn answer_w(count: i32, out: &[u16]) -> Answer {
    let error = if count == 0 { last_error() } else { 0 };
    let end = out.iter().position(|&unit| unit == 0).unwrap_or(out.len());
    (count, error, String::from_utf16_lossy(&out[..end]))
}

fn answer_a(count: i32, out: &[u8]) -> Answer {
    let error = if count == 0 { last_error() } else { 0 };
    let end = out.iter().position(|&byte| byte == 0).unwrap_or(out.len());
    (count, error, decode(&out[..end]))
}

/// GetDateFormatW and GetDateFormatA of WHEN in `picture` (a W string; the A form's its code page
/// 1252 bytes), into `size` characters.
fn date(flags: u32, picture: Option<&str>, size: i32) -> (Answer, Answer) {
    let wide = picture.map(wide_z);
    let narrow = picture.map(|picture| encode_z(picture));
    let mut out_w = [0u16; 64];
    let mut out_a = [0u8; 64];
    let count = unsafe {
        get_date_format_w(
            EN_US,
            flags,
            &WHEN,
            wide.as_ref().map_or(core::ptr::null(), |p| p.as_ptr()),
            out_w.as_mut_ptr(),
            size,
        )
    };
    let w = answer_w(count, &out_w);
    let count = unsafe {
        get_date_format_a(
            EN_US,
            flags,
            &WHEN,
            narrow.as_ref().map_or(core::ptr::null(), |p| p.as_ptr()),
            out_a.as_mut_ptr(),
            size,
        )
    };
    (w, answer_a(count, &out_a))
}

/// GetDateFormatA converts its picture and its answer through the ANSI code page; both forms count
/// the same characters with the terminator, answer a size query alike, and refuse alike.
///
/// Pins: kernel32.GetDateFormatW, kernel32.GetDateFormatA
#[test]
fn date_formats_answer_alike_in_both_forms() {
    let (w, a) = date(0, Some("'\u{20AC}' d MMM yyyy"), 64);
    assert_eq!(w, (13, 0, "\u{20AC} 3 Feb 2001".into()));
    assert_eq!(a, w);
    let (w, a) = date(0, None, 64);
    assert_eq!(w, (9, 0, "2/3/2001".into()));
    assert_eq!(a, w);
    // A size query: the characters (bytes) needed, the terminator counted; nothing written.
    let (w, a) = date(0, Some("'\u{20AC}' yyyy"), 0);
    assert_eq!(w, (7, 0, String::new()));
    assert_eq!(a, w);
    // A buffer one short.
    let (w, a) = date(0, Some("'\u{20AC}' yyyy"), 6);
    assert_eq!(w, (0, INSUFFICIENT_BUFFER, String::new()));
    assert_eq!(a, w);
    let (w, a) = date(0x1 | 0x2, None, 64);
    assert_eq!(w.1, INVALID_FLAGS);
    assert_eq!(a, w);
    let (w, a) = date(0, None, -1);
    assert_eq!(w.1, INVALID_PARAMETER);
    assert_eq!(a, w);
}

/// GetTimeFormatA converts its picture and its answer as GetDateFormatA does.
///
/// Pins: kernel32.GetTimeFormatW, kernel32.GetTimeFormatA
#[test]
fn time_formats_answer_alike_in_both_forms() {
    let picture = "h:mm '\u{20AC}' tt";
    let (wide, narrow) = (wide_z(picture), encode_z(picture));
    let mut out_w = [0u16; 64];
    let mut out_a = [0u8; 64];
    let count =
        unsafe { get_time_format_w(EN_US, 0, &WHEN, wide.as_ptr(), out_w.as_mut_ptr(), 64) };
    let w = answer_w(count, &out_w);
    let count =
        unsafe { get_time_format_a(EN_US, 0, &WHEN, narrow.as_ptr(), out_a.as_mut_ptr(), 64) };
    assert_eq!(w, (10, 0, "1:07 \u{20AC} PM".into()));
    assert_eq!(answer_a(count, &out_a), w);
    // The default picture, a buffer too short.
    let count =
        unsafe { get_time_format_w(EN_US, 0, &WHEN, core::ptr::null(), out_w.as_mut_ptr(), 3) };
    let w = answer_w(count, &out_w[..0]);
    let count =
        unsafe { get_time_format_a(EN_US, 0, &WHEN, core::ptr::null(), out_a.as_mut_ptr(), 3) };
    assert_eq!(w, (0, INSUFFICIENT_BUFFER, String::new()));
    assert_eq!(answer_a(count, &out_a[..0]), w);
}

/// GetNumberFormatA converts its value and NUMBERFMTA's separators, and narrows its answer; a
/// separator past three characters is refused by both forms alike.
///
/// Pins: kernel32.GetNumberFormatW, kernel32.GetNumberFormatA
#[test]
fn number_formats_answer_alike_in_both_forms() {
    fn number(value: &str, decimal: &str, thousand: &str) -> (Answer, Answer) {
        let (value_w, decimal_w, thousand_w) = (wide_z(value), wide_z(decimal), wide_z(thousand));
        let (value_a, decimal_a, thousand_a) =
            (encode_z(value), encode_z(decimal), encode_z(thousand));
        let format_w = NumberFmt {
            num_digits: 2,
            leading_zero: 1,
            grouping: 3,
            decimal_sep: decimal_w.as_ptr(),
            thousand_sep: thousand_w.as_ptr(),
            negative_order: 1,
        };
        let format_a = NumberFmt {
            num_digits: 2,
            leading_zero: 1,
            grouping: 3,
            decimal_sep: decimal_a.as_ptr(),
            thousand_sep: thousand_a.as_ptr(),
            negative_order: 1,
        };
        let mut out_w = [0u16; 64];
        let mut out_a = [0u8; 64];
        let count = unsafe {
            get_number_format_w(
                EN_US,
                0,
                value_w.as_ptr(),
                &format_w,
                out_w.as_mut_ptr(),
                64,
            )
        };
        let w = answer_w(count, &out_w);
        let count = unsafe {
            get_number_format_a(
                EN_US,
                0,
                value_a.as_ptr(),
                &format_a,
                out_a.as_mut_ptr(),
                64,
            )
        };
        (w, answer_a(count, &out_a))
    }
    let (w, a) = number("-1234567.891", "\u{20AC}", ".");
    assert_eq!(w, (14, 0, "-1.234.567\u{20AC}89".into()));
    assert_eq!(a, w);
    let (w, a) = number("12", "dec.", ",");
    assert_eq!(w, (0, INVALID_PARAMETER, String::new()));
    assert_eq!(a, w);
    let (w, a) = number("1e5", ".", ",");
    assert_eq!(w, (0, INVALID_PARAMETER, String::new()));
    assert_eq!(a, w);
}

/// A locale whose formats this surface lacks takes the stub path, logged under the form's own
/// entry: 0 with ERROR_CALL_NOT_IMPLEMENTED.
///
/// Pins: kernel32.GetNumberFormatW, kernel32.GetNumberFormatA
#[test]
fn a_locale_without_formats_is_logged_under_the_form_s_entry() {
    let mut out_w = [0u16; 8];
    let mut out_a = [0u8; 8];
    let (one_w, one_a) = (wide_z("1"), *b"1\0");
    for wide in [true, false] {
        DEBUG_PRINTS.with(|prints| prints.borrow_mut().clear());
        let count = unsafe {
            if wide {
                get_number_format_w(
                    DE_DE,
                    0,
                    one_w.as_ptr(),
                    core::ptr::null(),
                    out_w.as_mut_ptr(),
                    8,
                )
            } else {
                get_number_format_a(
                    DE_DE,
                    0,
                    one_a.as_ptr(),
                    core::ptr::null(),
                    out_a.as_mut_ptr(),
                    8,
                )
            }
        };
        assert_eq!((count, last_error()), (0, CALL_NOT_IMPLEMENTED));
        let form = if wide { 'W' } else { 'A' };
        let prints = DEBUG_PRINTS.with(|prints| prints.borrow().clone());
        assert!(
            prints[0].starts_with(&format!("stub kernel32.GetNumberFormat{form}(")),
            "{prints:?}"
        );
    }
}
