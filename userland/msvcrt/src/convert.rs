//! Number conversions: _ultoa, _itow, _ltow and _ultow, _wtol and _wtoi, atoi and atol, wcstol,
//! wcstoul and strtoul, as wide's capture pins them.
//!
//! - wcstol and wcstoul skip blanks, take a sign, then base 0's prefixes (`0x` hex, `0` octal) or
//!   base 16's `0x`, and the ASCII digits below the base. With no digit (`0x` alone counts as none)
//!   they answer 0 and the end pointer is the string itself; a base that is not 0 or 2 to 36 is the
//!   same. Overflow answers LONG_MAX or LONG_MIN (wcstol), ULONG_MAX (wcstoul, then negated like
//!   any value with a `-`: `-4294967296` is 1), errno ERANGE, the digits all consumed.
//! - strtoul is wcstoul over a narrow string, its blanks the LC_CTYPE locale's spaces.
//! - _wtol takes blanks, a sign and decimal digits, and wraps around without errno; atoi is _wtol
//!   over a narrow string, its blanks the LC_CTYPE locale's spaces (MSDN: atoi stops at the first
//!   character that cannot be part of the number). _wtoi is _wtol and atol is atoi: an int is a
//!   long on Win32.
//! - _ultoa and _ultow write the digits in any radix from 2 to 36, letters in lower case. _itow and
//!   _ltow write a negative value with a `-` in radix 10 and as unsigned in any other (MSDN: "If
//!   radix equals 10 and value is negative, the first character of the stored string is the minus
//!   sign"). A radix outside 2 to 36 writes the empty string.
//!
//! Each export reads its caller's string once ([`crate::edge`]); the conversions read it through
//! `at`, its unit at an index (0 past its end): a wide string's units, or a narrow string's bytes,
//! each the unit of its value (a byte's class is its wide value's below U+0100).

use rtl::cstr::bytes_until_nul;

use crate::ctype;
use crate::edge::{self, WideUnit};
use crate::scan::digit_value;
use crate::thread::{set_errno, ERANGE};

/// A narrow string's byte at `index` as a unit, 0 past its end.
fn unit_of(string: &[u8], index: usize) -> u16 {
    string.get(index).map_or(0, |&byte| byte.into())
}

/// A wide string's unit at `index`, 0 past its end.
fn wide_unit_of(string: &[WideUnit], index: usize) -> u16 {
    string.get(index).map_or(0, |unit| unit.get())
}

/// The blanks, the sign and the prefix: where the digits start, the sign, the base.
fn lead(at: impl Fn(usize) -> u16, base: i32) -> (usize, bool, u32) {
    let mut i = 0;
    while at(i) != 0 && ctype::wide_class(at(i), ctype::SPACE) != 0 {
        i += 1;
    }
    let negative = at(i) == b'-' as u16;
    if negative || at(i) == b'+' as u16 {
        i += 1;
    }
    let mut base = base as u32;
    let hex_prefix = at(i) == b'0' as u16 && (at(i + 1) == b'x' as u16 || at(i + 1) == b'X' as u16);
    if base == 0 {
        base = if hex_prefix {
            16
        } else if at(i) == b'0' as u16 {
            8
        } else {
            10
        };
    }
    if base == 16 && hex_prefix {
        i += 2;
    }
    (i, negative, base)
}

/// The conversion wcstol, wcstoul and strtoul share: the magnitude (ULONG_MAX past it), the sign,
/// whether it overflowed, the end's index (0 without a digit).
fn parse(at: impl Fn(usize) -> u16, base: i32) -> (u32, bool, bool, usize) {
    if base != 0 && !(2..=36).contains(&base) {
        return (0, false, false, 0);
    }
    let (mut i, negative, base) = lead(&at, base);
    let (mut value, mut overflow, mut digits) = (0u32, false, 0);
    while let Some(digit) = digit_value(at(i)).filter(|&d| d < base) {
        match value.checked_mul(base).and_then(|v| v.checked_add(digit)) {
            Some(next) => value = next,
            None => overflow = true,
        }
        digits += 1;
        i += 1;
    }
    if digits == 0 {
        return (0, false, false, 0);
    }
    (
        if overflow { u32::MAX } else { value },
        negative,
        overflow,
        i,
    )
}

/// The unsigned conversion's answer (negated, modulo 2^32, after a `-`; errno ERANGE on overflow)
/// and the end's index.
fn unsigned(at: impl Fn(usize) -> u16, base: i32) -> (u32, usize) {
    let (magnitude, negative, overflow, index) = parse(at, base);
    if overflow {
        set_errno(ERANGE);
    }
    let value = if negative {
        magnitude.wrapping_neg()
    } else {
        magnitude
    };
    (value, index)
}

/// The end pointer, `string`'s unit `index`, stored when asked.
///
/// # Safety
///
/// `end` is null or a pointer's storage.
unsafe fn set_end<T>(end: *mut *const T, string: *const T, index: usize) {
    if !end.is_null() {
        // SAFETY: the caller's contract.
        unsafe { end.write_unaligned(string.wrapping_add(index)) };
    }
}

/// wcstol: the string's long, the end of its digits stored in `end`.
///
/// # Safety
///
/// `string` is NUL-terminated; `end` is null or a pointer's storage.
#[unsafe(export_name = "f2k_export_wcstol")]
pub unsafe extern "C" fn wcstol(string: *const u16, end: *mut *const u16, base: i32) -> i32 {
    // SAFETY: the caller's string.
    let units = unsafe { edge::wide(string) };
    let (magnitude, negative, overflow, index) = parse(|i| wide_unit_of(units, i), base);
    // SAFETY: the caller's end pointer; the index is inside the string.
    unsafe { set_end(end, string, index) };
    let limit = if negative { 0x8000_0000 } else { 0x7FFF_FFFF };
    if overflow || magnitude > limit {
        set_errno(ERANGE);
        return if negative { i32::MIN } else { i32::MAX };
    }
    if negative {
        (magnitude as i32).wrapping_neg()
    } else {
        magnitude as i32
    }
}

/// wcstoul: the string's unsigned long (negated, modulo 2^32, after a `-`).
///
/// # Safety
///
/// As wcstol's.
#[unsafe(export_name = "f2k_export_wcstoul")]
pub unsafe extern "C" fn wcstoul(string: *const u16, end: *mut *const u16, base: i32) -> u32 {
    // SAFETY: the caller's string.
    let units = unsafe { edge::wide(string) };
    let (value, index) = unsigned(|i| wide_unit_of(units, i), base);
    // SAFETY: the caller's end pointer; the index is inside the string.
    unsafe { set_end(end, string, index) };
    value
}

/// strtoul: the narrow string's unsigned long, as wcstoul reads a wide one.
///
/// # Safety
///
/// `string` is NUL-terminated; `end` is null or a pointer's storage.
#[unsafe(export_name = "f2k_export_strtoul")]
pub unsafe extern "C" fn strtoul(string: *const u8, end: *mut *const u8, base: i32) -> u32 {
    // SAFETY: the caller's string.
    let bytes = unsafe { bytes_until_nul(string) };
    let (value, index) = unsigned(|i| unit_of(bytes, i), base);
    // SAFETY: the caller's end pointer; the index is inside the string.
    unsafe { set_end(end, string, index) };
    value
}

/// _wtol: the string's long, decimal, wrapping around.
///
/// # Safety
///
/// `string` is NUL-terminated.
#[unsafe(export_name = "f2k_export__wtol")]
pub unsafe extern "C" fn wtol(string: *const u16) -> i32 {
    // SAFETY: the caller's string.
    let units = unsafe { edge::wide(string) };
    decimal(|i| wide_unit_of(units, i))
}

/// _wtoi: the string's int, as _wtol reads it.
///
/// # Safety
///
/// `string` is NUL-terminated.
#[unsafe(export_name = "f2k_export__wtoi")]
pub unsafe extern "C" fn wtoi(string: *const u16) -> i32 {
    // SAFETY: the caller's string.
    let units = unsafe { edge::wide(string) };
    decimal(|i| wide_unit_of(units, i))
}

/// atoi: the narrow string's int, as _wtol reads a wide one.
///
/// # Safety
///
/// `string` is NUL-terminated.
#[unsafe(export_name = "f2k_export_atoi")]
pub unsafe extern "C" fn atoi(string: *const u8) -> i32 {
    // SAFETY: the caller's string.
    let bytes = unsafe { bytes_until_nul(string) };
    decimal(|i| unit_of(bytes, i))
}

/// atol: the narrow string's long, as atoi reads it.
///
/// # Safety
///
/// `string` is NUL-terminated.
#[unsafe(export_name = "f2k_export_atol")]
pub unsafe extern "C" fn atol(string: *const u8) -> i32 {
    // SAFETY: the caller's string.
    let bytes = unsafe { bytes_until_nul(string) };
    decimal(|i| unit_of(bytes, i))
}

/// The conversion _wtol, _wtoi, atoi and atol share: blanks, a sign, then decimal digits, wrapping
/// around without errno.
fn decimal(at: impl Fn(usize) -> u16) -> i32 {
    let (mut i, negative, _) = lead(&at, 10);
    let mut value = 0u32;
    while let Some(digit) = digit_value(at(i)).filter(|&d| d < 10) {
        value = value.wrapping_mul(10).wrapping_add(digit);
        i += 1;
    }
    let value = value as i32;
    if negative {
        value.wrapping_neg()
    } else {
        value
    }
}

/// The room the text of a number takes: 32 binary digits at most (a `-` comes only with radix 10's
/// ten).
const NUMBER_TEXT: usize = 32;

/// `value`'s text in `radix`, at the end of `out`: its digits, letters in lower case, after a `-`
/// when `signed` and the value is negative in radix 10 (in any other radix it is unsigned); empty
/// for a radix outside 2 to 36.
fn number_text(value: u32, signed: bool, radix: i32, out: &mut [u8; NUMBER_TEXT]) -> &[u8] {
    if !(2..=36).contains(&radix) {
        return &[];
    }
    let negative = signed && radix == 10 && (value as i32) < 0;
    let mut rest = if negative {
        (value as i32).unsigned_abs()
    } else {
        value
    };
    let mut at = out.len();
    loop {
        let digit = (rest % radix as u32) as u8;
        at -= 1;
        out[at] = if digit < 10 {
            b'0' + digit
        } else {
            b'a' + digit - 10
        };
        rest /= radix as u32;
        if rest == 0 {
            break;
        }
    }
    if negative {
        at -= 1;
        out[at] = b'-';
    }
    &out[at..]
}

/// _ultoa: `value`'s digits in `radix` into `buffer`, NUL-terminated; answers `buffer`.
///
/// # Safety
///
/// `buffer` has room for the digits and the NUL (33 bytes at most).
#[unsafe(export_name = "f2k_export__ultoa")]
pub unsafe extern "C" fn ultoa(value: u32, buffer: *mut u8, radix: i32) -> *mut u8 {
    let mut text = [0u8; NUMBER_TEXT];
    let text = number_text(value, false, radix, &mut text);
    // SAFETY: the caller's room for the digits and the NUL.
    let out = unsafe { core::slice::from_raw_parts_mut(buffer, text.len() + 1) };
    out[..text.len()].copy_from_slice(text);
    out[text.len()] = 0;
    buffer
}

/// The wide forms' work: `value`'s text in `radix` (see [`number_text`]) into `buffer`,
/// NUL-terminated; answers `buffer`.
///
/// # Safety
///
/// `buffer` has room for the text and the NUL (33 units at most), at any address.
unsafe fn wide_number(value: u32, signed: bool, buffer: *mut u16, radix: i32) -> *mut u16 {
    let mut text = [0u8; NUMBER_TEXT];
    let text = number_text(value, signed, radix, &mut text);
    // SAFETY: the caller's room for the text and the NUL.
    let out = unsafe { edge::wide_parts_mut(buffer, text.len() + 1) };
    for (slot, &byte) in out.iter_mut().zip(text.iter().chain([&0])) {
        *slot = WideUnit::new(byte.into());
    }
    buffer
}

/// _itow: `value`'s text in `radix` into `buffer`, `-` first for a negative value in radix 10;
/// answers `buffer`.
///
/// # Safety
///
/// `buffer` has room for the text and the NUL (33 units at most).
#[unsafe(export_name = "f2k_export__itow")]
pub unsafe extern "C" fn itow(value: i32, buffer: *mut u16, radix: i32) -> *mut u16 {
    // SAFETY: the caller's contract.
    unsafe { wide_number(value as u32, true, buffer, radix) }
}

/// _ltow: as _itow (a long is an int on Win32).
///
/// # Safety
///
/// As _itow's.
#[unsafe(export_name = "f2k_export__ltow")]
pub unsafe extern "C" fn ltow(value: i32, buffer: *mut u16, radix: i32) -> *mut u16 {
    // SAFETY: the caller's contract.
    unsafe { wide_number(value as u32, true, buffer, radix) }
}

/// _ultow: `value`'s digits in `radix` into `buffer`; answers `buffer`.
///
/// # Safety
///
/// As _itow's.
#[unsafe(export_name = "f2k_export__ultow")]
pub unsafe extern "C" fn ultow(value: u32, buffer: *mut u16, radix: i32) -> *mut u16 {
    // SAFETY: the caller's contract.
    unsafe { wide_number(value, false, buffer, radix) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::tests::wide;
    use crate::thread::errno_address;

    fn errno() -> i32 {
        // SAFETY: the thread's own errno.
        unsafe { *errno_address() }
    }

    /// wide's numbers block: each wcstol and wcstoul line, the value, errno and the end.
    #[test]
    fn wcstol_and_wcstoul_as_captured() {
        for (text, base, value, error, end) in [
            ("0x1A", 0, 26, 0, 4),
            ("0X1a", 0, 26, 0, 4),
            ("  -077", 0, -63, 0, 6),
            ("0", 0, 0, 0, 1),
            ("08", 0, 0, 0, 1),
            ("12abc", 0, 12, 0, 2),
            ("+42", 10, 42, 0, 3),
            ("-0x10", 0, -16, 0, 5),
            ("0x", 0, 0, 0, 0),
            ("0x", 16, 0, 0, 0),
            ("0x1A", 16, 26, 0, 4),
            ("0x1A", 10, 0, 0, 1),
            ("zz", 36, 1295, 0, 2),
            ("ZZ", 36, 1295, 0, 2),
            ("1010", 2, 10, 0, 4),
            ("2147483647", 10, i32::MAX, 0, 10),
            ("2147483648", 10, i32::MAX, 34, 10),
            ("-2147483648", 10, i32::MIN, 0, 11),
            ("-2147483649", 10, i32::MIN, 34, 11),
            ("99999999999999999999x", 10, i32::MAX, 34, 20),
            ("   ", 10, 0, 0, 0),
            ("", 10, 0, 0, 0),
            ("abc", 10, 0, 0, 0),
            ("- 5", 10, 0, 0, 0),
            ("12", 37, 0, 0, 0),
            ("\u{661}\u{662}", 10, 0, 0, 0),
            ("\u{FF11}\u{FF12}", 10, 0, 0, 0),
        ] {
            let s = wide(text);
            let mut e = core::ptr::null();
            set_errno(0);
            // SAFETY: a NUL-terminated string.
            let v = unsafe { wcstol(s.as_ptr(), &mut e, base) };
            // SAFETY: the end points into the string.
            let offset = unsafe { e.offset_from(s.as_ptr()) };
            assert_eq!(
                (v, errno(), offset),
                (value, error, end),
                "wcstol({text:?}, {base})"
            );
        }
        for (text, base, value, error, end) in [
            ("4294967295", 10, u32::MAX, 0, 10),
            ("4294967296", 10, u32::MAX, 34, 10),
            ("-1", 10, u32::MAX, 0, 2),
            ("-4294967296", 10, 1, 34, 11),
            ("0xFFFFFFFF", 16, u32::MAX, 0, 10),
            ("0x100000000", 0, u32::MAX, 34, 11),
            ("  +12", 0, 12, 0, 5),
            ("-0x10", 0, 4294967280, 0, 5),
            ("017", 0, 15, 0, 3),
            ("0", 0, 0, 0, 1),
            ("", 0, 0, 0, 0),
            ("x", 0, 0, 0, 0),
        ] {
            let s = wide(text);
            let mut e = core::ptr::null();
            set_errno(0);
            // SAFETY: as above.
            let v = unsafe { wcstoul(s.as_ptr(), &mut e, base) };
            // SAFETY: as above.
            let offset = unsafe { e.offset_from(s.as_ptr()) };
            assert_eq!(
                (v, errno(), offset),
                (value, error, end),
                "wcstoul({text:?}, {base})"
            );
        }
    }

    /// strtoul reads a narrow string as wcstoul a wide one: spawnkid's handles in hex and its
    /// counts in decimal (base 0), the end, ERANGE past ULONG_MAX.
    #[test]
    fn strtoul_reads_as_wcstoul() {
        for (text, base, value, error, end) in [
            ("0x7C", 0, 0x7C, 0, 4),
            ("259", 0, 259, 0, 3),
            ("  \t-1", 0, u32::MAX, 0, 5),
            ("017", 0, 15, 0, 3),
            ("4294967296", 10, u32::MAX, 34, 10),
            ("ff", 16, 255, 0, 2),
            ("12z", 36, 1403, 0, 3),
            ("x", 0, 0, 0, 0),
            ("", 0, 0, 0, 0),
            ("5", 1, 0, 0, 0),
        ] {
            let s: Vec<u8> = text.bytes().chain([0]).collect();
            let mut e = core::ptr::null();
            set_errno(0);
            // SAFETY: a NUL-terminated string.
            let v = unsafe { strtoul(s.as_ptr(), &mut e, base) };
            // SAFETY: the end points into the string.
            let offset = unsafe { e.offset_from(s.as_ptr()) };
            assert_eq!(
                (v, errno(), offset),
                (value, error, end),
                "strtoul({text:?}, {base})"
            );
        }
        // No end asked for.
        // SAFETY: as above.
        assert_eq!(
            unsafe { strtoul(b"42\0".as_ptr(), core::ptr::null_mut(), 0) },
            42
        );
    }

    #[test]
    fn wtol_as_captured() {
        for (text, value) in [
            ("123", 123),
            ("  -123abc", -123),
            ("+7", 7),
            ("\t\n 42", 42),
            ("", 0),
            ("abc", 0),
            ("0x1A", 0),
            ("2147483647", i32::MAX),
            ("2147483648", i32::MIN),
            ("-2147483649", i32::MAX),
            ("\u{661}\u{662}", 0),
        ] {
            let s = wide(text);
            set_errno(0);
            // SAFETY: a NUL-terminated string.
            assert_eq!(unsafe { wtol(s.as_ptr()) }, value, "{text:?}");
            assert_eq!(errno(), 0);
        }
    }

    /// atoi reads a narrow string as _wtol reads a wide one.
    #[test]
    fn atoi_reads_as_wtol() {
        for (text, value) in [
            (&b"3\0"[..], 3),
            (b"  -123abc\0", -123),
            (b"+7\0", 7),
            (b"\t\n 42\0", 42),
            (b"\0", 0),
            (b"x9\0", 0),
            (b"0x1A\0", 0),
            (b"2147483648\0", i32::MIN),
        ] {
            set_errno(0);
            // SAFETY: a NUL-terminated string.
            assert_eq!(unsafe { atoi(text.as_ptr()) }, value, "{text:?}");
            assert_eq!(errno(), 0);
        }
    }

    #[test]
    fn ultoa_as_captured() {
        let mut buffer = [0u8; 40];
        let show = |buffer: &[u8]| {
            String::from_utf8(buffer[..buffer.iter().position(|&b| b == 0).unwrap()].to_vec())
                .unwrap()
        };
        for (value, expected) in [
            (0u32, ["0", "0", "0", "0", "0"]),
            (255, ["11111111", "377", "255", "ff", "73"]),
            (
                123456789,
                [
                    "111010110111100110100010101",
                    "726746425",
                    "123456789",
                    "75bcd15",
                    "21i3v9",
                ],
            ),
            (
                2147483648,
                [
                    "10000000000000000000000000000000",
                    "20000000000",
                    "2147483648",
                    "80000000",
                    "zik0zk",
                ],
            ),
            (
                u32::MAX,
                [
                    "11111111111111111111111111111111",
                    "37777777777",
                    "4294967295",
                    "ffffffff",
                    "1z141z3",
                ],
            ),
        ] {
            for (radix, expected) in [2, 8, 10, 16, 36].into_iter().zip(expected) {
                // SAFETY: a buffer of 40 bytes.
                let r = unsafe { ultoa(value, buffer.as_mut_ptr(), radix) };
                assert_eq!(r, buffer.as_mut_ptr());
                assert_eq!(show(&buffer), expected);
            }
        }
    }

    /// strings' itow block: _itow and _ltow write a negative value with a `-` in radix 10 and as
    /// unsigned in any other, _ultow always unsigned; each answers the buffer, NUL-terminated after
    /// the text; a radix outside 2 to 36 writes the empty string.
    #[test]
    fn itow_ltow_and_ultow() {
        let minus_one = [
            "11111111111111111111111111111111",
            "37777777777",
            "-1",
            "ffffffff",
            "1z141z3",
        ];
        let int_min = [
            "10000000000000000000000000000000",
            "20000000000",
            "-2147483648",
            "80000000",
            "zik0zk",
        ];
        let int_max = [
            "1111111111111111111111111111111",
            "17777777777",
            "2147483647",
            "7fffffff",
            "zik0zj",
        ];
        let small = |v: &'static str| [v; 5];
        let signed = [
            (0, small("0")),
            (1, small("1")),
            (-1, minus_one),
            (255, ["11111111", "377", "255", "ff", "73"]),
            (i32::MIN, int_min),
            (i32::MAX, int_max),
        ];
        let show = |buffer: &[u16]| {
            let end = buffer.iter().position(|&u| u == 0).unwrap();
            assert!(buffer[end + 1..].iter().all(|&u| u == b'#' as u16));
            String::from_utf16(&buffer[..end]).unwrap()
        };
        let signed_forms: [unsafe extern "C" fn(i32, *mut u16, i32) -> *mut u16; 2] = [itow, ltow];
        for convert in signed_forms {
            for (value, expected) in signed {
                for (radix, expected) in [2, 8, 10, 16, 36].into_iter().zip(expected) {
                    let mut buffer = [b'#' as u16; 48];
                    // SAFETY: a buffer of 48 units.
                    let r = unsafe { convert(value, buffer.as_mut_ptr(), radix) };
                    assert_eq!(r, buffer.as_mut_ptr());
                    assert_eq!(show(&buffer), expected, "{value} in radix {radix}");
                }
            }
        }
        let unsigned = [
            (0, small("0")),
            (1, small("1")),
            (255, ["11111111", "377", "255", "ff", "73"]),
            (
                0x8000_0000,
                [int_min[0], int_min[1], "2147483648", int_min[3], int_min[4]],
            ),
            (0x7FFF_FFFF, int_max),
            (
                u32::MAX,
                [
                    minus_one[0],
                    minus_one[1],
                    "4294967295",
                    minus_one[3],
                    minus_one[4],
                ],
            ),
        ];
        for (value, expected) in unsigned {
            for (radix, expected) in [2, 8, 10, 16, 36].into_iter().zip(expected) {
                let mut buffer = [b'#' as u16; 48];
                // SAFETY: a buffer of 48 units.
                let r = unsafe { ultow(value, buffer.as_mut_ptr(), radix) };
                assert_eq!(r, buffer.as_mut_ptr());
                assert_eq!(show(&buffer), expected, "{value} in radix {radix}");
            }
        }
        for radix in [0, 1, 37] {
            let mut buffer = [b'#' as u16; 4];
            // SAFETY: a buffer of 4 units.
            unsafe { itow(-5, buffer.as_mut_ptr(), radix) };
            assert_eq!(show(&buffer), "");
        }
        // A buffer at an odd address.
        let mut bytes = [0u8; 16];
        // SAFETY: 15 bytes from an odd address: room for "-42" and the NUL.
        unsafe { itow(-42, bytes[1..].as_mut_ptr().cast(), 10) };
        assert_eq!(&bytes[1..9], b"-\x004\x002\x00\x00\x00");
    }

    /// strings' atoi block: _wtoi and atol read as _wtol and atoi, wrapping around past LONG_MAX
    /// and LONG_MIN without errno.
    #[test]
    fn wtoi_and_atol() {
        for (text, value) in [
            ("42", 42),
            (" \t 42", 42),
            ("\t-17", -17),
            ("+8", 8),
            ("-0", 0),
            ("123abc", 123),
            ("", 0),
            ("abc123", 0),
            ("  +-5", 0),
            ("- 5", 0),
            ("+", 0),
            ("2147483647", i32::MAX),
            ("2147483648", i32::MIN),
            ("-2147483648", i32::MIN),
            ("-2147483649", i32::MAX),
            ("99999999999", 1215752191),
            ("-99999999999", -1215752191),
        ] {
            let s = wide(text);
            let n: Vec<u8> = text.bytes().chain([0]).collect();
            set_errno(0);
            // SAFETY: NUL-terminated strings.
            let (w, a) = unsafe { (wtoi(s.as_ptr()), atol(n.as_ptr())) };
            assert_eq!((w, a, errno()), (value, value, 0), "{text:?}");
        }
    }
}
