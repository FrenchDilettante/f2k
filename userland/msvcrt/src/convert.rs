//! Number conversions: _ultoa, _itow, _ltow and _ultow, _wtol and _wtoi, atoi and atol, wcstol,
//! wcstoul and strtoul, and wcstod, as wide's capture pins them.
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
//! - wcstod reads the decimal form alone (its rules at [`wcstod`]), its value correctly rounded, as
//!   the capture's bits are (0.1 is 0x3FB999999999999A).
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
use crate::thread::{set_errno, EILSEQ, ERANGE};

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

/// The significant digits wcstod keeps for the conversion: enough to decide the rounding of any
/// double (its exact halfway points have at most 767), one more standing for the nonzero digits
/// beyond them.
const KEPT_DIGITS: usize = 768;

/// The text wcstod hands core's correctly rounded conversion: the kept digits, `e`, and the
/// exponent (sign and at most seven digits).
const REAL_TEXT: usize = KEPT_DIGITS + 1 + 1 + 1 + 7;

/// A real number's digits, gathered as wcstod reads them: its significant digits (leading zeros
/// dropped) and the power of ten they are scaled by.
struct Digits {
    text: [u8; REAL_TEXT],
    count: usize,
    exponent: i64,
    /// Whether a nonzero digit came past the kept ones.
    sticky: bool,
}

impl Digits {
    /// A digit of the integer part (`fraction` false) or of the fraction.
    fn push(&mut self, digit: u8, fraction: bool) {
        if self.count == 0 && digit == b'0' {
            if fraction {
                self.exponent -= 1;
            }
            return;
        }
        if self.count < KEPT_DIGITS - 1 {
            self.text[self.count] = digit;
            self.count += 1;
            if fraction {
                self.exponent -= 1;
            }
        } else {
            self.sticky |= digit != b'0';
            if !fraction {
                self.exponent += 1;
            }
        }
    }

    /// The magnitude, correctly rounded (core's conversion); 0 when every digit was 0.
    fn value(mut self, power: i64) -> f64 {
        if self.count == 0 {
            return 0.0;
        }
        if self.sticky {
            self.text[self.count] = b'1';
            self.count += 1;
            self.exponent -= 1;
        }
        // Past ±10^6 the answer is an infinity or zero whatever the digits.
        let exponent = self.exponent.saturating_add(power).clamp(-999_999, 999_999);
        let mut at = self.count;
        self.text[at] = b'e';
        at += 1;
        if exponent < 0 {
            self.text[at] = b'-';
            at += 1;
        }
        let mut digits = [0u8; 7];
        let mut length = 0;
        let mut rest = exponent.unsigned_abs();
        loop {
            digits[length] = b'0' + (rest % 10) as u8;
            length += 1;
            rest /= 10;
            if rest == 0 {
                break;
            }
        }
        for &digit in digits[..length].iter().rev() {
            self.text[at] = digit;
            at += 1;
        }
        core::str::from_utf8(&self.text[..at])
            .ok()
            .and_then(|text| text.parse::<f64>().ok())
            .unwrap_or(0.0)
    }
}

/// The smallest normal double: wcstod's results below it underflow.
const SMALLEST_NORMAL: f64 = f64::MIN_POSITIVE;

/// wcstod's work over the string's characters, each a narrow one (`at`, 0 past the end): the value,
/// whether it overflowed or underflowed, and the end's index (0 without a digit).
fn real(at: impl Fn(usize) -> u8) -> (f64, bool, usize) {
    let is_digit = |byte: u8| byte.is_ascii_digit();
    let mut i = 0;
    while at(i) != 0 && ctype::byte_class(at(i)) & ctype::SPACE != 0 {
        i += 1;
    }
    let negative = at(i) == b'-';
    if negative || at(i) == b'+' {
        i += 1;
    }
    let mut digits = Digits {
        text: [0; REAL_TEXT],
        count: 0,
        exponent: 0,
        sticky: false,
    };
    let mut seen = false;
    while is_digit(at(i)) {
        digits.push(at(i), false);
        seen = true;
        i += 1;
    }
    if at(i) == b'.' {
        i += 1;
        while is_digit(at(i)) {
            digits.push(at(i), true);
            seen = true;
            i += 1;
        }
    }
    if !seen {
        return (0.0, false, 0);
    }
    let mut power = 0i64;
    if matches!(at(i), b'e' | b'E' | b'd' | b'D') {
        let mut j = i + 1;
        let minus = at(j) == b'-';
        if minus || at(j) == b'+' {
            j += 1;
        }
        if is_digit(at(j)) {
            while is_digit(at(j)) {
                power = power
                    .saturating_mul(10)
                    .saturating_add(i64::from(at(j) - b'0'));
                j += 1;
            }
            if minus {
                power = -power;
            }
            i = j;
        }
    }
    let nonzero = digits.count != 0;
    let mut value = digits.value(power);
    let out_of_range = value.is_infinite() || (nonzero && value < SMALLEST_NORMAL);
    if nonzero && value < SMALLEST_NORMAL {
        value = 0.0;
    }
    (if negative { -value } else { value }, out_of_range, i)
}

/// wcstod: the string's double, the end of its number stored in `end`, as wide's capture pins it.
/// The string is read as narrow characters in the LC_CTYPE locale (a character the locale has no
/// narrow form of, anywhere in it, answers 0 with errno EILSEQ and the end the string itself);
/// then blanks (the locale's spaces), a sign, digits with a `.`, and an exponent after `e`, `E`,
/// `d` or `D` when digits follow it. No digit answers 0, the end the string itself (hex, `inf`
/// and `nan` are not read). A value past the largest double answers ±HUGE_VAL, one below the
/// smallest normal double 0 (a denormal is not kept), errno ERANGE either way, the number all
/// consumed.
///
/// # Safety
///
/// `string` is NUL-terminated; `end` is null or a pointer's storage.
#[unsafe(export_name = "f2k_export_wcstod")]
pub unsafe extern "C" fn wcstod(string: *const u16, end: *mut *const u16) -> f64 {
    // SAFETY: the caller's string.
    let units = unsafe { edge::wide(string) };
    if units
        .iter()
        .any(|unit| ctype::wide_to_byte(unit.get()).is_none())
    {
        set_errno(EILSEQ);
        // SAFETY: the caller's end pointer.
        unsafe { set_end(end, string, 0) };
        return 0.0;
    }
    let narrow = |i: usize| {
        units
            .get(i)
            .and_then(|unit| ctype::wide_to_byte(unit.get()))
            .unwrap_or(0)
    };
    let (value, out_of_range, index) = real(narrow);
    if out_of_range {
        set_errno(ERANGE);
    }
    // SAFETY: the caller's end pointer; the index is inside the string.
    unsafe { set_end(end, string, index) };
    value
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

    /// wide's wcstod block: each line's bits, end and errno.
    #[test]
    fn wcstod_as_captured() {
        for (text, bits, end, error) in [
            ("1.5", 0x3FF8000000000000u64, 3, 0),
            ("  -2.5e3xyz", 0xC0A3880000000000, 8, 0),
            ("+.5", 0x3FE0000000000000, 3, 0),
            ("5.", 0x4014000000000000, 2, 0),
            (".", 0, 0, 0),
            ("-", 0, 0, 0),
            ("", 0, 0, 0),
            ("   ", 0, 0, 0),
            ("\t\n 7", 0x401C000000000000, 4, 0),
            ("1e", 0x3FF0000000000000, 1, 0),
            ("1e+", 0x3FF0000000000000, 1, 0),
            ("1e-2", 0x3F847AE147AE147B, 4, 0),
            ("1E2", 0x4059000000000000, 3, 0),
            ("1d2", 0x4059000000000000, 3, 0),
            ("1D-2", 0x3F847AE147AE147B, 4, 0),
            ("0.1", 0x3FB999999999999A, 3, 0),
            ("-0", 0x8000000000000000, 2, 0),
            ("0x1A", 0, 1, 0),
            ("inf", 0, 0, 0),
            ("nan", 0, 0, 0),
            ("1,5", 0x3FF0000000000000, 1, 0),
            ("123456789012345678901234567890", 0x45F8EE90FF6C373E, 30, 0),
            ("1e400", 0x7FF0000000000000, 5, 34),
            ("-1e400", 0xFFF0000000000000, 6, 34),
            ("1e-400", 0, 6, 34),
            ("4.9e-324", 0, 8, 34),
            ("2.2250738585072014e-308", 0x0010000000000000, 23, 0),
            ("1.7976931348623157e308", 0x7FEFFFFFFFFFFFFF, 22, 0),
            ("1.7976931348623159e308", 0x7FF0000000000000, 22, 34),
            ("\u{FF11}.5", 0, 0, 42),
            ("\u{661}", 0, 0, 42),
            ("\u{A0}7", 0, 0, 0),
        ] {
            let s = wide(text);
            let mut e = core::ptr::null();
            set_errno(0);
            // SAFETY: a NUL-terminated string.
            let v = unsafe { wcstod(s.as_ptr(), &mut e) };
            // SAFETY: the end points into the string.
            let offset = unsafe { e.offset_from(s.as_ptr()) };
            assert_eq!(
                (v.to_bits(), offset, errno()),
                (bits, end, error),
                "wcstod({text:?})"
            );
        }
        let s = wide("6.25");
        set_errno(0);
        // SAFETY: a NUL-terminated string, no end pointer.
        let v = unsafe { wcstod(s.as_ptr(), core::ptr::null_mut()) };
        assert_eq!((v.to_bits(), errno()), (0x4019000000000000, 0));
    }

    /// Digits past the kept ones still decide the rounding, and a long run of zeros scales.
    #[test]
    fn wcstod_rounds_past_its_kept_digits() {
        let halfway = "9007199254740993"; // 2^53 + 1: halfway between two doubles.
        let mut above = String::from(halfway);
        above.push_str(&"0".repeat(800));
        above.push('1');
        let mut scaled = String::from("0.");
        scaled.push_str(&"0".repeat(900));
        scaled.push_str("25e902");
        for (text, expected) in [
            (halfway.to_string(), 9007199254740992.0),
            (format!("{halfway}.{}", &above[16..]), 9007199254740994.0),
            (scaled, 25.0),
        ] {
            let s = wide(&text);
            // SAFETY: a NUL-terminated string, no end pointer.
            let v = unsafe { wcstod(s.as_ptr(), core::ptr::null_mut()) };
            assert_eq!(v, expected);
        }
    }
}
