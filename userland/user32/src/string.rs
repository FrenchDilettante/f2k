//! The characters: CharNextA/W and CharPrevA/W, walks over a caller's string; CharUpperA/W,
//! CharLowerA/W and their Buff forms, its case changed in place; IsCharAlphaNumericA/W.
//!
//! The narrow walks step a byte at a time: the ANSI code page is 1252, single-byte, with no lead
//! bytes (F2K has no double-byte tables), so every character is one byte. The wide walks step a
//! UTF-16 unit at a time, a base character and the combining marks after it together, as the
//! charnext capture shows; a surrogate pair is two steps there, as on Windows 2000.
//!
//! The case and the character types are the user default locale's, as LCMapStringW's
//! LCMAP_UPPERCASE and LCMAP_LOWERCASE and GetStringTypeW's CT_CTYPE1 answer them (Windows 2000's
//! user32 imports both): F2K's one locale, U.S. English, whose tables `rtl::cp1252` holds and
//! kernel32's calls answer from. A narrow character crosses into UTF-16 and back through the ANSI
//! code page, as ntdll's conversions take it.

use rtl::cp1252::{self, C1_ALPHA, C1_DIGIT};
use rtl::edge::{In, Out};

use crate::imports;

/// Whether `unit` is a combining mark, which belongs to the character before it: the Combining
/// Diacritical Marks (U+0300-U+036F), the marks for symbols (U+20D0-U+20FF) and the combining
/// half marks (U+FE20-U+FE2F).
fn is_combining(unit: u16) -> bool {
    matches!(unit, 0x0300..=0x036F | 0x20D0..=0x20FF | 0xFE20..=0xFE2F)
}

/// The unit at `at`, read from the caller's string.
///
/// # Safety
///
/// `at` lies inside the caller's NUL-terminated string, its NUL included.
unsafe fn unit_at(at: *const u16) -> u16 {
    // SAFETY: the function's contract.
    unsafe { In::new(at) }.read()
}

/// CharNextA: the next character after `at`: the next byte; `at` itself at the NUL.
///
/// # Safety
///
/// `at` points into a NUL-terminated string, as for the platform's.
#[unsafe(export_name = "f2k_export_CharNextA")]
pub unsafe extern "system" fn char_next_a(at: *const u8) -> *const u8 {
    // SAFETY: the caller's string.
    if unsafe { In::new(at) }.read() == 0 {
        at
    } else {
        at.wrapping_add(1)
    }
}

/// CharPrevA: the character before `current` in the string from `start`: the byte before; `start`
/// when `current` is at it (or before it).
#[unsafe(export_name = "f2k_export_CharPrevA")]
pub extern "system" fn char_prev_a(start: *const u8, current: *const u8) -> *const u8 {
    if current > start {
        current.wrapping_sub(1)
    } else {
        start
    }
}

/// CharNextW: the next character after `at`: past its unit and the combining marks after it; `at`
/// itself at the NUL.
///
/// # Safety
///
/// `at` points into a NUL-terminated UTF-16 string, as for the platform's.
#[unsafe(export_name = "f2k_export_CharNextW")]
pub unsafe extern "system" fn char_next_w(at: *const u16) -> *const u16 {
    // SAFETY: the caller's string; the walk stops at its NUL, a unit past a mark that is not.
    unsafe {
        if unit_at(at) == 0 {
            return at;
        }
        let mut next = at.wrapping_add(1);
        while is_combining(unit_at(next)) {
            next = next.wrapping_add(1);
        }
        next
    }
}

/// CharPrevW: the character before `current` in the string from `start`: back over the combining
/// marks before it to their base character; `start` when `current` is at it. Marks that run back
/// to the string's start have no base to step onto: `current` comes back as it is (the charnext
/// capture's U+0301 "x").
///
/// # Safety
///
/// `start` and `current` point into one NUL-terminated UTF-16 string, as for the platform's.
#[unsafe(export_name = "f2k_export_CharPrevW")]
pub unsafe extern "system" fn char_prev_w(start: *const u16, current: *const u16) -> *const u16 {
    if current <= start {
        return start;
    }
    // SAFETY: the caller's string; the walk stays between `start` and `current`.
    unsafe {
        let mut prev = current.wrapping_sub(1);
        while prev > start && is_combining(unit_at(prev)) {
            prev = prev.wrapping_sub(1);
        }
        if is_combining(unit_at(prev)) {
            return current;
        }
        prev
    }
}

/// A narrow character's case changed: through UTF-16 and back, as the ANSI code page converts it
/// (a capital the code page lacks would come back as its default character; 1252's letters have
/// theirs).
fn narrow_case(byte: u8, upper: bool) -> u8 {
    let mut wide = [0u16];
    imports::multi_byte_to_unicode(&mut wide, &[byte]);
    let mut narrow = [0u8];
    imports::unicode_to_multi_byte(&mut narrow, &[cp1252::map_case(wide[0], upper)]);
    narrow[0]
}

/// Whether CharUpper's or CharLower's argument is a character in its low word rather than a
/// string's address: its high word is zero.
fn is_character<T>(argument: *mut T) -> bool {
    (argument as usize) >> 16 == 0
}

/// Each of the caller's units from `at` changed by `map`, in place: `count` of them (past a NUL
/// too), or with none up to the string's NUL. The units changed.
///
/// # Safety
///
/// `at` points at `count` units the call may read and write, or (no count) at a NUL-terminated
/// string it may, as for the platform's.
unsafe fn map_in_place<T: Copy + Default + PartialEq>(
    at: *mut T,
    count: Option<usize>,
    map: impl Fn(T) -> T,
) -> usize {
    let mut index = 0;
    while count.is_none_or(|count| index < count) {
        // SAFETY: the function's contract: one of the caller's units, at or before its NUL.
        let mut unit = unsafe { Out::new(at.wrapping_add(index)) };
        let value = unit.get();
        if count.is_none() && value == T::default() {
            break;
        }
        unit.set(map(value));
        index += 1;
    }
    index
}

/// CharUpperW and CharLowerW: the character in the argument's low word in the case `upper` asks
/// for, or the string at the argument changed to it in place and its address answered.
///
/// # Safety
///
/// As [`char_upper_w`]'s.
unsafe fn case_w(argument: *mut u16, upper: bool) -> *mut u16 {
    if is_character(argument) {
        return cp1252::map_case(argument as usize as u16, upper) as usize as *mut u16;
    }
    // SAFETY: the caller's string, NUL-terminated.
    unsafe { map_in_place(argument, None, |unit| cp1252::map_case(unit, upper)) };
    argument
}

/// CharUpperA and CharLowerA: [`case_w`]'s, over the ANSI code page's characters (the character
/// in the argument's low byte).
///
/// # Safety
///
/// As [`char_upper_a`]'s.
unsafe fn case_a(argument: *mut u8, upper: bool) -> *mut u8 {
    if is_character(argument) {
        return narrow_case(argument as usize as u8, upper) as usize as *mut u8;
    }
    // SAFETY: the caller's string, NUL-terminated.
    unsafe { map_in_place(argument, None, |byte| narrow_case(byte, upper)) };
    argument
}

/// CharUpperW: the character in the argument's low word (its high word zero) in capitals, or the
/// string at the argument in capitals in place, its address answered. Outside a Turkish locale
/// the dotless ı stays; ß and µ have no single capital and stay too.
///
/// # Safety
///
/// `argument` is a character in its low word, or a NUL-terminated string the call may change, as
/// for the platform's.
#[unsafe(export_name = "f2k_export_CharUpperW")]
pub unsafe extern "system" fn char_upper_w(argument: *mut u16) -> *mut u16 {
    // SAFETY: the caller's contract.
    unsafe { case_w(argument, true) }
}

/// CharLowerW: CharUpperW's, in small letters (the dotted İ stays).
///
/// # Safety
///
/// As [`char_upper_w`]'s.
#[unsafe(export_name = "f2k_export_CharLowerW")]
pub unsafe extern "system" fn char_lower_w(argument: *mut u16) -> *mut u16 {
    // SAFETY: the caller's contract.
    unsafe { case_w(argument, false) }
}

/// CharUpperA: CharUpperW's over the ANSI code page's characters (the character in the argument's
/// low byte): ÿ (0xFF) to Ÿ (0x9F), š (0x9A) to Š (0x8A).
///
/// # Safety
///
/// `argument` is a character in its low word, or a NUL-terminated string the call may change, as
/// for the platform's.
#[unsafe(export_name = "f2k_export_CharUpperA")]
pub unsafe extern "system" fn char_upper_a(argument: *mut u8) -> *mut u8 {
    // SAFETY: the caller's contract.
    unsafe { case_a(argument, true) }
}

/// CharLowerA: CharUpperA's, in small letters.
///
/// # Safety
///
/// As [`char_upper_a`]'s.
#[unsafe(export_name = "f2k_export_CharLowerA")]
pub unsafe extern "system" fn char_lower_a(argument: *mut u8) -> *mut u8 {
    // SAFETY: the caller's contract.
    unsafe { case_a(argument, false) }
}

/// CharUpperBuffW: the `count` units at `text` in capitals, in place, NULs and what follows them
/// as well; the count answered.
///
/// # Safety
///
/// `text` holds `count` units the call may change, as for the platform's.
#[unsafe(export_name = "f2k_export_CharUpperBuffW")]
pub unsafe extern "system" fn char_upper_buff_w(text: *mut u16, count: u32) -> u32 {
    // SAFETY: the caller's contract.
    unsafe {
        map_in_place(text, Some(count as usize), |unit| {
            cp1252::map_case(unit, true)
        }) as u32
    }
}

/// CharLowerBuffW: CharUpperBuffW's, in small letters.
///
/// # Safety
///
/// As [`char_upper_buff_w`]'s.
#[unsafe(export_name = "f2k_export_CharLowerBuffW")]
pub unsafe extern "system" fn char_lower_buff_w(text: *mut u16, count: u32) -> u32 {
    // SAFETY: the caller's contract.
    unsafe {
        map_in_place(text, Some(count as usize), |unit| {
            cp1252::map_case(unit, false)
        }) as u32
    }
}

/// CharUpperBuffA: CharUpperBuffW's over `count` bytes of the ANSI code page.
///
/// # Safety
///
/// `text` holds `count` bytes the call may change, as for the platform's.
#[unsafe(export_name = "f2k_export_CharUpperBuffA")]
pub unsafe extern "system" fn char_upper_buff_a(text: *mut u8, count: u32) -> u32 {
    // SAFETY: the caller's contract.
    unsafe { map_in_place(text, Some(count as usize), |byte| narrow_case(byte, true)) as u32 }
}

/// CharLowerBuffA: CharUpperBuffA's, in small letters.
///
/// # Safety
///
/// As [`char_upper_buff_a`]'s.
#[unsafe(export_name = "f2k_export_CharLowerBuffA")]
pub unsafe extern "system" fn char_lower_buff_a(text: *mut u8, count: u32) -> u32 {
    // SAFETY: the caller's contract.
    unsafe { map_in_place(text, Some(count as usize), |byte| narrow_case(byte, false)) as u32 }
}

/// IsCharAlphaNumericW: whether the character (the argument's low word) is a letter or a digit
/// (CT_CTYPE1's C1_ALPHA or C1_DIGIT): the other scripts' digits and Latin-1's superscript ones
/// are, the fractions, the ordinal indicators and the Roman numerals not.
#[unsafe(export_name = "f2k_export_IsCharAlphaNumericW")]
pub extern "system" fn is_char_alpha_numeric_w(character: u32) -> u32 {
    (cp1252::c1_flags(character as u16) & (C1_ALPHA | C1_DIGIT) != 0) as u32
}

/// IsCharAlphaNumericA: IsCharAlphaNumericW's, of the ANSI code page's character in the argument's
/// low byte (a CHAR, sign-extended by its caller).
#[unsafe(export_name = "f2k_export_IsCharAlphaNumericA")]
pub extern "system" fn is_char_alpha_numeric_a(character: u32) -> u32 {
    let mut wide = [0u16];
    imports::multi_byte_to_unicode(&mut wide, &[character as u8]);
    is_char_alpha_numeric_w(u32::from(wide[0]))
}

#[cfg(test)]
mod tests {
    use std::vec::Vec;

    use super::*;

    /// The upper and lower sections: the strings in place, and characters in the low word.
    ///
    /// Pins: user32.CharUpperW, user32.CharUpperA, user32.CharLowerW, user32.CharLowerA
    #[test]
    fn case_changes_follow_the_locale() {
        let mut small: Vec<u16> = std::vec![
            0x61, 0x7A, 0xE9, 0xFF, 0xDF, 0xB5, 0x131, 0x69, 0x3B1, 0x3C2, 0x430, 0xFF41, 0x31, 0
        ];
        let at = small.as_mut_ptr();
        // SAFETY: the test's own NUL-terminated strings, then characters in the low word.
        unsafe {
            assert_eq!(char_upper_w(at), at);
            assert_eq!(
                small,
                [
                    0x41, 0x5A, 0xC9, 0x178, 0xDF, 0xB5, 0x131, 0x49, 0x391, 0x3A3, 0x410, 0xFF21,
                    0x31, 0
                ]
            );
            let mut capital: Vec<u16> = std::vec![0x178, 0x130, 0x49, 0x3A3, 0x39C, 0];
            char_lower_w(capital.as_mut_ptr());
            assert_eq!(capital, [0xFF, 0x130, 0x69, 0x3C3, 0x3BC, 0]);
            assert_eq!(char_upper_w(0x3C2 as *mut u16) as usize, 0x3A3);
            assert_eq!(char_lower_w(0xFF21 as *mut u16) as usize, 0xFF41);
            assert_eq!(char_upper_w(core::ptr::null_mut()) as usize, 0);
            let mut narrow = *b"abz\xE9\xFF\xDF\xB5\x9A1!\0";
            char_upper_a(narrow.as_mut_ptr());
            assert_eq!(&narrow, b"ABZ\xC9\x9F\xDF\xB5\x8A1!\0");
            assert_eq!(char_upper_a(0xFF as *mut u8) as usize, 0x9F);
            assert_eq!(char_lower_a(0x8A as *mut u8) as usize, 0x9A);
        }
    }

    /// The buff section: the count runs past a NUL; a count of 0 changes nothing.
    ///
    /// Pins: user32.CharUpperBuffW, user32.CharLowerBuffW, user32.CharUpperBuffA,
    /// user32.CharLowerBuffA
    #[test]
    fn buffers_change_case_by_count() {
        let source = [0x61u16, 0x62, 0x43, 0, 0x64, 0x45, 0x66, 0xE9];
        let mut text = source;
        // SAFETY: the test's own buffers, as long as each count.
        unsafe {
            assert_eq!(char_upper_buff_w(text.as_mut_ptr(), 8), 8);
            assert_eq!(text, [0x41, 0x42, 0x43, 0, 0x44, 0x45, 0x46, 0xC9]);
            let mut text = source;
            assert_eq!(char_lower_buff_w(text.as_mut_ptr(), 3), 3);
            assert_eq!(text, [0x61, 0x62, 0x63, 0, 0x64, 0x45, 0x66, 0xE9]);
            let mut narrow = *b"abC\0dEf\xE9";
            assert_eq!(char_upper_buff_a(narrow.as_mut_ptr(), 0), 0);
            assert_eq!(&narrow, b"abC\0dEf\xE9");
            assert_eq!(char_upper_buff_a(narrow.as_mut_ptr(), 8), 8);
            assert_eq!(&narrow, b"ABC\0DEF\xC9");
        }
    }

    /// The alnum section.
    ///
    /// Pins: user32.IsCharAlphaNumericW, user32.IsCharAlphaNumericA
    #[test]
    fn letters_and_digits_are_alphanumeric() {
        for (character, answer) in [
            (0x61, 1),
            (0x30, 1),
            (0x5F, 0),
            (0xB2, 1),
            (0xBD, 0),
            (0xAA, 0),
            (0x660, 1),
            (0x2160, 0),
            (0x4E00, 1),
            (0xFF10, 1),
            (0, 0),
        ] {
            assert_eq!(
                is_char_alpha_numeric_w(character),
                answer,
                "U+{character:04X}"
            );
        }
        for (character, answer) in [(0xFFFF_FF8A, 1), (0x80, 0), (0xFF, 1), (0x2E, 0)] {
            assert_eq!(is_char_alpha_numeric_a(character), answer, "{character:#x}");
        }
    }

    /// The offsets a walk with CharNextW visits from the start until it stops moving.
    fn next_walk(text: &[u16]) -> Vec<usize> {
        let base = text.as_ptr();
        let mut at = base;
        let mut seen = std::vec![0];
        loop {
            // SAFETY: inside the test's NUL-terminated string.
            let next = unsafe { char_next_w(at) };
            // SAFETY: both inside the one string.
            seen.push(unsafe { next.offset_from(base) } as usize);
            if next == at {
                return seen;
            }
            at = next;
        }
    }

    /// The offsets a walk with CharPrevW visits from the NUL until it stops moving.
    fn prev_walk(text: &[u16]) -> Vec<usize> {
        let base = text.as_ptr();
        let mut at = base.wrapping_add(text.len() - 1);
        let mut seen = std::vec![text.len() - 1];
        loop {
            // SAFETY: inside the test's NUL-terminated string.
            let prev = unsafe { char_prev_w(base, at) };
            // SAFETY: both inside the one string.
            seen.push(unsafe { prev.offset_from(base) } as usize);
            if prev == at {
                return seen;
            }
            at = prev;
        }
    }

    /// The charnext section's wide walks.
    ///
    /// Pins: user32.CharNextW, user32.CharPrevW
    #[test]
    fn wide_walks_keep_marks_with_their_base() {
        let walk = |units: &[u16]| {
            let mut text = units.to_vec();
            text.push(0);
            (next_walk(&text), prev_walk(&text))
        };
        assert_eq!(
            walk(&[0x61, 0x62, 0x63]),
            (std::vec![0, 1, 2, 3, 3], std::vec![3, 2, 1, 0, 0])
        );
        assert_eq!(walk(&[]), (std::vec![0, 0], std::vec![0, 0]));
        assert_eq!(
            walk(&[0x65, 0x301, 0x78]),
            (std::vec![0, 2, 3, 3], std::vec![3, 2, 0, 0])
        );
        assert_eq!(
            walk(&[0x301, 0x78]),
            (std::vec![0, 1, 2, 2], std::vec![2, 1, 1])
        );
        assert_eq!(
            walk(&[0x61, 0x300, 0x301, 0x62]),
            (std::vec![0, 3, 4, 4], std::vec![4, 3, 0, 0])
        );
        assert_eq!(
            walk(&[0x61, 0xD800, 0xDC00, 0x78]),
            (std::vec![0, 1, 2, 3, 4, 4], std::vec![4, 3, 2, 1, 0, 0])
        );
    }

    /// The narrow walks are a byte at a time.
    ///
    /// Pins: user32.CharNextA, user32.CharPrevA
    #[test]
    fn narrow_walks_step_bytes() {
        let text = b"ab\xe9\0";
        let base = text.as_ptr();
        // SAFETY: inside the test's NUL-terminated string.
        unsafe {
            assert_eq!(char_next_a(base), base.wrapping_add(1));
            assert_eq!(char_next_a(base.wrapping_add(2)), base.wrapping_add(3));
            assert_eq!(char_next_a(base.wrapping_add(3)), base.wrapping_add(3));
        }
        assert_eq!(
            char_prev_a(base, base.wrapping_add(3)),
            base.wrapping_add(2)
        );
        assert_eq!(char_prev_a(base, base), base);
    }
}
