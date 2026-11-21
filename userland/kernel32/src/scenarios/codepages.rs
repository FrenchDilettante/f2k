//! The code pages' conversions past the ANSI and OEM pages' plain tables: UTF-8's ill-formed
//! sequences, 850, 28591, UTF-7 and CP_SYMBOL, best fit and the composite flags. The locale
//! fixture's utf8err, cpconv and bestfit blocks are the contract.

use super::last_error;
use crate::locale::*;

const CP_UTF7: u32 = 65000;
const CP_UTF8: u32 = 65001;
const CP_SYMBOL: u32 = 42;
const MB_COMPOSITE: u32 = 0x2;
const WC_DISCARDNS: u32 = 0x10;
const WC_SEPCHARS: u32 = 0x20;
const WC_DEFAULTCHAR: u32 = 0x40;
const WC_COMPOSITECHECK: u32 = 0x200;
const WC_NO_BEST_FIT_CHARS: u32 = 0x400;
const MB_PRECOMPOSED: u32 = 0x1;
const MB_ERR_INVALID_CHARS: u32 = 0x8;
const ERROR_NO_UNICODE_TRANSLATION: u32 = 1113;

/// MultiByteToWideChar(code page, flags) of `bytes` into 16 units: the count and the units, or 0
/// and the last error.
fn to_wide(code_page: u32, flags: u32, bytes: &[u8]) -> Result<Vec<u16>, u32> {
    let mut out = [0xBEEFu16; 16];
    let count = unsafe {
        multi_byte_to_wide_char(
            code_page,
            flags,
            bytes.as_ptr(),
            bytes.len() as i32,
            out.as_mut_ptr(),
            16,
        )
    };
    if count == 0 {
        return Err(last_error());
    }
    Ok(out[..count as usize].to_vec())
}

/// UTF-8 takes MB_ERR_INVALID_CHARS, and no other flag: an overlong sequence is
/// ERROR_NO_UNICODE_TRANSLATION with it or without, a stray continuation byte only with it, a
/// sequence a plain byte cuts short is dropped either way.
///
/// Pins: kernel32.MultiByteToWideChar
#[test]
fn utf8_refuses_what_it_cannot_decode() {
    assert_eq!(
        to_wide(CP_UTF8, MB_ERR_INVALID_CHARS, b"a\xC3\xA9"),
        Ok(vec![0x61, 0xE9])
    );
    assert_eq!(to_wide(CP_UTF8, MB_PRECOMPOSED, b"a"), Err(1004));
    for flags in [0, MB_ERR_INVALID_CHARS] {
        assert_eq!(
            to_wide(CP_UTF8, flags, b"\xC0\xAF"),
            Err(ERROR_NO_UNICODE_TRANSLATION)
        );
        assert_eq!(to_wide(CP_UTF8, flags, b"\xE2\x82x"), Ok(vec![0x78]));
    }
    assert_eq!(to_wide(CP_UTF8, 0, b"\x80x"), Ok(vec![0x78]));
    assert_eq!(
        to_wide(CP_UTF8, MB_ERR_INVALID_CHARS, b"\x80x"),
        Err(ERROR_NO_UNICODE_TRANSLATION)
    );
}

/// WideCharToMultiByte(code page, flags) of `units` into 32 bytes, with lpUsedDefaultChar when
/// `ask` says: the bytes and the report, or 0 and the last error.
fn to_narrow(code_page: u32, flags: u32, units: &[u16], ask: bool) -> Result<(Vec<u8>, u32), u32> {
    let mut out = [0xCCu8; 32];
    let mut used = 7u32;
    let used_ptr = if ask {
        &mut used as *mut u32
    } else {
        core::ptr::null_mut()
    };
    let count = unsafe {
        wide_char_to_multi_byte(
            code_page,
            flags,
            units.as_ptr(),
            units.len() as i32,
            out.as_mut_ptr(),
            32,
            core::ptr::null(),
            used_ptr,
        )
    };
    if count == 0 {
        return Err(last_error());
    }
    Ok((out[..count as usize].to_vec(), used))
}

/// IsValidCodePage and GetCPInfo know 850, 28591 and UTF-7 (MaxCharSize 5), not CP_SYMBOL, which
/// converts all the same.
///
/// Pins: kernel32.IsValidCodePage, kernel32.GetCPInfo
#[test]
fn the_pages_facts() {
    for (page, max) in [(850, 1), (28591, 1), (CP_UTF7, 5)] {
        assert_eq!(is_valid_code_page(page), 1, "{page}");
        let mut info = [0xCCu8; 18];
        assert_eq!(unsafe { get_cp_info(page, info.as_mut_ptr()) }, 1);
        assert_eq!(info[..6], [max, 0, 0, 0, b'?', 0], "{page}");
    }
    assert_eq!(is_valid_code_page(CP_SYMBOL), 0);
    let mut info = [0xCCu8; 18];
    assert_eq!(unsafe { get_cp_info(CP_SYMBOL, info.as_mut_ptr()) }, 0);
    assert_eq!((last_error(), info), (87, [0xCC; 18]));
}

/// 850 and 28591 convert through their tables, best-fitting what they lack unless
/// WC_NO_BEST_FIT_CHARS.
///
/// Pins: kernel32.MultiByteToWideChar, kernel32.WideCharToMultiByte
#[test]
fn the_oem_and_iso_pages_convert() {
    assert_eq!(
        to_wide(850, 0, b"A\x80\x82\x9B\xB0\xE1\xFF"),
        Ok(vec![0x41, 0xC7, 0xE9, 0xF8, 0x2591, 0xDF, 0xA0])
    );
    let to_oem = [0x00E9, 0x00C7, 0x2591, 0x00FF, 0x20AC, 0x0100];
    assert_eq!(
        to_narrow(850, 0, &to_oem, true),
        Ok((vec![0x82, 0x80, 0xB0, 0x98, 0x3F, 0x41], 1))
    );
    assert_eq!(
        to_narrow(850, WC_NO_BEST_FIT_CHARS, &to_oem, true),
        Ok((vec![0x82, 0x80, 0xB0, 0x98, 0x3F, 0x3F], 1))
    );
    assert_eq!(
        to_wide(28591, 0, b"A\x80\x9F\xA0\xE9\xFF"),
        Ok(vec![0x41, 0x80, 0x9F, 0xA0, 0xE9, 0xFF])
    );
    assert_eq!(
        to_narrow(28591, 0, &[0x00E9, 0x0080, 0x0100, 0x20AC], true),
        Ok((vec![0xE9, 0x80, 0x41, 0x3F], 1))
    );
}

/// UTF-7 and CP_SYMBOL take no flags, and neither a default character nor its report.
///
/// Pins: kernel32.MultiByteToWideChar, kernel32.WideCharToMultiByte
#[test]
fn utf7_and_symbol_convert_without_flags() {
    assert_eq!(
        to_wide(CP_UTF7, 0, b"Hi +Jjo-!"),
        Ok(vec![0x48, 0x69, 0x20, 0x263A, 0x21])
    );
    assert_eq!(to_wide(CP_UTF7, MB_ERR_INVALID_CHARS, b"+AGE-"), Err(1004));
    let smile = [0x48, 0x69, 0x20, 0x263A, 0x21];
    assert_eq!(
        to_narrow(CP_UTF7, 0, &smile, false),
        Ok((b"Hi +JjoAIQ-".to_vec(), 7))
    );
    assert_eq!(to_narrow(CP_UTF7, 0, &smile, true), Err(87));
    assert_eq!(
        to_narrow(CP_UTF7, WC_NO_BEST_FIT_CHARS, &smile, false),
        Err(1004)
    );
    assert_eq!(
        to_wide(CP_SYMBOL, 0, b"A \xFF"),
        Ok(vec![0xF041, 0xF020, 0xF0FF])
    );
    assert_eq!(to_wide(CP_SYMBOL, MB_PRECOMPOSED, b"A"), Err(1004));
    let pua = [0xF041, 0xF020, 0xF0FF];
    assert_eq!(
        to_narrow(CP_SYMBOL, 0, &pua, false),
        Ok((b"A \xFF".to_vec(), 7))
    );
    assert_eq!(to_narrow(CP_SYMBOL, 0, &pua, true), Err(87));
    assert_eq!(
        to_narrow(CP_SYMBOL, 0, &[0x41, 0x03B1], false),
        Err(ERROR_NO_UNICODE_TRANSLATION)
    );
}

/// 1252 and 437 best-fit from Windows' tables (∞ is 8, ™ in 437 is T), unless
/// WC_NO_BEST_FIT_CHARS; what neither holds is the default character, reported.
///
/// Pins: kernel32.WideCharToMultiByte
#[test]
fn best_fit_follows_windows_tables() {
    for (page, unit, byte) in [
        (1252, 0x221E, b'8'),
        (1252, 0xFF21, b'A'),
        (1252, 0x03B1, b'a'),
        (437, 0x2122, b'T'),
        (437, 0x00A9, b'c'),
    ] {
        assert_eq!(to_narrow(page, 0, &[unit], true), Ok((vec![byte], 0)));
        assert_eq!(
            to_narrow(page, WC_NO_BEST_FIT_CHARS, &[unit], true),
            Ok((vec![b'?'], 1))
        );
    }
    assert_eq!(to_narrow(1252, 0, &[0x0391], true), Ok((vec![b'?'], 1)));
}

/// WC_COMPOSITECHECK composes a letter and the mark after it; a pair with no precomposed form is
/// both characters (WC_SEPCHARS), the letter alone (WC_DISCARDNS) or the default character
/// (WC_DEFAULTCHAR). Those three need WC_COMPOSITECHECK.
///
/// Pins: kernel32.WideCharToMultiByte
#[test]
fn the_composite_check() {
    let decomposed = [0x65, 0x0301, 0x78];
    assert_eq!(
        to_narrow(1252, WC_COMPOSITECHECK, &decomposed, true),
        Ok((vec![0xE9, 0x78], 0))
    );
    assert_eq!(
        to_narrow(1252, 0, &decomposed, true),
        Ok((vec![0x65, 0xB4, 0x78], 0))
    );
    let uncomposable = [0x71, 0x0301];
    for (flags, expected) in [
        (WC_DISCARDNS, Ok((vec![0x71], 0))),
        (WC_SEPCHARS, Ok((vec![0x71, 0xB4], 0))),
        (WC_DEFAULTCHAR, Ok((vec![b'?'], 1))),
    ] {
        assert_eq!(
            to_narrow(1252, WC_COMPOSITECHECK | flags, &uncomposable, true),
            expected
        );
        assert_eq!(to_narrow(1252, flags, &uncomposable, true), Err(1004));
    }
}

/// MB_COMPOSITE decomposes the precomposed letters, but writes one as it is where the destination
/// has room for it alone; it may not go with MB_PRECOMPOSED.
///
/// Pins: kernel32.MultiByteToWideChar
#[test]
fn mb_composite_decomposes() {
    assert_eq!(
        to_wide(1252, MB_COMPOSITE, b"\xE9\xC5x"),
        Ok(vec![0x65, 0x0301, 0x41, 0x030A, 0x78])
    );
    assert_eq!(
        to_wide(1252, MB_PRECOMPOSED | MB_COMPOSITE, b"\xE9"),
        Err(1004)
    );
    let mut out = [0xBEEFu16; 2];
    let count = unsafe {
        multi_byte_to_wide_char(1252, MB_COMPOSITE, b"\xE9".as_ptr(), 1, out.as_mut_ptr(), 1)
    };
    assert_eq!((count, out), (1, [0x00E9, 0xBEEF]));
}
