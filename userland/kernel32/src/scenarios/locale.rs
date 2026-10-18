//! Locale / string conversion: code page 1252 (ANSI) and 437 (OEM) reported; the installed code
//! pages (1252, 437, 850, UTF-8) described; conversions, case mapping, and character typing
//! answered from the code page tables. The runtime fixture's locale block is the contract.

use rtl::cp1252;

use super::{last_error, UNREAD};
use crate::locale::*;

const CP_ACP: u32 = 0;
const CP_OEMCP: u32 = 1;
const CP_UTF8: u32 = 65001;
const MB_PRECOMPOSED: u32 = 0x1;
const LCMAP_LOWERCASE: u32 = 0x100;
const LCMAP_UPPERCASE: u32 = 0x200;
const LCMAP_SORTKEY: u32 = 0x400;
const CT_CTYPE1: u32 = 1;
const CT_CTYPE2: u32 = 2;
const LOCALE_US: u32 = 0x409;

/// Bytes whose conversions differ from Latin-1 or exercise the table's edges: ASCII, the euro sign,
/// a gap byte, the top of the C1 range, e-acute, y-diaeresis.
const SAMPLE: &[u8] = &[b'A', 0x80, 0x81, 0x9F, 0xE9, 0xFF];
const SAMPLE_WIDE: &[u16] = &[0x0041, 0x20AC, 0x0081, 0x0178, 0x00E9, 0x00FF];

fn unread<T>() -> *const T {
    UNREAD as *const T
}

/// GetACP and GetOEMCP: 1252 and 437.
#[test]
fn get_acp_reports_1252() {
    assert_eq!(get_acp(), 1252);
}

#[test]
fn get_oemcp_reports_437() {
    assert_eq!(get_oemcp(), 437);
}

/// GetCPInfo for CP_ACP, 1252, and 437 alike: TRUE and the single-byte CPINFO — MaxCharSize 1,
/// DefaultChar "?", no lead-byte ranges (which is what keeps the CRT off its DBCS path).
#[test]
fn get_cp_info_fills_the_single_byte_image() {
    for code_page in [CP_ACP, CP_OEMCP, 1252, 437, 850] {
        let mut image = [0xCCu8; 18];
        assert_eq!(unsafe { get_cp_info(code_page, image.as_mut_ptr()) }, 1);
        assert_eq!(image[..4], 1u32.to_le_bytes(), "MaxCharSize");
        assert_eq!(image[4..6], [b'?', 0], "DefaultChar");
        assert_eq!(image[6..], [0; 12], "LeadByte");
    }
}

/// MultiByteToWideChar converts through the 1252 table, explicit counts and NUL-terminated (-1)
/// alike; the terminated form counts and converts the terminator.
#[test]
fn multi_byte_to_wide_char_converts_through_the_table() {
    let mut source = SAMPLE.to_vec();
    source.push(0);
    let mut out = [0xCCCCu16; 16];
    let count = SAMPLE.len() as i32;
    assert_eq!(
        unsafe { multi_byte_to_wide_char(1252, MB_PRECOMPOSED, source.as_ptr(), count, out.as_mut_ptr(), 16) },
        count
    );
    assert_eq!(&out[..SAMPLE.len()], SAMPLE_WIDE);
    assert_eq!(
        unsafe { multi_byte_to_wide_char(CP_ACP, 0, source.as_ptr(), -1, core::ptr::null_mut(), 0) },
        count + 1
    );
    assert_eq!(unsafe { multi_byte_to_wide_char(CP_ACP, 0, source.as_ptr(), -1, out.as_mut_ptr(), 16) }, count + 1);
    assert_eq!(out[SAMPLE.len()], 0);
    let every_byte: Vec<u8> = (0..=255).collect();
    let mut wide = [0u16; 256];
    assert_eq!(unsafe { multi_byte_to_wide_char(1252, 0, every_byte.as_ptr(), 256, wide.as_mut_ptr(), 256) }, 256);
    assert_eq!(wide, cp1252::MB_TO_WC);
}

/// LCMapStringW maps case over the 1252 character set — LCMAP_LOWERCASE (0x100) or
/// LCMAP_UPPERCASE (0x200) exactly — whatever the locale; the sharp s has no single-character
/// uppercase and stays. The hello trace pins the direction: the CRT builds its lower case map
/// asking 0x100, then its upper one asking 0x200.
#[test]
fn lc_map_string_w_maps_case() {
    let mixed: [u16; 9] = [b'a' as u16, b'Z' as u16, 0xE9, 0xC9, 0xFF, 0x178, 0x161, 0xDF, 0x31];
    let count = mixed.len() as i32;
    for (flags, locale, expected) in [
        (LCMAP_UPPERCASE, LOCALE_US, [b'A' as u16, b'Z' as u16, 0xC9, 0xC9, 0x178, 0x178, 0x160, 0xDF, 0x31]),
        (LCMAP_LOWERCASE, 0, [b'a' as u16, b'z' as u16, 0xE9, 0xE9, 0xFF, 0xFF, 0x161, 0xDF, 0x31]),
    ] {
        let mut out = [0u16; 9];
        assert_eq!(unsafe { lc_map_string_w(locale, flags, mixed.as_ptr(), count, out.as_mut_ptr(), count) }, count);
        assert_eq!(out, expected);
    }
}

/// LCMapStringW refuses every other mapping (both case flags, none, a sort key) and an empty source
/// count, with 0 and the source unread; with no destination it is a size query, and a short
/// destination is refused.
#[test]
fn lc_map_string_w_refusals_and_size_queries() {
    let mut out = [0xCCCCu16; 8];
    for (flags, count) in [(LCMAP_UPPERCASE | LCMAP_LOWERCASE, 4), (0, 4), (LCMAP_SORTKEY, 4), (LCMAP_UPPERCASE, 0)] {
        assert_eq!(unsafe { lc_map_string_w(LOCALE_US, flags, unread(), count, out.as_mut_ptr(), 8) }, 0);
    }
    assert_eq!(unsafe { lc_map_string_w(LOCALE_US, LCMAP_LOWERCASE, unread(), 7, core::ptr::null_mut(), 0) }, 7);
    assert_eq!(unsafe { lc_map_string_w(LOCALE_US, LCMAP_LOWERCASE, unread(), 7, out.as_mut_ptr(), 6) }, 0);
    assert_eq!(out, [0xCCCC; 8]);
}

/// GetStringTypeW(CT_CTYPE1) writes each unit's C1 flags — upper, lower, digit, space, punct,
/// control, blank, hex digit, alpha — from the 1252 classification.
#[test]
fn get_string_type_w_classifies_ctype1() {
    let units: Vec<u16> = (0..=0xFF).chain([0x152, 0x161, 0x20AC, 0x4E00]).collect();
    let mut flags = vec![0u16; units.len()];
    assert_eq!(unsafe { get_string_type_w(CT_CTYPE1, units.as_ptr(), units.len() as i32, flags.as_mut_ptr()) }, 1);
    for (unit, flag) in units.iter().zip(&flags) {
        assert_eq!(*flag, cp1252::c1_flags(*unit), "{unit:#x}");
    }
    assert_eq!(flags[b'A' as usize], cp1252::C1_UPPER | cp1252::C1_ALPHA | cp1252::C1_XDIGIT);
    assert_eq!(flags[b'7' as usize] & cp1252::C1_DIGIT, cp1252::C1_DIGIT);
    assert_eq!(
        flags[b' ' as usize] & (cp1252::C1_SPACE | cp1252::C1_BLANK),
        cp1252::C1_SPACE | cp1252::C1_BLANK
    );
}

/// GetStringTypeW refuses every info type but CT_CTYPE1 with 0; an empty count succeeds with nothing
/// written (Windows 2000's GetStringTypeW checks its pointers, takes a
/// negative count as terminated, and classifies `count` characters, none for zero — unlike the A
/// form, whose conversion refuses a zero count). The source is not read for any of them.
#[test]
fn get_string_type_w_refusals_and_empty_counts() {
    let mut out = [0xCCCCu16; 4];
    assert_eq!(unsafe { get_string_type_w(CT_CTYPE2, unread(), 4, out.as_mut_ptr()) }, 0);
    assert_eq!(unsafe { get_string_type_w(CT_CTYPE1, unread(), 0, out.as_mut_ptr()) }, 1);
    assert_eq!(out, [0xCCCC; 4]);
}

/// GetCPInfo for UTF-8: TRUE, MaxCharSize 4. A code page the system lacks (12345) is refused with
/// FALSE and ERROR_INVALID_PARAMETER. The runtime fixture's locale block makes the same calls.
#[test]
fn get_cp_info_reports_utf_8_and_refuses_an_unknown_code_page() {
    let mut info = [0u8; 18];
    assert_eq!(unsafe { get_cp_info(CP_UTF8, info.as_mut_ptr()) }, 1);
    assert_eq!(info[..4], 4u32.to_le_bytes(), "MaxCharSize");
    assert_eq!(info[4..6], [b'?', 0], "DefaultChar");
    assert_eq!(unsafe { get_cp_info(12345, info.as_mut_ptr()) }, 0);
    assert_eq!(last_error(), 87);
}

/// MultiByteToWideChar refuses undefined flags (0x80) and an unknown code page (12345) with 0, and
/// an empty source count with 0. The runtime fixture's locale block pins the first two.
#[test]
fn multi_byte_to_wide_char_refusals() {
    let source = b"abc\0";
    let mut out = [0u16; 8];
    for (code_page, flags, count, error) in [(1252, 0x80, -1, 1004), (12345, 0, -1, 87), (CP_ACP, 0, 0, 87)] {
        assert_eq!(
            unsafe { multi_byte_to_wide_char(code_page, flags, source.as_ptr(), count, out.as_mut_ptr(), 8) },
            0,
            "{code_page} {flags:#x} {count}"
        );
        assert_eq!(last_error(), error);
    }
}

/// MultiByteToWideChar with no destination is a size query, the terminator counted for a -1
/// source; a destination too short for the result is refused with 0. The runtime fixture's locale
/// block makes the same calls.
#[test]
fn multi_byte_to_wide_char_size_queries_and_short_destinations() {
    let source = b"abc\0";
    assert_eq!(unsafe { multi_byte_to_wide_char(1252, 0, source.as_ptr(), -1, core::ptr::null_mut(), 0) }, 4);
    let mut out = [0u16; 2];
    assert_eq!(unsafe { multi_byte_to_wide_char(1252, 0, source.as_ptr(), -1, out.as_mut_ptr(), 2) }, 0);
    assert_eq!(last_error(), 122);
}

/// WideCharToMultiByte refuses an unknown code page and an empty source count; with no destination
/// it is a size query (the terminator counted for a -1 source), and a short destination is
/// refused. The runtime fixture's locale block pins the size query and the short destination.
#[test]
fn wide_char_to_multi_byte_refusals_and_size_queries() {
    let source = [b'A' as u16, b'B' as u16, b'C' as u16, 0];
    let mut out = [0u8; 8];
    let none = core::ptr::null();
    for (code_page, count) in [(12345, -1), (1252, 0)] {
        let converted = unsafe {
            wide_char_to_multi_byte(code_page, 0, source.as_ptr(), count, out.as_mut_ptr(), 8, none, core::ptr::null_mut())
        };
        assert_eq!(converted, 0, "{code_page} {count}");
    }
    let size = unsafe {
        wide_char_to_multi_byte(1252, 0, source.as_ptr(), -1, core::ptr::null_mut(), 0, none, core::ptr::null_mut())
    };
    assert_eq!(size, 4);
    let short = unsafe {
        wide_char_to_multi_byte(1252, 0, source.as_ptr(), -1, out.as_mut_ptr(), 2, none, core::ptr::null_mut())
    };
    assert_eq!(short, 0);
}

/// WideCharToMultiByte converts through the table's inverse; a code point the code page lacks
/// becomes the caller's default character, reported through lpUsedDefaultChar. The runtime
/// fixture's locale block makes the same conversion ("with default '#'").
#[test]
fn wide_char_to_multi_byte_converts_through_the_table() {
    let mut units = SAMPLE_WIDE.to_vec();
    units.extend_from_slice(&[0x4E00, 0]);
    let mut out = [0xCCu8; 16];
    let mut used = 0xCCCC_CCCCu32;
    let converted = unsafe {
        wide_char_to_multi_byte(1252, 0, units.as_ptr(), -1, out.as_mut_ptr(), 16, b"#\0".as_ptr(), &mut used)
    };
    assert_eq!(converted, 8);
    let mut expected = SAMPLE.to_vec();
    expected.extend_from_slice(b"#\0");
    assert_eq!(&out[..8], &expected[..]);
    assert_eq!(used, 1, "the default was used");
}

/// LCMapStringW takes a NUL-terminated source (a -1 count, as for every NLS call): the mapping
/// covers the terminator and the return counts it, as Windows documents the count.
#[test]
fn lc_map_string_w_takes_a_terminated_source() {
    let source = [b'a' as u16, b'b' as u16, 0];
    let mut out = [0u16; 4];
    assert_eq!(unsafe { lc_map_string_w(LOCALE_US, LCMAP_UPPERCASE, source.as_ptr(), -1, out.as_mut_ptr(), 4) }, 3);
    assert_eq!(out[..3], [b'A' as u16, b'B' as u16, 0]);
}

/// LCMapStringW's other NLS conventions: a zero destination size asks the size even with a
/// destination; a null destination with a size is refused; any negative count is NUL-terminated.
#[test]
fn lc_map_string_w_follows_the_nls_conventions() {
    let source = [b'a' as u16, b'b' as u16, 0];
    let mut out = [0xCCCCu16; 4];
    assert_eq!(
        unsafe { lc_map_string_w(LOCALE_US, LCMAP_UPPERCASE, source.as_ptr(), 2, out.as_mut_ptr(), 0) },
        2,
        "a zero size asks the size"
    );
    assert_eq!(out, [0xCCCC; 4], "nothing written for a size query");
    assert_eq!(
        unsafe { lc_map_string_w(LOCALE_US, LCMAP_UPPERCASE, source.as_ptr(), 2, core::ptr::null_mut(), 4) },
        0,
        "a null destination with a size"
    );
    assert_eq!(unsafe { lc_map_string_w(LOCALE_US, LCMAP_UPPERCASE, source.as_ptr(), -2, out.as_mut_ptr(), 4) }, 3);
    assert_eq!(out[..3], [b'A' as u16, b'B' as u16, 0]);
}

/// GetStringTypeW takes any negative count as NUL-terminated: the flag words stop at the
/// terminator instead of running on through the caller's memory.
#[test]
fn get_string_type_w_takes_any_negative_count_as_terminated() {
    let source = [b'A' as u16, 0];
    let mut out = [0xCCCCu16; 4];
    assert_eq!(unsafe { get_string_type_w(CT_CTYPE1, source.as_ptr(), -2, out.as_mut_ptr()) }, 1);
    assert_eq!(out[0], cp1252::c1_flags(b'A' as u16));
    assert_eq!(out[2..], [0xCCCC; 2], "nothing past the terminator's word");
}

/// GetStringTypeW takes a NUL-terminated source (a -1 count): one flag word per unit up to the
/// terminator, as Windows documents the count.
#[test]
fn get_string_type_w_takes_a_terminated_source() {
    let source = [b'A' as u16, b'7' as u16, 0];
    let mut out = [0xCCCCu16; 4];
    assert_eq!(unsafe { get_string_type_w(CT_CTYPE1, source.as_ptr(), -1, out.as_mut_ptr()) }, 1);
    assert_eq!(out[..2], [cp1252::c1_flags(b'A' as u16), cp1252::c1_flags(b'7' as u16)]);
}

/// Past the old caps: the converters take strings longer than 64K, counted or terminated.
#[test]
fn the_converters_take_strings_past_64k() {
    const LONG: i32 = 0x1_1000;
    let mut narrow = vec![b'a'; LONG as usize];
    narrow.push(0);
    let none = core::ptr::null_mut();
    assert_eq!(unsafe { multi_byte_to_wide_char(1252, 0, narrow.as_ptr(), -1, none, 0) }, LONG + 1);
    assert_eq!(unsafe { multi_byte_to_wide_char(1252, 0, narrow.as_ptr(), LONG, none, 0) }, LONG);
    let mut wide = vec![b'a' as u16; LONG as usize];
    wide.push(0);
    let (no_dst, no_default, no_report) = (core::ptr::null_mut(), core::ptr::null(), core::ptr::null_mut());
    assert_eq!(
        unsafe { wide_char_to_multi_byte(1252, 0, wide.as_ptr(), -1, no_dst, 0, no_default, no_report) },
        LONG + 1
    );
    assert_eq!(
        unsafe { wide_char_to_multi_byte(1252, 0, wide.as_ptr(), LONG, no_dst, 0, no_default, no_report) },
        LONG
    );
}

/// Past the old cap: LCMapStringA and GetStringTypeA take sources longer than 512 bytes,
/// counted or terminated, and CompareStringA a terminated one longer than 64K.
#[test]
fn the_narrow_nls_calls_take_long_sources() {
    let mut text = vec![b'a'; 600];
    text.push(0);
    let mut out = vec![0u8; 1202];
    assert_eq!(unsafe { lc_map_string_a(LOCALE_US, LCMAP_UPPERCASE, text.as_ptr(), 600, out.as_mut_ptr(), 600) }, 600);
    assert_eq!(&out[..600], &[b'A'; 600][..]);
    assert_eq!(last_error(), 122, "the captured quirk: a mapping into the buffer leaves 122");
    assert_eq!(
        unsafe { lc_map_string_a(LOCALE_US, LCMAP_UPPERCASE, text.as_ptr(), -1, core::ptr::null_mut(), 0) },
        601
    );
    let mut flags = vec![0u16; 600];
    assert_eq!(unsafe { get_string_type_a(LOCALE_US, CT_CTYPE1, text.as_ptr(), 600, flags.as_mut_ptr()) }, 1);
    assert_eq!(flags, vec![cp1252::c1_flags(b'a' as u16); 600]);
    let mut long = vec![b'q'; 0x1_1000];
    long.push(0);
    let other = long.clone();
    const CSTR_EQUAL: i32 = 2;
    assert_eq!(unsafe { compare_string_a(LOCALE_US, 0, long.as_ptr(), -1, other.as_ptr(), -1) }, CSTR_EQUAL);
}

/// GetLocaleInfoA and W answer the locale's values through the NLS counting rule, and
/// EnumSystemLocalesA hands its one locale to the callback.
#[test]
fn the_locale_answers_its_values() {
    let mut narrow = [0u8; 16];
    assert_eq!(unsafe { get_locale_info_a(LOCALE_US, 0x1001, narrow.as_mut_ptr(), 16) }, 8);
    assert_eq!(&narrow[..8], b"English\0");
    assert_eq!(unsafe { get_locale_info_a(LOCALE_US, 0x1001, core::ptr::null_mut(), 0) }, 8);
    assert_eq!(unsafe { get_locale_info_a(LOCALE_US, 0x1001, narrow.as_mut_ptr(), 4) }, 0);
    assert_eq!(last_error(), 122);
    let mut wide = [0u16; 8];
    assert_eq!(unsafe { get_locale_info_w(LOCALE_US, 0x0E, wide.as_mut_ptr(), 8) }, 2);
    assert_eq!(wide[..2], [b'.' as u16, 0]);
    assert_eq!(unsafe { get_locale_info_w(0x0407, 0x0E, wide.as_mut_ptr(), 8) }, 0);
    assert_eq!(last_error(), 87);
    assert_eq!((get_user_default_lcid(), get_system_default_lcid()), (0x409, 0x409));
    assert_eq!((is_valid_locale(0x409, 2), is_valid_locale(0x407, 2)), (1, 0));
    assert_eq!((is_valid_code_page(1252), is_valid_code_page(12345)), (1, 0));
    unsafe extern "system" fn seen(name: *const u8) -> u32 {
        assert_eq!(unsafe { core::slice::from_raw_parts(name, 9) }, b"00000409\0");
        1
    }
    assert_eq!(unsafe { enum_system_locales_a(Some(seen), 1) }, 1);
}

/// LOCALE_RETURN_NUMBER: a numeric value comes back as a DWORD — two units for the W form,
/// four bytes for the A form, which a zero size asks — decimal values and the hexadecimal language
/// ids alike; a value that is not a number is ERROR_INVALID_FLAGS, a short buffer
/// ERROR_INSUFFICIENT_BUFFER.
#[test]
fn a_number_comes_back_as_a_dword() {
    const RETURN_NUMBER: u32 = 0x2000_0000;
    let mut value = 0xCCCC_CCCCu32;
    let wide = &mut value as *mut u32 as *mut u16;
    assert_eq!(unsafe { get_locale_info_w(LOCALE_US, 0x1004 | RETURN_NUMBER, wide, 2) }, 2);
    assert_eq!(value, 1252, "LOCALE_IDEFAULTANSICODEPAGE");
    assert_eq!(unsafe { get_locale_info_w(LOCALE_US, 0x100C | RETURN_NUMBER, wide, 2) }, 2);
    assert_eq!(value, 6, "LOCALE_IFIRSTDAYOFWEEK");
    assert_eq!(unsafe { get_locale_info_w(LOCALE_US, 0x01 | RETURN_NUMBER, wide, 2) }, 2);
    assert_eq!(value, 0x409, "LOCALE_ILANGUAGE, hexadecimal");
    assert_eq!(unsafe { get_locale_info_w(LOCALE_US, 0x1004 | RETURN_NUMBER, core::ptr::null_mut(), 0) }, 2);
    value = 0xCCCC_CCCC;
    let narrow = &mut value as *mut u32 as *mut u8;
    assert_eq!(unsafe { get_locale_info_a(LOCALE_US, 0x0B | RETURN_NUMBER, narrow, 4) }, 4);
    assert_eq!(value, 437, "LOCALE_IDEFAULTCODEPAGE");
    assert_eq!(unsafe { get_locale_info_a(LOCALE_US, 0x0B | RETURN_NUMBER, core::ptr::null_mut(), 0) }, 4);
    assert_eq!(unsafe { get_locale_info_a(LOCALE_US, 0x0B | RETURN_NUMBER, narrow, 3) }, 0);
    assert_eq!(last_error(), 122);
    assert_eq!(unsafe { get_locale_info_w(LOCALE_US, 0x1004 | RETURN_NUMBER, wide, 1) }, 0);
    assert_eq!(last_error(), 122);
    for lctype in [0x0E, 0x10, 0x1001] {
        assert_eq!(unsafe { get_locale_info_w(LOCALE_US, lctype | RETURN_NUMBER, wide, 2) }, 0, "{lctype:#x}");
        assert_eq!(last_error(), 1004);
    }
}

/// WideCharToMultiByte's flags: WC_NO_BEST_FIT_CHARS is taken, and a unit the page does
/// not hold exactly becomes the default character instead of its best fit (reported); a negative
/// destination size is ERROR_INVALID_PARAMETER.
#[test]
fn wide_char_to_multi_byte_takes_no_best_fit() {
    const WC_NO_BEST_FIT_CHARS: u32 = 0x400;
    let source = [0x0100, b'A' as u16, 0x00E9, 0];
    let mut out = [0xCCu8; 8];
    let mut used = 0xCCCC_CCCCu32;
    let converted = unsafe {
        wide_char_to_multi_byte(1252, WC_NO_BEST_FIT_CHARS, source.as_ptr(), -1, out.as_mut_ptr(), 8, core::ptr::null(), &mut used)
    };
    assert_eq!(converted, 4);
    assert_eq!(&out[..4], b"?A\xE9\0", "U+0100 is not best-fit to 'A'");
    assert_eq!(used, 1);
    let converted = unsafe {
        wide_char_to_multi_byte(1252, 0, source.as_ptr(), -1, out.as_mut_ptr(), 8, core::ptr::null(), &mut used)
    };
    assert_eq!((converted, &out[..4], used), (4, &b"AA\xE9\0"[..], 0), "the best fit without the flag");
    let none = (core::ptr::null(), core::ptr::null_mut());
    let negative = unsafe { wide_char_to_multi_byte(1252, 0, source.as_ptr(), -1, out.as_mut_ptr(), -1, none.0, none.1) };
    assert_eq!((negative, last_error()), (0, 87));
    let utf8 = unsafe { wide_char_to_multi_byte(CP_UTF8, WC_NO_BEST_FIT_CHARS, source.as_ptr(), -1, out.as_mut_ptr(), 8, none.0, none.1) };
    assert_eq!((utf8, last_error()), (0, 1004), "UTF-8 takes no flags");
}

/// MultiByteToWideChar's MB_USEGLYPHCHARS: the OEM page's control bytes (0x01-0x1F, 0x7F)
/// become their glyphs; the ANSI page has no glyph table and ignores the flag.
#[test]
fn multi_byte_to_wide_char_uses_glyph_chars() {
    const MB_USEGLYPHCHARS: u32 = 0x4;
    let source = [0x00, 0x01, 0x0D, 0x1F, b'A', 0x7F, 0x80];
    let mut out = [0xCCCCu16; 8];
    let count = source.len() as i32;
    assert_eq!(unsafe { multi_byte_to_wide_char(437, MB_USEGLYPHCHARS, source.as_ptr(), count, out.as_mut_ptr(), 8) }, count);
    assert_eq!(out[..7], [0x0000, 0x263A, 0x266A, 0x25BC, 0x0041, 0x2302, 0x00C7]);
    assert_eq!(unsafe { multi_byte_to_wide_char(437, 0, source.as_ptr(), count, out.as_mut_ptr(), 8) }, count);
    assert_eq!(out[..7], [0x0000, 0x0001, 0x000D, 0x001F, 0x0041, 0x007F, 0x00C7]);
    assert_eq!(unsafe { multi_byte_to_wide_char(1252, MB_USEGLYPHCHARS, source.as_ptr(), count, out.as_mut_ptr(), 8) }, count);
    assert_eq!(out[..7], [0x0000, 0x0001, 0x000D, 0x001F, 0x0041, 0x007F, 0x20AC]);
}
