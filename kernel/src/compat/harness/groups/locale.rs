//! Locale / string conversion: code page 1252 (ANSI) and 437 (OEM) reported; the installed code
//! pages (1252, 437, 850, UTF-8) described; conversions, case mapping, and character typing
//! answered from the code page tables. The runtime fixture's locale block is the contract.

use crate::compat::cp1252;
use crate::compat::harness::surface::{Fixture, UNMAPPED};

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

/// GetACP and GetOEMCP: 1252 and 437.
#[test]
fn get_acp_reports_1252() {
    let mut fixture = Fixture::new();
    assert_eq!(fixture.call("GetACP", &[]), 1252);
}

#[test]
fn get_oemcp_reports_437() {
    let mut fixture = Fixture::new();
    assert_eq!(fixture.call("GetOEMCP", &[]), 437);
}

/// GetCPInfo for CP_ACP, 1252, and 437 alike: TRUE and the single-byte CPINFO — MaxCharSize 1,
/// DefaultChar "?", no lead-byte ranges (which is what keeps the CRT off its DBCS path).
#[test]
#[ignore = "B2: the kernel's GetCPInfo installs 1252 and 437 alone (not 850)"]
fn get_cp_info_fills_the_single_byte_image() {
    let mut fixture = Fixture::new();
    for code_page in [CP_ACP, CP_OEMCP, 1252, 437, 850] {
        let info = fixture.stage(&[0xCC; 18]);
        assert_eq!(fixture.call("GetCPInfo", &[code_page, info]), 1);
        let image = fixture.memory().bytes(info, 18);
        assert_eq!(image[..4], 1u32.to_le_bytes(), "MaxCharSize");
        assert_eq!(image[4..6], [b'?', 0], "DefaultChar");
        assert_eq!(image[6..], [0; 12], "LeadByte");
    }
}

/// MultiByteToWideChar converts through the 1252 table, explicit counts and NUL-terminated (-1)
/// alike; the terminated form counts and converts the terminator.
#[test]
fn multi_byte_to_wide_char_converts_through_the_table() {
    let mut fixture = Fixture::new();
    let source = fixture.c_string(SAMPLE);
    let out = fixture.stage(&[0xCC; 32]);
    let count = SAMPLE.len() as u32;
    assert_eq!(
        fixture.call(
            "MultiByteToWideChar",
            &[1252, MB_PRECOMPOSED, source, count, out, 16]
        ),
        count
    );
    assert_eq!(fixture.wide_at(out, count), SAMPLE_WIDE);
    assert_eq!(
        fixture.call("MultiByteToWideChar", &[CP_ACP, 0, source, u32::MAX, 0, 0]),
        count + 1
    );
    assert_eq!(
        fixture.call(
            "MultiByteToWideChar",
            &[CP_ACP, 0, source, u32::MAX, out, 16]
        ),
        count + 1
    );
    assert_eq!(fixture.wide_at(out, count + 1)[count as usize], 0);
    let every_byte: Vec<u8> = (0..=255).collect();
    let all = fixture.stage(&every_byte);
    let wide = fixture.buffer(512);
    assert_eq!(
        fixture.call("MultiByteToWideChar", &[1252, 0, all, 256, wide, 256]),
        256
    );
    assert_eq!(fixture.wide_at(wide, 256), cp1252::MB_TO_WC);
}

/// LCMapStringW maps case over the 1252 character set — LCMAP_LOWERCASE (0x100) or
/// LCMAP_UPPERCASE (0x200) exactly — whatever the locale; the sharp s has no single-character
/// uppercase and stays. The hello trace pins the direction: the CRT builds its lower case map
/// asking 0x100, then its upper one asking 0x200.
#[test]
fn lc_map_string_w_maps_case() {
    let mut fixture = Fixture::new();
    let mixed: &[u16] = &[
        b'a' as u16,
        b'Z' as u16,
        0xE9,
        0xC9,
        0xFF,
        0x178,
        0x161,
        0xDF,
        0x31,
    ];
    let source = fixture.wide(mixed);
    let out = fixture.buffer(2 * mixed.len() as u32);
    let count = mixed.len() as u32;
    for (flags, locale, expected) in [
        (
            LCMAP_UPPERCASE,
            LOCALE_US,
            [
                b'A' as u16,
                b'Z' as u16,
                0xC9,
                0xC9,
                0x178,
                0x178,
                0x160,
                0xDF,
                0x31,
            ],
        ),
        (
            LCMAP_LOWERCASE,
            0,
            [
                b'a' as u16,
                b'z' as u16,
                0xE9,
                0xE9,
                0xFF,
                0xFF,
                0x161,
                0xDF,
                0x31,
            ],
        ),
    ] {
        assert_eq!(
            fixture.call("LCMapStringW", &[locale, flags, source, count, out, count]),
            count
        );
        assert_eq!(fixture.wide_at(out, count), expected);
    }
}

/// LCMapStringW refuses every other mapping (both case flags, none, a sort key) and an empty source
/// count, with 0 and the source unread; with no destination it
/// is a size query, and a short destination is refused.
#[test]
fn lc_map_string_w_refusals_and_size_queries() {
    let mut fixture = Fixture::new();
    let out = fixture.stage(&[0xCC; 16]);
    for (flags, count) in [
        (LCMAP_UPPERCASE | LCMAP_LOWERCASE, 4),
        (0, 4),
        (LCMAP_SORTKEY, 4),
        (LCMAP_UPPERCASE, 0),
    ] {
        assert_eq!(
            fixture.call("LCMapStringW", &[LOCALE_US, flags, UNMAPPED, count, out, 8]),
            0
        );
    }
    assert_eq!(
        fixture.call(
            "LCMapStringW",
            &[LOCALE_US, LCMAP_LOWERCASE, UNMAPPED, 7, 0, 0]
        ),
        7
    );
    assert_eq!(
        fixture.call(
            "LCMapStringW",
            &[LOCALE_US, LCMAP_LOWERCASE, UNMAPPED, 7, out, 6]
        ),
        0
    );
    assert_eq!(fixture.memory().bytes(out, 16), [0xCC; 16]);
}

/// GetStringTypeW(CT_CTYPE1) writes each unit's C1 flags — upper, lower, digit, space, punct,
/// control, blank, hex digit, alpha — from the 1252 classification.
#[test]
fn get_string_type_w_classifies_ctype1() {
    let mut fixture = Fixture::new();
    let units: Vec<u16> = (0..=0xFF).chain([0x152, 0x161, 0x20AC, 0x4E00]).collect();
    let source = fixture.wide(&units);
    let out = fixture.buffer(2 * units.len() as u32);
    assert_eq!(
        fixture.call(
            "GetStringTypeW",
            &[CT_CTYPE1, source, units.len() as u32, out]
        ),
        1
    );
    let flags = fixture.wide_at(out, units.len() as u32);
    for (unit, flag) in units.iter().zip(&flags) {
        assert_eq!(*flag, cp1252::c1_flags(*unit), "{unit:#x}");
    }
    assert_eq!(
        flags[b'A' as usize],
        cp1252::C1_UPPER | cp1252::C1_ALPHA | cp1252::C1_XDIGIT
    );
    assert_eq!(flags[b'7' as usize] & cp1252::C1_DIGIT, cp1252::C1_DIGIT);
    assert_eq!(
        flags[b' ' as usize] & (cp1252::C1_SPACE | cp1252::C1_BLANK),
        cp1252::C1_SPACE | cp1252::C1_BLANK
    );
}

/// GetStringTypeW refuses every info type but CT_CTYPE1 with 0; an empty count succeeds with nothing
/// written. The source is not read for any of them.
#[test]
fn get_string_type_w_refusals_and_empty_counts() {
    let mut fixture = Fixture::new();
    let out = fixture.stage(&[0xCC; 8]);
    assert_eq!(
        fixture.call("GetStringTypeW", &[CT_CTYPE2, UNMAPPED, 4, out]),
        0
    );
    assert_eq!(
        fixture.call("GetStringTypeW", &[CT_CTYPE1, UNMAPPED, 0, out]),
        1
    );
    assert_eq!(fixture.memory().bytes(out, 8), [0xCC; 8]);
}

/// GetCPInfo for UTF-8: TRUE, MaxCharSize 4. A code page the system lacks (12345) is refused with
/// FALSE. The runtime fixture's locale block makes the same calls.
#[test]
#[ignore = "B2: the kernel's GetCPInfo installs 1252 and 437 alone (not UTF-8)"]
fn get_cp_info_reports_utf_8_and_refuses_an_unknown_code_page() {
    let mut fixture = Fixture::new();
    let info = fixture.stage(&[0; 18]);
    assert_eq!(fixture.call("GetCPInfo", &[CP_UTF8, info]), 1);
    assert_eq!(fixture.memory().u32_at(info), 4, "MaxCharSize");
    assert_eq!(
        fixture.memory().bytes(info + 4, 2),
        [b'?', 0],
        "DefaultChar"
    );
    assert_eq!(fixture.call("GetCPInfo", &[12345, info]), 0);
}

/// MultiByteToWideChar refuses undefined flags (0x80) and an unknown code page (12345) with 0, and
/// an empty source count with 0. The runtime fixture's locale block pins the first two.
#[test]
fn multi_byte_to_wide_char_refusals() {
    let mut fixture = Fixture::new();
    let source = fixture.c_string(b"abc");
    let out = fixture.buffer(16);
    for (code_page, flags, count) in [(1252, 0x80, u32::MAX), (12345, 0, u32::MAX), (CP_ACP, 0, 0)]
    {
        assert_eq!(
            fixture.call(
                "MultiByteToWideChar",
                &[code_page, flags, source, count, out, 8]
            ),
            0,
            "{code_page} {flags:#x} {count}"
        );
    }
}

/// MultiByteToWideChar with no destination is a size query, the terminator counted for a -1
/// source; a destination too short for the result is refused with 0. The runtime fixture's locale
/// block makes the same calls.
#[test]
fn multi_byte_to_wide_char_size_queries_and_short_destinations() {
    let mut fixture = Fixture::new();
    let source = fixture.c_string(b"abc");
    assert_eq!(
        fixture.call("MultiByteToWideChar", &[1252, 0, source, u32::MAX, 0, 0]),
        4
    );
    let out = fixture.buffer(16);
    assert_eq!(
        fixture.call("MultiByteToWideChar", &[1252, 0, source, u32::MAX, out, 2]),
        0
    );
}

/// WideCharToMultiByte refuses an unknown code page and an empty source count; with no destination
/// it is a size query (the terminator counted for a -1 source), and a short destination is
/// refused. The runtime fixture's locale block pins the size query and the short destination.
#[test]
fn wide_char_to_multi_byte_refusals_and_size_queries() {
    let mut fixture = Fixture::new();
    let source = fixture.wide(&[b'A' as u16, b'B' as u16, b'C' as u16, 0]);
    let out = fixture.buffer(16);
    for (code_page, count) in [(12345, u32::MAX), (1252, 0)] {
        assert_eq!(
            fixture.call(
                "WideCharToMultiByte",
                &[code_page, 0, source, count, out, 8, 0, 0]
            ),
            0,
            "{code_page} {count}"
        );
    }
    assert_eq!(
        fixture.call(
            "WideCharToMultiByte",
            &[1252, 0, source, u32::MAX, 0, 0, 0, 0]
        ),
        4
    );
    assert_eq!(
        fixture.call(
            "WideCharToMultiByte",
            &[1252, 0, source, u32::MAX, out, 2, 0, 0]
        ),
        0
    );
}

/// WideCharToMultiByte converts through the table's inverse; a code point the code page lacks
/// becomes the caller's default character, reported through lpUsedDefaultChar. The runtime
/// fixture's locale block makes the same conversion ("with default '#'").
#[test]
#[ignore = "B2: the kernel's WideCharToMultiByte ignores the caller's default character"]
fn wide_char_to_multi_byte_converts_through_the_table() {
    let mut fixture = Fixture::new();
    let mut units = SAMPLE_WIDE.to_vec();
    units.extend_from_slice(&[0x4E00, 0]);
    let source = fixture.wide(&units);
    let out = fixture.stage(&[0xCC; 16]);
    let used = fixture.stage(&[0xCC; 4]);
    let default = fixture.stage(b"#\0");
    assert_eq!(
        fixture.call(
            "WideCharToMultiByte",
            &[1252, 0, source, u32::MAX, out, 16, default, used]
        ),
        8
    );
    let mut expected = SAMPLE.to_vec();
    expected.extend_from_slice(b"#\0");
    assert_eq!(fixture.memory().bytes(out, 8), expected);
    assert_eq!(fixture.memory().u32_at(used), 1, "the default was used");
}

/// LCMapStringW takes a NUL-terminated source (a -1 count, as for every NLS call): the mapping
/// covers the terminator and the return counts it. Windows documents the count this way; F2K
/// refuses it.
#[test]
#[ignore = "K32-5: LCMapStringW refuses a -1 source count"]
fn lc_map_string_w_takes_a_terminated_source() {
    let mut fixture = Fixture::new();
    let source = fixture.wide(&[b'a' as u16, b'b' as u16, 0]);
    let out = fixture.buffer(8);
    assert_eq!(
        fixture.call(
            "LCMapStringW",
            &[LOCALE_US, LCMAP_UPPERCASE, source, u32::MAX, out, 4]
        ),
        3
    );
    assert_eq!(fixture.wide_at(out, 3), [b'A' as u16, b'B' as u16, 0]);
}

/// GetStringTypeW takes a NUL-terminated source (a -1 count): one flag word per unit up to the
/// terminator. Windows documents the count this way; F2K refuses it.
#[test]
#[ignore = "K32-5: GetStringTypeW refuses a -1 source count"]
fn get_string_type_w_takes_a_terminated_source() {
    let mut fixture = Fixture::new();
    let source = fixture.wide(&[b'A' as u16, b'7' as u16, 0]);
    let out = fixture.stage(&[0xCC; 8]);
    assert_eq!(
        fixture.call("GetStringTypeW", &[CT_CTYPE1, source, u32::MAX, out]),
        1
    );
    assert_eq!(
        fixture.wide_at(out, 2),
        [cp1252::c1_flags(b'A' as u16), cp1252::c1_flags(b'7' as u16)]
    );
}
