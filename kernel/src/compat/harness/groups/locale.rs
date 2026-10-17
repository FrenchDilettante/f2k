//! Locale / string conversion: codepage 1252 (ANSI) and 437 (OEM) reported; conversions, case
//! mapping, and character typing answered from the shipped codepage-1252 tables. The ANSI forms of
//! the mapping and typing calls are never called by the corpus and answer with a zero floor.

use crate::compat::cp1252;
use crate::compat::harness::surface::{assert_argument_blocks, Fixture, UNMAPPED};

pub const MEMBERS: &[&str] = &[
    "GetACP",
    "GetOEMCP",
    "GetCPInfo",
    "MultiByteToWideChar",
    "WideCharToMultiByte",
    "LCMapStringA",
    "LCMapStringW",
    "GetStringTypeA",
    "GetStringTypeW",
    "CompareStringA",
    "CompareStringW",
];

const CP_ACP: u32 = 0;
const CP_OEMCP: u32 = 1;
const MB_PRECOMPOSED: u32 = 0x1;
const MB_ERR_INVALID_CHARS: u32 = 0x8;
const WC_COMPOSITECHECK: u32 = 0x200;
/// The flags the CRT passes when it builds its case maps (the hello trace).
const CRT_CASE_MAP_FLAGS: u32 = 0x220;
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

/// Every member pops the block its callers push. Ledger: locale.
#[test]
#[ignore = "ledger locale: not switched on"]
fn locale_argument_blocks_match_the_prototypes() {
    assert_argument_blocks(MEMBERS);
}

/// GetACP and GetOEMCP: 1252 and 437. Ledger: locale/GetACP.
#[test]
#[ignore = "ledger locale/GetACP: not switched on"]
fn get_acp_reports_1252() {
    let mut fixture = Fixture::new();
    assert_eq!(fixture.call("GetACP", &[]), 1252);
}

/// Ledger: locale/GetOEMCP.
#[test]
#[ignore = "ledger locale/GetOEMCP: not switched on"]
fn get_oemcp_reports_437() {
    let mut fixture = Fixture::new();
    assert_eq!(fixture.call("GetOEMCP", &[]), 437);
}

/// GetCPInfo for CP_ACP, 1252, and 437 alike: TRUE and the single-byte CPINFO — MaxCharSize 1,
/// DefaultChar "?", no lead-byte ranges (which is what keeps the CRT off its DBCS path). Ledger:
/// locale/GetCPInfo.
#[test]
#[ignore = "ledger locale/GetCPInfo: the existing path writes caller memory (target-only)"]
fn get_cp_info_fills_the_single_byte_image() {
    let mut fixture = Fixture::new();
    for code_page in [CP_ACP, 1252, 437] {
        let info = fixture.stage(&[0xCC; 18]);
        assert_eq!(fixture.call("GetCPInfo", &[code_page, info]), 1);
        let image = fixture.memory().bytes(info, 18);
        assert_eq!(image[..4], 1u32.to_le_bytes(), "MaxCharSize");
        assert_eq!(image[4..6], [b'?', 0], "DefaultChar");
        assert_eq!(image[6..], [0; 12], "LeadByte");
    }
}

/// GetCPInfo refuses every other codepage — CP_OEMCP is not resolved on this surface — with FALSE
/// and the buffer untouched. Ledger: locale/GetCPInfo.
#[test]
#[ignore = "ledger locale/GetCPInfo: not switched on"]
fn get_cp_info_refuses_other_code_pages() {
    let mut fixture = Fixture::new();
    let info = fixture.stage(&[0xCC; 18]);
    for code_page in [CP_OEMCP, 850, 65001, 932] {
        assert_eq!(fixture.call("GetCPInfo", &[code_page, info]), 0);
    }
    assert_eq!(fixture.memory().bytes(info, 18), [0xCC; 18]);
}

/// MultiByteToWideChar validates in order — the codepage (CP_ACP or 1252 only), then the flags
/// (MB_PRECOMPOSED at most), then the count (zero refused) — each refusal 0, the destination
/// untouched; the source is not read for any of them. Ledger: locale/MultiByteToWideChar.
#[test]
#[ignore = "ledger locale/MultiByteToWideChar: not switched on"]
fn multi_byte_to_wide_char_refusals() {
    let mut fixture = Fixture::new();
    let out = fixture.stage(&[0xCC; 16]);
    for (code_page, flags, count) in [
        (437, 0, 4),
        (CP_OEMCP, 0, 4),
        (65001, 0, 4),
        (1252, MB_ERR_INVALID_CHARS, 4),
        (1252, MB_PRECOMPOSED | 0x2, 4),
        (CP_ACP, 0, 0),
    ] {
        assert_eq!(
            fixture.call(
                "MultiByteToWideChar",
                &[code_page, flags, UNMAPPED, count, out, 8]
            ),
            0,
            "{code_page} {flags:#x} {count}"
        );
    }
    assert_eq!(fixture.memory().bytes(out, 16), [0xCC; 16]);
}

/// MultiByteToWideChar with an explicit count and no destination is a size query: the count back,
/// the source unread. A destination shorter than the count is refused with 0, untouched. Ledger:
/// locale/MultiByteToWideChar.
#[test]
#[ignore = "ledger locale/MultiByteToWideChar: not switched on"]
fn multi_byte_to_wide_char_size_queries_and_short_destinations() {
    let mut fixture = Fixture::new();
    for flags in [0, MB_PRECOMPOSED] {
        assert_eq!(
            fixture.call("MultiByteToWideChar", &[1252, flags, UNMAPPED, 6, 0, 0]),
            6
        );
    }
    let out = fixture.stage(&[0xCC; 16]);
    assert_eq!(
        fixture.call("MultiByteToWideChar", &[CP_ACP, 0, UNMAPPED, 6, out, 5]),
        0
    );
    assert_eq!(fixture.memory().bytes(out, 16), [0xCC; 16]);
}

/// MultiByteToWideChar converts through the 1252 table, explicit counts and NUL-terminated (-1)
/// alike; the terminated form counts and converts the terminator. Ledger:
/// locale/MultiByteToWideChar.
#[test]
#[ignore = "ledger locale/MultiByteToWideChar: the existing path reads caller memory \
            (target-only)"]
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

/// WideCharToMultiByte validates the codepage (CP_ACP or 1252 only) and the count (zero refused),
/// each refusal 0 with the source unread; the flags are not validated. Ledger:
/// locale/WideCharToMultiByte.
#[test]
#[ignore = "ledger locale/WideCharToMultiByte: not switched on"]
fn wide_char_to_multi_byte_refusals_and_size_queries() {
    let mut fixture = Fixture::new();
    let out = fixture.stage(&[0xCC; 16]);
    for (code_page, count) in [(437, 4), (CP_OEMCP, 4), (65001, 4), (1252, 0)] {
        assert_eq!(
            fixture.call(
                "WideCharToMultiByte",
                &[code_page, 0, UNMAPPED, count, out, 8, 0, 0]
            ),
            0
        );
    }
    for flags in [0, WC_COMPOSITECHECK, CRT_CASE_MAP_FLAGS, 0xFFFF_FFFF] {
        assert_eq!(
            fixture.call(
                "WideCharToMultiByte",
                &[CP_ACP, flags, UNMAPPED, 6, 0, 0, 0, 0]
            ),
            6
        );
    }
    assert_eq!(
        fixture.call("WideCharToMultiByte", &[1252, 0, UNMAPPED, 6, out, 5, 0, 0]),
        0
    );
    assert_eq!(fixture.memory().bytes(out, 16), [0xCC; 16]);
}

/// WideCharToMultiByte converts through the table's inverse; a code point the codepage lacks
/// becomes "?", and the default-character pair is never read or written. Ledger:
/// locale/WideCharToMultiByte.
#[test]
#[ignore = "ledger locale/WideCharToMultiByte: the existing path reads caller memory \
            (target-only)"]
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
    expected.extend_from_slice(b"?\0");
    assert_eq!(fixture.memory().bytes(out, 8), expected);
    assert_eq!(fixture.memory().bytes(used, 4), [0xCC; 4]);
}

/// LCMapStringW maps case over the 1252 character set — LCMAP_LOWERCASE (0x100) or
/// LCMAP_UPPERCASE (0x200) exactly — whatever the locale; the sharp s has no single-character
/// uppercase and stays. The hello trace pins the direction: the CRT builds its lower case map
/// asking 0x100, then its upper one asking 0x200. Ledger: locale/LCMapStringW.
#[test]
#[ignore = "ledger locale/LCMapStringW: the existing path reads caller memory (target-only)"]
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

/// LCMapStringW refuses every other mapping (both case flags, none, a sort key) and both the empty
/// and the NUL-terminated (-1) source counts, with 0 and the source unread; with no destination it
/// is a size query, and a short destination is refused. Ledger: locale/LCMapStringW.
#[test]
#[ignore = "ledger locale/LCMapStringW: not switched on"]
fn lc_map_string_w_refusals_and_size_queries() {
    let mut fixture = Fixture::new();
    let out = fixture.stage(&[0xCC; 16]);
    for (flags, count) in [
        (LCMAP_UPPERCASE | LCMAP_LOWERCASE, 4),
        (0, 4),
        (LCMAP_SORTKEY, 4),
        (LCMAP_UPPERCASE, 0),
        (LCMAP_UPPERCASE, u32::MAX),
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
/// control, blank, hex digit, alpha — from the 1252 classification. Ledger: locale/GetStringTypeW.
#[test]
#[ignore = "ledger locale/GetStringTypeW: the existing path reads caller memory (target-only)"]
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

/// GetStringTypeW refuses every info type but CT_CTYPE1 and the NUL-terminated (-1) count with 0;
/// an empty count succeeds with nothing written. The source is not read for any of them. Ledger:
/// locale/GetStringTypeW.
#[test]
#[ignore = "ledger locale/GetStringTypeW: not switched on"]
fn get_string_type_w_refusals_and_empty_counts() {
    let mut fixture = Fixture::new();
    let out = fixture.stage(&[0xCC; 8]);
    assert_eq!(
        fixture.call("GetStringTypeW", &[CT_CTYPE2, UNMAPPED, 4, out]),
        0
    );
    assert_eq!(
        fixture.call("GetStringTypeW", &[CT_CTYPE1, UNMAPPED, u32::MAX, out]),
        0
    );
    assert_eq!(
        fixture.call("GetStringTypeW", &[CT_CTYPE1, UNMAPPED, 0, out]),
        1
    );
    assert_eq!(fixture.memory().bytes(out, 8), [0xCC; 8]);
}

/// LCMapStringA's floor: zero, nothing written. Ledger: locale/LCMapStringA.
#[test]
#[ignore = "ledger locale/LCMapStringA: unpinned floor"]
fn lc_map_string_a_answers_with_the_floor() {
    let mut fixture = Fixture::new();
    let source = fixture.c_string(b"abc");
    let out = fixture.stage(&[0xCC; 4]);
    assert_eq!(
        fixture.call(
            "LCMapStringA",
            &[LOCALE_US, LCMAP_UPPERCASE, source, 3, out, 4]
        ),
        0
    );
    assert_eq!(fixture.memory().bytes(out, 4), [0xCC; 4]);
}

/// GetStringTypeA's floor: zero, nothing written. Ledger: locale/GetStringTypeA.
#[test]
#[ignore = "ledger locale/GetStringTypeA: unpinned floor"]
fn get_string_type_a_answers_with_the_floor() {
    let mut fixture = Fixture::new();
    let source = fixture.c_string(b"abc");
    let out = fixture.stage(&[0xCC; 6]);
    assert_eq!(
        fixture.call("GetStringTypeA", &[LOCALE_US, CT_CTYPE1, source, 3, out]),
        0
    );
    assert_eq!(fixture.memory().bytes(out, 6), [0xCC; 6]);
}
