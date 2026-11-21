//! Code pages: the conversions MultiByteToWideChar and WideCharToMultiByte perform, and the facts
//! GetCPInfo and IsValidCodePage report.
//!
//! Two surfaces. The kernel's ([`CodePage`]: [`decode_byte`], [`encode_unit`]) converts the ANSI
//! page, 1252 ([`super::cp1252`]), and the OEM page, 437, with a small best fit of its own: a Latin
//! letter with a diacritic becomes its base letter, and in the ANSI page a combining accent its
//! spacing form. kernel32's ([`Page`]: [`to_wide`], [`to_narrow`]) converts 1252, 437, 850 and
//! 28591 ([`sbcs`], with Windows' full best-fit tables), UTF-7 ([`utf7`]), UTF-8 and CP_SYMBOL;
//! its tables stay out of the kernel's image, which never names them. CP_ACP and CP_THREAD_ACP name
//! 1252, CP_OEMCP 437.
//!
//! The narrow-to-wide direction is a table look-up for the single-byte pages (the low half is
//! ASCII; with MB_USEGLYPHCHARS the OEM pages' control bytes are their glyphs instead — the ANSI
//! page has no glyph table) and, for UTF-8, Windows 2000's decoder ([`utf8_decode`]), which refuses
//! an overlong or out-of-range sequence and otherwise drops an ill-formed one silently rather than
//! replacing it, unless MB_ERR_INVALID_CHARS asks it to refuse that too. The wide-to-narrow
//! direction maps a unit the page holds exactly; otherwise it best-fits, unless
//! WC_NO_BEST_FIT_CHARS asks not to; otherwise it substitutes the default character and reports
//! having done so.

/// The code pages, as their numbers.
pub const CP_ACP: u32 = 0;
pub const CP_OEMCP: u32 = 1;
pub const CP_THREAD_ACP: u32 = 3;
pub const CP_UTF7: u32 = 65000;
pub const CP_UTF8: u32 = 65001;
pub const CP_SYMBOL: u32 = 42;

pub mod sbcs;
mod tables;
pub mod utf7;

/// A code page this surface converts.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CodePage {
    Ansi,
    Oem,
    Utf8,
}

/// The code page a number names for conversion: none for one without a table here.
pub fn resolve(cp: u32) -> Option<CodePage> {
    match cp {
        CP_ACP | CP_THREAD_ACP | 1252 => Some(CodePage::Ansi),
        CP_OEMCP | 437 => Some(CodePage::Oem),
        CP_UTF8 => Some(CodePage::Utf8),
        _ => None,
    }
}

/// Whether a code page is installed (IsValidCodePage): the ones that convert, CP_SYMBOL aside.
pub fn is_valid(cp: u32) -> bool {
    matches!(cp, 437 | 850 | 1252 | 28591 | CP_UTF7 | CP_UTF8)
}

/// The CPINFO image of an installed code page (CP_ACP and CP_OEMCP included): the maximum
/// character size, the default character `?`, no lead-byte ranges.
pub fn cp_info(cp: u32) -> Option<[u8; 18]> {
    let max = match cp {
        CP_ACP | CP_OEMCP | CP_THREAD_ACP | 437 | 850 | 1252 | 28591 => 1u32,
        CP_UTF7 => 5,
        CP_UTF8 => 4,
        _ => return None,
    };
    let mut info = [0u8; 18];
    info[..4].copy_from_slice(&max.to_le_bytes());
    info[4] = b'?';
    Some(info)
}

/// Code page 437's high half (0x80-0xFF) as UTF-16.
pub const CP437_HIGH: [u16; 128] = [
    0x00C7, 0x00FC, 0x00E9, 0x00E2, 0x00E4, 0x00E0, 0x00E5, 0x00E7, 0x00EA, 0x00EB, 0x00E8, 0x00EF,
    0x00EE, 0x00EC, 0x00C4, 0x00C5, 0x00C9, 0x00E6, 0x00C6, 0x00F4, 0x00F6, 0x00F2, 0x00FB, 0x00F9,
    0x00FF, 0x00D6, 0x00DC, 0x00A2, 0x00A3, 0x00A5, 0x20A7, 0x0192, 0x00E1, 0x00ED, 0x00F3, 0x00FA,
    0x00F1, 0x00D1, 0x00AA, 0x00BA, 0x00BF, 0x2310, 0x00AC, 0x00BD, 0x00BC, 0x00A1, 0x00AB, 0x00BB,
    0x2591, 0x2592, 0x2593, 0x2502, 0x2524, 0x2561, 0x2562, 0x2556, 0x2555, 0x2563, 0x2551, 0x2557,
    0x255D, 0x255C, 0x255B, 0x2510, 0x2514, 0x2534, 0x252C, 0x251C, 0x2500, 0x253C, 0x255E, 0x255F,
    0x255A, 0x2554, 0x2569, 0x2566, 0x2560, 0x2550, 0x256C, 0x2567, 0x2568, 0x2564, 0x2565, 0x2559,
    0x2558, 0x2552, 0x2553, 0x256B, 0x256A, 0x2518, 0x250C, 0x2588, 0x2584, 0x258C, 0x2590, 0x2580,
    0x03B1, 0x00DF, 0x0393, 0x03C0, 0x03A3, 0x03C3, 0x00B5, 0x03C4, 0x03A6, 0x0398, 0x03A9, 0x03B4,
    0x221E, 0x03C6, 0x03B5, 0x2229, 0x2261, 0x00B1, 0x2265, 0x2264, 0x2320, 0x2321, 0x00F7, 0x2248,
    0x00B0, 0x2219, 0x00B7, 0x221A, 0x207F, 0x00B2, 0x25A0, 0x00A0,
];

/// Code page 437's glyphs for its control bytes 0x00-0x1F (MB_USEGLYPHCHARS); 0x7F's is U+2302.
pub const CP437_GLYPHS: [u16; 32] = [
    0x0000, 0x263A, 0x263B, 0x2665, 0x2666, 0x2663, 0x2660, 0x2022, 0x25D8, 0x25CB, 0x25D9, 0x2642,
    0x2640, 0x266A, 0x266B, 0x263C, 0x25BA, 0x25C4, 0x2195, 0x203C, 0x00B6, 0x00A7, 0x25AC, 0x21A8,
    0x2191, 0x2193, 0x2192, 0x2190, 0x221F, 0x2194, 0x25B2, 0x25BC,
];
/// Code page 437's glyph for 0x7F (MB_USEGLYPHCHARS).
pub const CP437_GLYPH_7F: u16 = 0x2302;

/// A single-byte page's byte as UTF-16.
pub fn decode_byte(page: CodePage, byte: u8) -> u16 {
    match page {
        CodePage::Oem if byte >= 0x80 => CP437_HIGH[byte as usize - 0x80],
        CodePage::Oem => byte as u16,
        _ => crate::cp1252::MB_TO_WC[byte as usize],
    }
}

/// The byte a single-byte page holds `unit` as exactly, if any.
fn exact_byte(page: CodePage, unit: u16) -> Option<u8> {
    match page {
        CodePage::Oem => {
            if unit < 0x80 {
                return Some(unit as u8);
            }
            CP437_HIGH
                .iter()
                .position(|&u| u == unit)
                .map(|i| 0x80 + i as u8)
        }
        _ => {
            let byte = crate::cp1252::wc_to_mb(unit);
            (crate::cp1252::MB_TO_WC[byte as usize] == unit).then_some(byte)
        }
    }
}

/// The base letters of U+0100-U+017F (Latin Extended-A), for best fit; a space where none fits.
const LATIN_EXTENDED_A: &[u8; 128] =
    b"AaAaAaCcCcCcCcDdDdEeEeEeEeEeGgGgGgGgHhHhIiIiIiIiIi  JjKk LlLlLl  LlNnNnNn   OoOoOo  RrRrRrSsSsSsSsTtTtTtUuUuUuUuUuUuWwYyYZzZzZz ";

/// The combining accents the ANSI page best-fits, and the spacing accents (or ASCII marks) they
/// become.
const ANSI_ACCENTS: [(u16, u8); 9] = [
    (0x0300, b'`'),
    (0x0301, 0xB4),
    (0x0302, b'^'),
    (0x0303, b'~'),
    (0x0304, 0xAF),
    (0x0308, 0xA8),
    (0x030A, 0xB0),
    (0x0327, 0xB8),
    (0x0332, b'_'),
];

/// The best-fit replacement of `unit` in `page`: a Latin letter with a diacritic becomes its base
/// letter, and in the ANSI page a combining accent its spacing form. A subset of Windows' own
/// tables ([`sbcs`]: the host tests hold it to them).
fn best_fit(page: CodePage, unit: u16) -> Option<u8> {
    match unit {
        // The ANSI page has the Icelandic eth, which the D with stroke looks like.
        0x0110 if page == CodePage::Ansi => Some(0xD0),
        0x0100..=0x017F => {
            let base = LATIN_EXTENDED_A[unit as usize - 0x100];
            (base != b' ').then_some(base)
        }
        0x0300..=0x036F if page == CodePage::Ansi => ANSI_ACCENTS
            .iter()
            .find(|&&(accent, _)| accent == unit)
            .map(|&(_, byte)| byte),
        _ => None,
    }
}

/// One unit to a single-byte page: exactly, best-fit (when `fit` allows it), or the default
/// (`None`).
pub fn encode_unit(page: CodePage, unit: u16, fit: bool) -> Option<u8> {
    exact_byte(page, unit).or_else(|| best_fit(page, unit).filter(|_| fit))
}

/// A string the code page cannot convert (ERROR_NO_UNICODE_TRANSLATION): UTF-8 Windows 2000
/// refuses to decode, a unit CP_SYMBOL has no byte for.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct NoTranslation;

/// UTF-8 to UTF-16, Windows 2000's way (the locale fixture's utf8err block), into `out`: the units
/// it decodes. A sequence that cannot be well formed refuses the whole string, whatever `strict`
/// says: a lead byte no sequence starts with (C0 and C1, whose sequences are all overlong, and F5
/// to FF, whose values all pass U+10FFFF or which start five- to eight-byte forms), and a
/// completed sequence that is overlong or past U+10FFFF. A surrogate's own three bytes decode to
/// it. The rest is dropped silently unless `strict` asks (MB_ERR_INVALID_CHARS): a continuation
/// byte no lead byte asked for, and a sequence the string's end cuts short, refuse the string
/// then. A sequence a byte that is not a continuation cuts short is dropped even then, and that
/// byte decodes on its own.
pub fn utf8_decode(
    bytes: &[u8],
    strict: bool,
    mut out: impl FnMut(u16),
) -> Result<(), NoTranslation> {
    let mut i = 0;
    while i < bytes.len() {
        let lead = bytes[i];
        let (trail, initial, least) = match lead {
            0x00..=0x7F => {
                out(lead as u16);
                i += 1;
                continue;
            }
            0x80..=0xBF if strict => return Err(NoTranslation),
            0x80..=0xBF => {
                i += 1;
                continue;
            }
            0xC2..=0xDF => (1, (lead & 0x1F) as u32, 0x80),
            0xE0..=0xEF => (2, (lead & 0x0F) as u32, 0x800),
            0xF0..=0xF4 => (3, (lead & 0x07) as u32, 0x1_0000),
            _ => return Err(NoTranslation),
        };
        let present = (1..=trail)
            .take_while(|&k| bytes.get(i + k).is_some_and(|&b| b & 0xC0 == 0x80))
            .count();
        if present < trail {
            if strict && i + 1 + present == bytes.len() {
                return Err(NoTranslation); // cut short by the string's end
            }
            // The broken sequence is dropped; the byte that broke it decodes on its own.
            i += 1 + present;
            continue;
        }
        let value = (1..=trail).fold(initial, |v, k| (v << 6) | (bytes[i + k] & 0x3F) as u32);
        if value < least || value > 0x10_FFFF {
            return Err(NoTranslation);
        }
        i += 1 + trail;
        if value >= 0x1_0000 {
            let v = value - 0x1_0000;
            out(0xD800 | (v >> 10) as u16);
            out(0xDC00 | (v & 0x3FF) as u16);
        } else {
            out(value as u16);
        }
    }
    Ok(())
}

/// UTF-16 to UTF-8, into `out` (a surrogate pair as one four-byte sequence, a lone surrogate as the
/// three bytes of its own value).
pub fn utf8_encode(units: &[u16], mut out: impl FnMut(u8)) {
    let mut i = 0;
    while i < units.len() {
        let unit = units[i] as u32;
        let value = if (0xD800..0xDC00).contains(&unit)
            && units
                .get(i + 1)
                .is_some_and(|&n| (0xDC00..0xE000).contains(&n))
        {
            i += 1;
            0x1_0000 + ((unit - 0xD800) << 10) + (units[i] as u32 - 0xDC00)
        } else {
            unit
        };
        i += 1;
        match value {
            0..=0x7F => out(value as u8),
            0x80..=0x7FF => {
                out(0xC0 | (value >> 6) as u8);
                out(0x80 | (value & 0x3F) as u8);
            }
            0x800..=0xFFFF => {
                out(0xE0 | (value >> 12) as u8);
                out(0x80 | ((value >> 6) & 0x3F) as u8);
                out(0x80 | (value & 0x3F) as u8);
            }
            _ => {
                out(0xF0 | (value >> 18) as u8);
                out(0x80 | ((value >> 12) & 0x3F) as u8);
                out(0x80 | ((value >> 6) & 0x3F) as u8);
                out(0x80 | (value & 0x3F) as u8);
            }
        }
    }
}

/// A code page MultiByteToWideChar and WideCharToMultiByte convert through (kernel32's; the
/// kernel's conversions keep to [`CodePage`]).
#[derive(Clone, Copy)]
pub enum Page {
    /// A single-byte page: 1252, 437, 850 or 28591.
    Single(&'static sbcs::SingleByte),
    /// UTF-7 (code page 65000).
    Utf7,
    /// UTF-8 (code page 65001).
    Utf8,
    /// CP_SYMBOL (42): a byte from 0x20 up is U+F000 plus itself, the Symbol fonts' private-use
    /// range; a byte below is itself. Windows 2000 converts through it, but IsValidCodePage and
    /// GetCPInfo do not know it.
    Symbol,
}

/// The page a code page number names for conversion: CP_ACP and CP_THREAD_ACP the ANSI page,
/// CP_OEMCP the OEM page; none for a page without a table here.
pub fn page(cp: u32) -> Option<Page> {
    Some(match cp {
        CP_ACP | CP_THREAD_ACP | 1252 => Page::Single(&sbcs::CP1252),
        CP_OEMCP | 437 => Page::Single(&sbcs::CP437),
        850 => Page::Single(&sbcs::CP850),
        28591 => Page::Single(&sbcs::CP28591),
        CP_UTF7 => Page::Utf7,
        CP_UTF8 => Page::Utf8,
        CP_SYMBOL => Page::Symbol,
        _ => return None,
    })
}

/// Narrow to wide: the units `bytes` decode to in `page`, a single-byte page's control bytes as
/// their glyphs when `glyphs` asks (MB_USEGLYPHCHARS); UTF-8 refuses what [`utf8_decode`] refuses
/// (`strict` for MB_ERR_INVALID_CHARS).
pub fn to_wide(
    page: Page,
    bytes: &[u8],
    glyphs: bool,
    strict: bool,
    mut out: impl FnMut(u16),
) -> Result<(), NoTranslation> {
    match page {
        Page::Utf8 => return utf8_decode(bytes, strict, out),
        Page::Utf7 => utf7::decode(bytes, out),
        Page::Symbol => bytes.iter().for_each(|&b| match b {
            0x00..=0x1F => out(b as u16),
            _ => out(0xF000 | b as u16),
        }),
        Page::Single(single) => bytes.iter().for_each(|&b| out(single.decode(b, glyphs))),
    }
    Ok(())
}

/// Wide to narrow: the bytes `units` encode to in `page`, a single-byte page substituting
/// `default` where it holds nothing that fits (nothing but an exact match when `fit` is false:
/// WC_NO_BEST_FIT_CHARS). Returns whether the default was used; CP_SYMBOL refuses a unit outside
/// its range.
pub fn to_narrow(
    page: Page,
    units: &[u16],
    default: u8,
    fit: bool,
    mut out: impl FnMut(u8),
) -> Result<bool, NoTranslation> {
    let mut used = false;
    match page {
        Page::Utf8 => utf8_encode(units, out),
        Page::Utf7 => utf7::encode(units, out),
        Page::Symbol => {
            for &unit in units {
                match unit {
                    0x00..=0x1F => out(unit as u8),
                    0xF020..=0xF0FF => out(unit as u8),
                    _ => return Err(NoTranslation),
                }
            }
        }
        Page::Single(single) => {
            for &unit in units {
                out(single.encode(unit, fit).unwrap_or_else(|| {
                    used = true;
                    default
                }));
            }
        }
    }
    Ok(used)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The conversion page of the kernel's page.
    fn page_of(page: CodePage) -> Page {
        match page {
            CodePage::Ansi => Page::Single(&sbcs::CP1252),
            CodePage::Oem => Page::Single(&sbcs::CP437),
            CodePage::Utf8 => Page::Utf8,
        }
    }

    fn wide(page: CodePage, bytes: &[u8]) -> Vec<u16> {
        let mut out = Vec::new();
        to_wide(page_of(page), bytes, false, false, |u| out.push(u)).unwrap();
        out
    }

    fn narrow(page: CodePage, units: &[u16], default: u8) -> (Vec<u8>, bool) {
        let mut out = Vec::new();
        let used = to_narrow(page_of(page), units, default, true, |b| out.push(b)).unwrap();
        (out, used)
    }

    /// The runtime capture's conversions.
    #[test]
    fn the_captured_conversions() {
        assert_eq!(
            wide(CodePage::Utf8, b"\xC3\xA9\xE2\x82\xAC\0"),
            [0x00E9, 0x20AC, 0]
        );
        assert_eq!(wide(CodePage::Utf8, b"a\xC3(b\0"), [0x61, 0x28, 0x62, 0]);
        let w = [0x20AC, 0x0100, 0x4E2D, b'A' as u16, 0];
        assert_eq!(
            narrow(CodePage::Ansi, &w, b'?'),
            (vec![0x80, 0x41, 0x3F, 0x41, 0], true)
        );
        assert_eq!(
            narrow(CodePage::Ansi, &w, b'#'),
            (vec![0x80, 0x41, 0x23, 0x41, 0], true)
        );
        assert_eq!(
            narrow(CodePage::Oem, &w, b'?').0,
            [0x3F, 0x41, 0x3F, 0x41, 0]
        );
        assert_eq!(
            narrow(CodePage::Utf8, &w, b'?').0,
            [0xE2, 0x82, 0xAC, 0xC4, 0x80, 0xE4, 0xB8, 0xAD, 0x41, 0]
        );
    }

    /// The 437 table round-trips through its inverse, and the pages' facts.
    #[test]
    fn the_oem_page_round_trips() {
        for byte in 0..=255u8 {
            let unit = decode_byte(CodePage::Oem, byte);
            assert_eq!(exact_byte(CodePage::Oem, unit), Some(byte), "{byte:#04x}");
        }
        assert_eq!(decode_byte(CodePage::Oem, 0x80), 0x00C7);
        assert_eq!(decode_byte(CodePage::Oem, 0xFF), 0x00A0);
        assert_eq!(resolve(CP_OEMCP), Some(CodePage::Oem));
        assert!(is_valid(850) && is_valid(28591) && is_valid(CP_UTF7) && !is_valid(12345));
        assert_eq!(cp_info(CP_UTF7).unwrap()[..5], [5, 0, 0, 0, b'?']);
        assert_eq!(cp_info(28591).unwrap()[..5], [1, 0, 0, 0, b'?']);
        assert!(!is_valid(CP_SYMBOL) && cp_info(CP_SYMBOL).is_none());
        assert!(page(CP_SYMBOL).is_some() && page(12345).is_none());
        assert_eq!(cp_info(CP_UTF8).unwrap()[..5], [4, 0, 0, 0, b'?']);
        assert_eq!(cp_info(12345), None);
    }

    /// CP_SYMBOL: a byte from 0x20 up is U+F000 plus itself and back, a control byte itself; a
    /// unit outside that range has no byte (the locale fixture's cpconv block).
    #[test]
    fn the_symbol_page() {
        let mut wide = Vec::new();
        to_wide(Page::Symbol, b"A \xFF\0", false, false, |u| wide.push(u)).unwrap();
        assert_eq!(wide, [0xF041, 0xF020, 0xF0FF, 0]);
        let mut narrow = Vec::new();
        let used = to_narrow(Page::Symbol, &wide, b'?', true, |b| narrow.push(b));
        assert_eq!((narrow, used), (b"A \xFF\0".to_vec(), Ok(false)));
        let refused = to_narrow(Page::Symbol, &[0x41, 0x03B1], b'?', true, |_| ());
        assert_eq!(refused, Err(NoTranslation));
    }

    /// UTF-8: four-byte sequences make surrogate pairs and back; stray continuations vanish.
    #[test]
    fn utf8_surrogates_and_strays() {
        assert_eq!(wide(CodePage::Utf8, b"\xF0\x9F\x98\x80"), [0xD83D, 0xDE00]);
        assert_eq!(
            narrow(CodePage::Utf8, &[0xD83D, 0xDE00], b'?').0,
            b"\xF0\x9F\x98\x80"
        );
        assert_eq!(wide(CodePage::Utf8, b"\x80a\xBF"), [0x61]);
    }

    /// UTF-8's ill-formed sequences, as the locale fixture's utf8err block has Windows 2000 decode
    /// them, leniently and under MB_ERR_INVALID_CHARS: the decoded units, or the refusal.
    #[test]
    fn utf8_ill_formed_sequences() {
        fn decode(bytes: &[u8], strict: bool) -> Result<Vec<u16>, NoTranslation> {
            let mut out = Vec::new();
            utf8_decode(bytes, strict, |u| out.push(u)).map(|()| out)
        }
        let both: &[(&[u8], Result<&[u16], NoTranslation>)] = &[
            (b"a\xC3\xA9", Ok(&[0x61, 0xE9])),
            (b"\xF0\x90\x80\x80", Ok(&[0xD800, 0xDC00])),
            (b"\xF4\x8F\xBF\xBF", Ok(&[0xDBFF, 0xDFFF])),
            (b"\xF4\x90\x80\x80", Err(NoTranslation)),
            (b"\xF5\x80\x80\x80", Err(NoTranslation)),
            (b"\xF7\xBF\xBF\xBF", Err(NoTranslation)),
            (b"\xF8\x88\x80\x80\x80", Err(NoTranslation)),
            (b"\xFC\x84\x80\x80\x80\x80", Err(NoTranslation)),
            (b"\xFE\xFF", Err(NoTranslation)),
            (b"\xC0\xAF", Err(NoTranslation)),
            (b"\xC1\xBF", Err(NoTranslation)),
            (b"\xE0\x80\xAF", Err(NoTranslation)),
            (b"\xF0\x80\x80\xAF", Err(NoTranslation)),
            (b"\xED\xA0\x80", Ok(&[0xD800])),
            (b"\xEF\xBF\xBF", Ok(&[0xFFFF])),
            (b"\xE2\x82x", Ok(&[0x78])),
        ];
        for &(bytes, expected) in both {
            for strict in [false, true] {
                assert_eq!(
                    decode(bytes, strict).as_deref().map_err(|e| *e),
                    expected,
                    "{bytes:02X?}, strict {strict}"
                );
            }
        }
        // A stray continuation, and a sequence the end cuts short: dropped, or refused when strict.
        for bytes in [&b"\x80x"[..], b"x\xE2\x82"] {
            assert_eq!(decode(bytes, false), Ok(vec![0x78]));
            assert_eq!(decode(bytes, true), Err(NoTranslation));
        }
    }

    /// The OEM page's glyphs (none of them a high-half character), and the best fit dropped for
    /// WC_NO_BEST_FIT_CHARS while exact matches stay.
    #[test]
    fn the_oem_glyphs() {
        assert_eq!(sbcs::CP437.decode(0x01, true), 0x263A);
        assert_eq!(sbcs::CP437.decode(0x7F, true), 0x2302);
        assert_eq!(sbcs::CP437.decode(0x41, true), 0x41);
        assert_eq!(
            sbcs::CP1252.decode(0x01, true),
            0x01,
            "the ANSI page has no glyphs"
        );
        for glyph in CP437_GLYPHS[1..].iter().chain(&[CP437_GLYPH_7F]) {
            assert!(!CP437_HIGH.contains(glyph), "{glyph:#06x}");
        }
        assert_eq!(encode_unit(CodePage::Ansi, 0x0100, true), Some(b'A'));
        assert_eq!(
            encode_unit(CodePage::Ansi, 0x0100, false),
            None,
            "no best fit"
        );
        assert_eq!(encode_unit(CodePage::Ansi, 0x00E9, false), Some(0xE9));
        assert_eq!(encode_unit(CodePage::Ansi, 0x0301, true), Some(0xB4));
        assert_eq!(
            encode_unit(CodePage::Oem, 0x0301, true),
            None,
            "437 has no acute"
        );
    }
}
