//! Code pages: the conversions MultiByteToWideChar and WideCharToMultiByte perform, and the facts
//! GetCPInfo and IsValidCodePage report.
//!
//! Three code pages convert: 1252 (the ANSI code page, [`super::cp1252`]), 437 (the OEM code page)
//! and UTF-8. 850 is installed — GetCPInfo describes it, IsValidCodePage accepts it — but has no
//! table here. CP_ACP and CP_THREAD_ACP name 1252, CP_OEMCP 437.
//!
//! The narrow-to-wide direction is a table look-up for the single-byte pages (without
//! MB_USEGLYPHCHARS the low half is ASCII) and, for UTF-8, Windows 2000's decoder, which drops an
//! ill-formed sequence silently rather than replacing it: a lead byte whose continuation is missing
//! is skipped and the byte that broke it decodes on its own, and a stray continuation byte is
//! skipped. The wide-to-narrow direction maps a unit the page holds exactly; otherwise it best-fits
//! (a Latin letter with a diacritic becomes its base letter); otherwise it substitutes the default
//! character and reports having done so.

/// The code pages, as their numbers.
pub const CP_ACP: u32 = 0;
pub const CP_OEMCP: u32 = 1;
pub const CP_THREAD_ACP: u32 = 3;
pub const CP_UTF8: u32 = 65001;

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

/// Whether a code page is installed (IsValidCodePage): the ones that convert, and 850.
pub fn is_valid(cp: u32) -> bool {
    matches!(cp, 437 | 850 | 1252 | CP_UTF8)
}

/// The CPINFO image of an installed code page (CP_ACP and CP_OEMCP included): the maximum
/// character size, the default character `?`, no lead-byte ranges.
pub fn cp_info(cp: u32) -> Option<[u8; 18]> {
    let max = match cp {
        CP_ACP | CP_OEMCP | CP_THREAD_ACP | 437 | 850 | 1252 => 1u32,
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

/// A single-byte page's byte as UTF-16.
pub fn decode_byte(page: CodePage, byte: u8) -> u16 {
    match page {
        CodePage::Oem if byte >= 0x80 => CP437_HIGH[byte as usize - 0x80],
        CodePage::Oem => byte as u16,
        _ => super::cp1252::MB_TO_WC[byte as usize],
    }
}

/// The byte a single-byte page holds `unit` as exactly, if any.
fn exact_byte(page: CodePage, unit: u16) -> Option<u8> {
    match page {
        CodePage::Oem => {
            if unit < 0x80 {
                return Some(unit as u8);
            }
            CP437_HIGH.iter().position(|&u| u == unit).map(|i| 0x80 + i as u8)
        }
        _ => {
            let byte = super::cp1252::wc_to_mb(unit);
            (super::cp1252::MB_TO_WC[byte as usize] == unit).then_some(byte)
        }
    }
}

/// The base letters of U+0100-U+017F (Latin Extended-A), for best fit; a space where none fits.
const LATIN_EXTENDED_A: &[u8; 128] =
    b"AaAaAaCcCcCcCcDdDdEeEeEeEeEeGgGgGgGgHhHhIiIiIiIiIi  JjKk LlLlLl  LlNnNnNn   OoOoOo  RrRrRrSsSsSsSsTtTtTtUuUuUuUuUuUuWwYyYZzZzZzs";

/// The best-fit replacement of `unit`: a Latin letter with a diacritic becomes its base letter.
fn best_fit(unit: u16) -> Option<u8> {
    match unit {
        0x0100..=0x017F => {
            let base = LATIN_EXTENDED_A[unit as usize - 0x100];
            (base != b' ').then_some(base)
        }
        _ => None,
    }
}

/// One unit to a single-byte page: exactly, best-fit, or the default (`None`).
pub fn encode_unit(page: CodePage, unit: u16) -> Option<u8> {
    exact_byte(page, unit).or_else(|| best_fit(unit))
}

/// UTF-8 to UTF-16, Windows 2000's way (see the module notes), into `out`: the units it decodes.
pub fn utf8_decode(bytes: &[u8], mut out: impl FnMut(u16)) {
    let mut i = 0;
    while i < bytes.len() {
        let lead = bytes[i];
        let (trail, initial) = match lead {
            0x00..=0x7F => {
                out(lead as u16);
                i += 1;
                continue;
            }
            0xC0..=0xDF => (1, (lead & 0x1F) as u32),
            0xE0..=0xEF => (2, (lead & 0x0F) as u32),
            0xF0..=0xF7 => (3, (lead & 0x07) as u32),
            // A stray continuation byte, or a byte no sequence starts with.
            _ => {
                i += 1;
                continue;
            }
        };
        let complete = (1..=trail).all(|k| bytes.get(i + k).is_some_and(|&b| b & 0xC0 == 0x80));
        if !complete {
            // The broken lead is skipped; the byte that broke it decodes on its own.
            i += 1;
            continue;
        }
        let value = (1..=trail).fold(initial, |v, k| (v << 6) | (bytes[i + k] & 0x3F) as u32);
        i += 1 + trail;
        if value >= 0x1_0000 {
            let v = value - 0x1_0000;
            out(0xD800 | (v >> 10) as u16);
            out(0xDC00 | (v & 0x3FF) as u16);
        } else {
            out(value as u16);
        }
    }
}

/// UTF-16 to UTF-8, into `out` (a surrogate pair as one four-byte sequence, a lone surrogate as the
/// three bytes of its own value).
pub fn utf8_encode(units: &[u16], mut out: impl FnMut(u8)) {
    let mut i = 0;
    while i < units.len() {
        let unit = units[i] as u32;
        let value = if (0xD800..0xDC00).contains(&unit)
            && units.get(i + 1).is_some_and(|&n| (0xDC00..0xE000).contains(&n))
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

/// Narrow to wide: the units `bytes` decode to in `page`.
pub fn to_wide(page: CodePage, bytes: &[u8], mut out: impl FnMut(u16)) {
    match page {
        CodePage::Utf8 => utf8_decode(bytes, out),
        _ => bytes.iter().for_each(|&b| out(decode_byte(page, b))),
    }
}

/// Wide to narrow: the bytes `units` encode to in `page`, a single-byte page substituting
/// `default` where it holds nothing that fits. Returns whether the default was used.
pub fn to_narrow(page: CodePage, units: &[u16], default: u8, mut out: impl FnMut(u8)) -> bool {
    match page {
        CodePage::Utf8 => {
            utf8_encode(units, out);
            false
        }
        _ => {
            let mut used = false;
            for &unit in units {
                out(encode_unit(page, unit).unwrap_or_else(|| {
                    used = true;
                    default
                }));
            }
            used
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wide(page: CodePage, bytes: &[u8]) -> Vec<u16> {
        let mut out = Vec::new();
        to_wide(page, bytes, |u| out.push(u));
        out
    }

    fn narrow(page: CodePage, units: &[u16], default: u8) -> (Vec<u8>, bool) {
        let mut out = Vec::new();
        let used = to_narrow(page, units, default, |b| out.push(b));
        (out, used)
    }

    /// The runtime capture's conversions.
    #[test]
    fn the_captured_conversions() {
        assert_eq!(wide(CodePage::Utf8, b"\xC3\xA9\xE2\x82\xAC\0"), [0x00E9, 0x20AC, 0]);
        assert_eq!(wide(CodePage::Utf8, b"a\xC3(b\0"), [0x61, 0x28, 0x62, 0]);
        let w = [0x20AC, 0x0100, 0x4E2D, b'A' as u16, 0];
        assert_eq!(narrow(CodePage::Ansi, &w, b'?'), (vec![0x80, 0x41, 0x3F, 0x41, 0], true));
        assert_eq!(narrow(CodePage::Ansi, &w, b'#'), (vec![0x80, 0x41, 0x23, 0x41, 0], true));
        assert_eq!(narrow(CodePage::Oem, &w, b'?').0, [0x3F, 0x41, 0x3F, 0x41, 0]);
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
        assert!(is_valid(850) && !is_valid(12345));
        assert_eq!(cp_info(CP_UTF8).unwrap()[..5], [4, 0, 0, 0, b'?']);
        assert_eq!(cp_info(12345), None);
    }

    /// UTF-8: four-byte sequences make surrogate pairs and back; stray continuations vanish.
    #[test]
    fn utf8_surrogates_and_strays() {
        assert_eq!(wide(CodePage::Utf8, b"\xF0\x9F\x98\x80"), [0xD83D, 0xDE00]);
        assert_eq!(narrow(CodePage::Utf8, &[0xD83D, 0xDE00], b'?').0, b"\xF0\x9F\x98\x80");
        assert_eq!(wide(CodePage::Utf8, b"\x80a\xBF"), [0x61]);
    }
}
