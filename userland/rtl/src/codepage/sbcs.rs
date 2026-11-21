//! The single-byte code pages MultiByteToWideChar and WideCharToMultiByte convert through: 1252
//! (ANSI), 437 (OEM), 850 and 28591 (ISO 8859-1), each a high half over ASCII and a best-fit table
//! (`super::tables`, generated from Microsoft's and Windows 2000's own data). Only kernel32 uses
//! them: the kernel's conversions keep to [`super::encode_unit`]'s small best fit, a subset of
//! these tables (the host tests hold it to them), so the tables stay out of its image.

use super::tables::{CP850_HIGH, FIT_1252, FIT_28591, FIT_437, FIT_850};
use super::{CP437_GLYPHS, CP437_GLYPH_7F, CP437_HIGH};
use crate::cp1252::MB_TO_WC;

/// A page's best fit: the units it holds no byte for exactly but approximates, ascending, and the
/// byte each becomes.
pub struct BestFit {
    pub(super) units: &'static [u16],
    pub(super) bytes: &'static [u8],
}

impl BestFit {
    /// The byte `unit` best-fits to, if any.
    pub fn get(&self, unit: u16) -> Option<u8> {
        self.units
            .binary_search(&unit)
            .ok()
            .map(|at| self.bytes[at])
    }

    /// How many units the table approximates.
    pub fn len(&self) -> usize {
        self.units.len()
    }

    /// Whether the table approximates nothing.
    pub fn is_empty(&self) -> bool {
        self.units.is_empty()
    }
}

/// A single-byte code page.
pub struct SingleByte {
    /// Its number.
    pub number: u32,
    /// Its bytes 0x80-0xFF as UTF-16; none for Latin-1's own.
    high: Option<&'static [u16]>,
    /// Whether its control bytes have glyphs (MB_USEGLYPHCHARS): the OEM pages'.
    glyphs: bool,
    /// Its best fit.
    pub fit: &'static BestFit,
}

/// The ANSI code page, Windows-1252.
pub static CP1252: SingleByte = SingleByte {
    number: 1252,
    high: Some(MB_TO_WC.split_at(0x80).1),
    glyphs: false,
    fit: &FIT_1252,
};

/// The OEM code page, 437 (United States).
pub static CP437: SingleByte = SingleByte {
    number: 437,
    high: Some(&CP437_HIGH),
    glyphs: true,
    fit: &FIT_437,
};

/// Code page 850 (Multilingual Latin I, OEM).
pub static CP850: SingleByte = SingleByte {
    number: 850,
    high: Some(&CP850_HIGH),
    glyphs: true,
    fit: &FIT_850,
};

/// Code page 28591 (ISO 8859-1): every byte its own Latin-1 character.
pub static CP28591: SingleByte = SingleByte {
    number: 28591,
    high: None,
    glyphs: false,
    fit: &FIT_28591,
};

impl SingleByte {
    /// `byte` as UTF-16, a control byte as its glyph when `glyphs` asks (MB_USEGLYPHCHARS) and the
    /// page has one.
    pub fn decode(&self, byte: u8, glyphs: bool) -> u16 {
        match byte {
            0x00..=0x1F if glyphs && self.glyphs => CP437_GLYPHS[byte as usize],
            0x7F if glyphs && self.glyphs => CP437_GLYPH_7F,
            0x80.. => self
                .high
                .map_or(byte as u16, |high| high[byte as usize - 0x80]),
            _ => byte as u16,
        }
    }

    /// The byte the page holds `unit` as exactly, if any.
    pub fn exact(&self, unit: u16) -> Option<u8> {
        match (unit, self.high) {
            (0x00..=0x7F, _) => Some(unit as u8),
            (_, Some(high)) => high
                .iter()
                .position(|&u| u == unit)
                .map(|at| 0x80 + at as u8),
            (0x80..=0xFF, None) => Some(unit as u8),
            _ => None,
        }
    }

    /// `unit`'s byte: exactly, else best-fit when `fit` allows it (not WC_NO_BEST_FIT_CHARS), else
    /// none (the default character's place).
    pub fn encode(&self, unit: u16, fit: bool) -> Option<u8> {
        self.exact(unit)
            .or_else(|| self.fit.get(unit).filter(|_| fit))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codepage::{decode_byte, encode_unit, CodePage};

    const PAGES: [&SingleByte; 4] = [&CP1252, &CP437, &CP850, &CP28591];

    /// Every page round-trips its 256 bytes; no best fit names a unit the page holds exactly, and
    /// the tables are sorted.
    #[test]
    fn the_pages_round_trip() {
        for page in PAGES {
            for byte in 0..=255u8 {
                let unit = page.decode(byte, false);
                assert_eq!(page.exact(unit), Some(byte), "{} {byte:#04x}", page.number);
            }
            assert!(page.fit.units.windows(2).all(|pair| pair[0] < pair[1]));
            assert_eq!(page.fit.units.len(), page.fit.bytes.len());
            for &unit in page.fit.units {
                assert_eq!(page.exact(unit), None, "{} {unit:#06x}", page.number);
            }
        }
        assert_eq!(CP850.decode(0x9B, false), 0x00F8);
        assert_eq!(CP28591.decode(0x80, false), 0x0080);
        assert_eq!(CP850.decode(0x01, true), 0x263A, "850 has 437's glyphs");
        assert_eq!(CP1252.decode(0x01, true), 0x01);
    }

    /// The kernel's small best fit ([`encode_unit`]) answers as these tables do wherever it
    /// answers, and its pages decode as these do.
    #[test]
    fn the_kernel_s_best_fit_is_a_subset() {
        for (core, page) in [(CodePage::Ansi, &CP1252), (CodePage::Oem, &CP437)] {
            for byte in 0..=255u8 {
                assert_eq!(decode_byte(core, byte), page.decode(byte, false));
            }
            for unit in 0..=0xFFFFu16 {
                if let Some(byte) = encode_unit(core, unit, true) {
                    assert_eq!(page.encode(unit, true), Some(byte), "{unit:#06x}");
                }
            }
        }
    }

    /// The locale fixture's samples: the cpconv and bestfit blocks' units.
    #[test]
    fn the_captured_best_fits() {
        let cases: &[(&SingleByte, u16, Option<u8>)] = &[
            (&CP850, 0x00E9, Some(0x82)),
            (&CP850, 0x2591, Some(0xB0)),
            (&CP850, 0x00FF, Some(0x98)),
            (&CP850, 0x20AC, None),
            (&CP850, 0x0100, Some(b'A')),
            (&CP28591, 0x0100, Some(b'A')),
            (&CP28591, 0x20AC, None),
            (&CP1252, 0x0131, Some(b'i')),
            (&CP1252, 0x0141, Some(b'L')),
            (&CP1252, 0x0391, None),
            (&CP1252, 0x03B1, Some(b'a')),
            (&CP1252, 0x2002, Some(b' ')),
            (&CP1252, 0x2215, Some(b'/')),
            (&CP1252, 0x221E, Some(b'8')),
            (&CP1252, 0x2260, None),
            (&CP1252, 0xFF21, Some(b'A')),
            (&CP1252, 0x4E2D, None),
            (&CP1252, 0x0301, Some(0xB4)),
            (&CP437, 0x00C0, Some(b'A')),
            (&CP437, 0x00A9, Some(b'c')),
            (&CP437, 0x2122, Some(b'T')),
        ];
        for &(page, unit, byte) in cases {
            assert_eq!(page.encode(unit, true), byte, "{} {unit:#06x}", page.number);
            let exact = page.exact(unit);
            assert_eq!(
                page.encode(unit, false),
                exact,
                "{} {unit:#06x}",
                page.number
            );
        }
    }
}
