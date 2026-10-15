//! Codepage 437, the console's output codepage and the VGA font's character set.
//!
//! The console uses it twice: bytes written to a console handle are in the output codepage and
//! become UTF-16 cells, and the VGA text renderer turns cells back into font glyphs (the adapter's
//! built-in font is laid out in this codepage). The low half is the identity — control codes
//! included, so a cell holding U+0001 shows the font's glyph 0x01 — and the high half is the
//! codepage's published mapping.
//!
//! Quirk: this is the standard mapping, not a capture from a real machine; the kernel32 locale
//! surface (MultiByteToWideChar and friends) does not use it.

/// The high half (0x80-0xFF), in byte order.
#[rustfmt::skip]
const HIGH: [u16; 128] = [
    0x00C7, 0x00FC, 0x00E9, 0x00E2, 0x00E4, 0x00E0, 0x00E5, 0x00E7, // 0x80
    0x00EA, 0x00EB, 0x00E8, 0x00EF, 0x00EE, 0x00EC, 0x00C4, 0x00C5, // 0x88
    0x00C9, 0x00E6, 0x00C6, 0x00F4, 0x00F6, 0x00F2, 0x00FB, 0x00F9, // 0x90
    0x00FF, 0x00D6, 0x00DC, 0x00A2, 0x00A3, 0x00A5, 0x20A7, 0x0192, // 0x98
    0x00E1, 0x00ED, 0x00F3, 0x00FA, 0x00F1, 0x00D1, 0x00AA, 0x00BA, // 0xA0
    0x00BF, 0x2310, 0x00AC, 0x00BD, 0x00BC, 0x00A1, 0x00AB, 0x00BB, // 0xA8
    0x2591, 0x2592, 0x2593, 0x2502, 0x2524, 0x2561, 0x2562, 0x2556, // 0xB0
    0x2555, 0x2563, 0x2551, 0x2557, 0x255D, 0x255C, 0x255B, 0x2510, // 0xB8
    0x2514, 0x2534, 0x252C, 0x251C, 0x2500, 0x253C, 0x255E, 0x255F, // 0xC0
    0x255A, 0x2554, 0x2569, 0x2566, 0x2560, 0x2550, 0x256C, 0x2567, // 0xC8
    0x2568, 0x2564, 0x2565, 0x2559, 0x2558, 0x2552, 0x2553, 0x256B, // 0xD0
    0x256A, 0x2518, 0x250C, 0x2588, 0x2584, 0x258C, 0x2590, 0x2580, // 0xD8
    0x03B1, 0x00DF, 0x0393, 0x03C0, 0x03A3, 0x03C3, 0x00B5, 0x03C4, // 0xE0
    0x03A6, 0x0398, 0x03A9, 0x03B4, 0x221E, 0x03C6, 0x03B5, 0x2229, // 0xE8
    0x2261, 0x00B1, 0x2265, 0x2264, 0x2320, 0x2321, 0x00F7, 0x2248, // 0xF0
    0x00B0, 0x2219, 0x00B7, 0x221A, 0x207F, 0x00B2, 0x25A0, 0x00A0, // 0xF8
];

/// The glyph a character has no place for in the font: the question mark.
pub const NO_GLYPH: u8 = b'?';

/// A byte of the codepage as a UTF-16 unit.
pub fn to_unicode(byte: u8) -> u16 {
    if byte < 0x80 {
        byte as u16
    } else {
        HIGH[byte as usize - 0x80]
    }
}

/// The font glyph for a UTF-16 unit: its byte in the codepage, or [`NO_GLYPH`] when the codepage
/// has none.
pub fn glyph(unit: u16) -> u8 {
    if unit < 0x80 {
        return unit as u8;
    }
    HIGH.iter()
        .position(|&mapped| mapped == unit)
        .map_or(NO_GLYPH, |index| 0x80 + index as u8)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_low_half_is_the_identity() {
        for byte in 0..0x80u8 {
            assert_eq!(to_unicode(byte), byte as u16);
            assert_eq!(glyph(byte as u16), byte);
        }
    }

    #[test]
    fn landmark_bytes_map() {
        assert_eq!(to_unicode(0x80), 0x00C7); // Ç
        assert_eq!(to_unicode(0x82), 0x00E9); // é
        assert_eq!(to_unicode(0xB3), 0x2502); // │
        assert_eq!(to_unicode(0xC4), 0x2500); // ─
        assert_eq!(to_unicode(0xDB), 0x2588); // █
        assert_eq!(to_unicode(0xE1), 0x00DF); // ß
        assert_eq!(to_unicode(0xFF), 0x00A0); // no-break space
    }

    #[test]
    fn the_high_half_round_trips() {
        for byte in 0x80..=0xFFu8 {
            assert_eq!(glyph(to_unicode(byte)), byte, "{byte:#04x}");
        }
    }

    #[test]
    fn the_high_half_is_a_permutation() {
        for (i, a) in HIGH.iter().enumerate() {
            assert!(*a >= 0x80, "{i}");
            for b in &HIGH[i + 1..] {
                assert_ne!(a, b);
            }
        }
    }

    #[test]
    fn characters_outside_the_codepage_have_no_glyph() {
        assert_eq!(glyph(0x20AC), NO_GLYPH); // €
        assert_eq!(glyph(0x4E2D), NO_GLYPH);
    }
}
