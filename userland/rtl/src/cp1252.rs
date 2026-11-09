//! Codepage 1252 replay data and conversions.
//!
//! The CRT's locale services (kernel32's NLS calls) answer from this single-byte codepage's tables;
//! the kernel converts its narrow names through them too (the FAT directory's long names, the
//! process parameters' strings), as Windows 2000's kernel and ntdll both carry the code page
//! tables. The byte-to-Unicode
//! table is the shipped `c_1252` data: identity except 27 bytes in 0x80-0x9F. The reverse direction
//! is its own inverse (every entry maps back), so no second table is kept.

/// The codepage's default character for unmapped code points.
pub const DEFAULT_CHAR: u8 = b'?';

/// Byte-to-Unicode for all 256 bytes.
#[rustfmt::skip]
pub const MB_TO_WC: [u16; 256] = [
    0x0000, 0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0007,
    0x0008, 0x0009, 0x000A, 0x000B, 0x000C, 0x000D, 0x000E, 0x000F,
    0x0010, 0x0011, 0x0012, 0x0013, 0x0014, 0x0015, 0x0016, 0x0017,
    0x0018, 0x0019, 0x001A, 0x001B, 0x001C, 0x001D, 0x001E, 0x001F,
    0x0020, 0x0021, 0x0022, 0x0023, 0x0024, 0x0025, 0x0026, 0x0027,
    0x0028, 0x0029, 0x002A, 0x002B, 0x002C, 0x002D, 0x002E, 0x002F,
    0x0030, 0x0031, 0x0032, 0x0033, 0x0034, 0x0035, 0x0036, 0x0037,
    0x0038, 0x0039, 0x003A, 0x003B, 0x003C, 0x003D, 0x003E, 0x003F,
    0x0040, 0x0041, 0x0042, 0x0043, 0x0044, 0x0045, 0x0046, 0x0047,
    0x0048, 0x0049, 0x004A, 0x004B, 0x004C, 0x004D, 0x004E, 0x004F,
    0x0050, 0x0051, 0x0052, 0x0053, 0x0054, 0x0055, 0x0056, 0x0057,
    0x0058, 0x0059, 0x005A, 0x005B, 0x005C, 0x005D, 0x005E, 0x005F,
    0x0060, 0x0061, 0x0062, 0x0063, 0x0064, 0x0065, 0x0066, 0x0067,
    0x0068, 0x0069, 0x006A, 0x006B, 0x006C, 0x006D, 0x006E, 0x006F,
    0x0070, 0x0071, 0x0072, 0x0073, 0x0074, 0x0075, 0x0076, 0x0077,
    0x0078, 0x0079, 0x007A, 0x007B, 0x007C, 0x007D, 0x007E, 0x007F,
    0x20AC, 0x0081, 0x201A, 0x0192, 0x201E, 0x2026, 0x2020, 0x2021,
    0x02C6, 0x2030, 0x0160, 0x2039, 0x0152, 0x008D, 0x017D, 0x008F,
    0x0090, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014,
    0x02DC, 0x2122, 0x0161, 0x203A, 0x0153, 0x009D, 0x017E, 0x0178,
    0x00A0, 0x00A1, 0x00A2, 0x00A3, 0x00A4, 0x00A5, 0x00A6, 0x00A7,
    0x00A8, 0x00A9, 0x00AA, 0x00AB, 0x00AC, 0x00AD, 0x00AE, 0x00AF,
    0x00B0, 0x00B1, 0x00B2, 0x00B3, 0x00B4, 0x00B5, 0x00B6, 0x00B7,
    0x00B8, 0x00B9, 0x00BA, 0x00BB, 0x00BC, 0x00BD, 0x00BE, 0x00BF,
    0x00C0, 0x00C1, 0x00C2, 0x00C3, 0x00C4, 0x00C5, 0x00C6, 0x00C7,
    0x00C8, 0x00C9, 0x00CA, 0x00CB, 0x00CC, 0x00CD, 0x00CE, 0x00CF,
    0x00D0, 0x00D1, 0x00D2, 0x00D3, 0x00D4, 0x00D5, 0x00D6, 0x00D7,
    0x00D8, 0x00D9, 0x00DA, 0x00DB, 0x00DC, 0x00DD, 0x00DE, 0x00DF,
    0x00E0, 0x00E1, 0x00E2, 0x00E3, 0x00E4, 0x00E5, 0x00E6, 0x00E7,
    0x00E8, 0x00E9, 0x00EA, 0x00EB, 0x00EC, 0x00ED, 0x00EE, 0x00EF,
    0x00F0, 0x00F1, 0x00F2, 0x00F3, 0x00F4, 0x00F5, 0x00F6, 0x00F7,
    0x00F8, 0x00F9, 0x00FA, 0x00FB, 0x00FC, 0x00FD, 0x00FE, 0x00FF,
];

/// Unicode-to-byte: the inverse of [`MB_TO_WC`] (the table is injective). Unmapped code points map
/// to [`DEFAULT_CHAR`].
pub fn wc_to_mb(wide: u16) -> u8 {
    for (byte, &mapped) in MB_TO_WC.iter().enumerate() {
        if mapped == wide {
            return byte as u8;
        }
    }
    DEFAULT_CHAR
}

/// The C1_* character-type bits GetStringTypeW reports (CT_CTYPE1, dwInfoType 1).
pub const C1_UPPER: u16 = 0x0001;
pub const C1_LOWER: u16 = 0x0002;
pub const C1_DIGIT: u16 = 0x0004;
pub const C1_SPACE: u16 = 0x0008;
pub const C1_PUNCT: u16 = 0x0010;
pub const C1_CNTRL: u16 = 0x0020;
pub const C1_BLANK: u16 = 0x0040;
pub const C1_XDIGIT: u16 = 0x0080;
pub const C1_ALPHA: u16 = 0x0100;

/// Character-type flags for one wide character (CT_CTYPE1), as Windows 2000 classifies ASCII,
/// Latin-1 and the code page's other characters (pinned by the runtime capture's tables): digits
/// are hex digits too; of the controls only the tab and the space are blank; the no-break space is
/// a blank space; Latin-1's symbols are punctuation — its superscript digits digits as well, its
/// ordinal indicators no letters; ƒ is a lower-case letter that is punctuation too. Beyond the code
/// page, [`beyond_flags`] classifies the scripts the C runtime's capture covers.
pub fn c1_flags(wide: u16) -> u16 {
    match wide {
        0x00..=0x08 | 0x0E..=0x1F | 0x7F => C1_CNTRL,
        0x09 => C1_CNTRL | C1_SPACE | C1_BLANK,
        0x0A..=0x0D => C1_CNTRL | C1_SPACE,
        0x20 | 0xA0 => C1_SPACE | C1_BLANK,
        0x30..=0x39 => C1_DIGIT | C1_XDIGIT,
        0x41..=0x46 => C1_UPPER | C1_ALPHA | C1_XDIGIT,
        0x47..=0x5A => C1_UPPER | C1_ALPHA,
        0x61..=0x66 => C1_LOWER | C1_ALPHA | C1_XDIGIT,
        0x67..=0x7A => C1_LOWER | C1_ALPHA,
        // ASCII punctuation.
        0x21..=0x2F | 0x3A..=0x40 | 0x5B..=0x60 | 0x7B..=0x7E => C1_PUNCT,
        // Latin-1's superscript digits, then its other symbols.
        0xB2 | 0xB3 | 0xB9 => C1_PUNCT | C1_DIGIT,
        0xA1..=0xBF | 0xD7 | 0xF7 => C1_PUNCT,
        // The code page's other punctuation.
        0x2013
        | 0x2014
        | 0x2018..=0x201F
        | 0x2020..=0x2022
        | 0x2026
        | 0x2030
        | 0x2039
        | 0x203A
        | 0x20AC
        | 0x2122
        | 0x02C6
        | 0x02DC => C1_PUNCT,
        // Latin-1 letters with case.
        0xDF => C1_LOWER | C1_ALPHA,
        0xC0..=0xD6 | 0xD8..=0xDE => C1_UPPER | C1_ALPHA,
        0xE0..=0xF6 | 0xF8..=0xFE | 0xFF => C1_LOWER | C1_ALPHA,
        // The code page's own letters.
        0x152 | 0x160 | 0x178 | 0x17D => C1_UPPER | C1_ALPHA,
        0x153 | 0x161 | 0x17E => C1_LOWER | C1_ALPHA,
        0x192 => C1_LOWER | C1_ALPHA | C1_PUNCT,
        // Latin-1 control range.
        0x80..=0x9F => C1_CNTRL,
        _ => beyond_flags(wide),
    }
}

/// The CT_CTYPE1 flags of a character beyond the code page's: Latin Extended-A's, Greek's and
/// Cyrillic's letters with their case ([`beyond_case`] pairs them), the ideographs, kana and Hangul
/// syllables as letters without case, the other scripts' decimal digits (digits, not hex digits),
/// the Unicode spaces, the line and paragraph separators (punctuation and controls, not spaces:
/// the wide fixture's iswctype capture of U+2028), and the fullwidth forms of ASCII's digits,
/// letters (both hex digits where ASCII's are) and punctuation.
fn beyond_flags(wide: u16) -> u16 {
    const UPPER: u16 = C1_UPPER | C1_ALPHA;
    const LOWER: u16 = C1_LOWER | C1_ALPHA;
    match wide {
        0x0100..=0x017F => match beyond_case(wide, false) {
            lower if lower != wide => UPPER,
            _ if beyond_case(wide, true) != wide => LOWER,
            // ĸ, ŉ and ſ have no other case.
            _ => LOWER,
        },
        0x0386 | 0x0388..=0x038A | 0x038C | 0x038E..=0x038F | 0x0391..=0x03A1 | 0x03A3..=0x03AB => {
            UPPER
        }
        0x0390 | 0x03AC..=0x03CE => LOWER,
        0x0400..=0x042F => UPPER,
        0x0430..=0x045F => LOWER,
        0x0660..=0x0669
        | 0x06F0..=0x06F9
        | 0x0966..=0x096F
        | 0x09E6..=0x09EF
        | 0x0A66..=0x0A6F
        | 0x0AE6..=0x0AEF
        | 0x0B66..=0x0B6F
        | 0x0BE7..=0x0BEF
        | 0x0C66..=0x0C6F
        | 0x0CE6..=0x0CEF
        | 0x0D66..=0x0D6F
        | 0x0E50..=0x0E59
        | 0x0ED0..=0x0ED9
        | 0x0F20..=0x0F29 => C1_DIGIT,
        0x2000..=0x200B | 0x3000 | 0xFEFF => C1_SPACE | C1_BLANK,
        0x2028 | 0x2029 => C1_PUNCT | C1_CNTRL,
        0x3041..=0x3094 | 0x30A1..=0x30FA | 0x4E00..=0x9FA5 | 0xAC00..=0xD7A3 | 0xF900..=0xFA2D => {
            C1_ALPHA
        }
        0xFF10..=0xFF19 => C1_DIGIT | C1_XDIGIT,
        0xFF21..=0xFF26 => UPPER | C1_XDIGIT,
        0xFF27..=0xFF3A => UPPER,
        0xFF41..=0xFF46 => LOWER | C1_XDIGIT,
        0xFF47..=0xFF5A => LOWER,
        0xFF01..=0xFF0F | 0xFF1A..=0xFF20 | 0xFF3B..=0xFF40 | 0xFF5B..=0xFF5E => C1_PUNCT,
        _ => 0,
    }
}

/// The C2_* bidirectional classes GetStringTypeW reports (CT_CTYPE2, dwInfoType 2): one value per
/// character, not bits.
pub const C2_NOTAPPLICABLE: u16 = 0x0000;
pub const C2_LEFTTORIGHT: u16 = 0x0001;
pub const C2_RIGHTTOLEFT: u16 = 0x0002;
pub const C2_EUROPENUMBER: u16 = 0x0003;
pub const C2_EUROPESEPARATOR: u16 = 0x0004;
pub const C2_EUROPETERMINATOR: u16 = 0x0005;
pub const C2_ARABICNUMBER: u16 = 0x0006;
pub const C2_COMMONSEPARATOR: u16 = 0x0007;
pub const C2_BLOCKSEPARATOR: u16 = 0x0008;
pub const C2_SEGMENTSEPARATOR: u16 = 0x0009;
pub const C2_WHITESPACE: u16 = 0x000A;
pub const C2_OTHERNEUTRAL: u16 = 0x000B;

/// The C3_* extended character-type bits GetStringTypeW reports (CT_CTYPE3, dwInfoType 4).
pub const C3_NONSPACING: u16 = 0x0001;
pub const C3_DIACRITIC: u16 = 0x0002;
pub const C3_VOWELMARK: u16 = 0x0004;
pub const C3_SYMBOL: u16 = 0x0008;
pub const C3_KATAKANA: u16 = 0x0010;
pub const C3_HIRAGANA: u16 = 0x0020;
pub const C3_HALFWIDTH: u16 = 0x0040;
pub const C3_FULLWIDTH: u16 = 0x0080;
pub const C3_IDEOGRAPH: u16 = 0x0100;
pub const C3_KASHIDA: u16 = 0x0200;
pub const C3_LEXICAL: u16 = 0x0400;
pub const C3_ALPHA: u16 = 0x8000;

/// The bidirectional class of one wide character (CT_CTYPE2), over the characters [`c1_flags`]
/// classifies, by Unicode's bidirectional categories. Windows 2000's own, which the utility
/// fixture's capture pins: the full stop is a European separator (Unicode calls it a common
/// one), and the controls Unicode calls boundary neutrals, which have no C2 class, are not
/// applicable (U+0001, and the terminator). The fullwidth forms of ASCII's characters take their
/// ASCII counterparts' classes; the letters and the other scripts' digits are left-to-right.
pub fn c2_class(wide: u16) -> u16 {
    match wide {
        0x09 | 0x0B | 0x1F => C2_SEGMENTSEPARATOR,
        0x0A | 0x0D | 0x1C..=0x1E | 0x85 | 0x2029 => C2_BLOCKSEPARATOR,
        // The boundary neutrals: the other controls, the soft hyphen, the zero-width space and
        // the byte order mark.
        0x00..=0x08 | 0x0E..=0x1B | 0x7F..=0x84 | 0x86..=0x9F | 0xAD | 0x200B | 0xFEFF => {
            C2_NOTAPPLICABLE
        }
        0x0C | 0x20 | 0x2000..=0x200A | 0x2028 | 0x3000 => C2_WHITESPACE,
        0x30..=0x39 | 0xB2 | 0xB3 | 0xB9 | 0x06F0..=0x06F9 => C2_EUROPENUMBER,
        0x0660..=0x0669 => C2_ARABICNUMBER,
        0x2B | 0x2D | 0x2E => C2_EUROPESEPARATOR,
        0x23..=0x25 | 0xA2..=0xA5 | 0xB0 | 0xB1 | 0x2030 | 0x20AC => C2_EUROPETERMINATOR,
        0x2C | 0x2F | 0x3A | 0xA0 => C2_COMMONSEPARATOR,
        // Latin-1's ordinal indicators and micro sign: letters to Unicode, punctuation to C1.
        0xAA | 0xB5 | 0xBA => C2_LEFTTORIGHT,
        0xFF01..=0xFF5E => c2_class(wide - 0xFEE0),
        _ => match c1_flags(wide) {
            c1 if c1 & (C1_ALPHA | C1_DIGIT) != 0 => C2_LEFTTORIGHT,
            c1 if c1 & C1_PUNCT != 0 => C2_OTHERNEUTRAL,
            _ => C2_NOTAPPLICABLE,
        },
    }
}

/// The extended character-type flags of one wide character (CT_CTYPE3), over the characters
/// [`c1_flags`] classifies: its letters are alphabetic, its punctuation and spaces symbols; ASCII's
/// printable characters are halfwidth, the fullwidth forms and the ideographic space fullwidth;
/// kana are hiragana or katakana, the ideographs ideographs (and neither fullwidth). Windows 2000's
/// own, which the utility fixture's capture pins: a precomposed letter is a diacritic and
/// nonspacing besides (é, here every Latin, Greek and Cyrillic letter with a canonical
/// decomposition), the tab is a symbol, and U+0001 nothing.
pub fn c3_flags(wide: u16) -> u16 {
    let width = match wide {
        0x20..=0x7E => C3_HALFWIDTH,
        0x3000 | 0xFF01..=0xFF5E => C3_FULLWIDTH,
        _ => 0,
    };
    let kind = match wide {
        0x3041..=0x3094 => C3_ALPHA | C3_HIRAGANA,
        0x30A1..=0x30FA => C3_ALPHA | C3_KATAKANA,
        0x4E00..=0x9FA5 | 0xF900..=0xFA2D => C3_ALPHA | C3_IDEOGRAPH,
        _ if precomposed(wide) => C3_ALPHA | C3_DIACRITIC | C3_NONSPACING,
        _ => match c1_flags(wide) {
            c1 if c1 & C1_ALPHA != 0 => C3_ALPHA,
            c1 if c1 & (C1_PUNCT | C1_SPACE) != 0 => C3_SYMBOL,
            _ => 0,
        },
    };
    width | kind
}

/// Whether a letter has a canonical decomposition into a base letter and diacritics: Latin-1's
/// accented letters and ÿ; Latin Extended-A's but for the letters with a stroke or a bar, the
/// dotless i, ĸ, ŋ, the ligatures and the compatibility forms (Ŀ, ŉ, ſ); Greek's letters with
/// tonos or dialytika; Cyrillic's with a breve, a grave, an acute or a diaeresis.
fn precomposed(wide: u16) -> bool {
    match wide {
        0xC0..=0xC5 | 0xC7..=0xCF | 0xD1..=0xD6 | 0xD9..=0xDD => true,
        0xE0..=0xE5 | 0xE7..=0xEF | 0xF1..=0xF6 | 0xF9..=0xFD | 0xFF => true,
        0x110 | 0x111 | 0x126 | 0x127 | 0x131..=0x133 | 0x138 | 0x13F..=0x142 | 0x149..=0x14B => {
            false
        }
        0x152 | 0x153 | 0x166 | 0x167 | 0x17F => false,
        0x100..=0x17E => true,
        0x386 | 0x388..=0x38A | 0x38C | 0x38E..=0x390 | 0x3AA..=0x3B0 | 0x3CA..=0x3CE => true,
        0x400 | 0x401 | 0x403 | 0x407 | 0x40C..=0x40E | 0x419 => true,
        0x439 | 0x450 | 0x451 | 0x453 | 0x457 | 0x45C..=0x45E => true,
        _ => false,
    }
}

/// Case mapping for one wide character (the LCMapStringW core); `upper` selects LCMAP_UPPERCASE.
/// Quirk: sharp s has no single-character uppercase and maps to itself.
pub fn map_case(wide: u16, upper: bool) -> u16 {
    let mapped = match wide {
        0x61..=0x7A if upper => wide - 0x20,                // a-z -> A-Z
        0x41..=0x5A if !upper => wide + 0x20,               // A-Z -> a-z
        0xE0..=0xF6 | 0xF8..=0xFE if upper => wide - 0x20,  // à-þ -> À-Þ
        0xC0..=0xD6 | 0xD8..=0xDE if !upper => wide + 0x20, // À-Þ -> à-þ
        0xFF if upper => 0x178,                             // ÿ -> Ÿ
        0x178 if !upper => 0xFF,                            // Ÿ -> ÿ
        0x153 if upper => 0x152,                            // œ -> Œ
        0x152 if !upper => 0x153,
        0x161 if upper => 0x160, // š -> Š
        0x160 if !upper => 0x161,
        0x17E if upper => 0x17D, // ž -> Ž
        0x17D if !upper => 0x17E,
        _ => beyond_case(wide, upper),
    };
    mapped
}

/// The case mapping of a letter beyond the code page's (see [`beyond_flags`]): Latin Extended-A's
/// pairs (İ lowers to i, ı uppers to I; ĸ, ŉ and ſ stay), Greek's (final sigma uppers to Σ; the
/// accented capitals pair with their small letters), Cyrillic's, and the fullwidth Latin letters.
fn beyond_case(wide: u16, upper: bool) -> u16 {
    // Latin Extended-A alternates capital and small letter, the capital on an even code point but
    // for 0x139..=0x148 and 0x179..=0x17E.
    let alternating = |odd_capital: bool| {
        let capital = (wide & 1 == 1) == odd_capital;
        match (capital, upper) {
            (true, false) => wide + 1,
            (false, true) => wide - 1,
            _ => wide,
        }
    };
    match wide {
        0x130 if !upper => 0x69,
        0x131 if upper => 0x49,
        0x130 | 0x131 | 0x138 | 0x149 | 0x17F => wide,
        0x100..=0x137 | 0x14A..=0x177 => alternating(false),
        0x139..=0x148 | 0x179..=0x17E => alternating(true),
        0x386 if !upper => 0x3AC,
        0x3AC if upper => 0x386,
        0x388..=0x38A if !upper => wide + 0x25,
        0x3AD..=0x3AF if upper => wide - 0x25,
        0x38C if !upper => 0x3CC,
        0x3CC if upper => 0x38C,
        0x38E..=0x38F if !upper => wide + 0x3F,
        0x3CD..=0x3CE if upper => wide - 0x3F,
        0x3C2 if upper => 0x3A3,
        0x391..=0x3A1 | 0x3A3..=0x3AB if !upper => wide + 0x20,
        0x3B1..=0x3C1 | 0x3C3..=0x3CB if upper => wide - 0x20,
        0x400..=0x40F if !upper => wide + 0x50,
        0x450..=0x45F if upper => wide - 0x50,
        0x410..=0x42F if !upper => wide + 0x20,
        0x430..=0x44F if upper => wide - 0x20,
        0xFF21..=0xFF3A if !upper => wide + 0x20,
        0xFF41..=0xFF5A if upper => wide - 0x20,
        _ => wide,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The 27 divergent bytes, straight from the shipped c_1252 table: everything else is identity
    /// (asserted separately).
    const DIVERGENT: [(u8, u16); 27] = [
        (0x80, 0x20AC),
        (0x82, 0x201A),
        (0x83, 0x0192),
        (0x84, 0x201E),
        (0x85, 0x2026),
        (0x86, 0x2020),
        (0x87, 0x2021),
        (0x88, 0x02C6),
        (0x89, 0x2030),
        (0x8A, 0x0160),
        (0x8B, 0x2039),
        (0x8C, 0x0152),
        (0x8E, 0x017D),
        (0x91, 0x2018),
        (0x92, 0x2019),
        (0x93, 0x201C),
        (0x94, 0x201D),
        (0x95, 0x2022),
        (0x96, 0x2013),
        (0x97, 0x2014),
        (0x98, 0x02DC),
        (0x99, 0x2122),
        (0x9A, 0x0161),
        (0x9B, 0x203A),
        (0x9C, 0x0153),
        (0x9E, 0x017E),
        (0x9F, 0x0178),
    ];

    /// The byte table: the 27 divergences, identity elsewhere.
    #[test]
    fn mb_to_wc_matches_the_shipped_table() {
        for (byte, wide) in DIVERGENT {
            assert_eq!(MB_TO_WC[byte as usize], wide, "byte {byte:#04x}");
        }
        for byte in 0u16..256 {
            let expected = match DIVERGENT.iter().find(|&&(b, _)| b as u16 == byte) {
                Some(&(_, wide)) => wide,
                None => byte,
            };
            assert_eq!(MB_TO_WC[byte as usize], expected, "byte {byte:#04x}");
        }
        assert_eq!(MB_TO_WC[0xE9], 0x00E9);
        assert_eq!(MB_TO_WC[0xFF], 0x00FF);
    }

    /// The reverse direction: every entry maps back (injective); unmapped code points fall to the
    /// default char.
    #[test]
    fn wc_to_mb_inverts_the_table() {
        for byte in 0..256u16 {
            assert_eq!(wc_to_mb(MB_TO_WC[byte as usize]), byte as u8);
        }
        assert_eq!(wc_to_mb(0x2603), DEFAULT_CHAR);
        assert_eq!(wc_to_mb(0x03A9), DEFAULT_CHAR);
        assert_eq!(DEFAULT_CHAR, b'?');
    }

    /// Ctype samples: hex letters and digits carry XDIGIT, plain letters case, space SPACE.
    #[test]
    fn c1_flags_pin_the_documented_samples() {
        assert_eq!(c1_flags(b'A' as u16), C1_UPPER | C1_ALPHA | C1_XDIGIT);
        assert_eq!(c1_flags(b'Z' as u16), C1_UPPER | C1_ALPHA);
        assert_eq!(c1_flags(b'a' as u16), C1_LOWER | C1_ALPHA | C1_XDIGIT);
        assert_eq!(c1_flags(b'z' as u16), C1_LOWER | C1_ALPHA);
        assert_eq!(c1_flags(b'0' as u16), C1_DIGIT | C1_XDIGIT);
        assert_eq!(c1_flags(b' ' as u16), C1_SPACE | C1_BLANK);
        assert_eq!(c1_flags(b'F' as u16), C1_UPPER | C1_ALPHA | C1_XDIGIT);
        assert_eq!(c1_flags(b'f' as u16), C1_LOWER | C1_ALPHA | C1_XDIGIT);
        assert_eq!(c1_flags(b'.' as u16), C1_PUNCT);
        assert_eq!(c1_flags(0x09), C1_CNTRL | C1_SPACE | C1_BLANK);
        assert_eq!(c1_flags(0x00), C1_CNTRL);
        assert_eq!(c1_flags(0x7F), C1_CNTRL);
        // The accented range and the codepage specials carry case.
        assert_eq!(c1_flags(0xE9), C1_LOWER | C1_ALPHA);
        assert_eq!(c1_flags(0xC9), C1_UPPER | C1_ALPHA);
        assert_eq!(c1_flags(0x0160), C1_UPPER | C1_ALPHA);
        assert_eq!(c1_flags(0x0161), C1_LOWER | C1_ALPHA);
        assert_eq!(c1_flags(0x20AC), C1_PUNCT);
    }

    /// Case samples: both directions over ASCII, Latin-1 and the codepage specials; sharp s stays
    /// itself.
    #[test]
    fn case_mapping_pins_the_documented_samples() {
        assert_eq!(map_case(b'a' as u16, true), b'A' as u16);
        assert_eq!(map_case(b'A' as u16, true), b'A' as u16);
        assert_eq!(map_case(b'a' as u16, false), b'a' as u16);
        assert_eq!(map_case(b'Z' as u16, false), b'z' as u16);
        assert_eq!(map_case(0x00E9, true), 0x00C9);
        assert_eq!(map_case(0x00C9, false), 0x00E9);
        assert_eq!(map_case(0x00DF, true), 0x00DF);
        assert_eq!(map_case(0x00FF, true), 0x0178);
        assert_eq!(map_case(0x0178, false), 0x00FF);
        assert_eq!(map_case(0x0153, true), 0x0152);
        assert_eq!(map_case(0x20AC, true), 0x20AC);
    }

    /// Beyond the code page, msvcrt's capture of iswalpha, iswdigit, iswspace, iswxdigit, towlower
    /// and towupper over code points past U+00FF (GetStringTypeW and LCMapStringW behind them).
    #[test]
    fn the_scripts_beyond_the_code_page() {
        for (unit, flags, lower, upper) in [
            (0x0100, 0x101, 0x0101, 0x0100),
            (0x0101, 0x102, 0x0101, 0x0100),
            (0x0178, 0x101, 0x00FF, 0x0178),
            (0x0391, 0x101, 0x03B1, 0x0391),
            (0x03B1, 0x102, 0x03B1, 0x0391),
            (0x0416, 0x101, 0x0436, 0x0416),
            (0x0436, 0x102, 0x0436, 0x0416),
            (0x0660, 0x004, 0x0660, 0x0660),
            (0x0669, 0x004, 0x0669, 0x0669),
            (0x2000, 0x048, 0x2000, 0x2000),
            (0x2028, 0x030, 0x2028, 0x2028),
            (0x3000, 0x048, 0x3000, 0x3000),
            (0x4E00, 0x100, 0x4E00, 0x4E00),
            (0xFEFF, 0x048, 0xFEFF, 0xFEFF),
            (0xFF10, 0x084, 0xFF10, 0xFF10),
            (0xFF21, 0x181, 0xFF41, 0xFF21),
            (0xFF41, 0x182, 0xFF41, 0xFF21),
        ] {
            assert_eq!(c1_flags(unit), flags, "U+{unit:04X}");
            assert_eq!(map_case(unit, false), lower, "U+{unit:04X} lower");
            assert_eq!(map_case(unit, true), upper, "U+{unit:04X} upper");
        }
        // Latin Extended-A's pairs both ways, and its letters without a pair.
        assert_eq!(
            (map_case(0x139, false), map_case(0x13A, true)),
            (0x13A, 0x139)
        );
        assert_eq!(
            (map_case(0x17D, false), map_case(0x17E, true)),
            (0x17E, 0x17D)
        );
        assert_eq!(
            (map_case(0x130, false), map_case(0x131, true)),
            (0x69, 0x49)
        );
        assert_eq!((c1_flags(0x138), map_case(0x138, true)), (0x102, 0x138));
        assert_eq!(
            (map_case(0x3C2, true), map_case(0x386, false)),
            (0x3A3, 0x3AC)
        );
    }

    /// The utility fixture's capture: CT_CTYPE1, CT_CTYPE2 and CT_CTYPE3 of its fifteen characters
    /// (A z 0 9, the space, ! . and the tab, U+0001, é, Α, 中, the ideographic space, Ａ and the
    /// terminator).
    #[test]
    fn the_captured_ctype2_and_ctype3_words() {
        for (unit, c1, c2, c3) in [
            (0x0041, 0x0181, 0x0001, 0x8040),
            (0x007A, 0x0102, 0x0001, 0x8040),
            (0x0030, 0x0084, 0x0003, 0x0040),
            (0x0039, 0x0084, 0x0003, 0x0040),
            (0x0020, 0x0048, 0x000A, 0x0048),
            (0x0021, 0x0010, 0x000B, 0x0048),
            (0x002E, 0x0010, 0x0004, 0x0048),
            (0x0009, 0x0068, 0x0009, 0x0008),
            (0x0001, 0x0020, 0x0000, 0x0000),
            (0x00E9, 0x0102, 0x0001, 0x8003),
            (0x0391, 0x0101, 0x0001, 0x8000),
            (0x4E2D, 0x0100, 0x0001, 0x8100),
            (0x3000, 0x0048, 0x000A, 0x0088),
            (0xFF21, 0x0181, 0x0001, 0x8080),
            (0x0000, 0x0020, 0x0000, 0x0000),
        ] {
            assert_eq!(c1_flags(unit), c1, "U+{unit:04X} CT_CTYPE1");
            assert_eq!(c2_class(unit), c2, "U+{unit:04X} CT_CTYPE2");
            assert_eq!(c3_flags(unit), c3, "U+{unit:04X} CT_CTYPE3");
        }
    }

    /// Beyond the capture, the documented classes: the bidirectional categories of ASCII's
    /// separators and terminators, Latin-1's numbers and neutrals, the Arabic digits and the
    /// fullwidth forms; the extended types of the letters with and without diacritics, the kana,
    /// and the controls that are not spaces.
    #[test]
    fn the_documented_classes_beyond_the_capture() {
        for (unit, c2) in [
            (0x000A, C2_BLOCKSEPARATOR),
            (0x000B, C2_SEGMENTSEPARATOR),
            (0x000C, C2_WHITESPACE),
            (0x0023, C2_EUROPETERMINATOR),
            (0x002B, C2_EUROPESEPARATOR),
            (0x002C, C2_COMMONSEPARATOR),
            (0x002F, C2_COMMONSEPARATOR),
            (0x003A, C2_COMMONSEPARATOR),
            (0x007F, C2_NOTAPPLICABLE),
            (0x0085, C2_BLOCKSEPARATOR),
            (0x00A0, C2_COMMONSEPARATOR),
            (0x00A3, C2_EUROPETERMINATOR),
            (0x00AA, C2_LEFTTORIGHT),
            (0x00B2, C2_EUROPENUMBER),
            (0x00D7, C2_OTHERNEUTRAL),
            (0x0192, C2_LEFTTORIGHT),
            (0x0660, C2_ARABICNUMBER),
            (0x06F0, C2_EUROPENUMBER),
            (0x0966, C2_LEFTTORIGHT),
            (0x2014, C2_OTHERNEUTRAL),
            (0x2028, C2_WHITESPACE),
            (0x2029, C2_BLOCKSEPARATOR),
            (0x20AC, C2_EUROPETERMINATOR),
            (0xFEFF, C2_NOTAPPLICABLE),
            (0xFF0C, C2_COMMONSEPARATOR),
            (0xFF10, C2_EUROPENUMBER),
            (0xFF01, C2_OTHERNEUTRAL),
            (0x05D0, C2_NOTAPPLICABLE),
        ] {
            assert_eq!(c2_class(unit), c2, "U+{unit:04X}");
        }
        const LETTER: u16 = C3_ALPHA | C3_DIACRITIC | C3_NONSPACING;
        for (unit, c3) in [
            (0x000A, C3_SYMBOL),
            (0x001B, 0),
            (0x007E, C3_HALFWIDTH | C3_SYMBOL),
            (0x00A0, C3_SYMBOL),
            (0x00C6, C3_ALPHA),
            (0x00C9, LETTER),
            (0x00DF, C3_ALPHA),
            (0x00F8, C3_ALPHA),
            (0x00FF, LETTER),
            (0x0110, C3_ALPHA),
            (0x0141, C3_ALPHA),
            (0x0152, C3_ALPHA),
            (0x0160, LETTER),
            (0x017E, LETTER),
            (0x0386, LETTER),
            (0x03B1, C3_ALPHA),
            (0x03CA, LETTER),
            (0x0401, LETTER),
            (0x0416, C3_ALPHA),
            (0x0419, LETTER),
            (0x0660, 0),
            (0x20AC, C3_SYMBOL),
            (0x3042, C3_ALPHA | C3_HIRAGANA),
            (0x30A2, C3_ALPHA | C3_KATAKANA),
            (0xAC00, C3_ALPHA),
            (0xF900, C3_ALPHA | C3_IDEOGRAPH),
            (0xFF10, C3_FULLWIDTH),
            (0xFF01, C3_FULLWIDTH | C3_SYMBOL),
            (0xFF41, C3_ALPHA | C3_FULLWIDTH),
        ] {
            assert_eq!(c3_flags(unit), c3, "U+{unit:04X}");
        }
    }

    /// The runtime capture's CT_CTYPE1 tables: GetStringTypeA over every code page 1252 byte (each
    /// through its Unicode character), GetStringTypeW over U+0080..U+00FF.
    #[test]
    fn the_captured_ctype1_tables() {
        const ANSI: [u16; 256] = [
            0x0020, 0x0020, 0x0020, 0x0020, 0x0020, 0x0020, 0x0020, 0x0020, 0x0020, 0x0068, 0x0028,
            0x0028, 0x0028, 0x0028, 0x0020, 0x0020, 0x0020, 0x0020, 0x0020, 0x0020, 0x0020, 0x0020,
            0x0020, 0x0020, 0x0020, 0x0020, 0x0020, 0x0020, 0x0020, 0x0020, 0x0020, 0x0020, 0x0048,
            0x0010, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010,
            0x0010, 0x0010, 0x0010, 0x0010, 0x0084, 0x0084, 0x0084, 0x0084, 0x0084, 0x0084, 0x0084,
            0x0084, 0x0084, 0x0084, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010, 0x0181,
            0x0181, 0x0181, 0x0181, 0x0181, 0x0181, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101,
            0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101,
            0x0101, 0x0101, 0x0101, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010, 0x0182, 0x0182,
            0x0182, 0x0182, 0x0182, 0x0182, 0x0102, 0x0102, 0x0102, 0x0102, 0x0102, 0x0102, 0x0102,
            0x0102, 0x0102, 0x0102, 0x0102, 0x0102, 0x0102, 0x0102, 0x0102, 0x0102, 0x0102, 0x0102,
            0x0102, 0x0102, 0x0010, 0x0010, 0x0010, 0x0010, 0x0020, 0x0010, 0x0020, 0x0010, 0x0112,
            0x0010, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010, 0x0101, 0x0010, 0x0101, 0x0020, 0x0101,
            0x0020, 0x0020, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010,
            0x0102, 0x0010, 0x0102, 0x0020, 0x0102, 0x0101, 0x0048, 0x0010, 0x0010, 0x0010, 0x0010,
            0x0010, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010,
            0x0010, 0x0010, 0x0014, 0x0014, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010, 0x0014, 0x0010,
            0x0010, 0x0010, 0x0010, 0x0010, 0x0010, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101,
            0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101,
            0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0010, 0x0101, 0x0101, 0x0101, 0x0101,
            0x0101, 0x0101, 0x0101, 0x0102, 0x0102, 0x0102, 0x0102, 0x0102, 0x0102, 0x0102, 0x0102,
            0x0102, 0x0102, 0x0102, 0x0102, 0x0102, 0x0102, 0x0102, 0x0102, 0x0102, 0x0102, 0x0102,
            0x0102, 0x0102, 0x0102, 0x0102, 0x0102, 0x0010, 0x0102, 0x0102, 0x0102, 0x0102, 0x0102,
            0x0102, 0x0102, 0x0102,
        ];
        const WIDE: [u16; 128] = [
            0x0020, 0x0020, 0x0020, 0x0020, 0x0020, 0x0020, 0x0020, 0x0020, 0x0020, 0x0020, 0x0020,
            0x0020, 0x0020, 0x0020, 0x0020, 0x0020, 0x0020, 0x0020, 0x0020, 0x0020, 0x0020, 0x0020,
            0x0020, 0x0020, 0x0020, 0x0020, 0x0020, 0x0020, 0x0020, 0x0020, 0x0020, 0x0020, 0x0048,
            0x0010, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010,
            0x0010, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010, 0x0014, 0x0014, 0x0010, 0x0010, 0x0010,
            0x0010, 0x0010, 0x0014, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010, 0x0101, 0x0101,
            0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101,
            0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0010,
            0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0102, 0x0102, 0x0102, 0x0102,
            0x0102, 0x0102, 0x0102, 0x0102, 0x0102, 0x0102, 0x0102, 0x0102, 0x0102, 0x0102, 0x0102,
            0x0102, 0x0102, 0x0102, 0x0102, 0x0102, 0x0102, 0x0102, 0x0102, 0x0102, 0x0010, 0x0102,
            0x0102, 0x0102, 0x0102, 0x0102, 0x0102, 0x0102, 0x0102,
        ];
        let mut wrong = Vec::new();
        for (byte, &expected) in ANSI.iter().enumerate() {
            let unit = MB_TO_WC[byte];
            if c1_flags(unit) != expected {
                wrong.push(format!(
                    "byte {byte:#04x} (U+{unit:04X}): {:#06x}, captured {expected:#06x}",
                    c1_flags(unit)
                ));
            }
        }
        for (i, &expected) in WIDE.iter().enumerate() {
            let unit = 0x80 + i as u16;
            if c1_flags(unit) != expected {
                wrong.push(format!(
                    "U+{unit:04X}: {:#06x}, captured {expected:#06x}",
                    c1_flags(unit)
                ));
            }
        }
        assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    }
}
