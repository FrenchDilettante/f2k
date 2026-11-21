//! UTF-7 (RFC 2152), as Windows 2000's code page 65000 converts it.
//!
//! Encoding writes directly only what Windows does — NUL, tab, line feed, carriage return, space,
//! the letters and digits and `'(),-./:?` — and `+` as `+-` where a run does not take it in; any
//! run of other units goes in base64 between `+` and a `-` Windows always writes, even where the
//! next character would end the run.
//! Decoding reads a base64 run after `+` until a `-` (dropped) or any byte not in base64 (decoded
//! on its own), a unit's bits left over at its end discarded; `+-` is `+`, and a `+` before a byte
//! not in base64 is dropped. A byte past 0x7F is its own Latin-1 character, and inside a run it
//! ends the run without discarding the bits left over (Windows' quirk).

/// The base64 alphabet.
const BASE64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// A base64 character's six bits.
fn sextet(byte: u8) -> Option<u32> {
    Some(match byte {
        b'A'..=b'Z' => byte - b'A',
        b'a'..=b'z' => byte - b'a' + 26,
        b'0'..=b'9' => byte - b'0' + 52,
        b'+' => 62,
        b'/' => 63,
        _ => return None,
    } as u32)
}

/// Whether Windows writes `unit` as itself.
fn direct(unit: u16) -> bool {
    matches!(unit,
        0x00 | 0x09 | 0x0A | 0x0D | 0x20 | 0x27..=0x29 | 0x2C..=0x3A | 0x3F
        | 0x41..=0x5A | 0x61..=0x7A)
}

/// UTF-7 to UTF-16, into `out`.
pub fn decode(bytes: &[u8], mut out: impl FnMut(u16)) {
    // The bits read and not yet a unit, and how many.
    let (mut bits, mut count) = (0u32, 0u32);
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'+' {
            out(bytes[i] as u16);
            i += 1;
            continue;
        }
        i += 1;
        if bytes.get(i) == Some(&b'-') {
            out(b'+' as u16);
            i += 1;
            continue;
        }
        while let Some(&byte) = bytes.get(i) {
            if byte == b'-' {
                i += 1;
                (bits, count) = (0, 0);
                break;
            }
            if byte >= 0x80 {
                break; // Windows keeps the unfinished unit's bits
            }
            let Some(six) = sextet(byte) else {
                (bits, count) = (0, 0);
                break;
            };
            bits = (bits << 6 | six) & 0x3F_FFFF;
            count += 6;
            if count >= 16 {
                count -= 16;
                out((bits >> count) as u16);
            }
            i += 1;
        }
    }
}

/// UTF-16 to UTF-7, into `out`.
pub fn encode(units: &[u16], mut out: impl FnMut(u8)) {
    let mut i = 0;
    while i < units.len() {
        let unit = units[i];
        if unit == b'+' as u16 {
            out(b'+');
            out(b'-');
            i += 1;
            continue;
        }
        if direct(unit) {
            out(unit as u8);
            i += 1;
            continue;
        }
        out(b'+');
        let (mut bits, mut count) = (0u32, 0u32);
        while i < units.len() && !direct(units[i]) {
            bits = (bits << 16 | units[i] as u32) & 0xFF_FFFF;
            count += 16;
            while count >= 6 {
                count -= 6;
                out(BASE64[(bits >> count) as usize & 0x3F]);
            }
            i += 1;
        }
        if count > 0 {
            out(BASE64[(bits << (6 - count)) as usize & 0x3F]);
        }
        out(b'-');
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wide(bytes: &[u8]) -> Vec<u16> {
        let mut out = Vec::new();
        decode(bytes, |u| out.push(u));
        out
    }

    fn narrow(units: &[u16]) -> Vec<u8> {
        let mut out = Vec::new();
        encode(units, |b| out.push(b));
        out
    }

    /// The locale fixture's cpconv block's conversions.
    #[test]
    fn the_captured_conversions() {
        assert_eq!(wide(b"+AGE-\0"), [0x61, 0]);
        assert_eq!(wide(b"Hi +Jjo-!\0"), [0x48, 0x69, 0x20, 0x263A, 0x21, 0]);
        assert_eq!(wide(b"+ZeVnLIqe-\0"), [0x65E5, 0x672C, 0x8A9E, 0]);
        assert_eq!(wide(b"A+ImIDkQ.\0"), [0x41, 0x2262, 0x0391, 0x2E, 0]);
        assert_eq!(wide(b"1+-2\0"), [0x31, 0x2B, 0x32, 0]);
        assert_eq!(wide(b"+AGE\0"), [0x61, 0]);
        assert_eq!(wide(b"+!x\0"), [0x21, 0x78, 0]);
        assert_eq!(wide(b"\xE9"), [0xE9]);
        let smile = [0x48, 0x69, 0x20, 0x263A, 0x21, 0];
        assert_eq!(narrow(&smile), b"Hi +JjoAIQ-\0");
        let direct = [0x61, 0x2B, 0x62, 0x7E, 0x5C, 0x2D, 0];
        assert_eq!(narrow(&direct), b"a+-b+AH4AXA--\0");
        assert_eq!(narrow(&[0x65E5, 0x672C, 0x8A9E]), b"+ZeVnLIqe-");
    }

    /// Whatever the encoder writes decodes back.
    #[test]
    fn round_trips() {
        let units: Vec<u16> = (0..0x300).chain([0xD800, 0xDC00, 0xFFFF, 0x20AC]).collect();
        assert_eq!(wide(&narrow(&units)), units);
    }
}
