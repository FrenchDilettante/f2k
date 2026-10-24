//! An image's execution options, as LdrQueryImageFileExecutionOptions reads them from the registry:
//! the values of the key named after the image's file name under Image File Execution Options
//! ([`key_name`]), handed back in the form the caller asks for ([`convert`]: a REG_SZ value read
//! as a REG_DWORD is its text's number, as RtlUnicodeStringToInteger reads it with base 0).

use crate::status::{STATUS_BUFFER_OVERFLOW, STATUS_SUCCESS};

/// The key the options live under, the image's file name its subkey.
pub const OPTIONS_KEY: &str =
    "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\";

/// The registry value types the conversion tells apart.
pub const REG_SZ: u32 = 1;
pub const REG_DWORD: u32 = 4;

const BACKSLASH: u16 = b'\\' as u16;

/// The options key's name for the image at path `image` (a path or a bare file name) into `out`:
/// [`OPTIONS_KEY`] and the image's file name, its last component; the units written, none when
/// `out` has no room.
pub fn key_name(image: &[u16], out: &mut [u16]) -> Option<usize> {
    let file_name = image
        .iter()
        .rposition(|&unit| unit == BACKSLASH)
        .map_or(image, |at| &image[at + 1..]);
    let length = OPTIONS_KEY.len() + file_name.len();
    let out = out.get_mut(..length)?;
    for (unit, byte) in out.iter_mut().zip(OPTIONS_KEY.bytes()) {
        *unit = byte as u16;
    }
    out[OPTIONS_KEY.len()..].copy_from_slice(file_name);
    Some(length)
}

/// The number a text spells, as RtlUnicodeStringToInteger reads it with base 0: blanks skipped, a
/// sign, then `0x` (hexadecimal), `0o` (octal) or `0b` (binary), decimal otherwise; the digits up
/// to the first that is not one (or the text's NUL), wrapping around.
pub fn text_number(text: &[u16]) -> u32 {
    let text = &text[..text
        .iter()
        .position(|&unit| unit == 0)
        .unwrap_or(text.len())];
    let mut at = text.iter().take_while(|&&unit| unit <= b' ' as u16).count();
    let negative = text.get(at) == Some(&(b'-' as u16));
    if negative || text.get(at) == Some(&(b'+' as u16)) {
        at += 1;
    }
    let prefix = (text.get(at), text.get(at + 1).map(|&unit| unit | 0x20));
    let base = match prefix {
        (Some(0x30), Some(0x78)) => 16,
        (Some(0x30), Some(0x6F)) => 8,
        (Some(0x30), Some(0x62)) => 2,
        _ => 10,
    };
    if base != 10 {
        at += 2;
    }
    let value = text[at..]
        .iter()
        .map_while(|&unit| char::from_u32(unit.into())?.to_digit(base))
        .fold(0u32, |value, digit| {
            value.wrapping_mul(base).wrapping_add(digit)
        });
    if negative {
        value.wrapping_neg()
    } else {
        value
    }
}

/// The units a REG_SZ value's number is read from: more than a dword's digits and the blanks
/// before them (a longer text's number is its first units').
const NUMBER_ROOM: usize = 64;

/// A value's data in the form the caller asks for: a REG_SZ value asked for as a REG_DWORD is its
/// text's number ([`text_number`]), any other value its data as stored. Into `out` when it fits:
/// the status (STATUS_BUFFER_OVERFLOW, `out` untouched, when it does not) and the bytes the answer
/// takes.
pub fn convert(wanted: u32, stored: u32, data: &[u8], out: &mut [u8]) -> (u32, usize) {
    let number;
    let answer = if wanted == REG_DWORD && stored == REG_SZ {
        let mut units = [0u16; NUMBER_ROOM];
        for (unit, &pair) in units.iter_mut().zip(data.as_chunks::<2>().0) {
            *unit = u16::from_le_bytes(pair);
        }
        number = text_number(&units).to_le_bytes();
        &number[..]
    } else {
        data
    };
    match out.get_mut(..answer.len()) {
        Some(out) => {
            out.copy_from_slice(answer);
            (STATUS_SUCCESS, answer.len())
        }
        None => (STATUS_BUFFER_OVERFLOW, answer.len()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().collect()
    }

    /// The key is the options key and the image's file name, whatever path it came with.
    #[test]
    fn the_key_is_named_after_the_file_name() {
        let mut out = [0u16; 256];
        for image in [
            "\\??\\C:\\CORPUS\\spawnkid.exe",
            "C:\\CORPUS\\spawnkid.exe",
            "spawnkid.exe",
        ] {
            let length = key_name(&wide(image), &mut out).unwrap();
            assert_eq!(
                String::from_utf16(&out[..length]).unwrap(),
                format!("{OPTIONS_KEY}spawnkid.exe"),
                "{image}"
            );
        }
        let mut short = [0u16; 40];
        assert_eq!(key_name(&wide("a.exe"), &mut short), None);
    }

    /// Text reads as RtlUnicodeStringToInteger's base 0 reads it.
    #[test]
    fn text_reads_as_a_number() {
        for (text, value) in [
            ("2", 2u32),
            ("  42", 42),
            ("0x10", 16),
            ("0X1f", 31),
            ("0o17", 15),
            ("0b101", 5),
            ("-1", u32::MAX),
            ("+7", 7),
            ("12ab", 12),
            ("0x", 0),
            ("", 0),
            ("abc", 0),
            ("4294967297", 1),
            ("5\0 6", 5),
        ] {
            assert_eq!(text_number(&wide(text)), value, "{text:?}");
        }
    }

    /// A REG_SZ asked for as a REG_DWORD is its number; anything else is copied as stored; a
    /// buffer too small is STATUS_BUFFER_OVERFLOW with the length the answer needs.
    #[test]
    fn values_convert_as_asked() {
        let text: Vec<u8> = wide("0x200\0")
            .iter()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        let mut out = [0xEEu8; 16];
        assert_eq!(
            convert(REG_DWORD, REG_SZ, &text, &mut out),
            (STATUS_SUCCESS, 4)
        );
        assert_eq!(out[..5], [0, 2, 0, 0, 0xEE]);
        let mut out = [0xEEu8; 16];
        assert_eq!(
            convert(REG_SZ, REG_SZ, &text, &mut out),
            (STATUS_SUCCESS, 12)
        );
        assert_eq!(out[..12], text[..]);
        assert_eq!(
            convert(REG_DWORD, REG_DWORD, &[1, 0, 0, 0], &mut out),
            (STATUS_SUCCESS, 4)
        );
        let mut small = [0xEEu8; 4];
        assert_eq!(
            convert(REG_SZ, REG_SZ, &text, &mut small),
            (STATUS_BUFFER_OVERFLOW, 12)
        );
        assert_eq!(small, [0xEE; 4], "untouched");
    }
}
