//! The code pages' conversions past the ANSI and OEM pages' plain tables: UTF-8's ill-formed
//! sequences. The locale fixture's utf8err block is the contract.

use super::last_error;
use crate::locale::*;

const CP_UTF8: u32 = 65001;
const MB_PRECOMPOSED: u32 = 0x1;
const MB_ERR_INVALID_CHARS: u32 = 0x8;
const ERROR_NO_UNICODE_TRANSLATION: u32 = 1113;

/// MultiByteToWideChar(code page, flags) of `bytes` into 16 units: the count and the units, or 0
/// and the last error.
fn to_wide(code_page: u32, flags: u32, bytes: &[u8]) -> Result<Vec<u16>, u32> {
    let mut out = [0xBEEFu16; 16];
    let count = unsafe {
        multi_byte_to_wide_char(
            code_page,
            flags,
            bytes.as_ptr(),
            bytes.len() as i32,
            out.as_mut_ptr(),
            16,
        )
    };
    if count == 0 {
        return Err(last_error());
    }
    Ok(out[..count as usize].to_vec())
}

/// UTF-8 takes MB_ERR_INVALID_CHARS, and no other flag: an overlong sequence is
/// ERROR_NO_UNICODE_TRANSLATION with it or without, a stray continuation byte only with it, a
/// sequence a plain byte cuts short is dropped either way.
///
/// Pins: kernel32.MultiByteToWideChar
#[test]
fn utf8_refuses_what_it_cannot_decode() {
    assert_eq!(
        to_wide(CP_UTF8, MB_ERR_INVALID_CHARS, b"a\xC3\xA9"),
        Ok(vec![0x61, 0xE9])
    );
    assert_eq!(to_wide(CP_UTF8, MB_PRECOMPOSED, b"a"), Err(1004));
    for flags in [0, MB_ERR_INVALID_CHARS] {
        assert_eq!(
            to_wide(CP_UTF8, flags, b"\xC0\xAF"),
            Err(ERROR_NO_UNICODE_TRANSLATION)
        );
        assert_eq!(to_wide(CP_UTF8, flags, b"\xE2\x82x"), Ok(vec![0x78]));
    }
    assert_eq!(to_wide(CP_UTF8, 0, b"\x80x"), Ok(vec![0x78]));
    assert_eq!(
        to_wide(CP_UTF8, MB_ERR_INVALID_CHARS, b"\x80x"),
        Err(ERROR_NO_UNICODE_TRANSLATION)
    );
}
