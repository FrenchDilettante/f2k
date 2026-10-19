//! Paths: root-relative, backslash-separated components, each `.`, `..`, or a name — a long name
//! or an 8.3 one, matched against both of an entry's names (see [`super::dir`]).
//!
//! Paths are bytes, the way Win32 hands them over (codepage 1252). The empty path, an empty
//! component, a component longer than a long name may be, and one carrying a byte no file name may
//! hold are malformed input. A name's 8.3 stored form (uppercase, space-padded) is what the short
//! names compare against: [`short_form`].
//!
//! Short names are stored in the OEM code page, 437, as Windows 2000 stores them: a name's byte is
//! decoded from 1252, upper-cased through Unicode, and stored as its 437 byte ([`oem_upper`]); a
//! listing shows a stored byte in 1252 again ([`oem_to_ansi`]).

use rtl::codepage::{decode_byte, encode_unit, CodePage};
use rtl::cp1252::{map_case, MB_TO_WC};

use super::dirent::stored_name;

/// The separator.
pub const SEPARATOR: u8 = b'\\';

/// The longest long name, in units.
pub const MAX_NAME: usize = 255;

/// One component.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Component<'a> {
    /// `.`: the current directory.
    Current,
    /// `..`: the parent directory (the root's parent is the root).
    Parent,
    /// A name, as given.
    Name(&'a [u8]),
}

/// The bytes a short name may not contain (beyond the controls, space, and DEL); the dot only
/// separates the extension.
const FORBIDDEN: &[u8] = b"\"*+,./:;<=>?[\\]|";

/// The bytes no name may contain (beyond the controls).
const FORBIDDEN_LONG: &[u8] = b"\"*/:<>?\\|";

fn is_name_byte(byte: u8) -> bool {
    byte > b' ' && byte != 0x7F && !FORBIDDEN.contains(&byte)
}

/// A code page 1252 byte's upper case as the code page 437 byte that holds it exactly, if any.
pub fn oem_upper(byte: u8) -> Option<u8> {
    if byte.is_ascii() {
        return Some(byte.to_ascii_uppercase());
    }
    let unit = map_case(MB_TO_WC[byte as usize], true);
    encode_unit(CodePage::Oem, unit, true).filter(|&oem| decode_byte(CodePage::Oem, oem) == unit)
}

/// A code page 1252 byte's upper case in code page 437 the way an alias takes it: exactly, or by
/// best fit (a Latin letter's base letter); none when 437 has nothing for it.
pub fn oem_upper_fit(byte: u8) -> Option<u8> {
    if byte.is_ascii() {
        return Some(byte.to_ascii_uppercase());
    }
    encode_unit(CodePage::Oem, map_case(MB_TO_WC[byte as usize], true), true)
}

/// A stored code page 437 byte in code page 1252: exactly, by best fit, or `?`.
pub fn oem_to_ansi(byte: u8) -> u8 {
    if byte.is_ascii() {
        return byte;
    }
    encode_unit(CodePage::Ansi, decode_byte(CodePage::Oem, byte), true).unwrap_or(rtl::cp1252::DEFAULT_CHAR)
}

/// The 8.3 stored form of a name, or none when it is not a plain 8.3 name: 1-8 name bytes, then
/// optionally a dot and 1-3 extension bytes, each one code page 437 holds. The bytes are stored
/// upper-cased in 437 ([`oem_upper`]).
pub fn short_form(component: &[u8]) -> Option<[u8; 11]> {
    let (base, extension) = match component.iter().position(|&byte| byte == b'.') {
        Some(dot) => (&component[..dot], &component[dot + 1..]),
        None => (component, &[][..]),
    };
    let has_dot = base.len() < component.len();
    let base_ok = (1..=8).contains(&base.len()) && base.iter().all(|&byte| is_name_byte(byte));
    let extension_ok = if has_dot {
        (1..=3).contains(&extension.len()) && extension.iter().all(|&byte| is_name_byte(byte))
    } else {
        true
    };
    if !base_ok || !extension_ok {
        return None;
    }
    let mut name = stored_name(base, extension);
    for byte in name.iter_mut() {
        *byte = oem_upper(*byte)?;
    }
    Some(name)
}

/// One component's kind, or none when it is malformed.
fn component(part: &[u8]) -> Option<Component<'_>> {
    match part {
        b"." => Some(Component::Current),
        b".." => Some(Component::Parent),
        _ if part.is_empty() || part.len() > MAX_NAME => None,
        _ if part.iter().any(|&byte| byte < b' ' || FORBIDDEN_LONG.contains(&byte)) => None,
        _ => Some(Component::Name(part)),
    }
}

/// Whether `path` is well formed: non-empty, and every component is `.`, `..` or a name.
pub fn is_valid(path: &[u8]) -> bool {
    !path.is_empty()
        && path
            .split(|&byte| byte == SEPARATOR)
            .all(|part| component(part).is_some())
}

/// The components of a well-formed path (see [`is_valid`]), in order.
pub fn components(path: &[u8]) -> impl Iterator<Item = Component<'_>> + '_ {
    assert!(
        is_valid(path),
        "a malformed path is refused before it is walked"
    );
    path.split(|&byte| byte == SEPARATOR)
        .map(|part| component(part).unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Lowercase and mixed case fold to the stored uppercase, space-padded.
    #[test]
    fn names_fold_to_the_stored_form() {
        assert_eq!(short_form(b"HELLO.EXE"), Some(*b"HELLO   EXE"));
        assert_eq!(short_form(b"hello.exe"), Some(*b"HELLO   EXE"));
        assert_eq!(short_form(b"HeLlO.eXe"), Some(*b"HELLO   EXE"));
        assert_eq!(short_form(b"boot"), Some(*b"BOOT       "));
        assert_eq!(short_form(b"F2K-KE~1"), Some(*b"F2K-KE~1   "));
        assert_eq!(short_form(b"A.B"), Some(*b"A       B  "));
        assert_eq!(short_form(b"12345678.123"), Some(*b"12345678123"));
    }

    /// Short names are stored in the OEM code page, 437: a code page 1252 byte is decoded,
    /// upper-cased through Unicode and stored as its 437 byte; a name holding a character 437 lacks
    /// has no short form (it takes a long name and an alias).
    #[test]
    fn short_forms_are_in_code_page_437() {
        assert_eq!(short_form(b"caf\xE9.txt"), Some(*b"CAF\x90    TXT"), "\u{e9} is \u{c9}, 0x90");
        assert_eq!(short_form(b"\xE5NAME.TXT"), Some(*b"\x8FNAME   TXT"), "\u{e5} is \u{c5}, 0x8F");
        assert_eq!(short_form(b"\xC4.\xFC"), Some(*b"\x8E       \x9A  "), "\u{c4} 0x8E, \u{dc} 0x9A");
        assert_eq!(short_form(b"\x80URO.TXT"), None, "the euro sign");
        assert_eq!(short_form(b"\xD7.TXT"), None, "the multiplication sign");
    }

    /// Not plain 8.3: too long a name or extension, an empty name or extension, two dots, a
    /// space, forbidden bytes, controls.
    #[test]
    fn non_8_3_names_have_no_short_form() {
        for bad in [
            &b""[..],
            b"f2k-kernel",
            b"123456789",
            b"NAME.LONG",
            b".EXE",
            b"NAME.",
            b"A.B.C",
            b"...",
            b"MY FILE",
            b"WHAT?",
            b"STAR*",
            b"A:B",
            b"TAB\t",
            b"DEL\x7F",
        ] {
            assert_eq!(short_form(bad), None, "{:?}", core::str::from_utf8(bad));
        }
    }

    /// Long names are components; empty paths, empty components, over-long names and forbidden
    /// bytes are malformed.
    #[test]
    fn malformed_paths() {
        assert!(is_valid(b"HELLO.EXE"));
        assert!(is_valid(b"BOOT\\LIMINE\\..\\..\\HELLO.EXE"));
        assert!(is_valid(b"BOOT\\long-name"));
        assert!(is_valid(b"DATA\\Long File Name.txt"));
        let long = [b'x'; MAX_NAME + 1];
        for bad in [
            &b""[..],
            b"\\",
            b"\\HELLO.EXE",
            b"BOOT\\",
            b"BOOT\\\\LIMINE",
            b"WHAT?",
            b"STAR*",
            b"A:B",
            b"TAB\t",
            &long[..],
        ] {
            assert!(!is_valid(bad), "{:?}", core::str::from_utf8(bad));
        }
    }

    #[test]
    fn components_split_in_order() {
        let parts: Vec<Component> = components(b"boot\\..\\.\\Long Name.txt").collect();
        assert_eq!(
            parts,
            vec![
                Component::Name(b"boot"),
                Component::Parent,
                Component::Current,
                Component::Name(b"Long Name.txt"),
            ]
        );
    }
}
