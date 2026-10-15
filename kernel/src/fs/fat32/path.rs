//! Paths: root-relative, backslash-separated components, each `.`, `..`, or an 8.3 name folded to
//! its stored form (uppercase, space-padded).
//!
//! Paths are bytes, the way Win32 hands them over: ASCII letters fold to uppercase, and bytes from
//! 0x80 up pass through as the volume's code page stores them. The empty path, an empty component,
//! and a component that is not a plain 8.3 name are malformed input.

use super::dirent::stored_name;

/// The separator.
pub const SEPARATOR: u8 = b'\\';

/// One folded component.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Component {
    /// `.`: the current directory.
    Current,
    /// `..`: the parent directory (the root's parent is the root).
    Parent,
    /// An 8.3 name in its stored form.
    Name([u8; 11]),
}

/// The bytes a short name may not contain (beyond the controls, space, and DEL); the dot only
/// separates the extension.
const FORBIDDEN: &[u8] = b"\"*+,./:;<=>?[\\]|";

fn is_name_byte(byte: u8) -> bool {
    byte > b' ' && byte != 0x7F && !FORBIDDEN.contains(&byte)
}

/// Fold one component, or none when it is not `.`, `..`, or a plain 8.3 name: 1-8 name bytes, then
/// optionally a dot and 1-3 extension bytes.
pub fn fold(component: &[u8]) -> Option<Component> {
    match component {
        b"." => return Some(Component::Current),
        b".." => return Some(Component::Parent),
        _ => {}
    }
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
    name.make_ascii_uppercase();
    Some(Component::Name(name))
}

/// Whether `path` is well formed: non-empty, and every component folds.
pub fn is_valid(path: &[u8]) -> bool {
    !path.is_empty()
        && path
            .split(|&byte| byte == SEPARATOR)
            .all(|part| fold(part).is_some())
}

/// The folded components of a well-formed path (see [`is_valid`]), in order.
pub fn components(path: &[u8]) -> impl Iterator<Item = Component> + '_ {
    assert!(
        is_valid(path),
        "a malformed path is refused before it is walked"
    );
    path.split(|&byte| byte == SEPARATOR)
        .map(|part| fold(part).unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(stored: &[u8; 11]) -> Option<Component> {
        Some(Component::Name(*stored))
    }

    /// Lowercase and mixed case fold to the stored uppercase, space-padded.
    #[test]
    fn names_fold_to_the_stored_form() {
        assert_eq!(fold(b"HELLO.EXE"), name(b"HELLO   EXE"));
        assert_eq!(fold(b"hello.exe"), name(b"HELLO   EXE"));
        assert_eq!(fold(b"HeLlO.eXe"), name(b"HELLO   EXE"));
        assert_eq!(fold(b"boot"), name(b"BOOT       "));
        assert_eq!(fold(b"F2K-KE~1"), name(b"F2K-KE~1   "));
        assert_eq!(fold(b"A.B"), name(b"A       B  "));
        assert_eq!(fold(b"12345678.123"), name(b"12345678123"));
        // Code-page bytes pass through unfolded.
        assert_eq!(fold(b"\xE5NAME.TXT"), name(b"\xE5NAME   TXT"));
    }

    #[test]
    fn dot_components_are_their_own() {
        assert_eq!(fold(b"."), Some(Component::Current));
        assert_eq!(fold(b".."), Some(Component::Parent));
    }

    /// Not plain 8.3: too long a name or extension, an empty name or extension, two dots, a
    /// space, forbidden bytes, controls.
    #[test]
    fn non_8_3_components_do_not_fold() {
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
            assert_eq!(fold(bad), None, "{:?}", core::str::from_utf8(bad));
        }
    }

    /// Empty paths and empty components — leading, trailing, doubled separators — are malformed.
    #[test]
    fn malformed_paths() {
        assert!(is_valid(b"HELLO.EXE"));
        assert!(is_valid(b"BOOT\\LIMINE\\..\\..\\HELLO.EXE"));
        for bad in [
            &b""[..],
            b"\\",
            b"\\HELLO.EXE",
            b"BOOT\\",
            b"BOOT\\\\LIMINE",
            b"BOOT\\long-name",
        ] {
            assert!(!is_valid(bad), "{:?}", core::str::from_utf8(bad));
        }
    }

    #[test]
    fn components_split_in_order() {
        let parts: Vec<Component> = components(b"boot\\..\\.\\hello.exe").collect();
        assert_eq!(
            parts,
            vec![
                Component::Name(*b"BOOT       "),
                Component::Parent,
                Component::Current,
                Component::Name(*b"HELLO   EXE"),
            ]
        );
    }
}
