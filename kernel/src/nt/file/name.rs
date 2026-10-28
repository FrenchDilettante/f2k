//! The names the file services take: an NT path in an OBJECT_ATTRIBUTES, as ntdll's
//! RtlDosPathNameToNtPathName_U makes it — absolute (`\??\C:\DIR\FILE`, or `\DosDevices\` for
//! `\??\`), or relative to a directory's file object (the RootDirectory handle: ntdll's names under
//! the current directory). The Win32 rules (separators, `.` and `..`, trailing dots and spaces, the
//! current directory) are user mode's: the kernel walks the components it is given.
//!
//! The boot volume is C:; `\??\C:` alone is the volume itself. Another drive is missing, as is any
//! other name under `\??` (STATUS_OBJECT_NAME_NOT_FOUND, STATUS_OBJECT_PATH_NOT_FOUND with more
//! after it); a name outside `\??` is no path there. A component is a FAT long name: no control
//! character and none of `"*/:<>?\|` (wildcards included: FastFat's open refuses them), not `.` or
//! `..`, at most 255 units, and in code page 1252 (the volume's names are kept as its bytes:
//! unverified); an empty component is no name either (STATUS_OBJECT_NAME_INVALID).

use super::super::attributes::MAX_NAME;
use crate::status::*;

/// The longest component, in units (a FAT long name's).
pub const MAX_COMPONENT: usize = 255;

/// The only drive: the boot volume.
const DRIVE: u8 = b'C';

const SEPARATOR: u16 = b'\\' as u16;

/// A name the file services walk: the components below where it starts (the volume's root for an
/// absolute name, the root directory's for a relative one), `\`-joined in code page 1252 bytes.
pub struct FileName {
    bytes: [u8; MAX_NAME],
    length: usize,
    /// Whether the name ended in a separator (it then names a directory).
    pub trailing: bool,
    /// Whether the name is the volume itself (`\??\C:`).
    pub volume: bool,
}

impl FileName {
    /// The components, `\`-joined (empty: where the name starts).
    pub fn path(&self) -> &[u8] {
        &self.bytes[..self.length]
    }

    /// The components, in order.
    pub fn components(&self) -> impl Iterator<Item = &[u8]> {
        self.path()
            .split(|&byte| byte == SEPARATOR as u8)
            .filter(|component| !component.is_empty())
    }

    /// The last component (empty for where the name starts).
    pub fn last(&self) -> &[u8] {
        let path = self.path();
        path.iter()
            .rposition(|&byte| byte == SEPARATOR as u8)
            .map_or(path, |at| &path[at + 1..])
    }

    /// Whether the name is where it starts (no component).
    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.length == 0
    }

    fn empty() -> FileName {
        FileName {
            bytes: [0; MAX_NAME],
            length: 0,
            trailing: false,
            volume: false,
        }
    }
}

/// Whether `units` begin with `prefix` (ASCII, case-insensitively).
fn starts_with(units: &[u16], prefix: &[u8]) -> bool {
    units.len() >= prefix.len()
        && units
            .iter()
            .zip(prefix)
            .all(|(&unit, &byte)| unit < 0x80 && (unit as u8).eq_ignore_ascii_case(&byte))
}

/// Whether a unit may be in a component.
fn valid_unit(unit: u16) -> bool {
    unit >= 0x20
        && !matches!(unit as u8, b'"' | b'*' | b'/' | b':' | b'<' | b'>' | b'?' | b'\\' | b'|' if unit < 0x80)
}

/// The components of `units` (no leading separator) into `name`, validated. A `.` or `..` is no
/// folding here (ntdll folded the DOS path's): inside the path it is a name the volume's
/// directories never answer to (their dot entries match no name), so the walk finds the path
/// missing, as Windows 2000's does (the files capture: `DATA\...\SMALL.TXT`, which ntdll makes
/// `DATA\..\SMALL.TXT`, is ERROR_PATH_NOT_FOUND); as the last component it is invalid.
fn components(units: &[u16], name: &mut FileName) -> Result<(), NtStatus> {
    if units.is_empty() {
        return Ok(());
    }
    let (body, trailing) = match units.split_last() {
        Some((&SEPARATOR, body)) => (body, true),
        _ => (units, false),
    };
    let count = body.split(|&unit| unit == SEPARATOR).count();
    for (index, component) in body.split(|&unit| unit == SEPARATOR).enumerate() {
        let dot = u16::from(b'.');
        let is_dot = component == [dot] || component == [dot, dot];
        if component.is_empty()
            || component.len() > MAX_COMPONENT
            || (is_dot && index + 1 == count)
            || !component.iter().all(|&unit| valid_unit(unit))
        {
            return Err(STATUS_OBJECT_NAME_INVALID);
        }
        if index > 0 {
            name.bytes[name.length] = SEPARATOR as u8;
            name.length += 1;
        }
        for &unit in component {
            let narrow = rtl::cp1252::wc_to_mb(unit);
            if rtl::cp1252::MB_TO_WC[narrow as usize] != unit {
                return Err(STATUS_OBJECT_NAME_INVALID);
            }
            name.bytes[name.length] = narrow;
            name.length += 1;
        }
    }
    name.trailing = trailing;
    Ok(())
}

/// An absolute NT name: the components below the volume's root.
pub fn absolute(units: &[u16]) -> Result<FileName, NtStatus> {
    if units.first() != Some(&SEPARATOR) {
        return Err(STATUS_OBJECT_PATH_SYNTAX_BAD);
    }
    let rest = [&b"\\??\\"[..], b"\\DosDevices\\"]
        .iter()
        .find_map(|prefix| starts_with(units, prefix).then(|| &units[prefix.len()..]))
        .ok_or(STATUS_OBJECT_PATH_NOT_FOUND)?;
    // The DOS device: a drive letter and its colon, or any other name the DOS devices do not hold.
    let device_end = rest
        .iter()
        .position(|&unit| unit == SEPARATOR)
        .unwrap_or(rest.len());
    let missing = if device_end == rest.len() {
        STATUS_OBJECT_NAME_NOT_FOUND
    } else {
        STATUS_OBJECT_PATH_NOT_FOUND
    };
    match rest[..device_end] {
        [letter, colon]
            if colon == u16::from(b':')
                && letter < 0x80
                && (letter as u8).eq_ignore_ascii_case(&DRIVE) => {}
        [] => return Err(STATUS_OBJECT_NAME_INVALID),
        _ => return Err(missing),
    }
    let mut name = FileName::empty();
    if device_end == rest.len() {
        name.volume = true;
        return Ok(name);
    }
    components(&rest[device_end + 1..], &mut name)?;
    Ok(name)
}

/// A name relative to a directory: the components below it (none: the directory itself). A
/// leading separator is no relative name.
pub fn relative(units: &[u16]) -> Result<FileName, NtStatus> {
    if units.first() == Some(&SEPARATOR) {
        return Err(STATUS_OBJECT_NAME_INVALID);
    }
    let mut name = FileName::empty();
    components(units, &mut name)?;
    Ok(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wide(text: &str) -> std::vec::Vec<u16> {
        text.encode_utf16().collect()
    }

    fn path(
        name: Result<FileName, NtStatus>,
    ) -> Result<(std::string::String, bool, bool), NtStatus> {
        name.map(|name| {
            (
                std::string::String::from_utf8(name.path().to_vec()).unwrap(),
                name.trailing,
                name.volume,
            )
        })
    }

    /// The volume's paths, the volume itself, and the names outside it.
    #[test]
    fn absolute_names_walk_the_boot_volume() {
        assert_eq!(
            path(absolute(&wide("\\??\\C:\\CORPUS\\DATA\\SMALL.TXT"))),
            Ok(("CORPUS\\DATA\\SMALL.TXT".into(), false, false))
        );
        assert_eq!(
            path(absolute(&wide("\\??\\c:\\CORPUS\\"))),
            Ok(("CORPUS".into(), true, false))
        );
        assert_eq!(
            path(absolute(&wide("\\DosDevices\\C:\\"))),
            Ok(("".into(), false, false))
        );
        assert_eq!(
            path(absolute(&wide("\\??\\C:"))),
            Ok(("".into(), false, true))
        );
        assert_eq!(
            path(absolute(&wide("\\??\\D:"))).err(),
            Some(STATUS_OBJECT_NAME_NOT_FOUND)
        );
        assert_eq!(
            path(absolute(&wide("\\??\\D:\\X"))).err(),
            Some(STATUS_OBJECT_PATH_NOT_FOUND)
        );
        assert_eq!(
            path(absolute(&wide("\\??\\UNC\\srv\\share"))).err(),
            Some(STATUS_OBJECT_PATH_NOT_FOUND)
        );
        assert_eq!(
            path(absolute(&wide("\\Device\\Harddisk0"))).err(),
            Some(STATUS_OBJECT_PATH_NOT_FOUND)
        );
        assert_eq!(
            path(absolute(&wide("C:\\X"))).err(),
            Some(STATUS_OBJECT_PATH_SYNTAX_BAD)
        );
        let name = absolute(&wide("\\??\\C:\\A\\B\\C.TXT")).unwrap();
        assert_eq!(
            name.components().collect::<std::vec::Vec<_>>(),
            [&b"A"[..], b"B", b"C.TXT"]
        );
        assert_eq!(name.last(), b"C.TXT");
    }

    /// What no component may be.
    #[test]
    fn components_are_fat_long_names() {
        for bad in [
            "SMA*.TXT", "A?B", "A<B", "A\"B", "A|B", "A\u{9}B", "A\\\\B", ".", "..", "\u{4E2D}",
        ] {
            let text = std::format!("\\??\\C:\\DATA\\{bad}");
            assert_eq!(
                path(absolute(&wide(&text))).err(),
                Some(STATUS_OBJECT_NAME_INVALID),
                "{bad}"
            );
        }
        let long = "x".repeat(MAX_COMPONENT);
        assert!(absolute(&wide(&std::format!("\\??\\C:\\{long}"))).is_ok());
        assert_eq!(
            path(absolute(&wide(&std::format!("\\??\\C:\\{long}x")))).err(),
            Some(STATUS_OBJECT_NAME_INVALID)
        );
        // Inside the path, `.` and `..` are names the walk will not find (the files capture).
        let name = absolute(&wide("\\??\\C:\\DATA\\..\\SMALL.TXT")).unwrap();
        assert_eq!(
            name.components().collect::<std::vec::Vec<_>>(),
            [&b"DATA"[..], b"..", b"SMALL.TXT"]
        );
        let name = absolute(&wide("\\??\\C:\\caf\u{E9}.txt")).unwrap();
        assert_eq!(
            name.path(),
            b"caf\xE9.txt",
            "the code page 1252 bytes, as the volume keeps names"
        );
    }

    /// A name relative to a directory: its components, the directory itself for none.
    #[test]
    fn relative_names_start_at_their_directory() {
        assert_eq!(
            path(relative(&wide("DATA\\SMALL.TXT"))),
            Ok(("DATA\\SMALL.TXT".into(), false, false))
        );
        assert_eq!(path(relative(&wide(""))), Ok(("".into(), false, false)));
        assert_eq!(
            path(relative(&wide("SUB\\"))),
            Ok(("SUB".into(), true, false))
        );
        assert_eq!(
            path(relative(&wide("\\X"))).err(),
            Some(STATUS_OBJECT_NAME_INVALID)
        );
        assert!(relative(&wide("")).unwrap().is_empty());
    }
}
