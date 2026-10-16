//! Win32 paths to boot-volume paths: what kernel32 does to a name before the file system sees it
//! (Windows 2000's `RtlDosPathNameToNtPathName_U`).
//!
//! One drive exists, C:, the boot volume. A path is made absolute against the process's current
//! directory; forward slashes are separators; empty components (doubled separators) vanish; `.`
//! and `..` fold lexically (`..` at the root stays there); and each component loses its trailing
//! dots and spaces — the Win32 naming rules, applied before any lookup. The result is the path the
//! FAT layer walks: backslash-separated, no drive, no leading separator, the root being the empty
//! path.

use super::error::{ERROR_FILENAME_EXCED_RANGE, ERROR_INVALID_NAME, ERROR_PATH_NOT_FOUND};

/// The ANSI path limit, terminator included.
pub const MAX_PATH: usize = 260;

/// The only drive letter: the boot volume.
pub const DRIVE: u8 = b'C';

/// The volume path separator.
const SEPARATOR: u8 = b'\\';

/// Bytes no Win32 file name component may contain (beyond the controls).
const INVALID: &[u8] = b"\"*:<>?|";

fn is_separator(byte: u8) -> bool {
    byte == b'\\' || byte == b'/'
}

/// A resolved boot-volume path.
#[derive(Clone, Copy)]
pub struct VolumePath {
    bytes: [u8; MAX_PATH],
    len: usize,
    trailing_separator: bool,
}

impl VolumePath {
    /// The root: the empty volume path.
    pub const fn root() -> VolumePath {
        VolumePath {
            bytes: [0; MAX_PATH],
            len: 0,
            trailing_separator: false,
        }
    }

    /// The volume path's bytes (empty for the root).
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    /// Whether the path is the root.
    pub fn is_root(&self) -> bool {
        self.len == 0
    }

    /// Whether the Win32 path ended in a separator (it then names a directory).
    pub fn trailing_separator(&self) -> bool {
        self.trailing_separator
    }

    /// The parent directory's volume path (the root's parent is the root).
    pub fn parent(&self) -> &[u8] {
        let path = self.as_bytes();
        match path.iter().rposition(|&byte| byte == SEPARATOR) {
            Some(index) => &path[..index],
            None => &[],
        }
    }

    /// The final component (empty for the root).
    pub fn file_name(&self) -> &[u8] {
        let path = self.as_bytes();
        match path.iter().rposition(|&byte| byte == SEPARATOR) {
            Some(index) => &path[index + 1..],
            None => path,
        }
    }

    /// Append one component.
    fn push(&mut self, component: &[u8]) -> Result<(), u32> {
        let separator = usize::from(self.len != 0);
        // Room for the drive prefix (`C:\`) and the terminator the Win32 form needs.
        if self.len + separator + component.len() + 3 + 1 > MAX_PATH {
            return Err(ERROR_FILENAME_EXCED_RANGE);
        }
        if separator == 1 {
            self.bytes[self.len] = SEPARATOR;
            self.len += 1;
        }
        self.bytes[self.len..self.len + component.len()].copy_from_slice(component);
        self.len += component.len();
        Ok(())
    }

    /// Drop the final component (the root stays the root).
    fn pop(&mut self) {
        self.len = self.parent().len();
    }

    /// Append every component of an already-resolved volume path.
    fn push_all(&mut self, path: &[u8]) -> Result<(), u32> {
        for component in path.split(|&byte| byte == SEPARATOR) {
            if !component.is_empty() {
                self.push(component)?;
            }
        }
        Ok(())
    }
}

/// Strip a component's trailing dots and spaces, keeping `.` and `..` themselves.
fn trim_component(component: &[u8]) -> &[u8] {
    if component == b"." || component == b".." {
        return component;
    }
    let end = component
        .iter()
        .rposition(|&byte| byte != b'.' && byte != b' ')
        .map_or(0, |index| index + 1);
    &component[..end]
}

/// Resolve the Win32 path `path` against `current`, the current directory's volume path. The
/// failure is the Win32 error the path functions report: an empty path, a UNC path or another drive
/// does not name the volume (ERROR_PATH_NOT_FOUND); wildcards and other reserved bytes are not
/// names (ERROR_INVALID_NAME); a path past MAX_PATH is too long (ERROR_FILENAME_EXCED_RANGE).
pub fn resolve(path: &[u8], current: &[u8]) -> Result<VolumePath, u32> {
    if path.len() >= MAX_PATH {
        return Err(ERROR_FILENAME_EXCED_RANGE);
    }
    if path.is_empty() {
        return Err(ERROR_PATH_NOT_FOUND);
    }
    let mut resolved = VolumePath::root();
    let rest = if path.len() >= 2 && path[1] == b':' {
        if !path[0].is_ascii_alphabetic() {
            return Err(ERROR_INVALID_NAME);
        }
        if path[0].to_ascii_uppercase() != DRIVE {
            return Err(ERROR_PATH_NOT_FOUND);
        }
        let tail = &path[2..];
        if !tail.first().is_some_and(|&byte| is_separator(byte)) {
            // `C:name`: relative to the drive's current directory.
            resolved.push_all(current)?;
        }
        tail
    } else if is_separator(path[0]) {
        if path.len() >= 2 && is_separator(path[1]) {
            // `\\server\share` and `\\.\device`: no such volume here.
            return Err(ERROR_PATH_NOT_FOUND);
        }
        path
    } else {
        resolved.push_all(current)?;
        path
    };

    let mut trailing = false;
    for component in rest.split(|&byte| is_separator(byte)) {
        trailing = component.is_empty();
        let component = trim_component(component);
        match component {
            b"" | b"." => {}
            b".." => resolved.pop(),
            _ => {
                if component
                    .iter()
                    .any(|&byte| byte < b' ' || INVALID.contains(&byte))
                {
                    return Err(ERROR_INVALID_NAME);
                }
                resolved.push(component)?;
            }
        }
    }
    resolved.trailing_separator = trailing && !resolved.is_root();
    Ok(resolved)
}

/// Write the Win32 form of a volume path (`C:\` and the path) into `out`; its length. `out` must
/// hold [`MAX_PATH`] bytes.
pub fn win32_form(path: &[u8], out: &mut [u8]) -> usize {
    out[..3].copy_from_slice(&[DRIVE, b':', SEPARATOR]);
    out[3..3 + path.len()].copy_from_slice(path);
    3 + path.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compat::error::{
        ERROR_FILENAME_EXCED_RANGE, ERROR_INVALID_NAME, ERROR_PATH_NOT_FOUND,
    };

    fn ok(path: &str, current: &str) -> String {
        let resolved = resolve(path.as_bytes(), current.as_bytes())
            .unwrap_or_else(|error| panic!("{path:?}: error {error}"));
        String::from_utf8(resolved.as_bytes().to_vec()).unwrap()
    }

    fn err(path: &str) -> u32 {
        match resolve(path.as_bytes(), b"") {
            Ok(resolved) => panic!("{path:?} resolved to {:?}", resolved.as_bytes()),
            Err(error) => error,
        }
    }

    /// Drive-absolute, root-relative and relative paths land on the same volume path.
    #[test]
    fn absolute_and_relative_forms() {
        assert_eq!(ok("C:\\DATA\\SMALL.TXT", ""), "DATA\\SMALL.TXT");
        assert_eq!(ok("c:\\data\\small.txt", "SUB"), "data\\small.txt");
        assert_eq!(ok("\\DATA\\SMALL.TXT", "SUB"), "DATA\\SMALL.TXT");
        assert_eq!(ok("SMALL.TXT", "DATA"), "DATA\\SMALL.TXT");
        assert_eq!(ok("C:SMALL.TXT", "DATA"), "DATA\\SMALL.TXT");
        assert_eq!(ok("C:\\", "DATA"), "");
        assert_eq!(ok("\\", "DATA"), "");
        assert_eq!(ok("C:", "DATA"), "DATA");
    }

    /// Forward slashes separate; doubled separators collapse; `.` and `..` fold, the root's `..`
    /// staying at the root.
    #[test]
    fn separators_and_dot_components_fold() {
        assert_eq!(ok("DATA/SMALL.TXT", ""), "DATA\\SMALL.TXT");
        assert_eq!(ok("DATA\\\\SUB//DEEP", ""), "DATA\\SUB\\DEEP");
        assert_eq!(ok("DATA\\.\\SUB\\..\\SMALL.TXT", ""), "DATA\\SMALL.TXT");
        assert_eq!(ok("..\\SMALL.TXT", "DATA\\SUB"), "DATA\\SMALL.TXT");
        assert_eq!(ok("..\\..\\..\\X", "DATA"), "X");
        assert_eq!(ok(".", "DATA"), "DATA");
    }

    /// Trailing dots and spaces drop from each component.
    #[test]
    fn trailing_dots_and_spaces_drop() {
        assert_eq!(ok("SMALL.TXT.", ""), "SMALL.TXT");
        assert_eq!(ok("SMALL.TXT . .", ""), "SMALL.TXT");
        assert_eq!(ok("DATA. \\SMALL.TXT", ""), "DATA\\SMALL.TXT");
        assert_eq!(ok("Long File Name.txt", ""), "Long File Name.txt");
    }

    /// A trailing separator is remembered: the path names a directory.
    #[test]
    fn a_trailing_separator_is_remembered() {
        let with = resolve(b"DATA\\SMALL.TXT\\", b"").unwrap();
        assert!(with.trailing_separator());
        assert_eq!(with.as_bytes(), b"DATA\\SMALL.TXT");
        assert!(!resolve(b"DATA\\SMALL.TXT", b"")
            .unwrap()
            .trailing_separator());
        assert!(!resolve(b"C:\\", b"").unwrap().trailing_separator());
    }

    /// The failures carry the Win32 errors the path functions report.
    #[test]
    fn failures_carry_their_win32_errors() {
        assert_eq!(err(""), ERROR_PATH_NOT_FOUND);
        assert_eq!(err("D:\\X"), ERROR_PATH_NOT_FOUND);
        assert_eq!(err("\\\\server\\share\\X"), ERROR_PATH_NOT_FOUND);
        assert_eq!(err("DATA\\SMA*.TXT"), ERROR_INVALID_NAME);
        assert_eq!(err("DATA\\A?B"), ERROR_INVALID_NAME);
        assert_eq!(err("DATA\\A:B"), ERROR_INVALID_NAME);
        assert_eq!(err("DATA\\A|B"), ERROR_INVALID_NAME);
        assert_eq!(err("DATA\\A\tB"), ERROR_INVALID_NAME);
        assert_eq!(err("1:\\X"), ERROR_INVALID_NAME);
        assert_eq!(err(&"A".repeat(300)), ERROR_FILENAME_EXCED_RANGE);
    }

    /// A path whose resolution outgrows MAX_PATH (with its drive prefix) is too long, even when the
    /// text itself is short.
    #[test]
    fn resolution_respects_max_path() {
        let current = "D".repeat(250);
        assert_eq!(
            resolve(b"SMALL.TXT", current.as_bytes()).err(),
            Some(ERROR_FILENAME_EXCED_RANGE)
        );
    }

    #[test]
    fn parents_and_file_names() {
        let path = resolve(b"DATA\\SUB\\LEAF.TXT", b"").unwrap();
        assert_eq!(path.parent(), b"DATA\\SUB");
        assert_eq!(path.file_name(), b"LEAF.TXT");
        let top = resolve(b"SMALL.TXT", b"").unwrap();
        assert_eq!(top.parent(), b"");
        assert_eq!(top.file_name(), b"SMALL.TXT");
        assert!(resolve(b"\\", b"").unwrap().is_root());
    }

    #[test]
    fn the_win32_form_carries_the_drive() {
        let mut out = [0u8; MAX_PATH];
        let len = win32_form(b"FILEIO.EXE", &mut out);
        assert_eq!(&out[..len], b"C:\\FILEIO.EXE");
        let len = win32_form(b"", &mut out);
        assert_eq!(&out[..len], b"C:\\");
    }
}
