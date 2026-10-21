//! DOS paths, as ntdll's path functions take them (RtlGetFullPathName_U,
//! RtlDosPathNameToNtPathName_U): a path made absolute against the current directory, folded, and
//! its NT form.
//!
//! The rules are the Win32 naming rules, applied here in user mode before any system service sees
//! the name (the kernel takes NT paths only): forward slashes are separators; empty components
//! (doubled separators) vanish; `.` and `..` fold lexically (`..` at the root stays there); each
//! component loses its trailing dots and spaces (F2K's rule until a capture settles it: Windows
//! 2000 may trim the last component alone). A drive-relative path (`C:name`) on the current
//! directory's drive is relative to it, on another drive relative to that drive's root (no
//! per-drive directories are kept: the `=C:` environment variables are not consulted). A UNC path
//! keeps its `\\server\share` prefix.

/// The longest path the functions build, in units, the terminator included (MAX_PATH).
pub const MAX_PATH: usize = 260;

/// A path the functions cannot build: it is empty, or too long for its room.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathError {
    /// No path (an empty one).
    Empty,
    /// The result does not fit.
    TooLong,
}

const BACKSLASH: u16 = b'\\' as u16;
const SLASH: u16 = b'/' as u16;
const COLON: u16 = b':' as u16;

fn is_separator(unit: u16) -> bool {
    unit == BACKSLASH || unit == SLASH
}

fn is_letter(unit: u16) -> bool {
    unit < 0x80 && (unit as u8).is_ascii_alphabetic()
}

/// The drive letter of `path`, upper-cased, when it starts `X:`.
fn drive_of(path: &[u16]) -> Option<u16> {
    match path {
        [letter, COLON, ..] if is_letter(*letter) => Some(*letter & !0x20),
        _ => None,
    }
}

/// A component without its trailing dots and spaces (`.` and `..` themselves kept).
fn trim(component: &[u16]) -> &[u16] {
    let dot = u16::from(b'.');
    if component == [dot] || component == [dot, dot] {
        return component;
    }
    let end = component
        .iter()
        .rposition(|&unit| unit != dot && unit != u16::from(b' '))
        .map_or(0, |index| index + 1);
    &component[..end]
}

/// A path being built into a caller's buffer.
struct Builder<'a> {
    out: &'a mut [u16],
    len: usize,
    /// Where the root ends: `..` never pops below it.
    root: usize,
}

impl Builder<'_> {
    fn push(&mut self, unit: u16) -> Result<(), PathError> {
        // The terminator needs its room too.
        if self.len + 1 >= self.out.len() {
            return Err(PathError::TooLong);
        }
        self.out[self.len] = unit;
        self.len += 1;
        Ok(())
    }

    fn push_all(&mut self, units: &[u16]) -> Result<(), PathError> {
        units.iter().try_for_each(|&unit| self.push(unit))
    }

    /// Append the components of `path` (relative to what is built), folding `.` and `..`.
    fn components(&mut self, path: &[u16]) -> Result<(), PathError> {
        let dot = u16::from(b'.');
        for component in path.split(|&unit| is_separator(unit)) {
            let component = trim(component);
            if component.is_empty() || component == [dot] {
                continue;
            }
            if component == [dot, dot] {
                // Back to the previous separator, never below the root.
                let at = self.out[self.root..self.len]
                    .iter()
                    .rposition(|&unit| unit == BACKSLASH);
                self.len = at.map_or(self.root, |at| self.root + at);
                continue;
            }
            if self.len > self.root {
                self.push(BACKSLASH)?;
            }
            self.push_all(component)?;
        }
        Ok(())
    }
}

/// RtlGetFullPathName_U's work: `path` made absolute against `current` (the current directory's
/// DOS path, its trailing separator included, `C:\DIR\`) and folded, into `out` (terminated); its
/// length in units. A trailing separator is kept. The file part (its last component) starts where
/// the second value says, when it has one.
pub fn full_path_name(
    path: &[u16],
    current: &[u16],
    out: &mut [u16],
) -> Result<(usize, Option<usize>), PathError> {
    if path.is_empty() {
        return Err(PathError::Empty);
    }
    let mut built = Builder {
        out,
        len: 0,
        root: 0,
    };
    let current_drive = drive_of(current).unwrap_or(u16::from(b'C'));
    // The current directory's components, after its `C:\`.
    let current_rest = current.get(3..).unwrap_or(&[]);
    let rest = if let Some(drive) = drive_of(path) {
        built.push_all(&[drive, COLON, BACKSLASH])?;
        built.root = 3;
        let tail = &path[2..];
        if drive == current_drive && !tail.first().is_some_and(|&unit| is_separator(unit)) {
            // `C:name`: relative to the drive's current directory.
            built.components(current_rest)?;
        }
        tail
    } else if path.len() >= 2 && is_separator(path[0]) && is_separator(path[1]) {
        // `\\server\share\rest`: the prefix kept, the rest folded under it.
        built.push_all(&[BACKSLASH, BACKSLASH])?;
        let tail = &path[2..];
        let mut parts = tail.splitn(3, |&unit| is_separator(unit));
        let server = parts.next().unwrap_or(&[]);
        let share = parts.next().unwrap_or(&[]);
        built.push_all(server)?;
        built.push(BACKSLASH)?;
        built.push_all(share)?;
        built.push(BACKSLASH)?;
        built.root = built.len;
        let consumed = server.len() + share.len() + 2;
        &tail[consumed.min(tail.len())..]
    } else {
        // `\name` is rooted on the current directory's drive; anything else relative to it.
        built.push_all(&[current_drive, COLON, BACKSLASH])?;
        built.root = 3;
        if !is_separator(path[0]) {
            built.components(current_rest)?;
        }
        path
    };
    built.components(rest)?;
    if rest.last().is_some_and(|&unit| is_separator(unit)) && built.len > built.root {
        built.push(BACKSLASH)?;
    }
    let len = built.len;
    let ends_in_separator = built.out[len - 1] == BACKSLASH;
    let file_part = (!ends_in_separator).then(|| {
        built.out[..len]
            .iter()
            .rposition(|&unit| unit == BACKSLASH)
            .map_or(0, |at| at + 1)
    });
    built.out[len] = 0;
    Ok((len, file_part))
}

/// What a DOS path is, as RtlDetermineDosPathNameType_U tells them apart.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathType {
    /// `\\server\share...`
    UncAbsolute,
    /// `C:\...`
    DriveAbsolute,
    /// `C:name`
    DriveRelative,
    /// `\name`
    Rooted,
    /// `name`
    Relative,
    /// `\\.\device`
    LocalDevice,
    /// `\\?\...`, passed through untouched.
    RootLocalDevice,
}

/// The type of `path` (RtlDetermineDosPathNameType_U).
pub fn path_type(path: &[u16]) -> PathType {
    let dot = u16::from(b'.');
    let question = u16::from(b'?');
    match path {
        [a, b, c, d, ..]
            if is_separator(*a)
                && is_separator(*b)
                && (*c == dot || *c == question)
                && is_separator(*d) =>
        {
            if *c == dot {
                PathType::LocalDevice
            } else {
                PathType::RootLocalDevice
            }
        }
        [a, b, ..] if is_separator(*a) && is_separator(*b) => PathType::UncAbsolute,
        [a, ..] if is_separator(*a) => PathType::Rooted,
        [_, COLON, c, ..] if drive_of(path).is_some() && is_separator(*c) => {
            PathType::DriveAbsolute
        }
        [_, COLON, ..] if drive_of(path).is_some() => PathType::DriveRelative,
        _ => PathType::Relative,
    }
}

/// A unit upper-cased as the case-insensitive comparisons fold it (ASCII and Latin-1 letters).
pub fn upcase(unit: u16) -> u16 {
    match unit {
        0x61..=0x7A => unit - 0x20,
        0xE0..=0xFE if unit != 0xF7 => unit - 0x20,
        0xFF => 0x178,
        _ => unit,
    }
}

/// RtlDosPathNameToNtPathName_U's answer, the NT path itself in the caller's buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NtName {
    /// The NT path's length in units (terminated).
    pub length: usize,
    /// Where its last component starts, when it has one (not ending in a separator).
    pub file_part: Option<usize>,
    /// Where the name relative to the current directory starts, when the path was relative and the
    /// current directory (open: `current_open`) is a prefix of its full form: the caller opens it
    /// against the current directory's handle (RTL_RELATIVE_NAME).
    pub relative: Option<usize>,
}

/// RtlDosPathNameToNtPathName_U's work: the NT path of `path`, made absolute against `current` (the
/// current directory's DOS path, its trailing separator included) and folded, into `out`. A
/// `\\?\` path passes untouched (its `\\?\` becomes `\??\`); a `\\.\` one keeps its device prefix,
/// its rest folded. The full path must fit [`MAX_PATH`] units with its terminator, as the
/// platform's buffer is that long.
pub fn dos_path_to_nt(
    path: &[u16],
    current: &[u16],
    current_open: bool,
    out: &mut [u16],
) -> Result<NtName, PathError> {
    if path.is_empty() {
        return Err(PathError::Empty);
    }
    let kind = path_type(path);
    let prefix = [BACKSLASH, u16::from(b'?'), u16::from(b'?'), BACKSLASH];
    if matches!(kind, PathType::RootLocalDevice | PathType::LocalDevice) {
        let rest = &path[4..];
        let mut built = Builder {
            out,
            len: 0,
            root: 0,
        };
        built.push_all(&prefix)?;
        built.root = built.len;
        if kind == PathType::RootLocalDevice {
            built.push_all(rest)?;
        } else {
            built.components(rest)?;
            if rest.last().is_some_and(|&unit| is_separator(unit)) && built.len > built.root {
                built.push(BACKSLASH)?;
            }
        }
        let len = built.len;
        built.out[len] = 0;
        let file_part = (built.out[len - 1] != BACKSLASH).then(|| {
            built.out[..len]
                .iter()
                .rposition(|&unit| unit == BACKSLASH)
                .map_or(0, |at| at + 1)
        });
        return Ok(NtName {
            length: len,
            file_part,
            relative: None,
        });
    }
    let mut full = [0u16; MAX_PATH];
    let (full_length, file_part) = full_path_name(path, current, &mut full)?;
    let full = &full[..full_length];
    let length = nt_path(full, out)?;
    // The NT form's prefix replaces the DOS form's: `\??\` before a drive, `\??\UNC` for `\`.
    let shift = if kind == PathType::UncAbsolute { 6 } else { 4 };
    let relative = (kind == PathType::Relative
        && current_open
        && current.len() <= full.len()
        && current
            .iter()
            .zip(full)
            .all(|(&a, &b)| upcase(a) == upcase(b)))
    .then_some(4 + current.len());
    Ok(NtName {
        length,
        file_part: file_part.map(|at| at + shift),
        relative,
    })
}

/// RtlDosPathNameToNtPathName_U's form of a full DOS path: `\??\` and the path (a UNC path's
/// `\\server` as `\??\UNC\server`), into `out`: its length in units.
pub fn nt_path(full: &[u16], out: &mut [u16]) -> Result<usize, PathError> {
    let mut built = Builder {
        out,
        len: 0,
        root: 0,
    };
    built.push_all(&[BACKSLASH, u16::from(b'?'), u16::from(b'?'), BACKSLASH])?;
    if full.len() >= 2 && full[0] == BACKSLASH && full[1] == BACKSLASH {
        built.push_all(&[u16::from(b'U'), u16::from(b'N'), u16::from(b'C')])?;
        built.push_all(&full[1..])?;
    } else {
        built.push_all(full)?;
    }
    let len = built.len;
    built.out[len] = 0;
    Ok(len)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wide(text: &str) -> std::vec::Vec<u16> {
        text.encode_utf16().collect()
    }

    fn full(path: &str, current: &str) -> Result<(String, Option<usize>), PathError> {
        let mut out = [0u16; MAX_PATH];
        let (len, file) = full_path_name(&wide(path), &wide(current), &mut out)?;
        assert_eq!(out[len], 0, "terminated");
        Ok((String::from_utf16(&out[..len]).unwrap(), file))
    }

    /// Absolute, rooted, relative and drive-relative paths, folded as the Win32 rules fold them.
    #[test]
    fn paths_are_made_absolute_and_folded() {
        let current = "C:\\CORPUS\\";
        assert_eq!(
            full("C:\\A\\B.TXT", current).unwrap(),
            ("C:\\A\\B.TXT".into(), Some(5))
        );
        assert_eq!(
            full("DATA\\SUB", current).unwrap().0,
            "C:\\CORPUS\\DATA\\SUB"
        );
        assert_eq!(
            full(".\\DATA\\.\\SUB\\", current).unwrap().0,
            "C:\\CORPUS\\DATA\\SUB\\"
        );
        assert_eq!(
            full("..\\..\\..\\X", current).unwrap().0,
            "C:\\X",
            "`..` stops at the root"
        );
        assert_eq!(full("\\WINNT", current).unwrap().0, "C:\\WINNT");
        assert_eq!(full("c:name", current).unwrap().0, "C:\\CORPUS\\name");
        assert_eq!(full("D:name", current).unwrap().0, "D:\\name");
        assert_eq!(full("C:", current).unwrap(), ("C:\\CORPUS".into(), Some(3)));
        assert_eq!(full("C:\\", current).unwrap(), ("C:\\".into(), None));
        assert_eq!(full("a/b//c", current).unwrap().0, "C:\\CORPUS\\a\\b\\c");
        assert_eq!(
            full("name. . ", current).unwrap().0,
            "C:\\CORPUS\\name",
            "trailing dots and spaces go"
        );
        assert_eq!(
            full("\\\\srv\\share\\dir\\..\\f", current).unwrap().0,
            "\\\\srv\\share\\f"
        );
        assert_eq!(full("", current), Err(PathError::Empty));
        let long = "x".repeat(300);
        assert_eq!(full(&long, current), Err(PathError::TooLong));
    }

    /// The NT form: `\??\` before a DOS path, `\??\UNC\` before a UNC one.
    #[test]
    fn nt_paths_lead_with_the_dos_devices() {
        let mut out = [0u16; MAX_PATH + 8];
        let len = nt_path(&wide("C:\\CORPUS\\"), &mut out).unwrap();
        assert_eq!(
            String::from_utf16(&out[..len]).unwrap(),
            "\\??\\C:\\CORPUS\\"
        );
        let len = nt_path(&wide("\\\\srv\\share"), &mut out).unwrap();
        assert_eq!(
            String::from_utf16(&out[..len]).unwrap(),
            "\\??\\UNC\\srv\\share"
        );
    }

    type Nt = (String, Option<String>, Option<String>);

    fn nt(path: &str, current: &str, open: bool) -> Result<Nt, PathError> {
        let mut out = [0u16; MAX_PATH + 8];
        let name = dos_path_to_nt(&wide(path), &wide(current), open, &mut out)?;
        assert_eq!(out[name.length], 0, "terminated");
        let text = |at: usize| String::from_utf16(&out[at..name.length]).unwrap();
        Ok((text(0), name.file_part.map(text), name.relative.map(text)))
    }

    /// The path types, as RtlDetermineDosPathNameType_U tells them apart.
    #[test]
    fn path_types() {
        for (path, kind) in [
            ("\\\\srv\\share", PathType::UncAbsolute),
            ("//srv/share", PathType::UncAbsolute),
            ("C:\\X", PathType::DriveAbsolute),
            ("c:/X", PathType::DriveAbsolute),
            ("C:X", PathType::DriveRelative),
            ("\\X", PathType::Rooted),
            ("X", PathType::Relative),
            (".\\X", PathType::Relative),
            ("1:\\X", PathType::Relative),
            ("\\\\.\\C:", PathType::LocalDevice),
            ("\\\\?\\C:\\X", PathType::RootLocalDevice),
        ] {
            assert_eq!(path_type(&wide(path)), kind, "{path}");
        }
    }

    /// The NT path of a DOS path, its file part, and the name relative to the current directory
    /// when the path is relative and under it (the current directory open).
    #[test]
    fn dos_paths_become_nt_paths() {
        let current = "C:\\CORPUS\\";
        assert_eq!(
            nt("DATA\\SMALL.TXT", current, true).unwrap(),
            (
                "\\??\\C:\\CORPUS\\DATA\\SMALL.TXT".into(),
                Some("SMALL.TXT".into()),
                Some("DATA\\SMALL.TXT".into())
            )
        );
        assert_eq!(
            nt(".\\DATA\\SUB\\", current, true).unwrap().2,
            Some("DATA\\SUB\\".into())
        );
        assert_eq!(
            nt("data\\x", "C:\\Corpus\\", true).unwrap().2,
            Some("data\\x".into()),
            "any case"
        );
        assert_eq!(
            nt("DATA\\SMALL.TXT", current, false).unwrap().2,
            None,
            "no handle"
        );
        assert_eq!(
            nt("..\\X", "C:\\CORPUS\\DATA\\", true).unwrap().2,
            None,
            "not under it"
        );
        assert_eq!(
            nt("C:\\CORPUS\\X", current, true).unwrap().2,
            None,
            "an absolute path"
        );
        assert_eq!(
            nt("\\CORPUS\\X", current, true).unwrap().2,
            None,
            "a rooted path"
        );
        assert_eq!(
            nt("C:\\", current, true).unwrap(),
            ("\\??\\C:\\".into(), None, None)
        );
        assert_eq!(
            nt("\\\\srv\\share\\f", current, true).unwrap(),
            ("\\??\\UNC\\srv\\share\\f".into(), Some("f".into()), None)
        );
        assert_eq!(
            nt("\\\\?\\C:\\a\\..\\b", current, true).unwrap().0,
            "\\??\\C:\\a\\..\\b",
            "untouched"
        );
        assert_eq!(
            nt("\\\\.\\C:", current, true).unwrap(),
            ("\\??\\C:".into(), Some("C:".into()), None)
        );
        assert_eq!(nt("", current, true), Err(PathError::Empty));
        let long = "x".repeat(250);
        assert_eq!(
            nt(&long, current, true).err(),
            Some(PathError::TooLong),
            "past MAX_PATH once made absolute"
        );
        assert_eq!(upcase(u16::from(b'a')), u16::from(b'A'));
        assert_eq!(upcase(0xE9), 0xC9);
        assert_eq!(upcase(0xF7), 0xF7, "the division sign");
    }
}
