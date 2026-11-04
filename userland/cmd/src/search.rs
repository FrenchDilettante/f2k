//! Finding the program a command's word names, as cmd.exe searches for one itself (CreateProcessW
//! would add only `.exe`): the current directory, then each PATH directory, trying the extensions
//! PATHEXT lists.

use crate::{fold, QUOTE};

/// PATHEXT's value when the variable is not set.
pub const DEFAULT_PATHEXT: &str = ".COM;.EXE;.BAT;.CMD";

/// The units a program's path is built in: MAX_PATH.
pub const PROGRAM_PATH: usize = 260;

/// Whether `unit` separates a path's components, or ends a drive (`:`).
fn is_separator(unit: u16) -> bool {
    unit == u16::from(b'\\') || unit == u16::from(b'/') || unit == u16::from(b':')
}

/// Whether two texts are the same, ignoring the case of their ASCII letters.
fn same(a: &[u16], b: &[u16]) -> bool {
    a.len() == b.len() && a.iter().zip(b).all(|(&a, &b)| fold(a) == fold(b))
}

/// A name's extension, its dot included: None for a last component without a dot.
pub fn extension(name: &[u16]) -> Option<&[u16]> {
    let component = name
        .iter()
        .rposition(|&unit| is_separator(unit))
        .map_or(0, |separator| separator + 1);
    let dot = name[component..]
        .iter()
        .rposition(|&unit| unit == u16::from(b'.'))?;
    Some(&name[component + dot..])
}

/// Whether a file found runs as a batch file: its extension is `.bat` or `.cmd`.
pub fn is_batch(path: &[u16]) -> bool {
    let bat: [u16; 4] = b".BAT".map(u16::from);
    let cmd: [u16; 4] = b".CMD".map(u16::from);
    extension(path).is_some_and(|extension| same(extension, &bat) || same(extension, &cmd))
}

/// Whether a batch file is a `.cmd` script, whose `set`, `path` and `prompt` set the ERRORLEVEL
/// to 0 when they succeed (a `.bat` file's leave it).
pub fn is_cmd_script(path: &[u16]) -> bool {
    let cmd: [u16; 4] = b".CMD".map(u16::from);
    extension(path).is_some_and(|extension| same(extension, &cmd))
}

/// A list's entries (PATH's directories, PATHEXT's extensions): separated by `;`, each without
/// the quotes around it, empty ones left out.
fn entries(list: &[u16]) -> impl Iterator<Item = &[u16]> {
    list.split(|&unit| unit == u16::from(b';'))
        .map(|entry| {
            let entry = entry.strip_prefix(&[QUOTE]).unwrap_or(entry);
            entry.strip_suffix(&[QUOTE]).unwrap_or(entry)
        })
        .filter(|entry| !entry.is_empty())
}

/// `parts` joined in `out`: None when they do not fit.
fn join<'a>(parts: &[&[u16]], out: &'a mut [u16]) -> Option<&'a [u16]> {
    let mut length = 0;
    for part in parts {
        out.get_mut(length..length + part.len())?
            .copy_from_slice(part);
        length += part.len();
    }
    Some(&out[..length])
}

/// The file the word `name` (its quotes already removed) names, in `found`, as cmd.exe finds a
/// program: in the current directory (the name as it is, a relative path), then in each of
/// `path`'s directories in turn, unless the name holds a path of its own (a `\`, `/` or `:`), which
/// restricts the search to that place. In each place, a name with an extension as given, whether
/// `pathext` lists it or not (`x.bat` with PATHEXT `.CMD`), and a name without one with each of
/// `pathext`'s extensions in turn, as Windows 2000's `start /?` says PATHEXT is read. `exists` says
/// whether a file (not a directory) goes by a path. None when nothing is found.
pub fn search<'a>(
    name: &[u16],
    path: &[u16],
    pathext: &[u16],
    exists: &mut dyn FnMut(&[u16]) -> bool,
    found: &'a mut [u16],
) -> Option<&'a [u16]> {
    if name.is_empty() {
        return None;
    }
    let as_given = extension(name).is_some();
    let restricted = name.iter().any(|&unit| is_separator(unit));
    let here: &[u16] = &[];
    let places = core::iter::once(here).chain(entries(path).filter(|_| !restricted));
    let backslash = [u16::from(b'\\')];
    let mut hit = None;
    'places: for place in places {
        let separator: &[u16] = match place.last() {
            None => &[],
            Some(&last) if last == backslash[0] || last == u16::from(b'/') => &[],
            Some(_) => &backslash,
        };
        if as_given {
            if let Some(candidate) = join(&[place, separator, name], found) {
                if exists(candidate) {
                    hit = Some(candidate.len());
                    break 'places;
                }
            }
            continue;
        }
        for extension in entries(pathext) {
            if let Some(candidate) = join(&[place, separator, name, extension], found) {
                if exists(candidate) {
                    hit = Some(candidate.len());
                    break 'places;
                }
            }
        }
    }
    hit.map(|length| &found[..length])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().collect()
    }

    fn narrow(units: &[u16]) -> String {
        String::from_utf16(units).unwrap()
    }

    /// The search over a fake file system holding `files` (compared ignoring case), and every
    /// path it tried, in order.
    fn find(name: &str, path: &str, files: &[&str]) -> (Option<String>, Vec<String>) {
        let mut tried = Vec::new();
        let mut found = [0; PROGRAM_PATH];
        let result = search(
            &wide(name),
            &wide(path),
            &wide(DEFAULT_PATHEXT),
            &mut |candidate| {
                let candidate = narrow(candidate);
                let hit = files
                    .iter()
                    .any(|file| file.eq_ignore_ascii_case(&candidate));
                tried.push(candidate);
                hit
            },
            &mut found,
        )
        .map(narrow);
        (result, tried)
    }

    #[test]
    fn the_current_directory_comes_first() {
        let (found, tried) = find(
            "pwd",
            "C:\\WINNT\\system32",
            &["pwd.exe", "C:\\WINNT\\system32\\pwd.exe"],
        );
        assert_eq!(found.as_deref(), Some("pwd.EXE"));
        assert_eq!(tried, ["pwd.COM", "pwd.EXE"]);
    }

    #[test]
    fn then_each_path_directory_with_each_extension() {
        let (found, tried) = find("t", "C:\\a;\"C:\\b\\\";;C:\\c", &["C:\\b\\t.bat"]);
        assert_eq!(found.as_deref(), Some("C:\\b\\t.BAT"));
        assert_eq!(
            tried,
            [
                "t.COM",
                "t.EXE",
                "t.BAT",
                "t.CMD",
                "C:\\a\\t.COM",
                "C:\\a\\t.EXE",
                "C:\\a\\t.BAT",
                "C:\\a\\t.CMD",
                "C:\\b\\t.COM",
                "C:\\b\\t.EXE",
                "C:\\b\\t.BAT",
            ]
        );
    }

    #[test]
    fn a_name_with_an_extension_is_tried_as_given() {
        let (found, tried) = find("x.Cmd", "C:\\a", &["C:\\a\\x.cmd"]);
        assert_eq!(found.as_deref(), Some("C:\\a\\x.Cmd"));
        assert_eq!(tried, ["x.Cmd", "C:\\a\\x.Cmd"]);
        // An extension PATHEXT does not list too, and PATHEXT's are not added to it.
        let (_, tried) = find("x.txt", "", &[]);
        assert_eq!(tried, ["x.txt"]);
        // batpext: with PATHEXT .CMD alone, x.bat named outright is found.
        let mut found = [0; PROGRAM_PATH];
        let hit = search(
            &wide("x.bat"),
            &[],
            &wide(".CMD"),
            &mut |candidate| narrow(candidate) == "x.bat",
            &mut found,
        );
        assert_eq!(hit.map(narrow).as_deref(), Some("x.bat"));
    }

    #[test]
    fn a_path_in_the_name_restricts_the_search() {
        let (found, tried) = find("..\\x", "C:\\a", &["C:\\a\\x.exe"]);
        assert_eq!(found, None);
        assert_eq!(tried, ["..\\x.COM", "..\\x.EXE", "..\\x.BAT", "..\\x.CMD"]);
        let (found, _) = find("C:\\d.e\\x.exe", "C:\\a", &["C:\\d.e\\x.exe"]);
        assert_eq!(found.as_deref(), Some("C:\\d.e\\x.exe"));
        let (_, tried) = find("C:x", "C:\\a", &[]);
        assert_eq!(tried.len(), 4);
    }

    #[test]
    fn nothing_found_is_none() {
        assert_eq!(find("nope", "C:\\a", &[]).0, None);
        assert_eq!(find("", "C:\\a", &["x"]).0, None);
    }

    #[test]
    fn extensions_and_batch_files() {
        assert_eq!(extension(&wide("a.b\\c")), None);
        assert_eq!(extension(&wide("a\\c.d.e")), Some(&wide(".e")[..]));
        assert!(is_batch(&wide("C:\\x.Bat")));
        assert!(is_batch(&wide("x.CMD")));
        assert!(!is_batch(&wide("x.cmd.exe")));
        assert!(!is_batch(&wide("cmd")));
        assert!(is_cmd_script(&wide("C:\\x.Cmd")));
        assert!(!is_cmd_script(&wide("x.bat")));
        assert!(!is_cmd_script(&wide("x.cmd.exe")));
    }
}
