//! What the file built-ins' arguments say, and what they print: their words and switches
//! ([`Tokens`]), `del`'s, `rd`'s, `copy`'s, `ren`'s and `move`'s forms, a path's directory and
//! name, the new name a wildcard rename gives, and the built-ins' messages.

use core::fmt;

use crate::{fold, is_blank, Text, QUOTE};

/// The attributes a file's FILE_ATTRIBUTE_* bits say it has.
pub const READONLY: u32 = 0x01;
pub const HIDDEN: u32 = 0x02;
pub const SYSTEM: u32 = 0x04;
pub const DIRECTORY: u32 = 0x10;
pub const ARCHIVE: u32 = 0x20;

/// Win32 errors the built-ins tell apart.
pub const ERROR_FILE_NOT_FOUND: u32 = 2;
pub const ERROR_PATH_NOT_FOUND: u32 = 3;
pub const ERROR_ACCESS_DENIED: u32 = 5;
pub const ERROR_NO_MORE_FILES: u32 = 18;
pub const ERROR_FILE_EXISTS: u32 = 80;
pub const ERROR_DIR_NOT_EMPTY: u32 = 145;
pub const ERROR_ALREADY_EXISTS: u32 = 183;
pub const ERROR_FILENAME_EXCED_RANGE: u32 = 206;

/// Windows 2000's text for a Win32 error a file built-in reports, CR LF included: the shell's
/// ([`crate::message`]) and the file system's own. None for one the shell has no text for.
pub fn message(error: u32) -> Option<&'static str> {
    match error {
        ERROR_FILE_EXISTS => Some("The file exists.\r\n"),
        ERROR_DIR_NOT_EMPTY => Some(NOT_EMPTY),
        ERROR_ALREADY_EXISTS => Some("Cannot create a file when that file already exists.\r\n"),
        ERROR_FILENAME_EXCED_RANGE => Some("The filename or extension is too long.\r\n"),
        267 => Some("The directory name is invalid.\r\n"),
        _ => crate::message(error),
    }
}

/// What `rd` prints for a directory that holds anything.
pub const NOT_EMPTY: &str = "The directory is not empty.\r\n";

/// What `copy` prints when a file's copy would be the file itself.
pub const ONTO_ITSELF: &str = "The file cannot be copied onto itself.\r\n";

/// What `ren` prints when the new name is taken.
pub const DUPLICATE: &str = "A duplicate file name exists, or the file cannot be found.\r\n";

/// What `move` prints when several files would go to one that is no directory.
pub const MULTIPLE: &str = "Cannot move multiple files to a single file.\r\n";

/// A piece of a file built-in's argument.
#[derive(Debug, PartialEq, Eq)]
pub enum Token<'a> {
    /// A file name, quotes and all (see [`crate::program_name`] to drop them).
    Name(&'a [u16]),
    /// A switch: what follows its `/` (`q`, `-y`, `a:-h`).
    Switch(&'a [u16]),
    /// `copy`'s `+`, which joins the files around it.
    Plus,
}

/// The tokens of a file built-in's argument. Tokens are separated by blanks and by `,`, `;` and
/// `=` outside quotes, as cmd separates a command's arguments; a `/` starts a switch, which runs
/// to the next separator or `/` (`/q/s` is two); a name runs to a separator or `/` outside
/// quotes, and, for `copy` (`plus`), `+` is a token of its own.
pub struct Tokens<'a> {
    rest: &'a [u16],
    plus: bool,
}

impl<'a> Tokens<'a> {
    pub fn new(argument: &'a [u16], plus: bool) -> Self {
        Tokens {
            rest: argument,
            plus,
        }
    }

    /// The names alone, the switches and `+` skipped.
    pub fn names(self) -> impl Iterator<Item = &'a [u16]> {
        self.filter_map(|token| match token {
            Token::Name(name) => Some(name),
            _ => None,
        })
    }
}

/// Whether `unit` separates a file built-in's tokens.
fn separates(unit: u16) -> bool {
    is_blank(unit) || b",;=".iter().any(|&byte| unit == u16::from(byte))
}

const SLASH: u16 = b'/' as u16;
const PLUS: u16 = b'+' as u16;

impl<'a> Iterator for Tokens<'a> {
    type Item = Token<'a>;

    fn next(&mut self) -> Option<Token<'a>> {
        let start = self
            .rest
            .iter()
            .position(|&unit| !separates(unit))
            .unwrap_or(self.rest.len());
        let rest = &self.rest[start..];
        let (&first, after) = rest.split_first()?;
        if first == SLASH {
            let end = after
                .iter()
                .position(|&unit| separates(unit) || unit == SLASH)
                .unwrap_or(after.len());
            self.rest = &after[end..];
            return Some(Token::Switch(&after[..end]));
        }
        if self.plus && first == PLUS {
            self.rest = after;
            return Some(Token::Plus);
        }
        let mut quoted = false;
        let end = rest
            .iter()
            .position(|&unit| {
                if unit == QUOTE {
                    quoted = !quoted;
                }
                !quoted && (separates(unit) || unit == SLASH || (self.plus && unit == PLUS))
            })
            .unwrap_or(rest.len());
        self.rest = &rest[end..];
        Some(Token::Name(&rest[..end]))
    }
}

/// Whether a switch's text is `name` (lowercase ASCII), whatever its case.
fn switch_is(switch: &[u16], name: &str) -> bool {
    crate::is_named(switch, name)
}

/// Why a built-in's argument was refused.
#[derive(Debug, PartialEq, Eq)]
pub enum Invalid<'a> {
    /// A switch the built-in does not take: what follows its `/`.
    Switch(&'a [u16]),
    /// Too few or too many names, or names where there can be none.
    Syntax,
}

/// What a built-in prints for an argument it refuses: `Invalid switch - /x` or the syntax's
/// message.
impl fmt::Display for Invalid<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Invalid::Switch(switch) => write!(f, "Invalid switch - /{}\r\n", Text(switch)),
            Invalid::Syntax => f.write_str(crate::SYNTAX),
        }
    }
}

/// Which files `del` (and `/A`) selects by their attributes: those with every `required` bit and
/// no `excluded` one, never a directory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Attributes {
    pub required: u32,
    pub excluded: u32,
}

impl Attributes {
    /// `del` without `/A`: hidden and system files left alone.
    pub const DEFAULT: Attributes = Attributes {
        required: 0,
        excluded: HIDDEN | SYSTEM,
    };

    /// Whether a file of `attributes` is selected.
    pub fn selects(&self, attributes: u32) -> bool {
        attributes & DIRECTORY == 0
            && attributes & self.required == self.required
            && attributes & self.excluded == 0
    }

    /// `/A`'s letters, after the `a` (and an optional `:`): `R`, `H`, `S`, `A`, each after a `-`
    /// for the files without it. `/A` alone selects every file. None for another letter.
    pub fn parse(letters: &[u16]) -> Option<Attributes> {
        let letters = letters.strip_prefix(&[u16::from(b':')]).unwrap_or(letters);
        let mut attributes = Attributes {
            required: 0,
            excluded: 0,
        };
        let mut not = false;
        for &unit in letters {
            let bit = match u8::try_from(fold(unit)).unwrap_or(0) {
                b'-' => {
                    not = true;
                    continue;
                }
                b'R' => READONLY,
                b'H' => HIDDEN,
                b'S' => SYSTEM,
                b'A' => ARCHIVE,
                _ => return None,
            };
            if core::mem::take(&mut not) {
                attributes.excluded |= bit;
            } else {
                attributes.required |= bit;
            }
        }
        Some(attributes)
    }
}

/// `del`'s switches (`del /?`): `/P` asks before each file, `/F` deletes read-only files too,
/// `/S` goes through the subdirectories, `/Q` deletes every file of a directory without asking,
/// `/A[[:]attributes]` selects files by their attributes.
#[derive(Debug, PartialEq, Eq)]
pub struct DeleteSwitches {
    pub prompt: bool,
    pub force: bool,
    pub subdirectories: bool,
    pub quiet: bool,
    pub attributes: Attributes,
}

/// `del`'s switches, wherever they are among its names.
pub fn delete_switches(argument: &[u16]) -> Result<DeleteSwitches, Invalid<'_>> {
    let mut switches = DeleteSwitches {
        prompt: false,
        force: false,
        subdirectories: false,
        quiet: false,
        attributes: Attributes::DEFAULT,
    };
    for token in Tokens::new(argument, false) {
        let Token::Switch(switch) = token else {
            continue;
        };
        match switch.first().map(|&unit| fold(unit)) {
            Some(unit) if unit == u16::from(b'A') => {
                switches.attributes =
                    Attributes::parse(&switch[1..]).ok_or(Invalid::Switch(switch))?;
            }
            _ if switch_is(switch, "p") => switches.prompt = true,
            _ if switch_is(switch, "f") => switches.force = true,
            _ if switch_is(switch, "s") => switches.subdirectories = true,
            _ if switch_is(switch, "q") => switches.quiet = true,
            _ => return Err(Invalid::Switch(switch)),
        }
    }
    Ok(switches)
}

/// `rd`'s switches (`rd /?`): `/S` removes the directory with all it holds, `/Q` without asking.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct RemoveSwitches {
    pub tree: bool,
    pub quiet: bool,
}

/// `rd`'s switches, wherever they are among its names.
pub fn remove_switches(argument: &[u16]) -> Result<RemoveSwitches, Invalid<'_>> {
    let mut switches = RemoveSwitches::default();
    for token in Tokens::new(argument, false) {
        match token {
            Token::Switch(switch) if switch_is(switch, "s") => switches.tree = true,
            Token::Switch(switch) if switch_is(switch, "q") => switches.quiet = true,
            Token::Switch(switch) => return Err(Invalid::Switch(switch)),
            _ => {}
        }
    }
    Ok(switches)
}

/// `md` takes no switch: the first one, refused.
pub fn no_switches(argument: &[u16]) -> Result<(), Invalid<'_>> {
    match Tokens::new(argument, false).find_map(|token| match token {
        Token::Switch(switch) => Some(switch),
        _ => None,
    }) {
        Some(switch) => Err(Invalid::Switch(switch)),
        None => Ok(()),
    }
}

/// How `copy` reads a source, or writes its destination (`/A`, `/B`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Text: a source read up to its first Ctrl+Z (0x1A), a Ctrl+Z written after the destination.
    Ascii,
    /// Bytes, all of them, as they are.
    Binary,
}

/// The Ctrl+Z an ASCII copy ends a file at, and ends its destination with.
pub const END_OF_FILE: u8 = 0x1A;

/// A file `copy` names, and the mode a switch gave it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CopyFile<'a> {
    pub name: &'a [u16],
    pub mode: Option<Mode>,
}

impl CopyFile<'_> {
    /// Its mode: the one a switch gave it, else `/A` for files joined (by `+` or a wildcard into
    /// one file) and `/B` for files copied one by one.
    pub fn mode(&self, joined: bool) -> Mode {
        self.mode
            .unwrap_or(if joined { Mode::Ascii } else { Mode::Binary })
    }
}

/// The sources one `copy` takes at most.
pub const SOURCES: usize = 16;

/// What `copy`'s argument says (`copy /?`): its sources, joined by `+` (`a+b`), its destination,
/// and whether it asks before replacing a file.
#[derive(Debug, PartialEq, Eq)]
pub struct Copy<'a> {
    sources: [CopyFile<'a>; SOURCES],
    count: usize,
    pub destination: Option<CopyFile<'a>>,
    /// Whether a `+` joined sources: they are copied into one file.
    pub joined: bool,
    /// `/Y` (Some(true): replace without asking) or `/-Y` (Some(false): ask), the last given.
    pub overwrite: Option<bool>,
}

impl<'a> Copy<'a> {
    pub fn sources(&self) -> &[CopyFile<'a>] {
        &self.sources[..self.count]
    }
}

/// `copy`'s argument read: its first names, joined by `+`, are its sources, and the name after
/// them, if any, its destination. `/A` and `/B` set the mode of the file before them and of the
/// files after them until the next; `/Y` and `/-Y` say whether to ask before replacing a file;
/// `/V`, `/N` and `/Z` are taken and change nothing. No source, a second name after the
/// destination, a `+` in it, or more than [`SOURCES`] sources is a syntax error.
pub fn copy(argument: &[u16]) -> Result<Copy<'_>, Invalid<'_>> {
    let mut copy = Copy {
        sources: [CopyFile {
            name: &[],
            mode: None,
        }; SOURCES],
        count: 0,
        destination: None,
        joined: false,
        overwrite: None,
    };
    let mut mode = None;
    let mut after_plus = false;
    for token in Tokens::new(argument, true) {
        match token {
            Token::Name(name) => {
                let file = CopyFile { name, mode };
                if copy.destination.is_some() {
                    return Err(Invalid::Syntax);
                }
                if copy.count == 0 || core::mem::take(&mut after_plus) {
                    *copy.sources.get_mut(copy.count).ok_or(Invalid::Syntax)? = file;
                    copy.count += 1;
                } else {
                    copy.destination = Some(file);
                }
            }
            Token::Plus => {
                if copy.count == 0 || copy.destination.is_some() {
                    return Err(Invalid::Syntax);
                }
                after_plus = true;
                copy.joined = true;
            }
            Token::Switch(switch) => {
                let switched = if switch_is(switch, "a") {
                    Some(Mode::Ascii)
                } else if switch_is(switch, "b") {
                    Some(Mode::Binary)
                } else {
                    if switch_is(switch, "y") {
                        copy.overwrite = Some(true);
                    } else if switch_is(switch, "-y") {
                        copy.overwrite = Some(false);
                    } else if !["v", "n", "z"].iter().any(|name| switch_is(switch, name)) {
                        return Err(Invalid::Switch(switch));
                    }
                    None
                };
                if let Some(switched) = switched {
                    mode = Some(switched);
                    let last = match &mut copy.destination {
                        Some(destination) => Some(destination),
                        None => copy
                            .count
                            .checked_sub(1)
                            .map(|last| &mut copy.sources[last]),
                    };
                    if let Some(last) = last {
                        last.mode = Some(switched);
                    }
                }
            }
        }
    }
    if copy.count == 0 {
        return Err(Invalid::Syntax);
    }
    Ok(copy)
}

/// Whether `/Y` or `/-Y` is among the COPYCMD variable's switches (the last one counts): Some(true)
/// for `/Y`, Some(false) for `/-Y`.
pub fn copycmd(value: &[u16]) -> Option<bool> {
    Tokens::new(value, false).fold(None, |overwrite, token| match token {
        Token::Switch(switch) if switch_is(switch, "y") => Some(true),
        Token::Switch(switch) if switch_is(switch, "-y") => Some(false),
        _ => overwrite,
    })
}

/// `ren`'s argument (`ren /?`): the file or files to rename, and their new name, which has no
/// drive or directory (it may hold wildcards). No switch is taken.
pub fn rename(argument: &[u16]) -> Result<(&[u16], &[u16]), Invalid<'_>> {
    no_switches(argument)?;
    let mut names = Tokens::new(argument, false).names();
    let (Some(from), Some(to), None) = (names.next(), names.next(), names.next()) else {
        return Err(Invalid::Syntax);
    };
    if to.iter().any(|&unit| is_separator(unit)) {
        return Err(Invalid::Syntax);
    }
    Ok((from, to))
}

/// What `move`'s argument says (`move /?`): the files to move, then where to.
#[derive(Debug, PartialEq, Eq)]
pub struct Move<'a> {
    argument: &'a [u16],
    /// How many names there are, the destination's included.
    names: usize,
    /// `/Y` (Some(true)) or `/-Y` (Some(false)), the last given.
    pub overwrite: Option<bool>,
}

impl<'a> Move<'a> {
    /// The files to move: every name but the last.
    pub fn sources(&self) -> impl Iterator<Item = &'a [u16]> {
        Tokens::new(self.argument, false)
            .names()
            .take(self.names - 1)
    }

    /// Where they go: the last name.
    pub fn destination(&self) -> &'a [u16] {
        Tokens::new(self.argument, false)
            .names()
            .last()
            .unwrap_or(&[])
    }
}

/// `move`'s argument read: two names at least, `/Y` and `/-Y` anywhere among them.
pub fn move_arguments(argument: &[u16]) -> Result<Move<'_>, Invalid<'_>> {
    let mut overwrite = None;
    let mut names = 0;
    for token in Tokens::new(argument, false) {
        match token {
            Token::Name(_) => names += 1,
            Token::Switch(switch) if switch_is(switch, "y") => overwrite = Some(true),
            Token::Switch(switch) if switch_is(switch, "-y") => overwrite = Some(false),
            Token::Switch(switch) => return Err(Invalid::Switch(switch)),
            Token::Plus => {}
        }
    }
    if names < 2 {
        return Err(Invalid::Syntax);
    }
    Ok(Move {
        argument,
        names,
        overwrite,
    })
}

/// Whether `unit` ends a path's directory part: `\`, `/` or a drive's `:`.
fn is_separator(unit: u16) -> bool {
    unit == u16::from(b'\\') || unit == SLASH || unit == u16::from(b':')
}

/// A path split into its directory, its last separator included (`sub\`, `C:`, or nothing), and
/// its last component.
pub fn split(path: &[u16]) -> (&[u16], &[u16]) {
    let at = path
        .iter()
        .rposition(|&unit| is_separator(unit))
        .map_or(0, |last| last + 1);
    path.split_at(at)
}

/// Whether a path names its directory: it ends with a separator (`sub\`, `C:`), or its last
/// component is `.` or `..`.
pub fn names_directory(path: &[u16]) -> bool {
    let (directory, name) = split(path);
    (name.is_empty() && !directory.is_empty()) || name == [DOT] || name == [DOT, DOT]
}

/// `directory`, a separator unless it ends with one (or is empty), then `name`, in `out`: None
/// when it does not fit.
pub fn join<'a>(directory: &[u16], name: &[u16], out: &'a mut [u16]) -> Option<&'a [u16]> {
    let separator: &[u16] = match directory.last() {
        None => &[],
        Some(&unit) if is_separator(unit) => &[],
        Some(_) => &[b'\\' as u16],
    };
    let length = directory.len() + separator.len() + name.len();
    let target = out.get_mut(..length)?;
    target[..directory.len()].copy_from_slice(directory);
    target[directory.len()..directory.len() + separator.len()].copy_from_slice(separator);
    target[directory.len() + separator.len()..].copy_from_slice(name);
    Some(&out[..length])
}

const STAR: u16 = b'*' as u16;
const QUESTION: u16 = b'?' as u16;
const DOT: u16 = b'.' as u16;

/// Whether a name holds a wildcard, `*` or `?`.
pub fn has_wildcards(name: &[u16]) -> bool {
    name.iter().any(|&unit| unit == STAR || unit == QUESTION)
}

/// Whether a name matches every file of its directory, as `*` and `*.*` do: `del` asks before
/// deleting them all.
pub fn matches_all(name: &[u16]) -> bool {
    name == [STAR] || name == [STAR, DOT, STAR]
}

/// Whether a name found in a directory is `.` or `..`, which no built-in works on.
pub fn is_dots(name: &[u16]) -> bool {
    name == [DOT] || name == [DOT, DOT]
}

/// Whether two full paths name the same file, whatever the case of their ASCII letters.
pub fn same_path(a: &[u16], b: &[u16]) -> bool {
    a.len() == b.len() && a.iter().zip(b).all(|(&a, &b)| fold(a) == fold(b))
}

/// The new name a wildcard `mask` gives the file `name`, as `ren` and `copy` give it, in `out`
/// (None when it does not fit). The mask is read from its start, a position kept in the name:
/// - `?` takes the name's next character, unless the name is at a `.` or its end;
/// - `*` at the mask's end takes the rest of the name; `*` before a character `c` takes the name up
///   to its last `c` and that `c` (the rest of the name, then `c`, when there is none), the mask's
///   `c` with it;
/// - `.` moves past the name's next `.` (to its end without one) and writes a `.`;
/// - any other character is written, and the name's next character skipped unless it is a `.`.
///
/// Dots and blanks the new name ends with are dropped.
pub fn rename_target<'a>(name: &[u16], mask: &[u16], out: &'a mut [u16]) -> Option<&'a [u16]> {
    let mut length = 0;
    let mut push = |units: &[u16], length: &mut usize| -> Option<()> {
        out.get_mut(*length..*length + units.len())?
            .copy_from_slice(units);
        *length += units.len();
        Some(())
    };
    let mut at = 0;
    let mut mask_at = 0;
    while mask_at < mask.len() {
        let unit = mask[mask_at];
        mask_at += 1;
        match unit {
            QUESTION => {
                if let Some(&next) = name.get(at) {
                    if next != DOT {
                        push(&[next], &mut length)?;
                        at += 1;
                    }
                }
            }
            STAR => {
                // `*?` and `**` take the rest of the name, as `*` at the end does.
                while mask.get(mask_at) == Some(&QUESTION) || mask.get(mask_at) == Some(&STAR) {
                    mask_at += 1;
                }
                let Some(&until) = mask.get(mask_at) else {
                    push(&name[at.min(name.len())..], &mut length)?;
                    at = name.len();
                    continue;
                };
                mask_at += 1;
                let rest = &name[at.min(name.len())..];
                match rest.iter().rposition(|&unit| unit == until) {
                    Some(last) => {
                        push(&rest[..=last], &mut length)?;
                        at += last + 1;
                    }
                    None => {
                        push(rest, &mut length)?;
                        push(&[until], &mut length)?;
                        at = name.len();
                    }
                }
            }
            DOT => {
                let rest = &name[at.min(name.len())..];
                at += rest
                    .iter()
                    .position(|&unit| unit == DOT)
                    .map_or(rest.len(), |dot| dot + 1);
                push(&[DOT], &mut length)?;
            }
            _ => {
                push(&[unit], &mut length)?;
                if name.get(at).is_some_and(|&next| next != DOT) {
                    at += 1;
                }
            }
        }
    }
    let kept = out[..length]
        .iter()
        .rposition(|&unit| unit != DOT && unit != u16::from(b' '))
        .map_or(0, |last| last + 1);
    Some(&out[..kept])
}

/// What `del` prints when a name matches no file: `Could Not Find` and the name made full.
pub struct CouldNotFind<'a>(pub &'a [u16]);

impl fmt::Display for CouldNotFind<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Could Not Find {}\r\n", Text(self.0))
    }
}

/// What `del` asks before deleting every file of a directory (the full path then `\*`), and
/// `rd /s` before removing a directory (its name as given).
pub struct AreYouSure<'a>(pub &'a [u16]);

impl fmt::Display for AreYouSure<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}, Are you sure (Y/N)? ", Text(self.0))
    }
}

/// What `del /p` asks before deleting a file, its full path.
pub struct DeleteFile<'a>(pub &'a [u16]);

impl fmt::Display for DeleteFile<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}, Delete (Y/N)? ", Text(self.0))
    }
}

/// What `del /s` prints for each file it deletes, its full path.
pub struct Deleted<'a>(pub &'a [u16]);

impl fmt::Display for Deleted<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Deleted file - {}\r\n", Text(self.0))
    }
}

/// What `copy` and `move` ask before replacing a file, its full path.
pub struct Overwrite<'a>(pub &'a [u16]);

impl fmt::Display for Overwrite<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Overwrite {}? (Yes/No/All): ", Text(self.0))
    }
}

/// What `copy` prints once done: how many files it wrote, right-aligned in nine columns.
pub struct Copied(pub usize);

impl fmt::Display for Copied {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:9} file(s) copied.\r\n", self.0)
    }
}

/// What `md` prints when the name is taken.
pub struct AlreadyExists<'a>(pub &'a [u16]);

impl fmt::Display for AlreadyExists<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "A subdirectory or file {} already exists.\r\n",
            Text(self.0)
        )
    }
}

/// An answer to [`Overwrite`]'s question.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Answer {
    Yes,
    No,
    /// Yes, and to every question after it.
    All,
}

/// The answer a line gives to [`Overwrite`]'s question: `y`, `n` or `a`, in either case, blanks
/// around it; None for anything else (the question is asked again).
pub fn overwrite_answer(line: &[u16]) -> Option<Answer> {
    match crate::trim(line) {
        [unit] => match u8::try_from(fold(*unit)).unwrap_or(0) {
            b'Y' => Some(Answer::Yes),
            b'N' => Some(Answer::No),
            b'A' => Some(Answer::All),
            _ => None,
        },
        _ => None,
    }
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

    fn tokens(argument: &str, plus: bool) -> Vec<String> {
        Tokens::new(&wide(argument), plus)
            .map(|token| match token {
                Token::Name(name) => narrow(name),
                Token::Switch(switch) => format!("/{}", narrow(switch)),
                Token::Plus => "+".to_string(),
            })
            .collect()
    }

    #[test]
    fn tokens_split_at_separators_switches_and_plus() {
        assert_eq!(
            tokens(" a.txt  b,c;d=e ", false),
            ["a.txt", "b", "c", "d", "e"]
        );
        assert_eq!(tokens("\"a b.txt\" c", false), ["\"a b.txt\"", "c"]);
        assert_eq!(tokens("/q/s a /A:-h", false), ["/q", "/s", "a", "/A:-h"]);
        assert_eq!(tokens("a.txt/q", false), ["a.txt", "/q"]);
        assert_eq!(tokens("a+b c", false), ["a+b", "c"]);
        assert_eq!(tokens("a+b c", true), ["a", "+", "b", "c"]);
        assert_eq!(tokens("a + \"b+c\"", true), ["a", "+", "\"b+c\""]);
        assert_eq!(tokens("", false), Vec::<String>::new());
    }

    #[test]
    fn del_switches() {
        let switches = delete_switches(&wide("/q a /F /s")).unwrap();
        assert!(switches.quiet && switches.force && switches.subdirectories && !switches.prompt);
        assert_eq!(switches.attributes, Attributes::DEFAULT);
        assert!(delete_switches(&wide("/p")).unwrap().prompt);
        let all = delete_switches(&wide("/a x")).unwrap().attributes;
        assert_eq!(
            all,
            Attributes {
                required: 0,
                excluded: 0
            }
        );
        let read_only = delete_switches(&wide("/A:R-h x")).unwrap().attributes;
        assert_eq!(
            read_only,
            Attributes {
                required: READONLY,
                excluded: HIDDEN
            }
        );
        assert_eq!(
            delete_switches(&wide("/x a")),
            Err(Invalid::Switch(&wide("x")))
        );
        assert_eq!(
            delete_switches(&wide("/a:z a")),
            Err(Invalid::Switch(&wide("a:z")))
        );
    }

    #[test]
    fn attributes_select_files_never_directories() {
        let default = Attributes::DEFAULT;
        assert!(default.selects(ARCHIVE));
        assert!(default.selects(READONLY));
        assert!(!default.selects(HIDDEN));
        assert!(!default.selects(SYSTEM | ARCHIVE));
        assert!(!default.selects(DIRECTORY));
        let all = Attributes::parse(&[]).unwrap();
        assert!(all.selects(HIDDEN | SYSTEM));
        assert!(!all.selects(DIRECTORY));
        let read_only = Attributes::parse(&wide("r")).unwrap();
        assert!(read_only.selects(READONLY | HIDDEN));
        assert!(!read_only.selects(ARCHIVE));
    }

    #[test]
    fn rd_and_md_switches() {
        assert_eq!(
            remove_switches(&wide("/s /Q d")),
            Ok(RemoveSwitches {
                tree: true,
                quiet: true
            })
        );
        assert_eq!(remove_switches(&wide("d")), Ok(RemoveSwitches::default()));
        assert_eq!(
            remove_switches(&wide("/f d")),
            Err(Invalid::Switch(&wide("f")))
        );
        assert_eq!(no_switches(&wide("a b")), Ok(()));
        assert_eq!(no_switches(&wide("a /x")), Err(Invalid::Switch(&wide("x"))));
    }

    fn files(copy: &Copy<'_>) -> Vec<(String, Option<Mode>)> {
        copy.sources()
            .iter()
            .map(|file| (narrow(file.name), file.mode))
            .collect()
    }

    #[test]
    fn copy_a_source_and_a_destination() {
        let argument = wide("a.txt b.txt");
        let copy = copy(&argument).unwrap();
        assert_eq!(files(&copy), [("a.txt".to_string(), None)]);
        assert_eq!(
            copy.destination.map(|file| narrow(file.name)),
            Some("b.txt".into())
        );
        assert!(!copy.joined);
        assert_eq!(copy.overwrite, None);
        let argument = wide("a.txt");
        let alone = super::copy(&argument).unwrap();
        assert_eq!(alone.destination, None);
    }

    #[test]
    fn copy_joins_sources_with_plus() {
        let argument = wide("a+b + c d");
        let copy = copy(&argument).unwrap();
        assert!(copy.joined);
        assert_eq!(
            files(&copy),
            [("a".into(), None), ("b".into(), None), ("c".into(), None)]
        );
        assert_eq!(
            copy.destination.map(|file| narrow(file.name)),
            Some("d".into())
        );
        let argument = wide("a+b");
        let appended = super::copy(&argument).unwrap();
        assert!(appended.joined && appended.destination.is_none());
    }

    #[test]
    fn copy_modes_apply_to_the_file_before_and_the_files_after() {
        let argument = wide("a /b + b + c /a d");
        let copy = copy(&argument).unwrap();
        assert_eq!(
            files(&copy),
            [
                ("a".into(), Some(Mode::Binary)),
                ("b".into(), Some(Mode::Binary)),
                ("c".into(), Some(Mode::Ascii)),
            ]
        );
        assert_eq!(copy.destination.unwrap().mode, Some(Mode::Ascii));
        let argument = wide("x y /b");
        let destination = super::copy(&argument).unwrap().destination.unwrap();
        assert_eq!(destination.mode, Some(Mode::Binary));
        let file = CopyFile {
            name: &[],
            mode: None,
        };
        assert_eq!(file.mode(true), Mode::Ascii);
        assert_eq!(file.mode(false), Mode::Binary);
    }

    #[test]
    fn copy_switches_and_errors() {
        let argument = wide("/y a b /-Y /v /n /z");
        assert_eq!(copy(&argument).unwrap().overwrite, Some(false));
        let argument = wide("/Y a b");
        assert_eq!(copy(&argument).unwrap().overwrite, Some(true));
        assert_eq!(copy(&wide("")), Err(Invalid::Syntax));
        assert_eq!(copy(&wide("/y")), Err(Invalid::Syntax));
        assert_eq!(copy(&wide("a b c")), Err(Invalid::Syntax));
        assert_eq!(copy(&wide("a b+c")), Err(Invalid::Syntax));
        assert_eq!(copy(&wide("+a b")), Err(Invalid::Syntax));
        assert_eq!(copy(&wide("a b /d")), Err(Invalid::Switch(&wide("d"))));
        let many = vec!["f"; SOURCES + 1].join("+");
        assert_eq!(copy(&wide(&many)), Err(Invalid::Syntax));
    }

    #[test]
    fn copycmd_presets_the_question() {
        assert_eq!(copycmd(&wide("/Y")), Some(true));
        assert_eq!(copycmd(&wide("/y /-y")), Some(false));
        assert_eq!(copycmd(&wide("/v")), None);
        assert_eq!(copycmd(&wide("")), None);
    }

    #[test]
    fn ren_takes_two_names_the_second_without_a_directory() {
        let argument = wide("a.txt b.txt");
        assert_eq!(
            rename(&argument),
            Ok((&wide("a.txt")[..], &wide("b.txt")[..]))
        );
        let argument = wide("sub\\*.txt *.bak");
        assert_eq!(
            rename(&argument),
            Ok((&wide("sub\\*.txt")[..], &wide("*.bak")[..]))
        );
        assert_eq!(rename(&wide("a")), Err(Invalid::Syntax));
        assert_eq!(rename(&wide("a b c")), Err(Invalid::Syntax));
        assert_eq!(rename(&wide("a sub\\b")), Err(Invalid::Syntax));
        assert_eq!(rename(&wide("a C:b")), Err(Invalid::Syntax));
        assert_eq!(rename(&wide("a b /q")), Err(Invalid::Switch(&wide("q"))));
    }

    #[test]
    fn move_takes_sources_then_a_destination() {
        let argument = wide("/y a, b dir");
        let parsed = move_arguments(&argument).unwrap();
        assert_eq!(parsed.overwrite, Some(true));
        assert_eq!(parsed.sources().map(narrow).collect::<Vec<_>>(), ["a", "b"]);
        assert_eq!(narrow(parsed.destination()), "dir");
        assert_eq!(move_arguments(&wide("a")), Err(Invalid::Syntax));
        assert_eq!(
            move_arguments(&wide("a b /x")),
            Err(Invalid::Switch(&wide("x")))
        );
    }

    #[test]
    fn paths_split_and_join() {
        let split_of = |path: &str| {
            let path = wide(path);
            let (directory, name) = split(&path);
            (narrow(directory), narrow(name))
        };
        assert_eq!(split_of("C:\\a\\b.txt"), ("C:\\a\\".into(), "b.txt".into()));
        assert_eq!(split_of("C:b.txt"), ("C:".into(), "b.txt".into()));
        assert_eq!(split_of("sub/x"), ("sub/".into(), "x".into()));
        assert_eq!(split_of("b.txt"), ("".into(), "b.txt".into()));
        let mut out = [0; 32];
        let join_of = |directory: &str, name: &str, out: &mut [u16]| {
            join(&wide(directory), &wide(name), out).map(narrow)
        };
        assert_eq!(join_of("sub", "a", &mut out), Some("sub\\a".into()));
        assert_eq!(join_of("sub\\", "a", &mut out), Some("sub\\a".into()));
        assert_eq!(join_of("C:", "a", &mut out), Some("C:a".into()));
        assert_eq!(join_of("", "a", &mut out), Some("a".into()));
        assert_eq!(join_of("long", "name", &mut out[..5]), None);
        assert!(names_directory(&wide("sub\\")));
        assert!(names_directory(&wide("..")));
        assert!(names_directory(&wide("C:")));
        assert!(!names_directory(&wide("sub")));
    }

    #[test]
    fn wildcards() {
        assert!(has_wildcards(&wide("*.txt")));
        assert!(has_wildcards(&wide("a?.txt")));
        assert!(!has_wildcards(&wide("a.txt")));
        assert!(matches_all(&wide("*")));
        assert!(matches_all(&wide("*.*")));
        assert!(!matches_all(&wide("*.txt")));
        assert!(is_dots(&wide(".")) && is_dots(&wide("..")) && !is_dots(&wide("...a")));
        assert!(same_path(&wide("C:\\A\\b.TXT"), &wide("c:\\a\\B.txt")));
        assert!(!same_path(&wide("C:\\a"), &wide("C:\\ab")));
    }

    fn renamed(name: &str, mask: &str) -> String {
        let mut out = [0; 64];
        narrow(rename_target(&wide(name), &wide(mask), &mut out).unwrap())
    }

    #[test]
    fn rename_masks() {
        assert_eq!(renamed("a.txt", "*.bak"), "a.bak");
        assert_eq!(renamed("foo.tar.gz", "*.bak"), "foo.tar.bak");
        assert_eq!(renamed("a.txt", "b.*"), "b.txt");
        assert_eq!(renamed("abc.txt", "?x?.*"), "axc.txt");
        assert_eq!(renamed("a.txt", "???.*"), "a.txt");
        assert_eq!(renamed("abc.txt", "*"), "abc.txt");
        assert_eq!(renamed("readme", "*.txt"), "readme.txt");
        assert_eq!(renamed("abc.txt", "*c.*"), "abc.txt");
        assert_eq!(renamed("abcdef.txt", "x*"), "xbcdef.txt");
        assert_eq!(renamed("a.txt", "*."), "a");
        assert_eq!(renamed("a.txt", "new.name"), "new.name");
        let mut short = [0; 2];
        assert_eq!(rename_target(&wide("abc"), &wide("*"), &mut short), None);
    }

    #[test]
    fn messages() {
        assert_eq!(
            CouldNotFind(&wide("C:\\x\\a.txt")).to_string(),
            "Could Not Find C:\\x\\a.txt\r\n"
        );
        assert_eq!(
            AreYouSure(&wide("C:\\x\\*")).to_string(),
            "C:\\x\\*, Are you sure (Y/N)? "
        );
        assert_eq!(
            DeleteFile(&wide("C:\\a")).to_string(),
            "C:\\a, Delete (Y/N)? "
        );
        assert_eq!(
            Deleted(&wide("C:\\a")).to_string(),
            "Deleted file - C:\\a\r\n"
        );
        assert_eq!(
            Overwrite(&wide("C:\\b")).to_string(),
            "Overwrite C:\\b? (Yes/No/All): "
        );
        assert_eq!(Copied(1).to_string(), "        1 file(s) copied.\r\n");
        assert_eq!(Copied(12).to_string(), "       12 file(s) copied.\r\n");
        assert_eq!(
            AlreadyExists(&wide("d")).to_string(),
            "A subdirectory or file d already exists.\r\n"
        );
        assert_eq!(
            Invalid::Switch(&wide("x")).to_string(),
            "Invalid switch - /x\r\n"
        );
        assert_eq!(Invalid::Syntax.to_string(), crate::SYNTAX);
        assert_eq!(message(ERROR_DIR_NOT_EMPTY), Some(NOT_EMPTY));
        assert_eq!(message(2), crate::message(2));
        assert_eq!(message(9999), None);
    }

    #[test]
    fn overwrite_answers() {
        assert_eq!(overwrite_answer(&wide("y\r\n")), Some(Answer::Yes));
        assert_eq!(overwrite_answer(&wide(" N \r\n")), Some(Answer::No));
        assert_eq!(overwrite_answer(&wide("a\r\n")), Some(Answer::All));
        assert_eq!(overwrite_answer(&wide("yes\r\n")), None);
        assert_eq!(overwrite_answer(&wide("\r\n")), None);
    }
}
