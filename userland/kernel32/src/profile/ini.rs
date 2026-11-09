//! A profile's text, as the profile calls read and edit it: pure code over the file's units (an
//! ANSI file's bytes widened through the ANSI code page, one unit a byte), host-tested.
//!
//! The text is lines, each ended by LF (a CR before it is not part of the line). A line is
//! classified by its first unit that is not a blank (a space or a tab):
//!
//! - none: a blank line;
//! - `;`: a comment;
//! - `[`: a section's header, its name what follows up to `]` (or the line's end), blanks around it
//!   dropped (`[ Padded ]` is `Padded`);
//! - anything else: an entry of the section above it (a line above every header belongs to none).
//!   An entry with `=` is a key: its name what comes before the first `=`, its value what comes
//!   after, blanks around each dropped, and a value both begun and ended by the same quote (`"` or
//!   `'`) read without them. An entry without `=` is no key: a section's listing shows it, a key's
//!   lookup never finds it.
//!
//! Names match without regard to case, the caller's with its blanks dropped too. A name is looked
//! up in the first section of its name only: a later section of the same name is listed among the
//! sections, but none of its keys is found, and a write goes to the first one.
//!
//! The edits ([`Splice`]) keep every other line's bytes as they were. A key's value is replaced
//! after its `=`, the key's spelling left as the file has it. A new key goes after the section's
//! last entry (before the comments and blank lines that follow it), a new section at the file's
//! end, each line ended by CR LF. A deleted key goes from its first unit that is not a blank
//! through its line's end (the blanks before it stay, ahead of the next line); a deleted section
//! from its header through its last entry's line (the comments and blank lines after that stay).
//! The Windows 2000 machine's capture of the profile fixture shows each of these with comments;
//! blank lines are taken to go as comments do. A replaced section's lines are the caller's as
//! written; a write's names are the caller's as given.

use core::iter::once;
use core::ops::Range;

/// The units the parser tells apart.
const TAB: u16 = 0x09;
const LF: u16 = 0x0A;
const CR: u16 = 0x0D;
const SPACE: u16 = 0x20;
const DOUBLE_QUOTE: u16 = 0x22;
const SINGLE_QUOTE: u16 = 0x27;
const SLASH: u16 = 0x2F;
const COLON: u16 = 0x3A;
const SEMICOLON: u16 = 0x3B;
const EQUALS: u16 = 0x3D;
const OPEN_BRACKET: u16 = 0x5B;
const BACKSLASH: u16 = 0x5C;
const CLOSE_BRACKET: u16 = 0x5D;

/// A line's end, as the edits write it.
pub const CRLF: &[u16] = &[CR, LF];
const OPEN: &[u16] = &[OPEN_BRACKET];
const CLOSE: &[u16] = &[CLOSE_BRACKET];
const ASSIGN: &[u16] = &[EQUALS];

/// Whether a unit is a blank: a space or a tab.
fn is_blank(unit: u16) -> bool {
    unit == SPACE || unit == TAB
}

/// `range` of `text` without the blanks at either end.
fn trim(text: &[u16], range: Range<usize>) -> Range<usize> {
    let Range { mut start, mut end } = range;
    while start < end && is_blank(text[start]) {
        start += 1;
    }
    while end > start && is_blank(text[end - 1]) {
        end -= 1;
    }
    start..end
}

/// A caller's name without the blanks at either end, as the lookups take it.
pub fn trimmed(name: &[u16]) -> &[u16] {
    &name[trim(name, 0..name.len())]
}

/// A default string without its trailing blanks, as the string lookups hand it back.
pub fn without_trailing_blanks(text: &[u16]) -> &[u16] {
    let end = text
        .iter()
        .rposition(|&unit| !is_blank(unit))
        .map_or(0, |at| at + 1);
    &text[..end]
}

/// Whether two names are the same, without regard to case.
fn same(a: &[u16], b: &[u16]) -> bool {
    a.len() == b.len()
        && a.iter()
            .zip(b)
            .all(|(&a, &b)| rtl::path::upcase(a) == rtl::path::upcase(b))
}

/// What a line is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Blank,
    Comment,
    Header,
    Entry,
}

/// One line of the text, as offsets into it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Line {
    /// Its first unit that is not a blank (its end, for a blank line).
    pub lead: usize,
    /// Where its content ends: its LF, or the CR before it, or the text's end.
    pub end: usize,
    /// Where the next line starts: past its LF, or the text's end.
    pub next: usize,
    pub kind: Kind,
    /// A header's section name; a key's name; an entry without `=`, the whole entry; blanks
    /// around each dropped.
    pub name: Range<usize>,
    /// A key's `=`.
    pub equals: Option<usize>,
}

impl Line {
    /// A key's value as the file has it, the blanks around it dropped (the empty one for an entry
    /// without `=`).
    pub fn raw_value<'a>(&self, text: &'a [u16]) -> &'a [u16] {
        match self.equals {
            Some(equals) => &text[trim(text, equals + 1..self.end)],
            None => &[],
        }
    }

    /// A key's value as the lookups hand it back: [`Line::raw_value`], without the quotes when it
    /// both begins and ends with the same one.
    pub fn value<'a>(&self, text: &'a [u16]) -> &'a [u16] {
        let value = self.raw_value(text);
        match value {
            [first, .., last]
                if first == last && (*first == DOUBLE_QUOTE || *first == SINGLE_QUOTE) =>
            {
                &value[1..value.len() - 1]
            }
            _ => value,
        }
    }

    /// Whether the line is a key: an entry with `=`.
    pub fn is_key(&self) -> bool {
        self.kind == Kind::Entry && self.equals.is_some()
    }
}

/// The lines of a text from an offset on.
#[derive(Clone)]
pub struct Lines<'a> {
    text: &'a [u16],
    at: usize,
}

impl<'a> Lines<'a> {
    /// The lines of `text` from `at`, the start of one.
    pub fn from(text: &'a [u16], at: usize) -> Lines<'a> {
        Lines { text, at }
    }
}

impl Iterator for Lines<'_> {
    type Item = Line;

    fn next(&mut self) -> Option<Line> {
        let text = self.text;
        let start = self.at;
        if start >= text.len() {
            return None;
        }
        let (mut end, next) = match text[start..].iter().position(|&unit| unit == LF) {
            Some(at) => (start + at, start + at + 1),
            None => (text.len(), text.len()),
        };
        if end > start && text[end - 1] == CR {
            end -= 1;
        }
        self.at = next;
        let lead = trim(text, start..end).start;
        let (kind, name, equals) = match text.get(lead) {
            _ if lead == end => (Kind::Blank, lead..lead, None),
            Some(&SEMICOLON) => (Kind::Comment, lead..lead, None),
            Some(&OPEN_BRACKET) => {
                let close = text[lead + 1..end]
                    .iter()
                    .position(|&unit| unit == CLOSE_BRACKET)
                    .map_or(end, |at| lead + 1 + at);
                (Kind::Header, trim(text, lead + 1..close), None)
            }
            _ => match text[lead..end].iter().position(|&unit| unit == EQUALS) {
                Some(at) => (Kind::Entry, trim(text, lead..lead + at), Some(lead + at)),
                None => (Kind::Entry, trim(text, lead..end), None),
            },
        };
        Some(Line {
            lead,
            end,
            next,
            kind,
            name,
            equals,
        })
    }
}

/// The headers of every section, in the file's order (a repeated name each time).
pub fn headers(text: &[u16]) -> impl Iterator<Item = Line> + Clone + '_ {
    Lines::from(text, 0).filter(|line| line.kind == Kind::Header)
}

/// A section the lookups found: its header, and where its last entry's line ends (the header's
/// own end when it has no entry).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Section {
    pub header: Line,
    pub entries_end: usize,
}

impl Section {
    /// Its entries, keys or not, in the file's order.
    pub fn entries<'a>(&self, text: &'a [u16]) -> impl Iterator<Item = Line> + Clone + 'a {
        Lines::from(text, self.header.next)
            .take_while(|line| line.kind != Kind::Header)
            .filter(|line| line.kind == Kind::Entry)
    }

    /// Its keys, in the file's order (a repeated name each time).
    pub fn keys<'a>(&self, text: &'a [u16]) -> impl Iterator<Item = Line> + Clone + 'a {
        self.entries(text).filter(Line::is_key)
    }

    /// The first key of `name` (any case, the caller's blanks dropped).
    pub fn key(&self, text: &[u16], name: &[u16]) -> Option<Line> {
        let name = trimmed(name);
        self.keys(text)
            .find(|line| same(&text[line.name.clone()], name))
    }
}

/// The first section of `name` (any case, the caller's blanks dropped).
pub fn section(text: &[u16], name: &[u16]) -> Option<Section> {
    let name = trimmed(name);
    let header = headers(text).find(|header| same(&text[header.name.clone()], name))?;
    let entries_end = Lines::from(text, header.next)
        .take_while(|line| line.kind != Kind::Header)
        .filter(|line| line.kind == Kind::Entry)
        .last()
        .map_or(header.next, |line| line.next);
    Some(Section {
        header,
        entries_end,
    })
}

/// A key's value as the string lookups hand it back ([`Line::value`]); none when the section or
/// the key is missing.
pub fn value<'a>(text: &'a [u16], section_name: &[u16], key: &[u16]) -> Option<&'a [u16]> {
    let line = section(text, section_name)?.key(text, key)?;
    Some(line.value(text))
}

/// Names as a list: each followed by a NUL, then one more NUL.
fn list<'a>(
    names: impl Iterator<Item = &'a [u16]> + Clone + 'a,
) -> impl Iterator<Item = u16> + Clone + 'a {
    names
        .flat_map(|name| name.iter().copied().chain(once(0)))
        .chain(once(0))
}

/// The list of every section's name, in the file's order.
pub fn section_names(text: &[u16]) -> impl Iterator<Item = u16> + Clone + '_ {
    list(headers(text).map(move |header| &text[header.name]))
}

/// The list of a section's key names, in the file's order.
pub fn key_names<'a>(text: &'a [u16], section: &Section) -> impl Iterator<Item = u16> + Clone + 'a {
    list(section.keys(text).map(move |line| &text[line.name]))
}

/// The list of a section's entries, as GetPrivateProfileSection hands them back: a key as its name,
/// `=` and its value, the blanks around each dropped (its quotes kept); an entry without `=` as it
/// is, the blanks around it dropped.
pub fn section_entries<'a>(
    text: &'a [u16],
    section: &Section,
) -> impl Iterator<Item = u16> + Clone + 'a {
    section
        .entries(text)
        .flat_map(move |line| {
            let (assign, value) = match line.equals {
                Some(_) => (ASSIGN, line.raw_value(text)),
                None => (&[][..], &[][..]),
            };
            text[line.name]
                .iter()
                .chain(assign)
                .chain(value)
                .copied()
                .chain(once(0))
        })
        .chain(once(0))
}

/// What of an answer goes into a caller's buffer of `size` units.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fit {
    /// The answer's first units written.
    pub units: usize,
    /// The NULs written after them.
    pub terminators: usize,
    /// The call's return value.
    pub count: u32,
    /// Whether the whole answer fit.
    pub whole: bool,
}

/// A string of `length` units in a buffer of `size`: the string and its NUL when they fit (the
/// string's length returned); otherwise its first `size - 1` units and a NUL (`size - 1`
/// returned); nothing at all in no room.
pub fn fit_string(length: usize, size: usize) -> Fit {
    if size == 0 {
        return Fit {
            units: 0,
            terminators: 0,
            count: 0,
            whole: false,
        };
    }
    let units = length.min(size - 1);
    Fit {
        units,
        terminators: 1,
        count: units as u32,
        whole: units == length,
    }
}

/// A list of `length` units, its final NUL counted, in a buffer of `size`: the whole list when it
/// fits (its length less the final NUL returned); otherwise its first `size - 2` units and two
/// NULs (`size - 2` returned) — a name cut where the room ends; in a buffer of one unit, a NUL;
/// nothing at all in no room.
pub fn fit_list(length: usize, size: usize) -> Fit {
    if length <= size {
        return Fit {
            units: length,
            terminators: 0,
            count: length.saturating_sub(1) as u32,
            whole: true,
        };
    }
    let units = size.saturating_sub(2);
    Fit {
        units,
        terminators: size - units,
        count: units as u32,
        whole: false,
    }
}

/// A change to the text: the units of `remove` replaced by `parts`, one after the other.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Splice<'a> {
    pub remove: Range<usize>,
    pub parts: [&'a [u16]; 9],
}

impl<'a> Splice<'a> {
    /// A splice of `remove` by up to nine parts.
    fn new(remove: Range<usize>, parts: &[&'a [u16]]) -> Splice<'a> {
        let mut all: [&[u16]; 9] = [&[]; 9];
        all[..parts.len()].copy_from_slice(parts);
        Splice { remove, parts: all }
    }

    /// The new text's pieces, one after the other: the text before the change, the parts, the text
    /// after it.
    pub fn pieces(&self, text: &'a [u16]) -> [&'a [u16]; 11] {
        let mut pieces: [&[u16]; 11] = [&[]; 11];
        pieces[0] = &text[..self.remove.start];
        pieces[1..10].copy_from_slice(&self.parts);
        pieces[10] = &text[self.remove.end..];
        pieces
    }
}

/// The line end a text needs before a line added at `at`: none at a line's start, CR LF at the end
/// of a text whose last line has no LF.
fn line_break(text: &[u16], at: usize) -> &'static [u16] {
    if at == 0 || text[at - 1] == LF {
        &[]
    } else {
        CRLF
    }
}

/// A key written: its value replaced when the section has the key, otherwise the key added after
/// the section's last entry, otherwise the section added at the text's end with the key.
pub fn write_key<'a>(
    text: &'a [u16],
    section_name: &'a [u16],
    key: &'a [u16],
    value: &'a [u16],
) -> Splice<'a> {
    match section(text, section_name) {
        Some(found) => match found.key(text, key) {
            Some(line) => {
                let after = line.equals.expect("a key has its '='") + 1;
                Splice::new(after..line.end, &[value])
            }
            None => {
                let at = found.entries_end;
                Splice::new(at..at, &[line_break(text, at), key, ASSIGN, value, CRLF])
            }
        },
        None => {
            let at = text.len();
            Splice::new(
                at..at,
                &[
                    line_break(text, at),
                    OPEN,
                    section_name,
                    CLOSE,
                    CRLF,
                    key,
                    ASSIGN,
                    value,
                    CRLF,
                ],
            )
        }
    }
}

/// A key deleted: none when the section or the key is missing.
pub fn delete_key<'a>(text: &[u16], section_name: &[u16], key: &[u16]) -> Option<Splice<'a>> {
    let line = section(text, section_name)?.key(text, key)?;
    Some(Splice::new(line.lead..line.next, &[]))
}

/// A section deleted, its header and entries: none when it is missing.
pub fn delete_section<'a>(text: &[u16], section_name: &[u16]) -> Option<Splice<'a>> {
    let found = section(text, section_name)?;
    Some(Splice::new(found.header.lead..found.entries_end, &[]))
}

/// A section's entries replaced by `body` (lines each ended by CR LF, [`section_body`]), or the
/// section added at the text's end with it.
pub fn write_section<'a>(text: &'a [u16], section_name: &'a [u16], body: &'a [u16]) -> Splice<'a> {
    match section(text, section_name) {
        Some(found) => {
            let at = found.header.next;
            Splice::new(at..found.entries_end, &[line_break(text, at), body])
        }
        None => {
            let at = text.len();
            Splice::new(
                at..at,
                &[line_break(text, at), OPEN, section_name, CLOSE, CRLF, body],
            )
        }
    }
}

/// A caller's list of entries (each NUL-terminated, an empty one last) as a section's lines: each
/// entry as it is, ended by CR LF.
pub fn section_body(list: &[u16]) -> impl Iterator<Item = u16> + Clone + '_ {
    list.split(|&unit| unit == 0)
        .take_while(|entry| !entry.is_empty())
        .flat_map(|entry| entry.iter().chain(CRLF).copied())
}

/// Whether a profile's file name names a file of the Windows directory: a name without a
/// directory or a drive in it. A name with one is the file it names, a relative one under the
/// current directory (`.\app.ini`).
pub fn in_windows_directory(name: &[u16]) -> bool {
    !name
        .iter()
        .any(|&unit| unit == BACKSLASH || unit == SLASH || unit == COLON)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn w(text: &str) -> Vec<u16> {
        text.encode_utf16().collect()
    }

    fn s(units: &[u16]) -> String {
        String::from_utf16(units).unwrap()
    }

    /// The units of a list, its NULs as `|`.
    fn shown(units: impl Iterator<Item = u16>) -> String {
        s(&units
            .map(|unit| if unit == 0 { u16::from(b'|') } else { unit })
            .collect::<Vec<_>>())
    }

    fn applied(text: &[u16], splice: &Splice<'_>) -> String {
        s(&splice.pieces(text).concat())
    }

    /// An edit of `text`, the text it leaves taken as the new one.
    fn step(text: &mut Vec<u16>, edit: impl Fn(&[u16]) -> Option<String>) -> String {
        let after = edit(text).unwrap();
        *text = w(&after);
        after
    }

    /// The fixture's profile.ini.
    const PROFILE: &str = "Orphan=before any section\r\n\
        ; a comment\r\n\
        [First]\r\n\
        Name=value one\r\n\
        \x20 Spaced  =   padded value   \r\n\
        Quoted=\"in double quotes\"\r\n\
        Single='in single quotes'\r\n\
        Half=\"opened only\r\n\
        Number=42\r\n\
        Blank=   \r\n\
        Empty=\r\n\
        NoEquals\r\n\
        NAME=the same key in upper case\r\n\
        [Second]\r\n\
        Key=second section\r\n\
        ;Hidden=commented out\r\n\
        [first]\r\n\
        Again=in a repeated section\r\n\
        [Empty]\r\n\
        [ Padded ]\r\n\
        Inner=in a padded section name\r\n";

    fn lookup(text: &str, section: &str, key: &str) -> Option<String> {
        let text = w(text);
        value(&text, &w(section), &w(key)).map(s)
    }

    /// A key's value: the blanks around it dropped, matching quotes dropped, an unmatched one
    /// kept; keys and sections in any case, the caller's blanks dropped; comments, entries without
    /// `=` and keys above every section never found; only the first section of a name searched.
    #[test]
    fn values_are_trimmed_and_unquoted() {
        let found = |section, key| lookup(PROFILE, section, key);
        assert_eq!(found("First", "Name").as_deref(), Some("value one"));
        assert_eq!(found("First", "Spaced").as_deref(), Some("padded value"));
        assert_eq!(
            found("First", "Quoted").as_deref(),
            Some("in double quotes")
        );
        assert_eq!(
            found("First", "Single").as_deref(),
            Some("in single quotes")
        );
        assert_eq!(found("First", "Half").as_deref(), Some("\"opened only"));
        assert_eq!(found("First", "Blank").as_deref(), Some(""));
        assert_eq!(found("First", "Empty").as_deref(), Some(""));
        assert_eq!(found("FIRST", "name").as_deref(), Some("value one"));
        assert_eq!(
            found(" Padded ", "Inner").as_deref(),
            Some("in a padded section name")
        );
        assert_eq!(
            found("Padded", " Inner ").as_deref(),
            Some("in a padded section name")
        );
        assert_eq!(found("First", "NoEquals"), None);
        assert_eq!(found("First", "Orphan"), None);
        assert_eq!(found("Second", "Hidden"), None);
        assert_eq!(found("first", "Again"), None);
        assert_eq!(found("Missing", "Name"), None);
    }

    /// LF alone ends a line too, and a last line without one is read.
    #[test]
    fn lines_end_with_lf_or_the_text() {
        assert_eq!(lookup("[a]\nk=1\nj=2", "a", "j").as_deref(), Some("2"));
        assert_eq!(lookup("[a]\r\nk=1\r", "a", "k").as_deref(), Some("1"));
        assert_eq!(lookup("[a", "a", "k"), None);
        assert_eq!(lookup("[a\r\nk=x", "a", "k").as_deref(), Some("x"));
        assert_eq!(
            lookup("\t[a]\r\n\tk\t=\tx\t\r\n", "a", "k").as_deref(),
            Some("x")
        );
    }

    /// The lists: the section names (repeated ones too), a section's key names (entries without
    /// `=` left out), its entries as `key=value` (trimmed, quotes kept) or as they are.
    #[test]
    fn the_lists_follow_the_file() {
        let text = w(PROFILE);
        assert_eq!(
            shown(section_names(&text)),
            "First|Second|first|Empty|Padded||"
        );
        let first = section(&text, &w("first")).unwrap();
        assert_eq!(
            shown(key_names(&text, &first)),
            "Name|Spaced|Quoted|Single|Half|Number|Blank|Empty|NAME||"
        );
        assert_eq!(
            shown(section_entries(&text, &first)),
            "Name=value one|Spaced=padded value|Quoted=\"in double quotes\"|\
             Single='in single quotes'|Half=\"opened only|Number=42|Blank=|Empty=|NoEquals|\
             NAME=the same key in upper case||"
        );
        let second = section(&text, &w("Second")).unwrap();
        assert_eq!(
            shown(section_entries(&text, &second)),
            "Key=second section||"
        );
        let empty = section(&text, &w("Empty")).unwrap();
        assert_eq!(shown(section_entries(&text, &empty)), "|");
        assert_eq!(shown(key_names(&text, &empty)), "|");
        assert_eq!(shown(section_names(&[])), "|");
    }

    /// The capture's own count: [First]'s 202 units of entries in profile.ini.
    #[test]
    fn the_captured_section_counts() {
        let text = w(&std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/kernel32/profile/profile.ini"
        ))
        .unwrap());
        let first = section(&text, &w("First")).unwrap();
        assert_eq!(section_entries(&text, &first).count() - 1, 202);
        assert_eq!(key_names(&text, &first).count() - 1, 73);
        assert_eq!(section_names(&text).count() - 1, 32);
    }

    /// A string fits with its NUL, or is cut to the room less one; a list fits whole, or is cut to
    /// the room less two and ends with two NULs; no room, nothing written.
    #[test]
    fn answers_fit_the_buffer() {
        assert_eq!(
            fit_string(9, 64),
            Fit {
                units: 9,
                terminators: 1,
                count: 9,
                whole: true
            }
        );
        assert_eq!(
            fit_string(9, 5),
            Fit {
                units: 4,
                terminators: 1,
                count: 4,
                whole: false
            }
        );
        assert_eq!(
            fit_string(9, 1),
            Fit {
                units: 0,
                terminators: 1,
                count: 0,
                whole: false
            }
        );
        assert_eq!(fit_string(9, 0).units + fit_string(9, 0).terminators, 0);
        assert_eq!(fit_string(0, 1).whole, true);
        assert_eq!(
            fit_list(74, 512),
            Fit {
                units: 74,
                terminators: 0,
                count: 73,
                whole: true
            }
        );
        assert_eq!(
            fit_list(74, 10),
            Fit {
                units: 8,
                terminators: 2,
                count: 8,
                whole: false
            }
        );
        assert_eq!(
            fit_list(74, 1),
            Fit {
                units: 0,
                terminators: 1,
                count: 0,
                whole: false
            }
        );
        assert_eq!(
            fit_list(1, 1),
            Fit {
                units: 1,
                terminators: 0,
                count: 0,
                whole: true
            }
        );
        assert_eq!(fit_list(74, 0).units + fit_list(74, 0).terminators, 0);
    }

    /// The write fixture's steps, each on the text the step before left.
    #[test]
    fn writes_edit_in_place() {
        let mut text = w("[First]\r\n\
            Name=value one\r\n\
            \x20 Spaced  =   padded value   \r\n\
            Number=42\r\n\
            NoEquals\r\n\
            NAME=upper\r\n\
            [Second]\r\n\
            Key=second section\r\n\
            ;Hidden=commented out\r\n\
            [first]\r\n\
            Again=repeated\r\n\
            [Empty]\r\n\
            [ Padded ]\r\n\
            Inner=x\r\n");
        let added = step(&mut text, |t| {
            Some(applied(
                t,
                &write_key(t, &w("Second"), &w("Added"), &w("v")),
            ))
        });
        assert!(added.contains("Key=second section\r\nAdded=v\r\n;Hidden"));
        let replaced = step(&mut text, |t| {
            Some(applied(
                t,
                &write_key(t, &w("First"), &w("number"), &w(" 43 ")),
            ))
        });
        assert!(replaced.contains("\r\nNumber= 43 \r\n"));
        let deleted = step(&mut text, |t| {
            Some(applied(t, &delete_key(t, &w("First"), &w("Spaced"))?))
        });
        assert!(deleted.contains("Name=value one\r\n  Number= 43 \r\n"));
        let set = step(&mut text, |t| {
            Some(applied(
                t,
                &write_key(t, &w("First"), &w("NoEquals"), &w("s")),
            ))
        });
        assert!(set.contains("NoEquals\r\nNAME=upper\r\nNoEquals=s\r\n[Second]"));
        let gone = step(&mut text, |t| {
            Some(applied(t, &delete_section(t, &w("Second"))?))
        });
        assert!(gone.contains("NoEquals=s\r\n;Hidden=commented out\r\n[first]"));
        let third = step(&mut text, |t| {
            Some(applied(t, &write_key(t, &w("Third"), &w("Key"), &w("n"))))
        });
        assert!(third.ends_with("Inner=x\r\n[Third]\r\nKey=n\r\n"));
        let again = step(&mut text, |t| {
            Some(applied(t, &write_key(t, &w("first"), &w("Again"), &w("c"))))
        });
        assert!(again.contains("NoEquals=s\r\nAgain=c\r\n;Hidden"));
        assert!(again.contains("[first]\r\nAgain=repeated\r\n"));
        assert_eq!(delete_key(&text, &w("Missing"), &w("Key")), None);
        assert_eq!(delete_key(&text, &w("First"), &w("Missing")), None);
        assert_eq!(delete_section(&text, &w("Missing")), None);

        let body: Vec<u16> = section_body(&w("One=1\0Two = 2\0Bare\0\0")).collect();
        let filled = step(&mut text, |t| {
            Some(applied(t, &write_section(t, &w("Empty"), &body)))
        });
        assert!(filled.contains("[Empty]\r\nOne=1\r\nTwo = 2\r\nBare\r\n[ Padded ]"));
        let only: Vec<u16> = section_body(&w("Only=w\0\0")).collect();
        let replaced = step(&mut text, |t| {
            Some(applied(t, &write_section(t, &w("Third"), &only)))
        });
        assert!(replaced.ends_with("[Third]\r\nOnly=w\r\n"));
        let made: Vec<u16> = section_body(&w("Made=by section\0\0")).collect();
        let fourth = step(&mut text, |t| {
            Some(applied(t, &write_section(t, &w("Fourth"), &made)))
        });
        assert!(fourth.ends_with("[Third]\r\nOnly=w\r\n[Fourth]\r\nMade=by section\r\n"));
    }

    /// A new file is the section and the key; a text whose last line has no LF gets CR LF before
    /// what is added after it.
    #[test]
    fn additions_start_on_a_line_of_their_own() {
        let empty: [u16; 0] = [];
        let made = write_key(&empty, &[0x4E], &[0x4B], &[0x76]);
        assert_eq!(applied(&empty, &made), "[N]\r\nK=v\r\n");
        let text = w("[a]\r\nk=1");
        let key = write_key(&text, &[0x61], &[0x6A], &[0x32]);
        assert_eq!(applied(&text, &key), "[a]\r\nk=1\r\nj=2\r\n");
        let other = write_key(&text, &[0x62], &[0x6A], &[0x32]);
        assert_eq!(applied(&text, &other), "[a]\r\nk=1\r\n[b]\r\nj=2\r\n");
        let header = w("[a]");
        let into = write_key(&header, &[0x61], &[0x6A], &[0x32]);
        assert_eq!(applied(&header, &into), "[a]\r\nj=2\r\n");
        let body = w("x\r\n");
        assert_eq!(
            applied(&header, &write_section(&header, &[0x61], &body)),
            "[a]\r\nx\r\n"
        );
    }

    /// A default loses its trailing blanks only; a caller's name loses the blanks at both ends.
    #[test]
    fn defaults_and_names_lose_their_blanks() {
        assert_eq!(s(without_trailing_blanks(&w(" dflt  "))), " dflt");
        assert_eq!(s(without_trailing_blanks(&w("   "))), "");
        assert_eq!(s(trimmed(&w(" Padded\t"))), "Padded");
    }

    /// A bare name is the Windows directory's; a path, relative or not, is its own.
    #[test]
    fn bare_names_go_to_the_windows_directory() {
        assert!(in_windows_directory(&w("win.ini")));
        assert!(!in_windows_directory(&w(".\\app.ini")));
        assert!(!in_windows_directory(&w("sub/app.ini")));
        assert!(!in_windows_directory(&w("C:app.ini")));
        assert!(!in_windows_directory(&w("C:\\CORPUS\\profile.ini")));
    }
}
