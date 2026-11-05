//! What `dir`'s argument says, and what it prints, as Windows 2000's cmd.exe has it with its
//! command extensions on (`dir /?`): its switches, preset by the DIRCMD variable ([`Switches`]),
//! the order a sorted listing takes ([`Order`], [`sort`]), and its lines: the volume's, the
//! directory's, an entry's in the long and wide formats, and the totals.

use core::cmp::Ordering;
use core::fmt;

use super::files::{Token, Tokens, ARCHIVE, DIRECTORY, HIDDEN, READONLY, SYSTEM};
use crate::{fold, Time};

/// What `dir` prints, on the standard error, when a name matches nothing.
pub const FILE_NOT_FOUND: &str = "File Not Found\r\n";

/// What comes before the totals of a listing through the subdirectories (`/S`).
pub const TOTAL_LISTED: &str = "\r\n     Total Files Listed:\r\n";

/// What follows a refused switch that came from the DIRCMD variable.
pub const IN_DIRCMD: &str = "(Error occurred in environment variable)\r\n";

/// Which entries a listing shows by their attributes (`/A`): those with every `required` bit and
/// no `excluded` one, directories (FILE_ATTRIBUTE_DIRECTORY) among them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Selection {
    pub required: u32,
    pub excluded: u32,
}

impl Selection {
    /// `/A` alone: every entry.
    pub const ALL: Selection = Selection {
        required: 0,
        excluded: 0,
    };
    /// Without `/A`: every entry but the hidden and system ones.
    pub const DEFAULT: Selection = Selection {
        required: 0,
        excluded: HIDDEN | SYSTEM,
    };

    /// Whether an entry of `attributes` is shown.
    pub fn selects(&self, attributes: u32) -> bool {
        attributes & self.required == self.required && attributes & self.excluded == 0
    }

    /// `/A`'s letters, after the `a` and an optional `:`: `D` directories, `R` read-only, `H`
    /// hidden, `A` ready for archiving, `S` system, each after a `-` for the entries without it.
    /// None for another letter.
    fn parse(letters: &[u16]) -> Option<Selection> {
        let mut selection = Selection::ALL;
        let mut not = false;
        for &unit in letters {
            let bit = match u8::try_from(fold(unit)).unwrap_or(0) {
                b'-' => {
                    not = true;
                    continue;
                }
                b'D' => DIRECTORY,
                b'R' => READONLY,
                b'H' => HIDDEN,
                b'A' => ARCHIVE,
                b'S' => SYSTEM,
                _ => return None,
            };
            if core::mem::take(&mut not) {
                selection.excluded |= bit;
            } else {
                selection.required |= bit;
            }
        }
        Some(selection)
    }
}

/// Which of an entry's times a listing shows and `/O:D` sorts by (`/T`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimeField {
    /// `/T:C`: when it was created.
    Creation,
    /// `/T:A`: when it was last read.
    Access,
    /// `/T:W`, the default: when it was last written.
    Written,
}

/// What a sorted listing compares entries by (`/O`'s letters).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Key {
    /// `N`: the names, alphabetically, whatever their case.
    Name,
    /// `E`: the extensions (after the last dot), alphabetically.
    Extension,
    /// `S`: the sizes, smallest first.
    Size,
    /// `D`: the times `/T` shows, oldest first.
    Date,
    /// `G`: directories before files.
    DirectoriesFirst,
}

/// One of `/O`'s keys, reversed by a `-` before its letter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SortKey {
    pub key: Key,
    pub reversed: bool,
}

/// The keys a sorted listing compares entries by, in turn: the first that tells two apart decides,
/// and entries no key tells apart keep the directory's order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Order {
    keys: [SortKey; 5],
    count: usize,
}

impl Order {
    /// `/O` alone: directories first, then by name.
    pub const DEFAULT: Order = Order {
        keys: [
            SortKey {
                key: Key::DirectoriesFirst,
                reversed: false,
            },
            SortKey {
                key: Key::Name,
                reversed: false,
            },
            SortKey {
                key: Key::Name,
                reversed: false,
            },
            SortKey {
                key: Key::Name,
                reversed: false,
            },
            SortKey {
                key: Key::Name,
                reversed: false,
            },
        ],
        count: 2,
    };

    /// The keys, in turn.
    pub fn keys(&self) -> &[SortKey] {
        &self.keys[..self.count]
    }

    /// `/O`'s letters, after the `o` and an optional `:`: `N`, `E`, `S`, `D`, `G`, each after a
    /// `-` to reverse it; none is [`Order::DEFAULT`]. A key given twice counts once, where it
    /// first shows. None for another letter.
    fn parse(letters: &[u16]) -> Option<Order> {
        if letters.is_empty() {
            return Some(Order::DEFAULT);
        }
        let mut order = Order {
            count: 0,
            ..Order::DEFAULT
        };
        let mut reversed = false;
        for &unit in letters {
            let key = match u8::try_from(fold(unit)).unwrap_or(0) {
                b'-' => {
                    reversed = true;
                    continue;
                }
                b'N' => Key::Name,
                b'E' => Key::Extension,
                b'S' => Key::Size,
                b'D' => Key::Date,
                b'G' => Key::DirectoriesFirst,
                _ => return None,
            };
            let reversed = core::mem::take(&mut reversed);
            if !order.keys().iter().any(|given| given.key == key) {
                order.keys[order.count] = SortKey { key, reversed };
                order.count += 1;
            }
        }
        Some(order)
    }

    /// How `a` compares with `b` (their names in `names`), by the keys in turn; Equal when no key
    /// tells them apart.
    pub fn compare(&self, a: &Item, b: &Item, names: &[u16]) -> Ordering {
        for sort in self.keys() {
            let ordering = match sort.key {
                Key::Name => compare_names(a.name(names), b.name(names)),
                Key::Extension => compare_names(extension(a.name(names)), extension(b.name(names))),
                Key::Size => a.size.cmp(&b.size),
                Key::Date => a.time.cmp(&b.time),
                Key::DirectoriesFirst => b.is_directory().cmp(&a.is_directory()),
            };
            let ordering = if sort.reversed {
                ordering.reverse()
            } else {
                ordering
            };
            if ordering != Ordering::Equal {
                return ordering;
            }
        }
        Ordering::Equal
    }
}

/// A UTF-16 unit lower-cased when it is an ASCII letter: names compare so, and `/L` shows them so.
fn lower(unit: u16) -> u16 {
    if (u16::from(b'A')..=u16::from(b'Z')).contains(&unit) {
        unit + 32
    } else {
        unit
    }
}

/// Two names compared whatever the case of their ASCII letters.
fn compare_names(a: &[u16], b: &[u16]) -> Ordering {
    a.iter()
        .map(|&unit| lower(unit))
        .cmp(b.iter().map(|&unit| lower(unit)))
}

/// A name's extension: what follows its last dot (nothing without one).
fn extension(name: &[u16]) -> &[u16] {
    match name.iter().rposition(|&unit| unit == u16::from(b'.')) {
        Some(dot) => &name[dot + 1..],
        None => &[],
    }
}

/// `dir`'s switches (`dir /?`), as the DIRCMD variable presets them and the command line sets them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Switches {
    /// `/A`: which entries are shown.
    pub selection: Selection,
    /// `/B`: the names alone, without the headings and the totals.
    pub bare: bool,
    /// `/C`, the default: sizes shown with thousands separators (`/-C` without).
    pub separators: bool,
    /// `/D`: the wide format, its entries sorted down the columns.
    pub by_column: bool,
    /// `/L`: the names in lowercase.
    pub lowercase: bool,
    /// `/O`: the entries sorted; None for the directory's order.
    pub order: Option<Order>,
    /// `/P`: a pause after each screenful.
    pub pause: bool,
    /// `/Q`: the owner of each file (taken, and not shown: see the README).
    pub owner: bool,
    /// `/S`: the subdirectories listed too, each under its own heading.
    pub subdirectories: bool,
    /// `/T`: the time shown, and sorted by.
    pub time: TimeField,
    /// `/W`: the wide format, the entries side by side.
    pub wide: bool,
    /// `/X`: each entry's short name before its name.
    pub short_names: bool,
}

impl Default for Switches {
    /// `dir` without switches: the long format, hidden and system files left out, sizes with their
    /// separators, the last write times, the directory's order.
    fn default() -> Self {
        Switches {
            selection: Selection::DEFAULT,
            bare: false,
            separators: true,
            by_column: false,
            lowercase: false,
            order: None,
            pause: false,
            owner: false,
            subdirectories: false,
            time: TimeField::Written,
            wide: false,
            short_names: false,
        }
    }
}

/// Why `dir` refused a switch: the switch's text, what follows its `/`.
#[derive(Debug, PartialEq, Eq)]
pub enum Invalid<'a> {
    /// A switch `dir` does not take.
    Switch(&'a [u16]),
    /// `/A`, `/O` or `/T` with a letter it does not take.
    Format(&'a [u16]),
}

/// What `dir` prints for a switch it refuses.
impl fmt::Display for Invalid<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Invalid::Switch(switch) => write!(f, "Invalid switch - \"{}\".\r\n", Lower(switch)),
            Invalid::Format(switch) => write!(
                f,
                "Parameter format not correct - \"{}\".\r\n",
                Lower(switch)
            ),
        }
    }
}

impl Switches {
    /// The switches `text` holds (the DIRCMD variable's, then the command line), applied over these
    /// in turn: a later one overrides an earlier one, and `/-x` turns `/x` off (`/-A` shows the
    /// default entries again, `/-O` the directory's order, `/-T` the last write times). The names
    /// among them are left for [`names`].
    pub fn apply<'a>(&mut self, text: &'a [u16]) -> Result<(), Invalid<'a>> {
        for token in Tokens::new(text, false) {
            if let Token::Switch(switch) = token {
                self.switch(switch)?;
            }
        }
        Ok(())
    }

    /// One switch, what follows its `/`.
    fn switch<'a>(&mut self, switch: &'a [u16]) -> Result<(), Invalid<'a>> {
        let (on, letters) = match switch.split_first() {
            Some((&unit, rest)) if unit == u16::from(b'-') => (false, rest),
            _ => (true, switch),
        };
        let Some((&letter, rest)) = letters.split_first() else {
            return Err(Invalid::Switch(switch));
        };
        // `/A`, `/O` and `/T` take their letters after an optional colon.
        let value = rest.strip_prefix(&[u16::from(b':')]).unwrap_or(rest);
        let letter = u8::try_from(fold(letter)).unwrap_or(0);
        match letter {
            b'A' if !on => self.selection = Selection::DEFAULT,
            b'A' => self.selection = Selection::parse(value).ok_or(Invalid::Format(switch))?,
            b'O' if !on => self.order = None,
            b'O' => self.order = Some(Order::parse(value).ok_or(Invalid::Format(switch))?),
            b'T' if !on => self.time = TimeField::Written,
            b'T' => {
                self.time = match value {
                    [unit] => match u8::try_from(fold(*unit)).unwrap_or(0) {
                        b'C' => TimeField::Creation,
                        b'A' => TimeField::Access,
                        b'W' => TimeField::Written,
                        _ => return Err(Invalid::Format(switch)),
                    },
                    _ => return Err(Invalid::Format(switch)),
                }
            }
            _ if !rest.is_empty() => return Err(Invalid::Switch(switch)),
            b'B' => self.bare = on,
            b'C' => self.separators = on,
            b'D' => self.by_column = on,
            b'L' => self.lowercase = on,
            b'P' => self.pause = on,
            b'Q' => self.owner = on,
            b'S' => self.subdirectories = on,
            b'W' => self.wide = on,
            b'X' => self.short_names = on,
            // The long format is always the new one, its names on the right; years always show
            // four digits.
            b'N' | b'4' => {}
            _ => return Err(Invalid::Switch(switch)),
        }
        Ok(())
    }
}

/// The names `dir`'s argument lists, quotes and all, its switches left out.
pub fn names(argument: &[u16]) -> impl Iterator<Item = &[u16]> {
    Tokens::new(argument, false).names()
}

/// An entry of a listing, gathered from the directory: its name and short name as ranges of a
/// buffer of names, its attributes, size and the time `/T` names.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Item {
    pub attributes: u32,
    pub size: u64,
    /// The FILETIME shown and sorted by.
    pub time: u64,
    /// Where it came in the directory's order.
    pub index: usize,
    pub name_start: usize,
    pub name_length: usize,
    pub short_start: usize,
    pub short_length: usize,
}

impl Item {
    /// Its name, in `names`.
    pub fn name<'a>(&self, names: &'a [u16]) -> &'a [u16] {
        names
            .get(self.name_start..self.name_start + self.name_length)
            .unwrap_or(&[])
    }

    /// Its short name, in `names` (empty when its name is one itself).
    pub fn short_name<'a>(&self, names: &'a [u16]) -> &'a [u16] {
        names
            .get(self.short_start..self.short_start + self.short_length)
            .unwrap_or(&[])
    }

    pub fn is_directory(&self) -> bool {
        self.attributes & DIRECTORY != 0
    }
}

/// `items` sorted by `order` (their names in `names`), those it does not tell apart in the
/// directory's order.
pub fn sort(items: &mut [Item], names: &[u16], order: &Order) {
    items.sort_unstable_by(|a, b| order.compare(a, b, names).then(a.index.cmp(&b.index)))
}

/// `value` in decimal, with a `,` between each group of three digits when `separators`, in `out`.
pub fn grouped(value: u64, separators: bool, out: &mut [u8; 27]) -> &str {
    let mut at = out.len();
    let mut rest = value;
    let mut digits = 0;
    loop {
        if separators && digits > 0 && digits % 3 == 0 {
            at -= 1;
            out[at] = b',';
        }
        at -= 1;
        out[at] = b'0' + (rest % 10) as u8;
        rest /= 10;
        digits += 1;
        if rest == 0 {
            break;
        }
    }
    core::str::from_utf8(&out[at..]).unwrap_or("")
}

/// UTF-16 text, its ASCII letters lower-cased when `.1` (`/L`, and a refused switch's text).
pub struct Lowered<'a>(pub &'a [u16], pub bool);

/// UTF-16 text, its ASCII letters lower-cased.
struct Lower<'a>(&'a [u16]);

impl fmt::Display for Lower<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Lowered(self.0, true).fmt(f)
    }
}

impl fmt::Display for Lowered<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let units = self
            .0
            .iter()
            .map(|&unit| if self.1 { lower(unit) } else { unit });
        for character in char::decode_utf16(units) {
            fmt::Write::write_char(f, character.unwrap_or(char::REPLACEMENT_CHARACTER))?;
        }
        Ok(())
    }
}

/// The heading's first line: the volume's label, or that it has none.
pub struct VolumeLabel<'a> {
    /// The drive's letter (`C`).
    pub drive: u16,
    pub label: &'a [u16],
}

impl fmt::Display for VolumeLabel<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let drive = crate::Text(core::slice::from_ref(&self.drive));
        if self.label.is_empty() {
            write!(f, " Volume in drive {drive} has no label.\r\n")
        } else {
            write!(
                f,
                " Volume in drive {drive} is {}\r\n",
                crate::Text(self.label)
            )
        }
    }
}

/// The heading's second line: the volume's serial number, in two halves of four hexadecimal
/// digits.
pub struct SerialNumber(pub u32);

impl fmt::Display for SerialNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            " Volume Serial Number is {:04X}-{:04X}\r\n",
            self.0 >> 16,
            self.0 & 0xFFFF
        )
    }
}

/// The heading of a directory's entries, its full path, between empty lines.
pub struct DirectoryOf<'a>(pub &'a [u16]);

impl fmt::Display for DirectoryOf<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "\r\n Directory of {}\r\n\r\n", crate::Text(self.0))
    }
}

/// An entry's date and time as the long format shows them, in the US format: `11/04/2026  10:30a`
/// (twelve hours, `a` or `p` after them).
pub struct Stamp<'a>(pub &'a Time);

impl fmt::Display for Stamp<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let time = self.0;
        let hour = match time.hour % 12 {
            0 => 12,
            hour => hour,
        };
        let half = if time.hour < 12 { 'a' } else { 'p' };
        write!(
            f,
            "{:02}/{:02}/{:04}  {hour:02}:{:02}{half}",
            time.month, time.day, time.year, time.minute
        )
    }
}

/// The columns an entry's size (or `<DIR>`) takes, after its time.
const SIZE_COLUMNS: usize = 20;

/// The columns a short name takes (`/X`): an 8.3 name's.
const SHORT_COLUMNS: usize = 12;

/// An entry's line in the long format: its date and time, `<DIR>` or its size (right-aligned),
/// with `/X` its short name (or blanks), then its name.
pub struct Entry<'a> {
    pub time: &'a Time,
    pub directory: bool,
    pub size: u64,
    pub separators: bool,
    /// Its short name with `/X`, None without.
    pub short_name: Option<&'a [u16]>,
    pub name: &'a [u16],
    pub lowercase: bool,
}

impl fmt::Display for Entry<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", Stamp(self.time))?;
        if self.directory {
            write!(f, "{:<SIZE_COLUMNS$}", "      <DIR>")?;
        } else {
            let mut digits = [0; 27];
            let size = grouped(self.size, self.separators, &mut digits);
            write!(f, "{size:>SIZE_COLUMNS$}")?;
        }
        f.write_str(" ")?;
        if let Some(short) = self.short_name {
            let shown = Lowered(short, self.lowercase);
            write!(
                f,
                "{shown}{:1$} ",
                "",
                SHORT_COLUMNS.saturating_sub(short.len())
            )?;
        }
        write!(f, "{}\r\n", Lowered(self.name, self.lowercase))
    }
}

/// A listing's count of files and their bytes.
pub struct FileTotals {
    pub files: u64,
    pub bytes: u64,
    pub separators: bool,
}

impl fmt::Display for FileTotals {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut digits = [0; 27];
        let bytes = grouped(self.bytes, self.separators, &mut digits);
        write!(f, "{:>16} File(s) {bytes:>14} bytes\r\n", self.files)
    }
}

/// A listing's count of directories (`.` and `..` among them), and the bytes free on the disk.
pub struct DirectoryTotals {
    pub directories: u64,
    pub free: u64,
    pub separators: bool,
}

impl fmt::Display for DirectoryTotals {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut digits = [0; 27];
        let free = grouped(self.free, self.separators, &mut digits);
        write!(
            f,
            "{:>16} Dir(s) {free:>15} bytes free\r\n",
            self.directories
        )
    }
}

/// The blanks between the wide format's columns, at the least.
const WIDE_GAP: usize = 3;

/// The width the wide format gives a column at the least: an 8.3 name's.
const WIDE_NAME: usize = 12;

/// How the wide format (`/W`, `/D`) lays entries out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Wide {
    /// The columns a row holds.
    pub columns: usize,
    /// The columns of the screen each takes, the blanks after its name included.
    pub width: usize,
    /// The rows the entries take.
    pub rows: usize,
    pub count: usize,
    /// Whether the entries are sorted down the columns (`/D`) rather than across the rows.
    pub by_column: bool,
}

impl Wide {
    /// The layout of `count` entries whose longest shows in `longest` columns (a directory's name
    /// in its brackets), on a screen `screen` columns wide: each column as wide as the longest
    /// name (an 8.3 name's at the least) and three blanks, as many as fit, the last one's blanks
    /// not needed.
    pub fn new(count: usize, longest: usize, screen: usize, by_column: bool) -> Wide {
        let width = longest.max(WIDE_NAME) + WIDE_GAP;
        let columns = ((screen + WIDE_GAP) / width).max(1);
        let rows = count.div_ceil(columns);
        Wide {
            columns,
            width,
            rows,
            count,
            by_column,
        }
    }

    /// Which entry (its place in the listing's order) shows at `row` and `column`: None past the
    /// last.
    pub fn at(&self, row: usize, column: usize) -> Option<usize> {
        let place = if self.by_column {
            column * self.rows + row
        } else {
            row * self.columns + column
        };
        (place < self.count && row < self.rows && column < self.columns).then_some(place)
    }
}

/// An entry's name as the wide format shows it: a directory's in brackets.
pub struct WideName<'a> {
    pub name: &'a [u16],
    pub directory: bool,
    pub lowercase: bool,
}

impl WideName<'_> {
    /// The columns it takes.
    pub fn columns(&self) -> usize {
        self.name.len() + if self.directory { 2 } else { 0 }
    }
}

impl fmt::Display for WideName<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = Lowered(self.name, self.lowercase);
        if self.directory {
            write!(f, "[{name}]")
        } else {
            write!(f, "{name}")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().collect()
    }

    fn switches(dircmd: &str, argument: &str) -> Switches {
        let mut switches = Switches::default();
        switches.apply(&wide(dircmd)).unwrap();
        switches.apply(&wide(argument)).unwrap();
        switches
    }

    fn refused(argument: &str) -> String {
        let argument = wide(argument);
        let mut switches = Switches::default();
        switches.apply(&argument).unwrap_err().to_string()
    }

    #[test]
    fn the_defaults() {
        let switches = Switches::default();
        assert_eq!(switches.selection, Selection::DEFAULT);
        assert!(switches.separators && !switches.bare && !switches.wide);
        assert_eq!(switches.order, None);
        assert_eq!(switches.time, TimeField::Written);
    }

    #[test]
    fn attributes_with_or_without_a_colon() {
        let directories = Selection {
            required: DIRECTORY,
            excluded: 0,
        };
        assert_eq!(switches("", "/A:D").selection, directories);
        assert_eq!(switches("", "/ad").selection, directories);
        assert_eq!(
            switches("", "/A:-D").selection,
            Selection {
                required: 0,
                excluded: DIRECTORY
            }
        );
        assert_eq!(
            switches("", "/a:h-sr").selection,
            Selection {
                required: HIDDEN | READONLY,
                excluded: SYSTEM
            }
        );
        assert_eq!(switches("", "/A").selection, Selection::ALL);
        assert_eq!(switches("", "/a /-a").selection, Selection::DEFAULT);
        assert_eq!(
            refused("/A:Z"),
            "Parameter format not correct - \"a:z\".\r\n"
        );
    }

    #[test]
    fn what_attributes_select() {
        assert!(Selection::DEFAULT.selects(ARCHIVE));
        assert!(Selection::DEFAULT.selects(DIRECTORY));
        assert!(!Selection::DEFAULT.selects(HIDDEN));
        assert!(!Selection::DEFAULT.selects(SYSTEM | DIRECTORY));
        assert!(Selection::ALL.selects(HIDDEN | SYSTEM));
        let files = Selection {
            required: 0,
            excluded: DIRECTORY,
        };
        assert!(files.selects(HIDDEN) && !files.selects(DIRECTORY));
    }

    #[test]
    fn sort_orders() {
        let keys = |argument: &str| {
            switches("", argument)
                .order
                .map(|order| order.keys().to_vec())
        };
        let key = |key, reversed| SortKey { key, reversed };
        assert_eq!(keys(""), None);
        assert_eq!(
            keys("/O"),
            Some(vec![
                key(Key::DirectoriesFirst, false),
                key(Key::Name, false)
            ])
        );
        assert_eq!(keys("/O:N"), Some(vec![key(Key::Name, false)]));
        assert_eq!(keys("/o-s"), Some(vec![key(Key::Size, true)]));
        assert_eq!(
            keys("/O:GE-DN"),
            Some(vec![
                key(Key::DirectoriesFirst, false),
                key(Key::Extension, false),
                key(Key::Date, true),
                key(Key::Name, false)
            ])
        );
        assert_eq!(keys("/O:NN-N"), Some(vec![key(Key::Name, false)]));
        assert_eq!(keys("/o:n /-o"), None);
        assert_eq!(
            refused("/O:X"),
            "Parameter format not correct - \"o:x\".\r\n"
        );
    }

    #[test]
    fn time_fields() {
        assert_eq!(switches("", "/T:C").time, TimeField::Creation);
        assert_eq!(switches("", "/ta").time, TimeField::Access);
        assert_eq!(switches("", "/T:W").time, TimeField::Written);
        assert_eq!(switches("", "/tc /-t").time, TimeField::Written);
        assert_eq!(
            refused("/T:X"),
            "Parameter format not correct - \"t:x\".\r\n"
        );
        assert_eq!(refused("/T"), "Parameter format not correct - \"t\".\r\n");
    }

    #[test]
    fn on_off_switches_and_dircmd() {
        let set = switches("", "/b/c /d /l /p /q /s /w /x /n /4");
        assert!(set.bare && set.separators && set.by_column && set.lowercase && set.pause);
        assert!(set.owner && set.subdirectories && set.wide && set.short_names);
        assert!(!switches("", "/-C").separators);
        // The command line overrides DIRCMD's switches, a /- turning one off.
        assert!(switches("/W /O:N", "").wide);
        assert!(!switches("/W /O:N", "/-W").wide);
        assert_eq!(switches("/W /O:N", "/-O").order, None);
        assert_eq!(refused("/Z"), "Invalid switch - \"z\".\r\n");
        assert_eq!(refused("/BS"), "Invalid switch - \"bs\".\r\n");
        assert_eq!(refused("/"), "Invalid switch - \"\".\r\n");
    }

    #[test]
    fn names_leave_the_switches_out() {
        let argument = wide("/b a.txt \"x y\\*.c\" /o:n sub");
        let names: Vec<_> = names(&argument)
            .map(|name| String::from_utf16(name).unwrap())
            .collect();
        assert_eq!(names, ["a.txt", "\"x y\\*.c\"", "sub"]);
    }

    /// Items over one buffer of names, each with its attributes, size and time, in this order.
    fn items(entries: &[(&str, u32, u64, u64)]) -> (Vec<Item>, Vec<u16>) {
        let mut names = Vec::new();
        let items = entries
            .iter()
            .enumerate()
            .map(|(index, &(name, attributes, size, time))| {
                let start = names.len();
                names.extend(name.encode_utf16());
                Item {
                    attributes,
                    size,
                    time,
                    index,
                    name_start: start,
                    name_length: names.len() - start,
                    ..Item::default()
                }
            })
            .collect();
        (items, names)
    }

    fn sorted(entries: &[(&str, u32, u64, u64)], order: &str) -> Vec<String> {
        let (mut items, names) = items(entries);
        let order = switches("", order).order.unwrap();
        sort(&mut items, &names, &order);
        items
            .iter()
            .map(|item| String::from_utf16(item.name(&names)).unwrap())
            .collect()
    }

    const ENTRIES: [(&str, u32, u64, u64); 6] = [
        ("sub", DIRECTORY, 0, 50),
        ("b.TXT", ARCHIVE, 120, 30),
        ("..", DIRECTORY, 0, 10),
        ("A.txt", ARCHIVE, 7, 40),
        (".", DIRECTORY, 0, 10),
        ("c.dat", ARCHIVE, 1200, 20),
    ];

    #[test]
    fn sorting_by_each_key() {
        assert_eq!(
            sorted(&ENTRIES, "/O:N"),
            [".", "..", "A.txt", "b.TXT", "c.dat", "sub"]
        );
        assert_eq!(
            sorted(&ENTRIES, "/O:-N"),
            ["sub", "c.dat", "b.TXT", "A.txt", "..", "."]
        );
        // Ties keep the directory's order: the three directories are all 0 bytes long.
        assert_eq!(
            sorted(&ENTRIES, "/O:S"),
            ["sub", "..", ".", "A.txt", "b.TXT", "c.dat"]
        );
        assert_eq!(
            sorted(&ENTRIES, "/O:-S"),
            ["c.dat", "b.TXT", "A.txt", "sub", "..", "."]
        );
        assert_eq!(
            sorted(&ENTRIES, "/O:E"),
            ["sub", "..", ".", "c.dat", "b.TXT", "A.txt"]
        );
        assert_eq!(
            sorted(&ENTRIES, "/O:D"),
            ["..", ".", "c.dat", "b.TXT", "A.txt", "sub"]
        );
        assert_eq!(
            sorted(&ENTRIES, "/O"),
            [".", "..", "sub", "A.txt", "b.TXT", "c.dat"]
        );
        assert_eq!(
            sorted(&ENTRIES, "/O:-GN"),
            ["A.txt", "b.TXT", "c.dat", ".", "..", "sub"]
        );
    }

    #[test]
    fn thousands_separators() {
        let shown = |value, separators| {
            let mut digits = [0; 27];
            grouped(value, separators, &mut digits).to_string()
        };
        assert_eq!(shown(0, true), "0");
        assert_eq!(shown(999, true), "999");
        assert_eq!(shown(1000, true), "1,000");
        assert_eq!(shown(1_234_567, true), "1,234,567");
        assert_eq!(shown(1_234_567, false), "1234567");
        assert_eq!(shown(u64::MAX, true), "18,446,744,073,709,551,615");
    }

    fn time(hour: u16, minute: u16) -> Time {
        Time {
            year: 2026,
            month: 11,
            day: 4,
            hour,
            minute,
            ..Time::default()
        }
    }

    #[test]
    fn the_long_format_s_columns() {
        let morning = time(9, 5);
        let line = |directory, size, short: Option<&str>, name: &str, lowercase| {
            let short = short.map(wide);
            Entry {
                time: &morning,
                directory,
                size,
                separators: true,
                short_name: short.as_deref(),
                name: &wide(name),
                lowercase,
            }
            .to_string()
        };
        assert_eq!(
            line(true, 0, None, ".", false),
            "11/04/2026  09:05a      <DIR>          .\r\n"
        );
        assert_eq!(
            line(false, 1200, None, "c.dat", false),
            "11/04/2026  09:05a               1,200 c.dat\r\n"
        );
        assert_eq!(
            line(false, 7, Some("LONGNA~1.TXT"), "Long name.txt", true),
            "11/04/2026  09:05a                   7 longna~1.txt long name.txt\r\n"
        );
        assert_eq!(
            line(true, 0, Some(""), "sub", false),
            "11/04/2026  09:05a      <DIR>                       sub\r\n"
        );
        // The names start in the same column whatever the line holds.
        assert_eq!(line(true, 0, None, "x", false).find('x'), Some(39));
        assert_eq!(line(false, 1, None, "x", false).find('x'), Some(39));
    }

    #[test]
    fn twelve_hour_times() {
        let stamp = |hour, minute| Stamp(&time(hour, minute)).to_string();
        assert_eq!(stamp(0, 0), "11/04/2026  12:00a");
        assert_eq!(stamp(11, 59), "11/04/2026  11:59a");
        assert_eq!(stamp(12, 0), "11/04/2026  12:00p");
        assert_eq!(stamp(23, 7), "11/04/2026  11:07p");
    }

    #[test]
    fn the_headings_and_totals() {
        let label = wide("F2K");
        let c = u16::from(b'C');
        assert_eq!(
            VolumeLabel {
                drive: c,
                label: &label
            }
            .to_string(),
            " Volume in drive C is F2K\r\n"
        );
        assert_eq!(
            VolumeLabel {
                drive: c,
                label: &[]
            }
            .to_string(),
            " Volume in drive C has no label.\r\n"
        );
        assert_eq!(
            SerialNumber(0x1C2E_3F4A).to_string(),
            " Volume Serial Number is 1C2E-3F4A\r\n"
        );
        assert_eq!(
            DirectoryOf(&wide("C:\\CORPUS")).to_string(),
            "\r\n Directory of C:\\CORPUS\r\n\r\n"
        );
        assert_eq!(
            FileTotals {
                files: 3,
                bytes: 1327,
                separators: true
            }
            .to_string(),
            "               3 File(s)          1,327 bytes\r\n"
        );
        assert_eq!(
            DirectoryTotals {
                directories: 3,
                free: 1_234_567_890,
                separators: true
            }
            .to_string(),
            "               3 Dir(s)   1,234,567,890 bytes free\r\n"
        );
        assert_eq!(
            DirectoryTotals {
                directories: 0,
                free: 1_234_567_890,
                separators: false
            }
            .to_string(),
            "               0 Dir(s)      1234567890 bytes free\r\n"
        );
    }

    #[test]
    fn the_wide_format_s_layout() {
        // Short names: columns of 15, five to a line of 80.
        let across = Wide::new(7, 5, 80, false);
        assert_eq!((across.width, across.columns, across.rows), (15, 5, 2));
        assert_eq!(across.at(0, 4), Some(4));
        assert_eq!(across.at(1, 1), Some(6));
        assert_eq!(across.at(1, 2), None);
        // Down the columns: the first column holds the first two.
        let down = Wide::new(7, 5, 80, true);
        assert_eq!(down.at(1, 0), Some(1));
        assert_eq!(down.at(0, 1), Some(2));
        assert_eq!(down.at(0, 3), Some(6));
        assert_eq!(down.at(1, 3), None);
        // A long name: three columns of 27, the last one's blanks not needed.
        assert_eq!(Wide::new(3, 24, 80, false).columns, 3);
        assert_eq!(Wide::new(3, 200, 80, false).columns, 1);
        let name = wide("sub");
        let shown = WideName {
            name: &name,
            directory: true,
            lowercase: false,
        };
        assert_eq!(
            (shown.to_string(), shown.columns()),
            ("[sub]".to_string(), 5)
        );
    }
}
