//! `dir` run: the names its argument lists, each one's directory read through FindFirstFileW (exe's
//! src/files.rs), its entries gathered into buffers from the process heap, sorted when `/O` says
//! so, and printed in the long, wide or bare format, a page at a time with `/P`; the volume's label
//! and serial number and the bytes free come from GetVolumeInformationW and GetDiskFreeSpaceExW.

use core::fmt::{self, Write};

use cmd::builtins::dir::{
    self as rules,
    DirectoryOf,
    DirectoryTotals,
    Entry,
    FileTotals,
    Item,
    Lowered,
    SerialNumber,
    Switches,
    TimeField,
    VolumeLabel,
    Wide,
    WideName,
};
use cmd::builtins::files::{self as paths, DIRECTORY, ERROR_FILE_NOT_FOUND, ERROR_NO_MORE_FILES};
use exe::MAX_PATH;

use super::{report, wide};

/// The pattern that matches every entry of a directory.
const STAR: &[u16] = &[b'*' as u16];

/// The columns the wide format fills when the standard output is no console.
const SCREEN_COLUMNS: usize = 80;

/// The error a path too long for a buffer is.
const TOO_LONG: exe::Error = exe::Error(paths::ERROR_FILENAME_EXCED_RANGE);

/// `dir`: the DIRCMD variable's switches, then the argument's, then each name listed (the current
/// directory without one). A name that matches nothing prints `File Not Found` on the standard
/// error and fails the command; a switch refused fails it before anything is listed.
pub fn list(argument: &[u16], state: &mut cmd::State) {
    let mut switches = Switches::default();
    let mut name = [0; 6];
    let mut preset = [0; cmd::LINE];
    if let Ok(Some(preset)) = exe::environment_variable(wide("DIRCMD", &mut name), &mut preset) {
        if let Err(invalid) = switches.apply(preset) {
            let _ = exe::stderr().print(format_args!("{invalid}{}", rules::IN_DIRCMD));
            return state.failed();
        }
    }
    if let Err(invalid) = switches.apply(argument) {
        let _ = exe::stderr().print(format_args!("{invalid}"));
        return state.failed();
    }
    let mut listing = Listing::new(&switches);
    let mut any = false;
    let mut found = true;
    for name in rules::names(argument) {
        any = true;
        found &= listing.name(name);
    }
    if !any {
        found = listing.name(&[]);
    }
    if !found {
        state.failed();
    }
}

/// What one directory held: its files and their bytes, its directories (`.` and `..` among them).
#[derive(Default)]
struct Totals {
    files: u64,
    bytes: u64,
    directories: u64,
}

/// A `dir` under way: its switches, the page it is on, and whether the volume's heading is out.
struct Listing<'a> {
    switches: &'a Switches,
    /// The lines a page holds with `/P` (the console window's, less one for the question); None
    /// without `/P`, or when the standard output is no console.
    page: Option<usize>,
    /// The lines printed since the last pause.
    lines: usize,
    /// Whether the volume's heading has been printed.
    heading: bool,
}

/// What counts the lines a piece of output takes.
struct Lines(usize);

impl Write for Lines {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        self.0 += text.bytes().filter(|&byte| byte == b'\n').count();
        Ok(())
    }
}

impl<'a> Listing<'a> {
    fn new(switches: &'a Switches) -> Self {
        let page = switches
            .pause
            .then(|| exe::window_size().ok().flatten())
            .flatten()
            .map(|(_, rows)| usize::from(rows).saturating_sub(1).max(1));
        Listing {
            switches,
            page,
            lines: 0,
            heading: false,
        }
    }

    /// `output` on the standard output, after a pause when it would not fit on the page.
    fn print(&mut self, output: impl fmt::Display) {
        if let Some(page) = self.page {
            let mut lines = Lines(0);
            let _ = write!(lines, "{output}");
            if self.lines > 0 && self.lines + lines.0 > page {
                super::console::pause();
                self.lines = 0;
            }
            self.lines += lines.0;
        }
        let _ = exe::stdout().print(format_args!("{output}"));
    }

    /// The entries `name` (quotes and all; nothing for the current directory) names listed: a
    /// directory's every entry, else those its last component matches, wildcards and all, in the
    /// directory before it; through the subdirectories with `/S`. Whether it matched anything.
    #[inline(never)]
    fn name(&mut self, name: &[u16]) -> bool {
        let mut buffer = [0; MAX_PATH];
        let Some(path) = cmd::program_name(name, &mut buffer) else {
            report(TOO_LONG);
            return false;
        };
        let (directory, pattern) = if path.is_empty() {
            (&[u16::from(b'.')][..], STAR)
        } else if !paths::has_wildcards(path)
            && (paths::names_directory(path)
                || exe::attributes(path).is_ok_and(|attributes| attributes & DIRECTORY != 0))
        {
            (path, STAR)
        } else {
            match paths::split(path) {
                (&[], file) => (&[u16::from(b'.')][..], file),
                split => split,
            }
        };
        let mut full = [0; MAX_PATH];
        let full = match exe::full_path(directory, &mut full) {
            Ok(full) => without_separator(full),
            Err(error) => {
                report(error);
                return false;
            }
        };
        if !exe::attributes(full).is_ok_and(|attributes| attributes & DIRECTORY != 0) {
            report(exe::Error(paths::ERROR_PATH_NOT_FOUND));
            return false;
        }
        if !self.switches.bare && !self.heading {
            if let Err(error) = self.volume_heading(full) {
                report(error);
                return false;
            }
            self.heading = true;
        }
        let mut totals = Totals::default();
        let found = if self.switches.subdirectories {
            let found = self.tree(full, pattern, &mut totals);
            if found && !self.switches.bare {
                self.print(rules::TOTAL_LISTED);
                self.totals(&totals);
                self.free(full, &totals);
            }
            found
        } else {
            if !self.switches.bare {
                self.print(DirectoryOf(full));
            }
            match self.directory(full, pattern, &mut totals) {
                Ok(true) => {
                    if !self.switches.bare {
                        self.free(full, &totals);
                    }
                    true
                }
                Ok(false) => false,
                Err(error) => {
                    report(error);
                    return false;
                }
            }
        };
        if !found {
            let _ = exe::stderr().print(format_args!("{}", rules::FILE_NOT_FOUND));
        }
        found
    }

    /// The volume's heading: its label and serial number, by the root of `full`'s drive.
    fn volume_heading(&mut self, full: &[u16]) -> Result<(), exe::Error> {
        let mut root = [0; 3];
        let root = drive_root(full, &mut root);
        let volume = exe::volume(root)?;
        self.print(VolumeLabel {
            drive: root.first().copied().unwrap_or(u16::from(b'?')),
            label: volume.label(),
        });
        self.print(SerialNumber(volume.serial));
        Ok(())
    }

    /// A listing's last line: its directories, and the bytes free on the drive `full` is on.
    fn free(&mut self, full: &[u16], totals: &Totals) {
        let mut root = [0; 3];
        let free = exe::free_bytes(drive_root(full, &mut root)).unwrap_or(0);
        self.print(DirectoryTotals {
            directories: totals.directories,
            free,
            separators: self.switches.separators,
        });
    }

    /// A directory's line of files and bytes.
    fn totals(&mut self, totals: &Totals) {
        self.print(FileTotals {
            files: totals.files,
            bytes: totals.bytes,
            separators: self.switches.separators,
        });
    }

    /// [`Listing::directory`] in `full` under its heading, then in each of its subdirectories,
    /// theirs, and so on, in the directory's order (`/S`); each directory that holds a match is
    /// listed with its own heading and line of files, and its counts added to `totals`. Whether
    /// any matched.
    #[inline(never)]
    fn tree(&mut self, full: &[u16], pattern: &[u16], totals: &mut Totals) -> bool {
        let mut own = Totals::default();
        let found = matches!(self.directory(full, pattern, &mut own), Ok(true));
        totals.files += own.files;
        totals.bytes += own.bytes;
        totals.directories += own.directories;
        let mut found_below = false;
        let mut buffer = [0; MAX_PATH];
        let Ok(Ok(entries)) = joined(full, STAR, &mut buffer).map(exe::find) else {
            return found;
        };
        for entry in entries {
            if entry.attributes & DIRECTORY == 0 || paths::is_dots(entry.name()) {
                continue;
            }
            let mut sub = [0; MAX_PATH];
            if let Ok(sub) = joined(full, entry.name(), &mut sub) {
                found_below |= self.tree(sub, pattern, totals);
            }
        }
        found || found_below
    }

    /// The entries `pattern` matches in the directory `full`, and that `/A` selects, printed in the
    /// listing's format and order, under the directory's heading with `/S`, then its line of files
    /// (the long and wide formats); their counts in `totals`. Ok(false) when none matches (the
    /// heading and the line of files left out), the error when the directory cannot be read.
    #[inline(never)]
    fn directory(
        &mut self,
        full: &[u16],
        pattern: &[u16],
        totals: &mut Totals,
    ) -> Result<bool, exe::Error> {
        let mut buffer = [0; MAX_PATH];
        let search = joined(full, pattern, &mut buffer)?;
        // The entries counted first, so that the buffers that hold them are as long as they need.
        let (mut count, mut units) = (0, 0);
        for entry in matches(search)? {
            if self.shows(&entry) {
                count += 1;
                units += entry.name().len() + entry.short_name().len();
            }
        }
        if count == 0 {
            return Ok(false);
        }
        let mut items = exe::Buffer::new(count, Item::default())?;
        let mut names = exe::Buffer::new(units, 0u16)?;
        let mut filled = 0;
        let mut used = 0;
        for (index, entry) in matches(search)?.enumerate() {
            if !self.shows(&entry) {
                continue;
            }
            let (name, short) = (entry.name(), entry.short_name());
            // The directory may have grown since it was counted: what does not fit is left out.
            let (Some(item), Some(room)) = (
                items.get_mut(filled),
                names.get_mut(used..used + name.len() + short.len()),
            ) else {
                break;
            };
            room[..name.len()].copy_from_slice(name);
            room[name.len()..].copy_from_slice(short);
            *item = Item {
                attributes: entry.attributes,
                size: entry.size,
                time: match self.switches.time {
                    TimeField::Creation => entry.creation_time,
                    TimeField::Access => entry.access_time,
                    TimeField::Written => entry.write_time,
                },
                index,
                name_start: used,
                name_length: name.len(),
                short_start: used + name.len(),
                short_length: short.len(),
            };
            filled += 1;
            used += name.len() + short.len();
        }
        let items = &mut items[..filled];
        if let Some(order) = &self.switches.order {
            rules::sort(items, &names, order);
        }
        for item in items.iter() {
            if item.is_directory() {
                totals.directories += 1;
            } else {
                totals.files += 1;
                totals.bytes += item.size;
            }
        }
        if self.switches.bare {
            for item in items.iter() {
                self.bare(full, item, &names);
            }
            return Ok(true);
        }
        if self.switches.subdirectories {
            self.print(DirectoryOf(full));
        }
        if self.switches.wide || self.switches.by_column {
            self.wide(items, &names);
        } else {
            for item in items.iter() {
                self.long(item, &names);
            }
        }
        self.totals(totals);
        Ok(true)
    }

    /// Whether the listing shows `entry`: `/A` selects it, and it is no `.` or `..` in the bare
    /// format.
    fn shows(&self, entry: &exe::Found) -> bool {
        self.switches.selection.selects(entry.attributes)
            && !(self.switches.bare && paths::is_dots(entry.name()))
    }

    /// An entry in the bare format: its name, after its directory with `/S`.
    fn bare(&mut self, full: &[u16], item: &Item, names: &[u16]) {
        let name = item.name(names);
        let lowercase = self.switches.lowercase;
        if self.switches.subdirectories {
            let mut path = [0; MAX_PATH];
            if let Ok(path) = joined(full, name, &mut path) {
                return self.print(Bare(Lowered(path, lowercase)));
            }
        }
        self.print(Bare(Lowered(name, lowercase)));
    }

    /// An entry in the long format.
    fn long(&mut self, item: &Item, names: &[u16]) {
        let time = exe::local_file_time(item.time)
            .map(|time| cmd::Time {
                year: time.year,
                month: time.month,
                weekday: time.day_of_week,
                day: time.day,
                hour: time.hour,
                minute: time.minute,
                second: time.second,
                milliseconds: time.milliseconds,
            })
            .unwrap_or_default();
        self.print(Entry {
            time: &time,
            directory: item.is_directory(),
            size: item.size,
            separators: self.switches.separators,
            short_name: self.switches.short_names.then(|| item.short_name(names)),
            name: item.name(names),
            lowercase: self.switches.lowercase,
        });
    }

    /// The entries in the wide format, side by side, across the rows (`/W`) or down the columns
    /// (`/D`), as many columns as the console window's width holds.
    fn wide(&mut self, items: &[Item], names: &[u16]) {
        let lowercase = self.switches.lowercase;
        let shown = |item: &Item| WideName {
            name: item.name(names),
            directory: item.is_directory(),
            lowercase,
        };
        let longest = items
            .iter()
            .map(|item| shown(item).columns())
            .max()
            .unwrap_or(0);
        let screen = exe::window_size()
            .ok()
            .flatten()
            .map_or(SCREEN_COLUMNS, |(columns, _)| usize::from(columns));
        let layout = Wide::new(items.len(), longest, screen, self.switches.by_column);
        for row in 0..layout.rows {
            self.print(WideRow {
                layout: &layout,
                row,
                items,
                shown: &shown,
            });
        }
    }
}

/// An entry's line in the bare format.
struct Bare<'a>(Lowered<'a>);

impl fmt::Display for Bare<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}\r\n", self.0)
    }
}

/// One row of the wide format: each entry padded to its column's width, but the row's last.
struct WideRow<'a, F: Fn(&Item) -> WideName<'a>> {
    layout: &'a Wide,
    row: usize,
    items: &'a [Item],
    shown: &'a F,
}

impl<'a, F: Fn(&Item) -> WideName<'a>> fmt::Display for WideRow<'a, F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for column in 0..self.layout.columns {
            let Some(place) = self.layout.at(self.row, column) else {
                break;
            };
            let name = (self.shown)(&self.items[place]);
            write!(f, "{name}")?;
            if self.layout.at(self.row, column + 1).is_some() {
                write!(
                    f,
                    "{:1$}",
                    "",
                    self.layout.width.saturating_sub(name.columns())
                )?;
            }
        }
        f.write_str("\r\n")
    }
}

/// The entries `search` matches: none (an empty search) when nothing does, the error when its
/// directory cannot be read.
fn matches(search: &[u16]) -> Result<impl Iterator<Item = exe::Found>, exe::Error> {
    match exe::find(search) {
        Ok(found) => Ok(Some(found).into_iter().flatten()),
        Err(exe::Error(ERROR_FILE_NOT_FOUND | ERROR_NO_MORE_FILES)) => {
            Ok(None.into_iter().flatten())
        }
        Err(error) => Err(error),
    }
}

/// `directory` and `name` joined, in `out`.
fn joined<'a>(
    directory: &[u16],
    name: &[u16],
    out: &'a mut [u16; MAX_PATH],
) -> Result<&'a [u16], exe::Error> {
    paths::join(directory, name, out).ok_or(TOO_LONG)
}

/// A full path without the separator it ends with, unless it is a drive's root (`C:\`).
fn without_separator(full: &[u16]) -> &[u16] {
    match full {
        [.., colon, _] if *colon == u16::from(b':') => full,
        [rest @ .., last] if *last == u16::from(b'\\') && !rest.is_empty() => rest,
        _ => full,
    }
}

/// The root directory of the drive a full path is on (`C:\`), in `out`; the path itself when it
/// names no drive.
fn drive_root<'a>(full: &'a [u16], out: &'a mut [u16; 3]) -> &'a [u16] {
    match full {
        [drive, colon, ..] if *colon == u16::from(b':') => {
            *out = [*drive, *colon, u16::from(b'\\')];
            &out[..]
        }
        _ => full,
    }
}
