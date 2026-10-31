//! The line a line-mode read edits, as Windows 2000's console edits it for every program's cooked
//! read (cmd.exe's prompt among them): the characters typed so far and the cursor among them,
//! insert or overtype, the echo redrawn on the screen buffer as the line changes, and the command
//! history the line recalls from and is recorded into.
//!
//! The keys, as Windows 2000's console documents them and its capture (the lineedit fixture)
//! shows them over queued key events:
//!
//! - Left, Right, Home and End move within the line; Ctrl+Left and Ctrl+Right by word (spaces part
//!   words). Ctrl+Right stops on the line's last character, never past it.
//! - Backspace and Delete take out the character before or at the cursor; Esc clears the line.
//! - Insert toggles insert and overtype for this line alone: each read starts in insert mode,
//!   whatever ENABLE_INSERT_MODE says (the capture: a read under mode 0x7 inserts too, and the mode
//!   reads back unchanged after a toggle). Windows 2000's console takes the starting mode from its
//!   own InsertMode setting, on unless the registry says otherwise, and F2K's registry has no
//!   `HKCU\Console`.
//! - Up, Down, PgUp, PgDn, F5 and F8 recall commands from the history ([`History`]); F1, F3 and
//!   Right at the line's end copy from the template, the newest command; F6 types ^Z; Alt+F7 clears
//!   the history.
//!
//! The echo lays the line out from the cell the read began at, one cell per character, two for a
//! control character (shown as ^ and its letter, as F6's ^Z), a tab as spaces to the next stop,
//! wrapping at the row's end; a line that wraps past the buffer's last row scrolls the buffer, and
//! the line's first row moves up with it. Each change redraws the line from the first character it
//! changed, and blanks the cells the line no longer takes.

use super::input::{
    KeyEventRecord,
    LEFT_ALT_PRESSED,
    LEFT_CTRL_PRESSED,
    RIGHT_ALT_PRESSED,
    RIGHT_CTRL_PRESSED,
};
use super::layout::{
    VK_DELETE,
    VK_DOWN,
    VK_END,
    VK_ESCAPE,
    VK_F1,
    VK_F3,
    VK_F5,
    VK_F6,
    VK_F7,
    VK_F8,
    VK_HOME,
    VK_INSERT,
    VK_LEFT,
    VK_NEXT,
    VK_PRIOR,
    VK_RIGHT,
    VK_UP,
};
use super::screen::{
    ScreenBuffer,
    ENABLE_PROCESSED_OUTPUT,
    ENABLE_WRAP_AT_EOL_OUTPUT,
    HEIGHT,
    WIDTH,
};
use crate::codepage::{self, CodePage};

/// The most characters a line-mode read's line holds, its CR LF included: the keys typed past
/// room for them are dropped.
pub const LINE_UNITS: usize = 1024;

/// The characters a line ends with, and the ones the editing keys stand for.
const CR: u16 = 0x0D;
const LF: u16 = 0x0A;
const BACKSPACE: u16 = 0x08;
const TAB: u16 = 0x09;
const SPACE: u16 = 0x20;
/// What F6 types: Ctrl+Z, the end-of-file character.
const CTRL_Z: u16 = 0x1A;

/// The columns between tab stops.
const TAB_STOP: usize = 8;

/// The mode each read starts in: insert. Windows 2000's console starts each read in its own
/// InsertMode setting (on, with no `HKCU\Console` to say otherwise), not in ENABLE_INSERT_MODE's
/// state, as its capture shows.
const INSERT_AT_START: bool = true;

/// The line a line-mode read builds: the characters typed so far, the cursor among them and
/// insert or overtype; where its echo starts on the screen and how many cells it takes; the
/// history buffer it goes with. Once its Enter arrived, the whole line with its CR LF, handed to
/// readers a buffer at a time until all of it is taken.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Line {
    units: [u16; LINE_UNITS],
    length: usize,
    /// How much of a complete line readers have taken.
    taken: usize,
    complete: bool,
    /// Whether a read has begun the line: its echo's first cell and its history are set.
    begun: bool,
    /// The cursor: the index of the character it stands on (the length at the line's end).
    cursor: usize,
    /// Typing inserts (true) or overtypes.
    insert: bool,
    /// The echo's first cell: its row (moved up as the buffer scrolls under the line) and column.
    row: usize,
    column: usize,
    /// The cells the echo takes.
    shown: usize,
    /// The history buffer the line recalls from and is recorded into.
    history: Option<usize>,
}

impl Line {
    pub const fn new() -> Self {
        Line {
            units: [0; LINE_UNITS],
            length: 0,
            taken: 0,
            complete: false,
            begun: false,
            cursor: 0,
            insert: INSERT_AT_START,
            row: 0,
            column: 0,
            shown: 0,
            history: None,
        }
    }

    /// The characters typed so far, or the complete line's part no reader took yet.
    pub fn pending(&self) -> &[u16] {
        &self.units[self.taken..self.length]
    }

    /// Whether the line's Enter arrived.
    pub fn is_complete(&self) -> bool {
        self.complete
    }

    /// Whether a read has begun the line.
    pub fn is_begun(&self) -> bool {
        self.begun
    }

    /// Begin the line for a read: its echo starts at `cursor` (row, column), and it goes with the
    /// history buffer `history`. A line begun already, by a read that waited for its Enter, stays
    /// as it is.
    pub fn begin(&mut self, cursor: (usize, usize), history: Option<usize>) {
        if self.begun {
            return;
        }
        self.begun = true;
        (self.row, self.column) = cursor;
        self.history = history;
    }

    /// The complete line's characters readers took: the line starts afresh once all are taken.
    /// The characters stay where they are (the next line overwrites them).
    pub fn consume(&mut self, count: usize) {
        self.taken = (self.taken + count).min(self.length);
        if self.taken == self.length {
            self.length = 0;
            self.taken = 0;
            self.complete = false;
            self.begun = false;
            self.cursor = 0;
            self.insert = INSERT_AT_START;
            self.shown = 0;
            self.history = None;
        }
    }

    /// Take one key going down: its edit applied to the line and, with `echo`, redrawn on the
    /// screen buffer; true when it was the Enter that completes the line (its CR LF added, the
    /// line recorded into its history when echoed — a line read without echo, a password, is
    /// kept out of it). The keys without an edit and the characters past the line's room do
    /// nothing.
    pub fn key(
        &mut self,
        key: &KeyEventRecord,
        histories: &mut Histories,
        echo: Option<&mut ScreenBuffer>,
    ) -> bool {
        let state = key.control_key_state;
        let ctrl = state & (LEFT_CTRL_PRESSED | RIGHT_CTRL_PRESSED) != 0;
        let alt = state & (LEFT_ALT_PRESSED | RIGHT_ALT_PRESSED) != 0;
        let vk = u8::try_from(key.virtual_key_code).unwrap_or(0);
        let mut history = self.history.map(|index| &mut histories.buffers[index]);
        let changed = match vk {
            VK_ESCAPE => self.replace(&[], 0),
            _ if key.char == CR => {
                if echo.is_some() && self.length != 0 {
                    if let Some(history) = history {
                        history.add(&self.units[..self.length]);
                    }
                }
                self.units[self.length] = CR;
                self.units[self.length + 1] = LF;
                self.length += 2;
                self.complete = true;
                return true;
            }
            _ if key.char == BACKSPACE => self.back_space(),
            _ if key.char != 0 => self.type_unit(key.char),
            VK_HOME => self.go(0),
            VK_END => self.go(self.length),
            VK_LEFT if ctrl => self.go(self.word_left()),
            VK_LEFT => self.go(self.cursor.saturating_sub(1)),
            VK_RIGHT if ctrl => self.go(self.word_right()),
            VK_RIGHT | VK_F1 if self.cursor < self.length => self.go(self.cursor + 1),
            VK_RIGHT | VK_F1 => {
                let next = history
                    .and_then(|history| history.newest())
                    .and_then(|template| template.get(self.cursor).copied());
                next.and_then(|unit| self.type_unit(unit))
            }
            VK_F3 => {
                let template = history.and_then(|history| history.newest());
                template.and_then(|template| self.copy_template(template))
            }
            VK_INSERT => {
                self.insert = !self.insert;
                None
            }
            VK_DELETE => self.delete(),
            VK_F6 => self.type_unit(CTRL_Z),
            VK_F7 if alt => {
                if let Some(history) = history {
                    history.clear();
                }
                None
            }
            VK_F8 => {
                let found = history
                    .as_deref_mut()
                    .and_then(|history| history.search(&self.units[..self.cursor]));
                match (found, history) {
                    (Some(index), Some(history)) => {
                        self.replace(history.command(index), self.cursor)
                    }
                    _ => None,
                }
            }
            VK_UP | VK_DOWN | VK_PRIOR | VK_NEXT | VK_F5 => {
                let found = history.as_deref_mut().and_then(|history| match vk {
                    VK_UP => history.up(),
                    VK_DOWN => history.down(),
                    VK_PRIOR => history.oldest(),
                    VK_NEXT => history.newest_index(),
                    _ => history.previous(),
                });
                match (found, history) {
                    (Some(index), Some(history)) => {
                        let command = history.command(index);
                        self.replace(command, command.len())
                    }
                    _ => None,
                }
            }
            _ => None,
        };
        if let Some(screen) = echo {
            match changed {
                Some(from) => self.redraw(from, screen),
                None => self.place_cursor(screen),
            }
        }
        false
    }

    /// The cursor moved to `index`: nothing to redraw.
    fn go(&mut self, index: usize) -> Option<usize> {
        self.cursor = index;
        None
    }

    /// The start of the word before the cursor: back over spaces, then over the word.
    fn word_left(&self) -> usize {
        let mut at = self.cursor;
        while at > 0 && self.units[at - 1] == SPACE {
            at -= 1;
        }
        while at > 0 && self.units[at - 1] != SPACE {
            at -= 1;
        }
        at
    }

    /// The start of the word after the cursor: on over the word, then over spaces, stopping at the
    /// line's last character (the capture: three Ctrl+Rights and a fourth from the start of
    /// "one two three" leave the cursor on its final e). At the line's end, nowhere.
    fn word_right(&self) -> usize {
        let mut at = self.cursor;
        if at >= self.length {
            return at;
        }
        let last = self.length - 1;
        while at < last && self.units[at] != SPACE {
            at += 1;
        }
        while at < last && self.units[at] == SPACE {
            at += 1;
        }
        at
    }

    /// Whether the line has room for one more character, its CR LF kept room for.
    fn has_room(&self) -> bool {
        self.length + 2 < LINE_UNITS
    }

    /// Type `unit` at the cursor: inserted, or over the character there in overtype (at the
    /// line's end it is added either way). Redrawn from where it went; dropped without room.
    fn type_unit(&mut self, unit: u16) -> Option<usize> {
        let at = self.cursor;
        if self.insert || at == self.length {
            if !self.has_room() {
                return None;
            }
            self.units.copy_within(at..self.length, at + 1);
            self.length += 1;
        }
        self.units[at] = unit;
        self.cursor += 1;
        Some(at)
    }

    /// Backspace: the character before the cursor taken out (overtype too).
    fn back_space(&mut self) -> Option<usize> {
        if self.cursor == 0 {
            return None;
        }
        self.cursor -= 1;
        self.units
            .copy_within(self.cursor + 1..self.length, self.cursor);
        self.length -= 1;
        Some(self.cursor)
    }

    /// Delete: the character at the cursor taken out.
    fn delete(&mut self) -> Option<usize> {
        if self.cursor == self.length {
            return None;
        }
        self.units
            .copy_within(self.cursor + 1..self.length, self.cursor);
        self.length -= 1;
        Some(self.cursor)
    }

    /// The line replaced by `text` (cut at the line's room), the cursor at `cursor`: redrawn whole.
    fn replace(&mut self, text: &[u16], cursor: usize) -> Option<usize> {
        let length = text.len().min(LINE_UNITS - 2);
        self.units[..length].copy_from_slice(&text[..length]);
        self.length = length;
        self.cursor = cursor.min(length);
        Some(0)
    }

    /// F3: as many characters as the template holds past the cursor, added at the line's end and
    /// taken from the template at the line's length — blanks past the template's end — the cursor
    /// then at the end. What Windows 2000's capture shows: with "abcdef" the template, "xy" and F3
    /// make "xycdef", and "abcdefgh", Home and F3 make "abcdefgh" and six blanks.
    fn copy_template(&mut self, template: &[u16]) -> Option<usize> {
        let count = template
            .len()
            .checked_sub(self.cursor)
            .filter(|&count| count != 0)?;
        let from = self.length;
        for index in from..from + count {
            if !self.has_room() {
                break;
            }
            self.units[self.length] = template.get(index).copied().unwrap_or(SPACE);
            self.length += 1;
        }
        self.cursor = self.length;
        Some(from)
    }

    /// The echo's cells of `unit` at the cell `at` from the echo's first one, into `cells`: how
    /// many it takes.
    fn glyph(&self, unit: u16, at: usize, cells: &mut [u8; TAB_STOP]) -> usize {
        match unit {
            TAB => {
                let count = TAB_STOP - (self.column + at) % TAB_STOP;
                cells[..count].fill(b' ');
                count
            }
            0..SPACE => {
                cells[0] = b'^';
                cells[1] = unit as u8 + b'@';
                2
            }
            _ => {
                cells[0] = codepage::encode_unit(CodePage::Oem, unit, true).unwrap_or(b'?');
                1
            }
        }
    }

    /// The cells the echo takes before the character at `index`.
    fn offset(&self, index: usize) -> usize {
        let mut cells = [0; TAB_STOP];
        self.units[..index]
            .iter()
            .fold(0, |at, &unit| at + self.glyph(unit, at, &mut cells))
    }

    /// The buffer's row and column of the echo's cell `at`, kept inside the buffer.
    fn cell(&self, at: usize) -> (usize, usize) {
        let linear = self.row * WIDTH + self.column + at;
        ((linear / WIDTH).min(HEIGHT - 1), linear % WIDTH)
    }

    /// The echo's cells of the characters from `index` up to `end`, a piece at a time to
    /// `cells`: the cell after the last.
    fn each_piece(&self, index: usize, end: usize, mut cells: impl FnMut(&[u8])) -> usize {
        let mut at = self.offset(index);
        let mut piece = [0u8; 64];
        let mut used = 0;
        let mut glyph = [0u8; TAB_STOP];
        for &unit in &self.units[index..end] {
            let count = self.glyph(unit, at, &mut glyph);
            if used + count > piece.len() {
                cells(&piece[..used]);
                used = 0;
            }
            piece[used..used + count].copy_from_slice(&glyph[..count]);
            used += count;
            at += count;
        }
        cells(&piece[..used]);
        at
    }

    /// Redraw the echo from the character at `index` on, in a write of its own: its cells, then
    /// blanks over the cells the line took before and no longer does; the buffer scrolled under
    /// the line moves its first row up; the cursor put back on the line's.
    fn redraw(&mut self, index: usize, screen: &mut ScreenBuffer) {
        let mode = screen.mode();
        // Each byte a cell, wrapping at the row's end, whatever the output mode.
        screen.set_mode(ENABLE_WRAP_AT_EOL_OUTPUT);
        let (row, column) = self.cell(self.offset(index));
        screen.set_cursor(row, column);
        screen.begin_write();
        let end = self.each_piece(index, self.length, |cells| screen.render(cells));
        let reached = end.max(self.shown);
        let blanks = [b' '; 64];
        let mut left = reached - end;
        while left != 0 {
            let take = left.min(blanks.len());
            screen.render(&blanks[..take]);
            left -= take;
        }
        screen.end_write();
        screen.set_mode(mode);
        // The row the write's end would have reached in a buffer without end, against the one
        // it reached: the rows the buffer scrolled.
        let expected = (self.row * WIDTH + self.column + reached) / WIDTH;
        let scrolled = expected.saturating_sub(screen.cursor().0);
        self.row = self.row.saturating_sub(scrolled);
        self.shown = end;
        self.place_cursor(screen);
    }

    /// The screen's cursor on the line's.
    fn place_cursor(&self, screen: &mut ScreenBuffer) {
        let (row, column) = self.cell(self.offset(self.cursor));
        screen.set_cursor(row, column);
    }

    /// The Enter's echo: the whole line again from its first cell (the same cells the edits left),
    /// then CR LF, each piece through `print` — the screen's cursor put on the line's first cell
    /// first, and the output mode the echo needs set around it.
    pub fn echo_entered(
        &self,
        screen: &mut ScreenBuffer,
        mut print: impl FnMut(&mut ScreenBuffer, &[u8]),
    ) {
        let mode = screen.mode();
        screen.set_mode(ENABLE_WRAP_AT_EOL_OUTPUT);
        let (row, column) = self.cell(0);
        screen.set_cursor(row, column);
        screen.begin_write();
        // The CR LF is not the line's to show.
        let end = self.length.saturating_sub(2);
        self.each_piece(0, end, |cells| print(&mut *screen, cells));
        screen.set_mode(ENABLE_PROCESSED_OUTPUT | ENABLE_WRAP_AT_EOL_OUTPUT);
        print(&mut *screen, b"\r\n");
        screen.end_write();
        screen.set_mode(mode);
    }
}

impl Default for Line {
    fn default() -> Self {
        Self::new()
    }
}

/// How many commands a history buffer keeps, and how many buffers a console has: Windows 2000's
/// defaults (HistoryBufferSize 50, NumberOfHistoryBuffers 4), which F2K's registry, with no
/// `HKCU\Console`, leaves them at. Duplicates are kept (HistoryNoDup 0).
pub const HISTORY_COMMANDS: usize = 50;
pub const HISTORY_BUFFERS: usize = 4;

/// The characters a history buffer keeps, all its commands together: F2K's own bound (Windows
/// 2000 allocates each command; the console lives in the kernel's image here, whose room is
/// tight). The oldest commands go to make room for a new one: a buffer of commands as long as a
/// row holds 25 of them.
pub const HISTORY_UNITS: usize = 2048;

/// The room for a program's name, the key of its history buffer.
const NAME_ROOM: usize = 16;

/// One program's command history: its commands, oldest first, and the command last displayed.
///
/// The rules, as Windows 2000's capture shows them (the lineedit fixture's history, search and
/// fkeys sections): a line entered is added (an empty one is not); the command last displayed
/// then is the new one — unless the line is the command last displayed, which stays so, so a
/// recalled command entered again leaves Down at the one after it. The first Up after a line is
/// added shows the command last displayed itself, every other Up the one before it (never past
/// the oldest); Down shows the one after it (never past the newest), PgUp the oldest, PgDn the
/// newest, F5 always the one before it. F8 looks back from the command last displayed (itself
/// first, after a line is added) for one starting with the characters before the cursor, round
/// past the oldest to the newest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct History {
    /// The program the buffer is for (its name's bytes), whether a program has it at all, and
    /// when a program last read with it (the least recently used one is taken for a new program).
    name: [u8; NAME_ROOM],
    name_length: usize,
    claimed: bool,
    used: u32,
    /// Each command's length, oldest first, and their characters back to back.
    lengths: [u16; HISTORY_COMMANDS],
    count: usize,
    units: [u16; HISTORY_UNITS],
    filled: usize,
    /// The command last displayed, and whether a line was added since anything was displayed.
    shown: usize,
    reset: bool,
}

impl History {
    const fn new() -> Self {
        History {
            name: [0; NAME_ROOM],
            name_length: 0,
            claimed: false,
            used: 0,
            lengths: [0; HISTORY_COMMANDS],
            count: 0,
            units: [0; HISTORY_UNITS],
            filled: 0,
            shown: 0,
            reset: true,
        }
    }

    /// How many commands it holds.
    pub fn len(&self) -> usize {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// The command at `index`, the oldest 0.
    pub fn command(&self, index: usize) -> &[u16] {
        let start: usize = self.lengths[..index]
            .iter()
            .map(|&length| length as usize)
            .sum();
        &self.units[start..start + self.lengths[index] as usize]
    }

    /// The newest command: the template F1 and F3 copy from.
    pub fn newest(&self) -> Option<&[u16]> {
        self.count.checked_sub(1).map(|index| self.command(index))
    }

    /// Add `command` (not an empty one), the oldest commands going to make room.
    pub fn add(&mut self, command: &[u16]) {
        if command.is_empty() {
            return;
        }
        let command = &command[..command.len().min(HISTORY_UNITS)];
        let mut keep = self.count != 0 && self.command(self.shown) == command;
        while self.count == HISTORY_COMMANDS || self.filled + command.len() > HISTORY_UNITS {
            let first = self.lengths[0] as usize;
            self.units.copy_within(first..self.filled, 0);
            self.filled -= first;
            self.lengths.copy_within(1..self.count, 0);
            self.count -= 1;
            match self.shown.checked_sub(1) {
                Some(shown) => self.shown = shown,
                None => keep = false,
            }
        }
        self.units[self.filled..self.filled + command.len()].copy_from_slice(command);
        self.filled += command.len();
        self.lengths[self.count] = command.len() as u16;
        self.count += 1;
        if !keep {
            self.shown = self.count - 1;
        }
        self.reset = true;
    }

    /// Forget every command (Alt+F7).
    pub fn clear(&mut self) {
        self.count = 0;
        self.filled = 0;
        self.shown = 0;
        self.reset = true;
    }

    /// Display the command at `index`: its index.
    fn display(&mut self, index: usize) -> Option<usize> {
        self.shown = index;
        self.reset = false;
        Some(index)
    }

    /// Up: the command last displayed, first after a line was added; the one before it otherwise.
    pub fn up(&mut self) -> Option<usize> {
        if self.count == 0 {
            return None;
        }
        let index = if self.reset {
            self.shown
        } else {
            self.shown.saturating_sub(1)
        };
        self.display(index)
    }

    /// Down: the command after the one last displayed; none past the newest.
    pub fn down(&mut self) -> Option<usize> {
        let index = self.shown + 1;
        (index < self.count).then(|| self.display(index)).flatten()
    }

    /// PgUp: the oldest command.
    pub fn oldest(&mut self) -> Option<usize> {
        (self.count != 0).then(|| self.display(0)).flatten()
    }

    /// PgDn: the newest command.
    pub fn newest_index(&mut self) -> Option<usize> {
        let index = self.count.checked_sub(1)?;
        self.display(index)
    }

    /// F5: the command before the one last displayed (the oldest stays).
    pub fn previous(&mut self) -> Option<usize> {
        if self.count == 0 {
            return None;
        }
        self.display(self.shown.saturating_sub(1))
    }

    /// F8: the first command back from the one last displayed (itself first, after a line was
    /// added; the one before it otherwise), round past the oldest to the newest, that starts with
    /// `prefix`; none matches, nothing displayed.
    pub fn search(&mut self, prefix: &[u16]) -> Option<usize> {
        let count = self.count;
        if count == 0 {
            return None;
        }
        let start = if self.reset {
            self.shown
        } else {
            (self.shown + count - 1) % count
        };
        let found = (0..count)
            .map(|step| (start + count - step) % count)
            .find(|&index| self.command(index).starts_with(prefix))?;
        self.display(found)
    }
}

/// A console's history buffers, one per program name, [`HISTORY_BUFFERS`] of them: a program's
/// buffer outlives the program, for the next one of its name, as Windows 2000's console keeps it.
/// A program with no buffer of its name takes a free one, else the least recently used one,
/// emptied. (Windows 2000 takes only a buffer no running program holds; F2K's server does not
/// follow processes ending, so a program still running may lose its buffer to a fifth.)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Histories {
    buffers: [History; HISTORY_BUFFERS],
    /// A count each claim raises: the buffers' use order.
    clock: u32,
}

impl Histories {
    pub const fn new() -> Self {
        Histories {
            buffers: [const { History::new() }; HISTORY_BUFFERS],
            clock: 0,
        }
    }

    /// The buffer of the program `name` (in the console's code page; compared without case, cut at
    /// the buffer's room): its index.
    pub fn claim(&mut self, name: &[u8]) -> usize {
        let name = &name[..name.len().min(NAME_ROOM)];
        self.clock = self.clock.wrapping_add(1);
        let found = self.buffers.iter().position(|buffer| {
            buffer.claimed && buffer.name[..buffer.name_length].eq_ignore_ascii_case(name)
        });
        let index = found.unwrap_or_else(|| {
            // A free buffer first, else the one whose last use is the longest ago.
            let clock = self.clock;
            let (index, _) = self
                .buffers
                .iter()
                .enumerate()
                .max_by_key(|(_, buffer)| (!buffer.claimed, clock.wrapping_sub(buffer.used)))
                .unwrap_or((0, &self.buffers[0]));
            let buffer = &mut self.buffers[index];
            buffer.clear();
            buffer.name[..name.len()].copy_from_slice(name);
            buffer.name_length = name.len();
            buffer.claimed = true;
            index
        });
        self.buffers[index].used = self.clock;
        index
    }

    /// The buffer at `index`.
    pub fn buffer(&self, index: usize) -> &History {
        &self.buffers[index]
    }
}

impl Default for Histories {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use std::boxed::Box;
    use std::format;
    use std::string::String;
    use std::vec::Vec;

    use super::*;
    use crate::console::input::ENHANCED_KEY;
    use crate::console::screen::Fill;

    /// Set 1 scan codes of the letters, as the lineedit fixture queues them.
    const SCAN_LETTERS: [u16; 26] = [
        0x1E, 0x30, 0x2E, 0x20, 0x12, 0x21, 0x22, 0x23, 0x17, 0x24, 0x25, 0x26, 0x32, 0x31, 0x18,
        0x19, 0x10, 0x13, 0x1F, 0x14, 0x16, 0x2F, 0x11, 0x2D, 0x15, 0x2C,
    ];

    /// The fixture's named keys: virtual key, scan code, character, control-key state.
    fn named(name: &str) -> (u16, u16, u16, u32) {
        let enhanced = ENHANCED_KEY;
        match name {
            "Enter" => (0x0D, 0x1C, 0x0D, 0),
            "Esc" => (0x1B, 0x01, 0x1B, 0),
            "BS" => (0x08, 0x0E, 0x08, 0),
            "Left" => (0x25, 0x4B, 0, enhanced),
            "Right" => (0x27, 0x4D, 0, enhanced),
            "Up" => (0x26, 0x48, 0, enhanced),
            "Down" => (0x28, 0x50, 0, enhanced),
            "Home" => (0x24, 0x47, 0, enhanced),
            "End" => (0x23, 0x4F, 0, enhanced),
            "PgUp" => (0x21, 0x49, 0, enhanced),
            "PgDn" => (0x22, 0x51, 0, enhanced),
            "Ins" => (0x2D, 0x52, 0, enhanced),
            "Del" => (0x2E, 0x53, 0, enhanced),
            "F1" => (0x70, 0x3B, 0, 0),
            "F3" => (0x72, 0x3D, 0, 0),
            "F5" => (0x74, 0x3F, 0, 0),
            "F6" => (0x75, 0x40, 0, 0),
            "F8" => (0x77, 0x42, 0, 0),
            "C-Left" => (0x25, 0x4B, 0, enhanced | LEFT_CTRL_PRESSED),
            "C-Right" => (0x27, 0x4D, 0, enhanced | LEFT_CTRL_PRESSED),
            "A-F7" => (0x76, 0x41, 0, LEFT_ALT_PRESSED),
            other => panic!("no key {other}"),
        }
    }

    fn key(down: bool, vk: u16, scan: u16, char: u16, state: u32) -> KeyEventRecord {
        KeyEventRecord {
            key_down: u32::from(down),
            repeat_count: 1,
            virtual_key_code: vk,
            virtual_scan_code: scan,
            char,
            control_key_state: state,
        }
    }

    /// The records a fixture spec makes, as the fixture's build() makes them: letters, digits and
    /// spaces as typed, {Name} for a named key, Ctrl and Alt pressed and released around the keys
    /// they modify.
    fn records(spec: &str) -> Vec<KeyEventRecord> {
        let mut out = Vec::new();
        let mut rest = spec;
        while let Some(first) = rest.chars().next() {
            let (vk, scan, char, state) = if first == '{' {
                let end = rest.find('}').expect("a closed name");
                let found = named(&rest[1..end]);
                rest = &rest[end + 1..];
                found
            } else {
                rest = &rest[1..];
                let char = first as u16;
                match first {
                    'a'..='z' => (char - 32, SCAN_LETTERS[(char - 0x61) as usize], char, 0),
                    '1'..='9' => (char, char - 0x31 + 2, char, 0),
                    '0' => (char, 0x0B, char, 0),
                    ' ' => (0x20, 0x39, char, 0),
                    other => panic!("no key {other}"),
                }
            };
            if state & LEFT_CTRL_PRESSED != 0 {
                out.push(key(true, 0x11, 0x1D, 0, LEFT_CTRL_PRESSED));
            }
            if state & LEFT_ALT_PRESSED != 0 {
                out.push(key(true, 0x12, 0x38, 0, LEFT_ALT_PRESSED));
            }
            out.push(key(true, vk, scan, char, state));
            out.push(key(false, vk, scan, char, state));
            if state & LEFT_ALT_PRESSED != 0 {
                out.push(key(false, 0x12, 0x38, 0, 0));
            }
            if state & LEFT_CTRL_PRESSED != 0 {
                out.push(key(false, 0x11, 0x1D, 0, 0));
            }
        }
        out
    }

    /// A console's line reads over one program's history, as the server's line-mode read drives
    /// them.
    struct Session {
        screen: Box<ScreenBuffer>,
        histories: Box<Histories>,
        line: Box<Line>,
        program: &'static [u8],
        echo: bool,
    }

    impl Session {
        fn new() -> Self {
            Session {
                screen: Box::new(ScreenBuffer::new()),
                histories: Box::new(Histories::new()),
                line: Box::new(Line::new()),
                program: b"lineedit",
                echo: true,
            }
        }

        /// One read over `spec` and Enter: the line read, its CR LF left out.
        fn edit(&mut self, spec: &str) -> String {
            let history = self.histories.claim(self.program);
            self.line.begin(self.screen.cursor(), Some(history));
            let mut all = records(spec);
            all.extend(records("{Enter}"));
            for record in all.iter().filter(|record| record.key_down != 0) {
                let echo = if self.echo {
                    Some(&mut *self.screen)
                } else {
                    None
                };
                if self.line.key(record, &mut self.histories, echo) {
                    break;
                }
            }
            assert!(self.line.is_complete());
            if self.echo {
                self.line
                    .echo_entered(&mut self.screen, |screen, bytes| screen.render(bytes));
            }
            let text = String::from_utf16(self.line.pending()).unwrap();
            self.line.consume(usize::MAX);
            text.strip_suffix("\r\n").expect("the CR LF").into()
        }

        /// Row `row` of the screen, trailing blanks trimmed.
        fn row(&self, row: usize) -> String {
            String::from_utf8(self.screen.row_text(row).to_vec())
                .unwrap()
                .trim_end()
                .into()
        }
    }

    #[test]
    fn plain_lines_are_read_as_typed() {
        let mut session = Session::new();
        assert_eq!(session.edit("abc"), "abc");
        assert_eq!(session.edit(""), "");
        assert_eq!(session.edit("a  b "), "a  b ");
        assert_eq!(
            (session.row(0), session.row(2), session.screen.cursor()),
            ("abc".into(), "a  b".into(), (3, 0))
        );
    }

    #[test]
    fn left_right_home_and_end_move_within_the_line() {
        let mut session = Session::new();
        assert_eq!(session.edit("abcd{Left}{Left}x"), "abxcd");
        assert_eq!(session.edit("abcd{Home}x"), "xabcd");
        assert_eq!(session.edit("abcd{Home}{End}x"), "abcdx");
        assert_eq!(session.edit("abcd{Home}{Right}{Right}x"), "abxcd");
        assert_eq!(
            session.edit("ab{Left}{Left}{Left}{Left}x"),
            "xab",
            "never past the start"
        );
        assert_eq!(session.edit("{Left}{Home}{End}x"), "x");
        assert_eq!(session.row(0), "abxcd", "the echo redrawn");
    }

    #[test]
    fn ctrl_left_and_right_move_by_word() {
        let mut session = Session::new();
        assert_eq!(session.edit("one two three{C-Left}x"), "one two xthree");
        assert_eq!(
            session.edit("one two three{C-Left}{C-Left}x"),
            "one xtwo three"
        );
        assert_eq!(
            session.edit("one two three{C-Left}{C-Left}{C-Left}{C-Left}x"),
            "xone two three"
        );
        assert_eq!(
            session.edit("one two three{Home}{C-Right}{C-Right}x"),
            "one two xthree"
        );
        assert_eq!(
            session.edit("one two three{Home}{C-Right}{C-Right}{C-Right}{C-Right}x"),
            "one two threxe",
            "the last character, never past it"
        );
        assert_eq!(session.edit("one two{Left}{Left}{C-Left}x"), "one xtwo");
        assert_eq!(session.edit("one  two{C-Left}{C-Left}x"), "xone  two");
    }

    #[test]
    fn delete_backspace_and_esc_take_characters_out() {
        let mut session = Session::new();
        assert_eq!(session.edit("abcd{Left}{Left}{Del}"), "abd");
        assert_eq!(session.edit("abcd{Home}{Del}{Del}"), "cd");
        assert_eq!(session.edit("abcd{Del}"), "abcd");
        assert_eq!(session.edit("abcd{Left}{BS}"), "abd");
        assert_eq!(session.edit("abcd{Home}{BS}"), "abcd");
        assert_eq!(session.edit("abcd{BS}{BS}x"), "abx");
        assert_eq!(session.edit("abcd{Left}{Left}{Esc}xy"), "xy");
        assert_eq!(session.row(6), "xy", "the cleared cells blanked");
    }

    #[test]
    fn insert_toggles_overtype_for_its_line_alone() {
        let mut session = Session::new();
        assert_eq!(session.edit("abcd{Home}xy"), "xyabcd");
        assert_eq!(session.edit("abcd{Home}{Ins}xy"), "xycd");
        assert_eq!(
            session.edit("abcd{Home}xy"),
            "xyabcd",
            "the next line inserts"
        );
        assert_eq!(session.edit("abcd{Home}{Ins}{Ins}xy"), "xyabcd");
        assert_eq!(
            session.edit("ab{Home}{Ins}xyz"),
            "xyz",
            "overtyping past the end"
        );
        assert_eq!(session.edit("abcd{Left}{Left}{BS}x"), "axcd");
        assert_eq!(session.edit("abcd{Left}{Left}{Del}x"), "abxd");
    }

    /// A line longer than a row wraps; an edit at its start redraws it across the wrap; a line of
    /// exactly a row leaves the cursor on the next row.
    #[test]
    fn long_lines_wrap_and_redraw_across_rows() {
        let letters = letters(170);
        let mut session = Session::new();
        assert_eq!(
            session.edit(&format!("{}{{Home}}x", &letters[..100])).len(),
            101
        );
        assert_eq!(session.row(0), format!("x{}", &letters[..79]));
        assert_eq!(session.row(1), letters[79..100]);
        assert_eq!(session.screen.cursor(), (2, 0));
        let lefts = "{Left}".repeat(25);
        assert_eq!(
            session.edit(&format!("{}{lefts}{{BS}}{{BS}}", &letters[..100])),
            format!("{}{}", &letters[..73], &letters[75..100])
        );
        assert_eq!(
            session.row(3),
            letters[82..100],
            "the second row's start pulled back"
        );
        assert_eq!(session.edit(&format!("{}{{Esc}}xy", &letters[..100])), "xy");
        assert_eq!(
            (session.row(4), session.row(5)),
            ("xy".into(), String::new())
        );
        assert_eq!(session.screen.cursor(), (5, 0));
        session.edit(&letters[..80]);
        assert_eq!(
            session.screen.cursor(),
            (7, 0),
            "a full row, then the Enter's row"
        );
    }

    /// A line typed on the buffer's last row scrolls the buffer as it wraps, and its edits are
    /// redrawn over the rows it moved to.
    #[test]
    fn a_line_on_the_last_row_scrolls_the_buffer() {
        let letters = letters(170);
        let last = HEIGHT - 1;
        let mut session = Session::new();
        session.screen.set_cursor(last, 0);
        session.edit(&format!("{letters}{{Home}}x"));
        assert_eq!(session.row(last - 3), format!("x{}", &letters[..79]));
        assert_eq!(session.row(last - 2), letters[79..159]);
        assert_eq!(session.row(last - 1), letters[159..170]);
        assert_eq!(session.screen.cursor(), (last, 0));
        session
            .screen
            .fill(0, 0, WIDTH * HEIGHT, Fill::Character(b' '));
        session.screen.set_cursor(last, 0);
        session.edit(&format!("{}{{Esc}}xy", &letters[..100]));
        assert_eq!(
            (
                session.row(last - 2),
                session.row(last - 1),
                session.row(last)
            ),
            (String::new(), "xy".into(), String::new())
        );
    }

    #[test]
    fn up_down_pgup_pgdn_and_f5_recall_commands() {
        let mut session = Session::new();
        for line in ["one", "two", "three"] {
            session.edit(line);
        }
        assert_eq!(session.edit("{Up}"), "three");
        assert_eq!(session.edit("{Up}{Up}"), "two");
        assert_eq!(
            session.edit(&"{Up}".repeat(8)),
            "one",
            "never past the oldest"
        );
        assert_eq!(session.edit("{Up}{Down}"), "two");
        assert_eq!(
            session.edit("{Down}"),
            "three",
            "after the command entered again"
        );
        assert_eq!(session.edit("{PgUp}"), "one");
        assert_eq!(
            session.edit("{PgDn}"),
            "one",
            "the newest: the one entered last"
        );
        assert_eq!(session.edit("{Up}x"), "onex");
        assert_eq!(session.edit("ab{Up}"), "onex", "what was typed replaced");
        assert_eq!(session.edit("{Up}{Esc}"), "");
        assert_eq!(session.edit("{F5}"), "one");
        assert_eq!(session.edit("{F5}{F5}"), "three");
    }

    #[test]
    fn f1_f3_and_right_copy_from_the_template_and_f6_types_ctrl_z() {
        let mut session = Session::new();
        for (spec, read) in [
            ("{F1}{F1}", "ab"),
            ("{F3}", "abcdef"),
            ("xy{F3}", "xycdef"),
            ("{F1}{F1}{F1}{F3}", "abcdef"),
            ("{Right}{Right}", "ab"),
            ("abcdefgh{Home}{F3}", "abcdefgh      "),
        ] {
            session.edit("abcdef");
            assert_eq!(session.edit(spec), read, "{spec}");
        }
        assert_eq!(session.edit("ab{F6}cd"), "ab\u{1A}cd");
        let row = session.screen.cursor().0 - 1;
        assert_eq!(
            session.row(row),
            "ab^Zcd",
            "a control character shown as ^ and its letter"
        );
    }

    #[test]
    fn f8_finds_the_commands_starting_with_what_was_typed() {
        let mut session = Session::new();
        for line in ["dir one", "echo two", "dir three"] {
            session.edit(line);
        }
        assert_eq!(session.edit("d{F8}"), "dir three");
        assert_eq!(session.edit("d{F8}{F8}"), "dir one");
        assert_eq!(session.edit("e{F8}"), "echo two");
        assert_eq!(session.edit("x{F8}"), "x", "no match: the line as it was");
        assert_eq!(session.edit("{F8}"), "x", "nothing typed: any command");
        assert_eq!(session.edit("dir t{F8}"), "dir three");
    }

    #[test]
    fn alt_f7_clears_the_history() {
        let mut session = Session::new();
        session.edit("one");
        session.edit("two");
        assert_eq!(session.edit("{A-F7}"), "");
        assert_eq!(session.edit("{Up}"), "");
        assert_eq!(session.edit("{F3}"), "");
        session.edit("three");
        assert_eq!(session.edit("{Up}"), "three");
        assert_eq!(session.edit("ab{A-F7}cd"), "abcd", "the line kept");
        assert_eq!(session.edit("{Up}"), "abcd");
    }

    /// A line read without echo is not recorded, and nothing of it shows.
    #[test]
    fn a_line_read_without_echo_stays_out_of_the_history() {
        let mut session = Session::new();
        session.edit("seen");
        session.echo = false;
        assert_eq!(session.edit("secret{Home}x"), "xsecret");
        assert_eq!(session.row(1), "");
        assert_eq!(session.edit("{Up}"), "seen");
    }

    /// Each program its own buffer, kept after it ends; a fifth program takes the least recently
    /// used one, emptied.
    #[test]
    fn each_program_has_a_history_buffer_of_its_own() {
        let mut session = Session::new();
        let programs: [&'static [u8]; 4] = [b"one", b"two", b"three", b"four"];
        for program in programs {
            session.program = program;
            session.edit(core::str::from_utf8(program).unwrap());
        }
        session.program = b"TWO";
        assert_eq!(session.edit("{Up}"), "two", "names compared without case");
        session.program = b"five";
        assert_eq!(session.edit("{Up}"), "", "a fresh buffer");
        session.program = b"one";
        assert_eq!(
            session.edit("{Up}"),
            "",
            "the least recently used one was taken"
        );
        session.program = b"four";
        assert_eq!(session.edit("{Up}"), "four");
    }

    /// A buffer keeps its newest 50 commands, and makes room for a long one by dropping the oldest.
    #[test]
    fn a_full_history_drops_its_oldest_commands() {
        let mut history = Box::new(History::new());
        for index in 0..60u16 {
            history.add(&[0x30 + index]);
        }
        assert_eq!(history.len(), HISTORY_COMMANDS);
        assert_eq!(history.command(0), [0x30 + 10]);
        let long = [0x41; 1000];
        for _ in 0..5 {
            history.add(&long);
        }
        assert_eq!(history.newest(), Some(&long[..]));
        assert!(history.len() < 10);
        assert_eq!(history.command(history.len() - 1), long);
    }

    /// `count` letters, a to z and round again.
    fn letters(count: usize) -> String {
        (0..count)
            .map(|index| char::from(b'a' + (index % 26) as u8))
            .collect()
    }

    /// The capture replayed: every read of tests/kernel32/lineedit/output.txt — the keys its
    /// label names, the line read, the echoed rows read back and the cursor's move — over a screen
    /// buffer cleared as each section clears it.
    #[test]
    fn the_capture_replays() {
        let capture = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/kernel32/lineedit/output.txt"
        ));
        let mut session = Session::new();
        let mut section = "";
        let mut clears = 0;
        let mut wide = true;
        let mut lines = capture.lines().peekable();
        let mut reads = 0;
        while let Some(text) = lines.next() {
            if let Some(name) = text.strip_prefix("== ") {
                section = name;
            } else if text.starts_with("-- ") {
                wide = text.starts_with("-- W");
                clears = 0;
            } else if text.starts_with("buffer cleared and the cursor homed") {
                session
                    .screen
                    .fill(0, 0, WIDTH * HEIGHT, Fill::Character(b' '));
                session.screen.set_cursor(0, 0);
                clears += 1;
                if section == "bottom" && clears > 1 {
                    session.screen.set_cursor(HEIGHT - 1, 0);
                }
            } else if let Some(rest) = text.strip_prefix("keys [") {
                let label = &rest[..rest.find("]: ").unwrap()];
                let before = session.screen.cursor();
                session
                    .screen
                    .fill(0, before.0 as i32, WIDTH * 3, Fill::Character(b' '));
                let read = session.edit(&spec_of(label));
                let after = session.screen.cursor();
                reads += 1;
                let units: Vec<u16> = format!("{read}\r\n").encode_utf16().collect();
                let expected = lines.next().unwrap();
                let got = if wide { vis_w(&units) } else { vis_a(&units) };
                assert!(
                    expected.ends_with(&format!("[{got}]")),
                    "{section} [{label}]: read {got:?}, captured {expected}"
                );
                let first = before.0;
                let last = after.0.saturating_sub(1).clamp(first, first + 3);
                while let Some(row_line) = lines.next_if(|line| !line.starts_with("  cursor after"))
                {
                    let (name, captured) = row_line.trim_start().split_once(": ").unwrap();
                    let row = if let Some(back) = name.strip_prefix("row H-") {
                        HEIGHT - back.parse::<usize>().unwrap()
                    } else if let Some(offset) = name.strip_prefix("echo row ") {
                        assert!(first != last, "{section} [{label}]: one row echoed");
                        first + offset.parse::<usize>().unwrap()
                    } else {
                        assert_eq!(name, "echo");
                        assert_eq!(first, last, "{section} [{label}]: rows echoed");
                        first
                    };
                    let got = format!("[{}]", session.row(row));
                    assert_eq!(got, captured, "{section} [{label}]: {name}");
                }
                let got = format!(
                    "  cursor after: {:+} rows, column {}",
                    after.0 as i32 - before.0 as i32,
                    after.1
                );
                assert_eq!(got, lines.next().unwrap(), "{section} [{label}]");
            }
        }
        assert!(reads > 200, "the capture's reads: {reads}");
    }

    /// The spec a read's label stands for: the label itself, or, for the long lines, so many
    /// letters then the keys its words name.
    fn spec_of(label: &str) -> String {
        let Some((count, rest)) = label.split_once(" letters") else {
            return label.into();
        };
        let suffix = match rest {
            "" => String::new(),
            ", Home, x" => "{Home}x".into(),
            ", Esc, xy" => "{Esc}xy".into(),
            ", Left 25 times, BS twice" => format!("{}{{BS}}{{BS}}", "{Left}".repeat(25)),
            ", Left 25 times, Del twice" => format!("{}{{Del}}{{Del}}", "{Left}".repeat(25)),
            other => panic!("no keys for {other}"),
        };
        letters(count.parse().unwrap()) + &suffix
    }

    /// The fixture's view of a wide read: CR, LF and backslash escaped, any other unit outside
    /// printable ASCII as <U+XXXX>; of a narrow one (`wide` false), as \xHH.
    fn vis(units: &[u16], wide: bool) -> String {
        units
            .iter()
            .map(|&unit| match unit {
                0x0D => "\\r".into(),
                0x0A => "\\n".into(),
                0x5C => "\\\\".into(),
                0x20..0x7F => String::from(char::from(unit as u8)),
                _ if wide => format!("<U+{unit:04X}>"),
                _ => format!("\\x{unit:02X}"),
            })
            .collect()
    }

    fn vis_w(units: &[u16]) -> String {
        vis(units, true)
    }

    fn vis_a(units: &[u16]) -> String {
        vis(units, false)
    }
}
