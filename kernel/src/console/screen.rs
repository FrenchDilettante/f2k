//! The console screen buffer: a grid of cells (a UTF-16 character and its attributes, the shape of
//! a Win32 `CHAR_INFO`), the cursor, and the window — the rows of the buffer the display shows.
//!
//! The buffer is taller than the window: output runs down the buffer and the window follows the
//! cursor; only when the cursor would leave the buffer's last row does the buffer itself scroll,
//! dropping its first row. Attributes are the console's 16-bit attribute word; the low byte is the
//! foreground/background nibble pair the text-mode adapter uses directly.
//!
//! Writes follow the console's default output mode (processed output, wrap at end of line):
//! - BEL is accepted and does nothing (no speaker driver);
//! - backspace moves the cursor one column left, never past column 0 and never erasing;
//! - tab writes blanks up to the next multiple-of-eight column;
//! - line feed moves to column 0 of the next row (a new line, not just a row down);
//! - carriage return moves to column 0;
//! - anything else is stored at the cursor, which advances and wraps to the next row's column 0
//!   when it passes the last column.
//!
//! Quirk: the backspace-at-column-0, tab-fill and new-row-attribute rules are the documented
//! processed-output behaviour as read, not yet pinned by a real-machine capture.

use super::cp437;

/// The buffer's size: the default console screen buffer.
pub const BUFFER_WIDTH: u16 = 80;
pub const BUFFER_HEIGHT: u16 = 300;
/// The window's height: the display's 25 rows (the window spans the buffer's full width).
pub const WINDOW_HEIGHT: u16 = 25;

const CELLS: usize = BUFFER_WIDTH as usize * BUFFER_HEIGHT as usize;

/// The default attributes: light grey on black (foreground red, green and blue).
pub const DEFAULT_ATTRIBUTES: u16 = 0x0007;

/// Tab stops fall on every multiple of this column.
const TAB_WIDTH: u16 = 8;

const BEL: u16 = 0x07;
const BACKSPACE: u16 = 0x08;
const TAB: u16 = 0x09;
const LINE_FEED: u16 = 0x0A;
const CARRIAGE_RETURN: u16 = 0x0D;

/// One cell: a UTF-16 character and its attributes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Cell {
    pub character: u16,
    pub attributes: u16,
}

impl Cell {
    /// A blank (a space) in `attributes`.
    pub const fn blank(attributes: u16) -> Self {
        Self {
            character: b' ' as u16,
            attributes,
        }
    }
}

/// A buffer position: column, row.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Coord {
    pub x: u16,
    pub y: u16,
}

/// The screen buffer (see the module doc).
pub struct ScreenBuffer {
    cells: [Cell; CELLS],
    cursor: Coord,
    /// The attributes new characters (and the blanks scrolling brings in) are written with.
    attributes: u16,
    /// The buffer row the window's first row shows.
    window_top: u16,
    /// Something the window shows may have changed since the last [`ScreenBuffer::take_dirty`].
    dirty: bool,
}

impl ScreenBuffer {
    /// A blank buffer in the default attributes, cursor and window at the top.
    pub const fn new() -> Self {
        Self {
            cells: [Cell::blank(DEFAULT_ATTRIBUTES); CELLS],
            cursor: Coord { x: 0, y: 0 },
            attributes: DEFAULT_ATTRIBUTES,
            window_top: 0,
            dirty: true,
        }
    }

    /// Row `row` of the window (0 is the window's top row).
    pub fn window_row(&self, row: u16) -> &[Cell] {
        assert!(row < WINDOW_HEIGHT, "window row {row} outside the window");
        let start = index(0, self.window_top + row);
        &self.cells[start..start + BUFFER_WIDTH as usize]
    }

    /// The cursor's position in the window, or `None` when it is outside it.
    pub fn cursor_in_window(&self) -> Option<Coord> {
        let row = self.cursor.y.checked_sub(self.window_top)?;
        (row < WINDOW_HEIGHT).then_some(Coord {
            x: self.cursor.x,
            y: row,
        })
    }

    /// Whether the window may have changed since the last call, clearing the mark.
    pub fn take_dirty(&mut self) -> bool {
        core::mem::replace(&mut self.dirty, false)
    }

    /// Write bytes in the output codepage (437) under the processed-output rules.
    pub fn write_bytes(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            self.write_unit(cp437::to_unicode(byte));
        }
    }

    /// Write one UTF-16 unit under the processed-output rules.
    pub fn write_unit(&mut self, unit: u16) {
        match unit {
            BEL => {}
            BACKSPACE => {
                if self.cursor.x > 0 {
                    self.cursor.x -= 1;
                    self.dirty = true;
                }
            }
            TAB => {
                let blanks = TAB_WIDTH - self.cursor.x % TAB_WIDTH;
                for _ in 0..blanks {
                    self.put(b' ' as u16);
                }
            }
            LINE_FEED => {
                self.cursor.x = 0;
                self.next_row();
            }
            CARRIAGE_RETURN => {
                self.cursor.x = 0;
                self.dirty = true;
            }
            _ => self.put(unit),
        }
    }

    /// Store `character` at the cursor and advance, wrapping past the last column.
    fn put(&mut self, character: u16) {
        self.cells[index(self.cursor.x, self.cursor.y)] = Cell {
            character,
            attributes: self.attributes,
        };
        self.dirty = true;
        self.cursor.x += 1;
        if self.cursor.x == BUFFER_WIDTH {
            self.cursor.x = 0;
            self.next_row();
        }
    }

    /// Move the cursor down a row — scrolling the buffer when it is on the last one — and bring
    /// the window along so the cursor stays visible.
    fn next_row(&mut self) {
        if self.cursor.y + 1 == BUFFER_HEIGHT {
            self.cells.copy_within(BUFFER_WIDTH as usize.., 0);
            let last = index(0, BUFFER_HEIGHT - 1);
            self.cells[last..].fill(Cell::blank(self.attributes));
        } else {
            self.cursor.y += 1;
        }
        if self.cursor.y >= self.window_top + WINDOW_HEIGHT {
            self.window_top = self.cursor.y + 1 - WINDOW_HEIGHT;
        }
        self.dirty = true;
    }
}

fn index(x: u16, y: u16) -> usize {
    y as usize * BUFFER_WIDTH as usize + x as usize
}

#[cfg(test)]
mod tests {
    use super::*;

    fn buffer() -> Box<ScreenBuffer> {
        Box::new(ScreenBuffer::new())
    }

    /// Row `y`'s characters as a string, trailing blanks trimmed.
    fn row_text(screen: &ScreenBuffer, y: u16) -> String {
        let text: String = (0..BUFFER_WIDTH)
            .map(|x| char::from_u32(cell(&screen, x, y).character as u32).unwrap())
            .collect();
        text.trim_end().to_string()
    }

    /// The cell at buffer position (`x`, `y`).
    fn cell(screen: &ScreenBuffer, x: u16, y: u16) -> Cell {
        screen.cells[index(x, y)]
    }

    fn at(x: u16, y: u16) -> Coord {
        Coord { x, y }
    }

    #[test]
    fn a_new_buffer_is_blank_with_the_cursor_home() {
        let mut screen = buffer();
        assert_eq!(screen.cursor, at(0, 0));
        assert_eq!(screen.window_top, 0);
        assert_eq!(screen.attributes, DEFAULT_ATTRIBUTES);
        assert_eq!(cell(&screen, 79, 299), Cell::blank(0x07));
        assert!(
            screen.take_dirty(),
            "the first render draws the blank window"
        );
        assert!(!screen.take_dirty());
    }

    #[test]
    fn hello_writes_one_line_and_moves_to_the_next() {
        // The hello fixture's single WriteFile: 15 bytes, CR LF terminated.
        let mut screen = buffer();
        screen.write_bytes(b"Hello, world!\r\n");
        assert_eq!(row_text(&screen, 0), "Hello, world!");
        assert_eq!(cell(&screen, 0, 0).attributes, DEFAULT_ATTRIBUTES);
        assert_eq!(screen.cursor, at(0, 1));
        assert!(screen.take_dirty());
    }

    #[test]
    fn line_feed_alone_starts_a_new_line() {
        let mut screen = buffer();
        screen.write_bytes(b"ab\ncd");
        assert_eq!(row_text(&screen, 0), "ab");
        assert_eq!(row_text(&screen, 1), "cd");
        assert_eq!(screen.cursor, at(2, 1));
    }

    #[test]
    fn carriage_return_rewrites_the_line() {
        let mut screen = buffer();
        screen.write_bytes(b"abcd\rxy");
        assert_eq!(row_text(&screen, 0), "xycd");
        assert_eq!(screen.cursor, at(2, 0));
    }

    #[test]
    fn backspace_moves_left_without_erasing() {
        let mut screen = buffer();
        screen.write_bytes(b"abc\x08\x08");
        assert_eq!(row_text(&screen, 0), "abc");
        assert_eq!(screen.cursor, at(1, 0));
        screen.write_bytes(b"X");
        assert_eq!(row_text(&screen, 0), "aXc");
        // At column 0 it stays put.
        screen.write_bytes(b"\r\x08");
        assert_eq!(screen.cursor, at(0, 0));
    }

    #[test]
    fn tab_fills_blanks_to_the_next_stop() {
        let mut screen = buffer();
        screen.write_bytes(b"ab\tc");
        assert_eq!(cell(&screen, 2, 0), Cell::blank(0x07));
        assert_eq!(cell(&screen, 8, 0).character, b'c' as u16);
        // At a stop, a tab advances a full stop.
        screen.write_bytes(b"\r\t");
        assert_eq!(screen.cursor, at(8, 0));
        // Overwrites what was there.
        let mut screen = buffer();
        screen.write_bytes(b"abcdefgh\r\t");
        assert_eq!(row_text(&screen, 0), "");
    }

    #[test]
    fn bell_does_nothing() {
        let mut screen = buffer();
        screen.write_bytes(b"a\x07b");
        assert_eq!(row_text(&screen, 0), "ab");
    }

    #[test]
    fn other_control_codes_are_stored_as_characters() {
        let mut screen = buffer();
        screen.write_bytes(b"\x01\x1b");
        assert_eq!(cell(&screen, 0, 0).character, 0x01);
        assert_eq!(cell(&screen, 1, 0).character, 0x1B);
    }

    #[test]
    fn high_bytes_are_codepage_437() {
        let mut screen = buffer();
        screen.write_bytes(&[0x82, 0xC4]);
        assert_eq!(cell(&screen, 0, 0).character, 0x00E9);
        assert_eq!(cell(&screen, 1, 0).character, 0x2500);
    }

    #[test]
    fn writing_the_last_column_wraps() {
        let mut screen = buffer();
        screen.write_bytes(&[b'x'; 80]);
        assert_eq!(screen.cursor, at(0, 1));
        // The classic consequence: a CR LF after a full row leaves an empty row.
        screen.write_bytes(b"\r\n");
        assert_eq!(screen.cursor, at(0, 2));
        assert_eq!(row_text(&screen, 1), "");
    }

    #[test]
    fn the_window_follows_the_cursor_down_the_buffer() {
        let mut screen = buffer();
        for _ in 0..24 {
            screen.write_bytes(b"\n");
        }
        assert_eq!(screen.window_top, 0);
        assert_eq!(screen.cursor_in_window(), Some(at(0, 24)));
        screen.write_bytes(b"\n");
        assert_eq!(screen.cursor, at(0, 25));
        assert_eq!(screen.window_top, 1);
        assert_eq!(screen.cursor_in_window(), Some(at(0, 24)));
    }

    #[test]
    fn the_window_shows_its_rows() {
        let mut screen = buffer();
        for line in 0..30 {
            screen.write_bytes(format!("line {line}\n").as_bytes());
        }
        // 30 lines leave the cursor on row 30; the window shows rows 6..31.
        assert_eq!(screen.window_top, 6);
        let first: Vec<u16> = screen.window_row(0)[..6]
            .iter()
            .map(|c| c.character)
            .collect();
        assert_eq!(first, "line 6".encode_utf16().collect::<Vec<_>>());
    }

    #[test]
    fn the_buffer_scrolls_at_its_last_row() {
        let mut screen = buffer();
        for line in 0..BUFFER_HEIGHT {
            screen.write_bytes(format!("{line}\n").as_bytes());
        }
        // 300 new lines from row 0: the last one scrolled the buffer once, so row 0 holds "1".
        assert_eq!(screen.cursor, at(0, BUFFER_HEIGHT - 1));
        assert_eq!(row_text(&screen, 0), "1");
        assert_eq!(row_text(&screen, BUFFER_HEIGHT - 2), "299");
        assert_eq!(row_text(&screen, BUFFER_HEIGHT - 1), "");
        assert_eq!(screen.window_top, BUFFER_HEIGHT - WINDOW_HEIGHT);
    }

    #[test]
    fn scrolled_in_rows_are_blank() {
        let mut screen = buffer();
        for _ in 0..BUFFER_HEIGHT - 1 {
            screen.write_bytes(b"\n");
        }
        screen.write_bytes(b"tail\n");
        assert_eq!(row_text(&screen, BUFFER_HEIGHT - 2), "tail");
        assert_eq!(
            cell(&screen, 0, BUFFER_HEIGHT - 1),
            Cell::blank(DEFAULT_ATTRIBUTES)
        );
    }

    #[test]
    fn a_cursor_outside_the_window_has_no_window_position() {
        let mut screen = buffer();
        screen.write_bytes(b"x");
        screen.window_top = 5;
        assert_eq!(screen.cursor_in_window(), None);
    }
}
