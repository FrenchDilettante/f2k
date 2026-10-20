//! The console's screen buffer: a grid of character cells, the cursor, the current attribute and
//! the output mode, and the renderer that turns a client's bytes into cells.
//!
//! The renderer follows the output mode's two bits. Processed output (ENABLE_PROCESSED_OUTPUT)
//! interprets the carriage return, line feed, backspace, tab and bell; any other byte, and every
//! byte of unprocessed output, becomes a cell (the text-mode font draws the control bytes' glyphs).
//! With ENABLE_WRAP_AT_EOL_OUTPUT a write past the last column continues on the next row; without
//! it the cursor's column does not move past the row's end: the run of cells starts over from the
//! column it began at. A line feed past the last row scrolls the grid up one row.
//!
//! The buffer records which rows each change touched ([`ScreenBuffer::take_damage`]), so the
//! device behind it copies only what changed.

use core::ops::Range;

use super::SmallRect;
use crate::codepage::{self, CodePage};

/// The grid's columns.
pub const WIDTH: usize = 80;
/// The grid's rows.
pub const HEIGHT: usize = 25;

/// A fresh buffer's attribute: light grey on black.
pub const DEFAULT_ATTRIBUTE: u8 = 0x07;

/// The output mode's bits.
pub const ENABLE_PROCESSED_OUTPUT: u32 = 0x1;
pub const ENABLE_WRAP_AT_EOL_OUTPUT: u32 = 0x2;
/// Every output mode bit a screen buffer holds.
pub const OUTPUT_MODE_MASK: u32 = ENABLE_PROCESSED_OUTPUT | ENABLE_WRAP_AT_EOL_OUTPUT;

/// The columns between tab stops.
const TAB_STOP: usize = 8;

/// One cell: its character (an OEM byte) and its attribute, in the text screen's order.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cell {
    pub character: u8,
    pub attribute: u8,
}

impl Cell {
    /// A space in `attribute`.
    pub const fn blank(attribute: u8) -> Self {
        Cell {
            character: b' ',
            attribute,
        }
    }
}

/// The grid: [`HEIGHT`] rows of [`WIDTH`] cells.
pub type Grid = [[Cell; WIDTH]; HEIGHT];

/// What a fill writes: each cell's character or each cell's attribute, the other kept.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fill {
    Character(u8),
    Attribute(u8),
}

/// The screen buffer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScreenBuffer {
    cells: Grid,
    /// The cursor: its row and column.
    row: usize,
    column: usize,
    /// The attribute written cells take.
    attribute: u8,
    /// The output mode (ENABLE_PROCESSED_OUTPUT, ENABLE_WRAP_AT_EOL_OUTPUT).
    mode: u32,
    /// Whether a backspace stops at column 0 rather than going back to the previous row's end.
    limit_backspace: bool,
    /// The column the current run of cells began at: where a run that passes the last column
    /// starts over without the wrap bit.
    anchor: usize,
    /// The rows changed since the last look, and whether anything (the cursor included) changed.
    damaged: Option<Range<usize>>,
}

impl ScreenBuffer {
    /// A fresh buffer: blank in the default attribute, the cursor home, the output mode a fresh
    /// console's.
    pub const fn new() -> Self {
        ScreenBuffer {
            cells: [[Cell::blank(DEFAULT_ATTRIBUTE); WIDTH]; HEIGHT],
            row: 0,
            column: 0,
            attribute: DEFAULT_ATTRIBUTE,
            mode: super::OUTPUT_MODE,
            limit_backspace: false,
            anchor: 0,
            damaged: None,
        }
    }

    /// The grid.
    pub fn cells(&self) -> &Grid {
        &self.cells
    }

    /// The cell at `row`, `column`.
    pub fn cell(&self, row: usize, column: usize) -> Cell {
        self.cells[row][column]
    }

    /// One row's characters.
    pub fn row_text(&self, row: usize) -> [u8; WIDTH] {
        self.cells[row].map(|cell| cell.character)
    }

    /// The cursor: its row and column.
    pub fn cursor(&self) -> (usize, usize) {
        (self.row, self.column)
    }

    /// Move the cursor; false (nothing moved) for a position outside the grid.
    pub fn set_cursor(&mut self, row: usize, column: usize) -> bool {
        if row >= HEIGHT || column >= WIDTH {
            return false;
        }
        (self.row, self.column) = (row, column);
        self.touch(0..0);
        true
    }

    /// The attribute written cells take.
    pub fn attribute(&self) -> u8 {
        self.attribute
    }

    pub fn set_attribute(&mut self, attribute: u8) {
        self.attribute = attribute;
    }

    /// The output mode.
    pub fn mode(&self) -> u32 {
        self.mode
    }

    /// Set the output mode: bits outside [`OUTPUT_MODE_MASK`] are the caller's to refuse.
    pub fn set_mode(&mut self, mode: u32) {
        self.mode = mode & OUTPUT_MODE_MASK;
    }

    /// Whether a backspace at column 0 stays there (a cooked echo's clamp) rather than going back
    /// to the previous row's last column.
    pub fn set_limit_backspace(&mut self, limit: bool) {
        self.limit_backspace = limit;
    }

    /// The rows changed since the last look (an empty range when only the cursor moved); none when
    /// nothing changed.
    pub fn take_damage(&mut self) -> Option<Range<usize>> {
        self.damaged.take()
    }

    /// Record a change to `rows` (empty: the cursor alone).
    fn touch(&mut self, rows: Range<usize>) {
        self.damaged = Some(match self.damaged.take() {
            None => rows,
            Some(old) if old.is_empty() => rows,
            Some(old) if rows.is_empty() => old,
            Some(old) => old.start.min(rows.start)..old.end.max(rows.end),
        });
    }

    /// One whole write: `bytes` rendered at the cursor.
    pub fn write_bytes(&mut self, bytes: &[u8]) {
        self.begin_write();
        self.render(bytes);
    }

    /// One whole write of UTF-16 units: a control character's CP437 glyph shown as its glyph
    /// byte, any other unit as the OEM byte it narrows to (`?` where nothing fits), rendered.
    pub fn write_wide(&mut self, units: &[u16]) {
        self.begin_write();
        for &unit in units {
            match glyph_byte(unit) {
                Some(glyph) => self.put(glyph),
                None => {
                    let byte = codepage::encode_unit(CodePage::Oem, unit, true).unwrap_or(b'?');
                    self.render(&[byte]);
                }
            }
        }
    }

    /// Start a write: its run of cells begins at the cursor. A write the caller hands over in
    /// pieces ([`ScreenBuffer::render`]) starts once.
    pub fn begin_write(&mut self) {
        self.anchor = self.column;
        self.touch(0..0);
    }

    /// Render `bytes` at the cursor, continuing the write [`ScreenBuffer::begin_write`] started.
    pub fn render(&mut self, bytes: &[u8]) {
        if self.mode & ENABLE_PROCESSED_OUTPUT == 0 {
            bytes.iter().for_each(|&byte| self.put(byte));
            return;
        }
        for &byte in bytes {
            match byte {
                b'\r' => self.column = 0,
                b'\n' => self.line_feed(),
                0x08 => self.backspace(),
                b'\t' => self.tab(),
                0x07 => continue,
                _ => {
                    self.put(byte);
                    continue;
                }
            }
            self.anchor = self.column;
        }
    }

    /// Store `character` at the cursor in the current attribute and step the cursor right.
    fn put(&mut self, character: u8) {
        self.cells[self.row][self.column] = Cell {
            character,
            attribute: self.attribute,
        };
        self.touch(self.row..self.row + 1);
        self.column += 1;
        if self.column < WIDTH {
            return;
        }
        if self.mode & ENABLE_WRAP_AT_EOL_OUTPUT != 0 {
            self.line_feed();
            self.anchor = 0;
        } else {
            self.column = self.anchor;
        }
    }

    /// Column 0 of the next row, the grid scrolled up when the cursor is on the last.
    fn line_feed(&mut self) {
        self.column = 0;
        if self.row + 1 < HEIGHT {
            self.row += 1;
        } else {
            self.scroll_up();
        }
    }

    /// One column back, the cell kept; at column 0 the previous row's last column (unless the
    /// backspace is limited), at the grid's origin nowhere.
    fn backspace(&mut self) {
        if self.column > 0 {
            self.column -= 1;
        } else if !self.limit_backspace && self.row > 0 {
            self.row -= 1;
            self.column = WIDTH - 1;
        }
    }

    /// Spaces in the current attribute up to the next tab stop; one at or past the row's end
    /// fills the row and moves to the next.
    fn tab(&mut self) {
        let stop = (self.column / TAB_STOP + 1) * TAB_STOP;
        let end = stop.min(WIDTH);
        self.cells[self.row][self.column..end].fill(Cell::blank(self.attribute));
        self.touch(self.row..self.row + 1);
        if stop >= WIDTH {
            self.line_feed();
        } else {
            self.column = stop;
        }
    }

    /// The grid up one row: the top row lost, a blank bottom row in the current attribute.
    fn scroll_up(&mut self) {
        self.cells.copy_within(1.., 0);
        self.cells[HEIGHT - 1] = [Cell::blank(self.attribute); WIDTH];
        self.touch(0..HEIGHT);
    }

    /// Fill `count` cells from (`x`, `y`), on across each row's end onto the next and clipped at
    /// the grid's end: the cells written (none from a start outside the grid).
    pub fn fill(&mut self, x: i32, y: i32, count: usize, fill: Fill) -> usize {
        if !(0..WIDTH as i32).contains(&x) || !(0..HEIGHT as i32).contains(&y) {
            return 0;
        }
        let start = y as usize * WIDTH + x as usize;
        let count = count.min(WIDTH * HEIGHT - start);
        for index in start..start + count {
            let cell = &mut self.cells[index / WIDTH][index % WIDTH];
            match fill {
                Fill::Character(character) => cell.character = character,
                Fill::Attribute(attribute) => cell.attribute = attribute,
            }
        }
        if count != 0 {
            self.touch(start / WIDTH..(start + count - 1) / WIDTH + 1);
        }
        count
    }

    /// Move the `source` rectangle's cells so its top left lands at (`x`, `y`), then fill the
    /// source cells the move left (those outside the destination) with `fill`. The source clips
    /// to the grid, the destination shifting with it; only cells inside `clip` (clipped to the
    /// grid; the whole grid when none) change. A source wholly outside the grid moves nothing.
    pub fn scroll(
        &mut self,
        source: SmallRect,
        clip: Option<SmallRect>,
        x: i32,
        y: i32,
        fill: Cell,
    ) {
        let Some(from) = Bounds::of(source).clipped() else {
            return;
        };
        let to_x = x + (from.left - source.left as i32);
        let to_y = y + (from.top - source.top as i32);
        let Some(clip) = clip.map_or(Some(Bounds::GRID), |clip| Bounds::of(clip).clipped()) else {
            return;
        };
        let (dx, dy) = (to_x - from.left, to_y - from.top);
        let destination = Bounds {
            left: to_x,
            top: to_y,
            right: to_x + (from.right - from.left),
            bottom: to_y + (from.bottom - from.top),
        };
        // The copy runs away from the direction of the move, so a cell is read before the move
        // overwrites it.
        let rows = from.top..=from.bottom;
        let columns = from.left..=from.right;
        let mut touched = false;
        let mut copy = |cells: &mut Grid, row: i32, column: i32| {
            let (to_row, to_column) = (row + dy, column + dx);
            if clip.contains(to_column, to_row) {
                cells[to_row as usize][to_column as usize] = cells[row as usize][column as usize];
                touched = true;
            }
        };
        for row in ordered(rows, dy > 0) {
            for column in ordered(columns.clone(), dx > 0) {
                copy(&mut self.cells, row, column);
            }
        }
        for row in from.top..=from.bottom {
            for column in from.left..=from.right {
                if !destination.contains(column, row) && clip.contains(column, row) {
                    self.cells[row as usize][column as usize] = fill;
                    touched = true;
                }
            }
        }
        if touched {
            self.touch(0..HEIGHT);
        }
    }
}

impl Default for ScreenBuffer {
    fn default() -> Self {
        Self::new()
    }
}

/// `range`, backwards when `reverse`.
fn ordered(range: core::ops::RangeInclusive<i32>, reverse: bool) -> impl Iterator<Item = i32> {
    let (forward, backward) = if reverse {
        (None, Some(range.rev()))
    } else {
        (Some(range), None)
    };
    forward
        .into_iter()
        .flatten()
        .chain(backward.into_iter().flatten())
}

/// The glyph byte a CP437 control-glyph unit stands for.
fn glyph_byte(unit: u16) -> Option<u8> {
    if unit == 0 {
        return None;
    }
    if unit == codepage::CP437_GLYPH_7F {
        return Some(0x7F);
    }
    codepage::CP437_GLYPHS
        .iter()
        .position(|&glyph| glyph == unit)
        .map(|byte| byte as u8)
}

/// An inclusive rectangle in grid coordinates, wide enough for SMALL_RECT's values to clip.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Bounds {
    left: i32,
    top: i32,
    right: i32,
    bottom: i32,
}

impl Bounds {
    const GRID: Bounds = Bounds {
        left: 0,
        top: 0,
        right: WIDTH as i32 - 1,
        bottom: HEIGHT as i32 - 1,
    };

    fn of(rect: SmallRect) -> Self {
        Bounds {
            left: rect.left.into(),
            top: rect.top.into(),
            right: rect.right.into(),
            bottom: rect.bottom.into(),
        }
    }

    /// The part inside the grid; none when nothing is.
    fn clipped(self) -> Option<Bounds> {
        let clipped = Bounds {
            left: self.left.max(0),
            top: self.top.max(0),
            right: self.right.min(Self::GRID.right),
            bottom: self.bottom.min(Self::GRID.bottom),
        };
        (clipped.left <= clipped.right && clipped.top <= clipped.bottom).then_some(clipped)
    }

    fn contains(&self, column: i32, row: i32) -> bool {
        (self.left..=self.right).contains(&column) && (self.top..=self.bottom).contains(&row)
    }
}

#[cfg(test)]
mod tests {
    use std::vec::Vec;

    use super::*;

    fn text(screen: &ScreenBuffer, row: usize) -> std::string::String {
        std::string::String::from_utf8(screen.row_text(row).to_vec()).unwrap()
    }

    fn trimmed(screen: &ScreenBuffer, row: usize) -> std::string::String {
        text(screen, row).trim_end().into()
    }

    /// A buffer whose rows read "r00", "r01", ... at their starts.
    fn numbered() -> ScreenBuffer {
        let mut screen = ScreenBuffer::new();
        for row in 0..HEIGHT {
            screen.set_cursor(row, 0);
            screen.write_bytes(std::format!("r{row:02}").as_bytes());
        }
        screen.set_cursor(0, 0);
        screen.take_damage();
        screen
    }

    #[test]
    fn a_fresh_buffer_is_blank_in_the_default_attribute() {
        let screen = ScreenBuffer::new();
        assert!(screen
            .cells()
            .iter()
            .flatten()
            .all(|&cell| cell == Cell::blank(0x07)));
        assert_eq!(screen.cursor(), (0, 0));
        assert_eq!(screen.mode(), 0x3);
        assert_eq!(core::mem::size_of::<Cell>(), 2, "a text screen cell");
    }

    #[test]
    fn printable_bytes_take_the_current_attribute_and_step_right() {
        let mut screen = ScreenBuffer::new();
        screen.write_bytes(b"Hi");
        screen.set_attribute(0x1E);
        screen.write_bytes(b"!");
        assert_eq!(trimmed(&screen, 0), "Hi!");
        assert_eq!(
            [0, 1, 2].map(|column| screen.cell(0, column).attribute),
            [0x07, 0x07, 0x1E]
        );
        assert_eq!(screen.cursor(), (0, 3));
    }

    #[test]
    fn carriage_return_and_line_feed() {
        let mut screen = ScreenBuffer::new();
        screen.write_bytes(b"abc\rX");
        assert_eq!(
            (trimmed(&screen, 0), screen.cursor()),
            ("Xbc".into(), (0, 1))
        );
        screen.write_bytes(b"\nde");
        assert_eq!(
            (trimmed(&screen, 1), screen.cursor()),
            ("de".into(), (1, 2)),
            "a line feed implies the carriage return"
        );
        screen.write_bytes(b"\r\nf");
        assert_eq!((trimmed(&screen, 2), screen.cursor()), ("f".into(), (2, 1)));
    }

    #[test]
    fn backspace_steps_back_without_erasing_and_wraps_to_the_row_above() {
        let mut screen = ScreenBuffer::new();
        screen.write_bytes(b"ab\x08");
        assert_eq!(
            (trimmed(&screen, 0), screen.cursor()),
            ("ab".into(), (0, 1))
        );
        screen.write_bytes(b"\x08\x08\x08");
        assert_eq!(screen.cursor(), (0, 0), "the origin stays");
        screen.write_bytes(b"\nx\x08\x08");
        assert_eq!(
            screen.cursor(),
            (0, WIDTH - 1),
            "the previous row's last column"
        );
        assert_eq!(screen.cell(1, 0).character, b'x');
        screen.set_limit_backspace(true);
        screen.write_bytes(b"\ny\x08\x08");
        assert_eq!(
            screen.cursor(),
            (1, 0),
            "the limited backspace clamps at column 0"
        );
    }

    #[test]
    fn tab_fills_spaces_to_the_next_stop() {
        let mut screen = ScreenBuffer::new();
        screen.fill(0, 0, WIDTH, Fill::Character(b'.'));
        screen.set_attribute(0x4F);
        screen.write_bytes(b"ab\t");
        assert_eq!(screen.cursor(), (0, 8));
        assert_eq!(&text(&screen, 0)[..10], "ab      ..");
        assert!((2..8).all(|column| screen.cell(0, column) == Cell::blank(0x4F)));
        screen.write_bytes(b"\t");
        assert_eq!(screen.cursor(), (0, 16), "from a stop to the next");
        screen.set_cursor(0, 75);
        screen.write_bytes(b"\t");
        assert_eq!(
            screen.cursor(),
            (1, 0),
            "past the last column: the next row"
        );
        assert!((75..WIDTH).all(|column| screen.cell(0, column) == Cell::blank(0x4F)));
        screen.set_cursor(0, 72);
        screen.write_bytes(b"\t");
        assert_eq!(
            screen.cursor(),
            (1, 0),
            "a stop at the width is past the last column"
        );
    }

    #[test]
    fn bell_renders_nothing() {
        let mut screen = ScreenBuffer::new();
        screen.write_bytes(b"a\x07b");
        assert_eq!(
            (trimmed(&screen, 0), screen.cursor()),
            ("ab".into(), (0, 2))
        );
    }

    #[test]
    fn other_control_bytes_are_cells_in_processed_output() {
        let mut screen = ScreenBuffer::new();
        screen.write_bytes(b"\x01\x1B\x00\x7F");
        assert_eq!(&screen.row_text(0)[..4], b"\x01\x1B\x00\x7F");
        assert_eq!(screen.cursor(), (0, 4));
    }

    #[test]
    fn unprocessed_output_makes_every_byte_a_cell() {
        let mut screen = ScreenBuffer::new();
        screen.set_mode(ENABLE_WRAP_AT_EOL_OUTPUT);
        screen.write_bytes(b"a\r\n\x08\t\x07b");
        assert_eq!(&screen.row_text(0)[..7], b"a\r\n\x08\t\x07b");
        assert_eq!(screen.cursor(), (0, 7));
        screen.set_cursor(0, WIDTH - 1);
        screen.write_bytes(b"\n\n");
        assert_eq!(
            (
                screen.cell(0, WIDTH - 1).character,
                screen.cell(1, 0).character
            ),
            (b'\n', b'\n')
        );
        assert_eq!(screen.cursor(), (1, 1), "the wrap bit still wraps");
        screen.set_mode(0);
        screen.set_cursor(2, WIDTH - 2);
        screen.write_bytes(b"\r\nXY");
        assert_eq!(&screen.row_text(2)[WIDTH - 2..], b"XY");
        assert_eq!(screen.cursor(), (2, WIDTH - 2));
    }

    #[test]
    fn wrap_at_the_end_of_line_continues_on_the_next_row() {
        let mut screen = ScreenBuffer::new();
        screen.set_cursor(0, 75);
        screen.write_bytes(b"0123456789");
        assert_eq!(&screen.row_text(0)[75..], b"01234");
        assert_eq!(trimmed(&screen, 1), "56789");
        assert_eq!(screen.cursor(), (1, 5));
        screen.set_cursor(1, 0);
        screen.write_bytes(&[b'x'; WIDTH]);
        assert_eq!(
            screen.cursor(),
            (2, 0),
            "the last column written moves on at once"
        );
    }

    #[test]
    fn without_wrap_a_run_starts_over_from_its_column() {
        let mut screen = ScreenBuffer::new();
        screen.set_mode(ENABLE_PROCESSED_OUTPUT);
        screen.set_cursor(0, 70);
        let hundred: Vec<u8> = (0..100).map(|index| b'0' + (index / 10) as u8).collect();
        screen.write_bytes(&hundred);
        assert_eq!(&screen.row_text(0)[70..], [b'9'; 10]);
        assert_eq!(screen.cursor(), (0, 70));
        assert_eq!(trimmed(&screen, 1), "", "nothing reached the next row");
        // A write handed over in pieces is one write.
        screen.set_cursor(3, 70);
        screen.begin_write();
        for piece in hundred.chunks(7) {
            screen.render(piece);
        }
        assert_eq!(&screen.row_text(3)[70..], [b'9'; 10]);
        assert_eq!(screen.cursor(), (3, 70));
        // From the last column, each character overwrites the last.
        screen.set_cursor(4, WIDTH - 1);
        screen.write_bytes(b"abc");
        assert_eq!(
            (screen.cell(4, WIDTH - 1).character, screen.cursor()),
            (b'c', (4, WIDTH - 1))
        );
        // A run short of the row's end moves the cursor as usual.
        screen.set_cursor(5, 70);
        screen.write_bytes(b"abcde");
        assert_eq!(screen.cursor(), (5, 75));
    }

    #[test]
    fn a_line_feed_on_the_last_row_scrolls_the_grid() {
        let mut screen = numbered();
        screen.set_cursor(HEIGHT - 1, 0);
        screen.set_attribute(0x2A);
        screen.write_bytes(b"\nend");
        assert_eq!(trimmed(&screen, 0), "r01", "the top row is lost");
        assert_eq!(
            trimmed(&screen, HEIGHT - 2),
            std::format!("r{:02}", HEIGHT - 1)
        );
        assert_eq!(trimmed(&screen, HEIGHT - 1), "end");
        assert_eq!(screen.cursor(), (HEIGHT - 1, 3));
        assert!(
            (3..WIDTH).all(|column| screen.cell(HEIGHT - 1, column) == Cell::blank(0x2A)),
            "the new row is blank in the current attribute"
        );
        assert_eq!(
            screen.take_damage(),
            Some(0..HEIGHT),
            "the whole view follows"
        );
        // A wrap off the last row scrolls too.
        screen.set_cursor(HEIGHT - 1, WIDTH - 1);
        screen.write_bytes(b"zq");
        assert_eq!(screen.cell(HEIGHT - 2, WIDTH - 1).character, b'z');
        assert_eq!(trimmed(&screen, HEIGHT - 1), "q");
    }

    #[test]
    fn damage_names_the_rows_a_write_changed() {
        let mut screen = ScreenBuffer::new();
        assert_eq!(screen.take_damage(), None);
        screen.set_cursor(3, 0);
        assert_eq!(screen.take_damage(), Some(0..0), "the cursor alone");
        screen.write_bytes(b"a\nb\n");
        assert_eq!(screen.take_damage(), Some(3..5));
        screen.write_bytes(b"\x07");
        assert_eq!(
            screen.take_damage(),
            Some(0..0),
            "a write moves the hardware cursor"
        );
        assert_eq!(screen.take_damage(), None);
    }

    #[test]
    fn wide_writes_narrow_through_the_oem_page() {
        let mut screen = ScreenBuffer::new();
        screen.write_wide(&[0x48, 0x00E9, 0x263A, 0x2302, 0x4E2D, 0x0101, 0x0A]);
        assert_eq!(&screen.row_text(0)[..6], b"H\x82\x01\x7F?a");
        assert_eq!(screen.cursor(), (1, 0), "a line feed is still a line feed");
    }

    #[test]
    fn fills_run_across_rows_and_clip_at_the_end() {
        let mut screen = numbered();
        assert_eq!(
            screen.fill(WIDTH as i32 - 2, 0, 5, Fill::Character(b'#')),
            5
        );
        assert_eq!(&screen.row_text(0)[WIDTH - 2..], b"##");
        assert_eq!(&screen.row_text(1)[..4], b"### ", "on across the row's end");
        assert_eq!(
            screen.cell(1, 0).attribute,
            0x07,
            "a character fill keeps attributes"
        );
        assert_eq!(screen.take_damage(), Some(0..2));
        assert_eq!(screen.fill(0, 1, 2, Fill::Attribute(0x71)), 2);
        assert_eq!(
            (screen.cell(1, 0), screen.cell(1, 2)),
            (
                Cell {
                    character: b'#',
                    attribute: 0x71
                },
                Cell {
                    character: b'#',
                    attribute: 0x07
                }
            ),
            "an attribute fill keeps characters"
        );
        assert_eq!(
            screen.fill(
                WIDTH as i32 - 3,
                HEIGHT as i32 - 1,
                WIDTH * HEIGHT,
                Fill::Character(b'+')
            ),
            3,
            "clipped at the buffer's end"
        );
        for (x, y) in [(-1, 0), (0, -1), (WIDTH as i32, 0), (0, HEIGHT as i32)] {
            assert_eq!(
                screen.fill(x, y, 10, Fill::Character(b'!')),
                0,
                "({x}, {y})"
            );
        }
        assert!(!screen
            .cells()
            .iter()
            .flatten()
            .any(|cell| cell.character == b'!'));
        assert_eq!(screen.fill(0, 0, 0, Fill::Character(b'!')), 0);
    }

    fn rect(left: i16, top: i16, right: i16, bottom: i16) -> SmallRect {
        SmallRect {
            left,
            top,
            right,
            bottom,
        }
    }

    #[test]
    fn a_scroll_moves_the_source_and_fills_what_it_left() {
        let mut screen = numbered();
        let fill = Cell {
            character: b'.',
            attribute: 0x1F,
        };
        // The whole grid up one row, the way a scroll-up is asked for.
        screen.scroll(
            rect(0, 1, WIDTH as i16 - 1, HEIGHT as i16 - 1),
            None,
            0,
            0,
            fill,
        );
        assert_eq!(trimmed(&screen, 0), "r01");
        assert_eq!(
            trimmed(&screen, HEIGHT - 2),
            std::format!("r{:02}", HEIGHT - 1)
        );
        assert!(screen.cells()[HEIGHT - 1].iter().all(|&cell| cell == fill));
        assert_eq!(screen.take_damage(), Some(0..HEIGHT));
    }

    #[test]
    fn an_overlapping_scroll_copies_before_it_fills() {
        let mut screen = numbered();
        let fill = Cell::blank(0x07);
        // Down two rows, overlapping: each row is read before the move overwrites it.
        screen.scroll(rect(0, 0, 2, 4), None, 0, 2, fill);
        let starts: Vec<_> = (0..7)
            .map(|row| text(&screen, row)[..3].to_string())
            .collect();
        assert_eq!(starts, ["   ", "   ", "r00", "r01", "r02", "r03", "r04"]);
        // Right one column, overlapping within the rows.
        let mut screen = numbered();
        screen.scroll(rect(0, 0, 2, 0), None, 1, 0, fill);
        assert_eq!(&text(&screen, 0)[..4], " r00");
        // Left one column.
        let mut screen = numbered();
        screen.scroll(rect(1, 0, 3, 0), None, 0, 0, fill);
        assert_eq!(&text(&screen, 0)[..4], "00  ");
    }

    #[test]
    fn a_scroll_source_clips_to_the_buffer_and_shifts_its_destination() {
        let mut screen = numbered();
        let fill = Cell {
            character: b'.',
            attribute: 0x07,
        };
        // The source's two columns left of the grid are clipped: the destination moves with them.
        screen.scroll(rect(-2, 0, 2, 0), None, 10, 1, fill);
        assert_eq!(&text(&screen, 1)[10..16], "  r00 ", "column 0 lands at 12");
        assert_eq!(&text(&screen, 0)[..3], "...");
        // A source wholly outside moves nothing.
        let mut screen = numbered();
        let before = screen.clone();
        screen.scroll(rect(WIDTH as i16, 0, WIDTH as i16 + 5, 3), None, 0, 0, fill);
        screen.scroll(rect(0, -5, 3, -1), None, 0, 0, fill);
        assert_eq!(screen, before);
    }

    #[test]
    fn a_clip_rectangle_bounds_every_change() {
        let mut screen = numbered();
        let fill = Cell {
            character: b'.',
            attribute: 0x07,
        };
        // Rows 0-3 down one, only rows 2-3 may change.
        screen.scroll(
            rect(0, 0, 2, 3),
            Some(rect(0, 2, WIDTH as i16 - 1, 3)),
            0,
            1,
            fill,
        );
        let starts: Vec<_> = (0..5)
            .map(|row| text(&screen, row)[..3].to_string())
            .collect();
        assert_eq!(starts, ["r00", "r01", "r01", "r02", "r04"]);
        // A clip outside the grid changes nothing.
        let mut screen = numbered();
        let before = screen.clone();
        screen.scroll(rect(0, 0, 2, 3), Some(rect(-9, -9, -1, -1)), 0, 1, fill);
        assert_eq!(screen, before);
    }
}
