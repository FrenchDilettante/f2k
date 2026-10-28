//! The VGA text screen: mode 3's grid of character cells, and the hardware cursor.
//!
//! The machine boots in text mode 3: [`COLUMNS`] × [`ROWS`] cells, each two bytes (the character,
//! then its attribute) laid out row by row from physical [`PHYS_BASE`]. The kernel window maps
//! physical `[0, 16 MiB)` at `KERNEL_BASE` from the boot directory on (`crate::mem::layout`), so
//! the screen is reached at [`VIRT_BASE`] with no mapping of its own. The cursor is the CRT
//! controller's: its location (`row * COLUMNS + column`) is registers 0x0E (high byte) and 0x0F
//! (low byte), reached through the index and data ports.
//!
//! The screen's logic runs against two seams — the cell memory ([`CellMemory`]) and the port space
//! ([`Io`]) — so the host tests drive it against fakes, as the other drivers' are.

use rtl::console::screen::Cell;

use super::portio::Io;

/// Mode 3's columns.
pub const COLUMNS: usize = 80;
/// Mode 3's rows.
pub const ROWS: usize = 25;

/// The text screen's physical address.
pub const PHYS_BASE: u32 = 0xB_8000;
/// Where the kernel reaches it: the kernel window's view of [`PHYS_BASE`].
pub const VIRT_BASE: u32 = crate::mem::paging::KERNEL_BASE + PHYS_BASE;

/// The CRT controller's index and data ports, and its cursor location registers.
const CRTC_INDEX: u16 = 0x3D4;
const CRTC_DATA: u16 = 0x3D5;
const CURSOR_HIGH: u8 = 0x0E;
const CURSOR_LOW: u8 = 0x0F;

/// The memory the cells are stored in, by cell index (`row * COLUMNS + column`).
pub trait CellMemory {
    /// Store one cell: its character in the low byte, its attribute in the high one.
    fn store(&mut self, index: usize, word: u16);
}

/// A cell as the screen stores it.
pub const fn cell_word(cell: Cell) -> u16 {
    cell.character as u16 | (cell.attribute as u16) << 8
}

/// The text screen over its cell memory and port space.
pub struct TextScreen<M: CellMemory, P: Io> {
    memory: M,
    ports: P,
}

impl<M: CellMemory, P: Io> TextScreen<M, P> {
    pub const fn new(memory: M, ports: P) -> Self {
        TextScreen { memory, ports }
    }

    /// Store one cell at `row`, `column`; nothing outside the grid.
    pub fn put(&mut self, row: usize, column: usize, cell: Cell) {
        if row < ROWS && column < COLUMNS {
            self.memory.store(row * COLUMNS + column, cell_word(cell));
        }
    }

    /// Store a row's cells from its first column, as many as the screen's row holds.
    pub fn put_row(&mut self, row: usize, cells: &[Cell]) {
        for (column, &cell) in cells.iter().take(COLUMNS).enumerate() {
            self.put(row, column, cell);
        }
    }

    /// Store a whole grid of rows from the top, as many as the screen holds.
    pub fn put_grid<const W: usize>(&mut self, rows: &[[Cell; W]]) {
        for (row, cells) in rows.iter().take(ROWS).enumerate() {
            self.put_row(row, cells);
        }
    }

    /// Blank every cell in `attribute`.
    pub fn clear(&mut self, attribute: u8) {
        for index in 0..COLUMNS * ROWS {
            self.memory.store(index, cell_word(Cell::blank(attribute)));
        }
    }

    /// The cell memory and port space (the host tests' look at their fakes).
    #[cfg(test)]
    pub fn parts(&mut self) -> (&mut M, &mut P) {
        (&mut self.memory, &mut self.ports)
    }

    /// Move the hardware cursor to `row`, `column` (clamped to the grid).
    pub fn set_cursor(&mut self, row: usize, column: usize) {
        let location = (row.min(ROWS - 1) * COLUMNS + column.min(COLUMNS - 1)) as u16;
        self.ports.out(CRTC_INDEX, CURSOR_HIGH);
        self.ports.out(CRTC_DATA, (location >> 8) as u8);
        self.ports.out(CRTC_INDEX, CURSOR_LOW);
        self.ports.out(CRTC_DATA, location as u8);
    }
}

/// The screen's memory: the kernel window's view of the text page.
#[cfg(target_arch = "x86")]
pub struct VgaMemory;

#[cfg(target_arch = "x86")]
impl CellMemory for VgaMemory {
    fn store(&mut self, index: usize, word: u16) {
        assert!(index < COLUMNS * ROWS);
        // SAFETY: the text page is mapped in the kernel window for the kernel's lifetime; the
        // assertion above keeps the cell index inside mode 3's grid. The store is device memory:
        // volatile.
        unsafe { (VIRT_BASE as *mut u16).add(index).write_volatile(word) }
    }
}

/// The machine's text screen.
#[cfg(target_arch = "x86")]
pub fn screen() -> TextScreen<VgaMemory, super::portio::Ports> {
    TextScreen::new(VgaMemory, super::portio::Ports)
}

#[cfg(test)]
mod tests {
    use std::vec::Vec;

    use super::*;

    struct Memory(Vec<u16>);

    impl CellMemory for Memory {
        fn store(&mut self, index: usize, word: u16) {
            self.0[index] = word;
        }
    }

    #[derive(Default)]
    struct Ports(Vec<(u16, u8)>);

    impl Io for Ports {
        fn out(&mut self, port: u16, byte: u8) {
            self.0.push((port, byte));
        }

        fn read(&mut self, _port: u16) -> u8 {
            0
        }

        fn read_word(&mut self, _port: u16) -> u16 {
            0
        }
    }

    fn screen() -> TextScreen<Memory, Ports> {
        TextScreen::new(Memory(std::vec![0; COLUMNS * ROWS]), Ports::default())
    }

    const A: Cell = Cell {
        character: b'A',
        attribute: 0x1E,
    };

    #[test]
    fn a_cell_is_its_character_then_its_attribute() {
        assert_eq!(cell_word(A).to_le_bytes(), [b'A', 0x1E]);
        assert_eq!(COLUMNS * ROWS * 2, 4000, "mode 3's grid fits its one page");
        assert!(COLUMNS * ROWS * 2 <= crate::mem::paging::PAGE_SIZE as usize);
    }

    /// The boot window maps the text page where the screen reaches it.
    #[test]
    fn the_kernel_window_maps_the_text_page() {
        use crate::mem::paging::{BOOT_TABLES, KERNEL_BASE, PAGE_PRESENT, PAGE_WRITE};
        assert_eq!(VIRT_BASE, 0x800B_8000);
        assert_eq!(
            (VIRT_BASE >> 22) as usize,
            (KERNEL_BASE >> 22) as usize,
            "the window's table"
        );
        let entry = BOOT_TABLES.0[0][((VIRT_BASE >> 12) & 0x3FF) as usize];
        assert_eq!(entry, PHYS_BASE | PAGE_PRESENT | PAGE_WRITE);
    }

    #[test]
    fn cells_land_row_by_row() {
        let mut screen = screen();
        screen.put(2, 5, A);
        assert_eq!(screen.memory.0[2 * COLUMNS + 5], cell_word(A));
        screen.put(ROWS, 0, A);
        screen.put(0, COLUMNS, A);
        assert_eq!(
            screen.memory.0.iter().filter(|&&word| word != 0).count(),
            1,
            "outside: nowhere"
        );
        screen.put_row(1, &[A; COLUMNS + 3]);
        assert!(screen.memory.0[COLUMNS..2 * COLUMNS]
            .iter()
            .all(|&word| word == cell_word(A)));
        assert_eq!(
            screen.memory.0[2 * COLUMNS],
            0,
            "a row stops at the screen's"
        );
    }

    #[test]
    fn a_grid_and_a_clear_cover_the_screen() {
        let mut screen = screen();
        screen.put_grid(&[[A; COLUMNS]; ROWS]);
        assert!(screen.memory.0.iter().all(|&word| word == cell_word(A)));
        screen.clear(0x07);
        assert!(screen.memory.0.iter().all(|&word| word == 0x0720));
    }

    #[test]
    fn the_cursor_goes_to_the_crtc_location_registers() {
        let mut screen = screen();
        screen.set_cursor(ROWS - 1, COLUMNS - 1);
        let location = (ROWS * COLUMNS - 1) as u16;
        assert_eq!(
            screen.ports.0,
            [
                (0x3D4, 0x0E),
                (0x3D5, (location >> 8) as u8),
                (0x3D4, 0x0F),
                (0x3D5, location as u8)
            ]
        );
    }
}
