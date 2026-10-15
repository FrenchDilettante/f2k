//! VGA text mode: the 80x25 grid of character/attribute words at physical 0xB8000, and the CRT
//! controller's cursor registers.
//!
//! A word holds the font glyph in its low byte and the attribute (foreground nibble, background
//! nibble) in its high byte. The cursor is a register pair holding the word offset it sits on,
//! and a disable bit in the cursor-start register hides it.
//!
//! Quirk: the controller is addressed at the colour base (0x3D4/0x3D5) — the mode the firmware
//! leaves a colour adapter in; a monochrome adapter (0x3B4) is not supported. The grid is reached
//! through the kernel window, which maps the low 8 MiB of physical memory, the adapter's window
//! included.

use crate::hw::portio::Io;

/// The grid's size.
pub const COLUMNS: u16 = 80;
pub const ROWS: u16 = 25;

/// The grid's physical address.
pub const TEXT_BUFFER_PHYS: u32 = 0x000B_8000;

/// The CRT controller's index and data ports (colour base).
const CRTC_INDEX: u16 = 0x3D4;
const CRTC_DATA: u16 = 0x3D5;

/// CRT controller registers.
const CURSOR_START: u8 = 0x0A;
const CURSOR_LOCATION_HIGH: u8 = 0x0E;
const CURSOR_LOCATION_LOW: u8 = 0x0F;

/// The cursor-start register's disable bit.
const CURSOR_DISABLE: u8 = 0x20;

/// A grid word: `glyph` in the low byte, `attribute` in the high byte.
pub const fn word(glyph: u8, attribute: u8) -> u16 {
    (attribute as u16) << 8 | glyph as u16
}

/// Place the hardware cursor on grid word `offset` (row * [`COLUMNS`] + column), or hide it. The
/// cursor's shape (the rest of the cursor-start register) is left as the firmware set it.
pub fn set_cursor<IoT: Io>(io: &mut IoT, offset: Option<u16>) {
    io.out(CRTC_INDEX, CURSOR_START);
    let start = io.read(CRTC_DATA);
    match offset {
        Some(offset) => {
            io.out(CRTC_DATA, start & !CURSOR_DISABLE);
            io.out(CRTC_INDEX, CURSOR_LOCATION_HIGH);
            io.out(CRTC_DATA, (offset >> 8) as u8);
            io.out(CRTC_INDEX, CURSOR_LOCATION_LOW);
            io.out(CRTC_DATA, offset as u8);
        }
        None => io.out(CRTC_DATA, start | CURSOR_DISABLE),
    }
}

/// The cursor's grid offset as the controller holds it, and whether it is shown.
#[allow(dead_code)] // read back by the console diagnostic only
pub fn cursor<IoT: Io>(io: &mut IoT) -> (u16, bool) {
    io.out(CRTC_INDEX, CURSOR_LOCATION_HIGH);
    let high = io.read(CRTC_DATA);
    io.out(CRTC_INDEX, CURSOR_LOCATION_LOW);
    let low = io.read(CRTC_DATA);
    io.out(CRTC_INDEX, CURSOR_START);
    let shown = io.read(CRTC_DATA) & CURSOR_DISABLE == 0;
    ((high as u16) << 8 | low as u16, shown)
}

#[cfg(target_arch = "x86")]
mod target {
    use super::*;

    /// The grid, through the kernel window.
    fn grid() -> *mut u16 {
        (crate::mem::paging::KERNEL_BASE + TEXT_BUFFER_PHYS) as *mut u16
    }

    /// Store one row of words.
    pub fn write_row(row: u16, words: &[u16; COLUMNS as usize]) {
        assert!(row < ROWS, "grid row {row} outside the grid");
        let base = row as usize * COLUMNS as usize;
        for (column, &word) in words.iter().enumerate() {
            // SAFETY: the grid is device memory mapped in the kernel window; the offset is inside
            // the 80x25 grid.
            unsafe { grid().add(base + column).write_volatile(word) };
        }
    }

    /// Read one row of words back (diagnostic).
    #[allow(dead_code)] // read back by the console diagnostic only
    pub fn read_row(row: u16) -> [u16; COLUMNS as usize] {
        assert!(row < ROWS, "grid row {row} outside the grid");
        let base = row as usize * COLUMNS as usize;
        // SAFETY: as in write_row.
        core::array::from_fn(|column| unsafe { grid().add(base + column).read_volatile() })
    }
}

#[cfg(target_arch = "x86")]
#[allow(unused_imports)] // `read_row`: read back by the console diagnostic only
pub use target::{read_row, write_row};

#[cfg(test)]
mod tests {
    use super::*;

    /// A CRT controller: an index latch over a register file, logging every port access.
    struct Crtc {
        index: u8,
        registers: [u8; 0x19],
        log: Vec<(u16, u8)>,
    }

    impl Crtc {
        fn new(cursor_start: u8) -> Self {
            let mut registers = [0; 0x19];
            registers[CURSOR_START as usize] = cursor_start;
            Self {
                index: 0,
                registers,
                log: Vec::new(),
            }
        }
    }

    impl Io for Crtc {
        fn out(&mut self, port: u16, byte: u8) {
            self.log.push((port, byte));
            match port {
                CRTC_INDEX => self.index = byte,
                CRTC_DATA => self.registers[self.index as usize] = byte,
                _ => panic!("unexpected port {port:#x}"),
            }
        }
        fn read(&mut self, port: u16) -> u8 {
            assert_eq!(port, CRTC_DATA);
            self.registers[self.index as usize]
        }
        fn read_word(&mut self, _port: u16) -> u16 {
            unreachable!("the controller is byte-wide")
        }
    }

    #[test]
    fn words_put_the_attribute_high() {
        assert_eq!(word(b'H', 0x07), 0x0748);
        assert_eq!(word(0xDB, 0x1F), 0x1FDB);
    }

    #[test]
    fn the_cursor_lands_on_its_offset() {
        // Cursor start 0x0D: an underline shape (scan lines 13..), shown.
        let mut crtc = Crtc::new(0x0D);
        set_cursor(&mut crtc, Some(24 * COLUMNS + 9));
        assert_eq!(crtc.registers[CURSOR_LOCATION_HIGH as usize], 0x07);
        assert_eq!(crtc.registers[CURSOR_LOCATION_LOW as usize], 0x89);
        assert_eq!(cursor(&mut crtc), (1929, true));
        // The shape is left alone.
        assert_eq!(crtc.registers[CURSOR_START as usize], 0x0D);
    }

    #[test]
    fn hiding_sets_the_disable_bit_only() {
        let mut crtc = Crtc::new(0x0D);
        set_cursor(&mut crtc, Some(5));
        set_cursor(&mut crtc, None);
        assert_eq!(crtc.registers[CURSOR_START as usize], 0x2D);
        assert_eq!(cursor(&mut crtc), (5, false));
        // Showing again clears it.
        set_cursor(&mut crtc, Some(6));
        assert_eq!(crtc.registers[CURSOR_START as usize], 0x0D);
    }

    #[test]
    fn a_hidden_cursor_keeps_its_location() {
        let mut crtc = Crtc::new(0x0D);
        set_cursor(&mut crtc, Some(100));
        let writes_before = crtc.log.len();
        set_cursor(&mut crtc, None);
        // Index the start register, write it back with the disable bit: nothing else.
        assert_eq!(
            &crtc.log[writes_before..],
            &[(CRTC_INDEX, CURSOR_START), (CRTC_DATA, 0x2D)]
        );
    }
}
