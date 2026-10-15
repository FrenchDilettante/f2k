//! The console: the screen buffer programs write to, shown on the VGA text display.
//!
//! One console exists. Bytes written to a console handle land in its screen buffer ([`screen`])
//! under the processed-output rules; the window — the 25 buffer rows the display shows — is then
//! rendered to the VGA text grid ([`crate::hw::vga`]) and the hardware cursor follows the buffer's.
//! Programs never reach the display: only the kernel writes the grid.
//!
//! Every byte written is also mirrored, unchanged, to COM1: the serial line is the console's log
//! (the on-target suite reads program output there), not its display.
//!
//! Input arrives from the keyboard driver as scancode bytes; the console decodes them
//! ([`keyboard`]) into key events and queues them ([`input`]) for whoever reads the console. The
//! lock keys start as the firmware left them (the BIOS data area's keyboard flags).
//!
//! Quirk: every touch of the console's state — a write, a decoded byte, a read — runs with
//! interrupts masked from start to finish, so none is ever torn by another; on one CPU that is the
//! whole lock. Services already enter with interrupts masked (the system-call gate is an interrupt
//! gate); the mask matters for the boot-time writers and the keyboard's DPC.

pub mod cp437;
pub mod input;
pub mod keyboard;
pub mod screen;

use screen::ScreenBuffer;

use crate::hw::vga;

/// The grid words window row `row` renders as: each cell's glyph in codepage 437 and the low byte
/// of its attributes (the adapter's foreground/background pair).
pub fn render_row(screen: &ScreenBuffer, row: u16) -> [u16; vga::COLUMNS as usize] {
    let cells = screen.window_row(row);
    core::array::from_fn(|column| {
        let cell = cells[column];
        vga::word(cp437::glyph(cell.character), cell.attributes as u8)
    })
}

/// The hardware cursor's grid offset for the buffer's cursor, or `None` when the cursor is outside
/// the window.
pub fn cursor_offset(screen: &ScreenBuffer) -> Option<u16> {
    screen
        .cursor_in_window()
        .map(|at| at.y * vga::COLUMNS + at.x)
}

#[cfg(target_arch = "x86")]
mod target {
    use core::ptr::addr_of_mut;

    use input::InputQueue;
    use keyboard::{Decoder, KeyEvent};

    use super::*;
    use crate::hw::portio::Ports;

    static mut SCREEN: ScreenBuffer = ScreenBuffer::new();
    static mut DECODER: Decoder = Decoder::new(0);
    static mut INPUT: InputQueue = input::input_queue();

    /// Run `f` with interrupts masked, restoring the interrupt flag exactly as found (see the
    /// module doc).
    fn masked<R>(f: impl FnOnce() -> R) -> R {
        let flags: u32;
        // SAFETY: saving EFLAGS and clearing IF touches no memory the compiler tracks.
        unsafe { core::arch::asm!("pushfd", "pop {}", "cli", out(reg) flags) };
        let result = f();
        // SAFETY: restores the flags saved above (IF included).
        unsafe { core::arch::asm!("push {}", "popfd", in(reg) flags) };
        result
    }

    /// Run `f` on the screen buffer, interrupts masked.
    fn with_screen<R>(f: impl FnOnce(&mut ScreenBuffer) -> R) -> R {
        // SAFETY: interrupts are masked on the only CPU: nothing else reaches the buffer now.
        masked(|| f(unsafe { &mut *addr_of_mut!(SCREEN) }))
    }

    /// The BIOS data area's keyboard flags byte (physical 0x417), through the kernel window.
    const FIRMWARE_KEYBOARD_FLAGS: u32 = crate::mem::paging::KERNEL_BASE + 0x417;

    /// The lock toggles the firmware's keyboard flags hold: Scroll Lock (bit 4), Num Lock (bit
    /// 5), Caps Lock (bit 6).
    fn firmware_locks() -> u32 {
        // SAFETY: the BIOS data area is ordinary memory in the kernel window, never handed out.
        let flags = unsafe { (FIRMWARE_KEYBOARD_FLAGS as *const u8).read_volatile() };
        [
            (0x10, keyboard::SCROLLLOCK_ON),
            (0x20, keyboard::NUMLOCK_ON),
            (0x40, keyboard::CAPSLOCK_ON),
        ]
        .iter()
        .filter(|&&(bit, _)| flags & bit != 0)
        .fold(0, |locks, &(_, on)| locks | on)
    }

    /// Feed one scancode byte from the keyboard driver; a completed key joins the input queue.
    pub fn keyboard_byte(byte: u8) {
        masked(|| {
            // SAFETY: interrupts are masked on the only CPU: the decoder and the queue are ours.
            unsafe {
                if let Some(event) = (*addr_of_mut!(DECODER)).feed(byte) {
                    (*addr_of_mut!(INPUT)).push(event);
                }
            }
        })
    }

    /// Take the oldest queued key event.
    #[allow(dead_code)] // read by the keyboard diagnostic only, until a console read service exists
    pub fn read_key() -> Option<KeyEvent> {
        // SAFETY: interrupts are masked on the only CPU: the queue is ours.
        masked(|| unsafe { (*addr_of_mut!(INPUT)).pop() })
    }

    /// Draw the window if it changed, and place the hardware cursor.
    fn render(screen: &mut ScreenBuffer) {
        if screen.take_dirty() {
            for row in 0..vga::ROWS {
                vga::write_row(row, &render_row(screen, row));
            }
        }
        vga::set_cursor(&mut Ports, cursor_offset(screen));
    }

    /// Bring the console up: draw the blank window over whatever the firmware left on the display,
    /// and start the keyboard decoder from the firmware's lock toggles.
    pub fn init() {
        with_screen(render);
        let locks = firmware_locks();
        // SAFETY: interrupts are masked on the only CPU: the decoder is ours.
        masked(|| unsafe { *addr_of_mut!(DECODER) = Decoder::new(locks) });
    }

    /// Write bytes in the output codepage to the console, mirroring them to COM1.
    pub fn write(bytes: &[u8]) {
        with_screen(|screen| {
            screen.write_bytes(bytes);
            for &byte in bytes {
                crate::hw::serial::write_byte_blocking(byte);
            }
            render(screen);
        });
    }

    /// The console diagnostic: thirty numbered lines (the window moves down six rows), then "a",
    /// a tab and "b" on the window's last row; then the display read back — three window rows, the
    /// cursor, the attribute — reported on COM1.
    #[cfg(feature = "console-smoke")]
    pub fn smoke() {
        use crate::serial_println;

        for line in 0..30u8 {
            write(&[
                b'l',
                b'i',
                b'n',
                b'e',
                b' ',
                b'0' + line / 10,
                b'0' + line % 10,
                b'\r',
                b'\n',
            ]);
        }
        write(b"a\tb");
        // End the mirrored partial line on COM1 only: the console's cursor stays after the "b".
        serial_println!("");
        for row in [0, 23, 24] {
            let words = vga::read_row(row);
            let glyphs: [u8; vga::COLUMNS as usize] = core::array::from_fn(|i| words[i] as u8);
            let text = core::str::from_utf8(&glyphs).unwrap_or("(not ASCII)");
            serial_println!(
                "F2K: console-smoke: window row {}: '{}'",
                row,
                text.trim_end()
            );
        }
        let (offset, shown) = vga::cursor(&mut Ports);
        serial_println!(
            "F2K: console-smoke: cursor at {} ({})",
            offset,
            if shown { "shown" } else { "hidden" }
        );
        serial_println!(
            "F2K: console-smoke: attribute {:#04x}",
            vga::read_row(0)[0] >> 8
        );
    }
    /// The keyboard diagnostic: wait (ten seconds at most) for ten key events, report each on
    /// COM1, then echo the characters the key-down events carried through the console and read the
    /// window row they landed on back from the display.
    #[cfg(feature = "keyboard-smoke")]
    pub fn keyboard_smoke() {
        use crate::serial_println;
        const EVENTS: usize = 10;
        const TIMEOUT_TICKS: u64 = 1000;

        serial_println!(
            "F2K: keyboard-smoke: ready (waiting for {} key events)",
            EVENTS
        );
        let deadline = crate::interrupt::clock::ticks() + TIMEOUT_TICKS;
        let mut typed = [0u8; EVENTS];
        let mut count = 0;
        let mut seen = 0;
        while seen < EVENTS {
            let Some(event) = read_key() else {
                if crate::interrupt::clock::ticks() >= deadline {
                    serial_println!("F2K: keyboard-smoke: timed out after {} events", seen);
                    break;
                }
                // Every interrupt wakes the halt (the tick bounds it).
                crate::interrupt::irql::state_mut().unmask_and_halt();
                continue;
            };
            seen += 1;
            serial_println!(
                "F2K: keyboard-smoke: {} vk {:#04x} scan {:#04x} char {:#06x} state {:#06x}",
                if event.key_down { "down" } else { "up" },
                event.virtual_key,
                event.scan_code,
                event.character,
                event.control_state
            );
            if event.key_down && event.character != 0 {
                typed[count] = cp437::glyph(event.character);
                count += 1;
            }
        }
        let row =
            with_screen(|screen| cursor_offset(screen)).map_or(0, |offset| offset / vga::COLUMNS);
        for &byte in &typed[..count] {
            if byte == b'\r' {
                write(b"\r\n");
            } else {
                write(&[byte]);
            }
        }
        // End a mirrored partial line on COM1 only.
        serial_println!("");
        let words = vga::read_row(row);
        let glyphs: [u8; vga::COLUMNS as usize] = core::array::from_fn(|i| words[i] as u8);
        serial_println!(
            "F2K: keyboard-smoke: echoed on window row {}: '{}'",
            row,
            core::str::from_utf8(&glyphs)
                .unwrap_or("(not ASCII)")
                .trim_end()
        );
    }
}

#[cfg(all(target_arch = "x86", feature = "keyboard-smoke"))]
pub use target::keyboard_smoke;
#[cfg(all(target_arch = "x86", feature = "console-smoke"))]
pub use target::smoke;
#[cfg(target_arch = "x86")]
pub use target::{init, keyboard_byte, write};

#[cfg(test)]
mod tests {
    use super::screen::{BUFFER_WIDTH, WINDOW_HEIGHT};
    use super::*;

    #[test]
    fn rows_render_as_glyph_and_attribute_words() {
        let mut screen = Box::new(ScreenBuffer::new());
        screen.write_bytes(b"Hi\xC4");
        let row = render_row(&screen, 0);
        assert_eq!(row[0], 0x0748);
        assert_eq!(row[1], 0x0769);
        assert_eq!(row[2], 0x07C4, "U+2500 renders as its 437 glyph");
        assert_eq!(
            row[3], 0x0720,
            "blanks are spaces in the default attributes"
        );
        assert_eq!(row.len(), BUFFER_WIDTH as usize);
    }

    #[test]
    fn a_character_without_a_glyph_renders_as_a_question_mark() {
        let mut screen = Box::new(ScreenBuffer::new());
        screen.write_unit(0x20AC);
        assert_eq!(render_row(&screen, 0)[0], 0x073F);
    }

    #[test]
    fn the_cursor_offset_is_relative_to_the_window() {
        let mut screen = Box::new(ScreenBuffer::new());
        assert_eq!(cursor_offset(&screen), Some(0));
        screen.write_bytes(b"ab\ncd");
        assert_eq!(cursor_offset(&screen), Some(80 + 2));
        for _ in 0..30 {
            screen.write_bytes(b"\n");
        }
        // The window followed: the cursor sits on its last row.
        assert_eq!(cursor_offset(&screen), Some((WINDOW_HEIGHT - 1) * 80));
    }

    #[test]
    fn the_window_matches_the_display() {
        assert_eq!(BUFFER_WIDTH, vga::COLUMNS);
        assert_eq!(WINDOW_HEIGHT, vga::ROWS);
    }
}
