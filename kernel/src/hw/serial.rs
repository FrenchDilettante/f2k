//! The serial line: a 16550 UART, COM1 at 0x3F8, the kernel's debugging output.
//!
//! The driver reaches the chip's registers through [`Io`], as the other drivers do, so its
//! programming runs unchanged on the target against the real ports and in the host tests against
//! a simulated register file. The line is programmed once, at boot, and written by polling: each
//! byte waits for the transmit holding register to empty, so output never needs an interrupt.

use crate::hw::portio::Io;

/// COM1's base port.
pub const COM1: u16 = 0x3F8;

/// The register offsets from the base. With the divisor latch open (DLAB set), offsets 0 and 1
/// are the baud divisor's low and high bytes.
const DATA: u16 = 0;
const INTERRUPT_ENABLE: u16 = 1;
const FIFO_CONTROL: u16 = 2;
const LINE_CONTROL: u16 = 3;
const MODEM_CONTROL: u16 = 4;
const LINE_STATUS: u16 = 5;

/// Line control: the divisor latch access bit.
const DLAB: u8 = 0x80;
/// Line control: 8 data bits, no parity, one stop bit.
const EIGHT_N_ONE: u8 = 0x03;
/// The baud divisor for 38400 baud from the 1.8432 MHz clock.
const DIVISOR_38400: u16 = 3;
/// FIFO control: enable the FIFOs, clear both, 14-byte receive trigger.
const FIFO_ENABLE_CLEAR: u8 = 0xC7;
/// Modem control: data terminal ready, request to send, and OUT2.
const DTR_RTS_OUT2: u8 = 0x0B;
/// Line status: the transmit holding register is empty.
const TRANSMIT_EMPTY: u8 = 0x20;

/// A 16550 UART at `base` in the port space `IoT`.
pub struct Uart<IoT: Io> {
    io: IoT,
    base: u16,
}

impl<IoT: Io> Uart<IoT> {
    /// The UART at `base`.
    pub const fn new(io: IoT, base: u16) -> Self {
        Uart { io, base }
    }

    /// The port space (the host tests' simulation).
    #[cfg(test)]
    pub fn io(&mut self) -> &mut IoT {
        &mut self.io
    }

    /// Program the line: no interrupts, 38400 baud, 8N1, FIFOs on and cleared, DTR and RTS.
    pub fn init(&mut self) {
        self.write_register(INTERRUPT_ENABLE, 0x00);
        self.write_register(LINE_CONTROL, DLAB);
        let [low, high] = DIVISOR_38400.to_le_bytes();
        self.write_register(DATA, low);
        self.write_register(INTERRUPT_ENABLE, high);
        self.write_register(LINE_CONTROL, EIGHT_N_ONE);
        self.write_register(FIFO_CONTROL, FIFO_ENABLE_CLEAR);
        self.write_register(MODEM_CONTROL, DTR_RTS_OUT2);
    }

    /// Send one byte, once the transmit holding register has emptied.
    pub fn write_byte(&mut self, byte: u8) {
        while self.io.read(self.base + LINE_STATUS) & TRANSMIT_EMPTY == 0 {
            core::hint::spin_loop();
        }
        self.write_register(DATA, byte);
    }

    fn write_register(&mut self, offset: u16, byte: u8) {
        self.io.out(self.base + offset, byte);
    }
}

impl<IoT: Io> core::fmt::Write for Uart<IoT> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        s.bytes().for_each(|byte| self.write_byte(byte));
        Ok(())
    }
}

/// COM1 over the real ports. The line holds no state of its own beyond the chip's, so every
/// writer makes its own.
#[cfg(target_arch = "x86")]
pub fn com1() -> Uart<crate::hw::portio::Ports> {
    Uart::new(crate::hw::portio::Ports, COM1)
}

/// Program COM1 (boot, before the first line).
#[cfg(target_arch = "x86")]
pub fn init() {
    com1().init();
}

/// Send one byte to COM1, waiting for room.
#[cfg(target_arch = "x86")]
pub fn write_byte_blocking(byte: u8) {
    com1().write_byte(byte);
}

/// Print to COM1, formatted.
#[macro_export]
macro_rules! serial_print {
    ($($arg:tt)*) => {
        let mut writer = $crate::hw::serial::com1();
        core::fmt::write(&mut writer, format_args!($($arg)*)).unwrap();
    };
}

/// Print a line to COM1, formatted.
#[macro_export]
macro_rules! serial_println {
    ($($arg:tt)*) => {
        $crate::serial_print!($($arg)*);
        $crate::hw::serial::write_byte_blocking(b'\n');
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The port writes in order, and a line status register that reports the transmitter busy for
    /// a set number of reads before it empties.
    struct Line {
        writes: Vec<(u16, u8)>,
        busy_reads: u32,
    }

    impl Io for Line {
        fn out(&mut self, port: u16, byte: u8) {
            self.writes.push((port, byte));
        }

        fn read(&mut self, port: u16) -> u8 {
            assert_eq!(port, COM1 + LINE_STATUS);
            if self.busy_reads > 0 {
                self.busy_reads -= 1;
                0
            } else {
                TRANSMIT_EMPTY
            }
        }

        fn read_word(&mut self, _port: u16) -> u16 {
            unreachable!("the UART has no word registers")
        }
    }

    fn uart() -> Uart<Line> {
        Uart::new(
            Line {
                writes: Vec::new(),
                busy_reads: 0,
            },
            COM1,
        )
    }

    /// The bring-up programs COM1 as the boot always has: interrupts off, the divisor 3 behind
    /// the latch, 8N1, the FIFOs, DTR and RTS.
    #[test]
    fn init_programs_the_line() {
        let mut uart = uart();
        uart.init();
        assert_eq!(
            uart.io().writes,
            [
                (0x3F9, 0x00),
                (0x3FB, 0x80),
                (0x3F8, 0x03),
                (0x3F9, 0x00),
                (0x3FB, 0x03),
                (0x3FA, 0xC7),
                (0x3FC, 0x0B),
            ]
        );
    }

    /// A byte waits for the transmitter, then goes to the data register; formatted text goes
    /// byte by byte.
    #[test]
    fn bytes_wait_for_the_transmitter() {
        use core::fmt::Write;
        let mut uart = uart();
        uart.io().busy_reads = 3;
        uart.write_byte(b'A');
        assert_eq!(uart.io().busy_reads, 0);
        write!(uart, "{}{}", 4, 2).unwrap();
        assert_eq!(
            uart.io().writes,
            [(0x3F8, b'A'), (0x3F8, b'4'), (0x3F8, b'2')]
        );
    }
}
