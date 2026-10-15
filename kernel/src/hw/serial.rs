//! Serial port module for debugging output
//!
//! Uses COM1 at 0x3F8 (standard serial port)

#[cfg(target_arch = "x86")]
use core::arch::asm;
#[cfg(target_arch = "x86")]
use core::fmt::{self, Write};

/// Standard COM1 port address
const COM1: u16 = 0x3F8;

/// Initialize serial port
#[cfg(target_arch = "x86")]
pub fn init() {
    unsafe {
        // Disable interrupts
        write_byte(COM1 + 1, 0x00);

        // Set baud rate divisor to 3 (38400 baud for 1.8432 MHz clock)
        write_byte(COM1 + 3, 0x80); // Set DLAB (bit 7)
        write_byte(COM1 + 0, 0x03); // Low byte of divisor
        write_byte(COM1 + 1, 0x00); // High byte of divisor

        // 8 bits, no parity, one stop bit
        write_byte(COM1 + 3, 0x03);

        // Enable FIFO, clear them
        write_byte(COM1 + 2, 0xC7);

        // Mark data terminal ready and request to send
        write_byte(COM1 + 4, 0x0B);
    }
}

/// Write a byte to an I/O port.
///
/// The UART lives in x86 I/O port space, which is only reachable with the `in`/`out` instructions.
/// A volatile pointer write to 0x3F8 would hit RAM.
#[cfg(target_arch = "x86")]
unsafe fn write_byte(port: u16, byte: u8) {
    asm!("out dx, al", in("dx") port, in("al") byte, options(nomem, nostack, preserves_flags));
}

/// Read a byte from an I/O port.
#[cfg(target_arch = "x86")]
unsafe fn read_byte(port: u16) -> u8 {
    let byte: u8;
    asm!("in al, dx", out("al") byte, in("dx") port, options(nomem, nostack, preserves_flags));
    byte
}

/// Wait for serial port to be ready to transmit
#[cfg(target_arch = "x86")]
fn wait_transmit() {
    unsafe {
        // Wait for Transmitter Holding Register to be empty
        while read_byte(COM1 + 5) & 0x20 == 0 {
            core::hint::spin_loop();
        }
    }
}

/// Write a byte to serial port (waits if needed)
#[cfg(target_arch = "x86")]
pub fn write_byte_blocking(byte: u8) {
    wait_transmit();
    unsafe {
        write_byte(COM1, byte);
    }
}

/// Serial port writer for formatting
pub struct SerialPort;

#[cfg(target_arch = "x86")]
impl Write for SerialPort {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for byte in s.bytes() {
            write_byte_blocking(byte);
        }
        Ok(())
    }
}

/// Print macro for serial output
#[macro_export]
macro_rules! serial_print {
    ($($arg:tt)*) => {
        let mut writer = $crate::hw::serial::SerialPort;
        core::fmt::write(&mut writer, format_args!($($arg)*)).unwrap();
    };
}

/// Println macro for serial output
#[macro_export]
macro_rules! serial_println {
    ($($arg:tt)*) => {
        $crate::serial_print!($($arg)*);
        $crate::hw::serial::write_byte_blocking(b'\n');
    };
}
