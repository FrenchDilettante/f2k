//! Serial port module for debugging output
//!
//! Uses COM1 at 0x3F8 (standard serial port)

use core::fmt::{self, Write};

/// Standard COM1 port address
const COM1: u16 = 0x3F8;

/// Initialize serial port
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

/// Write a byte to serial port
fn write_byte(port: u16, byte: u8) {
    unsafe {
        core::ptr::write_volatile(port as *mut u8, byte);
    }
}

/// Read a byte from serial port
fn read_byte(port: u16) -> u8 {
    unsafe {
        core::ptr::read_volatile(port as *const u8)
    }
}

/// Wait for serial port to be ready to transmit
fn wait_transmit() {
    unsafe {
        // Wait for Transmitter Holding Register to be empty
        while read_byte(COM1 + 5) & 0x20 == 0 {
            core::hint::spin_loop();
        }
    }
}

/// Write a byte to serial port (waits if needed)
pub fn write_byte_blocking(byte: u8) {
    wait_transmit();
    write_byte(COM1, byte);
}

/// Serial port writer for formatting
pub struct SerialPort;

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
        let mut writer = $crate::serial::SerialPort;
        core::fmt::write(&mut writer, format_args!($($arg)*)).unwrap();
    };
}

/// Println macro for serial output
#[macro_export]
macro_rules! serial_println {
    ($($arg:tt)*) => {
        $crate::serial_print!($($arg)*);
        $crate::serial::write_byte_blocking(b'\n');
    };
}
