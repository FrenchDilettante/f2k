//! The hardware layer: the programmable devices the kernel drives directly.
//!
//! Port I/O, the 8259A interrupt controller pair, the 8254 interval timer, the CMOS real-time
//! clock, the IDE disk controller, the i8042 keyboard controller and its PS/2 keyboard, the COM1
//! serial port, and the VGA text screen. The programmable devices reach their registers through the
//! [`portio::Io`] abstraction, so their logic is identical on target (real ports) and in the host
//! tests (a simulated register file).

pub mod ide;
pub mod kbd;
pub mod pic;
pub mod pit;
pub mod portio;
pub mod rtc;
pub mod serial;
pub mod vga;
