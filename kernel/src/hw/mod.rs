//! The hardware layer: the programmable devices the kernel drives directly.
//!
//! Port I/O, the 8259A interrupt controller pair, the 8254 interval timer, the IDE disk
//! controller, the COM1 serial port, the VGA text display, and the 8042 keyboard controller. The
//! programmable devices reach their registers through the [`portio::Io`] abstraction, so their
//! logic is identical on target (real ports) and in the host tests (a simulated register file).

pub mod ide;
pub mod pic;
pub mod pit;
pub mod portio;
pub mod ps2;
pub mod serial;
pub mod vga;
