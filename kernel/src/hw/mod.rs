//! The hardware layer: the programmable devices the kernel drives
//! directly.
//!
//! Byte-wide port I/O, the 8259A interrupt controller pair, the 8254
//! interval timer, and the COM1 serial port. The programmable
//! devices reach their registers through the [`portio::Io`]
//! abstraction, so their logic is identical on target (real ports)
//! and in the host tests (a simulated register file).

pub mod pic;
pub mod pit;
pub mod portio;
pub mod serial;
