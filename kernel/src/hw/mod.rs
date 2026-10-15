//! The hardware layer: the programmable devices the kernel drives directly.
//!
//! Port I/O, the 8259A interrupt controller pair, the 8254 interval timer, the IDE disk
//! controller, and the COM1 serial port. The programmable devices reach their registers through
//! the [`portio::Io`] abstraction, so their logic is identical on target (real ports) and in the
//! host tests (a simulated register file).

pub mod ide;
pub mod pic;
pub mod pit;
pub mod portio;
pub mod serial;
