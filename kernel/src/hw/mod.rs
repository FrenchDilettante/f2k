//! The hardware layer: the programmable devices the kernel drives.
//!
//! Port I/O, the 8259A interrupt controller pair, the 8254 interval timer, the CMOS real-time
//! clock, the IDE disk controller, the i8042 keyboard controller and its PS/2 keyboard, the COM1
//! serial port, the VGA text screen, and the VBE framebuffer (the graphics screen, set from user
//! mode). The programmable devices reach their registers through the [`portio::Io`] abstraction,
//! so their logic is identical on target (real ports) and in the host tests (a simulated register
//! file).
//!
//! The system hardware among them — the port space, the interrupt controller pair, the interval
//! timer, the real-time clock and the VBE framebuffer — sits behind the hardware abstraction
//! layer's interface ([`crate::hal`]). Outside that interface and those modules, the kernel names
//! `portio`, `pic`, `pit`, `rtc` and `vbe` only in the exceptions the layer's audit lists. The
//! device drivers — `ide`, `kbd`, `serial` and `vga` — are called directly, and reach their
//! registers through the layer's port space.

pub mod ide;
pub mod kbd;
pub mod pic;
pub mod pit;
pub mod portio;
pub mod rtc;
pub mod serial;
pub mod vbe;
pub mod vga;
