//! Byte-wide I/O port access.
//!
//! The programmable device drivers (the interrupt controller and the
//! interval timer) reach their registers through this trait, so their
//! logic runs unchanged off-target against a simulated register file
//! (the host unit tests) and on-target against real port I/O.

/// Byte-wide access to the x86 I/O port space.
pub trait Io {
    /// Write one byte to a port.
    fn out(&mut self, port: u16, byte: u8);
    /// Read one byte from a port.
    fn read(&mut self, port: u16) -> u8;
}

/// The real I/O port space, reached with `in`/`out` instructions.
///
/// The instructions have no Rust-side memory effect beyond the device;
/// the drivers sequence their accesses, so a plain wrapper suffices.
#[cfg(target_arch = "x86")]
#[derive(Copy, Clone)]
pub struct Ports;

#[cfg(target_arch = "x86")]
impl Io for Ports {
    fn out(&mut self, port: u16, byte: u8) {
        // SAFETY: an I/O port write has no in-memory side effects to
        // protect; the drivers own the access ordering.
        unsafe {
            core::arch::asm!(
                "out dx, al",
                in("dx") port,
                in("al") byte,
                options(nomem, nostack, preserves_flags)
            );
        }
    }

    fn read(&mut self, port: u16) -> u8 {
        let byte: u8;
        // SAFETY: as above.
        unsafe {
            core::arch::asm!(
                "in al, dx",
                out("al") byte,
                in("dx") port,
                options(nomem, nostack, preserves_flags)
            );
        }
        byte
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A small register file standing in for the port space, indexed
    /// by port modulo its length.
    struct Fake {
        regs: [u8; 8],
    }

    impl Io for Fake {
        fn out(&mut self, port: u16, byte: u8) {
            self.regs[(port % 8) as usize] = byte;
        }

        fn read(&mut self, port: u16) -> u8 {
            self.regs[(port % 8) as usize]
        }
    }

    /// The trait is the seam: a driver written against `Io` runs
    /// against the real ports on target and the fake in tests.
    #[test]
    fn io_trait_round_trips_through_a_fake() {
        let mut io = Fake { regs: [0; 8] };
        io.out(0x21, 0xFE);
        assert_eq!(io.read(0x21), 0xFE);
    }
}
