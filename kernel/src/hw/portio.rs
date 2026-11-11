//! I/O port access: byte-wide registers, the word-wide accesses a disk data port needs, and
//! the dword accesses PCI config mechanism #1 needs (the address port 0xCF8, the data port
//! 0xCFC).
//!
//! The programmable device drivers (the interrupt controller, the interval timer, the disk
//! controller) reach their registers through this trait, so their logic runs unchanged off-target
//! against a simulated register file (the host unit tests) and on-target against real port I/O.

/// Access to the x86 I/O port space.
pub trait Io {
    /// Write one byte to a port.
    fn out(&mut self, port: u16, byte: u8);
    /// Read one byte from a port.
    fn read(&mut self, port: u16) -> u8;
    /// Read one 16-bit word from a port in a single access (a data port that drains words must
    /// not be read as two bytes).
    fn read_word(&mut self, port: u16) -> u16;
    /// Write one 16-bit word to a port in a single access (a disk data port filled with words).
    /// Only the IDE simulation among the simulated port spaces runs a data-out command.
    fn out_word(&mut self, port: u16, word: u16) {
        let _ = (port, word);
        unimplemented!("this port space takes no word writes");
    }
    /// Read one 32-bit dword from a port in a single access (the PCI config data port returns
    /// the whole register; it must not be read as four bytes).
    fn read_dword(&mut self, port: u16) -> u32 {
        let _ = port;
        unimplemented!("this port space takes no dword reads");
    }
    /// Write one 32-bit dword to a port in a single access (the PCI config address port takes
    /// the whole address dword).
    fn out_dword(&mut self, port: u16, value: u32) {
        let _ = (port, value);
        unimplemented!("this port space takes no dword writes");
    }
}

/// The real I/O port space, reached with `in`/`out` instructions.
///
/// The instructions have no Rust-side memory effect beyond the device; the drivers sequence their
/// accesses, so a plain wrapper suffices.
/// Any mutable reference to a port space is itself a port space.
impl<T: Io + ?Sized> Io for &mut T {
    fn out(&mut self, port: u16, byte: u8) {
        (**self).out(port, byte)
    }

    fn read(&mut self, port: u16) -> u8 {
        (**self).read(port)
    }

    fn read_word(&mut self, port: u16) -> u16 {
        (**self).read_word(port)
    }

    fn out_word(&mut self, port: u16, word: u16) {
        (**self).out_word(port, word)
    }

    fn read_dword(&mut self, port: u16) -> u32 {
        (**self).read_dword(port)
    }

    fn out_dword(&mut self, port: u16, value: u32) {
        (**self).out_dword(port, value)
    }
}

#[cfg(target_arch = "x86")]
#[derive(Copy, Clone)]
pub struct Ports;

#[cfg(target_arch = "x86")]
impl Io for Ports {
    fn out(&mut self, port: u16, byte: u8) {
        // SAFETY: an I/O port write has no in-memory side effects to protect; the drivers own the
        // access ordering.
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

    fn read_word(&mut self, port: u16) -> u16 {
        let word: u16;
        // SAFETY: as above.
        unsafe {
            core::arch::asm!(
                "in ax, dx",
                out("ax") word,
                in("dx") port,
                options(nomem, nostack, preserves_flags)
            );
        }
        word
    }

    fn out_word(&mut self, port: u16, word: u16) {
        // SAFETY: as above.
        unsafe {
            core::arch::asm!(
                "out dx, ax",
                in("dx") port,
                in("ax") word,
                options(nomem, nostack, preserves_flags)
            );
        }
    }

    fn read_dword(&mut self, port: u16) -> u32 {
        let dword: u32;
        // SAFETY: as above.
        unsafe {
            core::arch::asm!(
                "in eax, dx",
                out("eax") dword,
                in("dx") port,
                options(nomem, nostack, preserves_flags)
            );
        }
        dword
    }

    fn out_dword(&mut self, port: u16, value: u32) {
        // SAFETY: as above.
        unsafe {
            core::arch::asm!(
                "out dx, eax",
                in("dx") port,
                in("eax") value,
                options(nomem, nostack, preserves_flags)
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A small register file standing in for the port space, indexed by port modulo its length.
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

        fn read_word(&mut self, port: u16) -> u16 {
            let low = self.regs[(port % 8) as usize];
            let high = self.regs[((port + 1) % 8) as usize];
            u16::from_le_bytes([low, high])
        }

        fn read_dword(&mut self, port: u16) -> u32 {
            let b0 = self.regs[(port % 8) as usize];
            let b1 = self.regs[((port + 1) % 8) as usize];
            let b2 = self.regs[((port + 2) % 8) as usize];
            let b3 = self.regs[((port + 3) % 8) as usize];
            u32::from_le_bytes([b0, b1, b2, b3])
        }

        fn out_dword(&mut self, port: u16, value: u32) {
            let [b0, b1, b2, b3] = value.to_le_bytes();
            self.regs[(port % 8) as usize] = b0;
            self.regs[((port + 1) % 8) as usize] = b1;
            self.regs[((port + 2) % 8) as usize] = b2;
            self.regs[((port + 3) % 8) as usize] = b3;
        }
    }

    /// The trait is the seam: a driver written against `Io` runs against the real ports on target
    /// and the fake in tests.
    #[test]
    fn io_trait_round_trips_through_a_fake() {
        let mut io = Fake { regs: [0; 8] };
        io.out(0x21, 0xFE);
        assert_eq!(io.read(0x21), 0xFE);
    }

    /// The word read returns one 16-bit value, low byte first (the x86 port order).
    #[test]
    fn the_word_read_is_little_endian() {
        let mut io = Fake { regs: [0; 8] };
        io.out(0x1F0, 0x34);
        io.out(0x1F1, 0x12);
        assert_eq!(io.read_word(0x1F0), 0x1234);
    }

    /// A dword written to a port reads back as one 32-bit value — the PCI config address port
    /// (0xCF8) and data port (0xCFC) each carry a whole dword.
    #[test]
    fn the_dword_access_round_trips() {
        let mut io = Fake { regs: [0; 8] };
        io.out_dword(0xCF8, 0x8000_0000);
        io.out_dword(0xCFC, 0x1234_5678);
        assert_eq!(io.read_dword(0xCF8), 0x8000_0000);
        assert_eq!(io.read_dword(0xCFC), 0x1234_5678);
    }

    /// The dword access spans the four consecutive ports, low byte first (the x86 port order),
    /// in both directions.
    #[test]
    fn the_dword_access_is_little_endian_across_four_ports() {
        let mut io = Fake { regs: [0; 8] };
        io.out_dword(0xCFC, 0x1234_5678);
        assert_eq!(io.read(0xCFC), 0x78);
        assert_eq!(io.read(0xCFD), 0x56);
        assert_eq!(io.read(0xCFE), 0x34);
        assert_eq!(io.read(0xCFF), 0x12);
        io.out(0xCFC, 0xEF);
        io.out(0xCFD, 0xBE);
        io.out(0xCFE, 0xAD);
        io.out(0xCFF, 0xDE);
        assert_eq!(io.read_dword(0xCFC), 0xDEAD_BEEF);
    }

    /// Byte and word accesses keep working beside the dword ones on the same register file.
    #[test]
    fn byte_and_word_accesses_still_work_beside_dword() {
        let mut io = Fake { regs: [0; 8] };
        io.out(0x21, 0xFE);
        io.out(0x1F2, 0x34);
        io.out(0x1F3, 0x12);
        io.out_dword(0xCFC, 0x1234_5678);
        assert_eq!(io.read(0x21), 0xFE);
        assert_eq!(io.read_word(0x1F2), 0x1234);
        assert_eq!(io.read_dword(0xCFC), 0x1234_5678);
    }
}
