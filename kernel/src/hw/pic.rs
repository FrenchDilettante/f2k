//! 8259A interrupt controller: the two-chip ISA cascade.
//!
//! The boot remaps the chips so ISA IRQ 0-15 arrive as CPU vectors 0x30-0x3F (clear of the syscall
//! gate at 0x2E), keeps every line masked until a driver connects it, and drives the
//! end-of-interrupt discipline.
//!
//! The controller owns the datasheet's spurious-interrupt quirk: a line that deasserts before the
//! CPU acknowledges is delivered as IRQ7 (or IRQ15) with no in-service bit set anywhere. The
//! in-service register therefore separates a real interrupt from a spurious one — a spurious master
//! interrupt needs no end-of-interrupt at all, while a spurious slave interrupt must still end the
//! master's cascade service (that in-service bit is real), but never the slave's.

use crate::hw::portio::Io;

/// First vector the master chip delivers (IRQ 0).
pub const MASTER_VECTOR_BASE: u8 = 0x30;

/// First vector the slave chip delivers (IRQ 8). The cascade wiring forces this to the master base
/// plus 8.
pub const SLAVE_VECTOR_BASE: u8 = MASTER_VECTOR_BASE + 8;

/// Last vector the cascade delivers (IRQ 15).
pub const LAST_VECTOR: u8 = SLAVE_VECTOR_BASE + 7;

// Port addresses: command/status and data (mask) per chip.
const MASTER_CMD: u16 = 0x20;
const MASTER_DATA: u16 = 0x21;
const SLAVE_CMD: u16 = 0xA0;
const SLAVE_DATA: u16 = 0xA1;

// Initialization command words: edge-triggered, cascade mode, a fourth word needed; the master has
// its slave on line 2, the slave answers on cascade identity 2; both run in 8086 mode.
const ICW1_INIT: u8 = 0x11;
const ICW4_8086: u8 = 0x01;
const MASTER_ICW3_SLAVE_ON_2: u8 = 0x04;
const SLAVE_ICW3_IDENTITY_2: u8 = 0x02;

/// The master's mask bit for the cascade line (IRQ 2, where the slave is wired).
const CASCADE_BIT: u8 = MASTER_ICW3_SLAVE_ON_2;

// Operating control words: a non-specific end-of-interrupt, and the read-register selects that make
// the next command-port read return the in-service or the request register.
const OCW2_NON_SPECIFIC_EOI: u8 = 0x20;
const OCW3_READ_IN_SERVICE: u8 = 0x0B;
const OCW3_READ_REQUEST: u8 = 0x0A;

/// The verdict of claiming a delivered vector: whether the interrupt was real, and — for a spurious
/// one — which end-of-interrupt work (if any) the controller already had to perform.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Verdict {
    /// A real interrupt: the in-service bit is set; the caller must end the interrupt
    /// ([`Pic::end_of_interrupt`]) when done.
    Real,
    /// A spurious master interrupt: no bit was in service, so the caller must not acknowledge it
    /// in any way.
    SpuriousNoEoi,
    /// A spurious slave interrupt: no slave bit was in service, but the master's cascade bit was —
    /// the controller has already ended the cascade service; the caller must not end anything.
    SpuriousCascadeEnded,
}

/// One 8259A pair, driven through `Io`: the vector bases it is remapped to, and its port space.
///
/// Its state is all in the chips, so it is driven through `&self`: each operation works on a copy
/// of the port space (the real one has no state of its own), and a kernel static needs no lock
/// beyond the level discipline its callers keep.
pub struct Pic<IoT: Io + Copy> {
    io: IoT,
    master_base: u8,
    slave_base: u8,
}

impl<IoT: Io + Copy> Pic<IoT> {
    /// A pair to be remapped to the given vector bases. Call [`Pic::remap`] before use.
    pub const fn new(io: IoT, master_base: u8, slave_base: u8) -> Self {
        Self {
            io,
            master_base,
            slave_base,
        }
    }

    /// The port space, for one operation's accesses.
    fn io(&self) -> IoT {
        self.io
    }

    /// Remap the cascade to the pair's vector bases and mask every line.
    ///
    /// The four-word initialization sequence per chip sets the vector bases and the cascade wiring;
    /// the masks close with every line disabled — a line is unmasked only when a driver connects
    /// it, so an unconnected vector's line can never raise it.
    pub fn remap(&self) {
        let mut io = self.io();
        io.out(MASTER_CMD, ICW1_INIT);
        io.out(MASTER_DATA, self.master_base);
        io.out(MASTER_DATA, MASTER_ICW3_SLAVE_ON_2);
        io.out(MASTER_DATA, ICW4_8086);

        io.out(SLAVE_CMD, ICW1_INIT);
        io.out(SLAVE_DATA, self.slave_base);
        io.out(SLAVE_DATA, SLAVE_ICW3_IDENTITY_2);
        io.out(SLAVE_DATA, ICW4_8086);

        self.mask_all();
    }

    /// The vector bases the remap programs: (master, slave).
    #[cfg(any(test, feature = "irq-smoke"))]
    pub fn vector_bases(&self) -> (u8, u8) {
        (self.master_base, self.slave_base)
    }

    /// The two chips' interrupt mask registers, (master, slave): a set bit is a masked line.
    #[cfg(any(test, feature = "irq-smoke"))]
    pub fn line_masks(&self) -> (u8, u8) {
        let mut io = self.io();
        (io.read(MASTER_DATA), io.read(SLAVE_DATA))
    }

    /// Mask all 16 lines (the data-port image after reset).
    pub fn mask_all(&self) {
        let mut io = self.io();
        io.out(MASTER_DATA, 0xFF);
        io.out(SLAVE_DATA, 0xFF);
    }

    /// Clear (enable) one line by vector. A slave line also opens the master's cascade line, which
    /// every slave interrupt passes through.
    pub fn unmask(&self, vector: u8) {
        let (port, bit) = self.line(vector);
        let mut io = self.io();
        let mask = io.read(port) & !bit;
        io.out(port, mask);
        if port == SLAVE_DATA {
            let master = io.read(MASTER_DATA) & !CASCADE_BIT;
            io.out(MASTER_DATA, master);
        }
    }

    /// Set (disable) one line by vector. Masking the last open slave line closes the cascade too.
    pub fn mask(&self, vector: u8) {
        let (port, bit) = self.line(vector);
        let mut io = self.io();
        let mask = io.read(port) | bit;
        io.out(port, mask);
        if port == SLAVE_DATA && mask == 0xFF {
            let master = io.read(MASTER_DATA) | CASCADE_BIT;
            io.out(MASTER_DATA, master);
        }
    }

    /// Whether one line is enabled, by vector. The cascade line is the slave's wiring, never a
    /// device line: its vector is never delivered, so it never reports enabled.
    pub fn is_unmasked(&self, vector: u8) -> bool {
        if self.is_cascade(vector) {
            return false;
        }
        let (port, bit) = self.line(vector);
        self.io().read(port) & bit == 0
    }

    /// Claim a delivered vector: probe the in-service register and settle the spurious question,
    /// performing the cascade end-of-interrupt a spurious slave interrupt demands.
    pub fn claim(&self, vector: u8) -> Verdict {
        if vector < self.slave_base {
            if self.in_service_bit(vector) {
                Verdict::Real
            } else {
                Verdict::SpuriousNoEoi
            }
        } else if self.in_service_bit(vector) {
            Verdict::Real
        } else {
            // The master took the cascade; end its service so the cascade line can deliver again.
            // The slave needs nothing.
            self.io().out(MASTER_CMD, OCW2_NON_SPECIFIC_EOI);
            Verdict::SpuriousCascadeEnded
        }
    }

    /// End a real interrupt: acknowledge the chip that served it — and, for a slave line, the
    /// master's cascade service too.
    pub fn end_of_interrupt(&self, vector: u8) {
        let mut io = self.io();
        if vector >= self.slave_base {
            io.out(SLAVE_CMD, OCW2_NON_SPECIFIC_EOI);
        }
        io.out(MASTER_CMD, OCW2_NON_SPECIFIC_EOI);
    }

    /// Whether a line has raised a request the processor has not acknowledged yet, by vector: its
    /// bit in the request register of the chip that serves it. (Every in-service probe selects its
    /// own register, so this read leaves nothing selected that they rely on.)
    pub fn requested(&self, vector: u8) -> bool {
        let cmd = if vector >= self.slave_base {
            SLAVE_CMD
        } else {
            MASTER_CMD
        };
        let mut io = self.io();
        io.out(cmd, OCW3_READ_REQUEST);
        io.read(cmd) & (1 << (vector & 7)) != 0
    }

    /// Whether the in-service register of both chips is clear: the on-target check that no
    /// interrupt was left half-served.
    pub fn in_service_clear(&self) -> bool {
        let master = self.read_in_service(false);
        let slave = self.read_in_service(true);
        master == 0 && slave == 0
    }

    /// Read the in-service bit for a vector: select the in-service register on the chip that would
    /// serve it, then read bit (vector mod 8).
    fn in_service_bit(&self, vector: u8) -> bool {
        let slave = vector >= self.slave_base;
        self.read_in_service(slave) & (1 << (vector & 7)) != 0
    }

    /// Select and read one chip's in-service register.
    fn read_in_service(&self, slave: bool) -> u8 {
        let cmd = if slave { SLAVE_CMD } else { MASTER_CMD };
        let mut io = self.io();
        io.out(cmd, OCW3_READ_IN_SERVICE);
        io.read(cmd)
    }

    /// The data port and line bit for a vector.
    fn line(&self, vector: u8) -> (u16, u8) {
        assert!(
            !self.is_cascade(vector),
            "the cascade line carries the slave, not a device"
        );
        if vector < self.slave_base {
            (MASTER_DATA, 1 << (vector - self.master_base))
        } else {
            (SLAVE_DATA, 1 << (vector - self.slave_base))
        }
    }

    /// Whether `vector` is the master's cascade line (IRQ 2).
    fn is_cascade(&self, vector: u8) -> bool {
        vector < self.slave_base && 1 << (vector - self.master_base) == CASCADE_BIT
    }
}

#[cfg(test)]
mod tests {
    use std::cell::{RefCell, RefMut};

    use super::*;

    /// A simulated 8259A pair: interrupt mask, in-service and request registers per chip, with
    /// command-port writes decoded the way the chips decode them.
    struct Sim {
        master: Chip,
        slave: Chip,
        writes: Vec<(u16, u8)>,
    }

    struct Chip {
        imr: u8,
        isr: u8,
        irr: u8,
        select_isr: bool,
    }

    impl Sim {
        fn new() -> Self {
            Self {
                master: Chip {
                    imr: 0,
                    isr: 0,
                    irr: 0,
                    select_isr: false,
                },
                slave: Chip {
                    imr: 0,
                    isr: 0,
                    irr: 0,
                    select_isr: false,
                },
                writes: Vec::new(),
            }
        }

        fn chip_mut(&mut self, port: u16) -> &mut Chip {
            if port >= SLAVE_CMD {
                &mut self.slave
            } else {
                &mut self.master
            }
        }

        /// Model the CPU's interrupt-acknowledge cycle for a line: the chip latches the line into
        /// its in-service register.
        fn acknowledge(&mut self, vector: u8) {
            if vector >= SLAVE_VECTOR_BASE {
                self.slave.isr |= 1 << (vector & 7);
                self.master.isr |= 1 << 2; // the cascade line
            } else {
                self.master.isr |= 1 << (vector & 7);
            }
        }

        fn writes_to(&self, port: u16) -> Vec<u8> {
            self.writes
                .iter()
                .filter(|&&(p, _)| p == port)
                .map(|&(_, b)| b)
                .collect()
        }

        /// The end-of-interrupt writes issued so far (OCW2 0x20 to a command port).
        fn eoi_writes(&self) -> Vec<(u16, u8)> {
            self.writes
                .iter()
                .copied()
                .filter(|&(p, b)| (p == MASTER_CMD || p == SLAVE_CMD) && b == OCW2_NON_SPECIFIC_EOI)
                .collect()
        }
    }

    /// The simulated pair as the controller drives it: a copyable handle on the shared registers.
    #[derive(Clone, Copy)]
    struct SimPorts(&'static RefCell<Sim>);

    impl Io for SimPorts {
        fn out(&mut self, port: u16, byte: u8) {
            self.0.borrow_mut().out(port, byte);
        }

        fn read(&mut self, port: u16) -> u8 {
            self.0.borrow_mut().read(port)
        }

        fn read_word(&mut self, port: u16) -> u16 {
            self.0.borrow_mut().read_word(port)
        }
    }

    /// The simulated registers behind `pic`, for a test to look at or change.
    fn sim(pic: &Pic<SimPorts>) -> RefMut<'static, Sim> {
        pic.io.0.borrow_mut()
    }

    impl Io for Sim {
        fn out(&mut self, port: u16, byte: u8) {
            self.writes.push((port, byte));
            match port {
                MASTER_CMD | SLAVE_CMD => {
                    let chip = self.chip_mut(port);
                    if byte & 0x20 != 0 {
                        // Non-specific EOI: clear the highest-priority in-service bit.
                        if let Some(bit) = (0..8).find(|&i| chip.isr & (1 << i) != 0) {
                            chip.isr &= !(1 << bit);
                        }
                    } else if byte & 0x08 != 0 {
                        chip.select_isr = byte & 0x01 != 0;
                    }
                }
                MASTER_DATA | SLAVE_DATA => {
                    self.chip_mut(port).imr = byte;
                }
                _ => {}
            }
        }

        fn read(&mut self, port: u16) -> u8 {
            match port {
                MASTER_CMD | SLAVE_CMD => {
                    let chip = self.chip_mut(port);
                    if chip.select_isr {
                        chip.isr
                    } else {
                        chip.irr
                    }
                }
                MASTER_DATA | SLAVE_DATA => self.chip_mut(port).imr,
                _ => 0,
            }
        }

        fn read_word(&mut self, _port: u16) -> u16 {
            0
        }
    }

    fn remapped() -> Pic<SimPorts> {
        let sim = Box::leak(Box::new(RefCell::new(Sim::new())));
        let pic = Pic::new(SimPorts(sim), MASTER_VECTOR_BASE, SLAVE_VECTOR_BASE);
        pic.remap();
        pic
    }

    /// The initialization sequence: per chip an ICW1 on the command port, then ICW2 (the vector
    /// base), ICW3 (the cascade wiring) and ICW4 (8086 mode) on the data port, in that order.
    #[test]
    fn remap_writes_the_initialization_sequence() {
        let pic = remapped();
        assert_eq!(sim(&pic).writes_to(MASTER_CMD), vec![0x11]);
        assert_eq!(
            sim(&pic).writes_to(MASTER_DATA),
            vec![MASTER_VECTOR_BASE, 0x04, 0x01, 0xFF]
        );
        assert_eq!(sim(&pic).writes_to(SLAVE_CMD), vec![0x11]);
        assert_eq!(
            sim(&pic).writes_to(SLAVE_DATA),
            vec![SLAVE_VECTOR_BASE, 0x02, 0x01, 0xFF]
        );
    }

    /// The readers the irq-smoke diagnostic reports: the bases the remap programmed, and the mask
    /// registers as the chips hold them (IRQ 0 open alone; then IRQ 14, which opens the cascade).
    #[test]
    fn bases_and_line_masks_read_back() {
        let pic = remapped();
        assert_eq!(pic.vector_bases(), (0x30, 0x38));
        assert_eq!(pic.line_masks(), (0xFF, 0xFF));
        pic.unmask(MASTER_VECTOR_BASE);
        assert_eq!(pic.line_masks(), (0xFE, 0xFF));
        pic.unmask(SLAVE_VECTOR_BASE + 6);
        assert_eq!(pic.line_masks(), (0xFA, 0xBF));
    }

    /// After remap every line is masked; unmasking and masking one line touches exactly its bit.
    #[test]
    fn masks_start_closed_and_toggle_per_line() {
        let pic = remapped();
        for vector in MASTER_VECTOR_BASE..=LAST_VECTOR {
            assert!(
                !pic.is_unmasked(vector),
                "vector {vector:#x} unmasked after remap"
            );
        }
        pic.unmask(MASTER_VECTOR_BASE); // IRQ 0
        assert!(pic.is_unmasked(MASTER_VECTOR_BASE));
        assert!(!pic.is_unmasked(MASTER_VECTOR_BASE + 1));
        pic.unmask(SLAVE_VECTOR_BASE + 4); // IRQ 12
        assert!(pic.is_unmasked(SLAVE_VECTOR_BASE + 4));
        assert!(!pic.is_unmasked(SLAVE_VECTOR_BASE));
        pic.mask(MASTER_VECTOR_BASE);
        assert!(!pic.is_unmasked(MASTER_VECTOR_BASE));
    }

    /// A slave line needs the master's cascade line open to reach the CPU: unmasking any slave line
    /// opens it, and it closes only when the last slave line is masked again. The cascade itself
    /// never reports as an enabled device line.
    #[test]
    fn slave_lines_open_and_close_the_cascade() {
        let pic = remapped();
        let cascade = MASTER_VECTOR_BASE + 2;
        let master_mask = |pic: &Pic<SimPorts>| sim(pic).master.imr;
        assert_ne!(master_mask(&pic) & CASCADE_BIT, 0, "closed after remap");

        pic.unmask(SLAVE_VECTOR_BASE + 6); // IRQ 14
        assert_eq!(master_mask(&pic) & CASCADE_BIT, 0, "opened by a slave line");
        assert_eq!(sim(&pic).slave.imr, !(1 << 6));
        assert!(
            !pic.is_unmasked(cascade),
            "the cascade is not a device line"
        );

        pic.unmask(SLAVE_VECTOR_BASE + 4); // IRQ 12
        pic.mask(SLAVE_VECTOR_BASE + 6);
        assert_eq!(master_mask(&pic) & CASCADE_BIT, 0, "IRQ 12 still needs it");
        pic.mask(SLAVE_VECTOR_BASE + 4);
        assert_ne!(
            master_mask(&pic) & CASCADE_BIT,
            0,
            "closed with the last slave line"
        );

        // Master lines never touch it.
        pic.unmask(MASTER_VECTOR_BASE);
        assert_ne!(master_mask(&pic) & CASCADE_BIT, 0);
    }

    /// Nothing connects to the cascade line: enabling it as a device line is a contract violation.
    #[test]
    #[should_panic(expected = "cascade line")]
    fn the_cascade_line_is_not_connectable() {
        let pic = remapped();
        pic.unmask(MASTER_VECTOR_BASE + 2);
    }

    /// A real interrupt: the acknowledge cycle latched the line in-service, so the claim is Real
    /// and the end-of-interrupt clears the in-service bits (the cascade bit included for a slave
    /// line).
    #[test]
    fn claim_real_master_and_slave_interrupts() {
        let pic = remapped();
        sim(&pic).acknowledge(MASTER_VECTOR_BASE);
        assert_eq!(pic.claim(MASTER_VECTOR_BASE), Verdict::Real);
        assert!(!pic.in_service_clear());
        pic.end_of_interrupt(MASTER_VECTOR_BASE);
        assert!(pic.in_service_clear());

        sim(&pic).acknowledge(SLAVE_VECTOR_BASE + 6);
        assert_eq!(pic.claim(SLAVE_VECTOR_BASE + 6), Verdict::Real);
        assert!(!pic.in_service_clear());
        pic.end_of_interrupt(SLAVE_VECTOR_BASE + 6);
        assert!(pic.in_service_clear());
    }

    /// A spurious IRQ7: nothing was in service, so the claim issues no acknowledgment at all — and
    /// the handler must not either.
    #[test]
    fn spurious_master_interrupt_needs_no_eoi() {
        let pic = remapped();
        let eois_before = sim(&pic).eoi_writes();
        assert_eq!(pic.claim(MASTER_VECTOR_BASE + 7), Verdict::SpuriousNoEoi);
        assert_eq!(sim(&pic).eoi_writes(), eois_before); // not one EOI
        assert!(pic.in_service_clear());
    }

    /// A spurious IRQ15: the slave served nothing, but the master's cascade bit is really in
    /// service — the claim ends the cascade (and only the cascade) itself.
    #[test]
    fn spurious_slave_interrupt_ends_only_the_cascade() {
        let pic = remapped();
        // The cascade fired, the slave answered with nothing.
        sim(&pic).master.isr |= 1 << 2;
        let eois_before = sim(&pic).eoi_writes();
        assert_eq!(
            pic.claim(SLAVE_VECTOR_BASE + 7),
            Verdict::SpuriousCascadeEnded
        );
        {
            let sim = sim(&pic);
            assert_eq!(sim.eoi_writes().len(), eois_before.len() + 1);
            assert_eq!(
                sim.eoi_writes().last().copied(),
                Some((MASTER_CMD, OCW2_NON_SPECIFIC_EOI))
            );
            assert_eq!(sim.slave.isr, 0); // the slave was never served
        }
        assert!(pic.in_service_clear());
    }

    /// A raised line not yet acknowledged shows in the request register (the clock's tick the
    /// performance counter must count before it is taken); the in-service probe still reads the
    /// in-service register after it.
    #[test]
    fn a_pending_request_reads_from_the_request_register() {
        let pic = remapped();
        assert!(!pic.requested(MASTER_VECTOR_BASE));
        sim(&pic).master.irr = 0x01;
        assert!(pic.requested(MASTER_VECTOR_BASE));
        assert!(!pic.requested(MASTER_VECTOR_BASE + 1));
        assert_eq!(
            pic.claim(MASTER_VECTOR_BASE),
            Verdict::SpuriousNoEoi,
            "nothing in service yet"
        );
        sim(&pic).acknowledge(MASTER_VECTOR_BASE);
        assert_eq!(pic.claim(MASTER_VECTOR_BASE), Verdict::Real);
    }

    /// The vector bases leave the whole IRQ band clear of the syscall gate at 0x2E, and the two
    /// chips cover 16 lines.
    #[test]
    fn vector_band_lays_out_around_the_syscall_gate() {
        assert_eq!(MASTER_VECTOR_BASE, 0x30);
        assert_eq!(SLAVE_VECTOR_BASE, 0x38);
        assert_eq!(LAST_VECTOR, 0x3F);
        assert!(!((MASTER_VECTOR_BASE as usize)..=(LAST_VECTOR as usize))
            .contains(&crate::user::syscall::SYSCALL_VECTOR));
    }
}
