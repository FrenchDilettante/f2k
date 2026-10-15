//! One channel's registers and the PIO data-in protocol: per sector, wait for the interrupt, check
//! the status the service routine acknowledged, confirm the data on the alternate status, drain
//! it; end the command with one status-register read.

use super::latch::{Completion, Latch};
use super::regs::{
    BUSY, COMMAND, DATA, DEVICE, DEVICE_LBA_MASTER, DRQ, ERR, ERROR, LBA_HIGH, LBA_LOW, LBA_MID,
    POLL_BOUND, SECTOR_COUNT, SECTOR_SIZE, STATUS,
};
use super::taskfile::TaskFile;
use super::{STATUS_IO_DEVICE_ERROR, STATUS_IO_TIMEOUT, STATUS_SUCCESS};
use crate::hw::portio::Io;

/// One channel's registers.
pub struct Channel<IoT: Io> {
    io: IoT,
    base: u16,
    control: u16,
}

impl<IoT: Io> Channel<IoT> {
    pub const fn new(io: IoT, base: u16, control: u16) -> Self {
        Channel { io, base, control }
    }

    /// The underlying port access.
    pub fn io(&mut self) -> &mut IoT {
        &mut self.io
    }

    /// The alternate status: the status without acknowledging INTRQ.
    pub fn alternate_status(&mut self) -> u8 {
        self.io.read(self.control)
    }

    /// The status register. Reading it acknowledges INTRQ.
    pub fn status(&mut self) -> u8 {
        self.io.read(self.base + STATUS)
    }

    /// Write the control register clear (`nIEN` off, no reset): the device's completions assert
    /// INTRQ from here on.
    pub fn enable_interrupt(&mut self) {
        self.io.out(self.control, 0);
    }

    /// Select the master and report whether a device answers. An empty channel floats: its status
    /// reads all ones on a bare bus, all zeros on an emulated one.
    pub fn detect(&mut self) -> bool {
        self.io.out(self.base + DEVICE, DEVICE_LBA_MASTER);
        self.settle();
        let status = self.alternate_status();
        status != 0x00 && status != 0xFF
    }

    /// Run one PIO data-in command that fills `buffer` with its `buffer.len() / 512` sectors, one
    /// interrupt per sector. Returns an NT status: success, timeout, or device error.
    #[must_use]
    pub fn pio_in<C: Completion<IoT>>(
        &mut self,
        latch: &Latch,
        completion: &mut C,
        task_file: TaskFile,
        command: u8,
        buffer: &mut [u8],
    ) -> i32 {
        assert!(
            !buffer.is_empty() && buffer.len() % SECTOR_SIZE == 0,
            "a PIO transfer moves whole sectors"
        );

        // The device ignores register writes while it is busy or holding data.
        if self.poll(|status| status & (BUSY | DRQ) == 0).is_none() {
            return STATUS_IO_TIMEOUT;
        }
        self.write_task_file(task_file);
        self.settle();

        // Armed before the command write: the interrupt can follow it at once.
        latch.arm();
        self.io.out(self.base + COMMAND, command);

        let sectors = buffer.len() / SECTOR_SIZE;
        for (index, sector) in buffer.chunks_exact_mut(SECTOR_SIZE).enumerate() {
            if !completion.wait(&mut self.io, latch) {
                latch.disarm();
                return STATUS_IO_TIMEOUT;
            }
            if latch.status() & ERR != 0 {
                return self.device_error();
            }
            // The interrupt reported the data ready; confirm it without acknowledging anything.
            match self.poll(|status| status & BUSY == 0) {
                None => return STATUS_IO_TIMEOUT,
                Some(status) if status & ERR != 0 => return self.device_error(),
                Some(status) if status & DRQ == 0 => return STATUS_IO_DEVICE_ERROR,
                Some(_) => {}
            }
            // The drain's last word starts the next sector, whose interrupt can follow at once.
            if index + 1 < sectors {
                latch.arm();
            }
            self.drain(sector);
        }

        // The command is over: no data left, no error. The status register read ends it.
        if self.poll(|status| status & BUSY == 0).is_none() {
            return STATUS_IO_TIMEOUT;
        }
        let status = self.status();
        if status & ERR != 0 {
            return self.device_error();
        }
        if status & DRQ != 0 {
            return STATUS_IO_DEVICE_ERROR;
        }
        STATUS_SUCCESS
    }

    fn write_task_file(&mut self, task_file: TaskFile) {
        self.io.out(self.base + SECTOR_COUNT, task_file.count);
        self.io.out(self.base + LBA_LOW, task_file.lba_low);
        self.io.out(self.base + LBA_MID, task_file.lba_mid);
        self.io.out(self.base + LBA_HIGH, task_file.lba_high);
        self.io.out(self.base + DEVICE, task_file.device);
    }

    /// Drain one sector from the data port, 256 words.
    fn drain(&mut self, sector: &mut [u8]) {
        for pair in sector.chunks_exact_mut(2) {
            let word = self.io.read_word(self.base + DATA);
            pair.copy_from_slice(&word.to_le_bytes());
        }
    }

    /// The device-select settle time: four alternate-status reads span the 400 ns a device takes
    /// to put its status on the bus.
    fn settle(&mut self) {
        for _ in 0..4 {
            self.alternate_status();
        }
    }

    /// Poll the alternate status until `done` accepts it, at most [`POLL_BOUND`] reads.
    fn poll(&mut self, done: impl Fn(u8) -> bool) -> Option<u8> {
        for _ in 0..POLL_BOUND {
            let status = self.alternate_status();
            if done(status) {
                return Some(status);
            }
        }
        None
    }

    /// A command that failed with ERR: read the error register (the device's diagnosis) and
    /// report the failure.
    fn device_error(&mut self) -> i32 {
        let _error = self.io.read(self.base + ERROR);
        STATUS_IO_DEVICE_ERROR
    }
}

#[cfg(test)]
mod tests {
    use super::super::read::read;
    use super::super::regs::{ABRT, IDENTIFY_DEVICE, PRIMARY_BASE, READ_SECTORS};
    use super::super::sim::{
        channel_with_nien, expected, ready, status_reads, Access, Deliver, DISK,
    };
    use super::super::taskfile::pack_lba28;
    use super::*;

    // --- The INTRQ discipline -----------------------------------------------------------------

    /// The simulated contract itself: the alternate status leaves INTRQ asserted, the status
    /// register acknowledges it, a command write deasserts it, and nIEN gates it.
    #[test]
    fn status_acknowledges_and_alternate_status_does_not() {
        let mut channel = ready();
        channel.io().out(PRIMARY_BASE + COMMAND, IDENTIFY_DEVICE);
        assert!(channel.io().line());
        channel.alternate_status();
        channel.alternate_status();
        assert!(
            channel.io().line(),
            "the alternate status never acknowledges"
        );
        channel.status();
        assert!(!channel.io().line(), "the status register does");

        // nIEN masks the line the device drives.
        let mut masked = channel_with_nien();
        masked.io().out(PRIMARY_BASE + COMMAND, IDENTIFY_DEVICE);
        assert!(masked.io().intrq && !masked.io().line());
    }

    /// A multi-sector read polls only the alternate status: the status register is read once per
    /// interrupt (by the service routine) and once at the end — and the line ends low.
    #[test]
    fn a_read_acknowledges_only_in_the_service_routine_and_at_the_end() {
        let mut channel = ready();
        channel.io().log.clear();
        let latch = Latch::new();
        let mut deliver = Deliver { delivered: 0 };
        let mut buffer = vec![0u8; 5 * SECTOR_SIZE];
        assert_eq!(
            read(&mut channel, &latch, &mut deliver, DISK, 7, &mut buffer),
            STATUS_SUCCESS
        );
        assert_eq!(deliver.delivered, 5);
        assert_eq!(
            channel.io().raised,
            5,
            "one interrupt per sector, none after the last"
        );
        assert_eq!(status_reads(&mut channel), 5 + 1);
        assert!(!channel.io().line());
        assert_eq!(latch.serviced(), 5);
        assert_eq!(latch.unsolicited(), 0);
        assert_eq!(buffer, expected(7, 5));
    }

    /// A device that also interrupts after the final drain: the closing status read acknowledges
    /// it, so the line ends low either way.
    #[test]
    fn the_closing_status_read_clears_a_completion_interrupt() {
        let mut channel = ready();
        channel.io().interrupt_after_last = true;
        let latch = Latch::new();
        let mut buffer = vec![0u8; 3 * SECTOR_SIZE];
        assert_eq!(
            read(
                &mut channel,
                &latch,
                &mut Deliver { delivered: 0 },
                DISK,
                0,
                &mut buffer
            ),
            STATUS_SUCCESS
        );
        assert_eq!(channel.io().raised, 4);
        assert!(!channel.io().line());
        assert_eq!(buffer, expected(0, 3));
    }

    /// Data is drained only after the interrupt: a device that stays busy (no interrupt yet)
    /// leaves the data port untouched until the wait reports it.
    #[test]
    fn data_is_read_only_after_the_interrupt() {
        let mut channel = ready();
        channel.io().busy_reads = 50;
        let latch = Latch::new();
        let mut buffer = vec![0u8; 2 * SECTOR_SIZE];
        assert_eq!(
            read(
                &mut channel,
                &latch,
                &mut Deliver { delivered: 0 },
                DISK,
                9,
                &mut buffer
            ),
            STATUS_SUCCESS
        );
        assert_eq!(buffer, expected(9, 2));
        // No data-port read ever happened with DRQ clear (it would have read zeros).
        let words = channel
            .io()
            .log
            .iter()
            .filter(|a| matches!(a, Access::Word(_)))
            .count();
        assert_eq!(words, 2 * 256);
    }

    /// No interrupt, no read: with nIEN left set the device never interrupts, and the read fails
    /// with a timeout instead of draining anything.
    #[test]
    fn without_an_interrupt_the_read_times_out() {
        let mut channel = channel_with_nien();
        let latch = Latch::new();
        let mut buffer = vec![0u8; SECTOR_SIZE];
        assert_eq!(
            read(
                &mut channel,
                &latch,
                &mut Deliver { delivered: 0 },
                DISK,
                0,
                &mut buffer
            ),
            STATUS_IO_TIMEOUT
        );
        assert_eq!(latch.serviced(), 0, "no interrupt was serviced");
        assert!(channel
            .io()
            .log
            .iter()
            .all(|a| !matches!(a, Access::Word(_))));
    }

    // --- Errors -------------------------------------------------------------------------------

    /// A sector past the device's end: the command completes with ERR|ABRT and an interrupt, and
    /// the read reports a device error after reading the error register.
    #[test]
    fn an_out_of_range_sector_is_a_device_error() {
        let mut channel = ready();
        let latch = Latch::new();
        let mut buffer = vec![0u8; SECTOR_SIZE];
        // The driver's own range check would refuse this; drive the device directly.
        let status = channel.pio_in(
            &latch,
            &mut Deliver { delivered: 0 },
            pack_lba28(DISK, 1),
            READ_SECTORS,
            &mut buffer,
        );
        assert_eq!(status, STATUS_IO_DEVICE_ERROR);
        assert_eq!(latch.status() & ERR, ERR);
        assert_eq!(channel.io().error, ABRT);
        assert!(channel
            .io()
            .log
            .contains(&Access::Read(PRIMARY_BASE + ERROR, ABRT)));
        assert!(!channel.io().line());

        // The device takes the next command normally.
        assert_eq!(
            read(
                &mut channel,
                &latch,
                &mut Deliver { delivered: 0 },
                DISK,
                1,
                &mut buffer
            ),
            STATUS_SUCCESS
        );
    }
}
