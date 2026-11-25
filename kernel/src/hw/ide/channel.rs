//! One channel's registers and the PIO protocols. Data moves in DRQ blocks: one sector, or up to
//! the SET MULTIPLE count under READ/WRITE MULTIPLE, the last block of a command possibly short.
//! Data in, per block: wait for the interrupt, check the status the service routine acknowledged,
//! confirm the data on the alternate status, drain it; end the command with one status-register
//! read. Data out: settle after the command, then per block poll for the device's request, fill
//! it, and wait for the interrupt that reports it taken. No data: wait for the interrupt that
//! reports the command done, then check the status.
//!
//! DMA: the bus master set up (stopped, its direction, the descriptor table, its status bits
//! cleared), the command written, the engine started; one interrupt when the command is done, then
//! the engine stopped and both its status and the device's checked.

use super::latch::{Completion, Latch};
use super::regs::{
    BM_COMMAND,
    BM_ERROR,
    BM_INTERRUPT,
    BM_START,
    BM_STATUS,
    BM_TABLE,
    BM_TO_MEMORY,
    BUSY,
    COMMAND,
    DATA,
    DEVICE,
    DEVICE_LBA_MASTER,
    DRQ,
    ERR,
    ERROR,
    FEATURES,
    LBA_HIGH,
    LBA_LOW,
    LBA_MID,
    POLL_BOUND,
    READ_DMA,
    SECTOR_COUNT,
    SECTOR_SIZE,
    SET_FEATURES,
    STATUS,
    WRITE_DMA,
};
use super::taskfile::TaskFile;
use crate::hal::Io;
use crate::status::{NtStatus, STATUS_IO_DEVICE_ERROR, STATUS_IO_TIMEOUT, STATUS_SUCCESS};

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
    /// interrupt per block of `block` sectors. Returns an NT status: success, timeout, or device
    /// error.
    #[must_use]
    pub fn pio_in<C: Completion<IoT>>(
        &mut self,
        latch: &Latch,
        completion: &mut C,
        task_file: TaskFile,
        command: u8,
        block: usize,
        buffer: &mut [u8],
    ) -> NtStatus {
        assert!(
            !buffer.is_empty() && buffer.len() % SECTOR_SIZE == 0,
            "a PIO transfer moves whole sectors"
        );
        assert!(block >= 1, "a DRQ block holds at least one sector");

        // The device ignores register writes while it is busy or holding data.
        if self.poll(|status| status & (BUSY | DRQ) == 0).is_none() {
            return STATUS_IO_TIMEOUT;
        }
        self.write_task_file(task_file);
        self.settle();

        // Armed before the command write: the interrupt can follow it at once.
        latch.arm();
        self.io.out(self.base + COMMAND, command);

        let blocks = buffer.len().div_ceil(block * SECTOR_SIZE);
        for (index, chunk) in buffer.chunks_mut(block * SECTOR_SIZE).enumerate() {
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
            // The drain's last word starts the next block, whose interrupt can follow at once.
            if index + 1 < blocks {
                latch.arm();
            }
            self.drain(chunk);
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

    /// Run one PIO data-out command that writes `buffer`'s `buffer.len() / 512` sectors: per block
    /// of `block` sectors, wait for the device to ask for the data (DRQ), fill it, and wait for the
    /// interrupt that reports the block taken. Returns an NT status: success, timeout, or device
    /// error.
    #[must_use]
    pub fn pio_out<C: Completion<IoT>>(
        &mut self,
        latch: &Latch,
        completion: &mut C,
        task_file: TaskFile,
        command: u8,
        block: usize,
        buffer: &[u8],
    ) -> NtStatus {
        assert!(
            !buffer.is_empty() && buffer.len() % SECTOR_SIZE == 0,
            "a PIO transfer moves whole sectors"
        );
        assert!(block >= 1, "a DRQ block holds at least one sector");
        if self.poll(|status| status & (BUSY | DRQ) == 0).is_none() {
            return STATUS_IO_TIMEOUT;
        }
        self.write_task_file(task_file);
        self.settle();
        self.io.out(self.base + COMMAND, command);
        // No interrupt announces the first block's request, and the device may take 400 ns to
        // post BUSY: a poll at once could read the status from before the command.
        self.settle();

        for chunk in buffer.chunks(block * SECTOR_SIZE) {
            // The device asks for the block without an interrupt: poll for its request.
            match self.poll(|status| status & BUSY == 0) {
                None => return STATUS_IO_TIMEOUT,
                Some(status) if status & ERR != 0 => return self.device_error(),
                Some(status) if status & DRQ == 0 => return STATUS_IO_DEVICE_ERROR,
                Some(_) => {}
            }
            // The interrupt follows the block's last word.
            latch.arm();
            self.fill(chunk);
            if !completion.wait(&mut self.io, latch) {
                latch.disarm();
                return STATUS_IO_TIMEOUT;
            }
            if latch.status() & ERR != 0 {
                return self.device_error();
            }
        }

        if self.poll(|status| status & BUSY == 0).is_none() {
            return STATUS_IO_TIMEOUT;
        }
        let status = self.alternate_status();
        if status & ERR != 0 {
            return self.device_error();
        }
        if status & DRQ != 0 {
            return STATUS_IO_DEVICE_ERROR;
        }
        STATUS_SUCCESS
    }

    /// Run one non-data command: the device is BUSY until it is done, then interrupts with its
    /// completion. The caller waits up to `waits` completion waits for that interrupt (a long
    /// command takes more than one), then checks the status the service routine acknowledged and
    /// that the device is no longer BUSY. Returns an NT status: success, timeout, or device error.
    #[must_use]
    pub fn non_data<C: Completion<IoT>>(
        &mut self,
        latch: &Latch,
        completion: &mut C,
        task_file: TaskFile,
        command: u8,
        waits: u32,
    ) -> NtStatus {
        if self.poll(|status| status & (BUSY | DRQ) == 0).is_none() {
            return STATUS_IO_TIMEOUT;
        }
        self.write_task_file(task_file);
        self.settle();
        // Armed before the command write: the completion can follow it at once.
        latch.arm();
        self.io.out(self.base + COMMAND, command);
        // A wait that gave up leaves the latch armed: the next one waits on for the same interrupt.
        if !(0..waits).any(|_| completion.wait(&mut self.io, latch)) {
            latch.disarm();
            return STATUS_IO_TIMEOUT;
        }
        if latch.status() & ERR != 0 {
            return self.device_error();
        }
        match self.poll(|status| status & BUSY == 0) {
            None => STATUS_IO_TIMEOUT,
            Some(status) if status & ERR != 0 => self.device_error(),
            Some(status) if status & DRQ != 0 => STATUS_IO_DEVICE_ERROR,
            Some(_) => STATUS_SUCCESS,
        }
    }

    /// Run one SET FEATURES subcommand `feature` with `count` in the sector count register (a
    /// non-data command; see [`Channel::non_data`]).
    #[must_use]
    pub fn set_features<C: Completion<IoT>>(
        &mut self,
        latch: &Latch,
        completion: &mut C,
        feature: u8,
        count: u8,
    ) -> NtStatus {
        if self.poll(|status| status & (BUSY | DRQ) == 0).is_none() {
            return STATUS_IO_TIMEOUT;
        }
        self.io.out(self.base + FEATURES, feature);
        let task_file = TaskFile {
            count,
            ..TaskFile::master()
        };
        self.non_data(latch, completion, task_file, SET_FEATURES, 1)
    }

    /// Run one DMA command (READ DMA when `to_memory`, else WRITE DMA) through the bus master at
    /// `bus_master` over the descriptor table at physical `table`, which names the transfer's
    /// memory: the engine set up (stopped, its direction, the table, its status bits cleared), the
    /// command written, the engine started; then the one interrupt the device raises when the
    /// command is done, the engine stopped, and both the device's status and the engine's checked.
    /// Returns an NT status: success, timeout, or device error.
    #[must_use]
    pub fn dma<C: Completion<IoT>>(
        &mut self,
        latch: &Latch,
        completion: &mut C,
        bus_master: u16,
        table: u32,
        task_file: TaskFile,
        to_memory: bool,
    ) -> NtStatus {
        let direction = if to_memory { BM_TO_MEMORY } else { 0 };
        let command = if to_memory { READ_DMA } else { WRITE_DMA };
        if self.poll(|status| status & (BUSY | DRQ) == 0).is_none() {
            return STATUS_IO_TIMEOUT;
        }
        self.io.out(bus_master + BM_COMMAND, direction);
        self.io.out_dword(bus_master + BM_TABLE, table);
        let engine = self.io.read(bus_master + BM_STATUS);
        self.io
            .out(bus_master + BM_STATUS, engine | BM_ERROR | BM_INTERRUPT);
        self.write_task_file(task_file);
        self.settle();
        // Armed before the command write: the completion can follow the engine's start at once.
        latch.arm();
        self.io.out(self.base + COMMAND, command);
        self.io.out(bus_master + BM_COMMAND, direction | BM_START);
        let completed = completion.wait(&mut self.io, latch);
        let engine = self.io.read(bus_master + BM_STATUS);
        // Stop the engine whatever happened, and clear its interrupt and error bits.
        self.io.out(bus_master + BM_COMMAND, direction);
        self.io
            .out(bus_master + BM_STATUS, engine | BM_ERROR | BM_INTERRUPT);
        if !completed {
            latch.disarm();
            return STATUS_IO_TIMEOUT;
        }
        if latch.status() & ERR != 0 {
            return self.device_error();
        }
        if engine & BM_ERROR != 0 {
            return STATUS_IO_DEVICE_ERROR;
        }
        match self.poll(|status| status & BUSY == 0) {
            None => STATUS_IO_TIMEOUT,
            Some(status) if status & ERR != 0 => self.device_error(),
            Some(status) if status & DRQ != 0 => STATUS_IO_DEVICE_ERROR,
            Some(_) => STATUS_SUCCESS,
        }
    }

    /// Fill one block into the data port, 256 words per sector.
    fn fill(&mut self, block: &[u8]) {
        for pair in block.chunks_exact(2) {
            self.io
                .out_word(self.base + DATA, u16::from_le_bytes([pair[0], pair[1]]));
        }
    }

    fn write_task_file(&mut self, task_file: TaskFile) {
        self.io.out(self.base + SECTOR_COUNT, task_file.count);
        self.io.out(self.base + LBA_LOW, task_file.lba_low);
        self.io.out(self.base + LBA_MID, task_file.lba_mid);
        self.io.out(self.base + LBA_HIGH, task_file.lba_high);
        self.io.out(self.base + DEVICE, task_file.device);
    }

    /// Drain one block from the data port, 256 words per sector.
    fn drain(&mut self, block: &mut [u8]) {
        for pair in block.chunks_exact_mut(2) {
            let word = self.io.read_word(self.base + DATA);
            pair.copy_from_slice(&word.to_le_bytes());
        }
    }

    /// The settle time after a device select or a command write: four alternate-status reads span
    /// the 400 ns a device takes to put its status on the bus.
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
    fn device_error(&mut self) -> NtStatus {
        let _error = self.io.read(self.base + ERROR);
        STATUS_IO_DEVICE_ERROR
    }
}

#[cfg(test)]
mod tests {
    use super::super::read::read;
    use super::super::regs::{ABRT, IDENTIFY_DEVICE, PRIMARY_BASE, READ_SECTORS};
    use super::super::sim::{
        channel_with_nien,
        expected,
        ready,
        status_reads,
        Access,
        Deliver,
        DISK,
    };
    use super::super::taskfile::pack_lba28;
    use super::*;

    // --- DMA -----------------------------------------------------------------------------------

    /// A descriptor table at `at` in the simulated memory, over `runs` (address, length).
    fn table(channel: &mut Channel<super::super::sim::SimChannel>, at: usize, runs: &[(u32, u32)]) {
        let mut entries = [super::super::busmaster::Descriptor::default(); 8];
        let count = super::super::busmaster::descriptors(
            runs.iter()
                .map(|&(address, length)| (u64::from(address), length)),
            &mut entries,
        )
        .unwrap();
        for (index, entry) in entries[..count].iter().enumerate() {
            channel.io().memory[at + 8 * index..at + 8 * index + 8].copy_from_slice(&entry.bytes());
        }
    }

    /// READ DMA: the engine moves the sectors into memory along the table, in its pieces, with
    /// one interrupt for the whole command; the engine ends stopped with its bits clear.
    #[test]
    fn a_dma_read_fills_memory_along_the_table() {
        use super::super::sim::BUS_MASTER;
        let mut channel = ready();
        let latch = Latch::new();
        let mut deliver = Deliver { delivered: 0 };
        // 3 sectors: one into 0x1000, two into 0x8000 (a second run).
        table(&mut channel, 0x100, &[(0x1000, 512), (0x8000, 1024)]);
        let status = channel.dma(
            &latch,
            &mut deliver,
            BUS_MASTER,
            0x100,
            pack_lba28(40, 3),
            true,
        );
        assert_eq!(status, STATUS_SUCCESS);
        assert_eq!(deliver.delivered, 1, "one interrupt for the command");
        let want = expected(40, 3);
        assert_eq!(channel.io().memory[0x1000..0x1200], want[..512]);
        assert_eq!(channel.io().memory[0x8000..0x8400], want[512..]);
        assert_eq!(channel.io().commands(), vec![READ_DMA]);
        assert_eq!(
            channel.io().bm_command,
            BM_TO_MEMORY,
            "stopped, the direction kept"
        );
        assert_eq!(channel.io().bm_status & (BM_INTERRUPT | BM_ERROR | 1), 0);
    }

    /// WRITE DMA: the engine moves memory onto the disk.
    #[test]
    fn a_dma_write_reaches_the_disk() {
        use super::super::sim::BUS_MASTER;
        let mut channel = ready();
        let latch = Latch::new();
        let mut deliver = Deliver { delivered: 0 };
        for (index, byte) in channel.io().memory[0x4000..0x4400].iter_mut().enumerate() {
            *byte = (index * 3) as u8;
        }
        table(&mut channel, 0x200, &[(0x4000, 1024)]);
        let status = channel.dma(
            &latch,
            &mut deliver,
            BUS_MASTER,
            0x200,
            pack_lba28(7, 2),
            false,
        );
        assert_eq!(status, STATUS_SUCCESS);
        let written = channel.io().memory[0x4000..0x4400].to_vec();
        assert_eq!(channel.io().sectors_at(7, 2), &written[..]);
        assert_eq!(channel.io().commands(), vec![WRITE_DMA]);
        assert_eq!(channel.io().bm_command, 0);
    }

    /// A command the device aborts (a range past the disk) is a device error, the engine stopped.
    #[test]
    fn an_aborted_dma_command_is_a_device_error() {
        use super::super::sim::BUS_MASTER;
        let mut channel = ready();
        let latch = Latch::new();
        let mut deliver = Deliver { delivered: 0 };
        table(&mut channel, 0x100, &[(0x1000, 1024)]);
        let status = channel.dma(
            &latch,
            &mut deliver,
            BUS_MASTER,
            0x100,
            pack_lba28(DISK - 1, 2),
            true,
        );
        assert_eq!(status, STATUS_IO_DEVICE_ERROR);
        assert_eq!(channel.io().bm_command & BM_START, 0);
    }

    /// SET FEATURES writes the subcommand to the features register and the value to the count:
    /// a multiword DMA mode is taken, anything else aborted.
    #[test]
    fn set_features_sets_the_transfer_mode() {
        use super::super::regs::{MULTIWORD_DMA, SET_TRANSFER_MODE};
        let mut channel = ready();
        let latch = Latch::new();
        let mut deliver = Deliver { delivered: 0 };
        let status =
            channel.set_features(&latch, &mut deliver, SET_TRANSFER_MODE, MULTIWORD_DMA | 2);
        assert_eq!(status, STATUS_SUCCESS);
        assert_eq!(channel.io().transfer_mode, Some(0x22));
        let status = channel.set_features(&latch, &mut deliver, SET_TRANSFER_MODE, 0x45);
        assert_eq!(status, STATUS_IO_DEVICE_ERROR);
    }

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
            read(&mut channel, &latch, &mut deliver, DISK, 1, 7, &mut buffer),
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
                1,
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
                1,
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
                1,
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
            1,
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
                1,
                &mut buffer
            ),
            STATUS_SUCCESS
        );
    }
}
