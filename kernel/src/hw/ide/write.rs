//! The block write: a run of contiguous sectors, range-checked against the disk and split into
//! commands of at most 256: WRITE MULTIPLE where bring-up set a multiple block, else WRITE SECTORS.

use super::channel::Channel;
use super::latch::{Completion, Latch};
use super::regs::{MAX_SECTORS_PER_COMMAND, SECTOR_SIZE, WRITE_MULTIPLE, WRITE_SECTORS};
use super::taskfile::pack_lba28;
use crate::hal::Io;
use crate::status::{NtStatus, STATUS_INVALID_PARAMETER, STATUS_NO_SUCH_DEVICE, STATUS_SUCCESS};

/// Write `buffer.len() / 512` contiguous sectors starting at `lba` to a disk of `capacity` sectors
/// (0: no disk), one command per 256, moving `block` sectors per interrupt (1: WRITE SECTORS).
/// Returns an NT status.
#[must_use]
pub fn write<IoT: Io, C: Completion<IoT>>(
    channel: &mut Channel<IoT>,
    latch: &Latch,
    completion: &mut C,
    capacity: u32,
    block: u8,
    lba: u32,
    buffer: &[u8],
) -> NtStatus {
    assert!(
        !buffer.is_empty() && buffer.len() % SECTOR_SIZE == 0,
        "a disk write moves whole sectors"
    );
    if capacity == 0 {
        return STATUS_NO_SUCH_DEVICE;
    }
    let sectors = (buffer.len() / SECTOR_SIZE) as u64;
    if lba as u64 + sectors > capacity as u64 {
        return STATUS_INVALID_PARAMETER;
    }
    let command = if block > 1 {
        WRITE_MULTIPLE
    } else {
        WRITE_SECTORS
    };
    let mut next = lba;
    for run in buffer.chunks(MAX_SECTORS_PER_COMMAND as usize * SECTOR_SIZE) {
        let count = (run.len() / SECTOR_SIZE) as u32;
        let status = channel.pio_out(
            latch,
            completion,
            pack_lba28(next, count),
            command,
            block.max(1) as usize,
            run,
        );
        if !status.is_success() {
            return status;
        }
        next += count;
    }
    STATUS_SUCCESS
}

#[cfg(test)]
mod tests {
    use super::super::sim::{ready, ready_multiple, Deliver, DISK};
    use super::*;
    use crate::status::STATUS_IO_DEVICE_ERROR;

    /// `sectors` sectors of data unlike the simulated disk's own pattern.
    fn data(sectors: u32) -> Vec<u8> {
        (0..sectors as usize * SECTOR_SIZE)
            .map(|index| (index * 13 + index / SECTOR_SIZE) as u8 ^ 0x5A)
            .collect()
    }

    /// WRITE SECTORS: per sector the device asks for the data with DRQ, takes 256 words and
    /// interrupts; the disk holds the data, a run past 256 sectors is two commands, and the line
    /// ends low.
    #[test]
    fn a_write_reaches_the_disk() {
        let mut channel = ready();
        let latch = Latch::new();
        let mut deliver = Deliver { delivered: 0 };
        let buffer = data(300);
        assert_eq!(
            write(&mut channel, &latch, &mut deliver, DISK, 1, 11, &buffer),
            STATUS_SUCCESS
        );
        assert_eq!(channel.io().sectors_at(11, 300), &buffer[..]);
        assert_eq!(channel.io().commands(), [WRITE_SECTORS, WRITE_SECTORS]);
        assert_eq!(deliver.delivered, 300, "one interrupt per sector taken");
        assert!(!channel.io().line());
    }

    /// WRITE MULTIPLE: per 8-sector block the device asks with DRQ, takes the block and
    /// interrupts, the last block short; the disk holds the data and the line ends low.
    #[test]
    fn write_multiple_moves_a_block_per_interrupt() {
        let mut channel = ready_multiple(8);
        channel.io().busy_reads = 3;
        let latch = Latch::new();
        let mut deliver = Deliver { delivered: 0 };
        let buffer = data(21);
        assert_eq!(
            write(&mut channel, &latch, &mut deliver, DISK, 8, 500, &buffer),
            STATUS_SUCCESS
        );
        assert_eq!(channel.io().sectors_at(500, 21), &buffer[..]);
        assert_eq!(channel.io().commands(), [WRITE_MULTIPLE]);
        assert_eq!(deliver.delivered, 3, "8 + 8 + 5");
        assert!(!channel.io().line());
    }

    /// A device that takes its 400 ns after the command write to post BUSY: a status read at once
    /// still shows the status from before the command, neither BUSY nor DRQ. The driver settles
    /// before it polls, so the write goes through — and a device slow to take each sector
    /// is waited out too.
    #[test]
    fn the_status_is_read_only_after_the_command_settles() {
        let mut channel = ready();
        channel.io().command_latency = 4;
        channel.io().busy_reads = 30;
        let latch = Latch::new();
        let buffer = data(3);
        let status = write(
            &mut channel,
            &latch,
            &mut Deliver { delivered: 0 },
            DISK,
            1,
            40,
            &buffer,
        );
        assert_eq!(status, STATUS_SUCCESS);
        assert_eq!(channel.io().sectors_at(40, 3), &buffer[..]);
    }

    /// A write past the disk's end is refused before any command; an aborted command is a device
    /// error.
    #[test]
    fn refusals() {
        let mut channel = ready();
        let latch = Latch::new();
        let buffer = data(2);
        assert_eq!(
            write(
                &mut channel,
                &latch,
                &mut Deliver { delivered: 0 },
                DISK,
                1,
                DISK - 1,
                &buffer
            ),
            STATUS_INVALID_PARAMETER
        );
        assert!(channel.io().commands().is_empty());
        let status = channel.pio_out(
            &latch,
            &mut Deliver { delivered: 0 },
            pack_lba28(DISK, 1),
            WRITE_SECTORS,
            1,
            &buffer[..SECTOR_SIZE],
        );
        assert_eq!(status, STATUS_IO_DEVICE_ERROR);
    }
}
