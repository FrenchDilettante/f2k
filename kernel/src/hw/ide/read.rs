//! The block read: a run of contiguous sectors, range-checked against the disk and split into
//! commands of at most 256: READ MULTIPLE where bring-up set a multiple block, else READ SECTORS.

use super::channel::Channel;
use super::latch::{Completion, Latch};
use super::regs::{MAX_SECTORS_PER_COMMAND, READ_MULTIPLE, READ_SECTORS, SECTOR_SIZE};
use super::taskfile::pack_lba28;
use crate::hal::Io;
use crate::status::{NtStatus, STATUS_INVALID_PARAMETER, STATUS_NO_SUCH_DEVICE, STATUS_SUCCESS};

/// Read `buffer.len() / 512` contiguous sectors starting at `lba` from a disk of `capacity`
/// sectors (0: no disk), one command per 256, moving `block` sectors per interrupt (1: READ
/// SECTORS). Returns an NT status.
#[must_use]
pub fn read<IoT: Io, C: Completion<IoT>>(
    channel: &mut Channel<IoT>,
    latch: &Latch,
    completion: &mut C,
    capacity: u32,
    block: u8,
    lba: u32,
    buffer: &mut [u8],
) -> NtStatus {
    assert!(
        !buffer.is_empty() && buffer.len() % SECTOR_SIZE == 0,
        "a disk read moves whole sectors"
    );
    if capacity == 0 {
        return STATUS_NO_SUCH_DEVICE;
    }
    let sectors = (buffer.len() / SECTOR_SIZE) as u64;
    if lba as u64 + sectors > capacity as u64 {
        return STATUS_INVALID_PARAMETER;
    }

    let command = if block > 1 {
        READ_MULTIPLE
    } else {
        READ_SECTORS
    };
    let mut next = lba;
    for run in buffer.chunks_mut(MAX_SECTORS_PER_COMMAND as usize * SECTOR_SIZE) {
        let count = (run.len() / SECTOR_SIZE) as u32;
        let status = channel.pio_in(
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
    use super::super::regs::{
        COMMAND,
        DEVICE,
        LBA_HIGH,
        LBA_LOW,
        LBA_MID,
        PRIMARY_BASE,
        SECTOR_COUNT,
    };
    use super::super::sim::{expected, ready, ready_multiple, status_reads, writes, Deliver, DISK};
    use super::*;
    use crate::status::{STATUS_IO_DEVICE_ERROR, STATUS_IO_TIMEOUT};

    /// READ SECTORS: count, LBA low/mid/high, device, then the command — and nothing written while
    /// the device was busy or holding data.
    #[test]
    fn read_sectors_writes_the_task_file_then_the_command() {
        let mut channel = ready();
        channel.io().log.clear();
        let latch = Latch::new();
        let mut buffer = vec![0u8; 2 * SECTOR_SIZE];
        let status = read(
            &mut channel,
            &latch,
            &mut Deliver { delivered: 0 },
            DISK,
            1,
            0x0A0B,
            &mut buffer,
        );
        assert_eq!(status, STATUS_SUCCESS);
        assert_eq!(
            writes(&mut channel),
            vec![
                (PRIMARY_BASE + SECTOR_COUNT, 2),
                (PRIMARY_BASE + LBA_LOW, 0x0B),
                (PRIMARY_BASE + LBA_MID, 0x0A),
                (PRIMARY_BASE + LBA_HIGH, 0x00),
                (PRIMARY_BASE + DEVICE, 0xE0),
                (PRIMARY_BASE + COMMAND, READ_SECTORS),
            ]
        );
        assert_eq!(buffer, expected(0x0A0B, 2));
    }

    /// A run longer than one command splits at 256 sectors: the first command's count register
    /// is 0 (256), the second carries the rest, at the advanced LBA.
    #[test]
    fn a_long_run_splits_at_256_sectors() {
        let mut channel = ready();
        channel.io().log.clear();
        let latch = Latch::new();
        let mut deliver = Deliver { delivered: 0 };
        let mut buffer = vec![0u8; 300 * SECTOR_SIZE];
        assert_eq!(
            read(
                &mut channel,
                &latch,
                &mut deliver,
                DISK,
                1,
                100,
                &mut buffer
            ),
            STATUS_SUCCESS
        );
        assert_eq!(buffer, expected(100, 300));
        assert_eq!(channel.io().commands(), vec![READ_SECTORS, READ_SECTORS]);
        let counts: Vec<u8> = writes(&mut channel)
            .into_iter()
            .filter(|&(port, _)| port == PRIMARY_BASE + SECTOR_COUNT)
            .map(|(_, count)| count)
            .collect();
        assert_eq!(counts, vec![0, 44]);
        let lows: Vec<u8> = writes(&mut channel)
            .into_iter()
            .filter(|&(port, _)| port == PRIMARY_BASE + LBA_LOW)
            .map(|(_, low)| low)
            .collect();
        assert_eq!(lows, vec![100, (100 + 256) as u8]);
        assert_eq!(deliver.delivered, 300, "one interrupt per sector");
    }

    /// READ MULTIPLE: one interrupt per 16-sector block, the last block short; a run past 256
    /// sectors still splits into two commands.
    #[test]
    fn read_multiple_moves_a_block_per_interrupt() {
        let mut channel = ready_multiple(16);
        let latch = Latch::new();
        let mut deliver = Deliver { delivered: 0 };
        let mut buffer = vec![0u8; 300 * SECTOR_SIZE];
        assert_eq!(
            read(
                &mut channel,
                &latch,
                &mut deliver,
                DISK,
                16,
                21,
                &mut buffer
            ),
            STATUS_SUCCESS
        );
        assert_eq!(buffer, expected(21, 300));
        assert_eq!(channel.io().commands(), [READ_MULTIPLE, READ_MULTIPLE]);
        // 256 = 16 blocks of 16; 44 = 2 of 16 and one of 12.
        assert_eq!(deliver.delivered, 16 + 3);
        assert_eq!(status_reads(&mut channel), 19 + 2);
        assert!(!channel.io().line());
    }

    /// A drive not in multiple mode aborts READ MULTIPLE: a device error.
    #[test]
    fn read_multiple_without_the_mode_is_a_device_error() {
        let mut channel = ready();
        let latch = Latch::new();
        let mut buffer = vec![0u8; 4 * SECTOR_SIZE];
        assert_eq!(
            read(
                &mut channel,
                &latch,
                &mut Deliver { delivered: 0 },
                DISK,
                16,
                0,
                &mut buffer
            ),
            STATUS_IO_DEVICE_ERROR
        );
    }

    /// The block API's refusals: a run leaving the disk, and a missing disk — before any port is
    /// touched.
    #[test]
    fn reads_outside_the_disk_or_without_one_are_refused() {
        let mut channel = ready();
        channel.io().log.clear();
        let latch = Latch::new();
        let mut deliver = Deliver { delivered: 0 };
        let mut buffer = vec![0u8; 2 * SECTOR_SIZE];
        assert_eq!(
            read(
                &mut channel,
                &latch,
                &mut deliver,
                DISK,
                1,
                DISK - 1,
                &mut buffer
            ),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            read(&mut channel, &latch, &mut deliver, 0, 1, 0, &mut buffer),
            STATUS_NO_SUCH_DEVICE
        );
        assert!(channel.io().log.is_empty());
        assert!(!STATUS_IO_TIMEOUT.is_success() && STATUS_SUCCESS.is_success());
    }

    #[test]
    #[should_panic(expected = "whole sectors")]
    fn a_partial_sector_buffer_is_a_contract_violation() {
        let mut channel = ready();
        let mut buffer = vec![0u8; 100];
        let _ = read(
            &mut channel,
            &Latch::new(),
            &mut Deliver { delivered: 0 },
            DISK,
            1,
            0,
            &mut buffer,
        );
    }
}
