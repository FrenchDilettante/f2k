//! The block write: a run of contiguous sectors, range-checked against the disk and split into
//! WRITE SECTORS commands of at most 256.

use super::channel::Channel;
use super::latch::{Completion, Latch};
use super::regs::{MAX_SECTORS_PER_COMMAND, SECTOR_SIZE, WRITE_SECTORS};
use super::taskfile::pack_lba28;
use crate::hw::portio::Io;
use crate::status::{
    nt_success, NtStatus, STATUS_INVALID_PARAMETER, STATUS_NO_SUCH_DEVICE, STATUS_SUCCESS,
};

/// Write `buffer.len() / 512` contiguous sectors starting at `lba` to a disk of `capacity` sectors
/// (0: no disk), one WRITE SECTORS command per 256. Returns an NT status.
#[must_use]
pub fn write<IoT: Io, C: Completion<IoT>>(
    channel: &mut Channel<IoT>,
    latch: &Latch,
    completion: &mut C,
    capacity: u32,
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
    let mut next = lba;
    for run in buffer.chunks(MAX_SECTORS_PER_COMMAND as usize * SECTOR_SIZE) {
        let count = (run.len() / SECTOR_SIZE) as u32;
        let status = channel.pio_out(latch, completion, pack_lba28(next, count), WRITE_SECTORS, run);
        if !nt_success(status) {
            return status;
        }
        next += count;
    }
    STATUS_SUCCESS
}
