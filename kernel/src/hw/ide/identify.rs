//! Device identification: the IDENTIFY DEVICE decode, and the bring-up that detects the master and
//! identifies it.

use super::channel::Channel;
use super::latch::{Completion, Latch};
use super::regs::{IDENTIFY_DEVICE, SECTOR_SIZE};
use super::taskfile::TaskFile;
use crate::hw::portio::Io;
use crate::status::{nt_success, NtStatus};

/// What IDENTIFY DEVICE reports that the driver uses.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Identity {
    /// Word 49 bit 9: LBA addressing supported.
    pub lba: bool,
    /// Words 60-61: the LBA28 sector count.
    pub sectors: u32,
    /// Word 47 low byte: the largest READ MULTIPLE block, in sectors.
    pub max_multiple: u8,
}

/// Decode the IDENTIFY DEVICE block (256 little-endian words).
pub fn decode_identify(block: &[u8; SECTOR_SIZE]) -> Identity {
    let word = |index: usize| u16::from_le_bytes([block[2 * index], block[2 * index + 1]]);
    Identity {
        lba: word(49) & (1 << 9) != 0,
        sectors: word(60) as u32 | (word(61) as u32) << 16,
        max_multiple: word(47) as u8,
    }
}

/// Why bring-up found no usable disk.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Absent {
    /// Nothing answers on the master position.
    NoDevice,
    /// A device answers but IDENTIFY DEVICE failed (an ATAPI device aborts it), with the status.
    NotAta(NtStatus),
    /// The disk does not support LBA addressing.
    NoLba,
}

/// Bring the master up: let the device interrupt, detect it, and IDENTIFY it. Returns the identity
/// of a disk the driver can address with LBA28.
pub fn bring_up<IoT: Io, C: Completion<IoT>>(
    channel: &mut Channel<IoT>,
    latch: &Latch,
    completion: &mut C,
) -> Result<Identity, Absent> {
    channel.enable_interrupt();
    if !channel.detect() {
        return Err(Absent::NoDevice);
    }
    let mut block = [0u8; SECTOR_SIZE];
    let status = channel.pio_in(
        latch,
        completion,
        TaskFile::master(),
        IDENTIFY_DEVICE,
        &mut block,
    );
    if !nt_success(status) {
        return Err(Absent::NotAta(status));
    }
    let identity = decode_identify(&block);
    if !identity.lba || identity.sectors == 0 {
        return Err(Absent::NoLba);
    }
    Ok(identity)
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
        PRIMARY_CONTROL,
        SECTOR_COUNT,
    };
    use super::super::sim::{identify_block, sim_channel, writes, Deliver, SimChannel, DISK};
    use super::*;

    /// IDENTIFY decode: word 49 bit 9 is LBA support, words 60-61 the LBA28 count (low word
    /// first), word 47's low byte the multiple setting.
    #[test]
    fn identify_decodes_lba_count_and_multiple() {
        let identity = decode_identify(&identify_block(131_072));
        assert_eq!(
            identity,
            Identity {
                lba: true,
                sectors: 131_072,
                max_multiple: 16
            }
        );

        // Both count words matter.
        assert_eq!(
            decode_identify(&identify_block(0x0012_3456)).sectors,
            0x0012_3456
        );

        let mut no_lba = identify_block(131_072);
        no_lba[2 * 49 + 1] &= !0x02; // clear bit 9
        assert!(!decode_identify(&no_lba).lba);
    }

    /// IDENTIFY bring-up: clear nIEN, select the master, then the task file and the command —
    /// one interrupt, one block, the identity decoded.
    #[test]
    fn bring_up_clears_nien_selects_and_identifies() {
        let mut channel = sim_channel(SimChannel::with_disk(DISK));
        let latch = Latch::new();
        let mut deliver = Deliver { delivered: 0 };
        let identity = bring_up(&mut channel, &latch, &mut deliver).unwrap();
        assert_eq!(
            identity,
            Identity {
                lba: true,
                sectors: DISK,
                max_multiple: 16
            }
        );

        assert_eq!(
            writes(&mut channel),
            vec![
                (PRIMARY_CONTROL, 0x00),
                (PRIMARY_BASE + DEVICE, 0xE0),
                (PRIMARY_BASE + SECTOR_COUNT, 0),
                (PRIMARY_BASE + LBA_LOW, 0),
                (PRIMARY_BASE + LBA_MID, 0),
                (PRIMARY_BASE + LBA_HIGH, 0),
                (PRIMARY_BASE + DEVICE, 0xE0),
                (PRIMARY_BASE + COMMAND, IDENTIFY_DEVICE),
            ]
        );
        assert_eq!(deliver.delivered, 1);
        assert_eq!(latch.serviced(), 1);
        assert_eq!(latch.unsolicited(), 0);
    }

    /// An empty master position floats to zero: bring-up reports no device without issuing a
    /// command.
    #[test]
    fn an_empty_channel_has_no_device() {
        let mut channel = sim_channel(SimChannel::empty());
        let latch = Latch::new();
        assert_eq!(
            bring_up(&mut channel, &latch, &mut Deliver { delivered: 0 }),
            Err(Absent::NoDevice)
        );
        assert!(channel.io().commands().is_empty());
    }
}
