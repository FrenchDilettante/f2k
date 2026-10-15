//! The task file: the registers a command's parameters occupy, and the LBA28 packing into them.

use super::regs::{DEVICE_LBA_MASTER, LBA28_LIMIT, MAX_SECTORS_PER_COMMAND};

/// The registers a command's parameters occupy, in the order they are written.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TaskFile {
    pub count: u8,
    pub lba_low: u8,
    pub lba_mid: u8,
    pub lba_high: u8,
    pub device: u8,
}

impl TaskFile {
    /// The master selected in LBA mode, no parameters: what IDENTIFY needs.
    pub const fn master() -> Self {
        TaskFile {
            count: 0,
            lba_low: 0,
            lba_mid: 0,
            lba_high: 0,
            device: DEVICE_LBA_MASTER,
        }
    }
}

/// Pack an LBA28 transfer of `count` sectors (1-256) starting at `lba`. A count of 256 is written
/// as 0. The run must end within LBA28 reach.
pub fn pack_lba28(lba: u32, count: u32) -> TaskFile {
    assert!(
        (1..=MAX_SECTORS_PER_COMMAND).contains(&count),
        "an LBA28 command moves 1-256 sectors"
    );
    assert!(
        lba as u64 + count as u64 <= LBA28_LIMIT,
        "the run must end within LBA28 reach"
    );
    TaskFile {
        count: count as u8,
        lba_low: lba as u8,
        lba_mid: (lba >> 8) as u8,
        lba_high: (lba >> 16) as u8,
        device: DEVICE_LBA_MASTER | ((lba >> 24) & 0x0F) as u8,
    }
}

/// The sector count a count-register value means: 0 is 256.
pub fn decode_count(register: u8) -> u32 {
    if register == 0 {
        MAX_SECTORS_PER_COMMAND
    } else {
        register as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// LBA28 packing: bits 0-23 across the three LBA registers, bits 24-27 in the device
    /// register's low nibble under the LBA-mode master bits.
    #[test]
    fn lba28_packing_spreads_the_address() {
        assert_eq!(
            pack_lba28(0x0ABC_DEF1, 1),
            TaskFile {
                count: 1,
                lba_low: 0xF1,
                lba_mid: 0xDE,
                lba_high: 0xBC,
                device: 0xEA
            }
        );
        assert_eq!(
            pack_lba28(4067, 8),
            TaskFile {
                count: 8,
                lba_low: 0xE3,
                lba_mid: 0x0F,
                lba_high: 0x00,
                device: 0xE0
            }
        );
        // The last addressable run.
        assert_eq!(pack_lba28((1 << 28) - 1, 1).device, 0xEF);
        assert_eq!(TaskFile::master().device, 0xE0);
    }

    /// The count register: 256 sectors are written as 0, and 0 reads back as 256.
    #[test]
    fn a_count_of_zero_means_256() {
        assert_eq!(pack_lba28(0, 256).count, 0);
        assert_eq!(pack_lba28(0, 255).count, 255);
        assert_eq!(decode_count(0), 256);
        assert_eq!(decode_count(1), 1);
        assert_eq!(decode_count(255), 255);
        for count in 1..=256 {
            assert_eq!(decode_count(pack_lba28(0, count).count), count);
        }
    }

    #[test]
    #[should_panic(expected = "1-256 sectors")]
    fn a_zero_sector_command_is_refused() {
        pack_lba28(0, 0);
    }

    #[test]
    #[should_panic(expected = "1-256 sectors")]
    fn a_257_sector_command_is_refused() {
        pack_lba28(0, 257);
    }

    #[test]
    #[should_panic(expected = "LBA28 reach")]
    fn a_run_past_lba28_reach_is_refused() {
        pack_lba28((1 << 28) - 1, 2);
    }
}
