//! The ATA register map: the primary channel's ports and interrupt, the command-block register
//! offsets, the status/error/control bits, the commands the driver issues, and the transfer sizes.

/// The primary channel's command block (data port first) and control register.
pub const PRIMARY_BASE: u16 = 0x1F0;
pub const PRIMARY_CONTROL: u16 = 0x3F6;

/// The primary channel's interrupt: ISA IRQ 14, vector 0x3E after the controller remap.
pub const PRIMARY_VECTOR: u8 = crate::hw::pic::MASTER_VECTOR_BASE + 14;

// Command-block register offsets. Offsets 1 and 7 read and write different registers.
pub(super) const DATA: u16 = 0;
pub(super) const ERROR: u16 = 1;
pub(super) const SECTOR_COUNT: u16 = 2;
pub(super) const LBA_LOW: u16 = 3;
pub(super) const LBA_MID: u16 = 4;
pub(super) const LBA_HIGH: u16 = 5;
pub(super) const DEVICE: u16 = 6;
pub(super) const STATUS: u16 = 7;
pub(super) const COMMAND: u16 = 7;

/// Status register bits.
pub const BUSY: u8 = 0x80;
pub const DRDY: u8 = 0x40;
pub const SEEK: u8 = 0x10;
pub const DRQ: u8 = 0x08;
pub const ERR: u8 = 0x01;

/// Error register: the command was aborted (unsupported, or the sector is out of range).
pub const ABRT: u8 = 0x04;

/// Device control: `nIEN` masks INTRQ when set. The driver keeps it clear.
pub const CONTROL_NIEN: u8 = 0x02;

/// The commands this driver issues.
pub const IDENTIFY_DEVICE: u8 = 0xEC;
pub const READ_SECTORS: u8 = 0x20;

/// Device/head for the master in LBA mode: bits 5-7 set (bit 6 is LBA), bit 4 clear (master), the
/// LBA's top nibble in bits 0-3.
pub(super) const DEVICE_LBA_MASTER: u8 = 0xE0;

/// Bytes per sector.
pub const SECTOR_SIZE: usize = 512;

/// The first sector LBA28 cannot address.
pub const LBA28_LIMIT: u64 = 1 << 28;

/// The most sectors one LBA28 command moves (a count register of 0).
pub const MAX_SECTORS_PER_COMMAND: u32 = 256;

/// Alternate-status reads before a poll gives up: far beyond any settle time, short enough that a
/// wedged device fails the request instead of hanging the caller.
pub const POLL_BOUND: u32 = 100_000;
