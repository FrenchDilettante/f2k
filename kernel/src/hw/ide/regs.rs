//! The ATA register map: the primary channel's ports and interrupt, the command-block register
//! offsets, the status/error/control bits, the commands the driver issues, and the transfer sizes.

/// The primary channel's command block (data port first) and control register.
pub const PRIMARY_BASE: u16 = 0x1F0;
pub const PRIMARY_CONTROL: u16 = 0x3F6;

/// The primary channel's interrupt: ISA IRQ 14, vector 0x3E on the platform's band.
pub const PRIMARY_VECTOR: u8 = crate::hal::interrupt_vector(14);

// Command-block register offsets. Offsets 1 and 7 read and write different registers.
pub(super) const DATA: u16 = 0;
pub(super) const ERROR: u16 = 1;
/// Offset 1 written: the features register.
pub(super) const FEATURES: u16 = 1;
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
/// WRITE SECTORS (PIO data-out, LBA28).
pub const WRITE_SECTORS: u8 = 0x30;
/// READ MULTIPLE and WRITE MULTIPLE: READ/WRITE SECTORS moving a SET MULTIPLE block per DRQ
/// and interrupt.
pub const READ_MULTIPLE: u8 = 0xC4;
pub const WRITE_MULTIPLE: u8 = 0xC5;
/// SET MULTIPLE MODE (non-data): the sector count register names the block size.
pub const SET_MULTIPLE_MODE: u8 = 0xC6;
/// READ DMA and WRITE DMA (LBA28): the sectors move by the controller's bus master, one
/// interrupt when the whole command is done.
pub const READ_DMA: u8 = 0xC8;
pub const WRITE_DMA: u8 = 0xCA;
/// SET FEATURES (non-data): the features register names the subcommand.
pub const SET_FEATURES: u8 = 0xEF;
/// SET FEATURES' subcommand that sets the transfer mode the sector count register names.
pub const SET_TRANSFER_MODE: u8 = 0x03;
/// The transfer-mode value of multiword DMA mode `n`: 0x20 | n.
pub const MULTIWORD_DMA: u8 = 0x20;
/// FLUSH CACHE (non-data): the drive writes its write cache to the medium.
pub const FLUSH_CACHE: u8 = 0xE7;
/// FLUSH CACHE EXT (non-data): FLUSH CACHE for a drive of the 48-bit address feature set.
pub const FLUSH_CACHE_EXT: u8 = 0xEA;
/// CHECK POWER MODE: no data; its completion asserts INTRQ (the `nest-smoke` diagnostic's
/// interrupt).
#[cfg(feature = "nest-smoke")]
pub const CHECK_POWER_MODE: u8 = 0xE5;

/// Device/head for the master in LBA mode: bits 5-7 set (bit 6 is LBA), bit 4 clear (master), the
/// LBA's top nibble in bits 0-3.
pub(super) const DEVICE_LBA_MASTER: u8 = 0xE0;

/// Bytes per sector.
pub const SECTOR_SIZE: usize = 512;

/// The first sector LBA28 cannot address.
pub const LBA28_LIMIT: u64 = 1 << 28;

/// The most sectors one LBA28 command moves (a count register of 0).
pub const MAX_SECTORS_PER_COMMAND: u32 = 256;

/// The DRQ block bring-up asks for, in sectors, when the drive allows it (Windows 2000's atapi
/// asks for 16).
pub const PREFERRED_MULTIPLE: u8 = 16;

/// Alternate-status reads before a poll gives up: far beyond any settle time, short enough that a
/// wedged device fails the request instead of hanging the caller.
pub const POLL_BOUND: u32 = 100_000;

/// The completion waits (about a second each in the kernel) a cache flush is given before it fails
/// as timed out: a drive may take tens of seconds to write a large cache out, where a sector's
/// transfer takes one wait.
pub const FLUSH_WAITS: u32 = 30;

// The bus master's registers (the PCI IDE controller's BAR 4, eight ports per channel; Intel's
// PIIX and the SFF-8038i layout every PCI IDE controller follows).
/// Bus master command: bit 0 starts the engine, bit 3 sets the direction.
pub const BM_COMMAND: u16 = 0;
/// Bus master status: bit 0 active, bit 1 error, bit 2 interrupt (bits 1 and 2 clear when written
/// as ones), bits 5-6 the drives' DMA-capable flags (firmware's, kept as read).
pub const BM_STATUS: u16 = 2;
/// The physical address of the descriptor table (a dword, 4-byte aligned).
pub const BM_TABLE: u16 = 4;
/// Command bit 0: start (set) or stop (clear) the engine.
pub const BM_START: u8 = 0x01;
/// Command bit 3: the transfer writes memory (a device read); clear, it reads memory.
pub const BM_TO_MEMORY: u8 = 0x08;
/// Status bit 0: the engine is moving data.
pub const BM_ACTIVE: u8 = 0x01;
/// Status bit 1: the transfer failed on the bus.
pub const BM_ERROR: u8 = 0x02;
/// Status bit 2: the drive raised its interrupt.
pub const BM_INTERRUPT: u8 = 0x04;
