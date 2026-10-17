//! An in-memory block device for the host tests: a byte image read as 512-byte sectors.

use super::{check_request, BlockDevice, BusType, DeviceInfo, DeviceKind};
use crate::status::{NtStatus, STATUS_SUCCESS};

/// A read-only disk over a byte image.
pub struct MemoryDisk {
    bytes: &'static [u8],
}

impl MemoryDisk {
    /// A disk over `bytes`, which holds whole sectors.
    pub fn new(bytes: &'static [u8]) -> Self {
        assert_eq!(bytes.len() % 512, 0, "a disk image holds whole sectors");
        MemoryDisk { bytes }
    }

    /// A disk of `sectors` sectors, each byte a function of its sector and offset.
    pub fn patterned(sectors: u64) -> Self {
        Self::new(Box::leak(Self::pattern_of(0, sectors).into_boxed_slice()))
    }

    /// The bytes of a patterned disk's sectors `lba..lba + sectors`.
    pub fn pattern_of(lba: u64, sectors: u64) -> Vec<u8> {
        (lba..lba + sectors)
            .flat_map(|sector| (0..512u64).map(move |offset| (sector * 31 ^ offset * 7) as u8))
            .collect()
    }
}

impl BlockDevice for MemoryDisk {
    fn info(&self) -> DeviceInfo {
        DeviceInfo {
            kind: DeviceKind::Disk,
            bus: BusType::Virtual,
            sector_size: 512,
            sectors: (self.bytes.len() / 512) as u64,
            removable: false,
            read_only: true,
        }
    }

    fn read(&self, lba: u64, buffer: &mut [u8]) -> NtStatus {
        if let Err(status) = check_request(&self.info(), lba, buffer) {
            return status;
        }
        let start = lba as usize * 512;
        buffer.copy_from_slice(&self.bytes[start..start + buffer.len()]);
        STATUS_SUCCESS
    }
}

/// A writable disk over a byte image (the FAT32 write tests'). Host tests run one thread per test,
/// each over its own disk, so the image needs no lock.
pub struct RamDisk {
    bytes: core::cell::UnsafeCell<Vec<u8>>,
}

// SAFETY: each disk is used by the one test thread that made it.
unsafe impl Sync for RamDisk {}

impl RamDisk {
    /// A disk over `bytes`, which holds whole sectors.
    pub fn new(bytes: Vec<u8>) -> Self {
        assert_eq!(bytes.len() % 512, 0, "a disk image holds whole sectors");
        RamDisk {
            bytes: core::cell::UnsafeCell::new(bytes),
        }
    }

    /// The image as it stands.
    pub fn image(&self) -> &[u8] {
        // SAFETY: see the Sync note; no write is in progress while a test reads.
        unsafe { &*self.bytes.get() }
    }
}

impl BlockDevice for RamDisk {
    fn info(&self) -> DeviceInfo {
        DeviceInfo {
            kind: DeviceKind::Disk,
            bus: BusType::Virtual,
            sector_size: 512,
            sectors: (self.image().len() / 512) as u64,
            removable: false,
            read_only: false,
        }
    }

    fn read(&self, lba: u64, buffer: &mut [u8]) -> NtStatus {
        if let Err(status) = check_request(&self.info(), lba, buffer) {
            return status;
        }
        let start = lba as usize * 512;
        buffer.copy_from_slice(&self.image()[start..start + buffer.len()]);
        STATUS_SUCCESS
    }

    fn write(&self, lba: u64, buffer: &[u8]) -> NtStatus {
        if let Err(status) = check_request(&self.info(), lba, buffer) {
            return status;
        }
        let start = lba as usize * 512;
        // SAFETY: see the Sync note.
        let bytes = unsafe { &mut *self.bytes.get() };
        bytes[start..start + buffer.len()].copy_from_slice(buffer);
        STATUS_SUCCESS
    }
}
