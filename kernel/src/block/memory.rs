//! An in-memory block device for the host tests: a byte image read as 512-byte sectors.

use std::sync::{Mutex, MutexGuard};

use super::{check_request, BlockDevice, BusType, DeviceInfo, DeviceKind};
use crate::status::NtStatus;

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

    fn read(&self, lba: u64, buffer: &mut [u8]) -> Result<(), NtStatus> {
        check_request(&self.info(), lba, buffer)?;
        let start = lba as usize * 512;
        buffer.copy_from_slice(&self.bytes[start..start + buffer.len()]);
        Ok(())
    }
}

/// A writable disk over a byte image (the FAT32 write tests').
pub struct RamDisk {
    bytes: Mutex<Vec<u8>>,
}

impl RamDisk {
    /// A disk over `bytes`, which holds whole sectors.
    pub fn new(bytes: Vec<u8>) -> Self {
        assert_eq!(bytes.len() % 512, 0, "a disk image holds whole sectors");
        RamDisk {
            bytes: Mutex::new(bytes),
        }
    }

    /// The image as it stands, held until the guard is dropped.
    pub fn image(&self) -> MutexGuard<'_, Vec<u8>> {
        self.bytes.lock().unwrap()
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

    fn read(&self, lba: u64, buffer: &mut [u8]) -> Result<(), NtStatus> {
        check_request(&self.info(), lba, buffer)?;
        let start = lba as usize * 512;
        buffer.copy_from_slice(&self.image()[start..start + buffer.len()]);
        Ok(())
    }

    fn write(&self, lba: u64, buffer: &[u8]) -> Result<(), NtStatus> {
        check_request(&self.info(), lba, buffer)?;
        let start = lba as usize * 512;
        self.image()[start..start + buffer.len()].copy_from_slice(buffer);
        Ok(())
    }
}
