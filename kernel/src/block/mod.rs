//! Block devices: the description and read contract every storage device implements, partition
//! views over them, and the registry the boot fills.
//!
//! Everything that stores sectors — the IDE disk today; later CD media, SATA, NVMe, USB — sits
//! behind [`BlockDevice`], so the consumers (the partition walk now, the filesystems and the file
//! API later) never know which controller holds the data. The layer's pieces: partition views
//! ([`partition`]), the device registry the boot fills ([`registry`]), the per-device lock that
//! queues concurrent readers ([`lock`]), and an in-memory device for the host tests ([`memory`]).
//! The description carries what the Windows device queries will report (drive type, size,
//! removable, read-only, the bus); the internal shape is the kernel's own.
//!
//! The read contract, for every device:
//!
//! - the buffer holds whole sectors (anything else is a contract violation: panic),
//! - a run that leaves the device fails with `STATUS_INVALID_PARAMETER` before any I/O,
//! - device failures surface as the device's NT status,
//! - the caller blocks until the transfer completes.

pub mod lock;
#[cfg(test)]
pub mod memory;
pub mod partition;
pub mod registry;

use crate::status::{NtStatus, STATUS_INVALID_PARAMETER};

/// What kind of device it is (the Windows drive type follows from it).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DeviceKind {
    /// A fixed or removable disk.
    Disk,
}

/// The bus a device sits on (what the storage property query reports).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BusType {
    /// A parallel ATA (IDE) disk.
    Ata,
    /// A device with no hardware behind it: memory.
    #[cfg(test)]
    Virtual,
}

/// What a device reports about itself.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DeviceInfo {
    pub kind: DeviceKind,
    pub bus: BusType,
    /// Bytes per sector: 512 for disks.
    pub sector_size: u32,
    /// Sectors on the device.
    pub sectors: u64,
    pub removable: bool,
    pub read_only: bool,
}

/// A device that stores sectors.
///
/// Devices are shared statics, so `read` takes `&self`; each device serializes its own requests.
pub trait BlockDevice: Sync {
    /// What the device reports about itself.
    fn info(&self) -> DeviceInfo;

    /// Read `buffer.len() / sector_size` sectors starting at `lba` into `buffer`, blocking until
    /// the transfer completes. Returns an NT status (see the module's read contract).
    #[must_use]
    fn read(&self, lba: u64, buffer: &mut [u8]) -> NtStatus;

    /// Write `buffer.len() / sector_size` sectors starting at `lba` from `buffer`, blocking until
    /// the transfer completes. A device that takes no writes refuses them (the default).
    #[must_use]
    fn write(&self, lba: u64, buffer: &[u8]) -> NtStatus {
        let _ = (lba, buffer);
        crate::status::STATUS_MEDIA_WRITE_PROTECTED
    }
}

/// The checks every device's `read` starts with: the buffer holds whole sectors (a contract
/// violation otherwise), and the run stays on the device. Returns the run's length in sectors, or
/// the status that refuses it.
pub fn check_request(info: &DeviceInfo, lba: u64, buffer: &[u8]) -> Result<u64, NtStatus> {
    let size = info.sector_size as usize;
    assert!(
        !buffer.is_empty() && buffer.len() % size == 0,
        "a block read moves whole sectors"
    );
    let sectors = (buffer.len() / size) as u64;
    match lba.checked_add(sectors) {
        Some(end) if end <= info.sectors => Ok(sectors),
        _ => Err(STATUS_INVALID_PARAMETER),
    }
}

#[cfg(test)]
mod tests {
    use super::memory::MemoryDisk;
    use super::*;
    use crate::status::STATUS_SUCCESS;

    /// A read returns the device's bytes at the run's offset.
    #[test]
    fn a_read_returns_the_run() {
        let disk = MemoryDisk::patterned(64);
        let mut buffer = vec![0u8; 3 * 512];
        assert_eq!(disk.read(10, &mut buffer), STATUS_SUCCESS);
        assert_eq!(buffer, MemoryDisk::pattern_of(10, 3));
    }

    /// A run that leaves the device is refused before any I/O — including one whose end
    /// overflows the LBA space.
    #[test]
    fn a_run_off_the_device_is_refused() {
        let disk = MemoryDisk::patterned(64);
        let info = disk.info();
        let mut buffer = vec![0xAAu8; 2 * 512];
        assert_eq!(check_request(&info, 62, &buffer), Ok(2));
        assert_eq!(
            check_request(&info, 63, &buffer),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(
            check_request(&info, u64::MAX, &buffer),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(disk.read(63, &mut buffer), STATUS_INVALID_PARAMETER);
        assert!(buffer.iter().all(|&byte| byte == 0xAA), "nothing was read");
    }

    #[test]
    #[should_panic(expected = "whole sectors")]
    fn a_partial_sector_buffer_is_a_contract_violation() {
        let disk = MemoryDisk::patterned(64);
        let _ = disk.read(0, &mut [0u8; 100]);
    }

    #[test]
    #[should_panic(expected = "whole sectors")]
    fn an_empty_buffer_is_a_contract_violation() {
        let disk = MemoryDisk::patterned(64);
        let _ = disk.read(0, &mut []);
    }
}
