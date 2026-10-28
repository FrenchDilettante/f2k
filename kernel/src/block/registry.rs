//! The device registry: the table of block devices, and the boot-time scan that registers a disk
//! and a partition view per primary MBR entry.
//!
//! The table is fixed-size and filled at boot: devices are statics, partitions live in a fixed
//! pool. A device's index is its stable identity ([`DeviceId`]); names and drive letters come with
//! the object namespace and will map onto it.

use super::partition::{walk_mbr, MbrEntry, MbrError, Partition};
use super::{BlockDevice, DeviceKind};
use crate::status::NtStatus;

/// How many devices the table holds.
pub const CAPACITY: usize = 16;

/// A registered device's index in the table.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DeviceId(pub usize);

/// What a registered device is.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Role {
    /// A whole disk.
    Disk,
    /// A primary partition of a registered disk.
    Partition { disk: DeviceId, entry: MbrEntry },
}

/// One registered device.
#[derive(Clone, Copy)]
pub struct Entry {
    pub device: &'static dyn BlockDevice,
    pub role: Role,
}

/// The device table.
pub struct Registry {
    entries: [Option<Entry>; CAPACITY],
    count: usize,
}

impl Registry {
    pub const fn new() -> Self {
        Registry {
            entries: [None; CAPACITY],
            count: 0,
        }
    }

    /// Add a device; its id is its position. The table is sized at build time, so running out is
    /// a kernel configuration fault.
    pub fn register(&mut self, device: &'static dyn BlockDevice, role: Role) -> DeviceId {
        assert!(self.count < CAPACITY, "the block device table is full");
        let id = DeviceId(self.count);
        self.entries[self.count] = Some(Entry { device, role });
        self.count += 1;
        id
    }

    pub fn get(&self, id: DeviceId) -> Option<Entry> {
        self.entries.get(id.0).copied().flatten()
    }

    /// The registered devices, in registration order.
    pub fn iter(&self) -> impl Iterator<Item = (DeviceId, Entry)> + '_ {
        self.entries[..self.count]
            .iter()
            .enumerate()
            .filter_map(|(index, entry)| entry.map(|entry| (DeviceId(index), entry)))
    }
}

/// What scanning a disk found.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Scan {
    /// The table was walked: this many partitions were registered.
    Partitions(usize),
    /// Sector 0 could not be read.
    ReadFailed(NtStatus),
    /// The table was refused.
    Refused(MbrError),
    /// The device is not a 512-byte-sector disk, so it carries no MBR.
    NotPartitioned,
}

/// Register `disk`, walk its MBR, and register a partition view per primary entry. `place` gives
/// each view its permanent home. A disk whose table cannot be read or is refused is still
/// registered, with no partitions.
pub fn scan(
    registry: &mut Registry,
    disk: &'static dyn BlockDevice,
    mut place: impl FnMut(Partition) -> &'static Partition,
) -> (DeviceId, Scan) {
    let id = registry.register(disk, Role::Disk);
    let info = disk.info();
    if info.kind != DeviceKind::Disk || info.sector_size != 512 {
        return (id, Scan::NotPartitioned);
    }
    let mut sector = [0u8; 512];
    let status = disk.read(0, &mut sector);
    if !status.is_success() {
        return (id, Scan::ReadFailed(status));
    }
    let entries = match walk_mbr(&sector, info.sectors) {
        Ok(entries) => entries,
        Err(error) => return (id, Scan::Refused(error)),
    };
    let mut registered = 0;
    for entry in entries.into_iter().flatten() {
        let partition = place(Partition::new(disk, entry));
        registry.register(partition, Role::Partition { disk: id, entry });
        registered += 1;
    }
    (id, Scan::Partitions(registered))
}

// --- The kernel's registry (target) ------------------------------------------------------------

#[cfg(target_arch = "x86")]
mod target {
    use core::ptr::addr_of_mut;

    use super::*;

    static mut REGISTRY: Registry = Registry::new();
    /// The partition views' permanent homes.
    static mut POOL: [Option<Partition>; CAPACITY] = [const { None }; CAPACITY];
    static mut POOL_USED: usize = 0;

    /// Register a disk and its partitions. Boot context only, before any reader.
    pub fn scan_disk(disk: &'static dyn BlockDevice) -> (DeviceId, Scan) {
        // SAFETY: boot context: sole access to the registry and the pool, which nothing reads
        // until the scans are done.
        unsafe {
            scan(&mut *addr_of_mut!(REGISTRY), disk, |partition| {
                let pool = &mut *addr_of_mut!(POOL);
                let used = &mut *addr_of_mut!(POOL_USED);
                assert!(*used < CAPACITY, "the partition pool is full");
                pool[*used] = Some(partition);
                *used += 1;
                pool[*used - 1].as_ref().unwrap()
            })
        }
    }

    /// The kernel's device table.
    pub fn registry() -> &'static Registry {
        // SAFETY: written only by the boot-time scans, read-only after.
        unsafe { &*addr_of_mut!(REGISTRY) }
    }
}

#[cfg(target_arch = "x86")]
#[allow(unused_imports)]
pub use target::{registry, scan_disk};

#[cfg(test)]
mod tests {
    use super::super::memory::MemoryDisk;
    use super::*;
    use crate::status::{STATUS_INVALID_PARAMETER, STATUS_SUCCESS};

    fn leak(partition: Partition) -> &'static Partition {
        Box::leak(Box::new(partition))
    }

    /// A disk image of `sectors` sectors whose sector 0 is `mbr`.
    fn disk_with(mbr: [u8; 512], sectors: usize) -> &'static MemoryDisk {
        let mut image = vec![0u8; sectors * 512];
        image[..512].copy_from_slice(&mbr);
        for (index, byte) in image[512..].iter_mut().enumerate() {
            *byte = (index / 512) as u8;
        }
        Box::leak(Box::new(MemoryDisk::new(Box::leak(
            image.into_boxed_slice(),
        ))))
    }

    fn mbr(entries: &[(usize, u8, u32, u32)]) -> [u8; 512] {
        let mut sector = [0u8; 512];
        for &(slot, kind, start, sectors) in entries {
            let entry = 446 + slot * 16;
            sector[entry + 4] = kind;
            sector[entry + 8..entry + 12].copy_from_slice(&start.to_le_bytes());
            sector[entry + 12..entry + 16].copy_from_slice(&sectors.to_le_bytes());
        }
        sector[510] = 0x55;
        sector[511] = 0xAA;
        sector
    }

    /// The scan registers the disk, then one view per primary entry in slot order, each tagged
    /// with its disk and entry — and the views read the disk at their offsets.
    #[test]
    fn a_scan_registers_the_disk_then_its_partitions() {
        let disk = disk_with(mbr(&[(0, 0x0C, 10, 20), (2, 0x07, 40, 8)]), 64);
        let mut registry = Registry::new();
        let (id, scan_result) = scan(&mut registry, disk, leak);
        assert_eq!((id, scan_result), (DeviceId(0), Scan::Partitions(2)));

        let roles: Vec<Role> = registry.iter().map(|(_, entry)| entry.role).collect();
        assert_eq!(roles.len(), 3);
        assert_eq!(roles[0], Role::Disk);
        assert!(matches!(
            roles[1],
            Role::Partition { disk: DeviceId(0), entry } if entry.index == 0 && entry.start == 10
        ));
        assert!(matches!(
            roles[2],
            Role::Partition { disk: DeviceId(0), entry } if entry.index == 2 && entry.start == 40
        ));

        // The second partition's sector 0 is the disk's sector 40.
        let second = registry.get(DeviceId(2)).unwrap().device;
        assert_eq!(second.info().sectors, 8);
        let mut sector = [0u8; 512];
        assert_eq!(second.read(0, &mut sector), STATUS_SUCCESS);
        assert!(sector.iter().all(|&byte| byte == 39), "disk sector 40");
        assert_eq!(second.read(8, &mut sector), STATUS_INVALID_PARAMETER);
    }

    /// A refused table or an unreadable sector 0 still registers the disk, with no partitions.
    #[test]
    fn a_bad_table_leaves_the_disk_unpartitioned() {
        let mut registry = Registry::new();
        let unsigned = disk_with([0u8; 512], 64);
        assert_eq!(
            scan(&mut registry, unsigned, leak),
            (DeviceId(0), Scan::Refused(MbrError::NoSignature))
        );
        let overrunning = disk_with(mbr(&[(1, 0x0C, 10, 100)]), 64);
        assert_eq!(
            scan(&mut registry, overrunning, leak),
            (DeviceId(1), Scan::Refused(MbrError::Overruns(1)))
        );
        assert_eq!(registry.iter().count(), 2, "both disks, no partitions");
    }

    /// Ids are positions; a missing id is none.
    #[test]
    fn ids_are_registration_positions() {
        let mut registry = Registry::new();
        let a: &'static MemoryDisk = Box::leak(Box::new(MemoryDisk::patterned(4)));
        let b: &'static MemoryDisk = Box::leak(Box::new(MemoryDisk::patterned(8)));
        assert_eq!(registry.register(a, Role::Disk), DeviceId(0));
        assert_eq!(registry.register(b, Role::Disk), DeviceId(1));
        assert_eq!(registry.get(DeviceId(1)).unwrap().device.info().sectors, 8);
        assert!(registry.get(DeviceId(2)).is_none());
        assert!(registry.get(DeviceId(CAPACITY + 5)).is_none());
    }

    #[test]
    #[should_panic(expected = "table is full")]
    fn a_full_table_is_a_configuration_fault() {
        let mut registry = Registry::new();
        let disk: &'static MemoryDisk = Box::leak(Box::new(MemoryDisk::patterned(1)));
        for _ in 0..=CAPACITY {
            registry.register(disk, Role::Disk);
        }
    }
}
