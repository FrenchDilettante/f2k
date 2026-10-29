//! The device registry: the table of block devices, and the boot-time scan that registers a disk
//! and a partition view per primary MBR entry.
//!
//! The table is fixed-size, built by the boot's scan, then frozen: devices are statics, and each
//! partition view lives in its own entry. A device's index is its stable identity ([`DeviceId`]);
//! names and drive letters come with the object namespace and will map onto it.

use rtl::array_vec::ArrayVec;

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

/// Where a registered device lives: a static of its driver's, or the entry itself (a partition
/// view).
#[derive(Clone, Copy)]
enum DeviceRef {
    Static(&'static dyn BlockDevice),
    Partition(Partition),
    /// The filler the table keeps past its length, never read through it.
    Vacant,
}

/// One registered device.
#[derive(Clone, Copy)]
pub struct Entry {
    device: DeviceRef,
    pub role: Role,
}

/// The filler the table's array keeps past its length (see [`ArrayVec`]): never read.
impl Default for Entry {
    fn default() -> Self {
        Entry {
            device: DeviceRef::Vacant,
            role: Role::Disk,
        }
    }
}

impl Entry {
    /// The device, for as long as the entry is borrowed (for good, from the kernel's frozen
    /// table).
    pub fn device(&self) -> &dyn BlockDevice {
        match &self.device {
            DeviceRef::Static(device) => *device,
            DeviceRef::Partition(partition) => partition,
            DeviceRef::Vacant => unreachable!("a vacant entry is never read"),
        }
    }
}

/// The device table.
#[derive(Default)]
pub struct Registry {
    entries: ArrayVec<Entry, CAPACITY>,
}

impl Registry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a device; its id is its position. The table is sized at build time, so running out is
    /// a kernel configuration fault.
    fn add(&mut self, device: DeviceRef, role: Role) -> DeviceId {
        let id = DeviceId(self.entries.len());
        if self.entries.try_push(Entry { device, role }).is_err() {
            panic!("the block device table is full");
        }
        id
    }

    /// Add a device that is a static of its driver's.
    pub fn register(&mut self, device: &'static dyn BlockDevice, role: Role) -> DeviceId {
        self.add(DeviceRef::Static(device), role)
    }

    pub fn get(&self, id: DeviceId) -> Option<&Entry> {
        self.entries.get(id.0)
    }

    /// The registered devices, in registration order.
    pub fn iter(&self) -> impl Iterator<Item = (DeviceId, &Entry)> + '_ {
        self.entries
            .iter()
            .enumerate()
            .map(|(index, entry)| (DeviceId(index), entry))
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

/// Register `disk`, walk its MBR, and register a partition view per primary entry. A disk whose
/// table cannot be read or is refused is still registered, with no partitions.
pub fn scan(registry: &mut Registry, disk: &'static dyn BlockDevice) -> (DeviceId, Scan) {
    let id = registry.register(disk, Role::Disk);
    let info = disk.info();
    if info.kind != DeviceKind::Disk || info.sector_size != 512 {
        return (id, Scan::NotPartitioned);
    }
    let mut sector = [0u8; 512];
    if let Err(status) = disk.read(0, &mut sector) {
        return (id, Scan::ReadFailed(status));
    }
    let entries = match walk_mbr(&sector, info.sectors) {
        Ok(entries) => entries,
        Err(error) => return (id, Scan::Refused(error)),
    };
    let mut registered = 0;
    for entry in entries.into_iter().flatten() {
        registry.add(
            DeviceRef::Partition(Partition::new(disk, entry)),
            Role::Partition { disk: id, entry },
        );
        registered += 1;
    }
    (id, Scan::Partitions(registered))
}

// --- The kernel's registry (target) ------------------------------------------------------------

#[cfg(target_arch = "x86")]
mod target {
    use super::*;
    use crate::sync::InitOnce;

    /// The kernel's device table, frozen once the boot's scan has built it.
    static REGISTRY: InitOnce<Registry> = InitOnce::new();

    /// Build the kernel's device table from the disks the boot found, each registered with its
    /// partitions, and freeze it. Boot context, once, before any reader.
    pub fn boot_scan(disks: impl IntoIterator<Item = &'static dyn BlockDevice>) {
        let mut registry = Registry::new();
        for disk in disks {
            scan(&mut registry, disk);
        }
        REGISTRY.set(registry);
    }

    /// The kernel's device table.
    pub fn registry() -> &'static Registry {
        REGISTRY.get()
    }
}

#[cfg(target_arch = "x86")]
#[allow(unused_imports)]
pub use target::{boot_scan, registry};

#[cfg(test)]
mod tests {
    use super::super::memory::MemoryDisk;
    use super::super::partition::mbr;
    use super::*;
    use crate::status::STATUS_INVALID_PARAMETER;

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

    /// An MBR with the given entries (slot, type, start, length), none bootable.
    fn table(entries: &[(usize, u8, u32, u32)]) -> [u8; 512] {
        let entries: Vec<_> = entries
            .iter()
            .map(|&(slot, kind, start, sectors)| (slot, 0, kind, start, sectors))
            .collect();
        mbr(&entries)
    }

    /// The scan registers the disk, then one view per primary entry in slot order, each tagged
    /// with its disk and entry — and the views read the disk at their offsets.
    #[test]
    fn a_scan_registers_the_disk_then_its_partitions() {
        let disk = disk_with(table(&[(0, 0x0C, 10, 20), (2, 0x07, 40, 8)]), 64);
        let mut registry = Registry::new();
        let (id, scan_result) = scan(&mut registry, disk);
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
        let second = registry.get(DeviceId(2)).unwrap().device();
        assert_eq!(second.info().sectors, 8);
        let mut sector = [0u8; 512];
        assert_eq!(second.read(0, &mut sector), Ok(()));
        assert!(sector.iter().all(|&byte| byte == 39), "disk sector 40");
        assert_eq!(second.read(8, &mut sector), Err(STATUS_INVALID_PARAMETER));
    }

    /// A refused table or an unreadable sector 0 still registers the disk, with no partitions.
    #[test]
    fn a_bad_table_leaves_the_disk_unpartitioned() {
        let mut registry = Registry::new();
        let unsigned = disk_with([0u8; 512], 64);
        assert_eq!(
            scan(&mut registry, unsigned),
            (DeviceId(0), Scan::Refused(MbrError::NoSignature))
        );
        let overrunning = disk_with(table(&[(1, 0x0C, 10, 100)]), 64);
        assert_eq!(
            scan(&mut registry, overrunning),
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
        assert_eq!(
            registry.get(DeviceId(1)).unwrap().device().info().sectors,
            8
        );
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
