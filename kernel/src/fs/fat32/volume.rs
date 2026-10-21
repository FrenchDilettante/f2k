//! A mounted FAT32 volume: the mount over a block device, its layout, the FAT entry lookup and
//! update, sector writes, and the volume's dirty mark — and the kernel's boot volume, mounted from
//! the first registered partition.
//!
//! Every change goes through [`Volume::set_fat_entry`] or [`Volume::write_sector`], and the first
//! one after the mount (or after [`Volume::mark_clean`]) is preceded by the dirty mark: FAT[1]'s
//! [`CLEAN_SHUTDOWN`] bit cleared in every FAT copy, as FastFat marks a volume it is changing.

use super::boot_sector::{validate, Refusal};
use super::fat::{decode_entry, entry_position, FatCache, FatEntry, ENTRY_MASK};
use super::layout::Layout;
use crate::block::BlockDevice;
use crate::status::{nt_success, NtStatus, STATUS_UNRECOGNIZED_VOLUME};

/// FAT[1]'s clean-shutdown bit: set while the volume on disk is consistent, clear (dirty) from a
/// writer's first change until it marks the volume clean again — a volume found dirty gets a check
/// at its next mount on Windows. Its neighbour, 0x0400_0000, is the hard-error bit (set: no error),
/// which writes leave alone.
pub const CLEAN_SHUTDOWN: u32 = 0x0800_0000;

/// Why a device did not mount.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MountError {
    /// The device's sectors are not 512 bytes, the only size FAT32 has.
    DeviceSectorSize(u32),
    /// The boot sector could not be read.
    Read(NtStatus),
    /// The boot sector failed a gate.
    Refused(Refusal),
}

impl MountError {
    /// The NT status the failure reports: the read's own, or an unrecognized volume.
    pub fn status(&self) -> NtStatus {
        match *self {
            MountError::Read(status) => status,
            MountError::DeviceSectorSize(_) | MountError::Refused(_) => STATUS_UNRECOGNIZED_VOLUME,
        }
    }
}

/// A mounted FAT32 volume.
pub struct Volume {
    device: &'static dyn BlockDevice,
    layout: Layout,
    cache: FatCache,
    /// Where the next free-cluster search starts (an allocation's hint).
    next_free: u32,
    /// Whether this mount has marked the volume dirty since it was mounted or last marked clean.
    dirty: bool,
}

impl Volume {
    /// Mount `device` (a partition, or any 512-byte-sector device holding a volume): read its boot
    /// sector, run the gate list, and compute the layout.
    pub fn mount(device: &'static dyn BlockDevice) -> Result<Volume, MountError> {
        let sector_size = device.info().sector_size;
        if sector_size != 512 {
            return Err(MountError::DeviceSectorSize(sector_size));
        }
        let mut sector = [0u8; 512];
        let status = device.read(0, &mut sector);
        if !nt_success(status) {
            return Err(MountError::Read(status));
        }
        let layout = validate(&sector).map_err(MountError::Refused)?;
        Ok(Volume {
            device,
            layout,
            cache: FatCache::new(),
            next_free: 2,
            dirty: false,
        })
    }

    /// The volume's geometry.
    pub fn layout(&self) -> &Layout {
        &self.layout
    }

    /// The device the volume lives on (its sector 0 is the boot sector).
    pub fn device(&self) -> &'static dyn BlockDevice {
        self.device
    }

    /// The FAT entry of `cluster`, which must be a data cluster of the volume (callers validate
    /// clusters they read off the volume; the entries this returns are validated already). Reads
    /// through the FAT sector cache, blocking on the device on a miss.
    pub fn fat_entry(&mut self, cluster: u32) -> Result<FatEntry, NtStatus> {
        assert!(
            self.layout.is_data_cluster(cluster),
            "cluster {} is not a data cluster of the volume",
            cluster
        );
        let (sector, offset) = entry_position(cluster);
        let data = self
            .cache
            .sector(self.device, self.layout.fat_start + sector)?;
        let raw = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);
        Ok(decode_entry(raw, self.layout.max_cluster()))
    }

    /// How many FAT copies the volume keeps (every one is written).
    pub fn fat_copies(&self) -> u32 {
        ((self.layout.data_start - self.layout.fat_start) / self.layout.sectors_per_fat as u64)
            as u32
    }

    /// Set `cluster`'s FAT entry to `value` (its low 28 bits; the reserved high bits stay), in
    /// every FAT copy and the cache.
    pub fn set_fat_entry(&mut self, cluster: u32, value: u32) -> Result<(), NtStatus> {
        assert!(
            self.layout.is_data_cluster(cluster),
            "cluster {} is not a data cluster of the volume",
            cluster
        );
        self.changing()?;
        let (sector, offset) = entry_position(cluster);
        self.patch_fat(sector, offset, |old| old & !ENTRY_MASK | value & ENTRY_MASK)
    }

    /// Rewrite the raw 32-bit FAT entry at `offset` of FAT sector `sector` through `update`, in
    /// every FAT copy and the cache (nothing is written when it stays the same).
    fn patch_fat(
        &mut self,
        sector: u64,
        offset: usize,
        update: impl FnOnce(u32) -> u32,
    ) -> Result<(), NtStatus> {
        let lba = self.layout.fat_start + sector;
        let mut data = *self.cache.sector(self.device, lba)?;
        let old = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);
        let raw = update(old);
        if raw == old {
            return Ok(());
        }
        data[offset..offset + 4].copy_from_slice(&raw.to_le_bytes());
        for copy in 0..self.fat_copies() as u64 {
            self.write_raw(lba + copy * self.layout.sectors_per_fat as u64, &data)?;
        }
        self.cache.store(lba, &data);
        Ok(())
    }

    /// Before a change: the dirty mark, when this mount has not made it yet.
    fn changing(&mut self) -> Result<(), NtStatus> {
        if !self.dirty {
            self.patch_fat(0, 4, |old| old & !CLEAN_SHUTDOWN)?;
            self.dirty = true;
        }
        Ok(())
    }

    /// Mark the volume clean (FAT[1]'s [`CLEAN_SHUTDOWN`] bit set again), once its changes are all
    /// on disk; the next change marks it dirty first. Nothing calls it yet: F2K has no unmount or
    /// flush of its own, so a volume it changed stays marked dirty.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn mark_clean(&mut self) -> Result<(), NtStatus> {
        if self.dirty {
            self.patch_fat(0, 4, |old| old | CLEAN_SHUTDOWN)?;
            self.dirty = false;
        }
        Ok(())
    }

    /// Read one sector of the volume.
    pub fn read_sector(&self, lba: u64, data: &mut [u8; 512]) -> Result<(), NtStatus> {
        let status = self.device.read(lba, data);
        if nt_success(status) {
            Ok(())
        } else {
            Err(status)
        }
    }

    /// Write one sector of the volume (a change: the dirty mark goes first).
    pub fn write_sector(&mut self, lba: u64, data: &[u8; 512]) -> Result<(), NtStatus> {
        self.changing()?;
        self.write_raw(lba, data)
    }

    fn write_raw(&self, lba: u64, data: &[u8; 512]) -> Result<(), NtStatus> {
        let status = self.device.write(lba, data);
        if nt_success(status) {
            Ok(())
        } else {
            Err(status)
        }
    }

    /// Where the next free-cluster search starts, and its update.
    pub fn next_free(&self) -> u32 {
        self.next_free
    }

    pub fn set_next_free(&mut self, cluster: u32) {
        self.next_free = cluster;
    }
}

// --- The boot volume (target) ------------------------------------------------------------------

#[cfg(target_arch = "x86")]
mod target {
    use core::ptr::addr_of_mut;

    use super::*;
    use crate::block::lock::DeviceLock;
    use crate::block::registry::{registry, Role};

    /// The boot's mount: none on a boot with no partition, else the outcome.
    static mut MOUNT: Option<Result<Volume, MountError>> = None;
    /// Serializes the volume's users (its FAT cache is shared state).
    static LOCK: DeviceLock = DeviceLock::new();

    /// Mount the first partition the registry holds. Boot context, after the block-device scan;
    /// silent — a boot without a volume is normal, and a refused one is left unmounted.
    pub fn mount_boot_volume() {
        LOCK.init();
        let partition = registry()
            .iter()
            .find(|(_, entry)| matches!(entry.role, Role::Partition { .. }));
        if let Some((_, entry)) = partition {
            // SAFETY: boot context, before any user of the volume.
            unsafe { *addr_of_mut!(MOUNT) = Some(Volume::mount(entry.device)) };
        }
    }

    /// How the boot's mount went: none when there was nothing to mount.
    pub fn boot_mount() -> Option<Result<(), MountError>> {
        // SAFETY: written once at boot, before any reader.
        let mount = unsafe { (*addr_of_mut!(MOUNT)).as_ref() };
        mount.map(|mount| mount.as_ref().map(|_| ()).map_err(|error| *error))
    }

    /// Run `body` on the boot volume, serialized against its other users; none when no volume is
    /// mounted. The whole use — the lock and the drive's commands under it — is one critical region
    /// of the running thread: a suspend or a termination waits until the volume is released.
    pub fn with_boot_volume<R>(body: impl FnOnce(&mut Volume) -> R) -> Option<R> {
        crate::process::threads::critical_region(|| {
            LOCK.with(|| {
                // SAFETY: the lock makes this the only user of the volume.
                let mount = unsafe { &mut *addr_of_mut!(MOUNT) };
                match mount {
                    Some(Ok(volume)) => Some(body(volume)),
                    _ => None,
                }
            })
        })
    }
}

#[cfg(target_arch = "x86")]
#[allow(unused_imports)]
pub use target::{boot_mount, mount_boot_volume, with_boot_volume};

#[cfg(test)]
mod tests {
    use super::super::fixtures::{built_layout, built_volume, Counting, Crafted, Crashing, BUILT};
    use super::*;
    use crate::block::memory::MemoryDisk;
    use crate::status::STATUS_IO_DEVICE_ERROR;

    /// The built volume's real boot sector mounts, with the built layout.
    #[test]
    fn the_built_volume_mounts() {
        let volume = Volume::mount(built_volume(2)).unwrap();
        assert_eq!(*volume.layout(), built_layout());
    }

    /// The facts of the built volume's FAT: the root directory (cluster 2) ends at once; the first
    /// file runs 3 -> 4 -> ... -> 58 and ends there; the next free cluster is free.
    #[test]
    fn the_built_volume_chains() {
        let mut volume = Volume::mount(built_volume(2)).unwrap();
        assert_eq!(volume.fat_entry(2), Ok(FatEntry::EndOfChain));
        assert_eq!(volume.fat_entry(3), Ok(FatEntry::Next(4)));
        assert_eq!(volume.fat_entry(57), Ok(FatEntry::Next(58)));
        assert_eq!(volume.fat_entry(58), Ok(FatEntry::EndOfChain));
        assert_eq!(volume.fat_entry(59), Ok(FatEntry::Free));
        assert_eq!(volume.fat_entry(128), Ok(FatEntry::Next(129)));
    }

    /// Lookups in one FAT sector read the device once: the mount reads the boot sector, the first
    /// lookup its FAT sector, and the second lookup — the same sector — nothing. A lookup in the
    /// next FAT sector reads that one.
    #[test]
    fn lookups_in_one_fat_sector_read_it_once() {
        let device = Counting::over(built_volume(2));
        let mut volume = Volume::mount(device).unwrap();
        assert_eq!(device.reads(), 1, "the boot sector");
        assert_eq!(volume.fat_entry(3), Ok(FatEntry::Next(4)));
        assert_eq!(device.reads(), 2, "the FAT sector");
        assert_eq!(volume.fat_entry(2), Ok(FatEntry::EndOfChain));
        assert_eq!(device.reads(), 2, "a cache hit");
        assert_eq!(volume.fat_entry(128), Ok(FatEntry::Next(129)));
        assert_eq!(device.reads(), 3, "the next FAT sector");
    }

    /// A refused boot sector, an unreadable one, and a device with other sector sizes do not
    /// mount — each reported as itself, with the status it maps to.
    #[test]
    fn failed_mounts_report_why() {
        let mut unsigned = *BUILT;
        unsigned[510] = 0;
        let image: &'static [u8] = Box::leak(Box::new(unsigned));
        let refused = Volume::mount(Box::leak(Box::new(MemoryDisk::new(image)))).err();
        assert_eq!(
            refused,
            Some(MountError::Refused(Refusal::NoSignature(0xAA00)))
        );
        assert_eq!(refused.unwrap().status(), STATUS_UNRECOGNIZED_VOLUME);

        let failing = Counting::over(built_volume(1));
        failing.fail(true);
        let unread = Volume::mount(failing).err();
        assert_eq!(unread, Some(MountError::Read(STATUS_IO_DEVICE_ERROR)));
        assert_eq!(unread.unwrap().status(), STATUS_IO_DEVICE_ERROR);
    }

    /// A device whose sectors are not 512 bytes is refused before anything is read.
    #[test]
    fn a_device_with_other_sectors_is_refused_unread() {
        struct Optical(&'static Counting);
        impl BlockDevice for Optical {
            fn info(&self) -> crate::block::DeviceInfo {
                crate::block::DeviceInfo {
                    sector_size: 2048,
                    ..self.0.info()
                }
            }

            fn read(&self, lba: u64, buffer: &mut [u8]) -> NtStatus {
                self.0.read(lba, buffer)
            }
        }
        let inner = Counting::over(built_volume(1));
        let optical: &'static Optical = Box::leak(Box::new(Optical(inner)));
        let refused = Volume::mount(optical).err();
        assert_eq!(refused, Some(MountError::DeviceSectorSize(2048)));
        assert_eq!(refused.unwrap().status(), STATUS_UNRECOGNIZED_VOLUME);
        assert_eq!(inner.reads(), 0);
    }

    /// A FAT read failure surfaces as the device's status and caches nothing.
    #[test]
    fn a_failed_fat_read_reports_the_device_status() {
        let device = Counting::over(built_volume(1));
        let mut volume = Volume::mount(device).unwrap();
        device.fail(true);
        assert_eq!(volume.fat_entry(3), Err(STATUS_IO_DEVICE_ERROR));
        device.fail(false);
        assert_eq!(volume.fat_entry(3), Ok(FatEntry::Next(4)));
    }

    /// FAT[1]'s clean-shutdown bit. The volume is marked dirty before its first change
    /// after the mount — a crash after one write leaves the mark, not the change — and once: later
    /// changes are their own writes alone, and a FAT change in FAT[1]'s own sector keeps the mark.
    /// Marking it clean sets the bit back, and the next change clears it again. The hard-error bit
    /// stays set (no error) throughout.
    #[test]
    fn a_change_marks_the_volume_dirty_first() {
        let crashing = Crashing::over(Crafted::new(1, 8).writable());
        let mut volume = Volume::mount(crashing).unwrap();
        let fat1 = || {
            let image = crashing.image().image();
            u32::from_le_bytes([image[516], image[517], image[518], image[519]])
        };
        let clean = |raw: u32| raw & CLEAN_SHUTDOWN != 0;
        assert!(clean(fat1()), "mounted clean");
        let data = volume.layout().cluster_lba(3);
        crashing.crash_after(1);
        volume.write_sector(data, &[0xAB; 512]).unwrap();
        assert!(!clean(fat1()), "the mark came first");
        assert_eq!(
            crashing.image().image()[data as usize * 512],
            0,
            "and the change after it"
        );

        crashing.crash_after(u32::MAX);
        let before = crashing.written();
        volume.write_sector(data, &[0xAB; 512]).unwrap();
        volume.set_fat_entry(3, 0x0FFF_FFFF).unwrap();
        assert_eq!(crashing.written() - before, 2, "no second mark");
        assert!(!clean(fat1()));
        assert_eq!(volume.fat_entry(3), Ok(FatEntry::EndOfChain));

        volume.mark_clean().unwrap();
        assert!(clean(fat1()));
        volume.set_fat_entry(4, 0x0FFF_FFFF).unwrap();
        assert!(!clean(fat1()), "dirty again");
        assert_eq!(fat1() & 0x0400_0000, 0x0400_0000, "no hard error");
    }

    #[test]
    #[should_panic(expected = "not a data cluster")]
    fn the_reserved_entries_are_not_lookups() {
        let mut volume = Volume::mount(built_volume(1)).unwrap();
        let _ = volume.fat_entry(1);
    }
}
