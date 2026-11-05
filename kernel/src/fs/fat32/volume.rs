//! A mounted FAT32 volume: the mount over a block device, its layout, the FAT entry lookup and
//! update, sector writes, and the volume's dirty mark — and the kernel's boot volume, mounted from
//! the first registered partition.
//!
//! Every change goes through [`Volume::set_fat_entry`] or [`Volume::write_sector`], and the first
//! one after the mount (or after [`Volume::mark_clean`]) is preceded by the dirty mark: FAT[1]'s
//! [`CLEAN_SHUTDOWN`] bit cleared in every FAT copy, as FastFat marks a volume it is changing. With
//! the mark, FSInfo's two hints become unknown (0xFFFFFFFF), so a volume left dirty never carries
//! a stale count; the shutdown's flush ([`Volume::flush`]) writes the counted ones back before it
//! marks the volume clean.
//!
//! The volume keeps its free-cluster count once it has one ([`Volume::free_clusters`]): FSInfo's
//! on a volume marked clean, else a FAT scan's, then kept in step with every FAT change.
//!
//! The shutdown closes the volume to changes ([`Volume::close`]): every change after it is refused
//! with STATUS_TOO_LATE, the status NT documents for a write to a volume after its dismount, before
//! anything is written (the dirty mark included), so the volume stays as the flush left it. Its
//! users hold the volume's lock across each whole operation, so a writer under way when the
//! shutdown comes finishes first, and the next one finds the volume closed.

use rtl::pod::Pod;

use super::boot_sector::{validate, Refusal};
use super::fat::{
    decode_entry,
    entry_position,
    FatCache,
    FatEntry,
    ENTRIES_PER_SECTOR,
    ENTRY_MASK,
};
use super::fsinfo::{FsInfo, UNKNOWN};
use super::layout::Layout;
use super::raw::to_block;
use crate::block::BlockDevice;
use crate::status::{NtStatus, STATUS_TOO_LATE, STATUS_UNRECOGNIZED_VOLUME};

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
    /// The free clusters, once counted (or read from FSInfo), kept in step with the FAT's changes.
    free: Option<u32>,
    /// Whether the shutdown has closed the volume to changes.
    closed: bool,
    /// The FSInfo sector while it is read and rewritten: the volume's own buffer, so the update
    /// takes no sector-sized frame on the stack of the service whose change triggers it.
    fsinfo: FsInfo,
}

/// What a FAT scan found: the free clusters, and the first free one at or after the allocator's
/// hint (wrapping to the volume's first free cluster; none on a full volume).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct FreeClusters {
    pub count: u32,
    pub next_free: Option<u32>,
}

/// What the flush did.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Flushed {
    /// FSInfo carries the scan's count and hint, and the volume is marked clean.
    Clean(FreeClusters),
    /// This mount never changed the volume: nothing to write (a volume found dirty at the mount
    /// stays dirty, for the check its mark asks for).
    Unchanged,
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
        device.read(0, &mut sector).map_err(MountError::Read)?;
        let layout = validate(&sector).map_err(MountError::Refused)?;
        Ok(Volume {
            device,
            layout,
            cache: FatCache::new(),
            next_free: 2,
            dirty: false,
            free: None,
            closed: false,
            fsinfo: FsInfo::zeroed(),
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
        let (sector, index) = entry_position(cluster);
        let data = self
            .cache
            .sector(self.device, self.layout.fat_start + sector)?;
        Ok(decode_entry(data[index].get(), self.layout.max_cluster()))
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
        let (sector, index) = entry_position(cluster);
        let old = self.patch_fat(sector, index, |old| old & !ENTRY_MASK | value & ENTRY_MASK)?;
        if let Some(free) = self.free.as_mut() {
            match (old & ENTRY_MASK == 0, value & ENTRY_MASK == 0) {
                (true, false) => *free = free.saturating_sub(1),
                (false, true) => *free += 1,
                _ => {}
            }
        }
        Ok(())
    }

    /// Rewrite the raw 32-bit FAT entry `index` of FAT sector `sector` through `update`, in every
    /// FAT copy and the cache (nothing is written when it stays the same): the entry as it was.
    fn patch_fat(
        &mut self,
        sector: u64,
        index: usize,
        update: impl FnOnce(u32) -> u32,
    ) -> Result<u32, NtStatus> {
        let lba = self.layout.fat_start + sector;
        let mut data = *self.cache.sector(self.device, lba)?;
        let old = data[index].get();
        let raw = update(old);
        if raw == old {
            return Ok(old);
        }
        data[index].set(raw);
        let bytes = to_block(&data);
        for copy in 0..self.fat_copies() as u64 {
            self.write_raw(lba + copy * self.layout.sectors_per_fat as u64, &bytes)?;
        }
        self.cache.store(lba, &data);
        Ok(old)
    }

    /// Before a change: refused once the volume is closed; else the dirty mark, when this mount
    /// has not made it yet, and FSInfo's hints made unknown with it.
    fn changing(&mut self) -> Result<(), NtStatus> {
        if self.closed {
            return Err(STATUS_TOO_LATE);
        }
        if !self.dirty {
            self.patch_fat(0, 1, |old| old & !CLEAN_SHUTDOWN)?;
            self.dirty = true;
            self.write_fsinfo(UNKNOWN, UNKNOWN)?;
        }
        Ok(())
    }

    /// Mark the volume clean (FAT[1]'s [`CLEAN_SHUTDOWN`] bit set again), once its changes are all
    /// on disk; the next change marks it dirty first.
    pub fn mark_clean(&mut self) -> Result<(), NtStatus> {
        if self.dirty {
            self.patch_fat(0, 1, |old| old | CLEAN_SHUTDOWN)?;
            self.dirty = false;
        }
        Ok(())
    }

    /// Close the volume to changes: every later change is refused with STATUS_TOO_LATE (see the
    /// module's documentation). The flush still writes.
    pub fn close(&mut self) {
        self.closed = true;
    }

    /// Flush the volume for the shutdown: when this mount changed it, count its free clusters with
    /// a FAT scan, write the count and the next-free hint to FSInfo (and its backup copy), then
    /// mark the volume clean. The FAT and the data are written through as they change, so nothing
    /// else waits to be written.
    pub fn flush(&mut self) -> Result<Flushed, NtStatus> {
        if !self.dirty {
            return Ok(Flushed::Unchanged);
        }
        let free = self.scan_free()?;
        self.free = Some(free.count);
        self.write_fsinfo(free.count, free.next_free.unwrap_or(UNKNOWN))?;
        self.mark_clean()?;
        Ok(Flushed::Clean(free))
    }

    /// Count the free clusters in the FAT, a FAT sector at a time through the cache: the count, and
    /// the first free cluster at or after the allocator's hint (see [`FreeClusters`]).
    pub fn scan_free(&mut self) -> Result<FreeClusters, NtStatus> {
        let max = self.layout.max_cluster();
        let hint = self.next_free.clamp(2, max);
        let (mut count, mut first, mut after_hint) = (0u32, None, None);
        for sector in 0..=max / ENTRIES_PER_SECTOR {
            let data = self
                .cache
                .sector(self.device, self.layout.fat_start + sector as u64)?;
            let base = sector * ENTRIES_PER_SECTOR;
            for (index, entry) in data.iter().enumerate() {
                let cluster = base + index as u32;
                if !(2..=max).contains(&cluster) || entry.get() & ENTRY_MASK != 0 {
                    continue;
                }
                count += 1;
                first.get_or_insert(cluster);
                if cluster >= hint {
                    after_hint.get_or_insert(cluster);
                }
            }
        }
        Ok(FreeClusters {
            count,
            next_free: after_hint.or(first),
        })
    }

    /// The volume's free clusters: the count it keeps, else FSInfo's on a volume marked clean
    /// (FAT[1]'s bit set: no change is missing from FSInfo) when the volume can have that many,
    /// else a FAT scan's; kept from then on.
    pub fn free_clusters(&mut self) -> Result<u32, NtStatus> {
        if let Some(free) = self.free {
            return Ok(free);
        }
        let fat1 = self.cache.sector(self.device, self.layout.fat_start)?[1].get();
        let mut free = None;
        if let (true, Some(lba)) = (fat1 & CLEAN_SHUTDOWN != 0, self.layout.fsinfo_sector) {
            self.device.read(lba, self.fsinfo.as_bytes_mut())?;
            if self.fsinfo.is_valid() {
                free = self.fsinfo.plausible_free_count(self.layout.cluster_count);
            }
        }
        let free = match free {
            Some(free) => free,
            None => self.scan_free()?.count,
        };
        self.free = Some(free);
        Ok(free)
    }

    /// Write FSInfo's hints, in the FSInfo sector and its backup copy, each rewritten only when it
    /// holds FSInfo's signatures (a sector without them keeps what it holds).
    fn write_fsinfo(&mut self, free_count: u32, next_free: u32) -> Result<(), NtStatus> {
        for lba in [self.layout.fsinfo_sector, self.layout.backup_fsinfo_sector]
            .into_iter()
            .flatten()
        {
            self.device.read(lba, self.fsinfo.as_bytes_mut())?;
            if !self.fsinfo.is_valid() {
                continue;
            }
            self.fsinfo.set_hints(free_count, next_free);
            self.device.write(lba, self.fsinfo.as_bytes())?;
        }
        Ok(())
    }

    /// Read one sector of the volume.
    pub fn read_sector(&self, lba: u64, data: &mut [u8; 512]) -> Result<(), NtStatus> {
        self.device.read(lba, data)
    }

    /// Write one sector of the volume (a change: the dirty mark goes first).
    pub fn write_sector(&mut self, lba: u64, data: &[u8; 512]) -> Result<(), NtStatus> {
        self.changing()?;
        self.write_raw(lba, data)
    }

    fn write_raw(&self, lba: u64, data: &[u8; 512]) -> Result<(), NtStatus> {
        self.device.write(lba, data)
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
    use super::*;
    use crate::block::lock::DeviceLock;
    use crate::block::registry::{registry, Role};

    /// The boot's mount — none on a boot with no partition, else the outcome — behind the lock
    /// that serializes the volume's users (its FAT cache is shared state).
    type Mount = Option<Result<Volume, MountError>>;
    static MOUNT: DeviceLock<Mount> = DeviceLock::new(None);

    /// Mount the first partition the registry holds. Boot context, after the block-device scan;
    /// silent — a boot without a volume is normal, and a refused one is left unmounted.
    pub fn mount_boot_volume() {
        MOUNT.init();
        let partition = registry()
            .iter()
            .find(|(_, entry)| matches!(entry.role, Role::Partition { .. }));
        if let Some((_, entry)) = partition {
            let mounted = Volume::mount(entry.device());
            with_mount(|mount| *mount = Some(mounted));
        }
    }

    /// How the boot's mount went: none when there was nothing to mount.
    pub fn boot_mount() -> Option<Result<(), MountError>> {
        with_mount(|mount| {
            mount
                .as_ref()
                .map(|mount| mount.as_ref().map(|_| ()).map_err(|error| *error))
        })
    }

    /// Run `body` on the boot volume, serialized against its other users; none when no volume is
    /// mounted.
    pub fn with_boot_volume<R>(body: impl FnOnce(&mut Volume) -> R) -> Option<R> {
        with_mount(|mount| match mount {
            Some(Ok(volume)) => Some(body(volume)),
            _ => None,
        })
    }

    /// Run `body` on the mount, holding its lock. The whole use — the lock and the drive's
    /// commands under it — is one critical region of the running thread: a suspend or a
    /// termination waits until the volume is released.
    fn with_mount<R>(body: impl FnOnce(&mut Mount) -> R) -> R {
        crate::process::threads::critical_region(|| MOUNT.with(body))
    }
}

#[cfg(target_arch = "x86")]
#[allow(unused_imports)]
pub use target::{boot_mount, mount_boot_volume, with_boot_volume};

#[cfg(test)]
mod tests {
    use super::super::fixtures::{built_layout, built_volume, Counting, Crafted, Crashing, BUILT};
    use super::*;
    use crate::block::memory::{MemoryDisk, RamDisk};
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

            fn read(&self, lba: u64, buffer: &mut [u8]) -> Result<(), NtStatus> {
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

    /// FSInfo's hints as the image holds them at `lba`: the free count and the next-free hint.
    fn hints(device: &RamDisk, lba: usize) -> (u32, u32) {
        let image = device.image();
        let word = |at: usize| {
            let at = lba * 512 + at;
            u32::from_le_bytes([image[at], image[at + 1], image[at + 2], image[at + 3]])
        };
        (word(488), word(492))
    }

    /// FAT[1] as the image holds it, on a formatted volume (the FAT at LBA 8).
    fn formatted_fat1(device: &RamDisk) -> u32 {
        let image = device.image();
        u32::from_le_bytes([
            image[8 * 512 + 4],
            image[8 * 512 + 5],
            image[8 * 512 + 6],
            image[8 * 512 + 7],
        ])
    }

    /// The first change after the mount makes FSInfo's hints unknown, in the sector and its backup
    /// copy, after the dirty mark; later changes leave them so.
    #[test]
    fn the_first_change_makes_fsinfos_hints_unknown() {
        let device = Crafted::formatted(8).writable();
        let mut volume = Volume::mount(device).unwrap();
        assert_eq!(hints(device, 1), (7, 3), "as formatted");
        assert_eq!(hints(device, 7), (7, 3));
        volume.set_fat_entry(3, 0x0FFF_FFFF).unwrap();
        assert_eq!(formatted_fat1(device) & CLEAN_SHUTDOWN, 0, "the dirty mark");
        assert_eq!(hints(device, 1), (UNKNOWN, UNKNOWN));
        assert_eq!(hints(device, 7), (UNKNOWN, UNKNOWN));
        volume.set_fat_entry(4, 0x0FFF_FFFF).unwrap();
        assert_eq!(hints(device, 1), (UNKNOWN, UNKNOWN));
    }

    /// A sector that does not carry FSInfo's signatures is never written as one: a sector named
    /// FSInfo whose lead signature is gone keeps what it holds, while the copy is still updated.
    #[test]
    fn a_sector_without_fsinfos_signatures_is_left_alone() {
        let device = Crafted::formatted(8).writable();
        device.image()[512] = 0;
        let mut volume = Volume::mount(device).unwrap();
        volume.set_fat_entry(3, 0x0FFF_FFFF).unwrap();
        assert_eq!(hints(device, 1), (7, 3), "not FSInfo: untouched");
        assert_eq!(hints(device, 7), (UNKNOWN, UNKNOWN), "the copy is");
    }

    /// The flush counts the free clusters with a FAT scan and writes the count and the first free
    /// cluster at or after the allocator's hint (wrapping to the first free one) to FSInfo and its
    /// copy, then marks the volume clean. A volume the mount never changed is left as it is.
    #[test]
    fn the_flush_writes_the_counted_hints_then_marks_the_volume_clean() {
        let device = Crafted::formatted(8).writable();
        let mut volume = Volume::mount(device).unwrap();
        assert_eq!(volume.flush(), Ok(Flushed::Unchanged));
        assert_eq!(hints(device, 1), (7, 3), "nothing written");

        for cluster in [3, 4, 9] {
            volume.set_fat_entry(cluster, 0x0FFF_FFFF).unwrap();
        }
        volume.set_next_free(9);
        let counted = FreeClusters {
            count: 4,
            next_free: Some(5),
        };
        assert_eq!(volume.scan_free(), Ok(counted), "9 is taken: wrapped to 5");
        assert_eq!(volume.flush(), Ok(Flushed::Clean(counted)));
        assert_eq!(hints(device, 1), (4, 5));
        assert_eq!(hints(device, 7), (4, 5));
        assert_ne!(formatted_fat1(device) & CLEAN_SHUTDOWN, 0, "marked clean");
        assert_eq!(volume.free_clusters(), Ok(4));

        volume.set_next_free(6);
        assert_eq!(volume.scan_free().unwrap().next_free, Some(6));
        assert_eq!(volume.flush(), Ok(Flushed::Unchanged), "clean since");
    }

    /// A full volume has no next free cluster: its hint is unknown.
    #[test]
    fn a_full_volume_has_no_next_free_hint() {
        let device = Crafted::formatted(3).writable();
        let mut volume = Volume::mount(device).unwrap();
        volume.set_fat_entry(3, 0x0FFF_FFFF).unwrap();
        volume.set_fat_entry(4, 0x0FFF_FFFF).unwrap();
        let full = FreeClusters {
            count: 0,
            next_free: None,
        };
        assert_eq!(volume.flush(), Ok(Flushed::Clean(full)));
        assert_eq!(hints(device, 1), (0, UNKNOWN));
    }

    /// Once closed, every change is refused with STATUS_TOO_LATE before anything is written, the
    /// dirty mark included; the flush still writes, and leaves the volume clean for good.
    #[test]
    fn a_closed_volume_refuses_changes() {
        let device = Crafted::formatted(8).writable();
        let mut volume = Volume::mount(device).unwrap();
        volume.close();
        assert_eq!(volume.set_fat_entry(3, 0x0FFF_FFFF), Err(STATUS_TOO_LATE));
        let data = volume.layout().cluster_lba(3);
        assert_eq!(
            volume.write_sector(data, &[0xAB; 512]),
            Err(STATUS_TOO_LATE)
        );
        assert_ne!(
            formatted_fat1(device) & CLEAN_SHUTDOWN,
            0,
            "never marked dirty"
        );
        assert_eq!(volume.fat_entry(3), Ok(FatEntry::Free));

        let device = Crafted::formatted(8).writable();
        let mut volume = Volume::mount(device).unwrap();
        volume.set_fat_entry(3, 0x0FFF_FFFF).unwrap();
        volume.close();
        assert_eq!(volume.set_fat_entry(4, 0x0FFF_FFFF), Err(STATUS_TOO_LATE));
        assert!(matches!(volume.flush(), Ok(Flushed::Clean(_))));
        assert_eq!(hints(device, 1), (6, 4));
        assert_eq!(volume.set_fat_entry(4, 0x0FFF_FFFF), Err(STATUS_TOO_LATE));
        assert_ne!(formatted_fat1(device) & CLEAN_SHUTDOWN, 0, "clean for good");
    }

    /// The free count: FSInfo's on a volume marked clean, when the volume can have that many; a
    /// FAT scan's on a dirty volume or past an implausible count; then kept in step with the FAT's
    /// changes, a cluster taken or given back.
    #[test]
    fn the_free_count_is_fsinfos_on_a_clean_volume_and_kept_in_step() {
        let formatted_with = |count: u32, clean: bool| {
            let device = Crafted::formatted(8).writable();
            let mut image = device.image();
            image[512 + 488..512 + 492].copy_from_slice(&count.to_le_bytes());
            if !clean {
                image[8 * 512 + 7] &= !0x08;
            }
            drop(image);
            device
        };
        let mut trusted = Volume::mount(formatted_with(100, true)).unwrap();
        assert_eq!(trusted.free_clusters(), Ok(100), "FSInfo's, trusted");
        trusted.set_fat_entry(3, 0x0FFF_FFFF).unwrap();
        assert_eq!(trusted.free_clusters(), Ok(99));
        trusted.set_fat_entry(3, 0x0FFF_FFF8).unwrap();
        assert_eq!(trusted.free_clusters(), Ok(99), "used to used");
        trusted.set_fat_entry(3, 0).unwrap();
        assert_eq!(trusted.free_clusters(), Ok(100));

        let mut dirty = Volume::mount(formatted_with(100, false)).unwrap();
        assert_eq!(dirty.free_clusters(), Ok(7), "a dirty volume's is scanned");
        let mut implausible = Volume::mount(formatted_with(70_000, true)).unwrap();
        assert_eq!(
            implausible.free_clusters(),
            Ok(7),
            "more than the volume holds"
        );
    }

    #[test]
    #[should_panic(expected = "not a data cluster")]
    fn the_reserved_entries_are_not_lookups() {
        let mut volume = Volume::mount(built_volume(1)).unwrap();
        let _ = volume.fat_entry(1);
    }
}
