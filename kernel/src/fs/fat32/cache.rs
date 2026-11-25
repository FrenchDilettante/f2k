//! The volume's sector caches: the FAT sectors and the directory and partial data sectors the file
//! system reads, held in memory as Windows 2000's FastFat holds them through the cache manager (the
//! volume's FAT stream and each directory's stream), so a walk along a chain or a directory, and an
//! entry's read-modify-write, do not go to the disk each time.
//!
//! A cache is write-through: every write reaches the device first, and the cached copy of each
//! sector it covers is then brought in step; a failed write drops them (the disk's contents are no
//! longer known). So the disk always holds what the cache does, and a read straight off the device
//! (a file's whole sectors, the paging file's pages) needs no look at the cache.
//!
//! The slots' bytes live outside the volume, taken once per mount for the system's life (on target
//! from the nonpaged pool), so a [`super::volume::Volume`] stays small enough to build on a stack.
//! The least recently used slot is evicted first.

use crate::block::BlockDevice;
use crate::status::NtStatus;

/// One cached sector's bytes.
pub type Sector = [u8; 512];

#[derive(Clone, Copy)]
struct Tag {
    /// The cached sector's LBA; none for an empty slot.
    lba: Option<u64>,
    /// When the slot was last used (the cache's clock).
    used: u64,
}

/// A read-through, write-through cache of `N` sectors, least recently used evicted first.
pub struct SectorCache<const N: usize> {
    tags: [Tag; N],
    data: &'static mut [Sector],
    clock: u64,
}

impl<const N: usize> SectorCache<N> {
    /// An empty cache over fresh storage for its `N` sectors.
    pub fn new() -> Self {
        let data = storage(N);
        assert!(data.len() == N, "no memory for the volume's sector cache");
        SectorCache {
            tags: [Tag { lba: None, used: 0 }; N],
            data,
            clock: 0,
        }
    }

    fn slot_of(&self, lba: u64) -> Option<usize> {
        self.tags.iter().position(|tag| tag.lba == Some(lba))
    }

    /// The sector at `lba` on `device`: from the cache, or read into the least recently used slot.
    /// A failed read caches nothing.
    pub fn sector(&mut self, device: &dyn BlockDevice, lba: u64) -> Result<&Sector, NtStatus> {
        self.clock += 1;
        let index = match self.slot_of(lba) {
            Some(hit) => hit,
            None => {
                // Empty slots have never been used, so they go first.
                let victim = (0..N)
                    .min_by_key(|&index| (self.tags[index].lba.is_some(), self.tags[index].used))
                    .unwrap();
                self.tags[victim].lba = None;
                device.read(lba, &mut self.data[victim])?;
                self.tags[victim].lba = Some(lba);
                victim
            }
        };
        self.tags[index].used = self.clock;
        Ok(&self.data[index])
    }

    /// Keep the cached copies of the sectors from `lba` in step with a write of `data` (whole
    /// sectors) that reached the device. Sectors not cached stay uncached.
    pub fn wrote(&mut self, lba: u64, data: &[u8]) {
        for (offset, bytes) in data.chunks_exact(512).enumerate() {
            if let Some(slot) = self.slot_of(lba + offset as u64) {
                self.data[slot].copy_from_slice(bytes);
            }
        }
    }

    /// Drop the cached copies of `sectors` sectors from `lba`: a write over them failed, so what
    /// the disk holds there is not known.
    pub fn forget(&mut self, lba: u64, sectors: u64) {
        for tag in self.tags.iter_mut() {
            if tag.lba.is_some_and(|at| (lba..lba + sectors).contains(&at)) {
                tag.lba = None;
            }
        }
    }
}

/// Storage for `sectors` sectors, kept for the system's life (a mount's caches): the nonpaged
/// pool's on target, the heap's on the host; empty when the pool has no room.
fn storage(sectors: usize) -> &'static mut [Sector] {
    #[cfg(target_arch = "x86")]
    let bytes: &'static mut [u8] = match crate::mem::pool::allocate(sectors * 512) {
        Some(block) => block.leak(),
        None => &mut [],
    };
    #[cfg(not(target_arch = "x86"))]
    let bytes: &'static mut [u8] = std::vec![0u8; sectors * 512].leak();
    bytes.as_chunks_mut::<512>().0
}

#[cfg(test)]
mod tests {
    use super::super::fixtures::Counting;
    use super::*;
    use crate::block::memory::MemoryDisk;
    use crate::status::STATUS_IO_DEVICE_ERROR;

    fn device(sectors: u64) -> &'static Counting {
        Counting::over(Box::leak(Box::new(MemoryDisk::patterned(sectors))))
    }

    /// A miss reads the device; a hit returns the cached bytes and touches no device.
    #[test]
    fn a_hit_touches_no_device() {
        let disk = device(16);
        let mut cache = SectorCache::<4>::new();
        let first = *cache.sector(disk, 5).unwrap();
        assert_eq!(disk.reads(), 1, "a miss reads");
        assert_eq!(&first[..], &MemoryDisk::pattern_of(5, 1)[..]);
        let again = *cache.sector(disk, 5).unwrap();
        assert_eq!(disk.reads(), 1, "a hit does not");
        assert_eq!(again, first);
    }

    /// A full cache evicts its least recently used sector: after 1, 2, 3, 4 and a touch of 1, a
    /// fifth sector evicts 2 — so 1 still hits and 2 misses.
    #[test]
    fn a_full_cache_evicts_the_least_recently_used() {
        let disk = device(16);
        let mut cache = SectorCache::<4>::new();
        for lba in 1..=4 {
            cache.sector(disk, lba).unwrap();
        }
        assert_eq!(disk.reads(), 4);
        cache.sector(disk, 1).unwrap();
        assert_eq!(disk.reads(), 4, "every sector fits");

        cache.sector(disk, 5).unwrap();
        assert_eq!(disk.reads(), 5);
        cache.sector(disk, 1).unwrap();
        assert_eq!(disk.reads(), 5, "the touched sector stayed");
        assert_eq!(
            &cache.sector(disk, 2).unwrap()[..],
            &MemoryDisk::pattern_of(2, 1)[..]
        );
        assert_eq!(disk.reads(), 6, "the least recently used was evicted");
    }

    /// A failed read reports the device's status and caches nothing: the next lookup reads again.
    #[test]
    fn a_failed_read_caches_nothing() {
        let disk = device(16);
        let mut cache = SectorCache::<4>::new();
        disk.fail(true);
        assert_eq!(cache.sector(disk, 7).err(), Some(STATUS_IO_DEVICE_ERROR));
        disk.fail(false);
        assert_eq!(
            &cache.sector(disk, 7).unwrap()[..],
            &MemoryDisk::pattern_of(7, 1)[..]
        );
        assert_eq!(disk.reads(), 2);
    }

    /// A failed read into a slot that held another sector drops that one too: its bytes were
    /// overwritten by whatever the read left.
    #[test]
    fn a_failed_read_over_an_evicted_slot_keeps_nothing_stale() {
        let disk = device(16);
        let mut cache = SectorCache::<1>::new();
        cache.sector(disk, 3).unwrap();
        disk.fail(true);
        assert!(cache.sector(disk, 4).is_err());
        disk.fail(false);
        assert_eq!(
            &cache.sector(disk, 3).unwrap()[..],
            &MemoryDisk::pattern_of(3, 1)[..]
        );
        assert_eq!(disk.reads(), 3, "the evicted sector is read again");
    }

    /// A write brings the cached sectors it covers in step and leaves the others uncached; a
    /// forgotten range reads again.
    #[test]
    fn writes_keep_the_cached_copies_in_step() {
        let disk = device(16);
        let mut cache = SectorCache::<4>::new();
        cache.sector(disk, 2).unwrap();
        cache.sector(disk, 4).unwrap();
        let mut data = [0u8; 3 * 512];
        data[512..1024].fill(0xAB);
        cache.wrote(1, &data);
        assert_eq!(cache.sector(disk, 2).unwrap(), &[0xAB; 512]);
        assert_eq!(disk.reads(), 2, "a hit");
        cache.sector(disk, 3).unwrap();
        assert_eq!(
            disk.reads(),
            3,
            "an uncovered sector was not cached by the write"
        );
        cache.forget(2, 2);
        cache.sector(disk, 2).unwrap();
        cache.sector(disk, 4).unwrap();
        assert_eq!(disk.reads(), 4, "4 lies past the forgotten range");
    }
}
