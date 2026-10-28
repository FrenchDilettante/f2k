//! The File Allocation Table: entry decode, and a small cache of recently used FAT sectors.
//!
//! An entry is 32 bits, little-endian, of which the low 28 count. FAT1 — the first copy — is the
//! one read; the mirror copies only matter to writes. The FAT is large (the built volume's is 993
//! sectors, about half a megabyte), so the kernel never holds it whole: entries are read through
//! the device, one sector at a time, through a few cached sectors. A sector is held as its 128
//! stored entries ([`FatSector`]).

use core::fmt;

use rtl::pod::Pod;

use super::check;
use super::raw::Le32;
use crate::block::BlockDevice;
use crate::status::NtStatus;

/// The bits of an entry that count.
pub const ENTRY_MASK: u32 = 0x0FFF_FFFF;
/// The bad-cluster marker.
pub const BAD: u32 = 0x0FFF_FFF7;
/// The end-of-chain markers start here and run to the mask.
pub const END_OF_CHAIN: u32 = 0x0FFF_FFF8;
/// Entries per 512-byte FAT sector.
pub const ENTRIES_PER_SECTOR: u32 = 128;

/// One FAT sector: its entries as stored.
pub type FatSector = [Le32; ENTRIES_PER_SECTOR as usize];

/// What a cluster's FAT entry says.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FatEntry {
    /// The cluster is unused.
    Free,
    /// The cluster is marked bad.
    Bad,
    /// The cluster ends its chain.
    EndOfChain,
    /// The chain continues at this cluster.
    Next(u32),
    /// The entry names no cluster of the volume (the masked value is kept for diagnosis).
    Corrupt(u32),
}

impl fmt::Display for FatEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            FatEntry::Free => write!(f, "free"),
            FatEntry::Bad => write!(f, "bad"),
            FatEntry::EndOfChain => write!(f, "end of chain"),
            FatEntry::Next(cluster) => write!(f, "{}", cluster),
            FatEntry::Corrupt(value) => write!(f, "corrupt ({:#010x})", value),
        }
    }
}

/// Decode a raw entry of a volume whose highest cluster is `max_cluster`.
pub fn decode_entry(raw: u32, max_cluster: u32) -> FatEntry {
    match raw & ENTRY_MASK {
        0 => FatEntry::Free,
        BAD => FatEntry::Bad,
        END_OF_CHAIN..=ENTRY_MASK => FatEntry::EndOfChain,
        next if (2..=max_cluster).contains(&next) => FatEntry::Next(next),
        corrupt => FatEntry::Corrupt(corrupt),
    }
}

/// Where cluster `cluster`'s entry lives: the sector within the FAT, and the entry's index in it.
pub fn entry_position(cluster: u32) -> (u64, usize) {
    (
        (cluster / ENTRIES_PER_SECTOR) as u64,
        (cluster % ENTRIES_PER_SECTOR) as usize,
    )
}

/// How many FAT sectors the cache holds.
pub const CACHE_SECTORS: usize = 4;

#[derive(Clone, Copy)]
struct Slot {
    /// The cached sector's LBA on the volume; none for an empty slot.
    lba: Option<u64>,
    /// When the slot was last used (the cache's clock).
    used: u64,
    data: FatSector,
}

/// A read-through cache of FAT sectors, least recently used evicted first.
pub struct FatCache {
    slots: [Slot; CACHE_SECTORS],
    clock: u64,
}

impl FatCache {
    pub const fn new() -> Self {
        FatCache {
            slots: [Slot {
                lba: None,
                used: 0,
                data: [Le32([0; 4]); ENTRIES_PER_SECTOR as usize],
            }; CACHE_SECTORS],
            clock: 0,
        }
    }

    /// Keep a cached copy of the sector at `lba` in step with a write of `data` to it.
    pub fn store(&mut self, lba: u64, data: &FatSector) {
        if let Some(slot) = self.slots.iter_mut().find(|slot| slot.lba == Some(lba)) {
            slot.data = *data;
        }
    }

    /// The sector at `lba` on `device`: from the cache, or read into the least recently used slot.
    /// A failed read caches nothing.
    pub fn sector(&mut self, device: &dyn BlockDevice, lba: u64) -> Result<&FatSector, NtStatus> {
        self.clock += 1;
        let index = match self.slots.iter().position(|slot| slot.lba == Some(lba)) {
            Some(hit) => hit,
            None => {
                let mut data = FatSector::zeroed();
                check(device.read(lba, data.as_bytes_mut()))?;
                // Empty slots have never been used, so they go first.
                let victim = (0..CACHE_SECTORS)
                    .min_by_key(|&index| (self.slots[index].lba.is_some(), self.slots[index].used))
                    .unwrap();
                self.slots[victim].lba = Some(lba);
                self.slots[victim].data = data;
                victim
            }
        };
        self.slots[index].used = self.clock;
        Ok(&self.slots[index].data)
    }
}

#[cfg(test)]
mod tests {
    use super::super::fixtures::Counting;
    use super::*;
    use crate::block::memory::MemoryDisk;
    use crate::status::STATUS_IO_DEVICE_ERROR;

    const MAX: u32 = 127_007;

    /// The entry values: free, bad, the end-of-chain range, a next cluster, and anything naming
    /// no cluster of the volume — reserved values, 1, past the last cluster — as corrupt. The top
    /// four bits never count.
    #[test]
    fn entries_decode_by_value() {
        assert_eq!(decode_entry(0, MAX), FatEntry::Free);
        assert_eq!(decode_entry(0x0FFF_FFF7, MAX), FatEntry::Bad);
        for end in 0x0FFF_FFF8..=0x0FFF_FFFF {
            assert_eq!(decode_entry(end, MAX), FatEntry::EndOfChain);
        }
        assert_eq!(decode_entry(4, MAX), FatEntry::Next(4));
        assert_eq!(decode_entry(2, MAX), FatEntry::Next(2));
        assert_eq!(decode_entry(MAX, MAX), FatEntry::Next(MAX));

        assert_eq!(decode_entry(1, MAX), FatEntry::Corrupt(1));
        assert_eq!(decode_entry(MAX + 1, MAX), FatEntry::Corrupt(MAX + 1));
        for reserved in 0x0FFF_FFF0..=0x0FFF_FFF6 {
            assert_eq!(decode_entry(reserved, MAX), FatEntry::Corrupt(reserved));
        }

        assert_eq!(decode_entry(0xF000_0004, MAX), FatEntry::Next(4));
        assert_eq!(decode_entry(0xF000_0000, MAX), FatEntry::Free);
        assert_eq!(decode_entry(0xFFFF_FFFF, MAX), FatEntry::EndOfChain);
    }

    /// An entry's place: 128 to a sector, 4 bytes each, little-endian.
    #[test]
    fn entries_are_128_to_a_sector() {
        assert_eq!(entry_position(0), (0, 0));
        assert_eq!(entry_position(3), (0, 3));
        assert_eq!(entry_position(127), (0, 127));
        assert_eq!(entry_position(128), (1, 0));
        assert_eq!(entry_position(127_007), (992, 31));

        let mut bytes = [0u8; 512];
        bytes[12..16].copy_from_slice(&[0x04, 0x03, 0x02, 0x01]);
        let sector: FatSector = super::super::raw::from_block(&bytes);
        assert_eq!(sector[3].get(), 0x0102_0304);
    }

    #[test]
    fn entries_display_for_the_diagnostic() {
        assert_eq!(FatEntry::Next(4).to_string(), "4");
        assert_eq!(FatEntry::EndOfChain.to_string(), "end of chain");
        assert_eq!(FatEntry::Corrupt(1).to_string(), "corrupt (0x00000001)");
    }

    fn device(sectors: u64) -> &'static Counting {
        Counting::over(Box::leak(Box::new(MemoryDisk::patterned(sectors))))
    }

    /// A miss reads the device; a hit returns the cached bytes and touches no device.
    #[test]
    fn a_hit_touches_no_device() {
        let disk = device(16);
        let mut cache = FatCache::new();
        let first = *cache.sector(disk, 5).unwrap();
        assert_eq!(disk.reads(), 1, "a miss reads");
        assert_eq!(first.as_bytes(), &MemoryDisk::pattern_of(5, 1)[..]);
        let again = *cache.sector(disk, 5).unwrap();
        assert_eq!(disk.reads(), 1, "a hit does not");
        assert_eq!(again, first);
    }

    /// A full cache evicts its least recently used sector: after 1, 2, 3, 4 and a touch of 1, a
    /// fifth sector evicts 2 — so 1 still hits and 2 misses.
    #[test]
    fn a_full_cache_evicts_the_least_recently_used() {
        let disk = device(16);
        let mut cache = FatCache::new();
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
            cache.sector(disk, 2).unwrap().as_bytes(),
            &MemoryDisk::pattern_of(2, 1)[..]
        );
        assert_eq!(disk.reads(), 6, "the least recently used was evicted");
    }

    /// A failed read reports the device's status and caches nothing: the next lookup reads again.
    #[test]
    fn a_failed_read_caches_nothing() {
        let disk = device(16);
        let mut cache = FatCache::new();
        disk.fail(true);
        assert_eq!(cache.sector(disk, 7).err(), Some(STATUS_IO_DEVICE_ERROR));
        disk.fail(false);
        assert_eq!(
            cache.sector(disk, 7).unwrap().as_bytes(),
            &MemoryDisk::pattern_of(7, 1)[..]
        );
        assert_eq!(disk.reads(), 2);
    }
}
