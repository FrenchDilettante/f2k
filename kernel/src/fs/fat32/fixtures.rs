//! Shared fixtures of the FAT32 host tests: the built volume's real boot sector and root
//! directory, its layout, in-memory volumes shaped like it, crafted small volumes for the directory
//! and chain tests, a directory-record builder, a device wrapper that counts reads, and one that
//! crashes after a number of writes.

use core::sync::atomic::{AtomicU32, Ordering};

use super::layout::Layout;
use crate::block::memory::MemoryDisk;
use crate::block::{BlockDevice, DeviceInfo};
use crate::status::{NtStatus, STATUS_IO_DEVICE_ERROR};

/// The built disk image's volume boot sector, captured once. Its bytes 67-70 (the volume serial
/// number) differ from build to build; nothing here reads them.
pub const BUILT: &[u8; 512] = include_bytes!("testdata/boot-sector.bin");

/// The built volume's geometry.
pub fn built_layout() -> Layout {
    Layout {
        sectors_per_cluster: 1,
        fat_start: 32,
        sectors_per_fat: 993,
        data_start: 2018,
        cluster_count: 127_006,
        root_cluster: 2,
    }
}

/// The FAT sectors at the front of a volume shaped like the built one: the two reserved entries,
/// the empty root directory's end of chain at cluster 2, the first file's chain 3 -> 4 -> ... ->
/// 58 and its end, and a recognizable entry at the start of every later sector (cluster
/// `128 * n` chains to `128 * n + 1`).
pub fn built_fat(sectors: usize) -> Vec<u8> {
    let mut fat = vec![0u8; sectors * 512];
    let mut put = |cluster: usize, value: u32| {
        fat[cluster * 4..cluster * 4 + 4].copy_from_slice(&value.to_le_bytes());
    };
    put(0, 0x0FFF_FFF0);
    put(1, 0x0FFF_FFFF);
    put(2, 0x0FFF_FFFF);
    for cluster in 3..58 {
        put(cluster, cluster as u32 + 1);
    }
    put(58, 0x0FFF_FFFF);
    for sector in 1..sectors {
        put(sector * 128, (sector * 128 + 1) as u32);
    }
    fat
}

/// An in-memory volume shaped like the built one, cut short after the first `fat_sectors` FAT
/// sectors (nothing beyond them is read): the real boot sector, the reserved sectors, then the
/// FAT.
pub fn built_volume(fat_sectors: usize) -> &'static MemoryDisk {
    let mut image = vec![0u8; 32 * 512];
    image[..512].copy_from_slice(BUILT);
    image.extend_from_slice(&built_fat(fat_sectors));
    Box::leak(Box::new(MemoryDisk::new(Box::leak(
        image.into_boxed_slice(),
    ))))
}

/// A device that counts the reads that reach it, and can be made to fail them.
pub struct Counting {
    inner: &'static dyn BlockDevice,
    reads: AtomicU32,
    failing: core::sync::atomic::AtomicBool,
}

impl Counting {
    pub fn over(inner: &'static dyn BlockDevice) -> &'static Counting {
        Box::leak(Box::new(Counting {
            inner,
            reads: AtomicU32::new(0),
            failing: core::sync::atomic::AtomicBool::new(false),
        }))
    }

    /// Reads that reached the device so far.
    pub fn reads(&self) -> u32 {
        self.reads.load(Ordering::SeqCst)
    }

    /// Make every later read fail with a device error.
    pub fn fail(&self, failing: bool) {
        self.failing.store(failing, Ordering::SeqCst);
    }
}

impl BlockDevice for Counting {
    fn info(&self) -> DeviceInfo {
        self.inner.info()
    }

    fn read(&self, lba: u64, buffer: &mut [u8]) -> NtStatus {
        self.reads.fetch_add(1, Ordering::SeqCst);
        if self.failing.load(Ordering::SeqCst) {
            return STATUS_IO_DEVICE_ERROR;
        }
        self.inner.read(lba, buffer)
    }

    fn write(&self, lba: u64, buffer: &[u8]) -> NtStatus {
        self.inner.write(lba, buffer)
    }
}

/// A writable device that loses power after a chosen number of writes: the later ones are
/// dropped (and reported done, as a drive's cache would), so the image shows what a crash at that
/// point leaves. It counts the writes that reached the image and the ones dropped.
pub struct Crashing {
    inner: &'static crate::block::memory::RamDisk,
    budget: AtomicU32,
    written: AtomicU32,
    dropped: AtomicU32,
}

impl Crashing {
    pub fn over(inner: &'static crate::block::memory::RamDisk) -> &'static Crashing {
        Box::leak(Box::new(Crashing {
            inner,
            budget: AtomicU32::new(u32::MAX),
            written: AtomicU32::new(0),
            dropped: AtomicU32::new(0),
        }))
    }

    /// Let `writes` more writes reach the image, and drop every one after them.
    pub fn crash_after(&self, writes: u32) {
        self.budget.store(writes, Ordering::SeqCst);
    }

    /// The image as the writes that reached it left it.
    pub fn image(&self) -> &'static crate::block::memory::RamDisk {
        self.inner
    }

    /// Writes that reached the image so far.
    pub fn written(&self) -> u32 {
        self.written.load(Ordering::SeqCst)
    }

    /// Writes dropped so far.
    pub fn dropped(&self) -> u32 {
        self.dropped.load(Ordering::SeqCst)
    }
}

impl BlockDevice for Crashing {
    fn info(&self) -> DeviceInfo {
        self.inner.info()
    }

    fn read(&self, lba: u64, buffer: &mut [u8]) -> NtStatus {
        self.inner.read(lba, buffer)
    }

    fn write(&self, lba: u64, buffer: &[u8]) -> NtStatus {
        let left = self.budget.load(Ordering::SeqCst);
        if left == 0 {
            self.dropped.fetch_add(1, Ordering::SeqCst);
            return crate::status::STATUS_SUCCESS;
        }
        if left != u32::MAX {
            self.budget.store(left - 1, Ordering::SeqCst);
        }
        self.written.fetch_add(1, Ordering::SeqCst);
        self.inner.write(lba, buffer)
    }
}

/// The built disk image's root directory sector (cluster 2), captured once: the volume label,
/// HELLO.EXE (cluster 3, 28672 bytes), the BOOT directory (cluster 59), the kernel's long-name
/// record and its short entry F2K-KE~1 (cluster 61), then the end. Its timestamps and the kernel's
/// size differ from build to build; nothing here reads the timestamps.
pub const ROOT_DIRECTORY: &[u8; 512] = include_bytes!("testdata/root-directory.bin");

/// The built volume's front, through its root directory: the real boot sector, the first FAT
/// sector, and the real root directory at the data region's start (LBA 2018).
pub fn built_volume_with_root() -> &'static MemoryDisk {
    let mut image = vec![0u8; 2019 * 512];
    image[..512].copy_from_slice(BUILT);
    image[32 * 512..33 * 512].copy_from_slice(&built_fat(1));
    image[2018 * 512..].copy_from_slice(ROOT_DIRECTORY);
    Box::leak(Box::new(MemoryDisk::new(Box::leak(
        image.into_boxed_slice(),
    ))))
}

/// A directory record with the given stored name, attributes, first cluster, and size.
pub fn record(name: &[u8; 11], attributes: u8, cluster: u32, size: u32) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[..11].copy_from_slice(name);
    bytes[11] = attributes;
    bytes[20..22].copy_from_slice(&((cluster >> 16) as u16).to_le_bytes());
    bytes[26..28].copy_from_slice(&(cluster as u16).to_le_bytes());
    bytes[28..32].copy_from_slice(&size.to_le_bytes());
    bytes
}

/// A small crafted volume: the boot sector (the built one, reshaped), its FAT from LBA 1 (one
/// sector, entries for clusters 0-127, unless it is a [`Crafted::full`] one), and the data region
/// right after it — cluster `c` at `2 + (c - 2) * sectors_per_cluster` for the one-sector FAT. The
/// boot sector claims enough clusters to pass the gates; the image holds only the clusters the test
/// writes.
pub struct Crafted {
    image: Vec<u8>,
    sectors_per_cluster: usize,
    fat_sectors: usize,
}

impl Crafted {
    /// A volume whose image holds clusters 2..`2 + clusters`, every FAT entry free, the root
    /// directory (cluster 2) one empty cluster ending its chain.
    pub fn new(sectors_per_cluster: u8, clusters: usize) -> Crafted {
        Crafted::build(sectors_per_cluster, clusters, 1, 70_000)
    }

    /// A volume of one-sector clusters with no room beyond the image's: a FAT covering every
    /// cluster the boot sector claims, clusters 3..`2 + clusters` free (the root, cluster 2, ends
    /// its chain), and every other cluster marked bad — so the volume has `clusters - 1` free.
    pub fn full(clusters: usize) -> Crafted {
        const CLAIMED: u32 = 65_530;
        let fat_sectors = (CLAIMED as usize + 2).div_ceil(128);
        let mut crafted = Crafted::build(1, clusters, fat_sectors, CLAIMED);
        for cluster in 2 + clusters as u32..CLAIMED + 2 {
            crafted.fat(cluster, 0x0FFF_FFF7);
        }
        crafted
    }

    fn build(sectors_per_cluster: u8, clusters: usize, fat_sectors: usize, claimed: u32) -> Crafted {
        let spc = sectors_per_cluster as usize;
        let mut image = vec![0u8; (1 + fat_sectors + clusters * spc) * 512];
        image[..512].copy_from_slice(BUILT);
        image[13] = sectors_per_cluster;
        image[14..16].copy_from_slice(&1u16.to_le_bytes());
        image[16] = 1;
        image[36..40].copy_from_slice(&(fat_sectors as u32).to_le_bytes());
        image[32..36].copy_from_slice(&(1 + fat_sectors as u32 + claimed * spc as u32).to_le_bytes());
        let mut crafted = Crafted {
            image,
            sectors_per_cluster: spc,
            fat_sectors,
        };
        crafted
            .fat(0, 0x0FFF_FFF8)
            .fat(1, 0x0FFF_FFFF)
            .fat(2, 0x0FFF_FFFF);
        crafted
    }

    /// Set cluster `cluster`'s FAT entry.
    pub fn fat(&mut self, cluster: u32, value: u32) -> &mut Crafted {
        assert!((cluster as usize) < 128 * self.fat_sectors, "past the crafted FAT");
        let at = 512 + cluster as usize * 4;
        self.image[at..at + 4].copy_from_slice(&value.to_le_bytes());
        self
    }

    /// Link `clusters` into a chain ending at the last one.
    pub fn chain(&mut self, clusters: &[u32]) -> &mut Crafted {
        for pair in clusters.windows(2) {
            self.fat(pair[0], pair[1]);
        }
        self.fat(*clusters.last().unwrap(), 0x0FFF_FFFF)
    }

    /// Write `bytes` at the start of cluster `cluster`.
    pub fn cluster(&mut self, cluster: u32, bytes: &[u8]) -> &mut Crafted {
        let cluster_bytes = self.sectors_per_cluster * 512;
        assert!(bytes.len() <= cluster_bytes, "more than a cluster");
        let at = (1 + self.fat_sectors + (cluster as usize - 2) * self.sectors_per_cluster) * 512;
        self.image[at..at + bytes.len()].copy_from_slice(bytes);
        self
    }

    /// Write `records` as the start of directory cluster `cluster`.
    pub fn directory(&mut self, cluster: u32, records: &[[u8; 32]]) -> &mut Crafted {
        let bytes: Vec<u8> = records.iter().flatten().copied().collect();
        self.cluster(cluster, &bytes)
    }

    /// The volume as a device that takes writes.
    pub fn writable(&self) -> &'static crate::block::memory::RamDisk {
        Box::leak(Box::new(crate::block::memory::RamDisk::new(self.image.clone())))
    }

    /// The volume as a device.
    pub fn device(&self) -> &'static MemoryDisk {
        Box::leak(Box::new(MemoryDisk::new(Box::leak(
            self.image.clone().into_boxed_slice(),
        ))))
    }
}

/// `count` bytes of a recognizable file: each byte a function of its position.
pub fn file_bytes(count: usize) -> Vec<u8> {
    (0..count)
        .map(|index| (index * 7 + index / 512) as u8)
        .collect()
}
