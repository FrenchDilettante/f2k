//! Shared fixtures of the FAT32 host tests: the built volume's real boot sector, its layout, an
//! in-memory volume shaped like it, and a device wrapper that counts reads.

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
}
