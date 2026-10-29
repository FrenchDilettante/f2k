//! Partition views: the MBR's primary entries as block devices of their own.
//!
//! The walk is a pure function over sector 0. A table is trusted only whole: a missing signature,
//! an entry that starts on the MBR itself, runs past the disk, or overlaps another refuses the
//! table, and the disk gets no partitions (a bad table is valid input, not a kernel fault).
//! Extended-partition containers are skipped: their logical partitions are not walked yet.

use core::mem::{offset_of, size_of};

use rtl::pod::Pod;

use super::{check_request, BlockDevice, DeviceInfo};
use crate::status::NtStatus;

/// The boot-sector signature word at offset 510.
pub const MBR_SIGNATURE: u16 = 0xAA55;

/// The partition table's entries.
pub const ENTRIES: usize = 4;

/// One partition-table entry as stored: 16 bytes, its two sector fields little-endian.
#[repr(C)]
#[derive(Clone, Copy, Default)]
// The layout names every field; the walk reads only those it validates.
#[allow(dead_code)]
struct PartitionEntry {
    /// 0x80 for the active (bootable) partition.
    status: u8,
    chs_first: [u8; 3],
    /// The partition type byte; 0 for an empty entry.
    kind: u8,
    chs_last: [u8; 3],
    lba_start: [u8; 4],
    sectors: [u8; 4],
}

impl PartitionEntry {
    /// The first sector, on the disk.
    fn start(&self) -> u64 {
        u32::from_le_bytes(self.lba_start) as u64
    }

    /// The length, in sectors.
    fn sectors(&self) -> u64 {
        u32::from_le_bytes(self.sectors) as u64
    }
}

/// Sector 0 of a partitioned disk as stored: the boot code, the four-entry partition table from
/// offset 446, and the signature word.
#[repr(C)]
#[derive(Clone, Copy)]
// The layout names every field; the walk reads only those it validates.
#[allow(dead_code)]
struct Mbr {
    boot_code: [u8; 446],
    entries: [PartitionEntry; ENTRIES],
    signature: [u8; 2],
}

// SAFETY: bytes and byte arrays only, so there is no padding (the sizes are asserted below) and
// every bit pattern is a value.
unsafe impl Pod for PartitionEntry {}
// SAFETY: as for `PartitionEntry`, which the table is an array of.
unsafe impl Pod for Mbr {}

const _: () = {
    assert!(size_of::<PartitionEntry>() == 16);
    assert!(offset_of!(PartitionEntry, kind) == 4);
    assert!(offset_of!(PartitionEntry, lba_start) == 8);
    assert!(offset_of!(PartitionEntry, sectors) == 12);
    assert!(size_of::<Mbr>() == 512);
    assert!(offset_of!(Mbr, entries) == 446);
    assert!(offset_of!(Mbr, signature) == 510);
};

/// One non-empty primary entry.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MbrEntry {
    /// The entry's slot in the table, 0-3.
    pub index: u8,
    /// The partition type byte.
    pub kind: u8,
    pub bootable: bool,
    /// The first sector, on the disk.
    pub start: u64,
    pub sectors: u64,
}

/// Why a table was refused.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MbrError {
    /// Sector 0 does not end in 0xAA55.
    NoSignature,
    /// The entry starts at sector 0, on the MBR itself.
    StartsAtZero(u8),
    /// The entry runs past the end of the disk.
    Overruns(u8),
    /// The two entries share sectors.
    Overlaps(u8, u8),
}

/// The extended-partition container types (CHS, LBA, and the Linux flavor).
fn is_extended(kind: u8) -> bool {
    matches!(kind, 0x05 | 0x0F | 0x85)
}

/// Walk an MBR (`sector` is sector 0 of a disk of `disk_sectors` sectors): the non-empty primary
/// entries by slot, or why the table is refused.
pub fn walk_mbr(
    sector: &[u8; 512],
    disk_sectors: u64,
) -> Result<[Option<MbrEntry>; ENTRIES], MbrError> {
    let mbr = Mbr::from_bytes(sector).expect("a sector holds an MBR");
    if u16::from_le_bytes(mbr.signature) != MBR_SIGNATURE {
        return Err(MbrError::NoSignature);
    }

    let mut entries = [None; ENTRIES];
    for (index, (slot, entry)) in entries.iter_mut().zip(&mbr.entries).enumerate() {
        let kind = entry.kind;
        let start = entry.start();
        let sectors = entry.sectors();
        if kind == 0 || sectors == 0 || is_extended(kind) {
            continue;
        }
        let index = index as u8;
        if start == 0 {
            return Err(MbrError::StartsAtZero(index));
        }
        if start + sectors > disk_sectors {
            return Err(MbrError::Overruns(index));
        }
        *slot = Some(MbrEntry {
            index,
            kind,
            bootable: entry.status == 0x80,
            start,
            sectors,
        });
    }

    for (i, a) in entries.iter().enumerate() {
        for b in entries.iter().skip(i + 1) {
            if let (Some(a), Some(b)) = (a, b) {
                if a.start < b.start + b.sectors && b.start < a.start + a.sectors {
                    return Err(MbrError::Overlaps(a.index, b.index));
                }
            }
        }
    }
    Ok(entries)
}

/// A primary partition: an offset and a length over its disk. Reads are checked against the
/// partition's own length, then land on the disk (whose lock they take).
#[derive(Clone, Copy)]
pub struct Partition {
    disk: &'static dyn BlockDevice,
    entry: MbrEntry,
}

impl Partition {
    pub fn new(disk: &'static dyn BlockDevice, entry: MbrEntry) -> Self {
        Partition { disk, entry }
    }
}

impl BlockDevice for Partition {
    /// The disk's description, at the partition's size.
    fn info(&self) -> DeviceInfo {
        DeviceInfo {
            sectors: self.entry.sectors,
            ..self.disk.info()
        }
    }

    fn read(&self, lba: u64, buffer: &mut [u8]) -> Result<(), NtStatus> {
        check_request(&self.info(), lba, buffer)?;
        self.disk.read(self.entry.start + lba, buffer)
    }

    fn write(&self, lba: u64, buffer: &[u8]) -> Result<(), NtStatus> {
        check_request(&self.info(), lba, buffer)?;
        self.disk.write(self.entry.start + lba, buffer)
    }
}

/// An MBR with the given entries (slot, boot flag, type, start, length) and the signature.
#[cfg(test)]
pub fn mbr(entries: &[(usize, u8, u8, u32, u32)]) -> [u8; 512] {
    let mut mbr = Mbr::zeroed();
    for &(slot, status, kind, start, sectors) in entries {
        mbr.entries[slot] = PartitionEntry {
            status,
            kind,
            lba_start: start.to_le_bytes(),
            sectors: sectors.to_le_bytes(),
            ..Default::default()
        };
    }
    mbr.signature = MBR_SIGNATURE.to_le_bytes();
    let mut sector = [0u8; 512];
    sector.copy_from_slice(mbr.as_bytes());
    sector
}

#[cfg(test)]
mod tests {
    use super::super::memory::MemoryDisk;
    use super::*;
    use crate::status::STATUS_INVALID_PARAMETER;

    /// The disk image's table: one bootable FAT32 (LBA) partition at 1 MiB, the rest empty.
    #[test]
    fn the_disk_image_table_walks_to_one_partition() {
        let table = walk_mbr(&mbr(&[(0, 0x80, 0x0C, 2048, 129_024)]), 131_072).unwrap();
        assert_eq!(
            table,
            [
                Some(MbrEntry {
                    index: 0,
                    kind: 0x0C,
                    bootable: true,
                    start: 2048,
                    sectors: 129_024
                }),
                None,
                None,
                None
            ]
        );
    }

    /// Entries keep their slot; empty slots (no type, or no length) and extended containers are
    /// skipped.
    #[test]
    fn empty_and_extended_entries_are_skipped() {
        let sector = mbr(&[
            (0, 0, 0x07, 100, 50),
            (1, 0, 0x0C, 200, 0),
            (2, 0, 0x0F, 300, 400),
            (3, 0, 0x83, 150, 50),
        ]);
        let table = walk_mbr(&sector, 1000).unwrap();
        assert_eq!(table[0].map(|e| (e.index, e.kind)), Some((0, 0x07)));
        assert_eq!(table[1], None, "no length");
        assert_eq!(table[2], None, "an extended container");
        assert_eq!(table[3].map(|e| (e.index, e.start)), Some((3, 150)));
        assert!(!table[0].unwrap().bootable);
    }

    /// The refusals: no signature, an entry on the MBR itself, one past the disk's end, and two
    /// sharing sectors.
    #[test]
    fn malformed_tables_are_refused() {
        let mut unsigned = mbr(&[(0, 0, 0x0C, 2048, 100)]);
        unsigned[511] = 0;
        assert_eq!(walk_mbr(&unsigned, 4096), Err(MbrError::NoSignature));

        assert_eq!(
            walk_mbr(&mbr(&[(1, 0, 0x0C, 0, 100)]), 4096),
            Err(MbrError::StartsAtZero(1))
        );
        // Ends exactly at the disk's end: fine. One sector further: refused.
        assert!(walk_mbr(&mbr(&[(0, 0, 0x0C, 2048, 2048)]), 4096).is_ok());
        assert_eq!(
            walk_mbr(&mbr(&[(2, 0, 0x0C, 2048, 2049)]), 4096),
            Err(MbrError::Overruns(2))
        );
        // Adjacent: fine. Sharing one sector: refused.
        assert!(walk_mbr(
            &mbr(&[(0, 0, 0x07, 100, 100), (3, 0, 0x07, 200, 100)]),
            4096
        )
        .is_ok());
        assert_eq!(
            walk_mbr(
                &mbr(&[(0, 0, 0x07, 100, 100), (3, 0, 0x07, 199, 100)]),
                4096
            ),
            Err(MbrError::Overlaps(0, 3))
        );
    }

    /// A partition reads its disk at its own offset, reports the disk's description at its own
    /// size, and refuses a run past its own end even when the disk goes on.
    #[test]
    fn a_partition_reads_its_disk_at_its_offset() {
        let disk: &'static MemoryDisk = Box::leak(Box::new(MemoryDisk::patterned(1000)));
        let entry = MbrEntry {
            index: 0,
            kind: 0x0C,
            bootable: false,
            start: 100,
            sectors: 50,
        };
        let partition = Partition::new(disk, entry);
        let info = partition.info();
        assert_eq!(info.sectors, 50);
        assert_eq!(
            DeviceInfo {
                sectors: 1000,
                ..info
            },
            disk.info()
        );

        let mut buffer = vec![0u8; 2 * 512];
        assert_eq!(partition.read(5, &mut buffer), Ok(()));
        assert_eq!(buffer, MemoryDisk::pattern_of(105, 2));

        assert_eq!(partition.read(48, &mut buffer), Ok(()));
        assert_eq!(
            partition.read(49, &mut buffer),
            Err(STATUS_INVALID_PARAMETER)
        );
    }
}
