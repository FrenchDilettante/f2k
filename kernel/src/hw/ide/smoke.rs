//! The `disk-smoke` boot diagnostic: after the driver comes up, read the drive's identity, the
//! MBR, the volume boot sector, and the first file the disk build copies into the volume, all
//! through the IRQ-driven read path, and report each on COM1.
//!
//! The decoders here read only the fields the diagnostic checks; they are not a partition or
//! filesystem layer.

/// CRC-32 (the IEEE 802.3 polynomial, reflected) of `bytes`.
pub fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &byte in bytes {
        crc ^= byte as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

fn le16(sector: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([sector[offset], sector[offset + 1]])
}

fn le32(sector: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        sector[offset],
        sector[offset + 1],
        sector[offset + 2],
        sector[offset + 3],
    ])
}

/// The boot-sector signature word at offset 510 (0xAA55 on a valid MBR or volume boot sector).
pub fn signature(sector: &[u8]) -> u16 {
    le16(sector, 510)
}

/// One MBR partition entry's type and extent.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PartitionEntry {
    pub kind: u8,
    pub start: u32,
    pub sectors: u32,
}

/// Partition entry `index` (0-3) of an MBR: 16-byte entries from offset 446.
pub fn partition_entry(mbr: &[u8], index: usize) -> PartitionEntry {
    let entry = 446 + 16 * index;
    PartitionEntry {
        kind: mbr[entry + 4],
        start: le32(mbr, entry + 8),
        sectors: le32(mbr, entry + 12),
    }
}

/// The FAT32 BIOS parameter block fields the diagnostic checks.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Bpb {
    pub bytes_per_sector: u16,
    pub sectors_per_cluster: u8,
    pub reserved_sectors: u16,
    pub fats: u8,
    pub sectors_per_fat: u32,
    pub root_cluster: u32,
}

impl Bpb {
    /// Decode a FAT32 volume boot sector's BPB.
    pub fn decode(sector: &[u8]) -> Self {
        Bpb {
            bytes_per_sector: le16(sector, 11),
            sectors_per_cluster: sector[13],
            reserved_sectors: le16(sector, 14),
            fats: sector[16],
            sectors_per_fat: le32(sector, 36),
            root_cluster: le32(sector, 44),
        }
    }

    /// The disk LBA of the data region (cluster 2) of a volume starting at `volume_start`.
    pub fn data_region(&self, volume_start: u32) -> u32 {
        volume_start + self.reserved_sectors as u32 + self.fats as u32 * self.sectors_per_fat
    }

    /// The disk LBA of `cluster`'s first sector.
    pub fn cluster_lba(&self, volume_start: u32, cluster: u32) -> u32 {
        self.data_region(volume_start) + (cluster - 2) * self.sectors_per_cluster as u32
    }
}

/// The diagnostic pass. Every check is an assert: a wrong answer from the disk stops the boot.
#[cfg(all(target_arch = "x86", feature = "disk-smoke"))]
pub fn run() {
    use core::ptr::addr_of_mut;

    use crate::hw::ide::disk::{self, LATCH};
    use crate::hw::ide::nt_success;
    use crate::hw::ide::regs::SECTOR_SIZE;
    use crate::serial_println;

    /// The disk image the disk build lays down: 64 MiB, one FAT32 partition at 1 MiB.
    const DISK_SECTORS: u32 = 131_072;
    const VOLUME_START: u32 = 2048;
    const VOLUME_SECTORS: u32 = 129_024;
    /// The first file copied into the fresh volume lands on the first free cluster.
    const FIRST_FILE_CLUSTER: u32 = 3;
    /// The multi-sector run read from the same place.
    const RUN_SECTORS: usize = 8;

    static mut RUN: [u8; RUN_SECTORS * SECTOR_SIZE] = [0; RUN_SECTORS * SECTOR_SIZE];

    fn read(lba: u32, buffer: &mut [u8]) {
        let status = disk::read(lba, buffer);
        assert!(
            nt_success(status),
            "disk-smoke: read at LBA {} failed with status {:#010x}",
            lba,
            status as u32
        );
    }

    // 1. The drive: IDENTIFY reported LBA support and the image's size.
    let identity = disk::identity().expect("disk-smoke: no usable disk on the primary master");
    assert!(identity.lba);
    assert_eq!(identity.sectors, DISK_SECTORS, "disk-smoke: sector count");
    serial_println!(
        "F2K: disk-smoke: drive detected (LBA supported, {} sectors)",
        identity.sectors
    );

    // 2. The MBR.
    let mut sector = [0u8; SECTOR_SIZE];
    read(0, &mut sector);
    let mbr_signature = signature(&sector);
    let entry = partition_entry(&sector, 0);
    assert_eq!(mbr_signature, 0xAA55, "disk-smoke: MBR signature");
    assert_eq!(
        entry,
        PartitionEntry {
            kind: 0x0C,
            start: VOLUME_START,
            sectors: VOLUME_SECTORS
        },
        "disk-smoke: partition 0"
    );
    serial_println!(
        "F2K: disk-smoke: MBR ok (signature {:#06X}, partition 0 type {:#04X} at LBA {}, {} sectors)",
        mbr_signature,
        entry.kind,
        entry.start,
        entry.sectors
    );

    // 3. The volume boot sector and its BPB.
    read(entry.start, &mut sector);
    let volume_signature = signature(&sector);
    let bpb = Bpb::decode(&sector);
    assert_eq!(
        volume_signature, 0xAA55,
        "disk-smoke: volume boot sector signature"
    );
    assert_eq!(
        bpb,
        Bpb {
            bytes_per_sector: 512,
            sectors_per_cluster: 1,
            reserved_sectors: 32,
            fats: 2,
            sectors_per_fat: 993,
            root_cluster: 2,
        },
        "disk-smoke: BPB"
    );
    let data_region = bpb.data_region(entry.start);
    assert_eq!(data_region, 4066, "disk-smoke: data region");
    serial_println!(
        "F2K: disk-smoke: volume boot sector ok (signature {:#06X}, {} bytes/sector, {} sector/cluster, {} reserved, {} FATs, {} sectors/FAT, root cluster {}, data region at LBA {})",
        volume_signature,
        bpb.bytes_per_sector,
        bpb.sectors_per_cluster,
        bpb.reserved_sectors,
        bpb.fats,
        bpb.sectors_per_fat,
        bpb.root_cluster,
        data_region
    );

    // 4. The first file's first sector, then an 8-sector run from the same place (one interrupt per
    //    sector).
    let file_lba = bpb.cluster_lba(entry.start, FIRST_FILE_CLUSTER);
    read(file_lba, &mut sector);
    serial_println!(
        "F2K: disk-smoke: LBA {} CRC-32 {:#010X}",
        file_lba,
        crc32(&sector)
    );
    // SAFETY: the diagnostic runs once, in the boot context; the buffer is its alone.
    let run = unsafe { &mut *addr_of_mut!(RUN) };
    read(file_lba, run);
    assert_eq!(
        &run[..SECTOR_SIZE],
        &sector[..],
        "disk-smoke: the run's first sector"
    );
    serial_println!(
        "F2K: disk-smoke: LBA {}+{} CRC-32 {:#010X}",
        file_lba,
        RUN_SECTORS,
        crc32(run)
    );

    // The interrupt accounting: one per sector moved, IDENTIFY's included, none unasked for.
    let verdict = crate::interrupt::audit();
    serial_println!(
        "F2K: disk-smoke: IRQ14 serviced {} interrupts ({} unsolicited), interrupt audit: {}",
        LATCH.serviced(),
        LATCH.unsolicited(),
        if verdict.is_ok() { "ok" } else { "FAILED" }
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The checksum is standard CRC-32: the zlib check value over "123456789", and the empty
    /// input.
    #[test]
    fn crc32_matches_the_standard_check_value() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(b""), 0);
    }

    /// The MBR decode: the signature word and partition entry 0's type, start, and length, at
    /// their offsets.
    #[test]
    fn mbr_fields_decode_at_their_offsets() {
        let mut mbr = [0u8; 512];
        mbr[446 + 4] = 0x0C;
        mbr[446 + 8..446 + 12].copy_from_slice(&2048u32.to_le_bytes());
        mbr[446 + 12..446 + 16].copy_from_slice(&129_024u32.to_le_bytes());
        mbr[510] = 0x55;
        mbr[511] = 0xAA;
        assert_eq!(signature(&mbr), 0xAA55);
        assert_eq!(
            partition_entry(&mbr, 0),
            PartitionEntry {
                kind: 0x0C,
                start: 2048,
                sectors: 129_024
            }
        );
        assert_eq!(
            partition_entry(&mbr, 1),
            PartitionEntry {
                kind: 0,
                start: 0,
                sectors: 0
            }
        );
    }

    /// The BPB decode, and the layout the disk image's volume has: the data region at
    /// 2048 + 32 + 2*993 = 4066, cluster 3 one sector later.
    #[test]
    fn bpb_fields_and_the_data_region() {
        let mut vbr = [0u8; 512];
        vbr[11..13].copy_from_slice(&512u16.to_le_bytes());
        vbr[13] = 1;
        vbr[14..16].copy_from_slice(&32u16.to_le_bytes());
        vbr[16] = 2;
        vbr[36..40].copy_from_slice(&993u32.to_le_bytes());
        vbr[44..48].copy_from_slice(&2u32.to_le_bytes());
        let bpb = Bpb::decode(&vbr);
        assert_eq!(
            bpb,
            Bpb {
                bytes_per_sector: 512,
                sectors_per_cluster: 1,
                reserved_sectors: 32,
                fats: 2,
                sectors_per_fat: 993,
                root_cluster: 2,
            }
        );
        assert_eq!(bpb.data_region(2048), 4066);
        assert_eq!(bpb.cluster_lba(2048, 2), 4066);
        assert_eq!(bpb.cluster_lba(2048, 3), 4067);
    }
}
