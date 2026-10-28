//! The `disk-smoke` boot diagnostic: after the driver comes up and the block layer has scanned the
//! disk, read the drive's identity, the MBR, the volume boot sector, and the first file the disk
//! build copies into the volume, all through the block devices and the IRQ-driven read path, and
//! report each on COM1.
//!
//! The decoders here read only the fields the diagnostic checks; they are not a filesystem layer.

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

    use crate::block::registry::{registry, Role};
    use crate::block::{BlockDevice, BusType, DeviceInfo, DeviceKind};
    use crate::fs::fat32::fat::FatEntry;
    use crate::fs::fat32::lookup::lookup;
    use crate::fs::fat32::read::read as read_file;
    use crate::fs::fat32::volume::{boot_mount, with_boot_volume};
    use crate::hw::ide::disk::{self, LATCH};
    use crate::hw::ide::regs::SECTOR_SIZE;
    use crate::serial_println;

    /// The disk image the disk build lays down: 64 MiB, one FAT32 partition at 1 MiB.
    const DISK_SECTORS: u64 = 131_072;
    const VOLUME_START: u64 = 2048;
    const VOLUME_SECTORS: u64 = 129_024;
    /// The first file copied into the fresh volume lands on the first free cluster.
    const FIRST_FILE_CLUSTER: u32 = 3;
    /// The multi-sector run read from the same place.
    const RUN_SECTORS: usize = 8;

    static mut RUN: [u8; RUN_SECTORS * SECTOR_SIZE] = [0; RUN_SECTORS * SECTOR_SIZE];
    /// Room for the whole first file.
    static mut FILE: [u8; 32 * 1024] = [0; 32 * 1024];

    fn read(device: &dyn BlockDevice, lba: u64, buffer: &mut [u8]) {
        let status = device.read(lba, buffer);
        assert!(
            status.is_success(),
            "disk-smoke: read at LBA {} failed with status {:#010x}",
            lba,
            status.0
        );
    }

    // 1. The drive: IDENTIFY reported LBA support and the image's size, and the block layer
    //    describes it.
    let identity = disk::identity().expect("disk-smoke: no usable disk on the primary master");
    assert!(identity.lba);
    assert_eq!(
        identity.sectors as u64, DISK_SECTORS,
        "disk-smoke: sector count"
    );
    let devices = registry();
    let (disk_id, disk_entry) = devices
        .iter()
        .find(|(_, entry)| entry.role == Role::Disk)
        .expect("disk-smoke: the disk is not registered");
    let disk_device = disk_entry.device;
    assert_eq!(
        disk_device.info(),
        DeviceInfo {
            kind: DeviceKind::Disk,
            bus: BusType::Ata,
            sector_size: 512,
            sectors: DISK_SECTORS,
            removable: false,
            read_only: false,
        },
        "disk-smoke: the disk's description"
    );
    serial_println!(
        "F2K: disk-smoke: drive detected (LBA supported, {} sectors)",
        identity.sectors
    );

    // The registered devices: the disk and the one partition its table carries.
    assert_eq!(devices.iter().count(), 2, "disk-smoke: registered devices");
    let (partition_id, partition_entry) = devices
        .iter()
        .find(|(_, entry)| matches!(entry.role, Role::Partition { disk, .. } if disk == disk_id))
        .expect("disk-smoke: no partition registered");
    let Role::Partition { entry, .. } = partition_entry.role else {
        unreachable!()
    };
    let volume = partition_entry.device;
    serial_println!(
        "F2K: disk-smoke: block devices: {} = ATA disk ({} sectors of {} bytes), {} = partition {} of device {} ({} sectors)",
        disk_id.0,
        disk_device.info().sectors,
        disk_device.info().sector_size,
        partition_id.0,
        entry.index,
        disk_id.0,
        volume.info().sectors
    );

    // 2. The MBR, read through the disk, and the partition the walk found in it.
    let mut sector = [0u8; SECTOR_SIZE];
    read(disk_device, 0, &mut sector);
    let mbr_signature = signature(&sector);
    assert_eq!(mbr_signature, 0xAA55, "disk-smoke: MBR signature");
    assert_eq!(
        (entry.index, entry.kind, entry.start, entry.sectors),
        (0, 0x0C, VOLUME_START, VOLUME_SECTORS),
        "disk-smoke: partition 0"
    );
    serial_println!(
        "F2K: disk-smoke: MBR ok (signature {:#06X}, partition 0 type {:#04X} at LBA {}, {} sectors)",
        mbr_signature,
        entry.kind,
        entry.start,
        entry.sectors
    );

    // 3. The volume boot sector — sector 0 of the partition — and its BPB.
    read(volume, 0, &mut sector);
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
    let data_region = bpb.data_region(entry.start as u32);
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

    // The boot's mount of the partition: its state, reported in disk LBAs, and two FAT entries
    // from one FAT sector — the second lookup is served by the cache.
    match boot_mount() {
        Some(Ok(())) => {}
        Some(Err(error)) => panic!("disk-smoke: the boot volume was refused: {:?}", error),
        None => panic!("disk-smoke: the boot mounted no volume"),
    }
    let (layout, cluster_3, cluster_2) =
        with_boot_volume(|volume| (*volume.layout(), volume.fat_entry(3), volume.fat_entry(2)))
            .unwrap();
    assert_eq!(
        (
            layout.cluster_count,
            layout.fat_start,
            layout.data_start,
            layout.root_cluster
        ),
        (127_006, 32, 2018, 2),
        "disk-smoke: mount state"
    );
    serial_println!(
        "F2K: disk-smoke: mount ok ({} clusters, FAT at LBA {}, data at LBA {}, root cluster {})",
        layout.cluster_count,
        entry.start + layout.fat_start,
        entry.start + layout.data_start,
        layout.root_cluster
    );
    assert_eq!(cluster_3, Ok(FatEntry::Next(4)), "disk-smoke: FAT[3]");
    assert_eq!(cluster_2, Ok(FatEntry::EndOfChain), "disk-smoke: FAT[2]");
    for (cluster, fat_entry) in [(3, cluster_3), (2, cluster_2)] {
        serial_println!(
            "F2K: disk-smoke: FAT cluster {} -> {}",
            cluster,
            fat_entry.unwrap()
        );
    }

    // The first file, found by name in the root directory and read whole through its cluster
    // chain: the bytes the pinned sector checksums came from, now delivered by the file system.
    // SAFETY: the diagnostic runs once, in the boot context; the buffer is its alone.
    let file_buffer = unsafe { &mut *addr_of_mut!(FILE) };
    let (hello, hello_status) = with_boot_volume(|volume| {
        let hello = lookup(volume, b"HELLO.EXE");
        let status = hello.map(|file| read_file(volume, &file, &mut file_buffer[..]));
        (hello, status)
    })
    .unwrap();
    let hello = hello.unwrap_or_else(|error| panic!("disk-smoke: HELLO.EXE lookup: {:?}", error));
    assert_eq!(
        (hello.first_cluster, hello.size, hello.directory),
        (3, 28_672, false),
        "disk-smoke: HELLO.EXE's entry"
    );
    serial_println!(
        "F2K: disk-smoke: HELLO.EXE: {} bytes, first cluster {}",
        hello.size,
        hello.first_cluster
    );
    let status = hello_status.unwrap();
    assert!(
        status.is_success(),
        "disk-smoke: HELLO.EXE read failed with status {:#010x}",
        status.0
    );
    serial_println!(
        "F2K: disk-smoke: HELLO.EXE via chain: CRC-32 {:#010X}",
        crc32(&file_buffer[..hello.size as usize])
    );

    // 4. The first file's first sector, read through the partition (reported at its disk LBA), then
    //    an 8-sector run from the same place (one interrupt per sector).
    let file_sector = bpb.cluster_lba(0, FIRST_FILE_CLUSTER) as u64;
    let file_lba = entry.start + file_sector;
    read(volume, file_sector, &mut sector);
    serial_println!(
        "F2K: disk-smoke: LBA {} CRC-32 {:#010X}",
        file_lba,
        crc32(&sector)
    );
    // SAFETY: the diagnostic runs once, in the boot context; the buffer is its alone.
    let run = unsafe { &mut *addr_of_mut!(RUN) };
    read(volume, file_sector, run);
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

    // The interrupt accounting: one per sector moved — IDENTIFY's, the boot scan's MBR read, the
    // boot mount's boot-sector read, and the file's directory and cluster reads included — and
    // none unasked for.
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

    /// The signature word is read at offset 510, little-endian.
    #[test]
    fn the_signature_is_the_word_at_offset_510() {
        let mut sector = [0u8; 512];
        sector[510] = 0x55;
        sector[511] = 0xAA;
        assert_eq!(signature(&sector), 0xAA55);
        sector[511] = 0;
        assert_eq!(signature(&sector), 0x0055);
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
