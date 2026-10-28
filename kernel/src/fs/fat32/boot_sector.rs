//! The volume boot sector: the BIOS parameter block's fields in their on-disk layout, and the gate
//! list a volume must pass to mount as FAT32.
//!
//! The validation is one pure function over the sector, the gates in a fixed order, each failure
//! reported distinctly: a refused volume is debuggable input, not a kernel fault.

use core::mem::{offset_of, size_of};

use rtl::pod::Pod;

use super::layout::Layout;
use super::raw::{from_block, Le16, Le32};

/// The boot-sector signature word at offset 510.
pub const SIGNATURE: u16 = 0xAA55;

/// The fewest clusters a FAT32 volume has; below it the volume is FAT12 or FAT16.
pub const MIN_CLUSTERS: u32 = 65_525;

/// The boot sector's fields the mount reads (the CHS relics — sectors per track, heads, hidden
/// sectors — are unused and not decoded).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BootSector {
    /// Offset 0: the boot jump's opcode.
    pub jump: u8,
    pub bytes_per_sector: u16,
    pub sectors_per_cluster: u8,
    pub reserved_sectors: u16,
    pub fats: u8,
    /// The FAT12/FAT16 root directory size: empty on FAT32.
    pub root_entries: u16,
    /// The 16-bit total: empty on FAT32.
    pub total_sectors_16: u16,
    pub media: u8,
    /// The 16-bit FAT size: empty on FAT32.
    pub sectors_per_fat_16: u16,
    pub total_sectors_32: u32,
    pub sectors_per_fat_32: u32,
    pub mirroring_flags: u16,
    pub version: u16,
    pub root_cluster: u32,
    /// The FSInfo sector, volume-relative.
    pub fsinfo_sector: u16,
    pub backup_boot_sector: u16,
    pub signature: u16,
}

impl BootSector {
    /// Decode the fields from the stored sector.
    pub fn decode(sector: &[u8; 512]) -> Self {
        let raw: RawBootSector = from_block(sector);
        BootSector {
            jump: raw.jump[0],
            bytes_per_sector: raw.bytes_per_sector.get(),
            sectors_per_cluster: raw.sectors_per_cluster,
            reserved_sectors: raw.reserved_sectors.get(),
            fats: raw.fats,
            root_entries: raw.root_entries.get(),
            total_sectors_16: raw.total_sectors_16.get(),
            media: raw.media,
            sectors_per_fat_16: raw.sectors_per_fat_16.get(),
            total_sectors_32: raw.total_sectors_32.get(),
            sectors_per_fat_32: raw.sectors_per_fat_32.get(),
            mirroring_flags: raw.mirroring_flags.get(),
            version: raw.version.get(),
            root_cluster: raw.root_cluster.get(),
            fsinfo_sector: raw.fsinfo_sector.get(),
            backup_boot_sector: raw.backup_boot_sector.get(),
            signature: raw.signature.get(),
        }
    }
}

/// The boot sector as stored: the boot jump, the BIOS parameter block with FAT32's extension of
/// it, the boot code, and the signature. The BPB's words sit at odd offsets (11, 17, 19, 22), so
/// every multi-byte field is an unaligned little-endian one.
#[repr(C)]
#[derive(Clone, Copy)]
// The layout names every field; the mount reads only those it validates.
#[allow(dead_code)]
struct RawBootSector {
    jump: [u8; 3],
    oem_name: [u8; 8],
    bytes_per_sector: Le16,
    sectors_per_cluster: u8,
    reserved_sectors: Le16,
    fats: u8,
    root_entries: Le16,
    total_sectors_16: Le16,
    media: u8,
    sectors_per_fat_16: Le16,
    sectors_per_track: Le16,
    heads: Le16,
    hidden_sectors: Le32,
    total_sectors_32: Le32,
    // FAT32's extension.
    sectors_per_fat_32: Le32,
    mirroring_flags: Le16,
    version: Le16,
    root_cluster: Le32,
    fsinfo_sector: Le16,
    backup_boot_sector: Le16,
    reserved: [u8; 12],
    drive_number: u8,
    reserved_nt: u8,
    extended_signature: u8,
    volume_id: Le32,
    volume_label: [u8; 11],
    file_system_type: [u8; 8],
    boot_code: [u8; 420],
    signature: Le16,
}

// SAFETY: bytes and byte arrays only (`Le16` and `Le32` are byte arrays), so there is no padding
// (the size is asserted below) and every bit pattern is a value.
unsafe impl Pod for RawBootSector {}

const _: () = {
    assert!(size_of::<RawBootSector>() == 512);
    assert!(offset_of!(RawBootSector, bytes_per_sector) == 11);
    assert!(offset_of!(RawBootSector, sectors_per_cluster) == 13);
    assert!(offset_of!(RawBootSector, reserved_sectors) == 14);
    assert!(offset_of!(RawBootSector, fats) == 16);
    assert!(offset_of!(RawBootSector, root_entries) == 17);
    assert!(offset_of!(RawBootSector, total_sectors_16) == 19);
    assert!(offset_of!(RawBootSector, media) == 21);
    assert!(offset_of!(RawBootSector, sectors_per_fat_16) == 22);
    assert!(offset_of!(RawBootSector, total_sectors_32) == 32);
    assert!(offset_of!(RawBootSector, sectors_per_fat_32) == 36);
    assert!(offset_of!(RawBootSector, mirroring_flags) == 40);
    assert!(offset_of!(RawBootSector, version) == 42);
    assert!(offset_of!(RawBootSector, root_cluster) == 44);
    assert!(offset_of!(RawBootSector, fsinfo_sector) == 48);
    assert!(offset_of!(RawBootSector, backup_boot_sector) == 50);
    assert!(offset_of!(RawBootSector, volume_id) == 67);
    assert!(offset_of!(RawBootSector, boot_code) == 90);
    assert!(offset_of!(RawBootSector, signature) == 510);
};

/// Why a boot sector does not mount as FAT32: one variant per gate, carrying the offending value.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Refusal {
    /// Offset 510 is not 0xAA55.
    NoSignature(u16),
    /// Offset 0 is not a jump (0xE9, 0xEB, or 0x49).
    NotAJump(u8),
    /// Bytes per sector is not 512.
    SectorSize(u16),
    /// Sectors per cluster is not a power of two in 1..=128.
    ClusterSize(u8),
    NoReservedSectors,
    NoFats,
    /// FAT16-shaped: the root directory size is set.
    RootEntries(u16),
    /// FAT16-shaped: the 16-bit total is set.
    TotalSectors16(u16),
    /// FAT16-shaped: the 16-bit FAT size is set.
    SectorsPerFat16(u16),
    /// The 32-bit FAT size is zero.
    NoSectorsPerFat,
    /// The media byte is not a known descriptor.
    Media(u8),
    /// Fewer than 65525 clusters: a FAT12 or FAT16 volume.
    TooFewClusters(u32),
    /// The FAT32 version is not 0.
    Version(u16),
    /// The FSInfo sector is zero.
    NoFsInfo,
    /// The root cluster is not a data cluster of the volume.
    RootCluster(u32),
}

/// The jump opcodes a boot sector may start with: the near and short jumps, and 0x49, which older
/// tools wrote.
fn is_jump(opcode: u8) -> bool {
    matches!(opcode, 0xE9 | 0xEB | 0x49)
}

/// The known media descriptors: 0xF0 and 0xF8-0xFF, plus 0x00 and 0x01, which older tools wrote
/// (0xFA, also written by older tools, falls in the 0xF8-0xFF range already).
fn is_known_media(media: u8) -> bool {
    matches!(media, 0xF0 | 0xF8..=0xFF | 0x00 | 0x01)
}

/// The gate list: whether `sector` mounts as a FAT32 volume, and its layout if it does. The gates
/// run in a fixed order; the first failure is the refusal.
pub fn validate(sector: &[u8; 512]) -> Result<Layout, Refusal> {
    let boot = BootSector::decode(sector);

    if boot.signature != SIGNATURE {
        return Err(Refusal::NoSignature(boot.signature));
    }
    if !is_jump(boot.jump) {
        return Err(Refusal::NotAJump(boot.jump));
    }
    if boot.bytes_per_sector != 512 {
        return Err(Refusal::SectorSize(boot.bytes_per_sector));
    }
    // Every power of two that fits in a byte is at most 128.
    if !boot.sectors_per_cluster.is_power_of_two() {
        return Err(Refusal::ClusterSize(boot.sectors_per_cluster));
    }
    if boot.reserved_sectors == 0 {
        return Err(Refusal::NoReservedSectors);
    }
    if boot.fats == 0 {
        return Err(Refusal::NoFats);
    }
    if boot.root_entries != 0 {
        return Err(Refusal::RootEntries(boot.root_entries));
    }
    if boot.total_sectors_16 != 0 {
        return Err(Refusal::TotalSectors16(boot.total_sectors_16));
    }
    if boot.sectors_per_fat_16 != 0 {
        return Err(Refusal::SectorsPerFat16(boot.sectors_per_fat_16));
    }
    if boot.sectors_per_fat_32 == 0 {
        return Err(Refusal::NoSectorsPerFat);
    }
    if !is_known_media(boot.media) {
        return Err(Refusal::Media(boot.media));
    }

    // The clusters are what the data region holds; a volume too small to hold its own FATs has
    // none.
    let data_start =
        boot.reserved_sectors as u64 + boot.fats as u64 * boot.sectors_per_fat_32 as u64;
    let data_sectors = (boot.total_sectors_32 as u64).saturating_sub(data_start);
    let cluster_count = (data_sectors / boot.sectors_per_cluster as u64) as u32;
    if cluster_count < MIN_CLUSTERS {
        return Err(Refusal::TooFewClusters(cluster_count));
    }

    if boot.version != 0 {
        return Err(Refusal::Version(boot.version));
    }
    if boot.fsinfo_sector == 0 {
        return Err(Refusal::NoFsInfo);
    }
    let layout = Layout {
        sectors_per_cluster: boot.sectors_per_cluster as u32,
        fat_start: boot.reserved_sectors as u64,
        sectors_per_fat: boot.sectors_per_fat_32,
        data_start,
        cluster_count,
        root_cluster: boot.root_cluster,
    };
    if !layout.is_data_cluster(boot.root_cluster) {
        return Err(Refusal::RootCluster(boot.root_cluster));
    }
    Ok(layout)
}

#[cfg(test)]
mod tests {
    use super::super::fixtures::{built_layout, BUILT};
    use super::*;

    /// The built boot sector with `change` applied.
    fn built_with(change: impl FnOnce(&mut [u8; 512])) -> [u8; 512] {
        let mut sector = *BUILT;
        change(&mut sector);
        sector
    }

    fn put16(sector: &mut [u8; 512], offset: usize, value: u16) {
        sector[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put32(sector: &mut [u8; 512], offset: usize, value: u32) {
        sector[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    /// The decode reads every field at its offset: the built volume's values.
    #[test]
    fn the_built_boot_sector_decodes_at_its_offsets() {
        assert_eq!(
            BootSector::decode(BUILT),
            BootSector {
                jump: 0xEB,
                bytes_per_sector: 512,
                sectors_per_cluster: 1,
                reserved_sectors: 32,
                fats: 2,
                root_entries: 0,
                total_sectors_16: 0,
                media: 0xF0,
                sectors_per_fat_16: 0,
                total_sectors_32: 129_024,
                sectors_per_fat_32: 993,
                mirroring_flags: 0,
                version: 0,
                root_cluster: 2,
                fsinfo_sector: 1,
                backup_boot_sector: 6,
                signature: 0xAA55,
            }
        );
    }

    /// The built volume passes every gate: 127006 clusters, the FAT at 32, the data region at
    /// 32 + 2 x 993 = 2018, the root at cluster 2.
    #[test]
    fn the_built_volume_passes_every_gate() {
        assert_eq!(validate(BUILT), Ok(built_layout()));
    }

    /// Each gate refuses on its own, reporting which gate and the offending value.
    #[test]
    fn every_gate_refuses_distinctly() {
        let cases: [(fn(&mut [u8; 512]), Refusal); 15] = [
            (|s| put16(s, 510, 0x0000), Refusal::NoSignature(0)),
            (|s| s[0] = 0x00, Refusal::NotAJump(0x00)),
            (|s| put16(s, 11, 4096), Refusal::SectorSize(4096)),
            (|s| s[13] = 0, Refusal::ClusterSize(0)),
            (|s| put16(s, 14, 0), Refusal::NoReservedSectors),
            (|s| s[16] = 0, Refusal::NoFats),
            (|s| put16(s, 17, 512), Refusal::RootEntries(512)),
            (|s| put16(s, 19, 40_000), Refusal::TotalSectors16(40_000)),
            (|s| put16(s, 22, 200), Refusal::SectorsPerFat16(200)),
            (|s| put32(s, 36, 0), Refusal::NoSectorsPerFat),
            (|s| s[21] = 0xF1, Refusal::Media(0xF1)),
            (
                |s| put32(s, 32, 60_000),
                Refusal::TooFewClusters(60_000 - 2018),
            ),
            (|s| put16(s, 42, 1), Refusal::Version(1)),
            (|s| put16(s, 48, 0), Refusal::NoFsInfo),
            (|s| put32(s, 44, 1), Refusal::RootCluster(1)),
        ];
        for (change, refusal) in cases {
            assert_eq!(validate(&built_with(change)), Err(refusal));
        }
    }

    /// A FAT16-shaped boot sector — the root directory, 16-bit total and 16-bit FAT size set, the
    /// 32-bit fields empty — is refused at the first FAT16 field.
    #[test]
    fn a_fat16_shaped_boot_sector_is_refused() {
        let fat16 = built_with(|s| {
            put16(s, 17, 512);
            put16(s, 19, 40_000);
            put16(s, 22, 40);
            put32(s, 32, 0);
            put32(s, 36, 0);
        });
        assert_eq!(validate(&fat16), Err(Refusal::RootEntries(512)));
    }

    /// The cluster size is a power of two up to 128: 3 and 96 are refused, every power accepted
    /// (the cluster count shrinks with it, so the total grows to keep the volume FAT32).
    #[test]
    fn cluster_sizes_are_powers_of_two() {
        for bad in [3u8, 6, 96, 255] {
            assert_eq!(
                validate(&built_with(|s| s[13] = bad)),
                Err(Refusal::ClusterSize(bad))
            );
        }
        for power in [1u8, 2, 4, 8, 16, 32, 64, 128] {
            let sector = built_with(|s| {
                s[13] = power;
                put32(s, 32, 2018 + 70_000 * power as u32);
            });
            let layout = validate(&sector).unwrap();
            assert_eq!(layout.sectors_per_cluster, power as u32);
            assert_eq!(layout.cluster_count, 70_000);
        }
    }

    /// The cluster count's FAT32 floor is 65525 exactly; a volume too small to hold its own FATs
    /// counts no clusters rather than wrapping.
    #[test]
    fn the_cluster_count_floor() {
        let at = |clusters: u32| built_with(|s| put32(s, 32, 2018 + clusters));
        assert_eq!(validate(&at(65_525)).unwrap().cluster_count, 65_525);
        assert_eq!(validate(&at(65_524)), Err(Refusal::TooFewClusters(65_524)));
        assert_eq!(
            validate(&built_with(|s| put32(s, 32, 100))),
            Err(Refusal::TooFewClusters(0))
        );
    }

    /// The root cluster must be a data cluster: 2 through the cluster count plus one.
    #[test]
    fn the_root_cluster_is_a_data_cluster() {
        let root = |cluster: u32| validate(&built_with(|s| put32(s, 44, cluster)));
        assert!(root(2).is_ok());
        assert!(root(127_007).is_ok());
        assert_eq!(root(0), Err(Refusal::RootCluster(0)));
        assert_eq!(root(127_008), Err(Refusal::RootCluster(127_008)));
    }

    /// The compatibility values: jumps 0xE9, 0xEB, 0x49; media 0xF0, 0xF8-0xFF, 0x00, 0x01,
    /// 0xFA. Their neighbours are refused.
    #[test]
    fn the_compatibility_values_are_accepted() {
        for jump in [0xE9u8, 0xEB, 0x49] {
            assert!(
                validate(&built_with(|s| s[0] = jump)).is_ok(),
                "jump {jump:#x}"
            );
        }
        for jump in [0xE8u8, 0xEA, 0x48, 0x90] {
            assert_eq!(
                validate(&built_with(|s| s[0] = jump)),
                Err(Refusal::NotAJump(jump))
            );
        }
        let accepted = [
            0xF0u8, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF, 0x00, 0x01,
        ];
        for media in accepted {
            assert!(
                validate(&built_with(|s| s[21] = media)).is_ok(),
                "media {media:#x}"
            );
        }
        for media in [0x02u8, 0x80, 0xEF, 0xF1, 0xF7] {
            assert_eq!(
                validate(&built_with(|s| s[21] = media)),
                Err(Refusal::Media(media))
            );
        }
    }
}
