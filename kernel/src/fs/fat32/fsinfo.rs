//! The FSInfo sector: FAT32's hints of how many clusters are free and where a search for one should
//! start, kept in a sector of the reserved area the boot sector names.
//!
//! The layout is the FAT32 specification's (Microsoft's "FAT: General Overview of On-Disk Format",
//! FSInfo Sector Structure): a lead signature at offset 0, 480 reserved bytes, a structure
//! signature at 484, the free-cluster count at 488, the next-free hint at 492, 12 reserved bytes,
//! and a trail signature at 508. Both counts are hints: 0xFFFFFFFF means unknown, and a driver
//! range-checks either before trusting it. The specification also keeps a copy of the boot record,
//! FSInfo included, at the backup boot sector; the volume keeps that copy in step only where one
//! is already there (a formatter may leave the backup boot sector alone, as mformat does).

use core::mem::{offset_of, size_of};

use rtl::pod::Pod;

use super::raw::Le32;

/// FSI_LeadSig: "RRaA".
pub const LEAD_SIGNATURE: u32 = 0x4161_5252;
/// FSI_StrucSig: "rrAa".
pub const STRUCT_SIGNATURE: u32 = 0x6141_7272;
/// FSI_TrailSig: the boot sector's 0xAA55, in the high word.
pub const TRAIL_SIGNATURE: u32 = 0xAA55_0000;
/// A count or hint not known: the reader computes it.
pub const UNKNOWN: u32 = 0xFFFF_FFFF;

/// The FSInfo sector as stored.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FsInfo {
    lead_signature: Le32,
    reserved1: [u8; 480],
    struct_signature: Le32,
    free_count: Le32,
    next_free: Le32,
    reserved2: [u8; 12],
    trail_signature: Le32,
}

// SAFETY: byte arrays only (`Le32` is one), so there is no padding (the size is asserted below)
// and every bit pattern is a value.
unsafe impl Pod for FsInfo {}

const _: () = {
    assert!(size_of::<FsInfo>() == 512);
    assert!(offset_of!(FsInfo, lead_signature) == 0);
    assert!(offset_of!(FsInfo, struct_signature) == 484);
    assert!(offset_of!(FsInfo, free_count) == 488);
    assert!(offset_of!(FsInfo, next_free) == 492);
    assert!(offset_of!(FsInfo, trail_signature) == 508);
};

impl FsInfo {
    /// Whether the sector carries FSInfo's three signatures: only then are its counts FSInfo's.
    pub fn is_valid(&self) -> bool {
        self.lead_signature.get() == LEAD_SIGNATURE
            && self.struct_signature.get() == STRUCT_SIGNATURE
            && self.trail_signature.get() == TRAIL_SIGNATURE
    }

    /// The free-cluster count (or [`UNKNOWN`]).
    pub fn free_count(&self) -> u32 {
        self.free_count.get()
    }

    /// The cluster a free-cluster search should start at (or [`UNKNOWN`]).
    pub fn next_free(&self) -> u32 {
        self.next_free.get()
    }

    /// Set both hints; the signatures and reserved bytes stay as they are.
    pub fn set_hints(&mut self, free_count: u32, next_free: u32) {
        self.free_count.set(free_count);
        self.next_free.set(next_free);
    }

    /// The free count, if it is one a volume of `clusters` data clusters can have.
    pub fn plausible_free_count(&self, clusters: u32) -> Option<u32> {
        Some(self.free_count()).filter(|&count| count <= clusters)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The sector mformat wrote on the built disk: the signatures at their offsets, its counts.
    fn formatted(free: u32, next: u32) -> [u8; 512] {
        let mut sector = [0u8; 512];
        sector[0..4].copy_from_slice(b"RRaA");
        sector[484..488].copy_from_slice(b"rrAa");
        sector[488..492].copy_from_slice(&free.to_le_bytes());
        sector[492..496].copy_from_slice(&next.to_le_bytes());
        sector[508..512].copy_from_slice(&[0x00, 0x00, 0x55, 0xAA]);
        sector
    }

    /// The signatures are the specification's bytes, and the counts read from their offsets.
    #[test]
    fn a_formatted_sector_decodes() {
        let info: FsInfo = super::super::raw::from_block(&formatted(90_123, 36_884));
        assert!(info.is_valid());
        assert_eq!(info.free_count(), 90_123);
        assert_eq!(info.next_free(), 36_884);
        assert_eq!(info.plausible_free_count(127_006), Some(90_123));
        assert_eq!(info.plausible_free_count(90_000), None);
    }

    /// Setting the hints writes their offsets alone.
    #[test]
    fn the_hints_are_written_at_their_offsets() {
        let mut info: FsInfo = super::super::raw::from_block(&formatted(1, 2));
        info.set_hints(UNKNOWN, 0x1234);
        let bytes: [u8; 512] = super::super::raw::to_block(&info);
        let mut expected = formatted(UNKNOWN, 0x1234);
        assert_eq!(bytes, expected);
        assert_eq!(info.plausible_free_count(u32::MAX - 1), None, "unknown");
        expected[0] = 0;
        let broken: FsInfo = super::super::raw::from_block(&expected);
        assert!(!broken.is_valid(), "a lead signature missing");
    }

    /// Any one signature missing makes the sector something else.
    #[test]
    fn every_signature_counts() {
        for at in [0, 484, 508] {
            let mut sector = formatted(0, 0);
            sector[at + 2] ^= 0xFF;
            let info: FsInfo = super::super::raw::from_block(&sector);
            assert!(!info.is_valid(), "the signature at {at}");
        }
    }
}
