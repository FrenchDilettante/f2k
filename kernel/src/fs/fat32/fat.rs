//! The File Allocation Table: entry decode, and a small cache of recently used FAT sectors.
//!
//! An entry is 32 bits, little-endian, of which the low 28 count. FAT1 — the first copy — is the
//! one read; the mirror copies only matter to writes. The FAT is large (the built volume's is 993
//! sectors, about half a megabyte), so the kernel never holds it whole: entries are read through
//! the device, one sector at a time, through a few cached sectors ([`super::cache`]). A sector is
//! held as its bytes, its 128 entries read and written in place ([`raw_entry`]).

use core::fmt;

use super::cache::Sector;

/// The bits of an entry that count.
pub const ENTRY_MASK: u32 = 0x0FFF_FFFF;
/// The bad-cluster marker.
pub const BAD: u32 = 0x0FFF_FFF7;
/// The end-of-chain markers start here and run to the mask.
pub const END_OF_CHAIN: u32 = 0x0FFF_FFF8;
/// Entries per 512-byte FAT sector.
pub const ENTRIES_PER_SECTOR: u32 = 128;

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

/// How many FAT sectors the volume's cache holds ([`super::cache`]): enough for a walk along a
/// long directory's chain and the file's own chain together, and for an allocation's search.
pub const CACHE_SECTORS: usize = 16;

/// The raw 32-bit entry `index` of a FAT sector's bytes.
pub fn raw_entry(sector: &Sector, index: usize) -> u32 {
    u32::from_le_bytes(sector[index * 4..index * 4 + 4].try_into().unwrap())
}

/// Set the raw 32-bit entry `index` of a FAT sector's bytes.
pub fn set_raw_entry(sector: &mut Sector, index: usize, raw: u32) {
    sector[index * 4..index * 4 + 4].copy_from_slice(&raw.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(raw_entry(&bytes, 3), 0x0102_0304);
        set_raw_entry(&mut bytes, 4, 0x0A0B_0C0D);
        assert_eq!(bytes[16..20], [0x0D, 0x0C, 0x0B, 0x0A]);
    }

    #[test]
    fn entries_display_for_the_diagnostic() {
        assert_eq!(FatEntry::Next(4).to_string(), "4");
        assert_eq!(FatEntry::EndOfChain.to_string(), "end of chain");
        assert_eq!(FatEntry::Corrupt(1).to_string(), "corrupt (0x00000001)");
    }
}
