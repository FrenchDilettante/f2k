//! Directory listings: a directory's entries in order, each with its long name when it has one.
//!
//! A long name rides in the records just before its 8.3 entry, last part first, each part
//! numbered and carrying the checksum of the 8.3 name it belongs to. The walk assembles a run as it
//! goes and attaches it to the entry that follows only when the run is complete, its numbers
//! descend without a gap, and its checksum matches that entry — otherwise the entry stands alone,
//! as an orphaned run (one a long-name-unaware writer left behind) must. Deleted records and the
//! volume label break a run.
//!
//! An entry answers to either of its names, without regard to case: the long name compares unit
//! by unit after case folding (the program's bytes decoded through codepage 1252), the 8.3 name
//! through its stored form (in code page 437, see [`super::path`]). The name a listing shows is the
//! long name, or the 8.3 name with the NT case bits applied; the short name it shows beside a long
//! one is the 8.3 name as stored — both in code page 1252.

use super::dirent::{
    checksum,
    decode,
    DirEntry,
    LongPart,
    Record,
    CASE_LOWER_BASE,
    CASE_LOWER_EXTENSION,
    ENTRY_SIZE,
};
use super::fat::FatEntry;
use super::lookup::LookupError;
use super::path::{oem_to_ansi, short_form, MAX_NAME};
use super::volume::Volume;
use crate::status::nt_success;

/// The most parts a long-name run has: 20 parts of 13 units cover the 255-unit limit.
const MAX_PARTS: usize = 20;
/// Units per long-name part.
const PART_UNITS: usize = 13;

/// One entry of a listing.
#[derive(Clone, Copy)]
pub struct Listed {
    /// The 8.3 record.
    pub entry: DirEntry,
    /// The long name's units (the first `long_len`).
    long: [u16; MAX_NAME],
    long_len: usize,
    /// The 8.3 record's position in its directory, counted in records: the entry's identity
    /// within the directory.
    pub index: u32,
    /// Whether this is a subdirectory's `.` or `..` record.
    pub dot: bool,
}

impl Listed {
    /// The long name, when the entry has one.
    pub fn long_name(&self) -> Option<&[u16]> {
        (self.long_len != 0).then(|| &self.long[..self.long_len])
    }

    /// The name a listing shows (codepage 1252): the long name, else the 8.3 name with the NT case
    /// bits applied. Returns its length.
    pub fn name(&self, out: &mut [u8; MAX_NAME]) -> usize {
        match self.long_name() {
            Some(units) => {
                for (byte, &unit) in out.iter_mut().zip(units) {
                    *byte = rtl::cp1252::wc_to_mb(unit);
                }
                units.len()
            }
            None => format_short(&self.entry.name, self.entry.case, out),
        }
    }

    /// The 8.3 name as stored, formatted `NAME.EXT`. Returns its length.
    pub fn short_name(&self, out: &mut [u8; 12]) -> usize {
        format_short(&self.entry.name, 0, out)
    }

    /// Whether the entry answers to `name` (codepage 1252): its long name or its 8.3 name, without
    /// regard to case.
    pub fn matches(&self, name: &[u8]) -> bool {
        if let Some(units) = self.long_name() {
            if units.len() == name.len()
                && units
                    .iter()
                    .zip(name)
                    .all(|(&unit, &byte)| fold_unit(unit) == fold_unit(decode_byte(byte)))
            {
                return true;
            }
        }
        if self.dot {
            return false;
        }
        short_form(name).is_some_and(|stored| stored == self.entry.name)
    }
}

/// A codepage 1252 byte as a UTF-16 unit.
pub fn decode_byte(byte: u8) -> u16 {
    rtl::cp1252::MB_TO_WC[byte as usize]
}

/// A unit's case-folded form, for name comparison: upper case, over the units codepage 1252 maps.
pub fn fold_unit(unit: u16) -> u16 {
    match unit {
        0x61..=0x7A => unit - 0x20,
        0xE0..=0xFE if unit != 0xF7 => unit - 0x20,
        0xFF => 0x178,
        0x153 | 0x161 => unit - 1,
        0x17E => 0x17D,
        _ => unit,
    }
}

/// Format a stored 8.3 name as `NAME.EXT` (no dot without an extension) in code page 1252, lowering
/// the base or the extension as the NT case bits say (ASCII letters only). Returns its length.
pub fn format_short(name: &[u8; 11], case: u8, out: &mut [u8]) -> usize {
    let trimmed = |part: &[u8]| part.iter().rposition(|&b| b != b' ').map_or(0, |i| i + 1);
    let (base, extension) = (&name[..8], &name[8..]);
    let (base_len, extension_len) = (trimmed(base), trimmed(extension));
    let mut len = 0;
    for &byte in &base[..base_len] {
        let byte = if case & CASE_LOWER_BASE != 0 {
            byte.to_ascii_lowercase()
        } else {
            byte
        };
        out[len] = oem_to_ansi(byte);
        len += 1;
    }
    if extension_len != 0 {
        out[len] = b'.';
        len += 1;
        for &byte in &extension[..extension_len] {
            let byte = if case & CASE_LOWER_EXTENSION != 0 {
                byte.to_ascii_lowercase()
            } else {
                byte
            };
            out[len] = oem_to_ansi(byte);
            len += 1;
        }
    }
    len
}

/// A long-name run being assembled.
struct Run {
    units: [u16; MAX_PARTS * PART_UNITS],
    /// How many parts the run has (0: no run).
    parts: u8,
    /// The part expected next (counting down to 0, when the run is complete).
    expected: u8,
    checksum: u8,
}

impl Run {
    fn new() -> Run {
        Run {
            units: [0; MAX_PARTS * PART_UNITS],
            parts: 0,
            expected: 0,
            checksum: 0,
        }
    }

    fn reset(&mut self) {
        self.parts = 0;
        self.expected = 0;
    }

    fn take(&mut self, part: &LongPart) {
        let order = part.order as usize;
        if order == 0 {
            return self.reset();
        }
        if part.last {
            if order > MAX_PARTS {
                return self.reset();
            }
            self.parts = part.order;
            self.checksum = part.checksum;
        } else if self.parts == 0 || part.order != self.expected || part.checksum != self.checksum {
            return self.reset();
        }
        self.units[(order - 1) * PART_UNITS..order * PART_UNITS].copy_from_slice(&part.units);
        self.expected = part.order - 1;
    }

    /// The run's name for the 8.3 entry `entry`, when the run is complete and belongs to it; the
    /// run is consumed either way.
    fn finish(&mut self, entry: &DirEntry, out: &mut [u16; MAX_NAME]) -> usize {
        let complete =
            self.parts != 0 && self.expected == 0 && self.checksum == checksum(&entry.name);
        let parts = self.parts as usize;
        self.reset();
        if !complete {
            return 0;
        }
        let units = &self.units[..parts * PART_UNITS];
        let len = units
            .iter()
            .position(|&u| u == 0)
            .unwrap_or(units.len())
            .min(MAX_NAME);
        out[..len].copy_from_slice(&units[..len]);
        len
    }
}

/// Walk the directory starting at `cluster` in order — files, subdirectories, and the `.` and
/// `..` records — calling `visit` with each until it returns false or the directory ends.
pub fn walk(
    volume: &mut Volume,
    mut cluster: u32,
    mut visit: impl FnMut(&Listed) -> bool,
) -> Result<(), LookupError> {
    let layout = *volume.layout();
    let mut sector = [0u8; 512];
    let mut run = Run::new();
    let mut listed = Listed {
        entry: DirEntry {
            name: [0; 11],
            attributes: 0,
            case: 0,
            first_cluster: 0,
            size: 0,
            times: Default::default(),
        },
        long: [0; MAX_NAME],
        long_len: 0,
        index: 0,
        dot: false,
    };
    let mut index = 0u32;
    // A chain longer than the volume has clusters loops.
    for _ in 0..layout.cluster_count {
        if !layout.is_data_cluster(cluster) {
            return Err(LookupError::Corrupt);
        }
        let first = layout.cluster_lba(cluster);
        for offset in 0..layout.sectors_per_cluster as u64 {
            let status = volume.device().read(first + offset, &mut sector);
            if !nt_success(status) {
                return Err(LookupError::Device(status));
            }
            for bytes in sector.as_chunks::<ENTRY_SIZE>().0 {
                let record = decode(bytes);
                let (entry, dot) = match record {
                    Record::End => return Ok(()),
                    Record::LongName(part) => {
                        run.take(&part);
                        index += 1;
                        continue;
                    }
                    Record::Deleted | Record::VolumeLabel => {
                        run.reset();
                        index += 1;
                        continue;
                    }
                    Record::Dot(entry) => (entry, true),
                    Record::Entry(entry) => (entry, false),
                };
                listed.entry = entry;
                listed.dot = dot;
                listed.index = index;
                listed.long_len = run.finish(&entry, &mut listed.long);
                index += 1;
                if !visit(&listed) {
                    return Ok(());
                }
            }
        }
        cluster = match volume.fat_entry(cluster).map_err(LookupError::Device)? {
            FatEntry::Next(next) => next,
            FatEntry::EndOfChain => return Ok(()),
            FatEntry::Free | FatEntry::Bad | FatEntry::Corrupt(_) => {
                return Err(LookupError::Corrupt)
            }
        };
    }
    Err(LookupError::Corrupt)
}

/// Whether the directory starting at `cluster` holds nothing but its dot records (a delete-on-close
/// directory must: the write side deletes only an empty one). A broken directory is
/// STATUS_FILE_CORRUPT_ERROR, a failed read its status.
pub fn is_empty(volume: &mut Volume, cluster: u32) -> Result<bool, crate::status::NtStatus> {
    let mut empty = true;
    walk(volume, cluster, |listed| {
        empty = listed.dot;
        empty
    })
    .map_err(|error| match error {
        LookupError::Device(status) => status,
        _ => crate::status::STATUS_FILE_CORRUPT_ERROR,
    })?;
    Ok(empty)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::super::fixtures::{record, Crafted};
    use super::*;

    /// The long-name records of `name` for the 8.3 entry `short`, in disk order (last part first).
    pub(crate) fn long_records(name: &str, short: &[u8; 11]) -> Vec<[u8; 32]> {
        let mut units: Vec<u16> = name.encode_utf16().collect();
        let parts = units.len().div_ceil(PART_UNITS);
        if units.len() % PART_UNITS != 0 {
            units.push(0);
        }
        units.resize(parts * PART_UNITS, 0xFFFF);
        let sum = checksum(short);
        let offsets: Vec<usize> = (1..11)
            .step_by(2)
            .chain((14..26).step_by(2))
            .chain((28..32).step_by(2))
            .collect();
        (1..=parts)
            .rev()
            .map(|order| {
                let mut bytes = [0u8; 32];
                bytes[0] = order as u8 | if order == parts { 0x40 } else { 0 };
                bytes[11] = 0x0F;
                bytes[13] = sum;
                for (i, &offset) in offsets.iter().enumerate() {
                    let unit = units[(order - 1) * PART_UNITS + i];
                    bytes[offset..offset + 2].copy_from_slice(&unit.to_le_bytes());
                }
                bytes
            })
            .collect()
    }

    fn names(volume: &mut Volume, cluster: u32) -> Vec<(String, String)> {
        let mut out = Vec::new();
        walk(volume, cluster, |listed| {
            let mut name = [0u8; MAX_NAME];
            let mut short = [0u8; 12];
            let n = listed.name(&mut name);
            let s = listed.short_name(&mut short);
            out.push((
                String::from_utf8_lossy(&name[..n]).into_owned(),
                String::from_utf8_lossy(&short[..s]).into_owned(),
            ));
            true
        })
        .unwrap();
        out
    }

    /// A long name spanning two parts attaches to its entry; plain 8.3 entries show their stored
    /// name (lowered by the case bits); the dot records are listed.
    #[test]
    fn a_listing_carries_long_names() {
        let mut records = vec![
            record(b".          ", 0x10, 3, 0),
            record(b"..         ", 0x10, 0, 0),
        ];
        records.extend(long_records("Long File Name.txt", b"LONGFI~1TXT"));
        records.push(record(b"LONGFI~1TXT", 0x20, 4, 11));
        records.push(record(b"SMALL   TXT", 0x20, 5, 31));
        let mut lower = record(b"README  TXT", 0x20, 6, 1);
        lower[12] = CASE_LOWER_BASE | CASE_LOWER_EXTENSION;
        records.push(lower);
        let mut crafted = Crafted::new(1, 8);
        crafted.directory(2, &records);
        let mut volume = Volume::mount(crafted.device()).unwrap();
        assert_eq!(
            names(&mut volume, 2),
            vec![
                (".".into(), ".".into()),
                ("..".into(), "..".into()),
                ("Long File Name.txt".into(), "LONGFI~1.TXT".into()),
                ("SMALL.TXT".into(), "SMALL.TXT".into()),
                ("readme.txt".into(), "README.TXT".into()),
            ]
        );
    }

    /// A run whose checksum belongs to another name, or with a part missing, is orphaned: the
    /// entry after it stands alone.
    #[test]
    fn a_broken_run_is_dropped() {
        let mut records = long_records("Another Name.txt", b"ANOTHE~1TXT");
        records.push(record(b"WRONG   TXT", 0x20, 4, 1));
        let mut gap = long_records("A Name Of Three Parts Long.txt", b"ANAMEO~1TXT");
        gap.remove(1);
        records.extend(gap);
        records.push(record(b"ANAMEO~1TXT", 0x20, 5, 1));
        let mut crafted = Crafted::new(1, 8);
        crafted.directory(2, &records);
        let mut volume = Volume::mount(crafted.device()).unwrap();
        let listed = names(&mut volume, 2);
        assert_eq!(listed[0].0, "WRONG.TXT");
        assert_eq!(listed[1].0, "ANAMEO~1.TXT");
    }

    /// A long-name record numbered 0 after a complete run (a corrupt one) breaks the run instead
    /// of panicking the walk: the entry after it stands alone.
    #[test]
    fn a_part_numbered_zero_breaks_the_run() {
        let mut records = long_records("Name.txt", b"NAME~1  TXT");
        let mut zero = records[0];
        zero[0] = 0x20;
        records.push(zero);
        records.push(record(b"NAME~1  TXT", 0x20, 4, 1));
        let mut crafted = Crafted::new(1, 8);
        crafted.directory(2, &records);
        let mut volume = Volume::mount(crafted.device()).unwrap();
        assert_eq!(
            names(&mut volume, 2),
            vec![("NAME~1.TXT".into(), "NAME~1.TXT".into())]
        );
    }

    /// A stored 8.3 name is code page 437: a listing shows it in code page 1252, and a name
    /// matches it through the same code page — in either case, while a 1252 byte that is the 437
    /// byte's value but another character does not.
    #[test]
    fn short_names_are_code_page_437() {
        let mut crafted = Crafted::new(1, 8);
        crafted.directory(
            2,
            &[
                record(b"CAF\x90    TXT", 0x20, 4, 1),
                record(b"\x8E       \x9A  ", 0x20, 5, 1),
            ],
        );
        let mut volume = Volume::mount(crafted.device()).unwrap();
        let mut seen = Vec::new();
        walk(&mut volume, 2, |listed| {
            let (mut name, mut short) = ([0u8; MAX_NAME], [0u8; 12]);
            let (n, s) = (listed.name(&mut name), listed.short_name(&mut short));
            seen.push((name[..n].to_vec(), short[..s].to_vec(), *listed));
            true
        })
        .unwrap();
        assert_eq!(seen[0].0, b"CAF\xC9.TXT");
        assert_eq!(seen[0].1, b"CAF\xC9.TXT");
        assert_eq!(seen[1].0, b"\xC4.\xDC");
        for name in [&b"caf\xE9.txt"[..], b"CAF\xC9.TXT"] {
            assert!(seen[0].2.matches(name), "{name:?}");
        }
        assert!(!seen[0].2.matches(b"CAF\x90.TXT"));
        assert!(seen[1].2.matches(b"\xE4.\xFC"));
    }

    /// A directory is empty while it holds its dot records alone: deleted records do not count, a
    /// file or a subdirectory does.
    #[test]
    fn emptiness_is_the_dot_records_alone() {
        let mut deleted = record(b"GONE    TXT", 0x20, 5, 1);
        deleted[0] = 0xE5;
        let mut crafted = Crafted::new(1, 8);
        crafted.directory(
            2,
            &[
                record(b".          ", 0x10, 2, 0),
                record(b"..         ", 0x10, 0, 0),
                deleted,
            ],
        );
        crafted.directory(
            3,
            &[
                record(b".          ", 0x10, 3, 0),
                record(b"SUB        ", 0x10, 4, 0),
            ],
        );
        crafted.fat(3, 0x0FFF_FFFF);
        let mut volume = Volume::mount(crafted.device()).unwrap();
        assert_eq!(is_empty(&mut volume, 2), Ok(true));
        assert_eq!(is_empty(&mut volume, 3), Ok(false));
    }

    /// An entry answers to its long name in any case and to its 8.3 name; a dot record to neither.
    #[test]
    fn entries_match_either_name() {
        let mut records = long_records("Long File Name.txt", b"LONGFI~1TXT");
        records.push(record(b"LONGFI~1TXT", 0x20, 4, 11));
        let mut crafted = Crafted::new(1, 8);
        crafted.directory(2, &records);
        let mut volume = Volume::mount(crafted.device()).unwrap();
        let mut found = None;
        walk(&mut volume, 2, |listed| {
            found = Some(*listed);
            false
        })
        .unwrap();
        let listed = found.unwrap();
        assert_eq!(listed.index, 2, "after its two long-name records");
        for name in [
            &b"Long File Name.txt"[..],
            b"LONG FILE NAME.TXT",
            b"long file name.txt",
            b"LONGFI~1.TXT",
            b"longfi~1.txt",
        ] {
            assert!(listed.matches(name), "{:?}", core::str::from_utf8(name));
        }
        for name in [
            &b"Long File Name"[..],
            b"LONGFI~1",
            b"Long File Name.txt.bak",
        ] {
            assert!(!listed.matches(name), "{:?}", core::str::from_utf8(name));
        }
    }
}
