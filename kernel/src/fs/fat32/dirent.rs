//! Directory entries: one 32-byte record of a directory, decoded into what the walk acts on.
//!
//! The first byte is structural — 0x00 ends the directory, 0xE5 marks a deleted entry, and 0x05
//! stands for a name that really starts with 0xE5. A long-file-name record (attributes 0x0F)
//! carries 13 UTF-16 units of the name of the 8.3 entry it precedes (see [`super::dir`]); the
//! volume label is told apart, and so are a subdirectory's `.` and `..` records, which the path
//! layer resolves itself and a directory listing shows.

/// Bytes per directory entry.
pub const ENTRY_SIZE: usize = 32;

/// Attribute bits.
pub const ATTR_READ_ONLY: u8 = 0x01;
pub const ATTR_HIDDEN: u8 = 0x02;
pub const ATTR_SYSTEM: u8 = 0x04;
pub const ATTR_VOLUME_LABEL: u8 = 0x08;
pub const ATTR_DIRECTORY: u8 = 0x10;
/// The attribute value of a long-file-name record.
pub const ATTR_LONG_NAME: u8 = 0x0F;

/// A name or extension byte that pads.
const SPACE: u8 = b' ';

/// The NT case bits (byte 12): an 8.3 name stored without a long name shows its base or its
/// extension in lower case.
pub const CASE_LOWER_BASE: u8 = 0x08;
pub const CASE_LOWER_EXTENSION: u8 = 0x10;

/// A record's timestamps, as stored: local time, in the FAT date and time encodings (a date's
/// year counts from 1980, a time's seconds in units of two; the creation time adds hundredths).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Times {
    pub create_hundredths: u8,
    pub create_time: u16,
    pub create_date: u16,
    pub access_date: u16,
    pub write_time: u16,
    pub write_date: u16,
}

/// A file or subdirectory's record.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DirEntry {
    /// The stored 8.3 name: 8 name bytes and 3 extension bytes, space-padded, the 0x05 escape
    /// already undone.
    pub name: [u8; 11],
    pub attributes: u8,
    /// The NT case bits.
    pub case: u8,
    /// The first cluster, both halves combined (0 for an empty file).
    pub first_cluster: u32,
    /// The size in bytes (0 for a directory).
    pub size: u32,
    pub times: Times,
}

impl DirEntry {
    pub fn is_directory(&self) -> bool {
        self.attributes & ATTR_DIRECTORY != 0
    }
}

/// One long-file-name record: its place in the name and the units it carries.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct LongPart {
    /// The part's ordinal, 1 for the name's first 13 units.
    pub order: u8,
    /// Whether this is the name's last part (the first record of the run on disk).
    pub last: bool,
    /// The checksum of the 8.3 name the run belongs to.
    pub checksum: u8,
    /// The units, NUL-terminated and 0xFFFF-padded in the last part.
    pub units: [u16; 13],
}

/// The checksum a long-name run carries of its 8.3 entry's stored name.
pub fn checksum(name: &[u8; 11]) -> u8 {
    name.iter()
        .fold(0u8, |sum, &byte| sum.rotate_right(1).wrapping_add(byte))
}

/// What one 32-byte record is.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Record {
    /// No entries follow in this directory.
    End,
    Deleted,
    /// A long-file-name record.
    LongName(LongPart),
    VolumeLabel,
    /// A subdirectory's `.` or `..` record.
    Dot(DirEntry),
    Entry(DirEntry),
}

/// Decode one record (`bytes` is exactly one entry).
pub fn decode(bytes: &[u8]) -> Record {
    assert_eq!(bytes.len(), ENTRY_SIZE, "a directory entry is 32 bytes");
    match bytes[0] {
        0x00 => return Record::End,
        0xE5 => return Record::Deleted,
        _ => {}
    }
    let attributes = bytes[11];
    let u16_at = |offset: usize| u16::from_le_bytes([bytes[offset], bytes[offset + 1]]);
    // A long-name record's attributes include the label bit, so it is told apart first.
    if attributes == ATTR_LONG_NAME {
        let mut units = [0u16; 13];
        let offsets = (1..11).step_by(2).chain((14..26).step_by(2)).chain((28..32).step_by(2));
        for (unit, offset) in units.iter_mut().zip(offsets) {
            *unit = u16_at(offset);
        }
        return Record::LongName(LongPart {
            order: bytes[0] & 0x1F,
            last: bytes[0] & 0x40 != 0,
            checksum: bytes[13],
            units,
        });
    }
    if attributes & ATTR_VOLUME_LABEL != 0 {
        return Record::VolumeLabel;
    }
    let mut name = [0u8; 11];
    name.copy_from_slice(&bytes[..11]);
    let dot = name == *b".          " || name == *b"..         ";
    if name[0] == 0x05 {
        name[0] = 0xE5;
    }
    let entry = DirEntry {
        name,
        attributes,
        case: bytes[12],
        first_cluster: (u16_at(20) as u32) << 16 | u16_at(26) as u32,
        size: u32::from_le_bytes([bytes[28], bytes[29], bytes[30], bytes[31]]),
        times: Times {
            create_hundredths: bytes[13],
            create_time: u16_at(14),
            create_date: u16_at(16),
            access_date: u16_at(18),
            write_time: u16_at(22),
            write_date: u16_at(24),
        },
    };
    if dot {
        Record::Dot(entry)
    } else {
        Record::Entry(entry)
    }
}

/// The stored form of an 8.3 name from its parts: the name and extension bytes, space-padded (the
/// caller folds the case).
pub fn stored_name(base: &[u8], extension: &[u8]) -> [u8; 11] {
    assert!(base.len() <= 8 && extension.len() <= 3, "an 8.3 name");
    let mut name = [SPACE; 11];
    name[..base.len()].copy_from_slice(base);
    name[8..8 + extension.len()].copy_from_slice(extension);
    name
}

#[cfg(test)]
mod tests {
    use super::super::fixtures::record;
    use super::*;

    /// A file record decodes at its offsets.
    #[test]
    fn a_file_record_decodes() {
        let bytes = record(b"HELLO   EXE", 0x20, 3, 28_672);
        assert_eq!(
            decode(&bytes),
            Record::Entry(DirEntry {
                name: *b"HELLO   EXE",
                attributes: 0x20,
                case: 0,
                first_cluster: 3,
                size: 28_672,
                times: Times::default(),
            })
        );
    }

    /// The first cluster is split across two fields: the high half at 20, the low at 26.
    #[test]
    fn the_first_cluster_combines_both_halves() {
        let bytes = record(b"BIG     DAT", 0x20, 0x0012_3456, 1);
        match decode(&bytes) {
            Record::Entry(entry) => assert_eq!(entry.first_cluster, 0x0012_3456),
            other => panic!("{other:?}"),
        }
        let mut high_only = [0u8; 32];
        high_only[..11].copy_from_slice(b"HIGH       ");
        high_only[20] = 0x01;
        assert!(matches!(decode(&high_only), Record::Entry(e) if e.first_cluster == 0x0001_0000));
    }

    /// The structural records: the end, a deleted entry, a long-name record, the label, and the
    /// two dot records — and a subdirectory is an entry like a file.
    #[test]
    fn structural_records_are_told_apart() {
        assert_eq!(decode(&[0u8; 32]), Record::End);
        let mut deleted = record(b"HELLO   EXE", 0x20, 3, 1);
        deleted[0] = 0xE5;
        assert_eq!(decode(&deleted), Record::Deleted);
        assert!(matches!(
            decode(&record(b"Af\x002\x00k\x00-\x00k\x00", 0x0F, 0, 0)),
            Record::LongName(part) if part.order == 1 && part.last && part.units[0] == u16::from(b'f')
        ));
        assert_eq!(
            decode(&record(b"F2K        ", 0x08, 0, 0)),
            Record::VolumeLabel
        );
        assert!(matches!(decode(&record(b".          ", 0x10, 9, 0)), Record::Dot(e) if e.first_cluster == 9));
        assert!(matches!(decode(&record(b"..         ", 0x10, 0, 0)), Record::Dot(_)));
        match decode(&record(b"BOOT       ", 0x10, 59, 0)) {
            Record::Entry(entry) => assert!(entry.is_directory()),
            other => panic!("{other:?}"),
        }
    }

    /// The 0x05 escape stands for a name whose first byte really is 0xE5 — not a deleted entry.
    #[test]
    fn the_escape_restores_a_leading_e5() {
        let mut bytes = record(b"XNAME   TXT", 0x20, 5, 10);
        bytes[0] = 0x05;
        match decode(&bytes) {
            Record::Entry(entry) => assert_eq!(&entry.name, b"\xE5NAME   TXT"),
            other => panic!("{other:?}"),
        }
    }

    /// The checksum a long name carries of its 8.3 entry (the rotate-and-add over the 11 bytes).
    #[test]
    fn the_short_name_checksum() {
        let mut sum = 0u8;
        for &byte in b"LONGFI~1TXT" {
            sum = (if sum & 1 != 0 { 0x80u8 } else { 0 })
                .wrapping_add(sum >> 1)
                .wrapping_add(byte);
        }
        assert_eq!(checksum(b"LONGFI~1TXT"), sum);
    }

    /// The timestamps and the case bits decode at their offsets.
    #[test]
    fn the_timestamps_decode() {
        let mut bytes = record(b"SMALL   TXT", 0x20, 5, 31);
        bytes[12] = CASE_LOWER_EXTENSION;
        bytes[13] = 57;
        bytes[14..16].copy_from_slice(&0x1234u16.to_le_bytes());
        bytes[16..18].copy_from_slice(&0x5678u16.to_le_bytes());
        bytes[18..20].copy_from_slice(&0x5679u16.to_le_bytes());
        bytes[22..24].copy_from_slice(&0x9ABCu16.to_le_bytes());
        bytes[24..26].copy_from_slice(&0x567Au16.to_le_bytes());
        match decode(&bytes) {
            Record::Entry(entry) => {
                assert_eq!(entry.case, CASE_LOWER_EXTENSION);
                assert_eq!(
                    entry.times,
                    Times {
                        create_hundredths: 57,
                        create_time: 0x1234,
                        create_date: 0x5678,
                        access_date: 0x5679,
                        write_time: 0x9ABC,
                        write_date: 0x567A,
                    }
                );
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn stored_names_are_space_padded() {
        assert_eq!(stored_name(b"HELLO", b"EXE"), *b"HELLO   EXE");
        assert_eq!(stored_name(b"BOOT", b""), *b"BOOT       ");
    }
}
