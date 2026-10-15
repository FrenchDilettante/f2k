//! Directory entries: one 32-byte record of a directory, decoded into what the walk acts on.
//!
//! The first byte is structural — 0x00 ends the directory, 0xE5 marks a deleted entry, and 0x05
//! stands for a name that really starts with 0xE5. Long-file-name records (attributes 0x0F) and
//! the volume label are skipped, and so are a subdirectory's `.` and `..` records: the path layer
//! resolves those itself.

/// Bytes per directory entry.
pub const ENTRY_SIZE: usize = 32;

/// Attribute bits.
pub const ATTR_VOLUME_LABEL: u8 = 0x08;
pub const ATTR_DIRECTORY: u8 = 0x10;
/// The attribute value of a long-file-name record.
pub const ATTR_LONG_NAME: u8 = 0x0F;

/// A name or extension byte that pads.
const SPACE: u8 = b' ';

/// A file or subdirectory's record.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DirEntry {
    /// The stored 8.3 name: 8 name bytes and 3 extension bytes, space-padded, the 0x05 escape
    /// already undone.
    pub name: [u8; 11],
    pub attributes: u8,
    /// The first cluster, both halves combined (0 for an empty file).
    pub first_cluster: u32,
    /// The size in bytes (0 for a directory).
    pub size: u32,
}

impl DirEntry {
    pub fn is_directory(&self) -> bool {
        self.attributes & ATTR_DIRECTORY != 0
    }
}

/// What one 32-byte record is.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Record {
    /// No entries follow in this directory.
    End,
    Deleted,
    /// A long-file-name record.
    LongName,
    VolumeLabel,
    /// A subdirectory's `.` or `..` record.
    Dot,
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
    // A long-name record's attributes include the label bit, so it is told apart first.
    if attributes == ATTR_LONG_NAME {
        return Record::LongName;
    }
    if attributes & ATTR_VOLUME_LABEL != 0 {
        return Record::VolumeLabel;
    }
    let mut name = [0u8; 11];
    name.copy_from_slice(&bytes[..11]);
    if name == *b".          " || name == *b"..         " {
        return Record::Dot;
    }
    if name[0] == 0x05 {
        name[0] = 0xE5;
    }
    let u16_at = |offset: usize| u16::from_le_bytes([bytes[offset], bytes[offset + 1]]);
    Record::Entry(DirEntry {
        name,
        attributes,
        first_cluster: (u16_at(20) as u32) << 16 | u16_at(26) as u32,
        size: u32::from_le_bytes([bytes[28], bytes[29], bytes[30], bytes[31]]),
    })
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
                first_cluster: 3,
                size: 28_672,
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
        assert_eq!(
            decode(&record(b"Af\x002\x00k\x00-\x00k\x00", 0x0F, 0, 0)),
            Record::LongName
        );
        assert_eq!(
            decode(&record(b"F2K        ", 0x08, 0, 0)),
            Record::VolumeLabel
        );
        assert_eq!(decode(&record(b".          ", 0x10, 9, 0)), Record::Dot);
        assert_eq!(decode(&record(b"..         ", 0x10, 0, 0)), Record::Dot);
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

    #[test]
    fn stored_names_are_space_padded() {
        assert_eq!(stored_name(b"HELLO", b"EXE"), *b"HELLO   EXE");
        assert_eq!(stored_name(b"BOOT", b""), *b"BOOT       ");
    }
}
