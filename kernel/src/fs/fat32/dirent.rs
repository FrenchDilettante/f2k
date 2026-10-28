//! Directory entries: one 32-byte record of a directory, decoded into what the walk acts on.
//!
//! The first byte is structural — 0x00 ends the directory, 0xE5 marks a deleted entry, and 0x05
//! stands for a name that really starts with 0xE5. A long-file-name record (attributes 0x0F)
//! carries 13 UTF-16 units of the name of the 8.3 entry it precedes (see [`super::dir`]); the
//! volume label is told apart, and so are a subdirectory's `.` and `..` records, which the path
//! layer resolves itself and a directory listing shows.
//!
//! A record's two shapes are [`RawDirEntry`] and [`RawLongEntry`], `#[repr(C)]` over little-endian
//! byte fields: a record is read from its 32 bytes by value, and written back as bytes.

use core::mem::{offset_of, size_of};

use rtl::pod::Pod;

use super::raw::{from_block, to_block, Le16, Le32};

/// Bytes per directory entry.
pub const ENTRY_SIZE: usize = 32;

/// One record's bytes, as a directory sector holds them.
pub type RecordBytes = [u8; ENTRY_SIZE];

/// The first byte of the record that ends the directory: none follows it.
pub const END: u8 = 0x00;
/// The first byte of a deleted record.
pub const DELETED: u8 = 0xE5;
/// The first byte stored for an 8.3 name that really starts with 0xE5, which would read as
/// [`DELETED`].
pub const ESCAPED_E5: u8 = 0x05;

/// A long-name record's order byte: the flag on the name's last part (the first record of the run
/// on disk), and the mask of the part's number.
pub const LAST_LONG_PART: u8 = 0x40;
pub const ORDER_MASK: u8 = 0x1F;
/// Units per long-name record.
pub const PART_UNITS: usize = 13;

/// The stored names of a subdirectory's `.` and `..` records.
pub const DOT: [u8; 11] = *b".          ";
pub const DOT_DOT: [u8; 11] = *b"..         ";

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
    pub units: [u16; PART_UNITS],
}

impl LongPart {
    /// The record that stores this part.
    pub fn record(&self) -> RawLongEntry {
        let mut record = RawLongEntry::zeroed();
        record.ord = self.order | if self.last { LAST_LONG_PART } else { 0 };
        record.attr = ATTR_LONG_NAME;
        record.checksum = self.checksum;
        for (field, &unit) in record.unit_fields().zip(&self.units) {
            field.set(unit);
        }
        record
    }
}

/// An 8.3 record as stored (Microsoft's FAT specification's field names).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RawDirEntry {
    /// The 8.3 name, its first byte escaped (see [`ESCAPED_E5`]) or structural.
    pub name: [u8; 11],
    pub attr: u8,
    /// The NT case bits.
    pub nt_res: u8,
    /// The creation time's hundredths.
    pub crt_tenth: u8,
    pub crt_time: Le16,
    pub crt_date: Le16,
    pub acc_date: Le16,
    /// The first cluster's high half.
    pub clus_hi: Le16,
    pub wrt_time: Le16,
    pub wrt_date: Le16,
    /// The first cluster's low half.
    pub clus_lo: Le16,
    pub size: Le32,
}

/// A long-name record as stored: its 13 units in three runs around the fields it shares with an
/// 8.3 record's layout (the attributes at 11, a first cluster of zero at 26).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RawLongEntry {
    /// The order byte: the part's number and the [`LAST_LONG_PART`] flag.
    pub ord: u8,
    pub name1: [Le16; 5],
    /// Always [`ATTR_LONG_NAME`].
    pub attr: u8,
    /// Zero: a long-name component.
    pub kind: u8,
    /// The checksum of the 8.3 name the run belongs to.
    pub checksum: u8,
    pub name2: [Le16; 6],
    /// Zero.
    pub clus_lo: Le16,
    pub name3: [Le16; 2],
}

// SAFETY: bytes and byte arrays only (`Le16` and `Le32` are byte arrays), so there is no padding
// (the sizes are asserted below) and every bit pattern is a value.
unsafe impl Pod for RawDirEntry {}
// SAFETY: as for `RawDirEntry`.
unsafe impl Pod for RawLongEntry {}

const _: () = {
    assert!(size_of::<RawDirEntry>() == ENTRY_SIZE);
    assert!(offset_of!(RawDirEntry, attr) == 11);
    assert!(offset_of!(RawDirEntry, nt_res) == 12);
    assert!(offset_of!(RawDirEntry, crt_tenth) == 13);
    assert!(offset_of!(RawDirEntry, crt_time) == 14);
    assert!(offset_of!(RawDirEntry, crt_date) == 16);
    assert!(offset_of!(RawDirEntry, acc_date) == 18);
    assert!(offset_of!(RawDirEntry, clus_hi) == 20);
    assert!(offset_of!(RawDirEntry, wrt_time) == 22);
    assert!(offset_of!(RawDirEntry, wrt_date) == 24);
    assert!(offset_of!(RawDirEntry, clus_lo) == 26);
    assert!(offset_of!(RawDirEntry, size) == 28);

    assert!(size_of::<RawLongEntry>() == ENTRY_SIZE);
    assert!(offset_of!(RawLongEntry, name1) == 1);
    assert!(offset_of!(RawLongEntry, attr) == 11);
    assert!(offset_of!(RawLongEntry, kind) == 12);
    assert!(offset_of!(RawLongEntry, checksum) == 13);
    assert!(offset_of!(RawLongEntry, name2) == 14);
    assert!(offset_of!(RawLongEntry, clus_lo) == 26);
    assert!(offset_of!(RawLongEntry, name3) == 28);
};

impl RawDirEntry {
    /// The record `bytes` hold.
    pub fn read(bytes: &RecordBytes) -> Self {
        from_block(bytes)
    }

    /// The record's bytes.
    pub fn bytes(&self) -> RecordBytes {
        to_block(self)
    }

    /// The 8.3 name, the [`ESCAPED_E5`] escape undone.
    pub fn short_name(&self) -> [u8; 11] {
        let mut name = self.name;
        if name[0] == ESCAPED_E5 {
            name[0] = DELETED;
        }
        name
    }

    /// Store the 8.3 name `name`, a leading 0xE5 escaped.
    pub fn set_short_name(&mut self, name: &[u8; 11]) {
        self.name = *name;
        if self.name[0] == DELETED {
            self.name[0] = ESCAPED_E5;
        }
    }

    /// The first cluster, both halves combined.
    pub fn first_cluster(&self) -> u32 {
        (self.clus_hi.get() as u32) << 16 | self.clus_lo.get() as u32
    }

    pub fn set_first_cluster(&mut self, cluster: u32) {
        self.clus_hi.set((cluster >> 16) as u16);
        self.clus_lo.set(cluster as u16);
    }

    pub fn times(&self) -> Times {
        Times {
            create_hundredths: self.crt_tenth,
            create_time: self.crt_time.get(),
            create_date: self.crt_date.get(),
            access_date: self.acc_date.get(),
            write_time: self.wrt_time.get(),
            write_date: self.wrt_date.get(),
        }
    }

    pub fn set_times(&mut self, times: &Times) {
        self.crt_tenth = times.create_hundredths;
        self.crt_time.set(times.create_time);
        self.crt_date.set(times.create_date);
        self.acc_date.set(times.access_date);
        self.wrt_time.set(times.write_time);
        self.wrt_date.set(times.write_date);
    }
}

impl RawLongEntry {
    /// The record `bytes` hold.
    pub fn read(bytes: &RecordBytes) -> Self {
        from_block(bytes)
    }

    /// The record's bytes.
    pub fn bytes(&self) -> RecordBytes {
        to_block(self)
    }

    /// The fields holding the part's units, in name order: the one place the three runs are put
    /// together.
    fn unit_fields(&mut self) -> impl Iterator<Item = &mut Le16> {
        self.name1
            .iter_mut()
            .chain(&mut self.name2)
            .chain(&mut self.name3)
    }

    /// The part this record stores.
    pub fn part(&self) -> LongPart {
        let mut units = [0u16; PART_UNITS];
        let mut record = *self;
        for (unit, field) in units.iter_mut().zip(record.unit_fields()) {
            *unit = field.get();
        }
        LongPart {
            order: self.ord & ORDER_MASK,
            last: self.ord & LAST_LONG_PART != 0,
            checksum: self.checksum,
            units,
        }
    }
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

/// Decode one record.
pub fn decode(bytes: &RecordBytes) -> Record {
    let raw = RawDirEntry::read(bytes);
    match raw.name[0] {
        END => return Record::End,
        DELETED => return Record::Deleted,
        _ => {}
    }
    // A long-name record's attributes include the label bit, so it is told apart first.
    if raw.attr == ATTR_LONG_NAME {
        return Record::LongName(RawLongEntry::read(bytes).part());
    }
    if raw.attr & ATTR_VOLUME_LABEL != 0 {
        return Record::VolumeLabel;
    }
    let dot = raw.name == DOT || raw.name == DOT_DOT;
    let entry = DirEntry {
        name: raw.short_name(),
        attributes: raw.attr,
        case: raw.nt_res,
        first_cluster: raw.first_cluster(),
        size: raw.size.get(),
        times: raw.times(),
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
        assert!(
            matches!(decode(&record(b".          ", 0x10, 9, 0)), Record::Dot(e) if e.first_cluster == 9)
        );
        assert!(matches!(
            decode(&record(b"..         ", 0x10, 0, 0)),
            Record::Dot(_)
        ));
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

    /// A long-name part's record: the order byte with the last-part flag, the long-name
    /// attributes, the checksum, and the 13 units in their three runs (from bytes 1, 14 and 28);
    /// decoding it gives the part back.
    #[test]
    fn a_long_part_encodes_at_its_offsets() {
        let units: [u16; PART_UNITS] = core::array::from_fn(|i| 0x0100 + i as u16);
        let part = LongPart {
            order: 2,
            last: true,
            checksum: 0xA7,
            units,
        };
        let bytes = part.record().bytes();
        assert_eq!(
            (bytes[0], bytes[11], bytes[12], bytes[13]),
            (0x42, 0x0F, 0, 0xA7)
        );
        let at = |offset: usize| u16::from_le_bytes([bytes[offset], bytes[offset + 1]]);
        let offsets = [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30];
        assert_eq!(offsets.map(at), units);
        assert_eq!(at(26), 0, "no first cluster");
        assert_eq!(decode(&bytes), Record::LongName(part));
    }

    /// A short record's fields land at their offsets, and a leading 0xE5 is stored escaped.
    #[test]
    fn a_short_record_encodes_at_its_offsets() {
        let mut raw = RawDirEntry::zeroed();
        raw.set_short_name(b"\xE5NAME   TXT");
        raw.attr = 0x20;
        raw.set_first_cluster(0x0012_3456);
        raw.size.set(31);
        let bytes = raw.bytes();
        assert_eq!(bytes[0], 0x05);
        assert_eq!(raw.short_name(), *b"\xE5NAME   TXT");
        let mut expected = record(b"\x05NAME   TXT", 0x20, 0x0012_3456, 31);
        assert_eq!(bytes, expected);
        expected[0] = b'X';
        assert_eq!(RawDirEntry::read(&expected).short_name(), *b"XNAME   TXT");
    }

    #[test]
    fn stored_names_are_space_padded() {
        assert_eq!(stored_name(b"HELLO", b"EXE"), *b"HELLO   EXE");
        assert_eq!(stored_name(b"BOOT", b""), *b"BOOT       ");
    }
}
