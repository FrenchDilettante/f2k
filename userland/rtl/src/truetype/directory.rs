//! The table directory: the sfnt header at the file's start and its table records, each a table's
//! tag, checksum, offset and length. GetFontData hands out a table by its tag, as the directory
//! places it, and every other table's reader starts from the bytes a record names.

use super::{read, Error, Tag};

/// The sfnt versions of a file with TrueType outlines: 0x00010000, and Apple's 'true'.
const VERSION_TRUETYPE: u32 = 0x0001_0000;
const VERSION_APPLE: u32 = u32::from_be_bytes(*b"true");
/// A TrueType collection's header tag: several fonts in one file, which this reader does not
/// open.
const VERSION_COLLECTION: u32 = u32::from_be_bytes(*b"ttcf");

/// The header's size (sfntVersion, numTables, searchRange, entrySelector, rangeShift), and a table
/// record's.
const HEADER_SIZE: usize = 12;
const RECORD_SIZE: usize = 16;

/// A table record: where the directory says a table lies in the file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TableRecord {
    pub tag: Tag,
    pub checksum: u32,
    pub offset: u32,
    pub length: u32,
}

impl TableRecord {
    /// The table's bytes in `file`.
    pub fn bytes<'a>(&self, file: &'a [u8]) -> Result<&'a [u8], Error> {
        read::bytes(file, self.offset as usize, self.length as usize)
    }

    /// Whether the table's bytes in `file` sum to the record's checksum. The `head` table's sum
    /// leaves out its checkSumAdjustment, which is set after the checksum is taken.
    pub fn checksum_matches(&self, file: &[u8]) -> Result<bool, Error> {
        let bytes = self.bytes(file)?;
        let sum = if self.tag == Tag::HEAD && bytes.len() >= 12 {
            table_checksum(&bytes[..8]).wrapping_add(table_checksum(&bytes[12..]))
        } else {
            table_checksum(bytes)
        };
        Ok(sum == self.checksum)
    }
}

/// The checksum the directory keeps for a table: the sum of its big-endian 32-bit words, the last
/// one padded with zeros. (The `head` table's own word at offset 8 is the caller's to leave out.)
pub fn table_checksum(bytes: &[u8]) -> u32 {
    bytes.chunks(4).fold(0u32, |sum, chunk| {
        let mut word = [0; 4];
        word[..chunk.len()].copy_from_slice(chunk);
        sum.wrapping_add(u32::from_be_bytes(word))
    })
}

/// The directory of a font file: its records, every one of them checked at parse time to lie
/// inside the file.
#[derive(Clone, Copy, Debug)]
pub struct Directory<'a> {
    records: &'a [u8],
}

impl<'a> Directory<'a> {
    /// The directory at the start of `file`. A collection, or a file whose outlines are not
    /// TrueType's (an OpenType font with CFF outlines, 'OTTO'), is [`Error::Unsupported`]; a
    /// record that reaches past the file's end is [`Error::Truncated`].
    pub fn parse(file: &'a [u8]) -> Result<Self, Error> {
        let version = read::u32(file, 0)?;
        if version == VERSION_COLLECTION {
            return Err(Error::Unsupported);
        }
        if version != VERSION_TRUETYPE && version != VERSION_APPLE {
            return Err(Error::Unsupported);
        }
        let count = read::u16(file, 4)? as usize;
        let records = read::bytes(file, HEADER_SIZE, count * RECORD_SIZE)?;
        let directory = Self { records };
        for record in directory.records() {
            record.bytes(file)?;
        }
        Ok(directory)
    }

    /// The number of tables.
    pub fn len(&self) -> usize {
        self.records.len() / RECORD_SIZE
    }

    /// Whether the file has no tables.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// The records, in the directory's order.
    pub fn records(&self) -> impl Iterator<Item = TableRecord> + 'a {
        let (records, _) = self.records.as_chunks::<RECORD_SIZE>();
        records.iter().map(|record| {
            let word = |at: usize| {
                u32::from_be_bytes([record[at], record[at + 1], record[at + 2], record[at + 3]])
            };
            TableRecord {
                tag: Tag(word(0)),
                checksum: word(4),
                offset: word(8),
                length: word(12),
            }
        })
    }

    /// The record of the table tagged `tag`, if the file has one.
    pub fn find(&self, tag: Tag) -> Option<TableRecord> {
        self.records().find(|record| record.tag == tag)
    }
}
