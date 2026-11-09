//! The naming table (`name`): the font's strings (its family, subfamily, full and PostScript
//! names, its copyright and version), each in records for a platform, an encoding and a language.
//! GetTextFace and GetOutlineTextMetrics's names come from the Windows platform's Unicode records.

use super::{read, Error};

/// The name IDs GDI reads.
pub const NAME_COPYRIGHT: u16 = 0;
pub const NAME_FAMILY: u16 = 1;
pub const NAME_SUBFAMILY: u16 = 2;
pub const NAME_UNIQUE: u16 = 3;
pub const NAME_FULL: u16 = 4;
pub const NAME_VERSION: u16 = 5;
pub const NAME_POSTSCRIPT: u16 = 6;

/// The platforms: Unicode, the Macintosh, Windows.
pub const PLATFORM_UNICODE: u16 = 0;
pub const PLATFORM_MACINTOSH: u16 = 1;
pub const PLATFORM_WINDOWS: u16 = 3;

/// The Windows platform's encodings: symbol, Unicode's basic plane, full Unicode.
pub const WINDOWS_SYMBOL: u16 = 0;
pub const WINDOWS_UNICODE_BMP: u16 = 1;
pub const WINDOWS_UNICODE_FULL: u16 = 10;

/// The Windows language ID of English (United States).
pub const LANGUAGE_ENGLISH_US: u16 = 0x0409;

/// A name record's size: platform, encoding, language, name ID, length, offset.
const RECORD_SIZE: usize = 12;

/// One string of the table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NameRecord<'a> {
    pub platform_id: u16,
    pub encoding_id: u16,
    pub language_id: u16,
    pub name_id: u16,
    /// The string's bytes, in the platform's encoding.
    pub bytes: &'a [u8],
}

impl<'a> NameRecord<'a> {
    /// Whether the string is UTF-16 (big-endian): the Unicode platform's and the Windows
    /// platform's records are.
    pub fn is_utf16(&self) -> bool {
        self.platform_id == PLATFORM_UNICODE || self.platform_id == PLATFORM_WINDOWS
    }

    /// The string's UTF-16 code units, for a record that [`is_utf16`](Self::is_utf16); a trailing
    /// odd byte is dropped.
    pub fn utf16(&self) -> impl Iterator<Item = u16> + 'a {
        let (units, _) = self.bytes.as_chunks::<2>();
        units.iter().map(|&unit| u16::from_be_bytes(unit))
    }
}

/// The naming table, its records checked at parse time to lie inside it.
#[derive(Clone, Copy, Debug)]
pub struct Name<'a> {
    records: &'a [u8],
    strings: &'a [u8],
}

impl<'a> Name<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self, Error> {
        let format = read::u16(data, 0)?;
        if format > 1 {
            return Err(Error::Malformed);
        }
        let count = read::u16(data, 2)? as usize;
        let strings = read::rest(data, read::u16(data, 4)? as usize)?;
        let records = read::bytes(data, 6, count * RECORD_SIZE)?;
        let name = Self { records, strings };
        for index in 0..count {
            name.record(index)?;
        }
        Ok(name)
    }

    /// The `index`th record.
    fn record(&self, index: usize) -> Result<NameRecord<'a>, Error> {
        let at = index * RECORD_SIZE;
        let length = read::u16(self.records, at + 8)? as usize;
        let offset = read::u16(self.records, at + 10)? as usize;
        Ok(NameRecord {
            platform_id: read::u16(self.records, at)?,
            encoding_id: read::u16(self.records, at + 2)?,
            language_id: read::u16(self.records, at + 4)?,
            name_id: read::u16(self.records, at + 6)?,
            bytes: read::bytes(self.strings, offset, length)?,
        })
    }

    /// The records, in the table's order.
    pub fn records(&self) -> impl Iterator<Item = NameRecord<'a>> + 'a {
        let name = *self;
        (0..self.records.len() / RECORD_SIZE).filter_map(move |index| name.record(index).ok())
    }

    /// The string Windows reads for `name_id`: the Windows platform's Unicode record in US
    /// English, else its Unicode record in any language, else its symbol encoding's, else the
    /// Unicode platform's. None when the font has no UTF-16 record of that name.
    pub fn windows_string(&self, name_id: u16) -> Option<NameRecord<'a>> {
        let named = move |record: &NameRecord| record.name_id == name_id;
        let windows = |encoding: u16| {
            move |record: &NameRecord| {
                record.platform_id == PLATFORM_WINDOWS && record.encoding_id == encoding
            }
        };
        let unicode_bmp = windows(WINDOWS_UNICODE_BMP);
        self.records()
            .find(|record| {
                named(record) && unicode_bmp(record) && record.language_id == LANGUAGE_ENGLISH_US
            })
            .or_else(|| {
                self.records()
                    .find(|record| named(record) && unicode_bmp(record))
            })
            .or_else(|| {
                self.records()
                    .find(|record| named(record) && windows(WINDOWS_SYMBOL)(record))
            })
            .or_else(|| {
                self.records()
                    .find(|record| named(record) && record.platform_id == PLATFORM_UNICODE)
            })
    }
}
