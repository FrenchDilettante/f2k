//! The character-to-glyph map (`cmap`): subtables, each for a platform and an encoding, that map a
//! character code to a glyph index. Formats 0 (a byte's 256 glyphs), 4 (segments of the basic
//! plane), 6 (a dense run) and 12 (groups across all of Unicode) are read; a subtable's header
//! and arrays are checked to lie inside the table when it is chosen, so a lookup reads only what
//! was checked.

use super::name::{
    PLATFORM_MACINTOSH,
    PLATFORM_UNICODE,
    PLATFORM_WINDOWS,
    WINDOWS_SYMBOL,
    WINDOWS_UNICODE_BMP,
    WINDOWS_UNICODE_FULL,
};
use super::{read, Error};

/// The character map: its encoding records.
#[derive(Clone, Copy, Debug)]
pub struct Cmap<'a> {
    data: &'a [u8],
    count: usize,
}

/// One subtable, its format's arrays checked to lie inside the table.
#[derive(Clone, Copy, Debug)]
pub struct Subtable<'a> {
    pub platform_id: u16,
    pub encoding_id: u16,
    format: Format<'a>,
}

#[derive(Clone, Copy, Debug)]
enum Format<'a> {
    /// The 256 glyph indices of a byte encoding.
    ByteEncoding(&'a [u8]),
    /// Format 4: the segments' arrays (`seg_count` each of end codes, start codes, deltas and
    /// range offsets) and, from the range offsets on, the glyph index array they point into.
    Segments {
        seg_count: usize,
        ends: &'a [u8],
        starts: &'a [u8],
        deltas: &'a [u8],
        range_offsets: &'a [u8],
    },
    /// Format 6: the glyphs of the codes from `first` on.
    Trimmed { first: u32, glyphs: &'a [u8] },
    /// Format 12: groups of start code, end code and first glyph.
    Groups(&'a [u8]),
}

impl<'a> Cmap<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self, Error> {
        if read::u16(data, 0)? != 0 {
            return Err(Error::Malformed);
        }
        let count = read::u16(data, 2)? as usize;
        read::bytes(data, 4, count * 8)?;
        Ok(Self { data, count })
    }

    /// The encoding records: platform, encoding and the subtable's offset.
    fn records(&self) -> impl Iterator<Item = (u16, u16, usize)> + 'a {
        let data = self.data;
        (0..self.count).filter_map(move |index| {
            let at = 4 + index * 8;
            Some((
                read::u16(data, at).ok()?,
                read::u16(data, at + 2).ok()?,
                read::u32(data, at + 4).ok()? as usize,
            ))
        })
    }

    /// The subtable for `platform` and `encoding`, if the table has one in a format this reader
    /// reads. A subtable whose arrays reach past the table is an error.
    pub fn subtable(&self, platform: u16, encoding: u16) -> Result<Option<Subtable<'a>>, Error> {
        for (platform_id, encoding_id, offset) in self.records() {
            if platform_id == platform && encoding_id == encoding {
                if let Some(format) = Format::parse(self.data, offset)? {
                    return Ok(Some(Subtable {
                        platform_id,
                        encoding_id,
                        format,
                    }));
                }
            }
        }
        Ok(None)
    }

    /// The subtable Unicode text is mapped through, in Windows' order of preference: the Windows
    /// platform's full-Unicode subtable, its basic-plane one, the Unicode platform's (any
    /// encoding), then the Windows symbol subtable, whose codes are the font's own (a symbol font
    /// maps its characters at U+F000 and up, and the caller offsets them). None when the font has
    /// none of these.
    pub fn unicode(&self) -> Result<Option<Subtable<'a>>, Error> {
        for (platform, encoding) in [
            (PLATFORM_WINDOWS, WINDOWS_UNICODE_FULL),
            (PLATFORM_WINDOWS, WINDOWS_UNICODE_BMP),
            (PLATFORM_UNICODE, 4),
            (PLATFORM_UNICODE, 3),
            (PLATFORM_UNICODE, 2),
            (PLATFORM_UNICODE, 1),
            (PLATFORM_UNICODE, 0),
            (PLATFORM_WINDOWS, WINDOWS_SYMBOL),
        ] {
            if let Some(subtable) = self.subtable(platform, encoding)? {
                return Ok(Some(subtable));
            }
        }
        Ok(None)
    }

    /// The Macintosh platform's Roman subtable, if the font has one.
    pub fn macintosh_roman(&self) -> Result<Option<Subtable<'a>>, Error> {
        self.subtable(PLATFORM_MACINTOSH, 0)
    }
}

impl<'a> Format<'a> {
    /// The subtable at `offset`, checked; None for a format this reader does not read.
    fn parse(data: &'a [u8], offset: usize) -> Result<Option<Self>, Error> {
        let table = read::rest(data, offset)?;
        Ok(Some(match read::u16(table, 0)? {
            0 => Self::ByteEncoding(read::bytes(table, 6, 256)?),
            4 => {
                // The subtable's own length bounds its arrays; a length past the table's end is
                // taken as the table's end.
                let length = read::u16(table, 2)? as usize;
                let table = table.get(..length).unwrap_or(table);
                let seg_count_x2 = read::u16(table, 6)? as usize;
                if !seg_count_x2.is_multiple_of(2) {
                    return Err(Error::Malformed);
                }
                let ends = read::bytes(table, 14, seg_count_x2)?;
                let starts = read::bytes(table, 16 + seg_count_x2, seg_count_x2)?;
                let deltas = read::bytes(table, 16 + 2 * seg_count_x2, seg_count_x2)?;
                // The range offsets run on into the glyph index array to the subtable's end: an
                // offset is counted from its own place in the array.
                let range_offsets = read::rest(table, 16 + 3 * seg_count_x2)?;
                read::bytes(range_offsets, 0, seg_count_x2)?;
                Self::Segments {
                    seg_count: seg_count_x2 / 2,
                    ends,
                    starts,
                    deltas,
                    range_offsets,
                }
            }
            6 => {
                let first = read::u16(table, 6)? as u32;
                let count = read::u16(table, 8)? as usize;
                Self::Trimmed {
                    first,
                    glyphs: read::bytes(table, 10, count * 2)?,
                }
            }
            12 => {
                let count = read::u32(table, 12)? as usize;
                let size = count.checked_mul(12).ok_or(Error::Truncated)?;
                Self::Groups(read::bytes(table, 16, size)?)
            }
            _ => return Ok(None),
        }))
    }
}

impl Subtable<'_> {
    /// The glyph `code` maps to: 0, the missing glyph, when it maps to none. A glyph index array
    /// entry a segment points past the subtable's end reads as the missing glyph too.
    pub fn glyph(&self, code: u32) -> u16 {
        self.format.glyph(code).unwrap_or(0)
    }

    /// The subtable's format number.
    pub fn format(&self) -> u16 {
        match self.format {
            Format::ByteEncoding(_) => 0,
            Format::Segments { .. } => 4,
            Format::Trimmed { .. } => 6,
            Format::Groups(_) => 12,
        }
    }
}

impl Format<'_> {
    fn glyph(&self, code: u32) -> Result<u16, Error> {
        match *self {
            Self::ByteEncoding(glyphs) => match code {
                0..=255 => Ok(glyphs[code as usize] as u16),
                _ => Ok(0),
            },
            Self::Segments {
                seg_count,
                ends,
                starts,
                deltas,
                range_offsets,
            } => {
                let Ok(code) = u16::try_from(code) else {
                    return Ok(0);
                };
                // The segments are sorted by end code: the first that ends at or after the code
                // holds it, if it starts at or before it.
                let (mut low, mut high) = (0, seg_count);
                while low < high {
                    let middle = (low + high) / 2;
                    if read::u16(ends, middle * 2)? < code {
                        low = middle + 1;
                    } else {
                        high = middle;
                    }
                }
                if low == seg_count {
                    return Ok(0);
                }
                let start = read::u16(starts, low * 2)?;
                if code < start {
                    return Ok(0);
                }
                let delta = read::u16(deltas, low * 2)?;
                let range_offset = read::u16(range_offsets, low * 2)? as usize;
                if range_offset == 0 {
                    return Ok(code.wrapping_add(delta));
                }
                let at = low * 2 + range_offset + (code - start) as usize * 2;
                match read::u16(range_offsets, at)? {
                    0 => Ok(0),
                    glyph => Ok(glyph.wrapping_add(delta)),
                }
            }
            Self::Trimmed { first, glyphs } => match code.checked_sub(first) {
                Some(index) if (index as usize) < glyphs.len() / 2 => {
                    read::u16(glyphs, index as usize * 2)
                }
                _ => Ok(0),
            },
            Self::Groups(groups) => {
                let (mut low, mut high) = (0, groups.len() / 12);
                while low < high {
                    let middle = (low + high) / 2;
                    let at = middle * 12;
                    let (start, end) = (read::u32(groups, at)?, read::u32(groups, at + 4)?);
                    if code < start {
                        high = middle;
                    } else if code > end {
                        low = middle + 1;
                    } else {
                        let glyph = read::u32(groups, at + 8)?.wrapping_add(code - start);
                        return Ok(u16::try_from(glyph).unwrap_or(0));
                    }
                }
                Ok(0)
            }
        }
    }
}
