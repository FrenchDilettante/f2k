//! The tables a font keeps per size in pixels: the device metrics (`hdmx`: each glyph's advance
//! at a ppem, as its instructions round it), the vertical device metrics (`VDMX`: the highest and
//! lowest pixel any glyph reaches at a ppem) and the grid-fitting and scan-conversion procedure
//! (`gasp`: whether to grid-fit and whether to smooth, by ppem).

use super::{read, Error};

/// The device metrics: records of a ppem, its largest advance and every glyph's advance.
#[derive(Clone, Copy, Debug)]
pub struct Hdmx<'a> {
    records: &'a [u8],
    count: usize,
    record_size: usize,
    num_glyphs: usize,
}

impl<'a> Hdmx<'a> {
    /// The table, for `num_glyphs` glyphs (maxp's); every record is checked to lie inside it and
    /// to hold a width for each glyph.
    pub fn parse(data: &'a [u8], num_glyphs: u16) -> Result<Self, Error> {
        if read::u16(data, 0)? != 0 {
            return Err(Error::Malformed);
        }
        let count = read::u16(data, 2)? as usize;
        let record_size = read::u32(data, 4)? as usize;
        let num_glyphs = num_glyphs as usize;
        if record_size < 2 + num_glyphs {
            return Err(Error::Malformed);
        }
        let size = count.checked_mul(record_size).ok_or(Error::Truncated)?;
        Ok(Self {
            records: read::bytes(data, 8, size)?,
            count,
            record_size,
            num_glyphs,
        })
    }

    /// The advance widths in pixels of every glyph at `ppem`, if the table has a record for it.
    pub fn widths(&self, ppem: u16) -> Option<&'a [u8]> {
        (0..self.count)
            .map(|index| &self.records[index * self.record_size..][..self.record_size])
            .find(|record| record[0] as u16 == ppem)
            .map(|record| &record[2..2 + self.num_glyphs])
    }
}

/// A VDMX entry: the highest and lowest pixel rows any glyph reaches at a ppem, relative to the
/// baseline (`y_min` is negative below it).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VdmxEntry {
    /// The ppem the entry is for.
    pub y_pel_height: u16,
    pub y_max: i16,
    pub y_min: i16,
}

/// The vertical device metrics: aspect-ratio ranges, each with a group of entries by ppem.
#[derive(Clone, Copy, Debug)]
pub struct Vdmx<'a> {
    data: &'a [u8],
    ratios: usize,
}

impl<'a> Vdmx<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self, Error> {
        if read::u16(data, 0)? > 1 {
            return Err(Error::Malformed);
        }
        let ratios = read::u16(data, 4)? as usize;
        // The ratio ranges (four bytes each), then a group's offset for each.
        read::bytes(data, 6, ratios * 6)?;
        Ok(Self { data, ratios })
    }

    /// The group of entries for a device whose pixels are `x_ratio` by `y_ratio` (1 by 1 for a
    /// display at the same resolution both ways): the first ratio range that holds the device's
    /// ratio, a range of x ratio 0 holding every ratio. Its entries are checked to lie inside the
    /// table.
    pub fn group(&self, x_ratio: u8, y_ratio: u8) -> Result<Option<VdmxGroup<'a>>, Error> {
        for index in 0..self.ratios {
            let range = read::bytes(self.data, 6 + index * 4, 4)?;
            let (range_x, start_y, end_y) = (range[1] as u32, range[2] as u32, range[3] as u32);
            let (x, y) = (x_ratio as u32, y_ratio as u32);
            // The device's y:x lies between the range's start:x and end:x.
            if range_x == 0 || (start_y * x <= y * range_x && y * range_x <= end_y * x) {
                let offset = read::u16(self.data, 6 + self.ratios * 4 + index * 2)? as usize;
                let group = read::rest(self.data, offset)?;
                let count = read::u16(group, 0)? as usize;
                return Ok(Some(VdmxGroup {
                    entries: read::bytes(group, 4, count * 6)?,
                    start: read::u8(group, 2)?,
                    end: read::u8(group, 3)?,
                }));
            }
        }
        Ok(None)
    }
}

/// A group of VDMX entries, sorted by ppem.
#[derive(Clone, Copy, Debug)]
pub struct VdmxGroup<'a> {
    entries: &'a [u8],
    /// The ppem range the group covers.
    pub start: u8,
    pub end: u8,
}

impl<'a> VdmxGroup<'a> {
    /// The entries, in the table's order (ascending ppem).
    pub fn entries(&self) -> impl Iterator<Item = VdmxEntry> + 'a {
        let (entries, _) = self.entries.as_chunks::<6>();
        entries
            .iter()
            .map(|&[h0, h1, max0, max1, min0, min1]| VdmxEntry {
                y_pel_height: u16::from_be_bytes([h0, h1]),
                y_max: i16::from_be_bytes([max0, max1]),
                y_min: i16::from_be_bytes([min0, min1]),
            })
    }

    /// The entry for `ppem`, if the group has one.
    pub fn entry(&self, ppem: u16) -> Option<VdmxEntry> {
        self.entries().find(|entry| entry.y_pel_height == ppem)
    }
}

/// The `gasp` behaviour bits: grid-fit (hint) at the size, and smooth (antialias) at it.
pub const GASP_GRIDFIT: u16 = 0x0001;
pub const GASP_DOGRAY: u16 = 0x0002;

/// The grid-fitting and scan-conversion procedure: ranges of ppem, each up to a largest ppem, with
/// their behaviour.
#[derive(Clone, Copy, Debug)]
pub struct Gasp<'a> {
    ranges: &'a [u8],
}

impl<'a> Gasp<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self, Error> {
        if read::u16(data, 0)? > 1 {
            return Err(Error::Malformed);
        }
        let count = read::u16(data, 2)? as usize;
        Ok(Self {
            ranges: read::bytes(data, 4, count * 4)?,
        })
    }

    /// The behaviour bits at `ppem`: the first range whose largest ppem is at or above it. None
    /// past the last range (whose largest ppem is 0xFFFF in a well-formed table).
    pub fn behavior(&self, ppem: u16) -> Option<u16> {
        let (ranges, _) = self.ranges.as_chunks::<4>();
        ranges
            .iter()
            .find(|&&[max0, max1, _, _]| u16::from_be_bytes([max0, max1]) >= ppem)
            .map(|&[_, _, behavior0, behavior1]| u16::from_be_bytes([behavior0, behavior1]))
    }
}
