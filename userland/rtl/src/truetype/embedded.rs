//! The embedded bitmaps: the bitmap location table (`EBLC`), whose strikes each hold a size's
//! glyphs as index subtables, and the bitmap data table (`EBDT`), which holds each glyph's image
//! and, in most formats, its metrics. A font drawn at a size it has a strike for draws the strike's
//! glyphs, not its outlines.
//!
//! Index subtable formats 1 to 5 are read, and image formats 1, 2 and 5 to 7: every format but the
//! composite bitmaps (8 and 9), which are [`Error::Unsupported`]. Only one-bit strikes are
//! offered, as the engine is monochrome.

use super::{read, Error};

/// A bitmap size record's size, and the line metrics' within it.
const SIZE_RECORD: usize = 48;
const LINE_METRICS: usize = 12;

/// The strike's flags: its small glyph metrics are horizontal ones.
pub const FLAG_HORIZONTAL_METRICS: u8 = 0x01;

/// A strike's line metrics, horizontal or vertical, in pixels.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LineMetrics {
    pub ascender: i8,
    pub descender: i8,
    pub width_max: u8,
    pub caret_slope_numerator: i8,
    pub caret_slope_denominator: i8,
    pub caret_offset: i8,
    pub min_origin_sb: i8,
    pub min_advance_sb: i8,
    pub max_before_bl: i8,
    pub min_after_bl: i8,
}

impl LineMetrics {
    fn parse(data: &[u8]) -> Result<Self, Error> {
        let byte = |at| read::i8(data, at);
        Ok(Self {
            ascender: byte(0)?,
            descender: byte(1)?,
            width_max: read::u8(data, 2)?,
            caret_slope_numerator: byte(3)?,
            caret_slope_denominator: byte(4)?,
            caret_offset: byte(5)?,
            min_origin_sb: byte(6)?,
            min_advance_sb: byte(7)?,
            max_before_bl: byte(8)?,
            min_after_bl: byte(9)?,
        })
    }
}

/// A glyph bitmap's horizontal metrics, in pixels: its size, the offset of its top-left pixel from
/// the origin (`bearing_y` up from the baseline to the top row), and the advance.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BitmapMetrics {
    pub height: u8,
    pub width: u8,
    pub bearing_x: i8,
    pub bearing_y: i8,
    pub advance: u8,
}

impl BitmapMetrics {
    /// The small metrics' five bytes: height, width, bearings, advance.
    fn small(data: &[u8], at: usize) -> Result<Self, Error> {
        Ok(Self {
            height: read::u8(data, at)?,
            width: read::u8(data, at + 1)?,
            bearing_x: read::i8(data, at + 2)?,
            bearing_y: read::i8(data, at + 3)?,
            advance: read::u8(data, at + 4)?,
        })
    }

    /// The big metrics' horizontal half: the same five fields, the vertical three after them.
    fn big(data: &[u8], at: usize) -> Result<Self, Error> {
        read::bytes(data, at, 8)?;
        Self::small(data, at)
    }
}

/// The strikes: the location table's size records over the data table.
#[derive(Clone, Copy, Debug)]
pub struct Strikes<'a> {
    eblc: &'a [u8],
    ebdt: &'a [u8],
    count: usize,
}

impl<'a> Strikes<'a> {
    pub fn parse(eblc: &'a [u8], ebdt: &'a [u8]) -> Result<Self, Error> {
        if read::u16(eblc, 0)? != 2 || read::u16(ebdt, 0)? != 2 {
            return Err(Error::Unsupported);
        }
        let count = read::u32(eblc, 4)? as usize;
        read::bytes(
            eblc,
            8,
            count.checked_mul(SIZE_RECORD).ok_or(Error::Truncated)?,
        )?;
        Ok(Self { eblc, ebdt, count })
    }

    /// Every strike, in the table's order.
    pub fn all(&self) -> impl Iterator<Item = Result<Strike<'a>, Error>> + 'a {
        let strikes = *self;
        (0..self.count).map(move |index| strikes.strike_at(index))
    }

    /// The one-bit strike of `ppem` pixels per em both ways, if the font has one.
    pub fn strike(&self, ppem: u16) -> Result<Option<Strike<'a>>, Error> {
        for strike in self.all() {
            let strike = strike?;
            if strike.ppem_x as u16 == ppem && strike.ppem_y as u16 == ppem && strike.bit_depth == 1
            {
                return Ok(Some(strike));
            }
        }
        Ok(None)
    }

    fn strike_at(&self, index: usize) -> Result<Strike<'a>, Error> {
        let record = read::bytes(self.eblc, 8 + index * SIZE_RECORD, SIZE_RECORD)?;
        let array_offset = read::u32(record, 0)? as usize;
        let count = read::u32(record, 8)? as usize;
        let array = read::bytes(
            self.eblc,
            array_offset,
            count.checked_mul(8).ok_or(Error::Truncated)?,
        )?;
        Ok(Strike {
            eblc: self.eblc,
            ebdt: self.ebdt,
            array_offset,
            array,
            hori: LineMetrics::parse(&record[16..16 + LINE_METRICS])?,
            vert: LineMetrics::parse(&record[28..28 + LINE_METRICS])?,
            start_glyph: read::u16(record, 40)?,
            end_glyph: read::u16(record, 42)?,
            ppem_x: record[44],
            ppem_y: record[45],
            bit_depth: record[46],
            flags: record[47],
        })
    }
}

/// One strike: a size's glyphs, found through its index subtables.
#[derive(Clone, Copy, Debug)]
pub struct Strike<'a> {
    eblc: &'a [u8],
    ebdt: &'a [u8],
    /// The index subtable array: each entry a glyph range and its subtable's offset from the
    /// array's start.
    array_offset: usize,
    array: &'a [u8],
    pub hori: LineMetrics,
    pub vert: LineMetrics,
    pub start_glyph: u16,
    pub end_glyph: u16,
    pub ppem_x: u8,
    pub ppem_y: u8,
    pub bit_depth: u8,
    pub flags: u8,
}

/// A glyph's image in a strike: its metrics and its rows of pixels, packed bit by bit across rows
/// (`bit_aligned`) or each row from a byte boundary. The most significant bit is the leftmost
/// pixel.
#[derive(Clone, Copy, Debug)]
pub struct StrikeGlyph<'a> {
    pub metrics: BitmapMetrics,
    data: &'a [u8],
    bit_aligned: bool,
}

impl StrikeGlyph<'_> {
    /// Whether pixel `x` of row `y` (from the top) is set; pixels outside the image are not.
    pub fn pixel(&self, x: u32, y: u32) -> bool {
        let (width, height) = (self.metrics.width as u32, self.metrics.height as u32);
        if x >= width || y >= height {
            return false;
        }
        let bit = if self.bit_aligned {
            y * width + x
        } else {
            y * width.div_ceil(8) * 8 + x
        } as usize;
        self.data
            .get(bit / 8)
            .is_some_and(|byte| byte & (0x80 >> (bit % 8)) != 0)
    }
}

impl<'a> Strike<'a> {
    /// Glyph `glyph`'s image in the strike, none when the strike leaves it out (a glyph outside
    /// every index subtable's range, or one whose image is empty).
    pub fn glyph(&self, glyph: u16) -> Result<Option<StrikeGlyph<'a>>, Error> {
        let (entries, _) = self.array.as_chunks::<8>();
        for &[first0, first1, last0, last1, offset0, offset1, offset2, offset3] in entries {
            let first = u16::from_be_bytes([first0, first1]);
            let last = u16::from_be_bytes([last0, last1]);
            if glyph < first || glyph > last {
                continue;
            }
            let offset = u32::from_be_bytes([offset0, offset1, offset2, offset3]) as usize;
            let subtable = read::rest(
                self.eblc,
                self.array_offset
                    .checked_add(offset)
                    .ok_or(Error::Truncated)?,
            )?;
            return self.subtable_glyph(subtable, glyph, first);
        }
        Ok(None)
    }

    /// Glyph `glyph`'s image through an index subtable whose range starts at glyph `first`.
    fn subtable_glyph(
        &self,
        subtable: &'a [u8],
        glyph: u16,
        first: u16,
    ) -> Result<Option<StrikeGlyph<'a>>, Error> {
        let index_format = read::u16(subtable, 0)?;
        let image_format = read::u16(subtable, 2)?;
        let image_data = read::u32(subtable, 4)? as usize;
        let index = (glyph - first) as usize;
        // Where the glyph's image starts and ends in the data table (from `image_data`), and the
        // metrics the subtable gives for every glyph it holds, if it does.
        let (start, end, shared_metrics) = match index_format {
            // Offsets for every glyph of the range, 32-bit (1) or 16-bit (3), each glyph's image
            // ending where the next one's starts.
            1 => (
                read::u32(subtable, 8 + index * 4)? as usize,
                read::u32(subtable, 12 + index * 4)? as usize,
                None,
            ),
            3 => (
                read::u16(subtable, 8 + index * 2)? as usize,
                read::u16(subtable, 10 + index * 2)? as usize,
                None,
            ),
            // Every glyph of the range the same size, with the same metrics.
            2 => {
                let size = read::u32(subtable, 8)? as usize;
                let start = index.checked_mul(size).ok_or(Error::Truncated)?;
                let end = start.checked_add(size).ok_or(Error::Truncated)?;
                (start, end, Some(BitmapMetrics::big(subtable, 12)?))
            }
            // The glyphs the range holds, each with its offset; the array runs one entry past the
            // last, where the last image ends.
            4 => {
                let count = read::u32(subtable, 8)? as usize;
                let entries = count.checked_add(1).ok_or(Error::Truncated)?;
                let pairs = read::bytes(
                    subtable,
                    12,
                    entries.checked_mul(4).ok_or(Error::Truncated)?,
                )?;
                let Some(found) = (0..count).find(|&at| read::u16(pairs, at * 4) == Ok(glyph))
                else {
                    return Ok(None);
                };
                (
                    read::u16(pairs, found * 4 + 2)? as usize,
                    read::u16(pairs, found * 4 + 6)? as usize,
                    None,
                )
            }
            // The glyphs the range holds, every one the same size, with the same metrics.
            5 => {
                let size = read::u32(subtable, 8)? as usize;
                let metrics = BitmapMetrics::big(subtable, 12)?;
                let count = read::u32(subtable, 20)? as usize;
                let glyphs =
                    read::bytes(subtable, 24, count.checked_mul(2).ok_or(Error::Truncated)?)?;
                let Some(found) = (0..count).find(|&at| read::u16(glyphs, at * 2) == Ok(glyph))
                else {
                    return Ok(None);
                };
                let start = found.checked_mul(size).ok_or(Error::Truncated)?;
                let end = start.checked_add(size).ok_or(Error::Truncated)?;
                (start, end, Some(metrics))
            }
            _ => return Err(Error::Unsupported),
        };
        self.image(image_format, image_data, start, end, shared_metrics)
    }

    /// The image at `start..end` from `image_data` in the data table, in `image_format`, with the
    /// subtable's shared metrics for the formats that carry none. An empty range is a glyph the
    /// strike leaves out.
    fn image(
        &self,
        image_format: u16,
        image_data: usize,
        start: usize,
        end: usize,
        shared_metrics: Option<BitmapMetrics>,
    ) -> Result<Option<StrikeGlyph<'a>>, Error> {
        if end < start {
            return Err(Error::Malformed);
        }
        if end == start {
            return Ok(None);
        }
        let at = image_data.checked_add(start).ok_or(Error::Truncated)?;
        let image = read::bytes(self.ebdt, at, end - start)?;
        let (metrics, bits_at, bit_aligned) = match image_format {
            1 => (BitmapMetrics::small(image, 0)?, 5, false),
            2 => (BitmapMetrics::small(image, 0)?, 5, true),
            5 => (shared_metrics.ok_or(Error::Malformed)?, 0, true),
            6 => (BitmapMetrics::big(image, 0)?, 8, false),
            7 => (BitmapMetrics::big(image, 0)?, 8, true),
            _ => return Err(Error::Unsupported),
        };
        let (width, height) = (metrics.width as usize, metrics.height as usize);
        let size = if bit_aligned {
            (width * height).div_ceil(8)
        } else {
            width.div_ceil(8) * height
        };
        Ok(Some(StrikeGlyph {
            metrics,
            data: read::bytes(image, bits_at, size)?,
            bit_aligned,
        }))
    }
}
