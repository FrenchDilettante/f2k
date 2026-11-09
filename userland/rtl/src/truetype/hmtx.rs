//! The horizontal metrics (`hmtx`): each glyph's advance width and left side bearing in font units.
//! The first `number_of_h_metrics` glyphs have both; the glyphs after them share the last advance
//! and have a bearing of their own.

use super::{read, Error};

/// The horizontal metrics, checked at parse time to hold every glyph's entry.
#[derive(Clone, Copy, Debug)]
pub struct Hmtx<'a> {
    data: &'a [u8],
    full: usize,
    num_glyphs: usize,
}

/// A glyph's horizontal metrics, in font units.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HMetric {
    pub advance_width: u16,
    pub left_side_bearing: i16,
}

impl<'a> Hmtx<'a> {
    /// The table, for `number_of_h_metrics` full entries (hhea's) and `num_glyphs` glyphs
    /// (maxp's).
    pub fn parse(data: &'a [u8], number_of_h_metrics: u16, num_glyphs: u16) -> Result<Self, Error> {
        let full = number_of_h_metrics as usize;
        let num_glyphs = num_glyphs as usize;
        if full == 0 || full > num_glyphs {
            return Err(Error::Malformed);
        }
        read::bytes(data, 0, full * 4 + (num_glyphs - full) * 2)?;
        Ok(Self {
            data,
            full,
            num_glyphs,
        })
    }

    /// The metrics of glyph `glyph`, none past the font's last glyph.
    pub fn metric(&self, glyph: u16) -> Option<HMetric> {
        let glyph = glyph as usize;
        if glyph >= self.num_glyphs {
            return None;
        }
        let (advance_at, bearing_at) = if glyph < self.full {
            (glyph * 4, glyph * 4 + 2)
        } else {
            ((self.full - 1) * 4, self.full * 4 + (glyph - self.full) * 2)
        };
        Some(HMetric {
            advance_width: read::u16(self.data, advance_at).ok()?,
            left_side_bearing: read::i16(self.data, bearing_at).ok()?,
        })
    }
}
