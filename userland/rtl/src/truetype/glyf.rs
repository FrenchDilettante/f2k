//! The glyph outlines: the index to location (`loca`), which places each glyph's data in the glyph
//! data table (`glyf`), and the glyphs themselves. A simple glyph is contours of points, each on
//! or off the curve (two on-curve points bound a line, an off-curve point between two points is a
//! quadratic Bézier's control point, and two off-curve points in a row imply an on-curve point
//! midway). A composite glyph is other glyphs placed by an offset or by matching points, each
//! under a 2-by-2 transform in 2.14 fixed point.
//!
//! The reader resolves a composite into one outline: every component's points scaled, transformed
//! and offset as its record says. In pixel units, an offset whose record sets ROUND_XY_TO_GRID is
//! rounded to the nearest whole pixel, so an accent keeps its place on the grid; which is why an
//! outline is read at its scale rather than scaled afterwards. Its points land in buffers the
//! caller lends ([`Outline`]), so no glyph needs an allocation and the caller bounds the work. The
//! glyphs' instructions are not run.

use super::scale::Scale;
use super::{read, Error};

/// A point's flag: it lies on the curve (else it is a quadratic's control point).
pub const ON_CURVE: u32 = 0x01;

/// The simple glyph's flags, as the file holds them.
const FLAG_ON_CURVE: u8 = 0x01;
const FLAG_X_SHORT: u8 = 0x02;
const FLAG_Y_SHORT: u8 = 0x04;
const FLAG_REPEAT: u8 = 0x08;
const FLAG_X_SAME_OR_POSITIVE: u8 = 0x10;
const FLAG_Y_SAME_OR_POSITIVE: u8 = 0x20;

/// A component record's flags.
const ARG_1_AND_2_ARE_WORDS: u16 = 0x0001;
const ARGS_ARE_XY_VALUES: u16 = 0x0002;
const ROUND_XY_TO_GRID: u16 = 0x0004;
const WE_HAVE_A_SCALE: u16 = 0x0008;
const MORE_COMPONENTS: u16 = 0x0020;
const WE_HAVE_AN_X_AND_Y_SCALE: u16 = 0x0040;
const WE_HAVE_A_TWO_BY_TWO: u16 = 0x0080;
const USE_MY_METRICS: u16 = 0x0200;
const SCALED_COMPONENT_OFFSET: u16 = 0x0800;
const UNSCALED_COMPONENT_OFFSET: u16 = 0x1000;

/// How deep composites may nest: a composite that reaches deeper (one that contains itself, at
/// any remove) is [`Error::CompositeTooDeep`]. Fonts nest a few levels at most.
pub const MAX_COMPONENT_DEPTH: u32 = 8;

/// How many component records one glyph's resolution may visit in all, so that composites of
/// composites cannot multiply the work past any bound.
pub const MAX_COMPONENTS: u32 = 1024;

/// One point of an outline.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Point {
    pub x: i32,
    pub y: i32,
    /// [`ON_CURVE`], or 0 for a control point.
    pub flags: u32,
}

impl Point {
    pub fn on_curve(&self) -> bool {
        self.flags & ON_CURVE != 0
    }
}

// SAFETY: three 32-bit integers in a #[repr(C)] structure, so no padding, and any bits make one.
unsafe impl crate::pod::Pod for Point {}

/// A glyph's header: its contour count (negative for a composite) and its bounding box in font
/// units, as the font gives them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GlyphHeader {
    pub number_of_contours: i16,
    pub x_min: i16,
    pub y_min: i16,
    pub x_max: i16,
    pub y_max: i16,
}

/// An outline, in buffers the caller lends: its points, and the index of each contour's last
/// point. A glyph's contours are read into it whole, or not at all.
pub struct Outline<'b> {
    points: &'b mut [Point],
    ends: &'b mut [u16],
    point_count: usize,
    contour_count: usize,
    metrics_glyph: u16,
}

impl<'b> Outline<'b> {
    /// An empty outline over `points` and `ends`, which bound the points and contours it can hold
    /// (and no more than 65536 points, as a contour's end is a 16-bit index).
    pub fn new(points: &'b mut [Point], ends: &'b mut [u16]) -> Self {
        Self {
            points,
            ends,
            point_count: 0,
            contour_count: 0,
            metrics_glyph: 0,
        }
    }

    /// Empties it.
    pub fn clear(&mut self) {
        self.point_count = 0;
        self.contour_count = 0;
        self.metrics_glyph = 0;
    }

    /// The points, every contour's in turn.
    pub fn points(&self) -> &[Point] {
        &self.points[..self.point_count]
    }

    /// The contours' ends: the index of each one's last point.
    pub fn contour_ends(&self) -> &[u16] {
        &self.ends[..self.contour_count]
    }

    /// The contours, each its points in order.
    pub fn contours(&self) -> impl Iterator<Item = &[Point]> {
        let points = self.points();
        let mut start = 0;
        self.contour_ends().iter().map(move |&end| {
            let contour = &points[start..=end as usize];
            start = end as usize + 1;
            contour
        })
    }

    /// Whether it has no contours (a space's glyph).
    pub fn is_empty(&self) -> bool {
        self.contour_count == 0
    }

    /// The glyph whose horizontal metrics the outline takes: its own, or the component's a
    /// composite names with USE_MY_METRICS.
    pub fn metrics_glyph(&self) -> u16 {
        self.metrics_glyph
    }

    /// The smallest and largest coordinates of its points, none when it has none: (x_min, y_min,
    /// x_max, y_max).
    pub fn bounds(&self) -> Option<(i32, i32, i32, i32)> {
        let mut points = self.points().iter();
        let first = points.next()?;
        Some(points.fold(
            (first.x, first.y, first.x, first.y),
            |(x0, y0, x1, y1), point| {
                (
                    x0.min(point.x),
                    y0.min(point.y),
                    x1.max(point.x),
                    y1.max(point.y),
                )
            },
        ))
    }

    /// Makes room for `count` more points, none of them yet read.
    fn grow(&mut self, count: usize) -> Result<&mut [Point], Error> {
        let start = self.point_count;
        let end = start.checked_add(count).ok_or(Error::BufferTooSmall)?;
        if end > self.points.len() || end > u16::MAX as usize + 1 {
            return Err(Error::BufferTooSmall);
        }
        self.point_count = end;
        Ok(&mut self.points[start..end])
    }

    /// Ends a contour at point `end`.
    fn end_contour(&mut self, end: usize) -> Result<(), Error> {
        let slot = self
            .ends
            .get_mut(self.contour_count)
            .ok_or(Error::BufferTooSmall)?;
        *slot = u16::try_from(end).map_err(|_| Error::BufferTooSmall)?;
        self.contour_count += 1;
        Ok(())
    }
}

/// The glyph table and its index: each glyph's data, checked against the table's bounds when it is
/// read.
#[derive(Clone, Copy, Debug)]
pub struct Glyphs<'a> {
    loca: &'a [u8],
    glyf: &'a [u8],
    long_offsets: bool,
    num_glyphs: u16,
}

impl<'a> Glyphs<'a> {
    /// The tables, for head's `index_to_loc_format` and maxp's glyph count; `loca` must hold an
    /// offset for each glyph and one past the last.
    pub fn parse(
        loca: &'a [u8],
        glyf: &'a [u8],
        index_to_loc_format: i16,
        num_glyphs: u16,
    ) -> Result<Self, Error> {
        let long_offsets = index_to_loc_format == 1;
        let entry = if long_offsets { 4 } else { 2 };
        read::bytes(loca, 0, (num_glyphs as usize + 1) * entry)?;
        Ok(Self {
            loca,
            glyf,
            long_offsets,
            num_glyphs,
        })
    }

    /// The number of glyphs.
    pub fn len(&self) -> u16 {
        self.num_glyphs
    }

    /// Whether the font has no glyphs.
    pub fn is_empty(&self) -> bool {
        self.num_glyphs == 0
    }

    /// Glyph `glyph`'s data: empty for a glyph with no outline. A glyph past the last, or whose
    /// offsets run backwards or past the table, is an error.
    pub fn data(&self, glyph: u16) -> Result<&'a [u8], Error> {
        if glyph >= self.num_glyphs {
            return Err(Error::BadGlyph);
        }
        let index = glyph as usize;
        let (start, end) = if self.long_offsets {
            (
                read::u32(self.loca, index * 4)? as usize,
                read::u32(self.loca, index * 4 + 4)? as usize,
            )
        } else {
            (
                read::u16(self.loca, index * 2)? as usize * 2,
                read::u16(self.loca, index * 2 + 2)? as usize * 2,
            )
        };
        if end < start {
            return Err(Error::Malformed);
        }
        read::bytes(self.glyf, start, end - start)
    }

    /// Glyph `glyph`'s header, none for a glyph with no outline.
    pub fn header(&self, glyph: u16) -> Result<Option<GlyphHeader>, Error> {
        let data = self.data(glyph)?;
        if data.is_empty() {
            return Ok(None);
        }
        Ok(Some(GlyphHeader {
            number_of_contours: read::i16(data, 0)?,
            x_min: read::i16(data, 2)?,
            y_min: read::i16(data, 4)?,
            x_max: read::i16(data, 6)?,
            y_max: read::i16(data, 8)?,
        }))
    }

    /// Reads glyph `glyph`'s outline into `outline`, emptied first, in `scale`'s units: a
    /// composite resolved into its components' contours. On an error the outline is left empty.
    pub fn outline(&self, glyph: u16, scale: Scale, outline: &mut Outline) -> Result<(), Error> {
        outline.clear();
        let mut budget = MAX_COMPONENTS;
        match self.load(glyph, scale, outline, 0, &mut budget) {
            Ok(metrics_glyph) => {
                outline.metrics_glyph = metrics_glyph;
                Ok(())
            }
            Err(error) => {
                outline.clear();
                Err(error)
            }
        }
    }

    /// Appends glyph `glyph`'s contours to `outline`, at composite depth `depth`. Its answer is the
    /// glyph whose metrics the outline takes.
    fn load(
        &self,
        glyph: u16,
        scale: Scale,
        outline: &mut Outline,
        depth: u32,
        budget: &mut u32,
    ) -> Result<u16, Error> {
        let data = self.data(glyph)?;
        if data.is_empty() {
            return Ok(glyph);
        }
        let contours = read::i16(data, 0)?;
        if contours >= 0 {
            load_simple(data, contours as usize, scale, outline)?;
            return Ok(glyph);
        }
        if depth >= MAX_COMPONENT_DEPTH {
            return Err(Error::CompositeTooDeep);
        }
        let mut metrics_glyph = glyph;
        let first_point = outline.point_count;
        let mut at = 10;
        loop {
            if *budget == 0 {
                return Err(Error::CompositeTooDeep);
            }
            *budget -= 1;
            let flags = read::u16(data, at)?;
            let component = read::u16(data, at + 2)?;
            at += 4;
            let (arg1, arg2) = if flags & ARG_1_AND_2_ARE_WORDS != 0 {
                at += 4;
                if flags & ARGS_ARE_XY_VALUES != 0 {
                    (
                        read::i16(data, at - 4)? as i32,
                        read::i16(data, at - 2)? as i32,
                    )
                } else {
                    (
                        read::u16(data, at - 4)? as i32,
                        read::u16(data, at - 2)? as i32,
                    )
                }
            } else {
                at += 2;
                if flags & ARGS_ARE_XY_VALUES != 0 {
                    (
                        read::i8(data, at - 2)? as i32,
                        read::i8(data, at - 1)? as i32,
                    )
                } else {
                    (
                        read::u8(data, at - 2)? as i32,
                        read::u8(data, at - 1)? as i32,
                    )
                }
            };
            // The transform [a c; b d] in 2.14: x' = a x + c y, y' = b x + d y.
            let f2dot14 = |offset| read::i16(data, offset).map(|value| value as i32);
            let transform = if flags & WE_HAVE_A_SCALE != 0 {
                at += 2;
                let scale = f2dot14(at - 2)?;
                Some([scale, 0, 0, scale])
            } else if flags & WE_HAVE_AN_X_AND_Y_SCALE != 0 {
                at += 4;
                Some([f2dot14(at - 4)?, 0, 0, f2dot14(at - 2)?])
            } else if flags & WE_HAVE_A_TWO_BY_TWO != 0 {
                at += 8;
                // Stored as xscale (a), scale01 (b), scale10 (c), yscale (d).
                Some([
                    f2dot14(at - 8)?,
                    f2dot14(at - 6)?,
                    f2dot14(at - 4)?,
                    f2dot14(at - 2)?,
                ])
            } else {
                None
            };

            let start = outline.point_count;
            let component_metrics = self.load(component, scale, outline, depth + 1, budget)?;
            if flags & USE_MY_METRICS != 0 {
                metrics_glyph = component_metrics;
            }
            let end = outline.point_count;
            if let Some(matrix) = transform {
                for point in &mut outline.points[start..end] {
                    (point.x, point.y) = apply(matrix, point.x, point.y);
                }
            }

            let (dx, dy) = if flags & ARGS_ARE_XY_VALUES != 0 {
                let (mut dx, mut dy) = (arg1, arg2);
                if let Some(matrix) = transform {
                    if flags & SCALED_COMPONENT_OFFSET != 0
                        && flags & UNSCALED_COMPONENT_OFFSET == 0
                    {
                        (dx, dy) = apply(matrix, dx, dy);
                    }
                }
                let (mut dx, mut dy) = (scale.apply(dx), scale.apply(dy));
                if flags & ROUND_XY_TO_GRID != 0 {
                    dx = scale.round_to_grid(dx);
                    dy = scale.round_to_grid(dy);
                }
                (dx, dy)
            } else {
                // Point matching: the composite's point `arg1` so far, and the component's point
                // `arg2`, are made to coincide.
                let parent = first_point + arg1 as usize;
                let child = start + arg2 as usize;
                if parent >= start || child >= end {
                    return Err(Error::Malformed);
                }
                let (parent, child) = (outline.points[parent], outline.points[child]);
                (parent.x - child.x, parent.y - child.y)
            };
            for point in &mut outline.points[start..end] {
                point.x = point.x.saturating_add(dx);
                point.y = point.y.saturating_add(dy);
            }

            if flags & MORE_COMPONENTS == 0 {
                return Ok(metrics_glyph);
            }
        }
    }
}

/// `(x, y)` under the 2.14 transform `[a, b, c, d]` (x' = a x + c y, y' = b x + d y), rounded to
/// the nearest (a half up).
fn apply([a, b, c, d]: [i32; 4], x: i32, y: i32) -> (i32, i32) {
    let (x, y) = (x as i64, y as i64);
    let round =
        |value: i64| ((value + 0x2000) >> 14).clamp(i32::MIN as i64, i32::MAX as i64) as i32;
    (
        round(a as i64 * x + c as i64 * y),
        round(b as i64 * x + d as i64 * y),
    )
}

/// Walks a simple glyph's flags, expanding their repeats: each call the next point's flag.
struct Flags<'a> {
    data: &'a [u8],
    at: usize,
    flag: u8,
    repeats: u8,
}

impl Flags<'_> {
    fn next(&mut self) -> Result<u8, Error> {
        if self.repeats > 0 {
            self.repeats -= 1;
            return Ok(self.flag);
        }
        self.flag = read::u8(self.data, self.at)?;
        self.at += 1;
        if self.flag & FLAG_REPEAT != 0 {
            self.repeats = read::u8(self.data, self.at)?;
            self.at += 1;
        }
        Ok(self.flag)
    }
}

/// Appends a simple glyph of `contours` contours to `outline`, its points in `scale`'s units.
fn load_simple(
    data: &[u8],
    contours: usize,
    scale: Scale,
    outline: &mut Outline,
) -> Result<(), Error> {
    let ends = read::bytes(data, 10, contours * 2)?;
    let mut count = 0;
    for index in 0..contours {
        let end = read::u16(ends, index * 2)? as usize;
        if end < count {
            return Err(Error::Malformed);
        }
        count = end + 1;
    }
    let instructions = read::u16(data, 10 + contours * 2)? as usize;
    let flags_at = (10 + contours * 2 + 2)
        .checked_add(instructions)
        .ok_or(Error::Truncated)?;

    // The flags, once to learn where the coordinates start and how many bytes the x's take.
    let walk = || Flags {
        data,
        at: flags_at,
        flag: 0,
        repeats: 0,
    };
    let mut flags = walk();
    let mut x_bytes = 0;
    for _ in 0..count {
        let flag = flags.next()?;
        x_bytes += match flag & (FLAG_X_SHORT | FLAG_X_SAME_OR_POSITIVE) {
            0 => 2,
            FLAG_X_SAME_OR_POSITIVE => 0,
            _ => 1,
        };
    }
    let x_at = flags.at;
    let y_at = x_at + x_bytes;

    let first = outline.point_count;
    let points = outline.grow(count)?;
    let (mut flags, mut x_reader, mut y_reader) = (walk(), x_at, y_at);
    let (mut x, mut y) = (0i32, 0i32);
    for point in points.iter_mut() {
        let flag = flags.next()?;
        x = x.saturating_add(delta(
            data,
            &mut x_reader,
            flag,
            FLAG_X_SHORT,
            FLAG_X_SAME_OR_POSITIVE,
        )?);
        y = y.saturating_add(delta(
            data,
            &mut y_reader,
            flag,
            FLAG_Y_SHORT,
            FLAG_Y_SAME_OR_POSITIVE,
        )?);
        *point = Point {
            x: scale.apply(x),
            y: scale.apply(y),
            flags: if flag & FLAG_ON_CURVE != 0 {
                ON_CURVE
            } else {
                0
            },
        };
    }
    for index in 0..contours {
        let end = read::u16(ends, index * 2)? as usize;
        outline.end_contour(first + end)?;
    }
    Ok(())
}

/// One coordinate's delta from the previous point, read at `at` as `flag` says: a byte whose sign
/// the `same_or_positive` bit gives, a repeat of the previous (no delta), or a signed word.
fn delta(
    data: &[u8],
    at: &mut usize,
    flag: u8,
    short: u8,
    same_or_positive: u8,
) -> Result<i32, Error> {
    if flag & short != 0 {
        let value = read::u8(data, *at)? as i32;
        *at += 1;
        Ok(if flag & same_or_positive != 0 {
            value
        } else {
            -value
        })
    } else if flag & same_or_positive != 0 {
        Ok(0)
    } else {
        let value = read::i16(data, *at)? as i32;
        *at += 2;
        Ok(value)
    }
}
