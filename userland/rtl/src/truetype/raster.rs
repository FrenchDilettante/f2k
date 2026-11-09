//! The scan converter: an outline in 26.6 pixels turned into a monochrome bitmap, by the TrueType
//! specification's rules.
//!
//! - **Rule 1:** a pixel whose centre lies inside the outline is on. Inside is the nonzero winding
//!   rule's: a point is inside when the contours wind around it a nonzero number of times.
//! - **Rule 2:** a pixel whose centre lies exactly on a contour is on.
//! - **Dropout control**, when asked for: where a scan line between two adjacent pixel centres (a
//!   row's or a column's) crosses into the outline and out again with neither pixel on, one of them
//!   is turned on: the left (or lower) one under rule 3, the one nearer the crossings' midpoint
//!   under rule 5 ([`Dropout`]). The variants that leave stubs alone (rules 4 and 6) are not
//!   offered.
//!
//! Quadratic segments are flattened into lines in 26.6 fixed point, finely enough that no line
//! strays more than a 128th of a pixel (half a 26.6 unit) from its curve. A scan line's crossings
//! are worked out into a buffer the caller lends, one scan line at a time, and nothing allocates.
//! No floating point is used: the kernel, which runs this code, does not keep the FPU's state for
//! itself.

use super::glyf::{Outline, Point};
use super::scale::ONE_PIXEL;
use super::Error;

/// Crossings are kept in 256ths of a 26.6 unit, so that a crossing on a pixel centre is found
/// exactly wherever the line's slope allows.
const SUBUNITS: i64 = 256;
/// One pixel, and half of one, in those units.
const PIXEL: i64 = ONE_PIXEL as i64 * SUBUNITS;
const HALF_PIXEL: i64 = PIXEL / 2;

/// The most lines one curve is cut into.
const MAX_STEPS: i64 = 256;

/// A point's x and y, in 26.6 units.
type Xy = (i32, i32);

/// The largest coordinate the scan converter takes, in 26.6 units (65536 pixels either way), so
/// that its products stay inside 64 bits.
pub const MAX_COORDINATE: i32 = 1 << 22;

/// The dropout control a glyph is scan-converted with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dropout {
    /// Rules 1 and 2 alone: a stroke thinner than a pixel may vanish. The TrueType graphics
    /// state's default, which a font's control-value program changes with SCANCTRL.
    Off,
    /// Rule 3: of the two pixels a dropout falls between, the left one (on a row) or the lower
    /// one (on a column).
    Simple,
    /// Rule 5: of the two, the one whose centre is nearer the midpoint of the crossings (the left
    /// or lower one when they are as near).
    Smart,
}

/// Where a scan line crosses a contour: the position along the scan line (in 256ths of a 26.6
/// unit) and the contour's direction across it (+1 or -1).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Crossing {
    pub position: i32,
    pub winding: i32,
}

// SAFETY: two 32-bit integers in a #[repr(C)] structure, so no padding, and any bits make one.
unsafe impl crate::pod::Pod for Crossing {}

/// A monochrome bitmap as GetGlyphOutline lays out GGO_BITMAP: rows from the top, each `stride`
/// bytes, a pixel a bit with the leftmost pixel in a byte's high bit. It covers `width` pixels
/// from column `left`, and `height` rows down from the row edge `top` (whole pixels, y up from the
/// baseline): its first row is the pixels between `top - 1` and `top`.
pub struct Target<'b> {
    pub bits: &'b mut [u8],
    pub stride: usize,
    pub width: u32,
    pub height: u32,
    pub left: i32,
    pub top: i32,
}

impl Target<'_> {
    /// The byte and mask of the pixel in column `column` whose bottom edge is `row` pixels above
    /// the baseline; none outside the bitmap.
    fn bit(&self, column: i64, row: i64) -> Option<(usize, u8)> {
        let x = column - self.left as i64;
        let y = self.top as i64 - 1 - row;
        if x < 0 || y < 0 || x >= self.width as i64 || y >= self.height as i64 {
            return None;
        }
        let at = (y as usize).checked_mul(self.stride)? + x as usize / 8;
        (at < self.bits.len()).then_some((at, 0x80 >> (x % 8)))
    }

    fn set(&mut self, column: i64, row: i64) {
        if let Some((at, mask)) = self.bit(column, row) {
            self.bits[at] |= mask;
        }
    }

    fn get(&self, column: i64, row: i64) -> bool {
        self.bit(column, row)
            .is_some_and(|(at, mask)| self.bits[at] & mask != 0)
    }
}

/// Which way scan lines run: along rows (positions are x's) or along columns (positions are y's).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Axis {
    Rows,
    Columns,
}

impl Axis {
    /// A point's coordinates as (along the scan line, across it).
    fn coordinates(self, (x, y): Xy) -> (i64, i64) {
        match self {
            Self::Rows => (x as i64, y as i64),
            Self::Columns => (y as i64, x as i64),
        }
    }

    /// The pixel at index `along` on scan line `line`, as (column, row).
    fn pixel(self, line: i64, along: i64) -> (i64, i64) {
        match self {
            Self::Rows => (along, line),
            Self::Columns => (line, along),
        }
    }
}

/// Scan-converts `outline` (26.6 pixels) into `target`, which the caller has cleared. Each scan
/// line's crossings land in `crossings`: a scan line that crosses the outline more often than it
/// holds is [`Error::BufferTooSmall`], and a point beyond [`MAX_COORDINATE`] is
/// [`Error::Unsupported`].
pub fn fill(
    outline: &Outline,
    target: &mut Target,
    dropout: Dropout,
    crossings: &mut [Crossing],
) -> Result<(), Error> {
    let range = -MAX_COORDINATE..=MAX_COORDINATE;
    if !outline
        .points()
        .iter()
        .all(|point| range.contains(&point.x) && range.contains(&point.y))
    {
        return Err(Error::Unsupported);
    }
    let rows = target.top as i64 - target.height as i64..target.top as i64;
    let columns = target.left as i64..target.left as i64 + target.width as i64;

    // Rules 1 and 2, row by row.
    for line in rows.clone() {
        let count = scan(outline, Axis::Rows, line, crossings, &mut |from, to| {
            for column in from..=to {
                target.set(column, line);
            }
        })?;
        for_each_span(&crossings[..count], &mut |low, high| {
            if let Some((from, to)) = centres(low, high) {
                for column in from..=to {
                    target.set(column, line);
                }
            }
        });
    }
    if dropout == Dropout::Off {
        return Ok(());
    }
    // Dropout control, along rows and then along columns, against the pixels already on.
    for (axis, lines) in [(Axis::Rows, rows), (Axis::Columns, columns)] {
        for line in lines {
            let count = scan(outline, axis, line, crossings, &mut |_, _| {})?;
            for_each_span(&crossings[..count], &mut |low, high| {
                if centres(low, high).is_some() {
                    return;
                }
                // The span falls between the centres of pixels `before` and `before + 1`.
                let before = (low - HALF_PIXEL).div_euclid(PIXEL);
                let (first, second) = (axis.pixel(line, before), axis.pixel(line, before + 1));
                if target.get(first.0, first.1) || target.get(second.0, second.1) {
                    return;
                }
                let chosen = match dropout {
                    Dropout::Smart => {
                        // Twice the midpoint, against twice the centres.
                        let middle = low + high;
                        let first_centre = 2 * (before * PIXEL + HALF_PIXEL);
                        let second_centre = first_centre + 2 * PIXEL;
                        if second_centre - middle < middle - first_centre {
                            second
                        } else {
                            first
                        }
                    }
                    _ => first,
                };
                target.set(chosen.0, chosen.1);
            });
        }
    }
    Ok(())
}

/// The pixels along a scan line whose centres lie in `low..=high` (positions along it): the first
/// and last one's index, none when no centre does.
fn centres(low: i64, high: i64) -> Option<(i64, i64)> {
    let first = (low - HALF_PIXEL + PIXEL - 1).div_euclid(PIXEL);
    let last = (high - HALF_PIXEL).div_euclid(PIXEL);
    (first <= last).then_some((first, last))
}

/// Hands each span of sorted `crossings` inside the outline (where the winding number leaves zero,
/// to where it returns to it) to `span`, as its two positions.
fn for_each_span(crossings: &[Crossing], span: &mut dyn FnMut(i64, i64)) {
    let mut winding = 0;
    let mut start = 0;
    for crossing in crossings {
        let before = winding;
        winding += crossing.winding;
        if before == 0 && winding != 0 {
            start = crossing.position as i64;
        } else if before != 0 && winding == 0 {
            span(start, crossing.position as i64);
        }
    }
}

/// Collects into `crossings`, sorted by position, where scan line `line` (through the centres of
/// the pixels of that index across the scan lines) crosses `outline`; the answer is their count.
/// A line holds its lower end and not its upper one, so a vertex the contour passes through
/// crosses once. The pixels rule 2 turns on beyond the spans the crossings bound (those under a
/// line that runs along the scan line on the centres, and those a line ends on) are handed to
/// `on_contour` as runs of indices along the scan line.
fn scan(
    outline: &Outline,
    axis: Axis,
    line: i64,
    crossings: &mut [Crossing],
    on_contour: &mut dyn FnMut(i64, i64),
) -> Result<usize, Error> {
    let centre = line * ONE_PIXEL as i64 + ONE_PIXEL as i64 / 2;
    let mut count = 0;
    let mut overflow = false;
    for_each_line(outline, &mut |from, to| {
        let (x0, y0) = axis.coordinates(from);
        let (x1, y1) = axis.coordinates(to);
        if y0 == y1 {
            if y0 == centre {
                if let Some((first, last)) = centres(x0.min(x1) * SUBUNITS, x0.max(x1) * SUBUNITS) {
                    on_contour(first, last);
                }
            }
            return;
        }
        if y1 == centre {
            if let Some((first, last)) = centres(x1 * SUBUNITS, x1 * SUBUNITS) {
                on_contour(first, last);
            }
        }
        let (low, high, winding) = if y0 < y1 { (y0, y1, 1) } else { (y1, y0, -1) };
        if centre < low || centre >= high {
            return;
        }
        // The crossing, rounded to the nearest subunit (a half up).
        let (numerator, denominator) = ((centre - y0) * (x1 - x0) * SUBUNITS, y1 - y0);
        let (numerator, denominator) = if denominator > 0 {
            (numerator, denominator)
        } else {
            (-numerator, -denominator)
        };
        let position = x0 * SUBUNITS + (2 * numerator + denominator).div_euclid(2 * denominator);
        match crossings.get_mut(count) {
            Some(slot) => {
                *slot = Crossing {
                    position: position as i32,
                    winding,
                };
                count += 1;
            }
            None => overflow = true,
        }
    });
    if overflow {
        return Err(Error::BufferTooSmall);
    }
    crossings[..count].sort_unstable_by_key(|crossing| crossing.position);
    Ok(count)
}

/// Hands every line of `outline`'s contours to `line`, its quadratic segments flattened.
fn for_each_line(outline: &Outline, line: &mut dyn FnMut(Xy, Xy)) {
    for contour in outline.contours() {
        for_each_segment(contour, &mut |from, control, to| match control {
            None => line(from, to),
            Some(control) => flatten(from, control, to, line),
        });
    }
}

/// Hands every segment of a closed contour to `segment`: its start, its control point if it is a
/// quadratic, and its end. Two control points in a row imply an on-curve point midway between
/// them; a contour of control points alone starts midway between its last and first.
fn for_each_segment(contour: &[Point], segment: &mut dyn FnMut(Xy, Option<Xy>, Xy)) {
    let (Some(first), Some(last)) = (contour.first(), contour.last()) else {
        return;
    };
    let xy = |point: &Point| (point.x, point.y);
    let midway = |a: Xy, b: Xy| ((a.0 + b.0) >> 1, (a.1 + b.1) >> 1);
    // The contour starts on the curve: at its first point, its last, or midway between them.
    let (start, rest) = if first.on_curve() {
        (xy(first), &contour[1..])
    } else if last.on_curve() {
        (xy(last), &contour[..contour.len() - 1])
    } else {
        (midway(xy(last), xy(first)), contour)
    };
    let mut current = start;
    let mut control: Option<Xy> = None;
    for point in rest {
        let here = xy(point);
        if point.on_curve() {
            segment(current, control.take(), here);
            current = here;
        } else {
            if let Some(previous) = control {
                let middle = midway(previous, here);
                segment(current, Some(previous), middle);
                current = middle;
            }
            control = Some(here);
        }
    }
    segment(current, control, start);
}

/// Cuts the quadratic from `from` through control `control` to `to` into lines that stray no
/// farther than half a 26.6 unit from it, handing each to `line`. The tolerance is finer than the
/// points' own grid so that a pixel centre near a curve falls on the side the curve puts it: the
/// fixture's '@' at 24 ppem has a centre half a unit inside a curve whose chords at a whole unit's
/// tolerance leave it out. The points are taken at even steps
/// of the curve's parameter, each worked out afresh, so no error accumulates.
fn flatten(from: Xy, control: Xy, to: Xy, line: &mut dyn FnMut(Xy, Xy)) {
    let (x0, y0) = (from.0 as i64, from.1 as i64);
    let (x1, y1) = (control.0 as i64, control.1 as i64);
    let (x2, y2) = (to.0 as i64, to.1 as i64);
    // A curve cut into n even steps strays at most |p0 - 2 p1 + p2| / (4 n²) from its lines: at
    // most half a unit when |p0 - 2 p1 + p2| <= 2 n².
    let deviation = (x0 - 2 * x1 + x2).abs().max((y0 - 2 * y1 + y2).abs());
    let mut steps = 1;
    while steps < MAX_STEPS && deviation > 2 * steps * steps {
        steps += 1;
    }
    let squared = steps * steps;
    let at = |step: i64, a: i64, b: i64, c: i64| {
        let (t, u) = (step, steps - step);
        let value = u * u * a + 2 * t * u * b + t * t * c;
        (2 * value + squared).div_euclid(2 * squared) as i32
    };
    let mut previous = from;
    for step in 1..=steps {
        let next = if step == steps {
            to
        } else {
            (at(step, x0, x1, x2), at(step, y0, y1, y2))
        };
        line(previous, next);
        previous = next;
    }
}
