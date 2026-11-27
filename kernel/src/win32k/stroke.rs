//! The lines and shapes rasterizer: cosmetic lines, wide (geometric) lines, and the outlines and
//! interiors of polygons, rectangles, ellipses and rounded rectangles, drawn into a [`Surface`]
//! through a DC's final region and its mix mode ([`Painter`]). The services are [`super::shape`]'s;
//! the pens' [`Stroke`]s are [`super::pen`]'s.
//!
//! Coordinates are the surface's, in 28.4 fixed point ([`Fx`]: sixteenths of a pixel), as Windows
//! 2000's GDI keeps a path's points; a pixel's centre is its integer coordinate.
//!
//! The rules, each fitted to the shapes capture (`tests/gdi32/shapes`) and pinned by this module's
//! host tests against it:
//!
//! - **Cosmetic lines** ([`giq`]): grid intersection quantization. A pixel is lit when the line
//!   leaves its diamond (the points less than half a pixel from its centre, in x plus y): in
//!   practice the pixel nearest the line on each column it crosses (each row, for a line steeper
//!   than 45 degrees), a crossing half-way between two pixels taking the upper (or the left) one,
//!   the pixel whose diamond holds the start lit and the one whose diamond holds the end not. With
//!   whole-pixel ends this is Bresenham's line with the end pixel left out, the ties going the same
//!   way whichever way the line is drawn (the capture's diagonals both ways). A styled line's
//!   dashes count pixels ([`Dashes`]).
//! - **Fills** ([`convex_span`]): a pixel is inside when its centre is, an edge's crossing of a row
//!   rounded up on both sides (a figure's left and top edges in, its right and bottom ones out), an
//!   edge holding the rows from its upper end to before its lower one.
//! - **Curves** ([`ellipse_path`], [`round_rect_path`]): an ellipse is four Bezier quadrants (the
//!   control points 0.5523 of the radius along the tangents, in 28.4), each flattened to two chords
//!   through its midpoint. A cosmetic pen draws the chords as lines; their fill is the polygon's.
//! - **Wide lines** ([`wide_row`]): each segment a band `width` wide, its half-width offset rounded
//!   to the half pixel (the capture's width-5 corners need exactly that); a join between segments
//!   the round pen's wedge (the arc's points at multiples of 45 degrees), the miter's point, or the
//!   bevel's triangle; a round end cap the disk of the pixels nearer the end than half of
//!   `sqrt(width^2 - 1)` (the capture's width-3 ends), a square cap the band carried on by half the
//!   width. The union of the pieces is drawn, each pixel once.
//! - **Mix modes**: each pixel drawn is the mix mode of the pen's or brush's pixel and the
//!   surface's ([`rtl::gdi::mix`]).

use rtl::gdi::{mix, mix_reads_destination, Rect, MAX_STYLE_ENTRIES};

use super::raster::{Clip, Pattern, Surface};
use super::region::{Buf, SmallBuf};

/// Sixteenths of a pixel: one coordinate's unit.
pub const ONE: i64 = 16;

/// A point in 28.4 fixed point (sixteenths of a pixel), the surface's coordinates.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Fx {
    pub x: i64,
    pub y: i64,
}

impl Fx {
    /// The centre of the pixel (`x`, `y`).
    pub const fn pixel(x: i32, y: i32) -> Fx {
        Fx {
            x: x as i64 * ONE,
            y: y as i64 * ONE,
        }
    }

    const fn add(self, other: Fx) -> Fx {
        Fx {
            x: self.x + other.x,
            y: self.y + other.y,
        }
    }

    const fn sub(self, other: Fx) -> Fx {
        Fx {
            x: self.x - other.x,
            y: self.y - other.y,
        }
    }

    const fn neg(self) -> Fx {
        Fx {
            x: -self.x,
            y: -self.y,
        }
    }
}

/// `a × b`, the cross product's z.
fn cross(a: Fx, b: Fx) -> i128 {
    i128::from(a.x) * i128::from(b.y) - i128::from(a.y) * i128::from(b.x)
}

/// `n / d` rounded down (`d` not zero).
fn floor_div(n: i128, d: i128) -> i128 {
    let (n, d) = if d < 0 { (-n, -d) } else { (n, d) };
    n.div_euclid(d)
}

/// `n / d` rounded up (`d` not zero).
fn ceil_div(n: i128, d: i128) -> i128 {
    -floor_div(-n, d)
}

/// `n / d` rounded to the nearest, a half up (`d` not zero).
fn round_div(n: i128, d: i128) -> i128 {
    let (n, d) = if d < 0 { (-n, -d) } else { (n, d) };
    floor_div(2 * n + d, 2 * d)
}

fn clamp32(value: i128) -> i32 {
    value.clamp(i128::from(i32::MIN), i128::from(i32::MAX)) as i32
}

/// The integer square root of `n` (rounded down).
fn isqrt(n: u128) -> u128 {
    if n < 2 {
        return n;
    }
    // Newton's iteration from above, in integers (the kernel keeps off the FPU).
    let bits = 128 - n.leading_zeros();
    let mut x = 1u128 << bits.div_ceil(2);
    loop {
        let next = (x + n / x) / 2;
        if next >= x {
            return x;
        }
        x = next;
    }
}

// --- The pens' strokes ---------------------------------------------------------------------------

/// A geometric pen's end cap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cap {
    Round,
    Square,
    Flat,
}

/// A geometric pen's join.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Join {
    Round,
    Bevel,
    Miter,
}

/// A styled pen's dashes: lengths on and off in turn, from on (pixels for a cosmetic pen, whose
/// lines count pixels; pixels along the line for a geometric one). None: a solid line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Dashes {
    lengths: [u32; MAX_STYLE_ENTRIES],
    count: u8,
}

impl Dashes {
    /// A solid line.
    pub const SOLID: Dashes = Dashes {
        lengths: [0; MAX_STYLE_ENTRIES],
        count: 0,
    };

    /// The dashes `lengths` (at most 16 of them).
    pub fn of(lengths: &[u32]) -> Dashes {
        Dashes::scaled(lengths, 1)
    }

    /// The dashes `lengths`, each `scale` times as long. Lengths that are all zero are a solid
    /// line.
    pub fn scaled(lengths: &[u32], scale: u32) -> Dashes {
        let mut dashes = Dashes::SOLID;
        let count = lengths.len().min(MAX_STYLE_ENTRIES);
        if lengths[..count].iter().all(|&length| length == 0) {
            return dashes;
        }
        for (slot, &length) in dashes.lengths.iter_mut().zip(&lengths[..count]) {
            *slot = length.saturating_mul(scale);
        }
        dashes.count = count as u8;
        dashes
    }

    /// Whether the line is solid.
    pub fn is_solid(&self) -> bool {
        self.count == 0
    }

    /// The whole pattern's length.
    fn period(&self) -> u64 {
        let lengths = &self.lengths[..self.count as usize];
        let sum: u64 = lengths.iter().map(|&length| u64::from(length)).sum();
        // An odd count repeats once more with on and off swapped, as Windows' styles do.
        if self.count % 2 == 1 {
            2 * sum
        } else {
            sum
        }
    }

    /// Whether the line is on at `position` (from the pattern's start).
    fn on_at(&self, position: u64) -> bool {
        let period = self.period();
        if self.is_solid() || period == 0 {
            return true;
        }
        let mut at = position % period;
        let count = self.count as usize;
        for index in 0.. {
            let length = u64::from(self.lengths[index % count]);
            if at < length {
                return index % 2 == 0;
            }
            at -= length;
        }
        true
    }

    /// Where the dash or gap holding `position` ends, past `position`.
    fn run_end(&self, position: u64) -> u64 {
        let period = self.period();
        if self.is_solid() || period == 0 {
            return u64::MAX;
        }
        let base = position - position % period;
        let mut end = base;
        let count = self.count as usize;
        for index in 0.. {
            end += u64::from(self.lengths[index % count]);
            if end > position {
                return end;
            }
        }
        u64::MAX
    }
}

/// What a pen draws: nothing, one-pixel lines, or wide ones (see [`super::pen`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stroke {
    Null,
    Cosmetic {
        color: u32,
        dashes: Dashes,
    },
    Geometric {
        color: u32,
        width: u32,
        cap: Cap,
        join: Join,
        dashes: Dashes,
        inside_frame: bool,
    },
}

// --- The painter ---------------------------------------------------------------------------------

/// What a fill paints with: one pixel value (the surface's own), or a brush's pattern.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum Ink {
    Pixel(u32),
    Pattern(Pattern),
}

/// A surface drawn on through a clipping region and a mix mode.
pub struct Painter<'a, S: Surface + ?Sized> {
    pub surface: &'a mut S,
    pub clip: Clip<'a>,
    pub mode: u32,
}

impl<S: Surface + ?Sized> Painter<'_, S> {
    /// The pixel (`x`, `y`) drawn with the pixel value `paint`, when it is inside the clipping
    /// region and the surface.
    pub fn plot(&mut self, x: i32, y: i32, paint: u32) {
        if !self.clip.contains(x, y) || !self.surface.bounds().contains(x, y) {
            return;
        }
        self.put(x, y, paint);
    }

    fn put(&mut self, x: i32, y: i32, paint: u32) {
        let destination = if mix_reads_destination(self.mode) {
            self.surface.load(x, y)
        } else {
            0
        };
        self.surface.store(x, y, mix(self.mode, paint, destination));
    }

    /// The pixels of row `y` from `from` to before `to`, inside the clipping region and the
    /// surface, drawn with `ink`.
    pub fn span(&mut self, y: i32, from: i32, to: i32, ink: &Ink) {
        if from >= to {
            return;
        }
        let area = Rect::new(from, y, to, y + 1).intersect(self.surface.bounds());
        let clip = self.clip;
        for (left, right) in clip.spans(y, area) {
            for x in left..right {
                let paint = match ink {
                    Ink::Pixel(pixel) => *pixel,
                    Ink::Pattern(pattern) => self.surface.pixel(pattern.at(x, y)),
                };
                self.put(x, y, paint);
            }
        }
    }
}

// --- Cosmetic lines ------------------------------------------------------------------------------

/// The pixel whose diamond holds `p` (the points less than half a pixel from its centre, in x
/// plus y); none for a point between diamonds.
fn diamond_of(p: Fx) -> Option<(i32, i32)> {
    let x = (p.x + ONE / 2).div_euclid(ONE);
    let y = (p.y + ONE / 2).div_euclid(ONE);
    ((p.x - x * ONE).abs() + (p.y - y * ONE).abs() < ONE / 2).then_some((x as i32, y as i32))
}

/// The pixels a cosmetic line from `a` to `b` lights, in order from `a` (see the module notes),
/// each handed to `f`.
pub fn giq(a: Fx, b: Fx, mut f: impl FnMut(i32, i32)) {
    if a == b {
        return;
    }
    let end = diamond_of(b);
    let mut last = None;
    let mut emit = |pixel: (i32, i32)| {
        if Some(pixel) != end && Some(pixel) != last {
            last = Some(pixel);
            f(pixel.0, pixel.1);
        }
    };
    if let Some(start) = diamond_of(a) {
        emit(start);
    }
    let (dx, dy) = (i128::from(b.x - a.x), i128::from(b.y - a.y));
    let one = i128::from(ONE);
    let half = one / 2;
    if dx.abs() >= dy.abs() {
        let step: i128 = if dx > 0 { 1 } else { -1 };
        let mut column = if dx > 0 {
            floor_div(i128::from(a.x), one) + 1
        } else {
            ceil_div(i128::from(a.x), one) - 1
        };
        while (dx > 0 && column * one < i128::from(b.x))
            || (dx < 0 && column * one > i128::from(b.x))
        {
            // The line's y at the column, num / dx: its row rounded, a half up.
            let num = i128::from(a.y) * dx + (column * one - i128::from(a.x)) * dy;
            let row = ceil_div(num - half * dx, one * dx);
            emit((clamp32(column), clamp32(row)));
            column += step;
        }
    } else {
        let step: i128 = if dy > 0 { 1 } else { -1 };
        let mut row = if dy > 0 {
            floor_div(i128::from(a.y), one) + 1
        } else {
            ceil_div(i128::from(a.y), one) - 1
        };
        while (dy > 0 && row * one < i128::from(b.y)) || (dy < 0 && row * one > i128::from(b.y)) {
            let num = i128::from(a.x) * dy + (row * one - i128::from(a.y)) * dx;
            let column = ceil_div(num - half * dy, one * dy);
            emit((clamp32(column), clamp32(row)));
            row += step;
        }
    }
}

/// The pixels a cosmetic pen lights along `path` (closed back to its first point when `closed`),
/// in order, each handed to `f` with whether the dashes have it on; the dashes count the pixels
/// from the path's start.
pub fn cosmetic_path(
    path: &[Fx],
    closed: bool,
    dashes: &Dashes,
    mut f: impl FnMut(i32, i32, bool),
) {
    let mut position = 0u64;
    let mut segment = |a: Fx, b: Fx| {
        giq(a, b, |x, y| {
            f(x, y, dashes.on_at(position));
            position += 1;
        })
    };
    for pair in path.windows(2) {
        segment(pair[0], pair[1]);
    }
    if closed && path.len() > 1 {
        segment(path[path.len() - 1], path[0]);
    }
}

// --- Fills ---------------------------------------------------------------------------------------

/// The pixels of row `y` inside the convex polygon `polygon` (closed back to its first point): from
/// one column to before the other; none when the row holds none (see the module notes).
pub fn convex_span(polygon: &[Fx], y: i32) -> Option<(i32, i32)> {
    let row = i128::from(y) * i128::from(ONE);
    let mut found: Option<(i128, i128)> = None;
    for index in 0..polygon.len() {
        let (a, b) = (polygon[index], polygon[(index + 1) % polygon.len()]);
        if a.y == b.y {
            continue;
        }
        let (low, high) = (a.y.min(b.y), a.y.max(b.y));
        if row < i128::from(low) || row >= i128::from(high) {
            continue;
        }
        let (dy, dx) = (i128::from(b.y - a.y), i128::from(b.x - a.x));
        let num = i128::from(a.x) * dy + (row - i128::from(a.y)) * dx;
        let x = ceil_div(num, i128::from(ONE) * dy);
        found = Some(match found {
            None => (x, x),
            Some((left, right)) => (left.min(x), right.max(x)),
        });
    }
    let (left, right) = found?;
    (left < right).then(|| (clamp32(left), clamp32(right)))
}

// --- Curves --------------------------------------------------------------------------------------

/// 0.5522847498 (the Bezier quadrant's control distance, a radius's part), in 32-bit fixed point.
const KAPPA: i128 = 2_372_003_169;

/// `radius` times [`KAPPA`], rounded.
fn kappa(radius: i64) -> i64 {
    ((i128::from(radius) * KAPPA + (1 << 31)) >> 32) as i64
}

/// The midpoint of the Bezier quadrant from `p0` to `p3` through the controls `p1` and `p2`,
/// rounded to the sixteenth.
fn bezier_mid(p0: Fx, p1: Fx, p2: Fx, p3: Fx) -> Fx {
    let mid = |a: i64, b: i64, c: i64, d: i64| {
        round_div(
            i128::from(a) + 3 * i128::from(b) + 3 * i128::from(c) + i128::from(d),
            8,
        ) as i64
    };
    Fx {
        x: mid(p0.x, p1.x, p2.x, p3.x),
        y: mid(p0.y, p1.y, p2.y, p3.y),
    }
}

/// The ellipse inscribed in the box from (`left`, `top`) to (`right`, `bottom`) (28.4), flattened:
/// eight points, counter-clockwise from the right end (see the module notes).
pub fn ellipse_path(left: i64, top: i64, right: i64, bottom: i64) -> [Fx; 8] {
    let half = |a: i64, b: i64| (a + b + 1).div_euclid(2);
    let (cx, cy) = (half(left, right), half(top, bottom));
    let (rx, ry) = (
        (right - left + 1).div_euclid(2),
        (bottom - top + 1).div_euclid(2),
    );
    let (kx, ky) = (kappa(rx), kappa(ry));
    let at = |x, y| Fx { x, y };
    let quadrants = [
        [
            at(right, cy),
            at(right, cy - ky),
            at(cx + kx, top),
            at(cx, top),
        ],
        [
            at(cx, top),
            at(cx - kx, top),
            at(left, cy - ky),
            at(left, cy),
        ],
        [
            at(left, cy),
            at(left, cy + ky),
            at(cx - kx, bottom),
            at(cx, bottom),
        ],
        [
            at(cx, bottom),
            at(cx + kx, bottom),
            at(right, cy + ky),
            at(right, cy),
        ],
    ];
    let mut path = [Fx::default(); 8];
    for (index, [p0, p1, p2, p3]) in quadrants.into_iter().enumerate() {
        path[2 * index] = p0;
        path[2 * index + 1] = bezier_mid(p0, p1, p2, p3);
    }
    path
}

/// The rounded rectangle of the box from (`left`, `top`) to (`right`, `bottom`), its corners
/// quarters of an ellipse of radii `rx` and `ry` (28.4), flattened: each corner's start, midpoint
/// and end, counter-clockwise from the top right corner (the straight sides between them).
pub fn round_rect_path(left: i64, top: i64, right: i64, bottom: i64, rx: i64, ry: i64) -> [Fx; 12] {
    let (kx, ky) = (kappa(rx), kappa(ry));
    let at = |x, y| Fx { x, y };
    let corners = [
        [
            at(right, top + ry),
            at(right, top + ry - ky),
            at(right - rx + kx, top),
            at(right - rx, top),
        ],
        [
            at(left + rx, top),
            at(left + rx - kx, top),
            at(left, top + ry - ky),
            at(left, top + ry),
        ],
        [
            at(left, bottom - ry),
            at(left, bottom - ry + ky),
            at(left + rx - kx, bottom),
            at(left + rx, bottom),
        ],
        [
            at(right - rx, bottom),
            at(right - rx + kx, bottom),
            at(right, bottom - ry + ky),
            at(right, bottom - ry),
        ],
    ];
    let mut path = [Fx::default(); 12];
    for (index, [p0, p1, p2, p3]) in corners.into_iter().enumerate() {
        path[3 * index] = p0;
        path[3 * index + 1] = bezier_mid(p0, p1, p2, p3);
        path[3 * index + 2] = p3;
    }
    path
}

// --- Wide lines ----------------------------------------------------------------------------------

/// `num / sqrt(den)` rounded to the nearest integer, a half up (`den` positive).
fn round_over_root(num: i128, den: i128) -> i64 {
    let root = isqrt(den as u128) as i128;
    if root * root == den {
        return round_div(num, root) as i64;
    }
    // Irrational: no tie. |num| / sqrt(den) in 16.16, from num^2 / den.
    let square = (num * num) as u128;
    let den = den as u128;
    let scaled = ((square / den) << 32) + (((square % den) << 32) / den);
    let magnitude = isqrt(scaled) as i128;
    let fixed = if num < 0 { -magnitude } else { magnitude };
    floor_div(fixed + (1 << 15), 1 << 16) as i64
}

/// The half-width offset of a segment going `d`, for a pen of `width`: `d` turned a quarter (to
/// its left on the screen), half the width long, rounded to the half pixel.
fn offset(d: Fx, width: u32) -> Fx {
    let den = i128::from(d.x) * i128::from(d.x) + i128::from(d.y) * i128::from(d.y);
    let w = i128::from(width);
    Fx {
        x: round_over_root(-i128::from(d.y) * w, den) * (ONE / 2),
        y: round_over_root(i128::from(d.x) * w, den) * (ONE / 2),
    }
}

/// [`offset`]'s along the segment: `d`, half the width long, rounded to the half pixel.
fn along(d: Fx, width: u32) -> Fx {
    let turned = offset(d, width);
    Fx {
        x: turned.y,
        y: -turned.x,
    }
}

/// One piece of a wide line: a convex polygon (at most eight points) or a round cap's disk.
#[derive(Clone, Copy, Debug)]
enum Piece {
    Polygon { points: [Fx; 8], len: u8 },
    Disk { center: Fx, width: u32 },
}

impl Piece {
    fn polygon(points: &[Fx]) -> Piece {
        let mut all = [Fx::default(); 8];
        all[..points.len()].copy_from_slice(points);
        Piece::Polygon {
            points: all,
            len: points.len() as u8,
        }
    }

    /// Its pixels on row `y`.
    fn span(&self, y: i32) -> Option<(i32, i32)> {
        match self {
            Piece::Polygon { points, len } => convex_span(&points[..*len as usize], y),
            Piece::Disk { center, width } => {
                // The pixels whose centres are nearer than sqrt(w^2 - 1) / 2: 4 d^2 < w^2 - 1.
                let w = i128::from(*width);
                let limit = (w * w - 1) * i128::from(ONE * ONE);
                let dy = i128::from(y) * i128::from(ONE) - i128::from(center.y);
                let room = limit - 4 * dy * dy;
                if room <= 0 {
                    return None;
                }
                let reach = w + 1;
                let middle = floor_div(i128::from(center.x), i128::from(ONE));
                let inside = |x: i128| {
                    let dx = x * i128::from(ONE) - i128::from(center.x);
                    4 * dx * dx < room
                };
                let left = (middle - reach..=middle + reach).find(|&x| inside(x))?;
                let right = (left..=middle + reach + 1).find(|&x| !inside(x))?;
                Some((clamp32(left), clamp32(right)))
            }
        }
    }
}

/// The pieces of a geometric pen's line along `path` (closed when `closed`; no two points alike in
/// a row), each handed to `f` (see the module notes).
#[allow(clippy::too_many_arguments)]
fn pieces(
    path: &[Fx],
    closed: bool,
    width: u32,
    cap: Cap,
    join: Join,
    dashes: &Dashes,
    f: &mut impl FnMut(Piece),
) {
    let count = path.len();
    if count < 2 {
        return;
    }
    let segments = if closed && count > 2 {
        count
    } else {
        count - 1
    };
    let segment = |index: usize| (path[index], path[(index + 1) % count]);
    if !dashes.is_solid() {
        dashed_pieces(path, segments, width, cap, dashes, f);
        return;
    }
    for index in 0..segments {
        let (a, b) = segment(index);
        let d = b.sub(a);
        let o = offset(d, width);
        let (mut a, mut b) = (a, b);
        if !closed && cap == Cap::Square {
            let e = along(d, width);
            if index == 0 {
                a = a.sub(e);
            }
            if index == segments - 1 {
                b = b.add(e);
            }
        }
        f(Piece::polygon(&[a.add(o), b.add(o), b.sub(o), a.sub(o)]));
    }
    let joins = if closed && count > 2 {
        segments
    } else {
        segments - 1
    };
    for index in 0..joins {
        let (a, v) = segment(index);
        let (_, b) = segment((index + 1) % segments);
        join_piece(a, v, b, width, join, f);
    }
    if !closed && cap == Cap::Round {
        f(Piece::Disk {
            center: path[0],
            width,
        });
        f(Piece::Disk {
            center: path[count - 1],
            width,
        });
    }
}

/// The join at `v` between the segments from `a` and to `b`.
fn join_piece(a: Fx, v: Fx, b: Fx, width: u32, join: Join, f: &mut impl FnMut(Piece)) {
    let (d1, d2) = (v.sub(a), b.sub(v));
    let turn = cross(d1, d2);
    if turn == 0 {
        return;
    }
    // The outer side: the offsets' opposite for a turn one way, the offsets for the other.
    let (o1, o2) = (offset(d1, width), offset(d2, width));
    let (o1, o2) = if turn > 0 {
        (o1.neg(), o2.neg())
    } else {
        (o1, o2)
    };
    let (p1, p2) = (v.add(o1), v.add(o2));
    match join {
        Join::Bevel => f(Piece::polygon(&[v, p1, p2])),
        Join::Miter => {
            let den = cross(d1, d2);
            let t_num = cross(p2.sub(p1), d2);
            let tip = Fx {
                x: p1.x + round_div(t_num * i128::from(d1.x), den) as i64,
                y: p1.y + round_div(t_num * i128::from(d1.y), den) as i64,
            };
            let reach = tip.sub(v);
            let limit = i128::from(width) * 5 * i128::from(ONE);
            let far = i128::from(reach.x) * i128::from(reach.x)
                + i128::from(reach.y) * i128::from(reach.y);
            if far > limit * limit {
                f(Piece::polygon(&[v, p1, p2]));
            } else {
                f(Piece::polygon(&[v, p1, tip, p2]));
            }
        }
        Join::Round => {
            // The wedge from p1 to p2 round the outside, through the arc's points at multiples of
            // 45 degrees strictly between them.
            let r = i64::from(width) * (ONE / 2);
            let diagonal = round_div(i128::from(r) * 7_071_067_812, 10_000_000_000) as i64;
            let directions = [
                Fx { x: r, y: 0 },
                Fx {
                    x: diagonal,
                    y: diagonal,
                },
                Fx { x: 0, y: r },
                Fx {
                    x: -diagonal,
                    y: diagonal,
                },
                Fx { x: -r, y: 0 },
                Fx {
                    x: -diagonal,
                    y: -diagonal,
                },
                Fx { x: 0, y: -r },
                Fx {
                    x: diagonal,
                    y: -diagonal,
                },
            ];
            let way = cross(o1, o2).signum();
            if way == 0 {
                return;
            }
            let mut inside = [Fx::default(); 4];
            let mut found = 0;
            for direction in directions {
                if cross(o1, direction).signum() == way
                    && cross(direction, o2).signum() == way
                    && found < inside.len()
                {
                    inside[found] = direction;
                    found += 1;
                }
            }
            let arc = &mut inside[..found];
            arc.sort_unstable_by(|p, q| {
                if cross(*p, *q).signum() == way {
                    core::cmp::Ordering::Less
                } else {
                    core::cmp::Ordering::Greater
                }
            });
            let mut points = [Fx::default(); 8];
            points[0] = v;
            points[1] = p1;
            for (slot, direction) in points[2..].iter_mut().zip(arc.iter()) {
                *slot = v.add(*direction);
            }
            points[2 + found] = p2;
            f(Piece::polygon(&points[..3 + found]));
        }
    }
}

/// A dashed geometric line's pieces: each dash its own band, with the pen's caps at both its ends.
fn dashed_pieces(
    path: &[Fx],
    segments: usize,
    width: u32,
    cap: Cap,
    dashes: &Dashes,
    f: &mut impl FnMut(Piece),
) {
    let count = path.len();
    let mut position = 0u64;
    for index in 0..segments {
        let (a, b) = (path[index], path[(index + 1) % count]);
        let d = b.sub(a);
        let length_sq = i128::from(d.x) * i128::from(d.x) + i128::from(d.y) * i128::from(d.y);
        // The segment's length, in sixteenths.
        let length = isqrt(length_sq as u128) as u64;
        let mut done = 0u64;
        while done < length {
            let run_end = dashes.run_end(position / ONE as u64) * ONE as u64;
            let step = run_end.saturating_sub(position).min(length - done).max(1);
            if dashes.on_at(position / ONE as u64) {
                let point = |t: u64| Fx {
                    x: a.x + round_div(i128::from(d.x) * i128::from(t), i128::from(length)) as i64,
                    y: a.y + round_div(i128::from(d.y) * i128::from(t), i128::from(length)) as i64,
                };
                let (from, to) = (point(done), point(done + step));
                if from != to {
                    pieces(
                        &[from, to],
                        false,
                        width,
                        cap,
                        Join::Round,
                        &Dashes::SOLID,
                        f,
                    );
                }
            }
            done += step;
            position += step;
        }
    }
}

/// The spans of row `y` a geometric pen's line along `path` covers, merged, into `out` (cleared
/// first); false when the list ran out of room.
#[allow(clippy::too_many_arguments)]
pub fn wide_row<B: Buf<(i32, i32)>>(
    path: &[Fx],
    closed: bool,
    width: u32,
    cap: Cap,
    join: Join,
    dashes: &Dashes,
    y: i32,
    out: &mut B,
) -> bool {
    out.truncate(0);
    let mut ok = true;
    pieces(path, closed, width, cap, join, dashes, &mut |piece| {
        if let Some(span) = piece.span(y) {
            ok &= out.push(span);
        }
    });
    merge(out);
    ok
}

/// `spans` sorted and merged where they touch or overlap.
pub fn merge<B: Buf<(i32, i32)>>(spans: &mut B) {
    let list = spans.as_mut_slice();
    list.sort_unstable();
    let mut kept = 0usize;
    for index in 0..list.len() {
        let (from, to) = list[index];
        if kept > 0 && from <= list[kept - 1].1 {
            list[kept - 1].1 = list[kept - 1].1.max(to);
        } else {
            list[kept] = (from, to);
            kept += 1;
        }
    }
    spans.truncate(kept);
}

/// The span from `from` to before `to` less the merged spans `holes`, each part handed to `f`.
pub fn subtract(from: i32, to: i32, holes: &[(i32, i32)], mut f: impl FnMut(i32, i32)) {
    let mut at = from;
    for &(left, right) in holes {
        if right <= at {
            continue;
        }
        if left >= to {
            break;
        }
        if left > at {
            f(at, left);
        }
        at = at.max(right);
    }
    if at < to {
        f(at, to);
    }
}

/// The rows a geometric line along `path` of `width` may touch.
pub fn rows_of(path: &[Fx], width: u32) -> (i32, i32) {
    let reach = i64::from(width) * ONE;
    let top = path.iter().map(|p| p.y).min().unwrap_or(0) - reach;
    let bottom = path.iter().map(|p| p.y).max().unwrap_or(0) + reach;
    (
        clamp32(floor_div(i128::from(top), i128::from(ONE))),
        clamp32(ceil_div(i128::from(bottom), i128::from(ONE)) + 1),
    )
}

/// The span list a row's wide line or fill is gathered in.
pub type SpanBuf = SmallBuf<(i32, i32), 32>;

/// An empty [`SpanBuf`].
pub fn span_buf() -> SpanBuf {
    SmallBuf::new((0, 0), 1 << 16)
}

// --- Figures -------------------------------------------------------------------------------------

/// A figure's interior, what its brush fills: none, a convex polygon (28.4), a rectangle, or a
/// region's banded rectangles (all the surface's coordinates).
#[derive(Clone, Copy, Debug)]
pub enum Interior<'a> {
    None,
    Convex(&'a [Fx]),
    Rect(Rect),
    Rects(&'a [Rect]),
}

impl Interior<'_> {
    /// Its rows, from one to before the other.
    fn rows(&self) -> (i32, i32) {
        match self {
            Interior::None => (0, 0),
            Interior::Convex(polygon) => rows_of(polygon, 0),
            Interior::Rect(rect) => (rect.top, rect.bottom),
            Interior::Rects(rects) => (
                rects.iter().map(|r| r.top).min().unwrap_or(0),
                rects.iter().map(|r| r.bottom).max().unwrap_or(0),
            ),
        }
    }

    /// Its spans on row `y`, each handed to `f`.
    fn spans(&self, y: i32, mut f: impl FnMut(i32, i32)) {
        match self {
            Interior::None => {}
            Interior::Convex(polygon) => {
                if let Some((from, to)) = convex_span(polygon, y) {
                    f(from, to);
                }
            }
            Interior::Rect(rect) => {
                if rect.top <= y && y < rect.bottom && rect.left < rect.right {
                    f(rect.left, rect.right);
                }
            }
            Interior::Rects(rects) => {
                for rect in rects.iter().filter(|r| r.top <= y && y < r.bottom) {
                    f(rect.left, rect.right);
                }
            }
        }
    }
}

/// A figure drawn: its interior filled with `brush` (none: the null brush), then its outline along
/// `path` (closed when `closed`) with the pen's `stroke` in the pen's pixel `pen` (its gaps in
/// `gap` when there is one: the background under OPAQUE). A wide pen's pixels are left out of the
/// fill, so each pixel is drawn once. False when a list ran out of room.
#[allow(clippy::too_many_arguments)]
pub fn draw<S: Surface + ?Sized>(
    painter: &mut Painter<'_, S>,
    stroke: &Stroke,
    pen: u32,
    gap: Option<u32>,
    path: &[Fx],
    closed: bool,
    interior: Interior,
    brush: Option<&Ink>,
) -> bool {
    let mut spans = span_buf();
    let mut ok = true;
    if let Some(brush) = brush {
        let (top, bottom) = interior.rows();
        for y in top..bottom {
            if let Stroke::Geometric {
                width,
                cap,
                join,
                dashes,
                ..
            } = stroke
            {
                ok &= wide_row(path, closed, *width, *cap, *join, dashes, y, &mut spans);
            } else {
                spans.truncate(0);
            }
            interior.spans(y, |from, to| {
                subtract(from, to, spans.as_slice(), |left, right| {
                    painter.span(y, left, right, brush)
                })
            });
        }
    }
    match stroke {
        Stroke::Null => {}
        Stroke::Cosmetic { dashes, .. } => cosmetic_path(path, closed, dashes, |x, y, on| {
            if on {
                painter.plot(x, y, pen);
            } else if let Some(gap) = gap {
                painter.plot(x, y, gap);
            }
        }),
        Stroke::Geometric {
            width,
            cap,
            join,
            dashes,
            ..
        } => {
            let (top, bottom) = rows_of(path, *width);
            for y in top..bottom {
                ok &= wide_row(path, closed, *width, *cap, *join, dashes, y, &mut spans);
                for &(from, to) in spans.as_slice() {
                    painter.span(y, from, to, &Ink::Pixel(pen));
                }
            }
        }
    }
    ok
}

// --- Shapes --------------------------------------------------------------------------------------

/// The shapes a box makes: Rectangle's, Ellipse's, RoundRect's (its corners' ellipse's width and
/// height).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Shape {
    Rectangle,
    Ellipse,
    RoundRect(i32, i32),
}

/// The points of `path` with the repeats in a row left out (and, for a closed path, a last point
/// that is its first), into `out`: how many.
pub fn dedup(path: &[Fx], closed: bool, out: &mut [Fx]) -> usize {
    let mut count = 0usize;
    for &point in path {
        if count == 0 || out[count - 1] != point {
            out[count] = point;
            count += 1;
        }
    }
    while closed && count > 1 && out[count - 1] == out[0] {
        count -= 1;
    }
    count
}

/// `shape` drawn in the box from (`left`, `top`) to (`right`, `bottom`) (the surface's pixels, in
/// either order) with the pen's `stroke` and the brush (see [`draw`]), as the shapes capture shows
/// Windows 2000 drawing it:
///
/// - an empty box draws nothing;
/// - a cosmetic pen's outline runs through the box's pixels, its right and bottom ones the last
///   inside it (Rectangle(1, 1, 8, 6)'s outline is at columns 1 and 7), Rectangle's from its top
///   right corner counter-clockwise, and a Rectangle's interior the pixels inside it;
/// - a geometric pen's outline runs along the same box, its band astride it, but for
///   PS_INSIDEFRAME, whose band runs half the width inside the box, so that the frame's outer edge
///   is the box's; the interior is the outline's own fill;
/// - with the null pen, the fill alone: a Rectangle's one pixel short of the box on the right and
///   at the bottom, an ellipse's or a rounded rectangle's the curve of the box a pixel smaller,
///   moved half a pixel up and left;
/// - a Rectangle's corners are mitred whatever the pen's join;
/// - a rounded rectangle's corners are at most the box's size, and a corner of no width or height
///   makes a Rectangle.
#[allow(clippy::too_many_arguments)]
pub fn draw_shape<S: Surface + ?Sized>(
    painter: &mut Painter<'_, S>,
    stroke: &Stroke,
    pen: u32,
    gap: Option<u32>,
    shape: Shape,
    (left, top, right, bottom): (i32, i32, i32, i32),
    brush: Option<&Ink>,
) -> bool {
    let (left, right) = (left.min(right), left.max(right));
    let (top, bottom) = (top.min(bottom), top.max(bottom));
    if left == right || top == bottom {
        return true;
    }
    let shape = match shape {
        Shape::RoundRect(0, _) | Shape::RoundRect(_, 0) => Shape::Rectangle,
        other => other,
    };
    let sixteenths = |value: i32| i64::from(value) * ONE;
    let (l, t, r, b) = match stroke {
        Stroke::Null => (
            sixteenths(left) - ONE / 2,
            sixteenths(top) - ONE / 2,
            sixteenths(right) - 3 * ONE / 2,
            sixteenths(bottom) - 3 * ONE / 2,
        ),
        Stroke::Geometric {
            inside_frame: true,
            width,
            ..
        } => {
            let half = i64::from(*width) * ONE / 2;
            (
                sixteenths(left) + half,
                sixteenths(top) + half,
                sixteenths(right) - half,
                sixteenths(bottom) - half,
            )
        }
        _ => (
            sixteenths(left),
            sixteenths(top),
            sixteenths(right - 1),
            sixteenths(bottom - 1),
        ),
    };
    let mut path = [Fx::default(); 12];
    let count = match shape {
        Shape::Rectangle => {
            if *stroke == Stroke::Null {
                let fill = Rect::new(left, top, right - 1, bottom - 1);
                return draw(
                    painter,
                    stroke,
                    pen,
                    gap,
                    &[],
                    false,
                    Interior::Rect(fill),
                    brush,
                );
            }
            let corners = [
                Fx { x: r, y: t },
                Fx { x: l, y: t },
                Fx { x: l, y: b },
                Fx { x: r, y: b },
            ];
            dedup(&corners, true, &mut path)
        }
        Shape::Ellipse => dedup(&ellipse_path(l, t, r, b), true, &mut path),
        Shape::RoundRect(width, height) => {
            let rx = (i64::from(width.unsigned_abs()) * ONE).min(r - l) / 2;
            let ry = (i64::from(height.unsigned_abs()) * ONE).min(b - t) / 2;
            dedup(&round_rect_path(l, t, r, b, rx, ry), true, &mut path)
        }
    };
    let path = &path[..count];
    let interior = match (shape, stroke) {
        (Shape::Rectangle, Stroke::Cosmetic { .. }) => {
            Interior::Rect(Rect::new(left + 1, top + 1, right - 1, bottom - 1))
        }
        _ => Interior::Convex(path),
    };
    let outline = if *stroke == Stroke::Null {
        &[][..]
    } else {
        path
    };
    // A Rectangle's corners are square whatever the pen's join (the capture's inside-frame
    // rectangle keeps its corners' pixels, where a round join's arc would cut them).
    let stroke = match (shape, *stroke) {
        (
            Shape::Rectangle,
            Stroke::Geometric {
                color,
                width,
                cap,
                dashes,
                inside_frame,
                ..
            },
        ) => Stroke::Geometric {
            color,
            width,
            cap,
            join: Join::Miter,
            dashes,
            inside_frame,
        },
        (_, stroke) => stroke,
    };
    draw(painter, &stroke, pen, gap, outline, true, interior, brush)
}

#[cfg(test)]
mod tests;
