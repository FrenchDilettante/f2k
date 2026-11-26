//! Regions: win32k's region objects, their algebra, and the services gdi32's region calls come
//! through.
//!
//! A region is an object of the object manager ([`crate::ob`]'s Region type), its body a
//! [`Region`]: its rectangles, y-x banded as Windows 2000's REGION keeps them, and its box. Its
//! creator's process holds it through an entry of the GDI handle table ([`super::gdi`]), its
//! handle carrying OBJ_REGION in its kind bits ([`rtl::gdi::object_handle`]), as a brush is held
//! ([`super::brush`]): DeleteObject frees the entry, and the process's end frees every region it
//! still owns.
//!
//! # The bands
//!
//! A region's rectangles are sorted by their top, then by their left. Those sharing a top share a
//! bottom too: a band, a row of rectangles side by side, none overlapping or touching another
//! (two that touch are one). The bands do not overlap. The algebra ([`combine`]) answers a band
//! for each stretch of rows over which both sources' bands are the same, and merges a band into
//! the one above when it touches it and has the same rectangles across (the coalescing Windows
//! 2000's region code does), so a region has one form: the regions capture's rectangles for each
//! CombineRgn mode are these. The empty region has no rectangle and an empty box.
//!
//! A polygon's region ([`polygon`]) is scanned a row at a time, as Windows 2000's is: each row a
//! band of its own, never merged with the row above (the capture's pentagram is 17 rectangles
//! under ALTERNATE, where merging its two topmost rows would make 16). A row `y` holds the pixels
//! from where the outline's edges cross the line `y` (the crossing rounded up) to where the next
//! crossing is (rounded up, not included): pairs of crossings under ALTERNATE, the stretches the
//! outline winds around under WINDING. An edge holds the rows from its upper end to its lower
//! end, not including the lower one; a horizontal edge none. The box of a polygon's region is its
//! points' (the capture's pentagram, whose top row is empty, has a box from 0).
//!
//! # Where the rectangles are
//!
//! A region of at most [`INLINE`] rectangles keeps them in its body; a larger one in a block of
//! the nonpaged pool ([`crate::mem::pool`]) its body names, which goes with the region (the
//! object's deletion, [`release_storage`]). The algebra writes its answer into a [`SmallBuf`],
//! which spills from the stack into the pool as it grows. A region's rectangles are read and
//! replaced in one hold of the object directory, so no thread reads a block another thread's call
//! gives back.
//!
//! # The services
//!
//! F2K's argument lists (see [`crate::win32k`]); a region's complexity is NULLREGION,
//! SIMPLEREGION or COMPLEXREGION:
//!
//! - NtGdiCreateRectRgn(i32 Left, i32 Top, i32 Right, i32 Bottom, ptr<u32> Region): a region of the
//!   rectangle, its edges put in order (an empty one is the empty region);
//! - NtGdiPolyPolyDraw(u32 Dc, ptr Points, ptr Counts, u32 Count, u32 Function, ptr<u32> Result):
//!   with I_POLYPOLYRGN, a region of the `Count` polygons (`Dc` its fill mode, as Windows 2000's
//!   gdi32 passes it); the other functions draw, which F2K does not yet do
//!   (STATUS_NOT_IMPLEMENTED);
//! - NtGdiSetRectRgn(handle Region, i32 Left, i32 Top, i32 Right, i32 Bottom): the region made the
//!   rectangle;
//! - NtGdiCombineRgn(handle Dest, handle Source1, handle Source2, u32 Mode, ptr<u32> Complexity):
//!   `Dest` made the sources' combination (RGN_COPY: the first's, `Source2` unread);
//!   STATUS_INVALID_PARAMETER for another mode, `Dest` untouched;
//! - NtGdiOffsetRgn(handle Region, i32 X, i32 Y, ptr<u32> Complexity): the region moved;
//! - NtGdiGetRgnBox(handle Region, ptr Box, ptr<u32> Complexity): its box (the empty rectangle for
//!   the empty region);
//! - NtGdiEqualRgn(handle Region1, handle Region2, ptr<u32> Equal): whether they hold the same
//!   rectangles;
//! - NtGdiPtInRegion(handle Region, i32 X, i32 Y, ptr<u32> Inside);
//! - NtGdiGetRegionData(handle Region, u32 Count, ptr Buffer, ptr<u32> Size): the RGNDATA (an
//!   RGNDATAHEADER, then the rectangles) into `Buffer` when `Count` bytes hold it, its size into
//!   `Size` (alone for a null buffer); STATUS_INVALID_PARAMETER when they do not (the capture's
//!   ERROR_INVALID_PARAMETER);
//! - NtGdiFillRgn(handle Dc, handle Region, handle Brush, ptr<u32> Result): the region (logical
//!   coordinates) painted with the brush, clipped as the DC clips; `Result` 0 for the null brush,
//!   which paints nothing;
//! - NtGdiFlush(): nothing of its own: the dispatcher runs the calling thread's GDI batch before
//!   any win32k service ([`run_batch`]), and GdiFlush calls this one for that.
//!
//! Every service of the region object's own fails with STATUS_INVALID_HANDLE for a handle that
//! names no region of the calling process.
//!
//! # The GDI batch
//!
//! gdi32's DeleteObject of a region queues the deletion in the calling thread's TEB (its GDI
//! batch, [`rtl::gdi::BATCH_DELETE_REGION`]) rather than entering the kernel, as Windows 2000's
//! does, and the region lives until the batch runs: on the thread's next win32k service, which the
//! dispatcher runs it before ([`run_batch`], Windows 2000's KeGdiFlushUserBatch at the system
//! service dispatch), or its GdiFlush. A batch left when its thread ends is not run; the regions
//! go with their process.

use rtl::gdi::*;

use crate::nt::call::{Handle, NtCall, NtResult, UserAddr, UserPtr};
use crate::status::*;

// --- Buffers -------------------------------------------------------------------------------------

/// A growable list the algebra writes into: a vector on the host, a [`SmallBuf`] in the kernel.
pub trait Buf<T: Copy> {
    /// `value` added at the end; false when there is no room left for it.
    fn push(&mut self, value: T) -> bool;
    /// The values, in order.
    fn as_slice(&self) -> &[T];
    /// The values, to change.
    fn as_mut_slice(&mut self) -> &mut [T];
    /// The values past the first `len` dropped.
    fn truncate(&mut self, len: usize);

    fn len(&self) -> usize {
        self.as_slice().len()
    }

    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
impl<T: Copy> Buf<T> for std::vec::Vec<T> {
    fn push(&mut self, value: T) -> bool {
        std::vec::Vec::push(self, value);
        true
    }

    fn as_slice(&self) -> &[T] {
        self
    }

    fn as_mut_slice(&mut self) -> &mut [T] {
        self
    }

    fn truncate(&mut self, len: usize) {
        std::vec::Vec::truncate(self, len)
    }
}

/// The most rectangles a region holds (2 MiB of them), and so the most a [`SmallBuf`] of
/// rectangles takes: a call whose answer would hold more fails, as one the pool cannot hold does.
pub const MOST_RECTS: usize = 1 << 17;

/// The most points a polygon region is made of.
pub const MOST_POINTS: usize = 1 << 16;

/// A block of the pool (the host's heap in the host tests): its address and its size.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Spill {
    address: usize,
    bytes: usize,
}

/// A zeroed block of `bytes` bytes, page-aligned; none when the pool has no room.
#[cfg(target_arch = "x86")]
fn allocate(bytes: usize) -> Option<Spill> {
    let block = crate::mem::pool::allocate(bytes)?;
    let address = block.virtual_address() as usize;
    block.leak();
    Some(Spill { address, bytes })
}

/// Give back a block [`allocate`] made.
#[cfg(target_arch = "x86")]
fn release(spill: Spill) {
    crate::mem::pool::release_block(spill.address as u32, spill.bytes);
}

#[cfg(not(target_arch = "x86"))]
fn allocate(bytes: usize) -> Option<Spill> {
    let words = std::vec![0u64; bytes.div_ceil(8)].leak();
    Some(Spill {
        address: words.as_mut_ptr() as usize,
        bytes,
    })
}

#[cfg(not(target_arch = "x86"))]
fn release(spill: Spill) {
    let words = spill.bytes.div_ceil(8);
    // SAFETY: the vector `allocate` leaked, of that length.
    drop(unsafe { std::vec::Vec::from_raw_parts(spill.address as *mut u64, words, words) });
}

/// A list of up to `N` values on the stack, then in a block of the pool that doubles as it fills
/// (at most `limit` values).
pub struct SmallBuf<T: Copy, const N: usize> {
    len: usize,
    limit: usize,
    inline: [T; N],
    spill: Option<Spill>,
}

impl<T: Copy, const N: usize> SmallBuf<T, N> {
    /// An empty list of at most `limit` values; `fill` the stack part's unused values.
    pub fn new(fill: T, limit: usize) -> Self {
        SmallBuf {
            len: 0,
            limit,
            inline: [fill; N],
            spill: None,
        }
    }

    fn capacity(&self) -> usize {
        self.spill
            .map_or(N, |spill| spill.bytes / core::mem::size_of::<T>())
    }

    /// Room for one more: the values moved to a block twice as large (a page at least).
    fn grow(&mut self) -> bool {
        let size = core::mem::size_of::<T>();
        let wanted = (self.capacity() * 2).max(4096 / size).min(self.limit);
        if wanted <= self.len {
            return false;
        }
        let Some(spill) = allocate(wanted * size) else {
            return false;
        };
        // SAFETY: the new block holds `wanted` values (page-aligned, and so aligned for any `T`
        // the algebra keeps), more than `len`; the old values are `len` of them.
        unsafe {
            core::ptr::copy_nonoverlapping(
                self.as_slice().as_ptr(),
                spill.address as *mut T,
                self.len,
            );
        }
        if let Some(old) = self.spill.replace(spill) {
            release(old);
        }
        true
    }

    /// Take the block out (the caller gives it back): none while the values are on the stack.
    fn take_spill(&mut self) -> Option<Spill> {
        let spill = self.spill.take();
        self.len = 0;
        spill
    }
}

impl<T: Copy, const N: usize> Buf<T> for SmallBuf<T, N> {
    fn push(&mut self, value: T) -> bool {
        if self.len == self.capacity() && !self.grow() {
            return false;
        }
        match self.spill {
            // SAFETY: the block holds `capacity` values, `len` below it.
            Some(spill) => unsafe { (spill.address as *mut T).add(self.len).write(value) },
            None => self.inline[self.len] = value,
        }
        self.len += 1;
        true
    }

    fn as_slice(&self) -> &[T] {
        match self.spill {
            // SAFETY: the block is the list's alone while it lives, its first `len` values set.
            Some(spill) => unsafe {
                core::slice::from_raw_parts(spill.address as *const T, self.len)
            },
            None => &self.inline[..self.len],
        }
    }

    fn as_mut_slice(&mut self) -> &mut [T] {
        match self.spill {
            // SAFETY: as in `as_slice`, borrowed exclusively.
            Some(spill) => unsafe {
                core::slice::from_raw_parts_mut(spill.address as *mut T, self.len)
            },
            None => &mut self.inline[..self.len],
        }
    }

    fn truncate(&mut self, len: usize) {
        self.len = self.len.min(len);
    }
}

impl<T: Copy, const N: usize> Drop for SmallBuf<T, N> {
    fn drop(&mut self) {
        if let Some(spill) = self.spill.take() {
            release(spill);
        }
    }
}

/// The rectangles the algebra answers into, as the services keep them: on the stack as many as a
/// region keeps in its body, so a region of more always has a block to take.
pub type RectBuf = SmallBuf<Rect, INLINE>;

/// An empty [`RectBuf`].
pub fn rect_buf() -> RectBuf {
    SmallBuf::new(Rect::EMPTY, MOST_RECTS)
}

// --- The algebra ---------------------------------------------------------------------------------

/// The box of `rects`: the empty rectangle for none.
pub fn bounds_of(rects: &[Rect]) -> Rect {
    rects
        .iter()
        .fold(Rect::EMPTY, |bounds, rect| bounds.union(*rect))
}

/// The index past the band `rects[start]` begins (the rectangles sharing its top and bottom).
fn band_end(rects: &[Rect], start: usize) -> usize {
    let Some(first) = rects.get(start) else {
        return rects.len();
    };
    let mut end = start + 1;
    while end < rects.len() && rects[end].top == first.top && rects[end].bottom == first.bottom {
        end += 1;
    }
    end
}

/// A banded list of rectangles being built, a band at a time, its rectangles in order: the
/// stretches of a band touching are merged, and with `coalesce` a band touching the one above with
/// the same stretches is merged into it.
struct Bands<'a, B: Buf<Rect>> {
    out: &'a mut B,
    coalesce: bool,
    /// Where the band before the one being built starts, if any.
    previous: Option<usize>,
    /// Where the band being built starts.
    current: usize,
    /// False once a rectangle found no room.
    ok: bool,
}

impl<'a, B: Buf<Rect>> Bands<'a, B> {
    fn new(out: &'a mut B, coalesce: bool) -> Self {
        out.truncate(0);
        Bands {
            out,
            coalesce,
            previous: None,
            current: 0,
            ok: true,
        }
    }

    fn begin(&mut self) {
        self.current = self.out.len();
    }

    /// The stretch from `left` to `right` (not included) of the band from `top` to `bottom`, after
    /// the band's others.
    fn span(&mut self, left: i32, right: i32, top: i32, bottom: i32) {
        if left >= right {
            return;
        }
        let len = self.out.len();
        if len > self.current {
            let last = &mut self.out.as_mut_slice()[len - 1];
            if last.right >= left {
                last.right = last.right.max(right);
                return;
            }
        }
        self.ok &= self.out.push(Rect::new(left, top, right, bottom));
    }

    /// The band built: merged into the one above when it can be.
    fn end(&mut self) {
        let start = self.current;
        let len = self.out.len();
        if len == start {
            return;
        }
        if let Some(previous) = self.previous.filter(|_| self.coalesce) {
            let rects = self.out.as_mut_slice();
            let (above, band) = rects[previous..len].split_at_mut(start - previous);
            let same = above.len() == band.len()
                && above[0].bottom == band[0].top
                && above
                    .iter()
                    .zip(band.iter())
                    .all(|(a, b)| a.left == b.left && a.right == b.right);
            if same {
                let bottom = band[0].bottom;
                for rect in above.iter_mut() {
                    rect.bottom = bottom;
                }
                self.out.truncate(start);
                return;
            }
        }
        self.previous = Some(start);
    }
}

/// Whether CombineRgn's `mode` keeps a point the first source holds (`in_a`) or the second does
/// (`in_b`); none for a mode that is no CombineRgn mode.
pub fn keeps(mode: u32) -> Option<fn(bool, bool) -> bool> {
    Some(match mode {
        RGN_AND => |a, b| a && b,
        RGN_OR => |a, b| a || b,
        RGN_XOR => |a, b| a != b,
        RGN_DIFF => |a, b| a && !b,
        RGN_COPY => |a, _| a,
        _ => return None,
    })
}

/// The stretches of one row that `keep` keeps of the first band's (`a`) and the second's (`b`)
/// rectangles, each handed to `emit` as its left and right, in order.
fn row_spans(a: &[Rect], b: &[Rect], keep: fn(bool, bool) -> bool, mut emit: impl FnMut(i32, i32)) {
    let (mut i, mut j) = (0, 0);
    let mut x = match (a.first(), b.first()) {
        (Some(ra), Some(rb)) => ra.left.min(rb.left),
        (Some(r), None) | (None, Some(r)) => r.left,
        (None, None) => return,
    };
    loop {
        let in_a = i < a.len() && a[i].left <= x;
        let in_b = j < b.len() && b[j].left <= x;
        let next = |rects: &[Rect], at: usize, inside: bool| match rects.get(at) {
            Some(rect) if inside => rect.right,
            Some(rect) => rect.left,
            None => i32::MAX,
        };
        let to = next(a, i, in_a).min(next(b, j, in_b));
        if to == i32::MAX {
            return;
        }
        if keep(in_a, in_b) {
            emit(x, to);
        }
        x = to;
        if i < a.len() && a[i].right <= x {
            i += 1;
        }
        if j < b.len() && b[j].right <= x {
            j += 1;
        }
    }
}

/// CombineRgn's algebra: the banded rectangles of the region `keep` makes of the banded regions
/// `a` and `b` (see the module notes), into `out`; false when `out` ran out of room.
pub fn combine<B: Buf<Rect>>(
    a: &[Rect],
    b: &[Rect],
    keep: fn(bool, bool) -> bool,
    out: &mut B,
) -> bool {
    let mut bands = Bands::new(out, true);
    let (mut ia, mut ib) = (0, 0);
    let mut y = match (a.first(), b.first()) {
        (Some(ra), Some(rb)) => ra.top.min(rb.top),
        (Some(r), None) | (None, Some(r)) => r.top,
        (None, None) => return true,
    };
    while ia < a.len() || ib < b.len() {
        let (ja, jb) = (band_end(a, ia), band_end(b, ib));
        let on = |rects: &[Rect], at: usize| rects.get(at).is_some_and(|rect| rect.top <= y);
        let (a_on, b_on) = (on(a, ia), on(b, ib));
        let next = |rects: &[Rect], at: usize, inside: bool| match rects.get(at) {
            Some(rect) if inside => rect.bottom,
            Some(rect) => rect.top,
            None => i32::MAX,
        };
        let to = next(a, ia, a_on).min(next(b, ib, b_on));
        let row_a = if a_on { &a[ia..ja] } else { &[] };
        let row_b = if b_on { &b[ib..jb] } else { &[] };
        if !row_a.is_empty() || !row_b.is_empty() {
            bands.begin();
            row_spans(row_a, row_b, keep, |left, right| {
                bands.span(left, right, y, to)
            });
            bands.end();
        }
        y = to;
        if a.get(ia).is_some_and(|rect| rect.bottom <= y) {
            ia = ja;
        }
        if b.get(ib).is_some_and(|rect| rect.bottom <= y) {
            ib = jb;
        }
    }
    bands.ok
}

/// The region of one rectangle: its edges put in order, none when it is empty.
pub fn ordered(left: i32, top: i32, right: i32, bottom: i32) -> Option<Rect> {
    let rect = Rect::new(
        left.min(right),
        top.min(bottom),
        left.max(right),
        top.max(bottom),
    );
    (!rect.is_empty()).then_some(rect)
}

/// `numerator / denominator` rounded up (`denominator` positive).
fn ceil_div(numerator: i64, denominator: i64) -> i64 {
    -((-numerator).div_euclid(denominator))
}

/// One edge's crossing of a row: where (rounded up) and which way the edge goes (1 down, -1 up).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Crossing {
    pub x: i32,
    pub direction: i32,
}

/// The polygons' edges: each polygon of `counts` points (in order in `points`) closed.
fn edges<'a>(points: &'a [Point], counts: &'a [u32]) -> impl Iterator<Item = (Point, Point)> + 'a {
    let mut start = 0usize;
    counts.iter().flat_map(move |&count| {
        let polygon = &points[start..start + count as usize];
        start += count as usize;
        (0..polygon.len()).map(move |i| (polygon[i], polygon[(i + 1) % polygon.len()]))
    })
}

/// CreatePolygonRgn's scan (see the module notes): the rows of the polygons (`counts` points each,
/// in order in `points`) under ALTERNATE or `winding`, into `out`, a band a row; `crossings` the
/// scratch list a row's crossings are sorted in. False when a list ran out of room.
pub fn polygon<B: Buf<Rect>, C: Buf<Crossing>>(
    points: &[Point],
    counts: &[u32],
    winding: bool,
    out: &mut B,
    crossings: &mut C,
) -> bool {
    let (Some(top), Some(bottom)) = (
        points.iter().map(|p| p.y).min(),
        points.iter().map(|p| p.y).max(),
    ) else {
        return true;
    };
    let mut bands = Bands::new(out, false);
    for y in top..bottom {
        crossings.truncate(0);
        for (p, q) in edges(points, counts) {
            if p.y == q.y || y < p.y.min(q.y) || y >= p.y.max(q.y) {
                continue;
            }
            let (dy, dx) = (
                i64::from(q.y) - i64::from(p.y),
                i64::from(q.x) - i64::from(p.x),
            );
            let numerator = i64::from(p.x) * dy + (i64::from(y) - i64::from(p.y)) * dx;
            let x = if dy > 0 {
                ceil_div(numerator, dy)
            } else {
                ceil_div(-numerator, -dy)
            };
            let crossing = Crossing {
                x: x.clamp(i64::from(i32::MIN), i64::from(i32::MAX)) as i32,
                direction: if dy > 0 { 1 } else { -1 },
            };
            if !crossings.push(crossing) {
                return false;
            }
        }
        let row = crossings.as_mut_slice();
        row.sort_unstable_by_key(|crossing| crossing.x);
        bands.begin();
        if winding {
            let (mut wind, mut from) = (0, 0);
            for crossing in row.iter() {
                if wind == 0 {
                    from = crossing.x;
                }
                wind += crossing.direction;
                if wind == 0 {
                    bands.span(from, crossing.x, y, y + 1);
                }
            }
        } else {
            for [from, to] in row.as_chunks::<2>().0 {
                bands.span(from.x, to.x, y, y + 1);
            }
        }
        bands.end();
        if !bands.ok {
            return false;
        }
    }
    bands.ok
}

/// The box of a polygon region of `points`: the points' (none for an empty region).
pub fn polygon_bounds(points: &[Point], empty: bool) -> Rect {
    if empty || points.is_empty() {
        return Rect::EMPTY;
    }
    let mut bounds = Rect::new(points[0].x, points[0].y, points[0].x, points[0].y);
    for p in points {
        bounds.left = bounds.left.min(p.x);
        bounds.top = bounds.top.min(p.y);
        bounds.right = bounds.right.max(p.x);
        bounds.bottom = bounds.bottom.max(p.y);
    }
    bounds
}

/// Whether (`x`, `y`) lies in one of `rects`.
pub fn contains(rects: &[Rect], x: i32, y: i32) -> bool {
    rects.iter().any(|rect| rect.contains(x, y))
}

/// The farthest a region's coordinates reach either way, as Windows 2000's regions keep them (28
/// bits): OffsetRgn moving one past it fails.
pub const MOST_COORDINATE: i32 = (1 << 27) - 1;

/// `rect` moved by `dx` and `dy`; none when an edge would pass [`MOST_COORDINATE`].
pub fn moved(rect: Rect, dx: i32, dy: i32) -> Option<Rect> {
    let edge = |at: i32, by: i32| {
        let moved = i64::from(at) + i64::from(by);
        (moved.abs() <= i64::from(MOST_COORDINATE)).then_some(moved as i32)
    };
    Some(Rect::new(
        edge(rect.left, dx)?,
        edge(rect.top, dy)?,
        edge(rect.right, dx)?,
        edge(rect.bottom, dy)?,
    ))
}

/// The RGNDATAHEADER of a region of `count` rectangles and box `bounds`.
pub fn data_header(count: usize, bounds: Rect) -> RgnDataHeader {
    RgnDataHeader {
        size: core::mem::size_of::<RgnDataHeader>() as u32,
        kind: RDH_RECTANGLES,
        count: count as u32,
        rgn_size: (count * core::mem::size_of::<Rect>()) as u32,
        bound: bounds,
    }
}

/// The bytes of GetRegionData's answer for a region of `count` rectangles.
pub fn data_size(count: usize) -> usize {
    core::mem::size_of::<RgnDataHeader>() + count * core::mem::size_of::<Rect>()
}

// --- The region object ---------------------------------------------------------------------------

/// The rectangles a region keeps in its body; a larger region keeps them in a block of the pool.
pub const INLINE: usize = 8;

/// Where a region's rectangles are.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Storage {
    Inline([Rect; INLINE]),
    Block(Spill),
}

/// A region object's body: its box and its rectangles (see the module notes).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Region {
    pub bounds: Rect,
    count: u32,
    storage: Storage,
}

impl Region {
    /// The empty region (and a pool's fresh record).
    pub const fn none() -> Self {
        Region {
            bounds: Rect::EMPTY,
            count: 0,
            storage: Storage::Inline([Rect::EMPTY; INLINE]),
        }
    }

    /// The region of one rectangle (the empty region for none).
    pub fn rect(rect: Option<Rect>) -> Self {
        let mut region = Region::none();
        if let Some(rect) = rect {
            region.bounds = rect;
            region.count = 1;
            let mut rects = [Rect::EMPTY; INLINE];
            rects[0] = rect;
            region.storage = Storage::Inline(rects);
        }
        region
    }

    /// The region `buf` holds, its box `bounds` (the rectangles' box for none): `buf`'s block
    /// handed over when there are more than [`INLINE`].
    pub fn of_buf(mut buf: RectBuf, bounds: Option<Rect>) -> Self {
        let rects = buf.as_slice();
        let count = rects.len();
        let bounds = match bounds {
            _ if count == 0 => Rect::EMPTY,
            Some(bounds) => bounds,
            None => bounds_of(rects),
        };
        if count <= INLINE {
            let mut inline = [Rect::EMPTY; INLINE];
            inline[..count].copy_from_slice(rects);
            return Region {
                bounds,
                count: count as u32,
                storage: Storage::Inline(inline),
            };
        }
        let spill = buf
            .take_spill()
            .expect("a list of more rectangles than a body holds has spilled");
        Region {
            bounds,
            count: count as u32,
            storage: Storage::Block(spill),
        }
    }

    /// How many rectangles it has.
    pub fn count(&self) -> usize {
        self.count as usize
    }

    /// Its complexity.
    pub fn complexity(&self) -> i32 {
        region_complexity(self.count())
    }

    /// Its rectangles.
    ///
    /// # Safety
    ///
    /// The region's block (if any) is still its own: read inside the hold of the object directory
    /// the body was read in, before anything replaces or deletes it.
    pub unsafe fn rects(&self) -> &[Rect] {
        match &self.storage {
            Storage::Inline(rects) => &rects[..self.count()],
            // SAFETY: the caller's contract: the block holds `count` rectangles.
            Storage::Block(spill) => unsafe {
                core::slice::from_raw_parts(spill.address as *const Rect, self.count())
            },
        }
    }

    /// A copy of the region, its rectangles in a block of their own; none when the pool has no
    /// room.
    ///
    /// # Safety
    ///
    /// As [`Region::rects`].
    pub unsafe fn duplicate(&self) -> Option<Region> {
        let mut buf = rect_buf();
        // SAFETY: the caller's contract.
        for rect in unsafe { self.rects() } {
            if !buf.push(*rect) {
                return None;
            }
        }
        Some(Region::of_buf(buf, Some(self.bounds)))
    }
}

/// A region its holder owns alone, no other body naming its block: a DC's clipping regions, a
/// window's update region, a copy a service works on. Its block goes back when it drops.
#[derive(Debug, PartialEq, Eq)]
pub struct OwnedRegion(Region);

impl OwnedRegion {
    /// The empty region.
    pub const fn empty() -> Self {
        OwnedRegion(Region::none())
    }

    /// The region of one rectangle (the empty region for an empty one).
    pub fn rect(rect: Rect) -> Self {
        OwnedRegion(Region::rect((!rect.is_empty()).then_some(rect)))
    }

    /// Take `region` over.
    ///
    /// # Safety
    ///
    /// Its block (if any) is no other body's: nothing else gives it back or reads it after.
    pub unsafe fn adopt(region: Region) -> Self {
        OwnedRegion(region)
    }

    /// The region of the banded rectangles `rects` (see the module notes), copied; none when the
    /// pool has no room for them.
    pub fn of_rects(rects: &[Rect]) -> Option<Self> {
        let mut buf = rect_buf();
        for rect in rects {
            if !buf.push(*rect) {
                return None;
            }
        }
        Some(OwnedRegion(Region::of_buf(buf, None)))
    }

    /// What `keep` makes of `a` and `b` (CombineRgn's algebra); none when the pool has no room.
    pub fn combined(a: &[Rect], b: &[Rect], keep: fn(bool, bool) -> bool) -> Option<Self> {
        let mut buf = rect_buf();
        combine(a, b, keep, &mut buf).then(|| OwnedRegion(Region::of_buf(buf, None)))
    }

    /// The region `rects` moved by `dx` and `dy` (each edge saturating); none when the pool has
    /// no room.
    pub fn moved(rects: &[Rect], dx: i32, dy: i32) -> Option<Self> {
        OwnedRegion::mapped(rects, |rect| rect.saturating_offset(dx, dy))
    }

    /// The region `rects` moved back by `dx` and `dy` (each edge saturating:
    /// [`Rect::saturating_offset_back`]); none when the pool has no room.
    pub fn moved_back(rects: &[Rect], dx: i32, dy: i32) -> Option<Self> {
        OwnedRegion::mapped(rects, |rect| rect.saturating_offset_back(dx, dy))
    }

    /// The region of `rects`, each moved by `map` (the bands kept).
    fn mapped(rects: &[Rect], map: impl Fn(&Rect) -> Rect) -> Option<Self> {
        let mut buf = rect_buf();
        for rect in rects {
            if !buf.push(map(rect)) {
                return None;
            }
        }
        Some(OwnedRegion(Region::of_buf(buf, None)))
    }

    /// A copy; none when the pool has no room.
    pub fn duplicate(&self) -> Option<Self> {
        OwnedRegion::of_rects(self.rects())
    }

    /// Its rectangles.
    pub fn rects(&self) -> &[Rect] {
        // SAFETY: the block (if any) is this holder's alone.
        unsafe { self.0.rects() }
    }

    /// Its box (the empty rectangle for the empty region).
    pub fn bounds(&self) -> Rect {
        self.0.bounds
    }

    /// Its complexity.
    pub fn complexity(&self) -> i32 {
        self.0.complexity()
    }

    /// Whether it holds no pixel.
    pub fn is_empty(&self) -> bool {
        self.0.count() == 0
    }

    /// It as the rasterizer clips to it.
    pub fn clip(&self) -> super::raster::Clip<'_> {
        super::raster::Clip::new(self.rects(), self.bounds())
    }

    /// The region's body, its block the caller's to give back from now on.
    pub fn into_inner(self) -> Region {
        let region = self.0;
        core::mem::forget(self);
        region
    }
}

impl Drop for OwnedRegion {
    fn drop(&mut self) {
        release_storage(&self.0);
    }
}

/// Give back the block `region` keeps its rectangles in, if any: the region object's deletion
/// (and a body replaced).
pub fn release_storage(region: &Region) {
    if let Storage::Block(spill) = region.storage {
        release(spill);
    }
}

/// `region` moved by `dx` and `dy`, its rectangles in place; false (the region left as it was)
/// when one would pass [`MOST_COORDINATE`].
///
/// # Safety
///
/// As [`Region::rects`], the block the caller's to change.
pub unsafe fn offset(region: &mut Region, dx: i32, dy: i32) -> bool {
    if region.count == 0 {
        return true;
    }
    let Some(bounds) = moved(region.bounds, dx, dy) else {
        return false;
    };
    // SAFETY: the caller's contract.
    let rects = unsafe { region.rects() };
    if rects.iter().any(|rect| moved(*rect, dx, dy).is_none()) {
        return false;
    }
    region.bounds = bounds;
    let count = region.count();
    match &mut region.storage {
        Storage::Inline(rects) => {
            for rect in &mut rects[..count] {
                *rect = rect.offset(dx, dy);
            }
        }
        Storage::Block(spill) => {
            // SAFETY: the caller's contract: the block is the region's, to change.
            let rects =
                unsafe { core::slice::from_raw_parts_mut(spill.address as *mut Rect, count) };
            for rect in rects {
                *rect = rect.offset(dx, dy);
            }
        }
    }
    true
}

/// The rectangles a service copies out of a region at a time.
pub const CHUNK: usize = 32;

/// I_POLYPOLYRGN: NtGdiPolyPolyDraw's function that makes a region (Windows 2000's).
pub const I_POLYPOLYRGN: u32 = 6;

// --- The services --------------------------------------------------------------------------------

/// NtGdiCreateRectRgn(Left, Top, Right, Bottom, Region): see the module notes.
pub fn create_rect_rgn(
    call: &mut NtCall,
    left: i32,
    top: i32,
    right: i32,
    bottom: i32,
    out: UserPtr<u32>,
) -> NtResult {
    let handle = objects::publish(call, Region::rect(ordered(left, top, right, bottom)))?;
    answer_handle(call, handle, out)
}

/// The new region `handle` into `out`; the region deleted again when it cannot be.
fn answer_handle(call: &mut NtCall, handle: u32, out: UserPtr<u32>) -> NtResult {
    if out.write(handle).is_err() {
        objects::delete(call, handle);
        return Err(STATUS_ACCESS_VIOLATION);
    }
    Ok(STATUS_SUCCESS)
}

/// NtGdiPolyPolyDraw(Dc, Points, Counts, Count, Function, Result): see the module notes.
#[allow(clippy::too_many_arguments)]
pub fn poly_poly_draw(
    call: &mut NtCall,
    dc: u32,
    points: UserAddr,
    counts: UserAddr,
    count: u32,
    function: u32,
    out: UserPtr<u32>,
) -> NtResult {
    if function != I_POLYPOLYRGN {
        return Err(STATUS_NOT_IMPLEMENTED);
    }
    let winding = match dc {
        ALTERNATE => false,
        WINDING => true,
        _ => return Err(STATUS_INVALID_PARAMETER),
    };
    if count == 0 || count as usize > MOST_POINTS / 2 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let mut polygon_counts: SmallBuf<u32, 8> = SmallBuf::new(0, MOST_POINTS / 2);
    let mut total = 0usize;
    for index in 0..count {
        let polygon = counts.offset(index * 4).cast::<u32>().read()?;
        total += polygon as usize;
        if polygon < 2 || total > MOST_POINTS {
            return Err(STATUS_INVALID_PARAMETER);
        }
        if !polygon_counts.push(polygon) {
            return Err(STATUS_NO_MEMORY);
        }
    }
    let mut corners: SmallBuf<Point, 16> = SmallBuf::new(Point::default(), MOST_POINTS);
    for index in 0..total {
        let point = points.offset(index as u32 * 8).cast::<Point>().read()?;
        if !corners.push(point) {
            return Err(STATUS_NO_MEMORY);
        }
    }
    let mut rects = rect_buf();
    let mut crossings: SmallBuf<Crossing, 32> = SmallBuf::new(Crossing::default(), MOST_POINTS);
    if !polygon(
        corners.as_slice(),
        polygon_counts.as_slice(),
        winding,
        &mut rects,
        &mut crossings,
    ) {
        return Err(STATUS_NO_MEMORY);
    }
    let bounds = polygon_bounds(corners.as_slice(), rects.is_empty());
    let handle = objects::publish(call, Region::of_buf(rects, Some(bounds)))?;
    answer_handle(call, handle, out)
}

/// NtGdiSetRectRgn(Region, Left, Top, Right, Bottom): see the module notes.
pub fn set_rect_rgn(
    call: &mut NtCall,
    region: Handle,
    left: i32,
    top: i32,
    right: i32,
    bottom: i32,
) -> NtResult {
    let new = Region::rect(ordered(left, top, right, bottom));
    objects::update(call, region, |old| Ok(core::mem::replace(old, new)))?;
    Ok(STATUS_SUCCESS)
}

/// NtGdiCombineRgn(Dest, Source1, Source2, Mode, Complexity): see the module notes.
pub fn combine_rgn(
    call: &mut NtCall,
    dest: Handle,
    source1: Handle,
    source2: Handle,
    mode: u32,
    out: UserPtr<u32>,
) -> NtResult {
    let keep = keeps(mode).ok_or(STATUS_INVALID_PARAMETER)?;
    let second = (mode != RGN_COPY).then_some(source2);
    let complexity = objects::combine_regions(call, dest, source1, second, keep)?;
    out.write(complexity as u32)?;
    Ok(STATUS_SUCCESS)
}

/// NtGdiOffsetRgn(Region, X, Y, Complexity): see the module notes; STATUS_INVALID_PARAMETER when
/// it would move past [`MOST_COORDINATE`] (the region as it was).
pub fn offset_rgn(
    call: &mut NtCall,
    region: Handle,
    x: i32,
    y: i32,
    out: UserPtr<u32>,
) -> NtResult {
    let complexity = objects::with_region_mut(call, region, |region| {
        // SAFETY: the body read in this hold of the directory, its block its own.
        if unsafe { offset(region, x, y) } {
            Ok(region.complexity())
        } else {
            Err(STATUS_INVALID_PARAMETER)
        }
    })??;
    out.write(complexity as u32)?;
    Ok(STATUS_SUCCESS)
}

/// NtGdiGetRgnBox(Region, Box, Complexity): see the module notes.
pub fn get_rgn_box(
    call: &mut NtCall,
    region: Handle,
    rect: UserAddr,
    out: UserPtr<u32>,
) -> NtResult {
    let (bounds, complexity) =
        objects::with_region_mut(call, region, |region| (region.bounds, region.complexity()))?;
    rect.cast::<Rect>().write(bounds)?;
    out.write(complexity as u32)?;
    Ok(STATUS_SUCCESS)
}

/// NtGdiEqualRgn(Region1, Region2, Equal): see the module notes.
pub fn equal_rgn(call: &mut NtCall, first: Handle, second: Handle, out: UserPtr<u32>) -> NtResult {
    let equal = objects::equal(call, first, second)?;
    out.write(equal as u32)?;
    Ok(STATUS_SUCCESS)
}

/// NtGdiPtInRegion(Region, X, Y, Inside): see the module notes.
pub fn pt_in_region(
    call: &mut NtCall,
    region: Handle,
    x: i32,
    y: i32,
    out: UserPtr<u32>,
) -> NtResult {
    let inside = objects::with_region_mut(call, region, |region| {
        // SAFETY: the body read in this hold of the directory.
        region.bounds.contains(x, y) && contains(unsafe { region.rects() }, x, y)
    })?;
    out.write(inside as u32)?;
    Ok(STATUS_SUCCESS)
}

/// NtGdiGetRegionData(Region, Count, Buffer, Size): see the module notes.
pub fn get_region_data(
    call: &mut NtCall,
    region: Handle,
    count: u32,
    buffer: UserAddr,
    out: UserPtr<u32>,
) -> NtResult {
    let (rects, bounds) =
        objects::with_region_mut(call, region, |region| (region.count(), region.bounds))?;
    let size = data_size(rects);
    if !buffer.is_null() {
        if (count as usize) < size {
            return Err(STATUS_INVALID_PARAMETER);
        }
        buffer.probe(size as u32)?;
        buffer
            .cast::<RgnDataHeader>()
            .write(data_header(rects, bounds))?;
        let mut at = 0;
        while at < rects {
            let mut chunk = [Rect::EMPTY; CHUNK];
            let taken = objects::copy_rects(call, region, at, &mut chunk)?;
            if taken == 0 {
                break;
            }
            let bytes = rtl::pod::slice_bytes(&chunk[..taken]);
            let offset = (core::mem::size_of::<RgnDataHeader>() + at * 16) as u32;
            buffer.offset(offset).write(bytes)?;
            at += taken;
        }
    }
    out.write(size as u32)?;
    Ok(STATUS_SUCCESS)
}

/// NtGdiFillRgn(Dc, Region, Brush, Result): see the module notes.
pub fn fill_rgn(
    call: &mut NtCall,
    dc: Handle,
    region: Handle,
    brush: Handle,
    out: UserPtr<u32>,
) -> NtResult {
    let (_dc_reference, state) = super::dc::dc_of(call, dc)?;
    let fill = super::brush::fill_of(call, brush)?;
    let count = objects::with_region_mut(call, region, |region| region.count())?;
    let pattern = fill.pattern(
        state.text_color,
        state.bk_color,
        state.pattern_origin(),
        super::display::sys_color,
    );
    let Some(pattern) = pattern else {
        out.write(0)?;
        return Ok(STATUS_SUCCESS);
    };
    let mut at = 0;
    while at < count {
        let mut chunk = [Rect::EMPTY; CHUNK];
        let taken = objects::copy_rects(call, region, at, &mut chunk)?;
        if taken == 0 {
            break;
        }
        super::bitmap::with_surface(&state, |surface| {
            for rect in &chunk[..taken] {
                let rect = state.screen_rect(*rect);
                super::raster::pat_blt(surface, state.clip(), rect, PATCOPY, Some(&pattern));
            }
        });
        at += taken;
    }
    out.write(1)?;
    Ok(STATUS_SUCCESS)
}

/// NtGdiFlush(): see the module notes.
pub fn flush(_call: &mut NtCall) -> NtResult {
    Ok(STATUS_SUCCESS)
}

// --- The target's side: the objects --------------------------------------------------------------

#[cfg(target_arch = "x86")]
mod objects {
    use super::*;
    use crate::ob::ObjectId;

    /// The region object the calling process's `handle` names, referenced; STATUS_INVALID_HANDLE
    /// for a handle that names none.
    fn reference(handle: Handle) -> Result<crate::ob::ObRef, NtStatus> {
        super::super::gdi::reference(handle.raw(), OBJ_REGION).ok_or(STATUS_INVALID_HANDLE)
    }

    /// Publish a new region: an object holding `region` (whose block it takes), its handle the
    /// calling process's; STATUS_INSUFFICIENT_RESOURCES when the regions' pool or the GDI table is
    /// full (the block given back).
    pub fn publish(_call: &mut NtCall, region: Region) -> Result<u32, NtStatus> {
        let Some(id) = crate::ob::locked(|directory| directory.create_region(region)) else {
            release_storage(&region);
            return Err(STATUS_INSUFFICIENT_RESOURCES);
        };
        super::super::gdi::insert(id).ok_or(STATUS_INSUFFICIENT_RESOURCES)
    }

    /// Delete the calling process's region `handle` (one a service just made).
    pub fn delete(_call: &mut NtCall, handle: u32) {
        super::super::gdi::delete(handle, OBJ_REGION);
    }

    /// Run `f` on the body of the region `id` names, in one hold of the directory.
    fn locked_region<R>(id: ObjectId, f: impl FnOnce(&mut Region) -> R) -> Result<R, NtStatus> {
        crate::ob::locked(|directory| directory.region(id).map(f)).ok_or(STATUS_INVALID_HANDLE)
    }

    /// Run `f` on the body of the region `handle` names, in one hold of the directory.
    pub fn with_region_mut<R>(
        _call: &mut NtCall,
        handle: Handle,
        f: impl FnOnce(&mut Region) -> R,
    ) -> Result<R, NtStatus> {
        let reference = reference(handle)?;
        locked_region(reference.id(), f)
    }

    /// Replace the body of the region `handle` names by what `f` makes of it, which answers the
    /// body replaced (its block given back here).
    pub fn update(
        call: &mut NtCall,
        handle: Handle,
        f: impl FnOnce(&mut Region) -> Result<Region, NtStatus>,
    ) -> Result<(), NtStatus> {
        let old = with_region_mut(call, handle, f)??;
        release_storage(&old);
        Ok(())
    }

    /// Up to `out.len()` of the rectangles of the region `handle` names, from the `at`th, into
    /// `out`: how many.
    pub fn copy_rects(
        call: &mut NtCall,
        handle: Handle,
        at: usize,
        out: &mut [Rect],
    ) -> Result<usize, NtStatus> {
        with_region_mut(call, handle, |region| {
            // SAFETY: the body read in this hold of the directory.
            let rects = unsafe { region.rects() };
            let rest = rects.get(at..).unwrap_or(&[]);
            let taken = rest.len().min(out.len());
            out[..taken].copy_from_slice(&rest[..taken]);
            taken
        })
    }

    /// Whether the regions `first` and `second` name hold the same rectangles.
    pub fn equal(_call: &mut NtCall, first: Handle, second: Handle) -> Result<bool, NtStatus> {
        let (a, b) = (reference(first)?, reference(second)?);
        crate::ob::locked(|directory| {
            let a = *directory.region(a.id())?;
            let b = *directory.region(b.id())?;
            // SAFETY: both bodies read in this hold of the directory.
            Some(unsafe { a.rects() == b.rects() })
        })
        .ok_or(STATUS_INVALID_HANDLE)
    }

    /// `dest` made what `keep` makes of `first` and `second` (none: RGN_COPY, `first`'s copy):
    /// its complexity. STATUS_INVALID_HANDLE for a handle that names no region,
    /// STATUS_NO_MEMORY when the answer finds no room (`dest` as it was).
    pub fn combine_regions(
        _call: &mut NtCall,
        dest: Handle,
        first: Handle,
        second: Option<Handle>,
        keep: fn(bool, bool) -> bool,
    ) -> Result<i32, NtStatus> {
        let first = reference(first)?;
        let second = second.map(reference).transpose()?;
        let dest = reference(dest)?;
        let old = crate::ob::locked(|directory| {
            let a = *directory.region(first.id()).ok_or(STATUS_INVALID_HANDLE)?;
            let b = match &second {
                Some(second) => Some(*directory.region(second.id()).ok_or(STATUS_INVALID_HANDLE)?),
                None => None,
            };
            directory.region(dest.id()).ok_or(STATUS_INVALID_HANDLE)?;
            // SAFETY: the bodies read in this hold of the directory, nothing replaced before the
            // answer is made.
            let new = unsafe {
                match b {
                    None => a.duplicate(),
                    Some(b) => {
                        let mut buf = rect_buf();
                        super::combine(a.rects(), b.rects(), keep, &mut buf)
                            .then(|| Region::of_buf(buf, None))
                    }
                }
            }
            .ok_or(STATUS_NO_MEMORY)?;
            let complexity = new.complexity();
            let body = directory.region(dest.id()).expect("checked above");
            Ok::<_, NtStatus>((core::mem::replace(body, new), complexity))
        });
        let (old, complexity) = old?;
        release_storage(&old);
        Ok(complexity)
    }

    /// A copy of the region `handle` names, the caller's own; STATUS_NO_MEMORY when the pool has
    /// no room for it.
    pub fn copy_of(_call: &mut NtCall, handle: Handle) -> Result<OwnedRegion, NtStatus> {
        let reference = reference(handle)?;
        locked_region(reference.id(), |region| {
            // SAFETY: the body read in this hold of the directory; the copy's block its own.
            unsafe { region.duplicate() }.map(|copy| unsafe { OwnedRegion::adopt(copy) })
        })?
        .ok_or(STATUS_NO_MEMORY)
    }

    /// Make the region `handle` names a copy of `source`.
    pub fn assign(call: &mut NtCall, handle: Handle, source: &OwnedRegion) -> Result<(), NtStatus> {
        let new = source.duplicate().ok_or(STATUS_NO_MEMORY)?.into_inner();
        let result = update(call, handle, |old| Ok(core::mem::replace(old, new)));
        if result.is_err() {
            release_storage(&new);
        }
        result
    }

    /// Make the region `handle` names the union of `parts` (ScrollWindowEx's hrgnUpdate).
    pub fn set_parts(call: &mut NtCall, handle: Handle, parts: &[Rect]) -> Result<(), NtStatus> {
        let mut region = rect_buf();
        for part in parts.iter().filter(|part| !part.is_empty()) {
            let mut next = rect_buf();
            if !super::combine(region.as_slice(), &[*part], |a, b| a || b, &mut next) {
                return Err(STATUS_NO_MEMORY);
            }
            region = next;
        }
        let new = Region::of_buf(region, None);
        let result = update(call, handle, |old| Ok(core::mem::replace(old, new)));
        if result.is_err() {
            release_storage(&new);
        }
        result
    }
}

// The host builds have no processes: no region object is made or found (the host tests drive the
// algebra themselves).
#[cfg(not(target_arch = "x86"))]
mod objects {
    use super::*;

    pub fn publish(_: &mut NtCall, region: Region) -> Result<u32, NtStatus> {
        release_storage(&region);
        Err(STATUS_NOT_IMPLEMENTED)
    }

    pub fn delete(_: &mut NtCall, _: u32) {}

    pub fn with_region_mut<R>(
        _: &mut NtCall,
        _: Handle,
        _: impl FnOnce(&mut Region) -> R,
    ) -> Result<R, NtStatus> {
        Err(STATUS_INVALID_HANDLE)
    }

    pub fn update(
        _: &mut NtCall,
        _: Handle,
        _: impl FnOnce(&mut Region) -> Result<Region, NtStatus>,
    ) -> Result<(), NtStatus> {
        Err(STATUS_INVALID_HANDLE)
    }

    pub fn copy_rects(
        _: &mut NtCall,
        _: Handle,
        _: usize,
        _: &mut [Rect],
    ) -> Result<usize, NtStatus> {
        Err(STATUS_INVALID_HANDLE)
    }

    pub fn equal(_: &mut NtCall, _: Handle, _: Handle) -> Result<bool, NtStatus> {
        Err(STATUS_INVALID_HANDLE)
    }

    pub fn combine_regions(
        _: &mut NtCall,
        _: Handle,
        _: Handle,
        _: Option<Handle>,
        _: fn(bool, bool) -> bool,
    ) -> Result<i32, NtStatus> {
        Err(STATUS_INVALID_HANDLE)
    }

    pub fn set_parts(_: &mut NtCall, _: Handle, _: &[Rect]) -> Result<(), NtStatus> {
        Err(STATUS_INVALID_HANDLE)
    }

    pub fn copy_of(_: &mut NtCall, _: Handle) -> Result<OwnedRegion, NtStatus> {
        Err(STATUS_INVALID_HANDLE)
    }

    pub fn assign(_: &mut NtCall, _: Handle, _: &OwnedRegion) -> Result<(), NtStatus> {
        Err(STATUS_INVALID_HANDLE)
    }
}

pub use objects::{assign, copy_of, set_parts};

// --- The batch -----------------------------------------------------------------------------------

/// Run the calling thread's GDI batch (see the module notes): each region deletion it queued, in
/// order (a handle that names no region any more is passed over, as Windows 2000's batch passes a
/// failed command), then the batch emptied. The dispatcher's step before every win32k service; a
/// TEB that cannot be read holds no batch.
#[cfg(target_arch = "x86")]
pub fn run_batch() {
    use crate::user::teb::teb_field;
    let teb = current_teb();
    let count_field = teb_field!(gdi_batch_count).of(teb);
    let count = match count_field.read() {
        Ok(0) | Err(_) => return,
        Ok(count) => count.min(GDI_BATCH_LIMIT),
    };
    let batch = teb + core::mem::offset_of!(rtl::peb::Teb<u32>, gdi_teb_batch) as u32;
    // GDI_TEB_BATCH: the bytes in use, the DC, then the buffer.
    let buffer = batch + 8;
    for index in 0..count {
        let at = buffer + index * core::mem::size_of::<BatchCommand>() as u32;
        let Ok(command) = UserPtr::<BatchCommand>::at(at).read() else {
            break;
        };
        if command.command == BATCH_DELETE_REGION {
            super::gdi::delete(command.handle, OBJ_REGION);
        }
    }
    let _ = count_field.write(0);
    let _ = UserPtr::<u32>::at(batch).write(0);
}

/// The running thread's TEB.
#[cfg(target_arch = "x86")]
fn current_teb() -> u32 {
    let thread = crate::sched::current_thread();
    crate::level::raised::<crate::level::Dispatch, _>(|dispatch| {
        crate::sched::DISPATCHER
            .get(dispatch)
            .thread(thread)
            .teb_va()
    })
}

#[cfg(test)]
mod tests {
    use std::vec::Vec;

    use super::*;

    fn r(left: i32, top: i32, right: i32, bottom: i32) -> Rect {
        Rect::new(left, top, right, bottom)
    }

    fn op(a: &[Rect], b: &[Rect], mode: u32) -> Vec<Rect> {
        let mut out = Vec::new();
        assert!(combine(a, b, keeps(mode).unwrap(), &mut out));
        out
    }

    /// A region's PtInRegion grid, rows of # and . as the capture prints them.
    fn grid(rects: &[Rect], width: i32, height: i32) -> Vec<String> {
        (0..height)
            .map(|y| {
                (0..width)
                    .map(|x| if contains(rects, x, y) { '#' } else { '.' })
                    .collect()
            })
            .collect()
    }

    /// The regions capture's combine section: two overlapping squares in each mode, as banded
    /// rectangles.
    #[test]
    fn the_combine_modes_answer_the_captures_bands() {
        let a = [r(0, 0, 6, 6)];
        let b = [r(3, 3, 9, 9)];
        assert_eq!(op(&a, &b, RGN_AND), [r(3, 3, 6, 6)]);
        assert_eq!(
            op(&a, &b, RGN_OR),
            [r(0, 0, 6, 3), r(0, 3, 9, 6), r(3, 6, 9, 9)]
        );
        assert_eq!(
            op(&a, &b, RGN_XOR),
            [r(0, 0, 6, 3), r(0, 3, 3, 6), r(6, 3, 9, 6), r(3, 6, 9, 9)]
        );
        assert_eq!(op(&a, &b, RGN_DIFF), [r(0, 0, 6, 3), r(0, 3, 3, 6)]);
        assert_eq!(op(&a, &[r(7, 0, 9, 2)], RGN_AND), []);
        assert_eq!(
            op(&[r(0, 0, 3, 3)], &[r(3, 0, 6, 3)], RGN_OR),
            [r(0, 0, 6, 3)]
        );
        assert_eq!(op(&a, &a, RGN_DIFF), []);
        assert_eq!(op(&[], &[], RGN_OR), []);
        assert_eq!(op(&a, &[], RGN_OR), a);
        assert_eq!(op(&[], &a, RGN_DIFF), []);
    }

    /// Bands that touch with the same stretches merge into one; ones that differ, or have a gap
    /// between them, stay apart.
    #[test]
    fn touching_bands_with_the_same_stretches_merge() {
        assert_eq!(
            op(&[r(0, 0, 4, 2)], &[r(0, 2, 4, 5)], RGN_OR),
            [r(0, 0, 4, 5)]
        );
        assert_eq!(
            op(&[r(0, 0, 4, 2)], &[r(0, 3, 4, 5)], RGN_OR),
            [r(0, 0, 4, 2), r(0, 3, 4, 5)]
        );
        // An L: the union of two rectangles is two bands, the cut's removal leaves one again.
        let l = op(&[r(0, 0, 2, 6)], &[r(0, 4, 6, 6)], RGN_OR);
        assert_eq!(l, [r(0, 0, 2, 4), r(0, 4, 6, 6)]);
        assert_eq!(op(&l, &[r(2, 4, 6, 6)], RGN_DIFF), [r(0, 0, 2, 6)]);
        // A frame's hole and its fill.
        let frame = op(&[r(0, 0, 9, 9)], &[r(3, 3, 6, 6)], RGN_DIFF);
        assert_eq!(
            frame,
            [r(0, 0, 9, 3), r(0, 3, 3, 6), r(6, 3, 9, 6), r(0, 6, 9, 9)]
        );
        assert_eq!(op(&frame, &[r(3, 3, 6, 6)], RGN_OR), [r(0, 0, 9, 9)]);
        assert_eq!(op(&frame, &[r(3, 3, 6, 6)], RGN_XOR), [r(0, 0, 9, 9)]);
    }

    /// Every mode agrees with its truth table on every point, for a few awkward pairs.
    #[test]
    fn every_mode_agrees_with_its_truth_table_pointwise() {
        let shapes: [&[Rect]; 4] = [
            &[r(1, 1, 7, 3), r(2, 3, 4, 8), r(5, 3, 8, 8)],
            &[r(0, 2, 9, 4), r(3, 6, 5, 9)],
            &[r(4, 0, 5, 10)],
            &[],
        ];
        // Make each shape banded first, by its union with nothing.
        let banded: Vec<Vec<Rect>> = shapes.iter().map(|s| op(s, &[], RGN_OR)).collect();
        for a in &banded {
            for b in &banded {
                for mode in [RGN_AND, RGN_OR, RGN_XOR, RGN_DIFF] {
                    let out = op(a, b, mode);
                    let keep = keeps(mode).unwrap();
                    for y in -1..11 {
                        for x in -1..11 {
                            assert_eq!(
                                contains(&out, x, y),
                                keep(contains(a, x, y), contains(b, x, y)),
                                "mode {mode} at ({x}, {y})"
                            );
                        }
                    }
                    // Banded: sorted, in bands that never overlap, stretches apart in a band.
                    for pair in out.windows(2) {
                        let (p, q) = (pair[0], pair[1]);
                        if p.top == q.top {
                            assert_eq!(p.bottom, q.bottom);
                            assert!(p.right < q.left, "{p:?} {q:?}");
                        } else {
                            assert!(p.bottom <= q.top, "{p:?} {q:?}");
                        }
                    }
                }
            }
        }
    }

    fn scan(points: &[(i32, i32)], winding: bool) -> Vec<Rect> {
        let points: Vec<Point> = points.iter().map(|&(x, y)| Point { x, y }).collect();
        let mut out = Vec::new();
        let mut crossings = Vec::new();
        assert!(polygon(
            &points,
            &[points.len() as u32],
            winding,
            &mut out,
            &mut crossings
        ));
        out
    }

    /// The capture's triangle: 8 rows, the same under both modes.
    #[test]
    fn the_triangle_scans_as_captured() {
        let tri = [(0, 0), (8, 0), (0, 8)];
        let alternate = scan(&tri, false);
        assert_eq!(alternate.len(), 8);
        assert_eq!(alternate, scan(&tri, true));
        assert_eq!(
            grid(&alternate, 10, 3),
            ["########..", "#######...", "######...."]
        );
        assert_eq!(alternate[7], r(0, 7, 1, 8));
        let points = tri.map(|(x, y)| Point { x, y });
        assert_eq!(polygon_bounds(&points, false), r(0, 0, 8, 8));
    }

    /// The capture's pentagram: 17 rectangles under ALTERNATE (its middle hollow), 12 under
    /// WINDING (filled); its rows as the capture's grids.
    #[test]
    fn the_pentagram_scans_as_captured() {
        let star = [(6, 0), (10, 11), (0, 4), (12, 4), (2, 11)];
        let alternate = scan(&star, false);
        assert_eq!(alternate.len(), 17);
        assert_eq!(
            grid(&alternate, 13, 12),
            [
                ".............",
                "......#......",
                "......#......",
                ".....###.....",
                "#####...####.",
                "..###...###..",
                "...#.....#...",
                "....#...#....",
                "....##.##....",
                "...##...##...",
                "...#.....#...",
                ".............",
            ]
        );
        let winding = scan(&star, true);
        assert_eq!(winding.len(), 12);
        assert_eq!(
            grid(&winding, 13, 12),
            [
                ".............",
                "......#......",
                "......#......",
                ".....###.....",
                "############.",
                "..#########..",
                "...#######...",
                "....#####....",
                "....#####....",
                "...##...##...",
                "...#.....#...",
                ".............",
            ]
        );
        let points = star.map(|(x, y)| Point { x, y });
        assert_eq!(polygon_bounds(&points, false), r(0, 0, 12, 11));
    }

    /// Two points make an empty region; a polygon whose edges all lie on one row too.
    #[test]
    fn a_flat_polygon_is_empty() {
        assert_eq!(scan(&[(0, 0), (8, 0)], false), []);
        assert_eq!(scan(&[(0, 3), (8, 3), (4, 3)], true), []);
        let points = [Point { x: 0, y: 0 }, Point { x: 8, y: 0 }];
        assert_eq!(polygon_bounds(&points, true), Rect::EMPTY);
    }

    /// Rows round their crossings up: a crossing on a whole pixel holds it on the left, leaves it
    /// on the right.
    #[test]
    fn crossings_round_up() {
        assert_eq!(ceil_div(7, 2), 4);
        assert_eq!(ceil_div(-7, 2), -3);
        assert_eq!(ceil_div(6, 3), 2);
        assert_eq!(ceil_div(-6, 3), -2);
        // A square's rows: its left edge in, its right one out, its bottom row out.
        assert_eq!(
            scan(&[(1, 1), (4, 1), (4, 3), (1, 3)], false),
            [r(1, 1, 4, 2), r(1, 2, 4, 3)]
        );
    }

    /// RGNDATA's layout, as the data capture prints it: a 32-byte header, 16 bytes a rectangle.
    #[test]
    fn region_data_is_laid_out_as_captured() {
        assert_eq!(data_size(4), 96);
        assert_eq!(data_size(1), 48);
        assert_eq!(data_size(0), 32);
        let header = data_header(4, r(0, 0, 9, 9));
        assert_eq!(
            rtl::pod::Pod::as_bytes(&header),
            [
                32, 0, 0, 0, 1, 0, 0, 0, 4, 0, 0, 0, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9, 0, 0,
                0, 9, 0, 0, 0
            ]
        );
    }

    /// A rectangle's edges are put in order; an empty one is the empty region.
    #[test]
    fn rectangles_are_ordered() {
        assert_eq!(ordered(8, 5, 2, 1), Some(r(2, 1, 8, 5)));
        assert_eq!(ordered(6, 2, 1, 0), Some(r(1, 0, 6, 2)));
        assert_eq!(ordered(3, 3, 3, 9), None);
        assert_eq!(ordered(5, 5, 5, 5), None);
        assert_eq!(Region::rect(None).complexity(), NULLREGION);
        assert_eq!(Region::rect(None).bounds, Rect::EMPTY);
        assert_eq!(Region::rect(ordered(2, 1, 8, 5)).complexity(), SIMPLEREGION);
    }

    /// A region moves with its box; one moved past the coordinates' reach stays as it was.
    #[test]
    fn offsets_move_the_region_and_its_box() {
        let mut region = Region::rect(ordered(1, 0, 6, 2));
        // SAFETY: an inline region.
        assert!(unsafe { offset(&mut region, 3, -2) });
        assert_eq!(region.bounds, r(4, -2, 9, 0));
        assert_eq!(unsafe { region.rects() }, [r(4, -2, 9, 0)]);
        assert!(!unsafe { offset(&mut region, MOST_COORDINATE, 0) });
        assert_eq!(region.bounds, r(4, -2, 9, 0));
        let mut empty = Region::none();
        assert!(unsafe { offset(&mut empty, 3, 3) });
        assert_eq!(empty.bounds, Rect::EMPTY);
    }

    /// A list spills from the stack into a block as it grows, and a region of more than
    /// [`INLINE`] rectangles takes the block, its copy one of its own.
    #[test]
    fn large_regions_spill_into_a_block() {
        let mut buf = rect_buf();
        for i in 0..600 {
            assert!(buf.push(r(0, 2 * i, 1, 2 * i + 1)));
        }
        assert_eq!(buf.len(), 600);
        assert_eq!(buf.as_slice()[599], r(0, 1198, 1, 1199));
        let region = Region::of_buf(buf, None);
        assert_eq!(region.count(), 600);
        assert_eq!(region.bounds, r(0, 0, 1, 1199));
        assert!(matches!(region.storage, Storage::Block(_)));
        // SAFETY: the region's block is its own until released below.
        let copy = unsafe { region.duplicate() }.unwrap();
        assert_ne!(copy.storage, region.storage);
        assert_eq!(unsafe { copy.rects() }, unsafe { region.rects() });
        release_storage(&region);
        release_storage(&copy);

        let mut small = rect_buf();
        assert!(small.push(r(0, 0, 1, 1)));
        let region = Region::of_buf(small, None);
        assert!(matches!(region.storage, Storage::Inline(_)));

        let mut limited: SmallBuf<u32, 2> = SmallBuf::new(0, 3);
        assert!(limited.push(1) && limited.push(2) && limited.push(3));
        assert!(!limited.push(4), "past its limit");
        assert_eq!(limited.as_slice(), [1, 2, 3]);
    }
}
