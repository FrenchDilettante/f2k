//! The rectangles: SetRect, SetRectEmpty, CopyRect, OffsetRect, InflateRect, IsRectEmpty,
//! EqualRect, PtInRect, IntersectRect, UnionRect and SubtractRect, user32's own arithmetic on a
//! caller's RECTs (no service).
//!
//! A rectangle holds the points from its left and top edges up to, not including, its right and
//! bottom ones: one whose right edge is not past its left, or whose bottom is not below its top
//! (an inverted one too), is empty. The coordinates wrap at 32 bits, as the rects capture's
//! InflateRect near the limits shows. Every helper refuses a NULL RECT with FALSE (IsRectEmpty
//! answers TRUE), writing nothing and leaving the last error alone, as the capture's `nulls` shows.
//!
//! A destination may be one of the sources (IntersectRect(&a, &a, &b)): each helper reads its
//! sources into values before it writes the destination.

use rtl::edge::In;
use rtl::gdi::Rect;

use crate::Out;

/// The empty rectangle SetRectEmpty sets, and a failed IntersectRect, UnionRect or SubtractRect
/// leaves.
const EMPTY: Rect = Rect {
    left: 0,
    top: 0,
    right: 0,
    bottom: 0,
};

/// Whether `rect` holds no point: its right edge not past its left, or its bottom not below its
/// top.
fn is_empty(rect: Rect) -> bool {
    rect.left >= rect.right || rect.top >= rect.bottom
}

/// The rectangle both hold; none when they share no point (an empty or inverted one shares none).
fn intersection(a: Rect, b: Rect) -> Option<Rect> {
    let both = Rect {
        left: a.left.max(b.left),
        top: a.top.max(b.top),
        right: a.right.min(b.right),
        bottom: a.bottom.min(b.bottom),
    };
    (!is_empty(both)).then_some(both)
}

/// The smallest rectangle holding both, an empty one left out; none when both are empty.
fn union(a: Rect, b: Rect) -> Option<Rect> {
    match (is_empty(a), is_empty(b)) {
        (true, true) => None,
        (true, false) => Some(b),
        (false, true) => Some(a),
        (false, false) => Some(Rect {
            left: a.left.min(b.left),
            top: a.top.min(b.top),
            right: a.right.max(b.right),
            bottom: a.bottom.max(b.bottom),
        }),
    }
}

/// What is left of `from` once `less` is taken out, when that is a rectangle: the part of `less`
/// over `from` must cover a whole side of it (its full height at the left or the right, else its
/// full width at the top or the bottom), or `from` is answered as it is. With it, whether the
/// answer is empty: one the subtraction emptied is the empty rectangle, an empty `from` is answered
/// as it is.
fn subtraction(from: Rect, less: Rect) -> (Rect, bool) {
    let mut rest = from;
    if let Some(cut) = intersection(from, less) {
        if cut.top == from.top && cut.bottom == from.bottom {
            if cut.left == from.left {
                rest.left = cut.right;
            } else if cut.right == from.right {
                rest.right = cut.left;
            }
        } else if cut.left == from.left && cut.right == from.right {
            if cut.top == from.top {
                rest.top = cut.bottom;
            } else if cut.bottom == from.bottom {
                rest.bottom = cut.top;
            }
        }
        if is_empty(rest) {
            return (EMPTY, true);
        }
    }
    (rest, is_empty(rest))
}

/// The caller's RECT at `at`, read; none for NULL.
///
/// # Safety
///
/// `at` is null or the address of a RECT the call may read, as for the platform's.
unsafe fn read(at: *const Rect) -> Option<Rect> {
    // SAFETY: the function's contract.
    unsafe { In::optional(at) }.map(|rect| rect.read())
}

/// SetRect: the caller's RECT set to the four coordinates as given (an inverted rectangle as
/// well); TRUE, FALSE for a NULL RECT.
///
/// # Safety
///
/// The caller's RECT, as for the platform's.
#[unsafe(export_name = "f2k_export_SetRect")]
pub unsafe extern "system" fn set_rect(
    rect: *mut Rect,
    left: i32,
    top: i32,
    right: i32,
    bottom: i32,
) -> u32 {
    // SAFETY: the caller's RECT, or null.
    let Some(mut rect) = (unsafe { Out::optional(rect) }) else {
        return 0;
    };
    rect.set(Rect {
        left,
        top,
        right,
        bottom,
    });
    1
}

/// SetRectEmpty: the caller's RECT set to (0,0,0,0); TRUE, FALSE for a NULL RECT.
///
/// # Safety
///
/// The caller's RECT, as for the platform's.
#[unsafe(export_name = "f2k_export_SetRectEmpty")]
pub unsafe extern "system" fn set_rect_empty(rect: *mut Rect) -> u32 {
    // SAFETY: the caller's RECT, or null.
    let Some(mut rect) = (unsafe { Out::optional(rect) }) else {
        return 0;
    };
    rect.set(EMPTY);
    1
}

/// CopyRect: the source RECT copied into the destination (onto itself as well); TRUE, FALSE when
/// either is NULL.
///
/// # Safety
///
/// The caller's RECTs, as for the platform's.
#[unsafe(export_name = "f2k_export_CopyRect")]
pub unsafe extern "system" fn copy_rect(destination: *mut Rect, source: *const Rect) -> u32 {
    // SAFETY: the caller's RECT, or null.
    let Some(value) = (unsafe { read(source) }) else {
        return 0;
    };
    // SAFETY: the caller's RECT, or null; the source is read already.
    let Some(mut destination) = (unsafe { Out::optional(destination) }) else {
        return 0;
    };
    destination.set(value);
    1
}

/// IsRectEmpty: whether the caller's RECT holds no point (an inverted one holds none); TRUE for a
/// NULL RECT.
///
/// # Safety
///
/// The caller's RECT, as for the platform's.
#[unsafe(export_name = "f2k_export_IsRectEmpty")]
pub unsafe extern "system" fn is_rect_empty(rect: *const Rect) -> u32 {
    // SAFETY: the caller's RECT, or null.
    unsafe { read(rect) }.is_none_or(is_empty) as u32
}

/// EqualRect: whether the two RECTs have the same four coordinates (two different empty ones are
/// not equal); FALSE when either is NULL.
///
/// # Safety
///
/// The caller's RECTs, as for the platform's.
#[unsafe(export_name = "f2k_export_EqualRect")]
pub unsafe extern "system" fn equal_rect(a: *const Rect, b: *const Rect) -> u32 {
    // SAFETY: the caller's RECTs, or null.
    let (a, b) = unsafe { (read(a), read(b)) };
    matches!((a, b), (Some(a), Some(b)) if a == b) as u32
}

/// PtInRect: whether the point (passed by value, its x and y) lies in the caller's RECT: on its
/// left or top edge, not on its right or bottom one; never in an empty or inverted one. FALSE for
/// a NULL RECT.
///
/// # Safety
///
/// The caller's RECT, as for the platform's.
#[unsafe(export_name = "f2k_export_PtInRect")]
pub unsafe extern "system" fn pt_in_rect(rect: *const Rect, x: i32, y: i32) -> u32 {
    // SAFETY: the caller's RECT, or null.
    let rect = unsafe { read(rect) };
    rect.is_some_and(|r| (r.left..r.right).contains(&x) && (r.top..r.bottom).contains(&y)) as u32
}

/// IntersectRect: the rectangle both sources hold, into the destination; FALSE, the destination
/// set empty, when they share no point. FALSE, nothing written, when any of the three is NULL.
///
/// # Safety
///
/// The caller's RECTs, as for the platform's.
#[unsafe(export_name = "f2k_export_IntersectRect")]
pub unsafe extern "system" fn intersect_rect(
    destination: *mut Rect,
    a: *const Rect,
    b: *const Rect,
) -> u32 {
    // SAFETY: the caller's RECTs, or null.
    let (Some(a), Some(b)) = (unsafe { (read(a), read(b)) }) else {
        return 0;
    };
    // SAFETY: the caller's RECT, or null; the sources are read already.
    let Some(mut destination) = (unsafe { Out::optional(destination) }) else {
        return 0;
    };
    let both = intersection(a, b);
    destination.set(both.unwrap_or(EMPTY));
    both.is_some() as u32
}

/// UnionRect: the smallest rectangle holding both sources, into the destination, an empty or
/// inverted source left out; FALSE, the destination set empty, when both are. FALSE, nothing
/// written, when any of the three is NULL.
///
/// # Safety
///
/// The caller's RECTs, as for the platform's.
#[unsafe(export_name = "f2k_export_UnionRect")]
pub unsafe extern "system" fn union_rect(
    destination: *mut Rect,
    a: *const Rect,
    b: *const Rect,
) -> u32 {
    // SAFETY: the caller's RECTs, or null.
    let (Some(a), Some(b)) = (unsafe { (read(a), read(b)) }) else {
        return 0;
    };
    // SAFETY: the caller's RECT, or null; the sources are read already.
    let Some(mut destination) = (unsafe { Out::optional(destination) }) else {
        return 0;
    };
    let both = union(a, b);
    destination.set(both.unwrap_or(EMPTY));
    both.is_some() as u32
}

/// SubtractRect: the first source less the second, into the destination, when what is left is a
/// rectangle ([`subtraction`]), the first source as it is otherwise; TRUE when that is not empty,
/// FALSE when it is. FALSE, nothing written, when any of the three is NULL.
///
/// # Safety
///
/// The caller's RECTs, as for the platform's.
#[unsafe(export_name = "f2k_export_SubtractRect")]
pub unsafe extern "system" fn subtract_rect(
    destination: *mut Rect,
    from: *const Rect,
    less: *const Rect,
) -> u32 {
    // SAFETY: the caller's RECTs, or null.
    let (Some(from), Some(less)) = (unsafe { (read(from), read(less)) }) else {
        return 0;
    };
    // SAFETY: the caller's RECT, or null; the sources are read already.
    let Some(mut destination) = (unsafe { Out::optional(destination) }) else {
        return 0;
    };
    let (rest, empty) = subtraction(from, less);
    destination.set(rest);
    !empty as u32
}

/// InflateRect: the caller's RECT grown by `dx` at its left and right and by `dy` at its top and
/// bottom (shrunk by negative ones, past its middle into an inverted rectangle; the coordinates
/// wrap at 32 bits); TRUE, FALSE for a NULL RECT.
///
/// # Safety
///
/// The caller's RECT, as for the platform's.
#[unsafe(export_name = "f2k_export_InflateRect")]
pub unsafe extern "system" fn inflate_rect(rect: *mut Rect, dx: i32, dy: i32) -> u32 {
    // SAFETY: the caller's RECT, or null.
    let Some(mut rect) = (unsafe { Out::optional(rect) }) else {
        return 0;
    };
    let r = rect.get();
    rect.set(Rect {
        left: r.left.wrapping_sub(dx),
        top: r.top.wrapping_sub(dy),
        right: r.right.wrapping_add(dx),
        bottom: r.bottom.wrapping_add(dy),
    });
    1
}

/// OffsetRect: the caller's RECT moved by `dx` and `dy` (an empty or inverted one as well, its
/// corners each moved); TRUE, FALSE for a NULL RECT. The last error is untouched.
///
/// # Safety
///
/// The caller's RECT, as for the platform's.
#[unsafe(export_name = "f2k_export_OffsetRect")]
pub unsafe extern "system" fn offset_rect(rect: *mut Rect, dx: i32, dy: i32) -> u32 {
    // SAFETY: the caller's RECT, or null.
    let Some(mut rect) = (unsafe { Out::optional(rect) }) else {
        return 0;
    };
    let r = rect.get();
    rect.set(Rect {
        left: r.left.wrapping_add(dx),
        top: r.top.wrapping_add(dy),
        right: r.right.wrapping_add(dx),
        bottom: r.bottom.wrapping_add(dy),
    });
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rect(left: i32, top: i32, right: i32, bottom: i32) -> Rect {
        Rect {
            left,
            top,
            right,
            bottom,
        }
    }

    /// The rect section's moves, an inverted rectangle's among them.
    ///
    /// Pins: user32.OffsetRect
    #[test]
    fn rectangles_move_by_the_offsets() {
        for (from, dx, dy, to) in [
            (rect(1, 2, 3, 4), 5, -7, rect(6, -5, 8, -3)),
            (rect(10, 20, 30, 40), -10, 10, rect(0, 30, 20, 50)),
            (rect(5, 5, 1, 1), 2, 2, rect(7, 7, 3, 3)),
            (
                rect(-100, -100, 100, 100),
                1000,
                -1000,
                rect(900, -1100, 1100, -900),
            ),
        ] {
            let mut r = from;
            // SAFETY: the test's own RECT.
            assert_eq!(unsafe { offset_rect(&mut r, dx, dy) }, 1);
            assert_eq!(r, to);
        }
        // SAFETY: a null RECT, which the call refuses.
        assert_eq!(unsafe { offset_rect(core::ptr::null_mut(), 1, 1) }, 0);
        let mut r = rect(0, 0, 0, 0);
        // SAFETY: the test's own RECT.
        assert_eq!(unsafe { set_rect(&mut r, 4, 3, 2, 1) }, 1);
        assert_eq!(r, rect(4, 3, 2, 1));
    }

    /// The destination the rects capture starts each call with.
    const UNSET: Rect = Rect {
        left: 111,
        top: 222,
        right: 333,
        bottom: 444,
    };

    /// A two-source helper's answer and destination, the destination starting as [`UNSET`].
    fn two(
        helper: unsafe extern "system" fn(*mut Rect, *const Rect, *const Rect) -> u32,
        a: Rect,
        b: Rect,
    ) -> (u32, Rect) {
        let mut d = UNSET;
        // SAFETY: the test's own RECTs.
        (unsafe { helper(&mut d, &a, &b) }, d)
    }

    /// The empty, inflate and pt sections.
    ///
    /// Pins: user32.SetRectEmpty, user32.IsRectEmpty, user32.EqualRect, user32.CopyRect,
    /// user32.InflateRect, user32.PtInRect
    #[test]
    fn empty_inflated_and_hit_rectangles() {
        let mut d = UNSET;
        // SAFETY: the test's own RECTs, here and below.
        unsafe {
            assert_eq!(set_rect_empty(&mut d), 1);
            assert_eq!(d, rect(0, 0, 0, 0));
            for (r, empty) in [
                (rect(0, 0, 10, 10), 0),
                (rect(5, 0, 5, 10), 1),
                (rect(10, 0, 0, 10), 1),
                (rect(0, 10, 10, 0), 1),
                (rect(-10, -10, -5, -5), 0),
            ] {
                assert_eq!(is_rect_empty(&r), empty, "{r:?}");
            }
            assert_eq!(equal_rect(&rect(1, 2, 3, 4), &rect(1, 2, 3, 4)), 1);
            assert_eq!(equal_rect(&rect(1, 2, 3, 4), &rect(1, 2, 3, 0)), 0);
            assert_eq!(equal_rect(&rect(0, 0, 0, 0), &rect(5, 5, 5, 9)), 0);
            let mut a = rect(5, 6, 7, 8);
            let alias: *mut Rect = &mut a;
            assert_eq!(copy_rect(alias, alias), 1);
            assert_eq!(a, rect(5, 6, 7, 8));
            for (from, dx, dy, to) in [
                (rect(0, 0, 10, 10), -6, -7, rect(6, 7, 4, 3)),
                (rect(10, 10, 0, 0), 2, 2, rect(8, 8, 2, 2)),
                (
                    rect(-2147483647, 0, 2147483646, 0),
                    2,
                    0,
                    rect(2147483647, 0, -2147483648, 0),
                ),
            ] {
                let mut r = from;
                assert_eq!(inflate_rect(&mut r, dx, dy), 1);
                assert_eq!(r, to);
            }
            let r = rect(10, 20, 30, 40);
            for (x, y, inside) in [(10, 20, 1), (30, 20, 0), (29, 39, 1), (20, 40, 0)] {
                assert_eq!(pt_in_rect(&r, x, y), inside, "({x},{y})");
            }
            assert_eq!(pt_in_rect(&rect(30, 40, 10, 20), 20, 30), 0);
        }
    }

    /// The intersect, union and subtract sections.
    ///
    /// Pins: user32.IntersectRect, user32.UnionRect, user32.SubtractRect
    #[test]
    fn rectangles_combine() {
        let a = rect(0, 0, 10, 10);
        assert_eq!(
            two(intersect_rect, a, rect(9, 9, 20, 20)),
            (1, rect(9, 9, 10, 10))
        );
        assert_eq!(
            two(intersect_rect, a, rect(10, 0, 20, 10)),
            (0, rect(0, 0, 0, 0))
        );
        assert_eq!(
            two(intersect_rect, a, rect(8, 8, 2, 2)),
            (0, rect(0, 0, 0, 0))
        );
        assert_eq!(
            two(union_rect, rect(50, 50, 60, 50), a),
            (1, rect(0, 0, 10, 10))
        );
        assert_eq!(
            two(union_rect, rect(30, 30, 20, 20), rect(10, 10, 0, 0)),
            (0, rect(0, 0, 0, 0))
        );
        assert_eq!(
            two(union_rect, rect(-10, -10, -5, -5), rect(5, 5, 10, 10)),
            (1, rect(-10, -10, 10, 10))
        );
        for (less, answer) in [
            (rect(-5, -5, 5, 15), (1, rect(5, 0, 10, 10))),
            (rect(7, -1, 20, 11), (1, rect(0, 0, 7, 10))),
            (rect(0, 6, 10, 10), (1, rect(0, 0, 10, 6))),
            (rect(0, 0, 5, 9), (1, a)),
            (rect(3, 0, 7, 10), (1, a)),
            (rect(-1, -1, 11, 11), (0, rect(0, 0, 0, 0))),
            (rect(5, 10, 0, 0), (1, a)),
        ] {
            assert_eq!(two(subtract_rect, a, less), answer, "{less:?}");
        }
        assert_eq!(
            two(subtract_rect, rect(5, 5, 5, 5), a),
            (0, rect(5, 5, 5, 5))
        );
        assert_eq!(
            two(subtract_rect, rect(10, 10, 0, 0), rect(0, 0, 5, 10)),
            (0, rect(10, 10, 0, 0))
        );
        let mut a = rect(0, 0, 10, 10);
        let b = rect(5, 5, 15, 15);
        let alias: *mut Rect = &mut a;
        // SAFETY: the test's own RECTs, the destination one of the sources.
        assert_eq!(unsafe { intersect_rect(alias, alias, &b) }, 1);
        assert_eq!(a, rect(5, 5, 10, 10));
    }

    /// The nulls section: each helper refuses a NULL RECT without writing.
    ///
    /// Pins: user32.SetRectEmpty, user32.IsRectEmpty, user32.EqualRect, user32.CopyRect,
    /// user32.InflateRect, user32.PtInRect, user32.IntersectRect, user32.UnionRect,
    /// user32.SubtractRect
    #[test]
    fn null_rectangles_are_refused() {
        let null = core::ptr::null_mut::<Rect>();
        let a = rect(0, 0, 10, 10);
        let mut d = UNSET;
        // SAFETY: the test's own RECTs, or null.
        unsafe {
            assert_eq!(set_rect_empty(null), 0);
            assert_eq!(is_rect_empty(null), 1);
            assert_eq!(equal_rect(null, &a), 0);
            assert_eq!(copy_rect(null, &a), 0);
            assert_eq!(copy_rect(&mut d, null), 0);
            assert_eq!(inflate_rect(null, 1, 1), 0);
            assert_eq!(pt_in_rect(null, 1, 1), 0);
            for helper in [intersect_rect, union_rect, subtract_rect] {
                assert_eq!(helper(null, &a, &a), 0);
                assert_eq!(helper(&mut d, null, &a), 0);
                assert_eq!(helper(&mut d, &a, null), 0);
            }
        }
        assert_eq!(d, UNSET);
    }
}
