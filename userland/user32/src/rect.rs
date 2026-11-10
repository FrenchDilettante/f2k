//! The rectangles: SetRect and OffsetRect, user32's own arithmetic on a caller's RECT (no
//! service).

use rtl::gdi::Rect;

use crate::Out;

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
}
