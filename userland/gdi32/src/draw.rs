//! Pens, lines and shapes: CreatePen and ExtCreatePen, MoveToEx, LineTo and GetCurrentPositionEx,
//! Polyline and Polygon, Rectangle, Ellipse and RoundRect, each over its win32k service
//! ([`imports`]). What the kernel draws, and how, is in its pen, shape and stroke modules' notes
//! (kernel/src/win32k/pen.rs, shape.rs, stroke.rs); SelectObject, GetObject and DeleteObject take
//! pens as they take the other objects ([`crate::dc`], [`crate::font`]).

use rtl::dib::LogBrush;
use rtl::gdi::{DCPT_CURRENT_POSITION, I_POLYPOLYGON, I_POLYPOLYLINE};

use crate::imports::{self, Caller, ShapeKind};
use crate::{answered, failed, ERROR_INVALID_PARAMETER};

/// CreatePen: a pen of the style, width and color (any style and width: see the kernel's notes);
/// NULL with the last error when the kernel has no room for one.
#[unsafe(export_name = "f2k_export_CreatePen")]
pub extern "system" fn create_pen(style: i32, width: i32, color: u32) -> usize {
    answered(imports::create_pen(style, width, color)).map_or(0, |pen| pen as usize)
}

/// ExtCreatePen: a cosmetic or geometric pen of the style and width, the LOGBRUSH's color, and
/// `count` user style entries; NULL with ERROR_INVALID_PARAMETER for no LOGBRUSH or a pen the
/// kernel refuses.
///
/// # Safety
///
/// `brush` the caller's LOGBRUSH (or null); `entries` its `count` dwords (the kernel reads them
/// through its fault-tolerant copies).
#[unsafe(export_name = "f2k_export_ExtCreatePen")]
pub unsafe extern "system" fn ext_create_pen(
    style: u32,
    width: u32,
    brush: *const LogBrush,
    count: u32,
    entries: *const u32,
) -> usize {
    if brush.is_null() {
        return failed(ERROR_INVALID_PARAMETER).unwrap_or(0);
    }
    // SAFETY: the caller's LOGBRUSH.
    let brush = unsafe { brush.read_unaligned() };
    answered(imports::ext_create_pen(
        style,
        width,
        brush,
        count,
        Caller(entries as usize),
    ))
    .map_or(0, |pen| pen as usize)
}

/// MoveToEx: the DC's current position moved to (`x`, `y`), the one it had into `previous` unless
/// it is null; FALSE with the last error for a DC that is none.
#[unsafe(export_name = "f2k_export_MoveToEx")]
pub extern "system" fn move_to_ex(dc: usize, x: i32, y: i32, previous: usize) -> u32 {
    answered(imports::move_to(dc, x, y, Caller(previous))).map_or(0, |()| 1)
}

/// GetCurrentPositionEx: the DC's current position into `point`.
#[unsafe(export_name = "f2k_export_GetCurrentPositionEx")]
pub extern "system" fn get_current_position_ex(dc: usize, point: usize) -> u32 {
    answered(imports::dc_point(dc, DCPT_CURRENT_POSITION, Caller(point))).map_or(0, |()| 1)
}

/// LineTo: a line from the DC's current position to (`x`, `y`), its end pixel left out; the point
/// becomes the current position.
#[unsafe(export_name = "f2k_export_LineTo")]
pub extern "system" fn line_to(dc: usize, x: i32, y: i32) -> u32 {
    answered(imports::line_to(dc, x, y)).map_or(0, |()| 1)
}

/// The figure of `count` points at `points` drawn by NtGdiPolyPolyDraw's `function`; FALSE with
/// ERROR_INVALID_PARAMETER for fewer than two points (the capture's Polyline of one).
fn poly(dc: usize, points: usize, count: i32, function: u32) -> u32 {
    if count < 2 {
        return failed(ERROR_INVALID_PARAMETER).unwrap_or(0);
    }
    let counts = [count as u32];
    answered(imports::poly_poly_draw(
        dc,
        Caller(points),
        &counts,
        function,
    ))
    .map_or(0, |()| 1)
}

/// Polyline: lines through the points, the current position untouched.
#[unsafe(export_name = "f2k_export_Polyline")]
pub extern "system" fn polyline(dc: usize, points: usize, count: i32) -> u32 {
    poly(dc, points, count, I_POLYPOLYLINE)
}

/// Polygon: the polygon of the points filled under the DC's fill mode and outlined, closed.
#[unsafe(export_name = "f2k_export_Polygon")]
pub extern "system" fn polygon(dc: usize, points: usize, count: i32) -> u32 {
    poly(dc, points, count, I_POLYPOLYGON)
}

fn shape(kind: ShapeKind, dc: usize, left: i32, top: i32, right: i32, bottom: i32) -> u32 {
    answered(imports::shape(kind, dc, left, top, right, bottom)).map_or(0, |()| 1)
}

/// Rectangle: the box outlined with the pen and filled with the brush.
#[unsafe(export_name = "f2k_export_Rectangle")]
pub extern "system" fn rectangle(dc: usize, left: i32, top: i32, right: i32, bottom: i32) -> u32 {
    shape(ShapeKind::Rectangle, dc, left, top, right, bottom)
}

/// Ellipse: the ellipse inscribed in the box, outlined and filled.
#[unsafe(export_name = "f2k_export_Ellipse")]
pub extern "system" fn ellipse(dc: usize, left: i32, top: i32, right: i32, bottom: i32) -> u32 {
    shape(ShapeKind::Ellipse, dc, left, top, right, bottom)
}

/// RoundRect: the box with corners of an ellipse `width` by `height`, outlined and filled.
#[unsafe(export_name = "f2k_export_RoundRect")]
pub extern "system" fn round_rect(
    dc: usize,
    left: i32,
    top: i32,
    right: i32,
    bottom: i32,
    width: i32,
    height: i32,
) -> u32 {
    shape(
        ShapeKind::RoundRect(width, height),
        dc,
        left,
        top,
        right,
        bottom,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::imports::host::LAST_ERROR;

    /// A figure of fewer than two points, and ExtCreatePen of no LOGBRUSH, fail here with
    /// ERROR_INVALID_PARAMETER, before any service.
    ///
    /// Pins: gdi32.Polyline, gdi32.Polygon, gdi32.ExtCreatePen
    #[test]
    fn too_few_points_fail_before_the_kernel() {
        LAST_ERROR.with(|error| error.set(0));
        assert_eq!(polyline(0x10, 0x1000, 1), 0);
        assert_eq!(
            LAST_ERROR.with(|error| error.get()),
            ERROR_INVALID_PARAMETER
        );
        LAST_ERROR.with(|error| error.set(0));
        assert_eq!(polygon(0x10, 0x1000, -3), 0);
        assert_eq!(
            LAST_ERROR.with(|error| error.get()),
            ERROR_INVALID_PARAMETER
        );
        LAST_ERROR.with(|error| error.set(0));
        // SAFETY: no LOGBRUSH is read.
        let pen = unsafe { ext_create_pen(0, 1, core::ptr::null(), 0, core::ptr::null()) };
        assert_eq!(pen, 0);
        assert_eq!(
            LAST_ERROR.with(|error| error.get()),
            ERROR_INVALID_PARAMETER
        );
    }
}
