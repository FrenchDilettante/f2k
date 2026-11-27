//! Lines and shapes: the services gdi32's MoveToEx, LineTo, GetCurrentPositionEx, Polyline,
//! Polygon, Rectangle, Ellipse and RoundRect come through. The drawing is the rasterizer's
//! ([`super::stroke`]), with the DC's pen ([`super::pen`]), brush, mix mode (SetROP2's) and polygon
//! fill mode, through its final region ([`super::dc`]'s clipping).
//!
//! The coordinates are logical, taken through the DC's mapping ([`super::mapping`]) and its origin;
//! the current position is kept in them, as Windows 2000's DC keeps it. A pen's width is the pen's
//! own, in pixels: F2K does not scale a geometric pen's width by the mapping. A cosmetic pen's
//! dashes leave their gaps in the background color when the background mode is OPAQUE, as Windows
//! draws styled lines; Polyline and Polygon leave the current position alone.
//!
//! The services (F2K's argument lists, see [`crate::win32k`]; a DC handle that names no DC is
//! STATUS_INVALID_HANDLE):
//!
//! - NtGdiMoveTo(handle Dc, i32 X, i32 Y, ptr Previous): the current position moved, the one it had
//!   into the POINT at `Previous` (unless null);
//! - NtGdiGetDCPoint(handle Dc, u32 Which, ptr Point): with DCPT_CURRENT_POSITION, the current
//!   position; with DCPT_VIEWPORT_EXT, DCPT_WINDOW_EXT, DCPT_VIEWPORT_ORG or DCPT_WINDOW_ORG, the
//!   mapping's extents or origins ([`super::mapping`]); STATUS_INVALID_PARAMETER for another point;
//! - NtGdiLineTo(handle Dc, i32 X, i32 Y): a line from the current position to the point, which
//!   becomes the current position;
//! - NtGdiPolyPolyDraw(u32 Dc, ptr Points, ptr Counts, u32 Count, u32 Function, ptr<u32> Result)
//!   with I_POLYPOLYGON or I_POLYPOLYLINE ([`poly_poly_draw`]; region.rs serves I_POLYPOLYRGN): the
//!   polygons (filled together under the fill mode, then outlined each, closed) or the polylines,
//!   each of `Counts[i]` points; a count below 2 is STATUS_INVALID_PARAMETER (the capture's
//!   Polyline of one point);
//! - NtGdiRectangle, NtGdiEllipse(handle Dc, i32 Left, i32 Top, i32 Right, i32 Bottom) and
//!   NtGdiRoundRect(the same, i32 Width, i32 Height): the shape ([`super::stroke::draw_shape`]).
//!
//! A drawing whose lists the pool cannot hold is STATUS_NO_MEMORY, as much of it drawn as was.

use rtl::gdi::*;

use super::bitmap::with_surface;
use super::dc::{dc_of, update_dc, DcState};
use super::raster::{screen_rgb, Pattern, Surface};
use super::region::{polygon, rect_buf, Buf, Crossing, SmallBuf, MOST_POINTS};
use super::stroke::{draw, draw_shape, Fx, Ink, Interior, Painter, Shape, Stroke};
use crate::nt::call::{Handle, NtCall, NtResult, UserAddr, UserPtr};
use crate::status::*;

/// Run `f` with a painter over the surface `dc` draws on (its final region, its mix mode), its
/// pen's stroke, the pen's pixel, the gaps' pixel (a cosmetic pen's dashes under OPAQUE) and the
/// brush's ink (none for the null brush); true before the graphics mode is set (nothing drawn).
fn paint(
    dc: &DcState,
    f: impl for<'p, 's> FnOnce(
        &mut Painter<'p, dyn Surface + 's>,
        &Stroke,
        u32,
        Option<u32>,
        Option<&Ink>,
    ) -> bool,
) -> bool {
    let stroke = dc.pen_state.stroke();
    let brush = dc.brush_fill.pattern(
        dc.text_color,
        dc.bk_color,
        dc.pattern_origin(),
        super::display::sys_color,
    );
    with_surface(dc, |surface| {
        let pen = surface.pixel(screen_rgb(dc.pen_state.color));
        let gap = match stroke {
            Stroke::Cosmetic { dashes, .. } if !dashes.is_solid() && dc.bk_mode == OPAQUE => {
                Some(surface.pixel(screen_rgb(dc.bk_color)))
            }
            _ => None,
        };
        let ink = brush.map(|pattern| match pattern {
            Pattern::Solid(rgb) => Ink::Pixel(surface.pixel(rgb)),
            other => Ink::Pattern(other),
        });
        let mut painter = Painter {
            surface,
            clip: dc.clip(),
            mode: dc.rop2,
        };
        f(&mut painter, &stroke, pen, gap, ink.as_ref())
    })
    .unwrap_or(true)
}

/// The surface's point, in 28.4, of the logical point (`x`, `y`).
fn surface_point(dc: &DcState, x: i32, y: i32) -> Fx {
    let (x, y) = dc.screen_point(x, y);
    Fx::pixel(x, y)
}

/// A drawing's outcome: STATUS_NO_MEMORY when a list ran out of room.
fn drawn(ok: bool) -> NtResult {
    if ok {
        Ok(STATUS_SUCCESS)
    } else {
        Err(STATUS_NO_MEMORY)
    }
}

/// NtGdiMoveTo(Dc, X, Y, Previous): see the module notes.
pub fn move_to(call: &mut NtCall, dc: Handle, x: i32, y: i32, previous: UserAddr) -> NtResult {
    let (px, py) = update_dc(call, dc, |dc| core::mem::replace(&mut dc.current, (x, y)))?;
    if !previous.is_null() {
        previous.cast::<Point>().write(Point { x: px, y: py })?;
    }
    Ok(STATUS_SUCCESS)
}

/// NtGdiGetDCPoint(Dc, Which, Point): see the module notes.
pub fn get_dc_point(call: &mut NtCall, dc: Handle, which: u32, point: UserAddr) -> NtResult {
    let (_reference, state) = dc_of(call, dc)?;
    let mapping = &state.mapping;
    let (x, y) = match which {
        DCPT_CURRENT_POSITION => state.current,
        DCPT_VIEWPORT_EXT => mapping.viewport_ext,
        DCPT_WINDOW_EXT => mapping.window_ext,
        DCPT_VIEWPORT_ORG => mapping.viewport_org,
        DCPT_WINDOW_ORG => mapping.window_org,
        _ => return Err(STATUS_INVALID_PARAMETER),
    };
    point.cast::<Point>().write(Point { x, y })?;
    Ok(STATUS_SUCCESS)
}

/// NtGdiLineTo(Dc, X, Y): see the module notes.
pub fn line_to(call: &mut NtCall, dc: Handle, x: i32, y: i32) -> NtResult {
    let (fx, fy) = update_dc(call, dc, |dc| core::mem::replace(&mut dc.current, (x, y)))?;
    let (_reference, state) = dc_of(call, dc)?;
    let path = [surface_point(&state, fx, fy), surface_point(&state, x, y)];
    let path = if path[0] == path[1] {
        &path[..1]
    } else {
        &path[..]
    };
    drawn(paint(&state, |painter, stroke, pen, gap, _| {
        draw(painter, stroke, pen, gap, path, false, Interior::None, None)
    }))
}

/// NtGdiRectangle(Dc, Left, Top, Right, Bottom): see the module notes.
pub fn rectangle(
    call: &mut NtCall,
    dc: Handle,
    left: i32,
    top: i32,
    right: i32,
    bottom: i32,
) -> NtResult {
    shape(call, dc, Shape::Rectangle, left, top, right, bottom)
}

/// NtGdiEllipse(Dc, Left, Top, Right, Bottom): see the module notes.
pub fn ellipse(
    call: &mut NtCall,
    dc: Handle,
    left: i32,
    top: i32,
    right: i32,
    bottom: i32,
) -> NtResult {
    shape(call, dc, Shape::Ellipse, left, top, right, bottom)
}

/// NtGdiRoundRect(Dc, Left, Top, Right, Bottom, Width, Height): see the module notes.
#[allow(clippy::too_many_arguments)]
pub fn round_rect(
    call: &mut NtCall,
    dc: Handle,
    left: i32,
    top: i32,
    right: i32,
    bottom: i32,
    width: i32,
    height: i32,
) -> NtResult {
    shape(
        call,
        dc,
        Shape::RoundRect(width, height),
        left,
        top,
        right,
        bottom,
    )
}

fn shape(
    call: &mut NtCall,
    dc: Handle,
    shape: Shape,
    left: i32,
    top: i32,
    right: i32,
    bottom: i32,
) -> NtResult {
    let (_reference, state) = dc_of(call, dc)?;
    let (left, top) = state.screen_point(left, top);
    let (right, bottom) = state.screen_point(right, bottom);
    // A round rectangle's corner is a size: scaled by the mapping, not moved, nor flipped.
    let shape = match shape {
        Shape::RoundRect(width, height) => {
            let (scaled_width, scaled_height) = state.device_distance(width, height);
            Shape::RoundRect(
                scaled_width.saturating_abs() * width.signum(),
                scaled_height.saturating_abs() * height.signum(),
            )
        }
        other => other,
    };
    drawn(paint(&state, |painter, stroke, pen, gap, brush| {
        draw_shape(
            painter,
            stroke,
            pen,
            gap,
            shape,
            (left, top, right, bottom),
            brush,
        )
    }))
}

/// NtGdiPolyPolyDraw's drawing functions (see the module notes): `function` I_POLYPOLYGON or
/// I_POLYPOLYLINE; 1 into `out`.
pub fn poly_poly_draw(
    call: &mut NtCall,
    dc: Handle,
    points: UserAddr,
    counts: UserAddr,
    count: u32,
    function: u32,
    out: UserPtr<u32>,
) -> NtResult {
    if count == 0 || count as usize > MOST_POINTS / 2 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let (_reference, state) = dc_of(call, dc)?;
    let mut figure_counts: SmallBuf<u32, 8> = SmallBuf::new(0, MOST_POINTS / 2);
    let mut total = 0usize;
    for index in 0..count {
        let figure = counts.offset(index * 4).cast::<u32>().read()?;
        total += figure as usize;
        if figure < 2 || total > MOST_POINTS {
            return Err(STATUS_INVALID_PARAMETER);
        }
        if !figure_counts.push(figure) {
            return Err(STATUS_NO_MEMORY);
        }
    }
    let mut corners: SmallBuf<Point, 16> = SmallBuf::new(Point::default(), MOST_POINTS);
    for index in 0..total {
        let point = points.offset(index as u32 * 8).cast::<Point>().read()?;
        let (x, y) = state.screen_point(point.x, point.y);
        if !corners.push(Point { x, y }) {
            return Err(STATUS_NO_MEMORY);
        }
    }
    let closed = match function {
        I_POLYPOLYGON => true,
        I_POLYPOLYLINE => false,
        _ => return Err(STATUS_NOT_IMPLEMENTED),
    };
    let mut rects = rect_buf();
    if closed && state.brush_fill != super::brush::Fill::Null {
        let mut crossings: SmallBuf<Crossing, 32> = SmallBuf::new(Crossing::default(), MOST_POINTS);
        let winding = state.fill_mode == WINDING;
        if !polygon(
            corners.as_slice(),
            figure_counts.as_slice(),
            winding,
            &mut rects,
            &mut crossings,
        ) {
            return Err(STATUS_NO_MEMORY);
        }
    }
    let mut ok = true;
    let mut start = 0usize;
    for (index, &figure) in figure_counts.as_slice().iter().enumerate() {
        let figure_points = &corners.as_slice()[start..start + figure as usize];
        start += figure as usize;
        let mut path: SmallBuf<Fx, 16> = SmallBuf::new(Fx::default(), MOST_POINTS);
        for point in figure_points {
            let point = Fx::pixel(point.x, point.y);
            if path.as_slice().last() != Some(&point) && !path.push(point) {
                return Err(STATUS_NO_MEMORY);
            }
        }
        let mut length = path.len();
        while closed && length > 1 && path.as_slice()[length - 1] == path.as_slice()[0] {
            length -= 1;
        }
        let path = &path.as_slice()[..length];
        // The polygons' interior is filled once, with the first.
        let interior = if index == 0 && closed {
            Interior::Rects(rects.as_slice())
        } else {
            Interior::None
        };
        ok &= paint(&state, |painter, stroke, pen, gap, brush| {
            let brush = if matches!(interior, Interior::None) {
                None
            } else {
                brush
            };
            draw(painter, stroke, pen, gap, path, closed, interior, brush)
        });
    }
    out.write(1)?;
    drawn(ok)
}
