//! Brushes: win32k's brush objects, the fills a DC paints with them, and PatBlt.
//!
//! A brush is an object of the object manager ([`crate::ob`]'s Brush type), its body a [`Brush`]:
//! what it paints ([`Fill`]). Its creator's process holds it through a handle in its handle table,
//! as a DC is held ([`super::dc`]), so a brush closes with its process's other handles at its end.
//! (Windows 2000 keeps its brushes in GDI's own handle table; F2K keeps them as it keeps its DCs.)
//! The handle a program sees carries the brush kind in its high word above the table's handle
//! ([`rtl::gdi::object_handle`]), as Windows 2000's GDI handles carry their type: it never reads
//! as FillRect's COLOR_* + 1, and gdi32 knows the kind from the handle.
//!
//! Beside the brush objects there are the global brushes, which every process names by the same
//! constant handle and which are never deleted ([`rtl::gdi::GlobalBrush`]): the stock brushes, the
//! system colors' brushes GetSysColorBrush answers, which paint in the system color as it is when
//! they draw (SetSysColors recolors them, as Windows 2000's keep their handles across it), and
//! user32's gray brush, the checkerboard DrawFocusRect draws with.
//!
//! A DC keeps the fill of the brush it has selected beside the brush's handle ([`super::dc::Dc`]):
//! a solid brush never changes, so the copy paints as the brush does, and a brush deleted while
//! selected leaves the DC able to draw (Windows 2000 defers such a deletion until the brush is
//! deselected; F2K's DC holds what it needs instead).
//!
//! The services (F2K's argument lists, see [`crate::win32k`]):
//!
//! - NtGdiCreateSolidBrush(u32 Color, ptr<u32> Brush): a solid brush of the COLORREF's color, its
//!   handle in the calling process (not inheritable);
//! - NtGdiPatBlt(handle Dc, i32 X, i32 Y, i32 Width, i32 Height, u32 Rop): the rectangle at (`X`,
//!   `Y`) (logical coordinates: the DC's origin added), `Width` by `Height` (a negative extent
//!   reaching back from the point), painted with the DC's brush by the raster operation, clipped to
//!   the DC's clipping region ([`super::raster::pat_blt`]). A raster operation that reads a source
//!   is STATUS_INVALID_PARAMETER (PatBlt has none); the null brush paints nothing where the
//!   operation reads the pattern.

use rtl::gdi::*;

use super::raster::{screen_rgb, Pattern};
use crate::nt::call::{Handle, NtCall, NtResult, UserPtr};
use crate::status::*;

/// The access a brush's handle carries: STANDARD_RIGHTS_REQUIRED (a brush has no specific rights).
pub const BRUSH_ACCESS: u32 = 0x000F_0000;

/// What a brush paints.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fill {
    /// Nothing: the null (hollow) brush.
    Null,
    /// One color, a COLORREF.
    Solid(u32),
    /// The system color at this index, as it is when the brush draws.
    SysColor(u32),
    /// The gray checkerboard ([`rtl::gdi::HALFTONE_ROWS`]), in the DC's background and text
    /// colors.
    Halftone,
}

impl Fill {
    /// What the global brush `brush` paints.
    pub fn of_global(brush: GlobalBrush) -> Fill {
        match brush {
            GlobalBrush::Stock(index) => match index {
                WHITE_BRUSH | DC_BRUSH => Fill::Solid(0x00FF_FFFF),
                LTGRAY_BRUSH => Fill::Solid(0x00C0_C0C0),
                GRAY_BRUSH => Fill::Solid(0x0080_8080),
                DKGRAY_BRUSH => Fill::Solid(0x0040_4040),
                BLACK_BRUSH => Fill::Solid(0x0000_0000),
                _ => Fill::Null,
            },
            GlobalBrush::SysColor(index) => Fill::SysColor(index),
            GlobalBrush::Halftone => Fill::Halftone,
        }
    }

    /// The pattern the fill paints with in a DC of `text_color` and `bk_color` (COLORREFs), its
    /// brush origin at the screen's `origin`, the system colors read through `sys_color`; none for
    /// the null brush.
    pub fn pattern(
        &self,
        text_color: u32,
        bk_color: u32,
        origin: (i32, i32),
        sys_color: impl FnOnce(u32) -> Option<u32>,
    ) -> Option<Pattern> {
        match *self {
            Fill::Null => None,
            Fill::Solid(color) => Some(Pattern::Solid(screen_rgb(color))),
            Fill::SysColor(index) => Some(Pattern::Solid(screen_rgb(sys_color(index)?))),
            Fill::Halftone => Some(Pattern::Mono {
                rows: HALFTONE_ROWS,
                origin,
                one: screen_rgb(bk_color),
                zero: screen_rgb(text_color),
            }),
        }
    }
}

/// A brush object's body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Brush {
    pub fill: Fill,
}

impl Brush {
    /// A record holding no brush (a pool's fresh record).
    pub const fn none() -> Self {
        Brush { fill: Fill::Null }
    }
}

/// The rectangle PatBlt names: the point and the extents, a negative extent reaching back from the
/// point (the rectangle's right and bottom edges outside it either way), moved by `origin`.
pub fn pat_blt_rect(x: i32, y: i32, width: i32, height: i32, origin: (i32, i32)) -> Rect {
    let span = |at: i32, extent: i32| {
        let end = at.saturating_add(extent);
        (at.min(end), at.max(end))
    };
    let (left, right) = span(x.saturating_add(origin.0), width);
    let (top, bottom) = span(y.saturating_add(origin.1), height);
    Rect {
        left,
        top,
        right,
        bottom,
    }
}

// --- The services --------------------------------------------------------------------------------

/// NtGdiCreateSolidBrush(Color, Brush): a solid brush of `color`, its handle (the brush kind's,
/// see the module notes) into `out`; STATUS_INSUFFICIENT_RESOURCES when the brushes' pool or the
/// handle table is full.
pub fn create_solid_brush(call: &mut NtCall, color: u32, out: UserPtr<u32>) -> NtResult {
    let handle = publish_brush(
        call,
        Brush {
            fill: Fill::Solid(color & RGB_MASK),
        },
    )?;
    if out.write(object_handle(OBJ_BRUSH, handle)).is_err() {
        close_brush(call, handle);
        return Err(STATUS_ACCESS_VIOLATION);
    }
    Ok(STATUS_SUCCESS)
}

/// NtGdiPatBlt(Dc, X, Y, Width, Height, Rop): see the module notes.
pub fn pat_blt(
    call: &mut NtCall,
    dc: Handle,
    x: i32,
    y: i32,
    width: i32,
    height: i32,
    rop: u32,
) -> NtResult {
    if !rop_is_sourceless(rop) {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let (_reference, dc) = super::dc::dc_of(call, dc)?;
    let origin = dc.origin;
    let rect = pat_blt_rect(x, y, width, height, origin);
    let pattern = dc.brush_fill.pattern(
        dc.text_color,
        dc.bk_color,
        origin,
        super::display::sys_color,
    );
    if pattern.is_none() && rop_uses_pattern(rop) {
        return Ok(STATUS_SUCCESS);
    }
    super::dc::with_screen(|screen| {
        super::raster::pat_blt(screen, dc.clip, rect, rop, pattern.as_ref())
    });
    Ok(STATUS_SUCCESS)
}

/// What the brush `handle` names paints: a global brush's fill, or the calling process's brush
/// object's; STATUS_OBJECT_TYPE_MISMATCH for a handle of another kind, STATUS_INVALID_HANDLE for
/// one that names nothing.
pub fn fill_of(call: &mut NtCall, handle: Handle) -> Result<Fill, NtStatus> {
    if let Some(brush) = global_brush(handle.raw()) {
        return Ok(Fill::of_global(brush));
    }
    match object_of(handle.raw()) {
        Some((OBJ_BRUSH, table)) => brush_object(call, Handle(table)),
        Some(_) => Err(STATUS_OBJECT_TYPE_MISMATCH),
        None if global_object_kind(handle.raw()).is_some() => Err(STATUS_OBJECT_TYPE_MISMATCH),
        // A bare handle-table handle: a DC's, or nothing a brush may be.
        None => Err(STATUS_INVALID_HANDLE),
    }
}

// --- The target's side: the objects --------------------------------------------------------------

/// A brush of state `brush` made, its handle in the calling process (not inheritable);
/// STATUS_INSUFFICIENT_RESOURCES when the brushes' pool or the handle table is full.
#[cfg(target_arch = "x86")]
fn publish_brush(call: &mut NtCall, brush: Brush) -> Result<u32, NtStatus> {
    let id = crate::ob::locked(|directory| directory.create_brush(brush))
        .ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
    crate::ob::publish(call.process(), id, BRUSH_ACCESS, false)
        .map(core::num::NonZeroU32::get)
        .ok_or(STATUS_INSUFFICIENT_RESOURCES)
}

/// Close the calling process's handle `handle` (one this service just made).
#[cfg(target_arch = "x86")]
fn close_brush(call: &mut NtCall, handle: u32) {
    call.process().close_handle(handle);
}

/// The fill of the brush object the calling process's handle-table handle `handle` names (see
/// [`fill_of`]).
#[cfg(target_arch = "x86")]
fn brush_object(_call: &mut NtCall, handle: Handle) -> Result<Fill, NtStatus> {
    let reference =
        crate::ob::reference_by_handle(handle.raw(), None).ok_or(STATUS_INVALID_HANDLE)?;
    if reference.id().kind != crate::ob::ObjectType::Brush {
        return Err(STATUS_OBJECT_TYPE_MISMATCH);
    }
    crate::ob::locked(|directory| directory.brush(reference.id()).map(|brush| brush.fill))
        .ok_or(STATUS_INVALID_HANDLE)
}

// The host builds have no processes: no brush object is made or found (the host tests drive the
// fills and the rectangles themselves).

#[cfg(not(target_arch = "x86"))]
fn publish_brush(_: &mut NtCall, _: Brush) -> Result<u32, NtStatus> {
    Err(STATUS_NOT_IMPLEMENTED)
}

#[cfg(not(target_arch = "x86"))]
fn close_brush(_: &mut NtCall, _: u32) {}

#[cfg(not(target_arch = "x86"))]
fn brush_object(_: &mut NtCall, _: Handle) -> Result<Fill, NtStatus> {
    Err(STATUS_INVALID_HANDLE)
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

    /// The stock brushes paint their documented grays (NULL_BRUSH nothing); a system color's brush
    /// reads its color when it draws; the gray brush is the checkerboard in the DC's colors, from
    /// the DC's origin.
    #[test]
    fn the_global_brushes_paint_their_colors() {
        let none = |_| None;
        let solid =
            |index| Fill::of_global(GlobalBrush::Stock(index)).pattern(0, 0xFF_FFFF, (0, 0), none);
        assert_eq!(solid(WHITE_BRUSH), Some(Pattern::Solid(0xFF_FFFF)));
        assert_eq!(solid(LTGRAY_BRUSH), Some(Pattern::Solid(0xC0_C0C0)));
        assert_eq!(solid(GRAY_BRUSH), Some(Pattern::Solid(0x80_8080)));
        assert_eq!(solid(DKGRAY_BRUSH), Some(Pattern::Solid(0x40_4040)));
        assert_eq!(solid(BLACK_BRUSH), Some(Pattern::Solid(0)));
        assert_eq!(solid(NULL_BRUSH), None);

        let face = Fill::of_global(GlobalBrush::SysColor(15));
        let scheme = |index| {
            rtl::display::DEFAULT_SYSTEM_COLORS
                .get(index as usize)
                .copied()
        };
        assert_eq!(
            face.pattern(0, 0, (0, 0), scheme),
            Some(Pattern::Solid(0xD4_D0C8)),
            "COLOR_BTNFACE, as the framebuffer's RGB"
        );
        assert_eq!(
            face.pattern(0, 0, (0, 0), |_| Some(0x00_00FF)),
            Some(Pattern::Solid(0xFF_0000))
        );

        let gray = Fill::of_global(GlobalBrush::Halftone);
        assert_eq!(
            gray.pattern(0x00_00FF, 0xFF_0000, (3, 4), none),
            Some(Pattern::Mono {
                rows: HALFTONE_ROWS,
                origin: (3, 4),
                one: 0x00_00FF,
                zero: 0xFF_0000,
            })
        );
        assert_eq!(
            Fill::Solid(0x0003_0201).pattern(0, 0, (0, 0), none),
            Some(Pattern::Solid(0x0001_0203))
        );
    }

    /// PatBlt's rectangle: the extents from the point, a negative one reaching back, moved by the
    /// DC's origin.
    #[test]
    fn pat_blt_rectangles_normalize() {
        assert_eq!(pat_blt_rect(2, 3, 4, 5, (0, 0)), rect(2, 3, 6, 8));
        assert_eq!(pat_blt_rect(2, 3, -2, -3, (0, 0)), rect(0, 0, 2, 3));
        assert_eq!(pat_blt_rect(2, 3, 4, 5, (100, 50)), rect(102, 53, 106, 58));
        assert_eq!(pat_blt_rect(1, 1, 0, 4, (0, 0)), rect(1, 1, 1, 5), "empty");
        assert_eq!(
            pat_blt_rect(i32::MAX - 1, 0, 10, 1, (5, 0)),
            rect(i32::MAX, 0, i32::MAX, 1),
            "saturated, not wrapped"
        );
    }
}
