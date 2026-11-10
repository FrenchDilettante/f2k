//! Brushes and fills: CreateSolidBrush and PatBlt, each over its win32k service ([`imports`]).
//! What the kernel serves is in its brush services' notes (kernel/src/win32k/brush.rs): solid
//! brushes as objects of the process, the global brushes (the stock ones, the system colors' and
//! user32's gray one) by their constant handles, and PatBlt by any raster operation without a
//! source. SelectObject and DeleteObject take brushes as they take the other objects
//! ([`crate::dc`]).

use crate::imports;
use crate::{answered, failed, ERROR_INVALID_PARAMETER};

/// CreateSolidBrush: a brush of the color's RGB (a COLORREF's high byte, a palette's flags, set
/// aside: the framebuffer is 32 bpp); NULL with the last error when the kernel has no room for
/// one.
#[unsafe(export_name = "f2k_export_CreateSolidBrush")]
pub extern "system" fn create_solid_brush(color: u32) -> usize {
    answered(imports::create_solid_brush(color)).map_or(0, |brush| brush as usize)
}

/// PatBlt: the rectangle at (`x`, `y`), `width` by `height` (a negative extent reaching back from
/// the point), painted with the DC's brush by the raster operation; FALSE with
/// ERROR_INVALID_PARAMETER for an operation that reads a source, with the service's error for a
/// DC that is none.
#[unsafe(export_name = "f2k_export_PatBlt")]
pub extern "system" fn pat_blt(
    dc: usize,
    x: i32,
    y: i32,
    width: i32,
    height: i32,
    rop: u32,
) -> u32 {
    if !rtl::gdi::rop_is_sourceless(rop) {
        return failed(ERROR_INVALID_PARAMETER).unwrap_or(0);
    }
    answered(imports::pat_blt(dc, x, y, width, height, rop)).map_or(0, |()| 1)
}

#[cfg(test)]
mod tests {
    use rtl::gdi::*;

    use super::*;
    use crate::dc::{delete_object, select_object};
    use crate::imports::host::{
        Fill,
        HostDc,
        BAD,
        BRUSHES,
        DC,
        FILLS,
        FIRST_BRUSH,
        HOST_DC,
        LAST_ERROR,
    };
    use crate::ERROR_INVALID_HANDLE;

    fn reset() {
        HOST_DC.with(|state| *state.borrow_mut() = HostDc::new());
        BRUSHES.with(|brushes| brushes.borrow_mut().clear());
        FILLS.with(|fills| fills.borrow_mut().clear());
        LAST_ERROR.with(|error| error.set(0xF2F2));
    }

    fn last_error() -> u32 {
        LAST_ERROR.with(|error| error.get())
    }

    /// A solid brush is an object the DC selects over the default one, which is answered; PatBlt
    /// fills with the selected brush; DeleteObject deletes the brush, which no DC selects then.
    ///
    /// Pins: gdi32.CreateSolidBrush, gdi32.PatBlt, gdi32.SelectObject, gdi32.DeleteObject
    #[test]
    fn a_solid_brush_fills_through_the_dc() {
        reset();
        let red = create_solid_brush(0x0100_00FF);
        assert_eq!(red, FIRST_BRUSH as usize);
        assert_eq!(
            BRUSHES.with(|brushes| brushes.borrow().clone()),
            [(FIRST_BRUSH, 0xFF)]
        );
        let white = stock_handle(WHITE_BRUSH).unwrap() as usize;
        assert_eq!(select_object(DC, red), white);
        assert_eq!(pat_blt(DC, 1, 2, -3, 4, PATCOPY), 1);
        assert_eq!(pat_blt(DC, 0, 0, 5, 5, DSTINVERT), 1);
        assert_eq!(select_object(DC, white), red);
        let fills = FILLS.with(|fills| fills.borrow().clone());
        assert_eq!(
            fills,
            [
                Fill {
                    x: 1,
                    y: 2,
                    width: -3,
                    height: 4,
                    rop: PATCOPY,
                    brush: red as u32
                },
                Fill {
                    x: 0,
                    y: 0,
                    width: 5,
                    height: 5,
                    rop: DSTINVERT,
                    brush: red as u32
                },
            ]
        );
        assert_eq!(last_error(), 0xF2F2);
        assert_eq!(delete_object(red), 1);
        assert_eq!(select_object(DC, red), 0, "deleted");
        assert_eq!(last_error(), ERROR_INVALID_HANDLE);
    }

    /// The global brushes select as brushes by their handles: a system color's and the gray one;
    /// DeleteObject leaves them. A DC or a handle that names nothing is no object to select.
    ///
    /// Pins: gdi32.SelectObject, gdi32.DeleteObject
    #[test]
    fn global_brushes_select_by_their_handles() {
        reset();
        let face = sys_color_brush(15).unwrap() as usize;
        let white = stock_handle(WHITE_BRUSH).unwrap() as usize;
        assert_eq!(select_object(DC, face), white);
        assert_eq!(select_object(DC, HALFTONE_BRUSH as usize), face);
        assert_eq!(delete_object(face), 1);
        assert_eq!(
            select_object(DC, face),
            HALFTONE_BRUSH as usize,
            "never deleted"
        );
        assert_eq!(select_object(DC, DC), 0, "a DC is no object a DC selects");
        assert_eq!(last_error(), ERROR_INVALID_HANDLE);
        assert_eq!(select_object(DC, 0x7FF0), 0);
        assert_eq!(last_error(), ERROR_INVALID_HANDLE);
    }

    /// PatBlt refuses a raster operation that reads a source before any service, and a DC that is
    /// none through the service.
    ///
    /// Pins: gdi32.PatBlt
    #[test]
    fn pat_blt_refuses_a_source() {
        reset();
        const SRCCOPY: u32 = 0x00CC_0020;
        assert_eq!(pat_blt(DC, 0, 0, 1, 1, SRCCOPY), 0);
        assert_eq!(last_error(), ERROR_INVALID_PARAMETER);
        assert_eq!(pat_blt(BAD, 0, 0, 1, 1, PATCOPY), 0);
        assert_eq!(last_error(), ERROR_INVALID_HANDLE);
        assert!(FILLS.with(|fills| fills.borrow().is_empty()));
    }
}
