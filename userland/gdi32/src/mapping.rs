//! Coordinate spaces and saved states: SetMapMode and GetMapMode, the window's and the viewport's
//! origins and extents (Set, Get, Offset, Scale), LPtoDP and DPtoLP, SaveDC and RestoreDC.
//!
//! The mapping is win32k's DC's (kernel/src/win32k/mapping.rs: the transform, the modes'
//! extents, MM_ISOTROPIC's adjustment, the rounding). Windows 2000's gdi32 writes the mapping's
//! fields in its user-mode copy of the DC's attributes and leaves the transform to the kernel; F2K
//! keeps no user-mode copy, so the same steps go through win32k's services: an origin or an
//! extent is set a coordinate at a time (NtGdiGetAndSetDCDword's DC_ indexes), the extents' rules
//! taken here as Windows 2000's gdi32 takes them (a fixed mode leaves them, 0 is refused), then
//! NtGdiComputeXformCoefficients adjusts MM_ISOTROPIC's viewport. The scales, the points' transform
//! and the saved states are win32k's services, as Windows 2000's.
//!
//! What the mapmode capture shows, beyond the kernel's rules: SetMapMode of a value that is no mode
//! answers 0 and sets no error; SetWindowExtEx of a zero extent answers FALSE, SetViewportExtEx's
//! TRUE, both after writing the previous extents and leaving the mapping; SaveDC of a DC that is
//! none answers 0 with no error, RestoreDC of a level that is none FALSE with
//! ERROR_INVALID_PARAMETER.

use rtl::gdi::*;
use rtl::status::STATUS_INVALID_HANDLE;

use crate::imports::{self, Caller};
use crate::{answered, failed, ERROR_INVALID_PARAMETER};

/// The DC's point `which` (rtl::gdi's DCPT_ indexes), or none with the last error.
fn dc_point(dc: usize, which: u32) -> Option<(i32, i32)> {
    let mut point = Point::default();
    answered(imports::dc_point(dc, which, Caller::of_mut(&mut point)))?;
    Some((point.x, point.y))
}

/// `value` into the caller's POINT, when given.
///
/// # Safety
///
/// `out`, when not null, a POINT's room.
unsafe fn put_point(out: *mut Point, (x, y): (i32, i32)) {
    // SAFETY: the caller's POINT.
    if let Some(mut out) = unsafe { crate::Out::optional(out) } {
        out.set(Point { x, y });
    }
}

/// `value` into the caller's SIZE, when given.
///
/// # Safety
///
/// `out`, when not null, a SIZE's room.
unsafe fn put_size(out: *mut Size, (cx, cy): (i32, i32)) {
    // SAFETY: the caller's SIZE.
    if let Some(mut out) = unsafe { crate::Out::optional(out) } {
        out.set(Size { cx, cy });
    }
}

/// SetMapMode: the DC's mapping mode set (the kernel sets the mode's extents), the one it had
/// answered; 0 and no error for a value that is no mode (as the mapmode capture's SetMapMode(0) and
/// (9)), 0 with the last error for a DC that is none.
#[unsafe(export_name = "f2k_export_SetMapMode")]
pub extern "system" fn set_map_mode(dc: usize, mode: i32) -> i32 {
    if !(MM_TEXT as i32..=MM_ANISOTROPIC as i32).contains(&mode) {
        return 0;
    }
    answered(imports::set_dc_dword(dc, DC_MAP_MODE, mode as u32))
        .map_or(0, |previous| previous as i32)
}

/// GetMapMode: the DC's mapping mode; 0 with the last error for a DC that is none.
#[unsafe(export_name = "f2k_export_GetMapMode")]
pub extern "system" fn get_map_mode(dc: usize) -> i32 {
    answered(imports::dc_dword(dc, DC_MAP_MODE)).map_or(0, |mode| mode as i32)
}

/// GetWindowOrgEx, GetViewportOrgEx, GetWindowExtEx and GetViewportExtEx's work: the DC's point
/// `which` into the caller's POINT (a SIZE's room is a POINT's); FALSE with the last error for a
/// DC that is none.
///
/// # Safety
///
/// `out`, when not null, a POINT's room.
unsafe fn get_point(dc: usize, which: u32, out: *mut Point) -> u32 {
    let Some(point) = dc_point(dc, which) else {
        return 0;
    };
    // SAFETY: the caller's contract.
    unsafe { put_point(out, point) };
    1
}

/// GetWindowOrgEx: the DC's window origin into `point`.
///
/// # Safety
///
/// `point`, when not null, a POINT's room.
#[unsafe(export_name = "f2k_export_GetWindowOrgEx")]
pub unsafe extern "system" fn get_window_org_ex(dc: usize, point: *mut Point) -> u32 {
    // SAFETY: the caller's contract.
    unsafe { get_point(dc, DCPT_WINDOW_ORG, point) }
}

/// GetViewportOrgEx: the DC's viewport origin into `point`.
///
/// # Safety
///
/// `point`, when not null, a POINT's room.
#[unsafe(export_name = "f2k_export_GetViewportOrgEx")]
pub unsafe extern "system" fn get_viewport_org_ex(dc: usize, point: *mut Point) -> u32 {
    // SAFETY: the caller's contract.
    unsafe { get_point(dc, DCPT_VIEWPORT_ORG, point) }
}

/// GetWindowExtEx: the DC's window extents into `size`.
///
/// # Safety
///
/// `size`, when not null, a SIZE's room.
#[unsafe(export_name = "f2k_export_GetWindowExtEx")]
pub unsafe extern "system" fn get_window_ext_ex(dc: usize, size: *mut Size) -> u32 {
    // SAFETY: the caller's contract (a SIZE is a POINT's two i32s).
    unsafe { get_point(dc, DCPT_WINDOW_EXT, size.cast()) }
}

/// GetViewportExtEx: the DC's viewport extents into `size`.
///
/// # Safety
///
/// `size`, when not null, a SIZE's room.
#[unsafe(export_name = "f2k_export_GetViewportExtEx")]
pub unsafe extern "system" fn get_viewport_ext_ex(dc: usize, size: *mut Size) -> u32 {
    // SAFETY: the caller's contract (a SIZE is a POINT's two i32s).
    unsafe { get_point(dc, DCPT_VIEWPORT_EXT, size.cast()) }
}

/// An origin set, a coordinate at a time (`indexes`, the x's and the y's DC_ index), the one it had
/// answered; none with the last error for a DC that is none.
fn set_origin(dc: usize, indexes: (u32, u32), (x, y): (i32, i32)) -> Option<(i32, i32)> {
    let old_x = answered(imports::set_dc_dword(dc, indexes.0, x as u32))?;
    let old_y = answered(imports::set_dc_dword(dc, indexes.1, y as u32))?;
    Some((old_x as i32, old_y as i32))
}

/// SetWindowOrgEx: the DC's window origin set (the logical point that lands on the viewport
/// origin), the one it had into `previous` (when given); FALSE with the last error for a DC that
/// is none.
///
/// # Safety
///
/// `previous`, when not null, a POINT's room.
#[unsafe(export_name = "f2k_export_SetWindowOrgEx")]
pub unsafe extern "system" fn set_window_org_ex(
    dc: usize,
    x: i32,
    y: i32,
    previous: *mut Point,
) -> u32 {
    let Some(old) = set_origin(dc, (DC_WINDOW_ORG_X, DC_WINDOW_ORG_Y), (x, y)) else {
        return 0;
    };
    // SAFETY: the caller's contract.
    unsafe { put_point(previous, old) };
    1
}

/// SetViewportOrgEx: the DC's viewport origin set (the device point the window origin lands on),
/// as SetWindowOrgEx.
///
/// # Safety
///
/// `previous`, when not null, a POINT's room.
#[unsafe(export_name = "f2k_export_SetViewportOrgEx")]
pub unsafe extern "system" fn set_viewport_org_ex(
    dc: usize,
    x: i32,
    y: i32,
    previous: *mut Point,
) -> u32 {
    let Some(old) = set_origin(dc, (DC_VIEWPORT_ORG_X, DC_VIEWPORT_ORG_Y), (x, y)) else {
        return 0;
    };
    // SAFETY: the caller's contract.
    unsafe { put_point(previous, old) };
    1
}

/// OffsetWindowOrgEx and OffsetViewportOrgEx's work: the origin `which` names moved by (`dx`,
/// `dy`), the one it had into `previous`.
///
/// # Safety
///
/// `previous`, when not null, a POINT's room.
unsafe fn offset_origin(dc: usize, window: bool, dx: i32, dy: i32, previous: *mut Point) -> u32 {
    let (which, indexes) = if window {
        (DCPT_WINDOW_ORG, (DC_WINDOW_ORG_X, DC_WINDOW_ORG_Y))
    } else {
        (DCPT_VIEWPORT_ORG, (DC_VIEWPORT_ORG_X, DC_VIEWPORT_ORG_Y))
    };
    let Some((x, y)) = dc_point(dc, which) else {
        return 0;
    };
    if set_origin(dc, indexes, (x.wrapping_add(dx), y.wrapping_add(dy))).is_none() {
        return 0;
    }
    // SAFETY: the caller's contract.
    unsafe { put_point(previous, (x, y)) };
    1
}

/// OffsetWindowOrgEx: the window origin moved by (`dx`, `dy`), the one it had into `previous`.
///
/// # Safety
///
/// `previous`, when not null, a POINT's room.
#[unsafe(export_name = "f2k_export_OffsetWindowOrgEx")]
pub unsafe extern "system" fn offset_window_org_ex(
    dc: usize,
    dx: i32,
    dy: i32,
    previous: *mut Point,
) -> u32 {
    // SAFETY: the caller's contract.
    unsafe { offset_origin(dc, true, dx, dy, previous) }
}

/// OffsetViewportOrgEx: the viewport origin moved by (`dx`, `dy`), the one it had into
/// `previous`.
///
/// # Safety
///
/// `previous`, when not null, a POINT's room.
#[unsafe(export_name = "f2k_export_OffsetViewportOrgEx")]
pub unsafe extern "system" fn offset_viewport_org_ex(
    dc: usize,
    dx: i32,
    dy: i32,
    previous: *mut Point,
) -> u32 {
    // SAFETY: the caller's contract.
    unsafe { offset_origin(dc, false, dx, dy, previous) }
}

/// SetWindowExtEx and SetViewportExtEx's work (see the module notes): the previous extents into
/// `previous`; in MM_ISOTROPIC and MM_ANISOTROPIC the extents set, a coordinate at a time, and
/// MM_ISOTROPIC's viewport adjusted; a fixed mode's left (TRUE); a zero extent refused, the
/// window's FALSE and the viewport's TRUE.
///
/// # Safety
///
/// `previous`, when not null, a SIZE's room.
unsafe fn set_ext(dc: usize, window: bool, x: i32, y: i32, previous: *mut Size) -> u32 {
    let (which, indexes) = if window {
        (DCPT_WINDOW_EXT, (DC_WINDOW_EXT_X, DC_WINDOW_EXT_Y))
    } else {
        (DCPT_VIEWPORT_EXT, (DC_VIEWPORT_EXT_X, DC_VIEWPORT_EXT_Y))
    };
    let Some(old) = dc_point(dc, which) else {
        return 0;
    };
    // SAFETY: the caller's contract.
    unsafe { put_size(previous, old) };
    let Some(mode) = answered(imports::dc_dword(dc, DC_MAP_MODE)) else {
        return 0;
    };
    if !matches!(mode, MM_ISOTROPIC | MM_ANISOTROPIC) {
        return 1;
    }
    if x == 0 || y == 0 {
        return (!window) as u32;
    }
    if answered(imports::set_dc_dword(dc, indexes.0, x as u32)).is_none()
        || answered(imports::set_dc_dword(dc, indexes.1, y as u32)).is_none()
    {
        return 0;
    }
    if mode == MM_ISOTROPIC && answered(imports::compute_xform(dc)).is_none() {
        return 0;
    }
    1
}

/// SetWindowExtEx: see [`set_ext`].
///
/// # Safety
///
/// `previous`, when not null, a SIZE's room.
#[unsafe(export_name = "f2k_export_SetWindowExtEx")]
pub unsafe extern "system" fn set_window_ext_ex(
    dc: usize,
    x: i32,
    y: i32,
    previous: *mut Size,
) -> u32 {
    // SAFETY: the caller's contract.
    unsafe { set_ext(dc, true, x, y, previous) }
}

/// SetViewportExtEx: see [`set_ext`].
///
/// # Safety
///
/// `previous`, when not null, a SIZE's room.
#[unsafe(export_name = "f2k_export_SetViewportExtEx")]
pub unsafe extern "system" fn set_viewport_ext_ex(
    dc: usize,
    x: i32,
    y: i32,
    previous: *mut Size,
) -> u32 {
    // SAFETY: the caller's contract.
    unsafe { set_ext(dc, false, x, y, previous) }
}

/// ScaleWindowExtEx: the window's extents scaled by `x_num / x_den` and `y_num / y_den` (the
/// kernel's NtGdiScaleWindowExtEx, which writes the previous extents); FALSE, no error, for a
/// scale the mapping refuses.
///
/// # Safety
///
/// `previous`, when not null, a SIZE's room.
#[unsafe(export_name = "f2k_export_ScaleWindowExtEx")]
pub unsafe extern "system" fn scale_window_ext_ex(
    dc: usize,
    x_num: i32,
    x_den: i32,
    y_num: i32,
    y_den: i32,
    previous: *mut Size,
) -> u32 {
    let previous = Caller(previous as usize);
    answered(imports::scale_ext(
        true,
        dc,
        (x_num, x_den),
        (y_num, y_den),
        previous,
    ))
    .map_or(0, u32::from)
}

/// ScaleViewportExtEx: the viewport's extents, as ScaleWindowExtEx.
///
/// # Safety
///
/// `previous`, when not null, a SIZE's room.
#[unsafe(export_name = "f2k_export_ScaleViewportExtEx")]
pub unsafe extern "system" fn scale_viewport_ext_ex(
    dc: usize,
    x_num: i32,
    x_den: i32,
    y_num: i32,
    y_den: i32,
    previous: *mut Size,
) -> u32 {
    let previous = Caller(previous as usize);
    answered(imports::scale_ext(
        false,
        dc,
        (x_num, x_den),
        (y_num, y_den),
        previous,
    ))
    .map_or(0, u32::from)
}

/// LPtoDP and DPtoLP's work: the `count` POINTs at `points` taken through the DC's mapping in
/// place, in the direction `mode`; FALSE with ERROR_INVALID_PARAMETER for a negative count, with
/// the service's error for a DC that is none or memory it cannot reach.
fn transform(dc: usize, points: *mut Point, count: i32, mode: u32) -> u32 {
    if count < 0 {
        return failed(ERROR_INVALID_PARAMETER).unwrap_or(0);
    }
    if count == 0 {
        return 1;
    }
    let points = Caller(points as usize);
    answered(imports::transform_points(dc, points, count as u32, mode)).map_or(0, |()| 1)
}

/// LPtoDP: the POINTs at `points` taken from logical to device coordinates.
#[unsafe(export_name = "f2k_export_LPtoDP")]
pub extern "system" fn lp_to_dp(dc: usize, points: *mut Point, count: i32) -> u32 {
    transform(dc, points, count, XFP_LPTODP)
}

/// DPtoLP: the POINTs at `points` taken from device to logical coordinates.
#[unsafe(export_name = "f2k_export_DPtoLP")]
pub extern "system" fn dp_to_lp(dc: usize, points: *mut Point, count: i32) -> u32 {
    transform(dc, points, count, XFP_DPTOLP)
}

/// SaveDC: the DC's whole state saved (the kernel's copy of it), its level answered; 0 and no
/// error for a DC that is none (the mapmode capture's SaveDC of a deleted DC), 0 with the last
/// error when the kernel has no room.
#[unsafe(export_name = "f2k_export_SaveDC")]
pub extern "system" fn save_dc(dc: usize) -> i32 {
    match imports::save_dc(dc) {
        Ok(level) => level as i32,
        Err(status) if status.0 == STATUS_INVALID_HANDLE => 0,
        Err(status) => {
            answered::<()>(Err(status));
            0
        }
    }
}

/// RestoreDC: the saved state `level` restored (negative: counted back from the last saved, -1
/// the last), the ones saved after it dropped; FALSE with ERROR_INVALID_PARAMETER for a level that
/// names none.
#[unsafe(export_name = "f2k_export_RestoreDC")]
pub extern "system" fn restore_dc(dc: usize, level: i32) -> u32 {
    answered(imports::restore_dc(dc, level)).map_or(0, |()| 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::imports::host::{HostDc, BAD, DC, HOST_DC, LAST_ERROR};

    fn last_error() -> u32 {
        LAST_ERROR.with(|error| error.get())
    }

    fn reset() {
        HOST_DC.with(|state| *state.borrow_mut() = HostDc::new());
        LAST_ERROR.with(|error| error.set(0xF2F2));
    }

    fn host() -> HostDc {
        HOST_DC.with(|state| *state.borrow())
    }

    /// The mapmode capture's `modes`: a value that is no mode answers 0, no error, the mode kept.
    #[test]
    fn set_map_mode_refuses_what_is_no_mode() {
        reset();
        assert_eq!(set_map_mode(DC, MM_ANISOTROPIC as i32), MM_TEXT as i32);
        assert_eq!(get_map_mode(DC), MM_ANISOTROPIC as i32);
        assert_eq!(set_map_mode(DC, 0), 0);
        assert_eq!(set_map_mode(DC, 9), 0);
        assert_eq!(last_error(), 0xF2F2);
        assert_eq!(get_map_mode(DC), MM_ANISOTROPIC as i32);
        assert_eq!(get_map_mode(BAD), 0);
        assert_ne!(last_error(), 0xF2F2);
    }

    /// The capture's `extorg`: MM_TEXT leaves the extents (TRUE, the previous ones written); a
    /// zero window extent is FALSE, a zero viewport extent TRUE, neither set.
    #[test]
    fn extents_follow_the_mode() {
        reset();
        let mut previous = Size { cx: -99, cy: -99 };
        // SAFETY: the test's own SIZE.
        unsafe {
            assert_eq!(set_window_ext_ex(DC, 2, 3, &mut previous), 1);
            assert_eq!((previous.cx, previous.cy), (1, 1));
            assert_eq!(host().window_ext, (1, 1));
            set_map_mode(DC, MM_ANISOTROPIC as i32);
            assert_eq!(set_window_ext_ex(DC, 100, 200, &mut previous), 1);
            assert_eq!(set_viewport_ext_ex(DC, 50, -400, core::ptr::null_mut()), 1);
            assert_eq!(set_window_ext_ex(DC, 0, 10, &mut previous), 0);
            assert_eq!((previous.cx, previous.cy), (100, 200));
            assert_eq!(set_viewport_ext_ex(DC, 0, 0, &mut previous), 1);
            assert_eq!((previous.cx, previous.cy), (50, -400));
            let mut got = Size::default();
            assert_eq!(get_viewport_ext_ex(DC, &mut got), 1);
            assert_eq!((got.cx, got.cy), (50, -400));
        }
        assert_eq!(host().window_ext, (100, 200));
        assert_eq!(host().fixes, 0, "MM_ANISOTROPIC needs no adjustment");
        set_map_mode(DC, MM_ISOTROPIC as i32);
        // SAFETY: no SIZE.
        unsafe { set_viewport_ext_ex(DC, 400, -300, core::ptr::null_mut()) };
        assert_eq!(host().fixes, 1, "MM_ISOTROPIC's is the kernel's");
        assert_eq!(last_error(), 0xF2F2);
    }

    /// The capture's `offset`: each offset answers the origin it moved from.
    #[test]
    fn offsets_answer_the_previous_origin() {
        reset();
        let mut previous = Point { x: -99, y: -99 };
        // SAFETY: the test's own POINT.
        unsafe {
            assert_eq!(offset_viewport_org_ex(DC, 3, -2, &mut previous), 1);
            assert_eq!((previous.x, previous.y), (0, 0));
            assert_eq!(offset_viewport_org_ex(DC, 3, -2, &mut previous), 1);
            assert_eq!((previous.x, previous.y), (3, -2));
            assert_eq!(offset_window_org_ex(DC, -5, 6, core::ptr::null_mut()), 1);
            assert_eq!(set_window_org_ex(DC, 1, 1, &mut previous), 1);
            assert_eq!((previous.x, previous.y), (-5, 6));
            let mut origin = Point::default();
            assert_eq!(get_viewport_org_ex(DC, &mut origin), 1);
            assert_eq!((origin.x, origin.y), (6, -4));
            assert_eq!(get_window_org_ex(DC, &mut origin), 1);
            assert_eq!((origin.x, origin.y), (1, 1));
            assert_eq!(offset_window_org_ex(BAD, 1, 1, &mut previous), 0);
        }
    }

    /// LPtoDP and DPtoLP go to the kernel (MM_TEXT's stand-in: the origins); no points is TRUE, a
    /// negative count ERROR_INVALID_PARAMETER.
    #[test]
    fn points_go_through_the_mapping() {
        reset();
        // SAFETY: no POINT.
        unsafe {
            set_window_org_ex(DC, 5, 7, core::ptr::null_mut());
            set_viewport_org_ex(DC, -3, 4, core::ptr::null_mut());
        }
        let mut points = [Point { x: 0, y: 0 }, Point { x: 10, y: 20 }];
        assert_eq!(lp_to_dp(DC, points.as_mut_ptr(), 2), 1);
        assert_eq!(
            (points[0].x, points[0].y, points[1].x, points[1].y),
            (-8, -3, 2, 17)
        );
        assert_eq!(dp_to_lp(DC, points.as_mut_ptr(), 1), 1);
        assert_eq!((points[0].x, points[0].y), (0, 0));
        assert_eq!(lp_to_dp(DC, points.as_mut_ptr(), 0), 1);
        assert_eq!(last_error(), 0xF2F2);
        assert_eq!(lp_to_dp(DC, points.as_mut_ptr(), -1), 0);
        assert_eq!(last_error(), ERROR_INVALID_PARAMETER);
    }

    /// The capture's `savedc`: the levels count up; a level that names none is FALSE with
    /// ERROR_INVALID_PARAMETER; SaveDC of a DC that is none is 0 with no error.
    #[test]
    fn saved_levels() {
        reset();
        assert_eq!(save_dc(DC), 1);
        assert_eq!(save_dc(DC), 2);
        assert_eq!(restore_dc(DC, -1), 1);
        assert_eq!(restore_dc(DC, 1), 1);
        assert_eq!(last_error(), 0xF2F2);
        assert_eq!(restore_dc(DC, -1), 0);
        assert_eq!(last_error(), ERROR_INVALID_PARAMETER);
        LAST_ERROR.with(|error| error.set(0xF2F2));
        assert_eq!(save_dc(DC), 1);
        for level in [5, 0, -2] {
            assert_eq!(restore_dc(DC, level), 0, "level {level}");
        }
        assert_eq!(restore_dc(DC, 1), 1);
        LAST_ERROR.with(|error| error.set(0xF2F2));
        assert_eq!(save_dc(BAD), 0);
        assert_eq!(last_error(), 0xF2F2, "no error");
    }
}
