//! The painting: InvalidateRect, ValidateRect, GetUpdateRect, BeginPaint and EndPaint, each over
//! its win32k service ([`imports`]).
//!
//! The erase: Windows 2000's BeginPaint (and GetUpdateRect, asked to erase) sends WM_ERASEBKGND
//! itself. win32k cannot send it (it calls no user-mode code), so its services report the pending
//! erase and user32 sends the message here, with a DC of the window: PAINTSTRUCT's fErase then
//! says whether the procedure left the erase undone (it answered 0).

use rtl::gdi::Rect;
use rtl::user::{PaintStruct, UPDATE_ERASE, UPDATE_NOT_EMPTY, WM_ERASEBKGND};

use crate::imports;
use crate::{answered, message, Out};

/// InvalidateRect: the rectangle (client coordinates; NULL: the whole client area) added to the
/// window's update region, its background to be erased when `erase` says; TRUE, or FALSE with
/// 1400 for a handle naming no window. A null window invalidates every top-level window.
#[unsafe(export_name = "f2k_export_InvalidateRect")]
pub extern "system" fn invalidate_rect(window: usize, rect: *const Rect, erase: u32) -> u32 {
    answered(imports::invalidate_rect(window, rect as usize, erase != 0)).is_some() as u32
}

/// ValidateRect: the rectangle (NULL: all of it) taken out of the window's update region; TRUE,
/// or FALSE with 1400 for a handle naming no window.
#[unsafe(export_name = "f2k_export_ValidateRect")]
pub extern "system" fn validate_rect(window: usize, rect: *const Rect) -> u32 {
    answered(imports::validate_rect(window, rect as usize)).is_some() as u32
}

/// GetUpdateRect: the update region's box into the RECT (zeros for none; the RECT may be NULL);
/// with `erase`, a pending erase carried out (WM_ERASEBKGND sent with a DC of the window). TRUE
/// when the region is not empty; FALSE, with 1400 for a handle naming no window.
#[unsafe(export_name = "f2k_export_GetUpdateRect")]
pub extern "system" fn get_update_rect(window: usize, rect: *mut Rect, erase: u32) -> u32 {
    let Some(bits) = answered(imports::update_rect(window, rect as usize, erase != 0)) else {
        return 0;
    };
    if bits & UPDATE_ERASE != 0 {
        if let Ok(dc) = imports::get_dc(window) {
            let _ = message::send(window, WM_ERASEBKGND, dc, 0);
            let _ = imports::close(dc as usize);
        }
    }
    (bits & UPDATE_NOT_EMPTY != 0) as u32
}

/// BeginPaint: the window prepared for painting, its PAINTSTRUCT filled (the DC, clipped to the
/// update region; fErase; rcPaint, the region's box in client coordinates), the window validated,
/// a pending erase sent; the DC, or NULL with the last error (1400 for a handle naming no window).
///
/// # Safety
///
/// The caller's PAINTSTRUCT to fill, as for the platform's.
#[unsafe(export_name = "f2k_export_BeginPaint")]
pub unsafe extern "system" fn begin_paint(window: usize, paint: *mut PaintStruct) -> usize {
    // SAFETY: the caller's PAINTSTRUCT, or null (which the kernel refuses).
    let paint = unsafe { Out::optional(paint) };
    begin(window, paint)
}

/// BeginPaint's core, over the caller's PAINTSTRUCT (none: a null address, which the service
/// refuses as memory it cannot write).
fn begin(window: usize, mut paint: Option<Out<'_, PaintStruct>>) -> usize {
    let address = paint.as_mut().map_or(0, |paint| paint.as_ptr() as usize);
    answered(imports::begin_paint(window, address)).map_or(0, |()| {
        let Some(mut paint) = paint else {
            return 0;
        };
        let mut filled = paint.get();
        if filled.erase != 0 {
            let erased = message::send(window, WM_ERASEBKGND, filled.hdc, 0).unwrap_or(0);
            filled.erase = (erased == 0) as i32;
            paint.set(filled);
        }
        filled.hdc as usize
    })
}

/// EndPaint: the end of the painting, BeginPaint's DC released; TRUE, or FALSE with the last
/// error (1400 for a handle naming no window, 998 for a PAINTSTRUCT the call cannot read).
#[unsafe(export_name = "f2k_export_EndPaint")]
pub extern "system" fn end_paint(window: usize, paint: *const PaintStruct) -> u32 {
    answered(imports::end_paint(window, paint as usize)).is_some() as u32
}

/// The default window procedure's WM_PAINT: the window validated by painting nothing, BeginPaint
/// and EndPaint over a PAINTSTRUCT of its own.
pub fn validate_by_painting(window: usize) {
    let mut paint = PaintStruct::default();
    if begin(window, Some(Out::from(&mut paint))) != 0 {
        let _ = imports::end_paint(window, &paint as *const PaintStruct as usize);
    }
}

#[cfg(test)]
mod tests {
    use core::cell::RefCell;

    use rtl::user::WM_PAINT;

    use super::*;
    use crate::class::{register_class_a, WndClass};
    use crate::imports::host::{procedure, wm, LAST_ERROR};
    use crate::window::{create_window_ex_a, show_window, update_window};

    std::thread_local! {
        static PAINTS: RefCell<std::vec::Vec<PaintStruct>> = const { RefCell::new(std::vec::Vec::new()) };
        static ERASE_ANSWER: core::cell::Cell<i32> = const { core::cell::Cell::new(1) };
    }

    /// A procedure that paints as the guipaint fixture's does, and answers WM_ERASEBKGND as told.
    fn painter(window: u32, message: u32, wparam: u32, lparam: i32) -> i32 {
        match message {
            WM_PAINT => {
                let mut paint = PaintStruct::default();
                // SAFETY: the test's own PAINTSTRUCT.
                unsafe { begin_paint(window as usize, &mut paint) };
                end_paint(window as usize, &paint);
                PAINTS.with(|paints| paints.borrow_mut().push(paint));
                0
            }
            WM_ERASEBKGND => ERASE_ANSWER.with(|answer| answer.get()),
            _ => crate::message::def_window_proc_a(window as usize, message, wparam, lparam),
        }
    }

    fn window(visible: bool) -> usize {
        let class = WndClass {
            wnd_proc: procedure(painter) as usize,
            class_name: c"F2KGuipaint".as_ptr() as usize,
            ..WndClass::default()
        };
        // SAFETY: a WNDCLASSA of the tests' own, and its name.
        let window = unsafe {
            register_class_a(&class);
            create_window_ex_a(
                0,
                c"F2KGuipaint".as_ptr().cast(),
                core::ptr::null(),
                0x8000_0000,
                0,
                0,
                320,
                200,
                0,
                0,
                0,
                0,
            )
        };
        if visible {
            show_window(window, 5);
        }
        window
    }

    /// A shown window's invalidation: GetUpdateRect reads the box, ValidateRect empties it; a
    /// hidden window has none.
    ///
    /// Pins: user32.InvalidateRect, user32.ValidateRect, user32.GetUpdateRect
    #[test]
    fn invalidation_and_validation() {
        let hidden = window(false);
        let mut rect = Rect::default();
        assert_eq!(invalidate_rect(hidden, core::ptr::null(), 1), 1);
        assert_eq!(get_update_rect(hidden, &mut rect, 0), 0);
        let shown = window(true);
        let sub = Rect {
            left: 10,
            top: 10,
            right: 50,
            bottom: 40,
        };
        assert_eq!(invalidate_rect(shown, &sub, 0), 1);
        assert_eq!(get_update_rect(shown, &mut rect, 0), 1);
        assert_eq!(rect, sub);
        assert_eq!(validate_rect(shown, core::ptr::null()), 1);
        assert_eq!(get_update_rect(shown, core::ptr::null_mut(), 0), 0);
        for answer in [
            invalidate_rect(0x7FFF_FFFC, core::ptr::null(), 1),
            get_update_rect(0x7FFF_FFFC, &mut rect, 0),
        ] {
            assert_eq!(answer, 0);
            assert_eq!(LAST_ERROR.with(|error| error.get()), 1400);
        }
    }

    /// UpdateWindow sends WM_PAINT once: BeginPaint's PAINTSTRUCT has the DC, rcPaint the client
    /// area, and fErase 0 after the procedure erased; a second UpdateWindow sends nothing.
    ///
    /// Pins: user32.UpdateWindow, user32.BeginPaint, user32.EndPaint
    #[test]
    fn update_window_paints_once() {
        let window = window(true);
        invalidate_rect(window, core::ptr::null(), 1);
        assert_eq!(update_window(window), 1);
        assert_eq!(update_window(window), 1);
        let paints = PAINTS.with(|paints| paints.take());
        assert_eq!(paints.len(), 1);
        assert_ne!(paints[0].hdc, 0);
        assert_eq!(paints[0].erase, 0);
        assert_eq!(
            paints[0].paint,
            Rect {
                left: 0,
                top: 0,
                right: 320,
                bottom: 200
            }
        );
        assert!(wm(|wm| wm.dcs.is_empty()), "EndPaint released the DC");
    }

    /// A procedure that leaves the erase undone leaves fErase set.
    ///
    /// Pins: user32.BeginPaint
    #[test]
    fn an_erase_left_undone_stays_pending() {
        let window = window(true);
        invalidate_rect(window, core::ptr::null(), 1);
        ERASE_ANSWER.with(|answer| answer.set(0));
        let mut paint = PaintStruct::default();
        // SAFETY: the test's own PAINTSTRUCT.
        assert_ne!(unsafe { begin_paint(window, &mut paint) }, 0);
        assert_eq!(paint.erase, 1);
        assert_eq!(end_paint(window, &paint), 1);
    }

    /// A bogus window is 1400 for BeginPaint, a null PAINTSTRUCT 998 for EndPaint.
    ///
    /// Pins: user32.BeginPaint, user32.EndPaint
    #[test]
    fn paint_errors() {
        let window = window(false);
        let mut paint = PaintStruct::default();
        // SAFETY: the test's own PAINTSTRUCT.
        assert_eq!(unsafe { begin_paint(0x7FFF_FFFC, &mut paint) }, 0);
        assert_eq!(LAST_ERROR.with(|error| error.get()), 1400);
        assert_eq!(end_paint(window, core::ptr::null()), 0);
        assert_eq!(LAST_ERROR.with(|error| error.get()), 998);
    }
}
