//! The mouse: the capture (SetCapture, GetCapture, ReleaseCapture), the cursor's place and shape
//! (GetCursorPos, SetCursorPos, SetCursor, GetCursor), each over its win32k service
//! ([`imports`]), and the default window procedure's mouse messages (WM_SETCURSOR,
//! WM_MOUSEACTIVATE, WM_CANCELMODE's release of the capture).
//!
//! The mouse's events reach the windows through win32k ([`crate::keyboard`]'s SendInput), which
//! posts the mouse messages, asks the window where the point is (WM_NCHITTEST) as the thread reads
//! them, and sends WM_MOUSEACTIVATE and WM_SETCURSOR before the thread has them, as Windows 2000's
//! queue does. Nothing draws the cursor yet: its shape is kept for GetCursor.

use rtl::nonclient::{
    HTBOTTOM,
    HTBOTTOMLEFT,
    HTBOTTOMRIGHT,
    HTCLIENT,
    HTLEFT,
    HTRIGHT,
    HTTOP,
    HTTOPLEFT,
    HTTOPRIGHT,
};
use rtl::user::*;
use rtl::window::GCL_HCURSOR;

use crate::{answered, class, imports, message, window, Out};

/// The stock cursors the default procedure sets (winuser.h's IDC_* ids).
const IDC_ARROW: u16 = 32512;
const IDC_SIZENWSE: u16 = 32642;
const IDC_SIZENESW: u16 = 32643;
const IDC_SIZEWE: u16 = 32644;
const IDC_SIZENS: u16 = 32645;

// --- The capture ---------------------------------------------------------------------------------

/// SetCapture: the mouse's messages all to `window`, a window of the calling thread's, wherever
/// the cursor is; the window that had the capture (NULL for none). The window that loses it is
/// sent WM_CAPTURECHANGED, lParam `window`, before the call returns (the mousein capture). NULL for
/// another thread's window; NULL with 1400 for a handle naming no window.
#[unsafe(export_name = "f2k_export_SetCapture")]
pub extern "system" fn set_capture(window: usize) -> usize {
    answered(imports::set_capture(window)).unwrap_or(0) as usize
}

/// GetCapture: the calling thread's capture window, NULL for none.
#[unsafe(export_name = "f2k_export_GetCapture")]
pub extern "system" fn get_capture() -> usize {
    imports::thread_state(THREAD_STATE_CAPTURE_WINDOW).unwrap_or(0) as usize
}

/// ReleaseCapture: the calling thread's capture taken from its window, which is sent
/// WM_CAPTURECHANGED, lParam NULL; TRUE, with the capture or without (the mousein capture).
#[unsafe(export_name = "f2k_export_ReleaseCapture")]
pub extern "system" fn release_capture() -> u32 {
    answered(imports::call_no_param(NO_PARAM_RELEASE_CAPTURE)).is_some() as u32
}

// --- The cursor ----------------------------------------------------------------------------------

/// GetCursorPos: the cursor's place on the screen into the caller's POINT; TRUE.
///
/// # Safety
///
/// The caller's POINT, as for the platform's.
#[unsafe(export_name = "f2k_export_GetCursorPos")]
pub unsafe extern "system" fn get_cursor_pos(point: *mut Point) -> u32 {
    let Some(at) = answered(imports::thread_state(THREAD_STATE_CURSOR_POS)) else {
        return 0;
    };
    let place = Point {
        x: i32::from(at as u16 as i16),
        y: i32::from((at >> 16) as u16 as i16),
    };
    // SAFETY: the caller's POINT.
    unsafe { Out::new(point) }.set(place);
    1
}

/// SetCursorPos: the cursor to the screen point (`x`, `y`), kept on the screen, and the window
/// under it sent a mouse move as for any of the mouse's (only the mouse's own events count as its
/// moves: the next one to this place still posts one); TRUE.
#[unsafe(export_name = "f2k_export_SetCursorPos")]
pub extern "system" fn set_cursor_pos(x: i32, y: i32) -> u32 {
    answered(imports::call_two_param(
        x as u32,
        y as u32,
        TWO_PARAM_SET_CURSOR_POS,
    ))
    .is_some() as u32
}

/// SetCursor: the cursor's shape (NULL for none); the shape it replaces. Nothing draws it yet.
#[unsafe(export_name = "f2k_export_SetCursor")]
pub extern "system" fn set_cursor(cursor: usize) -> usize {
    answered(imports::set_cursor(cursor)).unwrap_or(0) as usize
}

/// ShowCursor: the calling thread's display count one up (`show`) or one down, the new count
/// answered; the cursor shows while it is 0 or more (nothing draws it yet). The count starts at
/// -1, F2K's machine having no mouse (SM_MOUSEPRESENT 0), as Windows 2000 starts it then.
#[unsafe(export_name = "f2k_export_ShowCursor")]
pub extern "system" fn show_cursor(show: u32) -> i32 {
    imports::call_one_param((show != 0) as u32, ONE_PARAM_SHOW_CURSOR).unwrap_or(0) as i32
}

/// GetCursor: the cursor's shape, as SetCursor set it.
#[unsafe(export_name = "f2k_export_GetCursor")]
pub extern "system" fn get_cursor() -> usize {
    imports::thread_state(THREAD_STATE_CURSOR).unwrap_or(0) as usize
}

// --- The default procedure's messages ------------------------------------------------------------

/// The window's parent, when it is a child window.
fn child_parent(window: usize) -> Option<usize> {
    if window::style_of(window).unwrap_or(0) & WS_CHILD == 0 {
        return None;
    }
    window::links(window)
        .ok()
        .map(|links| links.parent as usize)
        .filter(|&parent| parent != 0)
}

/// The stock cursor `id`.
fn stock(id: u16) -> usize {
    class::load_cursor_w(0, id as usize as *const u16)
}

/// DefWindowProc's WM_SETCURSOR, as Windows 2000's: a child asks its parent first, and stops when
/// the parent answers TRUE; then the cursor the hit-test code (lParam's low word) calls for is set:
/// the class's cursor in the client area (none set for a class without one), a sizing border's
/// arrows on the borders, the arrow elsewhere. FALSE: the window's children may set their own.
pub fn set_cursor_default(window: usize, wparam: u32, lparam: i32) -> i32 {
    if let Some(parent) = child_parent(window) {
        if message::send(parent, WM_SETCURSOR, wparam, lparam).unwrap_or(0) != 0 {
            return 1;
        }
    }
    let cursor = match lparam as u32 & 0xFFFF {
        HTCLIENT => class::get_class_long_w(window, GCL_HCURSOR) as usize,
        HTLEFT | HTRIGHT => stock(IDC_SIZEWE),
        HTTOP | HTBOTTOM => stock(IDC_SIZENS),
        HTTOPLEFT | HTBOTTOMRIGHT => stock(IDC_SIZENWSE),
        HTTOPRIGHT | HTBOTTOMLEFT => stock(IDC_SIZENESW),
        _ => stock(IDC_ARROW),
    };
    if cursor != 0 {
        set_cursor(cursor);
    }
    0
}

/// DefWindowProc's WM_MOUSEACTIVATE: a child hands it to its parent, whose nonzero answer is its
/// own; MA_ACTIVATE otherwise. (Windows 2000's answers MA_NOACTIVATE for a press on the caption,
/// its move loop activating the window; F2K has no move loop yet, and activates at the press.)
pub fn mouse_activate_default(window: usize, wparam: u32, lparam: i32) -> i32 {
    if let Some(parent) = child_parent(window) {
        let answer = message::send(parent, WM_MOUSEACTIVATE, wparam, lparam).unwrap_or(0);
        if answer != 0 {
            return answer;
        }
    }
    MA_ACTIVATE as i32
}

/// DefWindowProc's WM_CANCELMODE, its capture part: the capture released when the window has it.
pub fn cancel_capture(window: usize) {
    if window != 0 && get_capture() == window {
        release_capture();
    }
}
