//! The caret: CreateCaret, DestroyCaret, ShowCaret, HideCaret, SetCaretPos, GetCaretPos and
//! GetGUIThreadInfo, each over its win32k service ([`imports`]), which keeps the thread's one
//! caret in its queue's state, blinks it and draws it (see the kernel's caret notes).
//!
//! The services answer the caret capture's errors as statuses this side maps back: a handle naming
//! no window is ERROR_INVALID_WINDOW_HANDLE, a thread with no caret ERROR_ACCESS_DENIED (the
//! kernel's STATUS_ACCESS_DENIED); a window of another thread (CreateCaret) or one that is not the
//! caret's (ShowCaret, HideCaret) is refused with the last error untouched. As Windows 2000's
//! DestroyCaret and SetCaretPos reach win32k through NtUserCallNoParam and NtUserCallTwoParam,
//! so do F2K's, by rtl::user's routine numbers.

use rtl::edge::{In, Out};
use rtl::user::{GuiThreadInfo, Point, NO_PARAM_DESTROY_CARET, TWO_PARAM_SET_CARET_POS};

use crate::{answered, failed, imports, spec, ERROR_INVALID_PARAMETER};

/// CreateCaret's bitmap that asks for a gray caret ((HBITMAP)1); 0 asks for a solid one.
const GRAY_CARET: usize = 1;

/// CreateCaret: the calling thread's caret made for `window`, `width` by `height` (the border's
/// size for 0), solid or gray, hidden, in place of the one it had; TRUE, FALSE with 1400 for a
/// handle naming no window (null included), FALSE with the last error untouched for another
/// thread's window. A caret from a bitmap goes to the stub routine: F2K has no bitmaps to draw.
#[unsafe(export_name = "f2k_export_CreateCaret")]
pub extern "system" fn create_caret(window: usize, bitmap: usize, width: i32, height: i32) -> u32 {
    if bitmap > GRAY_CARET {
        let args = [window as u64, bitmap as u64, width as u64, height as u64];
        // SAFETY: the arguments as CreateCaret's kinds read them: handles and numbers.
        return unsafe {
            crate::stub::stubbed(
                &spec::CreateCaret,
                "a caret from a bitmap not yet implemented",
                &args,
            )
        };
    }
    answered(imports::create_caret(
        window,
        bitmap == GRAY_CARET,
        width,
        height,
    ))
    .is_some_and(|made| made) as u32
}

/// DestroyCaret: the calling thread's caret destroyed (taken off the screen); TRUE, FALSE with
/// ERROR_ACCESS_DENIED when it has none.
#[unsafe(export_name = "f2k_export_DestroyCaret")]
pub extern "system" fn destroy_caret() -> u32 {
    answered(imports::call_no_param(NO_PARAM_DESTROY_CARET)).is_some() as u32
}

/// ShowCaret: the caret of `window` (NULL: of whatever window it is in) one step nearer showing
/// (it shows once each HideCaret is undone, and stays shown); see [`show_or_hide`].
#[unsafe(export_name = "f2k_export_ShowCaret")]
pub extern "system" fn show_caret(window: usize) -> u32 {
    show_or_hide(window, true)
}

/// HideCaret: the caret of `window` (NULL: of whatever window it is in) hidden once more; see
/// [`show_or_hide`].
#[unsafe(export_name = "f2k_export_HideCaret")]
pub extern "system" fn hide_caret(window: usize) -> u32 {
    show_or_hide(window, false)
}

/// ShowCaret's and HideCaret's core: TRUE; FALSE with ERROR_ACCESS_DENIED when the thread has no
/// caret, with 1400 for a handle naming no window, with the last error untouched for a window
/// that is not the caret's.
pub fn show_or_hide(window: usize, show: bool) -> u32 {
    answered(imports::show_caret(window, show)).is_some_and(|done| done) as u32
}

/// SetCaretPos: the calling thread's caret moved to (`x`, `y`), in its window's client
/// coordinates; TRUE, FALSE with ERROR_ACCESS_DENIED when it has no caret.
#[unsafe(export_name = "f2k_export_SetCaretPos")]
pub extern "system" fn set_caret_pos(x: i32, y: i32) -> u32 {
    answered(imports::call_two_param(
        x as u32,
        y as u32,
        TWO_PARAM_SET_CARET_POS,
    ))
    .is_some() as u32
}

/// GetCaretPos: the calling thread's caret place into the caller's POINT (the last caret's when it
/// has none now: the place is the thread's); TRUE.
///
/// # Safety
///
/// The caller's POINT, as for the platform's.
#[unsafe(export_name = "f2k_export_GetCaretPos")]
pub unsafe extern "system" fn get_caret_pos(point: *mut Point) -> u32 {
    let Some(place) = answered(imports::caret_pos()) else {
        return 0;
    };
    // SAFETY: the caller's POINT.
    unsafe { Out::new(point) }.set(place);
    1
}

/// GetGUIThreadInfo: the input state of the thread `thread` (its id; 0 for the foreground thread)
/// into the caller's GUITHREADINFO: its active, focus and capture windows, its caret's window and
/// rectangle, GUI_CARETBLINKING while the caret shows; TRUE. FALSE with ERROR_INVALID_PARAMETER
/// for a structure whose cbSize is not its size, or a thread id naming no GUI thread.
///
/// # Safety
///
/// The caller's GUITHREADINFO, as for the platform's.
#[unsafe(export_name = "f2k_export_GetGUIThreadInfo")]
pub unsafe extern "system" fn get_gui_thread_info(thread: u32, info: *mut GuiThreadInfo) -> u32 {
    // SAFETY: the caller's structure, its size read first.
    let size = unsafe { In::new(info as *const u32) }.read();
    if size as usize != core::mem::size_of::<GuiThreadInfo>() {
        return failed::<()>(ERROR_INVALID_PARAMETER).is_some() as u32;
    }
    let Some(answer) = answered(imports::gui_thread_info(thread)) else {
        return 0;
    };
    // SAFETY: the caller's structure, as above.
    unsafe { Out::new(info) }.set(answer);
    1
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::imports::host::{CARET, LAST_ERROR};

    fn last_error() -> u32 {
        LAST_ERROR.with(|error| error.get())
    }

    /// With no caret, DestroyCaret, SetCaretPos, ShowCaret and HideCaret fail with
    /// ERROR_ACCESS_DENIED, and GetCaretPos answers the thread's place.
    #[test]
    fn no_caret_is_access_denied() {
        assert_eq!(destroy_caret(), 0);
        assert_eq!(last_error(), 5);
        assert_eq!(set_caret_pos(1, 1), 0);
        assert_eq!(show_caret(0), 0);
        assert_eq!(hide_caret(0), 0);
        assert_eq!(last_error(), 5);
        let mut point = Point { x: -7, y: -7 };
        // SAFETY: a local POINT.
        assert_eq!(unsafe { get_caret_pos(&mut point) }, 1);
        assert_eq!(point, Point { x: 0, y: 0 });
    }

    /// CreateCaret of no window is 1400; a bitmap other than the gray one is the stub's.
    #[test]
    fn create_refuses_no_window_and_bitmaps() {
        assert_eq!(create_caret(0, 0, 2, 16), 0);
        assert_eq!(last_error(), 1400);
        assert_eq!(create_caret(0, 0x1234, 2, 16), 0);
        assert_eq!(last_error(), 120);
        assert_eq!(CARET.with(|caret| caret.get()).window, 0);
    }

    /// GetGUIThreadInfo refuses a structure of the wrong size with ERROR_INVALID_PARAMETER and
    /// answers the caret it has.
    #[test]
    fn gui_thread_info_checks_its_size() {
        let mut info = GuiThreadInfo {
            cb_size: 40,
            ..GuiThreadInfo::default()
        };
        // SAFETY: a local structure.
        assert_eq!(unsafe { get_gui_thread_info(0, &mut info) }, 0);
        assert_eq!(last_error(), ERROR_INVALID_PARAMETER);
        info.cb_size = 48;
        // SAFETY: as above.
        assert_eq!(unsafe { get_gui_thread_info(0, &mut info) }, 1);
        assert_eq!((info.hwnd_caret, info.flags), (0, 0));
    }
}
