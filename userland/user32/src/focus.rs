//! The focus, enabling and activation: SetFocus and GetFocus, SetActiveWindow and
//! GetActiveWindow, SetForegroundWindow and GetForegroundWindow, EnableWindow and IsWindowEnabled,
//! each over its win32k service ([`imports`]), and the default window procedure's WM_ACTIVATE
//! ([`activate_focus`]).
//!
//! The messages these calls make the window manager send (WM_SETFOCUS and WM_KILLFOCUS,
//! WM_NCACTIVATE, WM_ACTIVATE and WM_ACTIVATEAPP, WM_CANCELMODE and WM_ENABLE) are queued for the
//! window's thread: each call here that can send them receives them once its service returns
//! ([`message::receive_sent`]), so a program sees its procedure called before the call returns,
//! as on Windows 2000. GetFocus and GetActiveWindow read the calling thread's state through
//! NtUserGetThreadState, as Windows 2000's do; IsWindowEnabled reads the window's style, which
//! Windows 2000's user32 reads from the window manager's records mapped into its process, through
//! NtUserQueryWindow.

use rtl::user::{
    HWND_LOCK_ACTIVATE_FOCUS,
    HWND_LOCK_SET_FOREGROUND_WINDOW,
    HWND_PARAM_LOCK_ENABLE_WINDOW,
    THREAD_STATE_ACTIVE_WINDOW,
    THREAD_STATE_FOCUS_WINDOW,
};
use rtl::window::{WindowInfo, QUERY_WINDOW_INFO};

use crate::{answered, imports, message};

/// WS_DISABLED (winuser.h).
const WS_DISABLED: u32 = 0x0800_0000;

/// SetFocus: the keyboard focus to the window (NULL: to no window), the messages it sent received;
/// the window that had the focus, NULL for a window refused (a disabled one, one with a disabled
/// ancestor, another thread's) or with the last error (1400 for a handle naming no window).
#[unsafe(export_name = "f2k_export_SetFocus")]
pub extern "system" fn set_focus(window: usize) -> usize {
    let answer = imports::set_focus(window);
    message::receive_sent();
    answered(answer).unwrap_or(0) as usize
}

/// GetFocus: the calling thread's focus window, NULL for none.
#[unsafe(export_name = "f2k_export_GetFocus")]
pub extern "system" fn get_focus() -> usize {
    answered(imports::thread_state(THREAD_STATE_FOCUS_WINDOW)).unwrap_or(0) as usize
}

/// SetActiveWindow: the top-level window activated, the messages it sent received; the window that
/// was active, NULL for another thread's window or with the last error (1400 for a handle naming
/// no window). A child window activates nothing.
#[unsafe(export_name = "f2k_export_SetActiveWindow")]
pub extern "system" fn set_active_window(window: usize) -> usize {
    let answer = imports::set_active_window(window);
    message::receive_sent();
    answered(answer).unwrap_or(0) as usize
}

/// GetActiveWindow: the calling thread's active window, NULL for none.
#[unsafe(export_name = "f2k_export_GetActiveWindow")]
pub extern "system" fn get_active_window() -> usize {
    answered(imports::thread_state(THREAD_STATE_ACTIVE_WINDOW)).unwrap_or(0) as usize
}

/// GetForegroundWindow: the foreground thread's active window, NULL for none.
#[unsafe(export_name = "f2k_export_GetForegroundWindow")]
pub extern "system" fn get_foreground_window() -> usize {
    answered(imports::foreground_window()).unwrap_or(0) as usize
}

/// SetForegroundWindow: the window's thread made the foreground one and the window activated, the
/// messages it sent received; TRUE, or FALSE with the last error (1400 for a handle naming no
/// window, 5 when the caller may not take the foreground).
#[unsafe(export_name = "f2k_export_SetForegroundWindow")]
pub extern "system" fn set_foreground_window(window: usize) -> u32 {
    let answer = imports::call_hwnd_lock(window, HWND_LOCK_SET_FOREGROUND_WINDOW);
    message::receive_sent();
    answered(answer).is_some() as u32
}

/// EnableWindow: the window enabled or disabled, the messages it sent received; nonzero when it was
/// disabled before (the kernel's answer, the style's state byte's bit), 0 when it was not or with
/// the last error (1400 for a handle naming no window).
#[unsafe(export_name = "f2k_export_EnableWindow")]
pub extern "system" fn enable_window(window: usize, enable: u32) -> u32 {
    let answer =
        imports::call_hwnd_param_lock(window, (enable != 0) as u32, HWND_PARAM_LOCK_ENABLE_WINDOW);
    message::receive_sent();
    answered(answer).unwrap_or(0)
}

/// IsWindowEnabled: whether the window's style lacks WS_DISABLED; FALSE with 1400 for a handle
/// naming no window.
#[unsafe(export_name = "f2k_export_IsWindowEnabled")]
pub extern "system" fn is_window_enabled(window: usize) -> u32 {
    let mut info = WindowInfo {
        size: core::mem::size_of::<WindowInfo>() as u32,
        ..WindowInfo::default()
    };
    answered(imports::query_window(window, QUERY_WINDOW_INFO, &mut info))
        .is_some_and(|()| info.style & WS_DISABLED == 0) as u32
}

/// The default window procedure's WM_ACTIVATE for a window being activated (not minimized): the
/// focus to it, the messages that sends received.
pub fn activate_focus(window: usize) {
    let _ = imports::call_hwnd_lock(window, HWND_LOCK_ACTIVATE_FOCUS);
    message::receive_sent();
}

#[cfg(test)]
mod tests {
    use core::cell::RefCell;

    use rtl::user::{
        WA_ACTIVE,
        WA_INACTIVE,
        WM_ACTIVATE,
        WM_CANCELMODE,
        WM_ENABLE,
        WM_KILLFOCUS,
        WM_NCACTIVATE,
        WM_SETFOCUS,
    };

    use super::*;
    use crate::class::{register_class_a, WndClass};
    use crate::imports::host::{procedure, LAST_ERROR};
    use crate::message::def_window_proc_a;
    use crate::window::{create_window_ex_a, destroy_window};

    const UNSET: u32 = 0xF2F2_F2F2;

    std::thread_local! {
        static SEEN: RefCell<std::vec::Vec<(u32, u32, u32)>> = const { RefCell::new(std::vec::Vec::new()) };
    }

    /// The fixture's procedure: the focus and activation messages recorded, every message handed
    /// to DefWindowProc.
    fn recorder(window: u32, message: u32, wparam: u32, lparam: i32) -> i32 {
        if matches!(
            message,
            WM_SETFOCUS | WM_KILLFOCUS | WM_ENABLE | WM_ACTIVATE | WM_NCACTIVATE | WM_CANCELMODE
        ) {
            SEEN.with(|seen| seen.borrow_mut().push((window, message, wparam)));
        }
        def_window_proc_a(window as usize, message, wparam, lparam)
    }

    fn seen() -> std::vec::Vec<(u32, u32, u32)> {
        SEEN.with(|seen| seen.take())
    }

    fn last_error() -> u32 {
        LAST_ERROR.with(|error| error.get())
    }

    fn arm() {
        LAST_ERROR.with(|error| error.set(UNSET));
    }

    /// Two visible popups of a class of the recorder, their creations' messages forgotten.
    fn windows() -> (usize, usize) {
        let class = WndClass {
            wnd_proc: procedure(recorder) as usize,
            class_name: c"F2KFocusWin".as_ptr() as usize,
            ..WndClass::default()
        };
        let make = || {
            // SAFETY: the tests' own NUL-terminated names.
            unsafe {
                create_window_ex_a(
                    0,
                    c"F2KFocusWin".as_ptr().cast(),
                    c"focus".as_ptr().cast(),
                    0x9000_0000,
                    0,
                    0,
                    200,
                    120,
                    0,
                    0,
                    0,
                    0,
                )
            }
        };
        // SAFETY: a WNDCLASSA of the tests' own.
        unsafe { register_class_a(&class) };
        let windows = (make(), make());
        seen();
        windows
    }

    /// SetFocus answers the window that had the focus, and its procedures see WM_KILLFOCUS and
    /// WM_SETFOCUS before it returns; GetFocus reads it back; a dead handle is 1400.
    ///
    /// Pins: user32.SetFocus, user32.GetFocus
    #[test]
    fn the_focus_moves_with_its_messages() {
        let (a, b) = windows();
        assert_eq!(set_focus(a), 0);
        assert_eq!(seen(), [(a as u32, WM_SETFOCUS, 0)]);
        assert_eq!(set_focus(b), a);
        assert_eq!(
            seen(),
            [
                (a as u32, WM_KILLFOCUS, b as u32),
                (b as u32, WM_SETFOCUS, a as u32)
            ]
        );
        assert_eq!(get_focus(), b);
        assert_eq!(set_focus(0), b);
        assert_eq!(get_focus(), 0);
        arm();
        assert_eq!(set_focus(0x7FFF_FFFC), 0);
        assert_eq!(last_error(), 1400);
    }

    /// SetActiveWindow's activation reaches the procedures, whose DefWindowProc gives the window
    /// activated the focus; the active and foreground windows read back.
    ///
    /// Pins: user32.SetActiveWindow, user32.GetActiveWindow, user32.GetForegroundWindow,
    /// user32.SetForegroundWindow, user32.DefWindowProcA
    #[test]
    fn activation_gives_the_focus_through_the_default_procedure() {
        let (a, b) = windows();
        assert_eq!(set_foreground_window(a), 1);
        assert_eq!((get_active_window(), get_foreground_window()), (a, a));
        assert_eq!(get_focus(), a);
        seen();
        assert_eq!(set_active_window(b), a);
        assert_eq!(
            seen(),
            [
                (a as u32, WM_NCACTIVATE, 0),
                (a as u32, WM_ACTIVATE, WA_INACTIVE),
                (b as u32, WM_NCACTIVATE, 1),
                (b as u32, WM_ACTIVATE, WA_ACTIVE),
                (a as u32, WM_KILLFOCUS, b as u32),
                (b as u32, WM_SETFOCUS, a as u32),
            ]
        );
        assert_eq!((get_active_window(), get_focus()), (b, b));
        assert_eq!(destroy_window(b), 1);
    }

    /// EnableWindow answers the former state's bit and sends what the capture shows; disabling the
    /// focus window takes the focus; IsWindowEnabled reads the style; a dead handle is 1400.
    ///
    /// Pins: user32.EnableWindow, user32.IsWindowEnabled
    #[test]
    fn enabling_and_disabling() {
        let (a, _) = windows();
        set_focus(a);
        seen();
        assert_eq!(is_window_enabled(a), 1);
        assert_eq!(enable_window(a, 0), 0);
        assert_eq!(
            seen(),
            [
                (a as u32, WM_CANCELMODE, 0),
                (a as u32, WM_KILLFOCUS, 0),
                (a as u32, WM_ENABLE, 0)
            ]
        );
        assert_eq!((is_window_enabled(a), get_focus()), (0, 0));
        assert_eq!(enable_window(a, 1), 8);
        assert_eq!(seen(), [(a as u32, WM_ENABLE, 1)]);
        arm();
        assert_eq!(enable_window(0x7FFF_FFFC, 0), 0);
        assert_eq!(last_error(), 1400);
        arm();
        assert_eq!(is_window_enabled(0x7FFF_FFFC), 0);
        assert_eq!(last_error(), 1400);
    }
}
