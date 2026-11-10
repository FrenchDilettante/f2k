//! The window manager's shared shapes: what win32k's window services and user32's window calls
//! agree on. WINDOWINFO and WINDOWPOS as Windows 2000's winuser.h lays them out on x86
//! ([`WindowInfo`], [`WindowPos`]), the GetWindowLong/SetWindowLong indexes (winuser.h's GWL_*),
//! and the answers NtUserQueryWindow gives (F2K's own indexes: Windows 2000's user32 reads a
//! window's state from the window manager's records, mapped into every GUI process, where F2K's
//! asks the kernel).

use core::mem::{offset_of, size_of};

use crate::gdi::Rect;
use crate::pod::Pod;

/// NtUserQueryWindow's indexes: what it answers about a window.
///
/// The window's state as GetWindowInfo describes it, a [`WindowInfo`] (its rectangles in screen
/// coordinates: GetWindowRect's answer is its `window`).
pub const QUERY_WINDOW_INFO: u32 = 0;
/// Whether the window and every window above it have WS_VISIBLE (IsWindowVisible's answer), a
/// 32-bit boolean.
pub const QUERY_WINDOW_VISIBLE: u32 = 1;

/// The window's data as GetWindowLong reads it, a [`WindowData`].
pub const QUERY_WINDOW_DATA: u32 = 2;
/// The window's text (its title) as DefWindowProc reads it, a [`WindowText`].
pub const QUERY_WINDOW_TEXT: u32 = 3;
/// The window's extra bytes (its class's cbWndExtra) at the offset this index carries in its low
/// bits (`QUERY_WINDOW_EXTRA | offset`): as many as the answer's length asks, 2 (a WORD) or 4 (a
/// LONG). An offset whose bytes are not all inside the extra bytes is refused.
pub const QUERY_WINDOW_EXTRA: u32 = 0x8000_0000;

/// The GetWindowLong and SetWindowLong indexes of a window's own fields (winuser.h's GWL_*); an
/// index of 0 or more is an offset into the window's extra bytes.
pub const GWL_WNDPROC: i32 = -4;
pub const GWL_HINSTANCE: i32 = -6;
pub const GWL_HWNDPARENT: i32 = -8;
pub const GWL_ID: i32 = -12;
pub const GWL_STYLE: i32 = -16;
pub const GWL_EXSTYLE: i32 = -20;
pub const GWL_USERDATA: i32 = -21;

/// [`WindowData`]'s flags: the window procedure takes the narrow forms of the messages
/// (IsWindowUnicode's FALSE); the window belongs to a process other than the caller's.
pub const WINDOW_ANSI_PROC: u32 = 0x1;
pub const WINDOW_OTHER_PROCESS: u32 = 0x2;

/// The longest window text the window manager holds, in UTF-16 units (no terminator).
pub const WINDOW_TEXT_UNITS: usize = 128;

/// WINDOWINFO's dwWindowStatus: the window is its thread's active window.
pub const WS_ACTIVECAPTION: u32 = 0x0001;

/// WINDOWINFO (60 bytes): a window's rectangles, styles and status, as GetWindowInfo answers them.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WindowInfo {
    /// cbSize.
    pub size: u32,
    /// rcWindow: the window's rectangle, in screen coordinates.
    pub window: Rect,
    /// rcClient: the client area's rectangle, in screen coordinates.
    pub client: Rect,
    pub style: u32,
    pub ex_style: u32,
    /// dwWindowStatus: [`WS_ACTIVECAPTION`] or 0.
    pub status: u32,
    pub cx_window_borders: u32,
    pub cy_window_borders: u32,
    /// atomWindowType: the window's class atom.
    pub atom_window_type: u16,
    /// wCreatorVersion: the Windows version the window's creator expects.
    pub creator_version: u16,
}

/// WINDOWPOS (28 bytes): a window's new place, as WM_WINDOWPOSCHANGING and WM_WINDOWPOSCHANGED
/// carry it (their lParam points at one).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WindowPos {
    pub hwnd: u32,
    /// hwndInsertAfter: the window it goes after, or HWND_TOP, HWND_BOTTOM, HWND_TOPMOST,
    /// HWND_NOTOPMOST.
    pub insert_after: u32,
    /// The position, in the parent's client coordinates for a child window, in screen coordinates
    /// otherwise.
    pub x: i32,
    pub y: i32,
    pub cx: i32,
    pub cy: i32,
    /// The SWP_ flags.
    pub flags: u32,
}

/// A window's own fields as GetWindowLong answers them ([`QUERY_WINDOW_DATA`]).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WindowData {
    pub style: u32,
    pub ex_style: u32,
    /// GWL_ID: a child window's id, another window's menu handle (0 for none).
    pub id: u32,
    pub user_data: u32,
    /// GWL_HINSTANCE: the module the window was created with.
    pub instance: u32,
    /// GWL_HWNDPARENT: a child window's parent, another window's owner (0 for none).
    pub parent: u32,
    /// The window procedure's address; 0 for the window manager's own (the default procedure).
    pub proc: u32,
    /// [`WINDOW_ANSI_PROC`], [`WINDOW_OTHER_PROCESS`].
    pub flags: u32,
    /// How many extra bytes the window has (its class's cbWndExtra).
    pub extra: u32,
}

/// A window's text ([`QUERY_WINDOW_TEXT`]): its first `length` units, no terminator.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WindowText {
    pub length: u32,
    pub units: [u16; WINDOW_TEXT_UNITS],
}

impl Default for WindowText {
    fn default() -> Self {
        WindowText {
            length: 0,
            units: [0; WINDOW_TEXT_UNITS],
        }
    }
}

impl WindowText {
    /// The text's units.
    pub fn as_slice(&self) -> &[u16] {
        &self.units[..(self.length as usize).min(WINDOW_TEXT_UNITS)]
    }
}

const _: () = {
    assert!(size_of::<WindowData>() == 36);
    assert!(size_of::<WindowText>() == 4 + 2 * WINDOW_TEXT_UNITS);
    assert!(size_of::<WindowInfo>() == 60);
    assert!(offset_of!(WindowInfo, client) == 20);
    assert!(offset_of!(WindowInfo, style) == 36);
    assert!(offset_of!(WindowInfo, atom_window_type) == 56);
    assert!(size_of::<WindowPos>() == 28);
    assert!(offset_of!(WindowPos, flags) == 24);
};

// SAFETY: integers and RECTs, without padding (the asserts above pin the sizes and offsets, which
// leave no gap); any bit pattern is a value.
unsafe impl Pod for WindowInfo {}
// SAFETY: seven 32-bit integers.
unsafe impl Pod for WindowPos {}
// SAFETY: nine 32-bit integers.
unsafe impl Pod for WindowData {}
// SAFETY: an integer and an array of units, without padding (the assert above pins the size).
unsafe impl Pod for WindowText {}
