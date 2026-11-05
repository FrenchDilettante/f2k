//! The window manager's shared shapes: what win32k's window services and user32's window calls
//! agree on. WINDOWINFO and WINDOWPOS as Windows 2000's winuser.h lays them out on x86
//! ([`WindowInfo`], [`WindowPos`]), and the answers NtUserQueryWindow gives (F2K's own indexes:
//! Windows 2000's user32 reads a window's state from the window manager's records, mapped into
//! every GUI process, where F2K's asks the kernel).

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

const _: () = {
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
