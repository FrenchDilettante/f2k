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
/// The window's text (its title) as DefWindowProc reads it, as long as it is: its length in UTF-16
/// units, a 32-bit integer, then as many of its units as the answer's room holds after it (no
/// terminator). The answer may be any even length from 4: a caller whose room the length passes
/// asks again with more.
pub const QUERY_WINDOW_TEXT: u32 = 3;
/// The window's parent's handle, a 32-bit handle: the desktop window for a top-level window, 0
/// for a window with none (the desktop's own windows). IsChild walks it.
pub const QUERY_WINDOW_PARENT: u32 = 4;
/// The window's menu (GetMenu's answer): a top-level window's menu handle, a child's id, 0 for
/// none, a 32-bit value.
pub const QUERY_WINDOW_MENU: u32 = 5;
/// The window's place among its relatives, a [`WindowLinks`]: what GetWindow and the dialog
/// manager's walks over a dialog's controls read.
pub const QUERY_WINDOW_LINKS: u32 = 6;
/// The fields of the window's class GetClassLong reads, a [`WindowClass`].
pub const QUERY_WINDOW_CLASS: u32 = 7;
/// The window's thread and process, as their client ids, a [`WindowThread`]
/// (GetWindowThreadProcessId's answers).
pub const QUERY_WINDOW_THREAD: u32 = 8;
/// The window's extra bytes (its class's cbWndExtra) at the offset this index carries in its low
/// bits (`QUERY_WINDOW_EXTRA | offset`): as many as the answer's length asks, 2 (a WORD) or 4 (a
/// LONG). An offset whose bytes are not all inside the extra bytes is refused.
pub const QUERY_WINDOW_EXTRA: u32 = 0x8000_0000;
/// The extra bytes of the window's class (its cbClsExtra) at the offset this index carries in its
/// low bits (`QUERY_CLASS_EXTRA | offset`), as [`QUERY_WINDOW_EXTRA`] reads the window's own: what
/// GetClassLong and GetClassWord read at an offset of 0 or more.
pub const QUERY_CLASS_EXTRA: u32 = 0x4000_0000;

/// ChildWindowFromPointEx's flags (winuser.h's CWP_*): which children the search passes over.
pub const CWP_SKIPINVISIBLE: u32 = 0x0001;
pub const CWP_SKIPDISABLED: u32 = 0x0002;
pub const CWP_SKIPTRANSPARENT: u32 = 0x0004;

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
/// [`WindowData`]'s flags: the window is a dialog, marked so by the dialog manager
/// (NtUserSetWindowFNID with [`FNID_DIALOG`]): its extra bytes are the dialog's (DWL_*).
pub const WINDOW_DIALOG: u32 = 0x4;

/// NtUserSetWindowFNID's ids: the kind of window user32's own code makes of a window. Windows
/// 2000's values are not public; F2K's are its own. A dialog's ([`WINDOW_DIALOG`]).
pub const FNID_DIALOG: u32 = 0x02A4;

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

/// NCCALCSIZE_PARAMS (52 bytes): WM_NCCALCSIZE's lParam when its wParam is TRUE (SetWindowPos's
/// resize): the new window rectangle, the old one and the old client rectangle (in the parent's
/// client coordinates for a child window), and the WINDOWPOS of the move. The procedure leaves the
/// new client rectangle in the first.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NcCalcSizeParams {
    /// rgrc: the new window rectangle, the old window rectangle, the old client rectangle.
    pub rects: [Rect; 3],
    /// lppos: the address of the move's WINDOWPOS.
    pub pos: u32,
}

/// WINDOWPLACEMENT (44 bytes): a window's show state and its places, as GetWindowPlacement answers
/// them and SetWindowPlacement takes them; NtUserGetWindowPlacement and NtUserSetWindowPlacement
/// carry it.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WindowPlacement {
    /// The structure's size: 44.
    pub length: u32,
    /// [`WPF_SETMINPOSITION`], [`WPF_RESTORETOMAXIMIZED`].
    pub flags: u32,
    /// SW_SHOWMINIMIZED, SW_SHOWMAXIMIZED or SW_SHOWNORMAL (any show command, to set).
    pub show_cmd: u32,
    /// Where the window goes minimized (ptMinPosition), and maximized (ptMaxPosition): (-1, -1)
    /// for none of its own.
    pub min_x: i32,
    pub min_y: i32,
    pub max_x: i32,
    pub max_y: i32,
    /// Its place when neither minimized nor maximized, in its parent's client coordinates (the
    /// screen's, the work area's at its origin, for a top-level window).
    pub normal: Rect,
}

/// WINDOWPLACEMENT's flags (winuser.h's WPF_*): ptMinPosition is the window's to keep; a minimized
/// window restores to maximized.
pub const WPF_SETMINPOSITION: u32 = 0x1;
pub const WPF_RESTORETOMAXIMIZED: u32 = 0x2;

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

/// A window's thread and process ([`QUERY_WINDOW_THREAD`]): their client ids.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WindowThread {
    pub process: u32,
    pub thread: u32,
}

// SAFETY: two u32s, no padding; every bit pattern is valid.
unsafe impl Pod for WindowThread {}

/// A window's relatives ([`QUERY_WINDOW_LINKS`]), each a handle (0 for none): its parent (the
/// desktop window for a top-level window), its owner, its first child (the top of its children's
/// z-order), the siblings after it and before it in the z-order, and the window last active
/// among it and the windows it owns, directly or not (GetLastActivePopup's answer: 0 for a window
/// that is none's owner and was never active).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WindowLinks {
    pub parent: u32,
    pub owner: u32,
    pub child: u32,
    pub next: u32,
    pub previous: u32,
    pub last_active: u32,
}

/// A window property as NtUserBuildPropList lists it (Windows 2000's PROPSET: the data, then the
/// atom, a WORD padded to a DWORD here).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PropSet {
    pub data: u32,
    pub atom: u32,
}

/// The fields of a window's class ([`QUERY_WINDOW_CLASS`]) GetClassLong answers by their GCL_
/// indexes: its atom (GCW_ATOM), its style (GCL_STYLE), its background brush (GCL_HBRBACKGROUND: a
/// brush handle, or a system color's index plus one), its windows' extra bytes (GCL_CBWNDEXTRA)
/// and its own (GCL_CBCLSEXTRA), its procedure (GCL_WNDPROC, its form in `flags`), its module
/// (GCL_HMODULE), its icons and cursor (GCL_HICON, GCL_HICONSM: the small icon the window manager
/// made from the large one too, GCL_HCURSOR) and its menu name (GCL_MENUNAME: a string's as the
/// copy user32 keeps of it, an integer id as it is).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WindowClass {
    pub atom: u32,
    pub style: u32,
    pub background: u32,
    pub cb_wnd_extra: u32,
    pub cb_cls_extra: u32,
    pub wnd_proc: u32,
    /// [`CLASS_ANSI_PROC`].
    pub flags: u32,
    pub module: u32,
    pub icon: u32,
    pub icon_sm: u32,
    pub cursor: u32,
    pub menu_name: u32,
}

/// [`WindowClass`]'s flags: the class's procedure takes the narrow forms of the messages.
pub const CLASS_ANSI_PROC: u32 = 0x1;

/// NtUserGetClassInfo's answer: the class's atom in its low word, and this bit when its procedure
/// takes the narrow forms of the messages.
pub const CLASS_INFO_ANSI_PROC: u32 = 0x1_0000;

const _: () = {
    assert!(size_of::<WindowLinks>() == 24);
    assert!(size_of::<PropSet>() == 8);
    assert!(size_of::<WindowClass>() == 48);
    assert!(size_of::<WindowData>() == 36);
    assert!(size_of::<WindowInfo>() == 60);
    assert!(offset_of!(WindowInfo, client) == 20);
    assert!(offset_of!(WindowInfo, style) == 36);
    assert!(offset_of!(WindowInfo, atom_window_type) == 56);
    assert!(size_of::<WindowPos>() == 28);
    assert!(size_of::<NcCalcSizeParams>() == 52);
    assert!(size_of::<WindowPlacement>() == 44);
    assert!(offset_of!(WindowPlacement, normal) == 28);
    assert!(offset_of!(WindowPos, flags) == 24);
};

// SAFETY: integers and RECTs, without padding (the asserts above pin the sizes and offsets, which
// leave no gap); any bit pattern is a value.
unsafe impl Pod for WindowInfo {}
// SAFETY: seven 32-bit integers.
unsafe impl Pod for WindowPos {}
// SAFETY: three RECTs and a 32-bit integer, no padding (the assert above pins the size).
unsafe impl Pod for NcCalcSizeParams {}
// SAFETY: nine 32-bit integers.
unsafe impl Pod for WindowData {}
// SAFETY: six 32-bit integers.
unsafe impl Pod for WindowLinks {}
// SAFETY: two 32-bit integers.
unsafe impl Pod for PropSet {}
// SAFETY: twelve 32-bit integers.
unsafe impl Pod for WindowClass {}
// SAFETY: 32-bit integers and a RECT, without padding (the asserts above pin the size and the
// RECT's offset).
unsafe impl Pod for WindowPlacement {}
