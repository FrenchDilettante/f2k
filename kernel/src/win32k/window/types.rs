//! The window manager's public ABI constants and the values its decisions pass around.

use rtl::gdi::Rect;
use rtl::winerror::{
    ERROR_ACCESS_DENIED,
    ERROR_CANNOT_FIND_WND_CLASS,
    ERROR_INVALID_INDEX,
    ERROR_INVALID_PARAMETER,
    ERROR_INVALID_WINDOW_HANDLE,
    ERROR_NO_MORE_USER_HANDLES,
    ERROR_OUTOFMEMORY,
    ERROR_TLW_WITH_WSCHILD,
};

use super::*;
use crate::status::*;
use crate::win32k::class;

/// A window handle (HWND), as the handle table encodes it.
pub type Hwnd = u32;

/// A message's wParam.
pub type WParam = u32;

/// A message's lParam.
pub type LParam = i32;

/// A window procedure's answer (LRESULT, 32-bit on the target).
pub type LResult = i32;

/// The private ex-style bit an ANSI create sets. It is consumed at creation (moved to the
/// window's ANSI-creator flag) and never stored in the window's ex-style.
pub const ANSI_CREATOR_BIT: u32 = 0x8000_0000;

/// CW_USEDEFAULT (winuser.h): the position/size marker honored only by tiled windows.
pub const CW_USEDEFAULT: i32 = 0x8000_0000u32 as i32;

/// The second default marker the create path honors alongside CW_USEDEFAULT.
pub(super) const CW_USEDEFAULT_ALT: i32 = 0x8000;

/// The undocumented bit Windows 2000's WM_WINDOWPOSCHANGED carries after ShowWindow's show
/// (guigeo `sizemsg` captured 0x10001847); ShowWindow passes it, WM_WINDOWPOSCHANGING does not
/// carry it (inferred: the capture logs only WM_WINDOWPOSCHANGED).
pub const SWP_SHOWWINDOW_CALL: u32 = 0x1000_0000;

/// Where a minimized window without a minimized position of its own goes: off the screen, where
/// Windows 2000's desktop with its taskbar (ARW_HIDE) hides minimized windows (the guigeo
/// capture's ptMinPosition).
pub const MINIMIZED_POSITION: (i32, i32) = (-32000, -32000);

/// A minimized window's size (SM_CXMINIMIZED by SM_CYMINIMIZED, the standard scheme's at 96 dpi).
pub const MINIMIZED_SIZE: (i32, i32) = (160, 24);

/// The most positions an EndDeferWindowPos batch carries to the window manager at once.
pub const DEFER_POSITIONS: usize = 64;

/// SetWindowPos's special insert-after handles (winuser.h's HWND_*).
pub const HWND_TOP: Hwnd = 0;

pub const HWND_BOTTOM: Hwnd = 1;

pub const HWND_TOPMOST: Hwnd = -1i32 as Hwnd;

pub const HWND_NOTOPMOST: Hwnd = -2i32 as Hwnd;

/// WM_SIZE's commands (winuser.h's SIZE_*).
pub const SIZENORMAL: u32 = 0;

pub const SIZE_MINIMIZED: u32 = 1;

pub const SIZE_MAXIMIZED: u32 = 2;

/// The startup-info flags (winbase.h's STARTF_*).
pub const STARTF_USEPOSITION: u32 = 0x0000_0004;

pub const STARTF_USESIZE: u32 = 0x0000_0008;

/// DESKTOP_CREATEWINDOW (winnt.h), the desktop access right a create needs.
pub const DESKTOP_CREATEWINDOW: u32 = 0x0000_0001;

/// The atom of the icon-title system class ("#32771"), to which zombie windows are re-classed.
pub const ICONTITLE_ATOM: class::Atom = 0x8003;

/// Why a window operation failed: the Win32 error code (winerror.h) the decision reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    /// ERROR_ACCESS_DENIED (5): the window belongs to another thread, or the desktop access is
    /// missing.
    AccessDenied,
    /// ERROR_OUTOFMEMORY (14): the pool or the handle table is full. The rollback paths (a
    /// refused WM_NCCREATE, a failed WM_CREATE, an exceeded owner depth) answer with this too:
    /// they are memory-failure paths, and no other error applies to them.
    OutOfMemory,
    /// ERROR_INVALID_PARAMETER (87).
    InvalidParameter,
    /// ERROR_INVALID_WINDOW_HANDLE (1400): the handle names no live window.
    InvalidWindowHandle,
    /// ERROR_INVALID_INDEX (1413): a GetWindowLong/SetWindowLong index that names no field of the
    /// window, or extra bytes past the window's own.
    InvalidIndex,
    /// ERROR_TLW_WITH_WSCHILD (1406): a WS_CHILD window was created without a parent.
    TlwWithWsChild,
    /// ERROR_CANNOT_FIND_WND_CLASS (1407): the class name resolved to no visible class.
    CannotFindWindowClass,
    /// ERROR_NO_MORE_USER_HANDLES (1158): the creating process holds its quota's worth of USER
    /// objects, or the user handle table has no window slot left below its ceiling.
    NoMoreUserHandles,
    /// The window procedure refused the creation (WM_NCCREATE answering 0, WM_CREATE -1), or the
    /// window went while it was being created: no error, the last error left as it was (guiwin
    /// `refuse`); the creation's answer is NULL.
    Refused,
    /// The window procedure destroyed the window inside its WM_NCCREATE: Windows 2000's
    /// creation goes no further and answers the dead window's handle (this one), with
    /// ERROR_INVALID_PARAMETER for the last error (guiwin `diecreate`).
    DestroyedInNcCreate(Hwnd),
}

impl Failure {
    /// The Win32 error code (winerror.h) the decision reports.
    pub const fn code(self) -> u32 {
        match self {
            Failure::AccessDenied => ERROR_ACCESS_DENIED,
            Failure::OutOfMemory => ERROR_OUTOFMEMORY,
            Failure::InvalidParameter => ERROR_INVALID_PARAMETER,
            Failure::InvalidWindowHandle => ERROR_INVALID_WINDOW_HANDLE,
            Failure::InvalidIndex => ERROR_INVALID_INDEX,
            Failure::TlwWithWsChild => ERROR_TLW_WITH_WSCHILD,
            Failure::CannotFindWindowClass => ERROR_CANNOT_FIND_WND_CLASS,
            Failure::NoMoreUserHandles => ERROR_NO_MORE_USER_HANDLES,
            Failure::Refused => 0,
            Failure::DestroyedInNcCreate(_) => ERROR_INVALID_PARAMETER,
        }
    }

    /// The NTSTATUS the service answers: the Win32 error itself ([`Failure::code`]) in a
    /// FACILITY_NTWIN32 status, which user32 hands to GetLastError as is (ntdll's mapping answers
    /// the low word), as Windows 2000's win32k sets the thread's last error itself. A refused
    /// creation sets none: its service answers success and a null window instead.
    pub const fn status(self) -> NtStatus {
        NtStatus::from_win32(self.code())
    }
}

/// A position and size as the create path works with them (x, y, cx, cy).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SizeRect {
    pub x: i32,
    pub y: i32,
    pub cx: i32,
    pub cy: i32,
}

/// The window name a creation's WM_NCCREATE and WM_CREATE carry: the name the creation was given
/// (kept with the record until the creation ends), or the window's title, once WM_NCCREATE set it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CreateName {
    Given,
    Title,
}

/// The class a create names, as the create parameters carry it: an integer atom, a string name,
/// or the class's ANSI name (when the create came through the ANSI entry point).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClassArg {
    Atom(class::Atom),
    Name,
    AnsiName,
}

/// The create parameters the WM_NCCREATE and WM_CREATE handlers see (CREATESTRUCT's fields).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CreateParams {
    pub ex_style: u32,
    pub class_name: ClassArg,
    pub name: CreateName,
    pub style: u32,
    pub x: i32,
    pub y: i32,
    pub cx: i32,
    pub cy: i32,
    /// hwndParent: the parent window's handle, 0 for none.
    pub parent: Hwnd,
    /// hMenu: a child's menu id, a top-level window's menu handle.
    pub menu: Hwnd,
    /// hInstance.
    pub instance: u32,
    /// lpCreateParams.
    pub params: u32,
}

/// The menu argument of a create: none, a child's menu id, or a top-level window's menu handle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MenuInput {
    None,
    Id(u32),
    Handle(Hwnd),
}

impl MenuInput {
    pub(super) fn is_none(self) -> bool {
        self == MenuInput::None
    }

    /// The raw value (an id or a handle, as bits).
    pub(super) fn raw(self) -> u32 {
        match self {
            MenuInput::None => 0,
            MenuInput::Id(id) => id,
            MenuInput::Handle(h) => h,
        }
    }

    /// The handle value (a top-level window's menu is a handle; anything else answers 0).
    pub(super) fn handle(self) -> u32 {
        match self {
            MenuInput::Handle(h) => h,
            _ => 0,
        }
    }

    /// The handle a top-level window's menu is stored as.
    pub(super) fn as_window_menu(self) -> Menu {
        match self {
            MenuInput::None => Menu::None,
            other => Menu::Handle(other.raw()),
        }
    }

    /// The menu a child window stores (a raw id).
    pub(super) fn as_child_menu(self) -> Menu {
        match self {
            MenuInput::None => Menu::None,
            MenuInput::Id(id) => Menu::Id(id),
            MenuInput::Handle(h) => Menu::Handle(h),
        }
    }
}

/// A window's menu: none, a child's id, or a top-level window's handle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Menu {
    None,
    Id(u32),
    Handle(Hwnd),
}

impl Menu {
    pub(super) fn id(self) -> Option<u32> {
        match self {
            Menu::Id(id) => Some(id),
            _ => None,
        }
    }

    /// The value GetMenu answers: the menu's handle, a child's id, 0 for none.
    pub(super) fn raw(self) -> u32 {
        match self {
            Menu::None => 0,
            Menu::Id(id) => u32::from(id),
            Menu::Handle(h) => h,
        }
    }
}

/// Where a new window goes in its parent's child list.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZOrder {
    /// At the top (the head of the list).
    Top,
    /// At the bottom (after the last sibling before any bottom-most window).
    Bottom,
    /// Directly after this window.
    After(WindowId),
}

/// The activation command the destroy's fixups use: try this window, or skip past it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Activate {
    Try,
    Skip,
}

/// The min/max info a WM_GETMINMAXINFO answer carries (MINMAXINFO's, as (x, y) pairs): the window
/// manager's defaults ([`Windows::default_min_max_info`]) as the procedure left them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MinMaxInfo {
    /// ptReserved: the smallest size a minimized window's resize gives it.
    pub reserved: (i32, i32),
    /// ptMaxSize: the maximized window's size.
    pub max_size: (i32, i32),
    /// ptMaxPosition: the maximized window's place (in its parent's client coordinates).
    pub max_position: (i32, i32),
    /// ptMinTrackSize.
    pub min_track: (i32, i32),
    /// ptMaxTrackSize.
    pub max_track: (i32, i32),
}

impl MinMaxInfo {
    /// No limits: the min track is zero, the max track unbounded.
    pub fn unbounded() -> Self {
        MinMaxInfo {
            reserved: (0, 0),
            max_size: (i32::MAX, i32::MAX),
            max_position: (0, 0),
            min_track: (0, 0),
            max_track: (i32::MAX, i32::MAX),
        }
    }

    /// The MINMAXINFO a callback carries.
    pub fn raw(&self) -> rtl::user::MinMaxInfo {
        let point = |(x, y): (i32, i32)| rtl::user::Point { x, y };
        rtl::user::MinMaxInfo {
            reserved: point(self.reserved),
            max_size: point(self.max_size),
            max_position: point(self.max_position),
            min_track: point(self.min_track),
            max_track: point(self.max_track),
        }
    }

    /// The MINMAXINFO a procedure handed back. Any values are taken: the clamps saturate, and a
    /// size below zero is taken as zero where it is used.
    pub fn of_raw(raw: &rtl::user::MinMaxInfo) -> Self {
        let pair = |p: rtl::user::Point| (p.x, p.y);
        MinMaxInfo {
            reserved: pair(raw.reserved),
            max_size: pair(raw.max_size),
            max_position: pair(raw.max_position),
            min_track: pair(raw.min_track),
            max_track: pair(raw.max_track),
        }
    }
}

/// The startup info a thread's process carries (STARTUPINFOW's used fields).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StartupInfo {
    pub flags: u32,
    pub x: u32,
    pub y: u32,
    pub cx: u32,
    pub cy: u32,
}

/// The expected-version word of a create (the high word is the major version).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VersionCompat {
    /// A pre-4.0 (3.x) caller.
    pub win31: bool,
    /// A 4.0-or-later caller.
    pub win40: bool,
}

impl VersionCompat {
    pub fn of(version: u32) -> Self {
        let major = version >> 16;
        VersionCompat {
            win31: major == 3,
            win40: major >= 4,
        }
    }
}

/// The arguments of a create, as the service's caller passes them.
pub struct CreateArgs<'a> {
    pub ex_style: u32,
    /// The class as the caller named it (a string or an integer atom).
    pub class_name: class::Name<'a>,
    /// The atom `class_name` resolves to (0 when a string name has none), resolved by the service
    /// ([`WindowManager::create_window`]) through the class registry's
    /// [`class::Registry::atom_of`].
    pub class_atom: class::Atom,
    /// The window name (lpszName's string), empty for none.
    pub name: &'a [u16],
    pub style: u32,
    pub x: i32,
    pub y: i32,
    pub cx: i32,
    pub cy: i32,
    /// The parent window, if the caller gave one.
    pub parent: Option<WindowId>,
    pub menu: MenuInput,
    /// hInstance.
    pub instance: u32,
    /// lpCreateParams.
    pub params: u32,
    /// The expected-version word.
    pub version: u32,
}

/// A message the create/destroy logic sends.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    pub message: u32,
    pub wparam: WParam,
    pub lparam: LParam,
    /// The payload a handler may read or write: the create parameters for WM_NCCREATE/WM_CREATE,
    /// the rectangle or NCCALCSIZE_PARAMS for WM_NCCALCSIZE, the WINDOWPOS and STYLESTRUCT of the
    /// position and style messages, nothing otherwise. A send to a procedure hands back what the
    /// procedure left in it (WM_NCCALCSIZE, WM_WINDOWPOSCHANGING, WM_STYLECHANGING); a send the
    /// default procedure answers leaves WM_NCCALCSIZE's as it would ([`default_procedure`]).
    pub payload: Payload,
}

/// WM_NCCALCSIZE's NCCALCSIZE_PARAMS (wParam TRUE), as SetWindowPos's resize sends it: the new
/// window rectangle (the new client rectangle on the way back), the old one and the old client
/// rectangle, and the move's WINDOWPOS (which the procedure's lppos points at; not read back).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CalcSize {
    pub rects: [Rect; 3],
    pub pos: WindowPos,
}

/// The window rectangles a resize's WM_NCCALCSIZE reports ([`Session::calc_client`]'s TRUE
/// form), in screen coordinates: the window's rectangle and client rectangle before it, and the
/// move's WINDOWPOS.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Resize {
    pub window: Rect,
    pub client: Rect,
    pub pos: WindowPos,
}

/// A message's payload.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Payload {
    None,
    /// WM_NCCALCSIZE's window rectangle (wParam FALSE), the client rectangle on the way back.
    Rect(Rect),
    /// WM_NCCALCSIZE's NCCALCSIZE_PARAMS (wParam TRUE).
    CalcSize(CalcSize),
    Create(CreateParams),
    /// WM_WINDOWPOSCHANGING's and WM_WINDOWPOSCHANGED's WINDOWPOS (a WM_WINDOWPOSCHANGING handler
    /// may change it).
    WindowPos(WindowPos),
    /// WM_STYLECHANGING's and WM_STYLECHANGED's STYLESTRUCT (a WM_STYLECHANGING handler may change
    /// the new style).
    Style(StyleStruct),
    /// WM_GETMINMAXINFO's MINMAXINFO, the window manager's defaults (a handler may change them).
    MinMax(MinMaxInfo),
}

/// Where SetWindowPos puts a window in its parent's child list (its hWndInsertAfter).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InsertAfter {
    /// HWND_TOP: at the top (behind the topmost windows, for a window that is not one).
    Top,
    /// HWND_BOTTOM: at the bottom; a topmost window stops being one.
    Bottom,
    /// HWND_TOPMOST: at the top, a topmost window from then on.
    TopMost,
    /// HWND_NOTOPMOST: a topmost window stops being one, above every window that is not; no
    /// effect on another window.
    NoTopMost,
    /// Directly after this sibling.
    After(WindowId),
}

/// Pack a 16-bit low word and high word into a wParam.
pub(super) fn makelong(lo: u16, hi: u16) -> WParam {
    ((hi as u32) << 16) | lo as u32
}

/// HWND_MESSAGE (winuser.h): the parent that makes a message-only window, a child of the desktop's
/// message window.
pub const HWND_MESSAGE: Hwnd = -3i32 as Hwnd;

impl MenuInput {
    /// A create's raw hMenu: a child window's id, a top-level window's menu handle, none for 0.
    pub fn of(style: u32, raw: u32) -> Self {
        if raw == 0 {
            MenuInput::None
        } else if kind_of(style) == Kind::Child {
            MenuInput::Id(raw)
        } else {
            MenuInput::Handle(raw)
        }
    }
}

#[cfg(test)]
mod tests {
    use rtl::user::{WS_CHILD, WS_OVERLAPPED, WS_POPUP};

    use super::*;

    /// A create's raw hMenu: a child's id, a top-level window's handle, none for 0.
    #[test]
    fn the_raw_menu_is_read_by_the_window_kind() {
        assert_eq!(MenuInput::of(WS_CHILD, 0), MenuInput::None);
        assert_eq!(MenuInput::of(WS_CHILD, 7), MenuInput::Id(7));
        assert_eq!(
            MenuInput::of(WS_POPUP, 0x1_0040),
            MenuInput::Handle(0x1_0040)
        );
        assert_eq!(MenuInput::of(WS_OVERLAPPED, 0), MenuInput::None);
    }
}
