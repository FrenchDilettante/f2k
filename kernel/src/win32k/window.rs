//! Windows: the window records behind HWNDs, and the create/destroy decision logic that runs
//! over them.
//!
//! A window is a record in the window pool ([`Windows`]), named by a generation-tagged id
//! ([`WindowId`]), the object manager's pattern, with a handle into the window handle table
//! ([`sched::object::HandleTable`], the same shape the class registry's cursor table uses). Its
//! parent/child/next/owner links are the z-order and ownership lists the create and destroy
//! logic splices. Threads ([`Thread`]), desktops ([`Desktop`]) and monitors ([`Monitor`]) are
//! the calling context the decisions read: the thread's desktop and its access mask, its window
//! count and its queue's active/focus windows, the desktop's own window and message window, the
//! monitor's work area and cascade counter.
//!
//! The create path ([`Windows::create_window_ex`]) is the decision sequence: validation gates
//! (parent's desktop, desktop access, child-without-parent, nesting limits), class resolution
//! through [`super::class`] (atom, visibility, reference), style normalization (the private
//! ANSI-creator bit, the edge bit, WS_VISIBLE and the layered bit stripped from the stored
//! values), positioning (CW_USEDEFAULT handling, child offsets, the tiled cascade, monitor
//! clamping, min/max track), owner/parent/desktop wiring, and the message order WM_NCCREATE,
//! link, WM_NCCALCSIZE, WM_CREATE, WM_SIZE/WM_MOVE, WM_PARENTNOTIFY, show — with the rollback
//! path for a refused WM_NCCREATE (WM_NCDESTROY only, no WM_DESTROY) and the full destroy for a
//! refused WM_CREATE. The destroy path ([`Windows::destroy_window`]) is the cascade: ownership
//! checks, parent notify, hide, owned windows first, activation fixups, WM_DESTROY depth-first
//! parent before children, unlink, and the free — where a still-referenced window becomes a
//! zombie re-classed to the icon-title class instead of being freed.
//!
//! Both registries, this one and the class registry ([`super::class`]), sit behind one lock, the
//! window manager's ([`WindowManager`]): the decisions hold both at once, through every callback.
//! The boot makes each desktop's own windows, the desktop window and the message window, on a
//! thread record of the window manager's own ([`WindowManager::boot_desktop`]); a process thread
//! gets its record at its first win32k service ([`Windows::connect_thread`], through
//! [`super::winsta`]).
//!
//! The services, user32's calls (F2K's argument lists, see [`crate::win32k`]; Windows 2000's
//! numbers):
//!
//! - NtUserCreateWindowEx (0x114D): CreateWindowExW's arguments, the expected-version word, and the
//!   new window's handle through the last pointer;
//! - NtUserDestroyWindow (0x1159): destroy a window of the calling thread's.
//!
//! Seams recorded: message sending and the queue (the message slice) — every send and
//! window-manager call the decisions make goes through the [`Pump`] trait, and the services run
//! them with [`DefaultProcedure`], whose answers are the default procedure's; monitors and frame
//! metrics come from the display slice (the boot sets the primary monitor's work area); nothing
//! ends a thread's or a process's records yet (their windows and classes outlive them).

// Parts of the decision logic have no caller until the message slice lands (the activation and
// hook state, the zombie's references).
#![allow(dead_code)]

use super::class;
use crate::nt::call::{Handle, NtCall, NtResult, UserAddr, UserPtr};
use crate::sched::object::HandleTable;
use crate::sched::thread::ThreadId;
use crate::status::*;

// --- The public ABI and constants (winuser.h, winbase.h, winnt.h)
// ---------------------------------

/// A window handle (HWND), as the handle table encodes it.
pub type Hwnd = u32;
/// A message's wParam.
pub type WParam = u32;
/// A message's lParam.
pub type LParam = i32;
/// A window procedure's answer (LRESULT, 32-bit on the target).
pub type LResult = i32;

/// The window styles (winuser.h's WS_*).
pub const WS_OVERLAPPED: u32 = 0x0000_0000;
pub const WS_POPUP: u32 = 0x8000_0000;
pub const WS_CHILD: u32 = 0x4000_0000;
pub const WS_VISIBLE: u32 = 0x1000_0000;
pub const WS_CLIPSIBLINGS: u32 = 0x0400_0000;
pub const WS_CLIPCHILDREN: u32 = 0x0200_0000;
pub const WS_BORDER: u32 = 0x0080_0000;
pub const WS_DLGFRAME: u32 = 0x0040_0000;
pub const WS_CAPTION: u32 = 0x00C0_0000; // WS_BORDER | WS_DLGFRAME
pub const WS_SYSMENU: u32 = 0x0008_0000;
pub const WS_THICKFRAME: u32 = 0x0004_0000;
pub const WS_MINIMIZEBOX: u32 = 0x0002_0000;
pub const WS_MAXIMIZEBOX: u32 = 0x0001_0000;
pub const WS_MINIMIZE: u32 = 0x2000_0000;
pub const WS_MAXIMIZE: u32 = 0x0100_0000;
/// WS_OVERLAPPEDWINDOW.
pub const WS_OVERLAPPEDWINDOW: u32 =
    WS_CAPTION | WS_SYSMENU | WS_THICKFRAME | WS_MINIMIZEBOX | WS_MAXIMIZEBOX;

/// The extended window styles (winuser.h's WS_EX_*), the public subset.
pub const WS_EX_DLGMODALFRAME: u32 = 0x0000_0001;
pub const WS_EX_NOPARENTNOTIFY: u32 = 0x0000_0004;
pub const WS_EX_TOPMOST: u32 = 0x0000_0008;
pub const WS_EX_TOOLWINDOW: u32 = 0x0000_0080;
pub const WS_EX_WINDOWEDGE: u32 = 0x0000_0100;
pub const WS_EX_STATICEDGE: u32 = 0x0002_0000;
pub const WS_EX_APPWINDOW: u32 = 0x0004_0000;
pub const WS_EX_LAYERED: u32 = 0x0008_0000;

/// The private ex-style bit an ANSI create sets. It is consumed at creation (moved to the
/// window's ANSI-creator flag) and never stored in the window's ex-style.
pub const ANSI_CREATOR_BIT: u32 = 0x8000_0000;

/// CW_USEDEFAULT (winuser.h): the position/size marker honored only by tiled windows.
pub const CW_USEDEFAULT: i32 = 0x8000_0000u32 as i32;
/// The second default marker the create path honors alongside CW_USEDEFAULT.
const CW_USEDEFAULT_ALT: i32 = 0x8000;

/// The messages the create/destroy logic sends (winuser.h's WM_*).
pub const WM_CREATE: u32 = 0x0001;
pub const WM_DESTROY: u32 = 0x0002;
pub const WM_MOVE: u32 = 0x0003;
pub const WM_SIZE: u32 = 0x0005;
pub const WM_SETHOTKEY: u32 = 0x0032;
pub const WM_NCCREATE: u32 = 0x0081;
pub const WM_NCDESTROY: u32 = 0x0082;
pub const WM_NCCALCSIZE: u32 = 0x0083;
pub const WM_PARENTNOTIFY: u32 = 0x0210;

/// The show commands (winuser.h's SW_*) the decisions use.
pub const SW_HIDE: i32 = 0;
pub const SW_SHOW: i32 = 5;
pub const SW_SHOWMINNOACTIVE: i32 = 7;
pub const SW_SHOWNA: i32 = 8;
pub const SW_SHOWMAXIMIZED: i32 = 3;

/// The SetWindowPos flags (winuser.h's SWP_*) the destroy's hide uses.
pub const SWP_NOSIZE: u32 = 0x0001;
pub const SWP_NOMOVE: u32 = 0x0002;
pub const SWP_NOZORDER: u32 = 0x0004;
pub const SWP_NOACTIVATE: u32 = 0x0010;
pub const SWP_HIDEWINDOW: u32 = 0x0080;

/// SIZENORMAL (winuser.h's SIZE_*).
pub const SIZENORMAL: u32 = 0;

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
    /// ERROR_TLW_WITH_WSCHILD (1406): a WS_CHILD window was created without a parent.
    TlwWithWsChild,
    /// ERROR_CANNOT_FIND_WND_CLASS (1407): the class name resolved to no visible class.
    CannotFindWindowClass,
}

impl Failure {
    /// The Win32 error code (winerror.h) the decision reports.
    pub const fn code(self) -> u32 {
        match self {
            Failure::AccessDenied => 5,
            Failure::OutOfMemory => 14,
            Failure::InvalidParameter => 87,
            Failure::InvalidWindowHandle => 1400,
            Failure::TlwWithWsChild => 1406,
            Failure::CannotFindWindowClass => 1407,
        }
    }

    /// The NTSTATUS the service answers. The window-specific codes have no NTSTATUS counterpart
    /// (nothing maps to them in RtlNtStatusToDosError's table), so the closest documented status
    /// stands in; user32's body reports [`Failure::code`] for GetLastError.
    pub const fn status(self) -> NtStatus {
        match self {
            Failure::AccessDenied => STATUS_ACCESS_DENIED,
            Failure::OutOfMemory => STATUS_NO_MEMORY,
            Failure::InvalidParameter | Failure::TlwWithWsChild => STATUS_INVALID_PARAMETER,
            Failure::InvalidWindowHandle => STATUS_INVALID_HANDLE,
            Failure::CannotFindWindowClass => STATUS_OBJECT_NAME_NOT_FOUND,
        }
    }
}

// --- The values the decisions pass around
// ---------------------------------------------------------

/// A rectangle (winuser.h's RECT).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Rect {
    pub left: i32,
    pub top: i32,
    pub right: i32,
    pub bottom: i32,
}

/// A position and size as the create path works with them (x, y, cx, cy).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SizeRect {
    pub x: i32,
    pub y: i32,
    pub cx: i32,
    pub cy: i32,
}

/// The longest window text the record holds, in UTF-16 units.
pub const MAX_WINDOW_TEXT: usize = 128;

/// A window text (a title), copied into the record's own fixed buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TextBuf {
    units: [u16; MAX_WINDOW_TEXT],
    len: u16,
}

impl TextBuf {
    pub const EMPTY: Self = TextBuf {
        units: [0; MAX_WINDOW_TEXT],
        len: 0,
    };

    /// A copy of `units` (cut at the buffer's capacity).
    pub fn from_units(units: &[u16]) -> Self {
        let len = units.len().min(MAX_WINDOW_TEXT);
        let mut copy = TextBuf::EMPTY;
        copy.units[..len].copy_from_slice(&units[..len]);
        copy.len = len as u16;
        copy
    }

    pub fn as_slice(&self) -> &[u16] {
        &self.units[..self.len as usize]
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
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
    pub name: TextBuf,
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
    Id(u16),
    Handle(Hwnd),
}

impl MenuInput {
    fn is_none(self) -> bool {
        self == MenuInput::None
    }

    /// The raw value (an id or a handle, as bits).
    fn raw(self) -> u32 {
        match self {
            MenuInput::None => 0,
            MenuInput::Id(id) => id as u32,
            MenuInput::Handle(h) => h,
        }
    }

    /// The handle value (a top-level window's menu is a handle; anything else answers 0).
    fn handle(self) -> u32 {
        match self {
            MenuInput::Handle(h) => h,
            _ => 0,
        }
    }

    /// The handle a top-level window's menu is stored as.
    fn as_window_menu(self) -> Menu {
        match self {
            MenuInput::None => Menu::None,
            other => Menu::Handle(other.raw()),
        }
    }

    /// The menu a child window stores (a raw id).
    fn as_child_menu(self) -> Menu {
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
    Id(u16),
    Handle(Hwnd),
}

impl Menu {
    fn id(self) -> Option<u16> {
        match self {
            Menu::Id(id) => Some(id),
            _ => None,
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

/// The min/max info a WM_GETMINMAXINFO answer carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MinMaxInfo {
    /// ptReserved: the minimized size.
    pub reserved: (i32, i32),
    /// ptMaxSize.
    pub max_size: (i32, i32),
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
            min_track: (0, 0),
            max_track: (i32::MAX, i32::MAX),
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
    /// the rectangle for WM_NCCALCSIZE, nothing otherwise.
    pub payload: Payload,
}

/// A message's payload.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Payload {
    None,
    Rect(Rect),
    Create(CreateParams),
}

/// The message pump's seam (the message slice): every message and window-manager call the
/// create/destroy decisions make goes through here. The defaults answer as the default window
/// procedure and the no-op window-manager calls do; the tests supply a recording pump.
pub trait Pump {
    /// Send `message` to `target`; the handler's answer. The default procedure continues a
    /// creation (WM_NCCREATE answers 1) and answers 0 to everything else.
    fn send(
        &mut self,
        _windows: &mut Windows,
        _classes: &mut class::Registry,
        _target: WindowId,
        message: &mut Message,
    ) -> LResult {
        match message.message {
            WM_NCCREATE => 1,
            _ => 0,
        }
    }

    /// The WM_SIZE send (wparam is the SIZE_* command).
    fn send_size(
        &mut self,
        windows: &mut Windows,
        classes: &mut class::Registry,
        target: WindowId,
        command: u32,
    ) {
        self.send(
            windows,
            classes,
            target,
            &mut Message {
                message: WM_SIZE,
                wparam: command,
                lparam: 0,
                payload: Payload::None,
            },
        );
    }

    /// Show or hide the window (ShowWindow's command).
    fn show(&mut self, _windows: &mut Windows, _target: WindowId, _command: u32) -> bool {
        true
    }

    /// A SetWindowPos call (the SWP_* flags).
    fn set_window_pos(&mut self, _windows: &mut Windows, _target: WindowId, _flags: u32) {}

    /// Activate a window (the AW_* decision as [`Activate`]).
    fn activate(&mut self, _windows: &mut Windows, _target: WindowId, _command: Activate) -> bool {
        true
    }

    /// The min/max command (SW_SHOWMINNOACTIVE, SW_SHOWMAXIMIZED).
    fn min_maximize(&mut self, _windows: &mut Windows, _target: WindowId, _command: u32) {}

    /// The focus check before and after the destroy messages.
    fn check_focus(&mut self, _windows: &mut Windows, _target: WindowId) {}

    /// Share (or end sharing) input state between two threads.
    fn attach_input(&mut self, _from: ThreadId, _to: ThreadId, _attach: bool) {}

    /// Redraw the windows below `target` (the failed-hide fallback).
    fn redraw_below(&mut self, _windows: &mut Windows, _target: WindowId) {}

    /// Release the mouse capture.
    fn release_capture(&mut self, _windows: &mut Windows) {}

    /// Destroy the caret.
    fn destroy_caret(&mut self) {}

    /// Post the destroy-window event to a cross-thread child's queue.
    fn post_destroy_event(&mut self, _thread: ThreadId, _window: WindowId) {}

    /// The WM_GETMINMAXINFO answer.
    fn min_max_info(&mut self, _windows: &mut Windows, _target: WindowId) -> MinMaxInfo {
        MinMaxInfo::unbounded()
    }

    /// Load a class menu (the module and menu name); the menu's handle, none on failure.
    fn load_class_menu(&mut self, _module: u32, _name: &class::MenuName) -> Option<Hwnd> {
        None
    }

    /// Destroy a menu.
    fn destroy_menu(&mut self, _windows: &mut Windows, _menu: Hwnd) {}

    /// Create the window's cache DC (CS_OWNDC/CS_CLASSDC); false on failure.
    fn create_window_dc(
        &mut self,
        _windows: &mut Windows,
        _target: WindowId,
        _own_dc: bool,
    ) -> bool {
        true
    }

    /// Make the window layered; false on failure.
    fn set_layered(&mut self, _windows: &mut Windows, _target: WindowId) -> bool {
        true
    }

    /// The full-screen check over the window's rect.
    fn check_full_screen(
        &mut self,
        _windows: &mut Windows,
        _target: WindowId,
        _rect: &mut SizeRect,
    ) {
    }

    /// Where a top-level window inserts in the z-order (after the topmost pile).
    fn foreground_insert_after(&mut self, _windows: &mut Windows, _target: WindowId) -> ZOrder {
        ZOrder::Top
    }

    /// A hook's veto of a creation (the CBT hook's HCBT_CREATEWND).
    fn cbt_create_veto(
        &mut self,
        _windows: &mut Windows,
        _classes: &mut class::Registry,
        _target: WindowId,
        _params: &mut CreateParams,
    ) -> bool {
        false
    }

    /// A hook's veto of a destroy (the CBT hook's HCBT_DESTROYWND).
    fn cbt_destroy_veto(&mut self, _windows: &mut Windows, _target: WindowId) -> bool {
        false
    }

    /// Disown the clipboard (the window was the clipboard owner).
    fn disown_clipboard(&mut self, _windows: &mut Windows, _target: WindowId) {}

    /// Re-post a queued WM_QUIT for the window with its exit code.
    fn repost_quit(&mut self, _windows: &mut Windows, _target: WindowId) {}

    /// The timers/hotkeys/pending-sends cleanup at the window's end.
    fn window_teardown(&mut self, _windows: &mut Windows, _target: WindowId) {}

    /// Delete the window's properties.
    fn delete_properties(&mut self, _windows: &mut Windows, _target: WindowId) {}
}

// --- The window pool
// ---------------------------------------------------------------------------------

/// How many windows can exist at once.
pub const WINDOWS: usize = 256;
/// How many threads the create/destroy context holds.
pub const THREADS: usize = crate::ob::THREADS;
/// How many desktops the registry tracks.
pub const DESKTOPS: usize = 8;
/// How many monitors the registry tracks.
pub const MONITORS: usize = 4;
/// The primary monitor's index.
pub const PRIMARY_MONITOR: u16 = 0;
/// The nested window/owner depth limit.
const NESTED_WINDOW_LIMIT: u32 = 100;

/// A window's id: its record in the pool and the record's generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WindowId {
    index: u16,
    generation: u16,
}

/// One window record's header.
#[derive(Clone, Copy)]
struct Header {
    live: bool,
    generation: u16,
}

impl Header {
    const DEAD: Self = Header {
        live: false,
        generation: 0,
    };
}

/// The internal flags a window record carries (the bits that are not public style bits).
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
struct Flags {
    /// Size/move messages are deferred to show time (tiled windows).
    sendsizemove: bool,
    /// The window is destroyed (its handlers may still be running).
    destroyed: bool,
    /// The window is in the middle of being destroyed.
    in_destroy: bool,
    /// The create finished (WM_CREATE ran).
    initialized: bool,
    /// The create came through the ANSI entry point.
    ansi_creator: bool,
    /// A pre-4.0 (3.x) caller.
    win31_compat: bool,
    /// A 4.0-or-later caller.
    win40_compat: bool,
    /// The window procedure runs on the kernel side.
    server_side_proc: bool,
    /// WM_NCCREATE's handler set the window text.
    title_set: bool,
    /// The window sits at the bottom of the z-order.
    bottommost: bool,
    /// The window has a palette.
    has_palette: bool,
}

/// The window procedure a record points at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Proc {
    /// A client-side procedure (the class's wndProc value).
    Client(u32),
    /// The default window procedure (a zombie window's).
    Default,
}

/// A window: the record the pool holds.
#[derive(Clone, Copy)]
struct Window {
    handle: Hwnd,
    thread: ThreadId,
    /// The owning process, as the class registry keys it.
    process: class::Owner,
    /// The desktop the window is on (the packed desktop object id).
    desktop: u32,
    monitor: u16,
    /// The public style (the type, visible, clip and frame bits live here).
    style: u32,
    /// The public extended style.
    ex_style: u32,
    flags: Flags,
    parent: Option<WindowId>,
    child: Option<WindowId>,
    next: Option<WindowId>,
    owner: Option<WindowId>,
    last_active: Option<WindowId>,
    window_rect: Rect,
    client_rect: Rect,
    class: Option<class::ClassId>,
    menu: Menu,
    /// hModule.
    module: u32,
    proc: Proc,
    cb_wnd_extra: i32,
    title: TextBuf,
    /// The object's lock count: 1 at creation, dropped by the free; more than that means
    /// someone else still holds a reference and the free makes a zombie instead.
    locks: u32,
    /// The destroy cascade's bookkeeping for this window, while a cascade visits it.
    walk: Walk,
}

/// What the destroy cascade keeps in a window's record while it visits the window. The cascade
/// walks the window trees without recursing — a level of recursion costs more than a kilobyte of
/// the gate stack at opt-level 0, and both the parent chain and the owner chain may be 100 deep —
/// so the state a recursive walk would keep in its frames lives here: each window is on one walk
/// at a time, and a handler that destroys another window starts a walk of that window's own.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Walk {
    /// The sibling the WM_DESTROY walk visits after this window, read before this window's
    /// subtree is messaged: a handler that destroys it ends the walk of their parent's children.
    next: Option<WindowId>,
    /// The window whose owned-window cascade is destroying this one (none for the window the
    /// destroy was asked for).
    owner: Option<WindowId>,
    /// This window's destroy is a re-entry: it was marked for destruction already.
    already: bool,
    /// The calling thread's hooks-disabled flag from before a re-entry's destroy set it.
    saved_hooks: Option<bool>,
}

impl Walk {
    const NONE: Self = Walk {
        next: None,
        owner: None,
        already: false,
        saved_hooks: None,
    };
}

impl Window {
    const EMPTY: Self = Window {
        handle: 0,
        thread: ThreadId(0),
        process: 0,
        desktop: 0,
        monitor: PRIMARY_MONITOR,
        style: 0,
        ex_style: 0,
        flags: Flags {
            sendsizemove: false,
            destroyed: false,
            in_destroy: false,
            initialized: false,
            ansi_creator: false,
            win31_compat: false,
            win40_compat: false,
            server_side_proc: false,
            title_set: false,
            bottommost: false,
            has_palette: false,
        },
        parent: None,
        child: None,
        next: None,
        owner: None,
        last_active: None,
        window_rect: Rect {
            left: 0,
            top: 0,
            right: 0,
            bottom: 0,
        },
        client_rect: Rect {
            left: 0,
            top: 0,
            right: 0,
            bottom: 0,
        },
        class: None,
        menu: Menu::None,
        module: 0,
        proc: Proc::Default,
        cb_wnd_extra: 0,
        title: TextBuf::EMPTY,
        locks: 0,
        walk: Walk::NONE,
    };

    /// The window's kind, from the style's type bits.
    fn kind(&self) -> Kind {
        kind_of(self.style)
    }

    fn is_child(&self) -> bool {
        self.style & WS_CHILD != 0
    }

    fn is_popup(&self) -> bool {
        self.style & WS_POPUP != 0
    }

    fn is_tiled(&self) -> bool {
        !self.is_child() && !self.is_popup()
    }

    fn is_visible(&self) -> bool {
        self.style & WS_VISIBLE != 0
    }
}

/// A window's kind: from the style's WS_CHILD/WS_POPUP bits (WS_OVERLAPPED is tiled).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Tiled,
    Popup,
    Child,
}

fn kind_of(style: u32) -> Kind {
    if style & WS_CHILD != 0 {
        Kind::Child
    } else if style & WS_POPUP != 0 {
        Kind::Popup
    } else {
        Kind::Tiled
    }
}

/// The window pool: records behind headers, ids with generations.
struct WindowPool {
    headers: [Header; WINDOWS],
    records: [Window; WINDOWS],
}

impl WindowPool {
    /// Take the lowest free record for a new window (zeroed); none when the pool is exhausted.
    fn allocate(&mut self) -> Option<WindowId> {
        let index = self.headers.iter().position(|h| !h.live)?;
        self.headers[index].live = true;
        self.records[index] = Window::EMPTY;
        Some(WindowId {
            index: index as u16,
            generation: self.headers[index].generation,
        })
    }

    /// Free `id`'s record: dead, its generation moved on so the id resolves to nothing.
    fn free(&mut self, id: WindowId) {
        let header = &mut self.headers[id.index as usize];
        debug_assert!(
            header.live && header.generation == id.generation,
            "a live window id"
        );
        header.live = false;
        header.generation = header.generation.wrapping_add(1);
    }

    /// The live record `id` names.
    fn at(&self, id: WindowId) -> &Window {
        let header = &self.headers[id.index as usize];
        debug_assert!(
            header.live && header.generation == id.generation,
            "a live window id"
        );
        &self.records[id.index as usize]
    }

    /// The live record `id` names, mutable.
    fn at_mut(&mut self, id: WindowId) -> &mut Window {
        let header = &mut self.headers[id.index as usize];
        debug_assert!(
            header.live && header.generation == id.generation,
            "a live window id"
        );
        &mut self.records[id.index as usize]
    }

    fn is_live(&self, id: WindowId) -> bool {
        self.headers
            .get(id.index as usize)
            .is_some_and(|h| h.live && h.generation == id.generation)
    }
}

/// One window handle-table entry: the window it names, the thread that owns it, and the
/// destroy flags (the object manager's handle-table pattern).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct WindowEntry {
    id: WindowId,
    owner: ThreadId,
    /// The handle is marked for destruction: a re-entering destroy proceeds instead of failing
    /// the owner check.
    marked_destroy: bool,
    /// A free is in progress on the object.
    in_destroy: bool,
}

/// A thread's create/destroy context: its process, desktop and desktop access, its window count
/// and queue state, its startup info and hotkey.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Thread {
    pub live: bool,
    /// The thread the record serves, when it is a process's (none for the desktop's own).
    pub key: Option<ThreadKey>,
    pub process: class::Owner,
    /// The packed desktop object id.
    pub desktop: u32,
    /// The thread's desktop handle, when it has one (none while the root desktop window is
    /// being created).
    pub desktop_handle: Option<Hwnd>,
    /// The desktop access mask.
    pub desktop_access: u32,
    /// The thread's monitor, when the shell set one.
    pub monitor: Option<u16>,
    /// How many windows the thread created and has not destroyed.
    pub window_count: i32,
    pub active: Option<WindowId>,
    pub active_prev: Option<WindowId>,
    pub focus: Option<WindowId>,
    pub capture: Option<WindowId>,
    pub startup: StartupInfo,
    /// The process's pending hotkey.
    pub hotkey: u32,
    /// Thread teardown in progress.
    pub in_cleanup: bool,
    /// Hooks disabled (the destroy re-entry's duration).
    pub hooks_disabled: bool,
}

impl Thread {
    const EMPTY: Self = Thread {
        live: false,
        key: None,
        process: 0,
        desktop: 0,
        desktop_handle: None,
        desktop_access: 0,
        monitor: None,
        window_count: 0,
        active: None,
        active_prev: None,
        focus: None,
        capture: None,
        startup: StartupInfo {
            flags: 0,
            x: 0,
            y: 0,
            cx: 0,
            cy: 0,
        },
        hotkey: 0,
        in_cleanup: false,
        hooks_disabled: false,
    };
}

/// A thread as the window manager tells threads apart: its thread object's pool index and the
/// record's generation, so a thread that reuses an ended one's slot is told from it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ThreadKey {
    pub index: u16,
    pub generation: u16,
}

/// A desktop: its window and message window (wired by the window-station side), its shared
/// dialog system menu, and the queue/winsta backpointers the free clears.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Desktop {
    /// The packed desktop object id.
    pub id: u32,
    /// The desktop window.
    pub window: Option<WindowId>,
    /// The message window.
    pub message_window: Option<WindowId>,
    /// The desktop's shared dialog system menu handle.
    pub dialog_menu: Hwnd,
    pub foreground: Option<WindowId>,
    pub tray: Option<WindowId>,
}

impl Desktop {
    const EMPTY: Self = Desktop {
        id: 0,
        window: None,
        message_window: None,
        dialog_menu: 0,
        foreground: None,
        tray: None,
    };
}

/// A monitor: its rectangle (the work area, in the minimal subset) and the cascade counter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Monitor {
    pub rect: Rect,
    /// How many cascaded windows the monitor has stacked.
    pub window_stack: i32,
}

impl Monitor {
    const EMPTY: Self = Monitor {
        rect: Rect {
            left: 0,
            top: 0,
            right: 0,
            bottom: 0,
        },
        window_stack: 0,
    };
}

/// The window registry: the pool, the handle table, and the calling-context records.
pub struct Windows {
    pool: WindowPool,
    handles: HandleTable<WindowEntry>,
    threads: [Thread; THREADS],
    desktops: [Desktop; DESKTOPS],
    monitors: [Monitor; MONITORS],
    /// The clipboard owner, if a window has it.
    pub clipboard_owner: Option<WindowId>,
    /// The foreground thread's queue.
    pub foreground_thread: Option<ThreadId>,
}

impl Windows {
    /// Write an empty registry at `windows`, field by field (by value it would pass through the
    /// stack, which is smaller than it).
    ///
    /// # Safety
    ///
    /// `windows` is valid for writes, aligned, and the records' final address; its previous
    /// contents are overwritten, not dropped.
    pub unsafe fn write_empty(windows: *mut Windows) {
        use core::ptr::addr_of_mut;
        // SAFETY: the caller's contract; every field is written, the arrays element by element.
        unsafe {
            let headers = addr_of_mut!((*windows).pool.headers) as *mut Header;
            let records = addr_of_mut!((*windows).pool.records) as *mut Window;
            for index in 0..WINDOWS {
                headers.add(index).write(Header::DEAD);
                records.add(index).write(Window::EMPTY);
            }
            HandleTable::write_empty(addr_of_mut!((*windows).handles));
            let threads = addr_of_mut!((*windows).threads) as *mut Thread;
            for index in 0..THREADS {
                threads.add(index).write(Thread::EMPTY);
            }
            let desktops = addr_of_mut!((*windows).desktops) as *mut Desktop;
            for index in 0..DESKTOPS {
                desktops.add(index).write(Desktop::EMPTY);
            }
            let monitors = addr_of_mut!((*windows).monitors) as *mut Monitor;
            for index in 0..MONITORS {
                monitors.add(index).write(Monitor::EMPTY);
            }
            addr_of_mut!((*windows).clipboard_owner).write(None);
            addr_of_mut!((*windows).foreground_thread).write(None);
        }
    }

    // --- The wiring the other slices own
    // ------------------------------------------------------------

    /// Add a thread's context record: its process, desktop, desktop access and whether it has a
    /// desktop handle yet. Its index is the thread id.
    pub fn add_thread(
        &mut self,
        process: class::Owner,
        desktop: u32,
        desktop_access: u32,
        desktop_handle: Option<Hwnd>,
        monitor: Option<u16>,
    ) -> Option<ThreadId> {
        let index = self.threads.iter().position(|t| !t.live)?;
        self.threads[index] = Thread {
            live: true,
            process,
            desktop,
            desktop_handle,
            desktop_access,
            monitor,
            ..Thread::EMPTY
        };
        Some(ThreadId(index as u16))
    }

    /// The record of the process thread `key`, made at its first win32k service: the one it has,
    /// or a fresh one for the process `process` on the desktop `desktop`, through the desktop
    /// handle `desktop_handle` with the access `desktop_access`. A record an ended thread of the
    /// same slot left is reused when it holds no windows (nothing ends a thread's record yet).
    /// None when every record is taken.
    pub fn connect_thread(
        &mut self,
        key: ThreadKey,
        process: class::Owner,
        desktop: u32,
        desktop_access: u32,
        desktop_handle: Hwnd,
    ) -> Option<ThreadId> {
        if let Some(index) = self
            .threads
            .iter()
            .position(|t| t.live && t.key == Some(key))
        {
            return Some(ThreadId(index as u16));
        }
        let ended = self.threads.iter().position(|t| {
            t.live && t.window_count == 0 && t.key.is_some_and(|k| k.index == key.index)
        });
        if let Some(index) = ended {
            self.threads[index].live = false;
        }
        let id = self.add_thread(process, desktop, desktop_access, Some(desktop_handle), None)?;
        self.thread_mut(id).key = Some(key);
        Some(id)
    }

    /// Wire a desktop's window and message window (the window-station side's call).
    pub fn set_desktop(
        &mut self,
        id: u32,
        window: Option<WindowId>,
        message_window: Option<WindowId>,
    ) {
        let slot = self
            .desktops
            .iter_mut()
            .find(|d| d.id == 0 || d.id == id)
            .expect("a free desktop slot");
        *slot = Desktop {
            id,
            window,
            message_window,
            ..Desktop::EMPTY
        };
    }

    /// Set a monitor's rectangle (the display side's call).
    pub fn set_monitor(&mut self, index: u16, rect: Rect) {
        self.monitors[index as usize].rect = rect;
    }

    // --- Lookups
    // -----------------------------------------------------------------------------------

    fn at(&self, id: WindowId) -> &Window {
        self.pool.at(id)
    }

    fn at_mut(&mut self, id: WindowId) -> &mut Window {
        self.pool.at_mut(id)
    }

    fn thread(&self, id: ThreadId) -> &Thread {
        &self.threads[id.0 as usize]
    }

    fn thread_mut(&mut self, id: ThreadId) -> &mut Thread {
        &mut self.threads[id.0 as usize]
    }

    fn desktop_by_id(&self, id: u32) -> Option<&Desktop> {
        self.desktops.iter().find(|d| d.id == id)
    }

    fn desktop_by_id_mut(&mut self, id: u32) -> Option<&mut Desktop> {
        self.desktops.iter_mut().find(|d| d.id == id)
    }

    /// The window a handle names, when the handle is live (its record's generation matches);
    /// none otherwise — the handle validation the destroy service runs.
    pub fn window_from_handle(&self, handle: Hwnd) -> Option<WindowId> {
        let entry = self.handles.lookup(handle)?;
        self.pool.is_live(entry.id).then_some(entry.id)
    }

    /// The handle of `id` (0 for none).
    pub fn handle_of(&self, id: WindowId) -> Hwnd {
        self.pool.at(id).handle
    }

    /// The message window of the thread `thread`'s desktop: the parent HWND_MESSAGE names.
    pub fn message_window(&self, thread: ThreadId) -> Option<WindowId> {
        self.desktop_by_id(self.thread(thread).desktop)
            .and_then(|d| d.message_window)
    }

    // --- The class registry's view
    // ------------------------------------------------------------------------

    /// The window `handle` names, as the class-change services see it: its class, its process and
    /// its desktop. None for a handle naming no live window, or a window without a class.
    pub fn class_window(&self, handle: Hwnd) -> Option<class::Window> {
        let w = self.at(self.window_from_handle(handle)?);
        Some(class::Window {
            class: w.class?,
            owner: w.process,
            desktop: w.desktop,
        })
    }

    /// The window `handle` names, as the icon-change notification visits it. The records carry no
    /// drag-icon query flag and no small-icon property yet (the property list and the painting
    /// land later), so neither is set.
    pub fn class_view(&self, handle: Hwnd) -> Option<class::WindowView> {
        Some(view_of(self.class_window(handle)?.class))
    }

    /// Every live window with a class, as the icon-change notification visits them, into `views`
    /// (the caller's buffer, an entry a window); the answer is how many were written. The
    /// notification picks the changed class's own out of them.
    pub fn class_views(&self, views: &mut [class::WindowView]) -> usize {
        let live = self
            .pool
            .headers
            .iter()
            .zip(&self.pool.records)
            .filter(|(header, _)| header.live)
            .filter_map(|(_, record)| record.class);
        let mut written = 0;
        for (view, class) in views.iter_mut().zip(live) {
            *view = view_of(class);
            written += 1;
        }
        written
    }
}

/// A window of the class `class` as the icon-change notification sees it (see
/// [`Windows::class_view`]).
fn view_of(class: class::ClassId) -> class::WindowView {
    class::WindowView {
        class,
        query_drag_icon: false,
        has_own_icon_sm: false,
    }
}

// --- The decision logic
// ---------------------------------------------------------------------------

/// Whether `value` is one of the two CW_USEDEFAULT markers.
fn is_default_position(value: i32) -> bool {
    value == CW_USEDEFAULT || value == CW_USEDEFAULT_ALT
}

/// Pack a 16-bit low word and high word into a wParam.
fn makelong(lo: u16, hi: u16) -> WParam {
    ((hi as u32) << 16) | lo as u32
}

/// MultDiv: `n * numerator / denominator`, rounded toward zero, in 64 bits.
fn mult_div(n: i32, numerator: i32, denominator: i32) -> i32 {
    (n as i64 * numerator as i64 / denominator as i64) as i32
}

/// The frame and caption metrics the cascade offset uses (the display slice's values).
const CXSIZEFRAME: i32 = 4;
const CYSIZEFRAME: i32 = 4;
const CXSIZE: i32 = 8;
const CYSIZE: i32 = 20;

/// Whether a window of this style/ex-style gets the WS_EX_WINDOWEDGE bit: the dialog-modal
/// frame and the thick frame force it, the static edge forbids it, a caption gets it from a
/// 4.0-or-later app, and a dialog frame always.
fn needs_window_edge(style: u32, ex_style: u32, new_app: bool) -> bool {
    if ex_style & WS_EX_DLGMODALFRAME != 0 {
        true
    } else if ex_style & WS_EX_STATICEDGE != 0 {
        false
    } else if style & WS_THICKFRAME != 0 {
        true
    } else {
        match style & WS_CAPTION {
            WS_DLGFRAME => true,
            WS_CAPTION => new_app,
            _ => false,
        }
    }
}

impl Windows {
    /// The top-level window of `window`: walk up the parent chain while the window is a child.
    fn top_level_window(&self, window: WindowId) -> Option<WindowId> {
        let mut current = Some(window);
        while let Some(w) = current {
            if self.at(w).is_child() {
                current = self.at(w).parent;
            } else {
                return Some(w);
            }
        }
        None
    }

    /// The nested-children limit: the depth of `parent`'s chain plus the depth of `window`'s
    /// subtree (when it has one) must stay within the limit. At a create `window` is the new
    /// window (none yet), so only the parent chain counts.
    fn validate_parent_depth(&self, window: Option<WindowId>, parent: Option<WindowId>) -> bool {
        let mut depth = 1u32;
        let mut current = parent;
        while let Some(w) = current {
            current = self.at(w).parent;
            depth += 1;
        }
        let mut max = depth;
        if let Some(w) = window {
            if self.at(w).child.is_some() {
                max = max.max(self.subtree_depth(w, depth));
            }
        }
        max <= NESTED_WINDOW_LIMIT
    }

    /// The deepest level in `w`'s subtree (its children, theirs, and so on), `depth` being `w`'s
    /// own level. The walk follows the child, sibling and parent links, without recursing.
    fn subtree_depth(&self, w: WindowId, depth: u32) -> u32 {
        let mut max = depth;
        let Some(mut current) = self.at(w).child else {
            return max;
        };
        let mut level = depth + 1;
        loop {
            max = max.max(level);
            if let Some(child) = self.at(current).child {
                current = child;
                level += 1;
                continue;
            }
            // Up to the nearest ancestor below `w` with a next sibling.
            loop {
                if let Some(next) = self.at(current).next {
                    current = next;
                    break;
                }
                current = self.at(current).parent.expect("a child has its parent");
                level -= 1;
                if current == w {
                    return max;
                }
            }
        }
    }

    /// The owner-chain limit: no loop (the new window may not appear in it) and no chain deeper
    /// than the limit.
    fn validate_owner_depth(&self, window: WindowId, owner: Option<WindowId>) -> bool {
        let mut depth = 1u32;
        let mut current = owner;
        while let Some(w) = current {
            if w == window {
                return false;
            }
            current = self.at(w).owner;
            depth += 1;
            if depth > NESTED_WINDOW_LIMIT {
                return false;
            }
        }
        true
    }

    /// The cascade default rect for a tiled window on `monitor`: 3/4 by 3/4 of the work area,
    /// offset by the monitor's window-stack counter (reset when the offset leaves the top-left
    /// quarter of the work area), and the counter moves on.
    fn set_tiled_rect(&mut self, rc: &mut Rect, monitor: u16) {
        let work = self.monitors[monitor as usize].rect;
        let mut x = self.monitors[monitor as usize].window_stack * (CXSIZEFRAME + CXSIZE);
        let mut y = self.monitors[monitor as usize].window_stack * (CYSIZEFRAME + CYSIZE);
        if x > (work.right - work.left) / 4 || y > (work.bottom - work.top) / 4 {
            self.monitors[monitor as usize].window_stack = 0;
            x = 0;
            y = 0;
        }
        x += work.left;
        y += work.top;
        rc.left = x;
        rc.top = y;
        rc.right = x + mult_div(work.right - work.left, 3, 4);
        rc.bottom = y + mult_div(work.bottom - work.top, 3, 4);
        self.monitors[monitor as usize].window_stack += 1;
    }

    /// The min/max-track clamp: a tiled or thick-framed window's size is clamped into the
    /// min/max track (the reserved/max size while minimized).
    fn adjust_size(&mut self, id: WindowId, pump: &mut dyn Pump, cx: &mut i32, cy: &mut i32) {
        let (tiled, sizebox, minimized) = {
            let w = self.at(id);
            (
                w.is_tiled(),
                w.style & WS_THICKFRAME != 0,
                w.style & WS_MINIMIZE != 0,
            )
        };
        if tiled || sizebox {
            let mmi = pump.min_max_info(self, id);
            let (min, max) = if minimized {
                (mmi.reserved, mmi.max_size)
            } else {
                (mmi.min_track, mmi.max_track)
            };
            *cx = min.0.max((*cx).min(max.0));
            *cy = min.1.max((*cy).min(max.1));
        }
    }

    /// Splice `id` into `parent`'s child list at `z`: at the top (the new head), at the bottom
    /// (after the last sibling before any bottom-most window), or directly after a window.
    fn link_window(&mut self, id: WindowId, z: ZOrder, parent: WindowId) {
        if self.at(parent).child == Some(id) {
            // Attempting to link a window to itself.
            return;
        }
        match z {
            ZOrder::Top => self.link_top(id, parent),
            ZOrder::Bottom => {
                // Find the bottom-most window: the last sibling before any bottom-most one.
                let mut insert = self.at(parent).child;
                let link_top = match insert {
                    None => true,
                    Some(first) => self.at(first).flags.bottommost,
                };
                if !link_top {
                    while let Some(next) = insert.and_then(|i| self.at(i).next) {
                        if self.at(next).flags.bottommost {
                            break;
                        }
                        insert = Some(next);
                    }
                }
                match insert {
                    Some(after) => {
                        let next = self.at(after).next;
                        self.at_mut(id).next = next;
                        self.at_mut(after).next = Some(id);
                    }
                    None => self.link_top(id, parent),
                }
            }
            ZOrder::After(after) => {
                let next = self.at(after).next;
                self.at_mut(id).next = next;
                self.at_mut(after).next = Some(id);
            }
        }
    }

    /// Link `id` at the head of `parent`'s child list.
    fn link_top(&mut self, id: WindowId, parent: WindowId) {
        let head = self.at(parent).child;
        self.at_mut(id).next = head;
        self.at_mut(parent).child = Some(id);
    }

    /// Splice `id` out of `parent`'s child list (the head case or a mid-list walk); a window
    /// that is not in the list is tolerated.
    fn unlink_window(&mut self, id: WindowId, parent: WindowId) {
        if self.at(parent).child == Some(id) {
            let next = self.at(id).next;
            self.at_mut(parent).child = next;
            self.at_mut(id).next = None;
            return;
        }
        let mut current = self.at(parent).child;
        while let Some(c) = current {
            if self.at(c).next == Some(id) {
                let next = self.at(id).next;
                self.at_mut(c).next = next;
                self.at_mut(id).next = None;
                return;
            }
            current = self.at(c).next;
        }
        // Unlinking a window that is not in the list.
    }

    // --- Create
    // --------------------------------------------------------------------------------------

    /// The creation decision logic: validate, resolve the class, allocate and wire the record,
    /// position it, and run the message sequence. The answer is the new window's id; the
    /// service answers its handle.
    #[allow(clippy::too_many_arguments)]
    pub fn create_window_ex(
        &mut self,
        classes: &mut class::Registry,
        caller: ThreadId,
        args: &CreateArgs,
        pump: &mut dyn Pump,
    ) -> Result<WindowId, Failure> {
        // The private ANSI-creator bit is consumed here, never stored on the window.
        let ansi_creator = args.ex_style & ANSI_CREATOR_BIT != 0;
        let mut ex_style = args.ex_style & !ANSI_CREATOR_BIT;

        let (process, desktop_id) = {
            let thread = self.thread(caller);
            (thread.process, thread.desktop)
        };

        // A parent on another desktop is refused before anything else is looked at.
        if let Some(parent) = args.parent {
            if self.at(parent).desktop != desktop_id {
                return Err(Failure::InvalidParameter);
            }
        }

        let child = kind_of(args.style) == Kind::Child;

        // The desktop access check. It is skipped while the thread has no desktop handle yet:
        // that is the root desktop window's own creation.
        {
            let thread = self.thread(caller);
            if thread.desktop_handle.is_some() && thread.desktop_access & DESKTOP_CREATEWINDOW == 0
            {
                return Err(Failure::AccessDenied);
            }
        }

        // A child window needs a parent, and the parent chain has a depth limit.
        if child {
            let Some(parent) = args.parent else {
                return Err(Failure::TlwWithWsChild);
            };
            if !self.validate_parent_depth(None, Some(parent)) {
                return Err(Failure::InvalidParameter);
            }
        }

        // Class resolution: atom 0 (a string name with no atom) fails, and so does a class the
        // calling process cannot see. A null module looks classes up as the client module.
        let atom = args.class_atom;
        if atom == 0 {
            return Err(Failure::CannotFindWindowClass);
        }
        let module = if args.instance == 0 {
            class::CLIENT_MODULE
        } else {
            args.instance
        };
        let Some(class_id) = classes.class_ptr(atom, process, module) else {
            return Err(Failure::CannotFindWindowClass);
        };
        let info = classes
            .get_class_info(class::Name::Atom(atom), Some(module), process, true)
            .map_err(|_| Failure::CannotFindWindowClass)?;

        // The edge style decision.
        let compat = VersionCompat::of(args.version);
        if needs_window_edge(args.style, ex_style, compat.win40) {
            ex_style |= WS_EX_WINDOWEDGE;
        } else {
            ex_style &= !WS_EX_WINDOWEDGE;
        }

        // The record and its handle.
        let Some(id) = self.pool.allocate() else {
            return Err(Failure::OutOfMemory);
        };
        let handle = self.handles.insert(WindowEntry {
            id,
            owner: caller,
            marked_destroy: false,
            in_destroy: false,
        });
        if handle == 0 {
            self.pool.free(id);
            return Err(Failure::OutOfMemory);
        }
        {
            let monitor = self.thread(caller).monitor.unwrap_or(PRIMARY_MONITOR);
            let w = self.at_mut(id);
            w.handle = handle;
            w.thread = caller;
            w.process = process;
            w.desktop = desktop_id;
            w.monitor = monitor;
            w.style = args.style & !WS_VISIBLE; // WS_VISIBLE is stripped from the stored style
            w.ex_style = ex_style & !WS_EX_LAYERED; // so is the layered bit
            w.class = Some(class_id);
            w.cb_wnd_extra = info.cb_wnd_extra;
            w.locks = 1;
        }

        // The class reference (a class of another desktop is cloned for the window; a clone
        // failure frees the record and takes the class failure path).
        let mut view = class::Window {
            class: class_id,
            owner: process,
            desktop: desktop_id,
        };
        if !classes.reference_class(class_id, &mut view) {
            self.handles.close(handle);
            self.pool.free(id);
            return Err(Failure::CannotFindWindowClass);
        }
        self.at_mut(id).class = Some(view.class);

        // The window count goes up early, so the failure paths keep it correct through the free.
        self.thread_mut(caller).window_count += 1;

        // The create parameters the WM_NCCREATE and WM_CREATE handlers see.
        let mut params = CreateParams {
            ex_style,
            class_name: match args.class_name {
                class::Name::Atom(a) => ClassArg::Atom(a),
                class::Name::Text(_) if ansi_creator => ClassArg::AnsiName,
                class::Name::Text(_) => ClassArg::Name,
            },
            name: TextBuf::from_units(args.name),
            style: args.style,
            x: args.x,
            y: args.y,
            cx: args.cx,
            cy: args.cy,
            parent: args.parent.map_or(0, |p| self.at(p).handle),
            menu: if child {
                args.menu.raw()
            } else {
                args.menu.handle()
            },
            instance: args.instance,
            params: args.params,
        };

        // While callbacks run the parent pointer is the desktop's message window, so a parent
        // always exists.
        let desktop = self.desktop_by_id(desktop_id);
        let desktop_window = desktop.and_then(|d| d.window);
        let message_window = desktop.and_then(|d| d.message_window);
        self.at_mut(id).parent = message_window;

        // The module and the window procedure are stored before any callback.
        {
            let w = self.at_mut(id);
            w.module = args.instance;
            w.proc = Proc::Client(info.wnd_proc);
        }
        {
            let w = self.at_mut(id);
            w.flags.ansi_creator = ansi_creator;
            w.flags.win31_compat = compat.win31;
            w.flags.win40_compat = compat.win40;
        }

        // A hook can veto the creation outright.
        if pump.cbt_create_veto(self, classes, id, &mut params) {
            self.rollback_create(classes, caller, id, pump);
            return Err(Failure::OutOfMemory);
        }

        let mut z_order = ZOrder::Top;
        let tiled = self.at(id).kind() == Kind::Tiled;

        // CW_USEDEFAULT is honored only by tiled (overlapped) windows; elsewhere it zeroes.
        let (mut x, mut y, mut cx, mut cy) = (args.x, args.y, args.cx, args.cy);
        if !tiled {
            if is_default_position(x) {
                x = 0;
                y = 0;
            }
            if is_default_position(cx) {
                cx = 0;
                cy = 0;
            }
        }
        let mut src = SizeRect { x, y, cx, cy };
        let mut sw = SW_SHOW;

        // Children are positioned in the parent's client coordinates and stack at the bottom.
        if child {
            if let Some(parent) = args.parent {
                if Some(parent) != desktop_window {
                    let p = self.at(parent);
                    src.x += p.client_rect.left;
                    src.y += p.client_rect.top;
                }
            }
            z_order = ZOrder::Bottom;
        }

        // Tiled windows: forced styles and the cascade positioning decisions.
        let mut def_pos = false;
        let mut startup = false;
        let mut rc = Rect::default();
        if tiled {
            {
                let w = self.at_mut(id);
                w.style |= WS_CLIPSIBLINGS;
                if w.flags.win40_compat {
                    w.ex_style |= WS_EX_WINDOWEDGE;
                }
                // Size/move are deferred to show time.
                w.flags.sendsizemove = true;
            }
            // When x is default, y doubles as the show command.
            if is_default_position(x) && !is_default_position(y) {
                sw = y;
            }
            // The monitor: the thread's, else the parent's, else the primary.
            let monitor = self
                .thread(caller)
                .monitor
                .or_else(|| args.parent.map(|p| self.at(p).monitor))
                .unwrap_or(PRIMARY_MONITOR);
            self.set_tiled_rect(&mut rc, monitor);
            if is_default_position(x) {
                // Default positioning: the startup info, else the cascade rect.
                let usi = self.thread(caller).startup;
                if usi.flags & STARTF_USEPOSITION != 0 {
                    startup = true;
                    x = usi.x as i32;
                    src.x = x;
                    y = usi.y as i32;
                    src.y = y;
                } else {
                    x = rc.left;
                    src.x = x;
                    y = rc.top;
                    src.y = y;
                }
                def_pos = true;
            } else if self.monitors[monitor as usize].window_stack > 0 {
                // An app-specified position undoes the cascade's stacking effect.
                self.monitors[monitor as usize].window_stack -= 1;
            }
            if is_default_position(src.cx) {
                // Default sizing: the startup info, else fill the cascade rect.
                let usi = self.thread(caller).startup;
                if usi.flags & STARTF_USESIZE != 0 {
                    startup = true;
                    src.cx = usi.cx as i32;
                    src.cy = usi.cy as i32;
                } else {
                    src.cx = rc.right - x;
                    src.cy = rc.bottom - y;
                }
            } else if def_pos {
                // A default position with an app size: keep the window inside the monitor.
                let m = self.monitors[monitor as usize].rect;
                let dx = (src.x + src.cx) - m.right;
                let dy = (src.y + src.cy) - m.bottom;
                if dx > 0 {
                    x -= dx;
                    src.x = x;
                    if src.x < m.left {
                        src.x = m.left;
                        x = src.x;
                    }
                }
                if dy > 0 {
                    y -= dy;
                    src.y = y;
                    if src.y < m.top {
                        src.y = m.top;
                        y = src.y;
                    }
                }
            }
        }
        // The startup info is used once.
        if startup {
            self.thread_mut(caller).startup.flags &= !(STARTF_USESIZE | STARTF_USEPOSITION);
        }

        // Popup windows clip their siblings (the desktop window excepted).
        if self.at(id).kind() == Kind::Popup && Some(id) != desktop_window {
            self.at_mut(id).style |= WS_CLIPSIBLINGS;
        }

        // The forced caption/border bits go into the style's high word.
        if tiled {
            self.at_mut(id).style |= WS_CAPTION | WS_BORDER;
        }

        // The class menu when no menu was given (top-level windows only); a load failure is
        // tolerated and leaves the window without a menu.
        let mut menu = args.menu;
        if !child && menu.is_none() && info.menu_name != class::MenuName::None {
            if let Some(handle) = pump.load_class_menu(info.instance, &info.menu_name) {
                menu = MenuInput::Handle(handle);
                params.menu = handle;
            }
        }
        self.at_mut(id).menu = if child {
            menu.as_child_menu()
        } else {
            menu.as_window_menu()
        };

        // Owner and parent wiring for top-level windows: the owner is the parent's top-level
        // window; the parent itself becomes the desktop window (a message-window parent stays).
        let mut parent = args.parent;
        if !child {
            {
                let w = self.at_mut(id);
                w.last_active = Some(id);
                w.owner = None;
            }
            if let Some(p) = parent {
                if Some(p) != message_window && Some(p) != desktop_window {
                    let owner = self.top_level_window(p);
                    if !self.validate_owner_depth(id, owner) {
                        self.rollback_create(classes, caller, id, pump);
                        return Err(Failure::OutOfMemory);
                    }
                    {
                        let owner_topmost =
                            owner.is_some_and(|o| self.at(o).ex_style & WS_EX_TOPMOST != 0);
                        let w = self.at_mut(id);
                        w.owner = owner;
                        // A window must sit above a topmost owner.
                        if owner_topmost {
                            w.ex_style |= WS_EX_TOPMOST;
                        }
                    }
                    // An owner on another thread shares input state.
                    if let Some(o) = owner {
                        let owner_thread = self.at(o).thread;
                        if owner_thread != caller {
                            pump.attach_input(caller, owner_thread, true);
                        }
                    }
                }
            }
            if parent.is_none() || parent != message_window {
                parent = desktop_window;
            }
        }
        if let Some(p) = parent {
            self.at_mut(id).parent = Some(p);
        }

        // The CS_PARENTDC compat hack (skipped for pre-4.0 windows): the class style overrides
        // the clip bits unless the parent clips children.
        if !self.at(id).flags.win31_compat && info.style & class::CS_PARENTDC != 0 {
            if let Some(p) = parent {
                if self.at(p).style & WS_CLIPCHILDREN == 0 {
                    let w = self.at_mut(id);
                    w.style &= !(WS_CLIPCHILDREN | WS_CLIPSIBLINGS);
                }
            }
        }

        // A child of another thread's parent shares input state.
        if child {
            if let Some(p) = parent {
                if Some(p) != desktop_window && self.at(p).thread != caller {
                    let parent_thread = self.at(p).thread;
                    pump.attach_input(caller, parent_thread, true);
                }
            }
        }

        // Size clamping, the full-screen check, negative sizes, and the final window rect.
        self.adjust_size(id, pump, &mut src.cx, &mut src.cy);
        if !child && ex_style & WS_EX_TOOLWINDOW == 0 {
            pump.check_full_screen(self, id, &mut src);
        }
        if src.cx < 0 {
            src.cx = 0;
        }
        if src.cy < 0 {
            src.cy = 0;
        }
        {
            let w = self.at_mut(id);
            w.window_rect = Rect {
                left: src.x,
                top: src.y,
                right: src.x + src.cx,
                bottom: src.y + src.cy,
            };
        }

        // Layered windows and class/own DCs: a failure rolls the creation back.
        if ex_style & WS_EX_LAYERED != 0 && !pump.set_layered(self, id) {
            self.rollback_create(classes, caller, id, pump);
            return Err(Failure::OutOfMemory);
        }
        if info.style & (class::CS_OWNDC | class::CS_CLASSDC) != 0
            && !pump.create_window_dc(self, id, info.style & class::CS_OWNDC != 0)
        {
            self.rollback_create(classes, caller, id, pump);
            return Err(Failure::OutOfMemory);
        }

        // The create parameters carry the final position.
        params.x = x;
        params.y = y;
        params.cx = cx;
        params.cy = cy;

        // WM_NCCREATE first: a zero answer rolls the whole creation back.
        let mut message = Message {
            message: WM_NCCREATE,
            wparam: 0,
            lparam: 0,
            payload: Payload::Create(params),
        };
        if pump.send(self, classes, id, &mut message) == 0 {
            self.rollback_create(classes, caller, id, pump);
            return Err(Failure::OutOfMemory);
        }
        let Payload::Create(mut params) = message.payload else {
            unreachable!("the payload came back whole")
        };

        // WM_NCCREATE may have set the window text: the name WM_CREATE sees is refreshed from
        // the record, except when the original name was empty and the text never got set.
        {
            let w = self.at(id);
            if w.flags.title_set && !(params.name.is_empty() && w.title.is_empty()) {
                params.name = w.title;
            }
        }

        // Link the window into its parent's child list (the z-order decision for top-levels:
        // a non-topmost window does not go on top of the topmost pile).
        if let Some(p) = parent {
            if !child && Some(p) != message_window {
                let topmost_pile = match z_order {
                    ZOrder::Top => true,
                    ZOrder::After(after) => self.at(after).ex_style & WS_EX_TOPMOST != 0,
                    ZOrder::Bottom => false,
                };
                if self.at(id).ex_style & WS_EX_TOPMOST == 0 && topmost_pile {
                    z_order = pump.foreground_insert_after(self, id);
                }
            }
            self.link_window(id, z_order, p);
        }

        // WM_NCCALCSIZE: the client rect (no frame in the minimal subset: client == window).
        let window_rect = self.at(id).window_rect;
        let mut message = Message {
            message: WM_NCCALCSIZE,
            wparam: 0,
            lparam: 0,
            payload: Payload::Rect(window_rect),
        };
        pump.send(self, classes, id, &mut message);
        if let Payload::Rect(r) = message.payload {
            self.at_mut(id).client_rect = r;
        }

        // WM_CREATE: a -1 answer destroys the window for real and fails the create.
        let mut message = Message {
            message: WM_CREATE,
            wparam: 0,
            lparam: 0,
            payload: Payload::Create(params),
        };
        if pump.send(self, classes, id, &mut message) == -1 {
            let _ = self.destroy_window(classes, caller, id, pump);
            return Err(Failure::OutOfMemory);
        }

        // The window is officially created.
        self.at_mut(id).flags.initialized = true;

        // WM_SIZE/WM_MOVE, unless they are deferred to show time (tiled windows).
        if !self.at(id).flags.sendsizemove {
            pump.send_size(self, classes, id, SIZENORMAL);
            let mut rc = self.at(id).client_rect;
            if let Some(p) = parent {
                if Some(p) != desktop_window {
                    // WM_MOVE's position is client-relative for children.
                    let pc = self.at(p).client_rect;
                    rc.left -= pc.left;
                    rc.top -= pc.top;
                }
            }
            pump.send(
                self,
                classes,
                id,
                &mut Message {
                    message: WM_MOVE,
                    wparam: 0,
                    lparam: makelong(rc.left as u16, rc.top as u16) as LParam,
                    payload: Payload::None,
                },
            );
        }

        // Min/max setup.
        if self.at(id).style & WS_MINIMIZE != 0 {
            pump.min_maximize(self, id, SW_SHOWMINNOACTIVE as u32);
        } else if self.at(id).style & WS_MAXIMIZE != 0 {
            self.at_mut(id).style &= !WS_MAXIMIZE;
            pump.min_maximize(self, id, SW_SHOWMAXIMIZED as u32);
        }

        // Children tell their parent about the create.
        if child && self.at(id).ex_style & WS_EX_NOPARENTNOTIFY == 0 {
            if let Some(p) = self.at(id).parent {
                let (menu_id, handle) = {
                    let w = self.at(id);
                    (w.menu.id().unwrap_or(0), w.handle)
                };
                pump.send(
                    self,
                    classes,
                    p,
                    &mut Message {
                        message: WM_PARENTNOTIFY,
                        wparam: makelong(WM_CREATE as u16, menu_id),
                        lparam: handle as LParam,
                        payload: Payload::None,
                    },
                );
            }
        }

        // A window created with WS_VISIBLE is shown last.
        if args.style & WS_VISIBLE != 0 {
            pump.show(self, id, sw as u32);
        }

        // The process's hotkey lands on the first tiled/APPWINDOW window.
        if tiled || ex_style & WS_EX_APPWINDOW != 0 {
            let hotkey = self.thread(caller).hotkey;
            if hotkey != 0 {
                pump.send(
                    self,
                    classes,
                    id,
                    &mut Message {
                        message: WM_SETHOTKEY,
                        wparam: hotkey,
                        lparam: 0,
                        payload: Payload::None,
                    },
                );
                self.thread_mut(caller).hotkey = 0;
            }
        }

        Ok(id)
    }

    /// The shared rollback path of the create's failure points: mark the window destroyed, make
    /// sure it is not treated as visible, and free it (which sends WM_NCDESTROY, destroys any
    /// children, dereferences the class, drops the window count and frees the record and handle;
    /// no WM_DESTROY is sent — the window was never linked).
    fn rollback_create(
        &mut self,
        classes: &mut class::Registry,
        caller: ThreadId,
        id: WindowId,
        pump: &mut dyn Pump,
    ) {
        {
            let w = self.at_mut(id);
            w.flags.destroyed = true;
            w.style &= !WS_VISIBLE;
        }
        self.free_window(classes, caller, id, pump);
    }

    // --- Destroy
    // -------------------------------------------------------------------------------------

    /// The destroy decision logic for the window `window`. Only the owning thread may destroy
    /// a window (unless it is already marked for destruction: then the current thread adopts it
    /// and the destroy proceeds). The answer says whether the destroy ran; a hook's veto answers
    /// false with the window untouched.
    ///
    /// A window's destroy is its prologue ([`Windows::destroy_prologue`]: the input sharing's
    /// end, the parent notify, the hide), then the destroy of every window it owns, each in full,
    /// then its epilogue ([`Windows::destroy_epilogue`]: the activation fixups, WM_DESTROY to it
    /// and its children, the unlink and the free). The owned windows' destroys nest — each
    /// destroys its own owned windows first — and the cascade descends the owner chain through
    /// the records rather than by recursing (see [`Walk`]).
    pub fn destroy_window(
        &mut self,
        classes: &mut class::Registry,
        caller: ThreadId,
        window: WindowId,
        pump: &mut dyn Pump,
    ) -> Result<bool, Failure> {
        if !self.begin_destroy(caller, window, pump)? {
            return Ok(false);
        }
        self.destroy_prologue(classes, window, pump);
        let mut current = window;
        loop {
            // The windows `current` owns are destroyed before its own WM_DESTROY.
            if let Some(owned) = self.next_owned_window(current) {
                match self.begin_destroy(caller, owned, pump) {
                    Ok(true) => {
                        self.at_mut(owned).walk.owner = Some(current);
                        self.destroy_prologue(classes, owned, pump);
                        current = owned;
                    }
                    // One that cannot be destroyed loses its owner (a vetoed one included: the
                    // scan would find it again otherwise).
                    Ok(false) | Err(_) => self.at_mut(owned).owner = None,
                }
                continue;
            }
            let walk = self.at(current).walk;
            self.destroy_epilogue(classes, caller, current, walk.already, pump);
            if let Some(saved) = walk.saved_hooks {
                self.thread_mut(caller).hooks_disabled = saved;
            }
            match walk.owner {
                Some(owner) => current = owner,
                None => return Ok(true),
            }
        }
    }

    /// The destroy service over a handle: the handle validation first (an invalid handle is
    /// ERROR_INVALID_WINDOW_HANDLE), then the destroy.
    pub fn destroy_window_handle(
        &mut self,
        classes: &mut class::Registry,
        caller: ThreadId,
        handle: Hwnd,
        pump: &mut dyn Pump,
    ) -> Result<bool, Failure> {
        let Some(window) = self.window_from_handle(handle) else {
            return Err(Failure::InvalidWindowHandle);
        };
        self.destroy_window(classes, caller, window, pump)
    }

    /// The entry checks of `window`'s destroy: its handle must still name it, and only its thread
    /// may destroy it — unless it is marked for destruction already, when the calling thread
    /// adopts it (a re-entry, which runs with the thread's hooks disabled until its end). A hook
    /// can veto a first destroy: false, the window untouched. The re-entry state goes into the
    /// window's walk, for the epilogue.
    fn begin_destroy(
        &mut self,
        caller: ThreadId,
        window: WindowId,
        pump: &mut dyn Pump,
    ) -> Result<bool, Failure> {
        let handle = self.at(window).handle;
        let Some(entry) = self.handles.lookup(handle) else {
            return Err(Failure::InvalidWindowHandle);
        };
        let already = entry.marked_destroy;
        if already {
            // The re-entry path: adopt the current thread as the owner.
            if entry.owner != caller {
                self.handles.update(handle, |mut e| {
                    e.owner = caller;
                    e
                });
                self.at_mut(window).thread = caller;
            }
        } else if self.at(window).thread != caller {
            return Err(Failure::AccessDenied);
        }
        // A hook can veto a first destroy.
        let vetoed = !already
            && {
                let t = self.thread(caller);
                !t.in_cleanup && !t.hooks_disabled
            }
            && pump.cbt_destroy_veto(self, window);
        if vetoed {
            return Ok(false);
        }
        // Hooks are disabled for the duration of a re-entry's destroy.
        let saved_hooks = if already {
            let t = self.thread_mut(caller);
            let saved = t.hooks_disabled;
            t.hooks_disabled = true;
            Some(saved)
        } else {
            None
        };
        self.at_mut(window).walk = Walk {
            already,
            saved_hooks,
            ..Walk::NONE
        };
        Ok(true)
    }

    /// The first part of `window`'s destroy, before the windows it owns go: a cross-thread
    /// owner's input sharing ends, a child tells its parent, and the window is hidden before
    /// anything is messaged.
    fn destroy_prologue(
        &mut self,
        classes: &mut class::Registry,
        window: WindowId,
        pump: &mut dyn Pump,
    ) {
        // A cross-thread owner's input sharing ends here.
        {
            let w = self.at(window);
            if !w.is_child() {
                if let Some(o) = w.owner {
                    let owner_thread = self.at(o).thread;
                    if owner_thread != w.thread {
                        pump.attach_input(w.thread, owner_thread, false);
                    }
                }
            }
        }

        // A child tells its parent about the destroy before anything else happens to it.
        {
            let w = self.at(window);
            if w.is_child() && w.ex_style & WS_EX_NOPARENTNOTIFY == 0 {
                if let Some(p) = w.parent {
                    let (menu_id, handle) = (w.menu.id().unwrap_or(0), w.handle);
                    pump.send(
                        self,
                        classes,
                        p,
                        &mut Message {
                            message: WM_PARENTNOTIFY,
                            wparam: makelong(WM_DESTROY as u16, menu_id),
                            lparam: handle as LParam,
                            payload: Payload::None,
                        },
                    );
                }
            }
        }

        // Mark in-destroy (the mother desktop window excepted), then hide before anything is
        // messaged.
        if self.at(window).parent.is_some() {
            self.at_mut(window).flags.in_destroy = true;
        }
        if self.at(window).is_visible() {
            if self.at(window).is_child() {
                pump.show(self, window, SW_HIDE as u32);
            } else {
                // Hide without activating anyone else or moving/resizing/reordering.
                pump.set_window_pos(
                    self,
                    window,
                    SWP_HIDEWINDOW | SWP_NOACTIVATE | SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER,
                );
            }
            if self.at(window).is_visible() {
                // The hide did not take: force the bit off and redraw what was below.
                self.at_mut(window).style &= !WS_VISIBLE;
                pump.redraw_below(self, window);
            }
        }
    }

    /// The first window `owner` owns on its desktop window's child list, scanning from the head
    /// (each destroy restarts the scan: callbacks may have created or reordered windows); none
    /// for a child window, which owns none.
    fn next_owned_window(&self, owner: WindowId) -> Option<WindowId> {
        if self.at(owner).is_child() {
            return None;
        }
        let desktop_window = self
            .desktop_by_id(self.at(owner).desktop)
            .and_then(|d| d.window)?;
        let mut current = self.at(desktop_window).child;
        while let Some(w) = current {
            if self.at(w).owner == Some(owner) {
                return Some(w);
            }
            current = self.at(w).next;
        }
        None
    }

    /// The last part of `window`'s destroy, once the windows it owned are gone: the activation
    /// fixups and the destroy messages (both skipped on the re-entry path, `already`), the
    /// unlink, and the free.
    fn destroy_epilogue(
        &mut self,
        classes: &mut class::Registry,
        caller: ThreadId,
        window: WindowId,
        already: bool,
        pump: &mut dyn Pump,
    ) {
        let desktop_window = self
            .desktop_by_id(self.at(window).desktop)
            .and_then(|d| d.window);

        // Activation fixups (skipped on the re-entry path).
        if !already {
            let mut target = None;
            let mut command = Activate::Skip;
            {
                let t = self.thread(caller);
                if t.active == Some(window) {
                    let w = self.at(window);
                    if w.is_popup() && w.owner.is_some() {
                        // A popup: try its creator.
                        target = w.owner;
                        command = Activate::Try;
                    } else {
                        // Skip to the next window.
                        target = Some(window);
                        command = Activate::Skip;
                    }
                } else if t.active.is_none() && self.foreground_thread == Some(caller) {
                    target = Some(window);
                    command = Activate::Skip;
                }
            }
            if let Some(t) = target {
                let ok = pump.activate(self, t, command);
                if !ok || (command == Activate::Skip && self.thread(caller).active == Some(window))
                {
                    let t = self.thread_mut(caller);
                    t.active = None;
                    t.focus = None;
                    pump.destroy_caret();
                }
            }
            // Fix the owner chain's last-active popup: repoint it to the direct owner.
            let owner = self.at(window).owner;
            if let Some(o) = owner {
                let mut root = o;
                while let Some(n) = self.at(root).owner {
                    root = n;
                }
                if self.at(root).last_active == Some(window) {
                    self.at_mut(root).last_active = Some(o);
                }
            }
        }

        // The destroy messages (skipped on the re-entry path).
        if !already {
            self.send_destroy_messages(classes, window, pump);
        }

        // Unlink from the parent's child list (the re-entry path leaves the list alone).
        if let Some(p) = self.at(window).parent {
            if !already {
                let w = self.at(window);
                if w.is_child() && Some(p) != desktop_window && self.at(p).thread != w.thread {
                    let parent_thread = self.at(p).thread;
                    pump.attach_input(w.thread, parent_thread, false);
                }
                self.unlink_window(window, p);
            }
        }

        // Mark destroyed (the owner field stays valid for handlers).
        self.at_mut(window).flags.destroyed = true;

        // Free it.
        self.free_window(classes, caller, window, pump);
    }

    /// The WM_DESTROY cascade: the window itself first, then its children depth-first (parents
    /// assume their children still exist during WM_DESTROY), each window's focus check after its
    /// subtree's; a handler that destroys the sibling the walk visits next ends the walk of their
    /// parent's children. The walk follows the child and parent links, the next sibling kept in
    /// the record ([`Walk::next`]).
    fn send_destroy_messages(
        &mut self,
        classes: &mut class::Registry,
        window: WindowId,
        pump: &mut dyn Pump,
    ) {
        self.send_destroy(classes, window, pump);
        let mut current = window;
        let mut descend = true;
        loop {
            if descend {
                if let Some(child) = self.at(current).child {
                    let next = self.at(child).next;
                    self.at_mut(child).walk.next = next;
                    current = child;
                    self.send_destroy(classes, current, pump);
                    continue;
                }
            }
            // `current`'s subtree is done.
            pump.check_focus(self, current);
            if current == window {
                return;
            }
            let parent = self.at(current).parent.expect("a child has its parent");
            // Continue only while the next sibling is still a live child of the parent.
            match self.at_mut(current).walk.next.take() {
                Some(next) if self.pool.is_live(next) && self.at(next).parent == Some(parent) => {
                    let after = self.at(next).next;
                    self.at_mut(next).walk.next = after;
                    current = next;
                    self.send_destroy(classes, current, pump);
                    descend = true;
                }
                _ => {
                    current = parent;
                    descend = false;
                }
            }
        }
    }

    /// One window's step of the WM_DESTROY cascade, before its children's: the focus check, the
    /// clipboard, and WM_DESTROY itself.
    fn send_destroy(
        &mut self,
        classes: &mut class::Registry,
        window: WindowId,
        pump: &mut dyn Pump,
    ) {
        pump.check_focus(self, window);
        if self.clipboard_owner == Some(window) {
            pump.disown_clipboard(self, window);
        }
        pump.send(
            self,
            classes,
            window,
            &mut Message {
                message: WM_DESTROY,
                wparam: 0,
                lparam: 0,
                payload: Payload::None,
            },
        );
    }

    /// The free of `window` and its children: every child is unlinked and marked destroyed; a
    /// same-thread child is freed — its own children first, so each child's WM_NCDESTROY precedes
    /// its parent's — and a cross-thread child gets a destroy event posted to its own queue
    /// instead. The walk descends through the child links and climbs back through the parent
    /// links, which the unlink leaves in place; each record's free is [`Windows::free_record`].
    fn free_window(
        &mut self,
        classes: &mut class::Registry,
        caller: ThreadId,
        window: WindowId,
        pump: &mut dyn Pump,
    ) {
        self.adopt_marked(caller, window);
        let mut current = window;
        loop {
            if let Some(child) = self.at(current).child {
                {
                    let w = self.at_mut(child);
                    // Don't try to hide a child whose parent is dying.
                    w.style &= !WS_VISIBLE;
                    w.flags.destroyed = true;
                }
                self.unlink_window(child, current);
                let child_thread = self.at(child).thread;
                if child_thread != caller {
                    pump.post_destroy_event(child_thread, child);
                } else {
                    self.adopt_marked(caller, child);
                    current = child;
                }
                continue;
            }
            let parent = self.at(current).parent;
            self.free_record(classes, caller, current, pump);
            if current == window {
                return;
            }
            current = parent.expect("a freed child's parent");
        }
    }

    /// A window marked for destruction is adopted by the current thread at its free.
    fn adopt_marked(&mut self, caller: ThreadId, window: WindowId) {
        let handle = self.at(window).handle;
        if self
            .handles
            .lookup(handle)
            .is_some_and(|e| e.marked_destroy)
        {
            self.handles.update(handle, |mut e| {
                e.owner = caller;
                e
            });
            self.at_mut(window).thread = caller;
        }
    }

    /// The free of one window whose children are gone: the cleanup ordering, then the
    /// free-vs-zombie decision. WM_NCDESTROY to this window, then the backpointers, menus,
    /// properties, the class dereference, and the handle marks. The last lock frees the record
    /// and the handle; any other lock count leaves a zombie.
    fn free_record(
        &mut self,
        classes: &mut class::Registry,
        caller: ThreadId,
        window: WindowId,
        pump: &mut dyn Pump,
    ) {
        let handle = self.at(window).handle;

        // WM_NCDESTROY to this window.
        pump.send(
            self,
            classes,
            window,
            &mut Message {
                message: WM_NCDESTROY,
                wparam: 0,
                lparam: 0,
                payload: Payload::None,
            },
        );

        // Clear the owner's last-active if it points at this window.
        let owner = self.at(window).owner;
        if let Some(o) = owner {
            if self.at(o).last_active == Some(window) {
                self.at_mut(o).last_active = Some(o);
            }
        }

        // Clear the queue and desktop backpointers that point at this window.
        {
            let t = self.thread_mut(caller);
            if t.focus == Some(window) {
                t.focus = None;
            }
            if t.active_prev == Some(window) {
                t.active_prev = None;
            }
            if t.capture == Some(window) {
                t.capture = None;
                pump.release_capture(self);
            }
        }
        let desktop_id = self.at(window).desktop;
        if let Some(d) = self.desktop_by_id_mut(desktop_id) {
            if d.foreground == Some(window) {
                d.foreground = None;
            }
            if d.tray == Some(window) {
                d.tray = None;
            }
        }
        if self.clipboard_owner == Some(window) {
            self.clipboard_owner = None;
        }

        // Timers, hotkeys, pending sends; then a queued WM_QUIT is re-posted with its exit code.
        pump.window_teardown(self, window);
        pump.repost_quit(self, window);

        // The menus: a top-level window's menu goes (the desktop's shared dialog system menu
        // does not).
        {
            let w = self.at(window);
            if !w.is_child() {
                if let Menu::Handle(h) = w.menu {
                    let shared = self
                        .desktop_by_id(w.desktop)
                        .is_some_and(|d| d.dialog_menu == h);
                    if h != 0 && !shared {
                        pump.destroy_menu(self, h);
                    }
                }
            }
        }

        // The properties and the title string go with the record.
        pump.delete_properties(self, window);
        self.at_mut(window).title = TextBuf::EMPTY;

        // The links: a zombie window re-points its parent at the desktop window; a freed one
        // drops them.
        let desktop_window = self
            .desktop_by_id(self.at(window).desktop)
            .and_then(|d| d.window);
        {
            let w = self.at_mut(window);
            if Some(window) != desktop_window {
                w.parent = desktop_window;
            } else {
                w.parent = None;
            }
            w.child = None;
            w.owner = None;
            w.last_active = None;
        }

        // The class reference goes back.
        if let Some(class_id) = self.at(window).class {
            let mut view = class::Window {
                class: class_id,
                owner: self.at(window).process,
                desktop: self.at(window).desktop,
            };
            classes.dereference_class(&mut view);
        }

        // Mark the handle for destruction (the in-destroy flag blocks unlock recursion).
        self.handles.update(handle, |mut e| {
            e.marked_destroy = true;
            e.in_destroy = true;
            e
        });

        // The final unlock: the record's lock count drops.
        let locks = {
            let w = self.at_mut(window);
            w.locks -= 1;
            w.locks
        };
        if locks > 0 {
            // Still referenced elsewhere: the window becomes a zombie, not freed.
            self.handles.update(handle, |mut e| {
                e.in_destroy = false;
                e
            });
            self.make_zombie(classes, window);
            return;
        }

        // The last reference: free the record and the handle (the old HWND stops validating).
        self.at_mut(window).class = None;
        self.thread_mut(caller).window_count -= 1;
        self.at_mut(window).parent = None;
        self.handles.close(handle);
        self.pool.free(window);
    }

    /// The zombie: a still-referenced window at its free becomes an inert icon-title window —
    /// the default procedure, the icon-title system class, server-side, tiled, menu-less — and
    /// its handle stays valid until the last reference drops it.
    fn make_zombie(&mut self, classes: &mut class::Registry, window: WindowId) {
        {
            let w = self.at_mut(window);
            w.proc = Proc::Default;
            w.flags.server_side_proc = true;
            w.flags.has_palette = false;
        }
        let (process, desktop_id) = {
            let w = self.at(window);
            (w.process, w.desktop)
        };
        if let Some(icon) = classes.class_ptr(ICONTITLE_ATOM, process, class::WINDOW_MANAGER_MODULE)
        {
            let mut view = class::Window {
                class: icon,
                owner: process,
                desktop: desktop_id,
            };
            if classes.reference_class(icon, &mut view) {
                self.at_mut(window).class = Some(view.class);
            }
        }
        let w = self.at_mut(window);
        // The type bits are cleared and the window becomes tiled; the menu goes.
        w.style &= 0x0000_FFFF;
        w.menu = Menu::None;
    }
}

// --- The window manager: both registries behind one lock
// ------------------------------------------

/// The pump the services run the decisions with until the message queue lands: every send answers
/// as the default window procedure does, and every window-manager call is [`Pump`]'s default.
pub struct DefaultProcedure;

impl Pump for DefaultProcedure {}

/// HWND_MESSAGE (winuser.h): the parent that makes a message-only window, a child of the desktop's
/// message window.
pub const HWND_MESSAGE: Hwnd = -3i32 as Hwnd;

/// The desktop window's class: the integer atom of "#32769".
pub const DESKTOP_CLASS_ATOM: class::Atom = 0x8001;

/// The message window's class name, "Message".
const MESSAGE_CLASS: [u16; 7] = [
    b'M' as u16,
    b'e' as u16,
    b's' as u16,
    b's' as u16,
    b'a' as u16,
    b'g' as u16,
    b'e' as u16,
];

/// The window manager's state behind its one lock: the window registry, the class registry, and
/// the buffer the icon-change notification gathers the windows into.
///
/// One lock guards both registries, as one lock guards all of Windows 2000's window-manager state:
/// the create and destroy decisions hold both at once, through every callback; and a short lock's
/// guard keeps its taker's passive token borrowed, so no second short lock can be taken under it,
/// in any order.
pub struct WindowManager {
    pub windows: Windows,
    pub classes: class::Registry,
    /// The icon-change notification's windows (see [`Windows::class_views`]).
    pub views: [class::WindowView; WINDOWS],
}

impl WindowManager {
    /// Write an empty window manager at `manager`, field by field (by value it would pass through
    /// the stack, which is smaller than it).
    ///
    /// # Safety
    ///
    /// `manager` is valid for writes, aligned, and the records' final address; its previous
    /// contents are overwritten, not dropped.
    pub unsafe fn write_empty(manager: *mut WindowManager) {
        use core::ptr::addr_of_mut;
        // SAFETY: the caller's contract, handed on to each registry's own; the views are plain
        // data (ids and flags), which all-zero bytes make a value of.
        unsafe {
            Windows::write_empty(addr_of_mut!((*manager).windows));
            class::Registry::write_empty(addr_of_mut!((*manager).classes));
            let views = addr_of_mut!((*manager).views) as *mut class::WindowView;
            core::ptr::write_bytes(views, 0, WINDOWS);
        }
    }

    /// The boot's step for the desktop `desktop` (its packed object id): the primary monitor's
    /// work area, the desktop's two system classes ("#32769" and "Message"), the desktop's own
    /// thread — the window manager's, with no desktop handle, which lets it create the desktop's
    /// root windows — and those windows: the message window, the parent of message-only windows,
    /// and the desktop window, covering the work area, the parent of every top-level window. Both
    /// are made before the desktop names either, so neither has a parent.
    pub fn boot_desktop(&mut self, desktop: u32, work_area: Rect) -> Result<(), Failure> {
        self.windows.set_monitor(PRIMARY_MONITOR, work_area);
        self.windows.set_desktop(desktop, None, None);
        let flags = class::RegisterFlags {
            win40_compat: true,
            server_side_proc: true,
            system_class: true,
            server_class: false,
        };
        let wc = class::WndClassExW {
            cb_size: core::mem::size_of::<class::WndClassExW>() as u32,
            style: 0,
            wnd_proc: 0,
            cb_cls_extra: 0,
            cb_wnd_extra: 0,
            instance: class::WINDOW_MANAGER_MODULE,
            icon: 0,
            cursor: 0,
            background: 0,
            menu_name: 0,
            class_name: 0,
            icon_sm: 0,
        };
        for name in [
            class::Name::Atom(DESKTOP_CLASS_ATOM),
            class::Name::Text(&MESSAGE_CLASS),
        ] {
            self.classes
                .register_class(
                    &wc,
                    name,
                    class::MenuArg::None,
                    class::SYSTEM_OWNER,
                    flags,
                    desktop,
                )
                .map_err(|_| Failure::OutOfMemory)?;
        }
        let thread = self
            .windows
            .add_thread(
                class::SYSTEM_OWNER,
                desktop,
                DESKTOP_CREATEWINDOW,
                None,
                Some(PRIMARY_MONITOR),
            )
            .ok_or(Failure::OutOfMemory)?;
        let mut args = CreateArgs {
            ex_style: 0,
            class_name: class::Name::Text(&MESSAGE_CLASS),
            class_atom: 0,
            name: &[],
            style: WS_POPUP,
            x: 0,
            y: 0,
            cx: 0,
            cy: 0,
            parent: None,
            menu: MenuInput::None,
            instance: class::WINDOW_MANAGER_MODULE,
            params: 0,
            version: 0x0005_0000,
        };
        let message = self.create_window(thread, 0, &mut args, &mut DefaultProcedure)?;
        args.class_name = class::Name::Atom(DESKTOP_CLASS_ATOM);
        args.style = WS_POPUP | WS_CLIPCHILDREN;
        args.x = work_area.left;
        args.y = work_area.top;
        args.cx = work_area.right - work_area.left;
        args.cy = work_area.bottom - work_area.top;
        let window = self.create_window(thread, 0, &mut args, &mut DefaultProcedure)?;
        let id = |handle| self.windows.window_from_handle(handle);
        let (window, message) = (id(window), id(message));
        self.windows.set_desktop(desktop, window, message);
        Ok(())
    }

    /// NtUserCreateWindowEx's decision over the caller's decoded arguments: the parent handle
    /// resolved (none for 0, the desktop's message window for HWND_MESSAGE; a handle naming no
    /// window is ERROR_INVALID_WINDOW_HANDLE), the class name resolved to its atom through the
    /// class registry, then the creation. The new window's handle is the answer.
    pub fn create_window(
        &mut self,
        caller: ThreadId,
        parent: Hwnd,
        args: &mut CreateArgs,
        pump: &mut dyn Pump,
    ) -> Result<Hwnd, Failure> {
        args.parent = match parent {
            0 => None,
            HWND_MESSAGE => Some(
                self.windows
                    .message_window(caller)
                    .ok_or(Failure::InvalidWindowHandle)?,
            ),
            handle => Some(
                self.windows
                    .window_from_handle(handle)
                    .ok_or(Failure::InvalidWindowHandle)?,
            ),
        };
        args.class_atom = self.classes.atom_of(args.class_name);
        let id = self
            .windows
            .create_window_ex(&mut self.classes, caller, args, pump)?;
        Ok(self.windows.handle_of(id))
    }
}

impl MenuInput {
    /// A create's raw hMenu: a child window's id, a top-level window's menu handle, none for 0.
    pub fn of(style: u32, raw: u32) -> Self {
        if raw == 0 {
            MenuInput::None
        } else if kind_of(style) == Kind::Child {
            MenuInput::Id(raw as u16)
        } else {
            MenuInput::Handle(raw)
        }
    }
}

// --- The target's side: the window manager behind its lock, and the services
// ---------------------------------

/// The kernel's one window manager, behind its short lock. Built in place at its first
/// acquisition, the boot's ([`super::winsta::init`]): by value it would pass through the stack,
/// which is smaller than it.
#[cfg(target_arch = "x86")]
mod target {
    use super::*;
    use crate::level::{At, Passive};
    use crate::sync::{ShortGuard, ShortLock};

    static MANAGER: ShortLock<WindowManager> =
        // SAFETY: `write_empty` writes a whole window manager at the address it is handed, and
        // takes no lock.
        unsafe { ShortLock::in_place(WindowManager::write_empty) };

    /// The window manager, locked for as long as the guard lives.
    pub fn lock(passive: &mut At<Passive>) -> ShortGuard<'_, WindowManager> {
        MANAGER.lock(passive)
    }

    /// Run `f` on the locked window manager: the bridge for code that holds no passive token.
    ///
    /// # Panics
    ///
    /// The processor is above the passive level: inside the window manager's lock already, or at
    /// a raised level, where nothing may wait for it.
    pub fn locked<R>(f: impl FnOnce(&mut WindowManager) -> R) -> R {
        assert_eq!(
            crate::pcr::pcr().current(),
            crate::interrupt::irql::PASSIVE,
            "the window manager's bridge entered above the passive level"
        );
        // SAFETY: a passive entry (see `At::enter`): the ledger reads the passive level, and the
        // token stays on this thread, dropped with this frame.
        let mut passive = unsafe { At::<Passive>::enter() };
        let mut manager = MANAGER.lock(&mut passive);
        f(&mut manager)
    }
}

#[cfg(target_arch = "x86")]
pub use target::*;

/// Read a window name, NUL-terminated UTF-16, from the caller at `at` into `units`: none for a
/// null pointer, the name cut at the buffer's length (the record holds no more).
#[cfg(target_arch = "x86")]
fn read_text(at: UserAddr, units: &mut [u16]) -> Result<&[u16], NtStatus> {
    if at.is_null() {
        return Ok(&[]);
    }
    let mut len = 0;
    while len < units.len() {
        let unit = at.offset(2 * len as u32).cast::<u16>().read()?;
        if unit == 0 {
            break;
        }
        units[len] = unit;
        len += 1;
    }
    Ok(&units[..len])
}

/// NtUserCreateWindowEx(ExStyle, ClassName, WindowName, Style, X, Y, Width, Height, Parent, Menu,
/// Instance, Param, ExpectedVersion, Window): CreateWindowExW's arguments as they are (ClassName a
/// string pointer or an integer atom, the private ANSI-creator bit in ExStyle), the caller's
/// expected-version word, and the new window's handle into `window`. The handle's slot is written
/// first, so a creation is never left unreported by a fault.
#[cfg(target_arch = "x86")]
#[allow(clippy::too_many_arguments)]
pub fn create_window_ex(
    call: &mut NtCall,
    ex_style: u32,
    class_name: u32,
    window_name: UserAddr,
    style: u32,
    x: i32,
    y: i32,
    cx: i32,
    cy: i32,
    parent: Handle,
    menu: u32,
    instance: u32,
    param: u32,
    version: u32,
    window: UserPtr<u32>,
) -> NtResult {
    window.write(0)?;
    let mut class_units = [0u16; class::MAX_ATOM_NAME];
    let class_name = class::read_name(class_name, &mut class_units)?;
    let mut name_units = [0u16; MAX_WINDOW_TEXT];
    let name = read_text(window_name, &mut name_units)?;
    let caller = super::winsta::gui_thread(call)?.thread;
    let mut args = CreateArgs {
        ex_style,
        class_name,
        class_atom: 0,
        name,
        style,
        x,
        y,
        cx,
        cy,
        parent: None,
        menu: MenuInput::of(style, menu),
        instance,
        params: param,
        version,
    };
    let created = lock(call.passive())
        .create_window(caller, parent.raw(), &mut args, &mut DefaultProcedure)
        .map_err(Failure::status)?;
    window.write(created)?;
    Ok(STATUS_SUCCESS)
}

/// NtUserDestroyWindow(Window): destroy the window, owned windows and children with it. Only its
/// thread may; a destroy a hook vetoes answers STATUS_UNSUCCESSFUL, the window untouched.
#[cfg(target_arch = "x86")]
pub fn destroy_window(call: &mut NtCall, window: Handle) -> NtResult {
    let caller = super::winsta::gui_thread(call)?.thread;
    let mut manager = lock(call.passive());
    let WindowManager {
        windows, classes, ..
    } = &mut *manager;
    let destroyed = windows
        .destroy_window_handle(classes, caller, window.raw(), &mut DefaultProcedure)
        .map_err(Failure::status)?;
    if destroyed {
        Ok(STATUS_SUCCESS)
    } else {
        Err(STATUS_UNSUCCESSFUL)
    }
}

// The host builds have no processes and no user memory: the services answer nothing (the host
// tests drive the window manager itself).

#[cfg(not(target_arch = "x86"))]
#[allow(clippy::too_many_arguments)]
pub fn create_window_ex(
    _: &mut NtCall,
    _: u32,
    _: u32,
    _: UserAddr,
    _: u32,
    _: i32,
    _: i32,
    _: i32,
    _: i32,
    _: Handle,
    _: u32,
    _: u32,
    _: u32,
    _: u32,
    _: UserPtr<u32>,
) -> NtResult {
    Err(STATUS_NOT_IMPLEMENTED)
}

#[cfg(not(target_arch = "x86"))]
pub fn destroy_window(_: &mut NtCall, _: Handle) -> NtResult {
    Err(STATUS_NOT_IMPLEMENTED)
}

#[cfg(test)]
mod tests {
    //! The create/destroy decision logic's host tests, over a registry of each test's own.

    use super::*;
    use crate::win32k::class::{self, RegisterFlags};

    /// A fresh window registry, leaked at its final address (the pool's records stay put, as on
    /// target).
    fn windows() -> &'static mut Windows {
        let mut registry = Box::<Windows>::new_uninit();
        // SAFETY: the box is valid, aligned and the records' final address once leaked.
        unsafe { Windows::write_empty(registry.as_mut_ptr()) };
        // SAFETY: written whole just above.
        Box::leak(unsafe { registry.assume_init() })
    }

    /// A fresh class registry, leaked the same way.
    fn classes() -> &'static mut class::Registry {
        let mut registry = Box::<class::Registry>::new_uninit();
        // SAFETY: the box is valid, aligned and the records' final address once leaked.
        unsafe { class::Registry::write_empty(registry.as_mut_ptr()) };
        // SAFETY: written whole just above.
        Box::leak(unsafe { registry.assume_init() })
    }

    /// A text as UTF-16 units.
    fn units(text: &str) -> Vec<u16> {
        text.encode_utf16().collect()
    }

    const OWNER: class::Owner = 0;
    const OTHER_OWNER: class::Owner = 1;
    const MODULE: u32 = 0x0040_0000;
    const OTHER_MODULE: u32 = 0x0050_0000;
    const DESKTOP: u32 = 1;
    const OTHER_DESKTOP: u32 = 2;
    /// An expected-version word of a 5.0 app.
    const VERSION_50: u32 = 0x0005_0000;

    fn wnd_class() -> class::WndClassExW {
        class::WndClassExW {
            cb_size: 48,
            style: 0,
            wnd_proc: 0x0040_1000,
            cb_cls_extra: 0,
            cb_wnd_extra: 0,
            instance: MODULE,
            icon: 0,
            cursor: 0,
            background: 0,
            menu_name: 0,
            class_name: 0,
            icon_sm: 0,
        }
    }

    fn compat40() -> RegisterFlags {
        RegisterFlags {
            win40_compat: true,
            ..RegisterFlags::default()
        }
    }

    fn register(
        c: &mut class::Registry,
        name: class::Name,
        wc: &class::WndClassExW,
    ) -> class::Atom {
        register_on(c, name, wc, DESKTOP, OWNER, class::MenuArg::None)
    }

    #[allow(clippy::too_many_arguments)]
    fn register_on(
        c: &mut class::Registry,
        name: class::Name,
        wc: &class::WndClassExW,
        desktop: u32,
        owner: class::Owner,
        menu: class::MenuArg,
    ) -> class::Atom {
        c.register_class(wc, name, menu, owner, compat40(), desktop)
            .unwrap()
    }

    /// A thread on the test desktop, with full desktop access and the primary monitor.
    fn thread(w: &mut Windows) -> ThreadId {
        w.add_thread(
            OWNER,
            DESKTOP,
            DESKTOP_CREATEWINDOW,
            Some(0x10),
            Some(PRIMARY_MONITOR),
        )
        .unwrap()
    }

    /// A bare window record (pool and handle only), as the scaffolding would make one.
    fn raw_window(w: &mut Windows, t: ThreadId, style: u32, parent: Option<WindowId>) -> WindowId {
        raw_window_on(w, t, DESKTOP, style, parent)
    }

    fn raw_window_on(
        w: &mut Windows,
        t: ThreadId,
        desktop: u32,
        style: u32,
        parent: Option<WindowId>,
    ) -> WindowId {
        let id = w.pool.allocate().unwrap();
        let handle = w.handles.insert(WindowEntry {
            id,
            owner: t,
            marked_destroy: false,
            in_destroy: false,
        });
        let rec = w.pool.at_mut(id);
        rec.handle = handle;
        rec.thread = t;
        rec.process = OWNER;
        rec.desktop = desktop;
        rec.style = style;
        rec.parent = parent;
        rec.locks = 1;
        id
    }

    /// How many window records are live.
    fn live(w: &Windows) -> usize {
        w.pool.headers.iter().filter(|h| h.live).count()
    }

    /// A registry pair with a thread, the desktop's window and message window, a 640x480 monitor
    /// and one registered class.
    fn setup() -> (
        &'static mut Windows,
        &'static mut class::Registry,
        ThreadId,
        class::Atom,
        WindowId,
        WindowId,
    ) {
        let w = windows();
        let c = classes();
        let t = thread(w);
        let desk = raw_window(w, t, WS_OVERLAPPED, None);
        let msg = raw_window(w, t, WS_POPUP, None);
        w.set_desktop(DESKTOP, Some(desk), Some(msg));
        w.set_monitor(
            PRIMARY_MONITOR,
            Rect {
                left: 0,
                top: 0,
                right: 640,
                bottom: 480,
            },
        );
        let atom = register(c, class::Name::Text(&units("Test")), &wnd_class());
        (w, c, t, atom, desk, msg)
    }

    /// Create arguments for a plain create.
    fn args(atom: class::Atom, style: u32) -> CreateArgs<'static> {
        CreateArgs {
            ex_style: 0,
            class_name: class::Name::Atom(atom),
            class_atom: atom,
            name: &[],
            style,
            x: 10,
            y: 20,
            cx: 100,
            cy: 80,
            parent: None,
            menu: MenuInput::None,
            instance: MODULE,
            params: 0,
            version: VERSION_50,
        }
    }

    fn create(
        w: &mut Windows,
        c: &mut class::Registry,
        t: ThreadId,
        atom: class::Atom,
        style: u32,
        pump: &mut Rec,
    ) -> Result<WindowId, Failure> {
        let a = args(atom, style);
        w.create_window_ex(c, t, &a, pump)
    }

    /// One recorded pump call.
    #[derive(Clone, Debug, PartialEq)]
    enum Ev {
        Send(WindowId, u32, WParam, LParam),
        Show(WindowId, u32),
        SetPos(WindowId, u32),
        Activate(WindowId, Activate),
        MinMax(WindowId, u32),
        Focus(WindowId),
        Attach(ThreadId, ThreadId, bool),
        Redraw(WindowId),
        ReleaseCapture,
        Caret,
        PostEvent(ThreadId, WindowId),
        MinMaxInfo(WindowId),
        LoadMenu(u32),
        DestroyMenu(Hwnd),
        WindowDc(WindowId, bool),
        Layered(WindowId),
        FullScreen(WindowId),
        InsertAfter(WindowId),
        Clipboard(WindowId),
        Quit(WindowId),
        Teardown(WindowId),
        Props(WindowId),
    }

    /// A recording pump: logs every call, answers WM_NCCREATE with 1 and WM_CREATE with 0 unless
    /// told otherwise, and can play a handler that sets a title or destroys a sibling.
    struct Rec {
        events: Vec<Ev>,
        /// (target, message, params) for every WM_NCCREATE/WM_CREATE.
        params: Vec<(WindowId, u32, CreateParams)>,
        /// The parent pointer seen at each send (the create's pre-callback parent).
        parents: Vec<(WindowId, Option<WindowId>)>,
        /// The target's stored style at each send.
        styles: Vec<(WindowId, u32)>,
        nccreate_answer: LResult,
        create_answer: LResult,
        hide_works: bool,
        veto_destroy: bool,
        /// A window whose destroy alone the hook vetoes.
        veto_window: Option<WindowId>,
        activate_ok: bool,
        no_menus: bool,
        mmi: MinMaxInfo,
        caller: ThreadId,
        /// A title a fake handler sets during WM_NCCREATE.
        title_on_nccreate: Option<Vec<u16>>,
        title_done: bool,
        /// When WM_DESTROY reaches `watch`, destroy `victim` (a handler destroying a sibling).
        destroy_on_destroy: Option<(WindowId, WindowId)>,
        next_menu_handle: Hwnd,
    }

    impl Rec {
        fn new(caller: ThreadId) -> Self {
            Rec {
                events: Vec::new(),
                params: Vec::new(),
                parents: Vec::new(),
                styles: Vec::new(),
                nccreate_answer: 1,
                create_answer: 0,
                hide_works: true,
                veto_destroy: false,
                veto_window: None,
                activate_ok: true,
                no_menus: false,
                mmi: MinMaxInfo::unbounded(),
                caller,
                title_on_nccreate: None,
                title_done: false,
                destroy_on_destroy: None,
                next_menu_handle: 0x5000,
            }
        }

        /// Every message sent, as (target, message).
        fn sends(&self) -> Vec<(WindowId, u32)> {
            self.events
                .iter()
                .filter_map(|e| match e {
                    Ev::Send(w, m, _, _) => Some((*w, *m)),
                    _ => None,
                })
                .collect()
        }

        /// The messages sent, as messages only.
        fn messages(&self) -> Vec<u32> {
            self.sends().iter().map(|(_, m)| *m).collect()
        }
    }

    impl Pump for Rec {
        fn send(
            &mut self,
            windows: &mut Windows,
            classes: &mut class::Registry,
            target: WindowId,
            message: &mut Message,
        ) -> LResult {
            if let Payload::Create(ref p) = message.payload {
                self.params.push((target, message.message, *p));
            }
            self.parents.push((target, windows.at(target).parent));
            self.styles.push((target, windows.at(target).style));
            self.events.push(Ev::Send(
                target,
                message.message,
                message.wparam,
                message.lparam,
            ));
            if message.message == WM_NCCREATE && !self.title_done {
                if let Some(units) = self.title_on_nccreate.clone() {
                    self.title_done = true;
                    let w = windows.at_mut(target);
                    w.title = TextBuf::from_units(&units);
                    w.flags.title_set = true;
                }
            }
            if message.message == WM_DESTROY {
                if let Some((watch, victim)) = self.destroy_on_destroy {
                    if target == watch {
                        let _ = windows.destroy_window(classes, self.caller, victim, self);
                    }
                }
            }
            match message.message {
                WM_NCCREATE => self.nccreate_answer,
                WM_CREATE => self.create_answer,
                _ => 0,
            }
        }

        fn send_size(
            &mut self,
            _windows: &mut Windows,
            _classes: &mut class::Registry,
            target: WindowId,
            command: u32,
        ) {
            self.events.push(Ev::Send(target, WM_SIZE, command, 0));
        }

        fn show(&mut self, windows: &mut Windows, target: WindowId, command: u32) -> bool {
            self.events.push(Ev::Show(target, command));
            // A successful show sets the visible bit, a hide clears it.
            if self.hide_works {
                let w = windows.at_mut(target);
                if command == SW_HIDE as u32 {
                    w.style &= !WS_VISIBLE;
                } else {
                    w.style |= WS_VISIBLE;
                }
            }
            true
        }

        fn set_window_pos(&mut self, windows: &mut Windows, target: WindowId, flags: u32) {
            self.events.push(Ev::SetPos(target, flags));
            if self.hide_works && flags & SWP_HIDEWINDOW != 0 {
                windows.at_mut(target).style &= !WS_VISIBLE;
            }
        }

        fn activate(
            &mut self,
            _windows: &mut Windows,
            target: WindowId,
            command: Activate,
        ) -> bool {
            self.events.push(Ev::Activate(target, command));
            self.activate_ok
        }

        fn min_maximize(&mut self, _windows: &mut Windows, target: WindowId, command: u32) {
            self.events.push(Ev::MinMax(target, command));
        }

        fn check_focus(&mut self, _windows: &mut Windows, target: WindowId) {
            self.events.push(Ev::Focus(target));
        }

        fn attach_input(&mut self, from: ThreadId, to: ThreadId, attach: bool) {
            self.events.push(Ev::Attach(from, to, attach));
        }

        fn redraw_below(&mut self, _windows: &mut Windows, target: WindowId) {
            self.events.push(Ev::Redraw(target));
        }

        fn release_capture(&mut self, _windows: &mut Windows) {
            self.events.push(Ev::ReleaseCapture);
        }

        fn destroy_caret(&mut self) {
            self.events.push(Ev::Caret);
        }

        fn post_destroy_event(&mut self, thread: ThreadId, window: WindowId) {
            self.events.push(Ev::PostEvent(thread, window));
        }

        fn min_max_info(&mut self, _windows: &mut Windows, target: WindowId) -> MinMaxInfo {
            self.events.push(Ev::MinMaxInfo(target));
            self.mmi
        }

        fn load_class_menu(&mut self, module: u32, _name: &class::MenuName) -> Option<Hwnd> {
            self.events.push(Ev::LoadMenu(module));
            if self.no_menus {
                return None;
            }
            let h = self.next_menu_handle;
            self.next_menu_handle += 4;
            Some(h)
        }

        fn destroy_menu(&mut self, _windows: &mut Windows, menu: Hwnd) {
            self.events.push(Ev::DestroyMenu(menu));
        }

        fn create_window_dc(
            &mut self,
            _windows: &mut Windows,
            target: WindowId,
            own_dc: bool,
        ) -> bool {
            self.events.push(Ev::WindowDc(target, own_dc));
            true
        }

        fn set_layered(&mut self, _windows: &mut Windows, target: WindowId) -> bool {
            self.events.push(Ev::Layered(target));
            true
        }

        fn check_full_screen(
            &mut self,
            _windows: &mut Windows,
            target: WindowId,
            _rect: &mut SizeRect,
        ) {
            self.events.push(Ev::FullScreen(target));
        }

        fn foreground_insert_after(&mut self, _windows: &mut Windows, target: WindowId) -> ZOrder {
            self.events.push(Ev::InsertAfter(target));
            ZOrder::Top
        }

        fn cbt_create_veto(
            &mut self,
            windows: &mut Windows,
            _classes: &mut class::Registry,
            target: WindowId,
            _params: &mut CreateParams,
        ) -> bool {
            self.parents.push((target, windows.at(target).parent));
            false
        }

        fn cbt_destroy_veto(&mut self, _windows: &mut Windows, target: WindowId) -> bool {
            self.veto_destroy || self.veto_window == Some(target)
        }

        fn disown_clipboard(&mut self, _windows: &mut Windows, target: WindowId) {
            self.events.push(Ev::Clipboard(target));
        }

        fn repost_quit(&mut self, _windows: &mut Windows, target: WindowId) {
            self.events.push(Ev::Quit(target));
        }

        fn window_teardown(&mut self, _windows: &mut Windows, target: WindowId) {
            self.events.push(Ev::Teardown(target));
        }

        fn delete_properties(&mut self, _windows: &mut Windows, target: WindowId) {
            self.events.push(Ev::Props(target));
        }
    }

    // --- Validation (before any allocation)
    // ---------------------------------------------------------

    /// A parent on another desktop is refused before anything else: ERROR_INVALID_PARAMETER
    /// (87), and nothing is allocated.
    #[test]
    fn a_parent_on_another_desktop_is_refused() {
        let (w, c, t, atom, _, _) = setup();
        let other = raw_window_on(w, t, OTHER_DESKTOP, WS_OVERLAPPED, None);
        let before = live(w);
        let mut pump = Rec::new(t);
        let mut a = args(atom, WS_OVERLAPPED);
        a.parent = Some(other);
        let err = w.create_window_ex(c, t, &a, &mut pump).unwrap_err();
        assert_eq!(err, Failure::InvalidParameter);
        assert_eq!(err.code(), 87);
        assert_eq!(live(w), before, "nothing was allocated");
    }

    /// The desktop access check: a thread whose desktop access lacks DESKTOP_CREATEWINDOW is
    /// refused with ERROR_ACCESS_DENIED (5); a thread with no desktop handle yet (the root
    /// desktop window's own creation) skips the check.
    #[test]
    fn the_desktop_access_check() {
        let (w, c, _t, atom, _, _) = setup();
        let t2 = w.add_thread(OWNER, DESKTOP, 0, Some(0x20), None).unwrap();
        let mut pump = Rec::new(t2);
        let err = create(w, c, t2, atom, WS_OVERLAPPED, &mut pump).unwrap_err();
        assert_eq!(err, Failure::AccessDenied);
        assert_eq!(err.code(), 5);
        // No desktop handle: the check is skipped and the create proceeds.
        let t3 = w.add_thread(OWNER, DESKTOP, 0, None, None).unwrap();
        let mut pump = Rec::new(t3);
        assert!(create(w, c, t3, atom, WS_OVERLAPPED, &mut pump).is_ok());
    }

    /// A WS_CHILD window created without a parent fails with ERROR_TLW_WITH_WSCHILD (1406).
    #[test]
    fn a_child_window_needs_a_parent() {
        let (w, c, t, atom, _, _) = setup();
        let mut pump = Rec::new(t);
        let err = create(w, c, t, atom, WS_CHILD, &mut pump).unwrap_err();
        assert_eq!(err, Failure::TlwWithWsChild);
        assert_eq!(err.code(), 1406);
    }

    /// The nested-window limit: a child whose parent chain already reaches 100 levels fails with
    /// ERROR_INVALID_PARAMETER (87); at 99 levels it is accepted.
    #[test]
    fn the_nested_window_limit() {
        let (w, c, t, atom, _, _) = setup();
        // A chain of 100 windows, each the parent of the next.
        let mut chain = Vec::new();
        let mut parent = None;
        for _ in 0..100 {
            let id = raw_window(w, t, WS_CHILD, parent);
            chain.push(id);
            parent = Some(id);
        }
        let mut pump = Rec::new(t);
        // The deepest parent gives a chain depth of 101: refused.
        let mut a = args(atom, WS_CHILD);
        a.parent = Some(chain[99]);
        let err = w.create_window_ex(c, t, &a, &mut pump).unwrap_err();
        assert_eq!(err, Failure::InvalidParameter);
        assert_eq!(err.code(), 87);
        // 99 ancestors give a depth of 100: accepted.
        let mut a = args(atom, WS_CHILD);
        a.parent = Some(chain[98]);
        assert!(w.create_window_ex(c, t, &a, &mut pump).is_ok());
    }

    /// The private ANSI-creator bit is consumed at the create: it never reaches the stored
    /// ex-style, the window carries the ANSI-creator flag, and the create parameters name the
    /// class by its ANSI name.
    #[test]
    fn the_ansi_creator_bit_is_consumed() {
        let (w, c, t, atom, _, _) = setup();
        let name = units("Test");
        let mut pump = Rec::new(t);
        let mut a = args(atom, WS_OVERLAPPED);
        a.ex_style = ANSI_CREATOR_BIT | WS_EX_TOPMOST;
        a.class_name = class::Name::Text(&name);
        let id = w.create_window_ex(c, t, &a, &mut pump).unwrap();
        let rec = w.at(id);
        assert_eq!(rec.ex_style & ANSI_CREATOR_BIT, 0, "the bit is not stored");
        assert_eq!(
            rec.ex_style & WS_EX_TOPMOST,
            WS_EX_TOPMOST,
            "the other bits stay"
        );
        assert!(rec.flags.ansi_creator);
        let (_, _, params) = pump
            .params
            .iter()
            .find(|(_, m, _)| *m == WM_NCCREATE)
            .unwrap();
        assert_eq!(params.class_name, ClassArg::AnsiName);
    }

    /// The edge style decision: the dialog-modal frame and the thick frame force
    /// WS_EX_WINDOWEDGE, the static edge forbids it, a caption gets it from a 4.0-or-later app,
    /// and anything else clears it.
    #[test]
    fn the_edge_style_decision() {
        assert!(needs_window_edge(WS_CAPTION, 0, true));
        assert!(!needs_window_edge(WS_CAPTION, 0, false));
        assert!(!needs_window_edge(WS_CAPTION, WS_EX_STATICEDGE, true));
        assert!(needs_window_edge(0, WS_EX_DLGMODALFRAME, false));
        assert!(needs_window_edge(WS_THICKFRAME, 0, false));
        assert!(!needs_window_edge(WS_OVERLAPPED, 0, true));
        // Through the create: the stored ex-style carries the decision (a popup, so the tiled
        // path does not re-set the bit).
        let (w, c, t, atom, _, _) = setup();
        let mut pump = Rec::new(t);
        let mut a = args(atom, WS_POPUP);
        a.ex_style = WS_EX_STATICEDGE | WS_EX_WINDOWEDGE;
        let id = w.create_window_ex(c, t, &a, &mut pump).unwrap();
        assert_eq!(w.at(id).ex_style & WS_EX_WINDOWEDGE, 0, "cleared");
        let mut a = args(atom, WS_POPUP);
        a.ex_style = WS_EX_DLGMODALFRAME;
        let id = w.create_window_ex(c, t, &a, &mut pump).unwrap();
        assert_eq!(
            w.at(id).ex_style & WS_EX_WINDOWEDGE,
            WS_EX_WINDOWEDGE,
            "set"
        );
    }

    // --- Class-name resolution
    // ------------------------------------------------------------------------

    /// A class name that resolves to no atom fails with ERROR_CANNOT_FIND_WND_CLASS (1407).
    #[test]
    fn an_unknown_class_name_fails() {
        let (w, c, t, _atom, _, _) = setup();
        let mut pump = Rec::new(t);
        let name = units("NoSuchClass");
        let mut a = args(0, WS_OVERLAPPED);
        a.class_name = class::Name::Text(&name);
        let err = w.create_window_ex(c, t, &a, &mut pump).unwrap_err();
        assert_eq!(err, Failure::CannotFindWindowClass);
        assert_eq!(err.code(), 1407);
    }

    /// An integer atom names the class directly (no atom-table lookup); atom 0 fails the same
    /// way as an unknown string name.
    #[test]
    fn an_integer_atom_names_the_class_directly() {
        let (w, c, t, _atom, _, _) = setup();
        let atom = register(c, class::Name::Atom(0x8002), &wnd_class());
        assert_eq!(atom, 0x8002);
        let mut pump = Rec::new(t);
        let mut a = args(0x8002, WS_OVERLAPPED);
        a.class_name = class::Name::Atom(0x8002);
        let id = w.create_window_ex(c, t, &a, &mut pump).unwrap();
        assert!(w.pool.is_live(id));
        let (_, _, params) = pump
            .params
            .iter()
            .find(|(_, m, _)| *m == WM_NCCREATE)
            .unwrap();
        assert_eq!(params.class_name, ClassArg::Atom(0x8002));
        // Atom 0 fails.
        let mut pump = Rec::new(t);
        let a = args(0, WS_OVERLAPPED);
        let err = w.create_window_ex(c, t, &a, &mut pump).unwrap_err();
        assert_eq!(err, Failure::CannotFindWindowClass);
    }

    /// A class the calling process cannot see (another module's private class) fails with 1407
    /// and allocates nothing.
    #[test]
    fn a_class_the_process_cannot_see_fails() {
        let (w, c, t, _atom, _, _) = setup();
        let mut wc = wnd_class();
        wc.instance = OTHER_MODULE;
        let atom = register(c, class::Name::Text(&units("Private")), &wc);
        let mut pump = Rec::new(t);
        let name = units("Private");
        let mut a = args(atom, WS_OVERLAPPED);
        a.class_name = class::Name::Text(&name);
        let err = w.create_window_ex(c, t, &a, &mut pump).unwrap_err();
        assert_eq!(err, Failure::CannotFindWindowClass);
        assert_eq!(err.code(), 1407);
        assert_eq!(live(w), 2, "nothing was allocated");
    }

    // --- Allocation and early record state
    // ------------------------------------------------------------

    /// A full pool fails the create with ERROR_OUTOFMEMORY (14).
    #[test]
    fn a_full_pool_fails_the_create() {
        let (w, c, t, atom, _, _) = setup();
        while w.pool.allocate().is_some() {}
        let mut pump = Rec::new(t);
        let err = create(w, c, t, atom, WS_OVERLAPPED, &mut pump).unwrap_err();
        assert_eq!(err, Failure::OutOfMemory);
        assert_eq!(err.code(), 14);
    }

    /// A failed class reference (a cross-desktop class with no free class record for the clone)
    /// frees the window record and fails with 1407.
    #[test]
    fn a_failed_class_reference_frees_the_record() {
        let (w, c, t, _atom, _, _) = setup();
        // A class registered on the other desktop.
        let atom = register_on(
            c,
            class::Name::Text(&units("Far")),
            &wnd_class(),
            OTHER_DESKTOP,
            OWNER,
            class::MenuArg::None,
        );
        // Fill the class pool so the clone cannot be made (two records are already taken).
        for i in 0..(class::CLASSES - 2) {
            register(
                c,
                class::Name::Text(&units(&format!("Fill{i}"))),
                &wnd_class(),
            );
        }
        let before = live(w);
        let mut pump = Rec::new(t);
        let err = create(w, c, t, atom, WS_OVERLAPPED, &mut pump).unwrap_err();
        assert_eq!(err, Failure::CannotFindWindowClass);
        assert_eq!(err.code(), 1407);
        assert_eq!(live(w), before, "the record was freed");
        assert_eq!(w.thread(t).window_count, 0);
    }

    /// The stored state after a happy create: WS_VISIBLE and the layered bit are stripped from
    /// the stored values, the class's cbWndExtra is stored, and the thread's window count went
    /// up (the class's window count is probed by unregistering: refused while it has windows).
    #[test]
    fn the_stored_style_and_counters() {
        let (w, c, t, _atom, _, _) = setup();
        let mut wc = wnd_class();
        wc.cb_wnd_extra = 12;
        let atom = register(c, class::Name::Text(&units("Extra")), &wc);
        let mut pump = Rec::new(t);
        let mut a = args(atom, WS_OVERLAPPED | WS_VISIBLE);
        a.ex_style = WS_EX_LAYERED | WS_EX_TOPMOST;
        let id = w.create_window_ex(c, t, &a, &mut pump).unwrap();
        let rec = w.at(id);
        // WS_VISIBLE and the layered bit are stripped from the stored style (seen at
        // WM_NCCREATE, before any show re-sets the visible bit).
        assert_eq!(pump.styles[0].0, id);
        assert_eq!(pump.styles[0].1 & WS_VISIBLE, 0, "WS_VISIBLE is stripped");
        assert_eq!(
            rec.ex_style & WS_EX_LAYERED,
            0,
            "the layered bit is stripped"
        );
        assert_eq!(rec.ex_style & WS_EX_TOPMOST, WS_EX_TOPMOST);
        assert_eq!(rec.cb_wnd_extra, 12);
        assert_eq!(w.thread(t).window_count, 1);
        let err = c
            .unregister_class(class::Name::Text(&units("Extra")), OWNER, MODULE)
            .unwrap_err();
        assert_eq!(
            err,
            class::Failure::ClassHasWindows,
            "the class reference is held"
        );
    }

    /// Before any callback the record holds the class, the stored styles, the module and the
    /// procedure, and the parent pointer is the desktop's message window; the create parameters
    /// carry the arguments, the menu by kind.
    #[test]
    fn the_pre_callback_state() {
        let (w, c, t, atom, _, msg) = setup();
        let parent = raw_window(w, t, WS_OVERLAPPED, None);
        w.at_mut(parent).client_rect = Rect {
            left: 10,
            top: 20,
            right: 500,
            bottom: 400,
        };
        let mut pump = Rec::new(t);
        let name = units("hello");
        let mut a = args(atom, WS_CHILD);
        a.parent = Some(parent);
        a.menu = MenuInput::Id(7);
        a.name = &name;
        a.params = 0x1234;
        let id = w.create_window_ex(c, t, &a, &mut pump).unwrap();
        // While the create hook ran, the parent pointer was the message window (a parent always
        // exists during early callbacks).
        assert_eq!(pump.parents[0], (id, Some(msg)));
        // After the create it is the real parent.
        assert_eq!(w.at(id).parent, Some(parent));
        let rec = w.at(id);
        assert!(rec.class.is_some());
        assert_eq!(rec.module, MODULE);
        assert_eq!(rec.proc, Proc::Client(0x0040_1000));
        let (_, _, p) = &pump.params[0];
        assert_eq!(p.menu, 7, "a child's menu is the raw id");
        assert_eq!(p.parent, w.at(parent).handle);
        assert_eq!(p.name.as_slice(), &units("hello")[..]);
        assert_eq!(p.params, 0x1234);
        assert_eq!(p.style, WS_CHILD);
        // A top-level window's menu is a handle.
        let mut pump = Rec::new(t);
        let mut a = args(atom, WS_OVERLAPPED);
        a.menu = MenuInput::Handle(0x9000);
        let id = w.create_window_ex(c, t, &a, &mut pump).unwrap();
        assert_eq!(w.at(id).menu, Menu::Handle(0x9000));
        let (_, _, p) = pump
            .params
            .iter()
            .find(|(_, m, _)| *m == WM_NCCREATE)
            .unwrap();
        assert_eq!(p.menu, 0x9000);
    }

    // --- Positioning and size normalization
    // ------------------------------------------------------------

    /// CW_USEDEFAULT is zeroed for non-tiled windows: x and y, and cx/cy when cx is default.
    #[test]
    fn cw_usedefault_is_zeroed_for_non_tiled_windows() {
        let (w, c, t, atom, _, _) = setup();
        let parent = raw_window(w, t, WS_OVERLAPPED, None);
        let mut pump = Rec::new(t);
        let mut a = args(atom, WS_CHILD);
        a.parent = Some(parent);
        a.x = CW_USEDEFAULT;
        a.cx = CW_USEDEFAULT;
        let id = w.create_window_ex(c, t, &a, &mut pump).unwrap();
        assert_eq!(
            w.at(id).window_rect,
            Rect {
                left: 0,
                top: 0,
                right: 0,
                bottom: 0
            }
        );
        // The second default marker is honored too.
        let mut a = args(atom, WS_CHILD);
        a.parent = Some(parent);
        a.x = CW_USEDEFAULT_ALT;
        a.cx = CW_USEDEFAULT_ALT;
        let id = w.create_window_ex(c, t, &a, &mut pump).unwrap();
        assert_eq!(w.at(id).window_rect.right, 0);
        assert_eq!(w.at(id).window_rect.bottom, 0);
    }

    /// A child is positioned in the parent's client coordinates and stacks at the bottom of the
    /// parent's child list.
    #[test]
    fn children_are_positioned_in_the_parents_client_and_stack_at_the_bottom() {
        let (w, c, t, atom, _, _) = setup();
        let parent = raw_window(w, t, WS_OVERLAPPED, None);
        w.at_mut(parent).client_rect = Rect {
            left: 10,
            top: 20,
            right: 600,
            bottom: 400,
        };
        let mut pump = Rec::new(t);
        let mut a = args(atom, WS_CHILD);
        a.parent = Some(parent);
        a.x = 5;
        a.y = 6;
        a.cx = 30;
        a.cy = 40;
        let first = w.create_window_ex(c, t, &a, &mut pump).unwrap();
        assert_eq!(
            w.at(first).window_rect,
            Rect {
                left: 15,
                top: 26,
                right: 45,
                bottom: 66
            }
        );
        let second = w.create_window_ex(c, t, &a, &mut pump).unwrap();
        // The new child goes below the existing one.
        assert_eq!(w.at(parent).child, Some(first));
        assert_eq!(w.at(first).next, Some(second));
        assert_eq!(w.at(second).next, None);
    }

    /// A tiled window gets the forced styles: WS_CLIPSIBLINGS, the caption+border bits in the
    /// style's high word, the edge bit for a 4.0 app, and size/move deferred to show time.
    #[test]
    fn tiled_windows_get_the_forced_styles() {
        let (w, c, t, atom, _, _) = setup();
        let mut pump = Rec::new(t);
        let a = args(atom, WS_OVERLAPPED); // no caption/border given
        let id = w.create_window_ex(c, t, &a, &mut pump).unwrap();
        let rec = w.at(id);
        assert_eq!(rec.style & WS_CLIPSIBLINGS, WS_CLIPSIBLINGS);
        assert_eq!(rec.style & (WS_CAPTION | WS_BORDER), WS_CAPTION | WS_BORDER);
        assert_eq!(rec.ex_style & WS_EX_WINDOWEDGE, WS_EX_WINDOWEDGE);
        assert!(rec.flags.sendsizemove);
    }

    /// When x is CW_USEDEFAULT, y doubles as the show command (default SW_SHOW).
    #[test]
    fn the_show_command_comes_from_y_when_x_is_default() {
        let (w, c, t, atom, _, _) = setup();
        let mut pump = Rec::new(t);
        let mut a = args(atom, WS_OVERLAPPED | WS_VISIBLE);
        a.x = CW_USEDEFAULT;
        a.y = SW_SHOWNA;
        let _ = w.create_window_ex(c, t, &a, &mut pump).unwrap();
        let shows: Vec<u32> = pump
            .events
            .iter()
            .filter_map(|e| match e {
                Ev::Show(_, cmd) => Some(*cmd),
                _ => None,
            })
            .collect();
        assert_eq!(shows, vec![SW_SHOWNA as u32]);
        // With y also default: SW_SHOW.
        let mut pump = Rec::new(t);
        let mut a = args(atom, WS_OVERLAPPED | WS_VISIBLE);
        a.x = CW_USEDEFAULT;
        a.y = CW_USEDEFAULT;
        let _ = w.create_window_ex(c, t, &a, &mut pump).unwrap();
        let shows: Vec<u32> = pump
            .events
            .iter()
            .filter_map(|e| match e {
                Ev::Show(_, cmd) => Some(*cmd),
                _ => None,
            })
            .collect();
        assert_eq!(shows, vec![SW_SHOW as u32]);
    }

    /// The cascade default rect: 3/4 by 3/4 of the monitor's work area, offset by the window
    /// stack counter (reset when the offset leaves the top-left quarter), and the counter moves
    /// on.
    #[test]
    fn the_cascade_default_rect() {
        let (w, c, t, atom, _, _) = setup();
        let mut pump = Rec::new(t);
        let mut a = args(atom, WS_OVERLAPPED);
        a.x = CW_USEDEFAULT;
        a.cx = CW_USEDEFAULT;
        let id = w.create_window_ex(c, t, &a, &mut pump).unwrap();
        assert_eq!(
            w.at(id).window_rect,
            Rect {
                left: 0,
                top: 0,
                right: 480,
                bottom: 360
            }
        );
        assert_eq!(w.monitors[0].window_stack, 1);
        // The second cascaded window is offset by the frame+caption metrics (12, 24).
        let id = w.create_window_ex(c, t, &a, &mut pump).unwrap();
        assert_eq!(
            w.at(id).window_rect,
            Rect {
                left: 12,
                top: 24,
                right: 492,
                bottom: 384
            }
        );
        // An offset past a quarter of the work area resets the stack.
        w.monitors[0].window_stack = 100;
        let id = w.create_window_ex(c, t, &a, &mut pump).unwrap();
        assert_eq!(
            w.at(id).window_rect,
            Rect {
                left: 0,
                top: 0,
                right: 480,
                bottom: 360
            }
        );
        assert_eq!(w.monitors[0].window_stack, 1);
    }

    /// A default position with an app-given size keeps the size but is clamped into the
    /// monitor; an app-given position undoes the cascade's stacking effect.
    #[test]
    fn a_default_position_with_an_app_size_is_clamped_into_the_monitor() {
        let (w, c, t, atom, _, _) = setup();
        let mut pump = Rec::new(t);
        let mut a = args(atom, WS_OVERLAPPED);
        a.x = CW_USEDEFAULT;
        a.cx = 700;
        a.cy = 100;
        let id = w.create_window_ex(c, t, &a, &mut pump).unwrap();
        // 0+700 exceeds the 640-wide monitor: shifted left, clamped at the left edge.
        assert_eq!(
            w.at(id).window_rect,
            Rect {
                left: 0,
                top: 0,
                right: 700,
                bottom: 100
            }
        );
        assert_eq!(
            w.monitors[0].window_stack, 1,
            "a default position keeps the stack"
        );
        // An app-specified position undoes the stacking.
        w.monitors[0].window_stack = 3;
        let mut a = args(atom, WS_OVERLAPPED);
        a.x = 50;
        a.y = 60;
        a.cx = 100;
        a.cy = 100;
        let id = w.create_window_ex(c, t, &a, &mut pump).unwrap();
        assert_eq!(
            w.at(id).window_rect,
            Rect {
                left: 50,
                top: 60,
                right: 150,
                bottom: 160
            }
        );
        assert_eq!(
            w.monitors[0].window_stack, 3,
            "the stacking effect was undone"
        );
    }

    /// The default size fills the cascade rect (from the default position); the startup info
    /// overrides the defaults and is used once.
    #[test]
    fn the_default_size_fills_the_cascade_rect() {
        let (w, c, t, atom, _, _) = setup();
        let mut pump = Rec::new(t);
        let mut a = args(atom, WS_OVERLAPPED);
        a.x = CW_USEDEFAULT;
        a.cx = CW_USEDEFAULT;
        let id = w.create_window_ex(c, t, &a, &mut pump).unwrap();
        assert_eq!(
            w.at(id).window_rect,
            Rect {
                left: 0,
                top: 0,
                right: 480,
                bottom: 360
            }
        );
        // Startup info: position (5,6), size (70,80).
        w.thread_mut(t).startup = StartupInfo {
            flags: STARTF_USEPOSITION | STARTF_USESIZE,
            x: 5,
            y: 6,
            cx: 70,
            cy: 80,
        };
        let mut a = args(atom, WS_OVERLAPPED);
        a.x = CW_USEDEFAULT;
        a.cx = CW_USEDEFAULT;
        let id = w.create_window_ex(c, t, &a, &mut pump).unwrap();
        assert_eq!(
            w.at(id).window_rect,
            Rect {
                left: 5,
                top: 6,
                right: 75,
                bottom: 86
            }
        );
        assert_eq!(
            w.thread(t).startup.flags & (STARTF_USEPOSITION | STARTF_USESIZE),
            0,
            "the startup flags were used once"
        );
    }

    /// Popups clip siblings, a thick-framed window's size clamps into the min/max track, and
    /// negative sizes become zero.
    #[test]
    fn popups_clip_siblings_and_sizes_are_clamped() {
        let (w, c, t, atom, _, _) = setup();
        let mut pump = Rec::new(t);
        let a = args(atom, WS_POPUP);
        let id = w.create_window_ex(c, t, &a, &mut pump).unwrap();
        assert_eq!(w.at(id).style & WS_CLIPSIBLINGS, WS_CLIPSIBLINGS);
        // The min/max track clamp on a thick-framed window.
        pump.mmi = MinMaxInfo {
            reserved: (0, 0),
            max_size: (i32::MAX, i32::MAX),
            min_track: (100, 50),
            max_track: (200, 150),
        };
        let mut a = args(atom, WS_OVERLAPPED | WS_THICKFRAME);
        a.cx = 30;
        a.cy = 10_000;
        let id = w.create_window_ex(c, t, &a, &mut pump).unwrap();
        assert_eq!(
            w.at(id).window_rect,
            Rect {
                left: 10,
                top: 20,
                right: 110,
                bottom: 170
            }
        );
        // A plain child is not track-clamped, but negative sizes become zero.
        let parent = raw_window(w, t, WS_OVERLAPPED, None);
        let mut a = args(atom, WS_CHILD);
        a.parent = Some(parent);
        a.cx = -5;
        a.cy = -7;
        let id = w.create_window_ex(c, t, &a, &mut pump).unwrap();
        assert_eq!(
            w.at(id).window_rect,
            Rect {
                left: 10,
                top: 20,
                right: 10,
                bottom: 20
            }
        );
    }

    // --- Parent / owner / desktop wiring
    // ----------------------------------------------------------------

    /// The owner of a top-level window is the parent's top-level window; a topmost owner makes
    /// the window topmost; the parent link itself goes to the desktop window; an owner chain
    /// with a loop fails the create.
    #[test]
    fn the_owner_comes_from_the_parents_top_level() {
        let (w, c, t, atom, desk, _) = setup();
        let owner = raw_window(w, t, WS_OVERLAPPED, None);
        w.at_mut(owner).ex_style |= WS_EX_TOPMOST;
        let mut pump = Rec::new(t);
        let mut a = args(atom, WS_POPUP);
        a.parent = Some(owner);
        let id = w.create_window_ex(c, t, &a, &mut pump).unwrap();
        assert_eq!(w.at(id).owner, Some(owner));
        assert_eq!(
            w.at(id).ex_style & WS_EX_TOPMOST,
            WS_EX_TOPMOST,
            "above its owner"
        );
        assert_eq!(
            w.at(id).parent,
            Some(desk),
            "the parent link is the desktop window"
        );
        // An owner on another thread shares input state.
        let t2 = w
            .add_thread(OTHER_OWNER, DESKTOP, DESKTOP_CREATEWINDOW, Some(0x30), None)
            .unwrap();
        let foreign = raw_window(w, t2, WS_OVERLAPPED, None);
        let mut a = args(atom, WS_POPUP);
        a.parent = Some(foreign);
        let _ = w.create_window_ex(c, t, &a, &mut pump).unwrap();
        assert!(pump.events.contains(&Ev::Attach(t, t2, true)));
        // An owner-chain loop is refused and the record rolled back.
        let x = raw_window(w, t, WS_OVERLAPPED, None);
        let y = raw_window(w, t, WS_OVERLAPPED, None);
        w.at_mut(x).owner = Some(y);
        w.at_mut(y).owner = Some(x);
        let before = live(w);
        let mut a = args(atom, WS_POPUP);
        a.parent = Some(x);
        let err = w.create_window_ex(c, t, &a, &mut pump).unwrap_err();
        assert_eq!(
            err,
            Failure::OutOfMemory,
            "the owner-depth failure rolls back"
        );
        assert_eq!(live(w), before);
    }

    /// A top-level window with no parent is parented to the desktop window; a message-window
    /// parent stays the message window.
    #[test]
    fn a_missing_parent_defaults_to_the_desktop_window() {
        let (w, c, t, atom, desk, msg) = setup();
        let mut pump = Rec::new(t);
        let a = args(atom, WS_OVERLAPPED);
        let id = w.create_window_ex(c, t, &a, &mut pump).unwrap();
        assert_eq!(w.at(id).parent, Some(desk));
        assert_eq!(w.at(desk).child, Some(id));
        // A message-window parent stays.
        let mut a = args(atom, WS_OVERLAPPED);
        a.parent = Some(msg);
        let id = w.create_window_ex(c, t, &a, &mut pump).unwrap();
        assert_eq!(w.at(id).parent, Some(msg));
        assert_eq!(w.at(msg).child, Some(id));
    }

    /// A top-level window with no menu given inherits the class menu; a load failure is
    /// tolerated and leaves the window menu-less.
    #[test]
    fn the_class_menu_is_loaded_when_none_is_given() {
        let (w, c, t, _atom, _, _) = setup();
        let atom = register_on(
            c,
            class::Name::Text(&units("Menu")),
            &wnd_class(),
            DESKTOP,
            OWNER,
            class::MenuArg::Id(42),
        );
        let mut pump = Rec::new(t);
        let a = args(atom, WS_OVERLAPPED);
        let id = w.create_window_ex(c, t, &a, &mut pump).unwrap();
        assert!(pump.events.contains(&Ev::LoadMenu(MODULE)));
        assert_eq!(w.at(id).menu, Menu::Handle(0x5000));
        let (_, _, p) = pump
            .params
            .iter()
            .find(|(_, m, _)| *m == WM_NCCREATE)
            .unwrap();
        assert_eq!(p.menu, 0x5000);
        // A load failure is tolerated.
        pump.no_menus = true;
        let a = args(atom, WS_OVERLAPPED);
        let id = w.create_window_ex(c, t, &a, &mut pump).unwrap();
        assert_eq!(w.at(id).menu, Menu::None);
    }

    /// The menu is stored by kind: a child's as a raw id, a top-level window's as a handle.
    #[test]
    fn the_menu_is_stored_by_kind() {
        let (w, c, t, atom, _, _) = setup();
        let parent = raw_window(w, t, WS_OVERLAPPED, None);
        let mut pump = Rec::new(t);
        let mut a = args(atom, WS_CHILD);
        a.parent = Some(parent);
        a.menu = MenuInput::Id(9);
        let id = w.create_window_ex(c, t, &a, &mut pump).unwrap();
        assert_eq!(w.at(id).menu, Menu::Id(9));
        let mut a = args(atom, WS_OVERLAPPED);
        a.menu = MenuInput::Handle(0x9000);
        let id = w.create_window_ex(c, t, &a, &mut pump).unwrap();
        assert_eq!(w.at(id).menu, Menu::Handle(0x9000));
    }

    /// The CS_PARENTDC hack: a class with CS_PARENTDC clears the window's clip bits when the
    /// parent does not clip children (skipped for pre-4.0 windows).
    #[test]
    fn the_parentdc_hack_clears_the_clip_bits() {
        let (w, c, t, _atom, _, _) = setup();
        let mut wc = wnd_class();
        wc.style = class::CS_PARENTDC;
        let atom = register(c, class::Name::Text(&units("PD")), &wc);
        let parent = raw_window(w, t, WS_OVERLAPPED, None); // no WS_CLIPCHILDREN
        let mut pump = Rec::new(t);
        let mut a = args(atom, WS_CHILD | WS_CLIPSIBLINGS | WS_CLIPCHILDREN);
        a.parent = Some(parent);
        let id = w.create_window_ex(c, t, &a, &mut pump).unwrap();
        assert_eq!(w.at(id).style & (WS_CLIPCHILDREN | WS_CLIPSIBLINGS), 0);
        // A pre-4.0 window keeps them.
        let mut a = args(atom, WS_CHILD | WS_CLIPSIBLINGS);
        a.parent = Some(parent);
        a.version = 0x0003_0000;
        let id = w.create_window_ex(c, t, &a, &mut pump).unwrap();
        assert_eq!(w.at(id).style & WS_CLIPSIBLINGS, WS_CLIPSIBLINGS);
    }

    /// A child of another thread's parent attaches input.
    #[test]
    fn a_cross_thread_child_attaches_input() {
        let (w, c, t, atom, _, _) = setup();
        let t2 = w
            .add_thread(OTHER_OWNER, DESKTOP, DESKTOP_CREATEWINDOW, Some(0x40), None)
            .unwrap();
        let parent = raw_window(w, t2, WS_OVERLAPPED, None);
        let mut pump = Rec::new(t);
        let mut a = args(atom, WS_CHILD);
        a.parent = Some(parent);
        let id = w.create_window_ex(c, t, &a, &mut pump).unwrap();
        assert!(pump.events.contains(&Ev::Attach(t, t2, true)));
        assert_eq!(w.at(id).parent, Some(parent));
    }

    // --- Message ordering and failure rollback
    // -----------------------------------------------------------

    /// The create's message order: WM_NCCREATE, the link into the parent's child list, then
    /// WM_NCCALCSIZE (client == window rect: no frame in the minimal subset), then WM_CREATE.
    #[test]
    fn the_create_message_order() {
        let (w, c, t, atom, desk, _) = setup();
        let mut pump = Rec::new(t);
        let id = create(w, c, t, atom, WS_OVERLAPPED, &mut pump).unwrap();
        assert_eq!(
            pump.sends(),
            vec![(id, WM_NCCREATE), (id, WM_NCCALCSIZE), (id, WM_CREATE)]
        );
        assert_eq!(w.at(id).client_rect, w.at(id).window_rect);
        assert_eq!(
            w.at(desk).child,
            Some(id),
            "linked at the head of the desktop's list"
        );
    }

    /// A title set during WM_NCCREATE reaches the WM_CREATE parameters.
    #[test]
    fn the_title_set_during_nccreate_reaches_create() {
        let (w, c, t, atom, _, _) = setup();
        let mut pump = Rec::new(t);
        pump.title_on_nccreate = Some(units("new title"));
        let a = args(atom, WS_OVERLAPPED);
        let _ = w.create_window_ex(c, t, &a, &mut pump).unwrap();
        let (_, _, p) = pump
            .params
            .iter()
            .find(|(_, m, _)| *m == WM_CREATE)
            .unwrap();
        assert_eq!(p.name.as_slice(), &units("new title")[..]);
    }

    /// A WM_NCCREATE answered with 0 rolls the creation back: the only messages are WM_NCCREATE
    /// and WM_NCDESTROY (no WM_DESTROY — the window was never linked), and the record, handle,
    /// class reference and window count are all released.
    #[test]
    fn a_failed_nccreate_rolls_back() {
        let (w, c, t, atom, _, _) = setup();
        let mut pump = Rec::new(t);
        pump.nccreate_answer = 0;
        let err = create(w, c, t, atom, WS_OVERLAPPED, &mut pump).unwrap_err();
        assert_eq!(err, Failure::OutOfMemory);
        assert_eq!(pump.messages(), vec![WM_NCCREATE, WM_NCDESTROY]);
        assert_eq!(live(w), 2, "only the desktop windows remain");
        assert_eq!(w.thread(t).window_count, 0);
        // The class reference went back: the class can be unregistered now.
        assert!(c
            .unregister_class(class::Name::Text(&units("Test")), OWNER, MODULE)
            .is_ok());
    }

    /// A WM_CREATE answered with -1 runs the full destroy (WM_DESTROY and all) and fails the
    /// create.
    #[test]
    fn a_failed_create_destroys_the_window() {
        let (w, c, t, atom, _, _) = setup();
        let mut pump = Rec::new(t);
        pump.create_answer = -1;
        let err = create(w, c, t, atom, WS_OVERLAPPED, &mut pump).unwrap_err();
        assert_eq!(err, Failure::OutOfMemory);
        assert_eq!(
            pump.messages(),
            vec![
                WM_NCCREATE,
                WM_NCCALCSIZE,
                WM_CREATE,
                WM_DESTROY,
                WM_NCDESTROY
            ]
        );
        assert_eq!(live(w), 2);
        assert_eq!(w.thread(t).window_count, 0);
    }

    /// After WM_CREATE: WM_SIZE and WM_MOVE unless size/move are deferred (tiled windows), the
    /// WM_MOVE position client-relative for children, WM_PARENTNOTIFY for children, and the
    /// min/max command when the style asks.
    #[test]
    fn the_post_create_messages() {
        let (w, c, t, atom, _, _) = setup();
        let parent = raw_window(w, t, WS_OVERLAPPED, None);
        w.at_mut(parent).client_rect = Rect {
            left: 10,
            top: 20,
            right: 600,
            bottom: 400,
        };
        let mut pump = Rec::new(t);
        let mut a = args(atom, WS_CHILD);
        a.parent = Some(parent);
        a.x = 5;
        a.y = 6;
        a.cx = 30;
        a.cy = 40;
        let id = w.create_window_ex(c, t, &a, &mut pump).unwrap();
        let own: Vec<u32> = pump
            .sends()
            .iter()
            .filter(|(target, _)| *target == id)
            .map(|(_, m)| *m)
            .collect();
        assert_eq!(
            own,
            vec![WM_NCCREATE, WM_NCCALCSIZE, WM_CREATE, WM_SIZE, WM_MOVE]
        );
        // WM_MOVE's position is client-relative for the child: (15,26) - (10,20) = (5,6).
        let move_send = pump
            .events
            .iter()
            .find(|e| matches!(e, Ev::Send(t2, WM_MOVE, _, _) if *t2 == id))
            .unwrap();
        assert_eq!(
            *move_send,
            Ev::Send(id, WM_MOVE, 0, makelong(5, 6) as LParam)
        );
        // The parent was told about the create.
        assert!(pump.events.iter().any(|e| matches!(
            e,
            Ev::Send(t2, WM_PARENTNOTIFY, _, _) if *t2 == parent
        )));
        // A tiled window defers size/move to show time.
        pump.events.clear();
        let id = create(w, c, t, atom, WS_OVERLAPPED, &mut pump).unwrap();
        let own: Vec<u32> = pump
            .sends()
            .iter()
            .filter(|(target, _)| *target == id)
            .map(|(_, m)| *m)
            .collect();
        assert_eq!(own, vec![WM_NCCREATE, WM_NCCALCSIZE, WM_CREATE]);
        // A minimized window gets the min/max command.
        pump.events.clear();
        let id = create(w, c, t, atom, WS_OVERLAPPED | WS_MINIMIZE, &mut pump).unwrap();
        assert!(pump
            .events
            .contains(&Ev::MinMax(id, SW_SHOWMINNOACTIVE as u32)));
    }

    /// A child without WS_EX_NOPARENTNOTIFY tells its parent (WM_PARENTNOTIFY, wParam packs
    /// WM_CREATE and the menu id, lParam is the child's handle); with the ex-style it does not.
    #[test]
    fn children_notify_their_parent() {
        let (w, c, t, atom, _, _) = setup();
        let parent = raw_window(w, t, WS_OVERLAPPED, None);
        let mut pump = Rec::new(t);
        let mut a = args(atom, WS_CHILD);
        a.parent = Some(parent);
        a.menu = MenuInput::Id(9);
        let id = w.create_window_ex(c, t, &a, &mut pump).unwrap();
        let handle = w.at(id).handle;
        assert!(pump.events.contains(&Ev::Send(
            parent,
            WM_PARENTNOTIFY,
            makelong(WM_CREATE as u16, 9),
            handle as LParam
        )));
        // With WS_EX_NOPARENTNOTIFY: no notify.
        let mut pump = Rec::new(t);
        let mut a = args(atom, WS_CHILD);
        a.parent = Some(parent);
        a.ex_style = WS_EX_NOPARENTNOTIFY;
        let _ = w.create_window_ex(c, t, &a, &mut pump).unwrap();
        assert!(!pump
            .events
            .iter()
            .any(|e| matches!(e, Ev::Send(_, WM_PARENTNOTIFY, _, _))));
    }

    /// A window created with WS_VISIBLE is shown as the last step (the stored style lacks
    /// WS_VISIBLE); the process's hotkey lands on the first tiled window.
    #[test]
    fn a_visible_window_is_shown_last() {
        let (w, c, t, atom, _, _) = setup();
        w.thread_mut(t).hotkey = 0x1234;
        let mut pump = Rec::new(t);
        let a = args(atom, WS_OVERLAPPED | WS_VISIBLE);
        let id = w.create_window_ex(c, t, &a, &mut pump).unwrap();
        // The create parameters carried WS_VISIBLE; the stored style had it stripped (the show
        // at the end sets the visible bit again).
        let (_, _, p) = &pump.params[0];
        assert_eq!(p.style & WS_VISIBLE, WS_VISIBLE);
        assert!(pump.events.contains(&Ev::Show(id, SW_SHOW as u32)));
        // The show is the last window-manager step; the hotkey send follows it.
        assert_eq!(
            pump.events.last(),
            Some(&Ev::Send(id, WM_SETHOTKEY, 0x1234, 0))
        );
        assert_eq!(w.thread(t).hotkey, 0, "the hotkey was consumed");
        // Without WS_VISIBLE: no show.
        let mut pump = Rec::new(t);
        create(w, c, t, atom, WS_OVERLAPPED, &mut pump).unwrap();
        assert!(!pump.events.iter().any(|e| matches!(e, Ev::Show(..))));
    }

    // --- Destroy entry
    // ----------------------------------------------------------------------------------

    /// An invalid handle names no window; the destroy service answers
    /// ERROR_INVALID_WINDOW_HANDLE (1400).
    #[test]
    fn an_invalid_handle_names_no_window() {
        let (w, c, t, _atom, _, _) = setup();
        let mut pump = Rec::new(t);
        assert_eq!(w.window_from_handle(0xDEAD_BEEF), None);
        assert_eq!(w.window_from_handle(0), None);
        let err = w
            .destroy_window_handle(c, t, 0xDEAD_BEEF, &mut pump)
            .unwrap_err();
        assert_eq!(err, Failure::InvalidWindowHandle);
        assert_eq!(err.code(), 1400);
        assert_eq!(err.status(), STATUS_INVALID_HANDLE);
    }

    /// Another thread's window cannot be destroyed: ERROR_ACCESS_DENIED (5), nothing happens.
    #[test]
    fn another_threads_window_cannot_be_destroyed() {
        let (w, c, t, atom, _, _) = setup();
        let t2 = w
            .add_thread(OTHER_OWNER, DESKTOP, DESKTOP_CREATEWINDOW, Some(0x50), None)
            .unwrap();
        let mut pump = Rec::new(t);
        let id = create(w, c, t, atom, WS_OVERLAPPED, &mut pump).unwrap();
        let mut pump2 = Rec::new(t2);
        let err = w.destroy_window(c, t2, id, &mut pump2).unwrap_err();
        assert_eq!(err, Failure::AccessDenied);
        assert_eq!(err.code(), 5);
        assert!(w.pool.is_live(id));
        assert!(!w.at(id).flags.destroyed);
        assert!(pump2.events.is_empty());
    }

    /// A window already marked for destruction is adopted by the current thread and the destroy
    /// proceeds instead of failing the owner check.
    #[test]
    fn a_marked_window_is_destroyed_on_reentry() {
        let (w, c, t, atom, _, _) = setup();
        let t2 = w
            .add_thread(OTHER_OWNER, DESKTOP, DESKTOP_CREATEWINDOW, Some(0x60), None)
            .unwrap();
        let mut pump = Rec::new(t);
        let id = create(w, c, t, atom, WS_OVERLAPPED, &mut pump).unwrap();
        let handle = w.at(id).handle;
        // Marked for destroy, owned by the other thread.
        w.handles.update(handle, |mut e| {
            e.marked_destroy = true;
            e.owner = t2;
            e
        });
        w.at_mut(id).thread = t2;
        let mut pump2 = Rec::new(t);
        assert!(w.destroy_window(c, t, id, &mut pump2).unwrap());
        assert!(!w.pool.is_live(id));
    }

    /// A hook's veto leaves the window untouched: false, no messages, not marked.
    #[test]
    fn a_hook_can_veto_the_destroy() {
        let (w, c, t, atom, _, _) = setup();
        let mut pump = Rec::new(t);
        let id = create(w, c, t, atom, WS_OVERLAPPED, &mut pump).unwrap();
        pump.events.clear();
        pump.veto_destroy = true;
        assert!(!w.destroy_window(c, t, id, &mut pump).unwrap());
        assert!(w.pool.is_live(id));
        assert!(!w.at(id).flags.destroyed);
        assert!(pump.events.is_empty());
    }

    // --- The destroy cascade
    // ------------------------------------------------------------------------------

    /// The destroy hides before anything is messaged: a child gets SW_HIDE, a top-level gets the
    /// hide-only SetWindowPos; a child tells its parent first; if the hide does not take, the
    /// visible bit is forced off and the windows below are redrawn.
    #[test]
    fn the_destroy_hides_before_messaging() {
        let (w, c, t, atom, _, _) = setup();
        let parent = raw_window(w, t, WS_OVERLAPPED, None);
        let mut pump = Rec::new(t);
        let mut a = args(atom, WS_CHILD | WS_VISIBLE);
        a.parent = Some(parent);
        let id = w.create_window_ex(c, t, &a, &mut pump).unwrap();
        let handle = w.at(id).handle;
        pump.events.clear();
        assert!(w.destroy_window(c, t, id, &mut pump).unwrap());
        assert_eq!(
            pump.sends(),
            vec![
                (parent, WM_PARENTNOTIFY),
                (id, WM_DESTROY),
                (id, WM_NCDESTROY)
            ]
        );
        // The parent notify carried WM_DESTROY and the child's handle.
        assert!(pump.events.contains(&Ev::Send(
            parent,
            WM_PARENTNOTIFY,
            makelong(WM_DESTROY as u16, 0),
            handle as LParam
        )));
        // The hide (SW_HIDE) came before the first WM_DESTROY.
        let first_destroy = pump
            .events
            .iter()
            .position(|e| matches!(e, Ev::Send(_, WM_DESTROY, _, _)))
            .unwrap();
        let hide = pump
            .events
            .iter()
            .position(|e| matches!(e, Ev::Show(_, cmd) if *cmd == SW_HIDE as u32))
            .unwrap();
        assert!(hide < first_destroy);
        // A top-level window gets the hide-only SetWindowPos instead.
        let mut pump = Rec::new(t);
        let id = create(w, c, t, atom, WS_OVERLAPPED | WS_VISIBLE, &mut pump).unwrap();
        pump.events.clear();
        assert!(w.destroy_window(c, t, id, &mut pump).unwrap());
        assert!(pump.events.contains(&Ev::SetPos(
            id,
            SWP_HIDEWINDOW | SWP_NOACTIVATE | SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER
        )));
        // A hide that does not take: the visible bit is forced off and below is redrawn.
        let mut pump = Rec::new(t);
        pump.hide_works = false;
        let id = create(w, c, t, atom, WS_OVERLAPPED | WS_VISIBLE, &mut pump).unwrap();
        w.at_mut(id).style |= WS_VISIBLE; // the show ran, but did not stick
        pump.events.clear();
        assert!(w.destroy_window(c, t, id, &mut pump).unwrap());
        assert!(pump.events.contains(&Ev::Redraw(id)));
    }

    /// Owned windows are destroyed before the owner's own WM_DESTROY.
    #[test]
    fn owned_windows_go_first() {
        let (w, c, t, atom, _, _) = setup();
        let mut pump = Rec::new(t);
        let owner = create(w, c, t, atom, WS_OVERLAPPED, &mut pump).unwrap();
        let mut a = args(atom, WS_POPUP);
        a.parent = Some(owner);
        let owned = w.create_window_ex(c, t, &a, &mut pump).unwrap();
        assert_eq!(w.at(owned).owner, Some(owner));
        pump.events.clear();
        assert!(w.destroy_window(c, t, owner, &mut pump).unwrap());
        let sends = pump.sends();
        let owned_destroy = sends
            .iter()
            .position(|(t2, m)| *t2 == owned && *m == WM_DESTROY)
            .unwrap();
        let owner_destroy = sends
            .iter()
            .position(|(t2, m)| *t2 == owner && *m == WM_DESTROY)
            .unwrap();
        assert!(owned_destroy < owner_destroy);
        assert_eq!(
            &sends[owned_destroy..owned_destroy + 2],
            &[(owned, WM_DESTROY), (owned, WM_NCDESTROY)]
        );
    }

    /// Destroying the active window activates its owner (a popup) or skips to the next; a
    /// failed activation clears the active/focus windows and destroys the caret; the owner
    /// chain's last-active popup is repointed to the direct owner.
    #[test]
    fn the_active_window_fixups() {
        let (w, c, t, atom, _, _) = setup();
        let mut pump = Rec::new(t);
        let owner = create(w, c, t, atom, WS_OVERLAPPED, &mut pump).unwrap();
        let mut a = args(atom, WS_POPUP);
        a.parent = Some(owner);
        let popup = w.create_window_ex(c, t, &a, &mut pump).unwrap();
        w.thread_mut(t).active = Some(popup);
        w.thread_mut(t).focus = Some(popup);
        w.at_mut(owner).last_active = Some(popup);
        pump.events.clear();
        assert!(w.destroy_window(c, t, popup, &mut pump).unwrap());
        // A popup's creator is tried.
        assert!(pump.events.contains(&Ev::Activate(owner, Activate::Try)));
        assert_eq!(
            w.at(owner).last_active,
            Some(owner),
            "repointed to the direct owner"
        );
        // A failed activation of the active window clears active/focus and the caret.
        let id = create(w, c, t, atom, WS_OVERLAPPED, &mut pump).unwrap();
        w.thread_mut(t).active = Some(id);
        w.thread_mut(t).focus = Some(id);
        pump.activate_ok = false;
        pump.events.clear();
        assert!(w.destroy_window(c, t, id, &mut pump).unwrap());
        assert!(pump.events.contains(&Ev::Activate(id, Activate::Skip)));
        assert_eq!(w.thread(t).active, None);
        assert_eq!(w.thread(t).focus, None);
        assert!(pump.events.contains(&Ev::Caret));
    }

    /// Build the tree P -> C1 -> G1, C2.
    fn tree(
        w: &mut Windows,
        c: &mut class::Registry,
        t: ThreadId,
        atom: class::Atom,
        pump: &mut Rec,
    ) -> (WindowId, WindowId, WindowId, WindowId) {
        let p = create(w, c, t, atom, WS_OVERLAPPED, pump).unwrap();
        let mut a = args(atom, WS_CHILD);
        a.parent = Some(p);
        let c1 = w.create_window_ex(c, t, &a, pump).unwrap();
        let mut a = args(atom, WS_CHILD);
        a.parent = Some(c1);
        let g1 = w.create_window_ex(c, t, &a, pump).unwrap();
        let mut a = args(atom, WS_CHILD);
        a.parent = Some(p);
        let c2 = w.create_window_ex(c, t, &a, pump).unwrap();
        (p, c1, g1, c2)
    }

    /// The full cascade order: every window's WM_DESTROY precedes its WM_NCDESTROY, the children
    /// depth-first parent before children, and the parent's WM_NCDESTROY after its children's;
    /// then the unlink and the freed records.
    #[test]
    fn the_full_cascade_order() {
        let (w, c, t, atom, desk, _) = setup();
        let mut pump = Rec::new(t);
        let (p, c1, g1, c2) = tree(w, c, t, atom, &mut pump);
        pump.events.clear();
        assert!(w.destroy_window(c, t, p, &mut pump).unwrap());
        assert_eq!(
            pump.sends(),
            vec![
                (p, WM_DESTROY),
                (c1, WM_DESTROY),
                (g1, WM_DESTROY),
                (c2, WM_DESTROY),
                (g1, WM_NCDESTROY),
                (c1, WM_NCDESTROY),
                (c2, WM_NCDESTROY),
                (p, WM_NCDESTROY),
            ]
        );
        assert_eq!(w.at(desk).child, None, "unlinked from the desktop's list");
        for id in [p, c1, g1, c2] {
            assert!(!w.pool.is_live(id), "the record was freed");
        }
        assert_eq!(w.thread(t).window_count, 0);
    }

    /// A handler that destroys the next sibling during WM_DESTROY stops the child loop (the
    /// sibling's own destroy already ran inside the handler).
    #[test]
    fn a_handler_destroying_a_sibling_stops_the_loop() {
        let (w, c, t, atom, _, _) = setup();
        let mut pump = Rec::new(t);
        let (p, c1, g1, c2) = tree(w, c, t, atom, &mut pump);
        pump.events.clear();
        pump.destroy_on_destroy = Some((c1, c2));
        assert!(w.destroy_window(c, t, p, &mut pump).unwrap());
        assert_eq!(
            pump.sends(),
            vec![
                (p, WM_DESTROY),
                (c1, WM_DESTROY),
                // The handler's destroy of c2 (a child, so it notifies its parent first):
                (p, WM_PARENTNOTIFY),
                (c2, WM_DESTROY),
                (c2, WM_NCDESTROY),
                (g1, WM_DESTROY),
                (g1, WM_NCDESTROY),
                (c1, WM_NCDESTROY),
                (p, WM_NCDESTROY),
            ]
        );
    }

    /// A chain of children as deep as the nesting limit allows goes in one destroy: WM_DESTROY
    /// from the top down, WM_NCDESTROY from the bottom up, every record freed (the cascade keeps
    /// its place in the records, not in recursion).
    #[test]
    fn the_deepest_nesting_is_destroyed() {
        let (w, c, t, atom, desk, _) = setup();
        let mut pump = Rec::new(t);
        let top = create(w, c, t, atom, WS_OVERLAPPED, &mut pump).unwrap();
        let mut chain = vec![top];
        for _ in 0..98 {
            let mut a = args(atom, WS_CHILD);
            a.ex_style = WS_EX_NOPARENTNOTIFY;
            a.parent = chain.last().copied();
            chain.push(w.create_window_ex(c, t, &a, &mut pump).unwrap());
        }
        pump.events.clear();
        assert!(w.destroy_window(c, t, top, &mut pump).unwrap());
        let destroys: Vec<WindowId> = pump
            .sends()
            .iter()
            .filter(|(_, m)| *m == WM_DESTROY)
            .map(|(id, _)| *id)
            .collect();
        assert_eq!(destroys, chain);
        let ncdestroys: Vec<WindowId> = pump
            .sends()
            .iter()
            .filter(|(_, m)| *m == WM_NCDESTROY)
            .map(|(id, _)| *id)
            .collect();
        assert_eq!(ncdestroys, chain.iter().rev().copied().collect::<Vec<_>>());
        assert!(chain.iter().all(|&id| !w.pool.is_live(id)));
        assert_eq!(w.at(desk).child, None);
        assert_eq!(w.thread(t).window_count, 0);
    }

    /// An owner chain goes deepest first: each owned window's destroy runs whole before its
    /// owner's WM_DESTROY, each hidden before the windows it owns go.
    #[test]
    fn an_owner_chain_is_destroyed_deepest_first() {
        let (w, c, t, atom, _, _) = setup();
        let mut pump = Rec::new(t);
        let root = create(w, c, t, atom, WS_OVERLAPPED | WS_VISIBLE, &mut pump).unwrap();
        let mut chain = vec![root];
        for _ in 0..40 {
            let mut a = args(atom, WS_POPUP | WS_VISIBLE);
            a.parent = chain.last().copied();
            let owned = w.create_window_ex(c, t, &a, &mut pump).unwrap();
            assert_eq!(w.at(owned).owner, chain.last().copied());
            chain.push(owned);
        }
        pump.events.clear();
        assert!(w.destroy_window(c, t, root, &mut pump).unwrap());
        let sends = pump.sends();
        let expected: Vec<(WindowId, u32)> = chain
            .iter()
            .rev()
            .flat_map(|&id| [(id, WM_DESTROY), (id, WM_NCDESTROY)])
            .collect();
        assert_eq!(sends, expected);
        // Every hide comes before the first WM_DESTROY, the root's first.
        let hides: Vec<WindowId> = pump
            .events
            .iter()
            .filter_map(|e| match e {
                Ev::SetPos(id, flags) if flags & SWP_HIDEWINDOW != 0 => Some(*id),
                _ => None,
            })
            .collect();
        assert_eq!(hides, chain);
        assert!(chain.iter().all(|&id| !w.pool.is_live(id)));
        assert_eq!(w.thread(t).window_count, 0);
    }

    /// An owned window whose destroy a hook vetoes loses its owner, and so does one of another
    /// thread's; the owner's destroy goes on (the scan would find them again otherwise).
    #[test]
    fn an_owned_window_that_cannot_go_loses_its_owner() {
        let (w, c, t, atom, desk, _) = setup();
        let mut pump = Rec::new(t);
        let owner = create(w, c, t, atom, WS_OVERLAPPED, &mut pump).unwrap();
        let mut a = args(atom, WS_POPUP);
        a.parent = Some(owner);
        let owned = w.create_window_ex(c, t, &a, &mut pump).unwrap();
        let t2 = w
            .add_thread(OTHER_OWNER, DESKTOP, DESKTOP_CREATEWINDOW, Some(0x70), None)
            .unwrap();
        let foreign = raw_window(w, t2, WS_POPUP, Some(desk));
        w.link_window(foreign, ZOrder::Top, desk);
        w.at_mut(foreign).owner = Some(owner);
        // The hook vetoes the owned window's destroy alone.
        pump.veto_window = Some(owned);
        assert!(w.destroy_window(c, t, owner, &mut pump).unwrap());
        assert!(!w.pool.is_live(owner));
        assert!(w.pool.is_live(owned));
        assert_eq!(w.at(owned).owner, None, "the vetoed window lost its owner");
        assert!(w.pool.is_live(foreign));
        assert_eq!(
            w.at(foreign).owner,
            None,
            "the foreign window lost its owner"
        );
    }

    /// The subtree depth counts the window's own descendants, not its siblings'.
    #[test]
    fn the_subtree_depth_is_the_windows_own() {
        let (w, _c, t, _atom, desk, _) = setup();
        let a = raw_window(w, t, WS_OVERLAPPED, Some(desk));
        let b = raw_window(w, t, WS_OVERLAPPED, Some(desk));
        w.link_window(b, ZOrder::Top, desk);
        w.link_window(a, ZOrder::Top, desk);
        assert_eq!(w.at(a).next, Some(b));
        // b has a chain of 5 below it; a has 2.
        let mut parent = b;
        for _ in 0..5 {
            let id = raw_window(w, t, WS_CHILD, Some(parent));
            w.link_window(id, ZOrder::Bottom, parent);
            parent = id;
        }
        let a1 = raw_window(w, t, WS_CHILD, Some(a));
        w.link_window(a1, ZOrder::Bottom, a);
        let a2 = raw_window(w, t, WS_CHILD, Some(a));
        w.link_window(a2, ZOrder::Bottom, a);
        let a21 = raw_window(w, t, WS_CHILD, Some(a2));
        w.link_window(a21, ZOrder::Bottom, a2);
        assert_eq!(w.subtree_depth(a, 1), 3);
        assert_eq!(w.subtree_depth(b, 1), 6);
        assert_eq!(w.subtree_depth(a21, 4), 4);
    }

    /// The free's cleanup calls run after WM_NCDESTROY, in order: the window teardown, the quit
    /// repost, the menu's destroy, the properties; the class reference goes back.
    #[test]
    fn the_free_cleanup_calls() {
        let (w, c, t, atom, _, _) = setup();
        let mut pump = Rec::new(t);
        let mut a = args(atom, WS_OVERLAPPED);
        a.menu = MenuInput::Handle(0x9000);
        let id = w.create_window_ex(c, t, &a, &mut pump).unwrap();
        pump.events.clear();
        assert!(w.destroy_window(c, t, id, &mut pump).unwrap());
        let after = &pump.events[pump
            .events
            .iter()
            .position(|e| matches!(e, Ev::Send(_, WM_NCDESTROY, _, _)))
            .unwrap()
            + 1..];
        assert_eq!(
            after,
            &[
                Ev::Teardown(id),
                Ev::Quit(id),
                Ev::DestroyMenu(0x9000),
                Ev::Props(id),
            ]
        );
        // The class reference went back.
        assert!(c
            .unregister_class(class::Name::Text(&units("Test")), OWNER, MODULE)
            .is_ok());
    }

    /// The free-vs-zombie decision: with the last lock the record and handle are freed (the old
    /// HWND stops validating); with another reference held the window becomes a zombie: the
    /// default procedure, the icon-title class, server-side, tiled, menu-less, handle still
    /// valid.
    #[test]
    fn the_free_vs_zombie_decision() {
        let (w, c, t, atom, _, _) = setup();
        // The icon-title system class ("#32771").
        let mut wc = wnd_class();
        wc.instance = class::WINDOW_MANAGER_MODULE;
        let icon = c
            .register_class(
                &wc,
                class::Name::Atom(ICONTITLE_ATOM),
                class::MenuArg::None,
                OWNER,
                RegisterFlags {
                    win40_compat: true,
                    system_class: true,
                    ..RegisterFlags::default()
                },
                DESKTOP,
            )
            .unwrap();
        assert_eq!(icon, ICONTITLE_ATOM);
        let mut pump = Rec::new(t);
        // Freed: the last lock.
        let id = create(w, c, t, atom, WS_OVERLAPPED, &mut pump).unwrap();
        let handle = w.at(id).handle;
        assert!(w.destroy_window(c, t, id, &mut pump).unwrap());
        assert!(!w.pool.is_live(id));
        assert_eq!(
            w.window_from_handle(handle),
            None,
            "the old HWND no longer validates"
        );
        assert_eq!(w.thread(t).window_count, 0);
        // Zombie: another reference held.
        let mut a = args(atom, WS_OVERLAPPED);
        a.menu = MenuInput::Handle(0x9000);
        let id = w.create_window_ex(c, t, &a, &mut pump).unwrap();
        let handle = w.at(id).handle;
        w.at_mut(id).locks = 2;
        assert!(w.destroy_window(c, t, id, &mut pump).unwrap());
        assert!(w.pool.is_live(id), "the zombie stays");
        assert_eq!(
            w.window_from_handle(handle),
            Some(id),
            "its handle still validates"
        );
        let rec = w.at(id);
        assert_eq!(rec.proc, Proc::Default);
        assert!(rec.flags.server_side_proc);
        assert_eq!(
            rec.class,
            c.class_ptr(ICONTITLE_ATOM, OWNER, class::WINDOW_MANAGER_MODULE)
        );
        assert_eq!(
            rec.style & 0xFFFF_0000,
            0,
            "the type bits are cleared (tiled)"
        );
        assert_eq!(rec.menu, Menu::None);
        assert_eq!(
            w.thread(t).window_count,
            1,
            "the count drops only at the real free"
        );
    }

    /// The end state of a clean destroy: true, WM_DESTROY then WM_NCDESTROY, unlinked from the
    /// desktop's child list, the class reference and window count back, the handle freed so a
    /// second destroy of the same HWND fails with 1400.
    #[test]
    fn the_end_state_after_a_clean_destroy() {
        let (w, c, t, atom, desk, _) = setup();
        let mut pump = Rec::new(t);
        let id = create(w, c, t, atom, WS_OVERLAPPED, &mut pump).unwrap();
        let handle = w.at(id).handle;
        assert_eq!(w.at(desk).child, Some(id));
        pump.events.clear();
        assert!(w.destroy_window_handle(c, t, handle, &mut pump).unwrap());
        assert_eq!(pump.sends(), vec![(id, WM_DESTROY), (id, WM_NCDESTROY)]);
        assert!(!w.pool.is_live(id));
        assert_eq!(w.at(desk).child, None);
        assert_eq!(w.thread(t).window_count, 0);
        assert!(
            c.unregister_class(class::Name::Text(&units("Test")), OWNER, MODULE)
                .is_ok(),
            "the class reference is back"
        );
        // A second destroy of the same HWND: 1400.
        let err = w
            .destroy_window_handle(c, t, handle, &mut pump)
            .unwrap_err();
        assert_eq!(err, Failure::InvalidWindowHandle);
        assert_eq!(err.code(), 1400);
    }

    // --- The window manager: the services' side
    // ----------------------------------------------------------

    /// A fresh window manager, built in place and leaked, as the target's lock builds it.
    fn manager() -> &'static mut WindowManager {
        let mut manager = Box::<WindowManager>::new_uninit();
        // SAFETY: the box is valid, aligned and the records' final address once leaked.
        unsafe { WindowManager::write_empty(manager.as_mut_ptr()) };
        // SAFETY: written whole just above.
        Box::leak(unsafe { manager.assume_init() })
    }

    /// A 640x480 work area.
    const SCREEN: Rect = Rect {
        left: 0,
        top: 0,
        right: 640,
        bottom: 480,
    };

    fn key(index: u16, generation: u16) -> ThreadKey {
        ThreadKey { index, generation }
    }

    /// A thread's record is made at its first service and found again at its next; another thread
    /// gets its own; a thread reusing an ended one's slot takes the record over when it holds no
    /// windows, and gets a fresh one otherwise.
    #[test]
    fn a_thread_keeps_its_record() {
        let w = windows();
        let first = w
            .connect_thread(key(3, 0), OWNER, DESKTOP, DESKTOP_CREATEWINDOW, 0x10)
            .unwrap();
        assert_eq!(
            w.connect_thread(key(3, 0), OWNER, DESKTOP, DESKTOP_CREATEWINDOW, 0x10),
            Some(first)
        );
        let thread = w.thread(first);
        assert_eq!(thread.process, OWNER);
        assert_eq!(thread.desktop, DESKTOP);
        assert_eq!(thread.desktop_handle, Some(0x10));
        assert_eq!(thread.desktop_access, DESKTOP_CREATEWINDOW);
        let other = w
            .connect_thread(key(4, 0), OTHER_OWNER, DESKTOP, 0, 0x20)
            .unwrap();
        assert_ne!(other, first);

        // Slot 3 again, a later generation: the ended thread's empty record is taken over.
        let again = w
            .connect_thread(key(3, 1), OTHER_OWNER, DESKTOP, 0, 0x30)
            .unwrap();
        assert_eq!(again, first, "the lowest free record: the one given up");
        assert_eq!(w.thread(again).process, OTHER_OWNER);
        assert_eq!(w.thread(again).key, Some(key(3, 1)));

        // An ended thread that still holds windows keeps its record.
        w.thread_mut(again).window_count = 1;
        let fresh = w
            .connect_thread(key(3, 2), OWNER, DESKTOP, 0, 0x40)
            .unwrap();
        assert_ne!(fresh, again);
        assert!(w.thread(again).live);
    }

    /// The boot's desktop: the primary monitor's work area, a thread of the window manager's own,
    /// the desktop window over the work area and the message window, both parentless and
    /// unlinked, of the two system classes; the desktop names them.
    #[test]
    fn the_boot_makes_the_desktops_windows() {
        let m = manager();
        m.boot_desktop(DESKTOP, SCREEN).unwrap();
        assert_eq!(m.windows.monitors[PRIMARY_MONITOR as usize].rect, SCREEN);
        let desktop = *m.windows.desktop_by_id(DESKTOP).unwrap();
        let (window, message) = (desktop.window.unwrap(), desktop.message_window.unwrap());
        assert_ne!(window, message);
        let w = m.windows.at(window);
        assert_eq!(w.window_rect, SCREEN);
        assert_eq!(w.process, class::SYSTEM_OWNER);
        assert_eq!(w.parent, None);
        assert_eq!(m.windows.at(message).parent, None);
        assert_eq!(w.child, None, "nothing is linked under the desktop yet");
        let thread = m.windows.thread(w.thread);
        assert_eq!(thread.desktop_handle, None);
        assert_eq!(thread.key, None);
        assert_eq!(thread.window_count, 2);

        let class_of = |id| {
            let view = m.windows.class_window(m.windows.handle_of(id)).unwrap();
            let mut out = [0u16; 16];
            let written = m.classes.class_name(view.class, &mut out);
            String::from_utf16(&out[..written]).unwrap()
        };
        assert_eq!(class_of(window), "#32769");
        assert_eq!(class_of(message), "Message");
        // The system classes are every process's.
        assert!(m
            .classes
            .class_ptr(DESKTOP_CLASS_ATOM, OWNER, MODULE)
            .is_some());
    }

    /// The service's creation: the string class name resolved through the class registry, the
    /// parent handle resolved (HWND_MESSAGE to the desktop's message window), an unknown parent
    /// handle refused with ERROR_INVALID_WINDOW_HANDLE, a top-level window linked under the
    /// desktop window.
    #[test]
    fn the_service_resolves_the_class_name_and_the_parent() {
        let m = manager();
        m.boot_desktop(DESKTOP, SCREEN).unwrap();
        register(
            &mut m.classes,
            class::Name::Text(&units("App")),
            &wnd_class(),
        );
        let t = m
            .windows
            .connect_thread(key(1, 0), OWNER, DESKTOP, DESKTOP_CREATEWINDOW, 0x10)
            .unwrap();
        let name = units("App");
        let title = units("Hello");
        let mut a = args(0, WS_OVERLAPPED);
        a.class_name = class::Name::Text(&name);
        a.name = &title;
        let handle = m
            .create_window(t, 0, &mut a, &mut DefaultProcedure)
            .unwrap();
        let id = m.windows.window_from_handle(handle).unwrap();
        let desktop = *m.windows.desktop_by_id(DESKTOP).unwrap();
        assert_eq!(m.windows.at(id).parent, desktop.window);
        assert_eq!(m.windows.at(desktop.window.unwrap()).child, Some(id));
        assert_eq!(m.windows.at(id).thread, t);

        let mut a = args(0, WS_CHILD);
        a.class_name = class::Name::Text(&name);
        let child = m
            .create_window(t, handle, &mut a, &mut DefaultProcedure)
            .unwrap();
        let child = m.windows.window_from_handle(child).unwrap();
        assert_eq!(m.windows.at(child).parent, Some(id));

        let mut a = args(0, WS_CHILD);
        a.class_name = class::Name::Text(&name);
        let only = m
            .create_window(t, HWND_MESSAGE, &mut a, &mut DefaultProcedure)
            .unwrap();
        let only = m.windows.window_from_handle(only).unwrap();
        assert_eq!(m.windows.at(only).parent, desktop.message_window);

        let mut a = args(0, WS_CHILD);
        a.class_name = class::Name::Text(&name);
        assert_eq!(
            m.create_window(t, 0x1234, &mut a, &mut DefaultProcedure),
            Err(Failure::InvalidWindowHandle)
        );
        let missing = units("Missing");
        let mut a = args(0, WS_OVERLAPPED);
        a.class_name = class::Name::Text(&missing);
        assert_eq!(
            m.create_window(t, 0, &mut a, &mut DefaultProcedure),
            Err(Failure::CannotFindWindowClass)
        );

        // The process's thread cannot destroy the desktop's windows.
        let root = m.windows.handle_of(desktop.window.unwrap());
        assert_eq!(
            m.windows
                .destroy_window_handle(&mut m.classes, t, root, &mut DefaultProcedure),
            Err(Failure::AccessDenied)
        );
    }

    /// The class registry's view of the windows: a window's class, process and desktop through
    /// its handle (none for a dead handle or a window without a class), and every window with a
    /// class for the icon-change notification.
    #[test]
    fn the_class_registry_sees_the_windows() {
        let (w, c, t, atom, _, _) = setup();
        let mut pump = Rec::new(t);
        let a = create(w, c, t, atom, WS_OVERLAPPED, &mut pump).unwrap();
        let b = create(w, c, t, atom, WS_POPUP, &mut pump).unwrap();
        let view = w.class_window(w.handle_of(a)).unwrap();
        assert_eq!(view.class, w.at(a).class.unwrap());
        assert_eq!(view.owner, OWNER);
        assert_eq!(view.desktop, DESKTOP);
        assert_eq!(w.class_view(w.handle_of(b)).map(|v| v.class), w.at(b).class);
        assert_eq!(w.class_window(0x1234), None);

        // The scaffolding's desktop windows have no class: only the two created windows count.
        let mut views = [w.class_view(w.handle_of(a)).unwrap(); 8];
        assert_eq!(w.class_views(&mut views), 2);
        assert_eq!(w.class_views(&mut views[..1]), 1, "cut at the buffer");

        let handle = w.handle_of(a);
        w.destroy_window_handle(c, t, handle, &mut pump).unwrap();
        assert_eq!(w.class_window(handle), None);
        assert_eq!(w.class_views(&mut views), 1);
    }

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
