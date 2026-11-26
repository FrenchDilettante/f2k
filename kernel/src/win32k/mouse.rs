//! Mouse input: the cursor's position, the path a mouse event takes to a window, as Windows 2000's
//! raw input thread takes it, and the conversions a thread's read makes of the mouse messages it
//! finds.
//!
//! A mouse event comes from SendInput (there is no mouse driver yet), which runs it in the
//! caller's service, synchronously, as it runs a keystroke ([`super::input`]). Each event
//! ([`mouse_event`]), as Windows 2000's ProcessQueuedMouseEvents processes it:
//!
//! - moves the cursor: an absolute move to the place its 0-65535 coordinates name across the screen
//!   (x = dx * width / 65536, as the mouse driver's coordinates scale), a relative one by its
//!   amount, doubled past the default threshold of 6 (SPI_GETMOUSE's 6, 10, 1); the cursor stays on
//!   the screen;
//! - when the cursor's place is not the one the last event left it at, posts a WM_MOUSEMOVE. That
//!   last place is the input path's own ([`Cursor`]'s `last`, Windows 2000's `ptCursorLast`):
//!   SetCursorPos moves the cursor without moving it. So a move SendInput makes to where an earlier
//!   event already left the cursor posts nothing, even after SetCursorPos took the cursor away and
//!   back meanwhile (the mousein capture: the click section's move to the client area's centre,
//!   where the move section's event left it, posts no WM_MOUSEMOVE; the capture section's press,
//!   the cursor put elsewhere by SetCursorPos, posts one before itself);
//! - moves the system's key state for its buttons (VK_LBUTTON, VK_RBUTTON, VK_MBUTTON) and posts
//!   their messages, the left button's down and up, then the right's, then the middle's.
//!
//! A message goes to the window under the cursor, or the capture window: the foreground thread's
//! when it has one, else the capture window of the thread whose window is under the cursor
//! ([`target`]). The window under the cursor is the deepest visible window whose rectangle holds
//! the point, down the children while it is in their parent's client area, as Windows 2000's
//! SpeedHitTest finds it, a disabled child giving way to its parent ([`window_at`]). The message is
//! posted to that window's thread as an input message ([`super::queue::post_mouse`]), with the
//! screen point and the MK_ flags of the buttons and the modifiers down, a WM_MOUSEMOVE folding
//! into one the thread has not read yet at the end of its input (Windows 2000 keeps one pending
//! move a queue). SetCursorPos moves the cursor and posts a WM_MOUSEMOVE the same way
//! ([`set_cursor_pos`]).
//!
//! The thread's read converts the message ([`convert`]), as Windows 2000's xxxScanSysQueue does:
//! with the capture its own, the message goes to the capture window, a client message whatever the
//! point (HTCLIENT); otherwise the window's procedure is asked where the point is (WM_NCHITTEST, by
//! callback: the read's preparation, [`super::queue::Taken::Prepare`]), a disabled window being
//! HTERROR and an HTTRANSPARENT one letting the point through to its parent. HTCLIENT gives the
//! client message, its lParam the point in the window's client coordinates, wParam the MK_ flags;
//! any other code the non-client message (WM_NCMOUSEMOVE...), wParam the code, lParam the screen
//! point. A button's press becomes its double-click when the same button was pressed on the same
//! window within the double-click time (500 ms) and rectangle (SM_CXDOUBLECLK by SM_CYDOUBLECLK,
//! 4 by 4, about the first press), the window's class having CS_DBLCLKS or the press being
//! non-client ([`Click`]). The read filters the converted message. A message read out, without the
//! capture ([`after_read`]): a press on a window whose top-level window is not the active one sends
//! WM_MOUSEACTIVATE first, its answer activating the window (MA_ACTIVATE, MA_ACTIVATEANDEAT) and
//! eating the press (MA_ACTIVATEANDEAT, MA_NOACTIVATEANDEAT); then WM_SETCURSOR (the window, the
//! code and the message); an HTERROR message is eaten after it.
//!
//! The capture ([`super::focus`]'s SetCapture and ReleaseCapture) is each thread's, as Windows
//! 2000's is each queue's. Nothing draws the cursor yet: SetCursor keeps the shape
//! ([`Cursor::shape`]).
//!
//! The services, user32's calls (F2K's argument lists, see [`crate::win32k`]; Windows 2000's
//! numbers): NtUserSendInput's mouse events ([`super::input`]'s service); NtUserSetCursor
//! (0x11EC)(handle Cursor, ptr<u32> Previous): the shape set, the one it replaces through the
//! pointer; GetCursorPos and GetCapture are NtUserGetThreadState's routines, SetCapture and
//! ReleaseCapture [`super::focus`]'s, SetCursorPos NtUserCallTwoParam's ([`super::caret`]'s
//! service).

use rtl::gdi::Rect;
use rtl::nonclient::{HTCLIENT, HTERROR, HTTRANSPARENT};
use rtl::user::{
    MouseInput,
    Msg,
    Point,
    CS_DBLCLKS,
    MA_ACTIVATE,
    MA_ACTIVATEANDEAT,
    MA_NOACTIVATEANDEAT,
    MK_CONTROL,
    MK_LBUTTON,
    MK_MBUTTON,
    MK_RBUTTON,
    MK_SHIFT,
    MOUSEEVENTF_ABSOLUTE,
    MOUSEEVENTF_LEFTDOWN,
    MOUSEEVENTF_LEFTUP,
    MOUSEEVENTF_MIDDLEDOWN,
    MOUSEEVENTF_MIDDLEUP,
    MOUSEEVENTF_MOVE,
    MOUSEEVENTF_RIGHTDOWN,
    MOUSEEVENTF_RIGHTUP,
    NC_MOUSE_OFFSET,
    VK_CONTROL,
    VK_LBUTTON,
    VK_MBUTTON,
    VK_RBUTTON,
    VK_SHIFT,
    WM_LBUTTONDBLCLK,
    WM_LBUTTONDOWN,
    WM_LBUTTONUP,
    WM_MBUTTONDBLCLK,
    WM_MBUTTONDOWN,
    WM_MBUTTONUP,
    WM_MOUSEACTIVATE,
    WM_MOUSEFIRST,
    WM_MOUSELAST,
    WM_MOUSEMOVE,
    WM_RBUTTONDBLCLK,
    WM_RBUTTONDOWN,
    WM_RBUTTONUP,
    WM_SETCURSOR,
    WS_CHILD,
    WS_DISABLED,
    WS_VISIBLE,
};

use super::class;
use super::input::KeyState;
use super::window::{Hwnd, Message, Payload, Session, WindowId, Windows};
use crate::sched::thread::ThreadId;

/// GetDoubleClickTime's default: how soon a second press must follow the first, in milliseconds.
pub const DOUBLE_CLICK_TIME: u32 = 500;

/// SM_CXDOUBLECLK and SM_CYDOUBLECLK's defaults: the rectangle about the first press the second
/// must fall in.
pub const DOUBLE_CLICK_SIZE: i32 = 4;

/// SPI_GETMOUSE's default first threshold: a relative move by more than this is doubled
/// (acceleration 1).
const THRESHOLD: i32 = 6;

// --- The cursor ----------------------------------------------------------------------------------

/// The cursor: where it is, where the input path last left it, and its shape. The window
/// manager's, in the system's input state ([`super::input::RawInput`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cursor {
    /// Where the cursor is, in screen coordinates (GetCursorPos); none until it is first placed:
    /// the screen's centre then, where Windows 2000 starts it.
    at: Option<Point>,
    /// Where the last mouse event left it (Windows 2000's ptCursorLast, the origin at first):
    /// an event that finds the cursor elsewhere posts a WM_MOUSEMOVE. SetCursorPos leaves it.
    last: Point,
    /// The cursor's shape, as SetCursor set it (a cursor's handle, 0 for none).
    pub shape: u32,
}

impl Cursor {
    pub const EMPTY: Self = Cursor {
        at: None,
        last: Point { x: 0, y: 0 },
        shape: 0,
    };
}

/// The point `pt` kept on the screen `screen`.
pub fn clamp(pt: Point, screen: Rect) -> Point {
    Point {
        x: pt.x.clamp(screen.left, (screen.right - 1).max(screen.left)),
        y: pt.y.clamp(screen.top, (screen.bottom - 1).max(screen.top)),
    }
}

/// The cursor's place (GetCursorPos) on the screen `screen`: where it was put, or the screen's
/// centre before it ever was.
pub fn position(windows: &Windows, screen: Rect) -> Point {
    windows.input.cursor.at.unwrap_or(Point {
        x: (screen.left + screen.right) / 2,
        y: (screen.top + screen.bottom) / 2,
    })
}

/// The place an absolute move's coordinates (0-65535 across the screen) name on `screen`.
pub fn absolute(dx: i32, dy: i32, screen: Rect) -> Point {
    let scale =
        |d: i32, low: i32, high: i32| low + ((i64::from(d) * i64::from(high - low)) >> 16) as i32;
    clamp(
        Point {
            x: scale(dx, screen.left, screen.right),
            y: scale(dy, screen.top, screen.bottom),
        },
        screen,
    )
}

/// A relative move's amount as the default acceleration makes it: doubled past the threshold.
fn accelerated(d: i32) -> i32 {
    if d.abs() > THRESHOLD {
        d.saturating_mul(2)
    } else {
        d
    }
}

/// The MK_ flags of the key state `keys`: the mouse's buttons, Shift and Ctrl down.
pub fn mk_flags(keys: &KeyState) -> u32 {
    [
        (VK_LBUTTON, MK_LBUTTON),
        (VK_RBUTTON, MK_RBUTTON),
        (VK_SHIFT, MK_SHIFT),
        (VK_CONTROL, MK_CONTROL),
        (VK_MBUTTON, MK_MBUTTON),
    ]
    .iter()
    .filter(|&&(vk, _)| keys.is_down(vk as u8))
    .fold(0, |flags, &(_, mk)| flags | mk)
}

// --- The input path ------------------------------------------------------------------------------

/// The buttons of a mouse event: its flags going down and up, the button's key and its press's
/// message (the release's is the next one).
const BUTTONS: [(u32, u32, u32, u32); 3] = [
    (
        MOUSEEVENTF_LEFTDOWN,
        MOUSEEVENTF_LEFTUP,
        VK_LBUTTON,
        WM_LBUTTONDOWN,
    ),
    (
        MOUSEEVENTF_RIGHTDOWN,
        MOUSEEVENTF_RIGHTUP,
        VK_RBUTTON,
        WM_RBUTTONDOWN,
    ),
    (
        MOUSEEVENTF_MIDDLEDOWN,
        MOUSEEVENTF_MIDDLEUP,
        VK_MBUTTON,
        WM_MBUTTONDOWN,
    ),
];

/// A mouse event (SendInput's MOUSEINPUT) on the screen `screen`, stamped `time`: the cursor
/// moved, a WM_MOUSEMOVE posted when the input path last left it elsewhere, the buttons' key
/// states moved and their messages posted (see the module's description). The wheel's turns are
/// not served.
pub fn mouse_event(windows: &mut Windows, event: &MouseInput, screen: Rect, time: u32) {
    let mut pt = position(windows, screen);
    if event.flags & MOUSEEVENTF_MOVE != 0 {
        pt = if event.flags & MOUSEEVENTF_ABSOLUTE != 0 {
            absolute(event.dx, event.dy, screen)
        } else {
            clamp(
                Point {
                    x: pt.x.saturating_add(accelerated(event.dx)),
                    y: pt.y.saturating_add(accelerated(event.dy)),
                },
                screen,
            )
        };
    }
    let cursor = &mut windows.input.cursor;
    cursor.at = Some(pt);
    if cursor.last != pt {
        cursor.last = pt;
        post_at(windows, WM_MOUSEMOVE, 0, pt, time);
    }
    for &(down, up, vk, press) in &BUTTONS {
        if event.flags & down != 0 {
            windows.input.button(vk as u8, true);
            post_at(windows, press, vk as u8, pt, time);
        }
        if event.flags & up != 0 {
            windows.input.button(vk as u8, false);
            post_at(windows, press + 1, vk as u8, pt, time);
        }
    }
}

/// SetCursorPos: the cursor to (`x`, `y`), kept on the screen `screen`, and a WM_MOUSEMOVE posted
/// for its new place, stamped `time`. Where the input path last left the cursor stays as it was.
pub fn set_cursor_pos(windows: &mut Windows, x: i32, y: i32, screen: Rect, time: u32) {
    let pt = clamp(Point { x, y }, screen);
    windows.input.cursor.at = Some(pt);
    post_at(windows, WM_MOUSEMOVE, 0, pt, time);
}

/// The mouse message `message` (of the button `key`, 0 for a move) at the screen point `pt`,
/// posted to the window it goes to ([`target`]), stamped `time`: nothing when it goes to none.
fn post_at(windows: &mut Windows, message: u32, key: u8, pt: Point, time: u32) {
    let Some(window) = target(windows, pt) else {
        return;
    };
    let msg = Msg {
        hwnd: windows.handle_of(window),
        message,
        wparam: mk_flags(&windows.input.keys),
        lparam: makelong(pt.x, pt.y) as i32,
        time,
        pt,
    };
    let thread = windows.window_thread(window);
    super::queue::post_mouse(windows, thread, msg, key);
}

/// A point's coordinates as a message's lParam carries them: x in the low word, y in the high.
fn makelong(x: i32, y: i32) -> u32 {
    (x as u16 as u32) | (y as u16 as u32) << 16
}

/// The thread's capture window, while it lives.
pub fn capture_of(windows: &Windows, thread: ThreadId) -> Option<WindowId> {
    windows
        .thread(thread)
        .capture
        .filter(|&w| windows.is_live(w))
}

/// The window a mouse message at the screen point `pt` goes to: the foreground thread's capture
/// window; otherwise the window under the point ([`window_at`], on the foreground thread's
/// desktop), or its thread's capture window when that thread has one.
pub fn target(windows: &Windows, pt: Point) -> Option<WindowId> {
    let foreground = windows
        .foreground_thread
        .filter(|&thread| windows.thread(thread).live)?;
    if let Some(capture) = capture_of(windows, foreground) {
        return Some(capture);
    }
    let desktop = windows.thread_desktop_window(foreground)?;
    let under = window_at(windows, desktop, pt)?;
    Some(capture_of(windows, windows.window_thread(under)).unwrap_or(under))
}

/// The window under the screen point `pt` among the children of `parent`, as Windows 2000's
/// SpeedHitTest finds it: in z-order, the first visible one whose rectangle holds the point, then
/// down its children the same way while the point is in its client area, the deepest found. A
/// disabled child found gives way to its parent, which then has the message (Windows 2000 hands a
/// disabled control's clicks to its dialog). None when no window holds the point.
pub fn window_at(windows: &Windows, parent: WindowId, pt: Point) -> Option<WindowId> {
    let mut found = None;
    let mut at = windows.first_child(parent);
    while let Some(window) = at {
        let style = windows.window_style(window);
        if style & WS_VISIBLE != 0 && windows.window_rect(window).contains(pt.x, pt.y) {
            found = Some(window);
            if !windows.client_rect(window).contains(pt.x, pt.y) {
                break;
            }
            at = windows.first_child(window);
            continue;
        }
        at = windows.next_sibling(window);
    }
    let mut window = found?;
    while windows.window_style(window) & (WS_CHILD | WS_DISABLED) == WS_CHILD | WS_DISABLED {
        window = windows.parent_of(window)?;
    }
    Some(window)
}

// --- The read ------------------------------------------------------------------------------------

/// Whether `message` is a mouse message as the input path posts it (the client forms).
pub fn is_mouse(message: u32) -> bool {
    (WM_MOUSEFIRST..=WM_MOUSELAST).contains(&message)
}

/// Whether the client-form mouse message `message` is a button's press or double-click.
pub fn is_press(message: u32) -> bool {
    matches!(
        message,
        WM_LBUTTONDOWN
            | WM_LBUTTONDBLCLK
            | WM_RBUTTONDOWN
            | WM_RBUTTONDBLCLK
            | WM_MBUTTONDOWN
            | WM_MBUTTONDBLCLK
    )
}

/// Whether the client-form mouse message `message` is a button's release.
pub fn is_release(message: u32) -> bool {
    matches!(message, WM_LBUTTONUP | WM_RBUTTONUP | WM_MBUTTONUP)
}

/// What a thread's read learned of a mouse message's window: the window and the point it was asked
/// about, its hit-test code, and whether its class takes double-clicks (CS_DBLCLKS). Kept with the
/// message ([`super::queue`]'s input entries) until the read takes it out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Prepared {
    pub hwnd: Hwnd,
    pub pt: Point,
    pub hit: u32,
    pub dblclks: bool,
}

/// A press the thread read out, for the next press's double-click: its client-form message, its
/// window, its time and its point.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Click {
    pub message: u32,
    pub hwnd: Hwnd,
    pub time: u32,
    pub pt: Point,
}

/// The read's form of the mouse message `msg` (as posted: its client form, the screen point in its
/// lParam), going to the window `window` as `prepared` found it, after the press `click` the
/// thread last read out (see the module's description): the converted message, and its
/// client-form message (the press made a double-click when it is one).
pub fn convert(
    windows: &Windows,
    window: WindowId,
    msg: &Msg,
    prepared: &Prepared,
    click: Option<Click>,
) -> (Msg, u32) {
    let mut message = msg.message;
    if matches!(message, WM_LBUTTONDOWN | WM_RBUTTONDOWN | WM_MBUTTONDOWN)
        && (prepared.hit != HTCLIENT || prepared.dblclks)
        && click.is_some_and(|c| doubles(&c, message, prepared.hwnd, msg.time, msg.pt))
    {
        message += WM_LBUTTONDBLCLK - WM_LBUTTONDOWN;
    }
    let converted = if prepared.hit == HTCLIENT {
        let client = windows.client_rect(window);
        Msg {
            hwnd: prepared.hwnd,
            message,
            lparam: makelong(msg.pt.x - client.left, msg.pt.y - client.top) as i32,
            ..*msg
        }
    } else {
        Msg {
            hwnd: prepared.hwnd,
            message: message - NC_MOUSE_OFFSET,
            wparam: prepared.hit,
            lparam: makelong(msg.pt.x, msg.pt.y) as i32,
            ..*msg
        }
    };
    (converted, message)
}

/// Whether a press of `message` on `hwnd` at `time` and `pt` doubles the press `click`: the same
/// button on the same window, within the double-click time and rectangle.
fn doubles(click: &Click, message: u32, hwnd: Hwnd, time: u32, pt: Point) -> bool {
    let half = DOUBLE_CLICK_SIZE / 2;
    click.message == message
        && click.hwnd == hwnd
        && time.wrapping_sub(click.time) < DOUBLE_CLICK_TIME
        && (click.pt.x - half..click.pt.x + half).contains(&pt.x)
        && (click.pt.y - half..click.pt.y + half).contains(&pt.y)
}

/// The press the thread remembers after reading out the client-form message `message` (on
/// `hwnd`, at `time` and `pt`): a press is the next double-click's first, a double-click starts
/// over, any other message leaves the last one.
pub fn next_click(
    last: Option<Click>,
    message: u32,
    hwnd: Hwnd,
    time: u32,
    pt: Point,
) -> Option<Click> {
    match message {
        WM_LBUTTONDOWN | WM_RBUTTONDOWN | WM_MBUTTONDOWN => Some(Click {
            message,
            hwnd,
            time,
            pt,
        }),
        WM_LBUTTONDBLCLK | WM_RBUTTONDBLCLK | WM_MBUTTONDBLCLK => None,
        _ => last,
    }
}

/// What the read learned of `window` for a mouse message at `pt`, its hit-test code `hit` (the
/// procedure's answer to WM_NCHITTEST, HTCLIENT under the capture, HTERROR for a disabled window):
/// with whether the window's class takes double-clicks.
pub fn prepared(
    windows: &Windows,
    classes: &class::Registry,
    window: WindowId,
    pt: Point,
    hit: u32,
) -> Prepared {
    let hwnd = windows.handle_of(window);
    let dblclks = windows
        .class_window(hwnd)
        .is_some_and(|w| classes.class_data(w.class).style & CS_DBLCLKS != 0);
    Prepared {
        hwnd,
        pt,
        hit,
        dblclks,
    }
}

/// The hit-test code of `window` for a mouse message at the screen point `pt`, its read's
/// preparation (see the module's description): HTCLIENT under the capture (`captured`), HTERROR
/// for a disabled window, otherwise WM_NCHITTEST's answer, sent through `s`. A window whose
/// procedure is the window manager's answers by its rectangles: HTCLIENT in its client area,
/// HTNOWHERE elsewhere.
pub fn hit_test(s: &mut dyn Session, window: WindowId, pt: Point, captured: bool) -> u32 {
    if captured {
        return HTCLIENT;
    }
    let windows = s.windows();
    if windows.window_style(window) & WS_DISABLED != 0 {
        return HTERROR;
    }
    if windows.client_proc(window).is_none() {
        return u32::from(windows.client_rect(window).contains(pt.x, pt.y));
    }
    s.send(
        window,
        &mut Message {
            message: rtl::user::WM_NCHITTEST,
            wparam: 0,
            lparam: makelong(pt.x, pt.y) as i32,
            payload: Payload::None,
        },
    ) as u32
}

/// Whether a window answered HTTRANSPARENT: the point goes through it to its parent.
pub fn lets_through(hit: u32) -> bool {
    hit == HTTRANSPARENT
}

/// A mouse message a read took out, before it is handed to the thread.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MouseRead {
    /// The message as the thread receives it.
    pub msg: Msg,
    /// Its client form (a double-click's when it is one): WM_SETCURSOR's and WM_MOUSEACTIVATE's
    /// high word.
    pub client_message: u32,
    pub hit: u32,
    /// The thread's capture had it.
    pub captured: bool,
    /// The read takes it out (PeekMessage's PM_NOREMOVE does not: nothing is sent for it).
    pub removed: bool,
}

/// What follows a mouse message the thread `caller` read out, before the thread has it (see the
/// module's description): WM_MOUSEACTIVATE for a press on a window whose top-level window is not
/// the active window of the foreground thread, and WM_SETCURSOR, both without the capture.
/// Whether the thread has the message: not when WM_MOUSEACTIVATE's answer eats it, nor for an
/// HTERROR message.
pub fn after_read(s: &mut dyn Session, caller: ThreadId, read: &MouseRead) -> bool {
    if read.captured || !read.removed {
        return true;
    }
    let Some(window) = s.windows().window_from_handle(read.msg.hwnd) else {
        return false;
    };
    let words = (read.hit & 0xFFFF) | read.client_message << 16;
    let mut eaten = false;
    if is_press(read.client_message) {
        let windows = s.windows();
        let top = top_level(windows, window);
        let active = windows.foreground_thread == Some(caller)
            && super::focus::active_window(windows, caller) == Some(top);
        if !active {
            let handle = windows.handle_of(top);
            let answer = send(s, window, WM_MOUSEACTIVATE, handle, words);
            if matches!(answer, MA_ACTIVATE | MA_ACTIVATEANDEAT) && s.windows().is_live(top) {
                super::focus::activate_by_mouse(s, top);
            }
            eaten = matches!(answer, MA_ACTIVATEANDEAT | MA_NOACTIVATEANDEAT);
        }
    }
    if s.windows().is_live(window) {
        let hwnd = read.msg.hwnd;
        send(s, window, WM_SETCURSOR, hwnd, words);
    }
    !eaten && read.hit != HTERROR && s.windows().is_live(window)
}

/// A message with no payload sent to `target`: its answer.
fn send(s: &mut dyn Session, target: WindowId, message: u32, wparam: u32, lparam: u32) -> u32 {
    s.send(
        target,
        &mut Message {
            message,
            wparam,
            lparam: lparam as i32,
            payload: Payload::None,
        },
    ) as u32
}

/// The top-level window `window` belongs to: itself, or the parent its chain of child windows
/// ends at.
pub fn top_level(windows: &Windows, window: WindowId) -> WindowId {
    let mut top = window;
    while windows.window_style(top) & WS_CHILD != 0 {
        match windows.parent_of(top) {
            Some(parent) => top = parent,
            None => break,
        }
    }
    top
}

// --- The services --------------------------------------------------------------------------------

#[cfg(target_arch = "x86")]
mod services {
    use crate::nt::call::{Handle, NtCall, NtResult, UserPtr};
    use crate::status::*;
    use crate::win32k::queue::with_manager;
    use crate::win32k::winsta::gui_thread;

    /// NtUserSetCursor(Cursor, Previous): the cursor's shape set to the cursor `cursor` names (0
    /// for none); the shape it replaces into `previous`. Nothing draws it yet.
    pub fn set_cursor(call: &mut NtCall, cursor: Handle, previous: UserPtr<u32>) -> NtResult {
        gui_thread(call)?;
        let had = with_manager(call.passive(), |m| {
            core::mem::replace(&mut m.windows.input.cursor.shape, cursor.raw())
        });
        previous.write(had)?;
        Ok(STATUS_SUCCESS)
    }
}

// The host builds have no processes and no user memory: the services answer nothing.
#[cfg(not(target_arch = "x86"))]
mod services {
    use crate::nt::call::{Handle, NtCall, NtResult, UserPtr};
    use crate::status::*;

    pub fn set_cursor(_: &mut NtCall, _: Handle, _: UserPtr<u32>) -> NtResult {
        Err(STATUS_NOT_IMPLEMENTED)
    }
}

pub use services::set_cursor;

#[cfg(test)]
mod tests;
