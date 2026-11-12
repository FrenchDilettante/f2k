//! The caret: each thread's one caret, kept in its queue's state as Windows 2000 keeps it (the
//! window registry's thread record, [`super::window::Thread`]'s `caret`, beside its focus and
//! active windows), behind the window manager's lock; and the services CreateCaret, DestroyCaret,
//! ShowCaret, HideCaret, SetCaretPos, GetCaretPos and GetGUIThreadInfo come through.
//!
//! A caret ([`Caret`]) belongs to a window of its thread, has a size, a solid or gray look, and a
//! hide count: CreateCaret makes it hidden (the count 1, whatever it was), ShowCaret takes one off
//! the count down to 0, where it shows, and HideCaret adds one. Its place, in its window's client
//! coordinates, is the thread's, not the caret's: a new caret takes the place the last one had,
//! and GetCaretPos answers it with no caret at all (the caret capture's create block). As the
//! capture shows Windows 2000's:
//!
//! - CreateCaret of a window of another thread is refused with no error (the call answers FALSE); a
//!   width or height of 0 is the border's (SM_CXBORDER, SM_CYBORDER: 1);
//! - DestroyCaret, SetCaretPos, ShowCaret and HideCaret on a thread with no caret are
//!   STATUS_ACCESS_DENIED (ERROR_ACCESS_DENIED); ShowCaret and HideCaret of a window other than the
//!   caret's are refused with no error, and of a handle naming no window STATUS_INVALID_HANDLE;
//! - ShowCaret of a shown caret answers TRUE and leaves the count at 0;
//! - the caret stays where it is when the focus moves; its window's destruction destroys it.
//!
//! A shown caret blinks: every blink time (530 ms, Windows 2000's default) the thread's queue
//! turns it, on its next read ([`super::queue::take`], which waits no longer than the turn's due).
//! It is drawn by inverting its rectangle on the screen (PatBlt's DSTINVERT; a gray caret,
//! CreateCaret's (HBITMAP)1, XORs the halftone checkerboard in, PATINVERT), clipped to its
//! window's client area, so drawing it again takes it off. The rectangle drawn is kept, and a
//! caret taken off is inverted there, wherever its window has gone since. BeginPaint of the
//! caret's window, or of a window above it in its chain of parents (whose DC is not clipped by its
//! children), takes the caret off the screen while the window paints, and EndPaint puts it back
//! ([`paint_begins`], [`paint_ends`]), as Windows 2000's BeginPaint and EndPaint hide and show it.
//!
//! A caret made from a bitmap is not served: user32 refuses CreateCaret of one before it reaches
//! the kernel. GetGUIThreadInfo answers no menu or move-size state: the menu loop runs in user32
//! ([`super::menu`]'s notes), so its flags and hwndMenuOwner stay 0, and there is no move-size
//! loop.
//!
//! The services, user32's calls (F2K's argument lists, see [`crate::win32k`]; Windows 2000's
//! numbers):
//!
//! - NtUserCreateCaret (0x1149)(handle Window, u32 Gray, i32 Width, i32 Height, ptr<u32> Made): the
//!   caret made, whether it was into `Made`;
//! - NtUserShowCaret (0x1216) and NtUserHideCaret (0x11AB)(handle Window, ptr<u32> Done): the count
//!   changed, whether it was into `Done`;
//! - NtUserGetCaretPos (0x1177)(ptr Point): the thread's caret place;
//! - NtUserGetGUIThreadInfo (0x118B)(u32 ThreadId, ptr Info): the GUITHREADINFO of the thread (its
//!   client id; 0 for the foreground thread);
//! - NtUserCallTwoParam (0x113A)(u32 Param1, u32 Param2, u32 Routine, ptr<u32> Result): SetCaretPos
//!   (rtl::user's TWO_PARAM_SET_CARET_POS);
//! - NtUserCallNoParam's DestroyCaret routine ([`super::menu`]'s service serves the others).

use rtl::gdi::{Rect, DSTINVERT, HALFTONE_ROWS, PATINVERT};
use rtl::user::{GuiThreadInfo, GUI_CARETBLINKING};

use super::raster::Pattern;
use super::window::{WindowId, Windows, WS_CHILD};
use crate::sched::thread::ThreadId;
use crate::status::*;

/// The blink time, in milliseconds: Windows 2000's default (GetCaretBlinkTime).
pub const BLINK_MS: u32 = 530;

/// The interrupt time's units (100 ns) in a millisecond.
const UNITS_PER_MS: u64 = 10_000;

/// The blink time, in interrupt-time units.
const BLINK: u64 = BLINK_MS as u64 * UNITS_PER_MS;

/// The border's width and height (SM_CXBORDER, SM_CYBORDER): a caret's size where CreateCaret
/// asks for 0.
const BORDER: i32 = 1;

/// A thread's caret, and its place.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Caret {
    /// The caret's window; none when the thread has no caret.
    pub window: Option<WindowId>,
    /// ShowCaret's and HideCaret's count: shown at 0.
    pub hidden: u32,
    /// Its place, in its window's client coordinates: the thread's, kept between carets.
    pub x: i32,
    pub y: i32,
    pub width: i32,
    pub height: i32,
    /// CreateCaret's (HBITMAP)1: a gray caret.
    pub gray: bool,
    /// The screen rectangle it is drawn inverted at, while it is on the screen.
    pub drawn: Option<Rect>,
    /// BeginPaint took it off the screen; EndPaint puts it back.
    pub painting: bool,
    /// When the blink next turns it (interrupt time), while it is shown.
    pub due: Option<u64>,
    /// Its window was freed, and the messages its destruction sent are still on their way to the
    /// window's procedure: it shows nowhere, and goes once WM_NCDESTROY is delivered.
    pub dying: bool,
}

impl Caret {
    pub const EMPTY: Self = Caret {
        window: None,
        hidden: 0,
        x: 0,
        y: 0,
        width: 0,
        height: 0,
        gray: false,
        drawn: None,
        painting: false,
        due: None,
        dying: false,
    };

    /// Its rectangle, in its window's client coordinates.
    pub fn rect(&self) -> Rect {
        Rect {
            left: self.x,
            top: self.y,
            right: self.x.saturating_add(self.width),
            bottom: self.y.saturating_add(self.height),
        }
    }
}

// --- The drawing ---------------------------------------------------------------------------------

/// The caret inverted on the screen at `rect` (screen coordinates), as its look inverts it.
fn invert(rect: Rect, gray: bool) {
    let pattern = gray.then_some(Pattern::Mono {
        rows: HALFTONE_ROWS,
        origin: (0, 0),
        one: 0x00FF_FFFF,
        zero: 0,
    });
    let rop = if gray { PATINVERT } else { DSTINVERT };
    super::dc::with_screen(|screen| {
        let extent = Rect {
            left: 0,
            top: 0,
            right: screen.geometry.width as i32,
            bottom: screen.geometry.height as i32,
        };
        super::raster::pat_blt(screen, extent, rect, rop, pattern.as_ref());
    });
}

/// The caret of `thread` put on the screen, when it is shown, not painting, its window shown, and
/// not on it already.
fn draw(windows: &mut Windows, thread: ThreadId) {
    let caret = windows.thread(thread).caret;
    let Some(window) = caret.window else {
        return;
    };
    if caret.hidden != 0
        || caret.painting
        || caret.dying
        || caret.drawn.is_some()
        || !windows.is_live(window)
        || !super::paint::is_shown(windows, window)
    {
        return;
    }
    let client = windows.client_rect(window);
    let client = Rect {
        left: client.left,
        top: client.top,
        right: client.right,
        bottom: client.bottom,
    };
    let place = caret.rect();
    let rect = super::raster::intersect(
        client,
        Rect {
            left: client.left.saturating_add(place.left),
            top: client.top.saturating_add(place.top),
            right: client.left.saturating_add(place.right),
            bottom: client.top.saturating_add(place.bottom),
        },
    );
    if rect.left >= rect.right || rect.top >= rect.bottom {
        return;
    }
    invert(rect, caret.gray);
    windows.thread_mut(thread).caret.drawn = Some(rect);
}

/// The caret of `thread` taken off the screen, when it is on it.
fn undraw(windows: &mut Windows, thread: ThreadId) {
    let caret = &mut windows.thread_mut(thread).caret;
    if let Some(rect) = caret.drawn.take() {
        invert(rect, caret.gray);
    }
}

/// The caret of `thread` shown from `now`: on the screen, its blink's next turn a blink time on.
fn show_from(windows: &mut Windows, thread: ThreadId, now: u64) {
    draw(windows, thread);
    windows.thread_mut(thread).caret.due = Some(now + BLINK);
}

/// The caret of `thread` gone, taken off the screen first; its place kept.
fn remove(windows: &mut Windows, thread: ThreadId) {
    undraw(windows, thread);
    let caret = &mut windows.thread_mut(thread).caret;
    *caret = Caret {
        x: caret.x,
        y: caret.y,
        ..Caret::EMPTY
    };
}

// --- The decisions -------------------------------------------------------------------------------

/// CreateCaret by `caller` at `now`: a caret of `window` (a window of its own thread), `width` by
/// `height` (the border's for 0), gray or solid, made hidden in place of the thread's caret, at
/// the thread's caret place; whether it was made (FALSE, with no error, for another thread's
/// window).
pub fn create(
    windows: &mut Windows,
    caller: ThreadId,
    window: WindowId,
    gray: bool,
    width: i32,
    height: i32,
) -> bool {
    if windows.window_thread(window) != caller {
        return false;
    }
    remove(windows, caller);
    let caret = &mut windows.thread_mut(caller).caret;
    caret.window = Some(window);
    caret.hidden = 1;
    caret.width = if width == 0 { BORDER } else { width };
    caret.height = if height == 0 { BORDER } else { height };
    caret.gray = gray;
    true
}

/// The window of `caller`'s caret, when it has one (a dying caret's window is no longer live).
fn caret_window(windows: &Windows, caller: ThreadId) -> Option<WindowId> {
    let caret = windows.thread(caller).caret;
    caret.window.filter(|&w| caret.dying || windows.is_live(w))
}

/// DestroyCaret by `caller`: its caret gone; STATUS_ACCESS_DENIED when it has none.
pub fn destroy(windows: &mut Windows, caller: ThreadId) -> Result<(), NtStatus> {
    caret_window(windows, caller).ok_or(STATUS_ACCESS_DENIED)?;
    remove(windows, caller);
    Ok(())
}

/// ShowCaret (`show`) or HideCaret by `caller` of `window` (none: whatever window its caret is
/// in) at `now`: the count changed; FALSE, with no error, for a window that is not the caret's;
/// STATUS_ACCESS_DENIED when the thread has no caret.
pub fn show_or_hide(
    windows: &mut Windows,
    caller: ThreadId,
    window: Option<WindowId>,
    show: bool,
    now: u64,
) -> Result<bool, NtStatus> {
    let owner = caret_window(windows, caller).ok_or(STATUS_ACCESS_DENIED)?;
    if window.is_some_and(|w| w != owner) {
        return Ok(false);
    }
    let hidden = windows.thread(caller).caret.hidden;
    if show {
        if hidden > 0 {
            windows.thread_mut(caller).caret.hidden = hidden - 1;
            if hidden == 1 {
                show_from(windows, caller, now);
            }
        }
    } else {
        if hidden == 0 {
            undraw(windows, caller);
            windows.thread_mut(caller).caret.due = None;
        }
        windows.thread_mut(caller).caret.hidden = hidden.saturating_add(1);
    }
    Ok(true)
}

/// SetCaretPos by `caller` at `now`: its caret moved to (`x`, `y`), on the screen at once when it
/// is shown; STATUS_ACCESS_DENIED when it has no caret.
pub fn set_pos(
    windows: &mut Windows,
    caller: ThreadId,
    x: i32,
    y: i32,
    now: u64,
) -> Result<(), NtStatus> {
    caret_window(windows, caller).ok_or(STATUS_ACCESS_DENIED)?;
    undraw(windows, caller);
    let caret = &mut windows.thread_mut(caller).caret;
    caret.x = x;
    caret.y = y;
    if caret.hidden == 0 {
        show_from(windows, caller, now);
    }
    Ok(())
}

/// GetCaretPos for `caller`: its caret place, a caret or none.
pub fn pos(windows: &Windows, caller: ThreadId) -> (i32, i32) {
    let caret = windows.thread(caller).caret;
    (caret.x, caret.y)
}

/// The blink: `thread`'s shown caret turned when its due came by `now` (on the screen or off it),
/// its next turn a blink time on.
pub fn blink(windows: &mut Windows, thread: ThreadId, now: u64) {
    let caret = windows.thread(thread).caret;
    if caret.window.is_none() || caret.hidden != 0 || caret.due.is_none_or(|due| due > now) {
        return;
    }
    if caret.drawn.is_some() {
        undraw(windows, thread);
    } else {
        draw(windows, thread);
    }
    windows.thread_mut(thread).caret.due = Some(now + BLINK);
}

/// When `thread`'s caret next turns (interrupt time); none while it is not shown.
pub fn next_due(windows: &Windows, thread: ThreadId) -> Option<u64> {
    let caret = windows.thread(thread).caret;
    caret.window.and(caret.due)
}

/// Whether painting `painted` paints over `window`: it is the window, or above it in its chain of
/// parents.
fn paints_over(windows: &Windows, painted: WindowId, window: WindowId) -> bool {
    let mut at = Some(window);
    while let Some(w) = at {
        if w == painted {
            return true;
        }
        if windows.window_style(w) & WS_CHILD == 0 {
            return false;
        }
        at = windows.parent_of(w);
    }
    false
}

/// BeginPaint of `painted` by `caller`: its caret taken off the screen while the window paints,
/// when the paint covers it.
pub fn paint_begins(windows: &mut Windows, caller: ThreadId, painted: WindowId) {
    let Some(window) = caret_window(windows, caller) else {
        return;
    };
    if paints_over(windows, painted, window) {
        undraw(windows, caller);
        windows.thread_mut(caller).caret.painting = true;
    }
}

/// EndPaint by `caller`: its caret put back on the screen, when BeginPaint took it off.
pub fn paint_ends(windows: &mut Windows, caller: ThreadId) {
    if windows.thread(caller).caret.painting {
        windows.thread_mut(caller).caret.painting = false;
        draw(windows, caller);
    }
}

/// The window `window` is being freed: a caret in it goes with it, taken off the screen. Windows
/// 2000 sends the destruction's WM_KILLFOCUS and WM_DESTROY before it frees the window, so a
/// procedure that destroys its caret there finds it (the caret capture's focus block); F2K's are
/// on their way to a window with a client-side procedure still, so its caret dies with them
/// instead: it shows nowhere, but its thread's caret calls find it until the window's
/// WM_NCDESTROY is delivered ([`ncdestroy_delivered`]).
pub fn window_gone(windows: &mut Windows, window: WindowId) {
    let thread = windows.window_thread(window);
    if windows.thread(thread).caret.window != Some(window) {
        return;
    }
    if windows.client_proc(window).is_some() {
        undraw(windows, thread);
        windows.thread_mut(thread).caret.dying = true;
    } else {
        remove(windows, thread);
    }
}

/// `caller` delivered the WM_NCDESTROY of the freed window `window`: a caret that died with it
/// goes.
pub fn ncdestroy_delivered(windows: &mut Windows, caller: ThreadId, window: WindowId) {
    let caret = windows.thread(caller).caret;
    if caret.dying && caret.window == Some(window) {
        remove(windows, caller);
    }
}

/// GetGUIThreadInfo's answer for `thread`: its active, focus and capture windows, its caret's
/// window and rectangle (client coordinates), GUI_CARETBLINKING while the caret is shown; its size
/// field left for the caller.
pub fn gui_thread_info(windows: &Windows, thread: ThreadId) -> GuiThreadInfo {
    let handle = |window: Option<WindowId>| {
        window
            .filter(|&w| windows.is_live(w))
            .map_or(0, |w| windows.handle_of(w))
    };
    let record = windows.thread(thread);
    let caret = caret_window(windows, thread).filter(|_| !record.caret.dying);
    GuiThreadInfo {
        cb_size: 0,
        flags: if caret.is_some() && record.caret.hidden == 0 {
            GUI_CARETBLINKING
        } else {
            0
        },
        hwnd_active: handle(super::focus::active_window(windows, thread)),
        hwnd_focus: handle(super::focus::focus_window(windows, thread)),
        hwnd_capture: handle(record.capture),
        hwnd_menu_owner: 0,
        hwnd_move_size: 0,
        hwnd_caret: handle(caret),
        rc_caret: if caret.is_some() {
            record.caret.rect()
        } else {
            Rect::default()
        },
    }
}

// --- The services --------------------------------------------------------------------------------

#[cfg(target_arch = "x86")]
mod services {
    use rtl::user::{Point, TWO_PARAM_SET_CARET_POS};

    use super::*;
    use crate::nt::call::{Handle, NtCall, NtResult, UserAddr, UserPtr};
    use crate::win32k::queue::{now, queue_by_client_id, with_manager};
    use crate::win32k::winsta::gui_thread;

    /// The window a handle names, none for 0; STATUS_INVALID_HANDLE for a handle naming no window.
    fn optional_window(windows: &Windows, handle: Handle) -> Result<Option<WindowId>, NtStatus> {
        match handle.raw() {
            0 => Ok(None),
            raw => windows
                .window_from_handle(raw)
                .map(Some)
                .ok_or(STATUS_INVALID_HANDLE),
        }
    }

    /// NtUserCreateCaret(Window, Gray, Width, Height, Made): see [`create`]; whether the caret
    /// was made into `made`. STATUS_INVALID_HANDLE for a handle naming no window, null included.
    pub fn create_caret(
        call: &mut NtCall,
        window: Handle,
        gray: u32,
        width: i32,
        height: i32,
        made: UserPtr<u32>,
    ) -> NtResult {
        let caller = gui_thread(call)?.thread;
        let answer = with_manager(call.passive(), |m| {
            let id = m
                .windows
                .window_from_handle(window.raw())
                .ok_or(STATUS_INVALID_HANDLE)?;
            Ok::<_, NtStatus>(create(&mut m.windows, caller, id, gray != 0, width, height))
        })?;
        made.write(answer as u32)?;
        Ok(STATUS_SUCCESS)
    }

    /// NtUserShowCaret(Window, Done): see [`show_or_hide`].
    pub fn show_caret(call: &mut NtCall, window: Handle, done: UserPtr<u32>) -> NtResult {
        show_or_hide_service(call, window, true, done)
    }

    /// NtUserHideCaret(Window, Done): see [`show_or_hide`].
    pub fn hide_caret(call: &mut NtCall, window: Handle, done: UserPtr<u32>) -> NtResult {
        show_or_hide_service(call, window, false, done)
    }

    fn show_or_hide_service(
        call: &mut NtCall,
        window: Handle,
        show: bool,
        done: UserPtr<u32>,
    ) -> NtResult {
        let caller = gui_thread(call)?.thread;
        let at = now();
        let answer = with_manager(call.passive(), |m| {
            let id = optional_window(&m.windows, window)?;
            show_or_hide(&mut m.windows, caller, id, show, at)
        })?;
        done.write(answer as u32)?;
        Ok(STATUS_SUCCESS)
    }

    /// NtUserGetCaretPos(Point): the calling thread's caret place.
    pub fn get_caret_pos(call: &mut NtCall, point: UserAddr) -> NtResult {
        let caller = gui_thread(call)?.thread;
        let (x, y) = with_manager(call.passive(), |m| pos(&m.windows, caller));
        point.cast::<Point>().write(Point { x, y })?;
        Ok(STATUS_SUCCESS)
    }

    /// NtUserGetGUIThreadInfo(ThreadId, Info): see [`gui_thread_info`], the size field the
    /// structure's; STATUS_INVALID_PARAMETER for a thread id naming no GUI thread. With no
    /// foreground thread, every field is 0.
    pub fn get_gui_thread_info(call: &mut NtCall, thread_id: u32, info: UserAddr) -> NtResult {
        gui_thread(call)?;
        let answer = with_manager(call.passive(), |m| {
            let thread = if thread_id == 0 {
                m.windows.foreground_thread
            } else {
                Some(
                    queue_by_client_id(&m.windows, thread_id)
                        .ok_or(STATUS_INVALID_PARAMETER)?
                        .0,
                )
            };
            Ok::<_, NtStatus>(thread.map_or(GuiThreadInfo::default(), |thread| {
                gui_thread_info(&m.windows, thread)
            }))
        })?;
        info.cast::<GuiThreadInfo>().write(GuiThreadInfo {
            cb_size: core::mem::size_of::<GuiThreadInfo>() as u32,
            ..answer
        })?;
        Ok(STATUS_SUCCESS)
    }

    /// NtUserCallTwoParam(Param1, Param2, Routine, Result): SetCaretPos ([`set_pos`], the place
    /// the two parameters), 1 into `result`; STATUS_INVALID_PARAMETER for another routine.
    pub fn call_two_param(
        call: &mut NtCall,
        param1: u32,
        param2: u32,
        routine: u32,
        result: UserPtr<u32>,
    ) -> NtResult {
        let caller = gui_thread(call)?.thread;
        let at = now();
        with_manager(call.passive(), |m| match routine {
            TWO_PARAM_SET_CARET_POS => {
                set_pos(&mut m.windows, caller, param1 as i32, param2 as i32, at)
            }
            _ => Err(STATUS_INVALID_PARAMETER),
        })?;
        result.write(1)?;
        Ok(STATUS_SUCCESS)
    }
}

#[cfg(target_arch = "x86")]
pub use services::{
    call_two_param,
    create_caret,
    get_caret_pos,
    get_gui_thread_info,
    hide_caret,
    show_caret,
};

// The host builds have no processes and no user memory: the services answer nothing (the host
// tests drive the decisions themselves).
#[cfg(not(target_arch = "x86"))]
mod services {
    use crate::nt::call::{Handle, NtCall, NtResult, UserAddr, UserPtr};
    use crate::status::*;

    pub fn create_caret(
        _: &mut NtCall,
        _: Handle,
        _: u32,
        _: i32,
        _: i32,
        _: UserPtr<u32>,
    ) -> NtResult {
        Err(STATUS_NOT_IMPLEMENTED)
    }

    pub fn show_caret(_: &mut NtCall, _: Handle, _: UserPtr<u32>) -> NtResult {
        Err(STATUS_NOT_IMPLEMENTED)
    }

    pub fn hide_caret(_: &mut NtCall, _: Handle, _: UserPtr<u32>) -> NtResult {
        Err(STATUS_NOT_IMPLEMENTED)
    }

    pub fn get_caret_pos(_: &mut NtCall, _: UserAddr) -> NtResult {
        Err(STATUS_NOT_IMPLEMENTED)
    }

    pub fn get_gui_thread_info(_: &mut NtCall, _: u32, _: UserAddr) -> NtResult {
        Err(STATUS_NOT_IMPLEMENTED)
    }

    pub fn call_two_param(_: &mut NtCall, _: u32, _: u32, _: u32, _: UserPtr<u32>) -> NtResult {
        Err(STATUS_NOT_IMPLEMENTED)
    }
}

#[cfg(not(target_arch = "x86"))]
pub use services::{
    call_two_param,
    create_caret,
    get_caret_pos,
    get_gui_thread_info,
    hide_caret,
    show_caret,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::win32k::queue::rig::*;
    use crate::win32k::queue::{take, Taken};
    use crate::win32k::window::WS_CHILD;

    /// A thread with a popup and a child of it, and a second thread: (thread, popup, child, other).
    fn setup(
        m: &mut crate::win32k::window::WindowManager,
        atom: crate::win32k::class::Atom,
    ) -> (ThreadId, WindowId, WindowId, ThreadId) {
        let t = thread(m, 1, 0x10);
        let top = popup(m, atom, t);
        let child = window_at(m, atom, t, WS_CHILD, top, 10, 10, 100, 30);
        deliver(m, t);
        let other = thread(m, 2, 0x14);
        let top = m.windows.window_from_handle(top).unwrap();
        let child = m.windows.window_from_handle(child).unwrap();
        (t, top, child, other)
    }

    /// A caret is made hidden at the thread's place, which outlives it; a zero size is the
    /// border's; another thread's window is refused.
    #[test]
    fn carets_are_made_hidden_at_the_threads_place() {
        let (m, atom) = manager();
        let (t, top, child, other) = setup(m, atom);
        let w = &mut m.windows;
        assert_eq!(destroy(w, t), Err(STATUS_ACCESS_DENIED));
        assert!(create(w, t, top, false, 2, 16));
        assert_eq!(gui_thread_info(w, t).flags, 0);
        assert_eq!(set_pos(w, t, -5, 300, 0), Ok(()));
        assert!(create(w, t, child, true, 0, 0));
        let info = gui_thread_info(w, t);
        assert_eq!(info.hwnd_caret, w.handle_of(child));
        assert_eq!(
            info.rc_caret,
            Rect {
                left: -5,
                top: 300,
                right: -4,
                bottom: 301
            }
        );
        assert!(
            !create(w, other, top, false, 2, 2),
            "another thread's window"
        );
        assert_eq!(destroy(w, t), Ok(()));
        assert_eq!(gui_thread_info(w, t).hwnd_caret, 0);
        assert_eq!(pos(w, t), (-5, 300));
        assert_eq!(set_pos(w, t, 1, 1, 0), Err(STATUS_ACCESS_DENIED));
    }

    /// ShowCaret undoes HideCaret down to 0 and no further; another window's call is refused; the
    /// owner's destruction takes the caret.
    #[test]
    fn the_hide_count() {
        let (m, atom) = manager();
        let (t, top, child, _) = setup(m, atom);
        let w = &mut m.windows;
        assert_eq!(
            show_or_hide(w, t, Some(top), true, 0),
            Err(STATUS_ACCESS_DENIED)
        );
        assert!(create(w, t, top, false, 2, 16));
        let shown = |w: &Windows| gui_thread_info(w, t).flags & GUI_CARETBLINKING != 0;
        assert_eq!(show_or_hide(w, t, Some(top), true, 0), Ok(true));
        assert!(shown(w));
        assert_eq!(show_or_hide(w, t, Some(top), true, 0), Ok(true));
        assert_eq!(show_or_hide(w, t, None, false, 0), Ok(true));
        assert_eq!(show_or_hide(w, t, None, false, 0), Ok(true));
        assert_eq!(show_or_hide(w, t, None, true, 0), Ok(true));
        assert!(!shown(w));
        assert_eq!(show_or_hide(w, t, None, true, 0), Ok(true));
        assert!(shown(w));
        assert_eq!(show_or_hide(w, t, Some(child), false, 0), Ok(false));
        assert!(shown(w));
        crate::win32k::queue::window_gone(w, top);
        assert_eq!(gui_thread_info(w, t).hwnd_caret, 0);
        assert_eq!(
            set_pos(w, t, 3, 4, 0),
            Ok(()),
            "found until WM_NCDESTROY is delivered"
        );
        ncdestroy_delivered(w, t, top);
        assert_eq!(destroy(w, t), Err(STATUS_ACCESS_DENIED));
    }

    /// A shown caret's blink comes due on the thread's reads, which wait no longer than it.
    #[test]
    fn the_blink_bounds_the_wait() {
        let (m, atom) = manager();
        let (t, top, _, _) = setup(m, atom);
        assert!(create(&mut m.windows, t, top, false, 2, 16));
        assert_eq!(read(m, t, &all(), 0), Taken::Nothing { due: None });
        assert_eq!(show_or_hide(&mut m.windows, t, None, true, 100), Ok(true));
        assert_eq!(
            take(&mut m.windows, t, &all(), true, 200).unwrap(),
            Taken::Nothing {
                due: Some(100 + BLINK)
            }
        );
        assert_eq!(
            take(&mut m.windows, t, &all(), true, 100 + BLINK).unwrap(),
            Taken::Nothing {
                due: Some(100 + 2 * BLINK)
            }
        );
    }
}
