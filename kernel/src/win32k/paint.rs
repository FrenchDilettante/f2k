//! Painting: the windows' update regions, the WM_PAINT a thread's read makes for them, and
//! BeginPaint and EndPaint.
//!
//! A window's update region is a record of the window manager's ([`Updates`], beside the queues,
//! behind its one lock): the part of its client area to paint, in client coordinates, and whether
//! its background is to be erased first. F2K keeps the region as one rectangle, the bounding box
//! of what was invalidated: an invalidation adds its rectangle's box; a validation takes out what
//! of the box it covers whole (all of it, or a band across a side), and leaves the box as it is
//! otherwise, so a window may paint more than it must, never less.
//!
//! InvalidateRect adds to the update region of a window that is shown (it and every parent up to
//! the desktop window have WS_VISIBLE; a hidden window has none, as Windows 2000's has none), and
//! to its children's, through their client areas, unless it clips its children (WS_CLIPCHILDREN,
//! RedrawWindow's rule when it names neither RDW_ALLCHILDREN nor RDW_NOCHILDREN). ValidateRect
//! takes out the same way. A window with an update region makes a WM_PAINT when its thread's read
//! finds nothing before it ([`super::queue::take`]); the message stays until the window is
//! validated. BeginPaint hands out a DC clipped to the region, and the region in the PAINTSTRUCT,
//! and validates the window; EndPaint releases the DC.
//!
//! The erase: Windows 2000's BeginPaint (and GetUpdateRect, asked to erase) sends WM_ERASEBKGND
//! itself. Sending is the receiving thread's own work here ([`super::queue`]), so the services
//! report the pending erase instead — PAINTSTRUCT's fErase, GetUpdateRect's [`UPDATE_ERASE`] — and
//! user32 sends WM_ERASEBKGND with the DC, fErase then saying whether the procedure left it
//! undone. UpdateWindow's WM_PAINT is a message the window manager sends, queued for the window's
//! thread as the others are.
//!
//! The services, user32's calls (F2K's argument lists, see [`crate::win32k`]):
//!
//! - NtUserInvalidateRect(handle Window, ptr Rect, bool Erase): the rectangle (the client area for
//!   none) added; a null window invalidates every shown top-level window of the caller's desktop;
//! - NtUserValidateRect(handle Window, ptr Rect): the rectangle taken out (the region for none); a
//!   null window invalidates every window, as its documentation says;
//! - NtUserGetUpdateRect(handle Window, ptr Rect, bool Erase, ptr<u32> Result): the region's
//!   rectangle (zeros for none) and the [`UPDATE_NOT_EMPTY`] and [`UPDATE_ERASE`] bits;
//! - NtUserBeginPaint(handle Window, ptr Paint): the PAINTSTRUCT, its DC made;
//! - NtUserEndPaint(handle Window, ptr Paint): the PAINTSTRUCT's DC released;
//! - NtUserCallHwndLock(handle Window, u32 Routine): UpdateWindow ([`HWND_LOCK_UPDATE_WINDOW`]).

use rtl::gdi::Rect;
#[cfg(doc)]
use rtl::user::HWND_LOCK_UPDATE_WINDOW;
use rtl::user::{UPDATE_ERASE, UPDATE_NOT_EMPTY, WM_PAINT};

use super::queue::{self, Filter};
use super::raster::intersect;
use super::window::{
    self,
    Hwnd,
    Message,
    Payload,
    WindowId,
    Windows,
    WINDOWS,
    WS_CLIPCHILDREN,
    WS_VISIBLE,
};
use crate::sched::thread::ThreadId;

/// The empty rectangle.
const EMPTY: Rect = Rect {
    left: 0,
    top: 0,
    right: 0,
    bottom: 0,
};

/// Whether `r` covers nothing.
fn is_empty(r: &Rect) -> bool {
    r.left >= r.right || r.top >= r.bottom
}

/// The smallest rectangle covering both `a` and `b` (an empty one covers nothing).
fn union(a: Rect, b: Rect) -> Rect {
    if is_empty(&a) {
        return b;
    }
    if is_empty(&b) {
        return a;
    }
    Rect {
        left: a.left.min(b.left),
        top: a.top.min(b.top),
        right: a.right.max(b.right),
        bottom: a.bottom.max(b.bottom),
    }
}

/// `r` moved by (`dx`, `dy`).
fn offset(r: Rect, dx: i32, dy: i32) -> Rect {
    Rect {
        left: r.left + dx,
        top: r.top + dy,
        right: r.right + dx,
        bottom: r.bottom + dy,
    }
}

/// What is left of `region` once `cut` is taken out of it, as a bounding box: nothing when `cut`
/// covers it, the rest when `cut` covers a whole band across one side, the box unchanged
/// otherwise.
fn subtract(region: Rect, cut: Rect) -> Rect {
    let common = intersect(region, cut);
    if is_empty(&common) {
        return region;
    }
    if common == region {
        return EMPTY;
    }
    let mut left = region;
    if common.top == region.top && common.bottom == region.bottom {
        if common.left == region.left {
            left.left = common.right;
        } else if common.right == region.right {
            left.right = common.left;
        }
    } else if common.left == region.left && common.right == region.right {
        if common.top == region.top {
            left.top = common.bottom;
        } else if common.bottom == region.bottom {
            left.bottom = common.top;
        }
    }
    left
}

/// A window rectangle as GDI's RECT.
fn rect_of(r: window::Rect) -> Rect {
    Rect {
        left: r.left,
        top: r.top,
        right: r.right,
        bottom: r.bottom,
    }
}

/// One window's update region.
#[derive(Clone, Copy)]
struct Update {
    /// The window; none for a free record.
    window: Option<WindowId>,
    /// The window's thread, whose read makes its WM_PAINT.
    thread: ThreadId,
    /// The region's box, in client coordinates.
    rect: Rect,
    /// The background is to be erased.
    erase: bool,
}

impl Update {
    const EMPTY: Self = Update {
        window: None,
        thread: ThreadId(0),
        rect: EMPTY,
        erase: false,
    };
}

/// The windows' update regions: a record a window that has one.
pub struct Updates {
    records: [Update; WINDOWS],
}

impl Updates {
    /// Write an empty table at `updates`, element by element.
    ///
    /// # Safety
    ///
    /// `updates` is valid for writes, aligned, and the records' final address; its previous
    /// contents are overwritten, not dropped.
    pub unsafe fn write_empty(updates: *mut Updates) {
        // SAFETY: the caller's contract; every record is written.
        unsafe {
            let records = core::ptr::addr_of_mut!((*updates).records) as *mut Update;
            for index in 0..WINDOWS {
                records.add(index).write(Update::EMPTY);
            }
        }
    }

    /// The record of `window`'s update region, when it has one.
    fn find(&self, window: WindowId) -> Option<usize> {
        self.records.iter().position(|u| u.window == Some(window))
    }

    /// The window `window` is being freed: its update region goes.
    pub fn window_gone(&mut self, window: WindowId) {
        if let Some(at) = self.find(window) {
            self.records[at] = Update::EMPTY;
        }
    }

    /// The thread record `thread`'s queue ended: the update regions its reads would paint go.
    pub fn thread_gone(&mut self, thread: ThreadId) {
        for record in self.records.iter_mut() {
            if record.window.is_some() && record.thread == thread {
                *record = Update::EMPTY;
            }
        }
    }
}

/// Whether the window is shown: it and each parent up to the desktop window have WS_VISIBLE. A
/// message-only window never is.
pub fn is_shown(windows: &Windows, window: WindowId) -> bool {
    let (desktop, message) = windows.desktop_roots(window);
    let mut at = Some(window);
    while let Some(w) = at {
        if Some(w) == message {
            return false;
        }
        if Some(w) == desktop {
            return true;
        }
        if windows.window_style(w) & WS_VISIBLE == 0 {
            return false;
        }
        at = windows.parent_of(w);
    }
    true
}

/// Visit `root` and its subtree, parents before children: `visit` answers whether to go down
/// into the window's children. The walk follows the links, so it takes no stack however deep the
/// tree.
fn walk(
    windows: &mut Windows,
    root: WindowId,
    mut visit: impl FnMut(&mut Windows, WindowId) -> bool,
) {
    let mut at = root;
    loop {
        if visit(windows, at) {
            if let Some(child) = windows.first_child(at) {
                at = child;
                continue;
            }
        }
        loop {
            if at == root {
                return;
            }
            if let Some(next) = windows.next_sibling(at) {
                at = next;
                break;
            }
            match windows.parent_of(at) {
                Some(parent) => at = parent,
                None => return,
            }
        }
    }
}

/// The screen area `rect` names of the window's client area (client coordinates; the whole client
/// area for none), cut to the client area.
fn screen_area(windows: &Windows, window: WindowId, rect: Option<Rect>) -> Rect {
    let client = rect_of(windows.client_rect(window));
    match rect {
        None => client,
        Some(r) => intersect(offset(r, client.left, client.top), client),
    }
}

/// Whether a walk goes down into the window's children: not when it clips them.
fn reaches_children(windows: &Windows, window: WindowId) -> bool {
    windows.window_style(window) & WS_CLIPCHILDREN == 0
}

/// InvalidateRect over a window: `rect` (client coordinates; the client area for none) added to
/// the update region of the window, when it is shown, and of its shown children through their
/// client areas (see the module notes), `erase` asking their backgrounds erased. Each thread
/// given a region to paint is woken.
pub fn invalidate(windows: &mut Windows, window: WindowId, rect: Option<Rect>, erase: bool) {
    if !is_shown(windows, window) {
        return;
    }
    let area = screen_area(windows, window, rect);
    if is_empty(&area) {
        return;
    }
    walk(windows, window, |windows, w| {
        if w != window && windows.window_style(w) & WS_VISIBLE == 0 {
            return false;
        }
        let client = rect_of(windows.client_rect(w));
        let part = intersect(area, client);
        if !is_empty(&part) {
            add(windows, w, offset(part, -client.left, -client.top), erase);
        }
        reaches_children(windows, w)
    });
}

/// Add `rect` (client coordinates) to the window's update region.
fn add(windows: &mut Windows, window: WindowId, rect: Rect, erase: bool) {
    let thread = windows.window_thread(window);
    let updates = &mut windows.queues.updates;
    let at = match updates.find(window) {
        Some(at) => at,
        None => match updates.records.iter().position(|u| u.window.is_none()) {
            Some(at) => {
                updates.records[at] = Update {
                    window: Some(window),
                    thread,
                    ..Update::EMPTY
                };
                at
            }
            // One record a window: the table holds every window's.
            None => return,
        },
    };
    let record = &mut updates.records[at];
    record.rect = union(record.rect, rect);
    record.erase |= erase;
    windows.queues.wake_thread(thread);
}

/// ValidateRect over a window: `rect` (client coordinates; the whole region for none) taken out
/// of the update region of the window and of its children through their client areas (see the
/// module notes). A region left empty goes, and its erase with it.
pub fn validate(windows: &mut Windows, window: WindowId, rect: Option<Rect>) {
    let area = screen_area(windows, window, rect);
    walk(windows, window, |windows, w| {
        let client = rect_of(windows.client_rect(w));
        let cut = match rect {
            None if w == window => None,
            _ => Some(offset(intersect(area, client), -client.left, -client.top)),
        };
        take_out(windows, w, cut);
        reaches_children(windows, w)
    });
}

/// Take `cut` (client coordinates; everything for none) out of the window's update region.
fn take_out(windows: &mut Windows, window: WindowId, cut: Option<Rect>) {
    let updates = &mut windows.queues.updates;
    let Some(at) = updates.find(window) else {
        return;
    };
    let record = &mut updates.records[at];
    let left = match cut {
        None => EMPTY,
        Some(cut) => subtract(record.rect, cut),
    };
    if is_empty(&left) {
        *record = Update::EMPTY;
    } else {
        record.rect = left;
    }
}

/// The InvalidateRect and ValidateRect of a null window: every shown top-level window of
/// `caller`'s desktop, and their children, invalidated whole.
pub fn invalidate_all(windows: &mut Windows, caller: ThreadId, erase: bool) {
    let mut at = windows
        .thread_desktop_window(caller)
        .and_then(|desktop| windows.first_child(desktop));
    while let Some(window) = at {
        at = windows.next_sibling(window);
        invalidate(windows, window, None, erase);
    }
}

/// The window's update region: its box (client coordinates) and whether an erase is pending; none
/// when it has none.
pub fn update_of(windows: &Windows, window: WindowId) -> Option<(Rect, bool)> {
    let updates = &windows.queues.updates;
    let record = &updates.records[updates.find(window)?];
    Some((record.rect, record.erase))
}

/// GetUpdateRect over a window: the region's box (zeros for none) and the answer's bits —
/// [`UPDATE_NOT_EMPTY`], and [`UPDATE_ERASE`] when `erase` asks the erase and one was pending (no
/// longer pending: the caller sends WM_ERASEBKGND).
pub fn update_rect(windows: &mut Windows, window: WindowId, erase: bool) -> (Rect, u32) {
    let updates = &mut windows.queues.updates;
    let Some(at) = updates.find(window) else {
        return (EMPTY, 0);
    };
    let record = &mut updates.records[at];
    let mut bits = UPDATE_NOT_EMPTY;
    if erase && record.erase {
        record.erase = false;
        bits |= UPDATE_ERASE;
    }
    (record.rect, bits)
}

/// The next window of `thread`'s the filter takes a WM_PAINT for: one with an update region.
pub fn next_paint(windows: &Windows, thread: ThreadId, filter: &Filter) -> Option<Hwnd> {
    windows
        .queues
        .updates
        .records
        .iter()
        .filter(|u| u.thread == thread)
        .filter_map(|u| u.window)
        .filter(|&w| windows.is_live(w))
        .map(|w| windows.handle_of(w))
        .find(|&hwnd| filter.takes_window(hwnd))
}

/// What BeginPaint paints: the region's box in client coordinates (zeros for none), whether the
/// erase is pending, and the DC's clipping region (the box on the screen).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PaintArea {
    pub paint: Rect,
    pub erase: bool,
    pub clip: Rect,
}

/// BeginPaint's look at the window, before its DC is made: see [`PaintArea`].
pub fn paint_area(windows: &Windows, window: WindowId) -> PaintArea {
    let client = rect_of(windows.client_rect(window));
    let (paint, erase) = update_of(windows, window).unwrap_or((EMPTY, false));
    let paint = intersect(
        paint,
        Rect {
            left: 0,
            top: 0,
            right: client.right - client.left,
            bottom: client.bottom - client.top,
        },
    );
    let paint = if is_empty(&paint) { EMPTY } else { paint };
    PaintArea {
        paint,
        erase,
        clip: offset(paint, client.left, client.top),
    }
}

/// BeginPaint's validation: the window's own update region goes, whole (its children keep
/// theirs).
pub fn begin_validate(windows: &mut Windows, window: WindowId) {
    take_out(windows, window, None);
}

/// UpdateWindow: a WM_PAINT sent to the window when its update region is not empty (queued for
/// its thread as the window manager's sends are, [`queue::defer`]).
pub fn update_window(windows: &mut Windows, window: WindowId) {
    if update_of(windows, window).is_some() {
        let message = Message {
            message: WM_PAINT,
            wparam: 0,
            lparam: 0,
            payload: Payload::None,
        };
        queue::defer(windows, window, &message, 0);
    }
}

// --- The services --------------------------------------------------------------------------------

#[cfg(target_arch = "x86")]
mod services {
    use rtl::user::{PaintStruct, HWND_LOCK_UPDATE_WINDOW};

    use super::*;
    use crate::nt::call::{Handle, NtCall, NtResult, UserAddr, UserPtr};
    use crate::status::*;
    use crate::win32k::queue::with_manager;
    use crate::win32k::winsta::gui_thread;

    /// The window a handle names; STATUS_INVALID_HANDLE for none.
    fn window_of(windows: &Windows, handle: Handle) -> Result<WindowId, NtStatus> {
        windows
            .window_from_handle(handle.raw())
            .ok_or(STATUS_INVALID_HANDLE)
    }

    /// The rectangle a caller's pointer names; none for a null pointer.
    fn read_rect(rect: UserAddr) -> Result<Option<Rect>, NtStatus> {
        if rect.is_null() {
            return Ok(None);
        }
        Ok(Some(rect.cast::<Rect>().read()?))
    }

    /// NtUserInvalidateRect(Window, Rect, Erase): see [`invalidate`] and [`invalidate_all`].
    pub fn invalidate_rect(
        call: &mut NtCall,
        window: Handle,
        rect: UserAddr,
        erase: bool,
    ) -> NtResult {
        let caller = gui_thread(call)?.thread;
        let rect = read_rect(rect)?;
        with_manager(call.passive(), |m| {
            if window.raw() == 0 {
                invalidate_all(&mut m.windows, caller, erase);
                return Ok::<_, NtStatus>(());
            }
            let id = window_of(&m.windows, window)?;
            invalidate(&mut m.windows, id, rect, erase);
            Ok(())
        })?;
        Ok(STATUS_SUCCESS)
    }

    /// NtUserValidateRect(Window, Rect): see [`validate`]; a null window is
    /// [`invalidate_all`]'s, as ValidateRect's documentation says.
    pub fn validate_rect(call: &mut NtCall, window: Handle, rect: UserAddr) -> NtResult {
        let caller = gui_thread(call)?.thread;
        let rect = read_rect(rect)?;
        with_manager(call.passive(), |m| {
            if window.raw() == 0 {
                invalidate_all(&mut m.windows, caller, true);
                return Ok::<_, NtStatus>(());
            }
            let id = window_of(&m.windows, window)?;
            validate(&mut m.windows, id, rect);
            Ok(())
        })?;
        Ok(STATUS_SUCCESS)
    }

    /// NtUserGetUpdateRect(Window, Rect, Erase, Result): see [`update_rect`]; the rectangle
    /// written when the pointer is not null.
    pub fn get_update_rect(
        call: &mut NtCall,
        window: Handle,
        rect: UserAddr,
        erase: bool,
        result: UserPtr<u32>,
    ) -> NtResult {
        gui_thread(call)?;
        let (update, bits) = with_manager(call.passive(), |m| {
            let id = window_of(&m.windows, window)?;
            Ok::<_, NtStatus>(update_rect(&mut m.windows, id, erase))
        })?;
        if !rect.is_null() {
            rect.cast::<Rect>().write(update)?;
        }
        result.write(bits)?;
        Ok(STATUS_SUCCESS)
    }

    /// NtUserBeginPaint(Window, Paint): the PAINTSTRUCT, its DC clipped to the update region, its
    /// erase the pending one, its rcPaint the region's box; the window validated. The DC is made
    /// before the window is validated, and closed again when the PAINTSTRUCT cannot be written.
    pub fn begin_paint(call: &mut NtCall, window: Handle, paint: UserAddr) -> NtResult {
        gui_thread(call)?;
        let paint = paint.cast::<PaintStruct>();
        let area = with_manager(call.passive(), |m| {
            let id = window_of(&m.windows, window)?;
            Ok::<_, NtStatus>(paint_area(&m.windows, id))
        })?;
        let hdc = crate::win32k::dc::paint_dc(call, area.clip)?;
        with_manager(call.passive(), |m| {
            if let Some(id) = m.windows.window_from_handle(window.raw()) {
                begin_validate(&mut m.windows, id);
            }
        });
        let written = paint.write(PaintStruct {
            hdc,
            erase: area.erase as i32,
            paint: area.paint,
            ..PaintStruct::default()
        });
        if written.is_err() {
            let _ = crate::win32k::dc::release_paint_dc(call, hdc);
        }
        written?;
        Ok(STATUS_SUCCESS)
    }

    /// NtUserEndPaint(Window, Paint): the PAINTSTRUCT's DC released (a DC already gone is no
    /// failure: EndPaint always succeeds once its arguments are read).
    pub fn end_paint(call: &mut NtCall, window: Handle, paint: UserAddr) -> NtResult {
        gui_thread(call)?;
        with_manager(call.passive(), |m| {
            window_of(&m.windows, window).map(|_| ())
        })?;
        let paint = paint.cast::<PaintStruct>().read()?;
        let _ = crate::win32k::dc::release_paint_dc(call, paint.hdc);
        Ok(STATUS_SUCCESS)
    }

    /// NtUserCallHwndLock(Window, Routine): UpdateWindow ([`update_window`]), and the focus and
    /// activation routines ([`crate::win32k::focus::call_hwnd_lock`]); STATUS_INVALID_PARAMETER
    /// for another routine.
    pub fn call_hwnd_lock(call: &mut NtCall, window: Handle, routine: u32) -> NtResult {
        let caller = gui_thread(call)?.thread;
        with_manager(call.passive(), |m| {
            let id = window_of(&m.windows, window)?;
            match routine {
                HWND_LOCK_UPDATE_WINDOW => {
                    update_window(&mut m.windows, id);
                    Ok(())
                }
                _ => {
                    let crate::win32k::window::WindowManager {
                        windows, classes, ..
                    } = m;
                    crate::win32k::focus::call_hwnd_lock(
                        windows,
                        classes,
                        caller,
                        id,
                        routine,
                        &mut crate::win32k::queue::QueuePump,
                    )
                    .unwrap_or(Err(STATUS_INVALID_PARAMETER))
                }
            }
        })?;
        Ok(STATUS_SUCCESS)
    }
}

pub use services::{
    begin_paint,
    call_hwnd_lock,
    end_paint,
    get_update_rect,
    invalidate_rect,
    validate_rect,
};

// The host builds have no processes and no user memory: the services answer nothing (the host
// tests drive the update regions themselves).
#[cfg(not(target_arch = "x86"))]
mod services {
    use crate::nt::call::{Handle, NtCall, NtResult, UserAddr, UserPtr};
    use crate::status::*;

    pub fn invalidate_rect(_: &mut NtCall, _: Handle, _: UserAddr, _: bool) -> NtResult {
        Err(STATUS_NOT_IMPLEMENTED)
    }

    pub fn validate_rect(_: &mut NtCall, _: Handle, _: UserAddr) -> NtResult {
        Err(STATUS_NOT_IMPLEMENTED)
    }

    pub fn get_update_rect(
        _: &mut NtCall,
        _: Handle,
        _: UserAddr,
        _: bool,
        _: UserPtr<u32>,
    ) -> NtResult {
        Err(STATUS_NOT_IMPLEMENTED)
    }

    pub fn begin_paint(_: &mut NtCall, _: Handle, _: UserAddr) -> NtResult {
        Err(STATUS_NOT_IMPLEMENTED)
    }

    pub fn end_paint(_: &mut NtCall, _: Handle, _: UserAddr) -> NtResult {
        Err(STATUS_NOT_IMPLEMENTED)
    }

    pub fn call_hwnd_lock(_: &mut NtCall, _: Handle, _: u32) -> NtResult {
        Err(STATUS_NOT_IMPLEMENTED)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::win32k::class;
    use crate::win32k::queue::rig::*;
    use crate::win32k::queue::{QueuePump, Taken};
    use crate::win32k::window::{WindowManager, WS_CHILD, WS_POPUP};

    fn rect(left: i32, top: i32, right: i32, bottom: i32) -> Rect {
        Rect {
            left,
            top,
            right,
            bottom,
        }
    }

    /// A shown 320x200 popup at (`x`, `y`): its id and handle, its creation messages delivered.
    fn shown(
        m: &mut WindowManager,
        atom: class::Atom,
        t: ThreadId,
        x: i32,
        y: i32,
    ) -> (WindowId, Hwnd) {
        let h = window_at(m, atom, t, WS_POPUP, 0, x, y, 320, 200);
        deliver(m, t);
        let w = m.windows.window_from_handle(h).unwrap();
        m.windows.set_visible_for_tests(w, true);
        (w, h)
    }

    /// The invalidate, subrect and beginend captures: a hidden window takes no update region —
    /// GetUpdateRect then answers none with a zero rectangle, and BeginPaint's PAINTSTRUCT has no
    /// erase and a zero rcPaint.
    #[test]
    fn a_hidden_window_has_no_update_region() {
        let (m, atom) = manager();
        let t = thread(m, 1, 0x100);
        let h = popup(m, atom, t);
        deliver(m, t);
        let w = m.windows.window_from_handle(h).unwrap();
        invalidate(&mut m.windows, w, None, true);
        invalidate(&mut m.windows, w, Some(rect(10, 10, 50, 40)), true);
        assert_eq!(update_rect(&mut m.windows, w, false), (EMPTY, 0));
        validate(&mut m.windows, w, None);
        assert_eq!(
            paint_area(&m.windows, w),
            PaintArea {
                paint: EMPTY,
                erase: false,
                clip: EMPTY,
            }
        );
        assert_eq!(read(m, t, &all(), 0), Taken::Nothing { due: None });
    }

    /// The paint capture's path: a shown window's whole client area invalidated with the erase
    /// makes a WM_PAINT; GetUpdateRect reports the client area (its erase handed to the caller once
    /// when asked); BeginPaint's area is the client area, its erase pending, its clip the client
    /// area on the screen; once validated, nothing is left.
    #[test]
    fn a_shown_windows_invalidation_makes_a_wm_paint() {
        let (m, atom) = manager();
        let t = thread(m, 1, 0x100);
        let (w, h) = shown(m, atom, t, 30, 40);
        m.windows.queues.take_wakes();
        invalidate(&mut m.windows, w, None, true);
        assert_eq!(m.windows.queues.take_wakes()[0], 1 << t.0);
        assert_eq!(
            update_rect(&mut m.windows, w, false),
            (rect(0, 0, 320, 200), UPDATE_NOT_EMPTY)
        );
        let paint = msg_of(read(m, t, &all(), 0));
        assert_eq!((paint.hwnd, paint.message), (h, WM_PAINT));
        let again = msg_of(read(m, t, &all(), 0));
        assert_eq!(
            again.message, WM_PAINT,
            "it stays until the window is validated"
        );
        assert_eq!(
            paint_area(&m.windows, w),
            PaintArea {
                paint: rect(0, 0, 320, 200),
                erase: true,
                clip: rect(30, 40, 350, 240),
            }
        );
        assert_eq!(
            update_rect(&mut m.windows, w, true),
            (rect(0, 0, 320, 200), UPDATE_NOT_EMPTY | UPDATE_ERASE)
        );
        assert_eq!(
            update_rect(&mut m.windows, w, true),
            (rect(0, 0, 320, 200), UPDATE_NOT_EMPTY),
            "the erase is handed out once"
        );
        begin_validate(&mut m.windows, w);
        assert_eq!(update_rect(&mut m.windows, w, false), (EMPTY, 0));
        assert_eq!(read(m, t, &all(), 0), Taken::Nothing { due: None });
    }

    /// The subrect capture's rectangle on a shown window: the update region is the rectangle; a
    /// validation of it leaves none; a band across a side comes off the box, a hole in the middle
    /// leaves the box whole; an invalidation outside the client area adds nothing.
    #[test]
    fn a_subrectangle_is_added_and_taken_out() {
        let (m, atom) = manager();
        let t = thread(m, 1, 0x100);
        let (w, _) = shown(m, atom, t, 0, 0);
        let sub = rect(10, 10, 50, 40);
        invalidate(&mut m.windows, w, Some(sub), false);
        assert_eq!(
            update_rect(&mut m.windows, w, true),
            (sub, UPDATE_NOT_EMPTY)
        );
        validate(&mut m.windows, w, Some(sub));
        assert_eq!(update_rect(&mut m.windows, w, false), (EMPTY, 0));

        invalidate(&mut m.windows, w, Some(sub), false);
        invalidate(&mut m.windows, w, Some(rect(100, 100, 120, 110)), false);
        assert_eq!(
            update_rect(&mut m.windows, w, false).0,
            rect(10, 10, 120, 110)
        );
        validate(&mut m.windows, w, Some(rect(0, 0, 60, 200)));
        assert_eq!(
            update_rect(&mut m.windows, w, false).0,
            rect(60, 10, 120, 110)
        );
        validate(&mut m.windows, w, Some(rect(70, 20, 80, 30)));
        assert_eq!(
            update_rect(&mut m.windows, w, false).0,
            rect(60, 10, 120, 110)
        );
        validate(&mut m.windows, w, None);

        invalidate(&mut m.windows, w, Some(rect(400, 0, 500, 50)), false);
        assert_eq!(update_rect(&mut m.windows, w, false), (EMPTY, 0));
        invalidate(&mut m.windows, w, Some(rect(-10, -10, 5, 5)), false);
        assert_eq!(
            update_rect(&mut m.windows, w, false).0,
            rect(0, 0, 5, 5),
            "cut to the client area"
        );
    }

    /// The children: an invalidation reaches a shown child through its client area, unless the
    /// parent clips its children; a hidden child takes none; a validation takes out the same way;
    /// BeginPaint validates the window alone.
    #[test]
    fn children_share_their_parents_invalidation() {
        let (m, atom) = manager();
        let t = thread(m, 1, 0x100);
        let (parent, ph) = shown(m, atom, t, 0, 0);
        let child_h = window_at(m, atom, t, WS_CHILD, ph, 100, 50, 40, 30);
        let hidden_h = window_at(m, atom, t, WS_CHILD, ph, 0, 0, 40, 30);
        deliver(m, t);
        let child = m.windows.window_from_handle(child_h).unwrap();
        let hidden = m.windows.window_from_handle(hidden_h).unwrap();
        m.windows.set_visible_for_tests(child, true);
        invalidate(&mut m.windows, parent, Some(rect(110, 60, 300, 200)), true);
        assert_eq!(
            update_rect(&mut m.windows, child, false).0,
            rect(10, 10, 40, 30)
        );
        assert_eq!(update_rect(&mut m.windows, hidden, false), (EMPTY, 0));
        begin_validate(&mut m.windows, parent);
        assert_eq!(
            update_rect(&mut m.windows, child, false).1,
            UPDATE_NOT_EMPTY
        );
        validate(&mut m.windows, parent, None);
        assert_eq!(update_rect(&mut m.windows, child, false), (EMPTY, 0));

        let clipping = window_at(
            m,
            atom,
            t,
            WS_POPUP | crate::win32k::window::WS_CLIPCHILDREN,
            0,
            0,
            0,
            100,
            100,
        );
        let inner_h = window_at(m, atom, t, WS_CHILD, clipping, 0, 0, 10, 10);
        deliver(m, t);
        let clipping = m.windows.window_from_handle(clipping).unwrap();
        let inner = m.windows.window_from_handle(inner_h).unwrap();
        m.windows.set_visible_for_tests(clipping, true);
        m.windows.set_visible_for_tests(inner, true);
        invalidate(&mut m.windows, clipping, None, false);
        assert_eq!(
            update_rect(&mut m.windows, clipping, false).1,
            UPDATE_NOT_EMPTY
        );
        assert_eq!(update_rect(&mut m.windows, inner, false), (EMPTY, 0));
        assert!(is_shown(&m.windows, inner));
        m.windows.set_visible_for_tests(clipping, false);
        assert!(
            !is_shown(&m.windows, inner),
            "a hidden parent hides its children"
        );
    }

    /// UpdateWindow sends WM_PAINT (queued for the window's thread, as the window manager's sends
    /// are) when the update region is not empty, nothing otherwise.
    #[test]
    fn update_window_sends_wm_paint_when_there_is_something_to_paint() {
        let (m, atom) = manager();
        let t = thread(m, 1, 0x100);
        let (w, h) = shown(m, atom, t, 0, 0);
        update_window(&mut m.windows, w);
        assert_eq!(deliver(m, t), vec![]);
        invalidate(&mut m.windows, w, None, true);
        update_window(&mut m.windows, w);
        assert_eq!(deliver(m, t), vec![(h, WM_PAINT)]);
    }

    /// A window's update region goes with the window; a WM_PAINT is made only for the filter's
    /// window.
    #[test]
    fn the_update_region_goes_with_the_window() {
        let (m, atom) = manager();
        let t = thread(m, 1, 0x100);
        let (w, h) = shown(m, atom, t, 0, 0);
        let (other, _) = shown(m, atom, t, 0, 0);
        invalidate(&mut m.windows, w, None, false);
        let filter = crate::win32k::queue::Filter::new(m.windows.handle_of(other), 0, 0, 0);
        assert_eq!(read(m, t, &filter, 0), Taken::Nothing { due: None });
        let WindowManager {
            windows, classes, ..
        } = &mut *m;
        windows
            .destroy_window_handle(classes, t, h, &mut QueuePump)
            .unwrap();
        deliver(m, t);
        assert_eq!(read(m, t, &all(), 0), Taken::Nothing { due: None });
    }

    /// The null window's invalidation: every shown top-level window of the caller's desktop.
    #[test]
    fn a_null_window_invalidates_every_shown_window() {
        let (m, atom) = manager();
        let t = thread(m, 1, 0x100);
        let (a, _) = shown(m, atom, t, 0, 0);
        let hidden = popup(m, atom, t);
        deliver(m, t);
        let hidden = m.windows.window_from_handle(hidden).unwrap();
        invalidate_all(&mut m.windows, t, true);
        assert_eq!(
            update_rect(&mut m.windows, a, true),
            (rect(0, 0, 320, 200), UPDATE_NOT_EMPTY | UPDATE_ERASE)
        );
        assert_eq!(update_rect(&mut m.windows, hidden, false), (EMPTY, 0));
    }

    /// The box arithmetic: the union of two boxes, an empty one adding nothing; a cut that covers a
    /// band across a side takes it off, one that covers it all leaves nothing.
    #[test]
    fn the_box_arithmetic() {
        assert_eq!(union(EMPTY, rect(1, 2, 3, 4)), rect(1, 2, 3, 4));
        assert_eq!(union(rect(0, 0, 2, 2), rect(5, 5, 6, 6)), rect(0, 0, 6, 6));
        let r = rect(0, 0, 10, 10);
        assert_eq!(subtract(r, rect(-5, -5, 20, 20)), EMPTY);
        assert_eq!(subtract(r, rect(0, 0, 10, 4)), rect(0, 4, 10, 10));
        assert_eq!(subtract(r, rect(0, 6, 10, 10)), rect(0, 0, 10, 6));
        assert_eq!(subtract(r, rect(8, -1, 11, 11)), rect(0, 0, 8, 10));
        assert_eq!(subtract(r, rect(-1, 0, 3, 10)), rect(3, 0, 10, 10));
        assert_eq!(subtract(r, rect(2, 2, 4, 4)), r);
        assert_eq!(subtract(r, rect(20, 20, 30, 30)), r);
    }
}
