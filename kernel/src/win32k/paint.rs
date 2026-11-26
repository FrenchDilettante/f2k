//! Painting: the windows' update regions, the WM_PAINT a thread's read makes for them, and
//! BeginPaint and EndPaint.
//!
//! A window's update region is a record of the window manager's ([`Updates`], beside the queues,
//! behind its one lock): the part of its client area to paint, in client coordinates, and whether
//! its background is to be erased first. The region is a true region ([`super::region`]'s y-x
//! banded rectangles, its own block when it holds more than a body keeps): an invalidation adds
//! its rectangle or region (cut to the client area), a validation takes its rectangle or region
//! out. When the pool has no room for the answer, an invalidation adds the box of what it adds and
//! a validation takes nothing out, so a window may paint more than it must, never less.
//!
//! InvalidateRect and InvalidateRgn add to the update region of a window that is shown (it and
//! every parent up to the desktop window have WS_VISIBLE; a hidden window has none, as Windows
//! 2000's has none), and to its children's, through their client areas, unless it clips its
//! children (WS_CLIPCHILDREN, RedrawWindow's rule when it names neither RDW_ALLCHILDREN nor
//! RDW_NOCHILDREN). ValidateRect and ValidateRgn take out the same way. A window with an update
//! region makes a WM_PAINT when its thread's read finds nothing before it ([`super::queue::take`]);
//! the message stays until the window is validated. BeginPaint hands out a DC whose visible region
//! is cut to the update region ([`super::dc::paint_dc`]), the region's box in the PAINTSTRUCT's
//! rcPaint, and validates the window; EndPaint releases the DC. GetUpdateRgn copies the region into
//! a region object.
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
//! - NtUserInvalidateRgn(handle Window, handle Region, bool Erase): the region (client coordinates;
//!   the client area for a null handle) added;
//! - NtUserCallHwndParamLock's ValidateRgn ([`rtl::user::HWND_PARAM_LOCK_VALIDATE_RGN`], Windows
//!   2000's SFI_XXXVALIDATERGN): the region (all of it for a null handle) taken out
//!   ([`validate_rgn`]);
//! - NtUserGetUpdateRect(handle Window, ptr Rect, bool Erase, ptr<u32> Result): the region's
//!   rectangle (zeros for none) and the [`UPDATE_NOT_EMPTY`] and [`UPDATE_ERASE`] bits;
//! - NtUserGetUpdateRgn(handle Window, handle Region, bool Erase, ptr<u32> Result): the region
//!   object made a copy of the update region (the empty region for none), its complexity, and the
//!   [`UPDATE_ERASE`] bit as GetUpdateRect's (the result's high half);
//! - NtUserBeginPaint(handle Window, ptr Paint): the PAINTSTRUCT, its DC made;
//! - NtUserEndPaint(handle Window, ptr Paint): the PAINTSTRUCT's DC released;
//! - NtUserCallHwndLock(handle Window, u32 Routine): UpdateWindow ([`HWND_LOCK_UPDATE_WINDOW`]).

use rtl::gdi::Rect;
#[cfg(doc)]
use rtl::user::HWND_LOCK_UPDATE_WINDOW;
use rtl::user::{QS_PAINT, UPDATE_ERASE, UPDATE_NOT_EMPTY, WM_PAINT, WS_CLIPCHILDREN, WS_VISIBLE};

use super::queue::Filter;
use super::region::OwnedRegion;
use super::window::{Hwnd, Message, Payload, Session, WindowId, Windows};
use crate::sched::thread::ThreadId;
use crate::slots::{Id, LowestFirst, Record, Slots};

/// One window's update region.
struct Update {
    /// The window.
    window: Option<WindowId>,
    /// The window's thread, whose read makes its WM_PAINT.
    thread: ThreadId,
    /// The region, in client coordinates (its block given back when the record is cleared).
    region: OwnedRegion,
    /// The background is to be erased.
    erase: bool,
}

impl Update {
    const EMPTY: Self = Update {
        window: None,
        thread: ThreadId(0),
        region: OwnedRegion::empty(),
        erase: false,
    };
}

// SAFETY: `write_fresh` writes a whole record.
unsafe impl Record for Update {
    unsafe fn write_fresh(at: *mut Self, _: u32) {
        // SAFETY: the caller's contract.
        unsafe { at.write(Update::EMPTY) };
    }
}

/// The update records' kind of id.
enum UpdateTag {}

/// An update record's id.
type UpdateId = Id<UpdateTag>;

/// Update records to a chunk: one page's worth.
const UPDATES_PER_CHUNK: usize = crate::slots::per_page::<Update>();

const _: () = assert!(Slots::<Update, LowestFirst<UpdateTag>, UPDATES_PER_CHUNK>::CHUNK_PAGES == 1);

/// The windows' update regions: a record a window that has one, taken lowest free first, the
/// order the WM_PAINT search goes in ([`next_paint`]), grown a page at a time.
pub struct Updates {
    records: Slots<Update, LowestFirst<UpdateTag>, UPDATES_PER_CHUNK>,
}

impl Updates {
    /// Write an empty table at `updates`.
    ///
    /// # Safety
    ///
    /// `updates` is valid for writes and aligned; its previous contents are overwritten, not
    /// dropped.
    pub unsafe fn write_empty(updates: *mut Updates) {
        // SAFETY: the caller's contract.
        unsafe {
            updates.write(Updates {
                records: Slots::new(),
            })
        };
    }

    /// The record of `window`'s update region, when it has one.
    fn find(&self, window: WindowId) -> Option<UpdateId> {
        self.records
            .iter()
            .find(|(_, u)| u.window == Some(window))
            .map(|(id, _)| id)
    }

    fn record(&self, window: WindowId) -> Option<&Update> {
        self.records.get(self.find(window)?)
    }

    fn record_mut(&mut self, window: WindowId) -> Option<&mut Update> {
        let id = self.find(window)?;
        self.records.get_mut(id)
    }

    /// The window `window` is being freed: its update region goes.
    pub fn window_gone(&mut self, window: WindowId) {
        if let Some(id) = self.find(window) {
            self.free(id);
        }
    }

    /// Free the record `id`, its region's block given back first (a freed record is not
    /// dropped).
    fn free(&mut self, id: UpdateId) {
        if let Some(record) = self.records.get_mut(id) {
            record.region = OwnedRegion::empty();
        }
        self.records.free(id);
    }

    /// The thread record `thread`'s queue ended: the update regions its reads would paint go.
    pub fn thread_gone(&mut self, thread: ThreadId) {
        for index in 0..self.records.high_water() {
            let Some(id) = self.records.id_at(index) else {
                continue;
            };
            if self.records.get(id).is_some_and(|u| u.thread == thread) {
                self.free(id);
            }
        }
    }

    /// How many windows have an update region.
    #[cfg(test)]
    fn live(&self) -> u32 {
        self.records.live()
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
    let client = windows.client_rect(window);
    match rect {
        None => client,
        Some(r) => r
            .saturating_offset(client.left, client.top)
            .intersect(client),
    }
}

/// Whether a walk goes down into the window's children: not when it clips them.
fn reaches_children(windows: &Windows, window: WindowId) -> bool {
    windows.window_style(window) & WS_CLIPCHILDREN == 0
}

/// The rectangles of `rect` as a region's (none when it is empty).
fn rect_rects(rect: &Rect) -> &[Rect] {
    if rect.is_empty() {
        &[]
    } else {
        core::slice::from_ref(rect)
    }
}

/// The screen region `region` names of the window's client area (client coordinates; the whole
/// client area for none), cut to the client area; its box alone when the pool has no room for it.
fn screen_region(windows: &Windows, window: WindowId, region: Option<&[Rect]>) -> OwnedRegion {
    let client = windows.client_rect(window);
    let Some(rects) = region else {
        return OwnedRegion::rect(client);
    };
    OwnedRegion::moved(rects, client.left, client.top)
        .and_then(|moved| OwnedRegion::combined(moved.rects(), rect_rects(&client), |a, b| a && b))
        .unwrap_or_else(|| {
            let bounds = super::region::bounds_of(rects);
            OwnedRegion::rect(screen_area(windows, window, Some(bounds)))
        })
}

/// The part of the screen region `area` inside the client area `client`, in client coordinates;
/// none when the pool has no room for it.
fn client_part(area: &[Rect], client: Rect) -> Option<OwnedRegion> {
    let part = OwnedRegion::combined(area, rect_rects(&client), |a, b| a && b)?;
    if part.is_empty() {
        return Some(part);
    }
    OwnedRegion::moved_back(part.rects(), client.left, client.top)
}

/// InvalidateRect over a window: `rect` (client coordinates; the client area for none) added to
/// the update region of the window, when it is shown, and of its shown children through their
/// client areas (see the module notes), `erase` asking their backgrounds erased. Each thread
/// given a region to paint is woken.
pub fn invalidate(windows: &mut Windows, window: WindowId, rect: Option<Rect>, erase: bool) {
    match rect {
        Some(rect) => invalidate_region(windows, window, Some(rect_rects(&rect)), erase),
        None => invalidate_region(windows, window, None, erase),
    }
}

/// InvalidateRgn over a window: [`invalidate`] of the region `region` (banded rectangles, client
/// coordinates; the client area for none).
pub fn invalidate_region(
    windows: &mut Windows,
    window: WindowId,
    region: Option<&[Rect]>,
    erase: bool,
) {
    if !is_shown(windows, window) {
        return;
    }
    let area = screen_region(windows, window, region);
    if area.is_empty() {
        return;
    }
    walk(windows, window, |windows, w| {
        if w != window && windows.window_style(w) & WS_VISIBLE == 0 {
            return false;
        }
        let client = windows.client_rect(w);
        let part = client_part(area.rects(), client).unwrap_or_else(|| {
            let bounds = area.bounds().intersect(client);
            OwnedRegion::rect(bounds.saturating_offset_back(client.left, client.top))
        });
        if !part.is_empty() {
            add(windows, w, part, erase);
        }
        reaches_children(windows, w)
    });
}

/// Add `part` (client coordinates, not empty) to the window's update region.
fn add(windows: &mut Windows, window: WindowId, part: OwnedRegion, erase: bool) {
    let thread = windows.window_thread(window);
    let updates = &mut windows.queues.updates;
    let id = match updates.find(window) {
        Some(id) => id,
        None => match updates.records.allocate_or_grow(0, super::pages()) {
            Ok((id, record)) => {
                *record = Update {
                    window: Some(window),
                    thread,
                    ..Update::EMPTY
                };
                id
            }
            // No page left for the record: the window stays as it was, unpainted.
            Err(_) => return,
        },
    };
    let Some(record) = updates.records.get_mut(id) else {
        return;
    };
    record.region = if record.region.is_empty() {
        part
    } else {
        OwnedRegion::combined(record.region.rects(), part.rects(), |a, b| a || b)
            .unwrap_or_else(|| OwnedRegion::rect(record.region.bounds().union(part.bounds())))
    };
    record.erase |= erase;
    windows.queues.wake_thread(thread, QS_PAINT);
}

/// ValidateRect over a window: `rect` (client coordinates; the whole region for none) taken out
/// of the update region of the window and of its children through their client areas (see the
/// module notes). A region left empty goes, and its erase with it.
pub fn validate(windows: &mut Windows, window: WindowId, rect: Option<Rect>) {
    match rect {
        Some(rect) => validate_region(windows, window, Some(rect_rects(&rect))),
        None => validate_region(windows, window, None),
    }
}

/// ValidateRgn over a window: [`validate`] of the region `region` (banded rectangles, client
/// coordinates; the whole update region for none).
pub fn validate_region(windows: &mut Windows, window: WindowId, region: Option<&[Rect]>) {
    let area = screen_region(windows, window, region);
    walk(windows, window, |windows, w| {
        if region.is_none() && w == window {
            take_out(windows, w, None);
        } else if let Some(cut) = client_part(area.rects(), windows.client_rect(w)) {
            take_out(windows, w, Some(cut.rects()));
        }
        reaches_children(windows, w)
    });
}

/// Take `cut` (client coordinates; everything for none) out of the window's update region; when
/// the pool has no room for what is left, nothing is taken out.
fn take_out(windows: &mut Windows, window: WindowId, cut: Option<&[Rect]>) {
    let updates = &mut windows.queues.updates;
    let Some(id) = updates.find(window) else {
        return;
    };
    let Some(record) = updates.records.get_mut(id) else {
        return;
    };
    let left = match cut {
        None => OwnedRegion::empty(),
        Some([]) => return,
        Some(cut) => match OwnedRegion::combined(record.region.rects(), cut, |a, b| a && !b) {
            Some(left) => left,
            None => return,
        },
    };
    if left.is_empty() {
        updates.free(id);
    } else {
        record.region = left;
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
    let record = windows.queues.updates.record(window)?;
    Some((record.region.bounds(), record.erase))
}

/// The window's update region (client coordinates; none when it has none).
pub fn update_region_of(windows: &Windows, window: WindowId) -> Option<&OwnedRegion> {
    Some(&windows.queues.updates.record(window)?.region)
}

/// GetUpdateRgn over a window: a copy of the update region (the empty region for none), and
/// [`UPDATE_ERASE`] when `erase` asks the erase and one was pending (handed to the caller, as
/// [`update_rect`]'s); none when the pool has no room for the copy.
pub fn update_region(
    windows: &mut Windows,
    window: WindowId,
    erase: bool,
) -> Option<(OwnedRegion, u32)> {
    let Some(record) = windows.queues.updates.record_mut(window) else {
        return Some((OwnedRegion::empty(), 0));
    };
    let copy = record.region.duplicate()?;
    let mut bits = UPDATE_NOT_EMPTY;
    if erase && record.erase {
        record.erase = false;
        bits |= UPDATE_ERASE;
    }
    Some((copy, bits))
}

/// GetUpdateRect over a window: the region's box (zeros for none) and the answer's bits —
/// [`UPDATE_NOT_EMPTY`], and [`UPDATE_ERASE`] when `erase` asks the erase and one was pending (no
/// longer pending: the caller sends WM_ERASEBKGND).
pub fn update_rect(windows: &mut Windows, window: WindowId, erase: bool) -> (Rect, u32) {
    let Some(record) = windows.queues.updates.record_mut(window) else {
        return (Rect::EMPTY, 0);
    };
    let mut bits = UPDATE_NOT_EMPTY;
    if erase && record.erase {
        record.erase = false;
        bits |= UPDATE_ERASE;
    }
    (record.region.bounds(), bits)
}

/// The next window of `thread`'s the filter takes a WM_PAINT for: one with an update region.
pub fn next_paint(windows: &Windows, thread: ThreadId, filter: &Filter) -> Option<Hwnd> {
    windows
        .queues
        .updates
        .records
        .iter()
        .map(|(_, u)| u)
        .filter(|u| u.thread == thread)
        .filter_map(|u| u.window)
        .filter(|&w| windows.is_live(w))
        .map(|w| windows.handle_of(w))
        .find(|&hwnd| filter.takes_window(hwnd))
}

/// What BeginPaint paints: the region's box in client coordinates (zeros for none), whether the
/// erase is pending, the update region its DC's visible region is cut to (client coordinates,
/// within the client area), and the client area on the screen (the DC's origin its top left).
#[derive(Debug, PartialEq, Eq)]
pub struct PaintArea {
    pub paint: Rect,
    pub erase: bool,
    pub update: OwnedRegion,
    pub client: Rect,
}

/// BeginPaint's look at the window, before its DC is made: see [`PaintArea`]. When the pool has
/// no room for the region's copy, the DC is cut to its box.
pub fn paint_area(windows: &Windows, window: WindowId) -> PaintArea {
    let client = windows.client_rect(window);
    let local = Rect::new(0, 0, client.width(), client.height());
    let erase = update_of(windows, window).is_some_and(|(_, erase)| erase);
    let update = match update_region_of(windows, window) {
        None => OwnedRegion::empty(),
        Some(region) => OwnedRegion::combined(region.rects(), rect_rects(&local), |a, b| a && b)
            .unwrap_or_else(|| OwnedRegion::rect(region.bounds().intersect(local))),
    };
    PaintArea {
        paint: update.bounds(),
        erase,
        update,
        client,
    }
}

/// BeginPaint's validation: the window's own update region goes, whole (its children keep
/// theirs).
pub fn begin_validate(windows: &mut Windows, window: WindowId) {
    take_out(windows, window, None);
}

/// UpdateWindow: a WM_PAINT sent to the window when its update region is not empty, through the
/// session as the window manager's sends go.
pub fn update_window(s: &mut dyn Session, window: WindowId) {
    if update_of(s.windows(), window).is_some() {
        s.send(
            window,
            &mut Message {
                message: WM_PAINT,
                wparam: 0,
                lparam: 0,
                payload: Payload::None,
            },
        );
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
    use crate::win32k::window::Session;
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

    /// The region a caller's handle names, copied; none for a null handle.
    fn read_region(call: &mut NtCall, region: Handle) -> Result<Option<OwnedRegion>, NtStatus> {
        if region.raw() == 0 {
            return Ok(None);
        }
        crate::win32k::region::copy_of(call, region).map(Some)
    }

    /// NtUserInvalidateRgn(Window, Region, Erase): see [`invalidate_region`]; a null window is
    /// [`invalidate_all`]'s, as InvalidateRect's.
    pub fn invalidate_rgn(
        call: &mut NtCall,
        window: Handle,
        region: Handle,
        erase: bool,
    ) -> NtResult {
        let caller = gui_thread(call)?.thread;
        let region = read_region(call, region)?;
        with_manager(call.passive(), |m| {
            if window.raw() == 0 {
                invalidate_all(&mut m.windows, caller, erase);
                return Ok::<_, NtStatus>(());
            }
            let id = window_of(&m.windows, window)?;
            invalidate_region(
                &mut m.windows,
                id,
                region.as_ref().map(OwnedRegion::rects),
                erase,
            );
            Ok(())
        })?;
        Ok(STATUS_SUCCESS)
    }

    /// NtUserCallHwndParamLock's ValidateRgn(Window, Region): see [`validate_region`]; a null
    /// window is
    /// [`invalidate_all`]'s, as ValidateRect's.
    pub fn validate_rgn(call: &mut NtCall, window: Handle, region: Handle) -> NtResult {
        let caller = gui_thread(call)?.thread;
        let region = read_region(call, region)?;
        with_manager(call.passive(), |m| {
            if window.raw() == 0 {
                invalidate_all(&mut m.windows, caller, true);
                return Ok::<_, NtStatus>(());
            }
            let id = window_of(&m.windows, window)?;
            validate_region(&mut m.windows, id, region.as_ref().map(OwnedRegion::rects));
            Ok(())
        })?;
        Ok(STATUS_SUCCESS)
    }

    /// NtUserGetUpdateRgn(Window, Region, Erase, Result): see [`update_region`]; the region
    /// object made the copy, `Result` the region's complexity in its low half and [`UPDATE_ERASE`]
    /// in its high half.
    pub fn get_update_rgn(
        call: &mut NtCall,
        window: Handle,
        region: Handle,
        erase: bool,
        result: UserPtr<u32>,
    ) -> NtResult {
        gui_thread(call)?;
        let (copy, bits) = with_manager(call.passive(), |m| {
            let id = window_of(&m.windows, window)?;
            update_region(&mut m.windows, id, erase).ok_or(STATUS_NO_MEMORY)
        })?;
        crate::win32k::region::assign(call, region, &copy)?;
        let complexity = copy.complexity() as u32 & 0xFFFF;
        result.write(complexity | ((bits & UPDATE_ERASE) << 16))?;
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
    /// erase the pending one, its rcPaint the region's box; the window validated, the caller's
    /// caret taken off the screen when the paint covers it ([`crate::win32k::caret`]). The DC is
    /// made before the window is validated, and closed again when the PAINTSTRUCT cannot be
    /// written.
    pub fn begin_paint(call: &mut NtCall, window: Handle, paint: UserAddr) -> NtResult {
        let caller = gui_thread(call)?.thread;
        let paint = paint.cast::<PaintStruct>();
        let area = with_manager(call.passive(), |m| {
            let id = window_of(&m.windows, window)?;
            Ok::<_, NtStatus>(paint_area(&m.windows, id))
        })?;
        let hdc = crate::win32k::dc::paint_dc(call, area.client, &area.update)?;
        with_manager(call.passive(), |m| {
            if let Some(id) = m.windows.window_from_handle(window.raw()) {
                begin_validate(&mut m.windows, id);
                crate::win32k::caret::paint_begins(&mut m.windows, caller, id);
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
    /// failure: EndPaint always succeeds once its arguments are read), the caller's caret put
    /// back on the screen when BeginPaint took it off.
    pub fn end_paint(call: &mut NtCall, window: Handle, paint: UserAddr) -> NtResult {
        let caller = gui_thread(call)?.thread;
        with_manager(call.passive(), |m| {
            window_of(&m.windows, window)?;
            crate::win32k::caret::paint_ends(&mut m.windows, caller);
            Ok::<_, NtStatus>(())
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
        crate::win32k::queue::with_session(call.passive(), |s| {
            let id = window_of(s.windows(), window)?;
            match routine {
                HWND_LOCK_UPDATE_WINDOW => {
                    update_window(s, id);
                    Ok(())
                }
                _ => crate::win32k::focus::call_hwnd_lock(s, caller, id, routine)
                    .unwrap_or(Err(STATUS_INVALID_PARAMETER)),
            }
        })?;
        Ok(STATUS_SUCCESS)
    }
}

#[cfg(target_arch = "x86")]
pub use services::validate_rgn;
pub use services::{
    begin_paint,
    call_hwnd_lock,
    end_paint,
    get_update_rect,
    get_update_rgn,
    invalidate_rect,
    invalidate_rgn,
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

    pub fn invalidate_rgn(_: &mut NtCall, _: Handle, _: Handle, _: bool) -> NtResult {
        Err(STATUS_NOT_IMPLEMENTED)
    }

    pub fn get_update_rgn(
        _: &mut NtCall,
        _: Handle,
        _: Handle,
        _: bool,
        _: UserPtr<u32>,
    ) -> NtResult {
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
    use rtl::gdi::COMPLEXREGION;
    use rtl::user::{WS_CHILD, WS_CLIPCHILDREN, WS_POPUP};

    use super::*;
    use crate::win32k::class;
    use crate::win32k::queue::rig::*;
    use crate::win32k::queue::{QueueSession, Taken};
    use crate::win32k::window::WindowManager;

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

    /// More windows with update regions than the old fixed table's 256: each keeps its region,
    /// and the WM_PAINT search goes in the order the regions' records were taken, a freed record
    /// taken again before any other, as the table took them.
    #[test]
    fn update_regions_grow_past_the_old_table() {
        let (m, atom) = manager();
        let t = thread(m, 1, 0x100);
        let windows: Vec<_> = (0..300).map(|i| shown(m, atom, t, i, 0)).collect();
        for &(w, _) in windows.iter().rev() {
            invalidate(&mut m.windows, w, None, false);
        }
        assert_eq!(m.windows.queues.updates.live(), 300);
        assert!(windows
            .iter()
            .all(|&(w, _)| update_of(&m.windows, w).is_some()));
        assert_eq!(next_paint(&m.windows, t, &all()), Some(windows[299].1));
        // The first record and one in the middle go; the next region takes the first.
        validate(&mut m.windows, windows[299].0, None);
        validate(&mut m.windows, windows[10].0, None);
        assert_eq!(next_paint(&m.windows, t, &all()), Some(windows[298].1));
        invalidate(&mut m.windows, windows[10].0, None, false);
        assert_eq!(next_paint(&m.windows, t, &all()), Some(windows[10].1));
        assert_eq!(m.windows.queues.updates.live(), 299);
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
        invalidate(&mut m.windows, w, Some(Rect::new(10, 10, 50, 40)), true);
        assert_eq!(update_rect(&mut m.windows, w, false), (Rect::EMPTY, 0));
        validate(&mut m.windows, w, None);
        assert_eq!(
            paint_area(&m.windows, w),
            PaintArea {
                paint: Rect::EMPTY,
                erase: false,
                update: OwnedRegion::empty(),
                client: m.windows.client_rect(w),
            }
        );
        assert_eq!(read(m, t, &all(), 0), Taken::Nothing { due: None });
    }

    /// guimsg `redraw`: WM_SETREDRAW FALSE clears the window's WS_VISIBLE, and an invalidation then
    /// adds nothing (UpdateWindow sends no WM_PAINT); TRUE sets it again and invalidates nothing,
    /// so only a new invalidation makes a WM_PAINT.
    #[test]
    fn a_window_whose_redraw_is_off_takes_no_update_region() {
        let (m, atom) = manager();
        let t = thread(m, 1, 0x100);
        let (w, h) = shown(m, atom, t, 0, 0);
        m.windows.set_redraw(w, false);
        assert!(!m.windows.is_window_visible(w));
        invalidate(&mut m.windows, w, None, true);
        assert_eq!(update_rect(&mut m.windows, w, false), (Rect::EMPTY, 0));
        m.windows.set_redraw(w, true);
        assert!(m.windows.is_window_visible(w));
        assert_eq!(update_rect(&mut m.windows, w, false), (Rect::EMPTY, 0));
        assert_eq!(read(m, t, &all(), 0), Taken::Nothing { due: None });
        invalidate(&mut m.windows, w, None, true);
        let paint = msg_of(read(m, t, &all(), 0));
        assert_eq!((paint.hwnd, paint.message), (h, WM_PAINT));
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
            (Rect::new(0, 0, 320, 200), UPDATE_NOT_EMPTY)
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
                paint: Rect::new(0, 0, 320, 200),
                erase: true,
                update: OwnedRegion::rect(Rect::new(0, 0, 320, 200)),
                client: Rect::new(30, 40, 350, 240),
            }
        );
        assert_eq!(
            update_rect(&mut m.windows, w, true),
            (Rect::new(0, 0, 320, 200), UPDATE_NOT_EMPTY | UPDATE_ERASE)
        );
        assert_eq!(
            update_rect(&mut m.windows, w, true),
            (Rect::new(0, 0, 320, 200), UPDATE_NOT_EMPTY),
            "the erase is handed out once"
        );
        begin_validate(&mut m.windows, w);
        assert_eq!(update_rect(&mut m.windows, w, false), (Rect::EMPTY, 0));
        assert_eq!(read(m, t, &all(), 0), Taken::Nothing { due: None });
    }

    /// The subrect capture's rectangle on a shown window: the update region is the rectangle; a
    /// validation of it leaves none; two rectangles make a region of both, not their box, and a
    /// validation takes out exactly what it covers (the box shrinks to what is left; a hole in
    /// the middle leaves the box whole); an invalidation outside the client area adds nothing.
    #[test]
    fn a_subrectangle_is_added_and_taken_out() {
        let (m, atom) = manager();
        let t = thread(m, 1, 0x100);
        let (w, _) = shown(m, atom, t, 0, 0);
        let sub = Rect::new(10, 10, 50, 40);
        invalidate(&mut m.windows, w, Some(sub), false);
        assert_eq!(
            update_rect(&mut m.windows, w, true),
            (sub, UPDATE_NOT_EMPTY)
        );
        validate(&mut m.windows, w, Some(sub));
        assert_eq!(update_rect(&mut m.windows, w, false), (Rect::EMPTY, 0));

        invalidate(&mut m.windows, w, Some(sub), false);
        invalidate(
            &mut m.windows,
            w,
            Some(Rect::new(100, 100, 120, 110)),
            false,
        );
        assert_eq!(
            update_rect(&mut m.windows, w, false).0,
            Rect::new(10, 10, 120, 110)
        );
        assert_eq!(
            update_region_of(&m.windows, w).unwrap().rects(),
            [sub, Rect::new(100, 100, 120, 110)]
        );
        validate(&mut m.windows, w, Some(Rect::new(0, 0, 60, 200)));
        assert_eq!(
            update_rect(&mut m.windows, w, false).0,
            Rect::new(100, 100, 120, 110)
        );
        validate(&mut m.windows, w, Some(Rect::new(105, 102, 110, 104)));
        assert_eq!(
            update_rect(&mut m.windows, w, false).0,
            Rect::new(100, 100, 120, 110)
        );
        assert_eq!(
            update_region_of(&m.windows, w).unwrap().complexity(),
            COMPLEXREGION
        );
        validate(&mut m.windows, w, None);

        invalidate(&mut m.windows, w, Some(Rect::new(400, 0, 500, 50)), false);
        assert_eq!(update_rect(&mut m.windows, w, false), (Rect::EMPTY, 0));
        invalidate(&mut m.windows, w, Some(Rect::new(-10, -10, 5, 5)), false);
        assert_eq!(
            update_rect(&mut m.windows, w, false).0,
            Rect::new(0, 0, 5, 5),
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
        invalidate(
            &mut m.windows,
            parent,
            Some(Rect::new(110, 60, 300, 200)),
            true,
        );
        assert_eq!(
            update_rect(&mut m.windows, child, false).0,
            Rect::new(10, 10, 40, 30)
        );
        assert_eq!(update_rect(&mut m.windows, hidden, false), (Rect::EMPTY, 0));
        begin_validate(&mut m.windows, parent);
        assert_eq!(
            update_rect(&mut m.windows, child, false).1,
            UPDATE_NOT_EMPTY
        );
        validate(&mut m.windows, parent, None);
        assert_eq!(update_rect(&mut m.windows, child, false), (Rect::EMPTY, 0));

        let clipping = window_at(m, atom, t, WS_POPUP | WS_CLIPCHILDREN, 0, 0, 0, 100, 100);
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
        assert_eq!(update_rect(&mut m.windows, inner, false), (Rect::EMPTY, 0));
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
        let mut update = |m: &mut WindowManager| {
            let WindowManager {
                windows, classes, ..
            } = m;
            update_window(&mut QueueSession::new(windows, classes), w);
        };
        update(m);
        assert_eq!(deliver(m, t), vec![]);
        invalidate(&mut m.windows, w, None, true);
        update(m);
        assert_eq!(deliver(m, t), vec![(h, WM_PAINT)]);
    }

    /// A window's update region goes with the window; a WM_PAINT is made only for the filter's
    /// window. The window under the one destroyed is uncovered: its whole client area is to be
    /// painted, and only it.
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
        Windows::destroy_window_handle(&mut QueueSession::new(windows, classes), t, h).unwrap();
        deliver(m, t);
        assert_eq!(
            update_of(&m.windows, other),
            Some((Rect::new(0, 0, 320, 200), true))
        );
        validate(&mut m.windows, other, None);
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
            (Rect::new(0, 0, 320, 200), UPDATE_NOT_EMPTY | UPDATE_ERASE)
        );
        assert_eq!(update_rect(&mut m.windows, hidden, false), (Rect::EMPTY, 0));
    }

    /// InvalidateRect of a rectangle at i32's end, of a window away from the screen's origin:
    /// the rectangle, moved onto the screen saturated, is outside the client area; nothing is
    /// invalid.
    #[test]
    fn a_rectangle_at_i32s_end_invalidates_nothing() {
        let (m, atom) = manager();
        let t = thread(m, 1, 0x100);
        let (w, _) = shown(m, atom, t, 30, 40);
        let far = Rect::new(i32::MAX - 10, i32::MAX - 10, i32::MAX, i32::MAX);
        invalidate(&mut m.windows, w, Some(far), true);
        assert_eq!(update_rect(&mut m.windows, w, false), (Rect::EMPTY, 0));
        validate(&mut m.windows, w, Some(far));
    }

    /// A window moved to i32's start invalidated whole: its update region is its client area, in
    /// its own coordinates, exact.
    #[test]
    fn a_window_at_i32s_start_is_invalidated_whole() {
        let (m, atom) = manager();
        let t = thread(m, 1, 0x100);
        let (w, h) = shown(m, atom, t, 0, 0);
        let min = i32::MIN;
        assert_eq!(
            WindowManager::move_window(
                &mut QueueSession::new(&mut m.windows, &mut m.classes),
                h,
                min,
                min,
                320,
                200,
                false
            ),
            Ok(())
        );
        invalidate(&mut m.windows, w, None, true);
        assert_eq!(
            update_rect(&mut m.windows, w, false),
            (Rect::new(0, 0, 320, 200), UPDATE_NOT_EMPTY)
        );
        validate(&mut m.windows, w, Some(Rect::new(0, 0, 320, 100)));
        assert_eq!(
            update_rect(&mut m.windows, w, false),
            (Rect::new(0, 100, 320, 200), UPDATE_NOT_EMPTY)
        );
    }

    /// The regions capture's `update` section on a 64x48 window: a region invalidated is the
    /// update region; a second one makes the union (COMPLEXREGION); one past the client area is
    /// cut to it; NULL is the client area; an empty region adds nothing (no WM_PAINT); a region
    /// validated comes out exactly; BeginPaint's area is the region, its rcPaint the box.
    #[test]
    fn regions_invalidate_and_validate_exactly() {
        let (m, atom) = manager();
        let t = thread(m, 1, 0x100);
        let h = window_at(m, atom, t, WS_POPUP, 0, 0, 0, 64, 48);
        deliver(m, t);
        let w = m.windows.window_from_handle(h).unwrap();
        m.windows.set_visible_for_tests(w, true);
        let rects = |m: &WindowManager| update_region_of(&m.windows, w).map(|r| r.rects().to_vec());

        let a = [Rect::new(4, 4, 20, 12)];
        invalidate_region(&mut m.windows, w, Some(&a), false);
        assert_eq!(rects(m), Some(a.to_vec()));
        invalidate_region(&mut m.windows, w, Some(&[Rect::new(10, 8, 30, 30)]), false);
        let union = std::vec![
            Rect::new(4, 4, 20, 8),
            Rect::new(4, 8, 30, 12),
            Rect::new(10, 12, 30, 30),
        ];
        assert_eq!(rects(m), Some(union.clone()));
        let paint = paint_area(&m.windows, w);
        assert_eq!(paint.paint, Rect::new(4, 4, 30, 30));
        assert_eq!(paint.update.rects(), union.as_slice());

        validate_region(&mut m.windows, w, Some(&[Rect::new(4, 4, 20, 12)]));
        assert_eq!(
            rects(m),
            Some(std::vec![
                Rect::new(20, 8, 30, 12),
                Rect::new(10, 12, 30, 30)
            ])
        );
        validate(&mut m.windows, w, None);
        assert_eq!(rects(m), None);

        invalidate_region(&mut m.windows, w, Some(&[Rect::new(50, 40, 80, 60)]), false);
        assert_eq!(rects(m), Some(std::vec![Rect::new(50, 40, 64, 48)]));
        validate_region(&mut m.windows, w, None);
        invalidate_region(&mut m.windows, w, None, false);
        assert_eq!(rects(m), Some(std::vec![Rect::new(0, 0, 64, 48)]));
        validate(&mut m.windows, w, None);
        let _ = read(m, t, &all(), 0);
        invalidate_region(&mut m.windows, w, Some(&[]), false);
        assert_eq!(rects(m), None);
        assert_eq!(read(m, t, &all(), 0), Taken::Nothing { due: None });
        assert_eq!(
            update_region(&mut m.windows, w, false).map(|(r, bits)| (r.complexity(), bits)),
            Some((rtl::gdi::NULLREGION, 0))
        );
    }
}
