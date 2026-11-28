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
//! 2000's has none), and to its shown children's, unless it clips its children (WS_CLIPCHILDREN,
//! RedrawWindow's rule when it names neither RDW_ALLCHILDREN nor RDW_NOCHILDREN). A window that
//! does not clip its children draws over them (its DC is not cut by them: [`visible_region`]), so
//! a child its invalidation reaches is invalidated over its whole window rectangle: its client
//! part, its erase and its frame's painting (WM_NCPAINT, which BeginPaint sends first), whatever
//! the caller asked, as the redraw capture shows. The WM_PAINT search takes a parent before its
//! children, so they paint over what it painted. ValidateRect and ValidateRgn take out the same
//! way. A window with an update region (or a frame to paint, or RedrawWindow's internal paint)
//! makes a WM_PAINT when its thread's read finds nothing before it ([`super::queue::take`]); the
//! message stays until the window is validated. BeginPaint hands out a DC whose visible region is
//! the window's cut to the update region ([`super::dc::paint_dc`]), the region's box in the
//! PAINTSTRUCT's rcPaint, and validates the window; EndPaint releases the DC. GetUpdateRgn copies
//! the region into a region object.
//!
//! The erase: Windows 2000's BeginPaint (and GetUpdateRect, asked to erase) sends WM_ERASEBKGND
//! itself. Sending is the receiving thread's own work here ([`super::queue`]), so the services
//! report the pending erase instead — PAINTSTRUCT's fErase, GetUpdateRect's [`UPDATE_ERASE`] — and
//! user32 sends WM_ERASEBKGND with the DC, fErase then saying whether the procedure left it
//! undone. The frame alike: PAINTSTRUCT's fRestore, GetUpdateRect's [`UPDATE_FRAME`], and user32
//! sends WM_NCPAINT before the erase. UpdateWindow's WM_PAINTs (the window's, then its
//! descendants') are messages the window manager sends, queued for the window's thread as the
//! others are.
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
//! - NtUserCallHwndLock(handle Window, u32 Routine): UpdateWindow ([`HWND_LOCK_UPDATE_WINDOW`]);
//! - NtUserRedrawWindow(handle Window, ptr Rect, handle Region, u32 Flags): RedrawWindow
//!   ([`redraw`], [`update_window`]).

use rtl::gdi::Rect;
#[cfg(doc)]
use rtl::user::HWND_LOCK_UPDATE_WINDOW;
use rtl::user::{
    QS_PAINT,
    RDW_ALLCHILDREN,
    RDW_ERASE,
    RDW_FRAME,
    RDW_INTERNALPAINT,
    RDW_INVALIDATE,
    RDW_NOCHILDREN,
    RDW_NOERASE,
    RDW_NOFRAME,
    RDW_NOINTERNALPAINT,
    RDW_UPDATENOW,
    RDW_VALIDATE,
    UPDATE_ERASE,
    UPDATE_FRAME,
    UPDATE_NOT_EMPTY,
    WM_PAINT,
    WS_CHILD,
    WS_CLIPCHILDREN,
    WS_CLIPSIBLINGS,
    WS_VISIBLE,
};

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
    /// The frame is to be painted: BeginPaint's WM_NCPAINT, before the erase (the part of the
    /// update region over the non-client area, which F2K keeps as this flag alone).
    frame: bool,
    /// A WM_PAINT is due even with nothing to paint (RedrawWindow's RDW_INTERNALPAINT).
    internal: bool,
}

impl Update {
    const EMPTY: Self = Update {
        window: None,
        thread: ThreadId(0),
        region: OwnedRegion::empty(),
        erase: false,
        frame: false,
        internal: false,
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
/// the update region of the window, when it is shown, and of its shown children (see the module
/// notes), `erase` asking the window's background erased. Each thread given a region to paint is
/// woken.
pub fn invalidate(windows: &mut Windows, window: WindowId, rect: Option<Rect>, erase: bool) {
    match rect {
        Some(rect) => invalidate_region(windows, window, Some(rect_rects(&rect)), erase),
        None => invalidate_region(windows, window, None, erase),
    }
}

/// InvalidateRgn over a window: [`invalidate`] of the region `region` (banded rectangles, client
/// coordinates; the client area for none).
///
/// A child the area reaches is invalidated over its whole window rectangle, its frame and its
/// background included, whatever `erase` says: its parent's painting, which does not clip its
/// children, draws over all of it (the redraw capture: RedrawWindow's RDW_INVALIDATE over the whole
/// window, with or without RDW_ERASE, RDW_FRAME or RDW_NOFRAME, brings the child WM_NCPAINT,
/// WM_ERASEBKGND and WM_PAINT; a rectangle outside the child, nothing).
pub fn invalidate_region(
    windows: &mut Windows,
    window: WindowId,
    region: Option<&[Rect]>,
    erase: bool,
) {
    let flags = RDW_INVALIDATE | if erase { RDW_ERASE } else { 0 };
    redraw(windows, window, region, flags);
}

/// Whether a RedrawWindow of `flags` goes on from the window to its children: not with
/// RDW_NOCHILDREN; with RDW_ALLCHILDREN; otherwise unless the window clips its children.
fn redraw_reaches_children(windows: &Windows, window: WindowId, flags: u32) -> bool {
    flags & RDW_NOCHILDREN == 0
        && (flags & RDW_ALLCHILDREN != 0 || reaches_children(windows, window))
}

/// RedrawWindow's invalidations and validations over a window (its WM_PAINT sends, RDW_UPDATENOW,
/// and erases, RDW_ERASENOW, are the caller's): `region` (client coordinates; the client area for
/// none) and the window's children as RDW_NOCHILDREN, RDW_ALLCHILDREN and WS_CLIPCHILDREN say.
///
/// - RDW_INVALIDATE adds the area to the update region of the window, when it is shown, its erase
///   asked with RDW_ERASE, its frame's painting with RDW_FRAME over the whole window; a child the
///   area reaches is invalidated over its whole window rectangle, its frame and its erase asked
///   whatever the flags say when its parent does not clip it (see [`invalidate_region`]);
/// - RDW_INTERNALPAINT asks a WM_PAINT of each, even with nothing to paint;
/// - RDW_VALIDATE takes the area out (see [`validate_region`]), the pending erase with RDW_NOERASE,
///   the pending frame's painting with RDW_NOFRAME; RDW_NOINTERNALPAINT takes the internal paint
///   back.
///
/// The redraw capture's `redraw` block is each of these, flag by flag.
pub fn redraw(windows: &mut Windows, window: WindowId, region: Option<&[Rect]>, flags: u32) {
    if !is_shown(windows, window) {
        return;
    }
    let area = screen_region(windows, window, region);
    if flags & RDW_INVALIDATE != 0 && (!area.is_empty() || region.is_none()) {
        let whole_frame = flags & RDW_FRAME != 0 && region.is_none();
        walk(windows, window, |windows, w| {
            if w != window && windows.window_style(w) & WS_VISIBLE == 0 {
                return false;
            }
            let client = windows.client_rect(w);
            let part = client_part(area.rects(), client).unwrap_or_else(|| {
                let bounds = area.bounds().intersect(client);
                OwnedRegion::rect(bounds.saturating_offset_back(client.left, client.top))
            });
            if w == window {
                if !part.is_empty() || whole_frame {
                    add(windows, w, part, flags & RDW_ERASE != 0, whole_frame);
                }
            } else if reaches(area.rects(), windows.window_rect(w)) {
                let covered = windows
                    .parent_of(w)
                    .is_some_and(|p| reaches_children(windows, p));
                let erase = covered || flags & RDW_ERASE != 0;
                let frame = covered || flags & RDW_FRAME != 0;
                add(windows, w, part, erase, frame);
            }
            redraw_reaches_children(windows, w, flags)
        });
    }
    if flags & RDW_INTERNALPAINT != 0 {
        walk(windows, window, |windows, w| {
            if w != window && windows.window_style(w) & WS_VISIBLE == 0 {
                return false;
            }
            add(windows, w, OwnedRegion::empty(), false, false);
            if let Some(record) = windows.queues.updates.record_mut(w) {
                record.internal = true;
            }
            redraw_reaches_children(windows, w, flags)
        });
    }
    if flags & (RDW_VALIDATE | RDW_NOINTERNALPAINT) != 0 {
        walk(windows, window, |windows, w| {
            if flags & RDW_VALIDATE != 0 {
                validate_one(windows, window, w, &area, region.is_none());
                if let Some(record) = windows.queues.updates.record_mut(w) {
                    record.erase &= flags & RDW_NOERASE == 0;
                    record.frame &= flags & RDW_NOFRAME == 0;
                }
            }
            if flags & RDW_NOINTERNALPAINT != 0 {
                if let Some(record) = windows.queues.updates.record_mut(w) {
                    record.internal = false;
                }
            }
            drop_if_done(windows, w);
            redraw_reaches_children(windows, w, flags)
        });
    }
}

/// Whether the screen region `area` covers any of `rect`.
fn reaches(area: &[Rect], rect: Rect) -> bool {
    area.iter().any(|r| !r.intersect(rect).is_empty())
}

/// Whether the screen region `area` covers all of `rect` (false when the pool has no room to
/// tell).
fn covers(area: &[Rect], rect: Rect) -> bool {
    OwnedRegion::combined(rect_rects(&rect), area, |a, b| a && !b).is_some_and(|l| l.is_empty())
}

/// Add `part` (client coordinates; empty only with `frame`, or for an internal paint) to the
/// window's update region, its erase and its frame asked when `erase` and `frame` say.
fn add(windows: &mut Windows, window: WindowId, part: OwnedRegion, erase: bool, frame: bool) {
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
    if record.region.is_empty() {
        record.region = part;
    } else if !part.is_empty() {
        record.region = OwnedRegion::combined(record.region.rects(), part.rects(), |a, b| a || b)
            .unwrap_or_else(|| OwnedRegion::rect(record.region.bounds().union(part.bounds())));
    }
    record.erase |= erase;
    record.frame |= frame;
    windows.queues.wake_thread(thread, QS_PAINT);
}

/// ValidateRect over a window: `rect` (client coordinates; the whole region for none) taken out
/// of the update region of the window and of its children through their client areas (see the
/// module notes); a child whose whole window rectangle the area covers loses its frame's painting
/// too. A region left empty goes, and its erase with it.
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
        validate_one(windows, window, w, &area, region.is_none());
        drop_if_done(windows, w);
        reaches_children(windows, w)
    });
}

/// A validation's work on one window `w` of the walk from `window`: the screen region `area` taken
/// out of its update region; all of it (its frame's painting too) for the window itself when
/// `all`, and for a child whose whole window rectangle the area covers.
fn validate_one(
    windows: &mut Windows,
    window: WindowId,
    w: WindowId,
    area: &OwnedRegion,
    all: bool,
) {
    if all && w == window || w != window && covers(area.rects(), windows.window_rect(w)) {
        take_out(windows, w, None);
    } else if let Some(cut) = client_part(area.rects(), windows.client_rect(w)) {
        take_out(windows, w, Some(cut.rects()));
    }
}

/// The window's record freed when it is left with nothing to paint: no region, no frame, no
/// internal paint.
fn drop_if_done(windows: &mut Windows, window: WindowId) {
    let updates = &mut windows.queues.updates;
    if let Some(id) = updates.find(window) {
        if updates
            .records
            .get(id)
            .is_some_and(|u| u.region.is_empty() && !u.frame && !u.internal)
        {
            updates.free(id);
        }
    }
}

/// Take `cut` (client coordinates; everything, the erase and the frame's painting included, for
/// none) out of the window's update region; when the pool has no room for what is left, nothing is
/// taken out. A record left with nothing to paint goes ([`drop_if_done`]); an internal paint stays.
fn take_out(windows: &mut Windows, window: WindowId, cut: Option<&[Rect]>) {
    let updates = &mut windows.queues.updates;
    let Some(id) = updates.find(window) else {
        return;
    };
    let Some(record) = updates.records.get_mut(id) else {
        return;
    };
    match cut {
        None => {
            record.region = OwnedRegion::empty();
            record.erase = false;
            record.frame = false;
        }
        Some([]) => return,
        Some(cut) => match OwnedRegion::combined(record.region.rects(), cut, |a, b| a && !b) {
            Some(left) => record.region = left,
            None => return,
        },
    }
    drop_if_done(windows, window);
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

/// The pending painting GetUpdateRect and GetUpdateRgn hand to a caller that asks the erase
/// (Windows 2000's sends WM_NCPAINT and WM_ERASEBKGND then): [`UPDATE_FRAME`] when the frame was to
/// be painted, [`UPDATE_ERASE`] when an erase was pending over a region not empty; neither pending
/// any more. A record left with nothing to paint goes.
fn hand_over(windows: &mut Windows, window: WindowId) -> u32 {
    let Some(record) = windows.queues.updates.record_mut(window) else {
        return 0;
    };
    let mut bits = 0;
    if record.frame {
        record.frame = false;
        bits |= UPDATE_FRAME;
    }
    if record.erase && !record.region.is_empty() {
        record.erase = false;
        bits |= UPDATE_ERASE;
    }
    drop_if_done(windows, window);
    bits
}

/// GetUpdateRgn over a window: a copy of the update region (the empty region for none), and, when
/// `erase` asks it, what [`hand_over`] hands the caller; none when the pool has no room for the
/// copy.
pub fn update_region(
    windows: &mut Windows,
    window: WindowId,
    erase: bool,
) -> Option<(OwnedRegion, u32)> {
    let Some(record) = windows.queues.updates.record(window) else {
        return Some((OwnedRegion::empty(), 0));
    };
    let copy = record.region.duplicate()?;
    let mut bits = if copy.is_empty() { 0 } else { UPDATE_NOT_EMPTY };
    if erase {
        bits |= hand_over(windows, window);
    }
    Some((copy, bits))
}

/// GetUpdateRect over a window: the region's box (zeros for none) and the answer's bits —
/// [`UPDATE_NOT_EMPTY`] when the region is not empty (a window with its frame alone to paint has
/// nothing of its client area to report), and, when `erase` asks it, what [`hand_over`] hands the
/// caller.
pub fn update_rect(windows: &mut Windows, window: WindowId, erase: bool) -> (Rect, u32) {
    let Some(record) = windows.queues.updates.record(window) else {
        return (Rect::EMPTY, 0);
    };
    let bounds = record.region.bounds();
    let mut bits = if record.region.is_empty() {
        0
    } else {
        UPDATE_NOT_EMPTY
    };
    if erase {
        bits |= hand_over(windows, window);
    }
    (bounds, bits)
}

/// The next window of `thread`'s the filter takes a WM_PAINT for: one with an update region, its
/// outermost ancestor with one of `thread`'s the filter takes before it, so that a parent paints
/// before the children its painting covers (the redraw capture: the window's WM_PAINT, then the
/// child's).
pub fn next_paint(windows: &Windows, thread: ThreadId, filter: &Filter) -> Option<Hwnd> {
    let takes = |w: WindowId| {
        windows
            .queues
            .updates
            .record(w)
            .is_some_and(|u| u.thread == thread)
            && windows.is_live(w)
            && filter.takes_window(windows.handle_of(w))
    };
    let found = windows
        .queues
        .updates
        .records
        .iter()
        .map(|(_, u)| u)
        .filter(|u| u.thread == thread)
        .filter_map(|u| u.window)
        .find(|&w| takes(w))?;
    let mut best = found;
    let mut at = windows.parent_of(found);
    while let Some(w) = at {
        if !windows.is_live(w) {
            break;
        }
        if takes(w) {
            best = w;
        }
        at = windows.parent_of(w);
    }
    Some(windows.handle_of(best))
}

/// What BeginPaint paints: the region's box in client coordinates (zeros for none), whether the
/// erase is pending (never over nothing: the redraw capture's `lock`, a WM_PAINT of an empty
/// rcPaint has no WM_ERASEBKGND before it), whether the frame is to be painted first (WM_NCPAINT),
/// the update region its DC's visible region is cut to (client coordinates, within the client
/// area), the client area on the screen (the DC's origin its top left), and the window's visible
/// region the DC is cut to as well ([`visible_region`], screen coordinates).
#[derive(Debug, PartialEq, Eq)]
pub struct PaintArea {
    pub paint: Rect,
    pub erase: bool,
    pub frame: bool,
    pub update: OwnedRegion,
    pub client: Rect,
    pub visible: OwnedRegion,
}

/// BeginPaint's look at the window, before its DC is made: see [`PaintArea`]. When the pool has
/// no room for the region's copy, the DC is cut to its box.
pub fn paint_area(windows: &Windows, window: WindowId) -> PaintArea {
    let client = windows.client_rect(window);
    let local = Rect::new(0, 0, client.width(), client.height());
    let record = windows.queues.updates.record(window);
    let frame = record.is_some_and(|u| u.frame);
    let update = match update_region_of(windows, window) {
        None => OwnedRegion::empty(),
        Some(region) => OwnedRegion::combined(region.rects(), rect_rects(&local), |a, b| a && b)
            .unwrap_or_else(|| OwnedRegion::rect(region.bounds().intersect(local))),
    };
    let erase = record.is_some_and(|u| u.erase) && !update.is_empty();
    PaintArea {
        paint: update.bounds(),
        erase,
        frame,
        update,
        client,
        visible: visible_region(windows, window, Clipping::style(windows, window, false)),
    }
}

/// BeginPaint's validation: the window's own update region goes, whole, its internal paint too
/// (its children keep theirs).
pub fn begin_validate(windows: &mut Windows, window: WindowId) {
    if let Some(id) = windows.queues.updates.find(window) {
        windows.queues.updates.free(id);
    }
}

/// UpdateWindow: a WM_PAINT sent to the window when it has an update region, then to each of its
/// descendants of the same thread that has one, parents before children, through the session as
/// the window manager's sends go (the redraw capture: RDW_UPDATENOW paints the window, then the
/// child, before it returns); the window alone without `children` (RDW_NOCHILDREN). A window a
/// procedure destroys meanwhile ends the walk.
pub fn update_window(s: &mut dyn Session, window: WindowId, children: bool) {
    let thread = s.windows().window_thread(window);
    let mut at = window;
    loop {
        let windows = s.windows();
        if !windows.is_live(at) {
            return;
        }
        if update_of(windows, at).is_some() && (at == window || windows.window_thread(at) == thread)
        {
            s.send(
                at,
                &mut Message {
                    message: WM_PAINT,
                    wparam: 0,
                    lparam: 0,
                    payload: Payload::None,
                },
            );
        }
        let windows = s.windows();
        if !windows.is_live(at) || !windows.is_live(window) || !children {
            return;
        }
        // The next window, parents before children.
        if let Some(child) = windows.first_child(at) {
            at = child;
            continue;
        }
        loop {
            if at == window {
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

/// The window's frame to be painted when it shows anew (SetWindowPos's show, size or frame
/// change): true when it is painted now, by the caller's WM_NCPAINT; false when an ancestor whose
/// painting draws over it has an update region still to paint, the frame's painting then left to
/// the window's own WM_PAINT, after that ancestor's (Windows 2000 holds back such a window's
/// synchronous painting while its parent needs painting: the parent's erase would cover it).
pub fn frame_now(windows: &mut Windows, window: WindowId) -> bool {
    let mut at = window;
    let mut covered = false;
    while let Some(parent) = windows.parent_of(at) {
        if !windows.is_live(parent) || windows.window_style(at) & WS_CHILD == 0 {
            break;
        }
        if windows.window_style(parent) & WS_CLIPCHILDREN == 0
            && update_region_of(windows, parent).is_some_and(|r| !r.is_empty())
        {
            covered = true;
            break;
        }
        at = parent;
    }
    if !covered {
        return true;
    }
    add(windows, window, OwnedRegion::empty(), false, true);
    false
}

// --- Visible regions -----------------------------------------------------------------------------

/// What a window's DC is clipped by beyond its area: GetDCEx's DCX_CLIPCHILDREN and
/// DCX_CLIPSIBLINGS, the window's WS_CLIPCHILDREN and WS_CLIPSIBLINGS for DCX_USESTYLE (GetDC's,
/// GetWindowDC's and BeginPaint's), and whether the DC is of the window rectangle (DCX_WINDOW).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Clipping {
    pub whole: bool,
    pub children: bool,
    pub siblings: bool,
}

impl Clipping {
    /// The window's own clipping (DCX_USESTYLE): its WS_CLIPCHILDREN and WS_CLIPSIBLINGS.
    pub fn style(windows: &Windows, window: WindowId, whole: bool) -> Clipping {
        let style = windows.window_style(window);
        Clipping {
            whole,
            children: style & WS_CLIPCHILDREN != 0,
            siblings: style & WS_CLIPSIBLINGS != 0,
        }
    }
}

/// The window's visible region, screen coordinates: its client area (its window rectangle with
/// `clip.whole`) within each ancestor's client area, less
///
/// - its shown children's window rectangles, with `clip.children` (WS_CLIPCHILDREN): without it the
///   parent draws over its children, which paint again after it ([`invalidate_region`]);
/// - its shown siblings' above it, with `clip.siblings` (WS_CLIPSIBLINGS), and each ancestor's
///   shown siblings above it when that ancestor has WS_CLIPSIBLINGS, up to the top-level window.
///
/// Top-level windows are not cut by one another: F2K repaints nothing a z-order change uncovers
/// yet, so a window raised over another must draw all of itself. When the pool has no room for a
/// cut, the region is left without it (the window may draw more than it should, never less).
pub fn visible_region(windows: &Windows, window: WindowId, clip: Clipping) -> OwnedRegion {
    let (desktop, message) = windows.desktop_roots(window);
    let own = if clip.whole {
        windows.window_rect(window)
    } else {
        windows.client_rect(window)
    };
    // The area within every ancestor's client area.
    let mut area = own;
    let mut at = window;
    while let Some(parent) = windows.parent_of(at) {
        if Some(parent) == desktop
            || Some(parent) == message
            || windows.window_style(at) & WS_CHILD == 0
        {
            break;
        }
        area = area.intersect(windows.client_rect(parent));
        at = parent;
    }
    let mut region = OwnedRegion::rect(area);
    let cut = |region: &mut OwnedRegion, rect: Rect| {
        if region.is_empty() || rect.intersect(region.bounds()).is_empty() {
            return;
        }
        if let Some(left) = OwnedRegion::combined(region.rects(), rect_rects(&rect), |a, b| a && !b)
        {
            *region = left;
        }
    };
    if clip.children {
        let mut child = windows.first_child(window);
        while let Some(c) = child {
            if windows.window_style(c) & WS_VISIBLE != 0 {
                cut(&mut region, windows.window_rect(c));
            }
            child = windows.next_sibling(c);
        }
    }
    let mut at = window;
    let mut siblings = clip.siblings;
    while let Some(parent) = windows.parent_of(at) {
        if Some(parent) == desktop
            || Some(parent) == message
            || windows.window_style(at) & WS_CHILD == 0
        {
            break;
        }
        if siblings {
            let mut above = windows.first_child(parent);
            while let Some(s) = above {
                if s == at {
                    break;
                }
                if windows.window_style(s) & WS_VISIBLE != 0 {
                    cut(&mut region, windows.window_rect(s));
                }
                above = windows.next_sibling(s);
            }
        }
        at = parent;
        siblings = windows.window_style(at) & WS_CLIPSIBLINGS != 0;
    }
    region
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
    /// and [`UPDATE_FRAME`] in its high half.
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
        result.write(complexity | ((bits & (UPDATE_ERASE | UPDATE_FRAME)) << 16))?;
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

    /// NtUserBeginPaint(Window, Paint): the PAINTSTRUCT, its DC clipped to the update region and
    /// the window's visible region, its erase the pending one, its rcPaint the region's box, its
    /// fRestore 1 when the frame is to be painted first (user32 sends WM_NCPAINT and clears it);
    /// the window validated, the caller's caret taken off the screen when the paint covers it
    /// ([`crate::win32k::caret`]). The DC is made before the window is validated, and closed again
    /// when the PAINTSTRUCT cannot be written.
    pub fn begin_paint(call: &mut NtCall, window: Handle, paint: UserAddr) -> NtResult {
        let caller = gui_thread(call)?.thread;
        let paint = paint.cast::<PaintStruct>();
        let area = with_manager(call.passive(), |m| {
            let id = window_of(&m.windows, window)?;
            Ok::<_, NtStatus>(paint_area(&m.windows, id))
        })?;
        let hdc = crate::win32k::dc::paint_dc(call, area.client, &area.update, &area.visible)?;
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
            restore: area.frame as i32,
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

    /// NtUserRedrawWindow(Window, Rect, Region, Flags): see [`redraw`] (the rectangle, client
    /// coordinates, when given; the region otherwise; the client area for neither), then, with
    /// RDW_UPDATENOW, [`update_window`] (the window alone with RDW_NOCHILDREN). A null window is
    /// the caller's desktop window. RDW_ERASENOW's erase is user32's.
    pub fn redraw_window(
        call: &mut NtCall,
        window: Handle,
        rect: UserAddr,
        region: Handle,
        flags: u32,
    ) -> NtResult {
        let caller = gui_thread(call)?.thread;
        let rect = read_rect(rect)?;
        let region = match rect {
            Some(_) => None,
            None => read_region(call, region)?,
        };
        crate::win32k::queue::with_session(call.passive(), |s| {
            let id = if window.raw() == 0 {
                s.windows()
                    .thread_desktop_window(caller)
                    .ok_or(STATUS_INVALID_HANDLE)?
            } else {
                window_of(s.windows(), window)?
            };
            let rects = match (&rect, &region) {
                (Some(rect), _) => Some(rect_rects(rect)),
                (None, Some(region)) => Some(region.rects()),
                (None, None) => None,
            };
            redraw(s.windows(), id, rects, flags);
            if flags & RDW_UPDATENOW != 0 {
                update_window(s, id, flags & RDW_NOCHILDREN == 0);
            }
            Ok::<_, NtStatus>(())
        })?;
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
                    update_window(s, id, true);
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
    redraw_window,
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

    pub fn redraw_window(_: &mut NtCall, _: Handle, _: UserAddr, _: Handle, _: u32) -> NtResult {
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
                frame: false,
                update: OwnedRegion::empty(),
                client: m.windows.client_rect(w),
                visible: OwnedRegion::rect(m.windows.client_rect(w)),
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
        assert!(m.windows.queues.take_wakes().contains(t));
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
                frame: false,
                update: OwnedRegion::rect(Rect::new(0, 0, 320, 200)),
                client: Rect::new(30, 40, 350, 240),
                visible: OwnedRegion::rect(Rect::new(30, 40, 350, 240)),
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
            update_window(&mut QueueSession::new(windows, classes), w, true);
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

    /// A shown child of `parent` (a handle) at (`x`, `y`) in its client area, `cx` by `cy`, with
    /// `style` besides WS_CHILD and a frame `inset` wide: its id.
    #[allow(clippy::too_many_arguments)]
    fn child_of(
        m: &mut WindowManager,
        atom: class::Atom,
        t: ThreadId,
        parent: Hwnd,
        style: u32,
        (x, y, cx, cy): (i32, i32, i32, i32),
        inset: i32,
    ) -> WindowId {
        let h = window_at(m, atom, t, WS_CHILD | style, parent, x, y, cx, cy);
        deliver(m, t);
        let w = m.windows.window_from_handle(h).unwrap();
        m.windows.set_visible_for_tests(w, true);
        m.windows.set_frame_for_tests(w, inset);
        w
    }

    /// The redraw capture's `redraw`: an invalidation of the parent that reaches a child brings
    /// the child its frame's painting and its erase whatever the parent's erase says
    /// (RDW_INVALIDATE alone: the child's WM_NCPAINT, WM_ERASEBKGND, WM_PAINT); a rectangle outside
    /// the child reaches nothing; one over the child's frame alone leaves the child a WM_PAINT with
    /// an empty rcPaint, no erase, its frame painted, and GetUpdateRect and GetUpdateRgn see
    /// nothing.
    #[test]
    fn a_parents_invalidation_paints_its_childrens_frames() {
        let (m, atom) = manager();
        let t = thread(m, 1, 0x100);
        let (parent, ph) = shown(m, atom, t, 0, 0);
        let child = child_of(m, atom, t, ph, 0, (100, 50, 40, 30), 2);
        let child_h = m.windows.handle_of(child);

        invalidate(
            &mut m.windows,
            parent,
            Some(Rect::new(200, 100, 300, 200)),
            false,
        );
        assert_eq!(
            update_of(&m.windows, child),
            None,
            "a rectangle outside the child"
        );
        assert_eq!(
            update_of(&m.windows, parent),
            Some((Rect::new(200, 100, 300, 200), false))
        );
        validate(&mut m.windows, parent, None);

        invalidate(&mut m.windows, parent, None, false);
        let area = paint_area(&m.windows, child);
        assert_eq!(
            (area.paint, area.erase, area.frame),
            (Rect::new(0, 0, 36, 26), true, true)
        );
        assert!(
            !paint_area(&m.windows, parent).frame,
            "the parent's own frame is not asked"
        );
        validate(&mut m.windows, parent, None);
        assert_eq!(
            update_of(&m.windows, child),
            None,
            "the parent's validation takes it all"
        );

        // The child's frame alone: its top-left corner, the frame's two pixels.
        invalidate(
            &mut m.windows,
            parent,
            Some(Rect::new(90, 40, 101, 51)),
            true,
        );
        assert_eq!(update_rect(&mut m.windows, child, false), (Rect::EMPTY, 0));
        assert_eq!(
            update_region(&mut m.windows, child, false).map(|(r, b)| (r.is_empty(), b)),
            Some((true, 0))
        );
        let area = paint_area(&m.windows, child);
        assert_eq!(
            (area.paint, area.erase, area.frame),
            (Rect::EMPTY, false, true)
        );
        begin_validate(&mut m.windows, parent);
        let paint = msg_of(read(m, t, &all(), 0));
        assert_eq!((paint.hwnd, paint.message), (child_h, WM_PAINT));
        begin_validate(&mut m.windows, child);
        assert_eq!(read(m, t, &all(), 0), Taken::Nothing { due: None });

        // GetUpdateRect asked to erase hands the frame over (WM_NCPAINT, as Windows 2000's sends
        // it), and the erase only over a region not empty; nothing is left to paint then.
        invalidate(
            &mut m.windows,
            parent,
            Some(Rect::new(90, 40, 101, 51)),
            true,
        );
        assert_eq!(
            update_rect(&mut m.windows, child, true),
            (Rect::EMPTY, UPDATE_FRAME)
        );
        assert_eq!(update_of(&m.windows, child), None);
        invalidate(&mut m.windows, parent, None, false);
        assert_eq!(
            update_rect(&mut m.windows, child, true),
            (
                Rect::new(0, 0, 36, 26),
                UPDATE_NOT_EMPTY | UPDATE_ERASE | UPDATE_FRAME
            )
        );
        assert_eq!(
            update_of(&m.windows, child),
            Some((Rect::new(0, 0, 36, 26), false))
        );
    }

    /// The WM_PAINT search takes a parent before its child, however their records were taken (the
    /// redraw capture: the window's WM_PAINT, then the child's).
    #[test]
    fn a_parent_paints_before_its_child() {
        let (m, atom) = manager();
        let t = thread(m, 1, 0x100);
        let (parent, ph) = shown(m, atom, t, 0, 0);
        let child = child_of(m, atom, t, ph, 0, (10, 10, 40, 30), 0);
        invalidate(&mut m.windows, child, None, true);
        invalidate(&mut m.windows, parent, None, true);
        assert_eq!(next_paint(&m.windows, t, &all()), Some(ph));
        begin_validate(&mut m.windows, parent);
        assert_eq!(
            next_paint(&m.windows, t, &all()),
            Some(m.windows.handle_of(child))
        );
    }

    /// A child shown while its parent, which does not clip its children, has an update region:
    /// its frame is left to its WM_PAINT, after the parent's; with WS_CLIPCHILDREN, or nothing for
    /// the parent to paint, it is painted at once.
    #[test]
    fn a_childs_frame_waits_for_its_parents_painting() {
        let (m, atom) = manager();
        let t = thread(m, 1, 0x100);
        let (parent, ph) = shown(m, atom, t, 0, 0);
        let child = child_of(m, atom, t, ph, 0, (10, 10, 40, 30), 2);
        assert!(
            frame_now(&mut m.windows, child),
            "nothing for the parent to paint"
        );
        invalidate(&mut m.windows, parent, Some(Rect::new(0, 0, 5, 5)), true);
        assert!(!frame_now(&mut m.windows, child));
        assert!(paint_area(&m.windows, child).frame);

        let ch = window_at(m, atom, t, WS_POPUP | WS_CLIPCHILDREN, 0, 0, 0, 320, 200);
        deliver(m, t);
        let clipping = m.windows.window_from_handle(ch).unwrap();
        m.windows.set_visible_for_tests(clipping, true);
        let inner = child_of(m, atom, t, ch, 0, (10, 10, 40, 30), 2);
        invalidate(&mut m.windows, clipping, None, true);
        assert!(frame_now(&mut m.windows, inner));
        assert_eq!(update_of(&m.windows, inner), None);
    }

    /// The visible regions: a window's client area within its parent's client area; less its
    /// shown children only with WS_CLIPCHILDREN (DCX_CLIPCHILDREN); less its shown siblings
    /// above it only with WS_CLIPSIBLINGS, never those below; top-level windows not cut by one
    /// another; a window DC's (DCX_WINDOW) its whole rectangle.
    #[test]
    fn visible_regions_follow_the_clipping_styles() {
        let (m, atom) = manager();
        let t = thread(m, 1, 0x100);
        let (parent, ph) = shown(m, atom, t, 0, 0);
        // Created first: the top of the z-order, above `lower` (a new child goes under its
        // siblings, as a dialog's controls go, the first at the top).
        let upper = child_of(m, atom, t, ph, WS_CLIPSIBLINGS, (60, 30, 100, 50), 2);
        let lower = child_of(m, atom, t, ph, WS_CLIPSIBLINGS, (10, 10, 100, 50), 2);
        assert_eq!(m.windows.first_child(parent), Some(upper));
        let hidden = child_of(m, atom, t, ph, 0, (200, 100, 20, 20), 0);
        m.windows.set_visible_for_tests(hidden, false);
        shown(m, atom, t, 100, 0);
        let vis = |m: &WindowManager, w, clip| visible_region(&m.windows, w, clip).rects().to_vec();
        let plain = |whole| Clipping {
            whole,
            children: false,
            siblings: false,
        };

        assert_eq!(vis(m, parent, plain(false)), [Rect::new(0, 0, 320, 200)]);
        assert_eq!(
            vis(
                m,
                parent,
                Clipping {
                    children: true,
                    ..plain(false)
                }
            ),
            [
                Rect::new(0, 0, 320, 10),
                Rect::new(0, 10, 10, 30),
                Rect::new(110, 10, 320, 30),
                Rect::new(0, 30, 10, 60),
                Rect::new(160, 30, 320, 60),
                Rect::new(0, 60, 60, 80),
                Rect::new(160, 60, 320, 80),
                Rect::new(0, 80, 320, 200),
            ],
            "the shown children's window rectangles, not the hidden one's"
        );
        assert_eq!(
            vis(m, parent, Clipping::style(&m.windows, parent, false)),
            [Rect::new(0, 0, 320, 200)],
            "a top-level window: WS_CLIPSIBLINGS, but not cut by the other top-level window"
        );
        assert_eq!(
            vis(m, lower, Clipping::style(&m.windows, lower, false)),
            [Rect::new(12, 12, 108, 30), Rect::new(12, 30, 60, 58)],
            "the lower child's client area less the upper one"
        );
        assert_eq!(
            vis(m, lower, plain(false)),
            [Rect::new(12, 12, 108, 58)],
            "without WS_CLIPSIBLINGS"
        );
        assert_eq!(
            vis(m, upper, Clipping::style(&m.windows, upper, true)),
            [Rect::new(60, 30, 160, 80)],
            "the upper child's window rectangle: nothing above it"
        );
        // A child past its parent's client area is cut to it.
        let past = child_of(m, atom, t, ph, 0, (300, 190, 50, 50), 0);
        assert_eq!(vis(m, past, plain(true)), [Rect::new(300, 190, 320, 200)]);
    }

    /// The redraw capture's `redraw` block on the update records (its popup with a border, its
    /// child 40x30 at (10, 10) without one): each RDW_* flag's erase, frame and internal paint for
    /// the window and its child.
    #[test]
    fn redraw_window_flags_as_captured() {
        use rtl::user::{
            RDW_ALLCHILDREN,
            RDW_ERASE,
            RDW_FRAME,
            RDW_INTERNALPAINT,
            RDW_INVALIDATE,
            RDW_NOCHILDREN,
            RDW_NOERASE,
            RDW_NOFRAME,
            RDW_NOINTERNALPAINT,
            RDW_VALIDATE,
        };
        let (m, atom) = manager();
        let t = thread(m, 1, 0x100);
        let (top, th) = shown(m, atom, t, 0, 0);
        m.windows.set_frame_for_tests(top, 1);
        let child = child_of(m, atom, t, th, 0, (10, 10, 40, 30), 0);
        // (region's box, erase, frame) of each, after `flags`; then everything validated.
        let state = |m: &WindowManager, w| {
            let a = paint_area(&m.windows, w);
            let pending = m
                .windows
                .queues
                .updates
                .record(w)
                .map(|u| (u.erase, u.internal));
            (a.paint, pending, a.frame)
        };
        let mut check =
            |m: &mut WindowManager, rect: Option<Rect>, flags: u32, want_top, want_child| {
                let rects = rect.map(|r| std::vec![r]);
                redraw(&mut m.windows, top, rects.as_deref(), flags);
                assert_eq!(
                    (state(m, top), state(m, child)),
                    (want_top, want_child),
                    "flags {flags:#x}"
                );
                redraw(
                    &mut m.windows,
                    top,
                    None,
                    RDW_VALIDATE | RDW_NOINTERNALPAINT | RDW_ALLCHILDREN,
                );
                assert_eq!(
                    m.windows.queues.updates.live(),
                    0,
                    "flags {flags:#x}: all validated"
                );
            };
        let client = Rect::new(0, 0, 318, 198);
        let child_client = Rect::new(0, 0, 40, 30);
        let none = (Rect::EMPTY, None, false);
        // A rectangle outside the child: the window alone, no erase.
        check(
            m,
            Some(Rect::new(60, 40, 80, 60)),
            RDW_INVALIDATE,
            (Rect::new(60, 40, 80, 60), Some((false, false)), false),
            none,
        );
        // The whole window: the child's frame and erase whatever the flags say.
        let child_all = (child_client, Some((true, false)), true);
        check(
            m,
            None,
            RDW_INVALIDATE | RDW_ERASE,
            (client, Some((true, false)), false),
            child_all,
        );
        check(
            m,
            None,
            RDW_INVALIDATE | RDW_ERASE | RDW_ALLCHILDREN,
            (client, Some((true, false)), false),
            child_all,
        );
        check(
            m,
            None,
            RDW_INVALIDATE | RDW_NOCHILDREN,
            (client, Some((false, false)), false),
            none,
        );
        check(
            m,
            None,
            RDW_INVALIDATE | RDW_FRAME,
            (client, Some((false, false)), true),
            child_all,
        );
        check(
            m,
            None,
            RDW_INVALIDATE | RDW_NOFRAME,
            (client, Some((false, false)), false),
            child_all,
        );
        // An internal paint: a WM_PAINT for each, nothing to paint.
        let internal = (Rect::EMPTY, Some((false, true)), false);
        check(m, None, RDW_INTERNALPAINT, internal, internal);
        // A validation of a rectangle leaves the rest; RDW_NOERASE and RDW_NOFRAME take the
        // pending erase and frame back.
        redraw(
            &mut m.windows,
            top,
            None,
            RDW_INVALIDATE | RDW_ERASE | RDW_FRAME,
        );
        redraw(
            &mut m.windows,
            top,
            Some(&[Rect::new(60, 40, 80, 60)]),
            RDW_VALIDATE,
        );
        assert_eq!(
            update_region_of(&m.windows, top).unwrap().complexity(),
            COMPLEXREGION
        );
        assert_eq!(state(m, child), child_all, "the rectangle misses the child");
        redraw(
            &mut m.windows,
            top,
            Some(&[Rect::new(60, 40, 80, 60)]),
            RDW_VALIDATE | RDW_NOERASE | RDW_NOFRAME | RDW_NOCHILDREN,
        );
        assert_eq!(state(m, top), (client, Some((false, false)), false));
        assert_eq!(state(m, child), child_all, "RDW_NOCHILDREN");
    }
}
