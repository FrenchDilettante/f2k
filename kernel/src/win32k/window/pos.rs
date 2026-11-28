//! SetWindowPos's decision, and the repaint of what a hidden window uncovers.

use rtl::gdi::Rect;
use rtl::user::{WM_WINDOWPOSCHANGED, WM_WINDOWPOSCHANGING, WS_MINIMIZE, WS_VISIBLE};
use rtl::window::{
    SWP_FRAMECHANGED,
    SWP_HIDEWINDOW,
    SWP_NOACTIVATE,
    SWP_NOCLIENTMOVE,
    SWP_NOCLIENTSIZE,
    SWP_NOMOVE,
    SWP_NOREDRAW,
    SWP_NOSENDCHANGING,
    SWP_NOSIZE,
    SWP_NOZORDER,
    SWP_SHOWWINDOW,
};

use super::*;

impl Windows {
    /// SetWindowPos's decision for `window`: position (`x`, `y`, parent-client coordinates for a
    /// child), size (`cx`, `cy`, negative taken as zero), z-order place (`after`), each unless the
    /// SWP_ `flags` leave it alone, and visibility.
    ///
    /// WM_WINDOWPOSCHANGING first (unless SWP_NOSENDCHANGING; the handler may change it); then the
    /// rectangles (WM_NCCALCSIZE for a new size or SWP_FRAMECHANGED, the children moved with the
    /// client area), the z-order, the visibility, the activation (top-level, unless
    /// SWP_NOACTIVATE); then WM_WINDOWPOSCHANGED, SWP_NOMOVE/SWP_NOSIZE added for what did not
    /// change. A window shown or hidden is moved and sized too unless the flags say not (guigeo
    /// `swpshow`, against the documentation); a parentless window keeps its place. WM_SIZE and
    /// WM_MOVE are the default procedure's answer to WM_WINDOWPOSCHANGED.
    #[allow(clippy::too_many_arguments)]
    pub fn set_window_pos(
        s: &mut dyn Session,
        window: WindowId,
        after: InsertAfter,
        x: i32,
        y: i32,
        cx: i32,
        cy: i32,
        flags: u32,
    ) -> Result<(), Failure> {
        let windows = s.windows();
        let show_call = flags & SWP_SHOWWINDOW_CALL;
        let mut flags = flags & !SWP_SHOWWINDOW_CALL;
        if windows.at(window).parent.is_none() {
            flags |= SWP_NOZORDER;
        }
        let old = windows.at(window).window_rect;
        let origin = windows.parent_origin(window);
        let mut pos = WindowPos {
            hwnd: windows.at(window).handle,
            insert_after: windows.insert_after_handle(after),
            x,
            y,
            cx,
            cy,
            flags,
        };
        if flags & SWP_NOMOVE != 0 {
            pos.x = old.left.saturating_sub(origin.0);
            pos.y = old.top.saturating_sub(origin.1);
        }
        if flags & SWP_NOSIZE != 0 {
            pos.cx = old.right - old.left;
            pos.cy = old.bottom - old.top;
        }

        // The handler may change the new place, the flags among it.
        let mut after = after;
        if flags & SWP_NOSENDCHANGING == 0 {
            let mut message = Message {
                message: WM_WINDOWPOSCHANGING,
                wparam: 0,
                lparam: 0,
                payload: Payload::WindowPos(pos),
            };
            s.send(window, &mut message);
            let windows = s.windows();
            if !windows.pool.is_live(window) {
                return Err(Failure::InvalidWindowHandle);
            }
            // The handler's WINDOWPOS, as Windows 2000 takes it: its place, size, flags and
            // insert-after (an insert-after naming no window keeps the asked one). The window it
            // names stays this one, and F2K's private show bit stays the caller's.
            if let Payload::WindowPos(changed) = message.payload {
                if changed.insert_after != pos.insert_after {
                    after = windows
                        .insert_after_of(changed.insert_after)
                        .unwrap_or(after);
                }
                pos = WindowPos {
                    hwnd: pos.hwnd,
                    flags: changed.flags & !SWP_SHOWWINDOW_CALL,
                    ..changed
                };
            }
        }
        let windows = s.windows();
        let mut flags = pos.flags;

        // The rectangles.
        let mut rect = old;
        if flags & SWP_NOMOVE == 0 {
            rect.left = pos.x.saturating_add(origin.0);
            rect.top = pos.y.saturating_add(origin.1);
        }
        let (width, height) = if flags & SWP_NOSIZE == 0 {
            (pos.cx.max(0), pos.cy.max(0))
        } else {
            (old.right - old.left, old.bottom - old.top)
        };
        rect.right = rect.left.saturating_add(width);
        rect.bottom = rect.top.saturating_add(height);
        let moved = (rect.left, rect.top) != (old.left, old.top);
        let sized = (width, height) != (old.right - old.left, old.bottom - old.top);
        if !moved {
            flags |= SWP_NOMOVE;
        }
        if !sized {
            flags |= SWP_NOSIZE;
        }
        let old_client = windows.at(window).client_rect;
        let client = if sized || flags & SWP_FRAMECHANGED != 0 {
            let resize = Resize {
                window: old,
                client: old_client,
                pos: WindowPos { flags, ..pos },
            };
            let client = s.calc_client(window, rect, Some(resize));
            let windows = s.windows();
            if !windows.pool.is_live(window) {
                return Err(Failure::InvalidWindowHandle);
            }
            client
        } else {
            old_client.saturating_offset(
                rect.left.saturating_sub(old.left),
                rect.top.saturating_sub(old.top),
            )
        };
        let windows = s.windows();
        {
            let w = windows.at_mut(window);
            w.window_rect = rect;
            w.client_rect = client;
        }
        windows.offset_descendants(
            window,
            client.left.saturating_sub(old_client.left),
            client.top.saturating_sub(old_client.top),
        );

        // The z-order; a window that keeps its place among its siblings reports SWP_NOZORDER.
        if flags & SWP_NOZORDER == 0 {
            let before = windows.z_place(window);
            windows.reorder(window, after);
            if windows.z_place(window) == before {
                flags |= SWP_NOZORDER;
            }
        }

        // The visibility.
        let visible = windows.at(window).is_visible();
        let was_shown = crate::win32k::paint::is_shown(windows, window);
        if flags & SWP_SHOWWINDOW != 0 && !visible {
            windows.at_mut(window).style |= WS_VISIBLE;
            // A window shown for the first time is invalid over its whole area, to be erased.
            crate::win32k::paint::invalidate(windows, window, None, true);
        } else if flags & SWP_HIDEWINDOW != 0 && visible {
            windows.at_mut(window).style &= !WS_VISIBLE;
            if was_shown {
                Windows::expose(s, old, window);
            }
        } else {
            flags &= !(SWP_SHOWWINDOW | SWP_HIDEWINDOW);
        }
        let windows = s.windows();

        // The activation.
        if flags & SWP_NOACTIVATE == 0
            && !windows.at(window).is_child()
            && windows.at(window).is_visible()
        {
            s.activate(window, Activate::Try);
            let windows = s.windows();
            if !windows.pool.is_live(window) {
                return Err(Failure::InvalidWindowHandle);
            }
        }
        let windows = s.windows();

        // A resize of a shown window invalidates the whole client, without the erase flag, unless
        // SWP_NOREDRAW (Windows 2000 repaints the whole client on a size change).
        if sized
            && flags & SWP_NOREDRAW == 0
            && windows.pool.is_live(window)
            && crate::win32k::paint::is_shown(windows, window)
        {
            crate::win32k::paint::invalidate(windows, window, None, false);
        }

        // The frame, painted where it shows anew: the window shown, sized, or its frame changed;
        // left to the window's WM_PAINT when a parent still to paint would draw over it.
        if windows.pool.is_live(window)
            && (sized || flags & (SWP_SHOWWINDOW | SWP_FRAMECHANGED) != 0)
            && crate::win32k::paint::is_shown(windows, window)
            && windows.has_frame(window)
            && crate::win32k::paint::frame_now(windows, window)
        {
            s.paint_frame(window);
        }
        let windows = s.windows();

        // What the client area did: the default procedure's WM_SIZE and WM_MOVE follow from it. A
        // minimized window hidden reports its client area sized (the guigeo capture's minmax: its
        // SW_HIDE brings a WM_SIZE of SIZE_MINIMIZED).
        let hid_minimized =
            flags & SWP_HIDEWINDOW != 0 && windows.at(window).style & WS_MINIMIZE != 0;
        if (client.right - client.left, client.bottom - client.top)
            == (
                old_client.right - old_client.left,
                old_client.bottom - old_client.top,
            )
            && !hid_minimized
        {
            flags |= SWP_NOCLIENTSIZE;
        }
        if (client.left, client.top) == (old_client.left, old_client.top) {
            flags |= SWP_NOCLIENTMOVE;
        }

        // Nothing changed: no WM_WINDOWPOSCHANGED (an unchanged SetWindowPos sends none, guigeo
        // `sizemsg`).
        const NO_POSITION_CHANGE: u32 =
            SWP_NOSIZE | SWP_NOMOVE | SWP_NOCLIENTSIZE | SWP_NOCLIENTMOVE | SWP_NOZORDER;
        if flags & (NO_POSITION_CHANGE | SWP_FRAMECHANGED | SWP_SHOWWINDOW | SWP_HIDEWINDOW)
            == NO_POSITION_CHANGE
        {
            return Ok(());
        }

        // A changed client area's WM_SIZE and WM_MOVE replace the ones a tiled window's creation
        // deferred (guigeo minmax: a window moved before its first show gets one WM_SIZE).
        if flags & (SWP_NOCLIENTSIZE | SWP_NOCLIENTMOVE) != SWP_NOCLIENTSIZE | SWP_NOCLIENTMOVE {
            windows.at_mut(window).flags.sendsizemove = false;
        }

        let done = WindowPos {
            x: rect.left.saturating_sub(origin.0),
            y: rect.top.saturating_sub(origin.1),
            cx: width,
            cy: height,
            flags: flags | show_call,
            ..pos
        };
        s.send(
            window,
            &mut Message {
                message: WM_WINDOWPOSCHANGED,
                wparam: 0,
                lparam: 0,
                payload: Payload::WindowPos(done),
            },
        );
        Ok(())
    }

    /// The screen area `area` uncovered (`gone` was hidden there): every other shown window it
    /// overlaps is invalid there, to be erased, and its frame painted. F2K's windows do not clip
    /// one another, so every window under the area is repainted, not just what shows.
    fn expose(s: &mut dyn Session, area: Rect, gone: WindowId) {
        // By slot, the bound read again each turn: a frame's painting may make or destroy windows.
        let mut index = 0;
        while index < s.windows().pool.high_water() {
            let windows = s.windows();
            let at = index;
            index += 1;
            let Some(id) = windows.pool.id_at(at) else {
                continue;
            };
            if id == gone || !crate::win32k::paint::is_shown(windows, id) {
                continue;
            }
            let window_rect = windows.at(id).window_rect;
            let over = window_rect.intersect(area);
            if over.is_empty() {
                continue;
            }
            let client = windows.at(id).client_rect;
            let part = client.intersect(over);
            if !part.is_empty() {
                let local = part.saturating_offset_back(client.left, client.top);
                crate::win32k::paint::invalidate(windows, id, Some(local), true);
            }
            if windows.has_frame(id) && part != over {
                s.paint_frame(id);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use rtl::user::{WM_NCCALCSIZE, WS_CHILD, WS_OVERLAPPED, WS_OVERLAPPEDWINDOW, WS_POPUP};
    use rtl::window::{SW_HIDE, SW_SHOW};

    use super::*;
    use crate::win32k::window::testkit::*;

    /// WM_WINDOWPOSCHANGING's handler adding SWP_NOMOVE and setting cx (guigeo `edits`): the
    /// window keeps its place and takes the handler's width; the WINDOWPOS's window stays the one
    /// moved, whatever the handler wrote there.
    #[test]
    fn a_window_pos_changing_handlers_edit_counts() {
        let (w, c, t, atom, _, _) = setup();
        let mut pump = Rec::new(t);
        let id = create(w, c, t, atom, WS_POPUP, &mut pump).unwrap();
        pump.changing_answer = Some(WindowPos {
            hwnd: 0x1234,
            insert_after: 0,
            x: 60,
            y: 70,
            cx: 250,
            cy: 130,
            flags: SWP_NOZORDER | SWP_NOACTIVATE | SWP_NOMOVE,
        });
        assert_eq!(
            Windows::set_window_pos(
                &mut pump.on(w, c),
                id,
                InsertAfter::Top,
                60,
                70,
                220,
                130,
                SWP_NOZORDER | SWP_NOACTIVATE
            ),
            Ok(())
        );
        assert_eq!(w.at(id).window_rect, Rect::new(10, 20, 260, 150));
        let (_, _, changed) = *pump.positions.last().unwrap();
        assert_eq!(changed.hwnd, w.handle_of(id));
    }

    /// SetWindowPos's messages and rectangles: WM_WINDOWPOSCHANGING with the asked place, a new
    /// size's WM_NCCALCSIZE answering the client rectangle, WM_WINDOWPOSCHANGED with what happened
    /// (SWP_NOMOVE and SWP_NOSIZE for what did not); a move alone carries the client rectangle and
    /// the children along; a child's position is in its parent's client coordinates.
    #[test]
    fn set_window_pos_moves_sizes_and_reports() {
        let (w, c, t, atom, _, _) = setup();
        let mut pump = Rec::new(t);
        pump.nccalc_inset = 4;
        let top = create(w, c, t, atom, WS_POPUP, &mut pump).unwrap();
        let mut a = args(atom, WS_CHILD);
        (a.x, a.y, a.cx, a.cy) = (5, 6, 20, 10);
        a.parent = Some(top);
        let child = Windows::create_window_ex(&mut pump.on(w, c), t, &a).unwrap();
        // The create: window 10,20 100x80, client inset by 4; the child at 5,6 in the client.
        assert_eq!(
            w.at(top).client_rect,
            Rect {
                left: 14,
                top: 24,
                right: 106,
                bottom: 96
            }
        );
        assert_eq!(
            w.at(child).window_rect,
            Rect {
                left: 19,
                top: 30,
                right: 39,
                bottom: 40
            }
        );
        pump.events.clear();

        // A move and a size.
        assert_eq!(
            Windows::set_window_pos(
                &mut pump.on(w, c),
                top,
                InsertAfter::Top,
                50,
                60,
                200,
                150,
                SWP_NOZORDER | SWP_NOACTIVATE
            ),
            Ok(())
        );
        assert_eq!(
            pump.messages(),
            vec![WM_WINDOWPOSCHANGING, WM_NCCALCSIZE, WM_WINDOWPOSCHANGED]
        );
        assert_eq!(
            w.at(top).window_rect,
            Rect {
                left: 50,
                top: 60,
                right: 250,
                bottom: 210
            }
        );
        assert_eq!(
            w.at(top).client_rect,
            Rect {
                left: 54,
                top: 64,
                right: 246,
                bottom: 206
            }
        );
        assert_eq!(
            w.at(child).window_rect,
            Rect {
                left: 59,
                top: 70,
                right: 79,
                bottom: 80
            }
        );
        let (_, _, changed) = *pump.positions.last().unwrap();
        assert_eq!(
            (changed.x, changed.y, changed.cx, changed.cy),
            (50, 60, 200, 150)
        );
        assert_eq!(changed.flags, SWP_NOZORDER | SWP_NOACTIVATE);

        // A move alone: no WM_NCCALCSIZE, the client rectangle moves along; WM_WINDOWPOSCHANGED
        // says the size did not change.
        pump.events.clear();
        pump.positions.clear();
        let flags = SWP_NOZORDER | SWP_NOACTIVATE;
        assert_eq!(
            Windows::set_window_pos(
                &mut pump.on(w, c),
                top,
                InsertAfter::Top,
                0,
                0,
                200,
                150,
                flags
            ),
            Ok(())
        );
        assert_eq!(
            pump.messages(),
            vec![WM_WINDOWPOSCHANGING, WM_WINDOWPOSCHANGED]
        );
        assert_eq!(
            w.at(top).client_rect,
            Rect {
                left: 4,
                top: 4,
                right: 196,
                bottom: 146
            }
        );
        assert_eq!(
            w.at(child).window_rect,
            Rect {
                left: 9,
                top: 10,
                right: 29,
                bottom: 20
            }
        );
        assert_eq!(
            pump.positions[1].2.flags,
            flags | SWP_NOSIZE | SWP_NOCLIENTSIZE
        );

        // The same place again: nothing changed, no WM_WINDOWPOSCHANGED (guigeo `sizemsg`).
        pump.events.clear();
        assert_eq!(
            Windows::set_window_pos(
                &mut pump.on(w, c),
                top,
                InsertAfter::Top,
                0,
                0,
                200,
                150,
                flags
            ),
            Ok(())
        );
        assert_eq!(pump.messages(), vec![WM_WINDOWPOSCHANGING]);

        // A child's position is in its parent's client coordinates, and is reported so.
        pump.positions.clear();
        assert_eq!(
            Windows::set_window_pos(
                &mut pump.on(w, c),
                child,
                InsertAfter::Top,
                1,
                2,
                0,
                0,
                SWP_NOSIZE | SWP_NOZORDER
            ),
            Ok(())
        );
        assert_eq!(
            w.at(child).window_rect,
            Rect {
                left: 5,
                top: 6,
                right: 25,
                bottom: 16
            }
        );
        let (_, _, changed) = pump.positions[1];
        assert_eq!((changed.x, changed.y), (1, 2));

        // A negative size is taken as zero.
        assert_eq!(
            Windows::set_window_pos(
                &mut pump.on(w, c),
                child,
                InsertAfter::Top,
                1,
                2,
                -5,
                -5,
                SWP_NOZORDER
            ),
            Ok(())
        );
        assert_eq!(
            w.at(child).window_rect,
            Rect {
                left: 5,
                top: 6,
                right: 5,
                bottom: 6
            }
        );
    }

    /// The handler of WM_WINDOWPOSCHANGING may change the place; SWP_NOSENDCHANGING skips it; a
    /// show moves and sizes the window too (guigeo `swpshow`).
    #[test]
    fn set_window_pos_takes_the_handlers_changes() {
        let (w, c, t, atom, _, _) = setup();
        let mut pump = Rec::new(t);
        let id = create(w, c, t, atom, WS_POPUP, &mut pump).unwrap();
        pump.changing_answer = Some(WindowPos {
            hwnd: w.at(id).handle,
            insert_after: HWND_TOP,
            x: 7,
            y: 8,
            cx: 9,
            cy: 10,
            flags: SWP_NOZORDER | SWP_NOACTIVATE,
        });
        let flags = SWP_NOZORDER | SWP_NOACTIVATE;
        assert_eq!(
            Windows::set_window_pos(&mut pump.on(w, c), id, InsertAfter::Top, 1, 1, 1, 1, flags),
            Ok(())
        );
        assert_eq!(
            w.at(id).window_rect,
            Rect {
                left: 7,
                top: 8,
                right: 16,
                bottom: 18
            }
        );
        pump.positions.clear();
        assert_eq!(
            Windows::set_window_pos(
                &mut pump.on(w, c),
                id,
                InsertAfter::Top,
                1,
                1,
                1,
                1,
                flags | SWP_NOSENDCHANGING
            ),
            Ok(())
        );
        assert_eq!(
            w.at(id).window_rect,
            Rect {
                left: 1,
                top: 1,
                right: 2,
                bottom: 2
            }
        );
        assert_eq!(pump.positions.len(), 1, "WM_WINDOWPOSCHANGED alone");
        pump.changing_answer = None;
        assert_eq!(
            Windows::set_window_pos(
                &mut pump.on(w, c),
                id,
                InsertAfter::Top,
                30,
                30,
                30,
                30,
                flags | SWP_SHOWWINDOW
            ),
            Ok(())
        );
        assert!(w.at(id).is_visible());
        assert_eq!(
            w.at(id).window_rect,
            Rect {
                left: 30,
                top: 30,
                right: 60,
                bottom: 60
            }
        );
    }

    /// The activation: a top-level window shown or moved without SWP_NOACTIVATE is activated, a
    /// child never; hiding the thread's active window activates the next.
    #[test]
    fn the_activation_follows_the_flags() {
        let (w, c, t, atom, _, _) = setup();
        let mut pump = Rec::new(t);
        let top = create(w, c, t, atom, WS_POPUP | WS_VISIBLE, &mut pump).unwrap();
        pump.events.clear();
        Windows::set_window_pos(
            &mut pump.on(w, c),
            top,
            InsertAfter::Top,
            1,
            1,
            0,
            0,
            SWP_NOSIZE,
        )
        .unwrap();
        assert!(pump.events.contains(&Ev::Activate(top, Activate::Try)));
        pump.events.clear();
        Windows::set_window_pos(
            &mut pump.on(w, c),
            top,
            InsertAfter::Top,
            2,
            2,
            0,
            0,
            SWP_NOSIZE | SWP_NOACTIVATE,
        )
        .unwrap();
        assert!(!pump.events.iter().any(|e| matches!(e, Ev::Activate(..))));

        let mut a = args(atom, WS_CHILD | WS_VISIBLE);
        a.parent = Some(top);
        let child = Windows::create_window_ex(&mut pump.on(w, c), t, &a).unwrap();
        assert!(!pump
            .events
            .iter()
            .any(|e| matches!(e, Ev::Activate(x, _) if *x == child)));

        w.thread_mut(t).active = Some(top);
        pump.events.clear();
        assert_eq!(
            Windows::show_window(&mut pump.on(w, c), top, SW_HIDE),
            Ok(true)
        );
        assert!(pump.events.contains(&Ev::Activate(top, Activate::Skip)));
    }

    /// guigeo `swpshow`: SetWindowPos with SWP_SHOWWINDOW or SWP_HIDEWINDOW moves and sizes the
    /// window too, shown or hidden.
    #[test]
    fn a_shown_or_hidden_window_is_moved_and_sized_too() {
        let (w, c, t, atom, _, _) = setup();
        let mut pump = Rec::new(t);
        let id = create(w, c, t, atom, WS_OVERLAPPEDWINDOW, &mut pump).unwrap();
        for (x, y, cx, cy, flags, visible) in [
            (120, 90, 250, 180, SWP_SHOWWINDOW, true),
            (140, 100, 260, 190, SWP_SHOWWINDOW, true),
            (160, 110, 270, 170, SWP_HIDEWINDOW, false),
        ] {
            Windows::set_window_pos(
                &mut pump.on(w, c),
                id,
                InsertAfter::Top,
                x,
                y,
                cx,
                cy,
                flags | SWP_NOACTIVATE,
            )
            .unwrap();
            assert_eq!(w.at(id).window_rect, Rect::new(x, y, x + cx, y + cy));
            assert_eq!(w.at(id).is_visible(), visible);
        }
    }

    /// A resize of a shown window leaves its whole client in the update region, without the erase
    /// flag, so the next BeginPaint's rectangle is the new client; SWP_NOREDRAW keeps the client
    /// valid, and a hidden window's resize leaves nothing (its first show invalidates then).
    #[test]
    fn a_shown_windows_resize_invalidates_its_whole_client() {
        use crate::win32k::paint::{begin_validate, update_of};
        let (w, c, t, atom, _, _) = setup();
        let mut pump = Rec::new(t);
        pump.nccalc_inset = 4;
        let top = create(w, c, t, atom, WS_OVERLAPPED, &mut pump).unwrap();

        // Hidden: a resize invalidates nothing.
        Windows::set_window_pos(
            &mut pump.on(w, c),
            top,
            InsertAfter::Top,
            10,
            20,
            300,
            200,
            SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE,
        )
        .unwrap();
        assert_eq!(update_of(w, top), None);

        // Shown: the first show invalidated the client whole; validate it away, then resize again.
        assert_eq!(
            Windows::show_window(&mut pump.on(w, c), top, SW_SHOW),
            Ok(false)
        );
        begin_validate(w, top);
        assert_eq!(update_of(w, top), None);
        Windows::set_window_pos(
            &mut pump.on(w, c),
            top,
            InsertAfter::Top,
            10,
            20,
            400,
            260,
            SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE,
        )
        .unwrap();
        // The window at 10,20 of 400x260, the client inset by 4: the whole client, no erase.
        assert_eq!(
            update_of(w, top),
            Some((
                Rect {
                    left: 0,
                    top: 0,
                    right: 392,
                    bottom: 252
                },
                false
            ))
        );

        // SWP_NOREDRAW: the client stays valid through a resize.
        begin_validate(w, top);
        Windows::set_window_pos(
            &mut pump.on(w, c),
            top,
            InsertAfter::Top,
            10,
            20,
            500,
            300,
            SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE | SWP_NOREDRAW,
        )
        .unwrap();
        assert_eq!(update_of(w, top), None);
    }

    /// SetWindowPos(h, 0, 0x7FFFFFF0, 0, 100, 100, SWP_NOZORDER): the window goes where it was
    /// asked, its right edge saturated at i32::MAX, as Windows stores an extreme rectangle without
    /// faulting.
    #[test]
    fn set_window_pos_saturates_an_extreme_rectangle() {
        use crate::win32k::queue::{rig, QueueSession};
        let (m, atom) = rig::manager();
        let t = rig::thread(m, 1, 0x10);
        let h = rig::popup(m, atom, t);
        let WindowManager {
            windows, classes, ..
        } = m;
        let flags = SWP_NOZORDER;
        assert_eq!(
            Windows::set_window_pos_handle(
                &mut QueueSession::new(windows, classes),
                h,
                0,
                0x7FFF_FFF0,
                0,
                100,
                100,
                flags
            ),
            Ok(())
        );
        let w = windows.window_of(h).unwrap();
        assert_eq!(
            windows.window_rect(w),
            Rect {
                left: 0x7FFF_FFF0,
                top: 0,
                right: i32::MAX,
                bottom: 100
            }
        );
    }

    /// A framed window moved and sized at i32's end (its rectangle saturated, 15 by 15): its frame
    /// is taken off the rectangle as anywhere else, the client area's edges past i32's end
    /// saturated.
    #[test]
    fn a_framed_window_at_i32s_end_has_its_frame() {
        use crate::win32k::queue::{rig, QueueSession};
        let (m, atom) = rig::manager();
        let t = rig::thread(m, 1, 0x10);
        let h = rig::window_at(m, atom, t, WS_OVERLAPPEDWINDOW, 0, 0, 0, 200, 100);
        let w = m.windows.window_of(h).unwrap();
        let near = m.windows.client_rect(w);
        let at = 0x7FFF_FFF0;
        assert_eq!(
            WindowManager::move_window(
                &mut QueueSession::new(&mut m.windows, &mut m.classes),
                h,
                at,
                at,
                300,
                200,
                true
            ),
            Ok(())
        );
        assert_eq!(
            m.windows.client_rect(w),
            Rect {
                left: at + near.left,
                top: i32::MAX,
                right: i32::MAX - near.left,
                bottom: i32::MAX
            }
        );
    }
}
