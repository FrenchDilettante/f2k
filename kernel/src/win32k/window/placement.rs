//! GetWindowPlacement, SetWindowPlacement and EndDeferWindowPos.

use rtl::gdi::Rect;
use rtl::user::{WS_MAXIMIZE, WS_MINIMIZE};
use rtl::window::{
    SWP_NOACTIVATE,
    SWP_NOZORDER,
    SW_SHOWMAXIMIZED,
    SW_SHOWMINIMIZED,
    SW_SHOWNORMAL,
};

use super::*;

impl Windows {
    /// GetWindowPlacement's answer for `window`: its show state (SW_SHOWMINIMIZED,
    /// SW_SHOWMAXIMIZED or SW_SHOWNORMAL, hidden or not), WPF_RESTORETOMAXIMIZED while it is
    /// maximized or restores to maximized, its minimized position (where it is while minimized;
    /// (-1, -1) for none), its maximized position ((-1, -1) unless SetWindowPlacement gave one),
    /// and its normal place (where it is while neither minimized nor maximized).
    pub fn window_placement(&self, window: WindowId) -> rtl::window::WindowPlacement {
        let w = self.at(window);
        let origin = self.parent_origin(window);
        let here = w.window_rect.saturating_offset_back(origin.0, origin.1);
        let minimized = w.style & WS_MINIMIZE != 0;
        let maximized = w.style & WS_MAXIMIZE != 0;
        let show_cmd = if minimized {
            SW_SHOWMINIMIZED
        } else if maximized {
            SW_SHOWMAXIMIZED
        } else {
            SW_SHOWNORMAL
        };
        let (min_x, min_y) = if minimized {
            (here.left, here.top)
        } else {
            w.min_position.unwrap_or((-1, -1))
        };
        let (max_x, max_y) = w.max_position.unwrap_or((-1, -1));
        let normal = if minimized || maximized {
            w.normal.unwrap_or(here)
        } else {
            here
        };
        rtl::window::WindowPlacement {
            length: core::mem::size_of::<rtl::window::WindowPlacement>() as u32,
            flags: if w.restore_maximized || maximized {
                rtl::window::WPF_RESTORETOMAXIMIZED
            } else {
                0
            },
            show_cmd: show_cmd as u32,
            min_x,
            min_y,
            max_x,
            max_y,
            normal,
        }
    }

    /// SetWindowPlacement's decision for `window`: the normal place, the minimized position (only
    /// with WPF_SETMINPOSITION), the maximized position (none for (-1, -1)) and
    /// WPF_RESTORETOMAXIMIZED set; a normal window moved to its normal place; then the show command
    /// ([`Windows::show_window`]). ERROR_INVALID_PARAMETER for a length not the structure's.
    pub fn set_window_placement(
        s: &mut dyn Session,
        window: WindowId,
        placement: &rtl::window::WindowPlacement,
    ) -> Result<(), Failure> {
        let windows = s.windows();
        use rtl::window::{WPF_RESTORETOMAXIMIZED, WPF_SETMINPOSITION};
        if placement.length as usize != core::mem::size_of::<rtl::window::WindowPlacement>() {
            return Err(Failure::InvalidParameter);
        }
        let normal = Rect {
            left: placement.normal.left,
            top: placement.normal.top,
            right: placement.normal.right,
            bottom: placement.normal.bottom,
        };
        {
            let w = windows.at_mut(window);
            w.normal = Some(normal);
            w.min_position = (placement.flags & WPF_SETMINPOSITION != 0)
                .then_some((placement.min_x, placement.min_y));
            w.max_position = ((placement.max_x, placement.max_y) != (-1, -1))
                .then_some((placement.max_x, placement.max_y));
            w.restore_maximized = placement.flags & WPF_RESTORETOMAXIMIZED != 0;
        }
        if windows.at(window).style & (WS_MINIMIZE | WS_MAXIMIZE) == 0 {
            Windows::set_window_pos(
                s,
                window,
                InsertAfter::Top,
                normal.left,
                normal.top,
                normal.width(),
                normal.height(),
                SWP_NOZORDER | SWP_NOACTIVATE,
            )?;
        }
        let windows = s.windows();
        if !windows.pool.is_live(window) {
            return Err(Failure::InvalidWindowHandle);
        }
        Windows::show_window(s, window, placement.show_cmd as i32).map(|_| ())
    }

    /// EndDeferWindowPos over a batch's positions, in order, each as SetWindowPos
    /// ([`Windows::set_window_pos_handle`]), a window gone since skipped. A window named twice
    /// takes each position in turn, and its children move by each one's change from where the
    /// window began (Windows 2000 works out every change first, guigeo `defer`): before its second
    /// position the children are moved again, quietly, by what the first moved them.
    pub fn end_defer_window_pos(
        s: &mut dyn Session,
        positions: &[WindowPos],
    ) -> Result<(), Failure> {
        let windows = s.windows();
        let mut began = [(0 as Hwnd, 0i32, 0i32); DEFER_POSITIONS];
        for (at, pos) in positions.iter().enumerate() {
            let origin = windows.window_from_handle(pos.hwnd).map_or((0, 0), |w| {
                let client = windows.at(w).client_rect;
                (client.left, client.top)
            });
            let first = positions[..at]
                .iter()
                .position(|earlier| earlier.hwnd == pos.hwnd);
            began[at] = match first {
                Some(first) => began[first],
                None => (pos.hwnd, origin.0, origin.1),
            };
        }
        for (at, pos) in positions.iter().enumerate() {
            let windows = s.windows();
            let Some(window) = windows.window_from_handle(pos.hwnd) else {
                continue;
            };
            let client = windows.at(window).client_rect;
            let (_, left, top) = began[at];
            windows.offset_descendants(
                window,
                client.left.saturating_sub(left),
                client.top.saturating_sub(top),
            );
            Windows::set_window_pos_handle(
                s,
                pos.hwnd,
                pos.insert_after,
                pos.x,
                pos.y,
                pos.cx,
                pos.cy,
                pos.flags,
            )?;
        }
        Ok(())
    }
}

impl WindowManager {
    /// NtUserGetWindowPlacement's answer for the window `handle` names
    /// ([`Windows::window_placement`]).
    pub fn window_placement(&self, handle: Hwnd) -> Result<rtl::window::WindowPlacement, Failure> {
        let window = self.windows.window_of(handle)?;
        Ok(self.windows.window_placement(window))
    }

    /// NtUserSetWindowPlacement's decision over a handle ([`Windows::set_window_placement`]).
    pub fn set_window_placement(
        s: &mut dyn Session,
        handle: Hwnd,
        placement: &rtl::window::WindowPlacement,
    ) -> Result<(), Failure> {
        let windows = s.windows();
        let window = windows.window_of(handle)?;
        Windows::set_window_placement(s, window, placement)
    }

    /// NtUserEndDeferWindowPosEx's decision over a batch's positions
    /// ([`Windows::end_defer_window_pos`]).
    pub fn end_defer_window_pos(
        s: &mut dyn Session,
        positions: &[WindowPos],
    ) -> Result<(), Failure> {
        Windows::end_defer_window_pos(s, positions)
    }
}

#[cfg(test)]
mod tests {
    use rtl::user::{WS_CHILD, WS_OVERLAPPEDWINDOW, WS_POPUP, WS_VISIBLE};
    use rtl::window::SW_HIDE;

    use super::*;
    use crate::win32k::window::testkit::*;

    /// SetWindowPlacement, as the guigeo capture's placement shows Windows 2000's: the normal place
    /// set, a normal window moved there, the show command carried out (minimized, the minimized
    /// position chosen and answered while it lasts); a minimized position without
    /// WPF_SETMINPOSITION is none, (-1, -1); a length that is not the structure's is refused.
    #[test]
    fn the_window_placement() {
        let (w, c, t, atom, _, _) = setup();
        let mut pump = Rec::new(t);
        let id = create(w, c, t, atom, WS_OVERLAPPEDWINDOW, &mut pump).unwrap();
        let first = Rect {
            left: 150,
            top: 120,
            right: 450,
            bottom: 330,
        };
        let mut placement = rtl::window::WindowPlacement {
            length: 44,
            flags: 0,
            show_cmd: SW_SHOWMINIMIZED as u32,
            min_x: -1,
            min_y: -1,
            max_x: -1,
            max_y: -1,
            normal: first,
        };
        Windows::set_window_placement(&mut pump.on(w, c), id, &placement).unwrap();
        assert_eq!(
            w.at(id).style & (WS_MINIMIZE | WS_VISIBLE),
            WS_MINIMIZE | WS_VISIBLE
        );
        let answer = w.window_placement(id);
        assert_eq!((answer.length, answer.flags), (44, 0));
        assert_eq!((answer.min_x, answer.min_y), (-32000, -32000));
        assert_eq!(answer.normal, first);

        placement.show_cmd = SW_HIDE as u32;
        placement.length = 0;
        assert_eq!(
            Windows::set_window_placement(&mut pump.on(w, c), id, &placement),
            Err(Failure::InvalidParameter)
        );
        placement.length = 44;
        placement.show_cmd = SW_SHOWNORMAL as u32;
        Windows::set_window_placement(&mut pump.on(w, c), id, &placement).unwrap();
        assert_eq!(w.at(id).window_rect, first);
        assert_eq!(
            w.window_placement(id).min_x,
            -32000,
            "kept as it left the state"
        );
        placement.show_cmd = SW_HIDE as u32;
        Windows::set_window_placement(&mut pump.on(w, c), id, &placement).unwrap();
        let answer = w.window_placement(id);
        assert_eq!((answer.min_x, answer.show_cmd), (-1, SW_SHOWNORMAL as u32));
        assert!(!w.at(id).is_visible());
    }

    /// EndDeferWindowPos's positions, as the guigeo capture's defer shows Windows 2000's: a window
    /// named twice ends at its last position, its children moved by each position's change from
    /// where it began; a sizable window is no smaller than the minimum tracking size.
    #[test]
    fn deferred_positions_move_the_children_twice() {
        let (w, c, t, atom, _, _) = setup();
        let mut pump = Rec::new(t);
        let parent = create(w, c, t, atom, WS_OVERLAPPEDWINDOW, &mut pump).unwrap();
        let flags = SWP_NOZORDER | SWP_NOACTIVATE;
        Windows::set_window_pos(
            &mut pump.on(w, c),
            parent,
            InsertAfter::Top,
            10,
            20,
            320,
            200,
            flags,
        )
        .unwrap();
        let mut a = args(atom, WS_CHILD);
        a.parent = Some(parent);
        a.x = 10;
        a.y = 10;
        a.cx = 50;
        a.cy = 40;
        let child = Windows::create_window_ex(&mut pump.on(w, c), t, &a).unwrap();
        let handle = w.at(parent).handle;
        let pos = |x, y, cx, cy| WindowPos {
            hwnd: handle,
            insert_after: 0,
            x,
            y,
            cx,
            cy,
            flags,
        };
        Windows::end_defer_window_pos(
            &mut pump.on(w, c),
            &[pos(1, 2, 100, 50), pos(5, 6, 150, 70)],
        )
        .unwrap();
        let rect = w.at(parent).window_rect;
        assert_eq!(
            (rect.left, rect.top, rect.right, rect.bottom),
            (5, 6, 155, 76)
        );
        let client = w.at(parent).client_rect;
        let child_rect = w.at(child).window_rect;
        assert_eq!(
            (child_rect.left - client.left, child_rect.top - client.top),
            (1, -8)
        );
        Windows::end_defer_window_pos(&mut pump.on(w, c), &[pos(30, 40, 90, 80)]).unwrap();
        let rect = w.at(parent).window_rect;
        assert_eq!((rect.right - rect.left, rect.bottom - rect.top), (112, 80));
    }

    /// GetWindowPlacement of a child of a window moved to i32's start (where CreateWindowEx's x
    /// would be CW_USEDEFAULT): its place in the parent's client coordinates, exact.
    #[test]
    fn a_child_at_i32s_start_has_its_placement() {
        use crate::win32k::queue::{rig, QueueSession};
        let (m, atom) = rig::manager();
        let t = rig::thread(m, 1, 0x10);
        let parent = rig::window_at(m, atom, t, WS_POPUP, 0, 0, 0, 100, 100);
        let child = rig::window_at(m, atom, t, WS_CHILD, parent, 10, 20, 30, 40);
        let (min, size) = (i32::MIN, 100);
        assert_eq!(
            WindowManager::move_window(
                &mut QueueSession::new(&mut m.windows, &mut m.classes),
                parent,
                min,
                min,
                size,
                size,
                true
            ),
            Ok(())
        );
        assert_eq!(
            m.window_placement(child).unwrap().normal,
            Rect {
                left: 10,
                top: 20,
                right: 40,
                bottom: 60
            }
        );
    }

    /// SetWindowPlacement of a normal rectangle from i32's start to its end: the size saturated,
    /// the window at the start.
    #[test]
    fn set_window_placement_saturates_an_extreme_rectangle() {
        use crate::win32k::queue::{rig, QueueSession};
        let (m, atom) = rig::manager();
        let t = rig::thread(m, 1, 0x10);
        let h = rig::popup(m, atom, t);
        let placement = rtl::window::WindowPlacement {
            length: core::mem::size_of::<rtl::window::WindowPlacement>() as u32,
            flags: 0,
            show_cmd: SW_HIDE as u32,
            min_x: -1,
            min_y: -1,
            max_x: -1,
            max_y: -1,
            normal: Rect {
                left: i32::MIN,
                top: i32::MIN,
                right: i32::MAX,
                bottom: i32::MAX,
            },
        };
        assert_eq!(
            WindowManager::set_window_placement(
                &mut QueueSession::new(&mut m.windows, &mut m.classes),
                h,
                &placement
            ),
            Ok(())
        );
        let w = m.windows.window_of(h).unwrap();
        assert_eq!(
            m.windows.window_rect(w),
            Rect {
                left: i32::MIN,
                top: i32::MIN,
                right: -1,
                bottom: -1
            }
        );
    }

    /// An EndDeferWindowPos batch moving a window from i32's start to its end, twice: its moves
    /// saturate.
    #[test]
    fn a_deferred_batch_across_i32_saturates() {
        use crate::win32k::queue::{rig, QueueSession};
        let (m, atom) = rig::manager();
        let t = rig::thread(m, 1, 0x10);
        let h = rig::window_at(m, atom, t, WS_POPUP, 0, 0, 0, 100, 100);
        rig::window_at(m, atom, t, WS_CHILD, h, 10, 10, 20, 20);
        let (min, size) = (i32::MIN, 100);
        assert_eq!(
            WindowManager::move_window(
                &mut QueueSession::new(&mut m.windows, &mut m.classes),
                h,
                min,
                min,
                size,
                size,
                true
            ),
            Ok(())
        );
        let at = i32::MAX - 200;
        let pos = WindowPos {
            hwnd: h,
            insert_after: 0,
            x: at,
            y: at,
            cx: 100,
            cy: 100,
            flags: SWP_NOZORDER,
        };
        assert_eq!(
            WindowManager::end_defer_window_pos(
                &mut QueueSession::new(&mut m.windows, &mut m.classes),
                &[pos, pos]
            ),
            Ok(())
        );
        let w = m.windows.window_of(h).unwrap();
        assert_eq!(
            m.windows.window_rect(w),
            Rect {
                left: at,
                top: at,
                right: at + 100,
                bottom: at + 100
            }
        );
    }
}
