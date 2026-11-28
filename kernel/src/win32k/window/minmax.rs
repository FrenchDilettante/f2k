//! Minimizing, maximizing and restoring, and the tracking sizes WM_GETMINMAXINFO answers.

use rtl::gdi::Rect;
use rtl::user::{WS_MAXIMIZE, WS_MINIMIZE, WS_THICKFRAME};
use rtl::window::{
    SWP_FRAMECHANGED,
    SWP_NOACTIVATE,
    SWP_NOSIZE,
    SWP_NOZORDER,
    SW_FORCEMINIMIZE,
    SW_MINIMIZE,
    SW_SHOWMAXIMIZED,
    SW_SHOWMINIMIZED,
    SW_SHOWMINNOACTIVE,
};

use super::*;

impl Windows {
    /// The min/max-track clamp (Windows 2000's xxxAdjustSize): a tiled or thick-framed window's
    /// size is clamped into WM_GETMINMAXINFO's track sizes ([`Session::min_max_info`]; the
    /// reserved/max size while minimized); another window's is left alone, nothing sent.
    pub fn adjust_size<S: Session + ?Sized>(s: &mut S, id: WindowId, cx: &mut i32, cy: &mut i32) {
        let windows = s.windows();
        let (tiled, sizebox, minimized) = {
            let w = windows.at(id);
            (
                w.is_tiled(),
                w.style & WS_THICKFRAME != 0,
                w.style & WS_MINIMIZE != 0,
            )
        };
        if tiled || sizebox {
            let mmi = s.min_max_info(id);
            let (min, max) = if minimized {
                (mmi.reserved, mmi.max_size)
            } else {
                (mmi.min_track, mmi.max_track)
            };
            *cx = min.0.max((*cx).min(max.0));
            *cy = min.1.max((*cy).min(max.1));
        }
    }

    /// The minimize/maximize/restore part of `command` for `window` (guigeo minmax and placement):
    /// the new state's style and place through [`Windows::set_window_pos`] (WM_SIZE follows with
    /// the matching SIZE_*), visibility and activation left to the show.
    ///
    /// - Leaving the normal state keeps the place as the normal one; leaving the minimized state
    ///   keeps the corner as the minimized position.
    /// - Minimized: the minimized position, else [`MINIMIZED_POSITION`], at [`MINIMIZED_SIZE`]; it
    ///   restores to maximized when it was maximized.
    /// - Maximized: WM_GETMINMAXINFO's ptMaxSize at ptMaxPosition, by default the work area (a
    ///   child's parent's client area) with the sizing border outside it; the default clamp
    ///   follows.
    /// - Restored: the normal place.
    ///
    /// A command that would leave the window as it is does nothing.
    pub(super) fn min_maximize(
        s: &mut dyn Session,
        window: WindowId,
        command: i32,
    ) -> Result<(), Failure> {
        let windows = s.windows();
        enum State {
            Minimized,
            Maximized,
            Normal,
        }
        let style = windows.at(window).style;
        let minimized = style & WS_MINIMIZE != 0;
        let maximized = style & WS_MAXIMIZE != 0;
        let target = match command {
            SW_SHOWMINIMIZED | SW_MINIMIZE | SW_SHOWMINNOACTIVE | SW_FORCEMINIMIZE => {
                if minimized {
                    return Ok(());
                }
                State::Minimized
            }
            SW_SHOWMAXIMIZED => {
                if maximized {
                    return Ok(());
                }
                State::Maximized
            }
            _ if minimized && windows.at(window).restore_maximized => State::Maximized,
            _ if minimized || maximized => State::Normal,
            _ => return Ok(()),
        };
        // Maximized, the window takes WM_GETMINMAXINFO's size and place, asked before it changes.
        let mmi = match target {
            State::Maximized => {
                let mmi = s.min_max_info(window);
                if !s.windows().pool.is_live(window) {
                    return Err(Failure::InvalidWindowHandle);
                }
                mmi
            }
            _ => MinMaxInfo::unbounded(),
        };
        let windows = s.windows();
        let origin = windows.parent_origin(window);
        let here = windows
            .at(window)
            .window_rect
            .saturating_offset_back(origin.0, origin.1);
        {
            let w = windows.at_mut(window);
            if minimized {
                w.min_position = Some((here.left, here.top));
            } else if !maximized {
                w.normal = Some(here);
            }
        }
        let place = match target {
            State::Minimized => {
                let w = windows.at_mut(window);
                w.restore_maximized = maximized;
                w.style = (w.style | WS_MINIMIZE) & !WS_MAXIMIZE;
                let (x, y) = w.min_position.unwrap_or(MINIMIZED_POSITION);
                Rect {
                    left: x,
                    top: y,
                    right: x.saturating_add(MINIMIZED_SIZE.0),
                    bottom: y.saturating_add(MINIMIZED_SIZE.1),
                }
            }
            State::Maximized => {
                let (cx, cy) = windows.max_size_on_maximize(window, mmi.max_size);
                let w = windows.at_mut(window);
                w.style = (w.style | WS_MAXIMIZE) & !WS_MINIMIZE;
                let (x, y) = mmi.max_position;
                Rect {
                    left: x,
                    top: y,
                    right: x.saturating_add(cx.max(0)),
                    bottom: y.saturating_add(cy.max(0)),
                }
            }
            State::Normal => {
                let w = windows.at_mut(window);
                w.style &= !(WS_MINIMIZE | WS_MAXIMIZE);
                w.normal.unwrap_or(here)
            }
        };
        Windows::set_window_pos(
            s,
            window,
            InsertAfter::Top,
            place.left,
            place.top,
            place.width(),
            place.height(),
            SWP_NOZORDER | SWP_NOACTIVATE | SWP_FRAMECHANGED,
        )
    }

    /// The default window procedure's WM_WINDOWPOSCHANGING for `window` (Windows 2000's
    /// xxxHandleWindowPosChanging): a resize's size (`pos` without SWP_NOSIZE) clamped into the
    /// window's tracking sizes ([`Windows::adjust_size`], WM_GETMINMAXINFO sent for a tiled or
    /// thick-framed window).
    pub fn window_pos_changing<S: Session + ?Sized>(
        s: &mut S,
        window: WindowId,
        pos: &mut WindowPos,
    ) {
        if pos.flags & SWP_NOSIZE == 0 {
            Windows::adjust_size(s, window, &mut pos.cx, &mut pos.cy);
        }
    }

    /// The MINMAXINFO filled in for `window` before WM_GETMINMAXINFO goes (Windows 2000's
    /// xxxInitSendValidateMinMaxInfo):
    ///
    /// - maximized: the monitor (a child's parent's client area) with the sizing border on both
    ///   sides, the border's width outside the work area's corner (guigeo `mmdefault`), or where
    ///   SetWindowPlacement put it ([`Windows::maximized_rect`]);
    /// - min track: SM_CXMINTRACK by SM_CYMINTRACK (guigeo `defer` sizes 90 wide to 112);
    /// - max track: the screens' extent with a sizing border and an edge on each side (assumed: no
    ///   capture has it yet);
    /// - ptReserved: SM_CXMINIMIZED by SM_CYMINIMIZED (guigeo `mmdefault`: 160,24).
    pub fn default_min_max_info(&self, window: WindowId) -> MinMaxInfo {
        let max = self.maximized_rect(window, true);
        let screens = self.screens();
        let slack = 2 * (rtl::nonclient::FRAME + rtl::nonclient::EDGE);
        MinMaxInfo {
            reserved: MINIMIZED_SIZE,
            max_size: (
                max.right.saturating_sub(max.left),
                max.bottom.saturating_sub(max.top),
            ),
            max_position: (max.left, max.top),
            min_track: (rtl::nonclient::MIN_X, rtl::nonclient::MIN_Y),
            max_track: (
                screens.width().saturating_add(slack),
                screens.height().saturating_add(slack),
            ),
        }
    }

    /// The extent of every monitor together (the virtual screen).
    fn screens(&self) -> Rect {
        let mut all: Option<Rect> = None;
        for monitor in self.monitors.iter() {
            let r = monitor.rect;
            if r.right <= r.left || r.bottom <= r.top {
                continue;
            }
            all = Some(match all {
                None => r,
                Some(a) => Rect {
                    left: a.left.min(r.left),
                    top: a.top.min(r.top),
                    right: a.right.max(r.right),
                    bottom: a.bottom.max(r.bottom),
                },
            });
        }
        all.unwrap_or_default()
    }

    /// Where `window` goes maximized, in its parent's client coordinates: SetWindowPlacement's
    /// maximized position or the sizing border's width outside the work area (a child's parent's
    /// client area), as large as that area plus the border on both sides. With `monitor`, the
    /// whole monitor's size instead: the default ptMaxSize, which Windows 2000 takes from the
    /// monitor and its maximize brings back to the work area ([`Windows::max_size_on_maximize`]).
    fn maximized_rect(&self, window: WindowId, monitor: bool) -> Rect {
        let w = self.at(window);
        let (area, size) = match w.parent {
            Some(p) if w.is_child() && self.pool.is_live(p) => {
                let client = self.at(p).client_rect;
                let area = Rect {
                    left: 0,
                    top: 0,
                    right: client.right - client.left,
                    bottom: client.bottom - client.top,
                };
                (area, area)
            }
            _ => {
                let work = self.work_area(w.monitor);
                let size = if monitor {
                    self.monitors[w.monitor as usize].rect
                } else {
                    work
                };
                (work, size)
            }
        };
        let border = rtl::nonclient::Frame::of_styles(w.style & !WS_MINIMIZE, w.ex_style, false)
            .border_width;
        let (x, y) = w
            .max_position
            .unwrap_or((area.left - border, area.top - border));
        Rect {
            left: x,
            top: y,
            right: x.saturating_add((size.right - size.left).saturating_add(2 * border)),
            bottom: y.saturating_add((size.bottom - size.top).saturating_add(2 * border)),
        }
    }

    /// The size `window` takes maximized, WM_GETMINMAXINFO having answered `max_size`: the
    /// default's monitor size (with the border) becomes the work area's, as Windows 2000's
    /// maximize keeps a window off the taskbar; any other size the procedure chose stands.
    fn max_size_on_maximize(&self, window: WindowId, max_size: (i32, i32)) -> (i32, i32) {
        let monitor = self.maximized_rect(window, true);
        if max_size == (monitor.width(), monitor.height()) {
            let work = self.maximized_rect(window, false);
            (work.width(), work.height())
        } else {
            max_size
        }
    }
}

#[cfg(test)]
mod tests {
    use rtl::user::{
        WM_GETMINMAXINFO,
        WM_NCCREATE,
        WM_SIZE,
        WM_WINDOWPOSCHANGED,
        WS_OVERLAPPEDWINDOW,
        WS_POPUP,
        WS_VISIBLE,
    };
    use rtl::window::{
        SWP_HIDEWINDOW,
        SWP_NOCLIENTSIZE,
        SWP_NOMOVE,
        SW_HIDE,
        SW_RESTORE,
        SW_SHOWNORMAL,
    };

    use super::*;
    use crate::sched::thread::ThreadId;
    use crate::win32k::class;
    use crate::win32k::window::testkit::*;

    /// The window manager's MINMAXINFO before WM_GETMINMAXINFO goes: reserved, the minimized
    /// size; maximized, the monitor with the sizing border on both sides, placed the border's
    /// width outside the work area (where SetWindowPlacement's place says, when it has one);
    /// tracking from SM_CXMINTRACK by SM_CYMINTRACK to the screen with a border and an edge each
    /// side (guigeo `mmdefault`).
    #[test]
    fn the_min_max_defaults() {
        let (w, _, t, _, _, _) = setup();
        let id = raw_window(w, t, WS_OVERLAPPEDWINDOW, None);
        assert_eq!(
            w.default_min_max_info(id),
            MinMaxInfo {
                reserved: (160, 24),
                max_size: (648, 488),
                max_position: (-4, -4),
                min_track: (112, 27),
                max_track: (652, 492),
            }
        );
        w.at_mut(id).max_position = Some((30, 40));
        assert_eq!(w.default_min_max_info(id).max_position, (30, 40));
    }

    /// A tiled or thick-framed window's creation sends WM_GETMINMAXINFO first, with the defaults,
    /// and the procedure's tracking sizes clamp the size asked (guigeo `edits`: 100x100 asked,
    /// 300x250 the minimum); a popup without a sizing border hears no WM_GETMINMAXINFO.
    #[test]
    fn the_creation_asks_for_the_tracking_sizes() {
        let (w, c, t, atom, _, _) = setup();
        let mut pump = Rec::new(t);
        pump.mmi = Some(MinMaxInfo {
            min_track: (300, 250),
            max_track: (400, 300),
            ..MinMaxInfo::unbounded()
        });
        let mut a = args(atom, WS_OVERLAPPEDWINDOW);
        a.cx = 100;
        a.cy = 100;
        let id = Windows::create_window_ex(&mut pump.on(w, c), t, &a).unwrap();
        let first = pump
            .events
            .iter()
            .position(|e| matches!(e, Ev::MinMaxInfo(_) | Ev::Send(..)));
        assert_eq!(pump.events[first.unwrap()], Ev::MinMaxInfo(id));
        assert_eq!(pump.minmax_sent[0], (id, w.default_min_max_info(id)));
        let r = w.at(id).window_rect;
        assert_eq!((r.width(), r.height()), (300, 250));

        let mut pump = Rec::new(t);
        Windows::create_window_ex(&mut pump.on(w, c), t, &args(atom, WS_POPUP)).unwrap();
        assert!(pump.minmax_sent.is_empty());
    }

    /// A procedure that destroys its window during the creation's WM_GETMINMAXINFO ends the
    /// creation: nothing more is sent, and no window is made.
    #[test]
    fn a_window_destroyed_in_its_min_max_info_is_not_made() {
        let (w, c, t, atom, _, _) = setup();
        let mut pump = Rec::new(t);
        let a = args(atom, WS_OVERLAPPEDWINDOW);
        let mut session = pump.on(w, c);
        struct Destroying<'a, 'b>(&'a mut RecSession<'b>, ThreadId);
        impl Session for Destroying<'_, '_> {
            fn parts(&mut self) -> (&mut Windows, &mut class::Registry) {
                self.0.parts()
            }

            fn send(&mut self, target: WindowId, message: &mut Message) -> LResult {
                if message.message == WM_GETMINMAXINFO {
                    let caller = self.1;
                    let _ = Windows::destroy_window(self, caller, target);
                    return 0;
                }
                self.0.send(target, message)
            }
        }
        let mut destroying = Destroying(&mut session, t);
        assert_eq!(
            Windows::create_window_ex(&mut destroying, t, &a),
            Err(Failure::Refused)
        );
        assert!(!pump.messages().contains(&WM_NCCREATE));
    }

    /// The default procedure's WM_WINDOWPOSCHANGING clamps a resize into the procedure's tracking
    /// sizes (guigeo `edits`: 100x100 to the minimum 300x250, 600x450 to the maximum 400x300,
    /// 350x280 as asked); a move alone (SWP_NOSIZE) asks for none, and a popup without a sizing
    /// border is not clamped.
    #[test]
    fn the_default_window_pos_changing_clamps_a_resize() {
        let (w, c, t, atom, _, _) = setup();
        let mut pump = Rec::new(t);
        pump.mmi = Some(MinMaxInfo {
            min_track: (300, 250),
            max_track: (400, 300),
            ..MinMaxInfo::unbounded()
        });
        let id = create(w, c, t, atom, WS_OVERLAPPEDWINDOW, &mut pump).unwrap();
        let flags = SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE;
        for ((cx, cy), want) in [
            ((350, 280), (350, 280)),
            ((100, 100), (300, 250)),
            ((600, 450), (400, 300)),
        ] {
            Windows::set_window_pos(
                &mut pump.on(w, c),
                id,
                InsertAfter::Top,
                0,
                0,
                cx,
                cy,
                flags,
            )
            .unwrap();
            let r = w.at(id).window_rect;
            assert_eq!((r.width(), r.height()), want, "{cx}x{cy}");
        }
        pump.minmax_sent.clear();
        Windows::set_window_pos(
            &mut pump.on(w, c),
            id,
            InsertAfter::Top,
            5,
            5,
            0,
            0,
            SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE,
        )
        .unwrap();
        assert!(pump.minmax_sent.is_empty());

        let popup = create(w, c, t, atom, WS_POPUP, &mut pump).unwrap();
        Windows::set_window_pos(
            &mut pump.on(w, c),
            popup,
            InsertAfter::Top,
            0,
            0,
            20,
            10,
            flags,
        )
        .unwrap();
        let r = w.at(popup).window_rect;
        assert_eq!((r.width(), r.height()), (20, 10));
    }

    /// A procedure's MINMAXINFO is untrusted: a minimum above the maximum takes the minimum, a
    /// negative size becomes an empty window, extreme values saturate.
    #[test]
    fn a_wild_min_max_answer_stays_bounded() {
        let (w, c, t, atom, _, _) = setup();
        let mut pump = Rec::new(t);
        let id = create(w, c, t, atom, WS_OVERLAPPEDWINDOW, &mut pump).unwrap();
        let flags = SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE;
        pump.mmi = Some(MinMaxInfo {
            min_track: (500, 400),
            max_track: (100, 100),
            ..MinMaxInfo::unbounded()
        });
        Windows::set_window_pos(
            &mut pump.on(w, c),
            id,
            InsertAfter::Top,
            0,
            0,
            200,
            200,
            flags,
        )
        .unwrap();
        let r = w.at(id).window_rect;
        assert_eq!((r.width(), r.height()), (500, 400));
        pump.mmi = Some(MinMaxInfo {
            min_track: (i32::MIN, i32::MIN),
            max_track: (-50, -60),
            ..MinMaxInfo::unbounded()
        });
        Windows::set_window_pos(
            &mut pump.on(w, c),
            id,
            InsertAfter::Top,
            0,
            0,
            200,
            200,
            flags,
        )
        .unwrap();
        let r = w.at(id).window_rect;
        assert_eq!((r.width(), r.height()), (0, 0));
        pump.mmi = Some(MinMaxInfo {
            max_size: (i32::MAX, -7),
            max_position: (i32::MAX, i32::MIN),
            ..MinMaxInfo::unbounded()
        });
        assert!(Windows::show_window(&mut pump.on(w, c), id, SW_SHOWMAXIMIZED).is_ok());
        let r = w.at(id).window_rect;
        assert_eq!((r.left, r.top), (i32::MAX, i32::MIN));
        assert_eq!(r.height(), 0);
    }

    /// Maximized, a window takes the procedure's ptMaxSize at its ptMaxPosition (guigeo `edits`:
    /// 380x280 at 20,30), inside its tracking sizes.
    #[test]
    fn a_maximized_window_takes_the_procedures_max_size_and_place() {
        let (w, c, t, atom, _, _) = setup();
        let mut pump = Rec::new(t);
        pump.mmi = Some(MinMaxInfo {
            max_size: (380, 280),
            max_position: (20, 30),
            min_track: (300, 250),
            max_track: (400, 300),
            ..MinMaxInfo::unbounded()
        });
        let id = create(w, c, t, atom, WS_OVERLAPPEDWINDOW, &mut pump).unwrap();
        assert!(Windows::show_window(&mut pump.on(w, c), id, SW_SHOWMAXIMIZED).is_ok());
        assert_eq!(
            w.at(id).window_rect,
            Rect {
                left: 20,
                top: 30,
                right: 400,
                bottom: 310
            }
        );
    }

    /// guigeo minmax: min/max commands (and restoring a minimized window) go through the min/max
    /// seam, then change style and place through SetWindowPos (its WM_SIZE replaces the deferred
    /// WM_SIZE and WM_MOVE). Maximized fills the work area, border outside; minimized goes to
    /// (-32000, -32000), client empty; minimized from maximized restores to maximized, then normal.
    #[test]
    fn min_max_and_restore() {
        let (w, c, t, atom, _, _) = setup();
        let mut pump = Rec::new(t);
        let id = create(w, c, t, atom, WS_OVERLAPPEDWINDOW, &mut pump).unwrap();
        assert!(w.at(id).flags.sendsizemove);
        let flags = SWP_NOZORDER | SWP_NOACTIVATE;
        Windows::set_window_pos(
            &mut pump.on(w, c),
            id,
            InsertAfter::Top,
            50,
            60,
            200,
            150,
            flags,
        )
        .unwrap();
        assert!(!w.at(id).flags.sendsizemove, "the client area changed");
        let normal = Rect {
            left: 50,
            top: 60,
            right: 250,
            bottom: 210,
        };
        pump.events.clear();
        assert_eq!(
            Windows::show_window(&mut pump.on(w, c), id, SW_SHOWMAXIMIZED),
            Ok(false)
        );
        assert_eq!(pump.events[0], Ev::MinMax(id, SW_SHOWMAXIMIZED as u32));
        assert_eq!(
            w.at(id).style & (WS_MINIMIZE | WS_MAXIMIZE | WS_VISIBLE),
            WS_MAXIMIZE | WS_VISIBLE
        );
        assert_eq!(
            w.at(id).window_rect,
            Rect {
                left: -4,
                top: -4,
                right: 644,
                bottom: 484
            }
        );
        assert_eq!(
            pump.messages()
                .iter()
                .filter(|&&m| m == WM_WINDOWPOSCHANGED)
                .count(),
            2,
            "the maximize's, then the show's"
        );
        assert!(!pump.messages().contains(&WM_SIZE), "no deferred WM_SIZE");

        Windows::show_window(&mut pump.on(w, c), id, SW_MINIMIZE).unwrap();
        let minimized = w.at(id);
        assert_eq!(minimized.style & (WS_MINIMIZE | WS_MAXIMIZE), WS_MINIMIZE);
        assert_eq!(
            minimized.window_rect,
            Rect {
                left: -32000,
                top: -32000,
                right: -31840,
                bottom: -31976
            }
        );
        let client = minimized.client_rect;
        assert_eq!((client.left, client.right - client.left), (-32000, 0));
        assert!(minimized.restore_maximized);
        let placement = w.window_placement(id);
        assert_eq!(
            (placement.show_cmd, placement.flags, placement.min_x),
            (
                SW_SHOWMINIMIZED as u32,
                rtl::window::WPF_RESTORETOMAXIMIZED,
                -32000
            )
        );
        assert_eq!(placement.normal, normal);

        Windows::show_window(&mut pump.on(w, c), id, SW_RESTORE).unwrap();
        assert_eq!(w.at(id).style & (WS_MINIMIZE | WS_MAXIMIZE), WS_MAXIMIZE);
        Windows::show_window(&mut pump.on(w, c), id, SW_RESTORE).unwrap();
        assert_eq!(w.at(id).style & (WS_MINIMIZE | WS_MAXIMIZE), 0);
        assert_eq!(w.at(id).window_rect, normal);
        let placement = w.window_placement(id);
        assert_eq!(
            (
                placement.show_cmd,
                placement.flags,
                placement.min_x,
                placement.max_x
            ),
            (
                SW_SHOWNORMAL as u32,
                rtl::window::WPF_RESTORETOMAXIMIZED,
                -32000,
                -1
            )
        );

        // From the normal state a minimized window restores to it.
        Windows::show_window(&mut pump.on(w, c), id, SW_MINIMIZE).unwrap();
        assert!(!w.at(id).restore_maximized);
        Windows::show_window(&mut pump.on(w, c), id, SW_SHOWNORMAL).unwrap();
        assert_eq!(w.at(id).window_rect, normal);
    }

    /// guigeo `createmax`: a window created with WS_MAXIMIZE or WS_MINIMIZE is maximized or
    /// minimized at its creation, hidden or not, its normal place the one asked (SW_RESTORE brings
    /// it back there); the WM_WINDOWPOSCHANGED of that change leaves a tiled window's deferred
    /// WM_SIZE and WM_MOVE to its first show (Windows 2000's WS_VISIBLE window gets two WM_SIZEs).
    #[test]
    fn a_window_is_created_maximized_or_minimized() {
        let (w, c, t, atom, _, _) = setup();
        let asked = Rect {
            left: 10,
            top: 20,
            right: 310,
            bottom: 220,
        };
        for (bit, visible) in [
            (WS_MAXIMIZE, 0),
            (WS_MAXIMIZE, WS_VISIBLE),
            (WS_MINIMIZE, 0),
            (WS_MINIMIZE, WS_VISIBLE),
        ] {
            let mut pump = Rec::new(t);
            let mut a = args(atom, WS_OVERLAPPEDWINDOW | bit | visible);
            (a.cx, a.cy) = (300, 200);
            let id = Windows::create_window_ex(&mut pump.on(w, c), t, &a).unwrap();
            assert_eq!(
                w.at(id).style & (WS_MINIMIZE | WS_MAXIMIZE | WS_VISIBLE),
                bit | visible
            );
            let rect = w.at(id).window_rect;
            if bit == WS_MAXIMIZE {
                assert_eq!(rect, Rect::new(-4, -4, 644, 484));
            } else {
                assert_eq!((rect.left, rect.top), MINIMIZED_POSITION);
            }
            let changed = pump
                .messages()
                .iter()
                .filter(|&&m| m == WM_WINDOWPOSCHANGED)
                .count();
            let deferred = pump.messages().contains(&WM_SIZE);
            let (_, _, first) = *pump
                .positions
                .iter()
                .find(|(_, m, _)| *m == WM_WINDOWPOSCHANGED)
                .unwrap();
            assert_eq!(
                first.flags & SWP_NOCLIENTSIZE,
                0,
                "its client area changed: the default procedure's WM_SIZE"
            );
            assert_eq!(
                (changed, deferred, w.at(id).flags.sendsizemove),
                if visible != 0 {
                    (2, true, false)
                } else {
                    (1, false, true)
                },
                "the change's, then the show's and its deferred WM_SIZE"
            );
            Windows::show_window(&mut pump.on(w, c), id, SW_RESTORE).unwrap();
            assert_eq!(w.at(id).style & (WS_MINIMIZE | WS_MAXIMIZE), 0);
            assert_eq!(w.at(id).window_rect, asked);
            assert!(!w.at(id).flags.sendsizemove);
        }
    }

    /// A minimized window hidden reports its client area sized, so the default procedure sends it a
    /// WM_SIZE of SIZE_MINIMIZED (the guigeo capture's minmax); another window hidden does not.
    #[test]
    fn a_minimized_window_hidden_reports_its_size() {
        let (w, c, t, atom, _, _) = setup();
        let mut pump = Rec::new(t);
        let id = create(w, c, t, atom, WS_OVERLAPPEDWINDOW, &mut pump).unwrap();
        Windows::show_window(&mut pump.on(w, c), id, SW_MINIMIZE).unwrap();
        pump.positions.clear();
        assert_eq!(
            Windows::show_window(&mut pump.on(w, c), id, SW_HIDE),
            Ok(true)
        );
        let (_, message, changed) = *pump.positions.last().unwrap();
        assert_eq!(message, WM_WINDOWPOSCHANGED);
        assert_eq!(
            changed.flags & (SWP_HIDEWINDOW | SWP_NOCLIENTSIZE),
            SWP_HIDEWINDOW
        );
        Windows::show_window(&mut pump.on(w, c), id, SW_SHOWNORMAL).unwrap();
        pump.positions.clear();
        Windows::show_window(&mut pump.on(w, c), id, SW_HIDE).unwrap();
        let (_, _, changed) = *pump.positions.last().unwrap();
        assert_ne!(changed.flags & SWP_NOCLIENTSIZE, 0);
    }

    /// A minimized position and a maximized position at i32's end (SetWindowPlacement's): the
    /// window minimized and maximized there, its far edges saturated.
    #[test]
    fn minimized_and_maximized_positions_at_i32s_end_saturate() {
        use rtl::window::WPF_SETMINPOSITION;

        use crate::win32k::queue::{rig, QueueSession};
        let (m, atom) = rig::manager();
        let t = rig::thread(m, 1, 0x10);
        let h = rig::window_at(m, atom, t, WS_OVERLAPPEDWINDOW, 0, 0, 0, 200, 100);
        let at = i32::MAX - 10;
        let placement = rtl::window::WindowPlacement {
            length: core::mem::size_of::<rtl::window::WindowPlacement>() as u32,
            flags: WPF_SETMINPOSITION,
            show_cmd: SW_HIDE as u32,
            min_x: at,
            min_y: at,
            max_x: at,
            max_y: at,
            normal: Rect {
                left: 0,
                top: 0,
                right: 200,
                bottom: 100,
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
        let far = Rect {
            left: at,
            top: at,
            right: i32::MAX,
            bottom: i32::MAX,
        };
        assert!(WindowManager::show_window(
            &mut QueueSession::new(&mut m.windows, &mut m.classes),
            h,
            SW_MINIMIZE
        )
        .is_ok());
        assert_eq!(m.windows.window_rect(w), far);
        assert!(WindowManager::show_window(
            &mut QueueSession::new(&mut m.windows, &mut m.classes),
            h,
            SW_SHOWMAXIMIZED
        )
        .is_ok());
        assert_eq!(m.windows.window_rect(w), far);
    }
}
