//! A new window's place: CW_USEDEFAULT, a child's offset, the tiled cascade and monitor clamping.

use rtl::gdi::Rect;
use rtl::user::{WS_BORDER, WS_CAPTION, WS_CLIPSIBLINGS, WS_EX_WINDOWEDGE};
use rtl::window::SW_SHOW;

use super::*;
use crate::sched::thread::ThreadId;

/// Whether `value` is one of the two CW_USEDEFAULT markers.
fn is_default_position(value: i32) -> bool {
    value == CW_USEDEFAULT || value == CW_USEDEFAULT_ALT
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

/// A new window's place, as [`Windows::place_new_window`] decides it.
pub(super) struct Placement {
    pub(super) z_order: ZOrder,
    pub(super) tiled: bool,
    pub(super) x: i32,
    pub(super) y: i32,
    pub(super) cx: i32,
    pub(super) cy: i32,
    pub(super) src: SizeRect,
    pub(super) sw: i32,
}

impl Windows {
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

    /// The new window `id`'s place: CW_USEDEFAULT, a child's offset, the tiled cascade and
    /// monitor clamping, and the clip and caption bits they force.
    pub(super) fn place_new_window(
        &mut self,
        caller: ThreadId,
        id: WindowId,
        args: &CreateArgs,
        child: bool,
        desktop_window: Option<WindowId>,
    ) -> Placement {
        let windows = self;
        let mut z_order = ZOrder::Top;
        let tiled = windows.at(id).kind() == Kind::Tiled;

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
                    let p = windows.at(parent);
                    src.x = src.x.saturating_add(p.client_rect.left);
                    src.y = src.y.saturating_add(p.client_rect.top);
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
                let w = windows.at_mut(id);
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
            let monitor = windows
                .thread(caller)
                .monitor
                .or_else(|| args.parent.map(|p| windows.at(p).monitor))
                .unwrap_or(PRIMARY_MONITOR);
            windows.set_tiled_rect(&mut rc, monitor);
            if is_default_position(x) {
                // Default positioning: the startup info, else the cascade rect.
                let usi = windows.thread(caller).startup;
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
            } else if windows.monitors[monitor as usize].window_stack > 0 {
                // An app-specified position undoes the cascade's stacking effect.
                windows.monitors[monitor as usize].window_stack -= 1;
            }
            if is_default_position(src.cx) {
                // Default sizing: the startup info, else fill the cascade rect.
                let usi = windows.thread(caller).startup;
                if usi.flags & STARTF_USESIZE != 0 {
                    startup = true;
                    src.cx = usi.cx as i32;
                    src.cy = usi.cy as i32;
                } else {
                    src.cx = rc.right.saturating_sub(x);
                    src.cy = rc.bottom.saturating_sub(y);
                }
            } else if def_pos {
                // A default position with an app size: keep the window inside the monitor.
                let m = windows.monitors[monitor as usize].rect;
                let dx = src.x.saturating_add(src.cx).saturating_sub(m.right);
                let dy = src.y.saturating_add(src.cy).saturating_sub(m.bottom);
                if dx > 0 {
                    x = x.saturating_sub(dx);
                    src.x = x;
                    if src.x < m.left {
                        src.x = m.left;
                        x = src.x;
                    }
                }
                if dy > 0 {
                    y = y.saturating_sub(dy);
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
            windows.thread_mut(caller).startup.flags &= !(STARTF_USESIZE | STARTF_USEPOSITION);
        }

        // Popup windows clip their siblings (the desktop window excepted).
        if windows.at(id).kind() == Kind::Popup && Some(id) != desktop_window {
            windows.at_mut(id).style |= WS_CLIPSIBLINGS;
        }

        // The forced caption/border bits go into the style's high word.
        if tiled {
            windows.at_mut(id).style |= WS_CAPTION | WS_BORDER;
        }
        Placement {
            z_order,
            tiled,
            x,
            y,
            cx,
            cy,
            src,
            sw,
        }
    }
}

#[cfg(test)]
mod tests {
    use rtl::user::{WS_CHILD, WS_OVERLAPPED, WS_POPUP, WS_THICKFRAME, WS_VISIBLE};
    use rtl::window::{SWP_NOACTIVATE, SWP_NOMOVE, SWP_NOSIZE, SWP_SHOWWINDOW, SW_SHOWNA};

    use super::*;
    use crate::win32k::window::testkit::*;

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
        let id = Windows::create_window_ex(&mut pump.on(w, c), t, &a).unwrap();
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
        let id = Windows::create_window_ex(&mut pump.on(w, c), t, &a).unwrap();
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
        let first = Windows::create_window_ex(&mut pump.on(w, c), t, &a).unwrap();
        assert_eq!(
            w.at(first).window_rect,
            Rect {
                left: 15,
                top: 26,
                right: 45,
                bottom: 66
            }
        );
        let second = Windows::create_window_ex(&mut pump.on(w, c), t, &a).unwrap();
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
        let id = Windows::create_window_ex(&mut pump.on(w, c), t, &a).unwrap();
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
        let id = Windows::create_window_ex(&mut pump.on(w, c), t, &a).unwrap();
        // SW_SHOWNA: shown at the top of the z-order, not activated.
        let show = SWP_SHOWWINDOW | SWP_NOMOVE | SWP_NOSIZE;
        assert_eq!(pump.changing_flags(), vec![(id, show | SWP_NOACTIVATE)]);
        assert!(!pump.events.iter().any(|e| matches!(e, Ev::Activate(..))));
        assert!(w.at(id).is_visible());
        // With y also default: SW_SHOW, which activates.
        let mut pump = Rec::new(t);
        let mut a = args(atom, WS_OVERLAPPED | WS_VISIBLE);
        a.x = CW_USEDEFAULT;
        a.y = CW_USEDEFAULT;
        let id = Windows::create_window_ex(&mut pump.on(w, c), t, &a).unwrap();
        assert_eq!(pump.changing_flags(), vec![(id, show)]);
        assert!(pump.events.contains(&Ev::Activate(id, Activate::Try)));
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
        let id = Windows::create_window_ex(&mut pump.on(w, c), t, &a).unwrap();
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
        let id = Windows::create_window_ex(&mut pump.on(w, c), t, &a).unwrap();
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
        let id = Windows::create_window_ex(&mut pump.on(w, c), t, &a).unwrap();
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
        // The placement alone: no tracking sizes.
        pump.mmi = Some(MinMaxInfo::unbounded());
        let mut a = args(atom, WS_OVERLAPPED);
        a.x = CW_USEDEFAULT;
        a.cx = 700;
        a.cy = 100;
        let id = Windows::create_window_ex(&mut pump.on(w, c), t, &a).unwrap();
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
        let id = Windows::create_window_ex(&mut pump.on(w, c), t, &a).unwrap();
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
        // The placement alone: no tracking sizes.
        pump.mmi = Some(MinMaxInfo::unbounded());
        let mut a = args(atom, WS_OVERLAPPED);
        a.x = CW_USEDEFAULT;
        a.cx = CW_USEDEFAULT;
        let id = Windows::create_window_ex(&mut pump.on(w, c), t, &a).unwrap();
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
        let id = Windows::create_window_ex(&mut pump.on(w, c), t, &a).unwrap();
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
        let id = Windows::create_window_ex(&mut pump.on(w, c), t, &a).unwrap();
        assert_eq!(w.at(id).style & WS_CLIPSIBLINGS, WS_CLIPSIBLINGS);
        // The min/max track clamp on a thick-framed window.
        pump.mmi = Some(MinMaxInfo {
            min_track: (100, 50),
            max_track: (200, 150),
            ..MinMaxInfo::unbounded()
        });
        let mut a = args(atom, WS_OVERLAPPED | WS_THICKFRAME);
        a.cx = 30;
        a.cy = 10_000;
        let id = Windows::create_window_ex(&mut pump.on(w, c), t, &a).unwrap();
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
        let id = Windows::create_window_ex(&mut pump.on(w, c), t, &a).unwrap();
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

    /// CreateWindowEx at (0x7FFFFFF0, 0x7FFFFFF0), 100 by 100: the window's far edges saturated; a
    /// child placed past i32's end of its parent's client area, saturated there.
    #[test]
    fn create_window_saturates_an_extreme_rectangle() {
        use crate::win32k::queue::rig;
        let (m, atom) = rig::manager();
        let t = rig::thread(m, 1, 0x10);
        let at = 0x7FFF_FFF0;
        let h = rig::window_at(m, atom, t, WS_POPUP, 0, at, at, 100, 100);
        let w = m.windows.window_of(h).unwrap();
        let extreme = Rect {
            left: at,
            top: at,
            right: i32::MAX,
            bottom: i32::MAX,
        };
        assert_eq!(m.windows.window_rect(w), extreme);
        let parent = rig::window_at(m, atom, t, WS_POPUP, 0, 200, 150, 300, 200);
        let child = rig::window_at(m, atom, t, WS_CHILD, parent, at, 0, 10, 10);
        let child = m.windows.window_of(child).unwrap();
        assert_eq!(
            m.windows.window_rect(child),
            Rect {
                left: i32::MAX,
                top: 150,
                right: i32::MAX,
                bottom: 160
            }
        );
    }
}
