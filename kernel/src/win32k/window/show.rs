//! ShowWindow's decision.

use rtl::user::{WM_MOVE, WM_SHOWWINDOW, WS_MAXIMIZE, WS_MINIMIZE, WS_VISIBLE};
use rtl::window::{
    SWP_HIDEWINDOW,
    SWP_NOACTIVATE,
    SWP_NOMOVE,
    SWP_NOSIZE,
    SWP_NOZORDER,
    SWP_SHOWWINDOW,
    SW_FORCEMINIMIZE,
    SW_HIDE,
    SW_MAX,
    SW_MINIMIZE,
    SW_RESTORE,
    SW_SHOWDEFAULT,
    SW_SHOWMAXIMIZED,
    SW_SHOWMINIMIZED,
    SW_SHOWMINNOACTIVE,
    SW_SHOWNA,
    SW_SHOWNOACTIVATE,
    SW_SHOWNORMAL,
};

use super::*;

/// The show commands that minimize, maximize or restore the window before the show
/// ([`Windows::min_maximize`], after the min/max seam, [`Session::min_maximize`]): the minimizing
/// ones and the maximizing one, always; restoring ones only from a minimized or maximized window.
fn min_max_command(command: i32, style: u32) -> bool {
    match command {
        SW_SHOWMINIMIZED | SW_MINIMIZE | SW_SHOWMINNOACTIVE | SW_FORCEMINIMIZE
        | SW_SHOWMAXIMIZED => true,
        SW_SHOWNORMAL | SW_RESTORE | SW_SHOWDEFAULT => style & (WS_MINIMIZE | WS_MAXIMIZE) != 0,
        _ => false,
    }
}

impl Windows {
    /// ShowWindow's decision for `window`: answers whether it was visible before;
    /// ERROR_INVALID_PARAMETER for a command past SW_MAX.
    ///
    /// A visibility change sends WM_SHOWWINDOW (not for SW_SHOWNORMAL) and goes through
    /// [`Windows::set_window_pos`] without moving, sizing or reordering. SW_SHOWNA,
    /// SW_SHOWNOACTIVATE, the minimizing commands and any child's show leave activation alone. A
    /// top-level window shown comes to the top of the z-order, activated or not (the focus
    /// capture); a child keeps its place. A visible window shown again is only activated. Hiding
    /// the active top-level window activates the next one. Min/max/restore commands go through
    /// [`Windows::min_maximize`] first. A tiled window's first show sends its deferred WM_SIZE and
    /// WM_MOVE, unless a client-area change sent them since.
    pub fn show_window(
        s: &mut dyn Session,
        window: WindowId,
        command: i32,
    ) -> Result<bool, Failure> {
        let windows = s.windows();
        if !(SW_HIDE..=SW_MAX).contains(&command) {
            return Err(Failure::InvalidParameter);
        }
        let was_visible = windows.at(window).is_visible();
        let child = windows.at(window).is_child();
        let show = command != SW_HIDE;
        let activate = !child
            && !matches!(
                command,
                SW_HIDE
                    | SW_SHOWNA
                    | SW_SHOWNOACTIVATE
                    | SW_SHOWMINNOACTIVE
                    | SW_MINIMIZE
                    | SW_FORCEMINIMIZE
            );

        if min_max_command(command, windows.at(window).style) {
            s.min_maximize(window, command as u32);
            Windows::min_maximize(s, window, command)?;
            let windows = s.windows();
            if !windows.pool.is_live(window) {
                return Ok(was_visible);
            }
        }

        if show != was_visible {
            if command != SW_SHOWNORMAL {
                s.send(
                    window,
                    &mut Message {
                        message: WM_SHOWWINDOW,
                        wparam: show as WParam,
                        lparam: 0,
                        payload: Payload::None,
                    },
                );
                let windows = s.windows();
                if !windows.pool.is_live(window) {
                    return Ok(was_visible);
                }
            }
            let flags = SWP_NOMOVE
                | SWP_NOSIZE
                | if show && !child { 0 } else { SWP_NOZORDER }
                | if show {
                    SWP_SHOWWINDOW | SWP_SHOWWINDOW_CALL
                } else {
                    SWP_HIDEWINDOW
                }
                | if activate { 0 } else { SWP_NOACTIVATE };
            Windows::set_window_pos(s, window, InsertAfter::Top, 0, 0, 0, 0, flags)?;
        } else if show && activate {
            s.activate(window, Activate::Try);
        }
        let windows = s.windows();
        // A handler may have destroyed the window: nothing is left to do.
        if !windows.pool.is_live(window) {
            return Ok(was_visible);
        }

        // The hidden window was its thread's active one: the next one is activated.
        if !show && was_visible && !child {
            let thread = windows.at(window).thread;
            if windows.thread(thread).active == Some(window) {
                s.activate(window, Activate::Skip);
            }
        }
        let windows = s.windows();

        // The size and position messages a tiled window's creation deferred to its first show.
        if windows.at(window).flags.sendsizemove {
            windows.at_mut(window).flags.sendsizemove = false;
            let style = windows.at(window).style;
            let size = if style & WS_MINIMIZE != 0 {
                SIZE_MINIMIZED
            } else if style & WS_MAXIMIZE != 0 {
                SIZE_MAXIMIZED
            } else {
                SIZENORMAL
            };
            s.send_size(window, size);
            let windows = s.windows();
            let (x, y) = windows.client_position(window);
            s.send(
                window,
                &mut Message {
                    message: WM_MOVE,
                    wparam: 0,
                    lparam: makelong(x as u16, y as u16) as LParam,
                    payload: Payload::None,
                },
            );
        }
        Ok(was_visible)
    }
}

impl WindowManager {
    /// NtUserShowWindow's decision over a handle ([`Windows::show_window`]). The answer is
    /// ShowWindow's: the window's former visibility as the style's state byte holds it, WS_VISIBLE
    /// shifted down to it — 16 for a window that was visible, 0 for one that was not, as Windows
    /// 2000's ShowWindow answers (the guigeo capture).
    pub fn show_window(s: &mut dyn Session, handle: Hwnd, command: i32) -> Result<u32, Failure> {
        let windows = s.windows();
        let window = windows.window_of(handle)?;
        let was_visible = Windows::show_window(s, window, command)?;
        Ok(if was_visible { WS_VISIBLE >> 24 } else { 0 })
    }

    /// NtUserShowWindowAsync's decision over a handle: the command checked, the show carried out
    /// at once; only success is answered.
    pub fn show_window_async(
        s: &mut dyn Session,
        handle: Hwnd,
        command: i32,
    ) -> Result<(), Failure> {
        WindowManager::show_window(s, handle, command).map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use rtl::testing::wide;
    use rtl::user::{
        WM_SIZE,
        WM_WINDOWPOSCHANGED,
        WM_WINDOWPOSCHANGING,
        WS_OVERLAPPED,
        WS_OVERLAPPEDWINDOW,
        WS_POPUP,
    };
    use rtl::window::{QUERY_WINDOW_VISIBLE, SW_SHOW};

    use super::*;
    use crate::win32k::class;
    use crate::win32k::window::testkit::*;

    /// The flags every visibility-only position change carries.
    const SHOW_ONLY: u32 = SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER;

    /// ShowWindow's answers and messages, as the guigeo capture's show block runs them: the former
    /// visibility each time; WM_SHOWWINDOW and the position change only when the visibility
    /// changes, a top-level window shown coming to the top of the z-order; a hide of a hidden
    /// window does nothing; SW_SHOWNORMAL sends no WM_SHOWWINDOW; a command past SW_MAX is
    /// ERROR_INVALID_PARAMETER.
    #[test]
    fn show_window_answers_the_former_visibility() {
        let (w, c, t, atom, _, _) = setup();
        let mut pump = Rec::new(t);
        let id = create(w, c, t, atom, WS_POPUP, &mut pump).unwrap();
        pump.events.clear();
        assert_eq!(
            Windows::show_window(&mut pump.on(w, c), id, SW_SHOW),
            Ok(false)
        );
        assert!(w.at(id).is_visible());
        assert_eq!(
            pump.sends(),
            vec![
                (id, WM_SHOWWINDOW),
                (id, WM_WINDOWPOSCHANGING),
                (id, WM_WINDOWPOSCHANGED)
            ]
        );
        assert!(pump.events.contains(&Ev::Send(id, WM_SHOWWINDOW, 1, 0)));
        assert_eq!(
            pump.changing_flags(),
            vec![(id, SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW)]
        );
        assert!(pump.events.contains(&Ev::Activate(id, Activate::Try)));

        pump.events.clear();
        pump.positions.clear();
        assert_eq!(
            Windows::show_window(&mut pump.on(w, c), id, SW_HIDE),
            Ok(true)
        );
        assert!(!w.at(id).is_visible());
        assert!(pump.events.contains(&Ev::Send(id, WM_SHOWWINDOW, 0, 0)));
        assert_eq!(
            pump.changing_flags(),
            vec![(id, SHOW_ONLY | SWP_HIDEWINDOW | SWP_NOACTIVATE)]
        );

        // Hidden already: nothing happens.
        pump.events.clear();
        assert_eq!(
            Windows::show_window(&mut pump.on(w, c), id, SW_HIDE),
            Ok(false)
        );
        assert!(pump.events.is_empty());

        // SW_SHOWNORMAL: no WM_SHOWWINDOW (its documentation), the show all the same.
        assert_eq!(
            Windows::show_window(&mut pump.on(w, c), id, SW_SHOWNORMAL),
            Ok(false)
        );
        assert!(w.at(id).is_visible());
        assert!(!pump.messages().contains(&WM_SHOWWINDOW));

        // Visible already: activated, nothing else.
        pump.events.clear();
        assert_eq!(
            Windows::show_window(&mut pump.on(w, c), id, SW_SHOW),
            Ok(true)
        );
        assert_eq!(pump.events, vec![Ev::Activate(id, Activate::Try)]);
        pump.events.clear();
        assert_eq!(
            Windows::show_window(&mut pump.on(w, c), id, SW_SHOWNA),
            Ok(true)
        );
        assert!(pump.events.is_empty());

        for command in [-1, SW_MAX + 1, 0x100] {
            assert_eq!(
                Windows::show_window(&mut pump.on(w, c), id, command),
                Err(Failure::InvalidParameter)
            );
        }
    }

    /// The service's answer: 16 for a window that was visible — WS_VISIBLE in the style's state
    /// byte, as the capture's ShowWindow(SW_HIDE) answers — 0 for one that was not; the async
    /// show is carried out at once; a bogus handle is ERROR_INVALID_WINDOW_HANDLE.
    #[test]
    fn the_show_services_answer_as_the_capture() {
        let m = manager();
        m.boot_desktop(DESKTOP, SCREEN).unwrap();
        register(
            &mut m.classes,
            &m.windows.handles,
            class::Name::Text(&wide("App")),
            &wnd_class(),
        );
        let t = m
            .windows
            .connect_thread(key(1, 0), OWNER, DESKTOP, DESKTOP_CREATEWINDOW, 0x10)
            .unwrap();
        let name = wide("App");
        let mut a = args(0, WS_OVERLAPPEDWINDOW);
        a.class_name = class::Name::Text(&name);
        let h = WindowManager::create_window(
            &mut DefaultSession::new(&mut m.windows, &mut m.classes),
            t,
            0,
            &mut a,
        )
        .unwrap();
        assert_eq!(
            WindowManager::show_window(
                &mut DefaultSession::new(&mut m.windows, &mut m.classes),
                h,
                SW_SHOW
            ),
            Ok(0)
        );
        assert_eq!(
            WindowManager::show_window(
                &mut DefaultSession::new(&mut m.windows, &mut m.classes),
                h,
                SW_HIDE
            ),
            Ok(16)
        );
        assert_eq!(
            WindowManager::show_window(
                &mut DefaultSession::new(&mut m.windows, &mut m.classes),
                h,
                SW_SHOW
            ),
            Ok(0)
        );
        assert_eq!(
            WindowManager::show_window_async(
                &mut DefaultSession::new(&mut m.windows, &mut m.classes),
                h,
                SW_HIDE
            ),
            Ok(())
        );
        assert_eq!(
            m.query_window(h, QUERY_WINDOW_VISIBLE, 4, OWNER),
            Ok(Query::Visible(0))
        );
        assert_eq!(
            WindowManager::show_window_async(
                &mut DefaultSession::new(&mut m.windows, &mut m.classes),
                h,
                SW_SHOW
            ),
            Ok(())
        );
        assert_eq!(
            m.query_window(h, QUERY_WINDOW_VISIBLE, 4, OWNER),
            Ok(Query::Visible(1))
        );
        let bogus = 0x7FFF_FFFC;
        assert_eq!(
            WindowManager::show_window(
                &mut DefaultSession::new(&mut m.windows, &mut m.classes),
                bogus,
                SW_SHOW
            ),
            Err(Failure::InvalidWindowHandle)
        );
        assert_eq!(
            WindowManager::show_window_async(
                &mut DefaultSession::new(&mut m.windows, &mut m.classes),
                bogus,
                SW_SHOW
            ),
            Err(Failure::InvalidWindowHandle)
        );
    }

    /// A tiled window's first show, as guigeo `sizemsg` captured it: WM_WINDOWPOSCHANGED reports
    /// the client area unchanged (SWP_NOCLIENTSIZE, SWP_NOCLIENTMOVE), the window's place among its
    /// siblings kept (SWP_NOZORDER) and ShowWindow's own bit, then the deferred WM_SIZE carries the
    /// client area's size and WM_MOVE its place.
    #[test]
    fn the_first_show_reports_as_the_capture() {
        let (w, c, t, atom, _, _) = setup();
        let mut pump = Rec::new(t);
        let id = create(w, c, t, atom, WS_OVERLAPPED, &mut pump).unwrap();
        pump.events.clear();
        pump.positions.clear();
        Windows::show_window(&mut pump.on(w, c), id, SW_SHOW).unwrap();
        let (_, _, changed) = *pump.positions.last().unwrap();
        assert_eq!(changed.flags, 0x1000_1847);
        let messages = pump.messages();
        assert_eq!(
            &messages[messages.len() - 3..],
            &[WM_WINDOWPOSCHANGED, WM_SIZE, WM_MOVE]
        );
        let client = w.at(id).client_rect;
        let size = makelong(
            (client.right - client.left) as u16,
            (client.bottom - client.top) as u16,
        );
        assert!(pump
            .events
            .contains(&Ev::Send(id, WM_SIZE, 0, size as LParam)));
    }
}
