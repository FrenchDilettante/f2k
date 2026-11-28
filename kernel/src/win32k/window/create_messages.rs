//! The creation's messages, once the record is made, placed and wired: WM_NCCREATE, the link,
//! WM_NCCALCSIZE, WM_CREATE, WM_SIZE/WM_MOVE, the min/max setup, WM_PARENTNOTIFY and the show.

use rtl::user::{
    WM_CREATE,
    WM_MOVE,
    WM_NCCREATE,
    WM_PARENTNOTIFY,
    WM_SETHOTKEY,
    WS_EX_APPWINDOW,
    WS_EX_NOPARENTNOTIFY,
    WS_EX_TOPMOST,
    WS_MAXIMIZE,
    WS_MINIMIZE,
    WS_VISIBLE,
};
use rtl::window::{SW_SHOWMAXIMIZED, SW_SHOWMINNOACTIVE};

use super::*;
use crate::sched::thread::ThreadId;

/// What the creation's messages ([`Windows::create_messages`]) carry over from its setup.
pub(super) struct Creation {
    pub(super) caller: ThreadId,
    pub(super) id: WindowId,
    pub(super) child: bool,
    pub(super) tiled: bool,
    pub(super) ex_style: u32,
    pub(super) parent: Option<WindowId>,
    pub(super) message_window: Option<WindowId>,
    pub(super) desktop_window: Option<WindowId>,
    pub(super) z_order: ZOrder,
    pub(super) sw: i32,
    pub(super) x: i32,
    pub(super) y: i32,
    pub(super) cx: i32,
    pub(super) cy: i32,
    pub(super) params: CreateParams,
}

impl Windows {
    /// The creation's messages, once the record is made, placed and wired: WM_NCCREATE, the
    /// link, WM_NCCALCSIZE, WM_CREATE, WM_SIZE/WM_MOVE, the min/max setup, WM_PARENTNOTIFY, the
    /// show and the hotkey.
    pub(super) fn create_messages(
        s: &mut dyn Session,
        args: &CreateArgs,
        creation: Creation,
    ) -> Result<WindowId, Failure> {
        let Creation {
            caller,
            id,
            child,
            tiled,
            ex_style,
            parent,
            message_window,
            desktop_window,
            mut z_order,
            sw,
            x,
            y,
            cx,
            cy,
            mut params,
        } = creation;
        // The create parameters carry the final position.
        params.x = x;
        params.y = y;
        params.cx = cx;
        params.cy = cy;

        // WM_NCCREATE first: a zero answer rolls the whole creation back, the procedure's refusal
        // (no error). The procedure may have destroyed the window meanwhile: then it is gone, and
        // Windows 2000's creation answers its dead handle with ERROR_INVALID_PARAMETER.
        let handle = s.windows().at(id).handle;
        let mut message = Message {
            message: WM_NCCREATE,
            wparam: 0,
            lparam: 0,
            payload: Payload::Create(params),
        };
        let answer = s.send(id, &mut message);
        if Windows::gone_in_creation(s, id) {
            return Err(Failure::DestroyedInNcCreate(handle));
        }
        if answer == 0 {
            Windows::rollback_create(s, caller, id);
            return Err(Failure::Refused);
        }
        let windows = s.windows();
        let Payload::Create(mut params) = message.payload else {
            unreachable!("the payload came back whole")
        };

        // WM_NCCREATE may have set the window text: the name WM_CREATE sees is refreshed from
        // the record, except when the original name was empty and the text never got set.
        {
            let w = windows.at(id);
            if w.flags.title_set && !(w.create_name.is_empty() && w.title.is_empty()) {
                params.name = CreateName::Title;
            }
        }

        // Link the window into its parent's child list (the z-order decision for top-levels:
        // a non-topmost window does not go on top of the topmost pile).
        if let Some(p) = parent {
            if !child && Some(p) != message_window {
                let topmost_pile = match z_order {
                    ZOrder::Top => true,
                    ZOrder::After(after) => windows.at(after).ex_style & WS_EX_TOPMOST != 0,
                    ZOrder::Bottom => false,
                };
                if windows.at(id).ex_style & WS_EX_TOPMOST == 0 && topmost_pile {
                    z_order = s.foreground_insert_after(id);
                }
            }
            let windows = s.windows();
            windows.link_window(id, z_order, p);
        }
        let windows = s.windows();

        // A window created minimized is minimized once it is made (the min/max setup below): its
        // client area is a normal window's until then, so that minimizing it empties it (guigeo
        // `createmax`: a WM_SIZE of SIZE_MINIMIZED, hidden or not).
        let created_minimized = windows.at(id).style & WS_MINIMIZE != 0;
        windows.at_mut(id).style &= !WS_MINIMIZE;

        // WM_NCCALCSIZE: the client rect, the window's less the frame.
        let window_rect = windows.at(id).window_rect;
        let client = s.calc_client(id, window_rect, None);
        if Windows::gone_in_creation(s, id) {
            return Err(Failure::Refused);
        }
        let windows = s.windows();
        windows.at_mut(id).client_rect = client;

        // WM_CREATE: a -1 answer destroys the window for real and fails the create, the
        // procedure's refusal (no error; -2 and the rest go on, guiwin `refuse`).
        let mut message = Message {
            message: WM_CREATE,
            wparam: 0,
            lparam: 0,
            payload: Payload::Create(params),
        };
        let answer = s.send(id, &mut message);
        // Destroyed inside WM_CREATE: NULL, with ERROR_INVALID_PARAMETER (guiwin `diecreate`).
        if Windows::gone_in_creation(s, id) {
            return Err(Failure::InvalidParameter);
        }
        if answer == -1 {
            let _ = Windows::destroy_window(s, caller, id);
            return Err(Failure::Refused);
        }
        let windows = s.windows();
        // The creation's name is the sends' no longer (the queue's sends keep their own copy).
        let name = core::mem::take(&mut windows.at_mut(id).create_name);
        windows.texts.free(name);

        // The window is officially created.
        windows.at_mut(id).flags.initialized = true;

        // WM_SIZE/WM_MOVE, unless they are deferred to show time (tiled windows).
        if !windows.at(id).flags.sendsizemove {
            s.send_size(id, SIZENORMAL);
            if Windows::gone_in_creation(s, id) {
                return Err(Failure::Refused);
            }
            let windows = s.windows();
            let mut rc = windows.at(id).client_rect;
            if let Some(p) = parent {
                if Some(p) != desktop_window {
                    // WM_MOVE's position is client-relative for children.
                    let pc = windows.at(p).client_rect;
                    rc.left = rc.left.saturating_sub(pc.left);
                    rc.top = rc.top.saturating_sub(pc.top);
                }
            }
            s.send(
                id,
                &mut Message {
                    message: WM_MOVE,
                    wparam: 0,
                    lparam: makelong(rc.left as u16, rc.top as u16) as LParam,
                    payload: Payload::None,
                },
            );
            if Windows::gone_in_creation(s, id) {
                return Err(Failure::Refused);
            }
        }
        let windows = s.windows();

        // A window created with WS_MINIMIZE or WS_MAXIMIZE is minimized or maximized now, hidden
        // or not, its normal place the one it was created at (guigeo `createmax`: a visible one
        // gets two WM_SIZEs of its new state, a hidden one one). The style bit is off by now, so
        // the window leaves the normal state; a tiled window's deferred WM_SIZE and WM_MOVE still
        // wait for its first show.
        let min_max = if created_minimized {
            Some(SW_SHOWMINNOACTIVE)
        } else if windows.at(id).style & WS_MAXIMIZE != 0 {
            windows.at_mut(id).style &= !WS_MAXIMIZE;
            Some(SW_SHOWMAXIMIZED)
        } else {
            None
        };
        if let Some(command) = min_max {
            s.min_maximize(id, command as u32);
            let windows = s.windows();
            let deferred = windows.at(id).flags.sendsizemove;
            let _ = Windows::min_maximize(s, id, command);
            if Windows::gone_in_creation(s, id) {
                return Err(Failure::Refused);
            }
            let windows = s.windows();
            windows.at_mut(id).flags.sendsizemove = deferred;
        }
        let windows = s.windows();

        // Children tell their parent about the create.
        if child && windows.at(id).ex_style & WS_EX_NOPARENTNOTIFY == 0 {
            if let Some(p) = windows.at(id).parent {
                let (menu_id, handle) = {
                    let w = windows.at(id);
                    (w.menu.id().unwrap_or(0) as u16, w.handle)
                };
                s.send(
                    p,
                    &mut Message {
                        message: WM_PARENTNOTIFY,
                        wparam: makelong(WM_CREATE as u16, menu_id),
                        lparam: handle as LParam,
                        payload: Payload::None,
                    },
                );
                if Windows::gone_in_creation(s, id) {
                    return Err(Failure::Refused);
                }
            }
        }

        // A window created with WS_VISIBLE is shown last (a show command that is none is not
        // carried out).
        if args.style & WS_VISIBLE != 0 {
            let _ = Windows::show_window(s, id, sw);
            if Windows::gone_in_creation(s, id) {
                return Err(Failure::Refused);
            }
        }
        let windows = s.windows();

        // The process's hotkey lands on the first tiled/APPWINDOW window.
        if tiled || ex_style & WS_EX_APPWINDOW != 0 {
            let hotkey = windows.thread(caller).hotkey;
            if hotkey != 0 {
                s.send(
                    id,
                    &mut Message {
                        message: WM_SETHOTKEY,
                        wparam: hotkey,
                        lparam: 0,
                        payload: Payload::None,
                    },
                );
                let windows = s.windows();
                windows.thread_mut(caller).hotkey = 0;
                if Windows::gone_in_creation(s, id) {
                    return Err(Failure::Refused);
                }
            }
        }

        Ok(id)
    }
}

#[cfg(test)]
mod tests {
    use rtl::gdi::Rect;
    use rtl::testing::wide;
    use rtl::user::{
        WM_DESTROY,
        WM_NCCALCSIZE,
        WM_NCDESTROY,
        WM_SHOWWINDOW,
        WM_SIZE,
        WM_WINDOWPOSCHANGED,
        WM_WINDOWPOSCHANGING,
        WS_CHILD,
        WS_OVERLAPPED,
        WS_OVERLAPPEDWINDOW,
        WS_POPUP,
    };
    use rtl::window::{SWP_FRAMECHANGED, SWP_NOMOVE, SWP_NOSIZE, SWP_NOZORDER};

    use super::*;
    use crate::win32k::class;
    use crate::win32k::window::testkit::*;

    /// The client rectangle is the window's less the frame its styles give (an overlapped
    /// window's sizing border and caption), and a menu bar's room once it holds a menu: SetMenu's
    /// SWP_FRAMECHANGED takes it again.
    #[test]
    fn the_client_area_leaves_the_frame_and_the_menu_bar() {
        let (w, c, t, atom, _, _) = setup();
        let mut pump = Rec::new(t);
        let id = create(w, c, t, atom, WS_OVERLAPPEDWINDOW, &mut pump).unwrap();
        let r = w.at(id).window_rect;
        let framed = Rect {
            left: r.left + 4,
            top: r.top + 23,
            right: r.right - 4,
            bottom: r.bottom - 4,
        };
        assert_eq!(w.at(id).client_rect, framed);
        w.set_window_menu(id, 0x1234);
        let flags = SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_FRAMECHANGED;
        Windows::set_window_pos(&mut pump.on(w, c), id, InsertAfter::Top, 0, 0, 0, 0, flags)
            .unwrap();
        assert_eq!(
            w.at(id).client_rect,
            Rect {
                top: r.top + 42,
                ..framed
            }
        );
    }

    /// The create's message order: WM_NCCREATE, the link into the parent's child list, then
    /// WM_NCCALCSIZE (the client the window rect less the frame and caption a tiled window has),
    /// then WM_CREATE.
    #[test]
    fn the_create_message_order() {
        let (w, c, t, atom, desk, _) = setup();
        let mut pump = Rec::new(t);
        let id = create(w, c, t, atom, WS_OVERLAPPED, &mut pump).unwrap();
        assert_eq!(
            pump.sends(),
            vec![(id, WM_NCCREATE), (id, WM_NCCALCSIZE), (id, WM_CREATE)]
        );
        let r = w.at(id).window_rect;
        assert_eq!(
            w.at(id).client_rect,
            Rect {
                left: r.left + 3,
                top: r.top + 22,
                right: r.right - 3,
                bottom: r.bottom - 3
            }
        );
        assert_eq!(
            w.at(desk).child,
            Some(id),
            "linked at the head of the desktop's list"
        );
    }

    /// A title set during WM_NCCREATE reaches the WM_CREATE parameters.
    #[test]
    fn the_title_set_during_nccreate_reaches_create() {
        let (w, c, t, atom, _, _) = setup();
        let mut pump = Rec::new(t);
        pump.title_on_nccreate = Some(wide("new title"));
        let a = args(atom, WS_OVERLAPPED);
        let _ = Windows::create_window_ex(&mut pump.on(w, c), t, &a).unwrap();
        let create = pump
            .params
            .iter()
            .position(|(_, m, _)| *m == WM_CREATE)
            .unwrap();
        assert_eq!(pump.names[create], wide("new title"));
    }

    /// A creation's name and a window's text are kept whole however long they are (10,000
    /// units): WM_NCCREATE carries the whole name, the creation's copy goes once it ends, and the
    /// title goes back to the store with the window.
    #[test]
    fn long_texts_are_kept_whole_and_freed() {
        let (w, c, t, atom, _, _) = setup();
        let before = w.texts.counts();
        let mut pump = Rec::new(t);
        let name: Vec<u16> = (0..10_000u32).map(|i| 0x41 + (i % 26) as u16).collect();
        let mut a = args(atom, WS_OVERLAPPED);
        a.name = &name;
        let id = Windows::create_window_ex(&mut pump.on(w, c), t, &a).unwrap();
        assert_eq!(pump.names[0], name, "WM_NCCREATE carries the whole name");
        assert!(
            w.at(id).create_name.is_empty(),
            "the creation's copy is gone"
        );
        let handle = w.at(id).handle;
        let title: Vec<u16> = (0..10_000u32).map(|i| 0x4E00 + i as u16).collect();
        assert_eq!(w.set_window_text(handle, &title), Ok(()));
        assert_eq!(w.window_text(id), &title[..]);
        assert_eq!(w.texts.counts().0, before.0 + 1, "the title alone is held");
        assert!(Windows::destroy_window(&mut pump.on(w, c), t, id).is_ok());
        assert_eq!(
            w.texts.counts().0,
            before.0,
            "the title went with the window"
        );
    }

    /// A WM_NCCREATE answered with 0 rolls the creation back, the procedure's refusal (no error):
    /// the only messages are WM_NCCREATE and WM_NCDESTROY (no WM_DESTROY — the window was never
    /// linked), and the record, handle, class reference and window count are all released.
    #[test]
    fn a_failed_nccreate_rolls_back() {
        let (w, c, t, atom, _, _) = setup();
        let mut pump = Rec::new(t);
        pump.nccreate_answer = 0;
        let err = create(w, c, t, atom, WS_OVERLAPPED, &mut pump).unwrap_err();
        assert_eq!(err, Failure::Refused);
        assert_eq!(pump.messages(), vec![WM_NCCREATE, WM_NCDESTROY]);
        assert_eq!(live(w), 2, "only the desktop windows remain");
        assert_eq!(w.thread(t).window_count, 0);
        // The class reference went back: the class can be unregistered now.
        assert!(c
            .unregister_class(
                &mut w.handles,
                class::Name::Text(&wide("Test")),
                OWNER,
                MODULE
            )
            .is_ok());
    }

    /// A WM_CREATE answered with -1 runs the full destroy (WM_DESTROY and all) and fails the
    /// create, the procedure's refusal (no error).
    #[test]
    fn a_failed_create_destroys_the_window() {
        let (w, c, t, atom, _, _) = setup();
        let mut pump = Rec::new(t);
        pump.create_answer = -1;
        let err = create(w, c, t, atom, WS_OVERLAPPED, &mut pump).unwrap_err();
        assert_eq!(err, Failure::Refused);
        assert_eq!(
            pump.messages(),
            vec![
                WM_NCCREATE,
                WM_NCCALCSIZE,
                WM_CREATE,
                WM_DESTROY,
                WM_NCDESTROY
            ]
        );
        assert_eq!(live(w), 2);
        assert_eq!(w.thread(t).window_count, 0);
    }

    /// After WM_CREATE: WM_SIZE and WM_MOVE unless size/move are deferred (tiled windows), the
    /// WM_MOVE position client-relative for children, WM_PARENTNOTIFY for children, and the
    /// min/max command when the style asks.
    #[test]
    fn the_post_create_messages() {
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
        let id = Windows::create_window_ex(&mut pump.on(w, c), t, &a).unwrap();
        let own: Vec<u32> = pump
            .sends()
            .iter()
            .filter(|(target, _)| *target == id)
            .map(|(_, m)| *m)
            .collect();
        assert_eq!(
            own,
            vec![WM_NCCREATE, WM_NCCALCSIZE, WM_CREATE, WM_SIZE, WM_MOVE]
        );
        // WM_MOVE's position is client-relative for the child: (15,26) - (10,20) = (5,6).
        let move_send = pump
            .events
            .iter()
            .find(|e| matches!(e, Ev::Send(t2, WM_MOVE, _, _) if *t2 == id))
            .unwrap();
        assert_eq!(
            *move_send,
            Ev::Send(id, WM_MOVE, 0, makelong(5, 6) as LParam)
        );
        // The parent was told about the create.
        assert!(pump.events.iter().any(|e| matches!(
            e,
            Ev::Send(t2, WM_PARENTNOTIFY, _, _) if *t2 == parent
        )));
        // A tiled window defers size/move to show time.
        pump.events.clear();
        let id = create(w, c, t, atom, WS_OVERLAPPED, &mut pump).unwrap();
        let own: Vec<u32> = pump
            .sends()
            .iter()
            .filter(|(target, _)| *target == id)
            .map(|(_, m)| *m)
            .collect();
        assert_eq!(own, vec![WM_NCCREATE, WM_NCCALCSIZE, WM_CREATE]);
        // A minimized window gets the min/max command.
        pump.events.clear();
        let id = create(w, c, t, atom, WS_OVERLAPPED | WS_MINIMIZE, &mut pump).unwrap();
        assert!(pump
            .events
            .contains(&Ev::MinMax(id, SW_SHOWMINNOACTIVE as u32)));
    }

    /// A child without WS_EX_NOPARENTNOTIFY tells its parent (WM_PARENTNOTIFY, wParam packs
    /// WM_CREATE and the menu id, lParam is the child's handle); with the ex-style it does not.
    #[test]
    fn children_notify_their_parent() {
        let (w, c, t, atom, _, _) = setup();
        let parent = raw_window(w, t, WS_OVERLAPPED, None);
        let mut pump = Rec::new(t);
        let mut a = args(atom, WS_CHILD);
        a.parent = Some(parent);
        a.menu = MenuInput::Id(9);
        let id = Windows::create_window_ex(&mut pump.on(w, c), t, &a).unwrap();
        let handle = w.at(id).handle;
        assert!(pump.events.contains(&Ev::Send(
            parent,
            WM_PARENTNOTIFY,
            makelong(WM_CREATE as u16, 9),
            handle as LParam
        )));
        // With WS_EX_NOPARENTNOTIFY: no notify.
        let mut pump = Rec::new(t);
        let mut a = args(atom, WS_CHILD);
        a.parent = Some(parent);
        a.ex_style = WS_EX_NOPARENTNOTIFY;
        let _ = Windows::create_window_ex(&mut pump.on(w, c), t, &a).unwrap();
        assert!(!pump
            .events
            .iter()
            .any(|e| matches!(e, Ev::Send(_, WM_PARENTNOTIFY, _, _))));
    }

    /// A window created with WS_VISIBLE is shown as the last step (the stored style lacks
    /// WS_VISIBLE); the process's hotkey lands on the first tiled window.
    #[test]
    fn a_visible_window_is_shown_last() {
        let (w, c, t, atom, _, _) = setup();
        w.thread_mut(t).hotkey = 0x1234;
        let mut pump = Rec::new(t);
        let a = args(atom, WS_OVERLAPPED | WS_VISIBLE);
        let id = Windows::create_window_ex(&mut pump.on(w, c), t, &a).unwrap();
        // The create parameters carried WS_VISIBLE; the stored style had it stripped (the show
        // at the end sets the visible bit again).
        let (_, _, p) = &pump.params[0];
        assert_eq!(p.style & WS_VISIBLE, WS_VISIBLE);
        assert!(w.at(id).is_visible());
        // The show is the last window-manager step: WM_SHOWWINDOW, the position change, then the
        // size and move its creation deferred; the hotkey send follows it.
        let messages = pump.messages();
        let show = messages.iter().position(|&m| m == WM_SHOWWINDOW).unwrap();
        assert_eq!(
            &messages[show..],
            &[
                WM_SHOWWINDOW,
                WM_WINDOWPOSCHANGING,
                WM_WINDOWPOSCHANGED,
                WM_SIZE,
                WM_MOVE,
                WM_SETHOTKEY
            ]
        );
        assert_eq!(
            pump.events.last(),
            Some(&Ev::Send(id, WM_SETHOTKEY, 0x1234, 0))
        );
        assert_eq!(w.thread(t).hotkey, 0, "the hotkey was consumed");
        // Without WS_VISIBLE: no show.
        let mut pump = Rec::new(t);
        let id = create(w, c, t, atom, WS_OVERLAPPED, &mut pump).unwrap();
        assert!(!pump.messages().contains(&WM_SHOWWINDOW));
        assert!(!w.at(id).is_visible());
    }

    /// A window its procedure destroys while it is being created fails the creation, the window
    /// gone: from WM_NCCREATE with its dead handle and ERROR_INVALID_PARAMETER, from WM_CREATE
    /// with ERROR_INVALID_PARAMETER alone (guiwin `diecreate`), from WM_MOVE as a refusal.
    #[test]
    fn a_window_destroyed_in_its_creation_fails_it() {
        for message in [WM_NCCREATE, WM_CREATE, WM_MOVE] {
            let (w, c, t, atom, _, _) = setup();
            let mut pump = Rec::new(t);
            pump.destroy_self_on = Some(message);
            let err = create(w, c, t, atom, WS_POPUP, &mut pump).unwrap_err();
            match message {
                WM_NCCREATE => assert!(
                    matches!(err, Failure::DestroyedInNcCreate(h) if h != 0),
                    "{err:?}"
                ),
                WM_CREATE => assert_eq!(err, Failure::InvalidParameter),
                _ => assert_eq!(err, Failure::Refused, "destroyed in {message:#x}"),
            }
            assert_eq!(live(w), 2, "only the desktop windows remain");
            assert_eq!(w.thread(t).window_count, 0);
        }
    }
}
