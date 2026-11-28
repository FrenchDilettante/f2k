//! The decisions' session with the window manager ([`Session`]), what it holds the registries by
//! ([`Hold`]), and the default window procedure's answers.

use rtl::gdi::Rect;
use rtl::user::{
    WM_GETMINMAXINFO,
    WM_NCACTIVATE,
    WM_NCCALCSIZE,
    WM_NCCREATE,
    WM_NCPAINT,
    WM_QUERYENDSESSION,
    WM_SIZE,
    WM_WINDOWPOSCHANGING,
};

use super::*;
use crate::sched::thread::ThreadId;
use crate::win32k::class;

/// The default window procedure's answer where no client procedure answers: WM_NCCREATE,
/// WM_QUERYENDSESSION and WM_NCACTIVATE answer 1, the rest 0; WM_NCCALCSIZE's rectangle (either
/// form's first) becomes the client rectangle ([`Windows::default_client`]), as user32's
/// DefWindowProc makes it. A window gone leaves the payload as it is.
pub fn default_procedure(windows: &Windows, target: WindowId, message: &mut Message) -> LResult {
    if message.message == WM_NCCALCSIZE && windows.pool.is_live(target) {
        match &mut message.payload {
            Payload::Rect(rect) => *rect = windows.default_client(target, *rect),
            Payload::CalcSize(calc) => {
                calc.rects[0] = windows.default_client(target, calc.rects[0])
            }
            _ => {}
        }
    }
    match message.message {
        WM_NCCREATE | WM_QUERYENDSESSION | WM_NCACTIVATE => 1,
        _ => 0,
    }
}

/// [`default_procedure`]'s answer in the session `s`, with WM_WINDOWPOSCHANGING's WINDOWPOS
/// clamped as Windows 2000's DefWindowProc clamps it ([`Windows::window_pos_changing`]). user32's
/// DefWindowProc reaches the same clamp through HWND_PARAM_LOCK_WINDOW_POS_CHANGING.
pub fn default_send<S: Session + ?Sized>(
    s: &mut S,
    target: WindowId,
    message: &mut Message,
) -> LResult {
    if message.message == WM_WINDOWPOSCHANGING && s.windows().pool.is_live(target) {
        if let Payload::WindowPos(mut pos) = message.payload {
            Windows::window_pos_changing(s, target, &mut pos);
            message.payload = Payload::WindowPos(pos);
        }
        return 0;
    }
    default_procedure(s.windows(), target, message)
}

/// A decision's session with the window manager: the registries and every message and
/// window-manager call the decisions make. Decisions take `&mut dyn Session`, not `&mut Windows`,
/// so nothing borrowed from the registries lives across a send: each decision reads them again
/// after it, carrying only ids and values. That lets a send release the lock while a procedure
/// runs, as Windows 2000's `xxx` routines leave the USER critical section around a callback; a
/// window may then be gone when the send returns ([`Windows::is_live`]).
///
/// The defaults answer as the default procedure and no-op calls do. Implementations:
/// [`crate::win32k::queue::QueueSession`] (services), [`DefaultSession`] (boot), the tests'
/// recorder.
pub trait Session {
    /// Both registries, borrowed until the next send.
    fn parts(&mut self) -> (&mut Windows, &mut class::Registry);

    /// The window registry, borrowed until the next send.
    fn windows(&mut self) -> &mut Windows {
        self.parts().0
    }

    /// The class registry, borrowed until the next send.
    fn classes(&mut self) -> &mut class::Registry {
        self.parts().1
    }

    /// Send `message` to `target`; the handler's answer, and its payload as the handler left it.
    /// The default answers as the default procedure does ([`default_send`]).
    fn send(&mut self, target: WindowId, message: &mut Message) -> LResult {
        default_send(self, target, message)
    }

    /// From now on, messages to `thread`'s windows (none: no thread) are queued, not waited for,
    /// unless they go to the deciding thread's own: Windows 2000 hands another thread's activation
    /// to that thread as an event. Answers the thread this replaces, for the caller to put back.
    /// The default keeps none.
    fn queue_for(&mut self, _thread: Option<ThreadId>) -> Option<ThreadId> {
        None
    }

    /// The WM_SIZE send (wparam is the SIZE_* command, lparam the client area's width and height,
    /// as guigeo `sizemsg` captured).
    fn send_size(&mut self, target: WindowId, command: u32) {
        let client = self.windows().at(target).client_rect;
        let size = makelong(
            (client.right - client.left) as u16,
            (client.bottom - client.top) as u16,
        );
        self.send(
            target,
            &mut Message {
                message: WM_SIZE,
                wparam: command,
                lparam: size as LParam,
                payload: Payload::None,
            },
        );
    }

    /// WM_NCCALCSIZE to `target` for the window rectangle `rect` (screen coordinates): the client
    /// rectangle the handler hands back. A creation (`resize` none) sends the rectangle alone,
    /// wParam FALSE; a resize sends NCCALCSIZE_PARAMS, wParam TRUE (new rectangle, old one, old
    /// client rectangle, WINDOWPOS), as Windows 2000's SetWindowPos does. A child's rectangles go
    /// in its parent's client coordinates. The default procedure's answer takes the frame off
    /// ([`default_procedure`]). The WVR_* answer is unused: F2K keeps no valid bits to copy. A
    /// window destroyed meanwhile answers `rect`.
    fn calc_client(&mut self, target: WindowId, rect: Rect, resize: Option<Resize>) -> Rect {
        let (dx, dy) = self.windows().parent_origin(target);
        let local = |r: Rect| r.saturating_offset_back(dx, dy);
        let (wparam, payload) = match resize {
            None => (0, Payload::Rect(local(rect))),
            Some(resize) => (
                1,
                Payload::CalcSize(CalcSize {
                    rects: [local(rect), local(resize.window), local(resize.client)],
                    pos: resize.pos,
                }),
            ),
        };
        let mut message = Message {
            message: WM_NCCALCSIZE,
            wparam,
            lparam: 0,
            payload,
        };
        self.send(target, &mut message);
        if !self.windows().pool.is_live(target) {
            return rect;
        }
        let client = match message.payload {
            Payload::Rect(client) => client,
            Payload::CalcSize(calc) => calc.rects[0],
            _ => local(rect),
        };
        client.saturating_offset(dx, dy)
    }

    /// The frame of `target` to be painted: WM_NCPAINT sent, wParam 1 (the whole frame).
    fn paint_frame(&mut self, target: WindowId) {
        self.send(
            target,
            &mut Message {
                message: WM_NCPAINT,
                wparam: 1,
                lparam: 0,
                payload: Payload::None,
            },
        );
    }

    /// Show or hide the window (ShowWindow's command).
    fn show(&mut self, _target: WindowId, _command: u32) -> bool {
        true
    }

    /// A SetWindowPos call (the SWP_* flags).
    fn set_window_pos(&mut self, _target: WindowId, _flags: u32) {}

    /// Activate a window (the AW_* decision as [`Activate`]).
    fn activate(&mut self, _target: WindowId, _command: Activate) -> bool {
        true
    }

    /// The min/max command (SW_SHOWMINNOACTIVE, SW_SHOWMAXIMIZED).
    fn min_maximize(&mut self, _target: WindowId, _command: u32) {}

    /// The focus check before and after the destroy messages.
    fn check_focus(&mut self, _target: WindowId) {}

    /// Share (or end sharing) input state between two threads.
    fn attach_input(&mut self, _from: ThreadId, _to: ThreadId, _attach: bool) {}

    /// Redraw the windows below `target` (the failed-hide fallback).
    fn redraw_below(&mut self, _target: WindowId) {}

    /// Release the mouse capture.
    fn release_capture(&mut self) {}

    /// Destroy the caret.
    fn destroy_caret(&mut self) {}

    /// Post the destroy-window event to a cross-thread child's queue.
    fn post_destroy_event(&mut self, _thread: ThreadId, _window: WindowId) {}

    /// The WM_GETMINMAXINFO answer for `target`: the message sent with the window manager's
    /// defaults ([`Windows::default_min_max_info`]), as the procedure leaves them (Windows 2000's
    /// xxxInitSendValidateMinMaxInfo). A window gone meanwhile answers the defaults.
    fn min_max_info(&mut self, target: WindowId) -> MinMaxInfo {
        let defaults = self.windows().default_min_max_info(target);
        let mut message = Message {
            message: WM_GETMINMAXINFO,
            wparam: 0,
            lparam: 0,
            payload: Payload::MinMax(defaults),
        };
        self.send(target, &mut message);
        match message.payload {
            Payload::MinMax(answer) => answer,
            _ => defaults,
        }
    }

    /// Load a class menu (the module and menu name); the menu's handle, none on failure.
    fn load_class_menu(&mut self, _module: u32, _name: &class::MenuName) -> Option<Hwnd> {
        None
    }

    /// Destroy a menu (its window's end): the menu and its popups go ([`crate::win32k::menu`]).
    fn destroy_menu(&mut self, menu: Hwnd) {
        let _ = self.windows().destroy_menu_handle(menu);
    }

    /// Create the window's cache DC (CS_OWNDC/CS_CLASSDC); false on failure.
    fn create_window_dc(&mut self, _target: WindowId, _own_dc: bool) -> bool {
        true
    }

    /// Make the window layered; false on failure.
    fn set_layered(&mut self, _target: WindowId) -> bool {
        true
    }

    /// The full-screen check over the window's rect.
    fn check_full_screen(&mut self, _target: WindowId, _rect: &mut SizeRect) {}

    /// Where a top-level window inserts in the z-order (after the topmost pile).
    fn foreground_insert_after(&mut self, _target: WindowId) -> ZOrder {
        ZOrder::Top
    }

    /// A hook's veto of a creation (the CBT hook's HCBT_CREATEWND).
    fn cbt_create_veto(&mut self, _target: WindowId, _params: &mut CreateParams) -> bool {
        false
    }

    /// A hook's veto of a destroy (the CBT hook's HCBT_DESTROYWND).
    fn cbt_destroy_veto(&mut self, _target: WindowId) -> bool {
        false
    }

    /// Disown the clipboard (the window was the clipboard owner).
    fn disown_clipboard(&mut self, _target: WindowId) {}

    /// Re-post a queued WM_QUIT for the window with its exit code.
    fn repost_quit(&mut self, _target: WindowId) {}

    /// The timers/hotkeys/pending-sends cleanup at the window's end.
    fn window_teardown(&mut self, _target: WindowId) {}

    /// Delete the window's properties.
    fn delete_properties(&mut self, _target: WindowId) {}
}

/// What a session holds the registries by: the window manager's lock, its guard ([`Locked`]), in
/// the services, or the two registries borrowed ([`Split`]) at the boot and in the tests. Only
/// the guard can be let go of around a send.
pub trait Hold {
    /// Both registries.
    fn parts(&mut self) -> (&mut Windows, &mut class::Registry);

    /// Run `f` with the window manager's lock let go, as a callback to user mode runs, and take
    /// the lock back: what `f` answers. None when the holder has no lock to let go of (the
    /// registries borrowed at the boot and in the tests), `f` not run.
    fn unlocked<R>(
        &mut self,
        _f: impl FnOnce(&mut crate::level::At<crate::level::Passive>) -> R,
    ) -> Option<R> {
        None
    }
}

/// The two registries, borrowed for the session's life.
pub type Split<'a> = (&'a mut Windows, &'a mut class::Registry);

impl Hold for Split<'_> {
    fn parts(&mut self) -> (&mut Windows, &mut class::Registry) {
        (&mut *self.0, &mut *self.1)
    }
}

/// The window manager's lock, held for the session's life except where a send lets it go
/// ([`crate::sync::ShortGuard::unlocked`]).
pub type Locked<'a> = crate::sync::ShortGuard<'a, WindowManager>;

impl Hold for Locked<'_> {
    fn parts(&mut self) -> (&mut Windows, &mut class::Registry) {
        let manager: &mut WindowManager = self;
        (&mut manager.windows, &mut manager.classes)
    }

    /// The lock let go around `f`, the input state published and the queues' events set first,
    /// as the session's end does ([`crate::win32k::queue::Signals`]).
    #[cfg(target_arch = "x86")]
    fn unlocked<R>(
        &mut self,
        f: impl FnOnce(&mut crate::level::At<crate::level::Passive>) -> R,
    ) -> Option<R> {
        let signals = crate::win32k::queue::Signals::take(self);
        Some(crate::sync::ShortGuard::unlocked(self, |passive| {
            signals.raise(passive);
            f(passive)
        }))
    }
}

/// The session the boot runs the desktop's own windows' creation with, and the ends of threads and
/// processes: every send answers as the default window procedure does, and every window-manager
/// call is [`Session`]'s default.
pub struct DefaultSession<H: Hold>(pub H);

impl<'a> DefaultSession<Split<'a>> {
    /// A session over the two registries.
    pub fn new(windows: &'a mut Windows, classes: &'a mut class::Registry) -> Self {
        DefaultSession((windows, classes))
    }
}

impl<H: Hold> Session for DefaultSession<H> {
    fn parts(&mut self) -> (&mut Windows, &mut class::Registry) {
        self.0.parts()
    }
}

#[cfg(test)]
mod tests {
    use rtl::user::{WS_BORDER, WS_CHILD, WS_POPUP};
    use rtl::window::{SWP_NOACTIVATE, SWP_NOMOVE, SWP_NOZORDER};

    use super::*;
    use crate::win32k::window::testkit::*;

    /// WM_NCCALCSIZE's two forms: a creation sends the window rectangle (wParam FALSE), a resize an
    /// NCCALCSIZE_PARAMS (wParam TRUE) with the new and old window rectangles, the old client
    /// rectangle and the move's WINDOWPOS; a child's in its parent's client coordinates. The
    /// handler's client rectangle is the window's (back in screen coordinates); one the default
    /// procedure answers has the frame taken off.
    #[test]
    fn nccalcsize_carries_both_forms_and_its_answer_counts() {
        let (w, c, t, atom, _, _) = setup();
        let mut pump = Rec::new(t);
        let top = create(w, c, t, atom, WS_POPUP | WS_BORDER, &mut pump).unwrap();
        // The default procedure's: a one-pixel border off the window 10,20 100x80.
        assert_eq!(w.at(top).client_rect, Rect::new(11, 21, 109, 99));
        assert_eq!(
            pump.calcs,
            [(top, 0, Payload::Rect(Rect::new(10, 20, 110, 100)))]
        );
        pump.nccalc_inset = 5;
        let mut a = args(atom, WS_CHILD);
        (a.x, a.y, a.cx, a.cy) = (5, 6, 20, 10);
        a.parent = Some(top);
        let child = Windows::create_window_ex(&mut pump.on(w, c), t, &a).unwrap();
        assert_eq!(
            pump.calcs.last().unwrap(),
            &(child, 0, Payload::Rect(Rect::new(5, 6, 25, 16))),
            "a child's in its parent's client coordinates"
        );
        assert_eq!(w.at(child).window_rect, Rect::new(16, 27, 36, 37));
        assert_eq!(w.at(child).client_rect, Rect::new(21, 32, 31, 32));

        pump.calcs.clear();
        let flags = SWP_NOZORDER | SWP_NOACTIVATE;
        assert_eq!(
            Windows::set_window_pos(
                &mut pump.on(w, c),
                child,
                InsertAfter::Top,
                7,
                8,
                40,
                30,
                flags
            ),
            Ok(())
        );
        let [(target, wparam, Payload::CalcSize(calc))] = pump.calcs.as_slice() else {
            panic!("one WM_NCCALCSIZE, wParam TRUE: {:?}", pump.calcs);
        };
        assert_eq!((*target, *wparam), (child, 1));
        assert_eq!(
            calc.rects,
            [
                Rect::new(7, 8, 47, 38),
                Rect::new(5, 6, 25, 16),
                Rect::new(10, 11, 20, 11),
            ]
        );
        assert_eq!(
            (
                calc.pos.hwnd,
                calc.pos.x,
                calc.pos.y,
                calc.pos.cx,
                calc.pos.cy
            ),
            (w.handle_of(child), 7, 8, 40, 30)
        );
        assert_eq!(w.at(child).window_rect, Rect::new(18, 29, 58, 59));
        assert_eq!(w.at(child).client_rect, Rect::new(23, 34, 53, 54));

        // The default procedure answers the TRUE form as the FALSE one.
        pump.nccalc_inset = 0;
        assert_eq!(
            Windows::set_window_pos(
                &mut pump.on(w, c),
                top,
                InsertAfter::Top,
                0,
                0,
                50,
                40,
                flags | SWP_NOMOVE
            ),
            Ok(())
        );
        assert_eq!(w.at(top).client_rect, Rect::new(11, 21, 59, 59));
    }
}
