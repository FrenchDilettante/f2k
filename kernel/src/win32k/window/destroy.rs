//! DestroyWindow's decision: the entry checks, the owned windows first, the activation fixups and
//! the WM_DESTROY cascade; the free follows ([`super::free`]).

use rtl::user::{WM_DESTROY, WM_PARENTNOTIFY, WS_EX_NOPARENTNOTIFY, WS_VISIBLE};
use rtl::window::{SWP_HIDEWINDOW, SWP_NOACTIVATE, SWP_NOMOVE, SWP_NOSIZE, SWP_NOZORDER, SW_HIDE};

use super::*;
use crate::sched::thread::ThreadId;

impl Windows {
    /// The destroy of `window`. Only the owning thread may destroy it, unless it is marked for
    /// destruction already (the current thread adopts it). Answers whether the destroy ran; a
    /// hook's veto answers false, the window untouched.
    ///
    /// The prologue ([`Windows::destroy_prologue`]), then every owned window's destroy in full
    /// (nested, each owning window's owned ones first), then the epilogue
    /// ([`Windows::destroy_epilogue`]). The cascade descends the owner chain through the records,
    /// not by recursing (see [`Walk`]).
    pub fn destroy_window(
        s: &mut dyn Session,
        caller: ThreadId,
        window: WindowId,
    ) -> Result<bool, Failure> {
        // A window on its way already is left to the destroy under way, except from its own
        // WM_DESTROY: Windows 2000 destroys it again there, in full, and the outer destroy finds
        // it gone (guiwin `dienest`).
        if s.windows().on_its_way(window) {
            return Ok(true);
        }
        if !Windows::begin_destroy(s, caller, window)? {
            return Ok(false);
        }
        Windows::destroy_prologue(s, window);
        if !s.windows().pool.is_live(window) {
            return Ok(true);
        }
        let mut current = window;
        loop {
            let windows = s.windows();
            // The windows `current` owns are destroyed before its own WM_DESTROY.
            if let Some(owned) = windows.next_owned_window(current) {
                match Windows::begin_destroy(s, caller, owned) {
                    Ok(true) => {
                        s.windows().at_mut(owned).walk.owner = Some(current);
                        Windows::destroy_prologue(s, owned);
                        current = owned;
                    }
                    // One that cannot be destroyed loses its owner (a vetoed one included: the
                    // scan would find it again otherwise).
                    Ok(false) | Err(_) => s.windows().at_mut(owned).owner = None,
                }
                continue;
            }
            let windows = s.windows();
            let walk = windows.at(current).walk;
            Windows::destroy_epilogue(s, caller, current, walk.already);
            let windows = s.windows();
            if let Some(saved) = walk.saved_hooks {
                windows.thread_mut(caller).hooks_disabled = saved;
            }
            match walk.owner {
                Some(owner) => current = owner,
                None => return Ok(true),
            }
        }
    }

    /// The destroy service over a handle: the handle validation first (an invalid handle is
    /// ERROR_INVALID_WINDOW_HANDLE), then the destroy.
    pub fn destroy_window_handle(
        s: &mut dyn Session,
        caller: ThreadId,
        handle: Hwnd,
    ) -> Result<bool, Failure> {
        let windows = s.windows();
        let Some(window) = windows.window_from_handle(handle) else {
            return Err(Failure::InvalidWindowHandle);
        };
        Windows::destroy_window(s, caller, window)
    }

    /// The entry checks of `window`'s destroy: its handle must still name it, and only its thread
    /// may destroy it, unless it is marked for destruction (a re-entry: the caller adopts it, hooks
    /// disabled until its end). A hook can veto a first destroy. The re-entry state goes into the
    /// window's walk, for the epilogue.
    fn begin_destroy(
        s: &mut dyn Session,
        caller: ThreadId,
        window: WindowId,
    ) -> Result<bool, Failure> {
        let windows = s.windows();
        if windows.on_its_way(window) {
            return Ok(false);
        }
        let handle = windows.at(window).handle;
        let Some(entry) = windows.handles.window(handle) else {
            return Err(Failure::InvalidWindowHandle);
        };
        let already = entry.marked_destroy;
        if already {
            // The re-entry path: adopt the current thread as the owner.
            if entry.owner != caller {
                windows.handles.update_window(handle, |mut e| {
                    e.owner = caller;
                    e
                });
                windows.at_mut(window).thread = caller;
            }
        } else if windows.at(window).thread != caller {
            return Err(Failure::AccessDenied);
        }
        // A hook can veto a first destroy.
        let vetoed = !already
            && {
                let t = windows.thread(caller);
                !t.in_cleanup && !t.hooks_disabled
            }
            && s.cbt_destroy_veto(window);
        let windows = s.windows();
        if vetoed {
            return Ok(false);
        }
        // Hooks are disabled for the duration of a re-entry's destroy.
        let saved_hooks = if already {
            let t = windows.thread_mut(caller);
            let saved = t.hooks_disabled;
            t.hooks_disabled = true;
            Some(saved)
        } else {
            None
        };
        windows.at_mut(window).walk = Walk {
            already,
            saved_hooks,
            ..Walk::NONE
        };
        windows.at_mut(window).flags.destroying = true;
        Ok(true)
    }

    /// Whether `window`'s destroy is under way (begun, or reached by its parent's cascade) and it
    /// is not a zombie's re-entry (a window marked for destruction, which its destroy adopts).
    fn on_its_way(&self, window: WindowId) -> bool {
        let w = self.at(window);
        w.flags.destroying
            && !w.flags.in_wm_destroy
            && !self
                .handles
                .window(w.handle)
                .is_some_and(|e| e.marked_destroy)
    }

    /// The first part of `window`'s destroy, before the windows it owns go: a cross-thread
    /// owner's input sharing ends, a child tells its parent, and the window is hidden before
    /// anything is messaged.
    fn destroy_prologue(s: &mut dyn Session, window: WindowId) {
        let windows = s.windows();
        // A cross-thread owner's input sharing ends here.
        {
            let w = windows.at(window);
            let (thread, owner) = (w.thread, w.owner.filter(|_| !w.is_child()));
            if let Some(o) = owner {
                let owner_thread = windows.at(o).thread;
                if owner_thread != thread {
                    s.attach_input(thread, owner_thread, false);
                }
            }
        }
        let windows = s.windows();

        // A child tells its parent about the destroy before anything else happens to it.
        {
            let w = windows.at(window);
            if w.is_child() && w.ex_style & WS_EX_NOPARENTNOTIFY == 0 {
                if let Some(p) = w.parent {
                    let (menu_id, handle) = (w.menu.id().unwrap_or(0) as u16, w.handle);
                    s.send(
                        p,
                        &mut Message {
                            message: WM_PARENTNOTIFY,
                            wparam: makelong(WM_DESTROY as u16, menu_id),
                            lparam: handle as LParam,
                            payload: Payload::None,
                        },
                    );
                }
            }
        }
        let windows = s.windows();

        // Mark in-destroy (the mother desktop window excepted), then hide before anything is
        // messaged.
        if windows.at(window).parent.is_some() {
            windows.at_mut(window).flags.in_destroy = true;
        }
        if windows.at(window).is_visible() {
            // A child through ShowWindow's decision; a top-level window hidden without activating
            // anyone else or moving/resizing/reordering. Whether the hide took is the check below.
            if windows.at(window).is_child() {
                let _ = Windows::show_window(s, window, SW_HIDE);
            } else {
                let _ = Windows::set_window_pos(
                    s,
                    window,
                    InsertAfter::Top,
                    0,
                    0,
                    0,
                    0,
                    SWP_HIDEWINDOW | SWP_NOACTIVATE | SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER,
                );
            }
            let windows = s.windows();
            if windows.at(window).is_visible() {
                // The hide did not take: force the bit off and redraw what was below.
                windows.at_mut(window).style &= !WS_VISIBLE;
                s.redraw_below(window);
            }
        }
    }

    /// The first window `owner` owns on its desktop window's child list, scanning from the head
    /// (each destroy restarts the scan: callbacks may have created or reordered windows); none
    /// for a child window, which owns none.
    fn next_owned_window(&self, owner: WindowId) -> Option<WindowId> {
        if self.at(owner).is_child() {
            return None;
        }
        let desktop_window = self
            .desktop_by_id(self.at(owner).desktop)
            .and_then(|d| d.window)?;
        let mut current = self.at(desktop_window).child;
        while let Some(w) = current {
            if self.at(w).owner == Some(owner) {
                return Some(w);
            }
            current = self.at(w).next;
        }
        None
    }

    /// The last part of `window`'s destroy, once the windows it owned are gone: the activation
    /// fixups and the destroy messages (both skipped on the re-entry path, `already`), the
    /// unlink, and the free.
    fn destroy_epilogue(s: &mut dyn Session, caller: ThreadId, window: WindowId, already: bool) {
        let windows = s.windows();
        let desktop_window = windows
            .desktop_by_id(windows.at(window).desktop)
            .and_then(|d| d.window);

        // Activation fixups (skipped on the re-entry path).
        if !already {
            let mut target = None;
            let mut command = Activate::Skip;
            {
                let t = windows.thread(caller);
                if t.active == Some(window) {
                    let w = windows.at(window);
                    if w.is_popup() && w.owner.is_some() {
                        // A popup: try its creator.
                        target = w.owner;
                        command = Activate::Try;
                    } else {
                        // Skip to the next window.
                        target = Some(window);
                        command = Activate::Skip;
                    }
                } else if t.active.is_none() && windows.foreground_thread == Some(caller) {
                    target = Some(window);
                    command = Activate::Skip;
                }
            }
            if let Some(t) = target {
                let ok = s.activate(t, command);
                let windows = s.windows();
                if !ok
                    || (command == Activate::Skip && windows.thread(caller).active == Some(window))
                {
                    let t = windows.thread_mut(caller);
                    t.active = None;
                    t.focus = None;
                    s.destroy_caret();
                }
            }
            let windows = s.windows();
            // Fix the owner chain's last-active popup: repoint it to the direct owner.
            let owner = windows.at(window).owner;
            if let Some(o) = owner {
                let mut root = o;
                while let Some(n) = windows.at(root).owner {
                    root = n;
                }
                if windows.at(root).last_active == Some(window) {
                    windows.at_mut(root).last_active = Some(o);
                }
            }
        }

        // The destroy messages (skipped on the re-entry path). A WM_DESTROY handler that
        // destroyed the window again has freed it already: nothing is left to do.
        if !already {
            Windows::send_destroy_messages(s, window);
            if Windows::gone_in_destroy(s, window) {
                return;
            }
        }
        let windows = s.windows();

        // Unlink from the parent's child list (the re-entry path leaves the list alone).
        if let Some(p) = windows.at(window).parent {
            if !already {
                let w = windows.at(window);
                let (child, thread) = (w.is_child(), w.thread);
                let parent_thread = windows.at(p).thread;
                if child && Some(p) != desktop_window && parent_thread != thread {
                    s.attach_input(thread, parent_thread, false);
                }
                let windows = s.windows();
                windows.unlink_window(window, p);
            }
        }
        let windows = s.windows();

        // Mark destroyed (the owner field stays valid for handlers).
        windows.at_mut(window).flags.destroyed = true;

        // Free it.
        Windows::free_window(s, caller, window);
    }

    /// The WM_DESTROY cascade: the window first, then its children depth-first (parents assume
    /// their children exist during WM_DESTROY), each window's focus check after its subtree's. A
    /// handler that destroys the next sibling ends the walk of their parent's children
    /// ([`Walk::next`]).
    fn send_destroy_messages(s: &mut dyn Session, window: WindowId) {
        s.windows().at_mut(window).flags.in_wm_destroy = true;
        Windows::send_destroy(s, window);
        if Windows::gone_in_destroy(s, window) {
            return;
        }
        s.windows().at_mut(window).flags.in_wm_destroy = false;
        let mut current = window;
        let mut descend = true;
        loop {
            let windows = s.windows();
            if descend {
                if let Some(child) = windows.at(current).child {
                    let next = windows.at(child).next;
                    windows.at_mut(child).walk.next = next;
                    current = child;
                    Windows::send_destroy(s, current);
                    continue;
                }
            }
            // `current`'s subtree is done.
            s.check_focus(current);
            let windows = s.windows();
            if current == window {
                return;
            }
            let parent = windows.at(current).parent.expect("a child has its parent");
            // Continue only while the next sibling is still a live child of the parent.
            match windows.at_mut(current).walk.next.take() {
                Some(next)
                    if windows.pool.is_live(next) && windows.at(next).parent == Some(parent) =>
                {
                    let after = windows.at(next).next;
                    windows.at_mut(next).walk.next = after;
                    current = next;
                    Windows::send_destroy(s, current);
                    descend = true;
                }
                _ => {
                    current = parent;
                    descend = false;
                }
            }
        }
    }

    /// Whether `window`, whose WM_DESTROY was just sent, went meanwhile: its handler destroyed
    /// it again, in full (freed, or a zombie: its handle marked for destruction). Its destroyed
    /// flag tells nothing here: a parent's free sets it on a child of another thread's before
    /// that thread destroys it.
    fn gone_in_destroy(s: &mut dyn Session, window: WindowId) -> bool {
        let windows = s.windows();
        !windows.pool.is_live(window)
            || windows
                .handles
                .window(windows.at(window).handle)
                .is_none_or(|e| e.marked_destroy)
    }

    /// One window's step of the WM_DESTROY cascade, before its children's: the focus check, the
    /// clipboard, and WM_DESTROY itself.
    fn send_destroy(s: &mut dyn Session, window: WindowId) {
        s.windows().at_mut(window).flags.destroying = true;
        s.check_focus(window);
        let windows = s.windows();
        if windows.clipboard_owner == Some(window) {
            s.disown_clipboard(window);
        }
        s.send(
            window,
            &mut Message {
                message: WM_DESTROY,
                wparam: 0,
                lparam: 0,
                payload: Payload::None,
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use rtl::user::{
        WM_NCDESTROY,
        WM_SHOWWINDOW,
        WM_WINDOWPOSCHANGED,
        WM_WINDOWPOSCHANGING,
        WS_CHILD,
        WS_OVERLAPPED,
        WS_POPUP,
    };

    use super::*;
    use crate::status::*;
    use crate::win32k::class;
    use crate::win32k::window::testkit::*;

    /// An invalid handle names no window; the destroy service answers
    /// ERROR_INVALID_WINDOW_HANDLE (1400).
    #[test]
    fn an_invalid_handle_names_no_window() {
        let (w, c, t, _atom, _, _) = setup();
        let mut pump = Rec::new(t);
        assert_eq!(w.window_from_handle(0xDEAD_BEEF), None);
        assert_eq!(w.window_from_handle(0), None);
        let err = Windows::destroy_window_handle(&mut pump.on(w, c), t, 0xDEAD_BEEF).unwrap_err();
        assert_eq!(err, Failure::InvalidWindowHandle);
        assert_eq!(err.code(), 1400);
        assert_eq!(
            err.status(),
            NtStatus(0xC007_0578),
            "the error itself, carried"
        );
    }

    /// Another thread's window cannot be destroyed: ERROR_ACCESS_DENIED (5), nothing happens.
    #[test]
    fn another_threads_window_cannot_be_destroyed() {
        let (w, c, t, atom, _, _) = setup();
        let t2 = w
            .add_thread(OTHER_OWNER, DESKTOP, DESKTOP_CREATEWINDOW, Some(0x50), None)
            .unwrap();
        let mut pump = Rec::new(t);
        let id = create(w, c, t, atom, WS_OVERLAPPED, &mut pump).unwrap();
        let mut pump2 = Rec::new(t2);
        let err = Windows::destroy_window(&mut pump2.on(w, c), t2, id).unwrap_err();
        assert_eq!(err, Failure::AccessDenied);
        assert_eq!(err.code(), 5);
        assert!(w.pool.is_live(id));
        assert!(!w.at(id).flags.destroyed);
        assert!(pump2.events.is_empty());
    }

    /// A window already marked for destruction is adopted by the current thread and the destroy
    /// proceeds instead of failing the owner check.
    #[test]
    fn a_marked_window_is_destroyed_on_reentry() {
        let (w, c, t, atom, _, _) = setup();
        let t2 = w
            .add_thread(OTHER_OWNER, DESKTOP, DESKTOP_CREATEWINDOW, Some(0x60), None)
            .unwrap();
        let mut pump = Rec::new(t);
        let id = create(w, c, t, atom, WS_OVERLAPPED, &mut pump).unwrap();
        let handle = w.at(id).handle;
        // Marked for destroy, owned by the other thread.
        w.handles.update_window(handle, |mut e| {
            e.marked_destroy = true;
            e.owner = t2;
            e
        });
        w.at_mut(id).thread = t2;
        let mut pump2 = Rec::new(t);
        assert!(Windows::destroy_window(&mut pump2.on(w, c), t, id).unwrap());
        assert!(!w.pool.is_live(id));
    }

    /// A hook's veto leaves the window untouched: false, no messages, not marked.
    #[test]
    fn a_hook_can_veto_the_destroy() {
        let (w, c, t, atom, _, _) = setup();
        let mut pump = Rec::new(t);
        let id = create(w, c, t, atom, WS_OVERLAPPED, &mut pump).unwrap();
        pump.events.clear();
        pump.veto_destroy = true;
        assert!(!Windows::destroy_window(&mut pump.on(w, c), t, id).unwrap());
        assert!(w.pool.is_live(id));
        assert!(!w.at(id).flags.destroyed);
        assert!(pump.events.is_empty());
    }

    /// The destroy hides before anything is messaged: a child gets SW_HIDE, a top-level gets the
    /// hide-only SetWindowPos; a child tells its parent first; if the hide does not take, the
    /// visible bit is forced off and the windows below are redrawn.
    #[test]
    fn the_destroy_hides_before_messaging() {
        let (w, c, t, atom, _, _) = setup();
        let parent = raw_window(w, t, WS_OVERLAPPED, None);
        let mut pump = Rec::new(t);
        let mut a = args(atom, WS_CHILD | WS_VISIBLE);
        a.parent = Some(parent);
        let id = Windows::create_window_ex(&mut pump.on(w, c), t, &a).unwrap();
        let handle = w.at(id).handle;
        pump.events.clear();
        pump.positions.clear();
        assert!(Windows::destroy_window(&mut pump.on(w, c), t, id).unwrap());
        assert_eq!(
            pump.sends(),
            vec![
                (parent, WM_PARENTNOTIFY),
                (id, WM_SHOWWINDOW),
                (id, WM_WINDOWPOSCHANGING),
                (id, WM_WINDOWPOSCHANGED),
                (id, WM_DESTROY),
                (id, WM_NCDESTROY)
            ]
        );
        // The parent notify carried WM_DESTROY and the child's handle.
        assert!(pump.events.contains(&Ev::Send(
            parent,
            WM_PARENTNOTIFY,
            makelong(WM_DESTROY as u16, 0),
            handle as LParam
        )));
        // The hide (SW_HIDE) came before the first WM_DESTROY.
        let first_destroy = pump
            .events
            .iter()
            .position(|e| matches!(e, Ev::Send(_, WM_DESTROY, _, _)))
            .unwrap();
        let hide = pump
            .events
            .iter()
            .position(|e| *e == Ev::Send(id, WM_SHOWWINDOW, 0, 0))
            .unwrap();
        assert!(hide < first_destroy);
        assert_eq!(
            pump.changing_flags(),
            vec![(
                id,
                SWP_HIDEWINDOW | SWP_NOACTIVATE | SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER
            )],
            "a child's hide does not activate"
        );
        // A top-level window gets the hide-only SetWindowPos instead (no WM_SHOWWINDOW).
        let mut pump = Rec::new(t);
        let id = create(w, c, t, atom, WS_OVERLAPPED | WS_VISIBLE, &mut pump).unwrap();
        pump.events.clear();
        pump.positions.clear();
        assert!(Windows::destroy_window(&mut pump.on(w, c), t, id).unwrap());
        assert_eq!(
            pump.changing_flags(),
            vec![(
                id,
                SWP_HIDEWINDOW | SWP_NOACTIVATE | SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER
            )]
        );
        assert!(!pump.messages().contains(&WM_SHOWWINDOW));
        // A hide that does not take: the visible bit is forced off and below is redrawn.
        let mut pump = Rec::new(t);
        pump.hide_works = false; // a WM_WINDOWPOSCHANGED handler shows the window again
        let id = create(w, c, t, atom, WS_OVERLAPPED | WS_VISIBLE, &mut pump).unwrap();
        pump.events.clear();
        assert!(Windows::destroy_window(&mut pump.on(w, c), t, id).unwrap());
        assert!(pump.events.contains(&Ev::Redraw(id)));
    }

    /// Owned windows are destroyed before the owner's own WM_DESTROY.
    #[test]
    fn owned_windows_go_first() {
        let (w, c, t, atom, _, _) = setup();
        let mut pump = Rec::new(t);
        let owner = create(w, c, t, atom, WS_OVERLAPPED, &mut pump).unwrap();
        let mut a = args(atom, WS_POPUP);
        a.parent = Some(owner);
        let owned = Windows::create_window_ex(&mut pump.on(w, c), t, &a).unwrap();
        assert_eq!(w.at(owned).owner, Some(owner));
        pump.events.clear();
        assert!(Windows::destroy_window(&mut pump.on(w, c), t, owner).unwrap());
        let sends = pump.sends();
        let owned_destroy = sends
            .iter()
            .position(|(t2, m)| *t2 == owned && *m == WM_DESTROY)
            .unwrap();
        let owner_destroy = sends
            .iter()
            .position(|(t2, m)| *t2 == owner && *m == WM_DESTROY)
            .unwrap();
        assert!(owned_destroy < owner_destroy);
        assert_eq!(
            &sends[owned_destroy..owned_destroy + 2],
            &[(owned, WM_DESTROY), (owned, WM_NCDESTROY)]
        );
    }

    /// Destroying the active window activates its owner (a popup) or skips to the next; a
    /// failed activation clears the active/focus windows and destroys the caret; the owner
    /// chain's last-active popup is repointed to the direct owner.
    #[test]
    fn the_active_window_fixups() {
        let (w, c, t, atom, _, _) = setup();
        let mut pump = Rec::new(t);
        let owner = create(w, c, t, atom, WS_OVERLAPPED, &mut pump).unwrap();
        let mut a = args(atom, WS_POPUP);
        a.parent = Some(owner);
        let popup = Windows::create_window_ex(&mut pump.on(w, c), t, &a).unwrap();
        w.thread_mut(t).active = Some(popup);
        w.thread_mut(t).focus = Some(popup);
        w.at_mut(owner).last_active = Some(popup);
        pump.events.clear();
        assert!(Windows::destroy_window(&mut pump.on(w, c), t, popup).unwrap());
        // A popup's creator is tried.
        assert!(pump.events.contains(&Ev::Activate(owner, Activate::Try)));
        assert_eq!(
            w.at(owner).last_active,
            Some(owner),
            "repointed to the direct owner"
        );
        // A failed activation of the active window clears active/focus and the caret.
        let id = create(w, c, t, atom, WS_OVERLAPPED, &mut pump).unwrap();
        w.thread_mut(t).active = Some(id);
        w.thread_mut(t).focus = Some(id);
        pump.activate_ok = false;
        pump.events.clear();
        assert!(Windows::destroy_window(&mut pump.on(w, c), t, id).unwrap());
        assert!(pump.events.contains(&Ev::Activate(id, Activate::Skip)));
        assert_eq!(w.thread(t).active, None);
        assert_eq!(w.thread(t).focus, None);
        assert!(pump.events.contains(&Ev::Caret));
    }

    /// Build the tree P -> C1 -> G1, C2.
    fn tree(
        w: &mut Windows,
        c: &mut class::Registry,
        t: ThreadId,
        atom: class::Atom,
        pump: &mut Rec,
    ) -> (WindowId, WindowId, WindowId, WindowId) {
        let p = create(w, c, t, atom, WS_OVERLAPPED, pump).unwrap();
        let mut a = args(atom, WS_CHILD);
        a.parent = Some(p);
        let c1 = Windows::create_window_ex(&mut pump.on(w, c), t, &a).unwrap();
        let mut a = args(atom, WS_CHILD);
        a.parent = Some(c1);
        let g1 = Windows::create_window_ex(&mut pump.on(w, c), t, &a).unwrap();
        let mut a = args(atom, WS_CHILD);
        a.parent = Some(p);
        let c2 = Windows::create_window_ex(&mut pump.on(w, c), t, &a).unwrap();
        (p, c1, g1, c2)
    }

    /// The full cascade order: every window's WM_DESTROY precedes its WM_NCDESTROY, the children
    /// depth-first parent before children, and the parent's WM_NCDESTROY after its children's;
    /// then the unlink and the freed records.
    #[test]
    fn the_full_cascade_order() {
        let (w, c, t, atom, desk, _) = setup();
        let mut pump = Rec::new(t);
        let (p, c1, g1, c2) = tree(w, c, t, atom, &mut pump);
        pump.events.clear();
        assert!(Windows::destroy_window(&mut pump.on(w, c), t, p).unwrap());
        assert_eq!(
            pump.sends(),
            vec![
                (p, WM_DESTROY),
                (c1, WM_DESTROY),
                (g1, WM_DESTROY),
                (c2, WM_DESTROY),
                (g1, WM_NCDESTROY),
                (c1, WM_NCDESTROY),
                (c2, WM_NCDESTROY),
                (p, WM_NCDESTROY),
            ]
        );
        assert_eq!(w.at(desk).child, None, "unlinked from the desktop's list");
        for id in [p, c1, g1, c2] {
            assert!(!w.pool.is_live(id), "the record was freed");
        }
        assert_eq!(w.thread(t).window_count, 0);
    }

    /// A handler that destroys the next sibling during WM_DESTROY stops the child loop (the
    /// sibling's own destroy already ran inside the handler).
    #[test]
    fn a_handler_destroying_a_sibling_stops_the_loop() {
        let (w, c, t, atom, _, _) = setup();
        let mut pump = Rec::new(t);
        let (p, c1, g1, c2) = tree(w, c, t, atom, &mut pump);
        pump.events.clear();
        pump.destroy_on_destroy = Some((c1, c2));
        assert!(Windows::destroy_window(&mut pump.on(w, c), t, p).unwrap());
        assert_eq!(
            pump.sends(),
            vec![
                (p, WM_DESTROY),
                (c1, WM_DESTROY),
                // The handler's destroy of c2 (a child, so it notifies its parent first):
                (p, WM_PARENTNOTIFY),
                (c2, WM_DESTROY),
                (c2, WM_NCDESTROY),
                (g1, WM_DESTROY),
                (g1, WM_NCDESTROY),
                (c1, WM_NCDESTROY),
                (p, WM_NCDESTROY),
            ]
        );
    }

    /// A window destroyed from its own WM_DESTROY handler is destroyed again, nested: the inner
    /// destroy's WM_DESTROY and WM_NCDESTROY come inside the outer WM_DESTROY, and the outer
    /// destroy finds the window gone (guiwin `dienest`).
    #[test]
    fn a_window_destroyed_in_its_own_wm_destroy_is_destroyed_nested() {
        let (w, c, t, atom, _, _) = setup();
        let mut pump = Rec::new(t);
        let top = create(w, c, t, atom, WS_OVERLAPPED, &mut pump).unwrap();
        pump.events.clear();
        pump.destroy_self_on = Some(WM_DESTROY);
        assert!(Windows::destroy_window(&mut pump.on(w, c), t, top).unwrap());
        assert_eq!(
            pump.sends(),
            vec![(top, WM_DESTROY), (top, WM_DESTROY), (top, WM_NCDESTROY)]
        );
        assert!(!w.pool.is_live(top));
    }

    /// A window destroyed from its own WM_NCDESTROY handler is on its way already: the nested
    /// DestroyWindow succeeds and does nothing, so each message comes once.
    #[test]
    fn a_handler_destroying_its_own_window_changes_nothing() {
        for message in [WM_NCDESTROY] {
            let (w, c, t, atom, _, _) = setup();
            let mut pump = Rec::new(t);
            let top = create(w, c, t, atom, WS_OVERLAPPED, &mut pump).unwrap();
            pump.events.clear();
            pump.destroy_self_on = Some(message);
            assert!(Windows::destroy_window(&mut pump.on(w, c), t, top).unwrap());
            assert_eq!(pump.sends(), vec![(top, WM_DESTROY), (top, WM_NCDESTROY)]);
            assert!(!w.pool.is_live(top));
        }
    }

    /// A chain of children as deep as the nesting limit allows goes in one destroy: WM_DESTROY
    /// from the top down, WM_NCDESTROY from the bottom up, every record freed (the cascade keeps
    /// its place in the records, not in recursion).
    #[test]
    fn the_deepest_nesting_is_destroyed() {
        let (w, c, t, atom, desk, _) = setup();
        let mut pump = Rec::new(t);
        let top = create(w, c, t, atom, WS_OVERLAPPED, &mut pump).unwrap();
        let mut chain = vec![top];
        for _ in 0..98 {
            let mut a = args(atom, WS_CHILD);
            a.ex_style = WS_EX_NOPARENTNOTIFY;
            a.parent = chain.last().copied();
            chain.push(Windows::create_window_ex(&mut pump.on(w, c), t, &a).unwrap());
        }
        pump.events.clear();
        assert!(Windows::destroy_window(&mut pump.on(w, c), t, top).unwrap());
        let destroys: Vec<WindowId> = pump
            .sends()
            .iter()
            .filter(|(_, m)| *m == WM_DESTROY)
            .map(|(id, _)| *id)
            .collect();
        assert_eq!(destroys, chain);
        let ncdestroys: Vec<WindowId> = pump
            .sends()
            .iter()
            .filter(|(_, m)| *m == WM_NCDESTROY)
            .map(|(id, _)| *id)
            .collect();
        assert_eq!(ncdestroys, chain.iter().rev().copied().collect::<Vec<_>>());
        assert!(chain.iter().all(|&id| !w.pool.is_live(id)));
        assert_eq!(w.at(desk).child, None);
        assert_eq!(w.thread(t).window_count, 0);
    }

    /// An owner chain goes deepest first: each owned window's destroy runs whole before its
    /// owner's WM_DESTROY, each hidden before the windows it owns go.
    #[test]
    fn an_owner_chain_is_destroyed_deepest_first() {
        let (w, c, t, atom, _, _) = setup();
        let mut pump = Rec::new(t);
        let root = create(w, c, t, atom, WS_OVERLAPPED | WS_VISIBLE, &mut pump).unwrap();
        let mut chain = vec![root];
        for _ in 0..40 {
            let mut a = args(atom, WS_POPUP | WS_VISIBLE);
            a.parent = chain.last().copied();
            let owned = Windows::create_window_ex(&mut pump.on(w, c), t, &a).unwrap();
            assert_eq!(w.at(owned).owner, chain.last().copied());
            chain.push(owned);
        }
        pump.events.clear();
        assert!(Windows::destroy_window(&mut pump.on(w, c), t, root).unwrap());
        let sends: Vec<(WindowId, u32)> = pump
            .sends()
            .into_iter()
            .filter(|(_, m)| *m == WM_DESTROY || *m == WM_NCDESTROY)
            .collect();
        let expected: Vec<(WindowId, u32)> = chain
            .iter()
            .rev()
            .flat_map(|&id| [(id, WM_DESTROY), (id, WM_NCDESTROY)])
            .collect();
        assert_eq!(sends, expected);
        // Every hide comes before the first WM_DESTROY, the root's first.
        let hides: Vec<WindowId> = pump
            .changing_flags()
            .into_iter()
            .filter(|(_, flags)| flags & SWP_HIDEWINDOW != 0)
            .map(|(id, _)| id)
            .collect();
        assert_eq!(hides, chain);
        let first_destroy = pump
            .messages()
            .iter()
            .position(|&m| m == WM_DESTROY)
            .unwrap();
        let last_hide = pump
            .messages()
            .iter()
            .rposition(|&m| m == WM_WINDOWPOSCHANGED)
            .unwrap();
        assert!(last_hide < first_destroy);
        assert!(chain.iter().all(|&id| !w.pool.is_live(id)));
        assert_eq!(w.thread(t).window_count, 0);
    }

    /// An owned window whose destroy a hook vetoes loses its owner, and so does one of another
    /// thread's; the owner's destroy goes on (the scan would find them again otherwise).
    #[test]
    fn an_owned_window_that_cannot_go_loses_its_owner() {
        let (w, c, t, atom, desk, _) = setup();
        let mut pump = Rec::new(t);
        let owner = create(w, c, t, atom, WS_OVERLAPPED, &mut pump).unwrap();
        let mut a = args(atom, WS_POPUP);
        a.parent = Some(owner);
        let owned = Windows::create_window_ex(&mut pump.on(w, c), t, &a).unwrap();
        let t2 = w
            .add_thread(OTHER_OWNER, DESKTOP, DESKTOP_CREATEWINDOW, Some(0x70), None)
            .unwrap();
        let foreign = raw_window(w, t2, WS_POPUP, Some(desk));
        w.link_window(foreign, ZOrder::Top, desk);
        w.at_mut(foreign).owner = Some(owner);
        // The hook vetoes the owned window's destroy alone.
        pump.veto_window = Some(owned);
        assert!(Windows::destroy_window(&mut pump.on(w, c), t, owner).unwrap());
        assert!(!w.pool.is_live(owner));
        assert!(w.pool.is_live(owned));
        assert_eq!(w.at(owned).owner, None, "the vetoed window lost its owner");
        assert!(w.pool.is_live(foreign));
        assert_eq!(
            w.at(foreign).owner,
            None,
            "the foreign window lost its owner"
        );
    }
}
