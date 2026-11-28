//! A destroyed window's free: WM_NCDESTROY, the cleanup, and the free-or-zombie decision.

use rtl::user::{WM_NCDESTROY, WS_VISIBLE};

use super::*;
use crate::sched::thread::ThreadId;
use crate::win32k::class;

impl Windows {
    /// The free of `window` and its children: each child is unlinked and marked destroyed; a
    /// same-thread child is freed, its children first (each WM_NCDESTROY precedes its parent's); a
    /// cross-thread child gets a destroy event on its own queue. The walk climbs back through the
    /// parent links, which the unlink leaves in place.
    pub(super) fn free_window(s: &mut dyn Session, caller: ThreadId, window: WindowId) {
        let windows = s.windows();
        windows.adopt_marked(caller, window);
        let mut current = window;
        loop {
            let windows = s.windows();
            if let Some(child) = windows.at(current).child {
                {
                    let w = windows.at_mut(child);
                    // Don't try to hide a child whose parent is dying.
                    w.style &= !WS_VISIBLE;
                    w.flags.destroyed = true;
                }
                windows.unlink_window(child, current);
                let child_thread = windows.at(child).thread;
                if child_thread != caller {
                    // Its own thread destroys it, in full.
                    windows.at_mut(child).flags.destroying = false;
                    s.post_destroy_event(child_thread, child);
                } else {
                    windows.adopt_marked(caller, child);
                    current = child;
                }
                continue;
            }
            let windows = s.windows();
            let parent = windows.at(current).parent;
            Windows::free_record(s, caller, current);
            if current == window {
                return;
            }
            current = parent.expect("a freed child's parent");
        }
    }

    /// A window marked for destruction is adopted by the current thread at its free.
    fn adopt_marked(&mut self, caller: ThreadId, window: WindowId) {
        let handle = self.at(window).handle;
        if self
            .handles
            .window(handle)
            .is_some_and(|e| e.marked_destroy)
        {
            self.handles.update_window(handle, |mut e| {
                e.owner = caller;
                e
            });
            self.at_mut(window).thread = caller;
        }
    }

    /// The free of one window whose children are gone: the cleanup ordering, then the
    /// free-vs-zombie decision. WM_NCDESTROY to this window, then the backpointers, menus,
    /// properties, the class dereference, and the handle marks. The last lock frees the record
    /// and the handle; any other lock count leaves a zombie.
    fn free_record(s: &mut dyn Session, caller: ThreadId, window: WindowId) {
        let windows = s.windows();
        let handle = windows.at(window).handle;

        // WM_NCDESTROY to this window.
        s.send(
            window,
            &mut Message {
                message: WM_NCDESTROY,
                wparam: 0,
                lparam: 0,
                payload: Payload::None,
            },
        );
        let windows = s.windows();

        // Clear the owner's last-active if it points at this window.
        let owner = windows.at(window).owner;
        if let Some(o) = owner {
            if windows.at(o).last_active == Some(window) {
                windows.at_mut(o).last_active = Some(o);
            }
        }

        // Clear the queue and desktop backpointers that point at this window.
        {
            let t = windows.thread_mut(caller);
            if t.focus == Some(window) {
                t.focus = None;
            }
            if t.active_prev == Some(window) {
                t.active_prev = None;
            }
            if t.capture == Some(window) {
                t.capture = None;
                s.release_capture();
            }
        }
        let windows = s.windows();
        let desktop_id = windows.at(window).desktop;
        if let Some(d) = windows.desktop_by_id_mut(desktop_id) {
            if d.foreground == Some(window) {
                d.foreground = None;
            }
            if d.tray == Some(window) {
                d.tray = None;
            }
        }
        if windows.clipboard_owner == Some(window) {
            windows.clipboard_owner = None;
        }

        // Timers, hotkeys, pending sends; then a queued WM_QUIT is re-posted with its exit code.
        s.window_teardown(window);
        s.repost_quit(window);
        let windows = s.windows();

        // The menus: a top-level window's menu goes (the desktop's shared dialog system menu
        // does not).
        {
            let w = windows.at(window);
            if !w.is_child() {
                if let Menu::Handle(h) = w.menu {
                    let shared = windows
                        .desktop_by_id(w.desktop)
                        .is_some_and(|d| d.dialog_menu == h);
                    if h != 0 && !shared {
                        s.destroy_menu(h);
                    }
                }
            }
        }
        let windows = s.windows();
        // And its copy of the system menu (GetSystemMenu's).
        windows.destroy_system_menu(window);

        // The properties, the texts and the extra bytes go with the record.
        s.delete_properties(window);
        let (windows, classes) = s.parts();
        let (title, name) = {
            let w = windows.at_mut(window);
            (
                core::mem::take(&mut w.title),
                core::mem::take(&mut w.create_name),
            )
        };
        windows.texts.free(title);
        windows.texts.free(name);
        if let Some(block) = windows.at_mut(window).extra.take() {
            windows.extra.free(block);
        }

        // The links: a zombie window re-points its parent at the desktop window; a freed one
        // drops them.
        let desktop_window = windows
            .desktop_by_id(windows.at(window).desktop)
            .and_then(|d| d.window);
        {
            let w = windows.at_mut(window);
            if Some(window) != desktop_window {
                w.parent = desktop_window;
            } else {
                w.parent = None;
            }
            w.child = None;
            w.owner = None;
            w.last_active = None;
        }

        // The class reference goes back.
        if let Some(class_id) = windows.at(window).class {
            let mut view = class::Window {
                class: class_id,
                owner: windows.at(window).process,
                desktop: windows.at(window).desktop,
            };
            classes.dereference_class(&mut windows.handles, &mut view);
        }

        // Mark the handle for destruction (the in-destroy flag blocks unlock recursion).
        windows.handles.update_window(handle, |mut e| {
            e.marked_destroy = true;
            e.in_destroy = true;
            e
        });

        // The final unlock: the record's lock count drops.
        let locks = {
            let w = windows.at_mut(window);
            w.locks -= 1;
            w.locks
        };
        if locks > 0 {
            // Still referenced elsewhere: the window becomes a zombie, not freed.
            windows.handles.update_window(handle, |mut e| {
                e.in_destroy = false;
                e
            });
            windows.make_zombie(classes, window);
            return;
        }

        // The last reference: free the record and the handle (the old HWND stops validating).
        windows.at_mut(window).class = None;
        windows.thread_mut(caller).window_count -= 1;
        windows.at_mut(window).parent = None;
        windows.handles.close(handle);
        windows.pool.free(window);
    }

    /// The zombie: a still-referenced window at its free becomes an inert icon-title window —
    /// the default procedure, the icon-title system class, server-side, tiled, menu-less — and
    /// its handle stays valid until the last reference drops it.
    fn make_zombie(&mut self, classes: &mut class::Registry, window: WindowId) {
        {
            let w = self.at_mut(window);
            w.proc = Proc::Default;
            w.flags.server_side_proc = true;
            w.flags.has_palette = false;
        }
        let (process, desktop_id) = {
            let w = self.at(window);
            (w.process, w.desktop)
        };
        if let Some(icon) = classes.class_ptr(ICONTITLE_ATOM, process, class::WINDOW_MANAGER_MODULE)
        {
            let mut view = class::Window {
                class: icon,
                owner: process,
                desktop: desktop_id,
            };
            if classes.reference_class(icon, &mut view) {
                self.at_mut(window).class = Some(view.class);
            }
        }
        let w = self.at_mut(window);
        // The type bits are cleared and the window becomes tiled; the menu goes.
        w.style &= 0x0000_FFFF;
        w.menu = Menu::None;
    }
}

#[cfg(test)]
mod tests {
    use rtl::testing::wide;
    use rtl::user::{WM_DESTROY, WS_OVERLAPPED};

    use super::*;
    use crate::win32k::class::RegisterFlags;
    use crate::win32k::window::testkit::*;

    /// A window's copy of the system menu is the menu GetSystemMenu attached to it, until the
    /// menu goes or the window does, which takes the menu with it; bRevert destroys it.
    #[test]
    fn the_system_menu_copy_is_the_windows() {
        let (w, _, t, _, _, _) = setup();
        let a = raw_window(w, t, WS_OVERLAPPED, None);
        let b = raw_window(w, t, WS_OVERLAPPED, None);
        let (ha, hb) = (w.handle_of(a), w.handle_of(b));
        assert_eq!(w.system_menu_handle(ha, false, 0), Ok(0), "no copy yet");
        let copy = w.menus.create(&mut w.handles, OWNER).unwrap();
        assert_eq!(w.system_menu_handle(ha, false, copy), Ok(copy));
        assert_eq!(w.system_menu_handle(ha, false, 0), Ok(copy));
        assert_eq!(
            w.system_menu_handle(hb, false, 0),
            Ok(0),
            "another window's"
        );
        w.destroy_menu_handle(copy).unwrap();
        assert_eq!(
            w.system_menu_handle(ha, false, 0),
            Ok(0),
            "a destroyed copy"
        );
        let copy = w.menus.create(&mut w.handles, OWNER).unwrap();
        assert_eq!(w.system_menu_handle(ha, false, copy), Ok(copy));
        assert_eq!(w.system_menu_handle(ha, true, 0), Ok(0));
        assert!(w.menu_of(copy).is_err(), "bRevert destroys the copy");
        assert_eq!(w.system_menu_handle(ha, false, 0), Ok(0));
        let copy = w.menus.create(&mut w.handles, OWNER).unwrap();
        assert_eq!(w.system_menu_handle(hb, false, copy), Ok(copy));
        w.destroy_system_menu(b);
        assert!(
            w.menu_of(copy).is_err(),
            "the window's end destroys its copy"
        );
    }

    /// The free's cleanup calls run after WM_NCDESTROY, in order: the window teardown, the quit
    /// repost, the menu's destroy, the properties; the class reference goes back.
    #[test]
    fn the_free_cleanup_calls() {
        let (w, c, t, atom, _, _) = setup();
        let mut pump = Rec::new(t);
        let mut a = args(atom, WS_OVERLAPPED);
        a.menu = MenuInput::Handle(0x9000);
        let id = Windows::create_window_ex(&mut pump.on(w, c), t, &a).unwrap();
        pump.events.clear();
        assert!(Windows::destroy_window(&mut pump.on(w, c), t, id).unwrap());
        let after = &pump.events[pump
            .events
            .iter()
            .position(|e| matches!(e, Ev::Send(_, WM_NCDESTROY, _, _)))
            .unwrap()
            + 1..];
        assert_eq!(
            after,
            &[
                Ev::Teardown(id),
                Ev::Quit(id),
                Ev::DestroyMenu(0x9000),
                Ev::Props(id),
            ]
        );
        // The class reference went back.
        assert!(c
            .unregister_class(
                &mut w.handles,
                class::Name::Text(&wide("Test")),
                OWNER,
                MODULE
            )
            .is_ok());
    }

    /// The free-vs-zombie decision: with the last lock the record and handle are freed (the old
    /// HWND stops validating); with another reference held the window becomes a zombie: the
    /// default procedure, the icon-title class, server-side, tiled, menu-less, handle still
    /// valid.
    #[test]
    fn the_free_vs_zombie_decision() {
        let (w, c, t, atom, _, _) = setup();
        // The icon-title system class ("#32771").
        let mut wc = wnd_class();
        wc.instance = class::WINDOW_MANAGER_MODULE;
        let icon = c
            .register_class(
                &w.handles,
                &wc,
                class::Name::Atom(ICONTITLE_ATOM),
                class::MenuArg::None,
                OWNER,
                RegisterFlags {
                    win40_compat: true,
                    system_class: true,
                    ..RegisterFlags::default()
                },
                DESKTOP,
            )
            .unwrap();
        assert_eq!(icon, ICONTITLE_ATOM);
        let mut pump = Rec::new(t);
        // Freed: the last lock.
        let id = create(w, c, t, atom, WS_OVERLAPPED, &mut pump).unwrap();
        let handle = w.at(id).handle;
        assert!(Windows::destroy_window(&mut pump.on(w, c), t, id).unwrap());
        assert!(!w.pool.is_live(id));
        assert_eq!(
            w.window_from_handle(handle),
            None,
            "the old HWND no longer validates"
        );
        assert_eq!(w.thread(t).window_count, 0);
        // Zombie: another reference held.
        let mut a = args(atom, WS_OVERLAPPED);
        a.menu = MenuInput::Handle(0x9000);
        let id = Windows::create_window_ex(&mut pump.on(w, c), t, &a).unwrap();
        let handle = w.at(id).handle;
        w.at_mut(id).locks = 2;
        assert!(Windows::destroy_window(&mut pump.on(w, c), t, id).unwrap());
        assert!(w.pool.is_live(id), "the zombie stays");
        assert_eq!(
            w.window_from_handle(handle),
            Some(id),
            "its handle still validates"
        );
        let rec = w.at(id);
        assert_eq!(rec.proc, Proc::Default);
        assert!(rec.flags.server_side_proc);
        assert_eq!(
            rec.class,
            c.class_ptr(ICONTITLE_ATOM, OWNER, class::WINDOW_MANAGER_MODULE)
        );
        assert_eq!(
            rec.style & 0xFFFF_0000,
            0,
            "the type bits are cleared (tiled)"
        );
        assert_eq!(rec.menu, Menu::None);
        assert_eq!(
            w.thread(t).window_count,
            1,
            "the count drops only at the real free"
        );
    }

    /// The end state of a clean destroy: true, WM_DESTROY then WM_NCDESTROY, unlinked from the
    /// desktop's child list, the class reference and window count back, the handle freed so a
    /// second destroy of the same HWND fails with 1400.
    #[test]
    fn the_end_state_after_a_clean_destroy() {
        let (w, c, t, atom, desk, _) = setup();
        let mut pump = Rec::new(t);
        let id = create(w, c, t, atom, WS_OVERLAPPED, &mut pump).unwrap();
        let handle = w.at(id).handle;
        assert_eq!(w.at(desk).child, Some(id));
        pump.events.clear();
        assert!(Windows::destroy_window_handle(&mut pump.on(w, c), t, handle).unwrap());
        assert_eq!(pump.sends(), vec![(id, WM_DESTROY), (id, WM_NCDESTROY)]);
        assert!(!w.pool.is_live(id));
        assert_eq!(w.at(desk).child, None);
        assert_eq!(w.thread(t).window_count, 0);
        assert!(
            c.unregister_class(
                &mut w.handles,
                class::Name::Text(&wide("Test")),
                OWNER,
                MODULE
            )
            .is_ok(),
            "the class reference is back"
        );
        // A second destroy of the same HWND: 1400.
        let err = Windows::destroy_window_handle(&mut pump.on(w, c), t, handle).unwrap_err();
        assert_eq!(err, Failure::InvalidWindowHandle);
        assert_eq!(err.code(), 1400);
    }
}
