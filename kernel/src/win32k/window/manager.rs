//! The window manager ([`WindowManager`]): both registries behind one lock, the boot's desktops,
//! and the creation service's decision.

use rtl::gdi::Rect;
use rtl::user::{CS_DBLCLKS, WS_CLIPCHILDREN, WS_POPUP, WS_VISIBLE};
use rtl::window::DESKTOP_CLASS_ATOM;

use super::*;
use crate::sched::thread::ThreadId;
use crate::win32k::class;

/// The message window's class name, "Message".
const MESSAGE_CLASS: [u16; 7] = [
    b'M' as u16,
    b'e' as u16,
    b's' as u16,
    b's' as u16,
    b'a' as u16,
    b'g' as u16,
    b'e' as u16,
];

/// The window manager's state behind its one lock (as one lock guards all of Windows 2000's): the
/// window and class registries, the clipboard, the accelerator tables, the properties and the
/// scroll bars. The decisions let go of it only around a callback to user mode
/// ([`Hold::unlocked`]), reading both registries again after. A short lock's guard keeps its
/// taker's passive token borrowed, so no second short lock can be taken under it.
pub struct WindowManager {
    pub windows: Windows,
    pub classes: class::Registry,
    /// The clipboard of the one window station, WinSta0 ([`crate::win32k::clipboard`]).
    pub clipboard: crate::win32k::clipboard::Clipboard,
    /// The accelerator tables ([`crate::win32k::accel`]).
    pub accels: crate::win32k::accel::Accelerators,
    /// The windows' properties ([`crate::win32k::prop`]).
    pub props: crate::win32k::prop::Props,
}

impl WindowManager {
    /// Write an empty window manager at `manager`, field by field (by value it would pass through
    /// the stack, which is smaller than it).
    ///
    /// # Safety
    ///
    /// `manager` is valid for writes, aligned, and the records' final address; its previous
    /// contents are overwritten, not dropped.
    pub unsafe fn write_empty(manager: *mut WindowManager) {
        use core::ptr::addr_of_mut;
        // SAFETY: the caller's contract, handed on to each registry's own.
        unsafe {
            Windows::write_empty(addr_of_mut!((*manager).windows));
            class::Registry::write_empty(addr_of_mut!((*manager).classes));
            crate::win32k::clipboard::Clipboard::write_empty(addr_of_mut!((*manager).clipboard));
            crate::win32k::accel::Accelerators::write_empty(addr_of_mut!((*manager).accels));
            crate::win32k::prop::Props::write_empty(addr_of_mut!((*manager).props));
        }
    }

    /// The boot's step for the desktop `desktop` (its packed object id): the primary monitor's
    /// work area, the system classes "#32769" and "Message", the window manager's own thread (no
    /// desktop handle, so it may create the root windows), the message window and the visible
    /// desktop window over the work area. Both are made before the desktop names either, so
    /// neither has a parent.
    pub fn boot_desktop(&mut self, desktop: u32, work_area: Rect) -> Result<(), Failure> {
        self.windows.set_monitor(PRIMARY_MONITOR, work_area);
        self.windows.set_desktop(desktop, None, None);
        let flags = class::RegisterFlags {
            win40_compat: true,
            server_side_proc: true,
            system_class: true,
            server_class: false,
            ansi_proc: false,
        };
        let wc = class::WndClassExW {
            cb_size: core::mem::size_of::<class::WndClassExW>() as u32,
            style: 0,
            wnd_proc: 0,
            cb_cls_extra: 0,
            cb_wnd_extra: 0,
            instance: class::WINDOW_MANAGER_MODULE,
            icon: 0,
            cursor: 0,
            background: 0,
            menu_name: 0,
            class_name: 0,
            icon_sm: 0,
        };
        // The desktop window's class answers CS_DBLCLKS (the guiclass capture's GetClassLong of
        // the desktop window); the message window's has no style.
        for (name, style) in [
            (class::Name::Atom(DESKTOP_CLASS_ATOM), CS_DBLCLKS),
            (class::Name::Text(&MESSAGE_CLASS), 0),
        ] {
            self.classes
                .register_class(
                    &self.windows.handles,
                    &class::WndClassExW { style, ..wc },
                    name,
                    class::MenuArg::None,
                    class::SYSTEM_OWNER,
                    flags,
                    desktop,
                )
                .map_err(|_| Failure::OutOfMemory)?;
        }
        let thread = self
            .windows
            .add_thread(
                class::SYSTEM_OWNER,
                desktop,
                DESKTOP_CREATEWINDOW,
                None,
                Some(PRIMARY_MONITOR),
            )
            .ok_or(Failure::OutOfMemory)?;
        let mut args = CreateArgs {
            ex_style: 0,
            class_name: class::Name::Text(&MESSAGE_CLASS),
            class_atom: 0,
            name: &[],
            style: WS_POPUP,
            x: 0,
            y: 0,
            cx: 0,
            cy: 0,
            parent: None,
            menu: MenuInput::None,
            instance: class::WINDOW_MANAGER_MODULE,
            params: 0,
            version: 0x0005_0000,
        };
        let message = WindowManager::create_window(
            &mut DefaultSession::new(&mut self.windows, &mut self.classes),
            thread,
            0,
            &mut args,
        )?;
        args.class_name = class::Name::Atom(DESKTOP_CLASS_ATOM);
        args.style = WS_POPUP | WS_CLIPCHILDREN;
        args.x = work_area.left;
        args.y = work_area.top;
        args.cx = work_area.right - work_area.left;
        args.cy = work_area.bottom - work_area.top;
        let window = WindowManager::create_window(
            &mut DefaultSession::new(&mut self.windows, &mut self.classes),
            thread,
            0,
            &mut args,
        )?;
        let id = |handle| self.windows.window_from_handle(handle);
        let (window, message) = (id(window), id(message));
        self.windows.set_desktop(desktop, window, message);
        // The desktop window is visible from the boot on (the one desktop is the one on the
        // screen): a top-level window's visibility goes up to it. The message window never is.
        if let Some(window) = window {
            self.windows.at_mut(window).style |= WS_VISIBLE;
        }
        // The stock cursors and icons, the system's, once: their handles come after the first
        // desktop's windows'.
        if !self.classes.cursors.make_stock(&mut self.windows.handles) {
            return Err(Failure::OutOfMemory);
        }
        Ok(())
    }

    /// NtUserCreateWindowEx's decision over the caller's decoded arguments: the parent handle
    /// resolved (none for 0, the desktop's message window for HWND_MESSAGE; a handle naming no
    /// window is ERROR_INVALID_WINDOW_HANDLE), the class name resolved to its atom through the
    /// class registry, then the creation. The new window's handle is the answer.
    pub fn create_window(
        s: &mut dyn Session,
        caller: ThreadId,
        parent: Hwnd,
        args: &mut CreateArgs,
    ) -> Result<Hwnd, Failure> {
        let (windows, classes) = s.parts();
        args.parent = match parent {
            0 => None,
            HWND_MESSAGE => Some(
                windows
                    .message_window(caller)
                    .ok_or(Failure::InvalidWindowHandle)?,
            ),
            handle => Some(
                windows
                    .window_from_handle(handle)
                    .ok_or(Failure::InvalidWindowHandle)?,
            ),
        };
        args.class_atom = classes.atom_of(args.class_name);
        let id = Windows::create_window_ex(s, caller, args)?;
        let windows = s.windows();
        Ok(windows.handle_of(id))
    }

    /// The display's mode is now `width` by `height`: the primary work area is the whole screen
    /// (no taskbar) and every desktop window covers it. WM_DISPLAYCHANGE is not sent yet.
    pub fn display_changed(&mut self, width: i32, height: i32) {
        let screen = Rect {
            left: 0,
            top: 0,
            right: width,
            bottom: height,
        };
        self.windows.set_monitor(PRIMARY_MONITOR, screen);
        self.windows.cover_screen(screen);
    }
}

#[cfg(test)]
mod tests {
    use rtl::testing::wide;
    use rtl::user::{WS_CHILD, WS_OVERLAPPED};

    use super::*;
    use crate::win32k::window::testkit::*;

    /// The boot's desktop: the primary monitor's work area, a thread of the window manager's own,
    /// the desktop window over the work area and the message window, both parentless and
    /// unlinked, of the two system classes; the desktop names them.
    #[test]
    fn the_boot_makes_the_desktops_windows() {
        let m = manager();
        m.boot_desktop(DESKTOP, SCREEN).unwrap();
        assert_eq!(m.windows.monitors[PRIMARY_MONITOR as usize].rect, SCREEN);
        let desktop = *m.windows.desktop_by_id(DESKTOP).unwrap();
        let (window, message) = (desktop.window.unwrap(), desktop.message_window.unwrap());
        assert_ne!(window, message);
        let w = m.windows.at(window);
        assert_eq!(w.window_rect, SCREEN);
        assert_eq!(w.process, class::SYSTEM_OWNER);
        assert_eq!(w.parent, None);
        assert_eq!(m.windows.at(message).parent, None);
        assert_eq!(w.child, None, "nothing is linked under the desktop yet");
        let thread = m.windows.thread(w.thread);
        assert_eq!(thread.desktop_handle, None);
        assert_eq!(thread.key, None);
        assert_eq!(thread.window_count, 2);

        let class_of = |id| {
            let view = m.windows.class_window(m.windows.handle_of(id)).unwrap();
            let mut out = [0u16; 16];
            let written = m.classes.class_name(view.class, &mut out);
            String::from_utf16(&out[..written]).unwrap()
        };
        assert_eq!(class_of(window), "#32769");
        assert_eq!(class_of(message), "Message");
        // The system classes are every process's.
        assert!(m
            .classes
            .class_ptr(DESKTOP_CLASS_ATOM, OWNER, MODULE)
            .is_some());
    }

    /// user32's classes and dialogs: a narrow caller's window takes the class's narrow procedure
    /// (no Unicode window), a wide caller's the wide one; class names match case-insensitively,
    /// "#32770" is atom 0x8002; FindWindow matches class and title (case-insensitive); the dialog
    /// mark is set once, by the owning process; a child's links name its parent and siblings.
    #[test]
    fn user32s_classes_and_dialogs() {
        use rtl::window::{FNID_DIALOG, WINDOW_ANSI_PROC, WINDOW_DIALOG};
        let m = manager();
        m.boot_desktop(DESKTOP, SCREEN).unwrap();
        let mut wc = wnd_class();
        wc.wnd_proc = 0x1000;
        let button = register(
            &mut m.classes,
            &m.windows.handles,
            class::Name::Text(&wide("Button")),
            &wc,
        );
        m.classes
            .set_narrow_procedure(button, OWNER, wc.instance, 0x2000);
        register(
            &mut m.classes,
            &m.windows.handles,
            class::Name::Atom(0x8002),
            &wc,
        );
        let t = m
            .windows
            .connect_thread(key(1, 0), OWNER, DESKTOP, DESKTOP_CREATEWINDOW, 0x10)
            .unwrap();
        let upper = wide("BUTTON");
        let mut a = args(0, WS_OVERLAPPED);
        a.class_name = class::Name::Text(&upper);
        a.ex_style = ANSI_CREATOR_BIT;
        let narrow = WindowManager::create_window(
            &mut DefaultSession::new(&mut m.windows, &mut m.classes),
            t,
            0,
            &mut a,
        )
        .unwrap();
        let id = m.windows.window_from_handle(narrow).unwrap();
        let data = m.windows.window_data(id, OWNER);
        assert_eq!(
            (data.proc, data.flags & WINDOW_ANSI_PROC),
            (0x2000, WINDOW_ANSI_PROC)
        );
        let mut a = args(0, WS_CHILD);
        a.class_name = class::Name::Text(&upper);
        let first = WindowManager::create_window(
            &mut DefaultSession::new(&mut m.windows, &mut m.classes),
            t,
            narrow,
            &mut a,
        )
        .unwrap();
        let mut a = args(0, WS_CHILD);
        a.class_name = class::Name::Text(&upper);
        let second = WindowManager::create_window(
            &mut DefaultSession::new(&mut m.windows, &mut m.classes),
            t,
            narrow,
            &mut a,
        )
        .unwrap();
        let first_id = m.windows.window_from_handle(first).unwrap();
        let data = m.windows.window_data(first_id, OWNER);
        assert_eq!((data.proc, data.flags & WINDOW_ANSI_PROC), (0x1000, 0));
        let links = m.windows.window_links(first_id);
        assert_eq!(
            (links.parent, links.next, links.previous),
            (narrow, second, 0)
        );
        let second_links = m
            .windows
            .window_links(m.windows.window_from_handle(second).unwrap());
        assert_eq!(second_links.previous, first);

        let dialog_name = wide("#32770");
        let title = wide("Box");
        let mut a = args(0, WS_POPUP);
        a.class_name = class::Name::Text(&dialog_name);
        a.name = &title;
        let boxed = WindowManager::create_window(
            &mut DefaultSession::new(&mut m.windows, &mut m.classes),
            t,
            0,
            &mut a,
        )
        .unwrap();
        m.windows.set_window_text(boxed, &title).unwrap();
        let lower = wide("box");
        let found = m.find_window(
            t,
            None,
            None,
            Some(class::Name::Text(&dialog_name)),
            Some(&lower),
        );
        assert_eq!(found, Ok(Some(boxed)));
        let other = wide("Other");
        let found = m.find_window(t, None, None, Some(class::Name::Atom(0x8002)), Some(&other));
        assert_eq!(found, Ok(None));
        let missing = wide("Missing");
        let found = m.find_window(t, None, None, Some(class::Name::Text(&missing)), None);
        assert_eq!(found, Ok(None));

        let id = m.windows.window_from_handle(boxed).unwrap();
        assert_eq!(
            m.windows.set_window_fnid(id, FNID_DIALOG, OTHER_OWNER),
            Err(Failure::AccessDenied)
        );
        assert_eq!(m.windows.set_window_fnid(id, FNID_DIALOG, OWNER), Ok(()));
        assert_eq!(
            m.windows.set_window_fnid(id, FNID_DIALOG, OWNER),
            Err(Failure::InvalidParameter)
        );
        let flags = m.windows.window_data(id, OWNER).flags;
        assert_eq!(flags & WINDOW_DIALOG, WINDOW_DIALOG);
    }

    /// The service's creation: the string class name resolved through the class registry, the
    /// parent handle resolved (HWND_MESSAGE to the desktop's message window), an unknown parent
    /// handle refused with ERROR_INVALID_WINDOW_HANDLE, a top-level window linked under the
    /// desktop window.
    #[test]
    fn the_service_resolves_the_class_name_and_the_parent() {
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
        let title = wide("Hello");
        let mut a = args(0, WS_OVERLAPPED);
        a.class_name = class::Name::Text(&name);
        a.name = &title;
        let handle = WindowManager::create_window(
            &mut DefaultSession::new(&mut m.windows, &mut m.classes),
            t,
            0,
            &mut a,
        )
        .unwrap();
        let id = m.windows.window_from_handle(handle).unwrap();
        let desktop = *m.windows.desktop_by_id(DESKTOP).unwrap();
        assert_eq!(m.windows.at(id).parent, desktop.window);
        assert_eq!(m.windows.at(desktop.window.unwrap()).child, Some(id));
        assert_eq!(m.windows.at(id).thread, t);

        let mut a = args(0, WS_CHILD);
        a.class_name = class::Name::Text(&name);
        let child = WindowManager::create_window(
            &mut DefaultSession::new(&mut m.windows, &mut m.classes),
            t,
            handle,
            &mut a,
        )
        .unwrap();
        let child = m.windows.window_from_handle(child).unwrap();
        assert_eq!(m.windows.at(child).parent, Some(id));

        let mut a = args(0, WS_CHILD);
        a.class_name = class::Name::Text(&name);
        let only = WindowManager::create_window(
            &mut DefaultSession::new(&mut m.windows, &mut m.classes),
            t,
            HWND_MESSAGE,
            &mut a,
        )
        .unwrap();
        let only = m.windows.window_from_handle(only).unwrap();
        assert_eq!(m.windows.at(only).parent, desktop.message_window);

        let mut a = args(0, WS_CHILD);
        a.class_name = class::Name::Text(&name);
        assert_eq!(
            WindowManager::create_window(
                &mut DefaultSession::new(&mut m.windows, &mut m.classes),
                t,
                0x1234,
                &mut a
            ),
            Err(Failure::InvalidWindowHandle)
        );
        let missing = wide("Missing");
        let mut a = args(0, WS_OVERLAPPED);
        a.class_name = class::Name::Text(&missing);
        assert_eq!(
            WindowManager::create_window(
                &mut DefaultSession::new(&mut m.windows, &mut m.classes),
                t,
                0,
                &mut a
            ),
            Err(Failure::CannotFindWindowClass)
        );

        // The process's thread cannot destroy the desktop's windows.
        let root = m.windows.handle_of(desktop.window.unwrap());
        assert_eq!(
            Windows::destroy_window_handle(
                &mut DefaultSession::new(&mut m.windows, &mut m.classes),
                t,
                root
            ),
            Err(Failure::AccessDenied)
        );
    }

    /// A display mode change: the primary monitor's work area becomes the new screen, and the
    /// desktop window covers it.
    #[test]
    fn the_work_area_follows_the_display_mode() {
        let m = manager();
        m.boot_desktop(DESKTOP, SCREEN).unwrap();
        assert_eq!(m.windows.work_area(PRIMARY_MONITOR), SCREEN);
        m.display_changed(1024, 768);
        let screen = Rect {
            left: 0,
            top: 0,
            right: 1024,
            bottom: 768,
        };
        assert_eq!(m.windows.work_area(PRIMARY_MONITOR), screen);
        let desktop = m.windows.desktop_by_id(DESKTOP).unwrap().window.unwrap();
        assert_eq!(m.windows.at(desktop).window_rect, screen);
        assert_eq!(m.windows.at(desktop).client_rect, screen);
    }
}
