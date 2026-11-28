//! What the message layer (the queue, the timers, the painting) reads and sets of a window, and
//! its visibility and WINDOWINFO.

use rtl::gdi::Rect;
use rtl::scroll::ScrollBars;
use rtl::user::{WS_DISABLED, WS_VISIBLE};

use super::*;
use crate::sched::thread::ThreadId;
use crate::win32k::class;

impl Windows {
    /// Whether `id` names a live window.
    pub fn is_live(&self, id: WindowId) -> bool {
        self.pool.is_live(id)
    }

    /// The thread whose queue the window's messages go to.
    pub fn window_thread(&self, id: WindowId) -> ThreadId {
        self.at(id).thread
    }

    /// The process the window belongs to, as the class registry keys it.
    pub fn window_process(&self, id: WindowId) -> class::Owner {
        self.at(id).process
    }

    /// The client-side procedure the window's messages go to; none for a window whose procedure
    /// is the window manager's own (the desktop's windows, a zombie).
    pub fn client_proc(&self, id: WindowId) -> Option<u32> {
        let w = self.at(id);
        match w.proc {
            Proc::Client(proc) if proc != 0 && !w.flags.server_side_proc => Some(proc),
            _ => None,
        }
    }

    /// The window's own scroll bars, once a call made them ([`crate::win32k::scroll`]).
    pub fn own_scroll_bars(&self, id: WindowId) -> Option<ScrollBars> {
        self.at(id).scroll
    }

    /// The same, to make or change.
    pub fn own_scroll_bars_mut(&mut self, id: WindowId) -> &mut Option<ScrollBars> {
        &mut self.at_mut(id).scroll
    }

    /// The window's public style.
    pub fn window_style(&self, id: WindowId) -> u32 {
        self.at(id).style
    }

    /// Set or clear the window's WS_DISABLED: EnableWindow's change of state
    /// ([`crate::win32k::focus`]).
    pub fn set_disabled(&mut self, id: WindowId, disabled: bool) {
        let w = self.at_mut(id);
        if disabled {
            w.style |= WS_DISABLED;
        } else {
            w.style &= !WS_DISABLED;
        }
    }

    /// Set or clear the window's scroll bar style bits `bits` (WS_HSCROLL, WS_VSCROLL): a bar shown
    /// or hidden by the scroll bar calls ([`crate::win32k::scroll`]), with no message (the caller
    /// takes the frame again).
    pub fn set_scroll_styles(&mut self, id: WindowId, bits: u32, on: bool) {
        let w = self.at_mut(id);
        if on {
            w.style |= bits;
        } else {
            w.style &= !bits;
        }
    }

    /// The default window procedure's WM_SETREDRAW: WS_VISIBLE set (`redraw`) or cleared, nothing
    /// else, as Windows 2000's does it (guimsg `redraw`): no WM_SHOWWINDOW, no position change,
    /// nothing painted or uncovered; setting it again invalidates nothing.
    pub fn set_redraw(&mut self, id: WindowId, redraw: bool) {
        let w = self.at_mut(id);
        if redraw {
            w.style |= WS_VISIBLE;
        } else {
            w.style &= !WS_VISIBLE;
        }
    }

    /// Whether the window is a child window (one with no menu of its own).
    pub fn window_is_child(&self, id: WindowId) -> bool {
        self.at(id).is_child()
    }

    /// The window's menu, as GetMenu answers it: a top-level window's menu handle, a child's id,
    /// 0 for none.
    pub fn window_menu(&self, id: WindowId) -> u32 {
        self.at(id).menu.raw()
    }

    /// The window `id`'s copy of the system menu, as GetSystemMenu last attached it.
    pub fn window_system_menu(&self, id: WindowId) -> Option<crate::win32k::menu::MenuId> {
        self.at(id).system_menu
    }

    /// Attach `menu` to the window `id` as its copy of the system menu (none: no copy).
    pub fn set_window_system_menu(
        &mut self,
        id: WindowId,
        menu: Option<crate::win32k::menu::MenuId>,
    ) {
        self.at_mut(id).system_menu = menu;
    }

    /// Set a top-level window's menu handle (0: none).
    pub fn set_window_menu(&mut self, id: WindowId, menu: u32) {
        self.give_menu(
            id,
            if menu == 0 {
                Menu::None
            } else {
                Menu::Handle(menu)
            },
        );
    }

    /// Store `menu` as the window `id`'s, a menu its handle names marked as held by a window
    /// ([`crate::win32k::menu::Menus::mark_held`]: its destruction looks for the windows holding
    /// it).
    pub(super) fn give_menu(&mut self, id: WindowId, menu: Menu) {
        if let Menu::Handle(handle) = menu {
            self.menus.mark_held(&self.handles, handle);
        }
        self.at_mut(id).menu = menu;
    }

    /// Leave every top-level window holding the menu `menu` without one: the menu was destroyed.
    pub fn forget_menu(&mut self, menu: u32) {
        for (_, w) in self.pool.iter_mut() {
            if !w.is_child() && w.menu == Menu::Handle(menu) {
                w.menu = Menu::None;
            }
        }
    }

    /// The client rectangle the default window procedure gives `id` at the window rectangle
    /// `rect`: the frame its styles and menu give taken off ([`rtl::nonclient::Frame`]). The frame
    /// is taken off at the origin, then moved back saturated: a rectangle at i32's ends cannot
    /// overflow the frame's sums.
    pub fn default_client(&self, id: WindowId, rect: Rect) -> Rect {
        let w = self.at(id);
        let menu = matches!(w.menu, Menu::Handle(_));
        let frame = rtl::nonclient::Frame::of(w.style, w.ex_style, menu);
        let client = frame.client(Rect::new(0, 0, rect.width(), rect.height()));
        client.saturating_offset(rect.left, rect.top)
    }

    /// Whether the window `id` has a frame to paint: its window rectangle is not all client area.
    pub fn has_frame(&self, id: WindowId) -> bool {
        let w = self.at(id);
        w.window_rect != w.client_rect
    }

    /// The window's client rectangle, in screen coordinates.
    pub fn client_rect(&self, id: WindowId) -> Rect {
        self.at(id).client_rect
    }

    /// The window's rectangle, its non-client area included, in screen coordinates.
    pub fn window_rect(&self, id: WindowId) -> Rect {
        self.at(id).window_rect
    }

    /// The window's public extended style.
    pub fn window_ex_style(&self, id: WindowId) -> u32 {
        self.at(id).ex_style
    }

    /// The window's parent, its first child and its next sibling: the links a walk of a window's
    /// subtree follows.
    pub fn parent_of(&self, id: WindowId) -> Option<WindowId> {
        self.at(id).parent
    }

    pub fn first_child(&self, id: WindowId) -> Option<WindowId> {
        self.at(id).child
    }

    pub fn next_sibling(&self, id: WindowId) -> Option<WindowId> {
        self.at(id).next
    }

    /// The desktop window and the message window of the window's desktop: where a window's chain
    /// of parents ends.
    pub fn desktop_roots(&self, id: WindowId) -> (Option<WindowId>, Option<WindowId>) {
        self.desktop_by_id(self.at(id).desktop)
            .map_or((None, None), |d| (d.window, d.message_window))
    }

    /// The desktop window of the thread `thread`'s desktop, the parent of its top-level windows.
    pub fn thread_desktop_window(&self, thread: ThreadId) -> Option<WindowId> {
        self.desktop_by_id(self.thread(thread).desktop)
            .and_then(|d| d.window)
    }

    /// The thread record `thread` serves, when it is a process's.
    pub fn thread_key(&self, thread: ThreadId) -> Option<ThreadKey> {
        let t = self.thread(thread);
        if t.live {
            t.key
        } else {
            None
        }
    }

    /// The process of the thread record `thread`.
    pub fn thread_process(&self, thread: ThreadId) -> class::Owner {
        self.thread(thread).process
    }

    /// Set or clear the window's WS_VISIBLE: the message layer's tests' stand-in for showing and
    /// hiding a window.
    #[cfg(test)]
    pub fn set_visible_for_tests(&mut self, id: WindowId, visible: bool) {
        let w = self.at_mut(id);
        if visible {
            w.style |= WS_VISIBLE;
        } else {
            w.style &= !WS_VISIBLE;
        }
    }

    /// Give the window a frame `inset` pixels wide on every side: its client area its window
    /// rectangle less the inset (the paint layer's tests' stand-in for WM_NCCALCSIZE's answer).
    #[cfg(test)]
    pub fn set_frame_for_tests(&mut self, id: WindowId, inset: i32) {
        let w = self.at_mut(id);
        let r = w.window_rect;
        w.client_rect = Rect::new(
            r.left + inset,
            r.top + inset,
            r.right - inset,
            r.bottom - inset,
        );
    }

    /// Whether `window` and every window above it have WS_VISIBLE: IsWindowVisible's answer. The
    /// desktop window is visible and the message window is not, so no message-only window is.
    pub fn is_window_visible(&self, window: WindowId) -> bool {
        let mut current = Some(window);
        while let Some(w) = current {
            if !self.pool.is_live(w) {
                break;
            }
            if !self.at(w).is_visible() {
                return false;
            }
            current = self.at(w).parent;
        }
        true
    }

    /// `window`'s WINDOWINFO: rectangles in screen coordinates, styles, active or not, borders (the
    /// client's inset from the left and bottom edges), class atom and the creator's expected
    /// version (4.0 or 3.1: the records keep no finer one).
    pub fn window_info(&self, classes: &class::Registry, window: WindowId) -> WindowInfo {
        let w = self.at(window);
        let active = self.thread(w.thread).active == Some(window);
        WindowInfo {
            size: core::mem::size_of::<WindowInfo>() as u32,
            window: w.window_rect,
            client: w.client_rect,
            style: w.style,
            ex_style: w.ex_style,
            status: if active {
                rtl::window::WS_ACTIVECAPTION
            } else {
                0
            },
            cx_window_borders: (w.client_rect.left - w.window_rect.left).max(0) as u32,
            cy_window_borders: (w.window_rect.bottom - w.client_rect.bottom).max(0) as u32,
            atom_window_type: w.class.map_or(0, |c| classes.class_atom(c)),
            creator_version: if w.flags.win40_compat { 0x0400 } else { 0x030A },
        }
    }
}

#[cfg(test)]
mod tests {
    use rtl::testing::wide;
    use rtl::user::{WS_CHILD, WS_OVERLAPPED, WS_POPUP};
    use rtl::window::{QUERY_WINDOW_VISIBLE, SW_HIDE};

    use super::*;
    use crate::win32k::window::testkit::*;

    /// DestroyMenu leaves a top-level window holding the menu without one; a menu no window was
    /// given is destroyed without touching the windows' menus.
    #[test]
    fn a_destroyed_menu_leaves_the_window_holding_it() {
        let (w, _, t, _, _, _) = setup();
        let a = raw_window(w, t, WS_OVERLAPPED, None);
        let handle = w.handle_of(a);
        let held = w.menus.create(&mut w.handles, OWNER).unwrap();
        let loose = w.menus.create(&mut w.handles, OWNER).unwrap();
        w.set_menu_handle(handle, held).unwrap();
        w.destroy_menu_handle(loose).unwrap();
        assert_eq!(w.window_menu(a), held);
        w.destroy_menu_handle(held).unwrap();
        assert_eq!(w.window_menu(a), 0);
    }

    /// IsWindowVisible: the window and every window above it; the desktop window is visible, the
    /// message window is not, so a message-only window never is.
    #[test]
    fn visibility_runs_up_to_the_desktop() {
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
        let make = |m: &mut WindowManager, parent, style| {
            let mut a = args(0, style);
            a.class_name = class::Name::Text(&name);
            WindowManager::create_window(
                &mut DefaultSession::new(&mut m.windows, &mut m.classes),
                t,
                parent,
                &mut a,
            )
            .unwrap()
        };
        let top = make(m, 0, WS_OVERLAPPED | WS_VISIBLE);
        let child = make(m, top, WS_CHILD | WS_VISIBLE);
        let only = make(m, HWND_MESSAGE, WS_CHILD | WS_VISIBLE);
        let visible =
            |m: &WindowManager, h| m.query_window(h, QUERY_WINDOW_VISIBLE, 4, OWNER).unwrap();
        assert_eq!(visible(m, top), Query::Visible(1));
        assert_eq!(visible(m, child), Query::Visible(1));
        assert_eq!(visible(m, only), Query::Visible(0), "a message-only window");
        WindowManager::show_window(
            &mut DefaultSession::new(&mut m.windows, &mut m.classes),
            top,
            SW_HIDE,
        )
        .unwrap();
        assert_eq!(visible(m, child), Query::Visible(0), "its parent is hidden");
        let desktop = m.windows.desktop_by_id(DESKTOP).unwrap().window.unwrap();
        assert!(m.windows.is_window_visible(desktop));
    }

    /// WINDOWINFO: the rectangles, the styles, the active window's status, the borders, the class
    /// atom and the creator's version.
    #[test]
    fn the_window_info() {
        let (w, c, t, atom, _, _) = setup();
        let mut pump = Rec::new(t);
        pump.nccalc_inset = 3;
        let id = create(w, c, t, atom, WS_POPUP, &mut pump).unwrap();
        w.thread_mut(t).active = Some(id);
        let info = w.window_info(c, id);
        assert_eq!(
            info.window,
            Rect {
                left: 10,
                top: 20,
                right: 110,
                bottom: 100
            }
        );
        assert_eq!(
            info.client,
            Rect {
                left: 13,
                top: 23,
                right: 107,
                bottom: 97
            }
        );
        assert_eq!(info.style, w.at(id).style);
        assert_eq!(info.ex_style, w.at(id).ex_style);
        assert_eq!(info.status, rtl::window::WS_ACTIVECAPTION);
        assert_eq!((info.cx_window_borders, info.cy_window_borders), (3, 3));
        assert_eq!(info.atom_window_type, atom);
        assert_eq!(info.creator_version, 0x0400);
        w.thread_mut(t).active = None;
        assert_eq!(w.window_info(c, id).status, 0);
    }
}
