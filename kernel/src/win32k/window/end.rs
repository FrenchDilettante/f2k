//! The ends of threads, processes and the session: the windows they take, and the windows the
//! session's end asks.

use super::*;
use crate::sched::thread::ThreadId;
use crate::win32k::class;

impl Windows {
    /// The thread `thread` ended, as Windows 2000's thread cleanup has it: no hook vetoes its
    /// destroys, each of its windows goes (top of each tree first), and its queue ends
    /// ([`crate::win32k::queue::detach`]: unanswered sends fail). The record stays, empty, until
    /// its process's end or another thread takes it over ([`Windows::connect_thread`]).
    pub fn end_thread(s: &mut dyn Session, thread: ThreadId) {
        let windows = s.windows();
        let Some(t) = windows
            .threads
            .get_mut(thread.0 as usize)
            .filter(|t| t.live)
        else {
            return;
        };
        t.in_cleanup = true;
        while let Some(window) = s.windows().doomed_window(|w| w.thread == thread) {
            let windows = s.windows();
            if windows
                .at(window)
                .parent
                .is_some_and(|p| !windows.pool.is_live(p))
            {
                windows.at_mut(window).parent = None;
            }
            if Windows::destroy_window(s, thread, window) != Ok(true) {
                // Not reachable (the window's own thread, in cleanup, destroys it); never loop.
                break;
            }
        }
        let windows = s.windows();
        crate::win32k::queue::detach(windows, thread);
        if windows.foreground_thread == Some(thread) {
            windows.foreground_thread = None;
        }
    }

    /// The process `owner`'s end: no hook vetoes its destroys, each of its windows is destroyed
    /// as its own thread's (top of each tree first), and its threads' records go, their queues
    /// ended. A zombie is left to its other reference; a child left without its parent (its
    /// destroy event found no queue) is destroyed as a top-level one.
    pub fn end_process(s: &mut dyn Session, owner: class::Owner) {
        let windows = s.windows();
        for t in windows.threads.iter_mut() {
            if t.live && t.process == owner {
                t.in_cleanup = true;
            }
        }
        while let Some(window) = s.windows().process_window(owner) {
            let windows = s.windows();
            if windows
                .at(window)
                .parent
                .is_some_and(|p| !windows.pool.is_live(p))
            {
                windows.at_mut(window).parent = None;
            }
            let thread = windows.at(window).thread;
            if Windows::destroy_window(s, thread, window) != Ok(true) {
                // Not reachable (the window's own thread, in cleanup, destroys it); never loop.
                break;
            }
        }
        let windows = s.windows();
        for index in 0..windows.threads.len() {
            let t = &windows.threads[index];
            if t.live && t.process == owner {
                let thread = ThreadId(index as u16);
                crate::win32k::queue::detach(windows, thread);
                windows.threads[index] = Thread::EMPTY;
                if windows.foreground_thread == Some(thread) {
                    windows.foreground_thread = None;
                }
            }
        }
    }

    /// A live window of the process `owner` that is not a zombie: the top of its tree among the
    /// process's windows.
    fn process_window(&self, owner: class::Owner) -> Option<WindowId> {
        self.doomed_window(|w| w.process == owner)
    }

    /// A live window `picks` that is not a zombie: the top of its tree among the windows it picks.
    fn doomed_window(&self, picks: impl Fn(&Window) -> bool) -> Option<WindowId> {
        let doomed = |id: WindowId| {
            let w = self.at(id);
            picks(w)
                && !self
                    .handles
                    .window(w.handle)
                    .is_some_and(|e| e.marked_destroy)
        };
        let mut window = self.live_windows().find(|&id| doomed(id))?;
        while let Some(parent) = self.at(window).parent {
            if !self.pool.is_live(parent) || !doomed(parent) {
                break;
            }
            window = parent;
        }
        Some(window)
    }

    /// The live windows, in pool order.
    fn live_windows(&self) -> impl Iterator<Item = WindowId> + '_ {
        self.pool.iter().map(|(id, _)| id)
    }

    /// How many live windows belong to processes (the window manager's own aside): with no
    /// process left, each is one a process's end missed.
    pub fn process_windows(&self) -> usize {
        self.live_windows()
            .filter(|&id| self.at(id).process != class::SYSTEM_OWNER)
            .count()
    }

    /// The windows of the process `owner` the session's end messages (`crate::session`): its
    /// top-level windows (hidden included, message-only not) with a client-side procedure and not
    /// being destroyed, each desktop's in z-order, the top first.
    fn session_windows(&self, owner: class::Owner) -> impl Iterator<Item = WindowId> + '_ {
        self.desktops
            .iter()
            .filter_map(|desktop| desktop.window)
            .filter(|&root| self.pool.is_live(root))
            .flat_map(move |root| {
                core::iter::successors(self.at(root).child, move |&window| self.at(window).next)
            })
            .filter(move |&window| {
                let w = self.at(window);
                w.process == owner
                    && !w.flags.destroyed
                    && !w.flags.in_destroy
                    && self.client_proc(window).is_some()
            })
    }

    /// Whether the process `owner` has a window the session's end would ask.
    pub fn has_session_windows(&self, owner: class::Owner) -> bool {
        self.session_windows(owner).next().is_some()
    }

    /// The next window of the process `owner` the session's end asks WM_QUERYENDSESSION, marked
    /// asked: the first of its top-level windows (in z-order) not asked yet. None once every one
    /// has been asked; a window made meanwhile is asked in its turn.
    pub fn session_next_to_ask(&mut self, owner: class::Owner) -> Option<Hwnd> {
        let window = self
            .session_windows(owner)
            .find(|&window| !self.at(window).flags.session_asked)?;
        let w = self.at_mut(window);
        w.flags.session_asked = true;
        Some(w.handle)
    }

    /// The next window of the process `owner` the session's end sends WM_ENDSESSION, its mark
    /// cleared: the first of its top-level windows (in z-order) asked WM_QUERYENDSESSION. None once
    /// every window asked has been told; a window that stopped being a top-level one, or went,
    /// meanwhile is not.
    pub fn session_next_asked(&mut self, owner: class::Owner) -> Option<Hwnd> {
        let window = self
            .session_windows(owner)
            .find(|&window| self.at(window).flags.session_asked)?;
        let w = self.at_mut(window);
        w.flags.session_asked = false;
        Some(w.handle)
    }

    /// Clear the marks a session's end left on the windows of the process `owner`: before it asks
    /// the process, so a window an earlier end asked, then left (when the process did not answer),
    /// is asked again.
    pub fn session_forget(&mut self, owner: class::Owner) {
        for (_, w) in self.pool.iter_mut() {
            if w.process == owner {
                w.flags.session_asked = false;
            }
        }
    }
}

impl WindowManager {
    /// The process `owner`'s end, at its teardown: the clipboard closed if its thread had it open,
    /// the windows its threads' ends left ([`Windows::end_process`]), its threads' records and
    /// queues, then its classes (Windows 2000 destroys classes at the process's end).
    pub fn end_process(&mut self, owner: class::Owner) {
        let WindowManager {
            windows,
            classes,
            clipboard,
            accels,
            ..
        } = self;
        clipboard.process_gone(windows, owner);
        Windows::end_process(&mut DefaultSession::new(windows, classes), owner);
        classes.destroy_owner_classes(&mut windows.handles, owner);
        // The process's own user objects, as Windows 2000 destroys them at its end: its menus
        // (those its windows held went with them), its accelerator tables, its cursors and icons
        // (once its classes, which held them, are gone).
        windows.menus.destroy_owner(&mut windows.handles, owner);
        accels.destroy_owner(&mut windows.handles, owner);
        classes.cursors.destroy_owner(&mut windows.handles, owner);
        // Its count given back with each handle closed; what a zombie window keeps open is charged
        // to no process from now on, and the record starts afresh.
        windows.handles.end_process(owner);
    }

    /// The thread `key`'s end: its windows go and its queue ends ([`Windows::end_thread`]), as
    /// Windows 2000 does at thread exit; nothing for a thread that never connected.
    pub fn end_thread(&mut self, key: ThreadKey) {
        let WindowManager {
            windows, classes, ..
        } = self;
        let Some(index) = windows
            .threads
            .iter()
            .position(|t| t.live && t.key == Some(key))
        else {
            return;
        };
        Windows::end_thread(
            &mut DefaultSession::new(windows, classes),
            ThreadId(index as u16),
        );
    }

    /// What the processes' ends left behind: the processes' live windows and their classes, menus,
    /// accelerator tables, cursors and icons. With no process left, the teardown audit counts each
    /// as a leak.
    pub fn process_records(&self) -> usize {
        self.windows.process_windows()
            + self.classes.process_classes()
            + self.windows.menus.live()
            + self.accels.live()
            + self.classes.cursors.process_records()
    }
}

#[cfg(test)]
mod tests {
    use rtl::testing::wide;
    use rtl::user::{WS_CHILD, WS_OVERLAPPED, WS_POPUP};

    use super::*;
    use crate::win32k::window::testkit::*;

    /// A process's end: its windows go — the trees, the owned windows, a second thread's — then
    /// its classes and its threads' records; another process's windows and classes stay, a child
    /// of the ended process's window left without its parent among them. Nothing of the process is
    /// left for the audit to count.
    #[test]
    fn a_process_end_takes_its_windows_and_classes() {
        let m = manager();
        m.boot_desktop(DESKTOP, SCREEN).unwrap();
        register(
            &mut m.classes,
            &m.windows.handles,
            class::Name::Text(&wide("App")),
            &wnd_class(),
        );
        register_on(
            &mut m.classes,
            &m.windows.handles,
            class::Name::Text(&wide("Other")),
            &wnd_class(),
            DESKTOP,
            OTHER_OWNER,
            class::MenuArg::None,
        );
        let t = m
            .windows
            .connect_thread(key(1, 0), OWNER, DESKTOP, DESKTOP_CREATEWINDOW, 0x10)
            .unwrap();
        let t2 = m
            .windows
            .connect_thread(key(2, 0), OWNER, DESKTOP, DESKTOP_CREATEWINDOW, 0x10)
            .unwrap();
        let other = m
            .windows
            .connect_thread(key(3, 0), OTHER_OWNER, DESKTOP, DESKTOP_CREATEWINDOW, 0x20)
            .unwrap();
        let app = wide("App");
        let create = |m: &mut WindowManager, thread, parent, name: &[u16], style| {
            let mut a = args(0, style);
            a.class_name = class::Name::Text(name);
            WindowManager::create_window(
                &mut DefaultSession::new(&mut m.windows, &mut m.classes),
                thread,
                parent,
                &mut a,
            )
            .unwrap()
        };
        let top = create(m, t, 0, &app, WS_OVERLAPPED);
        let child = create(m, t, top, &app, WS_CHILD);
        let _grandchild = create(m, t, child, &app, WS_CHILD);
        let _owned = create(m, t, top, &app, WS_POPUP);
        let _second = create(m, t2, 0, &app, WS_POPUP);
        let other_name = wide("Other");
        let survivor = create(m, other, 0, &other_name, WS_OVERLAPPED);
        let foster = create(m, other, top, &other_name, WS_CHILD);
        assert_eq!(m.process_records(), 7 + 2);

        m.end_process(OWNER);
        assert_eq!(
            m.windows.process_windows(),
            2,
            "the other process's windows stay"
        );
        assert!(m.windows.window_from_handle(top).is_none());
        assert!(m.windows.window_from_handle(survivor).is_some());
        let foster = m.windows.window_from_handle(foster).unwrap();
        assert!(
            m.windows.at(foster).flags.destroyed,
            "its destroy event is posted"
        );
        assert_eq!(m.classes.process_classes(), 1, "the other process's class");
        assert!(!m.windows.thread(t).live);
        assert!(!m.windows.thread(t2).live);
        assert!(m.windows.thread(other).live);

        // The other process's end takes the rest, the orphaned child included.
        m.end_process(OTHER_OWNER);
        assert_eq!(m.process_records(), 0);
        let desktop = *m.windows.desktop_by_id(DESKTOP).unwrap();
        assert_eq!(m.windows.at(desktop.window.unwrap()).child, None);
        assert_eq!(live(&m.windows), 2, "the desktop's own windows");
    }
}
