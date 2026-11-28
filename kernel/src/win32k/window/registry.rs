//! The window registry ([`Windows`]) and the calling context it keeps: threads, desktops and
//! monitors; its wiring, lookups and the class registry's view of the windows.

use rtl::gdi::Rect;

use super::*;
use crate::sched::thread::ThreadId;
use crate::win32k::class;
use crate::win32k::handle::UserHandles;
use crate::win32k::text::Texts;

/// The thread records to a chunk of their table: a page's worth.
const THREADS_PER_CHUNK: usize = crate::slots::entries_per_page::<Thread>();

/// How many desktops the registry tracks.
pub const DESKTOPS: usize = 8;

/// How many monitors the registry tracks.
pub const MONITORS: usize = 4;

/// The primary monitor's index.
pub const PRIMARY_MONITOR: u16 = 0;

/// A thread's create/destroy context: its process, desktop and desktop access, its window count
/// and queue state, its startup info and hotkey.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Thread {
    pub live: bool,
    /// The thread the record serves, when it is a process's (none for the desktop's own).
    pub key: Option<ThreadKey>,
    pub process: class::Owner,
    /// The packed desktop object id.
    pub desktop: u32,
    /// The thread's desktop handle, when it has one (none while the root desktop window is
    /// being created).
    pub desktop_handle: Option<Hwnd>,
    /// The desktop access mask.
    pub desktop_access: u32,
    /// The thread's monitor, when the shell set one.
    pub monitor: Option<u16>,
    /// How many windows the thread created and has not destroyed.
    pub window_count: i32,
    pub active: Option<WindowId>,
    pub active_prev: Option<WindowId>,
    pub focus: Option<WindowId>,
    /// The focus the thread had when another thread's activation last deactivated it: given
    /// back when its window vetoes the deactivation
    /// ([`crate::win32k::focus::deactivation_vetoed`]).
    pub deactivated_focus: Option<WindowId>,
    pub capture: Option<WindowId>,
    /// The thread's caret ([`crate::win32k::caret`]).
    pub caret: crate::win32k::caret::Caret,
    /// The thread's key state, as of the last key message it read ([`crate::win32k::input`]).
    pub keys: crate::win32k::input::KeyState,
    pub startup: StartupInfo,
    /// The process's pending hotkey.
    pub hotkey: u32,
    /// Thread teardown in progress.
    pub in_cleanup: bool,
    /// Hooks disabled (the destroy re-entry's duration).
    pub hooks_disabled: bool,
}

// SAFETY: writes a whole record.
unsafe impl crate::slots::Record for Thread {
    unsafe fn write_fresh(at: *mut Self, _: u32) {
        // SAFETY: the caller's contract.
        unsafe { at.write(Thread::EMPTY) };
    }
}

impl Thread {
    pub(super) const EMPTY: Self = Thread {
        live: false,
        key: None,
        process: 0,
        desktop: 0,
        desktop_handle: None,
        desktop_access: 0,
        monitor: None,
        window_count: 0,
        active: None,
        active_prev: None,
        focus: None,
        deactivated_focus: None,
        capture: None,
        caret: crate::win32k::caret::Caret::EMPTY,
        keys: crate::win32k::input::KeyState::EMPTY,
        startup: StartupInfo {
            flags: 0,
            x: 0,
            y: 0,
            cx: 0,
            cy: 0,
        },
        hotkey: 0,
        in_cleanup: false,
        hooks_disabled: false,
    };
}

/// A thread as the window manager tells threads apart: its thread object's pool index and the
/// record's generation, so a thread that reuses an ended one's slot is told from it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ThreadKey {
    pub index: u16,
    pub generation: u16,
}

/// A desktop: its window and message window (wired by the window-station side), its shared
/// dialog system menu, and the queue/winsta backpointers the free clears.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Desktop {
    /// The packed desktop object id.
    pub id: u32,
    /// The desktop window.
    pub window: Option<WindowId>,
    /// The message window.
    pub message_window: Option<WindowId>,
    /// The desktop's shared dialog system menu handle.
    pub dialog_menu: Hwnd,
    pub foreground: Option<WindowId>,
    pub tray: Option<WindowId>,
}

impl Desktop {
    const EMPTY: Self = Desktop {
        id: 0,
        window: None,
        message_window: None,
        dialog_menu: 0,
        foreground: None,
        tray: None,
    };
}

/// A monitor: its rectangle (the work area, in the minimal subset) and the cascade counter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Monitor {
    pub rect: Rect,
    /// How many cascaded windows the monitor has stacked.
    pub window_stack: i32,
}

impl Monitor {
    const EMPTY: Self = Monitor {
        rect: Rect {
            left: 0,
            top: 0,
            right: 0,
            bottom: 0,
        },
        window_stack: 0,
    };
}

/// The window registry: the pool, the handle table, and the calling-context records.
pub struct Windows {
    pub(super) pool: WindowPool,
    /// The user handle table: windows', menus', accelerator tables' and cursors' and icons'
    /// handles, one table as Windows 2000's ([`crate::win32k::handle`]). It sits in the window
    /// registry, the kind looked up most, behind the window manager's lock as every kind's records
    /// are.
    pub handles: UserHandles,
    /// The threads' create/destroy contexts (Windows 2000's THREADINFO), each with its queue at
    /// its index in [`Windows::queues`]: made as a thread first needs one, and kept at their peak;
    /// a free one (not `live`) is taken first, lowest first.
    pub(super) threads: crate::slots::Records<Thread, THREADS_PER_CHUNK>,
    pub(super) desktops: [Desktop; DESKTOPS],
    pub(super) monitors: [Monitor; MONITORS],
    /// The clipboard owner, if a window has it.
    pub clipboard_owner: Option<WindowId>,
    /// The foreground thread's queue.
    pub foreground_thread: Option<ThreadId>,
    /// The system's input state: the asynchronous key state and the keyboard's decode
    /// ([`crate::win32k::input`]).
    pub input: crate::win32k::input::RawInput,
    /// The threads' message queues, the timers and the windows' update regions
    /// ([`crate::win32k::queue`]).
    pub queues: crate::win32k::queue::Queues,
    /// The windows' extra bytes.
    pub(super) extra: ExtraBytes,
    /// The windows' texts: their titles, and their creations' names.
    pub(in crate::win32k) texts: Texts,
    /// The menus ([`crate::win32k::menu`]): a window's menu is its record's, under the same lock.
    pub menus: crate::win32k::menu::Menus,
}

/// A window of the class `class` as the icon-change notification sees it (see
/// [`Windows::class_view`]).
fn view_of(class: class::ClassId) -> class::WindowView {
    class::WindowView {
        class,
        query_drag_icon: false,
        has_own_icon_sm: false,
    }
}

impl Windows {
    /// Write an empty registry at `windows`, field by field (by value it would pass through the
    /// stack, which is smaller than it).
    ///
    /// # Safety
    ///
    /// `windows` is valid for writes, aligned, and the records' final address; its previous
    /// contents are overwritten, not dropped.
    pub unsafe fn write_empty(windows: *mut Windows) {
        use core::ptr::addr_of_mut;
        // SAFETY: the caller's contract; every field is written, the arrays element by element.
        unsafe {
            addr_of_mut!((*windows).pool).write(WindowPool::new());
            UserHandles::write_empty(addr_of_mut!((*windows).handles));
            addr_of_mut!((*windows).threads).write(crate::slots::Records::new());
            let desktops = addr_of_mut!((*windows).desktops) as *mut Desktop;
            for index in 0..DESKTOPS {
                desktops.add(index).write(Desktop::EMPTY);
            }
            let monitors = addr_of_mut!((*windows).monitors) as *mut Monitor;
            for index in 0..MONITORS {
                monitors.add(index).write(Monitor::EMPTY);
            }
            addr_of_mut!((*windows).clipboard_owner).write(None);
            addr_of_mut!((*windows).foreground_thread).write(None);
            addr_of_mut!((*windows).input).write(crate::win32k::input::RawInput::EMPTY);
            crate::win32k::queue::Queues::write_empty(addr_of_mut!((*windows).queues));
            // Zero bytes are an empty arena: no granule taken, every byte zero.
            addr_of_mut!((*windows).extra).write_bytes(0, 1);
            addr_of_mut!((*windows).texts).write(Texts::EMPTY);
            crate::win32k::menu::Menus::write_empty(addr_of_mut!((*windows).menus));
        }
    }

    /// Add a thread's context record: its process, desktop, desktop access and whether it has a
    /// desktop handle yet. Its index is the thread id.
    pub fn add_thread(
        &mut self,
        process: class::Owner,
        desktop: u32,
        desktop_access: u32,
        desktop_handle: Option<Hwnd>,
        monitor: Option<u16>,
    ) -> Option<ThreadId> {
        let free = self.threads.iter().position(|t| !t.live);
        let index = match free {
            Some(index) => index,
            None => {
                // Every record made is taken: the next one, with its queue. None, and nothing
                // taken, when no page is left (or the u16 index is spent).
                let index = u16::try_from(self.threads.len())
                    .ok()
                    .filter(|&i| i != u16::MAX)?;
                self.threads
                    .ensure(index.into(), crate::win32k::pages())
                    .ok()?;
                index.into()
            }
        };
        if !self.queues.make(index as u16) {
            return None;
        }
        self.threads[index] = Thread {
            live: true,
            process,
            desktop,
            desktop_handle,
            desktop_access,
            monitor,
            ..Thread::EMPTY
        };
        Some(ThreadId(index as u16))
    }

    /// The record of the process thread `key`, made at its first win32k service: the one it has,
    /// or a fresh one. A record an ended thread of the same slot left is reused when it holds no
    /// windows (a thread's record outlives it until its process's end). None when every record is
    /// taken.
    pub fn connect_thread(
        &mut self,
        key: ThreadKey,
        process: class::Owner,
        desktop: u32,
        desktop_access: u32,
        desktop_handle: Hwnd,
    ) -> Option<ThreadId> {
        if let Some(index) = self
            .threads
            .iter()
            .position(|t| t.live && t.key == Some(key))
        {
            return Some(ThreadId(index as u16));
        }
        let ended = self.threads.iter().position(|t| {
            t.live && t.window_count == 0 && t.key.is_some_and(|k| k.index == key.index)
        });
        if let Some(index) = ended {
            self.threads[index].live = false;
        }
        let id = self.add_thread(process, desktop, desktop_access, Some(desktop_handle), None)?;
        self.thread_mut(id).key = Some(key);
        Some(id)
    }

    /// Wire a desktop's window and message window (the window-station side's call).
    pub fn set_desktop(
        &mut self,
        id: u32,
        window: Option<WindowId>,
        message_window: Option<WindowId>,
    ) {
        let slot = self
            .desktops
            .iter_mut()
            .find(|d| d.id == 0 || d.id == id)
            .expect("a free desktop slot");
        *slot = Desktop {
            id,
            window,
            message_window,
            ..Desktop::EMPTY
        };
    }

    /// Set a monitor's rectangle (the display side's call).
    pub fn set_monitor(&mut self, index: u16, rect: Rect) {
        self.monitors[index as usize].rect = rect;
    }

    /// A monitor's work area (SystemParametersInfo's SPI_GETWORKAREA, for the primary).
    pub fn work_area(&self, index: u16) -> Rect {
        self.monitors[index as usize].rect
    }

    /// Every desktop window covers `screen`, the display's new extent (its client area too: a
    /// desktop window has no frame).
    pub fn cover_screen(&mut self, screen: Rect) {
        for index in 0..DESKTOPS {
            if let Some(window) = self.desktops[index].window {
                let w = self.at_mut(window);
                w.window_rect = screen;
                w.client_rect = screen;
            }
        }
    }

    pub(super) fn at(&self, id: WindowId) -> &Window {
        self.pool.at(id)
    }

    /// The live record `id` names; none for a destroyed or forged id.
    pub(super) fn get(&self, id: WindowId) -> Option<&Window> {
        self.pool.get(id)
    }

    pub(super) fn at_mut(&mut self, id: WindowId) -> &mut Window {
        self.pool.at_mut(id)
    }

    pub(in crate::win32k) fn thread(&self, id: ThreadId) -> &Thread {
        &self.threads[id.0 as usize]
    }

    pub(in crate::win32k) fn thread_mut(&mut self, id: ThreadId) -> &mut Thread {
        &mut self.threads[id.0 as usize]
    }

    /// How many thread records are made: every index below it names one.
    pub(in crate::win32k) fn thread_records(&self) -> usize {
        self.threads.len()
    }

    pub(super) fn desktop_by_id(&self, id: u32) -> Option<&Desktop> {
        self.desktops.iter().find(|d| d.id == id)
    }

    pub(super) fn desktop_by_id_mut(&mut self, id: u32) -> Option<&mut Desktop> {
        self.desktops.iter_mut().find(|d| d.id == id)
    }

    /// The window a handle names, when the handle is live (its record's generation matches);
    /// none otherwise — the handle validation the destroy service runs.
    pub fn window_from_handle(&self, handle: Hwnd) -> Option<WindowId> {
        let entry = self.handles.window(handle)?;
        self.pool.is_live(entry.id).then_some(entry.id)
    }

    /// The handle of `id` (0 for none).
    pub fn handle_of(&self, id: WindowId) -> Hwnd {
        self.pool.at(id).handle
    }

    /// The message window of the thread `thread`'s desktop: the parent HWND_MESSAGE names.
    pub fn message_window(&self, thread: ThreadId) -> Option<WindowId> {
        self.desktop_by_id(self.thread(thread).desktop)
            .and_then(|d| d.message_window)
    }

    /// The window `handle` names, as the class-change services see it: its class, its process and
    /// its desktop. None for a handle naming no live window, or a window without a class.
    pub fn class_window(&self, handle: Hwnd) -> Option<class::Window> {
        let w = self.at(self.window_from_handle(handle)?);
        Some(class::Window {
            class: w.class?,
            owner: w.process,
            desktop: w.desktop,
        })
    }

    /// The window `handle` names, as the icon-change notification visits it. The records carry no
    /// drag-icon query flag and no small-icon property yet, so neither is set.
    pub fn class_view(&self, handle: Hwnd) -> Option<class::WindowView> {
        Some(view_of(self.class_window(handle)?.class))
    }

    /// Every live window with a class, as the icon-change notification visits them (no buffer).
    pub fn class_views(&self) -> impl Iterator<Item = class::WindowView> + '_ {
        Self::views_of(&self.pool)
    }

    /// The handle table, lent to a class change, beside the windows it notifies
    /// ([`Windows::class_views`]).
    pub fn handles_and_class_views(
        &mut self,
    ) -> (
        &mut UserHandles,
        impl Iterator<Item = class::WindowView> + '_,
    ) {
        (&mut self.handles, Self::views_of(&self.pool))
    }

    fn views_of(pool: &WindowPool) -> impl Iterator<Item = class::WindowView> + '_ {
        pool.iter()
            .filter_map(|(_, record)| record.class.map(view_of))
    }
}

#[cfg(test)]
mod tests {
    use rtl::user::{WS_OVERLAPPED, WS_POPUP};

    use super::*;
    use crate::win32k::window::testkit::*;

    /// A thread's record is made at its first service and found again at its next; another thread
    /// gets its own; a thread reusing an ended one's slot takes the record over when it holds no
    /// windows, and gets a fresh one otherwise.
    #[test]
    fn a_thread_keeps_its_record() {
        let w = windows();
        let first = w
            .connect_thread(key(3, 0), OWNER, DESKTOP, DESKTOP_CREATEWINDOW, 0x10)
            .unwrap();
        assert_eq!(
            w.connect_thread(key(3, 0), OWNER, DESKTOP, DESKTOP_CREATEWINDOW, 0x10),
            Some(first)
        );
        let thread = w.thread(first);
        assert_eq!(thread.process, OWNER);
        assert_eq!(thread.desktop, DESKTOP);
        assert_eq!(thread.desktop_handle, Some(0x10));
        assert_eq!(thread.desktop_access, DESKTOP_CREATEWINDOW);
        let other = w
            .connect_thread(key(4, 0), OTHER_OWNER, DESKTOP, 0, 0x20)
            .unwrap();
        assert_ne!(other, first);

        // Slot 3 again, a later generation: the ended thread's empty record is taken over.
        let again = w
            .connect_thread(key(3, 1), OTHER_OWNER, DESKTOP, 0, 0x30)
            .unwrap();
        assert_eq!(again, first, "the lowest free record: the one given up");
        assert_eq!(w.thread(again).process, OTHER_OWNER);
        assert_eq!(w.thread(again).key, Some(key(3, 1)));

        // An ended thread that still holds windows keeps its record.
        w.thread_mut(again).window_count = 1;
        let fresh = w
            .connect_thread(key(3, 2), OWNER, DESKTOP, 0, 0x40)
            .unwrap();
        assert_ne!(fresh, again);
        assert!(w.thread(again).live);
    }

    /// The class registry's view of the windows: a window's class, process and desktop through
    /// its handle (none for a dead handle or a window without a class), and every window with a
    /// class for the icon-change notification.
    #[test]
    fn the_class_registry_sees_the_windows() {
        let (w, c, t, atom, _, _) = setup();
        let mut pump = Rec::new(t);
        let a = create(w, c, t, atom, WS_OVERLAPPED, &mut pump).unwrap();
        let b = create(w, c, t, atom, WS_POPUP, &mut pump).unwrap();
        let view = w.class_window(w.handle_of(a)).unwrap();
        assert_eq!(view.class, w.at(a).class.unwrap());
        assert_eq!(view.owner, OWNER);
        assert_eq!(view.desktop, DESKTOP);
        assert_eq!(w.class_view(w.handle_of(b)).map(|v| v.class), w.at(b).class);
        assert_eq!(w.class_window(0x1234), None);

        // The scaffolding's desktop windows have no class: only the two created windows count.
        let views: Vec<_> = w.class_views().collect();
        assert_eq!(views.len(), 2);
        assert_eq!(views[0], w.class_view(w.handle_of(a)).unwrap());

        let handle = w.handle_of(a);
        Windows::destroy_window_handle(&mut pump.on(w, c), t, handle).unwrap();
        assert_eq!(w.class_window(handle), None);
        assert_eq!(w.class_views().count(), 1);
    }
}
