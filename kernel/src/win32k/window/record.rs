//! A window's record, its id, and the pools its records and extra bytes live in.

use rtl::gdi::Rect;
use rtl::scroll::ScrollBars;
use rtl::user::{WS_CHILD, WS_POPUP, WS_VISIBLE};

use super::*;
use crate::sched::thread::ThreadId;
use crate::slots::{Id, LowestFirst, Record, Slots, PAGE};
use crate::win32k::class;
use crate::win32k::text::Text;

/// The window pool's kind of id.
pub enum WindowTag {}

/// A window's id: its slot in the window pool and the slot's uniqueness count, which moves on
/// when the record is freed, so a destroyed window's id names nothing (never the record's next
/// window).
pub type WindowId = Id<WindowTag>;

impl WindowId {
    /// The id of the slot `index`, its first count (the handle table's tests).
    #[cfg(test)]
    pub const fn for_tests(index: u16) -> Self {
        Id::new(index, 1)
    }
}

/// The internal flags a window record carries (the bits that are not public style bits).
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub(super) struct Flags {
    /// Size/move messages are deferred to show time (tiled windows).
    pub(super) sendsizemove: bool,
    /// The window is destroyed (its handlers may still be running).
    pub(super) destroyed: bool,
    /// The window is in the middle of being destroyed.
    pub(super) in_destroy: bool,
    /// The window's destroy has begun, or the destroy cascade has reached it: a DestroyWindow of
    /// it from one of its handlers (WM_DESTROY's, WM_NCDESTROY's) finds it on its way already.
    pub(super) destroying: bool,
    /// Its own destroy is sending the window its WM_DESTROY: a DestroyWindow of it from that
    /// handler runs a destroy of its own, nested (guiwin `dienest`).
    pub(super) in_wm_destroy: bool,
    /// The create finished (WM_CREATE ran).
    pub(super) initialized: bool,
    /// The create came through the ANSI entry point.
    pub(super) ansi_creator: bool,
    /// A pre-4.0 (3.x) caller.
    pub(super) win31_compat: bool,
    /// A 4.0-or-later caller.
    pub(super) win40_compat: bool,
    /// The window procedure runs on the kernel side.
    pub(super) server_side_proc: bool,
    /// The window procedure takes the narrow forms of the messages (Windows 2000's WFANSIPROC):
    /// IsWindowUnicode's FALSE.
    pub(super) ansi_proc: bool,
    /// WM_NCCREATE's handler set the window text.
    pub(super) title_set: bool,
    /// The window sits at the bottom of the z-order.
    pub(super) bottommost: bool,
    /// The window has a palette.
    pub(super) has_palette: bool,
    /// The session's end asked the window WM_QUERYENDSESSION and has not sent it WM_ENDSESSION
    /// yet (see [`Windows::session_next_to_ask`]).
    pub(super) session_asked: bool,
}

/// The window procedure a record points at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Proc {
    /// A client-side procedure (the class's wndProc value).
    Client(u32),
    /// The default window procedure (a zombie window's).
    Default,
}

/// A window: the record the pool holds.
#[derive(Clone, Copy)]
pub(super) struct Window {
    pub(super) handle: Hwnd,
    pub(super) thread: ThreadId,
    /// The owning process, as the class registry keys it.
    pub(super) process: class::Owner,
    /// The desktop the window is on (the packed desktop object id).
    pub(super) desktop: u32,
    pub(super) monitor: u16,
    /// The public style (the type, visible, clip and frame bits live here).
    pub(super) style: u32,
    /// The public extended style.
    pub(super) ex_style: u32,
    pub(super) flags: Flags,
    pub(super) parent: Option<WindowId>,
    pub(super) child: Option<WindowId>,
    pub(super) next: Option<WindowId>,
    pub(super) owner: Option<WindowId>,
    pub(super) last_active: Option<WindowId>,
    pub(super) window_rect: Rect,
    pub(super) client_rect: Rect,
    pub(super) class: Option<class::ClassId>,
    pub(super) menu: Menu,
    /// hModule.
    pub(super) module: u32,
    pub(super) proc: Proc,
    pub(super) cb_wnd_extra: i32,
    /// The window's extra bytes (cbWndExtra of them), when it has any: a block of the registry's
    /// arena ([`ExtraBytes`]), kept out of the record so its copies stay small.
    pub(super) extra: Option<ExtraBlock>,
    /// GWL_USERDATA.
    pub(super) user_data: u32,
    /// The kind of window user32's code made of it (NtUserSetWindowFNID: rtl::window's FNID_*),
    /// 0 for none.
    pub(super) fnid: u16,
    /// The window's text: a block of the registry's store ([`Windows::texts`]).
    pub(super) title: Text,
    /// The name its creation was given, a block of the same store, while the creation runs (its
    /// WM_NCCREATE and WM_CREATE carry it: [`CreateName::Given`]); empty after it.
    pub(super) create_name: Text,
    /// The window's place when it is neither minimized nor maximized (GetWindowPlacement's
    /// rcNormalPosition), in its parent's client coordinates (the screen's for a top-level
    /// window): kept as it leaves that state, and set by SetWindowPlacement; none before either.
    pub(super) normal: Option<Rect>,
    /// Where the window was last minimized, its top-left corner (ptMinPosition): kept as it leaves
    /// the minimized state, and set by SetWindowPlacement's WPF_SETMINPOSITION; where it goes the
    /// next time it is minimized.
    pub(super) min_position: Option<(i32, i32)>,
    /// Where the window goes maximized (ptMaxPosition), as SetWindowPlacement set it.
    pub(super) max_position: Option<(i32, i32)>,
    /// The window was maximized when it was last minimized, or SetWindowPlacement said so
    /// (WPF_RESTORETOMAXIMIZED): a restore from minimized maximizes it.
    pub(super) restore_maximized: bool,
    /// The object's lock count: 1 at creation, dropped by the free; more than that means
    /// someone else still holds a reference and the free makes a zombie instead.
    pub(super) locks: u32,
    /// The destroy cascade's bookkeeping for this window, while a cascade visits it.
    pub(super) walk: Walk,
    /// The window's own scroll bars (Windows 2000's pSBInfo), once a call made them
    /// ([`crate::win32k::scroll`]).
    pub(super) scroll: Option<ScrollBars>,
    /// The window's copy of the system menu, once GetSystemMenu made one (Windows 2000's
    /// spmenuSys); a destroyed menu's id names nothing.
    pub(super) system_menu: Option<crate::win32k::menu::MenuId>,
}

/// The destroy cascade's state in a window's record. The cascade walks the trees without
/// recursing (a level costs over a kilobyte of gate stack at opt-level 0, and parent and owner
/// chains may be 100 deep), so what a recursive walk keeps in frames lives here: each window is
/// on one walk at a time; a handler that destroys another window starts that window's own walk.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct Walk {
    /// The sibling the WM_DESTROY walk visits after this window, read before this window's
    /// subtree is messaged: a handler that destroys it ends the walk of their parent's children.
    pub(super) next: Option<WindowId>,
    /// The window whose owned-window cascade is destroying this one (none for the window the
    /// destroy was asked for).
    pub(super) owner: Option<WindowId>,
    /// This window's destroy is a re-entry: it was marked for destruction already.
    pub(super) already: bool,
    /// The calling thread's hooks-disabled flag from before a re-entry's destroy set it.
    pub(super) saved_hooks: Option<bool>,
}

impl Walk {
    pub(super) const NONE: Self = Walk {
        next: None,
        owner: None,
        already: false,
        saved_hooks: None,
    };
}

impl Window {
    const EMPTY: Self = Window {
        handle: 0,
        thread: ThreadId(0),
        process: 0,
        desktop: 0,
        monitor: PRIMARY_MONITOR,
        style: 0,
        ex_style: 0,
        flags: Flags {
            sendsizemove: false,
            destroyed: false,
            in_destroy: false,
            destroying: false,
            in_wm_destroy: false,
            initialized: false,
            ansi_creator: false,
            win31_compat: false,
            win40_compat: false,
            server_side_proc: false,
            ansi_proc: false,
            title_set: false,
            bottommost: false,
            has_palette: false,
            session_asked: false,
        },
        parent: None,
        child: None,
        next: None,
        owner: None,
        last_active: None,
        window_rect: Rect {
            left: 0,
            top: 0,
            right: 0,
            bottom: 0,
        },
        client_rect: Rect {
            left: 0,
            top: 0,
            right: 0,
            bottom: 0,
        },
        class: None,
        menu: Menu::None,
        module: 0,
        proc: Proc::Default,
        cb_wnd_extra: 0,
        extra: None,
        user_data: 0,
        fnid: 0,
        title: Text::EMPTY,
        create_name: Text::EMPTY,
        normal: None,
        min_position: None,
        max_position: None,
        restore_maximized: false,
        locks: 0,
        walk: Walk::NONE,
        scroll: None,
        system_menu: None,
    };

    /// The window's kind, from the style's type bits.
    pub(super) fn kind(&self) -> Kind {
        kind_of(self.style)
    }

    pub(super) fn is_child(&self) -> bool {
        self.style & WS_CHILD != 0
    }

    pub(super) fn is_popup(&self) -> bool {
        self.style & WS_POPUP != 0
    }

    pub(super) fn is_tiled(&self) -> bool {
        !self.is_child() && !self.is_popup()
    }

    pub(super) fn is_visible(&self) -> bool {
        self.style & WS_VISIBLE != 0
    }
}

/// A window's kind: from the style's WS_CHILD/WS_POPUP bits (WS_OVERLAPPED is tiled).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Tiled,
    Popup,
    Child,
}

pub(super) fn kind_of(style: u32) -> Kind {
    if style & WS_CHILD != 0 {
        Kind::Child
    } else if style & WS_POPUP != 0 {
        Kind::Popup
    } else {
        Kind::Tiled
    }
}

// SAFETY: `write_fresh` writes a whole record.
unsafe impl Record for Window {
    unsafe fn write_fresh(at: *mut Self, _: u32) {
        // SAFETY: the caller's contract.
        unsafe { at.write(Window::EMPTY) };
    }
}

/// Window records to a chunk: four pages' worth, a slot being its record and 8 bytes.
const WINDOWS_PER_CHUNK: usize = 4 * PAGE / (core::mem::size_of::<Window>() + 8);

// The records hold no pointer, so the target's size and the host's agree.
const _: () = assert!(Slots::<Window, LowestFirst<WindowTag>, WINDOWS_PER_CHUNK>::CHUNK_PAGES == 4);

/// The window pool: records in slots of [`crate::slots`], grown a chunk at a time from the
/// nonpaged pool under the window manager's lock and kept at their peak. Records are taken lowest
/// free first (the exposed-area walk goes in that order). Every lookup is checked: a destroyed
/// window's id names nothing, whatever took its slot since, as a procedure running under a send
/// may destroy the window its caller holds the id of.
pub(super) struct WindowPool {
    slots: Slots<Window, LowestFirst<WindowTag>, WINDOWS_PER_CHUNK>,
}

impl WindowPool {
    pub(super) const fn new() -> Self {
        WindowPool {
            slots: Slots::new(),
        }
    }

    /// A free record for a new window (renewed empty); none when no page is left to grow by.
    pub(super) fn allocate(&mut self) -> Option<WindowId> {
        let (id, record) = self
            .slots
            .allocate_or_grow(0, crate::win32k::pages())
            .ok()?;
        *record = Window::EMPTY;
        Some(id)
    }

    /// Free `id`'s record: its count moves on, so the id resolves to nothing.
    pub(super) fn free(&mut self, id: WindowId) {
        let freed = self.slots.free(id);
        debug_assert!(freed, "a live window id");
    }

    /// The live record `id` names; none for a destroyed or forged id.
    pub(super) fn get(&self, id: WindowId) -> Option<&Window> {
        self.slots.get(id)
    }

    /// The live record `id` names. A destroyed window's id is a caller's bug (it checks
    /// [`WindowPool::is_live`] after anything that may have destroyed it): it stops here, in every
    /// build, rather than reading the record's next window.
    pub(super) fn at(&self, id: WindowId) -> &Window {
        self.slots.get(id).expect("a live window id")
    }

    /// The live record `id` names, mutable.
    pub(super) fn at_mut(&mut self, id: WindowId) -> &mut Window {
        self.slots.get_mut(id).expect("a live window id")
    }

    pub(super) fn is_live(&self, id: WindowId) -> bool {
        self.slots.get(id).is_some()
    }

    /// The live window at slot `index`, if one is.
    pub(super) fn id_at(&self, index: u32) -> Option<WindowId> {
        self.slots.id_at(index)
    }

    /// One past the highest slot ever taken: the walks by slot stop there.
    pub(super) fn high_water(&self) -> u32 {
        self.slots.high_water()
    }

    /// The live windows' ids and records, in slot order.
    pub(super) fn iter(&self) -> impl Iterator<Item = (WindowId, &Window)> + '_ {
        self.slots.iter()
    }

    /// The same, to change.
    pub(super) fn iter_mut(&mut self) -> impl Iterator<Item = (WindowId, &mut Window)> + '_ {
        self.slots.iter_mut()
    }

    /// How many windows are live.
    pub(super) fn live(&self) -> usize {
        self.slots.live() as usize
    }
}

/// How many bytes the windows' extra bytes share between them.
pub const EXTRA_BYTES: usize = 16 * 1024;

/// The arena's unit: a window's extra bytes take whole granules.
const EXTRA_GRANULE: usize = 16;

const EXTRA_GRANULES: usize = EXTRA_BYTES / EXTRA_GRANULE;

/// A window's extra bytes in the arena: a run of granules.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ExtraBlock {
    first: u16,
    granules: u16,
}

/// The windows' extra bytes (cbWndExtra), an arena of granules the records name: the stand-in for
/// the desktop heap Windows 2000 allocates them from, kept apart so the records stay small.
pub(super) struct ExtraBytes {
    bytes: [u8; EXTRA_BYTES],
    /// Which granules blocks hold, a bit each.
    taken: [u32; EXTRA_GRANULES / 32],
}

impl ExtraBytes {
    fn is_taken(&self, granule: usize) -> bool {
        self.taken[granule / 32] & (1 << (granule % 32)) != 0
    }

    fn mark(&mut self, block: ExtraBlock, taken: bool) {
        for granule in block.first as usize..(block.first + block.granules) as usize {
            if taken {
                self.taken[granule / 32] |= 1 << (granule % 32);
            } else {
                self.taken[granule / 32] &= !(1 << (granule % 32));
            }
        }
    }

    /// The lowest run of granules that holds `size` bytes, zeroed; none when no run is that long.
    pub(super) fn allocate(&mut self, size: usize) -> Option<ExtraBlock> {
        let granules = size.div_ceil(EXTRA_GRANULE);
        if granules == 0 || granules > EXTRA_GRANULES {
            return None;
        }
        let mut run = 0;
        for granule in 0..EXTRA_GRANULES {
            if self.is_taken(granule) {
                run = 0;
                continue;
            }
            run += 1;
            if run == granules {
                let block = ExtraBlock {
                    first: (granule + 1 - granules) as u16,
                    granules: granules as u16,
                };
                self.mark(block, true);
                self.bytes_mut(block).fill(0);
                return Some(block);
            }
        }
        None
    }

    pub(super) fn free(&mut self, block: ExtraBlock) {
        self.mark(block, false);
    }

    pub(super) fn bytes(&self, block: ExtraBlock) -> &[u8] {
        let first = block.first as usize * EXTRA_GRANULE;
        &self.bytes[first..first + block.granules as usize * EXTRA_GRANULE]
    }

    pub(super) fn bytes_mut(&mut self, block: ExtraBlock) -> &mut [u8] {
        let first = block.first as usize * EXTRA_GRANULE;
        &mut self.bytes[first..first + block.granules as usize * EXTRA_GRANULE]
    }

    /// How many granules blocks hold.
    pub(super) fn taken_granules(&self) -> usize {
        self.taken
            .iter()
            .map(|word| word.count_ones() as usize)
            .sum()
    }
}

/// A window's entry in the user handle table ([`UserHandles`]): the window it names, the thread
/// that owns it, and the destroy flags (Windows 2000's handle entry's owner and flags).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WindowEntry {
    pub(in crate::win32k) id: WindowId,
    pub(in crate::win32k) owner: ThreadId,
    /// The handle is marked for destruction: a re-entering destroy proceeds instead of failing
    /// the owner check.
    pub(in crate::win32k) marked_destroy: bool,
    /// A free is in progress on the object.
    pub(in crate::win32k) in_destroy: bool,
}

#[cfg(test)]
mod tests {
    use rtl::user::WS_OVERLAPPED;

    use super::*;
    use crate::win32k::window::testkit::*;

    /// Windows past the old fixed array's 256 and the user handle table's old 1,024 slots, each
    /// its own record and handle (even low words, all distinct); destroyed, they leave the pool at
    /// its peak, and the next window takes the lowest slot with its count moved on.
    #[test]
    fn the_pool_grows_past_its_old_cap() {
        let (w, c, t, atom, _, _) = setup();
        let mut pump = Rec::new(t);
        let ids: Vec<_> = (0..1100)
            .map(|_| create(w, c, t, atom, WS_POPUP, &mut pump).unwrap())
            .collect();
        assert_eq!(live(w), 1102);
        let handles: std::collections::BTreeSet<_> =
            ids.iter().map(|&id| w.handle_of(id)).collect();
        assert_eq!(handles.len(), 1100);
        assert!(
            handles.iter().all(|&h| h & 1 == 0),
            "windows' low words are even"
        );
        assert!(ids
            .iter()
            .all(|&id| w.window_from_handle(w.handle_of(id)) == Some(id)));
        let peak = w.pool.high_water();
        for &id in &ids {
            let handle = w.handle_of(id);
            Windows::destroy_window_handle(&mut pump.on(w, c), t, handle).unwrap();
        }
        assert_eq!(live(w), 2, "the desktop's own windows");
        assert!(ids.iter().all(|&id| !w.is_live(id)));
        assert_eq!(w.thread(t).window_count, 0);
        let again = create(w, c, t, atom, WS_POPUP, &mut pump).unwrap();
        assert_eq!(again.index, ids[0].index, "the lowest free slot");
        assert_eq!(again.uniq, ids[0].uniq + 1, "its count moved on");
        assert_eq!(w.pool.high_water(), peak);
    }

    /// A destroyed window's id names nothing, before and after a new window takes its slot; a
    /// forged id — a count of 0, a count ahead of the slot's, a slot past every one made — names
    /// nothing either.
    #[test]
    fn stale_and_forged_ids_name_nothing() {
        let (w, c, t, atom, _, _) = setup();
        let mut pump = Rec::new(t);
        let a = create(w, c, t, atom, WS_POPUP, &mut pump).unwrap();
        let b = create(w, c, t, atom, WS_POPUP, &mut pump).unwrap();
        let handle = w.handle_of(a);
        Windows::destroy_window_handle(&mut pump.on(w, c), t, handle).unwrap();
        assert!(!w.is_live(a));
        assert!(w.get(a).is_none());
        assert_eq!(w.window_from_handle(handle), None);
        let next = create(w, c, t, atom, WS_POPUP, &mut pump).unwrap();
        assert_eq!(next.index, a.index);
        assert_ne!(next, a);
        assert!(!w.is_live(a), "a new window in the slot is not the old one");
        assert!(w.is_live(next) && w.is_live(b));
        let past = w.pool.high_water() as u16;
        for forged in [
            WindowId::new(next.index, 0),
            WindowId::new(next.index, next.uniq + 1),
            WindowId::new(past, 1),
            WindowId::new(0xFFFE, 1),
            WindowId::new(0xFFFF, 1),
        ] {
            assert!(!w.is_live(forged), "{forged:?}");
            assert!(w.get(forged).is_none());
        }
    }

    /// A new window takes the lowest free slot whatever order the frees came in, as the fixed
    /// array did: the walks by slot (an exposed area's repaint, a process's end) keep their order.
    #[test]
    fn a_new_window_takes_the_lowest_free_slot() {
        let (w, c, t, atom, _, _) = setup();
        let mut pump = Rec::new(t);
        let ids: Vec<_> = (0..4)
            .map(|_| create(w, c, t, atom, WS_POPUP, &mut pump).unwrap())
            .collect();
        for i in [2, 0] {
            let handle = w.handle_of(ids[i]);
            Windows::destroy_window_handle(&mut pump.on(w, c), t, handle).unwrap();
        }
        let first = create(w, c, t, atom, WS_POPUP, &mut pump).unwrap();
        let second = create(w, c, t, atom, WS_POPUP, &mut pump).unwrap();
        assert_eq!((first.index, second.index), (ids[0].index, ids[2].index));
    }

    /// A destroyed window's id stops at the lookup, in every build, rather than read whatever
    /// record took its slot.
    #[test]
    #[should_panic(expected = "a live window id")]
    fn a_stale_id_stops_at_the_lookup() {
        let (w, c, t, atom, _, _) = setup();
        let mut pump = Rec::new(t);
        let a = create(w, c, t, atom, WS_POPUP, &mut pump).unwrap();
        let handle = w.handle_of(a);
        Windows::destroy_window_handle(&mut pump.on(w, c), t, handle).unwrap();
        create(w, c, t, atom, WS_POPUP, &mut pump).unwrap();
        let _ = w.window_style(a);
    }

    /// A pool with no page left to grow by fails the create with ERROR_OUTOFMEMORY (14).
    #[test]
    fn a_full_pool_fails_the_create() {
        let (w, c, t, atom, _, _) = setup();
        crate::win32k::test_pages::budget(0);
        while w.pool.allocate().is_some() {}
        let mut pump = Rec::new(t);
        let err = create(w, c, t, atom, WS_OVERLAPPED, &mut pump).unwrap_err();
        crate::win32k::test_pages::unlimited();
        assert_eq!(err, Failure::OutOfMemory);
        assert_eq!(err.code(), 14);
    }

    /// A destroyed window's handle names no window once its slot names the next one: the slot's
    /// uniqueness count in the high word moved on, the first handle's (count 1) too. A high word of
    /// 0 or 0xFFFF names whatever window the slot holds now.
    #[test]
    fn a_reused_slot_gets_a_new_handle() {
        let (w, c, t, atom, _, _) = setup();
        let mut pump = Rec::new(t);
        let first = create(w, c, t, atom, WS_POPUP, &mut pump).unwrap();
        let first = w.handle_of(first);
        assert_eq!(first >> 16, 1, "a slot's first handle has the count 1");
        assert!(Windows::destroy_window_handle(&mut pump.on(w, c), t, first).unwrap());
        let second = create(w, c, t, atom, WS_POPUP, &mut pump).unwrap();
        let old = w.handle_of(second);
        assert_eq!(
            (old & 0xFFFF, old >> 16),
            (first & 0xFFFF, 2),
            "the same slot, counted on"
        );
        assert!(Windows::destroy_window_handle(&mut pump.on(w, c), t, old).unwrap());
        let next = create(w, c, t, atom, WS_POPUP, &mut pump).unwrap();
        let new = w.handle_of(next);
        assert_eq!(new, old + 0x1_0000);
        assert_eq!(w.window_from_handle(old), None);
        assert_eq!(
            w.window_from_handle(first),
            None,
            "the first handle names nothing"
        );
        assert_eq!(w.window_from_handle(new), Some(next));
        assert_eq!(
            w.window_from_handle(first & 0xFFFF),
            Some(next),
            "the wildcard 0"
        );
        assert_eq!(w.window_from_handle(first | 0xFFFF_0000), Some(next));
        assert_eq!(w.window_from_handle(new + 0x1_0000), None);
        assert_eq!(
            Windows::destroy_window_handle(&mut pump.on(w, c), t, old),
            Err(Failure::InvalidWindowHandle)
        );
    }
}
