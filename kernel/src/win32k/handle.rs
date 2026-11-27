//! The user handle table: the one table every user object's handle names a slot of — windows,
//! menus, accelerator tables, cursors and icons — as Windows 2000's window manager keeps one
//! table (its handle entries) for every kind of its objects.
//!
//! An entry is typed: it names a window, a menu, an accelerator table or a cursor/icon, by its
//! record's id in that kind's pool ([`UserObject`]); the records themselves stay in their kinds'
//! pools ([`super::window`], [`super::menu`], [`super::accel`], [`super::icon`]). A handle holds
//! its slot's index in the low word, as Windows 2000's do, and the slot's uniqueness count in the
//! high word, which moves on by one each time the slot's handle is closed, so a destroyed object's
//! handle names nothing once its slot names another. The slots are a slot pool's
//! ([`crate::slots`], the [`UserHandle`] codec), grown a page at a time: the 16-bit low word is
//! the only ceiling, 65,535 handles. A slot's first handle has a count of 1, and the count runs to
//! 0xFFFE and wraps to 1: it is never 0 or 0xFFFF, the wildcards, so a live handle's high word
//! always tells it from the slot's later objects.
//!
//! Every lookup is by kind, and checks the type and the count: a window's call on a menu's handle
//! finds no window, and a handle whose count is not its slot's finds nothing — unless its high
//! word is 0 or 0xFFFF, which name whatever object the slot holds now (the menus capture: IsWindow
//! and IsMenu take a live object's low word with either high word, and refuse it with one more).
//!
//! Which slot a new object takes:
//!
//! - **A window takes an even slot.** Windows NT hands out even window handles only, because
//!   programs rely on a window handle's being even (Raymond Chen, "Why did we lose half of the
//!   window handles?", The Old New Thing, 2007: the table's index is the handle's low word, and
//!   half its values are lost to windows).
//! - **Every other kind takes an odd slot,** while one is free or the table has one never used, and
//!   an even one only once none is left: the window slots are kept for windows.
//! - **Among the slots a kind may take, the one freed last goes first,** then one never used,
//!   lowest first.
//!
//! The menus capture shows each of these: a window made after a window's destruction takes its
//! slot, its high word one more, and so does a table after a menu's; a menu or an icon made after
//! a window's destruction takes another slot, and so does a window after a menu's or an icon's.
//! The parity is the low word's: a window's handle is even, a menu's, a table's or a cursor's odd
//! until the odd slots run out (predicted for Windows 2000, `manywin`'s `parity`).
//!
//! **Each object counts against its process's quota.** An entry names the process that holds the
//! object (none for the window manager's own: the desktop's windows, the stock cursors and icons),
//! and the process's record ([`super::process`]) counts its objects from the insert to the close,
//! as Windows 2000's HMAllocObject and HMFreeObject count them in the process's W32PROCESS. A
//! process at its quota ([`super::quota`]: USERProcessHandleQuota, 10,000 by default) gets no
//! handle, and neither does any process once the table is at its ceiling: both are
//! ERROR_NO_MORE_USER_HANDLES (1158), as `manywin`'s `quota` predicts; no page left is
//! ERROR_NOT_ENOUGH_MEMORY's. A process's end closes its objects' handles, giving its count back,
//! and starts its record afresh ([`UserHandles::end_process`]).
//!
//! Seams recorded: Windows 2000's table has more kinds — hooks, the clipboard's data objects,
//! window positions (BeginDeferWindowPos), DDE objects, keyboard layouts, monitors and others.
//! F2K has no hooks or deferred positions yet, and its clipboard's data objects never reach an
//! application (user32 copies their bytes into a memory block of its own), so they keep their
//! own numbers.

use super::accel::TableId;
use super::class::{Owner, SYSTEM_OWNER};
use super::icon::CursorId;
use super::menu::MenuId;
use super::process::{self, W32Processes};
use super::window::WindowEntry;
use crate::slots::{per_page, Full, Record, Slots, UserHandle};

/// What a slot holds: an object of one kind, by its record's id in that kind's pool.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UserObject {
    /// A window: its record, its thread and its destroy flags.
    Window(WindowEntry),
    Menu(MenuId),
    AcceleratorTable(TableId),
    /// A cursor or an icon (one kind, as on Windows: HCURSOR and HICON are the same handles).
    Cursor(CursorId),
}

/// A slot's entry: the object it holds (none until its first insert), and the process its count
/// is charged to (none for the window manager's own objects).
#[derive(Clone, Copy)]
struct Entry {
    object: Option<UserObject>,
    owner: Option<Owner>,
}

// SAFETY: `write_fresh` writes a whole entry.
unsafe impl Record for Entry {
    unsafe fn write_fresh(at: *mut Self, _: u32) {
        // SAFETY: the caller's contract.
        unsafe {
            at.write(Entry {
                object: None,
                owner: None,
            })
        };
    }
}

/// Why an insert gave no handle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// ERROR_NO_MORE_USER_HANDLES (1158): the process holds its quota's worth of objects, or no
    /// slot its kind may take is left below the table's ceiling.
    NoMoreUserHandles,
    /// No page was left for the table's next chunk or the process's record: the create's own
    /// memory failure.
    NoMemory,
}

impl Refusal {
    /// The status a service answers for it, when the create has no failure of its own for memory:
    /// ERROR_NO_MORE_USER_HANDLES's ([`process::NO_MORE_USER_HANDLES`]) or STATUS_NO_MEMORY.
    pub const fn status(self) -> crate::status::NtStatus {
        match self {
            Refusal::NoMoreUserHandles => process::NO_MORE_USER_HANDLES,
            Refusal::NoMemory => crate::status::STATUS_NO_MEMORY,
        }
    }
}

/// Entries to a chunk: one page's worth.
const ENTRIES_PER_CHUNK: usize = per_page::<Entry>();

const _: () = assert!(Slots::<Entry, UserHandle, ENTRIES_PER_CHUNK>::CHUNK_PAGES == 1);

/// The lane of the even slots, windows'.
const EVEN: usize = 0;
/// The lane of the odd slots, every other kind's first.
const ODD: usize = 1;

/// The user handle table: a slot pool ([`crate::slots`]) in two lanes, the even slots and the odd,
/// each with its own freed slots (the one freed last first) and its own slots never used (lowest
/// first). It grows a page at a time, to the 16-bit low word's 65,535 slots (slot 0 is never
/// handed out, so no handle is 0): Windows' ceiling on USER handles, system-wide.
pub struct UserHandles {
    slots: Slots<Entry, UserHandle, ENTRIES_PER_CHUNK>,
    /// The processes' records: each one's count of the objects it holds.
    processes: W32Processes,
}

impl UserHandles {
    /// Write an empty table at `handles`: no chunk made, no page held.
    ///
    /// # Safety
    ///
    /// `handles` is valid for writes and aligned; its previous contents are overwritten, not
    /// dropped.
    pub unsafe fn write_empty(handles: *mut UserHandles) {
        // SAFETY: the caller's contract.
        unsafe {
            handles.write(UserHandles {
                slots: Slots::new(),
                processes: W32Processes::new(),
            })
        };
    }

    /// Take a slot of `lane` for `object` of `owner`, making its chunk if it needs one: its
    /// handle.
    fn take(&mut self, lane: usize, object: UserObject, owner: Option<Owner>) -> Result<u32, Full> {
        let (handle, entry) = self.slots.allocate_or_grow(lane, super::pages())?;
        *entry = Entry {
            object: Some(object),
            owner,
        };
        Ok(handle)
    }

    /// Insert `object`, held by the process `owner` (none, or [`SYSTEM_OWNER`], for the window
    /// manager's own, which count against no quota): its handle. A window takes an even slot, any
    /// other kind an odd one, or an even one once no odd one is left.
    /// [`Refusal::NoMoreUserHandles`] when the process holds its quota's worth of objects
    /// ([`super::quota::user_process_handle_quota`]) or no slot its kind may take is left;
    /// [`Refusal::NoMemory`] when no page is left for a chunk or the process's record.
    pub fn insert(&mut self, owner: Option<Owner>, object: UserObject) -> Result<u32, Refusal> {
        let owner = owner.filter(|&owner| owner != SYSTEM_OWNER);
        if let Some(owner) = owner {
            let quota = super::quota::user_process_handle_quota();
            self.processes
                .may_take_user_object(owner, quota, super::pages())
                .map_err(|refusal| match refusal {
                    process::Refusal::Quota => Refusal::NoMoreUserHandles,
                    process::Refusal::NoMemory => Refusal::NoMemory,
                })?;
        }
        let taken = match object {
            UserObject::Window(_) => self.take(EVEN, object, owner),
            _ => match self.take(ODD, object, owner) {
                Err(Full::Limit) => self.take(EVEN, object, owner),
                taken => taken,
            },
        };
        let handle = taken.map_err(|full| match full {
            Full::Limit => Refusal::NoMoreUserHandles,
            Full::NoChunk => Refusal::NoMemory,
        })?;
        if let Some(owner) = owner {
            self.processes.took_user_object(owner);
        }
        Ok(handle)
    }

    /// The object `handle` names, of whatever kind: its slot's, when its high word is the slot's
    /// count or a wildcard.
    pub fn object(&self, handle: u32) -> Option<UserObject> {
        self.slots.get(handle)?.object
    }

    /// The window `handle` names: none for a handle naming nothing or another kind's object.
    pub fn window(&self, handle: u32) -> Option<WindowEntry> {
        match self.object(handle)? {
            UserObject::Window(entry) => Some(entry),
            _ => None,
        }
    }

    /// The menu `handle` names.
    pub fn menu(&self, handle: u32) -> Option<MenuId> {
        match self.object(handle)? {
            UserObject::Menu(id) => Some(id),
            _ => None,
        }
    }

    /// The accelerator table `handle` names.
    pub fn accelerator_table(&self, handle: u32) -> Option<TableId> {
        match self.object(handle)? {
            UserObject::AcceleratorTable(id) => Some(id),
            _ => None,
        }
    }

    /// The cursor or icon `handle` names.
    pub fn cursor(&self, handle: u32) -> Option<CursorId> {
        match self.object(handle)? {
            UserObject::Cursor(id) => Some(id),
            _ => None,
        }
    }

    /// Change the window entry `handle` names in place; false when it names no window.
    pub fn update_window(
        &mut self,
        handle: u32,
        change: impl FnOnce(WindowEntry) -> WindowEntry,
    ) -> bool {
        match self.slots.get_mut(handle) {
            Some(Entry {
                object: Some(UserObject::Window(entry)),
                ..
            }) => {
                *entry = change(*entry);
                true
            }
            _ => false,
        }
    }

    /// Close `handle`, its slot's count moved on (from 0xFFFE back to 1, never to a wildcard), and
    /// the object given back to its process's count; what it named.
    pub fn close(&mut self, handle: u32) -> Option<UserObject> {
        let entry = self.slots.get_mut(handle)?;
        let object = entry.object.take()?;
        if let Some(owner) = entry.owner.take() {
            self.processes.gave_user_object(owner);
        }
        self.slots.free(handle);
        Some(object)
    }

    /// The processes' records (GetGuiResources reads a count).
    pub fn processes(&self) -> &W32Processes {
        &self.processes
    }

    /// The USER objects the process `owner` holds.
    #[cfg(test)]
    pub fn user_objects(&self, owner: Owner) -> u32 {
        self.processes.user_objects(owner)
    }

    /// The process `owner` has ended, its objects destroyed (their handles closed, its count given
    /// back): an object whose handle stays open for another holder (a zombie window another
    /// thread still references) is charged to no process from now on, and the process's record
    /// starts afresh for the next process at its index.
    pub fn end_process(&mut self, owner: Owner) {
        if owner == SYSTEM_OWNER || self.processes.user_objects(owner) == 0 {
            self.processes.end(owner);
            return;
        }
        for (_, entry) in self.slots.iter_mut() {
            if entry.owner == Some(owner) {
                entry.owner = None;
            }
        }
        self.processes.end(owner);
    }

    /// The handles open: one per live object of every kind.
    #[cfg(test)]
    pub fn live(&self) -> u32 {
        self.slots.live()
    }
}

#[cfg(test)]
mod tests {
    //! The table's host tests: the kinds share the slots, a lookup checks the kind and the count,
    //! the wildcards, the lanes, the wrap, growth past the old 1,024 slots and the ceiling.

    use std::boxed::Box;
    use std::vec::Vec;

    use super::*;
    use crate::win32k::test_pages;

    fn handles() -> Box<UserHandles> {
        let mut handles = Box::<UserHandles>::new_uninit();
        // SAFETY: the box is valid and aligned.
        unsafe { UserHandles::write_empty(handles.as_mut_ptr()) };
        // SAFETY: written whole just above.
        unsafe { handles.assume_init() }
    }

    /// Insert `object` for no process (no quota): its handle, 0 for a refusal.
    fn put(t: &mut UserHandles, object: UserObject) -> u32 {
        t.insert(None, object).unwrap_or(0)
    }

    const MENU: UserObject = UserObject::Menu(MenuId::for_tests(1));
    const WINDOW: UserObject = UserObject::Window(WindowEntry {
        id: crate::win32k::window::WindowId::for_tests(1),
        owner: crate::sched::thread::ThreadId(0),
        marked_destroy: false,
        in_destroy: false,
    });
    const CURSOR: UserObject = UserObject::Cursor(CursorId::for_tests(1));

    /// Objects of every kind take slots of the one table: no two live handles share a low word.
    /// Each kind's lookup finds its own kind only. The low word is the slot's index.
    #[test]
    fn kinds_share_the_slots_and_lookups_check_the_kind() {
        let mut t = handles();
        let m = put(&mut t, MENU);
        let c = put(&mut t, CURSOR);
        assert_eq!(
            (m, c),
            (0x1_0001, 0x1_0003),
            "odd slots, the index in the low word, a slot's first handle a count of 1"
        );
        assert!(t.menu(m).is_some() && t.cursor(m).is_none() && t.window(m).is_none());
        assert!(t.cursor(c).is_some() && t.menu(c).is_none());
        assert!(t.accelerator_table(m).is_none());
        assert!(!t.update_window(m, |e| e), "a menu's entry is no window's");
        assert_eq!(t.live(), 2);
    }

    /// A slot freed goes to the next object, of any kind, its count one more; the old handle names
    /// nothing, the count one more names nothing yet, and 0 and 0xFFFF name the live object.
    #[test]
    fn reuse_moves_the_count_and_the_wildcards_name_the_live_object() {
        let mut t = handles();
        let c = put(&mut t, CURSOR);
        assert_eq!(t.close(c), Some(CURSOR));
        assert_eq!(t.close(c), None, "a closed handle closes nothing");
        let m = put(&mut t, MENU);
        assert_eq!(m, c + 0x1_0000, "the slot just freed, its count one more");
        assert_eq!(t.cursor(c), None);
        assert_eq!(t.menu(c), None, "the destroyed first handle names nothing");
        assert_eq!(
            t.menu(c & 0xFFFF),
            Some(MenuId::for_tests(1)),
            "high word 0 names the live object"
        );
        assert_eq!(t.menu(m | 0xFFFF_0000), Some(MenuId::for_tests(1)));
        assert_eq!(
            t.menu(m + 0x1_0000),
            None,
            "a count ahead of the slot's names nothing"
        );
        assert_eq!(t.object(0), None);
        assert_eq!(t.object(0xFFFF_0000), None, "slot 0 holds nothing");
        assert_eq!(t.object(0xFFFF_FFFF), None, "a slot never made");
        assert_eq!(t.object(0x0001_0005), None, "a made slot never used");
        assert_eq!(
            t.close(m & 0xFFFF),
            Some(MENU),
            "a wildcard closes the live object"
        );
        assert_eq!(t.menu(m), None);
        assert_eq!(t.live(), 0);
    }

    /// A window takes an even slot, every other kind an odd one: a menu made after a window's
    /// destruction leaves its slot, and a window after a menu's; the other kinds take an even slot
    /// once no odd one is left. The slot freed last of a lane goes first.
    #[test]
    fn windows_take_the_even_slots() {
        let mut t = handles();
        let w = put(&mut t, WINDOW);
        assert_eq!(w, 0x1_0002);
        t.close(w);
        let m = put(&mut t, MENU);
        assert_eq!(m, 0x1_0001, "a fresh odd slot, the window's left");
        t.close(m);
        assert_eq!(
            put(&mut t, WINDOW),
            w + 0x1_0000,
            "the window's, not the menu's"
        );
        assert_eq!(put(&mut t, CURSOR), m + 0x1_0000, "the menu's");
        let (a, b) = (put(&mut t, MENU), put(&mut t, MENU));
        t.close(a);
        t.close(b);
        assert_eq!(put(&mut t, MENU), b + 0x1_0000, "the one freed last first");
        assert_eq!(put(&mut t, MENU), a + 0x1_0000);
        let mut odd = 0;
        loop {
            let h = put(&mut t, MENU);
            if h & 1 == 0 {
                assert_eq!(h, 0x1_0004, "an even slot once no odd one is left");
                break;
            }
            odd += 1;
        }
        assert_eq!(
            odd,
            0x8000 - 3,
            "the odd slots 1..=0xFFFF, three taken before"
        );
        assert_eq!(t.object(0x1_FFFF), Some(MENU), "the last odd slot, 0xFFFF");
    }

    /// The table has no cap but the 16-bit low word: 2,000 windows (past the 1,024 slots it had)
    /// take distinct even low words, each naming its own; once every even slot is taken, a window
    /// gets no handle while a menu still does.
    #[test]
    #[cfg_attr(miri, ignore)]
    fn windows_go_past_the_old_cap_to_the_low_word() {
        let mut t = handles();
        let windows: Vec<u32> = (0..2000).map(|_| put(&mut t, WINDOW)).collect();
        assert!(windows
            .iter()
            .all(|&h| h != 0 && h & 1 == 0 && h >> 16 == 1));
        let lows: std::collections::BTreeSet<u32> = windows.iter().map(|h| h & 0xFFFF).collect();
        assert_eq!(lows.len(), 2000);
        assert!(windows.iter().all(|&h| t.window(h)
            == Some(match WINDOW {
                UserObject::Window(e) => e,
                _ => unreachable!(),
            })));
        let mut more = 2000;
        while put(&mut t, WINDOW) != 0 {
            more += 1;
        }
        assert_eq!(more, 0x7FFF, "the even slots 2..=0xFFFE");
        assert_eq!(
            t.insert(None, WINDOW),
            Err(Refusal::NoMoreUserHandles),
            "the ceiling is ERROR_NO_MORE_USER_HANDLES"
        );
        assert_eq!(t.object(0x1_FFFE), Some(WINDOW));
        assert_eq!(put(&mut t, MENU), 0x1_0001, "the odd lane still has room");
        assert_eq!(t.live(), 0x8000);
    }

    /// A slot made and destroyed 65,540 times keeps its low word; its count runs 1..=0xFFFE and
    /// wraps to 1, never 0 or the wildcard 0xFFFF, the closed 0xFFFE handle naming nothing (what
    /// `manywin`'s `wrap` predicts: 0xFFFD, 0xFFFE, then 0x0001, 0x0002).
    #[test]
    #[cfg_attr(miri, ignore)]
    fn the_count_wraps_from_0xfffe_to_1() {
        let mut t = handles();
        let first = put(&mut t, MENU);
        let mut highs = std::vec![first >> 16];
        let mut last = first;
        for _ in 0..65_540 {
            assert_eq!(t.close(last), Some(MENU));
            last = put(&mut t, MENU);
            assert_eq!(last & 0xFFFF, first & 0xFFFF, "the same slot every round");
            highs.push(last >> 16);
        }
        assert!(highs.iter().all(|&h| h != 0 && h != 0xFFFF));
        let turn = highs.iter().position(|&h| h == 0xFFFE).unwrap();
        assert_eq!(highs[turn - 1..turn + 3], [0xFFFD, 0xFFFE, 1, 2]);
        let stale = (first & 0xFFFF) | 0xFFFE_0000;
        assert_eq!(
            t.menu(stale),
            None,
            "the closed 0xFFFE handle names nothing"
        );
        assert_eq!(t.menu(last), Some(MenuId::for_tests(1)));
    }

    /// A handle table that finds no page for a chunk hands out no handle, and is as it was: the
    /// live handles still name their objects and the next insert with pages succeeds.
    #[test]
    fn no_page_no_handle() {
        let mut t = handles();
        test_pages::budget(0);
        assert_eq!(t.insert(None, MENU), Err(Refusal::NoMemory));
        assert_eq!(t.insert(None, WINDOW), Err(Refusal::NoMemory));
        assert_eq!(
            t.insert(Some(P), MENU),
            Err(Refusal::NoMemory),
            "no page for the process's record"
        );
        test_pages::unlimited();
        let m = put(&mut t, MENU);
        assert_eq!(m, 0x1_0001);
        assert_eq!(t.menu(m), Some(MenuId::for_tests(1)));
    }

    /// A process's teardown closes every handle it held: the table is left with none live, every
    /// closed handle names nothing, and the slots go to the next objects, counts moved on.
    #[test]
    fn teardown_closes_every_handle() {
        let mut t = handles();
        let held: Vec<u32> = (0..1500)
            .map(|i| put(&mut t, if i % 3 == 0 { WINDOW } else { MENU }))
            .collect();
        assert_eq!(t.live(), 1500);
        for &h in &held {
            assert!(t.close(h).is_some());
        }
        assert_eq!(t.live(), 0);
        assert!(held.iter().all(|&h| t.object(h).is_none()));
        let w = put(&mut t, WINDOW);
        let last_window = *held.iter().rev().find(|&&h| h & 1 == 0).unwrap();
        assert_eq!(w, last_window + 0x1_0000, "the window slot closed last");
    }

    const P: Owner = 5;
    const Q: Owner = 6;

    /// Each object counts against its process from its insert to its close, whatever its kind;
    /// another process's count is its own, and the window manager's own objects count against
    /// none.
    #[test]
    fn objects_count_against_their_process() {
        let mut t = handles();
        let m = t.insert(Some(P), MENU).unwrap();
        let w = t.insert(Some(P), WINDOW).unwrap();
        let c = t.insert(Some(Q), CURSOR).unwrap();
        t.insert(None, MENU).unwrap();
        t.insert(Some(SYSTEM_OWNER), WINDOW).unwrap();
        assert_eq!((t.user_objects(P), t.user_objects(Q)), (2, 1));
        assert_eq!(
            t.user_objects(SYSTEM_OWNER),
            0,
            "the window manager's own count nowhere"
        );
        assert_eq!(t.close(m), Some(MENU));
        assert_eq!(t.user_objects(P), 1);
        assert_eq!(t.close(m), None);
        assert_eq!(
            t.user_objects(P),
            1,
            "a closed handle gives nothing back twice"
        );
        t.close(w);
        t.close(c);
        assert_eq!((t.user_objects(P), t.user_objects(Q)), (0, 0));
        assert_eq!(t.live(), 2);
    }

    /// `manywin`'s `quota`: a process makes 10,000 objects, then its next is refused with
    /// ERROR_NO_MORE_USER_HANDLES and takes no slot; one closed, the next is made and the one after
    /// refused again. Another process is not held back, and every close gives the count back.
    #[test]
    #[cfg_attr(miri, ignore)]
    fn the_quota_refuses_the_10001st_object() {
        let mut t = handles();
        let mut made = Vec::new();
        let refusal = loop {
            match t.insert(Some(P), MENU) {
                Ok(handle) => made.push(handle),
                Err(refusal) => break refusal,
            }
            assert!(made.len() <= 70_000, "no quota");
        };
        assert_eq!(made.len(), 10_000);
        assert_eq!(refusal, Refusal::NoMoreUserHandles);
        assert_eq!(rtl::status::dos_error(refusal.status().0), 1158);
        assert_eq!(t.user_objects(P), 10_000);
        assert_eq!(t.live(), 10_000, "the refused insert took no slot");
        assert_eq!(
            t.insert(Some(P), WINDOW),
            Err(Refusal::NoMoreUserHandles),
            "every kind counts against the one quota"
        );
        let last = made.pop().unwrap();
        assert_eq!(t.close(last), Some(MENU));
        let again = t.insert(Some(P), MENU).unwrap();
        assert_eq!(again, last + 0x1_0000, "the slot just freed");
        made.push(again);
        assert_eq!(t.insert(Some(P), MENU), Err(Refusal::NoMoreUserHandles));
        assert!(
            t.insert(Some(Q), MENU).is_ok(),
            "another process's quota is its own"
        );
        assert!(
            t.insert(None, MENU).is_ok(),
            "the window manager's own objects have none"
        );
        for &handle in &made {
            assert_eq!(t.close(handle), Some(MENU));
        }
        assert_eq!(t.user_objects(P), 0, "every object given back");
        assert!(t.insert(Some(P), MENU).is_ok());
    }

    /// A process's end gives its count back: its objects' handles closed, its record starts
    /// afresh. An object whose handle another holder keeps open (a zombie window) is charged to no
    /// process from then on, so its close takes nothing from the next process at the index.
    #[test]
    fn a_process_end_gives_its_count_back() {
        let mut t = handles();
        let held: Vec<u32> = (0..30)
            .map(|i| {
                t.insert(Some(P), if i % 3 == 0 { WINDOW } else { MENU })
                    .unwrap()
            })
            .collect();
        let other = t.insert(Some(Q), MENU).unwrap();
        assert_eq!(t.user_objects(P), 30);
        let (zombie, rest) = held.split_first().unwrap();
        for &handle in rest {
            t.close(handle);
        }
        assert_eq!(t.user_objects(P), 1);
        t.end_process(P);
        assert_eq!(t.user_objects(P), 0);
        assert_eq!(t.user_objects(Q), 1, "another process keeps its count");
        let next = t.insert(Some(P), MENU).unwrap();
        assert_eq!(
            t.user_objects(P),
            1,
            "the next process at the index starts at 0"
        );
        assert_eq!(t.close(*zombie), Some(WINDOW));
        assert_eq!(
            t.user_objects(P),
            1,
            "the zombie's close is charged to nobody"
        );
        t.close(next);
        t.close(other);
        assert_eq!((t.user_objects(P), t.user_objects(Q)), (0, 0));
    }
}
