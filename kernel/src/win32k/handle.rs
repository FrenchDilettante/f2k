//! The user handle table: the one table every user object's handle names a slot of — windows,
//! menus, accelerator tables, cursors and icons — as Windows 2000's window manager keeps one
//! table (its handle entries) for every kind of its objects.
//!
//! An entry is typed: it names a window, a menu, an accelerator table or a cursor/icon, by its
//! record's id in that kind's pool ([`UserObject`]); the records themselves stay in their kinds'
//! pools ([`super::window`], [`super::menu`], [`super::accel`], [`super::icon`]). A handle holds
//! its slot in the low word (the slot's index shifted left two, the shape of F2K's handle tables,
//! [`crate::sched::object`]) and the slot's uniqueness count in the high word, which moves on by
//! one each time the slot's handle is closed, so a destroyed object's handle names nothing once
//! its slot names another. A slot's first handle has a count of 0, the table's own value.
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
//! - **Every other kind takes an odd slot,** while one is free or the table has one never used,
//!   and an even one only once none is left: the window slots are kept for windows.
//! - **Among the slots a kind may take, the one freed last goes first,** then one never used,
//!   lowest first.
//!
//! The menus capture shows each of these: a window made after a window's destruction takes its
//! slot, its high word one more, and so does a table after a menu's; a menu or an icon made after
//! a window's destruction takes another slot, and so does a window after a menu's or an icon's.
//! The parity is the index's, F2K's handles being the index shifted left two (every low word is
//! even, a window's or not).
//!
//! Seams recorded: Windows 2000's table has more kinds — hooks, the clipboard's data objects,
//! window positions (BeginDeferWindowPos), DDE objects, keyboard layouts, monitors and others.
//! F2K has no hooks or deferred positions yet, and its clipboard's data objects never reach an
//! application (user32 copies their bytes into a memory block of its own), so they keep their
//! own numbers.

use super::accel::TableId;
use super::icon::CursorId;
use super::menu::MenuId;
use super::window::WindowEntry;
use crate::sched::object::{HANDLE_SHIFT, HANDLE_SLOTS};

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

/// A handle's high word that names whatever object its slot holds, besides 0.
const ANY_UNIQ: u16 = 0xFFFF;

/// The user handle table: the slots, each slot's uniqueness count, the freed slots and the next
/// slots of either parity never used. Slot 0 is never handed out, so no handle is 0.
pub struct UserHandles {
    slots: [Option<UserObject>; HANDLE_SLOTS],
    uniq: [u16; HANDLE_SLOTS],
    /// The freed slots, the most recently freed last.
    freed: [u16; HANDLE_SLOTS],
    freed_count: usize,
    /// The next even and odd slots never used.
    fresh: [usize; 2],
}

impl UserHandles {
    /// Write an empty table at `handles`, field by field.
    ///
    /// # Safety
    ///
    /// `handles` is valid for writes and aligned; its previous contents are overwritten, not
    /// dropped.
    pub unsafe fn write_empty(handles: *mut UserHandles) {
        use core::ptr::addr_of_mut;
        // SAFETY: the caller's contract; every field is written, the arrays element by element.
        unsafe {
            let slots = addr_of_mut!((*handles).slots) as *mut Option<UserObject>;
            let uniq = addr_of_mut!((*handles).uniq) as *mut u16;
            let freed = addr_of_mut!((*handles).freed) as *mut u16;
            for index in 0..HANDLE_SLOTS {
                slots.add(index).write(None);
                uniq.add(index).write(0);
                freed.add(index).write(0);
            }
            addr_of_mut!((*handles).freed_count).write(0);
            addr_of_mut!((*handles).fresh).write([2, 1]);
        }
    }

    /// Whether every slot is taken: the next insert would hand out no handle.
    pub fn is_full(&self) -> bool {
        self.freed_count == 0 && self.fresh.iter().all(|&next| next >= HANDLE_SLOTS)
    }

    /// The slot of the parity `parity` (0 even, 1 odd) the next object of it takes, taken off the
    /// freed slots or the fresh ones; none when neither has one.
    fn take(&mut self, parity: usize) -> Option<usize> {
        let freed = &self.freed[..self.freed_count];
        if let Some(at) = freed.iter().rposition(|&index| index as usize % 2 == parity) {
            let index = self.freed[at] as usize;
            self.freed.copy_within(at + 1..self.freed_count, at);
            self.freed_count -= 1;
            return Some(index);
        }
        let next = self.fresh[parity];
        (next < HANDLE_SLOTS).then(|| {
            self.fresh[parity] = next + 2;
            next
        })
    }

    /// Insert `object`: its handle, 0 when no slot its kind may take is free (a window takes an
    /// even slot, any other kind an odd one, or an even one once no odd one is left).
    pub fn insert(&mut self, object: UserObject) -> u32 {
        let index = match object {
            UserObject::Window(_) => self.take(0),
            _ => self.take(1).or_else(|| self.take(0)),
        };
        let Some(index) = index else {
            return 0;
        };
        self.slots[index] = Some(object);
        (index as u32) << HANDLE_SHIFT | (self.uniq[index] as u32) << 16
    }

    /// The index of `handle`'s slot, when its high word is the slot's count or a wildcard.
    fn slot(&self, handle: u32) -> Option<usize> {
        let index = ((handle & 0xFFFF) >> HANDLE_SHIFT) as usize;
        let high = (handle >> 16) as u16;
        let uniq = *self.uniq.get(index)?;
        (index != 0 && (high == uniq || high == 0 || high == ANY_UNIQ)).then_some(index)
    }

    /// The object `handle` names, of whatever kind.
    pub fn object(&self, handle: u32) -> Option<UserObject> {
        self.slots[self.slot(handle)?]
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
        let Some(index) = self.slot(handle) else {
            return false;
        };
        match self.slots[index] {
            Some(UserObject::Window(entry)) => {
                self.slots[index] = Some(UserObject::Window(change(entry)));
                true
            }
            _ => false,
        }
    }

    /// Close `handle`, its slot's count moved on (kept to 15 bits: a handle stays positive, and
    /// never reaches the wildcard 0xFFFF); what it named.
    pub fn close(&mut self, handle: u32) -> Option<UserObject> {
        let index = self.slot(handle)?;
        let object = self.slots[index].take()?;
        self.uniq[index] = self.uniq[index].wrapping_add(1) & 0x7FFF;
        self.freed[self.freed_count] = index as u16;
        self.freed_count += 1;
        Some(object)
    }
}

#[cfg(test)]
mod tests {
    //! The table's host tests: the kinds share the slots, a lookup checks the kind and the count,
    //! and the wildcards.

    use std::boxed::Box;

    use super::*;

    fn handles() -> Box<UserHandles> {
        let mut handles = Box::<UserHandles>::new_uninit();
        // SAFETY: the box is valid and aligned.
        unsafe { UserHandles::write_empty(handles.as_mut_ptr()) };
        // SAFETY: written whole just above.
        unsafe { handles.assume_init() }
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
    /// Each kind's lookup finds its own kind only.
    #[test]
    fn kinds_share_the_slots_and_lookups_check_the_kind() {
        let mut t = handles();
        let m = t.insert(MENU);
        let c = t.insert(CURSOR);
        assert_eq!((m, c), (4, 12), "odd slots, a slot's first handle a count of 0");
        assert!(t.menu(m).is_some() && t.cursor(m).is_none() && t.window(m).is_none());
        assert!(t.cursor(c).is_some() && t.menu(c).is_none());
        assert!(t.accelerator_table(m).is_none());
        assert!(!t.update_window(m, |e| e), "a menu's entry is no window's");
    }

    /// A slot freed goes to the next object, of any kind, its count one more; the old handle names
    /// nothing, the count one more names nothing yet, and 0 and 0xFFFF name the live object.
    #[test]
    fn reuse_moves_the_count_and_the_wildcards_name_the_live_object() {
        let mut t = handles();
        let c = t.insert(CURSOR);
        assert_eq!(t.close(c), Some(CURSOR));
        assert_eq!(t.close(c), None, "a closed handle closes nothing");
        let m = t.insert(MENU);
        assert_eq!(m, c | 0x1_0000, "the slot just freed, its count one more");
        assert_eq!(t.cursor(c), None);
        assert_eq!(
            t.menu(c),
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
        assert_eq!(
            t.object(0xFFFF_0000 | (HANDLE_SLOTS as u32) << HANDLE_SHIFT),
            None
        );
    }

    /// A window takes an even slot, every other kind an odd one: a menu made after a window's
    /// destruction leaves its slot, and a window after a menu's; the other kinds take an even slot
    /// once no odd one is left.
    #[test]
    fn windows_take_the_even_slots() {
        let mut t = handles();
        let w = t.insert(WINDOW);
        assert_eq!(w, 2 << HANDLE_SHIFT);
        t.close(w);
        let m = t.insert(MENU);
        assert_eq!(m, 1 << HANDLE_SHIFT, "a fresh odd slot, the window's left");
        t.close(m);
        assert_eq!(t.insert(WINDOW), w | 0x1_0000, "the window's, not the menu's");
        assert_eq!(t.insert(CURSOR), m | 0x1_0000, "the menu's");
        let mut odd = 0;
        while t.fresh[1] < HANDLE_SLOTS {
            t.insert(MENU);
            odd += 1;
        }
        assert_eq!(odd, HANDLE_SLOTS / 2 - 1);
        assert_eq!(
            t.insert(MENU),
            4 << HANDLE_SHIFT,
            "an even slot once no odd one is left"
        );
    }
}
