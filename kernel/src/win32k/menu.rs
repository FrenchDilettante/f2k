//! Menus: the menu records behind HMENUs, their items, and the services user32's menu calls come
//! through. Data only: user32 draws the menu bar in the non-client area and runs the keyboard menu
//! loop from these records, as its queries read them (Windows 2000's win32k does both itself).
//!
//! A menu is a record in the menu pool ([`Menus`], a slot pool: [`crate::slots`]), named by an id
//! with a uniqueness count ([`MenuId`]), with a handle into the user handle table
//! ([`super::handle`]). A menu holds its items in order: ids into the item pool (another slot
//! pool), each item its type (MFT_*), its state
//! (MFS_*, the enabling bits MF_GRAYED and MF_DISABLED kept apart, as EnableMenuItem's answer shows
//! them), its command id, the popup it opens (a menu's id: a popup destroyed meanwhile is none),
//! its application data and its text. A menu belongs to the process that made it, and goes at its
//! end.
//!
//! Windows 2000 keeps a menu in the desktop heap, its items an array of the menu's own; F2K's
//! records are fixed-size, so a menu holds at most [`MAX_MENU_ITEMS`] items and an item's text is
//! cut at [`MENU_ITEM_TEXT`] units. The pools grow a chunk of the nonpaged pool at a time, as menus
//! and items are made, and keep their peak; only memory bounds them. They sit in the window
//! registry ([`Windows::menus`]), behind the window manager's lock, as a window's menu is the
//! window record's: setting a menu, destroying it with its window, and destroying a window's menu
//! all hold the one lock. An id a menu was destroyed under, or one naming no slot at all, finds
//! nothing: the calls that take an id answer ERROR_INVALID_MENU_HANDLE (or nothing) for it.
//!
//! An item is named by its position in a menu (MF_BYPOSITION) or by its command (MF_BYCOMMAND):
//! the first item of that id, the menu's items searched in order and a popup's items right after
//! the item that opens it, so an item of a popup is found through the bar ([`Menus::find`]).
//!
//! The services (F2K's argument lists, see [`crate::win32k`]; Windows 2000's numbers):
//!
//! - NtUserCallNoParam (0x1138): CreateMenu and CreatePopupMenu (rtl::user's NO_PARAM_* routines),
//!   the empty cursor object LoadIcon fills in ([`super::icon`]), DestroyCaret ([`super::caret`])
//!   and ReleaseCapture ([`super::focus`]);
//! - NtUserThunkedMenuItemInfo (0x121F): an item inserted (InsertMenuItem) or changed
//!   (SetMenuItemInfo) from a MENUITEMINFOW; and, by an operation of F2K's own, an item or the menu
//!   answered as rtl::menu's MenuItemAnswer — what Windows 2000's user32 reads from the menu's
//!   record, mapped into its process (GetMenuItemCount, GetMenuItemID, GetSubMenu, GetMenuState,
//!   GetMenuString, IsMenu);
//! - NtUserDestroyMenu (0x1158): the menu and its popups destroyed;
//! - NtUserRemoveMenu (0x11D9) and NtUserDeleteMenu (0x1154): an item taken out of its menu, the
//!   popup it opens kept (RemoveMenu) or destroyed (DeleteMenu);
//! - NtUserSetMenuDefaultItem (0x11FB): the menu's default item (MFS_DEFAULT) moved to one item, or
//!   taken off them all;
//! - NtUserGetSystemMenu (0x11A1): a window's own copy of the system menu, which user32 builds
//!   (Windows 2000's win32k loads it from user32's resources by calling back into user mode), the
//!   copy attached to the window, answered, or destroyed (bRevert); it goes with its window;
//! - NtUserCheckMenuItem (0x113E) and NtUserEnableMenuItem (0x1164): the item's check or enabling
//!   changed, its previous one answered;
//! - NtUserSetMenu (0x11F9): a top-level window's menu set (GetMenu reads it through
//!   NtUserQueryWindow's QUERY_WINDOW_MENU).
//!
//! An item's state keeps MFS_DEFAULT and MFS_HILITE through a change of its state
//! (SetMenuItemInfo's MIIM_STATE ORs them in, as the menus fixture's `info` capture shows:
//! MFS_DISABLED set over MFS_CHECKED | MFS_DEFAULT | MFS_HILITE leaves 0x1083); only
//! SetMenuDefaultItem takes the default off. An item that opens a popup and is given another one
//! (or none) destroys the popup it opened, as ModifyMenu documents and the `info` capture shows of
//! SetMenuItemInfo.
//!
//! A failure names the Win32 error code of the decision ([`Failure`]'s variants), which the
//! service answers in a FACILITY_NTWIN32 status ([`Failure::status`]) for user32 to report as is:
//! ERROR_INVALID_WINDOW_HANDLE for a window naming nothing, ERROR_INVALID_MENU_HANDLE for a menu
//! naming nothing, ERROR_MENU_ITEM_NOT_FOUND for no such item.

use rtl::menu::{
    MenuItemAnswer,
    MenuItemInfoW,
    MENU_ITEM_TEXT,
    MFS_DEFAULT,
    MFS_GRAYED,
    MFS_HILITE,
    MFT_SEPARATOR,
    MF_BYPOSITION,
    MF_CHECKED,
    MF_DISABLED,
    MF_GRAYED,
    MIIM_BITMAP,
    MIIM_CHECKMARKS,
    MIIM_DATA,
    MIIM_FTYPE,
    MIIM_ID,
    MIIM_STATE,
    MIIM_STRING,
    MIIM_SUBMENU,
    MIIM_TYPE,
    STATE_BITS,
    TYPE_BITS,
};
use rtl::winerror::{
    ERROR_CHILD_WINDOW_MENU,
    ERROR_INVALID_MENU_HANDLE,
    ERROR_INVALID_WINDOW_HANDLE,
    ERROR_MENU_ITEM_NOT_FOUND,
    ERROR_NOT_ENOUGH_MEMORY,
};

use super::class::Owner;
use super::handle::{UserHandles, UserObject};
use super::window::Windows;
use crate::slots::{Id, KernelId, Record, Slots, KERNEL_PAGES, PAGE};
use crate::status::*;

/// How many items one menu holds.
pub const MAX_MENU_ITEMS: usize = 64;

/// The popups a menu's search and destruction go down at most (a popup inserted into itself would
/// otherwise never end them).
const MAX_DEPTH: u32 = 16;

/// Why a menu operation failed: the Win32 error code (winerror.h) the decision reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    /// ERROR_NOT_ENOUGH_MEMORY (8): the pools could not grow, or the menu holds its most items.
    NotEnoughMemory,
    /// ERROR_INVALID_WINDOW_HANDLE (1400).
    InvalidWindowHandle,
    /// ERROR_INVALID_MENU_HANDLE (1401).
    InvalidMenuHandle,
    /// ERROR_CHILD_WINDOW_MENU (1436): a child window has no menu.
    ChildWindowMenu,
    /// ERROR_MENU_ITEM_NOT_FOUND (1456).
    ItemNotFound,
}

impl Failure {
    /// The Win32 error code (winerror.h) the decision reports.
    pub const fn code(self) -> u32 {
        match self {
            Failure::NotEnoughMemory => ERROR_NOT_ENOUGH_MEMORY,
            Failure::InvalidWindowHandle => ERROR_INVALID_WINDOW_HANDLE,
            Failure::InvalidMenuHandle => ERROR_INVALID_MENU_HANDLE,
            Failure::ChildWindowMenu => ERROR_CHILD_WINDOW_MENU,
            Failure::ItemNotFound => ERROR_MENU_ITEM_NOT_FOUND,
        }
    }

    /// The NTSTATUS the service answers: the Win32 error itself ([`Failure::code`]) in a
    /// FACILITY_NTWIN32 status, which user32 hands to GetLastError as is.
    pub const fn status(self) -> NtStatus {
        NtStatus::from_win32(self.code())
    }
}

/// The menu pool's kind of id.
pub enum MenuTag {}

/// The item pool's kind of id.
pub enum ItemTag {}

/// A menu's id: its slot in the menu pool and the slot's uniqueness count.
pub type MenuId = Id<MenuTag>;

/// An item's id: its slot in the item pool and the slot's uniqueness count.
type ItemId = Id<ItemTag>;

impl MenuId {
    /// The id of the slot `index`, its first count (the handle table's tests).
    #[cfg(test)]
    pub const fn for_tests(index: u16) -> Self {
        Id::new(index, 1)
    }
}

/// Menu records to a chunk: one page's worth, a slot being its record and 8 bytes.
const MENUS_PER_CHUNK: usize = PAGE / (core::mem::size_of::<MenuRecord>() + 8);
/// Items to a chunk: four pages' worth.
const ITEMS_PER_CHUNK: usize = 4 * PAGE / (core::mem::size_of::<Item>() + 8);

// Measured (272-byte menus, 164-byte items); the records hold no pointer, so these are the target's
// and the host's alike.
const _: () = assert!(MENUS_PER_CHUNK == 14 && ITEMS_PER_CHUNK == 95);
const _: () = assert!(Slots::<MenuRecord, KernelId<MenuTag>, MENUS_PER_CHUNK>::CHUNK_PAGES == 1);
const _: () = assert!(Slots::<Item, KernelId<ItemTag>, ITEMS_PER_CHUNK>::CHUNK_PAGES == 4);

/// An item, as a call names it: by position in a menu, or by command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ItemRef {
    Position(u32),
    Command(u32),
}

impl ItemRef {
    /// The item a call's `item` and flags name (MF_BYPOSITION or MF_BYCOMMAND).
    pub fn of(item: u32, flags: u32) -> Self {
        if flags & MF_BYPOSITION != 0 {
            ItemRef::Position(item)
        } else {
            ItemRef::Command(item)
        }
    }
}

/// An item's fields as an insertion or a change gives them: a MENUITEMINFOW read, its text copied.
#[derive(Clone, Copy, Debug)]
pub struct ItemInfo<'a> {
    pub mask: u32,
    pub item_type: u32,
    pub state: u32,
    pub id: u32,
    /// The popup's handle (0 for none).
    pub submenu: u32,
    pub item_data: u32,
    /// The check marks' bitmaps (MIIM_CHECKMARKS) and the item's bitmap (MIIM_BITMAP).
    pub checked: u32,
    pub unchecked: u32,
    pub bitmap: u32,
    pub text: &'a [u16],
}

impl<'a> ItemInfo<'a> {
    /// The fields of `info`, its text `text`.
    pub fn of(info: &MenuItemInfoW, text: &'a [u16]) -> Self {
        ItemInfo {
            mask: info.mask,
            item_type: info.item_type,
            state: info.state,
            id: info.id,
            submenu: info.submenu,
            item_data: info.item_data,
            checked: info.checked,
            unchecked: info.unchecked,
            bitmap: info.bitmap,
            text,
        }
    }
}

/// One menu's record.
struct MenuRecord {
    handle: u32,
    owner: Owner,
    /// Set while the menu's destruction goes down its popups: a popup opening one of its own
    /// ancestors ends there.
    destroying: bool,
    /// The window whose system menu this menu is (its handle; 0 for none).
    system_of: u32,
    count: u16,
    /// The items, by position: ids into the item pool.
    items: [ItemId; MAX_MENU_ITEMS],
}

impl MenuRecord {
    const EMPTY: Self = MenuRecord {
        handle: 0,
        owner: 0,
        destroying: false,
        system_of: 0,
        count: 0,
        items: [Id::new(0, 0); MAX_MENU_ITEMS],
    };
}

// SAFETY: `write_fresh` writes a whole record.
unsafe impl Record for MenuRecord {
    unsafe fn write_fresh(at: *mut Self, _: u32) {
        // SAFETY: the caller's contract.
        unsafe { at.write(Self::EMPTY) };
    }
}

/// One item's record.
struct Item {
    item_type: u32,
    state: u32,
    id: u32,
    submenu: Option<MenuId>,
    item_data: u32,
    checked: u32,
    unchecked: u32,
    bitmap: u32,
    text_length: u8,
    text: [u16; MENU_ITEM_TEXT],
}

impl Item {
    const EMPTY: Self = Item {
        item_type: 0,
        state: 0,
        id: 0,
        submenu: None,
        item_data: 0,
        checked: 0,
        unchecked: 0,
        bitmap: 0,
        text_length: 0,
        text: [0; MENU_ITEM_TEXT],
    };
}

// SAFETY: `write_fresh` writes a whole record.
unsafe impl Record for Item {
    unsafe fn write_fresh(at: *mut Self, _: u32) {
        // SAFETY: the caller's contract.
        unsafe { at.write(Self::EMPTY) };
    }
}

/// The menu registry: the menu pool and the item pool. Their handles are the user handle table's
/// ([`UserHandles`], the window registry's), which the calls that make, find or destroy a menu are
/// lent.
pub struct Menus {
    menus: Slots<MenuRecord, KernelId<MenuTag>, MENUS_PER_CHUNK>,
    items: Slots<Item, KernelId<ItemTag>, ITEMS_PER_CHUNK>,
}

impl Menus {
    /// An empty registry: no menu, no chunk made.
    pub const fn new() -> Self {
        Menus {
            menus: Slots::new(),
            items: Slots::new(),
        }
    }

    /// Write an empty registry at `menus`.
    ///
    /// # Safety
    ///
    /// `menus` is valid for writes and aligned; its previous contents are overwritten, not
    /// dropped.
    pub unsafe fn write_empty(menus: *mut Menus) {
        // SAFETY: the caller's contract.
        unsafe { menus.write(Self::new()) };
    }

    /// The live menu `id` names; none for a destroyed or forged id.
    fn at(&self, id: MenuId) -> Option<&MenuRecord> {
        self.menus.get(id)
    }

    fn at_mut(&mut self, id: MenuId) -> Option<&mut MenuRecord> {
        self.menus.get_mut(id)
    }

    /// The live menu `id` names, or ERROR_INVALID_MENU_HANDLE.
    fn record(&self, id: MenuId) -> Result<&MenuRecord, Failure> {
        self.at(id).ok_or(Failure::InvalidMenuHandle)
    }

    fn is_live(&self, id: MenuId) -> bool {
        self.at(id).is_some()
    }

    /// The item at `position` of `menu`, when `menu` is live and holds one there.
    fn item(&self, menu: MenuId, position: usize) -> Option<&Item> {
        let record = self.at(menu)?;
        let id = *record.items[..record.count as usize].get(position)?;
        self.items.get(id)
    }

    fn item_mut(&mut self, menu: MenuId, position: usize) -> Option<&mut Item> {
        let record = self.menus.get(menu)?;
        let id = *record.items[..record.count as usize].get(position)?;
        self.items.get_mut(id)
    }

    /// A new menu of the process `owner`; its handle. A popup (CreatePopupMenu's) and a menu bar
    /// (CreateMenu's) are the same record until the menu bar's drawing and the menus' tracking
    /// tell them apart.
    pub fn create(&mut self, handles: &mut UserHandles, owner: Owner) -> Result<u32, Failure> {
        let (id, record) = self
            .menus
            .allocate_or_grow(0, &KERNEL_PAGES)
            .map_err(|_| Failure::NotEnoughMemory)?;
        let handle = handles.insert(UserObject::Menu(id));
        if handle == 0 {
            self.menus.free(id);
            return Err(Failure::NotEnoughMemory);
        }
        record.handle = handle;
        record.owner = owner;
        record.destroying = false;
        record.system_of = 0;
        record.count = 0;
        Ok(handle)
    }

    /// The menu `handle` names in `handles`, when it is live; ERROR_INVALID_MENU_HANDLE
    /// otherwise (another kind's handle among them).
    pub fn menu_of(&self, handles: &UserHandles, handle: u32) -> Result<MenuId, Failure> {
        match handles.menu(handle) {
            Some(id) if self.is_live(id) => Ok(id),
            _ => Err(Failure::InvalidMenuHandle),
        }
    }

    /// The handle of `id` (0 when it names no live menu).
    pub fn handle_of(&self, id: MenuId) -> u32 {
        self.at(id).map_or(0, |record| record.handle)
    }

    /// How many items `menu` holds (none when it names no live menu).
    pub fn count(&self, menu: MenuId) -> usize {
        self.at(menu).map_or(0, |record| record.count as usize)
    }

    /// The popup the item at `position` of `menu` opens, when it is still live.
    fn submenu(&self, menu: MenuId, position: usize) -> Option<MenuId> {
        self.item(menu, position)?
            .submenu
            .filter(|&sub| self.is_live(sub))
    }

    /// The item `item` names in `menu`: the menu holding it and its position there. By position,
    /// an item of `menu` itself; by command, the first item of the id, a popup's items searched
    /// right after the item that opens it. None for a menu naming nothing.
    pub fn find(&self, menu: MenuId, item: ItemRef) -> Option<(MenuId, usize)> {
        match item {
            ItemRef::Position(position) => {
                ((position as usize) < self.count(menu)).then_some((menu, position as usize))
            }
            ItemRef::Command(id) => self.find_command(menu, id, 0),
        }
    }

    fn find_command(&self, menu: MenuId, id: u32, depth: u32) -> Option<(MenuId, usize)> {
        if depth > MAX_DEPTH {
            return None;
        }
        for position in 0..self.count(menu) {
            if self.item(menu, position)?.id == id {
                return Some((menu, position));
            }
            if let Some(sub) = self.submenu(menu, position) {
                if let Some(found) = self.find_command(sub, id, depth + 1) {
                    return Some(found);
                }
            }
        }
        None
    }

    /// The position, in the menu holding it, of the item that opens `popup`, searched from `menu`
    /// down: WM_INITMENUPOPUP's index.
    pub fn position_in(&self, menu: MenuId, popup: MenuId) -> Option<usize> {
        self.position_at(menu, popup, 0)
    }

    fn position_at(&self, menu: MenuId, popup: MenuId, depth: u32) -> Option<usize> {
        if depth > MAX_DEPTH {
            return None;
        }
        for position in 0..self.count(menu) {
            if let Some(sub) = self.submenu(menu, position) {
                if sub == popup {
                    return Some(position);
                }
                if let Some(found) = self.position_at(sub, popup, depth + 1) {
                    return Some(found);
                }
            }
        }
        None
    }

    /// Insert an item into `menu` before the one `before` names (by position, at the end when the
    /// position is past it; by command, in the menu holding that item, and at `menu`'s end when no
    /// item has the command, as the menus fixture's `edit` and `insitem` captures show):
    /// InsertMenuItem. A separator is grayed, as Windows 2000's are; a popup must be a live menu.
    pub fn insert(
        &mut self,
        handles: &UserHandles,
        menu: MenuId,
        before: ItemRef,
        info: &ItemInfo<'_>,
    ) -> Result<(), Failure> {
        let count = self.record(menu)?.count as usize;
        let (holder, position) = match before {
            ItemRef::Position(position) => (menu, (position as usize).min(count)),
            ItemRef::Command(_) => self.find(menu, before).unwrap_or((menu, count)),
        };
        let submenu = self.submenu_of(handles, info)?;
        let record = self
            .menus
            .get_mut(holder)
            .ok_or(Failure::InvalidMenuHandle)?;
        let count = record.count as usize;
        if count >= MAX_MENU_ITEMS {
            return Err(Failure::NotEnoughMemory);
        }
        let (id, item) = self
            .items
            .allocate_or_grow(0, &KERNEL_PAGES)
            .map_err(|_| Failure::NotEnoughMemory)?;
        *item = Item::EMPTY;
        apply(item, info, submenu);
        if item.item_type & MFT_SEPARATOR != 0 {
            item.state |= MFS_GRAYED;
        }
        record.items.copy_within(position..count, position + 1);
        record.items[position] = id;
        record.count += 1;
        Ok(())
    }

    /// Change the fields the mask names of the item `item` names: SetMenuItemInfo. The popup the
    /// item opened, when a new one (or none) takes its place: the caller destroys it.
    pub fn set(
        &mut self,
        handles: &UserHandles,
        menu: MenuId,
        item: ItemRef,
        info: &ItemInfo<'_>,
    ) -> Result<Option<MenuId>, Failure> {
        self.record(menu)?;
        let (holder, position) = self.find(menu, item).ok_or(Failure::ItemNotFound)?;
        let submenu = self.submenu_of(handles, info)?;
        let previous = self.submenu(holder, position);
        let target = self
            .item_mut(holder, position)
            .ok_or(Failure::ItemNotFound)?;
        apply(target, info, submenu);
        Ok(previous.filter(|&old| info.mask & MIIM_SUBMENU != 0 && Some(old) != submenu))
    }

    /// Take the item `item` names out of the menu holding it (RemoveMenu, DeleteMenu): the popup
    /// it opened, which the caller keeps or destroys.
    pub fn remove(&mut self, menu: MenuId, item: ItemRef) -> Result<Option<MenuId>, Failure> {
        self.record(menu)?;
        let (holder, position) = self.find(menu, item).ok_or(Failure::ItemNotFound)?;
        let popup = self.submenu(holder, position);
        let record = self
            .menus
            .get_mut(holder)
            .ok_or(Failure::InvalidMenuHandle)?;
        let count = record.count as usize;
        let id = record.items[position];
        record.items.copy_within(position + 1..count, position);
        record.count -= 1;
        self.items.free(id);
        Ok(popup)
    }

    /// SetMenuDefaultItem: MFS_DEFAULT taken off every item of `menu` and given to the one `item`
    /// names in `menu` itself (by command too: a popup's items are not searched); u32::MAX takes it
    /// off them all. No such item, or a separator, is ERROR_MENU_ITEM_NOT_FOUND, nothing changed
    /// (Windows 2000 fails it without a last error, as the menus fixture's `default` capture
    /// shows).
    pub fn set_default(
        &mut self,
        menu: MenuId,
        item: u32,
        by_position: bool,
    ) -> Result<(), Failure> {
        let count = self.record(menu)?.count as usize;
        let target = if item == u32::MAX {
            None
        } else {
            let position = if by_position {
                ((item as usize) < count).then_some(item as usize)
            } else {
                (0..count).find(|&position| self.item(menu, position).is_some_and(|i| i.id == item))
            };
            let position = position.ok_or(Failure::ItemNotFound)?;
            let found = self.item(menu, position).ok_or(Failure::ItemNotFound)?;
            if found.item_type & MFT_SEPARATOR != 0 {
                return Err(Failure::ItemNotFound);
            }
            Some(position)
        };
        for position in 0..count {
            if let Some(item) = self.item_mut(menu, position) {
                if Some(position) == target {
                    item.state |= MFS_DEFAULT;
                } else {
                    item.state &= !MFS_DEFAULT;
                }
            }
        }
        Ok(())
    }

    /// The system menu of the window `window` (its handle), when it has one.
    pub fn system_menu_of(&self, window: u32) -> Option<MenuId> {
        if window == 0 {
            return None;
        }
        self.menus
            .iter()
            .find(|(_, record)| record.system_of == window)
            .map(|(id, _)| id)
    }

    /// The popup an insertion or a change names, when its mask names one: a live menu, or none.
    fn submenu_of(
        &self,
        handles: &UserHandles,
        info: &ItemInfo<'_>,
    ) -> Result<Option<MenuId>, Failure> {
        if info.mask & MIIM_SUBMENU == 0 || info.submenu == 0 {
            return Ok(None);
        }
        self.menu_of(handles, info.submenu).map(Some)
    }

    /// The menu itself, as F2K's menu query answers it: its item count.
    pub fn query_menu(&self, menu: MenuId) -> MenuItemAnswer {
        MenuItemAnswer {
            count: self.count(menu) as u32,
            holder: self.handle_of(menu),
            ..MenuItemAnswer::EMPTY
        }
    }

    /// The item `item` names, as F2K's menu query answers it.
    pub fn query_item(&self, menu: MenuId, item: ItemRef) -> Result<MenuItemAnswer, Failure> {
        self.record(menu)?;
        let (holder, position) = self.find(menu, item).ok_or(Failure::ItemNotFound)?;
        let record = self.item(holder, position).ok_or(Failure::ItemNotFound)?;
        let submenu = self.submenu(holder, position);
        let mut answer = MenuItemAnswer {
            count: self.count(holder) as u32,
            holder: self.handle_of(holder),
            position: position as u32,
            item_type: record.item_type,
            state: record.state,
            id: record.id,
            submenu: submenu.map_or(0, |sub| self.handle_of(sub)),
            submenu_count: submenu.map_or(0, |sub| self.count(sub) as u32),
            item_data: record.item_data,
            checked: record.checked,
            unchecked: record.unchecked,
            bitmap: record.bitmap,
            text_length: u32::from(record.text_length),
            text: [0; MENU_ITEM_TEXT],
        };
        answer.text = record.text;
        Ok(answer)
    }

    /// The item `item` names, to change: ERROR_INVALID_MENU_HANDLE for a menu naming nothing,
    /// ERROR_MENU_ITEM_NOT_FOUND for no such item.
    fn found_mut(&mut self, menu: MenuId, item: ItemRef) -> Result<&mut Item, Failure> {
        self.record(menu)?;
        let (holder, position) = self.find(menu, item).ok_or(Failure::ItemNotFound)?;
        self.item_mut(holder, position).ok_or(Failure::ItemNotFound)
    }

    /// CheckMenuItem: the item's check set or cleared (MF_CHECKED in `flags`); its previous check
    /// (MF_CHECKED or 0).
    pub fn check(&mut self, menu: MenuId, item: ItemRef, flags: u32) -> Result<u32, Failure> {
        let item = self.found_mut(menu, item)?;
        let previous = item.state & MF_CHECKED;
        item.state = item.state & !MF_CHECKED | flags & MF_CHECKED;
        Ok(previous)
    }

    /// EnableMenuItem: the item's MF_GRAYED and MF_DISABLED bits set to `flags`'; its previous
    /// ones.
    pub fn enable(&mut self, menu: MenuId, item: ItemRef, flags: u32) -> Result<u32, Failure> {
        let item = self.found_mut(menu, item)?;
        let bits = MF_GRAYED | MF_DISABLED;
        let previous = item.state & bits;
        item.state = item.state & !bits | flags & bits;
        Ok(previous)
    }

    /// Destroy `menu` and the popups its items open, their items with them: DestroyMenu, which
    /// Windows documents as recursive. Nothing for a menu naming nothing.
    pub fn destroy(&mut self, handles: &mut UserHandles, menu: MenuId) {
        self.destroy_at(handles, menu, 0);
    }

    fn destroy_at(&mut self, handles: &mut UserHandles, menu: MenuId, depth: u32) {
        // The record is read in place, not copied: a copy per popup level would cross the stack.
        let Some(record) = self.menus.get_mut(menu) else {
            return;
        };
        if record.destroying {
            return;
        }
        record.destroying = true;
        let count = record.count as usize;
        handles.close(record.handle);
        for position in 0..count {
            let Some(record) = self.menus.get(menu) else {
                break;
            };
            let id = record.items[position];
            let sub = self.items.get(id).and_then(|item| item.submenu);
            self.items.free(id);
            if let Some(sub) = sub {
                if depth < MAX_DEPTH {
                    self.destroy_at(handles, sub, depth + 1);
                }
            }
        }
        self.menus.free(menu);
    }

    /// Destroy every menu of the process `owner`, at its end.
    pub fn destroy_owner(&mut self, handles: &mut UserHandles, owner: Owner) {
        let mut from = 0;
        loop {
            let next = self
                .menus
                .iter()
                .find(|(id, record)| id.index >= from && record.owner == owner)
                .map(|(id, _)| id);
            let Some(id) = next else {
                break;
            };
            self.destroy(handles, id);
            from = id.index;
        }
    }

    /// How many menus are live.
    pub fn live(&self) -> usize {
        self.menus.live() as usize
    }
}

/// Set `item`'s fields as `info`'s mask names them (MIIM_TYPE the type and the text, MIIM_FTYPE
/// the type alone, MIIM_STRING the text alone; MIIM_STATE the state, MFS_DEFAULT and MFS_HILITE
/// kept).
fn apply(item: &mut Item, info: &ItemInfo<'_>, submenu: Option<MenuId>) {
    if info.mask & (MIIM_TYPE | MIIM_FTYPE) != 0 {
        item.item_type = info.item_type & TYPE_BITS;
    }
    if info.mask & MIIM_STATE != 0 {
        item.state = info.state & STATE_BITS | item.state & (MFS_DEFAULT | MFS_HILITE);
    }
    if info.mask & MIIM_CHECKMARKS != 0 {
        item.checked = info.checked;
        item.unchecked = info.unchecked;
    }
    if info.mask & MIIM_BITMAP != 0 {
        item.bitmap = info.bitmap;
    }
    if info.mask & MIIM_ID != 0 {
        item.id = info.id;
    }
    if info.mask & MIIM_SUBMENU != 0 {
        item.submenu = submenu;
    }
    if info.mask & MIIM_DATA != 0 {
        item.item_data = info.item_data;
    }
    if info.mask & (MIIM_TYPE | MIIM_STRING) != 0 {
        let length = info.text.len().min(MENU_ITEM_TEXT);
        item.text = [0; MENU_ITEM_TEXT];
        item.text[..length].copy_from_slice(&info.text[..length]);
        item.text_length = length as u8;
    }
}

// --- The window's side
// -------------------------------------------------------------------------------

impl Windows {
    /// The menu `handle` names, when it is live; ERROR_INVALID_MENU_HANDLE otherwise.
    pub fn menu_of(&self, handle: u32) -> Result<MenuId, Failure> {
        self.menus.menu_of(&self.handles, handle)
    }

    /// DestroyMenu over a handle: the menu and its popups destroyed, and a window holding it left
    /// without one.
    pub fn destroy_menu_handle(&mut self, handle: u32) -> Result<(), Failure> {
        let menu = self.menu_of(handle)?;
        let canonical = self.menus.handle_of(menu);
        self.menus.destroy(&mut self.handles, menu);
        self.forget_menu(canonical);
        Ok(())
    }

    /// SetMenuItemInfo over a handle: the item changed, the popup it no longer opens destroyed.
    pub fn set_menu_item(
        &mut self,
        handle: u32,
        item: ItemRef,
        info: &ItemInfo<'_>,
    ) -> Result<(), Failure> {
        let menu = self.menu_of(handle)?;
        if let Some(old) = self.menus.set(&self.handles, menu, item, info)? {
            self.destroy_menu_id(old);
        }
        Ok(())
    }

    /// RemoveMenu (`delete` false) or DeleteMenu over a handle: the item taken out, the popup it
    /// opened kept or destroyed.
    pub fn remove_menu_item(
        &mut self,
        handle: u32,
        item: ItemRef,
        delete: bool,
    ) -> Result<(), Failure> {
        let menu = self.menu_of(handle)?;
        if let Some(popup) = self.menus.remove(menu, item)? {
            if delete {
                self.destroy_menu_id(popup);
            }
        }
        Ok(())
    }

    /// The menu `menu` and its popups destroyed, a window holding it left without one.
    fn destroy_menu_id(&mut self, menu: MenuId) {
        let canonical = self.menus.handle_of(menu);
        self.menus.destroy(&mut self.handles, menu);
        self.forget_menu(canonical);
    }

    /// GetSystemMenu over handles: the window's copy of the system menu, its handle (0 for none
    /// yet); `made`, a menu user32 built, attached as the copy when the window has none; with
    /// `revert`, the copy destroyed and 0 answered.
    pub fn system_menu_handle(
        &mut self,
        window: u32,
        revert: bool,
        made: u32,
    ) -> Result<u32, Failure> {
        let id = self
            .window_from_handle(window)
            .ok_or(Failure::InvalidWindowHandle)?;
        let window = self.handle_of(id);
        let copy = self.menus.system_menu_of(window);
        if revert {
            if let Some(copy) = copy {
                self.destroy_menu_id(copy);
            }
            return Ok(0);
        }
        if let Some(copy) = copy {
            return Ok(self.menus.handle_of(copy));
        }
        if made == 0 {
            return Ok(0);
        }
        let menu = self.menu_of(made)?;
        if let Some(record) = self.menus.at_mut(menu) {
            record.system_of = window;
        }
        Ok(self.menus.handle_of(menu))
    }

    /// The window `window`'s copy of the system menu destroyed, at the window's end.
    pub fn destroy_system_menu(&mut self, window: u32) {
        if let Some(copy) = self.menus.system_menu_of(window) {
            self.destroy_menu_id(copy);
        }
    }

    /// SetMenu over handles: the window's menu set (none for a null menu); a child window has no
    /// menu (ERROR_CHILD_WINDOW_MENU). The menu it held before stays, as Windows documents.
    pub fn set_menu_handle(&mut self, window: u32, menu: u32) -> Result<(), Failure> {
        let id = self
            .window_from_handle(window)
            .ok_or(Failure::InvalidWindowHandle)?;
        // The menu's own handle is kept, whatever high word named it (0 and 0xFFFF name it too).
        let menu = match menu {
            0 => 0,
            menu => self.menus.handle_of(self.menu_of(menu)?),
        };
        if self.window_is_child(id) {
            return Err(Failure::ChildWindowMenu);
        }
        self.set_window_menu(id, menu);
        Ok(())
    }
}

// --- The services
// --------------------------------------------------------------------------------------

#[cfg(target_arch = "x86")]
mod services {
    use rtl::menu::{MENU_ITEM_INSERT, MENU_ITEM_QUERY, MENU_ITEM_SET, MENU_QUERY};
    use rtl::user::{
        NO_PARAM_CREATE_EMPTY_CURSOR,
        NO_PARAM_CREATE_MENU,
        NO_PARAM_CREATE_POPUP_MENU,
        NO_PARAM_DESTROY_CARET,
        NO_PARAM_RELEASE_CAPTURE,
    };
    use rtl::window::{SWP_FRAMECHANGED, SWP_NOACTIVATE, SWP_NOMOVE, SWP_NOSIZE, SWP_NOZORDER};

    use super::*;
    use crate::nt::call::{Handle, NtCall, NtResult, UserAddr, UserPtr};
    use crate::win32k::queue::{with_manager, with_session};
    use crate::win32k::window::Session;
    use crate::win32k::winsta::gui_thread;

    /// NtUserCallNoParam(Routine, Result): CreateMenu, CreatePopupMenu (the new menu's handle),
    /// the empty cursor object LoadIcon fills in (its handle), DestroyCaret (1;
    /// [`crate::win32k::caret::destroy`]'s failure), ReleaseCapture (1;
    /// [`crate::win32k::focus::set_capture`]); STATUS_INVALID_PARAMETER for another routine.
    pub fn call_no_param(call: &mut NtCall, routine: u32, result: UserPtr<u32>) -> NtResult {
        let caller = gui_thread(call)?;
        if routine == NO_PARAM_RELEASE_CAPTURE {
            with_session(call.passive(), |s| {
                crate::win32k::focus::set_capture(s, caller.thread, None);
            });
            result.write(1)?;
            return Ok(STATUS_SUCCESS);
        }
        let answer = with_manager(call.passive(), |m| match routine {
            NO_PARAM_CREATE_MENU | NO_PARAM_CREATE_POPUP_MENU => {
                let windows = &mut m.windows;
                windows
                    .menus
                    .create(&mut windows.handles, caller.owner)
                    .map_err(Failure::status)
            }
            NO_PARAM_CREATE_EMPTY_CURSOR => m
                .classes
                .cursors
                .create_empty(&mut m.windows.handles, caller.owner),
            NO_PARAM_DESTROY_CARET => {
                crate::win32k::caret::destroy(&mut m.windows, caller.thread).map(|()| 1)
            }
            _ => Err(STATUS_INVALID_PARAMETER),
        })?;
        result.write(answer)?;
        Ok(STATUS_SUCCESS)
    }

    /// An item's text: the units at `at`, `cch` of them (the MENUITEMINFOW's) or up to their NUL,
    /// cut at the item's longest, into `units`.
    fn read_item_text<'a>(
        at: UserAddr,
        info: &MenuItemInfoW,
        units: &'a mut [u16; MENU_ITEM_TEXT],
    ) -> Result<&'a [u16], NtStatus> {
        if at.is_null() {
            return Ok(&[]);
        }
        let limit = if info.cch == 0 {
            MENU_ITEM_TEXT
        } else {
            (info.cch as usize).min(MENU_ITEM_TEXT)
        };
        let mut length = 0;
        while length < limit {
            let unit = at.offset(2 * length as u32).cast::<u16>().read()?;
            if unit == 0 {
                break;
            }
            units[length] = unit;
            length += 1;
        }
        Ok(&units[..length])
    }

    /// NtUserThunkedMenuItemInfo(Menu, Item, Flags, Operation, Info, Text): by `operation`
    /// (rtl::menu's MENU_ITEM_* and MENU_QUERY), the MENUITEMINFOW at `info` inserted before the
    /// item `item` and the flags' MF_BYPOSITION name, or set on it, its text the units at `text`
    /// (Windows 2000's service takes the text apart too, as a counted string; the MENUITEMINFOW's
    /// dwTypeData is not read); or the item, or the menu, answered into `info` as a
    /// MenuItemAnswer once the window manager's lock is let go.
    pub fn thunked_menu_item_info(
        call: &mut NtCall,
        menu: Handle,
        item: u32,
        flags: u32,
        operation: u32,
        info: UserAddr,
        text: UserAddr,
    ) -> NtResult {
        gui_thread(call)?;
        let item = ItemRef::of(item, flags);
        match operation {
            MENU_ITEM_INSERT | MENU_ITEM_SET => {
                let given = info.cast::<MenuItemInfoW>().read()?;
                let mut units = [0u16; MENU_ITEM_TEXT];
                let text = if given.mask & (MIIM_TYPE | MIIM_STRING) != 0 {
                    read_item_text(text, &given, &mut units)?
                } else {
                    &[]
                };
                let fields = ItemInfo::of(&given, text);
                with_manager(call.passive(), |m| {
                    let windows = &mut m.windows;
                    let id = windows.menu_of(menu.raw())?;
                    if operation == MENU_ITEM_INSERT {
                        windows.menus.insert(&windows.handles, id, item, &fields)
                    } else {
                        windows.set_menu_item(menu.raw(), item, &fields)
                    }
                })
                .map_err(Failure::status)?;
            }
            MENU_ITEM_QUERY | MENU_QUERY => {
                let answer = with_manager(call.passive(), |m| {
                    let menus = &m.windows.menus;
                    let id = m.windows.menu_of(menu.raw())?;
                    if operation == MENU_QUERY {
                        Ok(menus.query_menu(id))
                    } else {
                        menus.query_item(id, item)
                    }
                })
                .map_err(Failure::status)?;
                info.cast::<MenuItemAnswer>().write(answer)?;
            }
            _ => return Err(STATUS_INVALID_PARAMETER),
        }
        Ok(STATUS_SUCCESS)
    }

    /// NtUserDestroyMenu(Menu): the menu and its popups destroyed.
    pub fn destroy_menu(call: &mut NtCall, menu: Handle) -> NtResult {
        gui_thread(call)?;
        with_manager(call.passive(), |m| {
            m.windows.destroy_menu_handle(menu.raw())
        })
        .map_err(Failure::status)?;
        Ok(STATUS_SUCCESS)
    }

    /// NtUserRemoveMenu(Menu, Position, Flags): the item taken out of its menu, the popup it opens
    /// kept; STATUS_OBJECT_NAME_NOT_FOUND for no such item.
    pub fn remove_menu(call: &mut NtCall, menu: Handle, position: u32, flags: u32) -> NtResult {
        remove(call, menu, position, flags, false)
    }

    /// NtUserDeleteMenu(Menu, Position, Flags): the item taken out of its menu, the popup it opens
    /// destroyed; STATUS_OBJECT_NAME_NOT_FOUND for no such item.
    pub fn delete_menu(call: &mut NtCall, menu: Handle, position: u32, flags: u32) -> NtResult {
        remove(call, menu, position, flags, true)
    }

    fn remove(
        call: &mut NtCall,
        menu: Handle,
        position: u32,
        flags: u32,
        delete: bool,
    ) -> NtResult {
        gui_thread(call)?;
        with_manager(call.passive(), |m| {
            m.windows
                .remove_menu_item(menu.raw(), ItemRef::of(position, flags), delete)
        })
        .map_err(Failure::status)?;
        Ok(STATUS_SUCCESS)
    }

    /// NtUserSetMenuDefaultItem(Menu, Item, ByPosition): the menu's default item set (u32::MAX:
    /// none); STATUS_OBJECT_NAME_NOT_FOUND for no such item or a separator.
    pub fn set_menu_default_item(
        call: &mut NtCall,
        menu: Handle,
        item: u32,
        by_position: bool,
    ) -> NtResult {
        gui_thread(call)?;
        with_manager(call.passive(), |m| {
            let id = m.windows.menu_of(menu.raw())?;
            m.windows.menus.set_default(id, item, by_position)
        })
        .map_err(Failure::status)?;
        Ok(STATUS_SUCCESS)
    }

    /// NtUserGetSystemMenu(Window, Revert, Made, Menu): the window's copy of the system menu into
    /// `answer` (0 for none yet), `made` attached as the copy when it has none; with `revert`, the
    /// copy destroyed and 0 answered ([`Windows::system_menu_handle`]).
    pub fn get_system_menu(
        call: &mut NtCall,
        window: Handle,
        revert: bool,
        made: Handle,
        answer: UserPtr<u32>,
    ) -> NtResult {
        gui_thread(call)?;
        let menu = with_manager(call.passive(), |m| {
            m.windows
                .system_menu_handle(window.raw(), revert, made.raw())
        })
        .map_err(Failure::status)?;
        answer.write(menu)?;
        Ok(STATUS_SUCCESS)
    }

    /// NtUserCheckMenuItem(Menu, Item, Check, Previous): CheckMenuItem's arguments, the item's
    /// previous check into `previous`; STATUS_OBJECT_NAME_NOT_FOUND for no such item.
    pub fn check_menu_item(
        call: &mut NtCall,
        menu: Handle,
        item: u32,
        check: u32,
        previous: UserPtr<u32>,
    ) -> NtResult {
        gui_thread(call)?;
        let answer = with_manager(call.passive(), |m| {
            let id = m.windows.menu_of(menu.raw())?;
            m.windows.menus.check(id, ItemRef::of(item, check), check)
        })
        .map_err(Failure::status)?;
        previous.write(answer)?;
        Ok(STATUS_SUCCESS)
    }

    /// NtUserEnableMenuItem(Menu, Item, Enable, Previous): EnableMenuItem's arguments, the item's
    /// previous enabling bits into `previous`; STATUS_OBJECT_NAME_NOT_FOUND for no such item.
    pub fn enable_menu_item(
        call: &mut NtCall,
        menu: Handle,
        item: u32,
        enable: u32,
        previous: UserPtr<u32>,
    ) -> NtResult {
        gui_thread(call)?;
        let answer = with_manager(call.passive(), |m| {
            let id = m.windows.menu_of(menu.raw())?;
            m.windows
                .menus
                .enable(id, ItemRef::of(item, enable), enable)
        })
        .map_err(Failure::status)?;
        previous.write(answer)?;
        Ok(STATUS_SUCCESS)
    }

    /// NtUserSetMenu(Window, Menu, Repaint): the window's menu set, and its frame changed as
    /// SetWindowPos's SWP_FRAMECHANGED changes it: the client area gives the menu bar its room (or
    /// takes it back), and a shown window's frame is painted with the bar.
    pub fn set_menu(call: &mut NtCall, window: Handle, menu: Handle, _repaint: bool) -> NtResult {
        gui_thread(call)?;
        with_session(call.passive(), |s| {
            s.windows()
                .set_menu_handle(window.raw(), menu.raw())
                .map_err(Failure::status)?;
            Windows::set_window_pos_handle(
                s,
                window.raw(),
                0,
                0,
                0,
                0,
                0,
                SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE | SWP_FRAMECHANGED,
            )
            .map_err(|failure| failure.status())
        })?;
        Ok(STATUS_SUCCESS)
    }
}

// The host builds have no processes and no user memory: the services answer nothing (the host
// tests drive the registry itself).
#[cfg(not(target_arch = "x86"))]
mod services {
    use super::*;
    use crate::nt::call::{Handle, NtCall, NtResult, UserAddr, UserPtr};

    pub fn call_no_param(_: &mut NtCall, _: u32, _: UserPtr<u32>) -> NtResult {
        Err(STATUS_NOT_IMPLEMENTED)
    }

    pub fn thunked_menu_item_info(
        _: &mut NtCall,
        _: Handle,
        _: u32,
        _: u32,
        _: u32,
        _: UserAddr,
        _: UserAddr,
    ) -> NtResult {
        Err(STATUS_NOT_IMPLEMENTED)
    }

    pub fn destroy_menu(_: &mut NtCall, _: Handle) -> NtResult {
        Err(STATUS_NOT_IMPLEMENTED)
    }

    pub fn remove_menu(_: &mut NtCall, _: Handle, _: u32, _: u32) -> NtResult {
        Err(STATUS_NOT_IMPLEMENTED)
    }

    pub fn delete_menu(_: &mut NtCall, _: Handle, _: u32, _: u32) -> NtResult {
        Err(STATUS_NOT_IMPLEMENTED)
    }

    pub fn set_menu_default_item(_: &mut NtCall, _: Handle, _: u32, _: bool) -> NtResult {
        Err(STATUS_NOT_IMPLEMENTED)
    }

    pub fn get_system_menu(
        _: &mut NtCall,
        _: Handle,
        _: bool,
        _: Handle,
        _: UserPtr<u32>,
    ) -> NtResult {
        Err(STATUS_NOT_IMPLEMENTED)
    }

    pub fn check_menu_item(_: &mut NtCall, _: Handle, _: u32, _: u32, _: UserPtr<u32>) -> NtResult {
        Err(STATUS_NOT_IMPLEMENTED)
    }

    pub fn enable_menu_item(
        _: &mut NtCall,
        _: Handle,
        _: u32,
        _: u32,
        _: UserPtr<u32>,
    ) -> NtResult {
        Err(STATUS_NOT_IMPLEMENTED)
    }

    pub fn set_menu(_: &mut NtCall, _: Handle, _: Handle, _: bool) -> NtResult {
        Err(STATUS_NOT_IMPLEMENTED)
    }
}

pub use services::{
    call_no_param,
    check_menu_item,
    delete_menu,
    destroy_menu,
    enable_menu_item,
    get_system_menu,
    remove_menu,
    set_menu,
    set_menu_default_item,
    thunked_menu_item_info,
};

#[cfg(test)]
mod tests {
    use std::boxed::Box;

    use rtl::menu::{MFS_CHECKED, MFT_RADIOCHECK};
    use rtl::testing::wide;

    use super::*;

    const OWNER: Owner = 3;

    /// The menu registry and the handle table its menus' handles are in.
    struct Fixture {
        menus: Box<Menus>,
        handles: Box<UserHandles>,
    }

    impl Fixture {
        fn create(&mut self, owner: Owner) -> Result<u32, Failure> {
            self.menus.create(&mut self.handles, owner)
        }

        fn menu_of(&self, handle: u32) -> Result<MenuId, Failure> {
            self.menus.menu_of(&self.handles, handle)
        }

        fn insert(&mut self, menu: MenuId, before: ItemRef, info: &ItemInfo<'_>) {
            self.menus
                .insert(&self.handles, menu, before, info)
                .unwrap();
        }

        fn set(&mut self, menu: MenuId, item: ItemRef, info: &ItemInfo<'_>) -> Option<MenuId> {
            self.menus.set(&self.handles, menu, item, info).unwrap()
        }

        fn remove(&mut self, menu: MenuId, item: ItemRef) -> Result<Option<MenuId>, Failure> {
            self.menus.remove(menu, item)
        }

        fn destroy(&mut self, menu: MenuId) {
            self.menus.destroy(&mut self.handles, menu);
        }

        fn destroy_owner(&mut self, owner: Owner) {
            self.menus.destroy_owner(&mut self.handles, owner);
        }
    }

    impl core::ops::Deref for Fixture {
        type Target = Menus;

        fn deref(&self) -> &Menus {
            &self.menus
        }
    }

    impl core::ops::DerefMut for Fixture {
        fn deref_mut(&mut self) -> &mut Menus {
            &mut self.menus
        }
    }

    fn menus() -> Fixture {
        let mut boxed = Box::<Menus>::new_uninit();
        let mut handles = Box::<UserHandles>::new_uninit();
        // SAFETY: the boxes' memory, valid and aligned, written whole before it is assumed.
        unsafe {
            Menus::write_empty(boxed.as_mut_ptr());
            UserHandles::write_empty(handles.as_mut_ptr());
            Fixture {
                menus: boxed.assume_init(),
                handles: handles.assume_init(),
            }
        }
    }

    /// An item of type `item_type` and state `state`, id `id`, opening `submenu`, its text `text`.
    fn add(
        m: &mut Fixture,
        menu: u32,
        item_type: u32,
        state: u32,
        id: u32,
        submenu: u32,
        text: &str,
    ) {
        let text = wide(text);
        let info = ItemInfo {
            mask: MIIM_FTYPE | MIIM_STATE | MIIM_ID | MIIM_SUBMENU | MIIM_STRING,
            item_type,
            state,
            id,
            submenu,
            item_data: 0,
            checked: 0,
            unchecked: 0,
            bitmap: 0,
            text: &text,
        };
        let id = m.menu_of(menu).unwrap();
        m.insert(id, ItemRef::Position(u32::MAX), &info);
    }

    /// The menus fixture's menu 200: the bar, File (New, Open grayed, a separator, Recent with
    /// First, Exit checked), View (Standard checked, Scientific, Programmer), Help.
    fn menu_200(m: &mut Fixture) -> (u32, u32, u32, u32) {
        let bar = m.create(OWNER).unwrap();
        let file = m.create(OWNER).unwrap();
        let recent = m.create(OWNER).unwrap();
        let view = m.create(OWNER).unwrap();
        add(m, file, 0, 0, 201, 0, "&New");
        add(m, file, 0, MF_GRAYED, 202, 0, "&Open");
        add(m, file, MFT_SEPARATOR, 0, 0, 0, "");
        add(m, recent, 0, 0, 205, 0, "First");
        add(m, file, 0, 0, recent, recent, "&Recent");
        add(m, file, 0, MF_CHECKED, 203, 0, "E&xit");
        add(m, view, 0, MF_CHECKED, 211, 0, "&Standard");
        add(m, view, 0, 0, 212, 0, "S&cientific");
        add(m, view, 0, 0, 213, 0, "&Programmer");
        add(m, bar, 0, 0, file, file, "&File");
        add(m, bar, 0, 0, view, view, "&View");
        add(m, bar, 0, 0, 220, 0, "&Help");
        (bar, file, recent, view)
    }

    /// Items by position and by command, through the bar into a nested popup, as the items
    /// section's capture answers them.
    #[test]
    fn items_are_found_by_position_and_by_command() {
        let mut m = menus();
        let (bar, file, recent, _) = menu_200(&mut m);
        let bar_id = m.menu_of(bar).unwrap();
        assert_eq!(m.count(bar_id), 3);
        let help = m.query_item(bar_id, ItemRef::Position(2)).unwrap();
        assert_eq!(
            (help.id, help.submenu, help.text()),
            (220, 0, &wide("&Help")[..])
        );
        let file_item = m.query_item(bar_id, ItemRef::Position(0)).unwrap();
        assert_eq!((file_item.submenu, file_item.submenu_count), (file, 5));
        assert_eq!(
            rtl::menu::state_word(file_item.item_type, file_item.state, Some(5)),
            0x510
        );
        let separator = m
            .query_item(m.menu_of(file).unwrap(), ItemRef::Position(2))
            .unwrap();
        assert_eq!(
            rtl::menu::state_word(separator.item_type, separator.state, None),
            0x803
        );
        let first = m.query_item(bar_id, ItemRef::Command(205)).unwrap();
        assert_eq!((first.holder, first.position), (recent, 0));
        assert_eq!(
            m.query_item(bar_id, ItemRef::Position(3)),
            Err(Failure::ItemNotFound)
        );
        assert_eq!(
            m.query_item(bar_id, ItemRef::Command(299)),
            Err(Failure::ItemNotFound)
        );
    }

    /// CheckMenuItem's and EnableMenuItem's previous states, as the check and enable sections'
    /// captures answer them.
    #[test]
    fn checks_and_enablings_answer_the_previous_state() {
        let mut m = menus();
        let (bar, file, _, _) = menu_200(&mut m);
        let bar = m.menu_of(bar).unwrap();
        assert_eq!(m.check(bar, ItemRef::Command(203), 0), Ok(MF_CHECKED));
        assert_eq!(m.check(bar, ItemRef::Command(203), 0), Ok(0));
        assert_eq!(m.check(bar, ItemRef::Command(201), MF_CHECKED), Ok(0));
        assert_eq!(
            m.check(bar, ItemRef::Command(201), MF_CHECKED),
            Ok(MF_CHECKED)
        );
        let file = m.menu_of(file).unwrap();
        assert_eq!(m.check(file, ItemRef::Position(1), MF_CHECKED), Ok(0));
        assert_eq!(m.query_item(file, ItemRef::Position(1)).unwrap().state, 9);
        assert_eq!(
            m.check(bar, ItemRef::Command(299), MF_CHECKED),
            Err(Failure::ItemNotFound)
        );
        assert_eq!(m.enable(bar, ItemRef::Command(202), 0), Ok(MF_GRAYED));
        assert_eq!(m.enable(bar, ItemRef::Command(202), 0), Ok(0));
        assert_eq!(m.enable(bar, ItemRef::Command(201), MF_DISABLED), Ok(0));
        assert_eq!(
            m.enable(bar, ItemRef::Command(201), MF_GRAYED),
            Ok(MF_DISABLED)
        );
        assert_eq!(m.enable(bar, ItemRef::Command(201), 3), Ok(MF_GRAYED));
        assert_eq!(m.enable(bar, ItemRef::Command(201), 0), Ok(3));
        assert_eq!(
            m.enable(bar, ItemRef::Position(7), 0),
            Err(Failure::ItemNotFound)
        );
    }

    /// A set changes only what its mask names: the radio check's type kept beside a new state.
    #[test]
    fn sets_change_what_their_mask_names() {
        let mut m = menus();
        let (_, _, _, view) = menu_200(&mut m);
        let view = m.menu_of(view).unwrap();
        let info = ItemInfo {
            mask: MIIM_FTYPE | MIIM_STATE,
            item_type: MFT_RADIOCHECK,
            state: MFS_CHECKED,
            id: 0,
            submenu: 0,
            item_data: 0,
            checked: 0,
            unchecked: 0,
            bitmap: 0,
            text: &[],
        };
        m.set(view, ItemRef::Command(212), &info);
        let item = m.query_item(view, ItemRef::Position(1)).unwrap();
        assert_eq!(
            (item.item_type, item.state, item.id),
            (MFT_RADIOCHECK, MFS_CHECKED, 212)
        );
        assert_eq!(item.text(), &wide("S&cientific")[..]);
    }

    /// A state change keeps the default and the highlight (the `info` capture's 0x1083); new check
    /// marks and a bitmap are kept and answered.
    #[test]
    fn state_changes_keep_the_default_and_the_highlight() {
        let mut m = menus();
        let (_, file, _, _) = menu_200(&mut m);
        let file = m.menu_of(file).unwrap();
        let mut info = ItemInfo {
            mask: MIIM_STATE,
            item_type: 0,
            state: MFS_CHECKED | MFS_DEFAULT | MFS_HILITE,
            id: 0,
            submenu: 0,
            item_data: 0,
            checked: 0,
            unchecked: 0,
            bitmap: 0,
            text: &[],
        };
        m.set(file, ItemRef::Position(0), &info);
        info.state = MFS_GRAYED;
        m.set(file, ItemRef::Position(0), &info);
        let item = m.query_item(file, ItemRef::Position(0)).unwrap();
        assert_eq!(item.state, 0x1083);
        info.mask = MIIM_CHECKMARKS | MIIM_BITMAP;
        info.checked = 0x40;
        info.bitmap = 8;
        m.set(file, ItemRef::Position(0), &info);
        let item = m.query_item(file, ItemRef::Position(0)).unwrap();
        assert_eq!((item.checked, item.unchecked, item.bitmap), (0x40, 0, 8));
    }

    /// An insertion by a command no item has appends to the menu; a popup given another (or none)
    /// is handed back to be destroyed; removal hands back the popup an item opened.
    #[test]
    fn insertions_changes_and_removals() {
        let mut m = menus();
        let (bar, file, recent, _) = menu_200(&mut m);
        let bar_id = m.menu_of(bar).unwrap();
        let text = wide("Lost");
        let info = ItemInfo {
            mask: MIIM_ID | MIIM_STRING,
            item_type: 0,
            state: 0,
            id: 311,
            submenu: 0,
            item_data: 0,
            checked: 0,
            unchecked: 0,
            bitmap: 0,
            text: &text,
        };
        m.insert(bar_id, ItemRef::Command(399), &info);
        assert_eq!(m.count(bar_id), 4);
        assert_eq!(m.query_item(bar_id, ItemRef::Position(3)).unwrap().id, 311);
        m.insert(bar_id, ItemRef::Command(202), &ItemInfo { id: 312, ..info });
        let file_id = m.menu_of(file).unwrap();
        assert_eq!(m.query_item(file_id, ItemRef::Position(1)).unwrap().id, 312);

        let recent_id = m.menu_of(recent).unwrap();
        let none = ItemInfo {
            mask: MIIM_SUBMENU,
            ..info
        };
        assert_eq!(m.set(file_id, ItemRef::Position(4), &none), Some(recent_id));
        assert_eq!(m.set(file_id, ItemRef::Position(4), &none), None);

        assert_eq!(m.remove(bar_id, ItemRef::Position(0)), Ok(Some(file_id)));
        assert_eq!(m.count(bar_id), 3);
        assert_eq!(
            m.remove(bar_id, ItemRef::Command(312)),
            Err(Failure::ItemNotFound)
        );
        assert_eq!(m.remove(file_id, ItemRef::Command(312)), Ok(None));
        assert_eq!(
            m.remove(bar_id, ItemRef::Position(9)),
            Err(Failure::ItemNotFound)
        );
    }

    /// SetMenuDefaultItem moves MFS_DEFAULT to one item of the menu itself, refuses a separator
    /// and a popup's item, and -1 takes it off them all (the `default` capture).
    #[test]
    fn the_default_item_is_the_menus_own() {
        let mut m = menus();
        let (bar, file, _, _) = menu_200(&mut m);
        let file = m.menu_of(file).unwrap();
        let state = |m: &Fixture, position| {
            m.query_item(file, ItemRef::Position(position))
                .unwrap()
                .state
                & MFS_DEFAULT
        };
        assert_eq!(m.set_default(file, 203, false), Ok(()));
        assert_eq!(state(&m, 4), MFS_DEFAULT);
        assert_eq!(m.set_default(file, 1, true), Ok(()));
        assert_eq!((state(&m, 1), state(&m, 4)), (MFS_DEFAULT, 0));
        assert_eq!(m.set_default(file, 2, true), Err(Failure::ItemNotFound));
        assert_eq!(state(&m, 1), MFS_DEFAULT, "a separator changes nothing");
        assert_eq!(m.set_default(file, 205, false), Err(Failure::ItemNotFound));
        let bar = m.menu_of(bar).unwrap();
        assert_eq!(m.set_default(bar, 201, false), Err(Failure::ItemNotFound));
        assert_eq!(m.set_default(file, u32::MAX, false), Ok(()));
        assert_eq!(state(&m, 1), 0);
    }

    /// A window's system menu is the menu marked as its, until the menu goes.
    #[test]
    fn system_menus_belong_to_their_window() {
        let mut m = menus();
        let menu = m.create(OWNER).unwrap();
        let id = m.menu_of(menu).unwrap();
        assert_eq!(m.system_menu_of(0x1234), None);
        m.at_mut(id).unwrap().system_of = 0x1234;
        assert_eq!(m.system_menu_of(0x1234), Some(id));
        assert_eq!(m.system_menu_of(0), None);
        m.destroy(id);
        assert_eq!(m.system_menu_of(0x1234), None);
    }

    /// DestroyMenu takes the popups with the menu; a destroyed handle names nothing, and the
    /// process's end takes what it left.
    #[test]
    fn destruction_is_recursive_and_ends_with_the_process() {
        let mut m = menus();
        let (bar, file, recent, view) = menu_200(&mut m);
        assert_eq!(m.live(), 4);
        let bar_id = m.menu_of(bar).unwrap();
        m.destroy(bar_id);
        for handle in [bar, file, recent, view] {
            assert_eq!(m.menu_of(handle), Err(Failure::InvalidMenuHandle));
        }
        assert_eq!(m.live(), 0);
        assert_eq!(m.items.live(), 0);
        menu_200(&mut m);
        let other = m.create(OWNER + 1).unwrap();
        m.destroy_owner(OWNER);
        assert_eq!(m.live(), 1);
        assert!(m.menu_of(other).is_ok());
        assert_eq!(
            m.menu_of(0x7FFC),
            Err(Failure::InvalidMenuHandle),
            "a slot holding nothing"
        );
    }

    /// A destroyed menu's id names nothing: every call taking it answers
    /// ERROR_INVALID_MENU_HANDLE or nothing, and none reads the record its slot holds now.
    #[test]
    fn a_destroyed_menus_id_names_nothing() {
        let mut m = menus();
        let (bar, _, _, _) = menu_200(&mut m);
        let bar_id = m.menu_of(bar).unwrap();
        m.destroy(bar_id);
        let text = wide("Late");
        let info = ItemInfo {
            mask: MIIM_ID | MIIM_STRING,
            item_type: 0,
            state: 0,
            id: 400,
            submenu: 0,
            item_data: 0,
            checked: 0,
            unchecked: 0,
            bitmap: 0,
            text: &text,
        };
        assert_eq!(m.count(bar_id), 0);
        assert_eq!(m.handle_of(bar_id), 0);
        assert_eq!(m.find(bar_id, ItemRef::Command(205)), None);
        assert_eq!(
            m.query_item(bar_id, ItemRef::Position(0)),
            Err(Failure::InvalidMenuHandle)
        );
        assert_eq!(
            m.menus
                .insert(&m.handles, bar_id, ItemRef::Position(0), &info),
            Err(Failure::InvalidMenuHandle)
        );
        assert_eq!(
            m.menus.set(&m.handles, bar_id, ItemRef::Position(0), &info),
            Err(Failure::InvalidMenuHandle)
        );
        assert_eq!(
            m.remove(bar_id, ItemRef::Position(0)),
            Err(Failure::InvalidMenuHandle)
        );
        assert_eq!(
            m.check(bar_id, ItemRef::Position(0), MF_CHECKED),
            Err(Failure::InvalidMenuHandle)
        );
        assert_eq!(
            m.enable(bar_id, ItemRef::Position(0), MF_GRAYED),
            Err(Failure::InvalidMenuHandle)
        );
        assert_eq!(
            m.set_default(bar_id, 0, true),
            Err(Failure::InvalidMenuHandle)
        );
        assert_eq!(m.query_menu(bar_id).count, 0);
        m.destroy(bar_id);
        assert_eq!(m.live(), 0);
    }

    /// An id past every slot made, or a handle whose table entry names one, finds nothing and
    /// panics nowhere (the old fixed array was indexed unchecked).
    #[test]
    fn an_id_past_the_pool_names_nothing() {
        let mut m = menus();
        let menu = m.create(OWNER).unwrap();
        for forged in [MenuId::for_tests(500), Id::new(0xFFFF, 1), Id::new(0, 0)] {
            assert_eq!(m.count(forged), 0);
            assert_eq!(
                m.query_item(forged, ItemRef::Position(0)),
                Err(Failure::InvalidMenuHandle)
            );
            m.destroy(forged);
            let handle = m.handles.insert(UserObject::Menu(forged));
            assert_eq!(m.menu_of(handle), Err(Failure::InvalidMenuHandle));
            m.handles.close(handle);
        }
        assert!(m.menu_of(menu).is_ok());
        assert_eq!(m.live(), 1);
    }

    /// A destroyed menu's slot and its items' are taken again, the old id and handle naming
    /// nothing; the pools grow past a chunk and keep their peak.
    #[test]
    fn slots_are_reused_and_the_pools_grow() {
        let mut m = menus();
        let first = m.create(OWNER).unwrap();
        let first_id = m.menu_of(first).unwrap();
        add(&mut m, first, 0, 0, 1, 0, "One");
        m.destroy(first_id);
        let second = m.create(OWNER).unwrap();
        let second_id = m.menu_of(second).unwrap();
        assert_eq!(second_id.index, first_id.index, "the freed slot taken");
        assert_eq!(second_id.uniq, first_id.uniq + 1);
        assert_eq!(m.menu_of(first), Err(Failure::InvalidMenuHandle));
        assert_eq!(m.count(first_id), 0);
        assert_eq!(m.count(second_id), 0, "a fresh menu holds no item");
        add(&mut m, second, 0, 0, 2, 0, "Two");
        assert_eq!(m.items.high_water(), 1, "the freed item taken");

        // Past one chunk of menus and one of items.
        let mut handles = std::vec::Vec::new();
        for _ in 0..3 * MENUS_PER_CHUNK {
            let menu = m.create(OWNER + 1).unwrap();
            for id in 0..8 {
                add(&mut m, menu, 0, 0, id, 0, "Item");
            }
            handles.push(menu);
        }
        assert_eq!(m.live(), 1 + 3 * MENUS_PER_CHUNK);
        assert!(m.items.live() as usize > ITEMS_PER_CHUNK);
        for &menu in &handles {
            let id = m.menu_of(menu).unwrap();
            assert_eq!(m.count(id), 8);
        }
        m.destroy_owner(OWNER + 1);
        assert_eq!(m.live(), 1);
        assert_eq!(m.items.live(), 1);
    }

    /// A popup inserted into itself, or into its own popup, ends its destruction there.
    #[test]
    fn a_popup_cycle_is_destroyed_once() {
        let mut m = menus();
        let a = m.create(OWNER).unwrap();
        let b = m.create(OWNER).unwrap();
        add(&mut m, a, 0, 0, b, b, "B");
        add(&mut m, b, 0, 0, a, a, "A");
        add(&mut m, a, 0, 0, a, a, "Self");
        let a_id = m.menu_of(a).unwrap();
        m.destroy(a_id);
        assert_eq!(m.live(), 0);
        assert_eq!(m.items.live(), 0);
        assert_eq!(m.menu_of(b), Err(Failure::InvalidMenuHandle));
    }
}
