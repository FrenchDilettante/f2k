//! Menus: the menu records behind HMENUs, their items, and the services user32's menu calls come
//! through. Data only: the menu bar is not drawn and no menu is tracked yet.
//!
//! A menu is a record in the menu pool ([`Menus`]), named by a generation-tagged id ([`MenuId`]),
//! the object manager's pattern, with a handle into the user handle table ([`super::handle`]). A
//! menu holds its items in order: indexes into the item pool, each item its type (MFT_*), its state
//! (MFS_*, the enabling bits MF_GRAYED and MF_DISABLED kept apart, as EnableMenuItem's answer shows
//! them), its command id, the popup it opens (a menu's id: a popup destroyed meanwhile is none),
//! its application data and its text. A menu belongs to the process that made it, and goes at its
//! end.
//!
//! Windows 2000 keeps a menu in the desktop heap, its items an array of the menu's own; F2K's
//! records are fixed-size, so a menu holds at most [`MAX_MENU_ITEMS`] items and an item's text is
//! cut at [`MENU_ITEM_TEXT`] units. The pools sit in the window registry ([`Windows::menus`]),
//! behind the window manager's lock, as a window's menu is the window record's: setting a menu,
//! destroying it with its window, and destroying a window's menu all hold the one lock.
//!
//! An item is named by its position in a menu (MF_BYPOSITION) or by its command (MF_BYCOMMAND):
//! the first item of that id, the menu's items searched in order and a popup's items right after
//! the item that opens it, so an item of a popup is found through the bar ([`Menus::find`]).
//!
//! The services (F2K's argument lists, see [`crate::win32k`]; Windows 2000's numbers):
//!
//! - NtUserCallNoParam (0x1138): CreateMenu and CreatePopupMenu (rtl::user's NO_PARAM_* routines),
//!   and the empty cursor object LoadIcon fills in ([`super::icon`]);
//! - NtUserThunkedMenuItemInfo (0x121F): an item inserted (InsertMenuItem) or changed
//!   (SetMenuItemInfo) from a MENUITEMINFOW; and, by an operation of F2K's own, an item or the menu
//!   answered as rtl::menu's MenuItemAnswer — what Windows 2000's user32 reads from the menu's
//!   record, mapped into its process (GetMenuItemCount, GetMenuItemID, GetSubMenu, GetMenuState,
//!   GetMenuString, IsMenu);
//! - NtUserDestroyMenu (0x1158): the menu and its popups destroyed;
//! - NtUserCheckMenuItem (0x113E) and NtUserEnableMenuItem (0x1164): the item's check or enabling
//!   changed, its previous one answered;
//! - NtUserSetMenu (0x11F9): a top-level window's menu set (GetMenu reads it through
//!   NtUserQueryWindow's QUERY_WINDOW_MENU).
//!
//! A failure names the Win32 error code of the decision ([`Failure`]'s variants); the service
//! answers a status user32 maps back: a window naming nothing is STATUS_INVALID_HANDLE, as for
//! every window service, and a menu naming nothing STATUS_OBJECT_TYPE_MISMATCH (the handle names no
//! menu).

use rtl::menu::{
    MenuItemAnswer,
    MenuItemInfoW,
    MENU_ITEM_TEXT,
    MFS_GRAYED,
    MFT_SEPARATOR,
    MF_BYPOSITION,
    MF_CHECKED,
    MF_DISABLED,
    MF_GRAYED,
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

use super::class::Owner;
use super::handle::{UserHandles, UserObject};
use super::window::Windows;
use crate::status::*;

/// How many menus can exist at once, and how many items between them.
pub const MENUS: usize = 256;
pub const ITEMS: usize = 1024;
/// How many items one menu holds.
pub const MAX_MENU_ITEMS: usize = 64;

/// The popups a menu's search and destruction go down at most (a popup inserted into itself would
/// otherwise never end them).
const MAX_DEPTH: u32 = 16;

/// Why a menu operation failed: the Win32 error code (winerror.h) the decision reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    /// ERROR_NOT_ENOUGH_MEMORY (8): the pools are full.
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
    /// The NTSTATUS the service answers: the menu-specific codes have no NTSTATUS of their own, so
    /// the closest documented one stands in, and user32's body reports the code.
    pub const fn status(self) -> NtStatus {
        match self {
            Failure::NotEnoughMemory => STATUS_NO_MEMORY,
            Failure::ChildWindowMenu => STATUS_INVALID_PARAMETER,
            Failure::InvalidWindowHandle => STATUS_INVALID_HANDLE,
            Failure::InvalidMenuHandle => STATUS_OBJECT_TYPE_MISMATCH,
            Failure::ItemNotFound => STATUS_OBJECT_NAME_NOT_FOUND,
        }
    }
}

/// A menu's id: its record in the pool and the record's generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MenuId {
    index: u16,
    generation: u16,
}

impl MenuId {
    /// The id of the record `index`, its first generation (the handle table's tests).
    #[cfg(test)]
    pub const fn for_tests(index: u16) -> Self {
        MenuId {
            index,
            generation: 0,
        }
    }
}

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
            text,
        }
    }
}

/// One menu's record.
#[derive(Clone, Copy)]
struct MenuRecord {
    live: bool,
    generation: u16,
    handle: u32,
    owner: Owner,
    count: u16,
    /// The items, by position: indexes into the item pool.
    items: [u16; MAX_MENU_ITEMS],
}

impl MenuRecord {
    const DEAD: Self = MenuRecord {
        live: false,
        generation: 0,
        handle: 0,
        owner: 0,
        count: 0,
        items: [0; MAX_MENU_ITEMS],
    };
}

/// One item's record.
#[derive(Clone, Copy)]
struct Item {
    used: bool,
    item_type: u32,
    state: u32,
    id: u32,
    submenu: Option<MenuId>,
    item_data: u32,
    text_length: u8,
    text: [u16; MENU_ITEM_TEXT],
}

impl Item {
    const EMPTY: Self = Item {
        used: false,
        item_type: 0,
        state: 0,
        id: 0,
        submenu: None,
        item_data: 0,
        text_length: 0,
        text: [0; MENU_ITEM_TEXT],
    };
}

/// The menu registry: the menu pool and the item pool. Their handles are the user handle table's
/// ([`UserHandles`], the window registry's), which the calls that make, find or destroy a menu are
/// lent.
pub struct Menus {
    menus: [MenuRecord; MENUS],
    items: [Item; ITEMS],
}

impl Menus {
    /// Write an empty registry at `menus`, element by element (by value it would pass through the
    /// stack, which is smaller than it).
    ///
    /// # Safety
    ///
    /// `menus` is valid for writes and aligned; its previous contents are overwritten, not
    /// dropped.
    pub unsafe fn write_empty(menus: *mut Menus) {
        use core::ptr::addr_of_mut;
        // SAFETY: the caller's contract; every field is written, the arrays element by element.
        unsafe {
            let records = addr_of_mut!((*menus).menus) as *mut MenuRecord;
            for index in 0..MENUS {
                records.add(index).write(MenuRecord::DEAD);
            }
            let items = addr_of_mut!((*menus).items) as *mut Item;
            for index in 0..ITEMS {
                items.add(index).write(Item::EMPTY);
            }
        }
    }

    fn at(&self, id: MenuId) -> &MenuRecord {
        &self.menus[id.index as usize]
    }

    fn at_mut(&mut self, id: MenuId) -> &mut MenuRecord {
        &mut self.menus[id.index as usize]
    }

    fn is_live(&self, id: MenuId) -> bool {
        let record = &self.menus[id.index as usize];
        record.live && record.generation == id.generation
    }

    /// The item at `position` of `menu`.
    fn item(&self, menu: MenuId, position: usize) -> &Item {
        &self.items[self.at(menu).items[position] as usize]
    }

    fn item_mut(&mut self, menu: MenuId, position: usize) -> &mut Item {
        let index = self.at(menu).items[position] as usize;
        &mut self.items[index]
    }

    /// A new menu of the process `owner`; its handle. A popup (CreatePopupMenu's) and a menu bar
    /// (CreateMenu's) are the same record until the menu bar's drawing and the menus' tracking
    /// tell them apart.
    pub fn create(&mut self, handles: &mut UserHandles, owner: Owner) -> Result<u32, Failure> {
        let index = self
            .menus
            .iter()
            .position(|m| !m.live)
            .ok_or(Failure::NotEnoughMemory)?;
        if handles.is_full() {
            return Err(Failure::NotEnoughMemory);
        }
        let id = MenuId {
            index: index as u16,
            generation: self.menus[index].generation,
        };
        let handle = handles.insert(UserObject::Menu(id));
        self.menus[index] = MenuRecord {
            live: true,
            generation: id.generation,
            handle,
            owner,
            count: 0,
            items: [0; MAX_MENU_ITEMS],
        };
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

    /// The handle of `id`.
    pub fn handle_of(&self, id: MenuId) -> u32 {
        self.at(id).handle
    }

    /// How many items `menu` holds.
    pub fn count(&self, menu: MenuId) -> usize {
        self.at(menu).count as usize
    }

    /// The popup the item at `position` of `menu` opens, when it is still live.
    fn submenu(&self, menu: MenuId, position: usize) -> Option<MenuId> {
        self.item(menu, position)
            .submenu
            .filter(|&sub| self.is_live(sub))
    }

    /// The item `item` names in `menu`: the menu holding it and its position there. By position,
    /// an item of `menu` itself; by command, the first item of the id, a popup's items searched
    /// right after the item that opens it.
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
            if self.item(menu, position).id == id {
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
    /// position is past it; by command, in the menu holding that item): InsertMenuItem. A
    /// separator is grayed, as Windows 2000's are; a popup must be a live menu.
    pub fn insert(
        &mut self,
        handles: &UserHandles,
        menu: MenuId,
        before: ItemRef,
        info: &ItemInfo<'_>,
    ) -> Result<(), Failure> {
        let (holder, position) = match before {
            ItemRef::Position(position) => (menu, (position as usize).min(self.count(menu))),
            ItemRef::Command(_) => self.find(menu, before).ok_or(Failure::ItemNotFound)?,
        };
        let submenu = self.submenu_of(handles, info)?;
        if self.count(holder) >= MAX_MENU_ITEMS {
            return Err(Failure::NotEnoughMemory);
        }
        let slot = self
            .items
            .iter()
            .position(|item| !item.used)
            .ok_or(Failure::NotEnoughMemory)?;
        let mut item = Item {
            used: true,
            ..Item::EMPTY
        };
        apply(&mut item, info, submenu);
        if item.item_type & MFT_SEPARATOR != 0 {
            item.state |= MFS_GRAYED;
        }
        self.items[slot] = item;
        let record = self.at_mut(holder);
        let count = record.count as usize;
        record.items.copy_within(position..count, position + 1);
        record.items[position] = slot as u16;
        record.count += 1;
        Ok(())
    }

    /// Change the fields the mask names of the item `item` names: SetMenuItemInfo.
    pub fn set(
        &mut self,
        handles: &UserHandles,
        menu: MenuId,
        item: ItemRef,
        info: &ItemInfo<'_>,
    ) -> Result<(), Failure> {
        let (holder, position) = self.find(menu, item).ok_or(Failure::ItemNotFound)?;
        let submenu = self.submenu_of(handles, info)?;
        apply(self.item_mut(holder, position), info, submenu);
        Ok(())
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
        let (holder, position) = self.find(menu, item).ok_or(Failure::ItemNotFound)?;
        let record = self.item(holder, position);
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
            text_length: u32::from(record.text_length),
            text: [0; MENU_ITEM_TEXT],
        };
        answer.text = record.text;
        Ok(answer)
    }

    /// CheckMenuItem: the item's check set or cleared (MF_CHECKED in `flags`); its previous check
    /// (MF_CHECKED or 0).
    pub fn check(&mut self, menu: MenuId, item: ItemRef, flags: u32) -> Result<u32, Failure> {
        let (holder, position) = self.find(menu, item).ok_or(Failure::ItemNotFound)?;
        let item = self.item_mut(holder, position);
        let previous = item.state & MF_CHECKED;
        item.state = item.state & !MF_CHECKED | flags & MF_CHECKED;
        Ok(previous)
    }

    /// EnableMenuItem: the item's MF_GRAYED and MF_DISABLED bits set to `flags`'; its previous
    /// ones.
    pub fn enable(&mut self, menu: MenuId, item: ItemRef, flags: u32) -> Result<u32, Failure> {
        let (holder, position) = self.find(menu, item).ok_or(Failure::ItemNotFound)?;
        let item = self.item_mut(holder, position);
        let bits = MF_GRAYED | MF_DISABLED;
        let previous = item.state & bits;
        item.state = item.state & !bits | flags & bits;
        Ok(previous)
    }

    /// Destroy `menu` and the popups its items open, their items with them: DestroyMenu, which
    /// Windows documents as recursive.
    pub fn destroy(&mut self, handles: &mut UserHandles, menu: MenuId) {
        self.destroy_at(handles, menu, 0);
    }

    fn destroy_at(&mut self, handles: &mut UserHandles, menu: MenuId, depth: u32) {
        if !self.is_live(menu) {
            return;
        }
        let record = *self.at(menu);
        handles.close(record.handle);
        let slot = self.at_mut(menu);
        slot.live = false;
        slot.generation = slot.generation.wrapping_add(1);
        slot.count = 0;
        for &index in &record.items[..record.count as usize] {
            let sub = self.items[index as usize].submenu;
            self.items[index as usize] = Item::EMPTY;
            if let Some(sub) = sub {
                if depth < MAX_DEPTH {
                    self.destroy_at(handles, sub, depth + 1);
                }
            }
        }
    }

    /// Destroy every menu of the process `owner`, at its end.
    pub fn destroy_owner(&mut self, handles: &mut UserHandles, owner: Owner) {
        for index in 0..MENUS {
            let record = &self.menus[index];
            if record.live && record.owner == owner {
                let id = MenuId {
                    index: index as u16,
                    generation: record.generation,
                };
                self.destroy(handles, id);
            }
        }
    }

    /// How many menus are live.
    pub fn live(&self) -> usize {
        self.menus.iter().filter(|m| m.live).count()
    }
}

/// Set `item`'s fields as `info`'s mask names them (MIIM_TYPE the type and the text, MIIM_FTYPE
/// the type alone, MIIM_STRING the text alone).
fn apply(item: &mut Item, info: &ItemInfo<'_>, submenu: Option<MenuId>) {
    if info.mask & (MIIM_TYPE | MIIM_FTYPE) != 0 {
        item.item_type = info.item_type & TYPE_BITS;
    }
    if info.mask & MIIM_STATE != 0 {
        item.state = info.state & STATE_BITS;
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
    };

    use super::*;
    use crate::nt::call::{Handle, NtCall, NtResult, UserAddr, UserPtr};
    use crate::win32k::queue::with_manager;
    use crate::win32k::winsta::gui_thread;

    /// NtUserCallNoParam(Routine, Result): CreateMenu, CreatePopupMenu (the new menu's handle),
    /// the empty cursor object LoadIcon fills in (its handle); STATUS_INVALID_PARAMETER for another
    /// routine.
    pub fn call_no_param(call: &mut NtCall, routine: u32, result: UserPtr<u32>) -> NtResult {
        let caller = gui_thread(call)?;
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
                        windows.menus.set(&windows.handles, id, item, &fields)
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

    /// NtUserSetMenu(Window, Menu, Repaint): the window's menu set. Nothing is drawn: the menu
    /// bar comes with the non-client area.
    pub fn set_menu(call: &mut NtCall, window: Handle, menu: Handle, _repaint: bool) -> NtResult {
        gui_thread(call)?;
        with_manager(call.passive(), |m| {
            m.windows.set_menu_handle(window.raw(), menu.raw())
        })
        .map_err(Failure::status)?;
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
    destroy_menu,
    enable_menu_item,
    set_menu,
    thunked_menu_item_info,
};

#[cfg(test)]
mod tests {
    use std::boxed::Box;

    use rtl::menu::{MFS_CHECKED, MFT_RADIOCHECK};

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

        fn set(&mut self, menu: MenuId, item: ItemRef, info: &ItemInfo<'_>) {
            self.menus.set(&self.handles, menu, item, info).unwrap();
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

    fn units(text: &str) -> std::vec::Vec<u16> {
        text.encode_utf16().collect()
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
        let text = units(text);
        let info = ItemInfo {
            mask: MIIM_FTYPE | MIIM_STATE | MIIM_ID | MIIM_SUBMENU | MIIM_STRING,
            item_type,
            state,
            id,
            submenu,
            item_data: 0,
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
            (220, 0, &units("&Help")[..])
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
            text: &[],
        };
        m.set(view, ItemRef::Command(212), &info);
        let item = m.query_item(view, ItemRef::Position(1)).unwrap();
        assert_eq!(
            (item.item_type, item.state, item.id),
            (MFT_RADIOCHECK, MFS_CHECKED, 212)
        );
        assert_eq!(item.text(), &units("S&cientific")[..]);
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
        assert!(m.items.iter().all(|item| !item.used));
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
}
