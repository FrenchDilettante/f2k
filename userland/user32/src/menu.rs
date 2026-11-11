//! Menus: CreateMenu and CreatePopupMenu, LoadMenuW and LoadMenuA, the item calls
//! (GetMenuItemCount, GetMenuItemID, GetSubMenu, GetMenuState, GetMenuStringA/W, CheckMenuItem,
//! CheckMenuRadioItem, EnableMenuItem), IsMenu, DestroyMenu, and a window's menu (GetMenu,
//! SetMenu), over win32k's menu services ([`imports`]).
//!
//! A menu is a win32k object. LoadMenu reads a MENU or MENUEX resource here, as Windows 2000's
//! user32 does (rtl::menu's [`Template`]), and builds the menu through the services: the bar
//! (CreateMenu's NtUserCallNoParam), each popup before the item that opens it (CreatePopupMenu's),
//! each item inserted at its level's end (InsertMenuItem's NtUserThunkedMenuItemInfo). A MENU
//! popup's item has the popup's handle for its id, as AppendMenu gives it one.
//!
//! What Windows 2000's user32 reads from a menu's record mapped into its process, F2K's asks the
//! kernel for (NtUserThunkedMenuItemInfo's queries): an item's type, state, id, popup and text, or
//! the menu's item count. What the calls answer, as the menus fixture's capture shows it:
//!
//! - a handle naming no menu is ERROR_INVALID_MENU_HANDLE, IsMenu and GetMenuItemCount's NULL
//!   included;
//! - an item that is not there answers -1 (GetMenuItemID, GetMenuState, CheckMenuItem,
//!   EnableMenuItem) or NULL (GetSubMenu) with the last error untouched; GetMenuString answers 0
//!   with ERROR_MENU_ITEM_NOT_FOUND, its buffer's first character set to NUL first;
//! - GetMenuState answers the item's type and state, a popup's low byte with MF_POPUP and its item
//!   count in the high byte (rtl::menu's [`state_word`]); GetMenuItemID answers -1 for a popup;
//! - CheckMenuRadioItem unchecks every item of the range but the one it checks, which gets the
//!   radio check and the check; it answers whether that item was in the range, and a range whose
//!   first command names no item is ERROR_MENU_ITEM_NOT_FOUND.

use rtl::edge::OutBuf;
use rtl::menu::*;
use rtl::status::{
    NtStatus,
    STATUS_INVALID_HANDLE,
    STATUS_INVALID_PARAMETER,
    STATUS_OBJECT_NAME_NOT_FOUND,
    STATUS_OBJECT_TYPE_MISMATCH,
};
use rtl::user::{NO_PARAM_CREATE_MENU, NO_PARAM_CREATE_POPUP_MENU};
use rtl::window::QUERY_WINDOW_MENU;

use crate::imports::{self, ResourceName};
use crate::{failed, failed_with};

/// RT_MENU: a menu template's resource type.
const RT_MENU: u16 = 4;

/// ERROR_INVALID_MENU_HANDLE, ERROR_CHILD_WINDOW_MENU, ERROR_MENU_ITEM_NOT_FOUND,
/// ERROR_INVALID_DATA.
pub const ERROR_INVALID_MENU_HANDLE: u32 = 1401;
pub const ERROR_CHILD_WINDOW_MENU: u32 = 1436;
pub const ERROR_MENU_ITEM_NOT_FOUND: u32 = 1456;
const ERROR_INVALID_DATA: u32 = 13;

/// The popups a template nests at most (a deeper one is refused as bad data).
const MAX_DEPTH: u32 = 16;

/// The Win32 error of a failed menu service: a handle naming no menu is
/// ERROR_INVALID_MENU_HANDLE, no such item ERROR_MENU_ITEM_NOT_FOUND, a window naming nothing
/// ERROR_INVALID_WINDOW_HANDLE (the kernel's menu module), anything else what ntdll maps it to.
pub fn menu_error(status: NtStatus) -> u32 {
    match status.0 {
        STATUS_OBJECT_TYPE_MISMATCH => ERROR_INVALID_MENU_HANDLE,
        STATUS_OBJECT_NAME_NOT_FOUND => ERROR_MENU_ITEM_NOT_FOUND,
        STATUS_INVALID_HANDLE => crate::ERROR_INVALID_WINDOW_HANDLE,
        _ => imports::dos_error(status),
    }
}

/// The item `item` names in `menu` (MF_BYPOSITION in `flags`), as the kernel answers it.
pub fn query(menu: usize, item: u32, flags: u32) -> Result<MenuItemAnswer, NtStatus> {
    let mut answer = MenuItemAnswer::EMPTY;
    imports::query_menu(
        menu,
        item,
        flags & MF_BYPOSITION,
        MENU_ITEM_QUERY,
        &mut answer,
    )?;
    Ok(answer)
}

/// The item's answer, none for no such item; the menu's failure (a handle naming no menu) made
/// the last error.
fn query_quiet(menu: usize, item: u32, flags: u32) -> Result<Option<MenuItemAnswer>, ()> {
    match query(menu, item, flags) {
        Ok(answer) => Ok(Some(answer)),
        Err(status) if status.0 == STATUS_OBJECT_NAME_NOT_FOUND => Ok(None),
        Err(status) => {
            imports::set_last_error(menu_error(status));
            Err(())
        }
    }
}

// --- LoadMenu
// --------------------------------------------------------------------------------------

/// LoadMenuW: the menu the module's MENU or MENUEX resource `name` describes (NULL: the program's
/// module), a new one each call; NULL with the last error when the module has no such resource.
///
/// # Safety
///
/// `name` is a resource number (its high word zero) or the address of a NUL-terminated UTF-16
/// string, as for the platform's.
#[unsafe(export_name = "f2k_export_LoadMenuW")]
pub unsafe extern "system" fn load_menu_w(instance: usize, name: *const u16) -> usize {
    // SAFETY: the caller's contract.
    unsafe { load_menu(instance, ResourceName::Wide(name as usize)) }
}

/// LoadMenuA: LoadMenuW's, the name an ANSI string or a number.
///
/// # Safety
///
/// As LoadMenuW's, the string ANSI.
#[unsafe(export_name = "f2k_export_LoadMenuA")]
pub unsafe extern "system" fn load_menu_a(instance: usize, name: *const u8) -> usize {
    // SAFETY: the caller's contract.
    unsafe { load_menu(instance, ResourceName::Narrow(name as usize)) }
}

/// LoadMenu's core: the resource found and read, the menu built.
///
/// # Safety
///
/// A string `name` is the caller's NUL-terminated string.
unsafe fn load_menu(instance: usize, name: ResourceName) -> usize {
    // SAFETY: the caller's contract.
    let Some(found) = (unsafe { imports::find_named_resource(instance, RT_MENU, name) }) else {
        return 0;
    };
    let Some(data) = imports::resource_data(instance, found) else {
        return 0;
    };
    build_menu(data).unwrap_or(0)
}

/// The menu a template's data describes, built through the services; none with the last error
/// (ERROR_INVALID_DATA for a template cut short or nested too deep, a service's failure), the
/// part already built destroyed.
pub fn build_menu(data: &[u8]) -> Option<usize> {
    let Some(mut template) = Template::new(data) else {
        return failed(ERROR_INVALID_DATA);
    };
    let bar = failed_with(imports::call_no_param(NO_PARAM_CREATE_MENU), menu_error)? as usize;
    match build_level(&mut template, bar, 0) {
        Ok(()) => Some(bar),
        Err(error) => {
            let _ = imports::destroy_menu(bar);
            failed(error)
        }
    }
}

/// One level of a template: its items inserted into `menu` up to the level's last, each popup
/// built before the item that opens it.
fn build_level(template: &mut Template<'_>, menu: usize, depth: u32) -> Result<(), u32> {
    if depth > MAX_DEPTH {
        return Err(ERROR_INVALID_DATA);
    }
    loop {
        let item = template.next().ok_or(ERROR_INVALID_DATA)?;
        let mut submenu = 0;
        if item.popup {
            submenu =
                imports::call_no_param(NO_PARAM_CREATE_POPUP_MENU).map_err(menu_error)? as usize;
            if let Err(error) = build_level(template, submenu, depth + 1) {
                let _ = imports::destroy_menu(submenu);
                return Err(error);
            }
        }
        let mut units = [0u16; MENU_ITEM_TEXT];
        let length = (item.text.len() / 2).min(MENU_ITEM_TEXT);
        let (pairs, _) = item.text.as_chunks::<2>();
        for (unit, &bytes) in units.iter_mut().zip(pairs) {
            *unit = u16::from_le_bytes(bytes);
        }
        let id = if item.popup && !template.extended() {
            submenu as u32
        } else {
            item.id
        };
        let info = MenuItemInfoW {
            size: core::mem::size_of::<MenuItemInfoW>() as u32,
            mask: MIIM_FTYPE | MIIM_STATE | MIIM_ID | MIIM_SUBMENU | MIIM_STRING,
            item_type: item.item_type,
            state: item.state,
            id,
            submenu: submenu as u32,
            ..MenuItemInfoW::default()
        };
        if let Err(status) = imports::set_menu_item(
            menu,
            u32::MAX,
            MF_BYPOSITION,
            MENU_ITEM_INSERT,
            &info,
            &units[..length],
        ) {
            if submenu != 0 {
                let _ = imports::destroy_menu(submenu);
            }
            return Err(menu_error(status));
        }
        if item.last {
            return Ok(());
        }
    }
}

// --- The menu and its items
// ------------------------------------------------------------------------

/// CreateMenu: a new, empty menu bar; NULL with the last error when win32k has no room.
#[unsafe(export_name = "f2k_export_CreateMenu")]
pub extern "system" fn create_menu() -> usize {
    failed_with(imports::call_no_param(NO_PARAM_CREATE_MENU), menu_error).map_or(0, |m| m as usize)
}

/// CreatePopupMenu: a new, empty popup menu; NULL with the last error when win32k has no room.
#[unsafe(export_name = "f2k_export_CreatePopupMenu")]
pub extern "system" fn create_popup_menu() -> usize {
    failed_with(
        imports::call_no_param(NO_PARAM_CREATE_POPUP_MENU),
        menu_error,
    )
    .map_or(0, |m| m as usize)
}

/// AppendMenu's core: an item at the end of `menu`, its type and state from the old flags (a
/// separator grayed, as a template's is), the popup `item` opens for MF_POPUP (its handle its id,
/// as a MENU template's popup has), the command id `item` otherwise, its text `text` (none for a
/// separator); TRUE, or FALSE with the last error. Bitmap and owner-drawn items are not served:
/// their `item` is taken as text no more.
fn append(menu: usize, flags: u32, item: usize, text: &[u16]) -> i32 {
    let (item_type, state) = from_flags(flags);
    let popup = flags & MF_POPUP != 0;
    let info = MenuItemInfoW {
        size: core::mem::size_of::<MenuItemInfoW>() as u32,
        mask: MIIM_FTYPE | MIIM_STATE | MIIM_ID | MIIM_SUBMENU | MIIM_STRING,
        item_type,
        state,
        id: item as u32,
        submenu: if popup { item as u32 } else { 0 },
        ..MenuItemInfoW::default()
    };
    let text = &text[..text.len().min(MENU_ITEM_TEXT)];
    failed_with(
        imports::set_menu_item(menu, u32::MAX, MF_BYPOSITION, MENU_ITEM_INSERT, &info, text),
        menu_error,
    )
    .is_some() as i32
}

/// Whether AppendMenu's `flags` make an item whose `item` pointer is its text: a string item, not
/// a separator, a bitmap or an owner-drawn one, with a text given.
fn has_text(flags: u32, text: usize) -> bool {
    flags & (MF_SEPARATOR | MF_OWNERDRAW | MFT_BITMAP) == 0 && text != 0
}

/// AppendMenuW: an item at the end of the menu (see [`append`]); TRUE, or FALSE with the last
/// error (ERROR_INVALID_MENU_HANDLE for a handle naming no menu).
///
/// # Safety
///
/// The caller's string, for a string item, as for the platform's.
#[unsafe(export_name = "f2k_export_AppendMenuW")]
pub unsafe extern "system" fn append_menu_w(
    menu: usize,
    flags: u32,
    item: usize,
    text: *const u16,
) -> i32 {
    if !has_text(flags, text as usize) {
        return append(menu, flags, item, &[]);
    }
    // SAFETY: a string item's text, NUL-terminated, as the caller hands it over.
    let text = unsafe { rtl::edge::InWStr::new(text) };
    let units = text.units();
    let mut buffer = [0u16; MENU_ITEM_TEXT];
    let length = units.len().min(MENU_ITEM_TEXT);
    for (index, unit) in buffer.iter_mut().take(length).enumerate() {
        *unit = units.get(index);
    }
    append(menu, flags, item, &buffer[..length])
}

/// AppendMenuA: AppendMenuW's, its text narrow.
///
/// # Safety
///
/// The caller's string, for a string item, as for the platform's.
#[unsafe(export_name = "f2k_export_AppendMenuA")]
pub unsafe extern "system" fn append_menu_a(
    menu: usize,
    flags: u32,
    item: usize,
    text: *const u8,
) -> i32 {
    if !has_text(flags, text as usize) {
        return append(menu, flags, item, &[]);
    }
    // SAFETY: a string item's text, NUL-terminated, as the caller hands it over.
    let text = unsafe { rtl::edge::InStr::new(text) };
    crate::with_wide(text.bytes(), |units| {
        let length = units.len().saturating_sub(1);
        append(menu, flags, item, &units[..length])
    })
    .unwrap_or(0)
}

/// IsMenu: TRUE for a handle naming a menu; FALSE with ERROR_INVALID_MENU_HANDLE otherwise.
#[unsafe(export_name = "f2k_export_IsMenu")]
pub extern "system" fn is_menu(menu: usize) -> i32 {
    let mut answer = MenuItemAnswer::EMPTY;
    failed_with(
        imports::query_menu(menu, 0, 0, MENU_QUERY, &mut answer),
        menu_error,
    )
    .is_some() as i32
}

/// DestroyMenu: the menu and its popups destroyed; FALSE with ERROR_INVALID_MENU_HANDLE for a
/// handle naming none.
#[unsafe(export_name = "f2k_export_DestroyMenu")]
pub extern "system" fn destroy_menu(menu: usize) -> i32 {
    failed_with(imports::destroy_menu(menu), menu_error).is_some() as i32
}

/// GetMenuItemCount: how many items the menu holds; -1 with ERROR_INVALID_MENU_HANDLE for a
/// handle naming none.
#[unsafe(export_name = "f2k_export_GetMenuItemCount")]
pub extern "system" fn get_menu_item_count(menu: usize) -> i32 {
    let mut answer = MenuItemAnswer::EMPTY;
    failed_with(
        imports::query_menu(menu, 0, 0, MENU_QUERY, &mut answer),
        menu_error,
    )
    .map_or(-1, |()| answer.count as i32)
}

/// GetMenuItemID: the command id of the item at `position`; -1 for a popup's item or no item.
#[unsafe(export_name = "f2k_export_GetMenuItemID")]
pub extern "system" fn get_menu_item_id(menu: usize, position: i32) -> u32 {
    match query_quiet(menu, position as u32, MF_BYPOSITION) {
        Ok(Some(item)) if item.submenu == 0 => item.id,
        _ => u32::MAX,
    }
}

/// GetSubMenu: the popup the item at `position` opens; NULL for an item that opens none, or no
/// item.
#[unsafe(export_name = "f2k_export_GetSubMenu")]
pub extern "system" fn get_sub_menu(menu: usize, position: i32) -> usize {
    match query_quiet(menu, position as u32, MF_BYPOSITION) {
        Ok(Some(item)) => item.submenu as usize,
        _ => 0,
    }
}

/// GetMenuState: the item's GetMenuState word ([`state_word`]); -1 for no item.
#[unsafe(export_name = "f2k_export_GetMenuState")]
pub extern "system" fn get_menu_state(menu: usize, item: u32, flags: u32) -> u32 {
    match query_quiet(menu, item, flags) {
        Ok(Some(item)) => state_word(
            item.item_type,
            item.state,
            (item.submenu != 0).then_some(item.submenu_count),
        ),
        _ => u32::MAX,
    }
}

/// GetMenuStringW: the item's text into the buffer, as far as `max - 1` characters and a NUL;
/// with no buffer (or a `max` of 0) its length. 0 with ERROR_MENU_ITEM_NOT_FOUND for no item.
///
/// # Safety
///
/// `buffer` is null or the caller's buffer of `max` characters, as for the platform's.
#[unsafe(export_name = "f2k_export_GetMenuStringW")]
pub unsafe extern "system" fn get_menu_string_w(
    menu: usize,
    item: u32,
    buffer: *mut u16,
    max: i32,
    flags: u32,
) -> i32 {
    // SAFETY: the caller's contract.
    let buffer = unsafe { OutBuf::optional(buffer, max.max(0) as usize) };
    menu_string(menu, item, flags, buffer, |text, out| {
        out[..text.len()].copy_from_slice(text);
        text.len()
    })
}

/// GetMenuStringA: GetMenuStringW's, the text converted to the ANSI code page (through ntdll's
/// RtlUnicodeToMultiByteN) and counted in bytes.
///
/// # Safety
///
/// `buffer` is null or the caller's buffer of `max` bytes, as for the platform's.
#[unsafe(export_name = "f2k_export_GetMenuStringA")]
pub unsafe extern "system" fn get_menu_string_a(
    menu: usize,
    item: u32,
    buffer: *mut u8,
    max: i32,
    flags: u32,
) -> i32 {
    // SAFETY: the caller's contract.
    let buffer = unsafe { OutBuf::optional(buffer, max.max(0) as usize) };
    menu_string(menu, item, flags, buffer, |text, out| {
        imports::unicode_to_multi_byte(out, text)
    })
}

/// GetMenuString's core over a buffer of `T` (units or bytes): its first value set to NUL, the
/// item's text converted by `convert` (into a scratch buffer of its own; the count it answers is
/// the text's length in `T`), as much of it as the buffer holds with a NUL after it.
fn menu_string<T: Copy + Default + From<u8>>(
    menu: usize,
    item: u32,
    flags: u32,
    mut buffer: Option<OutBuf<'_, T>>,
    convert: impl FnOnce(&[u16], &mut [T]) -> usize,
) -> i32 {
    if let Some(buffer) = buffer.as_mut().filter(|b| !b.is_empty()) {
        buffer.set(0, T::from(0));
    }
    let answer = match failed_with(query(menu, item, flags), menu_error) {
        Some(answer) => answer,
        None => return 0,
    };
    let mut scratch = [T::default(); 2 * MENU_ITEM_TEXT];
    let length = convert(answer.text(), &mut scratch);
    let Some(mut buffer) = buffer.filter(|b| !b.is_empty()) else {
        return length as i32;
    };
    let copied = length.min(buffer.len() - 1);
    buffer.put(&scratch[..copied]);
    buffer.set(copied, T::from(0));
    copied as i32
}

/// CheckMenuItem: the item's check set (MF_CHECKED) or cleared; its previous check, -1 for no
/// item.
#[unsafe(export_name = "f2k_export_CheckMenuItem")]
pub extern "system" fn check_menu_item(menu: usize, item: u32, check: u32) -> u32 {
    previous_state(imports::check_menu_item(menu, item, check))
}

/// EnableMenuItem: the item's MF_GRAYED and MF_DISABLED bits set; its previous ones, -1 for no
/// item.
#[unsafe(export_name = "f2k_export_EnableMenuItem")]
pub extern "system" fn enable_menu_item(menu: usize, item: u32, enable: u32) -> u32 {
    previous_state(imports::enable_menu_item(menu, item, enable))
}

/// A change's previous state; -1 for no item (the last error untouched) or a handle naming no
/// menu (ERROR_INVALID_MENU_HANDLE).
fn previous_state(answer: Result<u32, NtStatus>) -> u32 {
    match answer {
        Ok(previous) => previous,
        Err(status) if status.0 == STATUS_OBJECT_NAME_NOT_FOUND => u32::MAX,
        Err(status) => {
            imports::set_last_error(menu_error(status));
            u32::MAX
        }
    }
}

/// CheckMenuRadioItem: the items from `first` to `last` (by command, the menu holding `first`'s
/// item and its positions there; by position, the menu's own) unchecked, but the one `check`
/// names, which gets the radio check and the check. TRUE when it was in the range; FALSE with
/// ERROR_MENU_ITEM_NOT_FOUND when `first` or `last` names no item.
#[unsafe(export_name = "f2k_export_CheckMenuRadioItem")]
pub extern "system" fn check_menu_radio_item(
    menu: usize,
    first: u32,
    last: u32,
    check: u32,
    flags: u32,
) -> i32 {
    let by_position = flags & MF_BYPOSITION != 0;
    let (holder, from, to) = if by_position {
        let mut answer = MenuItemAnswer::EMPTY;
        if failed_with(
            imports::query_menu(menu, 0, 0, MENU_QUERY, &mut answer),
            menu_error,
        )
        .is_none()
        {
            return 0;
        }
        (menu, first, last.min(answer.count.saturating_sub(1)))
    } else {
        let Some(start) = failed_with(query(menu, first, MF_BYCOMMAND), menu_error) else {
            return 0;
        };
        let Some(end) = failed_with(query(start.holder as usize, last, MF_BYCOMMAND), menu_error)
        else {
            return 0;
        };
        (start.holder as usize, start.position, end.position)
    };
    let mut checked = false;
    for position in from.min(to)..=from.max(to) {
        let Ok(item) = query(holder, position, MF_BYPOSITION) else {
            continue;
        };
        let is_check = if by_position {
            position == check
        } else {
            item.id == check
        };
        let (item_type, state) = if is_check {
            checked = true;
            (item.item_type | MFT_RADIOCHECK, item.state | MFS_CHECKED)
        } else {
            (item.item_type, item.state & !MFS_CHECKED)
        };
        let info = MenuItemInfoW {
            size: core::mem::size_of::<MenuItemInfoW>() as u32,
            mask: MIIM_FTYPE | MIIM_STATE,
            item_type,
            state,
            ..MenuItemInfoW::default()
        };
        let _ = imports::set_menu_item(holder, position, MF_BYPOSITION, MENU_ITEM_SET, &info, &[]);
    }
    checked as i32
}

// --- A window's menu
// -------------------------------------------------------------------------------

/// GetMenu: the window's menu (a child window's id); NULL for none, or with
/// ERROR_INVALID_WINDOW_HANDLE for a handle naming no window.
#[unsafe(export_name = "f2k_export_GetMenu")]
pub extern "system" fn get_menu(window: usize) -> usize {
    let mut menu = 0u32;
    crate::answered(imports::query_window(window, QUERY_WINDOW_MENU, &mut menu))
        .map_or(0, |()| menu as usize)
}

/// SetMenu: the window's menu set (NULL: none), the one it held kept; FALSE with
/// ERROR_INVALID_WINDOW_HANDLE, ERROR_INVALID_MENU_HANDLE, or ERROR_CHILD_WINDOW_MENU for a child
/// window.
#[unsafe(export_name = "f2k_export_SetMenu")]
pub extern "system" fn set_menu(window: usize, menu: usize) -> i32 {
    failed_with(imports::set_menu(window, menu), |status| match status.0 {
        STATUS_INVALID_PARAMETER => ERROR_CHILD_WINDOW_MENU,
        _ => menu_error(status),
    })
    .is_some() as i32
}

#[cfg(test)]
mod tests {
    use std::vec::Vec;

    use super::*;
    use crate::imports::host::{add_resource, LAST_ERROR, PROGRAM};

    fn last_error() -> u32 {
        LAST_ERROR.with(|error| error.get())
    }

    fn units(text: &str) -> Vec<u8> {
        text.encode_utf16()
            .chain([0])
            .flat_map(|u| u.to_le_bytes())
            .collect()
    }

    /// The menus fixture's menu 200 (menus.rc), as the resource compiler writes it.
    fn menu_200() -> Vec<u8> {
        let mut data = std::vec![0, 0, 0, 0];
        let popup = |data: &mut Vec<u8>, flags: u16, text: &str| {
            data.extend_from_slice(&flags.to_le_bytes());
            data.extend(units(text));
        };
        let item = |data: &mut Vec<u8>, flags: u16, id: u16, text: &str| {
            data.extend_from_slice(&flags.to_le_bytes());
            data.extend_from_slice(&id.to_le_bytes());
            data.extend(units(text));
        };
        popup(&mut data, 0x10, "&File");
        item(&mut data, 0, 201, "&New");
        item(&mut data, 1, 202, "&Open");
        item(&mut data, 0, 0, "");
        popup(&mut data, 0x10, "&Recent");
        item(&mut data, 0x80, 205, "First");
        item(&mut data, 0x88, 203, "E&xit");
        popup(&mut data, 0x10, "&View");
        item(&mut data, 8, 211, "&Standard");
        item(&mut data, 0, 212, "S&cientific");
        item(&mut data, 0x80, 213, "&Programmer");
        item(&mut data, 0x80, 220, "&Help");
        data
    }

    fn load() -> usize {
        add_resource(PROGRAM, RT_MENU, 200, &menu_200());
        // SAFETY: a resource number.
        unsafe { load_menu_w(0, 200 as *const u16) }
    }

    fn string_w(menu: usize, item: u32, max: i32, flags: u32) -> (i32, std::string::String) {
        let mut buffer = [0x23u16; 32];
        // SAFETY: the test's buffer, as long as `max` says (at most 32).
        let n = unsafe { get_menu_string_w(menu, item, buffer.as_mut_ptr(), max, flags) };
        let end = buffer.iter().position(|&u| u == 0).unwrap_or(32);
        (n, std::string::String::from_utf16(&buffer[..end]).unwrap())
    }

    /// LoadMenu builds the template's menu; the items answer as the items section's capture.
    ///
    /// Pins: user32.LoadMenuW, user32.GetMenuItemCount, user32.GetMenuItemID, user32.GetSubMenu,
    /// user32.GetMenuState, user32.GetMenuStringW
    #[test]
    fn loaded_menus_answer_as_the_capture() {
        let bar = load();
        assert_ne!(bar, 0);
        assert_eq!(is_menu(bar), 1);
        let file = get_sub_menu(bar, 0);
        let recent = get_sub_menu(file, 3);
        assert_eq!(get_menu_item_count(bar), 3);
        assert_eq!(get_menu_item_count(file), 5);
        assert_eq!(get_menu_item_count(recent), 1);
        assert_eq!(get_menu_item_count(0), -1);
        assert_eq!(last_error(), ERROR_INVALID_MENU_HANDLE);
        assert_eq!(get_menu_item_id(bar, 0), u32::MAX);
        assert_eq!(get_menu_state(bar, 0, MF_BYPOSITION), 0x510);
        assert_eq!(get_menu_state(bar, 1, MF_BYPOSITION), 0x310);
        assert_eq!(get_menu_item_id(bar, 2), 220);
        assert_eq!(get_menu_state(bar, 3, MF_BYPOSITION), u32::MAX);
        assert_eq!(get_menu_item_id(file, 2), 0);
        assert_eq!(get_menu_state(file, 2, MF_BYPOSITION), 0x803);
        assert_eq!(get_menu_state(file, 1, MF_BYPOSITION), 0x1);
        assert_eq!(get_menu_state(bar, 203, MF_BYCOMMAND), 0x8);
        assert_eq!(get_menu_state(bar, 205, MF_BYCOMMAND), 0x0);
        assert_eq!(string_w(bar, 0, 32, MF_BYPOSITION), (5, "&File".into()));
        assert_eq!(string_w(bar, 205, 32, MF_BYCOMMAND), (5, "First".into()));
        assert_eq!(string_w(bar, 203, 3, MF_BYCOMMAND), (2, "E&".into()));
        assert_eq!(string_w(bar, 203, 1, MF_BYCOMMAND), (0, "".into()));
        LAST_ERROR.with(|error| error.set(0));
        assert_eq!(string_w(bar, 3, 32, MF_BYPOSITION), (0, "".into()));
        assert_eq!(last_error(), ERROR_MENU_ITEM_NOT_FOUND);
        // SAFETY: no buffer.
        let length = unsafe { get_menu_string_w(bar, 203, core::ptr::null_mut(), 0, 0) };
        assert_eq!(length, 5);
        assert_eq!(destroy_menu(bar), 1);
        assert_eq!(is_menu(bar), 0);
        assert_eq!(destroy_menu(bar), 0);
    }

    /// CheckMenuRadioItem's range and check, as the check section's capture.
    ///
    /// Pins: user32.CheckMenuRadioItem, user32.CheckMenuItem
    #[test]
    fn radio_checks_follow_the_capture() {
        let bar = load();
        let view = get_sub_menu(bar, 1);
        let states = || -> [u32; 3] {
            [0, 1, 2].map(|position| get_menu_state(view, position, MF_BYPOSITION))
        };
        assert_eq!(check_menu_radio_item(view, 211, 213, 212, MF_BYCOMMAND), 1);
        assert_eq!(states(), [0x0, 0x208, 0x0]);
        assert_eq!(check_menu_radio_item(view, 0, 2, 2, MF_BYPOSITION), 1);
        assert_eq!(states(), [0x0, 0x200, 0x208]);
        assert_eq!(check_menu_radio_item(bar, 211, 213, 211, MF_BYCOMMAND), 1);
        assert_eq!(states(), [0x208, 0x200, 0x200]);
        assert_eq!(check_menu_radio_item(view, 0, 1, 2, MF_BYPOSITION), 0);
        assert_eq!(states(), [0x200, 0x200, 0x200]);
        LAST_ERROR.with(|error| error.set(0));
        assert_eq!(check_menu_radio_item(view, 290, 295, 291, MF_BYCOMMAND), 0);
        assert_eq!(last_error(), ERROR_MENU_ITEM_NOT_FOUND);
        assert_eq!(check_menu_item(view, 212, MF_CHECKED), 0);
        assert_eq!(states(), [0x200, 0x208, 0x200]);
        assert_eq!(check_menu_item(bar, 299, MF_CHECKED), u32::MAX);
        assert_eq!(enable_menu_item(bar, 202, MF_ENABLED), 1);
    }
}
