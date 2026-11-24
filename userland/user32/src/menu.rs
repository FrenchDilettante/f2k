//! Menus: CreateMenu and CreatePopupMenu, LoadMenuW and LoadMenuA, the item calls
//! (GetMenuItemCount, GetMenuItemID, GetSubMenu, GetMenuState, GetMenuStringA/W, CheckMenuItem,
//! CheckMenuRadioItem, EnableMenuItem), the old-flags edits (AppendMenuA/W, InsertMenuA/W,
//! ModifyMenuA/W, RemoveMenu, DeleteMenu), the default item (SetMenuDefaultItem,
//! GetMenuDefaultItem), IsMenu, DestroyMenu, a window's menu (GetMenu, SetMenu) and its system menu
//! (GetSystemMenu), over win32k's menu services ([`imports`]). The MENUITEMINFO calls are
//! [`crate::menuinfo`]'s.
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
use rtl::status::NtStatus;
use rtl::user::{NO_PARAM_CREATE_MENU, NO_PARAM_CREATE_POPUP_MENU};
use rtl::window::QUERY_WINDOW_MENU;

use crate::imports::{self, ResourceName};
use crate::{failed, failed_with, window_error};

/// RT_MENU: a menu template's resource type.
const RT_MENU: u16 = 4;

use rtl::winerror::{ERROR_INVALID_DATA, ERROR_MENU_ITEM_NOT_FOUND};

/// The popups a template nests at most (a deeper one is refused as bad data).
const MAX_DEPTH: u32 = 16;

/// Whether a menu service's failure is ERROR_MENU_ITEM_NOT_FOUND, the kernel's own: no such item,
/// which the item calls answer with the last error untouched.
fn no_such_item(status: NtStatus) -> bool {
    status == NtStatus::from_win32(ERROR_MENU_ITEM_NOT_FOUND)
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
        Err(status) if no_such_item(status) => Ok(None),
        Err(status) => {
            imports::set_last_error(window_error(status));
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
    let bar = failed_with(imports::call_no_param(NO_PARAM_CREATE_MENU), window_error)? as usize;
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
                imports::call_no_param(NO_PARAM_CREATE_POPUP_MENU).map_err(window_error)? as usize;
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
            return Err(window_error(status));
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
    failed_with(imports::call_no_param(NO_PARAM_CREATE_MENU), window_error)
        .map_or(0, |m| m as usize)
}

/// CreatePopupMenu: a new, empty popup menu; NULL with the last error when win32k has no room.
#[unsafe(export_name = "f2k_export_CreatePopupMenu")]
pub extern "system" fn create_popup_menu() -> usize {
    failed_with(
        imports::call_no_param(NO_PARAM_CREATE_POPUP_MENU),
        window_error,
    )
    .map_or(0, |m| m as usize)
}

/// The item the old flags describe (AppendMenu's, InsertMenu's, ModifyMenu's): its type and state
/// from the flags (a separator grayed, as a template's is), the popup `item` opens for MF_POPUP
/// (its handle its id, as a MENU template's popup has), the command id `item` otherwise, its text
/// set when `text` gives one. A string item given no text is a separator, as Windows 2000's
/// AppendMenu makes it (the menus fixture's `edit` capture: an MF_STRING item of NULL text answers
/// 0x803), when `textless` says so (an insertion's; a change keeps the item's text).
fn flags_item(flags: u32, item: usize, text: Option<&[u16]>, textless: bool) -> MenuItemInfoW {
    let string = flags & (MF_SEPARATOR | MF_OWNERDRAW | MFT_BITMAP) == 0;
    let flags = if string && text.is_none() && textless {
        flags | MF_SEPARATOR
    } else {
        flags
    };
    let (item_type, state) = from_flags(flags);
    let popup = flags & MF_POPUP != 0;
    let mut mask = MIIM_FTYPE | MIIM_STATE | MIIM_ID | MIIM_SUBMENU;
    if text.is_some() {
        mask |= MIIM_STRING;
    }
    MenuItemInfoW {
        size: core::mem::size_of::<MenuItemInfoW>() as u32,
        mask,
        item_type,
        state,
        id: item as u32,
        submenu: if popup { item as u32 } else { 0 },
        ..MenuItemInfoW::default()
    }
}

/// The old-flags calls' core: the item `flags` and `item` describe (see [`flags_item`]) inserted
/// before the item `position` names (InsertMenu, AppendMenu's at the end), or set on it
/// (ModifyMenu, `operation` MENU_ITEM_SET); TRUE, or FALSE with the last error. Bitmap and
/// owner-drawn items are not served: their `item` is taken as text no more. `args` are the
/// call's, logged for those.
fn edit_by_flags(
    entry: &rtl::stub::Entry,
    args: &[u64],
    (menu, position, operation): (usize, u32, u32),
    flags: u32,
    item: usize,
    text: Option<&[u16]>,
) -> i32 {
    for (flag, what) in [
        (MFT_BITMAP, "MF_BITMAP items (a bitmap for the text)"),
        (MF_OWNERDRAW, "MF_OWNERDRAW items (drawn by the owner)"),
    ] {
        if flags & flag != 0 && EDIT_LOGGED.first(flag) {
            // SAFETY: the call's arguments, its item a pointer's kind, not read.
            unsafe {
                crate::stub::unhandled(
                    entry,
                    format_args!("{what} are not yet implemented: an item without it is made"),
                    args,
                )
            };
        }
    }
    let info = flags_item(flags, item, text, operation == MENU_ITEM_INSERT);
    let text = text.unwrap_or(&[]);
    let text = &text[..text.len().min(MENU_ITEM_TEXT)];
    failed_with(
        imports::set_menu_item(
            menu,
            position,
            flags & MF_BYPOSITION,
            operation,
            &info,
            text,
        ),
        window_error,
    )
    .is_some() as i32
}

/// The old-flags calls' cases logged in this process.
static EDIT_LOGGED: rtl::stub::Logged<2> = rtl::stub::Logged::new();

/// Whether the old flags `flags` make an item whose `item` pointer is its text: a string item, not
/// a separator, a bitmap or an owner-drawn one, with a text given.
fn has_text(flags: u32, text: usize) -> bool {
    flags & (MF_SEPARATOR | MF_OWNERDRAW | MFT_BITMAP) == 0 && text != 0
}

/// Run `f` on a wide call's text (none for an item whose pointer is no text, [`has_text`]), cut
/// at an item's longest.
///
/// # Safety
///
/// For a string item, `text` is the caller's NUL-terminated string.
unsafe fn with_text_w<R>(flags: u32, text: *const u16, f: impl FnOnce(Option<&[u16]>) -> R) -> R {
    if !has_text(flags, text as usize) {
        return f(None);
    }
    // SAFETY: a string item's text, NUL-terminated, as the caller hands it over.
    let text = unsafe { rtl::edge::InWStr::new(text) };
    let units = text.units();
    let mut buffer = [0u16; MENU_ITEM_TEXT];
    let length = units.len().min(MENU_ITEM_TEXT);
    for (index, unit) in buffer.iter_mut().take(length).enumerate() {
        *unit = units.get(index);
    }
    f(Some(&buffer[..length]))
}

/// [`with_text_w`]'s narrow form: the text converted to UTF-16 (none when the conversion's buffer
/// could not be had, the last error set).
///
/// # Safety
///
/// For a string item, `text` is the caller's NUL-terminated string.
unsafe fn with_text_a<R>(
    flags: u32,
    text: *const u8,
    f: impl FnOnce(Option<&[u16]>) -> R,
) -> Option<R> {
    if !has_text(flags, text as usize) {
        return Some(f(None));
    }
    // SAFETY: a string item's text, NUL-terminated, as the caller hands it over.
    let text = unsafe { rtl::edge::InStr::new(text) };
    crate::with_wide(text.bytes(), |units| f(Some(units)))
}

/// AppendMenuW: an item at the end of the menu (see [`edit_by_flags`]); TRUE, or FALSE with the
/// last error (ERROR_INVALID_MENU_HANDLE for a handle naming no menu).
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
    let args = [menu as u64, u64::from(flags), item as u64, text as u64];
    let at = (menu, u32::MAX, MENU_ITEM_INSERT);
    let flags = flags | MF_BYPOSITION;
    // SAFETY: the caller's contract.
    unsafe {
        with_text_w(flags, text, |text| {
            edit_by_flags(&crate::spec::AppendMenuW, &args, at, flags, item, text)
        })
    }
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
    let args = [menu as u64, u64::from(flags), item as u64, text as u64];
    let at = (menu, u32::MAX, MENU_ITEM_INSERT);
    let flags = flags | MF_BYPOSITION;
    // SAFETY: the caller's contract.
    unsafe {
        with_text_a(flags, text, |text| {
            edit_by_flags(&crate::spec::AppendMenuA, &args, at, flags, item, text)
        })
    }
    .unwrap_or(0)
}

/// InsertMenuW: an item before the one `position` names (MF_BYPOSITION in `flags`: at the end when
/// it is past it; by command, in the menu holding that item, at the end when none has the
/// command, as the menus fixture's `edit` capture shows); TRUE, or FALSE with the last error.
///
/// # Safety
///
/// The caller's string, for a string item, as for the platform's.
#[unsafe(export_name = "f2k_export_InsertMenuW")]
pub unsafe extern "system" fn insert_menu_w(
    menu: usize,
    position: u32,
    flags: u32,
    item: usize,
    text: *const u16,
) -> i32 {
    let args = [
        menu as u64,
        u64::from(position),
        u64::from(flags),
        item as u64,
        text as u64,
    ];
    let at = (menu, position, MENU_ITEM_INSERT);
    // SAFETY: the caller's contract.
    unsafe {
        with_text_w(flags, text, |text| {
            edit_by_flags(&crate::spec::InsertMenuW, &args, at, flags, item, text)
        })
    }
}

/// InsertMenuA: InsertMenuW's, its text narrow.
///
/// # Safety
///
/// The caller's string, for a string item, as for the platform's.
#[unsafe(export_name = "f2k_export_InsertMenuA")]
pub unsafe extern "system" fn insert_menu_a(
    menu: usize,
    position: u32,
    flags: u32,
    item: usize,
    text: *const u8,
) -> i32 {
    let args = [
        menu as u64,
        u64::from(position),
        u64::from(flags),
        item as u64,
        text as u64,
    ];
    let at = (menu, position, MENU_ITEM_INSERT);
    // SAFETY: the caller's contract.
    unsafe {
        with_text_a(flags, text, |text| {
            edit_by_flags(&crate::spec::InsertMenuA, &args, at, flags, item, text)
        })
    }
    .unwrap_or(0)
}

/// ModifyMenuW: the item `position` names (by command, through the popups) made over as the flags
/// describe: its type, state, id and popup (the popup it opened destroyed, as documented), its text
/// when the flags give one (a separator keeps its text, as the `edit` capture shows); TRUE, or
/// FALSE with ERROR_MENU_ITEM_NOT_FOUND for no such item.
///
/// # Safety
///
/// The caller's string, for a string item, as for the platform's.
#[unsafe(export_name = "f2k_export_ModifyMenuW")]
pub unsafe extern "system" fn modify_menu_w(
    menu: usize,
    position: u32,
    flags: u32,
    item: usize,
    text: *const u16,
) -> i32 {
    let args = [
        menu as u64,
        u64::from(position),
        u64::from(flags),
        item as u64,
        text as u64,
    ];
    let at = (menu, position, MENU_ITEM_SET);
    // SAFETY: the caller's contract.
    unsafe {
        with_text_w(flags, text, |text| {
            edit_by_flags(&crate::spec::ModifyMenuW, &args, at, flags, item, text)
        })
    }
}

/// ModifyMenuA: ModifyMenuW's, its text narrow.
///
/// # Safety
///
/// The caller's string, for a string item, as for the platform's.
#[unsafe(export_name = "f2k_export_ModifyMenuA")]
pub unsafe extern "system" fn modify_menu_a(
    menu: usize,
    position: u32,
    flags: u32,
    item: usize,
    text: *const u8,
) -> i32 {
    let args = [
        menu as u64,
        u64::from(position),
        u64::from(flags),
        item as u64,
        text as u64,
    ];
    let at = (menu, position, MENU_ITEM_SET);
    // SAFETY: the caller's contract.
    unsafe {
        with_text_a(flags, text, |text| {
            edit_by_flags(&crate::spec::ModifyMenuA, &args, at, flags, item, text)
        })
    }
    .unwrap_or(0)
}

/// RemoveMenu: the item `position` names (by command, through the popups) taken out of its menu,
/// the popup it opens kept; TRUE. FALSE for no such item, the last error untouched (the `edit`
/// capture), or ERROR_INVALID_MENU_HANDLE.
#[unsafe(export_name = "f2k_export_RemoveMenu")]
pub extern "system" fn remove_menu(menu: usize, position: u32, flags: u32) -> i32 {
    quiet_success(imports::remove_menu(menu, position, flags, false))
}

/// DeleteMenu: RemoveMenu's, the popup the item opens destroyed.
#[unsafe(export_name = "f2k_export_DeleteMenu")]
pub extern "system" fn delete_menu(menu: usize, position: u32, flags: u32) -> i32 {
    quiet_success(imports::remove_menu(menu, position, flags, true))
}

/// A change's success: TRUE; FALSE for no such item (the last error untouched) or a handle naming
/// no menu (ERROR_INVALID_MENU_HANDLE).
fn quiet_success(answer: Result<(), NtStatus>) -> i32 {
    match answer {
        Ok(()) => 1,
        Err(status) if no_such_item(status) => 0,
        Err(status) => {
            imports::set_last_error(window_error(status));
            0
        }
    }
}

/// IsMenu: TRUE for a handle naming a menu; FALSE with ERROR_INVALID_MENU_HANDLE otherwise.
#[unsafe(export_name = "f2k_export_IsMenu")]
pub extern "system" fn is_menu(menu: usize) -> i32 {
    let mut answer = MenuItemAnswer::EMPTY;
    failed_with(
        imports::query_menu(menu, 0, 0, MENU_QUERY, &mut answer),
        window_error,
    )
    .is_some() as i32
}

/// DestroyMenu: the menu and its popups destroyed; FALSE with ERROR_INVALID_MENU_HANDLE for a
/// handle naming none.
#[unsafe(export_name = "f2k_export_DestroyMenu")]
pub extern "system" fn destroy_menu(menu: usize) -> i32 {
    failed_with(imports::destroy_menu(menu), window_error).is_some() as i32
}

/// GetMenuItemCount: how many items the menu holds; -1 with ERROR_INVALID_MENU_HANDLE for a
/// handle naming none.
#[unsafe(export_name = "f2k_export_GetMenuItemCount")]
pub extern "system" fn get_menu_item_count(menu: usize) -> i32 {
    let mut answer = MenuItemAnswer::EMPTY;
    failed_with(
        imports::query_menu(menu, 0, 0, MENU_QUERY, &mut answer),
        window_error,
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

/// GetMenuState: the item's GetMenuState word ([`state_word`]), with MFS_CACHEDBMP for an item
/// whose bitmap is a predefined one; -1 for no item.
#[unsafe(export_name = "f2k_export_GetMenuState")]
pub extern "system" fn get_menu_state(menu: usize, item: u32, flags: u32) -> u32 {
    match query_quiet(menu, item, flags) {
        Ok(Some(item)) => {
            let cached = if is_predefined_bitmap(item.bitmap) {
                MFS_CACHEDBMP
            } else {
                0
            };
            state_word(
                item.item_type,
                item.state,
                (item.submenu != 0).then_some(item.submenu_count),
            ) | cached
        }
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
    let answer = match failed_with(query(menu, item, flags), window_error) {
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
        Err(status) if no_such_item(status) => u32::MAX,
        Err(status) => {
            imports::set_last_error(window_error(status));
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
            window_error,
        )
        .is_none()
        {
            return 0;
        }
        (menu, first, last.min(answer.count.saturating_sub(1)))
    } else {
        let Some(start) = failed_with(query(menu, first, MF_BYCOMMAND), window_error) else {
            return 0;
        };
        let Some(end) = failed_with(
            query(start.holder as usize, last, MF_BYCOMMAND),
            window_error,
        ) else {
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

// --- The default item
// -----------------------------------------------------------------------------

/// GetMenuDefaultItem's flags: a disabled default answered too; a popup's own default answered
/// for a default item that opens one.
pub const GMDI_USEDISABLED: u32 = 0x0001;
pub const GMDI_GOINTOPOPUPS: u32 = 0x0002;

/// SetMenuDefaultItem: the item `item` names in the menu itself (`by_position`, or by command
/// among its own items: a popup's are not searched) made its one default item (MFS_DEFAULT), -1
/// none; TRUE. FALSE for no such item or a separator, the last error untouched (the menus
/// fixture's `default` capture), or ERROR_INVALID_MENU_HANDLE.
#[unsafe(export_name = "f2k_export_SetMenuDefaultItem")]
pub extern "system" fn set_menu_default_item(menu: usize, item: u32, by_position: u32) -> i32 {
    quiet_success(imports::set_menu_default_item(menu, item, by_position != 0))
}

/// GetMenuDefaultItem: the menu's first item holding MFS_DEFAULT, its position (`by_position`) or
/// its id (a popup's item its id, the popup's handle for AppendMenu's); -1 for none, or a
/// disabled one without GMDI_USEDISABLED. With GMDI_GOINTOPOPUPS, a default item that opens a
/// popup answers the popup's own default, the item itself when the popup has none (as the
/// `default` capture shows). -1 with ERROR_INVALID_MENU_HANDLE for a handle naming no menu.
#[unsafe(export_name = "f2k_export_GetMenuDefaultItem")]
pub extern "system" fn get_menu_default_item(menu: usize, by_position: u32, flags: u32) -> u32 {
    let mut answer = MenuItemAnswer::EMPTY;
    if failed_with(
        imports::query_menu(menu, 0, 0, MENU_QUERY, &mut answer),
        window_error,
    )
    .is_none()
    {
        return u32::MAX;
    }
    default_item(menu, by_position != 0, flags, 0)
}

/// GetMenuDefaultItem's search of `menu`, `depth` popups down.
fn default_item(menu: usize, by_position: bool, flags: u32, depth: u32) -> u32 {
    let found = (0..)
        .map_while(|position| {
            query(menu, position, MF_BYPOSITION)
                .ok()
                .map(|item| (position, item))
        })
        .find(|(_, item)| item.state & MFS_DEFAULT != 0);
    let Some((position, item)) = found else {
        return u32::MAX;
    };
    if flags & GMDI_USEDISABLED == 0 && item.state & (MF_GRAYED | MF_DISABLED) != 0 {
        return u32::MAX;
    }
    if item.submenu != 0 && flags & GMDI_GOINTOPOPUPS != 0 && depth < MAX_DEPTH {
        let inner = default_item(item.submenu as usize, by_position, flags, depth + 1);
        if inner != u32::MAX {
            return inner;
        }
    }
    if by_position {
        position
    } else {
        item.id
    }
}

// --- The system menu
// ------------------------------------------------------------------------------

/// WS_SYSMENU: the window has a system menu.
const WS_SYSMENU: u32 = 0x0008_0000;

/// The system commands (winuser.h's SC_*) the system menu's items carry.
pub const SC_SIZE: u32 = 0xF000;
pub const SC_MOVE: u32 = 0xF010;
pub const SC_MINIMIZE: u32 = 0xF020;
pub const SC_MAXIMIZE: u32 = 0xF030;
pub const SC_CLOSE: u32 = 0xF060;
pub const SC_RESTORE: u32 = 0xF120;

/// The system menu's items, as the menus fixture's `sysmenu` capture shows Windows 2000's for every
/// window that has one (its style changes none of them: Windows enables and grays them as the menu
/// opens): the command, the text, the predefined bitmap (0 for none); a separator before Close.
const SYSTEM_ITEMS: [(u32, &str, u32); 7] = [
    (SC_RESTORE, "&Restore", HBMMENU_POPUP_RESTORE),
    (SC_MOVE, "&Move", 0),
    (SC_SIZE, "&Size", 0),
    (SC_MINIMIZE, "Mi&nimize", HBMMENU_POPUP_MINIMIZE),
    (SC_MAXIMIZE, "Ma&ximize", HBMMENU_POPUP_MAXIMIZE),
    (0, "", 0),
    (SC_CLOSE, "&Close\tAlt+F4", HBMMENU_POPUP_CLOSE),
];

/// A new popup holding the system menu's items; none with the last error.
fn build_system_menu() -> Option<usize> {
    let menu = create_popup_menu();
    if menu == 0 {
        return None;
    }
    for (id, text, bitmap) in SYSTEM_ITEMS {
        let mut units = [0u16; MENU_ITEM_TEXT];
        let mut length = 0;
        for (unit, slot) in text.encode_utf16().zip(units.iter_mut()) {
            *slot = unit;
            length += 1;
        }
        let item_type = if id == 0 { MFT_SEPARATOR } else { MFT_STRING };
        let info = MenuItemInfoW {
            size: core::mem::size_of::<MenuItemInfoW>() as u32,
            mask: MIIM_FTYPE | MIIM_ID | MIIM_STRING | MIIM_BITMAP,
            item_type,
            id,
            bitmap,
            ..MenuItemInfoW::default()
        };
        let inserted = imports::set_menu_item(
            menu,
            u32::MAX,
            MF_BYPOSITION,
            MENU_ITEM_INSERT,
            &info,
            &units[..length],
        );
        if failed_with(inserted, window_error).is_none() {
            let _ = imports::destroy_menu(menu);
            return None;
        }
    }
    Some(menu)
}

/// GetSystemMenu: the window's own copy of the system menu, made at the first call (none for a
/// window without WS_SYSMENU), the same menu after; with `revert`, the copy destroyed and NULL
/// answered (the next call makes another). NULL with ERROR_INVALID_WINDOW_HANDLE for a handle
/// naming no window. The copy goes with its window.
#[unsafe(export_name = "f2k_export_GetSystemMenu")]
pub extern "system" fn get_system_menu(window: usize, revert: u32) -> usize {
    let Some(copy) = crate::answered(imports::get_system_menu(window, revert != 0, 0)) else {
        return 0;
    };
    if revert != 0 || copy != 0 {
        return copy;
    }
    let has_one = crate::window::window_info(window).is_ok_and(|info| info.style & WS_SYSMENU != 0);
    if !has_one {
        return 0;
    }
    let Some(made) = build_system_menu() else {
        return 0;
    };
    let copy = crate::answered(imports::get_system_menu(window, false, made)).unwrap_or(0);
    if copy != made {
        let _ = imports::destroy_menu(made);
    }
    copy
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
    crate::answered(imports::set_menu(window, menu)).is_some() as i32
}

#[cfg(test)]
mod tests {
    use std::vec::Vec;

    use rtl::testing::utf16_bytes_z;
    use rtl::winerror::ERROR_INVALID_MENU_HANDLE;

    use super::*;
    use crate::imports::host::{add_resource, LAST_ERROR, PROGRAM};

    fn last_error() -> u32 {
        LAST_ERROR.with(|error| error.get())
    }

    /// The menus fixture's menu 200 (menus.rc), as the resource compiler writes it.
    fn menu_200() -> Vec<u8> {
        let mut data = std::vec![0, 0, 0, 0];
        let popup = |data: &mut Vec<u8>, flags: u16, text: &str| {
            data.extend_from_slice(&flags.to_le_bytes());
            data.extend(utf16_bytes_z(text));
        };
        let item = |data: &mut Vec<u8>, flags: u16, id: u16, text: &str| {
            data.extend_from_slice(&flags.to_le_bytes());
            data.extend_from_slice(&id.to_le_bytes());
            data.extend(utf16_bytes_z(text));
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

    fn state(menu: usize, position: u32) -> u32 {
        get_menu_state(menu, position, MF_BYPOSITION)
    }

    fn ids(menu: usize) -> std::vec::Vec<u32> {
        (0..get_menu_item_count(menu) as i32)
            .map(|position| get_menu_item_id(menu, position))
            .collect()
    }

    /// InsertMenu, ModifyMenu, DeleteMenu and RemoveMenu, as the edit section's capture answers
    /// them: a textless string item a separator, an insertion by a missing command appended, a
    /// separator keeping its text, a popup removed kept and a popup deleted destroyed.
    ///
    /// Pins: user32.AppendMenuW, user32.InsertMenuW, user32.ModifyMenuW, user32.DeleteMenu,
    /// user32.RemoveMenu
    #[test]
    fn edits_follow_the_capture() {
        let popup = create_popup_menu();
        let text = |s: &str| utf16_bytes_z(s);
        let as_units = |bytes: std::vec::Vec<u8>| -> std::vec::Vec<u16> {
            bytes
                .chunks(2)
                .map(|b| u16::from_le_bytes([b[0], b[1]]))
                .collect()
        };
        let one = as_units(text("&One"));
        let four = as_units(text("Four"));
        let lost = as_units(text("Lost"));
        let uno = as_units(text("Uno"));
        // SAFETY: the test's own strings, NUL-terminated.
        unsafe {
            assert_eq!(append_menu_w(popup, 0, 301, one.as_ptr()), 1);
            assert_eq!(append_menu_w(popup, MF_GRAYED, 304, four.as_ptr()), 1);
            assert_eq!(append_menu_w(popup, 0, 308, core::ptr::null()), 1);
            assert_eq!(state(popup, 2), 0x803, "a string item of no text");
            assert_eq!(
                insert_menu_w(popup, 399, MF_BYCOMMAND, 311, lost.as_ptr()),
                1
            );
            assert_eq!(
                insert_menu_w(popup, 304, MF_BYCOMMAND, 313, lost.as_ptr()),
                1
            );
            assert_eq!(ids(popup), [301, 313, 304, 308, 311]);
            assert_eq!(
                modify_menu_w(popup, 301, MF_BYCOMMAND | MF_CHECKED, 321, uno.as_ptr()),
                1
            );
            assert_eq!(state(popup, 0), MF_CHECKED);
            assert_eq!(
                modify_menu_w(
                    popup,
                    304,
                    MF_BYCOMMAND | MF_SEPARATOR,
                    0,
                    core::ptr::null()
                ),
                1
            );
            assert_eq!(string_w(popup, 2, 32, MF_BYPOSITION), (4, "Four".into()));
            assert_eq!(state(popup, 2), 0x803);
            LAST_ERROR.with(|error| error.set(0));
            assert_eq!(
                modify_menu_w(popup, 50, MF_BYPOSITION, 325, lost.as_ptr()),
                0
            );
            assert_eq!(last_error(), ERROR_MENU_ITEM_NOT_FOUND);
        }
        LAST_ERROR.with(|error| error.set(0));
        assert_eq!(delete_menu(popup, 399, MF_BYCOMMAND), 0);
        assert_eq!(remove_menu(popup, 40, MF_BYPOSITION), 0);
        assert_eq!(last_error(), 0, "no such item leaves the last error");
        assert_eq!(delete_menu(0, 0, MF_BYPOSITION), 0);
        assert_eq!(last_error(), ERROR_INVALID_MENU_HANDLE);
        assert_eq!(remove_menu(popup, 0, MF_BYPOSITION), 1);
        assert_eq!(ids(popup), [313, 0, 308, 311]);

        let bar = create_menu();
        let kept = create_popup_menu();
        let gone = create_popup_menu();
        let name = as_units(text("&Removed"));
        // SAFETY: the test's own string.
        unsafe {
            append_menu_w(bar, MF_POPUP, kept, name.as_ptr());
            append_menu_w(bar, MF_POPUP, gone, name.as_ptr());
        }
        assert_eq!(remove_menu(bar, 0, MF_BYPOSITION), 1);
        assert_eq!(is_menu(kept), 1);
        assert_eq!(delete_menu(bar, 0, MF_BYPOSITION), 1);
        assert_eq!(is_menu(gone), 0);
        assert_eq!(get_menu_item_count(bar), 0);
    }

    /// SetMenuDefaultItem and GetMenuDefaultItem with the GMDI_* flags, as the default section's
    /// capture answers them.
    ///
    /// Pins: user32.SetMenuDefaultItem, user32.GetMenuDefaultItem
    #[test]
    fn the_default_item_follows_the_capture() {
        let menu = create_popup_menu();
        let sub = create_popup_menu();
        let name = |s: &str| -> std::vec::Vec<u16> { s.encode_utf16().chain([0]).collect() };
        // SAFETY: the test's own strings.
        unsafe {
            append_menu_w(menu, 0, 601, name("A").as_ptr());
            append_menu_w(menu, MF_GRAYED, 602, name("B").as_ptr());
            append_menu_w(menu, MF_SEPARATOR, 0, core::ptr::null());
            append_menu_w(menu, 0, 603, name("C").as_ptr());
            append_menu_w(sub, 0, 611, name("X").as_ptr());
            append_menu_w(sub, 0, 612, name("Y").as_ptr());
            append_menu_w(menu, MF_POPUP, sub, name("&D").as_ptr());
        }
        let both = GMDI_USEDISABLED | GMDI_GOINTOPOPUPS;
        assert_eq!(get_menu_default_item(menu, 0, 0), u32::MAX);
        assert_eq!(set_menu_default_item(menu, 603, 0), 1);
        assert_eq!(get_menu_state(menu, 603, MF_BYCOMMAND), 0x1000);
        assert_eq!(get_menu_default_item(menu, 1, 0), 3);
        assert_eq!(set_menu_default_item(menu, 1, 1), 1);
        assert_eq!(get_menu_state(menu, 603, MF_BYCOMMAND), 0);
        assert_eq!(get_menu_default_item(menu, 0, 0), u32::MAX, "disabled");
        assert_eq!(get_menu_default_item(menu, 0, GMDI_USEDISABLED), 602);
        assert_eq!(set_menu_default_item(menu, 4, 1), 1);
        assert_eq!(
            get_menu_default_item(menu, 0, GMDI_GOINTOPOPUPS),
            sub as u32
        );
        assert_eq!(set_menu_default_item(sub, 612, 0), 1);
        assert_eq!(get_menu_default_item(menu, 0, both), 612);
        assert_eq!(get_menu_default_item(menu, 1, GMDI_GOINTOPOPUPS), 1);
        assert_eq!(get_menu_default_item(menu, 1, 0), 4);
        assert_eq!(set_menu_default_item(menu, 2, 1), 0, "a separator");
        assert_eq!(set_menu_default_item(menu, 611, 0), 0, "a popup's item");
        assert_eq!(get_menu_default_item(menu, 1, 0), 4);
        assert_eq!(set_menu_default_item(menu, u32::MAX, 0), 1);
        assert_eq!(get_menu_default_item(menu, 0, both), u32::MAX);
        assert_eq!(set_menu_default_item(0, 0, 1), 0);
        assert_eq!(get_menu_default_item(0, 0, 0), u32::MAX);
        assert_eq!(last_error(), ERROR_INVALID_MENU_HANDLE);
    }

    /// GetSystemMenu: the sysmenu section's items, the same copy twice, NULL for a window without
    /// WS_SYSMENU, a revert destroying the copy.
    ///
    /// Pins: user32.GetSystemMenu
    #[test]
    fn system_menus_follow_the_capture() {
        crate::class::SYSTEM_CLASSES_WANTED.with(|wanted| wanted.set(true));
        let class = crate::class::WndClass {
            wnd_proc: crate::imports::host::procedure(|w, m, wp, lp| {
                crate::message::def_window_proc_a(w as usize, m, wp, lp)
            }) as usize,
            class_name: c"F2KSysMenu".as_ptr() as usize,
            ..crate::class::WndClass::default()
        };
        let create = |style: u32| {
            // SAFETY: the class's name, the test's own.
            unsafe {
                crate::window::create_window_ex_a(
                    0,
                    c"F2KSysMenu".as_ptr().cast(),
                    core::ptr::null(),
                    style,
                    40,
                    40,
                    320,
                    200,
                    0,
                    0,
                    0,
                    0,
                )
            }
        };
        // SAFETY: a WNDCLASSA of the test's own.
        unsafe { crate::class::register_class_a(&class) };
        let window = create(0x00CF_0000);
        let menu = get_system_menu(window, 0);
        assert_ne!(menu, 0);
        assert_eq!(get_system_menu(window, 0), menu, "the same copy");
        assert_eq!(get_menu_item_count(menu), 7);
        assert_eq!(get_menu_item_id(menu, 0), SC_RESTORE);
        assert_eq!(state(menu, 0), MFS_CACHEDBMP);
        assert_eq!(state(menu, 1), 0, "Move has no bitmap");
        assert_eq!(state(menu, 5), 0x803);
        assert_eq!(
            string_w(menu, 6, 32, MF_BYPOSITION),
            (13, "&Close\tAlt+F4".into())
        );
        assert_eq!(get_system_menu(window, 1), 0);
        assert_eq!(is_menu(menu), 0, "the revert destroys the copy");
        assert_ne!(get_system_menu(window, 0), 0);
        let popup = create(0x8000_0000);
        assert_eq!(get_system_menu(popup, 0), 0, "no WS_SYSMENU");
        assert_eq!(get_system_menu(0, 0), 0);
        assert_eq!(last_error(), crate::ERROR_INVALID_WINDOW_HANDLE);
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
