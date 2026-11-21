//! The MENUITEMINFO calls: GetMenuItemInfoW and GetMenuItemInfoA, SetMenuItemInfoW and
//! SetMenuItemInfoA, InsertMenuItemW and InsertMenuItemA, over win32k's menu services
//! (NtUserThunkedMenuItemInfo's insertion, change and query, [`crate::menu`]).
//!
//! A MENUITEMINFO is Windows 2000's 48 bytes (rtl::menu's [`MenuItemInfoW`]) or NT 4's 44, which
//! has no hbmpItem; any other cbSize is ERROR_INVALID_PARAMETER, and so is a mask of MIIM_TYPE with
//! one of the masks that take its place (MIIM_STRING, MIIM_FTYPE, MIIM_BITMAP) or a bit Windows
//! 2000 does not define. What the calls answer, as the menus fixture's `info` and `insitem`
//! captures show:
//!
//! - GetMenuItemInfo writes the members its mask names and no other, but for hSubMenu, which it
//!   always writes (NULL when MIIM_SUBMENU is not asked for), and hbmpItem, which MIIM_TYPE writes
//!   NULL in a 48-byte structure. A handle naming no menu is ERROR_INVALID_PARAMETER there (a
//!   change or an insertion answers ERROR_INVALID_MENU_HANDLE), no such item
//!   ERROR_MENU_ITEM_NOT_FOUND, and nothing is written.
//! - The text (MIIM_STRING, or MIIM_TYPE for a string item: a separator's MIIM_TYPE answers
//!   dwTypeData NULL and cch 0): with no buffer, cch its length; with a buffer and a cch of 0,
//!   dwTypeData set to NULL and cch the length; otherwise as much of it as cch - 1 holds, a NUL
//!   after it, and cch the count copied ([`text_out`]). The narrow form counts bytes.
//! - SetMenuItemInfo and InsertMenuItem read the text up to its NUL, cch unread; an insertion that
//!   gives a string item no text makes a separator, as AppendMenu does (an MIIM_ID | MIIM_DATA item
//!   answers fType 0x800). InsertMenuItem by command names an item through the popups, and one no
//!   item has appends to the menu.

use rtl::edge::{In, InBuf, InStr, InWStr, OutBuf};
use rtl::menu::*;
use rtl::pod::Pod;
use rtl::status::NtStatus;

use crate::imports;
use crate::menu::{query, ERROR_INVALID_MENU_HANDLE};
use crate::{failed, failed_with, window_error, ERROR_INVALID_PARAMETER};

/// MENUITEMINFO's sizes: Windows 2000's, and NT 4's (no hbmpItem).
pub const MII_SIZE: u32 = 48;
pub const MII_NT4_SIZE: u32 = 44;

/// Every mask Windows 2000 defines.
const MIIM_ALL: u32 = MIIM_STATE
    | MIIM_ID
    | MIIM_SUBMENU
    | MIIM_CHECKMARKS
    | MIIM_TYPE
    | MIIM_DATA
    | MIIM_STRING
    | MIIM_BITMAP
    | MIIM_FTYPE;

/// The types whose item has no text: a separator, a bitmap, an owner-drawn item.
const NOT_TEXT: u32 = MFT_SEPARATOR | MFT_BITMAP | MFT_OWNERDRAW;

/// Whether a MENUITEMINFO of `size` bytes and mask `mask` is one Windows 2000 takes.
pub fn valid(size: u32, mask: u32) -> bool {
    let replaced = mask & MIIM_TYPE != 0 && mask & (MIIM_STRING | MIIM_FTYPE | MIIM_BITMAP) != 0;
    (size == MII_SIZE || size == MII_NT4_SIZE) && mask & !MIIM_ALL == 0 && !replaced
}

/// The caller's MENUITEMINFO: its cbSize bytes read (a 44-byte one's hbmpItem 0) and the size;
/// none with ERROR_INVALID_PARAMETER for a size or a mask Windows 2000 does not take.
///
/// # Safety
///
/// `at` is the caller's MENUITEMINFO, as for the platform's.
unsafe fn read_info(at: *const u8) -> Option<(MenuItemInfoW, usize)> {
    // SAFETY: the caller's contract: the structure's cbSize, its first member.
    let size = unsafe { In::new(at as *const u32) }.read();
    let mut info = MenuItemInfoW::default();
    let given = size.min(MII_SIZE) as usize;
    // SAFETY: as above, its first two members (cbSize and fMask).
    let mask = unsafe { In::new(at.add(4) as *const u32) }.read();
    if !valid(size, mask) {
        return failed(ERROR_INVALID_PARAMETER);
    }
    // SAFETY: as above: a valid size's bytes.
    unsafe { InBuf::new(at, given) }.copy_to(&mut info.as_bytes_mut()[..given]);
    Some((info, given))
}

/// `info`'s first `size` bytes written back into the caller's MENUITEMINFO.
///
/// # Safety
///
/// `at` is the caller's MENUITEMINFO of `size` bytes, as for the platform's.
unsafe fn write_info(at: *mut u8, info: &MenuItemInfoW, size: usize) {
    // SAFETY: the caller's contract.
    unsafe { OutBuf::new(at, size) }.put(&info.as_bytes()[..size]);
}

/// What GetMenuItemInfo does with an item's text of `length` units (or bytes), given a buffer or
/// not and its cch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TextOut {
    /// cch set to the length, dwTypeData kept (no buffer).
    Length(u32),
    /// dwTypeData set to NULL, cch to the length (a buffer of cch 0).
    Detach(u32),
    /// The text's first values copied, a NUL after them, cch their count.
    Copy(usize),
}

/// [`TextOut`] for a buffer given or not (`buffer`) of `cch` values, a text of `length`.
pub fn text_out(buffer: bool, cch: u32, length: usize) -> TextOut {
    match (buffer, cch) {
        (false, _) => TextOut::Length(length as u32),
        (true, 0) => TextOut::Detach(length as u32),
        (true, cch) => TextOut::Copy(length.min(cch as usize - 1)),
    }
}

/// `text` given back in the caller's dwTypeData and cch, as [`text_out`] says.
fn put_text<T: Copy + From<u8>>(info: &mut MenuItemInfoW, text: &[T]) {
    match text_out(info.type_data != 0, info.cch, text.len()) {
        TextOut::Length(length) => info.cch = length,
        TextOut::Detach(length) => {
            info.type_data = 0;
            info.cch = length;
        }
        TextOut::Copy(count) => {
            // SAFETY: GetMenuItemInfo's contract: dwTypeData a buffer of cch values.
            let mut out =
                unsafe { OutBuf::new(info.type_data as usize as *mut T, info.cch as usize) };
            out.put(&text[..count]);
            out.set(count, T::from(0));
            info.cch = count as u32;
        }
    }
}

/// The members GetMenuItemInfo answers of `item`, written into `info` (of `size` bytes) as its
/// mask names them; whether the item's text is to be given back too.
pub fn fill(info: &mut MenuItemInfoW, item: &MenuItemAnswer, size: usize) -> bool {
    let mask = info.mask;
    info.submenu = 0;
    if mask & MIIM_SUBMENU != 0 {
        info.submenu = item.submenu;
    }
    if mask & MIIM_STATE != 0 {
        info.state = item.state;
    }
    if mask & MIIM_ID != 0 {
        info.id = item.id;
    }
    if mask & MIIM_CHECKMARKS != 0 {
        info.checked = item.checked;
        info.unchecked = item.unchecked;
    }
    if mask & MIIM_DATA != 0 {
        info.item_data = item.item_data;
    }
    if mask & (MIIM_FTYPE | MIIM_TYPE) != 0 {
        info.item_type = item.item_type;
    }
    if mask & MIIM_BITMAP != 0 {
        info.bitmap = item.bitmap;
    }
    if mask & MIIM_TYPE != 0 {
        if size >= MII_SIZE as usize {
            info.bitmap = 0;
        }
        if item.item_type & NOT_TEXT != 0 {
            info.type_data = 0;
            info.cch = 0;
            return false;
        }
        return true;
    }
    mask & MIIM_STRING != 0
}

/// GetMenuItemInfo's core: the item `item` names (`by_position`, or by command through the
/// popups) answered into the caller's MENUITEMINFO, its text narrow for `ansi`.
///
/// # Safety
///
/// `at` is the caller's MENUITEMINFO, its dwTypeData a buffer of cch values when the text is
/// asked for.
unsafe fn get_info(menu: usize, item: u32, by_position: u32, at: *mut u8, ansi: bool) -> i32 {
    // SAFETY: the caller's contract.
    let Some((mut info, size)) = (unsafe { read_info(at) }) else {
        return 0;
    };
    let flags = if by_position != 0 { MF_BYPOSITION } else { 0 };
    let Some(answer) = failed_with(query(menu, item, flags), |status: NtStatus| {
        if status == NtStatus::from_win32(ERROR_INVALID_MENU_HANDLE) {
            ERROR_INVALID_PARAMETER
        } else {
            window_error(status)
        }
    }) else {
        return 0;
    };
    if fill(&mut info, &answer, size) {
        if ansi {
            let mut bytes = [0u8; 2 * MENU_ITEM_TEXT];
            let length = imports::unicode_to_multi_byte(&mut bytes, answer.text());
            put_text(&mut info, &bytes[..length]);
        } else {
            put_text(&mut info, answer.text());
        }
    }
    // SAFETY: the caller's contract.
    unsafe { write_info(at, &info, size) };
    1
}

/// GetMenuItemInfoW: the item's members its MENUITEMINFOW's mask names (see the module's
/// description); TRUE, or FALSE with the last error, the structure untouched.
///
/// # Safety
///
/// `info` is the caller's MENUITEMINFOW, as for the platform's.
#[unsafe(export_name = "f2k_export_GetMenuItemInfoW")]
pub unsafe extern "system" fn get_menu_item_info_w(
    menu: usize,
    item: u32,
    by_position: u32,
    info: *mut u8,
) -> i32 {
    // SAFETY: the caller's contract.
    unsafe { get_info(menu, item, by_position, info, false) }
}

/// GetMenuItemInfoA: GetMenuItemInfoW's, the text in the ANSI code page, counted in bytes.
///
/// # Safety
///
/// `info` is the caller's MENUITEMINFOA, as for the platform's.
#[unsafe(export_name = "f2k_export_GetMenuItemInfoA")]
pub unsafe extern "system" fn get_menu_item_info_a(
    menu: usize,
    item: u32,
    by_position: u32,
    info: *mut u8,
) -> i32 {
    // SAFETY: the caller's contract.
    unsafe { get_info(menu, item, by_position, info, true) }
}

/// The item `info` describes made ready for the services: a bitmap item's bitmap (MIIM_TYPE's
/// MFT_BITMAP, its handle in dwTypeData) moved to hbmpItem; for an insertion (`insert`), a
/// string item given no text (`has_text` false) made a separator.
pub fn prepare(info: &mut MenuItemInfoW, has_text: bool, insert: bool) {
    if info.mask & MIIM_TYPE != 0 && info.item_type & MFT_BITMAP != 0 {
        info.mask |= MIIM_BITMAP;
        info.bitmap = info.type_data;
    }
    let item_type = if info.mask & (MIIM_TYPE | MIIM_FTYPE) != 0 {
        info.item_type
    } else {
        MFT_STRING
    };
    let bitmap = info.mask & MIIM_BITMAP != 0 && info.bitmap != 0;
    if insert && !has_text && item_type & NOT_TEXT == 0 && !bitmap {
        info.mask |= MIIM_FTYPE;
        info.item_type = item_type | MFT_SEPARATOR;
    }
}

/// Whether the change or insertion `info` describes carries a text: MIIM_STRING, or MIIM_TYPE of
/// a string item.
fn wants_text(info: &MenuItemInfoW) -> bool {
    info.mask & MIIM_STRING != 0 || (info.mask & MIIM_TYPE != 0 && info.item_type & NOT_TEXT == 0)
}

/// SetMenuItemInfo's and InsertMenuItem's core (`operation` MENU_ITEM_SET or MENU_ITEM_INSERT):
/// the caller's MENUITEMINFO read, its text (narrow for `ansi`) up to its NUL, and the item set or
/// inserted; TRUE, or FALSE with the last error.
///
/// # Safety
///
/// `at` is the caller's MENUITEMINFO, its dwTypeData a NUL-terminated string where it carries one.
unsafe fn set_info(
    menu: usize,
    item: u32,
    by_position: u32,
    at: *const u8,
    ansi: bool,
    operation: u32,
) -> i32 {
    // SAFETY: the caller's contract.
    let Some((mut info, _)) = (unsafe { read_info(at) }) else {
        return 0;
    };
    let flags = if by_position != 0 { MF_BYPOSITION } else { 0 };
    let text_at = if wants_text(&info) { info.type_data } else { 0 };
    prepare(&mut info, text_at != 0, operation == MENU_ITEM_INSERT);
    let call = |text: &[u16]| {
        let text = &text[..text.len().min(MENU_ITEM_TEXT)];
        failed_with(
            imports::set_menu_item(menu, item, flags, operation, &info, text),
            window_error,
        )
        .is_some() as i32
    };
    if text_at == 0 {
        return call(&[]);
    }
    if ansi {
        // SAFETY: the caller's contract: dwTypeData its NUL-terminated string.
        let text = unsafe { InStr::new(text_at as usize as *const u8) };
        crate::with_wide(text.bytes(), call).unwrap_or(0)
    } else {
        // SAFETY: the caller's contract: dwTypeData its NUL-terminated string.
        let text = unsafe { InWStr::new(text_at as usize as *const u16) }.units();
        let mut units = [0u16; MENU_ITEM_TEXT];
        let length = text.len().min(MENU_ITEM_TEXT);
        for (index, unit) in units.iter_mut().take(length).enumerate() {
            *unit = text.get(index);
        }
        call(&units[..length])
    }
}

/// SetMenuItemInfoW: the item's members its MENUITEMINFOW's mask names set (MIIM_STATE keeps the
/// default and the highlight; a new popup, or none, destroys the one the item opened); TRUE, or
/// FALSE with ERROR_INVALID_PARAMETER, ERROR_INVALID_MENU_HANDLE or ERROR_MENU_ITEM_NOT_FOUND.
///
/// # Safety
///
/// `info` is the caller's MENUITEMINFOW, as for the platform's.
#[unsafe(export_name = "f2k_export_SetMenuItemInfoW")]
pub unsafe extern "system" fn set_menu_item_info_w(
    menu: usize,
    item: u32,
    by_position: u32,
    info: *const u8,
) -> i32 {
    // SAFETY: the caller's contract.
    unsafe { set_info(menu, item, by_position, info, false, MENU_ITEM_SET) }
}

/// SetMenuItemInfoA: SetMenuItemInfoW's, the text narrow.
///
/// # Safety
///
/// `info` is the caller's MENUITEMINFOA, as for the platform's.
#[unsafe(export_name = "f2k_export_SetMenuItemInfoA")]
pub unsafe extern "system" fn set_menu_item_info_a(
    menu: usize,
    item: u32,
    by_position: u32,
    info: *const u8,
) -> i32 {
    // SAFETY: the caller's contract.
    unsafe { set_info(menu, item, by_position, info, true, MENU_ITEM_SET) }
}

/// InsertMenuItemW: an item as the MENUITEMINFOW describes it inserted before the one `item` names
/// (by position, at the end past it; by command, through the popups, at the end when none has
/// it); TRUE, or FALSE with ERROR_INVALID_PARAMETER or ERROR_INVALID_MENU_HANDLE.
///
/// # Safety
///
/// `info` is the caller's MENUITEMINFOW, as for the platform's.
#[unsafe(export_name = "f2k_export_InsertMenuItemW")]
pub unsafe extern "system" fn insert_menu_item_w(
    menu: usize,
    item: u32,
    by_position: u32,
    info: *const u8,
) -> i32 {
    // SAFETY: the caller's contract.
    unsafe { set_info(menu, item, by_position, info, false, MENU_ITEM_INSERT) }
}

/// InsertMenuItemA: InsertMenuItemW's, the text narrow.
///
/// # Safety
///
/// `info` is the caller's MENUITEMINFOA, as for the platform's.
#[unsafe(export_name = "f2k_export_InsertMenuItemA")]
pub unsafe extern "system" fn insert_menu_item_a(
    menu: usize,
    item: u32,
    by_position: u32,
    info: *const u8,
) -> i32 {
    // SAFETY: the caller's contract.
    unsafe { set_info(menu, item, by_position, info, true, MENU_ITEM_INSERT) }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The sizes and masks the `info` capture takes and refuses.
    #[test]
    fn sizes_and_masks_follow_the_capture() {
        assert!(valid(48, MIIM_ID));
        assert!(valid(44, MIIM_TYPE | MIIM_ID));
        assert!(valid(44, MIIM_STRING), "NT 4's size takes the new masks");
        assert!(valid(48, 0));
        assert!(!valid(0, MIIM_ID));
        assert!(!valid(52, MIIM_ID));
        assert!(!valid(48, MIIM_ALL), "MIIM_TYPE with what replaces it");
        assert!(!valid(48, MIIM_TYPE | MIIM_STRING));
        assert!(!valid(48, 0x200));
    }

    /// The text's length and cch, as the `info` capture answers "&Alpha" (6 units).
    #[test]
    fn the_text_follows_cch() {
        assert_eq!(text_out(false, 20, 6), TextOut::Length(6));
        assert_eq!(text_out(false, 0, 6), TextOut::Length(6));
        assert_eq!(text_out(true, 0, 6), TextOut::Detach(6));
        assert_eq!(text_out(true, 3, 6), TextOut::Copy(2));
        assert_eq!(text_out(true, 6, 6), TextOut::Copy(5));
        assert_eq!(text_out(true, 7, 6), TextOut::Copy(6));
        assert_eq!(text_out(true, 20, 0), TextOut::Copy(0));
    }

    /// GetMenuItemInfo writes what the mask names, hSubMenu always, and MIIM_TYPE's hbmpItem;
    /// a separator's MIIM_TYPE has no text.
    #[test]
    fn the_members_follow_the_mask() {
        let pattern = 0xA5A5_A5A5;
        let blank = MenuItemInfoW {
            size: MII_SIZE,
            item_type: pattern,
            state: pattern,
            id: pattern,
            submenu: pattern,
            checked: pattern,
            unchecked: pattern,
            item_data: pattern,
            type_data: 0x1000,
            cch: 20,
            bitmap: pattern,
            ..MenuItemInfoW::default()
        };
        let mut item = MenuItemAnswer::EMPTY;
        item.state = MFS_CHECKED;
        item.id = 401;
        item.text_length = 6;

        let mut info = MenuItemInfoW {
            mask: MIIM_STATE,
            ..blank
        };
        assert!(!fill(&mut info, &item, 48));
        assert_eq!(
            (info.state, info.submenu, info.id),
            (MFS_CHECKED, 0, pattern)
        );

        let mut info = MenuItemInfoW {
            mask: MIIM_TYPE,
            ..blank
        };
        assert!(fill(&mut info, &item, 48));
        assert_eq!((info.item_type, info.bitmap), (0, 0));
        let mut old = MenuItemInfoW {
            mask: MIIM_TYPE,
            ..blank
        };
        fill(&mut old, &item, 44);
        assert_eq!(old.bitmap, pattern, "NT 4's structure has no hbmpItem");

        item.item_type = MFT_SEPARATOR;
        let mut info = MenuItemInfoW {
            mask: MIIM_TYPE | MIIM_ID | MIIM_STATE,
            ..blank
        };
        assert!(!fill(&mut info, &item, 48));
        assert_eq!(
            (info.item_type, info.type_data, info.cch),
            (MFT_SEPARATOR, 0, 0)
        );
        let mut info = MenuItemInfoW {
            mask: MIIM_FTYPE | MIIM_STRING,
            ..blank
        };
        assert!(
            fill(&mut info, &item, 48),
            "MIIM_STRING answers a separator's empty text"
        );
    }

    /// An insertion of a string item without text makes a separator; a change does not, nor does
    /// a bitmap item.
    #[test]
    fn textless_insertions_are_separators() {
        let mut info = MenuItemInfoW {
            size: MII_SIZE,
            mask: MIIM_ID | MIIM_DATA,
            item_type: 0xA5A5_A5A5,
            ..MenuItemInfoW::default()
        };
        prepare(&mut info, false, true);
        assert_eq!(
            (info.mask & MIIM_FTYPE, info.item_type),
            (MIIM_FTYPE, MFT_SEPARATOR)
        );
        let mut set = MenuItemInfoW {
            mask: MIIM_ID,
            ..MenuItemInfoW::default()
        };
        prepare(&mut set, false, false);
        assert_eq!(set.mask, MIIM_ID);
        let mut bitmap = MenuItemInfoW {
            mask: MIIM_TYPE,
            item_type: MFT_BITMAP,
            type_data: 7,
            ..MenuItemInfoW::default()
        };
        prepare(&mut bitmap, false, true);
        assert_eq!((bitmap.item_type, bitmap.bitmap), (MFT_BITMAP, 7));
        let mut text = MenuItemInfoW {
            mask: MIIM_STRING,
            ..MenuItemInfoW::default()
        };
        prepare(&mut text, true, true);
        assert_eq!(text.mask, MIIM_STRING);
    }
}
