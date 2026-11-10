//! Menus' shared shapes: what win32k's menu services and user32's menu calls agree on. The item
//! flags as Windows 2000's winuser.h numbers them (MF_*, MFT_*, MFS_*, MIIM_*), MENUITEMINFOW as it
//! lays it out on x86 ([`MenuItemInfoW`]), GetMenuState's word ([`state_word`]), the answer F2K's
//! menu query gives ([`MenuItemAnswer`]: Windows 2000's user32 reads a menu's items from the window
//! manager's records, mapped into every GUI process, where F2K's asks the kernel), and the MENU
//! and MENUEX resource templates' public layouts ([`Template`]), which user32's LoadMenu reads.

use core::mem::{offset_of, size_of};

use crate::pod::Pod;

// --- The flags (winuser.h) -----------------------------------------------------------------------

/// The item names a command (an id) or a position.
pub const MF_BYCOMMAND: u32 = 0x0000;
pub const MF_BYPOSITION: u32 = 0x0400;

/// The old flags, as AppendMenu, CheckMenuItem, EnableMenuItem and GetMenuState use them, and as a
/// MENU resource's items carry them.
pub const MF_ENABLED: u32 = 0x0000;
pub const MF_GRAYED: u32 = 0x0001;
pub const MF_DISABLED: u32 = 0x0002;
pub const MF_UNCHECKED: u32 = 0x0000;
pub const MF_CHECKED: u32 = 0x0008;
pub const MF_POPUP: u32 = 0x0010;
pub const MF_MENUBARBREAK: u32 = 0x0020;
pub const MF_MENUBREAK: u32 = 0x0040;
/// A MENU resource's last item of its level (resources only).
pub const MF_END: u32 = 0x0080;
pub const MF_OWNERDRAW: u32 = 0x0100;
pub const MF_SEPARATOR: u32 = 0x0800;
pub const MF_HELP: u32 = 0x4000;

/// The item types (MENUITEMINFO's fType).
pub const MFT_STRING: u32 = 0x0000;
pub const MFT_BITMAP: u32 = 0x0004;
pub const MFT_MENUBARBREAK: u32 = 0x0020;
pub const MFT_MENUBREAK: u32 = 0x0040;
pub const MFT_OWNERDRAW: u32 = 0x0100;
pub const MFT_RADIOCHECK: u32 = 0x0200;
pub const MFT_SEPARATOR: u32 = 0x0800;
pub const MFT_RIGHTORDER: u32 = 0x2000;
pub const MFT_RIGHTJUSTIFY: u32 = 0x4000;

/// The item states (MENUITEMINFO's fState). An item keeps MF_GRAYED and MF_DISABLED apart, as
/// EnableMenuItem's answer shows them; MFS_GRAYED and MFS_DISABLED are both.
pub const MFS_GRAYED: u32 = 0x0003;
pub const MFS_DISABLED: u32 = 0x0003;
pub const MFS_CHECKED: u32 = 0x0008;
pub const MFS_HILITE: u32 = 0x0080;
pub const MFS_DEFAULT: u32 = 0x1000;

/// The state bits an item keeps: the enabling bits, the check, the highlight, the default.
pub const STATE_BITS: u32 = MF_GRAYED | MF_DISABLED | MFS_CHECKED | MFS_HILITE | MFS_DEFAULT;
/// The type bits an item keeps.
pub const TYPE_BITS: u32 = MFT_BITMAP
    | MFT_MENUBARBREAK
    | MFT_MENUBREAK
    | MFT_OWNERDRAW
    | MFT_RADIOCHECK
    | MFT_SEPARATOR
    | MFT_RIGHTORDER
    | MFT_RIGHTJUSTIFY;

/// What a MENUITEMINFO's fMask says it carries (MIIM_*).
pub const MIIM_STATE: u32 = 0x0001;
pub const MIIM_ID: u32 = 0x0002;
pub const MIIM_SUBMENU: u32 = 0x0004;
pub const MIIM_CHECKMARKS: u32 = 0x0008;
pub const MIIM_TYPE: u32 = 0x0010;
pub const MIIM_DATA: u32 = 0x0020;
pub const MIIM_STRING: u32 = 0x0040;
pub const MIIM_BITMAP: u32 = 0x0080;
pub const MIIM_FTYPE: u32 = 0x0100;

/// The longest item text an item keeps, in UTF-16 units (a longer one is cut there): menu items
/// are short (a command's name, a tab and its accelerator's), and the window manager's records
/// are of a fixed size.
pub const MENU_ITEM_TEXT: usize = 64;

// --- MENUITEMINFOW -------------------------------------------------------------------------------

/// MENUITEMINFOW (48 bytes, Windows 2000's: hbmpItem last): an item as InsertMenuItem and
/// SetMenuItemInfo describe it. `type_data` is the address of the item's text (MFT_STRING), its
/// length in `cch`; NtUserThunkedMenuItemInfo takes the text as an argument of its own, as Windows
/// 2000's does (read up to its NUL when `cch` is 0), and leaves `type_data` unread.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MenuItemInfoW {
    pub size: u32,
    pub mask: u32,
    pub item_type: u32,
    pub state: u32,
    pub id: u32,
    pub submenu: u32,
    pub checked: u32,
    pub unchecked: u32,
    pub item_data: u32,
    pub type_data: u32,
    pub cch: u32,
    pub bitmap: u32,
}

/// NtUserThunkedMenuItemInfo's operations (F2K's own argument): the item inserted before the one
/// named (by position, at the end when the position is past it), the item's fields the mask
/// names set, the item answered as a [`MenuItemAnswer`], the menu itself answered (its item count
/// in `count`: the handle checked).
pub const MENU_ITEM_INSERT: u32 = 0;
pub const MENU_ITEM_SET: u32 = 1;
pub const MENU_ITEM_QUERY: u32 = 2;
pub const MENU_QUERY: u32 = 3;

/// What F2K's menu query answers about an item (or, for [`MENU_QUERY`], the menu: its count
/// alone): what Windows 2000's user32 reads from the menu's record.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MenuItemAnswer {
    /// How many items the menu holding the item has (the menu's own, for [`MENU_QUERY`]).
    pub count: u32,
    /// The menu holding the item (a popup's, for an item found by command inside it) and the
    /// item's position there.
    pub holder: u32,
    pub position: u32,
    pub item_type: u32,
    pub state: u32,
    pub id: u32,
    /// The popup the item opens (its handle; 0 for none) and how many items it has.
    pub submenu: u32,
    pub submenu_count: u32,
    pub item_data: u32,
    /// The item's text: its length in units and its units (no NUL).
    pub text_length: u32,
    pub text: [u16; MENU_ITEM_TEXT],
}

impl MenuItemAnswer {
    /// An answer of nothing yet.
    pub const EMPTY: MenuItemAnswer = MenuItemAnswer {
        count: 0,
        holder: 0,
        position: 0,
        item_type: 0,
        state: 0,
        id: 0,
        submenu: 0,
        submenu_count: 0,
        item_data: 0,
        text_length: 0,
        text: [0; MENU_ITEM_TEXT],
    };

    /// The item's text.
    pub fn text(&self) -> &[u16] {
        &self.text[..(self.text_length as usize).min(MENU_ITEM_TEXT)]
    }
}

const _: () = {
    assert!(size_of::<MenuItemInfoW>() == 48);
    assert!(offset_of!(MenuItemInfoW, type_data) == 36);
    assert!(size_of::<MenuItemAnswer>() == 40 + 2 * MENU_ITEM_TEXT);
};

// SAFETY: twelve 32-bit integers.
unsafe impl Pod for MenuItemInfoW {}
// SAFETY: ten 32-bit integers and an array of units of an even length: no padding (the assert
// above pins the size); any bit pattern is a value.
unsafe impl Pod for MenuItemAnswer {}

/// GetMenuState's word for an item of type `item_type` and state `state`: the two together; for an
/// item that opens a popup of `count` items, their low byte, MF_POPUP, and the count in the high
/// byte of the low word (the real machine's capture: 0x510 for a popup of five items).
pub fn state_word(item_type: u32, state: u32, popup_count: Option<u32>) -> u32 {
    let flags = item_type | state;
    match popup_count {
        Some(count) => (flags & 0xFF) | MF_POPUP | ((count & 0xFF) << 8),
        None => flags,
    }
}

/// An item's type and state from AppendMenu's old flags (and a MENU resource's): the breaks, the
/// owner-drawn and help bits, the separator are its type; the enabling and check bits its state.
/// A separator is grayed, as Windows 2000's are (GetMenuState answers 0x803 for one).
pub fn from_flags(flags: u32) -> (u32, u32) {
    let mut item_type =
        flags & (MF_MENUBARBREAK | MF_MENUBREAK | MF_OWNERDRAW | MF_SEPARATOR | MF_HELP);
    let mut state = flags & (MF_GRAYED | MF_DISABLED | MF_CHECKED);
    if flags & MF_SEPARATOR != 0 {
        item_type = MFT_SEPARATOR;
        state |= MFS_GRAYED;
    }
    (item_type, state)
}

// --- The MENU and MENUEX templates ---------------------------------------------------------------

/// One item of a menu template, as [`Template::next`] reads it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TemplateItem<'a> {
    /// The item's type and state (MFT_*, MFS_*).
    pub item_type: u32,
    pub state: u32,
    /// Its command id (0 for a MENU template's popup).
    pub id: u32,
    /// Its text: UTF-16 units as the template holds them (two bytes each, little-endian, at any
    /// alignment), without the NUL.
    pub text: &'a [u8],
    /// The item opens a popup, whose items follow it, up to their level's last.
    pub popup: bool,
    /// The item is its level's last.
    pub last: bool,
}

/// A MENU or MENUEX resource's template, read item by item (an iterator) in the order its items
/// lie, a popup's items right after it (the public layouts: MENUITEMTEMPLATEHEADER and
/// MENUITEMTEMPLATE for a MENU, its version 0; MENUEX_TEMPLATE_HEADER and MENUEX_TEMPLATE_ITEM for
/// a MENUEX, its version 1, each item on a DWORD boundary).
pub struct Template<'a> {
    data: &'a [u8],
    at: usize,
    extended: bool,
}

/// MENUEX_TEMPLATE_ITEM's bResInfo: the item opens a popup; it is its level's last.
const EX_POPUP: u16 = 0x01;
const EX_LAST: u16 = 0x80;

fn word(data: &[u8], at: usize) -> Option<u16> {
    data.get(at..at + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
}

fn dword(data: &[u8], at: usize) -> Option<u32> {
    data.get(at..at + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// The NUL-terminated UTF-16 string at `at`: its units' bytes and the offset past its NUL.
fn string(data: &[u8], at: usize) -> Option<(&[u8], usize)> {
    let mut end = at;
    loop {
        if word(data, end)? == 0 {
            return Some((&data[at..end], end + 2));
        }
        end += 2;
    }
}

impl<'a> Template<'a> {
    /// The template a resource's data holds; none for a version that is neither 0 nor 1, or a
    /// header the data is too short for.
    pub fn new(data: &'a [u8]) -> Option<Self> {
        match word(data, 0)? {
            0 => {
                let offset = word(data, 2)? as usize;
                Some(Template {
                    data,
                    at: 4 + offset,
                    extended: false,
                })
            }
            1 => {
                let offset = word(data, 2)? as usize;
                Some(Template {
                    data,
                    at: 4 + offset,
                    extended: true,
                })
            }
            _ => None,
        }
    }

    /// Whether it is a MENUEX template (a MENU template's popup items have no id).
    pub fn extended(&self) -> bool {
        self.extended
    }

    /// A MENU item: WORD mtOption; WORD mtID unless it is a popup; the text. An item of no text
    /// and no id that opens no popup is a separator (the resource compiler's MENUITEM SEPARATOR).
    fn next_plain(&mut self) -> Option<TemplateItem<'a>> {
        let data = self.data;
        let option = u32::from(word(data, self.at)?);
        let popup = option & MF_POPUP != 0;
        let (id, text_at) = if popup {
            (0, self.at + 2)
        } else {
            (u32::from(word(data, self.at + 2)?), self.at + 4)
        };
        let (text, next) = string(data, text_at)?;
        self.at = next;
        let separator = !popup && id == 0 && text.is_empty();
        let flags = option & !(MF_POPUP | MF_END) | if separator { MF_SEPARATOR } else { 0 };
        let (item_type, state) = from_flags(flags);
        Some(TemplateItem {
            item_type,
            state,
            id,
            text,
            popup,
            last: option & MF_END != 0,
        })
    }

    /// A MENUEX item: DWORD dwType, DWORD dwState, DWORD uId, WORD bResInfo, the text, then on
    /// the next DWORD boundary a popup's DWORD dwHelpId and its items.
    fn next_extended(&mut self) -> Option<TemplateItem<'a>> {
        let data = self.data;
        let at = self.at.next_multiple_of(4);
        let item_type = dword(data, at)?;
        let state = dword(data, at + 4)?;
        let id = dword(data, at + 8)?;
        let info = word(data, at + 12)?;
        let (text, mut next) = string(data, at + 14)?;
        let popup = info & EX_POPUP != 0;
        if popup {
            next = next.next_multiple_of(4) + 4;
        }
        self.at = next;
        Some(TemplateItem {
            item_type: item_type & TYPE_BITS,
            state: state & STATE_BITS,
            id,
            text,
            popup,
            last: info & EX_LAST != 0,
        })
    }
}

impl<'a> Iterator for Template<'a> {
    type Item = TemplateItem<'a>;

    /// The next item; none at the data's end or for an item cut short.
    fn next(&mut self) -> Option<TemplateItem<'a>> {
        if self.extended {
            self.next_extended()
        } else {
            self.next_plain()
        }
    }
}

#[cfg(test)]
mod tests {
    use std::vec::Vec;

    use super::*;

    fn units(text: &str) -> Vec<u8> {
        text.encode_utf16()
            .chain([0])
            .flat_map(|u| u.to_le_bytes())
            .collect()
    }

    fn text(item: &TemplateItem<'_>) -> std::string::String {
        let units: Vec<u16> = item
            .text
            .chunks(2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
            .collect();
        std::string::String::from_utf16(&units).unwrap()
    }

    /// A MENU template as the resource compiler writes one (the menus fixture's, cut down): a
    /// popup with an item, a separator and a grayed item, and an item of the bar.
    #[test]
    fn menu_templates_read_item_by_item() {
        let mut data = std::vec![0, 0, 0, 0];
        data.extend_from_slice(&0x10u16.to_le_bytes());
        data.extend(units("&File"));
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&201u16.to_le_bytes());
        data.extend(units("&New"));
        data.extend_from_slice(&[0, 0, 0, 0]);
        data.extend(units(""));
        data.extend_from_slice(&0x81u16.to_le_bytes());
        data.extend_from_slice(&202u16.to_le_bytes());
        data.extend(units("&Open"));
        data.extend_from_slice(&0x80u16.to_le_bytes());
        data.extend_from_slice(&220u16.to_le_bytes());
        data.extend(units("&Help"));
        let mut template = Template::new(&data).unwrap();
        let file = template.next().unwrap();
        assert!(file.popup && !file.last);
        assert_eq!(
            (text(&file).as_str(), file.item_type, file.state),
            ("&File", 0, 0)
        );
        let new = template.next().unwrap();
        assert_eq!(
            (new.id, text(&new).as_str(), new.popup),
            (201, "&New", false)
        );
        let separator = template.next().unwrap();
        assert_eq!(
            (separator.item_type, separator.state),
            (MFT_SEPARATOR, MFS_GRAYED)
        );
        let open = template.next().unwrap();
        assert_eq!((open.id, open.state, open.last), (202, MF_GRAYED, true));
        let help = template.next().unwrap();
        assert_eq!((help.id, help.last, help.popup), (220, true, false));
        assert_eq!(template.next(), None);
    }

    /// A MENUEX template: its items on DWORD boundaries, a popup's help id skipped.
    #[test]
    fn menuex_templates_read_item_by_item() {
        let mut data = std::vec![1, 0, 4, 0, 0, 0, 0, 0];
        let item = |data: &mut Vec<u8>, t: u32, s: u32, id: u32, info: u16, name: &str| {
            while data.len() % 4 != 0 {
                data.push(0);
            }
            data.extend_from_slice(&t.to_le_bytes());
            data.extend_from_slice(&s.to_le_bytes());
            data.extend_from_slice(&id.to_le_bytes());
            data.extend_from_slice(&info.to_le_bytes());
            data.extend(units(name));
            if info & EX_POPUP != 0 {
                while data.len() % 4 != 0 {
                    data.push(0);
                }
                data.extend_from_slice(&0u32.to_le_bytes());
            }
        };
        item(&mut data, 0, 0, 7, EX_POPUP, "&View");
        item(&mut data, MFT_RADIOCHECK, MFS_CHECKED, 211, 0, "&Standard");
        item(&mut data, 0, MFS_GRAYED, 212, EX_LAST, "S&cientific");
        item(&mut data, MFT_RIGHTJUSTIFY, 0, 220, EX_LAST, "&Help");
        let mut template = Template::new(&data).unwrap();
        let view = template.next().unwrap();
        assert_eq!(
            (view.id, view.popup, text(&view).as_str()),
            (7, true, "&View")
        );
        let standard = template.next().unwrap();
        assert_eq!(
            (standard.item_type, standard.state, standard.id),
            (MFT_RADIOCHECK, MFS_CHECKED, 211)
        );
        let scientific = template.next().unwrap();
        assert_eq!((scientific.state, scientific.last), (MFS_GRAYED, true));
        let help = template.next().unwrap();
        assert_eq!((help.item_type, help.last), (MFT_RIGHTJUSTIFY, true));
        assert_eq!(template.next(), None);
    }

    /// GetMenuState's word: an item's type and state; a popup's low byte, MF_POPUP and its count.
    #[test]
    fn state_words_are_the_captures() {
        assert_eq!(state_word(MFT_SEPARATOR, MFS_GRAYED, None), 0x803);
        assert_eq!(state_word(MFT_RADIOCHECK, MFS_CHECKED, None), 0x208);
        assert_eq!(state_word(0, 0, Some(5)), 0x510);
        assert_eq!(state_word(0, MF_GRAYED, Some(5)), 0x511);
        assert_eq!(state_word(0, MFS_CHECKED, Some(3)), 0x318);
        assert_eq!(from_flags(MF_GRAYED | MF_CHECKED), (0, 9));
        assert_eq!(from_flags(MF_SEPARATOR), (MFT_SEPARATOR, 3));
    }
}
