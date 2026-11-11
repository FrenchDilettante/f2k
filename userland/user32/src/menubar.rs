//! The menu bar and its popups: the bar drawn in a window's non-client area, the popup menu
//! windows (the system's menu class, #32768), the keyboard menu loop the default window procedure
//! runs for WM_SYSCOMMAND's SC_KEYMENU, DrawMenuBar and EndMenu.
//!
//! Windows 2000 runs the menu loop in win32k (xxxMNLoop), which sends the owner its menu messages
//! by calling back into user mode; F2K's win32k calls no user-mode code, so the loop runs here,
//! modal on the calling thread as the dialog manager's is: it reads the thread's queue through
//! GetMessage, handles the keys itself (TranslateMessage making their characters) and dispatches
//! every other message.
//!
//! The loop, as the public documentation gives it (the menus fixture's capture decides the order
//! once it is taken):
//! - entered: WM_ENTERMENULOOP (FALSE), then WM_INITMENU (the bar) to the owner;
//! - Alt or F10 alone selects the bar's first item; Alt with a letter (SC_KEYMENU's character)
//!   selects the bar item whose mnemonic it is and opens its popup;
//! - a selection sends WM_MENUSELECT (the item's id, or its position for a popup; its flags with
//!   MF_HILITE, and MF_POPUP for a popup; the menu); a popup opened sends WM_INITMENUPOPUP (its
//!   position in its parent) before it shows, its first item then selected; a popup closed sends
//!   WM_UNINITMENUPOPUP;
//! - Left and Right move along the bar (the open popup following) and in and out of nested popups;
//!   Up and Down move in a popup, past separators, wrapping, and open the bar item's popup; a
//!   letter selects the item whose mnemonic it is, carrying it out (or opening its popup) — a
//!   letter no item has sends WM_MENUCHAR, whose answer is followed (MNC_IGNORE beeps);
//! - Enter carries the selected item out, or opens its popup; a grayed or disabled item stays
//!   selected, nothing carried out (an assumption);
//! - Esc closes the innermost popup, and at the bar ends the loop; Alt or F10 again ends it, and so
//!   does EndMenu;
//! - the end: the popups closed (innermost first), WM_MENUSELECT with 0xFFFF and no menu (the
//!   documented "menu closed"), WM_EXITMENULOOP (FALSE); a command chosen is then posted to the
//!   owner as WM_COMMAND (its id, lParam 0).
//! - The loop sends WM_ENTERIDLE (MSGF_MENU, the innermost popup's window) as the queue runs dry.
//!
//! The bar is one row of the menu font (Tahoma, 8 points): each item its text with [`BAR_PAD`]
//! pixels on either side, the mnemonic underlined, a grayed item embossed. The selected item is
//! raised while the bar alone is selected, sunken while its popup is open. A popup's items are
//! [`item_height`] pixels high (a separator [`SEPARATOR`]): the check mark (Marlett's, or a radio
//! item's bullet) in its first column, the text, the accelerator text after its tab
//! right-aligned, the arrow of a nested popup in its last column; the selected item in
//! COLOR_HIGHLIGHT. Windows 2000 hides the mnemonics' underlines until the keyboard is used; F2K
//! always draws them.

use core::sync::atomic::{AtomicU32, Ordering};

use rtl::gdi::{Rect, TRANSPARENT};
use rtl::menu::{
    MenuItemAnswer,
    MFS_CHECKED,
    MFT_RADIOCHECK,
    MFT_SEPARATOR,
    MF_BYPOSITION,
    MF_DISABLED,
    MF_GRAYED,
    MF_POPUP,
};
use rtl::nonclient::{MENU, WS_CHILD};
use rtl::user::{
    Msg,
    WM_CHAR,
    WM_KEYDOWN,
    WM_KEYUP,
    WM_NULL,
    WM_SYSCHAR,
    WM_SYSKEYDOWN,
    WM_SYSKEYUP,
};

use crate::draw::{
    self,
    BDR_RAISEDINNER,
    BDR_SUNKENOUTER,
    BF_RECT,
    DT_CENTER,
    DT_LEFT,
    DT_NOPREFIX,
    DT_RIGHT,
    DT_SINGLELINE,
    DT_VCENTER,
};
use crate::imports::{self, Creation};
use crate::nonclient::{self, color, Framed, Glyph};
use crate::{message, paint, window};

/// The menu messages (winuser.h's WM_*).
pub const WM_COMMAND: u32 = 0x0111;
pub const WM_SYSCOMMAND: u32 = 0x0112;
pub const WM_INITMENU: u32 = 0x0116;
pub const WM_INITMENUPOPUP: u32 = 0x0117;
pub const WM_MENUSELECT: u32 = 0x011F;
pub const WM_MENUCHAR: u32 = 0x0120;
pub const WM_ENTERIDLE: u32 = 0x0121;
pub const WM_UNINITMENUPOPUP: u32 = 0x0125;
pub const WM_ENTERMENULOOP: u32 = 0x0211;
pub const WM_EXITMENULOOP: u32 = 0x0212;

/// WM_SYSCOMMAND's commands (winuser.h's SC_*).
pub const SC_KEYMENU: u32 = 0xF100;

/// WM_ENTERIDLE's MSGF_MENU.
const MSGF_MENU: u32 = 2;
/// WM_MENUSELECT's highlight flag.
const MF_HILITE: u32 = 0x0080;
/// WM_MENUCHAR's answers (its high word).
const MNC_CLOSE: u32 = 1;
const MNC_EXECUTE: u32 = 2;
const MNC_SELECT: u32 = 3;

/// The keys the loop handles (winuser.h's VK_*).
const VK_RETURN: u32 = 0x0D;
const VK_MENU: u32 = 0x12;
const VK_ESCAPE: u32 = 0x1B;
const VK_LEFT: u32 = 0x25;
const VK_UP: u32 = 0x26;
const VK_RIGHT: u32 = 0x27;
const VK_DOWN: u32 = 0x28;
const VK_F10: u32 = 0x79;

/// The system colors the menus are drawn in.
const COLOR_MENU: u32 = 4;
const COLOR_MENUTEXT: u32 = 7;
const COLOR_HIGHLIGHT: u32 = 13;
const COLOR_HIGHLIGHTTEXT: u32 = 14;
const COLOR_3DSHADOW: u32 = 16;
const COLOR_GRAYTEXT: u32 = 17;
const COLOR_3DHILIGHT: u32 = 20;

/// The menu class's atom: the documented #32768.
pub const MENU_CLASS_ATOM: u16 = 0x8000;
/// A popup menu window's extra bytes: its menu at 0, its selected item at 4 (-1 for none).
pub const MENU_EXTRA: i32 = 8;
const EXTRA_MENU: i32 = 0;
const EXTRA_SELECTED: i32 = 4;

/// A bar item's room either side of its text.
pub const BAR_PAD: i32 = 6;
/// A popup's columns: the check mark's (the text starts after it) and the arrow's.
const CHECK_COLUMN: i32 = 17;
const ARROW_COLUMN: i32 = 17;
/// The gap between an item's text and its accelerator text.
const ACCEL_GAP: i32 = 16;
/// A separator's height.
pub const SEPARATOR: i32 = 9;

/// The popup windows' styles: a popup with a dialog frame (Windows 2000's menus have its raised
/// edge), a tool window, over every other window.
const POPUP_STYLE: u32 = 0x8000_0000;
const POPUP_EX_STYLE: u32 = rtl::nonclient::WS_EX_DLGMODALFRAME
    | rtl::nonclient::WS_EX_WINDOWEDGE
    | rtl::nonclient::WS_EX_TOOLWINDOW
    | 0x0000_0008;

/// SetWindowPos's flags the popups are shown with, and HWND_TOPMOST.
const SWP_NOSIZE: u32 = 0x0001;
const SWP_NOMOVE: u32 = 0x0002;
const SWP_NOACTIVATE: u32 = 0x0010;
const SWP_SHOWWINDOW: u32 = 0x0040;
const HWND_TOPMOST: usize = usize::MAX;

/// The levels a loop opens at most: the bar's popup and three nested ones.
const LEVELS: usize = 4;

/// The window whose menu loop runs in this process (0 for none), its bar's selected item
/// (u32::MAX for none) and whether that item's popup is open, for the drawing of its bar; whether
/// EndMenu asked the loop to end.
static OWNER: AtomicU32 = AtomicU32::new(0);
static BAR_SELECTED: AtomicU32 = AtomicU32::new(u32::MAX);
static BAR_OPEN: AtomicU32 = AtomicU32::new(0);
static END_MENU: AtomicU32 = AtomicU32::new(0);

/// The window whose menu loop runs in this process, 0 for none.
pub fn loop_owner() -> usize {
    OWNER.load(Ordering::Acquire) as usize
}

/// The selection of `window`'s bar while its menu loop runs: the item, and whether its popup is
/// open.
pub fn bar_selection(window: usize) -> Option<(u32, bool)> {
    (loop_owner() == window && window != 0)
        .then(|| BAR_SELECTED.load(Ordering::Acquire))
        .filter(|&item| item != u32::MAX)
        .map(|item| (item, BAR_OPEN.load(Ordering::Acquire) != 0))
}

// --- The items -----------------------------------------------------------------------------------

/// The item at `position` of `menu`; none past its end.
fn item(menu: usize, position: u32) -> Option<MenuItemAnswer> {
    crate::menu::query(menu, position, MF_BYPOSITION).ok()
}

/// How many items `menu` has.
fn count(menu: usize) -> u32 {
    item(menu, 0).map_or(0, |answer| answer.count)
}

/// Whether the item is a separator.
fn is_separator(item: &MenuItemAnswer) -> bool {
    item.item_type & MFT_SEPARATOR != 0
}

/// Whether the item is grayed or disabled.
fn is_dimmed(item: &MenuItemAnswer) -> bool {
    item.state & (MF_GRAYED | MF_DISABLED) != 0
}

/// The item's label and accelerator text: its text before and after its first tab.
fn parts(item: &MenuItemAnswer) -> (&[u16], &[u16]) {
    let text = item.text();
    match text.iter().position(|&unit| unit == u16::from(b'\t')) {
        Some(tab) => (&text[..tab], &text[tab + 1..]),
        None => (text, &[]),
    }
}

/// The item's mnemonic, lowercase: the character after its first lone `&`.
fn mnemonic(item: &MenuItemAnswer) -> Option<u16> {
    let (label, _) = parts(item);
    let mut at = 0;
    while at + 1 < label.len() {
        if label[at] == u16::from(b'&') {
            if label[at + 1] != u16::from(b'&') {
                return Some(lower(label[at + 1]));
            }
            at += 1;
        }
        at += 1;
    }
    None
}

/// `unit` in lowercase (the ASCII and Latin-1 letters).
fn lower(unit: u16) -> u16 {
    match unit {
        0x41..=0x5A | 0xC0..=0xDE if unit != 0xD7 => unit + 0x20,
        _ => unit,
    }
}

/// The width of `label` in the DC's font, its prefixes left out.
fn label_width(dc: usize, label: &[u16]) -> i32 {
    let (_, rect) = draw::draw_text_in(
        dc,
        label,
        Rect::default(),
        DT_LEFT | DT_SINGLELINE | draw::DT_CALCRECT,
    );
    rect.right - rect.left
}

/// The font the menus are drawn in selected into `dc`: the DC's font before.
fn select_menu_font(dc: usize) -> Option<usize> {
    let font = nonclient::menu_font();
    (font != 0)
        .then(|| imports::select_object(dc, font))
        .flatten()
}

/// The text of an item drawn into `rect`: COLOR_MENUTEXT, the selection's text color, or a dimmed
/// item's (embossed unless selected).
fn draw_label(dc: usize, label: &[u16], rect: Rect, format: u32, dimmed: bool, selected: bool) {
    imports::set_bk_mode(dc, TRANSPARENT);
    let ink = |index: u32| imports::set_text_color(dc, crate::display::get_sys_color(index as i32));
    if dimmed && !selected {
        ink(COLOR_3DHILIGHT);
        let offset = Rect {
            left: rect.left + 1,
            top: rect.top + 1,
            right: rect.right + 1,
            bottom: rect.bottom + 1,
        };
        draw::draw_text_in(dc, label, offset, format);
        ink(COLOR_3DSHADOW);
    } else if dimmed {
        ink(COLOR_GRAYTEXT);
    } else if selected {
        ink(COLOR_HIGHLIGHTTEXT);
    } else {
        ink(COLOR_MENUTEXT);
    }
    draw::draw_text_in(dc, label, rect, format);
}

// --- The bar -------------------------------------------------------------------------------------

/// The rectangle of the bar item at `index` in the bar `bar`, its height the bar's less the line
/// under it; none past the last item. `dc` has the menu font selected.
fn bar_item(dc: usize, menu: usize, bar: Rect, index: u32) -> Option<Rect> {
    let mut x = bar.left;
    for position in 0..=index {
        let answer = item(menu, position)?;
        let width = label_width(dc, parts(&answer).0) + 2 * BAR_PAD;
        if position == index {
            return Some(Rect {
                left: x,
                top: bar.top,
                right: (x + width).min(bar.right),
                bottom: bar.top + MENU - 1,
            });
        }
        x += width;
    }
    None
}

/// The menu bar of `menu` drawn into `dc` at `bar` (the line under it included), its item
/// `selection` raised, or sunken when its popup is open.
pub fn draw_bar(dc: usize, menu: usize, bar: Rect, selection: Option<(u32, bool)>) {
    draw::fill(dc, bar, color(COLOR_MENU));
    let previous = select_menu_font(dc);
    for index in 0..count(menu) {
        let (Some(answer), Some(rect)) = (item(menu, index), bar_item(dc, menu, bar, index)) else {
            break;
        };
        if rect.left >= bar.right {
            break;
        }
        let mut text_rect = rect;
        match selection {
            Some((selected, open)) if selected == index => {
                if open {
                    draw::draw_edge_in(dc, rect, BDR_SUNKENOUTER, BF_RECT);
                    text_rect.left += 1;
                    text_rect.top += 1;
                    text_rect.right += 1;
                    text_rect.bottom += 1;
                } else {
                    draw::draw_edge_in(dc, rect, BDR_RAISEDINNER, BF_RECT);
                }
            }
            _ => {}
        }
        draw_label(
            dc,
            parts(&answer).0,
            text_rect,
            DT_CENTER | DT_VCENTER | DT_SINGLELINE,
            is_dimmed(&answer),
            false,
        );
    }
    if let Some(previous) = previous {
        imports::select_object(dc, previous);
    }
}

/// The bar of `window` redrawn as it stands (no bar: nothing).
fn redraw_bar(window: usize) {
    let Some(framed) = Framed::of(window) else {
        return;
    };
    let Some(bar) = framed.frame().menu_bar(framed.local()) else {
        return;
    };
    if window::is_window_visible(window) == 0 {
        return;
    }
    let Ok(dc) = imports::get_window_dc(window) else {
        return;
    };
    draw_bar(dc as usize, framed.menu, bar, bar_selection(window));
    let _ = imports::close(dc as usize);
}

/// DrawMenuBar: the window's menu bar redrawn, its items as they now stand; TRUE, or FALSE with
/// 1400 for a handle naming no window.
#[unsafe(export_name = "f2k_export_DrawMenuBar")]
pub extern "system" fn draw_menu_bar(window: usize) -> u32 {
    if !window::is_window_alive(window) {
        return crate::failed(crate::ERROR_INVALID_WINDOW_HANDLE).unwrap_or(0);
    }
    redraw_bar(window);
    1
}

/// EndMenu: the menu loop running in the process ended (its owner's thread woken by a WM_NULL);
/// TRUE.
#[unsafe(export_name = "f2k_export_EndMenu")]
pub extern "system" fn end_menu() -> u32 {
    let owner = loop_owner();
    if owner != 0 {
        END_MENU.store(1, Ordering::Release);
        let _ = imports::post_message(owner, WM_NULL, 0, 0);
    }
    1
}

// --- The popups ----------------------------------------------------------------------------------

/// A popup item's height: the menu font's height and four pixels, no less than a check mark's
/// cell's and four.
pub fn item_height(dc: usize) -> i32 {
    let height = imports::text_metrics(dc).map_or(16, |metric| metric.height);
    height.max(rtl::nonclient::MENU_CHECK) + 4
}

/// The rectangle of the popup item at `index` of `menu`, in its window's client coordinates
/// `width` wide. `dc` has the menu font selected.
fn popup_item(dc: usize, menu: usize, index: u32, width: i32) -> Option<Rect> {
    let height = item_height(dc);
    let mut y = 0;
    for position in 0..=index {
        let answer = item(menu, position)?;
        let h = if is_separator(&answer) {
            SEPARATOR
        } else {
            height
        };
        if position == index {
            return Some(Rect {
                left: 0,
                top: y,
                right: width,
                bottom: y + h,
            });
        }
        y += h;
    }
    None
}

/// The client size of `menu`'s popup. `dc` has the menu font selected.
fn popup_size(dc: usize, menu: usize) -> (i32, i32) {
    let height = item_height(dc);
    let (mut label, mut accel, mut total) = (0, 0, 0);
    for index in 0..count(menu) {
        let Some(answer) = item(menu, index) else {
            break;
        };
        if is_separator(&answer) {
            total += SEPARATOR;
            continue;
        }
        total += height;
        let (text, keys) = parts(&answer);
        label = label.max(label_width(dc, text));
        if !keys.is_empty() {
            accel = accel.max(label_width(dc, keys));
        }
    }
    let accel = if accel > 0 { ACCEL_GAP + accel } else { 0 };
    (CHECK_COLUMN + label + accel + ARROW_COLUMN, total)
}

/// The items of the popup `menu` drawn into `dc` over its client area `client`, `selected`
/// highlighted.
fn draw_popup(dc: usize, menu: usize, client: Rect, selected: Option<u32>) {
    draw::fill(dc, client, color(COLOR_MENU));
    let previous = select_menu_font(dc);
    for index in 0..count(menu) {
        let (Some(answer), Some(rect)) = (
            item(menu, index),
            popup_item(dc, menu, index, client.right - client.left),
        ) else {
            break;
        };
        if is_separator(&answer) {
            let middle = rect.top + SEPARATOR / 2;
            let line = |top: i32, index: u32| {
                let row = Rect {
                    left: rect.left + 1,
                    top,
                    right: rect.right - 1,
                    bottom: top + 1,
                };
                draw::fill(dc, row, color(index));
            };
            line(middle - 1, COLOR_3DSHADOW);
            line(middle, COLOR_3DHILIGHT);
            continue;
        }
        let is_selected = selected == Some(index);
        if is_selected {
            draw::fill(dc, rect, color(COLOR_HIGHLIGHT));
        }
        let dimmed = is_dimmed(&answer);
        let ink = if is_selected {
            COLOR_HIGHLIGHTTEXT
        } else {
            COLOR_MENUTEXT
        };
        if answer.state & MFS_CHECKED != 0 {
            let glyph = if answer.item_type & MFT_RADIOCHECK != 0 {
                Glyph::Bullet
            } else {
                Glyph::Check
            };
            let column = Rect {
                right: rect.left + CHECK_COLUMN,
                ..rect
            };
            nonclient::draw_glyph(dc, glyph, column, !dimmed || is_selected, ink);
        }
        let (label, keys) = parts(&answer);
        let text = Rect {
            left: rect.left + CHECK_COLUMN,
            right: rect.right - ARROW_COLUMN,
            ..rect
        };
        let format = DT_VCENTER | DT_SINGLELINE;
        draw_label(dc, label, text, DT_LEFT | format, dimmed, is_selected);
        if !keys.is_empty() {
            draw_label(
                dc,
                keys,
                text,
                DT_RIGHT | DT_NOPREFIX | format,
                dimmed,
                is_selected,
            );
        }
        if answer.submenu != 0 {
            let column = Rect {
                left: rect.right - ARROW_COLUMN,
                ..rect
            };
            nonclient::draw_glyph(dc, Glyph::Arrow, column, !dimmed || is_selected, ink);
        }
    }
    if let Some(previous) = previous {
        imports::select_object(dc, previous);
    }
}

/// A popup menu window's menu and selection, from its extra bytes.
fn popup_state(window: usize) -> (usize, Option<u32>) {
    let menu = window::get_window_long_w(window, EXTRA_MENU) as u32 as usize;
    let selected = window::get_window_long_w(window, EXTRA_SELECTED);
    (menu, (selected >= 0).then_some(selected as u32))
}

/// The popup window's items drawn into a DC of its client area, as they now stand.
fn redraw_popup(window: usize) {
    let (menu, selected) = popup_state(window);
    let Some(client) = window::client_rect(window) else {
        return;
    };
    let Ok(dc) = imports::get_dc(window) else {
        return;
    };
    draw_popup(dc as usize, menu, client, selected);
    let _ = imports::close(dc as usize);
}

/// The menu class's procedure (#32768), both forms: its items painted on WM_PAINT, its background
/// the menu's color; the rest the default procedure's.
pub fn menu_proc(window: usize, message: u32, wparam: u32, lparam: i32, ansi: bool) -> i32 {
    match message {
        rtl::user::WM_PAINT => {
            if let Some(painting) = paint::Painting::begin(window) {
                let (menu, selected) = popup_state(window);
                if let Some(client) = window::client_rect(window) {
                    draw_popup(painting.dc(), menu, client, selected);
                }
            }
            0
        }
        rtl::user::WM_ERASEBKGND => {
            if let Some(client) = window::client_rect(window) {
                draw::fill(wparam as usize, client, color(COLOR_MENU));
            }
            1
        }
        _ => message::default_procedure(window, message, wparam, lparam, ansi),
    }
}

/// The menu class's wide procedure.
pub extern "system" fn menu_proc_w(window: usize, message: u32, wparam: u32, lparam: i32) -> i32 {
    menu_proc(window, message, wparam, lparam, false)
}

/// The menu class's narrow procedure.
pub extern "system" fn menu_proc_a(window: usize, message: u32, wparam: u32, lparam: i32) -> i32 {
    menu_proc(window, message, wparam, lparam, true)
}

// --- The loop ------------------------------------------------------------------------------------

/// An open popup: its menu, its window, its selected item.
#[derive(Clone, Copy, Debug, Default)]
struct Level {
    menu: usize,
    window: usize,
    selected: Option<u32>,
}

/// How a loop ends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum End {
    /// Not yet.
    Running,
    /// Without a command.
    Cancelled,
    /// With the command of this id.
    Command(u32),
}

/// A keyboard menu loop's state.
struct Tracker {
    owner: usize,
    bar: usize,
    /// The bar's selected item.
    bar_selected: Option<u32>,
    /// The popups open, the bar's first.
    levels: [Level; LEVELS],
    depth: usize,
    end: End,
}

/// The selection message's word for an item: its id (its position for a popup) and its flags.
fn select_word(answer: &MenuItemAnswer, position: u32) -> u32 {
    let flags = (answer.item_type | answer.state) & 0x0F7F | MF_HILITE;
    if answer.submenu != 0 {
        (position & 0xFFFF) | (flags | MF_POPUP) << 16
    } else {
        (answer.id & 0xFFFF) | flags << 16
    }
}

impl Tracker {
    /// The menu the keys move in: the innermost popup's, or the bar.
    fn current(&self) -> usize {
        if self.depth == 0 {
            self.bar
        } else {
            self.levels[self.depth - 1].menu
        }
    }

    /// The bar's selection published for its drawing, and the bar redrawn.
    fn show_bar(&self) {
        BAR_SELECTED.store(self.bar_selected.unwrap_or(u32::MAX), Ordering::Release);
        BAR_OPEN.store((self.depth > 0) as u32, Ordering::Release);
        redraw_bar(self.owner);
    }

    /// The bar item `index` selected: WM_MENUSELECT, the bar redrawn.
    fn select_bar(&mut self, index: u32) {
        self.bar_selected = Some(index);
        self.show_bar();
        if let Some(answer) = item(self.bar, index) {
            let _ = message::send(
                self.owner,
                WM_MENUSELECT,
                select_word(&answer, index),
                self.bar as i32,
            );
        }
    }

    /// The item `index` of the innermost popup selected: WM_MENUSELECT, the popup redrawn.
    fn select_item(&mut self, index: u32) {
        let level = &mut self.levels[self.depth - 1];
        level.selected = Some(index);
        let (menu, popup) = (level.menu, level.window);
        window::set_window_long_w(popup, EXTRA_SELECTED, index as i32);
        redraw_popup(popup);
        if let Some(answer) = item(menu, index) {
            let _ = message::send(
                self.owner,
                WM_MENUSELECT,
                select_word(&answer, index),
                menu as i32,
            );
        }
    }

    /// The popup the selected item of the current menu opens, opened under the bar item or beside
    /// the popup item: WM_INITMENUPOPUP, its window shown, its first item selected. Nothing for an
    /// item opening none.
    fn open(&mut self) {
        if self.depth >= LEVELS {
            return;
        }
        let (parent, position) = if self.depth == 0 {
            (self.bar, self.bar_selected)
        } else {
            let level = self.levels[self.depth - 1];
            (level.menu, level.selected)
        };
        let Some(position) = position else {
            return;
        };
        let Some(answer) = item(parent, position) else {
            return;
        };
        if answer.submenu == 0 {
            return;
        }
        let menu = answer.submenu as usize;
        let _ = message::send(
            self.owner,
            WM_INITMENUPOPUP,
            menu as u32,
            (position & 0xFFFF) as i32,
        );

        // Its place: under the bar item, or beside the popup item, kept on the screen.
        let Ok(screen_dc) = imports::get_dc(0) else {
            return;
        };
        let screen_dc = screen_dc as usize;
        let previous = select_menu_font(screen_dc);
        let (cx, cy) = popup_size(screen_dc, menu);
        let anchor = if self.depth == 0 {
            Framed::of(self.owner).and_then(|framed| {
                let bar = framed.frame().menu_bar(framed.rect)?;
                bar_item(screen_dc, self.bar, bar, position)
                    .map(|rect| (rect.left, bar.top + MENU - 1))
            })
        } else {
            let level = self.levels[self.depth - 1];
            window::window_info(level.window).ok().and_then(|info| {
                let width = info.client.right - info.client.left;
                popup_item(screen_dc, level.menu, position, width).map(|rect| {
                    (
                        info.window.right - rtl::nonclient::DLG_FRAME,
                        info.client.top + rect.top - rtl::nonclient::DLG_FRAME,
                    )
                })
            })
        };
        if let Some(previous) = previous {
            imports::select_object(screen_dc, previous);
        }
        let _ = imports::close(screen_dc);
        let (x, y) = anchor.unwrap_or((0, 0));
        let frame = rtl::nonclient::Frame::of_styles(POPUP_STYLE, POPUP_EX_STYLE, false);
        let outer = frame.window(Rect {
            left: 0,
            top: 0,
            right: cx,
            bottom: cy,
        });
        let (width, height) = (outer.right - outer.left, outer.bottom - outer.top);
        let screen_width = crate::display::get_system_metrics(0);
        let screen_height = crate::display::get_system_metrics(1);
        let x = x.min(screen_width - width).max(0);
        let y = y.min(screen_height - height).max(0);
        let popup = window::create(&Creation {
            ex_style: POPUP_EX_STYLE,
            class: usize::from(MENU_CLASS_ATOM),
            name: 0,
            style: POPUP_STYLE,
            x,
            y,
            cx: width,
            cy: height,
            parent: self.owner,
            menu: 0,
            instance: crate::class::USER32_MODULE,
            param: 0,
            version: window::EXPECTED_VERSION,
        });
        if popup == 0 {
            return;
        }
        window::set_window_long_w(popup, EXTRA_MENU, menu as i32);
        window::set_window_long_w(popup, EXTRA_SELECTED, -1);
        self.levels[self.depth] = Level {
            menu,
            window: popup,
            selected: None,
        };
        self.depth += 1;
        if self.depth == 1 {
            self.show_bar();
        }
        window::set_window_pos(
            popup,
            HWND_TOPMOST,
            0,
            0,
            0,
            0,
            SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE | SWP_SHOWWINDOW,
        );
        if let Some(first) = self.next_item(None, true) {
            self.select_item(first);
        }
    }

    /// The innermost popup closed: its window destroyed, WM_UNINITMENUPOPUP.
    fn close(&mut self) {
        if self.depth == 0 {
            return;
        }
        self.depth -= 1;
        let level = self.levels[self.depth];
        window::destroy_window(level.window);
        let _ = message::send(self.owner, WM_UNINITMENUPOPUP, level.menu as u32, 0);
        if self.depth == 0 {
            self.show_bar();
        }
    }

    /// The item after (`forward`) or before `from` in the innermost popup, past separators,
    /// wrapping; the first (or last) for none.
    fn next_item(&self, from: Option<u32>, forward: bool) -> Option<u32> {
        let menu = self.current();
        let total = count(menu);
        if total == 0 {
            return None;
        }
        let mut at = from;
        for _ in 0..total {
            let next = match (at, forward) {
                (None, true) => 0,
                (None, false) => total - 1,
                (Some(i), true) => (i + 1) % total,
                (Some(i), false) => (i + total - 1) % total,
            };
            if item(menu, next).is_some_and(|answer| !is_separator(&answer)) {
                return Some(next);
            }
            at = Some(next);
        }
        None
    }

    /// The bar's selection moved one item along (`forward`) or back, wrapping; the popup that was
    /// open closed, the new item's opened.
    fn move_bar(&mut self, forward: bool) {
        let total = count(self.bar);
        if total == 0 {
            return;
        }
        let was_open = self.depth > 0;
        while self.depth > 0 {
            self.close();
        }
        let current = self.bar_selected.unwrap_or(0);
        let next = if forward {
            (current + 1) % total
        } else {
            (current + total - 1) % total
        };
        self.select_bar(next);
        if was_open {
            self.open();
        }
    }

    /// The selected item of the current menu carried out: its popup opened, or its command the
    /// loop's end; a dimmed item stays selected.
    fn choose(&mut self) {
        let (menu, selected) = if self.depth == 0 {
            (self.bar, self.bar_selected)
        } else {
            let level = self.levels[self.depth - 1];
            (level.menu, level.selected)
        };
        let Some(answer) = selected.and_then(|index| item(menu, index)) else {
            return;
        };
        if answer.submenu != 0 {
            self.open();
        } else if !is_dimmed(&answer) && !is_separator(&answer) {
            self.end = End::Command(answer.id);
        }
    }

    /// A key pressed.
    fn key(&mut self, vk: u32) {
        match vk {
            VK_ESCAPE => {
                if self.depth > 0 {
                    self.close();
                    if self.depth == 0 {
                        if let Some(index) = self.bar_selected {
                            self.select_bar(index);
                        }
                    }
                } else {
                    self.end = End::Cancelled;
                }
            }
            VK_MENU | VK_F10 => self.end = End::Cancelled,
            VK_LEFT => {
                if self.depth > 1 {
                    self.close();
                } else {
                    self.move_bar(false);
                }
            }
            VK_RIGHT => {
                let opens = self.depth > 0 && {
                    let level = self.levels[self.depth - 1];
                    level
                        .selected
                        .and_then(|index| item(level.menu, index))
                        .is_some_and(|answer| answer.submenu != 0)
                };
                if opens {
                    self.open();
                } else {
                    self.move_bar(true);
                }
            }
            VK_UP | VK_DOWN => {
                if self.depth == 0 {
                    self.open();
                } else {
                    let selected = self.levels[self.depth - 1].selected;
                    if let Some(next) = self.next_item(selected, vk == VK_DOWN) {
                        self.select_item(next);
                    }
                }
            }
            VK_RETURN => self.choose(),
            _ => {}
        }
    }

    /// A character typed: the item of the current menu whose mnemonic it is selected and carried
    /// out; WM_MENUCHAR when none is.
    fn character(&mut self, unit: u16) {
        let menu = self.current();
        let wanted = lower(unit);
        let found = (0..count(menu)).find(|&index| {
            item(menu, index).is_some_and(|answer| mnemonic(&answer) == Some(wanted))
        });
        let found = match found {
            Some(index) => Some(index),
            None => {
                let flags = if self.depth > 0 { MF_POPUP } else { 0 };
                let answer = message::send(
                    self.owner,
                    WM_MENUCHAR,
                    u32::from(unit) | flags << 16,
                    menu as i32,
                )
                .unwrap_or(0) as u32;
                match answer >> 16 {
                    MNC_CLOSE => {
                        self.end = End::Cancelled;
                        None
                    }
                    MNC_EXECUTE | MNC_SELECT => {
                        let index = answer & 0xFFFF;
                        if answer >> 16 == MNC_SELECT {
                            self.select(index);
                            return;
                        }
                        Some(index)
                    }
                    // MNC_IGNORE: Windows beeps, and F2K has no sound to make (MessageBeep).
                    _ => None,
                }
            }
        };
        if let Some(index) = found {
            self.select(index);
            self.choose();
        }
    }

    /// The item `index` of the current menu selected.
    fn select(&mut self, index: u32) {
        if self.depth == 0 {
            self.select_bar(index);
        } else {
            self.select_item(index);
        }
    }

    /// The end: the popups closed, the menu-closed WM_MENUSELECT, the bar redrawn as it rests,
    /// WM_EXITMENULOOP.
    fn finish(&mut self) {
        while self.depth > 0 {
            self.close();
        }
        let _ = message::send(self.owner, WM_MENUSELECT, 0xFFFF << 16, 0);
        OWNER.store(0, Ordering::Release);
        BAR_SELECTED.store(u32::MAX, Ordering::Release);
        BAR_OPEN.store(0, Ordering::Release);
        redraw_bar(self.owner);
        let _ = message::send(self.owner, WM_EXITMENULOOP, 0, 0);
    }
}

/// The keyboard menu loop of `owner`'s menu bar, run to its end: Alt or F10 alone (`character`
/// 0) selects the first bar item, a character the item whose mnemonic it is. Nothing for a window
/// without a menu bar, or while another loop runs in the process.
pub fn track_keyboard(owner: usize, character: u32) {
    let Some(framed) = Framed::of(owner) else {
        return;
    };
    if framed.menu == 0 || framed.style & WS_CHILD != 0 || count(framed.menu) == 0 {
        return;
    }
    if OWNER
        .compare_exchange(0, owner as u32, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return;
    }
    END_MENU.store(0, Ordering::Release);
    let mut tracker = Tracker {
        owner,
        bar: framed.menu,
        bar_selected: None,
        levels: [Level::default(); LEVELS],
        depth: 0,
        end: End::Running,
    };
    let _ = message::send(owner, WM_ENTERMENULOOP, 0, 0);
    let _ = message::send(owner, WM_INITMENU, framed.menu as u32, 0);
    if character == 0 {
        tracker.select_bar(0);
    } else {
        tracker.character(character as u16);
    }

    let mut idle_sent = false;
    let mut quit = None;
    while tracker.end == End::Running {
        if END_MENU.swap(0, Ordering::AcqRel) != 0 {
            tracker.end = End::Cancelled;
            break;
        }
        if !message::queue_holds_message() {
            if !idle_sent {
                idle_sent = true;
                let popup = match tracker.depth {
                    0 => 0,
                    depth => tracker.levels[depth - 1].window,
                };
                let _ = message::send(owner, WM_ENTERIDLE, MSGF_MENU, popup as i32);
                continue;
            }
        } else {
            idle_sent = false;
        }
        let mut msg = Msg::default();
        match message::next_message(&mut msg) {
            None => tracker.end = End::Cancelled,
            Some(false) => {
                quit = Some(msg.wparam);
                tracker.end = End::Cancelled;
            }
            Some(true) => match msg.message {
                WM_KEYDOWN | WM_SYSKEYDOWN => {
                    message::translate(&msg);
                    tracker.key(msg.wparam);
                }
                WM_CHAR | WM_SYSCHAR => tracker.character(msg.wparam as u16),
                WM_KEYUP | WM_SYSKEYUP => {}
                _ => {
                    message::dispatch(&msg, false);
                }
            },
        }
    }
    tracker.finish();
    if let End::Command(id) = tracker.end {
        let _ = imports::post_message(owner, WM_COMMAND, id & 0xFFFF, 0);
    }
    if let Some(code) = quit {
        message::post_quit_message(code as i32);
    }
}

#[cfg(test)]
mod tests {
    use core::cell::RefCell;

    use super::*;
    use crate::class::{register_class_a, WndClass, SYSTEM_CLASSES_WANTED};
    use crate::imports::host::procedure;
    use crate::menu::{append_menu_w, create_menu, create_popup_menu};
    use crate::window::create_window_ex_a;

    std::thread_local! {
        static SEEN: RefCell<std::vec::Vec<(u32, u32, i32)>> = const { RefCell::new(std::vec::Vec::new()) };
    }

    /// A procedure recording the menu messages, every message handed on to DefWindowProc.
    fn recorder(window: u32, message: u32, wparam: u32, lparam: i32) -> i32 {
        if matches!(
            message,
            WM_ENTERMENULOOP
                | WM_EXITMENULOOP
                | WM_INITMENU
                | WM_INITMENUPOPUP
                | WM_UNINITMENUPOPUP
                | WM_MENUSELECT
                | WM_COMMAND
        ) {
            SEEN.with(|seen| seen.borrow_mut().push((message, wparam, lparam)));
        }
        crate::message::def_window_proc_a(window as usize, message, wparam, lparam)
    }

    fn units(text: &str) -> std::vec::Vec<u16> {
        text.encode_utf16().chain([0]).collect()
    }

    /// A bar of "&File" and "&View", View's popup holding "&Standard" (211) and "S&cientific"
    /// (212), and a shown window holding it: the window, the bar, View's popup.
    fn window_with_menu() -> (usize, usize, usize) {
        SYSTEM_CLASSES_WANTED.with(|wanted| wanted.set(true));
        let bar = create_menu();
        let file = create_popup_menu();
        let view = create_popup_menu();
        // SAFETY: the test's own strings.
        unsafe {
            append_menu_w(file, 0, 201, units("&New").as_ptr());
            append_menu_w(view, 0, 211, units("&Standard").as_ptr());
            append_menu_w(view, 0, 212, units("S&cientific").as_ptr());
            append_menu_w(bar, MF_POPUP, file, units("&File").as_ptr());
            append_menu_w(bar, MF_POPUP, view, units("&View").as_ptr());
        }
        let class = WndClass {
            wnd_proc: procedure(recorder) as usize,
            class_name: c"F2KMenuLoop".as_ptr() as usize,
            ..WndClass::default()
        };
        // SAFETY: a WNDCLASSA of the test's own, and its name.
        let window = unsafe {
            register_class_a(&class);
            create_window_ex_a(
                0,
                c"F2KMenuLoop".as_ptr().cast(),
                core::ptr::null(),
                0x10CF_0000,
                100,
                80,
                300,
                200,
                0,
                0,
                0,
                0,
            )
        };
        crate::menu::set_menu(window, bar);
        (window, bar, view)
    }

    /// The mnemonics, and the selection's word: a popup by its position with MF_POPUP, a command
    /// by its id.
    #[test]
    fn mnemonics_and_the_selection_word() {
        let mut answer = MenuItemAnswer::EMPTY;
        let text: std::vec::Vec<u16> = "S&cientific\tF4".encode_utf16().collect();
        answer.text[..text.len()].copy_from_slice(&text);
        answer.text_length = text.len() as u32;
        answer.id = 212;
        assert_eq!(mnemonic(&answer), Some(u16::from(b'c')));
        assert_eq!(parts(&answer).1, &text[12..]);
        assert_eq!(select_word(&answer, 1), 212 | 0x0080 << 16);
        answer.submenu = 0x1234;
        assert_eq!(select_word(&answer, 1), 1 | 0x0090 << 16);
        assert_eq!(lower(u16::from(b'V')), u16::from(b'v'));
    }

    /// Right, Down, Down and Enter after Alt: the loop's messages in order, View's popup opened
    /// and Scientific chosen, its WM_COMMAND posted after the loop's end.
    ///
    /// Pins: user32.DefWindowProcA, user32.AppendMenuW, user32.DrawMenuBar
    #[test]
    fn the_keyboard_loop_chooses_an_item() {
        let (window, bar, view) = window_with_menu();
        crate::message::receive_sent();
        for vk in [VK_RIGHT, VK_DOWN, VK_DOWN, VK_RETURN] {
            let _ = imports::post_message(window, WM_KEYDOWN, vk, 0);
        }
        SEEN.with(|seen| seen.borrow_mut().clear());
        track_keyboard(window, 0);
        let seen = SEEN.with(|seen| seen.take());
        let (bar_menu, view_menu) = (bar as i32, view as i32);
        assert_eq!(
            seen,
            [
                (WM_ENTERMENULOOP, 0, 0),
                (WM_INITMENU, bar as u32, 0),
                (WM_MENUSELECT, 0x0090 << 16, bar_menu),
                (WM_MENUSELECT, 1 | 0x0090 << 16, bar_menu),
                (WM_INITMENUPOPUP, view as u32, 1),
                (WM_MENUSELECT, 211 | 0x0080 << 16, view_menu),
                (WM_MENUSELECT, 212 | 0x0080 << 16, view_menu),
                (WM_UNINITMENUPOPUP, view as u32, 0),
                (WM_MENUSELECT, 0xFFFF << 16, 0),
                (WM_EXITMENULOOP, 0, 0),
            ]
        );
        assert_eq!(loop_owner(), 0);
        let mut msg = Msg::default();
        assert_eq!(crate::message::next_message(&mut msg), Some(true));
        assert_eq!((msg.message, msg.wparam, msg.lparam), (WM_COMMAND, 212, 0));
        assert_eq!(draw_menu_bar(window), 1);
    }
}
