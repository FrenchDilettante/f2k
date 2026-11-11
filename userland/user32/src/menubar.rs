//! The menu bar: drawn in a window's non-client area from the menu's records (the items' text in
//! the menu font, Tahoma 8 points, each with [`BAR_PAD`] pixels on either side, the mnemonic
//! underlined, a grayed item embossed), and DrawMenuBar. Windows 2000 hides the mnemonics'
//! underlines until the keyboard is used; F2K always draws them. The bar is one row: F2K does not
//! wrap a bar too narrow for its items onto more rows.
//!
//! A menu loop running for the window (none yet) selects one of the bar's items: raised while the
//! bar alone is selected, sunken while its popup is open.

use core::sync::atomic::{AtomicU32, Ordering};

use rtl::gdi::{Rect, TRANSPARENT};
use rtl::menu::{MenuItemAnswer, MF_BYPOSITION, MF_DISABLED, MF_GRAYED};
use rtl::nonclient::MENU;

use crate::draw::{
    self,
    BDR_RAISEDINNER,
    BDR_SUNKENOUTER,
    BF_RECT,
    DT_CENTER,
    DT_LEFT,
    DT_SINGLELINE,
    DT_VCENTER,
};
use crate::imports;
use crate::nonclient::{self, color, Framed};
use crate::window;

/// The system colors the menus are drawn in.
const COLOR_MENU: u32 = 4;
const COLOR_MENUTEXT: u32 = 7;
const COLOR_HIGHLIGHTTEXT: u32 = 14;
const COLOR_3DSHADOW: u32 = 16;
const COLOR_GRAYTEXT: u32 = 17;
const COLOR_3DHILIGHT: u32 = 20;

/// A bar item's room either side of its text.
pub const BAR_PAD: i32 = 6;

/// The window whose menu loop runs in this process (0 for none), its bar's selected item
/// (u32::MAX for none) and whether that item's popup is open, for the drawing of its bar.
static OWNER: AtomicU32 = AtomicU32::new(0);
static BAR_SELECTED: AtomicU32 = AtomicU32::new(u32::MAX);
static BAR_OPEN: AtomicU32 = AtomicU32::new(0);

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
