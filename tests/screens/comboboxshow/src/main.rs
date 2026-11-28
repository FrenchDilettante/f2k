//! comboboxshow.exe: a top-level window with three ComboBox controls in its client area, the first
//! one's list dropped down, for test_comboboxes.py to look at.
//!
//! - A CBS_DROPDOWNLIST combo box: six items, the third selected, the focus on it, its list dropped
//!   down (CB_SHOWDROPDOWN) below it, cut to its six items.
//! - A CBS_DROPDOWN combo box: three items, its edit holding a text of its own.
//! - A CBS_SIMPLE combo box with WS_VSCROLL: its edit above its list of five items, the second
//!   selected (its text in the edit).
//!
//! The window does not clip its children (no WS_CLIPCHILDREN), so its painting covers the combo
//! boxes; each paints after it, its frame included. The program paints them all (UpdateWindow, the
//! window and then its descendants) before it drops the first combo box's list: F2K's top-level
//! windows do not cut one another's DCs yet (kernel/src/win32k/paint.rs's visible regions), so the
//! window painted later would cover the dropped list, a top-level window of its own.
//!
//! It prints `comboboxshow: ready` once the window shows and its queue is idle; Alt+F4 closes the
//! window (the default procedure's SC_CLOSE), which ends it with 0.

#![no_std]
#![no_main]

use common::{TopLevel, Wide, Window};
use exe::winuser::{
    CBS_DROPDOWN,
    CBS_DROPDOWNLIST,
    CBS_SIMPLE,
    CB_ADDSTRING,
    CB_SETCURSEL,
    CB_SHOWDROPDOWN,
    COLOR_3DFACE,
    WS_CAPTION,
    WS_SYSMENU,
    WS_VISIBLE,
    WS_VSCROLL,
};

exe::entry!(main);

/// The calls comboboxshow makes: the shared ones (common::ffi).
use common::ffi;

/// The window's styles: a caption with its system menu, a fixed frame.
const STYLE: u32 = WS_CAPTION | WS_SYSMENU | WS_VISIBLE;

/// WM_SETTEXT.
const WM_SETTEXT: u32 = 0x000C;

/// The line printed once the window shows and the queue is idle.
const READY: &str = "comboboxshow: ready";
/// The exit code when a window cannot be made.
const NO_WINDOW: u32 = 1;

/// The items.
const ITEMS: [&str; 6] = ["Alpha", "Bravo", "Charlie", "Delta", "Echo", "Foxtrot"];

/// A combo box child of `window` at (`x`, `y`), `cx` wide and made `cy` high, with `style`, its id
/// `id`, holding `items`, the item `selected` selected (none for -1); 0 when it cannot be made.
fn combo_box(
    window: &Window,
    style: u32,
    place: (i32, i32, i32, i32),
    id: usize,
    items: &[&str],
    selected: isize,
) -> usize {
    let combo = window.child("ComboBox", 0, style, "", place, id);
    if combo != 0 {
        // SAFETY: the program's own window and strings, which live for each call.
        unsafe {
            for item in items {
                let text = Wide::of(item);
                ffi::SendMessageW(combo, CB_ADDSTRING, 0, text.as_ptr() as isize);
            }
            if selected >= 0 {
                ffi::SendMessageW(combo, CB_SETCURSEL, selected as usize, 0);
            }
        }
    }
    combo
}

fn main() -> u32 {
    let made = TopLevel {
        class: "ComboBoxShow",
        title: "Combo boxes",
        procedure: common::procedure,
        background: COLOR_3DFACE + 1,
        style: STYLE,
        client: (300, 200),
        menu: 0,
    }
    .create();
    let (window, list, drop, simple) = match made {
        None => (None, 0, 0, 0),
        Some(window) => (
            Some(window),
            combo_box(
                &window,
                CBS_DROPDOWNLIST | WS_VSCROLL,
                (10, 10, 130, 150),
                101,
                &ITEMS,
                2,
            ),
            combo_box(
                &window,
                CBS_DROPDOWN | WS_VSCROLL,
                (160, 10, 130, 100),
                102,
                &ITEMS[..3],
                -1,
            ),
            combo_box(
                &window,
                CBS_SIMPLE | WS_VSCROLL,
                (160, 50, 130, 140),
                103,
                &ITEMS[..5],
                1,
            ),
        ),
    };
    let Some(window) = window.filter(|_| list != 0 && drop != 0 && simple != 0) else {
        let _ = exe::stderr().print(format_args!("comboboxshow: the windows cannot be made\r\n"));
        return NO_WINDOW;
    };
    let typed = Wide::of("Typed");
    // SAFETY: the program's own windows and string.
    unsafe {
        ffi::SendMessageW(drop, WM_SETTEXT, 0, typed.as_ptr() as isize);
        ffi::SetForegroundWindow(window.handle);
        ffi::SetFocus(list);
        ffi::UpdateWindow(window.handle);
        ffi::SendMessageW(list, CB_SHOWDROPDOWN, 1, 0);
    }
    common::pump_ready(READY);
    0
}
