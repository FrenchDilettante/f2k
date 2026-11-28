//! listboxshow.exe: a top-level window with three ListBox controls in its client area, for
//! test_listboxes.py to look at.
//!
//! - A list box with a border and WS_VSCROLL: fifteen items (more than show, so its scroll bar
//!   shows), the third selected, the focus on it (its focus rectangle drawn).
//! - An LBS_MULTIPLESEL list box with a border: five items, the first and the fourth selected.
//! - A disabled list box with a border: two items, their text greyed.
//!
//! The window does not clip its children (no WS_CLIPCHILDREN), so its painting covers the list
//! boxes; each paints after it, its frame (its client edge, its scroll bar) included.
//!
//! It prints `listboxshow: ready` once the window shows and its queue is idle; Alt+F4 closes the
//! window (the default procedure's SC_CLOSE), which ends it with 0.

#![no_std]
#![no_main]

use common::{TopLevel, Wide, Window};
use exe::winuser::{
    COLOR_3DFACE,
    LBS_MULTIPLESEL,
    LBS_NOINTEGRALHEIGHT,
    LBS_NOTIFY,
    LB_ADDSTRING,
    LB_SETCURSEL,
    LB_SETSEL,
    WS_BORDER,
    WS_CAPTION,
    WS_DISABLED,
    WS_SYSMENU,
    WS_VISIBLE,
    WS_VSCROLL,
};

exe::entry!(main);

/// The calls listboxshow makes: the shared ones (common::ffi).
use common::ffi;

/// The window's styles: a caption with its system menu, a fixed frame.
const STYLE: u32 = WS_CAPTION | WS_SYSMENU | WS_VISIBLE;

/// The line printed once the window shows and the queue is idle.
const READY: &str = "listboxshow: ready";
/// The exit code when a window cannot be made.
const NO_WINDOW: u32 = 1;

/// The first list box's items.
const ITEMS: [&str; 15] = [
    "Alpha", "Bravo", "Charlie", "Delta", "Echo", "Foxtrot", "Golf", "Hotel", "India", "Juliet",
    "Kilo", "Lima", "Mike", "November", "Oscar",
];

/// A list box child of `window` at (`x`, `y`), `cx` by `cy`, with `style`, its id `id`, holding
/// `items`; 0 when it cannot be made.
fn list_box(
    window: &Window,
    style: u32,
    place: (i32, i32, i32, i32),
    id: usize,
    items: &[&str],
) -> usize {
    let list = window.child(
        "ListBox",
        0,
        WS_BORDER | LBS_NOINTEGRALHEIGHT | style,
        "",
        place,
        id,
    );
    if list != 0 {
        for item in items {
            let text = Wide::of(item);
            // SAFETY: the program's own window and string, which lives for the call.
            unsafe { ffi::SendMessageW(list, LB_ADDSTRING, 0, text.as_ptr() as isize) };
        }
    }
    list
}

fn main() -> u32 {
    let made = TopLevel {
        class: "ListBoxShow",
        title: "List boxes",
        procedure: common::procedure,
        background: COLOR_3DFACE + 1,
        style: STYLE,
        client: (300, 200),
        menu: 0,
    }
    .create();
    let (window, single, multiple, disabled) = match made {
        None => (None, 0, 0, 0),
        Some(window) => (
            Some(window),
            list_box(
                &window,
                WS_VSCROLL | LBS_NOTIFY,
                (10, 10, 130, 180),
                101,
                &ITEMS,
            ),
            list_box(
                &window,
                LBS_MULTIPLESEL,
                (160, 10, 130, 100),
                102,
                &ITEMS[..5],
            ),
            list_box(
                &window,
                WS_DISABLED,
                (160, 130, 130, 60),
                103,
                &["Disabled", "Greyed"],
            ),
        ),
    };
    let Some(window) = window.filter(|_| single != 0 && multiple != 0 && disabled != 0) else {
        let _ = exe::stderr().print(format_args!("listboxshow: the windows cannot be made\r\n"));
        return NO_WINDOW;
    };
    // SAFETY: the program's own windows.
    unsafe {
        ffi::SendMessageW(single, LB_SETCURSEL, 2, 0);
        ffi::SendMessageW(multiple, LB_SETSEL, 1, 0);
        ffi::SendMessageW(multiple, LB_SETSEL, 1, 3);
        ffi::SetForegroundWindow(window.handle);
        ffi::SetFocus(single);
    }
    common::pump_ready(READY);
    0
}
