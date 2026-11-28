//! scrollshow.exe: a top-level window with both standard scroll bars (WS_HSCROLL, WS_VSCROLL) and
//! two ScrollBar controls in its client area, for test_scrollbars.py to look at.
//!
//! - The window's vertical bar: range 0-99, page 20, position 30 (a thumb a fifth of the track,
//!   below its top).
//! - Its horizontal bar: range 0-49, page 10, position 0, its left arrow disabled (EnableScrollBar
//!   ESB_DISABLE_LTUP).
//! - A horizontal ScrollBar control: range 0-10, position 5, no page (the thumb a square in the
//!   middle).
//! - A vertical ScrollBar control: range 0-4, page 0, both arrows disabled (ESB_DISABLE_BOTH).
//!
//! It prints `scrollshow: ready` once the window shows and its queue is idle; Alt+F4 closes the
//! window (the default procedure's SC_CLOSE), which ends it with 0.

#![no_std]
#![no_main]

use common::TopLevel;
use exe::winuser::{
    COLOR_WINDOW,
    ESB_DISABLE_BOTH,
    ESB_DISABLE_LTUP,
    SBS_HORZ,
    SBS_VERT,
    SB_CTL,
    SB_HORZ,
    SB_VERT,
    SIF_PAGE,
    SIF_POS,
    SIF_RANGE,
    WS_CAPTION,
    WS_HSCROLL,
    WS_SYSMENU,
    WS_VISIBLE,
    WS_VSCROLL,
};

exe::entry!(main);

/// The calls scrollshow makes, as user32 exports them: its own.
mod ffi {
    /// SCROLLINFO.
    #[repr(C)]
    pub struct ScrollInfo {
        pub size: u32,
        pub mask: u32,
        pub min: i32,
        pub max: i32,
        pub page: u32,
        pub pos: i32,
        pub track_pos: i32,
    }

    #[link(name = "user32", kind = "raw-dylib", import_name_type = "undecorated")]
    unsafe extern "system" {
        pub fn SetScrollInfo(window: usize, bar: i32, info: *const ScrollInfo, redraw: i32) -> i32;
        pub fn EnableScrollBar(window: usize, bar: u32, arrows: u32) -> i32;
    }
}

/// The window's styles: a caption with its system menu, a fixed frame, both scroll bars.
const WS_OVERLAPPED_FIXED: u32 = WS_CAPTION | WS_SYSMENU;
const STYLE: u32 = WS_OVERLAPPED_FIXED | WS_HSCROLL | WS_VSCROLL | WS_VISIBLE;

/// The line printed once the window shows and the queue is idle.
const READY: &str = "scrollshow: ready";
/// The exit code when the window cannot be made.
const NO_WINDOW: u32 = 1;

/// Sets `bar` of `window` to `min..=max`, `page` and `pos`, redrawn.
fn set(window: usize, bar: i32, min: i32, max: i32, page: u32, pos: i32) {
    let info = ffi::ScrollInfo {
        size: core::mem::size_of::<ffi::ScrollInfo>() as u32,
        mask: SIF_RANGE | SIF_PAGE | SIF_POS,
        min,
        max,
        page,
        pos,
        track_pos: 0,
    };
    // SAFETY: the program's window and its own SCROLLINFO.
    unsafe { ffi::SetScrollInfo(window, bar, &info, 1) };
}

fn main() -> u32 {
    let made = TopLevel {
        class: "ScrollShow",
        title: "Scroll bars",
        procedure: common::procedure,
        background: COLOR_WINDOW + 1,
        style: STYLE,
        client: (260, 200),
        menu: 0,
    }
    .create();
    let (window, across, down) = match made {
        None => (None, 0, 0),
        Some(window) => (
            Some(window),
            window.child("ScrollBar", 0, SBS_HORZ, "", (20, 30, 160, 17), 101),
            window.child("ScrollBar", 0, SBS_VERT, "", (200, 20, 17, 120), 102),
        ),
    };
    let Some(window) = window.filter(|_| across != 0 && down != 0) else {
        let _ = exe::stderr().print(format_args!("scrollshow: the windows cannot be made\r\n"));
        return NO_WINDOW;
    };
    set(window.handle, SB_VERT, 0, 99, 20, 30);
    set(window.handle, SB_HORZ, 0, 49, 10, 0);
    set(across, SB_CTL, 0, 10, 0, 5);
    set(down, SB_CTL, 0, 4, 0, 0);
    // SAFETY: the program's own windows.
    unsafe {
        ffi::EnableScrollBar(window.handle, SB_HORZ as u32, ESB_DISABLE_LTUP);
        ffi::EnableScrollBar(down, SB_CTL as u32, ESB_DISABLE_BOTH);
    }
    window.to_foreground();
    common::pump_ready(READY);
    0
}
