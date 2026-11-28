//! clipshow.exe: a top-level window that paints its whole client area itself, over the bordered
//! controls in it, for test_childpaint.py to look at.
//!
//! The window's class has no background brush; its WM_PAINT fills the whole client area (not just
//! rcPaint) in teal. It has no WS_CLIPCHILDREN, so its DC is not cut by its children and the fill
//! covers them; Windows 2000 paints each child again after it, its frame included, because an
//! invalidation of the parent reaches its children (their frames, their backgrounds, their client
//! areas). The children:
//!
//! - a Static with WS_BORDER (its one-pixel black frame);
//! - an Edit with WS_EX_CLIENTEDGE (its two-pixel sunken edge);
//! - a ListBox with WS_BORDER and WS_VSCROLL, more items than show (its frame and its scroll bar).
//!
//! The window is painted once as it shows; once its queue is idle the program invalidates its whole
//! client area again (InvalidateRect, erasing) and, once the queue is idle once more, prints
//! `clipshow: ready`. Alt+F4 closes the window (the default procedure's SC_CLOSE), which ends it
//! with 0.

#![no_std]
#![no_main]

use core::sync::atomic::{AtomicUsize, Ordering};

use common::{TopLevel, Wide};
use exe::winuser::{
    LBS_NOINTEGRALHEIGHT,
    LB_ADDSTRING,
    SS_LEFT,
    WM_PAINT,
    WS_BORDER,
    WS_CAPTION,
    WS_SYSMENU,
    WS_VISIBLE,
    WS_VSCROLL,
};

exe::entry!(main);

/// The calls clipshow makes, as user32 and gdi32 export them: the shared ones, and its own.
mod ffi {
    pub use common::ffi::*;

    #[link(name = "user32", kind = "raw-dylib", import_name_type = "undecorated")]
    unsafe extern "system" {
        pub fn GetClientRect(window: usize, rect: *mut Rect) -> i32;
        pub fn FillRect(dc: usize, rect: *const Rect, brush: usize) -> i32;
        pub fn InvalidateRect(window: usize, rect: *const Rect, erase: i32) -> i32;
    }
}

/// The window's styles: a caption with its system menu, a fixed frame; no WS_CLIPCHILDREN.
const STYLE: u32 = WS_CAPTION | WS_SYSMENU | WS_VISIBLE;
/// WS_EX_CLIENTEDGE: the Edit's sunken edge.
const WS_EX_CLIENTEDGE: u32 = 0x0000_0200;
/// ES_AUTOHSCROLL.
const ES_AUTOHSCROLL: u32 = 0x0080;
/// The window's fill, teal (a COLORREF: 0x00BBGGRR).
const TEAL: u32 = 0x0080_8000;

/// The teal brush, made once before the window.
static BRUSH: AtomicUsize = AtomicUsize::new(0);

/// The line printed once the window has painted twice and the queue is idle.
const READY: &str = "clipshow: ready";
/// The exit code when a window cannot be made.
const NO_WINDOW: u32 = 1;

/// The list box's items: more than its 100 pixels show.
const ITEMS: [&str; 10] = [
    "One", "Two", "Three", "Four", "Five", "Six", "Seven", "Eight", "Nine", "Ten",
];

/// The window's procedure: WM_PAINT fills the whole client area; the rest is the shared one's.
extern "system" fn procedure(window: usize, message: u32, wparam: usize, lparam: isize) -> isize {
    if message != WM_PAINT {
        return common::procedure(window, message, wparam, lparam);
    }
    common::paint(window, |dc| {
        let mut client = ffi::Rect::default();
        // SAFETY: the program's own window and RECT, BeginPaint's DC.
        unsafe {
            ffi::GetClientRect(window, &mut client);
            ffi::FillRect(dc, &client, BRUSH.load(Ordering::Relaxed));
        }
    });
    0
}

fn main() -> u32 {
    // SAFETY: no pointers.
    BRUSH.store(unsafe { ffi::CreateSolidBrush(TEAL) }, Ordering::Relaxed);
    let made = TopLevel {
        class: "ClipShow",
        title: "Child frames",
        procedure,
        background: 0,
        style: STYLE,
        client: (300, 200),
        menu: 0,
    }
    .create();
    let Some(window) = made else {
        let _ = exe::stderr().print(format_args!("clipshow: the window cannot be made\r\n"));
        return NO_WINDOW;
    };
    let made = [
        window.child(
            "Static",
            0,
            SS_LEFT | WS_BORDER,
            "Bordered",
            (10, 10, 120, 40),
            101,
        ),
        window.child(
            "Edit",
            WS_EX_CLIENTEDGE,
            ES_AUTOHSCROLL,
            "Edit",
            (10, 70, 120, 24),
            102,
        ),
        window.child(
            "ListBox",
            0,
            WS_BORDER | WS_VSCROLL | LBS_NOINTEGRALHEIGHT,
            "",
            (150, 10, 130, 100),
            103,
        ),
    ];
    if made.contains(&0) {
        let _ = exe::stderr().print(format_args!("clipshow: the controls cannot be made\r\n"));
        return NO_WINDOW;
    }
    // SAFETY: the program's own windows and strings.
    unsafe {
        for item in ITEMS {
            let text = Wide::of(item);
            ffi::SendMessageW(made[2], LB_ADDSTRING, 0, text.as_ptr() as isize);
        }
    }
    window.to_foreground();
    // 0: the first painting; 1: the window invalidated again; 2: ready printed.
    let mut stage = 0;
    common::pump(|| match stage {
        0 => {
            stage = 1;
            // SAFETY: the program's own window.
            unsafe { ffi::InvalidateRect(window.handle, core::ptr::null(), 1) };
            true
        }
        1 => {
            stage = 2;
            let _ = exe::stdout().print(format_args!("{READY}\r\n"));
            false
        }
        _ => false,
    });
    0
}
