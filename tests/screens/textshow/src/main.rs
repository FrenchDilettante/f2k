//! textshow.exe: a top-level window whose client area shows gdi32's text layout, for
//! test_textshow.py to look at. Its WM_PAINT draws, through BeginPaint's DC in the
//! stock System font, black text on yellow or cyan opaque cells:
//!
//! - top row: "Ab" at three reference points, each marked by a red pixel drawn after it: TA_LEFT |
//!   TA_TOP at (10, 8), TA_CENTER | TA_BASELINE at (80, 21), TA_RIGHT | TA_BOTTOM at (150, 24),
//!   their cells all in rows 8 to 23;
//! - TA_UPDATECP from MoveToEx(10, 32): "Ab" yellow, "Hello" cyan, "Ab" yellow, side by side;
//! - SetTextCharacterExtra(4): "Hello" at (10, 56), cyan, 54 pixels wide;
//! - SetTextJustification(40, 2): "a b c" at (10, 80), yellow, 71 pixels wide, the spaces 20 pixels
//!   wider each;
//! - PolyTextOutW: "Ab" at (10, 104) and "abc" at (130, 104) with ETO_OPAQUE over (120, 104) to
//!   (250, 124);
//! - MM_ANISOTROPIC at 2 pixels a unit from (10, 140): "Ab" under TA_RIGHT at logical (20, 0), its
//!   cells ending at (50, 140) (the font not scaled).
//!
//! It prints `textshow: ready` once the window shows and its queue is idle; Alt+F4 closes the
//! window (the default procedure's SC_CLOSE), which ends it with 0.

#![no_std]
#![no_main]

use common::{TopLevel, Wide};
use exe::winuser::{COLOR_WINDOW, WM_PAINT, WS_CAPTION, WS_SYSMENU, WS_VISIBLE};

exe::entry!(main);

/// The calls textshow makes, as user32 and gdi32 export them: the shared ones, and its own.
mod ffi {
    pub use common::ffi::*;

    /// POLYTEXTW.
    #[repr(C)]
    pub struct PolyTextW {
        pub x: i32,
        pub y: i32,
        pub count: u32,
        pub string: *const u16,
        pub options: u32,
        pub rect: Rect,
        pub dx: *const i32,
    }

    #[link(name = "gdi32", kind = "raw-dylib", import_name_type = "undecorated")]
    unsafe extern "system" {
        pub fn SetBkColor(dc: usize, color: u32) -> u32;
        pub fn SetTextColor(dc: usize, color: u32) -> u32;
        pub fn SetTextAlign(dc: usize, align: u32) -> u32;
        pub fn SetTextCharacterExtra(dc: usize, extra: i32) -> i32;
        pub fn SetTextJustification(dc: usize, extra: i32, breaks: i32) -> i32;
        pub fn TextOutW(dc: usize, x: i32, y: i32, string: *const u16, count: i32) -> i32;
        pub fn PolyTextOutW(dc: usize, texts: *const PolyTextW, count: i32) -> i32;
    }
}

/// The window's styles: a caption with its system menu, a fixed frame.
const STYLE: u32 = WS_CAPTION | WS_SYSMENU | WS_VISIBLE;

/// The line printed once the window shows and the queue is idle.
const READY: &str = "textshow: ready";
/// The exit code when the window cannot be made.
const NO_WINDOW: u32 = 1;

/// wingdi.h's values textshow uses.
const OPAQUE: i32 = 2;
const MM_ANISOTROPIC: i32 = 8;
const ETO_OPAQUE: u32 = 2;
const TA_UPDATECP: u32 = 1;
const TA_LEFT: u32 = 0;
const TA_RIGHT: u32 = 2;
const TA_CENTER: u32 = 6;
const TA_TOP: u32 = 0;
const TA_BOTTOM: u32 = 8;
const TA_BASELINE: u32 = 24;

const BLACK: u32 = 0x0000_0000;
const RED: u32 = 0x0000_00FF;
const YELLOW: u32 = 0x0000_FFFF;
const CYAN: u32 = 0x00FF_FF00;

/// `text` drawn by TextOutW at (`x`, `y`) on `background` cells.
///
/// # Safety
///
/// `dc` a DC of the program's.
unsafe fn text_out(dc: usize, x: i32, y: i32, text: &str, background: u32) {
    let text = Wide::of(text);
    // SAFETY: the caller's DC; the program's own string.
    unsafe {
        ffi::SetBkColor(dc, background);
        ffi::TextOutW(dc, x, y, text.as_ptr(), text.len());
    }
}

/// The sheet (see the module notes), drawn into `dc`.
fn draw(dc: usize) {
    // SAFETY: BeginPaint's DC, the program's own strings and structures.
    unsafe {
        ffi::SaveDC(dc);
        ffi::SetTextColor(dc, BLACK);
        ffi::SetBkMode(dc, OPAQUE);
        for (align, x, y) in [
            (TA_LEFT | TA_TOP, 10, 8),
            (TA_CENTER | TA_BASELINE, 80, 21),
            (TA_RIGHT | TA_BOTTOM, 150, 24),
        ] {
            ffi::SetTextAlign(dc, align);
            text_out(dc, x, y, "Ab", YELLOW);
            ffi::SetPixel(dc, x, y, RED);
        }
        ffi::SetTextAlign(dc, TA_LEFT | TA_TOP | TA_UPDATECP);
        ffi::MoveToEx(dc, 10, 32, core::ptr::null_mut());
        text_out(dc, 0, 0, "Ab", YELLOW);
        text_out(dc, 0, 0, "Hello", CYAN);
        text_out(dc, 0, 0, "Ab", YELLOW);
        ffi::SetTextAlign(dc, TA_LEFT | TA_TOP);
        ffi::SetTextCharacterExtra(dc, 4);
        text_out(dc, 10, 56, "Hello", CYAN);
        ffi::SetTextCharacterExtra(dc, 0);
        ffi::SetTextJustification(dc, 40, 2);
        text_out(dc, 10, 80, "a b c", YELLOW);
        ffi::SetTextJustification(dc, 0, 0);
        let (first, second) = (Wide::of("Ab"), Wide::of("abc"));
        let none = ffi::Rect::default();
        let texts = [
            ffi::PolyTextW {
                x: 10,
                y: 104,
                count: 2,
                string: first.as_ptr(),
                options: 0,
                rect: none,
                dx: core::ptr::null(),
            },
            ffi::PolyTextW {
                x: 130,
                y: 104,
                count: 3,
                string: second.as_ptr(),
                options: ETO_OPAQUE,
                rect: ffi::Rect {
                    left: 120,
                    top: 104,
                    right: 250,
                    bottom: 124,
                },
                dx: core::ptr::null(),
            },
        ];
        ffi::SetBkColor(dc, YELLOW);
        ffi::PolyTextOutW(dc, texts.as_ptr(), 2);
        ffi::SaveDC(dc);
        ffi::SetMapMode(dc, MM_ANISOTROPIC);
        ffi::SetWindowExtEx(dc, 1, 1, core::ptr::null_mut());
        ffi::SetViewportExtEx(dc, 2, 2, core::ptr::null_mut());
        ffi::SetViewportOrgEx(dc, 10, 140, core::ptr::null_mut());
        ffi::SetTextAlign(dc, TA_RIGHT | TA_TOP);
        text_out(dc, 20, 0, "Ab", YELLOW);
        ffi::RestoreDC(dc, -1);
        ffi::RestoreDC(dc, -1);
    }
}

/// The window's procedure: WM_PAINT draws the sheet; the rest is the shared one's.
extern "system" fn procedure(window: usize, message: u32, wparam: usize, lparam: isize) -> isize {
    if message != WM_PAINT {
        return common::procedure(window, message, wparam, lparam);
    }
    common::paint(window, draw);
    0
}

fn main() -> u32 {
    let made = TopLevel {
        class: "TextShow",
        title: "Text Layout",
        procedure,
        background: COLOR_WINDOW + 1,
        style: STYLE,
        client: (260, 200),
        menu: 0,
    }
    .create();
    let Some(window) = made else {
        let _ = exe::stderr().print(format_args!("textshow: the window cannot be made\r\n"));
        return NO_WINDOW;
    };
    window.to_foreground();
    common::pump_ready(READY);
    0
}
