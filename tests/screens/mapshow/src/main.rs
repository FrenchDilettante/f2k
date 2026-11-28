//! mapshow.exe: a top-level window whose client area is drawn through gdi32's mapping modes, for
//! test_mapshow.py to look at. Its WM_PAINT draws, through BeginPaint's DC, each part
//! between SaveDC and RestoreDC:
//!
//! - top left: a picture in a 10 by 10 logical space (a yellow square, a red Rectangle, a blue
//!   Ellipse, a green RoundRect, a black PatBlt mark at the logical origin, a diagonal line),
//!   MM_ANISOTROPIC at 8 pixels a unit, clipped by IntersectClipRect to its square;
//! - top middle: the same picture flipped, y up (a negative viewport extent);
//! - top right: an 8 by 8 bitmap (a black top row and left column, a red pixel) blitted 1:1 by
//!   BitBlt through a 4 times mapping, upright and flipped;
//! - bottom left: MM_ISOTROPIC, a 100 by 100 window asked onto a 240 by -90 viewport, the circle
//!   Ellipse(0, 0, 100, 100) staying round (the viewport shrunk to 90 by -90);
//! - bottom right, after the last RestoreDC: a green Rectangle in MM_TEXT's client coordinates.
//!
//! It prints `mapshow: ready` once the window shows and its queue is idle; Alt+F4 closes the
//! window (the default procedure's SC_CLOSE), which ends it with 0.

#![no_std]
#![no_main]

use common::{with, TopLevel};
use exe::winuser::{COLOR_WINDOW, WM_PAINT, WS_CAPTION, WS_SYSMENU, WS_VISIBLE};

exe::entry!(main);

/// The calls mapshow makes, as user32 and gdi32 export them: the shared ones, and its own.
mod ffi {
    pub use common::ffi::*;

    #[link(name = "gdi32", kind = "raw-dylib", import_name_type = "undecorated")]
    unsafe extern "system" {
        pub fn CreateCompatibleDC(dc: usize) -> usize;
        pub fn CreateCompatibleBitmap(dc: usize, width: i32, height: i32) -> usize;
        pub fn DeleteDC(dc: usize) -> i32;
        pub fn PatBlt(dc: usize, x: i32, y: i32, width: i32, height: i32, rop: u32) -> i32;
        pub fn BitBlt(
            dc: usize,
            x: i32,
            y: i32,
            width: i32,
            height: i32,
            source: usize,
            source_x: i32,
            source_y: i32,
            rop: u32,
        ) -> i32;
        pub fn IntersectClipRect(dc: usize, left: i32, top: i32, right: i32, bottom: i32) -> i32;
    }
}

/// The window's styles: a caption with its system menu, a fixed frame.
const STYLE: u32 = WS_CAPTION | WS_SYSMENU | WS_VISIBLE;

/// The line printed once the window shows and the queue is idle.
const READY: &str = "mapshow: ready";
/// The exit code when the window cannot be made.
const NO_WINDOW: u32 = 1;

/// wingdi.h's values mapshow uses.
const PS_SOLID: i32 = 0;
const BLACK_PEN: i32 = 7;
const MM_ISOTROPIC: i32 = 7;
const MM_ANISOTROPIC: i32 = 8;
const BLACKNESS: u32 = 0x0000_0042;
const WHITENESS: u32 = 0x00FF_0062;
const SRCCOPY: u32 = 0x00CC_0020;

const BLACK: u32 = 0x0000_0000;
const RED: u32 = 0x0000_00FF;
const GREEN: u32 = 0x0000_FF00;
const BLUE: u32 = 0x00FF_0000;
const YELLOW: u32 = 0x0000_FFFF;

/// `f` drawing into `dc` between SaveDC and RestoreDC(-1), MM_ANISOTROPIC mapping a window of
/// `window` extents onto a viewport of `viewport` extents at `origin` (client coordinates).
///
/// # Safety
///
/// `dc` a DC of the program's.
unsafe fn mapped(
    dc: usize,
    window: (i32, i32),
    viewport: (i32, i32),
    origin: (i32, i32),
    f: impl FnOnce(),
) {
    // SAFETY: the caller's DC.
    unsafe {
        ffi::SaveDC(dc);
        ffi::SetMapMode(dc, MM_ANISOTROPIC);
        ffi::SetWindowExtEx(dc, window.0, window.1, core::ptr::null_mut());
        ffi::SetViewportExtEx(dc, viewport.0, viewport.1, core::ptr::null_mut());
        ffi::SetViewportOrgEx(dc, origin.0, origin.1, core::ptr::null_mut());
        f();
        ffi::RestoreDC(dc, -1);
    }
}

/// The picture of the top left and top middle, in a 10 by 10 logical space, clipped to it.
///
/// # Safety
///
/// `dc` a DC of the program's, its mapping set.
unsafe fn picture(dc: usize) {
    // SAFETY: the caller's DC, the program's own objects.
    unsafe {
        ffi::IntersectClipRect(dc, 0, 0, 10, 10);
        with(dc, ffi::CreateSolidBrush(YELLOW), || {
            ffi::Rectangle(dc, 0, 0, 10, 10);
        });
        with(dc, ffi::CreateSolidBrush(RED), || {
            ffi::Rectangle(dc, 1, 1, 5, 4);
        });
        with(dc, ffi::CreateSolidBrush(BLUE), || {
            ffi::Ellipse(dc, 5, 1, 9, 5);
        });
        with(dc, ffi::CreateSolidBrush(GREEN), || {
            ffi::RoundRect(dc, 1, 5, 9, 9, 3, 3);
        });
        ffi::PatBlt(dc, 0, 0, 2, 1, BLACKNESS);
        // A line past the square's far corner: the clipping stops it there.
        ffi::MoveToEx(dc, 5, 5, core::ptr::null_mut());
        ffi::LineTo(dc, 14, 14);
    }
}

/// The 8 by 8 bitmap the top right blits: white, a black top row and left column, a red pixel at
/// (5, 5); a memory DC holding it.
///
/// # Safety
///
/// `dc` a DC of the program's.
unsafe fn tile(dc: usize) -> (usize, usize) {
    // SAFETY: the caller's DC; the program's own memory DC and bitmap.
    unsafe {
        let memory = ffi::CreateCompatibleDC(dc);
        let bitmap = ffi::CreateCompatibleBitmap(dc, 8, 8);
        ffi::SelectObject(memory, bitmap);
        ffi::PatBlt(memory, 0, 0, 8, 8, WHITENESS);
        ffi::PatBlt(memory, 0, 0, 8, 1, BLACKNESS);
        ffi::PatBlt(memory, 0, 0, 1, 8, BLACKNESS);
        ffi::SetPixel(memory, 5, 5, RED);
        (memory, bitmap)
    }
}

/// The sheet (see the module notes), drawn into `dc`.
fn draw(dc: usize) {
    // SAFETY: BeginPaint's DC, the program's own objects.
    unsafe {
        ffi::SaveDC(dc);
        ffi::SelectObject(dc, ffi::CreatePen(PS_SOLID, 1, BLACK));
        mapped(dc, (10, 10), (80, 80), (10, 10), || picture(dc));
        mapped(dc, (10, 10), (80, -80), (100, 90), || picture(dc));
        let (memory, bitmap) = tile(dc);
        mapped(dc, (1, 1), (4, 4), (190, 10), || {
            ffi::BitBlt(dc, 0, 0, 8, 8, memory, 0, 0, SRCCOPY);
        });
        mapped(dc, (1, 1), (4, -4), (190, 90), || {
            ffi::BitBlt(dc, 0, 0, 8, 8, memory, 0, 0, SRCCOPY);
        });
        ffi::DeleteDC(memory);
        ffi::DeleteObject(bitmap);
        ffi::SaveDC(dc);
        ffi::SetMapMode(dc, MM_ISOTROPIC);
        ffi::SetWindowExtEx(dc, 100, 100, core::ptr::null_mut());
        ffi::SetViewportExtEx(dc, 240, -90, core::ptr::null_mut());
        ffi::SetViewportOrgEx(dc, 10, 190, core::ptr::null_mut());
        with(dc, ffi::CreateSolidBrush(BLUE), || {
            ffi::Ellipse(dc, 0, 0, 100, 100);
        });
        ffi::RestoreDC(dc, -1);
        with(dc, ffi::CreateSolidBrush(GREEN), || {
            ffi::Rectangle(dc, 130, 110, 250, 190);
        });
        // The pen made above goes with the DC's state: the first SaveDC's put back, then it is
        // deleted.
        let pen = ffi::SelectObject(dc, ffi::GetStockObject(BLACK_PEN));
        ffi::RestoreDC(dc, 1);
        ffi::DeleteObject(pen);
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
        class: "MapShow",
        title: "Mapping",
        procedure,
        background: COLOR_WINDOW + 1,
        style: STYLE,
        client: (260, 200),
        menu: 0,
    }
    .create();
    let Some(window) = made else {
        let _ = exe::stderr().print(format_args!("mapshow: the window cannot be made\r\n"));
        return NO_WINDOW;
    };
    window.to_foreground();
    common::pump_ready(READY);
    0
}
