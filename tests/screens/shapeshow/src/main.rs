//! shapeshow.exe: a top-level window whose client area shows gdi32's pens, lines and shapes, for
//! test_shapeshow.py to look at. Its WM_PAINT draws, through BeginPaint's DC:
//!
//! - top row: a Rectangle (black pen, red brush), an Ellipse (black pen, blue brush) and a
//!   RoundRect (black pen, green brush);
//! - middle row: a pentagram Polygon under WINDING (black pen, yellow brush), a width-3 red
//!   Polyline, and the cosmetic styles PS_SOLID, PS_DASH, PS_DOT, PS_DASHDOT and PS_DASHDOTDOT as
//!   horizontal lines (TRANSPARENT, so their gaps show the window's white);
//! - bottom row: a width-9 corner under each ExtCreatePen join (miter, bevel, round), a width-5
//!   PS_INSIDEFRAME Ellipse with the null brush, and an R2_NOT Rectangle over a black bar.
//!
//! It prints `shapeshow: ready` once the window shows and its queue is idle; Alt+F4 closes the
//! window (the default procedure's SC_CLOSE), which ends it with 0.

#![no_std]
#![no_main]

use common::{with, TopLevel};
use exe::winuser::{COLOR_WINDOW, WM_PAINT, WS_CAPTION, WS_SYSMENU, WS_VISIBLE};

exe::entry!(main);

/// The calls shapeshow makes, as user32 and gdi32 export them: the shared ones, and its own.
mod ffi {
    pub use common::ffi::*;

    /// LOGBRUSH.
    #[repr(C)]
    pub struct LogBrush {
        pub style: u32,
        pub color: u32,
        pub hatch: usize,
    }

    #[link(name = "gdi32", kind = "raw-dylib", import_name_type = "undecorated")]
    unsafe extern "system" {
        pub fn ExtCreatePen(
            style: u32,
            width: u32,
            brush: *const LogBrush,
            count: u32,
            entries: *const u32,
        ) -> usize;
        pub fn SetROP2(dc: usize, mode: i32) -> i32;
        pub fn SetPolyFillMode(dc: usize, mode: i32) -> i32;
        pub fn Polyline(dc: usize, points: *const Point, count: i32) -> i32;
        pub fn Polygon(dc: usize, points: *const Point, count: i32) -> i32;
    }
}

/// The window's styles: a caption with its system menu, a fixed frame.
const STYLE: u32 = WS_CAPTION | WS_SYSMENU | WS_VISIBLE;

/// The line printed once the window shows and the queue is idle.
const READY: &str = "shapeshow: ready";
/// The exit code when the window cannot be made.
const NO_WINDOW: u32 = 1;

/// wingdi.h's values shapeshow uses.
const PS_SOLID: i32 = 0;
const PS_DASH: i32 = 1;
const PS_DOT: i32 = 2;
const PS_DASHDOT: i32 = 3;
const PS_DASHDOTDOT: i32 = 4;
const PS_INSIDEFRAME: i32 = 6;
const PS_GEOMETRIC: u32 = 0x0001_0000;
const PS_ENDCAP_FLAT: u32 = 0x0000_0200;
const PS_JOIN_ROUND: u32 = 0x0000_0000;
const PS_JOIN_BEVEL: u32 = 0x0000_1000;
const PS_JOIN_MITER: u32 = 0x0000_2000;
const NULL_BRUSH: i32 = 5;
const BLACK_BRUSH: i32 = 4;
const TRANSPARENT: i32 = 1;
const WINDING: i32 = 2;
const R2_NOT: i32 = 6;
const R2_COPYPEN: i32 = 13;

const BLACK: u32 = 0x0000_0000;
const RED: u32 = 0x0000_00FF;
const GREEN: u32 = 0x0000_FF00;
const BLUE: u32 = 0x00FF_0000;
const YELLOW: u32 = 0x0000_FFFF;

fn point(x: i32, y: i32) -> ffi::Point {
    ffi::Point { x, y }
}

/// The sheet (see the module notes), drawn into `dc`.
fn draw(dc: usize) {
    // SAFETY: BeginPaint's DC, the program's own objects and points.
    unsafe {
        let black = ffi::CreatePen(PS_SOLID, 1, BLACK);
        let old_pen = ffi::SelectObject(dc, black);
        // The top row.
        with(dc, ffi::CreateSolidBrush(RED), || {
            ffi::Rectangle(dc, 10, 10, 80, 60);
        });
        with(dc, ffi::CreateSolidBrush(BLUE), || {
            ffi::Ellipse(dc, 95, 10, 175, 60);
        });
        with(dc, ffi::CreateSolidBrush(GREEN), || {
            ffi::RoundRect(dc, 190, 10, 250, 60, 20, 16);
        });
        // The middle row.
        let star = [
            point(40, 70),
            point(60, 130),
            point(10, 92),
            point(70, 92),
            point(20, 130),
        ];
        ffi::SetPolyFillMode(dc, WINDING);
        with(dc, ffi::CreateSolidBrush(YELLOW), || {
            ffi::Polygon(dc, star.as_ptr(), star.len() as i32);
        });
        let zig = [
            point(90, 125),
            point(105, 75),
            point(120, 125),
            point(135, 75),
        ];
        with(dc, ffi::CreatePen(PS_SOLID, 3, RED), || {
            ffi::Polyline(dc, zig.as_ptr(), zig.len() as i32);
        });
        ffi::SetBkMode(dc, TRANSPARENT);
        for (index, style) in [PS_SOLID, PS_DASH, PS_DOT, PS_DASHDOT, PS_DASHDOTDOT]
            .into_iter()
            .enumerate()
        {
            let y = 76 + 12 * index as i32;
            with(dc, ffi::CreatePen(style, 1, BLACK), || {
                ffi::MoveToEx(dc, 150, y, core::ptr::null_mut());
                ffi::LineTo(dc, 250, y);
            });
        }
        // The bottom row.
        let brush = ffi::LogBrush {
            style: 0,
            color: BLUE,
            hatch: 0,
        };
        for (index, join) in [PS_JOIN_MITER, PS_JOIN_BEVEL, PS_JOIN_ROUND]
            .into_iter()
            .enumerate()
        {
            let x = 15 + 45 * index as i32;
            let corner = [point(x, 190), point(x + 15, 150), point(x + 30, 190)];
            let style = PS_GEOMETRIC | PS_ENDCAP_FLAT | join;
            with(
                dc,
                ffi::ExtCreatePen(style, 9, &brush, 0, core::ptr::null()),
                || {
                    ffi::Polyline(dc, corner.as_ptr(), corner.len() as i32);
                },
            );
        }
        let hollow = ffi::SelectObject(dc, ffi::GetStockObject(NULL_BRUSH));
        with(dc, ffi::CreatePen(PS_INSIDEFRAME, 5, GREEN), || {
            ffi::Ellipse(dc, 150, 145, 200, 195);
        });
        ffi::SelectObject(dc, ffi::GetStockObject(BLACK_BRUSH));
        ffi::Rectangle(dc, 210, 160, 250, 170);
        ffi::SetROP2(dc, R2_NOT);
        ffi::SelectObject(dc, ffi::GetStockObject(NULL_BRUSH));
        ffi::Rectangle(dc, 215, 145, 245, 190);
        ffi::SetROP2(dc, R2_COPYPEN);
        ffi::SelectObject(dc, hollow);
        ffi::SelectObject(dc, old_pen);
        ffi::DeleteObject(black);
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
        class: "ShapeShow",
        title: "Shapes",
        procedure,
        background: COLOR_WINDOW + 1,
        style: STYLE,
        client: (260, 200),
        menu: 0,
    }
    .create();
    let Some(window) = made else {
        let _ = exe::stderr().print(format_args!("shapeshow: the window cannot be made\r\n"));
        return NO_WINDOW;
    };
    window.to_foreground();
    common::pump_ready(READY);
    0
}
