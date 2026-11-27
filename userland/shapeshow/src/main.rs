//! shapeshow.exe: a top-level window whose client area shows gdi32's pens, lines and shapes, for
//! tests/core/test_shapeshow.py to look at. Its WM_PAINT draws, through BeginPaint's DC:
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

use exe::winuser::{
    COLOR_WINDOW,
    PM_NOREMOVE,
    SM_CXSCREEN,
    SM_CYSCREEN,
    WM_DESTROY,
    WM_PAINT,
    WS_CAPTION,
    WS_SYSMENU,
    WS_VISIBLE,
};

exe::entry!(main);

/// The calls shapeshow makes, as user32, gdi32 and kernel32 export them.
mod ffi {
    /// MSG (28 bytes).
    #[repr(C)]
    #[derive(Default)]
    pub struct Msg {
        pub window: usize,
        pub message: u32,
        pub wparam: usize,
        pub lparam: isize,
        pub time: u32,
        pub x: i32,
        pub y: i32,
    }

    /// RECT.
    #[repr(C)]
    #[derive(Default)]
    pub struct Rect {
        pub left: i32,
        pub top: i32,
        pub right: i32,
        pub bottom: i32,
    }

    /// POINT.
    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    pub struct Point {
        pub x: i32,
        pub y: i32,
    }

    /// LOGBRUSH.
    #[repr(C)]
    pub struct LogBrush {
        pub style: u32,
        pub color: u32,
        pub hatch: usize,
    }

    /// PAINTSTRUCT (64 bytes).
    #[repr(C)]
    #[derive(Default)]
    pub struct PaintStruct {
        pub dc: usize,
        pub erase: i32,
        pub paint: Rect,
        pub restore: i32,
        pub inc_update: i32,
        pub reserved: [u8; 32],
    }

    /// WNDCLASSW.
    #[repr(C)]
    pub struct WndClassW {
        pub style: u32,
        pub proc: extern "system" fn(usize, u32, usize, isize) -> isize,
        pub class_extra: i32,
        pub window_extra: i32,
        pub instance: usize,
        pub icon: usize,
        pub cursor: usize,
        pub background: usize,
        pub menu_name: *const u16,
        pub class_name: *const u16,
    }

    #[link(
        name = "kernel32",
        kind = "raw-dylib",
        import_name_type = "undecorated"
    )]
    unsafe extern "system" {
        pub fn GetModuleHandleA(name: *const u8) -> usize;
    }

    #[link(name = "user32", kind = "raw-dylib", import_name_type = "undecorated")]
    unsafe extern "system" {
        pub fn RegisterClassW(class: *const WndClassW) -> u16;
        pub fn CreateWindowExW(
            ex_style: u32,
            class: *const u16,
            name: *const u16,
            style: u32,
            x: i32,
            y: i32,
            cx: i32,
            cy: i32,
            parent: usize,
            menu: usize,
            instance: usize,
            param: usize,
        ) -> usize;
        pub fn DefWindowProcW(window: usize, message: u32, wparam: usize, lparam: isize) -> isize;
        pub fn AdjustWindowRectEx(rect: *mut Rect, style: u32, menu: i32, ex_style: u32) -> i32;
        pub fn GetSystemMetrics(index: i32) -> i32;
        pub fn GetMessageW(msg: *mut Msg, window: usize, first: u32, last: u32) -> i32;
        pub fn PeekMessageW(msg: *mut Msg, window: usize, first: u32, last: u32, flags: u32)
            -> i32;
        pub fn TranslateMessage(msg: *const Msg) -> i32;
        pub fn DispatchMessageW(msg: *const Msg) -> isize;
        pub fn SetForegroundWindow(window: usize) -> i32;
        pub fn PostQuitMessage(code: i32);
        pub fn BeginPaint(window: usize, paint: *mut PaintStruct) -> usize;
        pub fn EndPaint(window: usize, paint: *const PaintStruct) -> i32;
    }

    #[link(name = "gdi32", kind = "raw-dylib", import_name_type = "undecorated")]
    unsafe extern "system" {
        pub fn CreatePen(style: i32, width: i32, color: u32) -> usize;
        pub fn ExtCreatePen(
            style: u32,
            width: u32,
            brush: *const LogBrush,
            count: u32,
            entries: *const u32,
        ) -> usize;
        pub fn CreateSolidBrush(color: u32) -> usize;
        pub fn GetStockObject(index: i32) -> usize;
        pub fn SelectObject(dc: usize, object: usize) -> usize;
        pub fn DeleteObject(object: usize) -> i32;
        pub fn SetBkMode(dc: usize, mode: i32) -> i32;
        pub fn SetROP2(dc: usize, mode: i32) -> i32;
        pub fn SetPolyFillMode(dc: usize, mode: i32) -> i32;
        pub fn MoveToEx(dc: usize, x: i32, y: i32, previous: *mut Point) -> i32;
        pub fn LineTo(dc: usize, x: i32, y: i32) -> i32;
        pub fn Polyline(dc: usize, points: *const Point, count: i32) -> i32;
        pub fn Polygon(dc: usize, points: *const Point, count: i32) -> i32;
        pub fn Rectangle(dc: usize, left: i32, top: i32, right: i32, bottom: i32) -> i32;
        pub fn Ellipse(dc: usize, left: i32, top: i32, right: i32, bottom: i32) -> i32;
        pub fn RoundRect(
            dc: usize,
            left: i32,
            top: i32,
            right: i32,
            bottom: i32,
            width: i32,
            height: i32,
        ) -> i32;
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

/// A string's UTF-16 units, NUL-terminated, in a buffer of the program's own.
struct Wide([u16; 32]);

impl Wide {
    fn of(text: &str) -> Wide {
        let mut units = [0u16; 32];
        for (unit, value) in units.iter_mut().take(31).zip(text.encode_utf16()) {
            *unit = value;
        }
        Wide(units)
    }

    fn as_ptr(&self) -> *const u16 {
        self.0.as_ptr()
    }
}

/// `object` selected into `dc` while `f` draws, then the previous one back and `object` deleted.
///
/// # Safety
///
/// `dc` a DC of the program's; `object` a pen or brush it made (or a stock object).
unsafe fn with(dc: usize, object: usize, f: impl FnOnce()) {
    // SAFETY: the caller's DC and object.
    unsafe {
        let old = ffi::SelectObject(dc, object);
        f();
        ffi::SelectObject(dc, old);
        ffi::DeleteObject(object);
    }
}

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

extern "system" fn procedure(window: usize, message: u32, wparam: usize, lparam: isize) -> isize {
    match message {
        WM_PAINT => {
            let mut paint = ffi::PaintStruct::default();
            // SAFETY: the window's own PAINTSTRUCT.
            let dc = unsafe { ffi::BeginPaint(window, &mut paint) };
            if dc != 0 {
                draw(dc);
            }
            // SAFETY: as above.
            unsafe { ffi::EndPaint(window, &paint) };
            0
        }
        WM_DESTROY => {
            // SAFETY: no pointers.
            unsafe { ffi::PostQuitMessage(0) };
            0
        }
        // SAFETY: the message as the window manager handed it over.
        _ => unsafe { ffi::DefWindowProcW(window, message, wparam, lparam) },
    }
}

fn main() -> u32 {
    let class_name = Wide::of("ShapeShow");
    let title = Wide::of("Shapes");
    // SAFETY: the program's own module, class, strings and RECT, which live for each call.
    let window = unsafe {
        let instance = ffi::GetModuleHandleA(core::ptr::null());
        let class = ffi::WndClassW {
            style: 0,
            proc: procedure,
            class_extra: 0,
            window_extra: 0,
            instance,
            icon: 0,
            cursor: 0,
            background: COLOR_WINDOW + 1,
            menu_name: core::ptr::null(),
            class_name: class_name.as_ptr(),
        };
        if ffi::RegisterClassW(&class) == 0 {
            return NO_WINDOW;
        }
        let mut rect = ffi::Rect {
            left: 0,
            top: 0,
            right: 260,
            bottom: 200,
        };
        ffi::AdjustWindowRectEx(&mut rect, STYLE, 0, 0);
        let (cx, cy) = (rect.right - rect.left, rect.bottom - rect.top);
        let x = (ffi::GetSystemMetrics(SM_CXSCREEN) - cx) / 2;
        let y = (ffi::GetSystemMetrics(SM_CYSCREEN) - cy) / 2;
        ffi::CreateWindowExW(
            0,
            class_name.as_ptr(),
            title.as_ptr(),
            STYLE,
            x,
            y,
            cx,
            cy,
            0,
            0,
            instance,
            0,
        )
    };
    if window == 0 {
        let _ = exe::stderr().print(format_args!("shapeshow: the window cannot be made\r\n"));
        return NO_WINDOW;
    }
    // SAFETY: the program's own window.
    unsafe { ffi::SetForegroundWindow(window) };
    let mut ready = false;
    let mut msg = ffi::Msg::default();
    loop {
        // SAFETY: the loop's own MSG.
        let idle = unsafe { ffi::PeekMessageW(&mut msg, 0, 0, 0, PM_NOREMOVE) } == 0;
        if idle && !ready {
            ready = true;
            let _ = exe::stdout().print(format_args!("{READY}\r\n"));
        }
        // SAFETY: as above.
        if unsafe { ffi::GetMessageW(&mut msg, 0, 0, 0) } <= 0 {
            break;
        }
        // SAFETY: as above.
        unsafe {
            ffi::TranslateMessage(&msg);
            ffi::DispatchMessageW(&msg);
        }
    }
    0
}
