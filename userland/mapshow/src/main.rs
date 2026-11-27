//! mapshow.exe: a top-level window whose client area is drawn through gdi32's mapping modes, for
//! tests/core/test_mapshow.py to look at. Its WM_PAINT draws, through BeginPaint's DC, each part
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

/// The calls mapshow makes, as user32, gdi32 and kernel32 export them.
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

    /// SIZE.
    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    pub struct Size {
        pub cx: i32,
        pub cy: i32,
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
        pub fn CreateSolidBrush(color: u32) -> usize;
        pub fn GetStockObject(index: i32) -> usize;
        pub fn SelectObject(dc: usize, object: usize) -> usize;
        pub fn DeleteObject(object: usize) -> i32;
        pub fn CreateCompatibleDC(dc: usize) -> usize;
        pub fn CreateCompatibleBitmap(dc: usize, width: i32, height: i32) -> usize;
        pub fn DeleteDC(dc: usize) -> i32;
        pub fn SetPixel(dc: usize, x: i32, y: i32, color: u32) -> u32;
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
        pub fn MoveToEx(dc: usize, x: i32, y: i32, previous: *mut Point) -> i32;
        pub fn LineTo(dc: usize, x: i32, y: i32) -> i32;
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
        pub fn SaveDC(dc: usize) -> i32;
        pub fn RestoreDC(dc: usize, level: i32) -> i32;
        pub fn SetMapMode(dc: usize, mode: i32) -> i32;
        pub fn SetWindowExtEx(dc: usize, x: i32, y: i32, previous: *mut Size) -> i32;
        pub fn SetViewportExtEx(dc: usize, x: i32, y: i32, previous: *mut Size) -> i32;
        pub fn SetViewportOrgEx(dc: usize, x: i32, y: i32, previous: *mut Point) -> i32;
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
/// `dc` a DC of the program's; `object` a pen or brush it made.
unsafe fn with(dc: usize, object: usize, f: impl FnOnce()) {
    // SAFETY: the caller's DC and object.
    unsafe {
        let old = ffi::SelectObject(dc, object);
        f();
        ffi::SelectObject(dc, old);
        ffi::DeleteObject(object);
    }
}

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
    let class_name = Wide::of("MapShow");
    let title = Wide::of("Mapping");
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
        let _ = exe::stderr().print(format_args!("mapshow: the window cannot be made\r\n"));
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
