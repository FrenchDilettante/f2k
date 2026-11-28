//! The calls more than one screen test program makes, as user32, gdi32 and kernel32 export them,
//! and the structures they pass. A program's own `ffi` module re-exports these
//! (`pub use common::ffi::*`) beside the calls only it makes.

/// A window procedure (WNDPROC).
pub type WindowProc = extern "system" fn(usize, u32, usize, isize) -> isize;

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
#[derive(Clone, Copy, Default)]
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
    pub proc: WindowProc,
    pub class_extra: i32,
    pub window_extra: i32,
    pub instance: usize,
    pub icon: usize,
    pub cursor: usize,
    pub background: usize,
    pub menu_name: *const u16,
    pub class_name: *const u16,
}

/// WNDCLASSEXA (48 bytes).
#[repr(C)]
pub struct WndClassExA {
    pub size: u32,
    pub style: u32,
    pub proc: WindowProc,
    pub class_extra: i32,
    pub window_extra: i32,
    pub instance: usize,
    pub icon: usize,
    pub cursor: usize,
    pub background: usize,
    pub menu_name: *const u8,
    pub class_name: *const u8,
    pub small_icon: usize,
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
    pub fn GetMessageW(msg: *mut Msg, window: usize, first: u32, last: u32) -> i32;
    pub fn PeekMessageW(msg: *mut Msg, window: usize, first: u32, last: u32, flags: u32) -> i32;
    pub fn DispatchMessageW(msg: *const Msg) -> isize;
    pub fn SendMessageW(window: usize, message: u32, wparam: usize, lparam: isize) -> isize;

    pub fn RegisterClassExA(class: *const WndClassExA) -> u16;
    pub fn CreateWindowExA(
        ex_style: u32,
        class: *const u8,
        name: *const u8,
        style: u32,
        x: i32,
        y: i32,
        width: i32,
        height: i32,
        parent: usize,
        menu: usize,
        instance: usize,
        param: usize,
    ) -> usize;
    pub fn DefWindowProcA(window: usize, message: u32, wparam: usize, lparam: isize) -> isize;
    pub fn GetMessageA(msg: *mut Msg, window: usize, first: u32, last: u32) -> i32;
    pub fn DispatchMessageA(msg: *const Msg) -> isize;

    pub fn TranslateMessage(msg: *const Msg) -> i32;
    pub fn PostQuitMessage(code: i32);
    pub fn AdjustWindowRectEx(rect: *mut Rect, style: u32, menu: i32, ex_style: u32) -> i32;
    pub fn GetSystemMetrics(index: i32) -> i32;
    pub fn DestroyWindow(window: usize) -> i32;
    pub fn UpdateWindow(window: usize) -> i32;
    pub fn SetForegroundWindow(window: usize) -> i32;
    pub fn SetFocus(window: usize) -> usize;
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
    pub fn SetBkMode(dc: usize, mode: i32) -> i32;
    pub fn SetPixel(dc: usize, x: i32, y: i32, color: u32) -> u32;
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
}
