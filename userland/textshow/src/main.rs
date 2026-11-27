//! textshow.exe: a top-level window whose client area shows gdi32's text layout, for
//! tests/core/test_textshow.py to look at. Its WM_PAINT draws, through BeginPaint's DC in the
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

/// The calls textshow makes, as user32, gdi32 and kernel32 export them.
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
        pub fn SetPixel(dc: usize, x: i32, y: i32, color: u32) -> u32;
        pub fn SetBkColor(dc: usize, color: u32) -> u32;
        pub fn SetBkMode(dc: usize, mode: i32) -> i32;
        pub fn SetTextColor(dc: usize, color: u32) -> u32;
        pub fn SetTextAlign(dc: usize, align: u32) -> u32;
        pub fn SetTextCharacterExtra(dc: usize, extra: i32) -> i32;
        pub fn SetTextJustification(dc: usize, extra: i32, breaks: i32) -> i32;
        pub fn TextOutW(dc: usize, x: i32, y: i32, string: *const u16, count: i32) -> i32;
        pub fn PolyTextOutW(dc: usize, texts: *const PolyTextW, count: i32) -> i32;
        pub fn MoveToEx(dc: usize, x: i32, y: i32, previous: *mut Point) -> i32;
        pub fn SaveDC(dc: usize) -> i32;
        pub fn RestoreDC(dc: usize, level: i32) -> i32;
        pub fn SetMapMode(dc: usize, mode: i32) -> i32;
        pub fn SetWindowExtEx(dc: usize, x: i32, y: i32, previous: *mut Size) -> i32;
        pub fn SetViewportExtEx(dc: usize, x: i32, y: i32, previous: *mut Size) -> i32;
        pub fn SetViewportOrgEx(dc: usize, x: i32, y: i32, previous: *mut Point) -> i32;
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

/// A string's UTF-16 units, NUL-terminated, in a buffer of the program's own, and its length.
struct Wide([u16; 32], usize);

impl Wide {
    fn of(text: &str) -> Wide {
        let mut units = [0u16; 32];
        let mut length = 0;
        for (unit, value) in units.iter_mut().take(31).zip(text.encode_utf16()) {
            *unit = value;
            length += 1;
        }
        Wide(units, length)
    }

    fn as_ptr(&self) -> *const u16 {
        self.0.as_ptr()
    }

    fn len(&self) -> i32 {
        self.1 as i32
    }
}

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
    let class_name = Wide::of("TextShow");
    let title = Wide::of("Text Layout");
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
        let _ = exe::stderr().print(format_args!("textshow: the window cannot be made\r\n"));
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
