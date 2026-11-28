//! clipshow.exe: a top-level window that paints its whole client area itself, over the bordered
//! controls in it, for tests/core/test_childpaint.py to look at.
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

use exe::winuser::{
    LBS_NOINTEGRALHEIGHT,
    LB_ADDSTRING,
    PM_NOREMOVE,
    SM_CXSCREEN,
    SM_CYSCREEN,
    SS_LEFT,
    WM_DESTROY,
    WM_PAINT,
    WS_BORDER,
    WS_CAPTION,
    WS_CHILD,
    WS_SYSMENU,
    WS_VISIBLE,
    WS_VSCROLL,
};

exe::entry!(main);

/// The calls clipshow makes, as user32, gdi32 and kernel32 export them.
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

    #[link(name = "gdi32", kind = "raw-dylib", import_name_type = "undecorated")]
    unsafe extern "system" {
        pub fn CreateSolidBrush(color: u32) -> usize;
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
        pub fn SendMessageW(window: usize, message: u32, wparam: usize, lparam: isize) -> isize;
        pub fn AdjustWindowRectEx(rect: *mut Rect, style: u32, menu: i32, ex_style: u32) -> i32;
        pub fn GetSystemMetrics(index: i32) -> i32;
        pub fn GetMessageW(msg: *mut Msg, window: usize, first: u32, last: u32) -> i32;
        pub fn PeekMessageW(msg: *mut Msg, window: usize, first: u32, last: u32, flags: u32)
            -> i32;
        pub fn TranslateMessage(msg: *const Msg) -> i32;
        pub fn DispatchMessageW(msg: *const Msg) -> isize;
        pub fn SetForegroundWindow(window: usize) -> i32;
        pub fn BeginPaint(window: usize, paint: *mut PaintStruct) -> usize;
        pub fn EndPaint(window: usize, paint: *const PaintStruct) -> i32;
        pub fn GetClientRect(window: usize, rect: *mut Rect) -> i32;
        pub fn FillRect(dc: usize, rect: *const Rect, brush: usize) -> i32;
        pub fn InvalidateRect(window: usize, rect: *const Rect, erase: i32) -> i32;
        pub fn PostQuitMessage(code: i32);
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

extern "system" fn procedure(window: usize, message: u32, wparam: usize, lparam: isize) -> isize {
    match message {
        WM_PAINT => {
            let mut paint = ffi::PaintStruct::default();
            let mut client = ffi::Rect::default();
            // SAFETY: the program's own window, PAINTSTRUCT and RECT.
            unsafe {
                let dc = ffi::BeginPaint(window, &mut paint);
                ffi::GetClientRect(window, &mut client);
                ffi::FillRect(dc, &client, BRUSH.load(Ordering::Relaxed));
                ffi::EndPaint(window, &paint);
            }
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

/// A child of `parent` of the class `class`, with `ex_style` and `style` (WS_CHILD and WS_VISIBLE
/// added), its text `text`, at (`x`, `y`), `cx` by `cy`, its id `id`; 0 when it cannot be made.
#[allow(clippy::too_many_arguments)]
fn child(
    parent: usize,
    instance: usize,
    class: &str,
    ex_style: u32,
    style: u32,
    text: &str,
    (x, y, cx, cy): (i32, i32, i32, i32),
    id: usize,
) -> usize {
    let class = Wide::of(class);
    let text = Wide::of(text);
    // SAFETY: the program's own window, class name and text, which live for the call.
    unsafe {
        ffi::CreateWindowExW(
            ex_style,
            class.as_ptr(),
            text.as_ptr(),
            WS_CHILD | WS_VISIBLE | style,
            x,
            y,
            cx,
            cy,
            parent,
            id,
            instance,
            0,
        )
    }
}

fn main() -> u32 {
    let class_name = Wide::of("ClipShow");
    let title = Wide::of("Child frames");
    // SAFETY: the program's own module, class, strings and RECT, which live for each call.
    let (window, instance) = unsafe {
        let instance = ffi::GetModuleHandleA(core::ptr::null());
        BRUSH.store(ffi::CreateSolidBrush(TEAL), Ordering::Relaxed);
        let class = ffi::WndClassW {
            style: 0,
            proc: procedure,
            class_extra: 0,
            window_extra: 0,
            instance,
            icon: 0,
            cursor: 0,
            background: 0,
            menu_name: core::ptr::null(),
            class_name: class_name.as_ptr(),
        };
        if ffi::RegisterClassW(&class) == 0 {
            return NO_WINDOW;
        }
        let mut rect = ffi::Rect {
            left: 0,
            top: 0,
            right: 300,
            bottom: 200,
        };
        ffi::AdjustWindowRectEx(&mut rect, STYLE, 0, 0);
        let (cx, cy) = (rect.right - rect.left, rect.bottom - rect.top);
        let x = (ffi::GetSystemMetrics(SM_CXSCREEN) - cx) / 2;
        let y = (ffi::GetSystemMetrics(SM_CYSCREEN) - cy) / 2;
        let window = ffi::CreateWindowExW(
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
        );
        (window, instance)
    };
    if window == 0 {
        let _ = exe::stderr().print(format_args!("clipshow: the window cannot be made\r\n"));
        return NO_WINDOW;
    }
    let made = [
        child(
            window,
            instance,
            "Static",
            0,
            SS_LEFT | WS_BORDER,
            "Bordered",
            (10, 10, 120, 40),
            101,
        ),
        child(
            window,
            instance,
            "Edit",
            WS_EX_CLIENTEDGE,
            ES_AUTOHSCROLL,
            "Edit",
            (10, 70, 120, 24),
            102,
        ),
        child(
            window,
            instance,
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
        ffi::SetForegroundWindow(window);
    }
    // 0: the first painting; 1: the window invalidated again; 2: ready printed.
    let mut stage = 0;
    let mut msg = ffi::Msg::default();
    loop {
        // SAFETY: the loop's own MSG.
        let idle = unsafe { ffi::PeekMessageW(&mut msg, 0, 0, 0, PM_NOREMOVE) } == 0;
        if idle && stage == 0 {
            stage = 1;
            // SAFETY: the program's own window.
            unsafe { ffi::InvalidateRect(window, core::ptr::null(), 1) };
            continue;
        }
        if idle && stage == 1 {
            stage = 2;
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
