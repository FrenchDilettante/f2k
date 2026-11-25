//! scrollshow.exe: a top-level window with both standard scroll bars (WS_HSCROLL, WS_VSCROLL) and
//! two ScrollBar controls in its client area, for tests/core/test_scrollbars.py to look at.
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

exe::entry!(main);

/// The calls scrollshow makes, as user32 and kernel32 export them.
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

    /// SCROLLINFO (28 bytes).
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

    pub const PM_NOREMOVE: u32 = 0;
    pub const COLOR_WINDOW: usize = 5;
    pub const SM_CXSCREEN: i32 = 0;
    pub const SM_CYSCREEN: i32 = 1;
    pub const SB_HORZ: i32 = 0;
    pub const SB_VERT: i32 = 1;
    pub const SB_CTL: i32 = 2;
    pub const SIF_RANGE: u32 = 0x1;
    pub const SIF_PAGE: u32 = 0x2;
    pub const SIF_POS: u32 = 0x4;
    pub const ESB_DISABLE_BOTH: u32 = 0x3;
    pub const ESB_DISABLE_LTUP: u32 = 0x1;

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
        pub fn SetScrollInfo(window: usize, bar: i32, info: *const ScrollInfo, redraw: i32) -> i32;
        pub fn EnableScrollBar(window: usize, bar: u32, arrows: u32) -> i32;
        pub fn GetMessageW(msg: *mut Msg, window: usize, first: u32, last: u32) -> i32;
        pub fn PeekMessageW(msg: *mut Msg, window: usize, first: u32, last: u32, flags: u32)
            -> i32;
        pub fn TranslateMessage(msg: *const Msg) -> i32;
        pub fn DispatchMessageW(msg: *const Msg) -> isize;
        pub fn SetForegroundWindow(window: usize) -> i32;
        pub fn PostQuitMessage(code: i32);
    }
}

/// The messages the procedure reads (winuser.h).
const WM_DESTROY: u32 = 0x0002;

/// The window's styles: a caption with its system menu, a fixed frame, both scroll bars.
const WS_OVERLAPPED_FIXED: u32 = 0x00C0_0000 | 0x0008_0000; // WS_CAPTION | WS_SYSMENU
const WS_HSCROLL: u32 = 0x0010_0000;
const WS_VSCROLL: u32 = 0x0020_0000;
const WS_VISIBLE: u32 = 0x1000_0000;
const WS_CHILD: u32 = 0x4000_0000;
const SBS_HORZ: u32 = 0x0;
const SBS_VERT: u32 = 0x1;
const STYLE: u32 = WS_OVERLAPPED_FIXED | WS_HSCROLL | WS_VSCROLL | WS_VISIBLE;

/// The line printed once the window shows and the queue is idle.
const READY: &str = "scrollshow: ready";
/// The exit code when the window cannot be made.
const NO_WINDOW: u32 = 1;

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
        WM_DESTROY => {
            // SAFETY: no pointers.
            unsafe { ffi::PostQuitMessage(0) };
            0
        }
        // SAFETY: the message as the window manager handed it over.
        _ => unsafe { ffi::DefWindowProcW(window, message, wparam, lparam) },
    }
}

/// Sets `bar` of `window` to `min..=max`, `page` and `pos`, redrawn.
fn set(window: usize, bar: i32, min: i32, max: i32, page: u32, pos: i32) {
    let info = ffi::ScrollInfo {
        size: core::mem::size_of::<ffi::ScrollInfo>() as u32,
        mask: ffi::SIF_RANGE | ffi::SIF_PAGE | ffi::SIF_POS,
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
    let class_name = Wide::of("ScrollShow");
    let title = Wide::of("Scroll bars");
    let scroll_bar = Wide::of("ScrollBar");
    let empty = Wide::of("");
    // SAFETY: the program's own module, class, strings and RECT, which live for each call.
    let (window, across, down) = unsafe {
        let instance = ffi::GetModuleHandleA(core::ptr::null());
        let class = ffi::WndClassW {
            style: 0,
            proc: procedure,
            class_extra: 0,
            window_extra: 0,
            instance,
            icon: 0,
            cursor: 0,
            background: ffi::COLOR_WINDOW + 1,
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
        let x = (ffi::GetSystemMetrics(ffi::SM_CXSCREEN) - cx) / 2;
        let y = (ffi::GetSystemMetrics(ffi::SM_CYSCREEN) - cy) / 2;
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
        if window == 0 {
            (0, 0, 0)
        } else {
            let across = ffi::CreateWindowExW(
                0,
                scroll_bar.as_ptr(),
                empty.as_ptr(),
                WS_CHILD | WS_VISIBLE | SBS_HORZ,
                20,
                30,
                160,
                17,
                window,
                101,
                instance,
                0,
            );
            let down = ffi::CreateWindowExW(
                0,
                scroll_bar.as_ptr(),
                empty.as_ptr(),
                WS_CHILD | WS_VISIBLE | SBS_VERT,
                200,
                20,
                17,
                120,
                window,
                102,
                instance,
                0,
            );
            (window, across, down)
        }
    };
    if window == 0 || across == 0 || down == 0 {
        let _ = exe::stderr().print(format_args!("scrollshow: the windows cannot be made\r\n"));
        return NO_WINDOW;
    }
    set(window, ffi::SB_VERT, 0, 99, 20, 30);
    set(window, ffi::SB_HORZ, 0, 49, 10, 0);
    set(across, ffi::SB_CTL, 0, 10, 0, 5);
    set(down, ffi::SB_CTL, 0, 4, 0, 0);
    // SAFETY: the program's own windows.
    unsafe {
        ffi::EnableScrollBar(window, ffi::SB_HORZ as u32, ffi::ESB_DISABLE_LTUP);
        ffi::EnableScrollBar(down, ffi::SB_CTL as u32, ffi::ESB_DISABLE_BOTH);
        ffi::SetForegroundWindow(window);
    }
    let mut ready = false;
    let mut msg = ffi::Msg::default();
    loop {
        // SAFETY: the loop's own MSG.
        let idle = unsafe { ffi::PeekMessageW(&mut msg, 0, 0, 0, ffi::PM_NOREMOVE) } == 0;
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
