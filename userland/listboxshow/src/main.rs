//! listboxshow.exe: a top-level window with three ListBox controls in its client area, for
//! tests/core/test_listboxes.py to look at.
//!
//! - A list box with a border and WS_VSCROLL: fifteen items (more than show, so its scroll bar
//!   shows), the third selected, the focus on it (its focus rectangle drawn).
//! - An LBS_MULTIPLESEL list box with a border: five items, the first and the fourth selected.
//! - A disabled list box with a border: two items, their text greyed.
//!
//! The window does not clip its children (no WS_CLIPCHILDREN), so its painting covers the list
//! boxes; each paints after it, its frame (its client edge, its scroll bar) included.
//!
//! It prints `listboxshow: ready` once the window shows and its queue is idle; Alt+F4 closes the
//! window (the default procedure's SC_CLOSE), which ends it with 0.

#![no_std]
#![no_main]

use exe::winuser::{
    COLOR_3DFACE,
    LBS_MULTIPLESEL,
    LBS_NOINTEGRALHEIGHT,
    LBS_NOTIFY,
    LB_ADDSTRING,
    LB_SETCURSEL,
    LB_SETSEL,
    PM_NOREMOVE,
    SM_CXSCREEN,
    SM_CYSCREEN,
    WM_DESTROY,
    WS_BORDER,
    WS_CAPTION,
    WS_CHILD,
    WS_DISABLED,
    WS_SYSMENU,
    WS_VISIBLE,
    WS_VSCROLL,
};

exe::entry!(main);

/// The calls listboxshow makes, as user32 and kernel32 export them.
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
        pub fn SendMessageW(window: usize, message: u32, wparam: usize, lparam: isize) -> isize;
        pub fn AdjustWindowRectEx(rect: *mut Rect, style: u32, menu: i32, ex_style: u32) -> i32;
        pub fn GetSystemMetrics(index: i32) -> i32;
        pub fn GetMessageW(msg: *mut Msg, window: usize, first: u32, last: u32) -> i32;
        pub fn PeekMessageW(msg: *mut Msg, window: usize, first: u32, last: u32, flags: u32)
            -> i32;
        pub fn TranslateMessage(msg: *const Msg) -> i32;
        pub fn DispatchMessageW(msg: *const Msg) -> isize;
        pub fn SetForegroundWindow(window: usize) -> i32;
        pub fn SetFocus(window: usize) -> usize;
        pub fn PostQuitMessage(code: i32);
    }
}

/// The window's styles: a caption with its system menu, a fixed frame.
const STYLE: u32 = WS_CAPTION | WS_SYSMENU | WS_VISIBLE;

/// The line printed once the window shows and the queue is idle.
const READY: &str = "listboxshow: ready";
/// The exit code when a window cannot be made.
const NO_WINDOW: u32 = 1;

/// The first list box's items.
const ITEMS: [&str; 15] = [
    "Alpha", "Bravo", "Charlie", "Delta", "Echo", "Foxtrot", "Golf", "Hotel", "India", "Juliet",
    "Kilo", "Lima", "Mike", "November", "Oscar",
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
        WM_DESTROY => {
            // SAFETY: no pointers.
            unsafe { ffi::PostQuitMessage(0) };
            0
        }
        // SAFETY: the message as the window manager handed it over.
        _ => unsafe { ffi::DefWindowProcW(window, message, wparam, lparam) },
    }
}

/// A list box child of `parent` at (`x`, `y`), `cx` by `cy`, with `style`, its id `id`, holding
/// `items`; 0 when it cannot be made.
fn list_box(
    parent: usize,
    instance: usize,
    style: u32,
    (x, y, cx, cy): (i32, i32, i32, i32),
    id: usize,
    items: &[&str],
) -> usize {
    let class = Wide::of("ListBox");
    let empty = Wide::of("");
    // SAFETY: the program's own window, class name and strings, which live for each call.
    unsafe {
        let window = ffi::CreateWindowExW(
            0,
            class.as_ptr(),
            empty.as_ptr(),
            WS_CHILD | WS_VISIBLE | WS_BORDER | LBS_NOINTEGRALHEIGHT | style,
            x,
            y,
            cx,
            cy,
            parent,
            id,
            instance,
            0,
        );
        if window != 0 {
            for item in items {
                let text = Wide::of(item);
                ffi::SendMessageW(window, LB_ADDSTRING, 0, text.as_ptr() as isize);
            }
        }
        window
    }
}

fn main() -> u32 {
    let class_name = Wide::of("ListBoxShow");
    let title = Wide::of("List boxes");
    // SAFETY: the program's own module, class, strings and RECT, which live for each call.
    let (window, instance) = unsafe {
        let instance = ffi::GetModuleHandleA(core::ptr::null());
        let class = ffi::WndClassW {
            style: 0,
            proc: procedure,
            class_extra: 0,
            window_extra: 0,
            instance,
            icon: 0,
            cursor: 0,
            background: COLOR_3DFACE + 1,
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
    let (single, multiple, disabled) = if window == 0 {
        (0, 0, 0)
    } else {
        (
            list_box(
                window,
                instance,
                WS_VSCROLL | LBS_NOTIFY,
                (10, 10, 130, 180),
                101,
                &ITEMS,
            ),
            list_box(
                window,
                instance,
                LBS_MULTIPLESEL,
                (160, 10, 130, 100),
                102,
                &ITEMS[..5],
            ),
            list_box(
                window,
                instance,
                WS_DISABLED,
                (160, 130, 130, 60),
                103,
                &["Disabled", "Greyed"],
            ),
        )
    };
    if window == 0 || single == 0 || multiple == 0 || disabled == 0 {
        let _ = exe::stderr().print(format_args!("listboxshow: the windows cannot be made\r\n"));
        return NO_WINDOW;
    }
    // SAFETY: the program's own windows.
    unsafe {
        ffi::SendMessageW(single, LB_SETCURSEL, 2, 0);
        ffi::SendMessageW(multiple, LB_SETSEL, 1, 0);
        ffi::SendMessageW(multiple, LB_SETSEL, 1, 3);
        ffi::SetForegroundWindow(window);
        ffi::SetFocus(single);
    }
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
