//! menushow.exe: a top-level window with calc's styles (a caption, its system menu and minimize
//! box, a fixed frame) and calc's menu bar (Edit, View, Help) built with AppendMenuW, its size
//! from AdjustWindowRectEx, driven by the keyboard through the default window procedure's menu
//! loop. It prints a line once the window shows, one for each menu message its procedure
//! receives, one once a command has been taken and the window is painted again; closing the window
//! (Alt+F4) ends it (src/lib.rs lays the lines out).

#![no_std]
#![no_main]

use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use menushow::*;

exe::entry!(main);

/// The calls menushow makes, as user32 and kernel32 export them.
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

    /// PeekMessage's flag leaving the message in the queue; CheckMenuRadioItem's by-command flag;
    /// COLOR_3DFACE; SM_CXSCREEN and SM_CYSCREEN.
    pub const PM_NOREMOVE: u32 = 0;
    pub const MF_BYCOMMAND: u32 = 0;
    pub const COLOR_3DFACE: usize = 15;
    pub const SM_CXSCREEN: i32 = 0;
    pub const SM_CYSCREEN: i32 = 1;

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
        pub fn CreateMenu() -> usize;
        pub fn CreatePopupMenu() -> usize;
        pub fn AppendMenuW(menu: usize, flags: u32, item: usize, text: *const u16) -> i32;
        pub fn GetSubMenu(menu: usize, position: i32) -> usize;
        pub fn GetMenu(window: usize) -> usize;
        pub fn CheckMenuRadioItem(
            menu: usize,
            first: u32,
            last: u32,
            check: u32,
            flags: u32,
        ) -> i32;
        pub fn DrawMenuBar(window: usize) -> i32;
        pub fn GetMessageW(msg: *mut Msg, window: usize, first: u32, last: u32) -> i32;
        pub fn PeekMessageW(msg: *mut Msg, window: usize, first: u32, last: u32, flags: u32)
            -> i32;
        pub fn TranslateMessage(msg: *const Msg) -> i32;
        pub fn DispatchMessageW(msg: *const Msg) -> isize;
        pub fn SetForegroundWindow(window: usize) -> i32;
        pub fn PostQuitMessage(code: i32);
    }
}

/// A string's UTF-16 units, NUL-terminated, in a buffer of the program's own.
struct Wide([u16; 64]);

impl Wide {
    fn of(text: &str) -> Wide {
        let mut units = [0u16; 64];
        for (unit, value) in units.iter_mut().take(63).zip(text.encode_utf16()) {
            *unit = value;
        }
        Wide(units)
    }

    fn as_ptr(&self) -> *const u16 {
        self.0.as_ptr()
    }
}

/// The menu bar the window holds (0 before it is made).
static BAR: AtomicUsize = AtomicUsize::new(0);
/// A command was taken: the next idle prints the settled line.
static SETTLE: AtomicBool = AtomicBool::new(false);

/// The name a line gives the menu `handle`.
fn name_of(handle: usize) -> MenuName {
    let bar = BAR.load(Ordering::Relaxed);
    if handle == 0 {
        return MenuName::Null;
    }
    if handle == bar {
        return MenuName::Bar;
    }
    (0..MENU.len())
        // SAFETY: no pointers.
        .find(|&index| unsafe { ffi::GetSubMenu(bar, index as i32) } == handle)
        .map_or(MenuName::Other, MenuName::Popup)
}

/// The window's procedure: every menu message printed (and handed on to the default procedure,
/// which runs the menu loop); View's commands move its radio check; the window's end ends the
/// loop.
extern "system" fn procedure(window: usize, message: u32, wparam: usize, lparam: isize) -> isize {
    if is_menu_message(message) {
        let menu = menu_parameter(message, wparam as u32, lparam as u32).unwrap_or(0) as usize;
        let line = MenuLine {
            message,
            wparam: wparam as u32,
            lparam: lparam as u32,
            menu: name_of(menu),
        };
        let _ = exe::stdout().print(format_args!("{line}\r\n"));
    }
    match message {
        WM_COMMAND => {
            let id = wparam as u32 & 0xFFFF;
            if id == u32::from(ID_STANDARD) || id == u32::from(ID_SCIENTIFIC) {
                // SAFETY: the window's own menu.
                unsafe {
                    let view = ffi::GetSubMenu(ffi::GetMenu(window), 1);
                    ffi::CheckMenuRadioItem(
                        view,
                        ID_STANDARD.into(),
                        ID_SCIENTIFIC.into(),
                        id,
                        ffi::MF_BYCOMMAND,
                    );
                    ffi::DrawMenuBar(window);
                }
            }
            SETTLE.store(true, Ordering::Relaxed);
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

/// The menu bar of [`MENU`], built with CreateMenu, CreatePopupMenu and AppendMenuW; View's first
/// two items made radio items, Standard checked.
fn build_menu() -> usize {
    // SAFETY: the program's own menus and strings, which live for each call.
    unsafe {
        let bar = ffi::CreateMenu();
        for (name, items) in MENU {
            let popup = ffi::CreatePopupMenu();
            for &(flags, id, text) in items {
                let text = Wide::of(text);
                let at = if flags & MF_SEPARATOR != 0 {
                    core::ptr::null()
                } else {
                    text.as_ptr()
                };
                ffi::AppendMenuW(popup, flags, id.into(), at);
            }
            ffi::AppendMenuW(bar, MF_STRING | MF_POPUP, popup, Wide::of(name).as_ptr());
        }
        let view = ffi::GetSubMenu(bar, 1);
        ffi::CheckMenuRadioItem(
            view,
            ID_STANDARD.into(),
            ID_SCIENTIFIC.into(),
            ID_STANDARD.into(),
            ffi::MF_BYCOMMAND,
        );
        bar
    }
}

fn main() -> u32 {
    let class_name = Wide::of("MenuShow");
    let title = Wide::of("Calculator");
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
            background: ffi::COLOR_3DFACE + 1,
            menu_name: core::ptr::null(),
            class_name: class_name.as_ptr(),
        };
        if ffi::RegisterClassW(&class) == 0 {
            return NO_WINDOW;
        }
        let bar = build_menu();
        BAR.store(bar, Ordering::Relaxed);
        let mut rect = ffi::Rect {
            left: 0,
            top: 0,
            right: 260,
            bottom: 200,
        };
        ffi::AdjustWindowRectEx(&mut rect, STYLE, 1, 0);
        let (cx, cy) = (rect.right - rect.left, rect.bottom - rect.top);
        let x = (ffi::GetSystemMetrics(ffi::SM_CXSCREEN) - cx) / 2;
        let y = (ffi::GetSystemMetrics(ffi::SM_CYSCREEN) - cy) / 2;
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
            bar,
            instance,
            0,
        )
    };
    if window == 0 {
        let _ = exe::stderr().print(format_args!("menushow: the window cannot be made\r\n"));
        return NO_WINDOW;
    }
    // SAFETY: the program's own window.
    unsafe { ffi::SetForegroundWindow(window) };
    let mut ready = false;
    let mut msg = ffi::Msg::default();
    loop {
        // SAFETY: the loop's own MSG.
        let idle = unsafe { ffi::PeekMessageW(&mut msg, 0, 0, 0, ffi::PM_NOREMOVE) } == 0;
        if idle && !ready {
            ready = true;
            let _ = exe::stdout().print(format_args!("{READY}\r\n"));
        }
        if idle && SETTLE.swap(false, Ordering::Relaxed) {
            let _ = exe::stdout().print(format_args!("{SETTLED}\r\n"));
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
