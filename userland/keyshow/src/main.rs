//! keyshow.exe: a window that takes the keyboard and prints, on the standard output, each keyboard
//! message its procedure receives (src/lib.rs lays the lines out). Its window is made the
//! foreground and focus window, then it reads its queue (GetMessage, TranslateMessage,
//! DispatchMessage) until Escape's character, which destroys the window and ends the loop.

#![no_std]
#![no_main]

use keyshow::*;

exe::entry!(main);

/// The window's class name, and the messages and styles it uses (winuser.h).
const CLASS: &[u8] = b"F2KKeyShow\0";
const WM_DESTROY: u32 = 0x0002;
const WS_POPUP: u32 = 0x8000_0000;
const WS_VISIBLE: u32 = 0x1000_0000;
const WS_BORDER: u32 = 0x0080_0000;

/// The calls keyshow makes, as user32 and kernel32 export them.
mod ffi {
    /// WNDCLASSEXA (48 bytes).
    #[repr(C)]
    pub struct WndClassExA {
        pub size: u32,
        pub style: u32,
        pub proc: extern "system" fn(usize, u32, usize, isize) -> isize,
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
        pub fn RegisterClassExA(class: *const WndClassExA) -> u16;
        #[allow(clippy::too_many_arguments)]
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
        pub fn DestroyWindow(window: usize) -> i32;
        pub fn SetForegroundWindow(window: usize) -> i32;
        pub fn GetForegroundWindow() -> usize;
        pub fn SetFocus(window: usize) -> usize;
        pub fn GetMessageA(msg: *mut Msg, window: usize, first: u32, last: u32) -> i32;
        pub fn TranslateMessage(msg: *const Msg) -> i32;
        pub fn DispatchMessageA(msg: *const Msg) -> isize;
        pub fn DefWindowProcA(window: usize, message: u32, wparam: usize, lparam: isize) -> isize;
        pub fn PostQuitMessage(code: i32);
    }
}

/// The window's procedure: each keyboard message printed, answered 0 (DefWindowProc acts on none
/// of them); Escape's character destroys the window, whose WM_DESTROY ends the loop.
extern "system" fn procedure(window: usize, message: u32, wparam: usize, lparam: isize) -> isize {
    if let Some(line) = Line::of(message, wparam as u32, lparam as u32) {
        let _ = exe::stdout().print(format_args!("{line}\r\n"));
        if message == WM_CHAR && wparam as u32 == ESCAPE {
            // SAFETY: the window the procedure serves.
            unsafe { ffi::DestroyWindow(window) };
        }
        return 0;
    }
    if message == WM_DESTROY {
        // SAFETY: no pointers.
        unsafe { ffi::PostQuitMessage(0) };
        return 0;
    }
    // SAFETY: the message as the procedure received it.
    unsafe { ffi::DefWindowProcA(window, message, wparam, lparam) }
}

fn main() -> u32 {
    // SAFETY: the program's own module.
    let instance = unsafe { ffi::GetModuleHandleA(core::ptr::null()) };
    let class = ffi::WndClassExA {
        size: core::mem::size_of::<ffi::WndClassExA>() as u32,
        style: 0,
        proc: procedure,
        class_extra: 0,
        window_extra: 0,
        instance,
        icon: 0,
        cursor: 0,
        background: 0,
        menu_name: core::ptr::null(),
        class_name: CLASS.as_ptr(),
        small_icon: 0,
    };
    // SAFETY: the class's structure and name live for the call.
    let window = unsafe {
        ffi::RegisterClassExA(&class);
        ffi::CreateWindowExA(
            0,
            CLASS.as_ptr(),
            c"keyshow".as_ptr().cast(),
            WS_POPUP | WS_BORDER | WS_VISIBLE,
            40,
            40,
            160,
            80,
            0,
            0,
            instance,
            0,
        )
    };
    if window == 0 {
        let _ = exe::stderr().print(format_args!("keyshow: the window cannot be made\r\n"));
        return NO_WINDOW;
    }
    // SAFETY: the program's own window.
    let foreground = unsafe {
        ffi::SetForegroundWindow(window);
        ffi::SetFocus(window);
        ffi::GetForegroundWindow() == window
    };
    if !foreground {
        let _ = exe::stderr().print(format_args!("{NOT_FOREGROUND}\r\n"));
        return NO_WINDOW;
    }
    let _ = exe::stdout().print(format_args!("{READY}\r\n"));
    let mut msg = ffi::Msg::default();
    // SAFETY: the loop's own MSG.
    while unsafe { ffi::GetMessageA(&mut msg, 0, 0, 0) } > 0 {
        // SAFETY: as above.
        unsafe {
            ffi::TranslateMessage(&msg);
            ffi::DispatchMessageA(&msg);
        }
    }
    0
}
