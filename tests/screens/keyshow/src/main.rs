//! keyshow.exe: a window that takes the keyboard and prints, on the standard output, each keyboard
//! message its procedure receives (src/lib.rs lays the lines out). Its window is made the
//! foreground and focus window, then it reads its queue (GetMessage, TranslateMessage,
//! DispatchMessage) until Escape's character, which destroys the window and ends the loop.

#![no_std]
#![no_main]

use exe::winuser::{WM_CHAR, WM_DESTROY, WS_BORDER, WS_POPUP, WS_VISIBLE};
use keyshow::*;

exe::entry!(main);

/// The window's class name, and the messages and styles it uses (winuser.h).
const CLASS: &[u8] = b"F2KKeyShow\0";

/// The calls keyshow makes, as user32 exports them: the shared ones, and its own.
mod ffi {
    pub use common::ffi::*;

    #[link(name = "user32", kind = "raw-dylib", import_name_type = "undecorated")]
    unsafe extern "system" {
        pub fn GetForegroundWindow() -> usize;
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
    // No class, no window.
    let instance = common::register_class_a(CLASS, procedure, 0);
    // SAFETY: the class's name and the window's, NUL-terminated.
    let window = instance.map_or(0, |instance| unsafe {
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
    });
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
