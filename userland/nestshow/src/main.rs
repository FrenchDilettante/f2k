//! nestshow.exe: window procedures nested deep inside the kernel, and a message another thread
//! sends received inside GetMessage, each by the kernel's user-mode callbacks.
//!
//! Its window's WM_CREATE makes a child window of the same class, whose WM_CREATE makes the next,
//! [`DEPTH`] levels deep: each creation's messages reach their procedure by a callback from inside
//! the CreateWindowEx of the level above, so the kernel stack carries every level at once (a GUI
//! thread's large stack). Then a thread of its own sends the window a message while the main thread
//! waits in GetMessage (delivered by callback inside it), and posts the message that ends the loop.
//! Every step prints a line on the standard output.

#![no_std]
#![no_main]

use core::sync::atomic::{AtomicU32, Ordering};

exe::entry!(main);

/// How many windows nest, each made inside its parent's WM_CREATE.
const DEPTH: u32 = 20;

/// The window's class name, and the messages and styles it uses (winuser.h).
const CLASS: &[u8] = b"F2KNestShow\0";
const WM_CREATE: u32 = 0x0001;
const WM_USER: u32 = 0x0400;
const WS_POPUP: u32 = 0x8000_0000;
const WS_CHILD: u32 = 0x4000_0000;
const WS_VISIBLE: u32 = 0x1000_0000;

/// The program's module, the class's instance.
static INSTANCE: AtomicU32 = AtomicU32::new(0);

/// The level the next WM_CREATE is at.
static LEVEL: AtomicU32 = AtomicU32::new(0);

/// The calls nestshow makes, as user32 and kernel32 export them.
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
        pub fn CreateThread(
            attributes: usize,
            stack: usize,
            start: extern "system" fn(usize) -> u32,
            parameter: usize,
            flags: u32,
            id: *mut u32,
        ) -> usize;
        pub fn WaitForSingleObject(handle: usize, milliseconds: u32) -> u32;
        pub fn CloseHandle(handle: usize) -> i32;
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
        pub fn IsWindow(window: usize) -> i32;
        pub fn GetMessageA(msg: *mut Msg, window: usize, first: u32, last: u32) -> i32;
        pub fn DispatchMessageA(msg: *const Msg) -> isize;
        pub fn SendMessageA(window: usize, message: u32, wparam: usize, lparam: isize) -> isize;
        pub fn PostMessageA(window: usize, message: u32, wparam: usize, lparam: isize) -> i32;
        pub fn InSendMessage() -> i32;
        pub fn DefWindowProcA(window: usize, message: u32, wparam: usize, lparam: isize) -> isize;
        pub fn PostQuitMessage(code: i32);
    }
}

/// One line on the standard output.
fn say(line: core::fmt::Arguments<'_>) {
    let _ = exe::stdout().print(format_args!("{line}\r\n"));
}

/// The procedure: WM_CREATE makes the next level's window, a child of this one, until [`DEPTH`];
/// the other thread's WM_USER + 1 is answered 42, its WM_USER + 2 ends the loop.
extern "system" fn procedure(window: usize, message: u32, wparam: usize, lparam: isize) -> isize {
    match message {
        WM_CREATE => {
            let level = LEVEL.fetch_add(1, Ordering::Relaxed) + 1;
            say(format_args!("level {level}: WM_CREATE"));
            if level < DEPTH {
                // SAFETY: the class's name lives for the call; the parent is this window.
                let child = unsafe {
                    ffi::CreateWindowExA(
                        0,
                        CLASS.as_ptr(),
                        core::ptr::null(),
                        WS_CHILD | WS_VISIBLE,
                        1,
                        1,
                        100,
                        60,
                        window,
                        level as usize,
                        INSTANCE.load(Ordering::Relaxed) as usize,
                        0,
                    )
                };
                say(format_args!(
                    "level {level}: child made {}",
                    if child != 0 { "yes" } else { "no" }
                ));
            }
            0
        }
        m if m == WM_USER + 1 => {
            // SAFETY: no pointers.
            let sent = unsafe { ffi::InSendMessage() };
            say(format_args!(
                "WM_USER+1 wParam={wparam} InSendMessage={sent}"
            ));
            42
        }
        m if m == WM_USER + 2 => {
            // SAFETY: no pointers.
            unsafe { ffi::PostQuitMessage(0) };
            0
        }
        // SAFETY: the message as the procedure received it.
        _ => unsafe { ffi::DefWindowProcA(window, message, wparam, lparam) },
    }
}

/// The other thread: a message sent to the window, its answer printed, then the loop's end posted.
extern "system" fn sender(window: usize) -> u32 {
    // SAFETY: no pointers.
    let answer = unsafe { ffi::SendMessageA(window, WM_USER + 1, 7, 0) };
    say(format_args!("thread: SendMessage answered {answer}"));
    // SAFETY: no pointers.
    unsafe { ffi::PostMessageA(window, WM_USER + 2, 0, 0) };
    0
}

fn main() -> u32 {
    // SAFETY: the program's own module.
    let instance = unsafe { ffi::GetModuleHandleA(core::ptr::null()) };
    INSTANCE.store(instance as u32, Ordering::Relaxed);
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
    // SAFETY: the class's structure and name live for the calls.
    let window = unsafe {
        ffi::RegisterClassExA(&class);
        ffi::CreateWindowExA(
            0,
            CLASS.as_ptr(),
            c"nestshow".as_ptr().cast(),
            WS_POPUP,
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
    say(format_args!(
        "top window made {}, {} levels",
        if window != 0 { "yes" } else { "no" },
        LEVEL.load(Ordering::Relaxed)
    ));
    if window == 0 {
        return 1;
    }
    let mut id = 0;
    // SAFETY: the thread's routine and parameter; the id is this frame's.
    let thread = unsafe { ffi::CreateThread(0, 0, sender, window, 0, &mut id) };
    let mut msg = ffi::Msg::default();
    // SAFETY: the loop's own MSG.
    while unsafe { ffi::GetMessageA(&mut msg, 0, 0, 0) } > 0 {
        // SAFETY: as above.
        unsafe { ffi::DispatchMessageA(&msg) };
    }
    // SAFETY: the thread's handle and the program's own window.
    let gone = unsafe {
        ffi::WaitForSingleObject(thread, 0xFFFF_FFFF);
        ffi::CloseHandle(thread);
        ffi::DestroyWindow(window);
        ffi::IsWindow(window) == 0
    };
    say(format_args!(
        "destroyed {}",
        if gone { "yes" } else { "no" }
    ));
    0
}
