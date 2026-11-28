//! menushow.exe: a top-level window with calc's styles (a caption, its system menu and minimize
//! box, a fixed frame) and calc's menu bar (Edit, View, Help) built with AppendMenuW, its size
//! from AdjustWindowRectEx, driven by the keyboard through the default window procedure's menu
//! loop. It prints a line once the window shows, one for each menu message its procedure
//! receives, one once a command has been taken and the window is painted again; closing the window
//! (Alt+F4) ends it (src/lib.rs lays the lines out).

#![no_std]
#![no_main]

use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use common::{TopLevel, Wide};
use exe::winuser::{COLOR_3DFACE, MF_BYCOMMAND, MF_POPUP, MF_SEPARATOR, MF_STRING, WM_COMMAND};
use menushow::*;

exe::entry!(main);

/// The calls menushow makes, as user32 exports them: its own.
mod ffi {
    #[link(name = "user32", kind = "raw-dylib", import_name_type = "undecorated")]
    unsafe extern "system" {
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
                        MF_BYCOMMAND,
                    );
                    ffi::DrawMenuBar(window);
                }
            }
            SETTLE.store(true, Ordering::Relaxed);
            0
        }
        _ => common::procedure(window, message, wparam, lparam),
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
            MF_BYCOMMAND,
        );
        bar
    }
}

fn main() -> u32 {
    let bar = build_menu();
    BAR.store(bar, Ordering::Relaxed);
    let made = TopLevel {
        class: "MenuShow",
        title: "Calculator",
        procedure,
        background: COLOR_3DFACE + 1,
        style: STYLE,
        client: (260, 200),
        menu: bar,
    }
    .create();
    let Some(window) = made else {
        let _ = exe::stderr().print(format_args!("menushow: the window cannot be made\r\n"));
        return NO_WINDOW;
    };
    window.to_foreground();
    let mut ready = false;
    common::pump(|| {
        if !ready {
            ready = true;
            let _ = exe::stdout().print(format_args!("{READY}\r\n"));
        }
        if SETTLE.swap(false, Ordering::Relaxed) {
            let _ = exe::stdout().print(format_args!("{SETTLED}\r\n"));
        }
        false
    });
    0
}
