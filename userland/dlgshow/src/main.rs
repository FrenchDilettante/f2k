//! dlgshow.exe: a dialog of user32's dialog manager, made from a template in memory
//! (CreateDialogIndirectParamW) and driven by the keyboard through its own message loop and
//! IsDialogMessageW. It prints a line once the dialog shows, one for each key-down the dialog
//! takes (the key and the focus after it), one for each command its procedure receives, and its
//! end (src/lib.rs lays the lines out); OK and Cancel end it.

#![no_std]
#![no_main]

use dlgshow::*;

exe::entry!(main);

/// The calls dlgshow makes, as user32 and kernel32 export them.
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

    /// PeekMessage's flag leaving the message in the queue.
    pub const PM_NOREMOVE: u32 = 0;

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
        pub fn CreateDialogIndirectParamW(
            instance: usize,
            template: *const u16,
            owner: usize,
            proc: extern "system" fn(usize, u32, usize, isize) -> isize,
            param: isize,
        ) -> usize;
        pub fn IsDialogMessageW(dialog: usize, msg: *const Msg) -> i32;
        pub fn GetMessageW(msg: *mut Msg, window: usize, first: u32, last: u32) -> i32;
        pub fn PeekMessageW(msg: *mut Msg, window: usize, first: u32, last: u32, flags: u32)
            -> i32;
        pub fn TranslateMessage(msg: *const Msg) -> i32;
        pub fn DispatchMessageW(msg: *const Msg) -> isize;
        pub fn DestroyWindow(window: usize) -> i32;
        pub fn SetForegroundWindow(window: usize) -> i32;
        pub fn GetFocus() -> usize;
        pub fn GetDlgCtrlID(window: usize) -> i32;
        pub fn CheckRadioButton(dialog: usize, first: i32, last: i32, check: i32) -> i32;
        pub fn IsDlgButtonChecked(dialog: usize, id: i32) -> u32;
        pub fn PostQuitMessage(code: i32);
    }
}

/// The control with the focus.
fn focus() -> Focus {
    // SAFETY: no pointers.
    let window = unsafe { ffi::GetFocus() };
    // SAFETY: no pointers.
    Focus((window != 0).then(|| unsafe { ffi::GetDlgCtrlID(window) }))
}

/// The dialog's procedure: Standard checked at WM_INITDIALOG (the focus to the first tab stop,
/// OK); each command printed; OK and Cancel print the end and end the loop (the window is
/// destroyed after it).
extern "system" fn procedure(dialog: usize, message: u32, wparam: usize, _lparam: isize) -> isize {
    match message {
        WM_INITDIALOG => {
            // SAFETY: the dialog the procedure serves.
            unsafe {
                ffi::CheckRadioButton(
                    dialog,
                    ID_STANDARD.into(),
                    ID_SCIENTIFIC.into(),
                    ID_STANDARD.into(),
                )
            };
            1
        }
        WM_COMMAND => {
            let (id, code) = (wparam as u32 & 0xFFFF, wparam as u32 >> 16);
            let _ = exe::stdout().print(format_args!("{}\r\n", CommandLine { id, code }));
            if id == u32::from(ID_OK) || id == u32::from(ID_CANCEL) {
                // SAFETY: the dialog the procedure serves.
                let (keep, scientific) = unsafe {
                    (
                        ffi::IsDlgButtonChecked(dialog, ID_KEEP.into()),
                        ffi::IsDlgButtonChecked(dialog, ID_SCIENTIFIC.into()),
                    )
                };
                let end = EndLine {
                    ok: id == u32::from(ID_OK),
                    keep,
                    scientific,
                };
                let _ = exe::stdout().print(format_args!("{end}\r\n"));
                // SAFETY: no pointers.
                unsafe { ffi::PostQuitMessage(0) };
            }
            1
        }
        WM_CLOSE => {
            // SAFETY: no pointers.
            unsafe { ffi::PostQuitMessage(0) };
            1
        }
        _ => 0,
    }
}

/// The template's words, DWORD-aligned as a template must be.
#[repr(C, align(4))]
struct Template([u16; 512]);

fn main() -> u32 {
    let mut words = Template([0; 512]);
    if template(&mut words.0).is_none() {
        return NO_DIALOG;
    }
    // SAFETY: the program's own module; the template lives for the call.
    let dialog = unsafe {
        let instance = ffi::GetModuleHandleA(core::ptr::null());
        ffi::CreateDialogIndirectParamW(instance, words.0.as_ptr(), 0, procedure, 0)
    };
    if dialog == 0 {
        let _ = exe::stderr().print(format_args!("dlgshow: the dialog cannot be made\r\n"));
        return NO_DIALOG;
    }
    // SAFETY: the program's own window.
    unsafe { ffi::SetForegroundWindow(dialog) };
    let mut ready = false;
    let mut msg = ffi::Msg::default();
    loop {
        // SAFETY: the loop's own MSG.
        if !ready && unsafe { ffi::PeekMessageW(&mut msg, 0, 0, 0, ffi::PM_NOREMOVE) } == 0 {
            ready = true;
            let _ = exe::stdout().print(format_args!("{READY}, {}\r\n", focus()));
        }
        // SAFETY: as above.
        if unsafe { ffi::GetMessageW(&mut msg, 0, 0, 0) } <= 0 {
            break;
        }
        // SAFETY: as above.
        if unsafe { ffi::IsDialogMessageW(dialog, &msg) } == 0 {
            // SAFETY: as above.
            unsafe {
                ffi::TranslateMessage(&msg);
                ffi::DispatchMessageW(&msg);
            }
        } else if msg.message == WM_KEYDOWN {
            let line = KeyLine {
                key: msg.wparam as u32,
                focus: focus(),
            };
            let _ = exe::stdout().print(format_args!("{line}\r\n"));
        }
    }
    // SAFETY: the program's own window.
    unsafe { ffi::DestroyWindow(dialog) };
    0
}
