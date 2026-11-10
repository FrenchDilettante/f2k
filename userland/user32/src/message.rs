//! The message loop: GetMessage, PeekMessage, PostMessage, PostThreadMessage, PostQuitMessage,
//! SendMessage, DispatchMessage, TranslateMessage, and the default window procedure,
//! DefWindowProc; each over its win32k service ([`imports`]).
//!
//! The kernel calls no user-mode code: a message sent to one of the calling thread's windows (by
//! another thread, or by the window manager while it decides) reaches its procedure through the
//! thread's own reads. win32k's GetMessage and PeekMessage services answer a receipt
//! (rtl::user::Receipt): a posted message, WM_QUIT, or a sent message with the procedure to call,
//! whose answer goes back through NtUserCallOneParam's ONE_PARAM_END_SENT_MESSAGE. GetMessage and
//! PeekMessage deliver the sent messages they find and read on, as Windows 2000's do; the calls
//! that make the window manager send (CreateWindowEx, DestroyWindow, ShowWindow...) receive them
//! as soon as their service returns ([`receive_sent`]).
//!
//! SendMessage to a window of the calling thread calls its procedure here, as Windows 2000's
//! user32 does; to another thread's window the kernel waits for that thread's answer. Messages are
//! not translated between their narrow and wide forms: the A and W calls are the same call.

use rtl::edge::In;
use rtl::pod::Pod;
use rtl::status::{NtStatus, STATUS_INVALID_CID};
use rtl::user::*;

use crate::imports;
use crate::{answered, failed_with, focus, paint, window, Out};

/// The messages TranslateMessage looks at (winuser.h): the keys' and the system keys'.
const WM_KEYUP: u32 = 0x0101;
const WM_SYSKEYDOWN: u32 = 0x0104;
const WM_SYSKEYUP: u32 = 0x0105;
const WM_SYSCHAR: u32 = 0x0106;

/// ERROR_INVALID_THREAD_ID: PostThreadMessage to a thread there is none of.
pub const ERROR_INVALID_THREAD_ID: u32 = 1444;

/// The procedure `proc` a sent message's receipt names, called with its message; the answer
/// handed back to its sender. Both are copies: no reference to the receipt is held while the
/// procedure runs, which may write the structure its lParam points at in the receipt
/// (WM_NCCREATE's CREATESTRUCT).
fn deliver(proc: u32, msg: Msg) {
    let answer = if proc == 0 {
        default_procedure(msg.hwnd as usize, msg.message, msg.wparam, msg.lparam)
    } else {
        imports::call_procedure(proc, msg.hwnd, msg.message, msg.wparam, msg.lparam)
    };
    let _ = imports::call_one_param(answer as u32, ONE_PARAM_END_SENT_MESSAGE);
}

/// Receive the messages sent to the calling thread's windows: each delivered to its procedure, in
/// the order they were sent, until none is left.
pub fn receive_sent() {
    let mut receipt = Receipt::zeroed();
    while imports::peek_message(&mut receipt, 0, 0, 0, PM_REMOVE | PM_QS_SENDMESSAGE).is_ok()
        && receipt.kind == RECEIVED_SENT
    {
        deliver(receipt.proc, receipt.msg);
    }
}

/// GetMessageA: the next message the filter takes, waiting for one, into the caller's MSG (the
/// sent messages it finds first delivered); FALSE for WM_QUIT, TRUE for any other, -1 with the
/// last error for a failure (1400 for a filter window there is none of).
///
/// # Safety
///
/// The caller's MSG, as for the platform's.
#[unsafe(export_name = "f2k_export_GetMessageA")]
pub unsafe extern "system" fn get_message_a(
    msg: *mut Msg,
    window: usize,
    min: u32,
    max: u32,
) -> i32 {
    // SAFETY: the caller's MSG.
    let mut msg = unsafe { Out::new(msg) };
    get_message(&mut msg, window, min, max)
}

/// GetMessage's core.
fn get_message(out: &mut Out<'_, Msg>, window: usize, min: u32, max: u32) -> i32 {
    let mut receipt = Receipt::zeroed();
    loop {
        if answered(imports::get_message(&mut receipt, window, min, max)).is_none() {
            return -1;
        }
        match receipt.kind {
            RECEIVED_SENT => deliver(receipt.proc, receipt.msg),
            kind => {
                out.set(receipt.msg);
                return (kind != RECEIVED_QUIT) as i32;
            }
        }
    }
}

/// PeekMessageA: the next message the filter and the PM_ flags take, without waiting, into the
/// caller's MSG (removed with PM_REMOVE; the sent messages found first delivered); TRUE when there
/// was one, FALSE when there was none (the MSG untouched) or for a failure, with the last error.
///
/// # Safety
///
/// The caller's MSG, as for the platform's.
#[unsafe(export_name = "f2k_export_PeekMessageA")]
pub unsafe extern "system" fn peek_message_a(
    msg: *mut Msg,
    window: usize,
    min: u32,
    max: u32,
    flags: u32,
) -> u32 {
    // SAFETY: the caller's MSG.
    let mut msg = unsafe { Out::new(msg) };
    let mut receipt = Receipt::zeroed();
    loop {
        if answered(imports::peek_message(&mut receipt, window, min, max, flags)).is_none() {
            return 0;
        }
        match receipt.kind {
            RECEIVED_SENT => deliver(receipt.proc, receipt.msg),
            RECEIVED_NONE => return 0,
            _ => {
                msg.set(receipt.msg);
                return 1;
            }
        }
    }
}

/// PostMessageA: the message posted to the window's thread (a null window: the calling thread;
/// HWND_BROADCAST: every top-level window); TRUE, or FALSE with 1400 for a handle naming no window.
#[unsafe(export_name = "f2k_export_PostMessageA")]
pub extern "system" fn post_message_a(
    window: usize,
    message: u32,
    wparam: u32,
    lparam: i32,
) -> u32 {
    answered(imports::post_message(window, message, wparam, lparam)).is_some() as u32
}

/// PostThreadMessageA: a thread message posted to the thread whose id is `thread`; TRUE, or FALSE
/// with ERROR_INVALID_THREAD_ID for an id no thread with a queue has.
#[unsafe(export_name = "f2k_export_PostThreadMessageA")]
pub extern "system" fn post_thread_message_a(
    thread: u32,
    message: u32,
    wparam: u32,
    lparam: i32,
) -> u32 {
    let error = |status: NtStatus| match status.0 {
        STATUS_INVALID_CID => ERROR_INVALID_THREAD_ID,
        _ => imports::dos_error(status),
    };
    failed_with(
        imports::post_thread_message(thread, message, wparam, lparam),
        error,
    )
    .is_some() as u32
}

/// PostQuitMessage: WM_QUIT with the exit code left for the calling thread's next read (made when
/// the read finds nothing posted before it).
#[unsafe(export_name = "f2k_export_PostQuitMessage")]
pub extern "system" fn post_quit_message(code: i32) {
    let _ = imports::call_one_param(code as u32, ONE_PARAM_POST_QUIT_MESSAGE);
}

/// SendMessage's core: the window procedure's answer (called here for a window of the calling
/// thread, the kernel's answer otherwise); none with 1400 for a handle naming no window.
pub fn send(window: usize, message: u32, wparam: u32, lparam: i32) -> Option<i32> {
    let (proc, answer) = answered(imports::message_call(window, message, wparam, lparam))?;
    Some(if proc == 0 {
        answer
    } else {
        imports::call_procedure(proc, window as u32, message, wparam, lparam)
    })
}

/// SendMessageA: the message sent to the window, its procedure's answer; 0 with the last error for
/// a failure.
#[unsafe(export_name = "f2k_export_SendMessageA")]
pub extern "system" fn send_message_a(
    window: usize,
    message: u32,
    wparam: u32,
    lparam: i32,
) -> i32 {
    send(window, message, wparam, lparam).unwrap_or(0)
}

/// SendMessageW: SendMessageA's.
#[unsafe(export_name = "f2k_export_SendMessageW")]
pub extern "system" fn send_message_w(
    window: usize,
    message: u32,
    wparam: u32,
    lparam: i32,
) -> i32 {
    send(window, message, wparam, lparam).unwrap_or(0)
}

/// DispatchMessageA: the message handed to its window's procedure (WM_TIMER with a TimerProc to
/// the TimerProc, called with the message's time); the procedure's answer, 0 for a thread message,
/// 0 with 1400 for a window there is none of.
///
/// # Safety
///
/// The caller's MSG, as for the platform's.
#[unsafe(export_name = "f2k_export_DispatchMessageA")]
pub unsafe extern "system" fn dispatch_message_a(msg: *const Msg) -> i32 {
    // SAFETY: the caller's MSG.
    let msg = unsafe { In::new(msg) }.read();
    dispatch(&msg)
}

/// DispatchMessage's core.
fn dispatch(msg: &Msg) -> i32 {
    match answered(imports::dispatch_target(msg)) {
        None | Some(0) => 0,
        Some(proc) if msg.message == WM_TIMER && msg.lparam != 0 => {
            imports::call_procedure(proc, msg.hwnd, WM_TIMER, msg.wparam, msg.time as i32)
        }
        Some(proc) => imports::call_procedure(proc, msg.hwnd, msg.message, msg.wparam, msg.lparam),
    }
}

/// The character a key's virtual-key code makes whatever the shift state: the digits, the letters
/// (lower case: there is no shift state to read), space, Return, Backspace, Tab and Escape.
fn key_character(key: u32) -> Option<u32> {
    match key {
        0x30..=0x39 | 0x20 | 0x0D | 0x08 | 0x09 | 0x1B => Some(key),
        0x41..=0x5A => Some(key + 0x20),
        _ => None,
    }
}

/// TranslateMessage: a key-down message's character posted to the calling thread (WM_CHAR,
/// WM_SYSCHAR for a system key) where the key makes one; nonzero for every key message, 0 for
/// another.
///
/// # Safety
///
/// The caller's MSG, as for the platform's.
#[unsafe(export_name = "f2k_export_TranslateMessage")]
pub unsafe extern "system" fn translate_message(msg: *const Msg) -> u32 {
    // SAFETY: the caller's MSG.
    let msg = unsafe { In::new(msg) }.read();
    translate(&msg)
}

/// TranslateMessage's core.
fn translate(msg: &Msg) -> u32 {
    let character = match msg.message {
        WM_KEYDOWN => WM_CHAR,
        WM_SYSKEYDOWN => WM_SYSCHAR,
        WM_KEYUP | WM_SYSKEYUP => return 1,
        _ => return 0,
    };
    if let Some(value) = key_character(msg.wparam) {
        let _ = imports::post_message(msg.hwnd as usize, character, value, msg.lparam);
    }
    1
}

/// The default window procedure's answer to a message: WM_NCCREATE TRUE (the creation goes on);
/// WM_CLOSE the window destroyed; WM_PAINT the window validated through BeginPaint and EndPaint;
/// WM_ACTIVATE the focus to a window being activated that is not minimized, as the documentation
/// gives it; WM_NCACTIVATE TRUE (the change goes on: there is no caption to redraw yet);
/// WM_ERASEBKGND TRUE (the background counts as erased: there is no fill to draw it with yet);
/// WM_QUERYENDSESSION TRUE (the session may end, as the message's documentation gives
/// DefWindowProc's answer), whatever its lParam; WM_NCCALCSIZE the rectangle left as it is (the
/// client area is the window's: windows have no decoration yet); 0 to everything else,
/// WM_ENDSESSION included.
pub fn default_procedure(window: usize, message: u32, wparam: u32, _lparam: i32) -> i32 {
    match message {
        WM_NCCREATE | WM_ERASEBKGND | WM_QUERYENDSESSION | WM_NCACTIVATE => 1,
        WM_ACTIVATE => {
            if wparam & 0xFFFF != WA_INACTIVE && wparam >> 16 == 0 {
                focus::activate_focus(window);
            }
            0
        }
        WM_CLOSE => {
            window::destroy_window(window);
            0
        }
        WM_PAINT => {
            paint::validate_by_painting(window);
            0
        }
        _ => 0,
    }
}

/// DefWindowProcA: the default window procedure's answer.
#[unsafe(export_name = "f2k_export_DefWindowProcA")]
pub extern "system" fn def_window_proc_a(
    window: usize,
    message: u32,
    wparam: u32,
    lparam: i32,
) -> i32 {
    default_procedure(window, message, wparam, lparam)
}

/// DefWindowProcW: DefWindowProcA's.
#[unsafe(export_name = "f2k_export_DefWindowProcW")]
pub extern "system" fn def_window_proc_w(
    window: usize,
    message: u32,
    wparam: u32,
    lparam: i32,
) -> i32 {
    default_procedure(window, message, wparam, lparam)
}

#[cfg(test)]
mod tests {
    use core::cell::RefCell;

    use super::*;
    use crate::class::{register_class_a, WndClass};
    use crate::imports::host::{procedure, wm, LAST_ERROR, THREAD_ID};
    use crate::window::{create_window_ex_a, is_window};

    const UNSET: u32 = 0xF2F2_F2F2;

    std::thread_local! {
        static SEEN: RefCell<std::vec::Vec<(u32, u32, u32, i32)>> = const { RefCell::new(std::vec::Vec::new()) };
    }

    fn recorder(window: u32, message: u32, wparam: u32, lparam: i32) -> i32 {
        SEEN.with(|seen| seen.borrow_mut().push((window, message, wparam, lparam)));
        def_window_proc_a(window as usize, message, wparam, lparam)
    }

    fn seen() -> std::vec::Vec<(u32, u32, u32, i32)> {
        SEEN.with(|seen| seen.take())
    }

    fn last_error() -> u32 {
        LAST_ERROR.with(|error| error.get())
    }

    fn arm() {
        LAST_ERROR.with(|error| error.set(UNSET));
    }

    /// A window of a class of the recorder, its creation's messages seen and forgotten.
    fn window() -> usize {
        let class = WndClass {
            wnd_proc: procedure(recorder) as usize,
            class_name: c"F2KGuimsg".as_ptr() as usize,
            ..WndClass::default()
        };
        // SAFETY: a WNDCLASSA of the tests' own, and its name.
        let window = unsafe {
            register_class_a(&class);
            create_window_ex_a(
                0,
                c"F2KGuimsg".as_ptr().cast(),
                c"guimsg".as_ptr().cast(),
                0x8000_0000,
                0,
                0,
                320,
                200,
                0,
                0,
                0,
                0,
            )
        };
        assert_ne!(window, 0);
        seen();
        window
    }

    fn peek(flags: u32) -> (u32, Msg) {
        let mut msg = Msg::default();
        // SAFETY: the tests' own MSG.
        let answer = unsafe { peek_message_a(&mut msg, 0, 0, 0, flags) };
        (answer, msg)
    }

    /// A posted message comes back through GetMessage with its window and parameters; PeekMessage
    /// leaves it with PM_NOREMOVE and takes it with PM_REMOVE, in the order posted; an empty queue
    /// is FALSE with the last error untouched.
    ///
    /// Pins: user32.PostMessageA, user32.GetMessageA, user32.PeekMessageA
    #[test]
    fn posted_messages_come_back_in_order() {
        let window = window();
        arm();
        assert_eq!(post_message_a(window, WM_USER + 1, 11, 22), 1);
        assert_eq!(post_message_a(window, WM_USER + 2, 2, 0), 1);
        let (answer, msg) = peek(PM_NOREMOVE);
        assert_eq!((answer, msg.message, msg.wparam), (1, WM_USER + 1, 11));
        let (_, msg) = peek(PM_REMOVE);
        assert_eq!(msg.message, WM_USER + 1);
        let mut msg = Msg::default();
        // SAFETY: the tests' own MSG.
        assert_eq!(unsafe { get_message_a(&mut msg, 0, 0, 0) }, 1);
        assert_eq!(
            (msg.hwnd as usize, msg.message, msg.wparam),
            (window, WM_USER + 2, 2)
        );
        assert_eq!(peek(PM_REMOVE).0, 0);
        assert_eq!(last_error(), UNSET);
        assert_eq!(post_message_a(0x7FFF_FFFC, WM_USER, 0, 0), 0);
        assert_eq!(last_error(), 1400);
    }

    /// PostQuitMessage: GetMessage answers FALSE with WM_QUIT and the exit code.
    ///
    /// Pins: user32.PostQuitMessage, user32.GetMessageA
    #[test]
    fn the_quit_message_ends_the_loop() {
        post_quit_message(7);
        let mut msg = Msg::default();
        // SAFETY: the tests' own MSG.
        assert_eq!(unsafe { get_message_a(&mut msg, 0, 0, 0) }, 0);
        assert_eq!((msg.message, msg.wparam), (WM_QUIT, 7));
    }

    /// A sent message met by a read is delivered first, its answer handed back, and the read goes
    /// on to the posted message.
    ///
    /// Pins: user32.GetMessageA
    #[test]
    fn reads_deliver_sent_messages_first() {
        let window = window();
        post_message_a(window, WM_USER + 3, 0, 0);
        wm(|wm| {
            wm.sent.push_back(crate::imports::host::HostSent {
                hwnd: window as u32,
                message: WM_USER + 9,
                wparam: 1,
                lparam: 2,
                proc: wm.windows.last().unwrap().proc,
                create: None,
            })
        });
        let mut msg = Msg::default();
        // SAFETY: the tests' own MSG.
        assert_eq!(unsafe { get_message_a(&mut msg, 0, 0, 0) }, 1);
        assert_eq!(msg.message, WM_USER + 3);
        assert_eq!(seen(), [(window as u32, WM_USER + 9, 1, 2)]);
        assert_eq!(wm(|wm| wm.answers.last().copied()), Some((WM_USER + 9, 0)));
    }

    /// TranslateMessage answers 0 for another message and posts nothing; DispatchMessage hands the
    /// message to the window's procedure, a thread message to none.
    ///
    /// Pins: user32.TranslateMessage, user32.DispatchMessageA
    #[test]
    fn dispatch_calls_the_procedure() {
        let window = window();
        let msg = Msg {
            hwnd: window as u32,
            message: WM_USER + 5,
            wparam: 33,
            lparam: 44,
            ..Msg::default()
        };
        // SAFETY: the tests' own MSG.
        unsafe {
            assert_eq!(translate_message(&msg), 0);
            assert_eq!(dispatch_message_a(&msg), 0);
        }
        assert_eq!(seen(), [(window as u32, WM_USER + 5, 33, 44)]);
        let thread = Msg {
            message: WM_USER,
            ..Msg::default()
        };
        // SAFETY: as above.
        assert_eq!(unsafe { dispatch_message_a(&thread) }, 0);
        assert!(seen().is_empty());
        let key = Msg {
            hwnd: window as u32,
            message: WM_KEYDOWN,
            wparam: 0x41,
            ..Msg::default()
        };
        // SAFETY: as above.
        assert_eq!(unsafe { translate_message(&key) }, 1);
        let (_, char_msg) = peek(PM_REMOVE);
        assert_eq!((char_msg.message, char_msg.wparam), (WM_CHAR, 0x61));
    }

    /// SendMessage calls the procedure of a window of the calling thread; a dead window is 1400.
    ///
    /// Pins: user32.SendMessageA, user32.SendMessageW
    #[test]
    fn send_calls_the_procedure_at_once() {
        let window = window();
        assert_eq!(send_message_a(window, WM_USER + 6, 55, 66), 0);
        assert_eq!(send_message_w(window, WM_USER + 6, 55, 66), 0);
        assert_eq!(
            seen(),
            [
                (window as u32, WM_USER + 6, 55, 66),
                (window as u32, WM_USER + 6, 55, 66)
            ]
        );
        arm();
        assert_eq!(send_message_w(0x7FFF_FFFC, WM_USER, 0, 0), 0);
        assert_eq!(last_error(), 1400);
    }

    /// DefWindowProc: WM_CLOSE destroys the window (its procedure sees the destruction), WM_NULL
    /// and the rest answer 0, WM_ENDSESSION among them; WM_NCCREATE, WM_ERASEBKGND and
    /// WM_QUERYENDSESSION TRUE, a logoff's WM_QUERYENDSESSION too.
    ///
    /// Pins: user32.DefWindowProcA, user32.DefWindowProcW
    #[test]
    fn the_default_procedure() {
        let window = window();
        assert_eq!(def_window_proc_a(window, WM_CLOSE, 0, 0), 0);
        let messages: std::vec::Vec<u32> = seen().iter().map(|seen| seen.1).collect();
        assert_eq!(messages, [WM_DESTROY, WM_NCDESTROY]);
        assert_eq!(is_window(window), 0);
        assert_eq!(def_window_proc_w(window, WM_NULL, 0, 0), 0);
        assert_eq!(def_window_proc_w(window, WM_NCCREATE, 0, 0), 1);
        assert_eq!(def_window_proc_w(window, WM_ERASEBKGND, 0, 0), 1);
        assert_eq!(def_window_proc_a(window, WM_QUERYENDSESSION, 0, 0), 1);
        let logoff = ENDSESSION_LOGOFF as i32;
        assert_eq!(def_window_proc_w(window, WM_QUERYENDSESSION, 0, logoff), 1);
        assert_eq!(def_window_proc_a(window, WM_ENDSESSION, 1, 0), 0);
        assert_eq!(def_window_proc_w(window, WM_ENDSESSION, 0, logoff), 0);
        assert!(seen().is_empty());
    }

    /// PostThreadMessage to the calling thread is a thread message; another id is 1444.
    ///
    /// Pins: user32.PostThreadMessageA
    #[test]
    fn thread_messages() {
        let me = THREAD_ID.with(|id| id.get());
        assert_eq!(post_thread_message_a(me, WM_USER + 7, 1, 2), 1);
        let mut msg = Msg::default();
        // SAFETY: the tests' own MSG.
        assert_eq!(unsafe { get_message_a(&mut msg, 0, 0, 0) }, 1);
        assert_eq!(
            (msg.hwnd, msg.message, msg.wparam, msg.lparam),
            (0, WM_USER + 7, 1, 2)
        );
        assert_eq!(post_thread_message_a(me + 4, WM_USER, 0, 0), 0);
        assert_eq!(last_error(), ERROR_INVALID_THREAD_ID);
    }
}
