//! The message loop: GetMessage, PeekMessage, PostMessage, PostThreadMessage, PostQuitMessage,
//! SendMessage, InSendMessage, DispatchMessage, TranslateMessage, and the default window
//! procedure, DefWindowProc; each over its win32k service ([`imports`]).
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
//! user32 does; to another thread's window the kernel waits for that thread's answer. A message
//! reaches a procedure of the other form than its sender's translated ([`procedure`]): SendMessageA
//! and DispatchMessageA hand over narrow messages, SendMessageW and DispatchMessageW wide ones, the
//! window manager wide ones; another thread's message reaches the procedure as it was sent. The A
//! and W forms of the reads and the posts are the same calls: no posted message carries text.
//!
//! DefWindowProc keeps the window's text with the window manager, as Windows 2000's does: its
//! WM_NCCREATE sets the title the creation names, its WM_SETTEXT sets the text, and its WM_GETTEXT
//! and WM_GETTEXTLENGTH read it, through NtUserDefSetText and NtUserQueryWindow, in the form of the
//! DefWindowProc called.

use rtl::edge::{In, InStr, OutBuf};
use rtl::pod::Pod;
use rtl::status::{NtStatus, STATUS_INVALID_CID};
use rtl::user::*;
use rtl::window::{WindowText, QUERY_WINDOW_TEXT};

use crate::procedure::{self, Procedure};
use crate::{answered, failed_with, focus, imports, paint, window, Out};

/// The messages TranslateMessage looks at (winuser.h): the keys' and the system keys'.
const WM_KEYUP: u32 = 0x0101;
const WM_SYSKEYDOWN: u32 = 0x0104;
const WM_SYSKEYUP: u32 = 0x0105;
const WM_SYSCHAR: u32 = 0x0106;

/// ERROR_INVALID_THREAD_ID: PostThreadMessage to a thread there is none of.
pub const ERROR_INVALID_THREAD_ID: u32 = 1444;

/// The procedure `proc` a sent message's receipt names, called with its message (the window
/// manager's are wide: a narrow procedure's creation messages are translated); the answer handed
/// back to its sender. Both are copies: no reference to the receipt is held while the procedure
/// runs, which may write the structure its lParam points at in the receipt (WM_NCCREATE's
/// CREATESTRUCT).
fn deliver(proc: u32, msg: Msg) {
    let answer = if proc == 0 {
        default_procedure(
            msg.hwnd as usize,
            msg.message,
            msg.wparam,
            msg.lparam,
            false,
        )
    } else {
        let wide = matches!(msg.message, WM_NCCREATE | WM_CREATE);
        call(proc, wide.then_some(false), &msg)
    };
    let _ = imports::call_one_param(answer as u32, ONE_PARAM_END_SENT_MESSAGE);
}

/// The window procedure `proc` the kernel answered for `msg`'s window, called with the message:
/// translated from the form `from` (narrow when true) when the message is one that carries text
/// and the procedure takes the other form (its window's, read only then); as it is otherwise.
fn call(proc: u32, from: Option<bool>, msg: &Msg) -> i32 {
    let target = match from {
        Some(ansi) if procedure::translates(msg.message) => Procedure {
            address: proc,
            ansi: window::procedure_is_ansi(msg.hwnd as usize).unwrap_or(ansi),
        },
        _ => {
            return imports::call_procedure(proc, msg.hwnd, msg.message, msg.wparam, msg.lparam);
        }
    };
    procedure::call(
        target,
        from == Some(true),
        msg.hwnd,
        msg.message,
        msg.wparam,
        msg.lparam,
    )
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

/// GetMessageW: GetMessageA's (no message the queue holds carries text).
///
/// # Safety
///
/// The caller's MSG, as for the platform's.
#[unsafe(export_name = "f2k_export_GetMessageW")]
pub unsafe extern "system" fn get_message_w(
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
    peek_message(&mut msg, window, min, max, flags)
}

/// PeekMessageW: PeekMessageA's (no message the queue holds carries text).
///
/// # Safety
///
/// The caller's MSG, as for the platform's.
#[unsafe(export_name = "f2k_export_PeekMessageW")]
pub unsafe extern "system" fn peek_message_w(
    msg: *mut Msg,
    window: usize,
    min: u32,
    max: u32,
    flags: u32,
) -> u32 {
    // SAFETY: the caller's MSG.
    let mut msg = unsafe { Out::new(msg) };
    peek_message(&mut msg, window, min, max, flags)
}

/// PeekMessage's core.
fn peek_message(msg: &mut Out<'_, Msg>, window: usize, min: u32, max: u32, flags: u32) -> u32 {
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

/// PostMessageW: PostMessageA's.
#[unsafe(export_name = "f2k_export_PostMessageW")]
pub extern "system" fn post_message_w(
    window: usize,
    message: u32,
    wparam: u32,
    lparam: i32,
) -> u32 {
    post_message_a(window, message, wparam, lparam)
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

/// PostThreadMessageW: PostThreadMessageA's.
#[unsafe(export_name = "f2k_export_PostThreadMessageW")]
pub extern "system" fn post_thread_message_w(
    thread: u32,
    message: u32,
    wparam: u32,
    lparam: i32,
) -> u32 {
    post_thread_message_a(thread, message, wparam, lparam)
}

/// PostQuitMessage: WM_QUIT with the exit code left for the calling thread's next read (made when
/// the read finds nothing posted before it).
#[unsafe(export_name = "f2k_export_PostQuitMessage")]
pub extern "system" fn post_quit_message(code: i32) {
    let _ = imports::call_one_param(code as u32, ONE_PARAM_POST_QUIT_MESSAGE);
}

/// InSendMessage: whether the message the calling thread's procedure is handling was sent by
/// another thread (TRUE), rather than posted, or sent by the thread itself or by the window manager
/// on the thread's own call (FALSE); the last error untouched.
#[unsafe(export_name = "f2k_export_InSendMessage")]
pub extern "system" fn in_send_message() -> u32 {
    imports::call_one_param(0, ONE_PARAM_IN_SEND_MESSAGE).unwrap_or(0)
}

/// SendMessage's core, for a message of the narrow (`ansi`) or wide form: the window procedure's
/// answer (called here for a window of the calling thread, translated for a procedure of the
/// other form; the kernel's answer otherwise); none with 1400 for a handle naming no window.
pub fn send_as(window: usize, message: u32, wparam: u32, lparam: i32, ansi: bool) -> Option<i32> {
    let (proc, answer) = answered(imports::message_call(window, message, wparam, lparam))?;
    Some(if proc == 0 {
        answer
    } else {
        let msg = Msg {
            hwnd: window as u32,
            message,
            wparam,
            lparam,
            ..Msg::default()
        };
        call(proc, Some(ansi), &msg)
    })
}

/// SendMessageW's core: [`send_as`] for a wide message.
pub fn send(window: usize, message: u32, wparam: u32, lparam: i32) -> Option<i32> {
    send_as(window, message, wparam, lparam, false)
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
    send_as(window, message, wparam, lparam, true).unwrap_or(0)
}

/// SendMessageW: SendMessageA's, for a wide message.
#[unsafe(export_name = "f2k_export_SendMessageW")]
pub extern "system" fn send_message_w(
    window: usize,
    message: u32,
    wparam: u32,
    lparam: i32,
) -> i32 {
    send_as(window, message, wparam, lparam, false).unwrap_or(0)
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
    dispatch(&msg, true)
}

/// DispatchMessageW: DispatchMessageA's, for a wide message.
///
/// # Safety
///
/// The caller's MSG, as for the platform's.
#[unsafe(export_name = "f2k_export_DispatchMessageW")]
pub unsafe extern "system" fn dispatch_message_w(msg: *const Msg) -> i32 {
    // SAFETY: the caller's MSG.
    let msg = unsafe { In::new(msg) }.read();
    dispatch(&msg, false)
}

/// DispatchMessage's core, for a message of the narrow (`ansi`) or wide form.
fn dispatch(msg: &Msg, ansi: bool) -> i32 {
    match answered(imports::dispatch_target(msg)) {
        None | Some(0) => 0,
        Some(proc) if msg.message == WM_TIMER && msg.lparam != 0 => {
            imports::call_procedure(proc, msg.hwnd, WM_TIMER, msg.wparam, msg.time as i32)
        }
        Some(proc) => call(proc, Some(ansi), msg),
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

/// The default window procedure's answer to a message of the narrow (`ansi`) or wide form:
/// WM_NCCREATE the title the CREATESTRUCT names set, TRUE (the creation goes on); WM_SETTEXT the
/// text set, TRUE; WM_GETTEXT the text copied into the buffer (as much as fits with its
/// terminator; nothing into an empty one), the units or bytes copied; WM_GETTEXTLENGTH the text's
/// length; WM_CLOSE the window destroyed; WM_PAINT the window validated through BeginPaint and
/// EndPaint; WM_ACTIVATE the focus to a window being activated that is not minimized, as the
/// documentation gives it; WM_NCACTIVATE TRUE (the change goes on: there is no caption to redraw
/// yet); WM_ERASEBKGND TRUE (the background counts as erased: there is no fill to draw it with
/// yet); WM_QUERYENDSESSION TRUE (the session may end, as the message's documentation gives
/// DefWindowProc's answer), whatever its lParam; WM_NCCALCSIZE the rectangle left as it is (the
/// client area is the window's: windows have no decoration yet); 0 to everything else,
/// WM_ENDSESSION included, and to a text message for a handle naming no window.
pub fn default_procedure(window: usize, message: u32, wparam: u32, lparam: i32, ansi: bool) -> i32 {
    match message {
        WM_NCCREATE => {
            if lparam != 0 {
                // SAFETY: WM_NCCREATE's lParam as the window manager hands it over (or translated
                // for a narrow procedure): a CREATESTRUCT.
                let create = unsafe { In::new(lparam as usize as *const CreateStructW) }.read();
                // A resource id in the name's place (its high word zero) is no text.
                let name = if create.name >> 16 == 0 {
                    0
                } else {
                    create.name
                };
                let _ = set_text(window, name as i32, ansi);
            }
            1
        }
        WM_SETTEXT => set_text(window, lparam, ansi) as i32,
        WM_GETTEXT => get_text(window, wparam, lparam, ansi) as i32,
        WM_GETTEXTLENGTH => text_length(window, ansi) as i32,
        WM_ERASEBKGND | WM_QUERYENDSESSION | WM_NCACTIVATE => 1,
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

/// DefWindowProc's WM_SETTEXT: the window's text set to the string at `text` (the narrow form's
/// when `ansi`; 0: the empty text). Whether it was.
fn set_text(window: usize, text: i32, ansi: bool) -> bool {
    if !ansi || text == 0 {
        return imports::def_set_text(window, text as usize).is_ok();
    }
    // SAFETY: WM_SETTEXT's lParam (or a narrow CREATESTRUCT's name) as its sender hands it over: a
    // NUL-terminated string, narrow in this form.
    let text = unsafe { InStr::new(text as usize as *const u8) };
    crate::with_wide(text.bytes(), |units| {
        imports::def_set_text(window, units.as_ptr() as usize).is_ok()
    })
    .unwrap_or(false)
}

/// The window's text, as the window manager holds it: none for a handle naming no window.
pub fn window_text(window: usize) -> Option<WindowText> {
    let mut text = WindowText::default();
    imports::query_window(window, QUERY_WINDOW_TEXT, &mut text).ok()?;
    Some(text)
}

/// DefWindowProc's WM_GETTEXT: the window's text copied into the buffer of `max` units (bytes in
/// the narrow form) at `buffer`, cut to leave room for the terminator, terminated: the units (or
/// bytes) copied before it. An empty buffer is left as it is.
fn get_text(window: usize, max: u32, buffer: i32, ansi: bool) -> usize {
    if max == 0 || buffer == 0 {
        return 0;
    }
    let Some(text) = window_text(window) else {
        return 0;
    };
    let text = text.as_slice();
    if ansi {
        // SAFETY: WM_GETTEXT's lParam as its sender hands it over: a buffer of wParam bytes.
        let mut out = unsafe { OutBuf::new(buffer as usize as *mut u8, max as usize) };
        procedure::put_narrow(&mut out, text)
    } else {
        // SAFETY: WM_GETTEXT's lParam as its sender hands it over: a buffer of wParam units.
        let mut out = unsafe { OutBuf::new(buffer as usize as *mut u16, max as usize) };
        let length = text.len().min(max as usize - 1);
        out.put(&text[..length]);
        out.set(length, 0);
        length
    }
}

/// DefWindowProc's WM_GETTEXTLENGTH: the window's text's length in units (in bytes, the narrow
/// form's, when `ansi`).
fn text_length(window: usize, ansi: bool) -> usize {
    match window_text(window) {
        Some(text) if ansi => procedure::narrow_length(text.as_slice()),
        Some(text) => text.as_slice().len(),
        None => 0,
    }
}

/// DefWindowProcA: the default window procedure's answer to a narrow message.
#[unsafe(export_name = "f2k_export_DefWindowProcA")]
pub extern "system" fn def_window_proc_a(
    window: usize,
    message: u32,
    wparam: u32,
    lparam: i32,
) -> i32 {
    default_procedure(window, message, wparam, lparam, true)
}

/// DefWindowProcW: the default window procedure's answer to a wide message.
#[unsafe(export_name = "f2k_export_DefWindowProcW")]
pub extern "system" fn def_window_proc_w(
    window: usize,
    message: u32,
    wparam: u32,
    lparam: i32,
) -> i32 {
    default_procedure(window, message, wparam, lparam, false)
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

    /// The wide forms of the reads, the posts and DispatchMessage are the narrow forms' calls.
    ///
    /// Pins: user32.PostMessageW, user32.PostThreadMessageW, user32.PeekMessageW,
    /// user32.GetMessageW, user32.DispatchMessageW
    #[test]
    fn the_wide_forms_are_the_same_calls() {
        let window = window();
        assert_eq!(post_message_w(window, WM_USER + 4, 4, 5), 1);
        let me = THREAD_ID.with(|id| id.get());
        assert_eq!(post_thread_message_w(me, WM_USER + 8, 0, 0), 1);
        let mut msg = Msg::default();
        // SAFETY: the tests' own MSG.
        assert_eq!(unsafe { peek_message_w(&mut msg, 0, 0, 0, PM_REMOVE) }, 1);
        assert_eq!((msg.message, msg.wparam, msg.lparam), (WM_USER + 4, 4, 5));
        // SAFETY: as above.
        assert_eq!(unsafe { dispatch_message_w(&msg) }, 0);
        assert_eq!(seen(), [(window as u32, WM_USER + 4, 4, 5)]);
        // SAFETY: as above.
        assert_eq!(unsafe { get_message_w(&mut msg, 0, 0, 0) }, 1);
        assert_eq!((msg.hwnd, msg.message), (0, WM_USER + 8));
        // SAFETY: as above.
        assert_eq!(unsafe { peek_message_w(&mut msg, 0, 0, 0, PM_REMOVE) }, 0);
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
