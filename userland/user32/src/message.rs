//! The message loop: GetMessage, PeekMessage, PostMessage, PostThreadMessage, PostQuitMessage,
//! SendMessage, SendMessageTimeout, SendNotifyMessage, InSendMessage, DispatchMessage,
//! TranslateMessage, WaitMessage, MsgWaitForMultipleObjects, GetMessageTime and GetMessagePos,
//! IsHungAppWindow,
//! RegisterWindowMessage, and the default window procedure, DefWindowProc; each over its win32k
//! service ([`imports`]).
//!
//! A message the window manager sends to one of the calling thread's windows while it decides
//! (CreateWindowEx's, DestroyWindow's, ShowWindow's...) reaches its procedure by a callback from
//! inside the service, as on Windows 2000 ([`crate::callback`]), and its answer goes back to the
//! decision. So does a message another thread sends, from inside the receiving thread's own calls:
//! win32k's GetMessage and PeekMessage services deliver the sent messages they find by callback,
//! then answer a receipt (rtl::user::Receipt: a posted message, WM_QUIT, or none), as Windows
//! 2000's xxxReceiveMessage delivers them; so do WaitMessage and a thread's wait for another
//! thread's answer.
//!
//! SendMessage to a window of the calling thread calls its procedure here, as Windows 2000's
//! user32 does; to another thread's window the kernel waits for that thread's answer, delivering
//! the messages sent to the waiting thread meanwhile by callback, so two threads sending to each
//! other do not deadlock. A message
//! reaches a procedure of the other form than its sender's translated ([`procedure`]): SendMessageA
//! and DispatchMessageA hand over narrow messages, SendMessageW and DispatchMessageW wide ones, the
//! window manager wide ones; another thread's message reaches the procedure as it was sent. The A
//! and W forms of the reads and the posts are the same calls: no posted message carries text (a
//! post of a message whose lParam points at a text or a structure fails, ERROR_MESSAGE_SYNC_ONLY).
//! WM_COPYDATA sent to another process's window carries its data through the window manager, as
//! WM_SETTEXT's text does: the receiver's procedure reads its own copy.
//! SendMessageTimeout and SendNotifyMessage call a window of the calling thread here too; another
//! thread's answer the first waits no longer than its timeout for, the second not at all.
//!
//! DefWindowProc keeps the window's text with the window manager, as Windows 2000's does: its
//! WM_NCCREATE sets the title the creation names, its WM_SETTEXT sets the text, and its WM_GETTEXT
//! and WM_GETTEXTLENGTH read it, through NtUserDefSetText and NtUserQueryWindow, in the form of the
//! DefWindowProc called.

use core::sync::atomic::{AtomicU32, Ordering};

use rtl::display::{COLOR_3DFACE, COLOR_SCROLLBAR, COLOR_WINDOW, COLOR_WINDOWTEXT};
use rtl::edge::{In, InStr, OutBuf};
use rtl::status::NtStatus;
use rtl::user::*;
use rtl::window::{
    SWP_NOCLIENTMOVE,
    SWP_NOCLIENTSIZE,
    SW_MINIMIZE,
    SW_RESTORE,
    SW_SHOWMAXIMIZED,
    WINDOW_OTHER_PROCESS,
};

use crate::procedure::{self, Procedure};
use crate::records::Table;
use crate::{
    answered,
    failed,
    failed_with,
    focus,
    imports,
    menubar,
    mouse,
    nonclient,
    paint,
    window,
    window_error,
    Out,
};

/// The procedure `proc` a sent message names (a callback's), called with its
/// message (the window manager's are wide: a narrow procedure's creation messages are translated,
/// and a text another process's message carries, `carried_text`); its answer. `msg` is a copy: no
/// reference to where it came from is held while the procedure runs, which may write the structure
/// its lParam points at (WM_NCCREATE's CREATESTRUCT).
pub fn invoke(proc: u32, msg: Msg, carried_text: bool) -> i32 {
    if proc == 0 {
        default_procedure(
            msg.hwnd as usize,
            msg.message,
            msg.wparam,
            msg.lparam,
            false,
        )
    } else {
        // The window manager's own messages, a text another process's message carries, and a
        // character another thread sent (a narrow sender's converted on the way in) are wide.
        let wide = matches!(msg.message, WM_NCCREATE | WM_CREATE)
            || carried_text
            || procedure::char_message(msg.message);
        call(proc, wide.then_some(false), &msg)
    }
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
    get_message(&mut msg, window, min, max, true)
}

/// GetMessageW: GetMessageA's, the character messages' character as the queue holds it (no
/// message the queue holds carries text).
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
    get_message(&mut msg, window, min, max, false)
}

/// A message read out of the queue for a caller of the narrow (`ansi`) or wide form: the queue's
/// character messages are wide, a narrow caller's converted ([`procedure::char_to_narrow`]).
fn read_as(msg: Msg, ansi: bool) -> Msg {
    if !ansi {
        return msg;
    }
    Msg {
        wparam: procedure::char_to_narrow(msg.message, msg.wparam),
        ..msg
    }
}

/// GetMessage's core, for a caller of the narrow (`ansi`) or wide form.
fn get_message(out: &mut Out<'_, Msg>, window: usize, min: u32, max: u32, ansi: bool) -> i32 {
    let mut receipt = Receipt::default();
    if answered(imports::get_message(&mut receipt, window, min, max)).is_none() {
        return -1;
    }
    out.set(read_as(receipt.msg, ansi));
    (receipt.kind != RECEIVED_QUIT) as i32
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
    peek_message(&mut msg, window, min, max, flags, true)
}

/// PeekMessageW: PeekMessageA's, the character messages' character as the queue holds it (no
/// message the queue holds carries text).
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
    peek_message(&mut msg, window, min, max, flags, false)
}

/// PeekMessage's core, for a caller of the narrow (`ansi`) or wide form.
fn peek_message(
    msg: &mut Out<'_, Msg>,
    window: usize,
    min: u32,
    max: u32,
    flags: u32,
    ansi: bool,
) -> u32 {
    let mut receipt = Receipt::default();
    if answered(imports::peek_message(&mut receipt, window, min, max, flags)).is_none()
        || receipt.kind == RECEIVED_NONE
    {
        return 0;
    }
    msg.set(read_as(receipt.msg, ansi));
    1
}

/// The next message of the calling thread's queue into `msg`, waiting for one (the sent messages
/// found first delivered), as GetMessage takes it with no filter: whether it is not WM_QUIT; none,
/// with the last error, for a failure. The dialog manager's modal loop reads with it.
pub fn next_message(msg: &mut Msg) -> Option<bool> {
    let mut receipt = Receipt::default();
    answered(imports::get_message(&mut receipt, 0, 0, 0))?;
    *msg = receipt.msg;
    Some(receipt.kind != RECEIVED_QUIT)
}

/// Whether the calling thread's queue holds a message PeekMessage would find with no filter (the
/// sent messages found first delivered), leaving it there: the modal loop's test for idleness.
pub fn queue_holds_message() -> bool {
    let mut receipt = Receipt::default();
    imports::peek_message(&mut receipt, 0, 0, 0, PM_NOREMOVE).is_ok()
        && receipt.kind != RECEIVED_NONE
}

/// PostMessageA: PostMessageW's, a character message's character converted to the wide form the
/// queue holds ([`procedure::char_to_wide`]).
#[unsafe(export_name = "f2k_export_PostMessageA")]
pub extern "system" fn post_message_a(
    window: usize,
    message: u32,
    wparam: u32,
    lparam: i32,
) -> u32 {
    post_message_w(
        window,
        message,
        procedure::char_to_wide(message, wparam),
        lparam,
    )
}

/// PostMessageW: the message posted to the window's thread (a null window: the calling thread;
/// HWND_BROADCAST: every top-level window); TRUE, or FALSE with 1400 for a handle naming no window.
/// A queue that holds its 10,000 posted messages already refuses the post, FALSE with the last
/// error untouched ([`posted`]).
#[unsafe(export_name = "f2k_export_PostMessageW")]
pub extern "system" fn post_message_w(
    window: usize,
    message: u32,
    wparam: u32,
    lparam: i32,
) -> u32 {
    posted(
        imports::post_message(window, message, wparam, lparam),
        window_error,
    )
}

// ERROR_NOT_ENOUGH_QUOTA: win32k's refusal of a post to a queue that holds its 10,000 posted
// messages already.
use rtl::winerror::ERROR_NOT_ENOUGH_QUOTA;

/// A post's answer: TRUE, or FALSE with the failure's Win32 error (`error` maps it) made the last
/// error; but a full queue's refusal (ERROR_NOT_ENOUGH_QUOTA) leaves the last error as it was, as
/// guimsg `quota` shows Windows 2000's PostMessage does (later versions set 1816).
fn posted(answer: Result<(), NtStatus>, error: fn(NtStatus) -> u32) -> u32 {
    match answer {
        Ok(()) => 1,
        Err(status) if status == NtStatus::from_win32(ERROR_NOT_ENOUGH_QUOTA) => 0,
        Err(status) => {
            imports::set_last_error(error(status));
            0
        }
    }
}

/// PostThreadMessageA: PostThreadMessageW's, a character message's character converted to the
/// wide form the queue holds.
#[unsafe(export_name = "f2k_export_PostThreadMessageA")]
pub extern "system" fn post_thread_message_a(
    thread: u32,
    message: u32,
    wparam: u32,
    lparam: i32,
) -> u32 {
    post_thread_message_w(
        thread,
        message,
        procedure::char_to_wide(message, wparam),
        lparam,
    )
}

/// PostThreadMessageW: a thread message posted to the thread whose id is `thread`; TRUE, or FALSE
/// with ERROR_INVALID_THREAD_ID for an id no thread with a queue has (a full queue's refusal as
/// PostMessageW's).
#[unsafe(export_name = "f2k_export_PostThreadMessageW")]
pub extern "system" fn post_thread_message_w(
    thread: u32,
    message: u32,
    wparam: u32,
    lparam: i32,
) -> u32 {
    posted(
        imports::post_thread_message(thread, message, wparam, lparam),
        imports::dos_error,
    )
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
    send_within(window, message, wparam, lparam, ansi, None)
}

/// [`send_as`], another thread's answer waited for no longer than SendMessageTimeout's `timeout`
/// when there is one: none with ERROR_TIMEOUT when it does not come in time.
fn send_within(
    window: usize,
    message: u32,
    wparam: u32,
    lparam: i32,
    ansi: bool,
    timeout: Option<SendTimeout>,
) -> Option<i32> {
    // A narrow character message goes as wide, the form another thread's queue carries it in; a
    // narrow procedure of the calling thread's gets it back converted ([`call`]).
    if ansi && procedure::char_message(message) {
        let wparam = procedure::char_to_wide(message, wparam);
        return send_within(window, message, wparam, lparam, false, timeout);
    }
    // A text message to another process's window: the window manager carries its text (WM_SETTEXT's
    // there, WM_GETTEXT's back) in the wide form, so a narrow one goes as wide, converted here.
    if ansi
        && matches!(message, WM_SETTEXT | WM_GETTEXT | WM_GETTEXTLENGTH)
        && window::window_data(window).is_ok_and(|data| data.flags & WINDOW_OTHER_PROCESS != 0)
    {
        let mut reached = true;
        let answer =
            procedure::narrow_to_wide(message, wparam, lparam, |message, wparam, lparam| {
                send_within(window, message, wparam, lparam, false, timeout).unwrap_or_else(|| {
                    reached = false;
                    0
                })
            });
        return reached.then_some(answer);
    }
    // While it waits for another thread's answer, the thread handles the messages sent to it, as
    // Windows 2000's SendMessage does: the kernel delivers them by callback.
    let (proc, answer) = answered(imports::message_call_timeout(
        window, message, wparam, lparam, timeout,
    ))?;
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

/// SendMessageTimeoutW: the message sent to the window, its procedure's answer into `result` (when
/// given); TRUE. A window of the calling thread's is called at once, whatever the timeout, as
/// Windows 2000 calls it; another thread's answer is waited for `timeout` milliseconds, a message
/// its thread has not read by then taken back, and not at all with SMTO_ABORTIFHUNG when that
/// thread is hung (IsHungAppWindow's test): 0 with ERROR_TIMEOUT then, 0 with 1400 for a handle
/// naming no window, `result` 0 for every failure.
///
/// # Safety
///
/// `result` is the caller's DWORD or null, as for the platform's.
#[unsafe(export_name = "f2k_export_SendMessageTimeoutW")]
pub unsafe extern "system" fn send_message_timeout_w(
    window: usize,
    message: u32,
    wparam: u32,
    lparam: i32,
    flags: u32,
    timeout: u32,
    result: *mut u32,
) -> i32 {
    // SAFETY: the caller's DWORD, or null.
    let result = unsafe { Out::optional(result) };
    send_timeout(
        window, message, wparam, lparam, flags, timeout, result, false,
    )
}

/// SendMessageTimeoutA: SendMessageTimeoutW's, for a narrow message.
///
/// # Safety
///
/// `result` is the caller's DWORD or null, as for the platform's.
#[unsafe(export_name = "f2k_export_SendMessageTimeoutA")]
pub unsafe extern "system" fn send_message_timeout_a(
    window: usize,
    message: u32,
    wparam: u32,
    lparam: i32,
    flags: u32,
    timeout: u32,
    result: *mut u32,
) -> i32 {
    // SAFETY: the caller's DWORD, or null.
    let result = unsafe { Out::optional(result) };
    send_timeout(
        window, message, wparam, lparam, flags, timeout, result, true,
    )
}

/// SendMessageTimeout's core, for a message of the narrow (`ansi`) or wide form.
#[allow(clippy::too_many_arguments)]
fn send_timeout(
    window: usize,
    message: u32,
    wparam: u32,
    lparam: i32,
    flags: u32,
    timeout: u32,
    mut result: Option<Out<'_, u32>>,
    ansi: bool,
) -> i32 {
    let limit = SendTimeout { flags, timeout };
    let answer = send_within(window, message, wparam, lparam, ansi, Some(limit));
    if let Some(result) = result.as_mut() {
        result.set(answer.unwrap_or(0) as u32);
    }
    answer.is_some() as i32
}

/// SendNotifyMessageW: the message sent to the window without waiting for its answer: a window
/// of the calling thread's has its procedure called before the return, as SendMessage calls it;
/// another thread's has it queued for its thread, which handles it on its next read. TRUE; FALSE
/// with 1400 for a handle naming no window, with ERROR_MESSAGE_SYNC_ONLY for a message carrying a
/// pointer (WM_SETTEXT...) to another thread's window.
#[unsafe(export_name = "f2k_export_SendNotifyMessageW")]
pub extern "system" fn send_notify_message_w(
    window: usize,
    message: u32,
    wparam: u32,
    lparam: i32,
) -> u32 {
    send_notify(window, message, wparam, lparam, false)
}

/// SendNotifyMessageA: SendNotifyMessageW's, for a narrow message.
#[unsafe(export_name = "f2k_export_SendNotifyMessageA")]
pub extern "system" fn send_notify_message_a(
    window: usize,
    message: u32,
    wparam: u32,
    lparam: i32,
) -> u32 {
    send_notify(window, message, wparam, lparam, true)
}

/// SendNotifyMessage's core, for a message of the narrow (`ansi`) or wide form (a narrow character
/// message going as wide, as [`send_within`]'s).
fn send_notify(window: usize, message: u32, wparam: u32, lparam: i32, ansi: bool) -> u32 {
    if ansi && procedure::char_message(message) {
        let wparam = procedure::char_to_wide(message, wparam);
        return send_notify(window, message, wparam, lparam, false);
    }
    let Some(proc) = answered(imports::send_notify_message(
        window, message, wparam, lparam,
    )) else {
        return 0;
    };
    if proc != 0 {
        let msg = Msg {
            hwnd: window as u32,
            message,
            wparam,
            lparam,
            ..Msg::default()
        };
        call(proc, Some(ansi), &msg);
    }
    1
}

/// The wait's failure (winbase.h's WAIT_FAILED).
const WAIT_FAILED: u32 = 0xFFFF_FFFF;

/// MsgWaitForMultipleObjects: [`msg_wait_for_multiple_objects_ex`]'s, `wait_all` its
/// MWMO_WAITALL.
///
/// # Safety
///
/// The caller's handles, `count` of them.
#[unsafe(export_name = "f2k_export_MsgWaitForMultipleObjects")]
pub unsafe extern "system" fn msg_wait_for_multiple_objects(
    count: u32,
    handles: *const u32,
    wait_all: u32,
    milliseconds: u32,
    wake_mask: u32,
) -> u32 {
    let flags = if wait_all != 0 { MWMO_WAITALL } else { 0 };
    msg_wait(count, handles, milliseconds, wake_mask, flags)
}

/// MsgWaitForMultipleObjectsEx: the calling thread waits for one of the objects its handles name
/// to be signaled (WAIT_OBJECT_0 + its index, WAIT_ABANDONED_0 + it for an abandoned mutex), for
/// input of the wake mask's kinds to come to its queue since a read last looked for it
/// (WAIT_OBJECT_0 + `count`: a post, a send, a timer coming due...; with MWMO_INPUTAVAILABLE, input
/// the queue holds already), or for the timeout (WAIT_TIMEOUT). With MWMO_WAITALL, every object
/// and the input end it (WAIT_OBJECT_0); with MWMO_ALERTABLE, the thread's user APCs run and end
/// it (WAIT_IO_COMPLETION). WAIT_FAILED with the last error for a handle that names nothing it can
/// wait on, for 64 handles or more and for a flag it does not know (ERROR_INVALID_PARAMETER). The
/// messages sent meanwhile are not delivered: the caller's read does it.
///
/// # Safety
///
/// The caller's handles, `count` of them.
#[unsafe(export_name = "f2k_export_MsgWaitForMultipleObjectsEx")]
pub unsafe extern "system" fn msg_wait_for_multiple_objects_ex(
    count: u32,
    handles: *const u32,
    milliseconds: u32,
    wake_mask: u32,
    flags: u32,
) -> u32 {
    if flags & !MWMO_VALID != 0 {
        return failed(rtl::winerror::ERROR_INVALID_PARAMETER).unwrap_or(WAIT_FAILED);
    }
    msg_wait(count, handles, milliseconds, wake_mask, flags)
}

/// The MsgWaitForMultipleObjects calls' core: the kernel's wait.
fn msg_wait(count: u32, handles: *const u32, milliseconds: u32, wake_mask: u32, flags: u32) -> u32 {
    let wait = MsgWait {
        count,
        handles: handles as usize as u32,
        timeout: milliseconds,
        wake_mask,
        flags,
    };
    let answer = imports::call_two_param(
        &wait as *const MsgWait as usize as u32,
        0,
        TWO_PARAM_MSG_WAIT,
    );
    failed_with(answer, imports::dos_error).unwrap_or(WAIT_FAILED)
}

/// WaitMessage: the calling thread waits until something comes to its queue that no read has
/// looked for since (a message PeekMessage saw and left does not count; a timer coming due, a
/// post, a send do); the messages sent to its windows are delivered then. TRUE.
#[unsafe(export_name = "f2k_export_WaitMessage")]
pub extern "system" fn wait_message() -> u32 {
    if answered(imports::wait_message()).is_none() {
        return 0;
    }
    1
}

/// GetMessageTime: the time of the last message the calling thread's GetMessage or PeekMessage
/// retrieved (PeekMessage's PM_NOREMOVE too; a message sent to it, or its own SendMessage, leaves
/// it), in milliseconds since the boot; 0 before the first.
#[unsafe(export_name = "f2k_export_GetMessageTime")]
pub extern "system" fn get_message_time() -> i32 {
    imports::thread_state(THREAD_STATE_MESSAGE_TIME).unwrap_or(0) as i32
}

/// GetMessagePos: the cursor position of that last message, x in the low word and y in the high
/// word, as MSG's pt holds it.
#[unsafe(export_name = "f2k_export_GetMessagePos")]
pub extern "system" fn get_message_pos() -> u32 {
    imports::thread_state(THREAD_STATE_MESSAGE_POS).unwrap_or(0)
}

/// IsHungAppWindow: whether the window's thread is hung: it has not read its queue for 5 s
/// (HungAppTimeout's default) and its last read found something, where a thread whose last read
/// found its queue empty waits for input (Windows 2000's test, the hung capture's: a thread asleep
/// after a read that found nothing is not hung); never the calling thread's own window. FALSE with
/// 1400 for a handle naming no window.
#[unsafe(export_name = "f2k_export_IsHungAppWindow")]
pub extern "system" fn is_hung_app_window(window: usize) -> u32 {
    answered(imports::call_one_param(
        window as u32,
        ONE_PARAM_IS_HUNG_APP_WINDOW,
    ))
    .unwrap_or(0)
}

/// RegisterWindowMessageW: the message registered for the name, in 0xC000..=0xFFFF: the one it has
/// already when registered before, in any case, and RegisterClipboardFormat's format of the name
/// (Windows 2000: NtUserRegisterWindowMessage, in the atom table class names share); 0 with
/// ERROR_INVALID_NAME for an empty name, ERROR_INVALID_PARAMETER for none. The kernel reads the
/// name.
#[unsafe(export_name = "f2k_export_RegisterWindowMessageW")]
pub extern "system" fn register_window_message_w(name: *const u16) -> u32 {
    answered(imports::register_window_message(name as usize)).unwrap_or(0)
}

/// RegisterWindowMessageA: RegisterWindowMessageW's message, the name converted from the ANSI
/// code page first.
///
/// # Safety
///
/// `name` is a NUL-terminated string or null, as for the platform's.
#[unsafe(export_name = "f2k_export_RegisterWindowMessageA")]
pub unsafe extern "system" fn register_window_message_a(name: *const u8) -> u32 {
    if name.is_null() {
        return register_window_message_w(core::ptr::null());
    }
    // SAFETY: the caller's string.
    let name = unsafe { InStr::new(name) };
    crate::with_wide_z(name.bytes(), |units| {
        register_window_message_w(units.as_ptr())
    })
    .unwrap_or(0)
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
pub fn dispatch(msg: &Msg, ansi: bool) -> i32 {
    match answered(imports::dispatch_target(msg)) {
        None | Some(0) => 0,
        Some(proc) if msg.message == WM_TIMER && msg.lparam != 0 => {
            imports::call_procedure(proc, msg.hwnd, WM_TIMER, msg.wparam, msg.time as i32)
        }
        Some(proc) => call(proc, Some(ansi), msg),
    }
}

/// TranslateMessage: a key-down message's character posted for its window (WM_CHAR, WM_SYSCHAR
/// for a system key) where the key makes one, through win32k, which reads the calling thread's
/// key state and the keyboard layout; nonzero for every key message, 0 for another.
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

/// TranslateMessage's core: a key-up has no character (the US layout has no dead keys).
pub fn translate(msg: &Msg) -> u32 {
    match msg.message {
        WM_KEYDOWN | WM_SYSKEYDOWN => {
            let _ = imports::translate_message(msg);
            1
        }
        WM_KEYUP | WM_SYSKEYUP => 1,
        _ => 0,
    }
}

/// The default window procedure's answer to a message of the narrow (`ansi`) or wide form:
/// WM_NCCREATE the title the CREATESTRUCT names set, TRUE (the creation goes on); WM_SETTEXT the
/// text set (the caption redrawn), TRUE; WM_GETTEXT the text copied into the buffer (as much as
/// fits with its terminator; nothing into an empty one), the units or bytes copied;
/// WM_GETTEXTLENGTH the text's length; WM_CLOSE the window destroyed; WM_PAINT the window validated
/// through BeginPaint and EndPaint; WM_ACTIVATE the focus to a window being activated that is not
/// minimized, as the documentation gives it; WM_ERASEBKGND the client area filled with the class's
/// background brush (GCL_HBRBACKGROUND: a brush, or a system color's index plus one), TRUE, or
/// FALSE for a class with none; WM_CTLCOLOR* a control's colors set in its DC and the brush it
/// paints its background with answered (the window colors for an edit control and a list box, the
/// scroll bar's color for a scroll bar, the 3D face for the others, the text in COLOR_WINDOWTEXT);
/// WM_QUERYENDSESSION TRUE (the session may end, as the message's documentation gives
/// DefWindowProc's answer), whatever its lParam; the non-client messages ([`nonclient`]):
/// WM_NCCALCSIZE the frame taken off the rectangle, WM_NCHITTEST the part under the point,
/// WM_NCPAINT the frame drawn, WM_NCACTIVATE the caption redrawn, TRUE; the system keys (Alt or
/// F10 alone, and Alt with a character, send the top-level window SC_KEYMENU, Alt+F4 SC_CLOSE)
/// and WM_SYSCOMMAND (SC_KEYMENU runs the keyboard menu loop, SC_CLOSE sends WM_CLOSE,
/// SC_MINIMIZE, SC_MAXIMIZE and SC_RESTORE minimize, maximize and restore the window);
/// WM_CANCELMODE the window's menu loop ended ([`menubar::cancel_mode`]) and its capture released;
/// WM_SETCURSOR the cursor set, WM_MOUSEACTIVATE MA_ACTIVATE ([`mouse`]); WM_SETREDRAW the window's
/// WS_VISIBLE set or cleared, 0; WM_CONTEXTMENU a child's handed to its parent, 0; WM_SETICON the
/// window's big or small icon kept, the one it replaces answered, and WM_GETICON's answer it
/// ([`set_icon`]); WM_WINDOWPOSCHANGING a resize's size clamped into the window's tracking sizes
/// by win32k, which sends WM_GETMINMAXINFO for them (WM_GETMINMAXINFO itself leaves the window
/// manager's defaults as they are); 0 to everything else,
/// WM_ENDSESSION included, and to a text message for a handle naming no window.
/// The messages Windows 2000's acts on and F2K's does not yet ([`UNHANDLED_MESSAGES`]) are logged,
/// each once per process.
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
        WM_SETTEXT => {
            let set = set_text(window, lparam, ansi);
            if set {
                nonclient::redraw_caption(window);
            }
            set as i32
        }
        WM_GETTEXT => get_text(window, wparam, lparam, ansi) as i32,
        WM_GETTEXTLENGTH => text_length(window, ansi) as i32,
        WM_ERASEBKGND => erase_background(window, wparam as usize) as i32,
        WM_CTLCOLORMSGBOX..=WM_CTLCOLORSTATIC => control_colors(wparam as usize, message) as i32,
        WM_QUERYENDSESSION => 1,
        WM_CHANGEUISTATE => {
            change_ui_state(window, wparam);
            0
        }
        WM_UPDATEUISTATE => {
            update_ui_state(window, wparam);
            0
        }
        WM_QUERYUISTATE => ui_state(window) as i32,
        WM_NCDESTROY => {
            forget_ui_state(window);
            forget_icons(window);
            0
        }
        WM_SETREDRAW => {
            let _ = imports::call_hwnd_param_lock(window, wparam, HWND_PARAM_LOCK_SET_REDRAW);
            0
        }
        WM_CONTEXTMENU => {
            context_menu(window, wparam, lparam);
            0
        }
        WM_SETICON => set_icon(window, wparam, lparam as u32) as i32,
        WM_GETICON => icon_of(window, wparam) as i32,
        WM_WINDOWPOSCHANGED => {
            window_pos_changed(window, lparam);
            0
        }
        WM_WINDOWPOSCHANGING => {
            // The kernel's half (Windows 2000's xxxHandleWindowPosChanging): a resize clamped into
            // the window's tracking sizes, WM_GETMINMAXINFO sent to it meanwhile.
            if lparam != 0 {
                let _ = imports::call_hwnd_param_lock(
                    window,
                    lparam as u32,
                    HWND_PARAM_LOCK_WINDOW_POS_CHANGING,
                );
            }
            0
        }
        WM_NCCALCSIZE => nonclient::calc_size(window, wparam, lparam),
        WM_NCHITTEST => nonclient::hit_test(window, lparam),
        WM_NCPAINT => nonclient::paint(window),
        WM_NCACTIVATE => nonclient::activate(window, wparam),
        WM_SYSKEYDOWN | WM_SYSKEYUP | WM_KEYDOWN | WM_KEYUP | WM_SYSCHAR => {
            system_key(window, message, wparam, lparam, ansi);
            0
        }
        WM_SYSCOMMAND => {
            system_command(window, wparam, lparam, ansi);
            0
        }
        WM_CANCELMODE => {
            menubar::cancel_mode(window);
            mouse::cancel_capture(window);
            0
        }
        WM_SETCURSOR => mouse::set_cursor_default(window, wparam, lparam),
        WM_MOUSEACTIVATE => mouse::mouse_activate_default(window, wparam, lparam),
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
        _ => {
            if let Some(&(_, what)) = UNHANDLED_MESSAGES.iter().find(|&&(m, _)| m == message) {
                crate::stub::message_once(
                    &DEFAULT_LOGGED,
                    message,
                    default_entry(ansi),
                    format_args!("{what} is not yet implemented"),
                    (window, message, wparam, lparam),
                );
            }
            0
        }
    }
}

// --- The UI state (the keyboard cues) ------------------------------------------------------------

/// The UI state messages' actions (wParam's low word) and flags (its high word).
const UIS_SET: u32 = 1;
const UIS_CLEAR: u32 = 2;
const UIS_INITIALIZE: u32 = 3;
const UISF_ALL: u32 = 0x7;

/// The windows of this process whose UI state is not the default 0: (window, state), in a table
/// that grows with them ([`crate::records`]; Windows 2000 keeps the state in the window's own
/// structure). DefWindowProc runs in the window's own process, which answers WM_QUERYUISTATE for
/// it; its WM_NCDESTROY drops the record.
static UI_STATES: Table<2> = Table::new();

/// `record` kept in `table` for the window it names; a table out of room first drops the records
/// of windows that are gone (a procedure that never handed its WM_NCDESTROY to DefWindowProc left
/// them). False when the heap has no room for it.
fn keep_record<const W: usize>(table: &Table<W>, record: [usize; W]) -> bool {
    table.with(|records| {
        if records.get(record[0]).is_none() && records.len() == records.capacity() {
            records.retain(|kept| window::is_window_alive(kept[0]));
        }
        records.set(record)
    })
}

/// The window's UI state (WM_QUERYUISTATE's answer): 0 unless WM_UPDATEUISTATE set a flag.
fn ui_state(window: usize) -> u32 {
    UI_STATES
        .with(|states| states.get(window))
        .map_or(0, |[_, state]| state as u32)
}

/// The window's UI state set to `state` (0, the default, kept as no record). Without room for its
/// record the state stays the default.
fn set_ui_state(window: usize, state: u32) {
    if state == 0 {
        forget_ui_state(window);
    } else {
        let _ = keep_record(&UI_STATES, [window, state as usize]);
    }
}

/// The window's UI state forgotten as it goes (its handle may name another window later).
fn forget_ui_state(window: usize) {
    let _ = UI_STATES.with(|states| states.take(window));
}

/// `state` after WM_UPDATEUISTATE's `wparam`: UIS_SET sets the flags, UIS_CLEAR clears them, and so
/// does UIS_INITIALIZE (menus `cues`: after UIS_INITIALIZE of UISF_HIDEACCEL the window answers 0,
/// no keyboard input having come, the keyboard cues off; inferred from that one capture).
fn ui_state_after(state: u32, wparam: u32) -> u32 {
    let flags = (wparam >> 16) & UISF_ALL;
    match wparam & 0xFFFF {
        UIS_SET => state | flags,
        UIS_CLEAR | UIS_INITIALIZE => state & !flags,
        _ => state,
    }
}

/// DefWindowProc's WM_CHANGEUISTATE: a child hands it to its parent; a top-level window whose state
/// it changes sends itself WM_UPDATEUISTATE.
fn change_ui_state(window: usize, wparam: u32) {
    let style = window::style_of(window).unwrap_or(0);
    if style & WS_CHILD != 0 {
        if let Ok(links) = window::links(window) {
            if links.parent != 0 {
                let _ = send(links.parent as usize, WM_CHANGEUISTATE, wparam, 0);
                return;
            }
        }
    }
    if ui_state_after(ui_state(window), wparam) != ui_state(window) {
        let _ = send(window, WM_UPDATEUISTATE, wparam, 0);
    }
}

/// DefWindowProc's WM_UPDATEUISTATE: the window's state changed, then the message sent on to each
/// of its children.
fn update_ui_state(window: usize, wparam: u32) {
    set_ui_state(window, ui_state_after(ui_state(window), wparam));
    let mut child = window::links(window).map_or(0, |l| l.child as usize);
    while child != 0 {
        let _ = send(child, WM_UPDATEUISTATE, wparam, 0);
        child = window::links(child).map_or(0, |l| l.next as usize);
    }
}

/// DefWindowProc's WM_WINDOWPOSCHANGED: WM_MOVE (the client area's origin in the parent's client
/// coordinates, the screen's for a top-level window) unless the client area kept its place, then
/// WM_SIZE (SIZE_MINIMIZED, SIZE_MAXIMIZED or SIZE_RESTORED, and the client area's size) unless it
/// kept its size, both sent to `window`, as guigeo `sizemsg` captured (a procedure keeping the
/// message from DefWindowProc gets neither).
fn window_pos_changed(window: usize, lparam: i32) {
    if lparam == 0 {
        return;
    }
    // SAFETY: WM_WINDOWPOSCHANGED's lParam: a WINDOWPOS.
    let pos = unsafe { In::new(lparam as usize as *const rtl::window::WindowPos) }.read();
    let Ok(info) = window::window_info(window) else {
        return;
    };
    let client = info.client;
    if pos.flags & SWP_NOCLIENTMOVE == 0 {
        let parent = window::links(window).map_or(0, |l| l.parent as usize);
        let (dx, dy) =
            window::window_info(parent).map_or((0, 0), |p| (p.client.left, p.client.top));
        let (x, y) = (client.left - dx, client.top - dy);
        let at = ((y as u16 as u32) << 16) | x as u16 as u32;
        send(window, WM_MOVE, 0, at as i32);
    }
    if pos.flags & SWP_NOCLIENTSIZE == 0 {
        let command = if info.style & WS_MINIMIZE != 0 {
            1
        } else if info.style & 0x0100_0000 != 0 {
            2
        } else {
            0
        };
        let (cx, cy) = (client.right - client.left, client.bottom - client.top);
        let size = ((cy as u16 as u32) << 16) | cx as u16 as u32;
        send(window, WM_SIZE, command, size as i32);
    }
}

/// The messages DefWindowProc acts on in Windows 2000 that F2K's does not yet (it answers 0), and
/// what Windows 2000's does with each.
const UNHANDLED_MESSAGES: [(u32, &str); 6] = [
    (
        0x0013,
        "WM_QUERYOPEN (TRUE: the minimized window may be restored)",
    ),
    (0x0037, "WM_QUERYDRAGICON (the class's icon)"),
    (0x0317, "WM_PRINT (the window drawn into the DC)"),
    (0x0032, "WM_SETHOTKEY (the window's activation hot key)"),
    (0x0033, "WM_GETHOTKEY (the window's activation hot key)"),
    (
        0x0055,
        "WM_NOTIFYFORMAT (the window's form answered: NFR_ANSI or NFR_UNICODE)",
    ),
];

// --- WM_SETREDRAW, WM_CONTEXTMENU, and the window's icons ----------------------------------------

/// WM_SETICON's and WM_GETICON's wParam: the small icon (the caption's) and the big one
/// (Alt+Tab's).
const ICON_SMALL: u32 = 0;
const ICON_BIG: u32 = 1;
// ERROR_INVALID_HANDLE: the small icon a big one's WM_SETICON makes could not be made.
use rtl::winerror::ERROR_INVALID_HANDLE;

/// DefWindowProc's WM_CONTEXTMENU: a child hands it to its parent, as it came, its answer
/// dropped (guimsg `ctxmenu`: the parent's procedure answers 5, the child's send 0); a top-level
/// window's would open its window menu, which F2K has none of.
fn context_menu(window: usize, wparam: u32, lparam: i32) {
    if window::style_of(window).unwrap_or(0) & WS_CHILD == 0 {
        return;
    }
    if let Ok(links) = window::links(window) {
        if links.parent != 0 {
            let _ = send(links.parent as usize, WM_CONTEXTMENU, wparam, lparam);
        }
    }
}

/// The icons WM_SETICON gave a window: (window, big, small), 0 for none, in a table that grows
/// with the windows holding any ([`crate::records`]). DefWindowProc runs in the window's own
/// process, which answers its WM_GETICON, so the process keeps them (Windows 2000 keeps them as the
/// window's internal properties); its WM_NCDESTROY drops the record.
static ICONS: Table<3> = Table::new();

/// DefWindowProc's WM_GETICON: the window's big or small icon (`which`), 0 for none or for another
/// `which`.
fn icon_of(window: usize, which: u32) -> u32 {
    let slot = match which {
        ICON_BIG => 1,
        ICON_SMALL => 2,
        _ => return 0,
    };
    ICONS
        .with(|icons| icons.get(window))
        .map_or(0, |record| record[slot] as u32)
}

/// DefWindowProc's WM_SETICON: the window's big or small icon (`which`) set to `icon` (0: none),
/// the one it replaces answered (0 for another `which`). As guimsg `icon` shows Windows 2000's, a
/// big icon set while the window has no small one leaves ERROR_INVALID_HANDLE as the last error:
/// Windows 2000 makes the caption's small icon from the big one then, and the copy of the stock
/// icon the capture sets failed (inferred: WM_GETICON's small icon stays NULL). F2K's icons hold
/// no image to copy, so it keeps none, and leaves the same error.
fn set_icon(window: usize, which: u32, icon: u32) -> u32 {
    let slot = match which {
        ICON_BIG => 1,
        ICON_SMALL => 2,
        _ => return 0,
    };
    if which == ICON_BIG && icon != 0 && icon_of(window, ICON_SMALL) == 0 {
        imports::set_last_error(ERROR_INVALID_HANDLE);
    }
    let record = ICONS.with(|icons| icons.get(window));
    if record.is_none() && (icon == 0 || window == 0) {
        return 0;
    }
    let mut record = record.unwrap_or([window, 0, 0]);
    let previous = record[slot] as u32;
    record[slot] = icon as usize;
    if record[1] == 0 && record[2] == 0 {
        forget_icons(window);
    } else if !keep_record(&ICONS, record) {
        // No room for a new record: the window keeps no icon, as before the call.
        return 0;
    }
    previous
}

/// The window's icons forgotten as it goes (its handle may name another window later).
fn forget_icons(window: usize) {
    let _ = ICONS.with(|icons| icons.take(window));
}

/// The default procedure's cases logged in this process: a message, a system command, a key.
static DEFAULT_LOGGED: rtl::stub::Logged<32> = rtl::stub::Logged::new();

/// DefWindowProc's entry in the caller's form, as its lines name it.
fn default_entry(ansi: bool) -> &'static rtl::stub::Entry {
    if ansi {
        &crate::spec::DefWindowProcA
    } else {
        &crate::spec::DefWindowProcW
    }
}

/// DefWindowProc's WM_ERASEBKGND: the client area of `window` filled through `dc` with its class's
/// background brush; whether there was one to fill with.
fn erase_background(window: usize, dc: usize) -> bool {
    let Some(class) = window::class_data(window) else {
        return false;
    };
    if class.background == 0 {
        return false;
    }
    let Some(client) = window::client_rect(window) else {
        return false;
    };
    crate::draw::fill(dc, client, class.background as usize);
    true
}

/// DefWindowProc's WM_CTLCOLOR*: the text color COLOR_WINDOWTEXT and the background color of the
/// control's kind set in its DC `dc`, the brush of that color answered.
fn control_colors(dc: usize, message: u32) -> usize {
    let background = match message {
        WM_CTLCOLOREDIT | WM_CTLCOLORLISTBOX => COLOR_WINDOW,
        WM_CTLCOLORSCROLLBAR => COLOR_SCROLLBAR,
        _ => COLOR_3DFACE,
    };
    imports::set_text_color(dc, crate::display::get_sys_color(COLOR_WINDOWTEXT as i32));
    imports::set_bk_color(dc, crate::display::get_sys_color(background as i32));
    crate::display::get_sys_color_brush(background as i32)
}

/// The menu key pressed with no other key since (VK_MENU or VK_F10), 0 for none: the default
/// procedure's WM_SYSKEYUP of that key opens the menu. Windows 2000 keeps this in win32k's input
/// state; F2K's default procedure keeps it per process, from the key messages it is handed.
static MENU_KEY_ALONE: AtomicU32 = AtomicU32::new(0);

/// A key message's lParam bits: Alt down (the context code), the key down before (a repeat).
const KEY_CONTEXT: i32 = 1 << 29;
const KEY_PREVIOUS: i32 = 1 << 30;

/// The top-level window `window` is in: itself, or its first ancestor that is not a child.
fn top_level(window: usize) -> usize {
    let mut at = window;
    while window::style_of(at).is_some_and(|style| style & WS_CHILD != 0) {
        match window::links(at) {
            Ok(links) if links.parent != 0 => at = links.parent as usize,
            _ => break,
        }
    }
    at
}

/// The default procedure's system keys: Alt or F10 pressed and released alone sends the top-level
/// window WM_SYSCOMMAND SC_KEYMENU (lParam 0), Alt with a character SC_KEYMENU with the character
/// (Alt+Space, the system menu's, is not served: F2K has no system menu), Alt+F4 SC_CLOSE.
fn system_key(window: usize, message: u32, wparam: u32, lparam: i32, ansi: bool) {
    let send_command = |command: u32, parameter: i32| {
        let _ = send(top_level(window), WM_SYSCOMMAND, command, parameter);
    };
    match message {
        WM_SYSKEYDOWN if wparam == VK_MENU || wparam == VK_F10 => {
            if lparam & KEY_PREVIOUS == 0 {
                MENU_KEY_ALONE.store(wparam, Ordering::Relaxed);
                if wparam == VK_MENU {
                    menubar::alt_held(top_level(window), true);
                }
            }
        }
        WM_SYSKEYDOWN => {
            MENU_KEY_ALONE.store(0, Ordering::Relaxed);
            if wparam == VK_F4 && lparam & KEY_CONTEXT != 0 {
                send_command(SC_CLOSE, 0);
            }
        }
        WM_SYSKEYUP | WM_KEYUP if wparam == VK_MENU => {
            menubar::alt_held(top_level(window), false);
            let alone = MENU_KEY_ALONE.swap(0, Ordering::Relaxed) == wparam;
            if message == WM_SYSKEYUP && alone {
                send_command(SC_KEYMENU, 0);
            }
        }
        WM_SYSKEYUP if wparam == VK_F10 => {
            if MENU_KEY_ALONE.swap(0, Ordering::Relaxed) == wparam {
                send_command(SC_KEYMENU, 0);
            }
        }
        WM_SYSCHAR => {
            MENU_KEY_ALONE.store(0, Ordering::Relaxed);
            if lparam & KEY_CONTEXT != 0 && wparam != VK_SPACE {
                send_command(SC_KEYMENU, wparam as i32);
            } else if lparam & KEY_CONTEXT != 0 {
                crate::stub::message_once(
                    &DEFAULT_LOGGED,
                    VK_SPACE << 16 | WM_SYSCHAR,
                    default_entry(ansi),
                    "Alt+Space, the system menu, is not yet implemented",
                    (window, message, wparam, lparam),
                );
            }
        }
        WM_KEYDOWN => MENU_KEY_ALONE.store(0, Ordering::Relaxed),
        _ => {}
    }
}

/// The default procedure's WM_SYSCOMMAND: SC_KEYMENU runs the window's keyboard menu loop
/// ([`menubar::track_keyboard`]), SC_CLOSE sends WM_CLOSE; SC_MINIMIZE, SC_MAXIMIZE and SC_RESTORE
/// show the window SW_MINIMIZE, SW_SHOWMAXIMIZED and SW_RESTORE, as Windows 2000's xxxSysCommand
/// does (guimsg `syscmd`: one WM_SIZE each, SIZE_MINIMIZED, SIZE_MAXIMIZED, SIZE_RESTORED); the
/// other system commands (the system menu's moving and sizing...) are not served yet, and logged
/// (an application's own commands, below 0xF000, are not the default procedure's).
fn system_command(window: usize, wparam: u32, lparam: i32, ansi: bool) {
    match wparam & 0xFFF0 {
        SC_KEYMENU => menubar::track_keyboard(window, lparam as u32),
        SC_CLOSE => {
            let _ = send(window, WM_CLOSE, 0, 0);
        }
        SC_MINIMIZE => {
            window::show_window(window, SW_MINIMIZE);
        }
        SC_MAXIMIZE => {
            window::show_window(window, SW_SHOWMAXIMIZED);
        }
        SC_RESTORE => {
            window::show_window(window, SW_RESTORE);
        }
        command if command >= 0xF000 => {
            let name = SYSTEM_COMMANDS
                .iter()
                .find(|&&(c, _)| c == command)
                .map_or("this system command", |&(_, name)| name);
            crate::stub::message_once(
                &DEFAULT_LOGGED,
                command,
                default_entry(ansi),
                format_args!("{name} is not yet implemented"),
                (window, WM_SYSCOMMAND, wparam, lparam),
            );
        }
        _ => {}
    }
}

/// The system commands (winuser.h's SC_*) by name, as a log line names them.
const SYSTEM_COMMANDS: [(u32, &str); 16] = [
    (0xF000, "SC_SIZE"),
    (0xF010, "SC_MOVE"),
    (0xF020, "SC_MINIMIZE"),
    (0xF030, "SC_MAXIMIZE"),
    (0xF040, "SC_NEXTWINDOW"),
    (0xF050, "SC_PREVWINDOW"),
    (0xF070, "SC_VSCROLL"),
    (0xF080, "SC_HSCROLL"),
    (0xF090, "SC_MOUSEMENU"),
    (0xF110, "SC_ARRANGE"),
    (0xF120, "SC_RESTORE"),
    (0xF130, "SC_TASKLIST"),
    (0xF140, "SC_SCREENSAVE"),
    (0xF150, "SC_HOTKEY"),
    (0xF170, "SC_MONITORPOWER"),
    (0xF180, "SC_CONTEXTHELP"),
];

/// SetTimer: a timer of the window (NULL: a thread timer, its id made) set to come due every
/// `elapse` milliseconds, its WM_TIMER handed to `func` when there is one; the timer's id, or 0
/// with the last error (1400 for a handle naming no window).
#[unsafe(export_name = "f2k_export_SetTimer")]
pub extern "system" fn set_timer(window: usize, id: u32, elapse: u32, func: usize) -> u32 {
    answered(imports::set_timer(window, id, elapse, func)).unwrap_or(0)
}

/// KillTimer: the window's timer `id` (NULL: the thread timer of that id) gone; TRUE, or FALSE
/// with the last error (1400 for a handle naming no window); FALSE with the last error left as it
/// was for a timer there is not, as Windows 2000's (guimsg `killtimer`).
#[unsafe(export_name = "f2k_export_KillTimer")]
pub extern "system" fn kill_timer(window: usize, id: u32) -> u32 {
    match imports::kill_timer(window, id) {
        Err(status) if status.0 == rtl::status::STATUS_UNSUCCESSFUL => 0,
        answer => answered(answer).is_some() as u32,
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
    crate::with_wide_z(text.bytes(), |units| {
        imports::def_set_text(window, units.as_ptr() as usize).is_ok()
    })
    .unwrap_or(false)
}

/// The units of a window's text kept in the copy itself; a longer text is copied into a block of
/// the process heap.
const TEXT_UNITS: usize = 256;

/// A copy of a window's text, as long as it is ([`window_text`]).
pub struct WindowText {
    /// The answer's head (the length, two units), then the text when it fits.
    short: [u16; 2 + TEXT_UNITS],
    /// The answer, as `short`, for a longer text.
    long: Option<imports::HeapBlock>,
    length: usize,
}

impl Default for WindowText {
    fn default() -> Self {
        WindowText {
            short: [0; 2 + TEXT_UNITS],
            long: None,
            length: 0,
        }
    }
}

impl WindowText {
    /// The text's units.
    pub fn as_slice(&self) -> &[u16] {
        let answer = match &self.long {
            Some(block) => block.units(),
            None => &self.short[..],
        };
        &answer[2..2 + self.length]
    }
}

/// The window's text, as the window manager holds it, whole: none for a handle naming no window.
/// A text longer than the copy's own room is asked for again into a block of the process heap
/// (again while it grows meanwhile); with no room on the heap, the copy holds what fits.
pub fn window_text(window: usize) -> Option<WindowText> {
    let mut text = WindowText::default();
    let mut length = imports::query_window_text(window, &mut text.short).ok()?;
    text.length = length.min(TEXT_UNITS);
    while length > text.length {
        let Some(mut block) = imports::HeapBlock::new(2 * (2 + length)) else {
            return Some(text);
        };
        let room = length;
        length = imports::query_window_text(window, block.units_mut()).ok()?;
        text.long = Some(block);
        text.length = length.min(room);
    }
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
    use core::ptr::null_mut;

    use rtl::winerror::ERROR_INVALID_THREAD_ID;

    use super::*;
    use crate::class::{register_class_a, WndClass};
    use crate::imports::host::{procedure, wm, LAST_ERROR, THREAD_ID};
    use crate::window::{create_window_ex_a, is_window};

    const UNSET: u32 = 0xF2F2_F2F2;

    /// The UI state as menus `cues` captured it: UIS_CLEAR of a clear flag changes nothing,
    /// UIS_SET sets it, UIS_INITIALIZE clears it; a window's state is kept until it goes.
    #[test]
    fn the_ui_state_follows_the_capture() {
        let hide_accel = |action: u32| action | (2 << 16);
        assert_eq!(ui_state_after(0, hide_accel(UIS_CLEAR)), 0);
        assert_eq!(ui_state_after(0, hide_accel(UIS_SET)), 2);
        assert_eq!(ui_state_after(2, hide_accel(UIS_INITIALIZE)), 0);
        assert_eq!(ui_state_after(3, hide_accel(UIS_CLEAR)), 1);
        let window = 0xDEAD_0;
        assert_eq!(ui_state(window), 0);
        set_ui_state(window, 2);
        assert_eq!(ui_state(window), 2);
        assert_eq!(default_procedure(window, WM_QUERYUISTATE, 0, 0, false), 2);
        forget_ui_state(window);
        assert_eq!(ui_state(window), 0);
    }

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

    /// How many windows the process keeps a UI state and icons for.
    fn records_held() -> (usize, usize) {
        (
            UI_STATES.with(|states| states.len()),
            ICONS.with(|icons| icons.len()),
        )
    }

    /// More windows with a UI state and icons than the process's old fixed tables held (64 each):
    /// each answers its own, and DefWindowProc's WM_NCDESTROY leaves no record behind.
    #[test]
    fn ui_states_and_icons_past_a_fixed_table() {
        let held = records_held();
        let windows: std::vec::Vec<usize> = (0..100).map(|_| window()).collect();
        for (index, &window) in windows.iter().enumerate() {
            let state = 1 + index as u32 % 3;
            default_procedure(window, WM_UPDATEUISTATE, UIS_SET | state << 16, 0, false);
            default_procedure(window, WM_SETICON, ICON_SMALL, 0x1000 + index as i32, false);
            default_procedure(window, WM_SETICON, ICON_BIG, 0x2000 + index as i32, false);
        }
        assert_eq!(records_held(), (held.0 + 100, held.1 + 100));
        for (index, &window) in windows.iter().enumerate() {
            let state = 1 + index as i32 % 3;
            assert_eq!(
                default_procedure(window, WM_QUERYUISTATE, 0, 0, false),
                state
            );
            assert_eq!(
                default_procedure(window, WM_GETICON, ICON_SMALL, 0, false),
                0x1000 + index as i32
            );
            assert_eq!(
                default_procedure(window, WM_GETICON, ICON_BIG, 0, false),
                0x2000 + index as i32
            );
        }
        // Icons and a state set back to none leave no record either.
        let first = windows[0];
        default_procedure(first, WM_SETICON, ICON_SMALL, 0, false);
        default_procedure(first, WM_SETICON, ICON_BIG, 0, false);
        default_procedure(
            first,
            WM_UPDATEUISTATE,
            UIS_CLEAR | UISF_ALL << 16,
            0,
            false,
        );
        assert_eq!(records_held(), (held.0 + 99, held.1 + 99));
        for &window in &windows {
            assert_eq!(crate::window::destroy_window(window), 1);
        }
        assert_eq!(records_held(), held);
    }

    fn swallows_ncdestroy(window: u32, message: u32, wparam: u32, lparam: i32) -> i32 {
        if message == WM_NCDESTROY {
            return 0;
        }
        def_window_proc_a(window as usize, message, wparam, lparam)
    }

    /// A window whose procedure keeps WM_NCDESTROY from DefWindowProc leaves its record; a table
    /// out of room drops such records of windows that are gone before it grows.
    #[test]
    fn records_of_gone_windows_go_before_the_table_grows() {
        let class = WndClass {
            wnd_proc: procedure(swallows_ncdestroy) as usize,
            class_name: c"F2KSwallow".as_ptr() as usize,
            ..WndClass::default()
        };
        let make = || {
            // SAFETY: a WNDCLASSA of the test's own, and its name.
            let window = unsafe {
                create_window_ex_a(
                    0,
                    c"F2KSwallow".as_ptr().cast(),
                    core::ptr::null(),
                    0x8000_0000,
                    0,
                    0,
                    10,
                    10,
                    0,
                    0,
                    0,
                    0,
                )
            };
            assert_ne!(window, 0);
            default_procedure(window, WM_UPDATEUISTATE, UIS_SET | 2 << 16, 0, false);
            window
        };
        // SAFETY: as above.
        unsafe { register_class_a(&class) };
        let held = UI_STATES.with(|states| states.len());
        assert_eq!(held, 0, "this thread's table starts empty");
        let gone: std::vec::Vec<usize> = (0..20).map(|_| make()).collect();
        for &window in &gone {
            crate::window::destroy_window(window);
        }
        let capacity = UI_STATES.with(|states| states.capacity());
        assert_eq!(UI_STATES.with(|states| states.len()), 20);
        let live: std::vec::Vec<usize> = (20..capacity).map(|_| make()).collect();
        assert_eq!(UI_STATES.with(|states| states.len()), capacity);
        let one_more = make();
        assert_eq!(UI_STATES.with(|states| states.len()), live.len() + 1);
        assert_eq!(UI_STATES.with(|states| states.capacity()), capacity);
        assert!(gone.iter().all(|&window| ui_state(window) == 0));
        assert_eq!(ui_state(one_more), 2);
        for &window in live.iter().chain([&one_more]) {
            forget_ui_state(window);
            crate::window::destroy_window(window);
        }
        assert_eq!(UI_STATES.with(|states| states.len()), 0);
    }

    fn peek(flags: u32) -> (u32, Msg) {
        let mut msg = Msg::default();
        // SAFETY: the tests' own MSG.
        let answer = unsafe { peek_message_a(&mut msg, 0, 0, 0, flags) };
        (answer, msg)
    }

    /// A window's text is kept whole however long it is: 10,000 units set through the default
    /// procedure's service come back whole, their length in both forms (code page 1252's narrow
    /// form a byte each, U+4E00's its default character), and InternalGetWindowText cuts them to
    /// its buffer only.
    ///
    /// Pins: user32.InternalGetWindowText
    #[test]
    fn a_long_text_is_kept_whole() {
        let window = window();
        let text: std::vec::Vec<u16> = (0..10_000u32)
            .map(|i| match i % 3 {
                0 => 0x41 + (i % 26) as u16,
                1 => 0xE9,
                _ => 0x4E00,
            })
            .chain([0])
            .collect();
        assert!(imports::def_set_text(window, text.as_ptr() as usize).is_ok());
        let held = window_text(window).unwrap();
        assert_eq!(held.as_slice(), &text[..10_000]);
        assert_eq!(text_length(window, false), 10_000);
        assert_eq!(text_length(window, true), 10_000);
        let mut buffer = std::vec![0x23u16; 10_002];
        // SAFETY: the test's own buffer, of the counts given.
        let copied =
            unsafe { crate::window::internal_get_window_text(window, buffer.as_mut_ptr(), 10_002) };
        assert_eq!(copied, 10_000);
        assert_eq!(&buffer[..10_001], &text[..]);
        // SAFETY: as above.
        let copied =
            unsafe { crate::window::internal_get_window_text(window, buffer.as_mut_ptr(), 300) };
        assert_eq!((copied, buffer[299]), (299, 0));
        assert_eq!(&buffer[..299], &text[..299]);
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

    /// A character message's character is wide in the queue: PostMessageA's 0x80 (code page
    /// 1252's euro) reads back as U+20AC through PeekMessageW and as 0x80 through GetMessageA and
    /// PeekMessageA; DispatchMessageW's U+20AC and DispatchMessageA's 0x80 reach the narrow
    /// procedure as 0x80, as SendMessageW's and SendMessageA's do; another message's wParam is
    /// left as it is.
    ///
    /// Pins: user32.PostMessageA, user32.PostThreadMessageA, user32.GetMessageA,
    /// user32.PeekMessageA, user32.PeekMessageW, user32.DispatchMessageA, user32.DispatchMessageW,
    /// user32.SendMessageA, user32.SendMessageW
    #[test]
    fn characters_are_wide_in_the_queue() {
        let window = window();
        assert_eq!(post_message_a(window, WM_CHAR, 0x80, 1), 1);
        let mut msg = Msg::default();
        // SAFETY: the tests' own MSG.
        assert_eq!(unsafe { peek_message_w(&mut msg, 0, 0, 0, PM_NOREMOVE) }, 1);
        assert_eq!((msg.message, msg.wparam), (WM_CHAR, 0x20AC));
        assert_eq!(peek(PM_NOREMOVE).1.wparam, 0x80);
        // SAFETY: as above.
        assert_eq!(unsafe { get_message_a(&mut msg, 0, 0, 0) }, 1);
        assert_eq!((msg.message, msg.wparam), (WM_CHAR, 0x80));
        // SAFETY: as above.
        unsafe { dispatch_message_a(&msg) };
        let wide = Msg {
            wparam: 0x20AC,
            ..msg
        };
        // SAFETY: as above.
        unsafe { dispatch_message_w(&wide) };
        send_message_w(window, WM_SYSCHAR, 0x20AC, 0);
        send_message_a(window, WM_SYSCHAR, 0x80, 0);
        send_message_w(window, WM_USER, 0x20AC, 0);
        let w = window as u32;
        assert_eq!(
            seen(),
            [
                (w, WM_CHAR, 0x80, 1),
                (w, WM_CHAR, 0x80, 1),
                (w, WM_SYSCHAR, 0x80, 0),
                (w, WM_SYSCHAR, 0x80, 0),
                (w, WM_USER, 0x20AC, 0),
            ]
        );
        let me = THREAD_ID.with(|id| id.get());
        assert_eq!(post_thread_message_a(me, WM_DEADCHAR, 0x80, 0), 1);
        // SAFETY: as above.
        assert_eq!(unsafe { get_message_w(&mut msg, 0, 0, 0) }, 1);
        assert_eq!((msg.message, msg.wparam), (WM_DEADCHAR, 0x20AC));
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
        let handed = crate::imports::host::CHARACTERS.with(|seen| seen.borrow().clone());
        assert_eq!(
            handed,
            [key],
            "the key-down goes to win32k, which posts its character"
        );
        let up = Msg {
            message: WM_KEYUP,
            ..key
        };
        // SAFETY: as above.
        assert_eq!(unsafe { translate_message(&up) }, 1);
        assert_eq!(
            crate::imports::host::CHARACTERS.with(|seen| seen.borrow().len()),
            1,
            "a key-up makes no character"
        );
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
    /// and the rest answer 0, WM_ENDSESSION among them, WM_ERASEBKGND for a window there is none
    /// of; WM_NCCREATE and WM_QUERYENDSESSION TRUE, a logoff's WM_QUERYENDSESSION too.
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
        assert_eq!(def_window_proc_w(window, WM_ERASEBKGND, 0, 0), 0);
        assert_eq!(def_window_proc_a(window, WM_QUERYENDSESSION, 0, 0), 1);
        let logoff = ENDSESSION_LOGOFF as i32;
        assert_eq!(def_window_proc_w(window, WM_QUERYENDSESSION, 0, logoff), 1);
        assert_eq!(def_window_proc_a(window, WM_ENDSESSION, 1, 0), 0);
        assert_eq!(def_window_proc_w(window, WM_ENDSESSION, 0, logoff), 0);
        assert!(seen().is_empty());
    }

    /// guimsg `msgwait`: a flag MsgWaitForMultipleObjectsEx does not know fails it with
    /// ERROR_INVALID_PARAMETER, no service called.
    ///
    /// Pins: user32.MsgWaitForMultipleObjectsEx
    #[test]
    fn a_message_wait_with_an_unknown_flag_is_refused() {
        let services = crate::imports::host::SERVICES.with(|count| count.get());
        arm();
        // SAFETY: no handles are read.
        let answer =
            unsafe { msg_wait_for_multiple_objects_ex(0, core::ptr::null(), 0, 0xFF, 0x10) };
        assert_eq!(answer, WAIT_FAILED);
        assert_eq!(last_error(), rtl::winerror::ERROR_INVALID_PARAMETER);
        assert_eq!(
            crate::imports::host::SERVICES.with(|count| count.get()),
            services
        );
    }

    /// guimsg `quota`: a post a full queue refuses fails with the last error as it was; another
    /// refusal sets its error.
    ///
    /// Pins: user32.PostMessageW
    #[test]
    fn a_full_queue_leaves_the_last_error() {
        arm();
        let full = Err(NtStatus::from_win32(ERROR_NOT_ENOUGH_QUOTA));
        assert_eq!(posted(full, window_error), 0);
        assert_eq!(last_error(), UNSET);
        let gone = Err(NtStatus(rtl::status::STATUS_INVALID_HANDLE));
        assert_eq!(posted(gone, window_error), 0);
        assert_eq!(last_error(), 1400);
        assert_eq!(posted(Ok(()), window_error), 1);
    }

    /// guimsg `icon`: DefWindowProc keeps a window's big and small icons apart, WM_SETICON
    /// answering the one it replaces and WM_GETICON the one set (NULL before any, and after a NULL
    /// set); a big icon set while the window has no small one leaves ERROR_INVALID_HANDLE, and no
    /// other call touches the last error; the window's icons go with it.
    ///
    /// Pins: user32.DefWindowProcW
    #[test]
    fn the_icons_are_kept_big_and_small() {
        let (application, hand) = (0x1_0010, 0x1_0020);
        let window = window();
        let call = |message: u32, which: u32, icon: u32| {
            arm();
            let answer = def_window_proc_w(window, message, which, icon as i32) as u32;
            let error = last_error();
            (answer, (error != UNSET).then_some(error))
        };
        assert_eq!(call(WM_GETICON, ICON_BIG, 0), (0, None));
        assert_eq!(call(WM_GETICON, ICON_SMALL, 0), (0, None));
        assert_eq!(call(WM_SETICON, ICON_BIG, application), (0, Some(6)));
        assert_eq!(call(WM_GETICON, ICON_BIG, 0), (application, None));
        assert_eq!(call(WM_GETICON, ICON_SMALL, 0), (0, None));
        assert_eq!(call(WM_SETICON, ICON_SMALL, hand), (0, None));
        assert_eq!(call(WM_GETICON, ICON_SMALL, 0), (hand, None));
        assert_eq!(call(WM_SETICON, ICON_BIG, hand), (application, None));
        assert_eq!(call(WM_GETICON, ICON_BIG, 0), (hand, None));
        assert_eq!(call(WM_SETICON, ICON_BIG, 0), (hand, None));
        assert_eq!(call(WM_GETICON, ICON_BIG, 0), (0, None));
        assert_eq!(call(WM_GETICON, ICON_SMALL, 0), (hand, None));
        assert_eq!(call(WM_GETICON, 7, 0), (0, None));
        assert_eq!(def_window_proc_w(window, WM_CLOSE, 0, 0), 0);
        assert_eq!(icon_of(window, ICON_SMALL), 0, "its icons went with it");
    }

    /// guimsg `redraw`: WM_SETREDRAW FALSE clears the window's WS_VISIBLE, TRUE sets it again,
    /// both answering 0.
    ///
    /// Pins: user32.DefWindowProcW
    #[test]
    fn set_redraw_turns_the_visibility_off_and_on() {
        let window = window();
        crate::window::show_window(window, 5);
        let visible = || crate::window::style_of(window).unwrap() & 0x1000_0000 != 0;
        assert!(visible());
        assert_eq!(def_window_proc_w(window, WM_SETREDRAW, 0, 0), 0);
        assert!(!visible());
        assert_eq!(def_window_proc_w(window, WM_SETREDRAW, 1, 0), 0);
        assert!(visible());
    }

    /// guimsg `ctxmenu`: a child's WM_CONTEXTMENU reaches its parent's procedure as it came, and
    /// the child's DefWindowProc answers 0; a top-level window's goes nowhere.
    ///
    /// Pins: user32.DefWindowProcW
    #[test]
    fn a_childs_context_menu_goes_to_its_parent() {
        let parent = window();
        // SAFETY: the tests' own class name, registered by window().
        let child = unsafe {
            create_window_ex_a(
                0,
                c"F2KGuimsg".as_ptr().cast(),
                c"child".as_ptr().cast(),
                0x4000_0000,
                10,
                10,
                50,
                30,
                parent,
                0,
                0,
                0,
            )
        };
        assert_ne!(child, 0);
        seen();
        assert_eq!(
            def_window_proc_w(child, WM_CONTEXTMENU, child as u32, 0x0014_000A),
            0
        );
        assert_eq!(
            seen(),
            [(parent as u32, WM_CONTEXTMENU, child as u32, 0x0014_000A)]
        );
        assert_eq!(
            def_window_proc_w(parent, WM_CONTEXTMENU, parent as u32, 0),
            0
        );
        assert!(seen().is_empty());
    }

    /// DefWindowProc's WM_ERASEBKGND fills the client area with the class's background (a system
    /// color's index plus one), TRUE; a class with none is left, FALSE. WM_CTLCOLORBTN answers the
    /// 3D face's brush.
    ///
    /// Pins: user32.DefWindowProcW
    #[test]
    fn the_background_is_the_classs() {
        use crate::imports::host::canvas::{canvas, CANVAS_DC, PAPER};
        let window = window();
        assert_eq!(
            def_window_proc_w(window, WM_ERASEBKGND, CANVAS_DC as u32, 0),
            0
        );
        assert_eq!(canvas(|canvas| canvas.pixels[0]), PAPER);
        wm(|wm| {
            let atom = wm
                .windows
                .iter()
                .find(|w| w.handle as usize == window)
                .unwrap()
                .atom;
            wm.classes
                .iter_mut()
                .find(|c| c.atom == atom)
                .unwrap()
                .class
                .background = 6;
        });
        assert_eq!(
            def_window_proc_w(window, WM_ERASEBKGND, CANVAS_DC as u32, 0),
            1
        );
        assert_eq!(canvas(|canvas| canvas.pixels[0]), 0x00FF_FFFF);
        assert_eq!(
            def_window_proc_w(window, WM_CTLCOLORBTN, CANVAS_DC as u32, 0) as u32,
            rtl::gdi::sys_color_brush(15).unwrap()
        );
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

    /// SendMessageTimeout to a window of the calling thread calls its procedure at once, whatever
    /// the timeout, its answer into the result when one is given; a dead window is 1400, the
    /// result 0. SendNotifyMessage calls it before the return too.
    ///
    /// Pins: user32.SendMessageTimeoutW, user32.SendMessageTimeoutA, user32.SendNotifyMessageW,
    /// user32.SendNotifyMessageA
    #[test]
    fn the_timed_and_notifying_sends_call_the_thread_s_own_window() {
        let window = window();
        let mut result = UNSET;
        arm();
        // SAFETY: the tests' own DWORD.
        let answer = unsafe {
            send_message_timeout_w(window, WM_USER + 30, 3, 4, SMTO_NORMAL, 0, &mut result)
        };
        assert_eq!((answer, result, last_error()), (1, 0, UNSET));
        // SAFETY: no result pointer.
        let answer = unsafe {
            send_message_timeout_a(
                window,
                WM_USER + 30,
                5,
                6,
                SMTO_ABORTIFHUNG,
                1000,
                null_mut(),
            )
        };
        assert_eq!(answer, 1);
        assert_eq!(send_notify_message_w(window, WM_USER + 30, 1, 2), 1);
        assert_eq!(send_notify_message_a(window, WM_USER + 30, 7, 8), 1);
        assert_eq!(
            seen(),
            [
                (window as u32, WM_USER + 30, 3, 4),
                (window as u32, WM_USER + 30, 5, 6),
                (window as u32, WM_USER + 30, 1, 2),
                (window as u32, WM_USER + 30, 7, 8),
            ]
        );
        result = UNSET;
        // SAFETY: the tests' own DWORD.
        let answer = unsafe {
            send_message_timeout_w(0x7FFF_FFFC, WM_USER, 1, 1, SMTO_NORMAL, 1000, &mut result)
        };
        assert_eq!((answer, result, last_error()), (0, 0, 1400));
        arm();
        assert_eq!(send_notify_message_w(0x7FFF_FFFC, WM_USER, 1, 2), 0);
        assert_eq!(last_error(), 1400);
        arm();
        assert_eq!(is_hung_app_window(window), 0);
        assert_eq!(last_error(), UNSET);
        assert_eq!(is_hung_app_window(0x7FFF_FFFC), 0);
        assert_eq!(last_error(), 1400);
    }

    /// RegisterWindowMessage answers one message a name, in either form and any case, the
    /// clipboard format of that name; an empty name is ERROR_INVALID_NAME, none
    /// ERROR_INVALID_PARAMETER (the guimsg capture's).
    ///
    /// Pins: user32.RegisterWindowMessageW, user32.RegisterWindowMessageA
    #[test]
    fn a_registered_message_is_one_a_name() {
        let wide: std::vec::Vec<u16> = "F2KGuimsgRegistered\0".encode_utf16().collect();
        let other: std::vec::Vec<u16> = "f2kguimsgREGISTERED\0".encode_utf16().collect();
        let first = register_window_message_w(wide.as_ptr());
        assert!((0xC000..=0xFFFF).contains(&first));
        assert_eq!(register_window_message_w(other.as_ptr()), first);
        // SAFETY: NUL-terminated strings of the tests' own, and none.
        unsafe {
            assert_eq!(
                register_window_message_a(c"F2KGuimsgRegistered".as_ptr().cast()),
                first
            );
            assert_ne!(
                register_window_message_a(c"F2KGuimsgOther".as_ptr().cast()),
                first
            );
            arm();
            assert_eq!(register_window_message_a(c"".as_ptr().cast()), 0);
            assert_eq!(last_error(), 123);
            assert_eq!(register_window_message_a(core::ptr::null()), 0);
            assert_eq!(last_error(), 87);
        }
        assert_eq!(
            crate::clipboard::register_clipboard_format_w(wide.as_ptr()),
            first
        );
    }

    /// GetMessageTime and GetMessagePos answer the last message a read retrieved; WaitMessage
    /// returns when something is new to the queue.
    ///
    /// Pins: user32.GetMessageTime, user32.GetMessagePos, user32.WaitMessage
    #[test]
    fn the_last_message_s_time_and_place() {
        let window = window();
        post_message_a(window, WM_USER + 30, 1, 0);
        assert_eq!(wait_message(), 1);
        let (answer, msg) = peek(PM_NOREMOVE);
        assert_eq!(answer, 1);
        assert_eq!(get_message_time(), msg.time as i32);
        assert_eq!(
            get_message_pos(),
            (msg.pt.x as u16 as u32) | ((msg.pt.y as u16 as u32) << 16)
        );
        peek(PM_REMOVE);
    }
}
