//! The services: user32's calls into the message queues.

use rtl::pod::Pod;
use rtl::user::{
    Msg,
    MsgWait,
    Receipt,
    SendTimeout,
    COPY_DATA_HEAD,
    MWMO_ALERTABLE,
    MWMO_INPUTAVAILABLE,
    MWMO_WAITALL,
    ONE_PARAM_ENUM_CLIPBOARD_FORMATS,
    ONE_PARAM_GET_QUEUE_STATUS,
    ONE_PARAM_IN_SEND_MESSAGE,
    ONE_PARAM_IS_HUNG_APP_WINDOW,
    ONE_PARAM_POST_QUIT_MESSAGE,
    ONE_PARAM_REPLY_MESSAGE,
    ONE_PARAM_SHOW_CURSOR,
    RECEIVED_MESSAGE,
    RECEIVED_NONE,
    SMTO_ABORTIFHUNG,
    WM_COPYDATA,
    WM_SETTEXT,
};

use super::*;
use crate::nt::call::{Handle, NtCall, NtResult, UserAddr, UserPtr};
use crate::sched::thread::ThreadId;
use crate::sched::wait::{WaitableId, MAXIMUM_WAIT_OBJECTS};
use crate::status::*;
use crate::win32k::text::Staged;
use crate::win32k::window::{LResult, Session};
use crate::win32k::winsta::gui_thread;

/// NtUserPostMessage(Window, Msg, wParam, lParam): see [`post`].
pub fn post_message(
    call: &mut NtCall,
    window: Handle,
    message: u32,
    wparam: u32,
    lparam: i32,
) -> NtResult {
    let caller = gui_thread(call)?.thread;
    let time = millis(now());
    with_manager(call.passive(), |m| {
        post(
            &mut m.windows,
            caller,
            window.raw(),
            message,
            wparam,
            lparam,
            time,
        )
    })?;
    Ok(STATUS_SUCCESS)
}

/// NtUserPostThreadMessage(ThreadId, Msg, wParam, lParam): a thread message to the thread
/// whose client id is `thread_id`; [`INVALID_THREAD_ID`] when no thread that has not ended has
/// a queue of that id.
pub fn post_thread_message(
    call: &mut NtCall,
    thread_id: u32,
    message: u32,
    wparam: u32,
    lparam: i32,
) -> NtResult {
    gui_thread(call)?;
    let time = millis(now());
    let found = with_manager(call.passive(), |m| {
        queue_by_client_id(&m.windows, thread_id)
    });
    let (thread, key) = found.ok_or(INVALID_THREAD_ID)?;
    let running = crate::ob::locked(|directory| {
        directory.thread_object(crate::sched::thread::ThreadId(key.index))
    })
    .is_some_and(|object| object.generation == key.generation);
    if !running {
        return Err(INVALID_THREAD_ID);
    }
    with_manager(call.passive(), |m| {
        if m.windows.queues.queue_of(thread).is_none() {
            return Err(INVALID_THREAD_ID);
        }
        post_thread(&mut m.windows, thread, message, wparam, lparam, time)
    })?;
    Ok(STATUS_SUCCESS)
}

/// NtUserGetMessage(Receipt, Window, MsgFilterMin, MsgFilterMax): the next message the filter
/// takes, taken out, into the receipt, the messages sent to the caller delivered first by
/// callback ([`read_delivering`]); on a queue with none, the caller waits on its queue (until
/// its next timer's due, when it has timers). STATUS_INVALID_HANDLE when the filter names a
/// window there is not.
pub fn get_message(
    call: &mut NtCall,
    receipt: UserAddr,
    window: Handle,
    min: u32,
    max: u32,
) -> NtResult {
    let caller = gui_thread(call)?.thread;
    receipt.probe(core::mem::size_of::<Receipt>() as u32)?;
    let filter = Filter::new(window.raw(), min, max, 0);
    loop {
        let now = now();
        match read_delivering(call, caller, &filter, true, now)? {
            Taken::Nothing { due } => {
                let timeout = due.map(|due| due.saturating_sub(now) as i64);
                if timeout != Some(0) {
                    wait_on_queue(caller, timeout);
                }
            }
            taken => return write_receipt(receipt, taken),
        }
    }
}

/// NtUserPeekMessage(Receipt, Window, MsgFilterMin, MsgFilterMax, RemoveMsg): the next message
/// the filter takes, taken out with PM_REMOVE, into the receipt, the messages sent to the
/// caller delivered first by callback ([`read_delivering`]); RECEIVED_NONE when there is none.
pub fn peek_message(
    call: &mut NtCall,
    receipt: UserAddr,
    window: Handle,
    min: u32,
    max: u32,
    flags: u32,
) -> NtResult {
    let caller = gui_thread(call)?.thread;
    receipt.probe(core::mem::size_of::<Receipt>() as u32)?;
    let filter = Filter::new(window.raw(), min, max, flags);
    let remove = flags & rtl::user::PM_REMOVE != 0;
    let taken = read_delivering(call, caller, &filter, remove, now())?;
    write_receipt(receipt, taken)
}

/// A read of the caller's queue ([`take`]) at `now`: each sent message it hands out delivered
/// by callback before it reads on ([`receive_by_callback`]), as Windows 2000's reads receive
/// them first; a mouse message's window asked where its point is (WM_NCHITTEST,
/// [`crate::win32k::mouse::hit_test`]), and a mouse message read out followed by its
/// WM_MOUSEACTIVATE and WM_SETCURSOR ([`crate::win32k::mouse::after_read`]), eaten as they
/// say. What it took: a message, or nothing.
fn read_delivering(
    call: &mut NtCall,
    caller: ThreadId,
    filter: &Filter,
    remove: bool,
    now: u64,
) -> Result<Taken, NtStatus> {
    use crate::win32k::mouse;
    loop {
        let taken = with_session(call.passive(), |s| {
            let taken = take(s.windows(), caller, filter, remove, now)?;
            Ok::<_, NtStatus>(match taken {
                Taken::Sent(id) => {
                    receive_by_callback(&mut s.hold, caller, id);
                    None
                }
                Taken::Prepare {
                    entry,
                    window,
                    pt,
                    captured,
                } => {
                    let hit = mouse::hit_test(s, window, pt, captured);
                    let (windows, classes) = s.parts();
                    if windows.is_live(window) {
                        let prepared = mouse::prepared(windows, classes, window, pt, hit);
                        keep_prepared(windows, caller, entry, prepared);
                    }
                    None
                }
                Taken::Mouse(read) => {
                    mouse::after_read(s, caller, &read).then_some(Taken::Message(read.msg))
                }
                other => Some(other),
            })
        })?;
        if let Some(taken) = taken {
            return Ok(taken);
        }
    }
}

/// Deliver by callback every message sent to the caller ([`take_for_callback`]), oldest first.
fn receive_all(call: &mut NtCall, caller: ThreadId) {
    with_session(call.passive(), |s| {
        while let Some(id) = take_for_callback(s.windows(), caller) {
            receive_by_callback(&mut s.hold, caller, id);
        }
    });
}

/// Write what a read took into the caller's receipt.
fn write_receipt(receipt: UserAddr, taken: Taken) -> NtResult {
    let written = match taken {
        Taken::Message(msg) => Receipt {
            kind: Taken::kind_of(&msg),
            msg,
        },
        Taken::Mouse(read) => Receipt {
            kind: RECEIVED_MESSAGE,
            msg: read.msg,
        },
        Taken::Nothing { .. } | Taken::Sent(_) | Taken::Prepare { .. } => Receipt {
            kind: RECEIVED_NONE,
            msg: Msg::default(),
        },
    };
    receipt.cast::<Receipt>().write(written)?;
    Ok(STATUS_SUCCESS)
}

/// NtUserCallTwoParam's TWO_PARAM_MSG_WAIT: MsgWaitForMultipleObjects' wait ([`MsgWait`] at
/// `args`), a wait-any on the handles and the caller's queue: the count when input of the
/// wake mask's kinds came to the queue since a read last looked for it ([`wait_ready_with`]:
/// a timer coming due counts; with MWMO_INPUTAVAILABLE, input the queue holds counts too),
/// before the wait or while it lasts; otherwise the objects' wait status (WAIT_OBJECT_0 + n,
/// WAIT_ABANDONED_0 + n, WAIT_TIMEOUT). With MWMO_WAITALL, the input and every object, as one
/// wait-all on the objects and the queue's event (guimsg `msgwait`: signaled objects and no
/// input time out): the objects are waited for, and taken, once the input is there,
/// WAIT_OBJECT_0 when they all are. With MWMO_ALERTABLE, the caller's user APCs end the wait
/// (WAIT_IO_COMPLETION, the APCs run on its way out). STATUS_INVALID_PARAMETER for 64 handles
/// or more; a handle's refusal as NtWaitForMultipleObjects' (STATUS_INVALID_HANDLE...).
pub fn msg_wait(call: &mut NtCall, args: UserAddr) -> Result<u32, NtStatus> {
    let caller = gui_thread(call)?.thread;
    let wait = args.cast::<MsgWait>().read()?;
    let count = wait.count as usize;
    if count >= MAXIMUM_WAIT_OBJECTS {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let mut raw = [0u32; MAXIMUM_WAIT_OBJECTS];
    UserAddr(wait.handles).read(&mut raw.as_bytes_mut()[..4 * count])?;
    let mut objects = [WaitableId::Event(0); MAXIMUM_WAIT_OBJECTS];
    let mut held = [crate::ob::ObjectId {
        kind: crate::ob::ObjectType::Event,
        index: 0,
        generation: 0,
    }; MAXIMUM_WAIT_OBJECTS];
    for ((object, id), &handle) in objects.iter_mut().zip(&mut held).zip(&raw[..count]) {
        (*id, *object) = crate::nt::sync::waitable_of(handle)?;
    }
    let objects = &objects[..count];
    let wait_all = wait.flags & MWMO_WAITALL != 0;
    let alertable = wait.flags & MWMO_ALERTABLE != 0;
    let available = wait.flags & MWMO_INPUTAVAILABLE != 0;
    crate::nt::wait::check_objects(objects, wait_all)?;
    // A wait-all waits on the queue alone until the input is there.
    let with_queue = if wait_all { &objects[..0] } else { objects };
    let deadline = (wait.timeout != u32::MAX).then(|| now() + u64::from(wait.timeout) * 10_000);
    let passive = call.passive();
    crate::ob::waiting(&held[..count], || loop {
        let at = now();
        let due = match with_manager(passive, |m| {
            wait_ready_with(&mut m.windows, caller, at, wait.wake_mask, available)
        }) {
            Waited::Ready if !wait_all => return wait.count,
            Waited::Ready if objects.is_empty() => return STATUS_SUCCESS.0,
            Waited::Ready => {
                let timeout = deadline.map(|deadline| deadline.saturating_sub(at) as i64);
                return wait_on_objects(objects, true, alertable, timeout).0;
            }
            Waited::Wait { due } => due,
        };
        let end = match (deadline, due) {
            (Some(deadline), Some(due)) => Some(deadline.min(due)),
            (deadline, due) => deadline.or(due),
        };
        let timeout = end.map(|end| end.saturating_sub(at) as i64);
        let status = wait_on_objects_or_queue(caller, with_queue, alertable, timeout);
        if status == STATUS_TIMEOUT && deadline.is_none_or(|deadline| now() < deadline) {
            // A timer's due, not the caller's: look again.
            continue;
        }
        if status.0 != with_queue.len() as u32 {
            return status.0;
        }
    })
    .ok_or(STATUS_INVALID_HANDLE)
}

/// NtUserMessageCall(Window, Msg, wParam, lParam, Proc, Result, Timeout): SendMessage's and
/// SendMessageTimeout's kernel side ([`send`]): into `proc` the procedure to call for a window
/// of the caller's own thread, otherwise 0, and the answer into `result`, the caller waiting
/// for another thread's and delivering the messages sent to it meanwhile, as Windows 2000's
/// SendMessage does ([`receive_by_callback`]). With a timeout (rtl::user::SendTimeout; null for
/// SendMessage) the wait ends at its end, an unread message taken back ([`abandon_send`]), and
/// at once with SMTO_ABORTIFHUNG for a hung receiver ([`window_hung`]): STATUS_TIMEOUT
/// (user32's ERROR_TIMEOUT), `result` 0. STATUS_INVALID_HANDLE when the receiving thread ends
/// before it answers, its window gone with it ([`Awaited::Failed`]).
#[allow(clippy::too_many_arguments)]
pub fn message_call(
    call: &mut NtCall,
    window: Handle,
    message: u32,
    wparam: u32,
    lparam: i32,
    proc: UserPtr<u32>,
    result: UserPtr<i32>,
    timeout: UserAddr,
) -> NtResult {
    let thread = gui_thread(call)?;
    let caller = thread.thread;
    proc.write(0)?;
    result.write(0)?;
    let limit = match timeout.raw() {
        0 => None,
        _ => Some(timeout.cast::<SendTimeout>().read()?),
    };
    let (id, deadline) = match start_send(call, thread, window, message, wparam, lparam, limit)? {
        Started::Waiting(id, deadline) => (id, deadline),
        Started::Call(target) => {
            proc.write(target)?;
            return Ok(STATUS_SUCCESS);
        }
        Started::Answered(answer) => {
            result.write(answer)?;
            return Ok(STATUS_SUCCESS);
        }
        Started::Hung => return Ok(STATUS_TIMEOUT),
    };
    loop {
        let reply = with_session(call.passive(), |s| {
            let windows = s.windows();
            // WM_GETTEXT's text, as much as the sender's buffer holds.
            let got = answered_text(windows, id).map(|text| {
                let fits = text.len().min((wparam as usize).saturating_sub(1));
                Staged::copy_of(&text[..fits])
            });
            let awaited = await_reply(windows, caller, id);
            // A message sent to the waiting thread meanwhile, delivered first.
            let received = match awaited {
                Awaited::Wait => take_for_callback(s.windows(), caller),
                _ => None,
            };
            if let Some(sent) = received {
                receive_by_callback(&mut s.hold, caller, sent);
            }
            (awaited, got, received.is_some())
        });
        match reply {
            (Awaited::Answer(answer), got, _) => {
                if let (Some(got), true) = (got, lparam != 0 && wparam > 0) {
                    // Into the sender's buffer, terminated.
                    let got = got.ok_or(STATUS_NO_MEMORY)?;
                    got.write_terminated(UserAddr(lparam as u32), wparam as usize)?;
                }
                result.write(answer)?;
                return Ok(STATUS_SUCCESS);
            }
            // The receiving thread ended, its window with it (user32's 1400).
            (Awaited::Failed, ..) => return Err(STATUS_INVALID_HANDLE),
            // One delivered: look again before waiting.
            (Awaited::Wait, _, true) => {}
            (Awaited::Wait, _, false) => match deadline {
                None => wait_on_queue(caller, None),
                Some(deadline) => {
                    let now = now();
                    if now >= deadline {
                        with_manager(call.passive(), |m| abandon_send(&mut m.windows, caller, id));
                        return Ok(STATUS_TIMEOUT);
                    }
                    wait_on_queue(caller, Some((deadline - now) as i64));
                }
            },
        }
    }
}

/// WM_COPYDATA's COPYDATASTRUCT at `at` and the bytes it names, read from the sender, staged
/// in their carried form (rtl::user's COPY_DATA_HEAD): dwData, cbData, a zero lpData, then the
/// bytes, two a unit. STATUS_ACCESS_VIOLATION for what the caller's memory does not hold,
/// STATUS_NO_MEMORY when the pool has no room.
fn read_copy_data(at: UserAddr) -> Result<Staged, NtStatus> {
    let [data, count, bytes] = at.cast::<[u32; 3]>().read()?;
    let count = count as usize;
    let mut staged =
        Staged::with_length(COPY_DATA_HEAD + count.div_ceil(2)).ok_or(STATUS_NO_MEMORY)?;
    let units = staged.units_mut();
    units[..COPY_DATA_HEAD].copy_from_slice(&[
        data as u16,
        (data >> 16) as u16,
        count as u16,
        (count >> 16) as u16,
        0,
        0,
    ]);
    let mut buffer = [0u8; 256];
    let mut done = 0;
    while done < count {
        let part = (count - done).min(buffer.len());
        UserAddr(bytes)
            .offset(done as u32)
            .read(&mut buffer[..part])?;
        for (at, &byte) in buffer[..part].iter().enumerate() {
            let index = done + at;
            units[COPY_DATA_HEAD + index / 2] |= u16::from(byte) << (8 * (index % 2));
        }
        done += part;
    }
    Ok(staged)
}

/// How [`message_call`]'s fresh send started.
enum Started {
    /// Queued for another thread: the send to wait on, and its deadline.
    Waiting(SentId, Option<u64>),
    /// A window of the caller's own thread: the procedure user32 calls.
    Call(u32),
    /// Answered already.
    Answered(LResult),
    /// SMTO_ABORTIFHUNG, to a hung thread: not sent.
    Hung,
}

/// [`message_call`]'s fresh send: SMTO_ABORTIFHUNG's look at the receiver, WM_SETTEXT's
/// carried text read whole, and the send ([`Started`]).
#[allow(clippy::too_many_arguments)]
fn start_send(
    call: &mut NtCall,
    thread: crate::win32k::winsta::GuiThread,
    window: Handle,
    message: u32,
    wparam: u32,
    lparam: i32,
    limit: Option<SendTimeout>,
) -> Result<Started, NtStatus> {
    let caller = thread.thread;
    if limit.is_some_and(|l| l.flags & SMTO_ABORTIFHUNG != 0) {
        let time = millis(now());
        let hung = with_manager(call.passive(), |m| {
            window_hung(&m.windows, caller, window.raw(), time)
        })?;
        if hung {
            return Ok(Started::Hung);
        }
    }
    let deadline = limit.map(|l| now() + u64::from(l.timeout) * 10_000);
    // A text message to another process's window carries its text (user32 hands such a
    // message over in the wide form): WM_SETTEXT's read here, WM_GETTEXT's written back once
    // answered.
    let carried = with_manager(call.passive(), |m| {
        carries_text(&m.windows, thread.owner, window.raw(), message)
    });
    // A null lParam goes as it is (WM_SETTEXT's NULL, WM_COPYDATA's none).
    let carried = carried && lparam != 0;
    let text = match message {
        WM_SETTEXT if carried => Staged::read(UserAddr(lparam as u32))?,
        WM_COPYDATA if carried => read_copy_data(UserAddr(lparam as u32))?,
        _ => Staged::read(UserAddr(0))?,
    };
    let sending = with_manager(call.passive(), |m| {
        let sending = send_carrying(
            &mut m.windows,
            caller,
            window.raw(),
            message,
            wparam,
            lparam,
            carried.then_some(text.units()),
        );
        sending
    })?;
    Ok(match sending {
        Sending::Waiting(id) => Started::Waiting(id, deadline),
        Sending::Call(target) => Started::Call(target),
        Sending::Answered(answer) => Started::Answered(answer),
    })
}

/// NtUserSendNotifyMessage(Window, Msg, wParam, lParam, Proc): SendNotifyMessage's kernel
/// side ([`send_notify`]): the procedure to call into `proc` for a window of the caller's own
/// thread, 0 otherwise (the message queued for another thread's, or answered by the window
/// manager's procedure).
pub fn send_notify_message(
    call: &mut NtCall,
    window: Handle,
    message: u32,
    wparam: u32,
    lparam: i32,
    proc: UserPtr<u32>,
) -> NtResult {
    let caller = gui_thread(call)?.thread;
    let sending = with_manager(call.passive(), |m| {
        send_notify(
            &mut m.windows,
            caller,
            window.raw(),
            message,
            wparam,
            lparam,
        )
    })?;
    proc.write(match sending {
        Sending::Call(target) => target,
        _ => 0,
    })?;
    Ok(STATUS_SUCCESS)
}

/// NtUserSendMessageCallback(Window, Msg, wParam, lParam, Callback, Data, Proc, Result):
/// SendMessageCallback's kernel side ([`send_callback`]): the procedure to call for a window
/// of the caller's own thread into `proc`, user32 calling the callback after it; for a window
/// whose procedure is the window manager's, `proc` 0 and the answer into `result`, user32
/// calling the callback with it; STATUS_PENDING for a message queued for another thread, its
/// answer to reach the callback on a later read.
#[allow(clippy::too_many_arguments)]
pub fn send_message_callback(
    call: &mut NtCall,
    window: Handle,
    message: u32,
    wparam: u32,
    lparam: i32,
    callback: u32,
    data: u32,
    proc: UserPtr<u32>,
    result: UserPtr<i32>,
) -> NtResult {
    let caller = gui_thread(call)?.thread;
    proc.write(0)?;
    result.write(0)?;
    let sending = with_manager(call.passive(), |m| {
        send_callback(
            &mut m.windows,
            caller,
            window.raw(),
            message,
            wparam,
            lparam,
            callback,
            data,
        )
    })?;
    match sending {
        Sending::Call(target) => proc.write(target)?,
        Sending::Answered(answer) => result.write(answer)?,
        Sending::Waiting(_) => return Ok(STATUS_PENDING),
    }
    Ok(STATUS_SUCCESS)
}

/// NtUserWaitMessage(): the caller waits on its queue until something new comes to it
/// ([`wait_ready`]), its timers' dues waking it to look; the messages sent to it are delivered
/// by callback before it returns.
pub fn wait_message(call: &mut NtCall) -> NtResult {
    let caller = gui_thread(call)?.thread;
    loop {
        let now = now();
        match with_manager(call.passive(), |m| wait_ready(&mut m.windows, caller, now)) {
            Waited::Ready => {
                receive_all(call, caller);
                return Ok(STATUS_SUCCESS);
            }
            Waited::Wait { due } => {
                let timeout = due.map(|due| due.saturating_sub(now) as i64);
                if timeout != Some(0) {
                    wait_on_queue(caller, timeout);
                }
            }
        }
    }
}

/// NtUserDispatchMessage(Msg, Proc): the procedure DispatchMessage calls with the message
/// ([`dispatch_target`]) into `proc`.
pub fn dispatch_message(call: &mut NtCall, msg: UserAddr, proc: UserPtr<u32>) -> NtResult {
    let caller = gui_thread(call)?.thread;
    let msg = msg.cast::<Msg>().read()?;
    let target = with_manager(call.passive(), |m| {
        dispatch_target(&m.windows, caller, &msg)
    })?;
    proc.write(target)?;
    Ok(STATUS_SUCCESS)
}

/// NtUserCallOneParam(Param, Routine, Result): PostQuitMessage (the result 0), ReplyMessage
/// (the result whether it answered another thread's message), EnumClipboardFormats (the
/// result the format after the parameter's), InSendMessage (the result whether another thread
/// sent the message being delivered), IsHungAppWindow, ShowCursor (the result the new display
/// count), GetQueueStatus (the parameter the flags; the result [`queue_status`]'s);
/// STATUS_INVALID_PARAMETER for another routine.
pub fn call_one_param(
    call: &mut NtCall,
    param: u32,
    routine: u32,
    result: UserPtr<u32>,
) -> NtResult {
    let caller = gui_thread(call)?.thread;
    let time = millis(now());
    let answer = with_manager(call.passive(), |m| match routine {
        ONE_PARAM_POST_QUIT_MESSAGE => {
            post_quit(&mut m.windows, caller, param);
            Ok(0)
        }
        ONE_PARAM_REPLY_MESSAGE => Ok(reply(&mut m.windows, caller, param as LResult) as u32),
        ONE_PARAM_ENUM_CLIPBOARD_FORMATS => m
            .clipboard
            .next_format(caller, param)
            .map_err(crate::win32k::clipboard::Refusal::status),
        ONE_PARAM_IN_SEND_MESSAGE => Ok(in_send(&m.windows, caller) as u32),
        ONE_PARAM_IS_HUNG_APP_WINDOW => {
            window_hung(&m.windows, caller, param, time).map(|hung| hung as u32)
        }
        ONE_PARAM_SHOW_CURSOR => Ok(show_cursor(&mut m.windows, caller, param != 0) as u32),
        ONE_PARAM_GET_QUEUE_STATUS => Ok(queue_status(&mut m.windows, caller, now(), param)),
        _ => Err(STATUS_INVALID_PARAMETER),
    })?;
    result.write(answer)?;
    Ok(STATUS_SUCCESS)
}
