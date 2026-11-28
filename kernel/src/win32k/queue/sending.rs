//! Sending: SendMessage, SendNotifyMessage and SendMessageCallback to another thread.

use rtl::user::{sync_only, WM_COPYDATA, WM_GETTEXT, WM_SETTEXT};
use rtl::winerror::{ERROR_INVALID_THREAD_ID, ERROR_MESSAGE_SYNC_ONLY};

use super::*;
use crate::sched::thread::ThreadId;
use crate::status::*;
use crate::win32k::class;
use crate::win32k::window::{Hwnd, LParam, LResult, WParam, Windows};

/// Where SendMessage's message goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sending {
    /// A window of the caller's own thread: user32 calls this procedure itself.
    Call(u32),
    /// Answered already: a window whose procedure is the window manager's, or a thread with no
    /// queue to deliver to.
    Answered(LResult),
    /// Queued for the window's thread: the caller waits for the answer ([`collect_reply`]).
    Waiting(SentId),
}

/// SendMessage's step: see [`Sending`]. STATUS_INVALID_HANDLE for a handle naming no window,
/// STATUS_NO_MEMORY when the sent messages' pool cannot grow. (The service sends through
/// [`send_carrying`].)
#[cfg(test)]
pub fn send(
    windows: &mut Windows,
    caller: ThreadId,
    hwnd: Hwnd,
    message: u32,
    wparam: WParam,
    lparam: LParam,
) -> Result<Sending, NtStatus> {
    send_carrying(windows, caller, hwnd, message, wparam, lparam, None)
}

/// Whether `message` to the window `hwnd` from a thread of the process `caller` is a message whose
/// text goes through the window manager (WM_SETTEXT, WM_GETTEXT to another process's window, whose
/// address space the sender's pointer does not reach), or whose data does (WM_COPYDATA's, carried
/// as units: rtl::user's COPY_DATA_HEAD).
pub fn carries_text(windows: &Windows, caller: class::Owner, hwnd: Hwnd, message: u32) -> bool {
    if !matches!(message, WM_SETTEXT | WM_GETTEXT | WM_COPYDATA) {
        return false;
    }
    windows
        .window_from_handle(hwnd)
        .is_some_and(|w| windows.client_proc(w).is_some() && windows.window_process(w) != caller)
}

/// [`send`], WM_SETTEXT's `text` (wide, read from the sender), WM_COPYDATA's data or WM_GETTEXT's
/// answer carried through the window manager when `text` is some ([`carries_text`]), as long as
/// it is, in the queues' store: the callback that delivers it carries it in its block
/// ([`delivery`]), WM_GETTEXT's answer coming back from it ([`keep_text_reply`]).
#[allow(clippy::too_many_arguments)]
pub fn send_carrying(
    windows: &mut Windows,
    caller: ThreadId,
    hwnd: Hwnd,
    message: u32,
    wparam: WParam,
    lparam: LParam,
    text: Option<&[u16]>,
) -> Result<Sending, NtStatus> {
    let window = windows
        .window_from_handle(hwnd)
        .ok_or(STATUS_INVALID_HANDLE)?;
    let Some(proc) = windows.client_proc(window) else {
        return Ok(Sending::Answered(default_answer(message)));
    };
    let thread = windows.window_thread(window);
    if thread == caller {
        return Ok(Sending::Call(proc));
    }
    let queues = &mut windows.queues;
    let (Some(receiver), Some(sender)) = (queues.queue_of(thread), queues.queue_of(caller)) else {
        return Ok(Sending::Answered(0));
    };
    let carried = match text {
        Some(text) => Carried::Text(queues.store.store(text).ok_or(STATUS_NO_MEMORY)?),
        None => Carried::None,
    };
    let Some(id) = queues.allocate_sent(Sent {
        receiver: Some(receiver),
        sender: Some(sender),
        window: Some(window),
        hwnd,
        proc,
        message,
        wparam,
        lparam,
        carried,
        ..Sent::EMPTY
    }) else {
        if let Carried::Text(text) = carried {
            queues.store.free(text);
        }
        return Err(STATUS_NO_MEMORY);
    };
    queues.push_sent(receiver, id);
    Ok(Sending::Waiting(id))
}

/// ERROR_MESSAGE_SYNC_ONLY (1159), the Win32 error itself in a FACILITY_NTWIN32 status: a message
/// whose pointer cannot go to another thread ([`rtl::user::sync_only`]).
pub const MESSAGE_SYNC_ONLY: NtStatus = NtStatus::from_win32(ERROR_MESSAGE_SYNC_ONLY);

/// ERROR_INVALID_THREAD_ID (1444), carried as [`MESSAGE_SYNC_ONLY`] is: a thread id no thread with
/// a queue has.
pub const INVALID_THREAD_ID: NtStatus = NtStatus::from_win32(ERROR_INVALID_THREAD_ID);

/// SendNotifyMessage's step: a window of the caller's own thread is called as SendMessage calls
/// it ([`Sending::Call`]); a window whose procedure is the window manager's answered; another
/// thread's window has the message queued for its thread as a sent one, its answer waited for by
/// nobody ([`Sending::Answered`] 0 at once). STATUS_INVALID_HANDLE for a handle naming no window,
/// [`MESSAGE_SYNC_ONLY`] for a message whose pointer cannot go to another thread, STATUS_NO_MEMORY
/// when the sent messages' pool cannot grow.
pub fn send_notify(
    windows: &mut Windows,
    caller: ThreadId,
    hwnd: Hwnd,
    message: u32,
    wparam: WParam,
    lparam: LParam,
) -> Result<Sending, NtStatus> {
    let window = windows
        .window_from_handle(hwnd)
        .ok_or(STATUS_INVALID_HANDLE)?;
    let Some(proc) = windows.client_proc(window) else {
        return Ok(Sending::Answered(default_answer(message)));
    };
    let thread = windows.window_thread(window);
    if thread == caller {
        return Ok(Sending::Call(proc));
    }
    if sync_only(message) {
        return Err(MESSAGE_SYNC_ONLY);
    }
    let queues = &mut windows.queues;
    let Some(receiver) = queues.queue_of(thread) else {
        return Ok(Sending::Answered(0));
    };
    let id = queues
        .allocate_sent(Sent {
            receiver: Some(receiver),
            notify: true,
            window: Some(window),
            hwnd,
            proc,
            message,
            wparam,
            lparam,
            ..Sent::EMPTY
        })
        .ok_or(STATUS_NO_MEMORY)?;
    queues.push_sent(receiver, id);
    Ok(Sending::Answered(0))
}

/// SendMessageCallback's step: as [`send_notify`]'s, but another thread's window has the message
/// queued with the caller's `callback` and `data`, its answer coming back to the caller as a sent
/// message that calls the callback on the caller's next read ([`Queues::answer`]); a window of
/// the caller's own thread is called ([`Sending::Call`]) and one whose procedure is the window
/// manager's answered at once, user32 calling the callback itself then.
#[allow(clippy::too_many_arguments)]
pub fn send_callback(
    windows: &mut Windows,
    caller: ThreadId,
    hwnd: Hwnd,
    message: u32,
    wparam: WParam,
    lparam: LParam,
    callback: u32,
    data: u32,
) -> Result<Sending, NtStatus> {
    let window = windows
        .window_from_handle(hwnd)
        .ok_or(STATUS_INVALID_HANDLE)?;
    let Some(proc) = windows.client_proc(window) else {
        return Ok(Sending::Answered(default_answer(message)));
    };
    let thread = windows.window_thread(window);
    if thread == caller {
        return Ok(Sending::Call(proc));
    }
    if sync_only(message) {
        return Err(MESSAGE_SYNC_ONLY);
    }
    let queues = &mut windows.queues;
    let (Some(receiver), Some(sender)) = (queues.queue_of(thread), queues.queue_of(caller)) else {
        return Ok(Sending::Answered(0));
    };
    let id = queues
        .allocate_sent(Sent {
            receiver: Some(receiver),
            carried: Carried::Callback(Callback {
                proc: callback,
                data,
                sender,
            }),
            window: Some(window),
            hwnd,
            proc,
            message,
            wparam,
            lparam,
            ..Sent::EMPTY
        })
        .ok_or(STATUS_NO_MEMORY)?;
    queues.push_sent(receiver, id);
    Ok(Sending::Waiting(id))
}

/// The caller's send `id` timed out (SendMessageTimeout): a message its receiver has not read yet
/// is taken back, never to reach the procedure, as Windows 2000 takes it; one being handled is
/// left to it, its answer to nobody.
pub fn abandon_send(windows: &mut Windows, caller: ThreadId, id: SentId) {
    let queues = &mut windows.queues;
    let Some(sent) = queues.sent_at(id) else {
        return;
    };
    if sent.sender != queues.queue_of(caller) {
        return;
    }
    match (sent.state, sent.receiver) {
        (State::Queued, Some(receiver)) => {
            queues.unlink_sent(receiver, id);
            queues.free_sent(id);
        }
        (State::Answered | State::Dropped, _) => queues.free_sent(id),
        _ => queues.sent.at_mut(id).sender = None,
    }
}

/// The answer to the caller's send `id`, once its receiver gave it (the record goes back to the
/// pool); none while it waits.
pub fn collect_reply(windows: &mut Windows, caller: ThreadId, id: SentId) -> Option<LResult> {
    let queues = &mut windows.queues;
    let sent = queues.sent_at(id)?;
    if !matches!(sent.state, State::Answered | State::Replied)
        || sent.sender != queues.queue_of(caller)
    {
        return None;
    }
    let result = sent.result;
    queues.collected(id);
    Some(result)
}

/// What a sender found as it waits for the answer to its send ([`await_reply`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Awaited {
    /// The answer: the record went back to the pool.
    Answer(LResult),
    /// Nothing yet: the sender delivers the messages sent to it meanwhile
    /// ([`take_for_callback`]), as Windows 2000's SendMessage handles them while it waits, and
    /// waits on its queue.
    Wait,
    /// Never to be answered: the receiving thread ended first, its windows gone with it. The
    /// record went back to the pool; SendMessage fails (Windows 2000's fails when its receiver
    /// dies).
    Failed,
}

/// The caller's wait for the answer to its send `id`, one look: the answer once it came
/// ([`collect_reply`]), or the failure once its receiver ended; otherwise the caller delivers what
/// was sent to it meanwhile and waits on ([`Awaited::Wait`]).
pub fn await_reply(windows: &mut Windows, caller: ThreadId, id: SentId) -> Awaited {
    if let Some(answer) = collect_reply(windows, caller, id) {
        return Awaited::Answer(answer);
    }
    let queues = &mut windows.queues;
    if queues.sent_at(id).is_some_and(|s| {
        s.state == State::Dropped && s.sender.is_some() && s.sender == queues.queue_of(caller)
    }) {
        queues.free_sent(id);
        return Awaited::Failed;
    }
    Awaited::Wait
}

#[cfg(test)]
mod tests {
    use rtl::user::{
        QS_ALLINPUT,
        QS_SENDMESSAGE,
        WM_DESTROY,
        WM_NCCREATE,
        WM_NCDESTROY,
        WM_QUERYENDSESSION,
        WM_USER,
    };

    use super::*;
    use crate::win32k::queue::testkit::*;
    use crate::win32k::window::{ThreadKey, WindowManager};

    /// SendMessage: a window of the caller's own thread names its procedure; the window
    /// manager's own windows answer as the default procedure; another thread's window queues the
    /// message for that thread, whose procedure's answer the sender collects.
    #[test]
    fn a_send_to_another_thread_waits_for_its_answer() {
        let (m, atom) = manager();
        let a = thread(m, 1, 0x100);
        let b = thread(m, 2, 0x200);
        let ha = popup(m, atom, a);
        let hb = popup(m, atom, b);
        deliver(m, a);
        deliver(m, b);
        assert_eq!(
            send(&mut m.windows, a, ha, WM_USER, 0, 0),
            Ok(Sending::Call(PROC))
        );
        let desktop = m.windows.thread_desktop_window(a).unwrap();
        let desktop = m.windows.handle_of(desktop);
        assert_eq!(
            send(&mut m.windows, a, desktop, WM_NCCREATE, 0, 0),
            Ok(Sending::Answered(1))
        );
        assert_eq!(
            send(&mut m.windows, a, 0x7FFF_FFFC, WM_USER, 0, 0),
            Err(STATUS_INVALID_HANDLE)
        );

        m.windows.queues.take_wakes();
        let Ok(Sending::Waiting(id)) = send(&mut m.windows, a, hb, WM_USER + 6, 55, 66) else {
            panic!("queued for the other thread");
        };
        assert!(
            m.windows.queues.take_wakes().is_only(b),
            "the receiver woken"
        );
        assert_eq!(collect_reply(&mut m.windows, a, id), None);
        let Taken::Sent(got) = read(m, b, &all(), 0) else {
            panic!("the receiver reads it");
        };
        let head = head_of(&m.windows, got).unwrap();
        assert_eq!(
            (
                head.msg.hwnd,
                head.msg.message,
                head.msg.wparam,
                head.msg.lparam
            ),
            (hb, WM_USER + 6, 55, 66)
        );
        assert!(end_sent(&mut m.windows, b, 42));
        assert!(m.windows.queues.take_wakes().is_only(a), "the sender woken");
        assert_eq!(collect_reply(&mut m.windows, a, id), Some(42));
        assert_eq!(collect_reply(&mut m.windows, a, id), None, "collected once");

        // ReplyMessage answers before the procedure returns; the end's answer is dropped.
        let Ok(Sending::Waiting(id)) = send(&mut m.windows, a, hb, WM_USER, 0, 0) else {
            panic!("queued");
        };
        assert!(!reply(&mut m.windows, b, 1), "nothing handed out yet");
        read(m, b, &all(), 0);
        assert!(reply(&mut m.windows, b, 5));
        assert!(!reply(&mut m.windows, b, 6), "answered already");
        assert!(end_sent(&mut m.windows, b, 9));
        assert_eq!(collect_reply(&mut m.windows, a, id), Some(5));
    }

    /// A send ReplyMessage answered stays its receiver's until the delivery ends, even once its
    /// sender took the answer: the receiver's stack of deliveries keeps the send beneath it, whose
    /// delivery then ends with its own answer; the record goes back to the pool at the end. The
    /// server's sends the same.
    #[test]
    fn a_replied_send_collected_early_stays_on_its_receiver_s_stack() {
        let (m, atom) = manager();
        let a = thread(m, 1, 0x100);
        let b = thread(m, 2, 0x200);
        let c = thread(m, 3, 0x300);
        let hb = popup(m, atom, b);
        deliver(m, b);
        let Ok(Sending::Waiting(outer)) = send(&mut m.windows, a, hb, WM_USER, 1, 0) else {
            panic!("queued");
        };
        assert!(matches!(read(m, b, &all(), 0), Taken::Sent(_)));
        let Ok(Sending::Waiting(inner)) = send(&mut m.windows, c, hb, WM_USER, 2, 0) else {
            panic!("queued");
        };
        assert!(matches!(read(m, b, &all(), 0), Taken::Sent(_)), "nested");
        assert!(reply(&mut m.windows, b, 7));
        assert_eq!(collect_reply(&mut m.windows, c, inner), Some(7));
        assert_eq!(
            collect_reply(&mut m.windows, c, inner),
            None,
            "collected once"
        );
        assert!(end_sent(&mut m.windows, b, 9), "the inner delivery ends");
        assert!(
            end_sent(&mut m.windows, b, 8),
            "the outer one is still there"
        );
        assert!(!end_sent(&mut m.windows, b, 0), "nothing left");
        assert_eq!(collect_reply(&mut m.windows, a, outer), Some(8));
        assert_eq!(live_sends(m), 0, "every record back");

        // Answered early and abandoned by its sender: the end of the delivery frees it.
        let Ok(Sending::Waiting(id)) = send(&mut m.windows, a, hb, WM_USER, 3, 0) else {
            panic!("queued");
        };
        assert!(matches!(read(m, b, &all(), 0), Taken::Sent(_)));
        assert!(reply(&mut m.windows, b, 4));
        abandon_send(&mut m.windows, a, id);
        assert!(end_sent(&mut m.windows, b, 0));
        assert_eq!(live_sends(m), 0);

        // Answered early, collected after the delivery's end: as before.
        let Ok(Sending::Waiting(id)) = send(&mut m.windows, a, hb, WM_USER, 3, 0) else {
            panic!("queued");
        };
        assert!(matches!(read(m, b, &all(), 0), Taken::Sent(_)));
        assert!(reply(&mut m.windows, b, 4));
        assert!(end_sent(&mut m.windows, b, 0));
        assert_eq!(collect_reply(&mut m.windows, a, id), Some(4));
        assert_eq!(live_sends(m), 0);

        // The server's: taken early, freed at the delivery's end.
        let ServerSending::Waiting(id) = server_send(&mut m.windows, hb, WM_QUERYENDSESSION, 0, 0)
        else {
            panic!("queued");
        };
        assert!(matches!(read(m, b, &all(), 0), Taken::Sent(_)));
        assert!(reply(&mut m.windows, b, 1));
        assert_eq!(
            server_reply(&mut m.windows, id),
            Some(ServerReply::Answered(1))
        );
        assert_eq!(server_reply(&mut m.windows, id), None, "taken once");
        assert!(end_sent(&mut m.windows, b, 0));
        assert_eq!(live_sends(m), 0);

        // The receiver's thread ends while delivering a send answered early: its sender still
        // takes the answer.
        let Ok(Sending::Waiting(id)) = send(&mut m.windows, a, hb, WM_USER, 3, 0) else {
            panic!("queued");
        };
        assert!(matches!(read(m, b, &all(), 0), Taken::Sent(_)));
        assert!(reply(&mut m.windows, b, 6));
        detach(&mut m.windows, b);
        assert_eq!(collect_reply(&mut m.windows, a, id), Some(6));
        assert_eq!(live_sends(m), 0);
    }

    /// The sent messages' pool grows past a page and past the old fixed 128 records: 300 sends
    /// on their way at once, each answered in its order. An id's generation is its slot's count,
    /// 1 at first and one more once the slot is freed, the slot freed first taken first, so a
    /// collected send's id names nothing after.
    #[test]
    fn sends_on_their_way_grow_the_pool_and_stale_ids_name_nothing() {
        let (m, atom) = manager();
        let a = thread(m, 1, 0x100);
        let b = thread(m, 2, 0x200);
        let hb = popup(m, atom, b);
        deliver(m, b);
        // The creation's own sends used the first slots already.
        let fresh = m.windows.queues.sent.0.high_water();
        let ids: Vec<SentId> = (0..300)
            .map(|n| {
                let Ok(Sending::Waiting(id)) = send(&mut m.windows, a, hb, WM_USER, n, 0) else {
                    panic!("queued");
                };
                id
            })
            .collect();
        assert_eq!(live_sends(m), 300);
        assert!(
            ids.iter()
                .filter(|id| u32::from(id.index) >= fresh)
                .all(|id| id.generation == 1),
            "a slot's first count is 1"
        );
        for (n, id) in ids.iter().enumerate() {
            let Taken::Sent(got) = read(m, b, &all(), 0) else {
                panic!("the receiver reads send {n}");
            };
            assert_eq!(got, *id, "in the order sent");
            assert!(end_sent(&mut m.windows, b, n as LResult + 1));
            assert_eq!(
                collect_reply(&mut m.windows, a, *id),
                Some(n as LResult + 1)
            );
        }
        assert_eq!(live_sends(m), 0);

        assert_eq!(head_of(&m.windows, ids[0]), None, "stale");
        let unmade = SentId {
            index: 0x7FFF,
            generation: 1,
        };
        assert_eq!(head_of(&m.windows, unmade), None);

        let Ok(Sending::Waiting(again)) = send(&mut m.windows, a, hb, WM_USER, 0, 0) else {
            panic!("queued");
        };
        assert_eq!(again.index, ids[0].index, "the oldest freed first");
        assert_eq!(
            again.generation,
            ids[0].generation + 1,
            "its count moved on"
        );
        assert_eq!(collect_reply(&mut m.windows, a, ids[0]), None);
    }

    /// A message another thread sent to a window destroyed before it was read is answered 0 and
    /// never handed out; a queue that ends fails what was sent to it, and what was posted to it
    /// goes.
    #[test]
    fn a_send_to_a_window_gone_answers_zero_and_to_a_queue_gone_fails() {
        let (m, atom) = manager();
        let a = thread(m, 1, 0x100);
        let b = thread(m, 2, 0x200);
        let hb = popup(m, atom, b);
        deliver(m, b);
        let Ok(Sending::Waiting(id)) = send(&mut m.windows, a, hb, WM_USER, 0, 0) else {
            panic!("queued");
        };
        let WindowManager {
            windows, classes, ..
        } = &mut *m;
        Windows::destroy_window_handle(&mut QueueSession::new(windows, classes), b, hb).unwrap();
        assert_eq!(deliver(m, b), vec![(hb, WM_DESTROY), (hb, WM_NCDESTROY)]);
        assert_eq!(collect_reply(&mut m.windows, a, id), Some(0));

        let hb = popup(m, atom, b);
        deliver(m, b);
        post(&mut m.windows, b, 0, WM_USER, 0, 0, 0).unwrap();
        let Ok(Sending::Waiting(id)) = send(&mut m.windows, a, hb, WM_USER, 0, 0) else {
            panic!("queued");
        };
        // The record serves another thread now: the old thread's queue ends.
        let next = ThreadKey {
            index: 2,
            generation: 1,
        };
        attach(&mut m.windows, b, next, 0x300);
        assert_eq!(collect_reply(&mut m.windows, a, id), None);
        assert_eq!(await_reply(&mut m.windows, a, id), Awaited::Failed);
        assert_eq!(read(m, b, &all(), 0), Taken::Nothing { due: None });
        assert_eq!(queue_by_client_id(&m.windows, 0x200), None);
        assert!(queue_by_client_id(&m.windows, 0x300).is_some());
        detach(&mut m.windows, b);
        assert_eq!(m.windows.queues.queue_of(b), None);
    }

    /// SendNotifyMessage: a window of the caller's thread is called; another thread's has the
    /// message queued, handed out as another thread's sent message (InSendMessage TRUE) and
    /// answered to nobody; a window gone before it is read drops it. A message carrying a pointer
    /// is refused to another thread.
    #[test]
    fn a_notify_is_queued_and_answered_to_nobody() {
        let (m, atom) = manager();
        let a = thread(m, 1, 0x100);
        let b = thread(m, 2, 0x200);
        let ha = popup(m, atom, a);
        let hb = popup(m, atom, b);
        deliver(m, a);
        deliver(m, b);
        let base = live_sends(m);
        assert_eq!(
            send_notify(&mut m.windows, a, ha, WM_SETTEXT, 0, 0),
            Ok(Sending::Call(PROC))
        );
        assert_eq!(
            send_notify(&mut m.windows, a, hb, WM_SETTEXT, 0, 0),
            Err(MESSAGE_SYNC_ONLY)
        );
        assert_eq!(
            send_notify(&mut m.windows, a, 0x7FFF_FFFC, WM_USER, 0, 0),
            Err(STATUS_INVALID_HANDLE)
        );
        assert_eq!(
            send_notify(&mut m.windows, a, hb, WM_USER + 30, 5, 6),
            Ok(Sending::Answered(0))
        );
        let Taken::Sent(id) = read(m, b, &all(), 0) else {
            panic!("the receiver reads it");
        };
        let head = head_of(&m.windows, id).unwrap();
        assert_eq!(
            (head.msg.message, head.msg.wparam, head.msg.lparam),
            (WM_USER + 30, 5, 6)
        );
        assert!(in_send(&m.windows, b));
        assert!(!reply(&mut m.windows, b, 1), "nobody waits");
        assert!(end_sent(&mut m.windows, b, 11));
        assert_eq!(live_sends(m), base, "the record went back to the pool");

        send_notify(&mut m.windows, a, hb, WM_USER + 30, 7, 8).unwrap();
        let WindowManager {
            windows, classes, ..
        } = &mut *m;
        Windows::destroy_window_handle(&mut QueueSession::new(windows, classes), b, hb).unwrap();
        assert_eq!(deliver(m, b), vec![(hb, WM_DESTROY), (hb, WM_NCDESTROY)]);
        assert_eq!(live_sends(m), base);
    }

    /// SendMessageCallback: a window of the caller's thread is called; another thread's has the
    /// message queued (InSendMessage TRUE), and its answer comes back to the sender as a sent
    /// message that calls the callback (its data the wParam, the answer the lParam), new to the
    /// sender's queue (QS_SENDMESSAGE) until a read delivers it; a NULL callback's answer goes to
    /// nobody; a window gone before its thread reads the message is answered 0, still to the
    /// callback; a handle naming no window is refused.
    #[test]
    fn a_callback_send_answers_through_the_senders_queue() {
        const CALLBACK: u32 = 0x0040_2000;
        let (m, atom) = manager();
        let a = thread(m, 1, 0x100);
        let b = thread(m, 2, 0x200);
        let ha = popup(m, atom, a);
        let hb = popup(m, atom, b);
        deliver(m, a);
        deliver(m, b);
        let base = live_sends(m);
        assert_eq!(
            send_callback(&mut m.windows, a, ha, WM_USER, 1, 2, CALLBACK, 0x1111),
            Ok(Sending::Call(PROC))
        );
        assert_eq!(
            send_callback(&mut m.windows, a, 0x7FFF_FFFC, WM_USER, 0, 0, CALLBACK, 0),
            Err(STATUS_INVALID_HANDLE)
        );
        assert_eq!(
            send_callback(&mut m.windows, a, hb, WM_SETTEXT, 0, 0, CALLBACK, 0),
            Err(MESSAGE_SYNC_ONLY)
        );
        assert!(matches!(
            send_callback(&mut m.windows, a, hb, WM_USER + 30, 3, 4, CALLBACK, 0x3333),
            Ok(Sending::Waiting(_))
        ));
        assert_eq!(
            queue_status(&mut m.windows, a, 0, QS_SENDMESSAGE),
            0,
            "nothing for a yet"
        );
        let Taken::Sent(id) = read(m, b, &all(), 0) else {
            panic!("the receiver reads it");
        };
        assert_eq!(head_of(&m.windows, id).unwrap().msg.wparam, 3);
        assert!(in_send(&m.windows, b));
        assert!(end_sent(&mut m.windows, b, 103));
        assert_eq!(
            queue_status(&mut m.windows, a, 0, QS_ALLINPUT),
            QS_SENDMESSAGE << 16 | QS_SENDMESSAGE,
            "the answer waits in the sender's queue"
        );
        let Taken::Sent(back) = read(m, a, &all(), 0) else {
            panic!("the sender's read hands the answer out");
        };
        let head = head_of(&m.windows, back).unwrap();
        assert_eq!(
            (
                head.proc,
                head.msg.hwnd,
                head.msg.message,
                head.msg.wparam,
                head.msg.lparam
            ),
            (CALLBACK, hb, WM_USER + 30, 0x3333, 103)
        );
        assert!(
            !in_send(&m.windows, a),
            "the callback is no other thread's send"
        );
        assert!(end_sent(&mut m.windows, a, 0));
        assert_eq!(live_sends(m), base, "both records back in the pool");

        // No callback: the answer goes to nobody.
        send_callback(&mut m.windows, a, hb, WM_USER + 30, 5, 6, 0, 0).unwrap();
        assert!(matches!(read(m, b, &all(), 0), Taken::Sent(_)));
        assert!(end_sent(&mut m.windows, b, 1));
        assert_eq!(read(m, a, &all(), 0), Taken::Nothing { due: None });
        assert_eq!(live_sends(m), base);

        // The window gone before b reads: answered 0, to the callback.
        send_callback(&mut m.windows, a, hb, WM_USER + 30, 7, 8, CALLBACK, 0x7777).unwrap();
        let WindowManager {
            windows, classes, ..
        } = &mut *m;
        Windows::destroy_window_handle(&mut QueueSession::new(windows, classes), b, hb).unwrap();
        deliver(m, b);
        let Taken::Sent(back) = read(m, a, &all(), 0) else {
            panic!("the answer comes back");
        };
        let head = head_of(&m.windows, back).unwrap();
        assert_eq!(
            (head.proc, head.msg.wparam, head.msg.lparam),
            (CALLBACK, 0x7777, 0)
        );
        assert!(end_sent(&mut m.windows, a, 0));
        assert_eq!(live_sends(m), base);
    }

    /// A send that times out is taken back when its receiver has not read it (it never reaches
    /// the procedure, as the smto capture counts); one being handled is left to it, its answer
    /// to nobody.
    #[test]
    fn a_timed_out_send_is_taken_back() {
        let (m, atom) = manager();
        let a = thread(m, 1, 0x100);
        let b = thread(m, 2, 0x200);
        let hb = popup(m, atom, b);
        deliver(m, b);
        let base = live_sends(m);
        let Ok(Sending::Waiting(id)) = send(&mut m.windows, a, hb, WM_USER, 17, 18) else {
            panic!("queued");
        };
        abandon_send(&mut m.windows, a, id);
        assert_eq!(live_sends(m), base);
        assert_eq!(read(m, b, &all(), 0), Taken::Nothing { due: None });
        assert_eq!(collect_reply(&mut m.windows, a, id), None);

        let Ok(Sending::Waiting(id)) = send(&mut m.windows, a, hb, WM_USER, 19, 20) else {
            panic!("queued");
        };
        assert!(matches!(read(m, b, &all(), 0), Taken::Sent(_)));
        abandon_send(&mut m.windows, a, id);
        assert!(end_sent(&mut m.windows, b, 39));
        assert_eq!(live_sends(m), base);
        assert_eq!(collect_reply(&mut m.windows, a, id), None);
    }

    /// Two threads that send to each other: A sends to B's window; B's procedure sends to A's
    /// before it answers. A's wait is handed B's message and delivers it by callback, then waits
    /// on, as Windows 2000's SendMessage handles the messages sent to its thread while it waits;
    /// B gets its answer, then A. A wait with nothing sent to it waits.
    #[test]
    fn two_threads_sending_to_each_other_do_not_deadlock() {
        let (m, atom) = manager();
        let a = thread(m, 1, 0x100);
        let b = thread(m, 2, 0x200);
        let ha = popup(m, atom, a);
        let hb = popup(m, atom, b);
        deliver(m, a);
        deliver(m, b);
        let base = live_sends(m);

        let Ok(Sending::Waiting(to_b)) = send(&mut m.windows, a, hb, WM_USER + 1, 1, 0) else {
            panic!("A's send is queued for B");
        };
        assert_eq!(await_reply(&mut m.windows, a, to_b), Awaited::Wait);
        // B reads A's message; its procedure sends to A's window.
        assert!(matches!(read(m, b, &all(), 0), Taken::Sent(_)));
        let Ok(Sending::Waiting(to_a)) = send(&mut m.windows, b, ha, WM_USER + 2, 2, 0) else {
            panic!("B's send is queued for A");
        };
        assert_eq!(await_reply(&mut m.windows, b, to_a), Awaited::Wait);

        // A, waiting, delivers B's message by callback, then waits on.
        assert_eq!(await_reply(&mut m.windows, a, to_b), Awaited::Wait);
        let id = take_for_callback(&mut m.windows, a).expect("A is handed B's message");
        let head = head_of(&m.windows, id).unwrap();
        assert_eq!((head.msg.hwnd, head.msg.message), (ha, WM_USER + 2));
        end_received(&mut m.windows, a, id, 22, &out(&[]));
        assert_eq!(take_for_callback(&mut m.windows, a), None, "nothing more");
        assert_eq!(await_reply(&mut m.windows, a, to_b), Awaited::Wait);

        // B has its answer, and answers A's message.
        assert_eq!(await_reply(&mut m.windows, b, to_a), Awaited::Answer(22));
        assert!(end_sent(&mut m.windows, b, 11));
        assert_eq!(await_reply(&mut m.windows, a, to_b), Awaited::Answer(11));
        assert_eq!(live_sends(m), base, "both records went back to the pool");
    }
}
