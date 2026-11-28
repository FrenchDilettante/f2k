//! DispatchMessage's target, and the decisions' sends to other threads and their deliveries.

use rtl::user::{Msg, WM_NCACTIVATE, WM_NCDESTROY, WM_TIMER};

use super::*;
use crate::sched::thread::ThreadId;
use crate::status::*;
use crate::win32k::window::{LResult, Message, Payload, WindowId, Windows};

/// DispatchMessage's step for the caller's message: the procedure it goes to — WM_TIMER's
/// TimerProc when its lParam names one a live timer of the caller's process has (Windows 2000's
/// ValidateTimerCallback; a WM_TIMER posted by hand with another lParam goes nowhere, timers
/// `proc`), the window's procedure otherwise; 0 for a thread message, a window whose procedure
/// is the window manager's, or a TimerProc no timer has. STATUS_INVALID_HANDLE for a handle
/// naming no window.
pub fn dispatch_target(windows: &Windows, caller: ThreadId, msg: &Msg) -> Result<u32, NtStatus> {
    if msg.message == WM_TIMER && msg.lparam != 0 {
        let process = windows.thread_process(caller);
        let valid = windows.queues.timers.has_proc(msg.lparam as u32, |thread| {
            windows.thread_process(thread) == process
        });
        return Ok(if valid { msg.lparam as u32 } else { 0 });
    }
    if msg.hwnd == 0 {
        return Ok(0);
    }
    let window = windows
        .window_from_handle(msg.hwnd)
        .ok_or(STATUS_INVALID_HANDLE)?;
    Ok(windows.client_proc(window).unwrap_or(0))
}

/// Queue `message` for the window `target`'s thread as a message the window manager sent, no
/// thread waiting for its answer: a decision of a thread with no queue (the console server's), or
/// another thread's activation, which Windows 2000 hands that thread ([`Session::queue_for`]).
/// Nothing for a window whose procedure is the window manager's, a thread with no queue, a pool
/// that cannot grow (the message is lost), a creation message (by callback alone,
/// [`QueueSession`]), or WM_GETMINMAXINFO, whose defaults stand when nobody waits.
///
/// [`Session::queue_for`]: crate::win32k::window::Session::queue_for
pub fn defer(windows: &mut Windows, target: WindowId, message: &Message) {
    let Some(proc) = windows.client_proc(target) else {
        return;
    };
    let thread = windows.window_thread(target);
    let hwnd = windows.handle_of(target);
    let Some(receiver) = windows.queues.queue_of(thread) else {
        return;
    };
    let carried = match Carried::of(&message.payload) {
        None | Some(Carried::MinMax(_)) => return,
        Some(carried) => carried,
    };
    let queues = &mut windows.queues;
    let Some(id) = queues.allocate_sent(Sent {
        receiver: Some(receiver),
        window: Some(target),
        hwnd,
        proc,
        message: message.message,
        wparam: message.wparam,
        lparam: message.lparam,
        carried,
        ..Sent::EMPTY
    }) else {
        return;
    };
    queues.push_sent(receiver, id);
}

/// A decision's `message` to the window `target` of another thread than `caller`'s (whose
/// procedure is `proc`), queued for its thread with the window manager's copy of the structure
/// it carries, `caller` waiting for the answer ([`decision_reply`]), as Windows 2000's
/// `xxxInterSendMsgEx` queues it. None when the message is not one to wait for (a creation's),
/// either thread has no queue, or the pool cannot grow: the decision goes on with the default
/// procedure's answer then.
pub fn send_for_decision(
    windows: &mut Windows,
    caller: ThreadId,
    target: WindowId,
    proc: u32,
    message: &Message,
) -> Option<SentId> {
    let thread = windows.window_thread(target);
    if thread == caller {
        return None;
    }
    let carried = Carried::of(&message.payload)?;
    let hwnd = windows.handle_of(target);
    let queues = &mut windows.queues;
    let receiver = queues.queue_of(thread)?;
    let sender = queues.queue_of(caller)?;
    let id = queues.allocate_sent(Sent {
        receiver: Some(receiver),
        sender: Some(sender),
        window: Some(target),
        hwnd,
        proc,
        message: message.message,
        wparam: message.wparam,
        lparam: message.lparam,
        carried,
        ..Sent::EMPTY
    })?;
    queues.push_sent(receiver, id);
    Some(id)
}

/// What a decision waiting on its send to another thread's window found ([`decision_reply`]).
#[derive(Clone, Debug, PartialEq)]
pub enum Replied {
    /// The receiver's answer, and the message's payload as its procedure left it (the record
    /// went back to the pool).
    Answer(LResult, Payload),
    /// The receiving thread ended first: no answer (the record went back to the pool).
    Failed,
    /// A message sent to the waiting thread meanwhile, handed out for it to deliver by callback
    /// ([`end_received`]), as Windows 2000's sender handles the messages sent to it while it
    /// waits.
    Received(SentId),
    /// Nothing yet: the decision waits on its queue, the lock let go.
    Wait,
}

/// The decision's wait on its send `id` (from [`send_for_decision`]), one look: the answer and
/// the structure; otherwise the next message sent to `caller` to deliver meanwhile
/// ([`take_for_callback`]).
pub fn decision_reply(windows: &mut Windows, caller: ThreadId, id: SentId) -> Replied {
    let carried = windows.queues.sent_at(id).map(|sent| sent.carried);
    match await_reply(windows, caller, id) {
        Awaited::Answer(answer) => Replied::Answer(
            answer,
            carried.and_then(|c| c.payload()).unwrap_or(Payload::None),
        ),
        Awaited::Failed => Replied::Failed,
        Awaited::Wait => match take_for_callback(windows, caller) {
            Some(sent) => Replied::Received(sent),
            None => Replied::Wait,
        },
    }
}

/// The next message sent to `caller`, handed out for a callback to deliver (on its receiving
/// stack): the oldest, as Windows 2000's xxxReceiveMessage takes them. A message another thread
/// or the server sent to a window gone meanwhile is answered 0 (dropped, for the server) and
/// skipped (the window manager's own sends are delivered whatever became of the window).
pub fn take_for_callback(windows: &mut Windows, caller: ThreadId) -> Option<SentId> {
    let id = windows.queues.queue_of(caller)?;
    while let Some(index) = windows.queues.pop_sent(id) {
        let sent = *windows.queues.sent.at(index);
        let window_gone = sent.window.is_none_or(|w| !windows.is_live(w));
        let queues = &mut windows.queues;
        let from_thread = sent.sender.is_some() || sent.server || sent.notify || sent.is_callback();
        if from_thread && window_gone {
            queues.drop_unanswered(index);
            continue;
        }
        let receiving = queues.queues[id.index as usize].receiving;
        let record = queues.sent.at_mut(index);
        record.state = State::Received;
        record.next = receiving;
        queues.queues[id.index as usize].receiving = Some(index);
        return Some(index);
    }
    None
}

/// The end of the callback that delivered the message `id` to `caller` ([`take_for_callback`]):
/// its procedure's answer `result` and the in-out structure `out` it handed back go to its sender,
/// unless ReplyMessage answered already. Messages handed out above it and never ended (a callback
/// an exception cut short) are answered 0 first.
pub fn end_received(
    windows: &mut Windows,
    caller: ThreadId,
    id: SentId,
    result: LResult,
    out: &CallbackOut,
) {
    let queues = &mut windows.queues;
    let Some(queue) = queues.queue_of(caller) else {
        return;
    };
    let mut on_stack = queues.queues[queue.index as usize].receiving;
    while on_stack.is_some_and(|at| at != id) {
        on_stack = on_stack.and_then(|at| queues.sent.at(at).next);
    }
    if on_stack.is_none() {
        return;
    }
    loop {
        let queues = &mut windows.queues;
        let Some(top) = queues.queues[queue.index as usize].receiving else {
            return;
        };
        queues.queues[queue.index as usize].receiving = queues.sent.at(top).next;
        let Sent {
            message,
            wparam,
            window,
            state,
            sender,
            server,
            notify,
            carried,
            reply,
            ..
        } = *queues.sent.at(top);
        let answer = if top == id {
            keep_out(queues.sent.at_mut(top), out);
            result
        } else {
            0
        };
        if state == State::Received {
            queues.answer(top, answer);
        } else {
            queues.leave_stack(top);
        }
        if let (WM_NCDESTROY, Some(window)) = (message, window) {
            crate::win32k::caret::ncdestroy_delivered(windows, caller, window);
        }
        if top == id {
            // Another thread's activation deactivating this one, its WM_NCACTIVATE (FALSE)
            // answered FALSE: the deactivation stops there ([`crate::win32k::focus`]).
            let deferred = sender.is_none()
                && !server
                && !notify
                && !reply
                && !matches!(carried, Carried::Callback(_));
            if let (WM_NCACTIVATE, 0, true, 0, Some(window)) =
                (message, wparam, deferred, answer, window)
            {
                crate::win32k::focus::deactivation_vetoed(windows, caller, window);
            }
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use rtl::callback::{
        CallbackMsg,
        FN_INOUTLPPOINT5,
        FN_INOUTLPWINDOWPOS,
        FN_INOUTNCCALCSIZE,
        FN_INOUTSTYLECHANGE,
        FN_INSTRINGNULL,
    };
    use rtl::pod::Pod;
    use rtl::user::{
        StyleStruct,
        PM_QS_SENDMESSAGE,
        WM_GETMINMAXINFO,
        WM_NCCALCSIZE,
        WM_SETTEXT,
        WM_STYLECHANGING,
        WM_USER,
        WM_WINDOWPOSCHANGED,
        WM_WINDOWPOSCHANGING,
    };
    use rtl::window::SWP_NOMOVE;

    use super::*;
    use crate::win32k::queue::testkit::*;
    use crate::win32k::window;
    use crate::win32k::window::{WindowManager, WindowPos};

    /// DispatchMessage's procedure: WM_TIMER's TimerProc when a timer has it (none when no timer
    /// does: a WM_TIMER posted by hand), the window's procedure, none for a thread message; a
    /// handle naming no window is refused.
    #[test]
    fn dispatch_names_the_procedure() {
        let (m, atom) = manager();
        let t = thread(m, 1, 0x100);
        let h = popup(m, atom, t);
        let msg = |hwnd, message, lparam| Msg {
            hwnd,
            message,
            lparam,
            ..Msg::default()
        };
        assert_eq!(
            dispatch_target(&m.windows, t, &msg(h, WM_USER, 0)),
            Ok(PROC)
        );
        assert_eq!(dispatch_target(&m.windows, t, &msg(0, WM_USER, 0)), Ok(0));
        let timer = msg(h, WM_TIMER, 0x0040_2000);
        assert_eq!(dispatch_target(&m.windows, t, &timer), Ok(0));
        crate::win32k::timer::set(&mut m.windows, t, h, 1, 10, 0x0040_2000, 0).unwrap();
        assert_eq!(dispatch_target(&m.windows, t, &timer), Ok(0x0040_2000));
        crate::win32k::timer::kill(&mut m.windows, t, h, 1).unwrap();
        assert_eq!(dispatch_target(&m.windows, t, &timer), Ok(0));
        assert_eq!(
            dispatch_target(&m.windows, t, &msg(0x7FFF_FFFC, WM_USER, 0)),
            Err(STATUS_INVALID_HANDLE)
        );
    }

    /// A decision's send to another thread's window waits for the answer (gui-D slice 5): the
    /// message is queued for the window's thread with the window manager's copy of its WINDOWPOS,
    /// the receipt's lParam points at the receipt's copy, and what the procedure left there when
    /// its delivery ended comes back to the decision with the answer.
    #[test]
    fn a_decisions_send_to_another_threads_window_waits_for_the_structure() {
        let (m, atom) = manager();
        let a = thread(m, 1, 0x100);
        let b = thread(m, 2, 0x200);
        let hb = popup(m, atom, b);
        deliver(m, b);
        let base = live_sends(m);
        let wb = m.windows.window_from_handle(hb).unwrap();
        let pos = WindowPos {
            hwnd: hb,
            x: 10,
            y: 20,
            cx: 300,
            cy: 200,
            ..WindowPos::default()
        };
        let message = decision_message(WM_WINDOWPOSCHANGING, 0, Payload::WindowPos(pos));
        let id = send_for_decision(&mut m.windows, a, wb, PROC, &message).unwrap();
        assert_eq!(decision_reply(&mut m.windows, a, id), Replied::Wait);
        assert_eq!(
            send_for_decision(&mut m.windows, b, wb, PROC, &message),
            None,
            "the window's own thread calls back instead"
        );

        let Taken::Sent(got) = read(m, b, &all(), 0) else {
            panic!("B reads the decision's message");
        };
        let Some(Delivery::Structure(input, _)) = delivery(&m.windows, &m.classes, got) else {
            panic!("a structure's callback");
        };
        assert_eq!(input.api, FN_INOUTLPWINDOWPOS);
        assert_eq!(&input.carried[..input.length], pos.as_bytes());
        assert!(in_send(&m.windows, b), "another thread sent it");

        let edited = WindowPos {
            cx: 123,
            flags: SWP_NOMOVE,
            ..pos
        };
        end_received(&mut m.windows, b, got, 7, &out(edited.as_bytes()));
        assert_eq!(
            decision_reply(&mut m.windows, a, id),
            Replied::Answer(7, Payload::WindowPos(edited))
        );
        assert_eq!(live_sends(m), base, "the record went back to the pool");
    }

    /// The other in-out structures reach the receiver's callback and come back: WM_NCCALCSIZE's
    /// NCCALCSIZE_PARAMS (its WINDOWPOS after it; the three rectangles back) and
    /// WM_GETMINMAXINFO's MINMAXINFO; WM_WINDOWPOSCHANGED's WINDOWPOS is input only, and a short
    /// read-back changes nothing.
    #[test]
    fn the_callbacks_structures_come_back_to_the_waiting_decision() {
        let (m, atom) = manager();
        let a = thread(m, 1, 0x100);
        let b = thread(m, 2, 0x200);
        let hb = popup(m, atom, b);
        deliver(m, b);
        let wb = m.windows.window_from_handle(hb).unwrap();
        let rect = rtl::gdi::Rect::new(0, 0, 200, 100);
        let client = rtl::gdi::Rect::new(10, 10, 190, 90);
        let pos = WindowPos {
            hwnd: hb,
            cx: 200,
            cy: 100,
            ..WindowPos::default()
        };
        let calc = window::CalcSize {
            rects: [rect; 3],
            pos,
        };
        let mmi = window::MinMaxInfo {
            min_track: (100, 50),
            ..window::MinMaxInfo::unbounded()
        };
        let edited_mmi = window::MinMaxInfo {
            min_track: (400, 300),
            ..mmi
        };
        let edited_calc = rtl::window::NcCalcSizeParams {
            rects: [client, rect, rect],
            pos: 0,
        };
        let cases = [
            (
                decision_message(WM_NCCALCSIZE, 1, Payload::CalcSize(calc)),
                FN_INOUTNCCALCSIZE,
                edited_calc.as_bytes().to_vec(),
                Payload::CalcSize(window::CalcSize {
                    rects: [client, rect, rect],
                    pos,
                }),
            ),
            (
                decision_message(WM_GETMINMAXINFO, 0, Payload::MinMax(mmi)),
                FN_INOUTLPPOINT5,
                edited_mmi.raw().as_bytes().to_vec(),
                Payload::MinMax(edited_mmi),
            ),
            (
                decision_message(WM_GETMINMAXINFO, 0, Payload::MinMax(mmi)),
                FN_INOUTLPPOINT5,
                edited_mmi.raw().as_bytes()[..8].to_vec(),
                Payload::MinMax(mmi),
            ),
        ];
        for (message, api, back, expected) in cases {
            let id = send_for_decision(&mut m.windows, a, wb, PROC, &message).unwrap();
            let Taken::Sent(got) = read(m, b, &all(), 0) else {
                panic!("B reads it");
            };
            let Some(Delivery::Structure(input, sent)) = delivery(&m.windows, &m.classes, got)
            else {
                panic!("a structure's callback");
            };
            assert_eq!(input.api, api);
            assert_eq!(sent.payload, message.payload);
            if let Payload::CalcSize(_) = message.payload {
                let params = rtl::window::NcCalcSizeParams {
                    rects: [rect; 3],
                    pos: 0,
                };
                let mut carried = params.as_bytes().to_vec();
                carried.extend_from_slice(pos.as_bytes());
                assert_eq!(&input.carried[..input.length], &carried[..]);
            } else {
                assert_eq!(&input.carried[..input.length], mmi.raw().as_bytes());
            }
            end_received(&mut m.windows, b, got, 0, &out(&back));
            assert_eq!(
                decision_reply(&mut m.windows, a, id),
                Replied::Answer(0, expected)
            );
        }

        let changed = decision_message(WM_WINDOWPOSCHANGED, 0, Payload::WindowPos(pos));
        let id = send_for_decision(&mut m.windows, a, wb, PROC, &changed).unwrap();
        let Taken::Sent(got) = read(m, b, &all(), 0) else {
            panic!("B reads it");
        };
        let moved = WindowPos { x: 9, ..pos };
        end_received(&mut m.windows, b, got, 0, &out(moved.as_bytes()));
        assert_eq!(
            decision_reply(&mut m.windows, a, id),
            Replied::Answer(0, Payload::WindowPos(pos)),
            "input only"
        );
    }

    /// A decision waiting on another thread is handed the messages sent to its own thread
    /// meanwhile, to deliver by callback, in the order they were sent: a text another process's
    /// message carries, in its callback's block; another decision's (the receiver's, sending
    /// back), whose structure and answer go to that decision. So two threads whose decisions send
    /// to each other do not wait on each other.
    #[test]
    fn two_decisions_sending_to_each_other_do_not_deadlock() {
        let (m, atom) = manager();
        let a = thread(m, 1, 0x100);
        let b = thread(m, 2, 0x200);
        let ha = popup(m, atom, a);
        let hb = popup(m, atom, b);
        deliver(m, a);
        deliver(m, b);
        let base = live_sends(m);
        let wa = m.windows.window_from_handle(ha).unwrap();
        let wb = m.windows.window_from_handle(hb).unwrap();

        let to_b = send_for_decision(
            &mut m.windows,
            a,
            wb,
            PROC,
            &decision_message(WM_USER, 1, Payload::None),
        )
        .unwrap();
        // B, meanwhile: a SendMessage carrying a text, then a decision's WM_STYLECHANGING.
        let text: Vec<u16> = "Hi".encode_utf16().collect();
        let Ok(Sending::Waiting(texted)) =
            send_carrying(&mut m.windows, b, ha, WM_SETTEXT, 0, 0, Some(&text))
        else {
            panic!("queued for A");
        };
        let style = StyleStruct {
            style_old: 1,
            style_new: 2,
        };
        let to_a = send_for_decision(
            &mut m.windows,
            b,
            wa,
            PROC,
            &decision_message(WM_STYLECHANGING, 0, Payload::Style(style)),
        )
        .unwrap();
        // B's wait is handed A's message: its callback runs (and has not ended yet).
        let Replied::Received(from_a) = decision_reply(&mut m.windows, b, to_a) else {
            panic!("B is handed A's message");
        };
        assert_eq!(from_a, to_b);

        // A's wait is handed B's messages in the order they were sent: the text first, its
        // callback carrying it, then B's decision's message.
        let Replied::Received(got) = decision_reply(&mut m.windows, a, to_b) else {
            panic!("A is handed B's text");
        };
        assert_eq!(got, texted);
        assert_eq!(
            text_of(m, got),
            (
                FN_INSTRINGNULL,
                CallbackMsg {
                    proc: PROC,
                    hwnd: ha,
                    message: WM_SETTEXT,
                    wparam: 0,
                    lparam: 0,
                },
                text.clone(),
                0
            )
        );
        end_received(&mut m.windows, a, got, 1, &out(&[]));
        let Replied::Received(got) = decision_reply(&mut m.windows, a, to_b) else {
            panic!("A is handed B's message");
        };
        assert_eq!(got, to_a);
        let Some(Delivery::Structure(input, message)) = delivery(&m.windows, &m.classes, got)
        else {
            panic!("a structure's callback");
        };
        assert_eq!(input.api, FN_INOUTSTYLECHANGE);
        assert_eq!((input.head.hwnd, input.head.proc), (ha, PROC));
        assert_eq!(&input.carried[..input.length], style.as_bytes());
        assert_eq!(message.payload, Payload::Style(style));
        assert!(in_send(&m.windows, a));
        let edited = StyleStruct {
            style_new: 6,
            ..style
        };
        end_received(&mut m.windows, a, got, 3, &out(edited.as_bytes()));
        assert_eq!(decision_reply(&mut m.windows, a, to_b), Replied::Wait);

        // B's callback ends: each decision has its answer.
        end_received(&mut m.windows, b, from_a, 4, &out(&[]));
        assert_eq!(
            decision_reply(&mut m.windows, b, to_a),
            Replied::Answer(3, Payload::Style(edited))
        );
        assert_eq!(
            decision_reply(&mut m.windows, a, to_b),
            Replied::Answer(4, Payload::None)
        );
        assert_eq!(await_reply(&mut m.windows, b, texted), Awaited::Answer(1));
        assert_eq!(live_sends(m), base);
    }

    /// A callback's delivery that ends with messages handed out above it never ended (an
    /// exception cut a nested read's delivery short) answers them 0 first; a message to a window
    /// gone meanwhile is answered 0, not handed out.
    #[test]
    fn a_callbacks_end_answers_what_was_left_above_it() {
        let (m, atom) = manager();
        let a = thread(m, 1, 0x100);
        let b = thread(m, 2, 0x200);
        let ha = popup(m, atom, a);
        let hb = popup(m, atom, b);
        let gone = popup(m, atom, a);
        deliver(m, a);
        deliver(m, b);
        let base = live_sends(m);
        let wa = m.windows.window_from_handle(ha).unwrap();
        let wb = m.windows.window_from_handle(hb).unwrap();
        let wgone = m.windows.window_from_handle(gone).unwrap();
        let plain = decision_message(WM_USER, 0, Payload::None);
        let to_b = send_for_decision(&mut m.windows, a, wb, PROC, &plain).unwrap();
        let dropped = send_for_decision(&mut m.windows, b, wgone, PROC, &plain).unwrap();
        let first = send_for_decision(&mut m.windows, b, wa, PROC, &plain).unwrap();
        let Ok(Sending::Waiting(second)) = send(&mut m.windows, b, ha, WM_USER + 1, 0, 0) else {
            panic!("queued");
        };
        {
            let WindowManager {
                windows, classes, ..
            } = &mut *m;
            Windows::destroy_window_handle(&mut QueueSession::new(windows, classes), a, gone)
                .unwrap();
        }
        assert!(!m.windows.is_live(wgone));
        assert_eq!(
            decision_reply(&mut m.windows, a, to_b),
            Replied::Received(first)
        );
        assert_eq!(
            decision_reply(&mut m.windows, b, dropped),
            Replied::Answer(0, Payload::None),
            "its window went: answered 0"
        );
        // Inside the callback, a read hands out the next one, whose delivery never ends.
        let only_sent = Filter::new(0, 0, 0, PM_QS_SENDMESSAGE);
        assert_eq!(read(m, a, &only_sent, 0), Taken::Sent(second));
        end_received(&mut m.windows, a, first, 8, &out(&[]));
        assert_eq!(collect_reply(&mut m.windows, b, second), Some(0));
        assert_eq!(
            decision_reply(&mut m.windows, b, first),
            Replied::Answer(8, Payload::None)
        );
        assert!(!end_sent(&mut m.windows, a, 0), "nothing left on the stack");
        deliver(m, a);
        assert!(matches!(read(m, b, &all(), 0), Taken::Sent(_)));
        assert!(end_sent(&mut m.windows, b, 0));
        assert!(matches!(
            decision_reply(&mut m.windows, a, to_b),
            Replied::Answer(0, _)
        ));
        assert_eq!(live_sends(m), base);
    }

    /// A decision waiting on a thread that ends fails (Windows 2000's xxxInterSendMsgEx answers 0
    /// when its receiver dies); a decision's thread that ends while it waits leaves its send to
    /// nobody.
    #[test]
    fn a_decisions_send_fails_when_its_receiver_ends() {
        let (m, atom) = manager();
        let a = thread(m, 1, 0x100);
        let b = thread(m, 2, 0x200);
        let hb = popup(m, atom, b);
        deliver(m, b);
        let base = live_sends(m);
        let wb = m.windows.window_from_handle(hb).unwrap();
        let plain = decision_message(WM_USER, 0, Payload::None);
        let queued = send_for_decision(&mut m.windows, a, wb, PROC, &plain).unwrap();
        detach(&mut m.windows, b);
        assert_eq!(decision_reply(&mut m.windows, a, queued), Replied::Failed);
        assert_eq!(live_sends(m), base);
        assert_eq!(
            send_for_decision(&mut m.windows, a, wb, PROC, &plain),
            None,
            "no queue to send to"
        );

        let c = thread(m, 3, 0x300);
        let hc = popup(m, atom, c);
        deliver(m, c);
        let wc = m.windows.window_from_handle(hc).unwrap();
        send_for_decision(&mut m.windows, a, wc, PROC, &plain).unwrap();
        detach(&mut m.windows, a);
        assert!(matches!(read(m, c, &all(), 0), Taken::Sent(_)));
        assert!(end_sent(&mut m.windows, c, 0));
        assert_eq!(live_sends(m), base, "answered to nobody");
    }
}
