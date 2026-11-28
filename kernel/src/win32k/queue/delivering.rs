//! A sent message's delivery by callback, and ReplyMessage and InSendMessage.

#[cfg(test)]
use rtl::callback::OUT_MAX;
use rtl::callback::{CallbackMsg, FN_COPYDATA, FN_INSTRINGNULL, FN_OUTSTRING, OUT_STRING_MAX};
#[cfg(test)]
use rtl::user::Msg;
use rtl::user::{WM_COPYDATA, WM_GETTEXT};

use super::*;
use crate::sched::thread::ThreadId;
use crate::win32k::class;
use crate::win32k::text::Text;
use crate::win32k::window::{LResult, Message, Windows};

/// What the callback that delivers a sent message carries ([`delivery`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Delivery {
    /// A message with a structure, or none: the callback as [`callback_input`] makes it, and the
    /// message, its payload the window manager's copy (for [`keep_out`]).
    Structure(CallbackInput, Message),
    /// A text another process's message carries ([`Carried::Text`]): the slot ([`text_slot`]), the
    /// block's head (its lParam 0: the routine points it into the block), the text, and for
    /// WM_GETTEXT the units of the buffer the block holds after it for the procedure's answer
    /// (wParam's, no more than [`OUT_STRING_MAX`]).
    Text {
        api: u32,
        head: CallbackMsg,
        text: Text,
        room: u32,
    },
}

/// The `__fn*` slot a text another process's message carries goes through: WM_SETTEXT's
/// `__fnINSTRINGNULL`, WM_GETTEXT's `__fnOUTSTRING`, WM_COPYDATA's `__fnCOPYDATA` (rtl::callback's
/// notes).
fn text_slot(message: u32) -> u32 {
    match message {
        WM_GETTEXT => FN_OUTSTRING,
        WM_COPYDATA => FN_COPYDATA,
        _ => FN_INSTRINGNULL,
    }
}

/// The callback that delivers the sent message `id`, handed out ([`take_for_callback`]): see
/// [`Delivery`]. None for an id that names no message.
pub fn delivery(windows: &Windows, classes: &class::Registry, id: SentId) -> Option<Delivery> {
    let sent = windows.queues.sent_at(id)?;
    if let Carried::Text(text) = sent.carried {
        let api = text_slot(sent.message);
        return Some(Delivery::Text {
            api,
            head: CallbackMsg {
                proc: sent.proc,
                hwnd: sent.hwnd,
                message: sent.message,
                wparam: sent.wparam,
                lparam: 0,
            },
            text,
            room: match api {
                FN_OUTSTRING => sent.wparam.min(OUT_STRING_MAX),
                _ => 0,
            },
        });
    }
    let message = Message {
        message: sent.message,
        wparam: sent.wparam,
        lparam: sent.lparam,
        payload: sent.carried.payload()?,
    };
    let input = callback_input_for(windows, classes, sent.hwnd, sent.proc, &message);
    Some(Delivery::Structure(input, message))
}

/// The units of the text a [`Delivery::Text`] carries.
pub fn carried_units(windows: &Windows, text: Text) -> &[u16] {
    windows.queues.store.units(text)
}

/// WM_GETTEXT's answer `units`, read back from the callback that delivered the sent message `id`,
/// kept with it for its sender ([`answered_text`]); with no room in the store, an empty answer.
pub fn keep_text_reply(windows: &mut Windows, id: SentId, units: &[u16]) {
    let queues = &mut windows.queues;
    if queues.sent_at(id).is_none() {
        return;
    }
    let sent = queues.sent.at_mut(id);
    if let (Carried::Text(text), WM_GETTEXT) = (&mut sent.carried, sent.message) {
        if !queues.store.replace(text, units) {
            queues.store.free(*text);
            *text = Text::EMPTY;
        }
    }
}

/// WM_GETTEXT's text, once the caller's send `id` to another process is answered; none for
/// another send, or one not answered yet.
pub fn answered_text(windows: &Windows, id: SentId) -> Option<&[u16]> {
    let sent = windows.queues.sent_at(id)?;
    match (sent.carried, sent.message, sent.state) {
        (Carried::Text(text), WM_GETTEXT, State::Answered | State::Replied) => {
            Some(windows.queues.store.units(text))
        }
        _ => None,
    }
}

/// The callback slot and the size of the in-out structure the sent message `sent` carries: none
/// for a message whose structure does not come back (WM_WINDOWPOSCHANGED, WM_STYLECHANGED), or
/// that carries none.
fn in_out(sent: &Sent) -> Option<(u32, usize)> {
    let payload = sent.carried.payload()?;
    let api = slot(sent.message, &payload);
    let size = rtl::callback::out_size(api, sent.wparam);
    (size != 0).then_some((api, size))
}

/// The in-out structure `out` a callback handed back for the sent message `sent`, kept with it
/// ([`read_back`]).
pub(super) fn keep_out(sent: &mut Sent, out: &CallbackOut) {
    let Some((api, _)) = in_out(sent) else {
        return;
    };
    let Some(payload) = sent.carried.payload() else {
        return;
    };
    let mut message = Message {
        message: sent.message,
        wparam: sent.wparam,
        lparam: sent.lparam,
        payload,
    };
    read_back(api, &mut message, out);
    if let Some(carried) = Carried::of(&message.payload) {
        sent.carried = carried;
    }
}

// --- Answering -----------------------------------------------------------------------------------

/// What the callback that delivers the sent message `id` names: its procedure and its message, the
/// lParam the sender's (0 for a text: the callback points it into its block). The tests' look at a
/// delivery's head.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Head {
    pub proc: u32,
    pub msg: Msg,
}

/// The [`Head`] of the sent message `id`; none for an id that names none.
#[cfg(test)]
pub fn head_of(windows: &Windows, id: SentId) -> Option<Head> {
    let sent = windows.queues.sent_at(id)?;
    let lparam = match sent.carried {
        Carried::Text(_) => 0,
        _ => sent.lparam,
    };
    Some(Head {
        proc: sent.proc,
        msg: made(sent.hwnd, sent.message, sent.wparam, lparam, 0),
    })
}

/// The end of the caller's innermost sent message's delivery, its procedure's answer `result` and
/// no structure back ([`end_received`]): false when the caller was delivering none. The tests'
/// short hand for a callback's end.
#[cfg(test)]
pub fn end_sent(windows: &mut Windows, caller: ThreadId, result: LResult) -> bool {
    let Some(queue) = windows.queues.queue_of(caller) else {
        return false;
    };
    let Some(top) = windows.queues.queues[queue.index as usize].receiving else {
        return false;
    };
    let none = CallbackOut {
        bytes: [0; OUT_MAX],
        length: 0,
    };
    end_received(windows, caller, top, result, &none);
    true
}

/// ReplyMessage: answer the caller's innermost sent message with `result` now, when another thread
/// or the server sent it and waits; true when it did.
pub fn reply(windows: &mut Windows, caller: ThreadId, result: LResult) -> bool {
    let queues = &mut windows.queues;
    let Some(id) = queues.queue_of(caller) else {
        return false;
    };
    let Some(index) = queues.queues[id.index as usize].receiving else {
        return false;
    };
    let sent = queues.sent.at_mut(index);
    if (sent.sender.is_none() && !sent.server) || sent.state != State::Received {
        return false;
    }
    let sender = sent.sender;
    sent.state = State::Replied;
    sent.result = result;
    match sender {
        Some(sender) => queues.wake(sender),
        None => queues.server_wake = true,
    }
    true
}

/// InSendMessage: whether the caller's innermost sent message, the one its procedure is handling,
/// came from another thread or the server (a message the window manager sent on the caller's own
/// call, as Windows 2000 sends it within the calling thread, did not).
pub fn in_send(windows: &Windows, caller: ThreadId) -> bool {
    let queues = &windows.queues;
    let Some(id) = queues.queue_of(caller) else {
        return false;
    };
    let Some(index) = queues.queues[id.index as usize].receiving else {
        return false;
    };
    let sent = queues.sent.at(index);
    sent.sender.is_some() || sent.server || sent.notify || sent.is_callback()
}

#[cfg(test)]
mod tests {
    use rtl::callback::FN_INOUTNCCALCSIZE;
    use rtl::pod::Pod;
    use rtl::user::{WM_NCCALCSIZE, WM_SETTEXT, WM_USER, WS_POPUP};

    use super::*;
    use crate::win32k::queue::testkit::*;
    use crate::win32k::window::Payload;

    /// The host's session queues every message, but a creation's: WM_NCCALCSIZE first, the
    /// callback that delivers it carrying the window manager's copy of its rectangle.
    #[test]
    fn a_queued_messages_callback_carries_its_structure() {
        let (m, atom) = manager();
        let t = thread(m, 1, 0x100);
        let h = window_at(m, atom, t, WS_POPUP, 0, 5, 6, 30, 40);
        let Taken::Sent(id) = read(m, t, &all(), 0) else {
            panic!("WM_NCCALCSIZE first");
        };
        let Some(Delivery::Structure(input, message)) = delivery(&m.windows, &m.classes, id) else {
            panic!("a structure's callback");
        };
        assert_eq!(input.api, FN_INOUTNCCALCSIZE);
        assert_eq!(input.head.proc, PROC);
        assert_eq!((input.head.hwnd, input.head.message), (h, WM_NCCALCSIZE));
        let rect = rtl::gdi::Rect {
            left: 5,
            top: 6,
            right: 35,
            bottom: 46,
        };
        assert_eq!(message.payload, Payload::Rect(rect));
        assert_eq!(&input.carried[..input.length], rect.as_bytes());
        assert!(end_sent(&mut m.windows, t, 0));
        assert_eq!(delivery(&m.windows, &m.classes, id), None, "answered, gone");
    }

    /// guimsg `copydata`: WM_COPYDATA to another process's window carries its structure and
    /// data through the window manager, handed whole to the receiver's buffer (its lParam 0 until
    /// the receiver points it there); to the same process's window it carries nothing.
    #[test]
    fn copy_data_to_another_process_is_carried() {
        let (m, atom) = manager();
        let b = thread(m, 2, 0x200);
        let a = thread_of(m, 1, 0x100, OWNER + 1);
        let hb = popup(m, atom, b);
        deliver(m, b);
        assert!(carries_text(&m.windows, OWNER + 1, hb, WM_COPYDATA));
        assert!(!carries_text(&m.windows, OWNER, hb, WM_COPYDATA));
        let carried = [0x4B1D, 0, 3, 0, 0, 0, 0x6261, 0x0063];
        let Ok(Sending::Waiting(id)) = send_carrying(
            &mut m.windows,
            a,
            hb,
            WM_COPYDATA,
            0,
            0x5000,
            Some(&carried),
        ) else {
            panic!("queued for the other process's thread");
        };
        let Taken::Sent(got) = read(m, b, &all(), 0) else {
            panic!("the receiver reads it");
        };
        let (api, head, units, room) = text_of(m, got);
        assert_eq!((head.message, head.lparam), (WM_COPYDATA, 0));
        assert_eq!((api, units, room), (FN_COPYDATA, carried.to_vec(), 0));
        assert!(end_sent(&mut m.windows, b, 77));
        assert_eq!(collect_reply(&mut m.windows, a, id), Some(77));
    }

    /// WM_SETTEXT and WM_GETTEXT to another process's window carry their text through the window
    /// manager (wintext `xproc`), as long as it is: WM_SETTEXT's 10,000 units in its callback's
    /// block, WM_GETTEXT's callback a buffer of its wParam's units, wParam as the sender gave it,
    /// its 10,000-unit answer read back for the sender; a larger buffer than the block may hold is
    /// cut to OUT_STRING_MAX units. Another message, or the same process's
    /// window, carries none. The texts go back to the store with their messages.
    #[test]
    fn a_text_to_another_process_is_carried() {
        let (m, atom) = manager();
        let b = thread(m, 2, 0x200);
        let a = thread_of(m, 1, 0x100, OWNER + 1);
        let hb = popup(m, atom, b);
        deliver(m, b);
        assert!(carries_text(&m.windows, OWNER + 1, hb, WM_SETTEXT));
        assert!(carries_text(&m.windows, OWNER + 1, hb, WM_GETTEXT));
        assert!(!carries_text(&m.windows, OWNER + 1, hb, WM_USER));
        assert!(
            !carries_text(&m.windows, OWNER, hb, WM_SETTEXT),
            "the same process"
        );

        let text: Vec<u16> = (0..10_000u32).map(|i| 0x41 + (i % 26) as u16).collect();
        let Ok(Sending::Waiting(id)) =
            send_carrying(&mut m.windows, a, hb, WM_SETTEXT, 0, 0x5000, Some(&text))
        else {
            panic!("queued for the other process's thread");
        };
        let Taken::Sent(got) = read(m, b, &all(), 0) else {
            panic!("the receiver reads it");
        };
        let (api, head, units, room) = text_of(m, got);
        assert_eq!(head.lparam, 0, "the routine points it into its block");
        assert_eq!((api, room), (FN_INSTRINGNULL, 0), "no answer to read back");
        assert_eq!(units, text);
        assert!(end_sent(&mut m.windows, b, 1));
        assert_eq!(collect_reply(&mut m.windows, a, id), Some(1));

        let Ok(Sending::Waiting(id)) =
            send_carrying(&mut m.windows, a, hb, WM_GETTEXT, 20_000, 0x5000, Some(&[]))
        else {
            panic!("queued");
        };
        let Taken::Sent(got) = read(m, b, &all(), 0) else {
            panic!("the receiver reads it");
        };
        let (api, head, units, room) = text_of(m, got);
        assert_eq!(head.wparam, 20_000, "the sender's room");
        assert_eq!((api, units, room), (FN_OUTSTRING, vec![], 20_000));
        keep_text_reply(&mut m.windows, got, &text);
        assert!(end_sent(&mut m.windows, b, 10_000));
        assert_eq!(answered_text(&m.windows, id), Some(&text[..]));
        assert_eq!(collect_reply(&mut m.windows, a, id), Some(10_000));
        let Ok(Sending::Waiting(id)) = send_carrying(
            &mut m.windows,
            a,
            hb,
            WM_GETTEXT,
            0x10_0000,
            0x5000,
            Some(&[]),
        ) else {
            panic!("queued");
        };
        let Taken::Sent(got) = read(m, b, &all(), 0) else {
            panic!("the receiver reads it");
        };
        assert_eq!(text_of(m, got).3, OUT_STRING_MAX);
        assert!(end_sent(&mut m.windows, b, 0));
        assert_eq!(collect_reply(&mut m.windows, a, id), Some(0));
        assert_eq!(
            m.windows.queues.store.counts().0,
            0,
            "the texts went back to the store"
        );
    }
}
