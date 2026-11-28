//! The console server's sends, at the session's end.

use super::*;
use crate::win32k::window::{Hwnd, LParam, LResult, WParam, Windows};

/// Where a message the server sends goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServerSending {
    /// Queued for the window's thread: the server waits for the answer ([`server_reply`]).
    Waiting(SentId),
    /// Nowhere: the handle names no window, the window's procedure is the window manager's, its
    /// thread has no queue, or the sent messages' pool cannot grow.
    Unreachable,
}

/// What became of a message the server sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServerReply {
    /// The window procedure's answer.
    Answered(LResult),
    /// Its window or its receiver's queue went before it was answered.
    Dropped,
}

/// The console server's SendMessage, for the session's end (`crate::session`): `message` queued
/// for the window `hwnd`'s thread as another thread's send is, the server (no queue) waiting on its
/// own event ([`wait_for_server`]). Windows 2000's csrss sends WM_QUERYENDSESSION and
/// WM_ENDSESSION from a GUI thread with a queue; F2K's server is the console's control thread, a
/// system thread, so the answer is marked for it instead.
pub fn server_send(
    windows: &mut Windows,
    hwnd: Hwnd,
    message: u32,
    wparam: WParam,
    lparam: LParam,
) -> ServerSending {
    let Some(window) = windows.window_from_handle(hwnd) else {
        return ServerSending::Unreachable;
    };
    let Some(proc) = windows.client_proc(window) else {
        return ServerSending::Unreachable;
    };
    let thread = windows.window_thread(window);
    let queues = &mut windows.queues;
    let Some(receiver) = queues.queue_of(thread) else {
        return ServerSending::Unreachable;
    };
    let Some(id) = queues.allocate_sent(Sent {
        receiver: Some(receiver),
        server: true,
        window: Some(window),
        hwnd,
        proc,
        message,
        wparam,
        lparam,
        ..Sent::EMPTY
    }) else {
        return ServerSending::Unreachable;
    };
    queues.push_sent(receiver, id);
    ServerSending::Waiting(id)
}

/// What became of the server's send `id`, once its receiver answered it or it was dropped (the
/// record goes back to the pool); none while it waits.
pub fn server_reply(windows: &mut Windows, id: SentId) -> Option<ServerReply> {
    let queues = &mut windows.queues;
    let sent = queues.sent_at(id)?;
    let reply = match sent.state {
        State::Answered | State::Replied if sent.server => ServerReply::Answered(sent.result),
        State::Dropped => ServerReply::Dropped,
        State::Queued | State::Received | State::Answered | State::Replied => return None,
    };
    queues.collected(id);
    Some(reply)
}

/// The server waits no more on its send `id` (its time ran out, or the receiving process ended): a
/// message not handed out yet goes; one being delivered is left to its receiver, its answer then
/// going nowhere; one answered or dropped goes back to the pool.
pub fn server_abandon(windows: &mut Windows, id: SentId) {
    let queues = &mut windows.queues;
    let Some(sent) = queues.sent_at(id) else {
        return;
    };
    match sent.state {
        State::Queued => {
            if let Some(receiver) = sent.receiver {
                queues.unlink_sent(receiver, id);
            }
            queues.free_sent(id);
        }
        State::Received | State::Replied => queues.sent.at_mut(id).server = false,
        State::Answered | State::Dropped => queues.free_sent(id),
    }
}

#[cfg(test)]
mod tests {
    use rtl::user::{WM_DESTROY, WM_NCDESTROY};

    use super::*;
    use crate::win32k::queue::testkit::*;
    use crate::win32k::window::WindowManager;

    /// The server's sends: queued for the window's thread as another thread's are, the receiver
    /// woken; the procedure's answer, or ReplyMessage's, marks the server's event and is collected
    /// once. The default procedure answers WM_QUERYENDSESSION TRUE. A window the window manager
    /// runs, or no window, is unreachable.
    #[test]
    fn the_server_sends_and_collects_the_answer() {
        use rtl::user::{WM_ENDSESSION, WM_QUERYENDSESSION};
        assert_eq!(default_answer(WM_QUERYENDSESSION), 1);
        assert_eq!(default_answer(WM_ENDSESSION), 0);
        let (m, atom) = manager();
        let a = thread(m, 1, 0x100);
        let ha = popup(m, atom, a);
        deliver(m, a);
        let desktop = m.windows.thread_desktop_window(a).unwrap();
        let desktop = m.windows.handle_of(desktop);
        assert_eq!(
            server_send(&mut m.windows, desktop, WM_QUERYENDSESSION, 0, 0),
            ServerSending::Unreachable
        );
        assert_eq!(
            server_send(&mut m.windows, 0x7FFF_FFFC, WM_QUERYENDSESSION, 0, 0),
            ServerSending::Unreachable
        );

        m.windows.queues.take_wakes();
        let logoff = rtl::user::ENDSESSION_LOGOFF as LParam;
        let ServerSending::Waiting(id) =
            server_send(&mut m.windows, ha, WM_QUERYENDSESSION, 0, logoff)
        else {
            panic!("queued for the window's thread");
        };
        assert!(
            m.windows.queues.take_wakes().is_only(a),
            "the receiver woken"
        );
        assert!(!m.windows.queues.take_server_wake());
        assert_eq!(server_reply(&mut m.windows, id), None);
        let Taken::Sent(got) = read(m, a, &all(), 0) else {
            panic!("the receiver reads it");
        };
        let head = head_of(&m.windows, got).unwrap();
        assert_eq!(
            (
                head.proc,
                head.msg.hwnd,
                head.msg.message,
                head.msg.wparam,
                head.msg.lparam
            ),
            (PROC, ha, WM_QUERYENDSESSION, 0, logoff)
        );
        assert_eq!(server_reply(&mut m.windows, id), None, "being delivered");
        assert!(end_sent(&mut m.windows, a, 1));
        assert!(m.windows.queues.take_server_wake());
        assert!(m.windows.queues.take_wakes().is_empty(), "no thread woken");
        assert_eq!(
            server_reply(&mut m.windows, id),
            Some(ServerReply::Answered(1))
        );
        assert_eq!(server_reply(&mut m.windows, id), None, "collected once");

        // ReplyMessage answers the server too; the procedure's own answer is dropped.
        let ServerSending::Waiting(id) = server_send(&mut m.windows, ha, WM_ENDSESSION, 1, 0)
        else {
            panic!("queued");
        };
        read(m, a, &all(), 0);
        assert!(reply(&mut m.windows, a, 0));
        assert!(m.windows.queues.take_server_wake());
        assert!(end_sent(&mut m.windows, a, 9));
        assert_eq!(
            server_reply(&mut m.windows, id),
            Some(ServerReply::Answered(0))
        );
    }

    /// A server's send whose window goes before it is read, or whose receiver's queue ends, is
    /// dropped, not answered 0 (which would read as a refusal); one the server stops waiting on
    /// goes from the receiver's list, or is left to the delivery under way, its answer going
    /// nowhere.
    #[test]
    fn a_server_send_is_dropped_or_abandoned() {
        use rtl::user::WM_QUERYENDSESSION;
        let (m, atom) = manager();
        let b = thread(m, 2, 0x200);
        let hb = popup(m, atom, b);
        deliver(m, b);
        let ServerSending::Waiting(id) = server_send(&mut m.windows, hb, WM_QUERYENDSESSION, 0, 0)
        else {
            panic!("queued");
        };
        let WindowManager {
            windows, classes, ..
        } = &mut *m;
        Windows::destroy_window_handle(&mut QueueSession::new(windows, classes), b, hb).unwrap();
        assert_eq!(deliver(m, b), vec![(hb, WM_DESTROY), (hb, WM_NCDESTROY)]);
        assert!(m.windows.queues.take_server_wake());
        assert_eq!(server_reply(&mut m.windows, id), Some(ServerReply::Dropped));

        let hb = popup(m, atom, b);
        deliver(m, b);
        let ServerSending::Waiting(id) = server_send(&mut m.windows, hb, WM_QUERYENDSESSION, 0, 0)
        else {
            panic!("queued");
        };
        detach(&mut m.windows, b);
        assert_eq!(server_reply(&mut m.windows, id), Some(ServerReply::Dropped));

        // Abandoned while queued: the receiver never sees it.
        let b = thread(m, 3, 0x300);
        let hb = popup(m, atom, b);
        deliver(m, b);
        let ServerSending::Waiting(id) = server_send(&mut m.windows, hb, WM_QUERYENDSESSION, 0, 0)
        else {
            panic!("queued");
        };
        server_abandon(&mut m.windows, id);
        assert_eq!(server_reply(&mut m.windows, id), None);
        assert_eq!(deliver(m, b), vec![]);
        // Abandoned while delivered: the delivery ends with nobody to answer.
        let ServerSending::Waiting(id) = server_send(&mut m.windows, hb, WM_QUERYENDSESSION, 0, 0)
        else {
            panic!("queued");
        };
        assert!(matches!(read(m, b, &all(), 0), Taken::Sent(_)));
        server_abandon(&mut m.windows, id);
        m.windows.queues.take_server_wake();
        assert!(end_sent(&mut m.windows, b, 1));
        assert!(!m.windows.queues.take_server_wake());
        assert_eq!(server_reply(&mut m.windows, id), None);
        assert!(m.windows.queues.sent.live() == 0, "every record back");
    }
}
