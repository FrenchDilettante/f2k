//! Posting: PostMessage, PostThreadMessage, the input path's messages, PostQuitMessage.

use rtl::user::{
    sync_only,
    Msg,
    Point,
    HWND_BROADCAST,
    QS_ALLPOSTMESSAGE,
    QS_KEY,
    QS_MOUSEBUTTON,
    QS_MOUSEMOVE,
    QS_POSTMESSAGE,
};

use super::*;
use crate::sched::thread::ThreadId;
use crate::status::*;
use crate::win32k::window::{Hwnd, LParam, WParam, Windows};

/// PostMessage: `message` posted to the window `hwnd`'s thread, stamped `time`; a null window
/// posts a thread message to `caller`, HWND_BROADCAST posts to every top-level window of
/// `caller`'s desktop. STATUS_INVALID_HANDLE for a handle naming no window, [`MESSAGE_SYNC_ONLY`]
/// for a message whose pointer a post cannot carry (guimsg `postptr`: WM_SETTEXT and WM_COPYDATA
/// to the caller's own window, [`rtl::user::sync_only`]), ERROR_NOT_ENOUGH_QUOTA
/// for a queue holding [`POSTED_LIMIT`] posted messages, STATUS_INSUFFICIENT_RESOURCES when the
/// posted messages' pool cannot grow.
pub fn post(
    windows: &mut Windows,
    caller: ThreadId,
    hwnd: Hwnd,
    message: u32,
    wparam: WParam,
    lparam: LParam,
    time: u32,
) -> Result<(), NtStatus> {
    let msg = |hwnd| Msg {
        hwnd,
        message,
        wparam,
        lparam,
        time,
        pt: Point::default(),
    };
    if hwnd != 0 && hwnd != HWND_BROADCAST && windows.window_from_handle(hwnd).is_none() {
        return Err(STATUS_INVALID_HANDLE);
    }
    if sync_only(message) {
        return Err(MESSAGE_SYNC_ONLY);
    }
    match hwnd {
        0 => post_to(windows, caller, msg(0)),
        HWND_BROADCAST => {
            let mut at = windows
                .thread_desktop_window(caller)
                .and_then(|desktop| windows.first_child(desktop));
            while let Some(window) = at {
                at = windows.next_sibling(window);
                if windows.client_proc(window).is_some() {
                    let thread = windows.window_thread(window);
                    post_to(windows, thread, msg(windows.handle_of(window)))?;
                }
            }
            Ok(())
        }
        handle => {
            let window = windows
                .window_from_handle(handle)
                .ok_or(STATUS_INVALID_HANDLE)?;
            let thread = windows.window_thread(window);
            post_to(windows, thread, msg(handle))
        }
    }
}

/// PostThreadMessage: `message` posted to the thread record `thread`'s queue (the caller resolved
/// the client id, [`queue_by_client_id`]), with no window, stamped `time`; [`MESSAGE_SYNC_ONLY`]
/// for a message whose pointer a post cannot carry, as PostMessage's.
pub fn post_thread(
    windows: &mut Windows,
    thread: ThreadId,
    message: u32,
    wparam: WParam,
    lparam: LParam,
    time: u32,
) -> Result<(), NtStatus> {
    if sync_only(message) {
        return Err(MESSAGE_SYNC_ONLY);
    }
    post_to(
        windows,
        thread,
        Msg {
            hwnd: 0,
            message,
            wparam,
            lparam,
            time,
            pt: Point::default(),
        },
    )
}

/// Append `msg` to the thread record `thread`'s queue: STATUS_INVALID_PARAMETER when it has none
/// (a thread that never called win32k, or the window manager's own), ERROR_NOT_ENOUGH_QUOTA when
/// it holds [`POSTED_LIMIT`] posted messages already, STATUS_INSUFFICIENT_RESOURCES when the pool
/// cannot grow.
fn post_to(windows: &mut Windows, thread: ThreadId, msg: Msg) -> Result<(), NtStatus> {
    let queues = &mut windows.queues;
    let id = queues.queue_of(thread).ok_or(STATUS_INVALID_PARAMETER)?;
    queues.push_posted(id, msg)
}

/// An input message for the thread record `thread`'s queue: `msg`, a key message with no window
/// yet (the read binds it, [`crate::win32k::input::bind`]), whose key the key state names `key`
/// ([`crate::win32k::input`]). A repeating key-down (`repeat`) whose queue's last unread input
/// message is the same message of the same key raises that message's repeat count (lParam's low
/// word) instead, as Windows 2000's queue folds a held key's repeats. Nothing when the thread has
/// no queue; the message is lost when the pool cannot grow.
pub fn post_input(windows: &mut Windows, thread: ThreadId, msg: Msg, key: u8, repeat: bool) {
    let queues = &mut windows.queues;
    let Some(id) = queues.queue_of(thread) else {
        return;
    };
    if repeat {
        if let Some(tail) = queues.queues[id.index as usize].input.tail {
            let last = &mut queues.posted.get_mut(tail).msg;
            let count = last.lparam as u32 & 0xFFFF;
            if last.message == msg.message && last.wparam == msg.wparam && count < 0xFFFF {
                last.lparam = ((last.lparam as u32 & !0xFFFF) | (count + 1)) as LParam;
                queues.change(id, QS_KEY);
                return;
            }
        }
    }
    let _ = queues.push(id, Lane::Input, msg, key);
}

/// The kind of input message `message` is (a queue-status bit): a mouse move, a mouse button's,
/// or a key's.
pub(super) fn input_kind(message: u32) -> u32 {
    match message {
        rtl::user::WM_MOUSEMOVE => QS_MOUSEMOVE,
        m if crate::win32k::mouse::is_mouse(m) => QS_MOUSEBUTTON,
        _ => QS_KEY,
    }
}

/// A mouse message for the thread record `thread`'s queue, as the input path posts it
/// ([`crate::win32k::mouse`]): `msg`, its window bound, its lParam and pt the screen point, of the
/// button `key` (0 for a move). A WM_MOUSEMOVE while the queue's last input message, not read yet,
/// is a WM_MOUSEMOVE takes that message's place instead (the one pending move Windows 2000 keeps a
/// queue: what the read learned of its window is forgotten). Nothing when the thread has no
/// queue; the message is lost when the pool cannot grow.
pub fn post_mouse(windows: &mut Windows, thread: ThreadId, msg: Msg, key: u8) {
    let queues = &mut windows.queues;
    let Some(id) = queues.queue_of(thread) else {
        return;
    };
    if msg.message == rtl::user::WM_MOUSEMOVE {
        if let Some(tail) = queues.queues[id.index as usize].input.tail {
            let last = queues.posted.get_mut(tail);
            if last.msg.message == rtl::user::WM_MOUSEMOVE {
                last.msg = msg;
                last.prepared = None;
                queues.change(id, QS_MOUSEMOVE);
                return;
            }
        }
    }
    let _ = queues.push(id, Lane::Input, msg, key);
}

/// What a read learned of the window of the mouse message the input entry `entry` of `caller`'s
/// queue holds ([`Taken::Prepare`]), kept with it: when the entry still holds a mouse message at
/// the point the read asked about (the thread may have moved it on meanwhile, its pending move
/// folding a newer one in).
pub fn keep_prepared(
    windows: &mut Windows,
    caller: ThreadId,
    entry: u32,
    prepared: crate::win32k::mouse::Prepared,
) {
    let queues = &mut windows.queues;
    let Some(id) = queues.queue_of(caller) else {
        return;
    };
    let mut at = queues.queues[id.index as usize].input.head;
    while let Some(index) = at {
        let posted = queues.posted.get_mut(index);
        if index == entry {
            if crate::win32k::mouse::is_mouse(posted.msg.message) && posted.msg.pt == prepared.pt {
                posted.prepared = Some(prepared);
            }
            return;
        }
        at = posted.next;
    }
}

/// PostQuitMessage: the caller's next read that finds nothing posted before it makes a WM_QUIT
/// with the exit code `code`.
pub fn post_quit(windows: &mut Windows, caller: ThreadId, code: u32) {
    let queues = &mut windows.queues;
    if let Some(id) = queues.queue_of(caller) {
        queues.queues[id.index as usize].quit = Some(code);
        queues.change(id, QS_POSTMESSAGE | QS_ALLPOSTMESSAGE);
    }
}

#[cfg(test)]
mod tests {
    use rtl::user::{WM_COPYDATA, WM_KEYDOWN, WM_SETTEXT, WM_USER, WS_CHILD};
    use rtl::winerror::ERROR_NOT_ENOUGH_QUOTA;

    use super::*;
    use crate::win32k::queue::testkit::*;

    /// The threadmsg capture: PostThreadMessage to the thread's own client id posts a message with
    /// no window; an id no queue has names none.
    #[test]
    fn a_thread_message_has_no_window() {
        let (m, _) = manager();
        let t = thread(m, 1, 0x100);
        let (found, _) = queue_by_client_id(&m.windows, 0x100).unwrap();
        assert_eq!(found, t);
        assert_eq!(queue_by_client_id(&m.windows, 0x104), None);
        post_thread(&mut m.windows, found, WM_USER + 7, 1, 2, 0).unwrap();
        let msg = msg_of(read(m, t, &all(), 0));
        assert_eq!(
            (msg.hwnd, msg.message, msg.wparam, msg.lparam),
            (0, WM_USER + 7, 1, 2)
        );
    }

    /// guimsg `postptr`: a message whose pointer a post cannot carry (WM_SETTEXT, WM_COPYDATA) is
    /// refused with ERROR_MESSAGE_SYNC_ONLY, to the caller's own window and as a thread message,
    /// nothing queued; a handle naming no window is refused first.
    #[test]
    fn a_pointer_message_is_not_posted() {
        let (m, atom) = manager();
        let t = thread(m, 1, 0x100);
        let h = popup(m, atom, t);
        deliver(m, t);
        for message in [WM_SETTEXT, WM_COPYDATA] {
            assert_eq!(
                post(&mut m.windows, t, h, message, 0, 0x5000, 0),
                Err(MESSAGE_SYNC_ONLY)
            );
            assert_eq!(
                post_thread(&mut m.windows, t, message, 0, 0x5000, 0),
                Err(MESSAGE_SYNC_ONLY)
            );
        }
        assert_eq!(
            post(&mut m.windows, t, 0x7FFF_FFFC, WM_SETTEXT, 0, 0, 0),
            Err(STATUS_INVALID_HANDLE)
        );
        assert_eq!(read(m, t, &all(), 0), Taken::Nothing { due: None });
    }

    /// HWND_BROADCAST posts to every top-level window of the caller's desktop, its children not.
    #[test]
    fn a_broadcast_posts_to_the_top_level_windows() {
        let (m, atom) = manager();
        let a = thread(m, 1, 0x100);
        let b = thread(m, 2, 0x200);
        let ha = popup(m, atom, a);
        let hb = popup(m, atom, b);
        window_at(m, atom, a, WS_CHILD, ha, 0, 0, 10, 10);
        deliver(m, a);
        deliver(m, b);
        post(&mut m.windows, a, HWND_BROADCAST, WM_USER, 0, 0, 0).unwrap();
        assert_eq!(msg_of(read(m, a, &all(), 0)).hwnd, ha);
        assert_eq!(read(m, a, &all(), 0), Taken::Nothing { due: None });
        assert_eq!(msg_of(read(m, b, &all(), 0)).hwnd, hb);
    }

    /// guimsg `quota`: a queue holds [`POSTED_LIMIT`] posted messages, the next post refused with
    /// ERROR_NOT_ENOUGH_QUOTA; another thread's queue still takes posts, and the full queue still
    /// takes the keyboard's input, the pool growing for them; a message taken out makes room again.
    #[test]
    fn a_full_queue_refuses_the_post_and_no_other() {
        let (m, _) = manager();
        let t = thread(m, 1, 0x100);
        let other = thread(m, 2, 0x200);
        for _ in 0..POSTED_LIMIT {
            post(&mut m.windows, t, 0, WM_USER, 0, 0, 0).unwrap();
        }
        assert_eq!(
            post(&mut m.windows, t, 0, WM_USER, 0, 0, 0),
            Err(NtStatus::from_win32(ERROR_NOT_ENOUGH_QUOTA))
        );
        post_thread(&mut m.windows, other, WM_USER, 0, 0, 0).unwrap();
        let key = Msg {
            message: WM_KEYDOWN,
            wparam: 0x41,
            ..Msg::default()
        };
        post_input(&mut m.windows, t, key, 0x41, false);
        assert_eq!(
            m.windows.queues.queues[t.0 as usize].input.count, 1,
            "the input message is queued past the limit"
        );
        read(m, t, &all(), 0);
        post(&mut m.windows, t, 0, WM_USER, 0, 0, 0).unwrap();
        assert_eq!(m.windows.queues.posted.live(), POSTED_LIMIT + 2);
    }

    /// A post wakes the queue it goes to, once, until the wakes are taken; a thread with no queue
    /// (the window manager's own) takes no post.
    #[test]
    fn a_post_wakes_its_queue() {
        let (m, _) = manager();
        thread(m, 1, 0x100);
        let b = thread(m, 2, 0x200);
        m.windows.queues.take_wakes();
        post_thread(&mut m.windows, b, WM_USER, 0, 0, 0).unwrap();
        assert!(m.windows.queues.take_wakes().is_only(b));
        assert!(m.windows.queues.take_wakes().is_empty());
        let desktop = m.windows.thread_desktop_window(b).unwrap();
        let system = m.windows.window_thread(desktop);
        assert_eq!(
            post_thread(&mut m.windows, system, WM_USER, 0, 0, 0),
            Err(STATUS_INVALID_PARAMETER)
        );
    }
}
