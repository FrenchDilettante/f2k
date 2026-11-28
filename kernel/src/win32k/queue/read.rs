//! Reading: GetMessage's and PeekMessage's filter and their read of the queue.

use rtl::user::{
    Msg,
    Point,
    QS_ALLPOSTMESSAGE,
    QS_HOTKEY,
    QS_INPUT,
    QS_KEY,
    QS_MOUSE,
    QS_PAINT,
    QS_POSTMESSAGE,
    QS_SENDMESSAGE,
    QS_TIMER,
    RECEIVED_MESSAGE,
    RECEIVED_QUIT,
    WM_KEYFIRST,
    WM_KEYLAST,
    WM_MOUSEFIRST,
    WM_MOUSELAST,
    WM_PAINT,
    WM_QUIT,
    WM_SYSTIMER,
    WM_TIMER,
};

use super::*;
use crate::sched::thread::ThreadId;
use crate::status::*;
use crate::win32k::window::{Hwnd, LParam, WParam, WindowId, Windows};

/// Which window's messages a read takes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WindowFilter {
    /// The thread's windows' and its thread messages (a null window).
    Any,
    /// The thread messages only (a window of -1).
    ThreadMessages,
    /// The window's own.
    Window(Hwnd),
}

/// A read's filter: the window, the message range (both bounds zero takes every message), and the
/// kinds of message (PeekMessage's PM_QS_* bits as queue-status bits; every kind when none).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Filter {
    pub window: WindowFilter,
    pub min: u32,
    pub max: u32,
    pub kinds: u32,
}

impl Filter {
    /// The filter of GetMessage's or PeekMessage's arguments (`flags` PeekMessage's, its PM_QS_*
    /// bits in the high word; GetMessage's take every kind).
    pub fn new(hwnd: Hwnd, min: u32, max: u32, flags: u32) -> Self {
        let window = match hwnd {
            0 => WindowFilter::Any,
            u32::MAX => WindowFilter::ThreadMessages,
            handle => WindowFilter::Window(handle),
        };
        let kinds = match (flags >> 16) & ALL_KINDS {
            0 => ALL_KINDS,
            kinds => kinds,
        };
        Filter {
            window,
            min,
            max,
            kinds,
        }
    }

    /// Whether the message `message` is in the range.
    fn in_range(&self, message: u32) -> bool {
        (self.min == 0 && self.max == 0) || (self.min <= message && message <= self.max)
    }

    /// Whether a message of the window `hwnd` (0: a thread message) passes the window filter.
    pub fn takes_window(&self, hwnd: Hwnd) -> bool {
        match self.window {
            WindowFilter::Any => true,
            WindowFilter::ThreadMessages => hwnd == 0,
            WindowFilter::Window(handle) => hwnd == handle,
        }
    }

    /// Whether the filter takes `message` for the window `hwnd`.
    pub fn takes(&self, hwnd: Hwnd, message: u32) -> bool {
        self.takes_window(hwnd) && self.in_range(message)
    }

    /// Whether the filter looks at the kind `kind` (a queue-status bit).
    fn looks_at(&self, kind: u32) -> bool {
        self.kinds & kind != 0
    }

    /// Whether the filter looks at queued messages at all (PM_QS_SENDMESSAGE alone does not).
    fn looks_at_queued(&self) -> bool {
        self.kinds & !QS_SENDMESSAGE != 0
    }

    /// The kinds of message a read with the filter looks for, as Windows 2000's CalcWakeMask
    /// makes its wake mask: the PM_QS_* kinds, and of those, for a range, the sent and posted
    /// messages and the kinds whose messages the range holds. QS_ALLPOSTMESSAGE only for a read of
    /// every message that looks at the posted ones: a range leaves it.
    pub fn wake_mask(&self) -> u32 {
        if self.min == 0 && self.max == 0 {
            if self.kinds & QS_POSTMESSAGE != 0 {
                return self.kinds | QS_ALLPOSTMESSAGE;
            }
            return self.kinds;
        }
        let holds = |first: u32, last: u32| self.min <= last && first <= self.max;
        let mut mask = QS_SENDMESSAGE | QS_POSTMESSAGE | QS_HOTKEY;
        if holds(WM_KEYFIRST, WM_KEYLAST) {
            mask |= QS_KEY;
        }
        if holds(WM_MOUSEFIRST, WM_MOUSELAST) {
            mask |= QS_MOUSE;
        }
        if holds(WM_TIMER, WM_TIMER) || holds(WM_SYSTIMER, WM_SYSTIMER) {
            mask |= QS_TIMER;
        }
        if holds(WM_PAINT, WM_PAINT) {
            mask |= QS_PAINT;
        }
        self.kinds & mask
    }
}

/// What a read found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Taken {
    /// A sent message, handed out: the read delivers it by callback ([`delivery`],
    /// [`end_received`]), then reads on.
    Sent(SentId),
    /// A posted message, or one the queue made (WM_QUIT, WM_PAINT, WM_TIMER).
    Message(Msg),
    /// A mouse message whose window the read has to ask where the point is first: the input
    /// entry, the window it goes to, the screen point, whether the thread's capture has it. The
    /// caller learns it ([`crate::win32k::mouse::hit_test`], [`crate::win32k::mouse::prepared`]),
    /// keeps it with the entry ([`keep_prepared`]) and reads again.
    Prepare {
        entry: u32,
        window: WindowId,
        pt: Point,
        captured: bool,
    },
    /// A mouse message, converted for the thread ([`crate::win32k::mouse::convert`]): what follows
    /// it before the thread has it is the caller's ([`crate::win32k::mouse::after_read`]).
    Mouse(crate::win32k::mouse::MouseRead),
    /// Nothing for the filter; the thread's next timer's due (interrupt time), if it has timers.
    Nothing { due: Option<u64> },
}

impl Taken {
    /// The receipt's kind for a message: WM_QUIT's own (GetMessage answers 0), the others'.
    pub fn kind_of(msg: &Msg) -> u32 {
        if msg.message == WM_QUIT {
            RECEIVED_QUIT
        } else {
            RECEIVED_MESSAGE
        }
    }
}

/// GetMessage's and PeekMessage's read of the caller's queue at `now` (interrupt time, 100 ns
/// units), the messages it takes out when `remove`: in the documented order, the messages sent to
/// the thread (whatever the filter), the posted messages the filter takes, WM_QUIT (whatever the
/// range), WM_PAINT, WM_TIMER. STATUS_INVALID_HANDLE when the filter names a window there is not.
pub fn take(
    windows: &mut Windows,
    caller: ThreadId,
    filter: &Filter,
    remove: bool,
    now: u64,
) -> Result<Taken, NtStatus> {
    if let WindowFilter::Window(handle) = filter.window {
        windows
            .window_from_handle(handle)
            .ok_or(STATUS_INVALID_HANDLE)?;
    }
    let Some(id) = windows.queues.queue_of(caller) else {
        return Ok(Taken::Nothing { due: None });
    };
    let time = millis(now);
    let taken = read_queue(windows, caller, id, filter, remove, now)?;
    let queue = &mut windows.queues.queues[id.index as usize];
    queue.last_read = time;
    queue.idle = matches!(taken, Taken::Nothing { .. });
    if let Taken::Message(msg) | Taken::Mouse(crate::win32k::mouse::MouseRead { msg, .. }) = taken {
        queue.message_time = msg.time;
        queue.message_pos = msg.pt;
    }
    Ok(taken)
}

/// [`take`]'s read of the queue `id`: the timers that came due mark it, then the kinds the filter
/// looks for are no longer new to it ([`wait_ready`]); what the read finds.
fn read_queue(
    windows: &mut Windows,
    caller: ThreadId,
    id: QueueId,
    filter: &Filter,
    remove: bool,
    now: u64,
) -> Result<Taken, NtStatus> {
    let time = millis(now);
    if windows.queues.timers.expire(caller, now) {
        windows.queues.queues[id.index as usize].changed |= QS_TIMER;
    }
    windows.queues.queues[id.index as usize].changed &= !filter.wake_mask();

    // The sent messages, handed out for their callbacks one at a time ([`take_for_callback`]).
    if let Some(index) = take_for_callback(windows, caller) {
        return Ok(Taken::Sent(index));
    }
    if !filter.looks_at_queued() {
        return Ok(Taken::Nothing { due: None });
    }

    // The posted messages.
    if filter.looks_at(QS_POSTMESSAGE) {
        let queues = &mut windows.queues;
        let mut previous = None;
        let mut at = queues.queues[id.index as usize].posted.head;
        while let Some(entry) = at {
            let msg = queues.posted.get(entry).msg;
            if filter.takes(msg.hwnd, msg.message) {
                if remove {
                    queues.unlink_posted(id.index, Lane::Posted, previous, entry);
                }
                return Ok(Taken::Message(msg));
            }
            previous = Some(entry);
            at = queues.posted.get(entry).next;
        }
    }

    // The input messages, the keyboard's and the mouse's, in the order they came. A key message is
    // bound to its window as it is read (the thread's focus window now, or its active window), so
    // the filter judges the bound window and message. A key message taken out is the next step of
    // the thread's key state; one with no window to go to is discarded, still a step of the key
    // state, so that no key stays down for the thread. A mouse message is converted for its
    // window first ([`read_mouse`]).
    if filter.looks_at(QS_INPUT) {
        let mut previous = None;
        let mut at = windows.queues.queues[id.index as usize].input.head;
        while let Some(entry) = at {
            let Posted { msg, key, next, .. } = *windows.queues.posted.get(entry);
            if crate::win32k::mouse::is_mouse(msg.message) {
                match read_mouse(windows, caller, id, filter, remove, previous, entry) {
                    MouseStep::Found(taken) => return Ok(taken),
                    MouseStep::Again => continue,
                    MouseStep::Skipped => previous = Some(entry),
                    MouseStep::Dropped => {}
                }
                at = next;
                continue;
            }
            if !filter.looks_at(QS_KEY) {
                previous = Some(entry);
                at = next;
                continue;
            }
            match crate::win32k::input::bind(windows, caller, msg) {
                None => {
                    windows
                        .queues
                        .unlink_posted(id.index, Lane::Input, previous, entry);
                    crate::win32k::input::read(windows, caller, &msg, key);
                }
                Some(msg) if filter.takes(msg.hwnd, msg.message) => {
                    if remove {
                        windows
                            .queues
                            .unlink_posted(id.index, Lane::Input, previous, entry);
                        crate::win32k::input::read(windows, caller, &msg, key);
                    }
                    return Ok(Taken::Message(msg));
                }
                Some(_) => previous = Some(entry),
            }
            at = next;
        }
    }

    // WM_QUIT, whatever the range: a thread message.
    if filter.looks_at(QS_POSTMESSAGE) {
        let queues = &mut windows.queues;
        if let Some(code) = queues.queues[id.index as usize].quit {
            if filter.takes_window(0) {
                if remove {
                    queues.queues[id.index as usize].quit = None;
                }
                return Ok(Taken::Message(made(0, WM_QUIT, code, 0, time)));
            }
        }
    }

    // WM_PAINT, for a window of the thread's with an update region.
    if filter.looks_at(QS_PAINT) && filter.in_range(WM_PAINT) {
        if let Some(hwnd) = crate::win32k::paint::next_paint(windows, caller, filter) {
            return Ok(Taken::Message(made(hwnd, WM_PAINT, 0, 0, time)));
        }
    }

    // The caret's blink, which makes no message: the thread's caret turned when its turn came.
    crate::win32k::caret::blink(windows, caller, now);

    // WM_TIMER, for a timer of the thread's that came due.
    let caret_due = crate::win32k::caret::next_due(windows, caller);
    let timers = &mut windows.queues.timers;
    timers.expire(caller, now);
    if filter.looks_at(QS_TIMER) && filter.in_range(WM_TIMER) {
        if let Some((hwnd, id, func)) = timers.next_ready(caller, filter, remove) {
            return Ok(Taken::Message(made(
                hwnd,
                WM_TIMER,
                id,
                func as LParam,
                time,
            )));
        }
    }
    let due = match (timers.next_due(caller), caret_due) {
        (Some(timer), Some(caret)) => Some(timer.min(caret)),
        (timer, caret) => timer.or(caret),
    };
    Ok(Taken::Nothing { due })
}

/// What [`read_mouse`] did with a mouse message's entry.
enum MouseStep {
    /// The read's answer: the message, or its preparation.
    Found(Taken),
    /// The entry changed in place (a window that lets the point through gave it to its parent):
    /// look at it again.
    Again,
    /// The filter does not take it: it stays.
    Skipped,
    /// It is gone: its window is, or no window would have it.
    Dropped,
}

/// The read's look at the mouse message in the input entry `entry` of the queue `id` (`previous`
/// the entry before it), for `caller` (see [`crate::win32k::mouse`]): its window, the capture
/// window when the thread has the capture; what the read learned of it, or the preparation that
/// learns it; its conversion, judged by the filter; taken out when `remove`, the thread's key state
/// and its last press moving with it.
fn read_mouse(
    windows: &mut Windows,
    caller: ThreadId,
    id: QueueId,
    filter: &Filter,
    remove: bool,
    previous: Option<u32>,
    entry: u32,
) -> MouseStep {
    let Posted {
        msg, key, prepared, ..
    } = *windows.queues.posted.get(entry);
    if !filter.looks_at(input_kind(msg.message)) {
        return MouseStep::Skipped;
    }
    let discard = |windows: &mut Windows| {
        windows
            .queues
            .unlink_posted(id.index, Lane::Input, previous, entry);
        crate::win32k::input::read_button(windows, caller, msg.message, key);
        MouseStep::Dropped
    };
    let capture = crate::win32k::mouse::capture_of(windows, caller);
    let Some(window) = capture.or_else(|| windows.window_from_handle(msg.hwnd)) else {
        return discard(windows);
    };
    let hwnd = windows.handle_of(window);
    if !filter.takes_window(hwnd) {
        return MouseStep::Skipped;
    }
    let prepared = match prepared {
        Some(p) if p.hwnd == hwnd && p.pt == msg.pt => p,
        _ => {
            return MouseStep::Found(Taken::Prepare {
                entry,
                window,
                pt: msg.pt,
                captured: capture.is_some(),
            })
        }
    };
    if crate::win32k::mouse::lets_through(prepared.hit) {
        // HTTRANSPARENT: the point goes through to the parent, when it is the thread's.
        let parent = windows
            .parent_of(window)
            .filter(|_| windows.window_style(window) & rtl::user::WS_CHILD != 0)
            .filter(|&p| windows.window_thread(p) == caller);
        let Some(parent) = parent else {
            return discard(windows);
        };
        let parent = windows.handle_of(parent);
        let posted = windows.queues.posted.get_mut(entry);
        posted.msg.hwnd = parent;
        posted.prepared = None;
        return MouseStep::Again;
    }
    let click = windows.queues.queues[id.index as usize].click;
    let (converted, client_message) =
        crate::win32k::mouse::convert(windows, window, &msg, &prepared, click);
    if !filter.in_range(converted.message) {
        return MouseStep::Skipped;
    }
    if remove {
        windows
            .queues
            .unlink_posted(id.index, Lane::Input, previous, entry);
        crate::win32k::input::read_button(windows, caller, client_message, key);
        let queue = &mut windows.queues.queues[id.index as usize];
        queue.click = crate::win32k::mouse::next_click(
            click,
            client_message,
            hwnd,
            converted.time,
            converted.pt,
        );
    }
    MouseStep::Found(Taken::Mouse(crate::win32k::mouse::MouseRead {
        msg: converted,
        client_message,
        hit: prepared.hit,
        captured: capture.is_some(),
        removed: remove,
    }))
}

/// A message the queue makes, stamped `time`.
pub(super) fn made(hwnd: Hwnd, message: u32, wparam: WParam, lparam: LParam, time: u32) -> Msg {
    Msg {
        hwnd,
        message,
        wparam,
        lparam,
        time,
        pt: Point::default(),
    }
}

/// The interrupt time `now` (100 ns units) in milliseconds, as MSG's time counts them (it wraps,
/// as GetTickCount does).
pub fn millis(now: u64) -> u32 {
    (now / 10_000) as u32
}

#[cfg(test)]
mod tests {
    use rtl::user::{PM_QS_POSTMESSAGE, PM_QS_SENDMESSAGE, WM_USER};

    use super::*;
    use crate::win32k::queue::testkit::*;
    use crate::win32k::window::WindowManager;

    /// The post capture: GetMessage takes the posted message with its window and parameters.
    #[test]
    fn a_posted_message_is_read_back() {
        let (m, atom) = manager();
        let t = thread(m, 1, 0x100);
        let h = popup(m, atom, t);
        deliver(m, t);
        post(&mut m.windows, t, h, WM_USER + 1, 11, 22, 5).unwrap();
        let msg = msg_of(read(m, t, &all(), 0));
        assert_eq!(
            msg,
            Msg {
                hwnd: h,
                message: WM_USER + 1,
                wparam: 11,
                lparam: 22,
                time: 5,
                pt: Point::default(),
            }
        );
        assert_eq!(Taken::kind_of(&msg), RECEIVED_MESSAGE);
        assert_eq!(read(m, t, &all(), 0), Taken::Nothing { due: None });
    }

    /// The peek capture: PM_NOREMOVE twice hands out the first message both times, PM_REMOVE
    /// takes the first then the second, then the queue is empty.
    #[test]
    fn peek_leaves_or_takes() {
        let (m, atom) = manager();
        let t = thread(m, 1, 0x100);
        let h = popup(m, atom, t);
        deliver(m, t);
        post(&mut m.windows, t, h, WM_USER + 1, 1, 0, 0).unwrap();
        post(&mut m.windows, t, h, WM_USER + 2, 2, 0, 0).unwrap();
        let mut peek = |remove| take(&mut m.windows, t, &all(), remove, 0);
        let first = |taken| msg_of(taken).message;
        assert_eq!(first(peek(false).unwrap()), WM_USER + 1);
        assert_eq!(first(peek(false).unwrap()), WM_USER + 1);
        assert_eq!(first(peek(true).unwrap()), WM_USER + 1);
        assert_eq!(first(peek(true).unwrap()), WM_USER + 2);
        assert_eq!(peek(true), Ok(Taken::Nothing { due: None }));
    }

    /// The filters: a window's messages alone for its handle, the thread messages alone for -1,
    /// the range inclusive (both bounds zero: everything); a message the filter leaves stays,
    /// and the ones behind it that it takes come out first. A handle naming no window is refused.
    #[test]
    fn the_filters_pick_by_window_and_range() {
        let (m, atom) = manager();
        let t = thread(m, 1, 0x100);
        let a = popup(m, atom, t);
        let b = popup(m, atom, t);
        deliver(m, t);
        post(&mut m.windows, t, a, WM_USER + 1, 0, 0, 0).unwrap();
        post(&mut m.windows, t, 0, WM_USER + 2, 0, 0, 0).unwrap();
        post(&mut m.windows, t, b, WM_USER + 3, 0, 0, 0).unwrap();
        let next = |m: &mut WindowManager, filter: Filter| msg_of(read(m, t, &filter, 0)).message;
        assert_eq!(next(m, Filter::new(b, 0, 0, 0)), WM_USER + 3);
        assert_eq!(next(m, Filter::new(u32::MAX, 0, 0, 0)), WM_USER + 2);
        post(&mut m.windows, t, a, WM_USER + 9, 0, 0, 0).unwrap();
        assert_eq!(
            next(m, Filter::new(0, WM_USER + 5, WM_USER + 9, 0)),
            WM_USER + 9
        );
        assert_eq!(next(m, all()), WM_USER + 1);
        assert_eq!(
            take(
                &mut m.windows,
                t,
                &Filter::new(0x7FFF_FFFC, 0, 0, 0),
                true,
                0
            ),
            Err(STATUS_INVALID_HANDLE)
        );
        assert_eq!(
            post(&mut m.windows, t, 0x7FFF_FFFC, WM_USER, 0, 0, 0),
            Err(STATUS_INVALID_HANDLE)
        );
    }

    /// The quit capture: PostQuitMessage(7) makes a WM_QUIT with wParam 7 once nothing posted is
    /// left before it (GetMessage's 0), whatever the range; a window's filter does not take it;
    /// PM_NOREMOVE leaves it.
    #[test]
    fn quit_comes_after_the_posted_messages() {
        let (m, atom) = manager();
        let t = thread(m, 1, 0x100);
        let h = popup(m, atom, t);
        deliver(m, t);
        post(&mut m.windows, t, 0, WM_USER, 0, 0, 0).unwrap();
        post_quit(&mut m.windows, t, 7);
        assert_eq!(msg_of(read(m, t, &all(), 0)).message, WM_USER);
        assert_eq!(
            read(m, t, &Filter::new(h, 0, 0, 0), 0),
            Taken::Nothing { due: None },
            "a window's filter"
        );
        let ranged = Filter::new(0, WM_USER, WM_USER, 0);
        let quit = msg_of(take(&mut m.windows, t, &ranged, false, 0).unwrap());
        assert_eq!((quit.hwnd, quit.message, quit.wparam), (0, WM_QUIT, 7));
        assert_eq!(Taken::kind_of(&quit), RECEIVED_QUIT);
        assert_eq!(msg_of(read(m, t, &all(), 0)).message, WM_QUIT);
        assert_eq!(read(m, t, &all(), 0), Taken::Nothing { due: None });
    }

    /// Sent messages come before anything posted, whatever the filter; PM_QS_SENDMESSAGE alone
    /// looks at nothing else.
    #[test]
    fn sent_messages_come_first() {
        let (m, atom) = manager();
        let t = thread(m, 1, 0x100);
        post(&mut m.windows, t, 0, WM_USER, 0, 0, 0).unwrap();
        popup(m, atom, t);
        let posted_only = Filter::new(0, WM_USER, WM_USER, PM_QS_POSTMESSAGE);
        assert!(matches!(read(m, t, &posted_only, 0), Taken::Sent(_)));
        assert!(end_sent(&mut m.windows, t, 1));
        assert_eq!(deliver(m, t).len(), 2);
        let only_sent = Filter::new(0, 0, 0, PM_QS_SENDMESSAGE);
        assert_eq!(read(m, t, &only_sent, 0), Taken::Nothing { due: None });
        assert_eq!(msg_of(read(m, t, &all(), 0)).message, WM_USER);
        assert!(
            !end_sent(&mut m.windows, t, 0),
            "nothing is being delivered"
        );
    }

    /// A range's read looks for the kinds its messages are, and the sent and posted messages; a
    /// read of every message for QS_ALLPOSTMESSAGE too.
    #[test]
    fn a_range_looks_for_its_kinds() {
        assert_eq!(all().wake_mask(), ALL_KINDS | QS_ALLPOSTMESSAGE);
        let only_sent = Filter::new(0, 0, 0, rtl::user::PM_QS_SENDMESSAGE);
        assert_eq!(only_sent.wake_mask(), QS_SENDMESSAGE);
        let user = Filter::new(0, WM_USER, WM_USER, 0);
        assert_eq!(
            user.wake_mask(),
            QS_SENDMESSAGE | QS_POSTMESSAGE | QS_HOTKEY
        );
        let timer = Filter::new(0, WM_TIMER, WM_TIMER, 0);
        assert_eq!(timer.wake_mask() & (QS_TIMER | QS_KEY), QS_TIMER);
        let keys = Filter::new(0, WM_KEYFIRST, WM_KEYLAST, 0);
        assert_eq!(keys.wake_mask() & (QS_KEY | QS_PAINT), QS_KEY);
    }
}
