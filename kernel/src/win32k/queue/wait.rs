//! Waiting, and the thread's state of its reads: WaitMessage, GetQueueStatus, the hung test.

use rtl::user::{
    Point,
    QS_ALLINPUT,
    QS_ALLPOSTMESSAGE,
    QS_PAINT,
    QS_POSTMESSAGE,
    QS_SENDMESSAGE,
    QS_TIMER,
};

use super::*;
use crate::sched::thread::ThreadId;
use crate::status::*;
use crate::win32k::window::{Hwnd, Windows};

/// How long a thread that is not idle may go without reading its queue before it is deemed hung,
/// in milliseconds (Windows 2000's HungAppTimeout, 5 s).
pub const HUNG_TIMEOUT: u32 = 5000;

/// What WaitMessage's wait found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Waited {
    /// Something came to the queue since its last read looked for it: WaitMessage returns.
    Ready,
    /// Nothing new: the thread waits on its queue, until its next timer's due (interrupt time) if
    /// it has timers.
    Wait { due: Option<u64> },
}

/// WaitMessage's look at the caller's queue at `now` (interrupt time): ready when something came
/// to it since a read last looked for that kind (Windows 2000's change bits: a message already in
/// the queue that a read saw, and left, does not count; a timer that came due since does).
/// The thread idles meanwhile: it is never deemed hung while it waits.
pub fn wait_ready(windows: &mut Windows, caller: ThreadId, now: u64) -> Waited {
    wait_ready_for(windows, caller, now, QS_ALLINPUT)
}

/// [`wait_ready`] for the kinds `mask` (queue-status bits) alone: MsgWaitForMultipleObjects' wake
/// mask.
pub fn wait_ready_for(windows: &mut Windows, caller: ThreadId, now: u64, mask: u32) -> Waited {
    wait_ready_with(windows, caller, now, mask, false)
}

/// [`wait_ready_for`], and with `available` (MWMO_INPUTAVAILABLE) ready too when the queue holds
/// input of the mask's kinds already ([`holds`]), a read having seen it or not.
pub fn wait_ready_with(
    windows: &mut Windows,
    caller: ThreadId,
    now: u64,
    mask: u32,
    available: bool,
) -> Waited {
    let Some(id) = windows.queues.queue_of(caller) else {
        return Waited::Ready;
    };
    if windows.queues.timers.expire(caller, now) {
        windows.queues.queues[id.index as usize].changed |= QS_TIMER;
    }
    let mask = mask & (QS_ALLINPUT | QS_ALLPOSTMESSAGE);
    if available && holds(windows, caller, id) & mask != 0 {
        windows.queues.queues[id.index as usize].idle = true;
        return Waited::Ready;
    }
    let queue = &mut windows.queues.queues[id.index as usize];
    queue.idle = true;
    if queue.changed & mask != 0 {
        return Waited::Ready;
    }
    // The caret blinks while the thread waits, as while it reads.
    crate::win32k::caret::blink(windows, caller, now);
    let due = match (
        windows.queues.timers.next_due(caller),
        crate::win32k::caret::next_due(windows, caller),
    ) {
        (Some(timer), Some(caret)) => Some(timer.min(caret)),
        (timer, caret) => timer.or(caret),
    };
    Waited::Wait { due }
}

/// The kinds of message (queue-status bits) the caller's queue `id` holds now, seen by a read or
/// not: Windows 2000's wake bits. Its timers' expirations are the caller's to mark first.
fn holds(windows: &Windows, caller: ThreadId, id: QueueId) -> u32 {
    let queue = &windows.queues.queues[id.index as usize];
    let mut kinds = 0;
    if queue.posted.head.is_some() || queue.quit.is_some() {
        kinds |= QS_POSTMESSAGE | QS_ALLPOSTMESSAGE;
    }
    if queue.sent.head.is_some() {
        kinds |= QS_SENDMESSAGE;
    }
    let mut at = queue.input.head;
    while let Some(entry) = at {
        let posted = windows.queues.posted.get(entry);
        kinds |= input_kind(posted.msg.message);
        at = posted.next;
    }
    if windows.queues.timers.any_ready(caller) {
        kinds |= QS_TIMER;
    }
    if crate::win32k::paint::next_paint(windows, caller, &Filter::new(0, 0, 0, 0)).is_some() {
        kinds |= QS_PAINT;
    }
    kinds
}

/// GetQueueStatus: the kinds of message among `flags` (QS_* bits) the caller's queue holds now in
/// the high word (Windows 2000's wake bits), and those given it since a read or this call last
/// looked for them and still held in the low word (its change bits, which a kind's last message
/// taken out clears with its wake bit); the change bits of `flags` are cleared, as Windows 2000's
/// _GetQueueStatus clears them. Its timers' expirations mark it first.
pub fn queue_status(windows: &mut Windows, caller: ThreadId, now: u64, flags: u32) -> u32 {
    let Some(id) = windows.queues.queue_of(caller) else {
        return 0;
    };
    if windows.queues.timers.expire(caller, now) {
        windows.queues.queues[id.index as usize].changed |= QS_TIMER;
    }
    let flags = flags & (QS_ALLINPUT | QS_ALLPOSTMESSAGE);
    let held = holds(windows, caller, id) & flags;
    let queue = &mut windows.queues.queues[id.index as usize];
    let changed = queue.changed & held;
    queue.changed &= !flags;
    (held & 0xFFFF) << 16 | (changed & 0xFFFF)
}

/// ShowCursor's display count at a queue's start: -1, the cursor hidden, on a machine without a
/// mouse, as Windows 2000's CreateQueue starts it (F2K's user32 answers SM_MOUSEPRESENT 0); 0 with
/// one.
pub(super) const CURSOR_LEVEL_START: i32 = -1;

/// ShowCursor: the caller's queue's display count, one up when `show`, one down otherwise; the new
/// count (Windows 2000 keeps it a queue, a thread's own while it attaches to no other).
pub fn show_cursor(windows: &mut Windows, caller: ThreadId, show: bool) -> i32 {
    let Some(id) = windows.queues.queue_of(caller) else {
        return 0;
    };
    let queue = &mut windows.queues.queues[id.index as usize];
    queue.cursor_level += if show { 1 } else { -1 };
    queue.cursor_level
}

/// GetMessageTime: the time of the last message the caller's reads retrieved (PeekMessage's
/// PM_NOREMOVE included; a sent message is not retrieved), 0 before the first.
pub fn message_time(windows: &Windows, caller: ThreadId) -> u32 {
    windows.queues.queue_of(caller).map_or(0, |id| {
        windows.queues.queues[id.index as usize].message_time
    })
}

/// GetMessagePos: the cursor position of the last message the caller's reads retrieved, x in the
/// low word, y in the high word.
pub fn message_pos(windows: &Windows, caller: ThreadId) -> u32 {
    let pos = windows
        .queues
        .queue_of(caller)
        .map_or(Point::default(), |id| {
            windows.queues.queues[id.index as usize].message_pos
        });
    (pos.x as u16 as u32) | ((pos.y as u16 as u32) << 16)
}

/// Whether the thread record `thread` is hung at `time` (milliseconds): more than
/// [`HUNG_TIMEOUT`] without reading its queue, its last read having found something. As on
/// Windows 2000, a thread whose last read found nothing (GetMessage waiting, a PeekMessage loop
/// polling) is not hung.
pub fn hung(windows: &Windows, thread: ThreadId, time: u32) -> bool {
    windows.queues.queue_of(thread).is_some_and(|id| {
        let queue = &windows.queues.queues[id.index as usize];
        !queue.idle && time.wrapping_sub(queue.last_read) > HUNG_TIMEOUT
    })
}

/// IsHungAppWindow: whether the window `hwnd`'s thread is hung at `time` ([`hung`]); a window of
/// the caller's own thread, or of the window manager's, never is. STATUS_INVALID_HANDLE for a
/// handle naming no window.
pub fn window_hung(
    windows: &Windows,
    caller: ThreadId,
    hwnd: Hwnd,
    time: u32,
) -> Result<bool, NtStatus> {
    let window = windows
        .window_from_handle(hwnd)
        .ok_or(STATUS_INVALID_HANDLE)?;
    let thread = windows.window_thread(window);
    Ok(thread != caller && windows.client_proc(window).is_some() && hung(windows, thread, time))
}

#[cfg(test)]
mod tests {
    use rtl::user::{QS_KEY, WM_USER};

    use super::*;
    use crate::win32k::queue::testkit::*;
    use crate::win32k::window::WindowManager;

    /// MsgWaitForMultipleObjects' look at the queue: only the wake mask's kinds end it, a post
    /// for QS_POSTMESSAGE, not for QS_KEY alone; a read that looks for them makes them old.
    #[test]
    fn a_message_wait_looks_at_its_kinds() {
        let (m, _) = manager();
        let t = thread(m, 1, 0x100);
        read(m, t, &all(), 0);
        assert!(matches!(
            wait_ready_for(&mut m.windows, t, 0, QS_POSTMESSAGE),
            Waited::Wait { .. }
        ));
        post_thread(&mut m.windows, t, WM_USER, 0, 0, 0).unwrap();
        assert!(matches!(
            wait_ready_for(&mut m.windows, t, 0, QS_KEY),
            Waited::Wait { .. }
        ));
        assert_eq!(
            wait_ready_for(&mut m.windows, t, 0, QS_POSTMESSAGE),
            Waited::Ready
        );
        read(m, t, &all(), 0);
        assert!(matches!(
            wait_ready_for(&mut m.windows, t, 0, QS_ALLINPUT),
            Waited::Wait { .. }
        ));
    }

    /// WaitMessage wakes on what came to the queue since a read last looked for it, as the wait
    /// capture has it: a message posted before is new, one a peek saw and left is not, a timer
    /// coming due is, a post from another thread is. A read that looks only for sent messages
    /// leaves a post new.
    #[test]
    fn wait_message_wakes_on_what_is_new() {
        let (m, atom) = manager();
        let t = thread(m, 1, 0x100);
        let h = popup(m, atom, t);
        deliver(m, t);
        post(&mut m.windows, t, h, WM_USER + 30, 1, 0, 0).unwrap();
        assert_eq!(wait_ready(&mut m.windows, t, 0), Waited::Ready);
        deliver(m, t);
        assert_eq!(
            wait_ready(&mut m.windows, t, 0),
            Waited::Ready,
            "a read of the sent messages alone leaves the post new"
        );
        let peeked = take(&mut m.windows, t, &all(), false, 0).unwrap();
        assert_eq!(msg_of(peeked).message, WM_USER + 30);
        assert_eq!(wait_ready(&mut m.windows, t, 0), Waited::Wait { due: None });

        // A 300 ms timer: the wait lasts until its due, then finds it new.
        let ms = 10_000;
        crate::win32k::timer::set(&mut m.windows, t, h, 1, 300, 0, 0).unwrap();
        assert_eq!(
            wait_ready(&mut m.windows, t, 100 * ms),
            Waited::Wait {
                due: Some(300 * ms)
            }
        );
        assert_eq!(wait_ready(&mut m.windows, t, 300 * ms), Waited::Ready);
        take(&mut m.windows, t, &all(), true, 300 * ms).unwrap();
        take(&mut m.windows, t, &all(), true, 300 * ms).unwrap();
        assert!(matches!(
            wait_ready(&mut m.windows, t, 400 * ms),
            Waited::Wait { .. }
        ));

        // Another thread's post.
        post(&mut m.windows, t, h, WM_USER + 30, 9, 0, 0).unwrap();
        assert_eq!(wait_ready(&mut m.windows, t, 450 * ms), Waited::Ready);
    }

    /// guimsg `msgwait`: a post wakes a wait for QS_ALLPOSTMESSAGE until a read of every message
    /// looks; a message a peek saw is no longer new, but MWMO_INPUTAVAILABLE finds it, of the
    /// mask's kinds only.
    #[test]
    fn a_wait_finds_what_the_queue_holds_when_asked() {
        let (m, atom) = manager();
        let t = thread(m, 1, 0x100);
        let h = popup(m, atom, t);
        deliver(m, t);
        while !matches!(read(m, t, &all(), 0), Taken::Nothing { .. }) {}
        post(&mut m.windows, t, h, WM_USER, 0, 0, 0).unwrap();
        assert_eq!(
            wait_ready_for(&mut m.windows, t, 0, QS_ALLPOSTMESSAGE),
            Waited::Ready
        );
        let user = Filter::new(0, WM_USER + 1, WM_USER + 1, 0);
        take(&mut m.windows, t, &user, false, 0).unwrap();
        assert_eq!(
            wait_ready_for(&mut m.windows, t, 0, QS_ALLPOSTMESSAGE),
            Waited::Ready,
            "a range leaves it"
        );
        take(&mut m.windows, t, &all(), false, 0).unwrap();
        assert!(matches!(
            wait_ready_for(&mut m.windows, t, 0, QS_ALLINPUT),
            Waited::Wait { .. }
        ));
        assert_eq!(
            wait_ready_with(&mut m.windows, t, 0, QS_ALLINPUT, true),
            Waited::Ready
        );
        assert!(matches!(
            wait_ready_with(&mut m.windows, t, 0, QS_TIMER | QS_KEY, true),
            Waited::Wait { .. }
        ));
    }

    /// GetMessageTime and GetMessagePos answer the last message a read retrieved, a peek that
    /// leaves it included; a sent message leaves them (the msgpos capture).
    #[test]
    fn the_message_time_is_the_last_retrieved() {
        let (m, atom) = manager();
        let a = thread(m, 1, 0x100);
        let b = thread(m, 2, 0x200);
        let ha = popup(m, atom, a);
        deliver(m, a);
        assert_eq!(message_time(&m.windows, a), 0);
        post(&mut m.windows, a, ha, WM_USER, 1, 0, 100).unwrap();
        post(&mut m.windows, a, ha, WM_USER, 2, 0, 200).unwrap();
        take(&mut m.windows, a, &all(), false, 0).unwrap();
        assert_eq!(message_time(&m.windows, a), 100);
        take(&mut m.windows, a, &all(), true, 0).unwrap();
        take(&mut m.windows, a, &all(), true, 0).unwrap();
        assert_eq!(message_time(&m.windows, a), 200);
        assert_eq!(message_pos(&m.windows, a), 0);
        send(&mut m.windows, b, ha, WM_USER, 3, 0).unwrap();
        assert!(matches!(read(m, a, &all(), 900), Taken::Sent(_)));
        assert_eq!(message_time(&m.windows, a), 200, "a sent message leaves it");
        assert_eq!(message_time(&m.windows, b), 0);
    }

    /// A thread is hung once it has gone 5 s without reading its queue after a read that found
    /// something; one whose last read found its queue empty idles, however long it sleeps (the
    /// hung capture); a thread's own window, and a window manager's, never are.
    #[test]
    fn a_thread_is_hung_when_busy_past_the_timeout() {
        let (m, atom) = manager();
        let a = thread(m, 1, 0x100);
        let b = thread(m, 2, 0x200);
        let hb = popup(m, atom, b);
        deliver(m, b);
        let ms = 10_000;
        assert!(!hung(&m.windows, b, 60_000), "a thread that idled");
        post(&mut m.windows, a, hb, WM_USER, 0, 0, 0).unwrap();
        read(m, b, &all(), 1000 * ms);
        assert!(!hung(&m.windows, b, 6000));
        assert!(hung(&m.windows, b, 6001));
        assert_eq!(window_hung(&m.windows, a, hb, 6001), Ok(true));
        assert_eq!(window_hung(&m.windows, b, hb, 6001), Ok(false));
        assert_eq!(
            window_hung(&m.windows, a, 0x7FFF_FFFC, 6001),
            Err(STATUS_INVALID_HANDLE)
        );
        let desktop = m.windows.thread_desktop_window(a).unwrap();
        let desktop = m.windows.handle_of(desktop);
        assert_eq!(window_hung(&m.windows, a, desktop, 6001), Ok(false));
        read(m, b, &all(), 7000 * ms);
        assert!(!hung(&m.windows, b, 60_000), "its last read found nothing");
        assert_eq!(wait_ready(&mut m.windows, b, 0), Waited::Wait { due: None });
        assert!(!hung(&m.windows, b, 120_000), "it waits");
    }

    /// GetQueueStatus, as the msgwait capture's status section steps it: the kinds held in the
    /// high word, those new since the last look in the low word, which the call then clears for
    /// its flags; a peek clears what it looked for; a kind no longer held is not new; a timer
    /// counts once due.
    #[test]
    fn the_queue_status_has_what_is_held_and_what_is_new() {
        let (m, atom) = manager();
        let t = thread(m, 1, 0x100);
        let h = popup(m, atom, t);
        deliver(m, t);
        while !matches!(read(m, t, &all(), 0), Taken::Nothing { .. }) {}
        let status = |m: &mut WindowManager, flags| queue_status(&mut m.windows, t, 0, flags);
        assert_eq!(status(m, QS_ALLINPUT), 0);
        post(&mut m.windows, t, h, WM_USER, 1, 0, 0).unwrap();
        assert_eq!(status(m, QS_ALLINPUT), 0x0008_0008);
        assert_eq!(status(m, QS_ALLINPUT), 0x0008_0000, "no longer new");
        post(&mut m.windows, t, h, WM_USER, 2, 0, 0).unwrap();
        take(&mut m.windows, t, &all(), false, 0).unwrap();
        assert_eq!(status(m, QS_ALLINPUT), 0x0008_0000, "a peek saw it");
        while !matches!(read(m, t, &all(), 0), Taken::Nothing { .. }) {}
        assert_eq!(status(m, QS_ALLINPUT), 0);
        post(&mut m.windows, t, h, WM_USER, 3, 0, 0).unwrap();
        assert_eq!(status(m, QS_TIMER | QS_PAINT), 0);
        assert_eq!(
            status(m, QS_POSTMESSAGE),
            0x0008_0008,
            "other flags left it new"
        );
        assert_eq!(status(m, 0), 0);
        while !matches!(read(m, t, &all(), 0), Taken::Nothing { .. }) {}
        post(&mut m.windows, t, h, WM_USER, 4, 0, 0).unwrap();
        while !matches!(read(m, t, &all(), 0), Taken::Nothing { .. }) {}
        assert_eq!(status(m, QS_ALLINPUT), 0, "taken out: neither held nor new");

        let ms = 10_000;
        crate::win32k::timer::set(&mut m.windows, t, h, 9, 50, 0, 0).unwrap();
        assert_eq!(queue_status(&mut m.windows, t, 10 * ms, QS_ALLINPUT), 0);
        assert_eq!(
            queue_status(&mut m.windows, t, 150 * ms, QS_ALLINPUT),
            0x0010_0010
        );
        crate::win32k::timer::kill(&mut m.windows, t, h, 9).unwrap();
        assert_eq!(queue_status(&mut m.windows, t, 160 * ms, QS_ALLINPUT), 0);

        post_quit(&mut m.windows, t, 3);
        assert_eq!(status(m, QS_ALLINPUT), 0x0008_0008);
        assert_eq!(status(m, QS_POSTMESSAGE), 0x0008_0000);
    }

    /// ShowCursor: each queue's own display count, from -1 (no mouse), the new count answered.
    #[test]
    fn each_queue_counts_its_cursor_shows() {
        let (m, _) = manager();
        let a = thread(m, 1, 0x100);
        let b = thread(m, 2, 0x200);
        assert_eq!(show_cursor(&mut m.windows, a, true), 0);
        assert_eq!(show_cursor(&mut m.windows, a, true), 1);
        assert_eq!(
            show_cursor(&mut m.windows, b, true),
            0,
            "b counts on its own"
        );
        assert_eq!(show_cursor(&mut m.windows, a, false), 0);
        assert_eq!(show_cursor(&mut m.windows, a, false), -1);
        assert_eq!(show_cursor(&mut m.windows, a, false), -2);
        assert_eq!(show_cursor(&mut m.windows, b, false), -1);
    }
}
