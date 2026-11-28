//! The services' session ([`QueueSession`]): callbacks, the waits for other threads' answers,
//! and the signals set once the lock is let go.

#[cfg(target_arch = "x86")]
use core::mem::size_of;

#[cfg(target_arch = "x86")]
use rtl::callback::{FN_INSTRINGNULL, FN_OUTSTRING, OUT_MAX};
#[cfg(target_arch = "x86")]
use rtl::pod::Pod;

use super::*;
use crate::sched::thread::ThreadId;
#[cfg(target_arch = "x86")]
use crate::status::*;
use crate::win32k::class;
use crate::win32k::window::{
    self,
    Hold,
    LResult,
    Locked,
    Message,
    Payload,
    Session,
    WParam,
    WindowId,
    WindowManager,
    Windows,
};

/// Drop the messages the window manager queued for `thread` (sent by no thread, no answer
/// awaited: [`defer`]) that wait at the head of its sent list while `drop` says so (the window,
/// the message, its wParam); the first it keeps ends the run.
pub fn drop_deferred_run(
    windows: &mut Windows,
    thread: ThreadId,
    drop: impl Fn(Option<WindowId>, u32, WParam) -> bool,
) {
    let queues = &mut windows.queues;
    let Some(queue) = queues.queue_of(thread) else {
        return;
    };
    while let Some(head) = queues.queues[queue.index as usize].sent.head {
        let sent = queues.sent.at(head);
        let deferred = sent.sender.is_none() && !sent.server && !sent.notify;
        if !deferred || !drop(sent.window, sent.message, sent.wparam) {
            return;
        }
        let _ = queues.pop_sent(queue);
        queues.free_sent(head);
    }
}

/// The window `window` is being freed: the messages posted to it go, its timers, its update
/// region and its caret with them.
pub fn window_gone(windows: &mut Windows, window: WindowId) {
    crate::win32k::caret::window_gone(windows, window);
    let hwnd = windows.handle_of(window);
    let queues = &mut windows.queues;
    for index in 0..queues.queues.len() as u16 {
        if queues.queues[index as usize].live {
            queues.purge_posted(index, |msg| msg.hwnd == hwnd);
        }
    }
    queues.timers.window_gone(window);
    queues.updates.window_gone(window);
}

/// The session the services run the window manager's decisions in. A message to a window of the
/// deciding thread's own with a client-side procedure is a callback, the lock let go meanwhile
/// ([`Hold::unlocked`]), as Windows 2000's `xxx` routines call back (rtl::callback's notes). A
/// message to another thread's window is queued for it, the decision waiting for the answer and
/// the structure with the lock let go, delivering the messages sent to its own thread meanwhile
/// ([`send_and_wait`]), as `xxxInterSendMsgEx` waits; another thread's activation is queued and
/// not waited for ([`Session::queue_for`]). A thread with no queue queues its messages too
/// ([`defer`]). Those, and a window whose procedure is the window manager's, are answered as the
/// default procedure answers. A window's end takes its posted messages, timers and update region;
/// the activation and the destroy's focus check are [`crate::win32k::focus`]'s; the other calls are
/// [`Session`]'s defaults. The services hold it by the lock ([`with_session`]); the host tests by
/// the registries, which cannot be let go of, so their sends are all queued.
pub struct QueueSession<H: Hold> {
    pub hold: H,
    /// The thread whose windows' messages are queued for it, not waited for
    /// ([`Session::queue_for`]).
    queued_for: Option<ThreadId>,
}

impl<H: Hold> QueueSession<H> {
    /// A session over `hold`.
    pub fn over(hold: H) -> Self {
        QueueSession {
            hold,
            queued_for: None,
        }
    }
}

#[cfg(test)]
impl<'a> QueueSession<window::Split<'a>> {
    /// A session over the two registries.
    pub fn new(windows: &'a mut Windows, classes: &'a mut class::Registry) -> Self {
        QueueSession::over((windows, classes))
    }
}

impl QueueSession<Locked<'_>> {
    /// The whole window manager, borrowed until the next send: the state beside the registries
    /// (the clipboard, the accelerator tables, the properties).
    pub fn manager(&mut self) -> &mut WindowManager {
        &mut self.hold
    }
}

impl<H: Hold> Session for QueueSession<H> {
    fn parts(&mut self) -> (&mut Windows, &mut class::Registry) {
        self.hold.parts()
    }

    fn send(&mut self, target: WindowId, message: &mut Message) -> LResult {
        let windows = self.windows();
        let Some(proc) = windows.client_proc(target) else {
            return window::default_send(self, target, message);
        };
        if let Some(answer) = call_back(&mut self.hold, target, proc, message) {
            return answer;
        }
        let thread = self.windows().window_thread(target);
        let queued = self.queued_for == Some(thread);
        if !queued {
            if let Some(answer) = send_and_wait(&mut self.hold, target, proc, message) {
                return answer;
            }
        }
        defer(self.windows(), target, message);
        window::default_send(self, target, message)
    }

    fn queue_for(&mut self, thread: Option<ThreadId>) -> Option<ThreadId> {
        core::mem::replace(&mut self.queued_for, thread)
    }

    fn activate(&mut self, target: WindowId, command: window::Activate) -> bool {
        crate::win32k::focus::activate(self, target, command)
    }

    fn check_focus(&mut self, target: WindowId) {
        crate::win32k::focus::check_focus(self, target);
    }

    fn window_teardown(&mut self, target: WindowId) {
        window_gone(self.windows(), target);
    }

    fn disown_clipboard(&mut self, target: WindowId) {
        crate::win32k::clipboard::disown(self, target);
    }
}

/// The running thread's client id; none for a thread that is not a program's (the boot, a system
/// thread).
#[cfg(target_arch = "x86")]
fn running_client_id() -> Option<u32> {
    crate::sched::try_current_thread()?;
    Some(crate::level::raised::<crate::level::Dispatch, _>(
        |dispatch| {
            crate::sched::DISPATCHER
                .get(dispatch)
                .thread(crate::sched::current_thread())
                .thread_id()
        },
    ))
}

/// Call back to user mode through the slot `api` with the input block `parts` (KeUserModeCallback,
/// the lock let go): the routine's LRESULT and, for an in-out slot, the structure after it, no
/// more than `wanted` bytes and only when the routine handed back that much (the length is the
/// routine's word, the copy probed and fault-tolerant). 0 and no structure when the callback
/// failed (the kernel stack has no room for it, the user stack cannot take its block, the routine
/// took an exception or answered no LRESULT).
#[cfg(target_arch = "x86")]
fn call_user(
    passive: &mut crate::level::At<crate::level::Passive>,
    api: u32,
    parts: &[&[u8]],
    wanted: usize,
) -> (LResult, CallbackOut) {
    let mut out = CallbackOut {
        bytes: [0; OUT_MAX],
        length: 0,
    };
    let reply = crate::user::callback::call_user_mode(passive, api, parts);
    if reply.status != STATUS_SUCCESS || (reply.length as usize) < size_of::<LResult>() {
        return (0, out);
    }
    let output = crate::user::args::UserAddr(reply.output);
    let Ok(answer) = output.cast::<LResult>().read() else {
        return (0, out);
    };
    let handed = (reply.length as usize - size_of::<LResult>()).min(wanted);
    if handed == wanted
        && output
            .offset(size_of::<LResult>() as u32)
            .read(&mut out.bytes[..handed])
            .is_ok()
    {
        out.length = handed;
    }
    (answer, out)
}

/// The callback `message` to `target` is, when `target` is a window of the running thread's and
/// `hold` can let the lock go: the procedure `proc`'s answer, or 0 when the callback failed
/// ([`call_user`]). The structure the message carries comes back as the procedure left it, for
/// the in-out slots ([`read_back`]: the user's output block copied while the lock is let go, no
/// more than the structure's size). None when the message is not one to call back.
#[cfg(target_arch = "x86")]
fn call_back<H: Hold>(
    hold: &mut H,
    target: WindowId,
    proc: u32,
    message: &mut Message,
) -> Option<LResult> {
    use crate::win32k::text::Staged;
    // The running thread, by its client id: a window's thread record is the window registry's,
    // whose queue keeps the id.
    let running = running_client_id()?;
    let (windows, classes) = hold.parts();
    if client_id_of(windows, windows.window_thread(target)) != Some(running) {
        return None;
    }
    let input = callback_input(windows, classes, target, proc, message);
    // A creation message's window name, copied out of the registry before the lock goes.
    let name = match message.payload {
        Payload::Create(ref params) => {
            let text = windows.create_text(target, params.name);
            match Staged::copy_of(windows.texts.units(text)) {
                Some(name) => Some(name),
                None => return Some(0),
            }
        }
        _ => None,
    };
    let units = name.as_ref().map_or(&[][..], |name| name.units());
    let terminator: &[u8] = if name.is_some() { &[0, 0] } else { &[] };
    let parts = [
        input.head.as_bytes(),
        &input.carried[..input.length],
        rtl::pod::slice_bytes(units),
        terminator,
    ];
    let wanted = rtl::callback::out_size(input.api, message.wparam);
    let (answer, out) = hold.unlocked(|passive| call_user(passive, input.api, &parts, wanted))?;
    read_back(input.api, message, &out);
    Some(answer)
}

/// A decision's send of `message` to `target`, another thread's window (procedure `proc`), when
/// the running thread has a queue and `hold` can let the lock go: queued with the window manager's
/// copy of its structure ([`send_for_decision`]), the decision waiting on its queue with the lock
/// let go until the receiver answers, as `xxxInterSendMsgEx` waits. The answer, and the structure
/// as the procedure left it. Messages sent to the waiting thread meanwhile are delivered as they
/// come ([`take_for_callback`]), so two decisions sending to each other do not deadlock. A receiver
/// that ends first answers 0, the structure as sent. The wait has no end: a receiver that never
/// reads holds the decision, as on Windows 2000, though the thread may still be terminated inside
/// it. None when the message is not one to wait for.
#[cfg(target_arch = "x86")]
fn send_and_wait<H: Hold>(
    hold: &mut H,
    target: WindowId,
    proc: u32,
    message: &mut Message,
) -> Option<LResult> {
    let running = running_client_id()?;
    let (windows, _) = hold.parts();
    let (caller, _) = queue_by_client_id(windows, running)?;
    let id = send_for_decision(windows, caller, target, proc, message)?;
    loop {
        let (windows, _) = hold.parts();
        match decision_reply(windows, caller, id) {
            Replied::Answer(answer, payload) => {
                message.payload = payload;
                return Some(answer);
            }
            Replied::Failed => return Some(0),
            Replied::Received(sent) => receive_by_callback(hold, caller, sent),
            Replied::Wait => {
                if hold.unlocked(|_| wait_on_queue(caller, None)).is_none() {
                    // Not reached: a hold that cannot let go has no running program's thread.
                    let (windows, _) = hold.parts();
                    abandon_send(windows, caller, id);
                    return Some(0);
                }
            }
        }
    }
}

/// Deliver the message `id` handed out to `caller` ([`take_for_callback`]) by a callback to its
/// procedure, the lock let go, and hand its answer and structure (or WM_GETTEXT's text) to its
/// sender ([`end_received`]), as Windows 2000's xxxReceiveMessage does. A callback that fails (the
/// kernel stack has no room, the routine took an exception), or a text the pool has no room to
/// stage, answers 0, the structure as it was sent.
#[cfg(target_arch = "x86")]
pub fn receive_by_callback<H: Hold>(hold: &mut H, caller: ThreadId, id: SentId) {
    use crate::win32k::text::Staged;
    let mut out = CallbackOut {
        bytes: [0; OUT_MAX],
        length: 0,
    };
    let mut answer = 0;
    let mut reply = None;
    let (windows, classes) = hold.parts();
    match delivery(windows, classes, id) {
        Some(Delivery::Structure(input, message)) => {
            let parts = [input.head.as_bytes(), &input.carried[..input.length]];
            let wanted = rtl::callback::out_size(input.api, message.wparam);
            if let Some((a, o)) =
                hold.unlocked(|passive| call_user(passive, input.api, &parts, wanted))
            {
                (answer, out) = (a, o);
            }
        }
        Some(Delivery::Text {
            api,
            head,
            text,
            room,
        }) => {
            if let Some(staged) = Staged::copy_of(carried_units(windows, text)) {
                let terminator: &[u8] = if api == FN_INSTRINGNULL { &[0, 0] } else { &[] };
                let parts = [
                    head.as_bytes(),
                    rtl::pod::slice_bytes(staged.units()),
                    terminator,
                ];
                // WM_GETTEXT's block: a word for the answer, then the buffer.
                let space = if api == FN_OUTSTRING { 4 + 2 * room } else { 0 };
                if let Some((a, units)) =
                    hold.unlocked(|passive| call_user_for_text(passive, api, &parts, space, room))
                {
                    (answer, reply) = (a, units);
                }
            }
        }
        None => {}
    }
    let (windows, _) = hold.parts();
    if let Some(units) = &reply {
        keep_text_reply(windows, id, units.units());
    }
    end_received(windows, caller, id, answer, &out);
}

/// Call back through the text slot `api` with the block `parts` and `space` bytes of room after
/// it (KeUserModeCallback, the lock let go): the routine's LRESULT, and for `__fnOUTSTRING` the
/// text it handed back after it, as many units as the LRESULT says (none below 0, no more than the
/// buffer's `room` nor than the output block holds). 0 and no text when the callback failed.
#[cfg(target_arch = "x86")]
fn call_user_for_text(
    passive: &mut crate::level::At<crate::level::Passive>,
    api: u32,
    parts: &[&[u8]],
    space: u32,
    room: u32,
) -> (LResult, Option<crate::win32k::text::Staged>) {
    use crate::win32k::text::Staged;
    let reply = crate::user::callback::call_user_mode_with_room(passive, api, parts, space);
    if reply.status != STATUS_SUCCESS || (reply.length as usize) < size_of::<LResult>() {
        return (0, None);
    }
    let output = crate::user::args::UserAddr(reply.output);
    let Ok(answer) = output.cast::<LResult>().read() else {
        return (0, None);
    };
    if api != FN_OUTSTRING {
        return (answer, None);
    }
    let handed = (reply.length as usize - size_of::<LResult>()) / 2;
    let count = (answer.max(0) as usize).min(room as usize).min(handed);
    let text = Staged::read_counted(output.offset(size_of::<LResult>() as u32), count).ok();
    (answer, text)
}

/// The host has no user mode to call back: every send is queued.
#[cfg(not(target_arch = "x86"))]
fn call_back<H: Hold>(
    _hold: &mut H,
    _target: WindowId,
    _proc: u32,
    _message: &mut Message,
) -> Option<LResult> {
    None
}

/// The host's decisions do not wait: every send is queued.
#[cfg(not(target_arch = "x86"))]
fn send_and_wait<H: Hold>(
    _hold: &mut H,
    _target: WindowId,
    _proc: u32,
    _message: &mut Message,
) -> Option<LResult> {
    None
}

/// What a session's work left for after the lock: the input state published, the queues it gave
/// something to and whether the server's send was answered, whose events are set once the lock is
/// let go ([`Signals::raise`]).
pub struct Signals {
    pub(super) wakes: Wakes,
    /// How many queues are made: every one's event is set when the wakes overflowed.
    #[cfg_attr(not(target_arch = "x86"), allow(dead_code))]
    pub(super) made: usize,
    pub(super) server: bool,
}

impl Signals {
    /// Publish `manager`'s input state and take its pending wakes: before the lock is let go, at a
    /// session's end or around a callback.
    pub fn take(manager: &mut WindowManager) -> Signals {
        crate::win32k::input::publish(&manager.windows);
        let queues = &mut manager.windows.queues;
        Signals {
            wakes: queues.take_wakes(),
            made: queues.queues.len(),
            server: queues.take_server_wake(),
        }
    }
}

/// The increment a queue's event is set with: Windows 2000's SetWakeBit sets a GUI thread's wake
/// event with 2 where other events take EVENT_INCREMENT's 1. A thread woken for window-manager
/// input (a post, a send, a reply to its send, keyboard or mouse input) runs 2 above its base,
/// plus the foreground boost when its process is in the foreground
/// (`crate::process::foreground`). The server's event takes it too.
pub const GUI_WAKE_INCREMENT: i8 = 2;

#[cfg(test)]
mod tests {
    use rtl::user::{
        WM_DESTROY,
        WM_MOVE,
        WM_NCCALCSIZE,
        WM_NCDESTROY,
        WM_SIZE,
        WM_USER,
        WM_WINDOWPOSCHANGED,
        WM_WINDOWPOSCHANGING,
        WS_CHILD,
    };
    use rtl::window::{SWP_NOACTIVATE, SWP_NOCLIENTSIZE, SWP_NOSIZE, SWP_NOZORDER};

    use super::*;
    use crate::win32k::queue::testkit::*;
    use crate::win32k::window::{Hwnd, WindowManager};

    /// A window's creation, in the host's session (which cannot call back): WM_NCCALCSIZE,
    /// WM_SIZE and WM_MOVE queued for its thread as sent messages, in that order, WM_NCCREATE and
    /// WM_CREATE answered as the default procedure answers them (a creation's messages go to the
    /// creating thread's own window, by callback alone); the window exists at once.
    #[test]
    fn a_creation_sends_its_messages_through_the_queue() {
        let (m, atom) = manager();
        let t = thread(m, 1, 0x100);
        let h = popup(m, atom, t);
        assert!(m.windows.window_from_handle(h).is_some());
        assert_eq!(
            deliver(m, t),
            vec![(h, WM_NCCALCSIZE), (h, WM_SIZE), (h, WM_MOVE)]
        );
        assert_eq!(deliver(m, t), vec![], "each one once");
    }

    /// The destruction's WM_DESTROY and WM_NCDESTROY reach the procedure after the window is gone
    /// (the defproc capture's last recorded message is WM_NCDESTROY, IsWindow false after); what
    /// was posted to the window goes with it.
    #[test]
    fn a_destruction_delivers_after_the_window_is_gone() {
        let (m, atom) = manager();
        let t = thread(m, 1, 0x100);
        let h = popup(m, atom, t);
        deliver(m, t);
        post(&mut m.windows, t, h, WM_USER + 1, 0, 0, 0).unwrap();
        post(&mut m.windows, t, 0, WM_USER + 2, 0, 0, 0).unwrap();
        let WindowManager {
            windows, classes, ..
        } = &mut *m;
        Windows::destroy_window_handle(&mut QueueSession::new(windows, classes), t, h).unwrap();
        assert!(m.windows.window_from_handle(h).is_none());
        assert_eq!(deliver(m, t), vec![(h, WM_DESTROY), (h, WM_NCDESTROY)]);
        let msg = msg_of(read(m, t, &all(), 0));
        assert_eq!(
            (msg.hwnd, msg.message),
            (0, WM_USER + 2),
            "the window's own went"
        );
    }

    /// WM_WINDOWPOSCHANGING and WM_WINDOWPOSCHANGED carry their WINDOWPOS into the callback
    /// (guigeo `sizemsg` reads WM_WINDOWPOSCHANGED's flags): the move's place, and the flags
    /// reporting what did not change.
    #[test]
    fn a_window_pos_reaches_the_callback() {
        let (m, atom) = manager();
        let t = thread(m, 1, 0x100);
        let h = popup(m, atom, t);
        deliver(m, t);
        let WindowManager {
            windows, classes, ..
        } = &mut *m;
        let flags = SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE;
        Windows::set_window_pos_handle(
            &mut QueueSession::new(windows, classes),
            h,
            0,
            7,
            8,
            0,
            0,
            flags,
        )
        .unwrap();
        let only_sent = Filter::new(0, 0, 0, rtl::user::PM_QS_SENDMESSAGE);
        let mut changed = None;
        while let Taken::Sent(id) = read(m, t, &only_sent, 0) {
            let head = head_of(&m.windows, id).unwrap();
            let payload = payload_of(m, id);
            if head.msg.message == WM_WINDOWPOSCHANGED {
                let Payload::WindowPos(pos) = payload else {
                    panic!("a WINDOWPOS");
                };
                changed = Some(pos);
            } else if head.msg.message != WM_WINDOWPOSCHANGING {
                assert!(!matches!(payload, Payload::WindowPos(_)));
            }
            assert!(end_sent(&mut m.windows, t, 0));
        }
        let changed = changed.expect("WM_WINDOWPOSCHANGED");
        assert_eq!((changed.x, changed.y, changed.hwnd), (7, 8, h));
        assert_eq!(
            changed.flags,
            flags | SWP_NOCLIENTSIZE,
            "the client area moved, its size kept"
        );
    }

    /// The session's end's walk of a process's windows: its top-level windows only (not its
    /// children, nor another process's, nor the desktop's), each asked once in z-order, then each
    /// told once in the same order; the marks forgotten on demand.
    #[test]
    fn the_session_walks_a_process_s_top_level_windows() {
        let (m, atom) = manager();
        let a = thread(m, 1, 0x100);
        let b = thread_of(m, 2, 0x200, OTHER_OWNER);
        let first = popup(m, atom, a);
        let second = popup(m, atom, a);
        window_at(m, atom, a, WS_CHILD, first, 0, 0, 10, 10);
        let other_atom = register(m, OTHER_OWNER);
        let other = popup(m, other_atom, b);
        deliver(m, a);
        deliver(m, b);
        let desktop = m.windows.thread_desktop_window(a).unwrap();
        let z_order: Vec<Hwnd> = core::iter::successors(m.windows.first_child(desktop), |&w| {
            m.windows.next_sibling(w)
        })
        .map(|w| m.windows.handle_of(w))
        .filter(|&h| h == first || h == second)
        .collect();
        assert_eq!(z_order.len(), 2);
        assert!(m.windows.has_session_windows(OWNER));
        assert!(m.windows.has_session_windows(OTHER_OWNER));
        assert!(!m.windows.has_session_windows(5));
        let asked: Vec<Hwnd> =
            core::iter::from_fn(|| m.windows.session_next_to_ask(OWNER)).collect();
        assert_eq!(asked, z_order);
        assert_eq!(m.windows.session_next_to_ask(OTHER_OWNER), Some(other));
        let told: Vec<Hwnd> = core::iter::from_fn(|| m.windows.session_next_asked(OWNER)).collect();
        assert_eq!(told, z_order);
        assert_eq!(m.windows.session_next_asked(OWNER), None);
        m.windows.session_forget(OTHER_OWNER);
        assert_eq!(m.windows.session_next_asked(OTHER_OWNER), None);
        assert_eq!(m.windows.session_next_to_ask(OTHER_OWNER), Some(other));
    }
}
