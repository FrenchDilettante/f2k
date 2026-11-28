//! Message queues: each thread's queue of posted messages, of the messages sent to its windows,
//! and its WM_QUIT; the reads that take them in Windows 2000's documented order; and the session
//! the window manager's decisions send their messages through ([`QueueSession`]).
//!
//! A queue is a record of the window manager's ([`Queues`], in the window registry, behind its
//! one lock), one per thread record ([`window::Thread`]), made when a thread connects (its first
//! win32k service makes it a GUI thread, as on Windows 2000) and named by a generation-tagged id
//! ([`QueueId`]), the object manager's pattern. Posted messages are entries of one pool the queues
//! share, which grows a page at a time as they need it ([`super::posted`]), linked oldest first, in
//! two lanes: the messages posted to the thread, at most [`POSTED_LIMIT`] of them (Windows 2000's
//! USERPostMessageLimit), and the input messages the keyboard's keystrokes became
//! ([`super::input`], [`post_input`]), which the limit does not count. A read ([`take`])
//! answers, in the documented order: the messages sent to the thread's windows; the posted
//! messages its filter takes; the input messages it takes, each bound to its window as it is read
//! ([`super::input::bind`]: the focus window then, not when the key was pressed), a key message
//! read updating the thread's key state; the WM_QUIT PostQuitMessage left; a WM_PAINT for a window
//! of the thread's with an update region ([`super::paint`]); a WM_TIMER for one of its timers that
//! came due ([`super::timer`]). WM_QUIT, WM_PAINT and WM_TIMER
//! are never posted: they are made when a read finds nothing posted before them, as Windows 2000
//! makes them. A read that finds nothing for its filter blocks GetMessage's caller on its queue's
//! event, set by whatever gives the queue something: a post, a send, an answer, a timer set, an
//! invalidation. The wait is the scheduler's, outside the lock; its timeout is the thread's next
//! timer's due.
//!
//! A message the window manager's decisions send to a window of the deciding thread's own, with a
//! client-side procedure — the creation's WM_NCCREATE to WM_MOVE, the destruction's WM_DESTROY and
//! WM_NCDESTROY, what showing, moving and activating send — is a callback into user mode
//! (KeUserModeCallback, [`crate::user::callback`]): the decision lets the window manager's lock go,
//! user32 calls the procedure, and its answer comes back to the decision ([`QueueSession`]), as
//! Windows 2000's `xxx` routines call back. So a zero answer to WM_NCCREATE cancels the creation,
//! -1 to WM_CREATE fails it, and whatever the procedure does meanwhile (SetFocus from WM_ACTIVATE,
//! another window made from WM_CREATE) happens inside the decision, in Windows' order. What the
//! structure the procedure was handed comes back through the callback's output block, bounded by
//! the structure's size ([`read_back`]): WM_NCCALCSIZE's client rectangle, WM_WINDOWPOSCHANGING's
//! new place, WM_STYLECHANGING's new style, WM_GETMINMAXINFO's sizes. A message to another
//! thread's window is queued for that thread as a sent message with the window manager's copy of
//! the structure, and the decision waits for the answer with the lock let go
//! ([`send_for_decision`], [`decision_reply`]), as Windows 2000's `xxxInterSendMsgEx` waits; a
//! receiving thread that ends first fails the send (answered 0, the structure as sent). The
//! activation of another thread's windows is not waited for: Windows 2000 hands it to that thread
//! as an event, F2K queues its messages for that thread ([`defer`], [`Session::queue_for`]), as it
//! does a decision of a thread with no queue (the console server's), the decision going on with
//! the default procedure's answer.
//!
//! The messages sent to a thread reach their procedures the same way, by callback from inside the
//! thread's own calls, oldest first, before anything posted, as Windows 2000's xxxReceiveMessage
//! delivers them: GetMessage and PeekMessage deliver them all before they read on, WaitMessage
//! those that woke it, and a thread waiting for another's answer — its SendMessage, or a decision's
//! send — those that come meanwhile ([`take_for_callback`], [`delivery`], [`end_received`]), so
//! two threads that send to each other do not wait on each other. The callback carries the window
//! manager's copy of the structure, its in-out part coming back to the sender; a text another
//! process's message carries goes in the callback's block, WM_GETTEXT's answer coming back in its
//! output block ([`rtl::callback`]'s text slots).
//!
//! SendMessage to another thread's window is queued the same way, its sender waiting for the answer
//! ([`send`], [`await_reply`]); to a window of its own thread, the service names the procedure and
//! user32 calls it itself, as Windows 2000's user32 does. So do the console server's
//! WM_QUERYENDSESSION and WM_ENDSESSION at the session's end ([`server_send`]), the server, which
//! has no queue, waiting on an event of its own ([`wait_for_server`]). SendMessageTimeout's
//! sender waits no longer than its timeout, a message its receiver has not read by then taken back
//! ([`abandon_send`]); SendNotifyMessage's waits for nothing, its message answered to nobody
//! ([`send_notify`]). Sent messages are records of a slot pool ([`crate::slots`]) that grows a
//! page at a time and keeps its peak, each named by an id its slot's count checks ([`SentId`]).
//!
//! A queue keeps what Windows 2000 keeps of its thread's reads: the kinds of message given it
//! since a read last looked for them (the change bits WaitMessage wakes on, [`wait_ready`]: a
//! message a peek saw and left is no longer new), the time and cursor position of the last message
//! retrieved (GetMessageTime, GetMessagePos), and when the thread last read and whether that read
//! found nothing — a thread that has not read for [`HUNG_TIMEOUT`] after a read that found
//! something is hung ([`hung`]: IsHungAppWindow, SendMessageTimeout's SMTO_ABORTIFHUNG).
//!
//! The services, user32's calls (F2K's argument lists, see [`crate::win32k`]):
//!
//! - NtUserPostMessage(handle Window, u32 Msg, u32 wParam, i32 lParam): a window's message posted
//!   to the window's thread; a null window posts to the calling thread, HWND_BROADCAST to every
//!   top-level window of the caller's desktop;
//! - NtUserPostThreadMessage(u32 ThreadId, u32 Msg, u32 wParam, i32 lParam): a thread message;
//! - NtUserGetMessage(ptr Receipt, handle Window, u32 MsgFilterMin, u32 MsgFilterMax): the next
//!   message the filter takes, waiting for one, into the receipt, the sent messages delivered
//!   first;
//! - NtUserPeekMessage(ptr Receipt, handle Window, u32 MsgFilterMin, u32 MsgFilterMax, u32
//!   RemoveMsg): the same without waiting (RECEIVED_NONE when there is nothing);
//! - NtUserMessageCall(handle Window, u32 Msg, u32 wParam, i32 lParam, ptr<u32> Proc, ptr<i32>
//!   Result, ptr Timeout): SendMessage and SendMessageTimeout (rtl::user::SendTimeout; null for
//!   SendMessage): the procedure to call for a window of the caller's own thread, or the answer,
//!   STATUS_TIMEOUT for none in time;
//! - NtUserSendNotifyMessage(handle Window, u32 Msg, u32 wParam, i32 lParam, ptr<u32> Proc):
//!   SendNotifyMessage: the procedure to call for a window of the caller's own thread, or 0;
//! - NtUserWaitMessage(): WaitMessage, the sent messages that woke it delivered;
//! - NtUserDispatchMessage(ptr Msg, ptr<u32> Proc): the procedure DispatchMessage calls;
//! - NtUserCallOneParam(u32 Param, u32 Routine, ptr<u32> Result): PostQuitMessage, ReplyMessage,
//!   InSendMessage, IsHungAppWindow ([`rtl::user`]'s ONE_PARAM_* routines).

use core::mem::size_of;

use rtl::callback::{
    CallbackMsg,
    FN_COPYDATA,
    FN_DWORD,
    FN_INLPCREATESTRUCT,
    FN_INLPWINDOWPOS,
    FN_INOUTLPPOINT5,
    FN_INOUTLPWINDOWPOS,
    FN_INOUTNCCALCSIZE,
    FN_INOUTSTYLECHANGE,
    FN_INSTRINGNULL,
    FN_NCDESTROY,
    FN_OUTSTRING,
    OUT_MAX,
    OUT_STRING_MAX,
};
use rtl::pod::Pod;
use rtl::user::{
    sync_only,
    CreateStructW,
    Msg,
    Point,
    StyleStruct,
    HWND_BROADCAST,
    QS_ALLINPUT,
    QS_ALLPOSTMESSAGE,
    QS_HOTKEY,
    QS_INPUT,
    QS_KEY,
    QS_MOUSE,
    QS_MOUSEBUTTON,
    QS_MOUSEMOVE,
    QS_PAINT,
    QS_POSTMESSAGE,
    QS_SENDMESSAGE,
    QS_TIMER,
    RECEIVED_MESSAGE,
    RECEIVED_QUIT,
    WM_COPYDATA,
    WM_GETTEXT,
    WM_KEYFIRST,
    WM_KEYLAST,
    WM_MOUSEFIRST,
    WM_MOUSELAST,
    WM_NCACTIVATE,
    WM_NCCREATE,
    WM_NCDESTROY,
    WM_PAINT,
    WM_QUERYENDSESSION,
    WM_QUIT,
    WM_SETTEXT,
    WM_SYSTIMER,
    WM_TIMER,
    WM_WINDOWPOSCHANGING,
};

use super::class;
use super::text::{Text, Texts};
use super::window::{
    self,
    ClassArg,
    Hold,
    Hwnd,
    LParam,
    LResult,
    Locked,
    Message,
    Payload,
    Session,
    ThreadKey,
    WParam,
    WindowId,
    WindowManager,
    WindowPos,
    Windows,
};
use crate::sched::thread::ThreadId;
use crate::slots::{self, Codec, Match, Record, Reuse, Slots};
use crate::status::*;

/// How many messages posted to a thread its queue holds at once: Windows 2000's
/// USERPostMessageLimit, 10,000 by default. A post past it fails (guimsg `quota`), the input
/// messages aside, which it does not count.
pub const POSTED_LIMIT: u32 = 10_000;
// ERROR_NOT_ENOUGH_QUOTA: the post past [`POSTED_LIMIT`]'s refusal, as win32k carries it.
use rtl::winerror::{ERROR_INVALID_THREAD_ID, ERROR_MESSAGE_SYNC_ONLY, ERROR_NOT_ENOUGH_QUOTA};
/// Where the sent messages' pool takes its pages: the nonpaged pool on target.
#[cfg(target_arch = "x86")]
static PAGES: slots::NonpagedPages = slots::NonpagedPages;
#[cfg(not(target_arch = "x86"))]
static PAGES: slots::HostPages = slots::HostPages::new();

/// How many queues a wake set names one by one before it names them all ([`Wakes`]).
const WAKE_LIST: usize = 32;

/// The queues given something since the wakes were last taken, whose events are set once the
/// window manager's lock is let go: each named once, the first [`WAKE_LIST`] of them; past that
/// (a broadcast's many), every queue's event is set, a spurious wake costing a waiter one more
/// look at its queue and nothing else.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Wakes {
    queues: [u16; WAKE_LIST],
    count: u8,
    every: bool,
}

impl Wakes {
    const NONE: Wakes = Wakes {
        queues: [0; WAKE_LIST],
        count: 0,
        every: false,
    };

    /// Add the queue of the thread record `index`.
    fn add(&mut self, index: u16) {
        if self.every || self.listed().contains(&index) {
            return;
        }
        match self.queues.get_mut(self.count as usize) {
            Some(slot) => {
                *slot = index;
                self.count += 1;
            }
            None => self.every = true,
        }
    }

    /// The queues named one by one.
    fn listed(&self) -> &[u16] {
        &self.queues[..self.count as usize]
    }

    /// Whether no queue is to be woken.
    pub fn is_empty(&self) -> bool {
        self.count == 0 && !self.every
    }

    /// Whether the queue of the thread record `thread` is to be woken.
    #[cfg(test)]
    pub fn contains(&self, thread: ThreadId) -> bool {
        self.every || self.listed().contains(&thread.0)
    }

    /// Whether the queue of the thread record `thread` is the only one to be woken.
    #[cfg(test)]
    pub fn is_only(&self, thread: ThreadId) -> bool {
        !self.every && self.listed() == [thread.0]
    }

    /// The queues to wake, by thread record index: those named, or every one of `queues` ones
    /// made when the set overflowed.
    #[cfg_attr(not(target_arch = "x86"), allow(dead_code))]
    fn each(&self, made: usize) -> impl Iterator<Item = u16> + '_ {
        let every = self.every.then_some(0..made as u16).into_iter().flatten();
        let listed = (!self.every).then(|| self.listed().iter().copied());
        every.chain(listed.into_iter().flatten())
    }
}

/// The host builds have no queue events: the host tests wait on nothing.
#[cfg(not(target_arch = "x86"))]
fn make_event(_: u16) -> bool {
    true
}

/// The queues to a chunk of their table: a page's worth.
const QUEUES_PER_CHUNK: usize = slots::entries_per_page::<Queue>();

/// Every kind of message a read takes when its caller names none.
const ALL_KINDS: u32 = QS_INPUT | QS_POSTMESSAGE | QS_TIMER | QS_PAINT | QS_SENDMESSAGE | QS_HOTKEY;

/// The default window procedure's answer: 1 to WM_NCCREATE (the creation goes on) and to
/// WM_QUERYENDSESSION (the session may end), 0 to the rest.
pub fn default_answer(message: u32) -> LResult {
    match message {
        WM_NCCREATE | WM_QUERYENDSESSION => 1,
        _ => 0,
    }
}

// --- The records ---------------------------------------------------------------------------------

/// A queue's id: its record (the index of the thread record it serves) and the record's
/// generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QueueId {
    index: u16,
    generation: u16,
}

/// A sent message's id: its slot in the sent messages' pool and the slot's uniqueness count
/// ([`SentToken`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SentId {
    index: u16,
    generation: u16,
}

/// How a [`SentId`] carries its slot: the slot pool's codec for the sent messages, whose index
/// ceiling is [`SentId::token`]'s 15 bits.
pub struct SentToken;

impl Codec for SentToken {
    type Id = SentId;

    const LANES: usize = 1;
    /// 32,768 sends on their way at once, F2K's representation limit (a send waits on its receiver,
    /// so a thread has one or two on their way, a few for the messages it delivers meanwhile).
    const MAX_INDEX: u32 = 0x7FFF;
    const MAX_UNIQ: u16 = 0xFFFE;
    const RESERVED_LOW: u32 = 0;
    const REUSE: Reuse = Reuse::Fifo;

    fn encode(index: u32, uniq: u16) -> SentId {
        SentId {
            index: index as u16,
            generation: uniq,
        }
    }

    fn decode(id: SentId) -> Option<(u32, Match)> {
        Some((id.index as u32, Match::Exact(id.generation)))
    }
}

/// The sent messages a chunk of their pool holds: a page's worth.
const SENT_PER: usize = slots::per_page::<Sent>();
// A 132-byte record (an NCCALCSIZE_PARAMS and its WINDOWPOS the longest structure it carries) in a
// 140-byte slot: 29 to a page on target.
#[cfg(target_arch = "x86")]
const _: () = assert!(SENT_PER == 29 && Slots::<Sent, SentToken, SENT_PER>::CHUNK_PAGES == 1);

/// The sent messages: a slot pool that grows a page at a time and keeps its peak (the slot-pool
/// plan's rule), linked into their receivers' lists by [`SentId`]. A link names a live record
/// (a record leaves every list before it is freed), so [`SentPool::at`] holds it to that.
struct SentPool(Slots<Sent, SentToken, SENT_PER>);

impl SentPool {
    const EMPTY: Self = SentPool(Slots::new());

    /// The live sent message `id` names; none for a stale or forged id.
    fn get(&self, id: SentId) -> Option<&Sent> {
        self.0.get(id)
    }

    /// The live sent message a list links to.
    fn at(&self, id: SentId) -> &Sent {
        self.0.get(id).expect("a linked sent message is live")
    }

    /// [`SentPool::at`], to change.
    fn at_mut(&mut self, id: SentId) -> &mut Sent {
        self.0.get_mut(id).expect("a linked sent message is live")
    }

    /// `record` in a fresh slot, the pool grown by a page when it needs one: its id; none when no
    /// page can be had, or 32,768 sends are on their way.
    fn allocate(&mut self, record: Sent) -> Option<SentId> {
        let (id, slot) = self.0.allocate_or_grow(0, &PAGES).ok()?;
        *slot = record;
        Some(id)
    }

    /// Free the live sent message `id`: its id names nothing after.
    fn free(&mut self, id: SentId) {
        let freed = self.0.free(id);
        debug_assert!(freed, "a live sent message freed");
    }

    /// The live sent messages' ids, in slot order, one at a time: none of the pool borrowed
    /// between them, so a record can be freed on the way.
    fn next_live(&self, from: u32) -> Option<(u32, SentId)> {
        (from..self.0.high_water()).find_map(|index| Some((index, self.0.id_at(index)?)))
    }

    /// How many sent messages are live.
    #[cfg(test)]
    fn live(&self) -> u32 {
        self.0.live()
    }
}

/// A singly linked list of sent messages, oldest first.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct List {
    head: Option<SentId>,
    tail: Option<SentId>,
}

impl List {
    const EMPTY: Self = List {
        head: None,
        tail: None,
    };
}

/// A queue's list of entries from the posted messages' pool, oldest first, and how many it holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PostedList {
    head: Option<u32>,
    tail: Option<u32>,
    count: u32,
}

impl PostedList {
    const EMPTY: Self = PostedList {
        head: None,
        tail: None,
        count: 0,
    };
}

/// A thread's queue.
#[derive(Clone, Copy)]
struct Queue {
    live: bool,
    generation: u16,
    /// The thread it serves.
    key: Option<ThreadKey>,
    /// The thread's client id, as PostThreadMessage names it.
    client_id: u32,
    /// The posted messages, oldest first.
    posted: PostedList,
    /// The input messages, oldest first.
    input: PostedList,
    /// The sent messages not handed out yet, oldest first.
    sent: List,
    /// The sent messages handed out and not answered yet, innermost first.
    receiving: Option<SentId>,
    /// PostQuitMessage's exit code, until a read takes the WM_QUIT.
    quit: Option<u32>,
    /// The kinds of message (queue-status bits) given the queue since a read last looked for them:
    /// Windows 2000's change bits, what WaitMessage wakes on.
    changed: u32,
    /// When the thread last read its queue (milliseconds, MSG's clock).
    last_read: u32,
    /// The thread's last read found nothing, or it waits: it idles, waiting for input, and is
    /// never deemed hung.
    idle: bool,
    /// The time and the cursor position of the last message a read retrieved (GetMessageTime,
    /// GetMessagePos).
    message_time: u32,
    message_pos: Point,
    /// The last button press a read took out, for the next one's double-click
    /// ([`super::mouse::Click`]).
    click: Option<super::mouse::Click>,
    /// ShowCursor's display count ([`show_cursor`]).
    cursor_level: i32,
}

// SAFETY: writes a whole record.
unsafe impl Record for Queue {
    unsafe fn write_fresh(at: *mut Self, _: u32) {
        // SAFETY: the caller's contract.
        unsafe { at.write(Queue::EMPTY) };
    }
}

impl Queue {
    const EMPTY: Self = Queue {
        live: false,
        generation: 0,
        key: None,
        client_id: 0,
        posted: PostedList::EMPTY,
        input: PostedList::EMPTY,
        sent: List::EMPTY,
        receiving: None,
        quit: None,
        changed: 0,
        last_read: 0,
        idle: true,
        message_time: 0,
        message_pos: Point { x: 0, y: 0 },
        click: None,
        cursor_level: CURSOR_LEVEL_START,
    };
}

/// A posted message: the MSG a read hands out, and the link to the next one.
#[derive(Clone, Copy)]
struct Posted {
    msg: Msg,
    /// An input message's key, as the key state names it (the side's key for Shift, Ctrl and Alt,
    /// where the message names the generic one; a mouse button's key for its message, 0 for a
    /// move); 0 for a message posted to the thread.
    key: u8,
    /// What a read learned of a mouse message's window ([`super::mouse::Prepared`]).
    prepared: Option<super::mouse::Prepared>,
    next: Option<u32>,
}

/// The two lanes of a queue's entries from the posted messages' pool.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Lane {
    /// The messages posted to the thread or its windows.
    Posted,
    /// The input messages the keyboard's keystrokes became.
    Input,
}

/// Where a sent message is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    /// On its receiver's list, not handed out yet.
    Queued,
    /// Handed out: on its receiver's receiving stack.
    Received,
    /// Answered by ReplyMessage while still on its receiver's receiving stack: its sender (or the
    /// server) may take the answer at once, but the record stays until the delivery ends
    /// ([`Queues::leave_stack`]), the receiver's stack linked through it.
    Replied,
    /// Answered: the sender collects the answer.
    Answered,
    /// Never answered: its window or its receiver's queue went first (for a thread's send, its
    /// receiver's queue alone: a window gone is answered 0). Only a send the server or a thread
    /// waits on stays in this state, for its sender to collect ([`server_reply`],
    /// [`await_reply`]).
    Dropped,
}

/// The structure a sent message's lParam points at, carried with it: the window manager's copy,
/// which the receiver's procedure is handed and, for an in-out one, which comes back to the
/// sender as the procedure left it ([`read_back`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Carried {
    None,
    /// WM_NCCALCSIZE's rectangle (wParam FALSE).
    Rect(rtl::gdi::Rect),
    /// WM_NCCALCSIZE's NCCALCSIZE_PARAMS and the move's WINDOWPOS (wParam TRUE).
    CalcSize(window::CalcSize),
    /// WM_WINDOWPOSCHANGING's and WM_WINDOWPOSCHANGED's WINDOWPOS.
    WindowPos(window::WindowPos),
    /// WM_STYLECHANGING's and WM_STYLECHANGED's STYLESTRUCT.
    Style(StyleStruct),
    /// WM_GETMINMAXINFO's MINMAXINFO.
    MinMax(window::MinMaxInfo),
    /// WM_SETTEXT's text, WM_COPYDATA's structure and data (rtl::user's COPY_DATA_HEAD form), or
    /// WM_GETTEXT's answer, sent to another process's window: a block of the queues' store
    /// ([`Queues::store`]), as long as it is.
    Text(Text),
    /// No structure: SendMessageCallback's message from another thread, which carries where its
    /// answer goes instead ([`Queues::answer`]).
    Callback(Callback),
}

impl Carried {
    /// What a decision's message carries to another thread: its payload's structure; none for a
    /// creation's, which only the creating thread's own window is sent.
    fn of(payload: &Payload) -> Option<Carried> {
        Some(match *payload {
            Payload::None => Carried::None,
            Payload::Rect(r) => Carried::Rect(r),
            Payload::CalcSize(calc) => Carried::CalcSize(calc),
            Payload::WindowPos(pos) => Carried::WindowPos(pos),
            Payload::Style(style) => Carried::Style(style),
            Payload::MinMax(mmi) => Carried::MinMax(mmi),
            Payload::Create(_) => return None,
        })
    }

    /// The payload a callback carries it as; none for a text, which no callback carries.
    fn payload(&self) -> Option<Payload> {
        Some(match *self {
            Carried::None => Payload::None,
            Carried::Rect(r) => Payload::Rect(r),
            Carried::CalcSize(calc) => Payload::CalcSize(calc),
            Carried::WindowPos(pos) => Payload::WindowPos(pos),
            Carried::Style(style) => Payload::Style(style),
            Carried::MinMax(mmi) => Payload::MinMax(mmi),
            Carried::Callback(_) => Payload::None,
            Carried::Text(_) => return None,
        })
    }
}

/// Where a SendMessageCallback's answer goes: the callback (0 for none: the answer goes to nobody)
/// and the data it is called with, in the sending thread's queue.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Callback {
    proc: u32,
    data: u32,
    sender: QueueId,
}

/// A sent message.
#[derive(Clone, Copy)]
struct Sent {
    receiver: Option<QueueId>,
    /// The thread waiting for the answer; none for a message the window manager or the server
    /// sent.
    sender: Option<QueueId>,
    /// The console server waits for the answer (the session's end, on its control thread, which
    /// has no queue: see [`server_send`]).
    server: bool,
    /// SendNotifyMessage's: another thread sent it and waits for no answer.
    notify: bool,
    /// The answer to a SendMessageCallback, on its way to the sender's callback: delivered as a
    /// sent message whose procedure is the callback, its wParam the caller's data and its lParam
    /// the answer, as Windows 2000's SMF_CB_REPLY reaches CallClientProc.
    reply: bool,
    window: Option<WindowId>,
    hwnd: Hwnd,
    proc: u32,
    message: u32,
    wparam: WParam,
    lparam: LParam,
    carried: Carried,
    state: State,
    result: LResult,
    /// The next one on the receiver's list or receiving stack.
    next: Option<SentId>,
}

impl Sent {
    const EMPTY: Self = Sent {
        receiver: None,
        sender: None,
        server: false,
        notify: false,
        reply: false,
        window: None,
        hwnd: 0,
        proc: 0,
        message: 0,
        wparam: 0,
        lparam: 0,
        carried: Carried::None,
        state: State::Queued,
        result: 0,
        next: None,
    };

    /// SendMessageCallback's message from another thread ([`Carried::Callback`]).
    fn is_callback(&self) -> bool {
        matches!(self.carried, Carried::Callback(_))
    }
}

// SAFETY: `write_fresh` writes a whole record.
unsafe impl Record for Sent {
    unsafe fn write_fresh(at: *mut Self, _index: u32) {
        // SAFETY: the caller's contract; a record a page holds dozens of passes through the stack.
        unsafe { at.write(Sent::EMPTY) };
    }
}

/// The queues, the pools their messages come from, the timers ([`super::timer`]) and the windows'
/// update regions ([`super::paint`]): the message layer's state, in the window registry, behind the
/// window manager's lock.
pub struct Queues {
    /// The thread records' queues, at the records' indices: made with the record
    /// ([`Queues::make`]) and kept at their peak.
    queues: slots::Records<Queue, QUEUES_PER_CHUNK>,
    posted: super::posted::Pool<Posted>,
    sent: SentPool,
    /// The texts the sent messages carry: a text to another process's window.
    store: Texts,
    pub timers: super::timer::Timers,
    pub updates: super::paint::Updates,
    /// The queues something was given since the last [`Queues::take_wakes`]: their events are set
    /// once the lock is let go.
    wakes: Wakes,
    /// A send the server waits on was answered or dropped since the last
    /// [`Queues::take_server_wake`]: the server's event is set once the lock is let go.
    server_wake: bool,
}

impl Queues {
    /// Write empty queues at `queues`, field by field (by value they would pass through the
    /// stack, which is smaller than them).
    ///
    /// # Safety
    ///
    /// `queues` is valid for writes, aligned, and the records' final address; its previous
    /// contents are overwritten, not dropped.
    pub unsafe fn write_empty(queues: *mut Queues) {
        use core::ptr::addr_of_mut;
        // SAFETY: the caller's contract; every field is written, the arrays element by element.
        unsafe {
            addr_of_mut!((*queues).queues).write(slots::Records::new());
            addr_of_mut!((*queues).posted).write(super::posted::Pool::EMPTY);
            addr_of_mut!((*queues).sent).write(SentPool::EMPTY);
            addr_of_mut!((*queues).store).write(Texts::EMPTY);
            super::timer::Timers::write_empty(addr_of_mut!((*queues).timers));
            super::paint::Updates::write_empty(addr_of_mut!((*queues).updates));
            addr_of_mut!((*queues).wakes).write(Wakes::NONE);
            addr_of_mut!((*queues).server_wake).write(false);
        }
    }

    /// Make the queue of the thread record `index` (and its event), with the record: false when
    /// no page is left for it. What is made stays, for the next record at the index.
    pub fn make(&mut self, index: u16) -> bool {
        self.queues.ensure(index.into(), super::pages()).is_ok() && make_event(index)
    }

    /// The live queues, by their thread records.
    fn live_queues(&self) -> impl Iterator<Item = (ThreadId, &Queue)> + '_ {
        self.queues
            .iter()
            .enumerate()
            .filter(|(_, queue)| queue.live)
            .map(|(index, queue)| (ThreadId(index as u16), queue))
    }

    /// The queue of the thread record `thread`, when it has one.
    pub fn queue_of(&self, thread: ThreadId) -> Option<QueueId> {
        let queue = self.queues.get(thread.0 as usize)?;
        queue.live.then_some(QueueId {
            index: thread.0,
            generation: queue.generation,
        })
    }

    /// Mark the queue of the thread record `thread` as given something, of the kinds `changed`
    /// (queue-status bits: 0 for a change no read finds, a timer set): its event is set once the
    /// lock is let go.
    pub fn wake_thread(&mut self, thread: ThreadId, changed: u32) {
        if let Some(id) = self.queue_of(thread) {
            self.change(id, changed);
        }
    }

    fn wake(&mut self, id: QueueId) {
        self.wakes.add(id.index);
    }

    /// The queue was given something of the kinds `changed`: marked for WaitMessage, and woken.
    fn change(&mut self, id: QueueId, changed: u32) {
        self.queues[id.index as usize].changed |= changed;
        self.wake(id);
    }

    /// The queues to wake, the set emptied.
    pub fn take_wakes(&mut self) -> Wakes {
        core::mem::replace(&mut self.wakes, Wakes::NONE)
    }

    /// Whether the server's event is to be set (a send it waits on was answered or dropped), the
    /// mark cleared.
    pub fn take_server_wake(&mut self) -> bool {
        core::mem::replace(&mut self.server_wake, false)
    }

    // --- The posted messages' pool ---------------------------------------------------------------

    /// The queue at `index`'s list of the lane `lane`.
    fn lane(&mut self, index: u16, lane: Lane) -> &mut PostedList {
        let queue = &mut self.queues[index as usize];
        match lane {
            Lane::Posted => &mut queue.posted,
            Lane::Input => &mut queue.input,
        }
    }

    /// Append `msg` to the queue's posted messages: ERROR_NOT_ENOUGH_QUOTA (carried as a
    /// FACILITY_NTWIN32 status) when it holds [`POSTED_LIMIT`] already,
    /// STATUS_INSUFFICIENT_RESOURCES when the pool cannot grow.
    fn push_posted(&mut self, id: QueueId, msg: Msg) -> Result<(), NtStatus> {
        if self.queues[id.index as usize].posted.count >= POSTED_LIMIT {
            return Err(NtStatus::from_win32(ERROR_NOT_ENOUGH_QUOTA));
        }
        self.push(id, Lane::Posted, msg, 0)
    }

    /// Append `msg` (an input message's key `key`) to the queue's lane `lane`:
    /// STATUS_INSUFFICIENT_RESOURCES when the pool cannot grow.
    fn push(&mut self, id: QueueId, lane: Lane, msg: Msg, key: u8) -> Result<(), NtStatus> {
        let entry = self
            .posted
            .allocate(Posted {
                msg,
                key,
                prepared: None,
                next: None,
            })
            .ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        match self.lane(id.index, lane).tail {
            Some(tail) => self.posted.get_mut(tail).next = Some(entry),
            None => self.lane(id.index, lane).head = Some(entry),
        }
        let list = self.lane(id.index, lane);
        list.tail = Some(entry);
        list.count += 1;
        let kind = match lane {
            Lane::Posted => QS_POSTMESSAGE | QS_ALLPOSTMESSAGE,
            Lane::Input => input_kind(msg.message),
        };
        self.change(id, kind);
        Ok(())
    }

    /// Take `entry` out of the queue's lane `lane` (`previous` is the entry before it, none for
    /// the head) and give it back to the pool.
    fn unlink_posted(&mut self, index: u16, lane: Lane, previous: Option<u32>, entry: u32) {
        let next = self.posted.get(entry).next;
        match previous {
            Some(p) => self.posted.get_mut(p).next = next,
            None => self.lane(index, lane).head = next,
        }
        let list = self.lane(index, lane);
        if list.tail == Some(entry) {
            list.tail = previous;
        }
        list.count -= 1;
        self.posted.free(entry);
    }

    /// Drop every posted and input message of the queue at `index` that `drop` picks.
    fn purge_posted(&mut self, index: u16, drop: impl Fn(&Msg) -> bool) {
        for lane in [Lane::Posted, Lane::Input] {
            let mut previous = None;
            let mut at = self.lane(index, lane).head;
            while let Some(entry) = at {
                let next = self.posted.get(entry).next;
                if drop(&self.posted.get(entry).msg) {
                    self.unlink_posted(index, lane, previous, entry);
                } else {
                    previous = Some(entry);
                }
                at = next;
            }
        }
    }

    // --- The sent messages' pool -----------------------------------------------------------------

    /// The live sent message `id` names.
    fn sent_at(&self, id: SentId) -> Option<&Sent> {
        self.sent.get(id)
    }

    /// A fresh sent message from the pool; none when it cannot grow.
    fn allocate_sent(&mut self, record: Sent) -> Option<SentId> {
        self.sent.allocate(record)
    }

    /// Give the sent message `id` back to the pool, the text it carries with it.
    fn free_sent(&mut self, id: SentId) {
        if let Carried::Text(text) = self.sent.at(id).carried {
            self.store.free(text);
        }
        self.sent.free(id);
    }

    /// Append the sent message `id` to its receiver's list, and wake the receiver.
    fn push_sent(&mut self, receiver: QueueId, id: SentId) {
        let queue = &mut self.queues[receiver.index as usize];
        match queue.sent.tail {
            Some(tail) => self.sent.at_mut(tail).next = Some(id),
            None => queue.sent.head = Some(id),
        }
        queue.sent.tail = Some(id);
        self.change(receiver, QS_SENDMESSAGE);
    }

    /// Answer the sent message `id` with `result`: its sender, if it still waits, or the server,
    /// collects the answer; one nobody waits on goes back to the pool.
    fn answer(&mut self, id: SentId, result: LResult) {
        let sent = self.sent.at_mut(id);
        sent.next = None;
        if let Carried::Callback(callback) = sent.carried {
            sent.carried = Carried::None;
            self.answer_to_callback(id, callback, result);
            return;
        }
        if sent.server {
            sent.state = State::Answered;
            sent.result = result;
            self.server_wake = true;
            return;
        }
        match sent.sender {
            Some(sender) if self.queues[sender.index as usize].generation == sender.generation => {
                sent.state = State::Answered;
                sent.result = result;
                self.wake(sender);
            }
            _ => self.free_sent(id),
        }
    }

    /// SendMessageCallback's message `id` answered `result`: the record becomes the answer's way
    /// back, queued for the sending thread as a sent message its next read delivers to the
    /// callback (QS_SENDMESSAGE), as Windows 2000 queues an SMF_CB_REPLY; with no callback, or the
    /// sender's queue gone, back to the pool.
    fn answer_to_callback(&mut self, id: SentId, callback: Callback, result: LResult) {
        let sender = callback.sender;
        if callback.proc == 0
            || self.queues[sender.index as usize].generation != sender.generation
            || !self.queues[sender.index as usize].live
        {
            self.free_sent(id);
            return;
        }
        let sent = self.sent.at_mut(id);
        *sent = Sent {
            receiver: Some(sender),
            reply: true,
            window: sent.window,
            hwnd: sent.hwnd,
            proc: callback.proc,
            message: sent.message,
            wparam: callback.data,
            lparam: result,
            ..Sent::EMPTY
        };
        self.push_sent(sender, id);
    }

    /// The sent message `id` will never be answered (its window or its receiver's queue went): a
    /// send the server waits on is dropped, for the server to see, as no answer of the window's;
    /// any other is answered 0, what SendMessage gives back then.
    fn drop_unanswered(&mut self, id: SentId) {
        let sent = self.sent.at_mut(id);
        if sent.server {
            sent.next = None;
            sent.state = State::Dropped;
            self.server_wake = true;
        } else {
            self.answer(id, 0);
        }
    }

    /// The sent message `id` will never be answered: its receiver's queue ended, its thread gone.
    /// A send the server or a thread waits on is dropped, for the sender to see — the thread's
    /// SendMessage then fails, as Windows 2000's fails when its receiver dies; one nobody waits on
    /// goes back to the pool.
    fn receiver_gone(&mut self, id: SentId) {
        let sent = self.sent.at_mut(id);
        sent.next = None;
        match sent.sender {
            Some(sender) if self.queues[sender.index as usize].generation == sender.generation => {
                sent.state = State::Dropped;
                self.wake(sender);
            }
            _ if sent.server => {
                sent.state = State::Dropped;
                self.server_wake = true;
            }
            _ => self.free_sent(id),
        }
    }

    /// Take the sent message `id` off its receiver's list, where it waits to be handed out.
    fn unlink_sent(&mut self, receiver: QueueId, id: SentId) {
        let mut previous = None;
        let mut at = self.queues[receiver.index as usize].sent.head;
        while let Some(entry) = at {
            let next = self.sent.at(entry).next;
            if entry == id {
                let list = &mut self.queues[receiver.index as usize].sent;
                match previous {
                    Some(p) => self.sent.at_mut(p).next = next,
                    None => list.head = next,
                }
                if list.tail == Some(entry) {
                    list.tail = previous;
                }
                self.sent.at_mut(entry).next = None;
                return;
            }
            previous = Some(entry);
            at = next;
        }
    }

    /// The queue's next sent message, taken off its list; none when there is none.
    fn pop_sent(&mut self, id: QueueId) -> Option<SentId> {
        let queue = &mut self.queues[id.index as usize];
        let sent = queue.sent.head?;
        queue.sent.head = self.sent.at(sent).next;
        if queue.sent.head.is_none() {
            queue.sent.tail = None;
        }
        self.sent.at_mut(sent).next = None;
        Some(sent)
    }

    /// The sent message `id`, which ReplyMessage answered ([`State::Replied`]), leaves its
    /// receiver's stack: back to the pool when its answer was taken already (or nobody waits for
    /// it), else answered, for its sender or the server to take.
    fn leave_stack(&mut self, id: SentId) {
        let sent = self.sent.at_mut(id);
        sent.next = None;
        if sent.state != State::Replied {
            return;
        }
        if sent.sender.is_none() && !sent.server {
            self.free_sent(id);
        } else {
            sent.state = State::Answered;
        }
    }

    /// The sender or the server took the answer to the sent message `id`: back to the pool, unless
    /// its receiver still delivers it ([`State::Replied`]), whose delivery's end frees it.
    fn collected(&mut self, id: SentId) {
        let sent = self.sent.at_mut(id);
        if sent.state == State::Replied {
            sent.sender = None;
            sent.server = false;
        } else {
            self.free_sent(id);
        }
    }

    /// End the queue at `index`: what was posted to it goes, what was sent to it and not answered
    /// is dropped, failing its sender ([`Queues::receiver_gone`]), the sends it waits on are left
    /// to be dropped when answered, its timers go.
    fn end_queue(&mut self, index: u16) {
        self.purge_posted(index, |_| true);
        let id = QueueId {
            index,
            generation: self.queues[index as usize].generation,
        };
        while let Some(sent) = self.pop_sent(id) {
            self.receiver_gone(sent);
        }
        while let Some(sent) = self.queues[index as usize].receiving {
            self.queues[index as usize].receiving = self.sent.at(sent).next;
            if self.sent.at(sent).state == State::Received {
                self.receiver_gone(sent);
            } else {
                self.leave_stack(sent);
            }
        }
        // The sends it waits on, the innermost and the ones it delivered messages inside: their
        // answers go to nobody.
        let mut from = 0;
        while let Some((at, live)) = self.sent.next_live(from) {
            from = at + 1;
            let sent = self.sent.at_mut(live);
            if sent.sender == Some(id) {
                sent.sender = None;
                if sent.state == State::Answered {
                    self.free_sent(live);
                }
            }
        }
        self.timers.thread_gone(ThreadId(index));
        self.updates.thread_gone(ThreadId(index));
        let queue = &mut self.queues[index as usize];
        *queue = Queue {
            generation: queue.generation.wrapping_add(1),
            ..Queue::EMPTY
        };
    }
}

// --- The queues' lives ---------------------------------------------------------------------------

/// The thread record `thread` serves the thread `key`, whose client id is `client_id`: give it its
/// queue, at its first service, or a fresh one when the record served another thread before (that
/// thread's queue ends, see [`detach`]).
pub fn attach(windows: &mut Windows, thread: ThreadId, key: ThreadKey, client_id: u32) {
    let queues = &mut windows.queues;
    let index = thread.0;
    let queue = &queues.queues[index as usize];
    if queue.live && queue.key == Some(key) {
        return;
    }
    if queue.live {
        queues.end_queue(index);
    }
    let queue = &mut queues.queues[index as usize];
    *queue = Queue {
        live: true,
        generation: queue.generation,
        key: Some(key),
        client_id,
        ..Queue::EMPTY
    };
}

/// The thread record `thread`'s thread ended (or its process did): its queue ends with it. What
/// was posted to it goes; what was sent to it and not answered fails its sender; its timers go.
/// A record another thread takes over ends its queue through [`attach`] too.
pub fn detach(windows: &mut Windows, thread: ThreadId) {
    if windows.queues.queue_of(thread).is_some() {
        windows.queues.end_queue(thread.0);
    }
}

/// The queue of the thread whose client id is `client_id`, as PostThreadMessage names it, and the
/// thread it serves: the queue of the thread the client-id table names by it now. A queue whose
/// thread ended and whose object went keeps the id it had until its record goes (a GUI thread
/// that ended above the passive level leaves its queue to its process's reap), and the id may be
/// another thread's by then (client ids are reused, LIFO): that queue is not the id's.
pub fn queue_by_client_id(windows: &Windows, client_id: u32) -> Option<(ThreadId, ThreadKey)> {
    queue_by_client_id_in(windows, client_id, thread_named_by)
}

/// The thread the client-id table names by `client_id` now, as the window manager keys threads;
/// none for an id that names no thread object.
#[cfg(not(test))]
fn thread_named_by(client_id: u32) -> Option<Option<ThreadKey>> {
    let thread = crate::process::cid::lookup(client_id).and_then(|named| named.thread());
    Some(thread.map(|id| ThreadKey {
        index: id.index,
        generation: id.generation,
    }))
}

/// The host tests' queues carry client ids no table hands out: no check (see
/// [`queue_by_client_id_in`]'s own test for the check).
#[cfg(test)]
fn thread_named_by(_: u32) -> Option<Option<ThreadKey>> {
    None
}

/// [`queue_by_client_id`], the id's thread found by `named` (none: no check; some none: the id
/// names no thread).
fn queue_by_client_id_in(
    windows: &Windows,
    client_id: u32,
    named: impl FnOnce(u32) -> Option<Option<ThreadKey>>,
) -> Option<(ThreadId, ThreadKey)> {
    if client_id == 0 {
        return None;
    }
    let current = named(client_id);
    windows
        .queues
        .live_queues()
        .filter(|(_, q)| q.client_id == client_id)
        .filter_map(|(thread, q)| Some((thread, q.key?)))
        .find(|&(_, key)| current.is_none_or(|current| current == Some(key)))
}

/// The client id of the thread the thread record `thread` serves, as its queue keeps it; none for
/// a record with no queue (the window manager's own).
pub fn client_id_of(windows: &Windows, thread: ThreadId) -> Option<u32> {
    let queue = windows.queues.queues.get(thread.0 as usize)?;
    (queue.live && queue.client_id != 0).then_some(queue.client_id)
}

// --- Posting -------------------------------------------------------------------------------------

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
/// yet (the read binds it, [`super::input::bind`]), whose key the key state names `key`
/// ([`super::input`]). A key-down that repeats its key (`repeat`) while the queue's last input
/// message, not read yet, is the same message of the same key raises that message's repeat count
/// (lParam's low word) instead, as Windows 2000's queue folds a held key's repeats (the folded
/// message's window is bound when it is read, as any other's). Nothing when the thread has no
/// queue; the message is lost when the pool cannot grow.
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
fn input_kind(message: u32) -> u32 {
    match message {
        rtl::user::WM_MOUSEMOVE => QS_MOUSEMOVE,
        m if super::mouse::is_mouse(m) => QS_MOUSEBUTTON,
        _ => QS_KEY,
    }
}

/// A mouse message for the thread record `thread`'s queue, as the input path posts it
/// ([`super::mouse`]): `msg`, its window bound, its lParam and pt the screen point, of the button
/// `key` (0 for a move). A WM_MOUSEMOVE while the queue's last input message, not read yet, is a
/// WM_MOUSEMOVE takes that message's place instead (the one pending move Windows 2000 keeps a
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
    prepared: super::mouse::Prepared,
) {
    let queues = &mut windows.queues;
    let Some(id) = queues.queue_of(caller) else {
        return;
    };
    let mut at = queues.queues[id.index as usize].input.head;
    while let Some(index) = at {
        let posted = queues.posted.get_mut(index);
        if index == entry {
            if super::mouse::is_mouse(posted.msg.message) && posted.msg.pt == prepared.pt {
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

// --- Reading -------------------------------------------------------------------------------------

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
    /// caller learns it ([`super::mouse::hit_test`], [`super::mouse::prepared`]), keeps it with
    /// the entry ([`keep_prepared`]) and reads again.
    Prepare {
        entry: u32,
        window: WindowId,
        pt: Point,
        captured: bool,
    },
    /// A mouse message, converted for the thread ([`super::mouse::convert`]): what follows it
    /// before the thread has it is the caller's ([`super::mouse::after_read`]).
    Mouse(super::mouse::MouseRead),
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
    if let Taken::Message(msg) | Taken::Mouse(super::mouse::MouseRead { msg, .. }) = taken {
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
            if super::mouse::is_mouse(msg.message) {
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
            match super::input::bind(windows, caller, msg) {
                None => {
                    windows
                        .queues
                        .unlink_posted(id.index, Lane::Input, previous, entry);
                    super::input::read(windows, caller, &msg, key);
                }
                Some(msg) if filter.takes(msg.hwnd, msg.message) => {
                    if remove {
                        windows
                            .queues
                            .unlink_posted(id.index, Lane::Input, previous, entry);
                        super::input::read(windows, caller, &msg, key);
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
        if let Some(hwnd) = super::paint::next_paint(windows, caller, filter) {
            return Ok(Taken::Message(made(hwnd, WM_PAINT, 0, 0, time)));
        }
    }

    // The caret's blink, which makes no message: the thread's caret turned when its turn came.
    super::caret::blink(windows, caller, now);

    // WM_TIMER, for a timer of the thread's that came due.
    let caret_due = super::caret::next_due(windows, caller);
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
/// the entry before it), for `caller` (see [`super::mouse`]): its window, the capture window when
/// the thread has the capture; what the read learned of it, or the preparation that learns it; its
/// conversion, judged by the filter; taken out when `remove`, the thread's key state and its last
/// press moving with it.
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
        super::input::read_button(windows, caller, msg.message, key);
        MouseStep::Dropped
    };
    let capture = super::mouse::capture_of(windows, caller);
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
    if super::mouse::lets_through(prepared.hit) {
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
        super::mouse::convert(windows, window, &msg, &prepared, click);
    if !filter.in_range(converted.message) {
        return MouseStep::Skipped;
    }
    if remove {
        windows
            .queues
            .unlink_posted(id.index, Lane::Input, previous, entry);
        super::input::read_button(windows, caller, client_message, key);
        let queue = &mut windows.queues.queues[id.index as usize];
        queue.click =
            super::mouse::next_click(click, client_message, hwnd, converted.time, converted.pt);
    }
    MouseStep::Found(Taken::Mouse(super::mouse::MouseRead {
        msg: converted,
        client_message,
        hit: prepared.hit,
        captured: capture.is_some(),
        removed: remove,
    }))
}

/// A message the queue makes, stamped `time`.
fn made(hwnd: Hwnd, message: u32, wparam: WParam, lparam: LParam, time: u32) -> Msg {
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

// --- Waiting, and the thread's state of its reads ------------------------------------------------

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
    super::caret::blink(windows, caller, now);
    let due = match (
        windows.queues.timers.next_due(caller),
        super::caret::next_due(windows, caller),
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
    if super::paint::next_paint(windows, caller, &Filter::new(0, 0, 0, 0)).is_some() {
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
const CURSOR_LEVEL_START: i32 = -1;

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

/// Whether the thread record `thread` is hung at `time` (milliseconds): it has gone more than
/// [`HUNG_TIMEOUT`] without reading its queue, and does not idle — its last read found something,
/// as Windows 2000 deems a thread that is not waiting for input (one whose last read found its
/// queue empty, a GetMessage's caller waiting or a PeekMessage loop polling, is not hung).
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

// --- A sent message's delivery -------------------------------------------------------------------

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
fn keep_out(sent: &mut Sent, out: &CallbackOut) {
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

// --- Sending -------------------------------------------------------------------------------------

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

// --- The server's sends --------------------------------------------------------------------------

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
/// for the window `hwnd`'s thread as another thread's send is, the server, which has no queue,
/// waiting for its answer on its own event ([`wait_for_server`]). Windows 2000's csrss sends its
/// WM_QUERYENDSESSION and WM_ENDSESSION from a thread of its own, a GUI thread with a queue; F2K's
/// server is the console's control thread, a system thread, so the answer is marked for it instead.
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

/// Queue `message` for the window `target`'s thread as a message the window manager sent (no
/// thread waits for its answer): a decision of a thread with no queue (the console server's), or
/// the activation of another thread's windows, which Windows 2000 hands that thread to do
/// ([`Session::queue_for`]). Nothing for a window whose procedure is the window manager's, or a
/// thread with no queue; nothing either when the pool cannot grow (the message is lost), nor for
/// a creation message, which goes to the creating thread's own window, by callback
/// ([`QueueSession`]), nor for WM_GETMINMAXINFO, whose defaults stand when nobody waits for the
/// answer.
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
            super::caret::ncdestroy_delivered(windows, caller, window);
        }
        if top == id {
            // Another thread's activation deactivating this one, its WM_NCACTIVATE (FALSE)
            // answered FALSE: the deactivation stops there ([`super::focus`]).
            let deferred = sender.is_none()
                && !server
                && !notify
                && !reply
                && !matches!(carried, Carried::Callback(_));
            if let (WM_NCACTIVATE, 0, true, 0, Some(window)) =
                (message, wparam, deferred, answer, window)
            {
                super::focus::deactivation_vetoed(windows, caller, window);
            }
            return;
        }
    }
}

/// The `__fn*` slot a message the window manager sends goes through, by its payload's kind (see
/// [`callback_input`]).
fn slot(message: u32, payload: &Payload) -> u32 {
    match payload {
        Payload::None if message == WM_NCDESTROY => FN_NCDESTROY,
        Payload::None => FN_DWORD,
        Payload::Rect(_) | Payload::CalcSize(_) => FN_INOUTNCCALCSIZE,
        Payload::WindowPos(_) if message == WM_WINDOWPOSCHANGING => FN_INOUTLPWINDOWPOS,
        Payload::WindowPos(_) => FN_INLPWINDOWPOS,
        Payload::Style(_) => FN_INOUTSTYLECHANGE,
        Payload::MinMax(_) => FN_INOUTLPPOINT5,
        Payload::Create(_) => FN_INLPCREATESTRUCT,
    }
}

/// The callback a message the window manager sends to `target` (whose procedure is `proc`) is
/// (rtl::callback's notes): the `__fn*` slot its payload's kind names ([`slot`]), the input
/// block's head, and the structure the block carries after it (its first `length` bytes). A
/// creation message's window name follows the structure in the block
/// ([`Windows::create_text`]); its CREATESTRUCTW's lpszClass is the class's atom, as a receipt's
/// was. WM_NCCALCSIZE's NCCALCSIZE_PARAMS is followed by its WINDOWPOS (its lppos 0: user32 points
/// it at the copy); WM_WINDOWPOSCHANGING goes to the in-out WINDOWPOS slot, WM_WINDOWPOSCHANGED to
/// the input-only one.
pub fn callback_input(
    windows: &Windows,
    classes: &class::Registry,
    target: WindowId,
    proc: u32,
    message: &Message,
) -> CallbackInput {
    callback_input_for(windows, classes, windows.handle_of(target), proc, message)
}

/// [`callback_input`] for the window `hwnd`, by its handle: a message another thread sent, whose
/// window may be gone by its delivery.
fn callback_input_for(
    windows: &Windows,
    classes: &class::Registry,
    hwnd: Hwnd,
    proc: u32,
    message: &Message,
) -> CallbackInput {
    let mut input = CallbackInput {
        api: slot(message.message, &message.payload),
        head: CallbackMsg {
            proc,
            hwnd,
            message: message.message,
            wparam: message.wparam,
            lparam: message.lparam,
        },
        carried: [0; CARRIED],
        length: 0,
    };
    let mut put = |bytes: &[u8]| {
        input.carried[input.length..input.length + bytes.len()].copy_from_slice(bytes);
        input.length += bytes.len();
    };
    match &message.payload {
        Payload::None => {}
        Payload::Rect(r) => put(r.as_bytes()),
        Payload::CalcSize(calc) => {
            let params = rtl::window::NcCalcSizeParams {
                rects: calc.rects,
                pos: 0,
            };
            put(params.as_bytes());
            put(calc.pos.as_bytes());
        }
        Payload::WindowPos(p) => put(p.as_bytes()),
        Payload::Style(style) => put(style.as_bytes()),
        Payload::MinMax(mmi) => put(mmi.raw().as_bytes()),
        Payload::Create(p) => {
            let class = match p.class_name {
                ClassArg::Atom(atom) => atom,
                ClassArg::Name | ClassArg::AnsiName => windows
                    .class_window(hwnd)
                    .map_or(0, |w| classes.atom(w.class)),
            };
            let create = CreateStructW {
                create_params: p.params,
                instance: p.instance,
                menu: p.menu,
                parent: p.parent,
                cy: p.cy,
                cx: p.cx,
                y: p.y,
                x: p.x,
                style: p.style,
                name: 0,
                class: u32::from(class),
                ex_style: p.ex_style,
            };
            put(create.as_bytes());
        }
    }
    input
}

/// The longest structure a callback's block carries: an NCCALCSIZE_PARAMS and its WINDOWPOS (a
/// CREATESTRUCTW is shorter).
const CARRIED: usize = size_of::<rtl::window::NcCalcSizeParams>() + size_of::<WindowPos>();
const _: () = assert!(CARRIED >= size_of::<CreateStructW>());

/// What a callback's output block hands back after the LRESULT (rtl::callback's notes): at most
/// [`OUT_MAX`] bytes, read from the user's output block by the issuer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CallbackOut {
    pub bytes: [u8; OUT_MAX],
    /// How many of them the routine handed back.
    pub length: usize,
}

/// The structure `message` carried written back from the callback output `out` (the bytes after
/// the LRESULT): for the in-out slots only ([`rtl::callback::out_size`]) and only when the routine
/// handed back the whole structure; anything shorter (an untrusted routine's short or missing
/// block) leaves the structure as it was sent, anything longer is not read. WM_NCCALCSIZE's
/// TRUE form takes back its three rectangles, not lppos; WM_WINDOWPOSCHANGED and the creation's
/// structures are input only.
pub fn read_back(api: u32, message: &mut Message, out: &CallbackOut) {
    let wanted = rtl::callback::out_size(api, message.wparam);
    if wanted == 0 || out.length < wanted {
        return;
    }
    let bytes = &out.bytes[..wanted];
    match (&mut message.payload, api) {
        (Payload::Rect(rect), FN_INOUTNCCALCSIZE) => {
            if let Some(back) = rtl::gdi::Rect::from_bytes(bytes) {
                *rect = back;
            }
        }
        (Payload::CalcSize(calc), FN_INOUTNCCALCSIZE) => {
            if let Some(back) = rtl::window::NcCalcSizeParams::from_bytes(bytes) {
                calc.rects = back.rects;
            }
        }
        (Payload::WindowPos(pos), FN_INOUTLPWINDOWPOS) => {
            if let Some(back) = WindowPos::from_bytes(bytes) {
                *pos = back;
            }
        }
        (Payload::Style(style), FN_INOUTSTYLECHANGE) => {
            if let Some(back) = StyleStruct::from_bytes(bytes) {
                *style = back;
            }
        }
        (Payload::MinMax(mmi), FN_INOUTLPPOINT5) => {
            if let Some(back) = rtl::user::MinMaxInfo::from_bytes(bytes) {
                *mmi = window::MinMaxInfo::of_raw(&back);
            }
        }
        _ => {}
    }
}

/// A message's callback, as [`callback_input`] makes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CallbackInput {
    /// The `__fn*` slot.
    pub api: u32,
    pub head: CallbackMsg,
    /// The structure, its first `length` bytes.
    pub carried: [u8; CARRIED],
    pub length: usize,
}

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
    super::caret::window_gone(windows, window);
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
/// deciding thread's own, with a client-side procedure, is a callback to it: the lock let go
/// meanwhile ([`Hold::unlocked`]), the procedure's answer the send's, as Windows 2000's `xxx`
/// routines call back (rtl::callback's notes). A message to another thread's window is queued
/// for that thread, the decision waiting for the answer and the structure with the lock let go,
/// delivering by callback the messages sent to its own thread meanwhile ([`send_and_wait`]), as
/// Windows 2000's `xxxInterSendMsgEx` waits; the activation of another thread's windows is
/// queued for that thread and not waited for ([`Session::queue_for`]), as Windows 2000 hands it
/// to the thread as an event. A decision of a thread with no queue queues its messages too
/// ([`defer`]), answered as the default procedure answers. A window whose procedure is the window
/// manager's is answered as the default procedure answers. A window's end takes its posted
/// messages, timers and update region with it; the activation and the destroy's focus check are
/// [`super::focus`]'s. The other window-manager calls are [`Session`]'s defaults. The services
/// hold it by the window manager's lock ([`with_session`]); the host tests by the registries,
/// which cannot be let go of: their sends are all queued.
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
        super::focus::activate(self, target, command)
    }

    fn check_focus(&mut self, target: WindowId) {
        super::focus::check_focus(self, target);
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

/// The send of `message` to `target`, a window of another thread's (whose procedure is `proc`),
/// from a decision of the running thread, when it has a queue and `hold` can let the lock go: the
/// message queued for the window's thread with the window manager's copy of its structure
/// ([`send_for_decision`]), and the decision waiting on its queue, the lock let go, until the
/// receiver's procedure answers at its thread's next read (or inside its own wait), as Windows
/// 2000's `xxxInterSendMsgEx` waits. The answer, and the structure as the procedure left it. The
/// messages sent to the waiting thread meanwhile are delivered by callback as they come
/// ([`take_for_callback`]), so that two threads whose decisions send to each other do not wait on
/// each other for good. A receiving thread that ends first answers 0, the structure as it was
/// sent. A wait has no end: a receiver that never reads holds the decision, as on Windows 2000;
/// the thread may still be terminated inside it. None when the message is not one to wait for.
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
    wakes: Wakes,
    /// How many queues are made: every one's event is set when the wakes overflowed.
    #[cfg_attr(not(target_arch = "x86"), allow(dead_code))]
    made: usize,
    server: bool,
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

// --- The target's side: the queues' events, the waits, the services ------------------------------

#[cfg(target_arch = "x86")]
mod target {
    use core::cell::UnsafeCell;
    use core::ptr::NonNull;

    use super::*;
    use crate::level::{At, Dispatch, Passive};
    use crate::sched::event::{Event, EventKind, EVENT_WAKE_INCREMENT};
    use crate::sched::wait::{self, WaitMode, WaitReason, WaitableId};

    /// A queue's event: a synchronization event, set whenever its queue is given something (see
    /// [`Queues::take_wakes`]), waited on by the queue's thread alone. Named by its address in the
    /// dispatcher database ([`WaitableId::Embedded`]) when its chunk is made, and reached only
    /// through the dispatcher from then on.
    struct QueueEvent(UnsafeCell<Event>);

    // SAFETY: one processor. An event is touched directly once, by `write_fresh` as its chunk is
    // made, before its chunk is published: no thread can wait on it or set it yet. From then on
    // only the dispatcher reaches its header, by its address, serialized at the dispatch level.
    unsafe impl Sync for QueueEvent {}

    // SAFETY: writes a whole record, named at its final address.
    unsafe impl Record for QueueEvent {
        unsafe fn write_fresh(at: *mut Self, _: u32) {
            // SAFETY: the caller's contract: `at` is the record's final address, unpublished.
            unsafe {
                at.write(QueueEvent(UnsafeCell::new(Event::new(
                    EventKind::Synchronization,
                    false,
                ))));
                (*(*at).0.get()).init();
            }
        }
    }

    /// The queues' events, at their thread records' indices: made with the queue, from the
    /// nonpaged pool, outside the window manager (whose state its lock's holder borrows whole),
    /// and kept at their peak, so an event never moves.
    static EVENTS: crate::slots::SideTable<
        QueueEvent,
        { crate::slots::entries_per_page::<QueueEvent>() },
    > = crate::slots::SideTable::new();

    /// Make the event of the queue at `index`: false when no page is left for it.
    pub fn make_event(index: u16) -> bool {
        EVENTS
            .ensure(index.into(), &crate::slots::KERNEL_PAGES)
            .is_ok()
    }

    /// The event of the queue at `index`, made with the queue: its header's address. No
    /// reference to the event is formed.
    fn event_id(index: usize) -> WaitableId {
        let event = EVENTS
            .address(index as u32)
            .expect("a queue's event made with the queue");
        // SAFETY: a projection inside the record's own cell: it computes the header's address and
        // reads nothing.
        let header = unsafe { core::ptr::addr_of_mut!((*(*event.as_ptr()).0.get()).waitable) };
        WaitableId::Embedded(NonNull::new(header).expect("a made record is not null"))
    }

    /// The server's event: a synchronization event, set whenever a send the server waits on is
    /// answered or dropped (see [`Queues::take_server_wake`]), waited on by the console's control
    /// thread alone, which carries the session's end. Named and reached as the queues' events are.
    struct ServerEvent(UnsafeCell<Event>);

    // SAFETY: as for `QueueEvents`: touched directly once, by `init` at boot, then only through
    // the dispatcher, by its address, at the dispatch level.
    unsafe impl Sync for ServerEvent {}

    static SERVER: ServerEvent = ServerEvent(UnsafeCell::new(Event::new(
        EventKind::Synchronization,
        false,
    )));

    impl ServerEvent {
        /// The event's name: its header's address. No reference to the event is formed.
        fn id(&self) -> WaitableId {
            // SAFETY: a projection inside the static's own cell: it computes the header's address
            // and reads nothing.
            let header = unsafe { core::ptr::addr_of_mut!((*self.0.get()).waitable) };
            WaitableId::Embedded(NonNull::new(header).expect("a static is not null"))
        }
    }

    /// Name the server's event. Once, at boot, before the first process (the queues' are named
    /// as they are made).
    pub fn init() {
        let _masked = crate::pcr::pcr().mask_guard();
        // SAFETY: the one direct reach into the event (see the `Sync` impl): nothing waits on it
        // or sets it yet, and interrupts are masked for the reference's life.
        unsafe { (*SERVER.0.get()).init() };
    }

    /// Run `f` on the locked window manager, then set the events of the queues it gave something,
    /// once the lock is let go.
    pub fn with_manager<R>(
        passive: &mut At<Passive>,
        f: impl FnOnce(&mut WindowManager) -> R,
    ) -> R {
        with_session(passive, |session| f(session.manager()))
    }

    /// Run `f` in a session over the locked window manager ([`QueueSession`]), the window
    /// manager's decisions' way in, then set the events of the queues it gave something, once the
    /// lock is let go, and settle the foreground processes, which a change of the foreground
    /// window moves (`crate::process::foreground`).
    pub fn with_session<R>(
        passive: &mut At<Passive>,
        f: impl FnOnce(&mut QueueSession<Locked<'_>>) -> R,
    ) -> R {
        let (result, signals) = {
            let mut session = QueueSession::over(crate::win32k::window::lock(passive));
            let result = f(&mut session);
            (result, Signals::take(session.manager()))
        };
        signals.raise(passive);
        crate::process::foreground::sync();
        result
    }

    impl Signals {
        /// Set the events of the queues given something, and the server's when its send was
        /// answered: outside the window manager's lock.
        pub fn raise(self, passive: &mut At<Passive>) {
            let Signals {
                wakes,
                made,
                server,
            } = self;
            if !server && wakes.is_empty() {
                return;
            }
            let mut dispatch = passive.raise::<Dispatch>();
            let dispatcher = crate::sched::DISPATCHER.get(&mut dispatch);
            for index in wakes.each(made) {
                dispatcher.set_event(event_id(index.into()), EVENT_WAKE_INCREMENT);
            }
            if server {
                dispatcher.set_event(SERVER.id(), EVENT_WAKE_INCREMENT);
            }
        }
    }

    /// [`with_manager`] for a caller that holds no passive token: the console's control thread,
    /// carrying the session's end.
    ///
    /// # Panics
    ///
    /// The processor is above the passive level (see `crate::win32k::window::locked`).
    pub fn locked<R>(f: impl FnOnce(&mut WindowManager) -> R) -> R {
        assert_eq!(
            crate::pcr::pcr().current(),
            crate::interrupt::irql::PASSIVE,
            "the window manager's bridge entered above the passive level"
        );
        // SAFETY: a passive entry (see `At::enter`): the ledger reads the passive level, and the
        // token stays on this thread, dropped with this frame.
        let mut passive = unsafe { At::<Passive>::enter() };
        with_manager(&mut passive, f)
    }

    /// The server's wait for an answer to its send: until its event is set, or `also` (the
    /// receiving process's object) signals, or for `interval` (100 ns units, relative). A system
    /// thread's wait, in kernel mode.
    pub fn wait_for_server(also: WaitableId, interval: i64) {
        let objects = [SERVER.id(), also];
        let _ = wait::wait_current_with(|dispatcher, me, stamp, replay| {
            let timeout = wait::replay_timeout(
                dispatcher.thread(me),
                replay,
                Some(interval),
                stamp.interrupt_time,
            );
            dispatcher.wait_for_multiple(
                me,
                &objects,
                false,
                WaitReason::Executive,
                WaitMode::Kernel,
                false,
                timeout,
                stamp,
            )
        });
    }

    /// Wait on the queue of the thread record `thread` until something sets its event, or for
    /// `timeout` (100 ns units, relative). A program's wait: a thread terminated meanwhile ends
    /// inside it.
    pub fn wait_on_queue(thread: ThreadId, timeout: Option<i64>) {
        let event = event_id(thread.0 as usize);
        let _ = wait::wait_current_with(|dispatcher, me, stamp, replay| {
            let timeout =
                wait::replay_timeout(dispatcher.thread(me), replay, timeout, stamp.interrupt_time);
            dispatcher.wait_for(
                me,
                event,
                WaitReason::UserRequest,
                WaitMode::User,
                false,
                timeout,
                stamp,
            )
        });
    }

    /// MsgWaitForMultipleObjects' wait: the calling thread (its queue `thread`) waits on
    /// `objects` and on its queue's event at once, a wait-any, until `timeout` (100 ns units,
    /// relative; none: no end), its user APCs ending it when `alertable` (STATUS_USER_APC): the
    /// wait's status, STATUS_WAIT_0 + the count of `objects` for the queue's event (given
    /// something: the caller looks again at what).
    pub fn wait_on_objects_or_queue(
        thread: ThreadId,
        objects: &[WaitableId],
        alertable: bool,
        timeout: Option<i64>,
    ) -> NtStatus {
        let mut ids = [event_id(thread.0 as usize); wait::MAXIMUM_WAIT_OBJECTS];
        ids[..objects.len()].copy_from_slice(objects);
        wait_on_objects(&ids[..=objects.len()], false, alertable, timeout)
    }

    /// The calling thread waits on `objects` (one at least), a wait-all when `wait_all`, until
    /// `timeout` (100 ns units, relative; none: no end), alertably when `alertable`: the wait's
    /// status, as NtWaitForMultipleObjects'.
    pub fn wait_on_objects(
        objects: &[WaitableId],
        wait_all: bool,
        alertable: bool,
        timeout: Option<i64>,
    ) -> NtStatus {
        wait::wait_current_with(|dispatcher, me, stamp, replay| {
            let timeout =
                wait::replay_timeout(dispatcher.thread(me), replay, timeout, stamp.interrupt_time);
            dispatcher.wait_for_multiple(
                me,
                objects,
                wait_all,
                WaitReason::UserRequest,
                WaitMode::User,
                alertable,
                timeout,
                stamp,
            )
        })
    }

    /// The interrupt time, the clock the queues' times and the timers' dues read.
    pub fn now() -> u64 {
        crate::interrupt::clock::interrupt_time()
    }
}

#[cfg(target_arch = "x86")]
use target::make_event;
#[cfg(target_arch = "x86")]
pub use target::{
    init,
    locked,
    now,
    wait_for_server,
    wait_on_objects,
    wait_on_objects_or_queue,
    wait_on_queue,
    with_manager,
    with_session,
};

#[cfg(target_arch = "x86")]
mod services {
    use rtl::pod::Pod;
    use rtl::user::{
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
        RECEIVED_NONE,
        SMTO_ABORTIFHUNG,
    };

    use super::*;
    use crate::nt::call::{Handle, NtCall, NtResult, UserAddr, UserPtr};
    use crate::sched::wait::{WaitableId, MAXIMUM_WAIT_OBJECTS};
    use crate::win32k::text::Staged;
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

    /// A read of the caller's queue ([`take`]) at `now`, each sent message it hands out delivered
    /// by callback before it reads on ([`receive_by_callback`]), as Windows 2000's reads receive
    /// the sent messages first; a mouse message's window asked where its point is
    /// (WM_NCHITTEST, [`crate::win32k::mouse::hit_test`]) before the read goes on, and a mouse
    /// message read out followed by its WM_MOUSEACTIVATE and WM_SETCURSOR
    /// ([`crate::win32k::mouse::after_read`]), the message eaten as they say. What it took: a
    /// message, or nothing.
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
    /// SendMessageTimeout's kernel side ([`send`]): the procedure to call into `proc` for a window
    /// of the caller's own thread (`result` 0), otherwise 0 into `proc` and the answer into
    /// `result` — the caller waiting for it when another thread's procedure gives it, and
    /// delivering by callback the messages sent to it meanwhile, as Windows 2000's SendMessage
    /// does ([`receive_by_callback`]). With a timeout (rtl::user::SendTimeout,
    /// SendMessageTimeout's; null for SendMessage), the wait ends at its end, the message taken
    /// back if its receiver has not read it ([`abandon_send`]), and at once with SMTO_ABORTIFHUNG
    /// when the receiver is hung ([`window_hung`]): STATUS_TIMEOUT then (user32's ERROR_TIMEOUT),
    /// `result` 0. STATUS_INVALID_HANDLE when the receiving thread ends before it answers, its
    /// window gone with it ([`Awaited::Failed`]).
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
        let (id, deadline) = match start_send(call, thread, window, message, wparam, lparam, limit)?
        {
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
                            with_manager(call.passive(), |m| {
                                abandon_send(&mut m.windows, caller, id)
                            });
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
}

/// MsgWaitForMultipleObjects' wait: caret's NtUserCallTwoParam routes its routine here.
#[cfg(target_arch = "x86")]
pub use services::msg_wait;
pub use services::{
    call_one_param,
    dispatch_message,
    get_message,
    message_call,
    peek_message,
    post_message,
    post_thread_message,
    send_message_callback,
    send_notify_message,
    wait_message,
};

// The host builds have no processes and no user memory: the services answer nothing (the host
// tests drive the queues themselves).
#[cfg(not(target_arch = "x86"))]
mod services {
    use crate::nt::call::{Handle, NtCall, NtResult, UserAddr, UserPtr};
    use crate::status::*;

    pub fn post_message(_: &mut NtCall, _: Handle, _: u32, _: u32, _: i32) -> NtResult {
        Err(STATUS_NOT_IMPLEMENTED)
    }

    pub fn post_thread_message(_: &mut NtCall, _: u32, _: u32, _: u32, _: i32) -> NtResult {
        Err(STATUS_NOT_IMPLEMENTED)
    }

    pub fn get_message(_: &mut NtCall, _: UserAddr, _: Handle, _: u32, _: u32) -> NtResult {
        Err(STATUS_NOT_IMPLEMENTED)
    }

    pub fn peek_message(
        _: &mut NtCall,
        _: UserAddr,
        _: Handle,
        _: u32,
        _: u32,
        _: u32,
    ) -> NtResult {
        Err(STATUS_NOT_IMPLEMENTED)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn message_call(
        _: &mut NtCall,
        _: Handle,
        _: u32,
        _: u32,
        _: i32,
        _: UserPtr<u32>,
        _: UserPtr<i32>,
        _: UserAddr,
    ) -> NtResult {
        Err(STATUS_NOT_IMPLEMENTED)
    }

    pub fn send_notify_message(
        _: &mut NtCall,
        _: Handle,
        _: u32,
        _: u32,
        _: i32,
        _: UserPtr<u32>,
    ) -> NtResult {
        Err(STATUS_NOT_IMPLEMENTED)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn send_message_callback(
        _: &mut NtCall,
        _: Handle,
        _: u32,
        _: u32,
        _: i32,
        _: u32,
        _: u32,
        _: UserPtr<u32>,
        _: UserPtr<i32>,
    ) -> NtResult {
        Err(STATUS_NOT_IMPLEMENTED)
    }

    pub fn wait_message(_: &mut NtCall) -> NtResult {
        Err(STATUS_NOT_IMPLEMENTED)
    }

    pub fn dispatch_message(_: &mut NtCall, _: UserAddr, _: UserPtr<u32>) -> NtResult {
        Err(STATUS_NOT_IMPLEMENTED)
    }

    pub fn call_one_param(_: &mut NtCall, _: u32, _: u32, _: UserPtr<u32>) -> NtResult {
        Err(STATUS_NOT_IMPLEMENTED)
    }
}

/// The message layer's test rig: a window manager with the boot's desktop, a registered class,
/// threads with their queues, and windows of the class made through the queue's session.
#[cfg(test)]
pub(crate) mod rig {
    use rtl::gdi::Rect;
    use rtl::user::WS_POPUP;

    use super::*;
    use crate::win32k::window::{CreateArgs, MenuInput, WindowManager, DESKTOP_CREATEWINDOW};

    pub const DESKTOP: u32 = 1;
    pub const OWNER: class::Owner = 0;
    pub const OTHER_OWNER: class::Owner = 1;
    pub const MODULE: u32 = 0x0040_0000;
    /// The class's window procedure.
    pub const PROC: u32 = 0x0040_1000;

    /// A window manager with the boot's desktop (640x480) and the class "Rig" registered, leaked
    /// at its final address; the class's atom.
    pub fn manager() -> (&'static mut WindowManager, class::Atom) {
        let mut manager = Box::<WindowManager>::new_uninit();
        // SAFETY: the box is valid, aligned and the records' final address once leaked.
        unsafe { WindowManager::write_empty(manager.as_mut_ptr()) };
        // SAFETY: written whole just above.
        let m = Box::leak(unsafe { manager.assume_init() });
        m.boot_desktop(
            DESKTOP,
            Rect {
                left: 0,
                top: 0,
                right: 640,
                bottom: 480,
            },
        )
        .unwrap();
        let atom = register(m, OWNER);
        (m, atom)
    }

    /// The class "Rig" registered for the process `owner`: its atom.
    pub fn register(m: &mut WindowManager, owner: class::Owner) -> class::Atom {
        let name: Vec<u16> = "Rig".encode_utf16().collect();
        let wc = class::WndClassExW {
            cb_size: 48,
            style: 0,
            wnd_proc: PROC,
            cb_cls_extra: 0,
            cb_wnd_extra: 0,
            instance: MODULE,
            icon: 0,
            cursor: 0,
            background: 0,
            menu_name: 0,
            class_name: 0,
            icon_sm: 0,
        };
        let flags = class::RegisterFlags {
            win40_compat: true,
            ..class::RegisterFlags::default()
        };
        m.classes
            .register_class(
                &m.windows.handles,
                &wc,
                class::Name::Text(&name),
                class::MenuArg::None,
                owner,
                flags,
                DESKTOP,
            )
            .unwrap()
    }

    /// A thread of the process `owner` (its thread object's slot `slot`, client id `client_id`),
    /// connected, with its queue.
    pub fn thread_of(
        m: &mut WindowManager,
        slot: u16,
        client_id: u32,
        owner: class::Owner,
    ) -> ThreadId {
        let key = ThreadKey {
            index: slot,
            generation: 0,
        };
        let t = m
            .windows
            .connect_thread(key, owner, DESKTOP, DESKTOP_CREATEWINDOW, 0x10)
            .unwrap();
        attach(&mut m.windows, t, key, client_id);
        t
    }

    /// A thread of the rig's process.
    pub fn thread(m: &mut WindowManager, slot: u16, client_id: u32) -> ThreadId {
        thread_of(m, slot, client_id, OWNER)
    }

    /// A window of the class, `style` at (`x`, `y`) `cx` by `cy`, child of `parent` (0: a
    /// top-level window), made by `t` through the queue's session: its handle.
    #[allow(clippy::too_many_arguments)]
    pub fn window_at(
        m: &mut WindowManager,
        atom: class::Atom,
        t: ThreadId,
        style: u32,
        parent: Hwnd,
        x: i32,
        y: i32,
        cx: i32,
        cy: i32,
    ) -> Hwnd {
        let name: Vec<u16> = "Title".encode_utf16().collect();
        let mut args = CreateArgs {
            ex_style: 0,
            class_name: class::Name::Atom(atom),
            class_atom: atom,
            name: &name,
            style,
            x,
            y,
            cx,
            cy,
            parent: None,
            menu: MenuInput::None,
            instance: MODULE,
            params: 0x1234,
            version: 0x0005_0000,
        };
        WindowManager::create_window(
            &mut QueueSession::new(&mut m.windows, &mut m.classes),
            t,
            parent,
            &mut args,
        )
        .unwrap()
    }

    /// A hidden 320x200 popup at (0, 0), as the fixtures make theirs.
    pub fn popup(m: &mut WindowManager, atom: class::Atom, t: ThreadId) -> Hwnd {
        window_at(m, atom, t, WS_POPUP, 0, 0, 0, 320, 200)
    }

    /// Read `t`'s queue at `now` with `filter`, taking out.
    pub fn read(m: &mut WindowManager, t: ThreadId, filter: &Filter, now: u64) -> Taken {
        take(&mut m.windows, t, filter, true, now).unwrap()
    }

    /// Hand out and end every sent message waiting for `t`, as user32 delivers them: (window,
    /// message) each.
    pub fn deliver(m: &mut WindowManager, t: ThreadId) -> Vec<(Hwnd, u32)> {
        let only_sent = Filter::new(0, 0, 0, rtl::user::PM_QS_SENDMESSAGE);
        let mut got = Vec::new();
        while let Taken::Sent(id) = read(m, t, &only_sent, 0) {
            let head = head_of(&m.windows, id).unwrap();
            got.push((head.msg.hwnd, head.msg.message));
            assert!(end_sent(&mut m.windows, t, 0));
        }
        got
    }

    /// The payload the callback that delivers the sent message `id` carries.
    pub fn payload_of(m: &WindowManager, id: SentId) -> Payload {
        match delivery(&m.windows, &m.classes, id) {
            Some(Delivery::Structure(_, message)) => message.payload,
            other => panic!("a structure's callback, not {other:?}"),
        }
    }

    /// The text the callback that delivers the sent message `id` carries: its slot, its head, the
    /// text and WM_GETTEXT's buffer units.
    pub fn text_of(m: &WindowManager, id: SentId) -> (u32, CallbackMsg, Vec<u16>, u32) {
        match delivery(&m.windows, &m.classes, id) {
            Some(Delivery::Text {
                api,
                head,
                text,
                room,
            }) => (api, head, carried_units(&m.windows, text).to_vec(), room),
            other => panic!("a text's callback, not {other:?}"),
        }
    }

    /// Any message, window or range.
    pub fn all() -> Filter {
        Filter::new(0, 0, 0, 0)
    }

    /// The message a read found.
    pub fn msg_of(taken: Taken) -> Msg {
        match taken {
            Taken::Message(msg) => msg,
            other => panic!("a message, not {other:?}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use rtl::user::{
        PM_QS_POSTMESSAGE,
        PM_QS_SENDMESSAGE,
        WM_DESTROY,
        WM_GETMINMAXINFO,
        WM_KEYDOWN,
        WM_MOVE,
        WM_NCCALCSIZE,
        WM_NCDESTROY,
        WM_SIZE,
        WM_STYLECHANGING,
        WM_USER,
        WM_WINDOWPOSCHANGED,
        WS_CHILD,
        WS_POPUP,
    };
    use rtl::window::{SWP_NOACTIVATE, SWP_NOCLIENTSIZE, SWP_NOMOVE, SWP_NOSIZE, SWP_NOZORDER};

    use super::rig::*;
    use super::*;
    use crate::win32k::window::WindowManager;

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

    /// A creation message's callback: `__fnINLPCREATESTRUCT`, the class's procedure, and the
    /// CREATESTRUCTW the creation's parameters make (the class's atom for a class named by its
    /// string, lpszName left for the routine to point at the name after it); WM_NCDESTROY's is
    /// `__fnNCDESTROY`, another plain message's `__fnDWORD` with its lParam as it is, and
    /// WM_NCCALCSIZE's `__fnINOUTNCCALCSIZE` with the rectangle.
    #[test]
    fn a_messages_callback_carries_its_structure() {
        let (m, atom) = manager();
        let t = thread(m, 1, 0x100);
        let h = window_at(m, atom, t, WS_POPUP, 0, 5, 6, 30, 40);
        let w = m.windows.window_from_handle(h).unwrap();
        let params = window::CreateParams {
            ex_style: 0x8,
            class_name: ClassArg::Name,
            name: window::CreateName::Given,
            style: WS_POPUP,
            x: 5,
            y: 6,
            cx: 30,
            cy: 40,
            parent: 0,
            menu: 0,
            instance: MODULE,
            params: 0x1234,
        };
        let message = |message, payload| Message {
            message,
            wparam: 3,
            lparam: 4,
            payload,
        };
        let create = message(WM_NCCREATE, Payload::Create(params));
        let input = callback_input(&m.windows, &m.classes, w, PROC, &create);
        assert_eq!(input.api, FN_INLPCREATESTRUCT);
        assert_eq!(
            input.head,
            CallbackMsg {
                proc: PROC,
                hwnd: h,
                message: WM_NCCREATE,
                wparam: 3,
                lparam: 4,
            }
        );
        assert_eq!(input.length, 48);
        let cs = CreateStructW::from_bytes(&input.carried).unwrap();
        assert_eq!((cs.x, cs.y, cs.cx, cs.cy), (5, 6, 30, 40));
        assert_eq!(cs.create_params, 0x1234);
        assert_eq!(cs.instance, MODULE);
        assert_eq!((cs.style, cs.ex_style), (WS_POPUP, 0x8));
        assert_eq!(cs.name, 0);
        assert_eq!(cs.class, u32::from(atom));

        let plain = |number| {
            let input = callback_input(
                &m.windows,
                &m.classes,
                w,
                PROC,
                &message(number, Payload::None),
            );
            (input.api, input.head.lparam, input.length)
        };
        assert_eq!(plain(WM_NCDESTROY), (FN_NCDESTROY, 4, 0));
        assert_eq!(plain(WM_DESTROY), (FN_DWORD, 4, 0));
        let rect = rtl::gdi::Rect::new(1, 2, 3, 4);
        let input = callback_input(
            &m.windows,
            &m.classes,
            w,
            PROC,
            &message(WM_NCCALCSIZE, Payload::Rect(rect)),
        );
        assert_eq!((input.api, input.length), (FN_INOUTNCCALCSIZE, 16));
        assert_eq!(&input.carried[..16], rect.as_bytes());

        // A resize's WM_NCCALCSIZE (wParam TRUE): the NCCALCSIZE_PARAMS, lppos 0, then the
        // WINDOWPOS.
        let pos = WindowPos {
            hwnd: h,
            cx: 250,
            flags: 0x14,
            ..WindowPos::default()
        };
        let calc = window::CalcSize {
            rects: [rect, rtl::gdi::Rect::new(5, 6, 7, 8), rect],
            pos,
        };
        let mut resize = message(WM_NCCALCSIZE, Payload::CalcSize(calc));
        resize.wparam = 1;
        let input = callback_input(&m.windows, &m.classes, w, PROC, &resize);
        assert_eq!((input.api, input.length), (FN_INOUTNCCALCSIZE, 80));
        let params = rtl::window::NcCalcSizeParams::from_bytes(&input.carried[..52]).unwrap();
        assert_eq!((params.rects, params.pos), (calc.rects, 0));
        assert_eq!(&input.carried[52..80], pos.as_bytes());

        // WM_WINDOWPOSCHANGING's WINDOWPOS goes in and out, WM_WINDOWPOSCHANGED's in only.
        let slot = |number| {
            let input = callback_input(
                &m.windows,
                &m.classes,
                w,
                PROC,
                &message(number, Payload::WindowPos(pos)),
            );
            assert_eq!(&input.carried[..28], pos.as_bytes());
            (input.api, input.length)
        };
        assert_eq!(slot(WM_WINDOWPOSCHANGING), (FN_INOUTLPWINDOWPOS, 28));
        assert_eq!(slot(WM_WINDOWPOSCHANGED), (FN_INLPWINDOWPOS, 28));

        // WM_GETMINMAXINFO's MINMAXINFO, five POINTs, in and out.
        let mmi = window::MinMaxInfo {
            reserved: (1, 2),
            max_size: (3, 4),
            max_position: (5, 6),
            min_track: (7, 8),
            max_track: (9, 10),
        };
        let input = callback_input(
            &m.windows,
            &m.classes,
            w,
            PROC,
            &message(WM_GETMINMAXINFO, Payload::MinMax(mmi)),
        );
        assert_eq!((input.api, input.length), (FN_INOUTLPPOINT5, 40));
        let words: Vec<i32> = input.carried[..40]
            .chunks(4)
            .map(|c| i32::from_ne_bytes(c.try_into().unwrap()))
            .collect();
        assert_eq!(words, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    }

    /// A callback's output: `bytes` after the LRESULT.
    fn out(bytes: &[u8]) -> CallbackOut {
        let mut out = CallbackOut {
            bytes: [0; OUT_MAX],
            length: bytes.len().min(OUT_MAX),
        };
        out.bytes[..out.length].copy_from_slice(&bytes[..out.length]);
        out
    }

    /// The in-out slots' structures come back as the procedure left them: WM_NCCALCSIZE's
    /// rectangle, or its NCCALCSIZE_PARAMS's three rectangles (not lppos, nor the WINDOWPOS);
    /// WM_WINDOWPOSCHANGING's WINDOWPOS; WM_STYLECHANGING's STYLESTRUCT.
    #[test]
    fn a_callbacks_structure_comes_back() {
        let message = |message, wparam, payload| Message {
            message,
            wparam,
            lparam: 0,
            payload,
        };
        let rect = rtl::gdi::Rect::new(0, 0, 200, 100);
        let client = rtl::gdi::Rect::new(10, 10, 190, 90);
        let mut m = message(WM_NCCALCSIZE, 0, Payload::Rect(rect));
        read_back(FN_INOUTNCCALCSIZE, &mut m, &out(client.as_bytes()));
        assert_eq!(m.payload, Payload::Rect(client));

        let calc = window::CalcSize {
            rects: [rect; 3],
            pos: WindowPos::default(),
        };
        let back = rtl::window::NcCalcSizeParams {
            rects: [client, rect, client],
            pos: 0x7FFE_0000,
        };
        let mut m = message(WM_NCCALCSIZE, 1, Payload::CalcSize(calc));
        read_back(FN_INOUTNCCALCSIZE, &mut m, &out(back.as_bytes()));
        assert_eq!(
            m.payload,
            Payload::CalcSize(window::CalcSize {
                rects: [client, rect, client],
                pos: WindowPos::default(),
            })
        );

        let pos = WindowPos {
            x: 60,
            y: 70,
            cx: 220,
            cy: 130,
            ..WindowPos::default()
        };
        let edited = WindowPos {
            cx: 250,
            flags: 0x2,
            ..pos
        };
        let mut m = message(WM_WINDOWPOSCHANGING, 0, Payload::WindowPos(pos));
        read_back(FN_INOUTLPWINDOWPOS, &mut m, &out(edited.as_bytes()));
        assert_eq!(m.payload, Payload::WindowPos(edited));

        let style = StyleStruct {
            style_old: 0x04C0_0000,
            style_new: 0x04C8_0000,
        };
        let stuck = StyleStruct {
            style_new: 0x04CC_0000,
            ..style
        };
        let mut m = message(WM_STYLECHANGING, -16i32 as u32, Payload::Style(style));
        read_back(FN_INOUTSTYLECHANGE, &mut m, &out(stuck.as_bytes()));
        assert_eq!(m.payload, Payload::Style(stuck));

        // WM_GETMINMAXINFO's MINMAXINFO, whatever the procedure left in it (guigeo `edits`').
        let defaults = window::MinMaxInfo::unbounded();
        let answered = window::MinMaxInfo {
            reserved: (0, 0),
            max_size: (380, 280),
            max_position: (20, 30),
            min_track: (300, 250),
            max_track: (400, 300),
        };
        let mut m = message(WM_GETMINMAXINFO, 0, Payload::MinMax(defaults));
        read_back(FN_INOUTLPPOINT5, &mut m, &out(answered.raw().as_bytes()));
        assert_eq!(m.payload, Payload::MinMax(answered));
    }

    /// A routine's output is untrusted: one shorter than the slot's structure leaves the structure
    /// as it was sent, the bytes past it are not read, an input-only slot's are ignored, and a
    /// payload of another kind than the slot's is not written.
    #[test]
    fn a_short_or_foreign_callback_output_changes_nothing() {
        let rect = rtl::gdi::Rect::new(0, 0, 200, 100);
        let client = rtl::gdi::Rect::new(10, 10, 190, 90);
        let mut m = Message {
            message: WM_NCCALCSIZE,
            wparam: 0,
            lparam: 0,
            payload: Payload::Rect(rect),
        };
        read_back(FN_INOUTNCCALCSIZE, &mut m, &out(&client.as_bytes()[..12]));
        assert_eq!(m.payload, Payload::Rect(rect), "short");
        read_back(FN_INOUTNCCALCSIZE, &mut m, &out(&[]));
        assert_eq!(m.payload, Payload::Rect(rect), "none");
        let mut long = client.as_bytes().to_vec();
        long.extend_from_slice(&[0xFF; 36]);
        read_back(FN_INOUTNCCALCSIZE, &mut m, &out(&long));
        assert_eq!(
            m.payload,
            Payload::Rect(client),
            "longer: the rectangle alone"
        );

        // The TRUE form wants the whole NCCALCSIZE_PARAMS: a RECT's worth is short.
        let calc = window::CalcSize {
            rects: [rect; 3],
            pos: WindowPos::default(),
        };
        let mut m = Message {
            message: WM_NCCALCSIZE,
            wparam: 1,
            lparam: 0,
            payload: Payload::CalcSize(calc),
        };
        read_back(FN_INOUTNCCALCSIZE, &mut m, &out(client.as_bytes()));
        assert_eq!(m.payload, Payload::CalcSize(calc));

        let pos = WindowPos {
            cx: 220,
            ..WindowPos::default()
        };
        let edited = WindowPos { cx: 250, ..pos };
        let mut m = Message {
            message: WM_WINDOWPOSCHANGED,
            wparam: 0,
            lparam: 0,
            payload: Payload::WindowPos(pos),
        };
        read_back(FN_INLPWINDOWPOS, &mut m, &out(edited.as_bytes()));
        assert_eq!(m.payload, Payload::WindowPos(pos), "input only");
        read_back(FN_INOUTNCCALCSIZE, &mut m, &out(edited.as_bytes()));
        assert_eq!(m.payload, Payload::WindowPos(pos), "another kind's slot");

        // A MINMAXINFO short of its last POINT stays the defaults.
        let defaults = window::MinMaxInfo::unbounded();
        let answered = window::MinMaxInfo {
            min_track: (300, 250),
            ..defaults
        };
        let mut m = Message {
            message: WM_GETMINMAXINFO,
            wparam: 0,
            lparam: 0,
            payload: Payload::MinMax(defaults),
        };
        read_back(
            FN_INOUTLPPOINT5,
            &mut m,
            &out(&answered.raw().as_bytes()[..32]),
        );
        assert_eq!(m.payload, Payload::MinMax(defaults), "MINMAXINFO short");
        read_back(FN_INOUTLPWINDOWPOS, &mut m, &out(answered.raw().as_bytes()));
        assert_eq!(m.payload, Payload::MinMax(defaults), "another slot's");
    }

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

    /// A GUI thread that ended above the passive level leaves its queue, with its client id, to
    /// its process's reap; client ids are reused LIFO, so the id may name another thread first.
    /// PostThreadMessage's look-up takes the queue of the thread the client-id table names by
    /// the id now, never the ended one's, and none when the id names no thread.
    #[test]
    fn a_reused_client_id_finds_the_new_threads_queue() {
        let (m, _) = manager();
        let ended = thread(m, 1, 0x100);
        let new = thread(m, 2, 0x100);
        let key = |index| ThreadKey {
            index,
            generation: 0,
        };
        let found = |named: Option<Option<ThreadKey>>| {
            queue_by_client_id_in(&m.windows, 0x100, |id| {
                assert_eq!(id, 0x100);
                named
            })
        };
        assert_eq!(found(Some(Some(key(2)))), Some((new, key(2))));
        assert_eq!(found(Some(Some(key(1)))), Some((ended, key(1))));
        assert_eq!(found(Some(None)), None, "the id names no thread");
        assert_eq!(found(Some(Some(key(3)))), None, "another thread, no queue");
        assert_eq!(
            queue_by_client_id_in(&m.windows, 0, |_| panic!("no look-up for 0")),
            None
        );
    }

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

    /// A thread record's client id is its queue's (GetWindowThreadProcessId's thread id): none for
    /// the window manager's own record, which serves the desktop's windows and has no queue.
    #[test]
    fn a_window_s_thread_is_its_queue_s_client_id() {
        let (m, atom) = manager();
        let t = thread(m, 1, 0x100);
        let h = popup(m, atom, t);
        let id = m.windows.window_from_handle(h).unwrap();
        assert_eq!(
            client_id_of(&m.windows, m.windows.window_thread(id)),
            Some(0x100)
        );
        let desktop = m.windows.thread_desktop_window(t).unwrap();
        assert_eq!(
            client_id_of(&m.windows, m.windows.window_thread(desktop)),
            None
        );
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

    /// The sent messages in the pool, live.
    fn live_sends(m: &WindowManager) -> usize {
        m.windows.queues.sent.live() as usize
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
        super::super::timer::set(&mut m.windows, t, h, 1, 300, 0, 0).unwrap();
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
        super::super::timer::set(&mut m.windows, t, h, 9, 50, 0, 0).unwrap();
        assert_eq!(queue_status(&mut m.windows, t, 10 * ms, QS_ALLINPUT), 0);
        assert_eq!(
            queue_status(&mut m.windows, t, 150 * ms, QS_ALLINPUT),
            0x0010_0010
        );
        super::super::timer::kill(&mut m.windows, t, h, 9).unwrap();
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

    /// A thread's end, as Windows 2000's thread cleanup: its windows are destroyed (a child of its
    /// window with them, another thread's own window left), its queue ends, and a send waiting on
    /// it — queued, or handed out and not answered — fails its sender (SendMessage 0, 1400) and
    /// goes back to the pool. Later sends to its window find no window. Its record stays, empty,
    /// for its process's end.
    #[test]
    fn a_threads_end_takes_its_windows_and_fails_the_sends_to_it() {
        let (m, atom) = manager();
        let a = thread(m, 1, 0x100);
        let b = thread(m, 2, 0x200);
        let ha = popup(m, atom, a);
        let hb = popup(m, atom, b);
        let child = window_at(m, atom, b, WS_CHILD, hb, 0, 0, 10, 10);
        deliver(m, a);
        deliver(m, b);
        let base = live_sends(m);
        let Ok(Sending::Waiting(handed)) = send(&mut m.windows, a, hb, WM_USER, 1, 0) else {
            panic!("queued");
        };
        let Ok(Sending::Waiting(queued)) = send(&mut m.windows, a, hb, WM_USER, 2, 0) else {
            panic!("queued");
        };
        assert!(matches!(read(m, b, &all(), 0), Taken::Sent(_)));
        m.windows.queues.take_wakes();

        let key = ThreadKey {
            index: 2,
            generation: 0,
        };
        m.end_thread(key);
        assert!(m.windows.window_from_handle(hb).is_none());
        assert!(m.windows.window_from_handle(child).is_none());
        assert!(m.windows.window_from_handle(ha).is_some());
        assert_eq!(m.windows.queues.queue_of(b), None);
        assert!(
            m.windows.queues.take_wakes().contains(a),
            "the sender is woken"
        );
        assert_eq!(await_reply(&mut m.windows, a, handed), Awaited::Failed);
        assert_eq!(await_reply(&mut m.windows, a, queued), Awaited::Failed);
        assert_eq!(live_sends(m), base);
        assert_eq!(
            send(&mut m.windows, a, hb, WM_USER, 3, 0),
            Err(STATUS_INVALID_HANDLE)
        );
        assert!(m.windows.thread(b).live && m.windows.thread(b).window_count == 0);
        m.end_thread(key);

        // A timed-out send abandoned once its receiver ended goes back to the pool too.
        let c = thread(m, 3, 0x300);
        let hc = popup(m, atom, c);
        deliver(m, c);
        let Ok(Sending::Waiting(id)) = send(&mut m.windows, a, hc, WM_USER, 4, 0) else {
            panic!("queued");
        };
        detach(&mut m.windows, c);
        abandon_send(&mut m.windows, a, id);
        assert_eq!(live_sends(m), base);
    }

    /// A process's end ends its threads' queues with their records: a send waiting on one of them
    /// fails.
    #[test]
    fn a_processs_end_ends_its_queues() {
        let (m, atom) = manager();
        register(m, OTHER_OWNER);
        let a = thread(m, 1, 0x100);
        let b = thread_of(m, 2, 0x200, OTHER_OWNER);
        let hb = popup(m, atom, b);
        deliver(m, b);
        let Ok(Sending::Waiting(id)) = send(&mut m.windows, a, hb, WM_USER, 1, 0) else {
            panic!("queued");
        };
        m.end_process(OTHER_OWNER);
        assert_eq!(m.windows.queues.queue_of(b), None);
        assert!(m.windows.window_from_handle(hb).is_none());
        assert_eq!(await_reply(&mut m.windows, a, id), Awaited::Failed);
        assert!(m.windows.queues.queue_of(a).is_some());
    }

    /// A thread whose queue ends while it waits on sends, nested inside one another's delivery,
    /// leaves every one of them answered to nobody.
    #[test]
    fn a_waiting_threads_end_leaves_its_sends_to_nobody() {
        let (m, atom) = manager();
        let a = thread(m, 1, 0x100);
        let b = thread(m, 2, 0x200);
        let hb = popup(m, atom, b);
        deliver(m, b);
        let base = live_sends(m);
        let Ok(Sending::Waiting(outer)) = send(&mut m.windows, a, hb, WM_USER, 1, 0) else {
            panic!("queued");
        };
        let Ok(Sending::Waiting(inner)) = send(&mut m.windows, a, hb, WM_USER, 2, 0) else {
            panic!("queued");
        };
        assert!(matches!(read(m, b, &all(), 0), Taken::Sent(_)));
        detach(&mut m.windows, a);
        assert!(end_sent(&mut m.windows, b, 1));
        assert_eq!(collect_reply(&mut m.windows, a, outer), None);
        assert_eq!(collect_reply(&mut m.windows, a, inner), None);
        assert_eq!(
            deliver(m, b),
            vec![(hb, WM_USER)],
            "the inner one still reaches B"
        );
        assert_eq!(live_sends(m), base);
    }

    /// A decision's message to another thread's window with an in-out structure.
    fn decision_message(message: u32, wparam: WParam, payload: Payload) -> Message {
        Message {
            message,
            wparam,
            lparam: 0,
            payload,
        }
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
