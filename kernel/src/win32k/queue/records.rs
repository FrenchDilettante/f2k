//! The queues' records: the queue, the posted and sent messages, their ids and pools, and the
//! wake set.

use rtl::user::{
    Msg,
    Point,
    StyleStruct,
    QS_HOTKEY,
    QS_INPUT,
    QS_PAINT,
    QS_POSTMESSAGE,
    QS_SENDMESSAGE,
    QS_TIMER,
    WM_NCCREATE,
    WM_QUERYENDSESSION,
};

use super::*;
#[cfg(test)]
use crate::sched::thread::ThreadId;
use crate::slots::{self, Codec, Match, Record, Reuse, Slots};
use crate::win32k::text::Text;
use crate::win32k::window::{self, Hwnd, LParam, LResult, Payload, ThreadKey, WParam, WindowId};

/// How many messages posted to a thread its queue holds at once: Windows 2000's
/// USERPostMessageLimit, 10,000 by default. A post past it fails (guimsg `quota`), the input
/// messages aside, which it does not count.
pub const POSTED_LIMIT: u32 = 10_000;
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
    pub(super) const NONE: Wakes = Wakes {
        queues: [0; WAKE_LIST],
        count: 0,
        every: false,
    };

    /// Add the queue of the thread record `index`.
    pub(super) fn add(&mut self, index: u16) {
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
    pub(super) fn each(&self, made: usize) -> impl Iterator<Item = u16> + '_ {
        let every = self.every.then_some(0..made as u16).into_iter().flatten();
        let listed = (!self.every).then(|| self.listed().iter().copied());
        every.chain(listed.into_iter().flatten())
    }
}

/// The host builds have no queue events: the host tests wait on nothing.
#[cfg(not(target_arch = "x86"))]
pub(super) fn make_event(_: u16) -> bool {
    true
}

/// The queues to a chunk of their table: a page's worth.
pub(super) const QUEUES_PER_CHUNK: usize = slots::entries_per_page::<Queue>();

/// Every kind of message a read takes when its caller names none.
pub(super) const ALL_KINDS: u32 =
    QS_INPUT | QS_POSTMESSAGE | QS_TIMER | QS_PAINT | QS_SENDMESSAGE | QS_HOTKEY;

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
    pub(super) index: u16,
    pub(super) generation: u16,
}

/// A sent message's id: its slot in the sent messages' pool and the slot's uniqueness count
/// ([`SentToken`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SentId {
    pub(super) index: u16,
    pub(super) generation: u16,
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
pub(super) struct SentPool(pub(super) Slots<Sent, SentToken, SENT_PER>);

impl SentPool {
    pub(super) const EMPTY: Self = SentPool(Slots::new());

    /// The live sent message `id` names; none for a stale or forged id.
    pub(super) fn get(&self, id: SentId) -> Option<&Sent> {
        self.0.get(id)
    }

    /// The live sent message a list links to.
    pub(super) fn at(&self, id: SentId) -> &Sent {
        self.0.get(id).expect("a linked sent message is live")
    }

    /// [`SentPool::at`], to change.
    pub(super) fn at_mut(&mut self, id: SentId) -> &mut Sent {
        self.0.get_mut(id).expect("a linked sent message is live")
    }

    /// `record` in a fresh slot, the pool grown by a page when it needs one: its id; none when no
    /// page can be had, or 32,768 sends are on their way.
    pub(super) fn allocate(&mut self, record: Sent) -> Option<SentId> {
        let (id, slot) = self.0.allocate_or_grow(0, &PAGES).ok()?;
        *slot = record;
        Some(id)
    }

    /// Free the live sent message `id`: its id names nothing after.
    pub(super) fn free(&mut self, id: SentId) {
        let freed = self.0.free(id);
        debug_assert!(freed, "a live sent message freed");
    }

    /// The live sent messages' ids, in slot order, one at a time: none of the pool borrowed
    /// between them, so a record can be freed on the way.
    pub(super) fn next_live(&self, from: u32) -> Option<(u32, SentId)> {
        (from..self.0.high_water()).find_map(|index| Some((index, self.0.id_at(index)?)))
    }

    /// How many sent messages are live.
    #[cfg(test)]
    pub(super) fn live(&self) -> u32 {
        self.0.live()
    }
}

/// A singly linked list of sent messages, oldest first.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct List {
    pub(super) head: Option<SentId>,
    pub(super) tail: Option<SentId>,
}

impl List {
    const EMPTY: Self = List {
        head: None,
        tail: None,
    };
}

/// A queue's list of entries from the posted messages' pool, oldest first, and how many it holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct PostedList {
    pub(super) head: Option<u32>,
    pub(super) tail: Option<u32>,
    pub(super) count: u32,
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
pub(super) struct Queue {
    pub(super) live: bool,
    pub(super) generation: u16,
    /// The thread it serves.
    pub(super) key: Option<ThreadKey>,
    /// The thread's client id, as PostThreadMessage names it.
    pub(super) client_id: u32,
    /// The posted messages, oldest first.
    pub(super) posted: PostedList,
    /// The input messages, oldest first.
    pub(super) input: PostedList,
    /// The sent messages not handed out yet, oldest first.
    pub(super) sent: List,
    /// The sent messages handed out and not answered yet, innermost first.
    pub(super) receiving: Option<SentId>,
    /// PostQuitMessage's exit code, until a read takes the WM_QUIT.
    pub(super) quit: Option<u32>,
    /// The kinds of message (queue-status bits) given the queue since a read last looked for them:
    /// Windows 2000's change bits, what WaitMessage wakes on.
    pub(super) changed: u32,
    /// When the thread last read its queue (milliseconds, MSG's clock).
    pub(super) last_read: u32,
    /// The thread's last read found nothing, or it waits: it idles, waiting for input, and is
    /// never deemed hung.
    pub(super) idle: bool,
    /// The time and the cursor position of the last message a read retrieved (GetMessageTime,
    /// GetMessagePos).
    pub(super) message_time: u32,
    pub(super) message_pos: Point,
    /// The last button press a read took out, for the next one's double-click
    /// ([`crate::win32k::mouse::Click`]).
    pub(super) click: Option<crate::win32k::mouse::Click>,
    /// ShowCursor's display count ([`show_cursor`]).
    pub(super) cursor_level: i32,
}

// SAFETY: writes a whole record.
unsafe impl Record for Queue {
    unsafe fn write_fresh(at: *mut Self, _: u32) {
        // SAFETY: the caller's contract.
        unsafe { at.write(Queue::EMPTY) };
    }
}

impl Queue {
    pub(super) const EMPTY: Self = Queue {
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
pub(super) struct Posted {
    pub(super) msg: Msg,
    /// An input message's key, as the key state names it (the side's key for Shift, Ctrl and Alt,
    /// where the message names the generic one; a mouse button's key for its message, 0 for a
    /// move); 0 for a message posted to the thread.
    pub(super) key: u8,
    /// What a read learned of a mouse message's window ([`crate::win32k::mouse::Prepared`]).
    pub(super) prepared: Option<crate::win32k::mouse::Prepared>,
    pub(super) next: Option<u32>,
}

/// The two lanes of a queue's entries from the posted messages' pool.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Lane {
    /// The messages posted to the thread or its windows.
    Posted,
    /// The input messages the keyboard's keystrokes became.
    Input,
}

/// Where a sent message is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum State {
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
pub(super) enum Carried {
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
    pub(super) fn of(payload: &Payload) -> Option<Carried> {
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
    pub(super) fn payload(&self) -> Option<Payload> {
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
pub(super) struct Callback {
    pub(super) proc: u32,
    pub(super) data: u32,
    pub(super) sender: QueueId,
}

/// A sent message.
#[derive(Clone, Copy)]
pub(super) struct Sent {
    pub(super) receiver: Option<QueueId>,
    /// The thread waiting for the answer; none for a message the window manager or the server
    /// sent.
    pub(super) sender: Option<QueueId>,
    /// The console server waits for the answer (the session's end, on its control thread, which
    /// has no queue: see [`server_send`]).
    pub(super) server: bool,
    /// SendNotifyMessage's: another thread sent it and waits for no answer.
    pub(super) notify: bool,
    /// The answer to a SendMessageCallback, on its way to the sender's callback: delivered as a
    /// sent message whose procedure is the callback, its wParam the caller's data and its lParam
    /// the answer, as Windows 2000's SMF_CB_REPLY reaches CallClientProc.
    pub(super) reply: bool,
    pub(super) window: Option<WindowId>,
    pub(super) hwnd: Hwnd,
    pub(super) proc: u32,
    pub(super) message: u32,
    pub(super) wparam: WParam,
    pub(super) lparam: LParam,
    pub(super) carried: Carried,
    pub(super) state: State,
    pub(super) result: LResult,
    /// The next one on the receiver's list or receiving stack.
    pub(super) next: Option<SentId>,
}

impl Sent {
    pub(super) const EMPTY: Self = Sent {
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
    pub(super) fn is_callback(&self) -> bool {
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
