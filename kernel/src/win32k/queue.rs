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
//! procedure changes in the structure it was handed (WM_NCCALCSIZE's rectangle) does not come back
//! yet. A message to another thread's window is queued for that thread as a sent message, and the
//! decision goes on with the default procedure's answer (1 to WM_NCCREATE, 0 to the rest): the
//! thread's next read hands it out first, before anything posted, with the procedure to call and a
//! copy of the structure the message points at ([`rtl::user::Receipt`]); user32 calls the
//! procedure and hands the answer back ([`end_sent`]), which nobody waits for.
//!
//! SendMessage to another thread's window is queued the same way, its sender waiting for the answer
//! ([`send`], [`await_reply`]) and, as Windows 2000's sender does, handling the messages sent to
//! its own thread meanwhile: the wait hands them to user32, which delivers them and resumes it
//! ([`resume_send`]), so two threads that send to each other do not wait on each other; to a
//! window of its own thread, the service names the procedure and user32 calls it itself, as
//! Windows 2000's user32 does. So do the console server's
//! WM_QUERYENDSESSION and WM_ENDSESSION at the session's end ([`server_send`]), the server, which
//! has no queue, waiting on an event of its own ([`wait_for_server`]). SendMessageTimeout's
//! sender waits no longer than its timeout, a message its receiver has not read by then taken back
//! ([`abandon_send`]); SendNotifyMessage's waits for nothing, its message answered to nobody
//! ([`send_notify`]).
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
//!   message the filter takes, waiting for one, into the receipt;
//! - NtUserPeekMessage(ptr Receipt, handle Window, u32 MsgFilterMin, u32 MsgFilterMax, u32
//!   RemoveMsg): the same without waiting (RECEIVED_NONE when there is nothing);
//! - NtUserMessageCall(handle Window, u32 Msg, u32 wParam, i32 lParam, ptr<u32> Proc, ptr<i32>
//!   Result, ptr Timeout): SendMessage and SendMessageTimeout (rtl::user::SendTimeout; null for
//!   SendMessage): the procedure to call for a window of the caller's own thread, or the answer,
//!   STATUS_TIMEOUT for none in time;
//! - NtUserSendNotifyMessage(handle Window, u32 Msg, u32 wParam, i32 lParam, ptr<u32> Proc):
//!   SendNotifyMessage: the procedure to call for a window of the caller's own thread, or 0;
//! - NtUserWaitMessage(): WaitMessage;
//! - NtUserDispatchMessage(ptr Msg, ptr<u32> Proc): the procedure DispatchMessage calls;
//! - NtUserCallOneParam(u32 Param, u32 Routine, ptr<u32> Result): PostQuitMessage, ReplyMessage,
//!   IsHungAppWindow, and the end of a sent message's delivery ([`rtl::user`]'s ONE_PARAM_*
//!   routines).

use core::mem::{offset_of, size_of};

use rtl::callback::{
    CallbackMsg,
    FN_DWORD,
    FN_INLPCREATESTRUCT,
    FN_INLPWINDOWPOS,
    FN_INOUTNCCALCSIZE,
    FN_INOUTSTYLECHANGE,
    FN_NCDESTROY,
};
use rtl::pod::Pod;
use rtl::user::{
    sync_only,
    CreateStructW,
    Msg,
    Point,
    Receipt,
    ReceiptHead,
    StyleStruct,
    HWND_BROADCAST,
    NO_TEXT,
    QS_ALLINPUT,
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
    RECEIVED_SENT,
    WM_COPYDATA,
    WM_GETTEXT,
    WM_KEYFIRST,
    WM_KEYLAST,
    WM_MOUSEFIRST,
    WM_MOUSELAST,
    WM_NCCREATE,
    WM_NCDESTROY,
    WM_PAINT,
    WM_QUERYENDSESSION,
    WM_QUIT,
    WM_SETTEXT,
    WM_SYSTIMER,
    WM_TIMER,
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
    Windows,
    THREADS,
};
use crate::sched::thread::ThreadId;
use crate::status::*;

/// How many messages posted to a thread its queue holds at once: Windows 2000's
/// USERPostMessageLimit, 10,000 by default. A post past it fails (guimsg `quota`), the input
/// messages aside, which it does not count.
pub const POSTED_LIMIT: u32 = 10_000;
// ERROR_NOT_ENOUGH_QUOTA: the post past [`POSTED_LIMIT`]'s refusal, as win32k carries it.
use rtl::winerror::{ERROR_INVALID_THREAD_ID, ERROR_MESSAGE_SYNC_ONLY, ERROR_NOT_ENOUGH_QUOTA};
/// How many sent messages can be on their way at once.
pub const SENT: usize = 128;

/// The words of the wake set: a bit a queue.
const WAKE_WORDS: usize = THREADS.div_ceil(32);

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

/// A sent message's id: its record and the record's generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SentId {
    index: u16,
    generation: u16,
}

impl SentId {
    /// The id as user32 holds it while its sender delivers the messages sent to it
    /// ([`Awaited::Received`]): the generation in the high word, the record in the low one, with
    /// the low word's top bit set, so that no id is 0 (SendTimeout's `resume` for a fresh send).
    pub fn token(self) -> u32 {
        (self.generation as u32) << 16 | 0x8000 | self.index as u32
    }

    /// The id a [`SentId::token`] names; none for 0 or a token naming no record.
    pub fn from_token(token: u32) -> Option<SentId> {
        let index = token as u16 & !0x8000;
        (token & 0x8000 != 0 && (index as usize) < SENT).then_some(SentId {
            index,
            generation: (token >> 16) as u16,
        })
    }
}

/// A singly linked list of pool entries, oldest first.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct List {
    head: Option<u16>,
    tail: Option<u16>,
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
    receiving: Option<u16>,
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
    };
}

/// A posted message: the MSG a read hands out, and the link to the next one.
#[derive(Clone, Copy)]
struct Posted {
    msg: Msg,
    /// An input message's key, as the key state names it (the side's key for Shift, Ctrl and Alt,
    /// where the message names the generic one); 0 for a message posted to the thread.
    key: u8,
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
    /// Answered: the sender collects the answer.
    Answered,
    /// Never answered: its window or its receiver's queue went first (for a thread's send, its
    /// receiver's queue alone: a window gone is answered 0). Only a send the server or a thread
    /// waits on stays in this state, for its sender to collect ([`server_reply`],
    /// [`await_reply`]).
    Dropped,
}

/// The structure a sent message's lParam points at, carried with it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Carried {
    None,
    /// WM_NCCALCSIZE's rectangle.
    Rect(rtl::gdi::Rect),
    /// WM_WINDOWPOSCHANGING's and WM_WINDOWPOSCHANGED's WINDOWPOS.
    WindowPos(window::WindowPos),
    /// WM_STYLECHANGING's and WM_STYLECHANGED's STYLESTRUCT.
    Style(StyleStruct),
    /// WM_SETTEXT's text, or WM_GETTEXT's answer, sent to another process's window.
    Text(CarriedText),
}

/// A text a message to another process's window carries, as long as it is: WM_SETTEXT's, read
/// from the sender, or WM_GETTEXT's, read back from the receiver's buffer once its procedure
/// answers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CarriedText {
    /// The text, a block of the queues' store ([`Queues::store`]).
    text: Text,
    /// Where WM_GETTEXT's receiver put its buffer, and its units ([`received_text`]), 0 before.
    buffer: u32,
    room: u32,
}

/// A sent message.
#[derive(Clone, Copy)]
struct Sent {
    live: bool,
    generation: u16,
    receiver: Option<QueueId>,
    /// The thread waiting for the answer; none for a message the window manager or the server
    /// sent.
    sender: Option<QueueId>,
    /// The console server waits for the answer (the session's end, on its control thread, which
    /// has no queue: see [`server_send`]).
    server: bool,
    /// SendNotifyMessage's: another thread sent it and waits for no answer.
    notify: bool,
    /// SendMessageTimeout's: when its sender stops waiting (interrupt time), kept for the wait's
    /// resumption after the sender delivered the messages sent to it meanwhile.
    deadline: Option<u64>,
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
    next: Option<u16>,
}

impl Sent {
    const EMPTY: Self = Sent {
        live: false,
        generation: 0,
        receiver: None,
        sender: None,
        server: false,
        notify: false,
        deadline: None,
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
}

/// The queues, the pools their messages come from, the timers ([`super::timer`]) and the windows'
/// update regions ([`super::paint`]): the message layer's state, in the window registry, behind the
/// window manager's lock.
pub struct Queues {
    queues: [Queue; THREADS],
    posted: super::posted::Pool<Posted>,
    sent: [Sent; SENT],
    /// The texts the sent messages carry: a text to another process's window.
    store: Texts,
    pub timers: super::timer::Timers,
    pub updates: super::paint::Updates,
    /// The queues something was given since the last [`Queues::take_wakes`]: their events are set
    /// once the lock is let go.
    wakes: [u32; WAKE_WORDS],
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
            let records = addr_of_mut!((*queues).queues) as *mut Queue;
            for index in 0..THREADS {
                records.add(index).write(Queue::EMPTY);
            }
            addr_of_mut!((*queues).posted).write(super::posted::Pool::EMPTY);
            let sent = addr_of_mut!((*queues).sent) as *mut Sent;
            for index in 0..SENT {
                sent.add(index).write(Sent::EMPTY);
            }
            addr_of_mut!((*queues).store).write(Texts::EMPTY);
            super::timer::Timers::write_empty(addr_of_mut!((*queues).timers));
            super::paint::Updates::write_empty(addr_of_mut!((*queues).updates));
            addr_of_mut!((*queues).wakes).write([0; WAKE_WORDS]);
            addr_of_mut!((*queues).server_wake).write(false);
        }
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
        self.wakes[id.index as usize / 32] |= 1 << (id.index % 32);
    }

    /// The queue was given something of the kinds `changed`: marked for WaitMessage, and woken.
    fn change(&mut self, id: QueueId, changed: u32) {
        self.queues[id.index as usize].changed |= changed;
        self.wake(id);
    }

    /// The queues to wake, as a bit a thread record, the set emptied.
    pub fn take_wakes(&mut self) -> [u32; WAKE_WORDS] {
        core::mem::replace(&mut self.wakes, [0; WAKE_WORDS])
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
            Lane::Posted => QS_POSTMESSAGE,
            Lane::Input => QS_KEY,
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
        let sent = &self.sent[id.index as usize];
        (sent.live && sent.generation == id.generation).then_some(sent)
    }

    /// A fresh sent message from the pool; none when it is exhausted.
    fn allocate_sent(&mut self, record: Sent) -> Option<SentId> {
        let index = self.sent.iter().position(|s| !s.live)?;
        let generation = self.sent[index].generation;
        self.sent[index] = Sent {
            live: true,
            generation,
            ..record
        };
        Some(SentId {
            index: index as u16,
            generation,
        })
    }

    /// Give the sent message at `index` back to the pool, the text it carries with it.
    fn free_sent(&mut self, index: u16) {
        if let Carried::Text(carried) = self.sent[index as usize].carried {
            self.store.free(carried.text);
        }
        let generation = self.sent[index as usize].generation.wrapping_add(1);
        self.sent[index as usize] = Sent {
            generation,
            ..Sent::EMPTY
        };
    }

    /// Append the sent message at `index` to its receiver's list, and wake the receiver.
    fn push_sent(&mut self, receiver: QueueId, index: u16) {
        let queue = &mut self.queues[receiver.index as usize];
        match queue.sent.tail {
            Some(tail) => self.sent[tail as usize].next = Some(index),
            None => queue.sent.head = Some(index),
        }
        queue.sent.tail = Some(index);
        self.change(receiver, QS_SENDMESSAGE);
    }

    /// Answer the sent message at `index` with `result`: its sender, if it still waits, or the
    /// server, collects the answer; one nobody waits on goes back to the pool.
    fn answer(&mut self, index: u16, result: LResult) {
        let sent = &mut self.sent[index as usize];
        sent.next = None;
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
            _ => self.free_sent(index),
        }
    }

    /// The sent message at `index` will never be answered (its window or its receiver's queue
    /// went): a send the server waits on is dropped, for the server to see, as no answer of the
    /// window's; any other is answered 0, what SendMessage gives back then.
    fn drop_unanswered(&mut self, index: u16) {
        let sent = &mut self.sent[index as usize];
        if sent.server {
            sent.next = None;
            sent.state = State::Dropped;
            self.server_wake = true;
        } else {
            self.answer(index, 0);
        }
    }

    /// The sent message at `index` will never be answered: its receiver's queue ended, its thread
    /// gone. A send the server or a thread waits on is dropped, for the sender to see — the
    /// thread's SendMessage then fails, as Windows 2000's fails when its receiver dies; one nobody
    /// waits on goes back to the pool.
    fn receiver_gone(&mut self, index: u16) {
        let sent = &mut self.sent[index as usize];
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
            _ => self.free_sent(index),
        }
    }

    /// Take the sent message at `index` off its receiver's list, where it waits to be handed out.
    fn unlink_sent(&mut self, receiver: QueueId, index: u16) {
        let mut previous = None;
        let mut at = self.queues[receiver.index as usize].sent.head;
        while let Some(entry) = at {
            let next = self.sent[entry as usize].next;
            if entry == index {
                let list = &mut self.queues[receiver.index as usize].sent;
                match previous {
                    Some(p) => self.sent[p as usize].next = next,
                    None => list.head = next,
                }
                if list.tail == Some(entry) {
                    list.tail = previous;
                }
                self.sent[entry as usize].next = None;
                return;
            }
            previous = Some(entry);
            at = next;
        }
    }

    /// The queue's next sent message, taken off its list; none when there is none.
    fn pop_sent(&mut self, id: QueueId) -> Option<u16> {
        let queue = &mut self.queues[id.index as usize];
        let index = queue.sent.head?;
        queue.sent.head = self.sent[index as usize].next;
        if queue.sent.head.is_none() {
            queue.sent.tail = None;
        }
        self.sent[index as usize].next = None;
        Some(index)
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
            self.queues[index as usize].receiving = self.sent[sent as usize].next;
            if self.sent[sent as usize].state == State::Received {
                self.receiver_gone(sent);
            } else {
                self.sent[sent as usize].next = None;
            }
        }
        // The sends it waits on, the innermost and the ones it delivered messages inside: their
        // answers go to nobody.
        for at in 0..SENT as u16 {
            let sent = &mut self.sent[at as usize];
            if sent.live && sent.sender == Some(id) {
                sent.sender = None;
                if sent.state == State::Answered {
                    self.free_sent(at);
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
/// thread it serves.
pub fn queue_by_client_id(windows: &Windows, client_id: u32) -> Option<(ThreadId, ThreadKey)> {
    windows
        .queues
        .queues
        .iter()
        .enumerate()
        .find(|(_, q)| q.live && q.client_id == client_id && client_id != 0)
        .and_then(|(index, q)| Some((ThreadId(index as u16), q.key?)))
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

/// PostQuitMessage: the caller's next read that finds nothing posted before it makes a WM_QUIT
/// with the exit code `code`.
pub fn post_quit(windows: &mut Windows, caller: ThreadId, code: u32) {
    let queues = &mut windows.queues;
    if let Some(id) = queues.queue_of(caller) {
        queues.queues[id.index as usize].quit = Some(code);
        queues.change(id, QS_POSTMESSAGE);
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
    /// messages and the kinds whose messages the range holds.
    pub fn wake_mask(&self) -> u32 {
        if self.min == 0 && self.max == 0 {
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
    /// A sent message, handed out: its receipt is written from the record ([`receipt_head`]), its
    /// answer comes back with [`end_sent`].
    Sent(SentId),
    /// A posted message, or one the queue made (WM_QUIT, WM_PAINT, WM_TIMER).
    Message(Msg),
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
    if let Taken::Message(msg) = taken {
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

    // The sent messages: a message another thread or the server sent to a window destroyed since
    // is answered 0 (dropped, for the server) and skipped (the window manager's own sends are
    // delivered whatever became of the window).
    while let Some(index) = windows.queues.pop_sent(id) {
        let sent = windows.queues.sent[index as usize];
        let window_gone = sent.window.is_none_or(|w| !windows.is_live(w));
        if (sent.sender.is_some() || sent.server || sent.notify) && window_gone {
            windows.queues.drop_unanswered(index);
            continue;
        }
        let queues = &mut windows.queues;
        queues.sent[index as usize].state = State::Received;
        queues.sent[index as usize].next = queues.queues[id.index as usize].receiving;
        queues.queues[id.index as usize].receiving = Some(index);
        return Ok(Taken::Sent(SentId {
            index,
            generation: sent.generation,
        }));
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

    // The input messages: the keyboard's (there is no mouse yet), each bound to its window as it
    // is read (the thread's focus window now, or its active window), so the filter judges the
    // bound window and message. A key message taken out is the next step of the thread's key
    // state; one with no window to go to is discarded, still a step of the key state, so that no
    // key stays down for the thread.
    if filter.looks_at(QS_KEY) {
        let mut previous = None;
        let mut at = windows.queues.queues[id.index as usize].input.head;
        while let Some(entry) = at {
            let Posted { msg, key, next } = *windows.queues.posted.get(entry);
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
    let Some(id) = windows.queues.queue_of(caller) else {
        return Waited::Ready;
    };
    if windows.queues.timers.expire(caller, now) {
        windows.queues.queues[id.index as usize].changed |= QS_TIMER;
    }
    let queue = &mut windows.queues.queues[id.index as usize];
    queue.idle = true;
    if queue.changed & mask & QS_ALLINPUT != 0 {
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

// --- The receipt of a sent message ---------------------------------------------------------------

/// The receipt's head for the sent message `id` handed out to `caller` (none when it is not one
/// of `caller`'s, or gone), the receipt at `receipt` in the caller's memory: the procedure, and the
/// message, its lParam pointing at the receipt's copy of the structure it carries.
pub fn receipt_head(
    windows: &Windows,
    caller: ThreadId,
    id: SentId,
    receipt: u32,
    time: u32,
) -> Option<ReceiptHead> {
    let sent = windows.queues.sent_at(id)?;
    if sent.receiver.map(|r| r.index) != Some(caller.0) {
        return None;
    }
    let lparam = match sent.carried {
        Carried::None => sent.lparam,
        Carried::Rect(_) => receipt.wrapping_add(offset_of!(Receipt, rect) as u32) as LParam,
        Carried::WindowPos(_) => {
            receipt.wrapping_add(offset_of!(Receipt, window_pos) as u32) as LParam
        }
        Carried::Style(_) => receipt.wrapping_add(offset_of!(Receipt, style) as u32) as LParam,
        // The receiver points it at a buffer of its own ([`received_text`]).
        Carried::Text(_) => 0,
    };
    Some(ReceiptHead {
        kind: RECEIVED_SENT,
        proc: sent.proc,
        msg: made(sent.hwnd, sent.message, sent.wparam, lparam, time),
    })
}

/// The length of the text the sent message `id` carries (the receipt's `text`): a text message's
/// to another process (WM_GETTEXT's empty); NO_TEXT for none.
pub fn receipt_text(windows: &Windows, id: SentId) -> u32 {
    let queues = &windows.queues;
    match queues.sent_at(id).map(|sent| sent.carried) {
        Some(Carried::Text(carried)) => carried.text.len() as u32,
        _ => NO_TEXT,
    }
}

/// The text the caller's innermost sent message carries ([`receipt_text`]'s), its receiver's
/// buffer at `at` holding `room` units: WM_GETTEXT's buffer kept for its answer
/// ([`text_reply_buffer`]). None when the caller delivers no message that carries a text.
pub fn received_text(
    windows: &mut Windows,
    caller: ThreadId,
    at: u32,
    room: u32,
) -> Option<&[u16]> {
    let queues = &mut windows.queues;
    let index = queues.queues[queues.queue_of(caller)?.index as usize].receiving?;
    let sent = &mut queues.sent[index as usize];
    let text = match &mut sent.carried {
        Carried::Text(carried) => {
            if sent.message == WM_GETTEXT {
                carried.buffer = at;
                carried.room = room;
            }
            carried.text
        }
        _ => return None,
    };
    Some(queues.store.units(text))
}

/// The caller's innermost sent message, when it is WM_GETTEXT from another process whose
/// receiver was handed its buffer: where its procedure wrote the text, and how many units it may
/// hold (wParam's, as many as the buffer has).
pub fn text_reply_buffer(windows: &Windows, caller: ThreadId) -> Option<(u32, usize)> {
    let queues = &windows.queues;
    let index = queues.queues[queues.queue_of(caller)?.index as usize].receiving?;
    let sent = &queues.sent[index as usize];
    match (sent.carried, sent.message) {
        (Carried::Text(carried), WM_GETTEXT) if carried.buffer != 0 => Some((
            carried.buffer,
            (sent.wparam as usize).min(carried.room as usize),
        )),
        _ => None,
    }
}

/// WM_GETTEXT's answer `units`, read back from the receiver's buffer, kept with the caller's
/// innermost sent message for its sender ([`answered_text`]); with no room in the store, an empty
/// answer.
pub fn keep_text_reply(windows: &mut Windows, caller: ThreadId, units: &[u16]) {
    let queues = &mut windows.queues;
    let Some(queue) = queues.queue_of(caller) else {
        return;
    };
    let Some(index) = queues.queues[queue.index as usize].receiving else {
        return;
    };
    let sent = &mut queues.sent[index as usize];
    if let (Carried::Text(carried), WM_GETTEXT) = (&mut sent.carried, sent.message) {
        if !queues.store.replace(&mut carried.text, units) {
            queues.store.free(carried.text);
            carried.text = Text::EMPTY;
        }
    }
}

/// WM_GETTEXT's text, once the caller's send `id` to another process is answered; none for
/// another send, or one not answered yet.
pub fn answered_text(windows: &Windows, id: SentId) -> Option<&[u16]> {
    let sent = windows.queues.sent_at(id)?;
    match (sent.carried, sent.message, sent.state) {
        (Carried::Text(carried), WM_GETTEXT, State::Answered) => {
            Some(windows.queues.store.units(carried.text))
        }
        _ => None,
    }
}

/// The STYLESTRUCT the sent message `id` carries, when it carries one.
pub fn receipt_style(windows: &Windows, id: SentId) -> Option<StyleStruct> {
    match windows.queues.sent_at(id)?.carried {
        Carried::Style(style) => Some(style),
        _ => None,
    }
}

/// The WINDOWPOS the sent message `id` carries, when it carries one (WM_WINDOWPOSCHANGING,
/// WM_WINDOWPOSCHANGED).
pub fn receipt_window_pos(windows: &Windows, id: SentId) -> Option<window::WindowPos> {
    match windows.queues.sent_at(id)?.carried {
        Carried::WindowPos(pos) => Some(pos),
        _ => None,
    }
}

/// The rectangle the sent message `id` carries, when it carries one.
pub fn receipt_rect(windows: &Windows, id: SentId) -> Option<rtl::gdi::Rect> {
    match windows.queues.sent_at(id)?.carried {
        Carried::Rect(r) => Some(r),
        _ => None,
    }
}

// --- Answering -----------------------------------------------------------------------------------

/// The end of the caller's innermost sent message's delivery, its procedure's answer `result`:
/// handed to its sender unless ReplyMessage answered already. False when the caller was delivering
/// none.
pub fn end_sent(windows: &mut Windows, caller: ThreadId, result: LResult) -> bool {
    let queues = &mut windows.queues;
    let Some(id) = queues.queue_of(caller) else {
        return false;
    };
    let Some(index) = queues.queues[id.index as usize].receiving else {
        return false;
    };
    queues.queues[id.index as usize].receiving = queues.sent[index as usize].next;
    let Sent {
        message, window, ..
    } = queues.sent[index as usize];
    if queues.sent[index as usize].state == State::Received {
        queues.answer(index, result);
    } else {
        // ReplyMessage answered it: the sender collects that answer.
        queues.sent[index as usize].next = None;
    }
    if let (WM_NCDESTROY, Some(window)) = (message, window) {
        super::caret::ncdestroy_delivered(windows, caller, window);
    }
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
    let sent = &mut queues.sent[index as usize];
    if (sent.sender.is_none() && !sent.server) || sent.state != State::Received {
        return false;
    }
    let sender = sent.sender;
    sent.state = State::Answered;
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
    let sent = &queues.sent[index as usize];
    sent.sender.is_some() || sent.server || sent.notify
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
/// STATUS_NO_MEMORY when the sent messages' pool is full. (The service sends through
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

/// [`send`], WM_SETTEXT's `text` (wide, read from the sender) or WM_GETTEXT's answer carried
/// through the window manager when `text` is some ([`carries_text`]), as long as it is, in the
/// queues' store: the receiver asks for it into a buffer of its own ([`received_text`]),
/// WM_GETTEXT's of wParam's units.
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
        Some(text) => Carried::Text(CarriedText {
            text: queues.store.store(text).ok_or(STATUS_NO_MEMORY)?,
            buffer: 0,
            room: 0,
        }),
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
        if let Carried::Text(carried) = carried {
            queues.store.free(carried.text);
        }
        return Err(STATUS_NO_MEMORY);
    };
    queues.push_sent(receiver, id.index);
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
/// when the sent messages' pool is full.
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
    queues.push_sent(receiver, id.index);
    Ok(Sending::Answered(0))
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
            queues.unlink_sent(receiver, id.index);
            queues.free_sent(id.index);
        }
        (State::Answered | State::Dropped, _) => queues.free_sent(id.index),
        _ => queues.sent[id.index as usize].sender = None,
    }
}

/// The answer to the caller's send `id`, once its receiver gave it (the record goes back to the
/// pool); none while it waits.
pub fn collect_reply(windows: &mut Windows, caller: ThreadId, id: SentId) -> Option<LResult> {
    let queues = &mut windows.queues;
    let sent = queues.sent_at(id)?;
    if sent.state != State::Answered || sent.sender != queues.queue_of(caller) {
        return None;
    }
    let result = sent.result;
    queues.free_sent(id.index);
    Some(result)
}

/// What a sender found as it waits for the answer to its send ([`await_reply`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Awaited {
    /// The answer: the record went back to the pool.
    Answer(LResult),
    /// Messages were sent to the sender meanwhile: it delivers them (user32 reads them, as
    /// Windows 2000's SendMessage handles the messages sent to its thread while it waits), then
    /// waits on.
    Received,
    /// Nothing yet: the sender waits on its queue.
    Wait,
    /// Never to be answered: the receiving thread ended first, its windows gone with it. The
    /// record went back to the pool; SendMessage fails (Windows 2000's fails when its receiver
    /// dies).
    Failed,
}

/// The caller's wait for the answer to its send `id`, one look: the answer once it came
/// ([`collect_reply`]); otherwise whether messages sent to the caller wait to be handed out, as
/// Windows 2000's sender handles them inside its SendMessage, so that two threads sending to each
/// other do not wait on each other for good.
pub fn await_reply(windows: &mut Windows, caller: ThreadId, id: SentId) -> Awaited {
    if let Some(answer) = collect_reply(windows, caller, id) {
        return Awaited::Answer(answer);
    }
    let queues = &mut windows.queues;
    if queues.sent_at(id).is_some_and(|s| {
        s.state == State::Dropped && s.sender.is_some() && s.sender == queues.queue_of(caller)
    }) {
        queues.free_sent(id.index);
        return Awaited::Failed;
    }
    match queues.queue_of(caller) {
        Some(queue) if queues.queues[queue.index as usize].sent.head.is_some() => Awaited::Received,
        _ => Awaited::Wait,
    }
}

/// The caller's send `id` waits on once its sender delivered the messages sent to it
/// ([`Awaited::Received`]): its deadline (none for SendMessage's). STATUS_INVALID_PARAMETER for an
/// id that names no send of the caller's.
pub fn resume_send(
    windows: &Windows,
    caller: ThreadId,
    id: SentId,
) -> Result<Option<u64>, NtStatus> {
    let queues = &windows.queues;
    match queues.sent_at(id) {
        Some(sent) if sent.sender.is_some() && sent.sender == queues.queue_of(caller) => {
            Ok(sent.deadline)
        }
        _ => Err(STATUS_INVALID_PARAMETER),
    }
}

/// Keep the caller's send `id`'s `deadline` with it, for the wait's resumption ([`resume_send`]).
pub fn keep_deadline(windows: &mut Windows, id: SentId, deadline: Option<u64>) {
    if windows.queues.sent_at(id).is_some() {
        windows.queues.sent[id.index as usize].deadline = deadline;
    }
}

// --- The server's sends --------------------------------------------------------------------------

/// Where a message the server sends goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServerSending {
    /// Queued for the window's thread: the server waits for the answer ([`server_reply`]).
    Waiting(SentId),
    /// Nowhere: the handle names no window, the window's procedure is the window manager's, its
    /// thread has no queue, or the sent messages' pool is full.
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
    queues.push_sent(receiver, id.index);
    ServerSending::Waiting(id)
}

/// What became of the server's send `id`, once its receiver answered it or it was dropped (the
/// record goes back to the pool); none while it waits.
pub fn server_reply(windows: &mut Windows, id: SentId) -> Option<ServerReply> {
    let queues = &mut windows.queues;
    let sent = queues.sent_at(id)?;
    let reply = match sent.state {
        State::Answered => ServerReply::Answered(sent.result),
        State::Dropped => ServerReply::Dropped,
        State::Queued | State::Received => return None,
    };
    queues.free_sent(id.index);
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
                queues.unlink_sent(receiver, id.index);
            }
            queues.free_sent(id.index);
        }
        State::Received => queues.sent[id.index as usize].server = false,
        State::Answered | State::Dropped => queues.free_sent(id.index),
    }
}

/// DispatchMessage's step: the procedure the message goes to — WM_TIMER's TimerProc when its
/// lParam names one, the window's procedure otherwise; 0 for a thread message or a window whose
/// procedure is the window manager's. STATUS_INVALID_HANDLE for a handle naming no window.
pub fn dispatch_target(windows: &Windows, msg: &Msg) -> Result<u32, NtStatus> {
    if msg.message == WM_TIMER && msg.lparam != 0 {
        return Ok(msg.lparam as u32);
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
/// thread waits for its answer): see the module notes. Nothing for a window whose procedure is the
/// window manager's, or a thread with no queue; nothing either when the pool is full (the message
/// is lost), nor for a creation message, which goes to the creating thread's own window, by
/// callback ([`QueueSession`]).
pub fn defer(windows: &mut Windows, target: WindowId, message: &Message) {
    let Some(proc) = windows.client_proc(target) else {
        return;
    };
    let thread = windows.window_thread(target);
    let hwnd = windows.handle_of(target);
    let Some(receiver) = windows.queues.queue_of(thread) else {
        return;
    };
    let carried = match message.payload {
        Payload::None => Carried::None,
        Payload::Rect(r) => Carried::Rect(r),
        Payload::WindowPos(w) => Carried::WindowPos(w),
        Payload::Style(style) => Carried::Style(style),
        Payload::Create(_) => return,
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
    queues.push_sent(receiver, id.index);
}

/// The callback a message the window manager sends to `target` (whose procedure is `proc`) is
/// (rtl::callback's notes): the `__fn*` slot its payload's kind names, the input block's head, and
/// the structure the block carries after it (its first `length` bytes). A creation message's
/// window name follows the structure in the block ([`Windows::create_text`]); its CREATESTRUCTW's
/// lpszClass is the class's atom, as a receipt's was.
pub fn callback_input(
    windows: &Windows,
    classes: &class::Registry,
    target: WindowId,
    proc: u32,
    message: &Message,
) -> CallbackInput {
    let mut input = CallbackInput {
        api: FN_DWORD,
        head: CallbackMsg {
            proc,
            hwnd: windows.handle_of(target),
            message: message.message,
            wparam: message.wparam,
            lparam: message.lparam,
        },
        carried: [0; CARRIED],
        length: 0,
    };
    let (api, bytes): (u32, &[u8]) = match &message.payload {
        Payload::None if message.message == WM_NCDESTROY => (FN_NCDESTROY, &[]),
        Payload::None => (FN_DWORD, &[]),
        Payload::Rect(r) => (FN_INOUTNCCALCSIZE, r.as_bytes()),
        Payload::WindowPos(p) => (FN_INLPWINDOWPOS, p.as_bytes()),
        Payload::Style(style) => (FN_INOUTSTYLECHANGE, style.as_bytes()),
        Payload::Create(p) => {
            let class = match p.class_name {
                ClassArg::Atom(atom) => atom,
                ClassArg::Name | ClassArg::AnsiName => windows
                    .class_window(input.head.hwnd)
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
            input.carried.copy_from_slice(create.as_bytes());
            input.api = FN_INLPCREATESTRUCT;
            input.length = CARRIED;
            return input;
        }
    };
    input.api = api;
    input.carried[..bytes.len()].copy_from_slice(bytes);
    input.length = bytes.len();
    input
}

/// The longest structure a callback's block carries: a CREATESTRUCTW.
const CARRIED: usize = core::mem::size_of::<CreateStructW>();

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

/// The window `window` is being freed: the messages posted to it go, its timers, its update
/// region and its caret with them.
pub fn window_gone(windows: &mut Windows, window: WindowId) {
    super::caret::window_gone(windows, window);
    let hwnd = windows.handle_of(window);
    let queues = &mut windows.queues;
    for index in 0..THREADS as u16 {
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
/// routines call back (rtl::callback's notes); a message to another thread's window is queued for
/// that thread ([`defer`]) and answered as the default procedure answers. A window whose procedure
/// is the window manager's is answered as the default procedure answers. A window's end takes its
/// posted messages, timers and update region with it; the activation and the destroy's focus
/// check are [`super::focus`]'s. The other window-manager calls are [`Session`]'s defaults. The
/// services hold it by the window manager's lock ([`with_session`]); the host tests by the
/// registries, which cannot be let go of: their sends are all queued.
pub struct QueueSession<H: Hold>(pub H);

#[cfg(test)]
impl<'a> QueueSession<window::Split<'a>> {
    /// A session over the two registries.
    pub fn new(windows: &'a mut Windows, classes: &'a mut class::Registry) -> Self {
        QueueSession((windows, classes))
    }
}

impl QueueSession<Locked<'_>> {
    /// The whole window manager, borrowed until the next send: the state beside the registries
    /// (the clipboard, the accelerator tables, the properties).
    pub fn manager(&mut self) -> &mut WindowManager {
        &mut self.0
    }
}

impl<H: Hold> Session for QueueSession<H> {
    fn parts(&mut self) -> (&mut Windows, &mut class::Registry) {
        self.0.parts()
    }

    fn send(&mut self, target: WindowId, message: &mut Message) -> LResult {
        let windows = self.windows();
        let Some(proc) = windows.client_proc(target) else {
            return default_answer(message.message);
        };
        if let Some(answer) = call_back(&mut self.0, target, proc, message) {
            return answer;
        }
        defer(self.windows(), target, message);
        default_answer(message.message)
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

/// The callback `message` to `target` is, when `target` is a window of the running thread's and
/// `hold` can let the lock go: the procedure `proc`'s answer, or 0 when the callback failed (the
/// kernel stack has no room for it, the user stack cannot take its block, the routine took an
/// exception or answered no LRESULT). None when the message is not one to call back.
#[cfg(target_arch = "x86")]
fn call_back<H: Hold>(
    hold: &mut H,
    target: WindowId,
    proc: u32,
    message: &Message,
) -> Option<LResult> {
    use crate::win32k::text::Staged;
    // The running thread, by its client id: a window's thread record is the window registry's,
    // whose queue keeps the id.
    crate::sched::try_current_thread()?;
    let running = crate::level::raised::<crate::level::Dispatch, _>(|dispatch| {
        crate::sched::DISPATCHER
            .get(dispatch)
            .thread(crate::sched::current_thread())
            .thread_id()
    });
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
    hold.unlocked(|passive| {
        let reply = crate::user::callback::call_user_mode(passive, input.api, &parts);
        if reply.status != STATUS_SUCCESS || (reply.length as usize) < size_of::<LResult>() {
            return 0;
        }
        crate::user::args::UserPtr::<LResult>::at(reply.output)
            .read()
            .unwrap_or(0)
    })
}

/// The host has no user mode to call back: every send is queued.
#[cfg(not(target_arch = "x86"))]
fn call_back<H: Hold>(
    _hold: &mut H,
    _target: WindowId,
    _proc: u32,
    _message: &Message,
) -> Option<LResult> {
    None
}

/// What a session's work left for after the lock: the input state published, the queues it gave
/// something to and whether the server's send was answered, whose events are set once the lock is
/// let go ([`Signals::raise`]).
pub struct Signals {
    wakes: [u32; WAKE_WORDS],
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

    /// Each queue's event: a synchronization event, set whenever its queue is given something
    /// (see [`Queues::take_wakes`]), waited on by the queue's thread alone. They are named by their
    /// addresses in the dispatcher database ([`WaitableId::Embedded`]), and reached only through
    /// the dispatcher once named. They live outside the window manager, whose state its lock's
    /// holder borrows whole.
    struct QueueEvents([UnsafeCell<Event>; THREADS]);

    // SAFETY: one processor. The events are touched directly once, by `init` at boot, before any
    // thread can wait on one or set one; from then on only the dispatcher reaches their headers,
    // by their addresses, serialized at the dispatch level.
    unsafe impl Sync for QueueEvents {}

    static EVENTS: QueueEvents = QueueEvents(
        [const { UnsafeCell::new(Event::new(EventKind::Synchronization, false)) }; THREADS],
    );

    impl QueueEvents {
        /// The event of the queue at `index`: its header's address. No reference to the event is
        /// formed.
        fn id(&self, index: usize) -> WaitableId {
            // SAFETY: a projection inside the static's own cell: it computes the header's address
            // and reads nothing.
            let header = unsafe { core::ptr::addr_of_mut!((*self.0[index].get()).waitable) };
            WaitableId::Embedded(NonNull::new(header).expect("a static is not null"))
        }
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

    /// Name the queues' events and the server's. Once, at boot, before the first process.
    pub fn init() {
        let _masked = crate::pcr::pcr().mask_guard();
        for event in &EVENTS.0 {
            // SAFETY: the one direct reach into each event (see the `Sync` impl): nothing waits
            // on it or sets it yet, and interrupts are masked for the reference's life.
            unsafe { (*event.get()).init() };
        }
        // SAFETY: as above, for the server's event.
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
    /// lock is let go.
    pub fn with_session<R>(
        passive: &mut At<Passive>,
        f: impl FnOnce(&mut QueueSession<Locked<'_>>) -> R,
    ) -> R {
        let (result, signals) = {
            let mut session = QueueSession(crate::win32k::window::lock(passive));
            let result = f(&mut session);
            (result, Signals::take(session.manager()))
        };
        signals.raise(passive);
        result
    }

    impl Signals {
        /// Set the events of the queues given something, and the server's when its send was
        /// answered: outside the window manager's lock.
        pub fn raise(self, passive: &mut At<Passive>) {
            let Signals { wakes, server } = self;
            if !server && wakes.iter().all(|&word| word == 0) {
                return;
            }
            let mut dispatch = passive.raise::<Dispatch>();
            let dispatcher = crate::sched::DISPATCHER.get(&mut dispatch);
            for (word, bits) in wakes.iter().enumerate() {
                for bit in 0..32 {
                    if bits & (1 << bit) != 0 {
                        dispatcher.set_event(EVENTS.id(word * 32 + bit), EVENT_WAKE_INCREMENT);
                    }
                }
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
        let event = EVENTS.id(thread.0 as usize);
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
    /// relative; none: no end): the wait's status, STATUS_WAIT_0 + the count of `objects` for the
    /// queue's event (given something: the caller looks again at what).
    pub fn wait_on_objects_or_queue(
        thread: ThreadId,
        objects: &[WaitableId],
        timeout: Option<i64>,
    ) -> NtStatus {
        let mut ids = [EVENTS.id(thread.0 as usize); wait::MAXIMUM_WAIT_OBJECTS];
        ids[..objects.len()].copy_from_slice(objects);
        let ids = &ids[..=objects.len()];
        wait::wait_current_with(|dispatcher, me, stamp, replay| {
            let timeout =
                wait::replay_timeout(dispatcher.thread(me), replay, timeout, stamp.interrupt_time);
            dispatcher.wait_for_multiple(
                me,
                ids,
                false,
                WaitReason::UserRequest,
                WaitMode::User,
                false,
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
pub use target::{
    init,
    locked,
    now,
    wait_for_server,
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
        SendTimeout,
        COPY_DATA_HEAD,
        ONE_PARAM_END_SENT_MESSAGE,
        ONE_PARAM_ENUM_CLIPBOARD_FORMATS,
        ONE_PARAM_IN_SEND_MESSAGE,
        ONE_PARAM_IS_HUNG_APP_WINDOW,
        ONE_PARAM_POST_QUIT_MESSAGE,
        ONE_PARAM_REPLY_MESSAGE,
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
    /// takes, taken out, into the receipt; on a queue with none, the caller waits on its queue
    /// (until its next timer's due, when it has timers). STATUS_INVALID_HANDLE when the filter
    /// names a window there is not.
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
            let taken = with_manager(call.passive(), |m| {
                take(&mut m.windows, caller, &filter, true, now)
            })?;
            match taken {
                Taken::Nothing { due } => {
                    let timeout = due.map(|due| due.saturating_sub(now) as i64);
                    if timeout != Some(0) {
                        wait_on_queue(caller, timeout);
                    }
                }
                taken => return write_receipt(call, caller, receipt, taken, millis(now)),
            }
        }
    }

    /// NtUserPeekMessage(Receipt, Window, MsgFilterMin, MsgFilterMax, RemoveMsg): the next message
    /// the filter takes, taken out with PM_REMOVE, into the receipt; RECEIVED_NONE when there is
    /// none.
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
        let now = now();
        let taken = with_manager(call.passive(), |m| {
            take(&mut m.windows, caller, &filter, remove, now)
        })?;
        write_receipt(call, caller, receipt, taken, millis(now))
    }

    /// Write what a read took into the caller's receipt: the head, and for a sent message the
    /// structure it carries, each part read from its record under the lock and written once the
    /// lock is let go.
    fn write_receipt(
        call: &mut NtCall,
        caller: ThreadId,
        receipt: UserAddr,
        taken: Taken,
        time: u32,
    ) -> NtResult {
        let head = receipt.cast::<ReceiptHead>();
        let id = match taken {
            Taken::Nothing { .. } => {
                head.write(ReceiptHead {
                    kind: RECEIVED_NONE,
                    ..ReceiptHead::default()
                })?;
                return Ok(STATUS_SUCCESS);
            }
            Taken::Message(msg) => {
                head.write(ReceiptHead {
                    kind: Taken::kind_of(&msg),
                    proc: 0,
                    msg,
                })?;
                return Ok(STATUS_SUCCESS);
            }
            Taken::Sent(id) => id,
        };
        let base = receipt.raw();
        let (first, rect, style, pos, text) = with_manager(call.passive(), |m| {
            let w = &m.windows;
            (
                receipt_head(w, caller, id, base, time),
                receipt_rect(w, id),
                receipt_style(w, id),
                receipt_window_pos(w, id),
                receipt_text(w, id),
            )
        });
        let first = first.ok_or(STATUS_INVALID_PARAMETER)?;
        head.write(first)?;
        // The text's length: user32 asks for the text itself ([`receive_text`]).
        receipt
            .offset(offset_of!(Receipt, text) as u32)
            .cast::<u32>()
            .write(text)?;
        if let Some(pos) = pos {
            receipt
                .offset(offset_of!(Receipt, window_pos) as u32)
                .cast::<window::WindowPos>()
                .write(pos)?;
        }
        if let Some(rect) = rect {
            receipt
                .offset(offset_of!(Receipt, rect) as u32)
                .cast::<rtl::gdi::Rect>()
                .write(rect)?;
        }
        if let Some(style) = style {
            receipt
                .offset(offset_of!(Receipt, style) as u32)
                .cast::<StyleStruct>()
                .write(style)?;
        }
        Ok(STATUS_SUCCESS)
    }

    /// NtUserCallTwoParam's TWO_PARAM_RECEIVE_TEXT: the text the message the caller is
    /// delivering carries ([`received_text`]) into its buffer at `buffer`, of `room` units, as
    /// much as fits, terminated; WM_GETTEXT's buffer kept for its answer. STATUS_INVALID_PARAMETER
    /// when the caller delivers no message that carries a text. The text is copied under the lock
    /// and written once it is let go.
    pub fn receive_text(call: &mut NtCall, buffer: UserAddr, room: u32) -> NtResult {
        let caller = gui_thread(call)?.thread;
        let staged = with_manager(call.passive(), |m| {
            let units = received_text(&mut m.windows, caller, buffer.raw(), room)?;
            let fits = units.len().min((room as usize).saturating_sub(1));
            Some(Staged::copy_of(&units[..fits]))
        })
        .ok_or(STATUS_INVALID_PARAMETER)?
        .ok_or(STATUS_NO_MEMORY)?;
        staged.write_terminated(buffer, room as usize)?;
        Ok(STATUS_SUCCESS)
    }

    /// NtUserCallTwoParam's TWO_PARAM_MSG_WAIT: MsgWaitForMultipleObjects' wait ([`MsgWait`] at
    /// `args`), a wait-any on the handles and the caller's queue: the count when input of the
    /// wake mask's kinds came to the queue since a read last looked for it ([`wait_ready_for`]:
    /// a timer coming due counts), before the wait or while it lasts; otherwise the objects' wait
    /// status (WAIT_OBJECT_0 + n,
    /// WAIT_ABANDONED_0 + n, WAIT_TIMEOUT). STATUS_INVALID_PARAMETER for 64 handles or more;
    /// a handle's refusal as NtWaitForMultipleObjects' (STATUS_INVALID_HANDLE...).
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
        let deadline = (wait.timeout != u32::MAX).then(|| now() + u64::from(wait.timeout) * 10_000);
        let passive = call.passive();
        crate::ob::waiting(&held[..count], || loop {
            let at = now();
            let due = match with_manager(passive, |m| {
                wait_ready_for(&mut m.windows, caller, at, wait.wake_mask)
            }) {
                Waited::Ready => return wait.count,
                Waited::Wait { due } => due,
            };
            let end = match (deadline, due) {
                (Some(deadline), Some(due)) => Some(deadline.min(due)),
                (deadline, due) => deadline.or(due),
            };
            let timeout = end.map(|end| end.saturating_sub(at) as i64);
            let status = wait_on_objects_or_queue(caller, &objects[..count], timeout);
            if status == STATUS_TIMEOUT && deadline.is_none_or(|deadline| now() < deadline) {
                // A timer's due, not the caller's: look again.
                continue;
            }
            if status.0 != wait.count {
                return status.0;
            }
        })
        .ok_or(STATUS_INVALID_HANDLE)
    }

    /// NtUserMessageCall(Window, Msg, wParam, lParam, Proc, Result, Timeout): SendMessage's and
    /// SendMessageTimeout's kernel side ([`send`]): the procedure to call into `proc` for a window
    /// of the caller's own thread (`result` 0), otherwise 0 into `proc` and the answer into
    /// `result` — the caller waiting for it when another thread's procedure gives it. With a
    /// timeout (rtl::user::SendTimeout, SendMessageTimeout's; null for SendMessage), the wait ends
    /// at its end, the message taken back if its receiver has not read it ([`abandon_send`]), and
    /// at once with SMTO_ABORTIFHUNG when the receiver is hung ([`window_hung`]): STATUS_TIMEOUT
    /// then (user32's ERROR_TIMEOUT), `result` 0. STATUS_INVALID_HANDLE when the receiving thread
    /// ends before it answers, its window gone with it ([`Awaited::Failed`]).
    ///
    /// A message sent to the caller while it waits ends the wait with STATUS_PENDING, the send's
    /// token ([`SentId::token`]) in `result`: user32 delivers what was sent to its thread, then
    /// calls again with the same arguments and the token as the timeout's `resume`, which waits on
    /// for the same answer, until the same deadline ([`await_reply`]).
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
        let resumed = limit.and_then(|l| SentId::from_token(l.resume));
        let (id, deadline) = match resumed {
            Some(id) => {
                let deadline =
                    with_manager(call.passive(), |m| resume_send(&m.windows, caller, id))?;
                (id, deadline)
            }
            None => match start_send(call, thread, window, message, wparam, lparam, limit)? {
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
            },
        };
        loop {
            let reply = with_manager(call.passive(), |m| {
                // WM_GETTEXT's text, as much as the sender's buffer holds.
                let got = answered_text(&m.windows, id).map(|text| {
                    let fits = text.len().min((wparam as usize).saturating_sub(1));
                    Staged::copy_of(&text[..fits])
                });
                (await_reply(&mut m.windows, caller, id), got)
            });
            match reply {
                (Awaited::Answer(answer), got) => {
                    if let (Some(got), true) = (got, lparam != 0 && wparam > 0) {
                        // Into the sender's buffer, terminated.
                        let got = got.ok_or(STATUS_NO_MEMORY)?;
                        got.write_terminated(UserAddr(lparam as u32), wparam as usize)?;
                    }
                    result.write(answer)?;
                    return Ok(STATUS_SUCCESS);
                }
                (Awaited::Received, _) => {
                    result.write(id.token() as i32)?;
                    return Ok(STATUS_PENDING);
                }
                // The receiving thread ended, its window with it (user32's 1400).
                (Awaited::Failed, _) => return Err(STATUS_INVALID_HANDLE),
                (Awaited::Wait, _) => match deadline {
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
        let carried = carried && !(message == WM_COPYDATA && lparam == 0);
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
            if let Ok(Sending::Waiting(id)) = sending {
                keep_deadline(&mut m.windows, id, deadline);
            }
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

    /// NtUserWaitMessage(): the caller waits on its queue until something new comes to it
    /// ([`wait_ready`]), its timers' dues waking it to look.
    pub fn wait_message(call: &mut NtCall) -> NtResult {
        let caller = gui_thread(call)?.thread;
        loop {
            let now = now();
            match with_manager(call.passive(), |m| wait_ready(&mut m.windows, caller, now)) {
                Waited::Ready => return Ok(STATUS_SUCCESS),
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
        gui_thread(call)?;
        let msg = msg.cast::<Msg>().read()?;
        let target = with_manager(call.passive(), |m| dispatch_target(&m.windows, &msg))?;
        proc.write(target)?;
        Ok(STATUS_SUCCESS)
    }

    /// NtUserCallOneParam(Param, Routine, Result): PostQuitMessage (the result 0), ReplyMessage
    /// (the result whether it answered another thread's message), the end of a sent message's
    /// delivery (the result whether one was being delivered), EnumClipboardFormats (the result the
    /// format after the parameter's), InSendMessage (the result whether another thread sent the
    /// message being delivered); STATUS_INVALID_PARAMETER for another routine.
    pub fn call_one_param(
        call: &mut NtCall,
        param: u32,
        routine: u32,
        result: UserPtr<u32>,
    ) -> NtResult {
        let caller = gui_thread(call)?.thread;
        let time = millis(now());
        // WM_GETTEXT's answer to another process, read back from the receiver's buffer before the
        // end (its procedure's answer is the units it copied).
        let mut text_reply = None;
        if routine == ONE_PARAM_END_SENT_MESSAGE {
            if let Some((at, room)) =
                with_manager(call.passive(), |m| text_reply_buffer(&m.windows, caller))
            {
                let count = (param as usize).min(room);
                text_reply = Some(Staged::read_counted(UserAddr(at), count)?);
            }
        }
        let answer = with_manager(call.passive(), |m| match routine {
            ONE_PARAM_POST_QUIT_MESSAGE => {
                post_quit(&mut m.windows, caller, param);
                Ok(0)
            }
            ONE_PARAM_REPLY_MESSAGE => Ok(reply(&mut m.windows, caller, param as LResult) as u32),
            ONE_PARAM_END_SENT_MESSAGE => {
                if let Some(reply) = &text_reply {
                    keep_text_reply(&mut m.windows, caller, reply.units());
                }
                Ok(end_sent(&mut m.windows, caller, param as LResult) as u32)
            }
            ONE_PARAM_ENUM_CLIPBOARD_FORMATS => m
                .clipboard
                .next_format(caller, param)
                .map_err(crate::win32k::clipboard::Refusal::status),
            ONE_PARAM_IN_SEND_MESSAGE => Ok(in_send(&m.windows, caller) as u32),
            ONE_PARAM_IS_HUNG_APP_WINDOW => {
                window_hung(&m.windows, caller, param, time).map(|hung| hung as u32)
            }
            _ => Err(STATUS_INVALID_PARAMETER),
        })?;
        result.write(answer)?;
        Ok(STATUS_SUCCESS)
    }
}

pub use services::{
    call_one_param,
    dispatch_message,
    get_message,
    message_call,
    peek_message,
    post_message,
    post_thread_message,
    send_notify_message,
    wait_message,
};
/// The text of the message being delivered, into the caller's buffer, and
/// MsgWaitForMultipleObjects' wait: caret's NtUserCallTwoParam routes their routines here.
#[cfg(target_arch = "x86")]
pub use services::{msg_wait, receive_text};

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

    use super::*;
    use crate::win32k::window::{
        CreateArgs,
        MenuInput,
        WindowManager,
        DESKTOP_CREATEWINDOW,
        WS_POPUP,
    };

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
            let head = receipt_head(&m.windows, t, id, 0x1000, 0).unwrap();
            got.push((head.msg.hwnd, head.msg.message));
            assert!(end_sent(&mut m.windows, t, 0));
        }
        got
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
        WM_CREATE,
        WM_DESTROY,
        WM_MOVE,
        WM_NCCALCSIZE,
        WM_NCDESTROY,
        WM_SIZE,
        WM_USER,
    };

    use super::rig::*;
    use super::*;
    use crate::win32k::window::{WindowManager, WS_CHILD, WS_POPUP};

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
    }

    /// The host's session queues every message, but a creation's: WM_NCCALCSIZE first, its
    /// lParam pointing at the receipt's rectangle.
    #[test]
    fn a_queued_messages_receipt_carries_its_structure() {
        let (m, atom) = manager();
        let t = thread(m, 1, 0x100);
        let h = window_at(m, atom, t, WS_POPUP, 0, 5, 6, 30, 40);
        let base = 0x0010_0000;
        let Taken::Sent(id) = read(m, t, &all(), 0) else {
            panic!("WM_NCCALCSIZE first");
        };
        let head = receipt_head(&m.windows, t, id, base, 7).unwrap();
        assert_eq!(head.kind, RECEIVED_SENT);
        assert_eq!(head.proc, PROC);
        assert_eq!(
            (head.msg.hwnd, head.msg.message, head.msg.time),
            (h, WM_NCCALCSIZE, 7)
        );
        assert_eq!(head.msg.lparam as u32, base + 36);
        let r = receipt_rect(&m.windows, id).unwrap();
        assert_eq!((r.left, r.top, r.right, r.bottom), (5, 6, 35, 46));
        assert_eq!(receipt_text(&m.windows, id), NO_TEXT);
        assert_eq!(received_text(&mut m.windows, t, 0x2000, 6), None);
        // Another thread's message is not this one's to read.
        let other = thread(m, 2, 0x200);
        assert_eq!(receipt_head(&m.windows, other, id, base, 0), None);
        assert!(end_sent(&mut m.windows, t, 0));
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

    /// WM_WINDOWPOSCHANGING and WM_WINDOWPOSCHANGED carry their WINDOWPOS into the receipt (guigeo
    /// `sizemsg` reads WM_WINDOWPOSCHANGED's flags): the move's place, and the flags reporting what
    /// did not change.
    #[test]
    fn a_window_pos_reaches_the_receipt() {
        let (m, atom) = manager();
        let t = thread(m, 1, 0x100);
        let h = popup(m, atom, t);
        deliver(m, t);
        let WindowManager {
            windows, classes, ..
        } = &mut *m;
        let flags = window::SWP_NOSIZE | window::SWP_NOZORDER | window::SWP_NOACTIVATE;
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
            let head = receipt_head(&m.windows, t, id, 0x1000, 0).unwrap();
            if head.msg.message == window::WM_WINDOWPOSCHANGED {
                assert_eq!(head.msg.lparam as u32, 0x1000 + 52);
                changed = receipt_window_pos(&m.windows, id);
            } else if head.msg.message != window::WM_WINDOWPOSCHANGING {
                assert_eq!(receipt_window_pos(&m.windows, id), None);
            }
            assert!(end_sent(&mut m.windows, t, 0));
        }
        let changed = changed.expect("WM_WINDOWPOSCHANGED");
        assert_eq!((changed.x, changed.y, changed.hwnd), (7, 8, h));
        assert_eq!(
            changed.flags,
            flags | window::SWP_NOCLIENTSIZE,
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
        let head = receipt_head(&m.windows, b, got, 0x1000, 0).unwrap();
        assert_eq!((head.msg.message, head.msg.lparam), (WM_COPYDATA, 0));
        assert_eq!(receipt_text(&m.windows, got), carried.len() as u32);
        assert_eq!(
            received_text(&mut m.windows, b, 0x8000, 9),
            Some(&carried[..])
        );
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
    /// manager (wintext `xproc`), as long as it is: WM_SETTEXT's 10,000 units handed whole to the
    /// receiver's buffer, WM_GETTEXT's buffer its wParam's units, wParam as the sender gave it,
    /// its 10,000-unit answer read back for the sender. Another message, or the same process's
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
        let base = 0x1000;
        let Ok(Sending::Waiting(id)) =
            send_carrying(&mut m.windows, a, hb, WM_SETTEXT, 0, 0x5000, Some(&text))
        else {
            panic!("queued for the other process's thread");
        };
        let Taken::Sent(got) = read(m, b, &all(), 0) else {
            panic!("the receiver reads it");
        };
        let head = receipt_head(&m.windows, b, got, base, 0).unwrap();
        assert_eq!(head.msg.lparam, 0, "the receiver's buffer, once it has one");
        assert_eq!(receipt_text(&m.windows, got), 10_000);
        assert_eq!(
            received_text(&mut m.windows, b, 0x8000, 10_001),
            Some(&text[..])
        );
        assert_eq!(
            text_reply_buffer(&m.windows, b),
            None,
            "no answer to read back"
        );
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
        let head = receipt_head(&m.windows, b, got, base, 0).unwrap();
        assert_eq!(head.msg.wparam, 20_000, "the sender's room");
        assert_eq!(receipt_text(&m.windows, got), 0);
        assert_eq!(text_reply_buffer(&m.windows, b), None, "no buffer yet");
        assert_eq!(
            received_text(&mut m.windows, b, 0x8000, 20_000),
            Some(&[][..])
        );
        assert_eq!(text_reply_buffer(&m.windows, b), Some((0x8000, 20_000)));
        keep_text_reply(&mut m.windows, b, &text);
        assert!(end_sent(&mut m.windows, b, 10_000));
        assert_eq!(answered_text(&m.windows, id), Some(&text[..]));
        assert_eq!(collect_reply(&mut m.windows, a, id), Some(10_000));
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
        assert_eq!(
            m.windows.queues.take_wakes()[0],
            1 << b.0,
            "the receiver woken"
        );
        assert_eq!(collect_reply(&mut m.windows, a, id), None);
        let Taken::Sent(got) = read(m, b, &all(), 0) else {
            panic!("the receiver reads it");
        };
        let head = receipt_head(&m.windows, b, got, 0, 0).unwrap();
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
        assert_eq!(
            m.windows.queues.take_wakes()[0],
            1 << a.0,
            "the sender woken"
        );
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
        assert_eq!(
            m.windows.queues.take_wakes()[0],
            1 << a.0,
            "the receiver woken"
        );
        assert!(!m.windows.queues.take_server_wake());
        assert_eq!(server_reply(&mut m.windows, id), None);
        let Taken::Sent(got) = read(m, a, &all(), 0) else {
            panic!("the receiver reads it");
        };
        let head = receipt_head(&m.windows, a, got, 0, 0).unwrap();
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
        assert_eq!(
            m.windows.queues.take_wakes(),
            [0; WAKE_WORDS],
            "no thread woken"
        );
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
        assert!(
            m.windows.queues.sent.iter().all(|s| !s.live),
            "every record back"
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

    /// DispatchMessage's procedure: WM_TIMER's TimerProc when it has one, the window's procedure,
    /// none for a thread message; a handle naming no window is refused.
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
        assert_eq!(dispatch_target(&m.windows, &msg(h, WM_USER, 0)), Ok(PROC));
        assert_eq!(dispatch_target(&m.windows, &msg(0, WM_USER, 0)), Ok(0));
        assert_eq!(
            dispatch_target(&m.windows, &msg(h, WM_TIMER, 0x0040_2000)),
            Ok(0x0040_2000)
        );
        assert_eq!(
            dispatch_target(&m.windows, &msg(0x7FFF_FFFC, WM_USER, 0)),
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
            message: rtl::user::WM_KEYDOWN,
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
        assert_eq!(m.windows.queues.take_wakes()[0], 1 << b.0);
        assert_eq!(m.windows.queues.take_wakes()[0], 0);
        let desktop = m.windows.thread_desktop_window(b).unwrap();
        let system = m.windows.window_thread(desktop);
        assert_eq!(
            post_thread(&mut m.windows, system, WM_USER, 0, 0, 0),
            Err(STATUS_INVALID_PARAMETER)
        );
    }

    /// The sent messages in the pool, live.
    fn live_sends(m: &WindowManager) -> usize {
        m.windows.queues.sent.iter().filter(|s| s.live).count()
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

    /// A range's read looks for the kinds its messages are, and the sent and posted messages.
    #[test]
    fn a_range_looks_for_its_kinds() {
        assert_eq!(all().wake_mask(), ALL_KINDS);
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
        let head = receipt_head(&m.windows, b, id, 0, 0).unwrap();
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
    /// before it answers. A's wait finds B's message and hands it to user32, which delivers it
    /// and resumes the same wait, as Windows 2000's SendMessage handles the messages sent to its
    /// thread while it waits; B gets its answer, then A. A wait with nothing sent to it waits.
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
        keep_deadline(&mut m.windows, to_b, Some(5_000));
        assert_eq!(await_reply(&mut m.windows, a, to_b), Awaited::Wait);
        // B reads A's message; its procedure sends to A's window.
        assert!(matches!(read(m, b, &all(), 0), Taken::Sent(_)));
        let Ok(Sending::Waiting(to_a)) = send(&mut m.windows, b, ha, WM_USER + 2, 2, 0) else {
            panic!("B's send is queued for A");
        };
        assert_eq!(await_reply(&mut m.windows, b, to_a), Awaited::Wait);

        // A, waiting, is handed B's message: user32 delivers it, then resumes its own wait.
        assert_eq!(await_reply(&mut m.windows, a, to_b), Awaited::Received);
        let token = to_b.token();
        assert_eq!(SentId::from_token(token), Some(to_b));
        let Taken::Sent(id) = read(m, a, &all(), 0) else {
            panic!("A reads B's message");
        };
        let head = receipt_head(&m.windows, a, id, 0, 0).unwrap();
        assert_eq!((head.msg.hwnd, head.msg.message), (ha, WM_USER + 2));
        assert!(end_sent(&mut m.windows, a, 22));
        assert_eq!(
            resume_send(&m.windows, a, SentId::from_token(token).unwrap()),
            Ok(Some(5_000)),
            "the same wait, until the same deadline"
        );
        assert_eq!(
            resume_send(&m.windows, b, to_b),
            Err(STATUS_INVALID_PARAMETER),
            "another thread's send"
        );
        assert_eq!(await_reply(&mut m.windows, a, to_b), Awaited::Wait);

        // B has its answer, and answers A's message.
        assert_eq!(await_reply(&mut m.windows, b, to_a), Awaited::Answer(22));
        assert!(end_sent(&mut m.windows, b, 11));
        assert_eq!(await_reply(&mut m.windows, a, to_b), Awaited::Answer(11));
        assert_eq!(live_sends(m), base, "both records went back to the pool");
        assert_eq!(SentId::from_token(0), None);
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
        assert_ne!(
            m.windows.queues.take_wakes()[0] & (1 << a.0),
            0,
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
}
