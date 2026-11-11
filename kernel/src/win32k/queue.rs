//! Message queues: each thread's queue of posted messages, of the messages sent to its windows,
//! and its WM_QUIT; the reads that take them in Windows 2000's documented order; and the pump the
//! window manager's decisions send their messages through ([`QueuePump`]).
//!
//! A queue is a record of the window manager's ([`Queues`], in the window registry, behind its
//! one lock), one per thread record ([`window::Thread`]), made when a thread connects (its first
//! win32k service makes it a GUI thread, as on Windows 2000) and named by a generation-tagged id
//! ([`QueueId`]), the object manager's pattern. Posted messages are entries of one pool the queues
//! share, linked oldest first, in two lanes: the messages posted to the thread, and the input
//! messages the keyboard's keystrokes became ([`super::input`], [`post_input`]). A read ([`take`])
//! answers, in the documented order: the messages sent to the thread's windows; the posted
//! messages its filter takes; the input messages it takes (a key message read updates the
//! thread's key state); the WM_QUIT PostQuitMessage left; a WM_PAINT for a window of the thread's
//! with an update region ([`super::paint`]); a WM_TIMER for one of its timers that came due
//! ([`super::timer`]). WM_QUIT, WM_PAINT and WM_TIMER
//! are never posted: they are made when a read finds nothing posted before them, as Windows 2000
//! makes them. A read that finds nothing for its filter blocks GetMessage's caller on its queue's
//! event, set by whatever gives the queue something: a post, a send, an answer, a timer set, an
//! invalidation. The wait is the scheduler's, outside the lock; its timeout is the thread's next
//! timer's due.
//!
//! A sent message reaches its window procedure through the receiving thread's own GetMessage or
//! PeekMessage: there is no way for the kernel to call user-mode code and return (Windows 2000's
//! KeUserModeCallback). Every message the window manager's decisions send to a window with a
//! client-side procedure — the creation's WM_NCCREATE to WM_MOVE, the destruction's WM_DESTROY and
//! WM_NCDESTROY, what showing and moving send — is queued for the window's thread as a sent
//! message ([`QueuePump`]), and the decision goes on with the default procedure's answer (1 to
//! WM_NCCREATE, 0 to the rest). The thread's next read hands it out first, before anything posted,
//! with the procedure to call and a copy of the structure the message points at
//! ([`rtl::user::Receipt`]); user32 calls the procedure and hands the answer back
//! ([`end_sent`]). user32 reads them right after the service that sent them returns, so a program
//! sees its procedure called before CreateWindowEx or DestroyWindow returns, in the order the
//! decisions sent. What this cannot do: a procedure's answer never reaches the decision (a zero
//! answer to WM_NCCREATE does not cancel the creation, nor -1 to WM_CREATE fail it), and nothing
//! the procedure changes in the structure it was handed (WM_NCCALCSIZE's rectangle) comes back.
//!
//! SendMessage to another thread's window goes the same way, its sender waiting for the answer
//! ([`send`], [`collect_reply`]); to a window of its own thread, the service names the
//! procedure and user32 calls it itself, as Windows 2000's user32 does. So do the console server's
//! WM_QUERYENDSESSION and WM_ENDSESSION at the session's end ([`server_send`]), the server, which
//! has no queue, waiting on an event of its own ([`wait_for_server`]).
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
//!   Result): SendMessage: the procedure to call for a window of the caller's own thread, or the
//!   answer;
//! - NtUserDispatchMessage(ptr Msg, ptr<u32> Proc): the procedure DispatchMessage calls;
//! - NtUserCallOneParam(u32 Param, u32 Routine, ptr<u32> Result): PostQuitMessage, ReplyMessage,
//!   and the end of a sent message's delivery ([`rtl::user`]'s ONE_PARAM_* routines).

use core::mem::offset_of;

use rtl::user::{
    CreateStructW,
    Msg,
    Point,
    Receipt,
    ReceiptHead,
    StyleStruct,
    HWND_BROADCAST,
    QS_HOTKEY,
    QS_INPUT,
    QS_KEY,
    QS_PAINT,
    QS_POSTMESSAGE,
    QS_SENDMESSAGE,
    QS_TIMER,
    RECEIVED_MESSAGE,
    RECEIVED_QUIT,
    RECEIVED_SENT,
    WM_NCCREATE,
    WM_PAINT,
    WM_QUERYENDSESSION,
    WM_QUIT,
    WM_TIMER,
};

use super::class;
use super::window::{
    self,
    ClassArg,
    CreateParams,
    Hwnd,
    LParam,
    LResult,
    Message,
    Payload,
    Pump,
    TextBuf,
    ThreadKey,
    WParam,
    WindowId,
    Windows,
    THREADS,
};
use crate::sched::thread::ThreadId;
use crate::status::*;

/// How many posted messages the queues hold between them.
pub const POSTED: usize = 512;
/// How many sent messages can be on their way at once.
pub const SENT: usize = 128;
/// How many sent creation messages, each with its create parameters, can be on their way at once.
pub const CREATES: usize = 16;

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
    posted: List,
    /// The input messages, oldest first.
    input: List,
    /// The sent messages not handed out yet, oldest first.
    sent: List,
    /// The sent messages handed out and not answered yet, innermost first.
    receiving: Option<u16>,
    /// The send this thread waits on the answer of.
    awaiting: Option<SentId>,
    /// PostQuitMessage's exit code, until a read takes the WM_QUIT.
    quit: Option<u32>,
}

impl Queue {
    const EMPTY: Self = Queue {
        live: false,
        generation: 0,
        key: None,
        client_id: 0,
        posted: List::EMPTY,
        input: List::EMPTY,
        sent: List::EMPTY,
        receiving: None,
        awaiting: None,
        quit: None,
    };
}

/// A posted message: the MSG a read hands out, and the link to the next one.
#[derive(Clone, Copy)]
struct Posted {
    msg: Msg,
    /// An input message's key, as the key state names it (the side's key for Shift, Ctrl and Alt,
    /// where the message names the generic one); 0 for a message posted to the thread.
    key: u8,
    next: Option<u16>,
}

/// The two lanes of a queue's entries from the posted messages' pool.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Lane {
    /// The messages posted to the thread or its windows.
    Posted,
    /// The input messages the keyboard's keystrokes became.
    Input,
}

impl Posted {
    const EMPTY: Self = Posted {
        msg: Msg {
            hwnd: 0,
            message: 0,
            wparam: 0,
            lparam: 0,
            time: 0,
            pt: Point { x: 0, y: 0 },
        },
        key: 0,
        next: None,
    };
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
    /// Never answered: its window or its receiver's queue went first. Only a send the server waits
    /// on stays in this state, for the server to collect ([`server_reply`]); any other is answered
    /// 0 then.
    Dropped,
}

/// The structure a sent message's lParam points at, carried with it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Carried {
    None,
    /// WM_NCCALCSIZE's rectangle.
    Rect(window::Rect),
    /// WM_NCCREATE's and WM_CREATE's create parameters: a slot of the creates' pool.
    Create(u16),
    /// WM_WINDOWPOSCHANGING's and WM_WINDOWPOSCHANGED's WINDOWPOS.
    WindowPos(window::WindowPos),
    /// WM_STYLECHANGING's and WM_STYLECHANGED's STYLESTRUCT.
    Style(StyleStruct),
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

/// A sent creation message's create parameters, and the class's atom (CREATESTRUCT's lpszClass
/// for a class named by its string).
#[derive(Clone, Copy)]
struct CreateSlot {
    live: bool,
    class_atom: class::Atom,
    params: CreateParams,
}

/// The queues, the pools their messages come from, the timers ([`super::timer`]) and the windows'
/// update regions ([`super::paint`]): the message layer's state, in the window registry, behind the
/// window manager's lock.
pub struct Queues {
    queues: [Queue; THREADS],
    posted: [Posted; POSTED],
    /// The free posted entries, linked through their `next`.
    free_posted: Option<u16>,
    sent: [Sent; SENT],
    creates: [CreateSlot; CREATES],
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
            let posted = addr_of_mut!((*queues).posted) as *mut Posted;
            for index in 0..POSTED {
                let next = (index + 1 < POSTED).then_some(index as u16 + 1);
                posted.add(index).write(Posted {
                    next,
                    ..Posted::EMPTY
                });
            }
            addr_of_mut!((*queues).free_posted).write(Some(0));
            let sent = addr_of_mut!((*queues).sent) as *mut Sent;
            for index in 0..SENT {
                sent.add(index).write(Sent::EMPTY);
            }
            let creates = addr_of_mut!((*queues).creates) as *mut CreateSlot;
            for index in 0..CREATES {
                creates.add(index).write(CreateSlot {
                    live: false,
                    class_atom: 0,
                    params: CreateParams {
                        ex_style: 0,
                        class_name: ClassArg::Atom(0),
                        name: TextBuf::EMPTY,
                        style: 0,
                        x: 0,
                        y: 0,
                        cx: 0,
                        cy: 0,
                        parent: 0,
                        menu: 0,
                        instance: 0,
                        params: 0,
                    },
                });
            }
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

    /// Mark the queue of the thread record `thread` as given something: its event is set once the
    /// lock is let go.
    pub fn wake_thread(&mut self, thread: ThreadId) {
        if self.queue_of(thread).is_some() {
            self.wakes[thread.0 as usize / 32] |= 1 << (thread.0 % 32);
        }
    }

    fn wake(&mut self, id: QueueId) {
        self.wakes[id.index as usize / 32] |= 1 << (id.index % 32);
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
    fn lane(&mut self, index: u16, lane: Lane) -> &mut List {
        let queue = &mut self.queues[index as usize];
        match lane {
            Lane::Posted => &mut queue.posted,
            Lane::Input => &mut queue.input,
        }
    }

    /// Append `msg` to the queue's posted messages; false when the pool is exhausted.
    fn push_posted(&mut self, id: QueueId, msg: Msg) -> bool {
        self.push(id, Lane::Posted, msg, 0)
    }

    /// Append `msg` (an input message's key `key`) to the queue's lane `lane`; false when the pool
    /// is exhausted.
    fn push(&mut self, id: QueueId, lane: Lane, msg: Msg, key: u8) -> bool {
        let Some(entry) = self.free_posted else {
            return false;
        };
        self.free_posted = self.posted[entry as usize].next;
        self.posted[entry as usize] = Posted {
            msg,
            key,
            next: None,
        };
        match self.lane(id.index, lane).tail {
            Some(tail) => self.posted[tail as usize].next = Some(entry),
            None => self.lane(id.index, lane).head = Some(entry),
        }
        self.lane(id.index, lane).tail = Some(entry);
        self.wake(id);
        true
    }

    /// Take `entry` out of the queue's lane `lane` (`previous` is the entry before it, none for
    /// the head) and give it back to the pool.
    fn unlink_posted(&mut self, index: u16, lane: Lane, previous: Option<u16>, entry: u16) {
        let next = self.posted[entry as usize].next;
        match previous {
            Some(p) => self.posted[p as usize].next = next,
            None => self.lane(index, lane).head = next,
        }
        let list = self.lane(index, lane);
        if list.tail == Some(entry) {
            list.tail = previous;
        }
        self.posted[entry as usize] = Posted {
            next: self.free_posted,
            ..Posted::EMPTY
        };
        self.free_posted = Some(entry);
    }

    /// Drop every posted and input message of the queue at `index` that `drop` picks.
    fn purge_posted(&mut self, index: u16, drop: impl Fn(&Msg) -> bool) {
        for lane in [Lane::Posted, Lane::Input] {
            let mut previous = None;
            let mut at = self.lane(index, lane).head;
            while let Some(entry) = at {
                let next = self.posted[entry as usize].next;
                if drop(&self.posted[entry as usize].msg) {
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

    /// Give the sent message at `index` back to the pool, its create parameters with it.
    fn free_sent(&mut self, index: u16) {
        if let Carried::Create(slot) = self.sent[index as usize].carried {
            self.creates[slot as usize].live = false;
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
        self.wake(receiver);
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

    /// End the queue at `index`: what was posted to it goes, what was sent to it is answered 0 (or
    /// dropped, for the server), a send it waits on is left to be dropped when answered, its
    /// timers go.
    fn end_queue(&mut self, index: u16) {
        self.purge_posted(index, |_| true);
        let id = QueueId {
            index,
            generation: self.queues[index as usize].generation,
        };
        while let Some(sent) = self.pop_sent(id) {
            self.drop_unanswered(sent);
        }
        while let Some(sent) = self.queues[index as usize].receiving {
            self.queues[index as usize].receiving = self.sent[sent as usize].next;
            if self.sent[sent as usize].state == State::Received {
                self.drop_unanswered(sent);
            } else {
                self.sent[sent as usize].next = None;
            }
        }
        if let Some(awaited) = self.queues[index as usize].awaiting {
            if self.sent_at(awaited).is_some() {
                let sent = &mut self.sent[awaited.index as usize];
                sent.sender = None;
                if sent.state == State::Answered {
                    self.free_sent(awaited.index);
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

/// The thread record `thread`'s thread ended: its queue ends with it. What was posted to it goes;
/// what was sent to it is answered 0; its timers go. (Nothing ends a thread's record yet: a record
/// another thread takes over ends its queue through [`attach`].)
#[cfg_attr(not(test), allow(dead_code))]
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

// --- Posting -------------------------------------------------------------------------------------

/// PostMessage: `message` posted to the window `hwnd`'s thread, stamped `time`; a null window
/// posts a thread message to `caller`, HWND_BROADCAST posts to every top-level window of
/// `caller`'s desktop. STATUS_INVALID_HANDLE for a handle naming no window,
/// STATUS_INSUFFICIENT_RESOURCES when the posted messages' pool is full.
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
/// the client id, [`queue_by_client_id`]), with no window, stamped `time`.
pub fn post_thread(
    windows: &mut Windows,
    thread: ThreadId,
    message: u32,
    wparam: WParam,
    lparam: LParam,
    time: u32,
) -> Result<(), NtStatus> {
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
/// (a thread that never called win32k, or the window manager's own), STATUS_INSUFFICIENT_RESOURCES
/// when the pool is full.
fn post_to(windows: &mut Windows, thread: ThreadId, msg: Msg) -> Result<(), NtStatus> {
    let queues = &mut windows.queues;
    let id = queues.queue_of(thread).ok_or(STATUS_INVALID_PARAMETER)?;
    if queues.push_posted(id, msg) {
        Ok(())
    } else {
        Err(STATUS_INSUFFICIENT_RESOURCES)
    }
}

/// An input message for the thread record `thread`'s queue: `msg`, a key message whose key the key
/// state names `key` ([`super::input`]). A key-down that repeats its key (`repeat`) while the
/// queue's last input message, not read yet, is the same message of the same key for the same
/// window raises that message's repeat count (lParam's low word) instead, as Windows 2000's queue
/// folds a held key's repeats. Nothing when the thread has no queue; the message is lost when the
/// pool is full.
pub fn post_input(windows: &mut Windows, thread: ThreadId, msg: Msg, key: u8, repeat: bool) {
    let queues = &mut windows.queues;
    let Some(id) = queues.queue_of(thread) else {
        return;
    };
    if repeat {
        if let Some(tail) = queues.queues[id.index as usize].input.tail {
            let last = &mut queues.posted[tail as usize].msg;
            let count = last.lparam as u32 & 0xFFFF;
            if last.hwnd == msg.hwnd
                && last.message == msg.message
                && last.wparam == msg.wparam
                && count < 0xFFFF
            {
                last.lparam = ((last.lparam as u32 & !0xFFFF) | (count + 1)) as LParam;
                queues.wake(id);
                return;
            }
        }
    }
    queues.push(id, Lane::Input, msg, key);
}

/// PostQuitMessage: the caller's next read that finds nothing posted before it makes a WM_QUIT
/// with the exit code `code`.
pub fn post_quit(windows: &mut Windows, caller: ThreadId, code: u32) {
    let queues = &mut windows.queues;
    if let Some(id) = queues.queue_of(caller) {
        queues.queues[id.index as usize].quit = Some(code);
        queues.wake(id);
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

    // The sent messages: a message another thread or the server sent to a window destroyed since
    // is answered 0 (dropped, for the server) and skipped (the window manager's own sends are
    // delivered whatever became of the window).
    while let Some(index) = windows.queues.pop_sent(id) {
        let sent = windows.queues.sent[index as usize];
        let window_gone = sent.window.is_none_or(|w| !windows.is_live(w));
        if (sent.sender.is_some() || sent.server) && window_gone {
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
            let msg = queues.posted[entry as usize].msg;
            if filter.takes(msg.hwnd, msg.message) {
                if remove {
                    queues.unlink_posted(id.index, Lane::Posted, previous, entry);
                }
                return Ok(Taken::Message(msg));
            }
            previous = Some(entry);
            at = queues.posted[entry as usize].next;
        }
    }

    // The input messages: the keyboard's (there is no mouse yet). A key message taken out is the
    // next step of the thread's key state.
    if filter.looks_at(QS_KEY) {
        let queues = &mut windows.queues;
        let mut previous = None;
        let mut at = queues.queues[id.index as usize].input.head;
        while let Some(entry) = at {
            let Posted { msg, key, .. } = queues.posted[entry as usize];
            if filter.takes(msg.hwnd, msg.message) {
                if remove {
                    queues.unlink_posted(id.index, Lane::Input, previous, entry);
                    super::input::read(windows, caller, &msg, key);
                }
                return Ok(Taken::Message(msg));
            }
            previous = Some(entry);
            at = queues.posted[entry as usize].next;
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

    // WM_TIMER, for a timer of the thread's that came due.
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
    Ok(Taken::Nothing {
        due: timers.next_due(caller),
    })
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
        Carried::Create(_) => receipt.wrapping_add(offset_of!(Receipt, create) as u32) as LParam,
        Carried::WindowPos(_) => {
            receipt.wrapping_add(offset_of!(Receipt, window_pos) as u32) as LParam
        }
        Carried::Style(_) => receipt.wrapping_add(offset_of!(Receipt, style) as u32) as LParam,
    };
    Some(ReceiptHead {
        kind: RECEIVED_SENT,
        proc: sent.proc,
        msg: made(sent.hwnd, sent.message, sent.wparam, lparam, time),
    })
}

/// The CREATESTRUCTW the sent message `id` carries, when it carries one, its name pointing at the
/// receipt's copy (the receipt at `receipt`), its class the class's atom.
pub fn receipt_create(windows: &Windows, id: SentId, receipt: u32) -> Option<CreateStructW> {
    let Carried::Create(slot) = windows.queues.sent_at(id)?.carried else {
        return None;
    };
    let slot = &windows.queues.creates[slot as usize];
    let p = &slot.params;
    let class = match p.class_name {
        ClassArg::Atom(atom) => atom,
        ClassArg::Name | ClassArg::AnsiName => slot.class_atom,
    };
    Some(CreateStructW {
        create_params: p.params,
        instance: p.instance,
        menu: p.menu,
        parent: p.parent,
        cy: p.cy,
        cx: p.cx,
        y: p.y,
        x: p.x,
        style: p.style,
        name: receipt.wrapping_add(offset_of!(Receipt, name) as u32),
        class: u32::from(class),
        ex_style: p.ex_style,
    })
}

/// The window name the sent message `id`'s create parameters carry, from unit `from` on, into
/// `out`: the units written (0 past its end).
pub fn receipt_name(windows: &Windows, id: SentId, from: usize, out: &mut [u16]) -> usize {
    let Some(Carried::Create(slot)) = windows.queues.sent_at(id).map(|s| s.carried) else {
        return 0;
    };
    let name = &windows.queues.creates[slot as usize].params.name;
    let rest = name.as_slice().get(from..).unwrap_or(&[]);
    let written = rest.len().min(out.len());
    out[..written].copy_from_slice(&rest[..written]);
    written
}

/// The STYLESTRUCT the sent message `id` carries, when it carries one.
pub fn receipt_style(windows: &Windows, id: SentId) -> Option<StyleStruct> {
    match windows.queues.sent_at(id)?.carried {
        Carried::Style(style) => Some(style),
        _ => None,
    }
}

/// The rectangle the sent message `id` carries, when it carries one.
pub fn receipt_rect(windows: &Windows, id: SentId) -> Option<rtl::gdi::Rect> {
    match windows.queues.sent_at(id)?.carried {
        Carried::Rect(r) => Some(rtl::gdi::Rect {
            left: r.left,
            top: r.top,
            right: r.right,
            bottom: r.bottom,
        }),
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
    if queues.sent[index as usize].state == State::Received {
        queues.answer(index, result);
    } else {
        // ReplyMessage answered it: the sender collects that answer.
        queues.sent[index as usize].next = None;
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
    sent.sender.is_some() || sent.server
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
/// STATUS_NO_MEMORY when the sent messages' pool is full.
pub fn send(
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
    let queues = &mut windows.queues;
    let (Some(receiver), Some(sender)) = (queues.queue_of(thread), queues.queue_of(caller)) else {
        return Ok(Sending::Answered(0));
    };
    let id = queues
        .allocate_sent(Sent {
            receiver: Some(receiver),
            sender: Some(sender),
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
    queues.queues[sender.index as usize].awaiting = Some(id);
    Ok(Sending::Waiting(id))
}

/// The answer to the caller's send `id`, once its receiver gave it (the record goes back to the
/// pool); none while it waits.
pub fn collect_reply(windows: &mut Windows, caller: ThreadId, id: SentId) -> Option<LResult> {
    let queues = &mut windows.queues;
    let sent = queues.sent_at(id)?;
    if sent.state != State::Answered {
        return None;
    }
    let result = sent.result;
    queues.free_sent(id.index);
    if let Some(queue) = queues.queue_of(caller) {
        queues.queues[queue.index as usize].awaiting = None;
    }
    Some(result)
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
/// window manager's, or a thread with no queue; nothing either when the pools are full (the
/// message is lost). `class_atom` is the window's class's atom, for a creation message.
pub fn defer(windows: &mut Windows, target: WindowId, message: &Message, class_atom: class::Atom) {
    let Some(proc) = windows.client_proc(target) else {
        return;
    };
    let thread = windows.window_thread(target);
    let hwnd = windows.handle_of(target);
    let queues = &mut windows.queues;
    let Some(receiver) = queues.queue_of(thread) else {
        return;
    };
    let carried = match message.payload {
        Payload::None => Carried::None,
        Payload::Rect(r) => Carried::Rect(r),
        Payload::WindowPos(w) => Carried::WindowPos(w),
        Payload::Style(style) => Carried::Style(style),
        // The parameters are copied in place: by value they would cross the stack under the
        // creation's own large frame.
        Payload::Create(ref params) => {
            let Some(slot) = queues.creates.iter().position(|s| !s.live) else {
                return;
            };
            let record = &mut queues.creates[slot];
            record.live = true;
            record.class_atom = class_atom;
            record.params = *params;
            Carried::Create(slot as u16)
        }
    };
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
        if let Carried::Create(slot) = carried {
            queues.creates[slot as usize].live = false;
        }
        return;
    };
    queues.push_sent(receiver, id.index);
}

/// The window `window` is being freed: the messages posted to it go, its timers and its update
/// region with them.
pub fn window_gone(windows: &mut Windows, window: WindowId) {
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

/// The pump the services run the window manager's decisions with: every message to a window with a
/// client-side procedure is queued for its thread ([`defer`]) and answered as the default procedure
/// answers; a window's end takes its posted messages, timers and update region with it; the
/// activation and the destroy's focus check are [`super::focus`]'s. The other window-manager calls
/// are [`Pump`]'s defaults.
pub struct QueuePump;

impl Pump for QueuePump {
    fn send(
        &mut self,
        windows: &mut Windows,
        classes: &mut class::Registry,
        target: WindowId,
        message: &mut Message,
    ) -> LResult {
        let class_atom = match message.payload {
            Payload::Create(_) => windows
                .class_window(windows.handle_of(target))
                .map_or(0, |w| classes.atom(w.class)),
            _ => 0,
        };
        defer(windows, target, message, class_atom);
        default_answer(message.message)
    }

    fn activate(
        &mut self,
        windows: &mut Windows,
        classes: &mut class::Registry,
        target: WindowId,
        command: window::Activate,
    ) -> bool {
        super::focus::activate(windows, classes, target, command, self)
    }

    fn check_focus(
        &mut self,
        windows: &mut Windows,
        classes: &mut class::Registry,
        target: WindowId,
    ) {
        super::focus::check_focus(windows, classes, target, self);
    }

    fn window_teardown(&mut self, windows: &mut Windows, target: WindowId) {
        window_gone(windows, target);
    }

    fn disown_clipboard(&mut self, windows: &mut Windows, target: WindowId) {
        crate::win32k::clipboard::disown(windows, target);
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
    use crate::win32k::window::WindowManager;

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
        let (result, wakes, server) = {
            let mut manager = crate::win32k::window::lock(passive);
            let result = f(&mut manager);
            crate::win32k::input::publish(&manager.windows);
            let queues = &mut manager.windows.queues;
            (result, queues.take_wakes(), queues.take_server_wake())
        };
        if server || wakes.iter().any(|&word| word != 0) {
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
        result
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

    /// The interrupt time, the clock the queues' times and the timers' dues read.
    pub fn now() -> u64 {
        crate::interrupt::clock::interrupt_time()
    }
}

#[cfg(target_arch = "x86")]
pub use target::{init, locked, now, wait_for_server, wait_on_queue, with_manager};

#[cfg(target_arch = "x86")]
mod services {
    use rtl::pod::Pod;
    use rtl::user::{
        ONE_PARAM_END_SENT_MESSAGE,
        ONE_PARAM_ENUM_CLIPBOARD_FORMATS,
        ONE_PARAM_IN_SEND_MESSAGE,
        ONE_PARAM_POST_QUIT_MESSAGE,
        ONE_PARAM_REPLY_MESSAGE,
        RECEIPT_TEXT,
        RECEIVED_NONE,
    };

    use super::*;
    use crate::nt::call::{Handle, NtCall, NtResult, UserAddr, UserPtr};
    use crate::win32k::winsta::gui_thread;

    /// The window-name units a receipt's copy goes out in at a time, through a buffer on the
    /// stack.
    const NAME_CHUNK: usize = 32;

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
    /// whose client id is `thread_id`; STATUS_INVALID_CID when no thread that has not ended has
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
        let (thread, key) = found.ok_or(STATUS_INVALID_CID)?;
        let running = crate::ob::locked(|directory| {
            directory.thread_object(crate::sched::thread::ThreadId(key.index))
        })
        .is_some_and(|object| object.generation == key.generation);
        if !running {
            return Err(STATUS_INVALID_CID);
        }
        with_manager(call.passive(), |m| {
            if m.windows.queues.queue_of(thread).is_none() {
                return Err(STATUS_INVALID_CID);
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
        let (first, create, rect, style) = with_manager(call.passive(), |m| {
            let w = &m.windows;
            (
                receipt_head(w, caller, id, base, time),
                receipt_create(w, id, base),
                receipt_rect(w, id),
                receipt_style(w, id),
            )
        });
        let first = first.ok_or(STATUS_INVALID_PARAMETER)?;
        head.write(first)?;
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
        if let Some(create) = create {
            receipt
                .offset(offset_of!(Receipt, create) as u32)
                .cast::<CreateStructW>()
                .write(create)?;
            let name = receipt.offset(offset_of!(Receipt, name) as u32);
            let mut units = [0u16; NAME_CHUNK];
            let mut done = 0;
            loop {
                let got = with_manager(call.passive(), |m| {
                    receipt_name(&m.windows, id, done, &mut units)
                });
                let got = got.min(RECEIPT_TEXT - 1 - done);
                name.offset(2 * done as u32)
                    .write(&units.as_bytes()[..2 * got])?;
                done += got;
                if got < NAME_CHUNK {
                    break;
                }
            }
            name.offset(2 * done as u32).cast::<u16>().write(0)?;
        }
        Ok(STATUS_SUCCESS)
    }

    /// NtUserMessageCall(Window, Msg, wParam, lParam, Proc, Result): SendMessage's kernel side
    /// ([`send`]): the procedure to call into `proc` for a window of the caller's own
    /// thread (`result` 0), otherwise 0 into `proc` and the answer into `result` — the caller
    /// waiting for it when another thread's procedure gives it.
    pub fn message_call(
        call: &mut NtCall,
        window: Handle,
        message: u32,
        wparam: u32,
        lparam: i32,
        proc: UserPtr<u32>,
        result: UserPtr<i32>,
    ) -> NtResult {
        let caller = gui_thread(call)?.thread;
        proc.write(0)?;
        result.write(0)?;
        let sending = with_manager(call.passive(), |m| {
            send(
                &mut m.windows,
                caller,
                window.raw(),
                message,
                wparam,
                lparam,
            )
        })?;
        let answer = match sending {
            Sending::Call(target) => {
                proc.write(target)?;
                return Ok(STATUS_SUCCESS);
            }
            Sending::Answered(answer) => answer,
            Sending::Waiting(id) => loop {
                let reply = with_manager(call.passive(), |m| {
                    collect_reply(&mut m.windows, caller, id)
                });
                match reply {
                    Some(answer) => break answer,
                    None => wait_on_queue(caller, None),
                }
            },
        };
        result.write(answer)?;
        Ok(STATUS_SUCCESS)
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
        let answer = with_manager(call.passive(), |m| match routine {
            ONE_PARAM_POST_QUIT_MESSAGE => {
                post_quit(&mut m.windows, caller, param);
                Ok(0)
            }
            ONE_PARAM_REPLY_MESSAGE => Ok(reply(&mut m.windows, caller, param as LResult) as u32),
            ONE_PARAM_END_SENT_MESSAGE => {
                Ok(end_sent(&mut m.windows, caller, param as LResult) as u32)
            }
            ONE_PARAM_ENUM_CLIPBOARD_FORMATS => m
                .clipboard
                .next_format(caller, param)
                .map_err(crate::win32k::clipboard::Refusal::status),
            ONE_PARAM_IN_SEND_MESSAGE => Ok(in_send(&m.windows, caller) as u32),
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

    pub fn message_call(
        _: &mut NtCall,
        _: Handle,
        _: u32,
        _: u32,
        _: i32,
        _: UserPtr<u32>,
        _: UserPtr<i32>,
    ) -> NtResult {
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
/// threads with their queues, and windows of the class made through the queue's pump.
#[cfg(test)]
pub(crate) mod rig {
    use super::*;
    use crate::win32k::window::{
        CreateArgs,
        MenuInput,
        Rect,
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
    /// top-level window), made by `t` through the queue's pump: its handle.
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
        m.create_window(t, parent, &mut args, &mut QueuePump)
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

    /// A window's creation reaches its procedure as the capture counts it: WM_NCCREATE,
    /// WM_NCCALCSIZE, WM_CREATE, WM_SIZE and WM_MOVE, in that order, queued for its thread as
    /// sent messages; the window exists at once (the default procedure's answers carried the
    /// decisions).
    #[test]
    fn a_creation_sends_its_messages_through_the_queue() {
        let (m, atom) = manager();
        let t = thread(m, 1, 0x100);
        let h = popup(m, atom, t);
        assert!(m.windows.window_from_handle(h).is_some());
        assert_eq!(
            deliver(m, t),
            vec![
                (h, WM_NCCREATE),
                (h, WM_NCCALCSIZE),
                (h, WM_CREATE),
                (h, WM_SIZE),
                (h, WM_MOVE)
            ]
        );
        assert_eq!(deliver(m, t), vec![], "each one once");
    }

    /// The receipt of a creation message: the class's procedure, lParam pointing at the receipt's
    /// CREATESTRUCTW, whose fields are the creation's (the final position, the name pointing at the
    /// receipt's copy, the class's atom); WM_NCCALCSIZE's lParam points at the receipt's rectangle.
    #[test]
    fn a_creation_messages_receipt_carries_its_structure() {
        let (m, atom) = manager();
        let t = thread(m, 1, 0x100);
        let h = window_at(m, atom, t, WS_POPUP, 0, 5, 6, 30, 40);
        let base = 0x0010_0000;
        let Taken::Sent(id) = read(m, t, &all(), 0) else {
            panic!("WM_NCCREATE first");
        };
        let head = receipt_head(&m.windows, t, id, base, 7).unwrap();
        assert_eq!(head.kind, RECEIVED_SENT);
        assert_eq!(head.proc, PROC);
        assert_eq!(
            (head.msg.hwnd, head.msg.message, head.msg.time),
            (h, WM_NCCREATE, 7)
        );
        assert_eq!(head.msg.lparam as u32, base + 36);
        let cs = receipt_create(&m.windows, id, base).unwrap();
        assert_eq!((cs.x, cs.y, cs.cx, cs.cy), (5, 6, 30, 40));
        assert_eq!(cs.create_params, 0x1234);
        assert_eq!(cs.instance, MODULE);
        assert_eq!(cs.style, WS_POPUP);
        assert_eq!(cs.name, base + 128);
        assert_eq!(cs.class, u32::from(atom));
        let mut units = [0u16; 3];
        assert_eq!(receipt_name(&m.windows, id, 0, &mut units), 3);
        assert_eq!(&units, &[b'T' as u16, b'i' as u16, b't' as u16]);
        assert_eq!(receipt_name(&m.windows, id, 3, &mut units), 2, "the rest");
        assert_eq!(receipt_rect(&m.windows, id), None);
        assert!(end_sent(&mut m.windows, t, 1));

        let Taken::Sent(id) = read(m, t, &all(), 0) else {
            panic!("WM_NCCALCSIZE next");
        };
        let head = receipt_head(&m.windows, t, id, base, 0).unwrap();
        assert_eq!(head.msg.message, WM_NCCALCSIZE);
        assert_eq!(head.msg.lparam as u32, base + 84);
        let r = receipt_rect(&m.windows, id).unwrap();
        assert_eq!((r.left, r.top, r.right, r.bottom), (5, 6, 35, 46));
        assert_eq!(receipt_create(&m.windows, id, base), None);
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
        windows
            .destroy_window_handle(classes, t, h, &mut QueuePump)
            .unwrap();
        assert!(m.windows.window_from_handle(h).is_none());
        assert_eq!(deliver(m, t), vec![(h, WM_DESTROY), (h, WM_NCDESTROY)]);
        let msg = msg_of(read(m, t, &all(), 0));
        assert_eq!(
            (msg.hwnd, msg.message),
            (0, WM_USER + 2),
            "the window's own went"
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
        assert_eq!(deliver(m, t).len(), 4);
        let only_sent = Filter::new(0, 0, 0, PM_QS_SENDMESSAGE);
        assert_eq!(read(m, t, &only_sent, 0), Taken::Nothing { due: None });
        assert_eq!(msg_of(read(m, t, &all(), 0)).message, WM_USER);
        assert!(
            !end_sent(&mut m.windows, t, 0),
            "nothing is being delivered"
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
    /// never handed out; a queue that ends answers 0 to what was sent to it, and what was posted
    /// to it goes.
    #[test]
    fn a_send_to_a_window_or_queue_gone_answers_zero() {
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
        windows
            .destroy_window_handle(classes, b, hb, &mut QueuePump)
            .unwrap();
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
        assert_eq!(collect_reply(&mut m.windows, a, id), Some(0));
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
        windows
            .destroy_window_handle(classes, b, hb, &mut QueuePump)
            .unwrap();
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

    /// The posted messages' pool is shared and bounded: a full pool refuses the post; a message
    /// taken out gives its entry back.
    #[test]
    fn a_full_pool_refuses_the_post() {
        let (m, _) = manager();
        let t = thread(m, 1, 0x100);
        for _ in 0..POSTED {
            post(&mut m.windows, t, 0, WM_USER, 0, 0, 0).unwrap();
        }
        assert_eq!(
            post(&mut m.windows, t, 0, WM_USER, 0, 0, 0),
            Err(STATUS_INSUFFICIENT_RESOURCES)
        );
        read(m, t, &all(), 0);
        post(&mut m.windows, t, 0, WM_USER, 0, 0, 0).unwrap();
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
}
