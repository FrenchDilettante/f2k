//! Message queues: each thread's posted, input and sent messages and its WM_QUIT; the reads that
//! take them in Windows 2000's documented order; and the session the window manager's decisions
//! send through ([`QueueSession`]).
//!
//! A queue ([`Queues`], in the window registry, behind its lock) belongs to a thread record
//! ([`window::Thread`]), made at the thread's first win32k service (which makes it a GUI thread, as
//! on Windows 2000), and is named by a generation-tagged id ([`QueueId`]). Posted messages are
//! entries of one shared pool that grows a page at a time ([`super::posted`]), linked oldest first
//! in two lanes: those posted to the thread, at most [`POSTED_LIMIT`] (USERPostMessageLimit), and
//! the input messages ([`super::input`], [`post_input`]), which the limit does not count.
//!
//! A read ([`take`]) answers in the documented order: the sent messages; the posted messages its
//! filter takes; the input messages, each bound to its window as it is read
//! ([`super::input::bind`]: the focus window then, not at the key press), a key message updating
//! the key state; PostQuitMessage's WM_QUIT; a WM_PAINT for a window with an update region
//! ([`super::paint`]); a WM_TIMER for a due timer ([`super::timer`]). WM_QUIT, WM_PAINT and
//! WM_TIMER are never posted: a read makes them when nothing posted comes first, as Windows 2000
//! does. A read that finds nothing blocks GetMessage on its queue's event, set by a post, a send,
//! an answer, a timer set or an invalidation; the wait is the scheduler's, outside the lock, its
//! timeout the thread's next timer's due.
//!
//! A decision's message to a window of the deciding thread's own with a client-side procedure (the
//! creation's WM_NCCREATE to WM_MOVE, the destruction's WM_DESTROY and WM_NCDESTROY, what showing,
//! moving and activating send) is a callback into user mode (KeUserModeCallback,
//! [`crate::user::callback`]) with the lock let go, its answer coming back to the decision
//! ([`QueueSession`]), as Windows 2000's `xxx` routines call back. So a zero answer to WM_NCCREATE
//! cancels the creation, -1 to WM_CREATE fails it, and what the procedure does meanwhile (SetFocus
//! from WM_ACTIVATE, a window made from WM_CREATE) happens inside the decision, in Windows' order.
//! The structure handed to the procedure comes back through the callback's output block, bounded by
//! its size ([`read_back`]): WM_NCCALCSIZE's client rectangle, WM_WINDOWPOSCHANGING's new place,
//! WM_STYLECHANGING's new style, WM_GETMINMAXINFO's sizes. A message to another thread's window is
//! queued for that thread as a sent message with the window manager's copy of the structure, the
//! decision waiting for the answer with the lock let go ([`send_for_decision`],
//! [`decision_reply`]), as `xxxInterSendMsgEx` waits; a receiver that ends first fails the send
//! (answered 0, the structure as sent). Another thread's activation is not waited for: Windows 2000
//! hands it to that thread as an event, F2K queues its messages for it ([`defer`],
//! [`Session::queue_for`]), as for a decision of a thread with no queue (the console server's), the
//! decision going on with the default procedure's answer.
//!
//! Sent messages reach their procedures by callback from inside the receiving thread's own calls,
//! oldest first, before anything posted, as xxxReceiveMessage delivers them: GetMessage and
//! PeekMessage deliver them all before reading on, WaitMessage those that woke it, and a thread
//! waiting for an answer (its SendMessage, or a decision's send) those that come meanwhile
//! ([`take_for_callback`], [`delivery`], [`end_received`]), so two threads that send to each other
//! do not wait on each other. The callback carries the window manager's copy of the structure, its
//! in-out part coming back to the sender; a text another process's message carries goes in the
//! callback's block, WM_GETTEXT's answer in its output block ([`rtl::callback`]'s text slots).
//!
//! SendMessage to another thread's window is queued the same way, its sender waiting ([`send`],
//! [`await_reply`]); to a window of its own thread, the service names the procedure and user32
//! calls it, as Windows 2000's user32 does. So do the console server's WM_QUERYENDSESSION and
//! WM_ENDSESSION at the session's end ([`server_send`]), the server, which has no queue, waiting on
//! an event of its own ([`wait_for_server`]). SendMessageTimeout waits no longer than its timeout,
//! a message not read by then taken back ([`abandon_send`]); SendNotifyMessage waits for nothing,
//! its message answered to nobody ([`send_notify`]). Sent messages are records of a slot pool
//! ([`crate::slots`]) that grows a page at a time and keeps its peak, named by ids their slot's
//! count checks ([`SentId`]).
//!
//! A queue keeps Windows 2000's state of its thread's reads: the kinds of message given since a
//! read last looked for them (the change bits WaitMessage wakes on, [`wait_ready`]: a message a
//! peek saw and left is no longer new), the last retrieved message's time and cursor position
//! (GetMessageTime, GetMessagePos), and when the thread last read and whether that read found
//! nothing: a thread that has not read for [`HUNG_TIMEOUT`] after finding something is hung
//! ([`hung`]: IsHungAppWindow, SendMessageTimeout's SMTO_ABORTIFHUNG).
//!
//! Services (F2K's argument lists, see [`crate::win32k`]):
//!
//! - NtUserPostMessage(handle Window, u32 Msg, u32 wParam, i32 lParam): a null window posts to the
//!   calling thread, HWND_BROADCAST to every top-level window of the caller's desktop;
//! - NtUserPostThreadMessage(u32 ThreadId, u32 Msg, u32 wParam, i32 lParam);
//! - NtUserGetMessage(ptr Receipt, handle Window, u32 MsgFilterMin, u32 MsgFilterMax): waits for a
//!   message, the sent messages delivered first;
//! - NtUserPeekMessage(ptr Receipt, handle Window, u32 MsgFilterMin, u32 MsgFilterMax, u32
//!   RemoveMsg): the same without waiting (RECEIVED_NONE for nothing);
//! - NtUserMessageCall(handle Window, u32 Msg, u32 wParam, i32 lParam, ptr<u32> Proc, ptr<i32>
//!   Result, ptr Timeout): SendMessage and SendMessageTimeout (rtl::user::SendTimeout; null for
//!   SendMessage): the procedure to call for the caller's own window, or the answer, STATUS_TIMEOUT
//!   for none in time;
//! - NtUserSendNotifyMessage(handle Window, u32 Msg, u32 wParam, i32 lParam, ptr<u32> Proc): the
//!   procedure to call for the caller's own window, or 0;
//! - NtUserWaitMessage(): the sent messages that woke it delivered;
//! - NtUserDispatchMessage(ptr Msg, ptr<u32> Proc): the procedure DispatchMessage calls;
//! - NtUserCallOneParam(u32 Param, u32 Routine, ptr<u32> Result): PostQuitMessage, ReplyMessage,
//!   InSendMessage, IsHungAppWindow ([`rtl::user`]'s ONE_PARAM_* routines).
//!
//! [`window::Thread`]: super::window::Thread
//! [`Session::queue_for`]: super::window::Session::queue_for

mod callback;
mod decision;
mod delivering;
mod lives;
mod posting;
mod queues;
mod read;
mod records;
mod sending;
mod server;
#[cfg(target_arch = "x86")]
mod services;
#[cfg(not(target_arch = "x86"))]
mod services_host;
mod session;
#[cfg(target_arch = "x86")]
mod target;
#[cfg(test)]
pub(crate) mod testkit;
mod wait;

pub use self::callback::*;
pub use self::decision::*;
pub use self::delivering::*;
pub use self::lives::*;
pub use self::posting::*;
pub use self::queues::*;
pub use self::read::*;
pub use self::records::*;
pub use self::sending::*;
pub use self::server::*;
// The services; msg_wait, MsgWaitForMultipleObjects' wait, x86 only: caret's
// NtUserCallTwoParam routes its routine here.
#[cfg(target_arch = "x86")]
pub use self::services::*;
#[cfg(not(target_arch = "x86"))]
pub use self::services_host::*;
pub use self::session::*;
#[cfg(target_arch = "x86")]
use self::target::make_event;
#[cfg(target_arch = "x86")]
pub use self::target::{
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
// The message layer's test rig, by its old name.
#[cfg(test)]
pub(crate) use self::testkit as rig;
pub use self::wait::*;
