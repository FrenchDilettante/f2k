//! The queues' registry ([`Queues`]): the queue records, the message pools, and the links
//! between them.

use rtl::user::{Msg, QS_ALLPOSTMESSAGE, QS_POSTMESSAGE, QS_SENDMESSAGE};
// ERROR_NOT_ENOUGH_QUOTA: the post past [`POSTED_LIMIT`]'s refusal, as win32k carries it.
use rtl::winerror::ERROR_NOT_ENOUGH_QUOTA;

use super::*;
use crate::sched::thread::ThreadId;
use crate::slots;
use crate::status::*;
use crate::win32k::text::Texts;
use crate::win32k::window::LResult;

/// The queues, the pools their messages come from, the timers ([`crate::win32k::timer`]) and the
/// windows' update regions ([`crate::win32k::paint`]): the message layer's state, in the window
/// registry, behind the window manager's lock.
pub struct Queues {
    /// The thread records' queues, at the records' indices: made with the record
    /// ([`Queues::make`]) and kept at their peak.
    pub(super) queues: slots::Records<Queue, QUEUES_PER_CHUNK>,
    pub(super) posted: crate::win32k::posted::Pool<Posted>,
    pub(super) sent: SentPool,
    /// The texts the sent messages carry: a text to another process's window.
    pub(super) store: Texts,
    pub timers: crate::win32k::timer::Timers,
    pub updates: crate::win32k::paint::Updates,
    /// The queues something was given since the last [`Queues::take_wakes`]: their events are set
    /// once the lock is let go.
    wakes: Wakes,
    /// A send the server waits on was answered or dropped since the last
    /// [`Queues::take_server_wake`]: the server's event is set once the lock is let go.
    pub(super) server_wake: bool,
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
            addr_of_mut!((*queues).posted).write(crate::win32k::posted::Pool::EMPTY);
            addr_of_mut!((*queues).sent).write(SentPool::EMPTY);
            addr_of_mut!((*queues).store).write(Texts::EMPTY);
            crate::win32k::timer::Timers::write_empty(addr_of_mut!((*queues).timers));
            crate::win32k::paint::Updates::write_empty(addr_of_mut!((*queues).updates));
            addr_of_mut!((*queues).wakes).write(Wakes::NONE);
            addr_of_mut!((*queues).server_wake).write(false);
        }
    }

    /// Make the queue of the thread record `index` (and its event), with the record: false when
    /// no page is left for it. What is made stays, for the next record at the index.
    pub fn make(&mut self, index: u16) -> bool {
        self.queues
            .ensure(index.into(), crate::win32k::pages())
            .is_ok()
            && make_event(index)
    }

    /// The live queues, by their thread records.
    pub(super) fn live_queues(&self) -> impl Iterator<Item = (ThreadId, &Queue)> + '_ {
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

    pub(super) fn wake(&mut self, id: QueueId) {
        self.wakes.add(id.index);
    }

    /// The queue was given something of the kinds `changed`: marked for WaitMessage, and woken.
    pub(super) fn change(&mut self, id: QueueId, changed: u32) {
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
    pub(super) fn push_posted(&mut self, id: QueueId, msg: Msg) -> Result<(), NtStatus> {
        if self.queues[id.index as usize].posted.count >= POSTED_LIMIT {
            return Err(NtStatus::from_win32(ERROR_NOT_ENOUGH_QUOTA));
        }
        self.push(id, Lane::Posted, msg, 0)
    }

    /// Append `msg` (an input message's key `key`) to the queue's lane `lane`:
    /// STATUS_INSUFFICIENT_RESOURCES when the pool cannot grow.
    pub(super) fn push(
        &mut self,
        id: QueueId,
        lane: Lane,
        msg: Msg,
        key: u8,
    ) -> Result<(), NtStatus> {
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
    pub(super) fn unlink_posted(
        &mut self,
        index: u16,
        lane: Lane,
        previous: Option<u32>,
        entry: u32,
    ) {
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
    pub(super) fn purge_posted(&mut self, index: u16, drop: impl Fn(&Msg) -> bool) {
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
    pub(super) fn sent_at(&self, id: SentId) -> Option<&Sent> {
        self.sent.get(id)
    }

    /// A fresh sent message from the pool; none when it cannot grow.
    pub(super) fn allocate_sent(&mut self, record: Sent) -> Option<SentId> {
        self.sent.allocate(record)
    }

    /// Give the sent message `id` back to the pool, the text it carries with it.
    pub(super) fn free_sent(&mut self, id: SentId) {
        if let Carried::Text(text) = self.sent.at(id).carried {
            self.store.free(text);
        }
        self.sent.free(id);
    }

    /// Append the sent message `id` to its receiver's list, and wake the receiver.
    pub(super) fn push_sent(&mut self, receiver: QueueId, id: SentId) {
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
    pub(super) fn answer(&mut self, id: SentId, result: LResult) {
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
    pub(super) fn drop_unanswered(&mut self, id: SentId) {
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
    pub(super) fn unlink_sent(&mut self, receiver: QueueId, id: SentId) {
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
    pub(super) fn pop_sent(&mut self, id: QueueId) -> Option<SentId> {
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
    pub(super) fn leave_stack(&mut self, id: SentId) {
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
    pub(super) fn collected(&mut self, id: SentId) {
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
    pub(super) fn end_queue(&mut self, index: u16) {
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
