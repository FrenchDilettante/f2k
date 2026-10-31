//! The dispatcher: the ready queues, the processor's thread slots, and the dispatcher database.
//!
//! One processor. The dispatcher owns the ready lists — one per priority level, summarized in a
//! 32-bit bitmap whose bit P is set while ready list P is non-empty — and writes the processor's
//! three thread slots, which the processor control region keeps ([`super::processor`]): `current`
//! (Running), `next` (the Standby thread the next switch will enter) and `idle` (the resting
//! thread, installed by the boot). Selection is the bitmap: the highest set bit at or above the
//! floor names the queue, whose head is taken first-in, first-out. It also owns the records all of
//! this links (see [`super::database`]): threads are named by their index there.
//!
//! The state machines below decide, from a thread's state, what a change of priority, a boost, or
//! the end of a quantum does to the queues and the slots. They never switch: selecting the next
//! thread stops at Standby, and turning Standby into Running is the context switch's business.

use super::apc::ApcId;
use super::database::Database;
use super::list::{self, Cursor, IndexList, ListKind};
use super::process::{ProcessRef, ProcessThreads, SchedProcess};
use super::processor::{charged_tick, ThreadSlots};
use super::thread::{Thread, ThreadId, ThreadState};
use super::timer::TimerTable;
use super::wait::WaitingList;
use super::{
    HIGHEST_PRIORITY,
    PRIORITY_LEVELS,
    QUANTUM_WAIT_CHARGE,
    REALTIME_BASE,
    ROUND_TRIP_LIMIT,
    TIME_CRITICAL_CEILING,
};
#[cfg(target_arch = "x86")]
use crate::level::{At, Dispatch};

/// The priority increment a termination's exit APC grants the thread whose wait it breaks
/// (Windows 2000's PspTerminateThreadByPointer queues it with 2): the thread runs its exit soon.
pub const EXIT_APC_INCREMENT: i8 = 2;

/// How long a thread sits ready without running before the balance-set scan boosts it, in ticks:
/// the platform's constant (four of its nominal 75-tick seconds), about three seconds at this
/// clock's 10 ms tick.
pub const READY_WITHOUT_RUNNING: u64 = 4 * 75;
/// How many ready threads one balance-set scan examines at most.
pub const THREAD_SCAN_LIMIT: usize = 16;
/// How many ready threads one balance-set scan boosts at most.
pub const THREAD_READY_LIMIT: usize = 10;

/// The ready queue of one priority level.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ReadyQueue(pub u8);

impl ListKind for ReadyQueue {
    type Entry = ThreadId;
}

/// The dispatcher: ready queues, the summary, and the database. The processor slots it writes are
/// the processor control region's ([`ThreadSlots`]).
pub struct Dispatcher {
    /// One ready list per priority level.
    pub(super) ready: [IndexList<ReadyQueue>; PRIORITY_LEVELS],
    /// Bit P set while `ready[P]` is non-empty.
    ready_summary: u32,
    /// Whether the processor is running its idle thread (and a readied thread takes it
    /// immediately).
    processor_idle: bool,
    /// The waiting threads: the blocked-on-a-wait set, for the audit's walk.
    pub(super) waiting: IndexList<WaitingList>,
    /// The timer table: the due-time-ordered home of wait timeouts, driven by the clock's deferred
    /// expiry work.
    pub(super) timer_table: TimerTable,
    /// The priority level the next balance-set scan starts at (the scans take turns over the
    /// levels).
    scan_level: i8,
    /// The records: threads, the dispatcher objects' bodies, the APC records.
    pub(crate) db: Database,
}

// SAFETY: the dispatcher's raw pointers name pinned process records (a thread's owner and
// address-space process) and embedded waitable headers, each kept alive and in place by its owner
// while linked. One processor, and the dispatcher is reached only through its dispatch-level cell,
// so whichever kernel thread holds the token is the only one reaching what they point at.
unsafe impl Send for Dispatcher {}

impl Dispatcher {
    /// Write an empty dispatcher at `dispatcher`: empty queues, empty processor slots, an empty
    /// timer table on the clock's interval, and a fresh database.
    ///
    /// # Safety
    ///
    /// `dispatcher` is valid for writes, aligned, and the records' final address; its previous
    /// contents are overwritten, not dropped.
    pub unsafe fn write_empty(dispatcher: *mut Dispatcher) {
        use core::ptr::addr_of_mut;
        // SAFETY: the caller's contract; every field is written.
        unsafe {
            addr_of_mut!((*dispatcher).ready).write([IndexList::new(); PRIORITY_LEVELS]);
            addr_of_mut!((*dispatcher).ready_summary).write(0);
            addr_of_mut!((*dispatcher).processor_idle).write(false);
            addr_of_mut!((*dispatcher).waiting).write(IndexList::new());
            addr_of_mut!((*dispatcher).timer_table).write(TimerTable::new(
                crate::interrupt::clock::INTERVAL_100NS as u64,
            ));
            addr_of_mut!((*dispatcher).scan_level).write(1);
            Database::write_empty(addr_of_mut!((*dispatcher).db));
        }
        slots().reset();
        TimerTable::publish_empty();
    }

    /// The ready-summary and wait-structure invariants: bit P is set exactly while ready list P is
    /// non-empty, and the wait blocks and waiting threads agree.
    pub fn audit(&self) -> Result<(), &'static str> {
        let mut summary = 0u32;
        for (level, queue) in self.ready.iter().enumerate() {
            if !queue.is_empty() {
                summary |= 1 << level;
            }
        }
        if summary != self.ready_summary {
            return Err("ready summary does not match the ready queues");
        }
        self.audit_waits()
    }

    /// The Standby thread, if one is selected.
    pub fn next_thread(&self) -> Option<ThreadId> {
        slots().next()
    }

    /// Select `thread` into the standby slot, or empty it.
    fn set_next(&mut self, thread: Option<ThreadId>) {
        slots().set_next(thread);
    }

    /// The Running thread (see [`super::current_thread`]).
    pub fn current(&self) -> Option<ThreadId> {
        slots().current()
    }

    /// The idle thread, once installed.
    pub fn idle_thread(&self) -> Option<ThreadId> {
        slots().idle()
    }

    /// Whether the processor is running its idle thread.
    pub fn processor_idle(&self) -> bool {
        self.processor_idle
    }

    /// Whether a switch away from the idle thread is warranted: a Standby thread is pending or any
    /// ready queue is non-empty. The idle loop's next-thread check, as a query.
    pub fn has_schedulable(&self) -> bool {
        self.next_thread().is_some() || self.ready_summary != 0
    }

    /// Attach `thread` (a renewed record) to `process`: take the process's base priority, quantum
    /// and boost policy, join its thread list, and account the kernel stack. After this the thread
    /// is Initialized and schedulable.
    ///
    /// # Safety
    ///
    /// `process` is a live record at its final address, reached by nothing else meanwhile, and
    /// outlives the thread's membership in its list.
    pub unsafe fn attach(&mut self, thread: ThreadId, process: *mut SchedProcess) {
        // SAFETY: the caller's contract: the record is live, and this is the only reference to it.
        let process = unsafe { &mut *process };
        let record = self.thread_mut(thread);
        // Every thread is attached at its final address before it first runs: the place the
        // switch saves its floating-point state to.
        assert!(
            (core::ptr::addr_of!(record.fpu) as usize)
                .is_multiple_of(super::thread::FPU_STATE_ALIGN),
            "a thread's floating-point area is 16-byte aligned"
        );
        record.take_process_data(process);
        if process.stack_count == super::process::NO_THREADS {
            process.stack_count = 1;
        } else {
            process.stack_count += 1;
        }
        process.thread_seed = process.thread_seed.wrapping_add(1);
        list::push_back(self, ProcessThreads(ProcessRef::new(process)), thread);
    }

    /// The owning process of `thread`, to change, for as long as this borrow of the dispatcher.
    fn owner_mut(&mut self, thread: ThreadId) -> &mut SchedProcess {
        let process = ProcessRef::of(self.thread(thread).process);
        // SAFETY: the reference lives as long as this exclusive borrow of the dispatcher, which
        // serializes every use of the attached thread's process record.
        unsafe { process.get_mut() }
    }

    /// Begin running `thread` on `target`'s address space (see [`super::attach`]): the thread's
    /// bookkeeping, and the target's count of threads attached to it. Returns the directory to
    /// load, or none when `target` is the thread's address space already (a scope that changes
    /// nothing).
    ///
    /// # Panics
    ///
    /// The thread is attached to another process already: attaches do not nest.
    pub(crate) fn attach_space(
        &mut self,
        thread: ThreadId,
        target: *mut SchedProcess,
    ) -> Option<u32> {
        let target = ProcessRef::of(target);
        // SAFETY: the target outlives the scope (the attach's contract: its caller holds it), and
        // this exclusive borrow of the dispatcher serializes every use of it; the thread record is
        // another record than the process's.
        let target = unsafe { target.get_mut() };
        let dir_phys = self.thread_mut(thread).attach_space(target)?;
        target.attach_count += 1;
        Some(dir_phys)
    }

    /// Return `thread` to its own address space, from the one it attached to: the thread's
    /// bookkeeping, and the count of threads attached to that one. Kernel APCs the scope held off
    /// have their delivery armed again, for the thread's next window (Windows 2000's
    /// KeUnstackDetachProcess requests the APC interrupt for them). Returns the owner's directory,
    /// to load.
    ///
    /// # Panics
    ///
    /// The thread is not attached.
    pub(crate) fn detach_space(&mut self, thread: ThreadId) -> u32 {
        let space = ProcessRef::of(self.thread(thread).space.cast_mut());
        let record = self.thread_mut(thread);
        let dir_phys = record.detach_space();
        if !record.kernel_apcs.is_empty() {
            record.kernel_apc_pending = true;
        }
        // SAFETY: the process attached to outlives the scope, which ends here, and this exclusive
        // borrow of the dispatcher serializes every use of it.
        let space = unsafe { space.get_mut() };
        space.attach_count -= 1;
        dir_phys
    }

    /// The first attached thread of `process` other than `except` that is not terminating already,
    /// in creation order, or none. A process-ending termination repeats this query, one termination
    /// per answer: each marks its thread terminating (it stays attached until its own exit), so the
    /// walk never holds a link across a change and never answers the same thread twice.
    pub fn first_thread_except(
        &self,
        process: *mut SchedProcess,
        except: Option<ThreadId>,
    ) -> Option<ThreadId> {
        list::iter(self, ProcessThreads(ProcessRef::of(process)))
            .find(|&thread| Some(thread) != except && !self.thread(thread).terminate_pending)
    }

    /// Whether any attached thread of `process` satisfies `test`.
    pub fn any_thread_of(
        &self,
        process: *mut SchedProcess,
        test: impl Fn(&Thread) -> bool,
    ) -> bool {
        list::iter(self, ProcessThreads(ProcessRef::of(process)))
            .any(|thread| test(self.thread(thread)))
    }

    /// Install the idle thread and mark the processor idle. The boot install: the processor is
    /// executing this very thread, so it also takes the current slot.
    pub fn install_idle_thread(&mut self, thread: ThreadId) {
        let slots = slots();
        slots.set_idle(Some(thread));
        self.processor_idle = true;
        slots.set_current(Some(thread));
        slots.set_next(None);
        self.thread(thread).switch_in();
    }

    /// The switching path's caller-side install: the selected thread takes the current slot, and
    /// the processor is marked idle exactly when it is the idle thread with nothing schedulable
    /// (a process's last thread hands the processor to the idle thread for its reap even with
    /// threads ready: those keep their places, and a thread readied meanwhile competes with them
    /// rather than taking the standby slot of an idle processor). The running thread's
    /// quantum and user-copy attribution go back to its record and the selected thread's come out
    /// of its own, masked: the clock charges the slot, and no tick may land between the two
    /// halves. The Standby-to-Running state write is the swap's own effect.
    pub fn enter(&mut self, selected: ThreadId) {
        let slots = slots();
        let _masked = crate::pcr::pcr().mask_guard();
        if let Some(running) = slots.current() {
            self.thread_mut(running).switch_out();
        }
        slots.set_current(Some(selected));
        self.thread(selected).switch_in();
        self.processor_idle = Some(selected) == slots.idle() && !self.has_schedulable();
    }

    /// Select the highest-priority ready thread at or above `floor`, unlinking it from its queue.
    /// None if no thread qualifies.
    pub fn find_ready(&mut self, floor: i8) -> Option<ThreadId> {
        debug_assert!((0..=HIGHEST_PRIORITY).contains(&floor));
        let mask = !((1u32 << floor as u32).wrapping_sub(1));
        let set = mask & self.ready_summary;
        if set == 0 {
            return None;
        }
        // The highest set bit names the queue; the summary keeps it non-empty.
        let level = HIGHEST_PRIORITY - set.leading_zeros() as i8;
        let queue = ReadyQueue(level as u8);
        let thread = list::pop_front(self, queue).expect("a summary bit names a non-empty queue");
        if list::is_empty(self, queue) {
            self.ready_summary &= !(1 << level as u32);
        }
        Some(thread)
    }

    /// Make `thread` runnable: give it the processor if it can take it, else queue it.
    ///
    /// The taking order: an idle processor first; then the Standby slot; then the Running thread —
    /// strictly higher priority wins, equals never preempt. A thread pushed off the processor (or
    /// out of the standby slot) is marked preempted and re-readied through this same path, which
    /// puts it at the head of its queue; a thread that merely became runnable queues at the tail.
    pub fn make_ready(&mut self, thread: impl Into<ThreadId>) {
        let mut thread = thread.into();
        let record = self.thread(thread);
        assert!(
            !(record.state == ThreadState::Waiting && record.wait_block_head.is_some()),
            "a waiting thread is readied only through the wait exit"
        );
        loop {
            let record = self.thread_mut(thread);
            let preempted = core::mem::replace(&mut record.preempted, false);
            let priority = record.priority;

            if self.processor_idle {
                self.processor_idle = false;
                self.set_next(Some(thread));
                self.thread_mut(thread).state = ThreadState::Standby;
                return;
            }

            if let Some(standby) = self.next_thread() {
                if priority > self.thread(standby).priority {
                    self.thread_mut(standby).preempted = true;
                    self.set_next(Some(thread));
                    self.thread_mut(thread).state = ThreadState::Standby;
                    thread = standby;
                    continue;
                }
            } else if let Some(current) = self.current() {
                // No standby thread: try the running thread. None (the processor is between
                // threads) counts as non-preemptable.
                if priority > self.thread(current).priority {
                    self.thread_mut(current).preempted = true;
                    self.set_next(Some(thread));
                    self.thread_mut(thread).state = ThreadState::Standby;
                    // Asking the processor to redispatch is a no-op on one CPU: the dispatch level
                    // this runs at is itself the serialization.
                    return;
                }
            }

            // Nobody to preempt: queue by priority, stamped with the tick it joins at.
            let tick = tick_count();
            let record = self.thread_mut(thread);
            record.state = ThreadState::Ready;
            record.wait_time = tick;
            let queue = ReadyQueue(priority as u8);
            if preempted {
                list::push_front(self, queue, thread);
            } else {
                list::push_back(self, queue, thread);
            }
            self.ready_summary |= 1 << priority as u32;
            return;
        }
    }

    /// The thread the processor runs next: a pending Standby thread first, else the
    /// highest-priority ready thread, else the idle thread (with the processor marked idle so the
    /// next readied thread takes it immediately). None only before the boot installs the idle
    /// thread. The returned thread's state is the caller's to set — the context switch flips
    /// Standby to Running.
    pub fn select_next(&mut self) -> Option<ThreadId> {
        if let Some(selected) = self.next_thread() {
            self.set_next(None);
            return Some(selected);
        }
        let selected = self.find_ready(0);
        if selected.is_none() {
            self.processor_idle = true;
            return self.idle_thread();
        }
        selected
    }

    /// Take a Ready `thread` off its queue at `level`, clearing the level's summary bit when the
    /// queue empties.
    fn dequeue(&mut self, thread: ThreadId, level: i8) {
        let queue = ReadyQueue(level as u8);
        list::remove(self, queue, thread);
        if list::is_empty(self, queue) {
            self.ready_summary &= !(1 << level as u32);
        }
    }

    /// Apply `priority` to `thread` and let its state decide what moves: a Ready thread requeues
    /// (lowered) or re-readies (raised); a Standby or Running thread being lowered looks for a
    /// replacement at or above the new priority; every other state takes the field change alone.
    /// Equal priority is a complete no-op.
    ///
    /// This is the raw state machine: it does not touch the quantum or the decay fields.
    /// [`Dispatcher::set_priority`] is the full form callers outside the scheduler use.
    pub fn apply_priority(&mut self, thread: impl Into<ThreadId>, priority: i8) {
        let thread = thread.into();
        let record = self.thread_mut(thread);
        let old = record.priority;
        if priority == old {
            return;
        }
        record.priority = priority;
        let (parked_on_process, state) = (record.parked_on_process, record.state);

        match state {
            ThreadState::Ready => {
                if parked_on_process {
                    // The parked shape never has a ready-queue membership to move.
                    return;
                }
                self.dequeue(thread, old);
                if priority < old {
                    list::push_back(self, ReadyQueue(priority as u8), thread);
                    self.ready_summary |= 1 << priority as u32;
                } else {
                    self.make_ready(thread);
                }
            }
            ThreadState::Standby => {
                if priority < old {
                    if let Some(replacement) = self.find_ready(priority) {
                        self.thread_mut(replacement).state = ThreadState::Standby;
                        self.set_next(Some(replacement));
                        self.make_ready(thread);
                    }
                }
            }
            ThreadState::Running if self.next_thread().is_none() && priority < old => {
                if let Some(replacement) = self.find_ready(priority) {
                    self.thread_mut(replacement).state = ThreadState::Standby;
                    self.set_next(Some(replacement));
                }
            }
            _ => {}
        }
    }

    /// Set `thread`'s priority the full form: replenish its quantum, clear the decay fields, then
    /// run the state machine. Returns the previous priority.
    pub fn set_priority(&mut self, thread: impl Into<ThreadId>, priority: i8) -> i8 {
        let thread = thread.into();
        let record = self.thread_mut(thread);
        let old = record.priority;
        let thread_quantum = record.thread_quantum();
        record.set_quantum(thread_quantum);
        record.decrement_count = 0;
        record.priority_decrement = 0;
        self.apply_priority(thread, priority);
        old
    }

    /// Boost `thread` for a wake: the new priority is its base plus `increment`, applied only when
    /// that exceeds its current priority, capped below the realtime band, and only while no decay
    /// debt is outstanding and the thread runs below the realtime band. A boost that applies also
    /// replenishes the quantum. The thread's disable-boost policy is deliberately not consulted
    /// here — that gate belongs to the wait-exit path.
    pub fn boost(&mut self, thread: impl Into<ThreadId>, increment: i8) {
        let thread = thread.into();
        let record = self.thread_mut(thread);
        if record.priority >= REALTIME_BASE || record.priority_decrement != 0 {
            return;
        }
        let mut new = record.base_priority + increment;
        if new > record.priority {
            if new >= REALTIME_BASE {
                new = REALTIME_BASE - 1;
            }
            let thread_quantum = record.thread_quantum();
            record.set_quantum(thread_quantum);
            self.apply_priority(thread, new);
        }
    }

    /// The increment of `thread`'s base priority over its process's: what a base-priority change
    /// would report as the previous value. A saturated thread reports its pin, not the raw delta.
    pub fn base_increment(&self, thread: impl Into<ThreadId>) -> i32 {
        let record = self.thread(thread.into());
        if record.saturation != 0 {
            return saturation_pin() * record.saturation as i32;
        }
        record.base_priority as i32 - record.process().base_priority as i32
    }

    /// Set `thread`'s base priority to its process's base plus `increment`, clamped inside the
    /// thread's priority class, and returns the previous increment (see [`base_increment`]). An
    /// increment at or beyond half the priority range in either direction pins (saturates) the
    /// thread to its class edge; later process base changes cannot move a saturated thread within
    /// the same class.
    pub fn set_base_priority(&mut self, thread: impl Into<ThreadId>, increment: i32) -> i32 {
        let thread = thread.into();
        let old_increment = self.base_increment(thread);

        let record = self.thread_mut(thread);
        record.saturation = 0;
        if increment.abs() >= saturation_pin() {
            record.saturation = if increment > 0 { 1 } else { -1 };
        }

        let process_base = record.process().base_priority as i32;
        let old_base = record.base_priority as i32;

        let mut new_base = process_base + increment;
        let new_priority;
        if process_base >= REALTIME_BASE as i32 {
            // Realtime process: the base stays in the realtime band and the priority follows it
            // exactly.
            new_base = new_base.clamp(REALTIME_BASE as i32, HIGHEST_PRIORITY as i32);
            new_priority = new_base;
        } else {
            // Variable process: the base stays in the variable band.
            if new_base >= REALTIME_BASE as i32 {
                new_base = REALTIME_BASE as i32 - 1;
            } else if new_base <= 0 {
                new_base = 1;
            }
            if record.saturation != 0 {
                new_priority = new_base;
            } else {
                let mut candidate = record.priority as i32 + (new_base - old_base)
                    - record.priority_decrement as i32;
                if candidate >= REALTIME_BASE as i32 {
                    candidate = REALTIME_BASE as i32 - 1;
                }
                new_priority = candidate;
            }
        }

        record.base_priority = new_base as i8;
        record.decrement_count = 0;
        record.priority_decrement = 0;
        if new_priority != record.priority as i32 {
            let thread_quantum = record.thread_quantum();
            record.set_quantum(thread_quantum);
            self.apply_priority(thread, new_priority as i8);
        }
        old_increment
    }

    /// Select a ready thread of `priority` into the standby slot: the round-robin step the quantum
    /// end and the no-wait yield share. Does nothing while a standby thread is already pending;
    /// returns whether one was installed.
    pub fn standby_from_ready(&mut self, priority: i8) -> bool {
        if self.next_thread().is_some() {
            return false;
        }
        let Some(found) = self.find_ready(priority) else {
            return false;
        };
        self.thread_mut(found).state = ThreadState::Standby;
        self.set_next(Some(found));
        true
    }

    /// The yield SwitchToThread asks for (the platform's NtYieldExecution): when any ready thread
    /// at priority 1 or above can take the processor — a lower-priority one included — the running
    /// `thread` gives it up: its quantum replenished, its priority decayed one step toward its base
    /// (the decay debt consumed), and it queues at the tail of its level directly. It does not go
    /// through [`Dispatcher::make_ready`], which would let it take the standby slot straight back
    /// from a lower-priority thread. Returns whether it yielded; the caller then switches away.
    pub fn yield_execution(&mut self, thread: impl Into<ThreadId>) -> bool {
        let thread = thread.into();
        if self.next_thread().is_none() {
            self.standby_from_ready(1);
        }
        if self.next_thread().is_none() {
            return false;
        }
        let tick = tick_count();
        let record = self.thread_mut(thread);
        let thread_quantum = record.thread_quantum();
        record.set_quantum(thread_quantum);
        if record.priority < REALTIME_BASE {
            let decayed = record.priority - (record.priority_decrement + 1);
            record.priority = decayed.max(record.base_priority);
            record.priority_decrement = 0;
        }
        record.preempted = false;
        record.state = ThreadState::Ready;
        record.wait_time = tick;
        let priority = record.priority;
        list::push_back(self, ReadyQueue(priority as u8), thread);
        self.ready_summary |= 1 << priority as u32;
        true
    }

    /// The end of the running thread's quantum: reset the quantum, decay the priority one step
    /// toward the base (consuming any outstanding decay debt), and decide who runs next. A realtime
    /// thread does not decay; if its priority is unchanged and no standby is pending, the
    /// equal-priority ready thread takes the standby slot — round-robin among equals. A realtime
    /// thread whose process exempts it never ends its quantum at all (its quantum is refilled to
    /// the maximum instead). Returns the standby thread if one was selected.
    pub fn quantum_end(&mut self) -> Option<ThreadId> {
        let thread = self
            .current()
            .expect("quantum end without a running thread");
        let record = self.thread_mut(thread);
        if record.quantum() > 0 {
            return self.next_thread();
        }

        let process = record.process();
        let (disable_quantum, thread_quantum) = (process.disable_quantum, process.thread_quantum);
        if disable_quantum && record.priority >= REALTIME_BASE {
            record.set_quantum(i8::MAX);
            return self.next_thread();
        }

        record.set_quantum(thread_quantum);
        let priority = record.priority;
        let mut new_priority = priority;
        if priority < REALTIME_BASE {
            new_priority = (priority - record.priority_decrement - 1).max(record.base_priority);
            record.priority_decrement = 0;
        }

        if new_priority != priority {
            self.apply_priority(thread, new_priority);
        } else if self.next_thread().is_none() {
            self.standby_from_ready(priority);
        }
        // A thread whose quantum ended goes behind its equals when it is displaced, whatever
        // displaced it: an earlier arrival's preemption mark must not put it back at the head.
        if self.next_thread().is_some() {
            self.thread_mut(thread).preempted = false;
        }
        self.next_thread()
    }

    /// Charge one clock tick against `thread`'s quantum, as the clock charges the running thread's
    /// ([`ThreadSlots::charge_running_tick`]). Returns whether the quantum ended: the charge leaves
    /// a positive quantum alone; at zero it flags the end — except for the idle thread, which is
    /// never flagged (so its quantum runs off the bottom, and nothing reads it).
    pub fn tick_quantum(&mut self, thread: impl Into<ThreadId>) -> bool {
        let thread = thread.into();
        let record = self.thread_mut(thread);
        let quantum = charged_tick(record.quantum());
        record.set_quantum(quantum);
        if quantum > 0 {
            return false;
        }
        Some(thread) != self.idle_thread()
    }

    /// The dispatch window's decision: consume a pending request — the tick's quantum end first,
    /// else a standby arrival — and, when another thread should run, re-ready the running thread
    /// (its displacement flag decides head vs tail) and return the switch target; none when the
    /// running thread keeps the processor. The request is cleared before the quantum decision, and
    /// the decision re-verifies the quantum, so a stale or mid-window re-armed request costs
    /// nothing and survives for the next window.
    pub fn dispatch_target(&mut self) -> Option<ThreadId> {
        if slots().take_quantum_end() {
            self.quantum_end();
        }
        let current = self.current();
        let target = self
            .next_thread()
            .filter(|&target| Some(target) != current)?;
        // The target leaves the standby slot; the switch enters it.
        self.set_next(None);
        // The displaced thread goes back on the ready ladder — unless it is the idle thread, which
        // is never queued: selection reaches it only as the fallback.
        if let Some(current) = current.filter(|&current| Some(current) != self.idle_thread()) {
            self.make_ready(current);
        }
        Some(target)
    }

    /// Charge one completed wait against `thread`'s quantum, with the same decay at exhaustion as a
    /// quantum end. Realtime threads and threads with a time-critical base replenish outright. The
    /// wait machinery calls this at wait exit; the arithmetic lives here because the quantum ledger
    /// is one discipline. Returns whether the charge exhausted the quantum with the priority left
    /// where it was — the condition the no-wait tail's round-robin acts on.
    pub fn charge_wait(&mut self, thread: impl Into<ThreadId>) -> bool {
        let record = self.thread_mut(thread.into());
        let thread_quantum = record.thread_quantum();
        if record.priority >= REALTIME_BASE || record.base_priority >= TIME_CRITICAL_CEILING {
            record.set_quantum(thread_quantum);
            return false;
        }
        let quantum = record.quantum() - QUANTUM_WAIT_CHARGE;
        if quantum > 0 {
            record.set_quantum(quantum);
            return false;
        }
        record.set_quantum(thread_quantum);
        let priority = record.priority;
        record.priority =
            (record.priority - (record.priority_decrement + 1)).max(record.base_priority);
        record.priority_decrement = 0;
        record.priority == priority
    }

    /// Boost the running thread to the time-critical ceiling and keep it there for a fixed number
    /// of round trips: while the boost is in effect, each call renews the doubled quantum and
    /// counts down; when the count runs out, the thread drops back to its base priority through the
    /// full set-priority form and the boost is immediately retried. A thread already at or above
    /// the ceiling is never boosted.
    pub fn boost_current_round_trip(&mut self) {
        let thread = self
            .current()
            .expect("round-trip boost without a running thread");
        loop {
            let record = self.thread_mut(thread);
            let thread_quantum = record.thread_quantum();
            if record.priority_decrement == 0 && record.priority < TIME_CRITICAL_CEILING {
                record.priority_decrement = TIME_CRITICAL_CEILING - record.base_priority;
                record.decrement_count = ROUND_TRIP_LIMIT;
                record.priority = TIME_CRITICAL_CEILING;
                record.set_quantum(thread_quantum * 2);
                return;
            }
            if record.priority_decrement == 0 {
                return;
            }
            record.decrement_count -= 1;
            if record.decrement_count > 0 {
                record.set_quantum(thread_quantum * 2);
                return;
            }
            // Count exhausted: drop to base through the full form (quantum replenished, decay
            // cleared), then retry.
            let base = record.base_priority;
            self.set_priority(thread, base);
        }
    }

    /// The balance-set boost, applied to a ready-too-long thread the caller has already unlinked
    /// from its ready queue: raise it to the top of the variable band with a doubled quantum — the
    /// one place the quantum doubles — and re-ready it. The decay debt records how far the thread
    /// will fall back on its next decay.
    pub fn balance_boost(&mut self, thread: impl Into<ThreadId>) {
        let thread = thread.into();
        let record = self.thread(thread);
        debug_assert!(
            record.state != ThreadState::Ready
                || record.parked_on_process
                || !record.ready_link.is_linked(),
            "balance boost on a still-queued thread"
        );
        let record = self.thread_mut(thread);
        let boost_priority = REALTIME_BASE - 1;
        record.priority_decrement += boost_priority - record.priority;
        record.decrement_count = ROUND_TRIP_LIMIT;
        record.priority = boost_priority;
        let thread_quantum = record.thread_quantum();
        record.set_quantum(thread_quantum * 2);
        self.make_ready(thread);
    }

    /// The balance-set scan, once a second (the platform's balance-set manager): a thread that has
    /// sat ready without running for [`READY_WITHOUT_RUNNING`] ticks — starved by higher-priority
    /// work — takes the balance boost and runs. The scan covers the variable levels below the
    /// boost level, starting where the previous scan stopped; it examines at most
    /// [`THREAD_SCAN_LIMIT`] threads and boosts at most [`THREAD_READY_LIMIT`]. Returns how many it
    /// boosted.
    pub fn scan_ready_queues(&mut self) -> usize {
        let tick = tick_count();
        let top = REALTIME_BASE - 2;
        let mut level = self.scan_level.clamp(1, top);
        let (mut examined, mut boosted) = (0, 0);
        for _ in 0..top {
            if self.ready_summary & (1 << level as u32) != 0 {
                // The walk reads each next entry before the current one may be unlinked.
                let mut cursor = Cursor::front(self, ReadyQueue(level as u8));
                while examined < THREAD_SCAN_LIMIT && boosted < THREAD_READY_LIMIT {
                    let Some(thread) = cursor.next(self) else {
                        break;
                    };
                    examined += 1;
                    if tick.wrapping_sub(self.thread(thread).wait_time) >= READY_WITHOUT_RUNNING {
                        self.dequeue(thread, level);
                        self.balance_boost(thread);
                        boosted += 1;
                    }
                }
            }
            if examined >= THREAD_SCAN_LIMIT || boosted >= THREAD_READY_LIMIT {
                break;
            }
            level = if level == top { 1 } else { level + 1 };
        }
        self.scan_level = level;
        boosted
    }

    /// Terminate the running thread: retire it ([`Dispatcher::retire_current`]), then select the
    /// processor's next thread. Returns the selected thread — the caller's context switch enters
    /// it.
    pub fn terminate(&mut self) -> Option<ThreadId> {
        self.retire_current();
        self.select_next()
    }

    /// Retire the running thread, the first half of its termination: mark its object signaled (the
    /// thread's waiters observe the mark), satisfy every wait parked on the thread object, remove
    /// it from its process's thread list, mark it Terminated and return the kernel-stack loan. It
    /// keeps the current slot until the caller selects the next thread
    /// ([`Dispatcher::select_next`]), so whatever signals in between — its process's object, when
    /// it was the last thread — wakes waiters that same selection weighs.
    pub fn retire_current(&mut self) {
        let thread = self.current().expect("terminate without a running thread");
        self.retire(thread);
    }

    /// Terminate `thread`, another thread than the running one (Windows 2000's
    /// PspTerminateThreadByPointer): it runs its own exit, at its next window for a normal kernel
    /// APC. Its queued APCs are discarded first (a suspend's included), then its exit APC is
    /// queued — a no-op kernel half, `exit` its normal half, `status` its context — which breaks a
    /// wait it may break with the exit increment; from then on it takes no APC. Then it is
    /// force-resumed: a suspended thread runs on to its exit. A thread inside a critical region
    /// keeps its wait and runs on to the region's end; one at the APC level (a short lock's holder
    /// or waiter) runs on until it lowers; one that never ran delivers it at its startup, before
    /// its first user instruction. The exit status is recorded now, for GetExitCodeThread. False,
    /// with nothing changed, for a thread already terminating — its exit APC queued, or its own
    /// exit running.
    ///
    /// # Panics
    ///
    /// `thread` is the running thread (it ends through its own exit), or the idle thread.
    pub fn request_termination(
        &mut self,
        thread: impl Into<ThreadId>,
        exit: super::apc::NormalRoutine,
        status: u32,
    ) -> bool {
        let thread = thread.into();
        assert!(
            Some(thread) != self.current(),
            "the running thread terminates through its own exit"
        );
        assert!(
            Some(thread) != self.idle_thread(),
            "the idle thread never exits"
        );
        let record = self.thread_mut(thread);
        if record.terminate_pending {
            return false;
        }
        record.terminate_pending = true;
        record.exit_status = status;
        self.discard_apcs(thread);
        self.apc_mut(ApcId::Exit(thread)).init(
            thread,
            super::apc::nop_kernel_routine,
            Some(exit),
            super::apc::ApcMode::Kernel,
            status as usize,
        );
        let queued = self.queue_apc(ApcId::Exit(thread), 0, 0, EXIT_APC_INCREMENT);
        debug_assert!(queued, "a thread not terminating takes its exit APC");
        let record = self.thread_mut(thread);
        record.apc_queueable = false;
        // KeForceResumeThread: a suspended thread's counts go and its semaphore is released.
        if record.suspend_count != 0 || record.freeze_count != 0 {
            self.force_resume_thread(thread);
        }
        true
    }

    /// Give the processor to `thread`, a thread just terminated
    /// ([`Dispatcher::request_termination`]) that can run its exit now — Ready, its wait broken
    /// by the exit APC or never begun — ahead of the running thread, whatever their priorities:
    /// it takes the standby slot (a standby thread there goes back to the head of its ready
    /// queue), and the running thread, marked displaced, goes back to the head of its own at
    /// the next dispatch decision — the service boundary of the termination's caller. The
    /// terminated thread runs its exit, which does not wait, and its switch away selects the
    /// caller again. A thread that cannot run at once (waiting in a wait the APC does not
    /// break, already selected) is left as it is. Returns whether it was handed the processor.
    pub fn hand_processor_to(&mut self, thread: ThreadId) -> bool {
        let record = self.thread(thread);
        if record.state != ThreadState::Ready || record.parked_on_process {
            return false;
        }
        let Some(current) = self.current() else {
            return false;
        };
        let priority = record.priority;
        self.dequeue(thread, priority);
        if let Some(standby) = self.next_thread() {
            self.set_next(None);
            let record = self.thread_mut(standby);
            record.state = ThreadState::Ready;
            record.preempted = false;
            let level = record.priority;
            list::push_front(self, ReadyQueue(level as u8), standby);
            self.ready_summary |= 1 << level as u32;
        }
        self.thread_mut(thread).state = ThreadState::Standby;
        self.set_next(Some(thread));
        self.thread_mut(current).preempted = true;
        true
    }

    /// The scheduling teardown every termination ends with: the thread object signals once,
    /// forever, and its waiters wake through the satisfy walk with no priority boost (the exit
    /// path grants none); then the thread leaves its process's list and is Terminated.
    fn retire(&mut self, thread: ThreadId) {
        // The mutexes it holds are abandoned first: their waiters take them before the thread's
        // own waiters wake.
        self.abandon_mutexes(thread);
        let record = self.thread_mut(thread);
        record.waitable.signal_state = 1;
        if record.waitable.has_waiters() {
            self.satisfy_waiters(super::wait::WaitableId::Thread(thread), 0);
        }
        let process = ProcessRef::of(self.thread(thread).process);
        list::remove(self, ProcessThreads(process), thread);
        self.thread_mut(thread).state = ThreadState::Terminated;
        self.owner_mut(thread).stack_count -= 1;
    }

    /// Set the process's base priority to `new_base`, adjusting every attached thread's base and
    /// current priority within its class: a variable process keeps its threads in 1..15, a realtime
    /// one in 16..31. Saturated threads move only when the change crosses the class boundary — then
    /// they pin to their new class's edges; within a class they are left entirely alone. Returns
    /// the process's previous base priority.
    pub fn set_process_priority(&mut self, process: *mut SchedProcess, new_base: i8) -> i8 {
        let process = ProcessRef::of(process);
        // SAFETY: a process record outlives its threads' membership in its list (the attach's
        // contract), and this exclusive borrow of the dispatcher serializes every use of it; the
        // reference ends before the walk below.
        let old_base =
            core::mem::replace(unsafe { &mut process.get_mut().base_priority }, new_base);
        let adjustment = new_base as i32 - old_base as i32;

        // The walk reads each next thread before the priority machinery runs on the current one
        // (which never unlinks a thread from its process).
        let mut cursor = Cursor::front(self, ProcessThreads(process));
        while let Some(thread) = cursor.next(self) {
            let record = self.thread(thread);
            let mut new_priority = record.base_priority as i32 + adjustment;
            let saturation = record.saturation;
            if new_base >= REALTIME_BASE {
                new_priority = new_priority.clamp(REALTIME_BASE as i32, HIGHEST_PRIORITY as i32);
                if saturation == 0 || old_base < REALTIME_BASE {
                    if saturation > 0 {
                        new_priority = HIGHEST_PRIORITY as i32;
                    } else if saturation < 0 {
                        new_priority = REALTIME_BASE as i32;
                    }
                    self.apply_thread_adjustment(thread, new_priority);
                }
            } else {
                if new_priority >= REALTIME_BASE as i32 {
                    new_priority = REALTIME_BASE as i32 - 1;
                } else if new_priority <= 0 {
                    new_priority = 1;
                }
                if saturation == 0 || old_base >= REALTIME_BASE {
                    if saturation > 0 {
                        new_priority = REALTIME_BASE as i32 - 1;
                    } else if saturation < 0 {
                        new_priority = 1;
                    }
                    self.apply_thread_adjustment(thread, new_priority);
                }
            }
        }
        old_base
    }

    /// Apply one thread's adjusted base priority: store the base, replenish the quantum, clear the
    /// decay, and run the state machine.
    fn apply_thread_adjustment(&mut self, thread: ThreadId, new_priority: i32) {
        let record = self.thread_mut(thread);
        record.base_priority = new_priority as i8;
        let thread_quantum = record.thread_quantum();
        record.set_quantum(thread_quantum);
        record.decrement_count = 0;
        record.priority_decrement = 0;
        self.apply_priority(thread, new_priority as i8);
    }
}

/// The processor's thread slots, which the dispatcher writes.
fn slots() -> &'static ThreadSlots {
    &crate::pcr::pcr().threads
}

/// The clock's tick count (Windows 2000's KeTickCount, read unlocked): the stamp a thread takes as
/// it joins a ready queue, which the balance-set scan measures ready-without-running time against.
#[cfg(target_arch = "x86")]
fn tick_count() -> u64 {
    crate::interrupt::clock::ticks()
}

/// The host's tick count: what the tests set ([`set_test_ticks`]), per test thread.
#[cfg(not(target_arch = "x86"))]
fn tick_count() -> u64 {
    host_ticks::TICKS.with(core::cell::Cell::get)
}

#[cfg(not(target_arch = "x86"))]
mod host_ticks {
    extern crate std;

    std::thread_local! {
        /// The tick count the host's dispatcher reads.
        pub static TICKS: core::cell::Cell<u64> = const { core::cell::Cell::new(0) };
    }
}

/// Set the host's tick count, as the clock advances the kernel's.
#[cfg(test)]
pub(crate) fn set_test_ticks(ticks: u64) {
    host_ticks::TICKS.with(|cell| cell.set(ticks));
}

/// Deliver a pending dispatch request at a dispatch point: the interrupt exit (after the deferred
/// work has run) and the service boundary. The window opens only below the dispatch level — a
/// request armed inside an open window (the clock can preempt it) waits for the window's own lower.
/// The decision itself runs at the dispatch level: it re-readies the running thread, and a clock
/// interrupt landing in it must not drain or deliver on top of it. A delivered switch leaves the
/// calling frames in place on the calling thread's kernel stack: the interrupted exit unwinds when
/// the thread is next resumed, its state untouched.
///
/// The same window delivers the running thread's pending kernel APCs — after the dispatch
/// decision, mirroring the interrupt-exit order (the dispatch request outranks the APC request on
/// the way down): the running thread's own when nothing switched, the resumed thread's when the
/// switch came back to it.
#[cfg(target_arch = "x86")]
pub fn deliver_pending() {
    if crate::level::dispatch_entry(switch_if_requested).is_none() {
        return;
    }
    // The running thread's timeline, at the level the window opened at: a kernel APC queued on
    // it while it was off the processor runs now, before its interrupted frames unwind.
    super::apc::deliver_pending_apcs();
}

/// The dispatch decision, at the dispatch level: switch to the thread the decision names, if any
/// (see [`Dispatcher::dispatch_target`]). Returns whether it switched; the thread is running
/// again either way.
#[cfg(target_arch = "x86")]
fn switch_if_requested(dispatch: &mut At<Dispatch>) -> bool {
    let dispatcher = super::DISPATCHER.get(dispatch);
    let running = dispatcher.current();
    // The idle thread takes its own decisions, in its loop (Windows 2000's KiIdleLoop swaps to the
    // next thread itself): the drain, then the reap of an ended process, then the switch. Taken
    // here instead, the switch would leave an ended process waiting for the processor to fall idle
    // again. The standby thread stays where it is for the loop's next pass.
    if running.is_some() && running == dispatcher.idle_thread() {
        return false;
    }
    // A retired thread runs on to its exit's own switch, which selects the next thread itself
    // (Windows 2000's terminating thread holds the dispatcher from its signal to the swap): its
    // record may be renewed once it is off the processor, and its process torn down.
    if running.is_some_and(|thread| dispatcher.thread(thread).state() == ThreadState::Terminated) {
        return false;
    }
    let Some(target) = dispatcher.dispatch_target() else {
        return false;
    };
    let running = running.expect("a dispatch window runs on a thread");
    super::switch::switch_to(dispatch, running, target);
    true
}

/// What a lower from the dispatch level or above to below it runs (Windows 2000's DISPATCH
/// software interrupt, which fires as KeLowerIrql drops the level): the DPCs queued meanwhile,
/// then, when the level reached runs with interrupts enabled, a dispatch decision requested
/// meanwhile (a quantum a tick ended, a thread readied above the running one). A caller lowering
/// to a masked level is not preemptible there: its own dispatch point takes the decision (the
/// service boundary, a wait, an interrupt window). Kernel APCs wait for their own delivery points.
///
/// The work's own raises lower without coming back here: a switch is followed by another look, so
/// what arrived while this thread was away is not left for the next interrupt.
pub fn dispatch_on_lower() {
    let pcr = crate::pcr::pcr();
    loop {
        crate::interrupt::dpc::drain();
        if !pcr.interrupts_enabled() || !pcr.threads.dispatch_requested() {
            return;
        }
        #[cfg(target_arch = "x86")]
        if crate::level::dispatch_entry(switch_if_requested) == Some(true) {
            continue;
        }
        return;
    }
}

/// Half the priority range: the saturation threshold and the value a saturated base reports as its
/// increment.
fn saturation_pin() -> i32 {
    (HIGHEST_PRIORITY as i32 + 1) / 2
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sched::apc::{ApcArgs, ApcDelivery, ApcMode};
    use crate::sched::process::SchedProcess;
    use crate::sched::testkit::Rec;
    use crate::sched::thread::{Thread, ThreadState};
    use crate::sched::{QUANTUM_RESET, QUANTUM_TICK};

    // --- The rig ----------------------------------------------------------
    //
    // Threads and processes are kernel objects: they live at fixed addresses for as long as they
    // are linked, so the rig leaks every object it creates (one-shot tests; the addresses never
    // die).

    fn dispatcher() -> &'static mut Dispatcher {
        crate::sched::testkit::dispatcher()
    }

    fn process(base: i8) -> *mut SchedProcess {
        let p = Box::leak(Box::new(SchedProcess::new(0x0090_0000, base)));
        p as *mut SchedProcess
    }

    fn thread(p: *mut SchedProcess) -> Rec<Thread> {
        crate::sched::testkit::thread(p)
    }

    /// Run `t` as the processor's current thread.
    fn run(d: &mut Dispatcher, mut t: Rec<Thread>) {
        install_current(d, t.id());
        t.state = ThreadState::Running;
    }

    /// Put `thread` in the processor's current slot, its quantum handed over as a switch hands it,
    /// and nothing else changed.
    fn install_current(d: &mut Dispatcher, thread: ThreadId) {
        if let Some(running) = d.current() {
            d.thread_mut(running).switch_out();
        }
        slots().set_current(Some(thread));
        d.thread(thread).switch_in();
    }

    /// Make `t` the processor's standby thread.
    fn standby(d: &mut Dispatcher, mut t: Rec<Thread>) {
        d.set_next(Some(t.id()));
        t.state = ThreadState::Standby;
    }

    /// One full tick's charge of the running thread's quantum, as the clock interrupt makes it.
    fn charge_tick() {
        crate::level::raised::<crate::level::Clock, _>(|clock| slots().charge_running_tick(clock));
    }

    /// Whether a tick's charge requested the dispatch window's quantum decision.
    fn quantum_end_requested() -> bool {
        slots().quantum_end_requested()
    }

    /// `t`'s id, as the selection entries and the processor slots hold it.
    fn id_of(t: Rec<Thread>) -> Option<ThreadId> {
        Some(t.id())
    }

    // --- Group A: fresh state ------------------------------------------------

    /// A fresh dispatcher: 32 empty ready lists, no summary bits, an empty processor, the invariant
    /// holds.
    #[test]
    fn dispatcher_starts_empty() {
        let d = dispatcher();
        for queue in d.ready.iter() {
            assert!(queue.is_empty());
        }
        assert_eq!(d.ready_summary, 0);
        assert!(!d.processor_idle);
        assert!(d.current().is_none());
        assert!(d.next_thread().is_none());
        assert!(d.idle_thread().is_none());
        assert_eq!(d.audit(), Ok(()));
    }

    // --- Group B: insertion and selection ------------------------------------

    /// Selection takes the highest non-empty queue; the taken thread's queue bit clears and lower
    /// bits survive.
    #[test]
    fn selection_picks_the_highest_queue() {
        let d = dispatcher();
        let p = process(8);
        let mut t8 = thread(p);
        t8.priority = 8;
        let mut t12 = thread(p);
        t12.priority = 12;

        d.make_ready(t8);
        d.make_ready(t12);
        assert_eq!(d.ready_summary, (1 << 8) | (1 << 12));

        let got = d.find_ready(0);
        assert_eq!(got, id_of(t12));
        assert_eq!(t12.state(), ThreadState::Ready);
        assert_eq!(d.ready_summary, 1 << 8, "bit 12 clears, bit 8 survives");
        assert_eq!(d.audit(), Ok(()));
    }

    /// The floor masks lower queues: a thread below it is invisible.
    #[test]
    fn selection_floor_masks_lower_queues() {
        let d = dispatcher();
        let p = process(8);
        let mut t8 = thread(p);
        t8.priority = 8;
        let mut t12 = thread(p);
        t12.priority = 12;
        d.make_ready(t8);
        d.make_ready(t12);

        assert_eq!(d.find_ready(9), id_of(t12));
        assert!(d.find_ready(13).is_none());
        // The floor scan took t12 (queued at or above the floor); the failed scan took nothing.
        assert_eq!(d.ready_summary, 1 << 8);
    }

    /// An empty summary selects nothing.
    #[test]
    fn selection_from_empty_selects_nothing() {
        let d = dispatcher();
        assert!(d.find_ready(0).is_none());
    }

    /// Within one priority, selection is first-in, first-out.
    #[test]
    fn selection_is_fifo_within_a_priority() {
        let d = dispatcher();
        let p = process(8);
        let t1 = thread(p);
        let t2 = thread(p);
        let t3 = thread(p);
        d.make_ready(t1);
        d.make_ready(t2);
        d.make_ready(t3);

        assert_eq!(d.find_ready(0), id_of(t1));
        assert_eq!(d.find_ready(0), id_of(t2));
        assert_eq!(d.find_ready(0), id_of(t3));
        assert!(d.find_ready(0).is_none());
        assert_eq!(d.ready_summary, 0);
    }

    /// A thread that merely became runnable queues at the tail.
    #[test]
    fn fresh_thread_queues_at_the_tail() {
        let d = dispatcher();
        let p = process(8);
        let t1 = thread(p);
        let t2 = thread(p);
        d.make_ready(t1);
        d.make_ready(t2);

        assert_eq!(t1.state(), ThreadState::Ready);
        assert_eq!(t2.state(), ThreadState::Ready);
        assert_eq!(d.find_ready(0), id_of(t1), "t1 queued first runs first");
        assert_eq!(d.ready_summary, 1 << 8);
    }

    /// A preempted thread requeues at the head, ahead of threads queued at the same priority before
    /// it.
    #[test]
    fn preempted_thread_requeues_at_the_head() {
        let d = dispatcher();
        let p = process(8);
        let mut witness = thread(p);
        witness.priority = 12;
        d.make_ready(witness);

        let mut t = thread(p);
        t.priority = 12;
        t.preempted = true;
        d.make_ready(t);

        assert_eq!(
            d.find_ready(12),
            id_of(t),
            "the preempted thread is ahead of the witness"
        );
        assert_eq!(d.find_ready(12), id_of(witness));
        assert!(!t.preempted, "the flag is consumed by the insertion");
        assert_eq!(d.ready_summary, 0);
    }

    /// Draining a queue clears its bit; higher bits survive.
    #[test]
    fn draining_a_queue_clears_its_bit() {
        let d = dispatcher();
        let p = process(8);
        let mut t8 = thread(p);
        t8.priority = 8;
        let mut t9 = thread(p);
        t9.priority = 9;
        d.make_ready(t8);
        d.make_ready(t9);

        assert_eq!(d.find_ready(0), id_of(t9));
        assert_eq!(d.ready_summary, 1 << 8);
        assert_eq!(d.find_ready(0), id_of(t8));
        assert_eq!(d.ready_summary, 0);
        assert_eq!(d.audit(), Ok(()));
    }

    /// The summary invariant is an auditable property, and a manual corruption is caught.
    #[test]
    fn the_summary_tracks_the_queues() {
        let d = dispatcher();
        let p = process(8);
        let mut a = thread(p);
        a.priority = 5;
        let mut b = thread(p);
        b.priority = 20;
        d.make_ready(a);
        d.make_ready(b);
        assert_eq!(d.audit(), Ok(()));

        d.ready_summary |= 1 << 7;
        assert!(d.audit().is_err());
    }

    // --- Group C: ready and terminate transitions ----------------------------

    /// A readied thread on an idle processor takes it immediately: standby, and the idle flag
    /// clears.
    #[test]
    fn a_readied_thread_takes_an_idle_processor() {
        let d = dispatcher();
        let p = process(8);
        let idle = thread(p);
        d.install_idle_thread(idle.id());
        assert!(d.processor_idle);

        let mut t = thread(p);
        t.priority = 8;
        d.make_ready(t);
        assert_eq!(t.state(), ThreadState::Standby);
        assert_eq!(d.next_thread(), id_of(t));
        assert!(!d.processor_idle);
        assert_eq!(d.ready_summary, 0, "never queued");
    }

    /// A higher-priority arrival displaces the standby thread: the arrival becomes standby, the
    /// displaced thread is marked preempted and requeues at the head.
    #[test]
    fn an_arrival_displaces_the_standby_thread() {
        let d = dispatcher();
        let p = process(8);
        let mut witness = thread(p);
        witness.priority = 12;
        d.make_ready(witness);

        let mut standby_t = thread(p);
        standby_t.priority = 12;
        standby(d, standby_t);

        let mut arrival = thread(p);
        arrival.priority = 14;
        d.make_ready(arrival);

        assert_eq!(arrival.state(), ThreadState::Standby);
        assert_eq!(d.next_thread(), id_of(arrival));
        assert_eq!(standby_t.state(), ThreadState::Ready);
        assert!(!standby_t.preempted, "consumed by the requeue");
        assert_eq!(
            d.find_ready(12),
            id_of(standby_t),
            "the displaced thread requeued at the head, ahead of the witness"
        );
        assert_eq!(d.find_ready(12), id_of(witness));
    }

    /// A higher-priority arrival preempts the running thread: the arrival becomes standby and the
    /// running thread is marked preempted (still Running until the context switch).
    #[test]
    fn an_arrival_preempts_the_running_thread() {
        let d = dispatcher();
        let p = process(8);
        let mut current = thread(p);
        current.priority = 12;
        run(d, current);

        let mut arrival = thread(p);
        arrival.priority = 14;
        d.make_ready(arrival);

        assert_eq!(arrival.state(), ThreadState::Standby);
        assert_eq!(d.next_thread(), id_of(arrival));
        assert!(current.preempted);
        assert_eq!(current.state(), ThreadState::Running);
        assert_eq!(d.ready_summary, 0);
    }

    /// An equal-priority arrival never preempts: it queues.
    #[test]
    fn an_equal_arrival_never_preempts() {
        let d = dispatcher();
        let p = process(8);
        let mut current = thread(p);
        current.priority = 12;
        run(d, current);

        let mut arrival = thread(p);
        arrival.priority = 12;
        d.make_ready(arrival);

        assert_eq!(arrival.state(), ThreadState::Ready);
        assert!(d.next_thread().is_none());
        assert!(!current.preempted);
        assert_eq!(d.ready_summary, 1 << 12);
    }

    /// select_next consumes a pending standby thread first.
    #[test]
    fn select_next_consumes_the_standby_thread() {
        let d = dispatcher();
        let p = process(8);
        let t = thread(p);
        standby(d, t);

        assert_eq!(d.select_next(), id_of(t));
        assert!(d.next_thread().is_none());
        assert_eq!(
            t.state(),
            ThreadState::Standby,
            "the switch flips the state"
        );
    }

    /// With nothing pending, select_next scans the queues.
    #[test]
    fn select_next_scans_the_queues() {
        let d = dispatcher();
        let p = process(8);
        let t = thread(p);
        d.make_ready(t);
        assert_eq!(d.select_next(), id_of(t));
        assert_eq!(t.state(), ThreadState::Ready);
    }

    /// With nothing runnable at all, select_next falls back to the idle thread and marks the
    /// processor idle.
    #[test]
    fn select_next_falls_back_to_the_idle_thread() {
        let d = dispatcher();
        let p = process(8);
        let idle = thread(p);
        slots().set_idle(id_of(idle));

        assert_eq!(d.select_next(), id_of(idle));
        assert!(d.processor_idle);
    }

    /// The standby round-robin step, shared by the quantum end and the no-wait yield: an
    /// equal-priority ready thread takes the empty standby slot; a pending standby or an empty
    /// queue leaves it alone.
    #[test]
    fn standby_from_ready_installs_an_equal() {
        let d = dispatcher();
        let p = process(8);
        let mut t = thread(p);
        t.priority = 8;
        d.make_ready(t);

        assert!(d.standby_from_ready(8), "an equal is found and installed");
        assert_eq!(d.next_thread(), id_of(t));
        assert_eq!(t.state(), ThreadState::Standby);

        // A pending standby blocks the install.
        let mut other = thread(p);
        other.priority = 8;
        d.make_ready(other);
        assert!(!d.standby_from_ready(8));
        assert_eq!(
            d.next_thread(),
            id_of(t),
            "the pending standby is left alone"
        );

        // An empty queue installs nobody.
        assert!(!d.standby_from_ready(12));
    }

    /// Termination: the thread is signaled and Terminated, leaves its process's thread list,
    /// returns its kernel stack loan, and the processor's next thread is selected.
    #[test]
    fn terminate_signals_unlinks_and_selects() {
        let d = dispatcher();
        let p = process(8);
        let victim = thread(p);
        let survivor = thread(p);
        assert_eq!(unsafe { (*p).stack_count() }, 2);
        run(d, victim);
        d.make_ready(survivor);

        let selected = d.terminate();
        assert_eq!(selected, id_of(survivor));
        assert!(victim.signaled());
        assert_eq!(victim.state(), ThreadState::Terminated);
        assert_eq!(unsafe { (*p).stack_count() }, 1);
        // The survivor is still in the process's thread list.
        assert!(!unsafe { (*p).threads.is_empty() });
        // A second thread terminating empties it.
        standby(d, survivor);
        install_current(d, id_of(survivor).expect("a thread"));
        assert!(!d.terminate().is_none());
        assert_eq!(unsafe { (*p).stack_count() }, 0);
        assert!(unsafe { (*p).threads.is_empty() });
    }

    /// A termination's exit APC whose normal half does nothing: the host model never runs it (the
    /// exit itself is the target's).
    fn exit_normal(_thread: ThreadId, _status: usize, _argument1: usize, _argument2: usize) {}

    /// Whether `t`'s exit APC is queued, its context the exit status `status`.
    fn exit_queued(d: &Dispatcher, t: Rec<Thread>, status: u32) -> bool {
        let apc = d.apc(ApcId::Exit(t.id()));
        apc.inserted() && apc.normal_context == status as usize && apc.mode == ApcMode::Kernel
    }

    /// Terminating a Ready thread queues its exit APC and nothing else: it stays on its queue (the
    /// resume tail that dispatches it delivers the APC), attached, its status recorded, and takes
    /// no other APC from then on.
    #[test]
    fn a_termination_queues_the_exit_apc_on_a_ready_thread() {
        let d = dispatcher();
        let p = process(8);
        let running = thread(p);
        let first = thread(p);
        let second = thread(p);
        run(d, running);
        d.make_ready(first);
        d.make_ready(second);

        assert!(d.request_termination(first, exit_normal, 7));
        assert!(exit_queued(d, first, 7));
        assert!(first.kernel_apc_pending, "armed for the resume tail");
        assert!(first.termination_pending());
        assert!(!first.apc_queueable);
        assert_eq!(first.exit_status(), 7);
        assert_eq!(first.state(), ThreadState::Ready, "it runs its own exit");
        assert_eq!(d.ready_summary, 1 << 8);
        assert_eq!(unsafe { (*p).stack_count() }, 3, "attached until its exit");
        assert_eq!(
            d.suspend_thread(first),
            Err(crate::status::STATUS_THREAD_IS_TERMINATING)
        );
        // The walk of a process-ending termination passes it.
        assert_eq!(d.first_thread_except(p, Some(running.id())), id_of(second));
        assert_eq!(d.audit(), Ok(()));
    }

    /// The Standby thread keeps the standby slot: the switch enters it, and its resume tail
    /// delivers the exit APC.
    #[test]
    fn a_termination_leaves_the_standby_thread_in_its_slot() {
        let d = dispatcher();
        let p = process(8);
        let running = thread(p);
        let next = thread(p);
        run(d, running);
        standby(d, next);

        assert!(d.request_termination(next, exit_normal, 1));
        assert_eq!(d.next_thread(), id_of(next));
        assert_eq!(next.state(), ThreadState::Standby);
        assert!(exit_queued(d, next, 1));
    }

    /// A thread that never ran keeps its exit APC for its startup's delivery, before its first
    /// user instruction: nothing is unlinked, and the readying schedules it.
    #[test]
    fn a_never_readied_thread_keeps_its_exit_apc_for_its_startup() {
        let d = dispatcher();
        let p = process(8);
        let running = thread(p);
        let fresh = thread(p);
        run(d, running);

        assert!(d.request_termination(fresh, exit_normal, 0xC000_004B));
        assert_eq!(fresh.state(), ThreadState::Initialized);
        assert!(exit_queued(d, fresh, 0xC000_004B));
        d.make_ready(fresh);
        assert!(exit_queued(d, fresh, 0xC000_004B));
        assert_eq!(unsafe { (*p).stack_count() }, 2);
        assert_eq!(d.audit(), Ok(()));
    }

    /// The running thread exits through its own path, never through another's termination.
    #[test]
    #[should_panic(expected = "the running thread terminates through its own exit")]
    fn a_termination_refuses_the_running_thread() {
        let d = dispatcher();
        let p = process(8);
        let running = thread(p);
        run(d, running);
        d.request_termination(running, exit_normal, 0);
    }

    /// A thread is terminated once: a second request — or one for a thread running its own exit —
    /// changes nothing, its first status standing.
    #[test]
    fn a_termination_is_requested_once() {
        let d = dispatcher();
        let p = process(8);
        let running = thread(p);
        let other = thread(p);
        let mut exiting = thread(p);
        run(d, running);
        d.make_ready(other);
        assert!(d.request_termination(other, exit_normal, 5));
        assert!(!d.request_termination(other, exit_normal, 6));
        assert_eq!(other.exit_status(), 5);
        assert!(exit_queued(d, other, 5));

        // A thread whose own exit runs is marked terminating by it, its queue closed.
        exiting.terminate_pending = true;
        d.close_apc_queue(exiting.id());
        assert!(!d.request_termination(exiting, exit_normal, 6));
        assert!(!exiting.exit_apc.inserted());
    }

    // --- Group D: the priority-change state machine -------------------------

    /// An equal-priority set is a complete no-op.
    #[test]
    fn equal_priority_is_a_no_op() {
        let d = dispatcher();
        let p = process(8);
        let t = thread(p);
        d.make_ready(t);
        let summary = d.ready_summary;

        d.apply_priority(t, 8);
        assert_eq!(t.state(), ThreadState::Ready);
        assert_eq!(d.ready_summary, summary);
        assert_eq!(d.find_ready(0), id_of(t));
    }

    /// A Ready thread being lowered moves to the tail of the new queue; the old queue's bit clears.
    #[test]
    fn a_ready_thread_lowered_moves_queues() {
        let d = dispatcher();
        let p = process(8);
        let mut t = thread(p);
        t.priority = 12;
        d.make_ready(t);

        d.apply_priority(t, 8);
        assert_eq!(t.state(), ThreadState::Ready);
        assert_eq!(d.ready_summary, 1 << 8);
        assert_eq!(d.audit(), Ok(()));
        assert_eq!(d.find_ready(0), id_of(t));
    }

    /// A Ready thread being raised is re-readied: it re-enters the ready path (here, with nothing
    /// to preempt, at the tail of the new queue).
    #[test]
    fn a_ready_thread_raised_is_rereadied() {
        let d = dispatcher();
        let p = process(8);
        let mut t = thread(p);
        t.priority = 8;
        d.make_ready(t);

        d.apply_priority(t, 10);
        assert_eq!(t.state(), ThreadState::Ready);
        assert_eq!(d.ready_summary, 1 << 10);
        assert_eq!(d.find_ready(10), id_of(t));
    }

    /// A thread parked on its process (the swap machinery's parking spot, never true here) takes
    /// the field change alone.
    #[test]
    fn a_parked_thread_takes_the_field_only() {
        let d = dispatcher();
        let p = process(8);
        let mut t = thread(p);
        t.priority = 8;
        t.state = ThreadState::Ready;
        t.parked_on_process = true;

        d.apply_priority(t, 5);
        assert_eq!(t.priority(), 5);
        assert_eq!(d.ready_summary, 0);
        assert_eq!(d.audit(), Ok(()));
    }

    /// A Standby thread being lowered with a replacement available swaps: the replacement becomes
    /// standby, the thread re-readies.
    #[test]
    fn a_standby_thread_lowered_swaps_out() {
        let d = dispatcher();
        let p = process(8);
        let mut t = thread(p);
        t.priority = 12;
        standby(d, t);
        let mut replacement = thread(p);
        replacement.priority = 10;
        d.make_ready(replacement);

        d.apply_priority(t, 8);
        assert_eq!(replacement.state(), ThreadState::Standby);
        assert_eq!(d.next_thread(), id_of(replacement));
        assert_eq!(t.state(), ThreadState::Ready);
        assert_eq!(d.ready_summary, 1 << 8);
        assert_eq!(d.find_ready(8), id_of(t));
    }

    /// A Standby thread being lowered with no replacement stays standby — a standby thread is on no
    /// ready list.
    #[test]
    fn a_standby_thread_lowered_without_replacement_stays() {
        let d = dispatcher();
        let p = process(8);
        let mut t = thread(p);
        t.priority = 12;
        standby(d, t);

        d.apply_priority(t, 8);
        assert_eq!(t.priority(), 8);
        assert_eq!(t.state(), ThreadState::Standby);
        assert_eq!(d.next_thread(), id_of(t));
        assert_eq!(d.ready_summary, 0);
    }

    /// A Running thread being lowered with a candidate installs the candidate as standby; the
    /// running thread keeps Running.
    #[test]
    fn a_running_thread_lowered_installs_a_candidate() {
        let d = dispatcher();
        let p = process(8);
        let mut t = thread(p);
        t.priority = 12;
        run(d, t);
        let mut candidate = thread(p);
        candidate.priority = 10;
        d.make_ready(candidate);

        d.apply_priority(t, 8);
        assert_eq!(candidate.state(), ThreadState::Standby);
        assert_eq!(d.next_thread(), id_of(candidate));
        assert_eq!(t.state(), ThreadState::Running);
        assert_eq!(t.priority(), 8);
    }

    /// A Running thread being lowered while a standby is pending takes the field change alone — the
    /// pending thread owns the slot.
    #[test]
    fn a_running_thread_lowered_with_standby_pending_is_untouched() {
        let d = dispatcher();
        let p = process(8);
        let mut t = thread(p);
        t.priority = 12;
        run(d, t);
        let mut pending = thread(p);
        pending.priority = 14;
        standby(d, pending);
        let mut queued = thread(p);
        queued.priority = 10;
        d.make_ready(queued);

        d.apply_priority(t, 8);
        assert_eq!(d.next_thread(), id_of(pending));
        assert_eq!(queued.state(), ThreadState::Ready);
        assert_eq!(d.ready_summary, 1 << 10);
    }

    /// A Running thread being raised (or held) takes no dispatch action.
    #[test]
    fn a_running_thread_raised_takes_no_action() {
        let d = dispatcher();
        let p = process(8);
        let mut t = thread(p);
        t.priority = 8;
        run(d, t);

        d.apply_priority(t, 12);
        assert_eq!(t.priority(), 12);
        assert!(d.next_thread().is_none());
        assert_eq!(d.ready_summary, 0);
    }

    /// Initialized, Terminated, Waiting and Transition take the field change alone.
    #[test]
    fn unscheduled_states_take_the_field_only() {
        let d = dispatcher();
        let p = process(8);
        for state in [
            ThreadState::Initialized,
            ThreadState::Terminated,
            ThreadState::Waiting,
            ThreadState::Transition,
        ] {
            let mut t = thread(p);
            t.state = state;
            d.apply_priority(t, 10);
            assert_eq!(t.priority(), 10, "{:?}: field only", state);
            assert_eq!(t.state(), state, "{:?}: state untouched", state);
        }
        assert_eq!(d.ready_summary, 0);
        assert_eq!(d.audit(), Ok(()));
    }

    /// The full set-priority form: replenish the quantum, clear the decay fields, then run the
    /// machine; the old priority returns.
    #[test]
    fn set_priority_replenishes_before_the_machine() {
        let d = dispatcher();
        let p = process(8);
        let mut t = thread(p);
        t.priority = 8;
        t.set_quantum(0);
        t.decrement_count = 3;
        t.priority_decrement = 2;

        assert_eq!(d.set_priority(t, 10), 8);
        assert_eq!(t.priority(), 10);
        assert_eq!(t.quantum(), 6);
        assert_eq!(t.decrement_count(), 0);
        assert_eq!(t.priority_decrement(), 0);
    }

    /// Base-priority saturation: an increment at or beyond half the range pins the thread; the
    /// query reports the pin.
    #[test]
    fn base_priority_saturation_pins_and_reports() {
        let d = dispatcher();
        let p = process(8);

        let mut high = thread(p);
        high.base_priority = 8;
        high.priority = 8;
        assert_eq!(d.set_base_priority(high, 17), 0);
        assert_eq!(high.saturation(), 1);
        assert_eq!(d.base_increment(high), 16);

        let mut low = thread(p);
        low.base_priority = 8;
        low.priority = 8;
        assert_eq!(d.set_base_priority(low, -16), 0);
        assert_eq!(low.saturation(), -1);
        assert_eq!(d.base_increment(low), -16);

        let mut free = thread(p);
        free.base_priority = 8;
        free.priority = 8;
        assert_eq!(d.set_base_priority(free, 5), 0);
        assert_eq!(free.saturation(), 0);
        assert_eq!(d.base_increment(free), 5);
    }

    /// Base-priority change in a variable process: the base clamps below the realtime band and the
    /// priority follows with the decay debt subtracted.
    #[test]
    fn base_priority_variable_class_clamps() {
        let d = dispatcher();
        let p = process(8);
        let mut t = thread(p);
        t.base_priority = 8;
        t.priority = 10;
        t.priority_decrement = 2;

        d.set_base_priority(t, 9);
        assert_eq!(t.base_priority(), 15, "8 + 9 clamped below realtime");
        assert_eq!(t.priority(), 15, "10 + (15 - 8) - 2");
        assert_eq!(t.quantum(), 6, "a changed priority replenishes");
        assert_eq!(t.decrement_count(), 0);
        assert_eq!(t.priority_decrement(), 0);
    }

    /// Base-priority change in a realtime process: the base pins to the band and the priority
    /// equals the base.
    #[test]
    fn base_priority_realtime_class_pins() {
        let d = dispatcher();
        let p = process(24);
        let mut t = thread(p);
        t.base_priority = 24;
        t.priority = 26;

        d.set_base_priority(t, -30);
        assert_eq!(t.base_priority(), 16, "24 - 30 clamped up to the band");
        assert_eq!(t.priority(), 16, "realtime priority follows the base");

        d.set_base_priority(t, 30);
        assert_eq!(t.base_priority(), 31, "24 + 30 clamped down to the top");
        assert_eq!(t.priority(), 31);
    }

    /// The decay fields clear even when the computed priority does not change (and then the quantum
    /// is not replenished).
    #[test]
    fn base_priority_clears_decay_even_without_a_change() {
        let d = dispatcher();
        let p = process(8);
        let mut t = thread(p);
        t.base_priority = 8;
        t.priority = 8;
        t.set_quantum(1);
        t.decrement_count = 5;
        t.priority_decrement = 0;

        d.set_base_priority(t, 0);
        assert_eq!(t.base_priority(), 8);
        assert_eq!(t.priority(), 8);
        assert_eq!(t.quantum(), 1, "no replenish without a change");
        assert_eq!(t.decrement_count(), 0);
        assert_eq!(t.priority_decrement(), 0);
    }

    // --- Group E: the wake boost ---------------------------------------------

    /// A boost applies base plus increment when that exceeds the current priority, and replenishes
    /// the quantum.
    #[test]
    fn a_boost_raises_and_replenishes() {
        let d = dispatcher();
        let p = process(8);
        let mut t = thread(p);
        t.base_priority = 8;
        t.priority = 8;
        t.set_quantum(1);

        d.boost(t, 2);
        assert_eq!(t.priority(), 10);
        assert_eq!(t.quantum(), 6);
    }

    /// A boost is capped below the realtime band; the cap value is exact and the quantum resets
    /// even though the priority does not change.
    #[test]
    fn a_boost_caps_below_realtime() {
        let d = dispatcher();
        let p = process(8);
        let mut t = thread(p);
        t.base_priority = 15;
        t.priority = 15;
        t.set_quantum(1);

        d.boost(t, 10);
        assert_eq!(t.priority(), 15, "25 capped at 15");
        assert_eq!(t.quantum(), 6, "the reset precedes the set");
    }

    /// A boost that does not exceed the current priority does not apply: idempotent while a boost
    /// is already in effect.
    #[test]
    fn a_boost_below_the_current_priority_does_not_apply() {
        let d = dispatcher();
        let p = process(8);
        let mut t = thread(p);
        t.base_priority = 8;
        t.priority = 10;
        t.set_quantum(1);

        d.boost(t, 2);
        assert_eq!(t.priority(), 10);
        assert_eq!(t.quantum(), 1);
    }

    /// No boost while a decay debt is outstanding.
    #[test]
    fn a_boost_refuses_on_outstanding_decay() {
        let d = dispatcher();
        let p = process(8);
        let mut t = thread(p);
        t.base_priority = 8;
        t.priority = 12;
        t.priority_decrement = 4;
        t.set_quantum(2);

        d.boost(t, 10);
        assert_eq!(t.priority(), 12);
        assert_eq!(t.priority_decrement(), 4);
        assert_eq!(t.quantum(), 2);
    }

    /// No boost at a realtime priority.
    #[test]
    fn a_boost_refuses_at_realtime() {
        let d = dispatcher();
        let p = process(24);
        let mut t = thread(p);
        t.base_priority = 24;
        t.priority = 24;
        t.set_quantum(2);

        d.boost(t, 10);
        assert_eq!(t.priority(), 24);
        assert_eq!(t.quantum(), 2);
    }

    /// A boost that raises the priority drives the full state machine: it preempts a lower running
    /// thread, or queues when it cannot.
    #[test]
    fn a_boost_drives_the_state_machine() {
        // Raised above the running thread: standby, the running thread marked preempted.
        let d = dispatcher();
        let p = process(8);
        let mut current = thread(p);
        current.priority = 12;
        run(d, current);
        let mut t = thread(p);
        t.base_priority = 8;
        t.priority = 8;
        d.make_ready(t);

        d.boost(t, 6);
        assert_eq!(t.priority(), 14);
        assert_eq!(t.state(), ThreadState::Standby);
        assert_eq!(d.next_thread(), id_of(t));
        assert!(current.preempted);

        // Raised below the running thread: queued at the tail of the new priority.
        let d = dispatcher();
        let p = process(8);
        let mut current = thread(p);
        current.priority = 15;
        run(d, current);
        let mut t = thread(p);
        t.base_priority = 8;
        t.priority = 8;
        d.make_ready(t);

        d.boost(t, 6);
        assert_eq!(t.state(), ThreadState::Ready);
        assert_eq!(d.ready_summary, 1 << 14);
        assert_eq!(d.find_ready(14), id_of(t));
    }

    /// The boost itself does not consult the thread's boost policy; that gate belongs to the
    /// wait-exit path.
    #[test]
    fn a_boost_ignores_the_boost_policy() {
        let d = dispatcher();
        let p = process(8);
        let mut t = thread(p);
        t.base_priority = 8;
        t.priority = 8;
        t.set_quantum(1);
        t.disable_boost = true;

        d.boost(t, 2);
        assert_eq!(t.priority(), 10);
    }

    // --- Group F: quantum reset and end decay --------------------------------

    /// The tick cadence: 3 charged per tick, one quantum spans two ticks, and the end is flagged at
    /// zero — except for the idle thread.
    #[test]
    fn the_tick_charges_three_and_flags_at_zero() {
        let d = dispatcher();
        let p = process(8);
        let mut t = thread(p);
        t.set_quantum(6);

        assert!(!d.tick_quantum(t));
        assert_eq!(t.quantum(), 3);
        assert!(d.tick_quantum(t));
        assert_eq!(t.quantum(), 0);

        // The idle thread is never flagged.
        d.install_idle_thread(t.id());
        assert!(!d.tick_quantum(t));
        assert_eq!(t.quantum(), -3);
    }

    /// Quantum end resets the quantum to the process value first.
    #[test]
    fn quantum_end_resets_the_quantum() {
        let d = dispatcher();
        let p = process(8);
        let mut t = thread(p);
        run(d, t);
        t.set_quantum(0);

        assert!(d.quantum_end().is_none());
        assert_eq!(t.quantum(), 6);
    }

    /// Variable-class decay: one priority step per quantum.
    #[test]
    fn quantum_end_decays_one_step() {
        let d = dispatcher();
        let p = process(8);
        let mut t = thread(p);
        t.priority = 10;
        run(d, t);
        t.set_quantum(0);

        d.quantum_end();
        assert_eq!(t.priority(), 9);
        assert_eq!(t.quantum(), 6);
        assert_eq!(t.priority_decrement(), 0);
    }

    /// The decay floors at the base priority, and at the floor the equal-priority round-robin takes
    /// over.
    #[test]
    fn quantum_end_decays_to_the_floor() {
        let d = dispatcher();
        let p = process(8);
        let mut t = thread(p);
        t.priority = 8;
        run(d, t);
        t.set_quantum(0);

        assert!(d.quantum_end().is_none());
        assert_eq!(t.priority(), 8);
        assert_eq!(t.quantum(), 6);
    }

    /// The decay consumes the outstanding debt, then clears it.
    #[test]
    fn quantum_end_consumes_the_decay_debt() {
        let d = dispatcher();
        let p = process(8);
        let mut t = thread(p);
        t.priority = 10;
        t.priority_decrement = 3;
        run(d, t);
        t.set_quantum(0);

        d.quantum_end();
        assert_eq!(t.priority(), 8, "10 - 3 - 1 = 6, floored at the base");
        assert_eq!(t.priority_decrement(), 0);
    }

    /// Realtime threads do not decay: at quantum end an equal ready thread takes the standby slot —
    /// round-robin among equals.
    #[test]
    fn quantum_end_round_robins_realtime_equals() {
        let d = dispatcher();
        let p = process(24);
        let mut t = thread(p);
        t.priority = 24;
        run(d, t);
        t.set_quantum(0);
        let mut equal = thread(p);
        equal.priority = 24;
        d.make_ready(equal);

        let selected = d.quantum_end();
        assert_eq!(selected, id_of(equal));
        assert_eq!(equal.state(), ThreadState::Standby);
        assert_eq!(d.next_thread(), id_of(equal));
        assert_eq!(t.priority(), 24, "no decay in the realtime band");
        assert_eq!(t.quantum(), 6);
    }

    /// A realtime thread whose process exempts it never ends its quantum: the quantum refills to
    /// the maximum instead.
    #[test]
    fn quantum_end_exempt_realtime_never_ends() {
        let d = dispatcher();
        let p = process(24);
        unsafe { (*p).set_disable_quantum(true) };
        let mut t = thread(p);
        t.priority = 24;
        run(d, t);
        t.set_quantum(0);

        assert!(d.quantum_end().is_none());
        assert_eq!(t.quantum(), i8::MAX);
        assert_eq!(t.priority(), 24);
        assert!(d.next_thread().is_none());
    }

    /// The balance-set boost: raised to the top of the variable band with a doubled quantum — the
    /// one place the quantum doubles — and re-readied.
    #[test]
    fn the_balance_boost_doubles_the_quantum() {
        let d = dispatcher();
        let p = process(8);
        let mut t = thread(p);
        t.priority = 8;
        t.set_quantum(1);

        d.balance_boost(t);
        assert_eq!(t.priority_decrement(), 7, "the debt is the boost distance");
        assert_eq!(t.decrement_count(), 16);
        assert_eq!(t.priority(), 15);
        assert_eq!(t.quantum(), 12, "6 * 2: the doubled quantum");
        assert_eq!(t.state(), ThreadState::Ready);
        assert_eq!(d.find_ready(0), id_of(t));
    }

    /// The balance-set scan: a thread ready for the full threshold is boosted and preempts the
    /// spinner that starved it; one ready for less is left alone.
    #[test]
    fn the_scan_boosts_a_starved_thread() {
        let d = dispatcher();
        let p = process(8);
        let mut hog = thread(p);
        hog.priority = 8;
        run(d, hog);
        set_test_ticks(1000);
        let mut starved = thread(p);
        starved.priority = 1;
        starved.base_priority = 1;
        d.make_ready(starved);
        assert_eq!(starved.wait_time(), 1000, "stamped as it queued");

        set_test_ticks(1000 + READY_WITHOUT_RUNNING - 1);
        assert_eq!(d.scan_ready_queues(), 0, "not starved long enough yet");
        set_test_ticks(1000 + READY_WITHOUT_RUNNING);
        assert_eq!(d.scan_ready_queues(), 1);
        assert_eq!(starved.priority(), REALTIME_BASE - 1);
        assert_eq!(
            d.next_thread(),
            id_of(starved),
            "the boost preempts the spinner"
        );
    }

    /// The yield: nothing ready, no yield; a ready lower-priority thread takes the processor, and
    /// the yielder queues behind it at its decayed priority.
    #[test]
    fn the_yield_hands_the_processor_to_any_ready_thread() {
        let d = dispatcher();
        let p = process(8);
        let mut running = thread(p);
        running.priority = 10;
        running.base_priority = 8;
        run(d, running);
        assert!(!d.yield_execution(running), "nothing else is ready");
        assert_eq!(running.priority(), 10, "a refused yield changes nothing");

        let mut low = thread(p);
        low.priority = 4;
        low.base_priority = 4;
        d.make_ready(low);
        assert!(d.yield_execution(running));
        assert_eq!(
            d.next_thread(),
            id_of(low),
            "the lower-priority thread is selected"
        );
        assert_eq!(running.state(), ThreadState::Ready);
        assert_eq!(running.priority(), 9, "decayed one step");
        assert_eq!(d.find_ready(0), id_of(running));
    }

    /// The round-trip boost: to the ceiling with a doubled quantum, renewed per round trip, and
    /// dropped to base (through the full form) when the count runs out — then immediately retried.
    #[test]
    fn the_round_trip_boost_renews_then_drops() {
        let d = dispatcher();
        let p = process(8);
        let mut t = thread(p);
        t.priority = 8;
        run(d, t);
        t.set_quantum(1);

        d.boost_current_round_trip();
        assert_eq!(t.priority(), 14);
        assert_eq!(t.priority_decrement(), 6);
        assert_eq!(t.decrement_count(), 16);
        assert_eq!(t.quantum(), 12);

        d.boost_current_round_trip();
        assert_eq!(t.decrement_count(), 15);
        assert_eq!(t.quantum(), 12);

        // Run the count down to exhaustion: the drop replenishes and clears, then the boost is
        // retried.
        for _ in 0..15 {
            d.boost_current_round_trip();
        }
        assert_eq!(t.priority(), 14);
        assert_eq!(t.priority_decrement(), 6);
        assert_eq!(t.decrement_count(), 16);
        assert_eq!(t.quantum(), 12);
    }

    /// A thread at or above the ceiling is never round-trip boosted.
    #[test]
    fn the_round_trip_boost_refuses_at_the_ceiling() {
        let d = dispatcher();
        let p = process(8);
        let mut t = thread(p);
        t.priority = 15;
        run(d, t);
        t.set_quantum(3);

        d.boost_current_round_trip();
        assert_eq!(t.priority(), 15);
        assert_eq!(t.quantum(), 3);
        assert_eq!(t.priority_decrement(), 0);
    }

    /// The wait charge: one unit per completed wait, with the quantum-end decay at exhaustion;
    /// realtime threads and time-critical bases replenish outright.
    #[test]
    fn the_wait_charge_decays_at_exhaustion() {
        let d = dispatcher();
        let p = process(8);

        let mut t = thread(p);
        t.priority = 10;
        t.set_quantum(4);
        d.charge_wait(t);
        assert_eq!(t.quantum(), 3);

        // Exhaustion: reset and decay, floored at the base.
        let mut t = thread(p);
        t.priority = 10;
        t.priority_decrement = 2;
        t.set_quantum(1);
        d.charge_wait(t);
        assert_eq!(t.quantum(), 6);
        assert_eq!(t.priority(), 8, "10 - 2 - 1 = 7, floored at the base");
        assert_eq!(t.priority_decrement(), 0);

        // Realtime replenishes outright.
        let mut t = thread(p);
        t.priority = 24;
        t.set_quantum(5);
        d.charge_wait(t);
        assert_eq!(t.quantum(), 6);
        assert_eq!(t.priority(), 24);

        // A time-critical base replenishes outright.
        let mut t = thread(p);
        t.priority = 10;
        t.base_priority = 14;
        t.set_quantum(2);
        d.charge_wait(t);
        assert_eq!(t.quantum(), 6);
    }

    // --- Group G: the process side -------------------------------------------

    /// Process base-priority change within the variable class: every thread's base and priority
    /// move by the adjustment, clamped in the band; the quantum source stays the process's fixed
    /// value.
    #[test]
    fn process_priority_moves_variable_threads() {
        let d = dispatcher();
        let p = process(8);
        let mut a = thread(p);
        a.priority = 8;
        let mut b = thread(p);
        b.base_priority = 12;
        b.priority = 14;

        assert_eq!(d.set_process_priority(unsafe { &mut *p }, 12), 8);
        assert_eq!(unsafe { (*p).base_priority() }, 12);
        assert_eq!(a.base_priority(), 12);
        assert_eq!(a.priority(), 12);
        assert_eq!(b.base_priority(), 15, "12 + 4 clamped below realtime");
        assert_eq!(b.priority(), 15);
        assert_eq!(b.quantum(), 6, "the quantum source is the process");
        assert_eq!(unsafe { (*p).thread_quantum() }, 6);
        assert_eq!(d.audit(), Ok(()));
    }

    /// A process base-priority change into the realtime class clamps its threads into the realtime
    /// band.
    #[test]
    fn process_priority_into_realtime_clamps_threads() {
        let d = dispatcher();
        let p = process(8);
        let mut a = thread(p);
        a.priority = 8;

        d.set_process_priority(unsafe { &mut *p }, 16);
        assert_eq!(a.base_priority(), 16);
        assert_eq!(a.priority(), 16);
    }

    /// Crossing into the realtime class moves saturated threads to the realtime pins: high
    /// saturation to the top, low saturation to the band floor.
    #[test]
    fn process_priority_crossing_pins_saturated_threads() {
        let d = dispatcher();
        let p = process(8);
        let mut high = thread(p);
        high.saturation = 1;
        let mut low = thread(p);
        low.saturation = -1;

        d.set_process_priority(unsafe { &mut *p }, 16);
        assert_eq!(high.base_priority(), 31);
        assert_eq!(high.priority(), 31);
        assert_eq!(low.base_priority(), 16);
        assert_eq!(low.priority(), 16);
    }

    /// Saturated threads are untouched when the class does not cross — in either direction.
    #[test]
    fn process_priority_leaves_saturated_threads_within_a_class() {
        let d = dispatcher();

        // Realtime staying realtime: a saturated thread keeps its pinned base, priority and
        // quantum.
        let p = process(20);
        let mut t = thread(p);
        t.base_priority = 31;
        t.priority = 31;
        t.saturation = 1;
        t.set_quantum(2);
        d.set_process_priority(unsafe { &mut *p }, 24);
        assert_eq!(t.base_priority(), 31, "untouched by the walk");
        assert_eq!(t.priority(), 31);
        assert_eq!(t.quantum(), 2);

        // Variable staying variable.
        let p = process(8);
        let mut t = thread(p);
        t.base_priority = 15;
        t.priority = 15;
        t.saturation = 1;
        t.set_quantum(2);
        d.set_process_priority(unsafe { &mut *p }, 10);
        assert_eq!(t.base_priority(), 15);
        assert_eq!(t.priority(), 15);
        assert_eq!(t.quantum(), 2);
    }

    /// Crossing from realtime down to variable pins saturated threads to the variable edges.
    #[test]
    fn process_priority_crossing_down_pins_saturated_threads() {
        let d = dispatcher();
        let p = process(20);
        let mut high = thread(p);
        high.saturation = 1;
        let mut low = thread(p);
        low.saturation = -1;

        d.set_process_priority(unsafe { &mut *p }, 10);
        assert_eq!(high.base_priority(), 15, "the variable ceiling");
        assert_eq!(high.priority(), 15);
        assert_eq!(low.base_priority(), 1, "the variable floor");
        assert_eq!(low.priority(), 1);
    }

    // --- The tick's quantum charge --------------------------------------------

    /// A1: the two-tick cadence — the charge is half the reset, so a fresh quantum survives exactly
    /// one full tick and ends on the second; the window's decision resets it, and the cycle
    /// repeats.
    #[test]
    fn the_quantum_charge_runs_out_every_second_tick() {
        let d = dispatcher();
        let p = process(8);
        let t = thread(p);
        run(d, t);

        // One charge: mid-quantum, no request.
        charge_tick();
        assert_eq!(t.quantum(), QUANTUM_RESET - QUANTUM_TICK);
        assert!(
            !quantum_end_requested(),
            "a mid-quantum charge requests nothing"
        );

        // Second charge: the quantum ends, the request is armed.
        charge_tick();
        assert_eq!(t.quantum(), 0);
        assert!(quantum_end_requested(), "the quantum end arms the request");

        // The window consumes the request; with nobody else schedulable the decision resets the
        // quantum and the thread continues.
        assert!(d.dispatch_target().is_none());
        assert!(!quantum_end_requested(), "the window consumes the request");
        assert_eq!(t.quantum(), QUANTUM_RESET);

        // The cycle repeats.
        charge_tick();
        assert!(!quantum_end_requested());
        charge_tick();
        assert!(quantum_end_requested());
    }

    /// A1b: the running thread's quantum is the processor's while it runs — the clock charges it in
    /// the slots, without the dispatcher — and the switch hands it back to the record, the incoming
    /// thread's coming out of its own.
    #[test]
    fn the_running_quantum_lives_in_the_processor_slots() {
        let d = dispatcher();
        let p = process(8);
        let a = thread(p);
        let b = thread(p);
        d.enter(a.id());
        assert_eq!(slots().quantum(), QUANTUM_RESET);

        charge_tick();
        assert_eq!(slots().quantum(), QUANTUM_RESET - QUANTUM_TICK);
        assert_eq!(
            a.quantum(),
            QUANTUM_RESET - QUANTUM_TICK,
            "read where it is kept"
        );

        d.enter(b.id());
        assert_eq!(
            a.quantum(),
            QUANTUM_RESET - QUANTUM_TICK,
            "handed back at the switch"
        );
        assert_eq!(
            slots().quantum(),
            QUANTUM_RESET,
            "the incoming thread's own"
        );
        d.enter(a.id());
        assert_eq!(slots().quantum(), QUANTUM_RESET - QUANTUM_TICK);
    }

    /// A2: the charge is mode- and context-blind — it lands on whoever is current, taking no frame
    /// and no mode, whatever the tick interrupted.
    #[test]
    fn the_charge_lands_on_whoever_is_current() {
        let d = dispatcher();
        let p = process(8);
        let a = thread(p);
        let b = thread(p);
        run(d, a);
        charge_tick();
        assert_eq!(a.quantum(), QUANTUM_RESET - QUANTUM_TICK);
        assert_eq!(
            b.quantum(),
            QUANTUM_RESET,
            "a non-current thread is untouched"
        );

        run(d, b);
        charge_tick();
        assert_eq!(b.quantum(), QUANTUM_RESET - QUANTUM_TICK);
        assert_eq!(a.quantum(), QUANTUM_RESET - QUANTUM_TICK);
    }

    /// A3: the end test is signed — a charge landing on an already-exhausted quantum still ends it
    /// (zero or negative, not merely zero).
    #[test]
    fn an_exhausted_quantum_still_ends() {
        let d = dispatcher();
        let p = process(8);
        let mut t = thread(p);
        run(d, t);
        t.set_quantum(2);
        charge_tick();
        assert_eq!(t.quantum(), -1);
        assert!(quantum_end_requested());
    }

    /// A4: the idle thread is charged like any other thread but never requests — the gate sits
    /// between the charge and the request, never around the charge.
    #[test]
    fn the_idle_thread_is_charged_but_never_requests() {
        let d = dispatcher();
        let p = process(0);
        let mut idle = thread(p);
        d.install_idle_thread(idle.id());
        run(d, idle);

        charge_tick();
        assert_eq!(idle.quantum(), QUANTUM_RESET - QUANTUM_TICK);
        assert!(!quantum_end_requested());
        charge_tick();
        assert_eq!(idle.quantum(), 0, "the idle thread's quantum is real data");
        assert!(!quantum_end_requested(), "only the request is gated");
        assert!(d.dispatch_target().is_none());

        // The ledger's floor: a charge at the byte floor saturates (the counter is a signed byte)
        // rather than wrapping to a positive quantum — the never-reset ledger rests at the floor,
        // and no request ever arms.
        idle.set_quantum(i8::MIN);
        charge_tick();
        assert_eq!(idle.quantum(), i8::MIN);
        assert!(!quantum_end_requested());
    }

    /// A thread charged past its quantum without a dispatch window stays exhausted: the charge
    /// saturates at the byte floor instead of wrapping back to a positive quantum (about 43 ticks
    /// at the reset value) and silently granting the thread another one.
    #[test]
    fn an_overcharged_quantum_never_wraps_positive() {
        let d = dispatcher();
        let p = process(8);
        let mut t = thread(p);
        run(d, t);
        t.set_quantum(i8::MIN + 1);
        assert!(d.tick_quantum(t));
        assert_eq!(t.quantum(), i8::MIN);
        assert!(d.tick_quantum(t), "still exhausted at the floor");
        assert_eq!(t.quantum(), i8::MIN);
    }

    // --- The request rules ------------------------------------------------------

    /// B2: making a thread ready at strictly higher priority than the running thread requests the
    /// processor; an equal arrival never does — round-robin among equals happens only at quantum
    /// end.
    #[test]
    fn a_strictly_higher_arrival_requests_and_an_equal_does_not() {
        let d = dispatcher();
        let p = process(8);
        let main = thread(p);
        run(d, main);

        let mut higher = thread(p);
        higher.priority = 10;
        higher.base_priority = 10;
        d.make_ready(higher);
        assert!(
            d.next_thread() == id_of(higher),
            "the higher arrival takes the standby slot"
        );
        assert!(
            main.preempted,
            "the running thread is marked for the head requeue"
        );

        // The equal arrival: no request, a plain tail queueing.
        let d = dispatcher();
        let p = process(8);
        let main = thread(p);
        run(d, main);
        let equal = thread(p);
        d.make_ready(equal);
        assert!(d.next_thread().is_none(), "an equal arrival never requests");
        assert!(!main.preempted);
        assert_eq!(equal.state, ThreadState::Ready);
    }

    /// B3: the priority-change arms produce the same request data as an arrival — a Ready thread
    /// raised above the running thread, and a Running thread lowered below a ready one.
    #[test]
    fn priority_changes_request_the_processor() {
        // A Ready thread raised: it re-readies through the strictly-higher rule.
        let d = dispatcher();
        let p = process(8);
        let main = thread(p);
        run(d, main);
        let raised = thread(p);
        d.make_ready(raised);
        d.apply_priority(raised, 9);
        assert!(d.next_thread() == id_of(raised));
        assert!(main.preempted);

        // A Running thread lowered: the replacement look selects a ready thread at or above the new
        // priority.
        let d = dispatcher();
        let p = process(9);
        let main = thread(p);
        run(d, main);
        let better = thread(p);
        d.make_ready(better); // equal to the runner: queued, no request
        assert!(d.next_thread().is_none());
        d.apply_priority(main, 7);
        assert!(
            d.next_thread() == id_of(better),
            "the lowered thread's replacement is selected"
        );
    }

    /// B4: an idle processor takes a readied thread as a handoff, not a preemption — nothing is
    /// displaced and nothing is flagged.
    #[test]
    fn an_idle_processor_takes_the_thread_without_preemption() {
        let d = dispatcher();
        let p = process(0);
        let idle = thread(p);
        d.install_idle_thread(idle.id());
        run(d, idle);

        let p2 = process(8);
        let t = thread(p2);
        d.make_ready(t);
        assert!(d.next_thread() == id_of(t));
        assert!(!idle.preempted, "the handoff displaces nobody");
    }

    /// B5: the disable-quantum realtime exemption lives in the decision, not in the charge — the
    /// request is armed, then consumed to a refusal: the quantum refills to the maximum and nobody
    /// is selected.
    #[test]
    fn the_realtime_exemption_refuses_at_the_decision() {
        let d = dispatcher();
        let p = process(20);
        unsafe { (*p).disable_quantum = true };
        let rt = thread(p);
        run(d, rt);
        assert!(rt.priority() >= REALTIME_BASE);

        // A ready equal stays queued through the whole sequence.
        let other = thread(p);
        d.make_ready(other);
        assert!(d.next_thread().is_none(), "an equal arrival never requests");

        charge_tick();
        charge_tick();
        assert!(quantum_end_requested(), "the charge itself is not exempted");
        assert!(
            d.dispatch_target().is_none(),
            "the exemption refuses the switch"
        );
        assert_eq!(rt.quantum(), i8::MAX);
        assert_eq!(
            other.state,
            ThreadState::Ready,
            "the queued equal is untouched"
        );
    }

    // --- The delivery decision ----------------------------------------------------

    /// C1: a quantum end with a better thread switches, and the displaced running thread requeues
    /// at the tail — a round-robined thread keeps its turn order among equals.
    #[test]
    fn a_quantum_end_switches_to_the_equal_and_requeues_at_the_tail() {
        let d = dispatcher();
        let p = process(8);
        let a = thread(p);
        run(d, a);
        let b = thread(p);
        d.make_ready(b); // queued at 8

        charge_tick();
        charge_tick();
        let target = d.dispatch_target();
        assert!(target == id_of(b), "the round-robin look finds the equal");
        assert!(d.next_thread().is_none(), "the target leaves the slot");
        assert_eq!(
            b.state,
            ThreadState::Standby,
            "the caller enters the target"
        );
        assert_eq!(a.state, ThreadState::Ready);
        assert!(!a.preempted, "the quantum-end path flags nobody");
        // The tail requeue: the selection order keeps the round-robin's FIFO among equals.
        assert!(d.find_ready(0) == id_of(a));
    }

    /// C1's strictly-higher variant: the quantum-end loser still requeues at the tail even when a
    /// strictly higher thread had taken the slot — the quantum decision clears the displacement
    /// flag before the requeue spends it.
    #[test]
    fn a_quantum_end_clears_the_displacement_before_the_requeue() {
        let d = dispatcher();
        let p = process(8);
        let a = thread(p);
        run(d, a);
        // A queued equal gives the tail requeue something to fall behind.
        let queued = thread(p);
        d.make_ready(queued);
        let mut higher = thread(p);
        higher.priority = 12;
        higher.base_priority = 12;
        d.make_ready(higher); // takes the slot, flags a
        assert!(a.preempted);

        charge_tick();
        charge_tick();
        let target = d.dispatch_target();
        assert!(target == id_of(higher));
        assert!(!a.preempted, "the decision cleared the flag");
        // The tail requeue: the queued equal keeps its place ahead.
        assert!(d.find_ready(0) == id_of(queued));
        assert!(d.find_ready(0) == id_of(a));
    }

    /// C1b: the same displacement when the quantum end also decays the priority: the decay leaves
    /// the standby in place, and the thread still requeues behind the equal at its new level — the
    /// earlier arrival's preemption mark does not put it at the head.
    #[test]
    fn a_decaying_quantum_end_still_requeues_at_the_tail() {
        let d = dispatcher();
        let p = process(8);
        let mut a = thread(p);
        a.priority = 10; // boosted above its base of 8
        run(d, a);
        let mut equal = thread(p);
        equal.priority = 9;
        d.make_ready(equal);
        let mut higher = thread(p);
        higher.priority = 12;
        higher.base_priority = 12;
        d.make_ready(higher); // takes the slot, flags a
        assert!(a.preempted);

        charge_tick();
        charge_tick();
        let target = d.dispatch_target();
        assert!(target == id_of(higher));
        assert_eq!(a.priority(), 9, "the quantum end decayed one step");
        assert!(!a.preempted);
        assert!(d.find_ready(0) == id_of(equal));
        assert!(d.find_ready(0) == id_of(a));
    }

    /// C1c: a thread readied while the idle thread runs is switched to at the window, and the idle
    /// thread is not queued behind it: it stays the fallback, off every ready list.
    #[test]
    fn the_window_never_queues_the_idle_thread() {
        let d = dispatcher();
        let p = process(8);
        let idle_process = process(0);
        let mut idle = thread(idle_process);
        idle.state = ThreadState::Running;
        d.install_idle_thread(idle.id());
        let woken = thread(p);
        d.make_ready(woken); // takes the idle processor: the standby slot

        let target = d.dispatch_target();
        assert!(target == id_of(woken));
        assert_eq!(d.ready_summary, 0, "the idle thread is not on ready list 0");
        assert!(!d.has_schedulable());
        assert_eq!(
            idle.state(),
            ThreadState::Running,
            "untouched until the switch"
        );
    }

    /// C2: a request with no better thread is consumed to a refusal — the thread keeps the
    /// processor with a fresh quantum.
    #[test]
    fn a_request_with_no_better_thread_is_a_refusal() {
        let d = dispatcher();
        let p = process(8);
        let a = thread(p);
        run(d, a);

        charge_tick();
        charge_tick();
        assert!(d.dispatch_target().is_none());
        assert!(!quantum_end_requested());
        assert_eq!(a.quantum(), QUANTUM_RESET);
        assert_eq!(
            a.state,
            ThreadState::Running,
            "the thread keeps the processor"
        );
    }

    /// C3: a strictly-higher standby — the shape a drained deferred-work routine leaves — switches
    /// mid-quantum, with the displaced thread requeued at the head.
    #[test]
    fn a_standby_from_the_drained_work_switches_at_the_head_requeue() {
        let d = dispatcher();
        let p = process(8);
        let mut a = thread(p);
        run(d, a);
        a.set_quantum(QUANTUM_RESET - QUANTUM_TICK); // mid-quantum

        // A queued equal gives the head requeue something to be ahead of.
        let queued = thread(p);
        d.make_ready(queued);

        // The drain's effect: a strictly higher thread readied.
        let mut woken = thread(p);
        woken.priority = 12;
        woken.base_priority = 12;
        d.make_ready(woken);
        assert!(d.next_thread() == id_of(woken));

        let target = d.dispatch_target();
        assert!(target == id_of(woken));
        assert!(!quantum_end_requested(), "no quantum was involved");
        // The displaced thread went to the head of its queue.
        assert!(d.find_ready(0) == id_of(a));
        assert!(d.find_ready(0) == id_of(queued));
    }

    /// C4: the window's order — the drained work first, then the quantum decision — is what lets an
    /// equal readied by the drain win the round-robin look in the same window.
    #[test]
    fn the_window_sees_what_the_drain_readied() {
        let d = dispatcher();
        let p = process(8);
        let a = thread(p);
        run(d, a);
        charge_tick();
        charge_tick(); // the quantum ends, the request arms

        // The drained work readies an equal — after the request, before the decision.
        let s = thread(p);
        d.make_ready(s);

        let target = d.dispatch_target();
        assert!(
            target == id_of(s),
            "the post-drain table feeds the decision"
        );
        assert!(d.next_thread().is_none());
    }

    /// C5: the decision is frame-agnostic — it consults thread state alone; the interrupted frame's
    /// mode is not an input (the entry takes none).
    #[test]
    fn the_decision_reads_thread_state_alone() {
        // The decision is reached from whatever context the window opened in; the entry's only
        // inputs are the dispatcher's own state, so every context decides identically.
        let d = dispatcher();
        let p = process(8);
        let a = thread(p);
        run(d, a);
        let b = thread(p);
        d.make_ready(b);
        charge_tick();
        charge_tick();
        assert!(d.dispatch_target() == id_of(b));
    }

    // --- The request lifecycle -----------------------------------------------------

    /// D1: the request is cleared before the decision runs — the consumption is unconditional,
    /// refusal included.
    #[test]
    fn the_request_is_cleared_before_the_decision() {
        let d = dispatcher();
        let p = process(8);
        let a = thread(p);
        run(d, a);
        charge_tick();
        charge_tick();
        assert!(quantum_end_requested());
        assert!(d.dispatch_target().is_none());
        assert!(
            !quantum_end_requested(),
            "even a refused request is consumed"
        );
    }

    /// D2: the request is edge-armed per quantum end — only an end arms it, only a window consumes
    /// it, and nothing merges or queues in between.
    #[test]
    fn the_request_is_edge_armed_and_window_consumed() {
        let d = dispatcher();
        let p = process(8);
        let a = thread(p);
        run(d, a);

        charge_tick();
        assert!(
            !quantum_end_requested(),
            "a mid-quantum charge arms nothing"
        );
        charge_tick();
        assert!(quantum_end_requested());
        // A second end (a charge landing on the exhausted quantum mid-window) merges into the same
        // one-bit request.
        charge_tick();
        assert!(quantum_end_requested());
        assert!(d.dispatch_target().is_none());
        assert!(!quantum_end_requested(), "one bit, one consumption");

        // The next cycle arms fresh.
        charge_tick();
        charge_tick();
        assert!(quantum_end_requested());
    }

    /// D3: a stale request — one that outlived the window it armed (the quantum was reset before
    /// the window ran) — is consumed to a no-op: the decision re-verifies the quantum.
    #[test]
    fn a_stale_request_is_consumed_to_a_no_op() {
        let d = dispatcher();
        let p = process(8);
        let a = thread(p);
        run(d, a);
        let b = thread(p);
        d.make_ready(b);

        // A's quantum is positive (fresh), but a request is pending — the stale shape.
        slots().request_quantum_end();
        assert!(
            d.dispatch_target().is_none(),
            "the decision re-verifies, not trusts"
        );
        assert_eq!(
            a.state,
            ThreadState::Running,
            "the quantum's owner keeps the processor"
        );
        assert_eq!(
            b.state,
            ThreadState::Ready,
            "the queued equal is not stolen"
        );
    }

    // --- The service-boundary delivery -----------------------------------------------

    /// E1 (with F2's composition): a service that raises a ready thread above the caller leaves the
    /// request pending, and the boundary check delivers it — the caller is requeued at the head,
    /// having been displaced by a strictly higher thread.
    #[test]
    fn the_boundary_check_delivers_the_service_request() {
        let d = dispatcher();
        let p = process(8);
        let main = thread(p);
        run(d, main);
        let child = thread(p);
        d.make_ready(child); // queued at 8

        // The service's kernel work: raise the child above the caller.
        d.set_base_priority(child, 1);
        assert!(d.next_thread() == id_of(child), "the raise requests");
        assert!(main.preempted);

        // The boundary check: the same decision, no quantum involved.
        let target = d.dispatch_target();
        assert!(target == id_of(child));
        assert!(d.next_thread().is_none());
        // The displaced caller requeues at the head: its displacement flag decides head vs tail.
        assert!(d.find_ready(0) == id_of(main));
    }

    /// E2: with nothing pending, the check is a free no-op — no thread's state, quantum, or queue
    /// position moves.
    #[test]
    fn the_boundary_check_without_a_request_is_a_no_op() {
        let d = dispatcher();
        let p = process(8);
        let main = thread(p);
        run(d, main);
        let equal = thread(p);
        d.make_ready(equal); // equal: queued, no request

        assert!(d.dispatch_target().is_none());
        assert_eq!(main.state, ThreadState::Running);
        assert_eq!(main.quantum(), QUANTUM_RESET);
        assert_eq!(equal.state, ThreadState::Ready);
        assert!(d.next_thread().is_none());
    }

    // --- The APC delivery window's order -------------------------------------

    thread_local! {
        static APC_KERNEL_ROUTINE_RAN: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    }

    fn apc_kernel_routine(_apc: crate::sched::apc::ApcId, _args: &mut ApcArgs) {
        APC_KERNEL_ROUTINE_RAN.with(|ran| ran.set(true));
    }

    /// D7: the window's order — the dispatch decision (the quantum end, then the standby arrival)
    /// runs first, and the kernel-APC delivery applies to the thread the decision left current. A
    /// switch hands delivery to the resumed thread's own tail; the window never delivers on the
    /// outgoing thread.
    #[test]
    fn the_window_decides_the_dispatch_before_delivering_apcs() {
        // With a dispatch request pending and an equal-priority thread ready, the quantum-end
        // round-robin selects it: the decision's target is the switch's, and the running thread's
        // armed APC stays armed — the target delivers at its own resume tail, not here.
        let d = dispatcher();
        let p = process(8);
        let mut main = thread(p);
        run(d, main);
        let equal = thread(p);
        d.make_ready(equal);
        let mut apc = crate::sched::testkit::apc();
        apc.init(main, apc_kernel_routine, None, ApcMode::Kernel, 0);
        assert!(d.queue_apc(apc, 0, 0, 0));
        // The tick's quantum-end request: a charge that runs the quantum out arms the flag.
        main.set_quantum(0);
        charge_tick();

        let target = d.dispatch_target();
        assert_eq!(target, id_of(equal), "the decision switched");
        assert!(
            main.kernel_apc_pending,
            "the outgoing thread's APC is the resumed tail's, not the window's"
        );
        assert!(
            !APC_KERNEL_ROUTINE_RAN.with(|ran| ran.get()),
            "nothing delivered on the outgoing thread"
        );

        // Without a dispatch request, the window delivers on the current thread directly: the
        // decision leaves no target, and the armed APC runs here.
        let d = dispatcher();
        let p = process(8);
        let solo = thread(p);
        run(d, solo);
        let mut apc = crate::sched::testkit::apc();
        apc.init(solo, apc_kernel_routine, None, ApcMode::Kernel, 0);
        assert!(d.queue_apc(apc, 0, 0, 0));

        assert!(d.dispatch_target().is_none(), "no request, no target");
        assert_eq!(
            crate::sched::apc::deliver_kernel_apcs(),
            ApcDelivery::Delivered
        );
        assert!(
            APC_KERNEL_ROUTINE_RAN.with(|ran| ran.get()),
            "the window delivered the armed APC on the current thread"
        );
        assert!(!solo.kernel_apc_pending);
    }
}
