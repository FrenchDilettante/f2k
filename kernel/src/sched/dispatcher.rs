//! The dispatcher: the ready queues and the processor's thread slots.
//!
//! One processor. The dispatcher owns the ready lists — one per
//! priority level, summarized in a 32-bit bitmap whose bit P is set
//! while ready list P is non-empty — and the processor's three
//! slots: `current` (Running), `next` (the Standby thread the next
//! switch will enter) and `idle` (the resting thread, installed by
//! the boot). Selection is the bitmap: the highest set bit at or
//! above the floor names the queue, whose head is taken first-in,
//! first-out.
//!
//! The state machines below decide, from a thread's state, what a
//! change of priority, a boost, or the end of a quantum does to the
//! queues and the slots. They never switch: selecting the next
//! thread stops at Standby, and turning Standby into Running is the
//! context switch's business.

use super::process::SchedProcess;
use super::thread::{Thread, ThreadState};
use super::{
    unlink, List, Links, HIGHEST_PRIORITY, PRIORITY_LEVELS, QUANTUM_TICK, QUANTUM_WAIT_CHARGE,
    REALTIME_BASE, ROUND_TRIP_LIMIT, TIME_CRITICAL_CEILING,
};
use core::ptr::{addr_of_mut, eq, null_mut};

/// The dispatcher: ready queues, the summary, the processor slots.
pub struct Dispatcher {
    /// One ready list per priority level.
    ready: [List; PRIORITY_LEVELS],
    /// Bit P set while `ready[P]` is non-empty.
    ready_summary: u32,
    /// Whether the processor is running its idle thread (and a
    /// readied thread takes it immediately).
    processor_idle: bool,
    /// The Running thread.
    current: *mut Thread,
    /// The Standby thread: what the next switch enters, or null.
    next: *mut Thread,
    /// The idle thread, entered when nothing else is schedulable.
    idle_thread: *mut Thread,
}

impl Dispatcher {
    /// A dispatcher with unlinked sentinels; call [`Dispatcher::init`]
    /// once it is at its final address.
    pub const fn zeroed() -> Self {
        Dispatcher {
            ready: [List::empty(); PRIORITY_LEVELS],
            ready_summary: 0,
            processor_idle: false,
            current: null_mut(),
            next: null_mut(),
            idle_thread: null_mut(),
        }
    }

    /// Close the ready-list sentinels and empty the dispatcher.
    pub fn init(&mut self) {
        for queue in self.ready.iter_mut() {
            queue.init();
        }
        self.ready_summary = 0;
        self.processor_idle = false;
        self.current = null_mut();
        self.next = null_mut();
        self.idle_thread = null_mut();
    }

    /// The ready-summary invariant: bit P is set exactly while ready
    /// list P is non-empty.
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
        Ok(())
    }

    /// The Standby thread, if one is selected.
    pub fn next_thread(&self) -> *mut Thread {
        self.next
    }

    /// The Running thread.
    pub fn current_thread(&self) -> *mut Thread {
        self.current
    }

    /// Whether the processor is running its idle thread.
    pub fn processor_idle(&self) -> bool {
        self.processor_idle
    }

    /// Whether a switch away from the idle thread is warranted: a
    /// Standby thread is pending or any ready queue is non-empty.
    /// The idle loop's next-thread check, as a query.
    pub fn has_schedulable(&self) -> bool {
        !self.next.is_null() || self.ready_summary != 0
    }

    /// Install the idle thread and mark the processor idle. The boot
    /// install: the processor is executing this very thread, so it
    /// also takes the current slot.
    pub fn install_idle_thread(&mut self, thread: *mut Thread) {
        self.idle_thread = thread;
        self.processor_idle = true;
        self.current = thread;
        self.next = null_mut();
    }

/// The switching path's caller-side install: the selected thread
/// takes the current slot, and the processor is marked idle exactly
/// when it is the idle thread. The Standby-to-Running state write is
/// the swap's own effect.
    pub fn enter(&mut self, selected: *mut Thread) {
        self.current = selected;
        self.processor_idle = eq(selected, self.idle_thread);
    }

    /// Select the highest-priority ready thread at or above `floor`,
    /// unlinking it from its queue. Null if no thread qualifies.
    pub fn find_ready(&mut self, floor: i8) -> *mut Thread {
        debug_assert!((0..=HIGHEST_PRIORITY).contains(&floor));
        let mask = !((1u32 << floor as u32).wrapping_sub(1));
        let set = mask & self.ready_summary;
        if set == 0 {
            return null_mut();
        }

        // Align the highest set bit with the sign position, then walk
        // down one level per iteration.
        let mut level = HIGHEST_PRIORITY - set.leading_zeros() as i8;
        let mut bits = set << (HIGHEST_PRIORITY as u32 - level as u32);
        loop {
            if bits & 0x8000_0000 != 0 {
                let queue = &mut self.ready[level as usize];
                // SAFETY: the summary bit is set, so the queue is
                // non-empty and its head is linked.
                let thread = entry_to_thread(unsafe { queue.pop_front() });
                if queue.is_empty() {
                    self.ready_summary &= !(1 << level as u32);
                }
                return thread;
            }
            bits <<= 1;
            if bits == 0 {
                return null_mut();
            }
            level -= 1;
        }
    }

    /// Make `thread` runnable: give it the processor if it can take
    /// it, else queue it.
    ///
    /// The taking order: an idle processor first; then the Standby
    /// slot; then the Running thread — strictly higher priority wins,
    /// equals never preempt. A thread pushed off the processor (or
    /// out of the standby slot) is marked preempted and re-readied
    /// through this same path, which puts it at the head of its
    /// queue; a thread that merely became runnable queues at the
    /// tail.
    pub fn make_ready(&mut self, thread: &mut Thread) {
        let mut thread: *mut Thread = thread;
        loop {
            // SAFETY: the loop owns the thread exclusively; it is on
            // no ready list (callers queue or select it before it can
            // be passed again).
            let t: &mut Thread = unsafe { &mut *thread };
            let preempted = t.preempted;
            t.preempted = false;
            let priority = t.priority;

            if self.processor_idle {
                self.processor_idle = false;
                self.next = thread;
                t.state = ThreadState::Standby;
                return;
            }

            if !self.next.is_null() {
                // SAFETY: the standby thread is a live, attached
                // thread.
                let standby: &mut Thread = unsafe { &mut *self.next };
                if priority > standby.priority {
                    standby.preempted = true;
                    let displaced = self.next;
                    self.next = thread;
                    t.state = ThreadState::Standby;
                    thread = displaced;
                    continue;
                }
            } else {
                // No standby thread: try the running thread. None
                // (the processor is between threads) counts as
                // non-preemptable.
                let current = self.current;
                // SAFETY: the running thread, if any, is live.
                if !current.is_null() && priority > unsafe { (*current).priority } {
                    // SAFETY: as above.
                    unsafe { (*current).preempted = true };
                    self.next = thread;
                    t.state = ThreadState::Standby;
                    // Asking the processor to redispatch is a
                    // no-op on one CPU: the dispatch level this
                    // runs at is itself the serialization.
                    return;
                }
            }

            // Nobody to preempt: queue by priority.
            t.state = ThreadState::Ready;
            // SAFETY: the thread is on no ready list (see above) and
            // its ready link is valid.
            unsafe {
                let entry = addr_of_mut!(t.ready_links);
                let queue = &mut self.ready[priority as usize];
                if preempted {
                    queue.push_front(entry);
                } else {
                    queue.push_back(entry);
                }
            }
            self.ready_summary |= 1 << priority as u32;
            return;
        }
    }

    /// The thread the processor runs next: a pending Standby thread
    /// first, else the highest-priority ready thread, else the idle
    /// thread (with the processor marked idle so the next readied
    /// thread takes it immediately). The returned thread's state is
    /// the caller's to set — the context switch flips Standby to
    /// Running.
    pub fn select_next(&mut self) -> *mut Thread {
        if !self.next.is_null() {
            let selected = self.next;
            self.next = null_mut();
            return selected;
        }
        let selected = self.find_ready(0);
        if selected.is_null() {
            self.processor_idle = true;
            return self.idle_thread;
        }
        selected
    }

    /// Apply `priority` to `thread` and let its state decide what
    /// moves: a Ready thread requeues (lowered) or re-readies
    /// (raised); a Standby or Running thread being lowered looks for
    /// a replacement at or above the new priority; every other state
    /// takes the field change alone. Equal priority is a complete
    /// no-op.
    ///
    /// This is the raw state machine: it does not touch the quantum
    /// or the decay fields. [`Dispatcher::set_priority`] is the
    /// full form callers outside the scheduler use.
    pub fn apply_priority(&mut self, thread: &mut Thread, priority: i8) {
        let old = thread.priority;
        if priority == old {
            return;
        }
        thread.priority = priority;

        match thread.state {
            ThreadState::Ready => {
                if thread.parked_on_process {
                    // The parked shape never has a ready-queue
                    // membership to move.
                    return;
                }
                // SAFETY: a Ready thread is linked on its old
                // priority's queue.
                unsafe { unlink(addr_of_mut!(thread.ready_links)) };
                if self.ready[old as usize].is_empty() {
                    self.ready_summary &= !(1 << old as u32);
                }
                if priority < old {
                    // SAFETY: unlinked above; the new queue is live.
                    unsafe {
                        self.ready[priority as usize].push_back(addr_of_mut!(thread.ready_links))
                    };
                    self.ready_summary |= 1 << priority as u32;
                } else {
                    self.make_ready(thread);
                }
            }
            ThreadState::Standby => {
                if priority < old {
                    let replacement = self.find_ready(priority);
                    if !replacement.is_null() {
                        // SAFETY: the found thread is a live, unlinked
                        // thread.
                        unsafe { (*replacement).state = ThreadState::Standby };
                        self.next = replacement;
                        self.make_ready(thread);
                    }
                }
            }
            ThreadState::Running if self.next.is_null() && priority < old => {
                let replacement = self.find_ready(priority);
                if !replacement.is_null() {
                    // SAFETY: the found thread is a live, unlinked
                    // thread.
                    unsafe { (*replacement).state = ThreadState::Standby };
                    self.next = replacement;
                }
            }
            _ => {}
        }
    }

    /// Set `thread`'s priority the full form: replenish its quantum,
    /// clear the decay fields, then run the state machine. Returns
    /// the previous priority.
    pub fn set_priority(&mut self, thread: &mut Thread, priority: i8) -> i8 {
        let old = thread.priority;
        thread.quantum = unsafe { (*thread.process).thread_quantum };
        thread.decrement_count = 0;
        thread.priority_decrement = 0;
        self.apply_priority(thread, priority);
        old
    }

    /// Boost `thread` for a wake: the new priority is its base plus
    /// `increment`, applied only when that exceeds its current
    /// priority, capped below the realtime band, and only while no
    /// decay debt is outstanding and the thread runs below the
    /// realtime band. A boost that applies also replenishes the
    /// quantum. The thread's disable-boost policy is deliberately not
    /// consulted here — that gate belongs to the wait-exit path.
    pub fn boost(&mut self, thread: &mut Thread, increment: i8) {
        if thread.priority >= REALTIME_BASE || thread.priority_decrement != 0 {
            return;
        }
        let mut new = thread.base_priority + increment;
        if new > thread.priority {
            if new >= REALTIME_BASE {
                new = REALTIME_BASE - 1;
            }
            thread.quantum = unsafe { (*thread.process).thread_quantum };
            self.apply_priority(thread, new);
        }
    }

    /// The increment of `thread`'s base priority over its process's:
    /// what a base-priority change would report as the previous
    /// value. A saturated thread reports its pin, not the raw delta.
    pub fn base_increment(&self, thread: &Thread) -> i32 {
        let increment =
            thread.base_priority as i32 - unsafe { (*thread.process).base_priority } as i32;
        if thread.saturation != 0 {
            return saturation_pin() * thread.saturation as i32;
        }
        increment
    }

    /// Set `thread`'s base priority to its process's base plus
    /// `increment`, clamped inside the thread's priority class, and
    /// returns the previous increment (see [`base_increment`]). An
    /// increment at or beyond half the priority range in either
    /// direction pins (saturates) the thread to its class edge;
    /// later process base changes cannot move a saturated thread
    /// within the same class.
    pub fn set_base_priority(&mut self, thread: &mut Thread, increment: i32) -> i32 {
        let old_increment = self.base_increment(thread);

        thread.saturation = 0;
        if increment.abs() >= saturation_pin() {
            thread.saturation = if increment > 0 { 1 } else { -1 };
        }

        // SAFETY: the thread is attached; the process is pinned by
        // the thread's lifetime.
        let process: &mut SchedProcess = unsafe { &mut *thread.process };
        let process_base = process.base_priority as i32;
        let old_base = thread.base_priority as i32;

        let mut new_base = process_base + increment;
        let new_priority;
        if process_base >= REALTIME_BASE as i32 {
            // Realtime process: the base stays in the realtime band
            // and the priority follows it exactly.
            if new_base < REALTIME_BASE as i32 {
                new_base = REALTIME_BASE as i32;
            } else if new_base > HIGHEST_PRIORITY as i32 {
                new_base = HIGHEST_PRIORITY as i32;
            }
            new_priority = new_base;
        } else {
            // Variable process: the base stays in the variable band.
            if new_base >= REALTIME_BASE as i32 {
                new_base = REALTIME_BASE as i32 - 1;
            } else if new_base <= 0 {
                new_base = 1;
            }
            if thread.saturation != 0 {
                new_priority = new_base;
            } else {
                let mut candidate = thread.priority as i32
                    + (new_base - old_base)
                    - thread.priority_decrement as i32;
                if candidate >= REALTIME_BASE as i32 {
                    candidate = REALTIME_BASE as i32 - 1;
                }
                new_priority = candidate;
            }
        }

        thread.base_priority = new_base as i8;
        thread.decrement_count = 0;
        thread.priority_decrement = 0;
        if new_priority != thread.priority as i32 {
            thread.quantum = process.thread_quantum;
            self.apply_priority(thread, new_priority as i8);
        }
        old_increment
    }

    /// The end of the running thread's quantum: reset the quantum,
    /// decay the priority one step toward the base (consuming any
    /// outstanding decay debt), and decide who runs next. A
    /// realtime thread does not decay; if its priority is unchanged
    /// and no standby is pending, the equal-priority ready thread
    /// takes the standby slot — round-robin among equals. A realtime
    /// thread whose process exempts it never ends its quantum at all
    /// (its quantum is refilled to the maximum instead). Returns the
    /// standby thread if one was selected, null otherwise.
    pub fn quantum_end(&mut self) -> *mut Thread {
        debug_assert!(!self.current.is_null(), "quantum end without a running thread");
        // SAFETY: the running thread is live and attached; the
        // process pointer is valid for its lifetime.
        let thread: &mut Thread = unsafe { &mut *self.current };
        if thread.quantum > 0 {
            return self.next;
        }

        let process = unsafe { &mut *thread.process };
        if process.disable_quantum && thread.priority >= REALTIME_BASE {
            thread.quantum = i8::MAX;
            return self.next;
        }

        thread.quantum = process.thread_quantum;
        let priority = thread.priority;
        let mut new_priority = priority;
        if priority < REALTIME_BASE {
            new_priority = priority - thread.priority_decrement - 1;
            if new_priority < thread.base_priority {
                new_priority = thread.base_priority;
            }
            thread.priority_decrement = 0;
        }

        if new_priority != priority {
            self.apply_priority(thread, new_priority);
        } else if self.next.is_null() {
            let found = self.find_ready(priority);
            if !found.is_null() {
                // SAFETY: the found thread is a live, unlinked thread.
                unsafe { (*found).state = ThreadState::Standby };
                self.next = found;
            }
        } else {
            // Equal priority and a standby already pending: the
            // running thread stays until the switch.
            thread.preempted = false;
        }
        self.next
    }

    /// Charge one clock tick against `thread`'s quantum. Returns
    /// whether the quantum ended: the charge leaves a positive
    /// quantum alone; at zero it flags the end — except for the idle
    /// thread, which is never flagged.
    pub fn tick_quantum(&mut self, thread: &mut Thread) -> bool {
        thread.quantum -= QUANTUM_TICK;
        if thread.quantum > 0 {
            return false;
        }
        !core::ptr::eq(thread, self.idle_thread)
    }

    /// Charge one completed wait against `thread`'s quantum, with the
    /// same decay at exhaustion as a quantum end. Realtime threads
    /// and threads with a time-critical base replenish outright.
    /// The wait machinery calls this at wait exit; the arithmetic
    /// lives here because the quantum ledger is one discipline.
    pub fn charge_wait(&mut self, thread: &mut Thread) {
        let thread_quantum = unsafe { (*thread.process).thread_quantum };
        if thread.priority >= REALTIME_BASE
            || thread.base_priority >= TIME_CRITICAL_CEILING
        {
            thread.quantum = thread_quantum;
            return;
        }
        thread.quantum -= QUANTUM_WAIT_CHARGE;
        if thread.quantum > 0 {
            return;
        }
        thread.quantum = thread_quantum;
        thread.priority -= thread.priority_decrement + 1;
        if thread.priority < thread.base_priority {
            thread.priority = thread.base_priority;
        }
        thread.priority_decrement = 0;
    }

    /// Boost the running thread to the time-critical ceiling and keep
    /// it there for a fixed number of round trips: while the boost is
    /// in effect, each call renews the doubled quantum and counts
    /// down; when the count runs out, the thread drops back to its
    /// base priority through the full set-priority form and the boost
    /// is immediately retried. A thread already at or above the
    /// ceiling is never boosted.
    pub fn boost_current_round_trip(&mut self) {
        debug_assert!(!self.current.is_null(), "round-trip boost without a running thread");
        // SAFETY: the running thread is live for the whole call.
        let thread: &mut Thread = unsafe { &mut *self.current };
        let thread_quantum = unsafe { (*thread.process).thread_quantum };

        loop {
            if thread.priority_decrement == 0 && thread.priority < TIME_CRITICAL_CEILING {
                thread.priority_decrement = TIME_CRITICAL_CEILING - thread.base_priority;
                thread.decrement_count = ROUND_TRIP_LIMIT;
                thread.priority = TIME_CRITICAL_CEILING;
                thread.quantum = thread_quantum * 2;
                return;
            }
            if thread.priority_decrement == 0 {
                return;
            }
            thread.decrement_count -= 1;
            if thread.decrement_count > 0 {
                thread.quantum = thread_quantum * 2;
                return;
            }
            // Count exhausted: drop to base through the full form
            // (quantum replenished, decay cleared), then retry.
            let base = thread.base_priority;
            self.set_priority(thread, base);
        }
    }

    /// The balance-set boost, applied to a ready-too-long thread the
    /// caller has already unlinked from its ready queue: raise it to
    /// the top of the variable band with a doubled quantum — the one
    /// place the quantum doubles — and re-ready it. The decay debt
    /// records how far the thread will fall back on its next decay.
    pub fn balance_boost(&mut self, thread: &mut Thread) {
        debug_assert!(
            thread.state != ThreadState::Ready || thread.parked_on_process,
            "balance boost on a still-queued thread"
        );
        let thread_quantum = unsafe { (*thread.process).thread_quantum };
        let boost_priority = REALTIME_BASE - 1;
        thread.priority_decrement += boost_priority - thread.priority;
        thread.decrement_count = ROUND_TRIP_LIMIT;
        thread.priority = boost_priority;
        thread.quantum = thread_quantum * 2;
        self.make_ready(thread);
    }

    /// Terminate the running thread: mark it signaled (the thread's
    /// waiters observe the mark), remove it from its process's
    /// thread list, mark it Terminated, return the kernel-stack
    /// loan, and select the processor's next thread. Returns the
    /// selected thread — the caller's context switch enters it.
    pub fn terminate(&mut self) -> *mut Thread {
        debug_assert!(!self.current.is_null(), "terminate without a running thread");
        // SAFETY: the running thread is live and attached; its
        // process list and process are valid.
        let thread: &mut Thread = unsafe { &mut *self.current };
        thread.signaled = true;
        unsafe { unlink(addr_of_mut!(thread.process_links)) };
        thread.state = ThreadState::Terminated;
        unsafe { (*thread.process).stack_count -= 1 };
        self.select_next()
    }

    /// Set the process's base priority to `new_base`, adjusting every
    /// attached thread's base and current priority within its class:
    /// a variable process keeps its threads in 1..15, a realtime one
    /// in 16..31. Saturated threads move only when the change crosses
    /// the class boundary — then they pin to their new class's edges;
    /// within a class they are left entirely alone. Returns the
    /// process's previous base priority.
    pub fn set_process_priority(&mut self, process: &mut SchedProcess, new_base: i8) -> i8 {
        let old_base = process.base_priority;
        process.base_priority = new_base;
        let adjustment = new_base as i32 - old_base as i32;

        // Walk the thread list by hand: the loop must survive the
        // per-thread priority machinery touching the same objects.
        // SAFETY: the sentinel is alive; each entry is a thread's
        // process link (the only things ever linked here).
        let head = process.threads.sentinel();
        let mut entry = unsafe { (*head).next };
        while entry != head {
            // SAFETY: the entry is a live thread's process link; the
            // process pointer inside is valid by the attach
            // contract.
            let thread: &mut Thread = unsafe {
                &mut *((entry as usize - core::mem::offset_of!(Thread, process_links)) as *mut Thread)
            };
            entry = unsafe { (*entry).next };

            let mut new_priority = thread.base_priority as i32 + adjustment;
            if new_base >= REALTIME_BASE {
                if new_priority < REALTIME_BASE as i32 {
                    new_priority = REALTIME_BASE as i32;
                } else if new_priority > HIGHEST_PRIORITY as i32 {
                    new_priority = HIGHEST_PRIORITY as i32;
                }
                if thread.saturation == 0 || old_base < REALTIME_BASE {
                    if thread.saturation > 0 {
                        new_priority = HIGHEST_PRIORITY as i32;
                    } else if thread.saturation < 0 {
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
                if thread.saturation == 0 || old_base >= REALTIME_BASE {
                    if thread.saturation > 0 {
                        new_priority = REALTIME_BASE as i32 - 1;
                    } else if thread.saturation < 0 {
                        new_priority = 1;
                    }
                    self.apply_thread_adjustment(thread, new_priority);
                }
            }
        }
        old_base
    }

    /// Apply one thread's adjusted base priority: store the base,
    /// replenish the quantum, clear the decay, and run the state
    /// machine.
    fn apply_thread_adjustment(&mut self, thread: &mut Thread, new_priority: i32) {
        thread.base_priority = new_priority as i8;
        // SAFETY: the thread is attached; its process outlives it.
        thread.quantum = unsafe { (*thread.process).thread_quantum };
        thread.decrement_count = 0;
        thread.priority_decrement = 0;
        self.apply_priority(thread, new_priority as i8);
    }
}

/// Half the priority range: the saturation threshold and the value a
/// saturated base reports as its increment.
fn saturation_pin() -> i32 {
    (HIGHEST_PRIORITY as i32 + 1) / 2
}

/// The thread owning a ready-queue link.
// SAFETY-contract: `entry` is the ready link of a live thread.
fn entry_to_thread(entry: *mut Links) -> *mut Thread {
    (entry as usize - core::mem::offset_of!(Thread, ready_links)) as *mut Thread
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sched::process::SchedProcess;
    use crate::sched::thread::{Thread, ThreadState};

    // --- The rig ----------------------------------------------------------
    //
    // Threads and processes are kernel objects: they live at fixed
    // addresses for as long as they are linked, so the rig leaks
    // every object it creates (one-shot tests; the addresses never
    // die).

    fn dispatcher() -> &'static mut Dispatcher {
        let d = Box::leak(Box::new(Dispatcher::zeroed()));
        d.init();
        d
    }

    fn process(base: i8) -> *mut SchedProcess {
        let p = Box::leak(Box::new(SchedProcess::new(0x0090_0000, base)));
        p.init();
        p as *mut SchedProcess
    }

    fn thread(p: *mut SchedProcess) -> &'static mut Thread {
        let t = Box::leak(Box::new(Thread::empty()));
        // SAFETY: both objects are leaked at their final addresses.
        unsafe { t.attach_to(&mut *p) };
        t
    }

    /// Run `t` as the processor's current thread.
    fn run(d: &mut Dispatcher, t: *mut Thread) {
        d.current = t;
        // SAFETY: a live, attached thread.
        unsafe { (*t).state = ThreadState::Running };
    }

    /// Make `t` the processor's standby thread.
    fn standby(d: &mut Dispatcher, t: *mut Thread) {
        d.next = t;
        // SAFETY: as `run`.
        unsafe { (*t).state = ThreadState::Standby };
    }

    fn as_ptr(t: &Thread) -> *mut Thread {
        t as *const Thread as *mut Thread
    }

    // --- Group A: fresh state ------------------------------------------------

    /// A fresh dispatcher: 32 empty ready lists, no summary bits, an
    /// empty processor, the invariant holds.
    #[test]
    fn dispatcher_starts_empty() {
        let d = dispatcher();
        for queue in d.ready.iter() {
            assert!(queue.is_empty());
        }
        assert_eq!(d.ready_summary, 0);
        assert!(!d.processor_idle);
        assert!(d.current.is_null());
        assert!(d.next.is_null());
        assert!(d.idle_thread.is_null());
        assert_eq!(d.audit(), Ok(()));
    }

    // --- Group B: insertion and selection ------------------------------------

    /// Selection takes the highest non-empty queue; the taken
    /// thread's queue bit clears and lower bits survive.
    #[test]
    fn selection_picks_the_highest_queue() {
        let d = dispatcher();
        let p = process(8);
        let t8 = thread(p);
        t8.priority = 8;
        let t12 = thread(p);
        t12.priority = 12;

        d.make_ready(t8);
        d.make_ready(t12);
        assert_eq!(d.ready_summary, (1 << 8) | (1 << 12));

        let got = d.find_ready(0);
        assert_eq!(got, as_ptr(t12));
        assert_eq!(t12.state(), ThreadState::Ready);
        assert_eq!(d.ready_summary, 1 << 8, "bit 12 clears, bit 8 survives");
        assert_eq!(d.audit(), Ok(()));
    }

    /// The floor masks lower queues: a thread below it is invisible.
    #[test]
    fn selection_floor_masks_lower_queues() {
        let d = dispatcher();
        let p = process(8);
        let t8 = thread(p);
        t8.priority = 8;
        let t12 = thread(p);
        t12.priority = 12;
        d.make_ready(t8);
        d.make_ready(t12);

        assert_eq!(d.find_ready(9), as_ptr(t12));
        assert!(d.find_ready(13).is_null());
        // The floor scan took t12 (queued at or above the floor);
        // the failed scan took nothing.
        assert_eq!(d.ready_summary, 1 << 8);
    }

    /// An empty summary selects nothing.
    #[test]
    fn selection_from_empty_selects_nothing() {
        let d = dispatcher();
        assert!(d.find_ready(0).is_null());
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

        assert_eq!(d.find_ready(0), as_ptr(t1));
        assert_eq!(d.find_ready(0), as_ptr(t2));
        assert_eq!(d.find_ready(0), as_ptr(t3));
        assert!(d.find_ready(0).is_null());
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
        assert_eq!(d.find_ready(0), as_ptr(t1), "t1 queued first runs first");
        assert_eq!(d.ready_summary, 1 << 8);
    }

    /// A preempted thread requeues at the head, ahead of threads
    /// queued at the same priority before it.
    #[test]
    fn preempted_thread_requeues_at_the_head() {
        let d = dispatcher();
        let p = process(8);
        let witness = thread(p);
        witness.priority = 12;
        d.make_ready(witness);

        let t = thread(p);
        t.priority = 12;
        t.preempted = true;
        d.make_ready(t);

        assert_eq!(
            d.find_ready(12),
            as_ptr(t),
            "the preempted thread is ahead of the witness"
        );
        assert_eq!(d.find_ready(12), as_ptr(witness));
        assert!(!t.preempted, "the flag is consumed by the insertion");
        assert_eq!(d.ready_summary, 0);
    }

    /// Draining a queue clears its bit; higher bits survive.
    #[test]
    fn draining_a_queue_clears_its_bit() {
        let d = dispatcher();
        let p = process(8);
        let t8 = thread(p);
        t8.priority = 8;
        let t9 = thread(p);
        t9.priority = 9;
        d.make_ready(t8);
        d.make_ready(t9);

        assert_eq!(d.find_ready(0), as_ptr(t9));
        assert_eq!(d.ready_summary, 1 << 8);
        assert_eq!(d.find_ready(0), as_ptr(t8));
        assert_eq!(d.ready_summary, 0);
        assert_eq!(d.audit(), Ok(()));
    }

    /// The summary invariant is an auditable property, and a manual
    /// corruption is caught.
    #[test]
    fn the_summary_tracks_the_queues() {
        let d = dispatcher();
        let p = process(8);
        let a = thread(p);
        a.priority = 5;
        let b = thread(p);
        b.priority = 20;
        d.make_ready(a);
        d.make_ready(b);
        assert_eq!(d.audit(), Ok(()));

        d.ready_summary |= 1 << 7;
        assert!(d.audit().is_err());
    }

    // --- Group C: ready and terminate transitions ----------------------------

    /// A readied thread on an idle processor takes it immediately:
    /// standby, and the idle flag clears.
    #[test]
    fn a_readied_thread_takes_an_idle_processor() {
        let d = dispatcher();
        let p = process(8);
        let idle = thread(p);
        d.install_idle_thread(as_ptr(idle));
        assert!(d.processor_idle);

        let t = thread(p);
        t.priority = 8;
        d.make_ready(t);
        assert_eq!(t.state(), ThreadState::Standby);
        assert_eq!(d.next, as_ptr(t));
        assert!(!d.processor_idle);
        assert_eq!(d.ready_summary, 0, "never queued");
    }

    /// A higher-priority arrival displaces the standby thread: the
    /// arrival becomes standby, the displaced thread is marked
    /// preempted and requeues at the head.
    #[test]
    fn an_arrival_displaces_the_standby_thread() {
        let d = dispatcher();
        let p = process(8);
        let witness = thread(p);
        witness.priority = 12;
        d.make_ready(witness);

        let standby_t = thread(p);
        standby_t.priority = 12;
        standby(d, as_ptr(standby_t));

        let arrival = thread(p);
        arrival.priority = 14;
        d.make_ready(arrival);

        assert_eq!(arrival.state(), ThreadState::Standby);
        assert_eq!(d.next, as_ptr(arrival));
        assert_eq!(standby_t.state(), ThreadState::Ready);
        assert!(!standby_t.preempted, "consumed by the requeue");
        assert_eq!(
            d.find_ready(12),
            as_ptr(standby_t),
            "the displaced thread requeued at the head, ahead of the witness"
        );
        assert_eq!(d.find_ready(12), as_ptr(witness));
    }

    /// A higher-priority arrival preempts the running thread: the
    /// arrival becomes standby and the running thread is marked
    /// preempted (still Running until the context switch).
    #[test]
    fn an_arrival_preempts_the_running_thread() {
        let d = dispatcher();
        let p = process(8);
        let current = thread(p);
        current.priority = 12;
        run(d, as_ptr(current));

        let arrival = thread(p);
        arrival.priority = 14;
        d.make_ready(arrival);

        assert_eq!(arrival.state(), ThreadState::Standby);
        assert_eq!(d.next, as_ptr(arrival));
        assert!(current.preempted);
        assert_eq!(current.state(), ThreadState::Running);
        assert_eq!(d.ready_summary, 0);
    }

    /// An equal-priority arrival never preempts: it queues.
    #[test]
    fn an_equal_arrival_never_preempts() {
        let d = dispatcher();
        let p = process(8);
        let current = thread(p);
        current.priority = 12;
        run(d, as_ptr(current));

        let arrival = thread(p);
        arrival.priority = 12;
        d.make_ready(arrival);

        assert_eq!(arrival.state(), ThreadState::Ready);
        assert!(d.next.is_null());
        assert!(!current.preempted);
        assert_eq!(d.ready_summary, 1 << 12);
    }

    /// select_next consumes a pending standby thread first.
    #[test]
    fn select_next_consumes_the_standby_thread() {
        let d = dispatcher();
        let p = process(8);
        let t = thread(p);
        standby(d, as_ptr(t));

        assert_eq!(d.select_next(), as_ptr(t));
        assert!(d.next.is_null());
        assert_eq!(t.state(), ThreadState::Standby, "the switch flips the state");
    }

    /// With nothing pending, select_next scans the queues.
    #[test]
    fn select_next_scans_the_queues() {
        let d = dispatcher();
        let p = process(8);
        let t = thread(p);
        d.make_ready(t);
        assert_eq!(d.select_next(), as_ptr(t));
        assert_eq!(t.state(), ThreadState::Ready);
    }

    /// With nothing runnable at all, select_next falls back to the
    /// idle thread and marks the processor idle.
    #[test]
    fn select_next_falls_back_to_the_idle_thread() {
        let d = dispatcher();
        let p = process(8);
        let idle = thread(p);
        d.idle_thread = as_ptr(idle);

        assert_eq!(d.select_next(), as_ptr(idle));
        assert!(d.processor_idle);
    }

    /// Termination: the thread is signaled and Terminated, leaves its
    /// process's thread list, returns its kernel stack loan, and the
    /// processor's next thread is selected.
    #[test]
    fn terminate_signals_unlinks_and_selects() {
        let d = dispatcher();
        let p = process(8);
        let victim = thread(p);
        let survivor = thread(p);
        assert_eq!(unsafe { (*p).stack_count() }, 2);
        run(d, as_ptr(victim));
        d.make_ready(survivor);

        let selected = d.terminate();
        assert_eq!(selected, as_ptr(survivor));
        assert!(victim.signaled());
        assert_eq!(victim.state(), ThreadState::Terminated);
        assert_eq!(unsafe { (*p).stack_count() }, 1);
        // The survivor is still in the process's thread list.
        assert!(!unsafe { (*p).threads.is_empty() });
        // A second thread terminating empties it.
        standby(d, as_ptr(survivor));
        d.current = as_ptr(survivor);
        assert!(!d.terminate().is_null());
        assert_eq!(unsafe { (*p).stack_count() }, 0);
        assert!(unsafe { (*p).threads.is_empty() });
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
        assert_eq!(d.find_ready(0), as_ptr(t));
    }

    /// A Ready thread being lowered moves to the tail of the new
    /// queue; the old queue's bit clears.
    #[test]
    fn a_ready_thread_lowered_moves_queues() {
        let d = dispatcher();
        let p = process(8);
        let t = thread(p);
        t.priority = 12;
        d.make_ready(t);

        d.apply_priority(t, 8);
        assert_eq!(t.state(), ThreadState::Ready);
        assert_eq!(d.ready_summary, 1 << 8);
        assert_eq!(d.audit(), Ok(()));
        assert_eq!(d.find_ready(0), as_ptr(t));
    }

    /// A Ready thread being raised is re-readied: it re-enters the
    /// ready path (here, with nothing to preempt, at the tail of the
    /// new queue).
    #[test]
    fn a_ready_thread_raised_is_rereadied() {
        let d = dispatcher();
        let p = process(8);
        let t = thread(p);
        t.priority = 8;
        d.make_ready(t);

        d.apply_priority(t, 10);
        assert_eq!(t.state(), ThreadState::Ready);
        assert_eq!(d.ready_summary, 1 << 10);
        assert_eq!(d.find_ready(10), as_ptr(t));
    }

    /// A thread parked on its process (the swap machinery's parking
    /// spot, never true here) takes the field change alone.
    #[test]
    fn a_parked_thread_takes_the_field_only() {
        let d = dispatcher();
        let p = process(8);
        let t = thread(p);
        t.priority = 8;
        t.state = ThreadState::Ready;
        t.parked_on_process = true;

        d.apply_priority(t, 5);
        assert_eq!(t.priority(), 5);
        assert_eq!(d.ready_summary, 0);
        assert_eq!(d.audit(), Ok(()));
    }

    /// A Standby thread being lowered with a replacement available
    /// swaps: the replacement becomes standby, the thread re-readies.
    #[test]
    fn a_standby_thread_lowered_swaps_out() {
        let d = dispatcher();
        let p = process(8);
        let t = thread(p);
        t.priority = 12;
        standby(d, as_ptr(t));
        let replacement = thread(p);
        replacement.priority = 10;
        d.make_ready(replacement);

        d.apply_priority(t, 8);
        assert_eq!(replacement.state(), ThreadState::Standby);
        assert_eq!(d.next, as_ptr(replacement));
        assert_eq!(t.state(), ThreadState::Ready);
        assert_eq!(d.ready_summary, 1 << 8);
        assert_eq!(d.find_ready(8), as_ptr(t));
    }

    /// A Standby thread being lowered with no replacement stays
    /// standby — a standby thread is on no ready list.
    #[test]
    fn a_standby_thread_lowered_without_replacement_stays() {
        let d = dispatcher();
        let p = process(8);
        let t = thread(p);
        t.priority = 12;
        standby(d, as_ptr(t));

        d.apply_priority(t, 8);
        assert_eq!(t.priority(), 8);
        assert_eq!(t.state(), ThreadState::Standby);
        assert_eq!(d.next, as_ptr(t));
        assert_eq!(d.ready_summary, 0);
    }

    /// A Running thread being lowered with a candidate installs the
    /// candidate as standby; the running thread keeps Running.
    #[test]
    fn a_running_thread_lowered_installs_a_candidate() {
        let d = dispatcher();
        let p = process(8);
        let t = thread(p);
        t.priority = 12;
        run(d, as_ptr(t));
        let candidate = thread(p);
        candidate.priority = 10;
        d.make_ready(candidate);

        d.apply_priority(t, 8);
        assert_eq!(candidate.state(), ThreadState::Standby);
        assert_eq!(d.next, as_ptr(candidate));
        assert_eq!(t.state(), ThreadState::Running);
        assert_eq!(t.priority(), 8);
    }

    /// A Running thread being lowered while a standby is pending
    /// takes the field change alone — the pending thread owns the
    /// slot.
    #[test]
    fn a_running_thread_lowered_with_standby_pending_is_untouched() {
        let d = dispatcher();
        let p = process(8);
        let t = thread(p);
        t.priority = 12;
        run(d, as_ptr(t));
        let pending = thread(p);
        pending.priority = 14;
        standby(d, as_ptr(pending));
        let queued = thread(p);
        queued.priority = 10;
        d.make_ready(queued);

        d.apply_priority(t, 8);
        assert_eq!(d.next, as_ptr(pending));
        assert_eq!(queued.state(), ThreadState::Ready);
        assert_eq!(d.ready_summary, 1 << 10);
    }

    /// A Running thread being raised (or held) takes no dispatch
    /// action.
    #[test]
    fn a_running_thread_raised_takes_no_action() {
        let d = dispatcher();
        let p = process(8);
        let t = thread(p);
        t.priority = 8;
        run(d, as_ptr(t));

        d.apply_priority(t, 12);
        assert_eq!(t.priority(), 12);
        assert!(d.next.is_null());
        assert_eq!(d.ready_summary, 0);
    }

    /// Initialized, Terminated, Waiting and Transition take the field
    /// change alone.
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
            let t = thread(p);
            t.state = state;
            d.apply_priority(t, 10);
            assert_eq!(t.priority(), 10, "{:?}: field only", state);
            assert_eq!(t.state(), state, "{:?}: state untouched", state);
        }
        assert_eq!(d.ready_summary, 0);
        assert_eq!(d.audit(), Ok(()));
    }

    /// The full set-priority form: replenish the quantum, clear the
    /// decay fields, then run the machine; the old priority returns.
    #[test]
    fn set_priority_replenishes_before_the_machine() {
        let d = dispatcher();
        let p = process(8);
        let t = thread(p);
        t.priority = 8;
        t.quantum = 0;
        t.decrement_count = 3;
        t.priority_decrement = 2;

        assert_eq!(d.set_priority(t, 10), 8);
        assert_eq!(t.priority(), 10);
        assert_eq!(t.quantum(), 6);
        assert_eq!(t.decrement_count(), 0);
        assert_eq!(t.priority_decrement(), 0);
    }

    /// Base-priority saturation: an increment at or beyond half the
    /// range pins the thread; the query reports the pin.
    #[test]
    fn base_priority_saturation_pins_and_reports() {
        let d = dispatcher();
        let p = process(8);

        let high = thread(p);
        high.base_priority = 8;
        high.priority = 8;
        assert_eq!(d.set_base_priority(high, 17), 0);
        assert_eq!(high.saturation(), 1);
        assert_eq!(d.base_increment(high), 16);

        let low = thread(p);
        low.base_priority = 8;
        low.priority = 8;
        assert_eq!(d.set_base_priority(low, -16), 0);
        assert_eq!(low.saturation(), -1);
        assert_eq!(d.base_increment(low), -16);

        let free = thread(p);
        free.base_priority = 8;
        free.priority = 8;
        assert_eq!(d.set_base_priority(free, 5), 0);
        assert_eq!(free.saturation(), 0);
        assert_eq!(d.base_increment(free), 5);
    }

    /// Base-priority change in a variable process: the base clamps
    /// below the realtime band and the priority follows with the
    /// decay debt subtracted.
    #[test]
    fn base_priority_variable_class_clamps() {
        let d = dispatcher();
        let p = process(8);
        let t = thread(p);
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

    /// Base-priority change in a realtime process: the base pins to
    /// the band and the priority equals the base.
    #[test]
    fn base_priority_realtime_class_pins() {
        let d = dispatcher();
        let p = process(24);
        let t = thread(p);
        t.base_priority = 24;
        t.priority = 26;

        d.set_base_priority(t, -30);
        assert_eq!(t.base_priority(), 16, "24 - 30 clamped up to the band");
        assert_eq!(t.priority(), 16, "realtime priority follows the base");

        d.set_base_priority(t, 30);
        assert_eq!(t.base_priority(), 31, "24 + 30 clamped down to the top");
        assert_eq!(t.priority(), 31);
    }

    /// The decay fields clear even when the computed priority does
    /// not change (and then the quantum is not replenished).
    #[test]
    fn base_priority_clears_decay_even_without_a_change() {
        let d = dispatcher();
        let p = process(8);
        let t = thread(p);
        t.base_priority = 8;
        t.priority = 8;
        t.quantum = 1;
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

    /// A boost applies base plus increment when that exceeds the
    /// current priority, and replenishes the quantum.
    #[test]
    fn a_boost_raises_and_replenishes() {
        let d = dispatcher();
        let p = process(8);
        let t = thread(p);
        t.base_priority = 8;
        t.priority = 8;
        t.quantum = 1;

        d.boost(t, 2);
        assert_eq!(t.priority(), 10);
        assert_eq!(t.quantum(), 6);
    }

    /// A boost is capped below the realtime band; the cap value is
    /// exact and the quantum resets even though the priority does
    /// not change.
    #[test]
    fn a_boost_caps_below_realtime() {
        let d = dispatcher();
        let p = process(8);
        let t = thread(p);
        t.base_priority = 15;
        t.priority = 15;
        t.quantum = 1;

        d.boost(t, 10);
        assert_eq!(t.priority(), 15, "25 capped at 15");
        assert_eq!(t.quantum(), 6, "the reset precedes the set");
    }

    /// A boost that does not exceed the current priority does not
    /// apply: idempotent while a boost is already in effect.
    #[test]
    fn a_boost_below_the_current_priority_does_not_apply() {
        let d = dispatcher();
        let p = process(8);
        let t = thread(p);
        t.base_priority = 8;
        t.priority = 10;
        t.quantum = 1;

        d.boost(t, 2);
        assert_eq!(t.priority(), 10);
        assert_eq!(t.quantum(), 1);
    }

    /// No boost while a decay debt is outstanding.
    #[test]
    fn a_boost_refuses_on_outstanding_decay() {
        let d = dispatcher();
        let p = process(8);
        let t = thread(p);
        t.base_priority = 8;
        t.priority = 12;
        t.priority_decrement = 4;
        t.quantum = 2;

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
        let t = thread(p);
        t.base_priority = 24;
        t.priority = 24;
        t.quantum = 2;

        d.boost(t, 10);
        assert_eq!(t.priority(), 24);
        assert_eq!(t.quantum(), 2);
    }

    /// A boost that raises the priority drives the full state
    /// machine: it preempts a lower running thread, or queues when
    /// it cannot.
    #[test]
    fn a_boost_drives_the_state_machine() {
        // Raised above the running thread: standby, the running
        // thread marked preempted.
        let d = dispatcher();
        let p = process(8);
        let current = thread(p);
        current.priority = 12;
        run(d, as_ptr(current));
        let t = thread(p);
        t.base_priority = 8;
        t.priority = 8;
        d.make_ready(t);

        d.boost(t, 6);
        assert_eq!(t.priority(), 14);
        assert_eq!(t.state(), ThreadState::Standby);
        assert_eq!(d.next, as_ptr(t));
        assert!(current.preempted);

        // Raised below the running thread: queued at the tail of the
        // new priority.
        let d = dispatcher();
        let p = process(8);
        let current = thread(p);
        current.priority = 15;
        run(d, as_ptr(current));
        let t = thread(p);
        t.base_priority = 8;
        t.priority = 8;
        d.make_ready(t);

        d.boost(t, 6);
        assert_eq!(t.state(), ThreadState::Ready);
        assert_eq!(d.ready_summary, 1 << 14);
        assert_eq!(d.find_ready(14), as_ptr(t));
    }

    /// The boost itself does not consult the thread's boost policy;
    /// that gate belongs to the wait-exit path.
    #[test]
    fn a_boost_ignores_the_boost_policy() {
        let d = dispatcher();
        let p = process(8);
        let t = thread(p);
        t.base_priority = 8;
        t.priority = 8;
        t.quantum = 1;
        t.disable_boost = true;

        d.boost(t, 2);
        assert_eq!(t.priority(), 10);
    }

    // --- Group F: quantum reset and end decay --------------------------------

    /// The tick cadence: 3 charged per tick, one quantum spans two
    /// ticks, and the end is flagged at zero — except for the idle
    /// thread.
    #[test]
    fn the_tick_charges_three_and_flags_at_zero() {
        let d = dispatcher();
        let p = process(8);
        let t = thread(p);
        t.quantum = 6;

        assert!(!d.tick_quantum(t));
        assert_eq!(t.quantum(), 3);
        assert!(d.tick_quantum(t));
        assert_eq!(t.quantum(), 0);

        // The idle thread is never flagged.
        d.install_idle_thread(as_ptr(t));
        assert!(!d.tick_quantum(t));
        assert_eq!(t.quantum(), -3);
    }

    /// Quantum end resets the quantum to the process value first.
    #[test]
    fn quantum_end_resets_the_quantum() {
        let d = dispatcher();
        let p = process(8);
        let t = thread(p);
        run(d, as_ptr(t));
        t.quantum = 0;

        assert!(d.quantum_end().is_null());
        assert_eq!(t.quantum(), 6);
    }

    /// Variable-class decay: one priority step per quantum.
    #[test]
    fn quantum_end_decays_one_step() {
        let d = dispatcher();
        let p = process(8);
        let t = thread(p);
        t.priority = 10;
        run(d, as_ptr(t));
        t.quantum = 0;

        d.quantum_end();
        assert_eq!(t.priority(), 9);
        assert_eq!(t.quantum(), 6);
        assert_eq!(t.priority_decrement(), 0);
    }

    /// The decay floors at the base priority, and at the floor the
    /// equal-priority round-robin takes over.
    #[test]
    fn quantum_end_decays_to_the_floor() {
        let d = dispatcher();
        let p = process(8);
        let t = thread(p);
        t.priority = 8;
        run(d, as_ptr(t));
        t.quantum = 0;

        assert!(d.quantum_end().is_null());
        assert_eq!(t.priority(), 8);
        assert_eq!(t.quantum(), 6);
    }

    /// The decay consumes the outstanding debt, then clears it.
    #[test]
    fn quantum_end_consumes_the_decay_debt() {
        let d = dispatcher();
        let p = process(8);
        let t = thread(p);
        t.priority = 10;
        t.priority_decrement = 3;
        run(d, as_ptr(t));
        t.quantum = 0;

        d.quantum_end();
        assert_eq!(t.priority(), 8, "10 - 3 - 1 = 6, floored at the base");
        assert_eq!(t.priority_decrement(), 0);
    }

    /// Realtime threads do not decay: at quantum end an equal
    /// ready thread takes the standby slot — round-robin among
    /// equals.
    #[test]
    fn quantum_end_round_robins_realtime_equals() {
        let d = dispatcher();
        let p = process(24);
        let t = thread(p);
        t.priority = 24;
        run(d, as_ptr(t));
        t.quantum = 0;
        let equal = thread(p);
        equal.priority = 24;
        d.make_ready(equal);

        let selected = d.quantum_end();
        assert_eq!(selected, as_ptr(equal));
        assert_eq!(equal.state(), ThreadState::Standby);
        assert_eq!(d.next, as_ptr(equal));
        assert_eq!(t.priority(), 24, "no decay in the realtime band");
        assert_eq!(t.quantum(), 6);
    }

    /// A realtime thread whose process exempts it never ends its
    /// quantum: the quantum refills to the maximum instead.
    #[test]
    fn quantum_end_exempt_realtime_never_ends() {
        let d = dispatcher();
        let p = process(24);
        unsafe { (*p).set_disable_quantum(true) };
        let t = thread(p);
        t.priority = 24;
        run(d, as_ptr(t));
        t.quantum = 0;

        assert!(d.quantum_end().is_null());
        assert_eq!(t.quantum(), i8::MAX);
        assert_eq!(t.priority(), 24);
        assert!(d.next.is_null());
    }

    /// The balance-set boost: raised to the top of the variable band
    /// with a doubled quantum — the one place the quantum doubles —
    /// and re-readied.
    #[test]
    fn the_balance_boost_doubles_the_quantum() {
        let d = dispatcher();
        let p = process(8);
        let t = thread(p);
        t.priority = 8;
        t.quantum = 1;

        d.balance_boost(t);
        assert_eq!(t.priority_decrement(), 7, "the debt is the boost distance");
        assert_eq!(t.decrement_count(), 16);
        assert_eq!(t.priority(), 15);
        assert_eq!(t.quantum(), 12, "6 * 2: the doubled quantum");
        assert_eq!(t.state(), ThreadState::Ready);
        assert_eq!(d.find_ready(0), as_ptr(t));
    }

    /// The round-trip boost: to the ceiling with a doubled quantum,
    /// renewed per round trip, and dropped to base (through the full
    /// form) when the count runs out — then immediately retried.
    #[test]
    fn the_round_trip_boost_renews_then_drops() {
        let d = dispatcher();
        let p = process(8);
        let t = thread(p);
        t.priority = 8;
        run(d, as_ptr(t));
        t.quantum = 1;

        d.boost_current_round_trip();
        assert_eq!(t.priority(), 14);
        assert_eq!(t.priority_decrement(), 6);
        assert_eq!(t.decrement_count(), 16);
        assert_eq!(t.quantum(), 12);

        d.boost_current_round_trip();
        assert_eq!(t.decrement_count(), 15);
        assert_eq!(t.quantum(), 12);

        // Run the count down to exhaustion: the drop replenishes and
        // clears, then the boost is retried.
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
        let t = thread(p);
        t.priority = 15;
        run(d, as_ptr(t));
        t.quantum = 3;

        d.boost_current_round_trip();
        assert_eq!(t.priority(), 15);
        assert_eq!(t.quantum(), 3);
        assert_eq!(t.priority_decrement(), 0);
    }

    /// The wait charge: one unit per completed wait, with the
    /// quantum-end decay at exhaustion; realtime threads and
    /// time-critical bases replenish outright.
    #[test]
    fn the_wait_charge_decays_at_exhaustion() {
        let d = dispatcher();
        let p = process(8);

        let t = thread(p);
        t.priority = 10;
        t.quantum = 4;
        d.charge_wait(t);
        assert_eq!(t.quantum(), 3);

        // Exhaustion: reset and decay, floored at the base.
        let t = thread(p);
        t.priority = 10;
        t.priority_decrement = 2;
        t.quantum = 1;
        d.charge_wait(t);
        assert_eq!(t.quantum(), 6);
        assert_eq!(t.priority(), 8, "10 - 2 - 1 = 7, floored at the base");
        assert_eq!(t.priority_decrement(), 0);

        // Realtime replenishes outright.
        let t = thread(p);
        t.priority = 24;
        t.quantum = 5;
        d.charge_wait(t);
        assert_eq!(t.quantum(), 6);
        assert_eq!(t.priority(), 24);

        // A time-critical base replenishes outright.
        let t = thread(p);
        t.priority = 10;
        t.base_priority = 14;
        t.quantum = 2;
        d.charge_wait(t);
        assert_eq!(t.quantum(), 6);
    }

    // --- Group G: the process side -------------------------------------------

    /// Process base-priority change within the variable class: every
    /// thread's base and priority move by the adjustment, clamped in
    /// the band; the quantum source stays the process's fixed value.
    #[test]
    fn process_priority_moves_variable_threads() {
        let d = dispatcher();
        let p = process(8);
        let a = thread(p);
        a.priority = 8;
        let b = thread(p);
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

    /// A process base-priority change into the realtime class clamps
    /// its threads into the realtime band.
    #[test]
    fn process_priority_into_realtime_clamps_threads() {
        let d = dispatcher();
        let p = process(8);
        let a = thread(p);
        a.priority = 8;

        d.set_process_priority(unsafe { &mut *p }, 16);
        assert_eq!(a.base_priority(), 16);
        assert_eq!(a.priority(), 16);
    }

    /// Crossing into the realtime class moves saturated threads to
    /// the realtime pins: high saturation to the top, low saturation
    /// to the band floor.
    #[test]
    fn process_priority_crossing_pins_saturated_threads() {
        let d = dispatcher();
        let p = process(8);
        let high = thread(p);
        high.saturation = 1;
        let low = thread(p);
        low.saturation = -1;

        d.set_process_priority(unsafe { &mut *p }, 16);
        assert_eq!(high.base_priority(), 31);
        assert_eq!(high.priority(), 31);
        assert_eq!(low.base_priority(), 16);
        assert_eq!(low.priority(), 16);
    }

    /// Saturated threads are untouched when the class does not
    /// cross — in either direction.
    #[test]
    fn process_priority_leaves_saturated_threads_within_a_class() {
        let d = dispatcher();

        // Realtime staying realtime: a saturated thread keeps its
        // pinned base, priority and quantum.
        let p = process(20);
        let t = thread(p);
        t.base_priority = 31;
        t.priority = 31;
        t.saturation = 1;
        t.quantum = 2;
        d.set_process_priority(unsafe { &mut *p }, 24);
        assert_eq!(t.base_priority(), 31, "untouched by the walk");
        assert_eq!(t.priority(), 31);
        assert_eq!(t.quantum(), 2);

        // Variable staying variable.
        let p = process(8);
        let t = thread(p);
        t.base_priority = 15;
        t.priority = 15;
        t.saturation = 1;
        t.quantum = 2;
        d.set_process_priority(unsafe { &mut *p }, 10);
        assert_eq!(t.base_priority(), 15);
        assert_eq!(t.priority(), 15);
        assert_eq!(t.quantum(), 2);
    }

    /// Crossing from realtime down to variable pins saturated threads
    /// to the variable edges.
    #[test]
    fn process_priority_crossing_down_pins_saturated_threads() {
        let d = dispatcher();
        let p = process(20);
        let high = thread(p);
        high.saturation = 1;
        let low = thread(p);
        low.saturation = -1;

        d.set_process_priority(unsafe { &mut *p }, 10);
        assert_eq!(high.base_priority(), 15, "the variable ceiling");
        assert_eq!(high.priority(), 15);
        assert_eq!(low.base_priority(), 1, "the variable floor");
        assert_eq!(low.priority(), 1);
    }
}
