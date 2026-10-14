//! The thread object: the scheduling state every thread carries.

use super::process::SchedProcess;
use super::Links;
use core::ptr::addr_of_mut;

/// A thread's scheduling state, as the dispatcher moves it around:
/// created, queued, on the processor, selected as the processor's
/// next thread, exited, blocked.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum ThreadState {
    /// Created, never yet readied.
    Initialized = 0,
    /// On a ready list, waiting for the processor.
    Ready = 1,
    /// On the processor.
    Running = 2,
    /// Selected as the processor's next thread.
    Standby = 3,
    /// Exited; no longer scheduled.
    Terminated = 4,
    /// Blocked on a dispatcher object (the wait machinery's state).
    Waiting = 5,
    /// Between wake and ready, waiting for its kernel stack to be
    /// swapped in. Never entered: F2K never swaps kernel stacks out,
    /// so a woken thread goes straight to ready.
    Transition = 6,
}

/// A thread: one schedulable unit of execution.
///
/// A thread is an intrusive kernel object: it carries the links for
/// the ready queue and for its process's thread list, so the
/// dispatcher queues it in place and allocation never happens on the
/// scheduling path. A thread must be attached to exactly one process
/// for as long as it exists, and must be unlinked from both lists
/// (terminate does this) before it is dropped.
pub struct Thread {
    /// The owning process; the source of the quantum and of the
    /// priority class rules. Valid for the thread's lifetime.
    pub(super) process: *mut SchedProcess,

    /// The priority the scheduler queues and preempts by.
    pub(super) priority: i8,
    /// The priority the thread decays toward and is floored by.
    pub(super) base_priority: i8,
    /// Outstanding decay debt: subtracted once at the next decay,
    /// then cleared.
    pub(super) priority_decrement: i8,
    /// Round trips left on a sticky boost before the thread drops
    /// back to its base priority.
    pub(super) decrement_count: u8,
    /// Run time left before the scheduler reconsiders the processor.
    pub(super) quantum: i8,
    /// Whether a base-priority change pinned this thread to a class
    /// edge: -1 pinned low, +1 pinned high, 0 free.
    pub(super) saturation: i8,
    /// Whether wait-exit boosts are refused for this thread (the
    /// wait-exit gate; the wake boost itself does not consult it).
    pub(super) disable_boost: bool,

    /// The scheduling state.
    pub(super) state: ThreadState,
    /// Set when the thread is pushed off the processor (or the
    /// standby slot) by a higher-priority arrival: it then requeues
    /// at the head of its ready list rather than the tail.
    pub(super) preempted: bool,
    /// Always false in F2K: the reference parks not-yet-runnable
    /// threads on their process when the process is being swapped in,
    /// and F2K has no process swapping. The flag survives as the
    /// priority-change guard for the parked shape.
    pub(super) parked_on_process: bool,
    /// Set when the thread exits: the thread-object waits observe it.
    pub(super) signaled: bool,

    /// The ready-queue membership link.
    pub(super) ready_links: Links,
    /// The owning process's thread-list membership link.
    pub(super) process_links: Links,
}

impl Thread {
    /// A fresh, detached thread. Call [`Thread::attach_to`] before
    /// any scheduler operation.
    pub const fn empty() -> Self {
        Thread {
            process: core::ptr::null_mut(),
            priority: 0,
            base_priority: 0,
            priority_decrement: 0,
            decrement_count: 0,
            quantum: 0,
            saturation: 0,
            disable_boost: false,
            state: ThreadState::Initialized,
            preempted: false,
            parked_on_process: false,
            signaled: false,
            ready_links: Links::detached(),
            process_links: Links::detached(),
        }
    }

    /// Attach to `process`: take the process's base priority, quantum
    /// and boost policy, join its thread list, and account the kernel
    /// stack. After this the thread is Initialized and schedulable.
    ///
    /// # Safety
    ///
    /// The process must outlive the thread's membership in its list
    /// (the first link is written here), and both objects must be at
    /// their final addresses.
    pub unsafe fn attach_to(&mut self, process: &mut SchedProcess) {
        self.process = process as *mut SchedProcess;
        self.base_priority = process.base_priority;
        self.priority = self.base_priority;
        self.quantum = process.thread_quantum;
        self.disable_boost = process.disable_boost;
        self.state = ThreadState::Initialized;

        // SAFETY: the thread's process link is detached and the
        // process's thread list is initialized (caller contract).
        unsafe { process.threads.push_back(addr_of_mut!(self.process_links)) };
        if process.stack_count == super::process::NO_THREADS {
            process.stack_count = 1;
        } else {
            process.stack_count += 1;
        }
        process.thread_seed = process.thread_seed.wrapping_add(1);
    }

    /// The scheduling state.
    pub fn state(&self) -> ThreadState {
        self.state
    }

    /// The current priority.
    pub fn priority(&self) -> i8 {
        self.priority
    }

    /// The base priority.
    pub fn base_priority(&self) -> i8 {
        self.base_priority
    }

    /// The remaining quantum.
    pub fn quantum(&self) -> i8 {
        self.quantum
    }

    /// The outstanding decay debt.
    pub fn priority_decrement(&self) -> i8 {
        self.priority_decrement
    }

    /// The round trips left on a sticky boost.
    pub fn decrement_count(&self) -> u8 {
        self.decrement_count
    }

    /// The class-edge pin state (-1, 0, +1).
    pub fn saturation(&self) -> i8 {
        self.saturation
    }

    /// Whether the thread has exited.
    pub fn signaled(&self) -> bool {
        self.signaled
    }

    /// The owning process.
    ///
    /// # Safety
    ///
    /// The thread is attached (its lifetime pins the process).
    pub unsafe fn process(&self) -> &SchedProcess {
        unsafe { &*self.process }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The state ordinals: stable, distinct, with the lifecycle order
    /// the dump paths and any raw state byte depend on.
    #[test]
    fn state_ordinals() {
        assert_eq!(ThreadState::Initialized as u8, 0);
        assert_eq!(ThreadState::Ready as u8, 1);
        assert_eq!(ThreadState::Running as u8, 2);
        assert_eq!(ThreadState::Standby as u8, 3);
        assert_eq!(ThreadState::Terminated as u8, 4);
        assert_eq!(ThreadState::Waiting as u8, 5);
        assert_eq!(ThreadState::Transition as u8, 6);
    }

    /// Attaching takes the scheduling data from the process: base and
    /// current priority, quantum, boost policy; the state is
    /// Initialized; the stack count moves off its sentinel and the
    /// seed advances per thread.
    #[test]
    fn attach_takes_process_data() {
        let process = Box::leak(Box::new(SchedProcess::new(8)));
        process.init();

        let t1 = Box::leak(Box::new(Thread::empty()));
        // SAFETY: both objects are boxed at their final addresses.
        unsafe { t1.attach_to(process) };
        assert_eq!(t1.base_priority(), 8);
        assert_eq!(t1.priority(), 8);
        assert_eq!(t1.quantum(), 6);
        assert_eq!(t1.state(), ThreadState::Initialized);
        assert!(!t1.signaled());
        assert_eq!(process.stack_count(), 1);
        let seed_after_first = process.thread_seed();

        let t2 = Box::leak(Box::new(Thread::empty()));
        // SAFETY: as above.
        unsafe { t2.attach_to(process) };
        assert_eq!(process.stack_count(), 2);
        assert_eq!(process.thread_seed(), seed_after_first.wrapping_add(1));

        // The process list holds both, in creation order.
        // SAFETY: initialized list; entries stay linked.
        let first = unsafe { process.threads.first() };
        assert_eq!(first, core::ptr::addr_of_mut!(t1.process_links));
        assert!(!process.threads.is_empty());
    }
}
