//! The scheduler: thread objects and the dispatcher's ready queues.
//!
//! Threads are the kernel's unit of execution. Each carries a priority (0-31: 0-15 variable, 16-31
//! realtime), a base priority it decays toward, and a quantum — the run time granted before the
//! scheduler reconsiders the processor. The quantum is charged three units per clock tick and reset
//! to six, so one quantum spans two ticks; it is the same fixed value for every process, set once
//! at creation.
//!
//! The dispatcher keeps one ready list per priority plus a 32-bit summary whose bit P is set while
//! ready list P is non-empty, so selection scans bits instead of lists: the highest-priority
//! non-empty queue wins, first-in-first-out within a queue. A readied thread first tries to take
//! the processor outright — the idle flag, then the standby slot, then the running thread, with
//! strictly higher priority winning and equals never preempting — and only otherwise queues: at the
//! head if it was preempted mid-quantum, at the tail if it merely became runnable.
//!
//! The wiring sits on top: the idle thread (armed at boot, the processor's resting state), the
//! context switch that turns Standby into Running, the wait discipline (block, wake, timeout), the
//! timer table, the preemption delivery, and the thread-creation surface.
//!
//! One processor, no locking: every method runs serialized at the dispatch level, which the
//! interrupt core already raises around the dispatcher entries.

// Parts of the state machines stay unwired until their consumers land (the forced-resume route's
// caller is the future teardown conversion); the queues, the delivery, the suspend consumer, and
// the re-wait are live.
#![allow(dead_code)]

use core::ptr::{addr_of, addr_of_mut, null_mut};

/// The thread object: scheduling state, priorities, quantum.
pub mod thread;

/// The dispatcher: ready queues, selection, the state machines.
pub mod dispatcher;

/// The process record's scheduling side: base priority, quantum.
pub mod process;

/// The context switch: the swap assembly, the startup stub, and the machine-state offsets they
/// address threads through.
pub mod switch;

/// The startup frame builder: a fresh thread's first kernel stack contents, as pure layout.
pub mod startup;

/// The idle thread: the processor's resting thread and its loop.
pub mod idle;

/// The wait discipline: waitable objects, wait blocks, the block and wake paths, the timeout
/// machinery.
pub mod wait;

/// The timer table: the due-time-ordered buckets that hold wait timeouts, and the clock-driven
/// expiry walk.
pub mod timer;

/// The event object: the smallest waitable object, both flavors.
pub mod event;

/// The handle table: the per-process handle-to-object indirection.
pub mod object;

/// The APC machinery: the APC object, the queues, delivery, and the suspend consumer.
pub mod apc;

/// The semaphore object: a waitable whose signal state is a count.
pub mod semaphore;

// --- Constants -----------------------------------------------------------

/// The number of priority levels: one ready list and one summary bit each.
pub const PRIORITY_LEVELS: usize = 32;

/// The lowest thread priority. Only the idle thread runs here; a variable-class base is never
/// pinned below 1.
pub const LOWEST_PRIORITY: i8 = 0;

/// The lowest realtime priority: at or above it a thread never decays.
pub const REALTIME_BASE: i8 = 16;

/// The highest thread priority.
pub const HIGHEST_PRIORITY: i8 = 31;

/// The default base priority of a normal process.
pub const NORMAL_BASE: i8 = 8;

/// The amount charged against the running thread's quantum per clock tick.
pub const QUANTUM_TICK: i8 = 3;

/// The full quantum a thread starts each scheduling cycle with: two ticks' worth.
pub const QUANTUM_RESET: i8 = QUANTUM_TICK * 2;

/// The amount a completed wait charges against the quantum.
pub const QUANTUM_WAIT_CHARGE: i8 = 1;

/// How many round trips a sticky boost survives before the thread is dropped back to its base
/// priority.
pub const ROUND_TRIP_LIMIT: u8 = 16;

/// The ceiling of the executive's current-thread boost: a thread already at or above it is never
/// boosted further.
pub const TIME_CRITICAL_CEILING: i8 = 14;

// --- The intrusive list ---------------------------------------------------
//
// The scheduler links through its objects, never around them: a thread sits on a ready list and its
// process's thread list by carrying the link fields itself, so queueing allocates nothing and an
// unlinked object is free. The shape is a circular doubly-linked list around a sentinel whose head
// links to itself when empty.

/// A pair of link fields an object embeds once per list it can join.
#[derive(Clone, Copy)]
pub(crate) struct Links {
    next: *mut Links,
    prev: *mut Links,
}

impl Links {
    /// Detached links: not on any list.
    pub const fn detached() -> Self {
        Links {
            next: null_mut(),
            prev: null_mut(),
        }
    }
}

/// A list head: a sentinel plus the objects linked around it.
#[derive(Clone, Copy)]
pub(crate) struct List {
    head: Links,
}

impl List {
    /// A list whose sentinel is not yet linked; call [`List::init`] once the owning object has
    /// reached its final address.
    pub const fn empty() -> Self {
        List {
            head: Links::detached(),
        }
    }

    /// Close the sentinel: an empty list's head links to itself. Must run after the owning object
    /// is placed (the sentinel's links point into the object).
    pub fn init(&mut self) {
        self.head.next = addr_of_mut!(self.head);
        self.head.prev = addr_of_mut!(self.head);
    }

    /// Whether no object is linked. An uninitialized list (before [`List::init`]) counts as empty.
    pub fn is_empty(&self) -> bool {
        let head = addr_of!(self.head) as *mut Links;
        self.head.next == head || self.head.next.is_null()
    }

    /// Link `entry` at the front.
    ///
    /// # Safety
    ///
    /// The list is initialized and `entry` is on no list; `entry` stays valid while linked.
    pub unsafe fn push_front(&mut self, entry: *mut Links) {
        unsafe { link_after(addr_of_mut!(self.head), entry) };
    }

    /// Link `entry` at the back.
    ///
    /// # Safety
    ///
    /// Same contract as [`List::push_front`].
    pub unsafe fn push_back(&mut self, entry: *mut Links) {
        unsafe { link_before(addr_of_mut!(self.head), entry) };
    }

    /// Unlink and return the first entry, or null if the list is empty.
    ///
    /// # Safety
    ///
    /// The list is initialized; the returned entry is on no list once returned.
    pub unsafe fn pop_front(&mut self) -> *mut Links {
        if self.is_empty() {
            return null_mut();
        }
        let entry = self.head.next;
        unsafe { unlink(entry) };
        entry
    }

    /// The first entry without unlinking it, or null if empty.
    ///
    /// # Safety
    ///
    /// The list is initialized; the entry stays linked.
    pub unsafe fn first(&self) -> *mut Links {
        if self.is_empty() {
            return null_mut();
        }
        self.head.next
    }

    /// The sentinel link: the list's own head. A hand-rolled walk starts at the first entry and
    /// ends when it reaches this.
    pub fn sentinel(&mut self) -> *mut Links {
        addr_of_mut!(self.head)
    }
}

/// Link `entry` after `anchor`.
///
/// # Safety
///
/// `anchor` is a linked sentinel or a linked entry; `entry` is on no list.
pub(crate) unsafe fn link_after(anchor: *mut Links, entry: *mut Links) {
    unsafe {
        let next = (*anchor).next;
        (*entry).next = next;
        (*entry).prev = anchor;
        (*next).prev = entry;
        (*anchor).next = entry;
    }
}

/// Link `entry` before `anchor`.
///
/// # Safety
///
/// Same contract as [`link_after`].
pub(crate) unsafe fn link_before(anchor: *mut Links, entry: *mut Links) {
    unsafe {
        let prev = (*anchor).prev;
        (*entry).prev = prev;
        (*entry).next = anchor;
        (*prev).next = entry;
        (*anchor).prev = entry;
    }
}

/// Unlink `entry` from the list it is on.
///
/// # Safety
///
/// `entry` is linked on a list whose sentinel is alive.
pub(crate) unsafe fn unlink(entry: *mut Links) {
    unsafe {
        let prev = (*entry).prev;
        let next = (*entry).next;
        (*prev).next = next;
        (*next).prev = prev;
    }
}

/// Visit every attached thread's recorded gate-stack frames, in creation order (the teardown walk's
/// collection: each live thread's slot frames exactly once).
pub fn visit_gate_frames(process: &mut process::SchedProcess, visit: &mut dyn FnMut(u32)) {
    let sentinel = process.threads.sentinel();
    // SAFETY: the list is initialized and the entries stay linked for the walk.
    let mut entry = unsafe { process.threads.first() };
    while !entry.is_null() && !core::ptr::eq(entry, sentinel) {
        // SAFETY: the entry is a live thread's process link on this list; the list holds only
        // attached, live threads.
        let thread = unsafe {
            &*((entry as usize - core::mem::offset_of!(thread::Thread, process_links))
                as *const thread::Thread)
        };
        for &frame in &thread.gate_frames {
            visit(frame);
        }
        // SAFETY: a linked entry's next pointer names the next entry (or the sentinel).
        entry = unsafe { (*entry).next };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The band constants: 32 levels, realtime from 16, priority 0 reserved for the idle thread.
    #[test]
    fn priority_bands() {
        assert_eq!(PRIORITY_LEVELS, 32);
        assert_eq!(LOWEST_PRIORITY, 0);
        assert_eq!(REALTIME_BASE, 16);
        assert_eq!(HIGHEST_PRIORITY, 31);
        assert_eq!(NORMAL_BASE, 8);
        assert!(REALTIME_BASE < HIGHEST_PRIORITY);
    }

    /// The quantum constants: three per tick, six to reset — one quantum spans exactly two ticks.
    #[test]
    fn quantum_constants() {
        assert_eq!(QUANTUM_TICK, 3);
        assert_eq!(QUANTUM_RESET, 6);
        assert_eq!(QUANTUM_RESET / QUANTUM_TICK, 2);
        assert_eq!(QUANTUM_WAIT_CHARGE, 1);
        assert_eq!(ROUND_TRIP_LIMIT, 16);
        assert_eq!(TIME_CRITICAL_CEILING, 14);
    }

    /// The list: init closes the sentinel, push order is preserved, pop unlinks from the front, and
    /// unlink removes an interior entry without disturbing the rest.
    #[test]
    fn list_discipline() {
        let mut list = List::empty();
        assert!(list.is_empty());
        list.init();
        assert!(list.is_empty());

        let mut a = Links::detached();
        let mut b = Links::detached();
        let mut c = Links::detached();
        // SAFETY: the list is initialized and a/b/c are detached.
        unsafe {
            list.push_back(addr_of_mut!(a));
            list.push_back(addr_of_mut!(b));
            list.push_back(addr_of_mut!(c));
            assert_eq!(list.first(), addr_of_mut!(a));

            // Unlink the middle entry: front and back survive.
            unlink(addr_of_mut!(b));
            assert_eq!(list.first(), addr_of_mut!(a));
            assert_eq!(list.pop_front(), addr_of_mut!(a));
            assert_eq!(list.pop_front(), addr_of_mut!(c));
            assert_eq!(list.pop_front(), core::ptr::null_mut());
        }
        assert!(list.is_empty());
    }
}
