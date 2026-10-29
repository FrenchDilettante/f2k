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
//! The dispatcher owns its records — the threads and the bodies of the objects they wait on — in
//! the dispatcher database ([`database`]), and every queue it keeps links them by record index
//! ([`list`]): a thread sits on a ready list by carrying the link itself, as Windows 2000's
//! KTHREAD does, so queueing allocates nothing.
//!
//! One processor, no locking: the dispatcher is a dispatch-level cell ([`DISPATCHER`]), so every
//! method runs serialized at the dispatch level, with the dispatch token lent.

// Parts of the state machines stay unwired until their consumers land; the queues, the delivery,
// the suspend and exit consumers, the forced-resume route, and the re-wait are live.
#![allow(dead_code)]

#[cfg(target_arch = "x86")]
use crate::level::{Dispatch, LevelCell};

/// Index-linked lists: the dispatcher database's queues.
pub mod list;

/// Fixed pools of records, reached by index.
pub mod pool;

/// The dispatcher database: the records the dispatcher owns, and how its lists reach them.
pub mod database;

/// The host tests' rig: dispatchers and records built where the tests can reach them.
#[cfg(test)]
pub mod testkit;

/// The thread object: scheduling state, priorities, quantum.
pub mod thread;

/// The dispatcher: ready queues, selection, the state machines.
pub mod dispatcher;

/// The processor's threads: the current, next and idle threads, and the running thread's quantum.
pub mod processor;

/// The process record's scheduling side: base priority, quantum.
pub mod process;

/// The context switch: the swap assembly, the startup stub, and the machine-state offsets they
/// address threads through.
pub mod switch;

/// Attaching a thread to another process's address space, for a scope.
#[cfg(target_arch = "x86")]
pub mod attach;

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

/// The mutex object: a waitable owned recursively, abandoned by an owner's end.
pub mod mutex;

/// Waitable timers: the program's timer object, its period and completion APC.
pub mod waitable_timer;

// --- The running thread and the dispatcher ---------------------------------

/// The running thread (Windows 2000's KeGetCurrentThread): the processor's current slot, read
/// without the dispatcher. Its record is the dispatcher's
/// ([`dispatcher::Dispatcher::thread`]).
///
/// # Panics
///
/// No thread runs yet: the boot installs the idle thread before anything asks.
pub fn current_thread() -> thread::ThreadId {
    try_current_thread().expect("a thread runs")
}

/// The running thread, none before the boot installs the idle thread.
pub fn try_current_thread() -> Option<thread::ThreadId> {
    crate::pcr::pcr().threads.current()
}

/// The dispatcher database (Windows 2000's, which its dispatcher lock guards): dispatch-level
/// state, reached with the dispatch token. Built in place at its first borrow, the boot's: by value
/// it would pass through the boot stack, which is smaller than it.
#[cfg(target_arch = "x86")]
pub static DISPATCHER: LevelCell<Dispatch, dispatcher::Dispatcher> =
    // SAFETY: `write_empty` writes a whole dispatcher at the address it is handed, and reaches no
    // level cell (it empties the processor's thread slots and the published timer dues).
    unsafe { LevelCell::in_place(dispatcher::Dispatcher::write_empty) };

/// The host builds have no boot: each test thread installs a dispatcher of its own, which
/// [`DISPATCHER`] reaches there.
#[cfg(not(target_arch = "x86"))]
pub static DISPATCHER: host::Installed = host::Installed;

#[cfg(not(target_arch = "x86"))]
pub(crate) use host::install as install_host;

#[cfg(not(target_arch = "x86"))]
mod host {
    extern crate std;

    use core::cell::Cell;

    use super::dispatcher::Dispatcher;
    use crate::level::{Dispatch, LevelCell};

    std::thread_local! {
        static INSTALLED: Cell<Option<&'static LevelCell<Dispatch, Dispatcher>>> =
            const { Cell::new(None) };
    }

    /// The test thread's installed dispatcher, as the kernel's static names it.
    pub struct Installed;

    impl core::ops::Deref for Installed {
        type Target = LevelCell<Dispatch, Dispatcher>;

        /// The installed cell; panics when none is.
        fn deref(&self) -> &LevelCell<Dispatch, Dispatcher> {
            INSTALLED
                .with(Cell::get)
                .expect("a host dispatcher is installed")
        }
    }

    /// Make `dispatcher` this thread's: what [`super::DISPATCHER`] reaches from now on.
    pub fn install(dispatcher: &'static LevelCell<Dispatch, Dispatcher>) {
        INSTALLED.with(|installed| installed.set(Some(dispatcher)));
    }
}

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
}
