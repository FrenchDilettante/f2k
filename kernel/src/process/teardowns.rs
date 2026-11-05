//! Waiting for the ended processes' teardowns: the reap step's signal, and the bounded wait the
//! session's end takes on it before the machine's end.
//!
//! A process's waiters see it end at its last thread's exit (steps 1 to 3 of its end, see the
//! module notes of [`crate::process`]); its reap (step 4, and step 5 when nothing else holds its
//! object) comes later, on the idle thread, whenever no other thread is ready. The reap's reports —
//! the teardown audit, the suite's summary — would otherwise race whatever the waiter does next.
//! The session's end does not let them: before the shutdown, it waits until every process that has
//! ended, or is ending, has been torn down ([`await_all`]), so the audit and the summary always
//! precede the shutdown's first line. The wait is for the reap, not for the deletion: a process
//! object lives on while references hold it, as Windows 2000's csrss holds a handle to each of its
//! processes until it hears of their deaths, and nothing the shutdown flushes depends on it.
//!
//! The signal is a synchronization event the reap step sets after each process's reap, once the
//! runner has reported it. The waiter checks the processes, then waits on the event: a reap
//! between the check and the wait leaves the event set, so it is not missed, and a signal left
//! over from an earlier reap only makes the waiter check again. A reap under way counts as a
//! teardown still pending until its report is out ([`REAPING`]): its process is marked torn down
//! before the runner reports it, and the waiter could otherwise run between the two (the reap's
//! short locks open interrupts, and the waiter's timeout may fire there).

use core::cell::UnsafeCell;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::level::{raised, Dispatch};
use crate::sched::event::{Event, EventKind, EVENT_WAKE_INCREMENT};
use crate::sched::wait::{WaitReason, Waitable, WaitableId};
use crate::sched::DISPATCHER;

/// The reap step's signal (see the module's documentation), named by its address in the
/// dispatcher database ([`WaitableId::Embedded`]) and reached only through the dispatcher once
/// named.
struct ReapSignal(UnsafeCell<Event>);

// SAFETY: one processor. The event is touched directly once, by its naming ([`ReapSignal::id`]'s
// first call, with interrupts masked), before anything signals it or waits on it, since both name
// it through that call first; from then on only the dispatcher reaches its header, by its address,
// serialized at the dispatch level.
unsafe impl Sync for ReapSignal {}

static REAPED: ReapSignal = ReapSignal(UnsafeCell::new(Event::new(
    EventKind::Synchronization,
    false,
)));

/// Whether the event has been named.
static NAMED: AtomicBool = AtomicBool::new(false);

/// Whether the idle thread is inside a reap step: from its start to its signal.
static REAPING: AtomicBool = AtomicBool::new(false);

impl ReapSignal {
    /// The event's name: its header's address, named at the first call (the first reap's signal,
    /// or the first wait, whichever comes first: a fault-test boot reaps with no runner). No
    /// reference to the event is formed after that.
    fn id(&self) -> WaitableId {
        {
            let _masked = crate::pcr::pcr().mask_guard();
            if !NAMED.swap(true, Ordering::SeqCst) {
                // SAFETY: the one direct reach into the event (see the `Sync` impl): nothing has
                // named it yet, so nothing waits on it or signals it, and interrupts are masked
                // for the reference's life.
                unsafe { (*self.0.get()).init() };
            }
        }
        // SAFETY: a projection inside the static's own cell: it computes the header's address and
        // reads nothing.
        let header: *mut Waitable = unsafe { core::ptr::addr_of_mut!((*self.0.get()).waitable) };
        WaitableId::Embedded(NonNull::new(header).expect("a static is not null"))
    }
}

/// The reap step's first act: a teardown is under way until [`signal_reaped`].
pub fn reap_begins() {
    REAPING.store(true, Ordering::SeqCst);
}

/// The reap step's last act: a process has been torn down and reported, and a thread waiting for
/// the teardowns checks them again.
pub fn signal_reaped() {
    REAPING.store(false, Ordering::SeqCst);
    let signal = REAPED.id();
    raised::<Dispatch, _>(|dispatch| {
        DISPATCHER
            .get(dispatch)
            .set_event(signal, EVENT_WAKE_INCREMENT);
    });
}

/// Wait until no process that has ended, or is ending, waits for its teardown, for at most
/// `interval` (100 ns units): `Ok` once none does, or how many still do when the interval has
/// passed. Called at the passive level, from a thread that can wait and holds nothing a reap
/// needs (the session's end, on the console's control thread).
pub fn await_all(interval: i64) -> Result<(), usize> {
    let due = crate::interrupt::clock::interrupt_time().wrapping_add(interval as u64);
    loop {
        let reaping = usize::from(REAPING.load(Ordering::SeqCst));
        let pending = super::pool::teardowns_pending().max(reaping);
        if pending == 0 {
            return Ok(());
        }
        let left = due.wrapping_sub(crate::interrupt::clock::interrupt_time()) as i64;
        if left <= 0 {
            return Err(pending);
        }
        let signal = REAPED.id();
        crate::sched::wait::wait_current_for(signal, WaitReason::Executive, Some(left));
    }
}
