//! The target's side: the queues' events, the server's event and the waits.

use core::cell::UnsafeCell;
use core::ptr::NonNull;

use super::*;
use crate::level::{At, Dispatch, Passive};
use crate::sched::event::{Event, EventKind};
use crate::sched::thread::ThreadId;
use crate::sched::wait::{self, WaitMode, WaitReason, WaitableId};
use crate::slots::Record;
use crate::status::*;
use crate::win32k::window::{Locked, WindowManager};

/// A queue's event: a synchronization event, set whenever its queue is given something (see
/// [`Queues::take_wakes`]), waited on by the queue's thread alone. Named by its address in the
/// dispatcher database ([`WaitableId::Embedded`]) when its chunk is made, and reached only
/// through the dispatcher from then on.
struct QueueEvent(UnsafeCell<Event>);

// SAFETY: one processor. An event is touched directly once, by `write_fresh` as its chunk is
// made, before its chunk is published: no thread can wait on it or set it yet. From then on
// only the dispatcher reaches its header, by its address, serialized at the dispatch level.
unsafe impl Sync for QueueEvent {}

// SAFETY: writes a whole record, named at its final address.
unsafe impl Record for QueueEvent {
    unsafe fn write_fresh(at: *mut Self, _: u32) {
        // SAFETY: the caller's contract: `at` is the record's final address, unpublished.
        unsafe {
            at.write(QueueEvent(UnsafeCell::new(Event::new(
                EventKind::Synchronization,
                false,
            ))));
            (*(*at).0.get()).init();
        }
    }
}

/// The queues' events, at their thread records' indices: made with the queue, from the
/// nonpaged pool, outside the window manager (whose state its lock's holder borrows whole),
/// and kept at their peak, so an event never moves.
static EVENTS: crate::slots::SideTable<
    QueueEvent,
    { crate::slots::entries_per_page::<QueueEvent>() },
> = crate::slots::SideTable::new();

/// Make the event of the queue at `index`: false when no page is left for it.
pub fn make_event(index: u16) -> bool {
    EVENTS
        .ensure(index.into(), &crate::slots::KERNEL_PAGES)
        .is_ok()
}

/// The event of the queue at `index`, made with the queue: its header's address. No
/// reference to the event is formed.
fn event_id(index: usize) -> WaitableId {
    let event = EVENTS
        .address(index as u32)
        .expect("a queue's event made with the queue");
    // SAFETY: a projection inside the record's own cell: it computes the header's address and
    // reads nothing.
    let header = unsafe { core::ptr::addr_of_mut!((*(*event.as_ptr()).0.get()).waitable) };
    WaitableId::Embedded(NonNull::new(header).expect("a made record is not null"))
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

/// Name the server's event. Once, at boot, before the first process (the queues' are named
/// as they are made).
pub fn init() {
    let _masked = crate::pcr::pcr().mask_guard();
    // SAFETY: the one direct reach into the event (see the `Sync` impl): nothing waits on it
    // or sets it yet, and interrupts are masked for the reference's life.
    unsafe { (*SERVER.0.get()).init() };
}

/// Run `f` on the locked window manager, then set the events of the queues it gave something,
/// once the lock is let go.
pub fn with_manager<R>(passive: &mut At<Passive>, f: impl FnOnce(&mut WindowManager) -> R) -> R {
    with_session(passive, |session| f(session.manager()))
}

/// Run `f` in a session over the locked window manager ([`QueueSession`]), the window
/// manager's decisions' way in, then set the events of the queues it gave something, once the
/// lock is let go, and settle the foreground processes, which a change of the foreground
/// window moves (`crate::process::foreground`).
pub fn with_session<R>(
    passive: &mut At<Passive>,
    f: impl FnOnce(&mut QueueSession<Locked<'_>>) -> R,
) -> R {
    let (result, signals) = {
        let mut session = QueueSession::over(crate::win32k::window::lock(passive));
        let result = f(&mut session);
        (result, Signals::take(session.manager()))
    };
    signals.raise(passive);
    crate::process::foreground::sync();
    result
}

impl Signals {
    /// Set the events of the queues given something, and the server's when its send was
    /// answered: outside the window manager's lock.
    pub fn raise(self, passive: &mut At<Passive>) {
        let Signals {
            wakes,
            made,
            server,
        } = self;
        if !server && wakes.is_empty() {
            return;
        }
        let mut dispatch = passive.raise::<Dispatch>();
        let dispatcher = crate::sched::DISPATCHER.get(&mut dispatch);
        for index in wakes.each(made) {
            dispatcher.set_event(event_id(index.into()), GUI_WAKE_INCREMENT);
        }
        if server {
            dispatcher.set_event(SERVER.id(), GUI_WAKE_INCREMENT);
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
    let event = event_id(thread.0 as usize);
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
/// relative; none: no end), its user APCs ending it when `alertable` (STATUS_USER_APC): the
/// wait's status, STATUS_WAIT_0 + the count of `objects` for the queue's event (given
/// something: the caller looks again at what).
pub fn wait_on_objects_or_queue(
    thread: ThreadId,
    objects: &[WaitableId],
    alertable: bool,
    timeout: Option<i64>,
) -> NtStatus {
    let mut ids = [event_id(thread.0 as usize); wait::MAXIMUM_WAIT_OBJECTS];
    ids[..objects.len()].copy_from_slice(objects);
    wait_on_objects(&ids[..=objects.len()], false, alertable, timeout)
}

/// The calling thread waits on `objects` (one at least), a wait-all when `wait_all`, until
/// `timeout` (100 ns units, relative; none: no end), alertably when `alertable`: the wait's
/// status, as NtWaitForMultipleObjects'.
pub fn wait_on_objects(
    objects: &[WaitableId],
    wait_all: bool,
    alertable: bool,
    timeout: Option<i64>,
) -> NtStatus {
    wait::wait_current_with(|dispatcher, me, stamp, replay| {
        let timeout =
            wait::replay_timeout(dispatcher.thread(me), replay, timeout, stamp.interrupt_time);
        dispatcher.wait_for_multiple(
            me,
            objects,
            wait_all,
            WaitReason::UserRequest,
            WaitMode::User,
            alertable,
            timeout,
            stamp,
        )
    })
}

/// The interrupt time, the clock the queues' times and the timers' dues read.
pub fn now() -> u64 {
    crate::interrupt::clock::interrupt_time()
}
