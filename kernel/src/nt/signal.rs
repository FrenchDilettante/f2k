//! The synchronization services' pure pieces, out of their target-only bodies so the host tests
//! them (the services themselves are [`super::sync`]'s, on the target): the arguments the event,
//! mutant, semaphore and timer services check; the verdicts a named create and open reach on what
//! their name binds; and the state changes the signaling services make on the dispatcher (a pulse,
//! a semaphore's release, SignalAndWait's signal), each over the dispatcher the caller holds.

use crate::ob::ObjectType;
use crate::sched::dispatcher::Dispatcher;
use crate::sched::event::{EventKind, EVENT_WAKE_INCREMENT};
use crate::sched::mutex::MutexId;
use crate::sched::thread::ThreadId;
use crate::sched::wait::WaitableId;
use crate::status::*;

/// The priority increment a semaphore release grants the waiters it wakes.
const SEMAPHORE_WAKE_INCREMENT: i8 = 1;

// --- Arguments -----------------------------------------------------------------------------------

/// NtCreateEvent's EventType: NotificationEvent (0, manual-reset) or SynchronizationEvent (1,
/// auto-reset); STATUS_INVALID_PARAMETER for another.
#[cfg_attr(not(target_arch = "x86"), allow(dead_code))]
pub fn event_kind(event_type: u32) -> Result<EventKind, NtStatus> {
    match event_type {
        0 => Ok(EventKind::Notification),
        1 => Ok(EventKind::Synchronization),
        _ => Err(STATUS_INVALID_PARAMETER),
    }
}

/// NtCreateTimer's TimerType, as whether the timer resets manually: NotificationTimer (0, manual)
/// or SynchronizationTimer (1, auto-reset); STATUS_INVALID_PARAMETER for another.
#[cfg_attr(not(target_arch = "x86"), allow(dead_code))]
pub fn timer_manual_reset(timer_type: u32) -> Result<bool, NtStatus> {
    match timer_type {
        0 => Ok(true),
        1 => Ok(false),
        _ => Err(STATUS_INVALID_PARAMETER),
    }
}

/// NtCreateSemaphore's counts: a positive maximum and 0 <= initial <= maximum, else
/// STATUS_INVALID_PARAMETER.
#[cfg_attr(not(target_arch = "x86"), allow(dead_code))]
pub fn check_semaphore(initial: i32, maximum: i32) -> Result<(), NtStatus> {
    if maximum <= 0 || initial < 0 || initial > maximum {
        return Err(STATUS_INVALID_PARAMETER);
    }
    Ok(())
}

/// NtReleaseSemaphore's count, checked before its handle: STATUS_INVALID_PARAMETER unless
/// positive.
#[cfg_attr(not(target_arch = "x86"), allow(dead_code))]
pub fn check_release_count(count: i32) -> Result<(), NtStatus> {
    if count <= 0 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    Ok(())
}

/// NtSetTimer's Period, in milliseconds (zero: a one-shot), as the timer's period in 100 ns units;
/// STATUS_INVALID_PARAMETER for a negative one. The longest, i32::MAX milliseconds, fits.
#[cfg_attr(not(target_arch = "x86"), allow(dead_code))]
pub fn timer_period(period: i32) -> Result<u64, NtStatus> {
    let period = u64::try_from(period).map_err(|_| STATUS_INVALID_PARAMETER)?;
    Ok(period * 10_000)
}

/// What a set timer answers: STATUS_TIMER_RESUME_IGNORED when the caller asked it to resume the
/// machine (unsupported, as on a machine without power management), else STATUS_SUCCESS.
#[cfg_attr(not(target_arch = "x86"), allow(dead_code))]
pub fn set_timer_status(resume: bool) -> NtStatus {
    if resume {
        STATUS_TIMER_RESUME_IGNORED
    } else {
        STATUS_SUCCESS
    }
}

// --- Names ---------------------------------------------------------------------------------------

/// What a create's or an open's name binds in `\BaseNamedObjects`: the directory itself, or a live
/// object of a kind.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(not(target_arch = "x86"), allow(dead_code))]
pub enum Bound {
    Directory,
    Object(ObjectType),
}

/// A create of a `kind` object whose name binds `bound`: Ok to open the object bound (the create
/// answers STATUS_OBJECT_NAME_EXISTS) under OBJ_OPENIF (`open_if`) when the kinds agree,
/// STATUS_OBJECT_TYPE_MISMATCH when they do not (the directory is no kind a create makes);
/// without OBJ_OPENIF any bound name is STATUS_OBJECT_NAME_COLLISION.
#[cfg_attr(not(target_arch = "x86"), allow(dead_code))]
pub fn create_over(bound: Bound, kind: ObjectType, open_if: bool) -> Result<(), NtStatus> {
    match bound {
        _ if !open_if => Err(STATUS_OBJECT_NAME_COLLISION),
        Bound::Object(existing) if existing == kind => Ok(()),
        Bound::Object(_) | Bound::Directory => Err(STATUS_OBJECT_TYPE_MISMATCH),
    }
}

/// An open of a `kind` object, asking `access`, whose name binds `bound`: Ok for an object of its
/// kind asking some access; STATUS_OBJECT_TYPE_MISMATCH for another kind (the directory included),
/// then STATUS_ACCESS_DENIED for no access at all (Windows 2000's access check grants an empty
/// request nothing).
#[cfg_attr(not(target_arch = "x86"), allow(dead_code))]
pub fn open_of(bound: Bound, kind: ObjectType, access: u32) -> Result<(), NtStatus> {
    match bound {
        Bound::Object(existing) if existing == kind => {}
        Bound::Object(_) | Bound::Directory => return Err(STATUS_OBJECT_TYPE_MISMATCH),
    }
    if access == 0 {
        return Err(STATUS_ACCESS_DENIED);
    }
    Ok(())
}

// --- Signals -------------------------------------------------------------------------------------

/// NtPulseEvent's change: the event set for the waiters present (all of them for a notification
/// event, the oldest for a synchronization event, each granted the event wake boost), then left
/// cleared either way. Returns the previous state.
#[cfg_attr(not(target_arch = "x86"), allow(dead_code))]
pub fn pulse_event(dispatcher: &mut Dispatcher, event: WaitableId) -> i32 {
    let was = dispatcher.set_event(event, EVENT_WAKE_INCREMENT);
    dispatcher.reset_event(event);
    was
}

/// NtReleaseSemaphore's change: `count` (checked positive: [`check_release_count`]) added,
/// waking as many waiters as it covers; the previous count. STATUS_SEMAPHORE_LIMIT_EXCEEDED past
/// the maximum or on a wrap, the count unchanged.
#[cfg_attr(not(target_arch = "x86"), allow(dead_code))]
pub fn release_semaphore(
    dispatcher: &mut Dispatcher,
    semaphore: WaitableId,
    count: i32,
) -> Result<i32, NtStatus> {
    dispatcher
        .release_semaphore(semaphore, count, SEMAPHORE_WAKE_INCREMENT)
        .map_err(|_| STATUS_SEMAPHORE_LIMIT_EXCEEDED)
}

/// The kind of the object SignalAndWait's signal handle names (none: the handle names nothing),
/// with the right signaling it needs (see [`crate::ob::access::signal_right`]):
/// STATUS_INVALID_HANDLE for no object, STATUS_OBJECT_TYPE_MISMATCH for a kind no signal reaches.
#[cfg_attr(not(target_arch = "x86"), allow(dead_code))]
pub fn signal_needs(kind: Option<ObjectType>) -> Result<(ObjectType, u32), NtStatus> {
    let kind = kind.ok_or(STATUS_INVALID_HANDLE)?;
    let needed = crate::ob::access::signal_right(kind).ok_or(STATUS_OBJECT_TYPE_MISMATCH)?;
    Ok((kind, needed))
}

/// The object SignalAndWait signals, by its kind.
#[derive(Clone, Copy, Debug)]
#[cfg_attr(not(target_arch = "x86"), allow(dead_code))]
pub enum Signal {
    /// Set, with the event wake boost.
    Event(WaitableId),
    /// Released by one.
    Semaphore(WaitableId),
    /// Released by one unit of the caller's ownership.
    Mutant(MutexId),
}

/// SignalAndWait's signal on behalf of `thread` (the caller): the event set, the semaphore released
/// by one (STATUS_SEMAPHORE_LIMIT_EXCEEDED at its maximum), or the mutant released
/// (STATUS_MUTANT_NOT_OWNED unless `thread` owns it). A refusal changes nothing.
#[cfg_attr(not(target_arch = "x86"), allow(dead_code))]
pub fn signal(
    dispatcher: &mut Dispatcher,
    signal: Signal,
    thread: ThreadId,
) -> Result<(), NtStatus> {
    match signal {
        Signal::Event(event) => {
            dispatcher.set_event(event, EVENT_WAKE_INCREMENT);
        }
        Signal::Semaphore(semaphore) => {
            release_semaphore(dispatcher, semaphore, 1)?;
        }
        Signal::Mutant(mutant) => {
            dispatcher.release_mutex(mutant, thread)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ob::access::{EVENT_MODIFY_STATE, SEMAPHORE_MODIFY_STATE};
    use crate::sched::event::Event;
    use crate::sched::testkit::{self, Rec};
    use crate::sched::thread::{Thread, ThreadState};
    use crate::sched::wait::{ClockStamp, WaitDisposition, WaitMode, WaitReason, Waitable};

    const STAMP: ClockStamp = ClockStamp {
        interrupt_time: 10_000,
        tick: 5,
    };

    /// Park or satisfy `thread`'s untimed wait on `object`.
    fn wait(d: &mut Dispatcher, thread: Rec<Thread>, object: *mut Waitable) -> WaitDisposition {
        d.wait_single(
            thread,
            object,
            WaitReason::UserRequest,
            WaitMode::User,
            false,
            None,
            STAMP,
        )
    }

    /// The two event types and the two timer types; any other number is refused.
    #[test]
    fn the_event_and_timer_types() {
        assert_eq!(event_kind(0), Ok(EventKind::Notification));
        assert_eq!(event_kind(1), Ok(EventKind::Synchronization));
        for wrong in [2, 0x100, u32::MAX] {
            assert_eq!(event_kind(wrong), Err(STATUS_INVALID_PARAMETER));
            assert_eq!(timer_manual_reset(wrong), Err(STATUS_INVALID_PARAMETER));
        }
        assert_eq!(timer_manual_reset(0), Ok(true));
        assert_eq!(timer_manual_reset(1), Ok(false));
    }

    /// A semaphore's maximum is positive and its initial count between zero and it, both ends
    /// included; a release adds a positive count.
    #[test]
    fn a_semaphore_s_counts() {
        let invalid = Err(STATUS_INVALID_PARAMETER);
        assert_eq!(check_semaphore(0, 1), Ok(()));
        assert_eq!(check_semaphore(1, 1), Ok(()));
        assert_eq!(check_semaphore(0, i32::MAX), Ok(()));
        assert_eq!(check_semaphore(i32::MAX, i32::MAX), Ok(()));
        assert_eq!(check_semaphore(0, 0), invalid);
        assert_eq!(check_semaphore(0, -1), invalid);
        assert_eq!(check_semaphore(-1, 5), invalid);
        assert_eq!(check_semaphore(6, 5), invalid);
        assert_eq!(check_semaphore(i32::MIN, i32::MIN), invalid);

        assert_eq!(check_release_count(1), Ok(()));
        assert_eq!(check_release_count(i32::MAX), Ok(()));
        assert_eq!(check_release_count(0), invalid);
        assert_eq!(check_release_count(-1), invalid);
        assert_eq!(check_release_count(i32::MIN), invalid);
    }

    /// A timer's period: milliseconds to 100 ns units, zero a one-shot, the longest exact, a
    /// negative one refused; a resume asked for is ignored with its own success status.
    #[test]
    fn a_timer_s_period_and_resume() {
        assert_eq!(timer_period(0), Ok(0));
        assert_eq!(timer_period(1), Ok(10_000));
        assert_eq!(timer_period(1000), Ok(10_000_000));
        assert_eq!(timer_period(i32::MAX), Ok(i32::MAX as u64 * 10_000));
        assert_eq!(timer_period(-1), Err(STATUS_INVALID_PARAMETER));
        assert_eq!(timer_period(i32::MIN), Err(STATUS_INVALID_PARAMETER));

        assert_eq!(set_timer_status(false), STATUS_SUCCESS);
        assert_eq!(set_timer_status(true), STATUS_TIMER_RESUME_IGNORED);
        assert!(STATUS_TIMER_RESUME_IGNORED.is_success());
    }

    /// A create over a bound name: without OBJ_OPENIF always a collision (the directory's name
    /// included); with it, the same kind opens and any other kind, the directory included, is a
    /// type mismatch.
    #[test]
    fn a_create_over_a_bound_name() {
        let kinds = [
            ObjectType::Event,
            ObjectType::Mutex,
            ObjectType::Semaphore,
            ObjectType::Timer,
            ObjectType::Section,
        ];
        for kind in kinds {
            assert_eq!(
                create_over(Bound::Directory, kind, false),
                Err(STATUS_OBJECT_NAME_COLLISION)
            );
            assert_eq!(
                create_over(Bound::Directory, kind, true),
                Err(STATUS_OBJECT_TYPE_MISMATCH)
            );
            for existing in kinds {
                assert_eq!(
                    create_over(Bound::Object(existing), kind, false),
                    Err(STATUS_OBJECT_NAME_COLLISION),
                    "{existing:?} under {kind:?}"
                );
                let opened = if existing == kind {
                    Ok(())
                } else {
                    Err(STATUS_OBJECT_TYPE_MISMATCH)
                };
                assert_eq!(create_over(Bound::Object(existing), kind, true), opened);
            }
        }
    }

    /// An open: the kind first (the directory is never one an open of an object asks), then an
    /// empty access.
    #[test]
    fn an_open_checks_the_kind_then_the_access() {
        let event = ObjectType::Event;
        assert_eq!(open_of(Bound::Object(event), event, 0x1F_0003), Ok(()));
        assert_eq!(open_of(Bound::Object(event), event, 1), Ok(()));
        assert_eq!(
            open_of(Bound::Object(event), event, 0),
            Err(STATUS_ACCESS_DENIED)
        );
        assert_eq!(
            open_of(Bound::Object(ObjectType::Mutex), event, 0),
            Err(STATUS_OBJECT_TYPE_MISMATCH)
        );
        assert_eq!(
            open_of(Bound::Directory, event, 0x1F_0003),
            Err(STATUS_OBJECT_TYPE_MISMATCH)
        );
    }

    /// SignalAndWait's signal: an event's, a semaphore's and a mutant's rights; no object is an
    /// invalid handle, a kind no signal reaches a type mismatch.
    #[test]
    fn what_a_signal_needs() {
        assert_eq!(
            signal_needs(Some(ObjectType::Event)),
            Ok((ObjectType::Event, EVENT_MODIFY_STATE))
        );
        assert_eq!(
            signal_needs(Some(ObjectType::Semaphore)),
            Ok((ObjectType::Semaphore, SEMAPHORE_MODIFY_STATE))
        );
        assert_eq!(
            signal_needs(Some(ObjectType::Mutex)),
            Ok((ObjectType::Mutex, 0))
        );
        for kind in [
            ObjectType::Timer,
            ObjectType::Thread,
            ObjectType::Process,
            ObjectType::File,
            ObjectType::Section,
            ObjectType::Directory,
        ] {
            assert_eq!(
                signal_needs(Some(kind)),
                Err(STATUS_OBJECT_TYPE_MISMATCH),
                "{kind:?}"
            );
        }
        assert_eq!(signal_needs(None), Err(STATUS_INVALID_HANDLE));
    }

    /// A pulse of a notification event wakes every waiter present, of a synchronization event the
    /// oldest alone; both are left cleared, and the pulse answers the state before it.
    #[test]
    fn a_pulse_wakes_the_waiters_present_and_leaves_the_event_cleared() {
        let d = testkit::dispatcher();
        let p = testkit::process(8);
        let (a, b, c, e) = (
            testkit::thread(p),
            testkit::thread(p),
            testkit::thread(p),
            testkit::thread(p),
        );

        let manual: &mut Event = testkit::event(EventKind::Notification, false);
        assert_eq!(wait(d, a, manual.waitable()), WaitDisposition::Yield);
        assert_eq!(wait(d, b, manual.waitable()), WaitDisposition::Yield);
        assert_eq!(pulse_event(d, manual.id()), 0);
        assert_eq!(a.state(), ThreadState::Ready);
        assert_eq!(b.state(), ThreadState::Ready);
        assert_eq!(manual.signal_state(), 0, "left cleared");

        let auto: &mut Event = testkit::event(EventKind::Synchronization, false);
        assert_eq!(wait(d, c, auto.waitable()), WaitDisposition::Yield);
        assert_eq!(wait(d, e, auto.waitable()), WaitDisposition::Yield);
        assert_eq!(pulse_event(d, auto.id()), 0);
        assert_eq!(c.state(), ThreadState::Ready, "the oldest");
        assert_eq!(e.state(), ThreadState::Waiting, "the other stays");
        assert_eq!(auto.signal_state(), 0);

        // With nobody waiting a pulse signals no one and leaves the event as cleared as a reset.
        let signaled: &mut Event = testkit::event(EventKind::Notification, true);
        assert_eq!(pulse_event(d, signaled.id()), 1, "the state before");
        assert_eq!(signaled.signal_state(), 0);
    }

    /// A release adds its count and answers the one before; past the maximum, or wrapping, it is
    /// refused with the limit's status and the count stays.
    #[test]
    fn a_release_stops_at_the_semaphore_s_maximum() {
        let d = testkit::dispatcher();
        d.renew_semaphore(0, 1, 3);
        let semaphore = WaitableId::Semaphore(0);
        assert_eq!(release_semaphore(d, semaphore, 2), Ok(1));
        assert_eq!(d.waitable(semaphore).signal_state(), 3);
        assert_eq!(
            release_semaphore(d, semaphore, 1),
            Err(STATUS_SEMAPHORE_LIMIT_EXCEEDED)
        );
        assert_eq!(d.waitable(semaphore).signal_state(), 3, "unchanged");

        d.renew_semaphore(1, 1, i32::MAX);
        let wide = WaitableId::Semaphore(1);
        assert_eq!(
            release_semaphore(d, wide, i32::MAX),
            Err(STATUS_SEMAPHORE_LIMIT_EXCEEDED),
            "the wrap"
        );
        assert_eq!(release_semaphore(d, wide, i32::MAX - 1), Ok(1));
        assert_eq!(d.waitable(wide).signal_state(), i32::MAX);
    }

    /// SignalAndWait's signal for each kind: the event set, the semaphore released by one up to
    /// its maximum, the mutant released by its owner alone.
    #[test]
    fn a_signal_for_each_kind() {
        let d = testkit::dispatcher();
        let p = testkit::process(8);
        let (owner, other) = (testkit::thread(p), testkit::thread(p));

        let event: &mut Event = testkit::event(EventKind::Synchronization, false);
        assert_eq!(signal(d, Signal::Event(event.id()), owner.id()), Ok(()));
        assert_eq!(event.signal_state(), 1);
        assert_eq!(signal(d, Signal::Event(event.id()), owner.id()), Ok(()));
        assert_eq!(event.signal_state(), 1, "a set event stays set");

        d.renew_semaphore(0, 0, 1);
        let semaphore = WaitableId::Semaphore(0);
        assert_eq!(signal(d, Signal::Semaphore(semaphore), owner.id()), Ok(()));
        assert_eq!(d.waitable(semaphore).signal_state(), 1);
        assert_eq!(
            signal(d, Signal::Semaphore(semaphore), owner.id()),
            Err(STATUS_SEMAPHORE_LIMIT_EXCEEDED)
        );
        assert_eq!(d.waitable(semaphore).signal_state(), 1);

        let mut mutant = testkit::mutex();
        assert_eq!(
            signal(d, Signal::Mutant(mutant.id()), owner.id()),
            Err(STATUS_MUTANT_NOT_OWNED),
            "a free mutant is no one's"
        );
        assert_eq!(
            wait(d, owner, mutant.waitable()),
            WaitDisposition::Complete(STATUS_SUCCESS)
        );
        assert_eq!(
            signal(d, Signal::Mutant(mutant.id()), other.id()),
            Err(STATUS_MUTANT_NOT_OWNED)
        );
        assert_eq!(mutant.owner(), Some(owner.id()), "still the owner's");
        assert_eq!(signal(d, Signal::Mutant(mutant.id()), owner.id()), Ok(()));
        assert_eq!(mutant.owner(), None, "free again");
    }
}
