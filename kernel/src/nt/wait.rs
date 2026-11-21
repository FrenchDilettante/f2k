//! The waits' argument checks, NtWaitForMultipleObjects' before and after it reads its handles:
//! pure, so the host tests them (the services themselves are [`super::sync`]'s, on the target).

use crate::sched::wait::{WaitableId, MAXIMUM_WAIT_OBJECTS};
use crate::status::*;

/// NtWaitForMultipleObjects' count and wait type, checked before its handles are read: the count
/// as a length, and whether the wait is WaitAll (0) rather than WaitAny (1).
/// STATUS_INVALID_PARAMETER_1 for no objects or more than MAXIMUM_WAIT_OBJECTS (64),
/// STATUS_INVALID_PARAMETER_3 for another wait type.
#[cfg_attr(not(target_arch = "x86"), allow(dead_code))]
pub fn multiple_wait(count: u32, wait_type: u32) -> Result<(usize, bool), NtStatus> {
    let count = count as usize;
    if count == 0 || count > MAXIMUM_WAIT_OBJECTS {
        return Err(STATUS_INVALID_PARAMETER_1);
    }
    let wait_all = match wait_type {
        0 => true,
        1 => false,
        _ => return Err(STATUS_INVALID_PARAMETER_3),
    };
    Ok((count, wait_all))
}

/// The objects a multiple wait names, once its handles are resolved: a wait-all naming one object
/// twice is STATUS_INVALID_PARAMETER_MIX (a wait-any may).
#[cfg_attr(not(target_arch = "x86"), allow(dead_code))]
pub fn check_objects(objects: &[WaitableId], wait_all: bool) -> Result<(), NtStatus> {
    if wait_all && (1..objects.len()).any(|index| objects[..index].contains(&objects[index])) {
        return Err(STATUS_INVALID_PARAMETER_MIX);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One to 64 objects, WaitAll (0) or WaitAny (1): the count is checked before the type.
    #[test]
    fn the_count_and_the_type_are_checked_in_order() {
        assert_eq!(multiple_wait(1, 0), Ok((1, true)));
        assert_eq!(multiple_wait(64, 1), Ok((64, false)));
        assert_eq!(multiple_wait(0, 1), Err(STATUS_INVALID_PARAMETER_1));
        assert_eq!(multiple_wait(65, 1), Err(STATUS_INVALID_PARAMETER_1));
        assert_eq!(multiple_wait(u32::MAX, 0), Err(STATUS_INVALID_PARAMETER_1));
        assert_eq!(multiple_wait(2, 2), Err(STATUS_INVALID_PARAMETER_3));
        assert_eq!(multiple_wait(0, 2), Err(STATUS_INVALID_PARAMETER_1));
    }

    /// A wait-all naming an object twice is refused, wherever the second naming is; a wait-any may
    /// name it twice, and distinct objects of different kinds sharing an index are distinct.
    #[test]
    fn a_wait_all_names_each_object_once() {
        let (a, b, c) = (
            WaitableId::Event(1),
            WaitableId::Event(2),
            WaitableId::Semaphore(1),
        );
        assert_eq!(check_objects(&[a, b, c], true), Ok(()));
        assert_eq!(check_objects(&[a], true), Ok(()));
        assert_eq!(
            check_objects(&[a, b, a], true),
            Err(STATUS_INVALID_PARAMETER_MIX)
        );
        assert_eq!(
            check_objects(&[c, b, b], true),
            Err(STATUS_INVALID_PARAMETER_MIX)
        );
        assert_eq!(check_objects(&[a, b, a], false), Ok(()));
    }

    /// The statuses a multiple wait completes with, as NtWaitForMultipleObjects returns them: a
    /// wait-any STATUS_WAIT_0 + the lowest signaled index, STATUS_ABANDONED_WAIT_0 + it when that
    /// object is a mutant its owner ended holding (taken at once, or woken by the owner's end); a
    /// wait-all STATUS_WAIT_0, STATUS_ABANDONED_WAIT_0 when an abandoned mutant is among what it
    /// took; STATUS_TIMEOUT when nothing is signaled in time.
    #[test]
    fn a_multiple_wait_s_statuses() {
        use crate::sched::event::EventKind;
        use crate::sched::testkit;
        use crate::sched::thread::ThreadState;
        use crate::sched::wait::{ClockStamp, WaitDisposition, WaitMode, WaitReason};

        const WAIT_0: u32 = 0;
        const ABANDONED_WAIT_0: u32 = 0x80;
        const STAMP: ClockStamp = ClockStamp {
            interrupt_time: 10_000,
            tick: 5,
        };
        let d = testkit::dispatcher();
        let p = testkit::process(8);
        let (owner, waiter, other) = (testkit::thread(p), testkit::thread(p), testkit::thread(p));
        let wait = |thread: testkit::Rec<crate::sched::thread::Thread>,
                    objects: &[WaitableId],
                    wait_all: bool,
                    timeout: Option<i64>| {
            testkit::installed().wait_for_multiple(
                thread.id(),
                objects,
                wait_all,
                WaitReason::UserRequest,
                WaitMode::User,
                false,
                timeout,
                STAMP,
            )
        };
        let complete = |status: u32| WaitDisposition::Complete(NtStatus(status));

        let unset = testkit::event(EventKind::Notification, false).id();
        let set = testkit::event(EventKind::Notification, true).id();
        let mut mutex = testkit::mutex();
        let mutant = WaitableId::Mutex(mutex.id().0);

        assert_eq!(
            wait(waiter, &[unset, unset], false, Some(0)),
            complete(0x102)
        );
        assert_eq!(
            wait(waiter, &[unset, set], false, Some(0)),
            complete(WAIT_0 + 1)
        );
        mutex.abandoned = true;
        assert_eq!(
            wait(waiter, &[unset, unset, mutant, set], false, Some(0)),
            complete(ABANDONED_WAIT_0 + 2),
            "the abandoned mutant is the lowest signaled"
        );
        assert_eq!(d.release_mutex(mutex.id(), waiter.id()), Ok(0));
        assert_eq!(
            wait(waiter, &[unset, mutant], false, Some(0)),
            complete(WAIT_0 + 1),
            "the abandonment is reported once"
        );
        assert_eq!(d.release_mutex(mutex.id(), waiter.id()), Ok(0));

        mutex.abandoned = true;
        assert_eq!(
            wait(waiter, &[set, mutant], true, Some(0)),
            complete(ABANDONED_WAIT_0)
        );
        assert_eq!(d.release_mutex(mutex.id(), waiter.id()), Ok(0));
        assert_eq!(
            wait(waiter, &[set, mutant], true, Some(0)),
            complete(WAIT_0)
        );
        assert_eq!(d.release_mutex(mutex.id(), waiter.id()), Ok(0));

        // Parked on [an event, the mutant] while its owner holds it, woken by the owner's end.
        assert_eq!(wait(owner, &[mutant], false, None), complete(WAIT_0));
        assert_eq!(
            wait(other, &[unset, mutant], false, None),
            WaitDisposition::Yield
        );
        d.enter(owner.id());
        d.thread_mut(owner.id()).state = ThreadState::Running;
        d.retire_current();
        assert!(matches!(
            other.state(),
            ThreadState::Ready | ThreadState::Standby
        ));
        assert_eq!(other.wait_status(), NtStatus(ABANDONED_WAIT_0 + 1));
        assert_eq!(mutex.owner(), Some(other.id()));
    }
}
