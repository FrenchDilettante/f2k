//! The timer table: where wait timeouts live until they are due.
//!
//! The table is 128 buckets, one per hand value: a timer due at time T belongs to bucket
//! `floor(T / increment) & 127` — the bucket of the tick it falls *within*. Each bucket is a
//! due-time-ascending list (equals keep insertion order), so a bucket's head is its earliest due
//! and a walk can stop at the first entry that is not yet due.
//!
//! The clock drives everything. At the transition to full tick N its interrupt service checks two
//! bucket heads — the bucket of tick N-1, then the bucket of tick N — against the just-advanced
//! interrupt time; a due head enqueues the deferred expiry work with the firing tick's low word as
//! its argument. The deferred work then scans the buckets from the argument's own through the
//! current tick's (the whole table if the work was delayed over a full table round), collects the
//! due timers in due order, and expires each through the wait discipline's own expiry entry — the
//! same remove-signal-satisfy path a direct expiry takes.
//!
//! Due times are clock readings (100 ns units) compared as plain unsigned values; a due time is
//! "past" when it is less than or equal to the current reading. One membership link per timer
//! serves the bucket list and the walk's collection list: a timer is on exactly one at a time.
//!
//! One processor, no locking: every entry runs serialized at the dispatch level or above.

use core::ptr::{addr_of_mut, eq, null_mut};

use super::dispatcher::Dispatcher;
use super::wait::Timer;
use super::{link_after, Links, List};

/// The number of buckets: one per hand value, a power of two.
pub const TIMER_TABLE_SIZE: usize = 128;

/// The timer table: the due-time-ordered buckets of pending timers.
#[repr(C)]
pub struct TimerTable {
    /// The buckets, indexed by `floor(due / increment) & 127`.
    buckets: [List; TIMER_TABLE_SIZE],
    /// The time increment the bucket arithmetic divides by (the clock's interval, 100 ns units).
    increment: u64,
}

/// The timer a bucket entry belongs to.
// SAFETY-contract: `links` is the links field of a live timer.
fn timer_of(links: *mut Links) -> *mut Timer {
    (links as usize - core::mem::offset_of!(Timer, links)) as *mut Timer
}

/// A list's sentinel link (the shared accessor needs a mutable borrow; the walks here only read).
fn sentinel_of(list: &List) -> *mut Links {
    core::ptr::addr_of!(list.head) as *mut Links
}

/// Whether the head of `bucket` is due by `now`.
// SAFETY-contract: the bucket is initialized; its entries are live timers.
unsafe fn head_due(bucket: &List, now: u64) -> bool {
    let head = unsafe { bucket.first() };
    !head.is_null() && unsafe { (*timer_of(head)).due_time } <= now
}

impl TimerTable {
    /// A table with unlinked sentinels; call [`TimerTable::init`] once it is at its final address.
    pub const fn zeroed() -> Self {
        TimerTable {
            buckets: [List::empty(); TIMER_TABLE_SIZE],
            increment: 0,
        }
    }

    /// Close the bucket sentinels and set the increment the bucket arithmetic divides by (the
    /// clock's interval).
    pub fn init(&mut self, increment: u64) {
        for bucket in self.buckets.iter_mut() {
            bucket.init();
        }
        self.increment = increment;
    }

    /// The bucket a due time belongs to: the tick it falls within, masked to the table.
    fn bucket_of(&self, due: u64) -> usize {
        ((due / self.increment) as usize) & (TIMER_TABLE_SIZE - 1)
    }

    /// Insert `timer` at `due` (a clock reading, 100 ns units): clear any stale signal, record the
    /// due time, and link it into its bucket in due order. False means the due time is already past
    /// — the timer stays unsignaled and unheld, and the caller reports a timeout at once. The
    /// past-due verdict is settled at the entry, not after linking: the serialized kernel cannot
    /// move the clock between the caller's reading and the link, so the entry check is exact.
    pub fn insert(&mut self, timer: &mut Timer, due: u64, now: u64) -> bool {
        timer.waitable.signal_state = 0;
        self.link(timer, due, now)
    }

    /// A periodic timer's re-arm at its expiry: as [`TimerTable::insert`], but the signal the
    /// expiry just set stands — a periodic timer is never reset by its own re-arm, only by a wait
    /// that consumes the signal or a new set.
    pub fn reinsert_periodic(&mut self, timer: &mut Timer, due: u64, now: u64) -> bool {
        self.link(timer, due, now)
    }

    /// Record `due` and link `timer` into its bucket in due order; false (nothing linked) when the
    /// due time is already past.
    fn link(&mut self, timer: &mut Timer, due: u64, now: u64) -> bool {
        if due <= now {
            timer.inserted = false;
            return false;
        }
        timer.due_time = due;
        timer.inserted = true;

        let bucket = &mut self.buckets[self.bucket_of(due)];
        // SAFETY: the bucket is initialized; the timer's links are detached (an inserted timer is
        // on no list, and the entry check above refused a still-linked record's reuse).
        unsafe {
            let links = addr_of_mut!(timer.links);
            let sentinel = sentinel_of(bucket);
            // Search from the back: the first entry whose due is not later places the new timer
            // right after it, so equal dues keep insertion order; an empty bucket or an all-later
            // one inserts at the front.
            let mut anchor = (*sentinel).prev;
            while !eq(anchor, sentinel) {
                let other = timer_of(anchor);
                if (*other).due_time <= due {
                    break;
                }
                anchor = (*anchor).prev;
            }
            link_after(anchor, links);
        }
        true
    }

    /// Cancel `timer`: unlink it from the list it is on and release the hold, leaving the due time
    /// recorded. A cancelled timer expires as a no-op.
    pub fn remove(&mut self, timer: &mut Timer) {
        if timer.inserted {
            timer.inserted = false;
            // SAFETY: an inserted timer's links are wired into a bucket (or, mid-walk, the walk's
            // collection list); the unlink is the same either way.
            unsafe { unlink(addr_of_mut!(timer.links)) };
        }
    }

    /// The clock's expiry check at the transition to tick `tick_low`: the bucket of tick N-1 first,
    /// then the bucket of tick N, against `now` (the already-advanced interrupt time). The result
    /// is the firing bucket's tick — the argument the deferred expiry work carries.
    pub fn trigger(&self, now: u64, tick_low: u32) -> Option<u32> {
        let previous = tick_low.wrapping_sub(1);
        let index = (previous as usize) & (TIMER_TABLE_SIZE - 1);
        // SAFETY: the bucket is initialized.
        if unsafe { head_due(&self.buckets[index], now) } {
            return Some(previous);
        }
        let index = (tick_low as usize) & (TIMER_TABLE_SIZE - 1);
        // SAFETY: as above.
        if unsafe { head_due(&self.buckets[index], now) } {
            return Some(tick_low);
        }
        None
    }

    /// Collect the timers due by `now` into `expired`, from the buckets `argument`'s own through
    /// the current tick's (in wrap-around order); `tick_low` is the current tick's low word. A
    /// deferred work delayed over a full table round scans every bucket instead — the window
    /// bookkeeping is void at that point, so everything is checked.
    fn collect_due(&mut self, expired: &mut List, now: u64, tick_low: u32, argument: u32) {
        let limit = (tick_low as usize) & (TIMER_TABLE_SIZE - 1);
        let start = (argument as usize) & (TIMER_TABLE_SIZE - 1);
        let full = tick_low.wrapping_sub(argument) >= TIMER_TABLE_SIZE as u32;
        let span = if full {
            TIMER_TABLE_SIZE
        } else {
            // The inclusive wrap-around distance from start to limit; equal ends mean one bucket
            // (the window is under a round by the check above).
            (limit + TIMER_TABLE_SIZE - start) % TIMER_TABLE_SIZE + 1
        };
        for step in 0..span {
            let bucket = &mut self.buckets[(start + step) & (TIMER_TABLE_SIZE - 1)];
            // SAFETY: the bucket is initialized; its entries are live, inserted timers.
            unsafe {
                while head_due(bucket, now) {
                    let entry = bucket.first();
                    unlink(entry);
                    expired.push_back(entry);
                }
            }
        }
    }

    /// The table's consistency audit: every bucket entry is an inserted, unsignaled timer in its
    /// own bucket, in due order.
    pub fn audit(&self) -> Result<(), &'static str> {
        for (index, bucket) in self.buckets.iter().enumerate() {
            let sentinel = sentinel_of(bucket);
            let mut last_due: Option<u64> = None;
            // SAFETY: the bucket is initialized; the walk ends at the sentinel.
            let mut entry = unsafe { bucket.first() };
            while !entry.is_null() && !eq(entry, sentinel) {
                // SAFETY: the entry is a live timer's links.
                let timer = unsafe { &*timer_of(entry) };
                if !timer.inserted {
                    return Err("a bucket entry is not inserted");
                }
                // A periodic timer re-arms with its signal standing; every other entry was reset
                // by its insert.
                if timer.waitable.signal_state != 0 && timer.period == 0 {
                    return Err("a bucket entry is signaled");
                }
                if self.bucket_of(timer.due_time) != index {
                    return Err("a timer is linked in the wrong bucket");
                }
                if let Some(due) = last_due {
                    if timer.due_time < due {
                        return Err("a bucket is not due-ordered");
                    }
                }
                last_due = Some(timer.due_time);
                // SAFETY: a linked entry's next pointer names the next entry (or the sentinel).
                entry = unsafe { (*entry).next };
            }
        }
        Ok(())
    }
}

// SAFETY-contract: `entry` is a linked links field whose list sentinel is alive.
unsafe fn unlink(entry: *mut Links) {
    unsafe {
        let prev = (*entry).prev;
        let next = (*entry).next;
        (*prev).next = next;
        (*next).prev = prev;
        (*entry).prev = null_mut();
        (*entry).next = null_mut();
    }
}

impl Dispatcher {
    /// The clock's expiry check (the table's trigger, for the interrupt service).
    pub(crate) fn timer_trigger(&self, now: u64, tick_low: u32) -> Option<u32> {
        self.timer_table.trigger(now, tick_low)
    }

    /// The deferred expiry work: collect the timers due by `now` — from the buckets the `argument`
    /// tick names through the current one — and expire each in due order through the wait
    /// discipline's expiry entry. `tick_low` is the current tick's low word.
    pub(crate) fn expire_timers(&mut self, now: u64, tick_low: u32, argument: u32) {
        // The collection list: timers unlinked from their buckets await their expiry here, in due
        // order.
        let mut expired = List::empty();
        expired.init();
        self.timer_table
            .collect_due(&mut expired, now, tick_low, argument);

        // SAFETY: the list is initialized and holds unlinked-from- their-bucket timers; each pass
        // unlinks one entry and releases the hold — the removal the expiry entry would otherwise
        // repeat.
        unsafe {
            while !expired.is_empty() {
                let entry = expired.first();
                unlink(entry);
                let timer = timer_of(entry);
                (*timer).inserted = false;
                self.expire_timer(timer);
                self.timer_fired(&mut *timer, now);
            }
        }
    }

    /// What an expiry does past the signal-and-satisfy: queue the timer's APC (unless the previous
    /// one is still queued), and re-arm a periodic timer one period from `now`. A thread's wait
    /// timer has neither.
    pub(crate) fn timer_fired(&mut self, timer: &mut Timer, now: u64) {
        if !timer.apc.is_null() {
            // SAFETY: a timer's APC record lives as long as the timer (both in one record).
            if !unsafe { (*timer.apc).inserted } {
                self.queue_apc(timer.apc, timer.apc_routine, 0, 0);
            }
        }
        if timer.period != 0 && !timer.inserted {
            // The period is at least a millisecond, so the re-arm is always in the future.
            self.timer_table
                .reinsert_periodic(timer, now + timer.period, now);
        }
    }

    /// Cancel `timer`: out of the table, its period and APC dropped, a queued APC taken back out of
    /// its thread's queue. Returns whether the timer was signaled.
    pub(crate) fn cancel_timer(&mut self, timer: &mut Timer) -> bool {
        self.timer_table.remove(timer);
        timer.period = 0;
        if !timer.apc.is_null() {
            self.remove_apc(timer.apc);
            timer.apc = null_mut();
        }
        timer.waitable.signal_state > 0
    }
}

#[cfg(test)]
mod tests {
    use core::ptr::addr_of_mut;

    use super::*;
    use crate::sched::dispatcher::Dispatcher;
    use crate::sched::event::{Event, EventKind, EVENT_WAKE_INCREMENT};
    use crate::sched::process::SchedProcess;
    use crate::sched::thread::{Thread, ThreadState};
    use crate::sched::wait::{
        ClockStamp, WaitDisposition, WaitMode, WaitReason, STATUS_SUCCESS, STATUS_TIMEOUT,
        TIMER_BLOCK,
    };

    const INCREMENT: u64 = crate::interrupt::clock::INTERVAL_100NS as u64;

    // The tick: one increment. `tick(n)` is the interrupt time of tick n's boundary.
    fn tick(n: u64) -> u64 {
        n * INCREMENT
    }

    fn fresh_table() -> &'static mut TimerTable {
        let table = Box::leak(Box::new(TimerTable::zeroed()));
        table.init(INCREMENT);
        table
    }

    fn fresh_timer() -> &'static mut Timer {
        let timer = Box::leak(Box::new(Timer::new()));
        timer.init();
        timer
    }

    /// Walk one bucket head to tail, collecting the dues.
    fn bucket_dues(table: &TimerTable, index: usize) -> Vec<u64> {
        let bucket = &table.buckets[index];
        let sentinel = sentinel_of(bucket);
        let mut dues = Vec::new();
        // SAFETY: the bucket is initialized.
        let mut entry = unsafe { bucket.first() };
        while !entry.is_null() && !eq(entry, sentinel) {
            // SAFETY: the entry is a live timer's links.
            dues.push(unsafe { (*timer_of(entry)).due_time });
            // SAFETY: a linked entry's next names the next entry.
            entry = unsafe { (*entry).next };
        }
        dues
    }

    // --- The wait rig (the wait tests' shape) ---------------------------

    fn dispatcher() -> &'static mut Dispatcher {
        let dispatcher = Box::leak(Box::new(Dispatcher::zeroed()));
        dispatcher.init();
        dispatcher
    }

    fn process(base: i8) -> *mut SchedProcess {
        let process = Box::leak(Box::new(SchedProcess::new(0x0090_0000, base)));
        process.init();
        process
    }

    fn thread(process: *mut SchedProcess) -> &'static mut Thread {
        let thread = Box::leak(Box::new(Thread::empty()));
        // SAFETY: the process is initialized; the thread is at its final address.
        unsafe { thread.attach_to(&mut *process) };
        thread
    }

    fn event(kind: EventKind, signaled: bool) -> &'static mut Event {
        let event = Box::leak(Box::new(Event::new(kind, signaled)));
        event.init();
        event
    }

    fn stamp(system_time: u64, tick_count: u64) -> ClockStamp {
        ClockStamp {
            system_time,
            tick: tick_count,
        }
    }

    fn block_on(
        dispatcher: &mut Dispatcher,
        thread: &mut Thread,
        object: *mut crate::sched::wait::Waitable,
        timeout: Option<i64>,
        at: ClockStamp,
    ) {
        match dispatcher.wait_single(
            thread,
            object,
            WaitReason::UserRequest,
            WaitMode::User,
            false,
            timeout,
            at,
        ) {
            WaitDisposition::Yield => {}
            other => panic!("expected the wait to park, got {other:?}"),
        }
    }

    // --- Group A: the index arithmetic --------------------------------

    /// A1: due = now + interval; bucket = floor(due / increment) & 127 — the tick the due falls
    /// *within* (a due mid-tick m+1 sits in bucket m, which the trigger's tick-pair check catches
    /// at the transition to m+1). A 200 ms sleep from tick 1000 is due 19.97 ticks later: bucket
    /// 1019 & 127 = 123.
    #[test]
    fn the_index_is_the_due_tick_masked() {
        let table = fresh_table();
        let timer = fresh_timer();
        assert!(table.insert(timer, tick(1000) + 2_000_000, tick(1000)));
        assert_eq!(timer.due_time(), tick(1000) + 2_000_000);
        assert!(timer.inserted());
        assert_eq!(bucket_dues(table, 123), vec![tick(1000) + 2_000_000]);
        // Nowhere else: every other bucket is empty.
        for (index, _) in table.buckets.iter().enumerate() {
            if index != 123 {
                assert_eq!(bucket_dues(table, index), Vec::<u64>::new());
            }
        }
        assert_eq!(table.audit(), Ok(()));
    }

    /// A2: a due exactly on a tick multiple lands in that tick's own bucket — caught by the
    /// trigger's second arm.
    #[test]
    fn an_exact_tick_due_lands_in_its_own_bucket() {
        let table = fresh_table();
        let timer = fresh_timer();
        assert!(table.insert(timer, tick(1020), tick(1000)));
        assert_eq!(bucket_dues(table, 1020 & 127), vec![tick(1020)]);
    }

    /// A3: a sub-tick due is bucketed with the current tick and expires at the next tick boundary —
    /// the tick is the resolution floor.
    #[test]
    fn a_sub_tick_due_expires_next_boundary() {
        let table = fresh_table();
        let timer = fresh_timer();
        assert!(table.insert(timer, tick(1000) + 50_000, tick(1000)));
        assert_eq!(bucket_dues(table, 1000 & 127), vec![tick(1000) + 50_000]);
        // Not due at tick 1000's boundary, due at 1001's.
        assert_eq!(table.trigger(tick(1000), 1000), None);
        assert_eq!(table.trigger(tick(1001), 1001), Some(1000));
    }

    /// A4: long timers wrap the mask harmlessly — the table is a cache, never an ordering; the due
    /// comparison gates expiry.
    #[test]
    fn long_timers_wrap_the_mask_and_still_expire_on_time() {
        let dispatcher = dispatcher();
        let early = fresh_timer();
        let late = fresh_timer();
        assert!(dispatcher.timer_table.insert(early, tick(1300), tick(1000)));
        assert!(dispatcher
            .timer_table
            .insert(late, tick(1300) + 5_000, tick(1000)));
        // Both in bucket 1300 & 127 = 20, earliest due first.
        assert_eq!(
            bucket_dues(&dispatcher.timer_table, 20),
            vec![tick(1300), tick(1300) + 5_000]
        );

        // Bucket 20 is visited at every tick congruent to 20 mod 128; the head is not due until
        // tick 1300.
        for n in [1020u32, 1148, 1276].iter() {
            assert_eq!(dispatcher.timer_trigger(tick(*n as u64), *n), None);
        }
        // At the transition to tick 1300 the second arm fires (the exact-multiple head); the walk
        // expires the head only — the tail is not due yet.
        assert_eq!(dispatcher.timer_trigger(tick(1300), 1300), Some(1300));
        dispatcher.expire_timers(tick(1300), 1300, 1300);
        assert!(!early.inserted());
        assert_eq!(early.waitable.signal_state(), 1);
        assert!(late.inserted());
        assert_eq!(
            bucket_dues(&dispatcher.timer_table, 20),
            vec![tick(1300) + 5_000]
        );

        // The tail expires at tick 1301, through the first arm (its bucket is tick 1300's) with
        // argument 1300.
        assert_eq!(dispatcher.timer_trigger(tick(1301), 1301), Some(1300));
        dispatcher.expire_timers(tick(1301), 1301, 1300);
        assert_eq!(late.waitable.signal_state(), 1);
        assert_eq!(dispatcher.timer_table.audit(), Ok(()));
    }

    /// A5: the due-time base. The waits stamp the system-time accumulator; the table indexes by the
    /// same increment the clock advances both accumulators by at the captured rate, so the two
    /// bases coincide numerically. (If the clock's slew ever diverges from its increment, the waits
    /// must stamp interrupt time instead — the base the table reads.)
    #[test]
    fn the_due_base_matches_the_clock_at_the_captured_rate() {
        let mut clock = crate::interrupt::clock::Clock::new();
        clock.set_time_increment(
            crate::interrupt::clock::INTERVAL_100NS,
            crate::interrupt::clock::FINEST_100NS,
        );
        for n in 1..=50u64 {
            assert_eq!(clock.tick(), crate::interrupt::clock::Tick::Full);
            assert_eq!(clock.system_time(), tick(n));
            assert_eq!(clock.interrupt_time(), clock.system_time());
        }
    }

    // --- Group B: insertion order -------------------------------------

    /// B1: a bucket is due-ascending, and equal dues keep insertion order (the search from the back
    /// places the new entry after the first whose due is not later).
    #[test]
    fn buckets_are_due_ordered_and_equals_keep_insertion_order() {
        let table = fresh_table();
        let t1 = fresh_timer();
        let t2 = fresh_timer();
        let t3 = fresh_timer();
        let now = tick(1000);
        assert!(table.insert(t1, now + 50_000, now));
        assert!(table.insert(t2, now + 70_000, now));
        assert!(table.insert(t3, now + 70_000, now));
        assert_eq!(
            bucket_dues(table, 1000 & 127),
            vec![now + 50_000, now + 70_000, now + 70_000]
        );
        assert_eq!(table.audit(), Ok(()));
    }

    /// B2: an insert into an empty bucket is the front insert.
    #[test]
    fn an_empty_bucket_takes_the_front_insert() {
        let table = fresh_table();
        let timer = fresh_timer();
        assert!(table.insert(timer, tick(1000) + 2_000_000, tick(1000)));
        assert_eq!(bucket_dues(table, 123), vec![tick(1000) + 2_000_000]);
        assert_eq!(table.audit(), Ok(()));
    }

    /// B3/B4: a due that is already past is refused at the entry — unsignaled, unheld, unlinked —
    /// whether the bucket is empty or the timer would land mid-list; the wait's already-past arm is
    /// the caller's to take.
    #[test]
    fn a_past_due_is_refused_at_the_entry() {
        let table = fresh_table();
        let base = tick(1000);
        let low = fresh_timer();
        let high = fresh_timer();
        assert!(table.insert(low, base + 50_000, base));
        assert!(table.insert(high, base + 90_000, base));
        // The clock advances to the middle: an insert due exactly now would land between the
        // residents — refused at the entry, unsignaled and unlinked.
        let now = base + 70_000;
        let mid = fresh_timer();
        assert!(!table.insert(mid, base + 70_000, now));
        assert!(!mid.inserted());
        assert_eq!(mid.waitable.signal_state(), 0);
        assert_eq!(
            bucket_dues(table, 1000 & 127),
            vec![base + 50_000, base + 90_000]
        );

        // Due == now on an empty bucket: refused the same way.
        let fresh = fresh_timer();
        assert!(!table.insert(fresh, now, now));
        assert!(!fresh.inserted());
        assert_eq!(table.audit(), Ok(()));
    }

    // --- Group C: the walk ---------------------------------------------

    /// C1: the scan range runs from the argument tick's bucket through the current tick's — the
    /// first bucket scanned is the argument's own. (A due timer behind the argument's bucket was
    /// due when an earlier trigger fired; that trigger's argument is the older one, and its walk
    /// covers it — a delayed walk never widens backwards past its own argument.)
    #[test]
    fn the_walk_scans_from_the_argument_bucket_to_the_current() {
        let dispatcher = dispatcher();
        let in_range = fresh_timer();
        let behind = fresh_timer();
        let now = tick(1002);
        assert!(dispatcher
            .timer_table
            .insert(in_range, tick(1000) + 50_000, tick(1000)));
        assert!(dispatcher
            .timer_table
            .insert(behind, tick(999) + 50_000, tick(999)));
        dispatcher.expire_timers(now, 1002, 1000);
        assert!(!in_range.inserted());
        assert_eq!(in_range.waitable.signal_state(), 1);
        // Behind the argument's bucket: this walk's range is [1000, 1002]; bucket 103 is not in it.
        assert!(behind.inserted());
        assert_eq!(behind.waitable.signal_state(), 0);
        assert_eq!(dispatcher.timer_table.audit(), Ok(()));

        // The older argument covers it.
        dispatcher.expire_timers(now, 1002, 999);
        assert!(!behind.inserted());
    }

    /// C2: a deferred work delayed over a full table round scans every bucket — the window
    /// bookkeeping is void.
    #[test]
    fn a_delayed_walk_scans_the_whole_table() {
        let dispatcher = dispatcher();
        let stale = fresh_timer();
        assert!(dispatcher.timer_table.insert(stale, tick(500), tick(400)));
        // 130 ticks late: over the 128-bucket round.
        dispatcher.expire_timers(tick(1130), 1130, 1000);
        assert!(!stale.inserted());
        assert_eq!(stale.waitable.signal_state(), 1);
    }

    /// C3: a bucket's walk is head-while-due — a not-due head proves nothing behind it is due, and
    /// the bucket is left alone.
    #[test]
    fn the_walk_stops_at_a_not_due_head() {
        let dispatcher = dispatcher();
        let head = fresh_timer();
        let tail = fresh_timer();
        // Both dues fall within tick 1000 — one bucket.
        assert!(dispatcher
            .timer_table
            .insert(head, tick(1000) + 50_000, tick(1000)));
        assert!(dispatcher
            .timer_table
            .insert(tail, tick(1000) + 90_000, tick(1000)));
        // Mid-tick: the head is due, the tail is not.
        dispatcher.expire_timers(tick(1000) + 60_000, 1000, 1000);
        assert!(!head.inserted());
        assert_eq!(head.waitable.signal_state(), 1);
        assert!(tail.inserted());
        assert_eq!(tail.waitable.signal_state(), 0);
        assert_eq!(
            bucket_dues(&dispatcher.timer_table, 1000 & 127),
            vec![tick(1000) + 90_000]
        );
        assert_eq!(dispatcher.timer_table.audit(), Ok(()));
    }

    /// C4: the collection preserves due order across a mask-wrapping range (and C5: a due-later
    /// timer outside the range never expires).
    #[test]
    fn the_collection_wraps_the_mask_in_due_order() {
        let dispatcher = dispatcher();
        // Buckets 127, 1, 3 — inside the range [126, 3] that wraps the mask; bucket 11's timer is
        // outside and due later.
        let a = fresh_timer();
        let b = fresh_timer();
        let c = fresh_timer();
        let outside = fresh_timer();
        assert!(dispatcher.timer_table.insert(a, tick(1151), tick(1000)));
        assert!(dispatcher.timer_table.insert(b, tick(1153), tick(1000)));
        assert!(dispatcher.timer_table.insert(c, tick(1155), tick(1000)));
        assert!(dispatcher
            .timer_table
            .insert(outside, tick(1163), tick(1000)));

        dispatcher.expire_timers(tick(1160), 131, 126);
        for expired in [a, b, c] {
            assert!(!expired.inserted(), "expired");
            assert_eq!(expired.waitable.signal_state(), 1);
        }
        assert!(outside.inserted());
        assert_eq!(outside.waitable.signal_state(), 0);
        assert_eq!(dispatcher.timer_table.audit(), Ok(()));
    }

    /// C6/G2 composed: a thread parked on a delay is woken by the walk in collection order, with
    /// the timeout status its timer block planted, and the delay's resume side converts the timeout
    /// into a successful sleep.
    #[test]
    fn the_walk_wakes_parked_threads_in_due_order() {
        let dispatcher = dispatcher();
        let process = process(8);
        let sleeper_a = thread(process);
        let sleeper_b = thread(process);
        let at = stamp(tick(1000), 1000);
        match dispatcher.delay(sleeper_a, WaitMode::User, false, 2_000_000, at) {
            WaitDisposition::Yield => {}
            other => panic!("expected the delay to park, got {other:?}"),
        }
        match dispatcher.delay(sleeper_b, WaitMode::User, false, 1_000_000, at) {
            WaitDisposition::Yield => {}
            other => panic!("expected the delay to park, got {other:?}"),
        }
        // Both in the table, in their own buckets (20 ticks and 10 ticks out).
        assert!(sleeper_a.timer.inserted());
        assert!(sleeper_b.timer.inserted());
        assert_eq!(dispatcher.timer_table.audit(), Ok(()));

        // The transition to tick 1010: the first arm's bucket (1009 — the tick sleeper_b's due
        // falls within) holds its timer; the argument is that tick.
        assert_eq!(dispatcher.timer_trigger(tick(1010), 1010), Some(1009));
        dispatcher.expire_timers(tick(1010), 1010, 1009);
        assert_eq!(sleeper_b.wait_status(), STATUS_TIMEOUT);
        assert_eq!(
            Dispatcher::delay_completed(sleeper_b.wait_status()),
            STATUS_SUCCESS
        );
        assert_eq!(sleeper_b.state(), ThreadState::Ready);
        assert!(sleeper_a.timer.inserted());

        dispatcher.expire_timers(tick(1020), 1020, 1019);
        assert_eq!(
            Dispatcher::delay_completed(sleeper_a.wait_status()),
            STATUS_SUCCESS
        );
        assert_eq!(sleeper_a.state(), ThreadState::Ready);
    }

    /// C7: the audit catches a corrupted table.
    #[test]
    fn the_audit_rejects_a_signaled_bucket_entry() {
        let table = fresh_table();
        let timer = fresh_timer();
        assert!(table.insert(timer, tick(1000) + 50_000, tick(1000)));
        assert_eq!(table.audit(), Ok(()));
        // A linked timer must not be signaled.
        timer.waitable.signal_state = 1;
        assert_ne!(table.audit(), Ok(()));
    }

    // --- Group D: removal ----------------------------------------------

    /// D1: a cancelled timer leaves its bucket without disturbing the order; D2: the record
    /// re-inserts by its new due.
    #[test]
    fn removal_leaves_order_and_the_record_reuses() {
        let table = fresh_table();
        let t1 = fresh_timer();
        let t2 = fresh_timer();
        let t3 = fresh_timer();
        let now = tick(1000);
        assert!(table.insert(t1, now + 50_000, now));
        assert!(table.insert(t2, now + 70_000, now));
        assert!(table.insert(t3, now + 70_000, now));
        table.remove(t2);
        assert!(!t2.inserted());
        assert_eq!(t2.due_time(), now + 70_000, "the due time stays recorded");
        assert_eq!(
            bucket_dues(table, 1000 & 127),
            vec![now + 50_000, now + 70_000]
        );
        assert_eq!(table.audit(), Ok(()));

        // Re-insert with a later due: lands behind t3.
        assert!(table.insert(t2, now + 90_000, now));
        assert_eq!(
            bucket_dues(table, 1000 & 127),
            vec![now + 50_000, now + 70_000, now + 90_000]
        );
    }

    /// D3/D4 composed: a wake before the expiry cancels the table entry through the wait exit, and
    /// the later walk (and a direct expiry) find nothing to do for the cancelled timer.
    #[test]
    fn a_wake_cancels_the_table_entry_and_the_walk_skips_it() {
        let dispatcher = dispatcher();
        let process = process(8);
        let waiter = thread(process);
        let ev = event(EventKind::Notification, false);
        block_on(
            dispatcher,
            waiter,
            ev.waitable(),
            Some(2_000_000),
            stamp(tick(1000), 1000),
        );
        assert!(waiter.timer.inserted());

        // The signal-side wake: the wait exit cancels the timer.
        ev.set(dispatcher, EVENT_WAKE_INCREMENT);
        assert_eq!(waiter.wait_status(), STATUS_SUCCESS);
        assert!(!waiter.timer.inserted());
        assert_eq!(dispatcher.timer_table.audit(), Ok(()));

        // The walk at and past the would-be due tick: nothing expires for it, and the thread keeps
        // the wake's status.
        dispatcher.expire_timers(tick(1020), 1020, 1019);
        assert_eq!(waiter.wait_status(), STATUS_SUCCESS);
        assert_eq!(waiter.state(), ThreadState::Ready);
        assert_eq!(dispatcher.timer_table.audit(), Ok(()));
    }

    // --- Group F: the trigger -------------------------------------------

    /// F1/F3: the trigger's two arms — the bucket of tick N-1 first (argument N-1), then the bucket
    /// of tick N (argument N); nothing fires before the due is live.
    #[test]
    fn the_trigger_checks_the_tick_pair_in_order() {
        let table = fresh_table();
        let timer = fresh_timer();
        assert!(table.insert(timer, tick(1000) + 2_000_000, tick(1000)));

        // Not due at tick 1019's boundary (the mid-tick-1019 due lives in bucket 1019 & 127 = 123,
        // checked as the (N-1) arm there).
        assert_eq!(table.trigger(tick(1019), 1019), None);
        // At tick 1020's boundary the (N-1) arm finds it due: argument 1019.
        assert_eq!(table.trigger(tick(1020), 1020), Some(1019));

        // An exact-multiple due fires the N arm with the tick's own number as the argument.
        let table2 = fresh_table();
        let exact = fresh_timer();
        assert!(table2.insert(exact, tick(1020), tick(1000)));
        assert_eq!(table2.trigger(tick(1019), 1019), None);
        assert_eq!(table2.trigger(tick(1020), 1020), Some(1020));
    }

    // --- Group G: the thread-timer integration -------------------------

    /// G1: a delay wait parks the thread with its timer in the table — the chain is the timer block
    /// alone, the timer is linked in its bucket, and the idle path owns the processor while it
    /// runs.
    #[test]
    fn a_delay_parks_the_timer_in_the_table() {
        let dispatcher = dispatcher();
        let process = process(8);
        let sleeper = thread(process);
        match dispatcher.delay(
            sleeper,
            WaitMode::User,
            false,
            2_000_000,
            stamp(tick(1000), 1000),
        ) {
            WaitDisposition::Yield => {}
            other => panic!("expected the delay to park, got {other:?}"),
        }
        assert_eq!(sleeper.state(), ThreadState::Waiting);
        assert_eq!(sleeper.wait_reason(), WaitReason::DelayExecution);
        assert!(eq(
            sleeper.wait_block_head,
            addr_of_mut!(sleeper.wait_blocks[TIMER_BLOCK])
        ));
        assert!(sleeper.timer.inserted());
        assert_eq!(
            bucket_dues(&dispatcher.timer_table, 123),
            vec![tick(1000) + 2_000_000]
        );
        assert_eq!(dispatcher.timer_table.audit(), Ok(()));
    }

    /// G4: a timed wait's expiry through the walk returns the raw timeout status, exactly as a
    /// direct expiry does — the wait's two blocks both unwind. (The 10-tick timeout's due falls
    /// within tick 1009: the trigger's (N-1) arm at the transition to tick 1010 carries argument
    /// 1009.)
    #[test]
    fn a_timed_wait_times_out_through_the_walk() {
        let dispatcher = dispatcher();
        let process = process(8);
        let waiter = thread(process);
        let ev = event(EventKind::Notification, false);
        block_on(
            dispatcher,
            waiter,
            ev.waitable(),
            Some(1_000_000),
            stamp(tick(1000), 1000),
        );
        assert_eq!(dispatcher.timer_trigger(tick(1010), 1010), Some(1009));
        dispatcher.expire_timers(tick(1010), 1010, 1009);
        assert_eq!(waiter.wait_status(), STATUS_TIMEOUT);
        assert_eq!(waiter.state(), ThreadState::Ready);
        assert_eq!(ev.signal_state(), 0);
        assert_eq!(dispatcher.timer_table.audit(), Ok(()));
    }

    /// E1's wrap-safety: the longest relative interval (the sleep service's INFINITE arm) parks for
    /// a due time on the far side of the clock — not an immediate timeout.
    #[test]
    fn the_longest_relative_interval_parks_far_in_the_future() {
        let dispatcher = dispatcher();
        let process = process(8);
        let sleeper = thread(process);
        let now = tick(1000);
        // i64::MIN as the relative interval: the due wraps to now's complement, the farthest future
        // a u64 due holds.
        match dispatcher.delay(sleeper, WaitMode::User, false, i64::MIN, stamp(now, 1000)) {
            WaitDisposition::Yield => {}
            other => panic!("expected the delay to park, got {other:?}"),
        }
        assert!(sleeper.timer.inserted());
        assert!(sleeper.timer.due_time() > now);
        // And it never reads as due for any realistic clock value.
        assert_eq!(
            dispatcher.timer_trigger(now.wrapping_add(u32::MAX as u64), u32::MAX),
            None
        );
        assert_eq!(dispatcher.timer_table.audit(), Ok(()));
    }
}
