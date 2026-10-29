//! The deferred procedure call queue.
//!
//! An interrupt service routine can defer work: instead of doing it at the interrupt level it
//! enqueues a DPC — a routine that runs later, at the dispatch level, with interrupts enabled
//! around the call. The discipline:
//!
//!  - single flight: a DPC that is already queued is not re-enqueued, and the first insertion's
//!    arguments stand,
//!  - placement: high-importance DPCs go to the head, the rest to the tail,
//!  - the request gate: an enqueue asks for a dispatch interrupt only when no routine is active,
//!    none was already requested, and the importance/depth/rate table says a request is warranted,
//!  - retirement drains in order, clears the inserted state *before* the call (so a routine may
//!    re-enqueue itself), and clears the active/requested flags only once the queue empties.
//!
//! The queue is high-level state: interrupt service routines insert into it, so it is touched only
//! with every interrupt masked, through the processor control region's cell
//! ([`crate::pcr::Pcr::dpc_queue`]). Retirement detaches each entry inside that borrow, ends the
//! borrow, and calls the routine at the dispatch level with the dispatch token. The queue's depth
//! is published beside the cell as each borrow ends, for the readers that hold no token: the
//! interrupt exit's test for work and the idle loop's (Windows 2000 reads DpcQueueDepth unlocked
//! the same way).
//!
//! A DPC is an intrusive list member: the queue links through the Dpc itself, so nothing is
//! allocated and the same object can be re-enqueued for its whole life. The links are `Cell`s of
//! `&'static Dpc`, so a DPC is shared (`&'static`) from the moment it can be queued, and the list
//! surgery needs no pointers.

use core::cell::Cell;
use core::sync::atomic::{AtomicBool, AtomicI32, Ordering};

use crate::level::{Above, At, Dispatch, High, Level, LevelCell};
use crate::pcr::pcr;

/// A deferred routine: `(dispatch, dpc, context, argument1, argument2)`. It runs at the dispatch
/// level, handed that level's token; the arguments are the ones stored at insertion time.
pub type DpcRoutine = fn(&mut At<Dispatch>, &Dpc, usize, usize, usize);

/// How urgently a DPC wants to run.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Importance {
    /// Below the depth/rate thresholds: requested only when the queue is deep enough or the
    /// request rate low enough.
    Low,
    /// Requested as soon as the queue is idle (the default).
    Medium,
    /// Placed at the head and requested immediately.
    High,
}

/// A deferred procedure call.
pub struct Dpc {
    routine: DpcRoutine,
    context: usize,
    importance: Importance,
    /// The neighbours on the queue, while queued.
    next: Cell<Option<&'static Dpc>>,
    prev: Cell<Option<&'static Dpc>>,
    argument1: Cell<usize>,
    argument2: Cell<usize>,
    /// Single-flight mark: set at insertion, cleared before the call (or on removal). A second
    /// insert of a queued DPC is a no-op.
    queued: AtomicBool,
}

// SAFETY: one processor. The `Cell`s are read and written only by `DpcQueue`'s methods, which run
// inside the high-level borrow of the queue (interrupts masked), on the one queue the DPC is on
// (the `queued` flag keeps it on at most one): no two executions touch them at once. The routine,
// context and importance never change after construction.
unsafe impl Sync for Dpc {}

impl Dpc {
    /// A DPC that will call `routine` with `context`, at medium importance, not queued.
    pub const fn new(routine: DpcRoutine, context: usize) -> Self {
        Self {
            routine,
            context,
            importance: Importance::Medium,
            next: Cell::new(None),
            prev: Cell::new(None),
            argument1: Cell::new(0),
            argument2: Cell::new(0),
            queued: AtomicBool::new(false),
        }
    }

    /// The same DPC at another importance.
    pub const fn with_importance(self, importance: Importance) -> Self {
        Self { importance, ..self }
    }

    /// Whether the DPC is queued now.
    pub fn is_queued(&self) -> bool {
        self.queued.load(Ordering::SeqCst)
    }
}

/// The DPC queue: one processor's deferred work.
pub struct DpcQueue {
    /// The first and last queued DPCs.
    head: Option<&'static Dpc>,
    tail: Option<&'static Dpc>,
    /// Queued DPCs.
    depth: i32,
    /// DPCs enqueued since boot (feeds the request-rate average).
    count: i32,
    last_count: i32,
    request_rate: i32,
    /// The request-gate thresholds: a Low-importance DPC is requested only once the queue is at
    /// least this deep...
    max_depth: i32,
    /// ...or the recent request rate has fallen under this.
    min_rate: i32,
    /// A retire pass is running (blocks new dispatch requests).
    routine_active: bool,
    /// A dispatch interrupt has been requested and not yet consumed.
    interrupt_requested: bool,
    /// How many times the request gate has fired.
    dispatch_requests: u32,
}

/// A detached DPC's call, captured inside the queue's borrow and made outside it.
struct Call {
    dpc: &'static Dpc,
    argument1: usize,
    argument2: usize,
}

impl Call {
    /// Run the routine at the dispatch level.
    fn run(self, dispatch: &mut At<Dispatch>) {
        let dpc = self.dpc;
        (dpc.routine)(dispatch, dpc, dpc.context, self.argument1, self.argument2);
    }
}

impl DpcQueue {
    /// An empty queue with the given request-gate thresholds.
    pub const fn new(max_depth: i32, min_rate: i32) -> Self {
        Self {
            head: None,
            tail: None,
            depth: 0,
            count: 0,
            last_count: 0,
            request_rate: 0,
            max_depth,
            min_rate,
            routine_active: false,
            interrupt_requested: false,
            dispatch_requests: 0,
        }
    }

    /// Whether any DPC is queued.
    pub fn is_empty(&self) -> bool {
        self.head.is_none()
    }

    /// The number of queued DPCs.
    pub fn depth(&self) -> i32 {
        self.depth
    }

    /// Whether a dispatch interrupt is requested and unconsumed.
    pub fn interrupt_requested(&self) -> bool {
        self.interrupt_requested
    }

    /// Whether a retire pass is running.
    pub fn routine_active(&self) -> bool {
        self.routine_active
    }

    /// How many times the request gate has fired.
    pub fn dispatch_requests(&self) -> u32 {
        self.dispatch_requests
    }

    /// The recent deferred-work request rate (the folded history).
    pub fn request_rate(&self) -> i32 {
        self.request_rate
    }

    /// Enqueue `dpc` with the given arguments. Returns whether it was queued: an already-queued DPC
    /// is left alone (its first insertion's arguments stand).
    pub fn insert(&mut self, dpc: &'static Dpc, argument1: usize, argument2: usize) -> bool {
        if dpc.queued.swap(true, Ordering::SeqCst) {
            // Already queued: no operation performed.
            return false;
        }
        // Freshly claimed: store the arguments, link, and ask for a dispatch interrupt if the gate
        // is open.
        self.count = self.count.wrapping_add(1);
        self.depth += 1;
        dpc.argument1.set(argument1);
        dpc.argument2.set(argument2);
        if dpc.importance == Importance::High {
            self.link_head(dpc);
        } else {
            self.link_tail(dpc);
        }
        if !self.routine_active && !self.interrupt_requested {
            let warranted = dpc.importance != Importance::Low
                || self.depth >= self.max_depth
                || self.request_rate < self.min_rate;
            if warranted {
                self.interrupt_requested = true;
                self.dispatch_requests = self.dispatch_requests.wrapping_add(1);
            }
        }
        true
    }

    /// Dequeue `dpc` if it is queued (on this queue). Returns whether it was.
    pub fn remove(&mut self, dpc: &Dpc) -> bool {
        if !dpc.queued.load(Ordering::SeqCst) {
            return false;
        }
        self.depth -= 1;
        self.unlink(dpc);
        dpc.queued.store(false, Ordering::SeqCst);
        true
    }

    /// Fold the enqueue-count history into the request-rate average. Called by the interval clock's
    /// full-tick accounting.
    pub fn update_request_rate(&mut self) {
        let current = self.count;
        let last = self.last_count;
        self.last_count = current;
        self.request_rate = current.wrapping_sub(last).wrapping_add(self.request_rate) >> 1;
    }

    /// Start a retire pass: whether there is work and no pass is running already (then this one is
    /// marked running).
    fn begin_retire(&mut self) -> bool {
        if self.is_empty() || self.routine_active {
            return false;
        }
        self.routine_active = true;
        true
    }

    /// Detach the head and capture its call, or end the pass when the queue is empty.
    fn next_call(&mut self) -> Option<Call> {
        let Some(dpc) = self.head else {
            // Only now, with the list empty, clear the drain state. The queue is borrowed with
            // every interrupt masked, so no enqueue can land between the test and the clear.
            self.routine_active = false;
            self.interrupt_requested = false;
            return None;
        };
        self.unlink(dpc);
        // Clear the inserted state BEFORE the call, so the routine may re-enqueue this very DPC.
        dpc.queued.store(false, Ordering::SeqCst);
        self.depth -= 1;
        Some(Call {
            dpc,
            argument1: dpc.argument1.get(),
            argument2: dpc.argument2.get(),
        })
    }

    // --- The intrusive list -----------------------------------------------------------------
    //
    // A doubly-linked list through the DPCs' own links, with the queue holding both ends: removal
    // of an arbitrary DPC and head/tail insertion are constant time with no allocation.

    /// Link `dpc`, which is on no list, at the head.
    fn link_head(&mut self, dpc: &'static Dpc) {
        dpc.prev.set(None);
        dpc.next.set(self.head);
        match self.head {
            Some(head) => head.prev.set(Some(dpc)),
            None => self.tail = Some(dpc),
        }
        self.head = Some(dpc);
    }

    /// Link `dpc`, which is on no list, at the tail.
    fn link_tail(&mut self, dpc: &'static Dpc) {
        dpc.next.set(None);
        dpc.prev.set(self.tail);
        match self.tail {
            Some(tail) => tail.next.set(Some(dpc)),
            None => self.head = Some(dpc),
        }
        self.tail = Some(dpc);
    }

    /// Unlink `dpc`, which is on this list.
    fn unlink(&mut self, dpc: &Dpc) {
        let (prev, next) = (dpc.prev.take(), dpc.next.take());
        match prev {
            Some(prev) => prev.next.set(next),
            None => self.head = next,
        }
        match next {
            Some(next) => next.prev.set(prev),
            None => self.tail = prev,
        }
    }
}

/// A processor's DPC queue as its control region holds it: the queue, a high-level cell, and its
/// depth published for readers that hold no token (KPRCB's DpcListHead and DpcQueueDepth).
pub struct ProcessorQueue {
    queue: LevelCell<High, DpcQueue>,
    /// The queue's depth as the last borrow left it. Written only inside a borrow (with every
    /// interrupt masked), read anywhere: a reader that sees work which a nested interrupt's drain
    /// has since retired only raises for nothing, and an insert publishes before the interrupt
    /// that made it can exit.
    depth: AtomicI32,
}

impl ProcessorQueue {
    /// An empty queue with the given request-gate thresholds.
    pub const fn new(max_depth: i32, min_rate: i32) -> Self {
        ProcessorQueue {
            queue: LevelCell::new(DpcQueue::new(max_depth, min_rate)),
            depth: AtomicI32::new(0),
        }
    }

    /// Run `f` on the queue, for as long as the high token is lent; the depth it leaves is
    /// published as the borrow ends.
    pub fn with<R>(&self, high: &mut At<High>, f: impl FnOnce(&mut DpcQueue) -> R) -> R {
        let queue = self.queue.get(high);
        let result = f(queue);
        self.depth.store(queue.depth(), Ordering::SeqCst);
        result
    }

    /// Whether the published depth shows work: the test a retirement entry makes before it raises,
    /// with no token and nothing masked.
    pub fn has_pending(&self) -> bool {
        self.depth.load(Ordering::SeqCst) != 0
    }
}

/// Run every DPC on `queue`, at the dispatch level (Windows 2000's KiRetireDpcList). Each entry is
/// detached inside a high-level borrow of the queue; the borrow ends, and the routine runs with
/// interrupts enabled and the dispatch token.
pub fn retire(queue: &ProcessorQueue, dispatch: &mut At<Dispatch>) {
    // The caller's test for work ran with interrupts possibly enabled: a nested interrupt's exit
    // may have drained the queue since. Test again, masked, before the pass starts.
    if !queue.with(&mut dispatch.raise::<High>(), DpcQueue::begin_retire) {
        return;
    }
    loop {
        let next = queue.with(&mut dispatch.raise::<High>(), DpcQueue::next_call);
        let Some(call) = next else {
            return;
        };
        call.run(dispatch);
    }
}

/// Enqueue a DPC on the processor's queue (see [`DpcQueue::insert`]), from code that holds a level
/// token: raised to the high level for the insert.
pub fn enqueue_at<L: Level>(
    at: &mut At<L>,
    dpc: &'static Dpc,
    argument1: usize,
    argument2: usize,
) -> bool
where
    High: Above<L>,
{
    pcr().dpc_queue.with(&mut at.raise::<High>(), |queue| {
        queue.insert(dpc, argument1, argument2)
    })
}

/// Drain the processor's queue at the dispatch level: the shared body of the retirement entries —
/// the hardware-interrupt exit, the idle loop, and a lower below the dispatch level.
///
/// The drain refuses to run at or above the dispatch level, the same guarantee NT draws from its
/// dispatch software interrupt, which cannot fire until the level drops below it. Raising to the
/// dispatch level leaves the clock unmasked: a tick there could land inside dispatcher code (a
/// park's selection, a switch's install) or inside a running routine, and a drain at that point
/// would run timer expiry on top of the half-done ready-queue work. Refused work stays queued for
/// the next entry that finds the level lower: the outer retire pass (which loops until the queue
/// is empty), or the lower that leaves the dispatch level.
///
/// An empty queue costs one read of the published depth: no raise, nothing masked.
pub fn drain() {
    let queue = &pcr().dpc_queue;
    if !queue.has_pending() {
        return;
    }
    let _ = crate::level::dispatch_entry(|dispatch| retire(queue, dispatch));
}

/// Whether the processor's queue has work pending, by its published depth (the idle loop's test).
pub fn has_pending() -> bool {
    pcr().dpc_queue.has_pending()
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;
    use crate::interrupt::irql;
    use crate::level::raised;

    /// A queue of the test's own, with the given request-gate thresholds.
    fn queue(max_depth: i32, min_rate: i32) -> &'static ProcessorQueue {
        Box::leak(Box::new(ProcessorQueue::new(max_depth, min_rate)))
    }

    /// Insert through the bridge, as code without a token would.
    fn insert(queue: &ProcessorQueue, dpc: &'static Dpc, argument1: usize) -> bool {
        raised::<High, _>(|high| queue.with(high, |queue| queue.insert(dpc, argument1, 0)))
    }

    /// Read the queue through the bridge.
    fn inspect<R>(queue: &ProcessorQueue, read: impl FnOnce(&mut DpcQueue) -> R) -> R {
        raised::<High, _>(|high| queue.with(high, read))
    }

    /// Run a retire pass from the passive level, as the drain does.
    fn retire_from_passive(queue: &ProcessorQueue) {
        raised::<Dispatch, _>(|dispatch| retire(queue, dispatch));
    }

    /// One call as a routine saw it.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    struct Seen {
        argument1: usize,
        still_queued: bool,
        interrupts_enabled: bool,
        routine_active: bool,
        level: irql::Irql,
    }

    // The routines reach the test's log and queue through these: a routine's only inputs are its
    // token, its DPC and its words.
    thread_local! {
        static LOG: RefCell<Vec<Seen>> = const { RefCell::new(Vec::new()) };
        static QUEUE: Cell<Option<&'static ProcessorQueue>> = const { Cell::new(None) };
    }

    /// The recording routine: logs what it sees, the queue's routine-active flag read the way a
    /// routine reaches high-level state, by raising.
    fn record(dispatch: &mut At<Dispatch>, dpc: &Dpc, _context: usize, argument1: usize, _: usize) {
        let level = pcr().current();
        let interrupts_enabled = pcr().interrupts_enabled();
        let routine_active = QUEUE.with(Cell::get).map_or(false, |queue| {
            queue.with(&mut dispatch.raise::<High>(), |queue| {
                queue.routine_active()
            })
        });
        LOG.with(|log| {
            log.borrow_mut().push(Seen {
                argument1,
                still_queued: dpc.is_queued(),
                interrupts_enabled,
                routine_active,
                level,
            })
        });
    }

    fn calls() -> Vec<Seen> {
        LOG.with(|log| log.take())
    }

    fn recording_dpc() -> &'static Dpc {
        Box::leak(Box::new(Dpc::new(record, 0)))
    }

    fn recording_dpc_at(importance: Importance) -> &'static Dpc {
        Box::leak(Box::new(Dpc::new(record, 0).with_importance(importance)))
    }

    /// A queue the routines can reach, bound for the test.
    fn bound_queue(max_depth: i32, min_rate: i32) -> &'static ProcessorQueue {
        let queue = queue(max_depth, min_rate);
        QUEUE.with(|bound| bound.set(Some(queue)));
        queue
    }

    /// A fresh DPC carries the routine and context, defaults to medium importance, and is not
    /// queued.
    #[test]
    fn fresh_dpc_defaults() {
        let dpc = recording_dpc();
        assert_eq!(dpc.importance, Importance::Medium);
        assert!(!dpc.is_queued());
        assert_eq!(dpc.argument1.get(), 0);
        assert_eq!(dpc.argument2.get(), 0);
    }

    /// A fresh insert queues, stores the arguments, bumps the depth, keeps FIFO order, and puts a
    /// High-importance DPC at the head.
    #[test]
    fn fresh_inserts_store_arguments_and_order() {
        let queue = bound_queue(4, 0);
        assert!(insert(queue, recording_dpc(), 10));
        assert!(insert(queue, recording_dpc(), 20));
        assert!(insert(queue, recording_dpc_at(Importance::High), 30));
        assert_eq!(inspect(queue, |q| q.depth()), 3);

        retire_from_passive(queue);

        // High importance ran first; the rest in FIFO order, each with its insertion-time
        // arguments, in true call order.
        let order: Vec<usize> = calls().iter().map(|seen| seen.argument1).collect();
        assert_eq!(order, vec![30, 10, 20]);
        assert!(inspect(queue, |q| q.is_empty() && q.depth() == 0));
    }

    /// Re-inserting a queued DPC is a no-op: the second insert returns false and the first
    /// insertion's arguments stand.
    #[test]
    fn reinserting_a_queued_dpc_is_a_no_op() {
        let queue = bound_queue(4, 0);
        let dpc = recording_dpc();
        assert!(insert(queue, dpc, 10));
        assert!(!insert(queue, dpc, 20));
        assert_eq!(inspect(queue, |q| q.depth()), 1);

        retire_from_passive(queue);
        let seen = calls();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].argument1, 10);
    }

    /// Remove dequeues a queued DPC (and reports it), from the head, the middle or the tail;
    /// removing an idle one reports false; a double remove reports false the second time.
    #[test]
    fn remove_returns_whether_the_dpc_was_queued() {
        let queue = bound_queue(4, 0);
        let [first, middle, last] = [recording_dpc(), recording_dpc(), recording_dpc()];

        assert!(!inspect(queue, |q| q.remove(middle))); // idle

        assert!(insert(queue, first, 1));
        assert!(insert(queue, middle, 2));
        assert!(insert(queue, last, 3));
        assert!(inspect(queue, |q| q.remove(middle)));
        assert!(!inspect(queue, |q| q.remove(middle))); // already removed
        assert!(inspect(queue, |q| q.remove(last)));
        assert_eq!(inspect(queue, |q| q.depth()), 1);

        retire_from_passive(queue);
        // Only the survivor ran.
        let order: Vec<usize> = calls().iter().map(|seen| seen.argument1).collect();
        assert_eq!(order, vec![1]);

        // The list mended itself each time: the head alone is left, and goes too.
        assert!(insert(queue, first, 4));
        assert!(inspect(queue, |q| q.remove(first)));
        assert!(inspect(queue, |q| q.is_empty() && q.tail.is_none()));
    }

    /// The dispatch-request gate, as a decision table: nothing is requested while a routine is
    /// active or a request is already outstanding; otherwise a Medium/High DPC (or a Low one past
    /// the depth threshold) requests.
    #[test]
    fn the_request_gate_decision_table() {
        // Routine active: no request, even for High importance.
        let active = queue(4, 0);
        inspect(active, |q| q.routine_active = true);
        assert!(insert(active, recording_dpc_at(Importance::High), 0));
        assert!(!inspect(active, |q| q.interrupt_requested()));

        // Clear, Medium importance: requested.
        let medium = queue(4, 0);
        assert!(insert(medium, recording_dpc(), 0));
        assert!(inspect(medium, |q| q.interrupt_requested()));
        assert_eq!(inspect(medium, |q| q.dispatch_requests()), 1);

        // Clear, High importance: requested.
        let high = queue(4, 0);
        assert!(insert(high, recording_dpc_at(Importance::High), 0));
        assert!(inspect(high, |q| q.interrupt_requested()));

        // Clear, Low importance, depth under the threshold and rate at the floor: not requested...
        let low = queue(4, 0);
        assert!(insert(low, recording_dpc_at(Importance::Low), 0));
        assert!(!inspect(low, |q| q.interrupt_requested()));

        // ...but requested once the depth reaches the threshold.
        let deep = queue(3, 0);
        for _ in 0..2 {
            assert!(insert(deep, recording_dpc_at(Importance::Low), 0));
            assert!(!inspect(deep, |q| q.interrupt_requested()));
        }
        assert!(insert(deep, recording_dpc_at(Importance::Low), 0));
        assert!(inspect(deep, |q| q.interrupt_requested()));

        // A request already outstanding: no second request.
        let outstanding = queue(4, 0);
        assert!(insert(outstanding, recording_dpc(), 0));
        assert!(insert(outstanding, recording_dpc(), 0));
        assert_eq!(inspect(outstanding, |q| q.dispatch_requests()), 1);

        // Rate-driven: a Low DPC requests once the recent rate has fallen under the floor.
        let slow = queue(4, 1);
        inspect(slow, |q| q.request_rate = 0);
        assert!(insert(slow, recording_dpc_at(Importance::Low), 0));
        assert!(inspect(slow, |q| q.interrupt_requested()));
    }

    /// Retire discipline: the inserted state is cleared before the call, the routine runs at the
    /// dispatch level with interrupts enabled, the routine-active flag is set for the whole pass
    /// and cleared only when the queue empties.
    #[test]
    fn retire_clears_state_before_the_call_and_enables_interrupts() {
        let queue = bound_queue(4, 0);
        assert!(insert(queue, recording_dpc(), 0));
        retire_from_passive(queue);

        let seen = calls();
        assert_eq!(seen.len(), 1);
        assert!(
            !seen[0].still_queued,
            "inserted state must be cleared before the call"
        );
        assert!(
            seen[0].interrupts_enabled,
            "interrupts must be enabled around the routine"
        );
        assert!(
            seen[0].routine_active,
            "routine-active must be set during the pass"
        );
        assert_eq!(
            seen[0].level,
            irql::DISPATCH,
            "the routine runs at dispatch"
        );
        assert!(!inspect(queue, |q| q.routine_active() || q.interrupt_requested()));
        assert_eq!(pcr().current(), irql::PASSIVE);
        assert_eq!(pcr().audit(), Ok(()));
    }

    /// The race-close invariant: a DPC enqueued from inside a retire routine (while the queue
    /// "looked" empty) is not lost — the same retire pass drains it.
    #[test]
    fn a_mid_retire_enqueue_is_not_lost() {
        let queue = bound_queue(4, 0);
        assert!(insert(queue, Box::leak(Box::new(Dpc::new(chained, 0))), 0));

        retire_from_passive(queue);

        // The first routine enqueued the follow-up while the queue was otherwise empty; the same
        // pass must have drained it.
        let seen = calls();
        assert_eq!(seen.len(), 1, "the mid-drain enqueue must not be lost");
        assert_eq!(seen[0].argument1, 7, "the follow-up ran with its arguments");
        assert!(inspect(queue, |q| q.is_empty() && !q.routine_active()));
    }

    /// The chained routine: enqueues the follow-up DPC, raised from its own token as a routine
    /// does, and checks that the active flag blocks a new dispatch request mid-drain.
    fn chained(dispatch: &mut At<Dispatch>, _dpc: &Dpc, _context: usize, _: usize, _: usize) {
        let queue = QUEUE.with(Cell::get).unwrap();
        let follow = recording_dpc_at(Importance::Low);
        queue.with(&mut dispatch.raise::<High>(), |queue| {
            assert!(queue.insert(follow, 7, 0));
            // Mid-drain: no NEW dispatch request is issued (the first DPC's request is still
            // outstanding, which is exactly why the gate stays closed).
            assert_eq!(queue.dispatch_requests(), 1);
        });
    }

    /// Both retirement entries drain without double-draining: after the first drain the queue is
    /// empty and the second entry is a no-op.
    #[test]
    fn both_retirement_entries_drain_once() {
        let queue = bound_queue(4, 0);
        assert!(insert(queue, recording_dpc(), 0));

        // Entry one (the interrupt-exit drain shape).
        retire_from_passive(queue);
        assert_eq!(calls().len(), 1);

        // Entry two (the idle-loop window): empty, nothing runs.
        retire_from_passive(queue);
        assert!(calls().is_empty());
    }

    /// The processor's own queue, through the kernel's entries: an enqueue with a token at the
    /// dispatch level waits there — the drain refuses at or above the dispatch level — and runs
    /// at the lower that leaves it, as Windows 2000's KeLowerIrql runs the DISPATCH software
    /// interrupt.
    #[test]
    fn the_processors_queue_drains_at_the_lower_below_dispatch() {
        QUEUE.with(|bound| bound.set(Some(&pcr().dpc_queue)));
        assert!(!has_pending());
        raised::<Dispatch, _>(|dispatch| {
            assert!(enqueue_at(dispatch, recording_dpc(), 5, 0));
            assert!(has_pending());
            drain();
            assert!(has_pending(), "refused at the dispatch level");
            assert!(calls().is_empty());
        });

        assert!(!has_pending(), "the lower drained it");
        let seen = calls();
        assert_eq!(seen.len(), 1);
        assert_eq!((seen[0].argument1, seen[0].level), (5, irql::DISPATCH));
        assert!(seen[0].interrupts_enabled);
        assert_eq!(pcr().current(), irql::PASSIVE);
        assert_eq!(pcr().audit(), Ok(()));
    }

    /// A lower to a masked level drains what is queued too, its routines run enabled at the
    /// dispatch level, and leaves the level masked as its raise found it: a masked service stays
    /// masked across its dispatch-level work.
    #[test]
    fn a_masked_lower_drains_and_stays_masked() {
        QUEUE.with(|bound| bound.set(Some(&pcr().dpc_queue)));
        pcr().mask_interrupts();
        raised::<Dispatch, _>(|dispatch| {
            assert!(
                pcr().interrupts_enabled(),
                "the dispatch level runs enabled"
            );
            assert!(enqueue_at(dispatch, recording_dpc(), 6, 0));
        });
        assert!(!has_pending(), "the lower drained it");
        assert!(
            !pcr().interrupts_enabled(),
            "masked again, as the raise found it"
        );
        let seen = calls();
        assert_eq!((seen.len(), seen[0].argument1), (1, 6));
        assert!(seen[0].interrupts_enabled);
        pcr().unmask_interrupts();
        assert_eq!(pcr().audit(), Ok(()));
    }

    /// A lower that does not leave the dispatch level runs nothing: a raise from the dispatch level
    /// to the high one and back keeps the queue for the dispatch level's own lower.
    #[test]
    fn a_lower_within_the_dispatch_level_drains_nothing() {
        QUEUE.with(|bound| bound.set(Some(&pcr().dpc_queue)));
        raised::<Dispatch, _>(|dispatch| {
            assert!(enqueue_at(dispatch, recording_dpc(), 7, 0));
            {
                let _high = dispatch.raise::<High>();
            }
            assert!(has_pending(), "still queued at the dispatch level");
            assert!(calls().is_empty());
        });
        assert_eq!(calls().len(), 1);
    }

    /// The published depth follows every borrow: an insert publishes it, a retire pass publishes
    /// the emptied queue, and a removal publishes what is left.
    #[test]
    fn the_depth_is_published_as_each_borrow_ends() {
        let queue = bound_queue(4, 0);
        assert!(!queue.has_pending());
        let (first, second) = (recording_dpc(), recording_dpc());
        assert!(insert(queue, first, 1));
        assert!(insert(queue, second, 2));
        assert!(queue.has_pending());
        assert!(inspect(queue, |q| q.remove(first)));
        assert!(queue.has_pending(), "one left");
        retire_from_passive(queue);
        assert!(!queue.has_pending());
        assert_eq!(calls().len(), 1);
    }

    /// The request-rate average folds the enqueue-count history.
    #[test]
    fn request_rate_folds_the_count_history() {
        let mut queue = DpcQueue::new(4, 0);
        assert_eq!(queue.request_rate, 0);
        queue.count = 4;
        queue.update_request_rate(); // (4-0+0)>>1 = 2
        assert_eq!(queue.request_rate, 2);
        queue.count = 6;
        queue.update_request_rate(); // (6-4+2)>>1 = 2
        assert_eq!(queue.request_rate, 2);
        queue.count = 10;
        queue.update_request_rate(); // (10-6+2)>>1 = 3
        assert_eq!(queue.request_rate, 3);
    }
}
