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
//!    re-enqueue itself), and clears the active/requested flags only once the queue empties — then
//!    re-checks once more to close the race with an enqueue that arrived mid-drain.
//!
//! A DPC is an intrusive list member: the queue links through the Dpc itself, so nothing is
//! allocated and the same object can be re-enqueued for its whole life.

use core::ptr::{addr_of, addr_of_mut, null_mut};
use core::sync::atomic::{AtomicBool, Ordering};

use crate::interrupt::irql::{IrqlState, HIGH};

/// A deferred routine: `(dpc, context, argument1, argument2)`. The arguments are the ones stored at
/// insertion time.
pub type DpcRoutine = fn(&Dpc, usize, usize, usize);

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

/// Intrusive list links, shared by every queued DPC and the queue's own sentinel.
struct Links {
    next: *mut Links,
    prev: *mut Links,
}

/// A deferred procedure call.
pub struct Dpc {
    routine: DpcRoutine,
    context: usize,
    importance: Importance,
    /// Queue links. Valid while queued (and briefly during the detach step of retirement).
    links: Links,
    argument1: usize,
    argument2: usize,
    /// Single-flight mark: set at insertion, cleared before the call (or on removal). A second
    /// insert of a queued DPC is a no-op.
    queued: AtomicBool,
}

impl Dpc {
    /// A DPC that will call `routine` with `context`, at medium importance, not queued.
    pub const fn new(routine: DpcRoutine, context: usize) -> Self {
        Self {
            routine,
            context,
            importance: Importance::Medium,
            links: Links {
                next: null_mut(),
                prev: null_mut(),
            },
            argument1: 0,
            argument2: 0,
            queued: AtomicBool::new(false),
        }
    }

    /// Raise or lower this DPC's importance.
    pub fn set_importance(&mut self, importance: Importance) {
        self.importance = importance;
    }
}

/// The DPC queue: one processor's deferred work.
pub struct DpcQueue {
    /// Sentinel: an empty queue's head links to itself.
    head: Links,
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

impl DpcQueue {
    /// A zeroed queue; call [`DpcQueue::init`] before use.
    pub const fn zeroed() -> Self {
        Self {
            head: Links {
                next: null_mut(),
                prev: null_mut(),
            },
            depth: 0,
            count: 0,
            last_count: 0,
            request_rate: 0,
            max_depth: 0,
            min_rate: 0,
            routine_active: false,
            interrupt_requested: false,
            dispatch_requests: 0,
        }
    }

    /// Close the sentinel and set the request-gate thresholds.
    pub fn init(&mut self, max_depth: i32, min_rate: i32) {
        self.head.next = addr_of_mut!(self.head);
        self.head.prev = addr_of_mut!(self.head);
        self.max_depth = max_depth;
        self.min_rate = min_rate;
    }

    /// Whether any DPC is queued.
    pub fn is_empty(&self) -> bool {
        self.head.next == addr_of!(self.head) as *mut Links
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
    pub fn insert(
        &mut self,
        dpc: &mut Dpc,
        argument1: usize,
        argument2: usize,
        irql: &mut IrqlState,
    ) -> bool {
        let previous = irql.raise(HIGH);
        let was_queued = dpc.queued.swap(true, Ordering::SeqCst);
        let inserted = if !was_queued {
            // Freshly claimed: store the arguments, link, and ask for a dispatch interrupt if the
            // gate is open.
            self.count = self.count.wrapping_add(1);
            self.depth += 1;
            dpc.argument1 = argument1;
            dpc.argument2 = argument2;
            // SAFETY: the sentinel is linked and the DPC is on no list (the flag just moved to
            // true).
            unsafe {
                if dpc.importance == Importance::High {
                    link_after(addr_of_mut!(self.head), dpc);
                } else {
                    link_before(addr_of_mut!(self.head), dpc);
                }
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
        } else {
            // Already queued: no operation performed.
            false
        };
        irql.lower(previous);
        inserted
    }

    /// Dequeue `dpc` if it is queued. Returns whether it was.
    pub fn remove(&mut self, dpc: &Dpc, irql: &mut IrqlState) -> bool {
        let interrupts_were = irql.interrupts_enabled();
        irql.mask_interrupts();
        let was_queued = dpc.queued.load(Ordering::SeqCst);
        if was_queued {
            // The reference re-checks under its lock: the DPC may have been retired between the
            // first read and here.
            if dpc.queued.load(Ordering::SeqCst) {
                self.depth -= 1;
                // SAFETY: the DPC is on this queue's list.
                unsafe { unlink(dpc) };
                dpc.queued.store(false, Ordering::SeqCst);
            }
        }
        if interrupts_were {
            irql.unmask_interrupts();
        }
        was_queued
    }

    /// Run every queued DPC. Contract: interrupts masked on entry, masked on return; interrupts are
    /// enabled around each routine. The caller holds the dispatch level.
    pub fn retire(&mut self, irql: &mut IrqlState) {
        loop {
            self.routine_active = true;

            // Detach the head and capture its call before clearing the inserted state.
            // SAFETY: the list is non-empty (callers check) and the sentinel is linked.
            let dpc: &Dpc = unsafe { &*detach_head(self) };
            let routine = dpc.routine;
            let (context, argument1, argument2) = (dpc.context, dpc.argument1, dpc.argument2);

            // Clear the inserted state BEFORE the call, so the routine may re-enqueue this very
            // DPC.
            dpc.queued.store(false, Ordering::SeqCst);
            self.depth -= 1;

            irql.unmask_interrupts();
            routine(dpc, context, argument1, argument2);
            irql.mask_interrupts();

            if !self.is_empty() {
                continue;
            }

            // Only now, with the list empty, clear the drain state — and check one last time: an
            // enqueue that arrived while the last routine was running must not be left behind.
            self.routine_active = false;
            self.interrupt_requested = false;
            if !self.is_empty() {
                continue;
            }
            return;
        }
    }

    /// Fold the enqueue-count history into the request-rate average. Called by the interval clock's
    /// full-tick accounting.
    pub fn update_request_rate(&mut self) {
        let current = self.count;
        let last = self.last_count;
        self.last_count = current;
        self.request_rate = current.wrapping_sub(last).wrapping_add(self.request_rate) >> 1;
    }
}

// --- The intrusive list ---------------------------------------------------
//
// Plain pointer surgery on the Dpc links: the queue's sentinel and the DPCs form a circular
// doubly-linked list, which is what makes removal of an arbitrary DPC (and head/tail insertion)
// constant time with no allocation.

/// `Dpc`'s links member, as a link pointer.
fn links_of(dpc: *const Dpc) -> *mut Links {
    // SAFETY: every caller passes a reference to a live `Dpc` (coerced to the pointer), and
    // `addr_of!` takes the member's address without reading it.
    unsafe { core::ptr::addr_of!((*dpc).links) as *mut Links }
}

/// Link `dpc` after `anchor` (the sentinel for a head insert).
///
/// # Safety
///
/// `anchor` is the sentinel or a link currently on this queue's list; `dpc` is on no list.
unsafe fn link_after(anchor: *mut Links, dpc: &mut Dpc) {
    let entry = links_of(dpc);
    // SAFETY: the caller's contract: `anchor` is on the queue's ring, so it and its `next` are
    // live links, and `dpc`'s links are on no list, so rewiring the three touches nothing else.
    unsafe {
        let next = (*anchor).next;
        (*entry).next = next;
        (*entry).prev = anchor;
        (*next).prev = entry;
        (*anchor).next = entry;
    }
}

/// Link `dpc` before `anchor` (the sentinel for a tail insert).
///
/// # Safety
///
/// Same contract as [`link_after`].
unsafe fn link_before(anchor: *mut Links, dpc: &mut Dpc) {
    let entry = links_of(dpc);
    // SAFETY: as in `link_after`, with `anchor`'s `prev` as the other live neighbour.
    unsafe {
        let prev = (*anchor).prev;
        (*entry).prev = prev;
        (*entry).next = anchor;
        (*prev).next = entry;
        (*anchor).prev = entry;
    }
}

/// Unlink `dpc` from the list it is on.
///
/// # Safety
///
/// `dpc` is linked on a list whose sentinel is alive.
unsafe fn unlink(dpc: &Dpc) {
    let entry = links_of(dpc);
    // SAFETY: the caller's contract: `dpc` is linked on a list whose sentinel is alive, so its
    // `prev` and `next` are live links of that ring.
    unsafe {
        let prev = (*entry).prev;
        let next = (*entry).next;
        (*prev).next = next;
        (*next).prev = prev;
    }
}

/// Detach the queue's head and return the Dpc it belongs to.
///
/// # Safety
///
/// The queue is initialized and non-empty; the returned pointer's reference must not outlive the
/// retire iteration (the next iteration or an insert may touch the DPC).
unsafe fn detach_head(queue: *mut DpcQueue) -> *const Dpc {
    // SAFETY: the caller's contract: `queue` is live, initialized and holds a DPC, so the
    // sentinel's `next` is that DPC's links and the entry's `next` is a live link (another DPC's,
    // or the sentinel). Every link on the queue is a `Dpc`'s `links` member, so stepping back by
    // its offset yields the DPC.
    unsafe {
        let sentinel = addr_of_mut!((*queue).head);
        let entry = (*sentinel).next;
        let next = (*entry).next;
        (*sentinel).next = next;
        (*next).prev = sentinel;
        (entry as usize - core::mem::offset_of!(Dpc, links)) as *const Dpc
    }
}

// --- The kernel queue (target) ---------------------------------------------

/// The one DPC queue (single processor).
#[cfg(target_arch = "x86")]
static mut QUEUE: DpcQueue = DpcQueue::zeroed();

/// Initialize the kernel queue at boot. The request-gate thresholds: a Low-importance DPC is
/// requested once four are queued.
///
/// # Safety
///
/// Boot CPU, interrupts disabled, before the first enqueue.
#[cfg(target_arch = "x86")]
pub unsafe fn init() {
    // SAFETY: sole access, before any interrupt can enqueue.
    unsafe { (*addr_of_mut!(QUEUE)).init(4, 0) };
}

/// Enqueue a DPC on the kernel queue (see [`DpcQueue::insert`]).
#[cfg(target_arch = "x86")]
pub fn enqueue(dpc: &mut Dpc, argument1: usize, argument2: usize) -> bool {
    // SAFETY: single CPU; the queue and the level state are kernel statics whose accessors run
    // serialized by the level discipline.
    unsafe {
        (*addr_of_mut!(QUEUE)).insert(
            dpc,
            argument1,
            argument2,
            crate::interrupt::irql::state_mut(),
        )
    }
}

/// Drain the kernel queue at the dispatch level: the shared body of the two retirement entries —
/// the hardware-interrupt exit and the idle loop.
///
/// The drain refuses to run at or above the dispatch level, the same guarantee NT draws from its
/// dispatch software interrupt, which cannot fire until the level drops below it. Raising to the
/// dispatch level leaves the clock unmasked: a tick there could land inside dispatcher code (a
/// park's selection, a switch's install) or inside a running routine, and a drain at that point
/// would run timer expiry on top of the half-done ready-queue work. Refused work stays queued for
/// the next entry that finds the level lower — the outer retire pass (which loops until the queue
/// is empty), the next interrupt exit, or the idle loop — at most one tick later.
#[cfg(target_arch = "x86")]
pub fn drain() {
    // SAFETY: as above.
    unsafe {
        let queue = &mut *addr_of_mut!(QUEUE);
        if queue.is_empty() || queue.routine_active {
            return;
        }
        let irql = crate::interrupt::irql::state_mut();
        if irql.current() >= crate::interrupt::irql::DISPATCH {
            return;
        }
        let previous = irql.raise(crate::interrupt::irql::DISPATCH);
        // The raise re-enabled interrupts (the dispatch level is below the hardware floor); the
        // retire pass detaches entries the clock interrupt also links, so it starts masked, per its
        // contract. The lower restores the flag the raise captured.
        irql.mask_interrupts();
        // The test above ran with interrupts possibly enabled: a nested interrupt's exit may have
        // drained the queue since. The retire pass needs a non-empty queue, so test again, masked.
        if !queue.is_empty() && !queue.routine_active {
            queue.retire(irql);
        }
        irql.lower(previous);
    }
}

/// Whether the kernel queue has work pending (target helper for the interrupt audit).
#[cfg(target_arch = "x86")]
pub fn has_pending() -> bool {
    // SAFETY: read-only access.
    unsafe { !(*addr_of_mut!(QUEUE)).is_empty() }
}

/// The kernel queue (target helper for the clock's runtime accounting).
///
/// # Safety (target)
///
/// Single CPU, serialized access.
#[cfg(target_arch = "x86")]
pub(crate) fn queue_mut() -> &'static mut DpcQueue {
    // SAFETY: single CPU; callers run serialized.
    unsafe { &mut *addr_of_mut!(QUEUE) }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;
    use crate::interrupt::irql::DISPATCH;

    fn fresh() -> (DpcQueue, IrqlState) {
        let mut queue = DpcQueue::zeroed();
        queue.init(4, 0);
        (queue, IrqlState::new())
    }

    /// Records, per call: (argument1, was-still-queued, interrupts-were-enabled,
    /// routine-was-active).
    #[derive(Default)]
    struct Rec {
        calls: std::cell::RefCell<Vec<(usize, bool, bool, bool)>>,
    }

    impl Rec {
        fn routine(dpc: &Dpc, context: usize, argument1: usize, _argument2: usize) {
            let this = unsafe { &*(context as *const Rec) };
            this.calls.borrow_mut().push((
                argument1,
                dpc.queued.load(Ordering::SeqCst),
                TEST_IRQL.with(|i| unsafe { (*i.get()).interrupts_enabled() }),
                TEST_QUEUE.with(|q| unsafe { (*q.get()).routine_active() }),
            ));
        }
    }

    // The retire path must be reachable from the routines for the mid-drain enqueue tests — through
    // raw pointers, mirroring how the kernel's ISRs reach the statics.
    thread_local! {
        static TEST_QUEUE: Cell<*mut DpcQueue> = const { Cell::new(core::ptr::null_mut()) };
        static TEST_IRQL: Cell<*mut IrqlState> = const { Cell::new(core::ptr::null_mut()) };
        static FOLLOW_REC: Cell<*const Rec> = const { Cell::new(core::ptr::null()) };
    }

    /// Bind the thread-locals, run `body` with the queue and level state, then unbind.
    fn with_queue(max_depth: i32, min_rate: i32, body: impl FnOnce(&mut DpcQueue, &mut IrqlState)) {
        let mut queue = DpcQueue::zeroed();
        queue.init(max_depth, min_rate);
        let mut irql = IrqlState::new();
        TEST_QUEUE.with(|q| q.set(&mut queue as *mut DpcQueue));
        TEST_IRQL.with(|i| i.set(&mut irql as *mut IrqlState));
        body(&mut queue, &mut irql);
        TEST_QUEUE.with(|q| q.set(core::ptr::null_mut()));
        TEST_IRQL.with(|i| i.set(core::ptr::null_mut()));
    }

    fn recording_dpc(label: usize) -> (std::rc::Rc<Rec>, Dpc) {
        let rec = std::rc::Rc::new(Rec::default());
        let dpc = Dpc::new(Rec::routine, std::rc::Rc::as_ptr(&rec) as usize);
        (rec, dpc)
    }

    /// A DPC sharing `rec`, so its calls land in one ordered log.
    fn dpc_sharing(rec: &std::rc::Rc<Rec>) -> Dpc {
        Dpc::new(Rec::routine, std::rc::Rc::as_ptr(rec) as usize)
    }

    /// A fresh DPC carries the routine and context, defaults to medium importance, and is not
    /// queued.
    #[test]
    fn fresh_dpc_defaults() {
        let (_, dpc) = recording_dpc(0);
        assert_eq!(dpc.importance, Importance::Medium);
        assert!(!dpc.queued.load(Ordering::SeqCst));
        assert_eq!(dpc.argument1, 0);
        assert_eq!(dpc.argument2, 0);
    }

    /// A fresh insert queues, stores the arguments, bumps the depth, keeps FIFO order, and puts a
    /// High-importance DPC at the head.
    #[test]
    fn fresh_inserts_store_arguments_and_order() {
        with_queue(4, 0, |queue, irql| {
            let rec = std::rc::Rc::new(Rec::default());
            let mut dpc1 = dpc_sharing(&rec);
            let mut dpc2 = dpc_sharing(&rec);
            let mut dpc3 = dpc_sharing(&rec);
            dpc3.set_importance(Importance::High);

            assert!(queue.insert(&mut dpc1, 10, 0, irql));
            assert!(queue.insert(&mut dpc2, 20, 0, irql));
            assert!(queue.insert(&mut dpc3, 30, 0, irql));
            assert_eq!(queue.depth(), 3);

            irql.raise(DISPATCH);
            queue.retire(irql);
            irql.lower(crate::interrupt::irql::PASSIVE);

            // High importance ran first; the rest in FIFO order, each with its insertion-time
            // arguments, in true call order.
            let order: Vec<usize> = rec
                .calls
                .take()
                .into_iter()
                .map(|(arg, _, _, _)| arg)
                .collect();
            assert_eq!(order, vec![30, 10, 20]);
            assert!(queue.is_empty());
            assert_eq!(queue.depth(), 0);
        });
    }

    /// Re-inserting a queued DPC is a no-op: the second insert returns false and the first
    /// insertion's arguments stand.
    #[test]
    fn reinserting_a_queued_dpc_is_a_no_op() {
        with_queue(4, 0, |queue, irql| {
            let (rec, mut dpc) = recording_dpc(1);
            assert!(queue.insert(&mut dpc, 10, 0, irql));
            assert!(!queue.insert(&mut dpc, 20, 0, irql));
            assert_eq!(queue.depth(), 1);

            irql.raise(DISPATCH);
            queue.retire(irql);
            irql.lower(crate::interrupt::irql::PASSIVE);
            assert_eq!(rec.calls.take(), vec![(10, false, true, true)]);
        });
    }

    /// Remove dequeues a queued DPC (and reports it); removing an idle one reports false; a double
    /// remove reports false the second time.
    #[test]
    fn remove_returns_whether_the_dpc_was_queued() {
        with_queue(4, 0, |queue, irql| {
            let (rec, mut dpc) = recording_dpc(1);
            let (_, mut other) = recording_dpc(2);

            assert!(!queue.remove(&dpc, irql)); // idle

            assert!(queue.insert(&mut dpc, 10, 0, irql));
            assert!(queue.insert(&mut other, 20, 0, irql));
            assert!(queue.remove(&dpc, irql));
            assert!(!queue.remove(&dpc, irql)); // already removed
            assert_eq!(queue.depth(), 1);

            irql.raise(DISPATCH);
            queue.retire(irql);
            irql.lower(crate::interrupt::irql::PASSIVE);
            // Only the survivor ran.
            assert!(rec.calls.take().is_empty());
        });
    }

    /// The dispatch-request gate, as a decision table: nothing is requested while a routine is
    /// active or a request is already outstanding; otherwise a Medium/High DPC (or a Low one past
    /// the depth threshold) requests.
    #[test]
    fn the_request_gate_decision_table() {
        // Routine active: no request, even for High importance.
        with_queue(4, 0, |queue, irql| {
            queue.routine_active = true;
            let (_, mut dpc) = recording_dpc(1);
            dpc.set_importance(Importance::High);
            assert!(queue.insert(&mut dpc, 0, 0, irql));
            assert!(!queue.interrupt_requested());
        });

        // Clear, Medium importance: requested.
        with_queue(4, 0, |queue, irql| {
            let (_, mut dpc) = recording_dpc(1);
            assert!(queue.insert(&mut dpc, 0, 0, irql));
            assert!(queue.interrupt_requested());
            assert_eq!(queue.dispatch_requests(), 1);
        });

        // Clear, High importance: requested.
        with_queue(4, 0, |queue, irql| {
            let (_, mut dpc) = recording_dpc(1);
            dpc.set_importance(Importance::High);
            assert!(queue.insert(&mut dpc, 0, 0, irql));
            assert!(queue.interrupt_requested());
        });

        // Clear, Low importance, depth under the threshold and rate at the floor: not requested...
        with_queue(4, 0, |queue, irql| {
            let (_, mut dpc) = recording_dpc(1);
            dpc.set_importance(Importance::Low);
            assert!(queue.insert(&mut dpc, 0, 0, irql));
            assert!(!queue.interrupt_requested());
        });

        // ...but requested once the depth reaches the threshold.
        with_queue(3, 0, |queue, irql| {
            for i in 0..2 {
                let (_, mut dpc) = recording_dpc(i);
                dpc.set_importance(Importance::Low);
                assert!(queue.insert(&mut dpc, 0, 0, irql));
                assert!(!queue.interrupt_requested());
            }
            let (_, mut deep) = recording_dpc(9);
            deep.set_importance(Importance::Low);
            assert!(queue.insert(&mut deep, 0, 0, irql));
            assert!(queue.interrupt_requested());
        });

        // A request already outstanding: no second request.
        with_queue(4, 0, |queue, irql| {
            let (_, mut first) = recording_dpc(1);
            let (_, mut second) = recording_dpc(2);
            assert!(queue.insert(&mut first, 0, 0, irql));
            assert!(queue.insert(&mut second, 0, 0, irql));
            assert_eq!(queue.dispatch_requests(), 1);
        });

        // Rate-driven: a Low DPC requests once the recent rate has fallen under the floor.
        with_queue(4, 1, |queue, irql| {
            queue.request_rate = 0;
            let (_, mut dpc) = recording_dpc(1);
            dpc.set_importance(Importance::Low);
            assert!(queue.insert(&mut dpc, 0, 0, irql));
            assert!(queue.interrupt_requested());
        });
    }

    /// Retire discipline: the inserted state is cleared before the call, interrupts are enabled
    /// around the routine, the routine-active flag is set for the whole pass and cleared only when
    /// the queue empties.
    #[test]
    fn retire_clears_state_before_the_call_and_enables_interrupts() {
        with_queue(4, 0, |queue, irql| {
            let (rec, mut dpc) = recording_dpc(1);
            assert!(queue.insert(&mut dpc, 0, 0, irql));
            irql.raise(DISPATCH);
            queue.retire(irql);
            irql.lower(crate::interrupt::irql::PASSIVE);

            let calls = rec.calls.take();
            assert_eq!(calls.len(), 1);
            assert_eq!(
                calls[0].1, false,
                "inserted state must be cleared before the call"
            );
            assert_eq!(
                calls[0].2, true,
                "interrupts must be enabled around the routine"
            );
            assert_eq!(
                calls[0].3, true,
                "routine-active must be set during the pass"
            );
            assert!(!queue.routine_active());
            assert!(!queue.interrupt_requested());
        });
    }

    /// The race-close invariant: a DPC enqueued from inside a retire routine (while the queue
    /// "looked" empty) is not lost — the same retire pass drains it.
    #[test]
    fn a_mid_retire_enqueue_is_not_lost() {
        with_queue(4, 0, |queue, irql| {
            let mut dpc1 = Dpc::new(chained_routine, 0);
            assert!(queue.insert(&mut dpc1, 0, 0, irql));

            irql.raise(DISPATCH);
            queue.retire(irql);
            irql.lower(crate::interrupt::irql::PASSIVE);

            // dpc1's routine enqueued the follow-up DPC while the queue was otherwise empty; the
            // same pass must have drained it.
            let follow_calls = FOLLOW_REC.with(|f| unsafe { (*f.get()).calls.take() });
            assert_eq!(
                follow_calls.len(),
                1,
                "the mid-drain enqueue must not be lost"
            );
            assert_eq!(follow_calls[0].0, 7, "the follow-up ran with its arguments");
            assert!(queue.is_empty());
            assert!(!queue.routine_active());
        });
    }

    /// The chained routine: enqueues the follow-up DPC (leaked, so it outlives the pass) and
    /// records that the active flag blocks a new dispatch request mid-drain.
    fn chained_routine(_dpc: &Dpc, _context: usize, _a1: usize, _a2: usize) {
        let rec: &'static Rec = Box::leak(Box::new(Rec::default()));
        let follow: &'static mut Dpc =
            Box::leak(Box::new(Dpc::new(Rec::routine, rec as *const Rec as usize)));
        FOLLOW_REC.with(|f| f.set(rec as *const Rec));
        TEST_QUEUE.with(|q| {
            let queue = unsafe { &mut *q.get() };
            let irql = TEST_IRQL.with(|i| unsafe { &mut *i.get() });
            follow.set_importance(Importance::Low);
            assert!(queue.insert(follow, 7, 0, irql));
            // Mid-drain: no NEW dispatch request is issued (the first DPC's request is still
            // outstanding, which is exactly why the gate stays closed).
            assert_eq!(queue.dispatch_requests(), 1);
        });
    }

    /// Both retirement entries drain without double-draining: after the first drain the queue is
    /// empty and the second entry is a no-op.
    #[test]
    fn both_retirement_entries_drain_once() {
        with_queue(4, 0, |queue, irql| {
            let (rec, mut dpc) = recording_dpc(1);
            assert!(queue.insert(&mut dpc, 0, 0, irql));

            // Entry one (the interrupt-exit drain shape).
            irql.raise(DISPATCH);
            queue.retire(irql);
            irql.lower(crate::interrupt::irql::PASSIVE);
            assert_eq!(rec.calls.take().len(), 1);

            // Entry two (the idle-loop window): empty, nothing runs.
            assert!(queue.is_empty());
            assert!(rec.calls.take().is_empty());
        });
    }

    /// The request-rate average folds the enqueue-count history.
    #[test]
    fn request_rate_folds_the_count_history() {
        with_queue(4, 0, |queue, _irql| {
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
        });
    }
}
