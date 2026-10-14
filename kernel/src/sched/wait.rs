//! The wait discipline: how a thread blocks on a waitable object,
//! and how the object wakes it.
//!
//! A waitable object carries a header — its kind, its signal
//! state, and the list of the wait blocks parked on it. An event
//! is nothing but the header; a thread's own record is waitable
//! the same way (it signals once, at termination); a timer is the
//! third kind, and the timeout machinery below is built on each
//! thread owning one.
//!
//! A thread that cannot be satisfied at once joins the object: it
//! plants a wait block on the object's waiters list, takes a
//! circular chain of its own blocks describing everything the
//! wait covers, and enters the Waiting state. Whatever wakes it
//! — a signal on the object, a rival resolution cancelling the
//! wait, an expiry — goes through one exit, [`Dispatcher::unwait`],
//! which unwinds the chain, cancels the wait's timer, applies the
//! wake boost and the wait charge, and readies the thread. The
//! state's exit has a single owner: a waiting thread is readied
//! through the wait exit and nothing else.
//!
//! A timeout is the thread's own timer inserted through the seam
//! at the bottom of this module: the wait computes a due time and
//! hands it over; when the due time is live the timer carries it
//! and the wait blocks; the expiry entry signals the timer and
//! satisfies its waiters like any other object, with the timeout
//! status planted in the timer block at thread setup — the
//! timeout needs no special wake path at all. The timer table
//! itself is a later slice; the seam's entries are its contract.
//!
//! One processor, no locking: everything here runs serialized at
//! the dispatch level, so there are no races to arbitrate — which
//! of a wake and an expiry "wins" is decided by which runs first,
//! and the loser finds its lists already unwound.

use super::dispatcher::Dispatcher;
use super::thread::{Thread, ThreadState};
use super::{unlink, List, Links, REALTIME_BASE, TIME_CRITICAL_CEILING};
use core::ptr::{addr_of_mut, eq, null_mut};

/// The wait statuses, as documented NTSTATUS values: what a
/// completed wait reports. The timeout value is the ABI the Win32
/// wait returns raw (WAIT_TIMEOUT).
pub const STATUS_SUCCESS: i32 = 0x0000_0000;
pub const STATUS_TIMEOUT: i32 = 0x0000_0102;

/// The low three bits of a waitable kind: the selector that
/// decides whether a satisfied wait consumes the object's signal.
/// The timer kinds share numbers with the event kinds through it.
pub const WAIT_KIND_MASK: u8 = 0x7;

/// The number of wait blocks a thread owns: the builtin set plus
/// its timer block (the last slot).
pub const WAIT_BLOCKS: usize = 4;

/// The slot of the thread's timer block.
pub const TIMER_BLOCK: usize = WAIT_BLOCKS - 1;

/// The priority increment a timer expiry grants its waiters: none.
pub const TIMER_WAKE_INCREMENT: i8 = 0;

/// The kind of a waitable object, as the satisfy machinery reads
/// it. The ordinals are stable kernel data: the masked low three
/// bits select the signal-consumption rule, so the timer kinds sit
/// on the event rule through the mask.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum WaitKind {
    /// A manual-reset event: signaled until cleared, and one
    /// signal wakes every waiter present.
    NotificationEvent = 0,
    /// An auto-reset event: one signal wakes exactly one waiter,
    /// and the satisfy consumes the signal.
    SynchronizationEvent = 1,
    /// The thread object: signals once, at termination, forever.
    Thread = 6,
    /// A timer that stays signaled once it expires.
    TimerNotification = 8,
    /// A timer whose signal serves a single waiter.
    TimerSynchronization = 9,
}

impl WaitKind {
    /// Whether satisfying one waiter consumes the object's
    /// signal: the synchronization flavors do (through the
    /// three-bit mask, which folds the timer flavors onto the
    /// event rule), everything else does not.
    pub fn consumes_signal(self) -> bool {
        (self as u8 & WAIT_KIND_MASK) == WaitKind::SynchronizationEvent as u8
    }
}

/// The header every waitable object carries: what kind it is,
/// whether it is signaled, and which threads are parked on it.
#[repr(C)]
pub struct Waitable {
    /// The object's kind.
    pub(crate) kind: WaitKind,
    /// The signal state: positive means signaled.
    pub(crate) signal_state: i32,
    /// The wait blocks parked on this object.
    pub(crate) waiters: List,
}

impl Waitable {
    /// A fresh, unsignaled header; call [`Waitable::init`] once
    /// the owning object is at its final address.
    pub const fn new(kind: WaitKind, signal_state: i32) -> Self {
        Waitable { kind, signal_state, waiters: List::empty() }
    }

    /// A fresh, signaled header.
    pub const fn signaled(kind: WaitKind) -> Self {
        Waitable { kind, signal_state: 1, waiters: List::empty() }
    }

    /// Close the waiters sentinel; call once at the final address.
    pub fn init(&mut self) {
        self.waiters.init();
    }

    /// The object's kind.
    pub fn kind(&self) -> WaitKind {
        self.kind
    }

    /// The signal state: positive means signaled.
    pub fn signal_state(&self) -> i32 {
        self.signal_state
    }
}

/// A wait's timer: the record the timeout seam inserts, removes,
/// and expires. Each thread owns one for its wait timeouts.
#[repr(C)]
pub struct Timer {
    /// The timer as a waitable object: expiry signals it and
    /// satisfies its waiters.
    pub(crate) waitable: Waitable,
    /// The due time the seam recorded, in 100 ns units.
    pub(crate) due_time: i64,
    /// Whether the seam currently holds the timer.
    pub(crate) inserted: bool,
}

impl Timer {
    /// A fresh timer, uninserted and unsignaled; call
    /// [`Timer::init`] once the owning thread is at its final
    /// address.
    pub const fn new() -> Self {
        Timer {
            waitable: Waitable::new(WaitKind::TimerNotification, 0),
            due_time: 0,
            inserted: false,
        }
    }

    /// Close the header's waiters sentinel.
    pub fn init(&mut self) {
        self.waitable.init();
    }

    /// The recorded due time, in 100 ns units.
    pub fn due_time(&self) -> i64 {
        self.due_time
    }

    /// Whether the seam currently holds the timer.
    pub fn inserted(&self) -> bool {
        self.inserted
    }
}

/// One thread's claim on one object: linked on the object's
/// waiters list and chained circularly to the thread's other
/// blocks for the same wait. A thread embeds a fixed set: the
/// first block holds a single-object wait, its timer block joins
/// when the wait carries a timeout, and the timer block alone is
/// a delay.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct WaitBlock {
    /// The waiters-list membership link.
    pub(crate) links: Links,
    /// The claiming thread.
    pub(crate) thread: *mut Thread,
    /// The claimed object's header.
    pub(crate) object: *mut Waitable,
    /// The next block of the same wait, circularly.
    pub(crate) next_block: *mut WaitBlock,
    /// The status this block's satisfaction reports: the object
    /// block carries success, the timer block the timeout.
    pub(crate) key: i32,
    /// Whether the block is a wait-all claim. The multiple-object
    /// wait that would construct one is not built; the satisfy
    /// walk keeps the rule anyway.
    pub(crate) wait_all: bool,
}

impl WaitBlock {
    /// A detached block; the owning thread wires the fields at
    /// attach and per wait.
    pub const fn detached() -> Self {
        WaitBlock {
            links: Links::detached(),
            thread: null_mut(),
            object: null_mut(),
            next_block: null_mut(),
            key: 0,
            wait_all: false,
        }
    }
}

/// Why a thread waits. Diagnostic data the dump paths read; the
/// delay wait carries its own.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum WaitReason {
    /// A wait on a dispatcher object.
    Executive = 0,
    /// A timed sleep.
    DelayExecution = 4,
    /// A suspend delivered through the wait.
    Suspension = 5,
    /// A wait the program asked for.
    UserRequest = 6,
}

/// The mode of a wait. Inert data until the APC machinery exists;
/// user-mode APC delivery is its seam.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum WaitMode {
    /// A wait the kernel entered.
    Kernel = 0,
    /// A wait entered for a program.
    User = 1,
}

/// A reading of the kernel clock, taken by the wait's caller: the
/// system time (100 ns units) for due-time math, the tick count
/// for the wait-time stamp.
#[derive(Clone, Copy)]
pub struct ClockStamp {
    /// The system-time accumulator's value.
    pub system_time: u64,
    /// The tick count.
    pub tick: u64,
}

/// What the wait entry decided.
#[derive(Debug, PartialEq, Eq)]
pub enum WaitDisposition {
    /// The wait completed without blocking, with the status.
    Complete(i32),
    /// The thread is Waiting and the caller must switch away. The
    /// completion status lands in the thread's wait-status field
    /// when the wake runs; the thread's resume side reads it.
    Yield,
}

/// The wait block owning a waiters-list entry.
// SAFETY-contract: `entry` is the links field of a live wait block.
pub(crate) fn entry_to_block(entry: *mut Links) -> *mut WaitBlock {
    (entry as usize - core::mem::offset_of!(WaitBlock, links)) as *mut WaitBlock
}

/// Satisfy one waiter's claim on `object`: a synchronization
/// flavor's signal is consumed by the take, everything else's
/// stays.
fn consume_signal(object: &mut Waitable) {
    if object.kind.consumes_signal() {
        object.signal_state = 0;
    }
}

impl Dispatcher {
    /// Wait on a single object. Satisfies the wait at once when
    /// the object is signaled or the timeout is zero or already
    /// past; otherwise parks the thread: a wait block on the
    /// object, the state Waiting, the waiting list — and the
    /// switch away is the caller's business.
    pub fn wait_single(
        &mut self,
        thread: &mut Thread,
        object: *mut Waitable,
        reason: WaitReason,
        mode: WaitMode,
        alertable: bool,
        timeout: Option<i64>,
        stamp: ClockStamp,
    ) -> WaitDisposition {
        // A fresh wait starts from a clean completion status: the
        // wake ORs its status into the field.
        thread.wait_status = 0;

        // An already-signaled object satisfies the wait outright.
        // The take consumes an auto-reset flavor's signal; the
        // thread never leaves the Running state, and the wait it
        // did not block on still costs its quantum charge.
        // SAFETY: the object is a live, initialized waitable.
        let object: &mut Waitable = unsafe { &mut *object };
        if object.signal_state > 0 {
            consume_signal(object);
            self.charge_nowait(thread);
            return WaitDisposition::Complete(STATUS_SUCCESS);
        }

        // Plant the object block. Its fields are per-wait; the
        // chain is closed below, with the timer block when a
        // timeout arms one.
        // SAFETY: the block lives inside the thread for its
        // lifetime.
        let block: *mut WaitBlock = addr_of_mut!(thread.wait_blocks[0]);
        thread.wait_block_head = block;
        // SAFETY: as above.
        unsafe {
            (*block).object = object as *mut Waitable;
            (*block).key = STATUS_SUCCESS;
            (*block).wait_all = false;
        }

        // A zero timeout never blocks, even for an instant.
        if timeout == Some(0) {
            self.charge_nowait(thread);
            return WaitDisposition::Complete(STATUS_TIMEOUT);
        }

        match timeout {
            Some(interval) => {
                // The wait chain: object block, timer block,
                // circularly. The timer block's own claim is
                // constant per thread — its object, its key (the
                // timeout status), its wait type — planted once at
                // thread setup; the wait only re-links it.
                // SAFETY: both blocks live inside the thread.
                let timer_block: *mut WaitBlock =
                    addr_of_mut!(thread.wait_blocks[TIMER_BLOCK]);
                // SAFETY: as above.
                unsafe {
                    (*block).next_block = timer_block;
                    (*timer_block).next_block = block;
                    // SAFETY: the timer's waiters list is
                    // initialized at thread attach, and the block
                    // is on no list.
                    thread.timer.waitable.waiters.push_back(addr_of_mut!((*timer_block).links));
                }
                let due = stamp.system_time as i64 + interval;
                if !timer_insert(&mut thread.timer, due, stamp.system_time) {
                    // Already past: the wait reports a timeout and
                    // unwinds what it linked.
                    // SAFETY: linked above.
                    unsafe { unlink(addr_of_mut!((*timer_block).links)) };
                    self.charge_nowait(thread);
                    return WaitDisposition::Complete(STATUS_TIMEOUT);
                }
            }
            None => {
                // No timeout: the one-block chain closes on
                // itself.
                // SAFETY: as above.
                unsafe { (*block).next_block = block };
            }
        }

        // Join the object's waiters at the tail: waits satisfy
        // first-blocked-first-woken.
        // SAFETY: the block is on no list; the object's waiters
        // list is initialized.
        unsafe { object.waiters.push_back(addr_of_mut!((*block).links)) };

        // The block path: the wait's parameters land on the thread
        // and it joins the waiting list, in the Waiting state. The
        // switch away is the caller's business.
        thread.wait_alertable = alertable;
        thread.wait_mode = mode;
        thread.wait_reason = reason;
        thread.wait_time = stamp.tick;
        thread.state = ThreadState::Waiting;
        // SAFETY: the thread is on no waiting list; the
        // dispatcher's list is initialized.
        unsafe { self.waiting.push_back(addr_of_mut!(thread.wait_links)) };
        WaitDisposition::Yield
    }

    /// The delay wait: park `thread` on its own timer for
    /// `interval` (100 ns units, relative — or negative, an
    /// absolute due already past) — the sleep shape. The chain is
    /// the timer block alone, so the expiry is the only possible
    /// wake. An interval already past never parks: a boosted
    /// thread drops to its base priority, is readied with a fresh
    /// quantum when an equal-priority thread can take over, and
    /// the caller yields; with nobody to take over the delay
    /// completes at once.
    pub fn delay(
        &mut self,
        thread: &mut Thread,
        mode: WaitMode,
        alertable: bool,
        interval: i64,
        stamp: ClockStamp,
    ) -> WaitDisposition {
        // SAFETY: the timer block lives inside the thread.
        let block: *mut WaitBlock = addr_of_mut!(thread.wait_blocks[TIMER_BLOCK]);
        thread.wait_block_head = block;
        thread.wait_status = 0;
        // SAFETY: as above; the timer's waiters list is
        // initialized at thread attach, and the block is on no
        // list.
        unsafe {
            (*block).next_block = block;
            thread.timer.waitable.waiters.push_back(addr_of_mut!((*block).links));
        }

        let due = stamp.system_time as i64 + interval;
        if !timer_insert(&mut thread.timer, due, stamp.system_time) {
            // Already past: never a wait state. Drop a boosted
            // variable thread to its base — the drop itself may
            // select a replacement — then try to hand the
            // processor to an equal if nobody was selected.
            // SAFETY: linked above; the thread stays unparked.
            unsafe { unlink(addr_of_mut!((*block).links)) };
            let base = thread.base_priority;
            if thread.priority < REALTIME_BASE && thread.priority != base {
                thread.priority_decrement = 0;
                self.apply_priority(thread, base);
            }
            if self.next_thread().is_null() {
                self.standby_from_ready(thread.priority);
            }
            if !self.next_thread().is_null() {
                thread.preempted = false;
                // SAFETY: the thread is attached; its process
                // outlives it.
                thread.quantum = unsafe { (*thread.process).thread_quantum };
                self.make_ready(thread);
                return WaitDisposition::Yield;
            }
            return WaitDisposition::Complete(STATUS_SUCCESS);
        }

        thread.wait_alertable = alertable;
        thread.wait_mode = mode;
        thread.wait_reason = WaitReason::DelayExecution;
        thread.wait_time = stamp.tick;
        thread.state = ThreadState::Waiting;
        // SAFETY: the thread is on no waiting list.
        unsafe { self.waiting.push_back(addr_of_mut!(thread.wait_links)) };
        WaitDisposition::Yield
    }

    /// The delay's resume-side conversion: a sleep that timed out
    /// is a successful sleep. The thread's wait status carries
    /// the timeout; the delay completes as success.
    pub fn delay_completed(status: i32) -> i32 {
        if status == STATUS_TIMEOUT {
            STATUS_SUCCESS
        } else {
            status
        }
    }

    /// The wait exit: complete `thread`'s wait with `status` and a
    /// wake boost of `increment`. This is the single owner of the
    /// Waiting state's exit — every wake site goes through it. It
    /// unwinds the wait's blocks from their objects, leaves the
    /// waiting list, cancels the wait's timer if it is still live,
    /// applies the boost (the thread's no-boost policy gates it
    /// here — the boost itself leaves policy to its caller),
    /// charges the wait, and readies the thread.
    pub fn unwait(&mut self, thread: &mut Thread, status: i32, increment: i8) {
        assert!(
            thread.state == ThreadState::Waiting,
            "the wait exit runs on a waiting thread"
        );
        // The status is OR'd in, not assigned: a wait may carry a
        // status its wake must preserve.
        thread.wait_status |= status;

        // Unlink every block of the chain from the object it is
        // parked on, then leave the waiting list.
        let mut block = thread.wait_block_head;
        // SAFETY: the chain is circular, every block is linked,
        // and the walk returns to its head.
        unsafe {
            loop {
                unlink(addr_of_mut!((*block).links));
                block = (*block).next_block;
                if eq(block, thread.wait_block_head) {
                    break;
                }
            }
        }
        // SAFETY: a waiting thread is on the waiting list.
        unsafe { unlink(addr_of_mut!(thread.wait_links)) };
        // The wait is unwound: no chain to walk until the next
        // one, and the ready path may check.
        thread.wait_block_head = null_mut();

        // A wake beats its timeout: cancel the wait's timer if it
        // is still live.
        if thread.timer.inserted {
            timer_remove(&mut thread.timer);
        }

        if !thread.disable_boost {
            self.boost(thread, increment);
        }
        self.charge_wait(thread);
        self.make_ready(thread);
    }

    /// Satisfy as many of `object`'s waits as its signal allows:
    /// while it is signaled and waiters are parked, wake the head
    /// waiter with `increment`. An auto-reset flavor's signal
    /// serves exactly one waiter; every other kind's serves all
    /// present at once.
    pub fn satisfy_waiters(&mut self, object: *mut Waitable, increment: i8) {
        // SAFETY: the object is a live, initialized waitable.
        let object: &mut Waitable = unsafe { &mut *object };
        let sentinel = object.waiters.sentinel();
        // SAFETY: the waiters list is initialized and its entries
        // are wait blocks.
        let mut entry = unsafe { object.waiters.first() };
        while object.signal_state > 0 && !entry.is_null() && !eq(entry, sentinel) {
            // SAFETY: the entry is a wait block's links field.
            let block = entry_to_block(entry);
            // SAFETY: the block's thread and key are live.
            let thread = unsafe { (*block).thread };
            let key = unsafe { (*block).key };

            // SAFETY: the wait-all flag is a plain read.
            if unsafe { (*block).wait_all } {
                // A wait-all claim needs every object of its chain
                // signaled; otherwise it stays parked and the walk
                // moves on.
                // SAFETY: the chain is circular and every non-
                // timer block names a live waitable.
                if !unsafe { chain_all_signaled(block) } {
                    // SAFETY: a linked entry's next pointer names
                    // the next waiter.
                    entry = unsafe { (*entry).next };
                    continue;
                }
                // SAFETY: as above.
                unsafe { satisfy_chain(block) };
            } else {
                consume_signal(object);
            }

            // SAFETY: the waking thread is a live, waiting thread.
            self.unwait(unsafe { &mut *thread }, key, increment);
            // The wake unlinked the head block: continue from the
            // new head.
            // SAFETY: as above.
            entry = unsafe { object.waiters.first() };
        }
    }

    /// Expire `timer`: signal it and satisfy its waiters with no
    /// priority increment — what the clock's expiry work does per
    /// due timer. A timer an earlier wake already cancelled expires
    /// as a no-op.
    pub fn expire_timer(&mut self, timer: *mut Timer) {
        // SAFETY: the timer is a live, initialized record.
        let timer: &mut Timer = unsafe { &mut *timer };
        if timer.inserted {
            timer_remove(timer);
        }
        timer.waitable.signal_state = 1;
        let waitable = addr_of_mut!(timer.waitable);
        self.satisfy_waiters(waitable, TIMER_WAKE_INCREMENT);
    }

    /// The wait structures' audit: the waiting list holds only
    /// waiting threads, every block of a waiting thread's chain is
    /// linked on exactly the object it names, and every block
    /// parked on such an object belongs to a waiting thread's
    /// chain.
    pub fn audit_waits(&self) -> Result<(), &'static str> {
        let sentinel = list_sentinel(&self.waiting);
        // SAFETY: read-only walks of initialized lists.
        unsafe {
            let mut entry = self.waiting.first();
            while !entry.is_null() && !eq(entry, sentinel) {
                let thread = waiting_thread(entry);
                if (*thread).state != ThreadState::Waiting {
                    return Err("a non-waiting thread is on the waiting list");
                }
                // The chain: every block linked, and its object's
                // list holding it.
                let head = (*thread).wait_block_head;
                let mut block = head;
                loop {
                    if !linked(block) {
                        return Err("a waiting thread's block is unlinked");
                    }
                    let object = (*block).object;
                    if !list_holds(&(*object).waiters, addr_of_mut!((*block).links)) {
                        return Err("a wait block is not on its object's list");
                    }
                    // The reverse: every block parked on this
                    // object belongs to a waiting thread's chain.
                    let osentinel = (*object).waiters.sentinel();
                    let mut oentry = (*object).waiters.first();
                    while !oentry.is_null() && !eq(oentry, osentinel) {
                        let other = entry_to_block(oentry);
                        let owner = (*other).thread;
                        if (*owner).state != ThreadState::Waiting
                            || !chain_holds((*owner).wait_block_head, other)
                        {
                            return Err("a parked block has no waiting owner");
                        }
                        oentry = (*oentry).next;
                    }
                    block = (*block).next_block;
                    if eq(block, head) {
                        break;
                    }
                }
                entry = (*entry).next;
            }
        }
        Ok(())
    }

    /// The block path's switch away, and back. The calling thread
    /// has just parked on a wait: capture its level ledger, select
    /// the next thread, and swap away — the caller's frames stay
    /// on its own kernel stack, and the switch resumes them when a
    /// wake re-selects the thread. The resume side restores the
    /// (now woken) thread's ledger and pays the raise this site
    /// made; the wake's completion status is the thread's
    /// wait-status field.
    #[cfg(target_arch = "x86")]
    pub fn park_and_switch(&mut self) {
        let previous =
            crate::interrupt::irql::state_mut().raise(crate::interrupt::irql::DISPATCH);
        // SAFETY: the running thread, live and exclusive here.
        let old = self.current_thread();
        // SAFETY: as above.
        unsafe { (*old).level = crate::interrupt::irql::state_mut().capture() };
        let selected = self.select_next();
        debug_assert!(
            !selected.is_null(),
            "selection always yields the idle fallback"
        );
        self.enter(selected);
        // SAFETY: the selected thread's frame is planted (fresh) or
        // saved (resumed) — the selection discipline guarantees it —
        // and the dispatch level masks the dispatcher context.
        unsafe { super::switch::swap_context(old, selected) };
        // The parked thread's timeline resumes here.
        // SAFETY: the running thread, live.
        let current = self.current_thread();
        // SAFETY: as above.
        unsafe { crate::interrupt::irql::state_mut().restore((*current).level) };
        crate::interrupt::irql::state_mut().lower(previous);
    }

    /// The no-wait quantum adjustment: the tail of a wait that was
    /// satisfied without blocking. A variable thread below the
    /// time-critical base is charged one unit for the wait; at
    /// exhaustion the quantum resets and the priority decays one
    /// step, and when the decay left the priority alone, an
    /// equal-priority ready thread takes the standby slot — the
    /// round-robin among equals. Realtime threads and
    /// time-critical bases are not adjusted at all.
    fn charge_nowait(&mut self, thread: &mut Thread) {
        if thread.priority >= REALTIME_BASE
            || thread.base_priority >= TIME_CRITICAL_CEILING
        {
            return;
        }
        if self.charge_wait(thread) {
            self.standby_from_ready(thread.priority);
        }
    }
}

// --- The timeout seam -----------------------------------------------------
//
// The wait discipline's timer contract: the wait computes a due
// time from the clock reading its caller took and hands it to
// these entries. This slice hosts them against the timer record
// alone — a due time and an inserted mark; the timer table that
// orders and drives them is the next slice's, and it inherits
// this contract as-is.

/// Insert `timer` at `due` (100 ns units): clear any stale signal,
/// record the due time, and mark it held. False means the due time
/// has already passed — the timer stays unsignaled and unheld, and
/// the wait reports a timeout at once.
pub fn timer_insert(timer: &mut Timer, due: i64, now: u64) -> bool {
    timer.waitable.signal_state = 0;
    if due <= now as i64 {
        timer.inserted = false;
        return false;
    }
    timer.due_time = due;
    timer.inserted = true;
    true
}

/// Cancel `timer`: release the seam's hold, leaving the due time
/// recorded. A cancelled timer expires as a no-op.
pub fn timer_remove(timer: &mut Timer) {
    timer.inserted = false;
}

// --- The walk helpers -----------------------------------------------------

/// Whether every object of a wait-all chain is signaled. The head
/// block's object is the one under test; the rest are checked
/// here, skipping the timer block — its key, the timeout status,
/// is the chain's not-an-object marker.
// SAFETY-contract: `block` heads a circular chain of live blocks.
unsafe fn chain_all_signaled(block: *mut WaitBlock) -> bool {
    unsafe {
        let mut probe = (*block).next_block;
        while !eq(probe, block) {
            if (*probe).key != STATUS_TIMEOUT {
                let object = (*probe).object;
                if (*object).signal_state <= 0 {
                    return false;
                }
            }
            probe = (*probe).next_block;
        }
    }
    true
}

/// Consume the signal of every non-timer object of a wait-all
/// chain, head included.
// SAFETY-contract: as `chain_all_signaled`.
unsafe fn satisfy_chain(block: *mut WaitBlock) {
    unsafe {
        let mut probe = block;
        loop {
            if (*probe).key != STATUS_TIMEOUT {
                consume_signal(&mut *(*probe).object);
            }
            probe = (*probe).next_block;
            if eq(probe, block) {
                break;
            }
        }
    }
}

/// Whether `block`'s links are wired into a list: both neighbors
/// point back at it.
// SAFETY-contract: `block` is a live wait block.
unsafe fn linked(block: *mut WaitBlock) -> bool {
    unsafe {
        let links = addr_of_mut!((*block).links);
        let prev = (*links).prev;
        let next = (*links).next;
        !prev.is_null() && !next.is_null() && (*prev).next == links && (*next).prev == links
    }
}

/// Whether `list` holds `entry`.
// SAFETY-contract: `list` is initialized; `entry` is a live links
// field.
unsafe fn list_holds(list: &List, entry: *mut Links) -> bool {
    unsafe {
        let sentinel = list_sentinel(list);
        let mut probe = list.first();
        while !probe.is_null() && !eq(probe, sentinel) {
            if eq(probe, entry) {
                return true;
            }
            probe = (*probe).next;
        }
    }
    false
}

/// A list's sentinel, read-only (the audit walks must not borrow
/// what they inspect).
fn list_sentinel(list: &List) -> *mut Links {
    core::ptr::addr_of!(list.head) as *mut Links
}

/// Whether `chain` (a circular wait-block chain) holds `block`.
// SAFETY-contract: `chain` heads a circular chain; `block` is a
// live wait block.
unsafe fn chain_holds(chain: *mut WaitBlock, block: *mut WaitBlock) -> bool {
    unsafe {
        let mut probe = chain;
        loop {
            if eq(probe, block) {
                return true;
            }
            probe = (*probe).next_block;
            if eq(probe, chain) {
                return false;
            }
        }
    }
}

/// The waiting thread owning a waiting-list entry.
// SAFETY-contract: `entry` is the wait link of a live thread.
unsafe fn waiting_thread(entry: *mut Links) -> *mut Thread {
    (entry as usize - core::mem::offset_of!(Thread, wait_links)) as *mut Thread
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sched::event::{Event, EventKind, EVENT_WAKE_INCREMENT};
    use crate::sched::process::SchedProcess;

    // --- The rig ----------------------------------------------------------
    //
    // The same style as the dispatcher tests: kernel objects live
    // at fixed addresses for as long as they are linked, so the
    // rig leaks everything it creates.

    fn dispatcher() -> &'static mut Dispatcher {
        let d = Box::leak(Box::new(Dispatcher::zeroed()));
        d.init();
        d
    }

    fn process(base: i8) -> *mut SchedProcess {
        let p = Box::leak(Box::new(SchedProcess::new(0x0090_0000, base)));
        p.init();
        p as *mut SchedProcess
    }

    fn thread(p: *mut SchedProcess) -> &'static mut Thread {
        let t = Box::leak(Box::new(Thread::empty()));
        // SAFETY: both objects are leaked at their final addresses.
        unsafe { t.attach_to(&mut *p) };
        t
    }

    /// Run `t` as the processor's current thread.
    fn run(d: &mut Dispatcher, t: &mut Thread) {
        let ptr: *mut Thread = t;
        d.enter(ptr);
        t.state = ThreadState::Running;
    }

    fn as_ptr<T>(r: &T) -> *mut T {
        r as *const T as *mut T
    }

    fn stamp(system_time: u64, tick: u64) -> ClockStamp {
        ClockStamp { system_time, tick }
    }

    fn event(kind: EventKind, signaled: bool) -> &'static mut Event {
        let ev = Box::leak(Box::new(Event::new(kind, signaled)));
        ev.init();
        ev
    }

    /// Block `t` on `object` (with the rig's fixed clock reading),
    /// asserting the wait actually parked it.
    fn block_on(d: &mut Dispatcher, t: &mut Thread, object: *mut Waitable, timeout: Option<i64>) {
        match d.wait_single(
            t,
            object,
            WaitReason::Executive,
            WaitMode::User,
            false,
            timeout,
            stamp(10_000, 5),
        ) {
            WaitDisposition::Yield => {}
            _ => panic!("expected the wait to park the thread"),
        }
    }

    /// A completed wait's outcome, with its status.
    fn complete(status: i32) -> WaitDisposition {
        WaitDisposition::Complete(status)
    }

    /// The threads parked on `event`, in wait order.
    fn waiters(event: &Event) -> Vec<*mut Thread> {
        let list = &event.waitable.waiters;
        let sentinel = list_sentinel(list);
        let mut parked = Vec::new();
        // SAFETY: the list is initialized; the entries are wait
        // blocks parked on the event.
        let mut entry = unsafe { list.first() };
        while !entry.is_null() && !eq(entry, sentinel) {
            // SAFETY: the entry is a wait block's links field.
            let block = entry_to_block(entry);
            // SAFETY: the block's thread is live.
            parked.push(unsafe { (*block).thread });
            // SAFETY: a linked entry's next pointer names the next
            // waiter.
            entry = unsafe { (*entry).next };
        }
        parked
    }

    // --- Group B: construction and the block path ---------------------------

    /// Thread setup wires the wait fields: the thread is a
    /// waitable object of its own kind, every block names its
    /// owner, and the timer block's claim is planted once — its
    /// object the thread's own timer, its key the timeout status.
    #[test]
    fn thread_setup_wires_the_wait_fields() {
        let p = process(8);
        let t = thread(p);

        assert_eq!(t.waitable.kind(), WaitKind::Thread);
        assert_eq!(t.waitable.signal_state(), 0);
        assert!(t.waitable.waiters.is_empty());
        assert!(t.wait_blocks.iter().all(|b| eq(b.thread, as_ptr(t))));

        let timer_block = &t.wait_blocks[TIMER_BLOCK];
        assert!(eq(timer_block.object, addr_of_mut!(t.timer.waitable)));
        assert_eq!(timer_block.key, STATUS_TIMEOUT);
        assert!(!timer_block.wait_all);

        assert!(!t.timer.inserted());
        assert_eq!(t.timer.due_time(), 0);
        assert!(t.wait_block_head.is_null());
        assert_eq!(t.wait_status(), STATUS_SUCCESS);
    }

    /// The wait chain: without a timeout the object block closes
    /// on itself; with one it runs object block -> timer block ->
    /// object block, the timer block parked on the thread's timer.
    #[test]
    fn wait_block_construction() {
        let d = dispatcher();
        let p = process(8);
        let ev = event(EventKind::Notification, false);

        let t1 = thread(p);
        block_on(d, t1, ev.waitable(), None);
        let head = t1.wait_block_head;
        // SAFETY: the chain is live for the wait.
        unsafe {
            assert!(eq((*head).next_block, head), "the one-block chain closes on itself");
            assert!(eq((*head).object, ev.waitable()));
            assert_eq!((*head).key, STATUS_SUCCESS);
            assert!(!(*head).wait_all);
        }

        let t2 = thread(p);
        block_on(d, t2, ev.waitable(), Some(1_000_000));
        let head = t2.wait_block_head;
        // SAFETY: as above.
        let timer_block = unsafe { (*head).next_block };
        assert!(eq(timer_block, addr_of_mut!(t2.wait_blocks[TIMER_BLOCK])));
        // SAFETY: as above.
        unsafe { assert!(eq((*timer_block).next_block, head)) };
        assert!(t2.timer.inserted());
        assert_eq!(t2.timer.due_time(), 10_000 + 1_000_000);
    }

    /// Waiters join the object at the tail: satisfaction order is
    /// first-blocked-first-woken.
    #[test]
    fn waiters_join_the_tail() {
        let d = dispatcher();
        let p = process(8);
        let t1 = thread(p);
        let t2 = thread(p);
        let t3 = thread(p);
        let ev = event(EventKind::Notification, false);

        block_on(d, t1, ev.waitable(), None);
        block_on(d, t2, ev.waitable(), None);
        block_on(d, t3, ev.waitable(), None);

        assert_eq!(waiters(ev), vec![as_ptr(t1), as_ptr(t2), as_ptr(t3)]);
    }

    /// The block path lands the wait's parameters on the thread
    /// and takes it out of scheduling: Waiting, on the waiting
    /// list, on no ready list.
    #[test]
    fn the_block_path_lands_the_wait_fields() {
        let d = dispatcher();
        let p = process(8);
        let t = thread(p);
        let ev = event(EventKind::Notification, false);

        match d.wait_single(
            t,
            ev.waitable(),
            WaitReason::UserRequest,
            WaitMode::User,
            true,
            None,
            stamp(1_000_000, 77),
        ) {
            WaitDisposition::Yield => {}
            _ => panic!("expected the wait to park the thread"),
        }

        assert_eq!(t.state(), ThreadState::Waiting);
        assert_eq!(t.wait_reason(), WaitReason::UserRequest);
        assert_eq!(t.wait_mode(), WaitMode::User);
        assert!(t.wait_alertable());
        assert_eq!(t.wait_time(), 77);
        assert_eq!(t.wait_status(), 0);
        assert!(!t.wait_links.prev.is_null(), "on the waiting list");
        assert!(t.ready_links.next.is_null(), "on no ready list");
        assert_eq!(d.audit_waits(), Ok(()));
    }

    // --- Group C: the immediate-satisfaction paths ---------------------------

    /// An already-signaled notification event satisfies the wait
    /// outright: the signal survives the take, the thread never
    /// leaves Running, and the quantum is still charged.
    #[test]
    fn a_signaled_notification_event_satisfies_without_side_effects() {
        let d = dispatcher();
        let p = process(8);
        let t = thread(p);
        run(d, t);
        let ev = event(EventKind::Notification, true);

        assert_eq!(
            d.wait_single(t, ev.waitable(), WaitReason::Executive, WaitMode::Kernel, false, None, stamp(0, 0)),
            complete(STATUS_SUCCESS)
        );
        assert_eq!(ev.signal_state(), 1, "the notification signal survives the take");
        assert!(waiters(ev).is_empty());
        assert_eq!(t.state(), ThreadState::Running);
        assert_eq!(t.quantum(), 5, "the wait it did not block on still costs its charge");
        assert_eq!(d.audit_waits(), Ok(()));
    }

    /// An already-signaled synchronization event satisfies the
    /// wait and consumes the signal: one signal serves exactly one
    /// waiter, even when the waiter arrives after the signal.
    #[test]
    fn a_signaled_synchronization_event_resets_on_the_take() {
        let d = dispatcher();
        let p = process(8);
        let t = thread(p);
        run(d, t);
        let ev = event(EventKind::Synchronization, true);

        assert_eq!(
            d.wait_single(t, ev.waitable(), WaitReason::Executive, WaitMode::Kernel, false, None, stamp(0, 0)),
            complete(STATUS_SUCCESS)
        );
        assert_eq!(ev.signal_state(), 0, "the take consumes the parked signal");

        // The next wait on the cleared event cannot be satisfied.
        assert_eq!(
            d.wait_single(t, ev.waitable(), WaitReason::Executive, WaitMode::Kernel, false, Some(0), stamp(0, 0)),
            complete(STATUS_TIMEOUT)
        );
    }

    /// The satisfaction dispatch keys on the signal state alone:
    /// every waitable kind decides by it (no owner-based branch
    /// exists for any kind). The thread object is no exception.
    #[test]
    fn the_satisfaction_dispatch_keys_on_the_signal_state() {
        let d = dispatcher();
        let p = process(8);
        let t = thread(p);
        let other = thread(p);

        block_on(d, t, other.waitable(), None);
        assert_eq!(t.state(), ThreadState::Waiting);

        other.waitable.signal_state = 1;
        d.satisfy_waiters(other.waitable(), 0);
        assert_eq!(t.state(), ThreadState::Ready);
        assert_eq!(t.wait_status(), STATUS_SUCCESS);
        assert_eq!(d.audit_waits(), Ok(()));
    }

    /// A zero timeout never blocks, even for an instant: no wait
    /// block is linked, the thread stays Running, and the quantum
    /// charge still runs.
    #[test]
    fn a_zero_timeout_never_blocks() {
        let d = dispatcher();
        let p = process(8);
        let t = thread(p);
        run(d, t);
        let ev = event(EventKind::Notification, false);

        assert_eq!(
            d.wait_single(t, ev.waitable(), WaitReason::Executive, WaitMode::Kernel, false, Some(0), stamp(0, 0)),
            complete(STATUS_TIMEOUT)
        );
        assert!(waiters(ev).is_empty());
        assert_eq!(t.state(), ThreadState::Running);
        assert_eq!(t.quantum(), 5);
    }

    /// At the wait entry, "the object is signaled now" dominates
    /// "the deadline passed now": a satisfied wait reports success
    /// even with a zero timeout, which is simply dropped.
    #[test]
    fn a_signaled_object_beats_a_due_deadline() {
        let d = dispatcher();
        let p = process(8);
        let t = thread(p);
        run(d, t);
        let ev = event(EventKind::Notification, true);

        assert_eq!(
            d.wait_single(t, ev.waitable(), WaitReason::Executive, WaitMode::Kernel, false, Some(0), stamp(0, 0)),
            complete(STATUS_SUCCESS)
        );
        assert_eq!(ev.signal_state(), 1);
    }

    /// A due time already past is the seam's verdict, not the
    /// wait's arithmetic: the wait hands the due time over, trusts
    /// the false, and reports a timeout without parking. A
    /// negative interval is an absolute due time — an absolute
    /// already past is the shape that reaches it.
    #[test]
    fn a_due_time_already_past_times_out_at_once() {
        let d = dispatcher();
        let p = process(8);
        let t = thread(p);
        run(d, t);
        let ev = event(EventKind::Notification, false);

        assert_eq!(
            d.wait_single(t, ev.waitable(), WaitReason::Executive, WaitMode::Kernel, false, Some(-5), stamp(10_000, 0)),
            complete(STATUS_TIMEOUT)
        );
        assert!(waiters(ev).is_empty());
        assert_eq!(t.state(), ThreadState::Running);
        assert!(!t.timer.inserted());
        assert_eq!(t.timer.waitable.signal_state(), 0, "the failed insert leaves the timer unsignaled");
        assert_eq!(t.quantum(), 5);
    }

    /// The no-wait quantum adjustment: the charge, the decay
    /// (floored only below the base), the realtime exemption, and
    /// the round-robin tail — installed only when the decay left
    /// the priority alone and the standby slot is empty.
    #[test]
    fn the_nowait_charge_exhausts_decays_and_round_robins() {
        let d = dispatcher();
        let p = process(8);

        // Exhaustion: the quantum resets and the priority decays
        // one step — 11 - 1 = 10, above the base, so no floor.
        let t = thread(p);
        run(d, t);
        t.priority = 11;
        t.quantum = 1;
        let signaled = event(EventKind::Notification, true);
        assert_eq!(
            d.wait_single(t, signaled.waitable(), WaitReason::Executive, WaitMode::Kernel, false, None, stamp(0, 0)),
            complete(STATUS_SUCCESS)
        );
        assert_eq!(t.quantum(), 6);
        assert_eq!(t.priority(), 10);
        assert_eq!(t.priority_decrement(), 0);
        assert!(d.next_thread().is_null(), "a decay that moved the priority installs nobody");

        // A positive quantum survives the charge with no decay.
        let t2 = thread(p);
        run(d, t2);
        t2.priority = 11;
        t2.quantum = 2;
        assert_eq!(
            d.wait_single(t2, signaled.waitable(), WaitReason::Executive, WaitMode::Kernel, false, None, stamp(0, 0)),
            complete(STATUS_SUCCESS)
        );
        assert_eq!(t2.quantum(), 1);
        assert_eq!(t2.priority(), 11);

        // A realtime thread is never adjusted at all.
        let t3 = thread(p);
        run(d, t3);
        t3.priority = 24;
        t3.quantum = 3;
        assert_eq!(
            d.wait_single(t3, signaled.waitable(), WaitReason::Executive, WaitMode::Kernel, false, None, stamp(0, 0)),
            complete(STATUS_SUCCESS)
        );
        assert_eq!(t3.quantum(), 3);
        assert_eq!(t3.priority(), 24);

        // The tail: exhaustion at the base leaves the priority
        // alone, and an equal-priority ready thread takes the
        // standby slot — round-robin among equals.
        let d2 = dispatcher();
        let t4 = thread(p);
        run(d2, t4);
        t4.quantum = 1;
        let other = thread(p);
        d2.make_ready(other);
        assert_eq!(
            d2.wait_single(t4, signaled.waitable(), WaitReason::Executive, WaitMode::Kernel, false, None, stamp(0, 0)),
            complete(STATUS_SUCCESS)
        );
        assert_eq!(t4.priority(), 8, "8 - 1 floors back at the base: unchanged");
        assert_eq!(d2.next_thread(), as_ptr(other));
        assert_eq!(other.state(), ThreadState::Standby);
        assert_eq!(t4.state(), ThreadState::Running, "the running thread keeps the processor until the switch");

        // Exclusivity: a pending standby blocks the install.
        let d3 = dispatcher();
        let t5 = thread(p);
        run(d3, t5);
        t5.quantum = 1;
        let pending = thread(p);
        pending.priority = 9;
        d3.make_ready(pending);
        assert_eq!(d3.next_thread(), as_ptr(pending), "the higher arrival took the standby slot");
        assert_eq!(
            d3.wait_single(t5, signaled.waitable(), WaitReason::Executive, WaitMode::Kernel, false, None, stamp(0, 0)),
            complete(STATUS_SUCCESS)
        );
        assert_eq!(d3.next_thread(), as_ptr(pending), "the pending standby is left alone");
    }

    // --- Group D: the signal side -------------------------------------------

    /// A notification event wakes every waiter present at set
    /// time, in wait order, and keeps its signal.
    #[test]
    fn a_notification_event_wakes_every_waiter_in_order() {
        let d = dispatcher();
        let p = process(8);
        let t1 = thread(p);
        let t2 = thread(p);
        let t3 = thread(p);
        let ev = event(EventKind::Notification, false);

        block_on(d, t1, ev.waitable(), None);
        block_on(d, t2, ev.waitable(), None);
        block_on(d, t3, ev.waitable(), None);

        assert_eq!(ev.set(d, EVENT_WAKE_INCREMENT), 0);
        assert_eq!(ev.signal_state(), 1, "a notification signal outlives the wake");
        assert!(waiters(ev).is_empty());
        for t in [&t1, &t2, &t3] {
            assert_eq!(t.state(), ThreadState::Ready);
            assert_eq!(t.wait_status(), STATUS_SUCCESS);
        }
        // Wake order preserved into the ready queue.
        assert_eq!(d.find_ready(0), as_ptr(t1));
        assert_eq!(d.find_ready(0), as_ptr(t2));
        assert_eq!(d.find_ready(0), as_ptr(t3));
        assert_eq!(d.audit_waits(), Ok(()));
    }

    /// A synchronization event's signal serves exactly one waiter
    /// — the head, the oldest — and the event is clear again
    /// after each set.
    #[test]
    fn a_synchronization_event_wakes_exactly_the_head_waiter() {
        let d = dispatcher();
        let p = process(8);
        let t1 = thread(p);
        let t2 = thread(p);
        let t3 = thread(p);
        let ev = event(EventKind::Synchronization, false);

        block_on(d, t1, ev.waitable(), None);
        block_on(d, t2, ev.waitable(), None);
        block_on(d, t3, ev.waitable(), None);

        ev.set(d, EVENT_WAKE_INCREMENT);
        assert_eq!(t1.state(), ThreadState::Ready);
        assert_eq!(t2.state(), ThreadState::Waiting);
        assert_eq!(t3.state(), ThreadState::Waiting);
        assert_eq!(ev.signal_state(), 0);
        assert_eq!(waiters(ev), vec![as_ptr(t2), as_ptr(t3)]);

        ev.set(d, EVENT_WAKE_INCREMENT);
        assert_eq!(t2.state(), ThreadState::Ready);
        ev.set(d, EVENT_WAKE_INCREMENT);
        assert_eq!(t3.state(), ThreadState::Ready);
        assert!(waiters(ev).is_empty());

        // With nobody left, the signal parks again.
        ev.set(d, EVENT_WAKE_INCREMENT);
        assert_eq!(ev.signal_state(), 1);
    }

    /// The synchronization fast path: with a single waiter the set
    /// serves it directly and the signal state is never written —
    /// it stays clear, which a one-waiter walk would have left
    /// anyway.
    #[test]
    fn the_synchronization_fast_path_leaves_the_state_clear() {
        let d = dispatcher();
        let p = process(8);
        let t = thread(p);
        let ev = event(EventKind::Synchronization, false);

        block_on(d, t, ev.waitable(), None);
        assert_eq!(ev.set(d, EVENT_WAKE_INCREMENT), 0);
        assert_eq!(ev.signal_state(), 0, "the state is never written on the fast path");
        assert_eq!(t.state(), ThreadState::Ready);
        assert_eq!(t.wait_status(), STATUS_SUCCESS);
    }

    /// A wait-all head block takes the notification path instead
    /// of the fast one: the state is written, the satisfy walk
    /// runs — and a claim whose chain holds an unsignaled object
    /// stays parked under the written signal.
    #[test]
    fn a_wait_all_head_takes_the_notification_path() {
        let d = dispatcher();
        let p = process(8);
        let t = thread(p);
        let a = event(EventKind::Synchronization, false);
        let b = event(EventKind::Notification, false);

        // A hand-wired wait-all claim: block on A, then grow the
        // chain to a second object block on B (the multiple-object
        // wait that would construct this is not built; the branch
        // it drives is).
        block_on(d, t, a.waitable(), None);
        let head = t.wait_block_head;
        let second = addr_of_mut!(t.wait_blocks[1]);
        // SAFETY: both blocks live inside the thread; the objects
        // are initialized, and the second block is on no list.
        unsafe {
            (*head).wait_all = true;
            (*second).thread = as_ptr(t);
            (*second).object = b.waitable();
            (*second).key = STATUS_SUCCESS;
            (*second).wait_all = false;
            (*head).next_block = second;
            (*second).next_block = head;
            b.waitable.waiters.push_back(addr_of_mut!((*second).links));
        }
        assert_eq!(d.audit_waits(), Ok(()));

        a.set(d, EVENT_WAKE_INCREMENT);
        assert_eq!(a.signal_state(), 1, "the notification path writes the signal");
        assert_eq!(t.state(), ThreadState::Waiting, "the unsignaled B parks the claim");
        assert_eq!(waiters(a), vec![as_ptr(t)]);
        assert_eq!(b.signal_state(), 0);
    }

    /// The wait exit's discipline: the status lands (OR'd in), the
    /// chain unwinds from every object, the timer cancels, the
    /// boost applies with its gate, the wait is charged, and the
    /// thread readies.
    #[test]
    fn the_wait_exit_unwinds_the_wait() {
        let d = dispatcher();
        let p = process(8);
        let t = thread(p);
        let ev = event(EventKind::Notification, false);

        block_on(d, t, ev.waitable(), Some(1_000_000));
        d.unwait(t, STATUS_SUCCESS, EVENT_WAKE_INCREMENT);

        assert_eq!(t.wait_status(), STATUS_SUCCESS);
        assert!(waiters(ev).is_empty());
        assert!(t.timer.waitable.waiters.is_empty(), "the timer block left the timer's list");
        assert!(!t.timer.inserted(), "the wake cancelled the timer");
        assert!(t.wait_block_head.is_null(), "the chain is gone until the next wait");
        assert_eq!(t.state(), ThreadState::Ready);
        assert_eq!(t.priority(), 9, "the wake boost: base 8 plus 1");
        assert_eq!(t.quantum(), 5, "boosted to a fresh quantum, then charged for the wait");
        assert_eq!(d.audit_waits(), Ok(()));

        // The status is OR'd in, not assigned: a pre-set status
        // survives the wake. The entry always zeroes the field, so
        // only a wake-time pre-set status can observe the
        // distinction here.
        let t2 = thread(p);
        block_on(d, t2, ev.waitable(), None);
        t2.wait_status = 0x80;
        d.unwait(t2, STATUS_SUCCESS, 0);
        assert_eq!(t2.wait_status(), 0x80);
    }

    /// Thread termination satisfies the thread object's waiters:
    /// the object signals once, forever, before the scheduling
    /// teardown, and a woken waiter is what the processor runs
    /// next.
    #[test]
    fn termination_satisfies_the_thread_waiters() {
        let d = dispatcher();
        let p = process(8);
        let main = thread(p);
        let child = thread(p);
        run(d, child);

        block_on(d, main, child.waitable(), None);
        let selected = d.terminate();

        assert!(child.signaled(), "the thread object signals at exit");
        assert_eq!(child.state(), ThreadState::Terminated);
        assert_eq!(main.state(), ThreadState::Ready);
        assert_eq!(main.wait_status(), STATUS_SUCCESS);
        assert_eq!(selected, as_ptr(main), "the woken waiter is the next thread");
        assert_eq!(d.audit_waits(), Ok(()));
    }

    // --- Group E: the timeout seam -------------------------------------------

    /// Due times come from the clock reading the caller took:
    /// due = now + interval, carried by the timer with the
    /// inserted mark. An already-past due is refused.
    #[test]
    fn due_times_come_from_the_clock_reading() {
        let d = dispatcher();
        let p = process(8);
        let t = thread(p);
        let ev = event(EventKind::Notification, false);

        match d.wait_single(
            t,
            ev.waitable(),
            WaitReason::Executive,
            WaitMode::Kernel,
            false,
            Some(2_000),
            stamp(5_000, 3),
        ) {
            WaitDisposition::Yield => {}
            _ => panic!("expected the wait to park the thread"),
        }
        assert_eq!(t.timer.due_time(), 7_000);
        assert!(t.timer.inserted());
        assert_eq!(d.audit_waits(), Ok(()));

        // The refused arm: an absolute due already past —
        // unsignaled and unheld.
        let t2 = thread(p);
        assert_eq!(
            d.wait_single(t2, ev.waitable(), WaitReason::Executive, WaitMode::Kernel, false, Some(-1), stamp(5_000, 3)),
            complete(STATUS_TIMEOUT)
        );
        assert!(!t2.timer.inserted());
        assert_eq!(t2.timer.waitable.signal_state(), 0);
    }

    /// Expiry through the seam entry: the timer signals, the walk
    /// unwakes the waiter with the planted timeout status and no
    /// boost, and the whole wait unwinds — the object block leaves
    /// the event too.
    #[test]
    fn expiry_delivers_the_timeout_through_the_seam() {
        let d = dispatcher();
        let p = process(8);
        let t = thread(p);
        let ev = event(EventKind::Notification, false);

        block_on(d, t, ev.waitable(), Some(1_000_000));
        d.expire_timer(addr_of_mut!(t.timer));

        assert_eq!(t.timer.waitable.signal_state(), 1);
        assert_eq!(t.wait_status(), STATUS_TIMEOUT);
        assert_eq!(t.state(), ThreadState::Ready);
        assert!(waiters(ev).is_empty());
        assert!(!t.timer.inserted());
        assert_eq!(t.priority(), 8, "the expiry grants no wake boost");
        assert_eq!(t.quantum(), 5);
        assert_eq!(d.audit_waits(), Ok(()));
    }

    /// A wake beats its expiry: the signal-side unwait cancels
    /// the timer, and the late expiry finds empty lists — a thread
    /// is never unwoken twice for one wait.
    #[test]
    fn a_wake_cancels_the_timer_and_the_late_expiry_is_a_no_op() {
        let d = dispatcher();
        let p = process(8);
        let t = thread(p);
        let ev = event(EventKind::Notification, false);

        block_on(d, t, ev.waitable(), Some(1_000_000));
        ev.set(d, EVENT_WAKE_INCREMENT);
        assert_eq!(t.wait_status(), STATUS_SUCCESS);
        assert!(!t.timer.inserted());

        d.expire_timer(addr_of_mut!(t.timer));
        assert_eq!(t.wait_status(), STATUS_SUCCESS, "the loser of the race finds empty lists");
        assert_eq!(t.state(), ThreadState::Ready);
        assert_eq!(d.audit_waits(), Ok(()));
    }

    /// An expiry beats its wake: the timeout wins, the object
    /// block unlinks, and the later set finds nobody — it only
    /// writes the signal.
    #[test]
    fn an_expiry_wins_and_the_late_set_finds_nobody() {
        let d = dispatcher();
        let p = process(8);
        let t = thread(p);
        let ev = event(EventKind::Notification, false);

        block_on(d, t, ev.waitable(), Some(1_000_000));
        d.expire_timer(addr_of_mut!(t.timer));
        assert_eq!(t.wait_status(), STATUS_TIMEOUT);

        assert_eq!(ev.set(d, EVENT_WAKE_INCREMENT), 0);
        assert_eq!(ev.signal_state(), 1, "the late set only writes the signal");
        assert_eq!(t.wait_status(), STATUS_TIMEOUT);
        assert_eq!(t.state(), ThreadState::Ready);
    }

    /// The delay wait: the chain is the timer block alone, the
    /// wake is the expiry, and a sleep that timed out completes as
    /// a success. An already-expired delay never parks: it drops a
    /// boosted thread to its base and hands the processor to an
    /// equal, or completes at once with nobody to take over.
    #[test]
    fn the_delay_wait_blocks_on_the_timer_alone() {
        let d = dispatcher();
        let p = process(8);
        let t = thread(p);
        run(d, t);
        t.priority = 11;

        match d.delay(t, WaitMode::User, false, 1_000_000, stamp(100, 1)) {
            WaitDisposition::Yield => {}
            _ => panic!("expected the delay to park the thread"),
        }
        assert_eq!(t.state(), ThreadState::Waiting);
        assert_eq!(t.wait_reason(), WaitReason::DelayExecution);
        assert!(eq(t.wait_block_head, addr_of_mut!(t.wait_blocks[TIMER_BLOCK])));
        // SAFETY: the chain is live for the wait.
        unsafe { assert!(eq((*t.wait_block_head).next_block, t.wait_block_head)) };
        assert!(t.timer.inserted());
        assert_eq!(t.timer.due_time(), 100 + 1_000_000);

        d.expire_timer(addr_of_mut!(t.timer));
        assert_eq!(t.wait_status(), STATUS_TIMEOUT);
        assert_eq!(Dispatcher::delay_completed(t.wait_status()), STATUS_SUCCESS);
    }

    /// The delay's yield arm: already expired, never a wait state.
    #[test]
    fn an_expired_delay_yields_the_processor() {
        // Nobody to take over: completes at once, boosted thread
        // dropped to its base, no wait state consumed.
        let d = dispatcher();
        let p = process(8);
        let t = thread(p);
        run(d, t);
        t.priority = 11;
        assert_eq!(
            d.delay(t, WaitMode::Kernel, false, -1, stamp(100, 1)),
            complete(STATUS_SUCCESS)
        );
        assert_eq!(t.priority(), 8, "the yield drops a boosted thread to its base");
        assert_eq!(t.state(), ThreadState::Running);
        assert!(!t.timer.inserted());
        assert_eq!(d.audit_waits(), Ok(()));

        // An equal ready to take over: the current thread is
        // readied with a fresh quantum and the delay yields.
        let d2 = dispatcher();
        let p2 = process(8);
        let t2 = thread(p2);
        run(d2, t2);
        t2.priority = 11;
        t2.quantum = 2;
        let other = thread(p2);
        d2.make_ready(other);

        match d2.delay(t2, WaitMode::Kernel, false, -1, stamp(100, 1)) {
            WaitDisposition::Yield => {}
            _ => panic!("expected the expired delay to yield"),
        }
        assert_eq!(t2.priority(), 8);
        assert_eq!(t2.state(), ThreadState::Ready);
        assert!(!t2.preempted);
        assert_eq!(t2.quantum(), 6, "the yielding thread takes a fresh quantum");
        assert_eq!(d2.next_thread(), as_ptr(other));
    }

    // --- Group F: cross-cutting invariants -----------------------------------

    /// The wait exit is the only owner of the Waiting state's
    /// exit: it lands the thread on the ready ladder, never
    /// directly on the processor.
    #[test]
    fn the_wait_exit_is_the_only_waiting_state_exit() {
        let d = dispatcher();
        let p = process(8);
        let t = thread(p);
        let ev = event(EventKind::Notification, false);

        block_on(d, t, ev.waitable(), None);
        d.unwait(t, STATUS_SUCCESS, 0);
        assert!(
            t.state() == ThreadState::Ready || t.state() == ThreadState::Standby,
            "the ready ladder, never a direct Running install"
        );
    }

    #[test]
    #[should_panic(expected = "the wait exit runs on a waiting thread")]
    fn the_wait_exit_refuses_a_running_thread() {
        let d = dispatcher();
        let p = process(8);
        let t = thread(p);
        run(d, t);
        d.unwait(t, 0, 0);
    }

    #[test]
    #[should_panic(expected = "the wait exit runs on a waiting thread")]
    fn the_wait_exit_refuses_a_ready_thread() {
        let d = dispatcher();
        let p = process(8);
        let t = thread(p);
        t.state = ThreadState::Ready;
        d.unwait(t, 0, 0);
    }

    #[test]
    #[should_panic(expected = "a waiting thread is readied only through the wait exit")]
    fn the_ready_path_refuses_a_waiting_thread() {
        let d = dispatcher();
        let p = process(8);
        let t = thread(p);
        let ev = event(EventKind::Notification, false);
        block_on(d, t, ev.waitable(), None);
        d.make_ready(t);
    }

    /// The wait-structure audit: consistent across objects and
    /// threads mid-flight and after wakes; a non-waiting thread
    /// on the waiting list is an audit failure.
    #[test]
    fn the_wait_audit_tracks_the_structures() {
        let d = dispatcher();
        let p = process(8);
        let ev_a = event(EventKind::Notification, false);
        let ev_b = event(EventKind::Synchronization, false);

        let t1 = thread(p);
        let t2 = thread(p);
        let t3 = thread(p);
        block_on(d, t1, ev_a.waitable(), Some(1_000_000));
        block_on(d, t2, ev_a.waitable(), None);
        block_on(d, t3, ev_b.waitable(), None);
        assert_eq!(d.audit_waits(), Ok(()), "mid-flight");

        ev_a.set(d, EVENT_WAKE_INCREMENT);
        assert_eq!(d.audit_waits(), Ok(()), "after the wake");

        // The negative: a thread on the waiting list that is not
        // waiting is an audit failure.
        let stray = thread(p);
        // SAFETY: the list is initialized; the stray thread's wait
        // link is detached.
        unsafe { d.waiting.push_back(addr_of_mut!(stray.wait_links)) };
        assert!(d.audit_waits().is_err());
    }

    /// The wake boost's cap and gate: computed past the cap lands
    /// at the top of the variable band, a realtime thread gets no
    /// boost and a full replenish, and a disabled or debt-carrying
    /// thread gets no boost but is still charged.
    #[test]
    fn the_wake_boost_caps_and_gates() {
        let d = dispatcher();
        let p15 = process(15);
        let capped = thread(p15);
        capped.priority = 15;
        block_on(d, capped, event(EventKind::Notification, false).waitable(), None);
        d.unwait(capped, STATUS_SUCCESS, EVENT_WAKE_INCREMENT);
        assert_eq!(capped.priority(), 15, "computed 16 lands capped at 15");
        assert_eq!(capped.quantum(), 6, "a time-critical base replenishes instead of charging");

        let p = process(8);
        let rt = thread(p);
        rt.priority = 16;
        rt.quantum = 2;
        block_on(d, rt, event(EventKind::Notification, false).waitable(), None);
        d.unwait(rt, STATUS_SUCCESS, EVENT_WAKE_INCREMENT);
        assert_eq!(rt.priority(), 16, "realtime: no boost");
        assert_eq!(rt.quantum(), 6, "realtime: full replenish");

        let gated = thread(p);
        gated.disable_boost = true;
        gated.quantum = 6;
        block_on(d, gated, event(EventKind::Notification, false).waitable(), None);
        d.unwait(gated, STATUS_SUCCESS, EVENT_WAKE_INCREMENT);
        assert_eq!(gated.priority(), 8, "the policy gate refuses the boost");
        assert_eq!(gated.quantum(), 5, "the charge is unconditional");

        let indebted = thread(p);
        indebted.priority_decrement = 2;
        indebted.quantum = 6;
        block_on(d, indebted, event(EventKind::Notification, false).waitable(), None);
        d.unwait(indebted, STATUS_SUCCESS, EVENT_WAKE_INCREMENT);
        assert_eq!(indebted.priority(), 8, "outstanding decay debt refuses the boost");
        assert_eq!(indebted.priority_decrement(), 2, "the debt survives a charge that does not exhaust");
        assert_eq!(indebted.quantum(), 5);
    }
}
