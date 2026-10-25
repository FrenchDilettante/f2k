//! The APC machinery: asynchronous procedure calls queued on a thread and delivered on it.
//!
//! An APC is a request to run code on a particular thread — the kernel's way to make a thread do
//! something at a point it did not choose. Each thread owns two queues, kernel-mode and user-mode;
//! the kernel queue is delivered here, the user queue on the thread's way back to user mode,
//! through ntdll's KiUserApcDispatcher (see [`crate::user::apc`]).
//!
//! The queue discipline keeps specials ahead of normals: a special (no normal routine) lands after
//! the queued specials, a normal at the tail — so delivery order is specials first, then normals in
//! the order queued. Delivery runs on the owning thread: every special runs its kernel routine to
//! completion; every normal runs its kernel routine, then — unless gated — its normal routine at
//! the passive level, one at a time. The one consumer is the builtin suspend APC: its normal
//! routine blocks on the thread's suspend semaphore, which is what suspending a thread is.
//!
//! Delivery happens wherever a thread resumes execution or stands at a window: the interrupt exit
//! and the service boundary (both through [`Dispatcher::deliver_pending`], after the dispatch
//! decision) and both context-switch tails (the wait exit and the preemption resume). A queued APC
//! on a Running thread is consumed at the next window; one on a Waiting thread breaks the wait —
//! the wait replays after delivery; one on a Ready thread waits for dispatch, and the resume tail
//! delivers it the moment the thread runs.
//!
//! One processor, no locking: every method runs serialized at the dispatch level, like the rest of
//! the scheduler.

use core::ptr::{addr_of_mut, eq, null_mut};

use super::dispatcher::Dispatcher;
use super::thread::{Thread, ThreadState};
use super::wait::{WaitMode, WaitReason};
use super::{link_before, unlink, Links, List};
use crate::interrupt::irql;
use crate::status::{
    NtStatus,
    STATUS_KERNEL_APC,
    STATUS_SUSPEND_COUNT_EXCEEDED,
    STATUS_THREAD_IS_TERMINATING,
    STATUS_USER_APC,
};

/// The priority increment a suspend wake grants: none.
pub const SUSPEND_WAKE_INCREMENT: i8 = 0;

/// The documented ceiling of a thread's suspend count.
pub const MAX_SUSPEND_COUNT: u8 = 127;

/// The suspend semaphore's count ceiling. Two, because a forced resume can release the semaphore
/// with nobody parked on it (the thread never delivered its suspend APC), and the residue count
/// plus a later release must both fit.
pub const SUSPEND_SEMAPHORE_LIMIT: i32 = 2;

/// Which of a thread's two APC queues an APC belongs to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum ApcMode {
    /// The kernel queue: delivered by this machinery.
    Kernel = 0,
    /// The user queue: delivered in user mode (see [`crate::user::apc`]).
    User = 1,
}

/// A normal routine: the code an APC's second half runs on the owning thread, at the passive
/// level. It receives the dispatcher and the thread it runs on, plus the context and arguments
/// captured at init and insert. It may block — the suspend APC's does.
pub type NormalRoutine = fn(&mut Dispatcher, &mut Thread, usize, usize, usize);

/// A kernel routine: the code an APC's first half runs on the owning thread, above the passive
/// level. The slots are in-out: the routine may cancel the normal half (by clearing it) or rewrite
/// what it receives.
pub type KernelRoutine = fn(&mut Dispatcher, &mut Apc, &mut ApcArgs);

/// The in-out slots a delivery hands a kernel routine.
#[derive(Clone, Copy)]
pub struct ApcArgs {
    /// The normal routine to run after the kernel routine, or none to cancel it.
    pub normal_routine: Option<NormalRoutine>,
    /// The context the normal routine receives.
    pub normal_context: usize,
    /// The first argument captured at insert.
    pub system_argument1: usize,
    /// The second argument captured at insert.
    pub system_argument2: usize,
}

/// An APC: a request to run code on one thread.
///
/// An intrusive object: it carries its own queue link, so queueing allocates nothing. An APC
/// belongs to its thread for its lifetime; it is queued at most once (the insertion flag refuses a
/// double queue).
#[repr(C)]
pub struct Apc {
    /// The queue membership link.
    pub(crate) links: Links,
    /// The thread the APC runs on. Valid for the APC's lifetime.
    pub(crate) thread: *mut Thread,
    /// The first half: runs above the passive level.
    pub(crate) kernel_routine: KernelRoutine,
    /// The second half: runs at the passive level, on the owning thread. None makes the APC
    /// special.
    pub(crate) normal_routine: Option<NormalRoutine>,
    /// Which of the thread's two queues this APC belongs to.
    pub(crate) mode: ApcMode,
    /// The context the normal routine receives. Forced to zero for a special.
    pub(crate) normal_context: usize,
    /// A user APC's routine: the user-mode address its delivery calls with the context and both
    /// system arguments (Windows 2000 keeps it as the normal routine; here that slot holds the
    /// user-mode marker, [`crate::user::apc::user_normal_routine`]). Zero for a kernel APC.
    pub(crate) user_routine: usize,
    /// The first system argument, captured at insert.
    pub(crate) system_argument1: usize,
    /// The second system argument, captured at insert.
    pub(crate) system_argument2: usize,
    /// Whether the APC is currently in a queue.
    pub(crate) inserted: bool,
}

impl Apc {
    /// A fresh, detached APC; call [`Apc::init`] once it is at its final address and its thread is
    /// known.
    pub const fn detached() -> Self {
        Apc {
            links: Links::detached(),
            thread: null_mut(),
            kernel_routine: nop_kernel_routine,
            normal_routine: None,
            mode: ApcMode::Kernel,
            normal_context: 0,
            user_routine: 0,
            system_argument1: 0,
            system_argument2: 0,
            inserted: false,
        }
    }

    /// Bind `self` to `thread`: the routines, the mode, and the context. A null normal routine
    /// makes the APC special and forces the mode to kernel and the context to zero — a special
    /// has no normal half to receive them.
    pub fn init(
        &mut self,
        thread: *mut Thread,
        kernel_routine: KernelRoutine,
        normal_routine: Option<NormalRoutine>,
        mode: ApcMode,
        normal_context: usize,
    ) {
        self.thread = thread;
        self.kernel_routine = kernel_routine;
        self.normal_routine = normal_routine;
        if normal_routine.is_some() {
            self.mode = mode;
            self.normal_context = normal_context;
        } else {
            self.mode = ApcMode::Kernel;
            self.normal_context = 0;
        }
        self.inserted = false;
    }

    /// Whether the APC is currently in a queue.
    pub fn inserted(&self) -> bool {
        self.inserted
    }
}

/// A kernel routine that does nothing: the default of a detached APC and the suspend APC's first
/// half (its work is all in the normal half).
pub fn nop_kernel_routine(_dispatcher: &mut Dispatcher, _apc: &mut Apc, _args: &mut ApcArgs) {}

/// The suspend APC's normal half: block the thread on its own suspend semaphore — kernel mode,
/// nonalertable, no timeout. A resume releases the semaphore and this returns into its delivery's
/// tail; until one does, the thread is suspended.
pub(crate) fn suspend_apc_normal(
    dispatcher: &mut Dispatcher,
    thread: &mut Thread,
    _context: usize,
    _argument1: usize,
    _argument2: usize,
) {
    let semaphore = addr_of_mut!(thread.suspend_semaphore);
    // The real park: the shared blocking entry, whose replay loop re-plants the wait if a kernel
    // APC breaks it.
    #[cfg(target_arch = "x86")]
    {
        let _ = dispatcher;
        super::wait::wait_current(
            unsafe { (*semaphore).waitable() },
            WaitReason::Suspension,
            None,
        );
    }
    // The host model: park through the wait entry; the delivery observes the Waiting state and its
    // driver continues it after the wake.
    #[cfg(not(target_arch = "x86"))]
    {
        let stamp = super::wait::ClockStamp {
            interrupt_time: 0,
            tick: 0,
        };
        let _ = dispatcher.wait_single(
            thread,
            unsafe { (*semaphore).waitable() },
            WaitReason::Suspension,
            WaitMode::Kernel,
            false,
            None,
            stamp,
        );
    }
}

/// The APC a list entry belongs to.
// SAFETY-contract: `entry` is the links field of a live Apc.
pub(crate) fn entry_to_apc(entry: *mut Links) -> *mut Apc {
    (entry as usize - core::mem::offset_of!(Apc, links)) as *mut Apc
}

impl Dispatcher {
    /// Queue `apc` on its thread, capturing the system arguments. Refused — with nothing touched —
    /// while the thread's APC queuing is off (it is terminating); the inner insert refuses a
    /// double queue. Returns whether the APC was queued.
    pub fn queue_apc(
        &mut self,
        apc: *mut Apc,
        argument1: usize,
        argument2: usize,
        increment: i8,
    ) -> bool {
        // SAFETY: the caller owns the APC record; it is live and not on any list unless inserted.
        let apc: &mut Apc = unsafe { &mut *apc };
        // SAFETY: the APC's thread pointer is valid for the APC's lifetime.
        if !unsafe { (*apc.thread).apc_queueable } {
            return false;
        }
        apc.system_argument1 = argument1;
        apc.system_argument2 = argument2;
        self.insert_apc(apc, increment)
    }

    /// The insert: position the APC in its queue and arm its thread. Position — normals at the
    /// tail, specials after every queued special; arming — the kernel pending flag, plus a wake
    /// for a thread whose wait an APC may break. A thread parked in a wait an APC cannot break (it
    /// is not at the passive level, or a normal APC is gated out by an in-progress normal or a
    /// disabled queue) stays parked: the flag is armed and the delivery happens at the thread's
    /// next resume. Returns whether the APC was queued (a double insert refuses).
    fn insert_apc(&mut self, apc: &mut Apc, increment: i8) -> bool {
        if apc.inserted {
            return false;
        }
        // SAFETY: the APC's thread pointer is valid for the APC's lifetime.
        let thread: &mut Thread = unsafe { &mut *apc.thread };
        let queue: &mut List = match apc.mode {
            ApcMode::Kernel => &mut thread.kernel_apcs,
            ApcMode::User => &mut thread.user_apcs,
        };

        // SAFETY: the queue is initialized at thread attach; the APC is on no list.
        unsafe {
            if apc.normal_routine.is_some() {
                queue.push_back(addr_of_mut!(apc.links));
            } else {
                // A special lands behind the last queued special: walk while the entries are
                // specials, then insert before the first normal (or at the tail if there is none —
                // an empty queue's walk starts at the sentinel).
                let sentinel = queue.sentinel();
                let mut probe = queue.first();
                if probe.is_null() {
                    probe = sentinel;
                }
                while !eq(probe, sentinel) {
                    let other = entry_to_apc(probe);
                    if (*other).normal_routine.is_some() {
                        break;
                    }
                    probe = (*probe).next;
                }
                link_before(probe, addr_of_mut!(apc.links));
            }
        }
        apc.inserted = true;

        match apc.mode {
            ApcMode::Kernel => {
                thread.kernel_apc_pending = true;
                // A Running thread consumes the flag at its next window (the interrupt exit or the
                // service boundary); a Ready or fresh thread at the resume tail that dispatches it.
                if thread.state == ThreadState::Waiting
                    && thread.wait_irql == irql::PASSIVE
                    && (apc.normal_routine.is_none()
                        || (thread.kernel_apc_disable == 0 && !thread.kernel_apc_in_progress))
                {
                    self.unwait(thread, STATUS_KERNEL_APC, increment);
                }
            }
            ApcMode::User => {
                // The user arm: an alertable user-mode wait breaks; nothing else (the delivery is
                // the thread's own, on its way back to user mode: `user::apc`). Not while the
                // thread is attached to another process's address space (see `super::attach`): the
                // APC waits queued until the thread is back on its own.
                if thread.state == ThreadState::Waiting
                    && thread.wait_mode == WaitMode::User
                    && thread.wait_alertable
                    && !thread.attached()
                {
                    thread.user_apc_pending = true;
                    self.unwait(thread, STATUS_USER_APC, increment);
                }
            }
        }
        true
    }

    /// Take an APC out of its queue. Returns whether it was queued. When the removal empties the
    /// queue, the mode's pending flag clears.
    pub fn remove_apc(&mut self, apc: *mut Apc) -> bool {
        // SAFETY: the caller owns the APC record.
        let apc: &mut Apc = unsafe { &mut *apc };
        if !apc.inserted {
            return false;
        }
        apc.inserted = false;
        // SAFETY: an inserted APC's link is wired into its thread's queue.
        unsafe { unlink(addr_of_mut!(apc.links)) };
        // SAFETY: the APC's thread pointer is valid for the APC's lifetime.
        let thread: &mut Thread = unsafe { &mut *apc.thread };
        let empty = match apc.mode {
            ApcMode::Kernel => thread.kernel_apcs.is_empty(),
            ApcMode::User => thread.user_apcs.is_empty(),
        };
        if empty {
            match apc.mode {
                ApcMode::Kernel => thread.kernel_apc_pending = false,
                ApcMode::User => thread.user_apc_pending = false,
            }
        }
        true
    }

    /// Take a thread's whole APC queue of `mode` out as one list, marking every entry not
    /// inserted; the pending flags are untouched (an armed flag over an empty queue is a harmless
    /// residue — the delivery's loop test never runs). Returns the first entry of the detached
    /// circle, or null if the queue was empty. The termination of a thread off the processor
    /// discards its queues through this; a self-exit asserts its queue empty instead.
    pub fn flush_apcs(thread: &mut Thread, mode: ApcMode) -> *mut Links {
        let queue: &mut List = match mode {
            ApcMode::Kernel => &mut thread.kernel_apcs,
            ApcMode::User => &mut thread.user_apcs,
        };
        if queue.is_empty() {
            return null_mut();
        }
        // SAFETY: the queue is initialized and non-empty; its head is a live APC's link.
        let first = unsafe { queue.first() };
        // Detach the circle: the sentinel leaves it and closes on itself, so the thread's queue is
        // genuinely empty again and the flushed entries keep their own circle.
        // SAFETY: the sentinel is linked; the unlink splices it out.
        unsafe {
            unlink(queue.sentinel());
            queue.init();
            // Mark every entry of the detached circle not inserted.
            let mut probe = first;
            loop {
                (*entry_to_apc(probe)).inserted = false;
                // SAFETY: a linked entry's next names the next entry; the circle closes at first.
                probe = (*probe).next;
                if eq(probe, first) {
                    break;
                }
            }
        }
        first
    }

    /// Deliver the running thread's queued kernel APCs. The pending flag clears on entry — before
    /// any delivery — so an APC arriving during the delivery re-arms for the next window instead of
    /// being lost. Specials run first and to completion; normals run kernel-routine-then-normal,
    /// the normal half at the passive level, one at a time, gated by an in-progress normal and the
    /// thread's disable count — a gated normal stops the delivery with the queue intact (deferred,
    /// not dropped). The user queue is not delivered here: a user APC runs in user mode (see
    /// [`crate::user::apc`]).
    pub fn deliver_kernel_apcs(&mut self) -> ApcDelivery {
        // SAFETY: the running thread, live and exclusive here (the serialized dispatcher).
        let thread: &mut Thread = unsafe { &mut *self.current_thread() };
        thread.kernel_apc_pending = false;

        while !thread.kernel_apcs.is_empty() {
            // SAFETY: the queue is initialized and non-empty; the head is a queued APC's link.
            let head = unsafe { thread.kernel_apcs.first() };
            // SAFETY: the head names a queued APC.
            let apc = unsafe { &mut *entry_to_apc(head) };
            if apc.normal_routine.is_none() {
                // A special: unlink, clear, run its kernel routine to completion. Its normal half
                // is the none it was made with; whatever the routine writes into the slots is
                // discarded.
                // SAFETY: the head is linked on this queue.
                unsafe { unlink(head) };
                apc.inserted = false;
                let mut args = ApcArgs {
                    normal_routine: apc.normal_routine,
                    normal_context: apc.normal_context,
                    system_argument1: apc.system_argument1,
                    system_argument2: apc.system_argument2,
                };
                (apc.kernel_routine)(self, apc, &mut args);
            } else {
                // A normal: gated by an in-progress normal and the disable count — the same pair
                // the insert's wake arm consults, so a thread that could not be woken for it cannot
                // run it either.
                if !thread.kernel_apc_in_progress && thread.kernel_apc_disable == 0 {
                    // SAFETY: the head is linked on this queue.
                    unsafe { unlink(head) };
                    apc.inserted = false;
                    let mut args = ApcArgs {
                        normal_routine: apc.normal_routine,
                        normal_context: apc.normal_context,
                        system_argument1: apc.system_argument1,
                        system_argument2: apc.system_argument2,
                    };
                    (apc.kernel_routine)(self, apc, &mut args);

                    if let Some(normal) = args.normal_routine {
                        thread.kernel_apc_in_progress = true;
                        // The passivate shape: the normal half runs at the passive level.
                        #[cfg(target_arch = "x86")]
                        irql::state_mut().lower(irql::PASSIVE);
                        normal(
                            self,
                            thread,
                            args.normal_context,
                            args.system_argument1,
                            args.system_argument2,
                        );
                        // A normal routine may block — the suspend APC's does. On the target the
                        // call does not return until the thread is woken and running again; in the
                        // host model the park is observable and the delivery's driver continues it
                        // (see [`Dispatcher::resume_kernel_apcs`]).
                        if thread.state == ThreadState::Waiting {
                            return ApcDelivery::Parked;
                        }
                        #[cfg(target_arch = "x86")]
                        irql::state_mut().raise(irql::APC);
                    }
                    thread.kernel_apc_in_progress = false;
                } else {
                    // Gated out: stop with the queue intact.
                    break;
                }
            }
        }
        ApcDelivery::Delivered
    }

    /// The parked delivery's continuation, host model only: the thread parked inside a normal
    /// routine (its wait completed and its driver made it current again); finish the arm — the
    /// level is back, in-progress clears, and the queue loop resumes. On the target the parked
    /// delivery resumes by returning from the normal routine; nothing calls this.
    #[cfg(not(target_arch = "x86"))]
    pub fn resume_kernel_apcs(&mut self) {
        // SAFETY: the running thread, live and exclusive here.
        let thread: &mut Thread = unsafe { &mut *self.current_thread() };
        thread.kernel_apc_in_progress = false;
        // The remaining queue: a second normal routine may park again; the driver continues
        // likewise.
        let parked = self.deliver_kernel_apcs();
        let _ = parked;
    }

    /// Deliver the running thread's pending kernel APCs at a delivery point: the interrupt-exit
    /// and service-boundary windows (after the dispatch decision) and both context-switch tails
    /// (before the parked caller reads its wait status). A no-op when nothing is pending.
    #[cfg(target_arch = "x86")]
    pub(crate) fn deliver_pending_apcs(&mut self) {
        // SAFETY: the running thread, live and exclusive here.
        if !unsafe { (*self.current_thread()).kernel_apc_pending } {
            return;
        }
        let previous = irql::state_mut().raise(irql::APC);
        self.deliver_kernel_apcs();
        irql::state_mut().lower(previous);
    }

    // --- The suspend consumer ------------------------------------------------

    /// Suspend `thread`: bump its suspend count and, at zero, arm its builtin suspend APC — the
    /// APC's delivery is what actually parks the thread. Above zero the count alone rises: one
    /// suspend APC holds any depth. Returns the previous count; refused outright (nothing touched)
    /// at the documented maximum or on a thread whose APC queuing is off (it is terminating).
    pub fn suspend_thread(&mut self, thread: &mut Thread) -> Result<u8, NtStatus> {
        let old = thread.suspend_count;
        if old == MAX_SUSPEND_COUNT {
            return Err(STATUS_SUSPEND_COUNT_EXCEEDED);
        }
        if !thread.apc_queueable {
            return Err(STATUS_THREAD_IS_TERMINATING);
        }
        thread.suspend_count += 1;
        if old == 0 && thread.freeze_count == 0 {
            let apc = addr_of_mut!(thread.suspend_apc);
            if !self.queue_apc(apc, 0, 0, SUSPEND_WAKE_INCREMENT) {
                // The suspend APC is still queued from an earlier suspend that a resume undid
                // before the thread ever delivered it: that resume released a count with nobody
                // parked. The queued APC serves this suspend; the count it would find must go, or
                // its wait would be satisfied at once and the thread would run on.
                let semaphore = &mut thread.suspend_semaphore.waitable;
                if semaphore.signal_state > 0 {
                    semaphore.signal_state -= 1;
                }
            }
        }
        Ok(old)
    }

    /// Resume `thread`: at one — and no freeze — release the suspend semaphore, which wakes the
    /// thread the suspend APC parked; above one the count alone drops. A thread nobody suspended
    /// is a no-op. Returns the previous count.
    pub fn resume_thread(&mut self, thread: &mut Thread) -> u8 {
        let old = thread.suspend_count;
        if old != 0 {
            thread.suspend_count -= 1;
            if thread.suspend_count == 0 && thread.freeze_count == 0 {
                let semaphore = addr_of_mut!(thread.suspend_semaphore);
                self.release_suspend_semaphore(unsafe { &mut *semaphore });
            }
        }
        old
    }

    /// Force-resume `thread`: zero both counts and release the semaphore unconditionally — the
    /// exit route for a thread terminated while suspended (it must run its own exit, so whatever
    /// parked it is released). The release may land with nobody parked: the residue count stays for
    /// the next delivery's satisfied wait to consume, bounded by the semaphore's ceiling. Returns
    /// the sum of the two counts.
    pub fn force_resume_thread(&mut self, thread: &mut Thread) -> u32 {
        let old = thread.suspend_count as u32 + thread.freeze_count as u32;
        thread.freeze_count = 0;
        thread.suspend_count = 0;
        let semaphore = addr_of_mut!(thread.suspend_semaphore);
        self.release_suspend_semaphore(unsafe { &mut *semaphore });
        old
    }
}

/// The exit path's APC steps: refuse further queuing on the thread, and require its kernel queue
/// empty — the thread was Running, so every delivery window (the service boundary, the interrupt
/// exit, the resume tails) had its chance. A queued kernel APC here means a delivery was missed
/// somewhere: a loud failure, not a silent drop.
pub fn close_apc_queue(thread: &mut Thread) {
    thread.apc_queueable = false;
    assert!(
        thread.kernel_apcs.is_empty(),
        "a self-exiting thread has a queued kernel APC"
    );
    // User APCs the thread never turned alertable for are discarded, their records freed.
    Dispatcher::flush_apcs(thread, ApcMode::User);
    thread.user_apc_pending = false;
}

/// What a delivery did.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ApcDelivery {
    /// The delivery ran to its end: the queue drained or a gated normal stopped it.
    Delivered,
    /// The delivery parked inside a normal routine (host model: the wait entry returned with the
    /// thread Waiting; its driver continues with [`Dispatcher::resume_kernel_apcs`]). The
    /// in-progress flag stays set while parked.
    Parked,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sched::dispatcher::Dispatcher;
    use crate::sched::event::{Event, EventKind};
    use crate::sched::process::SchedProcess;
    use crate::sched::wait::{ClockStamp, WaitDisposition, WaitMode, WaitReason, Waitable};

    // --- The rig ------------------------------------------------------------
    //
    // The same style as the dispatcher and wait tests: kernel objects live at fixed addresses for
    // as long as they are linked, so the rig leaks everything it creates. The routines an APC runs
    // write through the APC's context pointer, so every test owns its recorder and parallel tests
    // share nothing.

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

    fn stamp(interrupt_time: u64, tick: u64) -> ClockStamp {
        ClockStamp {
            interrupt_time,
            tick,
        }
    }

    /// Block `t` on `object` in a kernel-mode wait, asserting the wait parked it.
    fn block_on(d: &mut Dispatcher, t: &mut Thread, object: *mut Waitable, timeout: Option<i64>) {
        block_on_as(d, t, object, WaitMode::Kernel, false, timeout);
    }

    /// Block `t` on `object` in the given mode and alertability, asserting the wait parked it.
    fn block_on_as(
        d: &mut Dispatcher,
        t: &mut Thread,
        object: *mut Waitable,
        mode: WaitMode,
        alertable: bool,
        timeout: Option<i64>,
    ) {
        match d.wait_single(
            t,
            object,
            WaitReason::Executive,
            mode,
            alertable,
            timeout,
            stamp(10_000, 5),
        ) {
            WaitDisposition::Yield => {}
            _ => panic!("expected the wait to park the thread"),
        }
    }

    fn event(kind: EventKind, signaled: bool) -> &'static mut Event {
        let ev = Box::leak(Box::new(Event::new(kind, signaled)));
        ev.init();
        ev
    }

    /// The call log: the routines an APC runs record here. A thread-local, because the host model
    /// runs every delivery on the test's own thread — each test owns its log with no plumbing
    /// through the APC records (a special's context is forced nil by design).
    thread_local! {
        static CALLS: std::cell::RefCell<Vec<&'static str>> =
            const { std::cell::RefCell::new(Vec::new()) };
        static ARGUMENTS: std::cell::RefCell<Vec<usize>> =
            const { std::cell::RefCell::new(Vec::new()) };
    }

    fn record(call: &'static str) {
        CALLS.with(|log| log.borrow_mut().push(call));
    }

    fn recorded_calls() -> Vec<&'static str> {
        CALLS.with(|log| log.borrow().clone())
    }

    fn recorded_arguments() -> Vec<usize> {
        ARGUMENTS.with(|log| log.borrow().clone())
    }

    /// A recording kernel routine: logs the call and the pending flag's state at call time.
    fn recording_kernel(dispatcher: &mut Dispatcher, _apc: &mut Apc, _args: &mut ApcArgs) {
        let pending = unsafe { (*dispatcher.current_thread()).kernel_apc_pending };
        record(if pending {
            "kernel:pending-set"
        } else {
            "kernel:pending-clear"
        });
    }

    /// A recording normal routine: logs the call and the first argument it received.
    fn recording_normal(
        _dispatcher: &mut Dispatcher,
        _thread: &mut Thread,
        _context: usize,
        argument1: usize,
        _argument2: usize,
    ) {
        ARGUMENTS.with(|log| log.borrow_mut().push(argument1));
        record("normal");
    }

    /// A special APC with the recording kernel routine.
    fn special(t: &mut Thread) -> &'static mut Apc {
        let apc = Box::leak(Box::new(Apc::detached()));
        apc.init(t as *mut Thread, recording_kernel, None, ApcMode::Kernel, 0);
        apc
    }

    /// A normal kernel APC with both routines recording.
    fn normal(t: &mut Thread) -> &'static mut Apc {
        let apc = Box::leak(Box::new(Apc::detached()));
        apc.init(
            t as *mut Thread,
            recording_kernel,
            Some(recording_normal),
            ApcMode::Kernel,
            0,
        );
        apc
    }

    /// The APCs queued on `thread`'s kernel queue, in queue order.
    fn queued(thread: &mut Thread) -> Vec<*mut Apc> {
        let mut order = Vec::new();
        let sentinel = thread.kernel_apcs.sentinel();
        // SAFETY: the queue is initialized; the entries are queued APCs' links.
        let mut entry = unsafe { thread.kernel_apcs.first() };
        while !entry.is_null() && !eq(entry, sentinel) {
            order.push(entry_to_apc(entry));
            // SAFETY: a linked entry's next names the next entry.
            entry = unsafe { (*entry).next };
        }
        order
    }

    // --- Group A: the APC object ---------------------------------------------

    /// A1: init rules — a null normal routine forces the special defaults (mode kernel, context
    /// zero); a present one honors the caller's mode and context; every record starts detached.
    #[test]
    fn init_rules_null_normal_defaults() {
        let p = process(8);
        let t = thread(p);

        let present = Box::leak(Box::new(Apc::detached()));
        present.init(
            t,
            recording_kernel,
            Some(recording_normal),
            ApcMode::User,
            0x99,
        );
        assert_eq!(present.mode, ApcMode::User);
        assert_eq!(present.normal_context, 0x99);
        assert!(present.normal_routine.is_some());
        assert!(!present.inserted());

        let null = Box::leak(Box::new(Apc::detached()));
        null.init(t, recording_kernel, None, ApcMode::User, 0x99);
        assert_eq!(null.mode, ApcMode::Kernel, "a special's mode is forced");
        assert_eq!(null.normal_context, 0, "a special's context is forced nil");
        assert!(!null.inserted());

        let kernel = Box::leak(Box::new(Apc::detached()));
        kernel.init(
            t,
            recording_kernel,
            Some(recording_normal),
            ApcMode::Kernel,
            0,
        );
        assert_eq!(kernel.mode, ApcMode::Kernel);
    }

    /// A2: the insertion flag is the lifecycle — a double queue refuses with the queue untouched.
    #[test]
    fn the_insertion_flag_is_the_lifecycle() {
        let d = dispatcher();
        let p = process(8);
        let t = thread(p);
        run(d, t);
        let apc = special(t);

        assert!(d.queue_apc(apc, 0, 0, 0));
        assert!(apc.inserted());
        assert!(!d.queue_apc(apc, 0, 0, 0), "a double insert refuses");
        assert_eq!(queued(t).len(), 1);
    }

    /// A3: argument capture happens on the queueable path only — a refused insert must not
    /// overwrite an object a caller may inspect or re-queue later.
    #[test]
    fn arguments_capture_on_the_queueable_path_only() {
        let d = dispatcher();
        let p = process(8);
        let t = thread(p);
        run(d, t);
        let apc = special(t);

        t.apc_queueable = false;
        assert!(!d.queue_apc(apc, 7, 8, 0));
        assert_eq!(apc.system_argument1, 0);
        assert_eq!(apc.system_argument2, 0);
        assert!(!apc.inserted());

        t.apc_queueable = true;
        assert!(d.queue_apc(apc, 7, 8, 0));
        assert_eq!(apc.system_argument1, 7);
        assert_eq!(apc.system_argument2, 8);
    }

    /// A4: a terminated thread's insert is refused by the queueable gate — nothing queues, no flag
    /// arms, the terminated record is untouched.
    #[test]
    fn a_terminated_thread_refuses_inserts() {
        let d = dispatcher();
        let p = process(8);
        let t = thread(p);
        run(d, t);
        let apc = special(t);

        t.state = ThreadState::Terminated;
        t.apc_queueable = false;
        assert!(!d.queue_apc(apc, 0, 0, 0));
        assert!(queued(t).is_empty());
        assert!(!t.kernel_apc_pending);
        assert!(!t.user_apc_pending);
    }

    // --- Group B: queue discipline --------------------------------------------

    /// B1: normals queue at the tail, first in first out.
    #[test]
    fn normals_queue_at_the_tail() {
        let d = dispatcher();
        let p = process(8);
        let t = thread(p);
        run(d, t);
        let n1 = normal(t);
        let n2 = normal(t);
        let n3 = normal(t);

        d.queue_apc(n1, 0, 0, 0);
        d.queue_apc(n2, 0, 0, 0);
        d.queue_apc(n3, 0, 0, 0);
        assert_eq!(
            queued(t),
            vec![n1 as *mut Apc, n2 as *mut Apc, n3 as *mut Apc]
        );
    }

    /// B2: a special lands after the queued specials and before the first normal, whatever the
    /// insertion order.
    #[test]
    fn specials_land_before_the_first_normal() {
        let d = dispatcher();
        let p = process(8);
        let t = thread(p);
        run(d, t);
        let n1 = normal(t);
        let s1 = special(t);
        let s2 = special(t);
        let n2 = normal(t);

        d.queue_apc(n1, 0, 0, 0);
        d.queue_apc(s1, 0, 0, 0);
        d.queue_apc(s2, 0, 0, 0);
        d.queue_apc(n2, 0, 0, 0);
        assert_eq!(
            queued(t),
            vec![
                s1 as *mut Apc,
                s2 as *mut Apc,
                n1 as *mut Apc,
                n2 as *mut Apc
            ]
        );
    }

    /// B3: there is no front-insert special case for user-mode normals — every normal queues at
    /// the tail. (The one shape that would front-insert is a user-mode thread-exit APC, and this
    /// kernel has no such producer.)
    #[test]
    fn user_normals_queue_at_the_tail_like_any_normal() {
        let d = dispatcher();
        let p = process(8);
        let t = thread(p);
        run(d, t);
        let first = normal(t);
        let user = Box::leak(Box::new(Apc::detached()));
        user.init(
            t,
            recording_kernel,
            Some(recording_normal),
            ApcMode::User,
            0,
        );

        d.queue_apc(first, 0, 0, 0);
        d.queue_apc(user, 0, 0, 0);
        assert_eq!(
            queued(t),
            vec![first as *mut Apc],
            "the user APC queues on its own list, not the kernel one"
        );
        // The user queue holds its one entry, at the tail.
        let mut user_queue = Vec::new();
        let sentinel = t.user_apcs.sentinel();
        // SAFETY: the queue is initialized.
        let mut entry = unsafe { t.user_apcs.first() };
        while !entry.is_null() && !eq(entry, sentinel) {
            user_queue.push(entry_to_apc(entry));
            // SAFETY: a linked entry's next names the next entry.
            entry = unsafe { (*entry).next };
        }
        assert_eq!(user_queue, vec![user as *mut Apc]);
    }

    /// B4: remove — the flag, the unlink, and the pending side effect only when the queue empties.
    #[test]
    fn remove_clears_the_flag_and_the_emptied_queue_s_pending() {
        let d = dispatcher();
        let p = process(8);
        let t = thread(p);
        run(d, t);
        let s1 = special(t);
        let n1 = normal(t);

        d.queue_apc(s1, 0, 0, 0);
        d.queue_apc(n1, 0, 0, 0);
        assert!(t.kernel_apc_pending);

        assert!(d.remove_apc(s1));
        assert!(!s1.inserted());
        assert!(
            t.kernel_apc_pending,
            "one entry remains: the flag stays armed"
        );

        assert!(d.remove_apc(n1));
        assert!(!t.kernel_apc_pending, "the queue emptied: the flag clears");

        assert!(!d.remove_apc(n1), "a second remove refuses");
        assert!(queued(t).is_empty());
    }

    /// B5: flush — the queue comes out as one list with every entry uninserted, and the pending
    /// flag is untouched (the armed flag over the empty queue is a harmless residue).
    #[test]
    fn flush_takes_the_queue_and_leaves_the_flag() {
        let d = dispatcher();
        let p = process(8);
        let t = thread(p);
        run(d, t);
        let s1 = special(t);
        let n1 = normal(t);

        d.queue_apc(s1, 0, 0, 0);
        d.queue_apc(n1, 0, 0, 0);

        let first = Dispatcher::flush_apcs(t, ApcMode::Kernel);
        assert!(eq(first, addr_of_mut!(s1.links)));
        assert!(!s1.inserted());
        assert!(!n1.inserted());
        assert!(t.kernel_apcs.is_empty(), "the queue is genuinely empty");
        assert!(
            t.kernel_apc_pending,
            "the flush does not touch the pending flag"
        );

        // The detached circle: s1 -> n1 -> s1.
        // SAFETY: the flushed circle's links are wired among the entries.
        unsafe {
            assert!(eq((*addr_of_mut!(s1.links)).next, addr_of_mut!(n1.links)));
            assert!(eq((*addr_of_mut!(n1.links)).next, addr_of_mut!(s1.links)));
        }

        // An empty flush returns null.
        assert!(Dispatcher::flush_apcs(t, ApcMode::Kernel).is_null());
    }

    // --- Group C: the pending arms ---------------------------------------------

    /// C1: a kernel APC on a Running thread arms the standing window — the flag sets, nothing
    /// moves.
    #[test]
    fn a_kernel_apc_on_a_running_thread_arms_the_window() {
        let d = dispatcher();
        let p = process(8);
        let t = thread(p);
        run(d, t);
        let apc = special(t);

        assert!(d.queue_apc(apc, 0, 0, 0));
        assert!(t.kernel_apc_pending);
        assert_eq!(t.state(), ThreadState::Running);
        assert!(d.next_thread().is_null());
        assert!(queued(t).len() == 1);
    }

    /// C2: a special APC breaks a waiting thread's wait at the passive level — the wake is the
    /// ordinary wait exit with the APC status.
    #[test]
    fn a_special_apc_breaks_a_passive_wait() {
        let d = dispatcher();
        let p = process(8);
        let t = thread(p);
        run(d, t);
        let ev = event(EventKind::Notification, false);
        block_on(d, t, ev.waitable(), Some(1_000_000));
        let apc = special(t);

        assert!(d.queue_apc(apc, 0, 0, 0));
        assert_eq!(t.state(), ThreadState::Ready, "the wait exit readied it");
        assert_eq!(t.wait_status(), STATUS_KERNEL_APC);
        assert!(
            ev.waitable.waiters.is_empty(),
            "the wake unlinked the block"
        );
        assert!(!t.timer.inserted(), "the wake cancelled the wait's timer");
    }

    /// C3: a normal APC's unwait arm is gated by the disable count and the in-progress flag — the
    /// queueing itself never is.
    #[test]
    fn the_normal_apc_unwait_arm_is_gated() {
        let d = dispatcher();
        let p = process(8);
        let ev = event(EventKind::Notification, false);

        let t1 = thread(p);
        run(d, t1);
        t1.kernel_apc_disable = 1;
        block_on(d, t1, ev.waitable(), None);

        let t2 = thread(p);
        run(d, t2);
        block_on(d, t2, ev.waitable(), None);

        let t3 = thread(p);
        run(d, t3);
        t3.kernel_apc_in_progress = true;
        block_on(d, t3, ev.waitable(), None);

        for (i, parked) in [t1, t2, t3].into_iter().enumerate() {
            let apc = normal(parked);
            assert!(d.queue_apc(apc, 0, 0, 0), "the queueing itself is ungated");
            assert!(parked.kernel_apc_pending);
            if i == 1 {
                assert_eq!(
                    parked.state(),
                    ThreadState::Ready,
                    "the ungated one unwaits"
                );
                assert_eq!(parked.wait_status(), STATUS_KERNEL_APC);
            } else {
                assert_eq!(
                    parked.state(),
                    ThreadState::Waiting,
                    "the gated ones stay parked"
                );
            }
        }
    }

    /// C4: the wait-level gate — a wait entered above the passive level is not APC-breakable.
    #[test]
    fn a_wait_above_the_passive_level_is_not_breakable() {
        let d = dispatcher();
        let p = process(8);
        let t = thread(p);
        run(d, t);
        let ev = event(EventKind::Notification, false);
        block_on(d, t, ev.waitable(), None);
        // The rig-only raised-level wait.
        t.wait_irql = irql::APC;
        let apc = special(t);

        assert!(d.queue_apc(apc, 0, 0, 0));
        assert!(t.kernel_apc_pending);
        assert_eq!(t.state(), ThreadState::Waiting, "the arm refuses to unwait");
    }

    /// C5: a kernel APC on a Ready thread arms nothing but the flag — the smoke's exact kernel-side
    /// pre-state (a suspended spinner is Ready when the suspend lands).
    #[test]
    fn a_ready_thread_arms_only_the_flag() {
        let d = dispatcher();
        let p = process(8);
        let main = thread(p);
        run(d, main);
        let worker = thread(p);
        // The worker is Ready: queued at its priority, not current.
        d.make_ready(worker);
        let apc = normal(worker);

        assert!(d.queue_apc(apc, 0, 0, 0));
        assert!(worker.kernel_apc_pending);
        assert_eq!(worker.state(), ThreadState::Ready);
        assert!(core::ptr::eq(
            d.current_thread(),
            main as *const Thread as *mut Thread
        ));
        assert!(d.next_thread().is_null());
    }

    /// C6: the user arm — an alertable user-mode wait breaks with the user-APC status; nothing else
    /// does. No F2K code builds a user APC; this exercises the armed data.
    #[test]
    fn the_user_arm_breaks_only_an_alertable_user_wait() {
        let d = dispatcher();
        let p = process(8);
        let ev = event(EventKind::Notification, false);

        let t1 = thread(p);
        run(d, t1);
        block_on_as(d, t1, ev.waitable(), WaitMode::User, true, None);

        let t2 = thread(p);
        run(d, t2);
        block_on_as(d, t2, ev.waitable(), WaitMode::User, false, None);

        let t3 = thread(p);
        run(d, t3);
        block_on_as(d, t3, ev.waitable(), WaitMode::Kernel, true, None);

        let t4 = thread(p);
        run(d, t4);

        for (i, parked) in [t1, t2, t3, t4].into_iter().enumerate() {
            let apc = Box::leak(Box::new(Apc::detached()));
            apc.init(
                parked,
                recording_kernel,
                Some(recording_normal),
                ApcMode::User,
                0,
            );
            assert!(d.queue_apc(apc, 0, 0, 0));
            if i == 0 {
                assert_eq!(parked.state(), ThreadState::Ready);
                assert_eq!(parked.wait_status(), STATUS_USER_APC);
                assert!(parked.user_apc_pending);
            } else {
                assert!(
                    parked.state() == ThreadState::Waiting
                        || parked.state() == ThreadState::Running,
                    "no other state changes"
                );
                assert!(!parked.user_apc_pending);
            }
        }
    }

    // --- Group D: delivery -----------------------------------------------------

    /// D1: the pending flag clears on entry, before any delivery — a routine arriving during the
    /// delivery re-arms for the next window instead of being lost.
    #[test]
    fn the_pending_flag_clears_on_entry() {
        let d = dispatcher();
        let p = process(8);
        let t = thread(p);
        run(d, t);
        let apc = special(t);
        d.queue_apc(apc, 0, 0, 0);

        assert_eq!(d.deliver_kernel_apcs(), ApcDelivery::Delivered);
        assert_eq!(recorded_calls(), vec!["kernel:pending-clear"]);
        assert!(queued(t).is_empty());
        assert!(!t.kernel_apc_pending);
    }

    /// D2: specials deliver first, in queue order, ahead of every normal queued before them.
    #[test]
    fn specials_deliver_first() {
        let d = dispatcher();
        let p = process(8);
        let t = thread(p);
        run(d, t);
        let n1 = normal(t);
        let s1 = special(t);
        let s2 = special(t);
        d.queue_apc(n1, 0, 0, 0);
        d.queue_apc(s1, 0, 0, 0);
        d.queue_apc(s2, 0, 0, 0);

        assert_eq!(d.deliver_kernel_apcs(), ApcDelivery::Delivered);
        assert_eq!(
            recorded_calls(),
            vec![
                "kernel:pending-clear",
                "kernel:pending-clear",
                "kernel:pending-clear",
                "normal"
            ]
        );
    }

    /// D3: the normal arm's order and bracket — the kernel routine first, then the normal routine
    /// with the in-progress flag set inside it and cleared after, the captured arguments received.
    #[test]
    fn the_normal_arm_brackets_the_normal_routine() {
        let d = dispatcher();
        let p = process(8);
        let t = thread(p);
        run(d, t);
        let apc = normal(t);
        d.queue_apc(apc, 0x11, 0x22, 0);

        assert_eq!(d.deliver_kernel_apcs(), ApcDelivery::Delivered);
        assert_eq!(recorded_calls(), vec!["kernel:pending-clear", "normal"]);
        assert_eq!(
            recorded_arguments(),
            vec![0x11],
            "the first captured argument"
        );
        assert!(!t.kernel_apc_in_progress, "the bracket closed");
        assert!(queued(t).is_empty());
    }

    /// A kernel routine may cancel the normal half through the in-out slots.
    #[test]
    fn a_kernel_routine_may_cancel_the_normal_half() {
        fn cancel_normal(_dispatcher: &mut Dispatcher, _apc: &mut Apc, args: &mut ApcArgs) {
            args.normal_routine = None;
        }
        let d = dispatcher();
        let p = process(8);
        let t = thread(p);
        run(d, t);
        let apc = Box::leak(Box::new(Apc::detached()));
        apc.init(t, cancel_normal, Some(recording_normal), ApcMode::Kernel, 0);
        d.queue_apc(apc, 0, 0, 0);

        assert_eq!(d.deliver_kernel_apcs(), ApcDelivery::Delivered);
        assert!(
            recorded_calls().is_empty(),
            "no routine with a recorder ran"
        );
        assert!(queued(t).is_empty());
    }

    /// D4: the normal arm's gates stop the delivery with the queue intact — deferred, not dropped.
    #[test]
    fn the_normal_arm_gates_stop_the_delivery() {
        let d = dispatcher();
        let p = process(8);
        let t = thread(p);
        run(d, t);
        let gated = normal(t);
        d.queue_apc(gated, 0, 0, 0);

        t.kernel_apc_disable = 1;
        assert_eq!(d.deliver_kernel_apcs(), ApcDelivery::Delivered);
        assert!(recorded_calls().is_empty(), "nothing ran");
        assert!(gated.inserted(), "the queue is intact");
        assert!(!t.kernel_apc_pending, "the entry flag was still cleared");

        t.kernel_apc_disable = 0;
        t.kernel_apc_in_progress = true;
        assert_eq!(d.deliver_kernel_apcs(), ApcDelivery::Delivered);
        assert!(recorded_calls().is_empty());

        // Ungated: the deferred APC delivers.
        t.kernel_apc_in_progress = false;
        t.kernel_apc_pending = true;
        assert_eq!(d.deliver_kernel_apcs(), ApcDelivery::Delivered);
        assert_eq!(recorded_calls(), vec!["kernel:pending-clear", "normal"]);
    }

    /// D5: the queue-empty stop, the armed-empty-flag no-op, and the special delivering ahead of a
    /// gated normal (the gate is per entry, not global).
    #[test]
    fn delivery_stops_on_the_empty_queue_and_gates_per_entry() {
        let d = dispatcher();
        let p = process(8);
        let t = thread(p);
        run(d, t);

        // The armed flag over an empty queue: a no-op.
        t.kernel_apc_pending = true;
        assert_eq!(d.deliver_kernel_apcs(), ApcDelivery::Delivered);
        assert!(!t.kernel_apc_pending);

        // A special behind a gated normal: the special delivers, the normal stays queued.
        let gated = normal(t);
        let s1 = special(t);
        d.queue_apc(gated, 0, 0, 0);
        d.queue_apc(s1, 0, 0, 0);
        t.kernel_apc_disable = 1;
        assert_eq!(d.deliver_kernel_apcs(), ApcDelivery::Delivered);
        assert_eq!(
            recorded_calls(),
            vec!["kernel:pending-clear"],
            "only the special ran"
        );
        assert!(gated.inserted());
        assert!(queued(t).len() == 1);
    }

    /// D6: the kernel delivery leaves the user queue alone — a user APC queued with its pending
    /// flag set delivers nothing here (its delivery is in user mode), its queue untouched.
    #[test]
    fn nothing_delivers_a_user_apc() {
        let d = dispatcher();
        let p = process(8);
        let t = thread(p);
        run(d, t);
        let apc = Box::leak(Box::new(Apc::detached()));
        apc.init(
            t,
            recording_kernel,
            Some(recording_normal),
            ApcMode::User,
            0,
        );
        d.queue_apc(apc, 0, 0, 0);
        t.user_apc_pending = true;

        assert_eq!(d.deliver_kernel_apcs(), ApcDelivery::Delivered);
        assert!(recorded_calls().is_empty(), "no user routine ran");
        assert!(apc.inserted(), "the user queue is untouched");
        assert!(t.user_apc_pending, "the armed flag stays");
    }

    // --- Group F: the suspend consumer -------------------------------------------

    /// F1: the count table, suspend side — the APC queues once at zero, and above zero only the
    /// count rises. The returns are the previous counts.
    #[test]
    fn suspend_queues_once_and_returns_the_previous_count() {
        let d = dispatcher();
        let p = process(8);
        let t = thread(p);
        run(d, t);

        assert_eq!(d.suspend_thread(t), Ok(0));
        assert_eq!(t.suspend_count, 1);
        assert!(t.suspend_apc.inserted());
        assert!(t.kernel_apc_pending, "armed per its state (Running)");

        assert_eq!(d.suspend_thread(t), Ok(1));
        assert_eq!(t.suspend_count, 2);
        assert!(queued(t).len() == 1, "the APC is not re-queued");
    }

    /// F2: the count table, resume side — the release happens at one only; a resume at zero is a
    /// no-op returning zero.
    #[test]
    fn resume_releases_at_one_and_no_ops_at_zero() {
        let d = dispatcher();
        let p = process(8);
        let t = thread(p);
        run(d, t);
        d.suspend_thread(t).unwrap();
        d.suspend_thread(t).unwrap();

        assert_eq!(d.resume_thread(t), 2);
        assert_eq!(t.suspend_count, 1);
        assert_eq!(t.suspend_semaphore.count(), 0, "no release yet");

        assert_eq!(d.resume_thread(t), 1);
        assert_eq!(t.suspend_count, 0);
        assert_eq!(t.suspend_semaphore.count(), 1, "the release happened");

        assert_eq!(d.resume_thread(t), 0);
        assert_eq!(
            t.suspend_semaphore.count(),
            1,
            "the no-op row releases nothing"
        );
    }

    /// F3: the overflow — the count stays at the documented maximum and the caller sees the error.
    #[test]
    fn the_suspend_overflow_is_refused() {
        let d = dispatcher();
        let p = process(8);
        let t = thread(p);
        run(d, t);
        t.suspend_count = MAX_SUSPEND_COUNT;

        assert_eq!(
            d.suspend_thread(t),
            Err(crate::status::STATUS_SUSPEND_COUNT_EXCEEDED)
        );
        assert_eq!(t.suspend_count, MAX_SUSPEND_COUNT);
        assert!(!t.suspend_apc.inserted());
    }

    /// F4: the suspend APC's delivery — the nop kernel half, then the normal half parks the thread
    /// on its own suspend semaphore; the delivery suspends inside the routine with the in-progress
    /// flag set, and the resume's wake completes it.
    #[test]
    fn the_suspend_apc_delivery_parks_and_resumes() {
        let d = dispatcher();
        let p = process(8);
        let t = thread(p);
        run(d, t);
        d.suspend_thread(t).unwrap();

        assert_eq!(d.deliver_kernel_apcs(), ApcDelivery::Parked);
        assert_eq!(t.state(), ThreadState::Waiting);
        assert_eq!(t.wait_reason, WaitReason::Suspension);
        assert_eq!(t.wait_mode, WaitMode::Kernel);
        assert!(!t.wait_alertable);
        assert!(!t.timer.inserted(), "no timeout");
        assert_eq!(t.suspend_semaphore.count(), 0);
        assert!(!t.suspend_apc.inserted(), "the APC was taken for delivery");
        assert!(
            t.kernel_apc_in_progress,
            "the delivery is suspended mid-routine"
        );

        // The resume: the release wakes the parked thread through the satisfy walk; the dispatcher
        // re-runs it (the host driver of the switch the release would schedule).
        assert_eq!(d.resume_thread(t), 1);
        assert_eq!(t.state(), ThreadState::Ready);
        run(d, t);

        // The parked delivery's continuation: the routine returns, the bracket closes, the queue
        // is empty, and the thread is Running and un-suspended.
        d.resume_kernel_apcs();
        assert!(!t.kernel_apc_in_progress);
        assert!(t.kernel_apcs.is_empty());
        assert_eq!(
            t.suspend_semaphore.count(),
            0,
            "the satisfied wait consumed it"
        );
    }

    /// F6b: a suspend that finds the APC still queued — an earlier suspend that a resume undid
    /// before the thread delivered it — takes back the count that resume left with nobody parked:
    /// the queued APC then parks the thread, however many such pairs came before.
    #[test]
    fn a_suspend_over_a_still_queued_apc_takes_back_the_residue() {
        let d = dispatcher();
        let p = process(8);
        let target = thread(p);
        let caller = thread(p);
        run(d, caller);
        d.make_ready(target);

        for _ in 0..3 {
            assert_eq!(d.suspend_thread(target), Ok(0));
            assert_eq!(d.resume_thread(target), 1);
        }
        assert_eq!(d.suspend_thread(target), Ok(0));
        assert!(target.suspend_apc.inserted());
        assert_eq!(target.suspend_semaphore.count(), 0, "no residue left");

        // The target runs and delivers: it parks, suspended.
        run(d, target);
        assert_eq!(d.deliver_kernel_apcs(), ApcDelivery::Parked);
        assert_eq!(target.state(), ThreadState::Waiting);
    }

    /// F7: force-resume — the exit route's unconditional release, waiter or not; the waiter-less
    /// release leaves the residue count.
    #[test]
    fn force_resume_releases_waiter_or_not() {
        // (a): the parked case — the release wakes exactly like a resume.
        let d = dispatcher();
        let p = process(8);
        let parked = thread(p);
        run(d, parked);
        d.suspend_thread(parked).unwrap();
        assert_eq!(d.deliver_kernel_apcs(), ApcDelivery::Parked);

        assert_eq!(d.force_resume_thread(parked), 1);
        assert_eq!(parked.suspend_count, 0);
        assert_eq!(parked.freeze_count, 0);
        assert_eq!(parked.state(), ThreadState::Ready);

        // (b): the undelivered case — the APC is queued but its thread was never dispatched, so
        // the release lands with nobody parked and the residue count stays.
        let d = dispatcher();
        let p = process(8);
        let ready = thread(p);
        run(d, ready);
        d.suspend_thread(ready).unwrap();
        assert_eq!(
            ready.state(),
            ThreadState::Running,
            "the C1 arm: no movement"
        );

        assert_eq!(d.force_resume_thread(ready), 1);
        assert_eq!(ready.suspend_count, 0);
        assert_eq!(
            ready.suspend_semaphore.count(),
            1,
            "the waiter-less residue"
        );
        // The queued APC stays: a delivery that finds the count signaled takes it at once.
        assert!(ready.suspend_apc.inserted());
    }

    /// F8: the freeze-count rows — the gates read the constant-zero field; the rows hold at zero
    /// (F1/F2's table) and the gate is live data.
    #[test]
    fn the_freeze_gates_read_the_constant_zero_field() {
        let d = dispatcher();
        let p = process(8);
        let t = thread(p);
        run(d, t);

        // The rig-only producer: a frozen thread's suspend raises the count without queueing, and
        // its resume lowers it without releasing.
        t.freeze_count = 1;
        assert_eq!(d.suspend_thread(t), Ok(0));
        assert_eq!(t.suspend_count, 1);
        assert!(
            !t.suspend_apc.inserted(),
            "the freeze gate refused the queue"
        );
        assert_eq!(d.resume_thread(t), 1);
        assert_eq!(t.suspend_count, 0);
        assert_eq!(t.suspend_semaphore.count(), 0, "no release");

        // The forced resume zeroes both.
        t.freeze_count = 1;
        t.suspend_count = 1;
        assert_eq!(d.force_resume_thread(t), 2);
        assert_eq!(t.freeze_count, 0);
        assert_eq!(t.suspend_count, 0);
        assert_eq!(t.suspend_semaphore.count(), 1);

        // The real state: with the field at its actual zero, the count table of F1/F2 holds.
        assert_eq!(d.suspend_thread(t), Ok(0));
        assert!(t.suspend_apc.inserted());
    }

    // --- Group G: the terminate side ----------------------------------------------

    /// G1: the exit closes the queue — queuing refuses, and the empty check passes with nothing
    /// queued; a queued kernel APC at the exit is the loud failure.
    #[test]
    fn the_exit_closes_the_queue() {
        let p = process(8);
        let t = thread(p);

        // The no-APC variant passes.
        close_apc_queue(t);
        assert!(!t.apc_queueable);
        let d = dispatcher();
        assert!(!d.queue_apc(addr_of_mut!(t.suspend_apc), 0, 0, 0));
        assert!(!t.suspend_apc.inserted());

        // The queued variant is the bug condition: the check refuses loudly.
        let p = process(8);
        let leaked = thread(p);
        let apc = special(leaked);
        let d = dispatcher();
        run(d, leaked);
        d.queue_apc(apc, 0, 0, 0);
        let refused = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            close_apc_queue(leaked);
        }));
        assert!(refused.is_err(), "a queued kernel APC at exit fails loudly");
    }

    /// G2: a suspended thread's exit route — the forced resume wakes the parked delivery so the
    /// thread can run on.
    #[test]
    fn a_suspended_threads_exit_route_force_resumes() {
        let d = dispatcher();
        let p = process(8);
        let t = thread(p);
        run(d, t);
        d.suspend_thread(t).unwrap();
        assert_eq!(d.deliver_kernel_apcs(), ApcDelivery::Parked);

        // The termination's step: the force-resume releases, the wake readies, and the delivery
        // completes — after which the exit's queue check passes.
        d.force_resume_thread(t);
        assert_eq!(t.state(), ThreadState::Ready);
        run(d, t);
        d.resume_kernel_apcs();
        close_apc_queue(t);
    }

    /// G2b: a suspended thread terminated by another — the process-ending fault's route. It never
    /// runs its own exit: its parked wait on the suspend semaphore is unwound, a still-queued APC
    /// is discarded, and the semaphore is left with no waiter.
    #[test]
    fn a_suspended_thread_terminated_by_another_leaves_nothing_parked() {
        // Parked inside the suspend APC's normal routine.
        let d = dispatcher();
        let p = process(8);
        let suspended = thread(p);
        let killer = thread(p);
        run(d, suspended);
        d.suspend_thread(suspended).unwrap();
        assert_eq!(d.deliver_kernel_apcs(), ApcDelivery::Parked);
        run(d, killer);

        d.terminate_other(suspended);
        assert_eq!(suspended.state(), ThreadState::Terminated);
        assert!(suspended.suspend_semaphore.waitable.waiters.is_empty());
        assert!(!d.has_schedulable());
        assert_eq!(d.audit(), Ok(()));

        // Suspended but never dispatched: the APC is still queued, and the termination discards
        // it — queue empty, flags down, the record no longer inserted.
        let d = dispatcher();
        let p = process(8);
        let queued = thread(p);
        let killer = thread(p);
        run(d, killer);
        d.make_ready(queued);
        d.suspend_thread(queued).unwrap();
        assert!(queued.suspend_apc.inserted());

        d.terminate_other(queued);
        assert_eq!(queued.state(), ThreadState::Terminated);
        assert!(queued.kernel_apcs.is_empty());
        assert!(!queued.kernel_apc_pending);
        assert!(!queued.suspend_apc.inserted());
        assert!(!queued.apc_queueable);
        assert_eq!(d.audit(), Ok(()));
    }

    /// G3: suspend of an exiting or exited thread is refused — the count does not move.
    #[test]
    fn suspend_of_a_terminated_thread_is_refused() {
        let d = dispatcher();
        let p = process(8);
        let t = thread(p);
        run(d, t);
        t.state = ThreadState::Terminated;
        close_apc_queue(t);

        assert_eq!(
            d.suspend_thread(t),
            Err(crate::status::STATUS_THREAD_IS_TERMINATING)
        );
        assert_eq!(t.suspend_count, 0);
        assert!(!t.suspend_apc.inserted());
    }
}
