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
//! the passive level, one at a time. The consumers are the thread's two builtin APCs: the suspend
//! APC, whose normal routine blocks on the thread's suspend semaphore, which is what suspending a
//! thread is; and the exit APC, whose normal routine runs the thread's own exit, which is what
//! terminating another thread is (see [`Dispatcher::request_termination`]).
//!
//! [`Dispatcher::request_termination`]: super::dispatcher::Dispatcher::request_termination
//!
//! Delivery happens wherever a thread resumes execution or stands at a window: the interrupt exit
//! and the service boundary (both through [`super::dispatcher::deliver_pending`], after the
//! dispatch decision) and both context-switch tails (the wait exit and the preemption resume). A
//! queued APC on a Running thread is consumed at the next window; one on a Waiting thread breaks
//! the wait — the wait replays after delivery; one on a Ready thread waits for dispatch, and the
//! resume tail delivers it the moment the thread runs. A window opens for kernel APCs only at the
//! passive level, as Windows 2000's APC interrupt fires only when the level drops below the APC
//! level: a thread holding a short lock (raised to the APC level), or waiting for one, is neither
//! suspended nor terminated nor handed a routine until it lowers, and the next window after that
//! delivers — a wait it enters at the passive level among them, which delivers before it blocks.
//! A normal kernel APC also waits for the thread's critical regions to end (the outermost's end
//! opens a window), and every kernel APC for a scope attached to another process's address space
//! to end (Windows 2000 queues a thread's own APCs in its saved APC state meanwhile).
//!
//! The routines run outside the dispatcher, as Windows 2000's KiDeliverApc releases the APC queue
//! lock before it calls them: the delivery takes the head of the queue in one borrow of the
//! dispatcher, ends it, and calls; a routine that needs the dispatcher (the suspend APC's waits)
//! takes it itself.
//!
//! The APC records are the dispatcher database's: a thread's builtin suspend APC, a waitable
//! timer's completion APC, and the user-APC records QueueUserAPC takes (each process its own
//! share of them). The queues link them by name.
//!
//! One processor, no locking: every method runs serialized, like the rest of the scheduler.

use super::dispatcher::Dispatcher;
use super::list::{self, Link, ListKind};
use super::thread::{ThreadId, ThreadState};
use super::wait::{WaitMode, WaitReason, WaitableId};
use crate::interrupt::irql;
use crate::level::{raised, Dispatch};
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

/// An APC record's name in the dispatcher database.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ApcId {
    /// The thread's builtin suspend APC.
    Suspend(ThreadId),
    /// The thread's exit APC, its termination's.
    Exit(ThreadId),
    /// The completion APC of the waitable timer at its pool index.
    Timer(u16),
    /// The user-APC record at its pool index.
    User(u16),
}

/// An APC record names itself: the queueing entry points take the record or its id alike.
impl From<&mut Apc> for ApcId {
    fn from(apc: &mut Apc) -> Self {
        apc.id
    }
}

impl From<&Apc> for ApcId {
    fn from(apc: &Apc) -> Self {
        apc.id
    }
}

/// One thread's APC queue of one mode.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ApcQueue {
    pub thread: ThreadId,
    pub mode: ApcMode,
}

impl ListKind for ApcQueue {
    type Entry = ApcId;
}

/// A normal routine: the code an APC's second half runs on the owning thread, at the passive
/// level, with no dispatcher borrow live. It receives the thread it runs on, plus the context and
/// arguments captured at init and insert. It may block — the suspend APC's does.
pub type NormalRoutine = fn(ThreadId, usize, usize, usize);

/// A kernel routine: the code an APC's first half runs on the owning thread, at the APC level, with
/// no dispatcher borrow live. The slots are in-out: the routine may cancel the normal half (by
/// clearing it) or rewrite what it receives.
pub type KernelRoutine = fn(ApcId, &mut ApcArgs);

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
/// It carries its own queue link, so queueing allocates nothing. An APC belongs to its thread
/// while bound to it; it is queued at most once (the insertion flag refuses a double queue).
pub struct Apc {
    /// The queue membership.
    pub(crate) link: Link<ApcQueue>,
    /// The thread the APC runs on, none before its first binding.
    pub(crate) thread: Option<ThreadId>,
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
    /// The record's own name in the database.
    pub(crate) id: ApcId,
}

impl Apc {
    /// A fresh, unbound APC record named `id`.
    pub const fn new(id: ApcId) -> Self {
        Apc {
            link: Link::detached(),
            thread: None,
            kernel_routine: nop_kernel_routine,
            normal_routine: None,
            mode: ApcMode::Kernel,
            normal_context: 0,
            user_routine: 0,
            system_argument1: 0,
            system_argument2: 0,
            inserted: false,
            id,
        }
    }

    /// Bind `self` to `thread`: the routines, the mode, and the context. No normal routine
    /// makes the APC special and forces the mode to kernel and the context to zero — a special
    /// has no normal half to receive them.
    pub fn init(
        &mut self,
        thread: impl Into<ThreadId>,
        kernel_routine: KernelRoutine,
        normal_routine: Option<NormalRoutine>,
        mode: ApcMode,
        normal_context: usize,
    ) {
        self.thread = Some(thread.into());
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

    /// The record's name.
    pub fn id(&self) -> ApcId {
        self.id
    }

    /// The thread the APC is bound to.
    pub fn thread(&self) -> Option<ThreadId> {
        self.thread
    }

    /// Whether the APC is currently in a queue.
    pub fn inserted(&self) -> bool {
        self.inserted
    }

    /// The slots a delivery hands the kernel routine: the normal half and what the APC captured.
    fn args(&self) -> ApcArgs {
        ApcArgs {
            normal_routine: self.normal_routine,
            normal_context: self.normal_context,
            system_argument1: self.system_argument1,
            system_argument2: self.system_argument2,
        }
    }

    /// The queue the APC joins: its thread's, of its mode.
    fn queue(&self) -> ApcQueue {
        ApcQueue {
            thread: self.thread.expect("a queued APC is bound to a thread"),
            mode: self.mode,
        }
    }
}

/// A kernel routine that does nothing: the default of an unbound APC and the suspend APC's first
/// half (its work is all in the normal half).
pub fn nop_kernel_routine(_apc: ApcId, _args: &mut ApcArgs) {}

/// The suspend APC's normal half: block the thread on its own suspend semaphore — kernel mode,
/// nonalertable, no timeout. A resume releases the semaphore and this returns into its delivery's
/// tail; until one does, the thread is suspended.
pub(crate) fn suspend_apc_normal(
    thread: ThreadId,
    _context: usize,
    _argument1: usize,
    _argument2: usize,
) {
    // The real park: the shared blocking entry, whose replay loop re-plants the wait if a kernel
    // APC breaks it.
    #[cfg(target_arch = "x86")]
    super::wait::wait_current_for(WaitableId::Suspend(thread), WaitReason::Suspension, None);
    // The host model: park through the wait entry; the delivery observes the Waiting state and its
    // driver continues it after the wake.
    #[cfg(not(target_arch = "x86"))]
    {
        let stamp = super::wait::ClockStamp {
            interrupt_time: 0,
            tick: 0,
        };
        let _ = crate::level::raised::<Dispatch, _>(|dispatch| {
            super::DISPATCHER.get(dispatch).wait_for(
                thread,
                WaitableId::Suspend(thread),
                WaitReason::Suspension,
                WaitMode::Kernel,
                false,
                None,
                stamp,
            )
        });
    }
}

impl Dispatcher {
    /// Queue `apc` on its thread, capturing the system arguments. Refused — with nothing touched —
    /// while the thread's APC queuing is off (it is terminating); the inner insert refuses a
    /// double queue. Returns whether the APC was queued.
    pub fn queue_apc(
        &mut self,
        apc: impl Into<ApcId>,
        argument1: usize,
        argument2: usize,
        increment: i8,
    ) -> bool {
        let apc = apc.into();
        let thread = self.apc(apc).queue().thread;
        if !self.thread(thread).apc_queueable {
            return false;
        }
        let record = self.apc_mut(apc);
        record.system_argument1 = argument1;
        record.system_argument2 = argument2;
        self.insert_apc(apc, increment)
    }

    /// The insert: position the APC in its queue and arm its thread. Position — normals at the
    /// tail, specials after every queued special; arming — the kernel pending flag, plus a wake
    /// for a thread whose wait an APC may break. A thread parked in a wait an APC cannot break (it
    /// is not at the passive level, it runs attached to another process's address space, or a
    /// normal APC is gated out by an in-progress normal or a disabled queue) stays parked: the flag
    /// is armed and the delivery happens at the thread's next resume. Returns whether the APC was
    /// queued (a double insert refuses).
    fn insert_apc(&mut self, apc: ApcId, increment: i8) -> bool {
        let record = self.apc(apc);
        if record.inserted {
            return false;
        }
        let queue = record.queue();
        let special = record.normal_routine.is_none();
        if special {
            // A special lands behind the last queued special: walk while the entries are
            // specials, then insert before the first normal (or at the tail if there is none).
            let mut probe = list::first(self, queue);
            while let Some(other) = probe {
                if self.apc(other).normal_routine.is_some() {
                    break;
                }
                probe = self.apc(other).link.next();
            }
            list::insert_before(self, queue, probe, apc);
        } else {
            list::push_back(self, queue, apc);
        }
        self.apc_mut(apc).inserted = true;

        let thread = self.thread_mut(queue.thread);
        match queue.mode {
            ApcMode::Kernel => {
                thread.kernel_apc_pending = true;
                // A Running thread consumes the flag at its next window (the interrupt exit or the
                // service boundary); a Ready or fresh thread at the resume tail that dispatches it.
                if thread.state == ThreadState::Waiting
                    && thread.wait_irql == irql::PASSIVE
                    && !thread.attached()
                    && (special
                        || (thread.kernel_apc_disable == 0 && !thread.kernel_apc_in_progress))
                {
                    self.unwait(queue.thread, STATUS_KERNEL_APC, increment);
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
                    self.unwait(queue.thread, STATUS_USER_APC, increment);
                }
            }
        }
        true
    }

    /// Take an APC out of its queue. Returns whether it was queued. When the removal empties the
    /// queue, the mode's pending flag clears.
    pub fn remove_apc(&mut self, apc: impl Into<ApcId>) -> bool {
        let apc = apc.into();
        let record = self.apc_mut(apc);
        if !record.inserted {
            return false;
        }
        record.inserted = false;
        let queue = record.queue();
        list::remove(self, queue, apc);
        if list::is_empty(self, queue) {
            let thread = self.thread_mut(queue.thread);
            match queue.mode {
                ApcMode::Kernel => thread.kernel_apc_pending = false,
                ApcMode::User => thread.user_apc_pending = false,
            }
        }
        true
    }

    /// Empty `thread`'s APC queue of `mode`, marking every entry not inserted; the pending flags
    /// are untouched (an armed flag over an empty queue is a harmless residue — the delivery's loop
    /// test never runs). Returns how many were queued. A termination's request and the exit's own
    /// start discard the thread's queues through this.
    pub fn flush_apcs(&mut self, thread: ThreadId, mode: ApcMode) -> usize {
        let queue = ApcQueue { thread, mode };
        let mut flushed = 0;
        while let Some(apc) = list::pop_front(self, queue) {
            self.apc_mut(apc).inserted = false;
            flushed += 1;
        }
        flushed
    }

    /// The first APC of `thread`'s queue of `mode`, none when it is empty.
    pub fn first_apc(&self, thread: ThreadId, mode: ApcMode) -> Option<ApcId> {
        list::first(self, ApcQueue { thread, mode })
    }

    /// The delivery's step under the dispatcher (the part of Windows 2000's KiDeliverApc that holds
    /// the APC queue lock): take the head of `thread`'s kernel queue for its delivery, unless the
    /// queue is empty, the thread runs attached to another process's address space, or the head
    /// is a normal APC the thread's state gates out — an in-progress normal or a critical region —
    /// the gates the insert's wake arm consults, so a thread that could not be woken for it cannot
    /// run it either. A gated APC stays queued (deferred, not dropped): the region's end, or the
    /// detach, arms its delivery again.
    fn next_kernel_apc(&mut self, thread: ThreadId) -> Option<KernelApc> {
        let queue = ApcQueue {
            thread,
            mode: ApcMode::Kernel,
        };
        let head = list::first(self, queue)?;
        let special = self.apc(head).normal_routine.is_none();
        let record = self.thread(thread);
        if record.attached()
            || (!special && (record.kernel_apc_in_progress || record.kernel_apc_disable != 0))
        {
            return None;
        }
        let args = self.take_queued(queue, head);
        Some(KernelApc {
            apc: head,
            kernel_routine: self.apc(head).kernel_routine,
            special,
            args,
        })
    }

    /// Take the queue's head `apc` off for its delivery, and capture what its routines receive.
    fn take_queued(&mut self, queue: ApcQueue, apc: ApcId) -> ApcArgs {
        list::remove(self, queue, apc);
        let record = self.apc_mut(apc);
        record.inserted = false;
        record.args()
    }

    // --- The suspend consumer ------------------------------------------------

    /// Suspend `thread`: bump its suspend count and, at zero, arm its builtin suspend APC — the
    /// APC's delivery is what actually parks the thread. Above zero the count alone rises: one
    /// suspend APC holds any depth. Returns the previous count; refused outright (nothing touched)
    /// at the documented maximum or on a thread whose APC queuing is off (it is terminating).
    pub fn suspend_thread(&mut self, thread: impl Into<ThreadId>) -> Result<u8, NtStatus> {
        let thread = thread.into();
        let record = self.thread_mut(thread);
        let old = record.suspend_count;
        if old == MAX_SUSPEND_COUNT {
            return Err(STATUS_SUSPEND_COUNT_EXCEEDED);
        }
        if !record.apc_queueable {
            return Err(STATUS_THREAD_IS_TERMINATING);
        }
        record.suspend_count += 1;
        if old == 0
            && record.freeze_count == 0
            && !self.queue_apc(ApcId::Suspend(thread), 0, 0, SUSPEND_WAKE_INCREMENT)
        {
            // The suspend APC is still queued from an earlier suspend that a resume undid before
            // the thread ever delivered it: that resume released a count with nobody parked. The
            // queued APC serves this suspend; the count it would find must go, or its wait would
            // be satisfied at once and the thread would run on.
            let semaphore = &mut self.thread_mut(thread).suspend_semaphore.waitable;
            if semaphore.signal_state > 0 {
                semaphore.signal_state -= 1;
            }
        }
        Ok(old)
    }

    /// Resume `thread`: at one — and no freeze — release the suspend semaphore, which wakes the
    /// thread the suspend APC parked; above one the count alone drops. A thread nobody suspended
    /// is a no-op. Returns the previous count.
    pub fn resume_thread(&mut self, thread: impl Into<ThreadId>) -> u8 {
        let thread = thread.into();
        let record = self.thread_mut(thread);
        let old = record.suspend_count;
        if old != 0 {
            record.suspend_count -= 1;
            if record.suspend_count == 0 && record.freeze_count == 0 {
                self.release_suspend_semaphore(thread);
            }
        }
        old
    }

    /// Force-resume `thread`: zero both counts and release the semaphore unconditionally — the
    /// exit route for a thread terminated while suspended (it must run its own exit, so whatever
    /// parked it is released). The release may land with nobody parked: the residue count stays for
    /// the next delivery's satisfied wait to consume, bounded by the semaphore's ceiling. Returns
    /// the sum of the two counts.
    pub fn force_resume_thread(&mut self, thread: impl Into<ThreadId>) -> u32 {
        let thread = thread.into();
        let record = self.thread_mut(thread);
        let old = record.suspend_count as u32 + record.freeze_count as u32;
        record.freeze_count = 0;
        record.suspend_count = 0;
        self.release_suspend_semaphore(thread);
        old
    }

    /// The exit path's APC steps, as its own exit begins (Windows 2000's PspExitThread disables
    /// the thread's APC queuing and runs its queues down): refuse further queuing on the thread,
    /// and discard what is queued — the user APCs it never turned alertable for (their records
    /// freed), and a kernel APC that had no window before the exit (a suspend, or a
    /// termination's exit APC, which the exit under way supersedes). Nothing delivers on the
    /// thread from here on.
    pub fn close_apc_queue(&mut self, thread: ThreadId) {
        self.thread_mut(thread).apc_queueable = false;
        self.discard_apcs(thread);
    }

    /// Discard `thread`'s queued APCs of both modes and their pending flags.
    pub(super) fn discard_apcs(&mut self, thread: ThreadId) {
        self.flush_apcs(thread, ApcMode::Kernel);
        self.flush_apcs(thread, ApcMode::User);
        let record = self.thread_mut(thread);
        record.kernel_apc_pending = false;
        record.user_apc_pending = false;
    }
}

/// A kernel APC taken off its queue for delivery: what its routines receive.
struct KernelApc {
    apc: ApcId,
    kernel_routine: KernelRoutine,
    /// No normal half: it runs to completion, ungated.
    special: bool,
    args: ApcArgs,
}

/// Deliver the running thread's queued kernel APCs (the kernel half of Windows 2000's
/// KiDeliverApc), entered at the passive level. The pending flag clears on entry — before any
/// delivery — so an APC arriving during the delivery re-arms for the next window instead of being
/// lost. The delivery runs at the APC level: specials run first and to completion; normals run
/// kernel-routine-then-normal, the normal half lowered back to the passive level, one at a time,
/// gated by an in-progress normal and the thread's critical regions — a gated normal stops the
/// delivery with the queue intact. Each APC is taken off its queue in a borrow of the dispatcher
/// that ends before its routines run. The user queue is not delivered here: a user APC runs in
/// user mode (see [`crate::user::apc`]).
pub fn deliver_kernel_apcs() -> ApcDelivery {
    let pcr = crate::pcr::pcr();
    let thread = super::current_thread();
    raised::<Dispatch, _>(|dispatch| {
        super::DISPATCHER
            .get(dispatch)
            .thread_mut(thread)
            .kernel_apc_pending = false
    });
    let mut entered = pcr.raise(irql::APC);
    debug_assert_eq!(
        entered.level(),
        irql::PASSIVE,
        "kernel APCs deliver from passive"
    );

    while let Some(KernelApc {
        apc,
        kernel_routine,
        special,
        mut args,
    }) =
        raised::<Dispatch, _>(|dispatch| super::DISPATCHER.get(dispatch).next_kernel_apc(thread))
    {
        // A special's normal half is the none it was made with; whatever its kernel routine writes
        // into the slots is discarded.
        kernel_routine(apc, &mut args);
        if special {
            continue;
        }
        if let Some(normal) = args.normal_routine {
            raised::<Dispatch, _>(|dispatch| {
                super::DISPATCHER
                    .get(dispatch)
                    .thread_mut(thread)
                    .kernel_apc_in_progress = true
            });
            // The normal half runs at the passive level the delivery was entered from.
            pcr.lower(entered);
            normal(
                thread,
                args.normal_context,
                args.system_argument1,
                args.system_argument2,
            );
            // A normal routine may block — the suspend APC's does. On the target the call does not
            // return until the thread is woken and running again; in the host model the park is
            // observable and the delivery's driver continues it, at the passive level (see
            // [`resume_kernel_apcs`]).
            if raised::<Dispatch, _>(|dispatch| {
                super::DISPATCHER.get(dispatch).thread(thread).state == ThreadState::Waiting
            }) {
                return ApcDelivery::Parked;
            }
            entered = pcr.raise(irql::APC);
        }
        raised::<Dispatch, _>(|dispatch| {
            super::DISPATCHER
                .get(dispatch)
                .thread_mut(thread)
                .kernel_apc_in_progress = false
        });
    }
    pcr.lower(entered);
    ApcDelivery::Delivered
}

/// The parked delivery's continuation, host model only: the thread parked inside a normal routine
/// (its wait completed and its driver made it current again); finish the arm — in-progress clears,
/// and the queue loop resumes. On the target the parked delivery resumes by returning from the
/// normal routine; nothing calls this.
#[cfg(not(target_arch = "x86"))]
pub fn resume_kernel_apcs() {
    let thread = super::current_thread();
    raised::<Dispatch, _>(|dispatch| {
        super::DISPATCHER
            .get(dispatch)
            .thread_mut(thread)
            .kernel_apc_in_progress = false
    });
    // The remaining queue: a second normal routine may park again; the driver continues likewise.
    let _ = deliver_kernel_apcs();
}

/// Deliver the running thread's pending kernel APCs at a delivery point: the interrupt-exit and
/// service-boundary windows (after the dispatch decision), both context-switch tails (before the
/// parked caller reads its wait status), and a fresh thread's startup. A no-op when nothing is
/// pending, and above the passive level: a thread at the APC level (a short lock's holder, or a
/// delivery already running) is not interrupted for its APCs, which wait for the next window at
/// the passive level.
pub(crate) fn deliver_pending_apcs() {
    let Some(thread) = super::try_current_thread() else {
        return;
    };
    if crate::pcr::pcr().current() != irql::PASSIVE {
        return;
    }
    if !raised::<Dispatch, _>(|dispatch| {
        super::DISPATCHER
            .get(dispatch)
            .thread(thread)
            .kernel_apc_pending
    }) {
        return;
    }
    let _ = deliver_kernel_apcs();
}

/// What a delivery did.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ApcDelivery {
    /// The delivery ran to its end: the queue drained or a gated normal stopped it.
    Delivered,
    /// The delivery parked inside a normal routine (host model: the wait entry returned with the
    /// thread Waiting; its driver continues with [`resume_kernel_apcs`]). The in-progress flag
    /// stays set while parked.
    Parked,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sched::dispatcher::Dispatcher;
    use crate::sched::event::{Event, EventKind};
    use crate::sched::process::SchedProcess;
    use crate::sched::testkit::Rec;
    use crate::sched::thread::Thread;
    use crate::sched::wait::{ClockStamp, WaitDisposition, WaitMode, WaitReason, Waitable};

    // --- The rig ------------------------------------------------------------
    //
    // The same style as the dispatcher and wait tests: kernel objects live at fixed addresses for
    // as long as they are linked, so the rig leaks everything it creates. The routines an APC runs
    // write through the APC's context pointer, so every test owns its recorder and parallel tests
    // share nothing.

    fn dispatcher() -> &'static mut Dispatcher {
        crate::sched::testkit::dispatcher()
    }

    fn process(base: i8) -> *mut SchedProcess {
        let p = Box::leak(Box::new(SchedProcess::new(0x0090_0000, base)));
        p as *mut SchedProcess
    }

    fn thread(p: *mut SchedProcess) -> Rec<Thread> {
        crate::sched::testkit::thread(p)
    }

    /// Run `t` as the processor's current thread.
    fn run(d: &mut Dispatcher, mut t: Rec<Thread>) {
        d.enter(t.id());
        t.state = ThreadState::Running;
    }

    fn stamp(interrupt_time: u64, tick: u64) -> ClockStamp {
        ClockStamp {
            interrupt_time,
            tick,
        }
    }

    /// Block `t` on `object` in a kernel-mode wait, asserting the wait parked it.
    fn block_on(d: &mut Dispatcher, t: Rec<Thread>, object: *mut Waitable, timeout: Option<i64>) {
        block_on_as(d, t, object, WaitMode::Kernel, false, timeout);
    }

    /// Block `t` on `object` in the given mode and alertability, asserting the wait parked it.
    fn block_on_as(
        d: &mut Dispatcher,
        t: Rec<Thread>,
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
    fn recording_kernel(_apc: ApcId, _args: &mut ApcArgs) {
        let dispatcher = crate::sched::testkit::installed();
        let pending = dispatcher
            .thread(dispatcher.current().unwrap())
            .kernel_apc_pending;
        record(if pending {
            "kernel:pending-set"
        } else {
            "kernel:pending-clear"
        });
    }

    /// A recording normal routine: logs the call and the first argument it received.
    fn recording_normal(_thread: ThreadId, _context: usize, argument1: usize, _argument2: usize) {
        ARGUMENTS.with(|log| log.borrow_mut().push(argument1));
        record("normal");
    }

    /// A special APC with the recording kernel routine.
    fn special(t: Rec<Thread>) -> Rec<Apc> {
        let mut apc = crate::sched::testkit::apc();
        apc.init(t, recording_kernel, None, ApcMode::Kernel, 0);
        apc
    }

    /// A normal kernel APC with both routines recording.
    fn normal(t: Rec<Thread>) -> Rec<Apc> {
        let mut apc = crate::sched::testkit::apc();
        apc.init(
            t,
            recording_kernel,
            Some(recording_normal),
            ApcMode::Kernel,
            0,
        );
        apc
    }

    /// The APCs queued on `thread`'s kernel queue, in queue order.
    fn queued(thread: Rec<Thread>) -> Vec<ApcId> {
        queued_of(thread, ApcMode::Kernel)
    }

    /// The APCs queued on `thread`'s queue of `mode`, in queue order.
    fn queued_of(thread: Rec<Thread>, mode: ApcMode) -> Vec<ApcId> {
        let queue = ApcQueue {
            thread: thread.id(),
            mode,
        };
        list::iter(crate::sched::testkit::installed(), queue).collect()
    }

    // --- Group A: the APC object ---------------------------------------------

    /// A1: init rules — a null normal routine forces the special defaults (mode kernel, context
    /// zero); a present one honors the caller's mode and context; every record starts detached.
    #[test]
    fn init_rules_null_normal_defaults() {
        let _d = dispatcher();
        let p = process(8);
        let t = thread(p);

        let mut present = crate::sched::testkit::apc();
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

        let mut null = crate::sched::testkit::apc();
        null.init(t, recording_kernel, None, ApcMode::User, 0x99);
        assert_eq!(null.mode, ApcMode::Kernel, "a special's mode is forced");
        assert_eq!(null.normal_context, 0, "a special's context is forced nil");
        assert!(!null.inserted());

        let mut kernel = crate::sched::testkit::apc();
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
        let mut t = thread(p);
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
        let mut t = thread(p);
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
        assert_eq!(queued(t), vec![n1.id(), n2.id(), n3.id()]);
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
        assert_eq!(queued(t), vec![s1.id(), s2.id(), n1.id(), n2.id()]);
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
        let mut user = crate::sched::testkit::apc();
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
            vec![first.id()],
            "the user APC queues on its own list, not the kernel one"
        );
        // The user queue holds its one entry, at the tail.
        assert_eq!(queued_of(t, ApcMode::User), vec![user.id()]);
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

    /// B5: flush — the queue is emptied with every entry uninserted and unlinked, and the pending
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

        assert_eq!(d.flush_apcs(t.id(), ApcMode::Kernel), 2);
        assert!(!s1.inserted());
        assert!(!n1.inserted());
        assert!(t.kernel_apcs.is_empty(), "the queue is genuinely empty");
        assert!(
            t.kernel_apc_pending,
            "the flush does not touch the pending flag"
        );
        assert!(!s1.link.is_linked() && !n1.link.is_linked());

        // An empty flush takes nothing.
        assert_eq!(d.flush_apcs(t.id(), ApcMode::Kernel), 0);
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
        assert!(d.next_thread().is_none());
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

        let mut t1 = thread(p);
        run(d, t1);
        t1.kernel_apc_disable = 1;
        block_on(d, t1, ev.waitable(), None);

        let t2 = thread(p);
        run(d, t2);
        block_on(d, t2, ev.waitable(), None);

        let mut t3 = thread(p);
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
        let mut t = thread(p);
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
        assert_eq!(d.current(), Some(main.id()));
        assert!(d.next_thread().is_none());
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
            let mut apc = crate::sched::testkit::apc();
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

        assert_eq!(deliver_kernel_apcs(), ApcDelivery::Delivered);
        assert_eq!(recorded_calls(), vec!["kernel:pending-clear"]);
        assert!(queued(t).is_empty());
        assert!(!t.kernel_apc_pending);
    }

    /// D1b: a window opens for kernel APCs only at the passive level: a thread at the APC level (a
    /// short lock's holder) keeps its APCs queued and armed, and the first window after it lowers
    /// delivers them.
    #[test]
    fn kernel_apcs_wait_for_the_passive_level() {
        let d = dispatcher();
        let p = process(8);
        let t = thread(p);
        run(d, t);
        let apc = special(t);
        d.queue_apc(apc, 0, 0, 0);

        let pcr = crate::pcr::pcr();
        let entered = pcr.raise(irql::APC);
        deliver_pending_apcs();
        assert!(
            recorded_calls().is_empty(),
            "nothing runs above the passive level"
        );
        assert_eq!(queued(t), vec![apc.id()]);
        assert!(t.kernel_apc_pending);

        pcr.lower(entered);
        deliver_pending_apcs();
        assert_eq!(recorded_calls(), vec!["kernel:pending-clear"]);
        assert!(queued(t).is_empty());
        assert_eq!(pcr.current(), irql::PASSIVE);
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

        assert_eq!(deliver_kernel_apcs(), ApcDelivery::Delivered);
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

        assert_eq!(deliver_kernel_apcs(), ApcDelivery::Delivered);
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
        fn cancel_normal(_apc: ApcId, args: &mut ApcArgs) {
            args.normal_routine = None;
        }
        let d = dispatcher();
        let p = process(8);
        let t = thread(p);
        run(d, t);
        let mut apc = crate::sched::testkit::apc();
        apc.init(t, cancel_normal, Some(recording_normal), ApcMode::Kernel, 0);
        d.queue_apc(apc, 0, 0, 0);

        assert_eq!(deliver_kernel_apcs(), ApcDelivery::Delivered);
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
        let mut t = thread(p);
        run(d, t);
        let gated = normal(t);
        d.queue_apc(gated, 0, 0, 0);

        t.kernel_apc_disable = 1;
        assert_eq!(deliver_kernel_apcs(), ApcDelivery::Delivered);
        assert!(recorded_calls().is_empty(), "nothing ran");
        assert!(gated.inserted(), "the queue is intact");
        assert!(!t.kernel_apc_pending, "the entry flag was still cleared");

        t.kernel_apc_disable = 0;
        t.kernel_apc_in_progress = true;
        assert_eq!(deliver_kernel_apcs(), ApcDelivery::Delivered);
        assert!(recorded_calls().is_empty());

        // Ungated: the deferred APC delivers.
        t.kernel_apc_in_progress = false;
        t.kernel_apc_pending = true;
        assert_eq!(deliver_kernel_apcs(), ApcDelivery::Delivered);
        assert_eq!(recorded_calls(), vec!["kernel:pending-clear", "normal"]);
    }

    /// D5: the queue-empty stop, the armed-empty-flag no-op, and the special delivering ahead of a
    /// gated normal (the gate is per entry, not global).
    #[test]
    fn delivery_stops_on_the_empty_queue_and_gates_per_entry() {
        let d = dispatcher();
        let p = process(8);
        let mut t = thread(p);
        run(d, t);

        // The armed flag over an empty queue: a no-op.
        t.kernel_apc_pending = true;
        assert_eq!(deliver_kernel_apcs(), ApcDelivery::Delivered);
        assert!(!t.kernel_apc_pending);

        // A special behind a gated normal: the special delivers, the normal stays queued.
        let gated = normal(t);
        let s1 = special(t);
        d.queue_apc(gated, 0, 0, 0);
        d.queue_apc(s1, 0, 0, 0);
        t.kernel_apc_disable = 1;
        assert_eq!(deliver_kernel_apcs(), ApcDelivery::Delivered);
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
        let mut t = thread(p);
        run(d, t);
        let mut apc = crate::sched::testkit::apc();
        apc.init(
            t,
            recording_kernel,
            Some(recording_normal),
            ApcMode::User,
            0,
        );
        d.queue_apc(apc, 0, 0, 0);
        t.user_apc_pending = true;

        assert_eq!(deliver_kernel_apcs(), ApcDelivery::Delivered);
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
        let mut t = thread(p);
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

        assert_eq!(deliver_kernel_apcs(), ApcDelivery::Parked);
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
        resume_kernel_apcs();
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
        assert_eq!(deliver_kernel_apcs(), ApcDelivery::Parked);
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
        assert_eq!(deliver_kernel_apcs(), ApcDelivery::Parked);

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
        let mut t = thread(p);
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

    /// A termination's exit APC as the tests bind it: its normal half records the status it ran
    /// with, standing in for the exit (which never returns on the target).
    fn recording_exit(_thread: ThreadId, status: usize, _argument1: usize, _argument2: usize) {
        ARGUMENTS.with(|log| log.borrow_mut().push(status));
        record("exit");
    }

    /// G1: the exit closes the queue — queuing refuses, and what was queued goes, both modes, with
    /// the pending flags: a kernel APC that had no window before the exit (the exit supersedes
    /// it), and the user APCs the thread never turned alertable for.
    #[test]
    fn the_exit_closes_the_queue() {
        let d = dispatcher();
        let p = process(8);
        let t = thread(p);
        run(d, t);
        let kernel = special(t);
        d.queue_apc(kernel, 0, 0, 0);
        let mut user = crate::sched::testkit::apc();
        user.init(
            t,
            nop_kernel_routine,
            Some(recording_normal),
            ApcMode::User,
            0,
        );
        d.queue_apc(user, 0, 0, 0);

        d.close_apc_queue(t.id());
        assert!(!t.apc_queueable);
        assert!(!kernel.inserted() && !user.inserted());
        assert!(t.kernel_apcs.is_empty() && t.user_apcs.is_empty());
        assert!(!t.kernel_apc_pending && !t.user_apc_pending);
        assert!(!d.queue_apc(ApcId::Suspend(t.id()), 0, 0, 0));
        assert!(!t.suspend_apc.inserted());
        assert!(recorded_calls().is_empty(), "nothing delivered");
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
        assert_eq!(deliver_kernel_apcs(), ApcDelivery::Parked);

        // The termination's step: the force-resume releases, the wake readies, and the delivery
        // completes — after which the exit closes the queue.
        d.force_resume_thread(t);
        assert_eq!(t.state(), ThreadState::Ready);
        run(d, t);
        resume_kernel_apcs();
        d.close_apc_queue(t.id());
    }

    /// G2b: a suspended thread terminated by another runs its own exit. Parked inside the suspend
    /// APC's normal routine, it is force-resumed, and the exit APC — held off meanwhile by the
    /// normal in progress — delivers once the suspend's routine returns. Suspended but never
    /// dispatched, its queued suspend APC is discarded, and its first delivery runs the exit alone.
    #[test]
    fn a_suspended_thread_terminated_by_another_runs_its_exit() {
        let d = dispatcher();
        let p = process(8);
        let suspended = thread(p);
        let killer = thread(p);
        run(d, suspended);
        d.suspend_thread(suspended).unwrap();
        assert_eq!(deliver_kernel_apcs(), ApcDelivery::Parked);
        run(d, killer);

        assert!(d.request_termination(suspended, recording_exit, 9));
        assert_eq!(
            suspended.state(),
            ThreadState::Ready,
            "the force-resume woke it"
        );
        assert_eq!(suspended.suspend_count, 0);
        assert!(suspended.suspend_semaphore.waitable.waiters.is_empty());
        assert_eq!(queued(suspended), vec![ApcId::Exit(suspended.id())]);
        assert_eq!(d.select_next(), Some(suspended.id()));
        run(d, suspended);
        resume_kernel_apcs();
        assert_eq!(recorded_calls(), vec!["exit"]);
        assert_eq!(recorded_arguments(), vec![9]);
        assert_eq!(d.audit(), Ok(()));

        // Suspended but never dispatched: the suspend APC is still queued, and the termination
        // discards it before it queues the exit APC.
        let d = dispatcher();
        let p = process(8);
        let queued_suspend = thread(p);
        let killer = thread(p);
        run(d, killer);
        d.make_ready(queued_suspend);
        d.suspend_thread(queued_suspend).unwrap();
        assert!(queued_suspend.suspend_apc.inserted());

        assert!(d.request_termination(queued_suspend, recording_exit, 4));
        assert!(!queued_suspend.suspend_apc.inserted());
        assert_eq!(
            queued(queued_suspend),
            vec![ApcId::Exit(queued_suspend.id())]
        );
        assert!(!queued_suspend.apc_queueable);
        assert_eq!(d.select_next(), Some(queued_suspend.id()));
        run(d, queued_suspend);
        assert_eq!(deliver_kernel_apcs(), ApcDelivery::Delivered);
        assert_eq!(recorded_calls(), vec!["exit", "exit"]);
        assert_eq!(recorded_arguments(), vec![9, 4]);
        assert_eq!(d.audit(), Ok(()));
    }

    /// G2c: the outermost critical region's end arms the delivery of the normal APCs it held off
    /// (KeLeaveCriticalRegion), so the next window runs them; an inner region's end, or one with
    /// nothing queued, arms nothing.
    #[test]
    fn leaving_a_region_arms_what_it_held_off() {
        let d = dispatcher();
        let p = process(8);
        let mut t = thread(p);
        run(d, t);
        t.enter_critical_region();
        t.enter_critical_region();
        let held = normal(t);
        d.queue_apc(held, 0, 0, 0);
        assert_eq!(deliver_kernel_apcs(), ApcDelivery::Delivered);
        assert!(recorded_calls().is_empty(), "held off by the region");
        assert!(!t.kernel_apc_pending);

        assert!(!t.leave_critical_region(), "the inner region");
        assert!(!t.kernel_apc_pending);
        assert!(
            t.leave_critical_region(),
            "the outermost, with an APC held off"
        );
        assert!(t.kernel_apc_pending);
        deliver_pending_apcs();
        assert_eq!(recorded_calls(), vec!["kernel:pending-clear", "normal"]);
    }

    /// G2d: a scope attached to another process's address space holds the thread's kernel APCs
    /// off, specials included (Windows 2000 keeps them in the thread's saved APC state); the
    /// detach arms their delivery again.
    #[test]
    fn an_attached_scope_holds_kernel_apcs_off() {
        let d = dispatcher();
        let p = process(8);
        let other = process(8);
        let t = thread(p);
        run(d, t);
        assert!(d.attach_space(t.id(), other).is_some());
        let apc = special(t);
        d.queue_apc(apc, 0, 0, 0);
        assert_eq!(deliver_kernel_apcs(), ApcDelivery::Delivered);
        assert!(recorded_calls().is_empty(), "held off by the scope");
        assert!(apc.inserted());

        d.detach_space(t.id());
        assert!(t.kernel_apc_pending, "the detach arms the delivery");
        deliver_pending_apcs();
        assert_eq!(recorded_calls(), vec!["kernel:pending-clear"]);
    }

    /// G3: suspend of an exiting or exited thread is refused — the count does not move.
    #[test]
    fn suspend_of_a_terminated_thread_is_refused() {
        let d = dispatcher();
        let p = process(8);
        let mut t = thread(p);
        run(d, t);
        t.state = ThreadState::Terminated;
        d.close_apc_queue(t.id());

        assert_eq!(
            d.suspend_thread(t),
            Err(crate::status::STATUS_THREAD_IS_TERMINATING)
        );
        assert_eq!(t.suspend_count, 0);
        assert!(!t.suspend_apc.inserted());
    }
}
