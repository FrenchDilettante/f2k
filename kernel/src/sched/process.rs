//! The process record's scheduling side, and the process object's body.
//!
//! A process owns the scheduling parameters its threads start from: the base priority and the
//! quantum. The quantum is fixed — set once here at creation to the kernel's one constant, never
//! varied — so "the thread quantum" is always this record's value. A process is always resident in
//! F2K (there is no process swapping), so a process's whole scheduling state is the fact of owning
//! runnable threads or not.
//!
//! The scheduling record is part of the process record (the process pool's), pinned with it,
//! where the context switch reads its directory base; its thread list links the thread records of
//! the dispatcher database by index. It carries its record's index in the pool, which is how the
//! running thread's processes are named outside the dispatcher (the processor's slots), and how
//! many threads of other processes run attached to its address space. The process object's body —
//! the waitable a wait on the process parks on, and the exit status — is a dispatcher-database
//! record of its own, at the process record's index.

use core::cell::UnsafeCell;
use core::ptr::NonNull;

use super::list::{IndexList, ListKind};
use super::thread::ThreadId;
use super::wait::{WaitKind, Waitable, WaitableId};
use super::QUANTUM_RESET;

/// The stack-count value meaning "no thread has been created yet".
pub const NO_THREADS: u16 = 0x7FFF;

/// The pool index of a scheduling record outside the process pool: the idle process's (or a host
/// test's).
pub const NOT_POOLED: u16 = u16::MAX;

/// A process's scheduling record, leading with its directory base at a pinned offset: the context
/// switch reads it through a thread's address-space pointer when a switch changes process.
#[repr(C)]
pub struct SchedProcess {
    /// The process's page-directory frame (physical address).
    pub(super) dir_phys: u32,
    /// The priority every attached thread starts from.
    pub(super) base_priority: i8,
    /// The quantum every thread of this process resets to: the fixed kernel constant, written once
    /// here.
    pub(super) thread_quantum: i8,
    /// Whether wait-exit boosts are refused for this process's threads (inherited at thread
    /// attach).
    pub(super) disable_boost: bool,
    /// Whether realtime threads of this process are exempt from quantum end (their quantum is
    /// refilled to the maximum instead).
    pub(super) disable_quantum: bool,
    /// Kernel stacks lent out to threads: the sentinel until the first thread attaches, one per
    /// attached thread, back to zero as the last one exits.
    pub(super) stack_count: u16,
    /// Advanced by one at each thread attach. On one processor it feeds nothing further (no
    /// per-CPU placement); it stays as observable bookkeeping.
    pub(super) thread_seed: u8,
    /// The process's threads, in creation order.
    pub(super) threads: IndexList<ProcessThreads>,
    /// The index of the process record this record belongs to in the process pool, or
    /// [`NOT_POOLED`]: what the processor's slots name the running thread's processes by.
    pub(super) index: u16,
    /// How many threads of other processes run attached to this address space (see
    /// [`super::attach`]): the attaches change it, at the dispatch level. The process's teardown
    /// waits for none to be left.
    pub(super) attach_count: u16,
}

/// A process's scheduling record, by its address: the process records are pinned (the process
/// pool's, or the idle process's static) and outlive their threads' membership in their lists.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ProcessRef(NonNull<SchedProcess>);

impl ProcessRef {
    /// The record at `process`'s address.
    pub fn new(process: &mut SchedProcess) -> Self {
        ProcessRef(NonNull::from(process))
    }

    /// The record of a thread's owner pointer.
    pub(super) fn of(process: *mut SchedProcess) -> Self {
        ProcessRef(NonNull::new(process).expect("an attached thread has a process"))
    }

    /// The record, for as long as the caller's borrow of the dispatcher.
    ///
    /// # Safety
    ///
    /// `'a` is no longer than a borrow of the dispatcher the record's thread list belongs to, and
    /// no other reference to the record is in use meanwhile. A process record is pinned and
    /// outlives the threads attached to it (the attach's contract), so it is alive throughout.
    pub(super) unsafe fn get<'a>(self) -> &'a SchedProcess {
        // SAFETY: the caller's contract.
        unsafe { self.0.as_ref() }
    }

    /// The record, to change, for as long as the caller's borrow of the dispatcher.
    ///
    /// # Safety
    ///
    /// As [`ProcessRef::get`], the borrow being exclusive.
    pub(super) unsafe fn get_mut<'a>(mut self) -> &'a mut SchedProcess {
        // SAFETY: the caller's contract.
        unsafe { self.0.as_mut() }
    }
}

/// The threads of one process.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ProcessThreads(pub ProcessRef);

impl ListKind for ProcessThreads {
    type Entry = ThreadId;
}

impl SchedProcess {
    /// A scheduling record with the given directory base and base priority, the fixed thread
    /// quantum, no threads, nothing attached, and both policies off, outside the process pool.
    pub const fn new(dir_phys: u32, base_priority: i8) -> Self {
        Self::pooled(dir_phys, base_priority, NOT_POOLED)
    }

    /// A scheduling record as [`SchedProcess::new`] makes one, of the process record at `index`
    /// in the process pool.
    pub const fn pooled(dir_phys: u32, base_priority: i8, index: u16) -> Self {
        SchedProcess {
            dir_phys,
            base_priority,
            thread_quantum: QUANTUM_RESET,
            disable_boost: false,
            disable_quantum: false,
            stack_count: NO_THREADS,
            thread_seed: 0,
            threads: IndexList::new(),
            index,
            attach_count: 0,
        }
    }

    /// The index of the process record this record belongs to in the process pool; none outside
    /// it (the idle process).
    pub fn pool_index(&self) -> Option<u16> {
        (self.index != NOT_POOLED).then_some(self.index)
    }

    /// How many threads of other processes run attached to this address space.
    pub fn attach_count(&self) -> u16 {
        self.attach_count
    }

    /// The process's page-directory frame.
    pub fn dir_phys(&self) -> u32 {
        self.dir_phys
    }

    /// Bind the directory base. The boot install's one late binding: the kernel's own process
    /// record takes the directory that is active at boot.
    pub fn set_dir_phys(&mut self, dir_phys: u32) {
        self.dir_phys = dir_phys;
    }

    /// The process's base priority.
    pub fn base_priority(&self) -> i8 {
        self.base_priority
    }

    /// The quantum this process's threads reset to.
    pub fn thread_quantum(&self) -> i8 {
        self.thread_quantum
    }

    /// The kernel stacks lent out (the sentinel before the first thread).
    pub fn stack_count(&self) -> u16 {
        self.stack_count
    }

    /// The thread-creation counter.
    pub fn thread_seed(&self) -> u8 {
        self.thread_seed
    }

    /// Whether realtime threads of this process skip quantum end.
    pub fn disable_quantum(&self) -> bool {
        self.disable_quantum
    }

    /// Set the quantum-end exemption for realtime threads, returning the previous value. The flag
    /// matters only together with a realtime priority.
    pub fn set_disable_quantum(&mut self, disable: bool) -> bool {
        let previous = self.disable_quantum;
        self.disable_quantum = disable;
        previous
    }

    /// Whether no thread is attached.
    pub fn has_no_threads(&self) -> bool {
        self.threads.is_empty()
    }
}

/// A scheduling record pinned in a static for the kernel's life: the idle process's, and every
/// process record's in the process pool. The dispatcher owns it: its threads' attaches keep its
/// address, and the dispatcher and the context switch reach it through that. Anyone else reaches
/// it only through a borrow of the dispatcher ([`PinnedProcess::get`], [`PinnedProcess::get_mut`]),
/// at the dispatch level, so the dispatcher's borrow is the record's.
pub struct PinnedProcess(UnsafeCell<SchedProcess>);

// SAFETY: one processor; the record is reached through its address by the dispatcher (serialized
// at the dispatch level) and the switch, which runs inside the dispatcher's own calls, and through
// the accessors below only while the caller borrows the dispatcher, so never beside them.
unsafe impl Sync for PinnedProcess {}

impl PinnedProcess {
    /// A pinned record with the given directory base and base priority (see
    /// [`SchedProcess::new`]).
    pub const fn new(dir_phys: u32, base_priority: i8) -> Self {
        PinnedProcess(UnsafeCell::new(SchedProcess::new(dir_phys, base_priority)))
    }

    /// A pinned record of the process record at `index` in the process pool (see
    /// [`SchedProcess::pooled`]).
    pub const fn pooled(dir_phys: u32, base_priority: i8, index: u16) -> Self {
        PinnedProcess(UnsafeCell::new(SchedProcess::pooled(
            dir_phys,
            base_priority,
            index,
        )))
    }

    /// The record's address: what its threads' attaches link, and what a thread's owner pointer
    /// is compared with.
    pub fn as_ptr(&self) -> *mut SchedProcess {
        self.0.get()
    }

    /// The record, to read, for as long as the caller borrows the dispatcher.
    pub fn get<'a>(&'a self, _dispatcher: &'a super::dispatcher::Dispatcher) -> &'a SchedProcess {
        // SAFETY: every other reach into the record is the dispatcher's own (its calls, and the
        // switch inside them) or another accessor's, which also borrows the dispatcher: none can
        // write it while this shared borrow of the dispatcher lives.
        unsafe { &*self.0.get() }
    }

    /// The record, to change, for as long as the caller borrows the dispatcher exclusively.
    // The `&mut` from `&self` is the point: the dispatcher's exclusive borrow is the record's.
    #[allow(clippy::mut_from_ref)]
    pub fn get_mut<'a>(
        &'a self,
        _dispatcher: &'a mut super::dispatcher::Dispatcher,
    ) -> &'a mut SchedProcess {
        // SAFETY: as in `get`: every other reach into the record needs the dispatcher, which this
        // exclusive borrow holds, so this is the only reference to the record while it lives.
        unsafe { &mut *self.0.get() }
    }
}

/// A process object's body: what a wait on the process, or a handle to it, reaches. The process
/// record itself is the process pool's record at the same index; it is reused once the object is
/// deleted (the process holds its own reference from its creation to the end of its teardown).
pub struct ProcessObject {
    /// Signaled when the process has ended (no thread of the process outlives that, so its own
    /// threads only ever see it unsignaled).
    pub waitable: Waitable,
    /// The process's exit code: STILL_ACTIVE until it ends.
    pub exit_status: u32,
}

impl ProcessObject {
    /// A fresh body, unsignaled and still active: the record `index` of the pool.
    pub const fn new(index: u16) -> Self {
        ProcessObject {
            waitable: Waitable::with_id(WaitKind::NotificationEvent, 0, WaitableId::Process(index)),
            exit_status: crate::ob::STILL_ACTIVE,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fresh record: the directory base as given, base priority as given, the fixed quantum, the
    /// no-threads sentinel, no threads, both policies off.
    #[test]
    fn process_defaults() {
        let process = Box::leak(Box::new(SchedProcess::new(0x0090_0000, 8)));
        assert_eq!(process.dir_phys(), 0x0090_0000);
        assert_eq!(process.base_priority(), 8);
        assert_eq!(process.thread_quantum(), 6);
        assert_eq!(process.stack_count(), NO_THREADS);
        assert!(process.threads.is_empty());
        assert!(!process.disable_boost);
        assert!(!process.disable_quantum());
        assert_eq!(process.thread_seed(), 0);
    }

    /// A process and a dispatcher whose threads attach to it, by id.
    fn rig() -> (
        &'static mut crate::sched::dispatcher::Dispatcher,
        &'static mut SchedProcess,
    ) {
        let dispatcher = crate::sched::testkit::dispatcher();
        let process = Box::leak(Box::new(SchedProcess::new(0x0090_0000, 8)));
        (dispatcher, process)
    }

    /// Attach a fresh thread to `process`.
    fn attach(process: &mut SchedProcess) -> ThreadId {
        crate::sched::testkit::thread(process).id()
    }

    /// The other-thread query: creation order, skipping the excepted thread, none once only it
    /// (or nothing) is attached — and it follows the list as threads leave it.
    #[test]
    fn first_thread_except_walks_the_others() {
        let (d, process) = rig();
        assert!(d.first_thread_except(process, None).is_none());
        let main = attach(process);
        let first = attach(process);
        let second = attach(process);
        let threads = ProcessThreads(ProcessRef::new(process));

        assert_eq!(d.first_thread_except(process, Some(main)), Some(first));
        assert_eq!(d.first_thread_except(process, Some(first)), Some(main));
        // Unlinking stands in for a termination.
        crate::sched::list::remove(d, threads, first);
        assert_eq!(d.first_thread_except(process, Some(main)), Some(second));
        crate::sched::list::remove(d, threads, second);
        assert!(d.first_thread_except(process, Some(main)).is_none());
        assert_eq!(d.first_thread_except(process, None), Some(main));
    }

    /// A thread whose termination is pending stays attached but is not answered again: the
    /// termination walk moves past it.
    #[test]
    fn first_thread_except_skips_pending_terminations() {
        let (d, process) = rig();
        let main = attach(process);
        let deferred = attach(process);
        let next = attach(process);
        d.thread_mut(deferred).terminate_pending = true;
        assert_eq!(d.first_thread_except(process, Some(main)), Some(next));
        crate::sched::list::remove(d, ProcessThreads(ProcessRef::new(process)), next);
        assert!(d.first_thread_except(process, Some(main)).is_none());
        assert_eq!(d.first_thread_except(process, Some(next)), Some(main));
    }

    /// The quantum-end exemption flag is a plain store returning the previous value.
    #[test]
    fn disable_quantum_flag() {
        let mut process = SchedProcess::new(0x0090_0000, 8);
        assert!(!process.set_disable_quantum(true));
        assert!(process.disable_quantum());
        assert!(process.set_disable_quantum(false));
        assert!(!process.disable_quantum());
    }
}
