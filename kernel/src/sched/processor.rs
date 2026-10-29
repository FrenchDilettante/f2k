//! The processor's threads: the scheduler's per-processor slots, kept in the processor control
//! region (Windows 2000's KPRCB CurrentThread, NextThread, IdleThread and QuantumEnd).
//!
//! The dispatcher writes them, serialized as it is; anyone reads them, without the dispatcher. The
//! running thread is what [`super::current_thread`] answers (KeGetCurrentThread), and the clock
//! interrupt charges the running thread's quantum here, at the clock level, without reaching the
//! dispatcher (KeUpdateRunTime): the running thread's quantum moves from its record into the slots
//! when it is switched in and back when it is switched out (see
//! [`super::dispatcher::Dispatcher::enter`]), so the one the clock charges is never in a record the
//! dispatcher may be borrowing. A charge that runs the quantum out sets the quantum-end request,
//! which the dispatch window consumes.
//!
//! The same handover carries what the running thread's own code reads of itself at any level,
//! without the dispatcher: its user-copy attribution, and its owner and address-space processes
//! (what the current process and its live pages are, Windows 2000's PsGetCurrentProcess through
//! the current thread).
//!
//! Every slot is an atomic: one processor, so the atomics are not about other processors but about
//! the clock interrupt, which may land between any two instructions of the code that reads and
//! writes them. A read-modify-write of the quantum by the dispatcher can lose a tick the clock
//! charged in its middle, as Windows 2000's can.

use core::sync::atomic::{AtomicBool, AtomicI8, AtomicPtr, AtomicU16, Ordering};

use super::process::SchedProcess;
use super::thread::ThreadId;
use super::QUANTUM_TICK;
use crate::level::{At, Clock};

/// A slot's value when it names no thread.
const NO_THREAD: u16 = u16::MAX;

/// One thread slot: a thread record's name, or none.
struct Slot(AtomicU16);

impl Slot {
    const fn new() -> Self {
        Slot(AtomicU16::new(NO_THREAD))
    }

    fn get(&self) -> Option<ThreadId> {
        match self.0.load(Ordering::SeqCst) {
            NO_THREAD => None,
            index => Some(ThreadId(index)),
        }
    }

    fn set(&self, thread: Option<ThreadId>) {
        let index = thread.map_or(NO_THREAD, |thread| thread.0);
        debug_assert!(thread.is_none() || index != NO_THREAD);
        self.0.store(index, Ordering::SeqCst);
    }
}

/// The processor's thread slots and the running thread's quantum.
pub struct ThreadSlots {
    /// The Running thread.
    current: Slot,
    /// The Standby thread: what the next switch enters, or none.
    next: Slot,
    /// The idle thread, entered when nothing else is schedulable.
    idle: Slot,
    /// The running thread's quantum, while it runs (its record holds it otherwise).
    quantum: AtomicI8,
    /// Whether the running thread's quantum ran out at a tick: the dispatch window's question,
    /// consumed (and cleared) before the quantum decision runs.
    quantum_end: AtomicBool,
    /// Whether the running thread is inside a user-memory copy on its process's behalf, while it
    /// runs (its record holds it otherwise): read by the copies and the exception handler at any
    /// level, the dispatch level included (the console server copies there).
    copying_user_memory: AtomicBool,
    /// The running thread's owner and address-space process (see [`super::attach`]), copied from
    /// its record as it takes the processor, and the latter changed with the record by an attach:
    /// what the current process and its live address space are read from at any level, as Windows
    /// 2000 reads the current thread's ApcState.Process through its processor block.
    process: AtomicPtr<SchedProcess>,
    space: AtomicPtr<SchedProcess>,
}

impl ThreadSlots {
    /// Empty slots: no thread yet.
    pub const fn new() -> Self {
        ThreadSlots {
            current: Slot::new(),
            next: Slot::new(),
            idle: Slot::new(),
            quantum: AtomicI8::new(0),
            quantum_end: AtomicBool::new(false),
            copying_user_memory: AtomicBool::new(false),
            process: AtomicPtr::new(core::ptr::null_mut()),
            space: AtomicPtr::new(core::ptr::null_mut()),
        }
    }

    /// The Running thread, none before the boot installs the idle thread.
    pub fn current(&self) -> Option<ThreadId> {
        self.current.get()
    }

    /// The Standby thread, if one is selected.
    pub fn next(&self) -> Option<ThreadId> {
        self.next.get()
    }

    /// The idle thread, once installed.
    pub fn idle(&self) -> Option<ThreadId> {
        self.idle.get()
    }

    /// The running thread's quantum.
    pub fn quantum(&self) -> i8 {
        self.quantum.load(Ordering::SeqCst)
    }

    /// The running thread's owner: its process's scheduling record (null before a thread runs).
    pub fn process(&self) -> *const SchedProcess {
        self.process.load(Ordering::SeqCst)
    }

    /// The running thread's address-space process: its owner, or while attached the process it
    /// attached to (null before a thread runs).
    pub fn space(&self) -> *const SchedProcess {
        self.space.load(Ordering::SeqCst)
    }

    /// Whether the running thread is inside a user-memory copy on its process's behalf.
    pub fn copying_user_memory(&self) -> bool {
        self.copying_user_memory.load(Ordering::SeqCst)
    }

    /// Mark the running thread inside a user-memory copy, or out of it; returns what it was.
    pub fn set_copying_user_memory(&self, copying: bool) -> bool {
        self.copying_user_memory.swap(copying, Ordering::SeqCst)
    }

    /// Whether a tick ran the running thread's quantum out since the last dispatch window.
    pub fn quantum_end_requested(&self) -> bool {
        self.quantum_end.load(Ordering::SeqCst)
    }

    /// Whether a dispatch decision may be pending: a tick ran the quantum out, or a thread waits in
    /// the standby slot. The cheap test a lower makes before it raises for the decision, which
    /// re-verifies both.
    pub fn dispatch_requested(&self) -> bool {
        self.quantum_end_requested() || self.next().is_some()
    }

    /// Charge the running thread's quantum for one full tick, at the clock level (Windows 2000's
    /// KeUpdateRunTime), and request the dispatch window's decision when the charge runs it out.
    /// The charge consults neither the interrupted frame nor the processor's mode — whoever is
    /// current is charged, whatever it was doing. The idle thread is charged like any other but
    /// never requests (its quantum runs off the bottom, and nothing reads it).
    pub fn charge_running_tick(&self, _clock: &At<Clock>) {
        let Some(current) = self.current() else {
            return;
        };
        let quantum = charged_tick(self.quantum());
        self.quantum.store(quantum, Ordering::SeqCst);
        if quantum <= 0 && Some(current) != self.idle() {
            self.quantum_end.store(true, Ordering::SeqCst);
        }
    }

    // --- The dispatcher's writes ---

    pub(super) fn set_current(&self, thread: Option<ThreadId>) {
        self.current.set(thread);
    }

    pub(super) fn set_next(&self, thread: Option<ThreadId>) {
        self.next.set(thread);
    }

    pub(super) fn set_idle(&self, thread: Option<ThreadId>) {
        self.idle.set(thread);
    }

    /// The running thread's owner and address-space process, as its record names them.
    pub(super) fn set_processes(&self, process: *mut SchedProcess, space: *const SchedProcess) {
        self.process.store(process, Ordering::SeqCst);
        self.space.store(space.cast_mut(), Ordering::SeqCst);
    }

    pub(super) fn set_quantum(&self, quantum: i8) {
        self.quantum.store(quantum, Ordering::SeqCst);
    }

    /// Consume the quantum-end request: whether one was pending, now cleared.
    pub(super) fn take_quantum_end(&self) -> bool {
        self.quantum_end.swap(false, Ordering::SeqCst)
    }

    /// Arm the quantum-end request, as a tick that ran the quantum out does.
    #[cfg(test)]
    pub(super) fn request_quantum_end(&self) {
        self.quantum_end.store(true, Ordering::SeqCst);
    }

    /// Empty every slot: a fresh dispatcher's processor.
    pub(super) fn reset(&self) {
        self.current.set(None);
        self.next.set(None);
        self.idle.set(None);
        self.quantum.store(0, Ordering::SeqCst);
        self.quantum_end.store(false, Ordering::SeqCst);
        self.copying_user_memory.store(false, Ordering::SeqCst);
        self.set_processes(core::ptr::null_mut(), core::ptr::null());
    }
}

/// A quantum charged for one tick. Saturating: a thread charged for longer than its quantum without
/// a dispatch window (about 43 ticks at the reset value) must not wrap back to a positive quantum.
pub(super) fn charged_tick(quantum: i8) -> i8 {
    quantum.saturating_sub(QUANTUM_TICK)
}
