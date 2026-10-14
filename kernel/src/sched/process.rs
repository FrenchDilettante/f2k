//! The process record's scheduling side.
//!
//! A process owns the scheduling parameters its threads start from:
//! the base priority and the quantum. The quantum is fixed — set once
//! here at creation to the kernel's one constant, never varied — so
//! "the thread quantum" is always this record's value. A process is
//! always resident in F2K (there is no process swapping), so a
//! process's whole scheduling state is the fact of owning runnable
//! threads or not.

use super::{List, QUANTUM_RESET};

/// The stack-count value meaning "no thread has been created yet".
pub const NO_THREADS: u16 = 0x7FFF;

/// A process's scheduling record, leading with its directory base at
/// a pinned offset: the context switch reads it through a thread's
/// owner pointer when a switch changes process.
#[repr(C)]
pub struct SchedProcess {
    /// The process's page-directory frame (physical address).
    pub(super) dir_phys: u32,
    /// The priority every attached thread starts from.
    pub(super) base_priority: i8,
    /// The quantum every thread of this process resets to: the fixed
    /// kernel constant, written once here.
    pub(super) thread_quantum: i8,
    /// Whether wait-exit boosts are refused for this process's
    /// threads (inherited at thread attach).
    pub(super) disable_boost: bool,
    /// Whether realtime threads of this process are exempt from
    /// quantum end (their quantum is refilled to the maximum
    /// instead).
    pub(super) disable_quantum: bool,
    /// Kernel stacks lent out to threads: the sentinel until the
    /// first thread attaches, one per attached thread, back to zero
    /// as the last one exits.
    pub(super) stack_count: u16,
    /// Advanced by one at each thread attach. On one processor it
    /// feeds nothing further (no per-CPU placement); it stays as
    /// observable bookkeeping.
    pub(super) thread_seed: u8,
    /// The process's threads, in creation order.
    pub(super) threads: List,
}

impl SchedProcess {
    /// A scheduling record with the given directory base and base
    /// priority, the fixed thread quantum, no threads, and both
    /// policies off. Call [`SchedProcess::init`] once the record is
    /// at its final address.
    pub const fn new(dir_phys: u32, base_priority: i8) -> Self {
        SchedProcess {
            dir_phys,
            base_priority,
            thread_quantum: QUANTUM_RESET,
            disable_boost: false,
            disable_quantum: false,
            stack_count: NO_THREADS,
            thread_seed: 0,
            threads: List::empty(),
        }
    }

    /// The process's page-directory frame.
    pub fn dir_phys(&self) -> u32 {
        self.dir_phys
    }

    /// Bind the directory base. The boot install's one late
    /// binding: the kernel's own process record takes the directory
    /// that is active at boot.
    pub fn set_dir_phys(&mut self, dir_phys: u32) {
        self.dir_phys = dir_phys;
    }

    /// Close the thread-list sentinel (see [`List::init`]).
    pub fn init(&mut self) {
        self.threads.init();
    }

    /// The process's base priority.
    pub fn base_priority(&self) -> i8 {
        self.base_priority
    }

    /// The quantum this process's threads reset to.
    pub fn thread_quantum(&self) -> i8 {
        self.thread_quantum
    }

    /// The kernel stacks lent out (the sentinel before the first
    /// thread).
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

    /// Set the quantum-end exemption for realtime threads, returning
    /// the previous value. The flag matters only together with a
    /// realtime priority.
    pub fn set_disable_quantum(&mut self, disable: bool) -> bool {
        let previous = self.disable_quantum;
        self.disable_quantum = disable;
        previous
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fresh record: the directory base as given, base priority as
    /// given, the fixed quantum, the no-threads sentinel, no
    /// threads, both policies off.
    #[test]
    fn process_defaults() {
        let process = Box::leak(Box::new(SchedProcess::new(0x0090_0000, 8)));
        process.init();
        assert_eq!(process.dir_phys(), 0x0090_0000);
        assert_eq!(process.base_priority(), 8);
        assert_eq!(process.thread_quantum(), 6);
        assert_eq!(process.stack_count(), NO_THREADS);
        assert!(process.threads.is_empty());
        assert!(!process.disable_boost);
        assert!(!process.disable_quantum());
        assert_eq!(process.thread_seed(), 0);
    }

    /// The quantum-end exemption flag is a plain store returning the
    /// previous value.
    #[test]
    fn disable_quantum_flag() {
        let mut process = SchedProcess::new(0x0090_0000, 8);
        assert!(!process.set_disable_quantum(true));
        assert!(process.disable_quantum());
        assert!(process.set_disable_quantum(false));
        assert!(!process.disable_quantum());
    }
}
