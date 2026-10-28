//! Attaching a thread to another process's address space: for a scope, the running thread runs on
//! that process's page directory while it stays its own process's thread (Windows'
//! KeStackAttachProcess and KeUnstackDetachProcess).
//!
//! A thread record names two processes: its owner, whose thread it is — the source of its
//! scheduling data, and the process whose handles and objects its services act on — and its
//! address-space process (Windows' ApcState.Process), the one whose directory it runs on: its
//! owner, except while attached. The context switch loads CR3 from the incoming thread's
//! address-space process ([`super::switch`]), so an attached thread switched away and back resumes
//! on the directory it attached to, and everything that reaches memory through the live directory
//! reaches the attached process's: the running process's page tables
//! ([`crate::mem::vm::CurrentPages`]), the page-fault resolution, the user-memory copies. A disk
//! read, a wait, a preemption inside the scope are all safe: the kernel stacks are mapped in every
//! address space ([`crate::mem::kstacks`]).
//!
//! [`attach`] returns an [`Attached`] guard whose drop detaches: the thread's own directory is live
//! again. Each change runs with interrupts masked, the record and CR3 moved together, so no
//! interrupt — and no switch one causes — sees one without the other. Attaches do not nest:
//! attaching while attached to another process panics, as Windows' KeAttachProcess refuses it
//! (INVALID_PROCESS_ATTACH_ATTEMPT); nothing in the kernel needs the nesting KeStackAttachProcess
//! allows. Attaching to the address space already in place is a scope that changes nothing. While
//! attached, a user APC neither breaks the thread's wait nor arms its delivery, and a system
//! service returns to user mode only detached.

use super::process::SchedProcess;
use super::thread::Thread;

/// The running thread attached to another process's address space, until the guard drops (see the
/// module notes). It stays on the thread that attached: the scope is that thread's.
#[must_use = "dropping the guard detaches at once"]
pub struct Attached {
    /// The thread that attached.
    thread: *mut Thread,
    /// Whether the attach changed the thread's address space: a scope over the one already in
    /// place changes nothing, and neither does its end.
    changed: bool,
}

/// Attach the running thread to `process`'s address space: from here until the guard drops, the
/// thread runs on `process`'s directory. `process` must outlive the scope: a process the caller
/// holds a reference on, or one being built or torn down by the caller.
///
/// # Panics
///
/// The thread is attached to another process already (attaches do not nest), or no thread runs.
pub fn attach(process: &SchedProcess) -> Attached {
    let thread = crate::sched::idle::dispatcher().current_thread();
    assert!(!thread.is_null(), "an attach runs on a thread");
    let changed = masked(|| {
        // SAFETY: the running thread's record is live while it runs, and the masked change is the
        // only borrow of it.
        let thread = unsafe { &mut *thread };
        let Some(dir_phys) = thread.attach_space(process) else {
            return false;
        };
        crate::mem::paging::activate_address_space(dir_phys);
        true
    });
    // Every thread's kernel stack is mapped in the directory now live: the kernel stack region's
    // tables are shared.
    debug_assert!(
        !changed || crate::mem::kstacks::every_stack_mapped_here(),
        "an attached address space misses a thread's kernel stack"
    );
    Attached { thread, changed }
}

/// Whether the running thread runs attached to another process's address space (none runs: not).
pub fn running_attached() -> bool {
    let thread = crate::sched::idle::dispatcher().current_thread();
    // SAFETY: the running thread's record is live while it runs.
    unsafe { thread.as_ref() }.is_some_and(Thread::attached)
}

impl Drop for Attached {
    /// Detach: the thread's own directory is live again.
    fn drop(&mut self) {
        if !self.changed {
            return;
        }
        debug_assert!(
            core::ptr::eq(
                self.thread,
                crate::sched::idle::dispatcher().current_thread()
            ),
            "a scope ends on the thread that attached"
        );
        masked(|| {
            // SAFETY: the attached thread is the running one (checked above in debug builds): its
            // record is live, and the masked change is the only borrow of it.
            let thread = unsafe { &mut *self.thread };
            crate::mem::paging::activate_address_space(thread.detach_space());
        });
    }
}

/// Run `body` with interrupts masked, then put the flag back as found.
fn masked<R>(body: impl FnOnce() -> R) -> R {
    let _masked = crate::pcr::pcr().mask_guard();
    body()
}
