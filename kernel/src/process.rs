//! The process object: every piece of per-process state in one place.
//!
//! A process owns its page directory (created per process, sharing the
//! kernel's kernel half), its ring-0 gate stack (frame-allocated,
//! supervisor-only, guard page below, pointed at by the TSS `esp0`
//! while it runs), and its user-heap bookkeeping ([`HeapState`]). The
//! image, stack, TEB and parameters pages are mapped fresh each run
//! into the process's directory, so they are per-process by
//! construction.
//!
//! Single tasking, run to completion: at most one process exists at a
//! time. The one kernel static here is the current-process pointer —
//! the run-to-completion analog of a scheduler's current pointer. It
//! is kernel state (like CR3 and the TSS), not per-process state;
//! everything per-process lives inside the [`Process`] it points at.
//! No other kernel static holds per-process state (the review
//! enforceable form: `static mut` outside the boot/cpu structures
//! names no per-process user state).

#[cfg(target_arch = "x86")]
use crate::mem::paging;

/// A process: one address space, one gate stack, one user heap.
pub struct Process {
    /// The fixture's name, as invoked (reported on COM1).
    name: &'static str,
    /// The process's page-directory frame.
    dir_phys: u32,
    /// The gate stack's frames (four, supervisor-only, released at
    /// teardown; the stack's top VA is the gate-stack window's top).
    gate_stack_frames: [u32; crate::mem::paging::GATE_STACK_PAGES],
    /// The user-heap bookkeeping (heap region + CRT region).
    heap: crate::userheap::HeapState,
}

impl Process {
    /// The process's name.
    pub fn name(&self) -> &'static str {
        self.name
    }

    /// The process's page-directory frame.
    pub fn dir_phys(&self) -> u32 {
        self.dir_phys
    }

    /// The user-heap state (the kernel32 heap services are served
    /// from here).
    pub fn heap_mut(&mut self) -> &mut crate::userheap::HeapState {
        &mut self.heap
    }
}

#[cfg(target_arch = "x86")]
impl Process {
    /// Create the process and make it current: a fresh address space
    /// (kernel half inherited, activated on CR3), a fresh gate stack
    /// (mapped into the new directory, installed as the TSS `esp0`),
    /// and fresh heap state. Every later user mapping (thunks, image,
    /// stack, TEB, params) lands in this process's directory.
    ///
    /// # Panics
    ///
    /// A process is already running (run to completion: one at a
    /// time), or the frame database is empty.
    pub fn start(name: &'static str) -> &'static mut Process {
        let dir_phys = paging::create_address_space();
        paging::activate_address_space(dir_phys);

        let gate_stack_frames = paging::map_gate_stack();
        crate::gdt::set_gate_stack_top(paging::GATE_STACK_TOP);

        install(Process {
            name,
            dir_phys,
            gate_stack_frames,
            heap: crate::userheap::HeapState::new(),
        })
    }
}

/// The current process. Single tasking: installed at start, read by
/// the service paths, and (in the teardown slice) taken at exit.
#[cfg(target_arch = "x86")]
static mut CURRENT: Option<Process> = None;

/// Install `process` as current and return it.
#[cfg(target_arch = "x86")]
fn install(process: Process) -> &'static mut Process {
    // SAFETY: single CPU, interrupts disabled; no process is running
    // when a new one starts (run to completion, asserted).
    unsafe {
        let slot = &mut *core::ptr::addr_of_mut!(CURRENT);
        assert!(slot.is_none(), "a process is already running");
        *slot = Some(process);
        slot.as_mut().expect("just installed")
    }
}

/// The current process, mutably (the heap services reach it this way).
///
/// # Panics
///
/// No process is running.
#[cfg(target_arch = "x86")]
pub fn current_mut() -> &'static mut Process {
    // SAFETY: single-threaded kernel; the pointer is installed before
    // ring 3 is entered and has no other writer.
    unsafe {
        let slot = &mut *core::ptr::addr_of_mut!(CURRENT);
        slot.as_mut().expect("no process is running")
    }
}

/// The current process, immutably (reporting paths).
///
/// # Panics
///
/// No process is running.
#[cfg(target_arch = "x86")]
pub fn current() -> &'static Process {
    // SAFETY: as `current_mut`.
    unsafe {
        let slot = &mut *core::ptr::addr_of_mut!(CURRENT);
        slot.as_ref().expect("no process is running")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fresh heap state is all-zero bookkeeping: a new process's
    /// heap starts with nothing committed and nothing reserved.
    #[test]
    fn fresh_process_state_starts_clean() {
        let heap = crate::userheap::HeapState::new();
        let mut process = Process {
            name: "fixture",
            dir_phys: 0x0090_0000,
            gate_stack_frames: [0x00B0_0000; crate::mem::paging::GATE_STACK_PAGES],
            heap,
        };
        assert_eq!(process.name(), "fixture");
        assert_eq!(process.dir_phys(), 0x0090_0000);
        // The heap state a service would see: creating the heap
        // reports the handle and resets nothing that exists.
        assert_eq!(process.heap_mut().create(), crate::userheap::HEAP_HANDLE);
    }
}
