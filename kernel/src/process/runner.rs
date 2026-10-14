//! The sequential multi-process suite runner (`run-process-suite`).
//!
//! One boot runs six processes: `exit0`, `ret0`, `bsscheck`,
//! `bsscheck`, `crash`, `exit0` — each created, run to completion,
//! torn down with the allocator audits re-run, then the next. The
//! first and last are the same fixture at the same image base, so the
//! suite can only pass with per-process directories; the `crash` leg
//! proves a user fault ends the process, not the kernel; the second
//! `bsscheck` proves teardown returns frames re-zeroed.
//!
//! Control flow is a chain, not a loop: `run_suite` starts process 1
//! and never returns; the exit service and the fault handler each
//! hand control to the next process through the context switch below.
//! Each process's exit chain runs on that process's own gate stack,
//! abandoned by the switch; the kernel continues on its boot stack
//! (in the kernel image window, mapped in every address space).

use crate::mem::paging;

/// The suite: process i runs `SEQUENCE[i - 1]`.
const SEQUENCE: [(&[u8], &str); 6] = [
    (crate::exec::loader::EXIT0, "exit0"),
    (crate::exec::loader::RET0, "ret0"),
    (crate::exec::loader::BSSCHECK, "bsscheck"),
    (crate::exec::loader::BSSCHECK, "bsscheck"),
    (crate::exec::loader::CRASH, "crash"),
    (crate::exec::loader::EXIT0, "exit0"),
];

/// The index of the process running or just finished (1-based).
static mut CURRENT: usize = 1;
/// How many processes ended by fault.
static mut FAULTS: u32 = 0;
/// How many teardown audits leaked.
static mut LEAKS: u32 = 0;

/// Start the suite: record the allocator baseline, then run the first
/// process. Never returns.
pub fn run_suite() -> ! {
    // The baseline for the per-process teardown audits: recorded once
    // the boot's permanent allocations are done, before the first
    // process takes any frame.
    crate::process::record_allocator_baseline();

    let (image, name) = SEQUENCE[0];
    crate::exec::loader::run_image(image, name)
}

/// The exit service's suite landing point: report, then continue the
/// chain. Never returns.
pub fn process_exited(code: u32) -> ! {
    let index = current_index();
    let name = crate::process::current().name();
    crate::serial_println!(
        "F2K: process {} ({}) exited normally (exit code={})",
        index,
        name,
        code
    );
    continue_after(false)
}

/// The user-fault suite landing point: report with the vector, then
/// continue the chain (the kernel survives the faulting process).
/// Never returns.
pub fn process_faulted(vector: u32) -> ! {
    let index = current_index();
    let name = crate::process::current().name();
    crate::serial_println!("F2K: process {} ({}) ended by fault (vector {})", index, name, vector);
    continue_after(true)
}

/// The shared end-of-process path: count the outcome, then hand off
/// through the context switch (the current kernel frames live on the
/// dying process's gate stack, unreachable once the address space
/// moves). Never returns.
fn continue_after(faulted: bool) -> ! {
    // SAFETY: suite state; single CPU, interrupts disabled.
    unsafe {
        if faulted {
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!(FAULTS),
                core::ptr::read_volatile(core::ptr::addr_of!(FAULTS)) + 1,
            );
        }
    }
    // SAFETY: the boot directory's kernel half is identical to the
    // process's, so the switch keeps every kernel mapping live; the
    // body never returns to the abandoned stack.
    unsafe { suite_context_switch(paging::boot_directory_phys()) }
}

/// After the context switch: tear the process down, audit, and run
/// the next process (or print the summary and halt). Runs on the
/// boot gate stack; never returns.
unsafe extern "C" fn continue_on_boot() -> ! {
    let index = current_index();

    // Release every frame the process owned and check the allocators
    // against the post-boot baseline.
    let ok = crate::process::teardown_current();
    if ok {
        crate::serial_println!(
            "F2K: process {} teardown audit: frame database ok, kernel heap ok",
            index
        );
    } else {
        // SAFETY: suite state; single CPU.
        unsafe {
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!(LEAKS),
                core::ptr::read_volatile(core::ptr::addr_of!(LEAKS)) + 1,
            );
        }
        let available = crate::mem::bootmem::with_frame_db(|db| db.available());
        crate::serial_println!(
            "F2K: process {} teardown audit FAILED: allocator state leaked (available {})",
            index,
            available
        );
    }

    // The next process, or the summary.
    if index >= SEQUENCE.len() as u32 {
        // SAFETY: suite state; single CPU.
        let faults = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(FAULTS)) };
        let leaks = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(LEAKS)) };
        crate::serial_println!(
            "F2K: process suite complete: {} run, {} faulted, {} leaks",
            SEQUENCE.len(),
            faults,
            leaks
        );
        crate::idle()
    }
    // Process index + 1 runs SEQUENCE[index].
    // SAFETY: suite state; single CPU; the next index is in bounds.
    unsafe {
        core::ptr::write_volatile(core::ptr::addr_of_mut!(CURRENT), index as usize + 1);
    }
    let (image, name) = SEQUENCE[index as usize];
    crate::exec::loader::run_image(image, name)
}

/// The index of the process running (or just finished).
fn current_index() -> u32 {
    // SAFETY: suite state; single CPU, read-only here.
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(CURRENT)) as u32 }
}

// --- The context switch ---------------------------------------------------
//
// The dying process's exit chain executes on that process's gate
// stack (esp inside kernel window 514 of its own directory). The
// handoff must, in order:
//   1. read the argument off the current (dying) stack,
//   2. re-point esp at the boot stack's top — it lives in the kernel
//      image window, mapped identically in every address space, so
//      it is valid both before and after the switch,
//   3. load the boot directory,
//   4. jump to the continuation, which never returns (no return
//      address is planted; the abandoned frames are gone for good).
//
// The boot stack (not a gate stack) is the right landing spot: the
// kernel continues on it through teardown and the next process's
// creation, and the next process's own gate stack only matters once
// ring 3 starts entering gates.

// SAFETY: the boot stack is 64 KiB and the only consumer of its top
// region is this handoff (kmain's frames below are dead by then).
unsafe extern "C" {
    /// The boot stack's top, exported by the entry stub's assembly.
    static boot_stack_top: u8;
}

core::arch::global_asm!(
    ".section .text.suite_context_switch, \"ax\"",
    ".global suite_context_switch",
    "suite_context_switch:",
    "    mov eax, [esp + 4]",       // boot directory phys (before the switch)
    "    mov esp, offset boot_stack_top",
    "    xor ebp, ebp",
    "    mov cr3, eax",
    "    jmp {body}",
    body = sym continue_on_boot,
);

unsafe extern "C" {
    /// Switch to the boot stack and the boot address space, then
    /// enter the continuation (never returns).
    fn suite_context_switch(boot_directory_phys: u32) -> !;
}
