//! The sequential multi-process suite runner (`run-process-suite`).
//!
//! One boot runs six processes: `exit0`, `ret0`, `bsscheck`, `bsscheck`, `crash`, `exit0` — each
//! created, run to completion, torn down with the allocator audits re-run, then the next. The first
//! and last are the same fixture at the same image base, so the suite can only pass with
//! per-process directories; the `crash` leg proves a user fault ends the process, not the kernel;
//! the second `bsscheck` proves teardown returns frames re-zeroed.
//!
//! The suite is a loop the idle thread drives. Each leg's process is created and entered as its
//! main thread — the ladder every boot uses — and runs on the scheduler to its exit or fault. Its
//! last thread's exit reports and switches to the idle thread, whose reap step tears the process
//! down on the boot stack and address space and hands the outcome here: the audit line, then the
//! next leg's process, or the summary.

use crate::process::exit::{self, AfterLeg, AuditReport, ProcessEnd, SuiteTally};

/// The suite: process i runs `SEQUENCE[i - 1]`, a program's path on the boot volume and its
/// process name.
const SEQUENCE: [(&[u8], &str); 6] = [
    (b"exit0.exe", "exit0"),
    (b"ret0.exe", "ret0"),
    (b"bsscheck.exe", "bsscheck"),
    (b"bsscheck.exe", "bsscheck"),
    (b"crash.exe", "crash"),
    (b"exit0.exe", "exit0"),
];

/// The index of the process running or just finished (1-based).
static mut CURRENT: u32 = 0;
/// The outcomes so far.
static mut TALLY: SuiteTally = SuiteTally::new();

/// Start the suite: record the allocator baseline, ready the first process's main thread, and enter
/// the idle loop. Never returns.
pub fn run_suite() -> ! {
    // The baseline for the per-process teardown audits: recorded once the boot's permanent
    // allocations are done, before the first process takes any frame.
    crate::process::record_allocator_baseline();
    start_leg(1);
    crate::sched::idle::idle_loop()
}

/// The running leg, for its process's end report: its index and fixture name.
pub fn current_leg() -> exit::Leg {
    (current_index(), crate::process::current().name())
}

/// The reap step's suite landing point, on the idle thread after the leg's teardown: audit the
/// allocators against the post-boot baseline and report, count the outcome, then ready the next
/// leg — or print the summary, after which the idle thread rests.
pub fn process_reaped(end: ProcessEnd) {
    let index = current_index();
    let audit = crate::process::audit_allocators();
    crate::serial_println!("{}", AuditReport { index, audit });

    // SAFETY: suite state; single CPU, touched only from the idle thread's reap step.
    let tally = unsafe { &mut *core::ptr::addr_of_mut!(TALLY) };
    tally.record(end, audit.is_ok());

    match exit::after_leg(index, SEQUENCE.len() as u32) {
        AfterLeg::Next(next) => start_leg(next),
        AfterLeg::Summary => {
            crate::serial_println!("{}", tally);
        }
    }
}

/// Create leg `index`'s process — its program read off the boot volume — and ready its main
/// thread; the idle loop's next pass switches to it.
fn start_leg(index: u32) {
    // SAFETY: suite state; single CPU, written only here.
    unsafe { core::ptr::write_volatile(core::ptr::addr_of_mut!(CURRENT), index) };
    let (path, name) = SEQUENCE[index as usize - 1];
    let entry = crate::exec::loader::load_path(path, name);
    crate::process::threads::start_main_thread(entry, crate::user::USER_STACK_TOP);
}

/// The index of the process running (or just finished).
fn current_index() -> u32 {
    // SAFETY: suite state; single CPU, read-only here.
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(CURRENT)) }
}
