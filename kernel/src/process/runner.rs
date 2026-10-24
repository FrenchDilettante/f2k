//! The boot's programs, run one after another.
//!
//! The user command line lists the programs to run (see [`crate::boot::cmdline::programs`]): one
//! command line, or several separated by ` ;; `; without one the boot runs exit0. Each runs as its
//! own process, in order: created, run to its end, torn down with the allocator audits re-run, then
//! the next, the way the corpus's capture script runs a fixture's sections one after another on
//! the real machine. Each process's start is announced on COM1 (`F2K: process 2 of 3: CORPUS\
//! runtime.exe env`), the line the test harness splits a boot's log on.
//!
//! A boot of one program reports in the one-process forms (`F2K: user process exited normally
//! ...`, `F2K: teardown audit: ...`). A boot of several numbers each process's lines and ends with
//! the summary (`F2K: process suite complete: ...`). The kernel's multi-process case lists exit0,
//! ret0, bare, bare, bare null-write, exit0: the first and last are the same fixture at the same
//! image base, so it can only pass with per-process directories; `bare`'s default run (its image
//! checks, 256 KiB of stack grown on demand) twice proves teardown returns frames re-zeroed; `bare
//! null-write` proves a user fault ends the process with its exception code (through kernel32's
//! BaseProcessStart frame), not the kernel.
//!
//! The runner is a loop the idle thread drives. Each process is created and entered as its main
//! thread — the ladder every boot uses — and runs on the scheduler to its exit or fault. Its last
//! thread's exit reports and switches to the idle thread, whose reap step tears the process down on
//! the boot stack and address space and hands the outcome here: the audit line, then the next
//! process, or the summary.

use crate::process::exit::{self, AfterLeg, AuditReport, ProcessEnd, SuiteTally};

/// The program a boot without a user command line runs.
const DEFAULT_PROGRAM: &[u8] = b"exit0";

/// How many programs the boot runs; 0 until the runner starts (the fault-test boots never start
/// it).
static mut LEGS: u32 = 0;
/// The index of the process running or just finished (1-based).
static mut CURRENT: u32 = 0;
/// The outcomes so far.
static mut TALLY: SuiteTally = SuiteTally::new();

/// Run the boot's programs: record the allocator baseline, ready the first program's main thread,
/// and enter the idle loop. Never returns.
pub fn run() -> ! {
    let legs = programs().count() as u32;
    // SAFETY: runner state; single-threaded boot, written only here.
    unsafe { core::ptr::write_volatile(core::ptr::addr_of_mut!(LEGS), legs) };
    // The baseline for the per-process teardown audits: recorded once the boot's permanent
    // allocations are done, before the first process takes any frame.
    crate::process::record_allocator_baseline();
    start_leg(1);
    crate::sched::idle::idle_loop()
}

/// The running process's leg, for its end report: its index and fixture name; none on a boot of
/// one program (or one the runner does not drive).
pub fn current_leg() -> Option<exit::Leg> {
    (leg_count() > 1).then(|| (current_index(), crate::process::current().name()))
}

/// The reap step's landing point, on the idle thread after a process's teardown: audit the
/// allocators against the post-boot baseline and report. On a boot of several programs, count the
/// outcome, then ready the next process — or print the summary, after which the idle thread rests.
pub fn process_reaped(end: ProcessEnd) {
    let audit = crate::process::audit_allocators();
    let legs = leg_count();
    if legs <= 1 {
        // Before the audit line: the harness stops the boot on it, so the dump must land first.
        #[cfg(feature = "perf-trace")]
        crate::perf::report();
        crate::serial_println!("{}", AuditReport { index: None, audit });
        return;
    }

    let index = current_index();
    crate::serial_println!(
        "{}",
        AuditReport {
            index: Some(index),
            audit
        }
    );
    // SAFETY: runner state; single CPU, touched only from the idle thread's reap step.
    let tally = unsafe { &mut *core::ptr::addr_of_mut!(TALLY) };
    tally.record(end, audit.is_ok());

    match exit::after_leg(index, legs) {
        AfterLeg::Next(next) => start_leg(next),
        AfterLeg::Summary => {
            // Before the summary line: the harness stops the boot on it.
            #[cfg(feature = "perf-trace")]
            crate::perf::report();
            crate::serial_println!("{}", tally);
        }
    }
}

/// The programs' command lines the boot runs: the user command line's list, else exit0 alone.
fn programs() -> impl Iterator<Item = &'static [u8]> {
    use crate::boot::cmdline::{kernel_command_line, programs, user_command_line};
    let listed = user_command_line(kernel_command_line())
        .filter(|line| programs(line).next().is_some())
        .unwrap_or(DEFAULT_PROGRAM);
    programs(listed)
}

/// Announce leg `index`, create its process — its program read off the boot volume — and ready its
/// main thread; the idle loop's next pass switches to it.
fn start_leg(index: u32) {
    // SAFETY: runner state; single CPU, written only here.
    unsafe { core::ptr::write_volatile(core::ptr::addr_of_mut!(CURRENT), index) };
    let command_line = programs()
        .nth(index as usize - 1)
        .expect("a leg the list holds");
    crate::serial_println!(
        "F2K: process {} of {}: {}",
        index,
        leg_count(),
        core::str::from_utf8(command_line).unwrap_or("(not ASCII)")
    );
    let mut path = [0u8; crate::user::MAX_PATH];
    let (length, name) = crate::user::program_image(command_line, &mut path);
    let entry = crate::exec::loader::load_path(&path[..length], name, command_line);
    crate::process::threads::start_main_thread(crate::user::main_thread_start(entry));
}

/// How many programs the boot runs (0 before the runner starts).
fn leg_count() -> u32 {
    // SAFETY: runner state; single CPU, read-only here.
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(LEGS)) }
}

/// The index of the process running (or just finished).
fn current_index() -> u32 {
    // SAFETY: runner state; single CPU, read-only here.
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(CURRENT)) }
}
