//! The boot's programs, run one after another (or side by side, with the `concurrent` option).
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
//! process, or the summary. An audit line waits for quiescence, when no process remains that has
//! not been torn down (only then can the free frames be held to the post-boot baseline); the next
//! process starts at that point too, so each line follows its own process's end. The perf trace
//! dump (the `perf-trace` feature) lands at the last quiescent point, before the boot's last line.
//!
//! Each process carries its leg, its index in the list, and everything it reports goes by that leg
//! — its end line, its audit line, its screenshot pause, its count in the summary — never by which
//! leg started last. A process with no leg, one another process started, reports its end as a
//! child (`F2K: child process 136 (spawn) exited normally (exit code=0)`, by its process id and its
//! image's name), with no audit line, no pause and no count of its own.
//!
//! With the kernel option `concurrent` (`... concurrent -- CORPUS\sched.exe sleep ;; hello`), the
//! legs run side by side instead: the runner loads every leg first, announcing each with its
//! start line as it is loaded, then readies every main thread, and the scheduler runs them all at
//! once. Every load is done before any thread is ready: a load runs on the idle thread, in the
//! loaded process's address space, and a ready thread could preempt it. No reap starts a leg (every
//! leg has started); each leg's end line prints as it ends, its audit line at the next quiescent
//! point, and the summary once every leg is reaped. The program output of legs that overlap
//! interleaves on COM1, so the log is judged whole, not split by leg.
//!
//! With the kernel option `screens` (`F2K: ... screens -- CORPUS\console.exe info ;; ...`), each
//! process's end pauses the boot before its audit line, for the test harness to take a screenshot
//! of what the process left on the screen: the runner announces `F2K: screen: process N ended`
//! and waits, interrupts masked, until the harness writes the CMOS mailbox byte through QEMU's
//! monitor ([`crate::hw::rtc::await_mailbox`]), or a few seconds' worth of reads pass.

use crate::process::exit::{self, AtQuiescence, Identity, ProcessEnd, Suite};
use crate::process::Process;

/// The program a boot without a user command line runs.
const DEFAULT_PROGRAM: &[u8] = b"exit0";

/// How many programs the boot runs; 0 until the runner starts (the fault-test boots never start
/// it). Read by an ending process's report, outside the runner's account.
static mut LEGS: u32 = 0;
/// The runner's account of the boot's programs: the legs started and reaped, their outcomes, and
/// what waits to be reported.
static mut SUITE: Suite = Suite::new();

/// The runner's account (see [`SUITE`]).
fn suite() -> &'static mut Suite {
    // SAFETY: runner state; single CPU, touched only by the boot's start and the idle thread's
    // reap step, one call's borrow at a time.
    unsafe { &mut *core::ptr::addr_of_mut!(SUITE) }
}

/// Run the boot's programs: record the allocator baseline, ready the first program's main thread
/// (every program's, with the `concurrent` option), and enter the idle loop. Never returns.
pub fn run() -> ! {
    let legs = programs().count() as u32;
    // SAFETY: runner state; single-threaded boot, written only here.
    unsafe { core::ptr::write_volatile(core::ptr::addr_of_mut!(LEGS), legs) };
    suite().begin(legs);
    // The baseline for the per-process teardown audits: recorded once the boot's permanent
    // allocations are done, before the first process takes any frame.
    crate::process::record_allocator_baseline();
    use crate::boot::cmdline::{kernel_command_line, kernel_option};
    if kernel_option(kernel_command_line(), b"concurrent") {
        start_every_leg(legs);
    } else {
        start_leg(1);
    }
    crate::sched::idle::idle_loop()
}

/// Who `process`'s end reports as, by its own leg: a suite's leg by its index and name, the lone
/// program of a boot of one (or of a boot the runner does not drive), or a child by its process id
/// and name.
pub fn identity(process: &Process) -> Identity {
    exit::identity(process.leg(), leg_count(), process.id(), process.name())
}

/// The reap step's landing point, on the idle thread after a process's teardown: audit the
/// allocators' structures and, for a leg (`leg`, none for a child), pause for its screenshot and
/// defer its audit line. At a `quiescent` reap, compare the free frames with the post-boot
/// baseline and report every deferred line, counting each leg on a boot of several programs (see
/// [`Suite`]); then ready the next leg — or print the summary, after which the idle thread rests.
pub fn process_reaped(leg: Option<u32>, end: ProcessEnd, quiescent: bool) {
    let (frames_audit_ok, heap_audit_ok) = crate::process::audit_structures();
    let frames = quiescent.then(crate::process::frames_against_baseline);
    if let Some(index) = leg {
        pause_for_screen(index);
    }
    suite().reaped(leg, end, frames_audit_ok, heap_audit_ok);
    let Some((available, baseline)) = frames else {
        return;
    };
    // On a boot of one program, before the audit line: the harness stops the boot on it, so the
    // dump must land first.
    #[cfg(feature = "perf-trace")]
    if leg_count() <= 1 {
        crate::perf::report();
    }
    let after = suite().settle(available, baseline, |report| {
        crate::serial_println!("{}", report);
    });
    match after {
        AtQuiescence::Start(next) => start_leg(next),
        AtQuiescence::Summary(tally) => {
            // Before the summary line: the harness stops the boot on it.
            #[cfg(feature = "perf-trace")]
            crate::perf::report();
            crate::serial_println!("{}", tally);
        }
        AtQuiescence::Rest => {}
    }
}

/// How many reads of the mailbox a pause makes before the boot goes on unanswered: seconds' worth.
const SCREEN_PAUSE_READS: u32 = 20_000_000;

/// With the `screens` option, hold the boot at leg `index`'s end until the harness has taken its
/// screenshot (see the module's documentation).
fn pause_for_screen(index: u32) {
    use crate::boot::cmdline::{kernel_command_line, kernel_option};
    use crate::hw::rtc::{await_mailbox, SCREEN_MAILBOX};
    if !kernel_option(kernel_command_line(), b"screens") {
        return;
    }
    let answered = await_mailbox(
        &mut crate::hw::portio::Ports,
        SCREEN_MAILBOX,
        SCREEN_PAUSE_READS,
        || {
            crate::serial_println!("F2K: screen: process {} ended", index);
        },
    );
    if !answered {
        crate::serial_println!("F2K: screen: no answer, going on");
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

/// Start leg `index`: load it, then ready its main thread; the idle loop's next pass switches to
/// it.
fn start_leg(index: u32) {
    let process = load_leg(index);
    crate::process::threads::ready_main_thread(process);
}

/// With the `concurrent` option, start all `legs` at once: load every leg, in order, then ready
/// every main thread, in the same order (see the module's documentation).
///
/// # Panics
///
/// More legs than there can be processes at once.
fn start_every_leg(legs: u32) {
    use crate::process::MAX_PROCESSES;
    assert!(
        legs as usize <= MAX_PROCESSES,
        "{legs} programs run side by side, at most {MAX_PROCESSES}"
    );
    let mut loaded: [Option<&'static mut Process>; MAX_PROCESSES] = [const { None }; MAX_PROCESSES];
    for (slot, index) in loaded.iter_mut().zip(1..=legs) {
        *slot = Some(load_leg(index));
    }
    for process in loaded.iter_mut().flatten() {
        crate::process::threads::ready_main_thread(process);
    }
}

/// Announce leg `index` and load it: create its process — its program read off the boot volume, the
/// leg its own — and plant its main thread's start while the process's address space is the live
/// one, then end the load. The thread is not readied: nothing runs until the caller readies it, so
/// another leg could be loaded first.
fn load_leg(index: u32) -> &'static mut crate::process::Process {
    suite().started(index);
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
    let (process, entry) =
        crate::exec::loader::load_path(&path[..length], name, command_line, Some(index));
    crate::process::threads::start_main_thread(process, crate::user::main_thread_start(entry));
    crate::process::detach();
    process
}

/// How many programs the boot runs (0 before the runner starts).
fn leg_count() -> u32 {
    // SAFETY: runner state; single CPU, read-only here.
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(LEGS)) }
}
