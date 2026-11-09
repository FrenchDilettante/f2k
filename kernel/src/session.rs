//! The session's end: ExitWindowsEx's work once the console server has taken the request.
//!
//! On Windows 2000, ExitWindowsEx goes to csrss, which tells winlogon; winlogon has csrss end the
//! session's processes, then calls NtShutdownSystem for every action but EWX_LOGOFF, and for a
//! logoff shows its logon dialog again. F2K has no winlogon (a known deviation, until the
//! session's own processes come): the console server stand-in takes the request
//! (`crate::csr`, the user server's API), and its control thread carries out the whole of it here,
//! after ExitWindowsEx has returned TRUE to its caller:
//! - Each of the console's processes is asked to end in turn, as csrss asks them: by shutdown
//!   level, the highest first, the caller last (see `Control::next_to_end`: each process starts at
//!   the default level, 0x280, until SetProcessShutdownParameters sets another; the console's order
//!   decides among them). The request is a control event — CTRL_LOGOFF_EVENT for EWX_LOGOFF,
//!   CTRL_SHUTDOWN_EVENT for every other action — delivered as Ctrl+C is, a thread of the process
//!   at its CtrlRoutine, which runs its handlers, the last registered first; the default handler
//!   ends the process.
//! - Each process has the wait (HKCU\Control Panel\Desktop\WaitToKillAppTimeout, documented at
//!   20,000 ms on Windows 2000; F2K has no registry value yet, so the constant) to end. One still
//!   running after it — a handler that returned TRUE without ending the process, say — is ended,
//!   where Windows would show its "End Program" dialog: F2K has no dialog, and ends it as Windows
//!   does with EWX_FORCE or SHUTDOWN_NORETRY. A COM1 line says so. EWX_FORCEIFHUNG asks for that
//!   same end after the wait.
//! - With EWX_FORCE, each process is ended without being asked, and without the wait.
//! - A process ended by the session's end exits with STATUS_CONTROL_C_EXIT, the code its default
//!   handler would have given it.
//! - Then the machine's end: nothing more for EWX_LOGOFF (with no logon to return to, the boot's
//!   runner sees its programs end and halts, as for any boot), [`shut_down`] for the rest, once
//!   every ended process has been torn down (`await_teardowns`): the waits above end at each
//!   process's end, which its waiters see before the idle thread reaps it, and the reap's report
//!   lines (the teardown audit, the suite's summary) come before the shutdown's first line.
//!
//! Two kernel options serve the test boots, as no program of the corpus calls ExitWindowsEx (a
//! real one would shut the capture machine down):
//! - `end-session=<flags>`: the first control event a program generates (GenerateConsoleCtrlEvent)
//!   is taken instead for ExitWindowsEx(<flags>) from that program, raised at the same point. The
//!   ctrl fixture generates its first event only once its child's handlers are in place, so a boot
//!   of it ends its session at a known point.
//! - `session-wait=<ms>`: the wait, shorter than 20 s for a boot to show a process ended after it.

/// The wait each process has to end once asked (WaitToKillAppTimeout's Windows 2000 default), in
/// milliseconds.
pub const WAIT_TO_KILL_APP_TIMEOUT_MS: u32 = 20_000;

/// The kernel option whose value, ExitWindowsEx's flags, turns the boot's first generated control
/// event into a request for the session's end.
const END_SESSION: &[u8] = b"end-session";

/// The kernel option whose value, in milliseconds, replaces the wait.
const SESSION_WAIT: &[u8] = b"session-wait";

/// The exit code of a process the session's end ends: STATUS_CONTROL_C_EXIT, its default
/// handler's.
const ENDED_STATUS: u32 = rtl::status::STATUS_CONTROL_C_EXIT;

/// A kernel option's number: decimal, or hexadecimal after `0x`; none for anything else.
fn number(text: &[u8]) -> Option<u32> {
    let text = core::str::from_utf8(text).ok()?;
    match text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        Some(hex) => u32::from_str_radix(hex, 16).ok(),
        None => text.parse().ok(),
    }
}

/// The flags of the `end-session` option in `kernel`'s command line, when it names flags
/// ExitWindowsEx takes.
fn end_session_flags(kernel: &[u8]) -> Option<u32> {
    let flags = number(crate::boot::cmdline::kernel_option_value(
        kernel,
        END_SESSION,
    )?)?;
    rtl::console::user::check_flags(flags).ok().map(|()| flags)
}

/// The wait the `session-wait` option in `kernel`'s command line sets, or the default one, in
/// milliseconds.
fn wait_ms(kernel: &[u8]) -> u32 {
    crate::boot::cmdline::kernel_option_value(kernel, SESSION_WAIT)
        .and_then(number)
        .unwrap_or(WAIT_TO_KILL_APP_TIMEOUT_MS)
}

/// The flags the kernel option `end-session` asks the boot's first generated control event to be
/// taken for; none without the option.
#[cfg(target_arch = "x86")]
pub fn option_flags() -> Option<u32> {
    end_session_flags(crate::boot::cmdline::kernel_command_line())
}

/// Host builds have no kernel command line.
#[cfg(not(target_arch = "x86"))]
pub fn option_flags() -> Option<u32> {
    None
}

/// End the session as `request` asks (see the module's documentation), on the console's control
/// thread, at the passive level; then the machine's end, for every action but EWX_LOGOFF.
#[cfg(target_arch = "x86")]
pub fn end(request: crate::csr::ctrl::SessionRequest) {
    use rtl::console::user::{action, forced};
    use rtl::console::{CTRL_LOGOFF_EVENT, CTRL_SHUTDOWN_EVENT};
    let action = action(request.flags);
    let event = match action {
        None => CTRL_LOGOFF_EVENT,
        Some(_) => CTRL_SHUTDOWN_EVENT,
    };
    let wait = wait_ms(crate::boot::cmdline::kernel_command_line());
    while let Some((process, routine)) = crate::csr::next_to_end(request.caller) {
        end_process(process, routine, event, forced(request.flags), wait);
    }
    crate::csr::session_ended();
    if let Some(action) = action {
        await_teardowns();
        shut_down(action);
    }
}

/// Wait, before the machine's end, until every process that has ended or is ending has been torn
/// down: the processes the session ended, and one that was leaving its console already (passed
/// over above). Their teardown audit and the runner's summary then come before the shutdown's
/// first line. The bound is the wait a process has to end (WaitToKillAppTimeout's default, not
/// the `session-wait` option, which shortens only the ending): a reap needs the idle thread, which
/// a process still running and never ending could keep off. Past it, a COM1 line says so and the
/// shutdown goes on.
#[cfg(target_arch = "x86")]
fn await_teardowns() {
    let interval = i64::from(WAIT_TO_KILL_APP_TIMEOUT_MS) * 10_000;
    if let Err(pending) = crate::process::teardowns::await_all(interval) {
        crate::serial_println!(
            "F2K: session: {} ended process(es) not torn down after {} ms: shutting down",
            pending,
            WAIT_TO_KILL_APP_TIMEOUT_MS
        );
    }
}

/// Ask the process `id` names to end (`event`, at its CtrlRoutine `routine`) and give it `wait`
/// milliseconds; end it if it is still running then, or at once when `forced`. Returns once it has
/// ended, or once a second wait for the end it was given has passed. A process gone already is
/// passed over.
#[cfg(target_arch = "x86")]
fn end_process(id: crate::ob::ObjectId, routine: u32, event: u32, forced: bool, wait: u32) {
    let interval = i64::from(wait) * 10_000;
    if !forced {
        // A process that is ending already, or cannot take the thread, is waited for all the same.
        let _ = crate::csr::ctrl::start_ctrl_thread(id, routine, event);
        if ended_within(id, interval) {
            return;
        }
        let named = with_process(id, |process| (process.id(), process.name()));
        if let Some((process_id, name)) = named {
            crate::serial_println!(
                "F2K: session: process {} ({}) still running after {} ms: ended",
                process_id,
                name.as_str(),
                wait
            );
        }
    }
    // Refused only when its end is under way already.
    with_process(id, |process| {
        let _ = crate::process::threads::terminate_process(process, ENDED_STATUS);
    });
    ended_within(id, interval);
}

/// `step` over the process `id` names, its object held for the step; none when it has gone.
#[cfg(target_arch = "x86")]
fn with_process<R>(
    id: crate::ob::ObjectId,
    step: impl FnOnce(&crate::process::Process) -> R,
) -> Option<R> {
    let _reference = crate::ob::reference(id)?;
    crate::process::pool::of_object(id).map(step)
}

/// Whether the process `id` names ends within `interval` (100 ns units): at once when it has
/// ended or gone already.
///
/// The wait holds no reference on the process's object, as a waiter's handle would: the last
/// process to end is reaped before the control thread runs again, and the runner's audit at that
/// reap would count a process still held as lost. Without one, the object is named by its index
/// alone, safely: a console process has run, so its object signals at its end, before its
/// deletion (which follows its reap), and the control thread, the highest-priority thread, runs
/// from the check to the wait without another thread between them.
#[cfg(target_arch = "x86")]
fn ended_within(id: crate::ob::ObjectId, interval: i64) -> bool {
    use crate::sched::wait::{wait_current_for, WaitReason};
    if !with_process(id, |process| process.end().is_none()).unwrap_or(false) {
        return true;
    }
    let ended = id.waitable().expect("a process object is waitable");
    wait_current_for(ended, WaitReason::Executive, Some(interval)) != crate::status::STATUS_TIMEOUT
}

/// The machine's end once the session has ended: the one step winlogon takes on Windows 2000 with
/// NtShutdownSystem(`action`), here the service's own path past its checks
/// (`crate::nt::shutdown::shut_down`): the volume flushed and marked clean, then the halt or the
/// restart.
///
/// It runs on the console's control thread, a system thread at the passive level that can wait,
/// once every console process has been asked and waited for. The console's state is reached only
/// for each step, at the dispatch level, and no volume lock is held here, so the shutdown's own
/// wait for the volume's lock lets a writer still holding it finish first (a process's
/// termination waits for its volume use to end, which is a critical region).
#[cfg(target_arch = "x86")]
pub fn shut_down(action: rtl::nt::ShutdownAction) -> ! {
    crate::nt::shutdown::shut_down(action)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `end-session` takes ExitWindowsEx's flags, decimal or hexadecimal, and only flags it
    /// accepts; `session-wait` replaces the 20 s wait.
    #[test]
    fn the_options_take_their_values() {
        assert_eq!(end_session_flags(b"k end-session=0 -- x"), Some(0));
        assert_eq!(end_session_flags(b"k end-session=0x5 -- x"), Some(5));
        assert_eq!(end_session_flags(b"k end-session=0x20 -- x"), None);
        assert_eq!(end_session_flags(b"k end-session=x -- x"), None);
        assert_eq!(end_session_flags(b"k -- x end-session=1"), None);
        assert_eq!(wait_ms(b"k -- x"), 20_000);
        assert_eq!(wait_ms(b"k session-wait=2000 -- x"), 2000);
        assert_eq!(wait_ms(b"k session-wait=soon -- x"), 20_000);
    }
}
