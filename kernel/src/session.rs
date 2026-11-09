//! The session's end: ExitWindowsEx's work once the console server has taken the request.
//!
//! On Windows 2000, ExitWindowsEx goes to csrss, which tells winlogon; winlogon has csrss end the
//! session's processes, then calls NtShutdownSystem for every action but EWX_LOGOFF, and for a
//! logoff shows its logon dialog again. F2K has no winlogon (a known deviation, until the
//! session's own processes come): the console server stand-in takes the request
//! (`crate::csr`, the user server's API), and its control thread carries out the whole of it here,
//! after ExitWindowsEx has returned TRUE to its caller:
//! - Each process the server knows is asked to end in turn, as csrss asks them: by shutdown level,
//!   the highest first, the caller last (see `Control::next_to_end`: each process starts at the
//!   default level, 0x280, until SetProcessShutdownParameters sets another; the server's order
//!   decides among them). The server knows the console's processes, and the processes that entered
//!   win32k, set their shutdown parameters or asked for the end, console or not
//!   (`crate::csr::ctrl`).
//! - A process with top-level windows is asked through them, as csrss's user server asks it
//!   (WM_QUERYENDSESSION's and WM_ENDSESSION's documentation): each of its top-level windows with a
//!   procedure of its own — hidden ones included, message-only ones not — in z-order, gets
//!   WM_QUERYENDSESSION (lParam ENDSESSION_LOGOFF for EWX_LOGOFF, 0 for every other action); then
//!   each window asked gets WM_ENDSESSION, wParam TRUE, the same lParam; then the process is ended,
//!   as the documentation lets the system end it once its windows have returned from WM_ENDSESSION.
//!   A window answering FALSE cancels the session's end: the asking stops, the windows of the
//!   process asked so far get WM_ENDSESSION with wParam FALSE, no other process is asked, and there
//!   is no machine's end. A process ended before it is left ended. Each message waits for its
//!   answer for the HungAppTimeout (HKCU\Control Panel\Desktop\HungAppTimeout, documented at 5,000
//!   ms; F2K has no registry value yet, so the constant): a window not answering by then is hung,
//!   and its process is ended where Windows would show its "End Program" dialog. A COM1 line says
//!   so, as for a refusal.
//! - A process without such windows that is one of the console's is asked with a control event —
//!   CTRL_LOGOFF_EVENT for EWX_LOGOFF, CTRL_SHUTDOWN_EVENT for every other action — delivered as
//!   Ctrl+C is, a thread of the process at its CtrlRoutine, which runs its handlers, the last
//!   registered first; the default handler ends the process. It then has the wait (HKCU\Control
//!   Panel\Desktop\WaitToKillAppTimeout, documented at 20,000 ms on Windows 2000; again the
//!   constant) to end. One still running after it — a handler that returned TRUE without ending the
//!   process, say — is ended, where Windows would show its "End Program" dialog: F2K has no dialog,
//!   and ends it as Windows does with EWX_FORCE or SHUTDOWN_NORETRY. A COM1 line says so.
//!   EWX_FORCEIFHUNG asks for that same end after the wait.
//! - A process with neither is ended without being asked: there is nothing to ask it through, and
//!   the documentation's logoff ends every process of the session.
//! - With EWX_FORCE, each process is ended without being asked, and without the wait.
//! - A process ended by the session's end exits with STATUS_CONTROL_C_EXIT, the code its default
//!   handler would have given it.
//! - Then the machine's end, unless a window cancelled the session's end: nothing more for
//!   EWX_LOGOFF (with no logon to return to, the boot's runner sees its programs end and halts, as
//!   for any boot), [`shut_down`] for the rest, once every ended process has been torn down
//!   (`await_teardowns`): the waits above end at each process's end, which its waiters see before
//!   the idle thread reaps it, and the reap's report lines (the teardown audit, the suite's
//!   summary) come before the shutdown's first line.
//!
//! Two kernel options serve the test boots, as no program of the corpus calls ExitWindowsEx (a
//! real one would shut the capture machine down):
//! - `end-session=<flags>`: the first control event a program generates (GenerateConsoleCtrlEvent)
//!   is taken instead for ExitWindowsEx(<flags>) from that program, raised at the same point. The
//!   ctrl fixture generates its first event only once its child's handlers are in place, so a boot
//!   of it ends its session at a known point.
//! - `session-wait=<ms>`: the wait, shorter than 20 s for a boot to show a process ended after it.

use crate::win32k::window::{Hwnd, LParam, LResult, WParam};

/// The wait each process has to end once asked (WaitToKillAppTimeout's Windows 2000 default), in
/// milliseconds.
pub const WAIT_TO_KILL_APP_TIMEOUT_MS: u32 = 20_000;

/// The wait for a window's answer to WM_QUERYENDSESSION or WM_ENDSESSION (HungAppTimeout's
/// Windows 2000 default), in milliseconds: a window that has not answered by then is hung.
pub const HUNG_APP_TIMEOUT_MS: u32 = 5_000;

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

/// WM_QUERYENDSESSION's and WM_ENDSESSION's lParam for a session's end of `flags`:
/// ENDSESSION_LOGOFF for a logoff, 0 for every other action.
fn end_lparam(flags: u32) -> LParam {
    match rtl::console::user::action(flags) {
        None => rtl::user::ENDSESSION_LOGOFF as LParam,
        Some(_) => 0,
    }
}

/// How the session's end asks a process to end.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Asking {
    /// Through its top-level windows: WM_QUERYENDSESSION, then WM_ENDSESSION.
    Windows,
    /// Through the console: the control event, at this CtrlRoutine.
    Console(u32),
    /// Not at all: it is ended at once.
    Not,
}

/// How a process is asked: not at all with EWX_FORCE (`forced`); through its windows when it has
/// some to ask (`windows`), its console's CtrlRoutine (`routine`) aside, as csrss's user server
/// takes a process with windows before its console server does; through its console otherwise;
/// not at all when it has neither.
fn asking(forced: bool, windows: bool, routine: Option<u32>) -> Asking {
    match (forced, windows, routine) {
        (true, _, _) => Asking::Not,
        (false, true, _) => Asking::Windows,
        (false, false, Some(routine)) => Asking::Console(routine),
        (false, false, None) => Asking::Not,
    }
}

/// What came back from a message the session's end sent a window.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Answer {
    /// The window procedure's answer.
    Answered(LResult),
    /// Nothing: the window, or its thread's queue, went first, or the message could not be sent.
    Unreachable,
    /// No answer within the HungAppTimeout.
    Hung,
    /// The window's process ended before it answered.
    Ended,
}

/// What became of a process asked through its windows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Asked {
    /// Every window asked answered TRUE (or could not answer) and was told the session ends.
    Agreed,
    /// A window answered FALSE: the session's end is cancelled.
    Refused,
    /// A window did not answer within the HungAppTimeout.
    Hung,
    /// The process ended while it was asked.
    Ended,
}

/// The window manager's part in asking one process through its windows: the target's
/// ([`ProcessWindows`]), or a test's.
trait SessionWindows {
    /// Clear the marks an earlier session's end left on the process's windows.
    fn forget(&mut self);
    /// The next top-level window to ask WM_QUERYENDSESSION, marked asked.
    fn next_to_ask(&mut self) -> Option<Hwnd>;
    /// The next window asked to send WM_ENDSESSION to, its mark cleared.
    fn next_asked(&mut self) -> Option<Hwnd>;
    /// Send `message` to `hwnd` and wait for its answer.
    fn send(&mut self, hwnd: Hwnd, message: u32, wparam: WParam, lparam: LParam) -> Answer;
}

/// Ask a process through its windows (see the module's documentation): WM_QUERYENDSESSION to each
/// of its top-level windows in turn, until one answers FALSE; then WM_ENDSESSION to each window
/// asked, wParam TRUE, or FALSE once one refused. A window that cannot answer (it went meanwhile)
/// does not refuse. A hung window, or the process's own end, stops the asking; once the session's
/// end is cancelled, they only stop the telling.
fn ask_windows(windows: &mut impl SessionWindows, lparam: LParam) -> Asked {
    use rtl::user::{WM_ENDSESSION, WM_QUERYENDSESSION};
    windows.forget();
    let mut refused = false;
    while let Some(hwnd) = windows.next_to_ask() {
        match windows.send(hwnd, WM_QUERYENDSESSION, 0, lparam) {
            Answer::Answered(0) => {
                refused = true;
                break;
            }
            Answer::Answered(_) | Answer::Unreachable => {}
            Answer::Hung => return Asked::Hung,
            Answer::Ended => return Asked::Ended,
        }
    }
    while let Some(hwnd) = windows.next_asked() {
        match windows.send(hwnd, WM_ENDSESSION, WParam::from(!refused), lparam) {
            Answer::Answered(_) | Answer::Unreachable => {}
            Answer::Hung | Answer::Ended if refused => break,
            Answer::Hung => return Asked::Hung,
            Answer::Ended => return Asked::Ended,
        }
    }
    if refused {
        Asked::Refused
    } else {
        Asked::Agreed
    }
}

/// How the session under way ends its processes: the control event and the windows' lParam its
/// action gives, whether it forces them, and the wait each has once asked, in milliseconds.
#[cfg(target_arch = "x86")]
struct Ending {
    event: u32,
    lparam: LParam,
    forced: bool,
    wait: u32,
}

/// End the session as `request` asks (see the module's documentation), on the console's control
/// thread, at the passive level; then the machine's end, for every action but EWX_LOGOFF, unless a
/// window cancelled the session's end.
#[cfg(target_arch = "x86")]
pub fn end(request: crate::csr::ctrl::SessionRequest) {
    use rtl::console::user::{action, forced};
    use rtl::console::{CTRL_LOGOFF_EVENT, CTRL_SHUTDOWN_EVENT};
    let action = action(request.flags);
    let ending = Ending {
        event: match action {
            None => CTRL_LOGOFF_EVENT,
            Some(_) => CTRL_SHUTDOWN_EVENT,
        },
        lparam: end_lparam(request.flags),
        forced: forced(request.flags),
        wait: wait_ms(crate::boot::cmdline::kernel_command_line()),
    };
    let mut cancelled = false;
    while let Some((process, routine)) = crate::csr::next_to_end(request.caller) {
        if !end_process(process, routine, &ending) {
            cancelled = true;
            break;
        }
    }
    crate::csr::session_ended();
    if let (Some(action), false) = (action, cancelled) {
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

/// Ask the process `id` names to end, as [`asking`] decides — through its windows, or its
/// console's CtrlRoutine `routine` and the wait — and end it if it is still running then, or at
/// once when it is not asked. Returns once it has ended, or once a second wait for the end it was
/// given has passed: true, or false when one of its windows refused (the session's end is
/// cancelled, and the process left running). A process gone already is passed over.
#[cfg(target_arch = "x86")]
fn end_process(id: crate::ob::ObjectId, routine: Option<u32>, ending: &Ending) -> bool {
    let interval = i64::from(ending.wait) * 10_000;
    let owner = id.index;
    let windows = !ending.forced
        && crate::win32k::window::locked(|manager| manager.windows.has_session_windows(owner));
    match asking(ending.forced, windows, routine) {
        Asking::Windows => {
            match ask_windows(&mut ProcessWindows { process: id, owner }, ending.lparam) {
                Asked::Agreed => {}
                Asked::Refused => {
                    report(
                        id,
                        format_args!("refused to end: the session's end is cancelled"),
                    );
                    return false;
                }
                Asked::Hung => report(
                    id,
                    format_args!("not answering after {} ms: ended", HUNG_APP_TIMEOUT_MS),
                ),
                Asked::Ended => {
                    ended_within(id, interval);
                    return true;
                }
            }
        }
        Asking::Console(routine) => {
            // A process that is ending already, or cannot take the thread, is waited for all the
            // same.
            let _ = crate::csr::ctrl::start_ctrl_thread(id, routine, ending.event);
            if ended_within(id, interval) {
                return true;
            }
            report(
                id,
                format_args!("still running after {} ms: ended", ending.wait),
            );
        }
        Asking::Not => {}
    }
    // Refused only when its end is under way already.
    with_process(id, |process| {
        let _ = crate::process::threads::terminate_process(process, ENDED_STATUS);
    });
    ended_within(id, interval);
    true
}

/// The COM1 line for what the session's end did to the process `id` names: `what` after its id
/// and name. Nothing for a process gone.
#[cfg(target_arch = "x86")]
fn report(id: crate::ob::ObjectId, what: core::fmt::Arguments) {
    if let Some((process_id, name)) = with_process(id, |process| (process.id(), process.name())) {
        crate::serial_println!(
            "F2K: session: process {} ({}) {}",
            process_id,
            name.as_str(),
            what
        );
    }
}

/// The target's windows of one process, for [`ask_windows`]: the window manager's records of
/// them, and the queues the messages go through, sent as the console server sends
/// (`crate::win32k::queue::server_send`).
#[cfg(target_arch = "x86")]
struct ProcessWindows {
    process: crate::ob::ObjectId,
    owner: crate::win32k::class::Owner,
}

#[cfg(target_arch = "x86")]
impl SessionWindows for ProcessWindows {
    fn forget(&mut self) {
        crate::win32k::window::locked(|manager| manager.windows.session_forget(self.owner));
    }

    fn next_to_ask(&mut self) -> Option<Hwnd> {
        crate::win32k::window::locked(|manager| manager.windows.session_next_to_ask(self.owner))
    }

    fn next_asked(&mut self) -> Option<Hwnd> {
        crate::win32k::window::locked(|manager| manager.windows.session_next_asked(self.owner))
    }

    /// The message queued for the window's thread, then the server's wait for its answer, up to
    /// the HungAppTimeout, or the process's end. The process's object is waited on without a
    /// reference, as [`ended_within`] waits on it: nothing blocks between the look at its end and
    /// the wait.
    fn send(&mut self, hwnd: Hwnd, message: u32, wparam: WParam, lparam: LParam) -> Answer {
        use crate::win32k::queue::{self, ServerReply, ServerSending};
        let sending = queue::locked(|manager| {
            queue::server_send(&mut manager.windows, hwnd, message, wparam, lparam)
        });
        let ServerSending::Waiting(sent) = sending else {
            return Answer::Unreachable;
        };
        let deadline = queue::now() + u64::from(HUNG_APP_TIMEOUT_MS) * 10_000;
        loop {
            if let Some(reply) =
                queue::locked(|manager| queue::server_reply(&mut manager.windows, sent))
            {
                return match reply {
                    ServerReply::Answered(answer) => Answer::Answered(answer),
                    ServerReply::Dropped => Answer::Unreachable,
                };
            }
            let ended =
                !with_process(self.process, |process| process.end().is_none()).unwrap_or(false);
            let left = deadline.saturating_sub(queue::now());
            if ended || left == 0 {
                queue::locked(|manager| queue::server_abandon(&mut manager.windows, sent));
                return if ended { Answer::Ended } else { Answer::Hung };
            }
            let process = self
                .process
                .waitable()
                .expect("a process object is waitable");
            queue::wait_for_server(process, left as i64);
        }
    }
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
/// alone, safely: a process the server knows has run, so its object signals at its end, before its
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
/// once every process has been asked and waited for. The server's state is reached only for each
/// step, at the dispatch level, and no volume lock is held here, so the shutdown's own wait for
/// the volume's lock lets a writer still holding it finish first (a process's termination waits
/// for its volume use to end, which is a critical region).
#[cfg(target_arch = "x86")]
pub fn shut_down(action: rtl::nt::ShutdownAction) -> ! {
    crate::nt::shutdown::shut_down(action)
}

#[cfg(test)]
mod tests {
    use rtl::user::{WM_ENDSESSION, WM_QUERYENDSESSION};

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

    /// A process is asked through its windows when it has some, its console aside; through its
    /// console otherwise; not at all with EWX_FORCE, or with neither. A logoff's lParam is
    /// ENDSESSION_LOGOFF, every other action's 0.
    #[test]
    fn how_a_process_is_asked() {
        assert_eq!(asking(false, true, Some(0x1000)), Asking::Windows);
        assert_eq!(asking(false, true, None), Asking::Windows);
        assert_eq!(asking(false, false, Some(0x1000)), Asking::Console(0x1000));
        assert_eq!(asking(false, false, None), Asking::Not);
        assert_eq!(asking(true, true, Some(0x1000)), Asking::Not);
        assert_eq!(asking(true, false, Some(0x1000)), Asking::Not);
        assert_eq!(end_lparam(0), i32::MIN);
        assert_eq!(end_lparam(4), i32::MIN, "EWX_LOGOFF | EWX_FORCE");
        assert_eq!(end_lparam(1), 0);
        assert_eq!(end_lparam(2), 0);
        assert_eq!(end_lparam(8), 0);
    }

    /// A process's windows, as a test sets them: each window's answer to WM_QUERYENDSESSION and
    /// to WM_ENDSESSION, the marks, and every message sent, in order.
    struct Fake {
        windows: std::vec::Vec<(Hwnd, Answer, Answer)>,
        asked: std::vec::Vec<Hwnd>,
        sent: std::vec::Vec<(Hwnd, u32, WParam, LParam)>,
        forgotten: bool,
    }

    impl Fake {
        fn new(windows: &[(Hwnd, Answer, Answer)]) -> Self {
            Fake {
                windows: windows.to_vec(),
                asked: std::vec![],
                sent: std::vec![],
                forgotten: false,
            }
        }
    }

    impl SessionWindows for Fake {
        fn forget(&mut self) {
            self.forgotten = true;
            self.asked.clear();
        }

        fn next_to_ask(&mut self) -> Option<Hwnd> {
            let next = self.windows.iter().map(|w| w.0).find(|hwnd| {
                !self.asked.contains(hwnd) && !self.sent.iter().any(|s| s.0 == *hwnd)
            })?;
            self.asked.push(next);
            Some(next)
        }

        fn next_asked(&mut self) -> Option<Hwnd> {
            (!self.asked.is_empty()).then(|| self.asked.remove(0))
        }

        fn send(&mut self, hwnd: Hwnd, message: u32, wparam: WParam, lparam: LParam) -> Answer {
            self.sent.push((hwnd, message, wparam, lparam));
            let window = self.windows.iter().find(|w| w.0 == hwnd).unwrap();
            if message == WM_QUERYENDSESSION {
                window.1
            } else {
                window.2
            }
        }
    }

    const Q: u32 = WM_QUERYENDSESSION;
    const E: u32 = WM_ENDSESSION;
    const YES: Answer = Answer::Answered(1);
    const NO: Answer = Answer::Answered(0);
    const DONE: Answer = Answer::Answered(0);

    /// Every window answering TRUE (or unreachable): each asked in turn, then each told TRUE, with
    /// the session's lParam; the marks of an earlier end forgotten first.
    #[test]
    fn every_window_agrees() {
        let logoff = rtl::user::ENDSESSION_LOGOFF as LParam;
        let mut fake = Fake::new(&[
            (10, YES, DONE),
            (11, Answer::Unreachable, Answer::Unreachable),
            (12, Answer::Answered(7), DONE),
        ]);
        assert_eq!(ask_windows(&mut fake, logoff), Asked::Agreed);
        assert!(fake.forgotten);
        assert_eq!(
            fake.sent,
            [
                (10, Q, 0, logoff),
                (11, Q, 0, logoff),
                (12, Q, 0, logoff),
                (10, E, 1, logoff),
                (11, E, 1, logoff),
                (12, E, 1, logoff),
            ]
        );
    }

    /// A window answering FALSE: no window after it is asked, and each window asked, itself
    /// included, is told FALSE; the session's end is cancelled.
    #[test]
    fn a_window_refuses() {
        let mut fake = Fake::new(&[(10, YES, DONE), (11, NO, DONE), (12, YES, DONE)]);
        assert_eq!(ask_windows(&mut fake, 0), Asked::Refused);
        assert_eq!(
            fake.sent,
            [(10, Q, 0, 0), (11, Q, 0, 0), (10, E, 0, 0), (11, E, 0, 0)]
        );
        // A hung window, once the end is cancelled, stops the telling only.
        let mut fake = Fake::new(&[(10, YES, Answer::Hung), (11, NO, DONE)]);
        assert_eq!(ask_windows(&mut fake, 0), Asked::Refused);
        assert_eq!(fake.sent, [(10, Q, 0, 0), (11, Q, 0, 0), (10, E, 0, 0)]);
    }

    /// A window not answering, or the process's end, stops the asking: the process is hung, or
    /// gone already.
    #[test]
    fn a_hung_window_or_an_ended_process() {
        let mut fake = Fake::new(&[(10, YES, DONE), (11, Answer::Hung, DONE), (12, YES, DONE)]);
        assert_eq!(ask_windows(&mut fake, 0), Asked::Hung);
        assert_eq!(fake.sent, [(10, Q, 0, 0), (11, Q, 0, 0)]);
        let mut fake = Fake::new(&[(10, YES, Answer::Hung)]);
        assert_eq!(ask_windows(&mut fake, 0), Asked::Hung);
        let mut fake = Fake::new(&[(10, Answer::Ended, DONE), (11, YES, DONE)]);
        assert_eq!(ask_windows(&mut fake, 0), Asked::Ended);
        assert_eq!(fake.sent, [(10, Q, 0, 0)]);
        let mut fake = Fake::new(&[(10, YES, Answer::Ended), (11, YES, DONE)]);
        assert_eq!(ask_windows(&mut fake, 0), Asked::Ended);
        // A process with no window left to ask agrees.
        assert_eq!(ask_windows(&mut Fake::new(&[]), 0), Asked::Agreed);
    }
}
