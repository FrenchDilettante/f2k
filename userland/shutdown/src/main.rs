//! shutdown.exe: shuts the local computer down, or restarts it, with the Windows 2000 Resource
//! Kit's command line (see the library). In order:
//! 1. the command line read: the usage for `/?` (ends with 0), the answer that no shutdown is
//!    pending for `/a`, the usage after the reason for one it does not take (ends with
//!    [`shutdown::USAGE`]);
//! 2. the local computer's name read, and a `\\computername` that is not it refused;
//! 3. SeShutdownPrivilege enabled in the process's token, the preamble every Windows program that
//!    shuts the machine down runs (F2K checks no privilege, but the calls succeed as Windows' do);
//! 4. without `/y`, the question, asked until it is answered Y or N;
//! 5. the message, then the countdown, a line rewritten each second, which Ctrl+C cancels;
//! 6. ExitWindowsEx: EWX_SHUTDOWN (Windows 2000's ends on "It is now safe to turn off your
//!    computer") or EWX_REBOOT, with EWX_FORCE for `/c`. It returns once the request is taken; the
//!    program then ends with 0, unless the session's end has ended it first.
//!
//! Anything that stops the shutdown ends the program with [`shutdown::NOT_ASKED`]: a no, Ctrl+C,
//! a computer refused, a call that failed (said on the standard error, with its Win32 error), or
//! `/a`.

#![no_std]
#![no_main]
#![forbid(unsafe_code)]

use shutdown::{Command, Options};

exe::entry!(main);

/// How long the countdown sleeps between two looks for Ctrl+C, in milliseconds.
const TICK: u32 = 100;

fn main() -> u32 {
    match shutdown::parse(exe::command_line()) {
        Ok(Command::Help) => {
            let _ = exe::stdout().print(format_args!("{}", shutdown::USAGE_TEXT));
            shutdown::ASKED
        }
        Ok(Command::Abort) => {
            let _ = exe::stderr().print(format_args!("{}", shutdown::NOTHING_TO_ABORT));
            shutdown::NOT_ASKED
        }
        Ok(Command::ShutDown(options)) => shut_down(&options),
        Err(usage) => {
            let _ = exe::stderr().print(format_args!("{usage}{}", shutdown::USAGE_TEXT));
            shutdown::USAGE
        }
    }
}

/// The shutdown `options` ask for, steps 2 to 6 (see the module's documentation): its exit code.
#[inline(never)]
fn shut_down(options: &Options) -> u32 {
    let mut buffer = [0; exe::MAX_COMPUTERNAME_LENGTH + 1];
    let local = match exe::computer_name(&mut buffer) {
        Ok(local) => local,
        Err(error) => return failed("the computer's name cannot be read", error),
    };
    if let Some(name) = &options.computer {
        if !shutdown::is_local(name, local) {
            let _ = exe::stderr().print(format_args!("{}", shutdown::NotLocal { name, local }));
            return shutdown::NOT_ASKED;
        }
    }
    if let Err(error) = enable_shutdown_privilege() {
        return failed("the shutdown privilege cannot be enabled", error);
    }
    // Ctrl+C cancels the question and the countdown rather than ending the program.
    let _ = exe::outlive_interrupts();
    let question = shutdown::Question {
        restart: options.restart,
        computer: local,
    };
    if !options.yes && !ask(&question) {
        let _ = exe::stdout().print(format_args!("{}", shutdown::CANCELLED));
        return shutdown::NOT_ASKED;
    }
    if !options.message.as_slice().is_empty() {
        let _ = exe::stdout().print(format_args!("{}\r\n", options.message));
    }
    if !count_down(options, local) {
        let _ = exe::stdout().print(format_args!("\r\n{}", shutdown::CANCELLED));
        return shutdown::NOT_ASKED;
    }
    let now = shutdown::Now {
        restart: options.restart,
        computer: local,
    };
    let _ = exe::stdout().print(format_args!("{now}"));
    let action = if options.restart {
        exe::EWX_REBOOT
    } else {
        exe::EWX_SHUTDOWN
    };
    let force = if options.force { exe::EWX_FORCE } else { 0 };
    if let Err(error) = exe::exit_windows(action | force) {
        return failed("the shutdown cannot be started", error);
    }
    shutdown::ASKED
}

/// Say on the standard error what failed, with its error: [`shutdown::NOT_ASKED`].
fn failed(what: &str, error: exe::Error) -> u32 {
    let _ = exe::stderr().print(format_args!("shutdown: {what} ({error})\r\n"));
    shutdown::NOT_ASKED
}

/// The preamble: the process's token opened, SeShutdownPrivilege's LUID looked up, and the
/// privilege enabled.
fn enable_shutdown_privilege() -> Result<(), exe::Error> {
    let token = exe::Token::open_own(exe::TOKEN_ADJUST_PRIVILEGES | exe::TOKEN_QUERY)?;
    let luid = exe::lookup_privilege(exe::SE_SHUTDOWN_NAME)?;
    token.enable(luid)
}

/// `question` asked until a line answers it: whether the answer is yes. Ctrl+C, the input's end
/// or a line that cannot be read answer no.
#[inline(never)]
fn ask(question: &shutdown::Question) -> bool {
    let mut line = [0; 64];
    loop {
        let _ = exe::stdout().print(format_args!("{question}"));
        match exe::read_line(&mut line) {
            Ok(exe::Input::Line(read)) => {
                if let Some(answer) = shutdown::answer(read) {
                    return answer;
                }
            }
            Ok(exe::Input::Aborted) => {
                let _ = exe::stdout().print(format_args!("\r\n"));
                return false;
            }
            Ok(exe::Input::End) | Err(_) => return false,
        }
    }
}

/// The countdown from `/t:xx`'s seconds, its line rewritten each second: false when Ctrl+C
/// cancelled it. Nothing for no delay.
#[inline(never)]
fn count_down(options: &Options, computer: &[u16]) -> bool {
    if options.delay == 0 {
        return true;
    }
    // A Ctrl+C before the countdown (answered by the question already) is not this one's.
    exe::take_interrupt();
    for seconds in (1..=options.delay).rev() {
        let line = shutdown::Countdown {
            restart: options.restart,
            computer,
            seconds,
            delay: options.delay,
        };
        let _ = exe::stdout().print(format_args!("{line}"));
        for _ in 0..1000 / TICK {
            exe::sleep(TICK);
            if exe::take_interrupt() {
                return false;
            }
        }
    }
    let _ = exe::stdout().print(format_args!("\r\n"));
    true
}
