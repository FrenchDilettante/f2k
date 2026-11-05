//! `start` run: a program started on its own, its priority class and directory as the switches
//! say, waited for with `/WAIT`; a built-in command or a batch file is run by a shell of its own,
//! `cmd /K`, as Windows' `start` runs one. There is one console, so the command always shares the
//! shell's, as `/B` asks (see the README).

use cmd::builtins::start::{self as rules, Start};
use cmd::{search, Command};
use exe::MAX_PATH;

use super::{report, wide};

/// `start`: its argument read (a switch it does not take fails it), its command started, and with
/// `/WAIT` waited for, its exit code the return code and the ERRORLEVEL. A command that cannot be
/// found or started fails it.
pub fn start(argument: &[u16], state: &mut cmd::State) {
    let start = match rules::parse(argument) {
        Ok(start) => start,
        Err(refused) => {
            let _ = exe::stderr().print(format_args!("{refused}"));
            return state.failed();
        }
    };
    let process = match cmd::parse(start.command) {
        Command::Run { line, word } => program(line, word, &start),
        _ => shell(start.command, &start),
    };
    let Some(process) = process else {
        return state.failed();
    };
    if start.wait {
        match process.wait() {
            Ok(code) => state.ended(code),
            Err(error) => {
                report(error);
                state.failed();
            }
        }
    }
}

/// The program `word` names, found as the shell finds one, started with `line` as its command
/// line; a batch file is run by a shell of its own. None, the reason reported, when nothing goes
/// by the name or it cannot be started.
#[inline(never)]
fn program(line: &[u16], word: &[u16], start: &Start<'_>) -> Option<exe::Process> {
    let mut found = [0; MAX_PATH];
    let Some(length) = crate::find_program(word, &mut found) else {
        let mut name = [0; MAX_PATH];
        let name = cmd::program_name(word, &mut name).unwrap_or(word);
        let _ = exe::stderr().print(format_args!(
            "The system cannot find the file {}.\r\n",
            cmd::Text(name)
        ));
        return None;
    };
    let path = &found[..length];
    if search::is_batch(path) {
        return shell(line, start);
    }
    let mut buffer = [0; cmd::LINE + MAX_PATH + 16];
    let Some(command) = cmd::command_line(line, word, &mut buffer) else {
        let _ = exe::stderr().print(format_args!("{}", cmd::TOO_LONG));
        return None;
    };
    create(path, command, start)
}

/// A shell of its own (COMSPEC's program, the shell's own file without one) running `command` and
/// staying (`/K`), or alone without one.
#[inline(never)]
fn shell(command: &[u16], start: &Start<'_>) -> Option<exe::Process> {
    let mut path = [0; MAX_PATH];
    let mut name = [0; 7];
    let path = match exe::environment_variable(wide("COMSPEC", &mut name), &mut path) {
        Ok(Some(path)) if !path.is_empty() => path,
        _ => {
            let mut own = [0; MAX_PATH];
            let own = match exe::program_path(&mut own) {
                Ok(own) => own,
                Err(error) => {
                    report(error);
                    return None;
                }
            };
            let length = own.len();
            path[..length].copy_from_slice(own);
            &path[..length]
        }
    };
    let mut line = [0; cmd::LINE + MAX_PATH + 8];
    let mut length = 0;
    let mut put = |units: &[u16]| {
        let end = length + units.len();
        if let Some(target) = line.get_mut(length..end) {
            target.copy_from_slice(units);
        }
        length = end;
    };
    let mut switch = [0; 4];
    put(&[u16::from(b'"')]);
    put(path);
    put(&[u16::from(b'"')]);
    if !command.is_empty() {
        put(wide(" /K ", &mut switch));
        put(command);
    }
    put(&[0]);
    if length > line.len() {
        let _ = exe::stderr().print(format_args!("{}", cmd::TOO_LONG));
        return None;
    }
    create(path, &mut line[..length], start)
}

/// The program file `path` started with `command` (its NUL included), in `/D`'s directory and at
/// the priority class a switch gave.
fn create(path: &[u16], command: &mut [u16], start: &Start<'_>) -> Option<exe::Process> {
    let mut buffer = [0; MAX_PATH];
    let directory = match start.directory {
        Some(directory) => cmd::program_name(directory, &mut buffer),
        None => None,
    };
    match exe::create_process_in(path, command, start.priority.unwrap_or(0), directory) {
        Ok(process) => Some(process),
        Err(error) => {
            report(error);
            None
        }
    }
}
