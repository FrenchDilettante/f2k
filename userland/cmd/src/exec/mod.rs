//! The built-ins src/builtins reads, run: the file built-ins (src/exec/files.rs), the console
//! and clock built-ins (src/exec/console.rs), `dir` (src/exec/dir.rs) and `start`
//! (src/exec/start.rs), each with the calls it makes and the questions it asks.
//!
//! What a built-in leaves the ERRORLEVEL and its return code as follows the shell's rules (see
//! [`cmd::clears_errorlevel`]): a failure sets both to 1, and success leaves the dispatcher to set
//! the ERRORLEVEL to 0 for the built-ins that clear it. `del` is the exception: it sets the
//! ERRORLEVEL to 0 even when a name found nothing or a file could not be deleted, which it
//! returns 1 for.

mod console;
mod dir;
mod files;
mod start;

use core::fmt;
use core::sync::atomic::{AtomicUsize, Ordering};

use cmd::builtins::files::{overwrite_answer, Answer};
use cmd::builtins::Builtin;

/// How many directories `pushd` saved, as the prompt's `$+` shows them: the shell's
/// [`cmd::State::directories`] counted after each built-in, for the prompt, which has no state.
static DEPTH: AtomicUsize = AtomicUsize::new(0);

/// How many directories `pushd` has saved.
pub fn depth() -> usize {
    DEPTH.load(Ordering::Relaxed)
}

/// `builtin` run. `in_batch` when its line comes from a batch file: `copy` and `move` then
/// replace files without asking, unless `/-Y` says to ask.
pub fn run(builtin: Builtin<'_>, state: &mut cmd::State, in_batch: bool) {
    match builtin {
        Builtin::Delete(argument) => files::delete(argument, state),
        Builtin::MakeDirectory(argument) => files::make_directories(argument, state),
        Builtin::RemoveDirectory(argument) => files::remove_directories(argument, state),
        Builtin::Copy(argument) => files::copy(argument, state, in_batch),
        Builtin::Rename(argument) => files::rename(argument, state),
        Builtin::Move(argument) => files::move_files(argument, state, in_batch),
        Builtin::PushDirectory(path) => console::push_directory(path, state),
        Builtin::PopDirectory => console::pop_directory(state),
        Builtin::Title(title) => console::title(title),
        Builtin::Colour(argument) => console::colour(argument, state),
        Builtin::Date(argument) => console::date(argument, state),
        Builtin::Time(argument) => console::time(argument, state),
        Builtin::Pause => console::pause(),
        Builtin::Directory(argument) => dir::list(argument, state),
        Builtin::Start(argument) => start::start(argument, state),
    }
    DEPTH.store(state.directories.depth(), Ordering::Relaxed);
}

/// A Win32 error a built-in met, on the standard error: Windows 2000's text when the shell has
/// one.
fn report(exe::Error(code): exe::Error) {
    let _ = match cmd::builtins::files::message(code) {
        Some(text) => exe::stderr().print(format_args!("{text}")),
        None => exe::stderr().print(format_args!("cmd: error {code}\r\n")),
    };
}

/// `question` asked on the standard output until a line answers it Y or N (see
/// [`cmd::batch::answer`]): whether the answer is Y. A line that cannot be read answers N.
#[inline(never)]
fn ask(question: impl fmt::Display) -> bool {
    let mut line = [0; cmd::LINE];
    loop {
        let _ = exe::stdout().print(format_args!("{question}"));
        match exe::read_line(&mut line) {
            Ok(exe::Input::Line(read)) => {
                if let Some(answer) = cmd::batch::answer(read) {
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

/// `copy`'s and `move`'s question before replacing the file `path` (its full path), asked until a
/// line answers it Yes, No or All. A line that cannot be read answers No.
#[inline(never)]
fn ask_overwrite(path: &[u16]) -> Answer {
    let mut line = [0; cmd::LINE];
    loop {
        let _ = exe::stdout().print(format_args!("{}", cmd::builtins::files::Overwrite(path)));
        match exe::read_line(&mut line) {
            Ok(exe::Input::Line(read)) => {
                if let Some(answer) = overwrite_answer(read) {
                    return answer;
                }
            }
            Ok(exe::Input::Aborted) => {
                let _ = exe::stdout().print(format_args!("\r\n"));
                return Answer::No;
            }
            Ok(exe::Input::End) | Err(_) => return Answer::No,
        }
    }
}

/// ASCII `text` as UTF-16, in `buffer` (as long as it).
fn wide<'a>(text: &str, buffer: &'a mut [u16]) -> &'a [u16] {
    for (unit, byte) in buffer.iter_mut().zip(text.bytes()) {
        *unit = u16::from(byte);
    }
    &buffer[..text.len().min(buffer.len())]
}
