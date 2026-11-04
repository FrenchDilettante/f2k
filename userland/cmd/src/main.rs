//! cmd.exe: F2K's command interpreter. It outlives Ctrl+C and Ctrl+Break, and reads its switches
//! (`cmd /?`'s). With `/C` it runs the string that follows and ends with its last command's return
//! code (not the ERRORLEVEL: see [`cmd::State::return_code`]); with `/K`
//! it runs it and goes on interactively; without either it prints its banner. Interactively it
//! prompts (as PROMPT says, `$P$G` without it) and reads a line from the console, again and again.
//!
//! A line's `%NAME%` variables are expanded first. `exit` ends the shell; `call`, `cd` (or
//! `chdir`), `cls`, `echo`, `path`, `prompt`, `rem`, `set`, `type` and `ver` are built in; any
//! other line names a program, found in the current directory and PATH with PATHEXT's extensions.
//! A Windows program is started, sharing the console, and waited for (Ctrl+C then reaches the
//! program, and the shell waits on); a batch file's lines run in the shell. A line Ctrl+C abandons
//! leaves what was typed and a fresh prompt below it. The shell ends with [`cmd::FAILED`] when the
//! standard input cannot be read, and with 0 at the input's end.

#![no_std]
#![no_main]
#![forbid(unsafe_code)]

use core::fmt::Write;
use core::sync::atomic::{AtomicU32, Ordering};

use cmd::batch::{self, LineReader};
use cmd::switches::{self, Then};
use cmd::{search, Command, Echo, Set, TooLong};

exe::entry!(main);

/// What a command leaves the shell to do.
enum Flow {
    /// Go on: the next line.
    Next,
    /// `exit /b` in a batch file: that batch ends (one that called it goes on).
    EndBatch,
    /// Every batch file ends, back to the prompt (Ctrl+C answered Y, or batches nested too deep).
    Abort,
    /// `exit`: the shell ends with the code.
    Exit(u32),
}

/// The batch file a line comes from.
struct Batch<'a> {
    /// The batch's name as typed, then what followed it on its line: its `%0` to `%9` and `%*`.
    arguments: &'a [u16],
    /// How many batch files run around it: 0 for one run from the prompt or `/C`'s string.
    depth: usize,
    /// Whether it is a `.cmd` script (see [`cmd::clears_errorlevel`]).
    cmd_script: bool,
}

fn main() -> u32 {
    // A shell that could not outlive Ctrl+C still runs: the key would end it.
    let _ = exe::outlive_interrupts();
    let mut state = cmd::State::default();
    let switches = switches::switches(exe::command_line());
    state.echo = !switches.echo_off;
    match switches.run {
        None => {
            let _ = exe::stdout().print(format_args!("{}", cmd::BANNER));
        }
        Some((then, string)) => {
            if let Flow::Exit(code) = run_string(string, switches.strip, &mut state) {
                return code;
            }
            if then == Then::End {
                return state.return_code;
            }
        }
    }
    interactive(&mut state)
}

// The helpers below each hold the buffers they need and are not inlined, so the main loop's frame
// carries none of them across its iterations.

/// `/C` or `/K`'s string, its quotes handled as `cmd /?` says, run as a typed line would be.
#[inline(never)]
fn run_string(string: &[u16], strip: bool, state: &mut cmd::State) -> Flow {
    let mut buffer = [0; cmd::LINE];
    let mut found = [0; exe::MAX_PATH];
    let mut executable = |name: &[u16]| find_program(name, &mut found).is_some();
    let Some(line) = switches::command_string(string, strip, &mut executable, &mut buffer) else {
        let _ = exe::stderr().print(format_args!("{}", cmd::TOO_LONG));
        state.failed();
        return Flow::Next;
    };
    execute(line, state, None)
}

/// The interactive shell: prompt, read a line, run it, until `exit` or the input's end.
#[inline(never)]
fn interactive(state: &mut cmd::State) -> u32 {
    let mut line = [0; cmd::LINE];
    loop {
        if state.echo {
            prompt(state.spaced);
        }
        // An interrupt before the read was the prompt's, or a program's: no batch's.
        let _ = exe::take_interrupt();
        match exe::read_line(&mut line) {
            Ok(exe::Input::Line(read)) => {
                if let Flow::Exit(code) = execute(read, state, None) {
                    return code;
                }
            }
            Ok(exe::Input::Aborted) => {
                // The console leaves the abandoned line as it echoed it, its cursor after it: the
                // next prompt goes below it, with no empty line between.
                let _ = exe::stdout().print(format_args!("\r\n"));
                state.spaced = false;
            }
            Ok(exe::Input::End) => return 0,
            Err(error) => {
                let _ = exe::stderr().print(format_args!(
                    "\r\ncmd: the standard input cannot be read ({error})\r\n"
                ));
                return cmd::FAILED;
            }
        }
    }
}

/// The prompt: an empty line first when `spaced`, then the PROMPT variable's text with its codes
/// replaced (the default's when there is none, or when it is too long to read).
#[inline(never)]
fn prompt(spaced: bool) {
    let mut text = [0; cmd::PROMPT_TEXT];
    let mut default = [0; cmd::DEFAULT_PROMPT.len()];
    let mut name = [0; cmd::PROMPT.len()];
    let text = match exe::environment_variable(wide(cmd::PROMPT, &mut name), &mut text) {
        Ok(Some(text)) => text,
        _ => wide(cmd::DEFAULT_PROMPT, &mut default),
    };
    let mut buffer = [0; exe::MAX_PATH];
    let directory = exe::current_directory(&mut buffer).unwrap_or(&[]);
    let time = time();
    let _ = exe::stdout().print(format_args!(
        "{}{}",
        if spaced { "\r\n" } else { "" },
        cmd::Prompt {
            text,
            directory,
            time: &time,
        }
    ));
}

/// ASCII `text` as UTF-16, in `buffer` (as long as it).
fn wide<'a>(text: &str, buffer: &'a mut [u16]) -> &'a [u16] {
    for (unit, byte) in buffer.iter_mut().zip(text.bytes()) {
        *unit = u16::from(byte);
    }
    &buffer[..text.len().min(buffer.len())]
}

/// The local time, as the prompt shows it.
fn time() -> cmd::Time {
    let time = exe::local_time();
    cmd::Time {
        year: time.year,
        month: time.month,
        weekday: time.day_of_week,
        day: time.day,
        hour: time.hour,
        minute: time.minute,
        second: time.second,
        milliseconds: time.milliseconds,
    }
}

/// The process's environment and current directory, as a line's expansion reads them.
struct Shell;

impl cmd::Variables for Shell {
    fn get(&mut self, name: &[u16], value: &mut [u16]) -> Result<Option<usize>, TooLong> {
        match exe::environment_variable(name, value) {
            Ok(value) => Ok(value.map(<[u16]>::len)),
            Err(_) => Err(TooLong),
        }
    }

    fn current_directory(&mut self, value: &mut [u16]) -> Result<usize, TooLong> {
        copy_current_directory(value)
    }

    fn time(&mut self) -> cmd::Time {
        time()
    }

    fn random(&mut self) -> u16 {
        random()
    }

    fn command_line(&self) -> &[u16] {
        exe::command_line()
    }
}

/// `%RANDOM%`'s generator's state: 0 until its first use seeds it from the clock.
static RANDOM: AtomicU32 = AtomicU32::new(0);

/// A number from 0 to 32767, from a linear congruential generator (C's `rand`'s constants).
fn random() -> u16 {
    let mut seed = RANDOM.load(Ordering::Relaxed);
    if seed == 0 {
        let time = exe::local_time();
        seed = (u32::from(time.minute) * 60 + u32::from(time.second)) * 1000
            + u32::from(time.milliseconds)
            + 1;
    }
    let next = seed.wrapping_mul(214_013).wrapping_add(2_531_011);
    RANDOM.store(next, Ordering::Relaxed);
    ((next >> 16) & 0x7FFF) as u16
}

/// The current directory, copied to the start of `value`: its length, 0 when it cannot be read.
#[inline(never)]
fn copy_current_directory(value: &mut [u16]) -> Result<usize, TooLong> {
    let mut buffer = [0; exe::MAX_PATH];
    let directory = exe::current_directory(&mut buffer).unwrap_or(&[]);
    value
        .get_mut(..directory.len())
        .ok_or(TooLong)?
        .copy_from_slice(directory);
    Ok(directory.len())
}

/// A line, typed or read from `batch`: its variables expanded (as that batch's line when there is
/// one), echoed after the prompt when it is a batch's and echo is on (unless `@` hides it), then
/// what it says done.
#[inline(never)]
fn execute(read: &[u16], state: &mut cmd::State, batch: Option<&Batch>) -> Flow {
    let mut buffer = [0; cmd::LINE];
    let arguments = batch.map(|batch| batch.arguments);
    let Ok(line) = cmd::expand(read, state.errorlevel, arguments, &mut Shell, &mut buffer) else {
        let _ = exe::stderr().print(format_args!("{}", cmd::TOO_LONG));
        state.spaced = true;
        state.return_code = 1;
        return Flow::Next;
    };
    if batch.is_some() && state.echo {
        if let Some(echoed) = batch::echoed(line) {
            prompt(state.spaced);
            let _ = exe::stdout().print(format_args!("{echoed}\r\n"));
        }
    }
    let command = cmd::parse(line);
    state.spaced = !matches!(command, Command::Empty | Command::ClearScreen);
    dispatch(command, state, batch, false)
}

/// What `command` says done. `called` when `call` runs it: a batch file it names returns to the
/// batch the line comes from, where one run without `call` replaces it. A command returns 0 unless
/// it fails or runs something that returns another code; a built-in that succeeds sets the
/// ERRORLEVEL to 0 when [`cmd::clears_errorlevel`] says so.
fn dispatch(
    command: Command<'_>,
    state: &mut cmd::State,
    batch: Option<&Batch>,
    called: bool,
) -> Flow {
    let clears = cmd::clears_errorlevel(&command, batch.is_some_and(|batch| batch.cmd_script));
    if command != Command::Empty {
        state.return_code = 0;
    }
    match command {
        Command::Empty | Command::Remark => {}
        Command::Call(argument) => {
            return dispatch(cmd::parse(argument), state, batch, true);
        }
        Command::Exit(argument) => {
            let exit = batch::exit(argument);
            if exit.batch && batch.is_some() {
                // The batch's ERRORLEVEL, not its return code: `exit /b` itself returns 0.
                if let Some(code) = exit.code {
                    state.errorlevel = code;
                }
                return Flow::EndBatch;
            }
            // Outside a batch file, `exit /b` ends the shell as `exit` does, its code the
            // ERRORLEVEL when it gives none.
            let default = if exit.batch { state.errorlevel } else { 0 };
            return Flow::Exit(exit.code.unwrap_or(default));
        }
        Command::ChangeDirectory(None) => print_current_directory(state),
        Command::ChangeDirectory(Some(path)) => {
            if exe::set_current_directory(path).is_err() {
                let _ = exe::stderr().print(format_args!("{}", cmd::PATH_NOT_FOUND));
                state.failed();
            }
        }
        Command::ClearScreen => {
            // Redirected, the screen's clearing is a form feed.
            if let Ok(false) = exe::clear_screen() {
                let _ = exe::stdout().print(format_args!("\u{C}"));
            }
        }
        Command::Echo(Echo::Show) => {
            let _ = exe::stdout().print(format_args!("{}", cmd::EchoState(state.echo)));
        }
        Command::Echo(Echo::On) => state.echo = true,
        Command::Echo(Echo::Off) => state.echo = false,
        Command::Echo(Echo::Text(text)) => {
            let _ = exe::stdout().print(format_args!("{}\r\n", cmd::Text(text)));
        }
        Command::Path(None) => print_path(state),
        Command::Path(Some(argument)) => {
            let value = (!cmd::clears_path(argument)).then_some(argument);
            assign(cmd::PATH, value, state);
        }
        Command::Prompt(text) => assign(cmd::PROMPT, text, state),
        Command::Set(argument) => set(argument, state),
        Command::Type(argument) => type_files(argument, state),
        Command::Version => {
            let _ = exe::stdout().print(format_args!("\r\n{}", cmd::BANNER));
        }
        Command::Run { line, word } => return run(line, word, state, batch, called),
    }
    if clears && state.return_code == 0 {
        state.errorlevel = 0;
    }
    Flow::Next
}

/// `cd` without an argument: the current directory, then CR LF.
#[inline(never)]
fn print_current_directory(state: &mut cmd::State) {
    let mut buffer = [0; exe::MAX_PATH];
    match exe::current_directory(&mut buffer) {
        Ok(directory) => {
            let _ = exe::stdout().print(format_args!("{}\r\n", cmd::Text(directory)));
        }
        Err(error) => {
            let _ = exe::stderr().print(format_args!(
                "cmd: the current directory cannot be read ({error})\r\n"
            ));
            state.failed();
        }
    }
}

/// The variable `name` (ASCII, PROMPT or PATH) set to `value`, or deleted (None); a failure
/// reported, and the command failed.
fn assign(name: &str, value: Option<&[u16]>, state: &mut cmd::State) {
    let mut buffer = [0; cmd::PROMPT.len()];
    if let Err(error) = exe::set_environment_variable(wide(name, &mut buffer), value) {
        report(error);
        state.failed();
    }
}

/// A Win32 error a built-in met, on the standard error: Windows 2000's text when the shell has
/// one.
fn report(exe::Error(code): exe::Error) {
    let _ = match cmd::message(code) {
        Some(text) => exe::stderr().print(format_args!("{text}")),
        None => exe::stderr().print(format_args!("cmd: error {code}\r\n")),
    };
}

/// `path` alone: `PATH=` and its value, or `No Path` without one. Read from the environment block,
/// so that a path of any length shows.
#[inline(never)]
fn print_path(state: &mut cmd::State) {
    let environment = match exe::environment() {
        Ok(environment) => environment,
        Err(error) => {
            report(error);
            return state.failed();
        }
    };
    let mut name = [0; cmd::PATH.len()];
    let path = wide(cmd::PATH, &mut name);
    let value = environment
        .entries()
        .find_map(|entry| cmd::value_of(entry, path));
    let mut out = exe::stdout();
    let _ = match value {
        Some(value) => out.print(format_args!("{}={}\r\n", cmd::PATH, cmd::Text(value))),
        None => out.print(format_args!("{}", cmd::NO_PATH)),
    };
}

/// `set`, in its forms: the variables shown, or one assigned or deleted. It fails, the ERRORLEVEL
/// 1, when no variable shows for a prefix, a variable to delete does not exist, or the argument
/// has no name.
#[inline(never)]
fn set(argument: &[u16], state: &mut cmd::State) {
    match cmd::set(argument) {
        Set::Show(prefix) => {
            let environment = match exe::environment() {
                Ok(environment) => environment,
                Err(error) => {
                    report(error);
                    return state.failed();
                }
            };
            let mut out = exe::stdout();
            let mut shown = false;
            for entry in environment
                .entries()
                .filter(|entry| cmd::listed(entry, prefix))
            {
                let _ = write!(out, "{}\r\n", cmd::Text(entry));
                shown = true;
            }
            let _ = out.flush();
            if let (false, Some(prefix)) = (shown, prefix) {
                let _ = exe::stderr().print(format_args!("{}", cmd::NotDefined(prefix)));
                state.failed();
            }
        }
        Set::Assign { name, value: [] } => {
            // A variable that does not exist is not there to delete. Its value is not needed: one
            // unit's room tells whether there is one.
            match exe::environment_variable(name, &mut [0; 1]) {
                Ok(None) => state.failed(),
                _ => {
                    if let Err(error) = exe::set_environment_variable(name, None) {
                        report(error);
                        state.failed();
                    }
                }
            }
        }
        Set::Assign { name, value } => {
            if let Err(error) = exe::set_environment_variable(name, Some(value)) {
                report(error);
                state.failed();
            }
        }
        Set::Incorrect => {
            let _ = exe::stderr().print(format_args!("{}", cmd::SYNTAX));
            state.failed();
        }
    }
}

/// `type`: each file the argument names, its bytes to the standard output as they are; with
/// several, each after its name (on the standard error, as Windows 2000's type writes it, so that
/// the files' bytes alone go where the output is redirected). A file that cannot be read is
/// reported, and `type` fails, the ERRORLEVEL 1.
fn type_files(argument: &[u16], state: &mut cmd::State) {
    let several = cmd::Names(argument).nth(1).is_some();
    let mut any = false;
    for name in cmd::Names(argument) {
        any = true;
        if let Err(error) = type_file(name, several) {
            report(error);
            if several {
                let _ = exe::stderr().print(format_args!("{}", cmd::NotProcessed(name)));
            }
            state.failed();
        }
    }
    if !any {
        let _ = exe::stderr().print(format_args!("{}", cmd::SYNTAX));
        state.failed();
    }
}

/// The file `name`'s bytes to the standard output, after its name when `several` files are typed.
/// It is read a kilobyte at a time.
#[inline(never)]
fn type_file(name: &[u16], several: bool) -> Result<(), exe::Error> {
    let file = exe::open_file(name)?;
    if several {
        let _ = exe::stderr().print(format_args!("{}", cmd::TypeHeader(name)));
    }
    let mut buffer = [0u8; 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            return Ok(());
        }
        exe::write_stdout_bytes(&buffer[..read])?;
    }
}

/// The program `word` names (see [`find_program`]), run with `line`: a batch file in the shell
/// (see [`run_batch`]), returning to `batch` when `called` and replacing it otherwise; any other
/// program started and waited for (see [`start_program`]). A word that names nothing is not
/// recognized, the ERRORLEVEL 9009.
#[inline(never)]
fn run(
    line: &[u16],
    word: &[u16],
    state: &mut cmd::State,
    batch: Option<&Batch>,
    called: bool,
) -> Flow {
    let mut found = [0; exe::MAX_PATH];
    let Some(length) = find_program(word, &mut found) else {
        let _ = exe::stderr().print(format_args!("{}", cmd::NotRecognized(word)));
        state.ended(cmd::NOT_RECOGNIZED);
        return Flow::Next;
    };
    let path = &found[..length];
    if !search::is_batch(path) {
        start_program(path, line, word, state);
        return Flow::Next;
    }
    let depth = batch.map_or(0, |batch| batch.depth + 1);
    match run_batch(path, line, depth, state) {
        flow @ (Flow::Exit(_) | Flow::Abort) => flow,
        // Control does not come back to a batch file that ran another without `call`.
        _ if batch.is_some() && !called => Flow::EndBatch,
        _ => Flow::Next,
    }
}

/// The program `word` (quotes and all) names, found as cmd.exe finds one: its path's length in
/// `found`, None when nothing goes by it. PATH and PATHEXT come from the environment block, so
/// that a PATH of any length is searched.
#[inline(never)]
fn find_program(word: &[u16], found: &mut [u16; exe::MAX_PATH]) -> Option<usize> {
    let mut name = [0; exe::MAX_PATH];
    let name = cmd::program_name(word, &mut name)?;
    let environment = exe::environment().ok();
    let lookup = |variable: &str| {
        let mut buffer = [0; 8];
        let variable = wide(variable, &mut buffer);
        environment.as_ref().and_then(|environment| {
            environment
                .entries()
                .find_map(|entry| cmd::value_of(entry, variable))
        })
    };
    let path = lookup(cmd::PATH).unwrap_or(&[]);
    let mut default = [0; search::DEFAULT_PATHEXT.len()];
    let pathext = match lookup("PATHEXT") {
        Some(pathext) => pathext,
        None => wide(search::DEFAULT_PATHEXT, &mut default),
    };
    search::search(name, path, pathext, &mut exe::file_exists, found).map(<[u16]>::len)
}

/// A batch file's lines run in the shell, `arguments` its `%0` to `%9` and `%*`, `depth` the
/// batch files around it. Before each line, a Ctrl+C or Ctrl+Break since the last asks whether to
/// end every batch file. Its labels and empty lines are skipped. It ends at its last line or
/// `exit /b`; the ERRORLEVEL is then its last command's (or `exit /b`'s), and so is its return
/// code (`exit /b` returning 0). The echo a batch file run from the prompt (or `/C`, `/K`) turns
/// on or off is put back once it ends, so that the prompt shows as before.
#[inline(never)]
fn run_batch(path: &[u16], arguments: &[u16], depth: usize, state: &mut cmd::State) -> Flow {
    if depth >= batch::DEPTH {
        let _ = exe::stderr().print(format_args!("{}", batch::RECURSION));
        return Flow::Abort;
    }
    let file = match exe::open_file(path) {
        Ok(file) => file,
        Err(error) => {
            report(error);
            state.failed();
            return Flow::Next;
        }
    };
    let echo = state.echo;
    let batch = Batch {
        arguments,
        depth,
        cmd_script: search::is_cmd_script(path),
    };
    let mut reader = LineReader::default();
    let mut units = [0; cmd::LINE];
    let flow = loop {
        if exe::take_interrupt() && terminate() {
            break Flow::Abort;
        }
        let line = match next_line(&file, &mut reader, &mut units) {
            Ok(Some(line)) => line,
            Ok(None) => break Flow::Next,
            Err(error) => {
                report(error);
                break Flow::Next;
            }
        };
        if batch::skipped(line) {
            continue;
        }
        match execute(line, state, Some(&batch)) {
            Flow::Next => {}
            Flow::EndBatch => break Flow::Next,
            flow => break flow,
        }
    };
    if depth == 0 {
        state.echo = echo;
    }
    flow
}

/// A batch file's next line, decoded from the OEM code page into `units`: None at its end.
#[inline(never)]
fn next_line<'a>(
    file: &exe::File,
    reader: &mut LineReader,
    units: &'a mut [u16],
) -> Result<Option<&'a [u16]>, exe::Error> {
    let mut bytes = [0; cmd::LINE];
    let Some(line) = reader.next_line(&mut |buffer| file.read(buffer), &mut bytes)? else {
        return Ok(None);
    };
    exe::oem_to_wide(line, units).map(Some)
}

/// `Terminate batch job (Y/N)? `, asked until a line answers it: whether to end every batch file.
/// A line that cannot be read ends them.
#[inline(never)]
fn terminate() -> bool {
    let mut line = [0; cmd::LINE];
    loop {
        let _ = exe::stdout().print(format_args!("{}", batch::TERMINATE));
        match exe::read_line(&mut line) {
            Ok(exe::Input::Line(read)) => {
                if let Some(answer) = batch::answer(read) {
                    return answer;
                }
            }
            Ok(exe::Input::Aborted) => {
                let _ = exe::take_interrupt();
                let _ = exe::stdout().print(format_args!("\r\n"));
            }
            Ok(exe::Input::End) | Err(_) => return true,
        }
    }
}

/// The program file `path`, started with `line` as its command line and waited for; its exit code
/// becomes the return code and the ERRORLEVEL. Errors go to the standard error, as Windows 2000's
/// cmd writes them; a program that cannot be started or waited for returns 1, the ERRORLEVEL
/// unchanged.
#[inline(never)]
fn start_program(path: &[u16], line: &[u16], word: &[u16], state: &mut cmd::State) {
    let mut buffer = [0; cmd::LINE + 1];
    let Some(command) = cmd::command_line(line, &mut buffer) else {
        // A line expanded is never longer than a line's units.
        return;
    };
    match exe::create_process_of(path, command) {
        Ok(process) => match process.wait() {
            Ok(code) => state.ended(code),
            Err(error) => {
                let _ = exe::stderr().print(format_args!(
                    "cmd: the program could not be waited for ({error})\r\n"
                ));
                state.return_code = 1;
            }
        },
        Err(exe::Error(code)) if cmd::NO_SUCH_PROGRAM.contains(&code) => {
            let _ = exe::stderr().print(format_args!("{}", cmd::NotRecognized(word)));
            state.ended(cmd::NOT_RECOGNIZED);
        }
        Err(exe::Error(code)) => {
            let _ = exe::stderr().print(format_args!("{}", cmd::CannotRun(word, code)));
            state.return_code = 1;
        }
    }
}
