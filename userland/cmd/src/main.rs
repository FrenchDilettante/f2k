//! cmd.exe: F2K's command interpreter. It outlives Ctrl+C and Ctrl+Break, and reads its switches
//! (`cmd /?`'s). With `/C` it runs the string that follows and ends with its last command's return
//! code (not the ERRORLEVEL: see [`cmd::State::return_code`]); with `/K`
//! it runs it and goes on interactively; without either it prints its banner. With `/U`, what it
//! writes to a file or a pipe (its built-ins' output and its messages) is UTF-16LE. Interactively
//! it prompts (as PROMPT says, `$P$G` without it) and reads a line from the console, again and
//! again, or from the file or pipe its standard input is, echoing each line after the prompt.
//!
//! A line's `%NAME%` variables are expanded first (a block's lines each as it is read, until the
//! group it opens closes), then its commands run as its operators say (`&`, `&&`, `||`, `|`,
//! groups in parentheses: cmd::syntax), `if` and `for` as src/control.rs runs them, each with its
//! redirections: the shell's standard handles replaced while it runs, so that a built-in writes to
//! them and a program is handed them. `exit` ends the shell; `call`, `cd` (or `chdir`), `cls`,
//! `echo`, `goto`, `path`, `prompt`, `rem`, `set`, `shift`, `type` and `ver` are built in, with the
//! file, console and clock built-ins (src/exec/); any other command names a program, found in the
//! current directory and PATH with PATHEXT's extensions. A Windows program is started,
//! sharing the console, and waited for (Ctrl+C then reaches the program, and the shell waits on); a
//! batch file's lines run in the shell. The commands a pipe joins run at once, each a process: a
//! program itself, anything else a `cmd /c` of its own. A line Ctrl+C abandons leaves what was
//! typed and a fresh prompt below it. The shell ends with [`cmd::FAILED`] when the standard input
//! cannot be read, and with 0 at the input's end.

#![no_std]
#![no_main]
#![forbid(unsafe_code)]

use core::cell::{Cell, RefCell};
use core::fmt::Write;
use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

use cmd::batch::{self, LineReader};
use cmd::builtins::files;
use cmd::flow::label;
use cmd::switches::{self, Then};
use cmd::syntax::{self, Element, Join, Kind, Redirection, Redirections, Syntax, Target};
use cmd::{search, Command, Echo, Set, TooLong};

mod control;
mod exec;
mod set_switch;

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
    /// `goto`: the batch file goes on after the label its [`Batch::label`] holds.
    Goto,
    /// A batch file run without `call`: it takes the place of the one running, whose
    /// [`Batch::arguments`] now hold its path and its line.
    Chain,
}

/// The units a block (a line and the lines a group it opens holds, expanded) may hold in a batch
/// file, at the prompt and in `/C`'s string.
const BLOCK: usize = 4096;

/// The units a typed line or `/C`'s string, a block of them included, may hold once expanded.
const COMMAND: usize = cmd::MAX_COMMAND + 1;

/// The units a label `goto` goes to may hold.
const LABEL: usize = 128;

/// A batch file's arguments, its own copy: its name as typed and what followed it on its line,
/// its path as found, and how `shift` moved them.
struct Arguments {
    line: [u16; cmd::LINE],
    length: usize,
    path: [u16; exe::MAX_PATH],
    path_length: usize,
    shifted: [usize; 10],
}

impl Arguments {
    /// The batch file at `path`, run with `line`, as it starts (what does not fit is cut).
    fn new(line: &[u16], path: &[u16]) -> Self {
        let mut arguments = Arguments {
            line: [0; cmd::LINE],
            length: 0,
            path: [0; exe::MAX_PATH],
            path_length: 0,
            shifted: [0; 10],
        };
        arguments.set(line, path);
        arguments
    }

    /// The batch file at `path`, run with `line`, in place of the one these were.
    fn set(&mut self, line: &[u16], path: &[u16]) {
        self.length = line.len().min(self.line.len());
        self.line[..self.length].copy_from_slice(&line[..self.length]);
        self.path_length = path.len().min(self.path.len());
        self.path[..self.path_length].copy_from_slice(&path[..self.path_length]);
        self.shifted = core::array::from_fn(|n| n);
    }

    /// The batch file's path.
    fn path(&self) -> &[u16] {
        &self.path[..self.path_length]
    }

    /// The arguments as the expansion reads them.
    fn view(&self) -> cmd::Arguments<'_> {
        cmd::Arguments {
            line: &self.line[..self.length],
            shifted: self.shifted,
            path: self.path(),
        }
    }
}

/// The batch file a line comes from, or what `call :label` runs of one (a batch file of its own,
/// with its own arguments).
struct Batch {
    /// Its `%0` to `%9` and `%*`, and its path.
    arguments: RefCell<Arguments>,
    /// How many batch files run around it: 0 for one run from the prompt or `/C`'s string.
    depth: usize,
    /// Whether the batch file run from the prompt (or `/C`'s string), around it, is a `.cmd`
    /// script (see [`cmd::clears_errorlevel`]): the batch files it runs read their commands as
    /// it does, whatever their own extension.
    cmd_script: bool,
    /// The label `goto` goes to, and its length.
    label: RefCell<([u16; LABEL], usize)>,
    /// Where its file is read: the bytes before the line after the one running, where `call
    /// :label` starts looking for its label.
    offset: Cell<u64>,
}

impl Batch {
    fn new(line: &[u16], path: &[u16], depth: usize, cmd_script: bool) -> Self {
        Batch {
            arguments: RefCell::new(Arguments::new(line, path)),
            depth,
            cmd_script,
            label: RefCell::new(([0; LABEL], 0)),
            offset: Cell::new(0),
        }
    }
}

/// Where the shell's stack was when it started: the address of a local of [`main`]'s.
static STACK_TOP: AtomicUsize = AtomicUsize::new(0);

/// The stack a batch file may start nesting in: the thread's 1 MiB (its image's reserve), less
/// what the deepest batch file's line may still need below it (blocks, `for` and `if` in each
/// other, a `call`). Past it, a batch file nesting another one stops every batch file, as
/// Windows' cmd does once its stack runs out (`batch::RECURSION`).
const STACK_BUDGET: usize = 0x10_0000 - 0x1_8000;

/// The bytes of stack in use below [`main`]'s frame, as the address of a local here tells.
#[inline(never)]
fn stack_used() -> usize {
    let here = 0u8;
    let at = core::hint::black_box(&here) as *const u8 as usize;
    STACK_TOP.load(Ordering::Relaxed).saturating_sub(at)
}

fn main() -> u32 {
    let top = 0u8;
    STACK_TOP.store(
        core::hint::black_box(&top) as *const u8 as usize,
        Ordering::Relaxed,
    );
    // A shell that could not outlive Ctrl+C still runs: the key would end it.
    let _ = exe::outlive_interrupts();
    let mut state = cmd::State::default();
    let switches = switches::switches(exe::command_line());
    exe::set_unicode_output(switches.unicode);
    if switches.help {
        let _ = exe::stdout().print(format_args!("{}", cmd::help::CMD));
        return cmd::help::SHOWN;
    }
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
    let Some(line) =
        switches::command_string(string, strip, &mut executable, &mut buffer[..cmd::MAX_LINE])
    else {
        let _ = exe::stderr().print(format_args!("{}", cmd::TOO_LONG));
        state.failed();
        return Flow::Next;
    };
    let length = line.len();
    let mut block = [0; COMMAND];
    // The string is all there is: a group it leaves open stays open.
    execute(&mut buffer, length, &mut block, state, None, &mut |_| {
        More::End
    })
}

/// The interactive shell: prompt, read a line, run it, until `exit` or the input's end. A standard
/// input that is no console is read as [`redirected_input`] says.
#[inline(never)]
fn interactive(state: &mut cmd::State) -> u32 {
    if !exe::standard_input_is_console() {
        return redirected_input(state);
    }
    let mut line = [0; cmd::LINE];
    let mut block = [0; COMMAND];
    loop {
        if state.echo {
            prompt(state.spaced);
        }
        // An interrupt before the read was the prompt's, or a program's: no batch's.
        let _ = exe::take_interrupt();
        match exe::read_line(&mut line) {
            Ok(exe::Input::Line(read)) => {
                let length = read.len();
                // A line ending with `^`, or leaving a group open, goes on with the next one,
                // read after `More? `.
                let mut more = |raw: &mut [u16]| {
                    let _ = exe::stdout().print(format_args!("{MORE}"));
                    match exe::read_line(raw) {
                        Ok(exe::Input::Line(read)) => More::Line(read.len()),
                        Ok(exe::Input::Aborted) => {
                            let _ = exe::stdout().print(format_args!("\r\n"));
                            More::Abandon
                        }
                        Ok(exe::Input::End) | Err(_) => More::End,
                    }
                };
                if let Flow::Exit(code) =
                    execute(&mut line, length, &mut block, state, None, &mut more)
                {
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

/// The shell reading its commands from a file or a pipe (`cmd < file`, `x | cmd`): prompt, read a
/// line (OEM bytes, ended by LF, a CR before it dropped), echo it after the prompt as the console
/// would have, run it; until `exit` or the input's end. The input is read a byte at a time, so that
/// a program a line starts reads the input from the next line on, as it shares the input with the
/// shell.
#[inline(never)]
fn redirected_input(state: &mut cmd::State) -> u32 {
    let mut reader = LineReader::default();
    let mut units = [0; cmd::LINE];
    let mut block = [0; COMMAND];
    let read = |buffer: &mut [u8]| {
        let byte = buffer.len().min(1);
        exe::read_standard_input(&mut buffer[..byte])
    };
    loop {
        if state.echo {
            prompt(state.spaced);
        }
        let _ = exe::take_interrupt();
        let line = match next_line(read, &mut reader, &mut units) {
            Ok(Some(line)) => line,
            Ok(None) => return 0,
            Err(error) => {
                let _ = exe::stderr().print(format_args!(
                    "\r\ncmd: the standard input cannot be read ({error})\r\n"
                ));
                return cmd::FAILED;
            }
        };
        let echo = state.echo;
        if echo {
            let _ = exe::stdout().print(format_args!("{}\r\n", cmd::Text(line)));
        }
        let length = line.len();
        // A line going on (`^`, a group left open) reads the next one, echoed after `More? `.
        let mut more = |raw: &mut [u16]| match next_line(read, &mut reader, raw) {
            Ok(Some(line)) => {
                if echo {
                    let _ = exe::stdout().print(format_args!("{MORE}{}\r\n", cmd::Text(line)));
                }
                More::Line(line.len())
            }
            _ => More::End,
        };
        if let Flow::Exit(code) = execute(&mut units, length, &mut block, state, None, &mut more) {
            return code;
        }
    }
}

/// What the shell prints before reading the next line of a line that goes on.
const MORE: &str = "More? ";

/// The next line of a line that goes on (what [`execute`] reads it from gives).
enum More {
    /// Its length, in the buffer handed over.
    Line(usize),
    /// None: the input ended (or there is no more, as after `/C`'s string).
    End,
    /// Ctrl+C abandoned it, and the line with it.
    Abandon,
}

/// The prompt: an empty line first when `spaced`, then the PROMPT variable's text with its codes
/// replaced (the default's when there is none, or when it is too long to read).
///
/// A text of [`cmd::PROMPT_TEXT`] units or more shows its first 511 units, then its first 512:
/// batline's capture has a 600-character prompt (no codes) written as 1,023 bytes where a
/// 4-character one is written as 4, which is neither the text cut at 511 (the size public sources
/// describe) nor the default prompt. Windows 2000's cmd keeps the prompt in a 512-unit buffer,
/// and its output reads as that buffer, filled with no end, shown on into the text after it.
#[inline(never)]
fn prompt(spaced: bool) {
    let mut text = [0; cmd::LINE];
    let mut default = [0; cmd::DEFAULT_PROMPT.len()];
    let mut name = [0; cmd::PROMPT.len()];
    let text = match exe::environment_variable(wide(cmd::PROMPT, &mut name), &mut text) {
        Ok(Some(text)) => text,
        _ => wide(cmd::DEFAULT_PROMPT, &mut default),
    };
    let (first, second) = if text.len() >= cmd::PROMPT_TEXT {
        (&text[..cmd::PROMPT_TEXT - 1], &text[..cmd::PROMPT_TEXT])
    } else {
        (text, &text[..0])
    };
    let mut buffer = [0; exe::MAX_PATH];
    let directory = exe::current_directory(&mut buffer).unwrap_or(&[]);
    let time = time();
    let shown = |text| cmd::Prompt {
        text,
        directory,
        time: &time,
        depth: exec::depth(),
    };
    let _ = exe::stdout().print(format_args!(
        "{}{}{}",
        if spaced { "\r\n" } else { "" },
        shown(first),
        shown(second),
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
    shell_time(&exe::local_time())
}

/// A SYSTEMTIME as the shell's own time.
fn shell_time(time: &exe::SystemTime) -> cmd::Time {
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

    fn full_path(&mut self, name: &[u16], value: &mut [u16]) -> Option<usize> {
        let mut buffer = [0; exe::MAX_PATH];
        let path = exe::full_path(name, &mut buffer).ok()?;
        let target = value.get_mut(..path.len())?;
        target.copy_from_slice(path);
        // A file there is keeps its own name's case (`%~x0` of `x` found as `x.CMD` is the
        // file's `.cmd`), as the directory holds it.
        if !files::has_wildcards(path) {
            if let Some(found) = exe::find(path).ok().and_then(|mut find| find.next()) {
                let (_, last) = files::split(target);
                let start = path.len() - last.len();
                if files::same_path(last, found.name()) {
                    target[start..].copy_from_slice(found.name());
                }
            }
        }
        Some(path.len())
    }

    fn file(&mut self, path: &[u16]) -> Option<(u32, u64)> {
        let found = exe::find(path).ok()?.next()?;
        Some((found.attributes, found.size))
    }

    fn short_path(&mut self, path: &[u16], value: &mut [u16]) -> Option<usize> {
        let mut buffer = [0; exe::MAX_PATH];
        let short = exe::short_path(path, &mut buffer).ok()?;
        value.get_mut(..short.len())?.copy_from_slice(short);
        Some(short.len())
    }

    fn written(&mut self, path: &[u16]) -> Option<cmd::Time> {
        let found = exe::find(path).ok()?.next()?;
        found.written().map(|time| shell_time(&time))
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

/// A line, typed or read from `batch`, in `raw` (`length` units): its variables expanded into
/// `block` (as that batch's line when there is one), and, while it leaves a group open (or, typed,
/// ends with `^`), the lines `more` gives after it, each expanded as it comes, a line feed between
/// them (a `^` ending a typed line goes instead; a batch file's lines join at a `^` as they are
/// read); empty lines and labels in a block are skipped. The line is then read (a line that
/// cannot run is reported, and fails), echoed after the prompt when it is a batch's and echo is on
/// (unless `@` hides it), then what it says done.
///
/// In a batch file, a line that expands past [`cmd::MAX_LINE`] or cannot run ends every batch
/// file, its return code [`syntax::FATAL`], as Windows 2000's does; typed, it fails.
#[inline(never)]
fn execute(
    raw: &mut [u16],
    length: usize,
    block: &mut [u16],
    state: &mut cmd::State,
    batch: Option<&Batch>,
    more: &mut dyn FnMut(&mut [u16]) -> More,
) -> Flow {
    let limit = if batch.is_some() {
        cmd::MAX_LINE
    } else {
        cmd::MAX_COMMAND
    };
    let Ok(mut used) = expand_into(&raw[..length], limit, state.errorlevel, batch, block) else {
        return too_long(state, batch);
    };
    loop {
        let caret = batch.is_none() && syntax::continues(&block[..used]);
        if !caret && !syntax::open(&block[..used]) {
            break;
        }
        let next = match more(raw) {
            More::Line(next) => next,
            More::End => break,
            More::Abandon => {
                state.spaced = false;
                return Flow::Next;
            }
        };
        let next = cmd::without_break(&raw[..next]);
        if caret {
            used -= 1;
        } else {
            if batch::skipped(next) {
                continue;
            }
            match block.get_mut(used) {
                Some(slot) => *slot = u16::from(b'\n'),
                None => return too_long(state, batch),
            }
            used += 1;
        }
        match expand_into(next, limit, state.errorlevel, batch, &mut block[used..]) {
            Ok(added) => used += added,
            Err(TooLong) => return too_long(state, batch),
        }
    }
    let line = &block[..used];
    if let Err(error) = syntax::check(line) {
        let _ = exe::stderr().print(format_args!("{error}"));
        state.spaced = true;
        if batch.is_some() {
            state.return_code = syntax::FATAL;
            return Flow::Abort;
        }
        state.failed();
        return Flow::Next;
    }
    if batch.is_some() && state.echo {
        echo_line(line, state.spaced);
    }
    run_line(line, state, batch)
}

/// `line` expanded into the start of `out` (as `batch`'s line when there is one), `limit` units
/// at most: the units written, its line break left out.
fn expand_into(
    line: &[u16],
    limit: usize,
    errorlevel: u32,
    batch: Option<&Batch>,
    out: &mut [u16],
) -> Result<usize, TooLong> {
    let arguments = batch.map(|batch| batch.arguments.borrow());
    let view = arguments.as_ref().map(|arguments| arguments.view());
    cmd::expand_within(line, limit, errorlevel, view.as_ref(), &mut Shell, out)
        .map(|text| cmd::without_break(text).len())
}

/// A line expanded past its bound: `The input line is too long.`; typed, the line fails. In a
/// batch file, Windows 2000's cmd then names the last program it found as unexpected (batline's
/// capture: the path of the program the line before ran) and ends every batch file, its return
/// code [`syntax::FATAL`].
#[inline(never)]
fn too_long(state: &mut cmd::State, batch: Option<&Batch>) -> Flow {
    let _ = exe::stderr().print(format_args!("{}", cmd::TOO_LONG));
    state.spaced = true;
    if batch.is_none() {
        state.return_code = 1;
        return Flow::Next;
    }
    let found = &state.found[..state.found_length];
    let _ = if found.is_empty() {
        exe::stderr().print(format_args!("{}", Syntax::Incorrect))
    } else {
        exe::stderr().print(format_args!("{}", Syntax::Unexpected(found)))
    };
    state.return_code = syntax::FATAL;
    Flow::Abort
}

/// A batch file's line echoed after the prompt, unless `@` hides it: a line of one command as cmd
/// rebuilds it, its redirections after it ([`batch::EchoedCommand`]); any other as it reads.
#[inline(never)]
fn echo_line(line: &[u16], spaced: bool) {
    let Some(echoed) = batch::echoed(line) else {
        return;
    };
    prompt(spaced);
    let mut text = [0; cmd::LINE];
    let mut redirections = Redirections::default();
    let command = syntax::single(line)
        .then(|| syntax::simple(line, &mut text, &mut redirections))
        .flatten();
    let _ = match command {
        Some(command) => exe::stdout().print(format_args!(
            "{}\r\n",
            batch::EchoedCommand {
                command,
                redirections: redirections.list(),
            }
        )),
        None => exe::stdout().print(format_args!("{echoed}\r\n")),
    };
}

/// A line's commands, as its `&`s separate them: each run in turn, until one ends the batch or the
/// shell.
fn run_line(text: &[u16], state: &mut cmd::State, batch: Option<&Batch>) -> Flow {
    for (part, _) in syntax::parts(text, Join::Then) {
        if cmd::trim(part).is_empty() {
            continue;
        }
        match run_or_else(part, state, batch) {
            Flow::Next => {}
            flow => return flow,
        }
    }
    Flow::Next
}

/// Commands `||` joins: each runs while those before it failed (their return code not 0).
fn run_or_else(text: &[u16], state: &mut cmd::State, batch: Option<&Batch>) -> Flow {
    for (index, (part, _)) in syntax::parts(text, Join::OrElse).enumerate() {
        if index > 0 && state.return_code == 0 {
            break;
        }
        match run_and_then(part, state, batch) {
            Flow::Next => {}
            flow => return flow,
        }
    }
    Flow::Next
}

/// Commands `&&` joins: each runs while those before it succeeded (their return code 0).
fn run_and_then(text: &[u16], state: &mut cmd::State, batch: Option<&Batch>) -> Flow {
    for (index, (part, _)) in syntax::parts(text, Join::AndThen).enumerate() {
        if index > 0 && state.return_code != 0 {
            break;
        }
        let flow = if syntax::parts(part, Join::Pipe).nth(1).is_some() {
            pipeline(part, state)
        } else {
            run_element(part, state, batch)
        };
        match flow {
            Flow::Next => {}
            flow => return flow,
        }
    }
    Flow::Next
}

/// One command between the operators, run in the shell: a group's line with the group's
/// redirections, or a simple command (see [`run_simple`]).
fn run_element(text: &[u16], state: &mut cmd::State, batch: Option<&Batch>) -> Flow {
    match syntax::element(text) {
        Ok(Element::Group {
            inner,
            redirections,
        }) => {
            let mut list = Redirections::default();
            syntax::group_redirections(redirections, &mut list);
            let mut redirected = Redirected::save();
            if !redirected.apply(list.list(), state) {
                return Flow::Next;
            }
            run_line(inner, state, batch)
        }
        Ok(Element::Flow(keyword, text)) => control::run(keyword, text, state, batch),
        Ok(Element::Simple(text)) => run_simple(text, state, batch),
        // The line was checked before it ran.
        Err(_) => Flow::Next,
    }
}

/// A simple command: its redirections applied (a failure reported, the command failed and not
/// run), then its help printed when it asks for it, or what it says done; the standard handles put
/// back after.
#[inline(never)]
fn run_simple(text: &[u16], state: &mut cmd::State, batch: Option<&Batch>) -> Flow {
    let mut buffer = [0; cmd::LINE];
    let mut list = Redirections::default();
    // A command's text is never longer than the line it is part of.
    let Some(line) = syntax::simple(text, &mut buffer, &mut list) else {
        return Flow::Next;
    };
    let command = cmd::parse(line);
    state.spaced = !matches!(command, Command::Empty | Command::ClearScreen);
    let mut redirected = Redirected::save();
    if !redirected.apply(list.list(), state) {
        return Flow::Next;
    }
    if let Some(help) = cmd::help::requested(line, &command) {
        let _ = exe::stdout().print(format_args!("{help}"));
        cmd::help::answered(&command, state);
        return Flow::Next;
    }
    dispatch(command, state, batch, false)
}

/// The handles a command may name in its redirections: 0 to 9.
const HANDLES: usize = 10;

/// The standard handles as they were before a command's redirections replaced them, put back when
/// the value is dropped, and the handles the redirections opened, closed then. Windows' cmd
/// redirects a command as long as it runs, the same way: a built-in writes to the handles, a
/// program is handed them.
struct Redirected {
    saved: [usize; 3],
    opened: [Option<exe::Handle>; syntax::REDIRECTIONS + 3],
    count: usize,
}

/// The standard handles, by their number.
const STANDARD: [exe::Standard; 3] = [
    exe::Standard::Input,
    exe::Standard::Output,
    exe::Standard::Error,
];

impl Redirected {
    /// The standard handles as they are.
    fn save() -> Self {
        Redirected {
            saved: STANDARD.map(exe::standard_handle),
            opened: core::array::from_fn(|_| None),
            count: 0,
        }
    }

    /// `handle` kept, to be closed once the command has run.
    fn keep(&mut self, handle: exe::Handle) -> usize {
        let raw = handle.raw();
        if let Some(slot) = self.opened.get_mut(self.count) {
            *slot = Some(handle);
            self.count += 1;
        }
        raw
    }

    /// The standard handle `which` made an inheritable duplicate of `handle` (a pipe's end), so
    /// that a program started is handed it.
    fn hand(&mut self, which: exe::Standard, handle: &exe::Handle) -> Result<(), exe::Error> {
        let duplicate = exe::duplicate(handle.raw())?;
        let raw = self.keep(duplicate);
        exe::set_standard_handle(which, raw)
    }

    /// `redirections` applied in order, from the standard handles as they are now: a file opened
    /// (`n<`, `n>`, `n>>`) or a handle duplicated (`n>&m`) becomes handle n, and handles 0 to 2
    /// the standard ones. False, the error reported and the command failed, when a file cannot be
    /// opened or a handle duplicated; the standard handles are then as they were.
    fn apply(&mut self, redirections: &[Redirection<'_>], state: &mut cmd::State) -> bool {
        let mut handles = [None; HANDLES];
        for (slot, which) in handles.iter_mut().zip(STANDARD) {
            *slot = Some(exe::standard_handle(which));
        }
        for redirection in redirections {
            let number = usize::from(redirection.handle);
            let handle = match redirection.target {
                Target::File(name) => open_target(name, redirection.kind),
                Target::Handle(source) => match handles[usize::from(source)] {
                    Some(source) => exe::duplicate(source).map_err(|_| Failure::Duplicate),
                    None => Err(Failure::Duplicate),
                },
            };
            match handle {
                Ok(handle) => handles[number] = Some(self.keep(handle)),
                Err(failure) => {
                    match failure {
                        Failure::Open(error) => report(error),
                        Failure::Duplicate => {
                            let _ = exe::stderr().print(format_args!(
                                "The handle could not be duplicated\r\n\
                                 during redirection of handle {number}.\r\n"
                            ));
                        }
                    }
                    state.failed();
                    return false;
                }
            }
        }
        for ((which, handle), saved) in STANDARD.into_iter().zip(handles).zip(self.saved) {
            if let Some(handle) = handle.filter(|&handle| handle != saved) {
                let _ = exe::set_standard_handle(which, handle);
            }
        }
        true
    }
}

impl Drop for Redirected {
    fn drop(&mut self) {
        for (which, saved) in STANDARD.into_iter().zip(self.saved) {
            if exe::standard_handle(which) != saved {
                let _ = exe::set_standard_handle(which, saved);
            }
        }
        // The handles opened close after this, as the fields drop.
    }
}

/// Why a redirection could not be made.
enum Failure {
    /// Its file could not be opened: the Win32 error.
    Open(exe::Error),
    /// The handle it duplicates is not open.
    Duplicate,
}

/// The file a redirection names (its quotes and escapes resolved), opened as `kind` says.
#[inline(never)]
fn open_target(name: &[u16], kind: Kind) -> Result<exe::Handle, Failure> {
    let mut buffer = [0; exe::MAX_PATH];
    // ERROR_FILENAME_EXCED_RANGE: longer than a path can be.
    let name = syntax::file_name(name, &mut buffer).ok_or(Failure::Open(exe::Error(206)))?;
    let redirect = match kind {
        Kind::Input => exe::Redirect::Read,
        Kind::Output => exe::Redirect::Truncate,
        Kind::Append => exe::Redirect::Append,
    };
    exe::open_redirection(name, redirect).map_err(Failure::Open)
}

/// The commands most a pipeline runs at once.
const PIPELINE: usize = 16;

/// The commands `text`'s pipes join, run at once: each started in turn, its standard input the
/// pipe from the one before and its standard output the pipe to the one after (its own
/// redirections applied over them), then each waited for. The last one's return code is the
/// pipeline's, and its ERRORLEVEL. A built-in, a batch file, a group, or a word naming nothing runs
/// in a `cmd /c` of its own, as Windows' cmd runs it.
#[inline(never)]
fn pipeline(text: &[u16], state: &mut cmd::State) -> Flow {
    state.spaced = true;
    let count = syntax::parts(text, Join::Pipe).count();
    if count > PIPELINE {
        let _ = exe::stderr().print(format_args!("{}", cmd::SYNTAX));
        state.failed();
        return Flow::Next;
    }
    let mut started: [Option<Result<exe::Process, Start>>; PIPELINE] =
        core::array::from_fn(|_| None);
    let mut input: Option<exe::Handle> = None;
    for (index, (element, _)) in syntax::parts(text, Join::Pipe).enumerate() {
        let pipe = if index + 1 < count {
            match exe::create_pipe() {
                Ok(pipe) => Some(pipe),
                Err(error) => {
                    report(error);
                    started[index] = Some(Err(Start::CannotRun));
                    break;
                }
            }
        } else {
            None
        };
        let output = pipe.as_ref().map(|(_, write)| write);
        started[index] = Some(start_element(element, input.as_ref(), output, state));
        // The shell keeps no end of a pipe a process holds: the reader sees the input end once the
        // writer has.
        input = pipe.map(|(read, _)| read);
    }
    drop(input);
    let mut last = Err(Start::CannotRun);
    for process in started.into_iter().flatten() {
        last = process.map(|process| process.wait().unwrap_or(1));
    }
    match last {
        Ok(code) => state.ended(code),
        Err(Start::NotRecognized) => state.not_recognized(),
        Err(Start::CannotRun) => state.return_code = 1,
    }
    Flow::Next
}

/// Why a process could not be started (the message printed).
enum Start {
    /// No program goes by the command's word: return code and ERRORLEVEL 9009.
    NotRecognized,
    /// Another failure: return code 1, the ERRORLEVEL kept.
    CannotRun,
}

/// One command of a pipeline started, its standard input `input` and its standard output `output`
/// when they are given (the pipes' ends): a program found by its word directly, with its own
/// redirections; anything else as a `cmd /c` of its own (see [`child_shell`]), which applies them.
#[inline(never)]
fn start_element(
    text: &[u16],
    input: Option<&exe::Handle>,
    output: Option<&exe::Handle>,
    state: &mut cmd::State,
) -> Result<exe::Process, Start> {
    let mut piped = Redirected::save();
    for (which, end) in [
        (exe::Standard::Input, input),
        (exe::Standard::Output, output),
    ] {
        if let Some(end) = end {
            piped.hand(which, end).map_err(|error| {
                report(error);
                Start::CannotRun
            })?;
        }
    }
    if let Ok(Element::Simple(simple)) = syntax::element(text) {
        let mut buffer = [0; cmd::LINE];
        let mut list = Redirections::default();
        if let Some(Command::Run { line, word }) =
            syntax::simple(simple, &mut buffer, &mut list).map(cmd::parse)
        {
            let mut found = [0; exe::MAX_PATH];
            if let Some(length) = find_program(word, &mut found) {
                let path = &found[..length];
                if !search::is_batch(path) {
                    let mut redirected = Redirected::save();
                    if !redirected.apply(list.list(), state) {
                        return Err(Start::CannotRun);
                    }
                    return launch(path, line, word);
                }
            }
        }
    }
    child_shell(text)
}

/// A `cmd /c` of the shell's own running `text`, as Windows' cmd runs a pipeline's built-in:
/// `COMSPEC`'s program (the shell's own file without one), its command line
/// `"program" /S /D /c" text"`.
#[inline(never)]
fn child_shell(text: &[u16]) -> Result<exe::Process, Start> {
    let mut path = [0; exe::MAX_PATH];
    let mut name = [0; 7];
    let path = match exe::environment_variable(wide("COMSPEC", &mut name), &mut path) {
        Ok(Some(path)) if !path.is_empty() => path,
        _ => {
            let mut own = [0; exe::MAX_PATH];
            let Ok(own) = exe::program_path(&mut own) else {
                return Err(Start::CannotRun);
            };
            let length = own.len();
            path[..length].copy_from_slice(own);
            &path[..length]
        }
    };
    let mut line = [0; cmd::LINE + exe::MAX_PATH + 16];
    let mut length = 0;
    let mut put = |units: &[u16]| {
        let end = length + units.len();
        if let Some(target) = line.get_mut(length..end) {
            target.copy_from_slice(units);
        }
        length = end;
    };
    let mut switches = [0; 13];
    put(&[u16::from(b'"')]);
    put(path);
    put(wide("\" /S /D /c\" ", &mut switches));
    // The blanks after the command stay its own (`echo x | y` echoes `x `).
    put(cmd::skip_blanks(cmd::without_break(text)));
    put(&[u16::from(b'"'), 0]);
    if length > line.len() {
        let _ = exe::stderr().print(format_args!("{}", cmd::TOO_LONG));
        return Err(Start::CannotRun);
    }
    create(path, &mut line[..length], cmd::trim(text))
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
        Command::Call(argument) => return call(argument, state, batch),
        Command::Exit(argument) => {
            let exit = batch::exit(argument);
            if exit.batch && batch.is_some() {
                // The batch's ERRORLEVEL, not its return code: `exit /b` itself returns 0.
                if let Some(code) = exit.code {
                    state.errorlevel = code;
                }
                return Flow::EndBatch;
            }
            // Outside a batch file, `exit /b` ends the shell as `exit` does; without a code,
            // either ends it with the ERRORLEVEL.
            return Flow::Exit(exit.code.unwrap_or(state.errorlevel));
        }
        Command::Goto(argument) => return control::goto(argument, state, batch),
        Command::ChangeDirectory(None) => print_current_directory(state),
        Command::ChangeDirectory(Some(path)) => {
            if exe::set_current_directory(path).is_err() {
                let _ = exe::stderr().print(format_args!("{}", cmd::PATH_NOT_FOUND));
                state.failed();
            } else {
                remember_drive_directory();
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
        Command::Set(argument) => {
            if !set_switch::run(argument, state, batch.is_some()) {
                set(argument, state);
            }
        }
        Command::Type(argument) => type_files(argument, state),
        Command::Version => {
            let _ = exe::stdout().print(format_args!("\r\n{}", cmd::BANNER));
        }
        Command::Shift(from) => {
            if let Some(batch) = batch {
                let shifted = {
                    let arguments = batch.arguments.borrow();
                    let mut view = arguments.view();
                    view.shift(from);
                    view.shifted
                };
                batch.arguments.borrow_mut().shifted = shifted;
            }
        }
        Command::Incorrect => {
            let _ = exe::stderr().print(format_args!("{}", cmd::SYNTAX));
            state.failed();
        }
        Command::Builtin(builtin) => exec::run(builtin, state, batch.is_some()),
        Command::Run { line, word } => return run(line, word, state, batch, called),
    }
    if clears && state.return_code == 0 {
        state.errorlevel = 0;
    }
    Flow::Next
}

/// `call`: its argument expanded a second time (as the batch file's line is, when there is one:
/// `%%X%%` in a batch file reads X's value), then run as a command, a batch file it names coming
/// back here once it ends. The ERRORLEVEL becomes what the command returns: 0 after `call echo`,
/// a program's exit code, the ERRORLEVEL a batch file leaves, 1 for a command not recognized.
/// `call :label` runs the batch file from its label (see [`control::call_label`]). `call` alone
/// fails.
fn call(argument: &[u16], state: &mut cmd::State, batch: Option<&Batch>) -> Flow {
    if cmd::trim(argument).is_empty() {
        state.failed();
        return Flow::Next;
    }
    let flow = if argument.contains(&u16::from(b'%')) {
        call_expanded(argument, state, batch)
    } else {
        // Nothing to expand: the line as it is, with no buffer held while what it runs runs (a
        // batch file `call` nests takes its share of the stack).
        call_line(argument, state, batch)
    };
    state.errorlevel = state.return_code;
    flow
}

/// `call`'s argument expanded a second time, then run ([`call_line`]).
#[inline(never)]
fn call_expanded(argument: &[u16], state: &mut cmd::State, batch: Option<&Batch>) -> Flow {
    let mut buffer = [0; cmd::LINE];
    let expanded = {
        let arguments = batch.map(|batch| batch.arguments.borrow());
        let view = arguments.as_ref().map(|arguments| arguments.view());
        cmd::expand(
            argument,
            state.errorlevel,
            view.as_ref(),
            &mut Shell,
            &mut buffer,
        )
    };
    let Ok(line) = expanded else {
        let _ = exe::stderr().print(format_args!("{}", cmd::TOO_LONG));
        state.failed();
        return Flow::Next;
    };
    call_line(line, state, batch)
}

/// What `call` runs: a label of the batch file, or a command.
fn call_line(line: &[u16], state: &mut cmd::State, batch: Option<&Batch>) -> Flow {
    if label::calls_label(line) {
        control::call_label(line, state, batch)
    } else {
        dispatch(cmd::parse(line), state, batch, true)
    }
}

/// The current directory kept in its drive's hidden variable (`=C:=C:\WINNT`), as Windows' cmd
/// keeps it after `cd`: the programs it starts inherit it, and a drive-relative path names it.
#[inline(never)]
fn remember_drive_directory() {
    let mut buffer = [0; exe::MAX_PATH];
    let Ok(directory) = exe::current_directory(&mut buffer) else {
        return;
    };
    if let Some(name) = cmd::drive_variable(directory) {
        let _ = exe::set_environment_variable(&name, Some(directory));
    }
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
/// several, or with a name holding wildcards (each file it matches, its directories left out),
/// each after its name (on the standard error, as Windows 2000's type writes it, so that the
/// files' bytes alone go where the output is redirected). A file that cannot be read, or a
/// wildcard name matching none, is reported, and `type` fails, the ERRORLEVEL 1.
fn type_files(argument: &[u16], state: &mut cmd::State) {
    let several = cmd::Names(argument).nth(1).is_some();
    let mut any = false;
    for name in cmd::Names(argument) {
        any = true;
        let typed = if files::has_wildcards(name) {
            type_matches(name)
        } else {
            type_file(name, several)
        };
        if let Err(error) = typed {
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

/// The files the wildcard name `pattern` matches typed, each after its name (its directory as
/// given, then its own name): ERROR_FILE_NOT_FOUND when it matches none.
#[inline(never)]
fn type_matches(pattern: &[u16]) -> Result<(), exe::Error> {
    let (directory, _) = files::split(pattern);
    let mut typed = false;
    for found in exe::find(pattern)? {
        if found.attributes & files::DIRECTORY != 0 {
            continue;
        }
        let mut buffer = [0; exe::MAX_PATH];
        // ERROR_FILENAME_EXCED_RANGE: longer than a path can be.
        let path = files::join(directory, found.name(), &mut buffer).ok_or(exe::Error(206))?;
        type_file(path, true)?;
        typed = true;
    }
    if typed {
        Ok(())
    } else {
        // ERROR_FILE_NOT_FOUND.
        Err(exe::Error(2))
    }
}

/// The file `name`'s bytes to the standard output, after its name when `header` says so. It is
/// read a kilobyte at a time.
#[inline(never)]
fn type_file(name: &[u16], header: bool) -> Result<(), exe::Error> {
    let file = exe::open_file(name)?;
    if header {
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
        state.not_recognized();
        return Flow::Next;
    };
    let path = &found[..length];
    keep_found(path, state);
    if !search::is_batch(path) {
        start_program(path, line, word, state);
        return Flow::Next;
    }
    if let (Some(batch), false) = (batch, called) {
        // The batch file takes the place of the one running: control does not come back.
        batch.arguments.borrow_mut().set(line, path);
        return Flow::Chain;
    }
    let depth = batch.map_or(0, |batch| batch.depth + 1);
    let cmd_script = batch.map_or_else(|| search::is_cmd_script(path), |batch| batch.cmd_script);
    match run_batch(path, line, depth, cmd_script, Entry::Top, state) {
        flow @ (Flow::Exit(_) | Flow::Abort) => flow,
        _ => {
            // A batch file `call` ran returns the ERRORLEVEL it leaves (`exit /b 5`'s 5).
            if called {
                state.return_code = state.errorlevel;
            }
            Flow::Next
        }
    }
}

/// The full path of the program found at `path`, kept for the message a batch file's line too
/// long gives (see [`too_long`]).
#[inline(never)]
fn keep_found(path: &[u16], state: &mut cmd::State) {
    let mut buffer = [0; exe::MAX_PATH];
    let full = exe::full_path(path, &mut buffer).unwrap_or(path);
    let kept = full.len().min(state.found.len());
    state.found[..kept].copy_from_slice(&full[..kept]);
    state.found_length = kept;
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

/// Where a batch file starts running.
#[derive(Clone, Copy)]
enum Entry<'a> {
    /// At its first line.
    Top,
    /// After its label, looked for from the offset (`call :label`: where the batch file that
    /// calls is).
    Label(&'a [u16], u64),
}

/// A batch file open, and where it is read.
struct Source {
    file: exe::File,
    reader: LineReader,
}

impl Source {
    /// The batch file at `path`, read from its start.
    fn open(path: &[u16]) -> Result<Source, exe::Error> {
        Ok(Source {
            file: exe::open_file(path)?,
            reader: LineReader::default(),
        })
    }

    /// The lines up to the label `label` read, from where the file is: whether it was found.
    #[inline(never)]
    fn find(&mut self, label: &[u16]) -> bool {
        let mut bytes = [0; cmd::MAX_LINE];
        let mut units = [0; cmd::LINE];
        let file = &self.file;
        self.reader.seek_label(
            &mut |buffer| file.read(buffer),
            |line: &[u8], units: &mut [u16]| exe::oem_to_wide(line, units).ok().map(<[u16]>::len),
            label,
            &mut bytes,
            &mut units,
        )
    }

    /// The lines before byte `offset` (a line's start) read.
    #[inline(never)]
    fn skip_to(&mut self, offset: u64) {
        let mut units = [0; cmd::LINE];
        while self.reader.offset() < offset {
            match next_line(
                |buffer| self.file.read(buffer),
                &mut self.reader,
                &mut units,
            ) {
                Ok(Some(_)) => {}
                _ => return,
            }
        }
    }
}

/// The label `label` looked for in the batch file at `path`, `source` reading it: from where it
/// is to its end, then from its start, as `goto /?` says. Its message when there is none.
fn find_label(source: &mut Source, path: &[u16], label: &[u16]) -> bool {
    if source.find(label) {
        return true;
    }
    if let Ok(from_start) = Source::open(path) {
        *source = from_start;
        if source.find(label) {
            return true;
        }
    }
    let _ = exe::stderr().print(format_args!("{}", label::NotFound(label)));
    false
}

/// A batch file's lines run in the shell, `line` its `%0` to `%9` and `%*`, `depth` the batch
/// files around it, from its start or a label. Before each line, a Ctrl+C or Ctrl+Break since the
/// last asks whether to end every batch file. Its labels and empty lines are skipped. `goto`
/// goes on after a label ([`find_label`]; a label not found ends the batch file, the ERRORLEVEL
/// 1), and a batch file run without `call` takes its place, at the same depth. It ends at its last
/// line, `exit /b` or `goto :eof`; the ERRORLEVEL is then its last command's (or `exit /b`'s), and
/// so is its return code (`exit /b` returning 0). The echo a batch file run from the prompt (or
/// `/C`, `/K`) turns on or off is put back once it ends, so that the prompt shows as before.
#[inline(never)]
fn run_batch(
    path: &[u16],
    line: &[u16],
    depth: usize,
    cmd_script: bool,
    start: Entry<'_>,
    state: &mut cmd::State,
) -> Flow {
    if depth >= batch::DEPTH || stack_used() > STACK_BUDGET {
        let _ = exe::stderr().print(format_args!("{}", batch::RECURSION));
        return Flow::Abort;
    }
    let mut source = match Source::open(path) {
        Ok(source) => source,
        Err(error) => {
            report(error);
            state.failed();
            return Flow::Next;
        }
    };
    let batch = Batch::new(line, path, depth, cmd_script);
    if let Entry::Label(label, offset) = start {
        source.skip_to(offset);
        if !find_label(&mut source, path, label) {
            state.failed();
            return Flow::Next;
        }
    }
    let echo = state.echo;
    let mut units = [0; cmd::LINE];
    let mut block = [0; BLOCK];
    let flow = loop {
        if exe::take_interrupt() && terminate() {
            break Flow::Abort;
        }
        let length = match next_batch_line(&source.file, &mut source.reader, &mut units) {
            Ok(Some(line)) => line.len(),
            Ok(None) => break Flow::Next,
            Err(error) => {
                report(error);
                break Flow::Next;
            }
        };
        batch.offset.set(source.reader.offset());
        if batch::skipped(&units[..length]) {
            continue;
        }
        let flow = {
            // The lines of a block the line opens.
            let mut more =
                |raw: &mut [u16]| match next_batch_line(&source.file, &mut source.reader, raw) {
                    Ok(Some(line)) => {
                        let length = line.len();
                        batch.offset.set(source.reader.offset());
                        More::Line(length)
                    }
                    _ => More::End,
                };
            execute(
                &mut units,
                length,
                &mut block,
                state,
                Some(&batch),
                &mut more,
            )
        };
        match flow {
            Flow::Next => {}
            Flow::EndBatch => break Flow::Next,
            Flow::Goto => {
                let (label, length) = *batch.label.borrow();
                let mut path = [0; exe::MAX_PATH];
                let path = {
                    let arguments = batch.arguments.borrow();
                    let own = arguments.path();
                    path[..own.len()].copy_from_slice(own);
                    &path[..own.len()]
                };
                if !find_label(&mut source, path, &label[..length]) {
                    state.failed();
                    break Flow::Next;
                }
            }
            Flow::Chain => {
                let opened = Source::open(batch.arguments.borrow().path());
                match opened {
                    Ok(opened) => source = opened,
                    Err(error) => {
                        report(error);
                        state.failed();
                        break Flow::Next;
                    }
                }
            }
            flow => break flow,
        }
    };
    if depth == 0 {
        state.echo = echo;
    }
    flow
}

/// A batch file's next line (see [`next_line`]), the lines after it joined to it while it ends
/// with a `^` that escapes nothing else ([`syntax::continues`]), that `^` dropped: Windows' cmd
/// reads on past it.
fn next_batch_line<'a>(
    file: &exe::File,
    reader: &mut LineReader,
    units: &'a mut [u16],
) -> Result<Option<&'a [u16]>, exe::Error> {
    let Some(first) = next_line(|buffer| file.read(buffer), reader, units)? else {
        return Ok(None);
    };
    let mut length = first.len();
    while syntax::continues(&units[..length]) {
        length -= 1;
        match next_line(|buffer| file.read(buffer), reader, &mut units[length..])? {
            Some(more) => length += more.len(),
            None => break,
        }
    }
    Ok(Some(&units[..length]))
}

/// The next line `read` gives (a batch file's, or the standard input's), cut at
/// [`cmd::MAX_LINE`] and decoded from the OEM code page into `units`: None at its end.
#[inline(never)]
fn next_line<'a>(
    mut read: impl FnMut(&mut [u8]) -> Result<usize, exe::Error>,
    reader: &mut LineReader,
    units: &'a mut [u16],
) -> Result<Option<&'a [u16]>, exe::Error> {
    let mut bytes = [0; cmd::MAX_LINE];
    let Some(line) = reader.next_line(&mut read, &mut bytes)? else {
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
/// becomes the return code and the ERRORLEVEL. A program that cannot be started is reported (see
/// [`launch`]); one that cannot be waited for returns 1, the ERRORLEVEL unchanged.
fn start_program(path: &[u16], line: &[u16], word: &[u16], state: &mut cmd::State) {
    match launch(path, line, word) {
        Ok(process) => match process.wait() {
            Ok(code) => state.ended(code),
            Err(error) => {
                let _ = exe::stderr().print(format_args!(
                    "cmd: the program could not be waited for ({error})\r\n"
                ));
                state.return_code = 1;
            }
        },
        Err(Start::NotRecognized) => state.not_recognized(),
        Err(Start::CannotRun) => state.return_code = 1,
    }
}

/// The program file `path` started with `line`, which starts with the program's `word`, as its
/// command line ([`cmd::command_line`]), handed the standard handles as they are (see
/// [`create`]).
#[inline(never)]
fn launch(path: &[u16], line: &[u16], word: &[u16]) -> Result<exe::Process, Start> {
    let mut buffer = [0; cmd::LINE + exe::MAX_PATH + 16];
    let Some(command) = cmd::command_line(line, word, &mut buffer) else {
        let _ = exe::stderr().print(format_args!("{}", cmd::TOO_LONG));
        return Err(Start::CannotRun);
    };
    create(path, command, word)
}

/// The program file `path` started with `command`, a command line ending with its NUL, handed the
/// standard handles as they are. Errors go to the standard error, as Windows 2000's cmd writes
/// them, about `word`: a file that cannot be found is not recognized, any other failure cannot
/// run.
fn create(path: &[u16], command: &mut [u16], word: &[u16]) -> Result<exe::Process, Start> {
    exe::create_process_of(path, command).map_err(|exe::Error(code)| {
        if cmd::NO_SUCH_PROGRAM.contains(&code) {
            let _ = exe::stderr().print(format_args!("{}", cmd::NotRecognized(word)));
            Start::NotRecognized
        } else {
            let _ = exe::stderr().print(format_args!("{}", cmd::CannotRun(word, code)));
            Start::CannotRun
        }
    })
}
