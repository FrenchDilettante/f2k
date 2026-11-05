//! The batch language's control flow, run (cmd::flow reads it): `if`'s condition tested and its
//! command run, or its `else` command; `for`'s command run once for each item of its set, its
//! variable replaced; `goto`, and `call :label`.

use cmd::builtins::files;
use cmd::flow::condition::{self, Probe};
use cmd::flow::label::{self, Goto};
use cmd::flow::repeat::{self, For, Items, Mode, Options, Source};
use cmd::flow::Keyword;
use cmd::syntax;

use crate::{
    batch,
    child_shell,
    echo_line,
    next_line,
    run_batch,
    run_line,
    terminate,
    Batch,
    Entry,
    Flow,
    LineReader,
    Redirected,
    Shell,
    BLOCK,
};

/// `if` or `for`, its text from its keyword on (checked before it runs): its help when its first
/// word asks for it (`if /?`), otherwise what it says done. It returns 0, unless the command it
/// runs returns another code.
pub(crate) fn run(
    keyword: Keyword,
    text: &[u16],
    state: &mut cmd::State,
    batch: Option<&Batch>,
) -> Flow {
    state.spaced = true;
    state.return_code = 0;
    match keyword {
        Keyword::If => match condition::parse(text) {
            Ok(condition::Header::If(header)) => run_if(&header, state, batch),
            Ok(condition::Header::Help(_)) => help("if", state),
            Err(_) => Flow::Next,
        },
        Keyword::For => match repeat::parse(text) {
            Ok(repeat::Header::For(header)) => run_for(&header, state, batch),
            Ok(repeat::Header::Help(_)) => help("for", state),
            Err(_) => Flow::Next,
        },
    }
}

/// A command's help printed in place of running it: it returns 1, the ERRORLEVEL kept.
fn help(name: &str, state: &mut cmd::State) -> Flow {
    let mut word = [0; 3];
    for (unit, byte) in word.iter_mut().zip(name.bytes()) {
        *unit = u16::from(byte);
    }
    if let Some(help) = cmd::help::of(&word[..name.len()]) {
        let _ = exe::stdout().print(format_args!("{help}"));
    }
    state.return_code = cmd::help::SHOWN;
    Flow::Next
}

/// The shell's state, as a condition reads it.
struct Conditions {
    errorlevel: u32,
}

impl Probe for Conditions {
    fn errorlevel(&self) -> u32 {
        self.errorlevel
    }

    fn exists(&mut self, name: &[u16]) -> bool {
        !name.is_empty() && (exe::attributes(name).is_ok() || exe::find(name).is_ok())
    }

    fn defined(&mut self, name: &[u16]) -> bool {
        // One unit's room tells whether there is a value.
        !matches!(exe::environment_variable(name, &mut [0; 1]), Ok(None))
    }
}

/// `if`: its command when the condition holds, its `else` command when it does not and it has
/// one.
fn run_if(header: &condition::If<'_>, state: &mut cmd::State, batch: Option<&Batch>) -> Flow {
    let (then, otherwise) = syntax::branches(header.command());
    let mut conditions = Conditions {
        errorlevel: state.errorlevel,
    };
    if header.holds(&mut conditions) {
        run_line(then, state, batch)
    } else if let Some(otherwise) = otherwise {
        run_line(otherwise, state, batch)
    } else {
        Flow::Next
    }
}

/// `for`: its command run for each item its mode gives, until one ends the batch file or the
/// shell (or `goto` leaves the loop).
fn run_for(header: &For<'_>, state: &mut cmd::State, batch: Option<&Batch>) -> Flow {
    match header.mode {
        Mode::Range => {
            for value in repeat::range(header.set) {
                let mut digits = [0; 24];
                let value = decimal(value, &mut digits);
                match iterate(header, &[(header.variable, value)], state, batch) {
                    Flow::Next => {}
                    flow => return flow,
                }
            }
            Flow::Next
        }
        Mode::Items => match header.recursive {
            Some(root) => recursive(header, root, state, batch),
            None => {
                for item in Items(header.set) {
                    let flow = if files::has_wildcards(item) {
                        matches(header, batch::unquote(item), state, batch)
                    } else {
                        iterate(header, &[(header.variable, item)], state, batch)
                    };
                    if !matches!(flow, Flow::Next) {
                        return flow;
                    }
                }
                Flow::Next
            }
        },
        Mode::Lines(options) => lines(header, &options, state, batch),
    }
}

/// `value` in decimal, in `digits`.
fn decimal(value: i64, digits: &mut [u16; 24]) -> &[u16] {
    let mut at = digits.len();
    let mut rest = value.unsigned_abs();
    loop {
        at -= 1;
        digits[at] = u16::from(b'0') + (rest % 10) as u16;
        rest /= 10;
        if rest == 0 {
            break;
        }
    }
    if value < 0 {
        at -= 1;
        digits[at] = u16::from(b'-');
    }
    &digits[at..]
}

/// The loop's command run once, its variables replaced by `variables` (see
/// [`repeat::substitute`]), echoed first after the prompt while echo is on (unless `@` hides it),
/// as Windows' cmd echoes each pass. Ctrl+C or Ctrl+Break since the last pass asks, in a batch
/// file, whether to end every batch file; at the prompt it ends the loop.
#[inline(never)]
fn iterate(
    header: &For<'_>,
    variables: &[(u16, &[u16])],
    state: &mut cmd::State,
    batch: Option<&Batch>,
) -> Flow {
    if exe::take_interrupt() && (batch.is_none() || terminate()) {
        return Flow::Abort;
    }
    let mut buffer = [0; BLOCK];
    let Ok(command) = repeat::substitute(header.command(), variables, &mut Shell, &mut buffer)
    else {
        let _ = exe::stderr().print(format_args!("{}", cmd::TOO_LONG));
        state.failed();
        return Flow::Next;
    };
    if state.echo {
        echo_line(command, state.spaced);
    }
    run_line(command, state, batch)
}

/// The files a wildcard `pattern` matches (directories with `/D`; neither hidden nor system ones,
/// nor `.` and `..`), each the pattern's directory as written and its name, in the directory's
/// order.
#[inline(never)]
fn matches(
    header: &For<'_>,
    pattern: &[u16],
    state: &mut cmd::State,
    batch: Option<&Batch>,
) -> Flow {
    let (directory, _) = files::split(pattern);
    let Ok(found) = exe::find(pattern) else {
        return Flow::Next;
    };
    for found in found {
        let directory_found = found.attributes & files::DIRECTORY != 0;
        if files::is_dots(found.name())
            || found.attributes & (files::HIDDEN | files::SYSTEM) != 0
            || directory_found != header.directories
        {
            continue;
        }
        let mut buffer = [0; exe::MAX_PATH];
        let Some(path) = files::join(directory, found.name(), &mut buffer) else {
            continue;
        };
        match iterate(header, &[(header.variable, path)], state, batch) {
            Flow::Next => {}
            flow => return flow,
        }
    }
    Flow::Next
}

/// `/R`: the set looked for in `root` (the current directory when empty) and in each directory
/// below it, a directory before those below it.
fn recursive(
    header: &For<'_>,
    root: &[u16],
    state: &mut cmd::State,
    batch: Option<&Batch>,
) -> Flow {
    let mut buffer = [0; exe::MAX_PATH];
    let root = batch::unquote(root);
    let directory = if root.is_empty() {
        exe::current_directory(&mut buffer)
    } else {
        exe::full_path(root, &mut buffer)
    };
    match directory {
        Ok(directory) => walk(header, directory, state, batch),
        Err(_) => Flow::Next,
    }
}

/// `/R` in `directory`: each item of the set, a wildcard one as the files it matches there, any
/// other as the directory and the item (`.` the directory itself, as `C:\x\.`); then each
/// directory in it, in turn.
#[inline(never)]
fn walk(
    header: &For<'_>,
    directory: &[u16],
    state: &mut cmd::State,
    batch: Option<&Batch>,
) -> Flow {
    for item in Items(header.set) {
        let item = batch::unquote(item);
        let mut buffer = [0; exe::MAX_PATH];
        let Some(path) = files::join(directory, item, &mut buffer) else {
            continue;
        };
        let flow = if files::has_wildcards(item) {
            matches(header, path, state, batch)
        } else {
            iterate(header, &[(header.variable, path)], state, batch)
        };
        if !matches!(flow, Flow::Next) {
            return flow;
        }
    }
    let mut pattern = [0; exe::MAX_PATH];
    let Some(pattern) = files::join(directory, &[u16::from(b'*')], &mut pattern) else {
        return Flow::Next;
    };
    let Ok(found) = exe::find(pattern) else {
        return Flow::Next;
    };
    for found in found {
        if found.attributes & files::DIRECTORY == 0 || files::is_dots(found.name()) {
            continue;
        }
        let mut buffer = [0; exe::MAX_PATH];
        let Some(below) = files::join(directory, found.name(), &mut buffer) else {
            continue;
        };
        match walk(header, below, state, batch) {
            Flow::Next => {}
            flow => return flow,
        }
    }
    Flow::Next
}

/// `/F`: the lines of the files, the string or the command's output its set names, each cut
/// into its variables' values ([`repeat::fields`]), `skip=`'s first lines of each left out.
fn lines(
    header: &For<'_>,
    options: &Options<'_>,
    state: &mut cmd::State,
    batch: Option<&Batch>,
) -> Flow {
    match repeat::source(header.set, options.backquote) {
        Source::Text(text) => {
            let mut skip = options.skip;
            pass(header, options, text, &mut skip, state, batch)
        }
        Source::Files(names) => {
            for name in Items(names) {
                // A file that cannot be opened is reported, and ends the loop, the ERRORLEVEL 1.
                let name = batch::unquote(name);
                let Ok(file) = exe::open_file(name) else {
                    let _ = exe::stderr().print(format_args!("{}", FileNotFound(name)));
                    state.failed();
                    return Flow::Next;
                };
                match file_lines(header, options, &file, state, batch) {
                    Flow::Next => {}
                    flow => return flow,
                }
            }
            Flow::Next
        }
        Source::Command(command) => command_lines(header, options, command, state, batch),
    }
}

/// One line of `/F`'s: skipped while `skip` counts down, otherwise its fields handed to the
/// variables, from the loop's variable on (`%%a`, `%%b`, ...), and the command run with them.
fn pass(
    header: &For<'_>,
    options: &Options<'_>,
    line: &[u16],
    skip: &mut usize,
    state: &mut cmd::State,
    batch: Option<&Batch>,
) -> Flow {
    if *skip > 0 {
        *skip -= 1;
        return Flow::Next;
    }
    let Some(fields) = repeat::fields(line, options) else {
        return Flow::Next;
    };
    let mut variables: [(u16, &[u16]); 32] = [(0, &[]); 32];
    for (index, (slot, value)) in variables
        .iter_mut()
        .zip(&fields.values[..fields.count])
        .enumerate()
    {
        *slot = (header.variable.wrapping_add(index as u16), value);
    }
    iterate(header, &variables[..fields.count], state, batch)
}

/// What `/F` prints when a file of its set cannot be opened.
struct FileNotFound<'a>(&'a [u16]);

impl core::fmt::Display for FileNotFound<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "The system cannot find the file {}.\r\n",
            cmd::Text(self.0)
        )
    }
}

/// `/F` over the lines of `file`.
#[inline(never)]
fn file_lines(
    header: &For<'_>,
    options: &Options<'_>,
    file: &exe::File,
    state: &mut cmd::State,
    batch: Option<&Batch>,
) -> Flow {
    let mut reader = LineReader::default();
    let mut units = [0; cmd::LINE];
    let mut skip = options.skip;
    loop {
        let line = match next_line(|buffer| file.read(buffer), &mut reader, &mut units) {
            Ok(Some(line)) => line,
            _ => return Flow::Next,
        };
        match pass(header, options, line, &mut skip, state, batch) {
            Flow::Next => {}
            flow => return flow,
        }
    }
}

/// `/F` over the lines `command` writes, run as Windows' cmd runs it: in a `cmd /c` of its own,
/// its standard output a pipe the shell reads. Each line is handled as it comes; the command is
/// waited for once its output ends.
#[inline(never)]
fn command_lines(
    header: &For<'_>,
    options: &Options<'_>,
    command: &[u16],
    state: &mut cmd::State,
    batch: Option<&Batch>,
) -> Flow {
    let Ok((read, write)) = exe::create_pipe() else {
        return Flow::Next;
    };
    let process = {
        let mut piped = Redirected::save();
        if piped.hand(exe::Standard::Output, &write).is_err() {
            return Flow::Next;
        }
        child_shell(command)
    };
    // The shell keeps no writing end: the output ends when the command's does.
    drop(write);
    let Ok(process) = process else {
        return Flow::Next;
    };
    let mut reader = LineReader::default();
    let mut units = [0; cmd::LINE];
    let mut skip = options.skip;
    let flow = loop {
        // The pipe is read as the standard input is, put in its place for the read.
        let input = exe::standard_handle(exe::Standard::Input);
        let _ = exe::set_standard_handle(exe::Standard::Input, read.raw());
        let line = next_line(exe::read_standard_input, &mut reader, &mut units);
        let _ = exe::set_standard_handle(exe::Standard::Input, input);
        let line = match line {
            Ok(Some(line)) => line,
            _ => break Flow::Next,
        };
        match pass(header, options, line, &mut skip, state, batch) {
            Flow::Next => {}
            flow => break flow,
        }
    };
    drop(read);
    let _ = process.wait();
    flow
}

/// `goto`'s argument: in a batch file, the label its batch file goes on after (its
/// [`Batch::label`]), or its end for `:eof`; without a label, `No batch label specified to GOTO
/// command.`, and the batch file ends, the ERRORLEVEL 1. At the prompt, nothing.
pub(crate) fn goto(argument: &[u16], state: &mut cmd::State, batch: Option<&Batch>) -> Flow {
    let Some(batch) = batch else {
        return Flow::Next;
    };
    match label::goto(argument) {
        Goto::Missing => {
            let _ = exe::stderr().print(format_args!("{}", label::MISSING));
            state.failed();
            Flow::EndBatch
        }
        Goto::End => Flow::EndBatch,
        Goto::Label(name) => {
            let mut slot = batch.label.borrow_mut();
            let length = name.len().min(slot.0.len());
            slot.0[..length].copy_from_slice(&name[..length]);
            slot.1 = length;
            Flow::Goto
        }
    }
}

/// `call :label arguments` (expanded): the batch file the line comes from run again from after
/// its label, as a batch file of its own whose `%0` is `:label` and whose arguments are those
/// after it, the label looked for from where the batch file is; back here once it ends, the
/// ERRORLEVEL its return code, as after a batch file `call` runs. Outside a batch file, `Invalid
/// attempt to call batch label outside of batch script.`, and it fails.
pub(crate) fn call_label(line: &[u16], state: &mut cmd::State, batch: Option<&Batch>) -> Flow {
    let Some(batch) = batch else {
        let _ = exe::stderr().print(format_args!("{}", label::OUTSIDE));
        state.failed();
        return Flow::Next;
    };
    let line = cmd::trim(line);
    let name = label::called(line);
    let mut path = [0; exe::MAX_PATH];
    let path = {
        let arguments = batch.arguments.borrow();
        let own = arguments.path();
        path[..own.len()].copy_from_slice(own);
        &path[..own.len()]
    };
    let start = Entry::Label(name, batch.offset.get());
    match run_batch(path, line, batch.depth + 1, batch.cmd_script, start, state) {
        flow @ (Flow::Exit(_) | Flow::Abort) => flow,
        _ => {
            state.return_code = state.errorlevel;
            Flow::Next
        }
    }
}
