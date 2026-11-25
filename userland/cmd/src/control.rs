//! The batch language's control flow, run (crate::flow reads it): a line's commands as its
//! operators join them (`&`, `||`, `&&`, groups in parentheses); `if`'s condition tested and its
//! command run, or its `else` command; `for`'s command run once for each item of its set, its
//! variable replaced. What a command does, and what the files, the environment and the console
//! say, the program (src/main.rs) answers as the [`Host`]; `goto` and `call :label`, which need
//! its batch files, are its own.

use core::fmt;

use crate::builtins::files;
use crate::flow::condition::{self, Probe};
use crate::flow::repeat::{self, For, Items, Mode, Options, Scope, Source};
use crate::flow::Keyword;
use crate::syntax::{self, Element, Join, Syntax};
use crate::{batch, State, Variables};

/// What a command leaves the shell to do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Flow {
    /// Go on: the next line.
    Next,
    /// `exit /b` in a batch file: that batch ends (one that called it goes on).
    EndBatch,
    /// Every batch file ends, back to the prompt (Ctrl+C answered Y, or batches nested too deep).
    Abort,
    /// `exit`: the shell ends with the code.
    Exit(u32),
    /// `goto`: the batch file goes on after the label its batch file holds.
    Goto,
    /// A batch file run without `call`: it takes the place of the one running, whose arguments
    /// now hold its path and its line.
    Chain,
}

/// The units a block (a line and the lines a group it opens holds, expanded) may hold in a batch
/// file, at the prompt and in `/C`'s string.
pub const BLOCK: usize = 4096;

/// The units a path may hold: Windows' MAX_PATH (the runtime's `exe::MAX_PATH`, which the library
/// cannot name in a host build).
pub const MAX_PATH: usize = 260;

/// The shell where the control flow runs: what a command does, and what the files, the
/// environment and the console say. The program's runs a line of the batch file it holds, if any.
pub trait Host {
    /// The environment and the current directory, as a loop variable's `%~` modifiers read them.
    fn variables(&mut self) -> &mut dyn Variables;

    /// A simple command (see [`syntax::Element::Simple`]): its redirections applied, its loop
    /// variables (`scope`) replaced in its words, then run.
    fn simple(&mut self, text: &[u16], state: &mut State, scope: Option<&Scope<'_>>) -> Flow;

    /// The commands `text`'s pipes join, run at once.
    fn pipeline(&mut self, text: &[u16], state: &mut State, scope: Option<&Scope<'_>>) -> Flow;

    /// A group's line `inner` run ([`run_line`]) with the group's `redirections` applied.
    fn group(
        &mut self,
        inner: &[u16],
        redirections: &[u16],
        state: &mut State,
        scope: Option<&Scope<'_>>,
    ) -> Flow
    where
        Self: Sized;

    /// A command that cannot be read: why, reported, and what that does to the batch file.
    fn malformed(&mut self, error: Syntax<'_>, state: &mut State) -> Flow;

    /// A `for`'s pass echoed after the prompt, its variables replaced (see [`Pass::iterate`]).
    fn echo(&mut self, command: &[u16], spaced: bool);

    /// Text written to the standard output.
    fn print(&mut self, text: fmt::Arguments<'_>);

    /// Text written to the standard error.
    fn report(&mut self, text: fmt::Arguments<'_>);

    /// Whether Ctrl+C or Ctrl+Break since the last pass of a loop ends it: in a batch file, once
    /// the user says to end every batch file; at the prompt, always.
    fn interrupted(&mut self) -> bool;

    /// Whether the file or directory `name` exists (`if exist`).
    fn exists(&mut self, name: &[u16]) -> bool;

    /// Whether the environment variable `name` is defined (`if defined`).
    fn defined(&mut self, name: &[u16]) -> bool;

    /// The files and directories a wildcard `pattern` matches, in the directory's order, each
    /// handed to `each` with its attributes until it returns another flow than [`Flow::Next`],
    /// which this returns. Nothing matching, or a pattern that cannot be looked for, is
    /// [`Flow::Next`].
    fn find(
        &mut self,
        pattern: &[u16],
        each: &mut dyn FnMut(&mut Self, &[u16], u32) -> Flow,
    ) -> Flow
    where
        Self: Sized;

    /// `/R`'s root: the full path of `root`, or the current directory when it is empty, in
    /// `buffer`; None when it cannot be made.
    fn directory<'b>(&mut self, root: &[u16], buffer: &'b mut [u16; MAX_PATH])
        -> Option<&'b [u16]>;

    /// The lines of the file `name`, each handed to `each` until it returns another flow than
    /// [`Flow::Next`], which this returns; None when the file cannot be opened.
    fn file_lines(
        &mut self,
        name: &[u16],
        each: &mut dyn FnMut(&mut Self, &[u16]) -> Flow,
    ) -> Option<Flow>
    where
        Self: Sized;

    /// The lines `command` writes (`for /f`'s `'command'`), each handed to `each` until it
    /// returns another flow than [`Flow::Next`], which this returns.
    fn command_lines(
        &mut self,
        command: &[u16],
        each: &mut dyn FnMut(&mut Self, &[u16]) -> Flow,
    ) -> Flow
    where
        Self: Sized;
}

/// A line's commands, as its `&`s separate them: each run in turn, until one ends the batch or the
/// shell. In a `for`'s command, `scope` holds the loops' variables, replaced in each command's
/// words as it runs (never in the line's syntax: see [`Scope`]).
pub fn run_line<H: Host>(
    text: &[u16],
    state: &mut State,
    host: &mut H,
    scope: Option<&Scope<'_>>,
) -> Flow {
    for (part, _) in syntax::parts(text, Join::Then) {
        if crate::trim(part).is_empty() {
            continue;
        }
        match run_or_else(part, state, host, scope) {
            Flow::Next => {}
            flow => return flow,
        }
    }
    Flow::Next
}

/// Commands `||` joins: each runs while those before it failed (their return code not 0).
fn run_or_else<H: Host>(
    text: &[u16],
    state: &mut State,
    host: &mut H,
    scope: Option<&Scope<'_>>,
) -> Flow {
    for (index, (part, _)) in syntax::parts(text, Join::OrElse).enumerate() {
        if index > 0 && state.return_code == 0 {
            break;
        }
        match run_and_then(part, state, host, scope) {
            Flow::Next => {}
            flow => return flow,
        }
    }
    Flow::Next
}

/// Commands `&&` joins: each runs while those before it succeeded (their return code 0).
fn run_and_then<H: Host>(
    text: &[u16],
    state: &mut State,
    host: &mut H,
    scope: Option<&Scope<'_>>,
) -> Flow {
    for (index, (part, _)) in syntax::parts(text, Join::AndThen).enumerate() {
        if index > 0 && state.return_code != 0 {
            break;
        }
        let flow = if syntax::parts(part, Join::Pipe).nth(1).is_some() {
            host.pipeline(part, state, scope)
        } else {
            run_element(part, state, host, scope)
        };
        match flow {
            Flow::Next => {}
            flow => return flow,
        }
    }
    Flow::Next
}

/// One command between the operators, run in the shell: a group's line with the group's
/// redirections, `if` or `for`, or a simple command ([`Host::simple`]).
fn run_element<H: Host>(
    text: &[u16],
    state: &mut State,
    host: &mut H,
    scope: Option<&Scope<'_>>,
) -> Flow {
    match syntax::element(text) {
        Ok(Element::Group {
            inner,
            redirections,
        }) => host.group(inner, redirections, state, scope),
        Ok(Element::Flow(keyword, text)) => run(keyword, text, state, host, scope),
        Ok(Element::Simple(text)) => host.simple(text, state, scope),
        Err(error) => host.malformed(error, state),
    }
}

/// `if` or `for`, its text from its keyword on: its help when its first word asks for it (`if
/// /?`), otherwise what it says done, the variables of the loops it is in (`scope`) replaced in
/// its words once they are read. It returns 0, unless the command it runs returns another code.
/// A header that cannot be read is reported as a line that cannot be ([`Host::malformed`]): the
/// line was checked before it ran, so only a text no line held (`call`'s) gets there.
pub fn run<H: Host>(
    keyword: Keyword,
    text: &[u16],
    state: &mut State,
    host: &mut H,
    scope: Option<&Scope<'_>>,
) -> Flow {
    state.spaced = true;
    state.return_code = 0;
    match keyword {
        Keyword::If => match condition::parse(text) {
            Ok(condition::Header::If(header)) => match scope {
                Some(scope) => run_bound_if(&header, scope, state, host),
                None => run_if(&header, state, host, None),
            },
            Ok(condition::Header::Help(_)) => help("if", state, host),
            Err(error) => host.malformed(error, state),
        },
        Keyword::For => match repeat::parse(text) {
            Ok(repeat::Header::For(header)) => match scope {
                Some(scope) if header.set.contains(&u16::from(b'%')) => {
                    run_bound_for(&header, scope, state, host)
                }
                _ => run_for(&header, header.set, state, host, scope),
            },
            Ok(repeat::Header::Help(_)) => help("for", state, host),
            Err(error) => host.malformed(error, state),
        },
    }
}

/// A command's help printed in place of running it: it returns 1, the ERRORLEVEL kept.
fn help<H: Host>(name: &str, state: &mut State, host: &mut H) -> Flow {
    let mut word = [0; 3];
    for (unit, byte) in word.iter_mut().zip(name.bytes()) {
        *unit = u16::from(byte);
    }
    if let Some(help) = crate::help::of(&word[..name.len()]) {
        host.print(format_args!("{help}"));
    }
    state.return_code = crate::help::SHOWN;
    Flow::Next
}

/// The shell's state, as a condition reads it.
struct Conditions<'h, H> {
    errorlevel: u32,
    host: &'h mut H,
}

impl<H: Host> Probe for Conditions<'_, H> {
    fn errorlevel(&self) -> u32 {
        self.errorlevel
    }

    fn exists(&mut self, name: &[u16]) -> bool {
        self.host.exists(name)
    }

    fn defined(&mut self, name: &[u16]) -> bool {
        self.host.defined(name)
    }
}

/// An `if` in a `for`'s command: its words bound to the loops' variables ([`condition::If::bound`])
/// before it runs. Words the values make longer than a block run nothing, as a command's do (see
/// the program's `run_bound`).
#[inline(never)]
fn run_bound_if<H: Host>(
    header: &condition::If<'_>,
    scope: &Scope<'_>,
    state: &mut State,
    host: &mut H,
) -> Flow {
    let mut buffer = [0; BLOCK];
    match header.bound(scope, host.variables(), &mut buffer) {
        Ok(bound) => run_if(&bound, state, host, Some(scope)),
        Err(_) => Flow::Next,
    }
}

/// `if`: its command when the condition holds, its `else` command when it does not and it has
/// one.
fn run_if<H: Host>(
    header: &condition::If<'_>,
    state: &mut State,
    host: &mut H,
    scope: Option<&Scope<'_>>,
) -> Flow {
    let (then, otherwise) = syntax::branches(header.command());
    let mut conditions = Conditions {
        errorlevel: state.errorlevel,
        host,
    };
    let holds = header.holds(&mut conditions);
    if holds {
        run_line(then, state, host, scope)
    } else if let Some(otherwise) = otherwise {
        run_line(otherwise, state, host, scope)
    } else {
        Flow::Next
    }
}

/// A `for` in another's command, its set bound to the loops' variables (`for %b in (%~a)` loops
/// over `a`'s words) before it runs.
#[inline(never)]
fn run_bound_for<H: Host>(
    header: &For<'_>,
    scope: &Scope<'_>,
    state: &mut State,
    host: &mut H,
) -> Flow {
    let mut buffer = [0; BLOCK];
    match repeat::substitute(header.set, scope, host.variables(), &mut buffer) {
        Ok(set) => run_for(header, set, state, host, Some(scope)),
        Err(_) => Flow::Next,
    }
}

/// `for`: its command run for each item its mode gives from `set` (its header's, bound to the
/// loops it is in), until one ends the batch file or the shell (or `goto` leaves the loop).
fn run_for<H: Host>(
    header: &For<'_>,
    set: &[u16],
    state: &mut State,
    host: &mut H,
    scope: Option<&Scope<'_>>,
) -> Flow {
    let pass = Pass { header, scope };
    match header.mode {
        Mode::Range => {
            for value in repeat::range(set) {
                let mut digits = [0; 24];
                let value = decimal(value, &mut digits);
                match pass.iterate(&[(header.variable, value)], state, host) {
                    Flow::Next => {}
                    flow => return flow,
                }
            }
            Flow::Next
        }
        Mode::Items => match header.recursive {
            Some(root) => recursive(&pass, set, root, state, host),
            None => {
                for item in Items(set) {
                    let flow = if files::has_wildcards(item) {
                        matches(&pass, batch::unquote(item), state, host)
                    } else {
                        pass.iterate(&[(header.variable, item)], state, host)
                    };
                    if !matches!(flow, Flow::Next) {
                        return flow;
                    }
                }
                Flow::Next
            }
        },
        Mode::Lines(options) => lines(&pass, set, &options, state, host),
    }
}

/// A `for` running: its header, and the variables of the loops it is in.
struct Pass<'a, 'b> {
    header: &'a For<'a>,
    scope: Option<&'a Scope<'b>>,
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

impl Pass<'_, '_> {
    /// The loop's command run once, its variables `variables` (and the outer loops') replaced in
    /// its words as each runs (see [`Scope`]), echoed first after the prompt while echo is on
    /// (unless `@` hides it), its variables replaced, as Windows' cmd echoes each pass. Ctrl+C or
    /// Ctrl+Break since the last pass asks, in a batch file, whether to end every batch file; at
    /// the prompt it ends the loop.
    #[inline(never)]
    fn iterate<H: Host>(
        &self,
        variables: &[(u16, &[u16])],
        state: &mut State,
        host: &mut H,
    ) -> Flow {
        if host.interrupted() {
            return Flow::Abort;
        }
        let scope = Scope {
            variables,
            outer: self.scope,
        };
        if state.echo {
            echo_pass(self.header.command(), &scope, state.spaced, host);
        }
        run_line(self.header.command(), state, host, Some(&scope))
    }
}

/// A pass's command echoed, its variables replaced (nothing when they make it longer than a
/// block).
#[inline(never)]
fn echo_pass<H: Host>(command: &[u16], scope: &Scope<'_>, spaced: bool, host: &mut H) {
    let mut buffer = [0; BLOCK];
    if let Ok(command) = repeat::substitute(command, scope, host.variables(), &mut buffer) {
        host.echo(command, spaced);
    }
}

/// The files a wildcard `pattern` matches (directories with `/D`; neither hidden nor system ones,
/// nor `.` and `..`), each the pattern's directory as written and its name, in the directory's
/// order.
#[inline(never)]
fn matches<H: Host>(pass: &Pass<'_, '_>, pattern: &[u16], state: &mut State, host: &mut H) -> Flow {
    let header = pass.header;
    let (directory, _) = files::split(pattern);
    host.find(pattern, &mut |host, name, attributes| {
        let directory_found = attributes & files::DIRECTORY != 0;
        if files::is_dots(name)
            || attributes & (files::HIDDEN | files::SYSTEM) != 0
            || directory_found != header.directories
        {
            return Flow::Next;
        }
        let mut buffer = [0; MAX_PATH];
        let Some(path) = files::join(directory, name, &mut buffer) else {
            return Flow::Next;
        };
        pass.iterate(&[(header.variable, path)], state, host)
    })
}

/// `/R`: the set looked for in `root` (the current directory when empty) and in each directory
/// below it, a directory before those below it.
fn recursive<H: Host>(
    pass: &Pass<'_, '_>,
    set: &[u16],
    root: &[u16],
    state: &mut State,
    host: &mut H,
) -> Flow {
    let mut buffer = [0; MAX_PATH];
    let root = batch::unquote(root);
    match host.directory(root, &mut buffer) {
        Some(directory) => walk(pass, set, directory, state, host),
        None => Flow::Next,
    }
}

/// `/R` in `directory`: each item of the set, a wildcard one as the files it matches there, any
/// other as the directory and the item (`.` the directory itself, as `C:\x\.`); then each
/// directory in it, in turn.
#[inline(never)]
fn walk<H: Host>(
    pass: &Pass<'_, '_>,
    set: &[u16],
    directory: &[u16],
    state: &mut State,
    host: &mut H,
) -> Flow {
    let header = pass.header;
    for item in Items(set) {
        let item = batch::unquote(item);
        let mut buffer = [0; MAX_PATH];
        let Some(path) = files::join(directory, item, &mut buffer) else {
            continue;
        };
        let flow = if files::has_wildcards(item) {
            matches(pass, path, state, host)
        } else {
            pass.iterate(&[(header.variable, path)], state, host)
        };
        if !matches!(flow, Flow::Next) {
            return flow;
        }
    }
    let mut pattern = [0; MAX_PATH];
    let Some(pattern) = files::join(directory, &[u16::from(b'*')], &mut pattern) else {
        return Flow::Next;
    };
    host.find(pattern, &mut |host, name, attributes| {
        if attributes & files::DIRECTORY == 0 || files::is_dots(name) {
            return Flow::Next;
        }
        let mut buffer = [0; MAX_PATH];
        let Some(below) = files::join(directory, name, &mut buffer) else {
            return Flow::Next;
        };
        walk(pass, set, below, state, host)
    })
}

/// `/F`: the lines of the files, the string or the command's output its set names, each cut
/// into its variables' values ([`repeat::fields`]), `skip=`'s first lines of each left out.
fn lines<H: Host>(
    pass: &Pass<'_, '_>,
    set: &[u16],
    options: &Options<'_>,
    state: &mut State,
    host: &mut H,
) -> Flow {
    match repeat::source(set, options.backquote) {
        Source::Text(text) => {
            let mut skip = options.skip;
            line(pass, options, text, &mut skip, state, host)
        }
        Source::Files(names) => {
            for name in Items(names) {
                // A file that cannot be opened is reported, and ends the loop, the ERRORLEVEL
                // kept. Windows 2000's cmd reports it twice, the first time with `??` for its
                // name (batflow's capture).
                let name = batch::unquote(name);
                let mut skip = options.skip;
                let read = host.file_lines(name, &mut |host, text| {
                    line(pass, options, text, &mut skip, state, host)
                });
                match read {
                    None => {
                        host.report(format_args!(
                            "{}{}",
                            FileNotFound(&[u16::from(b'?'); 2]),
                            FileNotFound(name)
                        ));
                        return Flow::Next;
                    }
                    Some(Flow::Next) => {}
                    Some(flow) => return flow,
                }
            }
            Flow::Next
        }
        Source::Command(command) => {
            let mut skip = options.skip;
            host.command_lines(command, &mut |host, text| {
                line(pass, options, text, &mut skip, state, host)
            })
        }
    }
}

/// One line of `/F`'s: skipped while `skip` counts down, otherwise its fields handed to the
/// variables, from the loop's variable on (`%%a`, `%%b`, ...), and the command run with them.
fn line<H: Host>(
    pass: &Pass<'_, '_>,
    options: &Options<'_>,
    line: &[u16],
    skip: &mut usize,
    state: &mut State,
    host: &mut H,
) -> Flow {
    let header = pass.header;
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
    pass.iterate(&variables[..fields.count], state, host)
}

/// What `/F` prints when a file of its set cannot be opened.
struct FileNotFound<'a>(&'a [u16]);

impl fmt::Display for FileNotFound<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "The system cannot find the file {}.\r\n",
            crate::Text(self.0)
        )
    }
}

#[cfg(test)]
mod tests;
