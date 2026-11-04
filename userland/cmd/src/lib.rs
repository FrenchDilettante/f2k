//! cmd: F2K's command interpreter, Windows 2000's cmd.exe with its command extensions on. Started
//! with `/C` or `/K` (src/switches.rs) it runs a command line first; interactively it prompts as
//! the PROMPT variable says (`$P$G` without one) and reads lines from the console. Each line has
//! its `%NAME%` variables expanded, then either runs a built-in command (`call`, `cd` or `chdir`,
//! `cls`, `echo`, `exit`, `path`, `prompt`, `rem`, `set`, `type`, `ver`) or names a program, found
//! as cmd.exe finds one (src/search.rs): a Windows program is started and waited for, a batch file
//! (src/batch.rs) runs its lines in the shell. No `goto`, `if`, `for` or `shift`, no pipes, no
//! redirection. The program (src/main.rs) makes the calls; this library reads the lines and says
//! what is printed.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

pub mod batch;
pub mod search;
pub mod switches;

use core::fmt;

/// The units a line read holds: the console's line, its CR LF included (a line-mode read's
/// longest). A line expanded holds as many.
pub const LINE: usize = 1024;

/// The units a PROMPT variable's value is read into: a longer one prompts as the default does.
pub const PROMPT_TEXT: usize = 512;

/// The exit code when the standard input cannot be read.
pub const FAILED: u32 = 1;

/// The version the shell names: the banner's line, and `ver`'s and `$V`'s text. Windows 2000's
/// cmd names Microsoft's product here; F2K names its own, with the version it implements.
pub const VERSION: &str = "F2K [Version 5.00.2195]";

/// What the shell prints as it starts, before its first prompt: [`VERSION`]'s line.
pub const BANNER: &str = "F2K [Version 5.00.2195]\r\n";

/// The prompt without a PROMPT variable: the current directory, then `>`.
pub const DEFAULT_PROMPT: &str = "$P$G";

/// What `cd` prints when SetCurrentDirectoryW refuses the path (Windows 2000's cmd's text for
/// ERROR_PATH_NOT_FOUND, whatever the failure).
pub const PATH_NOT_FOUND: &str = "The system cannot find the path specified.\r\n";

/// Windows 2000's text for ERROR_FILE_NOT_FOUND.
pub const FILE_NOT_FOUND: &str = "The system cannot find the file specified.\r\n";

/// What a built-in prints when its arguments make no sense.
pub const SYNTAX: &str = "The syntax of the command is incorrect.\r\n";

/// What the shell prints when a line's variables expand past a line's units.
pub const TOO_LONG: &str = "The input line is too long.\r\n";

/// What `path` prints without a PATH variable.
pub const NO_PATH: &str = "No Path\r\n";

/// The Win32 errors CreateProcessW fails with when there is no such program, which the shell
/// reports as a command not recognized: ERROR_FILE_NOT_FOUND and ERROR_PATH_NOT_FOUND.
pub const NO_SUCH_PROGRAM: [u32; 2] = [2, 3];

/// The ERRORLEVEL a command not recognized leaves (Windows' cmd's 9009).
pub const NOT_RECOGNIZED: u32 = 9009;

/// The variable the prompt's text comes from.
pub const PROMPT: &str = "PROMPT";

/// The variable `path` shows and sets.
pub const PATH: &str = "PATH";

/// Windows 2000's text for a Win32 error a built-in reports, CR LF included: None for one the
/// shell has no text for.
pub fn message(error: u32) -> Option<&'static str> {
    match error {
        2 => Some(FILE_NOT_FOUND),
        3 => Some(PATH_NOT_FOUND),
        5 => Some("Access is denied.\r\n"),
        32 => Some(
            "The process cannot access the file because it is being used by another process.\r\n",
        ),
        123 => Some("The filename, directory name, or volume label syntax is incorrect.\r\n"),
        _ => None,
    }
}

/// What the shell keeps between commands.
pub struct State {
    /// ERRORLEVEL: a program's exit code, or the code a built-in leaves (see
    /// [`clears_errorlevel`]).
    pub errorlevel: u32,
    /// The last command's return code: a program's exit code, 9009 for a command not recognized,
    /// a built-in's 0 when it succeeds and 1 when it fails, a batch file's its last command's. It
    /// is what `/C` ends with, and it is not the ERRORLEVEL: `echo` returns 0 and keeps the
    /// ERRORLEVEL, and `exit /b 3` sets the ERRORLEVEL to 3 and returns 0, so that a script ending
    /// with it ends `cmd /c` with 0, as Windows 2000's does.
    pub return_code: u32,
    /// Whether echo is on (`echo on`, `echo off`): off, the shell prompts with nothing.
    pub echo: bool,
    /// Whether the next prompt follows an empty line, as it does after a command. An empty line,
    /// an abandoned one and `cls` leave none.
    pub spaced: bool,
}

impl Default for State {
    /// The shell as it starts: echo on, ERRORLEVEL 0, the first prompt after an empty line (below
    /// the banner).
    fn default() -> Self {
        State {
            errorlevel: 0,
            return_code: 0,
            echo: true,
            spaced: true,
        }
    }
}

impl State {
    /// A program ended with `code`: its return code and the ERRORLEVEL.
    pub fn ended(&mut self, code: u32) {
        self.return_code = code;
        self.errorlevel = code;
    }

    /// A built-in failed: it returns 1, and the ERRORLEVEL becomes 1.
    pub fn failed(&mut self) {
        self.ended(1);
    }
}

/// Whether `command`, a built-in, sets the ERRORLEVEL to 0 when it succeeds (its failures set it
/// to 1). `cd`, `type` and `ver` always do; `set`, `path` and `prompt` do in a batch file named
/// `.cmd` (`in_cmd_script`), and leave it at the prompt and in a `.bat` file, as Windows 2000's
/// documentation of the two extensions says; `echo`, `rem` and `cls` never touch it. Programs,
/// `call` and `exit` set it their own way.
pub fn clears_errorlevel(command: &Command<'_>, in_cmd_script: bool) -> bool {
    match command {
        Command::ChangeDirectory(_) | Command::Type(_) | Command::Version => true,
        Command::Set(_) | Command::Path(_) | Command::Prompt(_) => in_cmd_script,
        _ => false,
    }
}

/// A line, read: what the shell does with it.
#[derive(Debug, PartialEq, Eq)]
pub enum Command<'a> {
    /// Nothing but blanks (and `@`): prompt again.
    Empty,
    /// `call`: the command its argument holds; a batch file it names returns to the caller.
    Call(&'a [u16]),
    /// `exit`, its argument (see [`batch::exit`]): the shell ends, or with `/B` the batch.
    Exit(&'a [u16]),
    /// `rem`: a remark, nothing done.
    Remark,
    /// `cd` or `chdir`: without an argument, print the current directory; with one, change to it.
    ChangeDirectory(Option<&'a [u16]>),
    /// `cls`: the screen cleared (its arguments ignored).
    ClearScreen,
    /// `echo`, in one of its forms.
    Echo(Echo<'a>),
    /// `path`: without an argument, show PATH; with one, set it (`;` alone clears it).
    Path(Option<&'a [u16]>),
    /// `prompt`: without an argument, back to the default prompt; with one, the new prompt.
    Prompt(Option<&'a [u16]>),
    /// `set`, its argument (see [`Set`]): leading blanks skipped, trailing ones kept.
    Set(&'a [u16]),
    /// `type`: the files its argument names (see [`Names`]).
    Type(&'a [u16]),
    /// `ver`: the version (its arguments ignored).
    Version,
    /// Anything else: the program the line's first word names (see [`program_name`]), run with
    /// the line (blanks trimmed) as its command line.
    Run { line: &'a [u16], word: &'a [u16] },
}

/// What `echo` does.
#[derive(Debug, PartialEq, Eq)]
pub enum Echo<'a> {
    /// `echo` alone (or followed by blanks only): echo's state shown.
    Show,
    /// `echo on`.
    On,
    /// `echo off`.
    Off,
    /// `echo text`, `echo.`: the text printed as given, then CR LF.
    Text(&'a [u16]),
}

/// What `set`'s argument asks for.
#[derive(Debug, PartialEq, Eq)]
pub enum Set<'a> {
    /// `set` alone: every variable; `set P`: the variables whose names start with P.
    Show(Option<&'a [u16]>),
    /// `set NAME=value`: NAME set to value, or deleted when value is empty.
    Assign { name: &'a [u16], value: &'a [u16] },
    /// `set =value`: no name.
    Incorrect,
}

const SPACE: u16 = b' ' as u16;
const TAB: u16 = b'\t' as u16;
const PERCENT: u16 = b'%' as u16;
pub(crate) const EQUALS: u16 = b'=' as u16;
pub(crate) const QUOTE: u16 = b'"' as u16;
const AT: u16 = b'@' as u16;
const DOLLAR: u16 = b'$' as u16;

/// Whether `unit` separates words: a space or a tab.
pub(crate) fn is_blank(unit: u16) -> bool {
    unit == SPACE || unit == TAB
}

/// Whether `unit` ends a built-in command's word: a blank, or one of cmd's delimiters `,` `;` `=`.
fn ends_word(unit: u16) -> bool {
    is_blank(unit) || unit == u16::from(b',') || unit == u16::from(b';') || unit == EQUALS
}

/// Whether `unit`, right after `echo`, separates it from its text: a blank, or one of the
/// characters Windows' cmd lets `echo` run into (`echo.`, `echo:`, `echo(`...), the one that is
/// not printed.
fn ends_echo(unit: u16) -> bool {
    is_blank(unit) || b".,;=:/\\([]+".iter().any(|&byte| unit == u16::from(byte))
}

/// `text` without its leading blanks.
pub(crate) fn skip_blanks(text: &[u16]) -> &[u16] {
    let start = text
        .iter()
        .position(|&unit| !is_blank(unit))
        .unwrap_or(text.len());
    &text[start..]
}

/// `text` without its trailing blanks.
fn trim_end(text: &[u16]) -> &[u16] {
    let end = text
        .iter()
        .rposition(|&unit| !is_blank(unit))
        .map_or(0, |last| last + 1);
    &text[..end]
}

/// `text` without the blanks around it.
pub(crate) fn trim_blanks(text: &[u16]) -> &[u16] {
    trim_end(skip_blanks(text))
}

/// A line as read, without its line break (CR LF, or the part of it there is).
pub(crate) fn without_break(line: &[u16]) -> &[u16] {
    let end = line
        .iter()
        .rposition(|&unit| unit != u16::from(b'\r') && unit != u16::from(b'\n'))
        .map_or(0, |last| last + 1);
    &line[..end]
}

/// A line as read, without its line break and the blanks around it.
pub fn trim(line: &[u16]) -> &[u16] {
    trim_blanks(without_break(line))
}

/// `unit` upper-cased when it is an ASCII letter: how variable names compare.
pub(crate) fn fold(unit: u16) -> u16 {
    if (u16::from(b'a')..=u16::from(b'z')).contains(&unit) {
        unit - 32
    } else {
        unit
    }
}

/// Whether two names are the same, ignoring the case of ASCII letters.
fn same_name(a: &[u16], b: &[u16]) -> bool {
    a.len() == b.len() && a.iter().zip(b).all(|(&a, &b)| fold(a) == fold(b))
}

/// Whether `word` is `name` (lowercase ASCII), ignoring case.
fn is_named(word: &[u16], name: &str) -> bool {
    word.len() == name.len()
        && word.iter().zip(name.bytes()).all(|(&unit, byte)| {
            u8::try_from(unit).is_ok_and(|unit| unit.to_ascii_lowercase() == byte)
        })
}

/// What a line read says to do, once expanded. Leading `@`s go (a batch file's line hides its
/// echo with one). The command word is the line's first; a built-in's ends at a blank or `,` `;`
/// `=` (`echo`'s at one of the characters it runs into), a program's at a blank, and built-ins
/// are recognized whatever their case.
pub fn parse(line: &[u16]) -> Command<'_> {
    let mut line = without_break(line);
    loop {
        line = skip_blanks(line);
        match line.split_first() {
            Some((&AT, rest)) => line = rest,
            _ => break,
        }
    }
    if trim_end(line).is_empty() {
        return Command::Empty;
    }
    if line.len() >= 4 && is_named(&line[..4], "echo") {
        match line.get(4) {
            None => return Command::Echo(Echo::Show),
            Some(&unit) if ends_echo(unit) => return Command::Echo(echo(unit, &line[5..])),
            Some(_) => {}
        }
    }
    let end = line
        .iter()
        .position(|&unit| ends_word(unit))
        .unwrap_or(line.len());
    let (word, rest) = line.split_at(end);
    let argument = skip_blanks(rest);
    if is_named(word, "exit") {
        return Command::Exit(trim_blanks(argument));
    }
    if is_named(word, "rem") {
        return Command::Remark;
    }
    if is_named(word, "call") {
        return Command::Call(argument);
    }
    if is_named(word, "cd") || is_named(word, "chdir") {
        let argument = trim_blanks(argument);
        return Command::ChangeDirectory((!argument.is_empty()).then_some(argument));
    }
    if is_named(word, "cls") {
        return Command::ClearScreen;
    }
    if is_named(word, "ver") {
        return Command::Version;
    }
    if is_named(word, "set") {
        return Command::Set(argument);
    }
    if is_named(word, "type") {
        return Command::Type(argument);
    }
    if is_named(word, "path") {
        let argument = trim_blanks(after_equals(argument));
        return Command::Path((!argument.is_empty()).then_some(argument));
    }
    if is_named(word, "prompt") {
        let argument = after_equals(argument);
        return Command::Prompt((!trim_end(argument).is_empty()).then_some(argument));
    }
    let line = trim_end(line);
    let mut quoted = false;
    let word = &line[..line
        .iter()
        .position(|&unit| {
            if unit == QUOTE {
                quoted = !quoted;
            }
            !quoted && is_blank(unit)
        })
        .unwrap_or(line.len())];
    Command::Run { line, word }
}

/// The name a program's word gives, in `out`: the word without its quotes (`"C:\a b\x"` names
/// `C:\a b\x`). None when it does not fit.
pub fn program_name<'a>(word: &[u16], out: &'a mut [u16]) -> Option<&'a [u16]> {
    let mut length = 0;
    for &unit in word.iter().filter(|&&unit| unit != QUOTE) {
        *out.get_mut(length)? = unit;
        length += 1;
    }
    Some(&out[..length])
}

/// `argument` without an `=` it starts with and the blanks after that (`path=x`, `prompt=$g`).
fn after_equals(argument: &[u16]) -> &[u16] {
    match argument.split_first() {
        Some((&EQUALS, rest)) => skip_blanks(rest),
        _ => argument,
    }
}

/// `echo`'s form: `separator` is the unit after the word, `text` what follows it.
fn echo(separator: u16, text: &[u16]) -> Echo<'_> {
    if !is_blank(separator) {
        return Echo::Text(text);
    }
    let word = trim_blanks(text);
    if word.is_empty() {
        Echo::Show
    } else if is_named(word, "on") {
        Echo::On
    } else if is_named(word, "off") {
        Echo::Off
    } else {
        Echo::Text(text)
    }
}

/// What `set`'s argument asks for. `set "NAME=value"` (command extensions) assigns what is
/// between the first quote and the last; a name is everything before the first `=`, blanks
/// included, and a value everything after it.
pub fn set(argument: &[u16]) -> Set<'_> {
    let mut argument = argument;
    if let Some((&QUOTE, rest)) = argument.split_first() {
        argument = match rest.iter().rposition(|&unit| unit == QUOTE) {
            Some(last) => &rest[..last],
            None => rest,
        };
    }
    match argument.iter().position(|&unit| unit == EQUALS) {
        Some(0) => Set::Incorrect,
        Some(equals) => Set::Assign {
            name: &argument[..equals],
            value: &argument[equals + 1..],
        },
        None => {
            let prefix = trim_end(argument);
            Set::Show((!prefix.is_empty()).then_some(prefix))
        }
    }
}

/// Whether `set` lists the environment block's `entry` (`NAME=value`): never a drive's current
/// directory (`=C:=C:\`, a name starting with `=`), and, with a prefix, only a name starting with
/// it, whatever the case of its ASCII letters.
pub fn listed(entry: &[u16], prefix: Option<&[u16]>) -> bool {
    if entry.first() == Some(&EQUALS) {
        return false;
    }
    let name = &entry[..entry
        .iter()
        .position(|&unit| unit == EQUALS)
        .unwrap_or(entry.len())];
    prefix
        .is_none_or(|prefix| name.len() >= prefix.len() && same_name(&name[..prefix.len()], prefix))
}

/// The value of the environment block's `entry` (`NAME=value`) when its name is `name`, whatever
/// the case of its ASCII letters.
pub fn value_of<'a>(entry: &'a [u16], name: &[u16]) -> Option<&'a [u16]> {
    match entry.get(name.len()) {
        Some(&EQUALS) if same_name(&entry[..name.len()], name) => Some(&entry[name.len() + 1..]),
        _ => None,
    }
}

/// Whether `path`'s argument clears PATH: `;` alone.
pub fn clears_path(argument: &[u16]) -> bool {
    argument == [u16::from(b';')]
}

/// The file names `type`'s argument holds: separated by blanks, a name in double quotes kept
/// whole, its quotes dropped.
pub struct Names<'a>(pub &'a [u16]);

impl<'a> Iterator for Names<'a> {
    type Item = &'a [u16];

    fn next(&mut self) -> Option<&'a [u16]> {
        let rest = skip_blanks(self.0);
        if rest.is_empty() {
            self.0 = rest;
            return None;
        }
        let (name, after) = if rest[0] == QUOTE {
            let inner = &rest[1..];
            match inner.iter().position(|&unit| unit == QUOTE) {
                Some(close) => (&inner[..close], &inner[close + 1..]),
                None => (inner, &inner[inner.len()..]),
            }
        } else {
            let end = rest
                .iter()
                .position(|&unit| is_blank(unit))
                .unwrap_or(rest.len());
            rest.split_at(end)
        };
        self.0 = after;
        Some(name)
    }
}

/// The line was too long: what does not fit a buffer.
#[derive(Debug, PartialEq, Eq)]
pub struct TooLong;

/// Where `%NAME%` finds its value: the process's environment, and what the dynamic variables
/// (`set /?`) show when no variable of their name exists.
pub trait Variables {
    /// The variable `name`'s value, written to the start of `value`: its length, None when there
    /// is no such variable, TooLong when it does not fit.
    fn get(&mut self, name: &[u16], value: &mut [u16]) -> Result<Option<usize>, TooLong>;

    /// The current directory (`%CD%`), written to the start of `value`: its length (0 when it
    /// cannot be read), TooLong when it does not fit.
    fn current_directory(&mut self, value: &mut [u16]) -> Result<usize, TooLong>;

    /// The local time (`%DATE%`, `%TIME%`).
    fn time(&mut self) -> Time;

    /// A random number from 0 to 32767 (`%RANDOM%`).
    fn random(&mut self) -> u16;

    /// The shell's own command line (`%CMDCMDLINE%`).
    fn command_line(&self) -> &[u16];
}

/// The command extensions' version `%CMDEXTVERSION%` shows: Windows 2000's.
pub const EXTENSIONS_VERSION: u32 = 2;

/// UTF-16 units written into a slice, as `core::fmt::Write`: TooLong once they do not fit.
struct Units<'a> {
    buffer: &'a mut [u16],
    length: usize,
}

impl fmt::Write for Units<'_> {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        for unit in text.encode_utf16() {
            *self.buffer.get_mut(self.length).ok_or(fmt::Error)? = unit;
            self.length += 1;
        }
        Ok(())
    }
}

/// `args` formatted into the start of `value`: the units written.
fn format(value: &mut [u16], args: fmt::Arguments<'_>) -> Result<usize, TooLong> {
    let mut units = Units {
        buffer: value,
        length: 0,
    };
    fmt::Write::write_fmt(&mut units, args).map_err(|_| TooLong)?;
    Ok(units.length)
}

/// The variable `name`'s value, written to the start of `value`: the environment's, else a
/// dynamic variable's (`set /?`): `%CD%`, `%DATE%`, `%TIME%`, `%RANDOM%`, `%ERRORLEVEL%` (signed),
/// `%CMDEXTVERSION%`, `%CMDCMDLINE%`. None for neither.
fn variable(
    name: &[u16],
    errorlevel: u32,
    variables: &mut dyn Variables,
    value: &mut [u16],
) -> Result<Option<usize>, TooLong> {
    if name.is_empty() {
        return Ok(None);
    }
    if let Some(length) = variables.get(name, value)? {
        return Ok(Some(length));
    }
    let length = if is_named(name, "errorlevel") {
        format(value, format_args!("{}", errorlevel as i32))?
    } else if is_named(name, "cd") {
        variables.current_directory(value)?
    } else if is_named(name, "date") {
        let time = variables.time();
        format(value, format_args!("{}", Date(&time)))?
    } else if is_named(name, "time") {
        let time = variables.time();
        format(value, format_args!("{}", Clock(&time)))?
    } else if is_named(name, "random") {
        let random = variables.random();
        format(value, format_args!("{random}"))?
    } else if is_named(name, "cmdextversion") {
        format(value, format_args!("{EXTENSIONS_VERSION}"))?
    } else if is_named(name, "cmdcmdline") {
        let line = variables.command_line();
        value
            .get_mut(..line.len())
            .ok_or(TooLong)?
            .copy_from_slice(line);
        line.len()
    } else {
        return Ok(None);
    };
    Ok(Some(length))
}

/// The letters a batch argument's `%~` may carry before its digit (`call /?`): the argument as a
/// full path, its drive, path, name, extension, short name, attributes, time, size.
const MODIFIERS: &[u8] = b"fdpnxsatz";

/// `line` with its variables expanded, in `expanded`: `%NAME%` becomes NAME's value (see
/// [`variable`]; names compare whatever the case of their letters), and `%NAME:~n,m%` the part of
/// its value [`substring`] and [`cut`] say.
///
/// Interactively (`batch` None), an undefined `%NAME%` keeps its `%` and name, its closing `%`
/// free to open the next variable, and a `%` without a closing one stays.
///
/// In a batch file (`batch` the batch's arguments, see [`batch::argument`]), `%0` to `%9` are its
/// arguments (nothing past the last), `%*` all of them after its name, `%~1` an argument without
/// its quotes; `%%` is `%`; an undefined `%NAME%` is nothing, and a `%` without a closing one
/// goes. `%~` with modifier letters (`%~dp0`) is left as it is.
///
/// TooLong when the expanded line does not fit `expanded`.
pub fn expand<'a>(
    line: &[u16],
    errorlevel: u32,
    batch: Option<&[u16]>,
    variables: &mut dyn Variables,
    expanded: &'a mut [u16],
) -> Result<&'a [u16], TooLong> {
    let mut length = 0;
    let mut at = 0;
    while at < line.len() {
        if line[at] != PERCENT {
            copy(&line[at..at + 1], expanded, &mut length)?;
            at += 1;
            continue;
        }
        if let Some(arguments) = batch {
            let next = line.get(at + 1).copied();
            let digit = |unit: Option<u16>| {
                unit.and_then(|unit| char::from_u32(u32::from(unit)))
                    .and_then(|c| c.to_digit(10))
                    .map(|digit| digit as usize)
            };
            if next.is_none() {
                break;
            }
            if next == Some(PERCENT) {
                copy(&[PERCENT], expanded, &mut length)?;
                at += 2;
                continue;
            }
            if let Some(n) = digit(next) {
                copy(
                    batch::argument(arguments, n).unwrap_or(&[]),
                    expanded,
                    &mut length,
                )?;
                at += 2;
                continue;
            }
            if next == Some(u16::from(b'*')) {
                copy(batch::all(arguments), expanded, &mut length)?;
                at += 2;
                continue;
            }
            if next == Some(u16::from(b'~')) {
                let letters = line[at + 2..]
                    .iter()
                    .take_while(|&&unit| {
                        u8::try_from(unit).is_ok_and(|byte| MODIFIERS.contains(&byte))
                    })
                    .count();
                let end = at + 2 + letters;
                if let Some(n) = digit(line.get(end).copied()) {
                    if letters == 0 {
                        let argument = batch::argument(arguments, n).unwrap_or(&[]);
                        copy(batch::unquote(argument), expanded, &mut length)?;
                    } else {
                        copy(&line[at..=end], expanded, &mut length)?;
                    }
                    at = end + 1;
                    continue;
                }
            }
        }
        let Some(close) = line[at + 1..].iter().position(|&unit| unit == PERCENT) else {
            if batch.is_none() {
                copy(&[PERCENT], expanded, &mut length)?;
            }
            at += 1;
            continue;
        };
        let close = at + 1 + close;
        let name = &line[at + 1..close];
        if let Some((base, offset, count)) = substring(name) {
            if let Some(value) = variable(base, errorlevel, variables, &mut expanded[length..])? {
                let range = cut(value, offset, count);
                let kept = range.len();
                expanded.copy_within(length + range.start..length + range.end, length);
                length += kept;
                at = close + 1;
                continue;
            }
        }
        match variable(name, errorlevel, variables, &mut expanded[length..])? {
            Some(value) => {
                length += value;
                at = close + 1;
            }
            None if batch.is_some() => at = close + 1,
            None => {
                copy(&line[at..close], expanded, &mut length)?;
                at = close;
            }
        }
    }
    Ok(&expanded[..length])
}

/// A decimal number with an optional sign, the whole of `text`: None for anything else.
fn signed(text: &[u16]) -> Option<i64> {
    let (negative, digits) = match text.split_first() {
        Some((&unit, rest)) if unit == u16::from(b'-') => (true, rest),
        Some((&unit, rest)) if unit == u16::from(b'+') => (false, rest),
        _ => (false, text),
    };
    if digits.is_empty() {
        return None;
    }
    let mut value: i64 = 0;
    for &unit in digits {
        let digit = char::from_u32(u32::from(unit))?.to_digit(10)?;
        value = value.saturating_mul(10).saturating_add(i64::from(digit));
    }
    Some(if negative { -value } else { value })
}

/// A variable's name with a substring after it (`set /?`): `NAME:~offset` or
/// `NAME:~offset,count`, read as the name, the offset and the count (None for the rest of the
/// value). None for a name without one, or one whose numbers are not decimal.
pub fn substring(name: &[u16]) -> Option<(&[u16], i64, Option<i64>)> {
    let colon = name.iter().position(|&unit| unit == u16::from(b':'))?;
    let spec = name[colon + 1..].strip_prefix(&[u16::from(b'~')])?;
    let (offset, count) = match spec.iter().position(|&unit| unit == u16::from(b',')) {
        Some(comma) => (signed(&spec[..comma])?, Some(signed(&spec[comma + 1..])?)),
        None => (signed(spec)?, None),
    };
    Some((&name[..colon], offset, count))
}

/// The part of a value `length` units long that a substring keeps: from `offset` (counted from
/// the end when negative), `count` units (all but the last `-count` when negative, the rest
/// without one); what lies outside the value is left out.
pub fn cut(length: usize, offset: i64, count: Option<i64>) -> core::ops::Range<usize> {
    let whole = length as i64;
    let from_end = |n: i64| {
        if n < 0 {
            (whole + n).max(0)
        } else {
            n.min(whole)
        }
    };
    let start = from_end(offset);
    let end = match count {
        None => whole,
        Some(count) if count < 0 => (whole + count).max(start),
        Some(count) => start.saturating_add(count).min(whole),
    };
    start as usize..end.max(start) as usize
}

/// `units` appended to `buffer`'s first `length`: TooLong when they do not fit.
fn copy(units: &[u16], buffer: &mut [u16], length: &mut usize) -> Result<(), TooLong> {
    buffer
        .get_mut(*length..*length + units.len())
        .ok_or(TooLong)?
        .copy_from_slice(units);
    *length += units.len();
    Ok(())
}

/// `line` copied into `buffer` then a NUL, the command line CreateProcessW takes: None when it does
/// not fit.
pub fn command_line<'a>(line: &[u16], buffer: &'a mut [u16]) -> Option<&'a mut [u16]> {
    let command = buffer.get_mut(..line.len() + 1)?;
    command[..line.len()].copy_from_slice(line);
    command[line.len()] = 0;
    Some(command)
}

/// UTF-16 text, shown as it decodes: an unpaired surrogate as U+FFFD.
pub struct Text<'a>(pub &'a [u16]);

impl fmt::Display for Text<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for character in char::decode_utf16(self.0.iter().copied()) {
            fmt::Write::write_char(f, character.unwrap_or(char::REPLACEMENT_CHARACTER))?;
        }
        Ok(())
    }
}

/// The local time, as GetLocalTime gives it: what `$D` and `$T` show.
#[derive(Clone, Copy, Default)]
pub struct Time {
    pub year: u16,
    pub month: u16,
    /// 0 for Sunday to 6 for Saturday.
    pub weekday: u16,
    pub day: u16,
    pub hour: u16,
    pub minute: u16,
    pub second: u16,
    pub milliseconds: u16,
}

/// The days' names as the US short date shows them, from Sunday.
const WEEKDAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];

/// The date as `$D` (and `%DATE%`) show it in the US format: `Tue 11/03/2026`.
pub struct Date<'a>(pub &'a Time);

impl fmt::Display for Date<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let time = self.0;
        let weekday = WEEKDAYS
            .get(usize::from(time.weekday))
            .copied()
            .unwrap_or("???");
        write!(
            f,
            "{weekday} {:02}/{:02}/{:04}",
            time.month, time.day, time.year
        )
    }
}

/// The time as `$T` (and `%TIME%`) show it in the US format, to the hundredth: `18:31:59.12`,
/// an hour below 10 after a space (` 9:05:03.00`).
pub struct Clock<'a>(pub &'a Time);

impl fmt::Display for Clock<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let time = self.0;
        write!(
            f,
            "{:2}:{:02}:{:02}.{:02}",
            time.hour,
            time.minute,
            time.second,
            time.milliseconds / 10
        )
    }
}

/// The prompt: `text` (the PROMPT variable, or [`DEFAULT_PROMPT`]) with its `$` codes replaced, as
/// `prompt /?` lists them: `$A` &, `$B` |, `$C` (, `$D` the date, `$E` escape, `$F` ), `$G` >,
/// `$H` a backspace (the character before erased), `$L` <, `$N` the drive, `$P` the drive and
/// path, `$Q` =, `$S` a space, `$T` the time, `$V` the version, `$_` CR LF, `$$` $; and, with
/// command extensions, `$+` (one `+` per pushd level: none, as there is no pushd) and `$M` (the
/// remote name of a network drive: none). Any other code shows nothing, and neither does a `$`
/// that ends the text.
pub struct Prompt<'a> {
    pub text: &'a [u16],
    /// The current directory, empty when it cannot be read.
    pub directory: &'a [u16],
    pub time: &'a Time,
}

impl fmt::Display for Prompt<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut text = self.text;
        while !text.is_empty() {
            let literal = text
                .iter()
                .position(|&unit| unit == DOLLAR)
                .unwrap_or(text.len());
            Text(&text[..literal]).fmt(f)?;
            text = &text[literal..];
            let Some(&code) = text.get(1) else {
                break;
            };
            text = &text[2..];
            match u8::try_from(fold(code)).unwrap_or(0) {
                b'A' => f.write_str("&")?,
                b'B' => f.write_str("|")?,
                b'C' => f.write_str("(")?,
                b'D' => Date(self.time).fmt(f)?,
                b'E' => f.write_str("\u{1B}")?,
                b'F' => f.write_str(")")?,
                b'G' => f.write_str(">")?,
                b'H' => f.write_str("\u{8} \u{8}")?,
                b'L' => f.write_str("<")?,
                b'N' => Text(drive(self.directory)).fmt(f)?,
                b'P' => Text(self.directory).fmt(f)?,
                b'Q' => f.write_str("=")?,
                b'S' => f.write_str(" ")?,
                b'T' => Clock(self.time).fmt(f)?,
                b'V' => f.write_str(VERSION)?,
                b'_' => f.write_str("\r\n")?,
                b'$' => f.write_str("$")?,
                _ => {}
            }
        }
        Ok(())
    }
}

/// The drive letter a directory starts with (`C` of `C:\WINNT`): nothing for a path without one.
fn drive(directory: &[u16]) -> &[u16] {
    match directory {
        [letter, colon, ..] if *colon == u16::from(b':') => core::slice::from_ref(letter),
        _ => &[],
    }
}

/// What `echo` alone prints: echo's state.
pub struct EchoState(pub bool);

impl fmt::Display for EchoState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ECHO is {}.\r\n", if self.0 { "on" } else { "off" })
    }
}

/// What `set P` prints when no variable's name starts with P.
pub struct NotDefined<'a>(pub &'a [u16]);

impl fmt::Display for NotDefined<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Environment variable {} not defined\r\n", Text(self.0))
    }
}

/// What `type` prints before each file when it is given several: an empty line, the name as
/// given, then two empty lines.
pub struct TypeHeader<'a>(pub &'a [u16]);

impl fmt::Display for TypeHeader<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "\r\n{}\r\n\r\n\r\n", Text(self.0))
    }
}

/// What `type` prints after a file of several it could not read.
pub struct NotProcessed<'a>(pub &'a [u16]);

impl fmt::Display for NotProcessed<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Error occurred while processing: {}.\r\n", Text(self.0))
    }
}

/// What Windows 2000's cmd prints when no program goes by a command's word.
pub struct NotRecognized<'a>(pub &'a [u16]);

impl fmt::Display for NotRecognized<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "'{}' is not recognized as an internal or external command,\r\n\
             operable program or batch file.\r\n",
            Text(self.0)
        )
    }
}

/// What the shell prints when a program it found cannot be started (an image that is not a
/// Windows program, for one): the word and the Win32 error.
pub struct CannotRun<'a>(pub &'a [u16], pub u32);

impl fmt::Display for CannotRun<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "'{}' cannot be run (error {}).\r\n",
            Text(self.0),
            self.1
        )
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().collect()
    }

    fn narrow(units: &[u16]) -> String {
        String::from_utf16(units).unwrap()
    }

    #[test]
    fn a_line_loses_its_line_break_and_blanks() {
        assert_eq!(trim(&wide("  pwd \t\r\n")), wide("pwd"));
        assert_eq!(trim(&wide("pwd\r")), wide("pwd"));
        assert_eq!(trim(&wide("dir a b")), wide("dir a b"));
        assert_eq!(trim(&wide(" \r\n")), wide(""));
        assert_eq!(trim(&[]), wide(""));
    }

    #[test]
    fn an_empty_line_prompts_again() {
        assert_eq!(parse(&wide("\r\n")), Command::Empty);
        assert_eq!(parse(&wide("\t  \r\n")), Command::Empty);
        assert_eq!(parse(&wide(" @ \r\n")), Command::Empty);
    }

    #[test]
    fn exit_whatever_its_case() {
        assert_eq!(parse(&wide("exit\r\n")), Command::Exit(&[]));
        assert_eq!(parse(&wide("  EXIT\r\n")), Command::Exit(&[]));
        let argument = wide("/b 3");
        assert_eq!(parse(&wide("Exit  /b 3 \r\n")), Command::Exit(&argument));
    }

    #[test]
    fn rem_and_call() {
        assert_eq!(parse(&wide("rem a %x% b\r\n")), Command::Remark);
        assert_eq!(parse(&wide("@REM\r\n")), Command::Remark);
        let argument = wide("t.cmd a ");
        assert_eq!(parse(&wide("call  t.cmd a \r\n")), Command::Call(&argument));
        assert_eq!(parse(&wide("call\r\n")), Command::Call(&[]));
    }

    #[test]
    fn a_quoted_program_word_runs_to_its_closing_quote() {
        let line = wide("\"C:\\a b\\x.exe\" y");
        assert_eq!(
            parse(&line),
            Command::Run {
                line: &line,
                word: &wide("\"C:\\a b\\x.exe\"")
            }
        );
        let mut out = [0; 16];
        assert_eq!(
            program_name(&wide("\"C:\\a b\\x\""), &mut out),
            Some(&wide("C:\\a b\\x")[..])
        );
        assert_eq!(program_name(&wide("x"), &mut [0; 0]), None);
    }

    #[test]
    fn cd_and_chdir_with_and_without_a_path() {
        assert_eq!(parse(&wide("cd\r\n")), Command::ChangeDirectory(None));
        assert_eq!(parse(&wide("CHDIR   \r\n")), Command::ChangeDirectory(None));
        let path = wide("C:\\Program Files");
        assert_eq!(
            parse(&wide("Cd   C:\\Program Files  \r\n")),
            Command::ChangeDirectory(Some(&path))
        );
        assert_eq!(
            parse(&wide("chdir\t\\\r\n")),
            Command::ChangeDirectory(Some(&wide("\\")))
        );
    }

    #[test]
    fn a_built_in_word_ends_at_a_blank_or_a_delimiter() {
        let line = wide("cdrom");
        assert_eq!(
            parse(&wide("cdrom\r\n")),
            Command::Run {
                line: &line,
                word: &line
            }
        );
        let line = wide("exit.exe");
        assert_eq!(
            parse(&wide("exit.exe\r\n")),
            Command::Run {
                line: &line,
                word: &line
            }
        );
        assert_eq!(parse(&wide("ver;\r\n")), Command::Version);
        assert_eq!(parse(&wide("CLS x\r\n")), Command::ClearScreen);
    }

    #[test]
    fn anything_else_runs_its_first_word() {
        let line = wide("pwd  a\tb");
        assert_eq!(
            parse(&wide("  pwd  a\tb \r\n")),
            Command::Run {
                line: &line,
                word: &wide("pwd")
            }
        );
        let line = wide("a=b c");
        assert_eq!(
            parse(&wide("a=b c\r\n")),
            Command::Run {
                line: &line,
                word: &wide("a=b")
            }
        );
    }

    #[test]
    fn a_leading_at_goes() {
        let line = wide("pwd");
        assert_eq!(
            parse(&wide("@pwd\r\n")),
            Command::Run {
                line: &line,
                word: &line
            }
        );
        assert_eq!(parse(&wide(" @ @ echo off\r\n")), Command::Echo(Echo::Off));
    }

    #[test]
    fn a_non_ascii_word_is_no_built_in() {
        // U+0130 (İ) lowercases to "i" plus a combining dot: no ASCII match.
        let line = wide("\u{130}");
        assert_eq!(
            parse(&line),
            Command::Run {
                line: &line,
                word: &line
            }
        );
    }

    #[test]
    fn echo_alone_shows_its_state() {
        assert_eq!(parse(&wide("echo\r\n")), Command::Echo(Echo::Show));
        assert_eq!(parse(&wide("ECHO   \r\n")), Command::Echo(Echo::Show));
        assert_eq!(EchoState(true).to_string(), "ECHO is on.\r\n");
        assert_eq!(EchoState(false).to_string(), "ECHO is off.\r\n");
    }

    #[test]
    fn echo_on_and_off_whatever_their_case() {
        assert_eq!(parse(&wide("echo on\r\n")), Command::Echo(Echo::On));
        assert_eq!(parse(&wide("Echo  OFF \r\n")), Command::Echo(Echo::Off));
        let text = wide("on off");
        assert_eq!(
            parse(&wide("echo on off\r\n")),
            Command::Echo(Echo::Text(&text))
        );
    }

    #[test]
    fn echo_prints_what_follows_its_separator() {
        let text = wide(" a  b ");
        assert_eq!(
            parse(&wide("echo  a  b \r\n")),
            Command::Echo(Echo::Text(&text))
        );
        assert_eq!(parse(&wide("echo.\r\n")), Command::Echo(Echo::Text(&[])));
        let text = wide("hi");
        assert_eq!(
            parse(&wide("echo:hi\r\n")),
            Command::Echo(Echo::Text(&text))
        );
        assert_eq!(
            parse(&wide("echo(hi\r\n")),
            Command::Echo(Echo::Text(&text))
        );
        let text = wide("on");
        assert_eq!(
            parse(&wide("echo.on\r\n")),
            Command::Echo(Echo::Text(&text))
        );
        let line = wide("echox");
        assert_eq!(
            parse(&wide("echox\r\n")),
            Command::Run {
                line: &line,
                word: &line
            }
        );
    }

    #[test]
    fn set_keeps_its_argument_s_trailing_blanks() {
        assert_eq!(parse(&wide("set\r\n")), Command::Set(&[]));
        let argument = wide("X=a b  ");
        assert_eq!(parse(&wide("SET   X=a b  \r\n")), Command::Set(&argument));
    }

    #[test]
    fn set_s_forms() {
        assert_eq!(set(&[]), Set::Show(None));
        assert_eq!(set(&wide("  ")), Set::Show(None));
        let prefix = wide("P");
        assert_eq!(set(&wide("P  ")), Set::Show(Some(&prefix)));
        let (name, value) = (wide("X"), wide("a=b "));
        assert_eq!(
            set(&wide("X=a=b ")),
            Set::Assign {
                name: &name,
                value: &value
            }
        );
        assert_eq!(
            set(&wide("X=")),
            Set::Assign {
                name: &name,
                value: &[]
            }
        );
        let (name, value) = (wide("X "), wide(" 1"));
        assert_eq!(
            set(&wide("X = 1")),
            Set::Assign {
                name: &name,
                value: &value
            }
        );
        assert_eq!(set(&wide("=x")), Set::Incorrect);
    }

    #[test]
    fn set_s_quoted_form_ends_at_the_last_quote() {
        let (name, value) = (wide("X"), wide("a \"b\""));
        assert_eq!(
            set(&wide("\"X=a \"b\"\" junk")),
            Set::Assign {
                name: &name,
                value: &value
            }
        );
        let value = wide("1");
        assert_eq!(
            set(&wide("\"X=1")),
            Set::Assign {
                name: &name,
                value: &value
            }
        );
    }

    #[test]
    fn set_lists_by_prefix_and_never_a_drive_s_directory() {
        assert!(listed(&wide("PATH=C:\\"), None));
        assert!(!listed(&wide("=C:=C:\\"), None));
        assert!(listed(&wide("PATH=C:\\"), Some(&wide("pa"))));
        assert!(listed(&wide("PATH=C:\\"), Some(&wide("path"))));
        assert!(!listed(&wide("PATH=C:\\"), Some(&wide("pathe"))));
        assert!(!listed(&wide("PATH=C:\\"), Some(&wide("x"))));
        assert!(!listed(&wide("=C:=C:\\"), Some(&wide("=C"))));
        assert_eq!(
            NotDefined(&wide("P")).to_string(),
            "Environment variable P not defined\r\n"
        );
    }

    #[test]
    fn an_entry_s_value_by_its_name() {
        let entry = wide("Path=C:\\a=b");
        assert_eq!(value_of(&entry, &wide("PATH")), Some(&wide("C:\\a=b")[..]));
        assert_eq!(value_of(&entry, &wide("PAT")), None);
        assert_eq!(value_of(&entry, &wide("PATHS")), None);
        assert_eq!(value_of(&wide("Path="), &wide("path")), Some(&[][..]));
    }

    #[test]
    fn path_s_forms() {
        assert_eq!(parse(&wide("path\r\n")), Command::Path(None));
        let argument = wide(";");
        assert_eq!(parse(&wide("PATH ; \r\n")), Command::Path(Some(&argument)));
        assert!(clears_path(&argument));
        let argument = wide("C:\\a;C:\\b");
        assert_eq!(
            parse(&wide("path C:\\a;C:\\b\r\n")),
            Command::Path(Some(&argument))
        );
        assert_eq!(
            parse(&wide("path=C:\\a;C:\\b\r\n")),
            Command::Path(Some(&argument))
        );
        assert!(!clears_path(&argument));
    }

    #[test]
    fn prompt_s_forms() {
        assert_eq!(parse(&wide("prompt\r\n")), Command::Prompt(None));
        assert_eq!(parse(&wide("prompt  \r\n")), Command::Prompt(None));
        let argument = wide("$p$g ");
        assert_eq!(
            parse(&wide("PROMPT $p$g \r\n")),
            Command::Prompt(Some(&argument))
        );
        assert_eq!(
            parse(&wide("prompt=$p$g \r\n")),
            Command::Prompt(Some(&argument))
        );
    }

    #[test]
    fn type_s_names() {
        let names: Vec<String> = Names(&wide(" a.txt  \"b c.txt\" d")).map(narrow).collect();
        assert_eq!(names, ["a.txt", "b c.txt", "d"]);
        assert_eq!(Names(&wide("   ")).count(), 0);
        let names: Vec<String> = Names(&wide("\"open")).map(narrow).collect();
        assert_eq!(names, ["open"]);
        let argument = wide("a b");
        assert_eq!(parse(&wide("type a b\r\n")), Command::Type(&argument));
    }

    #[test]
    fn type_s_header_and_error() {
        assert_eq!(
            TypeHeader(&wide("a.txt")).to_string(),
            "\r\na.txt\r\n\r\n\r\n"
        );
        assert_eq!(
            NotProcessed(&wide("b")).to_string(),
            "Error occurred while processing: b.\r\n"
        );
        assert_eq!(message(2), Some(FILE_NOT_FOUND));
        assert_eq!(message(1), None);
    }

    /// An environment for the expansion's tests: names compared upper-cased.
    struct Fake {
        variables: BTreeMap<String, String>,
        directory: String,
    }

    impl Fake {
        fn new(variables: &[(&str, &str)]) -> Fake {
            Fake {
                variables: variables
                    .iter()
                    .map(|(name, value)| (name.to_uppercase(), value.to_string()))
                    .collect(),
                directory: "C:\\WINNT".to_string(),
            }
        }
    }

    fn put(text: &str, value: &mut [u16]) -> Result<usize, TooLong> {
        let units = wide(text);
        value
            .get_mut(..units.len())
            .ok_or(TooLong)?
            .copy_from_slice(&units);
        Ok(units.len())
    }

    impl Variables for Fake {
        fn get(&mut self, name: &[u16], value: &mut [u16]) -> Result<Option<usize>, TooLong> {
            match self.variables.get(&narrow(name).to_uppercase()) {
                Some(text) => put(text, value).map(Some),
                None => Ok(None),
            }
        }

        fn current_directory(&mut self, value: &mut [u16]) -> Result<usize, TooLong> {
            put(&self.directory.clone(), value)
        }

        fn time(&mut self) -> Time {
            TIME
        }

        fn random(&mut self) -> u16 {
            12345
        }

        fn command_line(&self) -> &[u16] {
            &COMMAND_LINE
        }
    }

    /// The shell's command line, as the fake environment gives it.
    const COMMAND_LINE: [u16; 3] = [b'c' as u16, b'm' as u16, b'd' as u16];

    fn expanded(line: &str, errorlevel: u32, fake: &mut Fake) -> Result<String, TooLong> {
        let mut buffer = [0; 64];
        expand(&wide(line), errorlevel, None, fake, &mut buffer).map(narrow)
    }

    /// `line` expanded in a batch whose arguments are `arguments`.
    fn in_batch(line: &str, arguments: &str, fake: &mut Fake) -> String {
        let mut buffer = [0; 64];
        narrow(expand(&wide(line), 7, Some(&wide(arguments)), fake, &mut buffer).unwrap())
    }

    #[test]
    fn a_batch_s_arguments() {
        let mut fake = Fake::new(&[]);
        let arguments = "t.cmd a \"b c\" d";
        assert_eq!(
            in_batch("%0|%1|%2|%3|%4|", arguments, &mut fake),
            "t.cmd|a|\"b c\"|d||"
        );
        assert_eq!(in_batch("[%*]", arguments, &mut fake), "[a \"b c\" d]");
        assert_eq!(in_batch("[%*]", "t", &mut fake), "[]");
        assert_eq!(in_batch("%~2 %~1", arguments, &mut fake), "b c a");
        assert_eq!(in_batch("%~dp0 %~x9", arguments, &mut fake), "%~dp0 %~x9");
    }

    #[test]
    fn in_a_batch_undefined_is_nothing_and_percent_percent_is_one() {
        let mut fake = Fake::new(&[("A", "1")]);
        assert_eq!(in_batch("[%NOPE%][%A%]", "t", &mut fake), "[][1]");
        assert_eq!(in_batch("50%% done", "t", &mut fake), "50% done");
        assert_eq!(in_batch("50%", "t", &mut fake), "50");
        assert_eq!(in_batch("50% off", "t", &mut fake), "50 off");
        assert_eq!(in_batch("%errorlevel%", "t", &mut fake), "7");
        assert_eq!(in_batch("%~", "t", &mut fake), "~");
    }

    #[test]
    fn the_other_dynamic_variables() {
        let mut fake = Fake::new(&[]);
        assert_eq!(
            expanded(
                "%date%|%TIME%|%random%|%CmdExtVersion%|%cmdcmdline%",
                0,
                &mut fake
            ),
            Ok("Tue 11/03/2026|18:31:59.12|12345|2|cmd".to_string())
        );
        let mut fake = Fake::new(&[("DATE", "d"), ("RANDOM", "r")]);
        assert_eq!(
            expanded("%date%%random%", 0, &mut fake),
            Ok("dr".to_string())
        );
    }

    #[test]
    fn a_variable_expands_whatever_its_case() {
        let mut fake = Fake::new(&[("F2KX", "hello")]);
        assert_eq!(
            expanded("echo %F2KX% %f2kx%!\r\n", 0, &mut fake),
            Ok("echo hello hello!\r\n".to_string())
        );
    }

    #[test]
    fn an_undefined_variable_and_a_lone_percent_stay() {
        let mut fake = Fake::new(&[("A", "1")]);
        assert_eq!(
            expanded("echo %NOPE% 50%", 0, &mut fake),
            Ok("echo %NOPE% 50%".to_string())
        );
        assert_eq!(expanded("%%", 0, &mut fake), Ok("%%".to_string()));
        // The undefined name's closing % opens the next variable.
        assert_eq!(expanded("%x%A%", 0, &mut fake), Ok("%x1".to_string()));
        assert_eq!(expanded("%A%%A%", 0, &mut fake), Ok("11".to_string()));
    }

    #[test]
    fn errorlevel_and_cd_are_dynamic() {
        let mut fake = Fake::new(&[]);
        assert_eq!(
            expanded("%ERRORLEVEL% %cd%", 9009, &mut fake),
            Ok("9009 C:\\WINNT".to_string())
        );
        assert_eq!(
            expanded("%errorlevel%", 0xC000_013A, &mut fake),
            Ok("-1073741510".to_string())
        );
        let mut fake = Fake::new(&[("ERRORLEVEL", "x"), ("CD", "y")]);
        assert_eq!(
            expanded("%ERRORLEVEL%%CD%", 1, &mut fake),
            Ok("xy".to_string())
        );
    }

    #[test]
    fn an_expansion_past_the_buffer_is_too_long() {
        let long = "v".repeat(60);
        let mut fake = Fake::new(&[("A", &long)]);
        assert_eq!(expanded("12345%A%", 0, &mut fake), Err(TooLong));
        assert_eq!(expanded(&"x".repeat(65), 0, &mut fake), Err(TooLong));
        assert_eq!(expanded("%errorlevel%", 1, &mut fake).unwrap(), "1");
    }

    /// Tuesday 3 November 2026, 18:31:59.123.
    const TIME: Time = Time {
        year: 2026,
        month: 11,
        weekday: 2,
        day: 3,
        hour: 18,
        minute: 31,
        second: 59,
        milliseconds: 123,
    };

    fn prompt(text: &str, directory: &str, time: &Time) -> String {
        Prompt {
            text: &wide(text),
            directory: &wide(directory),
            time,
        }
        .to_string()
    }

    #[test]
    fn the_default_prompt_is_the_directory_then_a_greater_than() {
        assert_eq!(
            prompt(DEFAULT_PROMPT, "C:\\WINNT\\system32", &TIME),
            "C:\\WINNT\\system32>"
        );
        assert_eq!(prompt(DEFAULT_PROMPT, "", &TIME), ">");
    }

    #[test]
    fn the_prompt_s_codes() {
        assert_eq!(
            prompt("$a$b$c$e$f$g$l$q$s$_$$$h", "C:\\", &TIME),
            "&|(\u{1B})><= \r\n$\u{8} \u{8}"
        );
        assert_eq!(prompt("$N:$p", "D:\\x", &TIME), "D:D:\\x");
        assert_eq!(prompt("$n", "\\\\server\\share", &TIME), "");
        assert_eq!(prompt("$v", "C:\\", &TIME), "F2K [Version 5.00.2195]");
        assert_eq!(prompt("$+$m", "C:\\", &TIME), "");
        assert_eq!(prompt("a$xb$", "C:\\", &TIME), "ab");
        assert_eq!(prompt("caf\u{e9} $G", "C:\\", &TIME), "caf\u{e9} >");
    }

    #[test]
    fn the_prompt_s_date_and_time_are_us() {
        assert_eq!(prompt("$D $T", "C:\\", &TIME), "Tue 11/03/2026 18:31:59.12");
        let morning = Time {
            hour: 9,
            minute: 5,
            second: 3,
            milliseconds: 7,
            weekday: 0,
            month: 1,
            day: 4,
            ..TIME
        };
        assert_eq!(
            prompt("$d$t", "C:\\", &morning),
            "Sun 01/04/2026 9:05:03.00"
        );
    }

    #[test]
    fn the_state_as_the_shell_starts() {
        let state = State::default();
        assert_eq!(
            (
                state.errorlevel,
                state.return_code,
                state.echo,
                state.spaced
            ),
            (0, 0, true, true)
        );
    }

    #[test]
    fn a_program_s_code_is_both_a_built_in_s_failure_is_1() {
        let mut state = State::default();
        state.ended(0xFFFF_FFFF);
        assert_eq!((state.errorlevel, state.return_code), (u32::MAX, u32::MAX));
        state.failed();
        assert_eq!((state.errorlevel, state.return_code), (1, 1));
    }

    #[test]
    fn which_built_ins_clear_the_errorlevel_when_they_succeed() {
        let clears = |line: &str, cmd_script| clears_errorlevel(&parse(&wide(line)), cmd_script);
        // batver: ERRORLEVEL 0 after ver; cd and type, as ver, whatever the script.
        for line in ["ver", "cd", "cd x", "type a"] {
            assert!(clears(line, false) && clears(line, true), "{line}");
        }
        // batset: ERRORLEVEL 1 before `set BATSX=3` in a .cmd script, 0 after; a .bat file and
        // the prompt keep it.
        for line in ["set X=3", "set X", "path x", "prompt $g"] {
            assert!(clears(line, true) && !clears(line, false), "{line}");
        }
        // batlevel: ERRORLEVEL 3 after an echo.
        for line in ["echo x", "echo", "rem x", "cls", "exit /b", "call x", "x"] {
            assert!(!clears(line, true) && !clears(line, false), "{line}");
        }
    }

    #[test]
    fn a_substring_s_name_offset_and_count() {
        let name = wide("CD");
        assert_eq!(substring(&wide("CD:~0,2")), Some((&name[..], 0, Some(2))));
        assert_eq!(substring(&wide("CD:~-10")), Some((&name[..], -10, None)));
        assert_eq!(
            substring(&wide("CD:~+1,-2")),
            Some((&name[..], 1, Some(-2)))
        );
        assert_eq!(substring(&wide("CD")), None);
        assert_eq!(substring(&wide("CD:a=b")), None);
        assert_eq!(substring(&wide("CD:~")), None);
        assert_eq!(substring(&wide("CD:~x")), None);
        assert_eq!(substring(&wide("CD:~1,")), None);
    }

    #[test]
    fn a_substring_s_part_of_the_value() {
        // `set /?`'s examples, on a value of 20 units.
        assert_eq!(cut(20, 10, Some(5)), 10..15);
        assert_eq!(cut(20, -10, None), 10..20);
        assert_eq!(cut(20, 0, Some(-2)), 0..18);
        assert_eq!(cut(20, 10, None), 10..20);
        // Past either end: what lies inside the value.
        assert_eq!(cut(20, 30, None), 20..20);
        assert_eq!(cut(20, -30, Some(3)), 0..3);
        assert_eq!(cut(20, 15, Some(10)), 15..20);
        assert_eq!(cut(20, 15, Some(-10)), 15..15);
        assert_eq!(cut(0, 0, Some(2)), 0..0);
    }

    #[test]
    fn a_substring_expands_at_the_prompt_and_in_a_batch() {
        let mut fake = Fake::new(&[("P", "abcdef")]);
        fake.directory = "Z:\\cmd\\batcd".to_string();
        // batcd: the drive's hidden variable's name from %CD:~0,2%.
        assert_eq!(expanded("=%CD:~0,2%", 0, &mut fake), Ok("=Z:".to_string()));
        assert_eq!(
            expanded("[%p:~1,3%][%P:~-2%][%P:~0,-1%]", 0, &mut fake),
            Ok("[bcd][ef][abcde]".to_string())
        );
        assert_eq!(
            in_batch("[%P:~2%][%errorlevel:~0,1%]", "t", &mut fake),
            "[cdef][7]"
        );
        // An undefined variable's substring: nothing in a batch, as typed at the prompt.
        assert_eq!(in_batch("[%NOPE:~0,2%]", "t", &mut fake), "[]");
        assert_eq!(
            expanded("[%NOPE:~0,2%]", 0, &mut fake),
            Ok("[%NOPE:~0,2%]".to_string())
        );
    }

    #[test]
    fn the_command_line_ends_with_a_nul() {
        let mut buffer = [0xFFFF; 8];
        let command = command_line(&wide("pwd x"), &mut buffer).unwrap();
        assert_eq!(command, wide("pwd x\0"));
        assert!(command_line(&wide("12345678"), &mut buffer).is_none());
        assert_eq!(
            command_line(&wide("1234567"), &mut buffer).unwrap().len(),
            8
        );
    }

    #[test]
    fn the_banner_names_f2k() {
        assert_eq!(BANNER, "F2K [Version 5.00.2195]\r\n");
        assert_eq!(BANNER, format!("{VERSION}\r\n"));
    }

    #[test]
    fn an_unknown_command_says_so_as_windows_does() {
        assert_eq!(
            NotRecognized(&wide("foo")).to_string(),
            "'foo' is not recognized as an internal or external command,\r\n\
             operable program or batch file.\r\n"
        );
    }

    #[test]
    fn a_program_that_cannot_run_shows_its_error() {
        assert_eq!(
            CannotRun(&wide("x"), 193).to_string(),
            "'x' cannot be run (error 193).\r\n"
        );
    }

    #[test]
    fn text_decodes_lossily() {
        assert_eq!(Text(&[u16::from(b'a'), 0xD800]).to_string(), "a\u{FFFD}");
    }
}
