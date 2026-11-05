//! cmd: F2K's command interpreter, Windows 2000's cmd.exe with its command extensions on. Started
//! with `/C` or `/K` (src/switches.rs) it runs a command line first; interactively it prompts as
//! the PROMPT variable says (`$P$G` without one) and reads lines from the console, or from the
//! file or pipe its standard input is. Each line has its `%NAME%` variables expanded, then is read
//! as src/syntax.rs says: commands joined by `&`, `&&`, `||` and `|`, groups in parentheses,
//! redirections. Each command either runs a built-in (`call`, `cd` or `chdir`, `cls`, `echo`,
//! `exit`, `path`, `prompt`, `rem`, `set`, `shift`, `type`, `ver`) or names a program, found as
//! cmd.exe finds one (src/search.rs): a Windows program is started and waited for, a batch file
//! (src/batch.rs) runs its lines in the shell. `if`, `for` and `goto` and its labels are the
//! batch language's control flow (src/flow/). The program (src/main.rs) makes the calls; this
//! library reads the lines and says what is printed.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

pub mod arith;
pub mod batch;
pub mod builtins;
pub mod flow;
pub mod help;
pub mod search;
pub mod switches;
pub mod syntax;

use core::fmt;

/// The longest command line, in characters: Windows 2000's, as Microsoft documents it (2,047 on
/// Windows 2000 and Windows NT 4.0, 8,191 from Windows XP on). A line typed, read or given to `/C`,
/// and a line once its variables are expanded, holds this many at most; a batch file's line is cut
/// there.
pub const MAX_LINE: usize = 2047;

/// The units a line read holds: [`MAX_LINE`], and its line break (CR LF).
pub const LINE: usize = MAX_LINE + 2;

/// The longest line a typed command line or `/C`'s string may expand to: Windows 2000 runs a `/C`
/// string that expands past [`MAX_LINE`] (batline's 2,048 characters), where a batch file's line
/// is too long. No capture shows a bound; this is Windows XP's documented line, 8,191 characters.
pub const MAX_COMMAND: usize = 8191;

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
    /// The directories `pushd` saved, for `popd`.
    pub directories: builtins::console::Directories,
    /// The path of the last program the shell found, and its length: what Windows 2000's cmd
    /// names as unexpected when a batch file's line expands past [`MAX_LINE`] (see
    /// [`syntax::FATAL`]).
    pub found: [u16; FOUND],
    pub found_length: usize,
}

/// The units [`State::found`] keeps: a path's.
pub const FOUND: usize = 260;

impl Default for State {
    /// The shell as it starts: echo on, ERRORLEVEL 0, the first prompt after an empty line (below
    /// the banner).
    fn default() -> Self {
        State {
            errorlevel: 0,
            return_code: 0,
            echo: true,
            spaced: true,
            directories: builtins::console::Directories::default(),
            found: [0; FOUND],
            found_length: 0,
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

    /// No program goes by a command's word: it returns 1, as Windows 2000's cmd's does (`cmd /c`
    /// of it ends with 1, and `call` of it leaves the ERRORLEVEL 1), and the ERRORLEVEL becomes
    /// [`NOT_RECOGNIZED`].
    pub fn not_recognized(&mut self) {
        self.return_code = 1;
        self.errorlevel = NOT_RECOGNIZED;
    }
}

/// Whether `command`, a built-in, sets the ERRORLEVEL to 0 when it succeeds (its failures set it
/// to 1). `cd`, `type` and `ver` always do; `set`, `path` and `prompt` do when the batch file run
/// from the prompt (or `/C`'s string) is named `.cmd` (`in_cmd_script`), whatever the batch files
/// it runs are named, and leave it at the prompt and under a `.bat` file, as Windows 2000's
/// documentation of the two extensions says and its cmd does (a `.bat` file called from a `.cmd`
/// one clears it); `echo`, `rem` and `cls` never touch it. Programs, `call` and `exit` set it
/// their own way.
pub fn clears_errorlevel(command: &Command<'_>, in_cmd_script: bool) -> bool {
    match command {
        Command::ChangeDirectory(_) | Command::Type(_) | Command::Version => true,
        Command::Set(_) | Command::Path(_) | Command::Prompt(_) => in_cmd_script,
        Command::Builtin(builtin) => builtin.clears_errorlevel(),
        _ => false,
    }
}

/// A line, read: what the shell does with it.
#[derive(Debug, PartialEq, Eq)]
pub enum Command<'a> {
    /// Nothing but blanks (and `@`): prompt again.
    Empty,
    /// `call`: the command its argument holds, expanded a second time; a batch file it names
    /// returns to the caller.
    Call(&'a [u16]),
    /// `exit`, its argument (see [`batch::exit`]): the shell ends, or with `/B` the batch.
    Exit(&'a [u16]),
    /// `goto`, its argument (see [`flow::label::goto`]): the batch file goes on at a label.
    Goto(&'a [u16]),
    /// `rem`: a remark, nothing done.
    Remark,
    /// `cd` or `chdir`: without an argument, print the current directory; with one, change to it
    /// (the quotes around it dropped).
    ChangeDirectory(Option<&'a [u16]>),
    /// `cls`: the screen cleared (its arguments ignored, but for a switch: see
    /// [`Command::Incorrect`]).
    ClearScreen,
    /// `shift`: a batch file's arguments from `%n` on move down one (`%n` takes `%n+1`'s value);
    /// `%*` stays.
    Shift(usize),
    /// A built-in whose arguments it refuses (`cd/`, `cls /x`, `shift /x`): `The syntax of the
    /// command is incorrect.`, and it fails.
    Incorrect,
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
    /// A file, console or clock built-in (see [`builtins`]).
    Builtin(builtins::Builtin<'a>),
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

/// The unit that separates a block's lines once they are read (see [`syntax`]): a line feed,
/// which no line read holds.
pub(crate) const LF: u16 = b'\n' as u16;

/// Whether `unit` separates words: a space or a tab, or the line feed between a block's lines.
pub(crate) fn is_blank(unit: u16) -> bool {
    unit == SPACE || unit == TAB || unit == LF
}

/// Whether `unit` separates words as cmd's delimiters do: a blank, `,`, `;` or `=`.
pub(crate) fn is_delimiter(unit: u16) -> bool {
    is_blank(unit) || unit == u16::from(b',') || unit == u16::from(b';') || unit == EQUALS
}

/// Whether `unit` ends a built-in command's word: a delimiter, or one of the characters Windows'
/// cmd splits its internal commands' names at, `+` `/` `[` `]` `(` and `.` `\` `:`, so that
/// `cd..`, `cd\` and `cd/` are `cd` and its argument.
pub(crate) fn ends_word(unit: u16) -> bool {
    is_delimiter(unit) || b"+/[](.\\:".iter().any(|&byte| unit == u16::from(byte))
}

/// Whether `unit`, outside quotes, ends a program's word: a delimiter, or `/` (`cmd/c` runs `cmd`
/// with `/c`, as Windows 2000's cmd reads it).
fn ends_program(unit: u16) -> bool {
    is_delimiter(unit) || unit == u16::from(b'/')
}

/// Whether `unit`, right after `echo`, separates it from its text: a blank, or one of the
/// characters Windows' cmd lets `echo` run into (`echo.`, `echo:`, `echo(`...), the one that is
/// not printed.
fn ends_echo(unit: u16) -> bool {
    is_blank(unit) || b".,;=:/\\([]+".iter().any(|&byte| unit == u16::from(byte))
}

/// `text` without its leading blanks.
pub fn skip_blanks(text: &[u16]) -> &[u16] {
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
pub fn without_break(line: &[u16]) -> &[u16] {
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
pub(crate) fn same_name(a: &[u16], b: &[u16]) -> bool {
    a.len() == b.len() && a.iter().zip(b).all(|(&a, &b)| fold(a) == fold(b))
}

/// Whether `word` is `name` (lowercase ASCII), ignoring case.
pub(crate) fn is_named(word: &[u16], name: &str) -> bool {
    word.len() == name.len()
        && word.iter().zip(name.bytes()).all(|(&unit, byte)| {
            u8::try_from(unit).is_ok_and(|unit| unit.to_ascii_lowercase() == byte)
        })
}

/// `line` without its leading blanks and `@`s (a batch file's line hides its echo with one).
pub(crate) fn command_start(line: &[u16]) -> &[u16] {
    let mut line = without_break(line);
    loop {
        line = skip_blanks(line);
        match line.split_first() {
            Some((&AT, rest)) => line = rest,
            _ => break,
        }
    }
    line
}

/// A line's command word as a built-in's is read ([`ends_word`]), and the rest of the line.
pub(crate) fn command_word(line: &[u16]) -> (&[u16], &[u16]) {
    let end = line
        .iter()
        .position(|&unit| ends_word(unit))
        .unwrap_or(line.len());
    line.split_at(end)
}

/// Whether some word of `argument`, outside quotes, starts with a switch's `/`: words are
/// separated by blanks and by `,` `;` `=`.
fn has_switch(argument: &[u16]) -> bool {
    let mut quoted = false;
    let mut start = true;
    for &unit in argument {
        if unit == QUOTE {
            quoted = !quoted;
        }
        if !quoted && start && unit == u16::from(b'/') {
            return true;
        }
        start = !quoted && is_delimiter(unit);
    }
    false
}

/// What a line read says to do, once expanded. Leading `@`s go (a batch file's line hides its
/// echo with one). The command word is the line's first: a built-in's ends at a delimiter or one
/// of the characters [`ends_word`] lists (`echo`'s at one of the characters it runs into), and
/// built-ins are recognized whatever their case; a program's word ends at a delimiter or a `/`
/// after its first character, outside quotes.
pub fn parse(line: &[u16]) -> Command<'_> {
    let line = command_start(line);
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
    let (word, rest) = command_word(line);
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
    if is_named(word, "goto") {
        return Command::Goto(argument);
    }
    if is_named(word, "shift") {
        return shift(trim_blanks(argument));
    }
    if is_named(word, "cd") || is_named(word, "chdir") {
        return change_directory(trim_blanks(argument));
    }
    if is_named(word, "cls") {
        // A switch it does not take (any, as `cls /x`) is refused; other words are ignored.
        if has_switch(argument) {
            return Command::Incorrect;
        }
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
    if let Some(builtin) = builtins::parse(word, argument) {
        return Command::Builtin(builtin);
    }
    let line = trim_end(line);
    let mut quoted = false;
    let word = &line[..line
        .iter()
        .enumerate()
        .position(|(at, &unit)| {
            if unit == QUOTE {
                quoted = !quoted;
            }
            !quoted && (is_blank(unit) || (at > 0 && ends_program(unit)))
        })
        .unwrap_or(line.len())];
    Command::Run { line, word }
}

/// `cd`'s argument read: none, a path (its quotes removed), or, after `/D` (which changes the
/// drive too, as changing the directory does here), a path; any other switch is refused (`cd/`).
fn change_directory(argument: &[u16]) -> Command<'_> {
    let mut argument = argument;
    if argument.first() == Some(&u16::from(b'/')) {
        let drive = argument.len() >= 2
            && fold(argument[1]) == u16::from(b'D')
            && argument.get(2).is_none_or(|&unit| is_blank(unit));
        if !drive {
            return Command::Incorrect;
        }
        argument = skip_blanks(&argument[2..]);
    }
    let argument = unquote(argument);
    Command::ChangeDirectory((!argument.is_empty()).then_some(argument))
}

/// `shift`'s argument read: none (or words, ignored) shifts from `%0`, `/n` (a digit from 0 to 8)
/// from `%n`; any other switch is refused.
fn shift(argument: &[u16]) -> Command<'_> {
    match argument {
        [slash, digit] if *slash == u16::from(b'/') => {
            match char::from_u32(u32::from(*digit)).and_then(|c| c.to_digit(10)) {
                Some(digit @ 0..=8) => Command::Shift(digit as usize),
                _ => Command::Incorrect,
            }
        }
        [slash, ..] if *slash == u16::from(b'/') => Command::Incorrect,
        _ => Command::Shift(0),
    }
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

/// `text` without the quotes around it: a leading quote and the last one after it go, the text
/// after that last quote too (`cd "C:\Program Files"`, as `cd /?` writes it).
fn unquote(text: &[u16]) -> &[u16] {
    match text.split_first() {
        Some((&QUOTE, rest)) => match rest.iter().rposition(|&unit| unit == QUOTE) {
            Some(last) => &rest[..last],
            None => rest,
        },
        _ => text,
    }
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
            if trim_end(argument).is_empty() {
                return Set::Show(None);
            }
            // A `/?` after the prefix goes, and what follows it; then the prefix loses one
            // trailing blank and keeps the others (`set X   ` lists no `X`, but `set X > nul`
            // lists it), as Windows 2000's set reads it.
            let help = argument.windows(3).position(|units| {
                is_blank(units[0]) && units[1] == u16::from(b'/') && units[2] == u16::from(b'?')
            });
            let prefix = match help {
                Some(blank) => &argument[..=blank],
                None => argument,
            };
            Set::Show(Some(match prefix.split_last() {
                Some((&last, rest)) if is_blank(last) => rest,
                _ => prefix,
            }))
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

    /// `name`'s full path, as GetFullPathNameW makes it, written to the start of `value`: its
    /// length, None when it cannot be made or does not fit.
    fn full_path(&mut self, name: &[u16], value: &mut [u16]) -> Option<usize>;

    /// The file or directory at `path`: its attributes and size, None when there is none.
    fn file(&mut self, path: &[u16]) -> Option<(u32, u64)>;

    /// The full path `path` with each long name in it replaced by its 8.3 name, as
    /// GetShortPathNameW makes it, written to the start of `value`: its length, None when nothing
    /// goes by `path` or it does not fit.
    fn short_path(&mut self, path: &[u16], value: &mut [u16]) -> Option<usize>;

    /// When the file or directory at `path` was last written, in local time: None when there is
    /// none.
    fn written(&mut self, path: &[u16]) -> Option<Time>;
}

/// A batch file's arguments, as its lines' expansion reads them.
#[derive(Clone, Copy)]
pub struct Arguments<'a> {
    /// The batch's name as typed, then what followed it on its line (see [`batch::argument`]).
    pub line: &'a [u16],
    /// Which argument `%0` to `%9` each stand for, as `shift` left them: `%n` is the argument
    /// `shifted[n]`.
    pub shifted: [usize; 10],
    /// The batch file's path, as it was found: what `%~0`'s modifiers read when its name was not
    /// quoted.
    pub path: &'a [u16],
}

impl<'a> Arguments<'a> {
    /// A batch file's arguments before any `shift`.
    pub fn new(line: &'a [u16], path: &'a [u16]) -> Self {
        Arguments {
            line,
            shifted: core::array::from_fn(|n| n),
            path,
        }
    }

    /// `%n`, quotes kept: None past the last argument.
    pub fn get(&self, n: usize) -> Option<&'a [u16]> {
        batch::argument(self.line, self.shifted[n])
    }

    /// `shift /n`: `%n` to `%8` take the next one's argument, and `%9` the one after it.
    pub fn shift(&mut self, from: usize) {
        for n in from..9 {
            self.shifted[n] = self.shifted[n + 1];
        }
        self.shifted[9] += 1;
    }
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
/// full path, its drive, path, name, extension, short name, attributes, time and size.
pub(crate) const MODIFIERS: &[u8] = b"fdpnxsatz";

/// The attributes `%~a1` shows, in its order, by their FILE_ATTRIBUTE_ bits: directory,
/// read-only, archive, hidden, system, compressed, offline, temporary, reparse point; a `-` for
/// each the file has not.
const ATTRIBUTES: [(u8, u32); 9] = [
    (b'd', 0x10),
    (b'r', 0x01),
    (b'a', 0x20),
    (b'h', 0x02),
    (b's', 0x04),
    (b'c', 0x800),
    (b'o', 0x1000),
    (b't', 0x100),
    (b'l', 0x400),
];

/// `line` with its variables expanded, in `expanded`, [`MAX_LINE`] units at most, its line break
/// aside: `%NAME%` becomes NAME's value (see [`variable`]; names compare whatever the case of
/// their letters), `%NAME:~n,m%` the part of its value [`substring`] and [`cut`] say, and
/// `%NAME:old=new%` its value with `old` replaced ([`replace`]).
///
/// Interactively (`batch` None), an undefined `%NAME%` keeps its `%` and name, its closing `%`
/// free to open the next variable, and a `%` without a closing one stays.
///
/// In a batch file (`batch` its arguments), `%0` to `%9` are its arguments (nothing past the
/// last), `%*` all of them after its name, `%~1` an argument without its quotes, and `%~f1` with
/// [`MODIFIERS`] the parts of its path ([`modified`]); `%%` is `%`; an undefined `%NAME%` is
/// nothing, an undefined `%NAME:...` loses `%NAME:` and the scan goes on after the colon, and a
/// `%` without a closing one goes.
///
/// TooLong when the expanded line does not fit `expanded`.
pub fn expand<'a>(
    line: &[u16],
    errorlevel: u32,
    batch: Option<&Arguments<'_>>,
    variables: &mut dyn Variables,
    expanded: &'a mut [u16],
) -> Result<&'a [u16], TooLong> {
    expand_within(line, MAX_LINE, errorlevel, batch, variables, expanded)
}

/// [`expand`], the expanded line `limit` units at most (its line break aside): [`MAX_LINE`] for a
/// batch file's line, [`MAX_COMMAND`] for a typed one or `/C`'s string.
pub fn expand_within<'a>(
    line: &[u16],
    limit: usize,
    errorlevel: u32,
    batch: Option<&Arguments<'_>>,
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
                copy(arguments.get(n).unwrap_or(&[]), expanded, &mut length)?;
                at += 2;
                continue;
            }
            if next == Some(u16::from(b'*')) {
                copy(batch::all(arguments.line), expanded, &mut length)?;
                at += 2;
                continue;
            }
            if next == Some(u16::from(b'~')) {
                let letters = &line[at + 2..];
                let letters = &letters[..letters
                    .iter()
                    .take_while(|&&unit| {
                        u8::try_from(unit).is_ok_and(|byte| MODIFIERS.contains(&byte))
                    })
                    .count()];
                let end = at + 2 + letters.len();
                if let Some(n) = digit(line.get(end).copied()) {
                    let argument = batch::unquote(arguments.get(n).unwrap_or(&[]));
                    if letters.is_empty() {
                        copy(argument, expanded, &mut length)?;
                    } else {
                        // `%0` unquoted is the batch file found, its extension included.
                        let quoted = arguments
                            .get(n)
                            .is_some_and(|text| text.first() == Some(&QUOTE));
                        let name = if n == 0 && !quoted && arguments.shifted[0] == 0 {
                            arguments.path
                        } else {
                            argument
                        };
                        length += modified(name, letters, variables, &mut expanded[length..])?;
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
        if let Some(colon) = name.iter().position(|&unit| unit == u16::from(b':')) {
            let (base, spec) = (&name[..colon], &name[colon + 1..]);
            let edited = spec.first() == Some(&u16::from(b'~')) || spec.contains(&EQUALS);
            if edited {
                match variable(base, errorlevel, variables, &mut expanded[length..])? {
                    Some(value) => {
                        length += edit(name, colon, value, &mut expanded[length..])?;
                        at = close + 1;
                        continue;
                    }
                    None if batch.is_some() => {
                        // `%NAME:` goes; what follows the colon is read on.
                        at += 1 + colon + 1;
                        continue;
                    }
                    None => {}
                }
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
    if without_break(&expanded[..length]).len() > limit {
        return Err(TooLong);
    }
    Ok(&expanded[..length])
}

/// A variable's value, at the start of `buffer` and `length` units long, edited as `name` (the
/// text between its `%`s, its colon at `colon`) says: `~offset,count` keeps the part [`cut`]
/// says, and `old=new` replaces `old` ([`replace`]). A substring whose numbers cannot be read
/// gives `name` itself, as Windows 2000's cmd expands it. The units the result holds.
fn edit(name: &[u16], colon: usize, length: usize, buffer: &mut [u16]) -> Result<usize, TooLong> {
    let spec = &name[colon + 1..];
    if spec.first() == Some(&u16::from(b'~')) {
        return Ok(match offsets(&spec[1..]) {
            Some((offset, count)) => {
                let range = cut(length, offset, count);
                buffer.copy_within(range.clone(), 0);
                range.len()
            }
            None => {
                let mut written = 0;
                copy(name, buffer, &mut written)?;
                written
            }
        });
    }
    let equals = spec
        .iter()
        .position(|&unit| unit == EQUALS)
        .unwrap_or(spec.len());
    let new = spec.get(equals + 1..).unwrap_or(&[]);
    replace(&spec[..equals], new, length, buffer)
}

/// `%NAME:old=new%`'s value, from the value at the start of `buffer` (`length` units): every
/// `old` replaced by `new`, whatever the case of their ASCII letters; `*old` replaces everything
/// up to the first `old`, that `old` included. An empty `old` changes nothing. The units the
/// result holds.
#[inline(never)]
fn replace(old: &[u16], new: &[u16], length: usize, buffer: &mut [u16]) -> Result<usize, TooLong> {
    let mut value = [0; LINE];
    let value = value.get_mut(..length).ok_or(TooLong)?;
    value.copy_from_slice(&buffer[..length]);
    let (old, first) = match old.split_first() {
        Some((&star, rest)) if star == u16::from(b'*') => (rest, true),
        _ => (old, false),
    };
    if old.is_empty() {
        return Ok(length);
    }
    let matches = |at: usize| {
        value
            .get(at..at + old.len())
            .is_some_and(|text| same_name(text, old))
    };
    let mut written = 0;
    let mut at = 0;
    if first {
        if let Some(found) = (0..length).find(|&at| matches(at)) {
            copy(new, buffer, &mut written)?;
            at = found + old.len();
        }
    } else {
        while at < length {
            if matches(at) {
                copy(new, buffer, &mut written)?;
                at += old.len();
            } else {
                copy(&value[at..at + 1], buffer, &mut written)?;
                at += 1;
            }
        }
    }
    copy(&value[at..], buffer, &mut written)?;
    Ok(written)
}

/// A batch argument's `%~` modifiers applied to `name` (the argument without its quotes), in
/// `value`, in the order of the directory-listing line `for /?`'s `%~ftzaI` shows: the attributes
/// (`a`), last write's date and time (`t`, as [`Written`] shows them) and size (`z`) of the file
/// it names, then the parts of its full path (`f` all of it, else `d` its drive, `p` its
/// directory, `n` its name, `x` its extension, in that order), separated by blanks. With `s` the
/// parts are those of its short path ([`short_path`]), all of it when no other letter picks a
/// part. The attributes, time and size are left out for a name that names nothing. An empty
/// argument gives nothing. The units written.
#[inline(never)]
pub(crate) fn modified(
    name: &[u16],
    letters: &[u16],
    variables: &mut dyn Variables,
    value: &mut [u16],
) -> Result<usize, TooLong> {
    if name.is_empty() {
        return Ok(0);
    }
    let has = |letter: u8| letters.contains(&u16::from(letter));
    let mut full = [0; MAX_LINE];
    let full = match variables.full_path(name, &mut full) {
        Some(length) => &full[..length],
        None => name,
    };
    let file = variables.file(full);
    let mut length = 0;
    let gap = |length: &mut usize, value: &mut [u16]| {
        if *length > 0 {
            copy(&[SPACE], value, length)
        } else {
            Ok(())
        }
    };
    if let (true, Some((attributes, _))) = (has(b'a'), file) {
        for (letter, bit) in ATTRIBUTES {
            let shown = if attributes & bit != 0 { letter } else { b'-' };
            copy(&[u16::from(shown)], value, &mut length)?;
        }
    }
    let written = if has(b't') {
        file.and_then(|_| variables.written(full))
    } else {
        None
    };
    if let Some(time) = written {
        gap(&mut length, value)?;
        length += format(&mut value[length..], format_args!("{}", Written(&time)))?;
    }
    if let (true, Some((_, size))) = (has(b'z'), file) {
        gap(&mut length, value)?;
        length += format(&mut value[length..], format_args!("{size}"))?;
    }
    let mut short = [0; MAX_LINE];
    let path = if has(b's') {
        short_path(full, variables, &mut short)
    } else {
        full
    };
    let (drive, directory, stem, extension) = path_parts(path);
    let parts = [
        (b'd', drive),
        (b'p', directory),
        (b'n', stem),
        (b'x', extension),
    ];
    let picked = parts.iter().any(|&(letter, _)| has(letter));
    let whole = has(b'f') || (has(b's') && !picked);
    if picked || whole {
        gap(&mut length, value)?;
        for (letter, part) in parts {
            if whole || has(letter) {
                copy(part, value, &mut length)?;
            }
        }
    }
    Ok(length)
}

/// `%~s`'s path: the full path `full` with each long name in it replaced by its 8.3 name
/// ([`Variables::short_path`]), in `buffer`; `full` itself when the short path cannot be made
/// (nothing goes by it).
fn short_path<'a>(
    full: &'a [u16],
    variables: &mut dyn Variables,
    buffer: &'a mut [u16],
) -> &'a [u16] {
    match variables.short_path(full, buffer) {
        Some(length) => &buffer[..length],
        None => full,
    }
}

/// A file's last write as `%~t1` shows it, the US short date then the time on a 12-hour clock
/// without seconds, as `time /t` shows it: `11/04/2026 06:31 PM`.
pub struct Written<'a>(pub &'a Time);

impl fmt::Display for Written<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let time = self.0;
        let hour = match time.hour % 12 {
            0 => 12,
            hour => hour,
        };
        let half = if time.hour < 12 { "AM" } else { "PM" };
        write!(
            f,
            "{:02}/{:02}/{:04} {hour:02}:{:02} {half}",
            time.month, time.day, time.year, time.minute
        )
    }
}

/// A full path's drive (`C:`), directory (`\WINNT\`), name and extension (`.exe`, its dot
/// included; none without a dot in the last component).
fn path_parts(path: &[u16]) -> (&[u16], &[u16], &[u16], &[u16]) {
    let drive = match path {
        [_, colon, ..] if *colon == u16::from(b':') => 2,
        _ => 0,
    };
    let name = path
        .iter()
        .rposition(|&unit| unit == u16::from(b'\\') || unit == u16::from(b'/'))
        .map_or(drive, |separator| separator + 1)
        .max(drive);
    let dot = path[name..]
        .iter()
        .rposition(|&unit| unit == u16::from(b'.'))
        .map_or(path.len(), |dot| name + dot);
    (
        &path[..drive],
        &path[drive..name],
        &path[name..dot],
        &path[dot..],
    )
}

/// A number as C's `strtol` reads it with base 0, at the start of `text`: an optional sign, then
/// `0x` and hexadecimal digits, `0` and octal digits, or decimal digits. The number and the text
/// after it; None without a digit.
pub(crate) fn number(text: &[u16]) -> Option<(i64, &[u16])> {
    let (negative, text) = match text.split_first() {
        Some((&unit, rest)) if unit == u16::from(b'-') => (true, rest),
        Some((&unit, rest)) if unit == u16::from(b'+') => (false, rest),
        _ => (false, text),
    };
    let zero = u16::from(b'0');
    let (radix, digits) = match text {
        [first, x, rest @ ..]
            if *first == zero
                && fold(*x) == u16::from(b'X')
                && rest
                    .first()
                    .is_some_and(|&unit| hex_digit(unit, 16).is_some()) =>
        {
            (16, rest)
        }
        [first, ..] if *first == zero => (8, text),
        _ => (10, text),
    };
    let count = digits
        .iter()
        .take_while(|&&unit| hex_digit(unit, radix).is_some())
        .count();
    if count == 0 {
        return None;
    }
    let mut value: i64 = 0;
    for &unit in &digits[..count] {
        let digit = i64::from(hex_digit(unit, radix)?);
        value = value.saturating_mul(i64::from(radix)).saturating_add(digit);
    }
    Some((if negative { -value } else { value }, &digits[count..]))
}

/// `unit`'s value as a digit of `radix`: None for no such digit.
fn hex_digit(unit: u16, radix: u32) -> Option<u32> {
    char::from_u32(u32::from(unit))?.to_digit(radix)
}

/// A substring's numbers, the text after its `~`: `offset` or `offset,count`, each as
/// [`number`] reads it, nothing after them; None when they cannot be read.
fn offsets(spec: &[u16]) -> Option<(i64, Option<i64>)> {
    let (offset, rest) = number(spec)?;
    match rest.split_first() {
        None => Some((offset, None)),
        Some((&comma, rest)) if comma == u16::from(b',') => match number(rest)? {
            (count, []) => Some((offset, Some(count))),
            _ => None,
        },
        _ => None,
    }
}

/// A variable's name with a substring after it (`set /?`): `NAME:~offset` or
/// `NAME:~offset,count`, read as the name, the offset and the count (None for the rest of the
/// value), the numbers as [`number`] reads them. None for a name without one, or one whose numbers
/// cannot be read.
pub fn substring(name: &[u16]) -> Option<(&[u16], i64, Option<i64>)> {
    let colon = name.iter().position(|&unit| unit == u16::from(b':'))?;
    let spec = name[colon + 1..].strip_prefix(&[u16::from(b'~')])?;
    let (offset, count) = offsets(spec)?;
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
pub(crate) fn copy(units: &[u16], buffer: &mut [u16], length: &mut usize) -> Result<(), TooLong> {
    buffer
        .get_mut(*length..*length + units.len())
        .ok_or(TooLong)?
        .copy_from_slice(units);
    *length += units.len();
    Ok(())
}

/// `line`, which starts with the program's `word`, copied into `buffer` then a NUL, the command
/// line CreateProcessW takes: a blank goes between the word and what follows it when the word
/// ended at another delimiter (`x,a` runs `x` with `x ,a`), as Windows 2000's cmd hands it on.
/// None when it does not fit.
pub fn command_line<'a>(
    line: &[u16],
    word: &[u16],
    buffer: &'a mut [u16],
) -> Option<&'a mut [u16]> {
    let (word, rest) = line.split_at(word.len().min(line.len()));
    let blank = rest.first().is_some_and(|&unit| !is_blank(unit));
    let length = line.len() + usize::from(blank);
    let command = buffer.get_mut(..length + 1)?;
    command[..word.len()].copy_from_slice(word);
    if blank {
        command[word.len()] = SPACE;
    }
    command[length - rest.len()..length].copy_from_slice(rest);
    command[length] = 0;
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
/// command extensions, `$+` (one `+` per directory `pushd` saved) and `$M` (the
/// remote name of a network drive: none). Any other code ends the prompt, what follows it not
/// shown; a `$` that ends the text shows nothing.
pub struct Prompt<'a> {
    pub text: &'a [u16],
    /// The current directory, empty when it cannot be read.
    pub directory: &'a [u16],
    pub time: &'a Time,
    /// How many directories `pushd` saved: `$+` shows a `+` for each.
    pub depth: usize,
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
                b'+' => (0..self.depth).try_for_each(|_| f.write_str("+"))?,
                // An unknown code ends the prompt: what follows it is not shown.
                _ => break,
            }
        }
        Ok(())
    }
}

/// The name of the hidden variable that keeps the current directory of `directory`'s drive: `=`,
/// the drive's letter upper-cased, `:` (`=C:` for `c:\x`). None for a path without a drive (a UNC
/// path).
pub fn drive_variable(directory: &[u16]) -> Option<[u16; 3]> {
    match directory {
        [letter, colon, ..] if *colon == u16::from(b':') && *letter < 0x80 => {
            let letter = (*letter as u8).to_ascii_uppercase();
            letter
                .is_ascii_alphabetic()
                .then_some([EQUALS, u16::from(letter), *colon])
        }
        _ => None,
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
        // The quotes around the path go.
        assert_eq!(
            parse(&wide("cd \"C:\\Program Files\" \r\n")),
            Command::ChangeDirectory(Some(&path))
        );
        assert_eq!(
            parse(&wide("cd \"C:\\Program Files")),
            Command::ChangeDirectory(Some(&path))
        );
        assert_eq!(parse(&wide("cd \"\"")), Command::ChangeDirectory(None));
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
        assert_eq!(parse(&wide("ver;\r\n")), Command::Version);
        assert_eq!(parse(&wide("CLS x\r\n")), Command::ClearScreen);
        // And at the characters Windows' cmd splits its internal commands' names at.
        let (up, root) = (wide(".."), wide("\\"));
        assert_eq!(parse(&wide("cd..")), Command::ChangeDirectory(Some(&up)));
        assert_eq!(parse(&wide("cd\\")), Command::ChangeDirectory(Some(&root)));
        assert_eq!(parse(&wide("cd/")), Command::Incorrect);
        assert_eq!(parse(&wide("exit.exe")), Command::Exit(&wide(".exe")));
        assert_eq!(parse(&wide("ver+")), Command::Version);
        assert_eq!(parse(&wide("ver(")), Command::Version);
        assert_eq!(parse(&wide("ver:")), Command::Version);
    }

    #[test]
    fn cd_s_switches() {
        let path = wide("D:\\x");
        assert_eq!(
            parse(&wide("cd /d D:\\x")),
            Command::ChangeDirectory(Some(&path))
        );
        assert_eq!(
            parse(&wide("cd /D \"D:\\x\"")),
            Command::ChangeDirectory(Some(&path))
        );
        assert_eq!(parse(&wide("cd /d")), Command::ChangeDirectory(None));
        assert_eq!(parse(&wide("cd /x")), Command::Incorrect);
        assert_eq!(parse(&wide("cd /dx")), Command::Incorrect);
    }

    #[test]
    fn cls_refuses_a_switch_and_ignores_a_word() {
        assert_eq!(parse(&wide("cls /x")), Command::Incorrect);
        assert_eq!(parse(&wide("cls a,/x")), Command::Incorrect);
        assert_eq!(parse(&wide("cls foo")), Command::ClearScreen);
        assert_eq!(parse(&wide("cls a/x")), Command::ClearScreen);
        assert_eq!(parse(&wide("cls \"/x\"")), Command::ClearScreen);
    }

    #[test]
    fn shift_s_forms() {
        assert_eq!(parse(&wide("shift")), Command::Shift(0));
        assert_eq!(parse(&wide("SHIFT /3")), Command::Shift(3));
        assert_eq!(parse(&wide("shift x")), Command::Shift(0));
        assert_eq!(parse(&wide("shift /9")), Command::Incorrect);
        assert_eq!(parse(&wide("shift /x")), Command::Incorrect);
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
        // A program's word ends at a delimiter, and at a `/` after its first character, outside
        // quotes.
        for (text, word) in [
            ("a=b c", "a"),
            ("spawnkid,one", "spawnkid"),
            ("x;y", "x"),
            ("cmd/c x", "cmd"),
            ("/? x", "/?"),
            ("\"a,b/c\" d", "\"a,b/c\""),
            ("\"spawn\"kid exit 2", "\"spawn\"kid"),
        ] {
            let line = wide(text);
            assert_eq!(
                parse(&line),
                Command::Run {
                    line: &line,
                    word: &wide(word)
                },
                "{text}"
            );
        }
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
        // The prefix loses one trailing blank and keeps the others, and a `/?` after it goes.
        let prefix = wide("P  ");
        assert_eq!(set(&wide("P   ")), Set::Show(Some(&prefix)));
        let prefix = wide("P");
        assert_eq!(set(&wide("P ")), Set::Show(Some(&prefix)));
        assert_eq!(set(&wide("P /?")), Set::Show(Some(&prefix)));
        assert_eq!(set(&wide("P /?x y")), Set::Show(Some(&prefix)));
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

    /// An environment for the expansion's tests: names compared upper-cased, and files by their
    /// full paths, upper-cased, with their attributes and sizes (each last written at [`TIME`]),
    /// and their short paths.
    struct Fake {
        variables: BTreeMap<String, String>,
        directory: String,
        files: BTreeMap<String, (u32, u64)>,
        short: BTreeMap<String, String>,
    }

    impl Fake {
        fn new(variables: &[(&str, &str)]) -> Fake {
            Fake {
                variables: variables
                    .iter()
                    .map(|(name, value)| (name.to_uppercase(), value.to_string()))
                    .collect(),
                directory: "C:\\WINNT".to_string(),
                files: BTreeMap::new(),
                short: BTreeMap::new(),
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

        fn full_path(&mut self, name: &[u16], value: &mut [u16]) -> Option<usize> {
            let name = narrow(name);
            let full = if name.get(1..2) == Some(":") {
                name
            } else {
                format!("{}\\{name}", self.directory)
            };
            put(&full, value).ok()
        }

        fn file(&mut self, path: &[u16]) -> Option<(u32, u64)> {
            self.files.get(&narrow(path).to_uppercase()).copied()
        }

        fn short_path(&mut self, path: &[u16], value: &mut [u16]) -> Option<usize> {
            let short = self.short.get(&narrow(path).to_uppercase())?;
            put(short, value).ok()
        }

        fn written(&mut self, path: &[u16]) -> Option<Time> {
            self.file(path).map(|_| TIME)
        }
    }

    /// The shell's command line, as the fake environment gives it.
    const COMMAND_LINE: [u16; 3] = [b'c' as u16, b'm' as u16, b'd' as u16];

    fn expanded(line: &str, errorlevel: u32, fake: &mut Fake) -> Result<String, TooLong> {
        let mut buffer = [0; 64];
        expand(&wide(line), errorlevel, None, fake, &mut buffer).map(narrow)
    }

    /// `line` expanded in a batch whose arguments are `arguments`, found as `C:\\D\\t.cmd`.
    fn in_batch(line: &str, arguments: &str, fake: &mut Fake) -> String {
        let arguments = wide(arguments);
        let path = wide("C:\\D\\t.cmd");
        in_shifted_batch(line, Arguments::new(&arguments, &path), fake)
    }

    /// `line` expanded in a batch whose arguments are `arguments`.
    fn in_shifted_batch(line: &str, arguments: Arguments<'_>, fake: &mut Fake) -> String {
        let mut buffer = [0; 128];
        narrow(expand(&wide(line), 7, Some(&arguments), fake, &mut buffer).unwrap())
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
    }

    #[test]
    fn a_batch_argument_s_modifiers() {
        let mut fake = Fake::new(&[]);
        fake.files
            .insert("C:\\WINNT\\A.TXT".to_string(), (0x21, 42));
        let arguments = "t \"a.txt\" b.c.d e";
        assert_eq!(
            in_batch("[%~f1][%~d1][%~p1][%~n1][%~x1]", arguments, &mut fake),
            "[C:\\WINNT\\a.txt][C:][\\WINNT\\][a][.txt]"
        );
        assert_eq!(
            in_batch("[%~nx2][%~xn2][%~n3%~x3]", arguments, &mut fake),
            "[b.c.d][b.c.d][e]"
        );
        // The attributes and size of a file there is; nothing of them for one there is not.
        assert_eq!(
            in_batch("[%~a1][%~z1]", arguments, &mut fake),
            "[-ra------][42]"
        );
        assert_eq!(
            in_batch("[%~zanx1][%~az2][%~z4]", arguments, &mut fake),
            "[-ra------ 42 a.txt][][]"
        );
        // %0 not quoted is the batch file found; quoted, its name as typed.
        assert_eq!(
            in_batch("[%~nx0][%~x0][%~dp0]", arguments, &mut fake),
            "[t.cmd][.cmd][C:\\D\\]"
        );
        assert_eq!(in_batch("[%~nx0][%~x0]", "\"t\" x", &mut fake), "[t][]");
    }

    #[test]
    fn s_reads_the_short_path_and_t_the_last_write() {
        let mut fake = Fake::new(&[]);
        fake.files.insert(
            "C:\\WINNT\\LONG NAME\\A LONG FILE.TEXT".to_string(),
            (0x20, 7),
        );
        fake.short.insert(
            "C:\\WINNT\\LONG NAME\\A LONG FILE.TEXT".to_string(),
            "C:\\WINNT\\LONGNA~1\\ALONGF~1.TEX".to_string(),
        );
        let arguments = "t \"long name\\a long file.text\" missing.txt";
        // `s` alone is the whole short path; with part letters, those parts of it.
        assert_eq!(
            in_batch("[%~s1][%~sf1][%~fs1]", arguments, &mut fake),
            "[C:\\WINNT\\LONGNA~1\\ALONGF~1.TEX][C:\\WINNT\\LONGNA~1\\ALONGF~1.TEX]\
             [C:\\WINNT\\LONGNA~1\\ALONGF~1.TEX]"
        );
        assert_eq!(
            in_batch("[%~snx1][%~sp1][%~sd1][%~nx1]", arguments, &mut fake),
            "[ALONGF~1.TEX][\\WINNT\\LONGNA~1\\][C:][a long file.text]"
        );
        // A name with no short path (nothing goes by it) keeps its full path.
        assert_eq!(
            in_batch("[%~s2][%~snx2]", arguments, &mut fake),
            "[C:\\WINNT\\missing.txt][missing.txt]"
        );
        // The last write as `11/03/2026 06:31 PM`, in the directory-listing order with the
        // attributes, the size and the path; nothing of it for a file there is not.
        assert_eq!(
            in_batch("[%~t1][%~t2]", arguments, &mut fake),
            "[11/03/2026 06:31 PM][]"
        );
        assert_eq!(
            in_batch("[%~ftza1]", arguments, &mut fake),
            "[--a------ 11/03/2026 06:31 PM 7 C:\\WINNT\\long name\\a long file.text]"
        );
        assert_eq!(
            in_batch("[%~tsnx1][%~tnx2]", arguments, &mut fake),
            "[11/03/2026 06:31 PM ALONGF~1.TEX][missing.txt]"
        );
    }

    #[test]
    fn written_is_the_us_date_and_a_twelve_hour_clock() {
        let at = |hour, minute| {
            let time = Time {
                year: 2026,
                month: 1,
                day: 9,
                hour,
                minute,
                ..TIME
            };
            Written(&time).to_string()
        };
        assert_eq!(at(0, 5), "01/09/2026 12:05 AM");
        assert_eq!(at(9, 30), "01/09/2026 09:30 AM");
        assert_eq!(at(12, 0), "01/09/2026 12:00 PM");
        assert_eq!(at(23, 59), "01/09/2026 11:59 PM");
    }

    #[test]
    fn shift_moves_the_arguments_down() {
        let mut fake = Fake::new(&[]);
        let line = wide("t a b c d e f g h i j k");
        let path = wide("C:\\D\\t.cmd");
        let mut arguments = Arguments::new(&line, &path);
        arguments.shift(0);
        assert_eq!(
            in_shifted_batch("[%0][%1][%9][%*]", arguments, &mut fake),
            "[a][b][j][a b c d e f g h i j k]"
        );
        let mut arguments = Arguments::new(&line, &path);
        arguments.shift(2);
        assert_eq!(
            in_shifted_batch("[%0][%1][%2][%9]", arguments, &mut fake),
            "[t][a][c][j]"
        );
        // Shifted, %0's modifiers read the argument it now is.
        let mut arguments = Arguments::new(&line, &path);
        arguments.shift(0);
        assert_eq!(
            in_shifted_batch("[%~f0]", arguments, &mut fake),
            "[C:\\WINNT\\a]"
        );
    }

    #[test]
    fn percent_star_keeps_the_separators_after_the_name_s_blanks() {
        let mut fake = Fake::new(&[]);
        assert_eq!(in_batch("[%*]", "t.cmd ,;x y", &mut fake), "[,;x y]");
        assert_eq!(in_batch("[%1][%2]", "t.cmd ,;x y", &mut fake), "[x][y]");
    }

    #[test]
    fn a_value_s_replacements() {
        let mut fake = Fake::new(&[("S", "one two three")]);
        assert_eq!(
            in_batch("[%S:two=2%][%S:ONE=1%][%S:*two=X%][%S:o=%]", "t", &mut fake),
            "[one 2 three][1 two three][X three][ne tw three]"
        );
        assert_eq!(
            expanded("[%S:e=EE%][%S:=x%]", 0, &mut fake),
            Ok("[onEE two thrEEEE][one two three]".to_string())
        );
        assert_eq!(
            expanded("[%S:*zz=x%]", 0, &mut fake),
            Ok("[one two three]".to_string())
        );
        // A hidden variable whose name ends with a colon still expands whole.
        let mut fake = Fake::new(&[("=C:", "C:\\x")]);
        assert_eq!(expanded("%=C:%", 0, &mut fake), Ok("C:\\x".to_string()));
    }

    #[test]
    fn substrings_at_the_value_s_edges_and_malformed() {
        let mut fake = Fake::new(&[("S", "one two three")]);
        assert_eq!(
            in_batch(
                "[%S:~0,0%][%S:~-100%][%S:~5,-100%][%S:~100%][%S:~-100,3%]",
                "t",
                &mut fake
            ),
            "[][one two three][][][one]"
        );
        // Numbers as strtol reads them, base 0; others leave the name between the percents.
        assert_eq!(
            in_batch("[%S:~0x4%][%S:~010%]", "t", &mut fake),
            "[two three][three]"
        );
        assert_eq!(
            in_batch("[%S:~a%][%S:~4x%][%S:~1,%]", "t", &mut fake),
            "[S:~a][S:~4x][S:~1,]"
        );
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
    fn an_expansion_past_the_longest_line_is_too_long() {
        let mut fake = Fake::new(&[]);
        let mut buffer = [0; LINE];
        let line = wide(&"x".repeat(MAX_LINE));
        assert!(expand(&line, 0, None, &mut fake, &mut buffer).is_ok());
        let mut with_break = line.clone();
        with_break.extend(wide("\r\n"));
        assert!(expand(&with_break, 0, None, &mut fake, &mut buffer).is_ok());
        let longer = wide(&"x".repeat(MAX_LINE + 1));
        assert_eq!(
            expand(&longer, 0, None, &mut fake, &mut buffer),
            Err(TooLong)
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
            depth: 0,
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
        // An unknown code ends the prompt; a `$` at its end shows nothing.
        assert_eq!(prompt("[a$xb]", "C:\\", &TIME), "[a");
        assert_eq!(prompt("[c]$", "C:\\", &TIME), "[c]");
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
    fn a_command_not_recognized_returns_1_its_errorlevel_9009() {
        let mut state = State::default();
        state.not_recognized();
        assert_eq!((state.return_code, state.errorlevel), (1, NOT_RECOGNIZED));
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
        // An undefined variable's substring: in a batch, `%NOPE:` goes and the rest is read on
        // (its closing `%`, alone, goes too); as typed at the prompt.
        assert_eq!(in_batch("[%NOPE:~0,2%]", "t", &mut fake), "[~0,2]");
        assert_eq!(in_batch("[%NOPE:a=b%]", "t", &mut fake), "[a=b]");
        assert_eq!(
            expanded("[%NOPE:~0,2%]", 0, &mut fake),
            Ok("[%NOPE:~0,2%]".to_string())
        );
    }

    #[test]
    fn the_command_line_ends_with_a_nul() {
        let mut buffer = [0xFFFF; 8];
        let command = command_line(&wide("pwd x"), &wide("pwd"), &mut buffer).unwrap();
        assert_eq!(command, wide("pwd x\0"));
        assert!(command_line(&wide("12345678"), &wide("1"), &mut buffer).is_none());
        assert_eq!(
            command_line(&wide("1234567"), &wide("1234567"), &mut buffer)
                .unwrap()
                .len(),
            8
        );
    }

    #[test]
    fn a_blank_follows_a_word_ended_by_another_delimiter() {
        let mut buffer = [0; 32];
        let line = |line: &str, word: &str, buffer: &mut [u16]| {
            narrow(command_line(&wide(line), &wide(word), buffer).unwrap())
        };
        assert_eq!(line("x,one", "x", &mut buffer), "x ,one\0");
        assert_eq!(line("cmd/c y", "cmd", &mut buffer), "cmd /c y\0");
        assert_eq!(line("x  a  b", "x", &mut buffer), "x  a  b\0");
        assert_eq!(line("\"x\"y z", "\"x\"y", &mut buffer), "\"x\"y z\0");
        assert_eq!(line("x", "x", &mut buffer), "x\0");
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
    fn a_drive_s_hidden_variable() {
        assert_eq!(drive_variable(&wide("c:\\x")), Some([EQUALS, 0x43, 0x3A]));
        assert_eq!(drive_variable(&wide("Z:")), Some([EQUALS, 0x5A, 0x3A]));
        assert_eq!(drive_variable(&wide("\\\\srv\\share")), None);
        assert_eq!(drive_variable(&wide("1:\\")), None);
    }

    #[test]
    fn text_decodes_lossily() {
        assert_eq!(Text(&[u16::from(b'a'), 0xD800]).to_string(), "a\u{FFFD}");
    }
}
