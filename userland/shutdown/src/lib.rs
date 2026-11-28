//! shutdown: the Windows 2000 Resource Kit's `shutdown` command (KB 317371),
//! `shutdown [\\computername] [/l] [/a] [/r] [/t:xx] ["msg"] [/y] [/c]`, for the local computer.
//! The program (src/main.rs) asks the question, counts down and calls ExitWindowsEx; this library
//! reads its command line, says what it prints, and the codes it ends with.
//!
//! The arguments are split as the C runtime splits a command line (Microsoft's "Parsing C
//! command-line arguments"): blanks separate them, double quotes group blanks into one and are
//! dropped, and backslashes are plain unless they stand before a double quote. The switches are
//! read whatever their case:
//! - `\\computername`: the computer to shut down; only the local computer's own name is taken;
//! - `/l`: the local computer, which is also what a command line without `\\computername` means;
//! - `/a`: abort a pending shutdown; every other argument is then ignored;
//! - `/r`: restart instead of shutting down;
//! - `/t:xx`: wait `xx` seconds first, 20 without it;
//! - anything else: the message shown while it waits, 127 characters at most (several words are
//!   joined by a blank);
//! - `/y`: answer yes to the question before the shutdown;
//! - `/c`: force the running programs to quit (EWX_FORCE);
//! - `/?`: the usage.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

use core::fmt;

/// The exit code once the shutdown has been asked for (or the usage asked for with `/?`).
pub const ASKED: u32 = 0;
/// The exit code when no shutdown was asked for: cancelled, refused, failed, or nothing to abort.
pub const NOT_ASKED: u32 = 1;
/// The exit code of a command line shutdown does not take (3 is the runtime's panic).
pub const USAGE: u32 = 2;

/// The delay without `/t:xx`, in seconds (KB 317371: "The default is 20 seconds").
pub const DEFAULT_DELAY: u32 = 20;

/// The most characters a message holds (KB 317371).
pub const MESSAGE_CHARACTERS: usize = 127;

/// The units a message's buffer holds: every one of its characters a surrogate pair.
const MESSAGE_UNITS: usize = 2 * MESSAGE_CHARACTERS;

/// The units of a computer's name kept for the comparison: a name longer than this is never the
/// local computer's (MAX_COMPUTERNAME_LENGTH is 15).
const NAME_UNITS: usize = 63;

/// The units of a refused argument kept to show in its error.
const SHOWN_UNITS: usize = 63;

/// The usage, as `/?` and a command line shutdown does not take print it.
pub const USAGE_TEXT: &str = "\
Usage: SHUTDOWN [\\\\Computername] [/L] [/A] [/R] [/T:xx] [\"Msg\"] [/Y] [/C]\r
    \\\\Computername  The computer to shut down: this computer's own name only\r
    /L              Shut down the local computer\r
    /A              Abort a pending shutdown (the other switches are ignored)\r
    /R              Restart the computer after the shutdown\r
    /T:xx           Wait xx seconds first (20 by default); Ctrl+C cancels\r
    \"Msg\"           A message shown while waiting, 127 characters at most\r
    /Y              Answer yes to the question\r
    /C              Force the running programs to quit\r
";

/// What `/a` answers: no shutdown is ever pending (the Resource Kit tool's countdown lives in
/// winlogon, which F2K does not have; this tool counts down itself). The text is Windows'
/// own message for ERROR_NO_SHUTDOWN_IN_PROGRESS (1116), what AbortSystemShutdown fails with when
/// there is nothing to abort.
pub const NOTHING_TO_ABORT: &str =
    "Unable to abort the system shutdown because no shutdown was in progress.\r\n";

/// What a cancelled shutdown prints: a no to the question, or Ctrl+C during the question or the
/// countdown.
pub const CANCELLED: &str = "Shutdown cancelled.\r\n";

/// UTF-16 units in a buffer of `N`, as many as fit.
#[derive(Clone, Copy)]
pub struct Units<const N: usize> {
    units: [u16; N],
    length: usize,
    /// Whether units were dropped for want of room.
    cut: bool,
}

impl<const N: usize> Units<N> {
    /// No units.
    pub const fn new() -> Self {
        Units {
            units: [0; N],
            length: 0,
            cut: false,
        }
    }

    /// The units held.
    pub fn as_slice(&self) -> &[u16] {
        &self.units[..self.length]
    }

    /// Whether units were dropped for want of room.
    pub fn is_cut(&self) -> bool {
        self.cut
    }

    fn push(&mut self, unit: u16) {
        match self.units.get_mut(self.length) {
            Some(slot) => {
                *slot = unit;
                self.length += 1;
            }
            None => self.cut = true,
        }
    }

    fn clear(&mut self) {
        self.length = 0;
        self.cut = false;
    }
}

impl<const N: usize> Default for Units<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> fmt::Display for Units<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Text(self.as_slice()).fmt(f)
    }
}

/// UTF-16 text shown as it reads: an unpaired surrogate as U+FFFD.
pub struct Text<'a>(pub &'a [u16]);

impl fmt::Display for Text<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for character in char::decode_utf16(self.0.iter().copied()) {
            fmt::Write::write_char(f, character.unwrap_or(char::REPLACEMENT_CHARACTER))?;
        }
        Ok(())
    }
}

const QUOTE: u16 = b'"' as u16;
const BACKSLASH: u16 = b'\\' as u16;
const SLASH: u16 = b'/' as u16;
const COLON: u16 = b':' as u16;

fn is_blank(unit: u16) -> bool {
    unit == u16::from(b' ') || unit == u16::from(b'\t')
}

/// A command line's arguments after the program's name, split as the C runtime splits them.
pub struct Arguments<'a> {
    rest: &'a [u16],
}

impl<'a> Arguments<'a> {
    /// The arguments of `line`, a whole command line (GetCommandLineW's): the program's name, up
    /// to a blank or, quoted, to its closing quote, is passed over.
    pub fn new(line: &'a [u16]) -> Self {
        let rest = match line.first() {
            Some(&QUOTE) => match line[1..].iter().position(|&unit| unit == QUOTE) {
                Some(end) => &line[end + 2..],
                None => &[],
            },
            _ => {
                let end = line.iter().position(|&unit| is_blank(unit));
                &line[end.unwrap_or(line.len())..]
            }
        };
        Arguments { rest }
    }

    /// The next argument into `into` (emptied first): false at the line's end.
    pub fn next_into<const N: usize>(&mut self, into: &mut Units<N>) -> bool {
        into.clear();
        let start = self.rest.iter().position(|&unit| !is_blank(unit));
        let Some(start) = start else {
            self.rest = &[];
            return false;
        };
        let mut rest = &self.rest[start..];
        let mut quoted = false;
        while let Some(&unit) = rest.first() {
            if is_blank(unit) && !quoted {
                break;
            }
            if unit == BACKSLASH {
                let run = rest.iter().take_while(|&&unit| unit == BACKSLASH).count();
                if rest.get(run) == Some(&QUOTE) {
                    // 2n backslashes then a quote: n backslashes, the quote a delimiter; 2n + 1:
                    // n backslashes and the quote itself.
                    for _ in 0..run / 2 {
                        into.push(BACKSLASH);
                    }
                    if run % 2 == 1 {
                        into.push(QUOTE);
                    } else {
                        quoted = !quoted;
                    }
                    rest = &rest[run + 1..];
                } else {
                    for _ in 0..run {
                        into.push(BACKSLASH);
                    }
                    rest = &rest[run..];
                }
                continue;
            }
            if unit == QUOTE {
                quoted = !quoted;
            } else {
                into.push(unit);
            }
            rest = &rest[1..];
        }
        self.rest = rest;
        true
    }
}

/// What the command line asks for.
pub enum Command {
    /// The usage (`/?`).
    Help,
    /// Abort a pending shutdown (`/a`).
    Abort,
    /// Shut the computer down, or restart it.
    ShutDown(Options),
}

/// A shutdown's switches.
pub struct Options {
    /// The computer named with `\\computername` (the two backslashes dropped); none for the
    /// local computer.
    pub computer: Option<Units<NAME_UNITS>>,
    /// `/r`: restart instead of shutting down.
    pub restart: bool,
    /// `/t:xx`: the seconds to wait first.
    pub delay: u32,
    /// The message shown while waiting.
    pub message: Units<MESSAGE_UNITS>,
    /// `/y`: answer yes to the question.
    pub yes: bool,
    /// `/c`: force the running programs to quit.
    pub force: bool,
}

/// A command line shutdown does not take.
pub enum Usage {
    /// A switch it does not know.
    Unknown(Units<SHOWN_UNITS>),
    /// `/t:` without a number of seconds it can wait.
    Delay(Units<SHOWN_UNITS>),
    /// A message longer than 127 characters.
    MessageTooLong,
}

impl fmt::Display for Usage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Usage::Unknown(argument) => write!(f, "shutdown: unknown switch: {argument}\r\n"),
            Usage::Delay(argument) => write!(
                f,
                "shutdown: /T:xx takes a number of seconds: {argument}\r\n"
            ),
            Usage::MessageTooLong => write!(
                f,
                "shutdown: the message is longer than {MESSAGE_CHARACTERS} characters\r\n"
            ),
        }
    }
}

/// Whether `argument` is the switch `/<letter>`, whatever its case.
fn is_switch(argument: &[u16], letter: u8) -> bool {
    matches!(argument, [SLASH, unit] if ascii_upper(*unit) == u16::from(letter.to_ascii_uppercase()))
}

fn ascii_upper(unit: u16) -> u16 {
    if (u16::from(b'a')..=u16::from(b'z')).contains(&unit) {
        unit - 0x20
    } else {
        unit
    }
}

/// The seconds `/t:xx`'s digits say; none for anything but decimal digits that fit.
fn seconds(digits: &[u16]) -> Option<u32> {
    if digits.is_empty() {
        return None;
    }
    digits.iter().try_fold(0u32, |seconds, &unit| {
        let digit = unit
            .checked_sub(u16::from(b'0'))
            .filter(|&digit| digit < 10)?;
        seconds.checked_mul(10)?.checked_add(u32::from(digit))
    })
}

/// The units `argument` keeps for an error.
fn shown(argument: &[u16]) -> Units<SHOWN_UNITS> {
    let mut units = Units::new();
    for &unit in argument {
        units.push(unit);
    }
    units
}

/// What the command line `line` (a whole one, the program's name first) asks for: `/?` before
/// anything, then `/a`, which ignores every other argument, then the shutdown's switches.
pub fn parse(line: &[u16]) -> Result<Command, Usage> {
    let mut argument = Units::<MESSAGE_UNITS>::new();
    let mut arguments = Arguments::new(line);
    let (mut help, mut abort) = (false, false);
    while arguments.next_into(&mut argument) {
        let argument = argument.as_slice();
        help |= is_switch(argument, b'?');
        abort |= is_switch(argument, b'a');
    }
    if help {
        return Ok(Command::Help);
    }
    if abort {
        return Ok(Command::Abort);
    }
    let mut options = Options {
        computer: None,
        restart: false,
        delay: DEFAULT_DELAY,
        message: Units::new(),
        yes: false,
        force: false,
    };
    let mut characters = 0;
    let mut arguments = Arguments::new(line);
    while arguments.next_into(&mut argument) {
        let units = argument.as_slice();
        match units {
            [BACKSLASH, BACKSLASH, name @ ..] => {
                let mut computer = Units::new();
                for &unit in name {
                    computer.push(unit);
                }
                options.computer = Some(computer);
            }
            [SLASH, letter, COLON, digits @ ..] if ascii_upper(*letter) == u16::from(b'T') => {
                options.delay = seconds(digits).ok_or(Usage::Delay(shown(units)))?;
            }
            [SLASH, ..] if is_switch(units, b'l') => {}
            [SLASH, ..] if is_switch(units, b'r') => options.restart = true,
            [SLASH, ..] if is_switch(units, b'y') => options.yes = true,
            [SLASH, ..] if is_switch(units, b'c') => options.force = true,
            [SLASH, ..] => return Err(Usage::Unknown(shown(units))),
            _ => {
                // A word of the message: the words given are joined by a blank.
                if options.message.as_slice().is_empty() {
                    characters = 0;
                } else {
                    options.message.push(u16::from(b' '));
                    characters += 1;
                }
                characters += char::decode_utf16(units.iter().copied()).count();
                if argument.is_cut() || characters > MESSAGE_CHARACTERS {
                    return Err(Usage::MessageTooLong);
                }
                for &unit in units {
                    options.message.push(unit);
                }
            }
        }
    }
    Ok(Command::ShutDown(options))
}

/// Whether `name` (a `\\computername`'s, the backslashes dropped) is the local computer's name
/// `local`, as Windows compares computer names: whatever their case.
pub fn is_local(name: &Units<NAME_UNITS>, local: &[u16]) -> bool {
    !name.is_cut()
        && name.as_slice().len() == local.len()
        && name
            .as_slice()
            .iter()
            .zip(local)
            .all(|(&a, &b)| ascii_upper(a) == ascii_upper(b))
}

/// The refusal of a computer other than the local one, then CR LF.
pub struct NotLocal<'a> {
    pub name: &'a Units<NAME_UNITS>,
    pub local: &'a [u16],
}

impl fmt::Display for NotLocal<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "shutdown: \\\\{} is not this computer ({}): only the local computer can be shut down\r\n",
            self.name,
            Text(self.local)
        )
    }
}

/// The question before the shutdown, without its answer: `Shut down QEMU (Y/N)? `.
pub struct Question<'a> {
    pub restart: bool,
    pub computer: &'a [u16],
}

impl fmt::Display for Question<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let verb = if self.restart { "Restart" } else { "Shut down" };
        write!(f, "{verb} {} (Y/N)? ", Text(self.computer))
    }
}

/// The answer a line typed to the [`Question`] gives, CR LF and blanks around it dropped: yes for
/// Y, no for N, whatever their case; none for anything else (the question is asked again).
pub fn answer(line: &[u16]) -> Option<bool> {
    let start = line
        .iter()
        .position(|&unit| !is_blank(unit) && unit != 0x0D && unit != 0x0A);
    let end = line
        .iter()
        .rposition(|&unit| !is_blank(unit) && unit != 0x0D && unit != 0x0A);
    match (start, end) {
        (Some(start), Some(end)) if start == end => match ascii_upper(line[start]) {
            unit if unit == u16::from(b'Y') => Some(true),
            unit if unit == u16::from(b'N') => Some(false),
            _ => None,
        },
        _ => None,
    }
}

/// The countdown's line, rewritten each second over itself (a carriage return first, no line
/// feed): `Shutting down QEMU in 20 seconds (Ctrl+C cancels)`, blanks after it where the line for
/// the first second was longer.
pub struct Countdown<'a> {
    pub restart: bool,
    pub computer: &'a [u16],
    /// The seconds left.
    pub seconds: u32,
    /// The seconds the countdown started from.
    pub delay: u32,
}

/// The decimal digits `value` takes.
fn digits(value: u32) -> usize {
    value.checked_ilog10().map_or(1, |log| log as usize + 1)
}

/// The length of a countdown line's variable part for `seconds`: its digits and the plural's `s`.
fn variable_length(seconds: u32) -> usize {
    digits(seconds) + usize::from(seconds != 1)
}

impl fmt::Display for Countdown<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let verb = if self.restart {
            "Restarting"
        } else {
            "Shutting down"
        };
        let plural = if self.seconds == 1 { "" } else { "s" };
        write!(
            f,
            "\r{verb} {} in {} second{plural} (Ctrl+C cancels)",
            Text(self.computer),
            self.seconds
        )?;
        for _ in variable_length(self.seconds)..variable_length(self.delay) {
            f.write_str(" ")?;
        }
        Ok(())
    }
}

/// The line before ExitWindowsEx is called: `Shutting down QEMU.` or `Restarting QEMU.`.
pub struct Now<'a> {
    pub restart: bool,
    pub computer: &'a [u16],
}

impl fmt::Display for Now<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let verb = if self.restart {
            "Restarting"
        } else {
            "Shutting down"
        };
        write!(f, "{verb} {}.\r\n", Text(self.computer))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().collect()
    }

    fn arguments(line: &str) -> Vec<String> {
        let line = wide(line);
        let mut arguments = Arguments::new(&line);
        let mut argument = Units::<64>::new();
        let mut all = Vec::new();
        while arguments.next_into(&mut argument) {
            all.push(String::from_utf16(argument.as_slice()).unwrap());
        }
        all
    }

    fn taken(line: &str) -> Options {
        match parse(&wide(line)) {
            Ok(Command::ShutDown(options)) => options,
            Ok(Command::Help) => panic!("{line}: the usage"),
            Ok(Command::Abort) => panic!("{line}: an abort"),
            Err(usage) => panic!("{line}: {usage}"),
        }
    }

    fn usage(line: &str) -> String {
        match parse(&wide(line)) {
            Err(usage) => usage.to_string(),
            Ok(_) => panic!("{line}: taken"),
        }
    }

    #[test]
    fn the_program_s_name_is_passed_over() {
        assert_eq!(arguments("shutdown /l /y"), ["/l", "/y"]);
        assert_eq!(arguments("\"C:\\a b\\shutdown.exe\" /r"), ["/r"]);
        assert_eq!(arguments("shutdown"), Vec::<String>::new());
        assert_eq!(arguments("\"unclosed /r"), Vec::<String>::new());
        assert_eq!(arguments("shutdown   \t  "), Vec::<String>::new());
    }

    #[test]
    fn quotes_group_and_backslashes_escape_only_before_a_quote() {
        assert_eq!(
            arguments(r#"x "two words" a"b c"d \\pc"#),
            ["two words", "ab cd", r"\\pc"]
        );
        assert_eq!(arguments(r#"x a\"b a\\"b c" d"#), [r#"a"b"#, r"a\b c", "d"]);
        assert_eq!(arguments(r#"x a\\\"b"#), [r#"a\"b"#]);
        assert_eq!(arguments(r#"x """#), [""]);
    }

    #[test]
    fn without_switches_a_shutdown_of_the_local_computer_after_20_seconds() {
        let options = taken("shutdown");
        assert!(options.computer.is_none());
        assert!(!options.restart && !options.yes && !options.force);
        assert_eq!(options.delay, 20);
        assert!(options.message.as_slice().is_empty());
    }

    #[test]
    fn each_switch_whatever_its_case() {
        let options = taken(r#"shutdown /L /r /T:5 "Bye now" /Y /c"#);
        assert!(options.restart && options.yes && options.force);
        assert_eq!(options.delay, 5);
        assert_eq!(options.message.as_slice(), wide("Bye now"));
        let options = taken("shutdown /l /t:0 /y");
        assert!(!options.restart && options.yes && !options.force);
        assert_eq!(options.delay, 0);
        assert_eq!(taken("shutdown /t:120").delay, 120);
    }

    #[test]
    fn a_computer_s_name_and_the_message_s_words() {
        let options = taken(r"shutdown \\QEMU going down now");
        assert_eq!(options.computer.unwrap().as_slice(), wide("QEMU"));
        assert_eq!(options.message.as_slice(), wide("going down now"));
    }

    #[test]
    fn help_comes_first_then_abort_ignores_everything_else() {
        assert!(matches!(parse(&wide("shutdown /l /?")), Ok(Command::Help)));
        assert!(matches!(
            parse(&wide("shutdown /A /x /t:no")),
            Ok(Command::Abort)
        ));
        assert!(matches!(
            parse(&wide("shutdown /l /a /y")),
            Ok(Command::Abort)
        ));
    }

    #[test]
    fn what_shutdown_does_not_take() {
        assert_eq!(usage("shutdown /x"), "shutdown: unknown switch: /x\r\n");
        assert_eq!(usage("shutdown /lr"), "shutdown: unknown switch: /lr\r\n");
        assert_eq!(
            usage("shutdown /t:"),
            "shutdown: /T:xx takes a number of seconds: /t:\r\n"
        );
        assert_eq!(
            usage("shutdown /t:1x"),
            "shutdown: /T:xx takes a number of seconds: /t:1x\r\n"
        );
        assert_eq!(
            usage("shutdown /t:4294967296"),
            "shutdown: /T:xx takes a number of seconds: /t:4294967296\r\n"
        );
        assert_eq!(taken("shutdown /t:4294967295").delay, u32::MAX);
        assert_eq!(usage("shutdown /t"), "shutdown: unknown switch: /t\r\n");
    }

    #[test]
    fn the_message_holds_127_characters() {
        let longest = "m".repeat(127);
        assert_eq!(
            taken(&format!("shutdown \"{longest}\"")).message.as_slice(),
            wide(&longest)
        );
        let words = format!("{} {}", "m".repeat(63), "n".repeat(63));
        assert_eq!(
            taken(&format!("shutdown {words}")).message.as_slice(),
            wide(&words)
        );
        let pairs = "\u{1F600}".repeat(127);
        assert_eq!(
            taken(&format!("shutdown {pairs}")).message.as_slice(),
            wide(&pairs)
        );
        let too_long = "shutdown: the message is longer than 127 characters\r\n";
        assert_eq!(usage(&format!("shutdown \"{longest}m\"")), too_long);
        assert_eq!(usage(&format!("shutdown {longest} m")), too_long);
        assert_eq!(
            usage(&format!("shutdown \"{}\"", "m".repeat(400))),
            too_long
        );
    }

    #[test]
    fn the_local_computer_whatever_the_case() {
        let name = |text: &str| {
            let mut units = Units::new();
            for unit in text.encode_utf16() {
                units.push(unit);
            }
            units
        };
        let local = wide("QEMU");
        assert!(is_local(&name("QEMU"), &local));
        assert!(is_local(&name("qemu"), &local));
        assert!(!is_local(&name("QEMU2"), &local));
        assert!(!is_local(&name(""), &local));
        assert!(!is_local(&name(&"Q".repeat(100)), &wide(&"Q".repeat(63))));
        assert_eq!(
            NotLocal {
                name: &name("support"),
                local: &local
            }
            .to_string(),
            "shutdown: \\\\support is not this computer (QEMU): only the local computer can be shut down\r\n"
        );
    }

    #[test]
    fn the_question_and_its_answers() {
        let computer = wide("QEMU");
        assert_eq!(
            Question {
                restart: false,
                computer: &computer
            }
            .to_string(),
            "Shut down QEMU (Y/N)? "
        );
        assert_eq!(
            Question {
                restart: true,
                computer: &computer
            }
            .to_string(),
            "Restart QEMU (Y/N)? "
        );
        assert_eq!(answer(&wide("y\r\n")), Some(true));
        assert_eq!(answer(&wide(" Y \r\n")), Some(true));
        assert_eq!(answer(&wide("n\r\n")), Some(false));
        assert_eq!(answer(&wide("N")), Some(false));
        assert_eq!(answer(&wide("yes\r\n")), None);
        assert_eq!(answer(&wide("\r\n")), None);
    }

    #[test]
    fn the_countdown_rewrites_its_line() {
        let computer = wide("QEMU");
        let line = |restart, seconds, delay| {
            Countdown {
                restart,
                computer: &computer,
                seconds,
                delay,
            }
            .to_string()
        };
        assert_eq!(
            line(false, 20, 20),
            "\rShutting down QEMU in 20 seconds (Ctrl+C cancels)"
        );
        assert_eq!(
            line(false, 9, 20),
            "\rShutting down QEMU in 9 seconds (Ctrl+C cancels) "
        );
        assert_eq!(
            line(false, 1, 20),
            "\rShutting down QEMU in 1 second (Ctrl+C cancels)  "
        );
        assert_eq!(
            line(true, 1, 2),
            "\rRestarting QEMU in 1 second (Ctrl+C cancels) "
        );
        assert_eq!(
            line(true, 1, 1),
            "\rRestarting QEMU in 1 second (Ctrl+C cancels)"
        );
    }

    #[test]
    fn the_line_before_the_call() {
        let computer = wide("QEMU");
        assert_eq!(
            Now {
                restart: false,
                computer: &computer
            }
            .to_string(),
            "Shutting down QEMU.\r\n"
        );
        assert_eq!(
            Now {
                restart: true,
                computer: &computer
            }
            .to_string(),
            "Restarting QEMU.\r\n"
        );
    }

    #[test]
    fn the_usage_lines_fit_79_columns() {
        for line in USAGE_TEXT.split("\r\n") {
            assert!(line.len() <= 79, "{line}");
            assert!(!line.contains('\n'), "{line:?}");
        }
        assert!(USAGE_TEXT.ends_with("\r\n"));
    }
}
