//! cmd.exe's own command line, as `cmd /?` documents it: its switches, and the string after `/C`
//! or `/K` with its quotes handled.

use crate::{is_blank, skip_blanks, QUOTE};

/// What the string after `/C` or `/K` is followed by.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Then {
    /// `/C`: the shell ends once the string has run, with its ERRORLEVEL.
    End,
    /// `/K`: the shell goes on interactively.
    Prompt,
}

/// What cmd.exe's command line asks of it.
#[derive(Debug, PartialEq, Eq)]
pub struct Switches<'a> {
    /// `/Q`: echo starts off.
    pub echo_off: bool,
    /// `/S`: the string's first and last quotes are stripped whatever it holds.
    pub strip: bool,
    /// `/?`: the shell prints its help and ends, running nothing.
    pub help: bool,
    /// `/U` (and not a later `/A`): the built-ins' output to a file or a pipe is UTF-16LE.
    pub unicode: bool,
    /// `/C` or `/K` and what follows it (the rest of the command line, its leading blanks
    /// skipped); None without either, for an interactive shell.
    pub run: Option<(Then, &'a [u16])>,
}

/// The switches on cmd.exe's command line (as GetCommandLineW gives it, the program's name first:
/// a quoted name runs to its closing quote, another to the first blank). Each switch is `/` and a
/// letter, whatever its case, and may run into the next (`/q/c`). `/C` and `/K` end the switches:
/// the rest of the line is their string. `/Q`, `/S` and `/U` are kept, and `/A` undoes a `/U`
/// before it (the last of the two counts); `/D`, `/E:...`, `/F:...`, `/V:...` and `/T:...` (and
/// any other letter) are accepted and ignored, their `:` values with them. A word that is not a
/// switch ends the switches, the shell interactive.
pub fn switches(command_line: &[u16]) -> Switches<'_> {
    let mut rest = skip_program(command_line);
    let mut switches = Switches {
        echo_off: false,
        strip: false,
        help: false,
        unicode: false,
        run: None,
    };
    loop {
        rest = skip_blanks(rest);
        let Some((&slash, after)) = rest.split_first() else {
            break;
        };
        if slash != u16::from(b'/') {
            break;
        }
        let Some((&letter, after)) = after.split_first() else {
            break;
        };
        match u8::try_from(letter).map(|letter| letter.to_ascii_lowercase()) {
            Ok(b'c') => {
                switches.run = Some((Then::End, skip_blanks(after)));
                break;
            }
            Ok(b'k') => {
                switches.run = Some((Then::Prompt, skip_blanks(after)));
                break;
            }
            Ok(b'q') => switches.echo_off = true,
            Ok(b's') => switches.strip = true,
            Ok(b'?') => switches.help = true,
            Ok(b'u') => switches.unicode = true,
            Ok(b'a') => switches.unicode = false,
            _ => {}
        }
        // A value (`/E:ON`) runs to a blank or the next switch.
        rest = match after.split_first() {
            Some((&colon, value)) if colon == u16::from(b':') => {
                let end = value
                    .iter()
                    .position(|&unit| is_blank(unit) || unit == u16::from(b'/'))
                    .unwrap_or(value.len());
                &value[end..]
            }
            _ => after,
        };
    }
    switches
}

/// The command line after the program's name, which ends at a blank or at a switch's `/`
/// (`cmd/c x`).
fn skip_program(command_line: &[u16]) -> &[u16] {
    let line = skip_blanks(command_line);
    match line.split_first() {
        Some((&QUOTE, rest)) => match rest.iter().position(|&unit| unit == QUOTE) {
            Some(close) => &rest[close + 1..],
            None => &rest[rest.len()..],
        },
        _ => {
            let end = line
                .iter()
                .position(|&unit| is_blank(unit) || unit == u16::from(b'/'))
                .unwrap_or(line.len());
            &line[end..]
        }
    }
}

/// The characters `cmd /?`'s first quote rule calls special.
fn is_special(unit: u16) -> bool {
    b"&<>()@^|".iter().any(|&byte| unit == u16::from(byte))
}

/// The string after `/C` or `/K` as the shell runs it, its quotes handled by `cmd /?`'s rules, in
/// `out`:
/// 1. its quotes are kept when there is no `/S`, there are exactly two quotes, nothing between them
///    is special (`&<>()@^|`), there is a blank between them, and what is between them names an
///    executable file (`executable`);
/// 2. otherwise, when its first character is a quote, that quote and the string's last quote go,
///    the text after the last quote kept.
///
/// None when the string does not fit `out`.
pub fn command_string<'a>(
    string: &[u16],
    strip: bool,
    executable: &mut dyn FnMut(&[u16]) -> bool,
    out: &'a mut [u16],
) -> Option<&'a [u16]> {
    let string = skip_blanks(string);
    let quotes = string.iter().filter(|&&unit| unit == QUOTE).count();
    let keep = !strip && quotes == 2 && {
        let first = string.iter().position(|&unit| unit == QUOTE).unwrap_or(0);
        let last = string.iter().rposition(|&unit| unit == QUOTE).unwrap_or(0);
        let between = &string[first + 1..last];
        !between.iter().any(|&unit| is_special(unit))
            && between.iter().any(|&unit| is_blank(unit))
            && executable(between)
    };
    if !keep && string.first() == Some(&QUOTE) {
        let rest = &string[1..];
        let (before, after) = match rest.iter().rposition(|&unit| unit == QUOTE) {
            Some(last) => (&rest[..last], &rest[last + 1..]),
            None => (rest, &rest[rest.len()..]),
        };
        let length = before.len() + after.len();
        let target = out.get_mut(..length)?;
        target[..before.len()].copy_from_slice(before);
        target[before.len()..].copy_from_slice(after);
        return Some(&out[..length]);
    }
    let target = out.get_mut(..string.len())?;
    target.copy_from_slice(string);
    Some(&out[..string.len()])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().collect()
    }

    fn narrow(units: &[u16]) -> String {
        String::from_utf16(units).unwrap()
    }

    fn run_of(line: &str) -> Option<(Then, String)> {
        let line = wide(line);
        switches(&line).run.map(|(then, rest)| (then, narrow(rest)))
    }

    #[test]
    fn no_switch_is_interactive() {
        let line = wide("cmd.exe");
        assert_eq!(
            switches(&line),
            Switches {
                echo_off: false,
                strip: false,
                help: false,
                unicode: false,
                run: None
            }
        );
        assert_eq!(run_of("  WINNT\\system32\\cmd.exe   "), None);
    }

    #[test]
    fn c_and_k_take_the_rest_of_the_line() {
        assert_eq!(
            run_of("cmd /c echo hi  there "),
            Some((Then::End, "echo hi  there ".into()))
        );
        assert_eq!(
            run_of("cmd /K  dir /w"),
            Some((Then::Prompt, "dir /w".into()))
        );
        assert_eq!(run_of("cmd /cecho hi"), Some((Then::End, "echo hi".into())));
        assert_eq!(run_of("cmd /c"), Some((Then::End, "".into())));
        // After /C, a /K is the string's.
        assert_eq!(run_of("cmd /c /k x"), Some((Then::End, "/k x".into())));
    }

    #[test]
    fn the_program_s_name_may_be_quoted() {
        assert_eq!(
            run_of("\"C:\\a b\\cmd.exe\" /c x"),
            Some((Then::End, "x".into()))
        );
        assert_eq!(run_of("\"C:\\a /c b\\cmd.exe\""), None);
    }

    #[test]
    fn q_and_s_are_kept_the_others_ignored() {
        let line = wide("cmd /Q /d /a /u /e:on /F:OFF /v:on /t:1f /s /c x");
        let switches = switches(&line);
        assert!(switches.echo_off);
        assert!(switches.strip);
        assert_eq!(switches.run.map(|(_, rest)| narrow(rest)), Some("x".into()));
        let line = wide("cmd /q/e:off/c x");
        let switches = super::switches(&line);
        assert!(switches.echo_off && !switches.strip);
        assert_eq!(switches.run.map(|(_, rest)| narrow(rest)), Some("x".into()));
    }

    #[test]
    fn u_asks_for_unicode_output_and_a_for_bytes() {
        let unicode = |line: &str| switches(&wide(line)).unicode;
        assert!(unicode("cmd /u /c echo one"));
        assert!(unicode("cmd /U/c x"));
        assert!(!unicode("cmd /a /c x"));
        assert!(!unicode("cmd /c x"));
        // The last of the two counts.
        assert!(!unicode("cmd /u /a /c x"));
        assert!(unicode("cmd /a /u /c x"));
        // A /U in the string is the string's.
        assert!(!unicode("cmd /c cmd /u /c x"));
    }

    #[test]
    fn a_word_that_is_no_switch_ends_them() {
        assert_eq!(run_of("cmd foo /c x"), None);
    }

    fn string_of(string: &str, strip: bool, executable: &str) -> String {
        let mut out = [0; 64];
        let executable = wide(executable);
        narrow(
            command_string(
                &wide(string),
                strip,
                &mut |name| name == executable,
                &mut out,
            )
            .unwrap(),
        )
    }

    #[test]
    fn quotes_around_an_executable_with_a_blank_stay() {
        assert_eq!(
            string_of("\"C:\\a b\\x.exe\" arg", false, "C:\\a b\\x.exe"),
            "\"C:\\a b\\x.exe\" arg"
        );
    }

    #[test]
    fn otherwise_the_first_and_last_quotes_go() {
        // /S.
        assert_eq!(
            string_of("\"C:\\a b\\x.exe\" arg", true, "C:\\a b\\x.exe"),
            "C:\\a b\\x.exe arg"
        );
        // Not an executable.
        assert_eq!(
            string_of("\"C:\\a b\\x.exe\" arg", false, ""),
            "C:\\a b\\x.exe arg"
        );
        // No blank between the quotes.
        assert_eq!(string_of("\"x.exe\" arg", false, "x.exe"), "x.exe arg");
        // A special character between them.
        assert_eq!(string_of("\"a b&c\" d", false, "a b&c"), "a b&c d");
        // More than two quotes: the first and the last go, the text after the last kept.
        assert_eq!(
            string_of("\"a b\" \"c d\" e", false, "a b"),
            "a b\" \"c d e"
        );
        // A single quote.
        assert_eq!(string_of("\"a b", false, ""), "a b");
    }

    #[test]
    fn a_string_not_starting_with_a_quote_stays() {
        assert_eq!(string_of("echo \"a b\"", false, ""), "echo \"a b\"");
        assert_eq!(string_of("  echo hi ", true, ""), "echo hi ");
    }

    #[test]
    fn a_string_too_long_for_the_buffer_is_none() {
        let mut out = [0; 4];
        assert!(command_string(&wide("12345"), false, &mut |_| false, &mut out).is_none());
    }
}
