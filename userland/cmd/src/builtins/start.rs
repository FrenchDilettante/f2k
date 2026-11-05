//! What `start`'s argument says, as Windows 2000's cmd.exe reads it (`start /?`): the window's
//! title, the switches, then the command and its parameters ([`parse`]).

use core::fmt;

use crate::{is_blank, is_named, skip_blanks, trim_blanks, Text, QUOTE};

/// CreateProcess's priority classes, as `start`'s switches name them.
pub const IDLE_PRIORITY_CLASS: u32 = 0x0040;
pub const NORMAL_PRIORITY_CLASS: u32 = 0x0020;
pub const HIGH_PRIORITY_CLASS: u32 = 0x0080;
pub const REALTIME_PRIORITY_CLASS: u32 = 0x0100;
pub const BELOW_NORMAL_PRIORITY_CLASS: u32 = 0x4000;
pub const ABOVE_NORMAL_PRIORITY_CLASS: u32 = 0x8000;

/// What `start`'s argument says.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Start<'a> {
    /// The window's title: the first quoted word before the command, without its quotes.
    pub title: Option<&'a [u16]>,
    /// `/Dpath` (or `/D path`): the directory the command starts in, quotes and all.
    pub directory: Option<&'a [u16]>,
    /// `/I`: the environment the shell started with, rather than its own (taken, and not applied:
    /// see the README).
    pub original_environment: bool,
    /// `/MIN` or `/MAX`: how the new window shows (there is none: taken, and not applied).
    pub window: bool,
    /// `/B`: no new window, the command sharing the shell's console.
    pub background: bool,
    /// `/WAIT`: the shell waits for the command to end, and takes its exit code.
    pub wait: bool,
    /// `/LOW`, `/NORMAL`, `/HIGH`, `/REALTIME`, `/ABOVENORMAL` or `/BELOWNORMAL`: the priority
    /// class's creation flag, the last given.
    pub priority: Option<u32>,
    /// The command and its parameters, as the line holds them, the blanks around them dropped:
    /// empty for none.
    pub command: &'a [u16],
}

/// A switch `start` does not take: what follows its `/`.
#[derive(Debug, PartialEq, Eq)]
pub struct Refused<'a>(pub &'a [u16]);

/// What `start` prints for a switch it does not take.
impl fmt::Display for Refused<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "The system cannot accept the START command parameter /{}.\r\n",
            Text(self.0)
        )
    }
}

const SLASH: u16 = b'/' as u16;

/// The word at the start of `text` (which starts with no blank) and what follows it: a word runs
/// to a blank outside quotes.
fn word(text: &[u16]) -> (&[u16], &[u16]) {
    let mut quoted = false;
    let end = text
        .iter()
        .position(|&unit| {
            if unit == QUOTE {
                quoted = !quoted;
            }
            !quoted && is_blank(unit)
        })
        .unwrap_or(text.len());
    text.split_at(end)
}

/// `start`'s argument read: before the command, a quoted word is the title (the first one only) and
/// a word starting with `/` holds switches (`/wait/b` is two); the first other word starts the
/// command, which runs to the end of the line. `/D` takes the rest of its word as the directory,
/// or the next word when nothing follows it.
pub fn parse(argument: &[u16]) -> Result<Start<'_>, Refused<'_>> {
    let mut start = Start::default();
    let mut rest = skip_blanks(argument);
    loop {
        match rest.first() {
            Some(&QUOTE) if start.title.is_none() => {
                let inside = &rest[1..];
                let end = inside
                    .iter()
                    .position(|&unit| unit == QUOTE)
                    .unwrap_or(inside.len());
                start.title = Some(&inside[..end]);
                rest = skip_blanks(inside.get(end + 1..).unwrap_or(&[]));
            }
            Some(&SLASH) => {
                let (switches, after) = word(rest);
                rest = skip_blanks(after);
                let mut switches = switches;
                while let Some((_, text)) = switches.split_first() {
                    let end = text
                        .iter()
                        .position(|&unit| unit == SLASH)
                        .unwrap_or(text.len());
                    let (switch, more) = text.split_at(end);
                    if switch
                        .first()
                        .is_some_and(|&unit| crate::fold(unit) == u16::from(b'D'))
                    {
                        // The directory runs to the end of the word, slashes and all.
                        let path = &text[1..];
                        start.directory = Some(if path.is_empty() {
                            let (path, after) = word(rest);
                            rest = skip_blanks(after);
                            path
                        } else {
                            path
                        });
                        break;
                    }
                    start.switch(switch)?;
                    switches = more;
                }
            }
            _ => break,
        }
    }
    start.command = trim_blanks(rest);
    Ok(start)
}

impl Start<'_> {
    /// One switch but `/D`, what follows its `/`.
    fn switch<'a>(&mut self, switch: &'a [u16]) -> Result<(), Refused<'a>> {
        let named = |name| is_named(switch, name);
        if named("wait") {
            self.wait = true;
        } else if named("b") {
            self.background = true;
        } else if named("i") {
            self.original_environment = true;
        } else if named("min") || named("max") {
            self.window = true;
        } else if named("separate") || named("shared") {
            // 16-bit Windows programs' memory: there are none.
        } else {
            self.priority = Some(if named("low") {
                IDLE_PRIORITY_CLASS
            } else if named("normal") {
                NORMAL_PRIORITY_CLASS
            } else if named("high") {
                HIGH_PRIORITY_CLASS
            } else if named("realtime") {
                REALTIME_PRIORITY_CLASS
            } else if named("abovenormal") {
                ABOVE_NORMAL_PRIORITY_CLASS
            } else if named("belownormal") {
                BELOW_NORMAL_PRIORITY_CLASS
            } else {
                return Err(Refused(switch));
            });
        }
        Ok(())
    }
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

    #[test]
    fn the_command_and_its_parameters() {
        let argument = wide("  spawnkid exit 4  ");
        let start = parse(&argument).unwrap();
        assert_eq!(narrow(start.command), "spawnkid exit 4");
        assert!(!start.wait && !start.background && start.title.is_none());
        assert_eq!(parse(&wide("")).unwrap(), Start::default());
    }

    #[test]
    fn switches_before_the_command() {
        let argument = wide("/WAIT /b/low prog /wait x");
        let start = parse(&argument).unwrap();
        assert!(start.wait && start.background);
        assert_eq!(start.priority, Some(IDLE_PRIORITY_CLASS));
        // A switch after the command is the command's.
        assert_eq!(narrow(start.command), "prog /wait x");
        for (switch, class) in [
            ("/normal", NORMAL_PRIORITY_CLASS),
            ("/HIGH", HIGH_PRIORITY_CLASS),
            ("/realtime", REALTIME_PRIORITY_CLASS),
            ("/AboveNormal", ABOVE_NORMAL_PRIORITY_CLASS),
            ("/belownormal", BELOW_NORMAL_PRIORITY_CLASS),
            ("/high /low", IDLE_PRIORITY_CLASS),
        ] {
            assert_eq!(
                parse(&wide(switch)).unwrap().priority,
                Some(class),
                "{switch}"
            );
        }
        let argument = wide("/i /min /max /separate /shared x");
        let taken = parse(&argument).unwrap();
        assert!(taken.original_environment && taken.window && taken.priority.is_none());
        assert_eq!(narrow(taken.command), "x");
    }

    #[test]
    fn the_title_is_the_first_quoted_word() {
        let argument = wide("\"my title\" /b \"C:\\a b\\x.exe\" y");
        let start = parse(&argument).unwrap();
        assert_eq!(start.title.map(narrow).as_deref(), Some("my title"));
        assert!(start.background);
        assert_eq!(narrow(start.command), "\"C:\\a b\\x.exe\" y");
        // A program in quotes alone is taken for the title, as Windows' start takes it.
        let alone = wide("\"C:\\a b\\x.exe\"");
        let start = parse(&alone).unwrap();
        assert_eq!(start.title.map(narrow).as_deref(), Some("C:\\a b\\x.exe"));
        assert!(start.command.is_empty());
        let empty = wide("\"\" x");
        assert_eq!(parse(&empty).unwrap().title, Some(&[][..]));
    }

    #[test]
    fn the_directory() {
        let directory = |argument: &str| {
            let argument = wide(argument);
            let start = parse(&argument).unwrap();
            (
                start.directory.map(narrow),
                narrow(start.command),
                start.wait,
            )
        };
        assert_eq!(
            directory("/DC:\\temp x"),
            (Some("C:\\temp".into()), "x".into(), false)
        );
        assert_eq!(
            directory("/d \"C:\\a b\" /wait x"),
            (Some("\"C:\\a b\"".into()), "x".into(), true)
        );
        assert_eq!(
            directory("/wait/Dsub x"),
            (Some("sub".into()), "x".into(), true)
        );
    }

    #[test]
    fn a_switch_it_does_not_take() {
        let argument = wide("/wait /zz x");
        let refused = parse(&argument).unwrap_err();
        assert_eq!(narrow(refused.0), "zz");
        assert_eq!(
            refused.to_string(),
            "The system cannot accept the START command parameter /zz.\r\n"
        );
    }
}
