//! The built-in commands that work on files and directories (`del` or `erase`, `md` or `mkdir`,
//! `rd` or `rmdir`, `copy`, `ren` or `rename`, `move`, `pushd`, `popd`, `dir`), on the console and
//! the clock (`title`, `color`, `date`, `time`, `pause`), and that start programs (`start`), as
//! Windows 2000's cmd.exe has them with its command extensions on: which word names which
//! ([`parse`]), what their arguments say ([`files`], [`console`], [`dir`], [`start`]), and what
//! they print. The program (src/exec) makes the calls.

pub mod console;
pub mod dir;
pub mod files;
pub mod start;

use crate::{is_named, trim_blanks, trim_end};

/// One of the built-ins this module reads, its argument as the line gives it (leading blanks
/// skipped).
#[derive(Debug, PartialEq, Eq)]
pub enum Builtin<'a> {
    /// `del` or `erase`: files deleted (see [`files::delete_switches`]).
    Delete(&'a [u16]),
    /// `md` or `mkdir`: directories created, with the directories above them.
    MakeDirectory(&'a [u16]),
    /// `rd` or `rmdir`: directories removed (see [`files::remove_switches`]).
    RemoveDirectory(&'a [u16]),
    /// `copy`: files copied or joined (see [`files::copy`]).
    Copy(&'a [u16]),
    /// `ren` or `rename`: files renamed (see [`files::rename`]).
    Rename(&'a [u16]),
    /// `move`: files and directories moved or renamed (see [`files::move_arguments`]).
    Move(&'a [u16]),
    /// `pushd`: the current directory saved, then changed to the path (blanks around it dropped);
    /// without one, the saved directories listed.
    PushDirectory(&'a [u16]),
    /// `popd`: back to the directory `pushd` saved last (its arguments ignored).
    PopDirectory,
    /// `title`: the console window's title, the argument without its trailing blanks.
    Title(&'a [u16]),
    /// `color`: the screen's colours (see [`console::colour`]).
    Colour(&'a [u16]),
    /// `date`: the date shown, or set (see [`console::date_switches`]).
    Date(&'a [u16]),
    /// `time`: the time shown, or set.
    Time(&'a [u16]),
    /// `pause`: a key waited for (its arguments ignored).
    Pause,
    /// `dir`: a directory's entries listed (see [`dir::Switches`]).
    Directory(&'a [u16]),
    /// `start`: a program started, without waiting for it unless asked (see [`start::parse`]).
    Start(&'a [u16]),
}

/// The built-in `word` names, with its `argument`: None for a word naming none of this module's.
pub fn parse<'a>(word: &[u16], argument: &'a [u16]) -> Option<Builtin<'a>> {
    let named = |names: &[&str]| names.iter().any(|name| is_named(word, name));
    Some(if named(&["del", "erase"]) {
        Builtin::Delete(argument)
    } else if named(&["md", "mkdir"]) {
        Builtin::MakeDirectory(argument)
    } else if named(&["rd", "rmdir"]) {
        Builtin::RemoveDirectory(argument)
    } else if named(&["copy"]) {
        Builtin::Copy(argument)
    } else if named(&["ren", "rename"]) {
        Builtin::Rename(argument)
    } else if named(&["move"]) {
        Builtin::Move(argument)
    } else if named(&["pushd"]) {
        Builtin::PushDirectory(trim_blanks(argument))
    } else if named(&["popd"]) {
        Builtin::PopDirectory
    } else if named(&["title"]) {
        Builtin::Title(trim_end(argument))
    } else if named(&["color"]) {
        Builtin::Colour(argument)
    } else if named(&["date"]) {
        Builtin::Date(argument)
    } else if named(&["time"]) {
        Builtin::Time(argument)
    } else if named(&["pause"]) {
        Builtin::Pause
    } else if named(&["dir"]) {
        Builtin::Directory(argument)
    } else if named(&["start"]) {
        Builtin::Start(argument)
    } else {
        return None;
    })
}

impl Builtin<'_> {
    /// Whether the built-in sets the ERRORLEVEL to 0 when it succeeds, wherever it runs: `copy`,
    /// `date`, `del`, `md`, `move`, `pushd`, `ren`, `time`, `color`, `dir` and `start` do (`start
    /// /wait` sets it to the program's exit code); `rd`, `popd`, `title` and `pause` leave it as it
    /// is (each sets it to 1 when it fails, `del` excepted: see src/exec).
    pub fn clears_errorlevel(&self) -> bool {
        !matches!(
            self,
            Builtin::RemoveDirectory(_)
                | Builtin::PopDirectory
                | Builtin::Title(_)
                | Builtin::Pause
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().collect()
    }

    #[test]
    fn each_word_and_its_other_name() {
        let argument = wide("a.txt");
        for (word, builtin) in [
            ("del", Builtin::Delete(&argument)),
            ("ERASE", Builtin::Delete(&argument)),
            ("md", Builtin::MakeDirectory(&argument)),
            ("MkDir", Builtin::MakeDirectory(&argument)),
            ("rd", Builtin::RemoveDirectory(&argument)),
            ("rmdir", Builtin::RemoveDirectory(&argument)),
            ("copy", Builtin::Copy(&argument)),
            ("ren", Builtin::Rename(&argument)),
            ("rename", Builtin::Rename(&argument)),
            ("move", Builtin::Move(&argument)),
            ("pushd", Builtin::PushDirectory(&argument)),
            ("popd", Builtin::PopDirectory),
            ("title", Builtin::Title(&argument)),
            ("color", Builtin::Colour(&argument)),
            ("date", Builtin::Date(&argument)),
            ("time", Builtin::Time(&argument)),
            ("pause", Builtin::Pause),
            ("DIR", Builtin::Directory(&argument)),
            ("start", Builtin::Start(&argument)),
        ] {
            assert_eq!(parse(&wide(word), &argument), Some(builtin), "{word}");
        }
        assert_eq!(parse(&wide("vol"), &argument), None);
        assert_eq!(parse(&wide("colour"), &argument), None);
    }

    #[test]
    fn pushd_and_title_lose_their_blanks() {
        let path = wide("C:\\a b");
        assert_eq!(
            parse(&wide("pushd"), &wide("C:\\a b  ")),
            Some(Builtin::PushDirectory(&path))
        );
        let title = wide(" My  title");
        assert_eq!(
            parse(&wide("title"), &wide(" My  title \t")),
            Some(Builtin::Title(&title))
        );
    }

    #[test]
    fn the_prompt_shows_a_plus_per_saved_directory() {
        let prompt = |depth| {
            crate::Prompt {
                text: &wide("$+$p$g"),
                directory: &wide("C:\\"),
                time: &crate::Time::default(),
                depth,
            }
            .to_string()
        };
        assert_eq!(prompt(0), "C:\\>");
        assert_eq!(prompt(2), "++C:\\>");
    }

    #[test]
    fn which_clear_the_errorlevel() {
        let none: &[u16] = &[];
        for builtin in [
            Builtin::Delete(none),
            Builtin::MakeDirectory(none),
            Builtin::Copy(none),
            Builtin::Rename(none),
            Builtin::Move(none),
            Builtin::PushDirectory(none),
            Builtin::Colour(none),
            Builtin::Date(none),
            Builtin::Time(none),
            Builtin::Directory(none),
            Builtin::Start(none),
        ] {
            assert!(builtin.clears_errorlevel(), "{builtin:?}");
        }
        for builtin in [
            Builtin::RemoveDirectory(none),
            Builtin::PopDirectory,
            Builtin::Title(none),
            Builtin::Pause,
        ] {
            assert!(!builtin.clears_errorlevel(), "{builtin:?}");
        }
    }
}
