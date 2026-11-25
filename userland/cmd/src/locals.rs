//! `setlocal` and `endlocal`, as `setlocal /?` documents Windows 2000's: in a batch file,
//! `setlocal` saves the environment, the current directory and the two modes its arguments set
//! (command extensions, delayed expansion), and `endlocal` puts back what the last `setlocal`
//! saved. Each batch file (and what `call :label` runs) has its own: `endlocal` never undoes its
//! caller's, and the batch file's end undoes every `setlocal` it left ([`Locals::end`]). They do
//! nothing outside a batch file.
//!
//! `setlocal`'s arguments, whatever their case, are `ENABLEEXTENSIONS`, `DISABLEEXTENSIONS`,
//! `ENABLEDELAYEDEXPANSION` and `DISABLEDELAYEDEXPANSION`. Given any argument, `setlocal` sets the
//! ERRORLEVEL: 0 when each is one of those, 1 otherwise (`setlocal /?`: "This works because on old
//! versions of CMD.EXE, SETLOCAL does NOT set the ERRORLEVEL value"); without one it leaves it.
//! A batch file holds [`DEPTH`] `setlocal`s at most: one more prints [`MAXIMUM`].
//!
//! The environment and the directory are the program's to save and put back ([`Environment`]);
//! [`changes`] says which variables to set and delete to go from one environment block to another.

use crate::{is_delimiter, is_named, same_name, State};

/// The `setlocal`s a batch file may hold at once.
pub const DEPTH: usize = 32;

/// What `setlocal` prints past [`DEPTH`].
pub const MAXIMUM: &str = "Maximum setlocal recursion level reached.\r\n";

/// The modes `setlocal`'s arguments set, saved and put back with the environment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Modes {
    /// Command extensions (`/E:ON`, `ENABLEEXTENSIONS`). F2K's are always on: the mode is kept
    /// and put back, and changes nothing else.
    pub extensions: bool,
    /// Delayed expansion (`/V:ON`, `ENABLEDELAYEDEXPANSION`): `!NAME!` expanded as each command
    /// runs (see [`crate::delayed`]).
    pub delayed: bool,
}

impl Modes {
    /// The shell's modes now.
    pub fn of(state: &State) -> Modes {
        Modes {
            extensions: state.extensions,
            delayed: state.delayed,
        }
    }

    /// The modes put in the shell's state.
    fn apply(self, state: &mut State) {
        state.extensions = self.extensions;
        state.delayed = self.delayed;
    }
}

/// `setlocal`'s argument read: the modes its words set, and whether each word was one of the
/// four. None without any word.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Arguments {
    pub extensions: Option<bool>,
    pub delayed: Option<bool>,
    /// Whether every word is one of the four arguments.
    pub valid: bool,
}

/// `setlocal`'s argument, its words separated by delimiters (blanks, `,`, `;`, `=`), each read
/// whatever its case; a later word overrides an earlier one. None for no word.
pub fn arguments(argument: &[u16]) -> Option<Arguments> {
    let mut read = Arguments {
        extensions: None,
        delayed: None,
        valid: true,
    };
    let mut any = false;
    for word in argument
        .split(|&unit| is_delimiter(unit))
        .filter(|word| !word.is_empty())
    {
        any = true;
        if is_named(word, "enableextensions") {
            read.extensions = Some(true);
        } else if is_named(word, "disableextensions") {
            read.extensions = Some(false);
        } else if is_named(word, "enabledelayedexpansion") {
            read.delayed = Some(true);
        } else if is_named(word, "disabledelayedexpansion") {
            read.delayed = Some(false);
        } else {
            read.valid = false;
        }
    }
    any.then_some(read)
}

/// The environment and the current directory, as the program keeps them.
pub trait Environment {
    /// What [`Environment::save`] keeps.
    type Saved;

    /// The environment and the current directory, copied: None when there is no room for them.
    fn save(&mut self) -> Option<Self::Saved>;

    /// The environment and the current directory made what `saved` holds.
    fn restore(&mut self, saved: Self::Saved);
}

/// The `setlocal`s a batch file holds: what each saved, the oldest first.
pub struct Locals<S> {
    frames: [Option<(S, Modes)>; DEPTH],
    count: usize,
}

impl<S> Default for Locals<S> {
    fn default() -> Self {
        Locals {
            frames: core::array::from_fn(|_| None),
            count: 0,
        }
    }
}

impl<S> Locals<S> {
    /// How many `setlocal`s are in force.
    pub fn depth(&self) -> usize {
        self.count
    }

    /// `setlocal argument`: the environment, the directory and the modes saved, then the modes its
    /// argument names set. It returns 0; given an argument, it sets the ERRORLEVEL (see
    /// [`arguments`]) and returns it. Past [`DEPTH`], it prints [`MAXIMUM`] (to `report`) and
    /// does nothing else; with no room to save the environment, nothing at all.
    pub fn setlocal<E: Environment<Saved = S>>(
        &mut self,
        argument: &[u16],
        state: &mut State,
        environment: &mut E,
        report: &mut dyn FnMut(&str),
    ) {
        state.return_code = 0;
        if self.count == DEPTH {
            report(MAXIMUM);
            return;
        }
        let Some(saved) = environment.save() else {
            return;
        };
        self.frames[self.count] = Some((saved, Modes::of(state)));
        self.count += 1;
        if let Some(read) = arguments(argument) {
            if let Some(extensions) = read.extensions {
                state.extensions = extensions;
            }
            if let Some(delayed) = read.delayed {
                state.delayed = delayed;
            }
            let code = u32::from(!read.valid);
            state.return_code = code;
            state.errorlevel = code;
        }
    }

    /// `endlocal`: what the last `setlocal` saved put back, the ERRORLEVEL kept; nothing when
    /// there is none. It returns 0 (its arguments are ignored).
    pub fn endlocal<E: Environment<Saved = S>>(&mut self, state: &mut State, environment: &mut E) {
        state.return_code = 0;
        if self.count == 0 {
            return;
        }
        self.count -= 1;
        if let Some((saved, modes)) = self.frames[self.count].take() {
            environment.restore(saved);
            modes.apply(state);
        }
    }

    /// The batch file's end: what its first `setlocal` saved put back, the others dropped, the
    /// ERRORLEVEL and return code kept.
    pub fn end<E: Environment<Saved = S>>(&mut self, state: &mut State, environment: &mut E) {
        let first = self.frames[0].take();
        for frame in &mut self.frames[..self.count] {
            *frame = None;
        }
        self.count = 0;
        if let Some((saved, modes)) = first {
            environment.restore(saved);
            modes.apply(state);
        }
    }
}

/// An environment entry's name: up to its first `=` after its first unit (`=C:=C:\` is `=C:`).
fn name(entry: &[u16]) -> &[u16] {
    let end = entry
        .iter()
        .skip(1)
        .position(|&unit| unit == u16::from(b'='))
        .map_or(entry.len(), |at| at + 1);
    &entry[..end]
}

/// An entry's value: after its name's `=`.
fn value(entry: &[u16]) -> &[u16] {
    entry.get(name(entry).len() + 1..).unwrap_or_default()
}

/// An environment block's entries, `NAME=value` each, NULs between them.
fn entries(block: &[u16]) -> impl Iterator<Item = &[u16]> {
    block
        .split(|&unit| unit == 0)
        .filter(|entry| !entry.is_empty())
}

/// The entry of `block` named `name`, whatever its letters' case.
fn find<'a>(block: &'a [u16], wanted: &[u16]) -> Option<&'a [u16]> {
    entries(block).find(|entry| same_name(name(entry), wanted))
}

/// What [`changes`] hands each variable to: its name, and its value or None to delete it.
pub type Change<'a> = dyn FnMut(&[u16], Option<&[u16]>) + 'a;

/// The variables to change to make the environment block `current` the block `saved` (each a run
/// of `NAME=value` entries, NULs between them): each handed to `change`, its name and its value,
/// None for one to delete. A variable whose value is the same in both is left alone.
pub fn changes(saved: &[u16], current: &[u16], change: &mut Change<'_>) {
    for entry in entries(current) {
        if find(saved, name(entry)).is_none() {
            change(name(entry), None);
        }
    }
    for entry in entries(saved) {
        let same = find(current, name(entry)).is_some_and(|now| value(now) == value(entry));
        if !same {
            change(name(entry), Some(value(entry)));
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::testing::{narrow, wide};

    /// An environment and a current directory; the names upper-cased.
    #[derive(Clone, Debug, Default, PartialEq)]
    struct Fake {
        variables: BTreeMap<String, String>,
        directory: String,
        /// Whether a save finds no room.
        full: bool,
    }

    impl Fake {
        fn new(variables: &[(&str, &str)]) -> Fake {
            Fake {
                variables: variables
                    .iter()
                    .map(|(name, value)| (name.to_uppercase(), value.to_string()))
                    .collect(),
                directory: "C:\\F2K".to_string(),
                full: false,
            }
        }

        fn set(&mut self, name: &str, value: &str) {
            self.variables
                .insert(name.to_uppercase(), value.to_string());
        }

        fn get(&self, name: &str) -> Option<&str> {
            self.variables.get(&name.to_uppercase()).map(String::as_str)
        }
    }

    impl Environment for Fake {
        type Saved = (BTreeMap<String, String>, String);

        fn save(&mut self) -> Option<Self::Saved> {
            (!self.full).then(|| (self.variables.clone(), self.directory.clone()))
        }

        fn restore(&mut self, (variables, directory): Self::Saved) {
            self.variables = variables;
            self.directory = directory;
        }
    }

    /// A shell in a batch file: its state, its `setlocal`s, what it reported.
    struct Batch {
        state: State,
        locals: Locals<(BTreeMap<String, String>, String)>,
        environment: Fake,
        reported: String,
    }

    impl Batch {
        fn new(variables: &[(&str, &str)]) -> Batch {
            Batch {
                state: State::default(),
                locals: Locals::default(),
                environment: Fake::new(variables),
                reported: String::new(),
            }
        }

        fn setlocal(&mut self, argument: &str) {
            let reported = &mut self.reported;
            self.locals.setlocal(
                &wide(argument),
                &mut self.state,
                &mut self.environment,
                &mut |text| reported.push_str(text),
            );
        }

        fn endlocal(&mut self) {
            self.locals.endlocal(&mut self.state, &mut self.environment);
        }

        fn end(&mut self) {
            self.locals.end(&mut self.state, &mut self.environment);
        }
    }

    #[test]
    fn endlocal_puts_back_the_variables_and_the_directory() {
        let mut batch = Batch::new(&[("KEEP", "1"), ("CHANGED", "old"), ("GONE", "x")]);
        let before = batch.environment.clone();
        batch.setlocal("");
        batch.environment.set("CHANGED", "new");
        batch.environment.variables.remove("GONE");
        batch.environment.set("ADDED", "y");
        batch.environment.directory = "C:\\F2K\\SUB".to_string();
        batch.endlocal();
        assert_eq!(batch.environment, before);
        assert_eq!(batch.locals.depth(), 0);
    }

    #[test]
    fn setlocals_nest_and_endlocal_undoes_the_last() {
        let mut batch = Batch::new(&[]);
        batch.setlocal("");
        batch.environment.set("A", "1");
        batch.setlocal("");
        batch.environment.set("A", "2");
        batch.endlocal();
        assert_eq!(batch.environment.get("A"), Some("1"));
        batch.endlocal();
        assert_eq!(batch.environment.get("A"), None);
        // An endlocal past the last setlocal does nothing.
        batch.environment.set("A", "3");
        batch.endlocal();
        assert_eq!(batch.environment.get("A"), Some("3"));
    }

    #[test]
    fn the_batch_file_s_end_undoes_every_setlocal() {
        let mut batch = Batch::new(&[("A", "0")]);
        batch.setlocal("ENABLEDELAYEDEXPANSION");
        batch.environment.set("A", "1");
        batch.setlocal("DISABLEDELAYEDEXPANSION");
        batch.environment.set("A", "2");
        batch.state.errorlevel = 7;
        batch.end();
        assert_eq!(batch.environment.get("A"), Some("0"));
        assert!(!batch.state.delayed);
        assert_eq!(batch.state.errorlevel, 7);
        assert_eq!(batch.locals.depth(), 0);
        // Ending a batch file without setlocal changes nothing.
        batch.environment.set("A", "4");
        batch.end();
        assert_eq!(batch.environment.get("A"), Some("4"));
    }

    #[test]
    fn its_arguments_set_the_modes_until_endlocal() {
        let mut batch = Batch::new(&[]);
        assert!(batch.state.extensions && !batch.state.delayed);
        batch.setlocal("enableDelayedExpansion");
        assert!(batch.state.delayed);
        batch.setlocal("DISABLEEXTENSIONS");
        assert!(!batch.state.extensions && batch.state.delayed);
        batch.setlocal("disabledelayedexpansion enableextensions");
        assert!(batch.state.extensions && !batch.state.delayed);
        batch.endlocal();
        assert!(!batch.state.extensions && batch.state.delayed);
        batch.endlocal();
        batch.endlocal();
        assert!(batch.state.extensions && !batch.state.delayed);
    }

    #[test]
    fn an_argument_sets_the_errorlevel() {
        let mut batch = Batch::new(&[]);
        batch.state.errorlevel = 5;
        batch.setlocal("");
        assert_eq!((batch.state.errorlevel, batch.state.return_code), (5, 0));
        batch.setlocal("ENABLEEXTENSIONS");
        assert_eq!((batch.state.errorlevel, batch.state.return_code), (0, 0));
        batch.setlocal("bogus");
        assert_eq!((batch.state.errorlevel, batch.state.return_code), (1, 1));
        // A word it does not know with one it does: the known one applies, the ERRORLEVEL is 1.
        batch.setlocal("enabledelayedexpansion,bogus");
        assert_eq!(batch.state.errorlevel, 1);
        assert!(batch.state.delayed);
        // Each localized the environment all the same.
        assert_eq!(batch.locals.depth(), 4);
        // endlocal keeps the ERRORLEVEL.
        batch.endlocal();
        assert_eq!((batch.state.errorlevel, batch.state.return_code), (1, 0));
    }

    #[test]
    fn a_batch_file_holds_32_setlocals() {
        let mut batch = Batch::new(&[]);
        for level in 0..DEPTH {
            batch.environment.set("LEVEL", &level.to_string());
            batch.setlocal("");
        }
        assert!(batch.reported.is_empty());
        batch.state.errorlevel = 3;
        batch.setlocal("ENABLEDELAYEDEXPANSION");
        assert_eq!(batch.reported, MAXIMUM);
        assert_eq!(batch.locals.depth(), DEPTH);
        assert!(!batch.state.delayed);
        assert_eq!(batch.state.errorlevel, 3);
        batch.end();
        assert_eq!(batch.environment.get("LEVEL"), Some("0"));
    }

    #[test]
    fn no_room_to_save_localizes_nothing() {
        let mut batch = Batch::new(&[]);
        batch.environment.full = true;
        batch.setlocal("ENABLEDELAYEDEXPANSION");
        assert_eq!(batch.locals.depth(), 0);
        assert!(!batch.state.delayed);
    }

    #[test]
    fn arguments_are_read_word_by_word() {
        assert_eq!(arguments(&wide("")), None);
        assert_eq!(arguments(&wide("  ")), None);
        assert_eq!(
            arguments(&wide("EnableExtensions;DISABLEDELAYEDEXPANSION")),
            Some(Arguments {
                extensions: Some(true),
                delayed: Some(false),
                valid: true
            })
        );
        assert_eq!(
            arguments(&wide("enabledelayedexpansion disabledelayedexpansion")),
            Some(Arguments {
                extensions: None,
                delayed: Some(false),
                valid: true
            })
        );
        assert!(!arguments(&wide("enabledelayed")).unwrap().valid);
    }

    /// The changes from `current` to `saved` (`NAME=value` entries), in order.
    fn changed(saved: &[&str], current: &[&str]) -> Vec<String> {
        let block = |entries: &[&str]| {
            wide(
                &entries
                    .iter()
                    .map(|entry| format!("{entry}\0"))
                    .collect::<String>(),
            )
        };
        let mut out = Vec::new();
        changes(&block(saved), &block(current), &mut |name, value| {
            out.push(match value {
                Some(value) => format!("set {}={}", narrow(name), narrow(value)),
                None => format!("delete {}", narrow(name)),
            });
        });
        out
    }

    #[test]
    fn changes_between_two_blocks() {
        assert_eq!(
            changed(
                &["=C:=C:\\F2K", "A=1", "B=2", "Path=C:\\WINNT"],
                &["=C:=C:\\F2K\\SUB", "B=2", "C=3", "PATH=C:\\WINNT"],
            ),
            ["delete C", "set =C:=C:\\F2K", "set A=1"]
        );
        // A value holding `=` is the variable's.
        assert_eq!(changed(&["A=b=c"], &["A=b"]), ["set A=b=c"]);
        assert!(changed(&["A="], &["A="]).is_empty());
    }
}
