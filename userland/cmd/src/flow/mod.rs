//! The batch language's control flow, as Windows 2000's cmd reads it with its command extensions
//! on (`if /?`, `for /?`, `goto /?`, `call /?`): `if`'s conditions (src/flow/condition.rs),
//! `for`'s loops (src/flow/repeat.rs), and `goto`'s and `call`'s labels (src/flow/label.rs).
//!
//! `if` and `for` are read where a command starts, as cmd's parser reads them: their header (the
//! condition, or the loop up to `do`) first, then a command that takes the rest of the line, its
//! operators included (`if a==a echo x & echo y` runs both echoes, or neither), up to the `)`
//! closing a group around them or the end of a block's line (src/syntax.rs). After an `if`'s
//! command in parentheses, `else` and a second command may follow.

pub mod condition;
pub mod label;
pub mod repeat;

use crate::syntax::Syntax;
use crate::{command_word, is_blank, is_named, QUOTE};

/// The control-flow command a word names: `if` or `for`, whatever its case.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Keyword {
    If,
    For,
}

/// The control-flow command `text` (where a command starts, `@`s and blanks skipped) starts with:
/// its word, ended as a built-in's is ([`command_word`]: `if/i`, `for/f` included).
pub fn keyword(text: &[u16]) -> Option<Keyword> {
    let (word, _) = command_word(text);
    if is_named(word, "if") {
        Some(Keyword::If)
    } else if is_named(word, "for") {
        Some(Keyword::For)
    } else {
        None
    }
}

/// The length of `text`'s header when it starts with `if` or `for` (see [`keyword`]): where the
/// command it runs starts. Err with the keyword's length for a header that cannot be read (the
/// line is then reported by [`crate::syntax::check`]); None for no such keyword.
pub fn header(text: &[u16]) -> Option<(Keyword, Result<usize, usize>)> {
    let keyword = keyword(text)?;
    let length = match keyword {
        Keyword::If => condition::parse(text).map(|header| header.start()),
        Keyword::For => repeat::parse(text).map(|header| header.start()),
    };
    Some((keyword, length.map_err(|_| command_word(text).0.len())))
}

/// A header's words, read from its start: an offset into its text.
pub(crate) struct Cursor<'a> {
    pub text: &'a [u16],
    pub at: usize,
}

impl<'a> Cursor<'a> {
    /// A cursor after the keyword `text` starts with.
    pub fn after_keyword(text: &'a [u16]) -> Self {
        Cursor {
            text,
            at: command_word(text).0.len(),
        }
    }

    /// What is left.
    pub fn rest(&self) -> &'a [u16] {
        &self.text[self.at..]
    }

    /// The blanks at the cursor skipped.
    pub fn skip_blanks(&mut self) {
        while self.text.get(self.at).is_some_and(|&unit| is_blank(unit)) {
            self.at += 1;
        }
    }

    /// The units `separates` says separate words skipped.
    pub fn skip(&mut self, separates: impl Fn(u16) -> bool) {
        while self.text.get(self.at).is_some_and(|&unit| separates(unit)) {
            self.at += 1;
        }
    }

    /// The word at the cursor, taken: it runs to a unit `ends` says ends it, outside double
    /// quotes (its quotes kept). Empty at the text's end or at such a unit.
    pub fn word(&mut self, ends: impl Fn(u16) -> bool) -> &'a [u16] {
        let start = self.at;
        let mut quoted = false;
        while let Some(&unit) = self.text.get(self.at) {
            if unit == QUOTE {
                quoted = !quoted;
            } else if !quoted && ends(unit) {
                break;
            }
            self.at += 1;
        }
        &self.text[start..self.at]
    }

    /// The word at the cursor (see [`Cursor::word`]), not taken.
    pub fn peek(&self, ends: impl Fn(u16) -> bool) -> &'a [u16] {
        Cursor {
            text: self.text,
            at: self.at,
        }
        .word(ends)
    }

    /// Whether the text at the cursor starts with `units`.
    pub fn at(&self, units: &[u16]) -> bool {
        self.rest().starts_with(units)
    }
}

/// What a header with no word where one must be is: `The syntax of the command is incorrect.`,
/// or the word found where another was expected (`x was unexpected at this time.`).
pub(crate) fn unexpected(word: &[u16]) -> Syntax<'_> {
    if word.is_empty() {
        Syntax::Incorrect
    } else {
        Syntax::Unexpected(word)
    }
}

/// `/?` as a header's first word starts it: the command's help is asked for.
pub(crate) fn asks_help(word: &[u16]) -> bool {
    word.starts_with(&[u16::from(b'/'), u16::from(b'?')])
}

#[cfg(test)]
pub(crate) mod tests {
    use std::collections::BTreeMap;

    use crate::{Time, TooLong, Variables};

    pub fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().collect()
    }

    pub fn narrow(units: &[u16]) -> String {
        String::from_utf16(units).unwrap()
    }

    /// An environment for the flow modules' tests: variables, a current directory, and the files
    /// that exist (by their full path, upper-cased), with their attributes and sizes.
    pub struct Fake {
        pub variables: BTreeMap<String, String>,
        pub files: BTreeMap<String, (u32, u64)>,
    }

    impl Fake {
        pub fn new(variables: &[(&str, &str)], files: &[(&str, u64)]) -> Fake {
            Fake {
                variables: variables
                    .iter()
                    .map(|(name, value)| (name.to_uppercase(), value.to_string()))
                    .collect(),
                files: files
                    .iter()
                    .map(|(name, size)| (name.to_uppercase(), (0x20, *size)))
                    .collect(),
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
            put("C:\\F2K", value)
        }

        fn time(&mut self) -> Time {
            Time::default()
        }

        fn random(&mut self) -> u16 {
            7
        }

        fn command_line(&self) -> &[u16] {
            &[]
        }

        fn full_path(&mut self, name: &[u16], value: &mut [u16]) -> Option<usize> {
            let name = narrow(name);
            let full = if name.get(1..2) == Some(":") {
                name
            } else {
                format!("C:\\F2K\\{name}")
            };
            put(&full, value).ok()
        }

        fn file(&mut self, path: &[u16]) -> Option<(u32, u64)> {
            self.files.get(&narrow(path).to_uppercase()).copied()
        }

        /// No file has a short name: the modifiers' own tests are the library's.
        fn short_path(&mut self, _path: &[u16], _value: &mut [u16]) -> Option<usize> {
            None
        }

        /// No file has a time of its last write.
        fn written(&mut self, _path: &[u16]) -> Option<Time> {
            None
        }
    }

    #[test]
    fn keywords_end_as_built_in_words_do() {
        use super::{keyword, Keyword};
        assert_eq!(keyword(&wide("if a==a x")), Some(Keyword::If));
        assert_eq!(keyword(&wide("IF/i a==a x")), Some(Keyword::If));
        assert_eq!(keyword(&wide("for/f x")), Some(Keyword::For));
        assert_eq!(keyword(&wide("iffy")), None);
        assert_eq!(keyword(&wide("format")), None);
    }

    #[test]
    fn a_header_s_length_is_where_its_command_starts() {
        use super::{header, Keyword};
        let of = |text: &str| header(&wide(text));
        assert_eq!(of("if a==b echo x"), Some((Keyword::If, Ok(8))));
        assert_eq!(of("for %a in (x y) do echo"), Some((Keyword::For, Ok(19))));
        assert_eq!(of("if a echo"), Some((Keyword::If, Err(2))));
        assert_eq!(of("echo"), None);
    }
}
