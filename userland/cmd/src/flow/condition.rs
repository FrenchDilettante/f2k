//! `if`: a condition, then the command that runs when it holds (and, after `else`, the one that
//! runs when it does not), as `if /?` documents Windows 2000's with its command extensions on:
//!
//! ```text
//! IF [/I] [NOT] ERRORLEVEL number command
//! IF [/I] [NOT] string1==string2 command
//! IF [/I] [NOT] EXIST filename command
//! IF [/I] string1 compare-op string2 command
//! IF [/I] [NOT] DEFINED variable command
//! IF [/I] [NOT] CMDEXTVERSION number command
//! IF condition (command) ELSE command
//! ```
//!
//! The condition's words are separated by blanks, `,` and `;`; a word in double quotes may hold
//! them, and keeps its quotes, which `==` compares too. `==` needs no blanks around it
//! (`if %1==x`).

use core::cmp::Ordering;

use super::{asks_help, unexpected, Cursor};
use crate::syntax::Syntax;
use crate::{fold, is_blank, is_delimiter, is_named, number, same_name, trim_blanks, EQUALS};

/// How `compare-op` compares (`if /?`'s three-letter operators), or `==`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    /// `==`: the same text.
    Same,
    Equ,
    Neq,
    Lss,
    Leq,
    Gtr,
    Geq,
}

impl Op {
    /// The operator a word names, whatever its case.
    fn named(word: &[u16]) -> Option<Op> {
        [
            ("equ", Op::Equ),
            ("neq", Op::Neq),
            ("lss", Op::Lss),
            ("leq", Op::Leq),
            ("gtr", Op::Gtr),
            ("geq", Op::Geq),
        ]
        .into_iter()
        .find_map(|(name, op)| is_named(word, name).then_some(op))
    }
}

/// What an `if` tests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Test<'a> {
    /// `ERRORLEVEL number`: the ERRORLEVEL is `number` or more.
    ErrorLevel(i64),
    /// `EXIST filename`: a file or directory goes by the name (its quotes removed; wildcards
    /// allowed).
    Exist(&'a [u16]),
    /// `DEFINED variable`: the environment has the variable.
    Defined(&'a [u16]),
    /// `CMDEXTVERSION number`: the command extensions' version is `number` or more.
    Version(i64),
    /// `string1==string2`, `string1 compare-op string2`.
    Compare {
        left: &'a [u16],
        op: Op,
        right: &'a [u16],
    },
}

/// An `if` read: its condition, and where its command starts in its text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct If<'a> {
    /// `NOT`: the command runs when the test fails.
    pub not: bool,
    /// `/I`: strings compare whatever the case of their letters.
    pub fold: bool,
    pub test: Test<'a>,
    text: &'a [u16],
    start: usize,
}

/// What an `if`'s text says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Header<'a> {
    /// `if /?`: its help.
    Help(usize),
    If(If<'a>),
}

impl<'a> Header<'a> {
    /// Where the command after the header starts.
    pub fn start(&self) -> usize {
        match self {
            Header::Help(start) => *start,
            Header::If(header) => header.start,
        }
    }
}

impl<'a> If<'a> {
    /// The command after the condition, with its `else` part when it has one (see
    /// [`crate::syntax::branches`]).
    pub fn command(&self) -> &'a [u16] {
        &self.text[self.start..]
    }
}

/// Where the shell's state is read for a condition.
pub trait Probe {
    /// The ERRORLEVEL.
    fn errorlevel(&self) -> u32;
    /// Whether a file or directory goes by `name` (wildcards allowed).
    fn exists(&mut self, name: &[u16]) -> bool;
    /// Whether the environment has the variable `name`.
    fn defined(&mut self, name: &[u16]) -> bool;
}

/// Whether `unit` separates a condition's words: a blank, `,` or `;`.
fn separates(unit: u16) -> bool {
    is_blank(unit) || unit == u16::from(b',') || unit == u16::from(b';')
}

const DOUBLE_EQUALS: [u16; 2] = [EQUALS, EQUALS];

/// `text`, which starts with `if`, read. Incorrect when a word is missing (`if a==`, `if exist`,
/// no command); the word found where `==` or an operator should be is unexpected (`if a b x`).
pub fn parse(text: &[u16]) -> Result<Header<'_>, Syntax<'_>> {
    let mut cursor = Cursor::after_keyword(text);
    cursor.skip(separates);
    let word = cursor.peek(is_delimiter);
    if asks_help(word) {
        return Ok(Header::Help(cursor.at + word.len()));
    }
    let mut not = false;
    let mut fold = false;
    loop {
        let word = cursor.peek(is_delimiter);
        let mut after = Cursor {
            text,
            at: cursor.at + word.len(),
        };
        after.skip(separates);
        // A word before `==` is the string compared (`if not==not`).
        if after.at(&[EQUALS]) {
            break;
        }
        if !fold && is_named(word, "/i") {
            fold = true;
        } else if !not && is_named(word, "not") {
            not = true;
        } else {
            break;
        }
        cursor = after;
    }
    let first = cursor.word(is_delimiter);
    if first.is_empty() {
        return Err(Syntax::Incorrect);
    }
    cursor.skip(separates);
    let test = if cursor.at(&DOUBLE_EQUALS) {
        cursor.at += 2;
        cursor.skip(separates);
        let right = cursor.word(is_delimiter);
        if right.is_empty() {
            return Err(Syntax::Incorrect);
        }
        Test::Compare {
            left: first,
            op: Op::Same,
            right,
        }
    } else if let Some(keyword) = ["errorlevel", "exist", "defined", "cmdextversion"]
        .into_iter()
        .find(|name| is_named(first, name))
    {
        let argument = cursor.word(is_delimiter);
        if argument.is_empty() {
            return Err(Syntax::Incorrect);
        }
        match keyword {
            "errorlevel" => Test::ErrorLevel(whole_number(argument).ok_or(Syntax::Incorrect)?),
            "exist" => Test::Exist(crate::batch::unquote(argument)),
            "defined" => Test::Defined(argument),
            _ => Test::Version(whole_number(argument).ok_or(Syntax::Incorrect)?),
        }
    } else {
        let operator = cursor.word(is_delimiter);
        let op = Op::named(operator).ok_or_else(|| unexpected(operator))?;
        cursor.skip(separates);
        let right = cursor.word(is_delimiter);
        if right.is_empty() {
            return Err(Syntax::Incorrect);
        }
        Test::Compare {
            left: first,
            op,
            right,
        }
    };
    cursor.skip_blanks();
    if trim_blanks(cursor.rest()).is_empty() {
        return Err(Syntax::Incorrect);
    }
    Ok(Header::If(If {
        not,
        fold,
        test,
        text,
        start: cursor.at,
    }))
}

/// `text` read whole as a number, as C's `strtol` reads one with base 0 (a sign, then decimal
/// digits, `0x` and hexadecimal ones, or `0` and octal ones): None when anything is left.
fn whole_number(text: &[u16]) -> Option<i64> {
    match number(text)? {
        (value, []) => Some(value),
        _ => None,
    }
}

impl If<'_> {
    /// Whether the condition holds, `NOT` applied.
    pub fn holds(&self, probe: &mut dyn Probe) -> bool {
        let holds = match self.test {
            // The ERRORLEVEL compares as the signed number `%ERRORLEVEL%` shows.
            Test::ErrorLevel(number) => i64::from(probe.errorlevel() as i32) >= number,
            Test::Exist(name) => probe.exists(name),
            Test::Defined(name) => probe.defined(name),
            Test::Version(number) => i64::from(crate::EXTENSIONS_VERSION) >= number,
            Test::Compare { left, op, right } => compare(left, op, right, self.fold),
        };
        holds != self.not
    }
}

/// Whether `left op right` holds: `==` compares the texts; the other operators compare numbers
/// when both texts are numbers ([`whole_number`]: `if 010 EQU 8` holds), and texts otherwise
/// ([`order`]). `fold` (`/I`) compares texts whatever the case of their letters.
pub fn compare(left: &[u16], op: Op, right: &[u16], fold: bool) -> bool {
    let ordering = match (op, whole_number(left), whole_number(right)) {
        (Op::Same, _, _) => {
            return if fold {
                same_name(left, right)
            } else {
                left == right
            };
        }
        (_, Some(left), Some(right)) => left.cmp(&right),
        _ => order(left, right, fold),
    };
    match op {
        Op::Same | Op::Equ => ordering == Ordering::Equal,
        Op::Neq => ordering != Ordering::Equal,
        Op::Lss => ordering == Ordering::Less,
        Op::Leq => ordering != Ordering::Greater,
        Op::Gtr => ordering == Ordering::Greater,
        Op::Geq => ordering != Ordering::Less,
    }
}

/// Two texts' order, as a dictionary's (Windows' `lstrcmp` and `lstrcmpi`): letters first
/// whatever their case, then, unless `fold`, a lowercase letter before its capital.
fn order(left: &[u16], right: &[u16], fold_case: bool) -> Ordering {
    let folded = left
        .iter()
        .map(|&unit| fold(unit))
        .cmp(right.iter().map(|&unit| fold(unit)));
    if folded != Ordering::Equal || fold_case {
        return folded;
    }
    for (&a, &b) in left.iter().zip(right) {
        if a != b {
            // The same letter in two cases: the lowercase one first.
            return b.cmp(&a);
        }
    }
    Ordering::Equal
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow::tests::wide;

    struct State {
        errorlevel: u32,
    }

    impl Probe for State {
        fn errorlevel(&self) -> u32 {
            self.errorlevel
        }

        fn exists(&mut self, name: &[u16]) -> bool {
            name == wide("there.txt").as_slice() || name == wide("a b").as_slice()
        }

        fn defined(&mut self, name: &[u16]) -> bool {
            same_name(name, &wide("path"))
        }
    }

    /// Whether `line`'s condition holds at ERRORLEVEL `errorlevel`, and its command.
    fn run(line: &str, errorlevel: u32) -> (bool, String) {
        let line = wide(line);
        let Ok(Header::If(header)) = parse(&line) else {
            panic!("not read: {}", String::from_utf16_lossy(&line));
        };
        let holds = header.holds(&mut State { errorlevel });
        (holds, String::from_utf16(header.command()).unwrap())
    }

    fn error(line: &str) -> String {
        let line = wide(line);
        parse(&line).unwrap_err().to_string()
    }

    #[test]
    fn strings_compare_with_their_quotes() {
        assert_eq!(run("if a==a echo x", 0), (true, "echo x".into()));
        assert_eq!(run("if a == b echo x", 0).0, false);
        assert_eq!(run("if \"a b\"==\"a b\" echo", 0).0, true);
        assert_eq!(run("if \"a\"==a echo", 0).0, false);
        assert_eq!(run("if A==a echo", 0).0, false);
        assert_eq!(run("if /i A==a echo", 0).0, true);
        assert_eq!(run("if not a==b echo", 0).0, true);
        assert_eq!(run("if /I not A==a echo", 0).0, false);
        // bathelp's sizes, compared once their variables are replaced.
        assert_eq!(
            run("if 11==11 (echo y) else echo n", 0),
            (true, "(echo y) else echo n".into())
        );
        // A word before `==` is compared, whatever it says.
        assert_eq!(run("if not==not echo", 0).0, true);
        assert_eq!(run("if exist==exist echo", 0).0, true);
    }

    #[test]
    fn the_errorlevel_and_the_other_tests() {
        // batdyn: `if errorlevel 4` after a program exited with 4, its NOT twin.
        assert!(run("if errorlevel 4 echo", 4).0);
        assert!(run("if errorlevel 4 echo", 5).0);
        assert!(!run("if errorlevel 4 echo", 3).0);
        assert!(!run("if not errorlevel 4 echo", 4).0);
        assert!(run("IF ERRORLEVEL 0 echo", 0).0);
        assert!(run("if exist there.txt echo", 0).0);
        assert!(run("if exist \"a b\" echo", 0).0);
        assert!(run("if not exist missing echo", 0).0);
        assert!(run("if defined PATH echo", 0).0);
        assert!(!run("if defined nope echo", 0).0);
        assert!(run("if cmdextversion 2 echo", 0).0);
        assert!(!run("if cmdextversion 3 echo", 0).0);
    }

    #[test]
    fn compare_ops_compare_numbers_when_both_are() {
        // batdyn's RANDOM check.
        assert!(run("if 123 GEQ 0 if 123 LEQ 32767 set x=yes", 0).0);
        assert!(run("if 10 gtr 9 x", 0).0);
        assert!(
            !run("if 10 gtr 9x x", 0).0,
            "text: \"10\" sorts before \"9x\""
        );
        assert!(run("if 010 EQU 8 x", 0).0);
        assert!(run("if 0x10 EQU 16 x", 0).0);
        assert!(run("if -1 LSS 0 x", 0).0);
        assert!(run("if abc LSS abd x", 0).0);
        assert!(run("if a LSS B x", 0).0);
        assert!(run("if a LSS A x", 0).0);
        assert!(run("if /i a EQU A x", 0).0);
        assert!(run("if a NEQ b x", 0).0);
    }

    #[test]
    fn malformed_conditions() {
        let incorrect = crate::SYNTAX.to_string();
        assert_eq!(error("if"), incorrect);
        assert_eq!(error("if a=="), incorrect);
        assert_eq!(error("if a==b"), incorrect);
        assert_eq!(error("if a==b   "), incorrect);
        assert_eq!(error("if exist"), incorrect);
        assert_eq!(error("if errorlevel x echo"), incorrect);
        assert_eq!(error("if a b echo"), "b was unexpected at this time.\r\n");
        assert_eq!(error("if a EQU"), incorrect);
        assert_eq!(parse(&wide("if /?")).map(|header| header.start()), Ok(5));
    }
}
