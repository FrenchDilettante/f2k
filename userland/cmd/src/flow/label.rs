//! `goto` and `call`'s labels: a batch file's line whose first character, after blanks, is `:`
//! names a label, the word after the colon; `goto label` goes on at the line after it, and
//! `call :label arguments` runs the batch file from there as a batch file of its own, with its
//! own arguments, back after the call once it ends. `goto :eof` ends the batch file (or what
//! `call :label` runs).
//!
//! A label is looked for from where the batch file is to its end, then from its start, as `goto
//! /?` says; it is compared whatever the case of its letters.

use core::fmt;

use crate::{is_blank, is_delimiter, same_name, skip_blanks, Text};

/// Where `goto` goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Goto<'a> {
    /// No label given.
    Missing,
    /// `:eof`: the batch file's end.
    End,
    /// The label, without its colon.
    Label(&'a [u16]),
}

const COLON: u16 = b':' as u16;

/// `goto`'s argument (or what follows `call`), read: its first word, a colon before it dropped
/// (`goto :x` and `goto x` go to the same label), the words after it ignored. `:eof`, its colon
/// written, whatever its case, is the end.
pub fn goto(argument: &[u16]) -> Goto<'_> {
    let argument = skip_delimiters(argument);
    let (colon, rest) = match argument.split_first() {
        Some((&COLON, rest)) => (true, rest),
        _ => (false, argument),
    };
    let label = word(rest);
    if label.is_empty() {
        Goto::Missing
    } else if colon && crate::is_named(label, "eof") {
        Goto::End
    } else {
        Goto::Label(label)
    }
}

/// `text` without the delimiters it starts with (blanks, `,`, `;`, `=`).
fn skip_delimiters(text: &[u16]) -> &[u16] {
    let start = text
        .iter()
        .position(|&unit| !is_delimiter(unit))
        .unwrap_or(text.len());
    &text[start..]
}

/// The word `text` starts with: up to a delimiter.
fn word(text: &[u16]) -> &[u16] {
    let end = text
        .iter()
        .position(|&unit| is_delimiter(unit))
        .unwrap_or(text.len());
    &text[..end]
}

/// Whether the batch file's `line`, as read, is the label `label`: a `:` first after its blanks,
/// then the label's word (what follows it ignored).
pub fn names(line: &[u16], label: &[u16]) -> bool {
    let line = skip_blanks(line);
    match line.split_first() {
        Some((&COLON, rest)) => same_name(word(rest), label),
        _ => false,
    }
}

/// Whether `text` (after `call`, expanded) calls a label: it starts with `:`, its blanks skipped.
pub fn calls_label(text: &[u16]) -> bool {
    text.iter().find(|&&unit| !is_blank(unit)) == Some(&COLON)
}

/// The label `call :label arguments` calls: the word after the colon (`eof` too, which `call`
/// looks for as any other label).
pub fn called(text: &[u16]) -> &[u16] {
    let text = skip_blanks(text);
    word(text.strip_prefix(&[COLON]).unwrap_or(text))
}

/// What `goto` without a label prints.
pub const MISSING: &str = "No batch label specified to GOTO command.\r\n";

/// What `call :label` prints outside a batch file.
pub const OUTSIDE: &str = "Invalid attempt to call batch label outside of batch script.\r\n";

/// What `goto` and `call` print when the batch file has no such label.
pub struct NotFound<'a>(pub &'a [u16]);

impl fmt::Display for NotFound<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "The system cannot find the batch label specified - {}\r\n",
            Text(self.0)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow::tests::wide;

    fn target(argument: &str) -> Goto<'static> {
        let argument: &'static [u16] = Box::leak(wide(argument).into_boxed_slice());
        goto(argument)
    }

    #[test]
    fn goto_s_label() {
        assert_eq!(target("loop"), Goto::Label(&wide("loop")));
        assert_eq!(target(" :loop rest"), Goto::Label(&wide("loop")));
        assert_eq!(target(":eof"), Goto::End);
        assert_eq!(target(":EOF"), Goto::End);
        // Without its colon, eof is a label like any other.
        assert_eq!(target("eof"), Goto::Label(&wide("eof")));
        assert_eq!(target(""), Goto::Missing);
        assert_eq!(target(" : "), Goto::Missing);
    }

    #[test]
    fn a_line_names_a_label_whatever_its_case() {
        assert!(names(&wide(":loop"), &wide("LOOP")));
        assert!(names(&wide("  :loop the comment"), &wide("loop")));
        assert!(!names(&wide(":loops"), &wide("loop")));
        assert!(!names(&wide("echo :loop"), &wide("loop")));
        assert!(!names(&wide("::loop"), &wide("loop")));
    }

    #[test]
    fn a_call_of_a_label() {
        assert!(calls_label(&wide(":sub a b")));
        assert!(calls_label(&wide("  :sub")));
        assert!(!calls_label(&wide("x.cmd :sub")));
        assert_eq!(called(&wide(" :sub a b")), wide("sub"));
        assert_eq!(called(&wide(":eof")), wide("eof"));
    }
}
