//! `for`: a command run once for each item of a set, its variable replaced by the item, as `for
//! /?` documents Windows 2000's with its command extensions on:
//!
//! ```text
//! FOR %variable IN (set) DO command [command-parameters]
//! FOR /D %variable IN (set) DO command
//! FOR /R [[drive:]path] %variable IN (set) DO command
//! FOR /L %variable IN (start,step,end) DO command
//! FOR /F ["options"] %variable IN (file-set) DO command
//! FOR /F ["options"] %variable IN ("string") DO command
//! FOR /F ["options"] %variable IN ('command') DO command
//! ```
//!
//! The variable is one character, `%%v` in a batch file (whose `%%` its expansion makes `%`) and
//! `%v` at the prompt, its case counting. It is replaced in the command each time it runs, and so
//! is `%~v` with the modifiers a batch file's `%~1` takes ([`substitute`]).
//!
//! This module reads the header and the sets; the program walks the directories, reads the files
//! and runs the commands.

use super::{asks_help, unexpected, Cursor};
use crate::syntax::Syntax;
use crate::{
    batch,
    copy,
    fold,
    is_blank,
    is_delimiter,
    is_named,
    modified,
    skip_blanks,
    trim_blanks,
    TooLong,
    Variables,
    MODIFIERS,
    QUOTE,
};

const PERCENT: u16 = b'%' as u16;
const OPEN: u16 = b'(' as u16;
const CLOSE: u16 = b')' as u16;
const SLASH: u16 = b'/' as u16;

/// What a `for` loops over.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode<'a> {
    /// The set's items: files its wildcards match (directories with `/D`), other items as they
    /// are.
    Items,
    /// `/L`: the numbers `(start,step,end)` gives.
    Range,
    /// `/F`: the lines of files, of a string or of a command's output, cut into tokens.
    Lines(Options<'a>),
}

/// A `for` read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct For<'a> {
    /// `/D`: the set's wildcards match directories.
    pub directories: bool,
    /// `/R`: the set is looked for in a directory and each directory below it, the directory
    /// named after the switch (its quotes still on it; empty for the current one).
    pub recursive: Option<&'a [u16]>,
    pub mode: Mode<'a>,
    /// The variable's character.
    pub variable: u16,
    /// What the parentheses hold.
    pub set: &'a [u16],
    text: &'a [u16],
    start: usize,
}

impl<'a> For<'a> {
    /// The command after `do`.
    pub fn command(&self) -> &'a [u16] {
        &self.text[self.start..]
    }
}

/// What a `for`'s text says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Header<'a> {
    /// `for /?`: its help.
    Help(usize),
    For(For<'a>),
}

impl Header<'_> {
    /// Where the command after the header starts.
    pub fn start(&self) -> usize {
        match self {
            Header::Help(start) => *start,
            Header::For(header) => header.start,
        }
    }
}

/// Whether `unit` ends one of the header's words (a switch, the variable, `in`, `do`): a blank or
/// a `(`.
fn ends(unit: u16) -> bool {
    is_blank(unit) || unit == OPEN
}

/// `text`, which starts with `for`, read. A word that is not where it should be is unexpected
/// (`/x`, a variable that is not `%` and one character, no `in`, no set, no `do`); a set never
/// closed, or no command, is incorrect.
pub fn parse(text: &[u16]) -> Result<Header<'_>, Syntax<'_>> {
    let mut cursor = Cursor::after_keyword(text);
    let mut directories = false;
    let mut recursive = None;
    let mut mode = Mode::Items;
    loop {
        cursor.skip_blanks();
        let word = cursor.peek(ends);
        if word.first() != Some(&SLASH) {
            break;
        }
        if asks_help(word) {
            return Ok(Header::Help(cursor.at + word.len()));
        }
        let letter = match word {
            [_, letter] => u8::try_from(fold(*letter)).unwrap_or(0),
            _ => 0,
        };
        cursor.word(ends);
        cursor.skip_blanks();
        match letter {
            b'D' => directories = true,
            b'R' => {
                let root = cursor.peek(is_blank);
                recursive = Some(if root.first() == Some(&PERCENT) || root.is_empty() {
                    &root[..0]
                } else {
                    cursor.word(is_blank)
                });
            }
            b'L' => mode = Mode::Range,
            b'F' => {
                let quoted = cursor.peek(is_blank);
                mode = Mode::Lines(if quoted.first() == Some(&QUOTE) {
                    cursor.word(is_blank);
                    options(batch::unquote(quoted))?
                } else {
                    Options::default()
                });
            }
            _ => return Err(Syntax::Unexpected(word)),
        }
    }
    let variable = cursor.word(ends);
    let variable = match variable {
        [PERCENT, unit] => *unit,
        _ => return Err(unexpected(variable)),
    };
    cursor.skip_blanks();
    let word = cursor.word(ends);
    if !is_named(word, "in") {
        return Err(unexpected(word));
    }
    cursor.skip_blanks();
    if !cursor.at(&[OPEN]) {
        return Err(unexpected(cursor.peek(is_blank)));
    }
    let open = cursor.at;
    let close = closing(&text[open..]).ok_or(Syntax::Incorrect)? + open;
    let set = &text[open + 1..close];
    cursor.at = close + 1;
    cursor.skip_blanks();
    let word = cursor.word(ends);
    if !is_named(word, "do") {
        return Err(unexpected(word));
    }
    cursor.skip_blanks();
    if trim_blanks(cursor.rest()).is_empty() {
        return Err(Syntax::Incorrect);
    }
    Ok(Header::For(For {
        directories,
        recursive,
        mode,
        variable,
        set,
        text,
        start: cursor.at,
    }))
}

/// Where the `)` closing the `(` `text` starts with is, the parentheses inside it counted and
/// those inside double quotes not: None when none closes it.
fn closing(text: &[u16]) -> Option<usize> {
    let mut depth = 0usize;
    let mut quoted = false;
    for (at, &unit) in text.iter().enumerate() {
        match unit {
            QUOTE => quoted = !quoted,
            OPEN if !quoted => depth += 1,
            CLOSE if !quoted => {
                depth -= 1;
                if depth == 0 {
                    return Some(at);
                }
            }
            _ => {}
        }
    }
    None
}

/// A set's items, in order: separated by blanks, `,`, `;` and `=` outside double quotes, their
/// quotes kept.
pub struct Items<'a>(pub &'a [u16]);

impl<'a> Iterator for Items<'a> {
    type Item = &'a [u16];

    fn next(&mut self) -> Option<&'a [u16]> {
        let mut cursor = Cursor {
            text: self.0,
            at: 0,
        };
        cursor.skip(is_delimiter);
        let item = cursor.word(is_delimiter);
        self.0 = cursor.rest();
        (!item.is_empty()).then_some(item)
    }
}

/// `/L`'s numbers, as `(start,step,end)` gives them: each read as C's `atoi` reads a number, 0
/// when it is missing.
pub fn range(set: &[u16]) -> Range {
    let mut numbers = Items(set).map(atoi);
    let start = numbers.next().unwrap_or(0);
    let step = numbers.next().unwrap_or(0);
    let end = numbers.next().unwrap_or(0);
    Range {
        next: start,
        step,
        end,
    }
}

/// A number as C's `atoi` reads it: a sign, then decimal digits, the rest ignored; 0 without
/// digits. It wraps as a 32-bit number does.
fn atoi(text: &[u16]) -> i64 {
    let (negative, digits) = match text.split_first() {
        Some((&unit, rest)) if unit == u16::from(b'-') => (true, rest),
        Some((&unit, rest)) if unit == u16::from(b'+') => (false, rest),
        _ => (false, text),
    };
    let mut value: i32 = 0;
    for &unit in digits {
        let Some(digit) = char::from_u32(u32::from(unit)).and_then(|c| c.to_digit(10)) else {
            break;
        };
        value = value.wrapping_mul(10).wrapping_add(digit as i32);
    }
    i64::from(if negative {
        value.wrapping_neg()
    } else {
        value
    })
}

/// `/L`'s numbers: from the start, by the step, while they have not passed the end (a step of 0
/// never passes it).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Range {
    next: i64,
    step: i64,
    end: i64,
}

impl Iterator for Range {
    type Item = i64;

    fn next(&mut self) -> Option<i64> {
        let value = self.next;
        let past = if self.step < 0 {
            value < self.end
        } else {
            value > self.end
        };
        if past {
            return None;
        }
        self.next = value + self.step;
        Some(value)
    }
}

/// Which tokens of a line `/F` hands its variables: bit n - 1 for token n (1 to 31), and `*`,
/// the rest of the line after the last of them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tokens {
    pub mask: u32,
    pub star: bool,
}

impl Tokens {
    /// The variables the tokens take: one per token, one more for `*`.
    pub fn count(&self) -> usize {
        self.mask.count_ones() as usize + usize::from(self.star)
    }
}

/// `/F`'s options, as the quoted string after it gives them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Options<'a> {
    /// `eol=c`: a line whose first character (after its delimiters) is `c` is skipped; `;`
    /// without the option.
    pub eol: Option<u16>,
    /// `skip=n`: the lines skipped at the start of each file or output.
    pub skip: usize,
    /// `delims=xxx`: the characters that separate tokens; a blank and a tab without the option.
    pub delims: Option<&'a [u16]>,
    /// `tokens=x,y,m-n*`: the tokens handed to the variables; the first without the option.
    pub tokens: Tokens,
    /// `usebackq`: `"..."` names a file, `'...'` is a string and `` `...` `` a command.
    pub backquote: bool,
}

impl Default for Options<'_> {
    fn default() -> Self {
        Options {
            eol: Some(u16::from(b';')),
            skip: 0,
            delims: None,
            tokens: Tokens {
                mask: 1,
                star: false,
            },
            backquote: false,
        }
    }
}

/// The options' keywords, each ending with its `=` where it takes a value.
const KEYWORDS: [&str; 5] = ["eol=", "skip=", "delims=", "tokens=", "usebackq"];

/// Whether `text` starts with `keyword`, whatever the case of its letters.
fn starts_with_keyword(text: &[u16], keyword: &str) -> bool {
    text.len() >= keyword.len() && is_named(&text[..keyword.len()], keyword)
}

/// `/F`'s options string (inside its quotes), read: its options separated by blanks. `delims=`
/// takes every character after it up to a blank before another option, or to the string's end
/// (so a blank may be a delimiter when it comes last: `"delims=, "`); `eol=` takes the one
/// character after it. Anything else is unexpected.
pub fn options(text: &[u16]) -> Result<Options<'_>, Syntax<'_>> {
    let mut options = Options::default();
    let mut rest = text;
    loop {
        rest = skip_blanks(rest);
        if rest.is_empty() {
            return Ok(options);
        }
        let Some(keyword) = KEYWORDS.into_iter().find(|&k| starts_with_keyword(rest, k)) else {
            return Err(Syntax::Unexpected(rest));
        };
        let after = &rest[keyword.len()..];
        let value_end = |value: &[u16]| {
            value
                .iter()
                .position(|&unit| is_blank(unit))
                .unwrap_or(value.len())
        };
        rest = match keyword {
            "eol=" => {
                options.eol = after.first().copied();
                after.get(1..).unwrap_or(&[])
            }
            "skip=" => {
                let end = value_end(after);
                options.skip = decimal(&after[..end]).ok_or(Syntax::Unexpected(rest))?;
                &after[end..]
            }
            "delims=" => {
                let end = (0..after.len())
                    .find(|&at| {
                        is_blank(after[at]) && {
                            let next = skip_blanks(&after[at..]);
                            KEYWORDS.iter().any(|k| starts_with_keyword(next, k))
                        }
                    })
                    .unwrap_or(after.len());
                options.delims = Some(&after[..end]);
                &after[end..]
            }
            "tokens=" => {
                let end = value_end(after);
                options.tokens = tokens(&after[..end]).ok_or(Syntax::Unexpected(rest))?;
                &after[end..]
            }
            _ => {
                options.backquote = true;
                after
            }
        };
    }
}

/// A run of decimal digits, whole: None for anything else.
fn decimal(text: &[u16]) -> Option<usize> {
    if text.is_empty() {
        return None;
    }
    text.iter().try_fold(0usize, |value, &unit| {
        let digit = char::from_u32(u32::from(unit))?.to_digit(10)?;
        value.checked_mul(10)?.checked_add(digit as usize)
    })
}

/// `tokens=`'s value: numbers and ranges (`m-n`) from 1 to 31 separated by commas, then `*` if
/// it ends with one. None when it cannot be read.
fn tokens(text: &[u16]) -> Option<Tokens> {
    let star = u16::from(b'*');
    let (list, star_ends) = match text.split_last() {
        Some((&last, rest)) if last == star => (rest, true),
        _ => (text, false),
    };
    let list = list.strip_suffix(&[u16::from(b',')]).unwrap_or(list);
    let mut mask = 0u32;
    if !list.is_empty() {
        for item in list.split(|&unit| unit == u16::from(b',')) {
            let mut bounds = item.splitn(2, |&unit| unit == u16::from(b'-'));
            let from = decimal(bounds.next()?)?;
            let to = match bounds.next() {
                Some(to) => decimal(to)?,
                None => from,
            };
            if !(1..=31).contains(&from) || !(from..=31).contains(&to) {
                return None;
            }
            for token in from..=to {
                mask |= 1 << (token - 1);
            }
        }
    }
    (mask != 0 || star_ends).then_some(Tokens {
        mask,
        star: star_ends,
    })
}

/// Where `/F` reads its lines.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source<'a> {
    /// Files, their names as [`Items`] separates them.
    Files(&'a [u16]),
    /// A string: one line.
    Text(&'a [u16]),
    /// A command, whose output the lines are.
    Command(&'a [u16]),
}

/// What `/F`'s set names: a string in double quotes (single ones with `usebackq`), a command in
/// single quotes (backquotes with `usebackq`), files otherwise; a string or command is what lies
/// between its first quote and its last.
pub fn source(set: &[u16], backquote: bool) -> Source<'_> {
    let set = trim_blanks(set);
    let (text, command) = if backquote {
        (u16::from(b'\''), u16::from(b'`'))
    } else {
        (QUOTE, u16::from(b'\''))
    };
    let between = |quote: u16| {
        let rest = &set[1..];
        let last = rest
            .iter()
            .rposition(|&unit| unit == quote)
            .unwrap_or(rest.len());
        &rest[..last]
    };
    match set.first() {
        Some(&first) if first == text => Source::Text(between(text)),
        Some(&first) if first == command => Source::Command(between(command)),
        _ => Source::Files(set),
    }
}

/// The values a line gives `/F`'s variables, in order: the tokens asked for, then `*`'s rest.
pub struct Fields<'a> {
    pub values: [&'a [u16]; 32],
    pub count: usize,
}

/// `line` cut as `options` say: its tokens are the runs of characters between delimiters. None
/// for a line the loop skips: empty or delimiters only, starting with the `eol` character after
/// its delimiters, or without any token asked for. A token a line lacks is empty.
pub fn fields<'a>(line: &'a [u16], options: &Options<'_>) -> Option<Fields<'a>> {
    let delimiter = |unit: u16| match options.delims {
        Some(delims) => delims.contains(&unit),
        None => is_blank(unit),
    };
    let skip = |text: &'a [u16]| {
        let start = text
            .iter()
            .position(|&unit| !delimiter(unit))
            .unwrap_or(text.len());
        &text[start..]
    };
    let content = skip(line);
    if content.is_empty() || options.eol.is_some_and(|eol| content[0] == eol) {
        return None;
    }
    let mut fields = Fields {
        values: [&[]; 32],
        count: options.tokens.count(),
    };
    let last = 32 - options.tokens.mask.leading_zeros() as usize;
    let mut rest = content;
    let mut slot = 0;
    let mut any = false;
    for token in 1..=last {
        let length = rest
            .iter()
            .position(|&unit| delimiter(unit))
            .unwrap_or(rest.len());
        let value = &rest[..length];
        if options.tokens.mask & (1 << (token - 1)) != 0 {
            fields.values[slot] = value;
            slot += 1;
            any |= !value.is_empty();
        }
        rest = skip(&rest[length..]);
    }
    if options.tokens.star {
        fields.values[slot] = rest;
        any |= !rest.is_empty();
    }
    any.then_some(fields)
}

/// The modifier letters a `%~` reference may carry, at most.
const LETTERS: usize = 16;

/// A `%~` reference read at the start of `text` (after its `%~`): its modifier letters (lowercase),
/// the variable whose PATH-like value `$NAME:` names, the loop variable, and the units read.
struct Reference<'a> {
    letters: [u16; LETTERS],
    count: usize,
    search: Option<&'a [u16]>,
    variable: u16,
    length: usize,
}

/// The `%~` reference `text` starts with, `active` saying which characters are loop variables:
/// the longest run of modifier letters followed by a loop variable, or by `$NAME:` and one, as
/// cmd reads it (`%~fa` with the variable `a` is `a`'s full path, its `a` the variable). None when
/// no variable ends it.
fn reference<'a>(text: &'a [u16], active: &dyn Fn(u16) -> bool) -> Option<Reference<'a>> {
    let modifier = |unit: u16| {
        u8::try_from(fold(unit)).is_ok_and(|byte| MODIFIERS.contains(&byte.to_ascii_lowercase()))
    };
    let run = text.iter().take_while(|&&unit| modifier(unit)).count();
    let make = |letters: &[u16], search, variable, length| {
        let mut reference = Reference {
            letters: [0; LETTERS],
            count: letters.len().min(LETTERS),
            search,
            variable,
            length,
        };
        for (slot, &unit) in reference.letters.iter_mut().zip(letters) {
            *slot = u16::from(u8::try_from(fold(unit)).unwrap_or(0).to_ascii_lowercase());
        }
        reference
    };
    if text.get(run) == Some(&u16::from(b'$')) {
        let colon = text[run..]
            .iter()
            .position(|&unit| unit == u16::from(b':'))?
            + run;
        let variable = *text.get(colon + 1)?;
        return active(variable).then(|| {
            make(
                &text[..run],
                Some(&text[run + 1..colon]),
                variable,
                colon + 2,
            )
        });
    }
    (0..=run).rev().find_map(|length| {
        let variable = *text.get(length)?;
        active(variable).then(|| make(&text[..length], None, variable, length + 1))
    })
}

/// `body` with its loop variables replaced, in `out`: `%v` by `v`'s value as it is, `%~v` without
/// the quotes around it, and `%~` with modifier letters as a batch file's `%~1` is (the parts of
/// its full path, its attributes, its size: [`crate::modified`]); `%~$NAME:v` is the full path
/// of the first file named `v`'s value in the directories the variable NAME lists (`$PATH:`),
/// nothing when there is none, its letters applied to that path. A `%` before anything else
/// stays. `variables` are the loop's, by their character (case counts).
pub fn substitute<'b>(
    body: &[u16],
    variables: &[(u16, &[u16])],
    shell: &mut dyn Variables,
    out: &'b mut [u16],
) -> Result<&'b [u16], TooLong> {
    let value_of = |variable: u16| {
        variables
            .iter()
            .find(|(name, _)| *name == variable)
            .map(|(_, value)| *value)
    };
    let active = |unit: u16| value_of(unit).is_some();
    let mut length = 0;
    let mut at = 0;
    while at < body.len() {
        if body[at] != PERCENT {
            copy(&body[at..=at], out, &mut length)?;
            at += 1;
            continue;
        }
        let next = body.get(at + 1).copied();
        if next == Some(u16::from(b'~')) {
            if let Some(found) = reference(&body[at + 2..], &active) {
                let value = batch::unquote(value_of(found.variable).unwrap_or(&[]));
                let letters = &found.letters[..found.count];
                let end = at + 2 + found.length;
                if let Some(name) = found.search {
                    length += searched(value, name, letters, shell, &mut out[length..])?;
                } else if letters.is_empty() {
                    copy(value, out, &mut length)?;
                } else {
                    length += modified(value, letters, shell, &mut out[length..])?;
                }
                at = end;
                continue;
            }
        } else if let Some(value) = next.and_then(value_of) {
            copy(value, out, &mut length)?;
            at += 2;
            continue;
        }
        copy(&[PERCENT], out, &mut length)?;
        at += 1;
    }
    Ok(&out[..length])
}

/// `%~$NAME:v`: the first of NAME's directories (separated by `;`) holding the file `name`, its
/// full path with `letters` applied (all of it without letters), in `out`; nothing when none
/// does. The units written.
#[inline(never)]
fn searched(
    name: &[u16],
    variable: &[u16],
    letters: &[u16],
    shell: &mut dyn Variables,
    out: &mut [u16],
) -> Result<usize, TooLong> {
    let mut list = [0; crate::LINE];
    let Ok(Some(count)) = shell.get(variable, &mut list) else {
        return Ok(0);
    };
    if name.is_empty() {
        return Ok(0);
    }
    for directory in list[..count].split(|&unit| unit == u16::from(b';')) {
        let directory = batch::unquote(trim_blanks(directory));
        if directory.is_empty() {
            continue;
        }
        let mut path = [0; crate::FOUND];
        let mut length = 0;
        let separator: &[u16] = if directory.last() == Some(&u16::from(b'\\')) {
            &[]
        } else {
            &[b'\\' as u16]
        };
        if copy(directory, &mut path, &mut length).is_err()
            || copy(separator, &mut path, &mut length).is_err()
            || copy(name, &mut path, &mut length).is_err()
        {
            continue;
        }
        let mut full = [0; crate::FOUND];
        let full = match shell.full_path(&path[..length], &mut full) {
            Some(count) => &full[..count],
            None => continue,
        };
        if shell.file(full).is_some() {
            let all = [u16::from(b'f')];
            let letters = if letters.is_empty() {
                &all[..]
            } else {
                letters
            };
            return modified(full, letters, shell, out);
        }
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow::tests::{narrow, wide, Fake};

    fn header(text: &str) -> For<'static> {
        let text: &'static [u16] = Box::leak(wide(text).into_boxed_slice());
        match parse(text) {
            Ok(Header::For(header)) => header,
            other => panic!("not a for: {other:?}"),
        }
    }

    fn error(text: &str) -> String {
        let text = wide(text);
        parse(&text).unwrap_err().to_string()
    }

    #[test]
    fn the_header_s_parts() {
        let plain = header("for %a in (x y) do echo %a");
        assert_eq!(plain.variable, u16::from(b'a'));
        assert_eq!(narrow(plain.set), "x y");
        assert_eq!(narrow(plain.command()), "echo %a");
        assert_eq!(plain.mode, Mode::Items);
        let directories = header("FOR /D %B IN (*) DO (echo)");
        assert!(directories.directories);
        assert_eq!(directories.variable, u16::from(b'B'));
        assert_eq!(narrow(directories.command()), "(echo)");
        assert_eq!(header("for /r %a in (.) do x").recursive, Some(&[][..]));
        assert_eq!(
            header("for /r \"C:\\a b\" %a in (.) do x")
                .recursive
                .map(narrow),
            Some("\"C:\\a b\"".into())
        );
        assert_eq!(header("for /l %i in (1,1,3) do x").mode, Mode::Range);
        let lines = header("for /f \"tokens=1,2* delims=,\" %i in ('ver') do x");
        let Mode::Lines(options) = lines.mode else {
            panic!("no /f");
        };
        assert_eq!(
            options.tokens,
            Tokens {
                mask: 3,
                star: true
            }
        );
        assert_eq!(options.delims.map(narrow), Some(",".into()));
        assert_eq!(narrow(lines.set), "'ver'");
        // A set's parentheses and quotes are its own.
        assert_eq!(
            narrow(header("for %a in (\"a)\" (b)) do x").set),
            "\"a)\" (b)"
        );
        assert_eq!(narrow(header("for %a in(x)do x").set), "x");
        assert_eq!(parse(&wide("for /?")).map(|header| header.start()), Ok(6));
    }

    #[test]
    fn malformed_headers() {
        let incorrect = crate::SYNTAX.to_string();
        let unexpected = |what: &str| format!("{what} was unexpected at this time.\r\n");
        assert_eq!(error("for %a in (x) do"), incorrect);
        assert_eq!(error("for %a in (x"), incorrect);
        assert_eq!(error("for"), incorrect);
        assert_eq!(error("for x in (x) do y"), unexpected("x"));
        assert_eq!(error("for %%a in (x) do y"), unexpected("%%a"));
        assert_eq!(error("for %a of (x) do y"), unexpected("of"));
        assert_eq!(error("for %a in x do y"), unexpected("x"));
        assert_eq!(error("for %a in (x) echo y"), unexpected("echo"));
        assert_eq!(error("for /x %a in (x) do y"), unexpected("/x"));
        assert_eq!(
            error("for /f \"bogus\" %a in (x) do y"),
            unexpected("bogus")
        );
    }

    #[test]
    fn a_set_s_items() {
        let items = |set: &str| {
            let set = wide(set);
            Items(&set).map(narrow).collect::<Vec<_>>()
        };
        assert_eq!(items("a b,c;d=e"), ["a", "b", "c", "d", "e"]);
        assert_eq!(items(" \"a b\" *.txt "), ["\"a b\"", "*.txt"]);
        assert!(items("").is_empty());
    }

    #[test]
    fn l_s_numbers() {
        let numbers = |set: &str| range(&wide(set)).take(10).collect::<Vec<_>>();
        assert_eq!(numbers("1,1,5"), [1, 2, 3, 4, 5]);
        assert_eq!(numbers("5 -2 0"), [5, 3, 1]);
        assert_eq!(numbers("1,2,6"), [1, 3, 5]);
        assert_eq!(numbers("3,1,1"), Vec::<i64>::new());
        assert_eq!(numbers("4"), Vec::<i64>::new());
        assert_eq!(numbers("0,0,0").len(), 10);
    }

    #[test]
    fn f_s_options() {
        let read = |text: &str| options(Box::leak(wide(text).into_boxed_slice())).unwrap();
        let options = read("eol=# skip=2 delims=;, tokens=2-3,5* usebackq");
        assert_eq!(options.eol, Some(u16::from(b'#')));
        assert_eq!(options.skip, 2);
        assert_eq!(options.delims.map(narrow), Some(";,".into()));
        assert_eq!(
            options.tokens,
            Tokens {
                mask: 0b10110,
                star: true
            }
        );
        assert!(options.backquote);
        // A blank last among the delimiters is one.
        assert_eq!(
            read("tokens=* delims=, ").delims.map(narrow),
            Some(", ".into())
        );
        assert_eq!(read("delims=").delims.map(narrow), Some("".into()));
        assert_eq!(
            read("tokens=*").tokens,
            Tokens {
                mask: 0,
                star: true
            }
        );
        assert_eq!(read("").eol, Some(u16::from(b';')));
        assert!(super::options(&wide("tokens=0")).is_err());
        assert!(super::options(&wide("tokens=32")).is_err());
        assert!(super::options(&wide("skip=x")).is_err());
    }

    #[test]
    fn f_s_sources() {
        let of =
            |set: &str, backquote| match source(Box::leak(wide(set).into_boxed_slice()), backquote)
            {
                Source::Files(text) => format!("files {}", narrow(text)),
                Source::Text(text) => format!("text {}", narrow(text)),
                Source::Command(text) => format!("command {}", narrow(text)),
            };
        assert_eq!(of("\"a b\"", false), "text a b");
        assert_eq!(of("'ver /x'", false), "command ver /x");
        assert_eq!(of("a.txt b.txt", false), "files a.txt b.txt");
        assert_eq!(of("\"a b.txt\"", true), "files \"a b.txt\"");
        assert_eq!(of("'it''s'", true), "text it''s");
        assert_eq!(of("`ver`", true), "command ver");
    }

    #[test]
    fn a_line_s_fields() {
        let cut = |line: &str, spec: &str| {
            let options = options(Box::leak(wide(spec).into_boxed_slice())).unwrap();
            let line: &'static [u16] = Box::leak(wide(line).into_boxed_slice());
            fields(line, &options).map(|fields| {
                fields.values[..fields.count]
                    .iter()
                    .map(|value| narrow(value))
                    .collect::<Vec<_>>()
            })
        };
        assert_eq!(cut("  one two  three ", ""), Some(vec!["one".into()]));
        assert_eq!(
            cut("one two  three four", "tokens=1,3*"),
            Some(vec!["one".into(), "three".into(), "four".into()])
        );
        assert_eq!(
            cut("a,b,,c", "tokens=1-3 delims=,"),
            Some(vec!["a".into(), "b".into(), "c".into()])
        );
        assert_eq!(
            cut("  all of it  ", "tokens=*"),
            Some(vec!["all of it  ".into()])
        );
        assert_eq!(
            cut("one", "tokens=1,2"),
            Some(vec!["one".into(), "".into()])
        );
        assert_eq!(cut("one", "tokens=2"), None);
        assert_eq!(cut(";comment", ""), None);
        assert_eq!(cut("  ;comment", ""), None);
        assert_eq!(cut("#x", "eol=#"), None);
        assert_eq!(cut(";x", "eol=#"), Some(vec![";x".into()]));
        assert_eq!(cut("   ", ""), None);
        assert_eq!(cut(" a b", "delims="), Some(vec![" a b".into()]));
    }

    #[test]
    fn the_variables_are_replaced() {
        let mut shell = Fake::new(
            &[("PATH", "C:\\BIN;C:\\TOOLS")],
            &[("C:\\F2K\\batclr.out", 3), ("C:\\TOOLS\\x.exe", 9)],
        );
        let run = |body: &str, variables: &[(char, &str)], shell: &mut Fake| {
            let body = wide(body);
            let values: Vec<(u16, Vec<u16>)> = variables
                .iter()
                .map(|(name, value)| (*name as u16, wide(value)))
                .collect();
            let refs: Vec<(u16, &[u16])> = values
                .iter()
                .map(|(name, value)| (*name, value.as_slice()))
                .collect();
            let mut out = [0; 256];
            narrow(substitute(&body, &refs, shell, &mut out).unwrap())
        };
        // batclr's size of its output.
        assert_eq!(
            run(
                "echo   it wrote %~zF bytes",
                &[('F', "batclr.out")],
                &mut shell
            ),
            "echo   it wrote 3 bytes"
        );
        assert_eq!(
            run("%a-%A-%b", &[('a', "1"), ('A', "2")], &mut shell),
            "1-2-%b"
        );
        assert_eq!(run("%~a", &[('a', "\"q r\"")], &mut shell), "q r");
        // `%~fa`: the full path of `a`, the `a` the variable.
        assert_eq!(run("%~fa", &[('a', "x.txt")], &mut shell), "C:\\F2K\\x.txt");
        assert_eq!(run("%~nxF", &[('F', "C:\\d\\n.e")], &mut shell), "n.e");
        assert_eq!(
            run("%~$PATH:a", &[('a', "x.exe")], &mut shell),
            "C:\\TOOLS\\x.exe"
        );
        assert_eq!(
            run("%~dp$PATH:a", &[('a', "x.exe")], &mut shell),
            "C:\\TOOLS\\"
        );
        assert_eq!(run("[%~$PATH:a]", &[('a', "y.exe")], &mut shell), "[]");
        // Not a variable: the text stays.
        assert_eq!(
            run("100% %~q %%a", &[('a', "1")], &mut shell),
            "100% %~q %1"
        );
    }
}
