//! A command line's syntax, as Windows 2000's cmd reads a line once its variables are expanded:
//! the operators that join commands (`&`, `&&`, `||`, `|`), groups in parentheses, redirections
//! (`<`, `>`, `>>`, `n>`, `n>&m`), and the escapes (`^`) and quotes that make those characters
//! plain text.
//!
//! The operators bind, from the loosest: `&` (one command, then the next), `||` (the next when the
//! one before fails), `&&` (the next when the one before succeeds), `|` (a pipe between the two).
//! A `(` where a command starts opens a group, which its matching `)` closes; anywhere else, and a
//! `)` outside a group, is text. Outside quotes, `^` makes the unit after it text, and goes; inside
//! quotes every unit is text, the quotes kept.

use core::fmt;
use core::ops::Range;

use crate::{is_blank, is_delimiter, QUOTE};

const CARET: u16 = b'^' as u16;
const AMPERSAND: u16 = b'&' as u16;
const BAR: u16 = b'|' as u16;
const LESS: u16 = b'<' as u16;
const GREATER: u16 = b'>' as u16;
const OPEN: u16 = b'(' as u16;
const CLOSE: u16 = b')' as u16;
const AT: u16 = b'@' as u16;

/// An operator that joins two commands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Join {
    /// `&`: the first command, then the second.
    Then,
    /// `||`: the second when the first fails (its return code is not 0).
    OrElse,
    /// `&&`: the second when the first succeeds (its return code is 0).
    AndThen,
    /// `|`: both at once, the first's standard output the second's standard input.
    Pipe,
}

impl Join {
    /// The operators, from the loosest.
    const LEVELS: [Join; 4] = [Join::Then, Join::OrElse, Join::AndThen, Join::Pipe];

    /// The operator as written.
    pub fn text(self) -> &'static str {
        match self {
            Join::Then => "&",
            Join::OrElse => "||",
            Join::AndThen => "&&",
            Join::Pipe => "|",
        }
    }

    /// The operator binding next tighter, None for `|`.
    fn tighter(self) -> Option<Join> {
        let level = Join::LEVELS.iter().position(|&join| join == self)?;
        Join::LEVELS.get(level + 1).copied()
    }
}

/// What a run of a line's units is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Token {
    /// Text: a unit outside quotes, or one inside them (a quote included).
    Text,
    /// `^` and the unit it makes text (alone, at the line's end).
    Escape,
    /// A blank outside quotes.
    Blank,
    /// An operator joining two commands.
    Join(Join),
    /// The `(` opening a group, or the `)` closing one.
    Open,
    Close,
    /// A redirection's operator, with its handle and duplicated handle when they are written
    /// (`>`, `2>>`, `<`, `2>&1`): its target follows unless it duplicates a handle.
    Redirection,
}

/// Whether `unit`, before a digit, lets the digit be a redirection's handle: a delimiter (a
/// blank, `,`, `;` or `=`: `echo x=2> f` redirects handle 2), or an operator's character.
fn before_handle(unit: u16) -> bool {
    is_delimiter(unit) || [AMPERSAND, BAR, OPEN, CLOSE].contains(&unit)
}

fn digit(unit: Option<u16>) -> Option<u8> {
    unit.and_then(|unit| u8::try_from(unit).ok())
        .filter(u8::is_ascii_digit)
        .map(|byte| byte - b'0')
}

/// A line's tokens, in order, with the units each covers.
struct Tokens<'a> {
    line: &'a [u16],
    at: usize,
    quoted: bool,
    /// The groups open.
    depth: usize,
    /// Whether a command starts here: a `(` opens a group.
    start: bool,
}

impl<'a> Tokens<'a> {
    fn new(line: &'a [u16]) -> Self {
        Tokens {
            line,
            at: 0,
            quoted: false,
            depth: 0,
            start: true,
        }
    }

    /// The length of the redirection operator at `at` (a handle's digit, `<`, `>` or `>>`, then
    /// `&` and a digit), 0 for none.
    fn redirection(&self, at: usize) -> usize {
        let line = self.line;
        let mut end = at;
        if digit(line.get(at).copied()).is_some() {
            let handle = at == 0 || before_handle(line[at - 1]);
            if !handle || !matches!(line.get(at + 1), Some(&LESS | &GREATER)) {
                return 0;
            }
            end += 1;
        }
        match line.get(end) {
            Some(&LESS) => end += 1,
            Some(&GREATER) => {
                end += 1;
                if line.get(end) == Some(&GREATER) {
                    end += 1;
                }
            }
            _ => return 0,
        }
        if line.get(end) == Some(&AMPERSAND) && digit(line.get(end + 1).copied()).is_some() {
            end += 2;
        }
        end - at
    }
}

impl Iterator for Tokens<'_> {
    type Item = (Token, Range<usize>);

    fn next(&mut self) -> Option<(Token, Range<usize>)> {
        let at = self.at;
        let unit = *self.line.get(at)?;
        let next = self.line.get(at + 1).copied();
        let (token, length) = if self.quoted {
            self.quoted = unit != QUOTE;
            (Token::Text, 1)
        } else {
            match unit {
                QUOTE => {
                    self.quoted = true;
                    self.start = false;
                    (Token::Text, 1)
                }
                CARET => {
                    self.start = false;
                    (Token::Escape, if next.is_some() { 2 } else { 1 })
                }
                AMPERSAND => {
                    self.start = true;
                    if next == Some(AMPERSAND) {
                        (Token::Join(Join::AndThen), 2)
                    } else {
                        (Token::Join(Join::Then), 1)
                    }
                }
                BAR => {
                    self.start = true;
                    if next == Some(BAR) {
                        (Token::Join(Join::OrElse), 2)
                    } else {
                        (Token::Join(Join::Pipe), 1)
                    }
                }
                OPEN if self.start => {
                    self.depth += 1;
                    (Token::Open, 1)
                }
                CLOSE if self.depth > 0 => {
                    self.depth -= 1;
                    self.start = false;
                    (Token::Close, 1)
                }
                _ if is_blank(unit) => (Token::Blank, 1),
                _ => match self.redirection(at) {
                    0 => {
                        // `@` before a command hides its echo: the command still starts after it.
                        self.start &= unit == AT;
                        (Token::Text, 1)
                    }
                    length => (Token::Redirection, length),
                },
            }
        };
        self.at = at + length;
        Some((token, at..self.at))
    }
}

/// Why a line cannot run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Syntax<'a> {
    /// What cmd says of most malformed lines: `The syntax of the command is incorrect.`
    Incorrect,
    /// A text where it cannot be: `& was unexpected at this time.`
    Unexpected(&'a [u16]),
}

impl fmt::Display for Syntax<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Syntax::Incorrect => f.write_str(crate::SYNTAX),
            Syntax::Unexpected(text) => {
                write!(f, "{} was unexpected at this time.\r\n", crate::Text(text))
            }
        }
    }
}

/// The parts of a text its top-level operator `join` separates (outside any group), as
/// [`Parts`] gives them, each with the operator after it (None for the last).
pub struct Parts<'a> {
    text: &'a [u16],
    join: Join,
    tokens: Tokens<'a>,
    from: usize,
    done: bool,
}

/// `text`'s parts separated by `join` at its top level.
pub fn parts(text: &[u16], join: Join) -> Parts<'_> {
    Parts {
        text,
        join,
        tokens: Tokens::new(text),
        from: 0,
        done: false,
    }
}

impl<'a> Iterator for Parts<'a> {
    type Item = (&'a [u16], Option<&'a [u16]>);

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        let mut depth = 0usize;
        for (token, range) in self.tokens.by_ref() {
            match token {
                Token::Open => depth += 1,
                Token::Close => depth = depth.saturating_sub(1),
                Token::Join(join) if join == self.join && depth == 0 => {
                    let part = &self.text[self.from..range.start];
                    self.from = range.end;
                    return Some((part, Some(&self.text[range])));
                }
                _ => {}
            }
        }
        self.done = true;
        Some((&self.text[self.from..], None))
    }
}

/// Whether `text` holds no command: blanks alone.
fn blank(text: &[u16]) -> bool {
    text.iter().all(|&unit| is_blank(unit))
}

/// What a command between the operators is.
#[derive(Debug, PartialEq, Eq)]
pub enum Element<'a> {
    /// `( ... )`: the line inside the parentheses, and the redirections after them.
    Group {
        inner: &'a [u16],
        redirections: &'a [u16],
    },
    /// A command, its redirections among its words.
    Simple(&'a [u16]),
}

/// What `text`, a command between the operators, is: a group when a `(` opens it (Incorrect when
/// no `)` closes it), otherwise a simple command.
pub fn element(text: &[u16]) -> Result<Element<'_>, Syntax<'_>> {
    let mut tokens = Tokens::new(text);
    let mut opened = None;
    for (token, range) in tokens.by_ref() {
        match token {
            Token::Blank => {}
            Token::Open => {
                opened = Some(range.end);
                break;
            }
            _ => return Ok(Element::Simple(text)),
        }
    }
    let Some(inner_start) = opened else {
        return Ok(Element::Simple(text));
    };
    let mut depth = 1;
    for (token, range) in tokens {
        match token {
            Token::Open => depth += 1,
            Token::Close => {
                depth -= 1;
                if depth == 0 {
                    return Ok(Element::Group {
                        inner: &text[inner_start..range.start],
                        redirections: &text[range.end..],
                    });
                }
            }
            _ => {}
        }
    }
    Err(Syntax::Incorrect)
}

/// Whether `line` can run: None when it can, else why not. A command missing before an operator
/// is unexpected (`& was unexpected at this time.`), one missing after `&&`, `||` or `|` is
/// incorrect (a line may end with `&`); so are a group never closed, an empty one, a redirection
/// without a target or one past [`REDIRECTIONS`]. After a group's `)` only redirections may
/// follow: the first word of anything else is unexpected.
pub fn check(line: &[u16]) -> Result<(), Syntax<'_>> {
    check_at(line, Join::Then)
}

fn check_at(text: &[u16], join: Join) -> Result<(), Syntax<'_>> {
    let mut first = true;
    for (part, after) in parts(text, join) {
        if blank(part) {
            match after {
                // An empty command before an operator, the line's first or between two.
                Some(operator) => return Err(Syntax::Unexpected(operator)),
                // An empty one after the last: what `&` allows, and nothing alone.
                None if join == Join::Then || first => {}
                None => return Err(Syntax::Incorrect),
            }
        } else {
            match join.tighter() {
                Some(tighter) => check_at(part, tighter)?,
                None => check_element(part)?,
            }
        }
        first = false;
    }
    Ok(())
}

fn check_element(text: &[u16]) -> Result<(), Syntax<'_>> {
    match element(text)? {
        Element::Group {
            inner,
            redirections,
        } => {
            if blank(inner) {
                return Err(Syntax::Incorrect);
            }
            check(inner)?;
            let mut list = Redirections::default();
            let rest = scan(redirections, &mut |_| {}, &mut list)?;
            match rest {
                None => Ok(()),
                Some(word) => Err(Syntax::Unexpected(word)),
            }
        }
        Element::Simple(text) => {
            let mut list = Redirections::default();
            scan(text, &mut |_| {}, &mut list).map(|_| ())
        }
    }
}

/// What a redirection does with its handle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// `<`: read from the target.
    Input,
    /// `>`: written to the target, a file emptied first.
    Output,
    /// `>>`: written after the target's end.
    Append,
}

/// What a redirection's handle becomes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target<'a> {
    /// The file (or device) its name names, as written: its quotes and escapes still in it (see
    /// [`file_name`]).
    File(&'a [u16]),
    /// A duplicate of another handle (`2>&1`).
    Handle(u8),
}

/// One redirection: its handle (0 the standard input, 1 the output, 2 the error), what it does,
/// and where to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Redirection<'a> {
    pub handle: u8,
    pub kind: Kind,
    pub target: Target<'a>,
}

impl fmt::Display for Redirection<'_> {
    /// As cmd shows it when it echoes a command: the handle, the operator, the target (`1>out`,
    /// `2>&1`, `0<in`).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let operator = match self.kind {
            Kind::Input => "<",
            Kind::Output => ">",
            Kind::Append => ">>",
        };
        write!(f, "{}{operator}", self.handle)?;
        match self.target {
            Target::File(name) => crate::Text(name).fmt(f),
            Target::Handle(handle) => write!(f, "&{handle}"),
        }
    }
}

/// The redirections a command may carry.
pub const REDIRECTIONS: usize = 16;

/// A command's redirections, in the order they are written (and applied).
pub struct Redirections<'a> {
    list: [Redirection<'a>; REDIRECTIONS],
    count: usize,
}

impl Default for Redirections<'_> {
    fn default() -> Self {
        Redirections {
            list: [Redirection {
                handle: 0,
                kind: Kind::Input,
                target: Target::Handle(0),
            }; REDIRECTIONS],
            count: 0,
        }
    }
}

impl<'a> Redirections<'a> {
    /// The redirections, in order.
    pub fn list(&self) -> &[Redirection<'a>] {
        &self.list[..self.count]
    }

    fn push(&mut self, redirection: Redirection<'a>) -> Result<(), Syntax<'a>> {
        *self.list.get_mut(self.count).ok_or(Syntax::Incorrect)? = redirection;
        self.count += 1;
        Ok(())
    }
}

/// The redirection an operator's units (`2>>`, `<`, `>&1`) write, its target `file` when it
/// duplicates no handle.
fn redirection<'a>(operator: &[u16], file: &'a [u16]) -> Redirection<'a> {
    let (handle, rest) = match digit(operator.first().copied()) {
        Some(handle) => (Some(handle), &operator[1..]),
        None => (None, operator),
    };
    let (kind, rest) = match rest {
        [LESS, rest @ ..] => (Kind::Input, rest),
        [GREATER, GREATER, rest @ ..] => (Kind::Append, rest),
        [_, rest @ ..] => (Kind::Output, rest),
        [] => (Kind::Output, rest),
    };
    let target = match rest {
        [AMPERSAND, unit] => Target::Handle(digit(Some(*unit)).unwrap_or(0)),
        _ => Target::File(file),
    };
    let default = if kind == Kind::Input { 0 } else { 1 };
    Redirection {
        handle: handle.unwrap_or(default),
        kind,
        target,
    }
}

/// `text`, a command between the operators (or what follows a group's `)`), scanned: its text with
/// the redirections taken out and the escapes resolved handed to `put` a unit at a time, its
/// redirections into `redirections`. Returns the text's first word when there is one (what a
/// group's redirections may not hold). Incorrect for a redirection without a target, or too many.
fn scan<'a>(
    text: &'a [u16],
    put: &mut dyn FnMut(u16),
    redirections: &mut Redirections<'a>,
) -> Result<Option<&'a [u16]>, Syntax<'a>> {
    let mut tokens = Tokens::new(text).peekable();
    let mut word: Option<Range<usize>> = None;
    let mut first = None;
    while let Some((token, range)) = tokens.next() {
        match token {
            Token::Redirection => {
                let operator = &text[range.clone()];
                let duplicates = operator
                    .last()
                    .is_some_and(|&unit| digit(Some(unit)).is_some())
                    && operator.len() >= 2
                    && operator[operator.len() - 2] == AMPERSAND;
                let mut file = &text[range.end..range.end];
                if !duplicates {
                    while tokens
                        .next_if(|(token, _)| *token == Token::Blank)
                        .is_some()
                    {}
                    let mut target: Option<Range<usize>> = None;
                    while let Some((_, taken)) =
                        tokens.next_if(|(token, _)| matches!(token, Token::Text | Token::Escape))
                    {
                        target =
                            Some(target.map_or(taken.clone(), |target| target.start..taken.end));
                    }
                    file = &text[target.ok_or(Syntax::Incorrect)?];
                }
                redirections.push(redirection(operator, file))?;
                if let Some(word) = word.take() {
                    first.get_or_insert(word);
                }
                continue;
            }
            Token::Escape => {
                if let Some(&unit) = text
                    .get(range.start + 1..range.end)
                    .and_then(<[u16]>::first)
                {
                    put(unit);
                }
            }
            _ => {
                for &unit in &text[range.clone()] {
                    put(unit);
                }
            }
        }
        if token == Token::Blank {
            if let Some(word) = word.take() {
                first.get_or_insert(word);
            }
        } else {
            word = Some(word.map_or(range.clone(), |word| word.start..range.end));
        }
    }
    if let Some(word) = word {
        first.get_or_insert(word);
    }
    Ok(first.map(|range| &text[range]))
}

/// A simple command's text with its redirections taken out and its escapes resolved, in `out`, and
/// its redirections in `redirections`: what runs. None when the text does not fit `out`;
/// [`check`] has found the line well formed.
pub fn simple<'a, 'b>(
    text: &'a [u16],
    out: &'b mut [u16],
    redirections: &mut Redirections<'a>,
) -> Option<&'b [u16]> {
    let mut length = 0;
    let mut fits = true;
    let mut put = |unit: u16| match out.get_mut(length) {
        Some(slot) => {
            *slot = unit;
            length += 1;
        }
        None => fits = false,
    };
    scan(text, &mut put, redirections).ok()?;
    fits.then_some(&out[..length])
}

/// A group's redirections (what follows its `)`), into `redirections`.
pub fn group_redirections<'a>(text: &'a [u16], redirections: &mut Redirections<'a>) {
    let _ = scan(text, &mut |_| {}, redirections);
}

/// The name a redirection's file target gives, in `out`: its quotes dropped and its escapes
/// resolved (`"a b.txt"` names `a b.txt`). None when it does not fit.
pub fn file_name<'a>(target: &[u16], out: &'a mut [u16]) -> Option<&'a [u16]> {
    let mut length = 0;
    for (token, range) in Tokens::new(target) {
        let units = match token {
            Token::Escape => &target[(range.start + 1).min(range.end)..range.end],
            _ => &target[range],
        };
        for &unit in units.iter().filter(|&&unit| unit != QUOTE) {
            *out.get_mut(length)? = unit;
            length += 1;
        }
    }
    Some(&out[..length])
}

/// Whether `line` ends with a `^` outside quotes that escapes nothing: in a batch file, the next
/// line goes on this one, in that `^`'s place.
pub fn continues(line: &[u16]) -> bool {
    Tokens::new(line)
        .last()
        .is_some_and(|(token, range)| token == Token::Escape && range.len() == 1)
}

/// Whether `line` is one simple command (no operator, no group): its redirections are echoed as
/// cmd rebuilds them.
pub fn single(line: &[u16]) -> bool {
    !Tokens::new(line).any(|(token, _)| matches!(token, Token::Join(_) | Token::Open))
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

    fn split(text: &str, join: Join) -> Vec<(String, Option<String>)> {
        let text = wide(text);
        parts(&text, join)
            .map(|(part, after)| (narrow(part), after.map(narrow)))
            .collect()
    }

    fn checked(line: &str) -> Result<(), String> {
        let line = wide(line);
        check(&line).map_err(|error| error.to_string())
    }

    /// The text and the redirections (as cmd echoes them) of a simple command.
    fn command(text: &str) -> (String, Vec<String>) {
        let text = wide(text);
        let mut out = [0; 64];
        let mut redirections = Redirections::default();
        let cleaned = simple(&text, &mut out, &mut redirections).unwrap();
        (
            narrow(cleaned),
            redirections
                .list()
                .iter()
                .map(|redirection| redirection.to_string())
                .collect(),
        )
    }

    #[test]
    fn the_operators_split_at_their_own_level() {
        assert_eq!(
            split("a & b && c|d", Join::Then),
            [("a ".into(), Some("&".into())), (" b && c|d".into(), None)]
        );
        assert_eq!(
            split("b && c|d", Join::AndThen),
            [("b ".into(), Some("&&".into())), (" c|d".into(), None)]
        );
        assert_eq!(
            split("a||b|c", Join::Pipe),
            [("a||b".into(), Some("|".into())), ("c".into(), None)]
        );
        assert_eq!(split("a||b", Join::OrElse).len(), 2);
        assert_eq!(split("", Join::Then), [("".into(), None)]);
    }

    #[test]
    fn quotes_and_carets_make_operators_text() {
        assert_eq!(split("echo \"a&b\"", Join::Then).len(), 1);
        assert_eq!(split("echo a^&b", Join::Then).len(), 1);
        assert_eq!(split("echo a^^&b", Join::Then).len(), 2);
        assert_eq!(split("echo \"a\" & b", Join::Then).len(), 2);
        assert_eq!(command("echo a^&b ^| c^^").0, "echo a&b | c^");
        assert_eq!(command("echo \"^&\" ^\"&\"").0, "echo \"^&\" \"&\"");
        // A caret ending the line goes.
        assert_eq!(command("echo a^").0, "echo a");
        assert_eq!(command("echo a ^> b").0, "echo a > b");
    }

    #[test]
    fn a_handle_duplication_is_no_ampersand() {
        assert_eq!(split("x > f 2>&1 & y", Join::Then).len(), 2);
        assert_eq!(
            command("x > f 2>&1"),
            ("x  ".into(), vec!["1>f".into(), "2>&1".into()])
        );
    }

    #[test]
    fn groups_hold_their_operators() {
        assert_eq!(
            split("(a & b) & c", Join::Then),
            [("(a & b) ".into(), Some("&".into())), (" c".into(), None)]
        );
        let text = wide(" (a & (b)) > f");
        assert_eq!(
            element(&text),
            Ok(Element::Group {
                inner: &wide("a & (b)"),
                redirections: &wide(" > f")
            })
        );
        // A parenthesis inside a command is text, and so is a `)` outside a group.
        let text = wide("echo (a) b)");
        assert_eq!(element(&text), Ok(Element::Simple(&text)));
        assert_eq!(split("echo (a & b)", Join::Then).len(), 2);
        assert_eq!(split("x & (y & z) & w", Join::Then).len(), 3);
        assert_eq!(split("x|(y & z)", Join::Pipe).len(), 2);
    }

    #[test]
    fn redirections_anywhere_in_the_command() {
        assert_eq!(
            command("echo one> f"),
            ("echo one".into(), vec!["1>f".into()])
        );
        assert_eq!(
            command("> f echo the redirection first"),
            (" echo the redirection first".into(), vec!["1>f".into()])
        );
        assert_eq!(
            command("echo two>>f"),
            ("echo two".into(), vec!["1>>f".into()])
        );
        assert_eq!(
            command("prog read < in"),
            ("prog read ".into(), vec!["0<in".into()])
        );
        assert_eq!(
            command("prog 2> err > out x"),
            ("prog   x".into(), vec!["2>err".into(), "1>out".into()])
        );
        assert_eq!(
            command("x >\"a b.txt\" y"),
            ("x  y".into(), vec!["1>\"a b.txt\"".into()])
        );
        assert_eq!(command("x 3>f 1>&3 2<&0").1, ["3>f", "1>&3", "2<&0"]);
        assert_eq!(command("x>f>g").1, ["1>f", "1>g"]);
    }

    #[test]
    fn a_digit_is_a_handle_only_where_a_word_starts() {
        // `echo 1> f`: the 1 is the handle, echo has no text.
        assert_eq!(command("echo 1> f"), ("echo ".into(), vec!["1>f".into()]));
        assert_eq!(
            command("echo a1> f"),
            ("echo a1".into(), vec!["1>f".into()])
        );
        assert_eq!(command("echo 2>f"), ("echo ".into(), vec!["2>f".into()]));
        assert_eq!(command("2>f echo x").1, ["2>f"]);
        assert_eq!(command("echo 12>f"), ("echo 12".into(), vec!["1>f".into()]));
        // batstd: after a delimiter, `=` among them, it is the handle.
        assert_eq!(
            command("echo x=2> f"),
            ("echo x=".into(), vec!["2>f".into()])
        );
        assert_eq!(
            command("echo x,2> f"),
            ("echo x,".into(), vec!["2>f".into()])
        );
    }

    #[test]
    fn a_file_name_loses_its_quotes_and_escapes() {
        let mut out = [0; 16];
        assert_eq!(
            file_name(&wide("\"a b\".txt"), &mut out)
                .map(narrow)
                .as_deref(),
            Some("a b.txt")
        );
        assert_eq!(
            file_name(&wide("a^&b"), &mut out).map(narrow).as_deref(),
            Some("a&b")
        );
        assert!(file_name(&wide(&"x".repeat(17)), &mut out).is_none());
    }

    #[test]
    fn malformed_lines() {
        let incorrect = Err(crate::SYNTAX.to_string());
        let unexpected = |what: &str| Err(format!("{what} was unexpected at this time.\r\n"));
        assert_eq!(checked("echo a & echo b && c || d | e"), Ok(()));
        assert_eq!(checked("echo a &"), Ok(()));
        assert_eq!(checked(""), Ok(()));
        assert_eq!(checked("  "), Ok(()));
        assert_eq!(checked("& echo a"), unexpected("&"));
        assert_eq!(checked("| echo a"), unexpected("|"));
        assert_eq!(checked("echo a && && b"), unexpected("&&"));
        assert_eq!(checked("echo a & & b"), unexpected("&"));
        assert_eq!(checked("echo a |"), incorrect);
        assert_eq!(checked("echo a ||"), incorrect);
        assert_eq!(checked("echo a &&  "), incorrect);
        assert_eq!(checked("echo a >"), incorrect);
        assert_eq!(checked("echo a > & b"), incorrect);
        assert_eq!(checked("(echo a"), incorrect);
        assert_eq!(checked("()"), incorrect);
        assert_eq!(checked("(echo a) > f 2>&1"), Ok(()));
        assert_eq!(checked("(echo a) b c"), unexpected("b"));
        assert_eq!(checked("(echo a & | b)"), unexpected("|"));
        let many = "echo a".to_string() + &" >f".repeat(REDIRECTIONS + 1);
        assert_eq!(checked(&many), incorrect);
    }

    #[test]
    fn a_caret_ending_a_line_continues_it() {
        assert!(continues(&wide("echo one ^")));
        assert!(!continues(&wide("echo one ^^")));
        assert!(continues(&wide("echo one ^^^")));
        assert!(!continues(&wide("echo \"one ^")));
        assert!(!continues(&wide("echo one")));
        assert!(!continues(&wide("")));
    }

    #[test]
    fn a_single_command_has_no_operator() {
        assert!(single(&wide("echo a > f 2>&1")));
        assert!(single(&wide("echo a^&b \"|\"")));
        assert!(!single(&wide("echo a & b")));
        assert!(!single(&wide("(echo a)")));
    }

    #[test]
    fn a_text_too_long_for_its_buffer_is_none() {
        let text = wide("echo abc");
        let mut out = [0; 4];
        assert!(simple(&text, &mut out, &mut Redirections::default()).is_none());
    }
}
