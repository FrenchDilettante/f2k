//! `set`'s two switches, as Windows 2000's `set /?` documents them with command extensions on:
//! `set /a expression`, which evaluates an expression of 32-bit signed integers (assigning the
//! variables it names), and `set /p name=prompt`, which sets a variable to a line of input. This
//! module reads the switches and evaluates the expressions; src/set_switch.rs makes the calls.
//!
//! An expression is read as `set /?` lists its operators, tightest first:
//!
//! | Operators                                       | Meaning                               |
//! | ----------------------------------------------- | ------------------------------------- |
//! | `( )`                                           | Grouping                              |
//! | `! ~ -`                                         | Logical not, bitwise not, negation    |
//! | `* / %`                                         | Multiplication, division, remainder   |
//! | `+ -`                                           | Addition, subtraction                 |
//! | `<< >>`                                         | Shifts (`>>` keeps the sign)          |
//! | `&`, `^`, `\|`                                  | Bitwise and, exclusive or, or         |
//! | `= *= /= %= += -= &= ^= \|= <<= >>=`            | Assignments, from the right           |
//! | `,`                                             | Separates expressions                 |
//!
//! Arithmetic wraps at 32 bits, as the processor's does; division truncates towards zero. Any
//! other word is a variable's name, its value read as a number (0 when it is undefined or holds
//! none). Numbers are decimal, hexadecimal after `0x` and octal after a leading `0`. Quotes are
//! blanks. The expression is evaluated from left to right as it is read, with a stack of operands
//! and one of operators, so that an assignment before an error stays made.

use crate::{is_blank, set, skip_blanks, trim_blanks, Set, MAX_LINE, QUOTE};

/// What `set`'s argument asks for with a switch.
#[derive(Debug, PartialEq, Eq)]
pub enum Switch<'a> {
    /// `set /a expression`.
    Arithmetic(&'a [u16]),
    /// `set /p name=prompt`: `prompt` printed (it may be empty), then a line read into `name`.
    Prompt { name: &'a [u16], prompt: &'a [u16] },
    /// `set /a` without an expression, `set /p` without `name=`, or with an empty name.
    Incorrect,
}

/// The switch `set`'s argument (its leading blanks skipped) starts with, `/a` or `/p` in either
/// case: None for any other argument. What follows the switch's letter is the expression, or
/// `name=prompt` read as `set`'s own `name=value` is (its quoted form too: `set /p "X=? "`).
pub fn switch(argument: &[u16]) -> Option<Switch<'_>> {
    let (&slash, rest) = argument.split_first()?;
    let (&letter, rest) = rest.split_first()?;
    if slash != u16::from(b'/') {
        return None;
    }
    match u8::try_from(letter).map(|letter| letter.to_ascii_lowercase()) {
        Ok(b'a') => Some(if trim_blanks(rest).is_empty() {
            Switch::Incorrect
        } else {
            Switch::Arithmetic(rest)
        }),
        Ok(b'p') => Some(match set(skip_blanks(rest)) {
            Set::Assign { name, value } => Switch::Prompt {
                name,
                prompt: value,
            },
            Set::Show(_) | Set::Incorrect => Switch::Incorrect,
        }),
        _ => None,
    }
}

/// Why an expression cannot be evaluated: each prints Windows 2000's message, and leaves an
/// ERRORLEVEL of its own.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Error {
    /// An operand is missing: the expression ends after an operator, or an operator follows
    /// another; or an assignment has no variable on its left.
    MissingOperand,
    /// An operator is missing: two operands follow each other.
    MissingOperator,
    /// A `(` is not closed, or a `)` closes none.
    Unbalanced,
    /// A word starting with a digit is not a number (`08`, `0x`, `1a`).
    InvalidNumber,
    /// A division or a remainder by zero.
    DivideByZero,
    /// A variable could not be set: the Win32 error.
    Environment(u32),
}

impl Error {
    /// The message printed (on the standard error), CR LF included: None for a variable that
    /// could not be set, which the shell reports as it reports a Win32 error.
    pub fn text(self) -> Option<&'static str> {
        Some(match self {
            Error::MissingOperand => "Missing operand.\r\n",
            Error::MissingOperator => "Missing operator.\r\n",
            Error::Unbalanced => "Unbalanced parenthesis.\r\n",
            Error::InvalidNumber => {
                "Invalid number.  Numeric constants are either decimal (17), hexadecimal (0x11), \
                 or octal (021).\r\n"
            }
            Error::DivideByZero => "Divide by zero error.\r\n",
            Error::Environment(_) => return None,
        })
    }

    /// The ERRORLEVEL (and return code) it leaves: the number of cmd's message, as Windows' cmd
    /// leaves it (ss64's list, which numbers the message for a constant too large for 32 bits
    /// 1073750992, between the invalid number's and the division's), or 1 for a variable that
    /// could not be set.
    pub fn errorlevel(self) -> u32 {
        match self {
            Error::Unbalanced => 1_073_750_988,
            Error::MissingOperand => 1_073_750_989,
            Error::MissingOperator => 1_073_750_990,
            Error::InvalidNumber => 1_073_750_991,
            Error::DivideByZero => 1_073_750_993,
            Error::Environment(_) => 1,
        }
    }
}

/// The variables an expression reads and assigns: the environment's, in the shell.
pub trait Variables {
    /// The variable `name`'s value as a number (see [`number_in`]): 0 when there is no such
    /// variable.
    fn value(&mut self, name: &[u16]) -> i32;
    /// The variable `name` set to `value`, written in decimal ([`decimal`]); a failure is the
    /// Win32 error.
    fn assign(&mut self, name: &[u16], value: i32) -> Result<(), u32>;
}

/// `value` in decimal, a `-` before it when negative, as `set /a` writes a variable's value: in
/// `buffer`, which holds the longest (`-2147483648`).
pub fn decimal(value: i32, buffer: &mut [u16; 11]) -> &[u16] {
    let mut magnitude = value.unsigned_abs();
    let mut start = buffer.len();
    loop {
        start -= 1;
        buffer[start] = u16::from(b'0') + (magnitude % 10) as u16;
        magnitude /= 10;
        if magnitude == 0 {
            break;
        }
    }
    if value < 0 {
        start -= 1;
        buffer[start] = u16::from(b'-');
    }
    &buffer[start..]
}

/// A binary operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Binary {
    Multiply,
    Divide,
    Remainder,
    Add,
    Subtract,
    ShiftLeft,
    ShiftRight,
    And,
    Xor,
    Or,
}

impl Binary {
    /// How tightly it binds: the higher, the tighter.
    fn precedence(self) -> u8 {
        match self {
            Binary::Multiply | Binary::Divide | Binary::Remainder => 7,
            Binary::Add | Binary::Subtract => 6,
            Binary::ShiftLeft | Binary::ShiftRight => 5,
            Binary::And => 4,
            Binary::Xor => 3,
            Binary::Or => 2,
        }
    }

    /// `left` and `right` combined, wrapping at 32 bits. A shift counts only the low five bits of
    /// its count, as the processor's does.
    fn apply(self, left: i32, right: i32) -> Result<i32, Error> {
        Ok(match self {
            Binary::Multiply => left.wrapping_mul(right),
            Binary::Divide | Binary::Remainder if right == 0 => return Err(Error::DivideByZero),
            Binary::Divide => left.wrapping_div(right),
            Binary::Remainder => left.wrapping_rem(right),
            Binary::Add => left.wrapping_add(right),
            Binary::Subtract => left.wrapping_sub(right),
            Binary::ShiftLeft => left.wrapping_shl(right as u32),
            Binary::ShiftRight => left.wrapping_shr(right as u32),
            Binary::And => left & right,
            Binary::Xor => left ^ right,
            Binary::Or => left | right,
        })
    }
}

/// A prefix operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Unary {
    /// `!`: 1 for 0, 0 for anything else.
    Not,
    /// `~`.
    Invert,
    /// `-`.
    Negate,
}

impl Unary {
    fn apply(self, value: i32) -> i32 {
        match self {
            Unary::Not => i32::from(value == 0),
            Unary::Invert => !value,
            Unary::Negate => value.wrapping_neg(),
        }
    }
}

/// What the operator stack holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Operator {
    Unary(Unary),
    Binary(Binary),
    /// `=`, or `op=` with its operator.
    Assign(Option<Binary>),
    /// `,`.
    Comma,
    /// `(`, not yet closed.
    Open,
}

impl Operator {
    /// How tightly it binds; `(` is a barrier, never reduced by another operator.
    fn precedence(self) -> u8 {
        match self {
            Operator::Unary(_) => 8,
            Operator::Binary(binary) => binary.precedence(),
            Operator::Assign(_) => 1,
            Operator::Comma | Operator::Open => 0,
        }
    }
}

/// A word of the expression.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Token {
    /// The expression's end.
    End,
    /// A number: None when the word starting with a digit is none.
    Number(Option<i32>),
    /// A variable's name: the units from `start` to `end`.
    Name {
        start: usize,
        end: usize,
    },
    /// `!` or `~` (`-` is a [`Token::Binary`]: which it is depends on where it stands).
    Unary(Unary),
    Binary(Binary),
    Assign(Option<Binary>),
    Comma,
    Open,
    Close,
    /// `<` or `>` alone: no operator.
    Unknown,
}

/// What the operand stack holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Operand {
    Value(i32),
    /// A variable's name, its value not read yet: it may be assigned.
    Name {
        start: usize,
        end: usize,
    },
}

/// The characters operators, parentheses and the comma are made of.
const OPERATORS: &[u8] = b"+-*/%()!~&|^<>=,";

/// Whether `unit` ends a name or a number: a blank, a quote, an operator's character.
fn ends_word(unit: u16) -> bool {
    is_blank(unit) || unit == QUOTE || OPERATORS.iter().any(|&byte| unit == u16::from(byte))
}

/// The value of a digit in `radix`, if it is one.
fn digit(unit: u16, radix: u32) -> Option<u32> {
    char::from_u32(u32::from(unit))?.to_digit(radix)
}

/// The radix a number's text says, and where its digits start: `0x` hexadecimal, a leading `0`
/// octal, decimal otherwise.
fn radix_of(text: &[u16]) -> (u32, usize) {
    match text {
        [zero, x, ..]
            if *zero == u16::from(b'0') && (*x == u16::from(b'x') || *x == u16::from(b'X')) =>
        {
            (16, 2)
        }
        [zero, _, ..] if *zero == u16::from(b'0') => (8, 1),
        _ => (10, 0),
    }
}

/// The magnitude `digits` (in `radix`) give, read up to the first unit that is no digit, as
/// 32 bits: a decimal number past 2,147,483,647 is 2,147,483,647, a hexadecimal or octal one past
/// 0xFFFFFFFF is 0xFFFFFFFF, and from 0x80000000 on they are negative. Also how many units were
/// digits.
fn magnitude(digits: &[u16], radix: u32) -> (i32, usize) {
    let limit = if radix == 10 {
        i32::MAX as u64
    } else {
        u64::from(u32::MAX)
    };
    let mut value = 0u64;
    let mut count = 0;
    for &unit in digits {
        let Some(digit) = digit(unit, radix) else {
            break;
        };
        value = (value * u64::from(radix) + u64::from(digit)).min(limit);
        count += 1;
    }
    (value as u32 as i32, count)
}

/// A number written in the expression, the whole word: None when it is none (a digit its radix
/// does not have, a letter after it, `0x` with no digits).
fn literal(word: &[u16]) -> Option<i32> {
    let (radix, start) = radix_of(word);
    let digits = &word[start..];
    let (value, count) = magnitude(digits, radix);
    (count == digits.len() && (count > 0 || radix != 16)).then_some(value)
}

/// A variable's value as a number, as `set /a` reads it, lenient where a written number is not:
/// leading blanks skipped, then an optional sign, then as many digits as there are (in the radix
/// the text says, as for [`literal`]); the rest is ignored, and a value with no digits is 0
/// (`12abc` is 12; `abc` is 0, and so is `08`, whose 8 is no octal digit).
pub fn number_in(text: &[u16]) -> i32 {
    let text = skip_blanks(text);
    let (negative, text) = match text.split_first() {
        Some((&sign, rest)) if sign == u16::from(b'-') => (true, rest),
        Some((&sign, rest)) if sign == u16::from(b'+') => (false, rest),
        _ => (false, text),
    };
    let (radix, start) = radix_of(text);
    let (value, _) = magnitude(&text[start..], radix);
    if negative {
        value.wrapping_neg()
    } else {
        value
    }
}

/// A stack of at most N items, held in place.
struct Stack<T, const N: usize> {
    items: [T; N],
    length: usize,
}

impl<T: Copy, const N: usize> Stack<T, N> {
    fn new(fill: T) -> Self {
        Stack {
            items: [fill; N],
            length: 0,
        }
    }

    /// `item` pushed. The stacks are sized for a line's expression (see [`evaluate`]), so they
    /// cannot fill; were they to, the expression would have an operand too many.
    fn push(&mut self, item: T) -> Result<(), Error> {
        let slot = self
            .items
            .get_mut(self.length)
            .ok_or(Error::MissingOperator)?;
        *slot = item;
        self.length += 1;
        Ok(())
    }

    fn pop(&mut self) -> Option<T> {
        self.length = self.length.checked_sub(1)?;
        Some(self.items[self.length])
    }

    fn top(&self) -> Option<T> {
        self.length.checked_sub(1).map(|top| self.items[top])
    }

    fn top_mut(&mut self) -> Option<&mut T> {
        let top = self.length.checked_sub(1)?;
        self.items.get_mut(top)
    }
}

/// An expression being evaluated: its text, where reading is, and its two stacks.
struct Evaluation<'a, V: Variables> {
    text: &'a [u16],
    at: usize,
    variables: &'a mut V,
    /// Each operand is followed by an operator, so a line holds half as many as its units, and
    /// one more.
    operands: Stack<Operand, { MAX_LINE / 2 + 1 }>,
    operators: Stack<Operator, MAX_LINE>,
}

impl<V: Variables> Evaluation<'_, V> {
    /// The next token, and where reading goes on after it.
    fn token(&self) -> (Token, usize) {
        let text = self.text;
        let mut at = self.at;
        while at < text.len() && (is_blank(text[at]) || text[at] == QUOTE) {
            at += 1;
        }
        let Some(&unit) = text.get(at) else {
            return (Token::End, at);
        };
        let next = text.get(at + 1).copied();
        let is = |unit: Option<u16>, byte: u8| unit == Some(u16::from(byte));
        // An operator that may take `=` after it, its two units and the binary operator.
        let compound = |binary: Binary, length: usize| {
            if is(text.get(at + length).copied(), b'=') {
                (Token::Assign(Some(binary)), at + length + 1)
            } else {
                (Token::Binary(binary), at + length)
            }
        };
        match u8::try_from(unit).unwrap_or(0) {
            b'(' => (Token::Open, at + 1),
            b')' => (Token::Close, at + 1),
            b',' => (Token::Comma, at + 1),
            b'!' => (Token::Unary(Unary::Not), at + 1),
            b'~' => (Token::Unary(Unary::Invert), at + 1),
            b'=' => (Token::Assign(None), at + 1),
            b'*' => compound(Binary::Multiply, 1),
            b'/' => compound(Binary::Divide, 1),
            b'%' => compound(Binary::Remainder, 1),
            b'+' => compound(Binary::Add, 1),
            b'-' => compound(Binary::Subtract, 1),
            b'&' => compound(Binary::And, 1),
            b'^' => compound(Binary::Xor, 1),
            b'|' => compound(Binary::Or, 1),
            b'<' if is(next, b'<') => compound(Binary::ShiftLeft, 2),
            b'>' if is(next, b'>') => compound(Binary::ShiftRight, 2),
            b'<' | b'>' => (Token::Unknown, at + 1),
            _ => {
                let end = text[at..]
                    .iter()
                    .position(|&unit| ends_word(unit))
                    .map_or(text.len(), |length| at + length);
                if digit(unit, 10).is_some() {
                    (Token::Number(literal(&text[at..end])), end)
                } else {
                    (Token::Name { start: at, end }, end)
                }
            }
        }
    }

    /// The operand on top read as a value: a name's variable read now, so that variables are read
    /// from left to right, before what follows them is evaluated.
    fn resolve_top(&mut self) {
        if let Some(Operand::Name { start, end }) = self.operands.top() {
            let value = self.variables.value(&self.text[start..end]);
            if let Some(top) = self.operands.top_mut() {
                *top = Operand::Value(value);
            }
        }
    }

    /// The operand on top, popped as a value.
    fn pop_value(&mut self) -> Result<i32, Error> {
        self.resolve_top();
        match self.operands.pop() {
            Some(Operand::Value(value)) => Ok(value),
            _ => Err(Error::MissingOperand),
        }
    }

    /// The operator on top applied to its operands, its result pushed in their place. An
    /// assignment sets its variable as it is applied.
    fn reduce(&mut self) -> Result<(), Error> {
        let result = match self.operators.pop() {
            Some(Operator::Unary(unary)) => unary.apply(self.pop_value()?),
            Some(Operator::Binary(binary)) => {
                let right = self.pop_value()?;
                let left = self.pop_value()?;
                binary.apply(left, right)?
            }
            Some(Operator::Assign(binary)) => {
                let right = self.pop_value()?;
                let Some(Operand::Name { start, end }) = self.operands.pop() else {
                    return Err(Error::MissingOperand);
                };
                let name = &self.text[start..end];
                let value = match binary {
                    Some(binary) => binary.apply(self.variables.value(name), right)?,
                    None => right,
                };
                self.variables
                    .assign(name, value)
                    .map_err(Error::Environment)?;
                value
            }
            Some(Operator::Comma) => {
                let right = self.pop_value()?;
                self.pop_value()?;
                right
            }
            Some(Operator::Open) | None => return Err(Error::Unbalanced),
        };
        self.operands.push(Operand::Value(result))
    }

    /// The operators on the stack that bind at least as tightly as `incoming` reduced (more
    /// tightly, for an assignment, which groups from the right), down to the innermost `(`.
    fn reduce_for(&mut self, incoming: Operator) -> Result<(), Error> {
        while let Some(top) = self.operators.top() {
            let reduces = top != Operator::Open
                && (top.precedence() > incoming.precedence()
                    || (top.precedence() == incoming.precedence()
                        && !matches!(incoming, Operator::Assign(_))));
            if !reduces {
                break;
            }
            self.reduce()?;
        }
        Ok(())
    }

    /// Every operator down to the innermost `(` reduced, then that `(` popped (`closing`), or
    /// every operator, which must leave no `(` (at the end).
    fn reduce_all(&mut self, closing: bool) -> Result<(), Error> {
        self.resolve_top();
        loop {
            match self.operators.top() {
                Some(Operator::Open) if closing => {
                    self.operators.pop();
                    return Ok(());
                }
                Some(Operator::Open) => return Err(Error::Unbalanced),
                None if closing => return Err(Error::Unbalanced),
                None => return Ok(()),
                Some(_) => self.reduce()?,
            }
        }
    }

    /// The expression read and evaluated: its value, the last of those its commas separate.
    fn run(&mut self) -> Result<i32, Error> {
        let mut operand = true;
        loop {
            let (token, next) = self.token();
            self.at = next;
            if operand {
                match token {
                    Token::Number(Some(value)) => self.operands.push(Operand::Value(value))?,
                    Token::Number(None) => return Err(Error::InvalidNumber),
                    Token::Name { start, end } => {
                        self.operands.push(Operand::Name { start, end })?
                    }
                    Token::Open => {
                        self.operators.push(Operator::Open)?;
                        continue;
                    }
                    Token::Unary(unary) => {
                        self.operators.push(Operator::Unary(unary))?;
                        continue;
                    }
                    Token::Binary(Binary::Subtract) => {
                        self.operators.push(Operator::Unary(Unary::Negate))?;
                        continue;
                    }
                    _ => return Err(Error::MissingOperand),
                }
                operand = false;
                continue;
            }
            let incoming = match token {
                Token::Binary(binary) => Operator::Binary(binary),
                Token::Comma => Operator::Comma,
                Token::Assign(binary) => {
                    // Unary operators bind tighter: `-x=1` assigns no variable.
                    self.reduce_for(Operator::Assign(binary))?;
                    if !matches!(self.operands.top(), Some(Operand::Name { .. })) {
                        return Err(Error::MissingOperand);
                    }
                    self.operators.push(Operator::Assign(binary))?;
                    operand = true;
                    continue;
                }
                Token::Close => {
                    self.reduce_all(true)?;
                    continue;
                }
                Token::End => {
                    self.reduce_all(false)?;
                    return self.pop_value();
                }
                _ => return Err(Error::MissingOperator),
            };
            self.resolve_top();
            self.reduce_for(incoming)?;
            self.operators.push(incoming)?;
            operand = true;
        }
    }
}

/// `set /a`'s `expression` evaluated, its assignments made in `variables` as they are reached:
/// its value (the last expression's, after commas), or why it has none. Only its first
/// [`MAX_LINE`] units are read: a line holds no more.
#[inline(never)]
pub fn evaluate(expression: &[u16], variables: &mut impl Variables) -> Result<i32, Error> {
    let text = &expression[..expression.len().min(MAX_LINE)];
    Evaluation {
        text,
        at: 0,
        variables,
        operands: Stack::new(Operand::Value(0)),
        operators: Stack::new(Operator::Comma),
    }
    .run()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().collect()
    }

    /// Variables in a map, their names compared in capitals as the environment's are.
    #[derive(Default)]
    struct Fake {
        variables: BTreeMap<String, String>,
        /// A name whose assignment fails, with this error.
        refused: Option<(String, u32)>,
    }

    impl Fake {
        fn with(pairs: &[(&str, &str)]) -> Self {
            let mut fake = Fake::default();
            for (name, value) in pairs {
                fake.variables
                    .insert(name.to_ascii_uppercase(), value.to_string());
            }
            fake
        }

        fn get(&self, name: &str) -> Option<&str> {
            self.variables
                .get(&name.to_ascii_uppercase())
                .map(String::as_str)
        }
    }

    impl Variables for Fake {
        fn value(&mut self, name: &[u16]) -> i32 {
            let name = String::from_utf16(name).unwrap().to_ascii_uppercase();
            self.variables
                .get(&name)
                .map_or(0, |value| number_in(&wide(value)))
        }

        fn assign(&mut self, name: &[u16], value: i32) -> Result<(), u32> {
            let name = String::from_utf16(name).unwrap().to_ascii_uppercase();
            if let Some((refused, error)) = &self.refused {
                if *refused == name {
                    return Err(*error);
                }
            }
            let value = String::from_utf16(decimal(value, &mut [0; 11])).unwrap();
            self.variables.insert(name, value);
            Ok(())
        }
    }

    fn eval(expression: &str) -> Result<i32, Error> {
        evaluate(&wide(expression), &mut Fake::default())
    }

    fn eval_in(expression: &str, fake: &mut Fake) -> Result<i32, Error> {
        evaluate(&wide(expression), fake)
    }

    #[test]
    fn the_switches_are_read_in_either_case() {
        let expression = wide(" 1+2 ");
        assert_eq!(
            switch(&wide("/a 1+2 ")),
            Some(Switch::Arithmetic(&expression))
        );
        assert_eq!(
            switch(&wide("/A 1+2 ")),
            Some(Switch::Arithmetic(&expression))
        );
        let expression = wide("x=1");
        assert_eq!(
            switch(&wide("/ax=1")),
            Some(Switch::Arithmetic(&expression))
        );
        assert_eq!(switch(&wide("/a")), Some(Switch::Incorrect));
        assert_eq!(switch(&wide("/a   ")), Some(Switch::Incorrect));
        assert_eq!(switch(&wide("X=1")), None);
        assert_eq!(switch(&wide("/x")), None);
        assert_eq!(switch(&wide("/")), None);
        assert_eq!(switch(&[]), None);
    }

    #[test]
    fn set_p_reads_name_and_prompt_as_set_reads_them() {
        let (name, prompt) = (wide("X"), wide("Name? "));
        let expected = Some(Switch::Prompt {
            name: &name,
            prompt: &prompt,
        });
        assert_eq!(switch(&wide("/p X=Name? ")), expected);
        assert_eq!(switch(&wide("/P   X=Name? ")), expected);
        assert_eq!(switch(&wide("/p \"X=Name? \" more")), expected);
        assert_eq!(
            switch(&wide("/pX=")),
            Some(Switch::Prompt {
                name: &name,
                prompt: &[]
            })
        );
        assert_eq!(switch(&wide("/p")), Some(Switch::Incorrect));
        assert_eq!(switch(&wide("/p X")), Some(Switch::Incorrect));
        assert_eq!(switch(&wide("/p =x")), Some(Switch::Incorrect));
    }

    #[test]
    fn precedence_follows_set_s_table() {
        assert_eq!(eval("1+2*3"), Ok(7));
        assert_eq!(eval("(1+2)*3"), Ok(9));
        assert_eq!(eval("10-4-3"), Ok(3));
        assert_eq!(eval("100/10/5"), Ok(2));
        assert_eq!(eval("1+1<<2"), Ok(8));
        assert_eq!(eval("1<<2+1"), Ok(8));
        assert_eq!(eval("6&3<<1"), Ok(6));
        assert_eq!(eval("1|2^3&6"), Ok(1 | (2 ^ (3 & 6))));
        assert_eq!(eval("5^1|2"), Ok((5 ^ 1) | 2));
        assert_eq!(eval("-2*-3"), Ok(6));
        assert_eq!(eval("-(2+3)*2"), Ok(-10));
        assert_eq!(eval("!0+1"), Ok(2));
        assert_eq!(eval("~0*2"), Ok(-2));
        assert_eq!(eval("2- -2"), Ok(4));
        assert_eq!(eval("((((7))))"), Ok(7));
    }

    #[test]
    fn every_operator() {
        assert_eq!(eval("7*6"), Ok(42));
        assert_eq!(eval("7/2"), Ok(3));
        assert_eq!(eval("-7/2"), Ok(-3));
        assert_eq!(eval("7%3"), Ok(1));
        assert_eq!(eval("-7%3"), Ok(-1));
        assert_eq!(eval("7+3"), Ok(10));
        assert_eq!(eval("7-10"), Ok(-3));
        assert_eq!(eval("3<<4"), Ok(48));
        assert_eq!(eval("-16>>2"), Ok(-4));
        assert_eq!(eval("12&10"), Ok(8));
        assert_eq!(eval("12^10"), Ok(6));
        assert_eq!(eval("12|10"), Ok(14));
        assert_eq!(eval("!0"), Ok(1));
        assert_eq!(eval("!5"), Ok(0));
        assert_eq!(eval("!!5"), Ok(1));
        assert_eq!(eval("~5"), Ok(-6));
        assert_eq!(eval("-5"), Ok(-5));
        assert_eq!(eval("--5"), Ok(5));
        assert_eq!(eval("1,2,3"), Ok(3));
    }

    #[test]
    fn assignments_set_variables_from_the_right() {
        let mut fake = Fake::with(&[("x", "10")]);
        assert_eq!(eval_in("x+=5", &mut fake), Ok(15));
        assert_eq!(fake.get("X"), Some("15"));
        for (expression, value) in [
            ("x=10", 10),
            ("x*=3", 30),
            ("x/=4", 7),
            ("x%=4", 3),
            ("x-=5", -2),
            ("x&=6", 6),
            ("x^=3", 5),
            ("x|=8", 13),
            ("x<<=2", 52),
            ("x>>=3", 6),
        ] {
            assert_eq!(eval_in(expression, &mut fake), Ok(value), "{expression}");
            assert_eq!(fake.get("x"), Some(value.to_string().as_str()));
        }
        assert_eq!(eval_in("a=b=c=4", &mut fake), Ok(4));
        assert_eq!(
            (fake.get("a"), fake.get("b"), fake.get("c")),
            (Some("4"), Some("4"), Some("4"))
        );
        assert_eq!(eval_in("a=1, b=a+1, c=b*10", &mut fake), Ok(20));
        assert_eq!(fake.get("c"), Some("20"));
        assert_eq!(eval_in("y=(z=3)+1", &mut fake), Ok(4));
        assert_eq!((fake.get("y"), fake.get("z")), (Some("4"), Some("3")));
        assert_eq!(eval_in("n=-2147483647-1", &mut fake), Ok(i32::MIN));
        assert_eq!(fake.get("n"), Some("-2147483648"));
    }

    #[test]
    fn variables_are_read_by_name_and_read_leniently() {
        let mut fake = Fake::with(&[
            ("a", "12"),
            ("hex", "0x1F"),
            ("oct", "017"),
            ("neg", " -5"),
            ("junk", "12abc"),
            ("word", "abc"),
            ("bad", "08"),
            ("dotted.name", "3"),
            ("v2", "2"),
        ]);
        assert_eq!(eval_in("a+1", &mut fake), Ok(13));
        assert_eq!(eval_in("A*V2", &mut fake), Ok(24));
        assert_eq!(eval_in("undefined", &mut fake), Ok(0));
        assert_eq!(eval_in("hex+oct", &mut fake), Ok(31 + 15));
        assert_eq!(eval_in("neg", &mut fake), Ok(-5));
        assert_eq!(eval_in("junk", &mut fake), Ok(12));
        assert_eq!(eval_in("word", &mut fake), Ok(0));
        assert_eq!(eval_in("bad", &mut fake), Ok(0));
        assert_eq!(eval_in("dotted.name*2", &mut fake), Ok(6));
        // Read from left to right: `a` before the assignment in parentheses changes it.
        assert_eq!(eval_in("a+(a=1)", &mut fake), Ok(13));
    }

    #[test]
    fn numbers_in_decimal_hexadecimal_and_octal() {
        assert_eq!(eval("17"), Ok(17));
        assert_eq!(eval("0x11"), Ok(17));
        assert_eq!(eval("0X1f"), Ok(31));
        assert_eq!(eval("021"), Ok(17));
        assert_eq!(eval("0"), Ok(0));
        assert_eq!(eval("00"), Ok(0));
        assert_eq!(eval("0xFFFFFFFF"), Ok(-1));
        assert_eq!(eval("0x80000000"), Ok(i32::MIN));
        assert_eq!(eval("037777777777"), Ok(-1));
        // A decimal number stops at 2,147,483,647; hexadecimal and octal ones at 32 bits.
        assert_eq!(eval("2147483647"), Ok(i32::MAX));
        assert_eq!(eval("2147483648"), Ok(i32::MAX));
        assert_eq!(eval("99999999999999999999"), Ok(i32::MAX));
        assert_eq!(eval("0x123456789"), Ok(-1));
        assert_eq!(eval("\"1\"+\"2\""), Ok(3));
        assert_eq!(eval("  4  "), Ok(4));
        assert_eq!(eval("\t4\t*\t2"), Ok(8));
    }

    #[test]
    fn arithmetic_wraps_at_32_bits() {
        assert_eq!(eval("2147483647+1"), Ok(i32::MIN));
        assert_eq!(eval("-2147483647-2"), Ok(i32::MAX));
        assert_eq!(eval("65536*65536"), Ok(0));
        assert_eq!(eval("0x7FFFFFFF*2"), Ok(-2));
        assert_eq!(eval("-(-2147483647-1)"), Ok(i32::MIN));
        assert_eq!(eval("(-2147483647-1)/-1"), Ok(i32::MIN));
        assert_eq!(eval("(-2147483647-1)%-1"), Ok(0));
        assert_eq!(eval("1<<31"), Ok(i32::MIN));
        assert_eq!(eval("1<<32"), Ok(1));
        assert_eq!(eval("1<<33"), Ok(2));
        assert_eq!(eval("1<<-1"), Ok(i32::MIN));
        assert_eq!(eval("(1<<31)>>31"), Ok(-1));
    }

    #[test]
    fn values_are_written_in_decimal() {
        let written = |value| String::from_utf16(decimal(value, &mut [0; 11])).unwrap();
        assert_eq!(written(0), "0");
        assert_eq!(written(42), "42");
        assert_eq!(written(-7), "-7");
        assert_eq!(written(i32::MAX), "2147483647");
        assert_eq!(written(i32::MIN), "-2147483648");
    }

    #[test]
    fn each_error() {
        for (expression, error) in [
            ("1+", Error::MissingOperand),
            ("*2", Error::MissingOperand),
            ("1+*2", Error::MissingOperand),
            ("()", Error::MissingOperand),
            (",", Error::MissingOperand),
            ("1,", Error::MissingOperand),
            ("\"\"", Error::MissingOperand),
            ("5=3", Error::MissingOperand),
            ("-x=3", Error::MissingOperand),
            ("1+x=3", Error::MissingOperand),
            ("+1", Error::MissingOperand),
            ("1 2", Error::MissingOperator),
            ("x y", Error::MissingOperator),
            ("2(3)", Error::MissingOperator),
            ("1<2", Error::MissingOperator),
            ("x!=1", Error::MissingOperator),
            ("(1+2", Error::Unbalanced),
            ("1+2)", Error::Unbalanced),
            ("((1)", Error::Unbalanced),
            ("08", Error::InvalidNumber),
            ("09", Error::InvalidNumber),
            ("0x", Error::InvalidNumber),
            ("0xG", Error::InvalidNumber),
            ("1a", Error::InvalidNumber),
            ("1+08", Error::InvalidNumber),
            ("1/0", Error::DivideByZero),
            ("1%0", Error::DivideByZero),
            ("1/(2-2)", Error::DivideByZero),
        ] {
            assert_eq!(eval(expression), Err(error), "{expression}");
        }
        let mut fake = Fake::default();
        assert_eq!(eval_in("x/=0", &mut fake), Err(Error::DivideByZero));
        assert_eq!(fake.get("x"), None);
        fake.refused = Some(("Y".to_string(), 8));
        assert_eq!(eval_in("y=1", &mut fake), Err(Error::Environment(8)));
    }

    #[test]
    fn assignments_before_an_error_stay_made() {
        let mut fake = Fake::default();
        assert_eq!(eval_in("a=1, b=1/0", &mut fake), Err(Error::DivideByZero));
        assert_eq!((fake.get("a"), fake.get("b")), (Some("1"), None));
    }

    #[test]
    fn each_error_s_text_and_errorlevel() {
        assert_eq!(Error::MissingOperand.text(), Some("Missing operand.\r\n"));
        assert_eq!(Error::MissingOperator.text(), Some("Missing operator.\r\n"));
        assert_eq!(
            Error::Unbalanced.text(),
            Some("Unbalanced parenthesis.\r\n")
        );
        assert_eq!(
            Error::InvalidNumber.text(),
            Some(
                "Invalid number.  Numeric constants are either decimal (17), hexadecimal (0x11), \
                 or octal (021).\r\n"
            )
        );
        assert_eq!(
            Error::DivideByZero.text(),
            Some("Divide by zero error.\r\n")
        );
        assert_eq!(Error::Environment(8).text(), None);
        assert_eq!(Error::Unbalanced.errorlevel(), 1073750988);
        assert_eq!(Error::MissingOperand.errorlevel(), 1073750989);
        assert_eq!(Error::MissingOperator.errorlevel(), 1073750990);
        assert_eq!(Error::InvalidNumber.errorlevel(), 1073750991);
        assert_eq!(Error::DivideByZero.errorlevel(), 1073750993);
        assert_eq!(Error::Environment(8).errorlevel(), 1);
    }

    #[test]
    fn a_long_expression_fits_its_stacks() {
        let sum = vec!["1"; MAX_LINE / 2 + 1].join("+");
        assert_eq!(eval(&sum[..MAX_LINE]), Ok((MAX_LINE / 2 + 1) as i32));
        let nested = "(".repeat(MAX_LINE / 2) + "1" + &")".repeat(MAX_LINE / 2);
        assert_eq!(eval(&nested), Ok(1));
        // An even number of each, 2,046.
        assert_eq!(eval(&("-".repeat(MAX_LINE - 1) + "1")), Ok(1));
        assert_eq!(eval(&("~".repeat(MAX_LINE - 1) + "5")), Ok(5));
    }
}
