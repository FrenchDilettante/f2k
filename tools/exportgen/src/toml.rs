//! The TOML subset the specs and fixture declarations are written in, and a reader for it.
//!
//! The files are TOML: any TOML reader (Python's `tomllib` in the scripts) reads them in full. This
//! reader takes only the subset they use, and refuses everything else by line and column rather
//! than misreading it:
//!
//! - comments (`#` to the end of the line), blank lines;
//! - `key = value` pairs, keys bare (`A-Za-z0-9_-`) or quoted (`"…"`); no dotted keys;
//! - `[table]` headers and `[[array-of-tables]]` headers, one name each (no dots);
//! - values: basic strings (`"…"`, escapes `\" \\ \n \t \r \uXXXX`), literal strings (`'…'`),
//!   integers (decimal, `0x` hex, `_` separators, a leading `-`), floats (`1.5`), `true`/`false`,
//!   arrays (spanning lines, a trailing comma allowed, comments between items) and inline tables
//!   (`{ k = v, … }`, one line).
//!
//! Not taken: multi-line strings, dates and times, dotted keys, exponents, `inf`/`nan`.

use std::fmt;

/// A value, as read.
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    String(String),
    Integer(i64),
    Float(f64),
    Boolean(bool),
    Array(Vec<Value>),
    Table(Table),
}

/// A table: its pairs in file order (a key appears once).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Table {
    pub entries: Vec<(String, Value)>,
}

impl Table {
    /// The value under `key`.
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.entries.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    fn get_mut(&mut self, key: &str) -> Option<&mut Value> {
        self.entries
            .iter_mut()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v)
    }

    /// The keys, in file order.
    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.entries.iter().map(|(k, _)| k.as_str())
    }
}

impl Value {
    /// A short name for the value's kind, for messages.
    pub fn kind(&self) -> &'static str {
        match self {
            Value::String(_) => "a string",
            Value::Integer(_) => "an integer",
            Value::Float(_) => "a float",
            Value::Boolean(_) => "a boolean",
            Value::Array(_) => "an array",
            Value::Table(_) => "a table",
        }
    }
}

/// Why a document did not read: where, and what.
#[derive(Clone, Debug, PartialEq)]
pub struct Error {
    pub line: usize,
    pub column: usize,
    pub message: String,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}: {}", self.line, self.column, self.message)
    }
}

impl std::error::Error for Error {}

/// Read a document: its root table.
pub fn parse(text: &str) -> Result<Table, Error> {
    let mut reader = Reader {
        chars: text.chars().collect(),
        at: 0,
        line: 1,
        column: 1,
    };
    let mut root = Table::default();
    // Where pairs go: the root, a [table], or the last [[array]] element.
    let mut target: Vec<(String, bool)> = Vec::new();
    loop {
        reader.skip_blank_lines()?;
        if reader.done() {
            return Ok(root);
        }
        if reader.peek() == Some('[') {
            let array = reader.peek_at(1) == Some('[');
            reader.advance();
            if array {
                reader.advance();
            }
            reader.skip_spaces();
            let name = reader.key()?;
            reader.skip_spaces();
            reader.expect(']')?;
            if array {
                reader.expect(']')?;
            }
            reader.end_of_line()?;
            let (line, column) = (reader.line, reader.column);
            if array {
                match root.get_mut(&name) {
                    None => root.entries.push((
                        name.clone(),
                        Value::Array(vec![Value::Table(Table::default())]),
                    )),
                    Some(Value::Array(items))
                        if items.iter().all(|i| matches!(i, Value::Table(_))) =>
                    {
                        items.push(Value::Table(Table::default()))
                    }
                    Some(_) => {
                        return Err(Error {
                            line,
                            column,
                            message: format!(
                                "[[{name}]] reuses a key that is not an array of tables"
                            ),
                        })
                    }
                }
            } else {
                if root.get(&name).is_some() {
                    return Err(Error {
                        line,
                        column,
                        message: format!("[{name}] defined twice"),
                    });
                }
                root.entries
                    .push((name.clone(), Value::Table(Table::default())));
            }
            target = vec![(name, array)];
            continue;
        }
        let (line, column) = (reader.line, reader.column);
        let key = reader.key()?;
        reader.skip_spaces();
        reader.expect('=')?;
        reader.skip_spaces();
        let value = reader.value()?;
        reader.end_of_line()?;
        let table = match target.first() {
            None => &mut root,
            Some((name, array)) => match root.get_mut(name) {
                Some(Value::Table(table)) if !array => table,
                Some(Value::Array(items)) => match items.last_mut() {
                    Some(Value::Table(table)) => table,
                    _ => unreachable!("an array of tables ends in a table"),
                },
                _ => unreachable!("the header made the target"),
            },
        };
        if table.get(&key).is_some() {
            return Err(Error {
                line,
                column,
                message: format!("key {key:?} defined twice"),
            });
        }
        table.entries.push((key, value));
    }
}

struct Reader {
    chars: Vec<char>,
    at: usize,
    line: usize,
    column: usize,
}

impl Reader {
    fn done(&self) -> bool {
        self.at >= self.chars.len()
    }

    fn peek(&self) -> Option<char> {
        self.chars.get(self.at).copied()
    }

    fn peek_at(&self, offset: usize) -> Option<char> {
        self.chars.get(self.at + offset).copied()
    }

    fn advance(&mut self) -> Option<char> {
        let c = self.peek()?;
        self.at += 1;
        if c == '\n' {
            self.line += 1;
            self.column = 1;
        } else {
            self.column += 1;
        }
        Some(c)
    }

    fn error<T>(&self, message: impl Into<String>) -> Result<T, Error> {
        Err(Error {
            line: self.line,
            column: self.column,
            message: message.into(),
        })
    }

    fn expect(&mut self, wanted: char) -> Result<(), Error> {
        match self.peek() {
            Some(c) if c == wanted => {
                self.advance();
                Ok(())
            }
            Some(c) => self.error(format!("expected {wanted:?}, found {c:?}")),
            None => self.error(format!("expected {wanted:?}, found the end")),
        }
    }

    fn skip_spaces(&mut self) {
        while matches!(self.peek(), Some(' ' | '\t')) {
            self.advance();
        }
    }

    fn skip_comment(&mut self) {
        if self.peek() == Some('#') {
            while !matches!(self.peek(), None | Some('\n')) {
                self.advance();
            }
        }
    }

    /// Spaces, comments and line ends, up to the next content.
    fn skip_blank_lines(&mut self) -> Result<(), Error> {
        loop {
            self.skip_spaces();
            self.skip_comment();
            match self.peek() {
                Some('\n') => {
                    self.advance();
                }
                Some('\r') if self.peek_at(1) == Some('\n') => {
                    self.advance();
                    self.advance();
                }
                _ => return Ok(()),
            }
        }
    }

    /// Nothing but spaces and a comment before the line ends.
    fn end_of_line(&mut self) -> Result<(), Error> {
        self.skip_spaces();
        self.skip_comment();
        match self.peek() {
            None | Some('\n') => Ok(()),
            Some('\r') if self.peek_at(1) == Some('\n') => Ok(()),
            Some(c) => self.error(format!("unexpected {c:?} after the value")),
        }
    }

    fn key(&mut self) -> Result<String, Error> {
        match self.peek() {
            Some('"') => self.basic_string(),
            Some('\'') => self.literal_string(),
            _ => {
                let mut key = String::new();
                while let Some(c) = self.peek() {
                    if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                        key.push(c);
                        self.advance();
                    } else {
                        break;
                    }
                }
                if key.is_empty() {
                    return self.error("expected a key");
                }
                if self.peek() == Some('.') {
                    return self.error("dotted keys are outside the subset");
                }
                Ok(key)
            }
        }
    }

    fn value(&mut self) -> Result<Value, Error> {
        match self.peek() {
            Some('"') => {
                if self.peek_at(1) == Some('"') && self.peek_at(2) == Some('"') {
                    return self.error("multi-line strings are outside the subset");
                }
                Ok(Value::String(self.basic_string()?))
            }
            Some('\'') => {
                if self.peek_at(1) == Some('\'') && self.peek_at(2) == Some('\'') {
                    return self.error("multi-line strings are outside the subset");
                }
                Ok(Value::String(self.literal_string()?))
            }
            Some('[') => self.array(),
            Some('{') => self.inline_table(),
            Some('t' | 'f') => {
                let word = self.word();
                match word.as_str() {
                    "true" => Ok(Value::Boolean(true)),
                    "false" => Ok(Value::Boolean(false)),
                    _ => self.error(format!("unknown value {word:?}")),
                }
            }
            Some(c) if c.is_ascii_digit() || c == '-' || c == '+' => self.number(),
            Some(c) => self.error(format!("unexpected {c:?} where a value belongs")),
            None => self.error("expected a value, found the end"),
        }
    }

    fn word(&mut self) -> String {
        let mut word = String::new();
        while let Some(c) = self.peek() {
            if c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '+' | '.' | ':') {
                word.push(c);
                self.advance();
            } else {
                break;
            }
        }
        word
    }

    fn number(&mut self) -> Result<Value, Error> {
        let (line, column) = (self.line, self.column);
        let word = self.word();
        let bad = |what: &str| Error {
            line,
            column,
            message: format!("{what}: {word:?}"),
        };
        let (negative, digits) = match word.strip_prefix('-') {
            Some(rest) => (true, rest),
            None => (false, word.strip_prefix('+').unwrap_or(&word)),
        };
        let clean: String = digits.chars().filter(|&c| c != '_').collect();
        if let Some(hex) = clean.strip_prefix("0x") {
            let value = i64::from_str_radix(hex, 16).map_err(|_| bad("not a hex integer"))?;
            return Ok(Value::Integer(if negative { -value } else { value }));
        }
        if clean.contains(['e', 'E', ':']) || clean.contains("inf") || clean.contains("nan") {
            return Err(bad("outside the subset (exponent, date, inf or nan)"));
        }
        if clean.contains('.') {
            let value: f64 = clean.parse().map_err(|_| bad("not a float"))?;
            return Ok(Value::Float(if negative { -value } else { value }));
        }
        let value: i64 = clean.parse().map_err(|_| bad("not an integer"))?;
        Ok(Value::Integer(if negative { -value } else { value }))
    }

    fn basic_string(&mut self) -> Result<String, Error> {
        self.expect('"')?;
        let mut text = String::new();
        loop {
            match self.advance() {
                None | Some('\n') => return self.error("unterminated string"),
                Some('"') => return Ok(text),
                Some('\\') => match self.advance() {
                    Some('"') => text.push('"'),
                    Some('\\') => text.push('\\'),
                    Some('n') => text.push('\n'),
                    Some('t') => text.push('\t'),
                    Some('r') => text.push('\r'),
                    Some('u') => {
                        let mut code = 0u32;
                        for _ in 0..4 {
                            let digit = self.advance().and_then(|c| c.to_digit(16));
                            match digit {
                                Some(d) => code = code * 16 + d,
                                None => return self.error("\\u needs four hex digits"),
                            }
                        }
                        match char::from_u32(code) {
                            Some(c) => text.push(c),
                            None => return self.error("\\u names no character"),
                        }
                    }
                    Some(c) => return self.error(format!("unknown escape \\{c}")),
                    None => return self.error("unterminated string"),
                },
                Some(c) => text.push(c),
            }
        }
    }

    fn literal_string(&mut self) -> Result<String, Error> {
        self.expect('\'')?;
        let mut text = String::new();
        loop {
            match self.advance() {
                None | Some('\n') => return self.error("unterminated string"),
                Some('\'') => return Ok(text),
                Some(c) => text.push(c),
            }
        }
    }

    fn array(&mut self) -> Result<Value, Error> {
        self.expect('[')?;
        let mut items = Vec::new();
        loop {
            self.skip_blank_lines()?;
            if self.peek() == Some(']') {
                self.advance();
                return Ok(Value::Array(items));
            }
            items.push(self.value()?);
            self.skip_blank_lines()?;
            match self.peek() {
                Some(',') => {
                    self.advance();
                }
                Some(']') => {
                    self.advance();
                    return Ok(Value::Array(items));
                }
                Some(c) => {
                    return self.error(format!("expected ',' or ']' in the array, found {c:?}"))
                }
                None => return self.error("unterminated array"),
            }
        }
    }

    fn inline_table(&mut self) -> Result<Value, Error> {
        self.expect('{')?;
        let mut table = Table::default();
        self.skip_spaces();
        if self.peek() == Some('}') {
            self.advance();
            return Ok(Value::Table(table));
        }
        loop {
            self.skip_spaces();
            let key = self.key()?;
            self.skip_spaces();
            self.expect('=')?;
            self.skip_spaces();
            let value = self.value()?;
            if table.get(&key).is_some() {
                return self.error(format!("key {key:?} defined twice"));
            }
            table.entries.push((key, value));
            self.skip_spaces();
            match self.peek() {
                Some(',') => {
                    self.advance();
                }
                Some('}') => {
                    self.advance();
                    return Ok(Value::Table(table));
                }
                Some(c) => {
                    return self.error(format!(
                        "expected ',' or '}}' in the inline table, found {c:?}"
                    ))
                }
                None => return self.error("unterminated inline table"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(text: &str) -> Value {
        Value::String(text.to_string())
    }

    #[test]
    fn reads_the_subset() {
        let doc = parse(
            "# a comment\n\
             title = \"F2K\" # trailing\n\
             count = 0x1F\n\
             neg = -3\n\
             big = 1_000\n\
             ratio = 2.5\n\
             on = true\n\
             'quoted key' = 'raw \\ text'\n\
             list = [\n  \"a\", # first\n  \"b\",\n]\n\
             empty = []\n\
             inline = { service = \"svc_x\", n = 4 }\n\
             [pending]\n\
             \"fswrite/dir-write\" = \"FS-1: refused\"\n\
             [[export]]\nname = \"A\"\n\
             [[export]]\nname = \"B\"\n",
        )
        .unwrap();
        assert_eq!(doc.get("title"), Some(&s("F2K")));
        assert_eq!(doc.get("count"), Some(&Value::Integer(31)));
        assert_eq!(doc.get("neg"), Some(&Value::Integer(-3)));
        assert_eq!(doc.get("big"), Some(&Value::Integer(1000)));
        assert_eq!(doc.get("ratio"), Some(&Value::Float(2.5)));
        assert_eq!(doc.get("on"), Some(&Value::Boolean(true)));
        assert_eq!(doc.get("quoted key"), Some(&s("raw \\ text")));
        assert_eq!(doc.get("list"), Some(&Value::Array(vec![s("a"), s("b")])));
        assert_eq!(doc.get("empty"), Some(&Value::Array(vec![])));
        let Some(Value::Table(inline)) = doc.get("inline") else {
            panic!()
        };
        assert_eq!(inline.get("service"), Some(&s("svc_x")));
        assert_eq!(inline.get("n"), Some(&Value::Integer(4)));
        let Some(Value::Table(pending)) = doc.get("pending") else {
            panic!()
        };
        assert_eq!(pending.get("fswrite/dir-write"), Some(&s("FS-1: refused")));
        let Some(Value::Array(exports)) = doc.get("export") else {
            panic!()
        };
        assert_eq!(exports.len(), 2);
        let Value::Table(second) = &exports[1] else {
            panic!()
        };
        assert_eq!(second.get("name"), Some(&s("B")));
    }

    #[test]
    fn escapes() {
        let doc = parse(r#"a = "q\"b\\s\né""#).unwrap();
        assert_eq!(doc.get("a"), Some(&s("q\"b\\s\n\u{e9}")));
    }

    #[test]
    fn refuses_what_it_does_not_take_by_position() {
        for (text, line) in [
            ("a.b = 1", 1),
            ("a = \"\"\"x\"\"\"", 1),
            ("\na = 1979-05-27", 2),
            ("a = 1e3", 1),
            ("a = 1\na = 2", 2),
            ("a = \"open", 1),
            ("a = [1, 2", 1),
            ("a = 1 b", 1),
            ("[t]\n[t]", 2),
        ] {
            let error = parse(text).unwrap_err();
            assert_eq!(error.line, line, "{text:?}: {error}");
        }
    }

    #[test]
    fn crlf_line_ends() {
        let doc = parse("a = 1\r\n[[x]]\r\nb = \"c\"\r\n").unwrap();
        assert_eq!(doc.get("a"), Some(&Value::Integer(1)));
    }
}
