//! Directory searches: what a directory's file object remembers between NtQueryDirectoryFile
//! calls — the expression its first call named and where the listing stopped — and the expression
//! matching itself (FsRtlIsNameInExpression's rules).
//!
//! The expression arrives as kernel32 makes it (FindFirstFileExW's transformations: `?` becomes
//! DOS_QM, a `*` before a dot DOS_STAR, a dot before a wildcard or ending the pattern DOS_DOT, and
//! `*.*` alone `*`), upper-cased here as the file system compares case-insensitively. Entries are
//! matched by their long name, then their 8.3 name. A search is its directory's file object's own
//! ([`super::file::FileObject::search`]), as Windows 2000 keeps it in the file object's context
//! block: made by the first query, it goes with the object.

use rtl::array_vec::ArrayVec;

use super::fat32::dir::fold_unit;

/// The longest expression kept, in units.
pub const MAX_EXPRESSION: usize = 260;

/// The DOS wildcards kernel32's transformations make.
pub const DOS_STAR: u16 = b'<' as u16;
pub const DOS_QM: u16 = b'>' as u16;
pub const DOS_DOT: u16 = b'"' as u16;
const STAR: u16 = b'*' as u16;
const QUESTION: u16 = b'?' as u16;
const DOT: u16 = b'.' as u16;

/// Whether `name` (folded units) matches `expression` (folded units): `*` any run; `?` one unit;
/// DOS_STAR any run not past the name's last dot; DOS_QM one unit, or none at a dot or the end;
/// DOS_DOT a dot, or nothing at the end.
pub fn matches(expression: &[u16], name: &[u16]) -> bool {
    let Some((&first, rest)) = expression.split_first() else {
        return name.is_empty();
    };
    match first {
        STAR => (0..=name.len()).any(|skip| matches(rest, &name[skip..])),
        DOS_STAR => {
            let last_dot = name.iter().rposition(|&unit| unit == DOT);
            (0..=name.len())
                .filter(|&skip| last_dot.is_none_or(|dot| skip <= dot))
                .any(|skip| matches(rest, &name[skip..]))
        }
        QUESTION => !name.is_empty() && matches(rest, &name[1..]),
        DOS_QM => match name.first() {
            None => matches(rest, name),
            Some(&unit) if unit == DOT => matches(rest, name),
            Some(_) => matches(rest, &name[1..]),
        },
        DOS_DOT => match name.first() {
            None => matches(rest, name),
            Some(&unit) if unit == DOT => matches(rest, &name[1..]),
            Some(_) => false,
        },
        unit => name.first() == Some(&unit) && matches(rest, &name[1..]),
    }
}

/// One directory search: its expression (folded) and the record index the next match may start
/// at, and whether it has answered anything yet (an exhausted search that never matched is
/// STATUS_NO_SUCH_FILE, one that did STATUS_NO_MORE_FILES).
#[derive(Clone, Copy)]
pub struct Search {
    expression: ArrayVec<u16, MAX_EXPRESSION>,
    /// The record index the next match may start at.
    pub next: u32,
    /// Whether a query has returned an entry.
    pub answered: bool,
}

impl Search {
    /// A search of `expression` (none: every name), folded, from the directory's start. An
    /// expression past [`MAX_EXPRESSION`] keeps its first units.
    pub fn new(expression: Option<&[u16]>) -> Self {
        let mut kept = ArrayVec::new();
        match expression {
            Some(units) => units
                .iter()
                .take(MAX_EXPRESSION)
                .for_each(|&unit| kept.push(fold_unit(unit))),
            None => kept.push(STAR),
        }
        Search {
            expression: kept,
            next: 0,
            answered: false,
        }
    }

    /// The expression, folded.
    pub fn expression(&self) -> &[u16] {
        &self.expression
    }

    /// Back to the directory's start (RestartScan).
    pub fn restart(&mut self) {
        self.next = 0;
        self.answered = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn units(text: &str) -> Vec<u16> {
        text.encode_utf16().map(fold_unit).collect()
    }

    /// kernel32's transformation of a FindFirstFile pattern (FindFirstFileExW's, restated), after
    /// the path's own trimming of the trailing dots and spaces.
    fn transformed(pattern: &str) -> Vec<u16> {
        if pattern == "*.*" {
            return units("*");
        }
        let mut out: Vec<u16> = pattern
            .trim_end_matches(['.', ' '])
            .encode_utf16()
            .collect();
        for index in 0..out.len() {
            if index > 0 && out[index] == DOT && out[index - 1] == STAR {
                out[index - 1] = DOS_STAR;
            }
            if out[index] == QUESTION || out[index] == STAR {
                if out[index] == QUESTION {
                    out[index] = DOS_QM;
                }
                if index > 0 && out[index - 1] == DOT {
                    out[index - 1] = DOS_DOT;
                }
            }
        }
        if pattern.ends_with('.') && out.last() == Some(&STAR) {
            *out.last_mut().unwrap() = DOS_STAR;
        }
        out.into_iter().map(fold_unit).collect()
    }

    fn found(pattern: &str, name: &str) -> bool {
        matches(&transformed(pattern), &units(name))
    }

    /// The files capture's patterns over its directory.
    #[test]
    fn the_captured_patterns() {
        let names = [
            ".",
            "..",
            "BIG.BIN",
            "EMPTY.DAT",
            "HIDDEN.TXT",
            "Long File Name.txt",
            "SMALL.TXT",
            "SUB",
        ];
        let listed = |pattern: &str| -> Vec<&str> {
            names
                .iter()
                .copied()
                .filter(|name| found(pattern, name))
                .collect()
        };
        assert_eq!(listed("*"), names);
        assert_eq!(listed("*.*"), names);
        assert_eq!(
            listed("*.TXT"),
            ["HIDDEN.TXT", "Long File Name.txt", "SMALL.TXT"]
        );
        assert_eq!(listed("S*"), ["SMALL.TXT", "SUB"]);
        assert_eq!(listed("?????.TXT"), ["SMALL.TXT"]);
        assert_eq!(listed("Long*"), ["Long File Name.txt"]);
        assert!(listed("*.XYZ").is_empty());
        assert_eq!(listed("sub"), ["SUB"]);
    }

    /// The DOS forms: `?` before a dot matches short names too, `*.` matches names without an
    /// extension, and a DOS star stops at the last dot; a plain `?` (a caller of the service
    /// itself) is exactly one unit.
    #[test]
    fn the_dos_wildcards() {
        assert!(found("????.TXT", "AB.TXT"));
        assert!(!found("????.TXT", "ABCDE.TXT"));
        assert!(found("*.", "README"));
        assert!(!found("*.", "README.TXT"));
        assert!(found("*.gz", "a.tar.gz"));
        assert!(!found("*.tar", "a.tar.gz"));
        assert!(found("a?c", "abc"));
        assert!(!found("a?c", "ac"));
        assert!(matches(&units("A?C"), &units("ABC")));
        assert!(!matches(&units("A?C"), &units("AC")));
    }

    /// A search keeps its folded expression (every name without one, the first units of one too
    /// long) and restarts.
    #[test]
    fn a_search_keeps_its_expression() {
        let mut search = Search::new(Some(&units("s*")));
        assert_eq!(search.expression(), units("S*"));
        assert_eq!(Search::new(None).expression(), units("*"));
        search.next = 5;
        search.answered = true;
        search.restart();
        assert_eq!((search.next, search.answered), (0, false));
        let long = vec![b'a' as u16; MAX_EXPRESSION + 3];
        assert_eq!(
            Search::new(Some(&long)).expression(),
            units(&"A".repeat(MAX_EXPRESSION))
        );
    }
}
