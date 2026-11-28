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
use rtl::text::upcase;

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
///
/// The match runs the expression as a set of positions over the name, one unit at a time, as
/// FsRtlIsNameInExpression does: time in name length × expression length, whatever the pattern (a
/// backtracking match is exponential in its stars, and a search runs with interrupts masked). An
/// expression past [`MAX_EXPRESSION`] units (which a [`Search`] never keeps) matches nothing.
pub fn matches(expression: &[u16], name: &[u16]) -> bool {
    if expression.len() > MAX_EXPRESSION {
        return false;
    }
    let last_dot = name.iter().rposition(|&unit| unit == DOT);
    let mut states = States::default();
    states.insert(0);
    for (at, &unit) in name.iter().enumerate() {
        states.close(expression, Some(unit));
        let mut next = States::default();
        for (position, &wild) in expression.iter().enumerate() {
            if !states.contains(position) {
                continue;
            }
            match wild {
                STAR => next.insert(position),
                DOS_STAR if last_dot != Some(at) => next.insert(position),
                DOS_STAR => {}
                QUESTION => next.insert(position + 1),
                DOS_QM if unit != DOT => next.insert(position + 1),
                DOS_QM => {}
                DOS_DOT if unit == DOT => next.insert(position + 1),
                DOS_DOT => {}
                literal if literal == unit => next.insert(position + 1),
                _ => {}
            }
        }
        if next.is_empty() {
            return false;
        }
        states = next;
    }
    states.close(expression, None);
    states.contains(expression.len())
}

/// A set of expression positions (0 to [`MAX_EXPRESSION`], the last the expression's end).
#[derive(Default)]
struct States([u64; (MAX_EXPRESSION + 1).div_ceil(64)]);

impl States {
    fn insert(&mut self, position: usize) {
        self.0[position / 64] |= 1 << (position % 64);
    }

    fn contains(&self, position: usize) -> bool {
        self.0[position / 64] & (1 << (position % 64)) != 0
    }

    fn is_empty(&self) -> bool {
        self.0.iter().all(|&word| word == 0)
    }

    /// Adds the positions reached without taking a unit, before `next` (none: the name's end):
    /// past a star or a DOS star (an empty run), and past a DOS_QM or a DOS_DOT at a dot (DOS_QM)
    /// or the end (both). These only step forward, so one pass in order closes the set.
    fn close(&mut self, expression: &[u16], next: Option<u16>) {
        for (position, &wild) in expression.iter().enumerate() {
            let empty = match wild {
                STAR | DOS_STAR => true,
                DOS_QM => next.is_none_or(|unit| unit == DOT),
                DOS_DOT => next.is_none(),
                _ => false,
            };
            if empty && self.contains(position) {
                self.insert(position + 1);
            }
        }
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
                .for_each(|&unit| kept.push(upcase(unit))),
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
        text.encode_utf16().map(upcase).collect()
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
        out.into_iter().map(upcase).collect()
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

    /// The backtracking matcher this replaced, kept to check the state-set one against.
    fn backtracking(expression: &[u16], name: &[u16]) -> bool {
        let Some((&first, rest)) = expression.split_first() else {
            return name.is_empty();
        };
        match first {
            STAR => (0..=name.len()).any(|skip| backtracking(rest, &name[skip..])),
            DOS_STAR => {
                let last_dot = name.iter().rposition(|&unit| unit == DOT);
                (0..=name.len())
                    .filter(|&skip| last_dot.is_none_or(|dot| skip <= dot))
                    .any(|skip| backtracking(rest, &name[skip..]))
            }
            QUESTION => !name.is_empty() && backtracking(rest, &name[1..]),
            DOS_QM => match name.first() {
                None => backtracking(rest, name),
                Some(&unit) if unit == DOT => backtracking(rest, name),
                Some(_) => backtracking(rest, &name[1..]),
            },
            DOS_DOT => match name.first() {
                None => backtracking(rest, name),
                Some(&unit) if unit == DOT => backtracking(rest, &name[1..]),
                Some(_) => false,
            },
            unit => name.first() == Some(&unit) && backtracking(rest, &name[1..]),
        }
    }

    /// Every short expression over `*?<>".AB` against every short name over `.AB`: the state set
    /// answers as the backtracking match did.
    #[test]
    fn the_state_set_answers_as_backtracking_did() {
        let wild = [
            STAR,
            QUESTION,
            DOS_STAR,
            DOS_QM,
            DOS_DOT,
            DOT,
            b'A' as u16,
            b'B' as u16,
        ];
        let plain = [DOT, b'A' as u16, b'B' as u16];
        let every = |alphabet: &[u16], longest: usize| -> Vec<Vec<u16>> {
            let mut all = vec![Vec::new()];
            let mut last = vec![Vec::new()];
            for _ in 0..longest {
                last = last
                    .iter()
                    .flat_map(|word: &Vec<u16>| {
                        alphabet.iter().map(move |&unit| {
                            let mut longer = word.clone();
                            longer.push(unit);
                            longer
                        })
                    })
                    .collect();
                all.extend(last.iter().cloned());
            }
            all
        };
        let names = every(&plain, 5);
        for expression in every(&wild, 4) {
            for name in &names {
                assert_eq!(
                    matches(&expression, name),
                    backtracking(&expression, name),
                    "{expression:?} against {name:?}"
                );
            }
        }
    }

    /// Patterns that made the backtracking match exponential answer at once: stars that each
    /// could take any run, against a long name that fails only at its end.
    #[test]
    fn a_pathological_pattern_answers_at_once() {
        let name = units(&"a".repeat(255));
        assert!(!matches(&units("*a*a*a*a*a*a*a*a*a*a*a*a*a*b"), &name));
        assert!(matches(&units("*a*a*a*a*a*a*a*a*a*a*a*a*a*a"), &name));
        let dos: Vec<u16> = [DOS_STAR, b'A' as u16]
            .repeat(60)
            .into_iter()
            .chain([b'B' as u16])
            .collect();
        assert!(!matches(&dos, &name));
        let mixed: Vec<u16> = [STAR, DOS_QM, b'A' as u16]
            .repeat(80)
            .into_iter()
            .chain([DOS_DOT, b'B' as u16])
            .collect();
        assert!(!matches(&mixed, &name));
        let long = vec![STAR; MAX_EXPRESSION];
        assert!(matches(&long, &name));
        assert!(!matches(&vec![STAR; MAX_EXPRESSION + 1], &name));
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
