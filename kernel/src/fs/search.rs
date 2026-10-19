//! Directory searches: what a directory's file object remembers between NtQueryDirectoryFile
//! calls — the expression its first call named and where the listing stopped — and the expression
//! matching itself (FsRtlIsNameInExpression's rules).
//!
//! The expression arrives as kernel32 makes it (FindFirstFileExW's transformations: `?` becomes
//! DOS_QM, a `*` before a dot DOS_STAR, a dot before a wildcard or ending the pattern DOS_DOT, and
//! `*.*` alone `*`), upper-cased here as the file system compares case-insensitively. Entries are
//! matched by their long name, then their 8.3 name. The searches live in one pool, as the file
//! records do: a directory's file object names its search while it has one, and gives it back
//! with its cleanup (no handle is left to ask with).

use super::fat32::dir::fold_unit;

/// How many directory searches can be open at once (across processes): exhaustion fails the query
/// (STATUS_INSUFFICIENT_RESOURCES), not the kernel.
pub const SEARCHES: usize = 32;

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
    used: bool,
    expression: [u16; MAX_EXPRESSION],
    length: usize,
    /// The record index the next match may start at.
    pub next: u32,
    /// Whether a query has returned an entry.
    pub answered: bool,
}

impl Search {
    const FREE: Search = Search { used: false, expression: [0; MAX_EXPRESSION], length: 0, next: 0, answered: false };

    /// The expression, folded.
    pub fn expression(&self) -> &[u16] {
        &self.expression[..self.length]
    }

    /// Back to the directory's start (RestartScan).
    pub fn restart(&mut self) {
        self.next = 0;
        self.answered = false;
    }
}

/// The open searches.
pub struct Searches {
    slots: [Search; SEARCHES],
}

impl Searches {
    /// None open (the tests build the pool by value; the kernel writes it in place).
    #[cfg(test)]
    pub const fn empty() -> Self {
        Searches { slots: [Search::FREE; SEARCHES] }
    }

    /// Open a search of `expression` (none: every name), folded: its number (from 1); none when the
    /// pool is full. The expression must fit [`MAX_EXPRESSION`].
    pub fn open(&mut self, expression: Option<&[u16]>) -> Option<u16> {
        let index = self.slots.iter().position(|slot| !slot.used)?;
        let slot = &mut self.slots[index];
        *slot = Search::FREE;
        slot.used = true;
        match expression {
            Some(units) => {
                for (out, &unit) in slot.expression.iter_mut().zip(units) {
                    *out = fold_unit(unit);
                }
                slot.length = units.len().min(MAX_EXPRESSION);
            }
            None => {
                slot.expression[0] = STAR;
                slot.length = 1;
            }
        }
        Some(index as u16 + 1)
    }

    /// The search numbered `number`.
    pub fn get(&mut self, number: u16) -> &mut Search {
        &mut self.slots[number as usize - 1]
    }

    /// Give the search numbered `number` back (zero: none).
    pub fn close(&mut self, number: u16) {
        if number != 0 {
            self.slots[number as usize - 1].used = false;
        }
    }

    /// How many searches are open.
    #[cfg(test)]
    pub fn live(&self) -> usize {
        self.slots.iter().filter(|slot| slot.used).count()
    }
}

/// The kernel's searches, built in place at first use.
#[cfg(target_arch = "x86")]
static mut SEARCH_POOL: core::mem::MaybeUninit<Searches> = core::mem::MaybeUninit::uninit();

/// Whether [`SEARCH_POOL`] is built.
#[cfg(target_arch = "x86")]
static mut SEARCHES_BUILT: bool = false;

/// The kernel's directory searches.
#[cfg(target_arch = "x86")]
pub fn searches() -> &'static mut Searches {
    // SAFETY: single CPU; services run serialized (the gate masks interrupts). Built once, in
    // place: all zeros is every slot free.
    unsafe {
        let pool = (*core::ptr::addr_of_mut!(SEARCH_POOL)).as_mut_ptr();
        if !SEARCHES_BUILT {
            pool.write_bytes(0, 1);
            SEARCHES_BUILT = true;
        }
        &mut *pool
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
        let mut out: Vec<u16> = pattern.trim_end_matches(['.', ' ']).encode_utf16().collect();
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
        let names = [".", "..", "BIG.BIN", "EMPTY.DAT", "HIDDEN.TXT", "Long File Name.txt", "SMALL.TXT", "SUB"];
        let listed = |pattern: &str| -> Vec<&str> { names.iter().copied().filter(|name| found(pattern, name)).collect() };
        assert_eq!(listed("*"), names);
        assert_eq!(listed("*.*"), names);
        assert_eq!(listed("*.TXT"), ["HIDDEN.TXT", "Long File Name.txt", "SMALL.TXT"]);
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

    /// A search keeps its folded expression (every name without one), restarts, and its slot goes
    /// back to the pool.
    #[test]
    fn searches_are_pooled() {
        let mut pool = Searches::empty();
        let first = pool.open(Some(&units("s*"))).unwrap();
        assert_eq!(pool.get(first).expression(), units("S*"));
        let every = pool.open(None).unwrap();
        assert_eq!(pool.get(every).expression(), units("*"));
        pool.get(first).next = 5;
        pool.get(first).answered = true;
        pool.get(first).restart();
        assert_eq!((pool.get(first).next, pool.get(first).answered), (0, false));
        pool.close(first);
        pool.close(0);
        assert_eq!(pool.live(), 1);
        for _ in 1..SEARCHES {
            pool.open(None).unwrap();
        }
        assert!(pool.open(None).is_none(), "the pool is full");
    }
}
