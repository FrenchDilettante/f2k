//! ps: the running processes, one line each, sorted by process id. The program (src/main.rs) takes
//! them from kernel32's ToolHelp; this library says what it prints, in which order, and the codes
//! it ends with.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

use core::fmt;

/// The exit code when the processes cannot be listed or printed (2 stays free for a usage error,
/// and 3 is the runtime's panic).
pub const FAILED: u32 = 1;

/// One process as ps shows it: its id, its creator's, its thread count, its base priority and its
/// image's file name (UTF-16, as ToolHelp gives it).
#[derive(Clone, Copy)]
pub struct Process<'a> {
    pub id: u32,
    pub parent_id: u32,
    pub threads: u32,
    pub base_priority: i32,
    pub name: &'a [u16],
}

/// The column headings, then CR LF: each heading right-aligned over its column, the name's left.
pub struct Header;

impl fmt::Display for Header {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("  PID  PPID  THR  PRI  NAME\r\n")
    }
}

/// A process's line: the id, the creator's id, the threads and the base priority right-aligned
/// under their headings (a wider value widens its column), then the name (an unpaired surrogate
/// shows as U+FFFD), then CR LF.
pub struct Line<'a>(pub Process<'a>);

impl fmt::Display for Line<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let process = &self.0;
        write!(
            f,
            "{:>5}{:>6}{:>5}{:>5}  ",
            process.id, process.parent_id, process.threads, process.base_priority
        )?;
        for character in char::decode_utf16(process.name.iter().copied()) {
            fmt::Write::write_char(f, character.unwrap_or(char::REPLACEMENT_CHARACTER))?;
        }
        f.write_str("\r\n")
    }
}

/// The order ps prints in, by process id, one walk of the snapshot per line: whether the process
/// `id` is a better next line than `best` (none yet) after the line for `after` (none: the first
/// line) — it comes after `after`, and before `best`.
pub fn comes_next(after: Option<u32>, best: Option<u32>, id: u32) -> bool {
    after.is_none_or(|after| id > after) && best.is_none_or(|best| id < best)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().collect()
    }

    fn line(id: u32, parent_id: u32, threads: u32, base_priority: i32, name: &str) -> String {
        let name = wide(name);
        Line(Process {
            id,
            parent_id,
            threads,
            base_priority,
            name: &name,
        })
        .to_string()
    }

    /// The header and the lines line up as the plan's sample shows.
    #[test]
    fn the_columns_line_up_under_their_headings() {
        let table = [
            Header.to_string(),
            line(0, 0, 1, 0, "[System Process]"),
            line(24, 0, 1, 8, "sched.exe"),
            line(28, 0, 1, 8, "ps.exe"),
        ]
        .concat();
        assert_eq!(
            table,
            "  PID  PPID  THR  PRI  NAME\r\n\
             \x20   0     0    1    0  [System Process]\r\n\
             \x20  24     0    1    8  sched.exe\r\n\
             \x20  28     0    1    8  ps.exe\r\n"
        );
    }

    /// A value wider than its column widens it; the others keep their places.
    #[test]
    fn a_wide_value_widens_its_column() {
        assert_eq!(
            line(123_456, 8, 12, 13, "services.exe"),
            "123456     8   12   13  services.exe\r\n"
        );
    }

    /// Names beyond ASCII print as they are; an unpaired surrogate as the replacement character.
    #[test]
    fn names_beyond_ascii() {
        assert_eq!(
            line(8, 0, 1, 8, "café.exe"),
            "    8     0    1    8  café.exe\r\n"
        );
        let name = [u16::from(b'a'), 0xD800];
        let shown = Line(Process {
            id: 8,
            parent_id: 0,
            threads: 1,
            base_priority: 8,
            name: &name,
        })
        .to_string();
        assert!(shown.ends_with("  a\u{FFFD}\r\n"));
    }

    /// Picking the next line among a walk's ids, again and again, prints them sorted.
    #[test]
    fn the_lines_come_sorted_by_id() {
        let walk = [24, 0, 40, 8, 32];
        let mut printed = Vec::new();
        let mut after = None;
        loop {
            let mut best = None;
            for &id in &walk {
                if comes_next(after, best, id) {
                    best = Some(id);
                }
            }
            let Some(next) = best else { break };
            printed.push(next);
            after = Some(next);
        }
        assert_eq!(printed, [0, 8, 24, 32, 40]);
    }
}
