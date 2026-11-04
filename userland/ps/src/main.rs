//! ps.exe: the running processes, a header then one line each, sorted by process id (see
//! [`ps::Line`]), and ends with 0. When the processes cannot be listed or the lines cannot be
//! written, it says so on the standard error and ends with [`ps::FAILED`].
//!
//! F2K's programs have no heap yet, so ps keeps no copy of the list: the snapshot is the storage,
//! walked once per line for the process that comes next ([`ps::comes_next`]).

#![no_std]
#![no_main]
#![forbid(unsafe_code)]

use core::fmt::Write;

exe::entry!(main);

fn main() -> u32 {
    let snapshot = match exe::ProcessSnapshot::take() {
        Ok(snapshot) => snapshot,
        Err(error) => {
            let _ = exe::stderr().print(format_args!(
                "ps: the processes cannot be listed ({error})\r\n"
            ));
            return ps::FAILED;
        }
    };
    let mut out = exe::stdout();
    let _ = write!(out, "{}", ps::Header);
    let mut after = None;
    loop {
        let next = match next_process(&snapshot, after) {
            Ok(Some(next)) => next,
            Ok(None) => break,
            Err(error) => {
                let _ = out.flush();
                let _ = exe::stderr().print(format_args!(
                    "ps: the processes cannot be listed ({error})\r\n"
                ));
                return ps::FAILED;
            }
        };
        let _ = write!(out, "{}", ps::Line(process(&next)));
        after = Some(next.id);
    }
    if let Err(error) = out.flush() {
        let _ = exe::stderr().print(format_args!(
            "ps: the standard output cannot be written ({error})\r\n"
        ));
        return ps::FAILED;
    }
    0
}

/// The snapshot's process with the least id after `after` (any, for none): one walk of it.
#[inline(never)]
fn next_process(
    snapshot: &exe::ProcessSnapshot,
    after: Option<u32>,
) -> Result<Option<exe::ProcessEntry>, exe::Error> {
    let mut best: Option<exe::ProcessEntry> = None;
    for entry in snapshot.processes() {
        let entry = entry?;
        if ps::comes_next(after, best.map(|best| best.id), entry.id) {
            best = Some(entry);
        }
    }
    Ok(best)
}

/// A snapshot's entry as ps shows it.
fn process(entry: &exe::ProcessEntry) -> ps::Process<'_> {
    ps::Process {
        id: entry.id,
        parent_id: entry.parent_id,
        threads: entry.threads,
        base_priority: entry.base_priority,
        name: entry.name(),
    }
}
