//! The process pool: every process record, at its final address for the kernel's life, and the
//! current process.
//!
//! A record is in use while its process object lives ([`crate::ob`]'s process pool, same index):
//! the object is created with the record and holds the process's own reference until its deletion,
//! so a handle to the process keeps its record and its address space, as Windows 2000's keeps
//! the process until its object's deletion. The pool grows: the records are a side table
//! ([`crate::slots::SideTable`]) keyed by the object's index, whose record is made in the nonpaged
//! pool ([`crate::mem::pool`]) the first time a process takes its index, and kept for the kernel's
//! life, reused by every later process at that index, so it never moves (Windows 2000 takes its
//! EPROCESS from the nonpaged pool too). A record costs some 27 KiB, so a table of them built into
//! the kernel's image would cap the processes; this one has no cap, as Windows 2000 has none: what
//! bounds it is memory (a process whose object, record or side tables find no page is refused,
//! [`create`]), and the object's u16 index, a representation limit (65,534 processes) far past
//! what memory backs. The records are shared: what changes in one sits behind its own locks (see
//! [`Process`]), so every accessor hands out `&'static Process`, which every thread of the process
//! may hold at once.
//!
//! A running thread has two processes (see [`crate::sched::attach`]), and the pool answers both,
//! by the indices the processor's slots name them by. The current process, the calling process of
//! a system service, is the running thread's owner. Its handles and objects are the ones a service
//! acts on, whatever address space the thread runs on. The address-space process
//! ([`address_space`]) is the one whose directory the thread runs on: its owner, or while attached
//! the process it attached to — the process whose user pages the live page tables, the page-fault
//! resolution and the user-memory copies reach (Windows' PsGetCurrentProcess). On the idle thread
//! (whose own owner is the idle process, no pooled process) no process is current: code that acts
//! for a process there — the loader, attached to the process it builds; the reap, on the boot
//! address space — takes it explicitly.

use core::sync::atomic::{AtomicBool, Ordering};

#[cfg(target_arch = "x86")]
use super::Process;
#[cfg(target_arch = "x86")]
use crate::slots::{NonpagedPages, SideTable};

/// The process records, by pool index: a record is made, with its chunk, the first time a process
/// takes its index, and kept at that address for the kernel's life (see the module notes). Readers
/// take no lock: the table resolves through its directory alone, and is only ever ensured, never
/// borrowed mutably, so it holds its own directory. Its chunks and directory pages count among the
/// slot pools' permanent frames ([`crate::slots::chunk_frames`]), which the teardown audits add to
/// the free frames.
#[cfg(target_arch = "x86")]
static RECORDS: SideTable<Process, 1> = SideTable::new();

/// The record at pool `index`, if one was made.
#[cfg(target_arch = "x86")]
fn made(index: u16) -> Option<&'static Process> {
    RECORDS.get(index.into())
}

/// The record at pool `index`, made in the nonpaged pool when none was yet: none when the pool
/// has no room for it.
#[cfg(target_arch = "x86")]
fn make(index: u16) -> Option<&'static Process> {
    RECORDS.ensure(index.into(), &NonpagedPages).ok()?;
    made(index)
}

/// The record at pool `index`, whatever it holds (the caller knows a process holds it).
///
/// # Panics
///
/// No process ever took `index`.
#[cfg(target_arch = "x86")]
pub fn record(index: u16) -> &'static Process {
    made(index).expect("a process record taken by a live process")
}

/// Every record whose process object lives, with its object, in pool order: a hold of the
/// directory a step, each finding the next live object past the last one found (no snapshot of
/// every process, which would need room for as many as there may be). A process created during
/// the walk is found when its index lies ahead of it; one deleted meanwhile is not.
#[cfg(target_arch = "x86")]
fn live() -> impl Iterator<Item = (&'static Process, crate::ob::ObjectId)> {
    let mut from = 0u16;
    core::iter::from_fn(move || loop {
        let id = crate::ob::locked(|directory| directory.next_live_process(from))?;
        // The u16 index stops at 0xFFFE: the step after the last index finds nothing.
        from = id.index + 1;
        if let Some(process) = made(id.index).filter(|process| process.object() == id) {
            return Some((process, id));
        }
    })
}

/// Every process that has not ended, in pool order: the process listing's. As the toolhelp
/// fixture's capture shows Windows 2000's, a process leaves the listing when its last thread ends,
/// while its object lives on for the handles that hold it — the processes [`by_client_id`] finds.
/// One created without a thread yet is listed.
#[cfg(target_arch = "x86")]
pub fn listed() -> impl Iterator<Item = &'static Process> {
    live().filter_map(|(process, _)| {
        (process.end().is_none() && !process.deleting()).then_some(process)
    })
}

/// Create a process: its object and its record at the same index, the record taken in place over
/// the address space at `dir_phys`, named `name`, created by the process whose client id is
/// `parent_id` (zero: none), running as leg `leg` (none for a child).
/// STATUS_INSUFFICIENT_RESOURCES when the object, or a record not yet made (or the drivers'
/// stand-in for the process, [`crate::dev::io`]'s), finds no room in the nonpaged pool (Windows
/// 2000's answer to an exhausted pool), or every u16 index is in use; nothing is taken then — the
/// object made goes again — and the address space stays the caller's.
#[cfg(target_arch = "x86")]
pub(super) fn create(
    dir_phys: crate::mem::phys::PhysAddr,
    name: super::ProcessName,
    leg: Option<u32>,
    parent_id: u32,
) -> Result<&'static Process, crate::status::NtStatus> {
    let object = crate::ob::locked(|directory| directory.create_process())
        .ok_or(crate::status::STATUS_INSUFFICIENT_RESOURCES)?;
    let made = make(object.index).filter(|_| crate::dev::io::make_process_stand_in(object.index));
    let Some(process) = made else {
        // Nothing names the object yet, and nothing ran on it: its creator's reference was its
        // only one, and a process object's deletion leaves nothing to finish.
        let left = crate::ob::locked(|directory| directory.dereference(object));
        debug_assert!(left.is_none(), "a process object's deletion leaves nothing");
        return Err(crate::status::STATUS_INSUFFICIENT_RESOURCES);
    };
    process.renew(object, dir_phys, name, leg, parent_id);
    Ok(process)
}

/// The current process (see the module notes): the running thread's own — the calling process,
/// whose handles and objects a service acts on, attached or not.
///
/// # Panics
///
/// No process is current: the running thread is no pooled process's (the idle thread).
#[cfg(target_arch = "x86")]
pub fn current() -> &'static Process {
    record(
        crate::pcr::pcr()
            .threads
            .process()
            .expect("no process is current"),
    )
}

/// The process whose address space the running thread runs on (see the module notes): the one it
/// is attached to, or its own. Its user pages are the live ones.
///
/// # Panics
///
/// The running thread runs on no pooled process's address space (the idle thread, attached to
/// none).
#[cfg(target_arch = "x86")]
pub fn address_space() -> &'static Process {
    record(
        crate::pcr::pcr()
            .threads
            .space()
            .expect("no process's pages are live"),
    )
}

/// The process the idle thread has to reap: one that has ended (its last thread's exit recorded
/// why) and is not yet torn down, no other process's thread attached to it. None when every
/// process is running, visited or gone.
#[cfg(target_arch = "x86")]
pub fn ended() -> Option<&'static Process> {
    live()
        .map(|(process, _)| process)
        .find(|process| awaits_reap(process))
}

/// Whether reaping `reaped` leaves the system quiescent: no other process remains that has not
/// been torn down — none running, none ended and waiting for its own reap. A torn-down process
/// whose object a handle still holds counts as gone.
#[cfg(target_arch = "x86")]
pub fn quiescent_after(reaped: &Process) -> bool {
    !live().any(|(process, id)| id != reaped.object() && !process.torn_down())
}

/// A look for a process to reap, queued where one may have become reapable: its last thread's
/// retire, or the end of the last attach to it. Windows 2000 queues the dead thread to the
/// reaper's list (PspReaper) rather than polling for it; the idle thread scans only when queued.
pub struct ReapTrigger(AtomicBool);

impl ReapTrigger {
    pub const fn new() -> Self {
        Self(AtomicBool::new(false))
    }

    /// Queue a look.
    pub fn queue(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    /// Whether `scan` finds a process to reap, run only when a look is queued; `scan` answers
    /// none when it cannot look yet. The look is taken before the scan, so one queued during it is
    /// kept; it is kept too after a find (a reap takes one process) or no look.
    pub fn due(&self, scan: impl FnOnce() -> Option<bool>) -> bool {
        if !self.0.swap(false, Ordering::SeqCst) {
            return false;
        }
        let found = scan();
        if found != Some(false) {
            self.queue();
        }
        found == Some(true)
    }
}

#[cfg(target_arch = "x86")]
static REAP: ReapTrigger = ReapTrigger::new();

/// Queue a look for a process to reap (see [`ReapTrigger`]).
#[cfg(target_arch = "x86")]
pub fn queue_reap() {
    REAP.queue();
}

/// Whether the idle thread has a process to reap (see [`ended`]), scanned for only when a look is
/// queued ([`queue_reap`]). The idle thread cannot wait for the directory or a process's lock, and
/// need not: it runs on its own only when no other thread is ready — so none holds a short lock —
/// and a last thread hands it the processor only while none is held (see `crate::sync`'s notes).
/// Checked first all the same: a held lock holds the look off until the idle thread's next pass.
#[cfg(target_arch = "x86")]
pub fn reap_pending() -> bool {
    REAP.due(|| {
        if !crate::sync::short_locks_free() {
            return None;
        }
        debug_assert!(
            crate::ob::is_free(),
            "the idle thread finds the directory free"
        );
        Some(live().any(|(process, _)| awaits_reap(process)))
    })
}

/// How many processes have ended, or are ending, and are not torn down yet: the teardowns the
/// session's end waits for before the shutdown (see [`super::teardowns`]). A process counts from
/// the decision of its end (its termination, before its last thread has ended) when it has a
/// thread to end it; one terminated before its first thread is deleted, never reaped.
#[cfg(target_arch = "x86")]
pub fn teardowns_pending() -> usize {
    live()
        .filter(|(process, _)| {
            process.awaits_teardown()
                || (process.terminating() && !process.torn_down() && process.has_main_thread())
        })
        .count()
}

/// Whether `process`, whose object lives, awaits its reap: it has ended, it is not torn down, its
/// last thread has retired (it records the end before its retire, and nothing else runs between
/// its retire and its switch away), and no thread of another process runs attached to its address
/// space (a service reaching into it, see [`crate::sched::attach`]) — the reap follows that scope's
/// end. The address space itself outlives any such service: it goes with the process's deletion,
/// which the service's reference on the object holds off.
#[cfg(target_arch = "x86")]
fn awaits_reap(process: &Process) -> bool {
    let retired = crate::level::raised::<crate::level::Dispatch, _>(|dispatch| {
        process
            .sched(crate::sched::DISPATCHER.get(dispatch))
            .has_no_threads()
    });
    process.awaits_teardown() && retired && process.attach_count() == 0
}

/// The record of the process `id` names: none when `id` names no live process object. A record
/// lives as long as its object does — torn down, it still holds its identity (its client ids, its
/// object).
#[cfg(target_arch = "x86")]
pub fn of_object(id: crate::ob::ObjectId) -> Option<&'static Process> {
    crate::ob::locked(|directory| directory.process(id))?;
    let process = record(id.index);
    (process.object() == id).then_some(process)
}

/// The process object whose process has client id `id`, among the processes that have not ended:
/// as on Windows 2000, a process leaves the client id table when its last thread ends, while its
/// object lives on for the handles that hold it (they still query it and wait on it), so its id
/// names nothing any more. A process that never had a thread leaves it when its deletion begins.
#[cfg(target_arch = "x86")]
pub fn by_client_id(id: u32) -> Option<crate::ob::ObjectId> {
    live().find_map(|(process, object)| {
        (process.id() == id && process.end().is_none() && !process.deleting()).then_some(object)
    })
}

#[cfg(test)]
mod tests {
    use super::ReapTrigger;

    #[test]
    fn nothing_queued_scans_nothing() {
        let trigger = ReapTrigger::new();
        assert!(!trigger.due(|| panic!("scanned with nothing queued")));
    }

    #[test]
    fn a_find_keeps_the_look_and_a_miss_takes_it() {
        let trigger = ReapTrigger::new();
        trigger.queue();
        assert!(trigger.due(|| Some(true)));
        assert!(!trigger.due(|| Some(false)), "the next pass looks again");
        assert!(!trigger.due(|| panic!("the miss took the look")));
    }

    #[test]
    fn a_look_held_off_stays_queued() {
        let trigger = ReapTrigger::new();
        trigger.queue();
        assert!(!trigger.due(|| None));
        assert!(trigger.due(|| Some(true)));
    }

    #[test]
    fn a_look_queued_during_the_scan_is_kept() {
        let trigger = ReapTrigger::new();
        trigger.queue();
        assert!(!trigger.due(|| {
            trigger.queue();
            Some(false)
        }));
        assert!(trigger.due(|| Some(true)));
    }
}
