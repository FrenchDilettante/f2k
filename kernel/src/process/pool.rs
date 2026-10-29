//! The process pool: every process record, at its final address for the kernel's life, and the
//! current process.
//!
//! A record is in use while its process object lives ([`crate::ob`]'s process pool, same index):
//! the object is created with the record and holds the process's own reference until its teardown
//! ends, so a handle to the process outlives the record's resources but not its slot. The capacity
//! is fixed: a process created while every record is in use is refused ([`create`]). The records
//! are shared: what changes in one sits behind its own locks (see [`Process`]), so every accessor
//! hands out `&'static Process`, which every thread of the process may hold at once.
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

#[cfg(target_arch = "x86")]
use super::Process;

/// How many processes can exist at once.
pub const MAX_PROCESSES: usize = 16;

/// The process records, built with the kernel: a record no process holds is an empty one, and a
/// new process's record starts over in place ([`Process`]'s parts are too large to pass through a
/// stack by value).
#[cfg(target_arch = "x86")]
static POOL: [Process; MAX_PROCESSES] = [const { Process::empty() }; MAX_PROCESSES];

/// The record at pool `index`, whatever it holds (the caller knows a process holds it).
#[cfg(target_arch = "x86")]
pub fn record(index: u16) -> &'static Process {
    &POOL[index as usize]
}

/// The process objects that live now, by pool index, as one hold of the directory finds them.
#[cfg(target_arch = "x86")]
fn live_objects() -> [Option<crate::ob::ObjectId>; MAX_PROCESSES] {
    crate::ob::locked(|directory| {
        core::array::from_fn(|index| directory.processes_live(index as u16))
    })
}

/// Every record whose process object lives, with its object.
#[cfg(target_arch = "x86")]
fn live() -> impl Iterator<Item = (&'static Process, crate::ob::ObjectId)> {
    POOL.iter().zip(live_objects()).filter_map(|(process, id)| {
        id.filter(|&id| process.object() == id)
            .map(|id| (process, id))
    })
}

/// Create a process: its object and its record at the same index, the record taken in place over
/// the address space at `dir_phys`, named `name`, created by the process whose client id is
/// `parent_id` (zero: none), running as leg `leg` (none for a child).
/// STATUS_INSUFFICIENT_RESOURCES when every process record is in use (Windows 2000's answer to a
/// full table); nothing is taken then, and the address space stays the caller's.
#[cfg(target_arch = "x86")]
pub(super) fn create(
    dir_phys: u32,
    name: super::ProcessName,
    leg: Option<u32>,
    parent_id: u32,
) -> Result<&'static Process, crate::status::NtStatus> {
    let object = crate::ob::locked(|directory| directory.create_process())
        .ok_or(crate::status::STATUS_INSUFFICIENT_RESOURCES)?;
    let process = record(object.index);
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

/// Whether the idle thread has a process to reap (see [`ended`]). The idle thread cannot wait for
/// the directory or a process's lock, and need not: it runs on its own only when no other thread
/// is ready — so none holds a short lock — and a last thread hands it the processor only while
/// none is held (see `crate::sync`'s notes). Checked first all the same: a held lock holds the
/// reap off until the idle thread's next pass.
#[cfg(target_arch = "x86")]
pub fn reap_pending() -> bool {
    if !crate::sync::short_locks_free() {
        return false;
    }
    debug_assert!(
        crate::ob::is_free(),
        "the idle thread finds the directory free"
    );
    live().any(|(process, _)| awaits_reap(process))
}

/// Whether `process`, whose object lives, awaits its reap: it has ended, it is not torn down, its
/// last thread has retired (it records the end before its retire, and nothing else runs between
/// its retire and its switch away), and no thread of another process runs attached to its address
/// space (a service reaching into it, see [`crate::sched::attach`]) — its teardown waits for that
/// scope to end, so the directory the thread runs on is never freed under it.
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
/// names nothing any more.
#[cfg(target_arch = "x86")]
pub fn by_client_id(id: u32) -> Option<crate::ob::ObjectId> {
    live().find_map(|(process, object)| {
        (process.id() == id && process.end().is_none()).then_some(object)
    })
}
