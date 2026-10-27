//! The process pool: every process record, at its final address for the kernel's life, and the
//! current process.
//!
//! A record is in use while its process object lives ([`crate::ob`]'s process pool, same index):
//! the object is created with the record and holds the process's own reference until its teardown
//! ends, so a handle to the process outlives the record's resources but not its slot. The capacity
//! is fixed: a process created while every record is in use is refused ([`create`]).
//!
//! A running thread has two processes (see [`crate::sched::attach`]), and the pool answers both.
//! The current process, the calling process of a system service, is the running thread's owner:
//! the thread record's owner pointer is the process record's leading scheduling record. Its handles
//! and objects are the ones a service acts on, whatever address space the thread runs on. The
//! address-space process ([`address_space`]) is the one whose directory the thread runs on: its
//! owner, or while attached the process it attached to — the process whose user pages the live
//! page tables, the page-fault resolution and the user-memory copies reach (Windows'
//! PsGetCurrentProcess). On the idle thread (whose own owner is the idle process, no pooled
//! process) no process is current: code that acts for a process there — the loader, attached to
//! the process it builds; the reap, on the boot address space — takes it explicitly.

#[cfg(target_arch = "x86")]
use super::Process;

/// How many processes can exist at once.
pub const MAX_PROCESSES: usize = 16;

/// The process records. Built where they live, field by field: by value a record would pass
/// through the boot stack, which is smaller than it.
#[cfg(target_arch = "x86")]
static mut POOL: core::mem::MaybeUninit<[Process; MAX_PROCESSES]> =
    core::mem::MaybeUninit::uninit();

// The records own no resources of their own (their frames are released by the teardown walk), so
// reusing one is overwriting it.
#[cfg(target_arch = "x86")]
const _: () = assert!(!core::mem::needs_drop::<Process>());

/// The record at `index`.
#[cfg(target_arch = "x86")]
fn record(index: u16) -> *mut Process {
    assert!((index as usize) < MAX_PROCESSES);
    // SAFETY: an index into the static array; the pointer is in bounds.
    unsafe { ((*core::ptr::addr_of_mut!(POOL)).as_mut_ptr() as *mut Process).add(index as usize) }
}

/// The pool index of the record whose scheduling record is at `owner`; none for a scheduling record
/// outside the pool (the idle process's) or a null owner.
#[cfg(target_arch = "x86")]
fn index_of(owner: *const crate::sched::process::SchedProcess) -> Option<u16> {
    let base = record(0) as usize;
    let at = owner as usize;
    let size = core::mem::size_of::<Process>();
    // The scheduling record leads the process record, so an owner pointer is its record's address.
    (at >= base && at < base + MAX_PROCESSES * size && (at - base) % size == 0)
        .then(|| ((at - base) / size) as u16)
}

/// Create a process: its object and its record at the same index, built in place over the address
/// space at `dir_phys`, named `name`, running as leg `leg` (none for a child).
/// STATUS_INSUFFICIENT_RESOURCES when every process record is in use (Windows 2000's answer to a
/// full table); nothing is taken then, and the address space stays the caller's.
#[cfg(target_arch = "x86")]
pub(super) fn create(
    dir_phys: u32,
    name: super::ProcessName,
    leg: Option<u32>,
) -> Result<&'static mut Process, crate::nt::call::Status> {
    let object = crate::ob::directory()
        .create_process()
        .ok_or(crate::nt::object::STATUS_INSUFFICIENT_RESOURCES)?;
    let process = record(object.index);
    // SAFETY: single CPU, interrupts disabled; the record is free (its object was not live), and
    // every field is written before the record is read.
    unsafe {
        super::write_fresh(process, dir_phys, name, leg, object);
        Ok(&mut *process)
    }
}

/// The process `thread` belongs to: the record whose scheduling record is the thread's owner;
/// none for the idle thread, which no pooled process owns.
#[cfg(target_arch = "x86")]
pub fn owner_of(thread: &crate::sched::thread::Thread) -> Option<&'static mut Process> {
    let index = index_of(thread.process)?;
    // SAFETY: the record of a live thread's owner, at its final address for the thread's life.
    Some(unsafe { &mut *record(index) })
}

/// The current process, mutably: the running thread's own (see the module notes) — the calling
/// process, whose handles and objects a service acts on, attached or not.
///
/// # Panics
///
/// No process is current: the running thread is no pooled process's (the idle thread).
#[cfg(target_arch = "x86")]
pub fn current_mut() -> &'static mut Process {
    let index = running(|thread| index_of(thread.process)).expect("no process is current");
    // SAFETY: the record of the running thread's owner, at its final address for the thread's
    // life.
    unsafe { &mut *record(index) }
}

/// The current process, immutably (reporting paths, and the handle lookups that change nothing).
#[cfg(target_arch = "x86")]
pub fn current() -> &'static Process {
    current_mut()
}

/// The process whose address space the running thread runs on (see the module notes): the one it
/// is attached to, or its own. Its user pages are the live ones.
///
/// # Panics
///
/// The running thread runs on no pooled process's address space (the idle thread, attached to
/// none).
#[cfg(target_arch = "x86")]
pub fn address_space() -> &'static mut Process {
    let index = running(|thread| index_of(thread.space())).expect("no process's pages are live");
    // SAFETY: the record of the running thread's address-space process, which outlives the
    // thread's scope on it.
    unsafe { &mut *record(index) }
}

/// What `query` answers of the running thread's record; none before the scheduler has a thread.
#[cfg(target_arch = "x86")]
fn running<R>(query: impl FnOnce(&crate::sched::thread::Thread) -> Option<R>) -> Option<R> {
    let thread = crate::sched::idle::dispatcher().current_thread();
    // SAFETY: single CPU; the running thread's record is live while it runs.
    unsafe { thread.as_ref() }.and_then(query)
}

/// The process the idle thread has to reap: one that has ended (its last thread's exit recorded
/// why) and is not yet torn down, no other process's thread attached to it. None when every
/// process is running, visited or gone.
#[cfg(target_arch = "x86")]
pub fn ended() -> Option<&'static mut Process> {
    (0..MAX_PROCESSES as u16).find_map(|index| {
        let id = crate::ob::directory().processes_live(index)?;
        // SAFETY: the record of a live process object, at its final address.
        let process = unsafe { &mut *record(index) };
        (process.end.is_some() && !process.torn_down && process.object == id && !visited(process))
            .then_some(process)
    })
}

/// Whether reaping `reaped` leaves the system quiescent: no other process remains that has not
/// been torn down — none running, none ended and waiting for its own reap. A torn-down process
/// whose object a handle still holds counts as gone.
#[cfg(target_arch = "x86")]
pub fn quiescent_after(reaped: &Process) -> bool {
    !(0..MAX_PROCESSES as u16).any(|index| {
        crate::ob::directory()
            .processes_live(index)
            .is_some_and(|id| {
                // SAFETY: as in `ended`.
                let process = unsafe { &*record(index) };
                process.object == id && id != reaped.object && !process.torn_down
            })
    })
}

/// Whether the idle thread has a process to reap (see [`ended`]).
#[cfg(target_arch = "x86")]
pub fn reap_pending() -> bool {
    (0..MAX_PROCESSES as u16).any(|index| {
        crate::ob::directory()
            .processes_live(index)
            .is_some_and(|id| {
                // SAFETY: as in `ended`.
                let process = unsafe { &*record(index) };
                process.end.is_some()
                    && !process.torn_down
                    && process.object == id
                    && !visited(process)
            })
    })
}

/// Whether a thread of another process runs attached to `process`'s address space (a service
/// reaching into it, see [`crate::sched::attach`]): its teardown waits for the scope to end, so
/// the directory the thread runs on is never freed under it.
#[cfg(target_arch = "x86")]
fn visited(process: &Process) -> bool {
    crate::ob::directory().attached_to(&process.sched)
}

/// The record of the process `id` names: none when `id` names no live process object. A record
/// lives as long as its object does — torn down, it still holds its identity (its client ids, its
/// object).
#[cfg(target_arch = "x86")]
pub fn of_object(id: crate::ob::ObjectId) -> Option<&'static mut Process> {
    crate::ob::directory().process(id)?;
    // SAFETY: the record of a live process object, at its final address.
    let process = unsafe { &mut *record(id.index) };
    (process.object == id).then_some(process)
}

/// The process object whose process has client id `id`, among the processes that have not ended:
/// as on Windows 2000, a process leaves the client id table when its last thread ends, while its
/// object lives on for the handles that hold it (they still query it and wait on it), so its id
/// names nothing any more.
#[cfg(target_arch = "x86")]
pub fn by_client_id(id: u32) -> Option<crate::ob::ObjectId> {
    (0..MAX_PROCESSES as u16).find_map(|index| {
        let object = crate::ob::directory().processes_live(index)?;
        // SAFETY: as in `ended`.
        let process = unsafe { &*record(index) };
        (process.object == object && process.id == id && process.end.is_none()).then_some(object)
    })
}
