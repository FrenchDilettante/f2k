//! The process pool: every process record, at its final address for the kernel's life, and the
//! current process.
//!
//! A record is in use while its process object lives ([`crate::ob`]'s process pool, same index):
//! the object is created with the record and holds the process's own reference until its teardown
//! ends, so a handle to the process outlives the record's resources but not its slot. The capacity
//! is fixed (one process runs at a time until CreateProcess exists).
//!
//! The current process is the running thread's owner: the thread record's owner pointer is the
//! process record's leading scheduling record. Outside the process's own threads — the boot path
//! loading it, the idle thread reaping it — the kernel acts for the process it is attached to (the
//! idle thread's own owner is the idle process, which is no pooled process).

#[cfg(target_arch = "x86")]
use super::Process;

/// How many processes can exist at once.
pub const MAX_PROCESSES: usize = 16;

/// The process records. Built where they live, field by field: by value a record would pass
/// through the boot stack, which is smaller than it.
#[cfg(target_arch = "x86")]
static mut POOL: core::mem::MaybeUninit<[Process; MAX_PROCESSES]> =
    core::mem::MaybeUninit::uninit();

/// The record the kernel acts for outside the process's own threads (see the module notes).
#[cfg(target_arch = "x86")]
static mut ATTACHED: Option<u16> = None;

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

/// Create a process: its object (none free is the caller's failure, a panic today: one process runs
/// at a time) and its record at the same index, built in place over the address space at
/// `dir_phys`, named `name`; the kernel is attached to it until its main thread runs.
#[cfg(target_arch = "x86")]
pub(super) fn create(dir_phys: u32, name: &'static str) -> &'static mut Process {
    let object = crate::ob::directory()
        .create_process()
        .expect("a process record is free (one process runs at a time)");
    let process = record(object.index);
    // SAFETY: single CPU, interrupts disabled; the record is free (its object was not live), and
    // every field is written before the record is read.
    unsafe {
        super::write_fresh(process, dir_phys, name, object);
        *core::ptr::addr_of_mut!(ATTACHED) = Some(object.index);
        &mut *process
    }
}

/// The current process, mutably (see the module notes).
///
/// # Panics
///
/// No process is current: the running thread is no process's and the kernel is attached to none.
#[cfg(target_arch = "x86")]
pub fn current_mut() -> &'static mut Process {
    // SAFETY: single CPU; the running thread is live, and its owner (when it is a pooled process)
    // is that process's record at its final address. The attachment has no other writer.
    unsafe {
        let thread = crate::sched::idle::dispatcher().current_thread();
        let owner = if thread.is_null() {
            None
        } else {
            index_of((*thread).process)
        };
        let index = owner
            .or(*core::ptr::addr_of!(ATTACHED))
            .expect("no process is current");
        &mut *record(index)
    }
}

/// The current process, immutably (reporting paths, and the handle lookups that change nothing).
#[cfg(target_arch = "x86")]
pub fn current() -> &'static Process {
    current_mut()
}

/// Attach the kernel to the process at `index` (the idle thread's reap acts for it).
#[cfg(target_arch = "x86")]
fn attach(index: u16) {
    // SAFETY: single CPU; the attachment's writers run serialized.
    unsafe { *core::ptr::addr_of_mut!(ATTACHED) = Some(index) };
}

/// Detach the kernel from the process it acts for (its teardown is done).
#[cfg(target_arch = "x86")]
pub(super) fn detach() {
    // SAFETY: as `attach`.
    unsafe { *core::ptr::addr_of_mut!(ATTACHED) = None };
}

/// The process the idle thread has to reap, attached for it: one that has ended (its last thread's
/// exit recorded why) and is not yet torn down. None when every process is running or gone.
#[cfg(target_arch = "x86")]
pub fn ended() -> Option<&'static mut Process> {
    (0..MAX_PROCESSES as u16).find_map(|index| {
        let id = crate::ob::directory().processes_live(index)?;
        // SAFETY: the record of a live process object, at its final address.
        let process = unsafe { &mut *record(index) };
        if process.end.is_some() && !process.torn_down && process.object == id {
            attach(index);
            Some(process)
        } else {
            None
        }
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
                process.end.is_some() && !process.torn_down && process.object == id
            })
    })
}
