//! The process pool: every process record, at its final address for the kernel's life, and the
//! current process.
//!
//! A record is in use while its process object lives ([`crate::ob`]'s process pool, same index):
//! the object is created with the record and holds the process's own reference until its teardown
//! ends, so a handle to the process outlives the record's resources but not its slot. The capacity
//! is fixed (one process runs at a time until CreateProcess exists).
//!
//! The current process is the running thread's owner: the thread record's owner pointer is the
//! process record's leading scheduling record. Outside the process's own threads the kernel acts
//! for a process only inside two scopes, attached to it: its load (from its creation until its
//! main thread's start is planted, see [`detach`]) and its reap (from [`ended`] to the record's
//! release). Elsewhere on the idle thread (whose own owner is the idle process, no pooled process)
//! no process is current: code that acts for a process there takes it explicitly.

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
static mut ATTACHED: Attachment = Attachment::none();

/// Which process record the kernel is attached to: none outside a load or reap scope. Scopes never
/// nest: a load starts once the previous scope has ended (a reap ends before the next load the
/// runner starts from it).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Attachment(Option<u16>);

impl Attachment {
    /// Attached to nothing.
    pub const fn none() -> Self {
        Attachment(None)
    }

    /// Begin a scope acting for the record at `index`.
    ///
    /// # Panics
    ///
    /// A scope is already open.
    pub fn begin(&mut self, index: u16) {
        assert!(
            self.0.is_none(),
            "a process's load or reap begins with no other process attached"
        );
        self.0 = Some(index);
    }

    /// End the open scope.
    ///
    /// # Panics
    ///
    /// No scope is open.
    pub fn end(&mut self) {
        assert!(self.0.take().is_some(), "a scope ends once, after it began");
    }

    /// The record the open scope acts for; none outside a scope.
    pub fn index(&self) -> Option<u16> {
        self.0
    }
}

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
/// `dir_phys`, named `name`. Its load scope begins: the kernel is attached to it until the loader
/// is done with it ([`detach`]).
#[cfg(target_arch = "x86")]
// The record is the pool's, not borrowed from `name`: the lint reads the name's reference as the
// input the returned one comes from.
#[allow(clippy::mut_from_ref)]
pub(super) fn create(dir_phys: u32, name: &'static str) -> &'static mut Process {
    let object = crate::ob::directory()
        .create_process()
        .expect("a process record is free (one process runs at a time)");
    let process = record(object.index);
    // SAFETY: single CPU, interrupts disabled; the record is free (its object was not live), and
    // every field is written before the record is read.
    let process = unsafe {
        super::write_fresh(process, dir_phys, name, object);
        &mut *process
    };
    attach(object.index);
    process
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
            .or((*core::ptr::addr_of!(ATTACHED)).index())
            .expect("no process is current");
        &mut *record(index)
    }
}

/// The current process, immutably (reporting paths, and the handle lookups that change nothing).
#[cfg(target_arch = "x86")]
pub fn current() -> &'static Process {
    current_mut()
}

/// Attach the kernel to the process at `index`: its load or its reap begins.
#[cfg(target_arch = "x86")]
fn attach(index: u16) {
    // SAFETY: single CPU; the attachment's writers run serialized.
    unsafe { (*core::ptr::addr_of_mut!(ATTACHED)).begin(index) };
}

/// Detach the kernel from the process it acts for: the loader is done with the process (its main
/// thread's start is the caller's, through the process it holds), or its teardown is.
#[cfg(target_arch = "x86")]
pub fn detach() {
    // SAFETY: as `attach`.
    unsafe { (*core::ptr::addr_of_mut!(ATTACHED)).end() };
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
                process.end.is_some() && !process.torn_down && process.object == id
            })
    })
}

#[cfg(test)]
mod tests {
    use super::Attachment;

    /// A scope acts for its process from its beginning to its end, and for none after; the next
    /// scope begins afresh.
    #[test]
    fn a_scope_attaches_until_it_ends() {
        let mut attachment = Attachment::none();
        assert_eq!(attachment.index(), None);
        attachment.begin(3);
        assert_eq!(attachment.index(), Some(3));
        attachment.end();
        assert_eq!(attachment.index(), None, "cleared after the scope");
        attachment.begin(0);
        assert_eq!(attachment.index(), Some(0));
    }

    /// Two loads, or a load inside a reap, would leave the first process current for the second's
    /// work: scopes never nest.
    #[test]
    #[should_panic(expected = "no other process attached")]
    fn scopes_never_nest() {
        let mut attachment = Attachment::none();
        attachment.begin(1);
        attachment.begin(2);
    }

    /// A scope ends once.
    #[test]
    #[should_panic(expected = "a scope ends once")]
    fn a_scope_ends_once() {
        let mut attachment = Attachment::none();
        attachment.begin(1);
        attachment.end();
        attachment.end();
    }
}
