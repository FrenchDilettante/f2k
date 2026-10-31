//! The process object: every piece of per-process state in one place.
//!
//! A process owns its page directory (created per process, sharing the kernel's kernel half) and
//! its address space's regions ([`crate::mem::vm::AddressSpace`], the only writer of its user
//! entries); its heaps are its own user memory, ntdll's. The image, stack, TEB and parameters pages
//! are mapped fresh each run into the process's directory, each inside a region the loader seeds
//! first, so they are per-process by construction.
//!
//! A boot's program starts with its main thread ([`Process::start`]); a process another process
//! creates (NtCreateProcess) starts with none ([`Process::create`]), and its first thread, created
//! later by its creator, is its main thread. Until then nothing ends it: a termination only closes
//! it to new threads, and as on Windows 2000 it neither signals nor takes an exit code. It goes
//! when its object's last reference beside its own does, deleted on the calling thread
//! ([`Process::delete_threadless`]).
//!
//! The per-thread state split: the ring-0 gate stack (the thread's kernel stack, what the TSS
//! `esp0` points into) is per-thread, a slot of the kernel stack region numbered system-wide and
//! mapped in every address space ([`crate::mem::kstacks`]), each slot's frames recorded by their
//! owning thread. The thread records themselves are the object manager's ([`crate::ob`]), taken
//! from its whole pool; the process numbers its own threads ([`ordinals`]), which places their TEB
//! pages. The scheduling record is pinned with the process record, so a thread's address-space
//! pointer (its owner's record, or the one it attached to) resolves the directory base the context
//! switch loads.
//!
//! Kernel code builds or reads a process's address space from outside its threads by attaching to
//! it ([`Process::attach`], see [`crate::sched::attach`]): the loader, on the idle thread, builds a
//! new process's that way. The teardown does not attach: it reads the dead directory through the
//! scratch window, on the boot address space.
//!
//! A process runs on its threads until its last thread ends — the process's end, which its waiters
//! observe at once — and the idle thread tears it down later. The end and the teardown touch only
//! what the process owns — its handles, its views, its address space, its threads' records — so
//! another process may live on through them. The checks over the whole
//! system (the leak sweep over every object pool and the open-file records, the free frames against
//! the post-boot baseline) wait for quiescence: the reap after which no process remains that has
//! not been torn down. The boot's runner starts each program once the last is reaped, so every
//! reap is quiescent then; under the kernel option `concurrent`, only the last one is.
//!
//! The end of a process, in the platform's order:
//!
//! 1. every other thread is terminated (the exit service's and a fault's end): each takes an exit
//!    APC and runs its own exit at its next window — a thread inside a critical region at the
//!    region's end — and the last of the process's threads to exit runs the steps that follow;
//! 2. every handle closes, as CloseHandle would — the objects go with their last references; then
//!    its views are unmapped, each section or image segment losing the view's reference (Windows
//!    2000's MmCleanProcessAddressSpace: an image's file is closed once nothing maps it);
//! 3. the last thread's object signals, then the process object with the exit code: their waiters
//!    wake, and the switch away from the last thread may select one of them;
//! 4. the address space goes: every frame;
//! 5. the record is freed with the object's last reference.
//!
//! Steps 1 to 3 run on the last thread, in [`threads`]: by its switch away the process has ended
//! for everyone who can observe it, however long the reap waits for the processor. Steps 4 and 5
//! run on the idle thread's reap, in [`reap`], with the object audit between them and the teardown
//! audit after 5; their checks over the whole system, and the audit lines, wait for quiescence.
//! What the reap does can't run on the dying thread: the directory and its page tables are the
//! ones it runs on, and its gate stack the one it runs on.
//!
//! The records live in the process pool ([`pool`]), which also answers which process is current:
//! kernel state (like CR3 and the TSS), not per-process state. Everything per-process lives inside
//! the [`Process`] record — each part behind what guards it (see [`Process`]) — or in the shared
//! databases, at the process's index: its waitable and exit status in the dispatcher's, its thread
//! ordinals with its object in the directory, its objects reached through its handles, and its
//! threads' records through its thread list.

/// The end of a thread and of its process, as decisions: the exit routing, the report lines,
/// the suite's leg order and tally.
pub mod exit;

/// The boot's programs, run one after another.
#[cfg(target_arch = "x86")]
pub mod runner;

/// The process pool and the current process.
pub mod pool;

/// The process's thread ordinals: which thread holds which TEB page.
pub mod ordinals;

pub use pool::MAX_PROCESSES;
#[cfg(target_arch = "x86")]
pub use pool::{current, reap_pending};

/// The smoke-subset thread surface: child-thread creation, the thread records, the thread-exit
/// path.
#[cfg(target_arch = "x86")]
pub mod threads;

use core::cell::UnsafeCell;

#[cfg(target_arch = "x86")]
use crate::mem::paging;
use crate::mem::vm::AddressSpace;
use crate::sched::object::{HandleTable, HANDLE_SHIFT, HANDLE_SLOTS};
use crate::sched::process::{PinnedProcess, SchedProcess};
use crate::sync::ShortLock;

/// A process: one address space and its threads (Windows 2000's EPROCESS, the process object's
/// body: the record shares its object's index). Its parts are reached apart, each the way its
/// users need it, so no part is ever borrowed for another's sake:
///
/// - the scheduling record (KPROCESS) is the dispatcher's, at the dispatch level;
/// - the identity is written when the process is created, before anything can name it, and read
///   freely after;
/// - the handle table, the address space and the rest of what changes are each behind a short lock
///   of their own (Windows 2000's handle-table lock, the address-space locks, the process lock),
///   held only for the change itself: never across a wait, a hold of the directory or a copy of
///   user memory. The page-fault path takes the address space's alone.
pub struct Process {
    /// The scheduling record: the dispatcher's, which the process's threads link to (their owner
    /// and address-space pointers), and the switch reads the directory base from.
    sched: PinnedProcess,
    /// Who the process is (see [`IdentityCell`]).
    identity: IdentityCell,
    /// The handle table: the process's handles-to-objects (its open files' among them: a file
    /// object each, see `crate::fs::file`).
    handles: ShortLock<HandleTable>,
    /// The address space's regions and views: every user page the process holds lies in one, and
    /// every mapping, commit and release of its pages goes through it.
    space: ShortLock<AddressSpace>,
    /// What else changes over the process's life (see [`ProcessState`]).
    state: ShortLock<ProcessState>,
}

/// Who a process is: set when its record is taken, never changed after.
#[derive(Clone, Copy)]
struct Identity {
    /// The image's name, as its end reports it on COM1.
    name: ProcessName,
    /// The process's client id (what GetCurrentProcessId reports, through the TEB).
    id: u32,
    /// The client id of the process that created it (ProcessBasicInformation's
    /// InheritedFromUniqueProcessId): zero for a boot's program, which no process created.
    parent_id: u32,
    /// The boot's program the process runs as, its 1-based index in the boot's list (see
    /// `runner`); none for a process another process started. Its end reports by it.
    leg: Option<u32>,
    /// The process's object: what a handle to the process names and a wait on it waits for. It
    /// holds the process's own reference until the teardown's end, and its index is the record's
    /// in the pool.
    object: crate::ob::ObjectId,
    /// The process's page-directory frame.
    dir_phys: u32,
}

/// A process record's identity, written by the pool as it takes the record for a new process and
/// copied out by every read. The write needs no lock: the record is the new process's alone then —
/// its object was free until the pool took it, so nothing names the process yet — and on the one
/// processor nothing reads an identity in the middle of the write (no switch comes inside a plain
/// copy, and no interrupt handler reads a process's identity).
struct IdentityCell(UnsafeCell<Identity>);

// SAFETY: one processor, and the identity is reached only by the copies below: the write, whose
// caller vouches that nothing reads the identity meanwhile, and the reads, which keep no reference
// into the cell.
unsafe impl Sync for IdentityCell {}

impl IdentityCell {
    const fn new(identity: Identity) -> Self {
        IdentityCell(UnsafeCell::new(identity))
    }

    /// The identity, copied out.
    fn get(&self) -> Identity {
        // SAFETY: a copy; the one write is `renew`'s, which nothing reads beside (see there), and
        // no reference into the cell outlives a read.
        unsafe { *self.0.get() }
    }

    /// Write a new process's identity.
    ///
    /// # Safety
    ///
    /// Nothing reads the identity during the write: the record is taken for a new process whose
    /// object nothing names yet (see [`IdentityCell`]).
    #[cfg(target_arch = "x86")]
    unsafe fn renew(&self, identity: Identity) {
        // SAFETY: the caller's contract; no reference into the cell is live.
        unsafe { *self.0.get() = identity };
    }
}

/// What changes in a process besides its handles and its address space, behind one short lock:
/// small values read and written in place, the end state among them.
struct ProcessState {
    /// The priority class (PROCESS_PRIORITY_CLASS_*, ProcessPriorityClass's value).
    priority_class: u8,
    /// The hard-error mode (DefaultHardErrorProcessing, ProcessDefaultHardErrorMode's value: the
    /// hard-error and fault dialogs it governs never exist here; the value is kept for its round
    /// trip).
    hard_error_mode: u32,
    /// The process's console handles: the console server's own, outside the handle table, as
    /// Windows 2000's csrss keeps them (see `crate::csr`).
    console: rtl::console::Handles,
    /// The process's connection to win32k: its window station's and desktop's handles, made at its
    /// first win32k service (see `crate::win32k::winsta`); none until then.
    win32k: Option<crate::win32k::winsta::Connection>,
    /// Why the process ended, recorded by its last thread's exit; the idle thread's reap step
    /// tears down a process once this is set.
    end: Option<exit::ProcessEnd>,
    /// The end NtTerminateProcess or a fault decided for the process, while other threads were
    /// still to take their exit APCs: the last thread to exit ends the process with it.
    handed_end: Option<exit::ProcessEnd>,
    /// Whether another process terminated it while it had no thread (see
    /// `threads::terminate_process`): it takes no new thread, and is not terminated twice. Nothing
    /// ends it: it goes with its object's last reference.
    ending: bool,
    /// Whether the deletion of a process that never had a thread has begun (see
    /// [`Process::delete_threadless`]): it runs once.
    deleting: bool,
    /// Whether the teardown has run (the record waits for its object's last reference).
    torn_down: bool,
}

impl ProcessState {
    /// A new process's state: the default class and mode, the standard console handles, nothing
    /// ended.
    const fn fresh() -> Self {
        ProcessState {
            priority_class: NORMAL_PRIORITY_CLASS,
            hard_error_mode: DEFAULT_HARD_ERROR_MODE,
            console: rtl::console::Handles::standard(),
            win32k: None,
            end: None,
            handed_end: None,
            ending: false,
            deleting: false,
            torn_down: false,
        }
    }
}

/// A process's name: its image's file name without the extension, as its end report shows it — at
/// most [`NAME_ROOM`] bytes, as Windows 2000 keeps an image's name in its process
/// (EPROCESS.ImageFileName, sixteen bytes with the terminator). A byte past ASCII reads as `?`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ProcessName {
    bytes: [u8; NAME_ROOM],
    length: u8,
}

/// A process name's room in bytes.
pub const NAME_ROOM: usize = 15;

impl ProcessName {
    /// The empty name (a record no process holds).
    const EMPTY: ProcessName = ProcessName {
        bytes: [0; NAME_ROOM],
        length: 0,
    };

    /// The name `name` gives, cut at its room.
    pub fn new(name: &[u8]) -> Self {
        let mut bytes = [0u8; NAME_ROOM];
        let length = name.len().min(NAME_ROOM);
        for (out, &byte) in bytes.iter_mut().zip(&name[..length]) {
            *out = if byte.is_ascii() && byte != 0 {
                byte
            } else {
                b'?'
            };
        }
        ProcessName {
            bytes,
            length: length as u8,
        }
    }

    /// The stem of the file name `file_name`: what precedes its first dot.
    pub fn of_file(file_name: &[u8]) -> Self {
        let stem = file_name
            .iter()
            .position(|&byte| byte == b'.')
            .map_or(file_name, |dot| &file_name[..dot]);
        Self::new(stem)
    }

    /// The name, as text.
    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.bytes[..self.length as usize]).unwrap_or("?")
    }
}

/// The default priority class: PROCESS_PRIORITY_CLASS_NORMAL.
pub const NORMAL_PRIORITY_CLASS: u8 = crate::nt::process::PRIORITY_CLASS_NORMAL;
/// The default hard-error mode: 1, hard errors reported (a process created without
/// CREATE_DEFAULT_ERROR_MODE's parent mode; kernel32's SetErrorMode reads it as mode 0).
pub const DEFAULT_HARD_ERROR_MODE: u32 = 1;

/// How many threads a process can have alive besides its main thread: its created threads'
/// ordinals ([`ordinals`]). A terminated thread's ordinal is reused once nothing references its
/// object, so this bounds the live threads, not the threads created (the threads fixture's scale
/// block keeps 64 children alive at once).
pub const CHILD_THREADS: usize = 64;

/// How many handle-table slots one hold of a table reaches where a walk of the whole table
/// releases the lock between its steps (the exit's closing of every handle, an inheritance): few
/// enough for a step's copy of them to sit on a kernel stack.
const HANDLE_STEP: usize = 32;

/// Run `f` on `lock`'s value, locked: the bridge for the process's parts, whose users hold no
/// passive token, which it makes for the hold (as [`crate::ob::locked`] does for the directory).
///
/// # Panics
///
/// The processor is above the passive level: inside a process's lock or the directory's already
/// (`f`, or what it calls, taking one again), or at a raised level, where nothing may wait for it.
fn locked<T, R>(lock: &ShortLock<T>, f: impl FnOnce(&mut T) -> R) -> R {
    assert_eq!(
        crate::pcr::pcr().current(),
        crate::interrupt::irql::PASSIVE,
        "a process's lock taken above the passive level"
    );
    // SAFETY: a passive entry (see `At::enter`): the ledger reads the passive level, and the token
    // stays on this thread, dropped with this frame.
    let mut passive = unsafe { crate::level::At::<crate::level::Passive>::enter() };
    let mut guard = lock.lock(&mut passive);
    f(&mut guard)
}

impl Process {
    /// A record no process holds: every pool record's at the kernel's build.
    pub const fn empty() -> Self {
        Process {
            sched: PinnedProcess::new(0, crate::sched::NORMAL_BASE),
            identity: IdentityCell::new(Identity {
                name: ProcessName::EMPTY,
                id: 0,
                parent_id: 0,
                leg: None,
                object: crate::ob::ObjectId {
                    kind: crate::ob::ObjectType::Process,
                    index: 0,
                    generation: 0,
                },
                dir_phys: 0,
            }),
            handles: ShortLock::new(HandleTable::empty()),
            space: ShortLock::new(AddressSpace::new()),
            state: ShortLock::new(ProcessState::fresh()),
        }
    }

    /// Take this record, whose process object `object` the directory has just made (so nothing
    /// names it yet), for a new process: named `name`, its client id fresh, created by the process
    /// whose client id is `parent_id` (zero: none), running as leg `leg` (none for a child), over
    /// the address space at `dir_phys`. Every part starts over in place: its previous process (if
    /// any) was torn down before its object went, so the parts hold nothing.
    #[cfg(target_arch = "x86")]
    fn renew(
        &self,
        object: crate::ob::ObjectId,
        dir_phys: u32,
        name: ProcessName,
        leg: Option<u32>,
        parent_id: u32,
    ) {
        let identity = Identity {
            name,
            id: new_client_id(),
            parent_id,
            leg,
            object,
            dir_phys,
        };
        // SAFETY: the record is taken for a new process whose object the directory has just made:
        // nothing names it yet, so nothing reads its identity during the write.
        unsafe { self.identity.renew(identity) };
        crate::level::raised::<crate::level::Dispatch, _>(|dispatch| {
            let sched = self.sched.get_mut(crate::sched::DISPATCHER.get(dispatch));
            assert!(
                sched.has_no_threads() && sched.attach_count() == 0,
                "a free process record has no thread"
            );
            *sched = SchedProcess::pooled(dir_phys, crate::sched::NORMAL_BASE, object.index);
        });
        self.with_handles(|table| {
            table.drain(|_| unreachable!("a free process record holds no handle"))
        });
        self.with_space(AddressSpace::reset);
        locked(&self.state, |state| *state = ProcessState::fresh());
    }

    /// The process's name.
    pub fn name(&self) -> ProcessName {
        self.identity.get().name
    }

    /// The process's client id.
    pub fn id(&self) -> u32 {
        self.identity.get().id
    }

    /// The client id of the process that created this one; zero for a boot's program.
    pub fn parent_id(&self) -> u32 {
        self.identity.get().parent_id
    }

    /// The boot's program the process runs as (its 1-based index); none for a child.
    pub fn leg(&self) -> Option<u32> {
        self.identity.get().leg
    }

    /// The process's object.
    pub fn object(&self) -> crate::ob::ObjectId {
        self.identity.get().object
    }

    /// The process's page-directory frame.
    pub fn dir_phys(&self) -> u32 {
        self.identity.get().dir_phys
    }

    /// The scheduling record's address: what the process's threads' owner and address-space
    /// pointers are, and what the dispatcher's calls on the process take.
    pub fn sched_ptr(&self) -> *mut SchedProcess {
        self.sched.as_ptr()
    }

    /// The scheduling record, to read, for as long as the caller borrows the dispatcher.
    pub fn sched<'a>(
        &'a self,
        dispatcher: &'a crate::sched::dispatcher::Dispatcher,
    ) -> &'a SchedProcess {
        self.sched.get(dispatcher)
    }

    /// The kernel stacks the process's threads hold: one per attached thread (see
    /// [`SchedProcess::stack_count`]). A process that never had a thread holds none: its record's
    /// sentinel reads as 0.
    pub fn stack_count(&self) -> u16 {
        let count = crate::level::raised::<crate::level::Dispatch, _>(|dispatch| {
            self.sched(crate::sched::DISPATCHER.get(dispatch))
                .stack_count()
        });
        if count == crate::sched::process::NO_THREADS {
            0
        } else {
            count
        }
    }

    /// The process's base priority (KPROCESS's BasePriority).
    pub fn base_priority(&self) -> i8 {
        crate::level::raised::<crate::level::Dispatch, _>(|dispatch| {
            self.sched(crate::sched::DISPATCHER.get(dispatch))
                .base_priority()
        })
    }

    /// How many threads of other processes run attached to the process's address space.
    pub fn attach_count(&self) -> u16 {
        crate::level::raised::<crate::level::Dispatch, _>(|dispatch| {
            self.sched(crate::sched::DISPATCHER.get(dispatch))
                .attach_count()
        })
    }

    /// Run `f` on the handle table, locked.
    pub fn with_handles<R>(&self, f: impl FnOnce(&mut HandleTable) -> R) -> R {
        locked(&self.handles, f)
    }

    /// Run `f` on the address space, locked: never across a wait, a hold of the directory or a
    /// copy of user memory (the page-fault path takes this lock).
    pub fn with_space<R>(&self, f: impl FnOnce(&mut AddressSpace) -> R) -> R {
        locked(&self.space, f)
    }

    /// The entry a handle names in the table; none when it names nothing.
    pub fn lookup_handle(&self, handle: u32) -> Option<crate::ob::Entry> {
        self.with_handles(|table| table.lookup(handle))
    }

    /// Whether every slot of the handle table is taken: the next insert would find none.
    pub fn handles_full(&self) -> bool {
        self.with_handles(|table| table.is_full())
    }

    /// The console handles (the console server serves them).
    pub fn console(&self) -> rtl::console::Handles {
        locked(&self.state, |state| state.console)
    }

    /// Set the console handles: a new process's, its creator's inheritable ones.
    pub fn set_console(&self, console: rtl::console::Handles) {
        locked(&self.state, |state| state.console = console);
    }

    /// Run `f` on the console handles, locked: the console server's call, which `f` serves at the
    /// dispatch level (a raise from the lock's level).
    pub fn with_console<R>(&self, f: impl FnOnce(&mut rtl::console::Handles) -> R) -> R {
        locked(&self.state, |state| f(&mut state.console))
    }

    /// Whether the process is terminating: its end is decided and held for its last thread, or it
    /// was terminated with no thread. It takes no new thread then.
    pub fn terminating(&self) -> bool {
        locked(&self.state, |state| {
            state.ending || state.handed_end.is_some()
        })
    }

    /// Why the process ended; none while it runs.
    pub fn end(&self) -> Option<exit::ProcessEnd> {
        locked(&self.state, |state| state.end)
    }

    /// Whether the process has ended and is not torn down yet.
    pub fn awaits_teardown(&self) -> bool {
        locked(&self.state, |state| state.end.is_some() && !state.torn_down)
    }

    /// Whether the teardown has run.
    pub fn torn_down(&self) -> bool {
        locked(&self.state, |state| state.torn_down)
    }

    /// The process's connection to win32k, once its first win32k service made it.
    pub fn win32k(&self) -> Option<crate::win32k::winsta::Connection> {
        locked(&self.state, |state| state.win32k)
    }

    /// Record the process's connection to win32k.
    pub fn set_win32k(&self, connection: crate::win32k::winsta::Connection) {
        locked(&self.state, |state| state.win32k = Some(connection));
    }

    /// The process's priority class (PROCESS_PRIORITY_CLASS_*).
    pub fn priority_class(&self) -> u8 {
        locked(&self.state, |state| state.priority_class)
    }

    /// Record the process's priority class (the scheduling side is the caller's).
    pub fn set_priority_class(&self, class: u8) {
        locked(&self.state, |state| state.priority_class = class);
    }

    /// The process's hard-error mode.
    pub fn hard_error_mode(&self) -> u32 {
        locked(&self.state, |state| state.hard_error_mode)
    }

    /// Set the process's hard-error mode.
    pub fn set_hard_error_mode(&self, mode: u32) {
        locked(&self.state, |state| state.hard_error_mode = mode);
    }

    /// A user-APC record of the process's that is in no queue in `dispatcher`, or none (every
    /// record is queued). The records are the dispatcher database's (its APC queues link them by
    /// name): each process has its share of them, [`crate::sched::database::USER_APCS`] from its
    /// record's index on.
    pub fn free_apc(
        &self,
        dispatcher: &mut crate::sched::dispatcher::Dispatcher,
    ) -> Option<crate::sched::apc::ApcId> {
        use crate::sched::database::USER_APCS;
        let base = self.object().index * USER_APCS as u16;
        (base..base + USER_APCS as u16)
            .find(|&index| !dispatcher.user_apc_mut(index).inserted())
            .map(crate::sched::apc::ApcId::User)
    }

    /// Close a handle: the table's claim ends — the object's handle, with its reference (the last
    /// handle cleans a file object up, the last reference deletes the object). False when the
    /// handle names nothing.
    pub fn close_handle(&self, handle: u32) -> bool {
        let Some(entry) = self.take_handle(handle) else {
            return false;
        };
        self.release_handle(entry);
        true
    }

    /// The first half of a handle's close: its slot is free from here on (the next insert takes
    /// it), while what its entry names stays counted until [`Process::release_handle`]. None when
    /// the handle names nothing.
    pub fn take_handle(&self, handle: u32) -> Option<crate::ob::Entry> {
        self.with_handles(|table| table.close(handle))
    }

    /// The second half of a handle's close: what the entry [`Process::take_handle`] took out
    /// names is released (see [`Process::close_handle`]), the table's lock released by then.
    pub fn release_handle(&self, entry: crate::ob::Entry) {
        self.release_entry(entry);
    }

    /// Change the entry a handle names in this process's table with `change` (its inheritance, its
    /// protection from close: NtSetInformationObject's); false when the handle names nothing.
    pub fn update_handle(
        &self,
        handle: u32,
        change: impl FnOnce(crate::ob::Entry) -> crate::ob::Entry,
    ) -> bool {
        self.with_handles(|table| table.update(handle, change))
    }

    /// Release what one closed handle named. A process's last reference beside its own going
    /// deletes the process if it never had a thread (see `threads::delete_if_abandoned`).
    fn release_entry(&self, entry: crate::ob::Entry) {
        match entry.target {
            #[cfg(target_arch = "x86")]
            crate::ob::Target::Object(id) => {
                // What the close leaves (a file object's cleanup, which may reach the disk) is
                // finished once the directory is released.
                crate::ob::locked(|directory| directory.handle_closed(id)).finish();
                if id.kind == crate::ob::ObjectType::Process {
                    threads::delete_if_abandoned(id);
                }
            }
            #[cfg(not(target_arch = "x86"))]
            crate::ob::Target::Object(_) => {}
        }
    }

    /// Insert a handle to object `id` with `access` and `inheritance`, the object counting it; none
    /// when the table is full or the object is gone (the object is left as it was). The object is
    /// counted in one hold of the directory and the entry inserted in a hold of the table after
    /// it: the caller writes the handle to user memory once both are released (Windows 2000's
    /// ObInsertObject shape), and closes it again if that write faults.
    #[cfg(target_arch = "x86")]
    pub fn insert_object(
        &self,
        id: crate::ob::ObjectId,
        access: u32,
        inherit: bool,
    ) -> Option<core::num::NonZeroU32> {
        if self.handles_full() || !crate::ob::locked(|directory| directory.handle_opened(id)) {
            return None;
        }
        let handle =
            self.with_handles(|table| table.insert(crate::ob::Entry::object(id, access, inherit)));
        Some(core::num::NonZeroU32::new(handle).expect("a table with room hands out a handle"))
    }

    /// Take into this process's table, a fresh one, every inheritable handle of `parent`'s, each at
    /// its own value with its access and inheritance — the documented inheritance of a process
    /// created with InheritObjectTable (CreateProcess's bInheritHandles) — each object counting its
    /// new handle. (The console handles are not the table's: NtCreateProcess hands every child the
    /// parent's inheritable ones.) Returns how many handles were taken. The tables are walked a
    /// step of [`HANDLE_STEP`] slots at a time, each lock held for its own part of the step: the
    /// parent's entries read, the directory counting the ones taken, the child's slots taking them.
    #[cfg(target_arch = "x86")]
    pub fn inherit_handles(&self, parent: &Process) -> usize {
        let mut taken = 0;
        for first in (1..HANDLE_SLOTS).step_by(HANDLE_STEP) {
            let slots = first..(first + HANDLE_STEP).min(HANDLE_SLOTS);
            let mut step = [None; HANDLE_STEP];
            parent.with_handles(|table| {
                for (entry, index) in step.iter_mut().zip(slots.clone()) {
                    *entry = table
                        .lookup((index as u32) << HANDLE_SHIFT)
                        .filter(|entry| entry.inherit);
                }
            });
            // A handle names a live object (it holds it), so the count always takes.
            crate::ob::locked(|directory| {
                for entry in step.iter_mut() {
                    let counted = entry
                        .and_then(|entry| entry.object_id())
                        .is_some_and(|id| directory.handle_opened(id));
                    if !counted {
                        *entry = None;
                    }
                }
            });
            self.with_handles(|table| {
                for (entry, index) in step.iter().zip(slots) {
                    if let Some(entry) = *entry {
                        table.inherit_entry(index, entry);
                        taken += 1;
                    }
                }
            });
        }
        self.with_handles(HandleTable::end_inheritance);
        taken
    }

    /// Release every handle at once: the process-exit step. Each closes as a CloseHandle would, in
    /// slot order: a step of [`HANDLE_STEP`] slots is taken out of the table in one hold, and what
    /// they named released after it.
    pub fn release_handles(&self) {
        for first in (1..HANDLE_SLOTS).step_by(HANDLE_STEP) {
            let slots = first..(first + HANDLE_STEP).min(HANDLE_SLOTS);
            let mut step = [None; HANDLE_STEP];
            self.with_handles(|table| {
                for (entry, index) in step.iter_mut().zip(slots) {
                    *entry = table.close((index as u32) << HANDLE_SHIFT);
                }
            });
            for entry in step.into_iter().flatten() {
                self.release_entry(entry);
            }
        }
        self.with_handles(|table| table.drain(|_| {}));
    }

    /// Decide the process's end — NtTerminateProcess's, or a fault's — for whichever of its threads
    /// exits last (see [`exit::ThreadEnd::last_thread_end`]), and close it to new threads. The
    /// first decision stands: a later one, from a thread that had not taken its exit APC yet, or a
    /// second termination racing the first, changes nothing. Returns whether this one was the
    /// first.
    pub fn decide_end(&self, end: exit::ProcessEnd) -> bool {
        let first = locked(&self.state, |state| {
            let first = state.handed_end.is_none() && !state.ending;
            if first {
                state.handed_end = Some(end);
            }
            first
        });
        self.close_to_threads();
        first
    }

    /// The process takes no new thread from here on (see [`ordinals::Ordinals::close`]). Host
    /// builds have no directory to keep the ordinals in.
    fn close_to_threads(&self) {
        #[cfg(target_arch = "x86")]
        crate::ob::locked(|directory| {
            if let Some(ordinals) = directory.ordinals(self.object()) {
                ordinals.close();
            }
        });
    }

    /// The end decided for the process, held for its last thread; none unless NtTerminateProcess
    /// or a fault decided one.
    pub fn handed_end(&self) -> Option<exit::ProcessEnd> {
        locked(&self.state, |state| state.handed_end)
    }

    /// Record why the process ended: its last thread's exit, once.
    pub fn set_end(&self, end: exit::ProcessEnd) {
        locked(&self.state, |state| {
            assert!(state.end.is_none(), "a process ends once");
            state.end = Some(end);
        });
    }

    /// Mark a process with no thread terminated (see `threads::terminate_process`), and close it
    /// to new threads. Returns whether this was the first termination decided for it: false for a
    /// process terminated, or whose end is decided, already.
    pub fn mark_terminated(&self) -> bool {
        let first = locked(&self.state, |state| {
            let first = state.handed_end.is_none() && !state.ending;
            state.ending = true;
            first
        });
        self.close_to_threads();
        first
    }

    /// The process has ended, step 3 of its end (see the module notes): its object signals with
    /// `end`'s exit code, and its waiters wake. The last thread's exit signals it, after its own
    /// object, before its switch away selects the next thread.
    #[cfg(target_arch = "x86")]
    pub fn signal_end(&self, end: exit::ProcessEnd) {
        crate::ob::signal_process_end(self.object(), end.exit_status());
    }
}

#[cfg(target_arch = "x86")]
impl Process {
    /// Create a process with no thread: a fresh address space with the record taken from the
    /// pool, named `name`, created by the process whose client id is `parent_id` (zero: none),
    /// running as leg `leg` (none for a child). The address space is not live: the caller attaches
    /// to the process ([`Process::attach`]) to map its user pages, each inside one of its regions.
    ///
    /// STATUS_INSUFFICIENT_RESOURCES when no process record is to be had (Windows 2000's answer to
    /// a full table); the fresh directory is given back then.
    pub fn create(
        name: ProcessName,
        leg: Option<u32>,
        parent_id: u32,
    ) -> Result<&'static Process, crate::status::NtStatus> {
        let dir_phys = paging::create_address_space();
        let process = match pool::create(dir_phys, name, leg, parent_id) {
            Ok(process) => process,
            Err(status) => {
                free_directory(dir_phys);
                return Err(status);
            }
        };
        Ok(process)
    }

    /// Create a boot's program's process (see [`Process::create`]), then its main thread taking
    /// the system's lowest free gate-stack slot, the fixed TEB page, and the process's scheduling
    /// data. `leg` is the boot's program the process runs as. Returns the record for the caller's
    /// setup (the loader's), which threads it through.
    ///
    /// STATUS_INSUFFICIENT_RESOURCES when a process record, a gate-stack slot or a thread record is
    /// not to be had (Windows 2000's answer to a full table or an exhausted kernel stack). A
    /// refusal leaves nothing behind: what was taken before it — the address space, the process
    /// object and its record, the slot — is given back, in the reverse order.
    pub fn start(
        name: &str,
        leg: Option<u32>,
    ) -> Result<&'static Process, crate::status::NtStatus> {
        use crate::status::STATUS_INSUFFICIENT_RESOURCES;
        let process = Process::create(ProcessName::new(name.as_bytes()), leg, 0)?;

        // The main thread's gate stack, taken before its record (as a created thread's is): a
        // release undoes it when the record is not to be had, and nothing is attached before both
        // are held.
        let Some((slot, frames)) = crate::mem::kstacks::create() else {
            process.abandon();
            return Err(STATUS_INSUFFICIENT_RESOURCES);
        };

        // The main thread: its object holds the thread's own reference while it runs (released at
        // its end), on any free record of the pool; it holds the process's ordinal 0 (the fixed
        // TEB page), its stack a system region rather than a reservation of its own. It attaches
        // to the process and runs on the gate stack just taken.
        let made = crate::ob::locked(|directory| {
            let id = directory.create_thread()?;
            directory
                .ordinals(process.object())
                .expect("a process being started has its object")
                .hold_main(id, 0);
            Some(directory.renew_thread(id))
        });
        let Some(thread) = made else {
            crate::mem::kstacks::release((slot, frames));
            process.abandon();
            return Err(STATUS_INSUFFICIENT_RESOURCES);
        };
        let thread_id = new_client_id();
        crate::level::raised::<crate::level::Dispatch, _>(|dispatch| {
            let dispatcher = crate::sched::DISPATCHER.get(dispatch);
            let record = dispatcher.thread_mut(thread);
            record.gate_slot = slot;
            record.gate_frames = frames;
            record.initial_stack = paging::gate_slot_top(slot as u32);
            record.ordinal = ordinals::MAIN;
            record.teb_va = crate::user::thread_teb_va(ordinals::MAIN as u32);
            record.thread_id = thread_id;
            // SAFETY: the scheduling record is the pool's, at its final address, reached only
            // through this borrow of the dispatcher meanwhile, and it outlives its threads (its
            // teardown follows the last one's end).
            unsafe { dispatcher.attach(thread, process.sched_ptr()) };
        });
        // The TSS `esp0` is the switch's to install: the first switch into the main thread loads
        // its stack top.
        Ok(process)
    }

    /// Undo a start refused before the main thread was attached: the process's own reference on
    /// its object goes (no handle exists yet, so the object and the record go with it), then the
    /// fresh address space's directory, which maps nothing yet.
    fn abandon(&self) {
        let dir_phys = self.dir_phys();
        release_record(self);
        free_directory(dir_phys);
    }

    /// Delete a process that never had a thread, as Windows 2000 deletes one with its object
    /// (PspProcessDelete): its handles (inherited ones) close, its views and its address space go,
    /// then its own reference on its object, which takes the object and the record with it.
    /// Nothing signals and nothing reports: only a last thread's exit ends a process. Two callers:
    /// a creation refused after the address space was built (no handle to the process exists),
    /// and the object's last reference beside the process's own going
    /// ([`threads::delete_if_abandoned`]). Runs on the calling thread, detached from the process
    /// (the directory goes here), with none of the reap's conditions: no thread ever ran on the
    /// directory, and nothing else references the object. Once: a second call does nothing.
    pub fn delete_threadless(&self) {
        assert!(
            self.stack_count() == 0 && !self.has_main_thread(),
            "a deleted process never had a thread"
        );
        assert_eq!(
            self.attach_count(),
            0,
            "a deleted process has no thread attached to its address space"
        );
        if locked(&self.state, |state| {
            core::mem::replace(&mut state.deleting, true)
        }) {
            return;
        }
        self.release_handles();
        release_address_space_of(self);
        locked(&self.state, |state| state.torn_down = true);
        release_record(self);
    }

    /// Whether the deletion of the process, one that never had a thread, has begun: its client id
    /// names nothing from then on.
    pub fn deleting(&self) -> bool {
        locked(&self.state, |state| state.deleting)
    }

    /// Whether the process has a main thread: a boot's program from its start, a process another
    /// created (NtCreateProcess) from its first thread's creation on.
    pub fn has_main_thread(&self) -> bool {
        crate::ob::locked(|directory| {
            directory
                .ordinals(self.object())
                .is_some_and(|ordinals| ordinals.has_main())
        })
    }

    /// The process's main thread's record, while its object lives; none before the process has
    /// one, and once the object is gone (the record may be another thread's by then).
    pub fn main_thread(&self) -> Option<crate::sched::thread::ThreadId> {
        crate::ob::locked(|directory| {
            let id = directory.ordinals(self.object())?.main()?;
            directory.thread(id)
        })
    }

    /// The TEB of every thread of this process that has one: the main thread's, then the created
    /// threads' (terminated ones too: their pages stay mapped until the ordinal is reused), in
    /// ordinal order. Another process's threads are never among them.
    pub fn thread_tebs(&self) -> rtl::array_vec::ArrayVec<u32, { ordinals::ORDINALS }> {
        let mut tebs = rtl::array_vec::ArrayVec::new();
        crate::ob::locked(|directory| {
            if let Some(ordinals) = directory.ordinals(self.object()) {
                for (_, teb) in ordinals.tebs() {
                    tebs.push(teb);
                }
            }
        });
        tebs
    }

    /// Attach the running thread to this process's address space until the guard drops (see
    /// [`crate::sched::attach`]): its user pages are the live ones, while the thread's own process
    /// stays the calling process ([`current`]). The record outlives the scope: the caller holds a
    /// reference on the process, or builds it.
    pub fn attach(&self) -> crate::sched::attach::Attached {
        crate::sched::attach::attach(self.sched_ptr())
    }

    /// Unmap every view of the process's address space, the live one: its pages go, and the
    /// reference each held on its section or image segment is dropped (one nothing else
    /// references goes with it, an image segment closing its file). Windows 2000's
    /// MmCleanProcessAddressSpace: the process's end runs it before its object signals, so a waiter
    /// finds the files its views mapped closed. The rest of the address space goes at the
    /// teardown.
    pub fn unmap_views(&self) {
        use crate::mem::vm::{CurrentPages, VIEWS};
        let mut gone = [None; VIEWS];
        self.with_space(|space| {
            let mut count = 0;
            space.drop_views(|view| {
                gone[count] = Some(view);
                count += 1;
            });
            for view in gone[..count].iter().flatten() {
                let _ = space.release(&mut CurrentPages, view.base);
            }
        });
        for view in gone.iter().flatten() {
            crate::ob::release_mapping(view.mapping);
        }
    }
}

/// The next client id to hand out (see [`new_client_id`]).
#[cfg(target_arch = "x86")]
static NEXT_CLIENT_ID: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(FIRST_CLIENT_ID);

/// The first client id: NT never hands out 0 (no object) or 4 (the System process).
pub const FIRST_CLIENT_ID: u32 = 8;

/// How far apart client ids are: four, as the platform's are (handle-table indices there).
pub const CLIENT_ID_STEP: u32 = 4;

/// A fresh client id for a process or a thread: processes and threads share one id space, as on
/// NT, and an id is never reused within a boot (system state, not per-process state).
#[cfg(target_arch = "x86")]
pub fn new_client_id() -> u32 {
    // The id is the counter's value before the step, taken in one read-modify-write, so no two
    // callers are handed the same id. Nothing else is published with it, hence relaxed.
    NEXT_CLIENT_ID.fetch_add(CLIENT_ID_STEP, core::sync::atomic::Ordering::Relaxed)
}

/// Give back the directory frame of an address space that maps nothing of its own (a start
/// refused before its first mapping): its kernel half is shared, so the frame is all it holds.
#[cfg(target_arch = "x86")]
fn free_directory(dir_phys: u32) {
    use crate::mem::frame::FrameState;
    crate::mem::bootmem::with_frame_db(|db| {
        db.release(dir_phys / paging::PAGE_SIZE, FrameState::Free)
    });
}

// --- Teardown -------------------------------------------------------------
//
// A process whose last thread has ended is torn down by the idle thread, on the boot stack and the
// boot address space (the switch to the idle thread loaded it): every frame the process owned is
// released, and the directory frame last. The walk reads the dead directory through the scratch
// window — it is not mapped anywhere, and must not be: the kernel never runs on a directory being
// freed.

/// Walk the process directory at `dir_phys` and release everything it owns exclusively: every
/// committed PTE's data frame in the user windows — present, or committed but inaccessible (a
/// no-access or guard page still names its frame) — and their page tables. The shared kernel half
/// (the kernel stack region's tables among it, the gate stacks being the threads') is never
/// touched, and the directory frame is the caller's, last.
pub fn release_address_space(
    dir_phys: u32,
    read_entry: impl Fn(u32, usize) -> u32,
    mut release: impl FnMut(u32),
) {
    use crate::mem::paging::{KERNEL_HALF_START, PAGE_ADDR_MASK, PAGE_PRESENT, PT_ENTRIES};
    for window in 0..KERNEL_HALF_START {
        let pde = read_entry(dir_phys, window);
        if pde & PAGE_PRESENT == 0 {
            continue;
        }
        let table = pde & PAGE_ADDR_MASK;
        for index in 0..PT_ENTRIES {
            let pte = read_entry(table, index);
            if crate::mem::vm::names_frame(pte) {
                release(pte & PAGE_ADDR_MASK);
            }
        }
        release(table);
    }
}

/// Release every frame a finished process owns: the address space, and the directory frame last of
/// all. Its threads' gate stacks are not among them: every thread has ended by now, its stack
/// released by the system's kernel stacks (the last exit's parked one, by the caller before this,
/// unless another exit or creation already did).
///
/// # Panics
///
/// A thread is still attached: teardown follows the last thread's end, never precedes it.
pub fn release_process(
    process: &Process,
    read_entry: impl Fn(u32, usize) -> u32,
    mut release: impl FnMut(u32),
) {
    assert_eq!(
        process.stack_count(),
        0,
        "teardown of a process with attached threads"
    );
    let dir_phys = process.dir_phys();

    // User data frames and their tables from the walk, then the directory itself.
    release_address_space(dir_phys, read_entry, &mut release);
    release(dir_phys);
}

/// The idle thread's reap step: tear the ended process down, then let the runner decide what
/// follows by the process's own leg — the teardown audit, and on a boot of several programs the
/// next one (or the summary); the idle thread rests after the last. Whether the reap is quiescent —
/// no other process remains that has not been torn down — is decided once, before the teardown: it
/// decides whether the system-wide checks run now.
#[cfg(target_arch = "x86")]
pub fn reap() {
    let process = pool::ended().expect("reap with no ended process");
    let end = process.end().expect("an ended process recorded its end");
    let leg = process.leg();
    let quiescent = pool::quiescent_after(process);
    teardown(process, quiescent);
    runner::process_reaped(leg, end, quiescent);
    #[cfg(feature = "fault-test-exitio")]
    crate::user::check_volume_after_teardown();
}

/// Tear the ended `process` down, steps 4 and 5 of its end (see the module notes): its address
/// space goes, then its own reference on the object goes (the record is free for the next process
/// once nothing else references the object). Between the two, the object audit: its threads'
/// records start over, and at a `quiescent` reap the leak sweep runs. Nothing here is observable
/// to the process's waiters: its object signalled at its last thread's exit, which the teardown
/// checks first.
///
/// Must run on the boot address space, attached to nothing — the walk reads the dead directory
/// through the scratch window, never through a mapping, and nothing else here reaches the process's
/// user pages (its views' sections give their frames back through the frame database).
#[cfg(target_arch = "x86")]
fn teardown(process: &'static Process, quiescent: bool) {
    let end = process.end().expect("a torn-down process has ended");
    let object = crate::ob::locked(|directory| directory.process(process.object()))
        .expect("an ended process's object outlives its teardown");
    let signaled = crate::level::raised::<crate::level::Dispatch, _>(|dispatch| {
        let object = crate::sched::DISPATCHER
            .get(dispatch)
            .process_object_mut(object);
        object.waitable.signal_state() > 0 && object.exit_status == end.exit_status()
    });
    assert!(
        signaled,
        "a process's object signals its end before the teardown"
    );
    // Per thread first: the parked gate stack (the last exit's, or a later exit's in another
    // process: whichever is parked, its owner off it for good, since this runs on the idle
    // thread's boot stack). Then per process.
    crate::mem::kstacks::release_parked();
    release_address_space_of(process);
    audit_objects(process, quiescent);
    locked(&process.state, |state| state.torn_down = true);
    release_record(process);
}

/// Step 4: the address space goes — every frame the process owns (see [`release_process`]); the
/// reap releases the parked gate stack before it. The process is torn down in place: its record
/// holds absolute addresses into itself.
#[cfg(target_arch = "x86")]
fn release_address_space_of(process: &Process) {
    use crate::mem::frame::FrameState;
    use crate::mem::paging::{self, PAGE_SIZE};
    // The views of an ended process went with its end (see `Process::unmap_views`); a deleted
    // threadless one's go here, each dropping its reference on its section or image segment (one
    // nothing else references goes with it, dropping its hold on its frames) once the address
    // space has let go of them. Their pages are the walk's.
    let mut gone = [None; crate::mem::vm::VIEWS];
    process.with_space(|space| {
        let mut count = 0;
        space.drop_views(|view| {
            gone[count] = Some(view.mapping);
            count += 1;
        });
    });
    for mapping in gone.iter().flatten() {
        crate::ob::release_mapping(*mapping);
    }
    release_process(
        process,
        |frame, index| paging::read_frame_word(frame, index),
        |frame_phys| {
            // A frame goes back with its last holder: the system DLLs' pages and the shared data
            // page are the kernel's, every process one more holder of them.
            crate::mem::bootmem::with_frame_db(|db| {
                if db.unshare(frame_phys / PAGE_SIZE) {
                    db.release(frame_phys / PAGE_SIZE, FrameState::Free);
                }
            });
        },
    );
}

/// The object audit. With its handles closed, its waits returned and its threads ended, the
/// process holds no object any more: what only it held is gone, and its threads' records start
/// over. An object still live may be another process's too, so the leak sweep waits for a
/// `quiescent` reap: with no process left, no object is left either — nor any open-file record.
/// One that is would be a reference leak: it is reported, and swept all the same (a leaked
/// section's frames given back; the file records are forgotten whole).
#[cfg(target_arch = "x86")]
fn audit_objects(process: &Process, quiescent: bool) {
    crate::ob::locked(|directory| directory.process_ended(process.sched_ptr()));
    if !quiescent {
        return;
    }
    // With no process left, the console has none attached: its input-wait event goes with it.
    crate::csr::release_input_event();
    // The sweep, one leak at a time: a leaked section's frames are given back between the steps,
    // outside the directory's lock (the file records are forgotten whole after).
    let mut leaked = 0;
    while let Some(leak) = crate::ob::locked(crate::ob::Directory::sweep_next) {
        leaked += 1;
        if let Some(crate::ob::Followup::Section { frames, .. }) = leak.followup {
            crate::nt::section::release_frames(frames);
        }
    }
    crate::ob::locked(crate::ob::Directory::sweep_end);
    leaked += crate::fs::file::with_records(crate::fs::file::FileRecords::clear);
    if leaked != 0 {
        crate::serial_println!(
            "F2K: object audit FAILED: {} objects or file records outlived their process",
            leaked
        );
    }
}

/// Step 5: the process's own reference on its object goes. The record is reused once the object is
/// gone — now, unless a handle to the process outlives it.
#[cfg(target_arch = "x86")]
fn release_record(process: &Process) {
    crate::ob::release(process.object());
}

/// The post-boot free-frame count: the baseline the teardown audits compare against at
/// quiescence. Recorded once the boot's own permanent allocations are done, before the first
/// process starts.
#[cfg(target_arch = "x86")]
static BASELINE_FRAMES: crate::sync::InitOnce<u32> = crate::sync::InitOnce::new();

/// Record the allocator baseline (`available()` at the call site).
///
/// # Panics
///
/// The baseline is recorded already: the boot records it once.
#[cfg(target_arch = "x86")]
pub fn record_allocator_baseline() {
    BASELINE_FRAMES.set(crate::mem::bootmem::with_frame_db(|db| db.available()));
}

/// The frame database's structure audit, valid at any time and run at every reap: whether it holds.
#[cfg(target_arch = "x86")]
pub fn audit_structures() -> bool {
    crate::mem::bootmem::with_frame_db(|db| db.audit().is_ok())
}

/// The free frames now and at the post-boot baseline: equal at quiescence, when no process holds a
/// frame (see [`exit::DeferredAudits`]).
///
/// # Panics
///
/// The baseline is not recorded yet: it is, before the first process starts.
#[cfg(target_arch = "x86")]
pub fn frames_against_baseline() -> (u32, u32) {
    let baseline = *BASELINE_FRAMES.get();
    let available = crate::mem::bootmem::with_frame_db(|db| db.available());
    (available, baseline)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::mem::kstacks::{GateSlots, GateStack, KernelStacks};
    use crate::mem::layout::KERNEL_STACKS;
    use crate::mem::paging::{KERNEL_HALF_START, PAGE_PRESENT, PT_ENTRIES};
    use crate::mem::vm::{encode, PAGE_GUARD, PAGE_NOACCESS, PAGE_READWRITE};
    use crate::sched::thread::{Thread, ThreadId, NO_GATE_SLOT};

    // --- The process record (the per-thread state split's shape) --------

    /// A process record as the tests build it: by value, at `dir`, standing for a made-up process
    /// object.
    fn record_at(dir: u32) -> Process {
        let mut process = Process::empty();
        process.sched = PinnedProcess::new(dir, 8);
        *process.identity.0.get_mut() = Identity {
            name: ProcessName::new(b"fixture"),
            id: FIRST_CLIENT_ID,
            parent_id: 0,
            leg: None,
            object: crate::ob::ObjectId {
                kind: crate::ob::ObjectType::Process,
                index: 0,
                generation: 0,
            },
            dir_phys: dir,
        };
        process
    }

    fn fresh_process() -> Box<Process> {
        Box::new(record_at(0x0090_0000))
    }

    /// A process's name: its image's file name without the extension, cut at fifteen bytes (the
    /// image name Windows keeps in a process), a byte past ASCII as `?`.
    #[test]
    fn a_process_is_named_by_its_images_stem() {
        assert_eq!(ProcessName::of_file(b"spawnkid.exe").as_str(), "spawnkid");
        assert_eq!(ProcessName::of_file(b"kid copy.exe").as_str(), "kid copy");
        assert_eq!(ProcessName::of_file(b"KIDCOPY").as_str(), "KIDCOPY");
        assert_eq!(ProcessName::of_file(b"a.b.exe").as_str(), "a");
        assert_eq!(
            ProcessName::of_file(b"averyveryverylongname.exe").as_str(),
            "averyveryverylo"
        );
        assert_eq!(ProcessName::new(b"caf\xe9").as_str(), "caf?");
        assert_eq!(ProcessName::new(b"").as_str(), "");
    }

    /// A fresh record: no end under way, none recorded.
    #[test]
    fn a_fresh_process_is_not_ending() {
        let process = fresh_process();
        assert!(!process.terminating());
        assert!(process.end().is_none() && !process.awaits_teardown());
    }

    /// Client ids are NT's: never 0 or 4 (the System process), stepping by four, one space for
    /// processes and threads.
    #[test]
    fn client_ids_step_by_four_from_eight() {
        assert_eq!(FIRST_CLIENT_ID, 8);
        assert_eq!(CLIENT_ID_STEP, 4);
        assert_eq!(record_at(0x0090_0000).id(), FIRST_CLIENT_ID);
    }

    /// A fresh process: its scheduling record on its directory; the process owns no gate stack of
    /// its own, its threads do.
    #[test]
    fn fresh_process_state_starts_clean() {
        crate::sched::testkit::dispatcher();
        let process = fresh_process();
        assert_eq!(process.name().as_str(), "fixture");
        assert_eq!(process.dir_phys(), 0x0090_0000);
        assert_eq!(process.base_priority(), 8);
        assert_eq!(process.attach_count(), 0);
        assert_eq!(Thread::new(ThreadId(0)).gate_slot(), NO_GATE_SLOT);
        assert_eq!(process.with_handles(|table| table.live()), 0);
        assert_eq!(process.priority_class(), NORMAL_PRIORITY_CLASS);
        assert_eq!(process.hard_error_mode(), DEFAULT_HARD_ERROR_MODE);
        assert_eq!(process.console(), rtl::console::Handles::standard());
    }

    /// The parts are locked apart: the handle table and the address space each by its own lock,
    /// one hold after the other.
    #[test]
    fn the_parts_lock_apart() {
        let process = fresh_process();
        let handle = process.with_handles(|table| table.insert(event_entry()));
        assert!(process.with_space(|space| space.region_at(0x0040_0000).is_none()));
        assert_eq!(process.lookup_handle(handle), Some(event_entry()));
    }

    /// A part's lock is never taken inside another's: a hold is the change itself, nothing more.
    #[test]
    #[should_panic(expected = "a process's lock taken above the passive level")]
    fn a_part_is_never_locked_inside_another() {
        let process = fresh_process();
        process.with_space(|_| process.lookup_handle(4));
    }

    /// A handle-table entry naming an event (the host has no object manager to count it).
    fn event_entry() -> crate::ob::Entry {
        crate::ob::Entry::object(
            crate::ob::ObjectId {
                kind: crate::ob::ObjectType::Event,
                index: 0,
                generation: 0,
            },
            crate::ob::EVENT_ALL_ACCESS,
            false,
        )
    }

    /// The process-exit step closes every handle at once (an open file's among them: a file object
    /// is an object like any other, its cleanup the object manager's), and the table starts over.
    #[test]
    fn the_exit_step_releases_every_handle() {
        let process = fresh_process();
        let handle = process.with_handles(|table| table.insert(event_entry()));
        process.with_handles(|table| {
            // Past the first step of the walk, too.
            for _ in 0..2 * HANDLE_STEP {
                table.insert(event_entry());
            }
        });
        process.release_handles();
        assert_eq!(process.with_handles(|table| table.live()), 0);
        assert!(process.lookup_handle(handle).is_none());
        assert!(!process.close_handle(handle), "closed already");
        assert_eq!(
            process.with_handles(|table| table.insert(event_entry())),
            4,
            "the table starts over"
        );
    }

    // --- Teardown accounting -------------------------------------------------
    //
    // Fake physical memory: frames as pages of 1024 words, released frames collected with counts.

    struct FakeMemory {
        frames: HashMap<u32, [u32; PT_ENTRIES]>,
        released: Vec<u32>,
    }

    impl FakeMemory {
        fn new() -> Self {
            Self {
                frames: HashMap::new(),
                released: Vec::new(),
            }
        }

        /// Plant a frame whose words come from (index, value) pairs.
        fn plant(&mut self, frame: u32, words: &[(usize, u32)]) {
            let mut page = [0u32; PT_ENTRIES];
            for &(index, value) in words {
                page[index] = value;
            }
            self.frames.insert(frame, page);
        }

        fn read(&self, frame: u32, index: usize) -> u32 {
            self.frames[&frame][index]
        }

        /// Run the teardown's releases over the fake memory, in the target's order: the parked
        /// gate stack first (the system's kernel stacks give its frames back), then the real
        /// collection of the process's own frames.
        fn tear_down(&mut self, stacks: &mut KernelStacks, process: &Process) {
            if let Some((_, frames)) = stacks.take_parked() {
                self.released.extend_from_slice(&frames);
            }
            let mut released = core::mem::take(&mut self.released);
            release_process(
                process,
                |frame, index| self.read(frame, index),
                |frame_phys| released.push(frame_phys),
            );
            self.released = released;
        }

        /// How many times `frame` was released.
        fn count(&self, frame: u32) -> usize {
            self.released.iter().filter(|&&f| f == frame).count()
        }
    }

    /// The main thread's gate-stack frames (slot 0) and a child's (slot 1).
    const MAIN_STACK: [u32; crate::mem::paging::GATE_STACK_PAGES] = [
        0x00F1_0000,
        0x00F2_0000,
        0x00F3_0000,
        0x00F4_0000,
        0x00F1_1000,
        0x00F2_1000,
        0x00F3_1000,
        0x00F4_1000,
    ];
    const CHILD_STACK: [u32; crate::mem::paging::GATE_STACK_PAGES] = [
        0x00F5_0000,
        0x00F6_0000,
        0x00F7_0000,
        0x00F8_0000,
        0x00F5_1000,
        0x00F6_1000,
        0x00F7_1000,
        0x00F8_1000,
    ];

    /// The kernel stack region's first table: the boot's, shared by every directory.
    const SHARED_STACK_TABLE: u32 = 0x00C0_0000;

    /// A planted directory — two user tables' worth (a TEB page and an image page), and the shared
    /// kernel half with the kernel stack region's first table — and a process whose main thread
    /// owns slot 0 and whose child owns slot 1, both attached.
    fn planted_process(
        dir: u32,
    ) -> (
        FakeMemory,
        &'static Process,
        crate::sched::testkit::Rec<Thread>,
        crate::sched::testkit::Rec<Thread>,
    ) {
        let mut mem = FakeMemory::new();
        let user_table = 0x00A0_0000;
        mem.plant(
            dir,
            &[
                (1, user_table | PAGE_PRESENT),
                // The shared kernel half: present entries that must not be walked or released.
                (
                    KERNEL_STACKS.first_entry(),
                    SHARED_STACK_TABLE | PAGE_PRESENT,
                ),
                (KERNEL_HALF_START, 0x0010_0000 | PAGE_PRESENT),
                (KERNEL_HALF_START + 1, dir | PAGE_PRESENT), // self-map
            ],
        );
        // The TEB pages (user half: the walk owns them, so the thread records must not hold them)
        // and one image page; a page the program made no-access and a guard page, both committed
        // but not present: they still name their frames.
        mem.plant(
            user_table,
            &[
                (0, 0x00E0_0000 | PAGE_PRESENT),
                (1, encode(0x00E1_0000, PAGE_NOACCESS)),
                (2, encode(0x00E2_0000, PAGE_READWRITE | PAGE_GUARD)),
            ],
        );
        mem.plant(SHARED_STACK_TABLE, &[]);

        // Boxed to its final address before anything attaches to it: its threads name it by its
        // address, so the record must never move once attached.
        let process = Box::leak(Box::new(record_at(dir)));
        // The thread records are the dispatcher database's: a host dispatcher's here. The
        // system's ledger is the target's; a local one hands out the same slots here.
        crate::sched::testkit::dispatcher();
        let mut main = crate::sched::testkit::thread(process.sched_ptr());
        let mut child = crate::sched::testkit::thread(process.sched_ptr());
        let mut slots = GateSlots::empty();
        main.gate_slot = slots.allocate().unwrap();
        main.gate_frames = MAIN_STACK;
        child.gate_slot = slots.allocate().unwrap();
        child.gate_frames = CHILD_STACK;
        (mem, process, main, child)
    }

    /// Run `thread`'s exit as the exit path does, on the host dispatcher holding it: the
    /// scheduler's termination, then its own stack parked with the system's kernel stacks, the one
    /// parked before it handed back (returned, for the caller to account).
    fn exit(
        stacks: &mut KernelStacks,
        thread: crate::sched::testkit::Rec<Thread>,
    ) -> Option<GateStack> {
        let dispatcher = crate::sched::testkit::installed();
        dispatcher.enter(thread.id());
        dispatcher.terminate();
        stacks.park((thread.gate_slot, thread.gate_frames))
    }

    /// Teardown after every thread has exited releases exactly the process's own frames, each
    /// exactly once: the last exit's parked stack, the walked user data frames (committed pages the
    /// program may not touch included) and tables, and the directory — nothing from the shared
    /// kernel half, the kernel stack region's table included. An earlier exit's stack is not
    /// teardown's: the next exit released it. A thread's TEB page is released once, by the walk
    /// (the thread records never hold user-half frames).
    #[test]
    fn teardown_releases_exactly_the_process_frames() {
        let dir = 0x0090_0000;
        let (mut mem, process, main, child) = planted_process(dir);
        let mut stacks = KernelStacks::empty();
        // The child exits first, then the main thread — whose exit hands back the child's stack
        // for release from its own.
        assert_eq!(exit(&mut stacks, child), None);
        assert_eq!(exit(&mut stacks, main), Some((1, CHILD_STACK)));
        assert_eq!(process.stack_count(), 0);

        mem.tear_down(&mut stacks, process);

        let mut released = mem.released.clone();
        released.sort_unstable();
        let mut expected = vec![
            0x00A0_0000, // the user table
            0x00E0_0000, // the TEB/image data page
            0x00E1_0000, // the no-access page
            0x00E2_0000, // the guard page
            dir,         // the directory
        ];
        expected.extend_from_slice(&MAIN_STACK);
        expected.sort_unstable();
        assert_eq!(released, expected);
        // Exactly once each, always.
        for frame in expected {
            assert_eq!(mem.count(frame), 1, "frame {frame:#x}");
        }
        // The child's stack was the main thread's exit to release; the kernel half's tables and
        // targets stay.
        for frame in CHILD_STACK {
            assert_eq!(mem.count(frame), 0);
        }
        assert_eq!(mem.count(SHARED_STACK_TABLE), 0);
        assert_eq!(mem.count(0x0010_0000), 0);
        assert_eq!(stacks.take_parked(), None);
    }

    /// The teardown's order: per thread first (the parked stack), then per process (the
    /// address-space walk), the directory frame last of all.
    #[test]
    fn teardown_releases_per_thread_then_per_process() {
        let dir = 0x0090_0000;
        let (mut mem, process, main, child) = planted_process(dir);
        let mut stacks = KernelStacks::empty();
        exit(&mut stacks, child);
        exit(&mut stacks, main);

        mem.tear_down(&mut stacks, process);
        let released = &mem.released;
        assert_eq!(
            &released[..MAIN_STACK.len()],
            &MAIN_STACK,
            "the parked stack first"
        );
        assert_eq!(released.last(), Some(&dir), "the directory last");
        assert_eq!(released.len(), MAIN_STACK.len() + 4 + 1);
    }

    /// One parked stack serves the system: a process's last exit parks its stack, another
    /// process's thread exiting before the teardown releases it (handed back by its own park), and
    /// the teardown releases whatever is parked then — that other thread's stack, its owner off it
    /// for good. Every stack is released once, the process's own frames by the walk.
    #[test]
    fn a_teardown_releases_whatever_stack_is_parked() {
        let dir = 0x0090_0000;
        let (mut mem, process, main, child) = planted_process(dir);
        let mut stacks = KernelStacks::empty();
        assert_eq!(exit(&mut stacks, child), None);
        assert_eq!(exit(&mut stacks, main), Some((1, CHILD_STACK)));

        // A thread of another process (slot 2) exits before the teardown runs.
        let other_process = Box::leak(Box::new(record_at(0x0095_0000)));
        let mut other = crate::sched::testkit::thread(other_process.sched_ptr());
        other.gate_slot = 2;
        other.gate_frames = [0x00D0_0000; crate::mem::paging::GATE_STACK_PAGES];
        assert_eq!(exit(&mut stacks, other), Some((0, MAIN_STACK)));

        mem.tear_down(&mut stacks, process);
        assert_eq!(mem.count(0x00D0_0000), crate::mem::paging::GATE_STACK_PAGES);
        for frame in MAIN_STACK {
            assert_eq!(mem.count(frame), 0, "released by the other thread's exit");
        }
        assert_eq!(mem.count(dir), 1);
        assert_eq!(stacks.take_parked(), None);
    }

    /// Teardown never precedes the last thread's end: a process with a thread still attached is
    /// refused.
    #[test]
    #[should_panic(expected = "teardown of a process with attached threads")]
    fn teardown_refuses_a_process_with_attached_threads() {
        let dir = 0x0090_0000;
        let (mut mem, process, _main, child) = planted_process(dir);
        let mut stacks = KernelStacks::empty();
        exit(&mut stacks, child);
        mem.tear_down(&mut stacks, process);
    }

    /// A process that never had a thread holds the stack count's sentinel, which reads as no thread
    /// attached: its teardown (its deletion's) releases its address space, the directory last.
    #[test]
    fn a_process_that_never_had_a_thread_is_torn_down() {
        let _dispatcher = crate::sched::testkit::dispatcher();
        let dir = 0x0090_0000;
        let process: &'static Process = Box::leak(Box::new(record_at(dir)));
        let mut mem = FakeMemory::new();
        let user_table = 0x00A0_0000;
        mem.plant(
            dir,
            &[
                (1, user_table | PAGE_PRESENT),
                (KERNEL_HALF_START, 0x0010_0000 | PAGE_PRESENT),
            ],
        );
        mem.plant(user_table, &[(0, 0x00E0_0000 | PAGE_PRESENT)]);
        assert_eq!(process.stack_count(), 0, "the sentinel reads as none");
        mem.tear_down(&mut KernelStacks::empty(), process);
        assert_eq!(mem.released, vec![0x00E0_0000, user_table, dir]);
    }

    /// The walk's user range ends below the kernel stack region: the region's entries are in the
    /// shared kernel half, which the walk never reaches.
    #[test]
    fn the_kernel_stack_region_sits_in_the_kernel_half() {
        assert!(KERNEL_STACKS.first_entry() >= KERNEL_HALF_START);
        assert_eq!(KERNEL_STACKS.first_entry(), 656);
        assert_eq!(KERNEL_HALF_START, 512);
    }
}
