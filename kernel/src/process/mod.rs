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
//! later by its creator, is its main thread. Until then nothing ends it but a termination or its
//! last handle's closing (see [`threads`]).
//!
//! The per-thread state split: the ring-0 gate stack (the thread's kernel stack, what the TSS
//! `esp0` points into) is per-thread, a slot of the kernel stack region numbered system-wide and
//! mapped in every address space ([`crate::mem::kstacks`]), each slot's frames recorded by their
//! owning thread. The thread records themselves are the object manager's ([`crate::ob`]), taken
//! from its whole pool; the process numbers its own threads ([`ordinals`]), which places their TEB
//! pages. The scheduling record leads the process at a pinned offset, so a thread's address-space
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
//! 1. every other thread is terminated, without running again (the exit service's and a fault's
//!    end; a thread inside a critical region finishes it first);
//! 2. every handle closes, as CloseHandle would — the objects go with their last references;
//! 3. the last thread's object signals, then the process object with the exit code: their waiters
//!    wake, and the switch away from the last thread may select one of them;
//! 4. the address space goes: every frame;
//! 5. the record is freed with the object's last reference.
//!
//! Steps 1 to 3 run on the last thread, in [`threads`]: by its switch away the process has ended
//! for everyone who can observe it, however long the reap waits for the processor. Steps 4 and 5
//! run on the idle thread's reap, in [`reap`], with the object audit between them and the teardown
//! audit after 5; their checks over the whole system, and the audit lines, wait for quiescence.
//!
//! The records live in the process pool ([`pool`]), which also answers which process is current:
//! kernel state (like CR3 and the TSS), not per-process state. Everything per-process lives inside
//! the [`Process`] record, or in the object manager's pools every process shares: its objects,
//! reached through its handles, and its threads' records, through its thread list.

/// The end of a thread and of its process, as decisions: the exit routing, the report lines,
/// the suite's leg order and tally.
pub mod exit;

/// The boot's programs, run one after another.
#[cfg(target_arch = "x86")]
pub mod runner;

/// The process pool and the current process.
pub mod pool;

/// The process's own synchronization records: the user-APC records QueueUserAPC queues.
pub mod objects;

/// The process's thread ordinals: which thread holds which TEB page.
pub mod ordinals;

pub use pool::MAX_PROCESSES;
#[cfg(target_arch = "x86")]
pub use pool::{current, current_mut, reap_pending};

/// The smoke-subset thread surface: child-thread creation, the thread records, the thread-exit
/// path.
#[cfg(target_arch = "x86")]
pub mod threads;

#[cfg(target_arch = "x86")]
use crate::mem::paging;

/// A process: one address space and its threads.
#[repr(C)]
pub struct Process {
    /// The scheduling record, leading the process record: the context switch's assembly reads the
    /// directory base through a thread's owner pointer at a pinned offset.
    pub sched: crate::sched::process::SchedProcess,
    /// The image's name, as its end reports it on COM1.
    name: ProcessName,
    /// The process's client id (what GetCurrentProcessId reports, through the TEB).
    id: u32,
    /// The client id of the process that created it (ProcessBasicInformation's
    /// InheritedFromUniqueProcessId): zero for a boot's program, which no process created.
    parent_id: u32,
    /// The boot's program the process runs as, its 1-based index in the boot's list (see
    /// [`runner`]); none for a process another process started. Its end reports by it.
    leg: Option<u32>,
    /// The process's object: what a handle to the process names and a wait on it waits for. It
    /// holds the process's own reference until the teardown's end, and its index is the record's
    /// in the pool.
    object: crate::ob::ObjectId,
    /// The priority class (PROCESS_PRIORITY_CLASS_*, ProcessPriorityClass's value).
    priority_class: u8,
    /// The hard-error mode (DefaultHardErrorProcessing, ProcessDefaultHardErrorMode's value: the
    /// hard-error and fault dialogs it governs never exist here; the value is kept for its round
    /// trip).
    hard_error_mode: u32,
    /// The main thread's object (on any free thread record when the process started); none before
    /// the process has one. Its generation tells a later thread of the same record apart.
    main_thread: Option<crate::ob::ObjectId>,
    /// The thread ordinals: which thread holds which TEB page, and the pages a terminated thread
    /// left mapped.
    ordinals: ordinals::Ordinals,
    /// The address space's regions: every user page the process holds lies in one, and every
    /// mapping, commit and release of its pages goes through it.
    vm: crate::mem::vm::AddressSpace,
    /// The handle table: the process's handles-to-objects (its open files' among them: a file
    /// object each, see `crate::fs::file`).
    handles: crate::sched::object::HandleTable,
    /// The process's console handles: the console server's own, outside the handle table, as
    /// Windows 2000's csrss keeps them (see `crate::csr`).
    console: rtl::console::Handles,
    /// The process's connection to win32k: its window station's and desktop's handles, made at its
    /// first win32k service (see `crate::win32k::winsta`); none until then.
    win32k: Option<crate::win32k::winsta::Connection>,
    /// The user-APC records (the objects themselves are the object manager's).
    objects: objects::SyncObjects,
    /// Why the process ended, recorded by its last thread's exit; the idle thread's reap step
    /// tears down a process once this is set.
    end: Option<exit::ProcessEnd>,
    /// The end an exit or fault decided while some threads were still finishing a critical region:
    /// the last of them ends the process with it.
    handed_end: Option<exit::ProcessEnd>,
    /// Whether its end is under way with none of its threads running it (a termination from
    /// another process, or the deletion of one that never had a thread; see
    /// [`threads::end_unattended`]): it takes no new thread, and is not ended twice.
    ending: bool,
    /// Whether the teardown has run (the record waits for its object's last reference).
    torn_down: bool,
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

/// A process record's parts, borrowed apart (see [`Process::parts_mut`]).
pub struct ProcessParts<'a> {
    /// The address space's regions.
    pub vm: &'a mut crate::mem::vm::AddressSpace,
    /// The handle table.
    pub handles: &'a mut crate::sched::object::HandleTable,
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

// The scheduling record leads the process record: a thread's owner pointer and the process's
// directory base are one pinned chain.
const _: () = assert!(core::mem::offset_of!(Process, sched) == 0);

impl Process {
    /// The process's name.
    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    /// The process's client id.
    pub fn id(&self) -> u32 {
        self.id
    }

    /// The client id of the process that created this one; zero for a boot's program.
    pub fn parent_id(&self) -> u32 {
        self.parent_id
    }

    /// Record the client id of the process that created this one (its creator sets it, once the
    /// record is written).
    pub fn set_parent_id(&mut self, parent_id: u32) {
        self.parent_id = parent_id;
    }

    /// The boot's program the process runs as (its 1-based index); none for a child.
    pub fn leg(&self) -> Option<u32> {
        self.leg
    }

    /// The process's object.
    pub fn object(&self) -> crate::ob::ObjectId {
        self.object
    }

    /// The console handles (the console server serves them).
    pub fn console_mut(&mut self) -> &mut rtl::console::Handles {
        &mut self.console
    }

    /// Whether the process is ending: its end is held for threads finishing a critical region, or
    /// under way with none of its threads running it. It takes no new thread then.
    pub fn terminating(&self) -> bool {
        self.ending || self.handed_end.is_some()
    }

    /// Whether the process has a main thread: a boot's program from its start, a process another
    /// created (NtCreateProcess) from its first thread's creation on.
    pub fn has_main_thread(&self) -> bool {
        self.ordinals.has_main()
    }

    /// The process's connection to win32k, once its first win32k service made it.
    pub fn win32k(&self) -> Option<crate::win32k::winsta::Connection> {
        self.win32k
    }

    /// Record the process's connection to win32k.
    pub fn set_win32k(&mut self, connection: crate::win32k::winsta::Connection) {
        self.win32k = Some(connection);
    }

    /// The process's priority class (PROCESS_PRIORITY_CLASS_*).
    pub fn priority_class(&self) -> u8 {
        self.priority_class
    }

    /// Record the process's priority class (the scheduling side is the caller's).
    pub fn set_priority_class(&mut self, class: u8) {
        self.priority_class = class;
    }

    /// The process's hard-error mode.
    pub fn hard_error_mode(&self) -> u32 {
        self.hard_error_mode
    }

    /// Set the process's hard-error mode.
    pub fn set_hard_error_mode(&mut self, mode: u32) {
        self.hard_error_mode = mode;
    }

    /// The process's page-directory frame.
    pub fn dir_phys(&self) -> u32 {
        self.sched.dir_phys()
    }

    /// The record's parts, borrowed apart: what a service needs several of at once (the address
    /// space and the handle table, say) without re-borrowing the whole record.
    pub fn parts_mut(&mut self) -> ProcessParts<'_> {
        ProcessParts {
            vm: &mut self.vm,
            handles: &mut self.handles,
        }
    }

    /// The address space (every user mapping goes through it).
    pub fn vm(&mut self) -> &mut crate::mem::vm::AddressSpace {
        &mut self.vm
    }

    /// The address space, to read (a query that changes nothing).
    pub fn space(&self) -> &crate::mem::vm::AddressSpace {
        &self.vm
    }

    /// The user-APC records.
    pub fn sync_mut(&mut self) -> &mut objects::SyncObjects {
        &mut self.objects
    }

    /// The handle table, for lookups.
    pub fn handles(&self) -> &crate::sched::object::HandleTable {
        &self.handles
    }

    /// Close a handle: the table's claim ends — the object's handle, with its reference (the last
    /// handle cleans a file object up, the last reference deletes the object). False when the
    /// handle names nothing.
    pub fn close_handle(&mut self, handle: u32) -> bool {
        let Some(entry) = self.take_handle(handle) else {
            return false;
        };
        self.release_handle(entry);
        true
    }

    /// The first half of a handle's close: its slot is free from here on (the next insert takes
    /// it), while what its entry names stays counted until [`Process::release_handle`]. None when
    /// the handle names nothing.
    pub fn take_handle(&mut self, handle: u32) -> Option<crate::ob::Entry> {
        self.handles.close(handle)
    }

    /// The second half of a handle's close: what the entry [`Process::take_handle`] took out
    /// names is released (see [`Process::close_handle`]).
    pub fn release_handle(&mut self, entry: crate::ob::Entry) {
        self.release_entry(entry);
    }

    /// Change the entry a handle names in this process's table with `change` (its inheritance, its
    /// protection from close: NtSetInformationObject's); false when the handle names nothing.
    pub fn update_handle(
        &mut self,
        handle: u32,
        change: impl FnOnce(crate::ob::Entry) -> crate::ob::Entry,
    ) -> bool {
        self.handles.update(handle, change)
    }

    /// Release what one closed handle named. A process's last handle closing ends the process if
    /// it never had a thread (see [`threads::forsake_if_abandoned`]).
    fn release_entry(&mut self, entry: crate::ob::Entry) {
        match entry.target {
            #[cfg(target_arch = "x86")]
            crate::ob::Target::Object(id) => {
                crate::ob::directory().handle_closed(id, |followup| self.finish(followup));
                if id.kind == crate::ob::ObjectType::Process {
                    threads::forsake_if_abandoned(id);
                }
            }
            #[cfg(not(target_arch = "x86"))]
            crate::ob::Target::Object(_) => {}
        }
    }

    /// Finish what the object manager left to the process when one of its objects' last handle or
    /// last reference went: a section's hold on its frames (and a file's section's on its file
    /// object), a file object's cleanup and its record's close.
    pub fn finish(&mut self, followup: crate::ob::Followup) {
        use crate::ob::Followup;
        match followup {
            Followup::Section {
                frames,
                file_object,
            } => {
                crate::nt::section::release_frames(frames);
                #[cfg(target_arch = "x86")]
                if let Some(file_object) = file_object {
                    if let Some(followup) = unmap_file(file_object) {
                        self.finish(followup);
                    }
                }
                #[cfg(not(target_arch = "x86"))]
                let _ = file_object;
            }
            #[cfg(target_arch = "x86")]
            Followup::FileCleanup {
                record,
                access,
                share,
                delete_on_close,
            } => crate::fs::io::cleanup(record, access, share, delete_on_close),
            #[cfg(target_arch = "x86")]
            Followup::FileClose { record } => crate::fs::io::close(record),
            #[cfg(not(target_arch = "x86"))]
            Followup::FileCleanup { .. } | Followup::FileClose { .. } => {}
        }
    }

    /// Insert a handle to object `id` with `access` and `inheritance`, the object counting it; null
    /// when the table is full (the object is left as it was).
    #[cfg(target_arch = "x86")]
    pub fn insert_object(&mut self, id: crate::ob::ObjectId, access: u32, inherit: bool) -> u32 {
        if self.handles.is_full() || !crate::ob::directory().handle_opened(id) {
            return 0;
        }
        self.handles
            .insert(crate::ob::Entry::object(id, access, inherit))
    }

    /// Take into this process's table, a fresh one, every inheritable handle of `parent`'s, each at
    /// its own value with its access and inheritance — the documented inheritance of a process
    /// created with InheritObjectTable (CreateProcess's bInheritHandles) — each object counting its
    /// new handle. (The console handles are not the table's: NtCreateProcess hands every child the
    /// parent's inheritable ones.) Returns how many handles were taken.
    #[cfg(target_arch = "x86")]
    pub fn inherit_handles(&mut self, parent: &Process) -> usize {
        let directory = crate::ob::directory();
        self.handles.inherit_from(&parent.handles, |entry| {
            // A handle names a live object (it holds it), so the count always takes.
            entry.inherit
                && entry
                    .object_id()
                    .is_some_and(|id| directory.handle_opened(id))
        })
    }

    /// Every thread of this process that has a TEB, as (ordinal, TEB address): the main thread at
    /// ordinal 0, then the created threads (terminated ones too: their pages stay mapped until the
    /// ordinal is reused). Another process's threads are never among them.
    pub fn thread_tebs(&self) -> impl Iterator<Item = (u32, u32)> + '_ {
        self.ordinals.tebs()
    }

    /// Release every handle at once: the process-exit step. Each closes as a CloseHandle would.
    pub fn release_handles(&mut self) {
        use crate::sched::object::{HANDLE_SHIFT, HANDLE_SLOTS};
        for index in 1..HANDLE_SLOTS as u32 {
            if let Some(entry) = self.handles.close(index << HANDLE_SHIFT) {
                self.release_entry(entry);
            }
        }
        self.handles.drain(|_| {});
    }

    /// Hold the process's end for the threads still finishing a critical region (see
    /// [`exit::hand_over`]), once.
    pub fn hand_end(&mut self, end: exit::ProcessEnd) {
        assert!(
            self.handed_end.is_none(),
            "a process's end is handed on once"
        );
        self.handed_end = Some(end);
    }

    /// The end held for the threads finishing a critical region; none unless an exit or fault
    /// handed one on.
    pub fn handed_end(&self) -> Option<exit::ProcessEnd> {
        self.handed_end
    }

    /// Record why the process ended: its last thread's exit, once.
    pub fn set_end(&mut self, end: exit::ProcessEnd) {
        assert!(self.end.is_none(), "a process ends once");
        self.end = Some(end);
    }

    /// The process has ended, step 3 of its end (see the module notes): its object signals with
    /// `end`'s exit code, and its waiters wake. The last thread's exit signals it, after its own
    /// object, before its switch away selects the next thread.
    #[cfg(target_arch = "x86")]
    pub fn signal_end(&mut self, end: exit::ProcessEnd) {
        crate::ob::directory().signal_process_end(self.object, end.exit_status());
    }
}

#[cfg(target_arch = "x86")]
impl Process {
    /// Create a process with no thread: a fresh address space with the record built at its final
    /// address in the pool, named `name`, running as leg `leg` (none for a child). The
    /// address space is not live: the caller attaches to the
    /// process ([`Process::attach`]) to map its user pages, each inside one of its regions.
    ///
    /// STATUS_INSUFFICIENT_RESOURCES when no process record is to be had (Windows 2000's answer to
    /// a full table); the fresh directory is given back then.
    pub fn create(
        name: ProcessName,
        leg: Option<u32>,
    ) -> Result<&'static mut Process, crate::status::NtStatus> {
        let dir_phys = paging::create_address_space();
        let process = match pool::create(dir_phys, name, leg) {
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
    // The record is the pool's, not borrowed from `name`.
    #[allow(clippy::mut_from_ref)]
    pub fn start(
        name: &str,
        leg: Option<u32>,
    ) -> Result<&'static mut Process, crate::status::NtStatus> {
        use crate::status::STATUS_INSUFFICIENT_RESOURCES;
        let process = Process::create(ProcessName::new(name.as_bytes()), leg)?;

        // The main thread's gate stack, taken before its record (as a created thread's is): a
        // release undoes it when the record is not to be had, and nothing is attached before both
        // are held.
        let Some((slot, frames)) = crate::mem::kstacks::create() else {
            process.abandon();
            return Err(STATUS_INSUFFICIENT_RESOURCES);
        };

        // The main thread: its object holds the thread's own reference while it runs (released at
        // its end), on any free record of the pool; it holds the process's ordinal 0 (the fixed TEB
        // page). It attaches to the process and runs on the gate stack just taken.
        let directory = crate::ob::directory();
        let Some(id) = directory.create_thread() else {
            crate::mem::kstacks::release((slot, frames));
            process.abandon();
            return Err(STATUS_INSUFFICIENT_RESOURCES);
        };
        // Its stack is a system region, not a reservation of its own.
        process.hold_main_thread(id, 0);
        let thread = directory.renew_thread(id);
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
            // SAFETY: the process record is the pool's, at its final address, and outlives its
            // threads (its teardown follows the last one's end).
            unsafe { dispatcher.attach(thread, &mut process.sched) };
        });
        // The TSS `esp0` is the switch's to install: the first switch into the main thread loads
        // its stack top.
        Ok(process)
    }

    /// Undo a start refused before the main thread was attached: the process's own reference on
    /// its object goes (no handle exists yet, so the object and the record go with it), then the
    /// fresh address space's directory, which maps nothing yet.
    fn abandon(&mut self) {
        let dir_phys = self.dir_phys();
        release_record(self);
        free_directory(dir_phys);
    }

    /// Undo a creation refused after the process's address space was built — a process with no
    /// thread and no handle to it — at once, as its teardown would: its handles (inherited ones)
    /// close, its views and its address space go, then its own reference on its object, which
    /// takes the object and the record with it. Runs detached from it: the directory goes here.
    pub fn discard(&mut self) {
        assert!(
            self.sched.stack_count() == 0 && !self.has_main_thread(),
            "a discarded process never had a thread"
        );
        self.release_handles();
        release_address_space_of(self);
        self.torn_down = true;
        release_record(self);
    }

    /// Record the process's main thread: `id` its object, holding ordinal 0 over the stack
    /// reserved at `stack` (zero: a system region, a boot's program's). A boot's program's is made
    /// with the process; a process another process created has its first thread for it (see
    /// [`threads::create`]).
    fn hold_main_thread(&mut self, id: crate::ob::ObjectId, stack: u32) {
        self.main_thread = Some(id);
        self.ordinals.hold_main(id, stack);
    }

    /// The process's main thread's record, while its object lives; none before the process has
    /// one, and once the object is gone (the record may be another thread's by then).
    pub fn main_thread(&self) -> Option<crate::sched::thread::ThreadId> {
        crate::ob::directory().thread(self.main_thread?)
    }

    /// Attach the running thread to this process's address space until the guard drops (see
    /// [`crate::sched::attach`]): its user pages are the live ones, while the thread's own process
    /// stays the calling process ([`current`]). The record outlives the scope: the caller holds a
    /// reference on the process, or builds it.
    pub fn attach(&self) -> crate::sched::attach::Attached {
        crate::sched::attach::attach(&self.sched)
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

/// Build a fresh process record at `process`: the address space at `dir_phys`, named `name`,
/// running as leg `leg` (none for a child), standing for process object `object`, field by field
/// (by value the record would pass the caller's stack).
///
/// # Safety
///
/// `process` is valid for writes, aligned, and the record's final address; its previous contents
/// are overwritten, not dropped.
#[cfg(target_arch = "x86")]
unsafe fn write_fresh(
    process: *mut Process,
    dir_phys: u32,
    name: ProcessName,
    leg: Option<u32>,
    object: crate::ob::ObjectId,
) {
    use core::ptr::addr_of_mut;
    // SAFETY: the caller's contract; every field is written before the record is read.
    unsafe {
        addr_of_mut!((*process).sched).write(crate::sched::process::SchedProcess::new(
            dir_phys,
            crate::sched::NORMAL_BASE,
        ));
        addr_of_mut!((*process).name).write(name);
        addr_of_mut!((*process).id).write(new_client_id());
        addr_of_mut!((*process).parent_id).write(0);
        addr_of_mut!((*process).leg).write(leg);
        addr_of_mut!((*process).object).write(object);
        addr_of_mut!((*process).priority_class).write(NORMAL_PRIORITY_CLASS);
        addr_of_mut!((*process).hard_error_mode).write(DEFAULT_HARD_ERROR_MODE);
        addr_of_mut!((*process).main_thread).write(None);
        addr_of_mut!((*process).ordinals).write(ordinals::Ordinals::empty());
        crate::mem::vm::AddressSpace::write_empty(addr_of_mut!((*process).vm));
        crate::sched::object::HandleTable::write_empty(addr_of_mut!((*process).handles));
        addr_of_mut!((*process).console).write(rtl::console::Handles::standard());
        addr_of_mut!((*process).win32k).write(None);
        objects::SyncObjects::write_empty(addr_of_mut!((*process).objects), object.index);
        addr_of_mut!((*process).end).write(None);
        addr_of_mut!((*process).handed_end).write(None);
        addr_of_mut!((*process).ending).write(false);
        addr_of_mut!((*process).torn_down).write(false);
    }
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
    process: &mut Process,
    read_entry: impl Fn(u32, usize) -> u32,
    mut release: impl FnMut(u32),
) {
    assert_eq!(
        process.sched.stack_count(),
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
    let end = process.end.expect("an ended process recorded its end");
    let leg = process.leg;
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
fn teardown(process: &'static mut Process, quiescent: bool) {
    let end = process.end.expect("a torn-down process has ended");
    let object = crate::ob::directory()
        .process(process.object)
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
    release_address_space_of(process);
    audit_objects(process, quiescent);
    process.torn_down = true;
    release_record(process);
}

/// Step 4: the address space goes — every frame the process owns, per thread then per process: the
/// parked gate stack first (the last exit's, or a later exit's in another process: whichever is
/// parked, its owner off it for good, since this runs on the idle thread's boot stack), then the
/// address space (see [`release_process`]). The process is
/// torn down in place: its record holds absolute addresses into itself.
#[cfg(target_arch = "x86")]
fn release_address_space_of(process: &mut Process) {
    use crate::mem::frame::FrameState;
    use crate::mem::paging::{self, PAGE_SIZE};
    // The views go first, each dropping its reference on its section or image segment (one nothing
    // else references goes with it, dropping its hold on its frames).
    let directory = crate::ob::directory();
    let mut gone = [None; crate::mem::vm::VIEWS];
    let mut count = 0;
    process.vm().drop_views(|mapping| {
        gone[count] = directory.release_mapping(mapping);
        count += 1;
    });
    for followup in gone[..count].iter().flatten() {
        process.finish(*followup);
    }
    crate::mem::kstacks::release_parked();
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
fn audit_objects(process: &mut Process, quiescent: bool) {
    let directory = crate::ob::directory();
    directory.process_ended(&process.sched);
    if !quiescent {
        return;
    }
    let leaked = directory.sweep(|followup| {
        if let crate::ob::Followup::Section { frames, .. } = followup {
            crate::nt::section::release_frames(frames);
        }
    }) + crate::fs::file::with_records(crate::fs::file::FileRecords::clear);
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
fn release_record(process: &mut Process) {
    let _ = crate::ob::directory().dereference(process.object);
}

/// A file-backed section, or an image segment, is gone: its file is mapped once less, and its
/// reference on the file object goes (the followup is the object's close, when that was its last
/// reference).
#[cfg(target_arch = "x86")]
fn unmap_file(file_object: crate::ob::ObjectId) -> Option<crate::ob::Followup> {
    let directory = crate::ob::directory();
    let record = directory.file(file_object)?.record;
    crate::fs::file::with_records(|records| records.get_mut(record).user_mapped -= 1);
    directory.dereference(file_object)
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
    use crate::sched::process::SchedProcess;
    use crate::sched::thread::{Thread, ThreadId, NO_GATE_SLOT};

    // --- The process record (the per-thread state split's shape) --------

    /// A process record as the tests build it: by value, at `dir`, standing for a made-up process
    /// object.
    fn record_at(dir: u32) -> Process {
        Process {
            sched: SchedProcess::new(dir, 8),
            name: ProcessName::new(b"fixture"),
            id: FIRST_CLIENT_ID,
            parent_id: 0,
            leg: None,
            object: crate::ob::ObjectId {
                kind: crate::ob::ObjectType::Process,
                index: 0,
                generation: 0,
            },
            priority_class: NORMAL_PRIORITY_CLASS,
            hard_error_mode: DEFAULT_HARD_ERROR_MODE,
            main_thread: None,
            ordinals: ordinals::Ordinals::empty(),
            vm: crate::mem::vm::AddressSpace::new(),
            handles: crate::sched::object::HandleTable::empty(),
            console: rtl::console::Handles::standard(),
            win32k: None,
            objects: objects::SyncObjects::empty(),
            end: None,
            handed_end: None,
            ending: false,
            torn_down: false,
        }
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

    /// A fresh record: no end under way, no main thread yet.
    #[test]
    fn a_fresh_process_is_not_ending() {
        let process = fresh_process();
        assert!(!process.terminating());
        assert!(!process.has_main_thread());
    }

    /// Client ids are NT's: never 0 or 4 (the System process), stepping by four, one space for
    /// processes and threads.
    #[test]
    fn client_ids_step_by_four_from_eight() {
        assert_eq!(FIRST_CLIENT_ID, 8);
        assert_eq!(CLIENT_ID_STEP, 4);
        assert_eq!(record_at(0x0090_0000).id(), FIRST_CLIENT_ID);
    }

    /// A fresh process: the scheduling record leads it (the directory base at the pinned offset);
    /// the process owns no gate stack of its own, its threads do.
    #[test]
    fn fresh_process_state_starts_clean() {
        let process = fresh_process();
        assert_eq!(process.name(), "fixture");
        assert_eq!(process.dir_phys(), 0x0090_0000);
        assert_eq!(process.sched.base_priority(), 8);
        assert_eq!(Thread::new(ThreadId(0)).gate_slot(), NO_GATE_SLOT);
        assert_eq!(process.handles().live(), 0);
    }

    /// The parts borrow apart: the address space and the handle table, all at once.
    #[test]
    fn the_parts_borrow_apart() {
        let mut process = fresh_process();
        let parts = process.parts_mut();
        let handle = parts.handles.insert(event_entry());
        assert!(parts.vm.region_at(0x0040_0000).is_none());
        assert_eq!(process.handles().lookup(handle), Some(event_entry()));
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
        let mut process = fresh_process();
        let handle = process.handles.insert(event_entry());
        process.handles.insert(event_entry());
        process.release_handles();
        assert_eq!(process.handles.live(), 0);
        assert!(process.handles().lookup(handle).is_none());
        assert!(!process.close_handle(handle), "closed already");
        assert_eq!(
            process.handles.insert(event_entry()),
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
        fn tear_down(&mut self, stacks: &mut KernelStacks, process: &mut Process) {
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
        &'static mut Process,
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
        let mut main = crate::sched::testkit::thread(&mut process.sched);
        let mut child = crate::sched::testkit::thread(&mut process.sched);
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
        assert_eq!(process.sched.stack_count(), 0);

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
        let mut other = crate::sched::testkit::thread(&mut other_process.sched);
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

    /// The walk's user range ends below the kernel stack region: the region's entries are in the
    /// shared kernel half, which the walk never reaches.
    #[test]
    fn the_kernel_stack_region_sits_in_the_kernel_half() {
        assert!(KERNEL_STACKS.first_entry() >= KERNEL_HALF_START);
        assert_eq!(KERNEL_STACKS.first_entry(), 656);
        assert_eq!(KERNEL_HALF_START, 512);
    }
}
