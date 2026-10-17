//! The process object: every piece of per-process state in one place.
//!
//! A process owns its page directory (created per process, sharing the kernel's kernel half) and
//! its user-heap bookkeeping ([`HeapState`]). The image, stack, TEB and parameters pages are mapped
//! fresh each run into the process's directory, so they are per-process by construction.
//!
//! The per-thread state split: the ring-0 gate stack (the thread's kernel stack, what the TSS
//! `esp0` points into) is per-thread, sub-allocated as slots of the process's window
//! ([`GateSlots`]), each slot's frames recorded by their owning thread. The scheduling record leads
//! the process at a pinned offset, so a thread's owner pointer resolves the directory base the
//! context switch loads.
//!
//! One process at a time: each runs on its threads until its last thread ends, and the idle
//! thread tears it down before the next is created. The one kernel static here is the
//! current-process pointer — the process-level analog of a scheduler's current pointer. It is
//! kernel state (like CR3 and the TSS), not per-process state; everything per-process lives inside
//! the [`Process`] it points at. No other kernel static holds per-process
//! state (the review enforceable form: `static mut` outside the boot/cpu structures names no
//! per-process user state).

/// The end of a thread and of its process, as decisions: the exit routing, the report lines,
/// the suite's leg order and tally.
pub mod exit;

/// The sequential multi-process suite runner (`run-process-suite`).
#[cfg(all(target_arch = "x86", feature = "run-process-suite"))]
pub mod runner;

/// The synchronization-object records beyond events: semaphores, mutexes, user APCs, names.
pub mod objects;

/// The smoke-subset thread surface: child-thread creation, the object pools, the thread-exit path.
#[cfg(target_arch = "x86")]
pub mod threads;

#[cfg(target_arch = "x86")]
use crate::mem::paging;

/// A process: one address space, one gate-stack window, one heap.
#[repr(C)]
pub struct Process {
    /// The scheduling record, leading the process record: the context switch's assembly reads the
    /// directory base through a thread's owner pointer at a pinned offset.
    pub sched: crate::sched::process::SchedProcess,
    /// The fixture's name, as invoked (reported on COM1).
    name: &'static str,
    /// The process's client id (what GetCurrentProcessId reports).
    id: u32,
    /// The priority class SetPriorityClass last set (the documented class flag).
    priority_class: u32,
    /// The error mode SetErrorMode last set (the hard-error and fault dialogs it suppresses never
    /// exist here; the value is kept for its round trip).
    error_mode: u32,
    /// The TLS indexes TlsAlloc has handed out.
    tls_indexes: crate::user::tls::TlsIndexes,
    /// The image's implicit-TLS template, copied into every new thread's block (none without a TLS
    /// directory).
    tls_template: Option<crate::user::tls::Template>,
    /// The process's main thread: the thread the boot path enters ring 3 on. Its record owns its
    /// gate-stack slot's frames.
    main_thread: crate::sched::thread::Thread,
    /// The gate-stack window's slot occupancy (which threads own which slots).
    gate_slots: GateSlots,
    /// The user-heap bookkeeping (heap region + CRT region).
    heap: crate::user::userheap::HeapState,
    /// The handle table: the process's handles-to-objects.
    handles: crate::sched::object::HandleTable,
    /// The open files the table's file slots name.
    files: crate::fs::file::OpenFiles,
    /// An exited thread's gate stack, not yet released (see [`DeadStack`]).
    dead_stack: DeadStack,
    /// The created threads' records; a terminated child's record is reused once no handle names it.
    child_threads: [crate::sched::thread::Thread; CHILD_THREADS],
    /// The created events' records, reused once unreferenced.
    events: [crate::sched::event::Event; EVENTS],
    /// How many event records have ever been handed out (the pool's high-water mark).
    events_used: usize,
    /// The semaphores, mutexes, timers, user-APC records and object names, and the process's
    /// waitable.
    objects: objects::SyncObjects,
    /// The environment variables.
    environment: crate::compat::environment::Environment,
    /// Why the process ended, recorded by its last thread's exit; the idle thread's reap step
    /// tears down a process once this is set.
    end: Option<exit::ProcessEnd>,
    /// The end an exit or fault decided while some threads were still finishing a critical region:
    /// the last of them ends the process with it.
    handed_end: Option<exit::ProcessEnd>,
}

/// The default priority class (the documented NORMAL_PRIORITY_CLASS flag).
pub const NORMAL_PRIORITY_CLASS: u32 = 0x20;

/// How many threads a process can have alive besides its main thread. A terminated thread's record
/// is reused once no handle names it, so this bounds the live threads, not the threads created.
pub const CHILD_THREADS: usize = 64;

/// How many events a process can have at once. An event's record is reused once no handle names it
/// and no thread waits on it.
pub const EVENTS: usize = 256;

/// A fresh record set for [`Process::events`] (the tests build records by value).
#[cfg(test)]
const fn fresh_events() -> [crate::sched::event::Event; EVENTS] {
    use crate::sched::event::{Event, EventKind};
    [const { Event::new(EventKind::Notification, false) }; EVENTS]
}

/// One gate stack: its slot index and the frames mapped in it.
pub type GateStack = (u16, [u32; crate::mem::paging::GATE_STACK_PAGES]);

/// The process's exited-but-unreleased gate stack. A thread's exit runs on its own gate stack, so
/// it cannot unmap it: the exit parks it here, and code running on another stack releases it — the
/// next exit (which gets the earlier stack back from [`DeadStack::park`]), the next spawn, or the
/// teardown. At most one stack is ever parked: a park hands the previous one back.
pub struct DeadStack(Option<GateStack>);

impl DeadStack {
    /// Nothing parked.
    pub const fn empty() -> Self {
        DeadStack(None)
    }

    /// Park `stack` (the exiting thread's own) and return the previously parked one, which the
    /// caller can release: it is not the stack the caller runs on.
    pub fn park(&mut self, stack: GateStack) -> Option<GateStack> {
        self.0.replace(stack)
    }

    /// Take the parked stack for release, if any.
    pub fn take(&mut self) -> Option<GateStack> {
        self.0.take()
    }
}

// The scheduling record leads the process record: a thread's owner pointer and the process's
// directory base are one pinned chain.
const _: () = assert!(core::mem::offset_of!(Process, sched) == 0);

impl Process {
    /// The process's name.
    pub fn name(&self) -> &'static str {
        self.name
    }

    /// The process's client id.
    pub fn id(&self) -> u32 {
        self.id
    }

    /// The process's priority class (the documented class flag).
    pub fn priority_class(&self) -> u32 {
        self.priority_class
    }

    /// Record the process's priority class (the scheduling side is the caller's).
    pub fn set_priority_class(&mut self, class: u32) {
        self.priority_class = class;
    }

    /// The process's TLS indexes.
    pub fn tls_indexes_mut(&mut self) -> &mut crate::user::tls::TlsIndexes {
        &mut self.tls_indexes
    }

    /// The image's implicit-TLS template.
    pub fn tls_template(&self) -> Option<crate::user::tls::Template> {
        self.tls_template
    }

    /// Record the image's implicit-TLS template (the loader's, once).
    pub fn set_tls_template(&mut self, template: Option<crate::user::tls::Template>) {
        self.tls_template = template;
    }

    /// Set the process's error mode, returning the previous one.
    pub fn swap_error_mode(&mut self, mode: u32) -> u32 {
        core::mem::replace(&mut self.error_mode, mode)
    }

    /// The process's page-directory frame.
    pub fn dir_phys(&self) -> u32 {
        self.sched.dir_phys()
    }

    /// The process's main thread.
    pub fn main_thread(&self) -> &crate::sched::thread::Thread {
        &self.main_thread
    }

    /// Every thread that has a TEB, as (ordinal, TEB address): the main thread at ordinal 0, then
    /// the created threads (terminated ones too: their pages stay mapped until the record is
    /// reused).
    pub fn thread_tebs(&self) -> impl Iterator<Item = (u32, u32)> + '_ {
        core::iter::once((0, self.main_thread.teb_va()))
            .chain(
                self.child_threads
                    .iter()
                    .enumerate()
                    .map(|(index, thread)| (index as u32 + 1, thread.teb_va())),
            )
            .filter(|&(_, teb)| teb != 0)
    }

    /// The user-heap state (the kernel32 heap services are served from here).
    pub fn heap_mut(&mut self) -> &mut crate::user::userheap::HeapState {
        &mut self.heap
    }

    /// The handle table (the object services are served from here).
    pub fn handles_mut(&mut self) -> &mut crate::sched::object::HandleTable {
        &mut self.handles
    }

    /// The handle table and the synchronization-object records, together (a create consults the
    /// table while it takes a record).
    pub fn objects_mut(
        &mut self,
    ) -> (
        &mut crate::sched::object::HandleTable,
        &mut objects::SyncObjects,
    ) {
        (&mut self.handles, &mut self.objects)
    }

    /// The environment variables.
    pub fn environment_mut(&mut self) -> &mut crate::compat::environment::Environment {
        &mut self.environment
    }

    /// Open `file` (a file, not a directory) at its start and return its new handle; null when the
    /// open-file records or the handle table are full.
    pub fn open_file(&mut self, file: crate::fs::fat32::lookup::File) -> u32 {
        if self.handles.is_full() {
            return 0;
        }
        let Some(index) = self.files.open(file) else {
            return 0;
        };
        self.handles.insert(crate::sched::object::Slot::File(index))
    }

    /// The open file a handle names; none when it names no file.
    pub fn file_mut(&mut self, handle: u32) -> Option<&mut crate::fs::file::OpenFile> {
        match self.handles.lookup(handle)? {
            crate::sched::object::Slot::File(index) => Some(self.files.get_mut(index)),
            _ => None,
        }
    }

    /// Close a handle: the table's claim ends, and an open file's record is released with it.
    /// False when the handle names nothing.
    pub fn close_handle(&mut self, handle: u32) -> bool {
        match self.handles.close(handle) {
            Some(crate::sched::object::Slot::File(index)) => {
                self.files.release(index);
                true
            }
            Some(_) => true,
            None => false,
        }
    }

    /// Release every handle and open file at once: the process-exit step.
    pub fn release_handles(&mut self) {
        self.handles.clear();
        self.files.clear();
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
}

#[cfg(target_arch = "x86")]
impl Process {
    /// Create the process and make it current: a fresh address space with the record installed at
    /// its final address, then its main thread taking the window's lowest free gate-stack slot, the
    /// fixed TEB page, and the process's scheduling data. Every later user mapping lands in this
    /// process's directory. The record is reached through [`current_mut`] from then on: handing out
    /// a `&'static mut` here would alias every later `current_mut` borrow.
    pub fn start(name: &'static str) {
        let dir_phys = paging::create_address_space();
        paging::activate_address_space(dir_phys);

        install(dir_phys, name);
        let process = current_mut();

        // The scheduling record's thread-list sentinel closes now that the record is at its final
        // address.
        process.sched.init();

        // The main thread attaches to the process and takes the lowest free gate-stack slot.
        let sched = core::ptr::addr_of_mut!(process.sched);
        let thread = core::ptr::addr_of_mut!(process.main_thread);
        // SAFETY: the process record is installed at its final address; both pointers are into it.
        unsafe { (*thread).attach_to(&mut *sched) };
        let slot = process.gate_slots.allocate();
        // SAFETY: the slot pages map into the current address space, above the slot's unmapped
        // guard page.
        let frames = paging::map_gate_slot(slot as u32);
        // SAFETY: the main thread is not yet schedulable; nothing else reaches it.
        unsafe {
            (*thread).gate_slot = slot;
            (*thread).gate_frames = frames;
            (*thread).initial_stack = paging::gate_slot_top(slot as u32);
            (*thread).teb_va = crate::user::TEB_PAGE;
            (*thread).thread_id = new_client_id();
            (*thread).user_stack = crate::user::stack::UserStack::new(
                crate::user::USER_STACK_TOP,
                crate::user::USER_STACK_RESERVE,
                crate::user::USER_STACK_TOP - crate::user::USER_STACK_LOW_PAGE,
            );
        }
        // The TSS `esp0` is the switch's to install: the first switch into the main thread loads
        // its stack top.
    }
}

// --- The gate-stack slot ledger --------------------------------------------
//
// Per-thread slots: a guard page plus the four stack pages, lowest free index first. Occupancy only
// — each slot's frames are recorded by their owning thread, released exactly once.

/// How many occupancy words the ledger holds.
const SLOT_WORDS: usize = (crate::mem::paging::GATE_SLOT_CAPACITY + 63) / 64;

/// The gate-stack window's slot occupancy.
pub struct GateSlots {
    occupied: [u64; SLOT_WORDS],
}

impl GateSlots {
    /// An empty ledger: every slot free.
    pub const fn empty() -> Self {
        GateSlots {
            occupied: [0; SLOT_WORDS],
        }
    }

    /// Take the lowest free slot index. Panics past the window's capacity (an allocation overflow
    /// is a bug, not a wrap).
    pub fn allocate(&mut self) -> u16 {
        for (word_index, word) in self.occupied.iter_mut().enumerate() {
            if *word != u64::MAX {
                let bit = word.trailing_ones() as u16;
                let index = (word_index as u16) * 64 + bit;
                assert!(
                    (index as usize) < crate::mem::paging::GATE_SLOT_CAPACITY,
                    "gate-stack window exhausted ({} slots)",
                    crate::mem::paging::GATE_SLOT_CAPACITY
                );
                *word |= 1 << bit;
                return index;
            }
        }
        panic!("gate-stack window exhausted");
    }

    /// Free slot `index`. Panics on a double release (the frames would be released twice — the
    /// frame database's own discipline makes that a panic on target).
    pub fn release(&mut self, index: u16) {
        let bit = index % 64;
        let word = &mut self.occupied[(index / 64) as usize];
        assert!(
            *word & (1 << bit) != 0,
            "double release of gate slot {index}"
        );
        *word &= !(1 << bit);
    }

    /// Whether `index` is taken.
    pub fn is_taken(&self, index: u16) -> bool {
        let bit = index % 64;
        self.occupied[(index / 64) as usize] & (1 << bit) != 0
    }

    /// Whether every slot is free.
    pub fn is_empty(&self) -> bool {
        self.occupied.iter().all(|word| *word == 0)
    }
}

/// The next client id to hand out (see [`new_client_id`]).
#[cfg(target_arch = "x86")]
static mut NEXT_CLIENT_ID: u32 = FIRST_CLIENT_ID;

/// The first client id: NT never hands out 0 (no object) or 4 (the System process).
pub const FIRST_CLIENT_ID: u32 = 8;

/// The id after `id`: client ids step by four, as NT's (they are handle-table indices there).
pub const fn next_client_id(id: u32) -> u32 {
    id + 4
}

/// A fresh client id for a process or a thread: processes and threads share one id space, as on
/// NT, and an id is never reused within a boot (system state, not per-process state).
#[cfg(target_arch = "x86")]
pub fn new_client_id() -> u32 {
    // SAFETY: single CPU; ids are handed out from service and boot paths only, never from an
    // interrupt.
    unsafe {
        let next = &mut *core::ptr::addr_of_mut!(NEXT_CLIENT_ID);
        let id = *next;
        *next = next_client_id(id);
        id
    }
}

/// The current process. One at a time: installed at start, read by the service paths, and released
/// by the teardown once its last thread has ended. The record is built where it lives, field by
/// field: by value it would pass through the boot stack, which is smaller than the record.
#[cfg(target_arch = "x86")]
static mut CURRENT: core::mem::MaybeUninit<Process> = core::mem::MaybeUninit::uninit();

/// Whether [`CURRENT`] holds a process.
#[cfg(target_arch = "x86")]
static mut INSTALLED: bool = false;

// The record owns no resources of its own (its frames are released by the teardown walk), so
// releasing it is forgetting it.
#[cfg(target_arch = "x86")]
const _: () = assert!(!core::mem::needs_drop::<Process>());

/// Build a fresh process record in [`CURRENT`]: the address space at `dir_phys`, named `name`.
#[cfg(target_arch = "x86")]
fn install(dir_phys: u32, name: &'static str) {
    use core::ptr::addr_of_mut;
    // SAFETY: single CPU, interrupts disabled; no process is running when a new one starts (run to
    // completion, asserted). Every field is written before the record is read.
    unsafe {
        assert!(!INSTALLED, "a process is already running");
        let process = (*addr_of_mut!(CURRENT)).as_mut_ptr();
        addr_of_mut!((*process).sched).write(crate::sched::process::SchedProcess::new(
            dir_phys,
            crate::sched::NORMAL_BASE,
        ));
        addr_of_mut!((*process).name).write(name);
        addr_of_mut!((*process).id).write(new_client_id());
        addr_of_mut!((*process).priority_class).write(NORMAL_PRIORITY_CLASS);
        addr_of_mut!((*process).error_mode).write(0);
        addr_of_mut!((*process).tls_indexes).write(crate::user::tls::TlsIndexes::empty());
        addr_of_mut!((*process).tls_template).write(None);
        addr_of_mut!((*process).main_thread).write(crate::sched::thread::Thread::empty());
        addr_of_mut!((*process).gate_slots).write(GateSlots::empty());
        addr_of_mut!((*process).heap).write(crate::user::userheap::HeapState::new());
        crate::sched::object::HandleTable::write_empty(addr_of_mut!((*process).handles));
        addr_of_mut!((*process).files).write(crate::fs::file::OpenFiles::empty());
        addr_of_mut!((*process).dead_stack).write(DeadStack::empty());
        let threads = addr_of_mut!((*process).child_threads) as *mut crate::sched::thread::Thread;
        for index in 0..CHILD_THREADS {
            threads
                .add(index)
                .write(crate::sched::thread::Thread::empty());
        }
        let events = addr_of_mut!((*process).events) as *mut crate::sched::event::Event;
        for index in 0..EVENTS {
            events.add(index).write(crate::sched::event::Event::new(
                crate::sched::event::EventKind::Notification,
                false,
            ));
        }
        addr_of_mut!((*process).events_used).write(0);
        objects::SyncObjects::write_empty(addr_of_mut!((*process).objects));
        // All zeros is the empty store (written in place: by value it would pass the stack).
        addr_of_mut!((*process).environment).write_bytes(0, 1);
        addr_of_mut!((*process).end).write(None);
        addr_of_mut!((*process).handed_end).write(None);
        INSTALLED = true;
    }
}

/// The current process, mutably (the heap services reach it this way).
///
/// # Panics
///
/// No process is running.
#[cfg(target_arch = "x86")]
pub fn current_mut() -> &'static mut Process {
    // SAFETY: single-threaded kernel; the pointer is installed before ring 3 is entered and has no
    // other writer.
    unsafe {
        assert!(INSTALLED, "no process is running");
        (*core::ptr::addr_of_mut!(CURRENT)).assume_init_mut()
    }
}

/// The current process, immutably (reporting paths).
///
/// # Panics
///
/// No process is running.
#[cfg(target_arch = "x86")]
pub fn current() -> &'static Process {
    // SAFETY: as `current_mut`.
    unsafe {
        assert!(INSTALLED, "no process is running");
        (*core::ptr::addr_of!(CURRENT)).assume_init_ref()
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
/// present PTE's data frame in the user windows and their page tables, plus the gate window's
/// table. The gate slots' data frames are the threads' (released per thread, before this walk);
/// the shared kernel half is never touched, and the directory frame is the caller's, last.
pub fn release_address_space(
    dir_phys: u32,
    read_entry: impl Fn(u32, usize) -> u32,
    mut release: impl FnMut(u32),
) {
    use crate::mem::paging::{
        GATE_STACK_WINDOW, KERNEL_HALF_START, PAGE_ADDR_MASK, PAGE_PRESENT, PT_ENTRIES,
    };
    for window in 0..KERNEL_HALF_START {
        let pde = read_entry(dir_phys, window);
        if pde & PAGE_PRESENT == 0 {
            continue;
        }
        let table = pde & PAGE_ADDR_MASK;
        for index in 0..PT_ENTRIES {
            let pte = read_entry(table, index);
            if pte & PAGE_PRESENT != 0 {
                release(pte & PAGE_ADDR_MASK);
            }
        }
        release(table);
    }
    // The gate stack window (in the kernel half, per-process): its page-table frame is the
    // directory entry; the slot data frames belong to the threads (released through the thread
    // records).
    let pde = read_entry(dir_phys, (GATE_STACK_WINDOW >> 22) as usize);
    if pde & PAGE_PRESENT != 0 {
        release(pde & PAGE_ADDR_MASK);
    }
}

/// Release every frame a finished process owns, in the teardown's order: per-thread first, then
/// per-process. Every thread has ended by now and released its own gate stack from another stack —
/// except the last one, whose exit could only park it: its frames go first (the mapping goes with
/// the gate window's table). Then the address space, and the directory frame last of all.
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

    // Per thread: the last exit's parked stack.
    if let Some((_, frames)) = process.dead_stack.take() {
        for frame in frames {
            release(frame);
        }
    }

    // Per process: user data frames and their tables from the walk, the gate window's table from
    // its directory entry, then the directory itself.
    release_address_space(dir_phys, read_entry, &mut release);
    release(dir_phys);
}

/// Release the current process's record, for teardown. Call only when the kernel has switched off
/// the process's address space (its frames are then unreachable except through the scratch
/// window).
#[cfg(target_arch = "x86")]
fn release_current() {
    // SAFETY: single CPU; the teardown path is the only releaser, run once per process after the
    // address-space switch.
    unsafe {
        assert!(INSTALLED, "no process is running");
        INSTALLED = false;
    }
}

/// Whether the idle thread has a process to reap: the current process has ended (its last thread's
/// exit recorded why) and is not yet torn down.
#[cfg(target_arch = "x86")]
pub fn reap_pending() -> bool {
    // SAFETY: single CPU; a read of the current-process slot.
    unsafe {
        INSTALLED
            && (*core::ptr::addr_of!(CURRENT))
                .assume_init_ref()
                .end
                .is_some()
    }
}

/// The idle thread's reap step: tear the ended process down, then let the boot decide what
/// follows — a suite leg's audit and the next leg (or the summary), or, on a one-process boot,
/// nothing: the idle thread rests.
#[cfg(target_arch = "x86")]
pub fn reap() {
    let end = current().end.expect("reap of a process that has not ended");
    teardown_current();
    #[cfg(feature = "run-process-suite")]
    runner::process_reaped(end);
    #[cfg(not(feature = "run-process-suite"))]
    let _ = end;
    #[cfg(all(not(feature = "run-process-suite"), feature = "fault-test-exitio"))]
    crate::user::check_volume_after_teardown();
}

/// Tear the current process down: release every frame it owns, per thread then per process (see
/// [`release_process`]), and retire the current-process slot.
///
/// Must run on the boot address space — the walk reads the dead directory through the scratch
/// window, never through a mapping.
#[cfg(target_arch = "x86")]
fn teardown_current() {
    use crate::mem::frame::FrameState;
    use crate::mem::paging::{self, PAGE_SIZE};

    // The process is torn down in place: its record holds absolute addresses into itself, and
    // taking the slot would move it. The slot is retired only at the end.
    let process = current_mut();
    release_process(
        process,
        |frame, index| paging::read_frame_word(frame, index),
        |frame_phys| {
            crate::mem::bootmem::with_frame_db(|db| {
                db.release(frame_phys / PAGE_SIZE, FrameState::Free);
            });
        },
    );
    release_current();
}

/// The post-boot free-frame count: the baseline the per-process teardown audits compare against.
/// Recorded once the boot's own permanent allocations are done, before the first process starts.
#[cfg(all(target_arch = "x86", feature = "run-process-suite"))]
static mut BASELINE_FRAMES: u32 = 0;

/// Record the allocator baseline (`available()` at the call site).
#[cfg(all(target_arch = "x86", feature = "run-process-suite"))]
pub fn record_allocator_baseline() {
    // SAFETY: single CPU; written once at suite start before the first process, read by the
    // teardown audits.
    unsafe {
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!(BASELINE_FRAMES),
            crate::mem::bootmem::with_frame_db(|db| db.available()),
        );
    }
}

/// The zero-leak audit after a teardown: the frame database must audit clean and stand exactly at
/// the post-boot baseline, and the kernel heap must still audit clean (nothing per-process is
/// allocated from it). The error carries the frame database's available count.
#[cfg(all(target_arch = "x86", feature = "run-process-suite"))]
pub fn audit_allocators() -> Result<(), u32> {
    // SAFETY: recorded before the first process; read-only here.
    let baseline = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(BASELINE_FRAMES)) };
    let frames_ok =
        crate::mem::bootmem::with_frame_db(|db| db.audit().is_ok() && db.available() == baseline);
    let heap_ok = crate::mem::bootmem::with_heap(|heap| heap.audit().is_ok());
    if frames_ok && heap_ok {
        Ok(())
    } else {
        Err(crate::mem::bootmem::with_frame_db(|db| db.available()))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::mem::paging::{
        gate_slot_base, gate_slot_top, GATE_SLOT_CAPACITY, GATE_SLOT_STRIDE, GATE_STACK_TOP,
        GATE_STACK_WINDOW, KERNEL_HALF_START, PAGE_PRESENT, PT_ENTRIES,
    };
    use crate::sched::process::SchedProcess;
    use crate::sched::thread::{Thread, NO_GATE_SLOT};
    use crate::user::userheap::HeapState;

    // --- The process record (the per-thread state split's shape) --------

    /// A fresh process: the scheduling record leads it (the directory base at the pinned offset),
    /// the main thread starts detached with no slot, and the ledger is empty — the process owns no
    /// gate stack of its own anymore; its threads do.
    #[test]
    fn fresh_process_state_starts_clean() {
        let mut process = Process {
            sched: SchedProcess::new(0x0090_0000, 8),
            name: "fixture",
            id: FIRST_CLIENT_ID,
            priority_class: NORMAL_PRIORITY_CLASS,
            error_mode: 0,
            tls_indexes: crate::user::tls::TlsIndexes::empty(),
            tls_template: None,
            main_thread: Thread::empty(),
            gate_slots: GateSlots::empty(),
            heap: HeapState::new(),
            handles: crate::sched::object::HandleTable::empty(),
            files: crate::fs::file::OpenFiles::empty(),
            dead_stack: DeadStack::empty(),
            child_threads: [const { crate::sched::thread::Thread::empty() }; CHILD_THREADS],
            events: fresh_events(),
            events_used: 0,
            objects: objects::SyncObjects::empty(),
            environment: crate::compat::environment::Environment::empty(),
            end: None,
            handed_end: None,
        };
        assert_eq!(process.name(), "fixture");
        assert_eq!(process.dir_phys(), 0x0090_0000);
        assert_eq!(process.sched.base_priority(), 8);
        assert_eq!(process.main_thread().gate_slot(), NO_GATE_SLOT);
        assert!(process.gate_slots.is_empty());

        // The heap state a service would see: creating the heap reports the handle and resets
        // nothing that exists.
        assert_eq!(
            process.heap_mut().create(),
            crate::user::userheap::HEAP_HANDLE
        );
    }

    fn fresh_process() -> Process {
        Process {
            sched: SchedProcess::new(0x0090_0000, 8),
            name: "fixture",
            id: FIRST_CLIENT_ID,
            priority_class: NORMAL_PRIORITY_CLASS,
            error_mode: 0,
            tls_indexes: crate::user::tls::TlsIndexes::empty(),
            tls_template: None,
            main_thread: Thread::empty(),
            gate_slots: GateSlots::empty(),
            heap: HeapState::new(),
            handles: crate::sched::object::HandleTable::empty(),
            files: crate::fs::file::OpenFiles::empty(),
            dead_stack: DeadStack::empty(),
            child_threads: [const { crate::sched::thread::Thread::empty() }; CHILD_THREADS],
            events: fresh_events(),
            events_used: 0,
            objects: objects::SyncObjects::empty(),
            environment: crate::compat::environment::Environment::empty(),
            end: None,
            handed_end: None,
        }
    }

    fn a_file(size: u32) -> crate::fs::fat32::lookup::File {
        crate::fs::fat32::lookup::File {
            first_cluster: 3,
            size,
            directory: false,
        }
    }

    // --- File handles (the table's file slots and the open-file records) -----

    /// An open file is a table handle naming a record: found by its handle with its own position,
    /// released by the close (record and slot together), and a handle that names another kind of
    /// object, or nothing, names no file.
    #[test]
    fn file_handles_open_look_up_and_close() {
        let mut process = fresh_process();
        let first = process.open_file(a_file(100));
        let second = process.open_file(a_file(200));
        assert_eq!((first, second), (4, 8));
        process.file_mut(first).unwrap().position = 60;
        assert_eq!(process.file_mut(second).unwrap().position, 0);
        assert_eq!(process.file_mut(second).unwrap().file.size, 200);
        assert_eq!(process.file_mut(first | 0x3).unwrap().position, 60);

        assert!(process.close_handle(first));
        assert!(process.file_mut(first).is_none());
        assert!(!process.close_handle(first), "a double close");
        assert_eq!(process.files.live(), 1);

        // The freed slot and record come back for the next open, at position zero.
        assert_eq!(process.open_file(a_file(300)), first);
        assert_eq!(process.file_mut(first).unwrap().position, 0);
        assert_eq!(process.file_mut(first).unwrap().file.size, 300);

        // An event's handle names no file.
        let event = Box::leak(Box::new(crate::sched::event::Event::new(
            crate::sched::event::EventKind::Notification,
            false,
        )));
        let handle = process
            .handles
            .insert(crate::sched::object::Slot::Event(event.waitable()));
        assert!(process.file_mut(handle).is_none());
        assert!(process.file_mut(0x40).is_none());
        assert!(process.close_handle(handle));
        assert_eq!(process.files.live(), 2, "closing an event leaves the files");
    }

    /// The opens stop when the records run out, and when the table does — a refused open takes
    /// nothing.
    #[test]
    fn file_opens_stop_at_either_limit() {
        let mut process = fresh_process();
        for _ in 0..crate::fs::file::OPEN_FILES {
            assert_ne!(process.open_file(a_file(1)), 0);
        }
        assert_eq!(process.open_file(a_file(1)), 0, "the records are full");
        assert_eq!(process.handles.live(), crate::fs::file::OPEN_FILES);

        let mut crowded = fresh_process();
        let event = Box::leak(Box::new(crate::sched::event::Event::new(
            crate::sched::event::EventKind::Notification,
            false,
        )));
        while !crowded.handles.is_full() {
            crowded
                .handles
                .insert(crate::sched::object::Slot::Event(event.waitable()));
        }
        assert_eq!(crowded.open_file(a_file(1)), 0, "the table is full");
        assert_eq!(crowded.files.live(), 0, "no record taken");
    }

    /// The process-exit step releases every file handle and record at once.
    #[test]
    fn the_exit_step_releases_open_files() {
        let mut process = fresh_process();
        let handle = process.open_file(a_file(10));
        process.open_file(a_file(20));
        process.release_handles();
        assert_eq!(process.handles.live(), 0);
        assert_eq!(process.files.live(), 0);
        assert!(process.file_mut(handle).is_none());
        assert_eq!(process.open_file(a_file(30)), 4, "the table starts over");
    }

    // --- The dead-stack handoff (slot reuse after a thread exit) -----------

    /// An exit parks its own stack and hands back the one parked before it; a spawn takes whatever
    /// is parked. At most one stack waits at any time.
    #[test]
    fn the_dead_stack_parks_one_and_hands_back_the_previous() {
        let mut dead = DeadStack::empty();
        assert_eq!(dead.take(), None);
        assert_eq!(dead.park((1, [10, 11, 12, 13])), None);
        assert_eq!(
            dead.park((2, [20, 21, 22, 23])),
            Some((1, [10, 11, 12, 13]))
        );
        assert_eq!(dead.take(), Some((2, [20, 21, 22, 23])));
        assert_eq!(dead.take(), None);
    }

    /// The exit-then-spawn sequence of sequential create/wait/close rounds (the threads fixture's): a child's slot stays taken while
    /// its stack is parked (its pages are still mapped), and the next spawn's release frees it
    /// before the allocation, so the child after it gets the same slot back — unmapped first,
    /// never double-mapped.
    #[test]
    fn a_spawn_after_an_exit_reuses_the_released_slot() {
        let mut ledger = GateSlots::empty();
        let mut dead = DeadStack::empty();
        let main = ledger.allocate();
        let first = ledger.allocate();
        assert_eq!((main, first), (0, 1));

        // The child exits: its stack is parked, its slot still taken.
        assert_eq!(dead.park((first, [1, 2, 3, 4])), None);
        assert!(ledger.is_taken(first));

        // The next spawn releases the parked stack before it allocates.
        let (slot, _) = dead.take().expect("the exited child's stack is parked");
        ledger.release(slot);
        assert_eq!(ledger.allocate(), first);
        assert_eq!(dead.take(), None);
    }

    // --- The gate-slot ledger (B1/B2) --------------------------------------

    /// The ledger hands out the lowest free index; slot 0's top is the stack every boot has
    /// installed (the loader contract survives as the main thread's esp0), and two threads never
    /// share a slot.
    #[test]
    fn the_ledger_hands_out_distinct_slots() {
        let mut ledger = GateSlots::empty();
        let s0 = ledger.allocate();
        let s1 = ledger.allocate();
        assert_eq!((s0, s1), (0, 1));
        assert!(ledger.is_taken(0) && ledger.is_taken(1));
        assert!(!ledger.is_taken(2));

        // Two threads of one process share the window but never a slot: distinct bases, distinct
        // tops, disjoint frames.
        assert_eq!(gate_slot_base(0), GATE_STACK_WINDOW);
        assert_eq!(gate_slot_base(1), GATE_STACK_WINDOW + GATE_SLOT_STRIDE);
        assert_eq!(gate_slot_top(0), GATE_STACK_TOP);
        assert_eq!(gate_slot_top(1), gate_slot_base(1) + GATE_SLOT_STRIDE);
        // The stride: one guard page plus the four stack pages.
        assert_eq!(GATE_SLOT_STRIDE, 5 * 4096);
        // Capacity: the window is one directory entry (4 MiB); an allocation past capacity is an
        // assert, not a wrap.
        assert_eq!(GATE_SLOT_CAPACITY, 204);
        assert_eq!(
            (gate_slot_top(203) - GATE_STACK_WINDOW) / GATE_SLOT_STRIDE,
            204
        );
    }

    /// Slot release and reuse: a released index is free, the next allocation takes the lowest free
    /// index again, and a double release is refused.
    #[test]
    fn slot_release_reuses_the_lowest_free_index() {
        let mut ledger = GateSlots::empty();
        for _ in 0..3 {
            ledger.allocate();
        }
        ledger.release(1);
        assert!(!ledger.is_taken(1));
        assert_eq!(ledger.allocate(), 1);
        assert_eq!(ledger.allocate(), 3);

        // A double release is a bug: the frames would be released twice.
        ledger.release(3);
        let refused = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| ledger.release(3)));
        assert!(refused.is_err());
    }

    // --- Teardown accounting (B5) ------------------------------------------
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

        /// Run the real teardown collection over the fake memory, in its order.
        fn release(&mut self, process: &mut Process) {
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
    const MAIN_STACK: [u32; 4] = [0x00F1_0000, 0x00F2_0000, 0x00F3_0000, 0x00F4_0000];
    const CHILD_STACK: [u32; 4] = [0x00F5_0000, 0x00F6_0000, 0x00F7_0000, 0x00F8_0000];

    /// A planted directory — two user tables' worth (a TEB page and an image page) and the gate
    /// window's table — and a process whose main thread owns slot 0 and whose child owns slot 1,
    /// both attached.
    fn planted_process(dir: u32) -> (FakeMemory, &'static mut Process, &'static mut Thread) {
        let mut mem = FakeMemory::new();
        let user_table = 0x00A0_0000;
        let gate_table = 0x00C0_0000;
        mem.plant(
            dir,
            &[
                (1, user_table | PAGE_PRESENT),
                (
                    (GATE_STACK_WINDOW >> 22) as usize,
                    gate_table | PAGE_PRESENT,
                ),
                // The shared kernel half: present entries that must not be walked or released.
                (KERNEL_HALF_START, 0x0010_0000 | PAGE_PRESENT),
                (KERNEL_HALF_START + 1, dir | PAGE_PRESENT), // self-map
            ],
        );
        // The TEB pages (user half: the walk owns them, so the thread records must not hold them)
        // and one image page.
        mem.plant(user_table, &[(0, 0x00E0_0000 | PAGE_PRESENT)]);
        mem.plant(gate_table, &[]);

        // Boxed to its final address before anything links into it: the thread list's entries are
        // absolute addresses, so the record must never move once attached.
        let process = Box::leak(Box::new(Process {
            sched: SchedProcess::new(dir, 8),
            name: "fixture",
            id: FIRST_CLIENT_ID,
            priority_class: NORMAL_PRIORITY_CLASS,
            error_mode: 0,
            tls_indexes: crate::user::tls::TlsIndexes::empty(),
            tls_template: None,
            main_thread: Thread::empty(),
            gate_slots: GateSlots::empty(),
            heap: HeapState::new(),
            handles: crate::sched::object::HandleTable::empty(),
            files: crate::fs::file::OpenFiles::empty(),
            dead_stack: DeadStack::empty(),
            child_threads: [const { crate::sched::thread::Thread::empty() }; CHILD_THREADS],
            events: fresh_events(),
            events_used: 0,
            objects: objects::SyncObjects::empty(),
            environment: crate::compat::environment::Environment::empty(),
            end: None,
            handed_end: None,
        }));
        process.sched.init();
        let sched = core::ptr::addr_of_mut!(process.sched);
        let child = Box::leak(Box::new(Thread::empty()));
        // SAFETY: the process record and the child are at their final addresses.
        unsafe {
            let main = &mut *core::ptr::addr_of_mut!(process.main_thread);
            main.attach_to(&mut *sched);
            main.gate_slot = process.gate_slots.allocate();
            main.gate_frames = MAIN_STACK;
            child.attach_to(&mut *sched);
            child.gate_slot = process.gate_slots.allocate();
            child.gate_frames = CHILD_STACK;
        }
        (mem, process, child)
    }

    /// Run `thread`'s exit as the exit path does, on a host dispatcher: park its own stack and
    /// release whatever an earlier exit parked (returned, for the caller to account), then the
    /// scheduler's termination.
    fn exit(process: &mut Process, thread: &mut Thread) -> Option<GateStack> {
        let released = process
            .dead_stack
            .park((thread.gate_slot, thread.gate_frames));
        let dispatcher = Box::leak(Box::new(crate::sched::dispatcher::Dispatcher::zeroed()));
        dispatcher.init();
        dispatcher.enter(thread);
        dispatcher.terminate();
        released
    }

    /// Teardown after every thread has exited releases exactly the process's own frames, each
    /// exactly once: the last exit's parked stack, the walked user data frames and tables, the
    /// gate window's table, and the directory — nothing from the shared kernel half. An earlier
    /// exit's stack is not teardown's: the next exit released it. A thread's TEB page is released
    /// once, by the walk (the thread records never hold user-half frames).
    #[test]
    fn teardown_releases_exactly_the_process_frames() {
        let dir = 0x0090_0000;
        let (mut mem, process, child) = planted_process(dir);
        // The child exits first, then the main thread — whose exit hands back the child's stack
        // for release from its own.
        assert_eq!(exit(process, child), None);
        let main = core::ptr::addr_of_mut!(process.main_thread);
        // SAFETY: the main thread lives inside the leaked process record.
        assert_eq!(exit(process, unsafe { &mut *main }), Some((1, CHILD_STACK)));
        assert_eq!(process.sched.stack_count(), 0);

        mem.release(process);

        let mut released = mem.released.clone();
        released.sort_unstable();
        let mut expected = vec![
            0x00A0_0000, // the user table
            0x00C0_0000, // the gate window's table
            0x00E0_0000, // the TEB/image data page
            dir,         // the directory
        ];
        expected.extend_from_slice(&MAIN_STACK);
        expected.sort_unstable();
        assert_eq!(released, expected);
        // Exactly once each, always.
        for frame in expected {
            assert_eq!(mem.count(frame), 1, "frame {frame:#x}");
        }
        // The child's stack was the main thread's exit to release; the kernel half's targets stay.
        for frame in CHILD_STACK {
            assert_eq!(mem.count(frame), 0);
        }
        assert_eq!(mem.count(0x0010_0000), 0);
        assert_eq!(process.dead_stack.take(), None);
    }

    /// The teardown's order: per thread first (the parked stack), then per process (the
    /// address-space walk), the directory frame last of all.
    #[test]
    fn teardown_releases_per_thread_then_per_process() {
        let dir = 0x0090_0000;
        let (mut mem, process, child) = planted_process(dir);
        exit(process, child);
        let main = core::ptr::addr_of_mut!(process.main_thread);
        // SAFETY: the main thread lives inside the leaked process record.
        exit(process, unsafe { &mut *main });

        mem.release(process);
        let released = &mem.released;
        assert_eq!(&released[..4], &MAIN_STACK, "the parked stack first");
        assert_eq!(released.last(), Some(&dir), "the directory last");
        assert_eq!(released.len(), 4 + 3 + 1);
    }

    /// Teardown never precedes the last thread's end: a process with a thread still attached is
    /// refused.
    #[test]
    #[should_panic(expected = "teardown of a process with attached threads")]
    fn teardown_refuses_a_process_with_attached_threads() {
        let dir = 0x0090_0000;
        let (mut mem, process, child) = planted_process(dir);
        exit(process, child);
        mem.release(process);
    }

    /// The walk's user range ends below the gate window: the window is a kernel-half entry whose
    /// table the walk releases from the directory entry, never by scanning.
    #[test]
    fn the_gate_window_sits_in_the_kernel_half() {
        assert!((GATE_STACK_WINDOW >> 22) as usize >= KERNEL_HALF_START);
        assert_eq!((GATE_STACK_WINDOW >> 22) as usize, 514);
        assert_eq!(KERNEL_HALF_START, 512);
    }
}
