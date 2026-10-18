//! The process object: every piece of per-process state in one place.
//!
//! A process owns its page directory (created per process, sharing the kernel's kernel half), its
//! address space's regions ([`crate::mem::vm::AddressSpace`], the only writer of its user entries)
//! and its user-heap bookkeeping ([`HeapState`]). The image, stack, TEB and parameters pages are
//! mapped fresh each run into the process's directory, each inside a region the loader seeds first,
//! so they are per-process by construction.
//!
//! The per-thread state split: the ring-0 gate stack (the thread's kernel stack, what the TSS
//! `esp0` points into) is per-thread, sub-allocated as slots of the process's window
//! ([`GateSlots`]), each slot's frames recorded by their owning thread. The thread records
//! themselves are the object manager's ([`crate::ob`]). The scheduling record leads the process at
//! a pinned offset, so a thread's owner pointer resolves the directory base the context switch
//! loads.
//!
//! One process at a time: each runs on its threads until its last thread ends, and the idle
//! thread tears it down before the next is created.
//!
//! The end of a process, in the platform's order:
//!
//! 1. every other thread is terminated, without running again (the exit service's and a fault's
//!    end; a thread inside a critical region finishes it first);
//! 2. every handle closes, as CloseHandle would — the objects go with their last references;
//! 3. the address space goes: every frame;
//! 4. the process object signals with the exit code;
//! 5. the record is freed with the object's last reference.
//!
//! Steps 1 and 2 run on the last thread, in [`threads`]; 3 to 5 on the idle thread's reap, in
//! [`reap`], with the object audit between 3 and 4 and the teardown audit line after 5.
//!
//! The records live in the process pool ([`pool`]), which also answers which process is current:
//! kernel state (like CR3 and the TSS), not per-process state. Everything per-process lives inside
//! the [`Process`] record; no other kernel static holds per-process user state.

/// The end of a thread and of its process, as decisions: the exit routing, the report lines,
/// the suite's leg order and tally.
pub mod exit;

/// The sequential multi-process suite runner (`run-process-suite`).
#[cfg(all(target_arch = "x86", feature = "run-process-suite"))]
pub mod runner;

/// The process pool and the current process.
pub mod pool;

pub use pool::MAX_PROCESSES;
#[cfg(target_arch = "x86")]
pub use pool::{current, current_mut, reap_pending};

/// The smoke-subset thread surface: child-thread creation, the thread records, the thread-exit
/// path.
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
    /// The process's client id (what GetCurrentProcessId reports, through the TEB).
    id: u32,
    /// The process's object: what a handle to the process names and a wait on it waits for. It
    /// holds the process's own reference until the teardown's end, and its index is the record's in
    /// the pool.
    object: crate::ob::ObjectId,
    /// The gate-stack window's slot occupancy (which threads own which slots).
    gate_slots: GateSlots,
    /// The user-heap bookkeeping (heap region + CRT region).
    heap: crate::user::userheap::HeapState,
    /// The address space's regions: every user page the process holds lies in one, and every
    /// mapping, commit and release of its pages goes through it.
    vm: crate::mem::vm::AddressSpace,
    /// The handle table: the process's handles-to-objects.
    handles: crate::sched::object::HandleTable,
    /// The open files the table's file entries name.
    files: crate::fs::file::OpenFiles,
    /// The process's console handles: the console server's own, outside the handle table, as
    /// Windows 2000's csrss keeps them (see `crate::csr`).
    console: rtl::console::Handles,
    /// An exited thread's gate stack, not yet released (see [`DeadStack`]).
    dead_stack: DeadStack,
    /// Why the process ended, recorded by its last thread's exit; the idle thread's reap step
    /// tears down a process once this is set.
    end: Option<exit::ProcessEnd>,
    /// The end an exit or fault decided while some threads were still finishing a critical region:
    /// the last of them ends the process with it.
    handed_end: Option<exit::ProcessEnd>,
    /// Whether the teardown has run (the record waits for its object's last reference).
    torn_down: bool,
}

/// A process record's parts, borrowed apart (see [`Process::parts_mut`]).
pub struct ProcessParts<'a> {
    /// The address space's regions.
    pub vm: &'a mut crate::mem::vm::AddressSpace,
    /// The user-heap bookkeeping.
    pub heap: &'a mut crate::user::userheap::HeapState,
    /// The handle table.
    pub handles: &'a mut crate::sched::object::HandleTable,
    /// The open files the table's file entries name.
    pub files: &'a mut crate::fs::file::OpenFiles,
    /// The gate-stack window's slot occupancy.
    pub gate_slots: &'a mut GateSlots,
    /// An exited thread's gate stack, not yet released.
    pub dead_stack: &'a mut DeadStack,
}

/// How many threads a process can have alive besides its main thread. A terminated thread's record
/// is reused once nothing references its object, so this bounds the live threads, not the threads
/// created.
pub const CHILD_THREADS: usize = 3;

/// The main thread's record in the object manager's thread pool (created threads take the records
/// after it; a record's index is its thread's ordinal).
pub const MAIN_THREAD: u16 = 0;

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

    /// The process's object.
    pub fn object(&self) -> crate::ob::ObjectId {
        self.object
    }

    /// The console handles (the console server serves them).
    pub fn console_mut(&mut self) -> &mut rtl::console::Handles {
        &mut self.console
    }

    /// The process's page-directory frame.
    pub fn dir_phys(&self) -> u32 {
        self.sched.dir_phys()
    }

    /// The record's parts, borrowed apart: what a service needs several of at once (the heap and
    /// the address space its pages are committed in, say) without re-borrowing the whole record.
    pub fn parts_mut(&mut self) -> ProcessParts<'_> {
        ProcessParts {
            vm: &mut self.vm,
            heap: &mut self.heap,
            handles: &mut self.handles,
            files: &mut self.files,
            gate_slots: &mut self.gate_slots,
            dead_stack: &mut self.dead_stack,
        }
    }

    /// The user-heap state (the kernel32 heap services are served from here).
    pub fn heap_mut(&mut self) -> &mut crate::user::userheap::HeapState {
        &mut self.heap
    }

    /// The address space (every user mapping goes through it).
    pub fn vm(&mut self) -> &mut crate::mem::vm::AddressSpace {
        &mut self.vm
    }

    /// The handle table, for lookups.
    pub fn handles(&self) -> &crate::sched::object::HandleTable {
        &self.handles
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
        self.handles.insert(crate::ob::Entry {
            target: crate::ob::Target::File(index),
            access: crate::ob::FILE_GENERIC_READ,
            inherit: false,
        })
    }

    /// The open file a handle names; none when it names no file.
    pub fn file_mut(&mut self, handle: u32) -> Option<&mut crate::fs::file::OpenFile> {
        match self.handles.lookup(handle)?.target {
            crate::ob::Target::File(index) => Some(self.files.get_mut(index)),
            crate::ob::Target::Object(_) => None,
        }
    }

    /// Close a handle: the table's claim ends — an object's handle, with its reference (the last
    /// reference deletes the object); an open file's record with it. False when the handle names
    /// nothing.
    pub fn close_handle(&mut self, handle: u32) -> bool {
        let Some(entry) = self.handles.close(handle) else {
            return false;
        };
        self.release_entry(entry);
        true
    }

    /// Release what one closed handle named.
    fn release_entry(&mut self, entry: crate::ob::Entry) {
        match entry.target {
            crate::ob::Target::File(index) => self.files.release(index),
            #[cfg(target_arch = "x86")]
            crate::ob::Target::Object(id) => crate::ob::directory().handle_closed(
                id,
                crate::sched::idle::dispatcher(),
                |followup| self.finish(followup),
            ),
            #[cfg(not(target_arch = "x86"))]
            crate::ob::Target::Object(_) => {}
        }
    }

    /// Finish what the object manager left to the process when one of its objects' last handle or
    /// last reference went (no kind leaves anything yet: see [`crate::ob::Followup`]).
    pub fn finish(&mut self, followup: crate::ob::Followup) {
        match followup {}
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
}

#[cfg(target_arch = "x86")]
impl Process {
    /// Create the process and make it current: a fresh address space with the record built at its
    /// final address in the pool, then its main thread taking the window's lowest free gate-stack
    /// slot, the fixed TEB page, and the process's scheduling data. Every later user mapping lands
    /// in this process's directory, inside one of its regions. Returns the record for the caller's
    /// setup (the loader's), which threads it through rather than reaching for the current process
    /// again.
    // The record is the pool's, not borrowed from `name` (see `pool::create`).
    #[allow(clippy::mut_from_ref)]
    pub fn start(name: &'static str) -> &'static mut Process {
        let dir_phys = paging::create_address_space();
        paging::activate_address_space(dir_phys);

        let process = pool::create(dir_phys, name);

        // The scheduling record's thread-list sentinel closes now that the record is at its final
        // address.
        process.sched.init();

        // The main thread: its object holds the thread's own reference while it runs (released at
        // its end), on the main thread's record. It attaches to the process and takes the lowest
        // free gate-stack slot.
        let directory = crate::ob::directory();
        let id = directory
            .create_thread_in(MAIN_THREAD as usize..MAIN_THREAD as usize + 1)
            .expect("the main thread's record is free when a process starts");
        let thread: *mut crate::sched::thread::Thread = directory.threads.record(id.index);
        // SAFETY: the record is the pool's (static, its final address) and nothing else reaches it.
        unsafe { *thread = crate::sched::thread::Thread::empty() };
        let sched = core::ptr::addr_of_mut!(process.sched);
        // SAFETY: the process record is installed at its final address, and so is the thread
        // record.
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
        }
        // The TSS `esp0` is the switch's to install: the first switch into the main thread loads
        // its stack top.
        process
    }

    /// The process's main thread: its record in the object manager's thread pool.
    pub fn main_thread(&self) -> &'static mut crate::sched::thread::Thread {
        crate::ob::directory().threads.record(MAIN_THREAD)
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

/// The id after `id`: client ids step by four, as the platform's do (handle-table indices
/// there).
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

/// Build a fresh process record at `process`: the address space at `dir_phys`, named `name`,
/// standing for process object `object`, field by field (by value the record would pass the
/// caller's stack).
///
/// # Safety
///
/// `process` is valid for writes, aligned, and the record's final address; its previous contents
/// are overwritten, not dropped.
#[cfg(target_arch = "x86")]
unsafe fn write_fresh(
    process: *mut Process,
    dir_phys: u32,
    name: &'static str,
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
        addr_of_mut!((*process).object).write(object);
        addr_of_mut!((*process).gate_slots).write(GateSlots::empty());
        addr_of_mut!((*process).heap).write(crate::user::userheap::HeapState::new());
        crate::mem::vm::AddressSpace::write_empty(addr_of_mut!((*process).vm));
        crate::sched::object::HandleTable::write_empty(addr_of_mut!((*process).handles));
        addr_of_mut!((*process).files).write(crate::fs::file::OpenFiles::empty());
        addr_of_mut!((*process).console).write(rtl::console::Handles::standard());
        addr_of_mut!((*process).dead_stack).write(DeadStack::empty());
        addr_of_mut!((*process).end).write(None);
        addr_of_mut!((*process).handed_end).write(None);
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
/// no-access or guard page still names its frame) — and their page tables, plus the gate
/// window's table. The gate slots' data frames are the threads' (released per thread, before this walk);
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
            if crate::mem::vm::names_frame(pte) {
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

/// The idle thread's reap step: tear the ended process down, then let the boot decide what
/// follows — a suite leg's audit and the next leg (or the summary), or, on a one-process boot, the
/// teardown audit line, after which the idle thread rests.
#[cfg(target_arch = "x86")]
pub fn reap() {
    let process = pool::ended().expect("reap with no ended process");
    let end = process.end.expect("an ended process recorded its end");
    teardown(process);
    #[cfg(feature = "run-process-suite")]
    runner::process_reaped(end);
    #[cfg(not(feature = "run-process-suite"))]
    {
        let _ = end;
        crate::serial_println!(
            "{}",
            exit::AuditReport {
                index: None,
                audit: audit_allocators()
            }
        );
    }
    #[cfg(all(not(feature = "run-process-suite"), feature = "fault-test-exitio"))]
    crate::user::check_volume_after_teardown();
}

/// Tear the ended `process` down, steps 3 to 5 of its end (see the module notes): its address
/// space goes, its object signals, and its own reference on the object goes (the record is free for
/// the next process once nothing else references the object). Between the address space and the
/// signal, the object audit: with every handle closed and every thread ended, no object of the
/// process may be left.
///
/// Must run on the boot address space — the walk reads the dead directory through the scratch
/// window, never through a mapping.
#[cfg(target_arch = "x86")]
fn teardown(process: &'static mut Process) {
    let end = process.end.expect("a torn-down process has ended");
    release_address_space_of(process);
    audit_objects(process);
    signal_end(process, end);
    release_record(process);
}

/// Step 3: the address space goes — every frame the process owns, per thread then per process (see
/// [`release_process`]). The process is torn down in place: its record holds absolute addresses
/// into itself.
#[cfg(target_arch = "x86")]
fn release_address_space_of(process: &mut Process) {
    use crate::mem::frame::FrameState;
    use crate::mem::paging::{self, PAGE_SIZE};
    release_process(
        process,
        |frame, index| paging::read_frame_word(frame, index),
        |frame_phys| {
            // The shared data page is mapped into every process and freed by none.
            if crate::user::shared::is_frame(frame_phys) {
                return;
            }
            crate::mem::bootmem::with_frame_db(|db| {
                db.release(frame_phys / PAGE_SIZE, FrameState::Free);
            });
        },
    );
}

/// The object audit: every object was the process's (one process runs at a time), and with its
/// handles closed, its waits returned and its threads ended, none is left — nor any open-file
/// record. One that is would be a reference leak: it is reported, and swept all the same.
#[cfg(target_arch = "x86")]
fn audit_objects(process: &mut Process) {
    let leaked =
        crate::ob::directory().process_ended(crate::sched::idle::dispatcher(), |followup| {
            match followup {}
        }) + process.files.live();
    process.files.clear();
    if leaked != 0 {
        crate::serial_println!(
            "F2K: object audit FAILED: {} objects or file records outlived their process",
            leaked
        );
    }
}

/// Step 4: the process has ended — its object signals with the exit code, and its waiters wake.
#[cfg(target_arch = "x86")]
fn signal_end(process: &mut Process, end: exit::ProcessEnd) {
    crate::ob::directory().signal_process_end(
        process.object,
        end.exit_status(),
        crate::sched::idle::dispatcher(),
    );
    process.torn_down = true;
}

/// Step 5: the process's own reference on its object goes, and the kernel detaches from it. The
/// record is reused once the object is gone — now, unless a handle to the process outlives it.
#[cfg(target_arch = "x86")]
fn release_record(process: &mut Process) {
    let _ = crate::ob::directory().dereference(process.object, crate::sched::idle::dispatcher());
    pool::detach();
}

/// The post-boot free-frame count: the baseline the per-process teardown audits compare against.
/// Recorded once the boot's own permanent allocations are done, before the first process starts.
#[cfg(target_arch = "x86")]
static mut BASELINE_FRAMES: u32 = 0;

/// Record the allocator baseline (`available()` at the call site).
#[cfg(target_arch = "x86")]
pub fn record_allocator_baseline() {
    // SAFETY: single CPU; written once at boot before the first process, read by the teardown
    // audits.
    unsafe {
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!(BASELINE_FRAMES),
            crate::mem::bootmem::with_frame_db(|db| db.available()),
        );
    }
}

/// The zero-leak audit after a teardown: the frame database must audit clean and stand exactly at
/// the post-boot baseline, and the kernel heap must still audit clean (nothing per-process is
/// allocated from it). The error carries what is off.
#[cfg(target_arch = "x86")]
pub fn audit_allocators() -> Result<(), exit::Leak> {
    // SAFETY: recorded before the first process; read-only here.
    let baseline = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(BASELINE_FRAMES)) };
    let (frames_audit_ok, available) =
        crate::mem::bootmem::with_frame_db(|db| (db.audit().is_ok(), db.available()));
    let heap_audit_ok = crate::mem::bootmem::with_heap(|heap| heap.audit().is_ok());
    if frames_audit_ok && heap_audit_ok && available == baseline {
        Ok(())
    } else {
        Err(exit::Leak {
            available,
            baseline,
            frames_audit_ok,
            heap_audit_ok,
        })
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
    use crate::mem::vm::{encode, PAGE_GUARD, PAGE_NOACCESS, PAGE_READWRITE};
    use crate::sched::process::SchedProcess;
    use crate::sched::thread::{Thread, NO_GATE_SLOT};
    use crate::user::userheap::HeapState;

    // --- The process record (the per-thread state split's shape) --------

    /// A process record as the tests build it: by value, at `dir`, standing for a made-up process
    /// object.
    fn record_at(dir: u32) -> Process {
        Process {
            sched: SchedProcess::new(dir, 8),
            name: "fixture",
            id: FIRST_CLIENT_ID,
            object: crate::ob::ObjectId {
                kind: crate::ob::ObjectType::Process,
                index: 0,
                generation: 0,
            },
            gate_slots: GateSlots::empty(),
            heap: HeapState::new(),
            vm: crate::mem::vm::AddressSpace::new(),
            handles: crate::sched::object::HandleTable::empty(),
            files: crate::fs::file::OpenFiles::empty(),
            console: rtl::console::Handles::standard(),
            dead_stack: DeadStack::empty(),
            end: None,
            handed_end: None,
            torn_down: false,
        }
    }

    fn fresh_process() -> Box<Process> {
        Box::new(record_at(0x0090_0000))
    }

    /// Client ids are NT's: never 0 or 4 (the System process), stepping by four, one space for
    /// processes and threads.
    #[test]
    fn client_ids_step_by_four_from_eight() {
        assert_eq!(FIRST_CLIENT_ID, 8);
        assert_eq!(next_client_id(FIRST_CLIENT_ID), 12);
        assert_eq!(next_client_id(next_client_id(FIRST_CLIENT_ID)), 16);
        assert_eq!(record_at(0x0090_0000).id(), FIRST_CLIENT_ID);
    }

    /// A fresh process: the scheduling record leads it (the directory base at the pinned offset),
    /// and the ledger is empty — the process owns no gate stack of its own; its threads do.
    #[test]
    fn fresh_process_state_starts_clean() {
        let mut process = fresh_process();
        assert_eq!(process.name(), "fixture");
        assert_eq!(process.dir_phys(), 0x0090_0000);
        assert_eq!(process.sched.base_priority(), 8);
        assert_eq!(Thread::empty().gate_slot(), NO_GATE_SLOT);
        assert!(process.gate_slots.is_empty());
        assert_eq!(process.handles().live(), 0);

        // The heap state a service would see: creating the heap reports the handle and resets
        // nothing that exists.
        assert_eq!(
            process.heap_mut().create(),
            crate::user::userheap::HEAP_HANDLE
        );
    }

    /// The parts borrow apart: the heap and the address space, the handle table and the open
    /// files, all at once.
    #[test]
    fn the_parts_borrow_apart() {
        let mut process = fresh_process();
        let parts = process.parts_mut();
        let index = parts.files.open(a_file(5)).unwrap();
        let handle = parts.handles.insert(crate::ob::Entry {
            target: crate::ob::Target::File(index),
            access: crate::ob::FILE_GENERIC_READ,
            inherit: false,
        });
        assert_eq!(parts.heap.create(), crate::user::userheap::HEAP_HANDLE);
        assert!(parts.vm.region_at(0x0040_0000).is_none());
        assert!(parts.gate_slots.is_empty() && parts.dead_stack.take().is_none());
        assert_eq!(process.file_mut(handle).unwrap().file.size, 5);
    }

    fn a_file(size: u32) -> crate::fs::fat32::lookup::File {
        crate::fs::fat32::lookup::File {
            first_cluster: 3,
            size,
            directory: false,
        }
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

    // --- File handles (the table's file entries and the open-file records) -----

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
        let handle = process.handles.insert(event_entry());
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
        while !crowded.handles.is_full() {
            crowded.handles.insert(event_entry());
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

    /// The exit-then-spawn sequence the respawn fixture drives: a child's slot stays taken while
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

    // --- The gate-slot ledger ------------------------------------------------

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
    fn planted_process(
        dir: u32,
    ) -> (
        FakeMemory,
        &'static mut Process,
        &'static mut Thread,
        &'static mut Thread,
    ) {
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
        mem.plant(gate_table, &[]);

        // Boxed to its final address before anything links into it: the thread list's entries are
        // absolute addresses, so the record must never move once attached.
        let process = Box::leak(Box::new(record_at(dir)));
        process.sched.init();
        let sched = core::ptr::addr_of_mut!(process.sched);
        // The thread records are the object manager's on target; leaked here, at their final
        // addresses all the same.
        let main = Box::leak(Box::new(Thread::empty()));
        let child = Box::leak(Box::new(Thread::empty()));
        // SAFETY: the process record and the threads are at their final addresses.
        unsafe {
            main.attach_to(&mut *sched);
            main.gate_slot = process.gate_slots.allocate();
            main.gate_frames = MAIN_STACK;
            child.attach_to(&mut *sched);
            child.gate_slot = process.gate_slots.allocate();
            child.gate_frames = CHILD_STACK;
        }
        (mem, process, main, child)
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
    /// exactly once: the last exit's parked stack, the walked user data frames (committed pages the
    /// program may not touch included) and tables, the gate window's table, and the directory — nothing from the shared kernel half. An earlier
    /// exit's stack is not teardown's: the next exit released it. A thread's TEB page is released
    /// once, by the walk (the thread records never hold user-half frames).
    #[test]
    fn teardown_releases_exactly_the_process_frames() {
        let dir = 0x0090_0000;
        let (mut mem, process, main, child) = planted_process(dir);
        // The child exits first, then the main thread — whose exit hands back the child's stack
        // for release from its own.
        assert_eq!(exit(process, child), None);
        assert_eq!(exit(process, main), Some((1, CHILD_STACK)));
        assert_eq!(process.sched.stack_count(), 0);

        mem.release(process);

        let mut released = mem.released.clone();
        released.sort_unstable();
        let mut expected = vec![
            0x00A0_0000, // the user table
            0x00C0_0000, // the gate window's table
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
        let (mut mem, process, main, child) = planted_process(dir);
        exit(process, child);
        exit(process, main);

        mem.release(process);
        let released = &mem.released;
        assert_eq!(&released[..4], &MAIN_STACK, "the parked stack first");
        assert_eq!(released.last(), Some(&dir), "the directory last");
        assert_eq!(released.len(), 4 + 5 + 1);
    }

    /// Teardown never precedes the last thread's end: a process with a thread still attached is
    /// refused.
    #[test]
    #[should_panic(expected = "teardown of a process with attached threads")]
    fn teardown_refuses_a_process_with_attached_threads() {
        let dir = 0x0090_0000;
        let (mut mem, process, _main, child) = planted_process(dir);
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
