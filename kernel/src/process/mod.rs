//! The process object: every piece of per-process state in one place.
//!
//! A process owns its page directory (created per process, sharing
//! the kernel's kernel half) and its user-heap bookkeeping
//! ([`HeapState`]). The image, stack, TEB and parameters pages are
//! mapped fresh each run into the process's directory, so they are
//! per-process by construction.
//!
//! The per-thread state split: the ring-0 gate stack (the thread's
//! kernel stack, what the TSS `esp0` points into) is per-thread,
//! sub-allocated as slots of the process's window ([`GateSlots`]),
//! each slot's frames recorded by their owning thread. The scheduling
//! record leads the process at a pinned offset, so a thread's owner
//! pointer resolves the directory base the context switch loads.
//!
//! Single tasking, run to completion: at most one process exists at a
//! time. The one kernel static here is the current-process pointer —
//! the run-to-completion analog of a scheduler's current pointer. It
//! is kernel state (like CR3 and the TSS), not per-process state;
//! everything per-process lives inside the [`Process`] it points at.
//! No other kernel static holds per-process state (the review
//! enforceable form: `static mut` outside the boot/cpu structures
//! names no per-process user state).

/// The sequential multi-process suite runner (`run-process-suite`).
#[cfg(all(target_arch = "x86", feature = "run-process-suite"))]
pub mod runner;

#[cfg(target_arch = "x86")]
use crate::mem::paging;

/// A process: one address space, one gate-stack window, one heap.
#[repr(C)]
pub struct Process {
    /// The scheduling record, leading the process record: the
    /// context switch's assembly reads the directory base through a
    /// thread's owner pointer at a pinned offset.
    pub sched: crate::sched::process::SchedProcess,
    /// The fixture's name, as invoked (reported on COM1).
    name: &'static str,
    /// The process's main thread: the thread the boot path enters
    /// ring 3 on. Its record owns its gate-stack slot's frames.
    main_thread: crate::sched::thread::Thread,
    /// The gate-stack window's slot occupancy (which threads own
    /// which slots).
    gate_slots: GateSlots,
    /// The user-heap bookkeeping (heap region + CRT region).
    heap: crate::user::userheap::HeapState,
}

// The scheduling record leads the process record: a thread's owner
// pointer and the process's directory base are one pinned chain.
const _: () = assert!(core::mem::offset_of!(Process, sched) == 0);

impl Process {
    /// The process's name.
    pub fn name(&self) -> &'static str {
        self.name
    }

    /// The process's page-directory frame.
    pub fn dir_phys(&self) -> u32 {
        self.sched.dir_phys()
    }

    /// The process's main thread.
    pub fn main_thread(&self) -> &crate::sched::thread::Thread {
        &self.main_thread
    }

    /// The user-heap state (the kernel32 heap services are served
    /// from here).
    pub fn heap_mut(&mut self) -> &mut crate::user::userheap::HeapState {
        &mut self.heap
    }
}

#[cfg(target_arch = "x86")]
impl Process {
/// Create the process and make it current: a fresh address space
/// with the record installed at its final address, then its main
/// thread taking the window's lowest free gate-stack slot, the
/// fixed TEB page, and the process's scheduling data. Every later
/// user mapping lands in this process's directory.
    pub fn start(name: &'static str) -> &'static mut Process {
        let dir_phys = paging::create_address_space();
        paging::activate_address_space(dir_phys);

        let process = install(Process {
            sched: crate::sched::process::SchedProcess::new(
                dir_phys,
                crate::sched::NORMAL_BASE,
            ),
            name,
            main_thread: crate::sched::thread::Thread::empty(),
            gate_slots: GateSlots::empty(),
            heap: crate::user::userheap::HeapState::new(),
        });

        // The scheduling record's thread-list sentinel closes now
        // that the record is at its final address.
        process.sched.init();

        // The main thread attaches to the process and takes the
        // lowest free gate-stack slot.
        let sched = core::ptr::addr_of_mut!(process.sched);
        let thread = core::ptr::addr_of_mut!(process.main_thread);
        // SAFETY: the process record is installed at its final
        // address; both pointers are into it.
        unsafe { (*thread).attach_to(&mut *sched) };
        let slot = process.gate_slots.allocate();
        // SAFETY: the slot pages map into the current address space,
        // above the slot's unmapped guard page.
        let frames = paging::map_gate_slot(slot as u32);
        // SAFETY: the main thread is not shared (single tasking).
        unsafe {
            (*thread).gate_slot = slot;
            (*thread).gate_frames = frames;
            (*thread).initial_stack = paging::gate_slot_top(slot as u32);
            (*thread).teb_va = crate::user::TEB_PAGE;
        }
        // The boot path installs the main thread's stack top as the
        // TSS `esp0` directly; the switch's own per-switch install
        // takes over with the runner conversion.
        crate::cpu::gdt::set_gate_stack_top(paging::gate_slot_top(slot as u32));
        process
    }
}

// --- The gate-stack slot ledger --------------------------------------------
//
// Per-thread slots: a guard page plus the four stack pages, lowest
// free index first. Occupancy only — each slot's frames are recorded
// by their owning thread, released exactly once.

/// How many occupancy words the ledger holds.
const SLOT_WORDS: usize = (crate::mem::paging::GATE_SLOT_CAPACITY + 63) / 64;

/// The gate-stack window's slot occupancy.
pub struct GateSlots {
    occupied: [u64; SLOT_WORDS],
}

impl GateSlots {
    /// An empty ledger: every slot free.
    pub const fn empty() -> Self {
        GateSlots { occupied: [0; SLOT_WORDS] }
    }

    /// Take the lowest free slot index. Panics past the window's
    /// capacity (an allocation overflow is a bug, not a wrap).
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

    /// Free slot `index`. Panics on a double release (the frames
    /// would be released twice — the frame database's own
    /// discipline makes that a panic on target).
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

/// The current process. Single tasking: installed at start, read by
/// the service paths, and taken at exit by the teardown path.
#[cfg(target_arch = "x86")]
static mut CURRENT: Option<Process> = None;

/// Install `process` as current and return it.
#[cfg(target_arch = "x86")]
fn install(process: Process) -> &'static mut Process {
    // SAFETY: single CPU, interrupts disabled; no process is running
    // when a new one starts (run to completion, asserted).
    unsafe {
        let slot = &mut *core::ptr::addr_of_mut!(CURRENT);
        assert!(slot.is_none(), "a process is already running");
        *slot = Some(process);
        slot.as_mut().expect("just installed")
    }
}

/// The current process, mutably (the heap services reach it this way).
///
/// # Panics
///
/// No process is running.
#[cfg(target_arch = "x86")]
pub fn current_mut() -> &'static mut Process {
    // SAFETY: single-threaded kernel; the pointer is installed before
    // ring 3 is entered and has no other writer.
    unsafe {
        let slot = &mut *core::ptr::addr_of_mut!(CURRENT);
        slot.as_mut().expect("no process is running")
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
        let slot = &mut *core::ptr::addr_of_mut!(CURRENT);
        slot.as_ref().expect("no process is running")
    }
}

// --- Teardown (the multi-process suite) -----------------------------------
//
// After a process exits or faults, the kernel switches back to the
// boot address space (on the boot gate stack), then releases every
// frame the process owned: its user pages and their tables, the gate
// stack's data frames and table, and the directory frame last. The
// walk reads the dead directory through the scratch window — it is
// not mapped anywhere, and must not be: the kernel never runs on a
// directory being freed.

/// Walk the process directory at `dir_phys` and release everything
/// it owns exclusively: every present PTE's data frame in the user
/// windows and their page tables, plus the gate window's table. The
/// slot data frames are the threads' (released through
/// [`crate::sched::visit_gate_frames`]); the shared kernel half is
/// never touched, and the directory frame is the caller's, last.
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
    // The gate stack window (in the kernel half, per-process): its
    // page-table frame is the directory entry; the slot data frames
    // belong to the threads (released through the thread records).
    let pde = read_entry(dir_phys, (GATE_STACK_WINDOW >> 22) as usize);
    if pde & PAGE_PRESENT != 0 {
        release(pde & PAGE_ADDR_MASK);
    }
}

/// The current process, removed from the current-process pointer, for
/// teardown. Call only when the kernel has switched off the process's
/// address space (its frames are then unreachable except through the
/// scratch window).
#[cfg(all(target_arch = "x86", feature = "run-process-suite"))]
pub fn take_current() -> Process {
    // SAFETY: single CPU; the teardown path is the only taker, run
    // once per process after the address-space switch.
    unsafe {
        let slot = &mut *core::ptr::addr_of_mut!(CURRENT);
        slot.take().expect("no process is running")
    }
}

/// The post-boot free-frame count: the baseline the per-process
/// teardown audits compare against. Recorded once the boot's own
/// permanent allocations are done, before the first process starts.
#[cfg(all(target_arch = "x86", feature = "run-process-suite"))]
static mut BASELINE_FRAMES: u32 = 0;

/// Record the allocator baseline (`available()` at the call site).
#[cfg(all(target_arch = "x86", feature = "run-process-suite"))]
pub fn record_allocator_baseline() {
    // SAFETY: single CPU; written once at suite start before the
    // first process, read by the teardown audits.
    unsafe {
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!(BASELINE_FRAMES),
            crate::mem::bootmem::with_frame_db(|db| db.available()),
        );
    }
}

/// Tear the current process down completely: release every frame it
/// owns (the directory frame last), then audit the frame database and
/// the kernel heap against the post-boot baseline. Returns whether
/// the state returned exactly to the baseline (zero leak).
///
/// Must run on the boot address space — the walk reads the dead
/// directory through the scratch window, never through a mapping.
#[cfg(all(target_arch = "x86", feature = "run-process-suite"))]
pub fn teardown_current() -> bool {
    use crate::mem::frame::FrameState;
    use crate::mem::paging::{self, PAGE_SIZE};

    // The process is torn down in place: its thread list's entries
    // are absolute addresses into this very record, and taking the
    // slot would zero them. The slot is retired only at the end.
    let process = current_mut();
    let dir_phys = process.dir_phys();

    // SAFETY: the scratch window is installed in the boot directory;
    // the release path is its sole user; the frame ids come straight
    // out of the entries just read or the thread records.
    let mut release = |frame_phys: u32| {
        crate::mem::bootmem::with_frame_db(|db| {
            db.release(frame_phys / PAGE_SIZE, FrameState::Free);
        });
    };

    // The address space: user data frames and their tables from the
    // walk, the gate window's table from its directory entry.
    release_address_space(
        dir_phys,
        |frame, index| paging::read_frame_word(frame, index),
        |frame_phys| release(frame_phys),
    );

    // Every live thread's gate-stack slot: each thread's recorded
    // frames, exactly once (the guard pages were never mapped, so
    // they are never released).
    crate::sched::visit_gate_frames(&mut process.sched, &mut release);

    // The directory frame itself, last of all.
    crate::mem::bootmem::with_frame_db(|db| {
        db.release(dir_phys / PAGE_SIZE, FrameState::Free);
    });

    // Zero-leak audit: the frame database must be exactly at the
    // post-boot baseline, and the kernel heap must still audit clean
    // (nothing per-process is allocated from it).
    let baseline = unsafe {
        // SAFETY: recorded before the first process; read-only here.
        core::ptr::read_volatile(core::ptr::addr_of!(BASELINE_FRAMES))
    };
    let frames_ok = crate::mem::bootmem::with_frame_db(|db| {
        db.audit().is_ok() && db.available() == baseline
    });
    let heap_ok = crate::mem::bootmem::with_heap(|heap| heap.audit().is_ok());

    // The record's lists are dead: retire the current-process slot.
    take_current();
    frames_ok && heap_ok
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mem::paging::{
        gate_slot_base, gate_slot_top, GATE_SLOT_CAPACITY, GATE_SLOT_STRIDE, GATE_STACK_TOP,
        GATE_STACK_WINDOW, KERNEL_HALF_START, PAGE_PRESENT, PT_ENTRIES,
    };
    use crate::sched::process::SchedProcess;
    use crate::sched::thread::{Thread, NO_GATE_SLOT};
    use crate::user::userheap::HeapState;
    use std::collections::HashMap;

    // --- The process record (the per-thread state split's shape) --------

    /// A fresh process: the scheduling record leads it (the
    /// directory base at the pinned offset), the main thread starts
    /// detached with no slot, and the ledger is empty — the process
    /// owns no gate stack of its own anymore; its threads do.
    #[test]
    fn fresh_process_state_starts_clean() {
        let mut process = Process {
            sched: SchedProcess::new(0x0090_0000, 8),
            name: "fixture",
            main_thread: Thread::empty(),
            gate_slots: GateSlots::empty(),
            heap: HeapState::new(),
        };
        assert_eq!(process.name(), "fixture");
        assert_eq!(process.dir_phys(), 0x0090_0000);
        assert_eq!(process.sched.base_priority(), 8);
        assert_eq!(process.main_thread().gate_slot(), NO_GATE_SLOT);
        assert!(process.gate_slots.is_empty());

        // The heap state a service would see: creating the heap
        // reports the handle and resets nothing that exists.
        assert_eq!(process.heap_mut().create(), crate::user::userheap::HEAP_HANDLE);
    }

    // --- The gate-slot ledger (B1/B2) --------------------------------------

/// The ledger hands out the lowest free index; slot 0's top is the
/// stack every boot has installed (the loader contract survives as
/// the main thread's esp0), and two threads never share a slot.
    #[test]
    fn the_ledger_hands_out_distinct_slots() {
        let mut ledger = GateSlots::empty();
        let s0 = ledger.allocate();
        let s1 = ledger.allocate();
        assert_eq!((s0, s1), (0, 1));
        assert!(ledger.is_taken(0) && ledger.is_taken(1));
        assert!(!ledger.is_taken(2));

        // Two threads of one process share the window but never a
        // slot: distinct bases, distinct tops, disjoint frames.
        assert_eq!(gate_slot_base(0), GATE_STACK_WINDOW);
        assert_eq!(gate_slot_base(1), GATE_STACK_WINDOW + GATE_SLOT_STRIDE);
        assert_eq!(gate_slot_top(0), GATE_STACK_TOP);
        assert_eq!(gate_slot_top(1), gate_slot_base(1) + GATE_SLOT_STRIDE);
        // The stride: one guard page plus the four stack pages.
        assert_eq!(GATE_SLOT_STRIDE, 5 * 4096);
        // Capacity: the window is one directory entry (4 MiB); an
        // allocation past capacity is an assert, not a wrap.
        assert_eq!(GATE_SLOT_CAPACITY, 204);
        assert_eq!((gate_slot_top(203) - GATE_STACK_WINDOW) / GATE_SLOT_STRIDE, 204);
    }

    /// Slot release and reuse: a released index is free, the next
    /// allocation takes the lowest free index again, and a double
    /// release is refused.
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

        // A double release is a bug: the frames would be released
        // twice.
        ledger.release(3);
        let refused = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            ledger.release(3)
        }));
        assert!(refused.is_err());
    }

    // --- Teardown accounting (B5) ------------------------------------------
    //
    // Fake physical memory: frames as pages of 1024 words, released
    // frames collected with counts.

    struct FakeMemory {
        frames: HashMap<u32, [u32; PT_ENTRIES]>,
        released: Vec<u32>,
    }

    impl FakeMemory {
        fn new() -> Self {
            Self { frames: HashMap::new(), released: Vec::new() }
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

        /// Run the real collection over the fake memory: the
        /// address-space walk plus the thread-record frames —
        /// exactly what teardown does.
        fn release(&mut self, dir: u32, process: &mut Process) {
            let mut released = core::mem::take(&mut self.released);
            release_address_space(
                dir,
                |frame, index| self.read(frame, index),
                |frame_phys| released.push(frame_phys),
            );
            crate::sched::visit_gate_frames(&mut process.sched, &mut |frame| released.push(frame));
            self.released = released;
        }

        /// How many times `frame` was released.
        fn count(&self, frame: u32) -> usize {
            self.released.iter().filter(|&&f| f == frame).count()
        }
    }

    /// A process whose main thread owns slot 0 and whose second
    /// thread owns slot 1, both with recorded frames, plus a planted
    /// directory: two user tables (a TEB page and an image page) and
    /// the gate window's table.
    fn planted_process(dir: u32) -> (FakeMemory, &'static mut Process) {
        let mut mem = FakeMemory::new();
        let user_table = 0x00A0_0000;
        let gate_table = 0x00C0_0000;
        mem.plant(
            dir,
            &[
                (1, user_table | PAGE_PRESENT),
                ((GATE_STACK_WINDOW >> 22) as usize, gate_table | PAGE_PRESENT),
                // The shared kernel half: present entries that must
                // not be walked or released.
                (KERNEL_HALF_START, 0x0010_0000 | PAGE_PRESENT),
                (KERNEL_HALF_START + 1, dir | PAGE_PRESENT), // self-map
            ],
        );
        // The TEB pages (user half: the walk owns them, so the thread
        // records must not hold them) and one image page.
        mem.plant(user_table, &[(0, 0x00E0_0000 | PAGE_PRESENT)]);
        mem.plant(gate_table, &[]);

        // Boxed to its final address before anything links into it:
        // the thread list's entries are absolute addresses, so the
        // record must never move once attached.
        let process = Box::leak(Box::new(Process {
            sched: SchedProcess::new(dir, 8),
            name: "fixture",
            main_thread: Thread::empty(),
            gate_slots: GateSlots::empty(),
            heap: HeapState::new(),
        }));
        process.sched.init();
        // SAFETY: the process record is at its final address.
        let sched = core::ptr::addr_of_mut!(process.sched);
        unsafe {
            (*core::ptr::addr_of_mut!(process.main_thread)).attach_to(&mut *sched);
            (*core::ptr::addr_of_mut!(process.main_thread)).gate_frames =
                [0x00F1_0000, 0x00F2_0000, 0x00F3_0000, 0x00F4_0000];
            let second = Box::leak(Box::new(Thread::empty()));
            second.attach_to(&mut *sched);
            second.gate_frames = [0x00F5_0000, 0x00F6_0000, 0x00F7_0000, 0x00F8_0000];
        }
        (mem, process)
    }

/// The collection releases exactly the process's own frames, each
/// exactly once: walked user data frames and tables, the gate
/// window's table, every live thread's recorded slot frames — and
/// nothing from the shared kernel half, not the directory frame. A
/// thread's TEB page is released once, by the walk (the thread
/// records never hold user-half frames).
    #[test]
    fn teardown_releases_exactly_the_process_frames() {
        let dir = 0x0090_0000;
        let (mut mem, process) = planted_process(dir);
        mem.release(dir, process);

        let mut released = mem.released.clone();
        released.sort_unstable();
        let mut expected = vec![
            0x00A0_0000, // the user table
            0x00C0_0000, // the gate window's table
            0x00E0_0000, // the TEB/image data page
            0x00F1_0000, 0x00F2_0000, 0x00F3_0000, 0x00F4_0000, // main thread
            0x00F5_0000, 0x00F6_0000, 0x00F7_0000, 0x00F8_0000, // second thread
        ];
        expected.sort_unstable();
        assert_eq!(released, expected);
        // Exactly once each, always.
        for frame in expected {
            assert_eq!(mem.count(frame), 1, "frame {frame:#x}");
        }
        // The kernel half's targets and the directory itself stay.
        assert_eq!(mem.count(0x0010_0000), 0);
        assert_eq!(mem.count(dir), 0);
    }

    /// The walk's user range ends below the gate window: the window
    /// is a kernel-half entry whose table the walk releases from the
    /// directory entry, never by scanning.
    #[test]
    fn the_gate_window_sits_in_the_kernel_half() {
        assert!((GATE_STACK_WINDOW >> 22) as usize >= KERNEL_HALF_START);
        assert_eq!((GATE_STACK_WINDOW >> 22) as usize, 514);
        assert_eq!(KERNEL_HALF_START, 512);
    }
}
