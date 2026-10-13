//! The process object: every piece of per-process state in one place.
//!
//! A process owns its page directory (created per process, sharing the
//! kernel's kernel half), its ring-0 gate stack (frame-allocated,
//! supervisor-only, guard page below, pointed at by the TSS `esp0`
//! while it runs), and its user-heap bookkeeping ([`HeapState`]). The
//! image, stack, TEB and parameters pages are mapped fresh each run
//! into the process's directory, so they are per-process by
//! construction.
//!
//! Single tasking, run to completion: at most one process exists at a
//! time. The one kernel static here is the current-process pointer —
//! the run-to-completion analog of a scheduler's current pointer. It
//! is kernel state (like CR3 and the TSS), not per-process state;
//! everything per-process lives inside the [`Process`] it points at.
//! No other kernel static holds per-process state (the review
//! enforceable form: `static mut` outside the boot/cpu structures
//! names no per-process user state).

#[cfg(target_arch = "x86")]
use crate::mem::paging;

/// A process: one address space, one gate stack, one user heap.
pub struct Process {
    /// The fixture's name, as invoked (reported on COM1).
    name: &'static str,
    /// The process's page-directory frame.
    dir_phys: u32,
    /// The gate stack's frames (four, supervisor-only, released at
    /// teardown; the stack's top VA is the gate-stack window's top).
    gate_stack_frames: [u32; crate::mem::paging::GATE_STACK_PAGES],
    /// The user-heap bookkeeping (heap region + CRT region).
    heap: crate::userheap::HeapState,
}

impl Process {
    /// The process's name.
    pub fn name(&self) -> &'static str {
        self.name
    }

    /// The process's page-directory frame.
    pub fn dir_phys(&self) -> u32 {
        self.dir_phys
    }

    /// The user-heap state (the kernel32 heap services are served
    /// from here).
    pub fn heap_mut(&mut self) -> &mut crate::userheap::HeapState {
        &mut self.heap
    }
}

#[cfg(target_arch = "x86")]
impl Process {
    /// Create the process and make it current: a fresh address space
    /// (kernel half inherited, activated on CR3), a fresh gate stack
    /// (mapped into the new directory, installed as the TSS `esp0`),
    /// and fresh heap state. Every later user mapping (thunks, image,
    /// stack, TEB, params) lands in this process's directory.
    ///
    /// # Panics
    ///
    /// A process is already running (run to completion: one at a
    /// time), or the frame database is empty.
    pub fn start(name: &'static str) -> &'static mut Process {
        let dir_phys = paging::create_address_space();
        paging::activate_address_space(dir_phys);

        let gate_stack_frames = paging::map_gate_stack();
        crate::gdt::set_gate_stack_top(paging::GATE_STACK_TOP);

        install(Process {
            name,
            dir_phys,
            gate_stack_frames,
            heap: crate::userheap::HeapState::new(),
        })
    }
}

/// The current process. Single tasking: installed at start, read by
/// the service paths, and (in the teardown slice) taken at exit.
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

/// Walk the process directory at `dir_phys` and release everything it
/// owns exclusively: every present PTE's data frame in the user
/// windows, every present user window's page-table frame, and the
/// gate stack's data frames and page-table frame. `read_entry(frame,
/// index)` reads one word of a frame; `release(frame_phys)` returns
/// it. Frames in the shared kernel half (the kernel image window, the
/// self-map, the shared scratch table) are never touched, and the
/// directory frame itself is left alone — the caller releases it
/// last.
pub fn release_address_space(
    dir_phys: u32,
    gate_stack_frames: &[u32],
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
    // data frames were recorded at creation; its page-table frame is
    // the directory entry.
    let pde = read_entry(dir_phys, (GATE_STACK_WINDOW >> 22) as usize);
    if pde & PAGE_PRESENT != 0 {
        release(pde & PAGE_ADDR_MASK);
    }
    for &frame in gate_stack_frames {
        release(frame);
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

    let process = take_current();
    let dir_phys = process.dir_phys;

    // SAFETY: the scratch window is installed in the boot directory;
    // the release path is its sole user; the frame ids come straight
    // out of the entries just read.
    release_address_space(
        dir_phys,
        &process.gate_stack_frames,
        |frame, index| paging::read_frame_word(frame, index),
        |frame_phys| {
            crate::mem::bootmem::with_frame_db(|db| {
                db.release(frame_phys / PAGE_SIZE, FrameState::Free);
            });
        },
    );
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
    frames_ok && heap_ok
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fresh heap state is all-zero bookkeeping: a new process's
    /// heap starts with nothing committed and nothing reserved.
    #[test]
    fn fresh_process_state_starts_clean() {
        let heap = crate::userheap::HeapState::new();
        let mut process = Process {
            name: "fixture",
            dir_phys: 0x0090_0000,
            gate_stack_frames: [0x00B0_0000; crate::mem::paging::GATE_STACK_PAGES],
            heap,
        };
        assert_eq!(process.name(), "fixture");
        assert_eq!(process.dir_phys(), 0x0090_0000);
        // The heap state a service would see: creating the heap
        // reports the handle and resets nothing that exists.
        assert_eq!(process.heap_mut().create(), crate::userheap::HEAP_HANDLE);
    }

    // --- Teardown walk ------------------------------------------------
    //
    // Fake physical memory: frames as pages of 1024 words, released
    // frames collected in order.

    use crate::mem::paging::{
        GATE_STACK_WINDOW, KERNEL_HALF_START, PAGE_ADDR_MASK, PAGE_PRESENT, PT_ENTRIES,
    };
    use std::collections::HashMap;

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

        /// Run the walk over the fake memory.
        fn release(&mut self, dir: u32, gate_frames: &[u32]) {
            let mut released = core::mem::take(&mut self.released);
            release_address_space(
                dir,
                gate_frames,
                |frame, index| self.read(frame, index),
                |frame_phys| released.push(frame_phys),
            );
            self.released = released;
        }
    }

    /// A directory shaped like a real process's: two user windows
    /// with present PTEs, a gate stack window, and a populated
    /// kernel half whose entries must never be followed.
    fn planted_process(dir: u32, gate_table: u32) -> FakeMemory {
        let mut mem = FakeMemory::new();
        let user_table_a = 0x00A0_0000;
        let user_table_b = 0x00B0_0000;
        mem.plant(
            dir,
            &[
                (1, user_table_a | PAGE_PRESENT),
                (5, user_table_b | PAGE_PRESENT),
                ((GATE_STACK_WINDOW >> 22) as usize, gate_table | PAGE_PRESENT),
                // The shared kernel half: present entries that must
                // not be walked or released.
                (512, 0x0010_0000 | PAGE_PRESENT),
                (513, 0x0050_0000 | PAGE_PRESENT),
                (768, dir | PAGE_PRESENT),      // self-map
                (769, 0x00D0_0000 | PAGE_PRESENT), // shared scratch table
            ],
        );
        mem.plant(
            user_table_a,
            &[
                (0, 0x00E0_0000 | PAGE_PRESENT),
                (1, 0x00E1_0000 | PAGE_PRESENT),
                (1023, 0x00E2_0000 | PAGE_PRESENT),
            ],
        );
        mem.plant(user_table_b, &[(7, 0x00E3_0000 | PAGE_PRESENT)]);
        // The gate table's PTEs point at the recorded frames; the
        // walk must not read them (that would double-release).
        mem.plant(gate_table, &[(1, 0x00F1_0000 | PAGE_PRESENT)]);
        mem
    }

    /// The walk releases exactly the process's own frames: user data
    /// frames, their page tables, the gate stack's recorded frames
    /// and its table — and nothing from the shared kernel half, and
    /// not the directory frame (the caller releases it, last).
    #[test]
    fn teardown_releases_exactly_the_process_frames() {
        let dir = 0x0090_0000;
        let gate_table = 0x00C0_0000;
        let gate_frames = [0x00F1_0000, 0x00F2_0000, 0x00F3_0000, 0x00F4_0000];
        let mut mem = planted_process(dir, gate_table);
        mem.release(dir, &gate_frames);

        let mut released = mem.released.clone();
        released.sort_unstable();
        let mut expected = vec![
            0x00A0_0000, 0x00B0_0000, 0x00C0_0000, // page tables
            0x00E0_0000, 0x00E1_0000, 0x00E2_0000, 0x00E3_0000, // user data
            0x00F1_0000, 0x00F2_0000, 0x00F3_0000, 0x00F4_0000, // recorded
        ];
        expected.sort_unstable();
        assert_eq!(released, expected);
        // The kernel half's targets and the directory itself stay.
        assert!(!released.contains(&dir));
        assert!(!released.contains(&0x0010_0000));
        assert!(!released.contains(&0x0050_0000));
        assert!(!released.contains(&0x00D0_0000));
        // The recorded frames appear exactly once each: the gate
        // table's PTEs are never followed (a double release would
        // be a frame-database panic on target).
        assert_eq!(released.iter().filter(|&&f| f == 0x00F1_0000).count(), 1);
    }

    /// A process that never mapped a user page still releases its
    /// gate stack and its directory — and only through the recorded
    /// frames plus the gate window's table.
    #[test]
    fn teardown_of_an_empty_process_releases_the_gate_stack() {
        let dir = 0x0090_0000;
        let gate_table = 0x00C0_0000;
        let gate_frames = [0x00F1_0000, 0x00F2_0000, 0x00F3_0000, 0x00F4_0000];
        let mut mem = FakeMemory::new();
        mem.plant(
            dir,
            &[
                (KERNEL_HALF_START, 0x0010_0000 | PAGE_PRESENT),
                ((GATE_STACK_WINDOW >> 22) as usize, gate_table | PAGE_PRESENT),
            ],
        );
        mem.plant(gate_table, &[]);
        mem.release(dir, &gate_frames);

        let mut released = mem.released.clone();
        released.sort_unstable();
        assert_eq!(
            released,
            vec![0x00C0_0000, 0x00F1_0000, 0x00F2_0000, 0x00F3_0000, 0x00F4_0000]
        );
    }

    /// The gate window is a kernel-half entry but never a user one:
    /// the walk's user range ends below it.
    #[test]
    fn the_gate_window_sits_in_the_kernel_half() {
        assert!((GATE_STACK_WINDOW >> 22) as usize >= KERNEL_HALF_START);
        assert_eq!((GATE_STACK_WINDOW >> 22) as usize, 514);
    }
}
