//! The kernel stacks: every thread's ring-0 ("gate") stack, one ledger and one parked stack for the
//! whole system.
//!
//! Every thread's gate stack is a slot of the kernel stack region ([`layout::KERNEL_STACKS`]): a
//! guard page, never mapped, under the stack's [`paging::GATE_STACK_PAGES`]. The region's page
//! tables are shared by every directory, as Windows keeps its kernel stacks in system space: a
//! stack is mapped in every address space from its creation to its release, so a thread can build
//! or enter another process's address space on its own stack. Slots are numbered across the whole
//! region (448 MiB, 12,743 slots), the lowest free first; the ledger records occupancy, and each
//! slot's frames are recorded by the thread that owns it, released exactly once.
//!
//! The region's tables are made on demand, not at boot: a stack's creation asks for the tables of
//! its slots' range ([`stack_range`], one or two, a slot straddling a window's end) through
//! [`paging::ensure_kernel_tables`], which makes the missing ones and installs them in the master
//! directory and every live process directory before the stack is mapped, all in one borrow of the
//! memory manager's database. So no thread exists before its stack is in every address space: the
//! context switch loads the new thread's directory before it touches the stack, and that directory
//! was either live when the table was made or made since (its kernel half copied from one that
//! holds it). Never repaired at a fault: nothing could take a fault on a stack it cannot reach.
//! The tables are kept once made, as the pool's are; a run of slots wholly in made windows costs
//! no directory access. Windows 2000 takes its kernel stacks from its system PTEs, whose page
//! tables are all in place from its initialisation (from memory); F2K's span is larger than what it
//! backs, so it makes them as stacks reach them.
//!
//! A GUI thread trades its stack for a large one at its first win32k service (Windows 2000's
//! PsConvertToGuiThread, [`create_large`]): a run of [`paging::LARGE_STACK_SLOTS`] consecutive
//! slots, its top the run's top, the guard pages inside the run free for the stack to grow into.
//! It starts with the ordinary stack's pages mapped at its top and grows down, a page at a time,
//! to [`paging::LARGE_STACK_PAGES`], as the user-mode callbacks nesting on it need room ([`grow`],
//! Windows 2000's MmGrowKernelStack); the run's lowest guard page is never mapped. The slot-pool
//! plan's slice 17 (the region grown to its whole span, tables made on demand) leaves this as it
//! is: a run is consecutive slots wherever the ledger finds them, and its whole range's tables are
//! made at its creation, so growing it makes none.
//!
//! A thread cannot release the stack it runs on, so its exit parks it instead, as its last act
//! before the switch away, and whoever next runs on another stack releases it: the next exit (which
//! gets the earlier stack back from the park), the next thread creation, or the next process
//! teardown (on the idle thread's boot stack). One parked stack serves the whole system: its owner
//! has left it for good, whatever process the code releasing it runs in, and the release unmaps it
//! from the shared tables, not from one process's directory. A process's teardown, run after its
//! last thread's exit, finds that exit's stack parked or already released.

#[cfg(target_arch = "x86")]
use super::phys::PhysAddr;
#[cfg(target_arch = "x86")]
use super::{frame::FrameDb, with_database, Parts};
use super::{layout, paging};

/// How many slots the ledger tracks: every slot of the region (12,743).
pub const SLOTS: usize = paging::GATE_SLOT_CAPACITY;

/// How many occupancy words the ledger holds (200).
const SLOT_WORDS: usize = SLOTS.div_ceil(64);

/// The addresses a stack on the run of `slots` slots from `slot` may ever map: from above the
/// run's lowest guard page to its top (an ordinary stack's pages, or a large one's room to grow).
/// Its page tables are made at the stack's creation.
pub const fn stack_range(slot: u16, slots: u8) -> core::ops::Range<u32> {
    paging::gate_slot_base(slot as u32) + paging::PAGE_SIZE
        ..paging::gate_slot_top(slot as u32 + slots as u32 - 1)
}

/// One gate stack: the lowest slot of its run and how many slots the run spans (1, or
/// [`paging::LARGE_STACK_SLOTS`] for a GUI thread's large stack), how many pages are mapped down
/// from its top, and their frames by physical address, the top page's first, as raw words (the
/// thread record keeps them so).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GateStack {
    pub slot: u16,
    pub slots: u8,
    pub pages: u8,
    pub frames: [u32; paging::LARGE_STACK_PAGES],
}

impl GateStack {
    /// No stack: a thread record's before its creation.
    pub const NONE: GateStack = GateStack {
        slot: crate::sched::thread::NO_GATE_SLOT,
        slots: 1,
        pages: 0,
        frames: [0; paging::LARGE_STACK_PAGES],
    };

    /// The stack's top: the thread's stack top and `esp0` (the top of its run's highest slot).
    pub const fn top(&self) -> u32 {
        paging::gate_slot_top(self.slot as u32 + self.slots as u32 - 1)
    }

    /// Its lowest mapped byte: below it, unmapped pages (the guard, or room to grow into).
    pub const fn limit(&self) -> u32 {
        self.top() - self.pages as u32 * paging::PAGE_SIZE
    }

    /// The most pages it may have mapped: the large stack's, or the ordinary one's.
    pub const fn capacity(&self) -> usize {
        if self.slots > 1 {
            paging::LARGE_STACK_PAGES
        } else {
            paging::GATE_STACK_PAGES
        }
    }

    /// Whether it is a GUI thread's large stack.
    pub const fn is_large(&self) -> bool {
        self.slots > 1
    }

    /// The frames mapped in it.
    pub fn mapped(&self) -> &[u32] {
        &self.frames[..self.pages as usize]
    }
}

/// Which slots of the kernel stack region threads hold, and which of them are the lower slots of
/// a large stack's run (their top page is not the stack's).
pub struct GateSlots {
    occupied: [u64; SLOT_WORDS],
    lower: [u64; SLOT_WORDS],
}

impl GateSlots {
    /// An empty ledger: every slot free.
    pub const fn empty() -> Self {
        GateSlots {
            occupied: [0; SLOT_WORDS],
            lower: [0; SLOT_WORDS],
        }
    }

    /// Take the lowest run of `count` free consecutive slots: its lowest index; none when the
    /// region has no such run.
    pub fn allocate_run(&mut self, count: u16) -> Option<u16> {
        if count <= 1 {
            return self.allocate();
        }
        let start = (0..=SLOTS as u16 - count)
            .find(|&first| (first..first + count).all(|index| !self.is_taken(index)))?;
        for index in start..start + count {
            self.occupied[(index / 64) as usize] |= 1 << (index % 64);
            if index + 1 < start + count {
                self.lower[(index / 64) as usize] |= 1 << (index % 64);
            }
        }
        Some(start)
    }

    /// Free the run of `count` slots from `index` ([`GateSlots::allocate_run`]'s), each as
    /// [`GateSlots::release`] frees one.
    pub fn release_run(&mut self, index: u16, count: u16) {
        for slot in index..index + count.max(1) {
            self.lower[(slot / 64) as usize] &= !(1 << (slot % 64));
            self.release(slot);
        }
    }

    /// Whether `index` is a lower slot of a large stack's run.
    pub fn is_lower(&self, index: u16) -> bool {
        self.lower[(index / 64) as usize] & (1 << (index % 64)) != 0
    }

    /// Take the lowest free slot index; none when every slot of the region is taken.
    pub fn allocate(&mut self) -> Option<u16> {
        let (word_index, word) = self
            .occupied
            .iter_mut()
            .enumerate()
            .find(|(_, word)| **word != u64::MAX)?;
        let bit = word.trailing_ones();
        let index = word_index * 64 + bit as usize;
        if index >= SLOTS {
            return None;
        }
        *word |= 1 << bit;
        Some(index as u16)
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

    /// The taken slots, lowest first (an empty word costs one test).
    pub fn taken(&self) -> impl Iterator<Item = u16> + '_ {
        self.occupied
            .iter()
            .enumerate()
            .filter(|(_, word)| **word != 0)
            .flat_map(|(word_index, &word)| {
                (0..64u16)
                    .filter(move |bit| word & (1 << bit) != 0)
                    .map(move |bit| word_index as u16 * 64 + bit)
            })
    }

    /// Take every free slot below `end` for good, unmapped, marked as a run's lower slots are (no
    /// page sure to be mapped): the growth diagnostic's fence, so the next stack lies past it.
    #[cfg(any(test, feature = "pool-smoke"))]
    pub fn fence_below(&mut self, end: u16) {
        for index in 0..end {
            if !self.is_taken(index) {
                self.occupied[(index / 64) as usize] |= 1 << (index % 64);
                self.lower[(index / 64) as usize] |= 1 << (index % 64);
            }
        }
    }

    /// Whether every slot is free.
    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.occupied.iter().all(|word| *word == 0)
    }
}

/// The system's kernel stacks: the slot ledger, and the stack of the thread that exited last, not
/// yet released.
pub struct KernelStacks {
    slots: GateSlots,
    parked: Option<GateStack>,
}

impl KernelStacks {
    /// Every slot free, nothing parked.
    pub const fn empty() -> Self {
        KernelStacks {
            slots: GateSlots::empty(),
            parked: None,
        }
    }

    /// Park `stack` (the exiting thread's own) and return the previously parked one, which the
    /// caller can release: it is not the stack the caller runs on. A parked stack keeps its slot
    /// until its release.
    pub fn park(&mut self, stack: GateStack) -> Option<GateStack> {
        self.parked.replace(stack)
    }

    /// Take the parked stack for release, if any.
    pub fn take_parked(&mut self) -> Option<GateStack> {
        self.parked.take()
    }
}

// Every slot lies inside the region, the region spans up to the page tables, the ledger is its 200
// words, and a slot index fits the thread record's field.
const _: () = {
    assert!(paging::gate_slot_top(SLOTS as u32 - 1) as u64 <= layout::KERNEL_STACKS.end());
    assert!(paging::gate_slot_top(SLOTS as u32) as u64 > layout::KERNEL_STACKS.end());
    assert!(layout::KERNEL_STACKS.end() == layout::PAGE_TABLES.start as u64);
    assert!(SLOTS == 12_743 && SLOT_WORDS == 200);
    assert!(SLOTS < crate::sched::thread::NO_GATE_SLOT as usize);
};

// --- The system's kernel stacks (target) ----------------------------------
//
// The stacks are part of the memory manager's database (`super::Database`), with the frame
// database their frames come from. Each step runs whole inside one borrow of it at the high level
// (interrupts masked), so the ledger and the shared tables agree wherever anything else can look:
// a taken slot is mapped, a free one is not.

/// A fresh gate stack: the system's lowest free slot, its tables made if it is the first to reach
/// them and installed in every directory, then mapped in the shared tables (in every address space
/// at once); none when the region is full, or when the frame database has not the frames left for
/// a table or the stack: a thread's creation fails then, rather than the kernel.
#[cfg(target_arch = "x86")]
pub fn create() -> Option<GateStack> {
    create_spanning(1)
}

/// A GUI thread's large stack (see the module notes): the system's lowest run of
/// [`paging::LARGE_STACK_SLOTS`] free slots, the ordinary stack's pages mapped at its top; none
/// when the region has no such run or the frame database not the frames (the thread keeps its
/// ordinary stack then).
#[cfg(target_arch = "x86")]
pub fn create_large() -> Option<GateStack> {
    create_spanning(paging::LARGE_STACK_SLOTS as u8)
}

/// [`create`]'s work, over a run of `slots` slots.
#[cfg(target_arch = "x86")]
fn create_spanning(slots: u8) -> Option<GateStack> {
    let (stack, _made) = with_database(|database| {
        let Parts {
            frames,
            stacks,
            scratch,
            directories,
            ..
        } = database.parts();
        let slot = stacks.slots.allocate_run(slots as u16)?;
        // The run's tables first, in every directory: before a page is mapped through them, and
        // before any thread can run on the stack. Made tables are kept, whatever follows.
        let tables = directories.tables_made();
        let ready =
            paging::ensure_kernel_tables(frames, scratch, directories, stack_range(slot, slots))
                .is_ok();
        let made = directories.tables_made() - tables;
        if !ready || frames.available() < paging::GATE_STACK_PAGES as u32 {
            stacks.slots.release_run(slot, slots as u16);
            return None;
        }
        let mut stack = GateStack {
            slot,
            slots,
            pages: paging::GATE_STACK_PAGES as u8,
            frames: [0; paging::LARGE_STACK_PAGES],
        };
        let top = stack.top();
        paging::map_gate_pages(
            frames,
            scratch,
            top,
            0,
            paging::GATE_STACK_PAGES,
            &mut stack.frames,
        );
        Some((stack, made))
    })
    .unzip();
    #[cfg(feature = "pool-smoke")]
    if let (Some(stack), Some(made)) = (stack, _made) {
        smoke_report(stack, made);
    }
    stack
}

/// Grow `stack` (a large one's; the running thread's own) down until `low` is mapped: the pages
/// between its limit and `low`'s page mapped in the shared tables. False when `low` lies past what
/// it may grow to, or the frame database has not the frames: nothing is mapped then.
#[cfg(target_arch = "x86")]
pub fn grow(stack: &mut GateStack, low: u32) -> bool {
    let Some(span) = stack.top().checked_sub(low) else {
        return false;
    };
    let wanted = (span as usize).div_ceil(paging::PAGE_SIZE as usize);
    let have = stack.pages as usize;
    if wanted <= have {
        return true;
    }
    if wanted > stack.capacity() {
        return false;
    }
    with_database(|database| {
        let Parts {
            frames, scratch, ..
        } = database.parts();
        if frames.available() < (wanted - have) as u32 {
            return false;
        }
        let top = stack.top();
        paging::map_gate_pages(frames, scratch, top, have, wanted, &mut stack.frames);
        stack.pages = wanted as u8;
        true
    })
}

/// Release a gate stack whose thread has left it for good: unmap the slot from the shared tables,
/// return the frames to the frame database, and the slot to the ledger. Never the stack the
/// processor runs on (see [`park`]).
#[cfg(target_arch = "x86")]
pub fn release(stack: GateStack) {
    with_database(|database| {
        let Parts { frames, stacks, .. } = database.parts();
        release_in(stacks, frames, stack);
    });
}

/// Park the exiting thread's own stack, releasing the one parked before it.
#[cfg(target_arch = "x86")]
pub fn park(stack: GateStack) {
    with_database(|database| {
        let Parts { frames, stacks, .. } = database.parts();
        if let Some(previous) = stacks.park(stack) {
            release_in(stacks, frames, previous);
        }
    });
}

/// Release the parked stack, if any: from code running on another stack.
#[cfg(target_arch = "x86")]
pub fn release_parked() {
    with_database(|database| {
        let Parts { frames, stacks, .. } = database.parts();
        if let Some(stack) = stacks.take_parked() {
            release_in(stacks, frames, stack);
        }
    });
}

/// Whether every taken slot is mapped in the current directory — in every directory, the tables
/// being shared. A debug check of a new address space against the stacks of the threads that run
/// in the others.
#[cfg(target_arch = "x86")]
pub fn every_stack_mapped_here() -> bool {
    with_database(|database| {
        // A large stack's lower slots are its room to grow: only its top slot's top page is
        // sure to be mapped.
        let slots = &database.stacks.slots;
        slots
            .taken()
            .filter(|&slot| !slots.is_lower(slot))
            .all(|slot| paging::gate_stack_mapped(paging::gate_slot_top(slot as u32), 1))
    })
}

/// The end of the kernel stack region before it grew to its whole span (four entries, 16 MiB).
#[cfg(any(test, feature = "pool-smoke"))]
const OLD_END: u32 = layout::KERNEL_STACKS.start + 4 * layout::ENTRY_SPAN;

/// The first slot whose stack lies wholly past the old region's end: its tables were never made at
/// boot.
#[cfg(any(test, feature = "pool-smoke"))]
const fn first_slot_past_old_end() -> u16 {
    let mut slot = 0;
    while stack_range(slot, 1).start < OLD_END {
        slot += 1;
    }
    slot
}

/// The first slot whose stack reaches the region's window `window` (counted from 0): the slot that
/// straddles the end of the window before it into it.
#[cfg(any(test, feature = "pool-smoke"))]
const fn first_slot_into_window(window: u32) -> u16 {
    let mut slot = 0;
    while stack_range(slot, 1).end <= layout::KERNEL_STACKS.start + window * layout::ENTRY_SPAN {
        slot += 1;
    }
    slot
}

/// The region's window the next fence reaches into, once [`smoke`] armed the reports; 0 when
/// disarmed. The first two stacks whose creation makes a table report it, each moving the fence on
/// into the next window.
#[cfg(all(target_arch = "x86", feature = "pool-smoke"))]
static SMOKE_WINDOW: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// The last window [`smoke`]'s reports fence into: two reports, into windows 5 and 6.
#[cfg(all(target_arch = "x86", feature = "pool-smoke"))]
const SMOKE_LAST_WINDOW: u32 = 6;

/// The kernel stack region's growth diagnostic (the `pool-smoke` boot), after the pool's, before
/// the first process. A directory is made first; every free slot below the first one past the old
/// 16 MiB region is fenced off, so the next stack lies past it, in a window whose table was never
/// made; that stack's creation must make the table and install it in every live directory, and the
/// directory made before it must read and write the stack through its own entry. Then the fence
/// moves up to the slot that straddles into the next window, and stays: the next thread the boot
/// creates (the console control thread, in the System process) takes that slot, its table made at
/// its creation, and runs on it; the fence moves on into the window after, so the thread after it
/// (the first process's main thread, its directory live) does the same ([`smoke_report`]).
/// Reported on COM1; nothing is left behind but the tables and the fence (no frames).
#[cfg(all(target_arch = "x86", feature = "pool-smoke"))]
pub fn smoke() {
    use crate::level::{raised, High};
    let yes = |ok: bool| if ok { "yes" } else { "no" };

    let early = paging::create_address_space();
    let past = first_slot_past_old_end();
    with_database(|database| database.stacks.slots.fence_below(past));
    let tables = paging::kernel_table_frames();
    let stack = create().expect("the diagnostic's stack");
    crate::serial_println!(
        "F2K: pool-smoke: a kernel stack past the old 16 MiB region (slot {}): {}",
        stack.slot,
        yes(stack.slot == past && stack.limit() >= OLD_END)
    );
    crate::serial_println!(
        "F2K: pool-smoke: a table made for the stack: {}",
        yes(paging::kernel_table_frames() == tables + 1)
    );
    crate::serial_println!(
        "F2K: pool-smoke: every directory holds the stack's table: {}",
        yes(paging::directories_in_step())
    );

    // Write the stack's lowest and highest words here, read them in the directory made before the
    // table: the processor walks that directory's own entry for the stack's window.
    let (low, high) = (stack.limit() as *mut u32, (stack.top() - 4) as *mut u32);
    let seen = raised::<High, _>(|_| {
        // SAFETY: the stack is mapped in every directory (the check above) and no thread runs on
        // it; interrupts are masked, so nothing runs in the early directory but these accesses.
        unsafe {
            low.write_volatile(0xF2C5_0000);
            high.write_volatile(0xF2C5_FFFF);
            let home = paging::current_directory_phys();
            paging::activate_address_space(early);
            let words = (low.read_volatile(), high.read_volatile());
            high.write_volatile(0xF2C5_1111);
            paging::activate_address_space(home);
            (words, high.read_volatile())
        }
    });
    crate::serial_println!(
        "F2K: pool-smoke: a directory made before the table runs the stack's pages: {}",
        yes(seen == ((0xF2C5_0000, 0xF2C5_FFFF), 0xF2C5_1111))
    );

    release(stack);
    paging::retire_address_space(early);
    paging::release_frame_phys(early);
    let straddling = first_slot_into_window(5);
    with_database(|database| database.stacks.slots.fence_below(straddling));
    crate::serial_println!(
        "F2K: pool-smoke: stack released, table kept, slots fenced below {straddling}: {}",
        yes(paging::kernel_table_frames() == tables + 1)
    );
    SMOKE_WINDOW.store(6, core::sync::atomic::Ordering::Relaxed);
}

/// The armed diagnostic's report of a stack whose creation made a table: the slot, the tables
/// made, and how many process directories were live to receive them; then the fence moves on, so
/// the next stack reaches the next window.
#[cfg(all(target_arch = "x86", feature = "pool-smoke"))]
fn smoke_report(stack: GateStack, made: u32) {
    use core::sync::atomic::Ordering;
    let window = SMOKE_WINDOW.load(Ordering::Relaxed);
    if made == 0 || window == 0 {
        return;
    }
    crate::serial_println!(
        "F2K: pool-smoke: a thread's stack at slot {} made {made} table(s), {} directories live",
        stack.slot,
        paging::live_directories()
    );
    if window > SMOKE_LAST_WINDOW {
        SMOKE_WINDOW.store(0, Ordering::Relaxed);
        return;
    }
    let end = first_slot_into_window(window);
    with_database(|database| database.stacks.slots.fence_below(end));
    SMOKE_WINDOW.store(window + 1, Ordering::Relaxed);
}

/// [`release`]'s work, on the stacks and the frame database the caller holds.
#[cfg(target_arch = "x86")]
fn release_in(stacks: &mut KernelStacks, frames: &mut FrameDb, stack: GateStack) {
    use crate::mem::frame::FrameState;
    let mapped = paging::unmap_gate_pages(stack.top(), stack.pages as usize).map(PhysAddr::get);
    debug_assert_eq!(
        &mapped[..stack.pages as usize],
        stack.mapped(),
        "the stack maps the frames its thread recorded"
    );
    for &frame in stack.mapped() {
        frames.release(PhysAddr::new(frame).pfn(), FrameState::Free);
    }
    stacks.slots.release_run(stack.slot, stack.slots as u16);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mem::paging::{gate_slot_base, gate_slot_top, GATE_SLOT_STRIDE, PAGE_SIZE};

    /// The ledger hands out the lowest free index, and never one slot twice.
    #[test]
    fn the_ledger_hands_out_distinct_slots() {
        let mut ledger = GateSlots::empty();
        assert!(ledger.is_empty());
        assert_eq!((ledger.allocate(), ledger.allocate()), (Some(0), Some(1)));
        assert!(ledger.is_taken(0) && ledger.is_taken(1));
        assert!(!ledger.is_taken(2));
        assert!(!ledger.is_empty());
        assert_eq!(ledger.taken().collect::<Vec<_>>(), [0, 1]);
    }

    /// A released index is free again, and the next allocation takes the lowest free index; a
    /// double release is refused.
    #[test]
    fn a_release_frees_the_lowest_index_for_reuse() {
        let mut ledger = GateSlots::empty();
        for _ in 0..3 {
            ledger.allocate();
        }
        ledger.release(1);
        assert!(!ledger.is_taken(1));
        assert_eq!(ledger.taken().collect::<Vec<_>>(), [0, 2]);
        assert_eq!(ledger.allocate(), Some(1));
        assert_eq!(ledger.allocate(), Some(3));

        ledger.release(3);
        let refused = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| ledger.release(3)));
        assert!(refused.is_err(), "a double release is refused");
    }

    /// The ledger spans the whole region: every slot can be taken, and one more is refused as a
    /// status, not a panic. A release makes room again.
    #[test]
    fn a_full_ledger_refuses_the_next_allocation() {
        let mut ledger = GateSlots::empty();
        for expected in 0..SLOTS {
            assert_eq!(ledger.allocate(), Some(expected as u16));
        }
        assert_eq!(ledger.allocate(), None);
        assert_eq!(ledger.allocate(), None, "still full");
        assert_eq!(ledger.taken().count(), SLOTS);
        ledger.release(200);
        assert_eq!(ledger.allocate(), Some(200));
        assert_eq!(ledger.allocate(), None);
    }

    /// The region holds 12,743 slots (448 MiB at the 36 KiB stride) in a ledger of 200 words, far
    /// more than every thread record of the object manager, each a GUI thread's large stack, needs;
    /// backing them all would take more frames than the 256 MiB machine's memory, so frames run
    /// out first there.
    #[test]
    fn the_ledger_is_sized_to_the_region() {
        assert!(SLOTS > crate::ob::THREADS * paging::LARGE_STACK_SLOTS as usize);
        assert_eq!(SLOTS, 12_743);
        assert_eq!(SLOT_WORDS, 200);
        assert_eq!(
            core::mem::size_of::<GateSlots>(),
            2 * SLOT_WORDS * 8,
            "occupancy and lower bits"
        );
        assert_eq!(
            SLOTS,
            (layout::KERNEL_STACKS.size() / GATE_SLOT_STRIDE) as usize
        );
        assert!(
            SLOTS as u64 * paging::GATE_STACK_PAGES as u64 * PAGE_SIZE as u64 > 256 * 0x10_0000
        );
    }

    /// The ledger's last word is partial: its slots past the region are never handed out, and the
    /// taken slots are listed across every word, the last one's included.
    #[test]
    fn the_last_word_ends_at_the_region() {
        let mut ledger = GateSlots::empty();
        let last = SLOTS as u16 - 1;
        assert_eq!(last / 64, SLOT_WORDS as u16 - 1);
        assert_eq!(ledger.allocate_run(1), Some(0));
        assert_eq!(ledger.allocate_run(3), Some(1));
        ledger.fence_below(last);
        assert_eq!(ledger.allocate(), Some(last));
        assert_eq!(ledger.allocate(), None, "no slot past the region's end");
        assert_eq!(ledger.allocate_run(2), None);
        assert_eq!(ledger.taken().count(), SLOTS);
        assert_eq!(ledger.taken().last(), Some(last));
        ledger.release(4000);
        assert!(ledger.taken().all(|slot| slot != 4000));
        assert_eq!(ledger.taken().count(), SLOTS - 1);
    }

    /// A fence takes every free slot below its end, unmapped and marked lower (no page sure to be
    /// mapped), and leaves the taken ones as they are: the next stack lies past it.
    #[test]
    fn a_fence_puts_the_next_stack_past_it() {
        let mut ledger = GateSlots::empty();
        ledger.allocate();
        ledger.allocate();
        ledger.fence_below(500);
        assert!(!ledger.is_lower(0) && !ledger.is_lower(1));
        assert!((2..500).all(|slot| ledger.is_taken(slot) && ledger.is_lower(slot)));
        assert_eq!(ledger.allocate(), Some(500));
    }

    /// A stack's range runs from above its run's lowest guard page to its top: an ordinary stack's
    /// eight pages, a large one's 26. The old region's end falls inside slot 455's guard page, so
    /// slot 455 is the first wholly past it; slot 568 straddles the fifth window's end.
    #[test]
    fn a_stack_range_is_what_it_may_map() {
        let ordinary = stack_range(3, 1);
        assert_eq!(ordinary.start, gate_slot_base(3) + PAGE_SIZE);
        assert_eq!(ordinary.end, gate_slot_top(3));
        assert_eq!(
            ordinary.len() as u32,
            paging::GATE_STACK_PAGES as u32 * PAGE_SIZE
        );
        let large = stack_range(6, paging::LARGE_STACK_SLOTS as u8);
        assert_eq!(large.end, gate_slot_top(8));
        assert_eq!(
            large.len() as u32,
            paging::LARGE_STACK_PAGES as u32 * PAGE_SIZE
        );
        let grown = GateStack {
            slot: 6,
            slots: paging::LARGE_STACK_SLOTS as u8,
            pages: paging::LARGE_STACK_PAGES as u8,
            ..stack(6, 0)
        };
        assert_eq!(grown.limit()..grown.top(), large);

        assert_eq!(OLD_END, 0xA500_0000);
        assert_eq!(first_slot_past_old_end(), 455);
        assert_eq!(
            gate_slot_base(455),
            0xA4FF_F000,
            "the guard page is the old region's last"
        );
        assert_eq!(stack_range(455, 1).start, OLD_END);
        assert_eq!(first_slot_into_window(5), 568);
        assert_eq!(first_slot_into_window(6), 682);
        let straddling = stack_range(568, 1);
        assert_eq!(
            paging::directory_index(straddling.start) + 1,
            paging::directory_index(straddling.end - 1)
        );
        assert_eq!(
            paging::directory_index(straddling.end - 1),
            layout::KERNEL_STACKS.first_entry() + 5
        );
        let last = stack_range(SLOTS as u16 - 1, 1);
        assert!(last.end as u64 <= layout::KERNEL_STACKS.end());
        assert!(layout::KERNEL_STACKS.holds(last.start));
    }

    /// Slot addresses are unique in the system: every slot lies inside the region, its guard page
    /// at its base, and no two slots overlap — the first's at the region's start, the last's top
    /// inside its end.
    #[test]
    fn every_slot_has_a_system_unique_address() {
        let region = layout::KERNEL_STACKS;
        assert_eq!(gate_slot_base(0), region.start);
        for index in 0..SLOTS as u32 {
            let (base, top) = (gate_slot_base(index), gate_slot_top(index));
            assert!(region.holds(base) && region.holds(top - 1), "slot {index}");
            assert_eq!(top - base, GATE_SLOT_STRIDE);
            assert_eq!(base % PAGE_SIZE, 0);
            if index > 0 {
                assert_eq!(base, gate_slot_top(index - 1), "slots {index} and before");
            }
        }
        assert!(gate_slot_top(SLOTS as u32 - 1) as u64 <= region.end());
        assert!(
            gate_slot_top(SLOTS as u32) as u64 > region.end(),
            "one more would not fit"
        );
    }

    /// An ordinary stack at `slot`, its frames numbered from `first`.
    fn stack(slot: u16, first: u32) -> GateStack {
        let mut frames = [0; paging::LARGE_STACK_PAGES];
        for (i, frame) in frames.iter_mut().enumerate().take(paging::GATE_STACK_PAGES) {
            *frame = first + i as u32;
        }
        GateStack {
            slot,
            slots: 1,
            pages: paging::GATE_STACK_PAGES as u8,
            frames,
        }
    }

    /// A run of slots is the lowest free consecutive run, its slots but the top one marked lower;
    /// its release frees them all, and a slot alone fits the holes a run cannot.
    #[test]
    fn a_run_takes_the_lowest_consecutive_free_slots() {
        let mut ledger = GateSlots::empty();
        for _ in 0..4 {
            ledger.allocate();
        }
        ledger.release(1);
        assert_eq!(ledger.allocate_run(3), Some(4), "slot 1 alone is too short");
        assert!(ledger.is_taken(4) && ledger.is_taken(5) && ledger.is_taken(6));
        assert!(ledger.is_lower(4) && ledger.is_lower(5) && !ledger.is_lower(6));
        assert_eq!(ledger.allocate(), Some(1));
        ledger.release(2);
        ledger.release(3);
        assert_eq!(ledger.allocate_run(2), Some(2));
        ledger.release_run(4, 3);
        assert!(!ledger.is_taken(4) && !ledger.is_taken(6) && !ledger.is_lower(4));
        assert_eq!(ledger.allocate_run(1), Some(4));
        // No run left at the region's end: refused.
        let mut full = GateSlots::empty();
        for _ in 0..SLOTS - 1 {
            full.allocate();
        }
        assert_eq!(full.allocate_run(2), None);
        assert_eq!(full.allocate_run(1), Some(SLOTS as u16 - 1));
    }

    /// A large stack's top is its run's top, it starts with the ordinary stack's pages, may grow to
    /// 104 KiB, and stays clear of its run's lowest guard page; an ordinary stack is its slot.
    #[test]
    fn a_large_stack_spans_its_run() {
        let ordinary = stack(3, 0);
        assert_eq!(ordinary.top(), gate_slot_top(3));
        assert_eq!(ordinary.limit(), gate_slot_base(3) + PAGE_SIZE);
        assert_eq!(ordinary.capacity(), paging::GATE_STACK_PAGES);
        assert!(!ordinary.is_large());
        let large = GateStack {
            slot: 6,
            slots: paging::LARGE_STACK_SLOTS as u8,
            ..ordinary
        };
        assert!(large.is_large());
        assert_eq!(large.top(), gate_slot_top(8));
        assert_eq!(large.limit(), gate_slot_top(8) - 8 * PAGE_SIZE);
        assert_eq!(large.capacity(), 26);
        let grown = GateStack { pages: 26, ..large };
        assert_eq!(grown.top() - grown.limit(), 104 * 1024);
        assert!(
            grown.limit() > gate_slot_base(6),
            "the run's lowest guard stays unmapped"
        );
        assert_eq!(GateStack::NONE.mapped(), &[] as &[u32]);
    }

    // --- The parked stack ----------------------------------------------------

    /// An exit parks its own stack and hands back the one parked before it, whichever process's;
    /// a release takes whatever is parked. At most one stack waits at any time.
    #[test]
    fn the_park_holds_one_and_hands_back_the_previous() {
        let mut stacks = KernelStacks::empty();
        assert_eq!(stacks.take_parked(), None);
        assert_eq!(stacks.park(stack(1, 10)), None);
        assert_eq!(stacks.park(stack(2, 20)), Some(stack(1, 10)));
        assert_eq!(stacks.take_parked(), Some(stack(2, 20)));
        assert_eq!(stacks.take_parked(), None);
    }

    /// The exit-then-create sequence the respawn fixture drives: an exited thread's slot stays
    /// taken while its stack is parked (its pages are still mapped), and the next creation's
    /// release frees it before the allocation, so the thread after it gets the same slot back —
    /// unmapped first, never double-mapped.
    #[test]
    fn a_creation_after_an_exit_reuses_the_released_slot() {
        let mut stacks = KernelStacks::empty();
        let main = stacks.slots.allocate().unwrap();
        let first = stacks.slots.allocate().unwrap();
        assert_eq!((main, first), (0, 1));

        // The thread exits: its stack is parked, its slot still taken.
        assert_eq!(stacks.park(stack(first, 1)), None);
        assert!(stacks.slots.is_taken(first));

        // The next creation releases the parked stack before it allocates.
        let parked = stacks
            .take_parked()
            .expect("the exited thread's stack is parked");
        stacks.slots.release_run(parked.slot, parked.slots as u16);
        assert_eq!(stacks.slots.allocate(), Some(first));
        assert_eq!(stacks.take_parked(), None);
    }
}
