//! Kernel page tables made on demand, and the list of live directories they are installed in.
//!
//! Most of the kernel half's page tables are made at boot, before the first process directory, and
//! every directory copies them with the rest of the kernel half when it is made
//! ([`super::paging::assemble_process_directory`]). A region that grows on demand cannot do that:
//! the nonpaged pool spans 256 MiB, 64 tables, and makes a table only when a block first reaches
//! its 4 MiB window ([`ON_DEMAND`]). The new table must then be seen by every address space at
//! once, because the pool is reached from any thread, at any level, with interrupts masked: a
//! missing directory entry cannot be repaired at a fault there.
//!
//! So a table made on demand is installed, before anything is mapped through it, in the master
//! directory and in every live process directory, as Windows 2000 keeps a master copy of the system
//! page directory entries (MmSystemPagePtes) that new directories copy and a new system entry is
//! written into. Windows 2000 repairs its paged pool's entries lazily, at the fault
//! (MiCheckPdeForPagedPool); F2K has no paged pool, and its on-demand regions must never fault, so
//! it propagates eagerly. The master is the boot directory, the address space the kernel returns to
//! between processes; a process directory is made from the current directory's kernel half, which
//! the propagation keeps equal to the master's.
//!
//! The live directories are a list ([`DirectoryList`]) threaded through the directories themselves:
//! two entries no region ever maps ([`layout::DIRECTORY_LINKS`]) hold each directory's next and
//! previous links, never present, so the processor ignores them. The list costs no memory and has
//! no cap; it is changed, like every directory entry, under the memory manager's database borrow,
//! so a directory being made cannot miss a table being installed (the copy and the link are one
//! step, as the table's making and its propagation are another).
//!
//! Tables made on demand are kept once made (the region's peak, as the slot pools keep theirs), and
//! counted ([`DirectoryList::tables_made`]) for the teardown audit's frame balance.
//!
//! The interface the rest of the kernel uses is [`DirectoryList::ensure`] over a virtual address
//! range, so a later PAE build, whose directory entries are 8 bytes and 2 MiB each (and whose
//! kernel-half directory pages could be shared outright), implements the same call over its own
//! entries. The kernel stack region (slot-pool slice 17) is the next user.

use core::ops::Range;

use super::layout::{self, Region, DIRECTORY_LINKS};
use super::paging::{directory_index, KERNEL_HALF_START, PT_ENTRIES};
use super::phys::{Pfn, PhysAddr, PhysWord};
use super::pte::Pte;

/// The regions whose page tables are made on demand: a range [`DirectoryList::ensure`] is asked
/// for lies in one of them. Their tables are made nowhere else.
pub const ON_DEMAND: [Region; 1] = [layout::NONPAGED_POOL];

/// The directory entry holding a directory's next link.
const NEXT: usize = DIRECTORY_LINKS.first_entry();

/// The directory entry holding a directory's previous link.
const PREV: usize = NEXT + 1;

const _: () = assert!(DIRECTORY_LINKS.entries == 2);

/// How many windows one propagation pass over the list carries.
const PASS: usize = 16;

/// The kernel half's directory entries, as bits of the made-table ledger.
const HALF_ENTRIES: usize = PT_ENTRIES - KERNEL_HALF_START;

/// A link as a directory entry holds it: the frame number shifted past the present bit, so the
/// entry is never present; zero is the end of the list (frame 0 is never a directory).
const fn encode(dir: Option<PhysAddr>) -> u32 {
    match dir {
        Some(dir) => dir.pfn().get() << 1,
        None => 0,
    }
}

/// The directory a link entry names.
fn decode(entry: u32) -> Option<PhysAddr> {
    debug_assert!(entry & 1 == 0, "a directory link is never present");
    (entry != 0).then(|| Pfn::new((entry >> 1) as PhysWord).addr())
}

/// What the install needs of the machine: each directory's entries, one directory at a time, and
/// fresh tables. On target, the scratch window and the frame database; in the host tests, plain
/// arrays.
pub trait Directories {
    /// Run `step` on the entries of the directory at `dir`.
    fn with_directory<R>(
        &mut self,
        dir: PhysAddr,
        step: impl FnOnce(&mut [u32; PT_ENTRIES]) -> R,
    ) -> R;

    /// A fresh page table, every entry zero; none when no frame is left.
    fn new_table(&mut self) -> Option<PhysAddr>;
}

/// No frame was left for a page table the range needed. The tables made before it are installed
/// everywhere and kept.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NoTable;

/// The live process directories (the master is not one of them), and the kernel-half windows whose
/// tables were made on demand.
pub struct DirectoryList {
    /// The most recently linked directory.
    head: Option<PhysAddr>,
    /// How many directories are linked.
    live: u32,
    /// Which kernel-half windows have their table made on demand, bit `entry - KERNEL_HALF_START`.
    made: [u64; HALF_ENTRIES / 64],
    /// How many tables were made on demand (each kept for good).
    tables: u32,
}

impl DirectoryList {
    /// No directory and no table made.
    pub const fn empty() -> Self {
        DirectoryList {
            head: None,
            live: 0,
            made: [0; HALF_ENTRIES / 64],
            tables: 0,
        }
    }

    /// How many process directories are live.
    #[cfg_attr(not(any(test, feature = "pool-smoke")), allow(dead_code))]
    pub fn live(&self) -> u32 {
        self.live
    }

    /// How many page tables were made on demand: their frames are the kernel's for good.
    pub fn tables_made(&self) -> u32 {
        self.tables
    }

    /// Whether the table of directory entry `window` was made on demand.
    pub fn is_made(&self, window: usize) -> bool {
        let bit = window - KERNEL_HALF_START;
        self.made[bit / 64] & (1 << (bit % 64)) != 0
    }

    fn mark_made(&mut self, window: usize) {
        let bit = window - KERNEL_HALF_START;
        self.made[bit / 64] |= 1 << (bit % 64);
        self.tables += 1;
    }

    /// Link the fresh directory at `dir`, its kernel half already copied from a live one (so it
    /// holds every table made so far): from now on every table made is installed in it too. Its
    /// link entries are overwritten.
    pub fn link(&mut self, machine: &mut impl Directories, dir: PhysAddr) {
        let head = self.head;
        machine.with_directory(dir, |entries| {
            entries[NEXT] = encode(head);
            entries[PREV] = encode(None);
        });
        if let Some(head) = head {
            machine.with_directory(head, |entries| entries[PREV] = encode(Some(dir)));
        }
        self.head = Some(dir);
        self.live += 1;
    }

    /// Unlink the directory at `dir`, which is going: no table is installed in it any more.
    ///
    /// # Panics
    ///
    /// `dir` is not linked (the list's head, or a directory with a previous link).
    pub fn unlink(&mut self, machine: &mut impl Directories, dir: PhysAddr) {
        let (next, prev) = machine.with_directory(dir, |entries| {
            let links = (decode(entries[NEXT]), decode(entries[PREV]));
            entries[NEXT] = encode(None);
            entries[PREV] = encode(None);
            links
        });
        match prev {
            Some(prev) => machine.with_directory(prev, |entries| entries[NEXT] = encode(next)),
            None => {
                assert_eq!(self.head, Some(dir), "unlinking a directory not linked");
                self.head = next;
            }
        }
        if let Some(next) = next {
            machine.with_directory(next, |entries| entries[PREV] = encode(prev));
        }
        self.live -= 1;
    }

    /// Run `step` on every linked directory's entries, the most recently linked first.
    pub fn for_each(
        &self,
        machine: &mut impl Directories,
        mut step: impl FnMut(PhysAddr, &mut [u32; PT_ENTRIES]),
    ) {
        let mut at = self.head;
        while let Some(dir) = at {
            at = machine.with_directory(dir, |entries| {
                step(dir, entries);
                decode(entries[NEXT])
            });
        }
    }

    /// Make sure every page table of the kernel addresses `range` exists, in the master directory
    /// at `master` and every linked directory: the windows' tables not made yet are made (zeroed)
    /// and installed everywhere before this returns, so a page mapped through them is mapped in
    /// every address space. A range whose tables are all made costs no directory access.
    ///
    /// # Errors
    ///
    /// [`NoTable`] when a frame for a table runs out: the tables made before it are installed
    /// everywhere and kept, and the range's caller gives up its pages.
    ///
    /// # Panics
    ///
    /// The range is empty or does not lie in one region of [`ON_DEMAND`], or the master already has
    /// a table at a window not made here.
    pub fn ensure(
        &mut self,
        machine: &mut impl Directories,
        master: PhysAddr,
        range: Range<u32>,
    ) -> Result<(), NoTable> {
        assert!(
            !range.is_empty()
                && ON_DEMAND
                    .iter()
                    .any(|region| region.holds(range.start) && range.end as u64 <= region.end()),
            "on-demand tables asked for outside the on-demand regions"
        );
        let windows = directory_index(range.start)..directory_index(range.end - 1) + 1;
        let mut first = windows.start;
        while first < windows.end {
            let end = (first + PASS).min(windows.end);
            let mut made = [0u32; PASS];
            let mut out = false;
            for window in first..end {
                if self.is_made(window) {
                    continue;
                }
                let Some(table) = machine.new_table() else {
                    out = true;
                    break;
                };
                made[window - first] = Pte::kernel_rw(table).raw();
                self.mark_made(window);
            }
            if made.iter().any(|&entry| entry != 0) {
                install(machine, master, first, &made);
                self.for_each(machine, |_, entries| install_in(entries, first, &made));
            }
            if out {
                return Err(NoTable);
            }
            first = end;
        }
        Ok(())
    }

    /// Whether every linked directory holds exactly the master's on-demand entries (the audit the
    /// tests and the pool's diagnostic run).
    #[cfg_attr(not(any(test, feature = "pool-smoke")), allow(dead_code))]
    pub fn in_step(&self, machine: &mut impl Directories, master: PhysAddr) -> bool {
        let mut same = true;
        for region in ON_DEMAND {
            let windows = region.first_entry()..region.end_entry();
            let mut reference = [0u32; REGION_MAX];
            let reference = &mut reference[..windows.len()];
            machine.with_directory(master, |entries| {
                reference.copy_from_slice(&entries[windows.clone()]);
            });
            self.for_each(machine, |_, entries| {
                same &= entries[windows.clone()]
                    .iter()
                    .zip(reference.iter())
                    .all(|(&entry, &master)| walked(entry) == walked(master));
            });
        }
        same
    }
}

/// The most directory entries an on-demand region spans.
const REGION_MAX: usize = 128;

const _: () = {
    let mut i = 0;
    while i < ON_DEMAND.len() {
        assert!(ON_DEMAND[i].entries <= REGION_MAX);
        i += 1;
    }
};

/// What of a directory entry the processor walks: its frame and its present bit. The accessed bit
/// differs between copies of the same entry (the processor sets it in the directory it walked).
const fn walked(entry: u32) -> u32 {
    super::pte::frame_bits(entry) | (entry & super::pte::PRESENT)
}

/// Install the made entries (`made[i]` for window `first + i`, zero for none) in the master.
fn install(machine: &mut impl Directories, master: PhysAddr, first: usize, made: &[u32; PASS]) {
    machine.with_directory(master, |entries| {
        for (i, &entry) in made.iter().enumerate() {
            if entry != 0 {
                assert!(
                    !Pte::from_raw(entries[first + i]).present(),
                    "an on-demand window already had a table"
                );
                entries[first + i] = entry;
            }
        }
    });
}

/// Install the made entries in one linked directory.
fn install_in(entries: &mut [u32; PT_ENTRIES], first: usize, made: &[u32; PASS]) {
    for (i, &entry) in made.iter().enumerate() {
        if entry != 0 {
            debug_assert!(!Pte::from_raw(entries[first + i]).present());
            entries[first + i] = entry;
        }
    }
}

/// The link entries a fresh directory must not inherit from the one its kernel half is copied from:
/// [`super::paging::assemble_process_directory`] clears them.
pub const LINK_ENTRIES: Range<usize> = NEXT..PREV + 1;

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::mem::paging::PAGE_SIZE;
    use crate::mem::pool;

    /// Directories and tables as plain arrays, frames numbered from 0x100, with a frame budget.
    struct Fake {
        frames: HashMap<u32, Box<[u32; PT_ENTRIES]>>,
        next: u32,
        budget: usize,
        accesses: usize,
    }

    impl Fake {
        fn new(budget: usize) -> Self {
            Fake {
                frames: HashMap::new(),
                next: 0x100,
                budget,
                accesses: 0,
            }
        }

        fn frame(&mut self) -> PhysAddr {
            let frame = Pfn::new(self.next).addr();
            self.next += 1;
            self.frames.insert(frame.get(), Box::new([0; PT_ENTRIES]));
            frame
        }

        /// A directory whose kernel half is copied from `from`'s, as `create_address_space`
        /// assembles one, link entries cleared.
        fn directory_from(&mut self, from: PhysAddr) -> PhysAddr {
            let dir = self.frame();
            let source = *self.frames[&from.get()];
            let entries = self.frames.get_mut(&dir.get()).unwrap();
            crate::mem::paging::assemble_process_directory(
                entries,
                dir,
                PhysAddr::new(0x7000),
                |i| source[i],
            );
            dir
        }

        fn entry(&self, dir: PhysAddr, index: usize) -> u32 {
            self.frames[&dir.get()][index]
        }
    }

    impl Directories for Fake {
        fn with_directory<R>(
            &mut self,
            dir: PhysAddr,
            step: impl FnOnce(&mut [u32; PT_ENTRIES]) -> R,
        ) -> R {
            self.accesses += 1;
            step(self.frames.get_mut(&dir.get()).expect("a known frame"))
        }

        fn new_table(&mut self) -> Option<PhysAddr> {
            if self.budget == 0 {
                return None;
            }
            self.budget -= 1;
            Some(self.frame())
        }
    }

    const POOL: Region = layout::NONPAGED_POOL;

    /// The address `bytes` into the pool's region.
    fn at(bytes: u32) -> u32 {
        POOL.start + bytes
    }

    const WINDOW: u32 = layout::ENTRY_SPAN;

    /// A table made on demand lands in the master and in every directory linked before it; a
    /// directory made afterwards copies it; the list hands every linked directory to the walk.
    #[test]
    fn a_new_table_reaches_every_directory() {
        let mut fake = Fake::new(100);
        let master = fake.frame();
        let mut list = DirectoryList::empty();
        let a = fake.directory_from(master);
        list.link(&mut fake, a);
        let b = fake.directory_from(a);
        list.link(&mut fake, b);
        assert_eq!(list.live(), 2);

        list.ensure(&mut fake, master, at(0)..at(PAGE_SIZE))
            .unwrap();
        let window = POOL.first_entry();
        let entry = fake.entry(master, window);
        assert!(Pte::from_raw(entry).present());
        assert_eq!(fake.entry(a, window), entry);
        assert_eq!(fake.entry(b, window), entry);
        assert_eq!(list.tables_made(), 1);

        let c = fake.directory_from(b);
        list.link(&mut fake, c);
        assert_eq!(fake.entry(c, window), entry, "copied with the kernel half");
        assert!(list.in_step(&mut fake, master));
        // The processor sets the accessed bit in the directory it walks: not a difference.
        fake.frames.get_mut(&master.get()).unwrap()[window] |= crate::mem::pte::ACCESSED;
        assert!(list.in_step(&mut fake, master));
        // A directory missing the entry is one.
        fake.frames.get_mut(&b.get()).unwrap()[window] = 0;
        assert!(!list.in_step(&mut fake, master));
        fake.frames.get_mut(&b.get()).unwrap()[window] = entry;

        let mut seen = Vec::new();
        list.for_each(&mut fake, |dir, _| seen.push(dir));
        assert_eq!(seen, [c, b, a]);
    }

    /// A range across windows makes each missing table once; a range whose tables are made costs
    /// no directory access at all.
    #[test]
    fn a_range_makes_only_its_missing_tables() {
        let mut fake = Fake::new(100);
        let master = fake.frame();
        let mut list = DirectoryList::empty();
        let a = fake.directory_from(master);
        list.link(&mut fake, a);
        list.ensure(&mut fake, master, at(WINDOW)..at(WINDOW + 1))
            .unwrap();
        assert_eq!(list.tables_made(), 1);
        // Windows 0 to 2: 0 and 2 are new.
        list.ensure(
            &mut fake,
            master,
            at(WINDOW - PAGE_SIZE)..at(2 * WINDOW + PAGE_SIZE),
        )
        .unwrap();
        assert_eq!(list.tables_made(), 3);
        for window in POOL.first_entry()..POOL.first_entry() + 3 {
            assert!(list.is_made(window));
            assert!(Pte::from_raw(fake.entry(a, window)).present());
        }
        assert!(!list.is_made(POOL.first_entry() + 3));
        let before = fake.accesses;
        list.ensure(&mut fake, master, at(0)..at(3 * WINDOW))
            .unwrap();
        assert_eq!(fake.accesses, before, "nothing to make, nothing read");
        assert_eq!(list.tables_made(), 3);
        assert!(list.in_step(&mut fake, master));
    }

    /// The whole region's 64 tables, past one propagation pass, land everywhere.
    #[test]
    fn the_whole_region_takes_every_pass() {
        let mut fake = Fake::new(100);
        let master = fake.frame();
        let mut list = DirectoryList::empty();
        let dirs: Vec<_> = (0..5)
            .map(|_| {
                let dir = fake.directory_from(master);
                list.link(&mut fake, dir);
                dir
            })
            .collect();
        list.ensure(&mut fake, master, POOL.start..POOL.start + POOL.size())
            .unwrap();
        assert_eq!(list.tables_made(), 64);
        assert_eq!(pool::PAGES, 64 * PT_ENTRIES);
        for dir in dirs {
            for window in POOL.first_entry()..POOL.end_entry() {
                assert!(Pte::from_raw(fake.entry(dir, window)).present());
            }
        }
        assert!(list.in_step(&mut fake, master));
    }

    /// Running out of frames is a status: the tables made before it are installed everywhere and
    /// kept, and a later call with frames makes the rest.
    #[test]
    fn running_out_keeps_what_was_made() {
        let mut fake = Fake::new(2);
        let master = fake.frame();
        let mut list = DirectoryList::empty();
        let a = fake.directory_from(master);
        list.link(&mut fake, a);
        assert_eq!(
            list.ensure(&mut fake, master, at(0)..at(4 * WINDOW)),
            Err(NoTable)
        );
        assert_eq!(list.tables_made(), 2);
        assert!(list.in_step(&mut fake, master));
        assert!(Pte::from_raw(fake.entry(a, POOL.first_entry() + 1)).present());
        assert!(!Pte::from_raw(fake.entry(a, POOL.first_entry() + 2)).present());
        fake.budget = 2;
        list.ensure(&mut fake, master, at(0)..at(4 * WINDOW))
            .unwrap();
        assert_eq!(list.tables_made(), 4);
        assert!(list.in_step(&mut fake, master));
    }

    /// Unlinking from the head, the middle and the tail keeps the list whole; an unlinked
    /// directory gets no later table, and its links are cleared.
    #[test]
    fn unlinked_directories_leave_the_list() {
        let mut fake = Fake::new(100);
        let master = fake.frame();
        let mut list = DirectoryList::empty();
        let dirs: Vec<_> = (0..5)
            .map(|_| {
                let dir = fake.directory_from(master);
                list.link(&mut fake, dir);
                dir
            })
            .collect();
        let order = |list: &DirectoryList, fake: &mut Fake| {
            let mut seen = Vec::new();
            list.for_each(fake, |dir, _| seen.push(dir));
            seen
        };
        list.unlink(&mut fake, dirs[2]);
        assert_eq!(
            order(&list, &mut fake),
            [dirs[4], dirs[3], dirs[1], dirs[0]]
        );
        list.unlink(&mut fake, dirs[4]);
        assert_eq!(order(&list, &mut fake), [dirs[3], dirs[1], dirs[0]]);
        list.unlink(&mut fake, dirs[0]);
        assert_eq!(order(&list, &mut fake), [dirs[3], dirs[1]]);
        assert_eq!(list.live(), 2);
        for gone in [dirs[0], dirs[2], dirs[4]] {
            assert_eq!(fake.entry(gone, NEXT), 0);
            assert_eq!(fake.entry(gone, PREV), 0);
        }
        list.ensure(&mut fake, master, at(0)..at(1)).unwrap();
        let window = POOL.first_entry();
        assert!(Pte::from_raw(fake.entry(dirs[1], window)).present());
        assert!(!Pte::from_raw(fake.entry(dirs[2], window)).present());
        list.unlink(&mut fake, dirs[1]);
        list.unlink(&mut fake, dirs[3]);
        assert_eq!(list.live(), 0);
        assert!(order(&list, &mut fake).is_empty());
    }

    /// A directory not linked is refused, not unlinked silently.
    #[test]
    fn unlinking_a_stranger_panics() {
        let mut fake = Fake::new(1);
        let master = fake.frame();
        let mut list = DirectoryList::empty();
        let a = fake.directory_from(master);
        list.link(&mut fake, a);
        let stranger = fake.directory_from(master);
        let refused = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            list.unlink(&mut fake, stranger)
        }));
        assert!(refused.is_err());
    }

    /// The links are never present entries, so the processor ignores them; a new directory does
    /// not inherit its source's.
    #[test]
    fn links_are_never_present_and_never_inherited() {
        let mut fake = Fake::new(1);
        let master = fake.frame();
        let mut list = DirectoryList::empty();
        let a = fake.directory_from(master);
        list.link(&mut fake, a);
        let b = fake.directory_from(a);
        assert_eq!(fake.entry(b, NEXT), 0, "the copy clears the links");
        list.link(&mut fake, b);
        assert_eq!(decode(fake.entry(b, NEXT)), Some(a));
        assert_eq!(decode(fake.entry(a, PREV)), Some(b));
        for dir in [a, b] {
            for index in LINK_ENTRIES {
                assert!(!Pte::from_raw(fake.entry(dir, index)).present());
            }
        }
        assert_eq!(encode(Some(PhysAddr::new(0xFFFF_F000))), 0xF_FFFF << 1);
        assert_eq!(
            decode(encode(Some(PhysAddr::new(0xFFFF_F000)))),
            Some(PhysAddr::new(0xFFFF_F000))
        );
    }

    /// Only the on-demand regions' tables are made here.
    #[test]
    fn a_range_outside_the_on_demand_regions_is_refused() {
        let mut fake = Fake::new(1);
        let master = fake.frame();
        let mut list = DirectoryList::empty();
        for range in [
            layout::MODULES.start..layout::MODULES.start + 1,
            POOL.start - 1..POOL.start + 1,
            at(0)..at(0),
        ] {
            let refused = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                list.ensure(&mut fake, master, range.clone())
            }));
            assert!(refused.is_err(), "{range:x?}");
        }
    }
}
