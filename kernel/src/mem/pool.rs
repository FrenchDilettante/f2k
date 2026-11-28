//! The nonpaged pool, in miniature: blocks of kernel memory taken at runtime and given back with
//! whatever holds them (a pipe's data queues), as Windows 2000 takes them from its nonpaged pool.
//!
//! The pool is a region of its own ([`layout::NONPAGED_POOL`], 256 MiB), its page tables shared by
//! every directory, as the kernel stacks' are: a block mapped in them is mapped in every address
//! space, so any thread reaches it, whichever process it runs in. The tables are made on demand,
//! when a block first reaches a window, and installed in every directory before the block is
//! mapped ([`crate::mem::ktables`]); a table once made is kept. A block is a run of whole pages,
//! the lowest free run that fits; the ledger records which pages blocks hold, and a block's frames
//! are taken from the frame database and mapped when it is taken, unmapped and given back when it
//! goes ([`Block`]'s drop). Nothing is mapped in the region but live blocks.
//!
//! Running out is a status, never a panic: a request no free run fits, or one the frame database
//! has too few frames left for (its pages' or a new table's), gets no block (the caller answers
//! STATUS_INSUFFICIENT_RESOURCES, as Windows 2000's pool allocations fail).

use super::layout;
use super::paging::PAGE_SIZE;
use super::phys::{self, Pfn};

/// How many pages the region holds: 65,536 (256 MiB).
pub const PAGES: usize = (layout::NONPAGED_POOL.size() / PAGE_SIZE) as usize;

/// How many pages one directory entry's window holds (a page table's worth).
pub const ENTRY_PAGES: usize = (layout::ENTRY_SPAN / PAGE_SIZE) as usize;

/// How many directory entries the region spans.
const ENTRIES: usize = layout::NONPAGED_POOL.entries;

/// How many occupancy words the ledger holds.
const PAGE_WORDS: usize = PAGES / 64;

const _: () = assert!(PAGES == ENTRIES * ENTRY_PAGES && ENTRY_PAGES.is_multiple_of(64));
const _: () = assert!(ENTRY_PAGES <= u16::MAX as usize);

/// Which pages of the pool's region blocks hold: a bit per page (8 KiB for the 256 MiB region),
/// and per directory entry's window the count of its free pages, so the search for a free run
/// steps over a full window, or a wholly free one too short to end the run, without reading its
/// bits.
pub struct PoolPages {
    occupied: [u64; PAGE_WORDS],
    free: [u16; ENTRIES],
}

impl PoolPages {
    /// An empty ledger: every page free.
    pub const fn empty() -> Self {
        PoolPages {
            occupied: [0; PAGE_WORDS],
            free: [ENTRY_PAGES as u16; ENTRIES],
        }
    }

    /// Whether page `page` is taken.
    pub fn is_taken(&self, page: usize) -> bool {
        self.occupied[page / 64] & (1 << (page % 64)) != 0
    }

    /// How many pages of directory entry `entry`'s window (the region's `entry`th) are free.
    pub fn free_in_entry(&self, entry: usize) -> usize {
        self.free[entry] as usize
    }

    fn mark(&mut self, page: usize, taken: bool) {
        let bit = 1 << (page % 64);
        let free = &mut self.free[page / ENTRY_PAGES];
        if taken {
            self.occupied[page / 64] |= bit;
            *free -= 1;
        } else {
            self.occupied[page / 64] &= !bit;
            *free += 1;
        }
    }

    /// Take the lowest run of `count` free pages (at least one): its first page; none when no free
    /// run is that long.
    pub fn allocate(&mut self, count: usize) -> Option<usize> {
        let first = self.lowest_run(count)?;
        for page in first..first + count {
            self.mark(page, true);
        }
        Some(first)
    }

    /// The first page of the lowest run of `count` free pages. A window with no free page ends any
    /// run; a wholly free window, or a wholly free word of the bits, that cannot end the run either
    /// only lengthens it; only the rest is read a page at a time.
    fn lowest_run(&self, count: usize) -> Option<usize> {
        if count == 0 || count > PAGES {
            return None;
        }
        let mut run = 0;
        let mut page = 0;
        while page < PAGES {
            if page.is_multiple_of(ENTRY_PAGES) {
                let free = self.free_in_entry(page / ENTRY_PAGES);
                if free == 0 {
                    run = 0;
                    page += ENTRY_PAGES;
                    continue;
                }
                if free == ENTRY_PAGES && run + ENTRY_PAGES < count {
                    run += ENTRY_PAGES;
                    page += ENTRY_PAGES;
                    continue;
                }
            }
            if page.is_multiple_of(64) {
                let word = self.occupied[page / 64];
                if word == u64::MAX {
                    run = 0;
                    page += 64;
                    continue;
                }
                if word == 0 && run + 64 < count {
                    run += 64;
                    page += 64;
                    continue;
                }
            }
            if self.is_taken(page) {
                run = 0;
            } else {
                run += 1;
                if run == count {
                    return Some(page + 1 - count);
                }
            }
            page += 1;
        }
        None
    }

    /// Free the `count` pages from `first`. Panics on a page already free (its frame would be
    /// given back twice).
    pub fn release(&mut self, first: usize, count: usize) {
        for page in first..first + count {
            assert!(self.is_taken(page), "double release of pool page {page}");
            self.mark(page, false);
        }
    }

    /// How many pages blocks hold.
    #[cfg(test)]
    pub fn taken(&self) -> usize {
        self.occupied
            .iter()
            .map(|word| word.count_ones() as usize)
            .sum()
    }
}

/// The address of the pool's page `page`.
pub const fn page_address(page: usize) -> u32 {
    layout::NONPAGED_POOL.start + page as u32 * PAGE_SIZE
}

/// The pages a block of `bytes` takes: whole pages, at least one.
pub fn pages_for(bytes: usize) -> usize {
    bytes.div_ceil(PAGE_SIZE as usize).max(1)
}

/// The frames a 32-bit bus master reaches: those below 4 GiB. A contiguous block for a device
/// stays below it ([`contiguous_run`]), however wide a physical address grows.
pub const BUS_FRAME_LIMIT: u32 = 1 << 20;

/// The lowest run of `count` consecutive frames, each `usable`, among frames 1 to `frames` - 1
/// (frame 0 is never handed out) and below 4 GiB: its first frame number. None when no such run
/// exists. The search a physically contiguous block ([`allocate_contiguous`]) takes its frames
/// by.
pub fn contiguous_run(frames: u32, count: u32, usable: impl Fn(Pfn) -> bool) -> Option<Pfn> {
    // Frames past 4 GiB are out of a 32-bit bus master's reach, whatever a physical address's
    // width ([`phys::PhysWord`]).
    let end = frames.min(BUS_FRAME_LIMIT);
    if count == 0 {
        return None;
    }
    let mut run = 0;
    for frame in phys::frames(Pfn::new(1)..Pfn::new(end)) {
        if usable(frame) {
            run += 1;
            if run == count {
                return Some(frame + 1 - count);
            }
        } else {
            run = 0;
        }
    }
    None
}

#[cfg(target_arch = "x86")]
pub use target::*;

#[cfg(target_arch = "x86")]
mod target {
    use super::*;
    use crate::mem::frame::{FrameFlags, FrameState};
    use crate::mem::{paging, with_database, Parts};

    /// A block of the pool: `len` bytes at the start of its pages, which are mapped (in every
    /// address space) for as long as the block lives and given back when it is dropped. It is
    /// the only way to its memory, so it hands out its bytes as any owned buffer does.
    pub struct Block {
        first: usize,
        pages: usize,
        len: usize,
    }

    impl Block {
        fn address(&self) -> *mut u8 {
            page_address(self.first) as *mut u8
        }

        /// The block's virtual address: the start of its pages in the pool's region. The DMA
        /// layer's registry owns a block by this address rather than by the `Block` itself.
        pub fn virtual_address(&self) -> u32 {
            page_address(self.first)
        }

        /// The block kept for the kernel's life: its bytes, which nothing gives back (a cache a
        /// mount holds for as long as the system runs).
        pub fn leak(self) -> &'static mut [u8] {
            let (at, len) = (self.address(), self.len);
            core::mem::forget(self);
            // SAFETY: the block's pages are mapped in every address space and its alone (see
            // `as_ref`); forgotten, the block never unmaps them, and nothing else names them.
            unsafe { core::slice::from_raw_parts_mut(at, len) }
        }
    }

    /// `count` values, each `fresh()`, in a block kept for the kernel's life (a table sized at
    /// the boot, as the runner's audit ledger is by its legs): none when the pool has no room.
    pub fn leak_array<T>(count: usize, fresh: impl Fn() -> T) -> Option<&'static mut [T]> {
        const { assert!(core::mem::align_of::<T>() <= PAGE_SIZE as usize) };
        let bytes = (count * core::mem::size_of::<T>()).max(1);
        let at = allocate(bytes)?.leak().as_mut_ptr().cast::<T>();
        for index in 0..count {
            // SAFETY: the block holds `count` values from its page-aligned start, and is ours.
            unsafe { at.add(index).write(fresh()) };
        }
        // SAFETY: every value written above; the block is kept and named by nothing else.
        Some(unsafe { core::slice::from_raw_parts_mut(at, count) })
    }

    /// Release the block at virtual address `va` that [`allocate`] handed out for `bytes`:
    /// reconstructs the block and drops it (its pages unmapped, their frames and the pages
    /// themselves given back), as the DMA layer's free path does with a registry record.
    ///
    /// # Panics
    ///
    /// `va` lies outside the pool's region, is not page-aligned, or names no live block.
    pub fn release_block(va: u32, bytes: usize) {
        assert!(
            layout::NONPAGED_POOL.holds(va) && va.is_multiple_of(PAGE_SIZE),
            "a block address outside the nonpaged pool"
        );
        let first = ((va - layout::NONPAGED_POOL.start) / PAGE_SIZE) as usize;
        drop(Block {
            first,
            pages: pages_for(bytes),
            len: bytes,
        });
    }

    impl AsRef<[u8]> for Block {
        fn as_ref(&self) -> &[u8] {
            // SAFETY: the block's pages are mapped, writable and its alone from its allocation to
            // its drop (the ledger hands a page to one block at a time), and `len` lies inside
            // them; the borrow of `self` keeps the block alive for the slice's life.
            unsafe { core::slice::from_raw_parts(self.address(), self.len) }
        }
    }

    impl AsMut<[u8]> for Block {
        fn as_mut(&mut self) -> &mut [u8] {
            // SAFETY: as in `as_ref`; the exclusive borrow of the block makes this the only
            // reference to its memory.
            unsafe { core::slice::from_raw_parts_mut(self.address(), self.len) }
        }
    }

    /// The addresses of the `pages` pages from page `first`.
    fn span(first: usize, pages: usize) -> core::ops::Range<u32> {
        page_address(first)..page_address(first + pages)
    }

    /// A block of at least `bytes` bytes, zeroed: the lowest free run of the region's pages, each
    /// mapped over a fresh frame, the run's page tables made first where missing. None when no
    /// free run fits, or the frame database runs out before every page has its frame or table
    /// (what was taken is given back; a table made stays).
    pub fn allocate(bytes: usize) -> Option<Block> {
        let pages = pages_for(bytes);
        with_database(|database| {
            let Parts {
                frames,
                pool,
                scratch,
                directories,
                ..
            } = database.parts();
            let first = pool.allocate(pages)?;
            if paging::ensure_kernel_tables(frames, scratch, directories, span(first, pages))
                .is_err()
            {
                pool.release(first, pages);
                return None;
            }
            for page in first..first + pages {
                let Some(frame) = paging::try_allocate_frame(frames) else {
                    for mapped in first..page {
                        let frame = paging::unmap_pool_page(page_address(mapped));
                        frames.release(frame.pfn(), FrameState::Free);
                    }
                    pool.release(first, pages);
                    return None;
                };
                paging::map_pool_page(frames, scratch, page_address(page), frame);
            }
            Some(Block {
                first,
                pages,
                len: bytes,
            })
        })
    }

    /// A block of at least `bytes` bytes, zeroed, over physically contiguous frames (the lowest
    /// run of free or zeroed frames, flagless, below 4 GiB, [`contiguous_run`]): what a common
    /// buffer's one logical address needs. None when no free run of the region's pages fits, or
    /// no run of frames is long enough (what was taken is given back).
    pub fn allocate_contiguous(bytes: usize) -> Option<Block> {
        let pages = pages_for(bytes);
        with_database(|database| {
            let Parts {
                frames,
                pool,
                scratch,
                directories,
                ..
            } = database.parts();
            let first = pool.allocate(pages)?;
            if paging::ensure_kernel_tables(frames, scratch, directories, span(first, pages))
                .is_err()
            {
                pool.release(first, pages);
                return None;
            }
            let run = contiguous_run(frames.frame_count(), pages as u32, |frame| {
                let entry = frames.entry(frame);
                entry.state.has_color_chain() && entry.flags == FrameFlags::empty()
            });
            let Some(base) = run else {
                pool.release(first, pages);
                return None;
            };
            for page in 0..pages {
                let frame = base + page as u32;
                frames.take(frame);
                paging::map_pool_page(frames, scratch, page_address(first + page), frame.addr());
            }
            Some(Block {
                first,
                pages,
                len: bytes,
            })
        })
    }

    /// The pool's growth diagnostic (the `pool-smoke` boot), once the subsystems are up and before
    /// the first process: a directory made first, then blocks of 1 MiB until they run past the
    /// old 16 MiB region (the region before it grew to 256 MiB), each window's table made as a
    /// block first reaches it; then a second directory. Every live directory must hold every new
    /// table, the directory made before the growth must read a block's bytes through them, and the
    /// tables must stay when the blocks go. Reported on COM1; nothing is left behind but the
    /// tables.
    #[cfg(feature = "pool-smoke")]
    pub fn smoke() {
        use crate::level::{raised, High};
        const MIB: usize = 0x10_0000;
        const OLD_END: u32 = layout::NONPAGED_POOL.start + 4096 * PAGE_SIZE;
        let yes = |ok: bool| if ok { "yes" } else { "no" };

        let directories = paging::live_directories();
        let early = paging::create_address_space();
        let tables = paging::kernel_table_frames();
        let mut blocks: [Option<Block>; 48] = [const { None }; 48];
        let mut count = 0;
        while count < blocks.len() {
            let Some(mut block) = allocate(MIB) else {
                break;
            };
            let marker = 0xF2C0_0000 | count as u32;
            block.as_mut()[..4].copy_from_slice(&marker.to_le_bytes());
            let past = block.virtual_address() >= OLD_END;
            blocks[count] = Some(block);
            count += 1;
            if past {
                break;
            }
        }
        let last = blocks[..count].iter().flatten().last();
        let grown = last.is_some_and(|block| block.virtual_address() >= OLD_END);
        crate::klog!(
            Debug,
            "smoke",
            "pool-smoke: {count} blocks of 1 MiB, past the old 16 MiB region: {}",
            yes(grown)
        );
        let made = paging::kernel_table_frames() - tables;
        crate::klog!(
            Debug,
            "smoke",
            "pool-smoke: tables made for the growth: {}",
            yes(made > 0)
        );
        let late = paging::create_address_space();
        let in_step = paging::directories_in_step();
        crate::klog!(
            Debug,
            "smoke",
            "pool-smoke: every directory holds the new tables: {}",
            yes(in_step)
        );

        // Read the last block's marker in the directory made before the growth: the processor
        // walks that directory's own entry for the block's window.
        let seen = last.map(|block| {
            let at = block.virtual_address() as *const u32;
            raised::<High, _>(|_| {
                let home = paging::current_directory_phys();
                paging::activate_address_space(early);
                // SAFETY: the block is live and mapped in every directory (the check above);
                // interrupts are masked, so nothing runs in the early directory but this read.
                let word = unsafe { at.read_volatile() };
                paging::activate_address_space(home);
                word
            })
        });
        let expected = 0xF2C0_0000 | (count as u32).wrapping_sub(1);
        crate::klog!(
            Debug,
            "smoke",
            "pool-smoke: a directory made before the growth reads the new pages: {}",
            yes(seen == Some(expected))
        );

        for block in blocks.iter_mut() {
            drop(block.take());
        }
        for dir in [early, late] {
            paging::retire_address_space(dir);
            paging::release_frame_phys(dir);
        }
        let kept = paging::kernel_table_frames() == tables + made
            && paging::live_directories() == directories;
        crate::klog!(
            Debug,
            "smoke",
            "pool-smoke: blocks given back, tables kept, directories retired: {}",
            yes(kept)
        );
    }

    impl Drop for Block {
        /// The block goes: its pages unmapped from the shared tables, their frames given back to
        /// the frame database, and the pages to the ledger.
        fn drop(&mut self) {
            with_database(|database| {
                let Parts { frames, pool, .. } = database.parts();
                for page in self.first..self.first + self.pages {
                    let frame = paging::unmap_pool_page(page_address(page));
                    frames.release(frame.pfn(), FrameState::Free);
                }
                pool.release(self.first, self.pages);
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The region is 256 MiB of pages, and a page's address lies in it.
    #[test]
    fn the_ledger_spans_the_region() {
        assert_eq!(PAGES, 65_536);
        assert_eq!(ENTRY_PAGES, 1024);
        assert_eq!(core::mem::size_of::<PoolPages>(), 8192 + 128);
        assert_eq!(page_address(0), layout::NONPAGED_POOL.start);
        assert!(layout::NONPAGED_POOL.holds(page_address(PAGES - 1)));
        assert!(!layout::NONPAGED_POOL.holds(page_address(PAGES)));
    }

    /// A block takes whole pages: a default pipe ring's 4100 bytes two.
    #[test]
    fn blocks_take_whole_pages() {
        assert_eq!(pages_for(1), 1);
        assert_eq!(pages_for(4096), 1);
        assert_eq!(pages_for(4100), 2);
        assert_eq!(pages_for(65540), 17);
        assert_eq!(pages_for(0), 1);
    }

    /// A contiguous run of frames is the lowest of the length asked, skipping frame 0 and
    /// stopping below 4 GiB; none when no run is long enough.
    #[test]
    fn a_contiguous_run_of_frames_is_the_lowest_that_fits() {
        // Frames 1-3 usable, 4 not, 5-20 usable.
        let usable = |frame: Pfn| frame != Pfn::new(4);
        let at = |frame| Some(Pfn::new(frame));
        assert_eq!(contiguous_run(32, 1, usable), at(1), "never frame 0");
        assert_eq!(contiguous_run(32, 3, usable), at(1));
        assert_eq!(
            contiguous_run(32, 4, usable),
            at(5),
            "past the unusable frame"
        );
        assert_eq!(contiguous_run(32, 16, usable), at(5));
        assert_eq!(
            contiguous_run(21, 16, usable),
            at(5),
            "ending at the last frame"
        );
        assert_eq!(contiguous_run(20, 16, usable), None, "one frame short");
        assert_eq!(contiguous_run(32, 0, usable), None);
        // Nothing at or past 4 GiB (frame 0x10_0000).
        let high = |frame: Pfn| frame >= Pfn::new(0xF_FFFF);
        assert_eq!(BUS_FRAME_LIMIT, 0x10_0000);
        assert_eq!(contiguous_run(u32::MAX, 2, high), None);
        assert_eq!(contiguous_run(u32::MAX, 1, high), at(0xF_FFFF));
    }

    /// Runs are taken lowest first, a freed run is reused, and a run too long for any gap goes
    /// past it.
    #[test]
    fn runs_are_taken_lowest_first() {
        let mut pages = PoolPages::empty();
        assert_eq!(pages.allocate(2), Some(0));
        assert_eq!(pages.allocate(3), Some(2));
        assert_eq!(pages.allocate(1), Some(5));
        pages.release(0, 2);
        assert_eq!(pages.allocate(3), Some(6), "the two-page gap is too short");
        assert_eq!(pages.allocate(2), Some(0), "the gap fits two");
        assert_eq!(pages.taken(), 2 + 3 + 1 + 3);
        assert_eq!(pages.allocate(0), None);
    }

    /// A full region refuses the next block as a status; a release makes room again; a double
    /// release panics.
    #[test]
    fn a_full_region_refuses_and_a_release_makes_room() {
        let mut pages = PoolPages::empty();
        assert_eq!(pages.allocate(PAGES), Some(0));
        assert_eq!(pages.allocate(1), None);
        pages.release(100, 10);
        assert_eq!(pages.allocate(11), None);
        assert_eq!(pages.allocate(10), Some(100));
        pages.release(100, 1);
        let refused =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| pages.release(100, 1)));
        assert!(refused.is_err(), "a double release is refused");
    }

    /// The plain search the ledger's skips must agree with: the lowest run of `count` free pages,
    /// page by page.
    fn naive_run(pages: &PoolPages, count: usize) -> Option<usize> {
        let mut run = 0;
        for page in 0..PAGES {
            if pages.is_taken(page) {
                run = 0;
            } else {
                run += 1;
                if run == count {
                    return Some(page + 1 - count);
                }
            }
        }
        None
    }

    /// Blocks go on past the old 16 MiB region's 4,096 pages, into windows the old region never
    /// had, and each window's free count follows its pages.
    #[test]
    fn the_pool_grows_past_its_old_size() {
        let mut pages = PoolPages::empty();
        let mut firsts = Vec::new();
        for _ in 0..20 {
            firsts.push(pages.allocate(256).expect("room in the region"));
        }
        assert_eq!(
            firsts[16], 4096,
            "the 17th MiB starts where the old region ended"
        );
        assert_eq!(pages.taken(), 20 * 256);
        assert_eq!(pages.free_in_entry(0), 0);
        assert_eq!(pages.free_in_entry(3), 0);
        assert_eq!(pages.free_in_entry(4), ENTRY_PAGES - 4 * 256);
        assert_eq!(pages.free_in_entry(5), ENTRY_PAGES);
        assert!(layout::NONPAGED_POOL.holds(page_address(firsts[19] + 255)));
        pages.release(firsts[2], 256);
        assert_eq!(pages.free_in_entry(0), 256);
        assert_eq!(pages.allocate(256), Some(firsts[2]), "the lowest run first");
        for first in firsts {
            pages.release(first, 256);
        }
        assert_eq!(pages.taken(), 0);
        assert!((0..ENTRIES).all(|entry| pages.free_in_entry(entry) == ENTRY_PAGES));
    }

    /// The whole region in one block, then nothing; a run across a window's edge; a run longer
    /// than a window.
    #[test]
    fn runs_cross_windows_and_fill_the_region() {
        let mut pages = PoolPages::empty();
        assert_eq!(pages.allocate(ENTRY_PAGES - 10), Some(0));
        assert_eq!(
            pages.allocate(20),
            Some(ENTRY_PAGES - 10),
            "across the edge"
        );
        assert_eq!(pages.free_in_entry(0), 0);
        assert_eq!(pages.free_in_entry(1), ENTRY_PAGES - 10);
        assert_eq!(pages.allocate(3 * ENTRY_PAGES), Some(ENTRY_PAGES + 10));
        pages.release(0, ENTRY_PAGES - 10);
        pages.release(ENTRY_PAGES - 10, 20);
        pages.release(ENTRY_PAGES + 10, 3 * ENTRY_PAGES);
        assert_eq!(pages.allocate(PAGES), Some(0));
        assert_eq!(pages.allocate(1), None);
        assert!((0..ENTRIES).all(|entry| pages.free_in_entry(entry) == 0));
        pages.release(PAGES - 1, 1);
        assert_eq!(pages.allocate(1), Some(PAGES - 1), "the very last page");
        assert_eq!(pages.allocate(PAGES + 1), None);
    }

    /// The skips over full and wholly free windows and words find what the plain search finds,
    /// over a long run of random takes and releases.
    #[test]
    fn the_skipping_search_agrees_with_the_plain_one() {
        let mut pages = PoolPages::empty();
        let mut live: Vec<(usize, usize)> = Vec::new();
        // A small linear congruential generator: the same sequence every run.
        let mut seed = 0x2545_F491u32;
        let mut next = move || {
            seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            seed >> 8
        };
        let rounds = if cfg!(miri) { 40 } else { 3000 };
        for _ in 0..rounds {
            if live.is_empty() || next() % 3 != 0 {
                let count = match next() % 4 {
                    0 => 1 + next() as usize % 8,
                    1 => 1 + next() as usize % 100,
                    2 => 60 + next() as usize % 10,
                    _ => 900 + next() as usize % 300,
                };
                let expected = naive_run(&pages, count);
                assert_eq!(pages.lowest_run(count), expected, "a run of {count}");
                if let Some(first) = pages.allocate(count) {
                    live.push((first, count));
                }
            } else {
                let (first, count) = live.swap_remove(next() as usize % live.len());
                pages.release(first, count);
            }
        }
        for entry in 0..ENTRIES {
            let window = entry * ENTRY_PAGES..(entry + 1) * ENTRY_PAGES;
            let free = window.filter(|&page| !pages.is_taken(page)).count();
            assert_eq!(pages.free_in_entry(entry), free);
        }
    }
}
