//! The nonpaged pool, in miniature: blocks of kernel memory taken at runtime and given back with
//! whatever holds them (a pipe's data queues), as Windows 2000 takes them from its nonpaged pool.
//!
//! The pool is a region of its own ([`layout::NONPAGED_POOL`]), its page tables made at boot and
//! shared by every directory, as the kernel stacks' are: a block mapped in them is mapped in every
//! address space, so any thread reaches it, whichever process it runs in. A block is a run of
//! whole pages, the lowest free run that fits; the ledger records which pages blocks hold, and a
//! block's frames are taken from the frame database and mapped when it is taken, unmapped and
//! given back when it goes ([`Block`]'s drop). Nothing is mapped in the region but live blocks.
//!
//! Running out is a status, never a panic: a request no free run fits, or one the frame database
//! has too few frames left for, gets no block (the caller answers STATUS_INSUFFICIENT_RESOURCES,
//! as Windows 2000's pool allocations fail).

use super::layout;
use super::paging::PAGE_SIZE;

/// How many pages the region holds: 4096 (16 MiB).
pub const PAGES: usize = (layout::NONPAGED_POOL.size() / PAGE_SIZE) as usize;

/// How many occupancy words the ledger holds.
const PAGE_WORDS: usize = PAGES / 64;

/// Which pages of the pool's region blocks hold.
pub struct PoolPages {
    occupied: [u64; PAGE_WORDS],
}

impl PoolPages {
    /// An empty ledger: every page free.
    pub const fn empty() -> Self {
        PoolPages {
            occupied: [0; PAGE_WORDS],
        }
    }

    /// Whether page `page` is taken.
    pub fn is_taken(&self, page: usize) -> bool {
        self.occupied[page / 64] & (1 << (page % 64)) != 0
    }

    fn mark(&mut self, page: usize, taken: bool) {
        let bit = 1 << (page % 64);
        if taken {
            self.occupied[page / 64] |= bit;
        } else {
            self.occupied[page / 64] &= !bit;
        }
    }

    /// Take the lowest run of `count` free pages (at least one): its first page; none when no free
    /// run is that long.
    pub fn allocate(&mut self, count: usize) -> Option<usize> {
        if count == 0 || count > PAGES {
            return None;
        }
        let mut run = 0;
        for page in 0..PAGES {
            if self.is_taken(page) {
                run = 0;
                continue;
            }
            run += 1;
            if run == count {
                let first = page + 1 - count;
                for taken in first..=page {
                    self.mark(taken, true);
                }
                return Some(first);
            }
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

#[cfg(target_arch = "x86")]
pub use target::*;

#[cfg(target_arch = "x86")]
mod target {
    use super::*;
    use crate::mem::frame::FrameState;
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
            layout::NONPAGED_POOL.holds(va) && va % PAGE_SIZE == 0,
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

    /// A block of at least `bytes` bytes, zeroed: the lowest free run of the region's pages, each
    /// mapped over a fresh frame. None when no free run fits, or the frame database runs out
    /// before every page has its frame (what was taken is given back).
    pub fn allocate(bytes: usize) -> Option<Block> {
        let pages = pages_for(bytes);
        with_database(|database| {
            let Parts {
                frames,
                pool,
                scratch,
                ..
            } = database.parts();
            let first = pool.allocate(pages)?;
            for page in first..first + pages {
                let Some(frame) = paging::try_allocate_frame(frames) else {
                    for mapped in first..page {
                        let frame = paging::unmap_pool_page(page_address(mapped));
                        frames.release(frame / PAGE_SIZE, FrameState::Free);
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

    impl Drop for Block {
        /// The block goes: its pages unmapped from the shared tables, their frames given back to
        /// the frame database, and the pages to the ledger.
        fn drop(&mut self) {
            with_database(|database| {
                let Parts { frames, pool, .. } = database.parts();
                for page in self.first..self.first + self.pages {
                    let frame = paging::unmap_pool_page(page_address(page));
                    frames.release(frame / PAGE_SIZE, FrameState::Free);
                }
                pool.release(self.first, self.pages);
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The region is 16 MiB of pages, and a page's address lies in it.
    #[test]
    fn the_ledger_spans_the_region() {
        assert_eq!(PAGES, 4096);
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
}
