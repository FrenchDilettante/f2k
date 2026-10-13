//! Kernel heap: a fixed-pool allocator for loader and runtime
//! structures.
//!
//! Design: one static pool, blocks carved from a doubly-linked free
//! list, first fit. Block layout (offsets from the pool base, all
//! sizes multiples of 8):
//!
//! ```text
//! off + 0  payload size (u32)   off + 4  free flag (u32)
//! off + 8  payload ...          (8-byte aligned)
//! off + 8 + size  payload size copy (u32) + padding (u32)
//! ```
//!
//! The trailing size copy lets a freed block merge with its
//! predecessor. Free blocks keep the free-list links in their payload
//! (`next` then `prev`, pool offsets). No coalescing metadata beyond
//! that; the whole pool is one block chain, which [`KernelHeap::audit`]
//! can walk and check.
//!
//! This is an independent, deliberately small design (the executive's
//! tagged pools are a much larger machine, ported separately when the
//! compatibility layer needs them).

use core::alloc::Layout;
use core::ptr::NonNull;

/// Header size: payload size + free flag.
const HEADER_SIZE: usize = 8;
/// Footer size: payload size copy (used for backward merges) + padding.
const FOOTER_SIZE: usize = 8;
/// Smallest payload a block can carry: the two free-list links.
const MIN_PAYLOAD: usize = 8;
/// Smallest payload worth splitting a block for.
const MIN_SPLIT: usize = HEADER_SIZE + MIN_PAYLOAD + FOOTER_SIZE;
/// Pool offset meaning "no link".
const NONE: u32 = u32::MAX;

/// A fixed-pool heap. The pool is borrowed for the heap's lifetime;
/// the kernel supplies a static array, tests leak a boxed slice.
pub struct KernelHeap {
    pool: &'static mut [u8],
    free_head: Option<u32>,
}

impl KernelHeap {
    /// Build a heap over `pool` (one big free block).
    ///
    /// The pool must be 8-byte aligned (the boot pool's type
    /// guarantees it) and its length a
    /// positive multiple of 8.
    pub fn new(pool: &'static mut [u8]) -> Self {
        assert!(pool.len().is_multiple_of(8), "pool length must be a multiple of 8");
        assert!(pool.len() >= HEADER_SIZE + MIN_PAYLOAD + FOOTER_SIZE, "pool too small");
        let payload = (pool.len() - HEADER_SIZE - FOOTER_SIZE) as u32;
        let mut heap = KernelHeap {
            pool,
            free_head: None,
        };
        heap.write_block(0, payload, true);
        heap.link(0, NONE, NONE);
        heap.free_head = Some(0);
        heap
    }

    // -----------------------------------------------------------------
    // Raw field access. Offsets are 4-byte aligned by construction.

    fn rd(&self, off: usize) -> u32 {
        // SAFETY: callers only pass offsets inside the pool, computed
        // from block boundaries; reads are unaligned-tolerant.
        unsafe { (self.pool.as_ptr().add(off) as *const u32).read_unaligned() }
    }

    fn wr(&mut self, off: usize, value: u32) {
        // SAFETY: same contract as `rd`.
        unsafe {
            (self.pool.as_mut_ptr().add(off) as *mut u32).write_unaligned(value);
        }
    }

    /// Block payload size, read from the header at `off`.
    fn size(&self, off: u32) -> u32 {
        self.rd(off as usize)
    }

    fn is_free(&self, off: u32) -> bool {
        self.rd(off as usize + 4) == 1
    }

    /// Write a block's header and footer (size + free flag both ends).
    fn write_block(&mut self, off: u32, payload: u32, free: bool) {
        let o = off as usize;
        self.wr(o, payload);
        self.wr(o + 4, free as u32);
        self.wr(o + HEADER_SIZE + payload as usize, payload);
        self.wr(o + HEADER_SIZE + payload as usize + 4, free as u32);
    }

    /// Free-list links, kept in the block payload.
    fn links(&self, off: u32) -> (u32, u32) {
        (self.rd(off as usize + HEADER_SIZE), self.rd(off as usize + HEADER_SIZE + 4))
    }

    fn link(&mut self, off: u32, next: u32, prev: u32) {
        self.wr(off as usize + HEADER_SIZE, next);
        self.wr(off as usize + HEADER_SIZE + 4, prev);
    }

    /// Block start of the block following the one at `off`.
    fn next_block(&self, off: u32, payload: u32) -> u32 {
        off + (HEADER_SIZE + FOOTER_SIZE) as u32 + payload
    }

    /// Unlink the free block at `off` from the free list.
    fn unlink(&mut self, off: u32) {
        let (next, prev) = self.links(off);
        match prev {
            NONE => self.free_head = if next == NONE { None } else { Some(next) },
            p => self.wr(p as usize + HEADER_SIZE, next),
        }
        if next != NONE {
            self.wr(next as usize + HEADER_SIZE + 4, prev);
        }
    }

    /// Push the free block at `off` to the front of the free list.
    fn push_free(&mut self, off: u32) {
        let old = self.free_head.unwrap_or(NONE);
        self.link(off, old, NONE);
        if old != NONE {
            self.wr(old as usize + HEADER_SIZE + 4, off);
        }
        self.free_head = Some(off);
    }

    // -----------------------------------------------------------------
    // Allocation

    /// Allocate `layout` bytes (alignment must be at most 8).
    ///
    /// First fit; a block larger than needed is split when the
    /// remainder can hold a minimal block. Returns `None` when no
    /// block fits.
    pub fn alloc(&mut self, layout: Layout) -> Option<NonNull<u8>> {
        assert!(layout.align() <= 8, "kernel heap aligns to at most 8 bytes");
        let size = layout.size().max(MIN_PAYLOAD).next_multiple_of(8) as u32;

        // First fit, tracking the previous block for unlinking.
        let mut prev = NONE;
        let mut cur = self.free_head.unwrap_or(NONE);
        while cur != NONE {
            let payload = self.size(cur);
            if payload >= size {
                break;
            }
            prev = cur;
            cur = self.links(cur).0;
        }
        if cur == NONE {
            return None;
        }

        let payload = self.size(cur);
        let remainder = payload - size;
        if remainder >= MIN_SPLIT as u32 {
            // Split: the allocated block takes the front, the
            // remainder stays in the free list in the same position.
            let rest = cur + (HEADER_SIZE + FOOTER_SIZE) as u32 + size;
            let rest_payload = payload - size - (HEADER_SIZE + FOOTER_SIZE) as u32;
            let (next, prev_l) = self.links(cur);
            self.write_block(rest, rest_payload, true);
            self.link(rest, next, prev_l);
            if next != NONE {
                self.wr(next as usize + HEADER_SIZE + 4, rest);
            }
            match prev_l {
                NONE => self.free_head = Some(rest),
                p => self.wr(p as usize + HEADER_SIZE, rest),
            }
            self.write_block(cur, size, false);
        } else {
            // Take the whole block.
            self.unlink(cur);
            self.write_block(cur, payload, false);
        }

        // SAFETY: the payload lies inside the pool and is 8-byte
        // aligned (block starts and sizes are multiples of 8).
        Some(unsafe {
            NonNull::new_unchecked(self.pool.as_mut_ptr().add(cur as usize + HEADER_SIZE))
        })
    }

    /// Free an allocation returned by [`KernelHeap::alloc`].
    ///
    /// Merges with the adjacent blocks when they are free. Panics on
    /// a pointer that is not a live allocation head.
    pub fn dealloc(&mut self, ptr: NonNull<u8>) {
        let base = self.pool.as_ptr() as usize;
        let payload = ptr.as_ptr() as usize;
        assert!(
            payload >= base + HEADER_SIZE && payload + FOOTER_SIZE <= base + self.pool.len(),
            "pointer is outside the heap pool"
        );
        let off = (payload - base - HEADER_SIZE) as u32;

        let mut payload_size = self.size(off);
        assert!(!self.is_free(off), "double free");

        // Merge with the next block when it is free.
        let next_off = self.next_block(off, payload_size);
        if (next_off as usize) + HEADER_SIZE <= self.pool.len() && self.is_free(next_off) {
            let next_size = self.size(next_off);
            self.unlink(next_off);
            payload_size += (HEADER_SIZE + FOOTER_SIZE) as u32 + next_size;
        }

        // Merge with the previous block when it is free (the footer
        // right before our header carries its payload size).
        let mut off = off;
        if off > 0 {
            let prev_size = self.rd(off as usize - FOOTER_SIZE);
            let prev_off = off - (HEADER_SIZE + FOOTER_SIZE) as u32 - prev_size;
            if self.is_free(prev_off) {
                self.unlink(prev_off);
                payload_size += (HEADER_SIZE + FOOTER_SIZE) as u32 + prev_size;
                off = prev_off;
            }
        }

        self.write_block(off, payload_size, true);
        self.push_free(off);
    }

    // -----------------------------------------------------------------
    // Consistency audit

    /// Check the heap's invariants. Returns `Ok(())` when they hold.
    ///
    /// Walks the whole block chain and checks: headers and footers
    /// agree, the chain exactly covers the pool, every free block is
    /// on the free list exactly once, and the list links are mutual.
    pub fn audit(&self) -> Result<(), HeapError> {
        // The block chain must tile the pool exactly.
        let mut off = 0usize;
        let mut free_blocks = 0usize;
        while off < self.pool.len() {
            if off + HEADER_SIZE > self.pool.len() {
                return Err(HeapError::BlockOutsidePool);
            }
            let payload = self.rd(off) as usize;
            if !payload.is_multiple_of(8) || payload < MIN_PAYLOAD {
                return Err(HeapError::BadSize);
            }
            let end = off + HEADER_SIZE + payload + FOOTER_SIZE;
            if end > self.pool.len() {
                return Err(HeapError::BlockOutsidePool);
            }
            if self.rd(off + HEADER_SIZE + payload) != payload as u32 {
                return Err(HeapError::HeaderFooterMismatch);
            }
            if self.is_free(off as u32) {
                free_blocks += 1;
            }
            off = end;
        }
        if off != self.pool.len() {
            return Err(HeapError::ChainDoesNotCoverPool);
        }

        // The free list holds exactly the free blocks, once each, with
        // mutual links.
        let mut cur = self.free_head.unwrap_or(NONE);
        let mut prev = NONE;
        let mut listed = 0usize;
        while cur != NONE {
            if cur as usize + HEADER_SIZE + MIN_PAYLOAD > self.pool.len() {
                return Err(HeapError::BadLink);
            }
            if !self.is_free(cur) {
                return Err(HeapError::ListedNotFree);
            }
            let (next, prev_l) = self.links(cur);
            if prev_l != prev {
                return Err(HeapError::BadLink);
            }
            prev = cur;
            cur = next;
            listed += 1;
            if listed > self.pool.len() {
                return Err(HeapError::ListDoesNotTerminate);
            }
        }
        if listed != free_blocks {
            return Err(HeapError::FreeCountMismatch);
        }
        Ok(())
    }
}

/// Ways the heap can be internally inconsistent; reported by
/// [`KernelHeap::audit`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeapError {
    /// A block header or footer lies outside the pool.
    BlockOutsidePool,
    /// A payload size is not a positive multiple of 8.
    BadSize,
    /// A block's header and footer disagree.
    HeaderFooterMismatch,
    /// The block chain does not end exactly at the pool end.
    ChainDoesNotCoverPool,
    /// A free-list link points outside the pool.
    BadLink,
    /// A block on the free list is not marked free.
    ListedNotFree,
    /// The free list does not terminate.
    ListDoesNotTerminate,
    /// Free blocks on the chain and on the list disagree in count.
    FreeCountMismatch,
}

#[cfg(test)]
mod tests {
    use super::*;

    const POOL: usize = 4 * 1024;

    fn heap() -> KernelHeap {
        let pool: &'static mut [u8] = Box::leak(vec![0u8; POOL].into_boxed_slice());
        KernelHeap::new(pool)
    }

    fn alloc(heap: &mut KernelHeap, size: usize) -> NonNull<u8> {
        heap.alloc(Layout::from_size_align(size, 8).unwrap()).unwrap()
    }

    #[test]
    fn fresh_heap_is_one_big_free_block() {
        let heap = heap();
        assert_eq!(heap.audit(), Ok(()));
        assert!(heap.free_head.is_some());
    }

    #[test]
    fn allocations_are_distinct_and_aligned() {
        let mut heap = heap();
        let a = alloc(&mut heap, 16);
        let b = alloc(&mut heap, 16);
        let c = alloc(&mut heap, 64);
        assert_ne!(a.as_ptr(), b.as_ptr());
        assert_ne!(b.as_ptr(), c.as_ptr());
        for p in [a, b, c] {
            assert_eq!(p.as_ptr() as usize % 8, 0);
        }
        assert_eq!(heap.audit(), Ok(()));
    }

    #[test]
    fn freed_block_is_reused() {
        let mut heap = heap();
        let a = alloc(&mut heap, 64);
        let _b = alloc(&mut heap, 64);
        heap.dealloc(a);
        let c = alloc(&mut heap, 64);
        assert_eq!(a.as_ptr(), c.as_ptr(), "freed block should be first fit");
        assert_eq!(heap.audit(), Ok(()));
    }

    #[test]
    fn adjacent_frees_merge_forward_and_backward() {
        let mut heap = heap();
        let a = alloc(&mut heap, 100);
        let b = alloc(&mut heap, 100);
        let c = alloc(&mut heap, 100);
        let d = alloc(&mut heap, 100);

        // Free a then b: b merges backward into a.
        heap.dealloc(a);
        heap.dealloc(b);
        assert_eq!(heap.audit(), Ok(()));
        // The merged hole fits a + b plus both headers: allocate it
        // exactly (224 payload), so no split remainder sits between
        // the hole and c and the next merge starts at c.
        let big = alloc(&mut heap, 224);
        assert_eq!(a.as_ptr(), big.as_ptr());

        // Free c then d: c merges forward with d.
        heap.dealloc(c);
        heap.dealloc(d);
        let big2 = alloc(&mut heap, 200);
        assert_eq!(c.as_ptr(), big2.as_ptr());
        assert_eq!(heap.audit(), Ok(()));
    }

    #[test]
    fn oversized_request_splits_and_returns_remainder() {
        let mut heap = heap();
        // Take the whole pool with one allocation, then free it.
        let big = alloc(&mut heap, POOL - 64);
        assert_eq!(heap.alloc(Layout::from_size_align(POOL, 8).unwrap()), None);
        heap.dealloc(big);

        // A small allocation splits the big free block; the remainder
        // still serves the rest.
        let small = alloc(&mut heap, 32);
        let rest = alloc(&mut heap, POOL - 256);
        assert_ne!(small.as_ptr(), rest.as_ptr());
        assert_eq!(heap.audit(), Ok(()));
    }

    #[test]
    fn exhaustion_returns_none() {
        let mut heap = heap();
        let mut ptrs = Vec::new();
        loop {
            match heap.alloc(Layout::from_size_align(1024, 8).unwrap()) {
                Some(p) => ptrs.push(p),
                None => break,
            }
        }
        assert!(!ptrs.is_empty());
        assert_eq!(heap.audit(), Ok(()));
        // Freeing everything restores one big block.
        for p in ptrs {
            heap.dealloc(p);
        }
        assert_eq!(heap.audit(), Ok(()));
        assert!(heap.alloc(Layout::from_size_align(POOL - 64, 8).unwrap()).is_some());
    }

    #[test]
    #[should_panic(expected = "double free")]
    fn double_free_panics() {
        let mut heap = heap();
        let a = alloc(&mut heap, 16);
        heap.dealloc(a);
        heap.dealloc(a);
    }

    #[test]
    fn audit_detects_corruption() {
        let mut heap = heap();
        let a = alloc(&mut heap, 16);
        let off = a.as_ptr() as usize - heap.pool.as_ptr() as usize - HEADER_SIZE;
        // Corrupt the payload size in header and footer.
        heap.wr(off, 24);
        assert_ne!(heap.audit(), Ok(()));
        heap.wr(off, 16);
        assert_eq!(heap.audit(), Ok(()));
        heap.dealloc(a);
    }
}
