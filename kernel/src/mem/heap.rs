//! Kernel heap: a fixed-pool allocator for loader and runtime structures.
//!
//! Design: one static pool, blocks carved from a doubly-linked free list, first fit. A block is a
//! [`Tag`] (its payload size and whether it is free), the payload (8-byte aligned, a multiple of 8
//! bytes), and the same tag again:
//!
//! ```text
//! off            Tag { size, free }
//! off + 8        payload ...
//! off + 8 + size Tag { size, free }
//! ```
//!
//! The trailing tag lets a freed block merge with its predecessor. Free blocks keep their free-list
//! links in their payload ([`FreeLinks`], pool offsets). No coalescing metadata beyond that; the
//! whole pool is one block chain, which the audit can walk and check.
//!
//! This is an independent, deliberately small design (the executive's tagged pools are a much
//! larger machine, ported separately when the compatibility layer needs them).

use core::alloc::Layout;
use core::mem::{align_of, size_of};
use core::ptr::NonNull;

/// A block's boundary tag, at both its ends: the payload size, and 1 when the block is free.
#[repr(C)]
#[derive(Clone, Copy)]
struct Tag {
    size: u32,
    free: u32,
}

/// A free block's free-list links, kept at the start of its payload.
#[repr(C)]
#[derive(Clone, Copy)]
struct FreeLinks {
    next: Link,
    prev: Link,
}

/// A free-list link as the pool stores it: a free block's pool offset, `u32::MAX` for none.
#[repr(transparent)]
#[derive(Clone, Copy)]
struct Link(u32);

impl Link {
    fn new(to: Option<u32>) -> Link {
        Link(to.unwrap_or(u32::MAX))
    }

    fn get(self) -> Option<u32> {
        (self.0 != u32::MAX).then_some(self.0)
    }
}

impl FreeLinks {
    fn new(next: Option<u32>, prev: Option<u32>) -> FreeLinks {
        FreeLinks {
            next: Link::new(next),
            prev: Link::new(prev),
        }
    }
}

/// Header size: the leading tag.
const HEADER_SIZE: usize = size_of::<Tag>();
/// Footer size: the trailing tag (used for backward merges).
const FOOTER_SIZE: usize = size_of::<Tag>();
/// A block's size beyond its payload.
const OVERHEAD: u32 = (HEADER_SIZE + FOOTER_SIZE) as u32;
/// Smallest payload a block can carry: the two free-list links.
const MIN_PAYLOAD: usize = size_of::<FreeLinks>();
/// Smallest payload worth splitting a block for.
const MIN_SPLIT: usize = HEADER_SIZE + MIN_PAYLOAD + FOOTER_SIZE;

/// A fixed-pool heap over a pool it owns for its lifetime; the kernel supplies a static array,
/// tests leak a boxed slice.
///
/// The pool is held as its base pointer, never as a reference over the whole pool: the payloads it
/// hands out are the callers', and a reference spanning them, re-borrowed at every call, would
/// claim their bytes too. The heap reaches only its own bytes (the tags, a free block's links),
/// each through a pointer derived from the base.
pub struct KernelHeap {
    base: NonNull<u8>,
    len: usize,
    free_head: Option<u32>,
}

// SAFETY: the heap owns its pool (it was handed the only reference to it), so moving the heap to
// another thread moves that ownership with it; the pointer is just how it holds the pool.
unsafe impl Send for KernelHeap {}

impl KernelHeap {
    /// Build a heap over `pool` (one big free block).
    ///
    /// The pool must be 8-byte aligned and its length a positive multiple of 8.
    pub fn new(pool: &'static mut [u8]) -> Self {
        assert!(
            pool.len().is_multiple_of(8),
            "pool length must be a multiple of 8"
        );
        assert!(
            pool.len() >= HEADER_SIZE + MIN_PAYLOAD + FOOTER_SIZE,
            "pool too small"
        );
        assert!(
            u32::try_from(pool.len()).is_ok(),
            "pool offsets must fit 32 bits"
        );
        assert!(
            pool.as_ptr().addr().is_multiple_of(8),
            "pool must be 8-byte aligned"
        );
        let len = pool.len();
        let payload = len as u32 - OVERHEAD;
        let mut heap = KernelHeap {
            base: NonNull::from(pool).cast(),
            len,
            free_head: None,
        };
        heap.write_block(0, payload, true);
        heap.set_links(0, FreeLinks::new(None, None));
        heap.free_head = Some(0);
        heap
    }

    // -----------------------------------------------------------------
    // The heap's own bytes: tags and links, read and written by value.

    /// The `T` at pool offset `off`: one of the heap's own records.
    ///
    /// # Panics
    ///
    /// `off` is not aligned for `T`, or the record reaches past the pool, instead of touching
    /// memory past it.
    fn read<T: Copy>(&self, off: usize) -> T {
        self.check::<T>(off);
        // SAFETY: inside the pool and aligned (checked); the pool is the heap's for its lifetime,
        // and `T` is a tag or links record, plain words for which any bits are a value.
        unsafe { self.base.as_ptr().add(off).cast::<T>().read() }
    }

    /// Write `value` at pool offset `off`; panics as [`KernelHeap::read`].
    fn write<T: Copy>(&mut self, off: usize, value: T) {
        self.check::<T>(off);
        // SAFETY: as in `read`. The bytes are the heap's own: a tag, or a free block's payload,
        // which no caller holds.
        unsafe { self.base.as_ptr().add(off).cast::<T>().write(value) }
    }

    /// Panic unless a `T` at pool offset `off` is aligned and inside the pool.
    fn check<T>(&self, off: usize) {
        assert!(
            off.is_multiple_of(align_of::<T>())
                && off
                    .checked_add(size_of::<T>())
                    .is_some_and(|end| end <= self.len),
            "heap record outside the pool"
        );
    }

    /// The tag of the block at `off`.
    fn tag(&self, off: u32) -> Tag {
        self.read(off as usize)
    }

    /// Block payload size, read from the header at `off`.
    fn size(&self, off: u32) -> u32 {
        self.tag(off).size
    }

    fn is_free(&self, off: u32) -> bool {
        self.tag(off).free == 1
    }

    /// Write a block's header and footer (size + free flag both ends).
    fn write_block(&mut self, off: u32, payload: u32, free: bool) {
        let tag = Tag {
            size: payload,
            free: free as u32,
        };
        self.write(off as usize, tag);
        self.write(off as usize + HEADER_SIZE + payload as usize, tag);
    }

    /// Free-list links, kept in the block payload.
    fn links(&self, off: u32) -> FreeLinks {
        self.read(off as usize + HEADER_SIZE)
    }

    fn set_links(&mut self, off: u32, links: FreeLinks) {
        self.write(off as usize + HEADER_SIZE, links);
    }

    fn set_next(&mut self, off: u32, next: Option<u32>) {
        let links = self.links(off);
        self.set_links(off, FreeLinks::new(next, links.prev.get()));
    }

    fn set_prev(&mut self, off: u32, prev: Option<u32>) {
        let links = self.links(off);
        self.set_links(off, FreeLinks::new(links.next.get(), prev));
    }

    /// Block start of the block following the one at `off`.
    fn next_block(&self, off: u32, payload: u32) -> u32 {
        off + OVERHEAD + payload
    }

    /// Unlink the free block at `off` from the free list.
    fn unlink(&mut self, off: u32) {
        let links = self.links(off);
        let (next, prev) = (links.next.get(), links.prev.get());
        match prev {
            None => self.free_head = next,
            Some(prev) => self.set_next(prev, next),
        }
        if let Some(next) = next {
            self.set_prev(next, prev);
        }
    }

    /// Push the free block at `off` to the front of the free list.
    fn push_free(&mut self, off: u32) {
        let old = self.free_head;
        self.set_links(off, FreeLinks::new(old, None));
        if let Some(old) = old {
            self.set_prev(old, Some(off));
        }
        self.free_head = Some(off);
    }

    // -----------------------------------------------------------------
    // Allocation

    /// Allocate `layout` bytes (alignment must be at most 8).
    ///
    /// First fit; a block larger than needed is split when the remainder can hold a minimal block.
    /// Returns `None` when no block fits.
    pub fn alloc(&mut self, layout: Layout) -> Option<NonNull<u8>> {
        assert!(layout.align() <= 8, "kernel heap aligns to at most 8 bytes");
        let size = layout.size().max(MIN_PAYLOAD).next_multiple_of(8) as u32;

        // First fit.
        let mut cursor = self.free_head;
        let cur = loop {
            let cur = cursor?;
            if self.size(cur) >= size {
                break cur;
            }
            cursor = self.links(cur).next.get();
        };

        let payload = self.size(cur);
        let remainder = payload - size;
        if remainder >= MIN_SPLIT as u32 {
            // Split: the allocated block takes the front, the remainder stays in the free list in
            // the same position.
            let rest = cur + OVERHEAD + size;
            let rest_payload = payload - size - OVERHEAD;
            let links = self.links(cur);
            self.write_block(rest, rest_payload, true);
            self.set_links(rest, links);
            if let Some(next) = links.next.get() {
                self.set_prev(next, Some(rest));
            }
            match links.prev.get() {
                None => self.free_head = Some(rest),
                Some(prev) => self.set_next(prev, Some(rest)),
            }
            self.write_block(cur, size, false);
        } else {
            // Take the whole block.
            self.unlink(cur);
            self.write_block(cur, payload, false);
        }

        // The payload lies inside the pool and is 8-byte aligned (block starts and sizes are
        // multiples of 8).
        let at = self.base.as_ptr().wrapping_add(cur as usize + HEADER_SIZE);
        Some(NonNull::new(at).expect("a pool address is never null"))
    }

    /// Free an allocation returned by [`KernelHeap::alloc`].
    ///
    /// Merges with the adjacent blocks when they are free. Panics on a pointer that is not a live
    /// allocation head.
    pub fn dealloc(&mut self, ptr: NonNull<u8>) {
        let base = self.base.as_ptr().addr();
        let payload = ptr.as_ptr().addr();
        assert!(
            payload >= base + HEADER_SIZE && payload + FOOTER_SIZE <= base + self.len,
            "pointer is outside the heap pool"
        );
        let off = (payload - base - HEADER_SIZE) as u32;

        let mut payload_size = self.size(off);
        assert!(!self.is_free(off), "double free");

        // Merge with the next block when it is free.
        let next_off = self.next_block(off, payload_size);
        if (next_off as usize) + HEADER_SIZE <= self.len && self.is_free(next_off) {
            let next_size = self.size(next_off);
            self.unlink(next_off);
            payload_size += OVERHEAD + next_size;
        }

        // Merge with the previous block when it is free (the footer right before our header carries
        // its payload size).
        let mut off = off;
        if off > 0 {
            let prev_size = self.read::<Tag>(off as usize - FOOTER_SIZE).size;
            let prev_off = off - OVERHEAD - prev_size;
            if self.is_free(prev_off) {
                self.unlink(prev_off);
                payload_size += OVERHEAD + prev_size;
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
    /// Walks the whole block chain and checks: headers and footers agree, the chain exactly covers
    /// the pool, every free block is on the free list exactly once, and the list links are mutual.
    #[cfg(test)]
    pub fn audit(&self) -> Result<(), HeapError> {
        // The block chain must tile the pool exactly.
        let mut off = 0usize;
        let mut free_blocks = 0usize;
        while off < self.len {
            if off + HEADER_SIZE > self.len {
                return Err(HeapError::BlockOutsidePool);
            }
            let payload = self.read::<Tag>(off).size as usize;
            if !payload.is_multiple_of(8) || payload < MIN_PAYLOAD {
                return Err(HeapError::BadSize);
            }
            let end = off + HEADER_SIZE + payload + FOOTER_SIZE;
            if end > self.len {
                return Err(HeapError::BlockOutsidePool);
            }
            if self.read::<Tag>(off + HEADER_SIZE + payload).size != payload as u32 {
                return Err(HeapError::HeaderFooterMismatch);
            }
            if self.is_free(off as u32) {
                free_blocks += 1;
            }
            off = end;
        }
        if off != self.len {
            return Err(HeapError::ChainDoesNotCoverPool);
        }

        // The free list holds exactly the free blocks, once each, with mutual links.
        let mut cur = self.free_head;
        let mut prev = None;
        let mut listed = 0usize;
        while let Some(at) = cur {
            if !at.is_multiple_of(8) || at as usize + HEADER_SIZE + MIN_PAYLOAD > self.len {
                return Err(HeapError::BadLink);
            }
            if !self.is_free(at) {
                return Err(HeapError::ListedNotFree);
            }
            let links = self.links(at);
            if links.prev.get() != prev {
                return Err(HeapError::BadLink);
            }
            prev = Some(at);
            cur = links.next.get();
            listed += 1;
            if listed > self.len {
                return Err(HeapError::ListDoesNotTerminate);
            }
        }
        if listed != free_blocks {
            return Err(HeapError::FreeCountMismatch);
        }
        Ok(())
    }
}

/// Ways the heap can be internally inconsistent; reported by [`KernelHeap::audit`].
#[cfg(test)]
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
        heap.alloc(Layout::from_size_align(size, 8).unwrap())
            .unwrap()
    }

    #[test]
    fn fresh_heap_is_one_big_free_block() {
        let heap = heap();
        assert_eq!(heap.audit(), Ok(()));
        assert!(heap.free_head.is_some());
    }

    /// The records are the words the block layout names: two words of tag, two words of links.
    #[test]
    fn the_records_are_two_words_each() {
        assert_eq!((HEADER_SIZE, FOOTER_SIZE, MIN_PAYLOAD), (8, 8, 8));
        assert_eq!(MIN_SPLIT, 24);
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

    /// The payloads are the callers': writing all of one leaves the heap's own records, and the
    /// neighbours' payloads, intact.
    #[test]
    fn a_full_payload_write_leaves_the_heap_intact() {
        let mut heap = heap();
        let a = alloc(&mut heap, 40);
        let b = alloc(&mut heap, 40);
        // SAFETY: each pointer is a live 40-byte allocation of this heap.
        unsafe {
            core::ptr::write_bytes(b.as_ptr(), 0xBB, 40);
            core::ptr::write_bytes(a.as_ptr(), 0xAA, 40);
        }
        assert_eq!(heap.audit(), Ok(()));
        // SAFETY: as above, read back after the heap's audit.
        let b_bytes = unsafe { b.as_ptr().cast::<[u8; 40]>().read() };
        assert!(b_bytes.iter().all(|&byte| byte == 0xBB));
        heap.dealloc(a);
        heap.dealloc(b);
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
        // The merged hole fits a + b plus both headers: allocate it exactly (224 payload), so no
        // split remainder sits between the hole and c and the next merge starts at c.
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

        // A small allocation splits the big free block; the remainder still serves the rest.
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
        assert!(heap
            .alloc(Layout::from_size_align(POOL - 64, 8).unwrap())
            .is_some());
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
        let off = a.as_ptr() as usize - heap.base.as_ptr() as usize - HEADER_SIZE;
        // Corrupt the payload size in the header.
        heap.write(off, Tag { size: 24, free: 0 });
        assert_ne!(heap.audit(), Ok(()));
        heap.write(off, Tag { size: 16, free: 0 });
        assert_eq!(heap.audit(), Ok(()));
        heap.dealloc(a);
    }
}
