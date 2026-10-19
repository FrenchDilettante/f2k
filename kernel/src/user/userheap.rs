//! The user-mode heap the kernel32 heap services serve.
//!
//! The heap region: blocks served by HeapAlloc, managed here (the C runtime's own VirtualAlloc
//! pages are its reservations, through NtAllocateVirtualMemory). Until the heap moves into ntdll,
//! the region sits at a fixed address clear of the user stack.
//!
//! The allocator core is pure logic over a `&mut [u8]` region image (host-testable); the target
//! glue maps pages on demand. Blocks carry an 8-byte header (size, state), 8-byte aligned;
//! first-fit with splitting, free coalesces with both neighbors.
//!
//! The region is user memory: the program can overwrite any header (an overflow off the end of a
//! block is enough). Every header the kernel reads is therefore untrusted — sizes are checked
//! before they move a cursor ([`next_block`]), and a header that does not describe a block inside
//! the region ends the walk as a failed call, never as a kernel panic or an endless loop.

/// Heap block header size: one dword of block size (the user bytes, not counting the header), one
/// dword of state.
pub const HEADER_SIZE: usize = 8;

/// Block alignment: user pointers come back 8-byte aligned.
const ALIGN: usize = 8;

/// Header state: the block is free.
const STATE_FREE: u32 = 0;
/// Header state: the block is in use.
const STATE_IN_USE: u32 = 1;

/// The heap region's fixed user address and cap.
pub const HEAP_REGION_BASE: u32 = 0x0200_0000;
pub const HEAP_REGION_MAX: usize = 0x0010_0000;

/// HeapAlloc/HeapReAlloc flag: zero the new bytes.
const HEAP_ZERO_MEMORY: u32 = 0x0000_0008;
/// HeapReAlloc flag: never move the block.
const HEAP_REALLOC_IN_PLACE_ONLY: u32 = 0x0000_0010;

/// Round a request up to the block alignment; none when the rounding overflows (a request near
/// the top of the address space can never be served).
fn round_up(request: usize) -> Option<usize> {
    request.max(1).checked_next_multiple_of(ALIGN)
}

/// The block after the one at `offset` whose header claims `size` user bytes, or none when the
/// claim is not a block: a size off the alignment, or an end past `top` (overflow included). Every
/// walk steps through here, so a corrupted header can neither run a cursor out of the region nor
/// stall it (each step advances by at least the header).
fn next_block(offset: usize, size: u32, top: usize) -> Option<usize> {
    if size as usize % ALIGN != 0 {
        return None;
    }
    let next = offset
        .checked_add(HEADER_SIZE)?
        .checked_add(size as usize)?;
    (next <= top).then_some(next)
}

/// Read one block header: (user size, state).
fn read_header(region: &[u8], offset: usize) -> (u32, u32) {
    let size = u32::from_le_bytes([
        region[offset],
        region[offset + 1],
        region[offset + 2],
        region[offset + 3],
    ]);
    let state = u32::from_le_bytes([
        region[offset + 4],
        region[offset + 5],
        region[offset + 6],
        region[offset + 7],
    ]);
    (size, state)
}

/// Write one block header.
fn write_header(region: &mut [u8], offset: usize, size: u32, state: u32) {
    region[offset..offset + 4].copy_from_slice(&size.to_le_bytes());
    region[offset + 4..offset + 8].copy_from_slice(&state.to_le_bytes());
}

/// First-fit allocation. Absorbs adjacent free blocks while walking, splits a fitting block when
/// the tail is worth keeping, otherwise bumps at the top edge. Returns the user offset (past the
/// header) or `None` if even the bump path does not fit — the caller can then extend the region and
/// retry. A failed call never allocates; the walk's free-block absorption may persist (idempotent).
pub fn alloc_block(
    region: &mut [u8],
    top: &mut usize,
    request: usize,
    zero: bool,
) -> Option<usize> {
    let need = round_up(request)?;
    if need > region.len() || *top > region.len() {
        return None;
    }

    let mut offset = 0;
    while offset < *top {
        let (mut size, state) = read_header(region, offset);
        // A header that is not a block ends the walk: the heap is corrupt, the call fails.
        let mut next = next_block(offset, size, *top)?;
        if state == STATE_FREE {
            // Absorb following free blocks into this candidate.
            while next < *top {
                let (next_size, next_state) = read_header(region, next);
                if next_state != STATE_FREE {
                    break;
                }
                let after = next_block(next, next_size, *top)?;
                size = (after - offset - HEADER_SIZE) as u32;
                write_header(region, offset, size, STATE_FREE);
                next = after;
            }
            if size as usize >= need {
                let remainder = size as usize - need;
                let block_size = if remainder >= HEADER_SIZE + ALIGN {
                    // Split: shrink this block, plant a free block in the tail.
                    let tail = offset + HEADER_SIZE + need;
                    write_header(region, tail, (remainder - HEADER_SIZE) as u32, STATE_FREE);
                    need as u32
                } else {
                    size
                };
                write_header(region, offset, block_size, STATE_IN_USE);
                if zero {
                    region[offset + HEADER_SIZE..offset + HEADER_SIZE + need].fill(0);
                }
                return Some(offset + HEADER_SIZE);
            }
        }
        offset = next;
    }

    // Bump: a fresh in-use block at the top edge.
    let total = HEADER_SIZE + need;
    if total > region.len() - *top {
        return None;
    }
    write_header(region, *top, need as u32, STATE_IN_USE);
    if zero {
        region[*top + HEADER_SIZE..*top + total].fill(0);
    }
    let user = *top + HEADER_SIZE;
    *top += total;
    Some(user)
}

/// A user offset must name a live block header; returns its offset.
fn validate(region: &[u8], top: usize, user: usize) -> Option<usize> {
    if user < HEADER_SIZE || user >= top || user % ALIGN != 0 || top > region.len() {
        return None;
    }
    let block = user - HEADER_SIZE;
    let (size, state) = read_header(region, block);
    if state != STATE_IN_USE || size == 0 {
        return None;
    }
    next_block(block, size, top)?;
    Some(block)
}

/// Free the block owning `user`; false if it is not a live block. Coalesces with both neighbors.
pub fn free_block(region: &mut [u8], top: usize, user: usize) -> bool {
    let Some(block) = validate(region, top, user) else {
        return false;
    };
    let (mut size, _) = read_header(region, block);
    write_header(region, block, size, STATE_FREE);

    // Coalesce forward: absorb the next block while it is free. A corrupt neighbor stops the
    // merge; the block itself is already freed.
    let mut next = block + HEADER_SIZE + size as usize;
    while next < top {
        let (next_size, next_state) = read_header(region, next);
        if next_state != STATE_FREE {
            break;
        }
        let Some(after) = next_block(next, next_size, top) else {
            break;
        };
        size = (after - block - HEADER_SIZE) as u32;
        write_header(region, block, size, STATE_FREE);
        next = after;
    }

    // Coalesce backward: the block that ends exactly where this one starts, when it is free,
    // swallows this one. A corrupt header on the way stops the search.
    let mut cursor = 0;
    while cursor < block {
        let (walk_size, walk_state) = read_header(region, cursor);
        let Some(after) = next_block(cursor, walk_size, top) else {
            break;
        };
        if after == block {
            if walk_state == STATE_FREE {
                write_header(
                    region,
                    cursor,
                    walk_size + HEADER_SIZE as u32 + size,
                    STATE_FREE,
                );
            }
            break;
        }
        cursor = after;
    }
    true
}

/// The user size of the block owning `user`.
fn block_size(region: &[u8], top: usize, user: usize) -> Option<usize> {
    validate(region, top, user).map(|block| read_header(region, block).0 as usize)
}

/// Resize: grow by allocate-copy-free (zeroing the extension when asked), shrink by keeping the
/// block. The original is untouched on failure.
pub fn realloc_block(
    region: &mut [u8],
    top: &mut usize,
    user: usize,
    request: usize,
    zero: bool,
) -> Option<usize> {
    let old = block_size(region, *top, user)?;
    if request <= old {
        // Shrinking keeps the block (no split: the tail is not worth the bookkeeping).
        return Some(user);
    }
    let new = alloc_block(region, top, request, false)?;
    // A plain loop, not slice::copy_within: it lowers to memmove, which the no_std build does not
    // link. The blocks never overlap.
    for i in 0..old {
        region[new + i] = region[user + i];
    }
    if zero {
        // The allocation succeeded, so the rounding did too.
        let end = new + round_up(request).expect("rounded by the allocation");
        region[new + old..end].fill(0);
    }
    free_block(region, *top, user);
    Some(new)
}

// --- Target glue ------------------------------------------------------
//
// Runs the pure core over the heap region's committed prefix. User pages are RW and
// supervisor-accessible, so the kernel slices the region directly. The bookkeeping lives in
// [`HeapState`], one instance per process (inside the process object) — no kernel static holds heap
// state.

#[cfg(target_arch = "x86")]
use crate::mem::paging::PAGE_SIZE;
#[cfg(target_arch = "x86")]
use crate::mem::vm::{AddressSpace, CurrentPages, PAGE_READWRITE};

/// Per-process heap bookkeeping: the heap region's committed prefix and bump edge. A fresh process starts from [`HeapState::new`];
/// nothing survives the process that owns it.
pub struct HeapState {
    /// The heap region's committed prefix, in bytes.
    committed: usize,
    /// The heap region's bump edge (blocks live below it).
    top: usize,
}

impl HeapState {
    /// Fresh state: nothing committed.
    pub const fn new() -> Self {
        Self {
            committed: 0,
            top: 0,
        }
    }

    /// Reset the heap (HeapCreate). No mapping involved: the handle is a constant and the bump edge
    /// is state.
    pub fn create(&mut self) -> u32 {
        self.top = 0;
        HEAP_HANDLE
    }
}

#[cfg(target_arch = "x86")]
impl HeapState {
    /// Commit zeroed user pages in `space`'s heap region so the region image covers `bytes`; fails
    /// past the region cap or without frames, idempotent.
    fn commit_heap(&mut self, space: &mut AddressSpace, bytes: usize) -> bool {
        if bytes <= self.committed {
            return true;
        }
        if bytes > HEAP_REGION_MAX {
            return false;
        }
        let start = (self.committed as u32).div_ceil(PAGE_SIZE);
        let end = (bytes as u32).div_ceil(PAGE_SIZE);
        let committed = space.commit(
            &mut CurrentPages,
            HEAP_REGION_BASE + start * PAGE_SIZE,
            (end - start) * PAGE_SIZE,
            PAGE_READWRITE,
        );
        if committed.is_err() {
            return false;
        }
        self.committed = end as usize * PAGE_SIZE as usize;
        true
    }

    /// The heap region image (its committed prefix).
    fn heap_region(&mut self) -> &'static mut [u8] {
        // SAFETY: the committed prefix is mapped RW in the current process's address space; this
        // heap's only accessor.
        unsafe { core::slice::from_raw_parts_mut(HEAP_REGION_BASE as *mut u8, self.committed) }
    }

    /// HeapAlloc: first-fit, committing more of the region when the bump path needs it; 0 on
    /// failure.
    pub fn alloc(&mut self, space: &mut AddressSpace, flags: u32, request: usize) -> u32 {
        let zero = flags & HEAP_ZERO_MEMORY != 0;
        loop {
            let region = self.heap_region();
            let mut top = self.top;
            match alloc_block(region, &mut top, request, zero) {
                Some(user) => {
                    self.top = top;
                    return HEAP_REGION_BASE + user as u32;
                }
                None => {
                    // The bump path needs more region. Commit one page beyond the need (so small
                    // streams do not re-commit per allocation) and retry; past the cap the request
                    // fails.
                    let Some(need) = round_up(request)
                        .and_then(|rounded| top.checked_add(HEADER_SIZE + rounded))
                    else {
                        return 0;
                    };
                    if need > HEAP_REGION_MAX || !self.commit_heap(space, need + PAGE_SIZE as usize)
                    {
                        return 0;
                    }
                }
            }
        }
    }

    /// HeapFree: validate and coalesce; TRUE/FALSE.
    pub fn free(&mut self, ptr: u32) -> u32 {
        if ptr < HEAP_REGION_BASE {
            return 0;
        }
        let user = (ptr - HEAP_REGION_BASE) as usize;
        if free_block(self.heap_region(), self.top, user) {
            1
        } else {
            0
        }
    }

    /// HeapReAlloc over the region; 0 on failure. HEAP_REALLOC_IN_PLACE_ONLY never moves the
    /// block: a shrink keeps it, a growth fails.
    pub fn realloc(&mut self, ptr: u32, flags: u32, request: usize) -> u32 {
        let zero = flags & HEAP_ZERO_MEMORY != 0;
        if ptr < HEAP_REGION_BASE {
            return 0;
        }
        let user = (ptr - HEAP_REGION_BASE) as usize;
        let region = self.heap_region();
        let mut top = self.top;
        if flags & HEAP_REALLOC_IN_PLACE_ONLY != 0 {
            return match block_size(region, top, user) {
                Some(old) if request <= old => ptr,
                _ => 0,
            };
        }
        match realloc_block(region, &mut top, user, request, zero) {
            Some(new) => {
                self.top = top;
                HEAP_REGION_BASE + new as u32
            }
            None => 0,
        }
    }

    /// HeapDestroy: accept the handle, reset.
    pub fn destroy(&mut self, handle: u32) -> u32 {
        if handle == HEAP_HANDLE {
            self.create();
            1
        } else {
            0
        }
    }

}

/// The handle HeapCreate reports (nonzero, address-styled like real handles).
#[cfg(target_arch = "x86")]
pub const HEAP_HANDLE: u32 = HEAP_REGION_BASE;

/// The kernel32 heap services, served from the current process's heap state (the process object
/// owns it; see `process`).
#[cfg(target_arch = "x86")]
mod target {
    pub fn create() -> u32 {
        crate::process::current_mut().heap_mut().create()
    }
    pub fn alloc(flags: u32, request: usize) -> u32 {
        let parts = crate::process::current_mut().parts_mut();
        parts.heap.alloc(parts.vm, flags, request)
    }
    pub fn free(ptr: u32) -> u32 {
        crate::process::current_mut().heap_mut().free(ptr)
    }
    pub fn realloc(ptr: u32, flags: u32, request: usize) -> u32 {
        crate::process::current_mut()
            .heap_mut()
            .realloc(ptr, flags, request)
    }
    pub fn destroy(handle: u32) -> u32 {
        crate::process::current_mut().heap_mut().destroy(handle)
    }
}

#[cfg(target_arch = "x86")]
pub use target::*;

// Host stubs: the kernel32 registry names these but host builds never dispatch services.

#[cfg(not(target_arch = "x86"))]
mod host {
    fn target_only() -> ! {
        unimplemented!("user heap services run on the target")
    }

    pub const HEAP_HANDLE: u32 = 0;

    pub fn create() -> u32 {
        target_only()
    }
    pub fn alloc(_flags: u32, _request: usize) -> u32 {
        target_only()
    }
    pub fn free(_ptr: u32) -> u32 {
        target_only()
    }
    pub fn realloc(_ptr: u32, _flags: u32, _request: usize) -> u32 {
        target_only()
    }
    pub fn destroy(_handle: u32) -> u32 {
        target_only()
    }
}

#[cfg(not(target_arch = "x86"))]
pub use host::*;

#[cfg(test)]
mod tests {
    use super::*;

    /// A garbage-filled region image, so zeroing behavior is visible.
    struct Arena {
        bytes: [u8; 0x8000],
        top: usize,
    }

    impl Arena {
        fn new() -> Self {
            let mut bytes = [0u8; 0x8000];
            bytes.fill(0xAA);
            Self { bytes, top: 0 }
        }

        fn alloc(&mut self, request: usize, zero: bool) -> Option<usize> {
            alloc_block(&mut self.bytes, &mut self.top, request, zero)
        }

        fn free(&mut self, user: usize) -> bool {
            free_block(&mut self.bytes, self.top, user)
        }

        /// The bytes at a returned offset.
        fn block(&self, user: usize, len: usize) -> &[u8] {
            &self.bytes[user..user + len]
        }

        /// The same view, mutable.
        fn block_mut(&mut self, user: usize, len: usize) -> &mut [u8] {
            &mut self.bytes[user..user + len]
        }
    }

    /// The CRT's startup shapes; the zeroed one reads back zero despite the garbage-filled arena.
    #[test]
    fn crt_startup_shapes_succeed() {
        let mut arena = Arena::new();
        let bookkeeping = arena.alloc(0x140, false).expect("0x140");
        let headers = arena.alloc(0x41C4, true).expect("0x41C4 zeroed");
        let env_copy = arena.alloc(0x5D0, false).expect("0x5D0");
        assert_ne!(bookkeeping, headers);
        assert_ne!(headers, env_copy);
        assert!(arena.block(headers, 32).iter().all(|&b| b == 0));
        // The non-zeroed block's contents are undefined but writable.
        arena.block_mut(bookkeeping, 8).fill(0x5A);
        assert_eq!(&arena.block(bookkeeping, 8)[..], &[0x5A; 8]);
        // Offsets are header-relative: the first user byte sits right after its header, aligned.
        assert_eq!(bookkeeping, HEADER_SIZE);
        assert_eq!(headers % 8, 0);
    }

    /// A freed block comes back for a same-size request; coalesced neighbors are reused as one
    /// block.
    #[test]
    fn freed_blocks_are_reusable_and_coalesce() {
        let mut arena = Arena::new();
        let a = arena.alloc(0x100, false).unwrap();
        let b = arena.alloc(0x100, false).unwrap();
        let c = arena.alloc(0x100, false).unwrap();
        assert_ne!(a, b);
        assert_ne!(b, c);

        // Free all three: c merges into b merges into a.
        assert!(arena.free(a));
        assert!(arena.free(b));
        assert!(arena.free(c));
        // Double free is rejected.
        assert!(!arena.free(b));

        // The coalesced span serves the sum (plus the two absorbed headers) in one block.
        let merged = arena
            .alloc(0x300 + 2 * HEADER_SIZE, false)
            .expect("merged span");
        assert_eq!(merged, a);
    }

    /// First-fit: a freed block is reused ahead of the bump edge, split, and the tail serves;
    /// too-large falls to the bump.
    #[test]
    fn first_fit_splits_and_falls_through() {
        let mut arena = Arena::new();
        let a = arena.alloc(0x200, false).unwrap();
        let _b = arena.alloc(0x40, false).unwrap();
        assert!(arena.free(a));

        // Smaller request: splits a, leaving an 0xF8 tail.
        let small = arena.alloc(0x100, false).expect("first fit");
        assert_eq!(small, a);
        // The tail still serves its 0xF8.
        let tail = arena.alloc(0xF8, false).expect("tail");
        assert_eq!(tail, a + HEADER_SIZE + 0x100);

        // Too large for the free tail: the bump edge takes it.
        let before_top = arena.top;
        let big = arena.alloc(0x1000, false).expect("bump");
        assert_eq!(big, before_top + HEADER_SIZE);
    }

    /// Free rejects everything that is not a live block.
    #[test]
    fn free_rejects_non_blocks() {
        let mut arena = Arena::new();
        let a = arena.alloc(0x40, false).unwrap();
        assert!(!arena.free(0));
        assert!(!arena.free(4));
        assert!(!arena.free(a + 1));
        assert!(!arena.free(a + 0x10)); // interior, not a header
        assert!(!arena.free(a + 0x1000)); // past the top
        assert!(arena.free(a));
    }

    /// Realloc: grow copies and frees the old block (extension zeroed), shrink keeps it, non-blocks
    /// fail.
    #[test]
    fn realloc_copies_and_frees() {
        let mut arena = Arena::new();
        let a = arena.alloc(0x100, false).unwrap();
        arena
            .block_mut(a, 8)
            .copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);

        // Grow: contents preserved, extension zeroed.
        let grown = realloc_block(&mut arena.bytes, &mut arena.top, a, 0x180, true).expect("grow");
        assert_ne!(grown, a);
        assert_eq!(&arena.block(grown, 8)[..], &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert!(arena.block(grown + 0x100, 0x80).iter().all(|&b| b == 0));

        // The old block is free again and reusable.
        let reused = arena.alloc(0x100, false).expect("old block reused");
        assert_eq!(reused, a);

        // Shrink keeps the block.
        let shrunk = realloc_block(&mut arena.bytes, &mut arena.top, grown, 0x40, false).unwrap();
        assert_eq!(shrunk, grown);

        // Non-blocks fail.
        assert_eq!(
            realloc_block(&mut arena.bytes, &mut arena.top, 0x80, 0x40, false),
            None
        );
    }

    /// An alloc/free stream stays bounded: no leak of the top edge.
    #[test]
    fn alloc_free_stream_stays_bounded() {
        let mut arena = Arena::new();
        let mut top_high_water = 0;
        for round in 0..16 {
            let blocks: Vec<usize> = (0..8)
                .map(|i| arena.alloc(0x10 * (i + 1) + round, false).expect("stream"))
                .collect();
            top_high_water = top_high_water.max(arena.top);
            for &user in &blocks {
                assert!(arena.free(user));
            }
        }
        // The high water mark stays far below the arena; after a free-all the first allocation
        // reuses the coalesced span.
        assert!(top_high_water < 0x800);
        let first = arena.alloc(0x10, false).expect("after free-all");
        assert_eq!(first, HEADER_SIZE);
    }

    /// Requests round to 8-byte blocks; user offsets stay 8-aligned.
    #[test]
    fn requests_round_to_the_alignment() {
        assert_eq!(round_up(0), Some(8));
        assert_eq!(round_up(1), Some(8));
        assert_eq!(round_up(9), Some(16));
        assert_eq!(round_up(0x41C4), Some(0x41C8));
        let mut arena = Arena::new();
        for request in [1, 3, 8, 9, 0x40] {
            let user = arena.alloc(request, false).expect("aligned");
            assert_eq!(user % 8, 0);
        }
    }

    // --- Untrusted headers: the region is user memory -------------------

    /// Requests whose rounding or bump arithmetic overflows fail; they never panic. (The target's
    /// usize is 32 bits, where `HeapAlloc(h, 0, 0xFFFFFFFF)` is exactly this.)
    #[test]
    fn requests_near_the_top_of_the_address_space_fail() {
        assert_eq!(round_up(usize::MAX), None);
        assert_eq!(round_up(usize::MAX - 6), None);
        let mut arena = Arena::new();
        assert_eq!(arena.alloc(usize::MAX, false), None);
        assert_eq!(arena.alloc(usize::MAX - 7, true), None);
        assert_eq!(
            arena.alloc(0x8000, false),
            None,
            "header plus request > region"
        );
        assert_eq!(arena.top, 0);
    }

    /// The step rule: misaligned sizes and ends past the top are not blocks; a valid step moves at
    /// least one header forward.
    #[test]
    fn next_block_refuses_what_is_not_a_block() {
        assert_eq!(next_block(0, 8, 0x100), Some(16));
        assert_eq!(next_block(0, 0, 0x100), Some(8));
        assert_eq!(next_block(0, 4, 0x100), None, "misaligned");
        assert_eq!(next_block(0, 0x100, 0x100), None, "past the top");
        assert_eq!(next_block(usize::MAX - 4, 8, usize::MAX), None, "overflow");
        assert_eq!(next_block(0, u32::MAX - 7, 0x100), None, "wraps on 32-bit");
    }

    /// A one-word underflow into the next block's header (the classic heap overrun) — a huge size,
    /// a size that would step the cursor backwards on a 32-bit target, a misaligned size — makes
    /// the calls that walk over it fail, never panic or spin.
    #[test]
    fn corrupt_headers_fail_the_walk() {
        for bogus in [0xFFFF_FFF8u32, 0xFFFF_FFF0, 0x7FFF_FFF8, 0x13, 0x4000] {
            let mut arena = Arena::new();
            let a = arena.alloc(0x20, false).unwrap();
            let b = arena.alloc(0x20, false).unwrap();
            let _c = arena.alloc(0x20, false).unwrap();
            // Overrun `a` into `b`'s header size word.
            arena.bytes[b - HEADER_SIZE..b - HEADER_SIZE + 4].copy_from_slice(&bogus.to_le_bytes());
            assert!(
                !arena.free(b),
                "{bogus:#x}: b's header no longer describes a block"
            );
            assert!(arena.free(a), "{bogus:#x}: a is intact and frees");
            // a's slot is free again: a fitting request reuses it without touching b.
            assert_eq!(arena.alloc(0x20, false), Some(a), "{bogus:#x}");
            // A request that must walk past b's header fails cleanly.
            let mut walk = Arena::new();
            walk.bytes = arena.bytes;
            walk.top = arena.top;
            assert_eq!(walk.alloc(0x40, false), None, "{bogus:#x}: walk stops at b");
        }
    }

    /// A free block whose header was overwritten with "free, huge" is not merged into a freed
    /// neighbor: the forward coalesce checks the step.
    #[test]
    fn a_corrupt_free_neighbor_is_not_absorbed() {
        let mut arena = Arena::new();
        let a = arena.alloc(0x20, false).unwrap();
        let b = arena.alloc(0x20, false).unwrap();
        let _c = arena.alloc(0x20, false).unwrap();
        assert!(arena.free(b));
        arena.bytes[b - HEADER_SIZE..b - HEADER_SIZE + 4]
            .copy_from_slice(&0xFFFF_FFF8u32.to_le_bytes());
        assert!(arena.free(a));
        let (a_size, a_state) = read_header(&arena.bytes, a - HEADER_SIZE);
        assert_eq!((a_size, a_state), (0x20, STATE_FREE));
    }

    /// The target placement: the region above every mapped area, 64 KiB-aligned, in user space,
    /// below the system DLLs.
    #[test]
    fn the_region_is_placed_clear_of_the_user_layout() {
        assert_eq!(HEAP_REGION_BASE % 0x10000, 0);
        assert!(HEAP_REGION_BASE + HEAP_REGION_MAX as u32 <= crate::exec::modules::NTDLL_BASE);
        // The stack (0x300000) and the pages above it stay clear of the region.
        assert!(HEAP_REGION_BASE > 0x0032_0000);
    }
}
