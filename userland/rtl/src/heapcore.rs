//! The heap allocator's core: pure logic over a `&mut [u8]` image of a heap segment's committed
//! block area (host-tested). Blocks carry an 8-byte header — the block's capacity, and a state word
//! holding the in-use flag and the slack between the capacity and the size asked for (so HeapSize
//! answers the exact size) — and are 8-byte aligned; first fit with splitting, free coalesces with
//! both neighbors, a shrink splits the tail off.
//!
//! The segment is the program's own memory: it can overwrite any header (an overflow off the end of
//! a block is enough). Every header is therefore checked before it moves a cursor ([`next_block`]),
//! and a header that does not describe a block inside the area ends the walk as a failed call,
//! never as an endless loop. The heaps ([`crate::heap`]) compose this core over their segments and
//! big blocks.

/// Heap block header size: one dword of capacity (the user bytes, not counting the header), one
/// dword of state.
pub const HEADER_SIZE: usize = 8;

/// Block alignment: user pointers come back 8-byte aligned.
pub const ALIGN: usize = 8;

/// Header state (the state word's low byte): the block is free, or in use. The slack (capacity
/// minus the size asked for: up to 15 for a block reused without a split, 22 after an unsplit
/// shrink) rides in the next byte.
const STATE_FREE: u32 = 0;
const STATE_IN_USE: u32 = 1;
const SLACK_SHIFT: u32 = 8;

/// Round a request up to the block alignment; none when the rounding overflows (a request near
/// the top of the address space can never be served).
pub fn round_up(request: usize) -> Option<usize> {
    request.max(1).checked_next_multiple_of(ALIGN)
}

/// The block after the one at `offset` whose header claims `size` user bytes, or none when the
/// claim is not a block: a size off the alignment, or an end past `top` (overflow included). Every
/// walk steps through here, so a corrupted header can neither run a cursor out of the region nor
/// stall it (each step advances by at least the header).
fn next_block(offset: usize, size: u32, top: usize) -> Option<usize> {
    if !(size as usize).is_multiple_of(ALIGN) {
        return None;
    }
    let next = offset
        .checked_add(HEADER_SIZE)?
        .checked_add(size as usize)?;
    (next <= top).then_some(next)
}

/// Read one block header: (capacity, state word).
fn read_header(region: &[u8], offset: usize) -> (u32, u32) {
    let word = |at: usize| {
        u32::from_le_bytes([region[at], region[at + 1], region[at + 2], region[at + 3]])
    };
    (word(offset), word(offset + 4))
}

/// Write one block header.
fn write_header(region: &mut [u8], offset: usize, size: u32, state: u32) {
    region[offset..offset + 4].copy_from_slice(&size.to_le_bytes());
    region[offset + 4..offset + 8].copy_from_slice(&state.to_le_bytes());
}

/// The state word's state.
fn state_of(word: u32) -> u32 {
    word & 0xFF
}

/// An in-use state word for a block of `capacity` holding `request` bytes.
fn in_use(capacity: usize, request: usize) -> u32 {
    STATE_IN_USE | ((capacity - request.min(capacity)) as u32) << SLACK_SHIFT
}

/// Why an area refused an allocation: it has no room (its owner can commit more of the segment,
/// or try another), or a header on the walk is not a block (the heap is corrupt: more room cannot
/// mend it, and the call fails).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Refusal {
    Full,
    Corrupt,
}

/// First-fit allocation. Absorbs adjacent free blocks while walking, splits a fitting block when
/// the tail is worth keeping, otherwise bumps at the top edge. Returns the user offset (past the
/// header), or why not: [`Refusal::Full`] when even the bump path does not fit — the caller can
/// then extend the region and retry. A failed call never allocates; the walk's free-block
/// absorption may persist (idempotent).
pub fn alloc_block(
    region: &mut [u8],
    top: &mut usize,
    request: usize,
    zero: bool,
) -> Result<usize, Refusal> {
    let need = round_up(request).ok_or(Refusal::Full)?;
    if *top > region.len() {
        return Err(Refusal::Corrupt);
    }
    if need > region.len() {
        return Err(Refusal::Full);
    }

    let mut offset = 0;
    while offset < *top {
        let (mut size, state) = read_header(region, offset);
        // A header that is not a block ends the walk: the heap is corrupt, the call fails.
        let mut next = next_block(offset, size, *top).ok_or(Refusal::Corrupt)?;
        if state_of(state) == STATE_FREE {
            // Absorb following free blocks into this candidate.
            while next < *top {
                let (next_size, next_state) = read_header(region, next);
                if state_of(next_state) != STATE_FREE {
                    break;
                }
                let after = next_block(next, next_size, *top).ok_or(Refusal::Corrupt)?;
                size = (after - offset - HEADER_SIZE) as u32;
                write_header(region, offset, size, STATE_FREE);
                next = after;
            }
            if size as usize >= need {
                let block_size = split(region, offset, size as usize, need);
                write_header(
                    region,
                    offset,
                    block_size as u32,
                    in_use(block_size, request),
                );
                if zero {
                    region[offset + HEADER_SIZE..offset + HEADER_SIZE + need].fill(0);
                }
                return Ok(offset + HEADER_SIZE);
            }
        }
        offset = next;
    }

    // Bump: a fresh in-use block at the top edge.
    let total = HEADER_SIZE + need;
    if total > region.len() - *top {
        return Err(Refusal::Full);
    }
    write_header(region, *top, need as u32, in_use(need, request));
    if zero {
        region[*top + HEADER_SIZE..*top + total].fill(0);
    }
    let user = *top + HEADER_SIZE;
    *top += total;
    Ok(user)
}

/// Cut the block at `offset` of `capacity` down to `need` when the tail is worth keeping, planting
/// a free block there; the block's capacity after the cut.
fn split(region: &mut [u8], offset: usize, capacity: usize, need: usize) -> usize {
    let remainder = capacity - need;
    if remainder >= HEADER_SIZE + ALIGN {
        let tail = offset + HEADER_SIZE + need;
        write_header(region, tail, (remainder - HEADER_SIZE) as u32, STATE_FREE);
        need
    } else {
        capacity
    }
}

/// A user offset must name a live block header; returns its offset.
fn validate(region: &[u8], top: usize, user: usize) -> Option<usize> {
    if user < HEADER_SIZE || user >= top || !user.is_multiple_of(ALIGN) || top > region.len() {
        return None;
    }
    let block = user - HEADER_SIZE;
    let (size, state) = read_header(region, block);
    if state_of(state) != STATE_IN_USE || size == 0 {
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
        if state_of(next_state) != STATE_FREE {
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
            if state_of(walk_state) == STATE_FREE {
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

/// The size asked for of the block owning `user` (its capacity less the recorded slack).
pub fn block_size(region: &[u8], top: usize, user: usize) -> Option<usize> {
    validate(region, top, user).map(|block| {
        let (capacity, state) = read_header(region, block);
        let slack = (state >> SLACK_SHIFT) & 0xFF;
        (capacity - slack.min(capacity)) as usize
    })
}

/// Resize the block owning `user` without moving it: true when `request` fits its capacity (a
/// shrink splits the tail off; a growth into the slack zeroes it when asked).
pub fn resize_in_place(
    region: &mut [u8],
    top: usize,
    user: usize,
    request: usize,
    zero: bool,
) -> bool {
    let Some(block) = validate(region, top, user) else {
        return false;
    };
    let Some(old) = block_size(region, top, user) else {
        return false;
    };
    let (capacity, _) = read_header(region, block);
    let Some(need) = round_up(request) else {
        return false;
    };
    if need > capacity as usize {
        return false;
    }
    if zero && request > old {
        region[user + old..user + request].fill(0);
    }
    let kept = split(region, block, capacity as usize, need);
    write_header(region, block, kept as u32, in_use(kept, request));
    if kept != capacity as usize {
        // The split-off tail merges with a free block after it.
        let tail = block + HEADER_SIZE + kept;
        let (tail_size, _) = read_header(region, tail);
        let mut size = tail_size;
        let mut next = tail + HEADER_SIZE + size as usize;
        while next < top {
            let (next_size, next_state) = read_header(region, next);
            if state_of(next_state) != STATE_FREE {
                break;
            }
            let Some(after) = next_block(next, next_size, top) else {
                break;
            };
            size = (after - tail - HEADER_SIZE) as u32;
            next = after;
        }
        write_header(region, tail, size, STATE_FREE);
    }
    true
}

/// Resize: in place when the request fits the block, else allocate-copy-free (zeroing the
/// extension when asked). The original is untouched on failure. (The heaps compose the same steps
/// across their segment and big blocks; this is the core's own statement of them.)
#[cfg(test)]
pub fn realloc_block(
    region: &mut [u8],
    top: &mut usize,
    user: usize,
    request: usize,
    zero: bool,
) -> Option<usize> {
    let old = block_size(region, *top, user)?;
    if resize_in_place(region, *top, user, request, zero) {
        return Some(user);
    }
    let new = alloc_block(region, top, request, false).ok()?;
    // A plain loop, not slice::copy_within: the blocks never overlap.
    for i in 0..old {
        region[new + i] = region[user + i];
    }
    if zero {
        region[new + old..new + request].fill(0);
    }
    free_block(region, *top, user);
    Some(new)
}

/// Whether every header below `top` describes a block (HeapValidate's walk).
pub fn validate_area(region: &[u8], top: usize) -> bool {
    if top > region.len() {
        return false;
    }
    let mut offset = 0;
    while offset < top {
        let (size, state) = read_header(region, offset);
        if !matches!(state_of(state), STATE_FREE | STATE_IN_USE) {
            return false;
        }
        match next_block(offset, size, top) {
            Some(next) => offset = next,
            None => return false,
        }
    }
    true
}

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
            alloc_block(&mut self.bytes, &mut self.top, request, zero).ok()
        }

        /// Why an allocation is refused, when it is.
        fn refusal(&mut self, request: usize) -> Option<Refusal> {
            alloc_block(&mut self.bytes, &mut self.top, request, false).err()
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
            arena.refusal(0x8000),
            Some(Refusal::Full),
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
            assert_eq!(
                walk.refusal(0x40),
                Some(Refusal::Corrupt),
                "{bogus:#x}: walk stops at b, and says why"
            );
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

    // --- Exact sizes and in-place resizing ---------------------------------

    /// A free block reused without a split keeps up to 15 bytes of slack, and the size asked for
    /// still comes back exactly (MEM-2: the slack was capped at 8, so HeapSize over-reported).
    #[test]
    fn an_unsplit_reuse_answers_the_exact_size() {
        let mut arena = Arena::new();
        let a = arena.alloc(100, false).unwrap(); // capacity 104
        let _b = arena.alloc(8, false).unwrap();
        assert!(arena.free(a));
        // 92 rounds to 96: the 8-byte remainder is no block of its own, so the 104 stays whole.
        assert_eq!(arena.alloc(92, false), Some(a));
        assert_eq!(block_size(&arena.bytes, arena.top, a), Some(92));
        // The same through an in-place resize that keeps the block whole: 89 needs 96, and the
        // 8-byte remainder is no block either (slack 15).
        assert!(resize_in_place(&mut arena.bytes, arena.top, a, 89, false));
        assert_eq!(block_size(&arena.bytes, arena.top, a), Some(89));
        assert!(validate_area(&arena.bytes, arena.top));
    }

    /// The size asked for comes back exactly: the slack rides in the header.
    #[test]
    fn sizes_are_exact() {
        let mut arena = Arena::new();
        let a = arena.alloc(100, false).unwrap();
        assert_eq!(block_size(&arena.bytes, arena.top, a), Some(100));
        let z = arena.alloc(0, false).unwrap();
        assert_eq!(block_size(&arena.bytes, arena.top, z), Some(0));
        let b = realloc_block(&mut arena.bytes, &mut arena.top, a, 5000, false).unwrap();
        assert_eq!(block_size(&arena.bytes, arena.top, b), Some(5000));
    }

    /// A shrink in place keeps the block, answers the new size, and frees the tail for others.
    #[test]
    fn a_shrink_in_place_splits_the_tail() {
        let mut arena = Arena::new();
        let a = arena.alloc(0x1000, false).unwrap();
        let _b = arena.alloc(0x40, false).unwrap();
        assert!(resize_in_place(&mut arena.bytes, arena.top, a, 50, false));
        assert_eq!(block_size(&arena.bytes, arena.top, a), Some(50));
        let c = arena.alloc(0x800, false).unwrap();
        assert_eq!(c, a + 56 + HEADER_SIZE, "the tail serves");
        // Growth past the capacity is refused in place; inside the slack it is not.
        assert!(!resize_in_place(
            &mut arena.bytes,
            arena.top,
            a,
            0x100,
            false
        ));
        assert!(resize_in_place(&mut arena.bytes, arena.top, a, 54, false));
        assert_eq!(block_size(&arena.bytes, arena.top, a), Some(54));
        assert!(validate_area(&arena.bytes, arena.top));
    }

    /// A growth that moves zeroes from the old size on, when asked.
    #[test]
    fn a_moving_growth_zeroes_from_the_old_size() {
        let mut arena = Arena::new();
        let a = arena.alloc(10, false).unwrap();
        arena.block_mut(a, 10).fill(7);
        let _b = arena.alloc(8, false).unwrap();
        let grown = realloc_block(&mut arena.bytes, &mut arena.top, a, 40, true).unwrap();
        assert_ne!(grown, a);
        assert_eq!(arena.block(grown, 10), &[7; 10]);
        assert!(arena.block(grown + 10, 30).iter().all(|&b| b == 0));
    }

    /// The validation walk: a corrupt header fails it.
    #[test]
    fn validation_walks_every_header() {
        let mut arena = Arena::new();
        let a = arena.alloc(0x20, false).unwrap();
        let _b = arena.alloc(0x20, false).unwrap();
        assert!(validate_area(&arena.bytes, arena.top));
        arena.bytes[a - HEADER_SIZE..a - HEADER_SIZE + 4].copy_from_slice(&0x13u32.to_le_bytes());
        assert!(!validate_area(&arena.bytes, arena.top));
    }
}
