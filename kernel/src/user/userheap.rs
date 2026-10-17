//! The Win32 heaps: the process heap and the heaps HeapCreate makes, each on its own reservation in
//! the process's address space (see [`crate::mem::vm`]).
//!
//! A heap is a segment — a private reservation whose base is the heap's handle, committed on
//! demand from its start — and, for a growable heap, its big blocks: a request past
//! [`BIG_THRESHOLD`] gets a reservation of its own, as NT's heap hands such requests to the virtual
//! memory manager. A heap created with a maximum size is that one segment and nothing more: it
//! refuses what does not fit (raising STATUS_NO_MEMORY when it generates exceptions).
//!
//! Inside a segment, the allocator core is pure logic over a `&mut [u8]` image of the committed
//! block area (host-testable). Blocks carry an 8-byte header — the block's capacity, and a state
//! word holding the in-use flag and the slack between the capacity and the size asked for (so
//! HeapSize answers the exact size) — and are 8-byte aligned; first fit with splitting, free
//! coalesces with both neighbors, a shrink splits the tail off.
//!
//! The segment is user memory: the program can overwrite any header (an overflow off the end of a
//! block is enough). Every header the kernel reads is therefore untrusted — sizes are checked
//! before they move a cursor ([`next_block`]), and a header that does not describe a block inside
//! the area ends the walk as a failed call, never as a kernel panic or an endless loop.

/// Heap block header size: one dword of capacity (the user bytes, not counting the header), one
/// dword of state.
pub const HEADER_SIZE: usize = 8;

/// Block alignment: user pointers come back 8-byte aligned.
const ALIGN: usize = 8;

/// Header state (the state word's low byte): the block is free, or in use. The slack (capacity
/// minus the size asked for, 0 to 8) rides in the next byte.
const STATE_FREE: u32 = 0;
const STATE_IN_USE: u32 = 1;
const SLACK_SHIFT: u32 = 8;

/// The heap flags (public constants).
pub const HEAP_GENERATE_EXCEPTIONS: u32 = 0x0000_0004;
pub const HEAP_ZERO_MEMORY: u32 = 0x0000_0008;
pub const HEAP_REALLOC_IN_PLACE_ONLY: u32 = 0x0000_0010;

/// STATUS_NO_MEMORY: what a heap that generates exceptions raises when it cannot serve.
pub const STATUS_NO_MEMORY: u32 = 0xC000_0017;

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

/// Read one block header: (capacity, state word).
fn read_header(region: &[u8], offset: usize) -> (u32, u32) {
    let word = |at: usize| u32::from_le_bytes([region[at], region[at + 1], region[at + 2], region[at + 3]]);
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
    STATE_IN_USE | ((capacity - request.min(capacity)).min(ALIGN) as u32) << SLACK_SHIFT
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
        if state_of(state) == STATE_FREE {
            // Absorb following free blocks into this candidate.
            while next < *top {
                let (next_size, next_state) = read_header(region, next);
                if state_of(next_state) != STATE_FREE {
                    break;
                }
                let after = next_block(next, next_size, *top)?;
                size = (after - offset - HEADER_SIZE) as u32;
                write_header(region, offset, size, STATE_FREE);
                next = after;
            }
            if size as usize >= need {
                let block_size = split(region, offset, size as usize, need);
                write_header(region, offset, block_size as u32, in_use(block_size, request));
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
    write_header(region, *top, need as u32, in_use(need, request));
    if zero {
        region[*top + HEADER_SIZE..*top + total].fill(0);
    }
    let user = *top + HEADER_SIZE;
    *top += total;
    Some(user)
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
    if user < HEADER_SIZE || user >= top || user % ALIGN != 0 || top > region.len() {
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
        let slack = ((state >> SLACK_SHIFT) & 0xFF).min(ALIGN as u32);
        (capacity - slack.min(capacity)) as usize
    })
}

/// Resize the block owning `user` without moving it: true when `request` fits its capacity (a
/// shrink splits the tail off; a growth into the slack zeroes it when asked).
pub fn resize_in_place(region: &mut [u8], top: usize, user: usize, request: usize, zero: bool) -> bool {
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
    let new = alloc_block(region, top, request, false)?;
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

// --- The heaps ---------------------------------------------------------------------------------

/// How many heaps a process can hold, and how many big blocks each.
pub const HEAPS: usize = 16;
pub const BIG_BLOCKS: usize = 64;
/// A growable heap's segment reservation.
pub const GROWABLE_RESERVE: u32 = 0x200_0000;
/// The largest request a growable heap serves from its segment; larger ones get a reservation of
/// their own (NT's virtual-block threshold).
pub const BIG_THRESHOLD: usize = 0x7_F000;
/// The segment's header: the bytes before the first block (the handle names them, never a block).
const AREA: u32 = 0x20;
/// A big block's header: its user bytes start this far into its reservation.
const BIG_HEADER: u32 = 8;

/// One big block: its reservation's base (zero: the slot is free) and the size asked for.
#[derive(Clone, Copy, Default, Debug)]
struct Big {
    base: u32,
    size: u32,
}

/// One heap. All zeros is a free slot.
#[derive(Clone, Copy, Debug)]
pub struct Heap {
    live: bool,
    /// The segment's base: the heap's handle.
    base: u32,
    /// The segment's reservation, and its committed prefix (both from the base).
    reserve: u32,
    committed: u32,
    /// The block area's bump edge (from the area's start).
    top: u32,
    /// The creation flags.
    flags: u32,
    growable: bool,
    big: [Big; BIG_BLOCKS],
}

/// A process's heaps. All zeros is no heap at all.
pub struct Heaps {
    heaps: [Heap; HEAPS],
    /// The process heap's handle.
    process: u32,
}

impl Heaps {
    /// No heaps (the tests build it by value; the kernel zeroes it in place).
    #[cfg(test)]
    pub const fn new() -> Heaps {
        const FREE: Heap = Heap {
            live: false,
            base: 0,
            reserve: 0,
            committed: 0,
            top: 0,
            flags: 0,
            growable: false,
            big: [Big { base: 0, size: 0 }; BIG_BLOCKS],
        };
        Heaps {
            heaps: [FREE; HEAPS],
            process: 0,
        }
    }

    /// The process heap's handle (zero before it exists).
    #[cfg(test)]
    pub fn process_heap(&self) -> u32 {
        self.process
    }

    /// The live heap whose handle is `handle`.
    fn heap(&mut self, handle: u32) -> Option<&mut Heap> {
        self.heaps.iter_mut().find(|h| h.live && h.base == handle && handle != 0)
    }
}

#[cfg(target_arch = "x86")]
mod target {
    use super::*;
    use crate::mem::vm::{AddressSpace, CurrentPages, Kind, Pages, PAGE, PAGE_READWRITE};

    impl Heap {
        /// The committed block area.
        fn area(&self) -> &'static mut [u8] {
            // SAFETY: the segment's committed prefix is mapped read-write in the current process's
            // address space, and the area lies inside it; the heap's only kernel accessor.
            unsafe {
                core::slice::from_raw_parts_mut(
                    (self.base + AREA) as *mut u8,
                    (self.committed - AREA) as usize,
                )
            }
        }

        /// Whether the segment is still the heap's: the program may have freed it under the heap.
        fn intact(&self, space: &AddressSpace) -> bool {
            let committed = |va: u32| CurrentPages.entry(va) & 1 != 0;
            space.region_at(self.base).is_some_and(|r| r.base == self.base && r.kind == Kind::Private)
                && committed(self.base)
                && committed(self.base + self.committed - PAGE)
        }

        /// Commit the segment so the area covers `bytes`; refused past the reservation.
        fn grow(&mut self, space: &mut AddressSpace, bytes: usize) -> bool {
            let Some(end) = (bytes as u64 + AREA as u64).checked_next_multiple_of(PAGE as u64) else {
                return false;
            };
            if end <= self.committed as u64 {
                return true;
            }
            if end > self.reserve as u64 {
                return false;
            }
            let start = self.base + self.committed;
            let size = end as u32 - self.committed;
            if space.commit(&mut CurrentPages, start, size, PAGE_READWRITE).is_err() {
                return false;
            }
            self.committed = end as u32;
            true
        }

        /// A block from the segment, committing more of it as the bump path needs.
        fn segment_alloc(&mut self, space: &mut AddressSpace, request: usize, zero: bool) -> Option<u32> {
            loop {
                let mut top = self.top as usize;
                if let Some(user) = alloc_block(self.area(), &mut top, request, zero) {
                    self.top = top as u32;
                    return Some(self.base + AREA + user as u32);
                }
                // Commit a page beyond the need (so small streams do not commit per allocation);
                // past the reservation, exactly the need.
                let need = round_up(request)?.checked_add(top + HEADER_SIZE)?;
                if !self.grow(space, need + PAGE as usize) && !self.grow(space, need) {
                    return None;
                }
            }
        }

        /// A big block: a reservation of its own, committed whole.
        fn big_alloc(&mut self, space: &mut AddressSpace, request: usize) -> Option<u32> {
            let slot = self.big.iter().position(|b| b.base == 0)?;
            let size = (request as u64 + BIG_HEADER as u64).checked_next_multiple_of(PAGE as u64)?;
            if size > u32::MAX as u64 {
                return None;
            }
            let base = space.reserve(None, size as u32, PAGE_READWRITE, Kind::Private).ok()?;
            if space.commit(&mut CurrentPages, base, size as u32, PAGE_READWRITE).is_err() {
                let _ = space.release(&mut CurrentPages, base);
                return None;
            }
            self.big[slot] = Big { base, size: request as u32 };
            Some(base + BIG_HEADER)
        }

        fn alloc(&mut self, space: &mut AddressSpace, request: usize, zero: bool) -> Option<u32> {
            if !self.intact(space) {
                return None;
            }
            if self.growable && request > BIG_THRESHOLD {
                // A big block's pages are fresh: zeroed already.
                return self.big_alloc(space, request);
            }
            self.segment_alloc(space, request, zero)
        }

        /// The big block whose user bytes start at `pointer`.
        fn big_at(&self, pointer: u32) -> Option<usize> {
            self.big
                .iter()
                .position(|b| b.base != 0 && b.base.wrapping_add(BIG_HEADER) == pointer)
        }

        /// The segment offset (from the area's start) of the block at `pointer`.
        fn user_offset(&self, pointer: u32) -> Option<usize> {
            let start = self.base + AREA;
            (pointer >= start && pointer < self.base + self.committed).then(|| (pointer - start) as usize)
        }

        fn size(&self, space: &AddressSpace, pointer: u32) -> Option<u32> {
            if let Some(slot) = self.big_at(pointer) {
                return Some(self.big[slot].size);
            }
            if !self.intact(space) {
                return None;
            }
            let user = self.user_offset(pointer)?;
            block_size(self.area(), self.top as usize, user).map(|s| s as u32)
        }

        fn free(&mut self, space: &mut AddressSpace, pointer: u32) -> bool {
            if let Some(slot) = self.big_at(pointer) {
                let _ = space.release(&mut CurrentPages, self.big[slot].base);
                self.big[slot] = Big::default();
                return true;
            }
            if !self.intact(space) {
                return false;
            }
            match self.user_offset(pointer) {
                Some(user) => free_block(self.area(), self.top as usize, user),
                None => false,
            }
        }

        /// Resize in place: a segment block within its capacity, a big block within its pages.
        fn resize_in_place(&mut self, space: &AddressSpace, pointer: u32, request: usize, zero: bool) -> bool {
            if let Some(slot) = self.big_at(pointer) {
                let big = self.big[slot];
                let room = space.region_at(big.base).map_or(0, |r| r.size - BIG_HEADER) as usize;
                if request > room {
                    return false;
                }
                if zero && request > big.size as usize {
                    // SAFETY: the big block's committed pages, inside its reservation.
                    unsafe {
                        core::ptr::write_bytes(
                            (pointer + big.size) as *mut u8,
                            0,
                            request - big.size as usize,
                        )
                    };
                }
                self.big[slot].size = request as u32;
                return true;
            }
            if !self.intact(space) {
                return false;
            }
            match self.user_offset(pointer) {
                Some(user) => resize_in_place(self.area(), self.top as usize, user, request, zero),
                None => false,
            }
        }

        fn realloc(&mut self, space: &mut AddressSpace, pointer: u32, flags: u32, request: usize) -> Option<u32> {
            let zero = flags & HEAP_ZERO_MEMORY != 0;
            let old = self.size(space, pointer)? as usize;
            // A segment block that should become a big one moves even when it would fit.
            let to_big = self.growable && request > BIG_THRESHOLD && self.big_at(pointer).is_none();
            if (!to_big || flags & HEAP_REALLOC_IN_PLACE_ONLY != 0) && self.resize_in_place(space, pointer, request, zero) {
                return Some(pointer);
            }
            if flags & HEAP_REALLOC_IN_PLACE_ONLY != 0 {
                return None;
            }
            let new = self.alloc(space, request, false)?;
            let kept = old.min(request);
            // SAFETY: two distinct live blocks of this heap, committed user memory of the current
            // process, each at least `kept` bytes long.
            unsafe {
                core::ptr::copy_nonoverlapping(pointer as *const u8, new as *mut u8, kept);
                if zero && request > kept {
                    core::ptr::write_bytes((new as usize + kept) as *mut u8, 0, request - kept);
                }
            }
            self.free(space, pointer);
            Some(new)
        }

        fn validate(&self, space: &AddressSpace, pointer: u32) -> bool {
            if pointer != 0 {
                return self.size(space, pointer).is_some();
            }
            self.intact(space) && validate_area(self.area(), self.top as usize)
        }

        /// Give everything back: the big blocks and the segment.
        fn destroy(&mut self, space: &mut AddressSpace) {
            for big in self.big.iter().filter(|b| b.base != 0) {
                let _ = space.release(&mut CurrentPages, big.base);
            }
            let _ = space.release(&mut CurrentPages, self.base);
            self.live = false;
        }
    }

    impl Heaps {
        /// HeapCreate's work: a segment of `maximum` bytes (rounded to pages) — a growable heap's
        /// fixed reservation when zero — with `initial` bytes committed. The handle, or none.
        pub fn create(&mut self, space: &mut AddressSpace, flags: u32, initial: u32, maximum: u32) -> Option<u32> {
            let slot = self.heaps.iter().position(|h| !h.live)?;
            let growable = maximum == 0;
            let reserve = if growable {
                GROWABLE_RESERVE
            } else {
                (maximum.max(initial) as u64).max(PAGE as u64).checked_next_multiple_of(PAGE as u64)? as u32
            };
            let base = space.reserve(None, reserve, PAGE_READWRITE, Kind::Private).ok()?;
            let commit = (initial.max(AREA) as u64).next_multiple_of(PAGE as u64).min(reserve as u64) as u32;
            if space.commit(&mut CurrentPages, base, commit, PAGE_READWRITE).is_err() {
                let _ = space.release(&mut CurrentPages, base);
                return None;
            }
            self.heaps[slot] = Heap {
                live: true,
                base,
                reserve,
                committed: commit,
                top: 0,
                flags,
                growable,
                big: [Big::default(); BIG_BLOCKS],
            };
            Some(base)
        }

        /// Create the process heap (growable): its handle, for the PEB.
        pub fn create_process_heap(&mut self, space: &mut AddressSpace) -> u32 {
            self.process = self.create(space, 0, 0, 0).unwrap_or(0);
            self.process
        }
    }

    // --- Services ------------------------------------------------------------------------------

    use crate::user::TrapFrame;

    /// Run `body` over the running process's heaps and address space.
    fn with_heaps<R>(body: impl FnOnce(&mut Heaps, &mut AddressSpace) -> R) -> R {
        let process = crate::process::current_mut();
        let (heaps, space) = process.heaps_and_vm();
        body(heaps, space)
    }

    /// A failed allocation's end: zero, or STATUS_NO_MEMORY raised when the heap (or the call)
    /// generates exceptions.
    fn refuse(frame: &mut TrapFrame, flags: u32, request: u32, arg_bytes: u32) {
        frame.eax = 0;
        if flags & HEAP_GENERATE_EXCEPTIONS != 0 {
            crate::user::seh::raise_in_service(frame, STATUS_NO_MEMORY, &[request], arg_bytes);
        }
    }

    /// HeapCreate.
    pub fn svc_heap_create(frame: &mut TrapFrame, args: &[u32]) {
        let (flags, initial, maximum) = (args[0], args[1], args[2]);
        match with_heaps(|heaps, space| heaps.create(space, flags, initial, maximum)) {
            Some(handle) => frame.eax = handle,
            None => {
                frame.eax = 0;
                crate::user::teb::set_last_error(crate::compat::error::ERROR_NOT_ENOUGH_MEMORY);
            }
        }
    }

    /// HeapAlloc.
    pub fn svc_heap_alloc(frame: &mut TrapFrame, args: &[u32]) {
        let (handle, flags, request) = (args[0], args[1], args[2]);
        let (served, heap_flags) = with_heaps(|heaps, space| match heaps.heap(handle) {
            Some(heap) => (heap.alloc(space, request as usize, flags & HEAP_ZERO_MEMORY != 0), heap.flags),
            None => (None, 0),
        });
        match served {
            Some(pointer) => frame.eax = pointer,
            None => refuse(frame, flags | heap_flags, request, 12),
        }
    }

    /// HeapReAlloc.
    pub fn svc_heap_realloc(frame: &mut TrapFrame, args: &[u32]) {
        let (handle, flags, pointer, request) = (args[0], args[1], args[2], args[3]);
        let (served, heap_flags) = with_heaps(|heaps, space| match heaps.heap(handle) {
            Some(heap) => (heap.realloc(space, pointer, flags, request as usize), heap.flags),
            None => (None, 0),
        });
        match served {
            Some(pointer) => frame.eax = pointer,
            // An in-place growth that does not fit is a plain refusal.
            None if flags & HEAP_REALLOC_IN_PLACE_ONLY != 0 => frame.eax = 0,
            None => refuse(frame, flags | heap_flags, request, 16),
        }
    }

    /// HeapFree: a null pointer frees nothing and succeeds.
    pub fn svc_heap_free(frame: &mut TrapFrame, args: &[u32]) {
        let (handle, pointer) = (args[0], args[2]);
        frame.eax = u32::from(
            pointer == 0
                || with_heaps(|heaps, space| heaps.heap(handle).is_some_and(|heap| heap.free(space, pointer))),
        );
    }

    /// HeapSize: the size asked for; -1 for what is not a block.
    pub fn svc_heap_size(frame: &mut TrapFrame, args: &[u32]) {
        let (handle, pointer) = (args[0], args[2]);
        frame.eax = with_heaps(|heaps, space| heaps.heap(handle).and_then(|heap| heap.size(space, pointer)))
            .unwrap_or(u32::MAX);
    }

    /// HeapValidate: the whole heap's headers (null pointer), or one block.
    pub fn svc_heap_validate(frame: &mut TrapFrame, args: &[u32]) {
        let (handle, pointer) = (args[0], args[2]);
        frame.eax = u32::from(with_heaps(|heaps, space| {
            heaps.heap(handle).is_some_and(|heap| heap.validate(space, pointer))
        }));
    }

    /// HeapDestroy: every page of the heap given back. The process heap stays.
    pub fn svc_heap_destroy(frame: &mut TrapFrame, args: &[u32]) {
        let handle = args[0];
        let destroyed = with_heaps(|heaps, space| {
            if handle == heaps.process {
                return false;
            }
            match heaps.heap(handle) {
                Some(heap) => {
                    heap.destroy(space);
                    true
                }
                None => false,
            }
        });
        frame.eax = u32::from(destroyed);
        if !destroyed {
            crate::user::teb::set_last_error(crate::compat::error::ERROR_INVALID_HANDLE);
        }
    }

    /// The process heap's handle (Local and Global memory live there).
    pub fn process_heap() -> u32 {
        with_heaps(|heaps, _| heaps.process)
    }

    /// Allocate, resize, free and size on a heap by handle, for Local and Global memory.
    pub fn alloc(handle: u32, flags: u32, request: usize) -> Option<u32> {
        with_heaps(|heaps, space| heaps.heap(handle)?.alloc(space, request, flags & HEAP_ZERO_MEMORY != 0))
    }
    pub fn realloc(handle: u32, flags: u32, pointer: u32, request: usize) -> Option<u32> {
        with_heaps(|heaps, space| heaps.heap(handle)?.realloc(space, pointer, flags, request))
    }
    pub fn free(handle: u32, pointer: u32) -> bool {
        with_heaps(|heaps, space| heaps.heap(handle).is_some_and(|heap| heap.free(space, pointer)))
    }
    pub fn size(handle: u32, pointer: u32) -> Option<u32> {
        with_heaps(|heaps, space| heaps.heap(handle).and_then(|heap| heap.size(space, pointer)))
    }
}

#[cfg(target_arch = "x86")]
pub use target::*;

// Host stubs: the kernel32 registry names these but host builds never dispatch services.

#[cfg(not(target_arch = "x86"))]
mod host {
    use crate::user::TrapFrame;

    fn target_only() -> ! {
        unimplemented!("heap services run on the target")
    }

    pub fn svc_heap_create(_frame: &mut TrapFrame, _args: &[u32]) {
        target_only()
    }
    pub fn svc_heap_alloc(_frame: &mut TrapFrame, _args: &[u32]) {
        target_only()
    }
    pub fn svc_heap_realloc(_frame: &mut TrapFrame, _args: &[u32]) {
        target_only()
    }
    pub fn svc_heap_free(_frame: &mut TrapFrame, _args: &[u32]) {
        target_only()
    }
    pub fn svc_heap_size(_frame: &mut TrapFrame, _args: &[u32]) {
        target_only()
    }
    pub fn svc_heap_validate(_frame: &mut TrapFrame, _args: &[u32]) {
        target_only()
    }
    pub fn svc_heap_destroy(_frame: &mut TrapFrame, _args: &[u32]) {
        target_only()
    }
    pub fn process_heap() -> u32 {
        target_only()
    }
    pub fn alloc(_handle: u32, _flags: u32, _request: usize) -> Option<u32> {
        target_only()
    }
    pub fn realloc(_handle: u32, _flags: u32, _pointer: u32, _request: usize) -> Option<u32> {
        target_only()
    }
    pub fn free(_handle: u32, _pointer: u32) -> bool {
        target_only()
    }
    pub fn size(_handle: u32, _pointer: u32) -> Option<u32> {
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

    // --- Exact sizes and in-place resizing ---------------------------------

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
        assert!(!resize_in_place(&mut arena.bytes, arena.top, a, 0x100, false));
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
