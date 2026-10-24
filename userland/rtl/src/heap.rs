//! The Win32 heaps, in user mode as Windows 2000's ntdll runs them (the RtlCreateHeap family;
//! kernel32's Heap functions forward here or call in, and Local/Global memory lives on the process
//! heap): every byte of a heap, its bookkeeping included, is the program's own memory, so the
//! kernel never touches it, and a heap the program corrupts fails or faults the program alone.
//!
//! A heap is a chain of segments — reservations committed on demand from their start, the first
//! one's base the heap's handle — and, for a growable heap, its big blocks: a request past
//! [`BIG_THRESHOLD`] gets a reservation of its own (NT's virtual-alloc blocks), linked from the
//! heap's header. The first segment reserves what the heap was created with (the process heap's:
//! the image header's SizeOfHeapReserve); when a growable heap's segments cannot serve a request,
//! it adds a segment of [`SEGMENT_RESERVE`] bytes wherever the address space has room, as Windows'
//! heaps do. A heap created with a maximum size is its first segment and nothing more: it refuses
//! what does not fit.
//!
//! The first segment starts with the heap's header ([`Header`]): NT's signature, flags and force
//! flags at their offsets (programs read the process heap's flags), the first segment's
//! bookkeeping ([`Segment`]: its reservation, committed prefix, bump edge and the next segment),
//! the big blocks' list, and the heap's lock — a critical section, unless the heap or the call says
//! HEAP_NO_SERIALIZE. Its blocks follow ([`AREA`] bytes in); a further segment starts with its own
//! bookkeeping alone, its blocks [`SEGMENT_AREA`] bytes in. The pure allocator core
//! ([`crate::heapcore`]) manages each segment's blocks; the heap tries its segments in order.
//!
//! The heaps reach their memory through three audited functions ([`place`], [`view`], [`bytes`]):
//! the bookkeeping is typed (its changing words are cells), and the logic above them is safe Rust.
//!
//! The process's heaps are listed in its PEB ([`HeapList`]: NumberOfHeaps, MaximumNumberOfHeaps,
//! ProcessHeaps), under a lock of the process's own; a handle that is not listed is no heap, and
//! the calls refuse it without touching it.

use core::cell::Cell;
use core::mem::size_of;
use core::sync::atomic::{AtomicI32, AtomicU32};

use crate::critsec::{CriticalSection, System};
use crate::heapcore::{
    alloc_block,
    block_size,
    free_block,
    resize_in_place,
    round_up,
    validate_area,
    Refusal,
    HEADER_SIZE,
};

/// The heap flags (public constants).
pub const HEAP_NO_SERIALIZE: u32 = 0x0000_0001;
pub const HEAP_GROWABLE: u32 = 0x0000_0002;
pub const HEAP_GENERATE_EXCEPTIONS: u32 = 0x0000_0004;
pub const HEAP_ZERO_MEMORY: u32 = 0x0000_0008;
pub const HEAP_REALLOC_IN_PLACE_ONLY: u32 = 0x0000_0010;

/// STATUS_NO_MEMORY: what a heap that generates exceptions raises when it cannot serve.
pub const STATUS_NO_MEMORY: u32 = 0xC000_0017;

/// The page: reservations and commits are whole pages.
pub const PAGE: usize = 0x1000;
/// The address space's allocation granularity: a first segment sized from its commit alone
/// reserves a multiple of it.
const GRANULARITY: usize = 0x1_0000;
/// A first segment's reservation when the heap is created with neither a reservation nor a commit
/// size: 64 pages (RtlCreateHeap's documented default).
pub const DEFAULT_RESERVE: usize = 64 * PAGE;
/// A further segment's reservation (NT's default segment reserve, the PEB's HeapSegmentReserve:
/// 1 MiB), or more when a request needs it.
pub const SEGMENT_RESERVE: usize = 0x10_0000;
/// The largest request a growable heap serves from its segments; larger ones get a reservation of
/// their own (NT's virtual-block threshold).
pub const BIG_THRESHOLD: usize = 0x7_F000;
/// How many heaps a process can hold (the PEB's MaximumNumberOfHeaps).
pub const HEAPS: u32 = 16;
/// The header's signature word (NT's HEAP.Signature).
pub const SIGNATURE: u32 = 0xEEFF_EEFF;

/// The creation flags a heap keeps (the rest of HeapCreate's options are the platform's alone).
const KEPT_FLAGS: u32 = HEAP_NO_SERIALIZE | HEAP_GENERATE_EXCEPTIONS;

/// What the heaps need of the address space: reservations, committed on demand, given back whole.
pub trait Vm {
    /// Reserve `size` bytes (whole pages) anywhere: the base, or none when the address space has
    /// no room.
    fn reserve(&self, size: usize) -> Option<usize>;
    /// Commit `size` bytes (whole pages) at `base`, inside a reservation, read-write; fresh pages
    /// read zero. False when refused (no memory).
    fn commit(&self, base: usize, size: usize) -> bool;
    /// Give the reservation at `base` back, whole.
    fn release(&self, base: usize);
}

/// A segment's bookkeeping: its reservation and its committed prefix (both from the segment's
/// base), its block area's bump edge (from the area's start), and the next segment's base (zero:
/// the last).
#[repr(C)]
struct Segment {
    reserve: usize,
    committed: Cell<usize>,
    top: Cell<usize>,
    next: Cell<usize>,
}

/// The heap's header, at its handle (on the target: NT's signature at +0x08, flags at +0x0C, force
/// flags at +0x10).
#[repr(C)]
struct Header {
    /// NT's leading HEAP_ENTRY: unused here, zero.
    entry: [u32; 2],
    signature: u32,
    /// The kept creation flags, and HEAP_GROWABLE for a heap that adds segments.
    flags: u32,
    /// The flags forced on every call (a debugger's): none.
    force_flags: u32,
    /// The first segment's bookkeeping, which links the others.
    segment: Segment,
    /// The first big block's reservation (zero: none); each links the next.
    big: Cell<usize>,
    /// The heap's lock (unless the heap or the call is HEAP_NO_SERIALIZE).
    lock: CriticalSection,
}

/// The bytes of the first segment before its first block: the header, 8-aligned.
pub const AREA: usize = (size_of::<Header>() + 7) & !7;

/// The bytes of a further segment before its first block: its bookkeeping, 8-aligned.
pub const SEGMENT_AREA: usize = (size_of::<Segment>() + 7) & !7;

/// A big block's header, at its reservation's base: the next big block, the size asked for, and the
/// reservation's size. The user bytes follow it.
#[repr(C)]
struct Big {
    next: Cell<usize>,
    size: Cell<usize>,
    reserved: usize,
    _pad: usize,
}

/// A big block's header size: its user bytes start this far into its reservation.
const BIG_HEADER: usize = size_of::<Big>();

#[cfg(target_arch = "x86")]
const _: () = {
    // The header's documented words sit where NT keeps them, and the blocks start 0x40 in.
    assert!(core::mem::offset_of!(Header, signature) == 0x08);
    assert!(core::mem::offset_of!(Header, flags) == 0x0C);
    assert!(core::mem::offset_of!(Header, force_flags) == 0x10);
    assert!(AREA == 0x40);
    assert!(SEGMENT_AREA == 0x10);
    assert!(BIG_HEADER == 0x10);
};

// --- The heaps' memory: the audited accesses
// ------------------------------------------------------

/// Put `value` at `at`, a fresh place: the start of a reservation's committed first page, aligned
/// for any of the heaps' types, that no live heap uses yet (a new heap's header, a new segment's
/// bookkeeping, a new big block's header). The value, in place.
fn place<T>(at: usize, value: T) -> &'static T {
    let slot = at as *mut T;
    // SAFETY: the callers pass the base of a reservation they just committed: page-aligned,
    // read-write, at least a page long (every placed type is smaller), and theirs alone until the
    // heap's handle or link to it is published.
    unsafe {
        slot.write(value);
        &*slot
    }
}

/// The bookkeeping [`place`] put at `at`, as long as its heap lives (its changing words are cells,
/// so shared views of it never alias a mutable one).
fn view<T>(at: usize) -> &'static T {
    // SAFETY: the callers pass a live heap's handle (listed in the process's heap list), or a
    // segment's or big block's base read from that heap's links: places [`place`] wrote, committed
    // until the heap's destroy or the block's free gives them back. The program can overwrite them
    // (they are its memory); the heaps then fail or fault the program alone.
    unsafe { &*(at as *const T) }
}

/// The `len` bytes at `at`: a segment's block area or a block's user bytes.
fn bytes(at: usize, len: usize) -> &'static mut [u8] {
    // SAFETY: the callers pass committed ranges of a live heap past its bookkeeping (a segment's
    // committed area, a big block's user bytes, or a live block's `len` bytes), which no other
    // view covers for the call: the heap's lock (or the caller's HEAP_NO_SERIALIZE promise) keeps
    // them ours.
    unsafe { core::slice::from_raw_parts_mut(at as *mut u8, len) }
}

// --- Segments
// -------------------------------------------------------------------------------------

/// One segment of a heap: its base, its bookkeeping (in the heap's header for the first segment,
/// at its base for the others), and where its block area starts (from the base).
#[derive(Clone, Copy)]
struct Seg {
    base: usize,
    info: &'static Segment,
    start: usize,
}

impl Seg {
    /// The further segment at `base`.
    fn further(base: usize) -> Seg {
        Seg {
            base,
            info: view(base),
            start: SEGMENT_AREA,
        }
    }

    /// The committed block area.
    fn area(self) -> &'static mut [u8] {
        let len = self.info.committed.get().saturating_sub(self.start);
        bytes(self.base + self.start, len)
    }

    /// The area offset of the block at `pointer`, when it lies in this segment's committed area.
    fn user_offset(self, pointer: usize) -> Option<usize> {
        let start = self.base + self.start;
        let end = self.base + self.info.committed.get();
        (pointer >= start && pointer < end).then(|| pointer - start)
    }

    /// Commit the segment so the area covers `bytes`; refused past the reservation.
    fn grow(self, system: &impl Vm, bytes: usize) -> bool {
        let Some(end) = bytes
            .checked_add(self.start)
            .and_then(|end| end.checked_next_multiple_of(PAGE))
        else {
            return false;
        };
        let committed = self.info.committed.get();
        if end <= committed {
            return true;
        }
        if end > self.info.reserve || !system.commit(self.base + committed, end - committed) {
            return false;
        }
        self.info.committed.set(end);
        true
    }

    /// A block from the segment, committing more of it as the bump path needs: refused as full when
    /// the reservation (or the address space) has no more room, as corrupt when a header on the
    /// walk is not a block.
    fn alloc(self, system: &impl Vm, request: usize, zero: bool) -> Result<usize, Refusal> {
        loop {
            let mut top = self.info.top.get();
            match alloc_block(self.area(), &mut top, request, zero) {
                Ok(user) => {
                    self.info.top.set(top);
                    return Ok(self.base + self.start + user);
                }
                Err(Refusal::Corrupt) => return Err(Refusal::Corrupt),
                Err(Refusal::Full) => {}
            }
            // Commit a page beyond the need (so small streams do not commit per allocation); past
            // the reservation, exactly the need.
            let need = round_up(request)
                .and_then(|need| need.checked_add(top + HEADER_SIZE))
                .ok_or(Refusal::Full)?;
            let committed = self.info.committed.get();
            if !self.grow(system, need + PAGE) && !self.grow(system, need) {
                return Err(Refusal::Full);
            }
            // Retry only when the grow committed more: with the room already there, more commits
            // cannot help, and the call must not retry forever (MEM-1).
            if self.info.committed.get() == committed {
                return Err(Refusal::Full);
            }
        }
    }

    /// The size asked for of the block at area offset `user`.
    fn size(self, user: usize) -> Option<usize> {
        block_size(self.area(), self.info.top.get(), user)
    }

    /// Free the block at area offset `user`.
    fn free(self, user: usize) -> bool {
        free_block(self.area(), self.info.top.get(), user)
    }

    /// Resize the block at area offset `user` without moving it.
    fn resize(self, user: usize, request: usize, zero: bool) -> bool {
        resize_in_place(self.area(), self.info.top.get(), user, request, zero)
    }

    /// Whether every header of the area describes a block.
    fn validate(self) -> bool {
        validate_area(self.area(), self.info.top.get())
    }
}

/// A heap's segments, first to last.
struct Segments(Option<Seg>);

impl Iterator for Segments {
    type Item = Seg;

    fn next(&mut self) -> Option<Seg> {
        let segment = self.0?;
        self.0 = match segment.info.next.get() {
            0 => None,
            next => Some(Seg::further(next)),
        };
        Some(segment)
    }
}

// --- Heaps ----------------------------------------------------------------------------------------

/// A live heap, by its handle (its first segment's base).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Heap(usize);

/// Create a heap as HeapCreate asks for one: growable when `maximum` is zero (its first segment
/// sized from `initial`, as [`create_sized`] sizes it), else one segment of `maximum` bytes (at
/// least `initial`, rounded to pages); `initial` bytes committed. None when the address space has
/// no room.
pub fn create(
    system: &(impl System + Vm),
    flags: u32,
    initial: usize,
    maximum: usize,
) -> Option<Heap> {
    if maximum == 0 {
        create_sized(system, flags | HEAP_GROWABLE, 0, initial)
    } else {
        create_sized(
            system,
            flags & !HEAP_GROWABLE,
            maximum.max(initial),
            initial,
        )
    }
}

/// Create a heap as RtlCreateHeap sizes one: a first segment reserving `reserve` bytes with
/// `commit` committed — both zero: 64 pages reserved, one committed; no reservation size: the
/// commit size rounded up to the allocation granularity; no commit size: one page; a commit size
/// past the reservation: the reservation — and, for a growable heap (HEAP_GROWABLE, or no
/// reservation size), further segments as it fills. None when the address space has no room.
pub fn create_sized(
    system: &(impl System + Vm),
    flags: u32,
    reserve: usize,
    commit: usize,
) -> Option<Heap> {
    let growable = flags & HEAP_GROWABLE != 0 || reserve == 0;
    let (reserve, commit) = match (reserve, commit) {
        (0, 0) => (DEFAULT_RESERVE, PAGE),
        (0, commit) => (commit.checked_next_multiple_of(GRANULARITY)?, commit),
        (reserve, 0) => (reserve, PAGE),
        (reserve, commit) => (reserve, commit.min(reserve)),
    };
    let reserve = reserve.max(PAGE).checked_next_multiple_of(PAGE)?;
    let base = system.reserve(reserve)?;
    let commit = commit
        .max(AREA)
        .checked_next_multiple_of(PAGE)
        .unwrap_or(reserve)
        .min(reserve);
    if !system.commit(base, commit) {
        system.release(base);
        return None;
    }
    let header = place(
        base,
        Header {
            entry: [0; 2],
            signature: SIGNATURE,
            flags: flags & KEPT_FLAGS | if growable { HEAP_GROWABLE } else { 0 },
            force_flags: 0,
            segment: Segment {
                reserve,
                committed: Cell::new(commit),
                top: Cell::new(0),
                next: Cell::new(0),
            },
            big: Cell::new(0),
            lock: CriticalSection {
                debug_info: AtomicU32::new(0),
                lock_count: AtomicI32::new(0),
                recursion_count: AtomicI32::new(0),
                owning_thread: AtomicU32::new(0),
                lock_semaphore: AtomicU32::new(0),
                spin_count: AtomicU32::new(0),
            },
        },
    );
    // Spin count 0 and no preallocated event: the initialization cannot fail.
    let _ = header.lock.initialize(system, 0);
    Some(Heap(base))
}

impl Heap {
    /// The heap whose handle is `handle`.
    ///
    /// # Safety
    /// `handle` names a live heap of this process (one [`create`] made, not yet destroyed): the
    /// heap list's membership ([`HeapList::contains`]) is the check.
    pub unsafe fn from_handle(handle: usize) -> Heap {
        Heap(handle)
    }

    /// The heap's handle.
    pub fn handle(self) -> usize {
        self.0
    }

    fn header(self) -> &'static Header {
        view(self.0)
    }

    /// The heap's flags (its kept creation flags, HEAP_GROWABLE for a growable one).
    pub fn flags(self) -> u32 {
        self.header().flags
    }

    fn growable(self) -> bool {
        self.flags() & HEAP_GROWABLE != 0
    }

    /// The first segment, whose bookkeeping is the header's.
    fn first(self) -> Seg {
        Seg {
            base: self.0,
            info: &self.header().segment,
            start: AREA,
        }
    }

    /// The heap's segments, first to last.
    fn segments(self) -> Segments {
        Segments(Some(self.first()))
    }

    /// The segment holding the block at `pointer`, and the block's area offset there.
    fn find(self, pointer: usize) -> Option<(Seg, usize)> {
        self.segments()
            .find_map(|segment| Some((segment, segment.user_offset(pointer)?)))
    }

    /// Run `body` holding the heap's lock, unless the heap or the call is HEAP_NO_SERIALIZE.
    fn locked<R>(self, system: &impl System, flags: u32, body: impl FnOnce() -> R) -> R {
        let serialize = (flags | self.flags()) & HEAP_NO_SERIALIZE == 0;
        let lock = &self.header().lock;
        if serialize {
            lock.enter(system);
        }
        let result = body();
        if serialize {
            lock.leave(system);
        }
        result
    }

    /// RtlLockHeap's work: the heap's lock taken, held across the caller's calls (they take it
    /// again, recursively); a HEAP_NO_SERIALIZE heap has none to take.
    pub fn lock(self, system: &impl System) {
        if self.flags() & HEAP_NO_SERIALIZE == 0 {
            self.header().lock.enter(system);
        }
    }

    /// RtlUnlockHeap's work: the lock [`Heap::lock`] took, released.
    pub fn unlock(self, system: &impl System) {
        if self.flags() & HEAP_NO_SERIALIZE == 0 {
            self.header().lock.leave(system);
        }
    }

    /// A further segment linked after `last`, with room for `request`: [`SEGMENT_RESERVE`] bytes
    /// reserved, or the request's own size when larger, its first page committed.
    fn add_segment(self, system: &impl Vm, last: Seg, request: usize) -> Option<Seg> {
        let reserve = round_up(request)?
            .checked_add(SEGMENT_AREA + HEADER_SIZE)?
            .checked_next_multiple_of(PAGE)?
            .max(SEGMENT_RESERVE);
        let base = system.reserve(reserve)?;
        if !system.commit(base, PAGE) {
            system.release(base);
            return None;
        }
        let info = place(
            base,
            Segment {
                reserve,
                committed: Cell::new(PAGE),
                top: Cell::new(0),
                next: Cell::new(0),
            },
        );
        last.info.next.set(base);
        Some(Seg {
            base,
            info,
            start: SEGMENT_AREA,
        })
    }

    /// A big block: a reservation of its own, committed whole (its pages read zero), linked first.
    fn big_alloc(self, system: &impl Vm, request: usize) -> Option<usize> {
        let reserved = request
            .checked_add(BIG_HEADER)?
            .checked_next_multiple_of(PAGE)?;
        let base = system.reserve(reserved)?;
        if !system.commit(base, reserved) {
            system.release(base);
            return None;
        }
        let list = &self.header().big;
        place(
            base,
            Big {
                next: Cell::new(list.get()),
                size: Cell::new(request),
                reserved,
                _pad: 0,
            },
        );
        list.set(base);
        Some(base + BIG_HEADER)
    }

    /// The big block whose user bytes start at `pointer`: the link that names it, and its header.
    fn big_at(self, pointer: usize) -> Option<(&'static Cell<usize>, &'static Big)> {
        let mut link = &self.header().big;
        while link.get() != 0 {
            let big: &'static Big = view(link.get());
            if link.get().wrapping_add(BIG_HEADER) == pointer {
                return Some((link, big));
            }
            link = &big.next;
        }
        None
    }

    /// A block from the first segment that serves it; a growable heap whose segments are all full
    /// adds one. A corrupt segment fails the call: a further segment would only hide it.
    fn alloc_inner(self, system: &impl Vm, request: usize, zero: bool) -> Option<usize> {
        if self.growable() && request > BIG_THRESHOLD {
            return self.big_alloc(system, request);
        }
        let mut last = self.first();
        for segment in self.segments() {
            match segment.alloc(system, request, zero) {
                Ok(pointer) => return Some(pointer),
                Err(Refusal::Corrupt) => return None,
                Err(Refusal::Full) => last = segment,
            }
        }
        if !self.growable() {
            return None;
        }
        self.add_segment(system, last, request)?
            .alloc(system, request, zero)
            .ok()
    }

    fn size_inner(self, pointer: usize) -> Option<usize> {
        if let Some((_, big)) = self.big_at(pointer) {
            return Some(big.size.get());
        }
        let (segment, user) = self.find(pointer)?;
        segment.size(user)
    }

    fn free_inner(self, system: &impl Vm, pointer: usize) -> bool {
        if let Some((link, big)) = self.big_at(pointer) {
            let base = link.get();
            link.set(big.next.get());
            system.release(base);
            return true;
        }
        self.find(pointer)
            .is_some_and(|(segment, user)| segment.free(user))
    }

    /// Resize in place: a segment block within its capacity, a big block within its pages.
    fn resize_inner(self, pointer: usize, request: usize, zero: bool) -> bool {
        if let Some((_, big)) = self.big_at(pointer) {
            if request > big.reserved - BIG_HEADER {
                return false;
            }
            let old = big.size.get();
            if zero && request > old {
                bytes(pointer + old, request - old).fill(0);
            }
            big.size.set(request);
            return true;
        }
        self.find(pointer)
            .is_some_and(|(segment, user)| segment.resize(user, request, zero))
    }

    /// HeapAlloc's work: a block of `request` bytes (zeroed for HEAP_ZERO_MEMORY), or none.
    pub fn alloc(self, system: &(impl System + Vm), flags: u32, request: usize) -> Option<usize> {
        self.locked(system, flags, || {
            self.alloc_inner(system, request, flags & HEAP_ZERO_MEMORY != 0)
        })
    }

    /// HeapSize's work: the size asked for of the block at `pointer`, or none for what is not one.
    pub fn size(self, system: &impl System, flags: u32, pointer: usize) -> Option<usize> {
        self.locked(system, flags, || self.size_inner(pointer))
    }

    /// HeapFree's work: false for what is not a block of the heap.
    pub fn free(self, system: &(impl System + Vm), flags: u32, pointer: usize) -> bool {
        self.locked(system, flags, || self.free_inner(system, pointer))
    }

    /// HeapReAlloc's work: the block resized — in place when it fits (always for
    /// HEAP_REALLOC_IN_PLACE_ONLY, which otherwise refuses), else moved, its contents kept and an
    /// extension zeroed for HEAP_ZERO_MEMORY. A segment block that grows past the big-block
    /// threshold of a growable heap moves even when it would fit. The original is untouched on
    /// failure.
    pub fn realloc(
        self,
        system: &(impl System + Vm),
        flags: u32,
        pointer: usize,
        request: usize,
    ) -> Option<usize> {
        self.locked(system, flags, || {
            let zero = flags & HEAP_ZERO_MEMORY != 0;
            let in_place_only = flags & HEAP_REALLOC_IN_PLACE_ONLY != 0;
            let old = self.size_inner(pointer)?;
            let to_big =
                self.growable() && request > BIG_THRESHOLD && self.big_at(pointer).is_none();
            if (!to_big || in_place_only) && self.resize_inner(pointer, request, zero) {
                return Some(pointer);
            }
            if in_place_only {
                return None;
            }
            let new = self.alloc_inner(system, request, false)?;
            // Two distinct live blocks, the new one at least `request` bytes long.
            let kept = old.min(request);
            bytes(new, kept).copy_from_slice(bytes(pointer, kept));
            if zero && request > kept {
                bytes(new + kept, request - kept).fill(0);
            }
            self.free_inner(system, pointer);
            Some(new)
        })
    }

    /// HeapValidate's work: every segment's headers (a null pointer), or one block.
    pub fn validate(self, system: &impl System, flags: u32, pointer: usize) -> bool {
        self.locked(system, flags, || {
            if pointer != 0 {
                return self.size_inner(pointer).is_some();
            }
            self.segments().all(Seg::validate)
        })
    }

    /// HeapDestroy's work: every page given back — the big blocks, the further segments, then the
    /// first (each link read before its reservation goes).
    pub fn destroy(self, system: &(impl System + Vm)) {
        let header = self.header();
        let mut next = header.big.get();
        while next != 0 {
            let big: &Big = view(next);
            let base = next;
            next = big.next.get();
            system.release(base);
        }
        let mut next = header.segment.next.get();
        while next != 0 {
            let segment = Seg::further(next);
            next = segment.info.next.get();
            system.release(segment.base);
        }
        header.lock.delete(system);
        system.release(self.0);
    }
}

// --- The process's heaps -------------------------------------------------------------------------

/// The PEB's heap list (NumberOfHeaps at PEB+0x88, MaximumNumberOfHeaps at +0x8C, ProcessHeaps at
/// +0x90: an array of handles, the first the process heap).
#[repr(C)]
pub struct HeapList {
    pub count: u32,
    pub maximum: u32,
    pub heaps: *mut usize,
}

impl HeapList {
    /// The listed handles.
    fn handles(&self) -> &[usize] {
        if self.heaps.is_null() {
            return &[];
        }
        // SAFETY: the array the kernel planted beside the PEB, `maximum` long, `count` used.
        unsafe { core::slice::from_raw_parts(self.heaps, self.count.min(self.maximum) as usize) }
    }

    /// Whether `handle` names one of the process's heaps.
    pub fn contains(&self, handle: usize) -> bool {
        handle != 0 && self.handles().contains(&handle)
    }

    /// The listed heap `handle` names, or none (the calls' check before they touch a heap).
    pub fn heap(&self, handle: usize) -> Option<Heap> {
        // SAFETY: listed handles name live heaps (created, not yet destroyed).
        self.contains(handle)
            .then(|| unsafe { Heap::from_handle(handle) })
    }

    fn add(&mut self, handle: usize) -> bool {
        if self.heaps.is_null() || self.count >= self.maximum {
            return false;
        }
        // SAFETY: a slot of the array, below its maximum.
        unsafe { self.heaps.add(self.count as usize).write(handle) };
        self.count += 1;
        true
    }

    fn remove(&mut self, handle: usize) -> bool {
        let Some(at) = self.handles().iter().position(|&h| h == handle) else {
            return false;
        };
        let last = self.count as usize - 1;
        // SAFETY: slots of the array below its count: the last moves into the freed one.
        unsafe {
            self.heaps.add(at).write(self.heaps.add(last).read());
            self.heaps.add(last).write(0);
        }
        self.count -= 1;
        true
    }
}

/// The process's heaps: its PEB's list and the lock that guards it.
pub struct Process {
    pub list: *mut HeapList,
    pub lock: *const CriticalSection,
}

impl Process {
    /// The list, through its PEB pointer: the PEB's memory, not this handle's, so a shared handle
    /// hands it out (its writers hold the heap-list lock).
    #[allow(clippy::mut_from_ref)]
    fn list(&self) -> &mut HeapList {
        // SAFETY: the PEB's list, written only under the process's heap-list lock.
        unsafe { &mut *self.list }
    }

    fn with_lock<R>(&self, system: &impl System, body: impl FnOnce() -> R) -> R {
        // SAFETY: the process's heap-list lock, initialized at process start.
        let lock = unsafe { &*self.lock };
        lock.enter(system);
        let result = body();
        lock.leave(system);
        result
    }

    /// The process's heap `handle` names, or none.
    pub fn heap(&self, handle: usize) -> Option<Heap> {
        self.list().heap(handle)
    }

    /// Create a heap and list it: none when the address space has no room or the list is full.
    pub fn create(
        &self,
        system: &(impl System + Vm),
        flags: u32,
        initial: usize,
        maximum: usize,
    ) -> Option<Heap> {
        self.listed(system, create(system, flags, initial, maximum)?)
    }

    /// Create a heap as RtlCreateHeap sizes one ([`create_sized`]) and list it: none when the
    /// address space has no room or the list is full.
    pub fn create_sized(
        &self,
        system: &(impl System + Vm),
        flags: u32,
        reserve: usize,
        commit: usize,
    ) -> Option<Heap> {
        self.listed(system, create_sized(system, flags, reserve, commit)?)
    }

    /// List a fresh heap: the heap, or none (and the heap destroyed) when the list is full.
    fn listed(&self, system: &(impl System + Vm), heap: Heap) -> Option<Heap> {
        if !self.with_lock(system, || self.list().add(heap.handle())) {
            heap.destroy(system);
            return None;
        }
        Some(heap)
    }

    /// Unlist and destroy the heap `handle` names: false when it names none.
    pub fn destroy(&self, system: &(impl System + Vm), handle: usize) -> bool {
        let Some(heap) = self.with_lock(system, || {
            let heap = self.list().heap(handle)?;
            self.list().remove(handle).then_some(heap)
        }) else {
            return false;
        };
        heap.destroy(system);
        true
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::cell::RefCell;
    use std::sync::atomic::{AtomicI32, AtomicU32};

    use super::*;

    /// A one-thread system over host memory: reservations are page-aligned zeroed allocations,
    /// commits are counted against a budget (to make them fail), events never block.
    pub struct Host {
        pub live: RefCell<Vec<(usize, usize)>>,
        pub commit_budget: RefCell<usize>,
    }

    impl Host {
        pub fn new() -> Host {
            Host {
                live: RefCell::new(Vec::new()),
                commit_budget: RefCell::new(usize::MAX),
            }
        }

        fn layout(size: usize) -> std::alloc::Layout {
            std::alloc::Layout::from_size_align(size, PAGE).unwrap()
        }
    }

    impl Drop for Host {
        fn drop(&mut self) {
            for (base, size) in self.live.borrow_mut().drain(..) {
                // SAFETY: an allocation reserve made and release never took.
                unsafe { std::alloc::dealloc(base as *mut u8, Host::layout(size)) };
            }
        }
    }

    impl Vm for Host {
        fn reserve(&self, size: usize) -> Option<usize> {
            assert_eq!(size % PAGE, 0, "reservations are whole pages");
            // SAFETY: a nonzero, page-aligned layout.
            let base = unsafe { std::alloc::alloc_zeroed(Host::layout(size)) } as usize;
            (base != 0).then(|| {
                self.live.borrow_mut().push((base, size));
                base
            })
        }

        fn commit(&self, base: usize, size: usize) -> bool {
            assert_eq!(
                (base % PAGE, size % PAGE),
                (0, 0),
                "commits are whole pages"
            );
            assert!(
                self.live
                    .borrow()
                    .iter()
                    .any(|&(b, s)| base >= b && base + size <= b + s),
                "commits stay inside a reservation"
            );
            let mut budget = self.commit_budget.borrow_mut();
            if *budget < size {
                return false;
            }
            *budget -= size;
            true
        }

        fn release(&self, base: usize) {
            let mut live = self.live.borrow_mut();
            let at = live
                .iter()
                .position(|&(b, _)| b == base)
                .expect("a release names a reservation");
            let (base, size) = live.remove(at);
            // SAFETY: the allocation reserve made.
            unsafe { std::alloc::dealloc(base as *mut u8, Host::layout(size)) };
        }
    }

    impl System for Host {
        fn thread_id(&self) -> u32 {
            1
        }

        fn processors(&self) -> u32 {
            1
        }

        fn create_event(&self) -> u32 {
            4
        }

        fn wait(&self, _event: u32) {
            panic!("one thread never waits");
        }

        fn set(&self, _event: u32) {}

        fn close(&self, _handle: u32) {}

        fn raise(&self, status: u32) -> ! {
            panic!("raised {status:#x}");
        }
    }

    /// A free critical section, as the process start leaves the heap-list lock.
    pub fn free_lock() -> CriticalSection {
        CriticalSection {
            debug_info: AtomicU32::new(0),
            lock_count: AtomicI32::new(-1),
            recursion_count: AtomicI32::new(0),
            owning_thread: AtomicU32::new(0),
            lock_semaphore: AtomicU32::new(0),
            spin_count: AtomicU32::new(0),
        }
    }

    /// The heap's segments, first to last: (base, reservation, committed prefix).
    fn segments(heap: Heap) -> Vec<(usize, usize, usize)> {
        heap.segments()
            .map(|segment| {
                (
                    segment.base,
                    segment.info.reserve,
                    segment.info.committed.get(),
                )
            })
            .collect()
    }

    /// The header's fields read as created; a growable heap reserves its default first segment and
    /// commits its first page.
    #[test]
    fn a_heap_starts_with_its_header() {
        let host = Host::new();
        let heap = create(&host, HEAP_NO_SERIALIZE | 0x100, 0, 0).unwrap();
        let header = heap.header();
        assert_eq!(header.signature, SIGNATURE);
        assert_eq!(
            heap.flags(),
            HEAP_NO_SERIALIZE | HEAP_GROWABLE,
            "unknown options are not kept"
        );
        assert_eq!(
            (
                header.segment.top.get(),
                header.segment.next.get(),
                header.big.get()
            ),
            (0, 0, 0)
        );
        assert_eq!(segments(heap), [(heap.handle(), DEFAULT_RESERVE, PAGE)]);
        assert_eq!(
            header
                .lock
                .lock_count
                .load(core::sync::atomic::Ordering::SeqCst),
            -1
        );
        heap.destroy(&host);
        assert!(
            host.live.borrow().is_empty(),
            "destroy gives every page back"
        );
    }

    /// The first segment's sizes, as RtlCreateHeap's documentation lays them out, and HeapCreate's
    /// on top of them.
    #[test]
    fn the_first_segment_is_sized_as_asked() {
        let host = Host::new();
        let first = |heap: Heap| {
            let sizes = segments(heap)[0];
            let growable = heap.flags() & HEAP_GROWABLE != 0;
            heap.destroy(&host);
            (sizes.1, sizes.2, growable)
        };
        // The process heap's shape: the image header's 1 MiB reserved, 4 KiB committed.
        let heap = create_sized(&host, HEAP_GROWABLE, 0x10_0000, 0x1000).unwrap();
        assert_eq!(first(heap), (0x10_0000, PAGE, true));
        let heap = create_sized(&host, 0, 0, 0).unwrap();
        assert_eq!(first(heap), (DEFAULT_RESERVE, PAGE, true), "neither size");
        let heap = create_sized(&host, 0, 0, 0x1000).unwrap();
        assert_eq!(first(heap), (0x1_0000, PAGE, true), "a commit size alone");
        let heap = create_sized(&host, HEAP_GROWABLE, 0x3_0000, 0).unwrap();
        assert_eq!(first(heap), (0x3_0000, PAGE, true), "a reservation alone");
        let heap = create_sized(&host, 0, 0x2000, 0x8000).unwrap();
        assert_eq!(
            first(heap),
            (0x2000, 0x2000, false),
            "a commit past the reservation"
        );
        // HeapCreate: msvcrt's heap, and a capped one.
        let heap = create(&host, 0, 0x1000, 0).unwrap();
        assert_eq!(first(heap), (0x1_0000, PAGE, true));
        let heap = create(&host, 0, 64 << 10, 128 << 10).unwrap();
        assert_eq!(first(heap), (128 << 10, 64 << 10, false));
        assert!(host.live.borrow().is_empty());
    }

    /// Blocks come back 8-aligned, sized exactly, zeroed when asked, and free for reuse.
    #[test]
    fn blocks_allocate_size_and_free() {
        let host = Host::new();
        let heap = create(&host, 0, 0, 0).unwrap();
        let a = heap.alloc(&host, 0, 100).unwrap();
        assert_eq!(a % 8, 0);
        assert_eq!(a, heap.handle() + AREA + HEADER_SIZE);
        assert_eq!(heap.size(&host, 0, a), Some(100));
        bytes(a, 100).fill(0x5A);
        let z = heap.alloc(&host, HEAP_ZERO_MEMORY, 64).unwrap();
        assert!(bytes(z, 64).iter().all(|&b| b == 0));
        assert!(heap.free(&host, 0, a));
        assert!(!heap.free(&host, 0, a), "a double free is refused");
        assert_eq!(heap.size(&host, 0, a), None);
        assert!(heap.validate(&host, 0, 0));
        assert!(heap.validate(&host, 0, z));
        assert!(!heap.validate(&host, 0, z + 8));
        heap.destroy(&host);
    }

    /// A growable heap commits its first segment as its blocks need, then adds segments of the
    /// default reservation; every call works across them, and destroy gives every one back.
    #[test]
    fn a_growable_heap_adds_segments() {
        let host = Host::new();
        let heap = create_sized(&host, HEAP_GROWABLE, 0x1_0000, 0x1000).unwrap();
        // 0x1000-byte blocks (0x1008 with their headers): fifteen fill the 64 KiB first segment,
        // the rest go on to further ones.
        let blocks: Vec<usize> = (0..600)
            .map(|i| {
                let block = heap.alloc(&host, 0, 0x1000).unwrap();
                bytes(block, 0x1000).fill(i as u8);
                block
            })
            .collect();
        let chain = segments(heap);
        assert_eq!(chain.len(), 4, "64 KiB, then three of 1 MiB");
        assert_eq!(
            chain[0],
            (heap.handle(), 0x1_0000, 0x1_0000),
            "the first, full"
        );
        assert!(chain[1..]
            .iter()
            .all(|&(_, reserve, _)| reserve == SEGMENT_RESERVE));
        let in_segment = |block: usize| {
            chain
                .iter()
                .position(|&(base, reserve, _)| block > base && block < base + reserve)
        };
        let first_count = (0x1_0000 - AREA) / (0x1000 + HEADER_SIZE);
        assert_eq!(in_segment(blocks[0]), Some(0));
        assert_eq!(in_segment(blocks[first_count - 1]), Some(0));
        assert_eq!(in_segment(blocks[first_count]), Some(1));
        assert_eq!(in_segment(blocks[599]), Some(3));
        for (i, &block) in blocks.iter().enumerate() {
            assert_eq!(heap.size(&host, 0, block), Some(0x1000));
            assert!(
                bytes(block, 0x1000).iter().all(|&b| b == i as u8),
                "block {i} intact"
            );
        }
        assert!(heap.validate(&host, 0, 0));
        assert!(heap.validate(&host, 0, blocks[400]));

        // Frees in every segment; a freed block in an earlier segment serves first.
        for &block in blocks.iter().skip(1).step_by(2) {
            assert!(heap.free(&host, 0, block));
        }
        assert!(
            !heap.free(&host, 0, blocks[401]),
            "a double free in a further segment"
        );
        assert_eq!(heap.size(&host, 0, blocks[401]), None);
        assert_eq!(heap.alloc(&host, 0, 0x1000), Some(blocks[1]));
        // A growth that does not fit in place moves, to wherever there is room.
        bytes(blocks[400], 0x1000).fill(0x77);
        let moved = heap
            .realloc(&host, HEAP_ZERO_MEMORY, blocks[400], 0x3000)
            .unwrap();
        assert_ne!(moved, blocks[400]);
        assert!(bytes(moved, 0x1000).iter().all(|&b| b == 0x77));
        assert!(bytes(moved + 0x1000, 0x2000).iter().all(|&b| b == 0));
        assert_eq!(
            heap.size(&host, 0, blocks[400]),
            None,
            "the old block is free"
        );
        // A shrink in a further segment stays in place.
        assert_eq!(heap.realloc(&host, 0, blocks[598], 0x10), Some(blocks[598]));
        assert_eq!(heap.size(&host, 0, blocks[598]), Some(0x10));
        assert!(heap.validate(&host, 0, 0));
        assert_eq!(
            segments(heap).len(),
            4,
            "the freed room served: no new segment"
        );

        let big = heap.alloc(&host, 0, 8 << 20).unwrap();
        assert_eq!(
            host.live.borrow().len(),
            5,
            "a big block is a reservation of its own"
        );
        assert_eq!(heap.size(&host, 0, big), Some(8 << 20));
        heap.destroy(&host);
        assert!(
            host.live.borrow().is_empty(),
            "destroy gives every segment and big block back"
        );
    }

    /// A growable heap serves a request past the threshold from a reservation of its own, which its
    /// free gives back; the largest request below it fits a further segment.
    #[test]
    fn big_blocks() {
        let host = Host::new();
        let heap = create(&host, 0, 0, 0).unwrap();
        let big = heap.alloc(&host, 0, 8 << 20).unwrap();
        assert_eq!(
            host.live.borrow().len(),
            2,
            "a big block is a reservation of its own"
        );
        assert_eq!(heap.size(&host, 0, big), Some(8 << 20));
        bytes(big, 8 << 20)[(8 << 20) - 1] = 1;
        let second = heap.alloc(&host, 0, BIG_THRESHOLD + 1).unwrap();
        assert!(heap.free(&host, 0, big));
        assert_eq!(
            heap.size(&host, 0, second),
            Some(BIG_THRESHOLD + 1),
            "the list survives an unlink"
        );
        assert!(heap.free(&host, 0, second));
        assert_eq!(host.live.borrow().len(), 1);
        let largest = heap.alloc(&host, 0, BIG_THRESHOLD).unwrap();
        assert_eq!(segments(heap).len(), 2);
        assert_eq!(heap.size(&host, 0, largest), Some(BIG_THRESHOLD));
        heap.destroy(&host);
        assert!(host.live.borrow().is_empty());
    }

    /// A capped heap is its one segment: 128 KiB serves seven 16 KiB blocks, then refuses (the
    /// memory fixture's count) without a further segment, and HeapValidate walks it clean.
    #[test]
    fn a_capped_heap_refuses_past_its_segment() {
        let host = Host::new();
        let heap = create(&host, 0, 0, 128 << 10).unwrap();
        let served = (0..16)
            .take_while(|_| heap.alloc(&host, 0, 16 << 10).is_some())
            .count();
        assert_eq!(served, 7);
        assert_eq!(
            heap.alloc(&host, 0, BIG_THRESHOLD + 1),
            None,
            "no big blocks without growth"
        );
        assert_eq!(segments(heap).len(), 1);
        assert_eq!(host.live.borrow().len(), 1, "nothing reserved past the cap");
        assert!(heap.validate(&host, 0, 0));
        heap.destroy(&host);
    }

    /// A commit the address space refuses fails the call (a segment that cannot commit is given
    /// back), and the next one that fits succeeds.
    #[test]
    fn a_refused_commit_fails_the_call() {
        let host = Host::new();
        let heap = create(&host, 0, 0, 0).unwrap();
        *host.commit_budget.borrow_mut() = 0;
        assert_eq!(heap.alloc(&host, 0, 0x2000), None);
        assert!(
            heap.alloc(&host, 0, 0x100).is_some(),
            "the committed page still serves"
        );
        assert_eq!(host.live.borrow().len(), 1);
        heap.destroy(&host);
    }

    /// A corrupt block header fails the allocation that walks over it, with room still committed:
    /// the segment grows only while the grow commits more, so the call returns instead of retrying
    /// forever (MEM-1), and no further segment hides the corruption.
    #[test]
    fn a_corrupt_header_fails_the_call() {
        let host = Host::new();
        let heap = create(&host, 0, 0, 0).unwrap();
        let a = heap.alloc(&host, 0, 0x20).unwrap();
        let _b = heap.alloc(&host, 0, 0x20).unwrap();
        // Overrun `a` into the next block's size word: a misaligned size, no block.
        bytes(a, 0x24)[0x20..0x24].copy_from_slice(&0x13u32.to_le_bytes());
        let committed = segments(heap)[0].2;
        assert_eq!(
            heap.alloc(&host, 0, 0x40),
            None,
            "the walk stops at the corrupt header"
        );
        assert!(
            segments(heap)[0].2 <= committed + 2 * PAGE,
            "no endless growth"
        );
        assert_eq!(segments(heap).len(), 1, "no further segment");
        assert!(!heap.validate(&host, 0, 0));
        heap.destroy(&host);
    }

    /// HeapReAlloc: in place when it fits (shrink, or growth into the slack), refused in place
    /// otherwise, moved with the contents and a zeroed extension, and across the big-block
    /// threshold and back.
    #[test]
    fn reallocation() {
        let host = Host::new();
        let heap = create(&host, 0, 0, 0).unwrap();
        let a = heap.alloc(&host, 0, 100).unwrap();
        let _neighbor = heap.alloc(&host, 0, 8).unwrap();
        bytes(a, 100).fill(7);
        assert_eq!(heap.realloc(&host, 0, a, 50), Some(a));
        assert_eq!(heap.size(&host, 0, a), Some(50));
        assert_eq!(
            heap.realloc(&host, HEAP_REALLOC_IN_PLACE_ONLY, a, 1000),
            None
        );
        let moved = heap.realloc(&host, HEAP_ZERO_MEMORY, a, 1000).unwrap();
        assert_ne!(moved, a);
        assert_eq!(bytes(moved, 50), &[7; 50]);
        assert!(bytes(moved + 50, 950).iter().all(|&b| b == 0));
        let big = heap.realloc(&host, 0, moved, 1 << 20).unwrap();
        assert_eq!(bytes(big, 50), &[7; 50]);
        assert_eq!(
            heap.realloc(&host, 0, big, 1 << 19),
            Some(big),
            "a big block shrinks in place"
        );
        let small = heap.realloc(&host, 0, big, 64);
        assert_eq!(
            small,
            Some(big),
            "and stays big when shrunk below the threshold"
        );
        heap.destroy(&host);
    }

    /// The process's list: created heaps are listed (up to the maximum), unknown handles name none,
    /// and a destroyed heap is unlisted with its pages given back.
    #[test]
    fn the_process_lists_its_heaps() {
        let host = Host::new();
        let mut slots = [0usize; HEAPS as usize];
        let mut list = HeapList {
            count: 0,
            maximum: HEAPS,
            heaps: slots.as_mut_ptr(),
        };
        let lock = free_lock();
        let process = Process {
            list: &mut list,
            lock: &lock,
        };
        let first = process.create(&host, 0, 0, 0).unwrap();
        assert_eq!(process.heap(first.handle()), Some(first));
        assert_eq!(process.heap(first.handle() + 8), None);
        assert_eq!(process.heap(0), None);
        let more: Vec<Heap> = (1..HEAPS)
            .map(|_| process.create(&host, 0, 0, 1 << 16).unwrap())
            .collect();
        assert!(
            process.create(&host, 0, 0, 1 << 16).is_none(),
            "the list is full"
        );
        assert_eq!(
            host.live.borrow().len(),
            HEAPS as usize,
            "a heap the list refused is given back"
        );
        assert!(process.destroy(&host, more[3].handle()));
        assert!(!process.destroy(&host, more[3].handle()));
        assert_eq!(process.heap(more[3].handle()), None);
        assert_eq!(
            process.heap(more[14].handle()),
            Some(more[14]),
            "the last moved into the freed slot"
        );
        assert_eq!(unsafe { &*process.list }.count, HEAPS - 1);
    }
}
