//! The Win32 heaps, in user mode as Windows 2000's ntdll runs them (the RtlCreateHeap family;
//! kernel32's Heap functions forward here or call in, and Local/Global memory lives on the process
//! heap): every byte of a heap, its bookkeeping included, is the program's own memory, so the
//! kernel never touches it, and a heap the program corrupts fails or faults the program alone.
//!
//! A heap is a segment — a reservation whose base is the heap's handle, committed on demand from
//! its start — and, for a growable heap, its big blocks: a request past [`BIG_THRESHOLD`] gets a
//! reservation of its own (NT's virtual-alloc blocks), linked from the heap's header. A heap
//! created with a maximum size is that one segment and nothing more: it refuses what does not fit.
//!
//! The segment starts with the heap's header ([`Header`]): NT's signature, flags and force flags at
//! their offsets (programs read the process heap's flags), the segment's reservation, committed
//! prefix and bump edge, the big blocks' list, and the heap's lock — a critical section, unless the
//! heap or the call says HEAP_NO_SERIALIZE. The blocks follow ([`AREA`] bytes in), managed by the
//! pure allocator core ([`crate::heapcore`]).
//!
//! The process's heaps are listed in its PEB ([`HeapList`]: NumberOfHeaps, MaximumNumberOfHeaps,
//! ProcessHeaps), under a lock of the process's own; a handle that is not listed is no heap, and
//! the calls refuse it without touching it.

use core::mem::size_of;
use core::ptr::{addr_of, addr_of_mut};

use crate::critsec::{CriticalSection, System};
use crate::heapcore::{
    alloc_block,
    block_size,
    free_block,
    resize_in_place,
    round_up,
    validate_area,
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
/// A growable heap's segment reservation.
pub const GROWABLE_RESERVE: usize = 0x200_0000;
/// The largest request a growable heap serves from its segment; larger ones get a reservation of
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

/// The heap's header, at its handle (on the target: NT's signature at +0x08, flags at +0x0C, force
/// flags at +0x10).
#[repr(C)]
struct Header {
    /// NT's leading HEAP_ENTRY: unused here, zero.
    entry: [u32; 2],
    signature: u32,
    /// The kept creation flags, and HEAP_GROWABLE for a heap without a maximum.
    flags: u32,
    /// The flags forced on every call (a debugger's): none.
    force_flags: u32,
    /// The segment's reservation, and its committed prefix (both from the base).
    reserve: usize,
    committed: usize,
    /// The block area's bump edge (from the area's start).
    top: usize,
    /// The first big block's reservation (zero: none); each links the next.
    big: usize,
    /// The heap's lock (unless the heap or the call is HEAP_NO_SERIALIZE).
    lock: CriticalSection,
}

/// The bytes of the segment before its first block: the header, 8-aligned.
pub const AREA: usize = (size_of::<Header>() + 7) & !7;

/// A big block's header, at its reservation's base: the next big block, the size asked for, and the
/// reservation's size. The user bytes follow it.
#[repr(C)]
struct Big {
    next: usize,
    size: usize,
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
    assert!(BIG_HEADER == 0x10);
};

/// A live heap, by its handle (its segment's base).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Heap(usize);

/// Create a heap: a segment of `maximum` bytes (rounded to pages) — a growable heap's fixed
/// reservation when zero — with `initial` bytes committed. None when the address space has no room.
pub fn create(
    system: &(impl System + Vm),
    flags: u32,
    initial: usize,
    maximum: usize,
) -> Option<Heap> {
    let growable = maximum == 0;
    let reserve = if growable {
        GROWABLE_RESERVE
    } else {
        maximum
            .max(initial)
            .max(PAGE)
            .checked_next_multiple_of(PAGE)?
    };
    let base = system.reserve(reserve)?;
    let commit = initial
        .max(AREA)
        .checked_next_multiple_of(PAGE)
        .unwrap_or(reserve)
        .min(reserve);
    if !system.commit(base, commit) {
        system.release(base);
        return None;
    }
    let header = base as *mut Header;
    // SAFETY: the reservation's first page is committed, zeroed, read-write and ours alone yet; a
    // zeroed critical section is a valid one for its initialization to write.
    unsafe {
        addr_of_mut!((*header).signature).write(SIGNATURE);
        addr_of_mut!((*header).flags)
            .write(flags & KEPT_FLAGS | if growable { HEAP_GROWABLE } else { 0 });
        addr_of_mut!((*header).reserve).write(reserve);
        addr_of_mut!((*header).committed).write(commit);
        // Spin count 0 and no preallocated event: the initialization cannot fail.
        let _ = (*header).lock.initialize(system, 0);
    }
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

    fn header(self) -> *mut Header {
        self.0 as *mut Header
    }

    /// The heap's flags (its kept creation flags, HEAP_GROWABLE for a growable one).
    pub fn flags(self) -> u32 {
        // SAFETY: a live heap's header.
        unsafe { (*self.header()).flags }
    }

    fn growable(self) -> bool {
        self.flags() & HEAP_GROWABLE != 0
    }

    fn committed(self) -> usize {
        // SAFETY: a live heap's header.
        unsafe { (*self.header()).committed }
    }

    fn top(self) -> usize {
        // SAFETY: a live heap's header.
        unsafe { (*self.header()).top }
    }

    /// The committed block area.
    fn area(self) -> &'static mut [u8] {
        // SAFETY: the segment's committed prefix is read-write memory of this process, the area
        // lies inside it past the header, and the heap's lock (or the caller's HEAP_NO_SERIALIZE
        // promise) keeps it ours for the call.
        unsafe {
            core::slice::from_raw_parts_mut((self.0 + AREA) as *mut u8, self.committed() - AREA)
        }
    }

    /// Run `body` holding the heap's lock, unless the heap or the call is HEAP_NO_SERIALIZE.
    fn locked<R>(self, system: &impl System, flags: u32, body: impl FnOnce() -> R) -> R {
        let serialize = (flags | self.flags()) & HEAP_NO_SERIALIZE == 0;
        // SAFETY: a live heap's lock, used in place through its atomics.
        let lock = unsafe { &*addr_of!((*self.header()).lock) };
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
        // SAFETY: a live heap's lock, used in place through its atomics.
        let lock = unsafe { &*addr_of!((*self.header()).lock) };
        if self.flags() & HEAP_NO_SERIALIZE == 0 {
            lock.enter(system);
        }
    }

    /// RtlUnlockHeap's work: the lock [`Heap::lock`] took, released.
    pub fn unlock(self, system: &impl System) {
        // SAFETY: as above.
        let lock = unsafe { &*addr_of!((*self.header()).lock) };
        if self.flags() & HEAP_NO_SERIALIZE == 0 {
            lock.leave(system);
        }
    }

    /// Commit the segment so the area covers `bytes`; refused past the reservation.
    fn grow(self, system: &impl Vm, bytes: usize) -> bool {
        let Some(end) = bytes
            .checked_add(AREA)
            .and_then(|end| end.checked_next_multiple_of(PAGE))
        else {
            return false;
        };
        let header = self.header();
        // SAFETY: a live heap's header, under its lock.
        let (committed, reserve) = unsafe { ((*header).committed, (*header).reserve) };
        if end <= committed {
            return true;
        }
        if end > reserve || !system.commit(self.0 + committed, end - committed) {
            return false;
        }
        // SAFETY: as above.
        unsafe { (*header).committed = end };
        true
    }

    /// A block from the segment, committing more of it as the bump path needs.
    fn segment_alloc(self, system: &impl Vm, request: usize, zero: bool) -> Option<usize> {
        loop {
            let mut top = self.top();
            if let Some(user) = alloc_block(self.area(), &mut top, request, zero) {
                // SAFETY: a live heap's header, under its lock.
                unsafe { (*self.header()).top = top };
                return Some(self.0 + AREA + user);
            }
            // Commit a page beyond the need (so small streams do not commit per allocation); past
            // the reservation, exactly the need.
            let need = round_up(request)?.checked_add(top + HEADER_SIZE)?;
            let committed = self.committed();
            if !self.grow(system, need + PAGE) && !self.grow(system, need) {
                return None;
            }
            // Retry only when the grow committed more: a walk that failed with the room already
            // there failed on a corrupt header, and committing cannot mend it (MEM-1).
            if self.committed() == committed {
                return None;
            }
        }
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
        let big = base as *mut Big;
        // SAFETY: the fresh reservation's committed first page, and the heap's header under its
        // lock.
        unsafe {
            big.write(Big {
                next: (*self.header()).big,
                size: request,
                reserved,
                _pad: 0,
            });
            (*self.header()).big = base;
        }
        Some(base + BIG_HEADER)
    }

    /// The big block whose user bytes start at `pointer`: the link that names it, and its header.
    fn big_at(self, pointer: usize) -> Option<(*mut usize, *mut Big)> {
        // SAFETY: a live heap's header and its big blocks' headers (committed reservations),
        // under the heap's lock.
        unsafe {
            let mut link = addr_of_mut!((*self.header()).big);
            while *link != 0 {
                let big = *link as *mut Big;
                if (*link).wrapping_add(BIG_HEADER) == pointer {
                    return Some((link, big));
                }
                link = addr_of_mut!((*big).next);
            }
        }
        None
    }

    /// The segment offset (from the area's start) of the block at `pointer`.
    fn user_offset(self, pointer: usize) -> Option<usize> {
        let start = self.0 + AREA;
        (pointer >= start && pointer < self.0 + self.committed()).then(|| pointer - start)
    }

    fn alloc_inner(self, system: &impl Vm, request: usize, zero: bool) -> Option<usize> {
        if self.growable() && request > BIG_THRESHOLD {
            return self.big_alloc(system, request);
        }
        self.segment_alloc(system, request, zero)
    }

    fn size_inner(self, pointer: usize) -> Option<usize> {
        if let Some((_, big)) = self.big_at(pointer) {
            // SAFETY: the big block's header.
            return Some(unsafe { (*big).size });
        }
        block_size(self.area(), self.top(), self.user_offset(pointer)?)
    }

    fn free_inner(self, system: &impl Vm, pointer: usize) -> bool {
        if let Some((link, big)) = self.big_at(pointer) {
            // SAFETY: the link and the header it names, under the heap's lock.
            unsafe {
                let base = *link;
                *link = (*big).next;
                system.release(base);
            }
            return true;
        }
        match self.user_offset(pointer) {
            Some(user) => free_block(self.area(), self.top(), user),
            None => false,
        }
    }

    /// Resize in place: a segment block within its capacity, a big block within its pages.
    fn resize_inner(self, pointer: usize, request: usize, zero: bool) -> bool {
        if let Some((_, big)) = self.big_at(pointer) {
            // SAFETY: the big block's header and user bytes, committed whole.
            unsafe {
                if request > (*big).reserved - BIG_HEADER {
                    return false;
                }
                let old = (*big).size;
                if zero && request > old {
                    core::ptr::write_bytes((pointer + old) as *mut u8, 0, request - old);
                }
                (*big).size = request;
            }
            return true;
        }
        match self.user_offset(pointer) {
            Some(user) => resize_in_place(self.area(), self.top(), user, request, zero),
            None => false,
        }
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
            let kept = old.min(request);
            // SAFETY: two distinct live blocks of this heap, each at least `kept` bytes long.
            unsafe {
                core::ptr::copy_nonoverlapping(pointer as *const u8, new as *mut u8, kept);
                if zero && request > kept {
                    core::ptr::write_bytes((new + kept) as *mut u8, 0, request - kept);
                }
            }
            self.free_inner(system, pointer);
            Some(new)
        })
    }

    /// HeapValidate's work: the whole segment's headers (a null pointer), or one block.
    pub fn validate(self, system: &impl System, flags: u32, pointer: usize) -> bool {
        self.locked(system, flags, || {
            if pointer != 0 {
                return self.size_inner(pointer).is_some();
            }
            validate_area(self.area(), self.top())
        })
    }

    /// HeapDestroy's work: every page given back — the big blocks, then the segment.
    pub fn destroy(self, system: &(impl System + Vm)) {
        // SAFETY: a live heap's header and its big blocks' headers; nothing else uses the heap.
        unsafe {
            let mut next = (*self.header()).big;
            while next != 0 {
                let big = next as *mut Big;
                next = (*big).next;
                system.release(big as usize);
            }
            (*self.header()).lock.delete(system);
        }
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
        let heap = create(system, flags, initial, maximum)?;
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

    fn bytes(pointer: usize, len: usize) -> &'static mut [u8] {
        // SAFETY: a live block of a test heap, at least `len` bytes.
        unsafe { core::slice::from_raw_parts_mut(pointer as *mut u8, len) }
    }

    /// The header's fields read as created; a growable heap commits its first page.
    #[test]
    fn a_heap_starts_with_its_header() {
        let host = Host::new();
        let heap = create(&host, HEAP_NO_SERIALIZE | 0x100, 0, 0).unwrap();
        // SAFETY: the live heap's header.
        let header = unsafe { &*heap.header() };
        assert_eq!(header.signature, SIGNATURE);
        assert_eq!(
            heap.flags(),
            HEAP_NO_SERIALIZE | HEAP_GROWABLE,
            "unknown options are not kept"
        );
        assert_eq!(
            (header.reserve, header.committed, header.top, header.big),
            (GROWABLE_RESERVE, PAGE, 0, 0)
        );
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

    /// A growable heap commits as its blocks need, and serves a request past the threshold from a
    /// reservation of its own, which its free gives back.
    #[test]
    fn growth_and_big_blocks() {
        let host = Host::new();
        let heap = create(&host, 0, 0, 0).unwrap();
        let blocks: Vec<usize> = (0..64)
            .map(|_| heap.alloc(&host, 0, 0x1000).unwrap())
            .collect();
        assert!(
            heap.committed() > 64 * 0x1000,
            "the segment committed on demand"
        );
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
        for block in blocks {
            assert!(heap.free(&host, 0, block));
        }
        heap.destroy(&host);
    }

    /// A capped heap is its one segment: 128 KiB serves seven 16 KiB blocks, then refuses (the
    /// memory fixture's count), and HeapValidate walks it clean.
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
        assert!(heap.validate(&host, 0, 0));
        heap.destroy(&host);
    }

    /// A commit the address space refuses fails the call, and the next one that fits succeeds.
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
        heap.destroy(&host);
    }

    /// A corrupt block header fails the allocation that walks over it, with room still committed:
    /// the segment grows only while the grow commits more, so the call returns instead of retrying
    /// forever (MEM-1).
    #[test]
    fn a_corrupt_header_fails_the_call() {
        let host = Host::new();
        let heap = create(&host, 0, 0, 0).unwrap();
        let a = heap.alloc(&host, 0, 0x20).unwrap();
        let _b = heap.alloc(&host, 0, 0x20).unwrap();
        // Overrun `a` into the next block's size word: a misaligned size, no block.
        bytes(a, 0x24)[0x20..0x24].copy_from_slice(&0x13u32.to_le_bytes());
        let committed = heap.committed();
        assert_eq!(
            heap.alloc(&host, 0, 0x40),
            None,
            "the walk stops at the corrupt header"
        );
        assert!(
            heap.committed() <= committed + 2 * PAGE,
            "no endless growth"
        );
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
