//! Slot pools: the one shape for the kernel's tables of records named by an index, an id or a
//! handle.
//!
//! - [`Slots`] allocates and frees slots, each with a uniqueness count, and finds a live slot by
//!   its id or handle, refusing a stale or forged one.
//! - [`SideTable`] holds records by index only, allocating none of its own: the same index as
//!   another pool's.
//!
//! Storage is chunks of whole pages ([`Pages`]: the nonpaged pool on target), found through a
//! chunk directory ([`ChunkDir`]): [`Paged`], a tree of pages that deepens as chunks are added, or
//! [`Inline`], a fixed array. A chunk is never moved and never given back while its pool lives
//! (except by [`Slots::reset`]), so a record's address is stable and `&'static T` into a pool in a
//! static stays memory-safe; a freed slot's record is the next object's, so it stays logically
//! safe only behind a counted reference or an id its lookup checks.
//!
//! How an id or handle carries a slot is the pool's [`Codec`], which also sets the index ceiling
//! (a representation limit: memory runs out first), the reuse order and the uniqueness range.
//! Every codec shares the uniqueness rule: a fresh slot's count is 1; freeing moves it on, from
//! the codec's highest back to 1, so it is never 0 nor a wildcard.
//!
//! A pool takes no lock: its owner's lock gives the `&mut self` every change needs. Only chunk and
//! directory-page publication is atomic (Release stores, Acquire loads), so resolving an address
//! takes no lock. A reader without the owner's lock cannot borrow the pool while the owner holds
//! it mutably, so a pool resolved that way is built on a directory kept apart from it
//! ([`Slots::on`] with a `&'static Paged`), which the reader resolves through alone
//! ([`Slots::address_in`], [`SideTable::address_in`], [`SideTable::index_at_in`]).

// Only the process records (a `SideTable`), win32k's menus, menu items, accelerator tables and
// sent messages, and ob's non-dispatcher kinds, image segments and names (`Slots`) have moved onto
// these types; the rest waits for its consumers.
#![allow(dead_code)]

use core::cell::Cell;
use core::marker::PhantomData;
use core::ptr::{addr_of_mut, null_mut, NonNull};
use core::sync::atomic::{AtomicPtr, Ordering};

/// The size of a page, the unit chunks are made of.
pub const PAGE: usize = 4096;

/// Where chunks come from: the nonpaged pool on target ([`NonpagedPages`]), the host allocator in
/// tests.
pub trait Pages {
    /// `pages` whole zeroed pages, page-aligned and mapped in every address space; none when
    /// exhausted.
    fn take(&self, pages: usize) -> Option<NonNull<u8>>;

    /// Give back what [`Pages::take`] handed out.
    ///
    /// # Safety
    ///
    /// `at` and `pages` are one earlier `take`'s, not given back since, and nothing refers to
    /// those pages any more.
    unsafe fn give(&self, at: NonNull<u8>, pages: usize);
}

/// A record a pool holds: written in place when its chunk is made, renewed by its owner when its
/// slot is allocated, never dropped (its owner tears down what it holds before the free).
///
/// # Safety
///
/// [`Record::write_fresh`] leaves a whole, valid `Self` at `at`.
pub unsafe trait Record {
    /// Write a fresh record for slot `index` at `at`, field by field when it is large (a record
    /// passed by value would cross the stack).
    ///
    /// # Safety
    ///
    /// `at` is valid for writes and aligned; its zeroed contents are overwritten, not dropped.
    unsafe fn write_fresh(at: *mut Self, index: u32);
}

/// Which freed slot the next allocation of a lane takes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reuse {
    /// The one freed last: Windows 2000's order for NT, USER and GDI handles and client ids.
    Lifo,
    /// The one freed first: for kernel-internal ids, so a stale id aliases a new object only
    /// after every free slot has gone round its uniqueness range.
    Fifo,
}

/// The uniqueness an id or handle asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Match {
    /// Exactly the slot's count.
    Exact(u16),
    /// Whatever the slot holds now (a wildcard, or a format that carries no uniqueness).
    Any,
}

/// How ids or handles carry a slot's index and its uniqueness.
///
/// A lane is a residue of the index modulo [`Codec::LANES`]: each has its own free list and its
/// own cursor over the slots never used.
pub trait Codec {
    type Id: Copy + Eq;
    /// The lanes (USER: 2, even for windows and odd for the rest; every other codec 1).
    const LANES: usize;
    /// Indices below this are never handed out (handle 0; the client ids 0, 4 and 8).
    const RESERVED_LOW: u32;
    /// The highest index the encoding can carry: a representation limit ([`Full::Limit`]).
    const MAX_INDEX: u32;
    /// The highest uniqueness count; the one after it is 1. Never 0, never a wildcard.
    const MAX_UNIQ: u16;
    const REUSE: Reuse;
    fn encode(index: u32, uniq: u16) -> Self::Id;
    /// The index and uniqueness `id` names; none for a value the format cannot carry.
    fn decode(id: Self::Id) -> Option<(u32, Match)>;
}

/// Why a pool handed out no slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Full {
    /// The next slot lies in a chunk not made yet ([`Slots::allocate`]), or its making found no
    /// pages ([`Slots::grow`]): the pool is unchanged. Out of memory, to the owner.
    NoChunk,
    /// The next slot lies past the codec's [`Codec::MAX_INDEX`] or the directory's capacity.
    Limit,
}

/// Why a chunk was not published.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unpublished {
    /// Another chunk was published there first; the caller gives its own back.
    Raced,
    /// The directory could not make a page of its own.
    NoPage,
    /// The chunk number lies past the directory's capacity.
    Capacity,
}

/// Where a pool finds its chunk `i`.
///
/// # Safety
///
/// [`ChunkDir::chunk`] answers only what [`ChunkDir::publish`] published (Acquire against its
/// Release), until [`ChunkDir::release`]; the directory's own pages come only from the `pages`
/// [`ChunkDir::publish`] is handed.
pub unsafe trait ChunkDir {
    /// How many chunks it can name.
    const CAPACITY: u32;

    /// Chunk `chunk`'s address, without a lock; none if unmade.
    fn chunk(&self, chunk: u32) -> Option<NonNull<u8>>;

    /// Publish chunk `chunk`, fully written, at `at` (Release), with a compare-and-swap against
    /// none, so racing publishers make one chunk. The directory pages it needs come from `pages`,
    /// one at a time, and those of a lost race go back to it.
    fn publish(&self, chunk: u32, at: NonNull<u8>, pages: &impl Pages) -> Result<(), Unpublished>;

    /// The directory pages publishing chunk `chunk` would take now.
    fn missing_pages(&self, chunk: u32) -> usize;

    /// The directory pages publishing chunk `chunk` takes when the chunks published are exactly
    /// `0..chunk`: a [`Slots`]' next chunk, known without the directory.
    fn next_pages(chunk: u32) -> usize;

    /// Give back every published chunk (each `chunk_pages` long) and the directory's own pages,
    /// leaving it empty.
    ///
    /// # Safety
    ///
    /// Nothing refers to the chunks any more, nothing resolves through the directory meanwhile,
    /// and every page was taken from `pages`.
    unsafe fn release(&self, chunk_pages: usize, pages: &impl Pages);
}

/// A directory that starts empty in place: one a pool can hold itself.
pub trait EmptyDir: ChunkDir {
    /// A directory naming no chunk, holding no page.
    #[allow(clippy::declare_interior_mutable_const)]
    const EMPTY: Self;
}

// SAFETY: every answer is the referenced directory's.
unsafe impl<D: ChunkDir> ChunkDir for &D {
    const CAPACITY: u32 = D::CAPACITY;

    fn chunk(&self, chunk: u32) -> Option<NonNull<u8>> {
        (**self).chunk(chunk)
    }

    fn publish(&self, chunk: u32, at: NonNull<u8>, pages: &impl Pages) -> Result<(), Unpublished> {
        (**self).publish(chunk, at, pages)
    }

    fn missing_pages(&self, chunk: u32) -> usize {
        (**self).missing_pages(chunk)
    }

    fn next_pages(chunk: u32) -> usize {
        D::next_pages(chunk)
    }

    unsafe fn release(&self, chunk_pages: usize, pages: &impl Pages) {
        // SAFETY: the caller's contract.
        unsafe { (**self).release(chunk_pages, pages) }
    }
}

/// A fixed directory of `N` chunk pointers: for a table whose Windows ceiling is small and fixed
/// (the GDI table), where `N × PER` is that ceiling. Its static footprint is `4 × N` bytes.
pub struct Inline<const N: usize>([AtomicPtr<u8>; N]);

// SAFETY: `chunk` loads with Acquire what `publish` stored with Release; `release` empties it.
unsafe impl<const N: usize> ChunkDir for Inline<N> {
    const CAPACITY: u32 = N as u32;

    fn chunk(&self, chunk: u32) -> Option<NonNull<u8>> {
        NonNull::new(self.0.get(chunk as usize)?.load(Ordering::Acquire))
    }

    fn publish(&self, chunk: u32, at: NonNull<u8>, _: &impl Pages) -> Result<(), Unpublished> {
        let entry = self.0.get(chunk as usize).ok_or(Unpublished::Capacity)?;
        entry
            .compare_exchange(null_mut(), at.as_ptr(), Ordering::AcqRel, Ordering::Acquire)
            .map(|_| ())
            .map_err(|_| Unpublished::Raced)
    }

    fn missing_pages(&self, _: u32) -> usize {
        0
    }

    fn next_pages(_: u32) -> usize {
        0
    }

    unsafe fn release(&self, chunk_pages: usize, pages: &impl Pages) {
        for entry in &self.0 {
            if let Some(at) = NonNull::new(entry.swap(null_mut(), Ordering::AcqRel)) {
                // SAFETY: the caller's contract: published from `pages`, referred to no more.
                unsafe { pages.give(at, chunk_pages) };
            }
        }
    }
}

impl<const N: usize> EmptyDir for Inline<N> {
    #[allow(clippy::declare_interior_mutable_const)]
    const EMPTY: Self = Inline([const { AtomicPtr::new(null_mut()) }; N]);
}

/// The entries of a full directory page: 1,024 on the target, 512 on a 64-bit host.
pub const FANOUT: usize = PAGE / core::mem::size_of::<*mut u8>();

/// The growable directory: a tree of pages of `F` entries ([`FANOUT`], fewer only in tests).
///
/// The root is chunk 0 itself at height 0 (so a one-chunk pool holds no directory page), a page
/// of chunk pointers at height 1, and above that a page of pointers to pages one lower. A chunk
/// past the tree's span deepens it: a new root takes the old one as its entry 0. It names every
/// u32 chunk (at height 4 for 1,024 entries), so it never sets a pool's limit, and its static
/// footprint is one pointer.
///
/// New pages are written while only their maker sees them, then join the tree with one
/// compare-and-swap (Release) at the topmost, so the tree is published bottom up: a reader's
/// Acquire loads, level by level, find whole pages and whole chunks. Under the owner's lock the
/// swap never fails; between [`SideTable::ensure`]'s racers the loser gives its pages back.
pub struct Paged<const F: usize = FANOUT> {
    /// The root's address with its height in the low bits (a page's address has 12 clear); null
    /// when empty.
    root: AtomicPtr<u8>,
}

/// The low bits of [`Paged`]'s root word that hold the height.
const HEIGHT_BITS: usize = PAGE - 1;

impl<const F: usize> Paged<F> {
    /// The entries per page as a u64. At least 4, so the height stays within 16 and a
    /// publication within [`RESERVE`] pages.
    const FAN: u64 = {
        assert!(F >= 4 && F * core::mem::size_of::<*mut u8>() <= PAGE);
        F as u64
    };

    /// The chunks a tree of `height` spans.
    const fn span(height: u32) -> u64 {
        Self::FAN.pow(height)
    }

    /// The lowest height whose tree spans chunk `chunk`.
    const fn height(chunk: u32) -> u32 {
        let mut height = 0;
        while chunk as u64 >= Self::span(height) {
            height += 1;
        }
        height
    }

    /// Chunk `chunk`'s entry in its page at `level` (1: the page of chunk pointers).
    const fn digit(chunk: u32, level: u32) -> usize {
        ((chunk as u64 / Self::span(level - 1)) % Self::FAN) as usize
    }

    /// Entry `index` of directory page `page`.
    ///
    /// # Safety
    ///
    /// `page` is a directory page, taken and not given back while the reference lives.
    unsafe fn entry<'a>(page: *mut u8, index: usize) -> &'a AtomicPtr<u8> {
        debug_assert!(index < F);
        // SAFETY: the caller's contract; a page holds F pointers, zeroed (null) when taken.
        unsafe { &*page.cast::<AtomicPtr<u8>>().add(index) }
    }

    fn split(root: *mut u8) -> (*mut u8, u32) {
        let height = root.addr() & HEIGHT_BITS;
        (root.wrapping_sub(height), height as u32)
    }

    fn join(top: *mut u8, height: u32) -> *mut u8 {
        top.wrapping_add(height as usize)
    }

    /// The pages that carry chunk `chunk` at `at` down from a page at `height`, made from
    /// `pages` and unpublished: the top's address (`at` itself at height 0).
    fn build(
        chunk: u32,
        height: u32,
        at: NonNull<u8>,
        pages: &impl Pages,
    ) -> Result<*mut u8, Unpublished> {
        let mut below = at.as_ptr();
        for level in 1..=height {
            let Some(page) = pages.take(1) else {
                // SAFETY: built just now from `pages`, never published.
                unsafe { Self::unbuild(chunk, level - 1, below, pages) };
                return Err(Unpublished::NoPage);
            };
            // SAFETY: a page just taken, ours alone.
            unsafe { Self::entry(page.as_ptr(), Self::digit(chunk, level)) }
                .store(below, Ordering::Relaxed);
            below = page.as_ptr();
        }
        Ok(below)
    }

    /// Give back the pages of an unpublished [`Paged::build`], each emptied; the chunk stays.
    ///
    /// # Safety
    ///
    /// `top` is that build's, for `chunk` and `height`, never published.
    unsafe fn unbuild(chunk: u32, height: u32, top: *mut u8, pages: &impl Pages) {
        let mut page = top;
        for level in (1..=height).rev() {
            // SAFETY: a page of the build, ours alone.
            let below = unsafe { Self::entry(page, Self::digit(chunk, level)) }
                .swap(null_mut(), Ordering::Relaxed);
            // SAFETY: taken from `pages` by the build, referred to by nothing now.
            unsafe { pages.give(NonNull::new_unchecked(page), 1) };
            page = below;
        }
    }

    /// Give back the tree at `at` of `height`: its chunks and its pages.
    ///
    /// # Safety
    ///
    /// As [`ChunkDir::release`]'s; the tree is unpublished.
    unsafe fn give_tree(at: *mut u8, height: u32, chunk_pages: usize, pages: &impl Pages) {
        if height > 0 {
            for index in 0..F {
                // SAFETY: a page of the tree, ours alone now.
                let below = unsafe { Self::entry(at, index) }.load(Ordering::Relaxed);
                if !below.is_null() {
                    // SAFETY: the caller's contract, one level down.
                    unsafe { Self::give_tree(below, height - 1, chunk_pages, pages) };
                }
            }
        }
        let length = if height == 0 { chunk_pages } else { 1 };
        // SAFETY: the caller's contract: taken from `pages`, referred to no more.
        unsafe { pages.give(NonNull::new_unchecked(at), length) };
    }
}

// SAFETY: every page and chunk joins the tree by a Release compare-and-swap after it is written,
// and every resolution loads each level with Acquire; pages are given back only by `release`
// (published ones) or by their maker before publication.
unsafe impl<const F: usize> ChunkDir for Paged<F> {
    /// Every u32 chunk but the last, whose number is the capacity check's bound.
    const CAPACITY: u32 = u32::MAX;

    fn chunk(&self, chunk: u32) -> Option<NonNull<u8>> {
        let (mut at, height) = Self::split(self.root.load(Ordering::Acquire));
        if at.is_null() || chunk as u64 >= Self::span(height) {
            return None;
        }
        for level in (1..=height).rev() {
            // SAFETY: a published page, never given back before `release`.
            at = unsafe { Self::entry(at, Self::digit(chunk, level)) }.load(Ordering::Acquire);
            if at.is_null() {
                return None;
            }
        }
        NonNull::new(at)
    }

    fn publish(&self, chunk: u32, at: NonNull<u8>, pages: &impl Pages) -> Result<(), Unpublished> {
        if chunk == Self::CAPACITY {
            return Err(Unpublished::Capacity);
        }
        let wanted = Self::height(chunk);
        loop {
            let root = self.root.load(Ordering::Acquire);
            let (top, height) = Self::split(root);
            if top.is_null() {
                let made = Self::build(chunk, wanted, at, pages)?;
                let joined = Self::join(made, wanted);
                let swapped =
                    self.root
                        .compare_exchange(root, joined, Ordering::AcqRel, Ordering::Acquire);
                if swapped.is_ok() {
                    return Ok(());
                }
                // SAFETY: the build lost the race, so it is unpublished.
                unsafe { Self::unbuild(chunk, wanted, made, pages) };
                continue;
            }
            if height < wanted {
                // One level deeper: a new root whose entry 0 is the old one.
                let page = pages.take(1).ok_or(Unpublished::NoPage)?;
                // SAFETY: a page just taken, ours alone.
                let first = unsafe { Self::entry(page.as_ptr(), 0) };
                first.store(top, Ordering::Relaxed);
                let deeper = Self::join(page.as_ptr(), height + 1);
                let swapped =
                    self.root
                        .compare_exchange(root, deeper, Ordering::AcqRel, Ordering::Acquire);
                if swapped.is_err() {
                    first.store(null_mut(), Ordering::Relaxed);
                    // SAFETY: taken above, never published.
                    unsafe { pages.give(page, 1) };
                }
                continue;
            }
            if height == 0 {
                // The root is chunk 0, the one asked for.
                return Err(Unpublished::Raced);
            }
            let (mut page, mut level) = (top, height);
            loop {
                // SAFETY: a published page, never given back before `release`.
                let entry = unsafe { Self::entry(page, Self::digit(chunk, level)) };
                let below = entry.load(Ordering::Acquire);
                if !below.is_null() {
                    if level == 1 {
                        return Err(Unpublished::Raced);
                    }
                    (page, level) = (below, level - 1);
                    continue;
                }
                let made = Self::build(chunk, level - 1, at, pages)?;
                let swapped =
                    entry.compare_exchange(null_mut(), made, Ordering::AcqRel, Ordering::Acquire);
                if swapped.is_ok() {
                    return Ok(());
                }
                // SAFETY: the build lost the race, so it is unpublished; the entry is read again.
                unsafe { Self::unbuild(chunk, level - 1, made, pages) };
            }
        }
    }

    fn missing_pages(&self, chunk: u32) -> usize {
        let wanted = Self::height(chunk);
        let (top, height) = Self::split(self.root.load(Ordering::Acquire));
        if top.is_null() {
            return wanted as usize;
        }
        if height < wanted {
            // The new roots, and the chunk's own page at every level it lies past the old tree.
            let own = (1..wanted).filter(|&level| chunk as u64 >= Self::span(level));
            return (wanted - height) as usize + own.count();
        }
        let (mut page, mut level) = (top, height);
        while level > 1 {
            // SAFETY: a published page, never given back before `release`.
            let below = unsafe { Self::entry(page, Self::digit(chunk, level)) };
            let below = below.load(Ordering::Acquire);
            if below.is_null() {
                return level as usize - 1;
            }
            (page, level) = (below, level - 1);
        }
        0
    }

    fn next_pages(chunk: u32) -> usize {
        if chunk == 0 {
            return 0;
        }
        let (wanted, had) = (Self::height(chunk), Self::height(chunk - 1));
        // A new root when the tree deepens; a new page at every level the chunk starts.
        let starts = (1..wanted).filter(|&level| (chunk as u64).is_multiple_of(Self::span(level)));
        (wanted - had) as usize + starts.count()
    }

    unsafe fn release(&self, chunk_pages: usize, pages: &impl Pages) {
        let (top, height) = Self::split(self.root.swap(null_mut(), Ordering::AcqRel));
        if !top.is_null() {
            // SAFETY: the caller's contract; the tree is unpublished now.
            unsafe { Self::give_tree(top, height, chunk_pages, pages) };
        }
    }
}

impl<const F: usize> EmptyDir for Paged<F> {
    #[allow(clippy::declare_interior_mutable_const)]
    const EMPTY: Self = {
        let _ = Self::FAN;
        Paged {
            root: AtomicPtr::new(null_mut()),
        }
    };
}

/// The most directory pages one publication takes: at most 16 heights at 4 entries a page, a new
/// root for each and the chunk's own page below each.
const RESERVE: usize = 32;

/// Directory pages taken ahead and handed out one at a time, so a publication draws on these
/// alone: where taking pages is not legal (inside a `LevelCell<High>`), and so a publication that
/// would fail for want of pages fails before it changes anything.
struct Reserve {
    pages: [Cell<*mut u8>; RESERVE],
    count: Cell<usize>,
}

impl Reserve {
    const fn new() -> Self {
        Reserve {
            pages: [const { Cell::new(null_mut()) }; RESERVE],
            count: Cell::new(0),
        }
    }

    /// `count` pages from `pages`; none when it has too few, any taken given back.
    fn take_from(count: usize, pages: &impl Pages) -> Option<Self> {
        let reserve = Self::new();
        for _ in 0..count {
            let Some(page) = pages.take(1) else {
                reserve.give_back(pages);
                return None;
            };
            reserve.push(page.as_ptr());
        }
        Some(reserve)
    }

    fn push(&self, page: *mut u8) {
        let count = self.count.get();
        assert!(count < RESERVE, "a reserve within its capacity");
        self.pages[count].set(page);
        self.count.set(count + 1);
    }

    /// Give every page left back to `pages`, where they came from.
    fn give_back(&self, pages: &impl Pages) {
        while let Some(page) = self.take(1) {
            // SAFETY: taken from `pages` by `take_from`, referred to by nothing.
            unsafe { pages.give(page, 1) };
        }
    }
}

impl Pages for Reserve {
    fn take(&self, pages: usize) -> Option<NonNull<u8>> {
        let count = self.count.get();
        if pages != 1 || count == 0 {
            return None;
        }
        self.count.set(count - 1);
        NonNull::new(self.pages[count - 1].get())
    }

    unsafe fn give(&self, at: NonNull<u8>, pages: usize) {
        assert_eq!(pages, 1, "a directory page");
        // SAFETY: the caller's contract: a page of ours, referred to no more. Zeroed, as `take`
        // hands pages out.
        unsafe { at.as_ptr().write_bytes(0, PAGE) };
        self.push(at.as_ptr());
    }
}

/// The pages a chunk of `count` items of `T` takes, a whole number.
const fn pages_of<T>(count: usize) -> usize {
    (count * core::mem::size_of::<T>()).div_ceil(PAGE)
}

// --- Slots --------------------------------------------------------------------------------------

/// How many slots of `T` a page holds: the `PER` of a pool whose chunk is one page.
pub const fn per_page<T>() -> usize {
    PAGE / core::mem::size_of::<Slot<T>>()
}

/// A slot's state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
enum State {
    /// Never handed out since the chunk's making or the last [`Slots::drain`]; at or above its
    /// lane's cursor, or below the highest placed index until [`Slots::seal_placed`].
    Fresh,
    /// Freed, on its lane's free list.
    Free,
    /// Reserved: missed by lookups, skipped by allocations, until filled or unreserved.
    Reserved,
    Live,
}

/// A slot: its uniqueness count, its state, the next slot on its free list, its record.
#[repr(C)]
struct Slot<T> {
    uniq: u16,
    state: State,
    next: u32,
    value: T,
}

/// No slot: a free list's end.
const NONE: u32 = u32::MAX;

/// A lane's free list, threaded through the slots' `next`: taken at the head, freed onto the head
/// (Lifo) or the tail (Fifo).
#[derive(Clone, Copy)]
struct FreeList {
    head: u32,
    tail: u32,
}

impl FreeList {
    const EMPTY: Self = FreeList {
        head: NONE,
        tail: NONE,
    };
}

/// The uniqueness count after `uniq`: one more, or 1 after `max`. The one rule for a table kept
/// outside a pool too (the font table's faces), so its counts are never 0 either.
pub const fn next_uniq(uniq: u16, max: u16) -> u16 {
    if uniq >= max {
        1
    } else {
        uniq + 1
    }
}

/// A pool of records of `T`, `PER` to a chunk, named by `C`'s ids, its chunks found through `D`.
///
/// The pool's bookkeeping touches a slot's fields one at a time through raw pointers, never a
/// reference to the whole slot, so a reference its owner holds into a record stays valid.
pub struct Slots<T: Record, C: Codec, const PER: usize, D: ChunkDir = Paged> {
    chunks: D,
    /// Chunks made: the slots `[0, made × PER)` exist.
    made: u32,
    /// Per lane: the lowest index never handed out.
    fresh: [u32; 2],
    /// Per lane: the freed slots.
    free: [FreeList; 2],
    live: u32,
    /// One past the highest index ever handed out.
    high: u32,
    _records: PhantomData<T>,
    _codec: PhantomData<C>,
}

impl<T: Record, C: Codec, const PER: usize, D: EmptyDir> Slots<T, C, PER, D> {
    /// An empty pool holding its own directory: no chunk made, no page held.
    pub const fn new() -> Self {
        Self::on(D::EMPTY)
    }
}

impl<T: Record, C: Codec, const PER: usize, D: ChunkDir> Slots<T, C, PER, D> {
    /// The pages one chunk takes.
    pub const CHUNK_PAGES: usize = {
        assert!(PER > 0 && C::LANES >= 1 && C::LANES <= 2);
        assert!(core::mem::align_of::<Slot<T>>() <= PAGE);
        assert!(C::MAX_UNIQ >= 1);
        pages_of::<Slot<T>>(PER)
    };
    /// The highest index this pool can hand out: the codec's, or the directory's if lower.
    const LIMIT: u32 = {
        let directory = D::CAPACITY as u64 * PER as u64 - 1;
        if directory < C::MAX_INDEX as u64 {
            directory as u32
        } else {
            C::MAX_INDEX
        }
    };

    /// The lowest index of `lane` at or above `from`.
    const fn lane_start(lane: usize, from: u32) -> u32 {
        let lanes = C::LANES as u32;
        from + (lane as u32 + lanes - from % lanes) % lanes
    }

    /// An empty pool on `chunks`, an empty directory: its own, or one kept apart (a
    /// `&'static Paged`) for readers that resolve without the owner's lock
    /// ([`Slots::address_in`]).
    pub const fn on(chunks: D) -> Self {
        let _ = Self::CHUNK_PAGES;
        Slots {
            chunks,
            made: 0,
            fresh: [
                Self::lane_start(0, C::RESERVED_LOW),
                Self::lane_start(1, C::RESERVED_LOW),
            ],
            free: [FreeList::EMPTY; 2],
            live: 0,
            high: 0,
            _records: PhantomData,
            _codec: PhantomData,
        }
    }

    /// Slot `index` through `chunks`, if its chunk is made.
    fn slot_in(chunks: &impl ChunkDir, index: u32) -> Option<NonNull<Slot<T>>> {
        let base = chunks.chunk(index / PER as u32)?;
        let offset = (index as usize % PER) * core::mem::size_of::<Slot<T>>();
        // SAFETY: a published chunk holds PER slots, so the offset lies inside it.
        Some(unsafe { base.add(offset) }.cast())
    }

    fn slot(&self, index: u32) -> Option<NonNull<Slot<T>>> {
        Self::slot_in(&self.chunks, index)
    }

    /// Slot `index`, whose chunk is made.
    fn at(&self, index: u32) -> *mut Slot<T> {
        self.slot(index).expect("a slot of a made chunk").as_ptr()
    }

    /// Slot `index`'s uniqueness count and state.
    fn meta(&self, index: u32) -> (u16, State) {
        let slot = self.at(index);
        // SAFETY: a made chunk's slot, written whole; its meta is the pool's alone.
        unsafe { ((*slot).uniq, (*slot).state) }
    }

    fn set_uniq(&mut self, index: u32, uniq: u16) {
        // SAFETY: as in `meta`; `&mut self` keeps every other change away.
        unsafe { (*self.at(index)).uniq = uniq };
    }

    fn set_state(&mut self, index: u32, state: State) {
        // SAFETY: as in `set_uniq`.
        unsafe { (*self.at(index)).state = state };
    }

    fn next(&self, index: u32) -> u32 {
        // SAFETY: as in `meta`.
        unsafe { (*self.at(index)).next }
    }

    fn set_next(&mut self, index: u32, next: u32) {
        // SAFETY: as in `set_uniq`.
        unsafe { (*self.at(index)).next = next };
    }

    /// Slot `index`'s record, for the owner.
    fn value(&mut self, index: u32) -> &mut T {
        // SAFETY: a made chunk's slot, written whole; `&mut self` makes this the only reference
        // the pool hands out.
        unsafe { &mut (*self.at(index)).value }
    }

    /// The slot `id` names, live or reserved as `state` asks: its index.
    fn find(&self, id: C::Id, state: State) -> Option<u32> {
        let (index, wanted) = C::decode(id)?;
        if !(C::RESERVED_LOW..=Self::LIMIT).contains(&index) {
            return None;
        }
        let slot = self.slot(index)?;
        // SAFETY: a made chunk's slot, written whole; only the meta is read.
        let (uniq, current) = unsafe { ((*slot.as_ptr()).uniq, (*slot.as_ptr()).state) };
        let matches = match wanted {
            Match::Exact(asked) => asked == uniq,
            Match::Any => true,
        };
        (current == state && matches).then_some(index)
    }

    fn push(&mut self, index: u32) {
        let lane = index as usize % C::LANES;
        match C::REUSE {
            Reuse::Lifo => {
                let head = self.free[lane].head;
                self.set_next(index, head);
                self.free[lane].head = index;
                if head == NONE {
                    self.free[lane].tail = index;
                }
            }
            Reuse::Fifo => self.push_tail(index),
        }
    }

    fn push_tail(&mut self, index: u32) {
        let lane = index as usize % C::LANES;
        self.set_next(index, NONE);
        match self.free[lane].tail {
            NONE => self.free[lane].head = index,
            tail => self.set_next(tail, index),
        }
        self.free[lane].tail = index;
    }

    /// The next slot of `lane`: its free list's head, else its cursor's, now in `state`.
    fn take(&mut self, lane: usize, state: State) -> Result<u32, Full> {
        assert!(lane < C::LANES, "a lane of the codec's");
        let index = match self.free[lane].head {
            NONE => {
                let index = self.fresh[lane];
                if index > Self::LIMIT {
                    return Err(Full::Limit);
                }
                if index / PER as u32 >= self.made {
                    return Err(Full::NoChunk);
                }
                self.fresh[lane] = index + C::LANES as u32;
                index
            }
            head => {
                let next = self.next(head);
                self.free[lane].head = next;
                if next == NONE {
                    self.free[lane].tail = NONE;
                }
                head
            }
        };
        self.set_state(index, state);
        self.high = self.high.max(index + 1);
        Ok(index)
    }

    /// Slot `index`, just taken live: its id and its record.
    fn taken(&mut self, index: u32) -> (C::Id, &mut T) {
        self.live += 1;
        let (uniq, _) = self.meta(index);
        (C::encode(index, uniq), self.value(index))
    }

    /// A slot of `lane`, live: its id and its record, for the owner to renew. Never takes
    /// memory: [`Full::NoChunk`] when the slot's chunk is not made.
    pub fn allocate(&mut self, lane: usize) -> Result<(C::Id, &mut T), Full> {
        let index = self.take(lane, State::Live)?;
        Ok(self.taken(index))
    }

    /// [`Slots::allocate`], making chunks as it needs them.
    pub fn allocate_or_grow(
        &mut self,
        lane: usize,
        pages: &impl Pages,
    ) -> Result<(C::Id, &mut T), Full> {
        loop {
            match self.take(lane, State::Live) {
                Err(Full::NoChunk) => self.grow(pages)?,
                Err(full) => return Err(full),
                Ok(index) => return Ok(self.taken(index)),
            }
        }
    }

    /// The chunk the next [`Slots::grow`] makes.
    pub fn next_chunk(&self) -> u32 {
        self.made
    }

    /// Whether every made slot lies past the codec's limit, so no chunk would help.
    fn at_limit(&self) -> bool {
        self.made as u64 * PER as u64 > Self::LIMIT as u64
    }

    /// Make the next chunk, every slot written fresh, and publish it with any directory page it
    /// needs. Only where taking pages is legal. On failure the pool is as it was.
    pub fn grow(&mut self, pages: &impl Pages) -> Result<(), Full> {
        if self.at_limit() {
            return Err(Full::Limit);
        }
        let chunk = Chunk::<T, PER, D>::make(self.made, pages).ok_or(Full::NoChunk)?;
        self.adopt(chunk, pages)
    }

    /// Whether the next allocation of `lane` needs a chunk made first.
    pub fn needs_chunk(&self, lane: usize) -> bool {
        self.free[lane].head == NONE
            && self.fresh[lane] <= Self::LIMIT
            && self.fresh[lane] / PER as u32 >= self.made
    }

    /// Publish a chunk made outside the owner's lock ([`Chunk::make`]) as the next one, with the
    /// directory pages it carries: takes no page. A chunk not the next one (another took its
    /// place meanwhile, or the pool is at its limit) is given back to `pages`, and the pool is as
    /// it was.
    pub fn adopt(&mut self, chunk: Chunk<T, PER, D>, pages: &impl Pages) -> Result<(), Full> {
        let Chunk {
            number,
            at,
            directory,
            ..
        } = chunk;
        let published = if self.at_limit() {
            Err(Full::Limit)
        } else if number != self.made {
            Err(Full::NoChunk)
        } else {
            self.chunks
                .publish(number, at, &directory)
                .map_err(|unpublished| match unpublished {
                    Unpublished::Capacity => Full::Limit,
                    Unpublished::Raced | Unpublished::NoPage => Full::NoChunk,
                })
        };
        // None is left after a publication: the chunk carried exactly the pages it needed.
        directory.give_back(pages);
        match published {
            Ok(()) => self.made += 1,
            // SAFETY: made from `pages` by `Chunk::make`, never published.
            Err(_) => unsafe { pages.give(at, Self::CHUNK_PAGES) },
        }
        published
    }

    /// The live record `id` names; none for a stale, forged or reserved id.
    pub fn get(&self, id: C::Id) -> Option<&T> {
        let index = self.find(id, State::Live)?;
        // SAFETY: a made chunk's slot, written whole; `&self` keeps the pool's changes away.
        Some(unsafe { &(*self.at(index)).value })
    }

    /// [`Slots::get`], to change.
    pub fn get_mut(&mut self, id: C::Id) -> Option<&mut T> {
        let index = self.find(id, State::Live)?;
        Some(self.value(index))
    }

    /// The id of the live slot `index`; none for a slot not live, or not made.
    pub fn id_at(&self, index: u32) -> Option<C::Id> {
        if !(C::RESERVED_LOW..=Self::LIMIT).contains(&index) {
            return None;
        }
        let slot = self.slot(index)?;
        // SAFETY: a made chunk's slot, written whole; only the meta is read.
        let (uniq, state) = unsafe { ((*slot.as_ptr()).uniq, (*slot.as_ptr()).state) };
        (state == State::Live).then(|| C::encode(index, uniq))
    }

    /// The index `id` names while its slot is live.
    pub fn index_of(&self, id: C::Id) -> Option<u32> {
        self.find(id, State::Live)
    }

    /// Leave a slot of `index` for the next of its lane, its uniqueness count moved on.
    fn release(&mut self, index: u32) {
        let (uniq, _) = self.meta(index);
        self.set_uniq(index, next_uniq(uniq, C::MAX_UNIQ));
        self.set_state(index, State::Free);
        self.push(index);
    }

    /// Free the live slot `id` names: its record stays in place, its count moves on, so `id`
    /// names nothing more. False when `id` names no live slot.
    pub fn free(&mut self, id: C::Id) -> bool {
        let Some(index) = self.find(id, State::Live) else {
            return false;
        };
        self.live -= 1;
        self.release(index);
        true
    }

    /// Reserve a slot of `lane`: its id, which names nothing until [`Slots::fill`].
    pub fn reserve(&mut self, lane: usize) -> Result<C::Id, Full> {
        let index = self.take(lane, State::Reserved)?;
        Ok(C::encode(index, self.meta(index).0))
    }

    /// [`Slots::reserve`], making chunks as it needs them.
    pub fn reserve_or_grow(&mut self, lane: usize, pages: &impl Pages) -> Result<C::Id, Full> {
        loop {
            match self.reserve(lane) {
                Err(Full::NoChunk) => self.grow(pages)?,
                other => return other,
            }
        }
    }

    /// Make the reserved slot `id` live: its record, for the owner to renew.
    pub fn fill(&mut self, id: C::Id) -> Option<&mut T> {
        let index = self.find(id, State::Reserved)?;
        self.live += 1;
        self.set_state(index, State::Live);
        Some(self.value(index))
    }

    /// Give back the reserved slot `id`, its count moved on; false when `id` names none.
    pub fn unreserve(&mut self, id: C::Id) -> bool {
        let Some(index) = self.find(id, State::Reserved) else {
            return false;
        };
        self.release(index);
        true
    }

    /// Make slot `index` live, on a pool nothing was allocated from yet, making chunks as it
    /// needs them: its id and its record. Placed slots are in any order; [`Slots::seal_placed`]
    /// follows them, before any allocation.
    pub fn place(&mut self, index: u32, pages: &impl Pages) -> Result<(C::Id, &mut T), Full> {
        if !(C::RESERVED_LOW..=Self::LIMIT).contains(&index) {
            return Err(Full::Limit);
        }
        while index / PER as u32 >= self.made {
            self.grow(pages)?;
        }
        assert_eq!(self.meta(index).1, State::Fresh, "a slot placed once");
        self.set_state(index, State::Live);
        self.high = self.high.max(index + 1);
        Ok(self.taken(index))
    }

    /// End the placing: the slots below the highest placed that were not placed go to their
    /// lanes' free lists, the lowest to be taken first, and each lane's cursor moves past it.
    pub fn seal_placed(&mut self) {
        for index in C::RESERVED_LOW..self.high {
            if self.meta(index).1 == State::Fresh {
                self.set_state(index, State::Free);
                self.push_tail(index);
            }
        }
        for lane in 0..C::LANES {
            self.fresh[lane] = self.fresh[lane].max(Self::lane_start(lane, self.high));
        }
    }

    /// The live slots' ids and records, in index order.
    pub fn iter(&self) -> impl Iterator<Item = (C::Id, &T)> + '_ {
        (C::RESERVED_LOW..self.high).filter_map(move |index| {
            let slot = self.slot(index)?.as_ptr();
            // SAFETY: a made chunk's slot, written whole; `&self` keeps the pool's changes away.
            let (uniq, state, value) = unsafe { ((*slot).uniq, (*slot).state, &(*slot).value) };
            (state == State::Live).then(|| (C::encode(index, uniq), value))
        })
    }

    /// [`Slots::iter`], to change.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = (C::Id, &mut T)> + '_ {
        let this = &*self;
        (C::RESERVED_LOW..self.high).filter_map(move |index| {
            let slot = this.slot(index)?.as_ptr();
            // SAFETY: each index is visited once, so the records are distinct, and the exclusive
            // borrow of the pool lasts as long as the iterator.
            let (uniq, state, value) = unsafe { ((*slot).uniq, (*slot).state, &mut (*slot).value) };
            (state == State::Live).then(|| (C::encode(index, uniq), value))
        })
    }

    /// Back to no slot handed out, with `made` chunks.
    fn restart(&mut self, made: u32) {
        self.made = made;
        self.fresh = [
            Self::lane_start(0, C::RESERVED_LOW),
            Self::lane_start(1, C::RESERVED_LOW),
        ];
        self.free = [FreeList::EMPTY; 2];
        self.live = 0;
        self.high = 0;
    }

    /// Hand every live record to `f`, then empty the pool: every slot fresh again, its count
    /// moved on if it was live or reserved, the chunks kept.
    pub fn drain(&mut self, mut f: impl FnMut(C::Id, &mut T)) {
        for index in C::RESERVED_LOW..self.high {
            let (uniq, state) = self.meta(index);
            if state == State::Live {
                f(C::encode(index, uniq), self.value(index));
            }
            if matches!(state, State::Live | State::Reserved) {
                self.set_uniq(index, next_uniq(uniq, C::MAX_UNIQ));
            }
            self.set_state(index, State::Fresh);
        }
        self.restart(self.made);
    }

    /// Empty the pool and give back its chunks and directory pages, as a new pool: what a pool
    /// that restarts empty does (a process's handle table at its teardown). Live and reserved
    /// slots are discarded, not dropped.
    ///
    /// # Safety
    ///
    /// Every chunk was taken from `pages`, nothing refers to a record any more, and nothing
    /// resolves through the directory meanwhile.
    pub unsafe fn reset(&mut self, pages: &impl Pages) {
        // SAFETY: the caller's contract.
        unsafe { self.chunks.release(Self::CHUNK_PAGES, pages) };
        self.restart(0);
    }

    /// Slot `index`'s record's address, whatever its state; none if its chunk is unmade.
    pub fn address(&self, index: u32) -> Option<NonNull<T>> {
        Self::address_in(&self.chunks, index)
    }

    /// [`Slots::address`] through `chunks`, the directory the pool was built on
    /// ([`Slots::on`]): no borrow of the pool, so a reader without the owner's lock resolves
    /// while the owner changes it.
    pub fn address_in(chunks: &impl ChunkDir, index: u32) -> Option<NonNull<T>> {
        let slot = Self::slot_in(chunks, index)?;
        // SAFETY: a made chunk's slot; only the address is taken.
        Some(unsafe { NonNull::new_unchecked(addr_of_mut!((*slot.as_ptr()).value)) })
    }

    /// The live slots.
    pub fn live(&self) -> u32 {
        self.live
    }

    /// One past the highest index ever handed out.
    pub fn high_water(&self) -> u32 {
        self.high
    }

    /// Set slot `index`'s uniqueness count, to reach the wrap without 65K frees.
    #[cfg(test)]
    fn force_uniq(&mut self, index: u32, uniq: u16) {
        self.set_uniq(index, uniq);
    }
}

impl<T: Record, C: Codec, const PER: usize, D: EmptyDir> Default for Slots<T, C, PER, D> {
    fn default() -> Self {
        Self::new()
    }
}

/// A chunk of `PER` fresh slots with the directory pages its publication needs, made outside its
/// pool's owner's lock (where taking pages is not legal inside it) and handed to
/// [`Slots::adopt`], which publishes it or gives it back.
#[must_use = "a chunk not adopted holds its pages"]
pub struct Chunk<T: Record, const PER: usize, D: ChunkDir = Paged> {
    number: u32,
    at: NonNull<u8>,
    directory: Reserve,
    _records: PhantomData<(T, D)>,
}

impl<T: Record, const PER: usize, D: ChunkDir> Chunk<T, PER, D> {
    /// Chunk `number` ([`Slots::next_chunk`]), every slot written fresh, with the directory pages
    /// publishing it as the next chunk takes; none when `pages` has too few.
    pub fn make(number: u32, pages: &impl Pages) -> Option<Self> {
        let directory = Reserve::take_from(D::next_pages(number), pages)?;
        let Some(at) = pages.take(pages_of::<Slot<T>>(PER)) else {
            directory.give_back(pages);
            return None;
        };
        let first = number as usize * PER;
        let slots = at.cast::<Slot<T>>().as_ptr();
        for offset in 0..PER {
            // SAFETY: the pages hold PER slots, page-aligned (so aligned for `Slot<T>`), and are
            // ours alone until published; each slot is written whole.
            unsafe {
                let slot = slots.add(offset);
                addr_of_mut!((*slot).uniq).write(1);
                addr_of_mut!((*slot).state).write(State::Fresh);
                addr_of_mut!((*slot).next).write(NONE);
                T::write_fresh(addr_of_mut!((*slot).value), (first + offset) as u32);
            }
        }
        Some(Chunk {
            number,
            at,
            directory,
            _records: PhantomData,
        })
    }
}

// --- SideTable ----------------------------------------------------------------------------------

/// Why [`SideTable::ensure`] made no chunk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Exhausted {
    /// No pages for the chunk or a directory page.
    NoPages,
    /// The index lies past the directory's capacity.
    Limit,
}

/// A side table's entry: its index ahead of its record, so an address leads back to its index.
#[repr(C)]
struct Entry<T> {
    index: u32,
    value: T,
}

/// Records of `T` by index, `PER` to a chunk, with no allocation of their own: the same index as
/// another pool's (the dispatcher bodies, per-thread and per-process data).
pub struct SideTable<T: Record, const PER: usize, D: ChunkDir = Paged> {
    chunks: D,
    _records: PhantomData<T>,
}

impl<T: Record, const PER: usize, D: EmptyDir> SideTable<T, PER, D> {
    /// An empty table holding its own directory: no chunk made, no page held.
    pub const fn new() -> Self {
        Self::on(D::EMPTY)
    }
}

impl<T: Record, const PER: usize, D: ChunkDir> SideTable<T, PER, D> {
    /// The pages one chunk takes.
    pub const CHUNK_PAGES: usize = {
        assert!(PER > 0 && core::mem::size_of::<T>() > 0);
        assert!(core::mem::align_of::<Entry<T>>() <= PAGE);
        pages_of::<Entry<T>>(PER)
    };
    /// Where a record lies in its entry.
    const VALUE: usize = core::mem::offset_of!(Entry<T>, value);

    /// An empty table on `chunks`, an empty directory: its own, or one kept apart for readers
    /// that resolve without the owner's lock ([`SideTable::address_in`]).
    pub const fn on(chunks: D) -> Self {
        let _ = Self::CHUNK_PAGES;
        SideTable {
            chunks,
            _records: PhantomData,
        }
    }

    /// Make the chunk holding `index` if it is not made, every record written fresh, with the
    /// directory pages it needs. Takes no lock: racing callers make one chunk and one page of
    /// each, the losers' pages given back. On failure the table is as it was.
    pub fn ensure(&self, index: u32, pages: &impl Pages) -> Result<(), Exhausted> {
        let chunk = index / PER as u32;
        if chunk >= D::CAPACITY {
            return Err(Exhausted::Limit);
        }
        if self.chunks.chunk(chunk).is_some() {
            return Ok(());
        }
        let at = pages.take(Self::CHUNK_PAGES).ok_or(Exhausted::NoPages)?;
        let entries = at.cast::<Entry<T>>().as_ptr();
        for offset in 0..PER {
            // SAFETY: the pages hold PER entries, page-aligned, ours alone until published.
            unsafe {
                let entry = entries.add(offset);
                let index = chunk * PER as u32 + offset as u32;
                addr_of_mut!((*entry).index).write(index);
                T::write_fresh(addr_of_mut!((*entry).value), index);
            }
        }
        let published = loop {
            let Some(directory) = Reserve::take_from(self.chunks.missing_pages(chunk), pages)
            else {
                break Err(Unpublished::NoPage);
            };
            let published = self.chunks.publish(chunk, at, &directory);
            directory.give_back(pages);
            // Racers only add pages, which never asks more of this publication, but for the
            // first: a tree made meanwhile where there was none may. Count again.
            if published != Err(Unpublished::NoPage) {
                break published;
            }
        };
        match published {
            Ok(()) => Ok(()),
            Err(unpublished) => {
                // SAFETY: just taken from `pages`, never published.
                unsafe { pages.give(at, Self::CHUNK_PAGES) };
                match unpublished {
                    Unpublished::Raced => Ok(()),
                    Unpublished::NoPage => Err(Exhausted::NoPages),
                    Unpublished::Capacity => Err(Exhausted::Limit),
                }
            }
        }
    }

    /// Record `index`'s address; none if its chunk is unmade. Takes no lock.
    pub fn address(&self, index: u32) -> Option<NonNull<T>> {
        Self::address_in(&self.chunks, index)
    }

    /// [`SideTable::address`] through `chunks`, the directory the table was built on
    /// ([`SideTable::on`]), for a reader that cannot borrow the table.
    pub fn address_in(chunks: &impl ChunkDir, index: u32) -> Option<NonNull<T>> {
        let base = chunks.chunk(index / PER as u32)?;
        let entry = base.cast::<Entry<T>>();
        // SAFETY: a published chunk holds PER entries; only the address is taken.
        Some(unsafe {
            let entry = entry.add(index as usize % PER).as_ptr();
            NonNull::new_unchecked(addr_of_mut!((*entry).value))
        })
    }

    /// The index of the record at `at`: none for an address that is no record of the table.
    /// Reads the index its entry carries, then checks the table puts that record at `at`.
    ///
    /// # Safety
    ///
    /// The u32 where `at`'s entry index would be, [`SideTable::VALUE`] bytes before it, is
    /// readable through `at`: any address the table handed out, or one at least that far into an
    /// object `at` was derived from (not a reference to the record alone).
    pub unsafe fn index_at(&self, at: *const T) -> Option<u32> {
        // SAFETY: the caller's contract.
        unsafe { Self::index_at_in(&self.chunks, at) }
    }

    /// [`SideTable::index_at`] through `chunks`, as [`SideTable::address_in`].
    ///
    /// # Safety
    ///
    /// As [`SideTable::index_at`]'s.
    pub unsafe fn index_at_in(chunks: &impl ChunkDir, at: *const T) -> Option<u32> {
        let index = at.cast::<u8>().wrapping_sub(Self::VALUE).cast::<u32>();
        // SAFETY: the caller's contract; unaligned for an address that is no record's.
        let index = unsafe { index.read_unaligned() };
        let found = Self::address_in(chunks, index)?;
        (found.as_ptr().cast_const() == at).then_some(index)
    }

    /// Record `index`; none if its chunk is unmade.
    pub fn get(&self, index: u32) -> Option<&T> {
        // SAFETY: a published chunk's record, written whole before its publication.
        self.address(index).map(|at| unsafe { &*at.as_ptr() })
    }

    /// [`SideTable::get`], to change.
    pub fn get_mut(&mut self, index: u32) -> Option<&mut T> {
        // SAFETY: as in `get`; `&mut self` makes this the only reference.
        self.address(index).map(|at| unsafe { &mut *at.as_ptr() })
    }
}

impl<T: Record, const PER: usize, D: EmptyDir> Default for SideTable<T, PER, D> {
    fn default() -> Self {
        Self::new()
    }
}

// --- Codecs -------------------------------------------------------------------------------------

/// A kernel-internal id of kind `K`: a u16 index and a u16 uniqueness count.
pub struct Id<K> {
    pub index: u16,
    pub uniq: u16,
    _kind: PhantomData<fn() -> K>,
}

impl<K> Id<K> {
    pub const fn new(index: u16, uniq: u16) -> Self {
        Id {
            index,
            uniq,
            _kind: PhantomData,
        }
    }
}

impl<K> Clone for Id<K> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<K> Copy for Id<K> {}

impl<K> PartialEq for Id<K> {
    fn eq(&self, other: &Self) -> bool {
        (self.index, self.uniq) == (other.index, other.uniq)
    }
}

impl<K> Eq for Id<K> {}

impl<K> core::fmt::Debug for Id<K> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Id({}#{})", self.index, self.uniq)
    }
}

/// Kernel-internal ids ([`Id`]): ob's objects, win32k's records, cm, io. Never reach a program.
pub struct KernelId<K>(PhantomData<fn() -> K>);

impl<K> Codec for KernelId<K> {
    type Id = Id<K>;

    const LANES: usize = 1;
    /// The u16 index: 65,535 per kind, far more than memory backs.
    const MAX_INDEX: u32 = 0xFFFE;
    const MAX_UNIQ: u16 = 0xFFFE;
    const RESERVED_LOW: u32 = 0;
    const REUSE: Reuse = Reuse::Fifo;

    fn encode(index: u32, uniq: u16) -> Id<K> {
        Id::new(index as u16, uniq)
    }

    fn decode(id: Id<K>) -> Option<(u32, Match)> {
        Some((id.index as u32, Match::Exact(id.uniq)))
    }
}

/// A process's NT handles: the index shifted left two, the low two bits (the tag bits) ignored;
/// the value carries no uniqueness, so a closed handle names whatever takes its slot next, as on
/// Windows 2000.
pub struct NtHandle;

impl Codec for NtHandle {
    type Id = u32;

    const LANES: usize = 1;
    /// Windows' ~2^24 handles per process; memory runs out long before.
    const MAX_INDEX: u32 = (1 << 24) - 1;
    const MAX_UNIQ: u16 = 0xFFFE;
    const RESERVED_LOW: u32 = 1;
    const REUSE: Reuse = Reuse::Lifo;

    fn encode(index: u32, _: u16) -> u32 {
        index << 2
    }

    fn decode(handle: u32) -> Option<(u32, Match)> {
        Some((handle >> 2, Match::Any))
    }
}

/// USER handles: the index in the low word, the uniqueness in the high word, where 0 and 0xFFFF
/// name whatever the slot holds (the menus capture). Lane 0 (even) for windows, lane 1 (odd) for
/// the other kinds.
pub struct UserHandle;

impl Codec for UserHandle {
    type Id = u32;

    const LANES: usize = 2;
    /// The 16-bit low word: Windows' ~64K USER handles system-wide.
    const MAX_INDEX: u32 = 0xFFFF;
    const MAX_UNIQ: u16 = 0xFFFE;
    const RESERVED_LOW: u32 = 1;
    const REUSE: Reuse = Reuse::Lifo;

    fn encode(index: u32, uniq: u16) -> u32 {
        index | (uniq as u32) << 16
    }

    fn decode(handle: u32) -> Option<(u32, Match)> {
        let uniq = match (handle >> 16) as u16 {
            0 | 0xFFFF => Match::Any,
            uniq => Match::Exact(uniq),
        };
        Some((handle & 0xFFFF, uniq))
    }
}

/// GDI handles: the index in the low word, the kind in bits 16–22 (the owner's, ignored here),
/// the stock bit 23 clear, an 8-bit uniqueness in bits 24–31.
pub struct GdiHandle;

/// A GDI handle's stock bit: a stock object, never a table slot.
pub const GDI_STOCK: u32 = 1 << 23;

impl Codec for GdiHandle {
    type Id = u32;

    const LANES: usize = 1;
    /// Windows 2000's GDI table: 16,384 entries system-wide.
    const MAX_INDEX: u32 = 0x3FFF;
    const MAX_UNIQ: u16 = 0xFF;
    const RESERVED_LOW: u32 = 1;
    const REUSE: Reuse = Reuse::Lifo;

    fn encode(index: u32, uniq: u16) -> u32 {
        index | (uniq as u32) << 24
    }

    fn decode(handle: u32) -> Option<(u32, Match)> {
        (handle & GDI_STOCK == 0).then_some((handle & 0xFFFF, Match::Exact((handle >> 24) as u16)))
    }
}

/// Client ids (PIDs and TIDs): the index shifted left two, the low two bits ignored as a handle's;
/// 0 (the idle process), 4 and 8 (the System process) never handed out; the id freed last comes
/// back first, as Windows 2000's PspCidTable (a handle table) does.
pub struct ClientId;

impl Codec for ClientId {
    type Id = u32;

    const LANES: usize = 1;
    /// PspCidTable is a handle table: ~2^24 ids; memory runs out long before.
    const MAX_INDEX: u32 = (1 << 24) - 1;
    const MAX_UNIQ: u16 = 0xFFFE;
    const RESERVED_LOW: u32 = 3;
    const REUSE: Reuse = Reuse::Lifo;

    fn encode(index: u32, _: u16) -> u32 {
        index << 2
    }

    fn decode(id: u32) -> Option<(u32, Match)> {
        Some((id >> 2, Match::Any))
    }
}

// --- Pages --------------------------------------------------------------------------------------

/// Chunks from the nonpaged pool, kept until given back, their frames counted
/// ([`chunk_frames`]).
#[cfg(target_arch = "x86")]
pub struct NonpagedPages;

/// The frames the pools' chunks and directory pages hold now.
#[cfg(target_arch = "x86")]
static CHUNK_FRAMES: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// The frames the pools' chunks and directory pages hold: permanent at quiescence, when only the
/// pools that keep their peak hold any, so the teardown audits count them with the free frames.
#[cfg(target_arch = "x86")]
pub fn chunk_frames() -> u32 {
    CHUNK_FRAMES.load(Ordering::Relaxed)
}

#[cfg(target_arch = "x86")]
impl Pages for NonpagedPages {
    fn take(&self, pages: usize) -> Option<NonNull<u8>> {
        let block = crate::mem::pool::allocate(pages * PAGE)?;
        let at = block.virtual_address() as usize as *mut u8;
        // Kept until `give`, which rebuilds the block from its address.
        core::mem::forget(block);
        CHUNK_FRAMES.fetch_add(pages as u32, Ordering::Relaxed);
        NonNull::new(at)
    }

    unsafe fn give(&self, at: NonNull<u8>, pages: usize) {
        crate::mem::pool::release_block(at.as_ptr() as usize as u32, pages * PAGE);
        CHUNK_FRAMES.fetch_sub(pages as u32, Ordering::Relaxed);
    }
}

/// Pages from the host allocator, counted, with a budget a test lowers to make `take` fail: the
/// host builds' [`KERNEL_PAGES`] (the unit tests, and the plain library the documentation tests
/// build against), and the pools' own tests'.
#[cfg(not(target_arch = "x86"))]
pub struct HostPages {
    /// How many more pages `take` hands out.
    budget: core::sync::atomic::AtomicUsize,
    /// The pages taken and not given back.
    held: core::sync::atomic::AtomicUsize,
}

#[cfg(not(target_arch = "x86"))]
impl HostPages {
    pub const fn new() -> Self {
        Self::with_budget(usize::MAX)
    }

    pub const fn with_budget(pages: usize) -> Self {
        HostPages {
            budget: core::sync::atomic::AtomicUsize::new(pages),
            held: core::sync::atomic::AtomicUsize::new(0),
        }
    }

    pub fn set_budget(&self, pages: usize) {
        self.budget.store(pages, Ordering::SeqCst);
    }

    pub fn held(&self) -> usize {
        self.held.load(Ordering::SeqCst)
    }

    fn layout(pages: usize) -> std::alloc::Layout {
        std::alloc::Layout::from_size_align(pages * PAGE, PAGE).unwrap()
    }
}

#[cfg(not(target_arch = "x86"))]
impl Default for HostPages {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(not(target_arch = "x86"))]
impl Pages for HostPages {
    fn take(&self, pages: usize) -> Option<NonNull<u8>> {
        let mut left = self.budget.load(Ordering::SeqCst);
        loop {
            let after = left.checked_sub(pages)?;
            match self
                .budget
                .compare_exchange(left, after, Ordering::SeqCst, Ordering::SeqCst)
            {
                Ok(_) => break,
                Err(now) => left = now,
            }
        }
        // SAFETY: a nonzero size (every chunk holds a slot).
        let at = NonNull::new(unsafe { std::alloc::alloc_zeroed(Self::layout(pages)) })?;
        self.held.fetch_add(pages, Ordering::SeqCst);
        Some(at)
    }

    unsafe fn give(&self, at: NonNull<u8>, pages: usize) {
        // SAFETY: the caller's contract: one `take`'s pages, with its layout.
        unsafe { std::alloc::dealloc(at.as_ptr(), Self::layout(pages)) };
        self.held.fetch_sub(pages, Ordering::SeqCst);
    }
}

/// The pages the kernel's own pools grow from: the nonpaged pool on target.
#[cfg(target_arch = "x86")]
pub static KERNEL_PAGES: NonpagedPages = NonpagedPages;

/// The pages the kernel's own pools grow from: the host allocator in the host builds, where the
/// owners' tests run.
#[cfg(not(target_arch = "x86"))]
pub static KERNEL_PAGES: HostPages = HostPages::new();

#[cfg(test)]
mod tests {
    //! The pools' host tests, on [`HostPages`].

    use std::boxed::Box;
    use std::vec::Vec;

    use super::*;

    /// A test record: the index it was written fresh for, and a value its owner sets.
    #[derive(Debug)]
    struct Rec {
        index: u32,
        value: u32,
    }

    // SAFETY: `write_fresh` writes a whole record.
    unsafe impl Record for Rec {
        unsafe fn write_fresh(at: *mut Self, index: u32) {
            // SAFETY: the caller's contract.
            unsafe { at.write(Rec { index, value: 0 }) };
        }
    }

    /// Kernel-style ids with a small limit and either reuse order.
    struct Small<const MAX: u32, const LIFO: bool>;

    impl<const MAX: u32, const LIFO: bool> Codec for Small<MAX, LIFO> {
        type Id = Id<()>;

        const LANES: usize = 1;
        const MAX_INDEX: u32 = MAX;
        const MAX_UNIQ: u16 = 0xFFFE;
        const RESERVED_LOW: u32 = 0;
        const REUSE: Reuse = if LIFO { Reuse::Lifo } else { Reuse::Fifo };

        fn encode(index: u32, uniq: u16) -> Id<()> {
            Id::new(index as u16, uniq)
        }

        fn decode(id: Id<()>) -> Option<(u32, Match)> {
            Some((id.index as u32, Match::Exact(id.uniq)))
        }
    }

    type Kernel<const PER: usize, const N: usize> = Slots<Rec, KernelId<()>, PER, Inline<N>>;

    fn boxed<P>(pool: P) -> Box<P> {
        Box::new(pool)
    }

    /// Allocation fails with NoChunk until a chunk is made, then fills it; Limit comes exactly at
    /// the codec's highest index. A grow that finds no pages leaves the pool as it was.
    #[test]
    fn fill_and_grow() {
        let pages = HostPages::new();
        let mut pool = boxed(Slots::<Rec, Small<9, false>, 4, Inline<8>>::new());
        assert_eq!(pool.allocate(0).err(), Some(Full::NoChunk));
        let mut ids = Vec::new();
        loop {
            match pool.allocate(0) {
                Ok((id, rec)) => {
                    assert_eq!(
                        rec.index, id.index as u32,
                        "written fresh for its own index"
                    );
                    rec.value = id.index as u32 * 10;
                    ids.push(id);
                }
                Err(Full::NoChunk) => pool.grow(&pages).unwrap(),
                Err(Full::Limit) => break,
            }
        }
        assert_eq!(ids.len(), 10, "indices 0 to 9");
        assert_eq!(pool.live(), 10);
        assert_eq!(pool.high_water(), 10);
        assert_eq!(
            pool.grow(&pages),
            Err(Full::Limit),
            "no chunk past the limit"
        );
        for id in &ids {
            assert_eq!(pool.get(*id).unwrap().value, id.index as u32 * 10);
        }

        let mut pool = boxed(Slots::<Rec, Small<99, false>, 4, Inline<32>>::new());
        let pages = HostPages::with_budget(1);
        pool.grow(&pages).unwrap();
        let ids: Vec<_> = (0..4).map(|_| pool.allocate(0).unwrap().0).collect();
        assert_eq!(pool.allocate(0).err(), Some(Full::NoChunk));
        assert_eq!(pool.grow(&pages), Err(Full::NoChunk), "no pages left");
        assert_eq!(pool.allocate_or_grow(0, &pages).err(), Some(Full::NoChunk));
        assert_eq!(
            (pool.live(), pool.high_water(), pool.next_chunk()),
            (4, 4, 1)
        );
        assert!(ids.iter().all(|id| pool.get(*id).is_some()));
        pages.set_budget(1);
        assert!(pool.allocate_or_grow(0, &pages).is_ok());
    }

    /// `id_at` names a live slot's current id, and nothing for a freed, reserved, unmade or
    /// out-of-range slot; `per_page` fills a page with slots and no more.
    #[test]
    fn id_at_names_live_slots_only() {
        let pages = HostPages::new();
        let mut pool = boxed(Slots::<Rec, Small<9, false>, 4, Inline<8>>::new());
        let a = pool.allocate_or_grow(0, &pages).unwrap().0;
        let b = pool.allocate_or_grow(0, &pages).unwrap().0;
        let reserved = pool.reserve(0).unwrap();
        assert_eq!(pool.id_at(0), Some(a));
        assert_eq!(pool.id_at(1), Some(b));
        assert_eq!(pool.id_at(2), None, "reserved");
        assert_eq!(pool.id_at(3), None, "fresh");
        assert_eq!(pool.id_at(4), None, "an unmade chunk");
        assert_eq!(pool.id_at(10), None, "past the limit");
        assert!(pool.free(a));
        assert_eq!(pool.id_at(0), None, "freed");
        assert!(pool.unreserve(reserved));
        let again = pool.allocate(0).unwrap().0;
        assert_eq!(
            (again.index, again.uniq),
            (0, 2),
            "the oldest freed, its count on"
        );
        assert_eq!(pool.id_at(0), Some(again));

        let per = per_page::<Rec>();
        assert!(per * core::mem::size_of::<Slot<Rec>>() <= PAGE);
        assert!((per + 1) * core::mem::size_of::<Slot<Rec>>() > PAGE);
        assert_eq!(
            Slots::<Rec, Small<9, false>, { per_page::<Rec>() }, Paged>::CHUNK_PAGES,
            1
        );
    }

    /// A fixed directory of N chunks reaches Limit at N × PER slots.
    #[test]
    fn an_inline_directory_ends_at_its_chunks() {
        let pages = HostPages::new();
        let mut pool = boxed(Kernel::<4, 3>::new());
        for _ in 0..12 {
            pool.allocate_or_grow(0, &pages).unwrap();
        }
        assert_eq!(pool.allocate_or_grow(0, &pages).err(), Some(Full::Limit));
        assert_eq!(pool.grow(&pages), Err(Full::Limit));
        assert_eq!(pages.held(), 3);
    }

    /// A record's address never changes as the pool grows.
    #[test]
    fn addresses_are_stable_across_growth() {
        let pages = HostPages::new();
        let mut pool = boxed(Kernel::<1, 2048>::new());
        let (first, _) = pool.allocate_or_grow(0, &pages).unwrap();
        let before = pool.address(0).unwrap();
        let mut addresses = Vec::new();
        for _ in 0..2000 {
            let (id, rec) = pool.allocate_or_grow(0, &pages).unwrap();
            addresses.push((id, rec as *mut Rec));
        }
        assert_eq!(pool.address(0), Some(before));
        assert_eq!(
            pool.get(first).map(|r| r as *const Rec),
            Some(before.as_ptr().cast_const())
        );
        for (id, at) in addresses {
            assert_eq!(pool.address(id.index as u32).unwrap().as_ptr(), at);
        }
        assert_eq!(pool.address(2001), None, "an unmade chunk's");
    }

    /// Lifo takes the slot freed last first; Fifo the one freed first.
    #[test]
    fn reuse_orders() {
        let pages = HostPages::new();
        let mut lifo = boxed(Slots::<Rec, Small<99, true>, 8, Inline<4>>::new());
        let mut fifo = boxed(Slots::<Rec, Small<99, false>, 8, Inline<4>>::new());
        let l: Vec<_> = (0..4)
            .map(|_| lifo.allocate_or_grow(0, &pages).unwrap().0)
            .collect();
        let f: Vec<_> = (0..4)
            .map(|_| fifo.allocate_or_grow(0, &pages).unwrap().0)
            .collect();
        for i in [1, 3, 0] {
            assert!(lifo.free(l[i]));
            assert!(fifo.free(f[i]));
        }
        let lifo: Vec<_> = (0..4).map(|_| lifo.allocate(0).unwrap().0.index).collect();
        let fifo: Vec<_> = (0..4).map(|_| fifo.allocate(0).unwrap().0.index).collect();
        assert_eq!(lifo, [0, 3, 1, 4]);
        assert_eq!(fifo, [1, 3, 0, 4]);
    }

    /// A freed id names nothing; the next id in its slot has the count one more; an id with a
    /// count ahead of its slot's names nothing. A slot's first count is 1.
    #[test]
    fn stale_ids_name_nothing() {
        let pages = HostPages::new();
        let mut pool = boxed(Kernel::<8, 4>::new());
        let (old, _) = pool.allocate_or_grow(0, &pages).unwrap();
        assert_eq!(old.uniq, 1, "a slot's first count");
        assert!(pool.free(old));
        assert!(!pool.free(old), "a freed id frees nothing");
        assert!(pool.get(old).is_none());
        let (new, _) = pool.allocate(0).unwrap();
        assert_eq!(
            (new.index, new.uniq),
            (old.index, 2),
            "the freed slot, counted on"
        );
        assert!(pool.get(old).is_none());
        assert!(pool.get(new).is_some());
        assert!(pool.get(Id::new(new.index, 3)).is_none());
        assert!(pool.get(Id::new(new.index, 0)).is_none(), "0 names nothing");
    }

    /// The USER table: windows take even slots, the other kinds odd ones and even ones once no odd
    /// is left; the slot freed last of a kind's lane goes first. Its handles' low word is the
    /// index, the high word the count from 1, with 0 and 0xFFFF naming the live object.
    mod user {
        use super::*;

        type Table = Slots<Rec, UserHandle, 512, Inline<128>>;

        fn window(t: &mut Table, pages: &HostPages) -> u32 {
            t.allocate_or_grow(0, pages).unwrap().0
        }

        fn other(t: &mut Table, pages: &HostPages) -> u32 {
            match t.allocate_or_grow(1, pages) {
                Err(Full::Limit) => t.allocate_or_grow(0, pages).unwrap().0,
                other => other.unwrap().0,
            }
        }

        #[test]
        fn kinds_share_the_slots() {
            let pages = HostPages::new();
            let mut t = boxed(Table::new());
            let (m, c) = (other(&mut t, &pages), other(&mut t, &pages));
            assert_eq!((m, c), (0x1_0001, 0x1_0003));
        }

        #[test]
        fn reuse_moves_the_count_and_the_wildcards_name_the_live_object() {
            let pages = HostPages::new();
            let mut t = boxed(Table::new());
            let c = other(&mut t, &pages);
            assert!(t.free(c));
            assert!(!t.free(c));
            let m = other(&mut t, &pages);
            assert_eq!(m, c + 0x1_0000, "the slot just freed, its count one more");
            assert!(
                t.get(c).is_none(),
                "the destroyed first handle names nothing"
            );
            assert!(
                t.get(m & 0xFFFF).is_some(),
                "high word 0 names the live object"
            );
            assert!(t.get(m | 0xFFFF_0000).is_some(), "so does 0xFFFF");
            assert!(t.get(m + 0x1_0000).is_none());
            assert!(t.get(0).is_none() && t.get(0xFFFF_0000).is_none(), "slot 0");
        }

        #[test]
        #[cfg_attr(miri, ignore)]
        fn windows_take_the_even_slots() {
            let pages = HostPages::new();
            let mut t = boxed(Table::new());
            let w = window(&mut t, &pages);
            assert_eq!(w, 0x1_0002);
            t.free(w);
            let m = other(&mut t, &pages);
            assert_eq!(m, 0x1_0001, "a fresh odd slot, the window's left");
            t.free(m);
            assert_eq!(
                window(&mut t, &pages),
                w + 0x1_0000,
                "the window's, not the menu's"
            );
            assert_eq!(other(&mut t, &pages), m + 0x1_0000, "the menu's");
            let mut odd = 0;
            while t.fresh[1] <= UserHandle::MAX_INDEX {
                other(&mut t, &pages);
                odd += 1;
            }
            assert_eq!(odd, 0x8000 - 1);
            assert_eq!(
                other(&mut t, &pages),
                0x1_0004,
                "an even slot once no odd is left"
            );
        }
    }

    /// A slot's count wraps from the codec's highest to 1, never 0 nor a wildcard.
    #[test]
    fn counts_wrap_to_1() {
        let pages = HostPages::new();
        let mut user = boxed(Slots::<Rec, UserHandle, 8, Inline<4>>::new());
        let h = user.allocate_or_grow(1, &pages).unwrap().0;
        user.force_uniq(h & 0xFFFF, 0xFFFE);
        let h = (h & 0xFFFF) | 0xFFFE_0000;
        assert!(user.get(h).is_some());
        assert!(user.free(h));
        assert_eq!(user.allocate(1).unwrap().0, (h & 0xFFFF) | 0x1_0000);
        assert!(user.get(h).is_none());

        let mut gdi = boxed(Slots::<Rec, GdiHandle, 8, Inline<4>>::new());
        let g = gdi.allocate_or_grow(0, &pages).unwrap().0;
        assert_eq!(g, 0x0100_0001);
        gdi.force_uniq(1, 0xFF);
        assert!(gdi.free(0xFF00_0001));
        assert_eq!(gdi.allocate(0).unwrap().0, 0x0100_0001);

        let mut kernel = boxed(Kernel::<8, 4>::new());
        let k = kernel.allocate_or_grow(0, &pages).unwrap().0;
        kernel.force_uniq(k.index as u32, 0xFFFE);
        assert!(kernel.free(Id::new(k.index, 0xFFFE)));
        assert_eq!(kernel.allocate(0).unwrap().0, Id::new(k.index, 1));
    }

    /// Every value decodes without a panic, whatever it names.
    #[test]
    fn forged_values_never_panic() {
        let pages = HostPages::new();
        let mut kernel = boxed(Kernel::<16, 4>::new());
        let mut nt = boxed(Slots::<Rec, NtHandle, 16, Inline<4>>::new());
        let mut user = boxed(Slots::<Rec, UserHandle, 16, Inline<4>>::new());
        let mut gdi = boxed(Slots::<Rec, GdiHandle, 16, Inline<4>>::new());
        let mut cid = boxed(Slots::<Rec, ClientId, 16, Inline<4>>::new());
        for _ in 0..20 {
            kernel.allocate_or_grow(0, &pages).unwrap();
            nt.allocate_or_grow(0, &pages).unwrap();
            user.allocate_or_grow(0, &pages).unwrap();
            gdi.allocate_or_grow(0, &pages).unwrap();
            cid.allocate_or_grow(0, &pages).unwrap();
        }
        let mut probe = |value: u32| {
            let _ = kernel.get(Id::new(value as u16, (value >> 16) as u16));
            let _ = kernel.get_mut(Id::new((value >> 16) as u16, value as u16));
            let _ = nt.get(value);
            let _ = user.get(value);
            let _ = gdi.get(value);
            let _ = cid.get(value);
            let _ = user.free(value ^ 0x8000_0000);
        };
        let edges = [
            0,
            4,
            0xFFFF,
            0xFFFF_0000,
            0xFFFF_FFFC,
            0xFFFF_FFFF,
            21 << 2,
            33 << 2,
            64 << 2,
        ];
        edges.into_iter().for_each(&mut probe);
        let mut x: u32 = 0x1234_5678;
        for _ in 0..if cfg!(miri) { 1 << 10 } else { 1 << 20 } {
            x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            probe(x);
        }
        assert!(nt.get(20 << 2).is_some());
        assert!(nt.get(21 << 2).is_none(), "an index never handed out");
        assert!(nt.get(64 << 2).is_none(), "an index in an unmade chunk");
    }

    /// A reserved slot is missed by lookups and skipped by allocations until filled; unreserved,
    /// it goes to the next allocation; drain and reset drop reservations.
    #[test]
    fn reservation() {
        let pages = HostPages::new();
        let mut t = boxed(Slots::<Rec, NtHandle, 8, Inline<4>>::new());
        let r = t.reserve_or_grow(0, &pages).unwrap();
        assert_eq!(r, 4);
        assert!(t.get(r).is_none());
        let (h, _) = t.allocate(0).unwrap();
        assert_eq!(h, 8, "the reserved slot skipped");
        assert!(!t.free(r), "a reservation is not live");
        t.fill(r).unwrap().value = 7;
        assert_eq!(t.get(r).unwrap().value, 7);
        assert!(t.fill(r).is_none(), "filled once");
        let r2 = t.reserve(0).unwrap();
        assert!(t.unreserve(r2));
        assert!(!t.unreserve(r2));
        assert_eq!(
            t.allocate(0).unwrap().0,
            r2,
            "Lifo: the unreserved slot next"
        );
        let r3 = t.reserve(0).unwrap();
        t.drain(|_, _| {});
        assert!(t.fill(r3).is_none() && t.live() == 0);
        let r4 = t.reserve(0).unwrap();
        // SAFETY: the chunks are `pages`', and nothing refers to them.
        unsafe { t.reset(&pages) };
        assert!(t.fill(r4).is_none());
        assert_eq!(pages.held(), 0);
    }

    /// Slots placed at scattered indices; once sealed, the gaps below the highest go first, the
    /// lowest first, then the slots above it.
    #[test]
    fn inheritance() {
        let pages = HostPages::new();
        let mut t = boxed(Slots::<Rec, NtHandle, 4, Inline<8>>::new());
        for index in [9, 2, 5] {
            let (h, rec) = t.place(index, &pages).unwrap();
            assert_eq!(h, index << 2);
            rec.value = index;
        }
        assert_eq!(
            t.place(0, &pages).err(),
            Some(Full::Limit),
            "handle 0 is reserved"
        );
        t.seal_placed();
        let next: Vec<_> = (0..7)
            .map(|_| t.allocate_or_grow(0, &pages).unwrap().0 >> 2)
            .collect();
        assert_eq!(next, [1, 3, 4, 6, 7, 8, 10]);
        assert_eq!(t.get(5 << 2).unwrap().value, 5);
    }

    /// The live slots, in index order across chunks; drain empties; reset gives back every page.
    #[test]
    fn iteration_drain_and_reset() {
        let pages = HostPages::new();
        let mut t = boxed(Kernel::<4, 8>::new());
        let ids: Vec<_> = (0..11)
            .map(|_| t.allocate_or_grow(0, &pages).unwrap().0)
            .collect();
        for i in [0, 5, 6, 10] {
            t.free(ids[i]);
        }
        let seen: Vec<_> = t.iter().map(|(id, rec)| (id.index, rec.index)).collect();
        let expected: Vec<_> = [1u16, 2, 3, 4, 7, 8, 9]
            .iter()
            .map(|&i| (i, i as u32))
            .collect();
        assert_eq!(seen, expected);
        for (id, rec) in t.iter_mut() {
            rec.value = id.index as u32 + 100;
        }
        let mut drained = Vec::new();
        t.drain(|id, rec| drained.push((id.index, rec.value)));
        assert_eq!(drained.len(), 7);
        assert!(drained.iter().all(|&(i, v)| v == i as u32 + 100));
        assert_eq!((t.live(), t.iter().count()), (0, 0));
        let (again, _) = t.allocate(0).unwrap();
        assert_eq!(
            (again.index, again.uniq),
            (0, 2),
            "a drained pool starts over, counts kept"
        );
        assert!(t.get(ids[1]).is_none(), "a drained id names nothing");
        assert_eq!(pages.held(), 3);
        // SAFETY: the chunks are `pages`', and nothing refers to them.
        unsafe { t.reset(&pages) };
        assert_eq!(pages.held(), 0);
        assert_eq!(t.allocate(0).err(), Some(Full::NoChunk));
    }

    /// `ensure` makes the chunk once; an un-ensured index has no record; racing ensures make one
    /// chunk, the losers' pages given back.
    #[test]
    fn side_table_ensure() {
        let pages = HostPages::new();
        let mut t = boxed(SideTable::<Rec, 4, Inline<8>>::new());
        assert!(t.get(5).is_none());
        t.ensure(5, &pages).unwrap();
        t.ensure(6, &pages).unwrap();
        assert_eq!(pages.held(), 1);
        assert_eq!(t.get(5).unwrap().index, 5);
        assert!(t.get(3).is_none() && t.get(9).is_none());
        t.get_mut(4).unwrap().value = 9;
        assert_eq!(t.get(4).unwrap().value, 9);
        assert_eq!(t.ensure(32, &pages), Err(Exhausted::Limit));
        pages.set_budget(0);
        assert_eq!(t.ensure(9, &pages), Err(Exhausted::NoPages));
        assert!(t.get(9).is_none());
    }

    #[test]
    fn side_table_ensure_races_make_one_chunk() {
        let pages = HostPages::new();
        let t = SideTable::<Rec, 4, Inline<8>>::new();
        std::thread::scope(|scope| {
            for i in 0..8 {
                let (t, pages) = (&t, &pages);
                scope.spawn(move || t.ensure(20 + i % 4, pages).unwrap());
            }
        });
        assert_eq!(pages.held(), 1);
        assert_eq!(t.get(22).unwrap().index, 22);
    }

    /// A chunk made outside the owner's lock and adopted in it; one not the next is given back.
    #[test]
    fn two_phase_growth() {
        let pages = HostPages::new();
        let mut t = boxed(Kernel::<4, 8>::new());
        assert!(t.needs_chunk(0));
        let chunk = Chunk::make(t.next_chunk(), &pages).unwrap();
        let stale = Chunk::make(t.next_chunk(), &pages).unwrap();
        t.adopt(chunk, &pages).unwrap();
        assert!(!t.needs_chunk(0));
        assert_eq!(pages.held(), 2);
        assert_eq!(t.adopt(stale, &pages), Err(Full::NoChunk));
        assert_eq!(pages.held(), 1, "the stale chunk given back");
        assert_eq!(t.allocate(0).unwrap().1.index, 0);
    }

    /// Each codec's shape.
    #[test]
    fn codecs() {
        assert_eq!(UserHandle::encode(3, 1), 0x0001_0003);
        assert_eq!(UserHandle::decode(0xFFFF_0003), Some((3, Match::Any)));
        assert_eq!(UserHandle::decode(0x0000_0003), Some((3, Match::Any)));
        assert_eq!(UserHandle::decode(0x0002_0003), Some((3, Match::Exact(2))));
        let kind = 0x0005_0000;
        assert_eq!(GdiHandle::encode(7, 0x12) | kind, 0x1205_0007);
        assert_eq!(
            GdiHandle::decode(0x1205_0007),
            Some((7, Match::Exact(0x12)))
        );
        assert_eq!(
            GdiHandle::decode(0x1205_0007 | GDI_STOCK),
            None,
            "a stock object's"
        );
        assert_eq!(
            NtHandle::decode(0x13),
            Some((4, Match::Any)),
            "tag bits ignored"
        );
        let pages = HostPages::new();
        let mut cid = boxed(Slots::<Rec, ClientId, 8, Inline<4>>::new());
        let a = cid.allocate_or_grow(0, &pages).unwrap().0;
        let b = cid.allocate(0).unwrap().0;
        assert_eq!((a, b), (12, 16), "0, 4 and 8 reserved");
        cid.free(a);
        cid.free(b);
        assert_eq!(cid.allocate(0).unwrap().0, 16, "Lifo");
        assert!(cid.get(12).is_none() && cid.get(16).is_some());
    }

    // --- The growable directory ---

    /// A directory of 4 entries a page, so a few hundred chunks reach height 5.
    type Four = Paged<4>;

    /// The directory pages a tree holding `chunks` has: at each level up to the highest chunk's
    /// height, one per distinct chunk / F^level.
    fn tree_pages<const F: usize>(chunks: &[u32]) -> usize {
        let Some(&high) = chunks.iter().max() else {
            return 0;
        };
        (1..=Paged::<F>::height(high))
            .map(|level| {
                let mut pages: Vec<u64> = chunks
                    .iter()
                    .map(|&chunk| chunk as u64 / Paged::<F>::span(level))
                    .collect();
                pages.sort_unstable();
                pages.dedup();
                pages.len()
            })
            .sum()
    }

    fn height<const F: usize>(dir: &Paged<F>) -> u32 {
        Paged::<F>::split(dir.root.load(Ordering::SeqCst)).1
    }

    /// The root is null until the first chunk, which is the root itself; each later chunk takes
    /// the directory pages `next_pages` says, the tree deepening at 1, 4, 16, 64 and 256 chunks;
    /// every record keeps its address; reset gives every page back.
    #[test]
    fn a_paged_pool_deepens_as_it_grows() {
        let pages = HostPages::new();
        let mut pool = boxed(Slots::<Rec, Small<0xFFFE, false>, 1, Four>::new());
        assert!(pool.chunks.root.load(Ordering::SeqCst).is_null());
        assert_eq!(pool.address(0), None);
        let mut records = Vec::new();
        for chunk in 0..300u32 {
            let need = Four::next_pages(chunk);
            assert_eq!(need, pool.chunks.missing_pages(chunk), "chunk {chunk}");
            let held = pages.held();
            let (id, rec) = pool.allocate_or_grow(0, &pages).unwrap();
            assert_eq!(id.index as u32, chunk);
            rec.value = chunk + 7;
            records.push(rec as *mut Rec);
            assert_eq!(pages.held(), held + 1 + need, "chunk {chunk}");
            if chunk == 0 {
                assert_eq!((height(&pool.chunks), pages.held()), (0, 1), "no page");
            }
        }
        let all: Vec<u32> = (0..300).collect();
        assert_eq!(pages.held(), 300 + tree_pages::<4>(&all));
        assert_eq!(height(&pool.chunks), 5);
        for (index, at) in records.into_iter().enumerate() {
            let index = index as u32;
            assert_eq!(pool.address(index).unwrap().as_ptr(), at);
            assert_eq!(pool.get(Id::new(index as u16, 1)).unwrap().value, index + 7);
        }
        assert_eq!(pool.address(300), None);
        assert_eq!(pool.address(5000), None, "past the tree's span");
        // SAFETY: the chunks are `pages`', and nothing refers to them.
        unsafe { pool.reset(&pages) };
        assert_eq!(pages.held(), 0);
        assert!(pool.chunks.root.load(Ordering::SeqCst).is_null());
        assert_eq!(pool.allocate(0).err(), Some(Full::NoChunk));
    }

    /// At full fan-out: past a page of chunk pointers (a second leaf) and past 65,535 indices, an
    /// NT handle table's records all resolve.
    #[test]
    #[cfg_attr(miri, ignore)]
    fn a_paged_pool_passes_a_leaf_and_the_u16_indices() {
        let pages = HostPages::new();
        let mut t = boxed(Slots::<Rec, NtHandle, 64>::new());
        let mut handles = Vec::new();
        while handles.len() < 70_000 {
            let (h, rec) = t.allocate_or_grow(0, &pages).unwrap();
            rec.value = h;
            handles.push(h);
        }
        let chunks = t.next_chunk();
        assert!(chunks as usize > FANOUT);
        assert_eq!(height(&t.chunks), 2);
        let all: Vec<u32> = (0..chunks).collect();
        assert_eq!(pages.held(), chunks as usize + tree_pages::<FANOUT>(&all));
        assert!(handles.iter().all(|&h| t.get(h).unwrap().value == h));
        assert_eq!(t.get(70_001 << 2).map(|r| r.index), None);
    }

    /// A grow whose chunk finds pages but a directory page does not leaves the pool as it was,
    /// whether it lacked a page of the chunk's path or a new root.
    #[test]
    fn a_failed_directory_page_leaves_the_pool_unchanged() {
        let pages = HostPages::with_budget(1);
        let mut pool = boxed(Slots::<Rec, Small<0xFFFE, false>, 1, Four>::new());
        pool.grow(&pages).unwrap();
        let first = pool.address(0);
        pages.set_budget(1);
        assert_eq!(
            pool.grow(&pages),
            Err(Full::NoChunk),
            "chunk 1 needs a leaf"
        );
        assert_eq!(
            (pages.held(), pool.next_chunk(), height(&pool.chunks)),
            (1, 1, 0)
        );
        assert_eq!(pool.address(0), first);
        pages.set_budget(2);
        pool.grow(&pages).unwrap();
        pages.set_budget(2);
        pool.grow(&pages).unwrap();
        pool.grow(&pages).unwrap();
        assert_eq!(
            (pages.held(), pool.next_chunk(), height(&pool.chunks)),
            (5, 4, 1)
        );
        pages.set_budget(2);
        assert_eq!(
            pool.grow(&pages),
            Err(Full::NoChunk),
            "chunk 4: root, leaf, chunk"
        );
        assert_eq!(
            (pages.held(), pool.next_chunk(), height(&pool.chunks)),
            (5, 4, 1)
        );
        assert_eq!(pages.held(), 5);
        assert!(Chunk::<Rec, 1, Four>::make(4, &pages).is_none());
        assert_eq!(pages.held(), 5, "a chunk that cannot be made holds nothing");
        pages.set_budget(3);
        pool.grow(&pages).unwrap();
        assert_eq!((pages.held(), height(&pool.chunks)), (8, 2));
        assert!((0..5).all(|index| pool.address(index).is_some()));
    }

    /// A chunk made outside the owner's lock carries its directory pages, so adopting takes none;
    /// a stale one gives back its chunk and its pages.
    #[test]
    fn two_phase_growth_carries_the_directory() {
        let pages = HostPages::new();
        let mut t = boxed(Slots::<Rec, Small<0xFFFE, false>, 1, Four>::new());
        for _ in 0..4 {
            let chunk = Chunk::make(t.next_chunk(), &pages).unwrap();
            t.adopt(chunk, &pages).unwrap();
        }
        let chunk = Chunk::make(t.next_chunk(), &pages).unwrap();
        let stale = Chunk::make(t.next_chunk(), &pages).unwrap();
        let held = pages.held();
        pages.set_budget(0);
        t.adopt(chunk, &pages).unwrap();
        assert_eq!(pages.held(), held, "adopting took no page");
        assert_eq!(height(&t.chunks), 2);
        assert_eq!(t.adopt(stale, &pages), Err(Full::NoChunk));
        assert_eq!(
            pages.held(),
            held - 3,
            "the stale chunk, its root and its leaf given back"
        );
        assert_eq!(
            t.address(4).map(|at| unsafe { (*at.as_ptr()).index }),
            Some(4)
        );
    }

    /// `ensure` in any order builds the same tree: a far index first makes a deep path at once,
    /// lower ones fill in beside it; an address leads back to its index; a foreign or shifted one
    /// to none.
    #[test]
    fn a_paged_side_table_fills_sparsely() {
        let pages = HostPages::new();
        let mut t = boxed(SideTable::<Rec, 2, Four>::new());
        assert_eq!(t.chunks.missing_pages(500), 5);
        t.ensure(1000, &pages).unwrap();
        assert_eq!((pages.held(), height(&t.chunks)), (6, 5));
        assert_eq!(
            (t.get(1000).unwrap().index, t.get(1001).unwrap().index),
            (1000, 1001)
        );
        assert!(t.get(999).is_none() && t.get(0).is_none());
        assert_eq!(t.chunks.missing_pages(0), 4);
        t.ensure(0, &pages).unwrap();
        assert_eq!(t.chunks.missing_pages(1), 0);
        t.ensure(3, &pages).unwrap();
        t.ensure(2, &pages).unwrap();
        assert_eq!(pages.held(), 3 + tree_pages::<4>(&[500, 0, 1]));
        t.get_mut(3).unwrap().value = 9;
        assert_eq!(t.get(3).unwrap().value, 9);
        for index in [0, 1, 2, 3, 1000, 1001] {
            let at = t.address(index).unwrap().as_ptr();
            // SAFETY: an address the table handed out.
            assert_eq!(unsafe { t.index_at(at) }, Some(index));
            assert_eq!(
                // SAFETY: as above.
                unsafe { SideTable::<Rec, 2, Four>::index_at_in(&t.chunks, at) },
                Some(index)
            );
            let shifted = at.cast::<u8>().wrapping_add(1).cast::<Rec>();
            // SAFETY: inside the table's chunk, so readable.
            assert_eq!(unsafe { t.index_at(shifted) }, None);
        }
        for index in [3, 7] {
            let foreign = Box::into_raw(Box::new(Entry {
                index,
                value: Rec { index, value: 0 },
            }));
            // SAFETY: derived from the whole entry, so its index is readable through it.
            let at = unsafe { addr_of_mut!((*foreign).value) };
            // SAFETY: as above.
            assert_eq!(unsafe { t.index_at(at) }, None, "not the table's");
            // SAFETY: made by `Box::into_raw` above.
            drop(unsafe { Box::from_raw(foreign) });
        }
        assert_eq!(
            SideTable::<Rec, 1, Four>::new().ensure(u32::MAX, &pages),
            Err(Exhausted::Limit)
        );
        let held = pages.held();
        pages.set_budget(1);
        assert_eq!(
            t.ensure(20, &pages),
            Err(Exhausted::NoPages),
            "a leaf and a chunk"
        );
        assert_eq!((pages.held(), t.chunks.missing_pages(10)), (held, 1));
    }

    /// Threads ensuring scattered indices at once, a far one deepening the tree under the others,
    /// make one chunk each and one page of each directory page; the losers give theirs back.
    #[test]
    fn paged_ensure_races_make_one_tree() {
        let rounds = if cfg!(miri) { 2 } else { 50 };
        for round in 0..rounds {
            let pages = HostPages::new();
            let t = SideTable::<Rec, 1, Four>::new();
            let sets: [&[u32]; 4] = [&[0, 300, 5], &[301, 1, 4000], &[4000, 6, 0], &[2, 302, 70]];
            std::thread::scope(|scope| {
                for thread in 0..8 {
                    let (t, pages) = (&t, &pages);
                    let set = sets[(thread + round) % 4];
                    scope.spawn(move || {
                        for &index in set {
                            t.ensure(index, pages).unwrap();
                        }
                    });
                }
            });
            let mut all: Vec<u32> = sets.concat();
            all.sort_unstable();
            all.dedup();
            assert_eq!(pages.held(), all.len() + tree_pages::<4>(&all));
            assert!(all
                .iter()
                .all(|&index| t.get(index).unwrap().index == index));
            // SAFETY: the table's pages are `pages`', and nothing refers to them.
            unsafe {
                t.chunks
                    .release(SideTable::<Rec, 1, Four>::CHUNK_PAGES, &pages)
            };
            assert_eq!(pages.held(), 0);
        }
    }

    /// Readers resolve through a directory kept apart from the pool, without borrowing it, while
    /// its owner grows it: every chunk they find is whole, and stays.
    #[test]
    fn readers_resolve_while_the_owner_grows() {
        const CHUNKS: u32 = if cfg!(miri) { 40 } else { 600 };
        type Pool<'d> = Slots<Rec, Small<0xFFFE, false>, 2, &'d Four>;
        let pages = HostPages::new();
        let dir = Four::EMPTY;
        let mut pool = Pool::on(&dir);
        let done = std::sync::atomic::AtomicBool::new(false);
        std::thread::scope(|scope| {
            for _ in 0..3 {
                let (dir, done) = (&dir, &done);
                scope.spawn(move || {
                    let mut seen = 0;
                    loop {
                        let finished = done.load(Ordering::Acquire);
                        let mut index = 0;
                        while let Some(at) = Pool::address_in(dir, index) {
                            // SAFETY: a published record, written before its publication and
                            // not changed since.
                            assert_eq!(unsafe { (*at.as_ptr()).index }, index);
                            index += 1;
                        }
                        assert!(index >= seen, "a published chunk stays");
                        seen = index;
                        if finished {
                            break;
                        }
                    }
                    assert_eq!(seen, CHUNKS * 2);
                });
            }
            for _ in 0..CHUNKS {
                pool.grow(&pages).unwrap();
            }
            done.store(true, Ordering::Release);
        });
        assert_eq!(
            pool.address(CHUNKS * 2 - 1),
            Pool::address_in(&dir, CHUNKS * 2 - 1)
        );
        // SAFETY: the chunks are `pages`', and the readers are gone.
        unsafe { pool.reset(&pages) };
        assert_eq!(pages.held(), 0);
    }
}
