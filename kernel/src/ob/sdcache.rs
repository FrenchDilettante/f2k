//! The object manager's shared security-descriptor cache: one copy of each distinct descriptor,
//! reference-counted, that every object carrying it shares.
//!
//! An object's record no longer holds a descriptor's bytes inline: it holds an [`SdRef`], a handle
//! to a cache entry, and the entry is pool-allocated with the descriptor's bytes at whatever
//! length they take — a descriptor past any fixed bound is stored as it is. Two objects whose
//! descriptors are equal, the per-type defaults above all, share one entry; an entry goes back to
//! the pool when its last reference goes.
//!
//! The cache is a fixed table of buckets, hashed over the descriptor's bytes: a bucket holds a
//! chain of entries, and the chain is walked comparing the full hash first and the bytes themselves
//! on a hash match, so two descriptors that hash alike but differ still get entries of their own.
//!
//! The table's state lives in a dispatch-level cell (see [`crate::level`]): reached with the
//! dispatch token, which no execution holds twice, so the table needs no lock of its own — the same
//! discipline the dispatcher database's state uses, and the one shape that is reachable both from
//! the object directory's lock (whose holder lends the APC token to raise further) and from plain
//! passive-level code through the level bridge. A handle's clone and drop take the token briefly
//! too, for the count alone.

use core::fmt;
use core::ops::Deref;
use core::ptr::NonNull;

use crate::cm;
#[cfg(target_arch = "x86")]
use crate::level::{Dispatch, LevelCell};
use crate::slots::{Pages, PAGE};

/// The buckets' count: a power of two, so a hash masks to its bucket.
const BUCKETS: usize = 256;

/// One cached descriptor: the chain link, its reference count, its full hash and length, then
/// its bytes (self-relative) at whatever length they take.
#[repr(C)]
struct Entry {
    next: Option<NonNull<Entry>>,
    refs: u32,
    hash: u32,
    len: u32,
}

impl Entry {
    /// # Safety
    ///
    /// `at` names a live entry: the chain holds live entries only, and a handle's reference keeps
    /// its entry alive.
    unsafe fn next(at: NonNull<Entry>) -> Option<NonNull<Entry>> {
        // SAFETY: the caller's contract; the field is read through a raw pointer, which no
        // reference to the entry aliases.
        unsafe { core::ptr::addr_of!((*at.as_ptr()).next).read() }
    }

    /// # Safety
    ///
    /// As [`Entry::next`], and the entry is being unlinked or chained, so the write is the
    /// table's own.
    unsafe fn set_next(at: NonNull<Entry>, next: Option<NonNull<Entry>>) {
        // SAFETY: as the caller's contract.
        unsafe { core::ptr::addr_of_mut!((*at.as_ptr()).next).write(next) }
    }

    /// # Safety
    ///
    /// As [`Entry::next`].
    unsafe fn refs(at: NonNull<Entry>) -> u32 {
        // SAFETY: as the caller's contract.
        unsafe { core::ptr::addr_of!((*at.as_ptr()).refs).read() }
    }

    /// # Safety
    ///
    /// As [`Entry::set_next`]: the count changes only with the cache reached, so the write is the
    /// table's own.
    unsafe fn set_refs(at: NonNull<Entry>, refs: u32) {
        // SAFETY: as the caller's contract.
        unsafe { core::ptr::addr_of_mut!((*at.as_ptr()).refs).write(refs) }
    }

    /// # Safety
    ///
    /// As [`Entry::next`].
    unsafe fn hash(at: NonNull<Entry>) -> u32 {
        // SAFETY: as the caller's contract.
        unsafe { core::ptr::addr_of!((*at.as_ptr()).hash).read() }
    }

    /// # Safety
    ///
    /// As [`Entry::set_next`]: written once, at the entry's insert.
    unsafe fn set_hash(at: NonNull<Entry>, hash: u32) {
        // SAFETY: as the caller's contract.
        unsafe { core::ptr::addr_of_mut!((*at.as_ptr()).hash).write(hash) }
    }

    /// # Safety
    ///
    /// As [`Entry::next`].
    unsafe fn len(at: NonNull<Entry>) -> u32 {
        // SAFETY: as the caller's contract.
        unsafe { core::ptr::addr_of!((*at.as_ptr()).len).read() }
    }

    /// # Safety
    ///
    /// As [`Entry::set_next`]: written once, at the entry's insert.
    unsafe fn set_len(at: NonNull<Entry>, len: u32) {
        // SAFETY: as the caller's contract.
        unsafe { core::ptr::addr_of_mut!((*at.as_ptr()).len).write(len) }
    }

    /// The entry's descriptor bytes, at the header's end.
    ///
    /// # Safety
    ///
    /// As [`Entry::next`]: the caller keeps the entry alive (a reference on it) for as long as it
    /// reads the bytes.
    unsafe fn bytes(at: NonNull<Entry>) -> *mut u8 {
        // SAFETY: the entry's allocation holds the header and then the bytes.
        unsafe { at.as_ptr().cast::<u8>().add(core::mem::size_of::<Entry>()) }
    }
}

/// Whether the entry at `at`'s descriptor bytes equal `bytes`: word for word, then the tail.
///
/// # Safety
///
/// As [`Entry::bytes`].
unsafe fn entry_bytes_eq(at: NonNull<Entry>, bytes: &[u8]) -> bool {
    // SAFETY: the caller's contract; the entry's allocation holds `bytes.len()` bytes past its
    // header.
    let entry = unsafe { Entry::bytes(at) };
    let (words, tail) = bytes.as_chunks::<8>();
    let mut offset = 0;
    for word in words {
        // SAFETY: the entry holds at least `offset + 8` bytes past its header.
        if unsafe { core::ptr::read_unaligned(entry.add(offset).cast::<u64>()) }
            != u64::from_le_bytes(*word)
        {
            return false;
        }
        offset += 8;
    }
    for (index, byte) in tail.iter().enumerate() {
        // SAFETY: the entry holds at least `offset + index + 1` bytes past its header.
        if unsafe { core::ptr::read(entry.add(offset + index)) } != *byte {
            return false;
        }
    }
    true
}

/// The cache's table: the buckets' chains, and how many entries they hold.
struct Cache {
    buckets: [Option<NonNull<Entry>>; BUCKETS],
    entries: usize,
}

// SAFETY: the cell hands its `&mut Cache` to the one execution holding the dispatch token, as every
// level cell does; the entries it names are pool pages, mapped in every address space and read by
// any thread, and their bytes are never rewritten after the insert.
unsafe impl Send for Cache {}

impl Cache {
    /// An empty table.
    const fn empty() -> Cache {
        Cache {
            buckets: [None; BUCKETS],
            entries: 0,
        }
    }

    /// Log `bytes` into the table: the entry holding them, a new reference on it, or a fresh entry
    /// chained at its bucket's head. None when the pages have no room for a new entry.
    fn log(&mut self, bytes: &[u8]) -> Option<SdRef> {
        let full = hash(bytes);
        let bucket = (full as usize) & (BUCKETS - 1);
        let mut at = self.buckets[bucket];
        while let Some(entry) = at {
            // SAFETY: the chain holds live entries only, and the walk holds no reference of its
            // own: the table is reached, so no other walk or count runs meanwhile.
            unsafe {
                if Entry::hash(entry) == full && entry_bytes_eq(entry, bytes) {
                    Entry::set_refs(entry, Entry::refs(entry) + 1);
                    return Some(SdRef(Some(entry)));
                }
                at = Entry::next(entry);
            }
        }
        let entry = alloc_entry(bytes)?;
        // SAFETY: the new entry is ours alone until it is chained, and the fields are written
        // whole.
        unsafe {
            Entry::set_next(entry, self.buckets[bucket]);
            Entry::set_refs(entry, 1);
            Entry::set_hash(entry, full);
            Entry::set_len(entry, bytes.len() as u32);
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), Entry::bytes(entry), bytes.len());
        }
        self.buckets[bucket] = Some(entry);
        self.entries += 1;
        Some(SdRef(Some(entry)))
    }

    /// Take the entry `at` out of its bucket.
    ///
    /// # Safety
    ///
    /// `at` is chained in the table.
    fn unlink(&mut self, at: NonNull<Entry>) {
        let bucket = (unsafe { Entry::hash(at) } as usize) & (BUCKETS - 1);
        // The link that points at `at`: the bucket's head, or the entry before it in the chain.
        let mut link = core::ptr::addr_of_mut!(self.buckets[bucket]);
        loop {
            // SAFETY: `link` names a link of the chain, and the chain holds live entries only.
            let entry = unsafe { *link }.expect("the entry is chained");
            if entry == at {
                // SAFETY: `entry` is live, and its `next` is read and the link rewritten through
                // raw pointers, which no reference aliases.
                unsafe { *link = Entry::next(entry) };
                self.entries -= 1;
                return;
            }
            // SAFETY: `entry` is live, so its `next` field is the chain's next link.
            link = unsafe { core::ptr::addr_of_mut!((*entry.as_ptr()).next) };
        }
    }
}

/// The kernel's cache, at the dispatch level: reached with the dispatch token, which no execution
/// holds twice, so the table needs no lock of its own.
#[cfg(target_arch = "x86")]
static CACHE: LevelCell<Dispatch, Cache> = LevelCell::new(Cache::empty());

/// Run `f` on the cache. On the target, through the bridge to the dispatch level; on the host, on
/// the calling thread's own cache (a host test thread runs alone, as the target's one processor
/// does).
#[cfg(target_arch = "x86")]
fn with<R>(f: impl FnOnce(&mut Cache) -> R) -> R {
    crate::level::raised::<Dispatch, _>(|dispatch| f(CACHE.get(dispatch)))
}

/// As the target's [`with`], on the host.
#[cfg(not(target_arch = "x86"))]
fn with<R>(f: impl FnOnce(&mut Cache) -> R) -> R {
    std::thread_local! {
        static CACHE: core::cell::RefCell<Cache> =
            const { core::cell::RefCell::new(Cache::empty()) };
    }
    CACHE.with(|cache| f(&mut cache.borrow_mut()))
}

/// Where the cache's entries and buffers come from: the kernel's pages.
#[cfg(not(test))]
fn pages() -> &'static impl Pages {
    &crate::slots::KERNEL_PAGES
}

/// As [`pages`], in the host tests: the test thread's own, so a test can spend them and count what
/// they hold.
#[cfg(test)]
fn pages() -> &'static crate::slots::HostPages {
    tests::pages()
}

/// The full hash of a descriptor's bytes: the sum of its dwords read unaligned, the tail bytes
/// zero-padded. Two descriptors that differ only in the order of their dwords hash alike — which
/// is what the bucket walk's byte compare is for.
fn hash(bytes: &[u8]) -> u32 {
    let mut sum = 0u32;
    let (dwords, tail) = bytes.as_chunks::<4>();
    for dword in dwords {
        sum = sum.wrapping_add(u32::from_le_bytes(*dword));
    }
    if !tail.is_empty() {
        let mut dword = [0u8; 4];
        dword[..tail.len()].copy_from_slice(tail);
        sum = sum.wrapping_add(u32::from_le_bytes(dword));
    }
    sum
}

/// An entry's whole size for `len` descriptor bytes, and the pages it takes.
fn entry_size(len: usize) -> usize {
    core::mem::size_of::<Entry>() + len
}

/// Allocate an entry for `bytes`, its pages zeroed; none when the pages have no room.
fn alloc_entry(bytes: &[u8]) -> Option<NonNull<Entry>> {
    let size = entry_size(bytes.len());
    let at = pages().take(size.div_ceil(PAGE).max(1))?;
    Some(at.cast())
}

/// Free the entry at `at`, of `len` descriptor bytes, back to the pages.
///
/// # Safety
///
/// `at` came from one `alloc_entry` of those bytes, is not given back since, and nothing refers to
/// the entry any more: its refcount reached zero.
unsafe fn free_entry(at: NonNull<Entry>) {
    let len = unsafe { Entry::len(at) } as usize;
    let size = entry_size(len);
    // SAFETY: the caller's contract.
    unsafe { pages().give(at.cast(), size.div_ceil(PAGE).max(1)) };
}

/// A shared security descriptor: a handle to a cache entry, reference-counted. Cloning takes a
/// reference, dropping releases one, and the last release frees the entry back to the pages — so
/// a handle copied out of the object directory keeps its entry alive for as long as it lives.
pub struct SdRef(Option<NonNull<Entry>>);

impl SdRef {
    /// No descriptor at all: an empty slice, which the access check reads as a denial in user
    /// mode (only a dead record and the pending slot's empty state hold it).
    pub const NONE: SdRef = SdRef(None);

    /// Whether it names no descriptor.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn is_none(&self) -> bool {
        self.0.is_none()
    }

    /// Whether it and `other` name the same entry.
    pub fn same(&self, other: &SdRef) -> bool {
        self.0 == other.0
    }

    /// The descriptor's bytes (self-relative), read through `f`: they are copied out of the
    /// entry into a fresh pool buffer first, so `f` gets a plain slice, and the copy needs no
    /// reach of the cache — the handle holds a reference, so the entry lives as long as the
    /// handle does. None when the pool has no room for the copy.
    pub fn with_bytes<R>(&self, f: impl FnOnce(&[u8]) -> R) -> Option<R> {
        match self.0 {
            None => Some(f(&[])),
            Some(at) => {
                // SAFETY: the handle's reference keeps the entry alive for the copy.
                let len = unsafe { Entry::len(at) } as usize;
                let mut buffer = PoolBuf::take(len)?;
                // SAFETY: the entry's allocation holds `len` bytes past its header, and the
                // buffer's block holds `len` of its own; both are ours alone for the copy.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        Entry::bytes(at),
                        AsMut::<[u8]>::as_mut(&mut buffer.block).as_mut_ptr(),
                        len,
                    );
                }
                Some(f(AsRef::as_ref(&buffer.block)))
            }
        }
    }
}

impl PartialEq for SdRef {
    fn eq(&self, other: &Self) -> bool {
        self.same(other)
    }
}

impl Eq for SdRef {}

impl Clone for SdRef {
    fn clone(&self) -> Self {
        match self.0 {
            None => SdRef::NONE,
            Some(at) => {
                with(|_| {
                    // SAFETY: the handle's reference keeps the entry alive.
                    unsafe { Entry::set_refs(at, Entry::refs(at) + 1) }
                });
                SdRef(Some(at))
            }
        }
    }
}

impl Drop for SdRef {
    fn drop(&mut self) {
        if let Some(at) = self.0.take() {
            with(|cache| {
                // SAFETY: the handle's reference is one of the entry's, so the count is nonzero.
                let refs = unsafe { Entry::refs(at) } - 1;
                if refs == 0 {
                    // SAFETY: the entry is chained, and nothing refers to it once freed.
                    unsafe {
                        cache.unlink(at);
                        free_entry(at);
                    }
                } else {
                    // SAFETY: as above.
                    unsafe { Entry::set_refs(at, refs) };
                }
            });
        }
    }
}

impl fmt::Debug for SdRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let len = self.with_bytes(|bytes| bytes.len()).unwrap_or(0);
        f.debug_tuple("SdRef").field(&len).finish()
    }
}

/// Log `bytes` into the cache: the entry holding them, with a new reference on it (inserting a
/// fresh entry when none holds them), as a handle. None when the pages have no room for a new
/// entry.
pub fn log(bytes: &[u8]) -> Option<SdRef> {
    with(|cache| cache.log(bytes))
}

/// Take another reference on `handle`'s entry, as a new handle to it: the clone of the handle.
#[cfg_attr(not(test), allow(dead_code))]
pub fn reference(handle: SdRef) -> SdRef {
    handle.clone()
}

/// Release `handle`'s reference, freeing the entry when it was the last: the drop of the handle.
#[cfg_attr(not(test), allow(dead_code))]
pub fn dereference(handle: SdRef) {
    drop(handle)
}

/// How many entries the cache holds (the host tests' own).
#[cfg(test)]
pub fn entries() -> usize {
    with(|cache| cache.entries)
}

/// The reference count of the entry `handle` names (the host tests' own).
#[cfg(test)]
pub fn refs(handle: &SdRef) -> u32 {
    with(|_| match handle.0 {
        None => 0,
        // SAFETY: the handle's reference keeps the entry alive.
        Some(at) => unsafe { Entry::refs(at) },
    })
}

/// A buffer of `len` bytes from the pool (the nonpaged pool on target, the host allocator in
/// host builds), zeroed, given back when dropped: the scratch a capture, a query's answer or a
/// merge's result is built in, at whatever length it takes.
pub struct PoolBuf {
    block: cm::Pages,
}

impl PoolBuf {
    /// A zeroed buffer of `len` bytes; none when the pool has no room.
    pub fn take(len: usize) -> Option<PoolBuf> {
        Some(PoolBuf {
            block: cm::allocate(len)?,
        })
    }

    /// The buffer's bytes.
    pub fn as_slice(&self) -> &[u8] {
        AsRef::as_ref(&self.block)
    }

    /// The buffer's bytes, to write.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        AsMut::as_mut(&mut self.block)
    }
}

impl Deref for PoolBuf {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl PartialEq for PoolBuf {
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl fmt::Debug for PoolBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PoolBuf")
            .field("len", &self.as_slice().len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    //! The cache's host tests, on the test thread's own pages: a hit shares the entry, a miss makes
    //! one, a hash collision is settled by the bytes, the count goes up and down and frees at zero,
    //! and a descriptor past any fixed bound is stored whole.

    use super::*;

    thread_local! {
        /// The pages this test thread's cache takes from.
        static PAGES: core::cell::Cell<&'static crate::slots::HostPages> =
            core::cell::Cell::new(&crate::slots::KERNEL_PAGES);
    }

    /// The pages the cache takes from, on this test thread.
    pub(super) fn pages() -> &'static crate::slots::HostPages {
        PAGES.with(core::cell::Cell::get)
    }

    /// From now on, this thread's cache takes from `count` pages only.
    fn budget(count: usize) {
        pages().set_budget(count);
    }

    /// A descriptor's bytes of `len`, all `fill`: distinct lengths give distinct descriptors.
    fn sd(len: usize, fill: u8) -> Vec<u8> {
        vec![fill; len]
    }

    /// A handle's descriptor bytes, copied out of its entry.
    fn bytes(handle: &SdRef) -> Vec<u8> {
        handle.with_bytes(|bytes| bytes.to_vec()).unwrap()
    }

    /// A fresh cache and fresh pages of this thread's own, for a test that counts entries or held
    /// pages: every take and give of the test then goes to the one pages instance.
    fn rig() {
        PAGES.with(|cell| {
            cell.set(Box::leak(Box::new(crate::slots::HostPages::with_budget(
                usize::MAX,
            ))))
        });
        fresh();
    }

    /// Empty the cache: every entry unlinked and its pages given back.
    fn fresh() {
        loop {
            let head = with(|cache| cache.buckets.iter().copied().find_map(|head| head));
            let Some(at) = head else { break };
            with(|cache| {
                // SAFETY: the entry is chained, and nothing refers to it once freed.
                unsafe {
                    cache.unlink(at);
                    free_entry(at);
                }
            });
        }
        assert_eq!(entries(), 0);
    }

    /// Logging the same bytes twice names one entry, with the count up: a hit shares, a miss makes.
    #[test]
    fn a_hit_shares_one_entry_and_a_miss_makes_one() {
        rig();
        let a = log(&sd(20, 1)).unwrap();
        assert_eq!(entries(), 1);
        assert_eq!(refs(&a), 1);
        let b = log(&sd(20, 1)).unwrap();
        assert_eq!(entries(), 1, "the same bytes log to the same entry");
        assert!(a.same(&b));
        assert_eq!(refs(&a), 2);
        assert_eq!(bytes(&a), sd(20, 1));

        let c = log(&sd(20, 2)).unwrap();
        assert_eq!(entries(), 2, "different bytes get their own entry");
        assert!(!a.same(&c));
        assert_eq!(refs(&c), 1);

        // A handle cloned out of the table takes a reference, and dropping it releases one.
        let d = a.clone();
        assert_eq!(refs(&a), 3);
        drop(d);
        assert_eq!(refs(&a), 2);
        drop(b);
        assert_eq!(refs(&a), 1);
        assert_eq!(entries(), 2, "the entry lives while a reference does");
        drop(a);
        drop(c);
        assert_eq!(entries(), 0);
    }

    /// Two descriptors that hash alike — their dwords in the other order — still get entries of
    /// their own: the full hash matches and the byte compare refuses.
    #[test]
    fn a_hash_collision_is_settled_by_the_bytes() {
        rig();
        // 0x01010101 + 0x02020202 and 0x02020202 + 0x01010101: the same sum, different bytes.
        let one = [1u8, 1, 1, 1, 2, 2, 2, 2];
        let other = [2u8, 2, 2, 2, 1, 1, 1, 1];
        assert_eq!(hash(&one), hash(&other), "the dword sum collides");
        assert_ne!(one, other);

        let a = log(&one).unwrap();
        let b = log(&other).unwrap();
        assert_eq!(entries(), 2, "the byte compare keeps them apart");
        assert!(!a.same(&b));
        assert_eq!(bytes(&a), one);
        assert_eq!(bytes(&b), other);
        // The same two again: still two entries, one hit each.
        assert!(log(&one).unwrap().same(&a));
        assert!(log(&other).unwrap().same(&b));
        assert_eq!(entries(), 2);
        drop(a);
        drop(b);
    }

    /// The last reference frees the entry back to the pages: the count reaches zero, the entry
    /// leaves the table, and its pages go back.
    #[test]
    fn the_last_reference_frees_the_entry_to_the_pages() {
        rig();
        let held_before = pages().held();
        let a = log(&sd(64, 7)).unwrap();
        let b = a.clone();
        let c = reference(a.clone());
        assert_eq!(refs(&a), 3);
        assert_eq!(entries(), 1);

        dereference(b);
        assert_eq!(refs(&a), 2);
        assert_eq!(entries(), 1, "not the last");
        let held = pages().held();
        assert!(held > held_before, "the entry holds pages");

        drop(c);
        assert_eq!(refs(&a), 1);
        dereference(a);
        assert_eq!(entries(), 0, "freed at zero");
        assert_eq!(pages().held(), held_before, "its pages went back");
    }

    /// A descriptor past any fixed bound is stored whole: a 300-byte one, and a 5 KiB one, both
    /// read back byte for byte.
    #[test]
    fn a_descriptor_past_256_bytes_is_stored_whole() {
        rig();
        for len in [257usize, 300, 5 * 1024 + 8] {
            let bytes_vec = sd(len, 0xAB);
            let a = log(&bytes_vec).unwrap();
            assert_eq!(bytes(&a), bytes_vec, "{len} bytes");
            assert_eq!(refs(&a), 1);
            // And it shares on a hit, at that length too.
            let b = log(&bytes_vec).unwrap();
            assert!(a.same(&b));
            assert_eq!(bytes(&a).len(), len);
            drop(a);
            drop(b);
        }
        assert_eq!(entries(), 0);
    }

    /// No room in the pages for a new entry: `log` gives none, and what is already cached still
    /// answers. An empty descriptor logs as an entry of its own (one byte).
    #[test]
    fn a_spent_pool_refuses_a_new_entry_only() {
        rig();
        let a = log(&sd(20, 3)).unwrap();
        budget(0);
        assert!(log(&sd(20, 4)).is_none(), "no pages for a new entry");
        let hit = log(&sd(20, 3)).unwrap();
        assert!(hit.same(&a), "a hit needs no pages");
        assert_eq!(entries(), 1);
        assert_eq!(refs(&a), 2, "the hit took a reference");
        drop(hit);
        budget(usize::MAX);
        drop(a);
        assert_eq!(entries(), 0);
    }

    /// The scratch buffer: zeroed at its length, writable through its slice, compared and
    /// debugged by its bytes, at whatever length it takes.
    #[test]
    fn a_pool_buffer_holds_its_bytes() {
        rig();
        let mut buf = PoolBuf::take(5000).unwrap();
        assert_eq!(buf.len(), 5000);
        assert!(buf.as_slice().iter().all(|&b| b == 0), "zeroed");
        buf.as_mut_slice()[4999] = 9;
        assert_eq!(buf[4999], 9);
        assert!(buf.as_slice()[..4].iter().all(|&b| b == 0));
        assert_eq!(format!("{:?}", buf), "PoolBuf { len: 5000 }");
        let same = PoolBuf::take(5000).unwrap();
        assert_ne!(buf, same, "one byte written apart");
        buf.as_mut_slice()[4999] = 0;
        assert_eq!(buf, same);
        assert!(PoolBuf::take(0).is_some(), "an empty buffer takes a block");
    }

    /// The empty handle names nothing, clones and drops as nothing, and reads as an empty slice.
    #[test]
    fn the_none_handle_is_inert() {
        rig();
        assert!(SdRef::NONE.is_none());
        assert_eq!(bytes(&SdRef::NONE), Vec::<u8>::new());
        assert_eq!(refs(&SdRef::NONE), 0);
        let clone = SdRef::NONE.clone();
        assert!(clone.is_none());
        assert!(SdRef::NONE.same(&clone));
        drop(clone);
        drop(SdRef::NONE);
        assert_eq!(entries(), 0);
        assert_eq!(format!("{:?}", SdRef::NONE), "SdRef(0)");
    }
}
