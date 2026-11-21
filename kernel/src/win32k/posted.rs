//! The posted messages' pool: the entries the queues' posted and input messages live in
//! ([`super::queue`]), named by a u32 index, made a page at a time from the nonpaged pool as the
//! queues need them. Windows 2000 allocates each posted message from its pool as it is posted; what
//! bounds a queue is its own limit (USERPostMessageLimit, [`super::queue::POSTED_LIMIT`]), not a
//! table every queue shares, so a program that fills its queue leaves the others, and the
//! keyboard's input, room.
//!
//! A chunk is one page of entries; a directory, a block of its own, names the chunks, and doubles
//! when it is full (the chunks themselves never move). The pool keeps its peak: a chunk, once made,
//! stays, its entries going back on the free list (the slot-pool plan's rule, whose `Slots` this
//! pool's shape anticipates: chunks of pages found through a directory, an index naming an entry).
//! Only memory bounds it: a page the nonpaged pool has no room for fails the allocation.

use core::mem::{size_of, MaybeUninit};
use core::ptr::NonNull;

/// A chunk's bytes: a page.
const CHUNK_BYTES: usize = 4096;

/// The directory's first size, in chunks.
const FIRST_DIRECTORY: usize = 16;

/// No entry: the end of the free list.
const NONE: u32 = u32::MAX;

/// `bytes` bytes of zeroed memory, page-aligned: a block of the nonpaged pool, kept until
/// [`give`] (on the host, the allocator's); none when there is no room.
fn take(bytes: usize) -> Option<NonNull<u8>> {
    #[cfg(target_arch = "x86")]
    {
        let block = crate::mem::pool::allocate(bytes)?;
        let at = block.virtual_address();
        // The pool keeps the block's pages mapped until `give` releases them by their address.
        core::mem::forget(block);
        NonNull::new(at as usize as *mut u8)
    }
    #[cfg(not(target_arch = "x86"))]
    {
        let layout = std::alloc::Layout::from_size_align(bytes, CHUNK_BYTES).ok()?;
        // SAFETY: the layout's size is not zero (the callers ask for a page or more).
        NonNull::new(unsafe { std::alloc::alloc_zeroed(layout) })
    }
}

/// Give back the `bytes` bytes at `at` that [`take`] handed out.
///
/// # Safety
///
/// `at` and `bytes` are a [`take`]'s, given back once, and nothing refers to the memory after.
unsafe fn give(at: NonNull<u8>, bytes: usize) {
    #[cfg(target_arch = "x86")]
    {
        crate::mem::pool::release_block(at.as_ptr() as usize as u32, bytes);
    }
    #[cfg(not(target_arch = "x86"))]
    {
        let layout = std::alloc::Layout::from_size_align(bytes, CHUNK_BYTES).unwrap();
        // SAFETY: the caller's contract: `take`'s memory, of this layout.
        unsafe { std::alloc::dealloc(at.as_ptr(), layout) };
    }
}

/// An entry: its record while it is allocated, the next free entry of its chunk while it is not.
struct Slot<T> {
    value: MaybeUninit<T>,
    /// The next free entry of the chunk, by its place in the chunk; [`NONE`] for none.
    next_free: u32,
    live: bool,
}

/// A chunk's head, at the start of its page, its entries after it.
struct Head {
    /// The chunk's first free entry, by its place in the chunk; [`NONE`] for none.
    free: u32,
    /// How many of its entries are allocated.
    live: u32,
}

/// A pool of `T` records, each named by its index (see the module notes).
pub struct Pool<T: Copy> {
    /// The chunks' addresses, `capacity` of them, the first `made` made; null before the first.
    directory: *mut NonNull<Head>,
    capacity: usize,
    made: usize,
    /// No chunk below this one has a free entry.
    first_free: usize,
    live: u32,
    _records: core::marker::PhantomData<T>,
}

// SAFETY: the pool owns its directory and its chunks (nothing else points into them), and its
// records are `T`s, so moving it to another thread moves that ownership with it.
unsafe impl<T: Copy + Send> Send for Pool<T> {}

impl<T: Copy> Pool<T> {
    /// A pool with no chunk yet.
    pub const EMPTY: Self = Pool {
        directory: core::ptr::null_mut(),
        capacity: 0,
        made: 0,
        first_free: 0,
        live: 0,
        _records: core::marker::PhantomData,
    };
    /// A chunk's entries.
    const PER: usize = {
        let per = (CHUNK_BYTES - Self::SLOTS_AT) / size_of::<Slot<T>>();
        assert!(per > 0, "an entry larger than a page");
        per
    };
    /// Where a chunk's entries start: past its head, aligned for them.
    const SLOTS_AT: usize = size_of::<Head>().next_multiple_of(core::mem::align_of::<Slot<T>>());

    /// How many records are allocated.
    #[cfg(test)]
    pub fn live(&self) -> u32 {
        self.live
    }

    /// How many entries the chunks made hold, allocated or free.
    #[cfg(test)]
    pub fn entries(&self) -> usize {
        self.made * Self::PER
    }

    /// Chunk `chunk`'s head.
    fn head(&self, chunk: usize) -> *mut Head {
        assert!(chunk < self.made, "an index no chunk holds");
        // SAFETY: the directory holds `made` chunk addresses.
        unsafe { (*self.directory.add(chunk)).as_ptr() }
    }

    /// Entry `at` of chunk `chunk`.
    fn slot_in(&self, chunk: usize, at: usize) -> *mut Slot<T> {
        // SAFETY: a chunk is a page: its head, then `PER` entries from `SLOTS_AT`.
        unsafe {
            self.head(chunk)
                .cast::<u8>()
                .add(Self::SLOTS_AT)
                .cast::<Slot<T>>()
                .add(at)
        }
    }

    /// The entry `index` names.
    fn slot(&self, index: u32) -> *mut Slot<T> {
        self.slot_in(index as usize / Self::PER, index as usize % Self::PER)
    }

    /// `value` in a free entry, the lowest chunk with one first, the pool grown by a chunk when
    /// none has: its index; none when the memory for a chunk (or a larger directory) cannot be had.
    pub fn allocate(&mut self, value: T) -> Option<u32> {
        // SAFETY: the heads and entries are the pool's (see `head` and `slot_in`).
        unsafe {
            while self.first_free < self.made && (*self.head(self.first_free)).free == NONE {
                self.first_free += 1;
            }
            if self.first_free == self.made {
                self.grow()?;
            }
            let chunk = self.first_free;
            let head = self.head(chunk);
            let at = (*head).free as usize;
            let slot = self.slot_in(chunk, at);
            (*head).free = (*slot).next_free;
            (*head).live += 1;
            (*slot).value.write(value);
            (*slot).live = true;
            self.live += 1;
            Some((chunk * Self::PER + at) as u32)
        }
    }

    /// The record `index` names, allocated.
    pub fn get(&self, index: u32) -> &T {
        let slot = self.slot(index);
        // SAFETY: the entry is the pool's, and its chunk stays while it is allocated; its record
        // is written while it is, which the assertion checks.
        unsafe {
            assert!((*slot).live, "a free entry's record");
            (*slot).value.assume_init_ref()
        }
    }

    /// The record `index` names, allocated, to change.
    pub fn get_mut(&mut self, index: u32) -> &mut T {
        let slot = self.slot(index);
        // SAFETY: as in `get`; the exclusive borrow of the pool makes this the only reference.
        unsafe {
            assert!((*slot).live, "a free entry's record");
            (*slot).value.assume_init_mut()
        }
    }

    /// The entry `index` names given back; the last chunks, once they hold nothing, given back to
    /// the nonpaged pool with it, and the directory once no chunk is left, so that the pool holds
    /// no page once its records are gone (a process's posts leave nothing behind it).
    pub fn free(&mut self, index: u32) {
        let (chunk, at) = (index as usize / Self::PER, index as usize % Self::PER);
        let head = self.head(chunk);
        let slot = self.slot_in(chunk, at);
        // SAFETY: the head and the entry are the pool's; the record (a `T: Copy`) needs no drop.
        unsafe {
            assert!((*slot).live, "an entry freed twice");
            (*slot).live = false;
            (*slot).next_free = (*head).free;
            (*head).free = at as u32;
            (*head).live -= 1;
        }
        self.live -= 1;
        self.first_free = self.first_free.min(chunk);
        // SAFETY: as above; a chunk given back is past `made`, and no index names it any more.
        unsafe {
            while self.made > 0 && (*self.head(self.made - 1)).live == 0 {
                self.made -= 1;
                give((*self.directory.add(self.made)).cast(), CHUNK_BYTES);
            }
            if self.made == 0 && !self.directory.is_null() {
                give(
                    NonNull::new_unchecked(self.directory.cast()),
                    self.capacity * size_of::<NonNull<Head>>(),
                );
                self.directory = core::ptr::null_mut();
                self.capacity = 0;
            }
        }
        self.first_free = self.first_free.min(self.made);
    }

    /// One more chunk, its entries free (the lowest first), the directory doubled first when it is
    /// full; none when the memory cannot be had.
    fn grow(&mut self) -> Option<()> {
        // The indices stop short of a u32's last values: a representation limit, which memory
        // reaches long before.
        u32::try_from((self.made + 1) * Self::PER).ok()?;
        if self.made == self.capacity {
            let capacity = (self.capacity * 2).max(FIRST_DIRECTORY);
            let directory = take(capacity * size_of::<NonNull<Head>>())?
                .cast::<NonNull<Head>>()
                .as_ptr();
            if !self.directory.is_null() {
                // SAFETY: both directories are the pool's, the new one larger, and apart.
                unsafe {
                    core::ptr::copy_nonoverlapping(self.directory, directory, self.made);
                    give(
                        NonNull::new_unchecked(self.directory.cast()),
                        self.capacity * size_of::<NonNull<Head>>(),
                    );
                }
            }
            self.directory = directory;
            self.capacity = capacity;
        }
        let chunk = take(CHUNK_BYTES)?.cast::<Head>();
        // SAFETY: the page is the pool's alone: its head, then `PER` entries; the directory has
        // room for `made + 1` addresses.
        unsafe {
            chunk.as_ptr().write(Head { free: 0, live: 0 });
            let slots = chunk
                .as_ptr()
                .cast::<u8>()
                .add(Self::SLOTS_AT)
                .cast::<Slot<T>>();
            for at in 0..Self::PER {
                slots.add(at).write(Slot {
                    value: MaybeUninit::uninit(),
                    next_free: if at + 1 < Self::PER {
                        at as u32 + 1
                    } else {
                        NONE
                    },
                    live: false,
                });
            }
            self.directory.add(self.made).write(chunk);
        }
        self.made += 1;
        Some(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Records go in and come back by their index, past the first chunk and the first directory;
    /// a freed entry is handed out again (its chunk's last freed first); the last chunks go once
    /// they hold nothing, and everything once the pool does.
    #[test]
    fn records_come_back_by_their_index() {
        let mut pool = Pool::<[u32; 7]>::EMPTY;
        let per = Pool::<[u32; 7]>::PER;
        let count = per * (FIRST_DIRECTORY + 3);
        let indexes: std::vec::Vec<u32> = (0..count as u32)
            .map(|n| pool.allocate([n; 7]).unwrap())
            .collect();
        assert_eq!(pool.live(), count as u32);
        for (n, &index) in indexes.iter().enumerate() {
            assert_eq!(*pool.get(index), [n as u32; 7]);
        }
        pool.free(indexes[5]);
        assert_eq!(pool.allocate([2; 7]), Some(indexes[5]));
        pool.get_mut(indexes[5])[0] = 9;
        assert_eq!(pool.get(indexes[5])[..2], [9, 2]);
        // The last chunk emptied goes; an emptied chunk below a held one stays.
        for &index in &indexes[count - per..] {
            pool.free(index);
        }
        assert_eq!(pool.entries(), count - per);
        for &index in &indexes[count - 3 * per..count - 2 * per] {
            pool.free(index);
        }
        assert_eq!(pool.entries(), count - per);
        let again = pool.allocate([3; 7]).unwrap();
        assert_eq!(
            again as usize / per,
            (count - 3 * per) / per,
            "the lowest chunk with a free entry"
        );
        pool.free(again);
        for &index in &indexes[..count - 3 * per] {
            pool.free(index);
        }
        assert_eq!(
            pool.entries(),
            count - per,
            "a held chunk keeps those below"
        );
        for &index in &indexes[count - 2 * per..count - per] {
            pool.free(index);
        }
        assert_eq!((pool.live(), pool.entries()), (0, 0));
        assert!(pool.directory.is_null());
        assert_eq!(pool.allocate([4; 7]), Some(0));
    }

    /// A freed entry's record is not there to read.
    #[test]
    #[should_panic(expected = "a free entry's record")]
    fn a_free_entry_is_not_read() {
        let mut pool = Pool::<u32>::EMPTY;
        let index = pool.allocate(3).unwrap();
        pool.allocate(4).unwrap();
        pool.free(index);
        pool.get(index);
    }
}
