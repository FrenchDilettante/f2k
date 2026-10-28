//! Fixed pools of records, reached by index: the dispatcher database's storage.
//!
//! A pool is an array built where it lives (by value a pool of threads would pass through the
//! caller's stack, which is smaller than it) and never moved again, so a record keeps its address
//! for the kernel's life: the context switch is handed thread records by address. Which records
//! hold a live object is not the pool's business: the object directory keeps that, in its headers.

use core::cell::UnsafeCell;

/// `N` records of `T`, indexed from zero. The records sit in a cell: the context switch and the
/// running thread's own code reach a record by its address while the pool is borrowed for reading.
#[repr(transparent)]
pub struct Pool<T, const N: usize> {
    records: UnsafeCell<[T; N]>,
}

impl<T, const N: usize> Pool<T, N> {
    /// Write a pool at `pool`, record `index` being `fresh(index)`, record by record.
    ///
    /// # Safety
    ///
    /// `pool` is valid for writes and aligned; its previous contents are overwritten, not dropped.
    pub unsafe fn write_empty(pool: *mut Self, fresh: impl Fn(u16) -> T) {
        assert!(N <= u16::MAX as usize, "a pool's indexes fit sixteen bits");
        // `UnsafeCell<[T; N]>` has the layout of `[T; N]`, which the pool's one field is.
        let records = pool as *mut T;
        for index in 0..N {
            // SAFETY: the caller's contract; `index` is inside the array the pool is.
            unsafe { records.add(index).write(fresh(index as u16)) };
        }
    }

    /// How many records the pool holds.
    pub const fn capacity(&self) -> usize {
        N
    }

    /// The record at `index`.
    pub fn get(&self, index: u16) -> &T {
        // SAFETY: the records are changed only through `&mut self` (or through an address handed
        // out by `address`, whose users run with the pool unborrowed), so a shared borrow of the
        // pool is a shared borrow of its records.
        unsafe { &(*self.records.get())[index as usize] }
    }

    /// The record at `index`, to change.
    pub fn get_mut(&mut self, index: u16) -> &mut T {
        &mut self.records.get_mut()[index as usize]
    }

    /// The address of the record at `index`: what the context switch is handed, and the running
    /// thread's code reaches its record through.
    pub fn address(&self, index: u16) -> *mut T {
        assert!((index as usize) < N, "a record index inside the pool");
        // SAFETY: `index` is inside the array (checked above).
        unsafe { (self.records.get() as *mut T).add(index as usize) }
    }

    /// The index of the record at `address`, none for an address that is not one of the pool's
    /// records. Reads nothing: the address is compared, never dereferenced.
    pub fn index_of(&self, address: *const T) -> Option<u16> {
        let base = self.records.get() as usize;
        let offset = (address as usize).checked_sub(base)?;
        let size = core::mem::size_of::<T>();
        let index = offset / size;
        (offset % size == 0 && index < N).then_some(index as u16)
    }

    /// The records with their indexes.
    pub fn iter(&self) -> impl Iterator<Item = (u16, &T)> {
        (0..N as u16).map(move |index| (index, self.get(index)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A pool built in place holds each record as its index made it, and keeps it where it is.
    #[test]
    fn a_pool_is_built_in_place_by_index() {
        let mut storage = Box::<Pool<(u16, u32), 5>>::new_uninit();
        // SAFETY: the box's storage is valid for writes and aligned.
        unsafe { Pool::write_empty(storage.as_mut_ptr(), |index| (index, 7)) };
        // SAFETY: every record was written above.
        let mut pool = unsafe { storage.assume_init() };
        assert_eq!(pool.capacity(), 5);
        assert_eq!(*pool.get(3), (3, 7));
        pool.get_mut(3).1 = 9;
        assert_eq!(pool.get(3).1, 9);
        assert!(core::ptr::eq(pool.address(3), pool.get(3)));
        assert_eq!(pool.index_of(pool.address(3)), Some(3));
        assert_eq!(pool.index_of(core::ptr::null()), None);
        let past = pool.address(4).wrapping_add(1);
        assert_eq!(pool.index_of(past), None, "past the last record");
        assert_eq!(pool.iter().map(|(index, _)| index).sum::<u16>(), 10);
    }
}
