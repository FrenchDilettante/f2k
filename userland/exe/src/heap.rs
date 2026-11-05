//! Memory from the process heap: a buffer of a size known only at run time (a directory's entries,
//! as `dir` sorts them), freed when it is dropped. kernel32's HeapAlloc and HeapFree, imported by
//! name and wrapped once, safely.

use core::ops::{Deref, DerefMut};
use core::ptr::NonNull;

use crate::output::Error;

/// ERROR_NOT_ENOUGH_MEMORY: what a buffer the heap cannot give fails with.
const ERROR_NOT_ENOUGH_MEMORY: u32 = 8;

/// The alignment the process heap gives every block: 8 bytes, on x86.
const HEAP_ALIGNMENT: usize = 8;

#[link(
    name = "kernel32",
    kind = "raw-dylib",
    import_name_type = "undecorated"
)]
unsafe extern "system" {
    /// The process's default heap.
    fn GetProcessHeap() -> usize;
    /// A block of `bytes` from a heap: null when there is no room.
    fn HeapAlloc(heap: usize, flags: u32, bytes: usize) -> *mut u8;
    /// A block HeapAlloc gave back to its heap.
    fn HeapFree(heap: usize, flags: u32, block: *mut u8) -> i32;
}

/// `length` values of `T` on the process heap, each starting as a copy of the one given, freed
/// when the buffer is dropped. It reads and writes as a slice.
pub struct Buffer<T: Copy> {
    block: NonNull<T>,
    length: usize,
}

impl<T: Copy> Buffer<T> {
    /// `length` copies of `fill`: ERROR_NOT_ENOUGH_MEMORY when the heap has no room for them.
    pub fn new(length: usize, fill: T) -> Result<Self, Error> {
        const { assert!(align_of::<T>() <= HEAP_ALIGNMENT) };
        let bytes = length
            .max(1)
            .checked_mul(size_of::<T>().max(1))
            .ok_or(Error(ERROR_NOT_ENOUGH_MEMORY))?;
        // SAFETY: no pointers; the process heap's handle is valid while the process lives.
        let block = unsafe { HeapAlloc(GetProcessHeap(), 0, bytes) };
        let block = NonNull::new(block.cast::<T>()).ok_or(Error(ERROR_NOT_ENOUGH_MEMORY))?;
        for at in 0..length {
            // SAFETY: the block holds `length` values of T, aligned for T (the heap aligns every
            // block to 8 bytes, which T's alignment divides); each is written once, before any
            // read.
            unsafe { block.add(at).write(fill) };
        }
        Ok(Buffer { block, length })
    }
}

impl<T: Copy> Deref for Buffer<T> {
    type Target = [T];

    fn deref(&self) -> &[T] {
        // SAFETY: the block holds `length` initialized values of T, owned by this buffer and alive
        // while it lives; the borrow of `self` keeps them from being written meanwhile.
        unsafe { core::slice::from_raw_parts(self.block.as_ptr(), self.length) }
    }
}

impl<T: Copy> DerefMut for Buffer<T> {
    fn deref_mut(&mut self) -> &mut [T] {
        // SAFETY: as for `deref`, and the borrow of `self` is exclusive.
        unsafe { core::slice::from_raw_parts_mut(self.block.as_ptr(), self.length) }
    }
}

impl<T: Copy> Drop for Buffer<T> {
    fn drop(&mut self) {
        // SAFETY: the block is HeapAlloc's, from the process heap, and freed once, here; T is Copy,
        // so its values need no drop.
        unsafe { HeapFree(GetProcessHeap(), 0, self.block.as_ptr().cast()) };
    }
}
