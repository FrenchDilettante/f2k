//! What kernel32 holds on the process heap, and the handles it makes for itself, as owned values
//! that give back what they hold when dropped, as Windows 2000's kernel32 keeps its working buffers
//! on the process heap (RtlAllocateHeap, RtlFreeHeap): an array of a fixed length
//! ([`HeapArray`]), a vector of a fixed capacity ([`HeapVec`]), a string ntdll made there
//! ([`HeapString`]: an ANSI string's conversion, a DOS path's NT form) and a handle closed when
//! dropped ([`Owned`]).

use core::ops::{Deref, DerefMut};
use core::ptr::NonNull;

use crate::error::ERROR_NOT_ENOUGH_MEMORY;
use crate::nt::{self, AnsiString, UnicodeString};
use crate::ntcall::{self, NtStatus};

/// The process heap had no room for a block: ERROR_NOT_ENOUGH_MEMORY.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OutOfMemory;

impl OutOfMemory {
    /// The Win32 error a call that found no room sets.
    pub const fn error(self) -> u32 {
        ERROR_NOT_ENOUGH_MEMORY
    }
}

/// Values in a block on the process heap, as many as it was made with, freed when dropped.
pub struct HeapArray<T: Copy + Default> {
    block: NonNull<T>,
    length: usize,
}

// SAFETY: the array owns its block, as a `Box<[T]>` owns its own, and the process heap serves
// every thread of the process: a thread the array is handed to may use it and free it.
unsafe impl<T: Copy + Default + Send> Send for HeapArray<T> {}

impl<T: Copy + Default> HeapArray<T> {
    /// `length` default values; none when the heap has no room.
    pub fn new(length: usize) -> Result<HeapArray<T>, OutOfMemory> {
        let bytes = size_of::<T>()
            .checked_mul(length.max(1))
            .ok_or(OutOfMemory)?;
        let block = ntcall::allocate_heap(bytes).ok_or(OutOfMemory)?.cast::<T>();
        for at in 0..length {
            // SAFETY: the block holds `length` values, and the heap's blocks are 8-byte aligned,
            // aligned for any `T` kernel32 keeps there.
            unsafe { block.as_ptr().add(at).write(T::default()) };
        }
        Ok(HeapArray { block, length })
    }

    /// The parts, one after the other.
    pub fn joined(parts: &[&[T]]) -> Result<HeapArray<T>, OutOfMemory> {
        let mut array = HeapArray::new(parts.iter().map(|part| part.len()).sum())?;
        let mut at = 0;
        for part in parts {
            array[at..at + part.len()].copy_from_slice(part);
            at += part.len();
        }
        Ok(array)
    }

    /// The first `length` values kept, those past them left behind (none when it holds no more);
    /// the block stays whole until the array is dropped.
    pub fn truncate(&mut self, length: usize) {
        self.length = self.length.min(length);
    }
}

impl<T: Copy + Default> Deref for HeapArray<T> {
    type Target = [T];

    fn deref(&self) -> &[T] {
        // SAFETY: the block holds `length` initialized values (`new` wrote them, and `truncate`
        // only shortens), the array's own until it is dropped.
        unsafe { core::slice::from_raw_parts(self.block.as_ptr(), self.length) }
    }
}

impl<T: Copy + Default> DerefMut for HeapArray<T> {
    fn deref_mut(&mut self) -> &mut [T] {
        // SAFETY: as in `deref`, borrowed mutably through the array.
        unsafe { core::slice::from_raw_parts_mut(self.block.as_ptr(), self.length) }
    }
}

impl<T: Copy + Default> Drop for HeapArray<T> {
    fn drop(&mut self) {
        // SAFETY: the block `new` had from the process heap, which nothing uses past the array.
        unsafe { ntcall::free_heap(self.block.as_ptr().cast()) };
    }
}

/// Values in a block on the process heap of a capacity fixed when it is made (or when it grows,
/// into a new block), added at the end; freed when dropped. The block's room past the values
/// holds default values, so a service may write there ([`HeapVec::spare_mut`]) and the vector
/// take what it wrote ([`HeapVec::extend_written`]).
pub struct HeapVec<T: Copy + Default> {
    block: HeapArray<T>,
    length: usize,
}

impl<T: Copy + Default> HeapVec<T> {
    /// An empty vector of room for `capacity` values; none when the heap has no room.
    pub fn with_capacity(capacity: usize) -> Result<HeapVec<T>, OutOfMemory> {
        Ok(HeapVec {
            block: HeapArray::new(capacity)?,
            length: 0,
        })
    }

    /// The values it has room for.
    pub fn capacity(&self) -> usize {
        self.block.len()
    }

    /// `value` added at the end; the value back when the vector is full.
    pub fn try_push(&mut self, value: T) -> Result<(), T> {
        match self.block.get_mut(self.length) {
            Some(slot) => {
                *slot = value;
                self.length += 1;
                Ok(())
            }
            None => Err(value),
        }
    }

    /// `value` added at the end.
    ///
    /// # Panics
    ///
    /// When the vector is full: its owner sizes it for everything it adds, so running past its
    /// room is a bug, not an input error.
    pub fn push(&mut self, value: T) {
        if self.try_push(value).is_err() {
            panic!("HeapVec::push past its capacity");
        }
    }

    /// `values` added at the end.
    ///
    /// # Panics
    ///
    /// As [`HeapVec::push`], when they do not all fit.
    pub fn extend(&mut self, values: impl IntoIterator<Item = T>) {
        for value in values {
            self.push(value);
        }
    }

    /// The room past the values, for a service to write into.
    pub fn spare_mut(&mut self) -> &mut [T] {
        &mut self.block[self.length..]
    }

    /// The first `count` values of the room past the values (what a service wrote there through
    /// [`HeapVec::spare_mut`]) taken as the vector's.
    ///
    /// # Panics
    ///
    /// When `count` is past the room.
    pub fn extend_written(&mut self, count: usize) {
        assert!(
            count <= self.capacity() - self.length,
            "HeapVec::extend_written past its capacity"
        );
        self.length += count;
    }

    /// The values past the first `length` dropped (none when it holds no more).
    pub fn truncate(&mut self, length: usize) {
        if length < self.length {
            self.block[length..self.length].fill(T::default());
            self.length = length;
        }
    }

    /// The vector moved into a new block of room for `capacity` values, its values kept (a
    /// capacity below its length keeps its length's room); none, the vector as it was, when the
    /// heap has no room.
    pub fn grow(&mut self, capacity: usize) -> Result<(), OutOfMemory> {
        let mut block = HeapArray::new(capacity.max(self.length))?;
        block[..self.length].copy_from_slice(self);
        self.block = block;
        Ok(())
    }
}

impl<T: Copy + Default> Deref for HeapVec<T> {
    type Target = [T];

    fn deref(&self) -> &[T] {
        &self.block[..self.length]
    }
}

impl<T: Copy + Default> DerefMut for HeapVec<T> {
    fn deref_mut(&mut self) -> &mut [T] {
        &mut self.block[..self.length]
    }
}

/// A UNICODE_STRING whose buffer ntdll allocated on the process heap (an ANSI string's
/// conversion, a DOS path's NT form), freed (RtlFreeUnicodeString) when dropped.
pub struct HeapString(UnicodeString);

impl HeapString {
    /// An ANSI string converted through the ANSI code page onto the process heap, as Windows 2000's
    /// kernel32 converts an A call's string for a call that keeps it whole (ntdll's
    /// RtlInitAnsiString, then RtlAnsiStringToUnicodeString, its allocating form): the converting
    /// call's status when it fails (STATUS_INVALID_PARAMETER_2 for a string whose Unicode form is
    /// past a counted string's reach, STATUS_NO_MEMORY when the heap has no room).
    ///
    /// # Safety
    ///
    /// `text` is null (the empty string) or points at a NUL-terminated string (a bad pointer
    /// faults the caller, as on the platform).
    pub unsafe fn from_ansi(text: *const u8) -> Result<HeapString, NtStatus> {
        let mut ansi = AnsiString::empty();
        let mut wide = UnicodeString::empty();
        // SAFETY: ntdll's exports, over the caller's string and the structures above; the
        // conversion's buffer is new, on the process heap.
        let status = unsafe {
            nt::RtlInitAnsiString(&mut ansi, text);
            nt::RtlAnsiStringToUnicodeString(&mut wide, &ansi, 1)
        };
        if rtl::status::nt_success(status) {
            Ok(HeapString(wide))
        } else {
            Err(status)
        }
    }

    /// A string ntdll made on the process heap, taken over.
    ///
    /// # Safety
    ///
    /// `string`'s buffer is null or a block of the process heap that ntdll allocated for it,
    /// holding its length in bytes, aligned, and used by nothing else.
    pub unsafe fn adopt(string: UnicodeString) -> HeapString {
        HeapString(string)
    }

    /// The counted string, as the services take it.
    pub fn string(&self) -> &UnicodeString {
        &self.0
    }

    /// Its units.
    pub fn units(&self) -> &[u16] {
        // SAFETY: the buffer is the string's own block (`from_ansi`, `adopt`), holding its length,
        // aligned (the heap's blocks are), unchanged while the string is.
        unsafe { self.0.units() }
    }
}

impl Drop for HeapString {
    fn drop(&mut self) {
        // SAFETY: ntdll's export, over the string whose block it allocated on the process heap;
        // nothing uses the block past the string.
        unsafe { nt::RtlFreeUnicodeString(&mut self.0) };
    }
}

/// A handle kernel32 made for itself: closed (NtClose) when dropped, unless it is handed out.
pub struct Owned(pub u32);

impl Owned {
    /// The handle, for the caller to keep.
    pub fn into_raw(self) -> u32 {
        let handle = self.0;
        core::mem::forget(self);
        handle
    }
}

impl Drop for Owned {
    fn drop(&mut self) {
        let _ = ntcall::close(self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_array_holds_its_parts_and_shortens() {
        let mut array = HeapArray::joined(&[&[1u16, 2], &[], &[3]]).unwrap();
        assert_eq!(&*array, &[1, 2, 3]);
        array.truncate(2);
        assert_eq!(&*array, &[1, 2]);
        array.truncate(5);
        assert_eq!(&*array, &[1, 2]);
        assert_eq!(&*HeapArray::<u8>::new(0).unwrap(), &[] as &[u8]);
    }

    #[test]
    fn a_vector_refuses_values_past_its_capacity() {
        let mut vector = HeapVec::with_capacity(3).unwrap();
        vector.extend([7u32, 8]);
        assert_eq!(vector.try_push(9), Ok(()));
        assert_eq!(vector.try_push(10), Err(10));
        assert_eq!(&*vector, &[7, 8, 9]);
        vector.truncate(1);
        assert_eq!(&*vector, &[7]);
    }

    #[test]
    #[should_panic(expected = "past its capacity")]
    fn a_push_past_the_capacity_panics() {
        let mut vector = HeapVec::with_capacity(1).unwrap();
        vector.extend([1u16, 2]);
    }

    #[test]
    fn a_vector_takes_what_was_written_into_its_room() {
        let mut vector = HeapVec::with_capacity(4).unwrap();
        vector.push(1u16);
        vector.spare_mut()[..2].copy_from_slice(&[2, 3]);
        vector.extend_written(2);
        assert_eq!(&*vector, &[1, 2, 3]);
        assert_eq!(vector.spare_mut(), &[0]);
    }

    #[test]
    fn a_vector_grows_into_a_new_block_keeping_its_values() {
        let mut vector = HeapVec::with_capacity(2).unwrap();
        vector.extend([1u32, 2]);
        vector.grow(4).unwrap();
        assert_eq!(vector.capacity(), 4);
        vector.extend([3, 4]);
        assert_eq!(&*vector, &[1, 2, 3, 4]);
    }
}
