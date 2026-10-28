//! A vector of fixed capacity, for the code that has no allocator (the kernel, and the DLLs' code
//! that runs before their heap or must not take it): up to `N` values in an array of its own,
//! which the vector owns and slices.

use core::ops::{Deref, DerefMut};

/// Up to `N` values of `T`, kept in order in an array: the values past the length are defaults,
/// never read through the vector.
#[derive(Clone, Copy)]
pub struct ArrayVec<T: Copy + Default, const N: usize> {
    items: [T; N],
    length: usize,
}

impl<T: Copy + Default, const N: usize> ArrayVec<T, N> {
    /// An empty vector.
    pub fn new() -> Self {
        Self {
            items: [T::default(); N],
            length: 0,
        }
    }

    /// The values it holds.
    pub fn len(&self) -> usize {
        self.length
    }

    /// Whether it holds none.
    pub fn is_empty(&self) -> bool {
        self.length == 0
    }

    /// The most values it holds, `N`.
    pub const fn capacity(&self) -> usize {
        N
    }

    /// Whether it holds `N` values.
    pub fn is_full(&self) -> bool {
        self.length == N
    }

    /// `value` added at the end; the value back when the vector is full.
    pub fn try_push(&mut self, value: T) -> Result<(), T> {
        match self.items.get_mut(self.length) {
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
    /// When the vector is full.
    pub fn push(&mut self, value: T) {
        if self.try_push(value).is_err() {
            panic!("ArrayVec::push past its capacity");
        }
    }

    /// The last value, taken off; none when empty.
    pub fn pop(&mut self) -> Option<T> {
        self.length = self.length.checked_sub(1)?;
        Some(core::mem::take(&mut self.items[self.length]))
    }

    /// The values past the first `length` dropped (none when it holds no more).
    pub fn truncate(&mut self, length: usize) {
        if length < self.length {
            self.items[length..self.length].fill(T::default());
            self.length = length;
        }
    }

    /// Every value dropped.
    pub fn clear(&mut self) {
        self.truncate(0);
    }

    /// `values` added at the end, all of them, or none and the error when they do not fit.
    pub fn try_extend_from_slice(&mut self, values: &[T]) -> Result<(), CapacityError> {
        let end = self.length + values.len();
        let room = self.items.get_mut(self.length..end).ok_or(CapacityError)?;
        room.copy_from_slice(values);
        self.length = end;
        Ok(())
    }

    /// The values, as a slice.
    pub fn as_slice(&self) -> &[T] {
        &self.items[..self.length]
    }

    /// The values, as a writable slice.
    pub fn as_mut_slice(&mut self) -> &mut [T] {
        &mut self.items[..self.length]
    }
}

/// What [`ArrayVec::try_extend_from_slice`] answers when the values do not fit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapacityError;

impl<T: Copy + Default, const N: usize> Default for ArrayVec<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Copy + Default, const N: usize> Deref for ArrayVec<T, N> {
    type Target = [T];

    fn deref(&self) -> &[T] {
        self.as_slice()
    }
}

impl<T: Copy + Default, const N: usize> DerefMut for ArrayVec<T, N> {
    fn deref_mut(&mut self) -> &mut [T] {
        self.as_mut_slice()
    }
}

impl<T: Copy + Default + core::fmt::Debug, const N: usize> core::fmt::Debug for ArrayVec<T, N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_list().entries(self.as_slice()).finish()
    }
}

impl<T: Copy + Default + PartialEq, const N: usize, const M: usize> PartialEq<ArrayVec<T, M>>
    for ArrayVec<T, N>
{
    fn eq(&self, other: &ArrayVec<T, M>) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl<T: Copy + Default + Eq, const N: usize> Eq for ArrayVec<T, N> {}

impl<T: Copy + Default + PartialEq, const N: usize> PartialEq<[T]> for ArrayVec<T, N> {
    fn eq(&self, other: &[T]) -> bool {
        self.as_slice() == other
    }
}

impl<T: Copy + Default + PartialEq, const N: usize> PartialEq<&[T]> for ArrayVec<T, N> {
    fn eq(&self, other: &&[T]) -> bool {
        self.as_slice() == *other
    }
}

impl<T: Copy + Default + PartialEq, const N: usize, const M: usize> PartialEq<[T; M]>
    for ArrayVec<T, N>
{
    fn eq(&self, other: &[T; M]) -> bool {
        self.as_slice() == other
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_are_pushed_up_to_the_capacity() {
        let mut vec = ArrayVec::<u32, 3>::new();
        assert!(vec.is_empty());
        assert_eq!(vec.capacity(), 3);
        vec.push(1);
        assert_eq!(vec.try_push(2), Ok(()));
        vec.push(3);
        assert!(vec.is_full());
        assert_eq!(vec.try_push(4), Err(4));
        assert_eq!(vec.len(), 3);
        assert_eq!(vec, [1, 2, 3]);
        assert_eq!(vec.iter().sum::<u32>(), 6);
    }

    #[test]
    #[should_panic(expected = "past its capacity")]
    fn a_push_past_the_capacity_panics() {
        let mut vec = ArrayVec::<u8, 1>::new();
        vec.push(1);
        vec.push(2);
    }

    #[test]
    fn values_are_taken_off_the_end() {
        let mut vec = ArrayVec::<u8, 4>::new();
        vec.try_extend_from_slice(b"abc").unwrap();
        assert_eq!(vec.pop(), Some(b'c'));
        assert_eq!(vec, &b"ab"[..]);
        vec.truncate(5);
        assert_eq!(vec.len(), 2);
        vec.truncate(1);
        assert_eq!(vec, *b"a");
        vec.clear();
        assert_eq!(vec.pop(), None);
        assert!(vec.is_empty());
    }

    #[test]
    fn an_extension_fits_whole_or_not_at_all() {
        let mut vec = ArrayVec::<u16, 4>::new();
        vec.push(7);
        assert_eq!(vec.try_extend_from_slice(&[1, 2, 3, 4]), Err(CapacityError));
        assert_eq!(vec, [7]);
        assert_eq!(vec.try_extend_from_slice(&[1, 2, 3]), Ok(()));
        assert_eq!(vec, [7, 1, 2, 3]);
        assert_eq!(vec.try_extend_from_slice(&[]), Ok(()));
    }

    #[test]
    fn the_values_are_a_slice() {
        let mut vec = ArrayVec::<u8, 8>::default();
        vec.try_extend_from_slice(b"cab").unwrap();
        vec.sort();
        vec[0] = b'A';
        assert_eq!(vec.as_slice(), b"Abc");
        assert_eq!(vec.as_mut_slice().len(), 3);
        let mut other = ArrayVec::<u8, 3>::new();
        other.try_extend_from_slice(b"Abc").unwrap();
        assert_eq!(vec, other);
        assert_eq!(format!("{vec:?}"), "[65, 98, 99]");
    }
}
