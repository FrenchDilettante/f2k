//! A caller's memory at a DLL export's edge: the pointers a program hands an export, each made
//! once, on entry, into a small value the code below reaches the memory through safely.
//!
//! - [`Out`]: one value the call writes (and reads, for an in-out one).
//! - [`OutBuf`]: a buffer of a known number of values the call writes.
//! - [`In`]: one value the call reads (a caller's structure).
//! - [`InBuf`]: a buffer of a known number of values the call reads.
//! - [`InStr`] and [`InWStr`]: NUL-terminated strings, narrow and UTF-16.
//!
//! An x86 program may pass any of these at any address: x86 tolerates a misaligned access and
//! Windows reads and writes such memory like any other. A Rust reference must be aligned, so these
//! are not references: every access through them is unaligned.
//!
//! Making one touches no memory. Each is made by one `unsafe` constructor whose contract is the
//! export's own (the caller's memory is what the API says it is); everything after it is safe. A
//! pointer the caller could not read or write faults where the call reaches it, in the caller's
//! thread, as Windows' own code does: making the values first, all at once, leaves where and in
//! which order the call touches the caller's memory as the code below has it.

use core::marker::PhantomData;
use core::mem::size_of;

use crate::pod::Pod;

/// A caller's out parameter: the place of a `T` it gave the address of, written (and read, for an
/// in-out one) unaligned.
pub struct Out<'a, T> {
    at: *mut T,
    place: PhantomData<&'a mut T>,
}

impl<'a, T: Copy> Out<'a, T> {
    /// The out parameter at `at`.
    ///
    /// # Safety
    ///
    /// `at` is the address (at any alignment) of a `T` the call may read and write for `'a`, which
    /// nothing else reaches meanwhile; or an address the caller cannot reach, which faults the
    /// caller when the call does, as on the platform.
    pub unsafe fn new(at: *mut T) -> Self {
        Out {
            at,
            place: PhantomData,
        }
    }

    /// The out parameter at `at`: none for null (an optional parameter not given).
    ///
    /// # Safety
    ///
    /// As [`Out::new`]'s, for a non-null `at`.
    pub unsafe fn optional(at: *mut T) -> Option<Self> {
        // SAFETY: the caller's contract, for the non-null address.
        (!at.is_null()).then(|| unsafe { Out::new(at) })
    }

    /// The value the place holds.
    pub fn get(&self) -> T {
        // SAFETY: `new`'s contract: a readable `T`, read unaligned.
        unsafe { self.at.read_unaligned() }
    }

    /// Write `value` to the place.
    pub fn set(&mut self, value: T) {
        // SAFETY: `new`'s contract: a writable `T`, written unaligned.
        unsafe { self.at.write_unaligned(value) }
    }

    /// The place's address, for a system service to write (the kernel probes it, and writes it
    /// unaligned as well).
    pub fn as_ptr(&mut self) -> *mut T {
        self.at
    }

    /// The place, lent for a shorter time.
    pub fn reborrow(&mut self) -> Out<'_, T> {
        Out {
            at: self.at,
            place: PhantomData,
        }
    }

    /// The `U` at byte `offset` of the place (a field of the caller's structure), lent for a
    /// shorter time.
    ///
    /// # Panics
    ///
    /// When the `U` runs past the place.
    pub fn part<U: Copy>(&mut self, offset: usize) -> Out<'_, U> {
        assert!(
            offset <= size_of::<T>() && size_of::<U>() <= size_of::<T>() - offset,
            "a part past the caller's place"
        );
        Out {
            at: self.at.cast::<u8>().wrapping_add(offset).cast(),
            place: PhantomData,
        }
    }
}

impl<'a, T> From<&'a mut T> for Out<'a, T> {
    /// A place of the code's own as an out parameter.
    fn from(place: &'a mut T) -> Self {
        Out {
            at: place,
            place: PhantomData,
        }
    }
}

/// A caller's buffer of `len` values of `T` the call writes, each written unaligned. Its writes
/// stay inside it: one past its length is a bug of the code below, and panics.
pub struct OutBuf<'a, T> {
    at: *mut T,
    len: usize,
    values: PhantomData<&'a mut [T]>,
}

impl<'a, T: Copy> OutBuf<'a, T> {
    /// The buffer of `len` values at `at`.
    ///
    /// # Safety
    ///
    /// `at` is the address (at any alignment) of `len` values of `T` the call may write for `'a`,
    /// which nothing else reaches meanwhile; or (for a call that writes none, or a caller whose
    /// buffer is bad) an address the caller cannot reach, which faults the caller when the call
    /// writes there, as on the platform.
    pub unsafe fn new(at: *mut T, len: usize) -> Self {
        OutBuf {
            at,
            len,
            values: PhantomData,
        }
    }

    /// The buffer of `len` values at `at`: none for null (an optional buffer not given).
    ///
    /// # Safety
    ///
    /// As [`OutBuf::new`]'s, for a non-null `at`.
    pub unsafe fn optional(at: *mut T, len: usize) -> Option<Self> {
        // SAFETY: the caller's contract, for the non-null address.
        (!at.is_null()).then(|| unsafe { OutBuf::new(at, len) })
    }

    /// The values it holds.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether it holds none.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Whether the caller passed no buffer at all.
    pub fn is_null(&self) -> bool {
        self.at.is_null()
    }

    /// Write `value` at `index`.
    ///
    /// # Panics
    ///
    /// When `index` is past the buffer.
    pub fn set(&mut self, index: usize, value: T) {
        assert!(index < self.len, "a write past the caller's buffer");
        // SAFETY: `new`'s contract: one of the buffer's values, written unaligned.
        unsafe { self.at.add(index).write_unaligned(value) }
    }

    /// Write `values` from `index` on.
    ///
    /// # Panics
    ///
    /// When they run past the buffer.
    pub fn put_at(&mut self, index: usize, values: &[T]) {
        assert!(
            index <= self.len && values.len() <= self.len - index,
            "a write past the caller's buffer"
        );
        for (at, &value) in values.iter().enumerate() {
            // SAFETY: `new`'s contract: inside the buffer (checked above), written unaligned.
            unsafe { self.at.add(index + at).write_unaligned(value) }
        }
    }

    /// Write `values` from the buffer's start.
    ///
    /// # Panics
    ///
    /// When they run past the buffer.
    pub fn put(&mut self, values: &[T]) {
        self.put_at(0, values)
    }

    /// The buffer's address, for a system service or ntdll to write (they are handed its length).
    pub fn as_mut_ptr(&mut self) -> *mut T {
        self.at
    }

    /// The address of value `index` (where an answer says the caller's buffer holds something).
    pub fn address(&self, index: usize) -> usize {
        self.at.wrapping_add(index) as usize
    }

    /// The buffer from value `from` on.
    ///
    /// # Panics
    ///
    /// When `from` is past the buffer.
    pub fn tail(self, from: usize) -> OutBuf<'a, T> {
        assert!(from <= self.len, "a part past the caller's buffer");
        OutBuf {
            at: self.at.wrapping_add(from),
            len: self.len - from,
            values: PhantomData,
        }
    }

    /// The first `len` values of the buffer (all of it when it holds fewer).
    pub fn head(self, len: usize) -> OutBuf<'a, T> {
        OutBuf {
            at: self.at,
            len: self.len.min(len),
            values: PhantomData,
        }
    }

    /// The buffer as values of `V` (a DWORD in a buffer of characters): as many as fit in its
    /// bytes.
    pub fn reinterpret<V: Copy>(self) -> OutBuf<'a, V> {
        OutBuf {
            at: self.at.cast(),
            len: self.len * size_of::<T>() / size_of::<V>(),
            values: PhantomData,
        }
    }

    /// The buffer, lent for a shorter time.
    pub fn reborrow(&mut self) -> OutBuf<'_, T> {
        OutBuf {
            at: self.at,
            len: self.len,
            values: PhantomData,
        }
    }
}

impl<'a, T> From<&'a mut [T]> for OutBuf<'a, T> {
    /// A buffer of the code's own as a caller's buffer (a call's work that fills its own).
    fn from(values: &'a mut [T]) -> Self {
        OutBuf {
            at: values.as_mut_ptr(),
            len: values.len(),
            values: PhantomData,
        }
    }
}

impl OutBuf<'_, u8> {
    /// Write `value`'s bytes at byte `offset` (a field of the caller's structure).
    ///
    /// # Panics
    ///
    /// When they run past the buffer.
    pub fn store<P: Pod>(&mut self, offset: usize, value: P) {
        self.put_at(offset, value.as_bytes())
    }
}

/// A caller's value the call reads, read unaligned (a structure it passes the address of).
pub struct In<'a, T> {
    at: *const T,
    value: PhantomData<&'a T>,
}

// A value only read: copies of it read the same memory, as copies of a `&T` do.
impl<T> Clone for In<'_, T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for In<'_, T> {}

impl<'a, T: Copy> In<'a, T> {
    /// The value at `at`.
    ///
    /// # Safety
    ///
    /// `at` is the address (at any alignment) of a `T` the call may read for `'a`, which nothing
    /// writes meanwhile; or an address the caller cannot read, which faults the caller when the
    /// call does, as on the platform.
    pub unsafe fn new(at: *const T) -> Self {
        In {
            at,
            value: PhantomData,
        }
    }

    /// The value at `at`: none for null (an optional parameter not given).
    ///
    /// # Safety
    ///
    /// As [`In::new`]'s, for a non-null `at`.
    pub unsafe fn optional(at: *const T) -> Option<Self> {
        // SAFETY: the caller's contract, for the non-null address.
        (!at.is_null()).then(|| unsafe { In::new(at) })
    }

    /// The value.
    pub fn read(&self) -> T {
        // SAFETY: `new`'s contract: a readable `T`, read unaligned.
        unsafe { self.at.read_unaligned() }
    }

    /// Its address, for a system service to read (the kernel probes it).
    pub fn as_ptr(&self) -> *const T {
        self.at
    }
}

/// A caller's buffer of `len` values of `T` the call reads, each read unaligned. Its reads stay
/// inside it: one past its length is a bug of the code below, and panics.
#[derive(Clone, Copy)]
pub struct InBuf<'a, T> {
    at: *const T,
    len: usize,
    values: PhantomData<&'a [T]>,
}

impl<'a, T: Copy> InBuf<'a, T> {
    /// The buffer of `len` values at `at`.
    ///
    /// # Safety
    ///
    /// `at` is the address (at any alignment) of `len` values of `T` the call may read for `'a`,
    /// which nothing writes meanwhile; or (for a call that reads none, or a caller whose buffer is
    /// bad) an address the caller cannot read, which faults the caller when the call reads there,
    /// as on the platform.
    pub unsafe fn new(at: *const T, len: usize) -> Self {
        InBuf {
            at,
            len,
            values: PhantomData,
        }
    }

    /// The values it holds.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether it holds none.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Value `index`.
    ///
    /// # Panics
    ///
    /// When `index` is past the buffer.
    pub fn get(&self, index: usize) -> T {
        assert!(index < self.len, "a read past the caller's buffer");
        // SAFETY: `new`'s contract: one of the buffer's values, read unaligned.
        unsafe { self.at.add(index).read_unaligned() }
    }

    /// The values, in order.
    pub fn iter(self) -> impl Iterator<Item = T> + 'a {
        (0..self.len).map(move |index| self.get(index))
    }

    /// The values copied into the start of `out`.
    ///
    /// # Panics
    ///
    /// When `out` is shorter than the buffer.
    pub fn copy_to(&self, out: &mut [T]) {
        for (slot, value) in out[..self.len].iter_mut().zip(self.iter()) {
            *slot = value;
        }
    }

    /// The values as a slice when their address is aligned for `T` (a slice cannot be otherwise);
    /// none when it is not.
    pub fn aligned(&self) -> Option<&'a [T]> {
        if self.len == 0 {
            return Some(&[]);
        }
        // SAFETY: `new`'s contract: `len` readable values, unchanged for 'a, at an aligned address
        // (checked).
        self.at
            .is_aligned()
            .then(|| unsafe { core::slice::from_raw_parts(self.at, self.len) })
    }

    /// The buffer's address, for a system service or ntdll to read (they are handed its length).
    pub fn as_ptr(&self) -> *const T {
        self.at
    }
}

impl<'a> InBuf<'a, u8> {
    /// The bytes, as a slice (bytes are aligned at any address).
    pub fn bytes(&self) -> &'a [u8] {
        self.aligned().expect("bytes are aligned anywhere")
    }
}

/// A caller's NUL-terminated narrow string, read up to its terminator where the call reads it.
#[derive(Clone, Copy)]
pub struct InStr<'a> {
    at: *const u8,
    bytes: PhantomData<&'a [u8]>,
}

impl<'a> InStr<'a> {
    /// The string at `at`.
    ///
    /// # Safety
    ///
    /// `at` points at a NUL-terminated string the call may read for `'a`, unchanged meanwhile; or
    /// at memory the caller cannot read, which faults the caller when the call reads it, as on the
    /// platform.
    pub unsafe fn new(at: *const u8) -> Self {
        InStr {
            at,
            bytes: PhantomData,
        }
    }

    /// The string at `at`: none for null (an optional string not given, or the empty one).
    ///
    /// # Safety
    ///
    /// As [`InStr::new`]'s, for a non-null `at`.
    pub unsafe fn optional(at: *const u8) -> Option<Self> {
        // SAFETY: the caller's contract, for the non-null address.
        (!at.is_null()).then(|| unsafe { InStr::new(at) })
    }

    /// The string's bytes, its terminator left out (read to it).
    pub fn bytes(&self) -> &'a [u8] {
        // SAFETY: `new`'s contract: a NUL-terminated string, unchanged for 'a.
        unsafe { crate::cstr::bytes_until_nul(self.at) }
    }

    /// The string's bytes, its terminator left out, when it ends within `most` bytes: read to its
    /// terminator, or to the byte past the `most`th (none: a string longer than that).
    pub fn bytes_within(&self, most: usize) -> Option<&'a [u8]> {
        // SAFETY: `new`'s contract: a NUL-terminated string, read a byte at a time up to its
        // terminator (or the bound before it).
        let length = (0..=most).find(|&at| unsafe { self.at.add(at).read() } == 0)?;
        // SAFETY: the `length` bytes before the terminator, read above, unchanged for 'a.
        Some(unsafe { core::slice::from_raw_parts(self.at, length) })
    }

    /// The string's bytes and its terminator.
    pub fn with_nul(&self) -> &'a [u8] {
        let length = self.bytes().len();
        // SAFETY: as in `bytes`: the string's bytes and the terminator after them.
        unsafe { core::slice::from_raw_parts(self.at, length + 1) }
    }

    /// Whether the string is empty (its first byte alone read).
    pub fn is_empty(&self) -> bool {
        // SAFETY: `new`'s contract: a string's first byte is readable.
        unsafe { self.at.read() == 0 }
    }

    /// The string's address, for ntdll to read (to its terminator).
    pub fn as_ptr(&self) -> *const u8 {
        self.at
    }
}

/// A caller's NUL-terminated UTF-16 string, at any address, read up to its terminator where the
/// call reads it.
#[derive(Clone, Copy)]
pub struct InWStr<'a> {
    at: *const u16,
    units: PhantomData<&'a [u16]>,
}

impl<'a> InWStr<'a> {
    /// The string at `at`.
    ///
    /// # Safety
    ///
    /// `at` (at any alignment) points at a NUL-terminated UTF-16 string the call may read for
    /// `'a`, unchanged meanwhile; or at memory the caller cannot read, which faults the caller when
    /// the call reads it, as on the platform.
    pub unsafe fn new(at: *const u16) -> Self {
        InWStr {
            at,
            units: PhantomData,
        }
    }

    /// The string at `at`: none for null (an optional string not given).
    ///
    /// # Safety
    ///
    /// As [`InWStr::new`]'s, for a non-null `at`.
    pub unsafe fn optional(at: *const u16) -> Option<Self> {
        // SAFETY: the caller's contract, for the non-null address.
        (!at.is_null()).then(|| unsafe { InWStr::new(at) })
    }

    /// The string's length in units, its terminator left out (read to it).
    pub fn len(&self) -> usize {
        // SAFETY: `new`'s contract: a NUL-terminated string, read unaligned to its terminator.
        unsafe { crate::cstr::len_until_nul(self.at) }
    }

    /// Whether the string is empty (its first unit alone read).
    pub fn is_empty(&self) -> bool {
        // SAFETY: `new`'s contract: a string's first unit is readable, read unaligned.
        unsafe { self.at.read_unaligned() == 0 }
    }

    /// The string's units, its terminator left out (read to it), as a buffer read unaligned.
    pub fn units(&self) -> InBuf<'a, u16> {
        // SAFETY: `new`'s contract: the `len` units before the terminator are readable, unchanged
        // for 'a.
        unsafe { InBuf::new(self.at, self.len()) }
    }

    /// The string's address, for ntdll or a system service to read (to its terminator, or through
    /// a counted string over it).
    pub fn as_ptr(&self) -> *const u16 {
        self.at
    }
}

/// The caller's buffer of `length` bytes at `at`, to read: none for a null address with a length
/// (a buffer the call cannot reach), the empty slice for no length.
///
/// # Safety
///
/// `at` is null, or holds `length` bytes the call may read for `'a`, which nothing writes
/// meanwhile.
pub unsafe fn caller_bytes<'a>(at: *const u8, length: usize) -> Option<&'a [u8]> {
    if length == 0 {
        return Some(&[]);
    }
    if at.is_null() {
        return None;
    }
    // SAFETY: the caller's contract: `length` readable bytes.
    Some(unsafe { core::slice::from_raw_parts(at, length) })
}

/// The caller's buffer of `length` bytes at `at`, to write: none for a null address with a length,
/// the empty slice for no length.
///
/// # Safety
///
/// `at` is null, or holds `length` bytes the call may read and write for `'a`, which nothing else
/// reaches meanwhile.
pub unsafe fn caller_bytes_mut<'a>(at: *mut u8, length: usize) -> Option<&'a mut [u8]> {
    if length == 0 {
        return Some(&mut []);
    }
    if at.is_null() {
        return None;
    }
    // SAFETY: the caller's contract: `length` writable bytes, ours for the call.
    Some(unsafe { core::slice::from_raw_parts_mut(at, length) })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Writes and reads go through any address, an odd one too.
    #[test]
    fn values_are_reached_unaligned() {
        let mut bytes = [0u8; 16];
        // SAFETY: four bytes of the array, at an odd address.
        let mut out = unsafe { Out::new(bytes[1..].as_mut_ptr().cast::<u32>()) };
        out.set(0x1122_3344);
        assert_eq!(out.get(), 0x1122_3344);
        assert_eq!(&bytes[1..5], &[0x44, 0x33, 0x22, 0x11]);
        // SAFETY: as above.
        let value = unsafe { In::new(bytes[1..].as_ptr().cast::<u32>()) };
        assert_eq!(value.read(), 0x1122_3344);
        // SAFETY: none given.
        assert!(unsafe { Out::<u32>::optional(core::ptr::null_mut()) }.is_none());
        let mut words = [0u8; 9];
        // SAFETY: four units of the array, at an odd address.
        let mut buffer = unsafe { OutBuf::new(words[1..].as_mut_ptr().cast::<u16>(), 4) };
        buffer.put(&[1, 2]);
        buffer.set(3, 4);
        assert_eq!(&words, &[0, 1, 0, 2, 0, 0, 0, 4, 0]);
        // SAFETY: the units written above.
        let read = unsafe { InBuf::new(words[1..].as_ptr().cast::<u16>(), 4) };
        assert!(read.aligned().is_none());
        assert_eq!(read.iter().collect::<std::vec::Vec<_>>(), [1, 2, 0, 4]);
    }

    #[test]
    #[should_panic(expected = "past the caller's buffer")]
    fn a_write_past_the_buffer_panics() {
        let mut units = [0u16; 2];
        // SAFETY: the two units above.
        let mut buffer = unsafe { OutBuf::new(units.as_mut_ptr(), 2) };
        buffer.put(&[1, 2, 3]);
    }

    /// A structure's field is reached through its part, at any address; the place lends itself
    /// again for a shorter time.
    #[test]
    fn a_place_lends_its_parts() {
        #[derive(Clone, Copy)]
        #[repr(C)]
        struct Pair {
            first: u32,
            second: u32,
        }
        let mut bytes = [0u8; 9];
        // SAFETY: a pair's eight bytes of the array, at an odd address.
        let mut pair = unsafe { Out::new(bytes[1..].as_mut_ptr().cast::<Pair>()) };
        pair.part::<u32>(4).set(0x0102_0304);
        pair.reborrow().part::<u32>(0).set(7);
        let read = pair.get();
        assert_eq!((read.first, read.second), (7, 0x0102_0304));
        let mut own = [0u16; 3];
        OutBuf::from(&mut own[..]).put(&[5, 6]);
        assert_eq!(own, [5, 6, 0]);
    }

    #[test]
    #[should_panic(expected = "past the caller's place")]
    fn a_part_past_the_place_panics() {
        let mut word = 0u32;
        Out::from(&mut word).part::<u32>(2);
    }

    /// Strings are read where the call reads them, to their terminator, at any address.
    #[test]
    fn strings_read_to_their_terminator() {
        // SAFETY: a terminated string.
        let narrow = unsafe { InStr::new(c"abc".as_ptr().cast()) };
        assert_eq!(
            (narrow.bytes(), narrow.with_nul()),
            (&b"abc"[..], &b"abc\0"[..])
        );
        let mut bytes = [0u8; 9];
        bytes[1..7].copy_from_slice(&[b'h', 0, b'i', 0, b'!', 0]);
        // SAFETY: a terminated UTF-16 string at an odd address (zeroed past its text).
        let wide = unsafe { InWStr::new(bytes[1..].as_ptr().cast::<u16>()) };
        assert_eq!(wide.len(), 3);
        assert!(!wide.is_empty());
        assert_eq!(
            wide.units().iter().collect::<std::vec::Vec<_>>(),
            [0x68, 0x69, 0x21]
        );
    }
}
