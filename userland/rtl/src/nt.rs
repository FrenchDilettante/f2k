//! The NT structures the system services and the runtime library take, as NT 5.0 lays them out on
//! x86, one definition for every side: UNICODE_STRING and ANSI_STRING ([`UnicodeString`],
//! [`AnsiString`]), OBJECT_ATTRIBUTES ([`ObjectAttributes`]), CLIENT_ID ([`ClientId`]) and
//! IO_STATUS_BLOCK ([`IoStatusBlock`]).
//!
//! Their pointer-sized fields are generic, as [`crate::params::ProcessParameters`]' are: `u32` for
//! a 32-bit process's addresses read from anywhere (the kernel, which reads them from user memory
//! on any host, or another process's memory), a native pointer type in the DLLs' own code (the same
//! layout on their target, and host addresses in the host tests). The layout asserts hold for the
//! `u32` form, which is also [`Pod`].
//!
//! The structures the query and set services answer and take are in [`info`].

use core::mem::{offset_of, size_of};

use crate::pod::Pod;

pub mod info;

/// A UNICODE_STRING: its length and room in bytes, and its buffer (an address, or an offset in a
/// denormalized process parameters block; zero or null for none).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UnicodeString<P> {
    pub length: u16,
    pub maximum_length: u16,
    pub buffer: P,
}

/// An ANSI_STRING (STRING): its length and room in bytes, and its buffer.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AnsiString<P> {
    pub length: u16,
    pub maximum_length: u16,
    pub buffer: P,
}

/// An OBJECT_ATTRIBUTES: what names an object to the system services: the structure's length, the
/// directory the name is relative to (a handle; zero for the namespace's root), the name (a
/// UNICODE_STRING's address), the OBJ_* flags, and the security descriptor and quality of service.
///
/// Its three kinds of pointer-sized field each take a type: `P` the handle, `Name` the name's
/// pointer and `Security` the security pointers, all `P` unless given, so the DLLs can keep the
/// name a typed pointer (or a reference, which has a pointer's layout) and the kernel can read
/// all of them as `u32`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ObjectAttributes<P, Name = P, Security = P> {
    pub length: u32,
    pub root_directory: P,
    pub object_name: Name,
    pub attributes: u32,
    pub security_descriptor: Security,
    pub security_quality_of_service: Security,
}

/// A CLIENT_ID: a process's id and one of its threads' (zero for none).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ClientId<P> {
    pub unique_process: P,
    pub unique_thread: P,
}

/// An IO_STATUS_BLOCK: the status (in a union with a pointer, so the field is pointer-sized; the
/// NTSTATUS is its low dword) and the information (a count, or what an open did).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IoStatusBlock<P> {
    pub status: P,
    pub information: P,
}

impl UnicodeString<*mut u16> {
    /// The empty string, with no buffer: what a service that answers a string fills, or the
    /// probe that asks a value's length.
    pub const fn empty() -> Self {
        UnicodeString {
            length: 0,
            maximum_length: 0,
            buffer: core::ptr::null_mut(),
        }
    }

    /// A string over `units`, its length and room theirs; none past a counted string's reach
    /// ([`crate::string::MAX_USTRING`] bytes). The buffer is the slice's: a service reads it
    /// through the string and never writes it (one that writes gets a [`Self::with_room`]).
    pub fn from_units(units: &[u16]) -> Option<Self> {
        let length = Self::bytes(units.len())?;
        Some(UnicodeString {
            length,
            maximum_length: length,
            buffer: units.as_ptr().cast_mut(),
        })
    }

    /// A string over the first `length` units of `buffer`, its room the whole buffer (as much
    /// of it as a counted string reaches: [`crate::string::MAX_USTRING`] bytes), for a service
    /// that writes the string; none when the length is past the room.
    pub fn with_room(buffer: &mut [u16], length: usize) -> Option<Self> {
        let room = buffer.len().min(crate::string::MAX_USTRING / 2);
        if length > room {
            return None;
        }
        Some(UnicodeString {
            length: Self::bytes(length)?,
            maximum_length: Self::bytes(room)?,
            buffer: buffer.as_mut_ptr(),
        })
    }

    /// `units` UTF-16 units in bytes, as a counted string's length; none past its reach.
    fn bytes(units: usize) -> Option<u16> {
        u16::try_from(units.checked_mul(2)?)
            .ok()
            .filter(|&bytes| usize::from(bytes) <= crate::string::MAX_USTRING)
    }

    /// The string's units (none for a length under one unit).
    ///
    /// # Safety
    ///
    /// The buffer holds `length` bytes, aligned for `u16`, unchanged while the units are borrowed.
    pub unsafe fn units(&self) -> &[u16] {
        if self.length < 2 {
            return &[];
        }
        // SAFETY: the caller's contract.
        unsafe { core::slice::from_raw_parts(self.buffer, usize::from(self.length) / 2) }
    }
}

impl AnsiString<*mut u8> {
    /// The empty string, with no buffer: what a conversion that allocates fills.
    pub const fn empty() -> Self {
        AnsiString {
            length: 0,
            maximum_length: 0,
            buffer: core::ptr::null_mut(),
        }
    }

    /// The string's bytes.
    ///
    /// # Safety
    ///
    /// The buffer holds `length` bytes, unchanged while they are borrowed.
    pub unsafe fn bytes(&self) -> &[u8] {
        if self.length == 0 {
            return &[];
        }
        // SAFETY: the caller's contract.
        unsafe { core::slice::from_raw_parts(self.buffer, usize::from(self.length)) }
    }
}

// SAFETY: two u16s and a u32, 8 bytes without padding.
unsafe impl Pod for UnicodeString<u32> {}
// SAFETY: as above.
unsafe impl Pod for AnsiString<u32> {}
// SAFETY: six u32s.
unsafe impl Pod for ObjectAttributes<u32> {}
// SAFETY: two u32s.
unsafe impl Pod for ClientId<u32> {}
// SAFETY: two u32s.
unsafe impl Pod for IoStatusBlock<u32> {}

const _: () = {
    // NT 5.0's layouts, with 32-bit pointers on any host.
    assert!(size_of::<UnicodeString<u32>>() == 8);
    assert!(offset_of!(UnicodeString<u32>, maximum_length) == 2);
    assert!(offset_of!(UnicodeString<u32>, buffer) == 4);
    assert!(size_of::<AnsiString<u32>>() == 8);
    assert!(offset_of!(AnsiString<u32>, maximum_length) == 2);
    assert!(offset_of!(AnsiString<u32>, buffer) == 4);
    assert!(size_of::<ObjectAttributes<u32>>() == 24);
    assert!(offset_of!(ObjectAttributes<u32>, root_directory) == 4);
    assert!(offset_of!(ObjectAttributes<u32>, object_name) == 8);
    assert!(offset_of!(ObjectAttributes<u32>, attributes) == 12);
    assert!(offset_of!(ObjectAttributes<u32>, security_descriptor) == 16);
    assert!(offset_of!(ObjectAttributes<u32>, security_quality_of_service) == 20);
    assert!(size_of::<ClientId<u32>>() == 8);
    assert!(offset_of!(ClientId<u32>, unique_thread) == 4);
    assert!(size_of::<IoStatusBlock<u32>>() == 8);
    assert!(offset_of!(IoStatusBlock<u32>, information) == 4);
};

// The DLLs' native forms lay out as the 32-bit ones on their target.
#[cfg(target_arch = "x86")]
const _: () = {
    assert!(size_of::<UnicodeString<*mut u16>>() == 8);
    assert!(size_of::<AnsiString<*mut u8>>() == 8);
    assert!(size_of::<ObjectAttributes<u32, *const UnicodeString<*mut u16>, *const u8>>() == 24);
    assert!(size_of::<ClientId<usize>>() == 8);
    assert!(size_of::<IoStatusBlock<usize>>() == 8);
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::string::MAX_USTRING;

    #[test]
    fn a_string_over_units_counts_them_up_to_its_reach() {
        let units = [0x41u16; 3];
        let string = UnicodeString::from_units(&units).unwrap();
        assert_eq!((string.length, string.maximum_length), (6, 6));
        assert_eq!(string.buffer.cast_const(), units.as_ptr());
        let long = [0u16; MAX_USTRING / 2 + 1];
        assert!(UnicodeString::from_units(&long[..MAX_USTRING / 2]).is_some());
        assert!(UnicodeString::from_units(&long).is_none());
    }

    #[test]
    fn a_string_with_room_has_the_buffer_up_to_its_reach() {
        let mut buffer = [0u16; 8];
        let string = UnicodeString::with_room(&mut buffer, 3).unwrap();
        assert_eq!((string.length, string.maximum_length), (6, 16));
        assert!(UnicodeString::with_room(&mut buffer, 9).is_none());
        let mut long = [0u16; MAX_USTRING];
        let string = UnicodeString::with_room(&mut long, 0).unwrap();
        assert_eq!(usize::from(string.maximum_length), MAX_USTRING);
        assert!(UnicodeString::with_room(&mut long, MAX_USTRING / 2 + 1).is_none());
    }

    #[test]
    fn a_string_reads_its_units() {
        let mut text = [u16::from(b'a'), u16::from(b'b'), 0];
        let string = UnicodeString {
            length: 4,
            maximum_length: 6,
            buffer: text.as_mut_ptr(),
        };
        // SAFETY: the buffer holds the length.
        assert_eq!(unsafe { string.units() }, &text[..2]);
        // SAFETY: no units are read.
        assert!(unsafe { UnicodeString::empty().units() }.is_empty());
    }

    #[test]
    fn a_string_reads_its_bytes() {
        let mut text = *b"abc";
        let string = AnsiString {
            length: 2,
            maximum_length: 3,
            buffer: text.as_mut_ptr(),
        };
        // SAFETY: the buffer holds the length.
        assert_eq!(unsafe { string.bytes() }, b"ab");
    }

    #[test]
    fn the_32_bit_forms_are_their_bytes() {
        let attributes = ObjectAttributes::<u32> {
            length: 24,
            root_directory: 0x10,
            object_name: 0x2000,
            attributes: 0x40,
            security_descriptor: 0,
            security_quality_of_service: 0,
        };
        let bytes = attributes.as_bytes();
        assert_eq!(&bytes[4..12], &[0x10, 0, 0, 0, 0, 0x20, 0, 0]);
        assert_eq!(ObjectAttributes::<u32>::from_bytes(bytes), Some(attributes));
        assert_eq!(
            UnicodeString::<u32>::from_bytes(&[6, 0, 8, 0, 0, 0x10, 0, 0]),
            Some(UnicodeString {
                length: 6,
                maximum_length: 8,
                buffer: 0x1000
            })
        );
    }
}
