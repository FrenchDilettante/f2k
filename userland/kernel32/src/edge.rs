//! The caller's memory at kernel32's exports: rtl's edge values ([`Out`], [`OutBuf`], [`In`],
//! [`InBuf`], [`InStr`], [`InWStr`]), each made once, at the export, in one `unsafe` block whose
//! contract is the API's; and what kernel32 builds over them: the NLS calls' counted strings
//! ([`Counted`]: a count, or NUL-terminated for a negative one), a buffer a call hands a string
//! back into ([`Text`]: an A call's narrowed through the ANSI code page, a W call's as it is), a W
//! call's string as a slice ([`wide_units`]: borrowed where aligned, copied where not) or as the
//! counted string the services read in place ([`counted`]), an A call's string converted into a
//! buffer of kernel32's ([`ansi_into`]), and CreateProcess's environment block
//! ([`EnvironmentBlock`]: read through its final empty entry).
//!
//! The code below the exports is safe: it reaches the caller's memory through these values only,
//! where and in the order Windows 2000's kernel32 reaches it (making a value touches no memory),
//! and a pointer the caller cannot reach faults the caller there, as on the platform.

pub use rtl::edge::{caller_bytes, In, InBuf, InStr, InWStr, Out, OutBuf};

use crate::base::WideUnits;
use crate::heap::HeapArray;
use crate::nt::UnicodeString;
use crate::ntcall;

/// A caller's buffer for a string a call hands back, of the size the caller gave: an A call's
/// bytes (the units narrowed through the ANSI code page) or a W call's UTF-16 units as they are.
/// Code page 1252 is one byte a character, so both count the same characters.
pub enum Text<'a> {
    Ansi(OutBuf<'a, u8>),
    Wide(OutBuf<'a, u16>),
}

impl<'a> Text<'a> {
    /// The characters the buffer holds.
    pub fn len(&self) -> usize {
        match self {
            Text::Ansi(buffer) => buffer.len(),
            Text::Wide(buffer) => buffer.len(),
        }
    }

    /// Whether it holds none.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Whether the caller passed no buffer at all.
    pub fn is_null(&self) -> bool {
        match self {
            Text::Ansi(buffer) => buffer.is_null(),
            Text::Wide(buffer) => buffer.is_null(),
        }
    }

    /// Write `units` from character `at` on.
    ///
    /// # Panics
    ///
    /// When they run past the buffer: the callers check the room first.
    pub fn put_at(&mut self, at: usize, units: &[u16]) {
        match self {
            Text::Ansi(buffer) => ntcall::unicode_to_multi_byte(buffer, at, units),
            Text::Wide(buffer) => buffer.put_at(at, units),
        }
    }

    /// Write `units` from the buffer's start.
    ///
    /// # Panics
    ///
    /// As [`Text::put_at`].
    pub fn put(&mut self, units: &[u16]) {
        self.put_at(0, units)
    }

    /// Write `units` from the buffer's start, then the terminator.
    ///
    /// # Panics
    ///
    /// As [`Text::put_at`].
    pub fn put_terminated(&mut self, units: &[u16]) {
        self.put(units);
        self.put_unit(units.len(), 0);
    }

    /// Write one unit at character `at`.
    ///
    /// # Panics
    ///
    /// As [`Text::put_at`].
    pub fn put_unit(&mut self, at: usize, unit: u16) {
        self.put_at(at, &[unit])
    }

    /// The address of the buffer's character `at` (a file part's place in it).
    pub fn address(&self, at: usize) -> usize {
        match self {
            Text::Ansi(buffer) => buffer.address(at),
            Text::Wide(buffer) => buffer.address(at),
        }
    }
}

/// A caller's string as the NLS calls take one: a count of units, or a NUL-terminated string for a
/// negative count. The call judges the count first (some refuse a negative one but -1, or a null
/// string), then reads the string where its code reads it.
#[derive(Clone, Copy)]
pub struct Counted<'a, U> {
    at: *const U,
    count: i32,
    units: core::marker::PhantomData<&'a [U]>,
}

impl<'a, U: Copy + Default + PartialEq> Counted<'a, U> {
    /// The string of `count` units at `at` (at any alignment).
    ///
    /// # Safety
    ///
    /// For a negative count, `at` points at a NUL-terminated string; otherwise it holds `count`
    /// units; either readable for `'a` and unchanged meanwhile (or memory the caller cannot read,
    /// which faults the caller where the call reads it, as on the platform).
    pub unsafe fn new(at: *const U, count: i32) -> Self {
        Counted {
            at,
            count,
            units: core::marker::PhantomData,
        }
    }

    /// The count as the caller gave it.
    pub fn count(&self) -> i32 {
        self.count
    }

    /// Whether the caller passed no string at all.
    pub fn is_null(&self) -> bool {
        self.at.is_null()
    }

    /// The string's units: its count of them, or for a negative count those before its terminator
    /// (read to it), and the terminator too when it `counts`.
    pub fn units(&self, counts: bool) -> InBuf<'a, U> {
        let length = if self.count < 0 {
            // SAFETY: `new`'s contract: a NUL-terminated string for a negative count, read
            // unaligned to its terminator.
            (unsafe { rtl::cstr::len_until_nul(self.at) }) + usize::from(counts)
        } else {
            self.count as usize
        };
        // SAFETY: `new`'s contract: the units counted above are readable (the terminator too).
        unsafe { InBuf::new(self.at, length) }
    }
}

/// A caller's environment block (CreateProcess's lpEnvironment), at any address: entries each
/// NUL-terminated, an empty one last, of narrow or UTF-16 units; read through its final empty entry
/// where the call reads it.
#[derive(Clone, Copy)]
pub struct EnvironmentBlock<'a, U> {
    at: *const U,
    units: core::marker::PhantomData<&'a [U]>,
}

impl<'a, U: Copy + Default + PartialEq> EnvironmentBlock<'a, U> {
    /// The block at `at`.
    ///
    /// # Safety
    ///
    /// `at` points at an environment block readable for `'a` and unchanged meanwhile (or at memory
    /// the caller cannot read, which faults the caller where the call reads it, as on the
    /// platform).
    pub unsafe fn new(at: *const U) -> Self {
        EnvironmentBlock {
            at,
            units: core::marker::PhantomData,
        }
    }

    /// Its units through its final empty entry (an empty block's two NULs counted), read to it.
    pub fn units(&self) -> InBuf<'a, U> {
        // SAFETY: `new`'s contract: a block, its entries each read unaligned to their NUL, through
        // the empty one.
        let length = unsafe { crate::env::block_length(self.at) };
        // SAFETY: `new`'s contract: the units the scan read, unchanged for 'a.
        unsafe { InBuf::new(self.at, length) }
    }
}

/// A caller's UTF-16 string, its terminator left out, read to it: the caller's own units where its
/// pointer is aligned, a copy on the process heap where it is not (a Rust slice must be aligned;
/// an x86 program may hand an LPCWSTR at an odd address, which Windows reads like any other). None
/// only when that copy finds no room.
pub fn wide_units<'a>(string: &InWStr<'a>) -> Option<WideUnits<'a>> {
    wide_units_of(string.units())
}

/// A caller's `length` UTF-16 units, as [`wide_units`] reads a string: borrowed where aligned,
/// copied onto the process heap where not; none only when that copy finds no room.
pub fn wide_units_of(units: InBuf<'_, u16>) -> Option<WideUnits<'_>> {
    if let Some(units) = units.aligned() {
        return Some(WideUnits::Borrowed(units));
    }
    let mut copy = HeapArray::new(units.len()).ok()?;
    units.copy_to(&mut copy);
    Some(WideUnits::Copied(copy))
}

/// A UNICODE_STRING over a caller's NUL-terminated string, as RtlInitUnicodeString makes one: its
/// length to the terminator, its room the terminator's too (a string past the UNICODE_STRING's
/// limit stops at it: an assumption, unverified on the platform). The string stays where it is, at
/// any address: the services read it through the counted string.
pub fn counted(string: &InWStr<'_>) -> UnicodeString {
    const MOST_UNITS: usize = rtl::string::MAX_USTRING / 2 - 1;
    let units = string.len().min(MOST_UNITS);
    UnicodeString {
        length: (2 * units) as u16,
        maximum_length: (2 * units + 2) as u16,
        buffer: string.as_ptr().cast_mut(),
    }
}

/// An A call's narrow string converted into `buffer`, terminated, as Windows 2000's kernel32
/// converts one into a buffer of its own (the thread's static Unicode string, for a name): ntdll's
/// RtlInitAnsiString, then RtlAnsiStringToUnicodeString through the ANSI code page. Its length in
/// units; none when the buffer cannot hold it and its terminator (no string is the empty one).
pub fn ansi_into(string: Option<&InStr<'_>>, buffer: &mut [u16]) -> Option<usize> {
    ntcall::ansi_to_unicode(string, buffer).ok()
}
