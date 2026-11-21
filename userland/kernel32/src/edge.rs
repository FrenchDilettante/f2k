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
use crate::error::{Failure, ERROR_NOT_ENOUGH_MEMORY};
use crate::heap::{HeapArray, HeapString};
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

/// A caller's NUL-terminated string, of an A call (bytes in the ANSI code page) or a W call (UTF-16
/// units). The call reads and converts it where its code does, in the way its A form does: what an
/// A/W pair genuinely does differently is a `match` on this at that place, the rest is one body.
#[derive(Clone, Copy)]
pub enum CallerStr<'a> {
    Ansi(InStr<'a>),
    Wide(InWStr<'a>),
}

impl<'a> CallerStr<'a> {
    /// Whether it holds no character (read to its terminator).
    pub fn is_empty(&self) -> bool {
        match self {
            CallerStr::Ansi(string) => string.is_empty(),
            CallerStr::Wide(string) => string.is_empty(),
        }
    }

    /// The string as UTF-16 units, its terminator left out, for a call that keeps it whole: a W
    /// call's where they are ([`wide_units`]: ERROR_NOT_ENOUGH_MEMORY when an unaligned string's
    /// copy finds no room); an A call's converted onto the process heap ([`HeapString::of_ansi`]:
    /// RtlInitAnsiString and RtlAnsiStringToUnicodeString, the status of a failed conversion: a
    /// string past a counted string's reach, or no room).
    pub fn units(&self) -> Result<CallerUnits<'a>, Failure> {
        match self {
            CallerStr::Wide(string) => wide_units(string)
                .map(CallerUnits::Wide)
                .ok_or(Failure::Error(ERROR_NOT_ENOUGH_MEMORY)),
            CallerStr::Ansi(string) => HeapString::of_ansi(Some(string))
                .map(CallerUnits::Ansi)
                .map_err(Failure::Status),
        }
    }
}

/// A caller's string as [`CallerStr::units`] reads it.
pub enum CallerUnits<'a> {
    Ansi(HeapString),
    Wide(WideUnits<'a>),
}

impl core::ops::Deref for CallerUnits<'_> {
    type Target = [u16];

    fn deref(&self) -> &[u16] {
        match self {
            CallerUnits::Ansi(string) => string.units(),
            CallerUnits::Wide(units) => units,
        }
    }
}

/// The character of an A/W pair's form: `u8` for the A export (its strings in the ANSI code page),
/// `u16` for the W export (UTF-16). A pair is one body generic over it and two one-line exports;
/// what this carries is all the body needs to tell them apart: the caller's strings
/// ([`CallerStr`]), the buffers it answers into ([`Text`]), and which of the pair's spec entries
/// (its stub log line) is this form's.
pub trait CallerChar: Copy + Default + PartialEq + 'static {
    /// Whether this is the W form's.
    const WIDE: bool;

    /// The caller's NUL-terminated string at `at`, made where the export makes its values (it
    /// reads nothing yet).
    ///
    /// # Safety
    ///
    /// As [`InStr::new`]'s or [`InWStr::new`]'s.
    unsafe fn string<'a>(at: *const Self) -> CallerStr<'a>;

    /// [`CallerChar::string`], none for a null pointer.
    ///
    /// # Safety
    ///
    /// As [`InStr::optional`]'s or [`InWStr::optional`]'s.
    unsafe fn optional_string<'a>(at: *const Self) -> Option<CallerStr<'a>> {
        // SAFETY: the caller's contract, for a pointer that is not null.
        (!at.is_null()).then(|| unsafe { Self::string(at) })
    }

    /// The caller's buffer for a string the call hands back, of this form's characters.
    fn text(buffer: OutBuf<'_, Self>) -> Text<'_>;

    /// Of the pair's A and W values (its spec entries), this form's.
    fn of<T>(ansi: T, wide: T) -> T {
        if Self::WIDE {
            wide
        } else {
            ansi
        }
    }
}

impl CallerChar for u8 {
    const WIDE: bool = false;

    unsafe fn string<'a>(at: *const u8) -> CallerStr<'a> {
        // SAFETY: the caller's contract.
        CallerStr::Ansi(unsafe { InStr::new(at) })
    }

    fn text(buffer: OutBuf<'_, u8>) -> Text<'_> {
        Text::Ansi(buffer)
    }
}

impl CallerChar for u16 {
    const WIDE: bool = true;

    unsafe fn string<'a>(at: *const u16) -> CallerStr<'a> {
        // SAFETY: the caller's contract.
        CallerStr::Wide(unsafe { InWStr::new(at) })
    }

    fn text(buffer: OutBuf<'_, u16>) -> Text<'_> {
        Text::Wide(buffer)
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

/// [`counted`] over a string the caller may not have passed: NULL is the empty string, as
/// RtlInitUnicodeString makes it from a null pointer (no length, no room, no buffer).
pub fn counted_optional(string: Option<&InWStr<'_>>) -> UnicodeString {
    string.map_or(UnicodeString::empty(), counted)
}

/// An A call's narrow string converted into `buffer`, terminated, as Windows 2000's kernel32
/// converts one into a buffer of its own (the thread's static Unicode string, for a name): ntdll's
/// RtlInitAnsiString, then RtlAnsiStringToUnicodeString through the ANSI code page. Its length in
/// units; none when the buffer cannot hold it and its terminator (no string is the empty one).
pub fn ansi_into(string: Option<&InStr<'_>>, buffer: &mut [u16]) -> Option<usize> {
    ntcall::ansi_to_unicode(string, buffer).ok()
}
