//! The exports' edge: a caller's string read once, where an export takes it, into a slice that the
//! code below the export works on safely.
//!
//! A narrow string is its bytes (`rtl::cstr::bytes_until_nul`, or [`bytes_bounded`] for a count's
//! worth). A wide string is a slice of [`WideUnit`]s, each UTF-16 unit as the two bytes it lies in:
//! a caller may hand a wide string at any address (an x86 program may pass an LPCWSTR at an odd
//! one, which Windows reads like any other), where a `&[u16]` could not be formed.

/// A UTF-16 unit of a caller's string, as it lies in memory: two bytes, at any address.
#[repr(transparent)]
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub struct WideUnit([u8; 2]);

impl WideUnit {
    pub const fn new(unit: u16) -> WideUnit {
        WideUnit(unit.to_ne_bytes())
    }

    pub const fn get(self) -> u16 {
        u16::from_ne_bytes(self.0)
    }
}

/// A wide string's units, as `u16`s.
pub fn units(
    string: &[WideUnit],
) -> impl DoubleEndedIterator<Item = u16> + ExactSizeIterator + Clone + '_ {
    string.iter().map(|unit| unit.get())
}

/// The bytes of the string at `string` up to its NUL (left out) or `max` bytes, whichever comes
/// first.
///
/// # Safety
///
/// `string` is readable to its NUL or for `max` bytes, and unchanged while the bytes are borrowed.
pub unsafe fn bytes_bounded<'a>(string: *const u8, max: usize) -> &'a [u8] {
    let mut length = 0;
    // SAFETY: the caller's string, read up to its NUL or `max` bytes.
    while length < max && unsafe { string.add(length).read() } != 0 {
        length += 1;
    }
    if length == 0 {
        return &[];
    }
    // SAFETY: the `length` bytes read above.
    unsafe { core::slice::from_raw_parts(string, length) }
}

/// The units of the wide string at `string`, its NUL left out.
///
/// # Safety
///
/// `string` points at a NUL-terminated UTF-16 string (at any address), readable to its NUL and
/// unchanged while the units are borrowed.
pub unsafe fn wide<'a>(string: *const u16) -> &'a [WideUnit] {
    // SAFETY: the caller's contract.
    let length = unsafe { rtl::cstr::len_until_nul(string) };
    // SAFETY: the caller's contract: the `length` units before the NUL, as their bytes.
    unsafe { wide_parts(string, length) }
}

/// The units of the wide string at `string` up to its NUL (left out) or `max` units, whichever
/// comes first.
///
/// # Safety
///
/// `string` is readable (at any address) to its NUL or for `max` units, and unchanged while the
/// units are borrowed.
pub unsafe fn wide_bounded<'a>(string: *const u16, max: usize) -> &'a [WideUnit] {
    let mut length = 0;
    // SAFETY: the caller's string, read up to its NUL or `max` units, unaligned.
    while length < max && unsafe { string.add(length).read_unaligned() } != 0 {
        length += 1;
    }
    // SAFETY: the `length` units read above.
    unsafe { wide_parts(string, length) }
}

/// `length` units at `string`, as a slice.
///
/// # Safety
///
/// The `length` units at `string` are readable and unchanged while borrowed.
pub unsafe fn wide_parts<'a>(string: *const u16, length: usize) -> &'a [WideUnit] {
    if length == 0 {
        return &[];
    }
    // SAFETY: the caller's units, as their bytes (WideUnit's alignment is one).
    unsafe { core::slice::from_raw_parts(string.cast::<WideUnit>(), length) }
}

/// `length` units at `string`, as a slice to change.
///
/// # Safety
///
/// The `length` units at `string` are writable, and the caller's alone while borrowed.
pub unsafe fn wide_parts_mut<'a>(string: *mut u16, length: usize) -> &'a mut [WideUnit] {
    if length == 0 {
        return &mut [];
    }
    // SAFETY: the caller's units, as their bytes (WideUnit's alignment is one).
    unsafe { core::slice::from_raw_parts_mut(string.cast::<WideUnit>(), length) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_wide_string_is_read_at_any_address() {
        let bytes = *b"\0a\0b\0\0\0";
        // SAFETY: "ab" as UTF-16 at an odd address, terminated.
        let string = unsafe { wide(bytes[1..].as_ptr().cast::<u16>()) };
        assert_eq!(units(string).collect::<Vec<_>>(), [0x61, 0x62]);
        // SAFETY: as above, bounded.
        let string = unsafe { wide_bounded(bytes[1..].as_ptr().cast::<u16>(), 1) };
        assert_eq!(units(string).collect::<Vec<_>>(), [0x61]);
    }

    #[test]
    fn a_bounded_string_stops_at_its_nul_or_its_count() {
        // SAFETY: a terminated string, read within it.
        unsafe {
            assert_eq!(bytes_bounded(b"abc\0".as_ptr(), 2), b"ab");
            assert_eq!(bytes_bounded(b"abc\0".as_ptr(), 9), b"abc");
            assert_eq!(bytes_bounded(core::ptr::null(), 0), b"");
        }
    }
}
