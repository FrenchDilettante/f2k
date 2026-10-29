//! NUL-terminated strings: a caller's string read once, to its terminator, into a slice the code
//! after it works on safely, and the length of a string held in a buffer.

/// The bytes of the NUL-terminated string at `string`, its terminator excluded.
///
/// # Safety
///
/// `string` points at a NUL-terminated string, readable to its terminator and unchanged while the
/// bytes are borrowed.
pub unsafe fn bytes_until_nul<'a>(string: *const u8) -> &'a [u8] {
    let mut length = 0;
    // SAFETY: the caller's string, read up to its terminator.
    while unsafe { string.add(length).read() } != 0 {
        length += 1;
    }
    // SAFETY: the `length` bytes before the terminator, read above.
    unsafe { core::slice::from_raw_parts(string, length) }
}

/// The UTF-16 units of the NUL-terminated string at `string`, its terminator excluded.
///
/// # Safety
///
/// `string` is aligned for `u16` (a slice of misaligned units is undefined behaviour, even unread)
/// and points at a NUL-terminated string, readable to its terminator and unchanged while the units
/// are borrowed.
pub unsafe fn units_until_nul<'a>(string: *const u16) -> &'a [u16] {
    let mut length = 0;
    // SAFETY: the caller's aligned string, read up to its terminator.
    while unsafe { string.add(length).read() } != 0 {
        length += 1;
    }
    // SAFETY: the `length` units before the terminator, read above.
    unsafe { core::slice::from_raw_parts(string, length) }
}

/// The length in units of the NUL-terminated string at `string`, its terminator excluded, read with
/// unaligned reads: a caller's string may sit at any address (an x86 program may hand an LPCWSTR at
/// an odd one, which Windows reads like any other), where [`units_until_nul`]'s slice could not.
///
/// # Safety
///
/// `string` points at a NUL-terminated string, readable to its terminator.
pub unsafe fn len_until_nul<U: Copy + Default + PartialEq>(string: *const U) -> usize {
    let nul = U::default();
    let mut length = 0;
    // SAFETY: the caller's string, read up to its terminator; an unaligned read takes any address.
    while unsafe { string.add(length).read_unaligned() } != nul {
        length += 1;
    }
    length
}

/// The length of the string at the start of `buffer`: the units before its first NUL, or the whole
/// buffer when it holds none.
pub fn nul_len<T: Copy + Default + PartialEq>(buffer: &[T]) -> usize {
    let nul = T::default();
    buffer
        .iter()
        .position(|&unit| unit == nul)
        .unwrap_or(buffer.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_string_is_read_to_its_terminator() {
        let text = *b"abc\0def\0";
        // SAFETY: a terminated string.
        assert_eq!(unsafe { bytes_until_nul(text.as_ptr()) }, b"abc");
        // SAFETY: as above.
        assert_eq!(unsafe { bytes_until_nul(text[3..].as_ptr()) }, b"");
        let wide = [0x61u16, 0x2603, 0, 0x62];
        // SAFETY: an aligned, terminated string.
        assert_eq!(unsafe { units_until_nul(wide.as_ptr()) }, &wide[..2]);
    }

    #[test]
    fn a_string_at_any_address_is_counted_to_its_terminator() {
        let bytes = *b"\0a\0b\0\0\0";
        // SAFETY: "ab" as UTF-16 at an odd address, terminated, read unaligned.
        assert_eq!(
            unsafe { len_until_nul(bytes[1..].as_ptr().cast::<u16>()) },
            2
        );
        // SAFETY: a terminated narrow string.
        assert_eq!(unsafe { len_until_nul(b"abc\0".as_ptr()) }, 3);
    }

    #[test]
    fn a_buffer_string_ends_at_its_first_nul_or_the_buffer() {
        assert_eq!(nul_len(b"ab\0c\0"), 2);
        assert_eq!(nul_len(b"abc"), 3);
        assert_eq!(nul_len::<u16>(&[]), 0);
        assert_eq!(nul_len(&[0x41u16, 0x42, 0]), 2);
    }
}
