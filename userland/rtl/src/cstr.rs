//! NUL-terminated strings: a caller's string read once, to its terminator, into a slice the code
//! after it works on safely, and the length of a string held in a buffer; and ASCII text widened to
//! UTF-16, the system's own names and literals ([`ascii_units`] at compile time, [`ascii_into`] at
//! run time).
//!
//! The widening makes each byte its own unit. That is Latin-1, not the ANSI code page (1252's
//! 0x80-0x9F differ: 0x80 is the euro sign, U+20AC), and the two agree on ASCII only: the helpers
//! take nothing else. Text that may hold any byte, a caller's or a file's, goes through the code
//! page ([`crate::string::multi_byte_to_unicode`]).

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

/// `text` (ASCII) as UTF-16 units, NUL-padded to `N`: a wide literal made at compile time
/// (`const DEBUGGER: [u16; 9] = ascii_units("Debugger");`, its terminator the padding). A non-ASCII
/// byte or a text longer than `N` fails the build in a constant, and panics at run time.
pub const fn ascii_units<const N: usize>(text: &str) -> [u16; N] {
    let bytes = text.as_bytes();
    assert!(bytes.len() <= N, "the text is longer than its units");
    let mut units = [0u16; N];
    let mut at = 0;
    while at < bytes.len() {
        assert!(bytes[at].is_ascii(), "the text is not ASCII");
        units[at] = bytes[at] as u16;
        at += 1;
    }
    units
}

/// `text` (ASCII) as UTF-16 units into `out`, as many as it has room for: the units written. The
/// text is checked to be ASCII in a debug build only; text that may hold any byte goes through
/// [`crate::string::multi_byte_to_unicode`] instead.
pub fn ascii_into(out: &mut [u16], text: &[u8]) -> usize {
    debug_assert!(text.is_ascii(), "the text is not ASCII");
    let count = out.len().min(text.len());
    for (unit, &byte) in out.iter_mut().zip(&text[..count]) {
        *unit = u16::from(byte);
    }
    count
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

    #[test]
    fn ascii_widens_a_unit_for_each_byte() {
        const EXE: [u16; 5] = ascii_units(".exe");
        assert_eq!(EXE, [0x2E, 0x65, 0x78, 0x65, 0]);
        assert_eq!(ascii_units::<3>("\\??"), [0x5C, 0x3F, 0x3F]);
        let mut out = [0xFFFFu16; 4];
        assert_eq!(ascii_into(&mut out, b"ab"), 2);
        assert_eq!(out, [0x61, 0x62, 0xFFFF, 0xFFFF]);
        assert_eq!(ascii_into(&mut out[..1], b"xyz"), 1);
        assert_eq!(out[0], 0x78);
    }

    #[test]
    #[should_panic(expected = "longer")]
    fn a_literal_past_its_units_is_refused() {
        let _ = ascii_units::<2>("abc");
    }

    #[test]
    #[should_panic(expected = "not ASCII")]
    fn a_literal_past_ascii_is_refused() {
        let _ = ascii_units::<4>("\u{e9}");
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "not ASCII")]
    fn run_time_text_past_ascii_is_refused_in_a_debug_build() {
        ascii_into(&mut [0; 2], &[0x80]);
    }
}
