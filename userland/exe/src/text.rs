//! ASCII text widened to UTF-16: the programs' own literals (a privilege's name, a built-in's word)
//! handed to the W calls, as rtl's `cstr::ascii_into` widens the system's.
//!
//! Each byte becomes its own unit. That is Latin-1, not a code page (1252's 0x80-0x9F differ), and
//! the two agree on ASCII only: the widening takes nothing else. Text that may hold any byte, a
//! file's or a pipe's, is decoded through its code page instead.

/// `text` (ASCII) as UTF-16 units into `out`, as many as it has room for: the units written. The
/// text is checked to be ASCII in a debug build only.
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
    fn ascii_widens_a_unit_for_each_byte() {
        let mut out = [0xFFFFu16; 4];
        assert_eq!(ascii_into(&mut out, b"ab"), 2);
        assert_eq!(out, [0x61, 0x62, 0xFFFF, 0xFFFF]);
        assert_eq!(ascii_into(&mut out[..1], b"xyz"), 1);
        assert_eq!(out[0], 0x78);
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "not ASCII")]
    fn text_past_ascii_is_refused_in_a_debug_build() {
        ascii_into(&mut [0; 2], &[0x80]);
    }
}
