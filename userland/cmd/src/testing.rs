//! The host tests' text helpers, shared by the shell's modules: a test's `&str` as the UTF-16 units
//! the shell reads, and units read back as a `String`. The programs keep off rtl, so the shell has
//! its own (rtl's `testing` module has the same two, with the NUL-terminated forms besides).

/// `text`'s UTF-16 units, without a terminator.
pub fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().collect()
}

/// `units` as a `String`; the test fails on a lone surrogate.
pub fn narrow(units: &[u16]) -> String {
    String::from_utf16(units).unwrap()
}
