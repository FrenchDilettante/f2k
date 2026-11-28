//! The host tests' text helpers, shared by the shell's modules: a test's `&str` as the UTF-16 units
//! the shell reads, and units read back as a `String`. The programs keep off rtl, so the shell has
//! its own (rtl's `testing` module has the same two, with the NUL-terminated forms besides). The
//! fake environments keep their variables through [`variables_of`] and answer through [`look_up`]
//! and [`put`].

use std::collections::BTreeMap;

use crate::TooLong;

/// `text`'s UTF-16 units, without a terminator.
pub fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().collect()
}

/// `units` as a `String`; the test fails on a lone surrogate.
pub fn narrow(units: &[u16]) -> String {
    String::from_utf16(units).unwrap()
}

/// `text` into a variable's `value` buffer, as the shell's environment answers: its length in
/// units, or [`TooLong`] when the buffer has no room for it.
pub fn put(text: &str, value: &mut [u16]) -> Result<usize, TooLong> {
    let units = wide(text);
    value
        .get_mut(..units.len())
        .ok_or(TooLong)?
        .copy_from_slice(&units);
    Ok(units.len())
}

/// The `(name, value)` pairs as a fake environment's variables, the names upper-cased.
pub fn variables_of(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(name, value)| (name.to_uppercase(), value.to_string()))
        .collect()
}

/// The variable `name` (compared upper-cased) of `variables` into `value`, as [`put`] answers;
/// none when it is not set.
pub fn look_up(
    variables: &BTreeMap<String, String>,
    name: &[u16],
    value: &mut [u16],
) -> Result<Option<usize>, TooLong> {
    match variables.get(&narrow(name).to_uppercase()) {
        Some(text) => put(text, value).map(Some),
        None => Ok(None),
    }
}
