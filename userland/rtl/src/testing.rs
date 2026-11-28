//! The host tests' text helpers: a test's `&str` as the UTF-16 units or the little-endian bytes the
//! code under test takes, and units read back as a `String`. rtl's own tests have them, and so do
//! the kernel's and the system DLLs' through the `testing` feature their dev-dependency on rtl
//! turns on; the code that ships never compiles them.
//!
//! Each conversion comes with and without a terminator, the `_z` form appending the NUL, so a test
//! says which one it hands over.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

pub mod sec;

/// `text`'s UTF-16 units, without a terminator.
pub fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().collect()
}

/// `text`'s UTF-16 units, NUL-terminated.
pub fn wide_z(text: &str) -> Vec<u16> {
    text.encode_utf16().chain([0]).collect()
}

/// `text`'s UTF-16 units as little-endian bytes, without a terminator.
pub fn utf16_bytes(text: &str) -> Vec<u8> {
    text.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

/// `text`'s UTF-16 units as little-endian bytes, NUL-terminated (two zero bytes).
pub fn utf16_bytes_z(text: &str) -> Vec<u8> {
    text.encode_utf16()
        .chain([0])
        .flat_map(u16::to_le_bytes)
        .collect()
}

/// `units` as a `String`; the test fails on a lone surrogate.
pub fn narrow(units: &[u16]) -> String {
    String::from_utf16(units).unwrap()
}
