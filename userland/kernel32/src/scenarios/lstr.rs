//! The lstr string functions: lstrlen, lstrcpy, lstrcpyn and lstrcat over the test's own memory
//! (the host has no exception frame to catch a fault, so the bad pointers here are NULL, which each
//! body refuses before it reads). The lstr fixture is the contract on the machine, its bad pages
//! included; these pin what each call answers, which units reach the destination (the sentinel
//! past them untouched), and that none of them sets the last error.

use super::last_error;
use crate::base::set_last_error;
use crate::lstr::*;

/// The last error a call leaves alone, armed before it.
const UNTOUCHED: u32 = 0x0F2F_2F2F;
/// The sentinel every buffer holds before a call: 'Z', and its W unit.
const FILL_A: u8 = 0x5A;
const FILL_W: u16 = 0x5A5A;

fn arm() {
    set_last_error(UNTOUCHED);
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain([0]).collect()
}

/// A wide buffer of `count` units, `text` and its terminator first, the sentinel after.
fn wide_buffer(text: &str, count: usize) -> Vec<u16> {
    let mut buffer = vec![FILL_W; count];
    let text = wide(text);
    buffer[..text.len()].copy_from_slice(&text);
    buffer
}

/// lstrlenA and lstrlenW: the length without the terminator, a byte or unit outside ASCII counted
/// as one; NULL is 0; a W string at an odd address is read as any other; the last error is left
/// alone.
///
/// Pins: kernel32.lstrlenA, kernel32.lstrlenW
#[test]
fn lstrlen_counts_to_the_terminator() {
    arm();
    assert_eq!(unsafe { lstrlen_a(b"\0".as_ptr()) }, 0);
    assert_eq!(unsafe { lstrlen_a(b"abc\0".as_ptr()) }, 3);
    assert_eq!(unsafe { lstrlen_a(b"caf\xE9\0".as_ptr()) }, 4);
    assert_eq!(unsafe { lstrlen_a(core::ptr::null()) }, 0);
    assert_eq!(unsafe { lstrlen_w(wide("").as_ptr()) }, 0);
    assert_eq!(unsafe { lstrlen_w(wide("abc").as_ptr()) }, 3);
    assert_eq!(unsafe { lstrlen_w(wide("caf\u{E9}\u{4E2D}").as_ptr()) }, 5);
    assert_eq!(unsafe { lstrlen_w(core::ptr::null()) }, 0);
    let odd = b"\0a\0b\0\0\0";
    assert_eq!(unsafe { lstrlen_w(odd.as_ptr().add(1).cast()) }, 2);
    assert_eq!(last_error(), UNTOUCHED);
}

/// lstrcpyA and lstrcpyW: the source and its terminator copied, the sentinel after them untouched,
/// the destination answered; an empty source writes the terminator alone; a NULL destination or
/// source answers NULL, the buffer untouched; the last error is left alone.
///
/// Pins: kernel32.lstrcpyA, kernel32.lstrcpyW
#[test]
fn lstrcpy_copies_through_the_terminator() {
    arm();
    let mut buffer = [FILL_A; 16];
    let answer = unsafe { lstrcpy_a(buffer.as_mut_ptr(), b"abc\0".as_ptr()) };
    assert_eq!(answer, buffer.as_mut_ptr());
    assert_eq!(&buffer[..6], b"abc\0ZZ");
    let mut buffer = [FILL_A; 16];
    unsafe { lstrcpy_a(buffer.as_mut_ptr(), b"\0".as_ptr()) };
    assert_eq!(&buffer[..3], b"\0ZZ");
    assert!(unsafe { lstrcpy_a(core::ptr::null_mut(), b"abc\0".as_ptr()) }.is_null());
    let mut buffer = [FILL_A; 16];
    assert!(unsafe { lstrcpy_a(buffer.as_mut_ptr(), core::ptr::null()) }.is_null());
    assert_eq!(buffer, [FILL_A; 16]);

    let mut buffer = [FILL_W; 16];
    let answer = unsafe { lstrcpy_w(buffer.as_mut_ptr(), wide("abc").as_ptr()) };
    assert_eq!(answer, buffer.as_mut_ptr());
    assert_eq!(buffer[..6], [97, 98, 99, 0, FILL_W, FILL_W]);
    assert!(unsafe { lstrcpy_w(core::ptr::null_mut(), wide("abc").as_ptr()) }.is_null());
    let mut buffer = [FILL_W; 16];
    assert!(unsafe { lstrcpy_w(buffer.as_mut_ptr(), core::ptr::null()) }.is_null());
    assert_eq!(buffer, [FILL_W; 16]);
    assert_eq!(last_error(), UNTOUCHED);
}

/// lstrcpynA and lstrcpynW of "abcde": a count of 0 writes nothing; 1 the terminator alone; 5
/// "abcd" and the terminator; 6 and 10 the whole string, the sentinel after its terminator
/// untouched (no padding); -1 copies to the source's terminator. A NULL destination or source
/// answers NULL, the buffer untouched; a count of 0 answers the destination whatever the pointers.
///
/// Pins: kernel32.lstrcpynA, kernel32.lstrcpynW
#[test]
fn lstrcpyn_copies_at_most_one_less_than_its_count() {
    arm();
    let source = b"abcde\0";
    for (count, expected) in [
        (0, &b"ZZZZZZZZ"[..]),
        (1, b"\0ZZZZZZZ"),
        (5, b"abcd\0ZZZ"),
        (6, b"abcde\0ZZ"),
        (10, b"abcde\0ZZ"),
        (-1, b"abcde\0ZZ"),
    ] {
        let mut buffer = [FILL_A; 8];
        let answer = unsafe { lstrcpyn_a(buffer.as_mut_ptr(), source.as_ptr(), count) };
        assert_eq!(answer, buffer.as_mut_ptr(), "count {count}");
        assert_eq!(&buffer, expected, "count {count}");
    }
    assert!(unsafe { lstrcpyn_a(core::ptr::null_mut(), source.as_ptr(), 5) }.is_null());
    let mut buffer = [FILL_A; 8];
    assert!(unsafe { lstrcpyn_a(buffer.as_mut_ptr(), core::ptr::null(), 5) }.is_null());
    assert_eq!(buffer, [FILL_A; 8]);
    assert_eq!(
        unsafe { lstrcpyn_a(buffer.as_mut_ptr(), core::ptr::null(), 0) },
        buffer.as_mut_ptr()
    );

    let source = wide("abcde");
    for (count, expected) in [(0, ""), (1, ""), (5, "abcd"), (6, "abcde"), (10, "abcde")] {
        let mut buffer = [FILL_W; 8];
        let answer = unsafe { lstrcpyn_w(buffer.as_mut_ptr(), source.as_ptr(), count) };
        assert_eq!(answer, buffer.as_mut_ptr(), "count {count}");
        let written = if count == 0 {
            vec![FILL_W; 8]
        } else {
            wide_buffer(expected, 8)
        };
        assert_eq!(buffer[..], written[..], "count {count}");
    }
    assert!(unsafe { lstrcpyn_w(core::ptr::null_mut(), source.as_ptr(), 5) }.is_null());
    let mut buffer = [FILL_W; 8];
    assert!(unsafe { lstrcpyn_w(buffer.as_mut_ptr(), core::ptr::null(), 5) }.is_null());
    assert_eq!(buffer, [FILL_W; 8]);
    assert_eq!(last_error(), UNTOUCHED);
}

/// lstrcatA and lstrcatW: the source and its terminator copied over the destination's terminator,
/// the sentinel after untouched, the destination answered; onto an empty string, and an empty
/// source (the destination as it was). A NULL destination or source answers NULL, the destination
/// untouched; the last error is left alone.
///
/// Pins: kernel32.lstrcatA, kernel32.lstrcatW
#[test]
fn lstrcat_appends_at_the_terminator() {
    arm();
    let start = |text: &[u8]| {
        let mut buffer = [FILL_A; 16];
        buffer[..text.len()].copy_from_slice(text);
        buffer
    };
    let mut buffer = start(b"ab\0");
    let answer = unsafe { lstrcat_a(buffer.as_mut_ptr(), b"cd\0".as_ptr()) };
    assert_eq!(answer, buffer.as_mut_ptr());
    assert_eq!(&buffer[..6], b"abcd\0Z");
    let mut buffer = start(b"\0");
    unsafe { lstrcat_a(buffer.as_mut_ptr(), b"xy\0".as_ptr()) };
    assert_eq!(&buffer[..4], b"xy\0Z");
    let mut buffer = start(b"ab\0");
    unsafe { lstrcat_a(buffer.as_mut_ptr(), b"\0".as_ptr()) };
    assert_eq!(&buffer[..4], b"ab\0Z");
    assert!(unsafe { lstrcat_a(core::ptr::null_mut(), b"cd\0".as_ptr()) }.is_null());
    let mut buffer = start(b"ab\0");
    assert!(unsafe { lstrcat_a(buffer.as_mut_ptr(), core::ptr::null()) }.is_null());
    assert_eq!(buffer, start(b"ab\0"));

    let mut buffer = wide_buffer("ab", 16);
    let answer = unsafe { lstrcat_w(buffer.as_mut_ptr(), wide("cd").as_ptr()) };
    assert_eq!(answer, buffer.as_mut_ptr());
    assert_eq!(buffer, wide_buffer("abcd", 16));
    let mut buffer = wide_buffer("", 16);
    unsafe { lstrcat_w(buffer.as_mut_ptr(), wide("xy").as_ptr()) };
    assert_eq!(buffer, wide_buffer("xy", 16));
    assert!(unsafe { lstrcat_w(core::ptr::null_mut(), wide("cd").as_ptr()) }.is_null());
    let mut buffer = wide_buffer("ab", 16);
    assert!(unsafe { lstrcat_w(buffer.as_mut_ptr(), core::ptr::null()) }.is_null());
    assert_eq!(buffer, wide_buffer("ab", 16));
    assert_eq!(last_error(), UNTOUCHED);
}
