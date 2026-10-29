//! The string functions: strcmp and _stricmp, the narrow ones spawn's programs call (strlen,
//! strcpy, strcat, strcspn, strrchr, _strnicmp), and the wide ones cmd.exe calls.
//!
//! The narrow ones as the C runtime reference documents them: strrchr finds the terminator for 0;
//! _strnicmp compares at most `count` characters, each lowered in the LC_CTYPE locale, answering
//! the difference of the first that differ as _stricmp does.
//!
//! As wide's capture pins them: wcscmp and strcmp answer -1, 0 or 1; wcsncmp, _wcsicmp and
//! _wcsnicmp the difference of the first units that differ (each lowered first, in the LC_CTYPE
//! locale, for the case-insensitive ones: `[` against `a` is -6); wcsncpy pads with NULs and leaves
//! a full destination unterminated; wcschr and wcsrchr find the terminator too; wcsstr finds the
//! empty string at the start; _wcslwr and _wcsupr map in place, in the LC_CTYPE locale.
//!
//! Each export reads its caller's strings once, into slices ([`crate::edge`]); the work below is
//! over those.

use core::iter::once;

use rtl::cstr::bytes_until_nul;

use crate::ctype;
use crate::edge::{self, units, WideUnit};

/// The first `count` units of two strings compared, each string's NUL after its units and each
/// unit mapped by `map` first: the difference of the first that differ; 0 at a common NUL or past
/// the count.
fn difference(
    a: impl Iterator<Item = u32>,
    b: impl Iterator<Item = u32>,
    count: usize,
    map: impl Fn(u32) -> u32,
) -> i32 {
    for (x, y) in a.chain(once(0)).zip(b.chain(once(0))).take(count) {
        let (x, y) = (map(x), map(y));
        if x != y || x == 0 {
            return x as i32 - y as i32;
        }
    }
    0
}

/// A narrow string's bytes as the compares take them.
fn narrow_values(string: &[u8]) -> impl Iterator<Item = u32> + '_ {
    string.iter().map(|&byte| u32::from(byte))
}

/// A wide string's units as the compares take them.
fn wide_values(string: &[WideUnit]) -> impl Iterator<Item = u32> + '_ {
    units(string).map(u32::from)
}

/// A byte lowered in the LC_CTYPE locale, as the compares map them.
fn lower_byte(value: u32) -> u32 {
    u32::from(ctype::byte_lower(value as u8))
}

/// A wide unit lowered in the LC_CTYPE locale, as the compares map them.
fn lower_wide(value: u32) -> u32 {
    u32::from(ctype::wide_lower(value as u16))
}

/// strcmp: the strings' order, byte by byte, as -1, 0 or 1.
///
/// # Safety
///
/// Both strings are NUL-terminated.
#[unsafe(export_name = "f2k_export_strcmp")]
pub unsafe extern "C" fn strcmp(a: *const u8, b: *const u8) -> i32 {
    // SAFETY: the caller's strings.
    let (a, b) = unsafe { (bytes_until_nul(a), bytes_until_nul(b)) };
    difference(narrow_values(a), narrow_values(b), usize::MAX, |b| b).signum()
}

/// _stricmp: the strings' order without regard to case (each byte lowered in the LC_CTYPE
/// locale): the difference of the first bytes that differ.
///
/// # Safety
///
/// Both strings are NUL-terminated.
#[unsafe(export_name = "f2k_export__stricmp")]
pub unsafe extern "C" fn stricmp(a: *const u8, b: *const u8) -> i32 {
    // SAFETY: the caller's strings.
    let (a, b) = unsafe { (bytes_until_nul(a), bytes_until_nul(b)) };
    difference(narrow_values(a), narrow_values(b), usize::MAX, lower_byte)
}

/// wcslen.
///
/// # Safety
///
/// `string` is NUL-terminated.
#[unsafe(export_name = "f2k_export_wcslen")]
pub unsafe extern "C" fn wcslen(string: *const u16) -> usize {
    // SAFETY: the caller's string.
    unsafe { rtl::cstr::len_until_nul(string) }
}

/// The wide compares' work over the caller's strings, each read to its NUL or `count` units.
///
/// # Safety
///
/// Both strings are NUL-terminated or hold `count` units.
unsafe fn wide_difference(
    a: *const u16,
    b: *const u16,
    count: usize,
    map: impl Fn(u32) -> u32,
) -> i32 {
    // SAFETY: the caller's strings.
    let (a, b) = unsafe { (edge::wide_bounded(a, count), edge::wide_bounded(b, count)) };
    difference(wide_values(a), wide_values(b), count, map)
}

/// wcscmp: the order, unit by unit, as -1, 0 or 1.
///
/// # Safety
///
/// Both strings are NUL-terminated.
#[unsafe(export_name = "f2k_export_wcscmp")]
pub unsafe extern "C" fn wcscmp(a: *const u16, b: *const u16) -> i32 {
    // SAFETY: the caller's contract.
    unsafe { wide_difference(a, b, usize::MAX, |u| u) }.signum()
}

/// wcsncmp: the first `count` units' order: the difference of the first that differ.
///
/// # Safety
///
/// Both strings are NUL-terminated or hold `count` units.
#[unsafe(export_name = "f2k_export_wcsncmp")]
pub unsafe extern "C" fn wcsncmp(a: *const u16, b: *const u16, count: usize) -> i32 {
    // SAFETY: the caller's contract.
    unsafe { wide_difference(a, b, count, |u| u) }
}

/// _wcsicmp: the order without regard to case.
///
/// # Safety
///
/// Both strings are NUL-terminated.
#[unsafe(export_name = "f2k_export__wcsicmp")]
pub unsafe extern "C" fn wcsicmp(a: *const u16, b: *const u16) -> i32 {
    // SAFETY: the caller's contract.
    unsafe { wide_difference(a, b, usize::MAX, lower_wide) }
}

/// _wcsnicmp: the first `count` units' order without regard to case.
///
/// # Safety
///
/// Both strings are NUL-terminated or hold `count` units.
#[unsafe(export_name = "f2k_export__wcsnicmp")]
pub unsafe extern "C" fn wcsnicmp(a: *const u16, b: *const u16, count: usize) -> i32 {
    // SAFETY: the caller's contract.
    unsafe { wide_difference(a, b, count, lower_wide) }
}

/// wcscpy: `source` and its NUL copied to `destination`; answers `destination`.
///
/// # Safety
///
/// `source` is NUL-terminated; `destination` has room for it.
#[unsafe(export_name = "f2k_export_wcscpy")]
pub unsafe extern "C" fn wcscpy(destination: *mut u16, source: *const u16) -> *mut u16 {
    // SAFETY: the caller's string, and its room for the string and the NUL (ranges that overlap,
    // the caller's error in C, are copied as memmove copies).
    unsafe {
        let length = rtl::cstr::len_until_nul(source) + 1;
        core::ptr::copy(source.cast::<u8>(), destination.cast::<u8>(), 2 * length);
    }
    destination
}

/// wcsncpy: `count` units: `source`'s, then NULs (none when `source` fills them).
///
/// # Safety
///
/// `source` is NUL-terminated or holds `count` units; `destination` holds `count` units, apart
/// from them.
#[unsafe(export_name = "f2k_export_wcsncpy")]
pub unsafe extern "C" fn wcsncpy(
    destination: *mut u16,
    source: *const u16,
    count: usize,
) -> *mut u16 {
    // SAFETY: the caller's string, read to its NUL or `count` units, and its room of `count` units.
    let (source, out) = unsafe {
        (
            edge::wide_bounded(source, count),
            edge::wide_parts_mut(destination, count),
        )
    };
    let (copied, padding) = out.split_at_mut(source.len());
    copied.copy_from_slice(source);
    padding.fill(WideUnit::new(0));
    destination
}

/// wcscat: `source` appended to `destination`; answers `destination`.
///
/// # Safety
///
/// Both strings are NUL-terminated; `destination` has room for both.
#[unsafe(export_name = "f2k_export_wcscat")]
pub unsafe extern "C" fn wcscat(destination: *mut u16, source: *const u16) -> *mut u16 {
    // SAFETY: the caller's strings and room: the copy goes over `destination`'s NUL.
    unsafe {
        let end = destination.add(rtl::cstr::len_until_nul(destination));
        wcscpy(end, source);
    }
    destination
}

/// The address of `string`'s unit `index` (its NUL at its length).
fn unit_address(string: *const u16, index: usize) -> *const u16 {
    string.wrapping_add(index)
}

/// wcschr: the first `c` in `string` (its NUL for 0), or NULL.
///
/// # Safety
///
/// `string` is NUL-terminated.
#[unsafe(export_name = "f2k_export_wcschr")]
pub unsafe extern "C" fn wcschr(string: *const u16, c: u32) -> *const u16 {
    // SAFETY: the caller's string.
    let units_of = unsafe { edge::wide(string) };
    match units(units_of)
        .chain(once(0))
        .position(|unit| unit == c as u16)
    {
        Some(at) => unit_address(string, at),
        None => core::ptr::null(),
    }
}

/// wcsrchr: the last `c` in `string` (its NUL for 0), or NULL.
///
/// # Safety
///
/// `string` is NUL-terminated.
#[unsafe(export_name = "f2k_export_wcsrchr")]
pub unsafe extern "C" fn wcsrchr(string: *const u16, c: u32) -> *const u16 {
    // SAFETY: the caller's string.
    let units_of = unsafe { edge::wide(string) };
    let found = if c as u16 == 0 {
        Some(units_of.len())
    } else {
        units(units_of).rposition(|unit| unit == c as u16)
    };
    match found {
        Some(at) => unit_address(string, at),
        None => core::ptr::null(),
    }
}

/// wcsstr: the first occurrence of `search` in `string` (`string` itself for the empty one), or
/// NULL.
///
/// # Safety
///
/// Both strings are NUL-terminated.
#[unsafe(export_name = "f2k_export_wcsstr")]
pub unsafe extern "C" fn wcsstr(string: *const u16, search: *const u16) -> *const u16 {
    // SAFETY: the caller's strings.
    let (haystack, wanted) = unsafe { (edge::wide(string), edge::wide(search)) };
    if wanted.is_empty() {
        return string;
    }
    match haystack
        .windows(wanted.len())
        .position(|window| window == wanted)
    {
        Some(at) => unit_address(string, at),
        None => core::ptr::null(),
    }
}

/// wcsspn: the length of `string`'s first run of units that are in `set`.
///
/// # Safety
///
/// Both strings are NUL-terminated.
#[unsafe(export_name = "f2k_export_wcsspn")]
pub unsafe extern "C" fn wcsspn(string: *const u16, set: *const u16) -> usize {
    // SAFETY: the caller's strings.
    let (string, set) = unsafe { (edge::wide(string), edge::wide(set)) };
    string
        .iter()
        .position(|unit| !set.contains(unit))
        .unwrap_or(string.len())
}

/// The string's units mapped in place.
fn map_in_place(string: &mut [WideUnit], map: impl Fn(u16) -> u16) {
    for unit in string {
        *unit = WideUnit::new(map(unit.get()));
    }
}

/// _wcslwr: the string lowered in place (LC_CTYPE's mapping); answers it.
///
/// # Safety
///
/// `string` is NUL-terminated and writable.
#[unsafe(export_name = "f2k_export__wcslwr")]
pub unsafe extern "C" fn wcslwr(string: *mut u16) -> *mut u16 {
    // SAFETY: the caller's writable string, the call's alone.
    let units_of = unsafe { edge::wide_parts_mut(string, rtl::cstr::len_until_nul(string)) };
    map_in_place(units_of, ctype::wide_lower);
    string
}

/// _wcsupr: the string raised in place; answers it.
///
/// # Safety
///
/// `string` is NUL-terminated and writable.
#[unsafe(export_name = "f2k_export__wcsupr")]
pub unsafe extern "C" fn wcsupr(string: *mut u16) -> *mut u16 {
    // SAFETY: as _wcslwr's.
    let units_of = unsafe { edge::wide_parts_mut(string, rtl::cstr::len_until_nul(string)) };
    map_in_place(units_of, ctype::wide_upper);
    string
}

/// strlen.
///
/// # Safety
///
/// `string` is NUL-terminated.
#[unsafe(export_name = "f2k_export_strlen")]
pub unsafe extern "C" fn strlen(string: *const u8) -> usize {
    // SAFETY: the caller's contract.
    unsafe { bytes_until_nul(string) }.len()
}

/// strcpy: `source` and its NUL copied to `destination`; answers `destination`.
///
/// # Safety
///
/// `source` is NUL-terminated; `destination` has room for it.
#[unsafe(export_name = "f2k_export_strcpy")]
pub unsafe extern "C" fn strcpy(destination: *mut u8, source: *const u8) -> *mut u8 {
    // SAFETY: the caller's string and room (ranges that overlap, the caller's error in C, are
    // copied as memmove copies).
    unsafe {
        let length = bytes_until_nul(source).len() + 1;
        core::ptr::copy(source, destination, length);
    }
    destination
}

/// strcat: `source` appended to `destination`; answers `destination`.
///
/// # Safety
///
/// Both strings are NUL-terminated; `destination` has room for both.
#[unsafe(export_name = "f2k_export_strcat")]
pub unsafe extern "C" fn strcat(destination: *mut u8, source: *const u8) -> *mut u8 {
    // SAFETY: the caller's strings and room: the copy goes over `destination`'s NUL.
    unsafe { strcpy(destination.add(bytes_until_nul(destination).len()), source) };
    destination
}

/// The length of `string`'s first run of bytes that are not in `set`.
fn complement_span(string: &[u8], set: &[u8]) -> usize {
    string
        .iter()
        .position(|byte| set.contains(byte))
        .unwrap_or(string.len())
}

/// strcspn: the length of `string`'s first run of characters not in `set`.
///
/// # Safety
///
/// Both strings are NUL-terminated.
#[unsafe(export_name = "f2k_export_strcspn")]
pub unsafe extern "C" fn strcspn(string: *const u8, set: *const u8) -> usize {
    // SAFETY: the caller's strings.
    let (string, set) = unsafe { (bytes_until_nul(string), bytes_until_nul(set)) };
    complement_span(string, set)
}

/// strrchr: the last `c` (as a char) in `string`, its NUL for 0, or NULL.
///
/// # Safety
///
/// `string` is NUL-terminated.
#[unsafe(export_name = "f2k_export_strrchr")]
pub unsafe extern "C" fn strrchr(string: *const u8, c: i32) -> *const u8 {
    // SAFETY: the caller's string.
    let bytes = unsafe { bytes_until_nul(string) };
    let found = if c as u8 == 0 {
        Some(bytes.len())
    } else {
        bytes.iter().rposition(|&byte| byte == c as u8)
    };
    match found {
        Some(at) => string.wrapping_add(at),
        None => core::ptr::null(),
    }
}

/// _strnicmp: the first `count` characters' order without regard to case (each byte lowered in
/// the LC_CTYPE locale): the difference of the first that differ, as _stricmp answers.
///
/// # Safety
///
/// Both strings are NUL-terminated or hold `count` bytes.
#[unsafe(export_name = "f2k_export__strnicmp")]
pub unsafe extern "C" fn strnicmp(a: *const u8, b: *const u8, count: usize) -> i32 {
    // SAFETY: the caller's strings.
    let (a, b) = unsafe { (edge::bytes_bounded(a, count), edge::bytes_bounded(b, count)) };
    difference(narrow_values(a), narrow_values(b), count, lower_byte)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::tests::wide;

    fn w(text: &str) -> Vec<u16> {
        wide(text)
    }

    /// wide's wcs block.
    #[test]
    fn wcs_as_captured() {
        // SAFETY: NUL-terminated strings, buffers large enough.
        unsafe {
            assert_eq!((wcslen(w("").as_ptr()), wcslen(w("abc").as_ptr())), (0, 3));
            let mut buf = [b'#' as u16; 16];
            assert_eq!(
                wcscpy(buf.as_mut_ptr(), w("hello").as_ptr()),
                buf.as_mut_ptr()
            );
            assert_eq!(String::from_utf16_lossy(&buf[..8]), "hello\0##");
            let mut buf = [b'#' as u16; 16];
            wcsncpy(buf.as_mut_ptr(), w("ab").as_ptr(), 6);
            assert_eq!(String::from_utf16_lossy(&buf[..8]), "ab\0\0\0\0##");
            let mut buf = [b'#' as u16; 16];
            wcsncpy(buf.as_mut_ptr(), w("abcdef").as_ptr(), 4);
            assert_eq!(String::from_utf16_lossy(&buf[..6]), "abcd##");
            let mut buf = [b'#' as u16; 16];
            wcsncpy(buf.as_mut_ptr(), w("abc").as_ptr(), 0);
            assert_eq!(String::from_utf16_lossy(&buf[..4]), "####");
            let mut buf = [b'#' as u16; 16];
            buf[..3].copy_from_slice(&w("ab"));
            wcscat(buf.as_mut_ptr(), w("cd").as_ptr());
            wcscat(buf.as_mut_ptr(), w("").as_ptr());
            assert_eq!(String::from_utf16_lossy(&buf[..6]), "abcd\0#");

            let cmp = |a: &str, b: &str| wcscmp(w(a).as_ptr(), w(b).as_ptr());
            assert_eq!(
                [
                    cmp("abc", "abd"),
                    cmp("abc", "abc"),
                    cmp("abd", "abc"),
                    cmp("ab", "abc"),
                    cmp("abc", "ab"),
                    cmp("", ""),
                    cmp("é", "z"),
                    cmp("a", "A"),
                    cmp("Α", "α")
                ],
                [-1, 0, 1, -1, 1, 0, 1, 1, -1]
            );
            let ncmp = |a: &str, b: &str, n| wcsncmp(w(a).as_ptr(), w(b).as_ptr(), n);
            assert_eq!(
                [
                    ncmp("abcd", "abce", 3),
                    ncmp("abcd", "abce", 4),
                    ncmp("ab", "abc", 5),
                    ncmp("x", "y", 0)
                ],
                [0, -1, -99, 0]
            );

            let list = w("a,b,c");
            let off = |p: *const u16| {
                if p.is_null() {
                    -1
                } else {
                    p.offset_from(list.as_ptr())
                }
            };
            assert_eq!(
                [
                    off(wcschr(list.as_ptr(), b',' as u32)),
                    off(wcschr(list.as_ptr(), b'c' as u32)),
                    off(wcschr(list.as_ptr(), b'z' as u32)),
                    off(wcschr(list.as_ptr(), 0))
                ],
                [1, 4, -1, 5]
            );
            assert_eq!(
                [
                    off(wcsrchr(list.as_ptr(), b',' as u32)),
                    off(wcsrchr(list.as_ptr(), b'a' as u32)),
                    off(wcsrchr(list.as_ptr(), b'z' as u32)),
                    off(wcsrchr(list.as_ptr(), 0))
                ],
                [3, 0, -1, 5]
            );
            let hay = w("haystack");
            let find = |s: &str| {
                let p = wcsstr(hay.as_ptr(), w(s).as_ptr());
                if p.is_null() {
                    -1
                } else {
                    p.offset_from(hay.as_ptr())
                }
            };
            assert_eq!(
                [
                    find("st"),
                    find("stack"),
                    find("k"),
                    find(""),
                    find("stacks"),
                    find("x")
                ],
                [3, 3, 7, 0, -1, -1]
            );
            let spn = |a: &str, b: &str| wcsspn(w(a).as_ptr(), w(b).as_ptr());
            assert_eq!(
                [
                    spn("aabbcx", "ab"),
                    spn("xyz", "ab"),
                    spn("", "a"),
                    spn("abc", ""),
                    spn("abc", "cba")
                ],
                [4, 0, 0, 0, 3]
            );
        }
    }

    /// strlen, strcpy and strcat: the copies carry the NUL and nothing past it; the answers are the
    /// destination.
    #[test]
    fn narrow_strings_copy_and_append() {
        // SAFETY: NUL-terminated strings, buffers large enough.
        unsafe {
            assert_eq!(
                (strlen(b"\0".as_ptr()), strlen(b"spawn\0".as_ptr())),
                (0, 5)
            );
            let mut buf = [b'#'; 16];
            assert_eq!(
                strcpy(buf.as_mut_ptr(), b"home\0".as_ptr()),
                buf.as_mut_ptr()
            );
            assert_eq!(&buf[..7], b"home\0##");
            assert_eq!(
                strcat(buf.as_mut_ptr(), b"\\kid\0".as_ptr()),
                buf.as_mut_ptr()
            );
            strcat(buf.as_mut_ptr(), b"\0".as_ptr());
            assert_eq!(&buf[..11], b"home\\kid\0##");
            strcpy(buf.as_mut_ptr(), b"\0".as_ptr());
            assert_eq!(&buf[..2], b"\0o");
        }
    }

    /// strcspn and strrchr.
    #[test]
    fn narrow_strings_are_searched() {
        // SAFETY: NUL-terminated strings.
        unsafe {
            let cspn = |a: &[u8], b: &[u8]| strcspn(a.as_ptr(), b.as_ptr());
            assert_eq!(
                [
                    cspn(b"line\r\n\0", b"\r\n\0"),
                    cspn(b"line\0", b"\r\n\0"),
                    cspn(b"\0", b"x\0"),
                    cspn(b"abc\0", b"\0"),
                    cspn(b"\nx\0", b"\r\n\0")
                ],
                [4, 4, 0, 3, 0]
            );
            let path = b"C:\\CORPUS\\spawn.exe\0";
            let at = |c: i32| {
                let p = strrchr(path.as_ptr(), c);
                if p.is_null() {
                    -1
                } else {
                    p.offset_from(path.as_ptr())
                }
            };
            assert_eq!(
                [at(b'\\' as i32), at(b'.' as i32), at(b'z' as i32), at(0)],
                [9, 15, -1, 19]
            );
            assert_eq!(at(0x15C), 9, "c taken as a char");
        }
    }

    /// _strnicmp: at most `count` characters, lowered, the difference of the first that differ.
    #[test]
    fn strnicmp_compares_a_prefix_without_regard_to_case() {
        let _locale = crate::ctype::tests::LOCALE.lock().unwrap();
        // SAFETY: setlocale over a NUL-terminated name.
        unsafe { crate::ctype::setlocale(0, b"C\0".as_ptr()) };
        // SAFETY: NUL-terminated strings.
        let nicmp = |a: &[u8], b: &[u8], n| unsafe { strnicmp(a.as_ptr(), b.as_ptr(), n) };
        assert_eq!(
            [
                nicmp(b"C:\\CORPUS\\x\0", b"c:\\corpus\0", 9),
                nicmp(b"C:\\CORPUS\\x\0", b"c:\\corpus\0", 10),
                nicmp(b"abc\0", b"ABD\0", 3),
                nicmp(b"abc\0", b"ABD\0", 2),
                nicmp(b"ab\0", b"AB\0", 10),
                nicmp(b"a\0", b"AB\0", 5),
                nicmp(b"[\0", b"a\0", 1),
                nicmp(b"x\0", b"y\0", 0)
            ],
            [0, b'\\' as i32, -1, 0, 0, -98, -6, 0]
        );
        // A string shorter than the count but unterminated past it is not read past the count.
        let unterminated = [b'A', b'B'];
        // SAFETY: two bytes, the count.
        assert_eq!(
            unsafe { strnicmp(unterminated.as_ptr(), b"ab\0".as_ptr(), 2) },
            0
        );
    }

    /// wide's case block, in both locales.
    #[test]
    fn case_as_captured() {
        let _locale = crate::ctype::tests::LOCALE.lock().unwrap();
        // SAFETY: NUL-terminated strings.
        let icmp = |a: &str, b: &str| unsafe { wcsicmp(w(a).as_ptr(), w(b).as_ptr()) };
        let nicmp = |a: &str, b: &str, n| unsafe { wcsnicmp(w(a).as_ptr(), w(b).as_ptr(), n) };
        let mixed = "AbC 1[_éÉÿāĀαΑжЖ";
        let lower = || {
            let mut s = w(mixed);
            // SAFETY: a NUL-terminated buffer.
            unsafe { wcslwr(s.as_mut_ptr()) };
            String::from_utf16_lossy(&s[..s.len() - 1])
        };
        let upper = || {
            let mut s = w(mixed);
            // SAFETY: as above.
            unsafe { wcsupr(s.as_mut_ptr()) };
            String::from_utf16_lossy(&s[..s.len() - 1])
        };
        // SAFETY: setlocale over NUL-terminated names.
        unsafe { crate::ctype::setlocale(0, b"C\0".as_ptr()) };
        assert_eq!(
            [
                icmp("abc", "ABC"),
                icmp("abc", "ABD"),
                icmp("abd", "ABC"),
                icmp("a", "AB"),
                icmp("", "")
            ],
            [0, -1, 1, -98, 0]
        );
        assert_eq!(
            [
                icmp("[", "a"),
                icmp("_", "A"),
                icmp("é", "É"),
                icmp("é", "E"),
                icmp("α", "Α")
            ],
            [-6, -2, 32, 132, 32]
        );
        assert_eq!(
            [
                nicmp("abcX", "ABCy", 3),
                nicmp("abcX", "ABCy", 4),
                nicmp("ab", "AB", 10),
                nicmp("a", "b", 0)
            ],
            [0, -1, 0, 0]
        );
        assert_eq!(lower(), "abc 1[_éÉÿāĀαΑжЖ");
        assert_eq!(upper(), "ABC 1[_éÉÿāĀαΑжЖ");
        // SAFETY: as above.
        unsafe { crate::ctype::setlocale(0, b"\0".as_ptr()) };
        assert_eq!(
            [
                icmp("[", "a"),
                icmp("_", "A"),
                icmp("é", "É"),
                icmp("é", "E"),
                icmp("α", "Α")
            ],
            [-6, -2, 0, 132, 0]
        );
        assert_eq!(lower(), "abc 1[_ééÿāāααжж");
        assert_eq!(upper(), "ABC 1[_ÉÉŸĀĀΑΑЖЖ");
        // SAFETY: as above.
        unsafe { crate::ctype::setlocale(0, b"C\0".as_ptr()) };
    }
}
