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

use crate::ctype;

/// A wide string's unit at `index`.
///
/// # Safety
///
/// `index` is at or before the string's NUL (or inside its buffer).
unsafe fn at(string: *const u16, index: usize) -> u16 {
    // SAFETY: the caller's contract.
    unsafe { string.add(index).read_unaligned() }
}

/// A wide string's length in units.
///
/// # Safety
///
/// `string` is NUL-terminated.
pub unsafe fn wide_length(string: *const u16) -> usize {
    let mut length = 0;
    // SAFETY: the caller's string, read up to its NUL.
    while unsafe { at(string, length) } != 0 {
        length += 1;
    }
    length
}

/// The sign of an ordering, as -1, 0 or 1.
fn sign(ordering: core::cmp::Ordering) -> i32 {
    ordering as i32
}

/// strcmp: the strings' order, byte by byte, as -1, 0 or 1.
///
/// # Safety
///
/// Both strings are NUL-terminated.
#[unsafe(export_name = "f2k_export_strcmp")]
pub unsafe extern "C" fn strcmp(a: *const u8, b: *const u8) -> i32 {
    let mut i = 0;
    loop {
        // SAFETY: the caller's strings, read up to the first NUL.
        let (x, y) = unsafe { (a.add(i).read(), b.add(i).read()) };
        if x != y || x == 0 {
            return sign(x.cmp(&y));
        }
        i += 1;
    }
}

/// _stricmp: the strings' order without regard to case (each byte lowered in the LC_CTYPE
/// locale): the difference of the first bytes that differ.
///
/// # Safety
///
/// Both strings are NUL-terminated.
#[unsafe(export_name = "f2k_export__stricmp")]
pub unsafe extern "C" fn stricmp(a: *const u8, b: *const u8) -> i32 {
    let mut i = 0;
    loop {
        // SAFETY: as strcmp's.
        let (x, y) = unsafe {
            (
                ctype::byte_lower(a.add(i).read()),
                ctype::byte_lower(b.add(i).read()),
            )
        };
        if x != y || x == 0 {
            return x as i32 - y as i32;
        }
        i += 1;
    }
}

/// wcslen.
///
/// # Safety
///
/// `string` is NUL-terminated.
#[unsafe(export_name = "f2k_export_wcslen")]
pub unsafe extern "C" fn wcslen(string: *const u16) -> usize {
    // SAFETY: the caller's contract.
    unsafe { wide_length(string) }
}

/// The comparison the wide compares share: up to `count` units, each mapped by `map`; the first
/// difference.
///
/// # Safety
///
/// Both strings are NUL-terminated (or hold `count` units).
unsafe fn compare(a: *const u16, b: *const u16, count: usize, map: impl Fn(u16) -> u16) -> i32 {
    for i in 0..count {
        // SAFETY: the caller's strings, read up to the first NUL.
        let (x, y) = unsafe { (map(at(a, i)), map(at(b, i))) };
        if x != y || x == 0 {
            return x as i32 - y as i32;
        }
    }
    0
}

/// wcscmp: the order, unit by unit, as -1, 0 or 1.
///
/// # Safety
///
/// Both strings are NUL-terminated.
#[unsafe(export_name = "f2k_export_wcscmp")]
pub unsafe extern "C" fn wcscmp(a: *const u16, b: *const u16) -> i32 {
    // SAFETY: the caller's contract.
    unsafe { compare(a, b, usize::MAX, |u| u) }.signum()
}

/// wcsncmp: the first `count` units' order: the difference of the first that differ.
///
/// # Safety
///
/// Both strings are NUL-terminated or hold `count` units.
#[unsafe(export_name = "f2k_export_wcsncmp")]
pub unsafe extern "C" fn wcsncmp(a: *const u16, b: *const u16, count: usize) -> i32 {
    // SAFETY: the caller's contract.
    unsafe { compare(a, b, count, |u| u) }
}

/// _wcsicmp: the order without regard to case.
///
/// # Safety
///
/// Both strings are NUL-terminated.
#[unsafe(export_name = "f2k_export__wcsicmp")]
pub unsafe extern "C" fn wcsicmp(a: *const u16, b: *const u16) -> i32 {
    // SAFETY: the caller's contract.
    unsafe { compare(a, b, usize::MAX, ctype::wide_lower) }
}

/// _wcsnicmp: the first `count` units' order without regard to case.
///
/// # Safety
///
/// Both strings are NUL-terminated or hold `count` units.
#[unsafe(export_name = "f2k_export__wcsnicmp")]
pub unsafe extern "C" fn wcsnicmp(a: *const u16, b: *const u16, count: usize) -> i32 {
    // SAFETY: the caller's contract.
    unsafe { compare(a, b, count, ctype::wide_lower) }
}

/// wcscpy: `source` and its NUL copied to `destination`; answers `destination`.
///
/// # Safety
///
/// `source` is NUL-terminated; `destination` has room for it.
#[unsafe(export_name = "f2k_export_wcscpy")]
pub unsafe extern "C" fn wcscpy(destination: *mut u16, source: *const u16) -> *mut u16 {
    let mut i = 0;
    loop {
        // SAFETY: the caller's contract.
        let unit = unsafe { at(source, i) };
        // SAFETY: as above.
        unsafe { destination.add(i).write_unaligned(unit) };
        if unit == 0 {
            return destination;
        }
        i += 1;
    }
}

/// wcsncpy: `count` units: `source`'s, then NULs (none when `source` fills them).
///
/// # Safety
///
/// `source` is NUL-terminated or holds `count` units; `destination` holds `count` units.
#[unsafe(export_name = "f2k_export_wcsncpy")]
pub unsafe extern "C" fn wcsncpy(
    destination: *mut u16,
    source: *const u16,
    count: usize,
) -> *mut u16 {
    let mut ended = false;
    for i in 0..count {
        // SAFETY: the caller's contract (the source is not read past its NUL).
        let unit = if ended { 0 } else { unsafe { at(source, i) } };
        ended |= unit == 0;
        // SAFETY: as above.
        unsafe { destination.add(i).write_unaligned(unit) };
    }
    destination
}

/// wcscat: `source` appended to `destination`; answers `destination`.
///
/// # Safety
///
/// Both strings are NUL-terminated; `destination` has room for both.
#[unsafe(export_name = "f2k_export_wcscat")]
pub unsafe extern "C" fn wcscat(destination: *mut u16, source: *const u16) -> *mut u16 {
    // SAFETY: the caller's contract.
    unsafe {
        wcscpy(destination.add(wide_length(destination)), source);
    }
    destination
}

/// wcschr: the first `c` in `string` (its NUL for 0), or NULL.
///
/// # Safety
///
/// `string` is NUL-terminated.
#[unsafe(export_name = "f2k_export_wcschr")]
pub unsafe extern "C" fn wcschr(string: *const u16, c: u32) -> *const u16 {
    let c = c as u16;
    let mut i = 0;
    loop {
        // SAFETY: the caller's string, read up to its NUL.
        let unit = unsafe { at(string, i) };
        if unit == c {
            // SAFETY: inside the string.
            return unsafe { string.add(i) };
        }
        if unit == 0 {
            return core::ptr::null();
        }
        i += 1;
    }
}

/// wcsrchr: the last `c` in `string` (its NUL for 0), or NULL.
///
/// # Safety
///
/// `string` is NUL-terminated.
#[unsafe(export_name = "f2k_export_wcsrchr")]
pub unsafe extern "C" fn wcsrchr(string: *const u16, c: u32) -> *const u16 {
    let c = c as u16;
    let mut found = core::ptr::null();
    let mut i = 0;
    loop {
        // SAFETY: as wcschr's.
        let unit = unsafe { at(string, i) };
        if unit == c {
            // SAFETY: inside the string.
            found = unsafe { string.add(i) };
        }
        if unit == 0 {
            return found;
        }
        i += 1;
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
    // SAFETY: the caller's strings, read up to their NULs.
    unsafe {
        let wanted = wide_length(search);
        let mut start = 0;
        loop {
            if (0..wanted).all(|i| at(string, start + i) == at(search, i)) {
                return string.add(start);
            }
            if at(string, start) == 0 {
                return core::ptr::null();
            }
            start += 1;
        }
    }
}

/// wcsspn: the length of `string`'s first run of units that are in `set`.
///
/// # Safety
///
/// Both strings are NUL-terminated.
#[unsafe(export_name = "f2k_export_wcsspn")]
pub unsafe extern "C" fn wcsspn(string: *const u16, set: *const u16) -> usize {
    // SAFETY: the caller's strings, read up to their NULs.
    unsafe {
        let set_length = wide_length(set);
        let mut i = 0;
        while at(string, i) != 0 && (0..set_length).any(|j| at(set, j) == at(string, i)) {
            i += 1;
        }
        i
    }
}

/// The string's units mapped in place; answers it.
///
/// # Safety
///
/// `string` is NUL-terminated and writable.
unsafe fn map_in_place(string: *mut u16, map: impl Fn(u16) -> u16) -> *mut u16 {
    let mut i = 0;
    loop {
        // SAFETY: the caller's string, up to its NUL.
        let unit = unsafe { at(string, i) };
        if unit == 0 {
            return string;
        }
        // SAFETY: as above.
        unsafe { string.add(i).write_unaligned(map(unit)) };
        i += 1;
    }
}

/// _wcslwr: the string lowered in place (LC_CTYPE's mapping); answers it.
///
/// # Safety
///
/// `string` is NUL-terminated and writable.
#[unsafe(export_name = "f2k_export__wcslwr")]
pub unsafe extern "C" fn wcslwr(string: *mut u16) -> *mut u16 {
    // SAFETY: the caller's contract.
    unsafe { map_in_place(string, ctype::wide_lower) }
}

/// _wcsupr: the string raised in place; answers it.
///
/// # Safety
///
/// `string` is NUL-terminated and writable.
#[unsafe(export_name = "f2k_export__wcsupr")]
pub unsafe extern "C" fn wcsupr(string: *mut u16) -> *mut u16 {
    // SAFETY: the caller's contract.
    unsafe { map_in_place(string, ctype::wide_upper) }
}

/// A narrow string's bytes, its NUL left out.
///
/// # Safety
///
/// `string` is NUL-terminated, and stays unchanged while the bytes are in use.
pub(crate) unsafe fn narrow<'a>(string: *const u8) -> &'a [u8] {
    // SAFETY: the caller's contract.
    unsafe { core::ffi::CStr::from_ptr(string.cast()) }.to_bytes()
}

/// A narrow string's bytes up to `count` of them, its NUL included when it comes first.
///
/// # Safety
///
/// `string` is NUL-terminated or holds `count` bytes.
unsafe fn bounded<'a>(string: *const u8, count: usize) -> &'a [u8] {
    if count == 0 {
        return &[];
    }
    let mut length = 0;
    // SAFETY: the caller's string, read up to its NUL or `count` bytes.
    while length < count && unsafe { string.add(length).read() } != 0 {
        length += 1;
    }
    // SAFETY: as above: the bytes read, and the NUL when it was reached.
    unsafe { core::slice::from_raw_parts(string, (length + 1).min(count)) }
}

/// strlen.
///
/// # Safety
///
/// `string` is NUL-terminated.
#[unsafe(export_name = "f2k_export_strlen")]
pub unsafe extern "C" fn strlen(string: *const u8) -> usize {
    // SAFETY: the caller's contract.
    unsafe { narrow(string) }.len()
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
        let source = core::ffi::CStr::from_ptr(source.cast()).to_bytes_with_nul();
        core::ptr::copy(source.as_ptr(), destination, source.len());
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
    // SAFETY: the caller's strings and room.
    unsafe { strcpy(destination.add(narrow(destination).len()), source) };
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
    let (string, set) = unsafe { (narrow(string), narrow(set)) };
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
    let bytes = unsafe { core::ffi::CStr::from_ptr(string.cast()) }.to_bytes_with_nul();
    match bytes.iter().rposition(|&byte| byte == c as u8) {
        // SAFETY: inside the string.
        Some(at) => unsafe { string.add(at) },
        None => core::ptr::null(),
    }
}

/// The comparison _strnicmp makes of its strings' bytes (each its NUL included when reached first):
/// each byte lowered in the LC_CTYPE locale, the difference of the first that differ, 0 at a common
/// NUL or past the bytes.
fn compare_folded(a: &[u8], b: &[u8]) -> i32 {
    for (&x, &y) in a.iter().zip(b) {
        let (x, y) = (ctype::byte_lower(x), ctype::byte_lower(y));
        if x != y || x == 0 {
            return x as i32 - y as i32;
        }
    }
    0
}

/// _strnicmp: the first `count` characters' order without regard to case.
///
/// # Safety
///
/// Both strings are NUL-terminated or hold `count` bytes.
#[unsafe(export_name = "f2k_export__strnicmp")]
pub unsafe extern "C" fn strnicmp(a: *const u8, b: *const u8, count: usize) -> i32 {
    // SAFETY: the caller's strings.
    let (a, b) = unsafe { (bounded(a, count), bounded(b, count)) };
    compare_folded(a, b)
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
