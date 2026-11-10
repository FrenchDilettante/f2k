//! The characters: CharNextA/W and CharPrevA/W, walks over a caller's string.
//!
//! The narrow walks step a byte at a time: the ANSI code page is 1252, single-byte, with no lead
//! bytes (F2K has no double-byte tables), so every character is one byte. The wide walks step a
//! UTF-16 unit at a time, a base character and the combining marks after it together, as the
//! charnext capture shows; a surrogate pair is two steps there, as on Windows 2000.

use rtl::edge::In;

/// Whether `unit` is a combining mark, which belongs to the character before it: the Combining
/// Diacritical Marks (U+0300-U+036F), the marks for symbols (U+20D0-U+20FF) and the combining
/// half marks (U+FE20-U+FE2F).
fn is_combining(unit: u16) -> bool {
    matches!(unit, 0x0300..=0x036F | 0x20D0..=0x20FF | 0xFE20..=0xFE2F)
}

/// The unit at `at`, read from the caller's string.
///
/// # Safety
///
/// `at` lies inside the caller's NUL-terminated string, its NUL included.
unsafe fn unit_at(at: *const u16) -> u16 {
    // SAFETY: the function's contract.
    unsafe { In::new(at) }.read()
}

/// CharNextA: the next character after `at`: the next byte; `at` itself at the NUL.
///
/// # Safety
///
/// `at` points into a NUL-terminated string, as for the platform's.
#[unsafe(export_name = "f2k_export_CharNextA")]
pub unsafe extern "system" fn char_next_a(at: *const u8) -> *const u8 {
    // SAFETY: the caller's string.
    if unsafe { In::new(at) }.read() == 0 {
        at
    } else {
        at.wrapping_add(1)
    }
}

/// CharPrevA: the character before `current` in the string from `start`: the byte before; `start`
/// when `current` is at it (or before it).
#[unsafe(export_name = "f2k_export_CharPrevA")]
pub extern "system" fn char_prev_a(start: *const u8, current: *const u8) -> *const u8 {
    if current > start {
        current.wrapping_sub(1)
    } else {
        start
    }
}

/// CharNextW: the next character after `at`: past its unit and the combining marks after it; `at`
/// itself at the NUL.
///
/// # Safety
///
/// `at` points into a NUL-terminated UTF-16 string, as for the platform's.
#[unsafe(export_name = "f2k_export_CharNextW")]
pub unsafe extern "system" fn char_next_w(at: *const u16) -> *const u16 {
    // SAFETY: the caller's string; the walk stops at its NUL, a unit past a mark that is not.
    unsafe {
        if unit_at(at) == 0 {
            return at;
        }
        let mut next = at.wrapping_add(1);
        while is_combining(unit_at(next)) {
            next = next.wrapping_add(1);
        }
        next
    }
}

/// CharPrevW: the character before `current` in the string from `start`: back over the combining
/// marks before it to their base character; `start` when `current` is at it. Marks that run back
/// to the string's start have no base to step onto: `current` comes back as it is (the charnext
/// capture's U+0301 "x").
///
/// # Safety
///
/// `start` and `current` point into one NUL-terminated UTF-16 string, as for the platform's.
#[unsafe(export_name = "f2k_export_CharPrevW")]
pub unsafe extern "system" fn char_prev_w(start: *const u16, current: *const u16) -> *const u16 {
    if current <= start {
        return start;
    }
    // SAFETY: the caller's string; the walk stays between `start` and `current`.
    unsafe {
        let mut prev = current.wrapping_sub(1);
        while prev > start && is_combining(unit_at(prev)) {
            prev = prev.wrapping_sub(1);
        }
        if is_combining(unit_at(prev)) {
            return current;
        }
        prev
    }
}

#[cfg(test)]
mod tests {
    use std::vec::Vec;

    use super::*;

    /// The offsets a walk with CharNextW visits from the start until it stops moving.
    fn next_walk(text: &[u16]) -> Vec<usize> {
        let base = text.as_ptr();
        let mut at = base;
        let mut seen = std::vec![0];
        loop {
            // SAFETY: inside the test's NUL-terminated string.
            let next = unsafe { char_next_w(at) };
            // SAFETY: both inside the one string.
            seen.push(unsafe { next.offset_from(base) } as usize);
            if next == at {
                return seen;
            }
            at = next;
        }
    }

    /// The offsets a walk with CharPrevW visits from the NUL until it stops moving.
    fn prev_walk(text: &[u16]) -> Vec<usize> {
        let base = text.as_ptr();
        let mut at = base.wrapping_add(text.len() - 1);
        let mut seen = std::vec![text.len() - 1];
        loop {
            // SAFETY: inside the test's NUL-terminated string.
            let prev = unsafe { char_prev_w(base, at) };
            // SAFETY: both inside the one string.
            seen.push(unsafe { prev.offset_from(base) } as usize);
            if prev == at {
                return seen;
            }
            at = prev;
        }
    }

    /// The charnext section's wide walks.
    ///
    /// Pins: user32.CharNextW, user32.CharPrevW
    #[test]
    fn wide_walks_keep_marks_with_their_base() {
        let walk = |units: &[u16]| {
            let mut text = units.to_vec();
            text.push(0);
            (next_walk(&text), prev_walk(&text))
        };
        assert_eq!(
            walk(&[0x61, 0x62, 0x63]),
            (std::vec![0, 1, 2, 3, 3], std::vec![3, 2, 1, 0, 0])
        );
        assert_eq!(walk(&[]), (std::vec![0, 0], std::vec![0, 0]));
        assert_eq!(
            walk(&[0x65, 0x301, 0x78]),
            (std::vec![0, 2, 3, 3], std::vec![3, 2, 0, 0])
        );
        assert_eq!(
            walk(&[0x301, 0x78]),
            (std::vec![0, 1, 2, 2], std::vec![2, 1, 1])
        );
        assert_eq!(
            walk(&[0x61, 0x300, 0x301, 0x62]),
            (std::vec![0, 3, 4, 4], std::vec![4, 3, 0, 0])
        );
        assert_eq!(
            walk(&[0x61, 0xD800, 0xDC00, 0x78]),
            (std::vec![0, 1, 2, 3, 4, 4], std::vec![4, 3, 2, 1, 0, 0])
        );
    }

    /// The narrow walks are a byte at a time.
    ///
    /// Pins: user32.CharNextA, user32.CharPrevA
    #[test]
    fn narrow_walks_step_bytes() {
        let text = b"ab\xe9\0";
        let base = text.as_ptr();
        // SAFETY: inside the test's NUL-terminated string.
        unsafe {
            assert_eq!(char_next_a(base), base.wrapping_add(1));
            assert_eq!(char_next_a(base.wrapping_add(2)), base.wrapping_add(3));
            assert_eq!(char_next_a(base.wrapping_add(3)), base.wrapping_add(3));
        }
        assert_eq!(
            char_prev_a(base, base.wrapping_add(3)),
            base.wrapping_add(2)
        );
        assert_eq!(char_prev_a(base, base), base);
    }
}
