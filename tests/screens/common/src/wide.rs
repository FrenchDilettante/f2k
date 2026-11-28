//! A string's UTF-16 units, NUL-terminated, in a buffer of the program's own.

/// The units a [`Wide`] holds, its NUL included.
const CAPACITY: usize = 64;

/// A string's UTF-16 units, NUL-terminated, in a buffer of the program's own, and its length (the
/// first 63 units, a longer string cut there).
pub struct Wide([u16; CAPACITY], usize);

impl Wide {
    pub fn of(text: &str) -> Wide {
        let mut units = [0u16; CAPACITY];
        let mut length = 0;
        for (unit, value) in units.iter_mut().take(CAPACITY - 1).zip(text.encode_utf16()) {
            *unit = value;
            length += 1;
        }
        Wide(units, length)
    }

    pub fn as_ptr(&self) -> *const u16 {
        self.0.as_ptr()
    }

    /// The units before the NUL.
    pub fn len(&self) -> i32 {
        self.1 as i32
    }

    pub fn is_empty(&self) -> bool {
        self.1 == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_string_is_widened_and_terminated() {
        let wide = Wide::of("Ab");
        assert_eq!((wide.len(), &wide.0[..3]), (2, &[0x41, 0x62, 0][..]));
    }

    #[test]
    fn a_long_string_is_cut_before_its_nul() {
        let wide = Wide::of(&"x".repeat(80));
        assert_eq!((wide.len(), wide.0[CAPACITY - 1]), (63, 0));
    }
}
