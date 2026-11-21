//! Numbers as text: an unsigned value's digits in a radix, at least so many of them (leading
//! zeros), most significant first ([`Digits`]): what printf's integer conversions, GetDateFormat's
//! and GetTimeFormat's numbers, a code page's name, a temporary file's number and a pipe's name
//! write.

/// The case of the digits past nine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Case {
    Upper,
    Lower,
}

/// The most digits a value has: a u64's in base 2.
const MAX_DIGITS: usize = 64;

/// A value's digits, most significant first, held in place.
#[derive(Clone, Copy, Debug)]
pub struct Digits {
    bytes: [u8; MAX_DIGITS],
    start: usize,
}

impl Digits {
    /// `value`'s digits in `radix` (2 to 16): none for zero, then zeros ahead of them up to
    /// `width` digits (64 at most), letters past nine in `case`.
    ///
    /// # Panics
    ///
    /// For a radix outside 2 to 16.
    pub fn new(value: u64, radix: u32, width: usize, case: Case) -> Digits {
        assert!((2..=16).contains(&radix), "a radix of 2 to 16");
        let alphabet: &[u8; 16] = match case {
            Case::Upper => b"0123456789ABCDEF",
            Case::Lower => b"0123456789abcdef",
        };
        let mut bytes = [b'0'; MAX_DIGITS];
        let mut start = MAX_DIGITS;
        let mut rest = value;
        while rest != 0 {
            start -= 1;
            bytes[start] = alphabet[(rest % u64::from(radix)) as usize];
            rest /= u64::from(radix);
        }
        Digits {
            bytes,
            start: start.min(MAX_DIGITS - width.min(MAX_DIGITS)),
        }
    }

    /// The digits, as ASCII bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[self.start..]
    }

    /// The digits, as UTF-16 units.
    pub fn units(&self) -> impl Iterator<Item = u16> + '_ {
        self.as_bytes().iter().map(|&byte| u16::from(byte))
    }

    /// How many digits there are.
    pub fn len(&self) -> usize {
        MAX_DIGITS - self.start
    }

    /// Whether there are none (zero, without a width).
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// `value` in decimal, at least `width` digits (one at least for a zero).
pub fn decimal(value: u64, width: usize) -> Digits {
    Digits::new(value, 10, width.max(1), Case::Upper)
}

/// `value` in hexadecimal, at least `width` digits (one at least for a zero), letters in `case`.
pub fn hex(value: u64, width: usize, case: Case) -> Digits {
    Digits::new(value, 16, width.max(1), case)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_value_has_its_digits_padded_to_the_width() {
        assert_eq!(decimal(0, 0).as_bytes(), b"0");
        assert_eq!(decimal(7, 2).as_bytes(), b"07");
        assert_eq!(decimal(1252, 1).as_bytes(), b"1252");
        assert_eq!(decimal(65001, 3).as_bytes(), b"65001");
        assert_eq!(decimal(u64::MAX, 1).as_bytes(), b"18446744073709551615");
        assert_eq!(hex(0xBEEF, 1, Case::Upper).as_bytes(), b"BEEF");
        assert_eq!(hex(0x1F, 8, Case::Lower).as_bytes(), b"0000001f");
        assert_eq!(hex(0, 1, Case::Upper).as_bytes(), b"0");
        assert_eq!(Digits::new(8, 8, 0, Case::Lower).as_bytes(), b"10");
        assert_eq!(Digits::new(5, 2, 0, Case::Lower).as_bytes(), b"101");
        assert_eq!(decimal(12, 2).units().collect::<Vec<u16>>(), [0x31, 0x32]);
    }

    /// Zero has no digits of its own: only the width's (printf's zero precision writes none).
    #[test]
    fn zero_is_only_its_width() {
        assert!(Digits::new(0, 10, 0, Case::Lower).is_empty());
        assert_eq!(Digits::new(0, 10, 3, Case::Lower).as_bytes(), b"000");
        assert_eq!(Digits::new(1, 2, 100, Case::Lower).len(), 64);
    }
}
