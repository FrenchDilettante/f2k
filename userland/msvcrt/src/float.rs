//! A double's decimal digits, as the C runtime's formatter prints them: the value's exact decimal
//! expansion rounded to 17 significant digits (half away from zero), the digits beyond them zeros
//! (Visual C++'s printf before 2015 prints that way: Rick Regan's "Exploring Binary" documents
//! it), then rounded again, the same way, to the conversion's precision.

/// The significant digits the formatter keeps.
const SIGNIFICANT: usize = 17;

/// A finite double's digits: `0.d1 d2 … dn × 10^exponent`, without trailing zeros (none at all
/// for zero).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Decimal {
    pub negative: bool,
    pub digits: [u8; SIGNIFICANT + 1],
    pub count: usize,
    pub exponent: i32,
}

/// What a double is, to the formatter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Value {
    Finite(Decimal),
    /// An infinity, its sign.
    Infinite(bool),
    /// A NaN: its sign, and whether it is the indefinite one (the invalid operations' result, the
    /// sign set and the quiet bit alone), quiet or signaling.
    NaN {
        negative: bool,
        indefinite: bool,
        quiet: bool,
    },
}

impl Decimal {
    /// The digit at `index` (zero past the significant ones).
    pub fn digit(&self, index: i32) -> u8 {
        if index >= 0 && (index as usize) < self.count {
            self.digits[index as usize]
        } else {
            0
        }
    }

    pub fn is_zero(&self) -> bool {
        self.count == 0
    }

    /// The value rounded to `keep` significant digits, half away from zero (`keep` may be zero or
    /// less: a value that rounds to its next power of ten, or to zero).
    pub fn rounded(&self, keep: i32) -> Decimal {
        let mut result = *self;
        if keep >= self.count as i32 {
            return result;
        }
        let up = keep >= 0 && self.digit(keep) >= 5;
        if keep <= 0 {
            result.count = 0;
            if up {
                result.digits[0] = 1;
                result.count = 1;
                result.exponent += 1;
            }
            return result;
        }
        result.count = keep as usize;
        if up {
            let mut at = result.count;
            loop {
                if at == 0 {
                    // Every digit carried: 0.999… became 1.
                    result.digits[0] = 1;
                    result.count = 1;
                    result.exponent += 1;
                    break;
                }
                at -= 1;
                if result.digits[at] == 9 {
                    result.digits[at] = 0;
                } else {
                    result.digits[at] += 1;
                    break;
                }
            }
        }
        while result.count > 0 && result.digits[result.count - 1] == 0 {
            result.count -= 1;
        }
        result
    }
}

/// A big unsigned integer, little-endian 32-bit limbs: enough for 2^1077 (a double's largest
/// integer shifted) and for 10 × 2^1074 (its smallest fraction, scaled by ten).
#[derive(Clone, Copy)]
struct Big {
    limbs: [u32; 36],
}

impl Big {
    fn from_u64(value: u64) -> Big {
        let mut big = Big { limbs: [0; 36] };
        big.limbs[0] = value as u32;
        big.limbs[1] = (value >> 32) as u32;
        big
    }

    fn is_zero(&self) -> bool {
        self.limbs.iter().all(|&limb| limb == 0)
    }

    fn shift_left(&mut self, bits: usize) {
        let (words, bits) = (bits / 32, bits % 32);
        for i in (0..self.limbs.len()).rev() {
            let low = if i >= words { self.limbs[i - words] } else { 0 };
            let lower = if i > words {
                self.limbs[i - words - 1]
            } else {
                0
            };
            self.limbs[i] = if bits == 0 {
                low
            } else {
                (low << bits) | (lower >> (32 - bits))
            };
        }
    }

    fn multiply(&mut self, factor: u32) {
        let mut carry = 0u64;
        for limb in self.limbs.iter_mut() {
            let product = *limb as u64 * factor as u64 + carry;
            *limb = product as u32;
            carry = product >> 32;
        }
    }

    /// The remainder of the division by `divisor`, the quotient left in place.
    fn divide(&mut self, divisor: u32) -> u32 {
        let mut remainder = 0u64;
        for limb in self.limbs.iter_mut().rev() {
            let value = (remainder << 32) | *limb as u64;
            *limb = (value / divisor as u64) as u32;
            remainder = value % divisor as u64;
        }
        remainder as u32
    }

    /// The bits from `bit` up, removed (the fraction's next digit: the value is below ten times
    /// 2^bit, so they are a few bits of one word or two).
    fn take_above(&mut self, bit: usize) -> u32 {
        let (word, shift) = (bit / 32, bit % 32);
        let mut value = self.limbs[word] >> shift;
        if shift != 0 {
            value |= self.limbs[word + 1] << (32 - shift);
        }
        self.limbs[word] &= (1u32 << shift).wrapping_sub(1);
        for limb in self.limbs[word + 1..].iter_mut() {
            *limb = 0;
        }
        value
    }
}

/// The digits of `value`, rounded to 17 significant digits.
pub fn decompose(value: f64) -> Value {
    let bits = value.to_bits();
    let negative = bits >> 63 != 0;
    let biased = ((bits >> 52) & 0x7FF) as i32;
    let fraction = bits & ((1 << 52) - 1);
    if biased == 0x7FF {
        if fraction == 0 {
            return Value::Infinite(negative);
        }
        let quiet = fraction >> 51 != 0;
        return Value::NaN {
            negative,
            indefinite: negative && fraction == 1 << 51,
            quiet,
        };
    }
    let (mantissa, exponent) = if biased == 0 {
        (fraction, -1074)
    } else {
        (fraction | 1 << 52, biased - 1075)
    };
    let mut decimal = Decimal {
        negative,
        digits: [0; SIGNIFICANT + 1],
        count: 0,
        exponent: 0,
    };
    if mantissa == 0 {
        return Value::Finite(decimal);
    }
    // The first 18 significant digits, exact: the 18th rounds the 17th.
    let push = |decimal: &mut Decimal, digit: u8| {
        if decimal.count == 0 && digit == 0 {
            decimal.exponent -= 1;
        } else if decimal.count <= SIGNIFICANT {
            decimal.digits[decimal.count] = digit;
            decimal.count += 1;
        }
    };
    if exponent >= 0 {
        // An integer: its digits from the divisions by 10^9, least significant first.
        let mut big = Big::from_u64(mantissa);
        big.shift_left(exponent as usize);
        let mut chunks = [0u32; 40];
        let mut count = 0;
        while !big.is_zero() {
            chunks[count] = big.divide(1_000_000_000);
            count += 1;
        }
        let mut started = false;
        for &chunk in chunks[..count].iter().rev() {
            let mut divisor = 100_000_000;
            while divisor > 0 {
                let digit = (chunk / divisor % 10) as u8;
                divisor /= 10;
                if !started && digit == 0 {
                    continue;
                }
                started = true;
                decimal.exponent += 1;
                push(&mut decimal, digit);
            }
        }
    } else {
        let shift = (-exponent) as usize;
        let integer = if shift >= 64 { 0 } else { mantissa >> shift };
        if integer != 0 {
            let mut digits = [0u8; 20];
            let (mut rest, mut count) = (integer, 0);
            while rest != 0 {
                digits[count] = (rest % 10) as u8;
                rest /= 10;
                count += 1;
            }
            for &digit in digits[..count].iter().rev() {
                decimal.exponent += 1;
                push(&mut decimal, digit);
            }
        }
        let mut rest = Big::from_u64(if shift >= 64 {
            mantissa
        } else {
            mantissa & ((1 << shift) - 1)
        });
        while !rest.is_zero() && decimal.count <= SIGNIFICANT {
            rest.multiply(10);
            let digit = rest.take_above(shift) as u8;
            push(&mut decimal, digit);
        }
    }
    Value::Finite(decimal.rounded(SIGNIFICANT as i32))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digits(value: f64) -> (String, i32) {
        match decompose(value) {
            Value::Finite(d) => (
                d.digits[..d.count]
                    .iter()
                    .map(|&d| (b'0' + d) as char)
                    .collect(),
                d.exponent,
            ),
            other => panic!("{other:?}"),
        }
    }

    /// Exact values come out whole; others are their expansion rounded to 17 digits.
    #[test]
    fn seventeen_digits() {
        assert_eq!(digits(2.5), ("25".into(), 1));
        assert_eq!(digits(0.0), ("".into(), 0));
        assert_eq!(digits(1e22), ("1".into(), 23));
        assert_eq!(digits(0.1), ("10000000000000001".into(), 0));
        assert_eq!(digits(0.000123), ("12300000000000001".into(), -3));
        assert_eq!(digits(123456789.0), ("123456789".into(), 9));
        assert_eq!(digits(1.0 / 3.0), ("33333333333333331".into(), 0));
        assert_eq!(digits(f64::MAX), ("17976931348623157".into(), 309));
        assert_eq!(digits(5e-324), ("49406564584124654".into(), -323));
        assert_eq!(digits(2.675), ("26749999999999998".into(), 1));
    }

    /// Rounding is half away from zero, and carries into a new leading digit.
    #[test]
    fn rounding() {
        let Value::Finite(d) = decompose(0.5) else {
            panic!()
        };
        let r = d.rounded(0);
        assert_eq!((r.digits[0], r.count, r.exponent), (1, 1, 1));
        let Value::Finite(d) = decompose(9.96) else {
            panic!()
        };
        let r = d.rounded(2);
        assert_eq!((r.digits[0], r.count, r.exponent), (1, 1, 2));
        let Value::Finite(d) = decompose(0.0004) else {
            panic!()
        };
        assert!(d.rounded(-1).is_zero());
    }

    #[test]
    fn specials() {
        assert_eq!(decompose(f64::INFINITY), Value::Infinite(false));
        assert_eq!(decompose(f64::NEG_INFINITY), Value::Infinite(true));
        assert!(matches!(
            decompose(f64::from_bits(0xFFF8_0000_0000_0000)),
            Value::NaN {
                indefinite: true,
                quiet: true,
                ..
            }
        ));
    }
}
