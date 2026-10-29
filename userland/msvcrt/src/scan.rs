//! The scanf engine swscanf runs: a wide string read against a wide format, as MSDN's "Format
//! Specification Fields: scanf and wscanf Functions" describes Visual C++ 6's, and as wide's
//! capture pins it.
//!
//! `%[*][width][size]type`: `*` reads without storing; the width bounds the units a field reads;
//! sizes `h` (a short; a narrow string or character), `l` and `w` (a long or a double; a wide
//! string or character), `L` (a double), `I64` (a 64-bit integer). Types `d` `i` (`0x` hex, `0`
//! octal) `u` `o` `x` `X` `p`, `e` `f` `g` `E` `G`, `c` `C` (the width's units, no blank
//! skipped), `s` `S`, `[set]` and `[^set]` (with ranges `a-z`), `n` (the units read so far,
//! not counted), `%%`. A blank in the format skips any blanks of the input; another character must
//! match the input's.
//!
//! The answer is the count of fields stored: a field that does not match ends the scan, and so does
//! the input's end; neither answers EOF (wide's capture: `swscanf(L"", L"%d")` answers 0).
//!
//! The export reads the input and the format once, into slices ([`crate::edge`]).

use crate::ctype;
use crate::edge::WideUnit;
use crate::format::Args;

/// A string's unit at `index`, 0 past its end.
fn unit_at(string: &[WideUnit], index: usize) -> u16 {
    string.get(index).map_or(0, |unit| unit.get())
}

/// The input, read unit by unit (0 at its end).
struct Input<'a> {
    units: &'a [WideUnit],
    read: usize,
}

impl Input<'_> {
    fn peek(&self) -> u16 {
        unit_at(self.units, self.read)
    }

    fn take(&mut self) {
        self.read += 1;
    }

    fn skip_blanks(&mut self) {
        while self.peek() != 0 && ctype::wide_class(self.peek(), ctype::SPACE) != 0 {
            self.take();
        }
    }
}

/// The format, read unit by unit (0 at its end).
struct Format<'a> {
    units: &'a [WideUnit],
    at: usize,
}

impl<'a> Format<'a> {
    /// The unit `ahead` units on (0 past the end).
    fn peek_ahead(&self, ahead: usize) -> u16 {
        unit_at(self.units, self.at + ahead)
    }

    fn peek(&self) -> u16 {
        self.peek_ahead(0)
    }

    fn next(&mut self) -> u16 {
        let unit = self.peek();
        if unit != 0 {
            self.at += 1;
        }
        unit
    }

    /// The units from `start` to where the format is now.
    fn since(&self, start: usize) -> &'a [WideUnit] {
        &self.units[start..self.at]
    }
}

/// A field's size.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Size {
    Default,
    Short,
    Long,
    Quad,
}

/// Scan `input` against `format` (their units, each NUL left out), storing through `args`'
/// pointers; the count of fields stored.
pub fn scan(input: &[WideUnit], format: &[WideUnit], args: &mut impl Args) -> i32 {
    let mut input = Input {
        units: input,
        read: 0,
    };
    let mut format = Format {
        units: format,
        at: 0,
    };
    let mut stored = 0;
    loop {
        let f = format.next();
        if f == 0 {
            break;
        }
        if ctype::wide_class(f, ctype::SPACE) != 0 {
            while ctype::wide_class(format.peek(), ctype::SPACE) != 0 {
                format.next();
            }
            input.skip_blanks();
            continue;
        }
        if f != b'%' as u16 || format.peek() == b'%' as u16 {
            if f == b'%' as u16 {
                format.next();
            }
            if input.peek() != f {
                break;
            }
            input.take();
            continue;
        }
        let mut suppress = false;
        if format.peek() == b'*' as u16 {
            suppress = true;
            format.next();
        }
        let mut width = 0usize;
        while (b'0' as u16..=b'9' as u16).contains(&format.peek()) {
            width = width
                .saturating_mul(10)
                .saturating_add((format.next() - b'0' as u16) as usize);
        }
        let mut size = Size::Default;
        loop {
            match format.peek() {
                0x68 /* h */ => size = Size::Short,
                0x6C /* l */ | 0x77 /* w */ => size = Size::Long,
                0x4C /* L */ => size = Size::Quad,
                0x49 /* I */ => {
                    let (a, b) = (format.peek_ahead(1), format.peek_ahead(2));
                    if (a, b) == (b'6' as u16, b'4' as u16) {
                        format.next();
                        format.next();
                        size = Size::Quad;
                    } else {
                        break;
                    }
                }
                _ => break,
            }
            format.next();
        }
        let conversion = format.next();
        let limit = if width == 0 { usize::MAX } else { width };
        // SAFETY: `Args`' contract: a pointer of the type each field stores, for each field not
        // suppressed.
        let matched = unsafe {
            match conversion as u8 {
                _ if conversion >= 0x80 || conversion == 0 => false,
                b'n' => {
                    if !suppress {
                        store_integer(args.pointer(), size, input.read as u64);
                    }
                    continue;
                }
                b'd' | b'i' | b'u' | b'o' | b'x' | b'X' | b'p' => {
                    input.skip_blanks();
                    match integer(&mut input, conversion as u8, limit) {
                        Some(value) => {
                            if !suppress {
                                let size = if conversion == b'p' as u16 {
                                    Size::Default
                                } else {
                                    size
                                };
                                store_integer(args.pointer(), size, value);
                            }
                            true
                        }
                        None => false,
                    }
                }
                b'e' | b'f' | b'g' | b'E' | b'G' => {
                    input.skip_blanks();
                    match real(&mut input, limit) {
                        Some(value) => {
                            if !suppress {
                                let pointer = args.pointer();
                                if size == Size::Long || size == Size::Quad {
                                    (pointer as *mut f64).write_unaligned(value);
                                } else {
                                    (pointer as *mut f32).write_unaligned(value as f32);
                                }
                            }
                            true
                        }
                        None => false,
                    }
                }
                b'c' | b'C' | b's' | b'S' | b'[' => {
                    let narrow = match size {
                        Size::Short => true,
                        Size::Long => false,
                        _ => conversion == b'C' as u16 || conversion == b'S' as u16,
                    };
                    let set = if conversion == b'[' as u16 {
                        match Set::parse(&mut format) {
                            Some(set) => Some(set),
                            None => break,
                        }
                    } else {
                        None
                    };
                    let character = conversion == b'c' as u16 || conversion == b'C' as u16;
                    if !character && set.is_none() {
                        input.skip_blanks();
                    }
                    let limit = if character && width == 0 { 1 } else { limit };
                    let destination = if suppress { 0 } else { args.pointer() };
                    let mut count = 0;
                    while count < limit {
                        let unit = input.peek();
                        let accepted = unit != 0
                            && match &set {
                                Some(set) => set.contains(unit),
                                None => character || ctype::wide_class(unit, ctype::SPACE) == 0,
                            };
                        if !accepted {
                            break;
                        }
                        if destination != 0 {
                            if narrow {
                                (destination as *mut u8)
                                    .add(count)
                                    .write(ctype::wide_to_byte(unit).unwrap_or(b'?'));
                            } else {
                                (destination as *mut u16).add(count).write_unaligned(unit);
                            }
                        }
                        input.take();
                        count += 1;
                    }
                    // A character field needs all its units; the others one at least.
                    let complete = if character { count == limit } else { count > 0 };
                    if complete && destination != 0 && !character {
                        if narrow {
                            (destination as *mut u8).add(count).write(0);
                        } else {
                            (destination as *mut u16).add(count).write_unaligned(0);
                        }
                    }
                    complete
                }
                _ => false,
            }
        };
        if !matched {
            break;
        }
        if !suppress {
            stored += 1;
        }
    }
    stored
}

/// An integer field: its value, wrapped to 64 bits; none when no digit is there.
fn integer(input: &mut Input, conversion: u8, limit: usize) -> Option<u64> {
    let mut taken = 0;
    let mut negative = false;
    let unit = input.peek();
    if (unit == b'-' as u16 || unit == b'+' as u16) && taken < limit {
        negative = unit == b'-' as u16;
        input.take();
        taken += 1;
    }
    let mut digits = 0;
    let mut radix = match conversion {
        b'o' => 8,
        b'x' | b'X' | b'p' => 16,
        b'i' => 0,
        _ => 10,
    };
    if (radix == 0 || radix == 16) && input.peek() == b'0' as u16 && taken < limit {
        input.take();
        taken += 1;
        digits += 1;
        let unit = input.peek();
        if (unit == b'x' as u16 || unit == b'X' as u16) && taken < limit {
            input.take();
            taken += 1;
            radix = 16;
        } else if radix == 0 {
            radix = 8;
        }
    }
    if radix == 0 {
        radix = 10;
    }
    let mut value = 0u64;
    while taken < limit {
        let Some(digit) = digit_value(input.peek()).filter(|&d| d < radix) else {
            break;
        };
        value = value.wrapping_mul(radix as u64).wrapping_add(digit as u64);
        input.take();
        taken += 1;
        digits += 1;
    }
    (digits > 0).then(|| {
        if negative {
            value.wrapping_neg()
        } else {
            value
        }
    })
}

/// A unit's value as a digit (letters from ten up), ASCII only.
pub fn digit_value(unit: u16) -> Option<u32> {
    match unit {
        0x30..=0x39 => Some((unit - 0x30) as u32),
        0x41..=0x5A => Some((unit - 0x41) as u32 + 10),
        0x61..=0x7A => Some((unit - 0x61) as u32 + 10),
        _ => None,
    }
}

/// An integer stored at `pointer`, its size the field's.
///
/// # Safety
///
/// `pointer` holds an integer of that size.
unsafe fn store_integer(pointer: usize, size: Size, value: u64) {
    // SAFETY: the caller's contract.
    unsafe {
        match size {
            Size::Short => (pointer as *mut u16).write_unaligned(value as u16),
            Size::Quad => (pointer as *mut u64).write_unaligned(value),
            _ => (pointer as *mut u32).write_unaligned(value as u32),
        }
    }
}

/// A floating-point field: `[sign]digits[.digits][e[sign]digits]`, its value from its first 19
/// significant digits scaled by the power of ten; none without a digit.
fn real(input: &mut Input, limit: usize) -> Option<f64> {
    let mut taken = 0;
    let mut accept = |input: &mut Input, test: &dyn Fn(u16) -> bool| {
        let unit = input.peek();
        if taken < limit && unit != 0 && test(unit) {
            input.take();
            taken += 1;
            Some(unit)
        } else {
            None
        }
    };
    let negative = accept(input, &|u| u == b'-' as u16 || u == b'+' as u16) == Some(b'-' as u16);
    let is_digit = |u: u16| (b'0' as u16..=b'9' as u16).contains(&u);
    let (mut mantissa, mut exponent, mut digits) = (0u64, 0i32, 0);
    while let Some(unit) = accept(input, &is_digit) {
        digits += 1;
        if mantissa < 1_000_000_000_000_000_000 {
            mantissa = mantissa * 10 + (unit - b'0' as u16) as u64;
        } else {
            exponent += 1;
        }
    }
    if accept(input, &|u| u == b'.' as u16).is_some() {
        while let Some(unit) = accept(input, &is_digit) {
            digits += 1;
            if mantissa < 1_000_000_000_000_000_000 {
                mantissa = mantissa * 10 + (unit - b'0' as u16) as u64;
                exponent -= 1;
            }
        }
    }
    if digits == 0 {
        return None;
    }
    if accept(input, &|u| u == b'e' as u16 || u == b'E' as u16).is_some() {
        let negative =
            accept(input, &|u| u == b'-' as u16 || u == b'+' as u16) == Some(b'-' as u16);
        let mut power = 0i32;
        while let Some(unit) = accept(input, &is_digit) {
            power = power
                .saturating_mul(10)
                .saturating_add((unit - b'0' as u16) as i32);
        }
        exponent = exponent.saturating_add(if negative { -power } else { power });
    }
    let mut value = mantissa as f64;
    let scale = |value: &mut f64, mut power: i32, up: bool| {
        while power > 0 {
            let step = power.min(22);
            let factor = (0..step).fold(1.0f64, |f, _| f * 10.0);
            if up {
                *value *= factor;
            } else {
                *value /= factor;
            }
            power -= step;
        }
    };
    if exponent >= 0 {
        scale(&mut value, exponent, true);
    } else {
        scale(&mut value, -exponent, false);
    }
    Some(if negative { -value } else { value })
}

/// A `%[` field's set: the format's units between the brackets.
struct Set<'a> {
    negated: bool,
    units: &'a [WideUnit],
}

impl<'a> Set<'a> {
    /// The set after `%[`, the format left past its `]`; none when it never closes.
    fn parse(format: &mut Format<'a>) -> Option<Set<'a>> {
        let mut negated = false;
        if format.peek() == b'^' as u16 {
            negated = true;
            format.next();
        }
        let start = format.at;
        // A `]` first is the set's own.
        if format.peek() == b']' as u16 {
            format.next();
        }
        loop {
            match format.next() {
                0 => return None,
                0x5D /* ] */ => break,
                _ => {}
            }
        }
        let units = format.since(start);
        Some(Set {
            negated,
            units: &units[..units.len() - 1],
        })
    }

    fn contains(&self, unit: u16) -> bool {
        let at = |i: usize| unit_at(self.units, i);
        let length = self.units.len();
        let mut found = false;
        let mut i = 0;
        while i < length {
            let low = at(i);
            if i + 2 < length && at(i + 1) == b'-' as u16 {
                let high = at(i + 2);
                let (low, high) = if low <= high {
                    (low, high)
                } else {
                    (high, low)
                };
                if (low..=high).contains(&unit) {
                    found = true;
                }
                i += 3;
            } else {
                if low == unit {
                    found = true;
                }
                i += 1;
            }
        }
        found != self.negated
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::tests::{units_of, wide, Arg::P, List};

    fn run(input: &str, format: &str, pointers: &[usize]) -> i32 {
        scan(
            &units_of(&wide(input)),
            &units_of(&wide(format)),
            &mut List(pointers.iter().map(|&p| P(p)).collect()),
        )
    }

    fn text(units: &[u16]) -> String {
        String::from_utf16_lossy(&units[..units.iter().position(|&u| u == 0).unwrap()])
    }

    /// wide's scan block, line by line.
    #[test]
    fn swscanf_as_captured() {
        let (mut a, mut b, mut c, mut u);
        (a, b, u) = (-999i32, -999i32, 0u32);
        let (mut w1, mut w2, mut nb) = ([0u16; 32], [0u16; 32], [0u8; 32]);
        let addr = |p: *mut i32| p as usize;
        assert_eq!(
            run(
                "42 -17 0x1F word rest",
                "%d %d %x %s %S",
                &[
                    addr(&mut a),
                    addr(&mut b),
                    &mut u as *mut u32 as usize,
                    w1.as_mut_ptr() as usize,
                    nb.as_mut_ptr() as usize
                ]
            ),
            5
        );
        assert_eq!((a, b, u, text(&w1)), (42, -17, 31, "word".into()));
        assert_eq!(&nb[..5], b"rest\0");

        let (mut w1, mut w2b) = ([0u16; 32], [0u16; 32]);
        a = -999;
        assert_eq!(
            run(
                "abc123def",
                "%[a-z]%d%s",
                &[
                    w1.as_mut_ptr() as usize,
                    addr(&mut a),
                    w2b.as_mut_ptr() as usize
                ]
            ),
            3
        );
        assert_eq!(
            (text(&w1), a, text(&w2b)),
            ("abc".into(), 123, "def".into())
        );

        let mut w1 = [0u16; 32];
        assert_eq!(
            run(
                "key=value with spaces",
                "%[^=]=%[^\n]",
                &[w1.as_mut_ptr() as usize, w2.as_mut_ptr() as usize]
            ),
            2
        );
        assert_eq!(
            (text(&w1), text(&w2)),
            ("key".into(), "value with spaces".into())
        );

        (a, b) = (-999, -999);
        assert_eq!(run("12345", "%3d%d", &[addr(&mut a), addr(&mut b)]), 2);
        assert_eq!((a, b), (123, 45));

        (a, b, c) = (-999, -999, -999);
        assert_eq!(
            run(
                "0x1A 077 -5",
                "%i %i %i",
                &[addr(&mut a), addr(&mut b), addr(&mut c)]
            ),
            3
        );
        assert_eq!((a, b, c), (26, 63, -5));

        (a, b) = (-999, -999);
        assert_eq!(run("10 20", "%d%n", &[addr(&mut a), addr(&mut b)]), 1);
        assert_eq!((a, b), (10, 2));

        (a, b) = (-999, -999);
        assert_eq!(run("7 x", "%d %d", &[addr(&mut a), addr(&mut b)]), 1);
        assert_eq!((a, b), (7, -999));

        for input in ["x", "", "   "] {
            a = -999;
            assert_eq!(run(input, "%d", &[addr(&mut a)]), 0, "{input:?}");
            assert_eq!(a, -999);
        }
        assert_eq!(run("abc", "abd%d", &[addr(&mut a)]), 0);
        assert_eq!(a, -999);
    }

    /// The rest: characters, suppression, floats, `%%`.
    #[test]
    fn other_fields() {
        let mut chars = [0u16; 4];
        let mut x = 0i32;
        let mut f = 0f32;
        let mut d = 0f64;
        assert_eq!(
            run(
                "ab 5% 2.5 -1e3",
                "%2c%*d%% %f %lf",
                &[
                    chars.as_mut_ptr() as usize,
                    &mut f as *mut f32 as usize,
                    &mut d as *mut f64 as usize
                ]
            ),
            3
        );
        assert_eq!(
            (&chars[..2], f, d),
            (&[b'a' as u16, b'b' as u16][..], 2.5, -1000.0)
        );
        assert_eq!(run("9", "%hd", &[&mut x as *mut i32 as usize]), 1);
        assert_eq!(x, 9);
    }
}
