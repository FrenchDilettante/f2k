//! The scanf engine the scanning exports share, narrow and wide: sscanf, fscanf and scanf read
//! bytes against a narrow format, swscanf, fwscanf and wscanf UTF-16 units against a wide one, as
//! MSDN's "Format Specification Fields: scanf and wscanf Functions" describes Visual C++ 6's, and
//! as wide's capture pins it.
//!
//! `%[*][width][size]type`: `*` reads without storing; the width bounds the units a field reads;
//! sizes `h` (a short; a narrow string or character), `l` and `w` (a long or a double; a wide
//! string or character), `L` (a double; on an integer, a long, as VC6's input.c reads it: it only
//! bumps `longone`), `I64` (a 64-bit integer). Types `d` `i` (`0x` hex, `0`
//! octal) `u` `o` `x` `X` `p`, `e` `f` `g` `E` `G`, `c` `C` (the width's units, no blank
//! skipped), `s` `S`, `[set]` and `[^set]` (with ranges `a-z`), `n` (the units read so far,
//! not counted), `%%`. A blank in the format skips any blanks of the input; another character must
//! match the input's.
//!
//! `c`, `s` and `[` store the caller's own width of character and `C` and `S` the other, unless a
//! size says which: sscanf's `%s` stores bytes and its `%S` wide characters, swscanf's the reverse.
//! A narrow scan's input is bytes, its blanks the LC_CTYPE locale's spaces, and a byte it stores as
//! a wide character is converted as mbtowc converts it; a wide scan's input is UTF-16 units, and a
//! unit it stores as a byte is converted as wctomb converts it (`?` for one the code page lacks).
//!
//! The answer is the count of fields stored: a field that does not match ends the scan, and so does
//! the input's end. A narrow scan whose input ends before any conversion matched answers EOF, as
//! VC6's input.c does (MSDN: "EOF ... if the end of the string is reached before the first
//! conversion"); a wide one answers 0 there (wide's capture: `swscanf(L"", L"%d")` answers 0, and
//! so does `L"   "`).
//!
//! The input is a [`Source`]: a string's units, read once into a slice ([`crate::edge`]) where the
//! export takes it ([`Units`]), or a stream's characters (fscanf's, through [`crate::stdio`]).

use crate::ctype;
use crate::format::{Args, Unit};

/// EOF.
const EOF: i32 = -1;

/// Where a scan reads: the input's units (bytes for a narrow scan, UTF-16 units for a wide one),
/// one at a time.
pub trait Source {
    /// The next unit, not taken; none at the input's end.
    fn peek(&mut self) -> Option<u16>;
    /// The unit [`Source::peek`] answered, taken.
    fn take(&mut self);
}

/// A string's units as a scan's input (sscanf's bytes, swscanf's wide units), its NUL left out.
pub struct Units<'a, U> {
    units: &'a [U],
    at: usize,
}

impl<'a, U> Units<'a, U> {
    pub fn new(units: &'a [U]) -> Units<'a, U> {
        Units { units, at: 0 }
    }
}

impl<U: Unit> Source for Units<'_, U> {
    fn peek(&mut self) -> Option<u16> {
        self.units.get(self.at).map(|unit| unit.value() as u16)
    }

    fn take(&mut self) {
        self.at += 1;
    }
}

/// A unit of a string at `index`, 0 past its end.
fn unit_at<U: Unit>(string: &[U], index: usize) -> u16 {
    string.get(index).map_or(0, |unit| unit.value() as u16)
}

/// Whether a unit of a scan of `U`'s width is a blank: a byte's class in the LC_CTYPE locale, or a
/// wide character's.
fn is_space<U: Unit>(unit: u16) -> bool {
    if U::WIDE {
        ctype::wide_class(unit, ctype::SPACE) != 0
    } else {
        ctype::byte_class(unit as u8) & ctype::SPACE != 0
    }
}

/// A unit of a scan of `U`'s width as a byte to store: a byte as it is, a wide character as wctomb
/// converts it (`?` for one the locale's code page lacks).
fn narrow_of<U: Unit>(unit: u16) -> u8 {
    if U::WIDE {
        ctype::wide_to_byte(unit).unwrap_or(b'?')
    } else {
        unit as u8
    }
}

/// A unit of a scan of `U`'s width as a wide character to store: a byte as mbtowc converts it, a
/// wide character as it is.
fn wide_of<U: Unit>(unit: u16) -> u16 {
    if U::WIDE {
        unit
    } else {
        ctype::byte_to_wide(unit as u8)
    }
}

/// The input, read unit by unit: the units taken so far, and whether its end was reached.
struct Input<'s, S> {
    source: &'s mut S,
    read: usize,
    ended: bool,
}

impl<S: Source> Input<'_, S> {
    /// The next unit, not taken; none at the end.
    fn next_unit(&mut self) -> Option<u16> {
        let unit = self.source.peek();
        self.ended |= unit.is_none();
        unit
    }

    /// The next unit, 0 at the end (where no number's character is wanted).
    fn peek(&mut self) -> u16 {
        self.next_unit().unwrap_or(0)
    }

    fn take(&mut self) {
        self.source.take();
        self.read += 1;
    }

    fn skip_blanks<U: Unit>(&mut self) {
        while self.next_unit().is_some_and(is_space::<U>) {
            self.take();
        }
    }
}

/// The format, read unit by unit (0 at its end).
struct Format<'a, U> {
    units: &'a [U],
    at: usize,
}

impl<'a, U: Unit> Format<'a, U> {
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
    fn since(&self, start: usize) -> &'a [U] {
        &self.units[start..self.at]
    }
}

/// A field's size.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Size {
    Default,
    Short,
    Long,
    /// `L`: a double, and on an integer conversion a long (32 bits), never a 64-bit store.
    LongDouble,
    Quad,
}

/// Scan `input` against `format` (its units, its NUL left out), storing through `args`' pointers;
/// the count of fields stored, or EOF for a narrow scan whose input ended before any conversion
/// matched.
pub fn scan<U: Unit>(input: &mut impl Source, format: &[U], args: &mut impl Args) -> i32 {
    let mut input = Input {
        source: input,
        read: 0,
        ended: false,
    };
    let mut format = Format {
        units: format,
        at: 0,
    };
    let mut stored = 0;
    // Conversions that matched, stored or not (VC6's `match`).
    let mut matched_any = false;
    loop {
        let f = format.next();
        if f == 0 {
            break;
        }
        if is_space::<U>(f) {
            while is_space::<U>(format.peek()) {
                format.next();
            }
            input.skip_blanks::<U>();
            continue;
        }
        if f != b'%' as u16 || format.peek() == b'%' as u16 {
            if f == b'%' as u16 {
                format.next();
            }
            if input.next_unit() != Some(f) {
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
                0x4C /* L */ => size = Size::LongDouble,
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
                    input.skip_blanks::<U>();
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
                    input.skip_blanks::<U>();
                    match real(&mut input, limit) {
                        Some(value) => {
                            if !suppress {
                                let pointer = args.pointer();
                                if matches!(size, Size::Long | Size::LongDouble | Size::Quad) {
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
                    // The caller's own width for `c`, `s` and `[`, the other for `C` and `S`.
                    let other = conversion == b'C' as u16 || conversion == b'S' as u16;
                    let narrow = match size {
                        Size::Short => true,
                        Size::Long => false,
                        _ => other == U::WIDE,
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
                        input.skip_blanks::<U>();
                    }
                    let limit = if character && width == 0 { 1 } else { limit };
                    let destination = if suppress { 0 } else { args.pointer() };
                    let mut count = 0;
                    while count < limit {
                        let Some(unit) = input.next_unit() else {
                            break;
                        };
                        let accepted = match &set {
                            Some(set) => set.contains(unit),
                            None => character || !is_space::<U>(unit),
                        };
                        if !accepted {
                            break;
                        }
                        if destination != 0 {
                            if narrow {
                                (destination as *mut u8)
                                    .add(count)
                                    .write(narrow_of::<U>(unit));
                            } else {
                                (destination as *mut u16)
                                    .add(count)
                                    .write_unaligned(wide_of::<U>(unit));
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
        matched_any = true;
        if !suppress {
            stored += 1;
        }
    }
    if !U::WIDE && input.ended && stored == 0 && !matched_any {
        return EOF;
    }
    stored
}

/// An integer field: its value, wrapped to 64 bits; none when no digit is there.
fn integer(input: &mut Input<impl Source>, conversion: u8, limit: usize) -> Option<u64> {
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
fn real(input: &mut Input<impl Source>, limit: usize) -> Option<f64> {
    let mut taken = 0;
    let mut accept = |input: &mut Input<_>, test: &dyn Fn(u16) -> bool| {
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
struct Set<'a, U> {
    negated: bool,
    units: &'a [U],
}

impl<'a, U: Unit> Set<'a, U> {
    /// The set after `%[`, the format left past its `]`; none when it never closes.
    fn parse(format: &mut Format<'a, U>) -> Option<Set<'a, U>> {
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
    use rtl::testing::wide_z;

    use super::*;
    use crate::format::tests::{units_of, Arg::P, List};

    fn run(input: &str, format: &str, pointers: &[usize]) -> i32 {
        scan(
            &mut Units::new(&units_of(&wide_z(input))),
            &units_of(&wide_z(format)),
            &mut List(pointers.iter().map(|&p| P(p)).collect()),
        )
    }

    /// A narrow scan, as sscanf runs it.
    fn run_narrow(input: &[u8], format: &[u8], pointers: &[usize]) -> i32 {
        scan(
            &mut Units::new(input),
            format,
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

    /// runtime's sscanf line: a narrow scan reads as the wide one does, its `%s` storing bytes.
    #[test]
    fn sscanf_as_captured() {
        let (mut x, mut u, mut d, mut i) = (0i32, 0u32, 0f64, 0i32);
        let mut word = [0u8; 32];
        assert_eq!(
            run_narrow(
                b"42 0x1F 3.5 word 077",
                b"%d %x %lf %31s %o",
                &[
                    &mut x as *mut i32 as usize,
                    &mut u as *mut u32 as usize,
                    &mut d as *mut f64 as usize,
                    word.as_mut_ptr() as usize,
                    &mut i as *mut i32 as usize,
                ]
            ),
            5
        );
        assert_eq!((x, u, d, &word[..5], i), (42, 31, 3.5, &b"word\0"[..], 63));
    }

    /// A narrow scan's `c`, `s` and `[` store bytes as they are, `C` and `S` (and `l`) wide
    /// characters as mbtowc converts the bytes, `h` bytes; a byte past ASCII is no blank in the
    /// "C" locale.
    #[test]
    fn a_narrow_scan_stores_its_own_width_unless_told() {
        let _locale = ctype::tests::LOCALE.lock().unwrap();
        // SAFETY: setlocale over a NUL-terminated name.
        unsafe { ctype::setlocale(0, b"C\0".as_ptr()) };
        let (mut n1, mut n2, mut n3) = ([0u8; 8], [0u8; 8], [0u8; 8]);
        let (mut w1, mut w2) = ([0u16; 8], [0u16; 8]);
        assert_eq!(
            run_narrow(
                b"\xE9t\xE9 ab xy \xE9z q",
                b"%s %S %c%C %[^ ]%ls %hs",
                &[
                    n1.as_mut_ptr() as usize,
                    w1.as_mut_ptr() as usize,
                    n2.as_mut_ptr() as usize,
                    w2.as_mut_ptr() as usize,
                    n3.as_mut_ptr() as usize,
                    w2[2..].as_mut_ptr() as usize,
                    n2[2..].as_mut_ptr() as usize,
                ]
            ),
            6
        );
        assert_eq!(&n1[..4], b"\xE9t\xE9\0");
        assert_eq!(&w1[..3], [0x61, 0x62, 0]);
        assert_eq!((n2[0], w2[0]), (b'x', b'y' as u16));
        assert_eq!(&n3[..3], b"\xE9z\0");
        // `%ls` skips the blank and reads "q" wide; `%hs` finds the end, not counted.
        assert_eq!((&w2[2..4], n2[2]), (&[b'q' as u16, 0][..], 0));
    }

    /// A narrow scan whose input ends before any conversion matched answers EOF, as VC6's input.c
    /// does: an empty or blank input, or one that ends at a literal; a conversion that matched,
    /// stored or not, or a character that does not match, answers the count. A wide scan answers 0
    /// there (wide's capture).
    #[test]
    fn a_narrow_scan_answers_eof_at_the_inputs_end() {
        let mut a = -999i32;
        let p = &mut a as *mut i32 as usize;
        for (input, format, answer) in [
            (&b""[..], &b"%d"[..], -1),
            (b"   ", b"%d", -1),
            (b"", b" ", -1),
            (b"", b"abc", -1),
            (b"a", b"a%d", -1),
            (b"", b"", 0),
            (b"x", b"%d", 0),
            (b"5", b"%*d", 0),
            (b"5", b"%*d%d", 0),
            (b"7", b"%d %d", 1),
            (b"7", b"%d", 1),
        ] {
            assert_eq!(
                run_narrow(input, format, &[p, p]),
                answer,
                "sscanf({:?}, {:?})",
                String::from_utf8_lossy(input),
                String::from_utf8_lossy(format)
            );
        }
        for (input, format) in [("", "%d"), ("   ", "%d"), ("", "abc"), ("a", "a%d")] {
            assert_eq!(
                run(input, format, &[p]),
                0,
                "swscanf({input:?}, {format:?})"
            );
        }
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

    /// `L` on an integer conversion stores a long, as VC6's input.c does: four bytes, the word
    /// after the int untouched (an eight-byte store would overrun it); on a float, a double.
    #[test]
    fn l_stores_a_long_into_an_integer_and_a_double_into_a_float() {
        for (input, format, value) in [
            ("5", "%Ld", 5u32),
            ("1f", "%Lx", 0x1F),
            ("-2", "%Li", -2i32 as u32),
            ("7", "%Lu", 7),
        ] {
            let mut slots = [0xCCCC_CCCCu32; 2];
            assert_eq!(
                run(input, format, &[slots.as_mut_ptr() as usize]),
                1,
                "{format}"
            );
            assert_eq!(slots, [value, 0xCCCC_CCCC], "{format}");
        }
        let mut slots = [0xCCCC_CCCCu32; 2];
        assert_eq!(run("ab", "ab%Ln", &[slots.as_mut_ptr() as usize]), 0);
        assert_eq!(slots, [2, 0xCCCC_CCCC], "%Ln");
        let mut d = 0f64;
        assert_eq!(run("2.5", "%Lf", &[&mut d as *mut f64 as usize]), 1);
        assert_eq!(d, 2.5);
    }
}
