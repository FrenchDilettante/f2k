//! The printf engine every formatted-output export shares, narrow and wide: printf, fprintf,
//! sprintf, _vsnprintf, swprintf, _snwprintf and _vsnwprintf.
//!
//! `%[flags][width][.precision][size]type`, as MSDN's "Format Specification Fields" describes
//! Visual C++ 6's, and as the corpus captures pin it:
//!
//! - flags `-`, `+`, space, `#` (`0x`/`0X` before a nonzero hex number, `0` before octal, the point
//!   kept and trailing zeros too for `g`), `0` (zeros to the width, after the sign or prefix; not
//!   for an integer with a precision);
//! - a width and a precision, as digits or `*` (taken from the arguments; a negative width
//!   left-justifies, a negative precision is none);
//! - sizes `h` (a short: the value truncated; a narrow character or string), `l` and `w` (a long; a
//!   wide character or string), `L`, `I64` and `ll` (a 64-bit integer; `L` a double), `I32`;
//! - types `d` `i` `u` `o` `x` `X`, `c` and `C`, `s` and `S` (the format's own width and the other,
//!   `(null)` for NULL; a precision bounds the units written), `e` `E` `f` `g` `G` (a double, its
//!   exponent of three digits at least, its digits those of [`crate::float`]; an infinity or NaN as
//!   `1.#INF`, `1.#QNAN`, `1.#SNAN`, `-1.#IND`), `p` (eight upper-case hex digits), `n` (the count
//!   so far, stored), `Z` (an ANSI_STRING, or with `w`/`l` a UNICODE_STRING); `%%`.
//!
//! An unknown type writes its letter. A narrow string or character written to a wide output, or a
//! wide one to a narrow output, is converted in the LC_CTYPE locale ([`crate::ctype`]); a wide
//! character the locale's code page lacks ends the string there.

use crate::float::{self, Decimal, Value};

/// The variable arguments, consumed in order.
pub trait Args {
    /// A dword (an `int`, a `long`, a promoted `short` or character).
    fn int(&mut self) -> u32;
    /// A quadword (`__int64`: two dwords, the low one first).
    fn quad(&mut self) -> u64;
    /// A double (two dwords).
    fn double(&mut self) -> f64;
    /// A pointer.
    fn pointer(&mut self) -> usize;
}

/// The caller's variable arguments where its call pushed them (a `va_list`): dwords in order.
pub struct VaList(pub *const u8);

impl VaList {
    fn take<T: Copy>(&mut self) -> T {
        // SAFETY: the caller's argument block (the contract of the export taking it).
        let value = unsafe { (self.0 as *const T).read_unaligned() };
        let size = core::mem::size_of::<T>().max(4);
        // SAFETY: the next argument follows.
        self.0 = unsafe { self.0.add(size) };
        value
    }
}

impl Args for VaList {
    fn int(&mut self) -> u32 {
        self.take()
    }

    fn quad(&mut self) -> u64 {
        self.take()
    }

    fn double(&mut self) -> f64 {
        self.take()
    }

    fn pointer(&mut self) -> usize {
        self.take()
    }
}

/// A code unit of a format or an output: a byte (the narrow functions) or a UTF-16 unit (the
/// wide ones).
pub trait Unit: Copy {
    const WIDE: bool;
    fn value(self) -> u32;
}

impl Unit for u8 {
    const WIDE: bool = false;

    fn value(self) -> u32 {
        self as u32
    }
}

impl Unit for u16 {
    const WIDE: bool = true;

    fn value(self) -> u32 {
        self as u32
    }
}

/// Where the text goes: one unit at a time, of the output's width.
pub trait Output {
    fn put(&mut self, unit: u32);
}

/// One conversion's specification.
#[derive(Default, Clone, Copy)]
struct Spec {
    left: bool,
    plus: bool,
    space: bool,
    alternate: bool,
    zero: bool,
    width: usize,
    precision: Option<usize>,
    short: bool,
    long: bool,
    quad: bool,
}

/// The engine's state: the output and the count of units written.
struct Writer<'a, O: Output> {
    out: &'a mut O,
    count: usize,
}

impl<O: Output> Writer<'_, O> {
    fn put(&mut self, unit: u32) {
        self.out.put(unit);
        self.count += 1;
    }

    fn pad(&mut self, unit: u32, count: usize) {
        for _ in 0..count {
            self.put(unit);
        }
    }

    fn ascii(&mut self, text: &[u8]) {
        for &b in text {
            self.put(b as u32);
        }
    }
}

/// A string argument: where its units are, and how many may be read.
#[derive(Clone, Copy)]
enum Text {
    Narrow(*const u8, Option<usize>),
    Wide(*const u16, Option<usize>),
}

/// Format the NUL-terminated `format` with `args` into `out`; the count of units written.
///
/// # Safety
///
/// `format` is NUL-terminated; `args` holds what its conversions consume, the strings and the
/// pointers among them valid.
pub unsafe fn format<U: Unit, O: Output>(
    format: *const U,
    args: &mut impl Args,
    out: &mut O,
) -> usize {
    let mut w = Writer { out, count: 0 };
    let mut at = format;
    // SAFETY: the caller's NUL-terminated format, read up to its NUL.
    let next = |at: &mut *const U| unsafe {
        let unit = (**at).value();
        if unit != 0 {
            *at = at.add(1);
        }
        unit
    };
    loop {
        let unit = next(&mut at);
        if unit == 0 {
            break;
        }
        if unit != b'%' as u32 {
            w.put(unit);
            continue;
        }
        let mut spec = Spec::default();
        let mut c = next(&mut at);
        loop {
            match c as u8 {
                b'-' if c < 0x80 => spec.left = true,
                b'+' if c < 0x80 => spec.plus = true,
                b' ' if c < 0x80 => spec.space = true,
                b'#' if c < 0x80 => spec.alternate = true,
                b'0' if c < 0x80 => spec.zero = true,
                _ => break,
            }
            c = next(&mut at);
        }
        if c == b'*' as u32 {
            let width = args.int() as i32;
            if width < 0 {
                spec.left = true;
            }
            spec.width = width.unsigned_abs() as usize;
            c = next(&mut at);
        } else {
            while (b'0' as u32..=b'9' as u32).contains(&c) {
                spec.width = spec
                    .width
                    .saturating_mul(10)
                    .saturating_add((c - b'0' as u32) as usize);
                c = next(&mut at);
            }
        }
        if c == b'.' as u32 {
            c = next(&mut at);
            let mut precision = 0usize;
            if c == b'*' as u32 {
                let given = args.int() as i32;
                c = next(&mut at);
                spec.precision = (given >= 0).then_some(given as usize);
            } else {
                while (b'0' as u32..=b'9' as u32).contains(&c) {
                    precision = precision
                        .saturating_mul(10)
                        .saturating_add((c - b'0' as u32) as usize);
                    c = next(&mut at);
                }
                spec.precision = Some(precision);
            }
        }
        // The size.
        loop {
            match c {
                0x68 /* h */ => spec.short = true,
                0x6C /* l */ => {
                    if spec.long {
                        spec.quad = true;
                    }
                    spec.long = true;
                }
                0x77 /* w */ => spec.long = true,
                0x4C /* L */ => spec.quad = true,
                0x49 /* I */ => {
                    // SAFETY: the format's next units, read before its NUL.
                    let (a, b) = unsafe { ((*at).value(), if (*at).value() != 0 { (*at.add(1)).value() } else { 0 }) };
                    if (a, b) == (b'6' as u32, b'4' as u32) {
                        spec.quad = true;
                        next(&mut at);
                        next(&mut at);
                    } else if (a, b) == (b'3' as u32, b'2' as u32) {
                        next(&mut at);
                        next(&mut at);
                    } else {
                        break;
                    }
                }
                _ => break,
            }
            c = next(&mut at);
        }
        if c == 0 {
            break;
        }
        // SAFETY: the caller's arguments, as the conversion reads them.
        unsafe { convert::<U, O>(&mut w, c, spec, args) };
    }
    w.count
}

/// Whether a `c`/`s` conversion reads the other width than the output's: `C`/`S`, and `h` for a
/// wide output, `l`/`w` for a narrow one.
fn other_width<U: Unit>(conversion: u32, spec: &Spec) -> bool {
    let upper = conversion == b'C' as u32 || conversion == b'S' as u32;
    let wide_argument = if spec.short {
        false
    } else if spec.long {
        true
    } else {
        U::WIDE != upper
    };
    wide_argument != U::WIDE
}

/// One conversion.
///
/// # Safety
///
/// As [`format`]'s.
unsafe fn convert<U: Unit, O: Output>(w: &mut Writer<O>, c: u32, spec: Spec, args: &mut impl Args) {
    match c as u8 {
        _ if c >= 0x80 => w.put(c),
        b'%' => w.put(c),
        b'd' | b'i' => {
            let value = if spec.quad {
                args.quad() as i64
            } else if spec.short {
                args.int() as i16 as i64
            } else {
                args.int() as i32 as i64
            };
            integer(w, spec, value.unsigned_abs(), value < 0, 10, false);
        }
        b'u' | b'o' | b'x' | b'X' => {
            let value = if spec.quad {
                args.quad()
            } else if spec.short {
                args.int() as u16 as u64
            } else {
                args.int() as u64
            };
            let radix = match c as u8 {
                b'u' => 10,
                b'o' => 8,
                _ => 16,
            };
            integer(w, spec, value, false, radix, c == b'X' as u32);
        }
        b'p' => {
            let spec = Spec {
                precision: Some(8),
                alternate: false,
                ..spec
            };
            integer(w, spec, args.pointer() as u64, false, 16, true);
        }
        b'c' | b'C' => {
            let value = args.int();
            let unit = if other_width::<U>(c, &spec) {
                if U::WIDE {
                    Some(crate::ctype::byte_to_wide(value as u8) as u32)
                } else {
                    crate::ctype::wide_to_byte(value as u16).map(|b| b as u32)
                }
            } else if U::WIDE {
                Some(value & 0xFFFF)
            } else {
                Some(value & 0xFF)
            };
            let length = unit.is_some() as usize;
            let fill = if spec.zero && !spec.left { b'0' } else { b' ' } as u32;
            if !spec.left {
                w.pad(fill, spec.width.saturating_sub(length));
            }
            if let Some(unit) = unit {
                w.put(unit);
            }
            if spec.left {
                w.pad(b' ' as u32, spec.width.saturating_sub(length));
            }
        }
        b's' | b'S' => {
            let pointer = args.pointer();
            let text = if pointer == 0 {
                // "(null)", in the output's own width.
                Text::Narrow(c"(null)".as_ptr().cast(), None)
            } else if other_width::<U>(c, &spec) != U::WIDE {
                Text::Wide(pointer as *const u16, None)
            } else {
                Text::Narrow(pointer as *const u8, None)
            };
            // SAFETY: the caller's string.
            unsafe { string::<U, O>(w, spec, text) };
        }
        b'Z' => {
            // ANSI_STRING / UNICODE_STRING: Length (bytes), MaximumLength, Buffer.
            let pointer = args.pointer();
            // SAFETY: the caller's counted string, when there is one.
            let text = unsafe {
                if pointer == 0 || (pointer as *const usize).add(1).read_unaligned() == 0 {
                    Text::Narrow(c"(null)".as_ptr().cast(), None)
                } else {
                    let length = (pointer as *const u16).read_unaligned() as usize;
                    let buffer = (pointer as *const usize).add(1).read_unaligned();
                    if spec.long {
                        Text::Wide(buffer as *const u16, Some(length / 2))
                    } else {
                        Text::Narrow(buffer as *const u8, Some(length))
                    }
                }
            };
            // SAFETY: as above.
            unsafe { string::<U, O>(w, spec, text) };
        }
        b'n' => {
            let pointer = args.pointer();
            if pointer != 0 {
                // SAFETY: the caller's int.
                unsafe {
                    if spec.short {
                        (pointer as *mut u16).write_unaligned(w.count as u16)
                    } else {
                        (pointer as *mut u32).write_unaligned(w.count as u32)
                    }
                };
            }
        }
        b'e' | b'E' | b'f' | b'g' | b'G' => real(w, spec, args.double(), c as u8),
        _ => w.put(c),
    }
}

/// An integer conversion: `magnitude`'s digits in `radix`, signed by `negative`.
fn integer<O: Output>(
    w: &mut Writer<O>,
    spec: Spec,
    magnitude: u64,
    negative: bool,
    radix: u64,
    upper: bool,
) {
    let mut digits = [0u8; 64];
    let mut count = 0;
    let mut rest = magnitude;
    while rest != 0 {
        let digit = (rest % radix) as u8;
        digits[count] = match digit {
            0..=9 => b'0' + digit,
            _ if upper => b'A' + digit - 10,
            _ => b'a' + digit - 10,
        };
        count += 1;
        rest /= radix;
    }
    let precision = spec.precision.unwrap_or(1);
    let mut zeros = precision.saturating_sub(count);
    if radix == 8 && spec.alternate && magnitude != 0 && zeros == 0 {
        zeros = 1;
    }
    let prefix: &[u8] = if negative {
        b"-"
    } else if radix == 10 && spec.plus {
        b"+"
    } else if radix == 10 && spec.space {
        b" "
    } else if radix == 16 && spec.alternate && magnitude != 0 {
        if upper {
            b"0X"
        } else {
            b"0x"
        }
    } else {
        b""
    };
    let length = prefix.len() + zeros + count;
    let fill = spec.width.saturating_sub(length);
    let zero_fill = spec.zero && !spec.left && spec.precision.is_none();
    if !spec.left && !zero_fill {
        w.pad(b' ' as u32, fill);
    }
    w.ascii(prefix);
    if zero_fill {
        w.pad(b'0' as u32, fill);
    }
    w.pad(b'0' as u32, zeros);
    for &d in digits[..count].iter().rev() {
        w.put(d as u32);
    }
    if spec.left {
        w.pad(b' ' as u32, fill);
    }
}

/// The units of a string argument as the output takes them, at most `limit` (each converted to the
/// output's width), handed to `each`; their count.
///
/// # Safety
///
/// The string is readable to its NUL or its length.
unsafe fn units<U: Unit>(text: Text, limit: Option<usize>, mut each: impl FnMut(u32)) -> usize {
    let limit = limit.unwrap_or(usize::MAX);
    let mut count = 0;
    match text {
        Text::Narrow(p, length) => {
            let mut i = 0;
            while count < limit && length.is_none_or(|n| i < n) {
                // SAFETY: the caller's contract.
                let byte = unsafe { p.add(i).read() };
                if byte == 0 && length.is_none() {
                    break;
                }
                each(if U::WIDE {
                    crate::ctype::byte_to_wide(byte) as u32
                } else {
                    byte as u32
                });
                count += 1;
                i += 1;
            }
        }
        Text::Wide(p, length) => {
            let mut i = 0;
            while count < limit && length.is_none_or(|n| i < n) {
                // SAFETY: the caller's contract.
                let unit = unsafe { p.add(i).read_unaligned() };
                if unit == 0 && length.is_none() {
                    break;
                }
                if U::WIDE {
                    each(unit as u32);
                } else {
                    match crate::ctype::wide_to_byte(unit) {
                        Some(byte) => each(byte as u32),
                        None => break,
                    }
                }
                count += 1;
                i += 1;
            }
        }
    }
    count
}

/// A string conversion, padded to the width.
///
/// # Safety
///
/// As [`units`]'.
unsafe fn string<U: Unit, O: Output>(w: &mut Writer<O>, spec: Spec, text: Text) {
    // SAFETY: the caller's contract (the first pass counts, the second writes).
    let length = unsafe { units::<U>(text, spec.precision, |_| {}) };
    let fill = spec.width.saturating_sub(length);
    let fill_unit = if spec.zero && !spec.left { b'0' } else { b' ' } as u32;
    if !spec.left {
        w.pad(fill_unit, fill);
    }
    // SAFETY: as above.
    unsafe { units::<U>(text, spec.precision, |unit| w.put(unit)) };
    if spec.left {
        w.pad(b' ' as u32, fill);
    }
}

/// The text of a floating-point conversion, built before it is padded.
struct Number {
    text: [u8; 400],
    length: usize,
}

impl Number {
    fn push(&mut self, b: u8) {
        if self.length < self.text.len() {
            self.text[self.length] = b;
            self.length += 1;
        }
    }
}

/// `e`, `E`, `f`, `g`, `G`.
fn real<O: Output>(w: &mut Writer<O>, spec: Spec, value: f64, conversion: u8) {
    let mut n = Number {
        text: [0; 400],
        length: 0,
    };
    let precision = spec.precision.unwrap_or(6);
    let upper = conversion.is_ascii_uppercase();
    let negative = match float::decompose(value) {
        Value::Finite(decimal) => {
            match conversion.to_ascii_lowercase() {
                b'f' => fixed(&mut n, &decimal, precision as i32, spec.alternate),
                b'e' => exponential(
                    &mut n,
                    &decimal.rounded(precision as i32 + 1),
                    precision,
                    spec.alternate,
                    upper,
                ),
                _ => {
                    let significant = precision.max(1) as i32;
                    let rounded = decimal.rounded(significant);
                    let exponent = if rounded.is_zero() {
                        0
                    } else {
                        rounded.exponent - 1
                    };
                    if exponent < -4 || exponent >= significant {
                        exponential(
                            &mut n,
                            &rounded,
                            (significant - 1) as usize,
                            spec.alternate,
                            upper,
                        );
                    } else {
                        fixed(&mut n, &rounded, significant - 1 - exponent, spec.alternate);
                    }
                    if !spec.alternate {
                        trim(&mut n);
                    }
                }
            }
            decimal.negative
        }
        special => {
            let (negative, name): (bool, &[u8]) = match special {
                Value::Infinite(negative) => (negative, b"1.#INF"),
                Value::NaN {
                    indefinite: true, ..
                } => (true, b"1.#IND"),
                Value::NaN {
                    negative,
                    quiet: true,
                    ..
                } => (negative, b"1.#QNAN"),
                Value::NaN { negative, .. } => (negative, b"1.#SNAN"),
                Value::Finite(_) => unreachable!(),
            };
            for &b in name {
                n.push(b);
            }
            // The precision's digits after the point, zeros past the name's.
            for _ in name.len() - 2..precision {
                n.push(b'0');
            }
            negative
        }
    };
    let sign: &[u8] = if negative {
        b"-"
    } else if spec.plus {
        b"+"
    } else if spec.space {
        b" "
    } else {
        b""
    };
    let length = sign.len() + n.length;
    let fill = spec.width.saturating_sub(length);
    if !spec.left && !spec.zero {
        w.pad(b' ' as u32, fill);
    }
    w.ascii(sign);
    if !spec.left && spec.zero {
        w.pad(b'0' as u32, fill);
    }
    for &b in &n.text[..n.length] {
        w.put(b as u32);
    }
    if spec.left {
        w.pad(b' ' as u32, fill);
    }
}

/// `f`: the integer digits, the point and `precision` digits.
fn fixed(n: &mut Number, decimal: &Decimal, precision: i32, alternate: bool) {
    let rounded = decimal.rounded(decimal.exponent + precision);
    if rounded.exponent > 0 && !rounded.is_zero() {
        for i in 0..rounded.exponent {
            n.push(b'0' + rounded.digit(i));
        }
    } else {
        n.push(b'0');
    }
    if precision > 0 || alternate {
        n.push(b'.');
    }
    for j in 0..precision {
        let index = if rounded.is_zero() {
            -1
        } else {
            rounded.exponent + j
        };
        n.push(b'0' + rounded.digit(index));
    }
}

/// `e`: one digit, the point, `precision` digits, the exponent (three digits at least).
fn exponential(n: &mut Number, rounded: &Decimal, precision: usize, alternate: bool, upper: bool) {
    n.push(b'0' + rounded.digit(0));
    if precision > 0 || alternate {
        n.push(b'.');
    }
    for i in 1..=precision as i32 {
        n.push(b'0' + rounded.digit(i));
    }
    n.push(if upper { b'E' } else { b'e' });
    let exponent = if rounded.is_zero() {
        0
    } else {
        rounded.exponent - 1
    };
    n.push(if exponent < 0 { b'-' } else { b'+' });
    let magnitude = exponent.unsigned_abs();
    n.push(b'0' + (magnitude / 100 % 10) as u8);
    n.push(b'0' + (magnitude / 10 % 10) as u8);
    n.push(b'0' + (magnitude % 10) as u8);
}

/// `g` without `#`: the fraction's trailing zeros, and a point left bare, removed.
fn trim(n: &mut Number) {
    let text = &n.text[..n.length];
    let Some(point) = text.iter().position(|&b| b == b'.') else {
        return;
    };
    let end = text
        .iter()
        .position(|&b| b == b'e' || b == b'E')
        .unwrap_or(n.length);
    let mut keep = end;
    while keep > point + 1 && text[keep - 1] == b'0' {
        keep -= 1;
    }
    if keep == point + 1 {
        keep = point;
    }
    let removed = end - keep;
    n.text.copy_within(end..n.length, keep);
    n.length -= removed;
}

/// An output into a buffer of `capacity` units: what fits is written, the rest counted.
pub struct Buffer<U> {
    pub at: *mut U,
    pub capacity: usize,
    pub written: usize,
}

impl Output for Buffer<u8> {
    fn put(&mut self, unit: u32) {
        if self.written < self.capacity {
            // SAFETY: inside the caller's buffer.
            unsafe { self.at.add(self.written).write(unit as u8) };
        }
        self.written += 1;
    }
}

impl Output for Buffer<u16> {
    fn put(&mut self, unit: u32) {
        if self.written < self.capacity {
            // SAFETY: inside the caller's buffer.
            unsafe { self.at.add(self.written).write_unaligned(unit as u16) };
        }
        self.written += 1;
    }
}

/// The bounded formatters' convention (_vsnprintf, _snwprintf, _vsnwprintf): the count when the
/// text fits `count` units, terminated when there is room left for the NUL; -1 when it does not
/// fit, `count` units written and no NUL.
///
/// # Safety
///
/// `buffer` holds `count` units; the format and the arguments are [`format`]'s.
pub unsafe fn bounded<U: Unit>(
    buffer: *mut U,
    count: usize,
    text: *const U,
    args: &mut impl Args,
) -> i32
where
    Buffer<U>: Output,
{
    let mut out = Buffer {
        at: buffer,
        capacity: count,
        written: 0,
    };
    // SAFETY: the caller's contract.
    let length = unsafe { format(text, args, &mut out) };
    if length > count {
        return -1;
    }
    if length < count {
        // SAFETY: inside the buffer.
        unsafe { out.put_terminator(length) };
    }
    length as i32
}

impl<U> Buffer<U> {
    /// The NUL after `length` units.
    ///
    /// # Safety
    ///
    /// `length` is inside the buffer.
    unsafe fn put_terminator(&mut self, length: usize) {
        // SAFETY: the caller's contract; a zero unit of the buffer's width.
        unsafe { core::ptr::write_bytes(self.at.add(length), 0, 1) };
    }
}

/// The unbounded formatters' (sprintf, swprintf): the text and its NUL; the count.
///
/// # Safety
///
/// `buffer` has room for the text; the format and the arguments are [`format`]'s.
pub unsafe fn unbounded<U: Unit>(buffer: *mut U, text: *const U, args: &mut impl Args) -> i32
where
    Buffer<U>: Output,
{
    let mut out = Buffer {
        at: buffer,
        capacity: usize::MAX,
        written: 0,
    };
    // SAFETY: the caller's contract.
    let length = unsafe { format(text, args, &mut out) };
    // SAFETY: as above.
    unsafe { out.put_terminator(length) };
    length as i32
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// One argument, as the host tests hand them over.
    #[derive(Clone, Copy)]
    pub enum Arg {
        I(u32),
        Q(u64),
        D(f64),
        P(usize),
    }

    pub struct List(pub std::collections::VecDeque<Arg>);

    impl Args for List {
        fn int(&mut self) -> u32 {
            match self.0.pop_front() {
                Some(Arg::I(v)) => v,
                Some(Arg::P(p)) => p as u32,
                _ => panic!("an int expected"),
            }
        }

        fn quad(&mut self) -> u64 {
            match self.0.pop_front() {
                Some(Arg::Q(v)) => v,
                _ => panic!("a quad expected"),
            }
        }

        fn double(&mut self) -> f64 {
            match self.0.pop_front() {
                Some(Arg::D(v)) => v,
                _ => panic!("a double expected"),
            }
        }

        fn pointer(&mut self) -> usize {
            match self.0.pop_front() {
                Some(Arg::P(p)) => p,
                _ => panic!("a pointer expected"),
            }
        }
    }

    pub fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain([0]).collect()
    }

    /// A narrow format's text.
    fn narrow(format: &str, args: &[Arg]) -> String {
        let mut text = format.as_bytes().to_vec();
        text.push(0);
        let mut out = vec![0u8; 512];
        // SAFETY: a NUL-terminated format, a buffer large enough.
        let n = unsafe {
            unbounded(
                out.as_mut_ptr(),
                text.as_ptr(),
                &mut List(args.iter().copied().collect()),
            )
        };
        String::from_utf8_lossy(&out[..n as usize]).into_owned()
    }

    /// A wide format's text, its count.
    fn widef(format: &str, args: &[Arg]) -> (i32, String) {
        let text = wide(format);
        let mut out = vec![0u16; 512];
        // SAFETY: as above.
        let n = unsafe {
            unbounded(
                out.as_mut_ptr(),
                text.as_ptr(),
                &mut List(args.iter().copied().collect()),
            )
        };
        (n, String::from_utf16_lossy(&out[..n as usize]))
    }

    use Arg::*;

    /// wide's format block: swprintf's integers, flags, widths, strings and characters.
    #[test]
    fn swprintf_as_captured() {
        let neg = |v: i32| I(v as u32);
        assert_eq!(
            widef(
                "%d|%u|%x|%X|%o|%i|%%",
                &[neg(-42), I(42), I(255), I(255), I(8), neg(-7)]
            ),
            (20, "-42|42|ff|FF|10|-7|%".into())
        );
        assert_eq!(
            widef(
                "[%5d][%-5d][%05d][%+d][% d][%.3d][%5.3d][%*d][%#x][%#X][%#o][%lu][%hd]",
                &[I(42), I(42), I(42), I(42), I(42), I(7), I(7), I(4), I(9), I(255), I(255), I(8), I(u32::MAX), I(70000)]
            ),
            (84, "[   42][42   ][00042][+42][ 42][007][  007][   9][0xff][0XFF][010][4294967295][4464]".into())
        );
        let w = wide("wide");
        let ab = wide("ab");
        let narrow_text = b"narrow\0";
        let mixed: Vec<u16> = vec![
            0xE9, 0xC9, 0xFF, 0x101, 0x100, 0x3B1, 0x391, 0x436, 0x416, 0,
        ];
        let (n, text) = widef(
            "%s|%S|%hs|%ls|%.2s|%5s|%-5s|%s",
            &[
                P(w.as_ptr() as usize),
                P(narrow_text.as_ptr() as usize),
                P(narrow_text.as_ptr() as usize),
                P(w.as_ptr() as usize),
                P(w.as_ptr() as usize),
                P(ab.as_ptr() as usize),
                P(ab.as_ptr() as usize),
                P(mixed.as_ptr() as usize),
            ],
        );
        assert_eq!(n, 48);
        assert_eq!(text, "wide|narrow|narrow|wide|wi|   ab|ab   |éÉÿāĀαΑжЖ");
        assert_eq!(
            widef(
                "%c|%C|%hc|%lc|%c",
                &[
                    I('a' as u32),
                    I('b' as u32),
                    I('c' as u32),
                    I('d' as u32),
                    I(0xE9)
                ]
            ),
            (9, "a|b|c|d|é".into())
        );
        let cafe = b"caf\xE9\0";
        let ete = b"\xE9t\xE9\0";
        assert_eq!(
            widef(
                "%S|%hs",
                &[P(cafe.as_ptr() as usize), P(ete.as_ptr() as usize)]
            ),
            (8, "café|été".into())
        );
        assert_eq!(widef("", &[]), (0, "".into()));
    }

    /// The bounded forms: -1 and no terminator when the text overflows, the count and no
    /// terminator for an exact fit, the terminator when there is room.
    #[test]
    fn bounded_as_captured() {
        let run = |count: usize, format: &str, args: &[Arg]| {
            let text = wide(format);
            let mut out = vec![b'#' as u16; 20];
            // SAFETY: a buffer of 20 units, `count` at most.
            let n = unsafe {
                bounded(
                    out.as_mut_ptr(),
                    count,
                    text.as_ptr(),
                    &mut List(args.iter().copied().collect()),
                )
            };
            let shown: String = out[..9]
                .iter()
                .map(|&u| {
                    if u == 0 {
                        '0'
                    } else {
                        char::from_u32(u as u32).unwrap()
                    }
                })
                .collect();
            (n, shown)
        };
        let over = wide("overflowing");
        let abcde = wide("abcde");
        let tail = wide("tail");
        assert_eq!(
            run(5, "%s", &[P(over.as_ptr() as usize)]),
            (-1, "overf####".into())
        );
        assert_eq!(
            run(5, "%s", &[P(abcde.as_ptr() as usize)]),
            (5, "abcde####".into())
        );
        assert_eq!(
            run(6, "%s", &[P(abcde.as_ptr() as usize)]),
            (5, "abcde0###".into())
        );
        assert_eq!(run(0, "abc", &[]), (-1, "#########".into()));
        assert_eq!(run(10, "%d-%d", &[I(12), I(345)]), (6, "12-3450##".into()));
        assert_eq!(
            run(6, "%d|%s", &[I(1234), P(tail.as_ptr() as usize)]),
            (-1, "1234|t###".into())
        );
        assert_eq!(
            run(9, "%d|%s", &[I(1234), P(tail.as_ptr() as usize)]),
            (9, "1234|tail".into())
        );
    }

    /// Doubles, as Visual C++ 6 prints them; the narrow side's other conversions.
    #[test]
    fn narrow_conversions() {
        assert_eq!(narrow("%5.2f|%c", &[D(2.5), I('z' as u32)]), " 2.50|z");
        assert_eq!(
            narrow("%f %e %g %G", &[D(1.5), D(1234.5), D(0.0001), D(1e20)]),
            "1.500000 1.234500e+003 0.0001 1E+020"
        );
        assert_eq!(
            narrow("%.0f %.1f %.2f", &[D(0.5), D(0.25), D(2.675)]),
            "1 0.3 2.67"
        );
        assert_eq!(
            narrow("%g %g %#g %g", &[D(100000.0), D(1000000.0), D(1.0), D(0.0)]),
            "100000 1e+006 1.00000 0"
        );
        assert_eq!(
            narrow("%+08.3f|%-8.1e|", &[D(-3.14159), D(0.0)]),
            "-003.142|0.0e+000|"
        );
        assert_eq!(narrow("%f", &[D(f64::INFINITY)]), "1.#INF00");
        assert_eq!(
            narrow("%f", &[D(f64::from_bits(0xFFF8_0000_0000_0000))]),
            "-1.#IND00"
        );
        assert_eq!(narrow("%.20f", &[D(0.1)]), "0.10000000000000001000");
        assert_eq!(
            narrow(
                "%p|%08lX|%lX|%02X",
                &[P(0x12FF7C), I(0xC0000005), I(0x10), I(5)]
            ),
            "0012FF7C|C0000005|10|05"
        );
        assert_eq!(
            narrow(
                "%I64d %I64x %lld",
                &[Q(-5i64 as u64), Q(0x1_0000_0000), Q(7)]
            ),
            "-5 100000000 7"
        );
        let w = wide("w\u{E9}");
        assert_eq!(
            narrow(
                "[%S][%ls][%5.1s][%s]",
                &[
                    P(w.as_ptr() as usize),
                    P(w.as_ptr() as usize),
                    P(b"ab\0".as_ptr() as usize),
                    P(0)
                ]
            ),
            "[w\u{FFFD}][w\u{FFFD}][    a][(null)]"
        );
        let mut stored = 0u32;
        assert_eq!(
            narrow("abc%n%y", &[P(&mut stored as *mut u32 as usize)]),
            "abcy"
        );
        assert_eq!(stored, 3);
        assert_eq!(
            narrow(
                "%-4d|%04d|%x|%#o|%.0d|",
                &[I(7), I(-7i32 as u32), I(0), I(0), I(0)]
            ),
            "7   |-007|0|0||"
        );
    }
}
