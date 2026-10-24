//! The printf conversions ntdll's DbgPrint formats its text with (the C runtime's, as Windows
//! 2000's `_vsnprintf` serves them): `%[flags][width][.precision][length]conversion`.
//!
//! - flags `-` (left-justified), `+` and space (a sign for positive numbers), `#` (`0x`, `0X` or
//!   `0` before a nonzero number), `0` (zeros to the width; not with `-` or a precision);
//! - a width and a precision, as digits or `*` (taken from the arguments; a negative width
//!   left-justifies);
//! - lengths `h`, `l`, `w` (wide: `%ws`, `%wc`, `%wZ`), `ll` and `I64` (a 64-bit integer), `I32`;
//! - conversions `d` `i` `u` `o` `x` `X`, `c` and `C` (a wide character), `s` and `S` (a wide
//!   string; `(null)` for NULL; a precision bounds the units), `Z` (an ANSI_STRING, or with `w` a
//!   UNICODE_STRING, by pointer), `p` (eight hex digits), `%`.
//!
//! A wide unit is written as the byte it is below 0x100, as `?` above. Anything else (floating
//! point, `%n`, an unknown conversion) is [`Unsupported`]: DbgPrint takes its stub path, the
//! format and the offending conversion logged.

use crate::stub::Memory;

/// The variable arguments, consumed in order: a dword, a quadword (two dwords on the stack), a
/// pointer (a dword on the target; the host tests' are their own size).
pub trait Args {
    fn next_u32(&mut self) -> u32;
    fn next_u64(&mut self) -> u64;
    fn next_ptr(&mut self) -> usize;
}

/// Where the text goes: bytes, as the format and the arguments give them.
pub trait Sink {
    fn put(&mut self, bytes: &[u8]);
}

/// A conversion the formatter does not serve: the offset of its `%` in the format, and its length.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Unsupported {
    pub at: usize,
    pub length: usize,
}

/// One conversion's specification.
#[derive(Default)]
struct Spec {
    left: bool,
    plus: bool,
    space: bool,
    alternate: bool,
    zero: bool,
    width: usize,
    precision: Option<usize>,
    wide: bool,
    long_long: bool,
}

/// Format `format` (its bytes, to its NUL or its end) with `args` into `out`. Strings are read
/// through `memory`: one that cannot be read shows as `(unreadable)`.
pub fn format(
    format: &[u8],
    args: &mut impl Args,
    memory: &impl Memory,
    out: &mut impl Sink,
) -> Result<(), Unsupported> {
    let format = format.split(|&b| b == 0).next().unwrap_or(&[]);
    let mut i = 0;
    while i < format.len() {
        let start = i;
        let Some(offset) = format[i..].iter().position(|&b| b == b'%') else {
            out.put(&format[i..]);
            break;
        };
        out.put(&format[i..i + offset]);
        i += offset + 1;
        let unsupported = |end: usize| Unsupported {
            at: start + offset,
            length: end.min(format.len()) - (start + offset),
        };
        let mut spec = Spec::default();
        while let Some(&flag) = format.get(i) {
            match flag {
                b'-' => spec.left = true,
                b'+' => spec.plus = true,
                b' ' => spec.space = true,
                b'#' => spec.alternate = true,
                b'0' => spec.zero = true,
                _ => break,
            }
            i += 1;
        }
        if format.get(i) == Some(&b'*') {
            let width = args.next_u32() as i32;
            if width < 0 {
                spec.left = true;
            }
            spec.width = width.unsigned_abs() as usize;
            i += 1;
        } else {
            spec.width = number(format, &mut i);
        }
        if format.get(i) == Some(&b'.') {
            i += 1;
            spec.precision = Some(if format.get(i) == Some(&b'*') {
                i += 1;
                (args.next_u32() as i32).max(0) as usize
            } else {
                number(format, &mut i)
            });
        }
        match format.get(i) {
            Some(b'h') => i += 1,
            Some(b'w') => {
                spec.wide = true;
                i += 1;
            }
            Some(b'l') => {
                i += 1;
                if format.get(i) == Some(&b'l') {
                    spec.long_long = true;
                    i += 1;
                } else {
                    spec.wide = true;
                }
            }
            Some(b'I') => match format.get(i + 1..i + 3) {
                Some(b"64") => {
                    spec.long_long = true;
                    i += 3;
                }
                Some(b"32") => i += 3,
                _ => return Err(unsupported(i + 1)),
            },
            _ => {}
        }
        let Some(&conversion) = format.get(i) else {
            return Err(unsupported(i));
        };
        i += 1;
        match conversion {
            b'%' => out.put(b"%"),
            b'd' | b'i' => {
                let value = if spec.long_long {
                    args.next_u64() as i64
                } else {
                    args.next_u32() as i32 as i64
                };
                integer(value.unsigned_abs(), value < 0, 10, false, &spec, out);
            }
            b'u' | b'o' | b'x' | b'X' => {
                let value = if spec.long_long {
                    args.next_u64()
                } else {
                    u64::from(args.next_u32())
                };
                let base = match conversion {
                    b'u' => 10,
                    b'o' => 8,
                    _ => 16,
                };
                integer(value, false, base, conversion == b'X', &spec, out);
            }
            b'p' => {
                let value = args.next_u32();
                let mut digits = [0u8; 8];
                for (k, digit) in digits.iter_mut().enumerate() {
                    *digit = b"0123456789ABCDEF"[(value >> (28 - 4 * k)) as usize & 0xF];
                }
                pad(&digits, &spec, out);
            }
            b'c' | b'C' => {
                let unit = args.next_u32() as u16;
                let byte = if conversion == b'C' || spec.wide {
                    narrow(unit)
                } else {
                    unit as u8
                };
                pad(&[byte], &spec, out);
            }
            b's' | b'S' => {
                let address = args.next_ptr();
                let wide = conversion == b'S' || spec.wide;
                text(address, wide, None, spec.precision, &spec, memory, out);
            }
            b'Z' => {
                // A counted string (ANSI_STRING, UNICODE_STRING): its length in bytes, its room,
                // then its buffer, a pointer's size in.
                let address = args.next_ptr();
                let size = 2 * core::mem::size_of::<usize>();
                if address == 0 || !memory.readable(address) || !memory.readable(address + size - 1)
                {
                    pad(b"(null)", &spec, out);
                } else {
                    // SAFETY: the structure's pages can be read (the memory says so).
                    let (length, buffer) = unsafe {
                        (
                            (address as *const u16).read_unaligned(),
                            ((address + size / 2) as *const usize).read_unaligned(),
                        )
                    };
                    let units = usize::from(length) / if spec.wide { 2 } else { 1 };
                    text(
                        buffer,
                        spec.wide,
                        Some(units),
                        spec.precision,
                        &spec,
                        memory,
                        out,
                    );
                }
            }
            _ => return Err(unsupported(i)),
        }
    }
    Ok(())
}

/// A decimal number at `format[*i..]`, `*i` past it (zero for none).
fn number(format: &[u8], i: &mut usize) -> usize {
    let mut value = 0usize;
    while let Some(digit) = format.get(*i).filter(|b| b.is_ascii_digit()) {
        value = value
            .saturating_mul(10)
            .saturating_add(usize::from(digit - b'0'));
        *i += 1;
    }
    value
}

/// A wide unit as a byte: itself below 0x100, `?` above.
fn narrow(unit: u16) -> u8 {
    u8::try_from(unit).unwrap_or(b'?')
}

/// An integer: its sign, the `#` prefix, the precision's zeros, then the width's padding.
fn integer(
    magnitude: u64,
    negative: bool,
    base: u64,
    upper: bool,
    spec: &Spec,
    out: &mut impl Sink,
) {
    let mut digits = [0u8; 64];
    let mut count = 0;
    let mut rest = magnitude;
    let alphabet: &[u8; 16] = if upper {
        b"0123456789ABCDEF"
    } else {
        b"0123456789abcdef"
    };
    while rest != 0 {
        digits[63 - count] = alphabet[(rest % base) as usize];
        rest /= base;
        count += 1;
    }
    // A zero precision with a zero value writes no digits; otherwise at least one.
    let minimum = spec.precision.unwrap_or(1);
    let mut body = [0u8; 96];
    let mut length = 0;
    let mut push = |byte: u8, length: &mut usize| {
        body[*length] = byte;
        *length += 1;
    };
    if negative {
        push(b'-', &mut length);
    } else if spec.plus && base == 10 {
        push(b'+', &mut length);
    } else if spec.space && base == 10 {
        push(b' ', &mut length);
    }
    if spec.alternate && magnitude != 0 {
        match base {
            16 => {
                push(b'0', &mut length);
                push(if upper { b'X' } else { b'x' }, &mut length);
            }
            8 => push(b'0', &mut length),
            _ => {}
        }
    }
    let prefix = length;
    for _ in count..minimum.min(64) {
        push(b'0', &mut length);
    }
    for &digit in &digits[64 - count..] {
        push(digit, &mut length);
    }
    // Zeros to the width go between the prefix and the digits.
    if spec.zero && !spec.left && spec.precision.is_none() && length < spec.width {
        let zeros = spec.width - length;
        out.put(&body[..prefix]);
        for _ in 0..zeros {
            out.put(b"0");
        }
        out.put(&body[prefix..length]);
    } else {
        pad(&body[..length], spec, out);
    }
}

/// `bytes`, padded with spaces to the width (on the right when left-justified).
fn pad(bytes: &[u8], spec: &Spec, out: &mut impl Sink) {
    let fill = spec.width.saturating_sub(bytes.len());
    if !spec.left {
        for _ in 0..fill {
            out.put(b" ");
        }
    }
    out.put(bytes);
    if spec.left {
        for _ in 0..fill {
            out.put(b" ");
        }
    }
}

/// A string at `address`: to its NUL, or `count` units for a counted one, bounded by `precision`.
fn text(
    address: usize,
    wide: bool,
    count: Option<usize>,
    precision: Option<usize>,
    spec: &Spec,
    memory: &impl Memory,
    out: &mut impl Sink,
) {
    if address == 0 {
        return pad(b"(null)", spec, out);
    }
    let limit = match (count, precision) {
        (Some(a), Some(b)) => a.min(b),
        (Some(a), None) | (None, Some(a)) => a,
        (None, None) => usize::MAX,
    };
    let unit_bytes = if wide { 2 } else { 1 };
    // The units, read while their pages can be read; the width needs the length first.
    let mut shown = [0u8; 256];
    let mut length = 0;
    let mut unreadable = false;
    while length < limit && length < shown.len() {
        let at = address + length * unit_bytes;
        if !memory.readable(at) || !memory.readable(at + unit_bytes - 1) {
            unreadable = true;
            break;
        }
        // SAFETY: the unit's page can be read (the memory says so).
        let unit = unsafe {
            if wide {
                (at as *const u16).read_unaligned()
            } else {
                u16::from((at as *const u8).read())
            }
        };
        if unit == 0 && count.is_none() {
            break;
        }
        shown[length] = narrow(unit);
        length += 1;
    }
    if unreadable && length == 0 {
        return pad(b"(unreadable)", spec, out);
    }
    pad(&shown[..length], spec, out);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct All;
    impl Memory for All {
        fn readable(&self, address: usize) -> bool {
            address >= 0x1000
        }
    }

    /// The arguments as slots: a dword or a host pointer each, a quadword two (low first), as
    /// the stack holds them.
    struct Stack(Vec<usize>);
    impl Args for Stack {
        fn next_u32(&mut self) -> u32 {
            self.next_ptr() as u32
        }

        fn next_u64(&mut self) -> u64 {
            let low = u64::from(self.next_u32());
            low | u64::from(self.next_u32()) << 32
        }

        fn next_ptr(&mut self) -> usize {
            if self.0.is_empty() {
                0
            } else {
                self.0.remove(0)
            }
        }
    }

    impl Sink for Vec<u8> {
        fn put(&mut self, bytes: &[u8]) {
            self.extend_from_slice(bytes);
        }
    }

    fn printed(format_text: &str, args: &[usize]) -> String {
        let mut out = Vec::new();
        let mut format_bytes = format_text.as_bytes().to_vec();
        format_bytes.push(0);
        format(&format_bytes, &mut Stack(args.to_vec()), &All, &mut out).unwrap();
        String::from_utf8_lossy(&out).into_owned()
    }

    fn address<T>(value: &T) -> usize {
        value as *const T as usize
    }

    #[test]
    fn integers() {
        assert_eq!(
            printed("%d %i %u", &[-5i32 as u32 as usize, 7, 4_000_000_000]),
            "-5 7 4000000000"
        );
        assert_eq!(
            printed("%x %X %#x %#X %o %#o", &[255, 255, 255, 255, 8, 8]),
            "ff FF 0xff 0XFF 10 010"
        );
        assert_eq!(
            printed("[%5d|%-5d|%05d|%+d|% d]", &[42, 42, 42, 42, 42]),
            "[   42|42   |00042|+42| 42]"
        );
        assert_eq!(
            printed("[%.3d|%8.3x|%-#8x]", &[7, 0xa, 0x1f]),
            "[007|     00a|0x1f    ]"
        );
        assert_eq!(
            printed("[%*d|%-*d|%.*d]", &[4, 1, 4, 2, 3, 3]),
            "[   1|2   |003]"
        );
        assert_eq!(printed("[%*d]", &[-4i32 as u32 as usize, 9]), "[9   ]");
        assert_eq!(printed("[%.0d]", &[0]), "[]");
        assert_eq!(printed("%05d", &[-42i32 as u32 as usize]), "-0042");
        assert_eq!(printed("%#08x", &[0x1f]), "0x00001f");
    }

    #[test]
    fn sixty_four_bit_integers() {
        let max = u32::MAX as usize;
        assert_eq!(
            printed("%I64x %llu %I64d", &[0x1, 0x2, 5, 0, max, max]),
            "200000001 5 -1"
        );
        assert_eq!(printed("%I32x|%lx|%hx", &[1, 2, 3]), "1|2|3");
    }

    #[test]
    fn characters_and_pointers() {
        let chars = [
            b'a' as usize,
            b'b' as usize,
            0xE9,
            0x263A,
            b'x' as usize,
            b'y' as usize,
        ];
        assert_eq!(
            printed("%c%c%C%wc|%3c|%-3c|", &chars),
            "ab\u{FFFD}?|  x|y  |"
        );
        assert_eq!(printed("%p %%", &[0x12ff40]), "0012FF40 %");
    }

    #[test]
    fn strings() {
        let narrow = b"hello\0";
        let wide: Vec<u16> = "wide\u{263A}".encode_utf16().chain([0]).collect();
        let n = address(&narrow[0]);
        let w = address(&wide[0]);
        assert_eq!(
            printed("[%s|%.3s|%8s|%-7s]", &[n, n, n, n]),
            "[hello|hel|   hello|hello  ]"
        );
        assert_eq!(printed("[%S|%ws|%ls]", &[w, w, w]), "[wide?|wide?|wide?]");
        assert_eq!(printed("[%s|%S]", &[0, 0]), "[(null)|(null)]");
        assert_eq!(printed("[%s]", &[0x10]), "[(unreadable)]");
    }

    #[test]
    fn counted_strings() {
        #[repr(C)]
        struct Counted {
            length: u16,
            room: u16,
            buffer: usize,
        }
        let text = b"counted, not terminated";
        let wide: Vec<u16> = "wide one".encode_utf16().collect();
        let ansi = Counted {
            length: 7,
            room: 7,
            buffer: address(&text[0]),
        };
        let unicode = Counted {
            length: 8,
            room: 8,
            buffer: address(&wide[0]),
        };
        assert_eq!(
            printed("[%Z|%wZ|%Z]", &[address(&ansi), address(&unicode), 0]),
            "[counted|wide|(null)]"
        );
    }

    #[test]
    fn unsupported_conversions_say_where() {
        let mut out = Vec::new();
        for (text, at, length) in [
            ("x %f y", 2, 2),
            ("%5.2e", 0, 5),
            ("ab %n", 3, 2),
            ("%I16d", 0, 2),
            ("%", 0, 1),
        ] {
            let mut bytes = text.as_bytes().to_vec();
            bytes.push(0);
            assert_eq!(
                format(&bytes, &mut Stack(vec![]), &All, &mut out),
                Err(Unsupported { at, length }),
                "{text}"
            );
        }
    }
}
