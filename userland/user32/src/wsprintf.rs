//! wsprintfA/W and wvsprintfA/W: user32's own formatting, not the C runtime's.
//!
//! `%[flags][width][.precision][size]type`, as Windows 2000's user32 documents it and as the
//! wsprintf capture pins it:
//!
//! - flags `-` (left-justified), `#` (`0x` or `0X` before a hexadecimal number, zero as well) and
//!   `0` (zeros to the width: after the sign, before the digits but after a `0x`, which the width
//!   leaves out; for a string or character too; not with `-` or a precision);
//! - a width and a precision, as digits only (a precision is the fewest digits of a number, the
//!   most units of a string);
//! - sizes `h` (a narrow character or string) and `l` (a wide one); a number is always the whole
//!   32-bit argument, whatever its size;
//! - types `d` and `i` (signed), `u`, `x` and `X`, `p` (eight upper-case hexadecimal digits), `c`
//!   and `s` (the form's own width), `C` and `S` (the other form's). A NULL string writes nothing.
//!
//! Any other type, `%` among them, writes its own unit and takes no argument: `%%` is `%`, and
//! what wsprintf does not document comes out as text from that unit on (`%f` is `f`, `%+d` is
//! `+d`, `%*d` is `*d`, `%I64d` is `I64d`, `%lld` is `ld`). A `%` at the format's end writes
//! nothing.
//!
//! The output holds at most [`LIMIT`] units, its terminator past them: what goes past them is
//! dropped, and the units written are answered. A narrow string or character written to a wide
//! output, or a wide one to a narrow output, crosses through the ANSI code page as ntdll converts
//! it (a wide unit the code page lacks is its default character, `?`).

use rtl::edge::{In, InStr, InWStr, OutBuf};

use crate::imports;

/// The most units wsprintf writes, its terminator left out.
pub const LIMIT: usize = 1024;

/// The variable arguments, consumed in order: one dword each (an `int`, a promoted character, a
/// string's address).
///
/// # Safety
///
/// An implementation hands out what the format consuming it asks for: for each string conversion,
/// zero or the address of a NUL-terminated string of the conversion's width the call may read
/// (up to its terminator, or to the precision's last unit).
pub unsafe trait Args {
    fn next(&mut self) -> usize;
}

/// The caller's variable arguments where its call pushed them (a `va_list`): dwords in order.
pub struct VaList(*const u32);

impl VaList {
    /// The arguments at `at`.
    ///
    /// # Safety
    ///
    /// `at` is the caller's argument block (a `va_list`): the dwords the format it is used with
    /// consumes, in order, as [`Args`] asks, valid while the list is in use.
    pub unsafe fn new(at: *const u8) -> VaList {
        VaList(at.cast())
    }
}

// SAFETY: `new`'s contract: the arguments are those the format asks for.
unsafe impl Args for VaList {
    fn next(&mut self) -> usize {
        // SAFETY: `new`'s contract: the next dword of the caller's argument block.
        let value = unsafe { In::new(self.0) }.read();
        self.0 = self.0.wrapping_add(1);
        value as usize
    }
}

/// A unit of an output: a byte (wsprintfA) or a UTF-16 unit (wsprintfW).
pub trait Unit: Copy {
    const WIDE: bool;
    /// The unit `value` is in this output's width (a narrow output's value is a byte already).
    fn of(value: u16) -> Self;
}

impl Unit for u8 {
    const WIDE: bool = false;

    fn of(value: u16) -> u8 {
        value as u8
    }
}

impl Unit for u16 {
    const WIDE: bool = true;

    fn of(value: u16) -> u16 {
        value
    }
}

/// The caller's output: at most [`LIMIT`] units, then the terminator.
pub struct Limited<'a, T> {
    out: OutBuf<'a, T>,
    written: usize,
}

impl<'a, T: Unit> Limited<'a, T> {
    /// The output into `out`, which holds `LIMIT + 1` units (or fewer, for a shorter output).
    pub fn new(out: OutBuf<'a, T>) -> Self {
        Limited { out, written: 0 }
    }

    /// One unit more, dropped past the limit.
    fn put(&mut self, value: u16) {
        if self.written < LIMIT {
            self.out.set(self.written, T::of(value));
            self.written += 1;
        }
    }

    /// `count` units of `value`.
    fn repeat(&mut self, value: u8, count: usize) {
        for _ in 0..count.min(LIMIT - self.written) {
            self.put(u16::from(value));
        }
    }

    /// The output terminated: the units written before the terminator.
    pub fn finish(mut self) -> usize {
        self.out.set(self.written, T::of(0));
        self.written
    }
}

/// A size prefix.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Size {
    None,
    /// `h`: a narrow character or string.
    Short,
    /// `l`: a wide character or string.
    Long,
}

/// One conversion's specification.
struct Spec {
    left: bool,
    alternate: bool,
    zero: bool,
    width: usize,
    precision: Option<usize>,
    size: Size,
}

impl Spec {
    /// Whether a character or string conversion `kind` (`c`, `s`; `C`, `S` the other form's)
    /// reads a wide one: by its size prefix, else by its letter's case and the output's width.
    fn wide<T: Unit>(&self, kind: u16) -> bool {
        match self.size {
            Size::Long => true,
            Size::Short => false,
            Size::None => (kind == u16::from(b'c') || kind == u16::from(b's')) == T::WIDE,
        }
    }
}

/// The unit `value` (a byte when `wide` is false, a UTF-16 unit when it is true) as an output of
/// `T`'s width writes it: as it is in its own width, through the ANSI code page in the other.
fn crossed<T: Unit>(value: u16, wide: bool) -> u16 {
    match (wide, T::WIDE) {
        (false, true) => {
            let mut unit = [0u16];
            imports::multi_byte_to_unicode(&mut unit, &[value as u8]);
            unit[0]
        }
        (true, false) => {
            let mut byte = [0u8];
            imports::unicode_to_multi_byte(&mut byte, &[value]);
            u16::from(byte[0])
        }
        _ => value,
    }
}

/// A run of decimal digits at `at` in the format, read past; zero for none (saturating far past
/// any limit).
fn digits(format: &impl Fn(usize) -> u16, at: &mut usize) -> usize {
    let mut value = 0usize;
    while let digit @ 0x30..=0x39 = format(*at) {
        value = value
            .saturating_mul(10)
            .saturating_add(usize::from(digit - 0x30));
        *at += 1;
    }
    value
}

/// Format the text `format` gives (its unit at an index, zero at its end) with `args` into `out`.
pub fn format<T: Unit>(format: impl Fn(usize) -> u16, args: &mut impl Args, out: &mut Limited<T>) {
    let mut at = 0;
    loop {
        let unit = format(at);
        at += 1;
        match unit {
            0 => return,
            0x25 => {}
            _ => {
                out.put(unit);
                continue;
            }
        }
        let mut spec = Spec {
            left: false,
            alternate: false,
            zero: false,
            width: 0,
            precision: None,
            size: Size::None,
        };
        loop {
            match format(at) {
                0x2D => spec.left = true,
                0x23 => spec.alternate = true,
                0x30 => spec.zero = true,
                _ => break,
            }
            at += 1;
        }
        spec.width = digits(&format, &mut at);
        if format(at) == u16::from(b'.') {
            at += 1;
            spec.precision = Some(digits(&format, &mut at));
        }
        spec.size = match format(at) {
            0x68 => Size::Short,
            0x6C => Size::Long,
            _ => Size::None,
        };
        if spec.size != Size::None {
            at += 1;
        }
        let kind = format(at);
        if kind == 0 {
            return;
        }
        at += 1;
        match u8::try_from(kind).unwrap_or(0) {
            b'd' | b'i' => {
                let value = args.next() as u32 as i32;
                number(value.unsigned_abs(), value < 0, 10, false, &spec, out);
            }
            b'u' => number(args.next() as u32, false, 10, false, &spec, out),
            b'x' | b'X' => {
                let upper = kind == u16::from(b'X');
                number(args.next() as u32, false, 16, upper, &spec, out);
            }
            b'p' => {
                spec.precision = spec.precision.or(Some(8));
                number(args.next() as u32, false, 16, true, &spec, out);
            }
            b'c' | b'C' => {
                let wide = spec.wide::<T>(kind);
                let value = args.next() as u16;
                let value = if wide { value } else { value & 0xFF };
                let unit = crossed::<T>(value, wide);
                pad_before(1, &spec, out);
                out.put(unit);
                pad_after(1, &spec, out);
            }
            b's' | b'S' => {
                let wide = spec.wide::<T>(kind);
                text(args.next(), wide, &spec, out);
            }
            _ => out.put(kind),
        }
    }
}

/// The padding before a field of `length` units: spaces to the width, or zeros with the `0` flag;
/// none for a left-justified one.
fn pad_before<T: Unit>(length: usize, spec: &Spec, out: &mut Limited<T>) {
    if !spec.left {
        let fill = if spec.zero { b'0' } else { b' ' };
        out.repeat(fill, spec.width.saturating_sub(length));
    }
}

/// The padding after a left-justified field of `length` units: spaces to the width.
fn pad_after<T: Unit>(length: usize, spec: &Spec, out: &mut Limited<T>) {
    if spec.left {
        out.repeat(b' ', spec.width.saturating_sub(length));
    }
}

/// A number: its magnitude in `base` (`upper` for upper-case hexadecimal digits) after its sign or
/// its `0x`, to the precision's digits and the width.
fn number<T: Unit>(
    magnitude: u32,
    negative: bool,
    base: u32,
    upper: bool,
    spec: &Spec,
    out: &mut Limited<T>,
) {
    let mut buffer = [0u8; 10];
    let mut start = buffer.len();
    let mut rest = magnitude;
    loop {
        let digit = (rest % base) as u8;
        start -= 1;
        buffer[start] = match digit {
            0..=9 => b'0' + digit,
            _ if upper => b'A' + digit - 10,
            _ => b'a' + digit - 10,
        };
        rest /= base;
        if rest == 0 {
            break;
        }
    }
    let digits = &buffer[start..];
    let sign = usize::from(negative);
    let prefix: &[u8] = match (spec.alternate && base == 16, upper) {
        (false, _) => b"",
        (true, false) => b"0x",
        (true, true) => b"0X",
    };
    let mut zeros = spec.precision.unwrap_or(0).saturating_sub(digits.len());
    if spec.zero && !spec.left && spec.precision.is_none() {
        // The `0x` is not counted against the width: "%#08x" pads its digits to eight.
        zeros = zeros.max(spec.width.saturating_sub(sign + digits.len()));
    }
    let length = sign + prefix.len() + zeros + digits.len();
    if !spec.left {
        out.repeat(b' ', spec.width.saturating_sub(length));
    }
    if negative {
        out.put(u16::from(b'-'));
    }
    for &unit in prefix {
        out.put(u16::from(unit));
    }
    out.repeat(b'0', zeros);
    for &digit in digits {
        out.put(u16::from(digit));
    }
    pad_after(length, spec, out);
}

/// The unit at `index` of the string at `address`, narrow or `wide`.
///
/// # Safety
///
/// `address` is a NUL-terminated string of that width the call may read, `index` at or before its
/// terminator.
unsafe fn unit_at(address: usize, index: usize, wide: bool) -> u16 {
    // SAFETY: the function's contract.
    unsafe {
        if wide {
            In::new((address as *const u16).wrapping_add(index)).read()
        } else {
            u16::from(In::new((address as *const u8).wrapping_add(index)).read())
        }
    }
}

/// A string argument: its units up to its terminator or the precision, to the width; nothing of
/// its own for NULL.
fn text<T: Unit>(address: usize, wide: bool, spec: &Spec, out: &mut Limited<T>) {
    let most = spec.precision.unwrap_or(usize::MAX);
    let mut length = 0;
    // SAFETY: `Args`' contract: the conversion's argument is zero or a NUL-terminated string of
    // its width, read up to its terminator or the precision's last unit.
    while address != 0 && length < most && unsafe { unit_at(address, length, wide) } != 0 {
        length += 1;
    }
    pad_before(length, spec, out);
    for index in 0..length {
        // SAFETY: as above: a unit before the terminator.
        let unit = unsafe { unit_at(address, index, wide) };
        out.put(crossed::<T>(unit, wide));
    }
    pad_after(length, spec, out);
}

/// wvsprintfA: the narrow format with the `va_list`'s arguments into the buffer, at most
/// [`LIMIT`] bytes and the terminator; the bytes written before the terminator.
///
/// # Safety
///
/// `output` holds the output and its terminator; `text` is a NUL-terminated format; `args` holds
/// the arguments it consumes, as for the platform's.
#[unsafe(export_name = "f2k_export_wvsprintfA")]
pub unsafe extern "system" fn wvsprintf_a(
    output: *mut u8,
    text: *const u8,
    args: *const u8,
) -> i32 {
    // SAFETY: the caller's contract: the format, the arguments, and a buffer the output fits in
    // (it writes no more than LIMIT units and the terminator).
    let (text, mut args, output) = unsafe {
        (
            InStr::new(text),
            VaList::new(args),
            OutBuf::new(output, LIMIT + 1),
        )
    };
    let units = text.bytes();
    let mut out = Limited::new(output);
    format(
        |at| units.get(at).map_or(0, |&byte| u16::from(byte)),
        &mut args,
        &mut out,
    );
    out.finish() as i32
}

/// wvsprintfW: wvsprintfA's, in UTF-16 units.
///
/// # Safety
///
/// As [`wvsprintf_a`]'s, in UTF-16 units.
#[unsafe(export_name = "f2k_export_wvsprintfW")]
pub unsafe extern "system" fn wvsprintf_w(
    output: *mut u16,
    text: *const u16,
    args: *const u8,
) -> i32 {
    // SAFETY: as wvsprintfA's.
    let (text, mut args, output) = unsafe {
        (
            InWStr::new(text),
            VaList::new(args),
            OutBuf::new(output, LIMIT + 1),
        )
    };
    let units = text.units();
    let mut out = Limited::new(output);
    format(
        |at| if at < units.len() { units.get(at) } else { 0 },
        &mut args,
        &mut out,
    );
    out.finish() as i32
}

/// The exports taking variable arguments (cdecl, the caller popping them): each hands its fixed
/// arguments and the address of its variable ones, where its caller pushed them, to its `va_list`
/// form.
#[cfg(target_arch = "x86")]
mod variadic {
    /// wsprintfA(output, format, ...).
    #[unsafe(naked)]
    #[unsafe(export_name = "f2k_export_wsprintfA")]
    pub unsafe extern "C" fn wsprintf_a() {
        core::arch::naked_asm!(
            "lea eax, [esp+12]",
            "push eax",
            "push dword ptr [esp+12]",
            "push dword ptr [esp+12]",
            "call {body}",
            "ret",
            body = sym super::wvsprintf_a,
        )
    }

    /// wsprintfW(output, format, ...).
    #[unsafe(naked)]
    #[unsafe(export_name = "f2k_export_wsprintfW")]
    pub unsafe extern "C" fn wsprintf_w() {
        core::arch::naked_asm!(
            "lea eax, [esp+12]",
            "push eax",
            "push dword ptr [esp+12]",
            "push dword ptr [esp+12]",
            "call {body}",
            "ret",
            body = sym super::wvsprintf_w,
        )
    }
}

#[cfg(test)]
mod tests {
    use std::string::String;
    use std::vec::Vec;

    use super::*;

    /// The host's arguments: a list of values, strings' addresses among them.
    struct List<'a>(core::slice::Iter<'a, usize>);

    // SAFETY: the tests' strings are NUL-terminated and alive for the call.
    unsafe impl Args for List<'_> {
        fn next(&mut self) -> usize {
            self.0.next().copied().unwrap_or(0)
        }
    }

    /// The narrow output of `text` with `args`: its bytes up to the terminator, and the answer.
    fn narrow(text: &str, args: &[usize]) -> (Vec<u8>, usize) {
        let mut buffer = std::vec![b'#'; 2100];
        let mut out = Limited::new(OutBuf::from(&mut buffer[..]));
        let bytes = text.as_bytes();
        format(
            |at| bytes.get(at).map_or(0, |&byte| u16::from(byte)),
            &mut List(args.iter()),
            &mut out,
        );
        let written = out.finish();
        assert_eq!(buffer[written], 0, "the terminator after the answer");
        assert_eq!(buffer[written + 1], b'#', "nothing past the terminator");
        (buffer[..written].to_vec(), written)
    }

    /// The wide output of `text` with `args`.
    fn wide(text: &str, args: &[usize]) -> (Vec<u16>, usize) {
        let mut buffer = std::vec![0x23u16; 2100];
        let mut out = Limited::new(OutBuf::from(&mut buffer[..]));
        let units: Vec<u16> = text.encode_utf16().collect();
        format(
            |at| units.get(at).copied().unwrap_or(0),
            &mut List(args.iter()),
            &mut out,
        );
        let written = out.finish();
        assert_eq!(buffer[written], 0, "the terminator after the answer");
        (buffer[..written].to_vec(), written)
    }

    /// Both forms of a format whose output is ASCII.
    fn both(text: &str, args: &[usize]) -> String {
        let (bytes, _) = narrow(text, args);
        let (units, _) = wide(text, args);
        let narrow = String::from_utf8(bytes).unwrap();
        assert_eq!(narrow, String::from_utf16(&units).unwrap(), "{text}");
        narrow
    }

    /// The ints section's flags, widths, precisions and sizes.
    ///
    /// Pins: user32.wsprintfA, user32.wsprintfW
    #[test]
    fn numbers_take_flags_widths_and_precisions() {
        for (text, value, answer) in [
            ("%d", 0x8000_0000, "-2147483648"),
            ("%u", 0xFFFF_FFFF, "4294967295"),
            ("%#x", 0, "0x0"),
            ("%#X", 0xBEEF, "0XBEEF"),
            ("%#d", 42, "42"),
            ("%-5d|", 42, "42   |"),
            ("%05d", (-42i32) as u32 as usize, "-0042"),
            ("%-05d|", 42, "42   |"),
            ("%#08x", 0xABC, "0x00000abc"),
            ("%8.3d|", (-7i32) as u32 as usize, "    -007|"),
            ("%.0d|", 0, "0|"),
            ("%.5x", 0xAB, "000ab"),
            ("%hd", 0x18000, "98304"),
            ("%hX", 0xFFFF_ABCD, "FFFFABCD"),
            ("%p", 0x12AB_34CD, "12AB34CD"),
        ] {
            assert_eq!(both(text, &[value]), answer, "{text}");
        }
        assert_eq!(both("[%x-%u]", &[255, 255]), "[ff-255]");
    }

    /// The others section: `%` and what wsprintf does not document.
    ///
    /// Pins: user32.wsprintfA, user32.wsprintfW
    #[test]
    fn unknown_types_write_themselves() {
        for (text, answer) in [
            ("100%%", "100%"),
            ("%%d", "%d"),
            ("100%", "100"),
            ("%5%|", "%|"),
            ("%#o", "o"),
            ("%f", "f"),
            ("%+d", "+d"),
            ("% d", " d"),
            ("[%*d]", "[*d]"),
            ("[%.*d]", "[*d]"),
            ("%I64d", "I64d"),
            ("%Lx", "Lx"),
            ("%lld", "ld"),
        ] {
            assert_eq!(both(text, &[6, 42]), answer, "{text}");
        }
    }

    /// The strings section: the forms' own and the other's strings and characters, NULL, widths,
    /// precisions, and text crossing the code page.
    ///
    /// Pins: user32.wsprintfA, user32.wsprintfW
    #[test]
    fn strings_and_characters_in_both_forms() {
        let ab = b"ab\0".as_ptr() as usize;
        let cafe = b"caf\xE9\0".as_ptr() as usize;
        let euro = b"\x80\0".as_ptr() as usize;
        let wide_ab: Vec<u16> = std::vec![0x61, 0x62, 0x63, 0x64, 0];
        let wide_ab = wide_ab.as_ptr() as usize;
        let ideograph: Vec<u16> = std::vec![0x78, 0x4E00, 0x79, 0];
        let ideograph = ideograph.as_ptr() as usize;
        assert_eq!(narrow("[%05s]", &[ab]).0, b"[000ab]");
        assert_eq!(narrow("[%-5s]", &[ab]).0, b"[ab   ]");
        assert_eq!(narrow("[%.0s]", &[ab]).0, b"[]");
        assert_eq!(narrow("%s", &[0]), (std::vec![], 0));
        assert_eq!(narrow("[%5.2S]", &[wide_ab]).0, b"[   ab]");
        assert_eq!(narrow("%ls", &[ideograph]).0, b"x?y");
        assert_eq!(narrow("%hs", &[cafe]).0, b"caf\xE9");
        assert_eq!(wide("%S", &[cafe]).0, [0x63, 0x61, 0x66, 0xE9]);
        assert_eq!(wide("%hs", &[euro]).0, [0x20AC]);
        assert_eq!(wide("%s", &[ideograph]).0, [0x78, 0x4E00, 0x79]);
        assert_eq!(wide("%ls", &[0]).0, Vec::<u16>::new());
        assert_eq!(narrow("%C", &[0x4E00]).0, b"?");
        assert_eq!(narrow("%lc", &[0xE9]).0, b"\xE9");
        assert_eq!(narrow("[%-3c]", &[0x78]).0, b"[x  ]");
        assert_eq!(wide("%c", &[0x4E00]).0, [0x4E00]);
        assert_eq!(wide("%C", &[0x80]).0, [0x20AC]);
        assert_eq!(wide("%hc", &[0x7A]).0, [0x7A]);
        assert_eq!(narrow("a%cb", &[0]), (b"a\0b".to_vec(), 3));
    }

    /// The limit section: 1024 units at most, the terminator after them.
    ///
    /// Pins: user32.wsprintfA, user32.wsprintfW
    #[test]
    fn the_output_stops_at_the_limit() {
        let long: Vec<u8> = (0..1500)
            .map(|at| b'0' + (at % 10) as u8)
            .chain([0])
            .collect();
        let long = long.as_ptr() as usize;
        let (bytes, written) = narrow("%s", &[long]);
        assert_eq!((written, &bytes[1020..]), (1024, &b"0123"[..]));
        assert_eq!(wide("%hs", &[long]).1, 1024);
        let literal = "f".repeat(1100);
        assert_eq!(narrow(&literal, &[]).1, 1024);
        let (bytes, written) = narrow("%1100d", &[5]);
        assert_eq!(written, 1024);
        assert!(bytes.iter().all(|&byte| byte == b' '));
        assert_eq!(narrow(&"x".repeat(1023), &[]).1, 1023);
    }
}
