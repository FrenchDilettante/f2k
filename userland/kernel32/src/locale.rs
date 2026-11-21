//! The locale group, kernel32's own NLS code as on Windows 2000 (no kernel transition): the code
//! pages and their conversions (MultiByteToWideChar and WideCharToMultiByte over `rtl::codepage`),
//! lead bytes (IsDBCSLeadByte) and the code page list (EnumSystemCodePages), the language groups
//! (IsValidLanguageGroup), LCMapString ([`lcmap`], its sort keys [`sortkey`]'s), character types
//! over code page 1252 (`rtl::cp1252`),
//! comparison ([`crate::collate`]), the one locale's facts ([`crate::localeinfo`]), and MulDiv,
//! which the group's spec section keeps beside them. The date, time and number formats are
//! [`crate::nlsformat`]'s, FoldString [`crate::fold`]'s.
//!
//! The caller's strings are read and written where they are: a pointer the caller cannot read or
//! write faults in the caller's thread, as kernel32's own code does on Windows 2000.

use rtl::codepage::sbcs::SingleByte;
use rtl::codepage::{self, Page};
use rtl::cp1252;

use crate::base::set_last_error;
use crate::edge::{wide_units_of, Counted, In, InBuf, Out, OutBuf};
use crate::error::{
    answer,
    bool_answer,
    Failure,
    ERROR_INSUFFICIENT_BUFFER,
    ERROR_INVALID_FLAGS,
    ERROR_INVALID_PARAMETER,
    ERROR_NOT_ENOUGH_MEMORY,
};

mod lcmap;
pub mod sortkey;

pub use lcmap::{lc_map_string_a, lc_map_string_w};

/// The code pages this surface reports: ANSI 1252, OEM 437.
pub const ACP: u32 = 1252;
pub const OEMCP: u32 = 437;

/// A failed call's Win32 error.
fn refused<T>(code: u32) -> Result<T, Failure> {
    Err(Failure::Error(code))
}

/// GetACP: the ANSI code page.
#[unsafe(export_name = "f2k_export_GetACP")]
pub extern "system" fn get_acp() -> u32 {
    ACP
}

/// GetOEMCP: the OEM code page.
#[unsafe(export_name = "f2k_export_GetOEMCP")]
pub extern "system" fn get_oemcp() -> u32 {
    OEMCP
}

/// sizeof(CPINFO).
const CP_INFO_SIZE: usize = 18;

/// GetCPInfo: an installed code page's facts (see [`rtl::codepage::cp_info`]) into the 18-byte
/// CPINFO; FALSE with ERROR_INVALID_PARAMETER for another code page, the structure untouched.
///
/// # Safety
///
/// `info` points at a writable CPINFO.
#[unsafe(export_name = "f2k_export_GetCPInfo")]
pub unsafe extern "system" fn get_cp_info(page: u32, info: *mut u8) -> u32 {
    // SAFETY: the caller's CPINFO (the contract).
    let info = unsafe { OutBuf::new(info, CP_INFO_SIZE) };
    bool_answer(cp_info(page, info))
}

/// GetCPInfo's work.
fn cp_info(page: u32, mut info: OutBuf<'_, u8>) -> Result<(), Failure> {
    let facts = codepage::cp_info(page).ok_or(Failure::Error(ERROR_INVALID_PARAMETER))?;
    info.put(&facts);
    Ok(())
}

/// IsValidCodePage: whether the code page is installed.
#[unsafe(export_name = "f2k_export_IsValidCodePage")]
pub extern "system" fn is_valid_code_page(page: u32) -> u32 {
    u32::from(codepage::is_valid(page))
}

/// CPINFO's LeadByte: up to five (first, last) ranges after MaxCharSize and DefaultChar, ended by
/// a pair of zeroes.
const LEAD_BYTES: core::ops::Range<usize> = 6..CP_INFO_SIZE;

/// IsDBCSLeadByteEx: whether the byte is a lead byte of the code page, from its lead-byte ranges as
/// GetCPInfo describes them (none of the installed pages has any, so FALSE); FALSE with
/// ERROR_INVALID_PARAMETER for a code page that is not installed.
#[unsafe(export_name = "f2k_export_IsDBCSLeadByteEx")]
pub extern "system" fn is_dbcs_lead_byte_ex(page: u32, byte: u32) -> u32 {
    let Some(facts) = codepage::cp_info(page) else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    let byte = byte as u8;
    let (ranges, _) = facts[LEAD_BYTES].as_chunks::<2>();
    let lead = ranges
        .iter()
        .take_while(|&&range| range != [0, 0])
        .any(|&[first, last]| (first..=last).contains(&byte));
    u32::from(lead)
}

/// IsDBCSLeadByte: IsDBCSLeadByteEx in the ANSI code page.
#[unsafe(export_name = "f2k_export_IsDBCSLeadByte")]
pub extern "system" fn is_dbcs_lead_byte(byte: u32) -> u32 {
    is_dbcs_lead_byte_ex(codepage::CP_ACP, byte)
}

/// MulDiv: `number * numerator / denominator` over a 64-bit product, rounded to the nearest
/// integer, halves away from zero (the quotient of the magnitudes rounded, then signed); -1 for a
/// zero denominator or a magnitude past 2^31 - 1. A result of -2^31 is overflow too, as the
/// utility fixture's capture shows: Windows 2000 checks the magnitude, whichever the sign. The last
/// error is left alone.
#[unsafe(export_name = "f2k_export_MulDiv")]
pub extern "system" fn mul_div(number: i32, numerator: i32, denominator: i32) -> i32 {
    if denominator == 0 {
        return -1;
    }
    let product = i64::from(number) * i64::from(numerator);
    let divisor = i64::from(denominator).unsigned_abs();
    let magnitude = (product.unsigned_abs() + divisor / 2) / divisor;
    let Ok(magnitude) = i32::try_from(magnitude) else {
        return -1;
    };
    let negative = (product < 0) != (denominator < 0);
    if negative {
        -magnitude
    } else {
        magnitude
    }
}

/// A conversion's source: through the terminator for -1 (the terminator converted too), else as
/// counted; ERROR_INVALID_PARAMETER for zero, a count below -1, or a null source.
fn convert_source<'a, U: Copy + Default + PartialEq>(
    src: &Counted<'a, U>,
) -> Result<InBuf<'a, U>, Failure> {
    if src.is_null() || src.count() == 0 || src.count() < -1 {
        return refused(ERROR_INVALID_PARAMETER);
    }
    Ok(src.units(true))
}

/// A conversion's destination: ERROR_INVALID_PARAMETER for a negative size, or a null buffer with
/// a size.
pub(crate) fn check_destination<U: Copy>(
    dst: &OutBuf<'_, U>,
    capacity: i32,
) -> Result<(), Failure> {
    if capacity < 0 || (dst.is_null() && capacity != 0) {
        return refused(ERROR_INVALID_PARAMETER);
    }
    Ok(())
}

/// The room a caller's size gives a buffer: none for a negative one (which the calls refuse
/// before they write).
pub(crate) fn room(size: i32) -> usize {
    size.max(0) as usize
}

/// Where a conversion's output goes: the units produced are counted, and written while the
/// destination (none for a size query) has room.
pub(crate) struct Produced<'a, U> {
    dst: OutBuf<'a, U>,
    produced: usize,
}

impl<'a, U: Copy> Produced<'a, U> {
    pub(crate) fn new(dst: OutBuf<'a, U>) -> Self {
        Produced { dst, produced: 0 }
    }

    /// One more unit.
    pub(crate) fn put(&mut self, unit: U) {
        if self.produced < self.dst.len() {
            self.dst.set(self.produced, unit);
        }
        self.produced += 1;
    }

    /// The conversion's answer: the count, or ERROR_INSUFFICIENT_BUFFER when the destination was
    /// too short (a size query never is).
    pub(crate) fn finish(&self) -> Result<usize, Failure> {
        if !self.dst.is_empty() && self.produced > self.dst.len() {
            refused(ERROR_INSUFFICIENT_BUFFER)
        } else {
            Ok(self.produced)
        }
    }
}

/// MultiByteToWideChar over the code pages [`rtl::codepage::page`] names: a size query (no
/// destination size) or the conversion, the OEM pages' control bytes as glyphs for
/// MB_USEGLYPHCHARS. ERROR_INVALID_FLAGS for a flag the page does not take (UTF-8 takes
/// MB_ERR_INVALID_CHARS alone, UTF-7 and CP_SYMBOL none), ERROR_INVALID_PARAMETER for an unknown
/// page or a bad count, ERROR_NO_UNICODE_TRANSLATION for UTF-8 Windows 2000 refuses to decode,
/// ERROR_INSUFFICIENT_BUFFER for a destination too small.
///
/// # Safety
///
/// The source holds `count` bytes (a NUL-terminated string for -1); the destination `capacity`
/// units.
#[unsafe(export_name = "f2k_export_MultiByteToWideChar")]
pub unsafe extern "system" fn multi_byte_to_wide_char(
    cp: u32,
    flags: u32,
    src: *const u8,
    count: i32,
    dst: *mut u16,
    capacity: i32,
) -> i32 {
    // SAFETY: the caller's source and destination (the contract; a negative size, which the call
    // refuses before it writes, holds none).
    let (src, out) = unsafe { (Counted::new(src, count), OutBuf::new(dst, room(capacity))) };
    answer(to_wide(cp, flags, src, out, capacity), 0)
}

/// ERROR_NO_UNICODE_TRANSLATION: a string the code page cannot convert.
const ERROR_NO_UNICODE_TRANSLATION: u32 = 1113;

/// MultiByteToWideChar's flags.
const MB_USEGLYPHCHARS: u32 = 0x4;
const MB_ERR_INVALID_CHARS: u32 = 0x8;

/// MultiByteToWideChar's work.
fn to_wide(
    cp: u32,
    flags: u32,
    src: Counted<'_, u8>,
    dst: OutBuf<'_, u16>,
    capacity: i32,
) -> Result<i32, Failure> {
    const VALID_FLAGS: u32 = 0xF; // precomposed, composite, glyph chars, invalid chars
    if flags & !VALID_FLAGS != 0 {
        return refused(ERROR_INVALID_FLAGS);
    }
    let page = codepage::page(cp).ok_or(Failure::Error(ERROR_INVALID_PARAMETER))?;
    let taken = match page {
        Page::Single(_) => VALID_FLAGS,
        Page::Utf8 => MB_ERR_INVALID_CHARS,
        Page::Utf7 | Page::Symbol => 0,
    };
    if flags & !taken != 0 || flags & MB_PRECOMPOSED_COMPOSITE == MB_PRECOMPOSED_COMPOSITE {
        return refused(ERROR_INVALID_FLAGS);
    }
    let bytes = convert_source(&src)?;
    check_destination(&dst, capacity)?;
    let mut out = Produced::new(dst);
    let glyphs = flags & MB_USEGLYPHCHARS != 0;
    let strict = flags & MB_ERR_INVALID_CHARS != 0;
    let composite = flags & MB_COMPOSITE != 0;
    codepage::to_wide(
        page,
        bytes.bytes(),
        glyphs,
        strict,
        |unit| match composite {
            true => out.put_decomposed(unit),
            false => out.put(unit),
        },
    )
    .map_err(|_| Failure::Error(ERROR_NO_UNICODE_TRANSLATION))?;
    Ok(out.finish()? as i32)
}

/// MB_PRECOMPOSED and MB_COMPOSITE, which may not go together.
const MB_PRECOMPOSED_COMPOSITE: u32 = 0x1 | MB_COMPOSITE;
const MB_COMPOSITE: u32 = 0x2;

impl Produced<'_, u16> {
    /// MB_COMPOSITE's unit: a precomposed letter as its base letter and combining mark
    /// ([`crate::fold::decomposed`]); but where the destination has room for one unit and not two,
    /// the letter as it is, as Windows 2000 writes it (the locale fixture's bestfit block: é into
    /// one unit is é).
    fn put_decomposed(&mut self, unit: u16) {
        match crate::fold::decomposed(unit) {
            Some(_) if self.produced + 1 == self.dst.len() => self.put(unit),
            Some((base, mark)) => {
                self.put(base);
                self.put(mark);
            }
            None => self.put(unit),
        }
    }
}

/// WideCharToMultiByte over the code pages [`rtl::codepage::page`] names: a single-byte page
/// best-fits what it does not hold (unless WC_NO_BEST_FIT_CHARS) and substitutes the default
/// character (the caller's, else `?`) for the rest, reporting it when asked; UTF-7, UTF-8 and
/// CP_SYMBOL take no flags (ERROR_INVALID_FLAGS), and neither a default nor the report
/// (ERROR_INVALID_PARAMETER), and CP_SYMBOL refuses a unit it has no byte for
/// (ERROR_NO_UNICODE_TRANSLATION). Errors otherwise as MultiByteToWideChar's.
///
/// # Safety
///
/// As MultiByteToWideChar's; the default character and the report, when given, are readable and
/// writable.
#[allow(clippy::too_many_arguments)]
#[unsafe(export_name = "f2k_export_WideCharToMultiByte")]
pub unsafe extern "system" fn wide_char_to_multi_byte(
    cp: u32,
    flags: u32,
    src: *const u16,
    count: i32,
    dst: *mut u8,
    capacity: i32,
    default_char: *const u8,
    used_default: *mut u32,
) -> i32 {
    // SAFETY: the caller's source, destination, default character and report (the contract).
    let (src, out, default, used) = unsafe {
        (
            Counted::new(src, count),
            OutBuf::new(dst, room(capacity)),
            In::optional(default_char),
            Out::optional(used_default),
        )
    };
    let narrow = Narrow {
        default,
        used,
        capacity,
    };
    answer(to_narrow(cp, flags, src, out, narrow), 0)
}

/// WideCharToMultiByte's other arguments: the default character and the report, when given, and
/// the destination's size.
struct Narrow<'a> {
    default: Option<In<'a, u8>>,
    used: Option<Out<'a, u32>>,
    capacity: i32,
}

/// WideCharToMultiByte's work.
fn to_narrow(
    cp: u32,
    flags: u32,
    src: Counted<'_, u16>,
    dst: OutBuf<'_, u8>,
    narrow: Narrow<'_>,
) -> Result<i32, Failure> {
    const VALID_FLAGS: u32 =
        WC_DISCARDNS | WC_SEPCHARS | WC_DEFAULTCHAR | WC_COMPOSITECHECK | WC_NO_BEST_FIT_CHARS;
    let Narrow {
        default,
        used,
        capacity,
    } = narrow;
    let page = codepage::page(cp).ok_or(Failure::Error(ERROR_INVALID_PARAMETER))?;
    let single = match page {
        Page::Single(single) => Some(single),
        _ => None,
    };
    let composing = WC_DISCARDNS | WC_SEPCHARS | WC_DEFAULTCHAR;
    let refused_flags = flags & !VALID_FLAGS != 0
        || (single.is_none() && flags != 0)
        || (flags & composing != 0 && flags & WC_COMPOSITECHECK == 0);
    if refused_flags {
        return refused(ERROR_INVALID_FLAGS);
    }
    if single.is_none() && (default.is_some() || used.is_some()) {
        return refused(ERROR_INVALID_PARAMETER);
    }
    let units = convert_source(&src)?;
    check_destination(&dst, capacity)?;
    let default = default.map_or(b'?', |default| default.read());
    let units = wide_units_of(units).ok_or(Failure::Error(ERROR_NOT_ENOUGH_MEMORY))?;
    let mut out = Produced::new(dst);
    let fit = flags & WC_NO_BEST_FIT_CHARS == 0;
    let replaced = match single {
        Some(single) => encode_composites(single, flags, &units, default, |byte| out.put(byte)),
        None => codepage::to_narrow(page, &units, default, fit, |byte| out.put(byte))
            .map_err(|_| Failure::Error(ERROR_NO_UNICODE_TRANSLATION))?,
    };
    let produced = out.finish()?;
    if let Some(mut used) = used {
        used.set(u32::from(replaced));
    }
    Ok(produced as i32)
}

/// WideCharToMultiByte's flags.
const WC_COMPOSITECHECK: u32 = 0x200;
const WC_DISCARDNS: u32 = 0x10;
const WC_SEPCHARS: u32 = 0x20;
const WC_DEFAULTCHAR: u32 = 0x40;
const WC_NO_BEST_FIT_CHARS: u32 = 0x400;

/// Whether `unit` is a nonspacing mark WC_COMPOSITECHECK looks for after a base character: the
/// combining diacritical marks.
fn nonspacing(unit: u16) -> bool {
    (0x0300..=0x036F).contains(&unit)
}

/// A single-byte page's encoding of `units` (WideCharToMultiByte's), each unit exactly, best-fit
/// unless WC_NO_BEST_FIT_CHARS, else `default`. With WC_COMPOSITECHECK a base character and the
/// nonspacing mark after it are composed into their precomposed character where there is one (and
/// encoded as one); where there is none, WC_DISCARDNS drops the mark, WC_DEFAULTCHAR writes
/// `default` for the pair, and WC_SEPCHARS (the default) encodes both. Returns whether `default`
/// was written.
fn encode_composites(
    page: &SingleByte,
    flags: u32,
    units: &[u16],
    default: u8,
    mut out: impl FnMut(u8),
) -> bool {
    let fit = flags & WC_NO_BEST_FIT_CHARS == 0;
    let mut used = false;
    // A unit's byte, none standing for the default character.
    let mut put = |byte: Option<u8>| {
        used |= byte.is_none();
        out(byte.unwrap_or(default));
    };
    let mut at = 0;
    while at < units.len() {
        let unit = units[at];
        let mark = units.get(at + 1).copied().filter(|&next| nonspacing(next));
        match mark {
            Some(mark) if flags & WC_COMPOSITECHECK != 0 && !nonspacing(unit) => {
                at += 2;
                if let Some(precomposed) = crate::fold::composed(unit, mark) {
                    put(page.encode(precomposed, fit));
                } else if flags & WC_DISCARDNS != 0 {
                    put(page.encode(unit, fit));
                } else if flags & WC_DEFAULTCHAR != 0 {
                    put(None);
                } else {
                    put(page.encode(unit, fit));
                    put(page.encode(mark, fit));
                }
            }
            _ => {
                at += 1;
                put(page.encode(unit, fit));
            }
        }
    }
    used
}

/// GetStringType's information types: one at a time, each a classifier of one character.
const CT_CTYPE1: u32 = 1;
const CT_CTYPE2: u32 = 2;
const CT_CTYPE3: u32 = 4;

/// The classifier of a GetStringType information type: CT_CTYPE1's character types, CT_CTYPE2's
/// bidirectional classes or CT_CTYPE3's extended types (`rtl::cp1252`). ERROR_INVALID_FLAGS for
/// anything else, combinations included.
fn classifier(info: u32) -> Result<fn(u16) -> u16, Failure> {
    match info {
        CT_CTYPE1 => Ok(cp1252::c1_flags),
        CT_CTYPE2 => Ok(cp1252::c2_class),
        CT_CTYPE3 => Ok(cp1252::c3_flags),
        _ => refused(ERROR_INVALID_FLAGS),
    }
}

/// GetStringType's output: ERROR_INVALID_PARAMETER for none (the utility fixture's capture).
fn check_types(out: &OutBuf<'_, u16>) -> Result<(), Failure> {
    if out.is_null() {
        return refused(ERROR_INVALID_PARAMETER);
    }
    Ok(())
}

/// A narrow source: -1 is through its terminator, which counts; zero, anything below -1 and a null
/// source are ERROR_INVALID_PARAMETER (Windows 2000's NLS calls check the pointer before they read
/// it).
pub(crate) fn narrow_source<'a>(src: &Counted<'a, u8>) -> Result<InBuf<'a, u8>, Failure> {
    if src.is_null() {
        return refused(ERROR_INVALID_PARAMETER);
    }
    match src.count() {
        -1 => Ok(src.units(true)),
        count if count <= 0 => refused(ERROR_INVALID_PARAMETER),
        _ => Ok(src.units(true)),
    }
}

/// A wide source, as the NLS calls take it: a negative count is NUL-terminated, the terminator
/// counted (and processed); zero and a null source are ERROR_INVALID_PARAMETER.
pub(crate) fn wide_source<'a>(src: &Counted<'a, u16>) -> Result<InBuf<'a, u16>, Failure> {
    if src.is_null() {
        return refused(ERROR_INVALID_PARAMETER);
    }
    match src.count() {
        0 => refused(ERROR_INVALID_PARAMETER),
        _ => Ok(src.units(true)),
    }
}

/// GetStringTypeA: the CT_CTYPE1, CT_CTYPE2 or CT_CTYPE3 classification of code page 1252 bytes,
/// through Unicode (the locale is the one this surface has). ERROR_INVALID_FLAGS for another
/// information type; ERROR_INVALID_PARAMETER for a zero count or no output.
///
/// # Safety
///
/// The source holds its count of bytes (a NUL-terminated string for -1); the output as many words.
#[unsafe(export_name = "f2k_export_GetStringTypeA")]
pub unsafe extern "system" fn get_string_type_a(
    _locale: u32,
    info: u32,
    src: *const u8,
    count: i32,
    out: *mut u16,
) -> u32 {
    // SAFETY: the caller's source and output (the contract: a flag word for each source unit,
    // which bounds the call's writes; a null output, which the call refuses, holds none).
    let (src, out) = unsafe { (Counted::new(src, count), OutBuf::new(out, usize::MAX)) };
    bool_answer(string_type_narrow(info, src, out))
}

/// GetStringTypeA's work.
fn string_type_narrow(
    info: u32,
    src: Counted<'_, u8>,
    mut out: OutBuf<'_, u16>,
) -> Result<(), Failure> {
    let classify = classifier(info)?;
    let src = narrow_source(&src)?;
    check_types(&out)?;
    for (at, byte) in src.iter().enumerate() {
        out.set(at, classify(cp1252::MB_TO_WC[byte as usize]));
    }
    Ok(())
}

/// GetStringTypeW: classify each wide char (CT_CTYPE1, CT_CTYPE2 or CT_CTYPE3), writing the flag
/// words, with the NLS calls' conventions (those GetStringTypeA follows): a NUL-terminated source
/// for a negative count, the terminator classified too; ERROR_INVALID_FLAGS for another
/// information type. A zero count is ERROR_INVALID_PARAMETER, the output untouched (the runtime
/// capture), as GetStringTypeA's is, and so is no output (the utility capture).
///
/// # Safety
///
/// As GetStringTypeA's, in units.
#[unsafe(export_name = "f2k_export_GetStringTypeW")]
pub unsafe extern "system" fn get_string_type_w(
    info: u32,
    src: *const u16,
    count: i32,
    out: *mut u16,
) -> u32 {
    // SAFETY: the caller's source and output (the contract: a flag word for each source unit,
    // which bounds the call's writes; a null output, which the call refuses, holds none).
    let (src, out) = unsafe { (Counted::new(src, count), OutBuf::new(out, usize::MAX)) };
    bool_answer(string_type_wide(info, src, out))
}

/// GetStringTypeExA: GetStringTypeA, with its locale.
///
/// # Safety
///
/// As GetStringTypeA's.
#[unsafe(export_name = "f2k_export_GetStringTypeExA")]
pub unsafe extern "system" fn get_string_type_ex_a(
    locale: u32,
    info: u32,
    src: *const u8,
    count: i32,
    out: *mut u16,
) -> u32 {
    // SAFETY: the caller's source and output, as GetStringTypeA takes them (the contract).
    unsafe { get_string_type_a(locale, info, src, count, out) }
}

/// GetStringTypeExW: GetStringTypeW, the locale ignored (as documented: Unicode characters
/// classify the same in every locale).
///
/// # Safety
///
/// As GetStringTypeW's.
#[unsafe(export_name = "f2k_export_GetStringTypeExW")]
pub unsafe extern "system" fn get_string_type_ex_w(
    _locale: u32,
    info: u32,
    src: *const u16,
    count: i32,
    out: *mut u16,
) -> u32 {
    // SAFETY: the caller's source and output, as GetStringTypeW takes them (the contract).
    unsafe { get_string_type_w(info, src, count, out) }
}

/// GetStringTypeW's work.
fn string_type_wide(
    info: u32,
    src: Counted<'_, u16>,
    mut out: OutBuf<'_, u16>,
) -> Result<(), Failure> {
    let classify = classifier(info)?;
    let src = wide_source(&src)?;
    check_types(&out)?;
    for (at, unit) in src.iter().enumerate() {
        out.set(at, classify(unit));
    }
    Ok(())
}

/// A CompareString argument: through its terminator for -1 (the terminator left out), else as
/// counted. ERROR_INVALID_PARAMETER for a null string or a length below -1.
fn compare_source<'a, U: Copy + Default + PartialEq>(
    string: &Counted<'a, U>,
) -> Result<InBuf<'a, U>, Failure> {
    if string.is_null() || string.count() < -1 {
        return refused(ERROR_INVALID_PARAMETER);
    }
    Ok(string.units(false))
}

/// The comparison CompareStringA and CompareStringW share, over strings of units read in place
/// through `decode` (see [`crate::collate`]). The locale is checked first, as Windows 2000 checks
/// it before the flags and the strings: ERROR_INVALID_PARAMETER for one it does not support
/// ([`crate::localeinfo::supported_locale`]); a supported one is not consulted further, every
/// locale comparing the same. ERROR_INVALID_FLAGS for an unknown flag.
fn compare_strings<U: Copy + Default + PartialEq>(
    locale: u32,
    flags: u32,
    a: Counted<'_, U>,
    b: Counted<'_, U>,
    decode: fn(U) -> u32,
) -> Result<i32, Failure> {
    if !crate::localeinfo::supported_locale(locale) {
        return refused(ERROR_INVALID_PARAMETER);
    }
    if flags & !crate::collate::VALID_FLAGS != 0 {
        return refused(ERROR_INVALID_FLAGS);
    }
    let a = compare_source(&a)?;
    let b = compare_source(&b)?;
    let read_a = |index: usize| decode(a.get(index));
    let read_b = |index: usize| decode(b.get(index));
    Ok(crate::collate::compare_with(&read_a, a.len(), &read_b, b.len(), flags) as i32)
}

/// A code page 1252 byte as the comparison weighs it: its Unicode character.
fn decode_ansi(byte: u8) -> u32 {
    u32::from(cp1252::MB_TO_WC[byte as usize])
}

/// CompareStringA: the comparison over ANSI strings, each byte decoded through code page 1252.
///
/// # Safety
///
/// Each string holds its count of bytes (NUL-terminated for -1).
#[unsafe(export_name = "f2k_export_CompareStringA")]
pub unsafe extern "system" fn compare_string_a(
    locale: u32,
    flags: u32,
    a: *const u8,
    a_count: i32,
    b: *const u8,
    b_count: i32,
) -> i32 {
    // SAFETY: the caller's strings (the contract).
    let (a, b) = unsafe { (Counted::new(a, a_count), Counted::new(b, b_count)) };
    answer(compare_strings(locale, flags, a, b, decode_ansi), 0)
}

/// CompareStringW: the comparison over UTF-16 code units.
///
/// # Safety
///
/// Each string holds its count of units (NUL-terminated for -1).
#[unsafe(export_name = "f2k_export_CompareStringW")]
pub unsafe extern "system" fn compare_string_w(
    locale: u32,
    flags: u32,
    a: *const u16,
    a_count: i32,
    b: *const u16,
    b_count: i32,
) -> i32 {
    // SAFETY: the caller's strings (the contract).
    let (a, b) = unsafe { (Counted::new(a, a_count), Counted::new(b, b_count)) };
    answer(compare_strings(locale, flags, a, b, u32::from), 0)
}

/// NORM_IGNORECASE: lstrcmpi's comparison.
const NORM_IGNORECASE: u32 = 0x1;

/// lstrcmp's answer from CompareString's over the two strings (each to its terminator, in the
/// thread's locale): its order less two, -1, 0 or 1. A NULL string, which CompareString refuses
/// (ERROR_INVALID_PARAMETER, left set), sorts before any other, and two NULLs are equal: the
/// runtime capture's answers.
fn lstrcmp_answer(compared: i32, first_null: bool, second_null: bool) -> i32 {
    if compared != 0 {
        return compared - 2;
    }
    i32::from(second_null && !first_null) - i32::from(first_null && !second_null)
}

/// The lstrcmp calls' work: CompareString's comparison in the thread's locale (which it does not
/// consult: SetThreadLocale checked it, and the comparison is every locale's), its answer as
/// [`lstrcmp_answer`] makes it.
fn lstrcmp<U: Copy + Default + PartialEq>(
    first: Counted<'_, U>,
    second: Counted<'_, U>,
    flags: u32,
    decode: fn(U) -> u32,
) -> i32 {
    let nulls = (first.is_null(), second.is_null());
    let locale = crate::localeinfo::LOCALE_USER_DEFAULT;
    let compared = answer(compare_strings(locale, flags, first, second, decode), 0);
    lstrcmp_answer(compared, nulls.0, nulls.1)
}

/// lstrcmpA: the ANSI strings compared as CompareStringA compares them, word sort, case counting
/// (see [`lstrcmp_answer`]).
///
/// # Safety
///
/// Each string is NULL or NUL-terminated.
#[unsafe(export_name = "f2k_export_lstrcmpA")]
pub unsafe extern "system" fn lstrcmp_a(first: *const u8, second: *const u8) -> i32 {
    // SAFETY: the caller's strings (the contract).
    let (a, b) = unsafe { (Counted::new(first, -1), Counted::new(second, -1)) };
    lstrcmp(a, b, 0, decode_ansi)
}

/// lstrcmpW (as [`lstrcmp_a`], over UTF-16 strings).
///
/// # Safety
///
/// Each string is NULL or NUL-terminated.
#[unsafe(export_name = "f2k_export_lstrcmpW")]
pub unsafe extern "system" fn lstrcmp_w(first: *const u16, second: *const u16) -> i32 {
    // SAFETY: the caller's strings (the contract).
    let (a, b) = unsafe { (Counted::new(first, -1), Counted::new(second, -1)) };
    lstrcmp(a, b, 0, u32::from)
}

/// lstrcmpiA (as [`lstrcmp_a`], case ignored: NORM_IGNORECASE).
///
/// # Safety
///
/// Each string is NULL or NUL-terminated.
#[unsafe(export_name = "f2k_export_lstrcmpiA")]
pub unsafe extern "system" fn lstrcmpi_a(first: *const u8, second: *const u8) -> i32 {
    // SAFETY: the caller's strings (the contract).
    let (a, b) = unsafe { (Counted::new(first, -1), Counted::new(second, -1)) };
    lstrcmp(a, b, NORM_IGNORECASE, decode_ansi)
}

/// lstrcmpiW (as [`lstrcmpi_a`], over UTF-16 strings).
///
/// # Safety
///
/// Each string is NULL or NUL-terminated.
#[unsafe(export_name = "f2k_export_lstrcmpiW")]
pub unsafe extern "system" fn lstrcmpi_w(first: *const u16, second: *const u16) -> i32 {
    // SAFETY: the caller's strings (the contract).
    let (a, b) = unsafe { (Counted::new(first, -1), Counted::new(second, -1)) };
    lstrcmp(a, b, NORM_IGNORECASE, u32::from)
}

/// GetThreadLocale: the calling thread's locale, from its TEB's CurrentLocale (the kernel starts
/// every thread in the default).
#[unsafe(export_name = "f2k_export_GetThreadLocale")]
pub extern "system" fn get_thread_locale() -> u32 {
    crate::base::current_locale()
}

/// SetThreadLocale: the calling thread's locale, in its TEB. The neutral locale (0) and the default
/// pseudo-locales (LOCALE_USER_DEFAULT, LOCALE_SYSTEM_DEFAULT) stand for the user's default; any
/// other must be a well-formed LCID — the default sort, no reserved bits, a primary language and a
/// sublanguage — or the call is ERROR_INVALID_PARAMETER, the locale kept. The locale's tables are
/// not consulted: a thread may name a locale this surface has no facts for (the runtime capture
/// sets French).
#[unsafe(export_name = "f2k_export_SetThreadLocale")]
pub extern "system" fn set_thread_locale(locale: u32) -> u32 {
    use crate::localeinfo::{LCID_EN_US, LOCALE_SYSTEM_DEFAULT, LOCALE_USER_DEFAULT};
    let locale = match locale {
        0 | LOCALE_USER_DEFAULT | LOCALE_SYSTEM_DEFAULT => LCID_EN_US,
        locale => locale,
    };
    let (primary, sublanguage) = (locale & 0x3FF, (locale >> 10) & 0x3F);
    if locale >> 16 != 0 || primary == 0 || sublanguage == 0 {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }
    crate::base::set_current_locale(locale);
    1
}

/// GetUserDefaultLCID: the one locale.
#[unsafe(export_name = "f2k_export_GetUserDefaultLCID")]
pub extern "system" fn get_user_default_lcid() -> u32 {
    crate::localeinfo::LCID_EN_US
}

/// GetUserDefaultLangID: the user's default locale's language,
/// LANGIDFROMLCID(GetUserDefaultLCID()), zero-extended.
#[unsafe(export_name = "f2k_export_GetUserDefaultLangID")]
pub extern "system" fn get_user_default_lang_id() -> u32 {
    get_user_default_lcid() & 0xFFFF
}

/// GetSystemDefaultLCID: the one locale.
#[unsafe(export_name = "f2k_export_GetSystemDefaultLCID")]
pub extern "system" fn get_system_default_lcid() -> u32 {
    crate::localeinfo::LCID_EN_US
}

/// IsValidLocale: whether Windows 2000 supports the locale (LCID_SUPPORTED) or the capture
/// machine's language group installs it (LCID_INSTALLED), see
/// [`crate::localeinfo::valid_locale`]; the last error is left alone.
#[unsafe(export_name = "f2k_export_IsValidLocale")]
pub extern "system" fn is_valid_locale(lcid: u32, flags: u32) -> u32 {
    u32::from(crate::localeinfo::valid_locale(lcid, flags))
}

/// GetLocaleInfoA/W's common body: the value, in `U`-sized characters (`unit` converting each
/// character: the W form's UTF-16, the A form's ANSI code page), through the NLS counting rule: a
/// zero size asks the room needed (the terminator counted), a fitting value is copied with its
/// terminator and its room returned. With LOCALE_RETURN_NUMBER a numeric value is a DWORD instead,
/// its room in `U`s (two units, four bytes); a value that is not a number is ERROR_INVALID_FLAGS.
/// LOCALE_FONTSIGNATURE is sixteen units of bits, no terminator: the A form copies their 32 bytes.
/// ERROR_INVALID_PARAMETER for a locale this surface does not describe or a bad buffer argument,
/// ERROR_INVALID_FLAGS for an unknown type, ERROR_INSUFFICIENT_BUFFER for a buffer too small.
fn get_locale_info<U: Copy>(
    lcid: u32,
    lctype: u32,
    mut buffer: OutBuf<'_, U>,
    size: i32,
    unit: fn(char) -> U,
) -> Result<i32, Failure> {
    use crate::localeinfo::{
        font_signature,
        info,
        names_locale,
        number,
        LOCALE_FONTSIGNATURE,
        LOCALE_RETURN_NUMBER,
    };
    if !names_locale(lcid) || size < 0 || (size > 0 && buffer.is_null()) {
        return refused(ERROR_INVALID_PARAMETER);
    }
    if lctype & LOCALE_RETURN_NUMBER != 0 {
        let value = number(lcid, lctype).ok_or(Failure::Error(ERROR_INVALID_FLAGS))?;
        let needed = core::mem::size_of::<u32>() / core::mem::size_of::<U>();
        if size == 0 {
            return Ok(needed as i32);
        }
        if (size as usize) < needed {
            return refused(ERROR_INSUFFICIENT_BUFFER);
        }
        buffer.reinterpret::<u32>().set(0, value);
        return Ok(needed as i32);
    }
    if lctype & 0xFFFF == LOCALE_FONTSIGNATURE {
        let signature = font_signature(lcid).ok_or(Failure::Error(ERROR_INVALID_FLAGS))?;
        let needed = signature.len() * 2 / core::mem::size_of::<U>();
        if size == 0 {
            return Ok(needed as i32);
        }
        if (size as usize) < needed {
            return refused(ERROR_INSUFFICIENT_BUFFER);
        }
        buffer.reinterpret::<u16>().put(&signature);
        return Ok(needed as i32);
    }
    let value = info(lcid, lctype).ok_or(Failure::Error(ERROR_INVALID_FLAGS))?;
    let needed = value.chars().count() + 1;
    if size == 0 {
        return Ok(needed as i32);
    }
    if (size as usize) < needed {
        return refused(ERROR_INSUFFICIENT_BUFFER);
    }
    for (at, c) in value.chars().chain(['\0']).enumerate() {
        buffer.set(at, unit(c));
    }
    Ok(needed as i32)
}

/// A locale value's character in the W form.
fn wide_char(c: char) -> u16 {
    c as u16
}

/// A locale value's character in the A form: its ANSI code page byte.
fn ansi_char(c: char) -> u8 {
    codepage::sbcs::CP1252
        .encode(c as u16, true)
        .unwrap_or(cp1252::DEFAULT_CHAR)
}

/// GetLocaleInfoA.
///
/// # Safety
///
/// The buffer holds `size` bytes.
#[unsafe(export_name = "f2k_export_GetLocaleInfoA")]
pub unsafe extern "system" fn get_locale_info_a(
    lcid: u32,
    lctype: u32,
    buffer: *mut u8,
    size: i32,
) -> i32 {
    // SAFETY: the caller's buffer of `size` characters (the contract; a negative size, which the
    // call refuses, holds none).
    let buffer = unsafe { OutBuf::new(buffer, room(size)) };
    answer(get_locale_info(lcid, lctype, buffer, size, ansi_char), 0)
}

/// GetLocaleInfoW.
///
/// # Safety
///
/// The buffer holds `size` units.
#[unsafe(export_name = "f2k_export_GetLocaleInfoW")]
pub unsafe extern "system" fn get_locale_info_w(
    lcid: u32,
    lctype: u32,
    buffer: *mut u16,
    size: i32,
) -> i32 {
    // SAFETY: the caller's buffer of `size` characters (the contract; a negative size, which the
    // call refuses, holds none).
    let buffer = unsafe { OutBuf::new(buffer, room(size)) };
    answer(get_locale_info(lcid, lctype, buffer, size, wide_char), 0)
}

/// The one locale's name, as EnumSystemLocalesA hands it to the callback, and as
/// EnumSystemLocalesW does.
const LOCALE_NAME: &[u8; 9] = b"00000409\0";
const LOCALE_NAME_W: [u16; 9] = {
    let mut units = [0u16; 9];
    let mut at = 0;
    while at < 9 {
        units[at] = LOCALE_NAME[at] as u16;
        at += 1;
    }
    units
};

/// EnumSystemLocalesA: the one locale, to the caller's callback (stdcall, its argument the locale's
/// name); ERROR_INVALID_PARAMETER for no callback.
///
/// # Safety
///
/// `callback` is a LOCALE_ENUMPROCA.
#[unsafe(export_name = "f2k_export_EnumSystemLocalesA")]
pub unsafe extern "system" fn enum_system_locales_a(
    callback: Option<unsafe extern "system" fn(*const u8) -> u32>,
    _flags: u32,
) -> u32 {
    let Some(callback) = callback else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    // SAFETY: the caller's callback, given the locale's name.
    unsafe { callback(LOCALE_NAME.as_ptr()) };
    1
}

/// EnumSystemLocalesW: as [`enum_system_locales_a`], the name wide.
///
/// # Safety
///
/// `callback` is a LOCALE_ENUMPROCW.
#[unsafe(export_name = "f2k_export_EnumSystemLocalesW")]
pub unsafe extern "system" fn enum_system_locales_w(
    callback: Option<unsafe extern "system" fn(*const u16) -> u32>,
    _flags: u32,
) -> u32 {
    let Some(callback) = callback else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    // SAFETY: the caller's callback, given the locale's name.
    unsafe { callback(LOCALE_NAME_W.as_ptr()) };
    1
}

/// EnumSystemCodePages' flags, and IsValidLanguageGroup's.
const CP_INSTALLED: u32 = 1;
const CP_SUPPORTED: u32 = 2;
const LGRPID_INSTALLED: u32 = 1;
const LGRPID_SUPPORTED: u32 = 2;

/// The code pages Windows 2000 supports: its NLS registry's list (Control\Nls\CodePage), with
/// UTF-7 and UTF-8, which EnumSystemCodePages adds to it. Reconstructed from the code page
/// identifiers MSDN documents for Windows 2000; the locale fixture's capture pins its length (133)
/// and that 437, 850, 1252 and 65001 are among it.
const SUPPORTED_CODE_PAGES: [u16; 133] = [
    37, 437, 500, 708, 720, 737, 775, 850, 852, 855, 857, 858, 860, 861, 862, 863, 864, 865, 866,
    869, 870, 874, 875, 932, 936, 949, 950, 1026, 1047, 1140, 1141, 1142, 1143, 1144, 1145, 1146,
    1147, 1148, 1149, 1250, 1251, 1252, 1253, 1254, 1255, 1256, 1257, 1258, 1361, 10000, 10001,
    10002, 10003, 10004, 10005, 10006, 10007, 10008, 10010, 10017, 10021, 10029, 10079, 10081,
    10082, 20000, 20001, 20002, 20003, 20004, 20005, 20105, 20106, 20107, 20108, 20127, 20261,
    20269, 20273, 20277, 20278, 20280, 20284, 20285, 20290, 20297, 20420, 20423, 20424, 20833,
    20838, 20866, 20871, 20880, 20905, 20924, 20932, 20936, 20949, 21025, 21027, 21866, 28591,
    28592, 28593, 28594, 28595, 28596, 28597, 28598, 28599, 28605, 50220, 50221, 50222, 50225,
    50227, 50229, 51932, 51949, 52936, 57002, 57003, 57004, 57005, 57006, 57007, 57008, 57009,
    57010, 57011, 65000, 65001,
];

/// The code pages a Windows 2000 machine with the Western Europe and United States language group
/// alone has installed (the capture machine's: its count is masked, as it follows the groups
/// installed): the group's OEM, ANSI, Mac, EBCDIC, ISO and IA5 pages, with UTF-7 and UTF-8. Most of
/// them have no table in F2K, which IsValidCodePage reports as not installed ([`rtl::codepage`]):
/// the capture's own installed list has a page IsValidCodePage refuses too ("IsValidCodePage of
/// each no" is the fixture's check that every listed page is valid, not that none is).
const INSTALLED_CODE_PAGES: [u16; 43] = [
    37, 437, 500, 850, 858, 860, 861, 863, 865, 1047, 1140, 1141, 1142, 1143, 1144, 1145, 1146,
    1147, 1148, 1149, 1252, 10000, 10079, 20105, 20106, 20107, 20108, 20127, 20261, 20269, 20273,
    20277, 20278, 20280, 20284, 20285, 20297, 20871, 20924, 28591, 28605, 65000, 65001,
];

/// The code pages EnumSystemCodePages lists for its flags: CP_INSTALLED's, or CP_SUPPORTED's (no
/// flag lists them too, as the capture's flags 0 does); ERROR_INVALID_FLAGS for anything else.
fn code_pages(flags: u32) -> Result<&'static [u16], Failure> {
    match flags {
        CP_INSTALLED => Ok(&INSTALLED_CODE_PAGES),
        0 | CP_SUPPORTED => Ok(&SUPPORTED_CODE_PAGES),
        _ => refused(ERROR_INVALID_FLAGS),
    }
}

/// A code page's number in decimal, NUL-terminated, into `out`: its digits' count.
fn code_page_name(page: u16, out: &mut [u8; 6]) -> usize {
    let digits = rtl::fmt::decimal(u64::from(page), 1);
    let count = digits.len();
    out[..count].copy_from_slice(digits.as_bytes());
    out[count] = 0;
    count
}

/// EnumSystemCodePages' walk: `call` given each listed page's name, until it answers FALSE — the
/// first call's answer unheeded, as the capture's callback answering FALSE is called twice.
/// ERROR_INVALID_PARAMETER for no callback, then ERROR_INVALID_FLAGS for flags it does not take.
fn enum_code_pages(
    has_callback: bool,
    flags: u32,
    mut call: impl FnMut(&[u8; 6]) -> bool,
) -> Result<(), Failure> {
    if !has_callback {
        return refused(ERROR_INVALID_PARAMETER);
    }
    for (index, &page) in code_pages(flags)?.iter().enumerate() {
        let mut name = [0u8; 6];
        code_page_name(page, &mut name);
        if !call(&name) && index > 0 {
            break;
        }
    }
    Ok(())
}

/// EnumSystemCodePagesA: the code pages the flags name, each one's decimal number handed to the
/// callback (see `enum_code_pages`); TRUE, or FALSE with the last error set.
///
/// # Safety
///
/// The callback, when given, is a CODEPAGE_ENUMPROCA.
#[unsafe(export_name = "f2k_export_EnumSystemCodePagesA")]
pub unsafe extern "system" fn enum_system_code_pages_a(
    callback: Option<unsafe extern "system" fn(*const u8) -> u32>,
    flags: u32,
) -> u32 {
    bool_answer(enum_code_pages(callback.is_some(), flags, |name| {
        let callback = callback.expect("checked before the walk");
        // SAFETY: the caller's callback (the contract), given a NUL-terminated name of its own.
        unsafe { callback(name.as_ptr()) != 0 }
    }))
}

/// EnumSystemCodePagesW: EnumSystemCodePagesA's walk, each name in UTF-16.
///
/// # Safety
///
/// The callback, when given, is a CODEPAGE_ENUMPROCW.
#[unsafe(export_name = "f2k_export_EnumSystemCodePagesW")]
pub unsafe extern "system" fn enum_system_code_pages_w(
    callback: Option<unsafe extern "system" fn(*const u16) -> u32>,
    flags: u32,
) -> u32 {
    bool_answer(enum_code_pages(callback.is_some(), flags, |name| {
        let callback = callback.expect("checked before the walk");
        let wide = name.map(u16::from);
        // SAFETY: the caller's callback (the contract), given a NUL-terminated name of its own.
        unsafe { callback(wide.as_ptr()) != 0 }
    }))
}

/// IsValidLanguageGroup: whether a language group is installed (LGRPID_INSTALLED: Western Europe
/// and United States, group 1, alone, as on the capture machine) or supported (LGRPID_SUPPORTED, or
/// no flag: Windows 2000's seventeen, 1 to 17). Other flags answer FALSE; the last error is never
/// set (the capture).
#[unsafe(export_name = "f2k_export_IsValidLanguageGroup")]
pub extern "system" fn is_valid_language_group(group: u32, flags: u32) -> u32 {
    let valid = match flags {
        LGRPID_INSTALLED => group == 1,
        0 | LGRPID_SUPPORTED => (1..=17).contains(&group),
        _ => false,
    };
    u32::from(valid)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The capture's facts: 133 supported pages, the installed among them, four pages in both, and
    /// a page listed as installed that IsValidCodePage refuses.
    #[test]
    fn the_code_page_lists() {
        assert!(SUPPORTED_CODE_PAGES
            .windows(2)
            .all(|pair| pair[0] < pair[1]));
        assert!(INSTALLED_CODE_PAGES
            .iter()
            .all(|page| SUPPORTED_CODE_PAGES.binary_search(page).is_ok()));
        for page in [437, 850, 1252, 65001] {
            assert!(INSTALLED_CODE_PAGES.contains(&page) && codepage::is_valid(u32::from(page)));
        }
        assert!(INSTALLED_CODE_PAGES
            .iter()
            .any(|&page| !codepage::is_valid(u32::from(page))));
        let mut name = [0u8; 6];
        assert_eq!(code_page_name(65001, &mut name), 5);
        assert_eq!(&name, b"65001\0");
    }

    /// The walk: every page for CP_SUPPORTED and for no flag; a callback answering FALSE called
    /// twice; the refusals.
    #[test]
    fn the_walk() {
        let mut calls = 0;
        assert_eq!(
            enum_code_pages(true, 0, |_| {
                calls += 1;
                true
            }),
            Ok(())
        );
        assert_eq!(calls, 133);
        calls = 0;
        assert_eq!(
            enum_code_pages(true, CP_INSTALLED, |_| {
                calls += 1;
                false
            }),
            Ok(())
        );
        assert_eq!(calls, 2);
        assert_eq!(
            enum_code_pages(true, 3, |_| true),
            Err(Failure::Error(ERROR_INVALID_FLAGS))
        );
        assert_eq!(
            enum_code_pages(false, CP_INSTALLED, |_| true),
            Err(Failure::Error(ERROR_INVALID_PARAMETER))
        );
        assert_eq!(
            (
                is_valid_language_group(1, 0),
                is_valid_language_group(17, 2)
            ),
            (1, 1)
        );
        assert_eq!(
            (
                is_valid_language_group(7, 1),
                is_valid_language_group(1, 3),
                is_valid_language_group(18, 2)
            ),
            (0, 0, 0)
        );
    }
}
