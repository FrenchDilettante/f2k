//! The locale group, kernel32's own NLS code as on Windows 2000 (no kernel transition): the code
//! pages and their conversions (MultiByteToWideChar and WideCharToMultiByte over `rtl::codepage`),
//! lead bytes (IsDBCSLeadByte) and the code page list (EnumSystemCodePages), the language groups
//! (IsValidLanguageGroup), case mapping and character types over code page 1252 (`rtl::cp1252`),
//! comparison ([`crate::collate`]), the one locale's facts ([`crate::localeinfo`]), and MulDiv,
//! which the group's spec section keeps beside them. The date, time and number formats are
//! [`crate::nlsformat`]'s, FoldString [`crate::fold`]'s.
//!
//! The caller's strings are read and written where they are: a pointer the caller cannot read or
//! write faults in the caller's thread, as kernel32's own code does on Windows 2000.

use rtl::codepage::{self, CodePage};
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

/// MultiByteToWideChar over 1252, 437 and UTF-8 (see [`rtl::codepage`]): a size query (no
/// destination size) or the conversion, the OEM page's control bytes as glyphs for
/// MB_USEGLYPHCHARS. ERROR_INVALID_FLAGS for a flag the page does not take
/// (UTF-8 takes none), ERROR_INVALID_PARAMETER for an unknown page or a bad count,
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

/// MultiByteToWideChar's work.
fn to_wide(
    cp: u32,
    flags: u32,
    src: Counted<'_, u8>,
    dst: OutBuf<'_, u16>,
    capacity: i32,
) -> Result<i32, Failure> {
    const VALID_FLAGS: u32 = 0xF; // precomposed, composite, glyph chars, invalid chars
    const MB_USEGLYPHCHARS: u32 = 0x4;
    if flags & !VALID_FLAGS != 0 || (cp == codepage::CP_UTF8 && flags != 0) {
        return refused(ERROR_INVALID_FLAGS);
    }
    let page = codepage::resolve(cp).ok_or(Failure::Error(ERROR_INVALID_PARAMETER))?;
    let bytes = convert_source(&src)?;
    check_destination(&dst, capacity)?;
    let mut out = Produced::new(dst);
    codepage::to_wide(page, bytes.bytes(), flags & MB_USEGLYPHCHARS != 0, |unit| {
        out.put(unit)
    });
    Ok(out.finish()? as i32)
}

/// WideCharToMultiByte over 1252, 437 and UTF-8: a single-byte page best-fits what it does not hold
/// (unless WC_NO_BEST_FIT_CHARS) and substitutes the default character (the caller's, else `?`)
/// for the rest, reporting it when asked; UTF-8 takes no flags, and neither a default nor the
/// report (ERROR_INVALID_PARAMETER). Errors as MultiByteToWideChar's.
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
    // Discard ns, sep chars, default char, composite check, no best fit.
    const VALID_FLAGS: u32 = 0x10 | 0x20 | 0x40 | 0x200 | WC_NO_BEST_FIT_CHARS;
    const WC_NO_BEST_FIT_CHARS: u32 = 0x400;
    let Narrow {
        default,
        used,
        capacity,
    } = narrow;
    let page = codepage::resolve(cp).ok_or(Failure::Error(ERROR_INVALID_PARAMETER))?;
    if flags & !VALID_FLAGS != 0 || (page == CodePage::Utf8 && flags != 0) {
        return refused(ERROR_INVALID_FLAGS);
    }
    if page == CodePage::Utf8 && (default.is_some() || used.is_some()) {
        return refused(ERROR_INVALID_PARAMETER);
    }
    let units = convert_source(&src)?;
    check_destination(&dst, capacity)?;
    let default = default.map_or(b'?', |default| default.read());
    let units = wide_units_of(units).ok_or(Failure::Error(ERROR_NOT_ENOUGH_MEMORY))?;
    let mut out = Produced::new(dst);
    let fit = flags & WC_NO_BEST_FIT_CHARS == 0;
    let replaced = codepage::to_narrow(page, &units, default, fit, |byte| out.put(byte));
    let produced = out.finish()?;
    if let Some(mut used) = used {
        used.set(u32::from(replaced));
    }
    Ok(produced as i32)
}

/// LCMapString's case-mapping flags.
const LCMAP_LOWERCASE: u32 = 0x0000_0100;
const LCMAP_UPPERCASE: u32 = 0x0000_0200;

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

/// A narrow source: -1 is through its terminator, which counts; zero and anything below -1 are
/// ERROR_INVALID_PARAMETER.
fn narrow_source<'a>(src: &Counted<'a, u8>) -> Result<InBuf<'a, u8>, Failure> {
    match src.count() {
        -1 => Ok(src.units(true)),
        count if count <= 0 => refused(ERROR_INVALID_PARAMETER),
        _ => Ok(src.units(true)),
    }
}

/// A wide source, as the NLS calls take it: a negative count is NUL-terminated, the terminator
/// counted (and processed); zero is ERROR_INVALID_PARAMETER.
fn wide_source<'a>(src: &Counted<'a, u16>) -> Result<InBuf<'a, u16>, Failure> {
    match src.count() {
        0 => refused(ERROR_INVALID_PARAMETER),
        _ => Ok(src.units(true)),
    }
}

/// LCMapStringA: case mapping of code page 1252 bytes, through Unicode (a byte whose mapped
/// character the page lacks stays itself). A size query (no destination size) returns the count;
/// ERROR_INSUFFICIENT_BUFFER for a destination too small; ERROR_INVALID_FLAGS for anything but the
/// two case mappings. Quirk, as captured: a mapping into the buffer leaves
/// ERROR_INSUFFICIENT_BUFFER as the last error even though it succeeds.
///
/// # Safety
///
/// The source holds its count of bytes (a NUL-terminated string for -1); the destination its size.
#[unsafe(export_name = "f2k_export_LCMapStringA")]
pub unsafe extern "system" fn lc_map_string_a(
    _locale: u32,
    flags: u32,
    src: *const u8,
    count: i32,
    dst: *mut u8,
    capacity: i32,
) -> i32 {
    // SAFETY: the caller's source and destination (the contract; a negative size reads as the
    // unsigned one, as Windows 2000's does).
    let (src, dst) = unsafe {
        (
            Counted::new(src, count),
            OutBuf::new(dst, capacity as u32 as usize),
        )
    };
    answer(map_narrow(flags, src, dst), 0)
}

/// LCMapStringA's work.
fn map_narrow(flags: u32, src: Counted<'_, u8>, mut dst: OutBuf<'_, u8>) -> Result<i32, Failure> {
    use cp1252::{map_case, wc_to_mb, MB_TO_WC};
    if flags != LCMAP_UPPERCASE && flags != LCMAP_LOWERCASE {
        return refused(ERROR_INVALID_FLAGS);
    }
    let src = narrow_source(&src)?;
    let count = src.len();
    if dst.is_empty() {
        return Ok(count as i32);
    }
    if dst.len() < count {
        return refused(ERROR_INSUFFICIENT_BUFFER);
    }
    for (at, byte) in src.iter().enumerate() {
        let mapped = map_case(MB_TO_WC[byte as usize], flags == LCMAP_UPPERCASE);
        let back = wc_to_mb(mapped);
        let out = if MB_TO_WC[back as usize] == mapped {
            back
        } else {
            byte
        };
        dst.set(at, out);
    }
    set_last_error(ERROR_INSUFFICIENT_BUFFER);
    Ok(count as i32)
}

/// LCMapStringW: case mapping over the 1252 character set, with the NLS calls' conventions (those
/// LCMapStringA follows): a NUL-terminated source for a negative count, the terminator mapped and
/// counted; a zero destination size asks the size needed; ERROR_INVALID_FLAGS for anything but the
/// two case mappings, ERROR_INVALID_PARAMETER for a zero source count, a negative destination size
/// or a null destination with a size, ERROR_INSUFFICIENT_BUFFER for a destination too small. The
/// locale is ignored (this surface has one).
///
/// # Safety
///
/// As LCMapStringA's, in units.
#[unsafe(export_name = "f2k_export_LCMapStringW")]
pub unsafe extern "system" fn lc_map_string_w(
    _locale: u32,
    flags: u32,
    src: *const u16,
    count: i32,
    dst: *mut u16,
    capacity: i32,
) -> i32 {
    // SAFETY: the caller's source and destination (the contract; a negative size, which the call
    // refuses before it writes, holds none).
    let (src, out) = unsafe { (Counted::new(src, count), OutBuf::new(dst, room(capacity))) };
    answer(map_wide(flags, src, out, capacity), 0)
}

/// LCMapStringW's work.
fn map_wide(
    flags: u32,
    src: Counted<'_, u16>,
    mut dst: OutBuf<'_, u16>,
    capacity: i32,
) -> Result<i32, Failure> {
    if flags != LCMAP_UPPERCASE && flags != LCMAP_LOWERCASE {
        return refused(ERROR_INVALID_FLAGS);
    }
    let upper = flags == LCMAP_UPPERCASE;
    check_destination(&dst, capacity)?;
    let src = wide_source(&src)?;
    let count = src.len();
    if dst.is_empty() {
        return Ok(count as i32); // the size query
    }
    if dst.len() < count {
        return refused(ERROR_INSUFFICIENT_BUFFER);
    }
    for (at, unit) in src.iter().enumerate() {
        dst.set(at, cp1252::map_case(unit, upper));
    }
    Ok(count as i32)
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

/// IsValidLocale: the one locale is installed and supported.
#[unsafe(export_name = "f2k_export_IsValidLocale")]
pub extern "system" fn is_valid_locale(lcid: u32, _flags: u32) -> u32 {
    u32::from(lcid == crate::localeinfo::LCID_EN_US)
}

/// GetLocaleInfoA/W's common body: the value, in `U`-sized characters (ASCII widened for the W
/// form), through the NLS counting rule: a zero size asks the room needed (the terminator counted),
/// a fitting value is copied with its terminator and its room returned. With LOCALE_RETURN_NUMBER a
/// numeric value is a DWORD instead, its room in `U`s (two units, four bytes); a value that is not
/// a number is ERROR_INVALID_FLAGS. ERROR_INVALID_PARAMETER for another locale or a bad buffer
/// argument, ERROR_INVALID_FLAGS for an unknown type, ERROR_INSUFFICIENT_BUFFER for a buffer too
/// small.
fn get_locale_info<U: Copy + From<u8>>(
    lcid: u32,
    lctype: u32,
    mut buffer: OutBuf<'_, U>,
    size: i32,
) -> Result<i32, Failure> {
    use crate::localeinfo::{info, names_locale, number, LOCALE_RETURN_NUMBER};
    if !names_locale(lcid) || size < 0 || (size > 0 && buffer.is_null()) {
        return refused(ERROR_INVALID_PARAMETER);
    }
    if lctype & LOCALE_RETURN_NUMBER != 0 {
        let value = number(lctype).ok_or(Failure::Error(ERROR_INVALID_FLAGS))?;
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
    let value = info(lctype).ok_or(Failure::Error(ERROR_INVALID_FLAGS))?;
    let needed = value.len() + 1;
    if size == 0 {
        return Ok(needed as i32);
    }
    if (size as usize) < needed {
        return refused(ERROR_INSUFFICIENT_BUFFER);
    }
    for (at, byte) in value.bytes().chain([0]).enumerate() {
        buffer.set(at, U::from(byte));
    }
    Ok(needed as i32)
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
    answer(get_locale_info(lcid, lctype, buffer, size), 0)
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
    answer(get_locale_info(lcid, lctype, buffer, size), 0)
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
    let mut digits = [0u8; 5];
    let mut count = 0;
    let mut value = page;
    loop {
        digits[count] = b'0' + (value % 10) as u8;
        count += 1;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    for (at, &digit) in digits[..count].iter().rev().enumerate() {
        out[at] = digit;
    }
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
