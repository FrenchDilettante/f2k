//! The locale group, kernel32's own NLS code as on Windows 2000 (no kernel transition): the code
//! pages and their conversions (MultiByteToWideChar and WideCharToMultiByte over `rtl::codepage`),
//! case mapping and character types over code page 1252 (`rtl::cp1252`), comparison
//! ([`crate::collate`]), and the one locale's facts ([`crate::localeinfo`]).
//!
//! The caller's strings are read and written where they are: a pointer the caller cannot read or
//! write faults in the caller's thread, as kernel32's own code does on Windows 2000.

use rtl::codepage::{self, CodePage};
use rtl::cp1252;

use crate::base::set_last_error;
use crate::error::{ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_FLAGS, ERROR_INVALID_PARAMETER};

/// The code pages this surface reports: ANSI 1252, OEM 437.
pub const ACP: u32 = 1252;
pub const OEMCP: u32 = 437;

/// A failed call: its last error set, the failure value returned.
fn fail<T>(code: u32, value: T) -> T {
    set_last_error(code);
    value
}

/// The length in units of the NUL-terminated string at `src`, the terminator excluded.
///
/// # Safety
///
/// `src` points at a NUL-terminated string.
unsafe fn length<U: Copy + Default + PartialEq>(src: *const U) -> usize {
    let mut at = 0;
    // SAFETY: the caller's contract: the units up to the terminator are readable.
    while unsafe { src.add(at).read_unaligned() } != U::default() {
        at += 1;
    }
    at
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

/// GetCPInfo: an installed code page's facts (see [`rtl::codepage::cp_info`]) into the 18-byte
/// CPINFO; FALSE with ERROR_INVALID_PARAMETER for another code page, the structure untouched.
///
/// # Safety
///
/// `info` points at a writable CPINFO.
#[unsafe(export_name = "f2k_export_GetCPInfo")]
pub unsafe extern "system" fn get_cp_info(page: u32, info: *mut u8) -> u32 {
    let Some(facts) = codepage::cp_info(page) else {
        return fail(ERROR_INVALID_PARAMETER, 0);
    };
    // SAFETY: the caller's CPINFO.
    unsafe { info.copy_from_nonoverlapping(facts.as_ptr(), facts.len()) };
    1
}

/// IsValidCodePage: whether the code page is installed.
#[unsafe(export_name = "f2k_export_IsValidCodePage")]
pub extern "system" fn is_valid_code_page(page: u32) -> u32 {
    u32::from(codepage::is_valid(page))
}

/// A conversion's source length in units: through the terminator for -1 (the terminator converted
/// too), else as given; ERROR_INVALID_PARAMETER for zero, a count below -1, or a null source.
///
/// # Safety
///
/// For -1, `src` points at a NUL-terminated string.
unsafe fn convert_length<U: Copy + Default + PartialEq>(
    src: *const U,
    count: i32,
) -> Result<usize, u32> {
    if src.is_null() || count == 0 || count < -1 {
        return Err(ERROR_INVALID_PARAMETER);
    }
    if count == -1 {
        // SAFETY: the caller's contract.
        return Ok(unsafe { length(src) } + 1);
    }
    Ok(count as usize)
}

/// Where a conversion's output goes: the units produced are counted, and written while the
/// destination (of `capacity` units; none for a size query) has room.
struct Out<U> {
    dst: *mut U,
    capacity: usize,
    produced: usize,
}

impl<U> Out<U> {
    fn new(dst: *mut U, capacity: i32) -> Self {
        Out {
            dst,
            capacity: capacity as usize,
            produced: 0,
        }
    }

    /// One more unit.
    ///
    /// # Safety
    ///
    /// The destination has `capacity` writable units.
    unsafe fn put(&mut self, unit: U) {
        if self.produced < self.capacity {
            // SAFETY: inside the destination's capacity.
            unsafe { self.dst.add(self.produced).write_unaligned(unit) };
        }
        self.produced += 1;
    }

    /// The conversion's answer: the count, or ERROR_INSUFFICIENT_BUFFER when the destination was
    /// too short (a size query never is).
    fn finish(&self) -> Result<usize, u32> {
        if self.capacity != 0 && self.produced > self.capacity {
            Err(ERROR_INSUFFICIENT_BUFFER)
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
    const VALID_FLAGS: u32 = 0xF; // precomposed, composite, glyph chars, invalid chars
    const MB_USEGLYPHCHARS: u32 = 0x4;
    if flags & !VALID_FLAGS != 0 || (cp == codepage::CP_UTF8 && flags != 0) {
        return fail(ERROR_INVALID_FLAGS, 0);
    }
    let Some(page) = codepage::resolve(cp) else {
        return fail(ERROR_INVALID_PARAMETER, 0);
    };
    // SAFETY: the caller's contract.
    let count = match unsafe { convert_length(src, count) } {
        Ok(count) => count,
        Err(code) => return fail(code, 0),
    };
    if capacity < 0 || (dst.is_null() && capacity != 0) {
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    // SAFETY: the caller's source of `count` bytes.
    let bytes = unsafe { core::slice::from_raw_parts(src, count) };
    let mut out = Out::new(dst, capacity);
    // SAFETY: the caller's destination of `capacity` units.
    codepage::to_wide(page, bytes, flags & MB_USEGLYPHCHARS != 0, |unit| unsafe {
        out.put(unit)
    });
    match out.finish() {
        Ok(count) => count as i32,
        Err(code) => fail(code, 0),
    }
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
    // Discard ns, sep chars, default char, composite check, no best fit.
    const VALID_FLAGS: u32 = 0x10 | 0x20 | 0x40 | 0x200 | WC_NO_BEST_FIT_CHARS;
    const WC_NO_BEST_FIT_CHARS: u32 = 0x400;
    let Some(page) = codepage::resolve(cp) else {
        return fail(ERROR_INVALID_PARAMETER, 0);
    };
    if flags & !VALID_FLAGS != 0 || (page == CodePage::Utf8 && flags != 0) {
        return fail(ERROR_INVALID_FLAGS, 0);
    }
    if page == CodePage::Utf8 && (!default_char.is_null() || !used_default.is_null()) {
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    // SAFETY: the caller's contract.
    let count = match unsafe { convert_length(src, count) } {
        Ok(count) => count,
        Err(code) => return fail(code, 0),
    };
    if capacity < 0 || (dst.is_null() && capacity != 0) {
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    // SAFETY: the caller's default character, when given.
    let default = if default_char.is_null() {
        b'?'
    } else {
        unsafe { default_char.read() }
    };
    // SAFETY: the caller's source of `count` units.
    let units = unsafe { core::slice::from_raw_parts(src, count) };
    let mut out = Out::new(dst, capacity);
    let fit = flags & WC_NO_BEST_FIT_CHARS == 0;
    // SAFETY: the caller's destination of `capacity` bytes.
    let used = codepage::to_narrow(page, units, default, fit, |byte| unsafe { out.put(byte) });
    let produced = match out.finish() {
        Ok(count) => count,
        Err(code) => return fail(code, 0),
    };
    if !used_default.is_null() {
        // SAFETY: the caller's report.
        unsafe { used_default.write_unaligned(u32::from(used)) };
    }
    produced as i32
}

/// LCMapString's case-mapping flags.
const LCMAP_LOWERCASE: u32 = 0x0000_0100;
const LCMAP_UPPERCASE: u32 = 0x0000_0200;

/// GetStringType's one information type.
const CT_CTYPE1: u32 = 1;

/// A narrow source count: -1 is through its terminator, which counts; zero and anything below -1
/// are ERROR_INVALID_PARAMETER.
///
/// # Safety
///
/// For -1, `src` points at a NUL-terminated string.
unsafe fn narrow_count(src: *const u8, count: i32) -> Result<usize, u32> {
    match count {
        // SAFETY: the caller's contract.
        -1 => Ok(unsafe { length(src) } + 1),
        count if count <= 0 => Err(ERROR_INVALID_PARAMETER),
        count => Ok(count as usize),
    }
}

/// A wide source count, as the NLS calls take it: a negative count is NUL-terminated, the
/// terminator counted (and processed); zero is ERROR_INVALID_PARAMETER.
///
/// # Safety
///
/// For a negative count, `src` points at a NUL-terminated string.
unsafe fn wide_count(src: *const u16, count: i32) -> Result<usize, u32> {
    match count {
        0 => Err(ERROR_INVALID_PARAMETER),
        // SAFETY: the caller's contract.
        count if count < 0 => Ok(unsafe { length(src) } + 1),
        count => Ok(count as usize),
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
    use cp1252::{map_case, wc_to_mb, MB_TO_WC};
    if flags != LCMAP_UPPERCASE && flags != LCMAP_LOWERCASE {
        return fail(ERROR_INVALID_FLAGS, 0);
    }
    // SAFETY: the caller's contract.
    let count = match unsafe { narrow_count(src, count) } {
        Ok(count) => count,
        Err(code) => return fail(code, 0),
    };
    let capacity = capacity as u32 as usize;
    if capacity == 0 {
        return count as i32;
    }
    if capacity < count {
        return fail(ERROR_INSUFFICIENT_BUFFER, 0);
    }
    for at in 0..count {
        // SAFETY: inside the caller's source and destination.
        let byte = unsafe { src.add(at).read() };
        let mapped = map_case(MB_TO_WC[byte as usize], flags == LCMAP_UPPERCASE);
        let back = wc_to_mb(mapped);
        let out = if MB_TO_WC[back as usize] == mapped {
            back
        } else {
            byte
        };
        // SAFETY: as above.
        unsafe { dst.add(at).write(out) };
    }
    set_last_error(ERROR_INSUFFICIENT_BUFFER);
    count as i32
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
    if flags != LCMAP_UPPERCASE && flags != LCMAP_LOWERCASE {
        return fail(ERROR_INVALID_FLAGS, 0);
    }
    let upper = flags == LCMAP_UPPERCASE;
    if capacity < 0 || (dst.is_null() && capacity != 0) {
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    // SAFETY: the caller's contract.
    let count = match unsafe { wide_count(src, count) } {
        Ok(count) => count,
        Err(code) => return fail(code, 0),
    };
    if capacity == 0 {
        return count as i32; // the size query
    }
    if (capacity as usize) < count {
        return fail(ERROR_INSUFFICIENT_BUFFER, 0);
    }
    for at in 0..count {
        // SAFETY: inside the caller's source and destination.
        unsafe {
            dst.add(at)
                .write_unaligned(cp1252::map_case(src.add(at).read_unaligned(), upper))
        };
    }
    count as i32
}

/// GetStringTypeA: CT_CTYPE1 classification of code page 1252 bytes, through Unicode (the locale is
/// the one this surface has). ERROR_INVALID_FLAGS for another information type.
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
    if info != CT_CTYPE1 {
        return fail(ERROR_INVALID_FLAGS, 0);
    }
    // SAFETY: the caller's contract.
    let count = match unsafe { narrow_count(src, count) } {
        Ok(count) => count,
        Err(code) => return fail(code, 0),
    };
    for at in 0..count {
        // SAFETY: inside the caller's source and output.
        unsafe {
            let byte = src.add(at).read();
            out.add(at)
                .write_unaligned(cp1252::c1_flags(cp1252::MB_TO_WC[byte as usize]));
        }
    }
    1
}

/// GetStringTypeW: classify each wide char (CT_CTYPE1 only), writing the flag words, with the NLS
/// calls' conventions (those GetStringTypeA follows): a NUL-terminated source for a negative count,
/// the terminator classified too; ERROR_INVALID_FLAGS for another information type. A zero count
/// is ERROR_INVALID_PARAMETER, the output untouched (the runtime capture), as GetStringTypeA's is.
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
    if info != CT_CTYPE1 {
        return fail(ERROR_INVALID_FLAGS, 0);
    }
    if count == 0 {
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    // SAFETY: the caller's contract.
    let count = match unsafe { wide_count(src, count) } {
        Ok(count) => count,
        Err(code) => return fail(code, 0),
    };
    for at in 0..count {
        // SAFETY: inside the caller's source and output.
        unsafe {
            out.add(at)
                .write_unaligned(cp1252::c1_flags(src.add(at).read_unaligned()))
        };
    }
    1
}

/// A CompareString argument's length in units: through its terminator for -1, else as given.
/// ERROR_INVALID_PARAMETER for a null string or a length below -1.
///
/// # Safety
///
/// For -1, `string` points at a NUL-terminated string.
unsafe fn compare_length<U: Copy + Default + PartialEq>(
    string: *const U,
    count: i32,
) -> Result<usize, u32> {
    if string.is_null() || count < -1 {
        return Err(ERROR_INVALID_PARAMETER);
    }
    if count == -1 {
        // SAFETY: the caller's contract.
        return Ok(unsafe { length(string) });
    }
    Ok(count as usize)
}

/// The comparison CompareStringA and CompareStringW share, over strings of units read in place
/// through `decode` (see [`crate::collate`]). The locale is not consulted: every locale compares
/// the same. ERROR_INVALID_FLAGS for an unknown flag.
///
/// # Safety
///
/// Each string holds its count of units (NUL-terminated for -1).
unsafe fn compare_strings<U: Copy + Default + PartialEq>(
    flags: u32,
    (a, a_count): (*const U, i32),
    (b, b_count): (*const U, i32),
    decode: fn(U) -> u32,
) -> i32 {
    if flags & !crate::collate::VALID_FLAGS != 0 {
        return fail(ERROR_INVALID_FLAGS, 0);
    }
    // SAFETY: the caller's contract.
    let lengths = unsafe {
        compare_length(a, a_count).and_then(|a_len| Ok((a_len, compare_length(b, b_count)?)))
    };
    let (a_len, b_len) = match lengths {
        Ok(lengths) => lengths,
        Err(code) => return fail(code, 0),
    };
    // SAFETY: the comparison reads below each string's length.
    let read =
        |base: *const U| move |index: usize| decode(unsafe { base.add(index).read_unaligned() });
    crate::collate::compare_with(&read(a), a_len, &read(b), b_len, flags) as i32
}

/// CompareStringA: the comparison over ANSI strings, each byte decoded through code page 1252.
///
/// # Safety
///
/// Each string holds its count of bytes (NUL-terminated for -1).
#[unsafe(export_name = "f2k_export_CompareStringA")]
pub unsafe extern "system" fn compare_string_a(
    _locale: u32,
    flags: u32,
    a: *const u8,
    a_count: i32,
    b: *const u8,
    b_count: i32,
) -> i32 {
    // SAFETY: the caller's contract.
    unsafe {
        compare_strings(flags, (a, a_count), (b, b_count), |byte| {
            u32::from(cp1252::MB_TO_WC[byte as usize])
        })
    }
}

/// CompareStringW: the comparison over UTF-16 code units.
///
/// # Safety
///
/// Each string holds its count of units (NUL-terminated for -1).
#[unsafe(export_name = "f2k_export_CompareStringW")]
pub unsafe extern "system" fn compare_string_w(
    _locale: u32,
    flags: u32,
    a: *const u16,
    a_count: i32,
    b: *const u16,
    b_count: i32,
) -> i32 {
    // SAFETY: the caller's contract.
    unsafe { compare_strings(flags, (a, a_count), (b, b_count), u32::from) }
}

/// GetUserDefaultLCID: the one locale.
#[unsafe(export_name = "f2k_export_GetUserDefaultLCID")]
pub extern "system" fn get_user_default_lcid() -> u32 {
    crate::localeinfo::LCID_EN_US
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
///
/// # Safety
///
/// The buffer holds `size` units.
unsafe fn get_locale_info<U: From<u8>>(lcid: u32, lctype: u32, buffer: *mut U, size: i32) -> i32 {
    use crate::localeinfo::{info, names_locale, number, LOCALE_RETURN_NUMBER};
    if !names_locale(lcid) || size < 0 || (size > 0 && buffer.is_null()) {
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    if lctype & LOCALE_RETURN_NUMBER != 0 {
        let Some(value) = number(lctype) else {
            return fail(ERROR_INVALID_FLAGS, 0);
        };
        let needed = core::mem::size_of::<u32>() / core::mem::size_of::<U>();
        if size == 0 {
            return needed as i32;
        }
        if (size as usize) < needed {
            return fail(ERROR_INSUFFICIENT_BUFFER, 0);
        }
        // SAFETY: the caller's buffer holds the DWORD.
        unsafe { (buffer as *mut u32).write_unaligned(value) };
        return needed as i32;
    }
    let Some(value) = info(lctype) else {
        return fail(ERROR_INVALID_FLAGS, 0);
    };
    let needed = value.len() + 1;
    if size == 0 {
        return needed as i32;
    }
    if (size as usize) < needed {
        return fail(ERROR_INSUFFICIENT_BUFFER, 0);
    }
    for (at, byte) in value.bytes().chain([0]).enumerate() {
        // SAFETY: inside the caller's buffer.
        unsafe { buffer.add(at).write_unaligned(U::from(byte)) };
    }
    needed as i32
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
    // SAFETY: the caller's contract.
    unsafe { get_locale_info(lcid, lctype, buffer, size) }
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
    // SAFETY: the caller's contract.
    unsafe { get_locale_info(lcid, lctype, buffer, size) }
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
        return fail(ERROR_INVALID_PARAMETER, 0);
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
        return fail(ERROR_INVALID_PARAMETER, 0);
    };
    // SAFETY: the caller's callback, given the locale's name.
    unsafe { callback(LOCALE_NAME_W.as_ptr()) };
    1
}
