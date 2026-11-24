//! LCMapStringW and LCMapStringA: a string mapped by the LCMAP_ and NORM_ flags, or its sort key
//! ([`super::sortkey`]), as Windows 2000's kernel32 maps them.
//!
//! The checks come in Windows 2000's order: the locale (ERROR_INVALID_PARAMETER for one it does not
//! support), the arguments (ERROR_INVALID_PARAMETER: no source, a zero count, a negative size, no
//! destination with a size, a sort key or any mapping but case's into its own source), then the
//! flags (ERROR_INVALID_FLAGS):
//!
//! - LCMAP_SORTKEY goes with the NORM_ flags, SORT_STRINGSORT and LCMAP_BYTEREV alone; its size is
//!   in bytes, and a -1 count leaves the terminator out of the key;
//! - otherwise NORM_IGNORENONSPACE and NORM_IGNORESYMBOLS go with each other and LCMAP_BYTEREV only
//!   (they drop the nonspacing marks, a precomposed letter's included, and the punctuation and
//!   symbols), and the other NORM_ flags and SORT_STRINGSORT not at all;
//! - LCMAP_UPPERCASE and LCMAP_LOWERCASE, LCMAP_HIRAGANA and LCMAP_KATAKANA, LCMAP_HALFWIDTH and
//!   LCMAP_FULLWIDTH, LCMAP_SIMPLIFIED_CHINESE and LCMAP_TRADITIONAL_CHINESE each exclude the
//!   other; no flag at all is refused too. LCMAP_BYTEREV swaps each unit's bytes after the rest.
//!
//! The width maps cover ASCII and the ideographic space against the fullwidth forms, and the
//! halfwidth symbols; the kana maps hiragana and katakana; the Chinese maps leave the string as it
//! is (not covered). A mapping's -1 count takes the terminator in, mapped and counted. A
//! destination too small is ERROR_INSUFFICIENT_BUFFER, nothing written.
//!
//! LCMapStringA converts its source through the ANSI code page, maps it as LCMapStringW does, and
//! converts a mapping back with the page's best fit (a unit it has nothing for is `?`); a sort key
//! is the same bytes. Quirk, as the runtime capture has it: a source past 128 characters leaves
//! ERROR_INSUFFICIENT_BUFFER as the last error, Windows 2000's first try into its stack buffer,
//! though the call succeeds.

use rtl::codepage::sbcs::CP1252;
use rtl::cp1252;
use rtl::winerror::{
    ERROR_INSUFFICIENT_BUFFER,
    ERROR_INVALID_FLAGS,
    ERROR_INVALID_PARAMETER,
    ERROR_NOT_ENOUGH_MEMORY,
};

use super::sortkey::{
    self,
    NORM_IGNORECASE,
    NORM_IGNOREKANATYPE,
    NORM_IGNORENONSPACE,
    NORM_IGNORESYMBOLS,
    NORM_IGNOREWIDTH,
    SORT_STRINGSORT,
};
use super::{narrow_source, refused, room, wide_source};
use crate::base::set_last_error;
use crate::edge::{Counted, OutBuf};
use crate::error::{answer, Failure};
use crate::heap::HeapVec;

/// The LCMAP_ flags.
const LCMAP_LOWERCASE: u32 = 0x0000_0100;
const LCMAP_UPPERCASE: u32 = 0x0000_0200;
const LCMAP_SORTKEY: u32 = 0x0000_0400;
const LCMAP_BYTEREV: u32 = 0x0000_0800;
const LCMAP_HIRAGANA: u32 = 0x0010_0000;
const LCMAP_KATAKANA: u32 = 0x0020_0000;
const LCMAP_HALFWIDTH: u32 = 0x0040_0000;
const LCMAP_FULLWIDTH: u32 = 0x0080_0000;
const LCMAP_SIMPLIFIED_CHINESE: u32 = 0x0200_0000;
const LCMAP_TRADITIONAL_CHINESE: u32 = 0x0400_0000;

/// The NORM_ flags a sort key takes, and the two a mapping does.
const NORM_KEY: u32 = NORM_IGNORECASE
    | NORM_IGNORENONSPACE
    | NORM_IGNORESYMBOLS
    | NORM_IGNOREKANATYPE
    | NORM_IGNOREWIDTH
    | SORT_STRINGSORT;
const NORM_MAP: u32 = NORM_IGNORENONSPACE | NORM_IGNORESYMBOLS;

/// The maps, and the pairs of them that exclude each other.
const MAPS: u32 = LCMAP_LOWERCASE
    | LCMAP_UPPERCASE
    | LCMAP_HIRAGANA
    | LCMAP_KATAKANA
    | LCMAP_HALFWIDTH
    | LCMAP_FULLWIDTH
    | LCMAP_SIMPLIFIED_CHINESE
    | LCMAP_TRADITIONAL_CHINESE;
const EXCLUSIVE: [u32; 4] = [
    LCMAP_LOWERCASE | LCMAP_UPPERCASE,
    LCMAP_HIRAGANA | LCMAP_KATAKANA,
    LCMAP_HALFWIDTH | LCMAP_FULLWIDTH,
    LCMAP_SIMPLIFIED_CHINESE | LCMAP_TRADITIONAL_CHINESE,
];

/// The flags judged (see the module notes): ERROR_INVALID_FLAGS for a combination Windows 2000
/// refuses.
fn check_flags(flags: u32) -> Result<(), Failure> {
    let rest = flags & !LCMAP_BYTEREV;
    let valid = if flags & LCMAP_SORTKEY != 0 {
        rest & !(LCMAP_SORTKEY | NORM_KEY) == 0
    } else if rest & NORM_MAP != 0 {
        rest & !NORM_MAP == 0
    } else {
        flags != 0 && rest & !MAPS == 0 && EXCLUSIVE.iter().all(|&pair| rest & pair != pair)
    };
    match valid {
        true => Ok(()),
        false => refused(ERROR_INVALID_FLAGS),
    }
}

/// The checks before the flags: the locale, the source, the destination, a mapping into its own
/// source.
fn check_call(
    locale: u32,
    flags: u32,
    null_source: bool,
    count: i32,
    capacity: i32,
    null_destination: bool,
    same: bool,
) -> Result<(), Failure> {
    let in_place = same && flags & !(LCMAP_UPPERCASE | LCMAP_LOWERCASE) != 0;
    let refused_call = !crate::localeinfo::supported_locale(locale)
        || null_source
        || count == 0
        || capacity < 0
        || (null_destination && capacity != 0)
        || in_place;
    if refused_call {
        return refused(ERROR_INVALID_PARAMETER);
    }
    check_flags(flags)
}

/// The width maps' pairs outside ASCII's run: the ideographic space and the halfwidth symbols.
const WIDTH_PAIRS: [(u16, u16); 8] = [
    (0x0020, 0x3000),
    (0x00A2, 0xFFE0),
    (0x00A3, 0xFFE1),
    (0x00AC, 0xFFE2),
    (0x00AF, 0xFFE3),
    (0x00A6, 0xFFE4),
    (0x00A5, 0xFFE5),
    (0x20A9, 0xFFE6),
];

/// `unit` in full width (LCMAP_FULLWIDTH) or half width.
fn widened(unit: u16, full: bool) -> u16 {
    match unit {
        0x21..=0x7E if full => unit + 0xFEE0,
        0xFF01..=0xFF5E if !full => unit - 0xFEE0,
        _ => WIDTH_PAIRS
            .iter()
            .find_map(|&(half, wide)| match full {
                true => (unit == half).then_some(wide),
                false => (unit == wide).then_some(half),
            })
            .unwrap_or(unit),
    }
}

/// `unit` as katakana (LCMAP_KATAKANA) or hiragana: the kana the two scripts share.
fn kana(unit: u16, katakana: bool) -> u16 {
    match unit {
        0x3041..=0x3096 | 0x309D | 0x309E if katakana => unit + 0x60,
        0x30A1..=0x30F6 | 0x30FD | 0x30FE if !katakana => unit - 0x60,
        _ => unit,
    }
}

/// The string `units` mapped by `flags` (judged, no sort key), each unit to `out`.
fn map(flags: u32, units: impl Iterator<Item = u16>, mut out: impl FnMut(u16)) {
    let mut put = |unit: u16| {
        if flags & NORM_IGNORENONSPACE != 0 && sortkey::is_nonspacing(unit) {
            return;
        }
        if flags & NORM_IGNORESYMBOLS != 0 && sortkey::is_symbol(unit) {
            return;
        }
        let mut unit = unit;
        if flags & (LCMAP_UPPERCASE | LCMAP_LOWERCASE) != 0 {
            unit = cp1252::map_case(unit, flags & LCMAP_UPPERCASE != 0);
        }
        if flags & (LCMAP_HALFWIDTH | LCMAP_FULLWIDTH) != 0 {
            unit = widened(unit, flags & LCMAP_FULLWIDTH != 0);
        }
        if flags & (LCMAP_HIRAGANA | LCMAP_KATAKANA) != 0 {
            unit = kana(unit, flags & LCMAP_KATAKANA != 0);
        }
        if flags & LCMAP_BYTEREV != 0 {
            unit = unit.swap_bytes();
        }
        out(unit);
    };
    for unit in units {
        match crate::fold::decomposed(unit) {
            Some((base, mark)) if flags & NORM_IGNORENONSPACE != 0 => {
                put(base);
                put(mark);
            }
            _ => put(unit),
        }
    }
}

/// The sort key of `units` (`count` of them) under the locale and the flags (judged), each byte to
/// `out`; none without memory for its weights.
fn sort_key(
    locale: u32,
    flags: u32,
    units: impl Iterator<Item = u16>,
    count: usize,
    mut out: impl FnMut(u8),
) -> Result<(), Failure> {
    let no_memory = |_| Failure::Error(ERROR_NOT_ENOUGH_MEMORY);
    // An expansion is three elements at the most.
    let mut elements = HeapVec::with_capacity(3 * count).map_err(no_memory)?;
    let mut specials = HeapVec::with_capacity(3 * count).map_err(no_memory)?;
    sortkey::weigh(
        flags,
        units,
        |element| elements.push(element),
        |special| specials.push(special),
    );
    let reverse = sortkey::reverses_diacritics(effective(locale));
    sortkey::assemble(flags, reverse, &elements[..], &specials[..], |byte| {
        out(byte)
    });
    Ok(())
}

/// The locale a default pseudo-locale stands for.
fn effective(locale: u32) -> u32 {
    match locale & 0xFFFF {
        0 | 0x0400 | 0x0800 => crate::localeinfo::LCID_EN_US,
        _ => locale,
    }
}

/// What a call produced: its units, on the process heap, then copied into the destination when they
/// fit (none written otherwise).
fn deliver<U: Copy + Default>(produced: &[U], mut dst: OutBuf<'_, U>) -> Result<i32, Failure> {
    if dst.is_empty() {
        return Ok(produced.len() as i32); // the size query
    }
    if dst.len() < produced.len() {
        return refused(ERROR_INSUFFICIENT_BUFFER);
    }
    dst.put(produced);
    Ok(produced.len() as i32)
}

/// A sort key's bytes with LCMAP_BYTEREV: each pair swapped, as the key's units would be.
fn reverse_pairs(bytes: &mut [u8]) {
    bytes
        .as_chunks_mut::<2>()
        .0
        .iter_mut()
        .for_each(|pair| pair.swap(0, 1));
}

/// LCMapStringW: see the module notes.
///
/// # Safety
///
/// The source holds `count` units (a NUL-terminated string for a negative count); the destination
/// `capacity` units, or bytes for a sort key.
#[unsafe(export_name = "f2k_export_LCMapStringW")]
pub unsafe extern "system" fn lc_map_string_w(
    locale: u32,
    flags: u32,
    src: *const u16,
    count: i32,
    dst: *mut u16,
    capacity: i32,
) -> i32 {
    let same = !src.is_null() && core::ptr::eq(src, dst);
    // SAFETY: the caller's source (the contract).
    let src = unsafe { Counted::new(src, count) };
    let checked = check_call(
        locale,
        flags,
        src.is_null(),
        count,
        capacity,
        dst.is_null(),
        same,
    );
    if let Err(failure) = checked {
        return answer::<i32>(Err(failure), 0);
    }
    if flags & LCMAP_SORTKEY != 0 {
        // SAFETY: the caller's destination of `capacity` bytes (the contract).
        let out = unsafe { OutBuf::new(dst.cast::<u8>(), room(capacity)) };
        let units = src.units(false);
        return answer(key_into(locale, flags, units.iter(), units.len(), out), 0);
    }
    // SAFETY: the caller's destination of `capacity` units (the contract).
    let out = unsafe { OutBuf::new(dst, room(capacity)) };
    answer(map_wide(flags, src, out), 0)
}

/// A sort key into the caller's bytes.
fn key_into(
    locale: u32,
    flags: u32,
    units: impl Iterator<Item = u16>,
    count: usize,
    out: OutBuf<'_, u8>,
) -> Result<i32, Failure> {
    // The key's bytes: two a unit and one each of three weights an element, three elements a unit
    // at the most; two more a unit for the special weights; the separators.
    let mut key = HeapVec::with_capacity(16 * count + 8)
        .map_err(|_| Failure::Error(ERROR_NOT_ENOUGH_MEMORY))?;
    sort_key(locale, flags, units, count, |byte| key.push(byte))?;
    if flags & LCMAP_BYTEREV != 0 {
        reverse_pairs(&mut key);
    }
    deliver(&key, out)
}

/// LCMapStringW's mapping.
fn map_wide(flags: u32, src: Counted<'_, u16>, mut dst: OutBuf<'_, u16>) -> Result<i32, Failure> {
    let units = wide_source(&src)?;
    if flags & NORM_MAP == 0 {
        // A unit for a unit: the size is the source's, known before it is read.
        let count = units.len();
        if dst.is_empty() {
            return Ok(count as i32);
        }
        if dst.len() < count {
            return refused(ERROR_INSUFFICIENT_BUFFER);
        }
        let mut at = 0;
        map(flags, units.iter(), |unit| {
            dst.set(at, unit);
            at += 1;
        });
        return Ok(count as i32);
    }
    let mut mapped = HeapVec::with_capacity(2 * units.len())
        .map_err(|_| Failure::Error(ERROR_NOT_ENOUGH_MEMORY))?;
    map(flags, units.iter(), |unit| mapped.push(unit));
    deliver(&mapped, dst)
}

/// The characters past which LCMapStringA's conversion overflows Windows 2000's stack buffer.
const STACK_STRING: usize = 128;

/// LCMapStringA: see the module notes.
///
/// # Safety
///
/// The source holds `count` bytes (a NUL-terminated string for a negative count); the destination
/// `capacity` bytes (a negative size read as the unsigned one, as Windows 2000's does).
#[unsafe(export_name = "f2k_export_LCMapStringA")]
pub unsafe extern "system" fn lc_map_string_a(
    locale: u32,
    flags: u32,
    src: *const u8,
    count: i32,
    dst: *mut u8,
    capacity: i32,
) -> i32 {
    // SAFETY: the caller's source and destination (the contract).
    let (src, out) = unsafe {
        (
            Counted::new(src, count),
            OutBuf::new(dst, capacity as u32 as usize),
        )
    };
    let checked = check_call(locale, flags, src.is_null(), count, 0, false, false);
    answer(
        checked.and_then(|()| map_narrow(locale, flags, src, out)),
        0,
    )
}

/// LCMapStringA's work, once the call is checked.
fn map_narrow(
    locale: u32,
    flags: u32,
    src: Counted<'_, u8>,
    dst: OutBuf<'_, u8>,
) -> Result<i32, Failure> {
    let bytes = narrow_source(&src)?;
    let query = dst.is_empty();
    let terminated = src.count() < 0;
    let wide = bytes.iter().map(|byte| CP1252.decode(byte, false));
    let answer = if flags & LCMAP_SORTKEY != 0 {
        let length = bytes.len() - usize::from(terminated);
        key_into(locale, flags, wide.take(length), length, dst)
    } else {
        let mut mapped = HeapVec::with_capacity(2 * bytes.len())
            .map_err(|_| Failure::Error(ERROR_NOT_ENOUGH_MEMORY))?;
        map(flags, wide, |unit| {
            mapped.push(CP1252.encode(unit, true).unwrap_or(cp1252::DEFAULT_CHAR))
        });
        deliver(&mapped, dst)
    }?;
    if bytes.len() > STACK_STRING && !query {
        set_last_error(ERROR_INSUFFICIENT_BUFFER);
    }
    Ok(answer)
}
