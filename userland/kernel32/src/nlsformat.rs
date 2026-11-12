//! The date, time and number formats: GetDateFormatW/A, GetTimeFormatW/A and GetNumberFormatW/A,
//! kernel32's own NLS code over the one locale's facts ([`crate::localeinfo`]: SSHORTDATE,
//! SLONGDATE, SYEARMONTH, STIMEFORMAT, the day and month names, the time markers, SDECIMAL,
//! STHOUSAND, SGROUPING, IDIGITS, ILZERO, INEGNUMBER), as Windows 2000's kernel32 makes them.
//!
//! Each call checks, in order: the locale (ERROR_INVALID_PARAMETER for one Windows 2000 does not
//! support; one it supports whose formats this surface lacks is logged as not implemented), the
//! buffer (ERROR_INVALID_PARAMETER for a negative size, or no buffer with a size), the flags
//! (ERROR_INVALID_FLAGS, LOCALE_NOUSEROVERRIDE with a format of the caller's included), then its
//! input (ERROR_INVALID_PARAMETER). The answer counts the terminator; a size of 0 asks for it, a
//! buffer too short is ERROR_INSUFFICIENT_BUFFER. An A call converts the caller's strings from the
//! ANSI code page and its answer back into it.
//!
//! A picture string's elements are runs of their letter (`dddd`, `MM`, `yy`, `hh`, `tt`...); text
//! between single quotes is copied as it is, a doubled quote inside them standing for one (an empty
//! pair outside them stands for nothing), and any other character is copied too. Dates: `d` and
//! `dd` the day, `ddd` and longer its abbreviated and full names (the day of the week computed from
//! the date, the SYSTEMTIME's own ignored); `M`, `MM`, `MMM` and longer the month likewise; `y` and
//! `yy` the year's last two digits, `yyy` and longer the whole year; `g` and longer the era, which
//! the Gregorian calendar of the locale has none of. Times: `h` and `hh` the hour of a 12-hour
//! clock (of a 24-hour one under TIME_FORCE24HOURFORMAT), `H` and `HH` of a 24-hour one, `m` and
//! `s` the minutes and seconds, a doubled letter (or more) with a leading zero; `t` the time
//! marker's first character, `tt` and longer the whole marker.
//!
//! The TIME_ flags drop elements from the picture, with the separators that tie them to it, as the
//! locale fixture's capture shows: the minutes and seconds (TIME_NOMINUTESORSECONDS) or the
//! seconds (TIME_NOSECONDS) take the unquoted characters since the last element written with them
//! ("h:mm:ss tt" is "h tt"; "tt h 'at' m:s" is "tt h'at'"); the time marker (TIME_NOTIMEMARKER)
//! takes those since the element before it when that element was written ("h:mm:ss tt" is
//! "h:mm:ss"), none when it was dropped too ("h tt" is "h "), and the unquoted characters after it
//! when it comes first ("tt h" is "h").
//!
//! Numbers: an optional minus sign, decimal digits and at most one decimal point (a string of none
//! of them is zero), anything else ERROR_INVALID_PARAMETER. The value is rounded to NUMBERFMT's
//! NumDigits, halves up, in decimal (no floating point: any length rounds exactly), its integer
//! part grouped (Grouping's digits are the groups' sizes from the decimal point, the last one
//! repeating; a 0 after the first ends the grouping: 32 groups as 12,34,567 and 10 as 123,4) and a
//! zero integer part written as 0 unless LeadingZero is 0 and there is a fraction; a value that
//! rounds to zero has no sign. NegativeOrder 0 to 4 places the sign: (1.1), -1.1, - 1.1, 1.1-, 1.1
//! -. A NUMBERFMT with NumDigits past 9, LeadingZero past 1, NegativeOrder past 4, or a separator
//! missing, empty or longer than 3 characters is ERROR_INVALID_PARAMETER.

use core::ops::Deref;

use crate::base::WideUnits;
use crate::edge::{wide_units, In, InStr, InWStr, OutBuf, Text};
use crate::error::{
    answer,
    Failure,
    ERROR_INSUFFICIENT_BUFFER,
    ERROR_INVALID_FLAGS,
    ERROR_INVALID_PARAMETER,
    ERROR_NOT_ENOUGH_MEMORY,
};
use crate::heap::{HeapString, HeapVec};
use crate::locale::room;
use crate::localeinfo;

/// The flags every call takes.
const LOCALE_NOUSEROVERRIDE: u32 = 0x8000_0000;
const LOCALE_USE_CP_ACP: u32 = 0x4000_0000;

/// GetDateFormat's flags.
const DATE_SHORTDATE: u32 = 0x01;
const DATE_LONGDATE: u32 = 0x02;
const DATE_USE_ALT_CALENDAR: u32 = 0x04;
const DATE_YEARMONTH: u32 = 0x08;
const DATE_LTRREADING: u32 = 0x10;
const DATE_RTLREADING: u32 = 0x20;

/// GetTimeFormat's flags.
const TIME_NOMINUTESORSECONDS: u32 = 0x01;
const TIME_NOSECONDS: u32 = 0x02;
const TIME_NOTIMEMARKER: u32 = 0x04;
const TIME_FORCE24HOURFORMAT: u32 = 0x08;

/// The LCTYPEs the formats read.
const LOCALE_SDECIMAL: u32 = 0x0E;
const LOCALE_STHOUSAND: u32 = 0x0F;
const LOCALE_SGROUPING: u32 = 0x10;
const LOCALE_IDIGITS: u32 = 0x11;
const LOCALE_ILZERO: u32 = 0x12;
const LOCALE_SSHORTDATE: u32 = 0x1F;
const LOCALE_SLONGDATE: u32 = 0x20;
const LOCALE_S1159: u32 = 0x28;
const LOCALE_S2359: u32 = 0x29;
const LOCALE_SDAYNAME1: u32 = 0x2A;
const LOCALE_SABBREVDAYNAME1: u32 = 0x31;
const LOCALE_SMONTHNAME1: u32 = 0x38;
const LOCALE_SABBREVMONTHNAME1: u32 = 0x44;
const LOCALE_SNEGATIVESIGN: u32 = 0x51;
const LOCALE_STIMEFORMAT: u32 = 0x1003;
const LOCALE_SYEARMONTH: u32 = 0x1006;
const LOCALE_INEGNUMBER: u32 = 0x1010;

/// The quote that opens and closes a picture's literal text.
const QUOTE: u16 = b'\'' as u16;

// --- The caller's side --------------------------------------------------------------------------

/// A caller's string as UTF-16 units: a W call's as it is, an A call's converted from the ANSI
/// code page onto the process heap.
enum Units<'a> {
    Wide(WideUnits<'a>),
    Narrow(HeapString),
}

impl Deref for Units<'_> {
    type Target = [u16];

    fn deref(&self) -> &[u16] {
        match self {
            Units::Wide(units) => units,
            Units::Narrow(string) => string.units(),
        }
    }
}

/// A W call's string, when given.
fn wide(string: Option<InWStr<'_>>) -> Result<Option<Units<'_>>, Failure> {
    string
        .map(|string| {
            wide_units(&string)
                .map(Units::Wide)
                .ok_or(Failure::Error(ERROR_NOT_ENOUGH_MEMORY))
        })
        .transpose()
}

/// An A call's string, when given, converted.
fn narrow(string: Option<InStr<'_>>) -> Result<Option<Units<'static>>, Failure> {
    string
        .map(|string| {
            HeapString::of_ansi(Some(&string))
                .map(Units::Narrow)
                .map_err(Failure::Status)
        })
        .transpose()
}

/// Whether a locale is one Windows 2000 supports whose formats this surface lacks: the call is
/// logged as not implemented.
fn lacks_formats(lcid: u32) -> bool {
    !localeinfo::names_locale(lcid) && localeinfo::supported_locale(lcid)
}

/// The locale and the buffer judged: ERROR_INVALID_PARAMETER for a locale this surface does not
/// describe, a negative size, or no buffer with a size.
fn check_call(lcid: u32, out: &Text<'_>, size: i32) -> Result<(), Failure> {
    if !localeinfo::names_locale(lcid) || size < 0 || (out.is_null() && size != 0) {
        return Err(Failure::Error(ERROR_INVALID_PARAMETER));
    }
    Ok(())
}

/// The formatted text handed back: its length with the terminator for a size query (no room), else
/// written and terminated; ERROR_INSUFFICIENT_BUFFER for a buffer too short.
fn deliver(text: &[u16], mut out: Text<'_>) -> Result<i32, Failure> {
    let needed = text.len() + 1;
    if out.is_empty() {
        return Ok(needed as i32);
    }
    if out.len() < needed {
        return Err(Failure::Error(ERROR_INSUFFICIENT_BUFFER));
    }
    out.put_terminated(text);
    Ok(needed as i32)
}

/// A locale string's units, into `buffer`.
fn locale_units(lctype: u32, buffer: &mut [u16; 32]) -> &[u16] {
    let text = localeinfo::info(lctype).unwrap_or("");
    for (slot, byte) in buffer.iter_mut().zip(text.bytes()) {
        *slot = u16::from(byte);
    }
    &buffer[..text.len().min(32)]
}

/// A locale string's characters, added to `out`.
fn push_info(out: &mut HeapVec<u16>, lctype: u32) {
    out.extend(
        localeinfo::info(lctype)
            .unwrap_or("")
            .bytes()
            .map(u16::from),
    );
}

/// `value` in decimal, at least `width` digits (leading zeros), added through `push`.
fn push_number(value: u32, width: usize, mut push: impl FnMut(u16)) {
    let mut digits = [0u16; 10];
    let mut count = 0;
    let mut rest = value;
    loop {
        digits[count] = u16::from(b'0') + (rest % 10) as u16;
        count += 1;
        rest /= 10;
        if rest == 0 {
            break;
        }
    }
    for _ in count..width {
        push(u16::from(b'0'));
    }
    digits[..count].iter().rev().for_each(|&digit| push(digit));
}

/// One piece of a picture string: a run of an element's letter, or a character copied (quoted
/// when it came from between quotes).
#[derive(Clone, Copy)]
enum Token {
    Element(u8, usize),
    Literal(u16, bool),
}

/// A picture string's tokens, the letters `elements` names being elements (see the module notes),
/// in order.
fn tokens(picture: &[u16], elements: &[u8], mut each: impl FnMut(Token)) {
    let mut at = 0;
    let mut quoted = false;
    while at < picture.len() {
        let unit = picture[at];
        if quoted {
            if unit != QUOTE {
                each(Token::Literal(unit, true));
            } else if picture.get(at + 1) == Some(&QUOTE) {
                each(Token::Literal(QUOTE, true));
                at += 1;
            } else {
                quoted = false;
            }
            at += 1;
        } else if unit == QUOTE {
            quoted = true;
            at += 1;
        } else if let Some(&letter) = elements.iter().find(|&&letter| u16::from(letter) == unit) {
            let run = picture[at..]
                .iter()
                .take_while(|&&next| next == unit)
                .count();
            each(Token::Element(letter, run));
            at += run;
        } else {
            each(Token::Literal(unit, false));
            at += 1;
        }
    }
}

/// A SYSTEMTIME's fields, the caller's words in order: year, month, day of the week, day, hour,
/// minute, second, milliseconds.
type SystemTimeWords = [u16; 8];

/// The fields the formats read, the day of the week (0, Sunday, to 6) computed from the date.
#[derive(Clone, Copy)]
struct Civil {
    year: u16,
    month: u16,
    day: u16,
    day_of_week: u16,
    hour: u16,
    minute: u16,
    second: u16,
}

impl Civil {
    /// The caller's SYSTEMTIME, or the local time for none.
    fn of(words: Option<SystemTimeWords>) -> Civil {
        let [year, month, _, day, hour, minute, second, _] = words.unwrap_or_else(|| {
            let now = crate::time::local_system_time();
            [
                now.year,
                now.month,
                now.day_of_week,
                now.day,
                now.hour,
                now.minute,
                now.second,
                now.milliseconds,
            ]
        });
        let days = rtl::time::days_from_civil(i64::from(year), u32::from(month), u32::from(day));
        Civil {
            year,
            month,
            day,
            day_of_week: (days + 4).rem_euclid(7) as u16,
            hour,
            minute,
            second,
        }
    }
}

/// Whether `year` is a leap year of the Gregorian calendar.
fn is_leap(year: u16) -> bool {
    year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
}

/// A SYSTEMTIME's date judged: a year SYSTEMTIME holds (1601 to 30827), a month and a day of it;
/// ERROR_INVALID_PARAMETER otherwise.
fn check_date(words: &SystemTimeWords) -> Result<(), Failure> {
    let [year, month, _, day, ..] = *words;
    let days = match month {
        2 if is_leap(year) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        1..=12 => 31,
        _ => 0,
    };
    if !(1601..=30827).contains(&year) || day == 0 || day > days {
        return Err(Failure::Error(ERROR_INVALID_PARAMETER));
    }
    Ok(())
}

/// A SYSTEMTIME's time of day judged: ERROR_INVALID_PARAMETER for a field past its range (the date
/// is not consulted).
fn check_time(words: &SystemTimeWords) -> Result<(), Failure> {
    let [.., hour, minute, second, milliseconds] = *words;
    if hour > 23 || minute > 59 || second > 59 || milliseconds > 999 {
        return Err(Failure::Error(ERROR_INVALID_PARAMETER));
    }
    Ok(())
}

// --- Dates --------------------------------------------------------------------------------------

/// GetDateFormat's flags judged: ERROR_INVALID_FLAGS for an unknown one, two of the formats
/// (DATE_SHORTDATE, DATE_LONGDATE, DATE_YEARMONTH), both reading orders, or a format flag or
/// LOCALE_NOUSEROVERRIDE with a picture of the caller's. The locale's picture the flags name.
fn date_picture(flags: u32, picture: bool) -> Result<u32, Failure> {
    const VALID: u32 = DATE_SHORTDATE
        | DATE_LONGDATE
        | DATE_USE_ALT_CALENDAR
        | DATE_YEARMONTH
        | DATE_LTRREADING
        | DATE_RTLREADING
        | LOCALE_NOUSEROVERRIDE
        | LOCALE_USE_CP_ACP;
    let formats = flags & (DATE_SHORTDATE | DATE_LONGDATE | DATE_YEARMONTH);
    let orders = DATE_LTRREADING | DATE_RTLREADING;
    let refused = flags & !VALID != 0
        || formats.count_ones() > 1
        || flags & orders == orders
        || (picture && flags & (formats | LOCALE_NOUSEROVERRIDE) != 0);
    if refused {
        return Err(Failure::Error(ERROR_INVALID_FLAGS));
    }
    Ok(match formats {
        DATE_LONGDATE => LOCALE_SLONGDATE,
        DATE_YEARMONTH => LOCALE_SYEARMONTH,
        _ => LOCALE_SSHORTDATE,
    })
}

/// One date element, written to `out`.
fn date_element(date: &Civil, letter: u8, run: usize, out: &mut HeapVec<u16>) {
    let weekday = u32::from((date.day_of_week + 6) % 7); // the names start on Monday
    let month = u32::from(date.month) - 1;
    match (letter, run) {
        (b'd', 1 | 2) => push_number(u32::from(date.day), run, |unit| out.push(unit)),
        (b'd', 3) => push_info(out, LOCALE_SABBREVDAYNAME1 + weekday),
        (b'd', _) => push_info(out, LOCALE_SDAYNAME1 + weekday),
        (b'M', 1 | 2) => push_number(u32::from(date.month), run, |unit| out.push(unit)),
        (b'M', 3) => push_info(out, LOCALE_SABBREVMONTHNAME1 + month),
        (b'M', _) => push_info(out, LOCALE_SMONTHNAME1 + month),
        (b'y', 1 | 2) => push_number(u32::from(date.year % 100), run, |unit| out.push(unit)),
        (b'y', _) => push_number(u32::from(date.year), 1, |unit| out.push(unit)),
        _ => {} // the era: the locale's Gregorian calendar has none
    }
}

/// GetDateFormat's work, once its strings are units.
fn get_date_format(
    lcid: u32,
    flags: u32,
    date: Option<SystemTimeWords>,
    picture: Option<&[u16]>,
    out: Text<'_>,
    size: i32,
) -> Result<i32, Failure> {
    check_call(lcid, &out, size)?;
    let lctype = date_picture(flags, picture.is_some())?;
    if let Some(words) = &date {
        check_date(words)?;
    }
    let date = Civil::of(date);
    let mut default = [0u16; 32];
    let picture = picture.unwrap_or_else(|| locale_units(lctype, &mut default));
    // An element writes at most three units a letter ("dddd" as "Wednesday").
    let mut text = HeapVec::with_capacity(3 * picture.len() + 1)?;
    tokens(picture, b"dMyg", |token| match token {
        Token::Element(letter, run) => date_element(&date, letter, run, &mut text),
        Token::Literal(unit, _) => text.push(unit),
    });
    deliver(&text, out)
}

/// The reading-order flags this surface does not lay out yet (one alone: both are refused).
fn reading_order(flags: u32) -> bool {
    let orders = flags & (DATE_LTRREADING | DATE_RTLREADING);
    orders != 0 && orders != DATE_LTRREADING | DATE_RTLREADING
}

/// GetDateFormatW: the date (the local one for none) in the picture given, or the locale's format
/// the flags name (see the module notes); the characters written with the terminator, or needed
/// for a size of 0.
///
/// # Safety
///
/// `date`, when given, points at a SYSTEMTIME; `picture`, when given, at a NUL-terminated string;
/// `buffer` holds `size` characters.
#[unsafe(export_name = "f2k_export_GetDateFormatW")]
pub unsafe extern "system" fn get_date_format_w(
    lcid: u32,
    flags: u32,
    date: *const SystemTimeWords,
    picture: *const u16,
    buffer: *mut u16,
    size: i32,
) -> i32 {
    if lacks_formats(lcid) || reading_order(flags) {
        let args = [
            lcid,
            flags,
            date as u32,
            picture as u32,
            buffer as u32,
            size as u32,
        ];
        // SAFETY: the caller's arguments, as the export's kinds read them.
        return unsafe { stubbed(&crate::spec::GetDateFormatW, &args) };
    }
    // SAFETY: the caller's SYSTEMTIME and picture when given, and its buffer of `size` characters
    // (the contract; a negative size, which the call refuses, holds none).
    let (date, picture, out) = unsafe {
        (
            In::optional(date),
            InWStr::optional(picture),
            OutBuf::new(buffer, room(size)),
        )
    };
    let date = date.map(|date| date.read());
    let result = wide(picture).and_then(|picture| {
        get_date_format(lcid, flags, date, picture.as_deref(), Text::Wide(out), size)
    });
    answer(result, 0)
}

/// GetDateFormatA: GetDateFormatW's, its picture and its answer in the ANSI code page.
///
/// # Safety
///
/// As GetDateFormatW's, in bytes.
#[unsafe(export_name = "f2k_export_GetDateFormatA")]
pub unsafe extern "system" fn get_date_format_a(
    lcid: u32,
    flags: u32,
    date: *const SystemTimeWords,
    picture: *const u8,
    buffer: *mut u8,
    size: i32,
) -> i32 {
    if lacks_formats(lcid) || reading_order(flags) {
        let args = [
            lcid,
            flags,
            date as u32,
            picture as u32,
            buffer as u32,
            size as u32,
        ];
        // SAFETY: the caller's arguments, as the export's kinds read them.
        return unsafe { stubbed(&crate::spec::GetDateFormatA, &args) };
    }
    // SAFETY: as GetDateFormatW's.
    let (date, picture, out) = unsafe {
        (
            In::optional(date),
            InStr::optional(picture),
            OutBuf::new(buffer, room(size)),
        )
    };
    let date = date.map(|date| date.read());
    let result = narrow(picture).and_then(|picture| {
        get_date_format(lcid, flags, date, picture.as_deref(), Text::Ansi(out), size)
    });
    answer(result, 0)
}

/// The stub path of a call this surface does not handle: logged, then failed as the export fails.
///
/// # Safety
///
/// `args` are the caller's, as the export's kinds read them.
unsafe fn stubbed(entry: &rtl::stub::Entry, args: &[u32; 6]) -> i32 {
    let args = args.map(u64::from);
    // SAFETY: the caller's contract.
    (unsafe { crate::stub::stubbed(entry, "not yet implemented", &args) }) as i32
}

// --- Times --------------------------------------------------------------------------------------

/// A unit of a time being formatted, and whether it came from between quotes (the TIME_ flags
/// never drop those).
#[derive(Clone, Copy, Default)]
struct TimeUnit {
    unit: u16,
    quoted: bool,
}

/// GetTimeFormat's flags judged: ERROR_INVALID_FLAGS for an unknown one, or LOCALE_NOUSEROVERRIDE
/// with a picture of the caller's.
fn check_time_flags(flags: u32, picture: bool) -> Result<(), Failure> {
    const VALID: u32 = TIME_NOMINUTESORSECONDS
        | TIME_NOSECONDS
        | TIME_NOTIMEMARKER
        | TIME_FORCE24HOURFORMAT
        | LOCALE_NOUSEROVERRIDE
        | LOCALE_USE_CP_ACP;
    if flags & !VALID != 0 || (picture && flags & LOCALE_NOUSEROVERRIDE != 0) {
        return Err(Failure::Error(ERROR_INVALID_FLAGS));
    }
    Ok(())
}

/// Whether the flags drop a time element.
fn dropped(flags: u32, letter: u8) -> bool {
    match letter {
        b'm' => flags & TIME_NOMINUTESORSECONDS != 0,
        b's' => flags & (TIME_NOMINUTESORSECONDS | TIME_NOSECONDS) != 0,
        b't' => flags & TIME_NOTIMEMARKER != 0,
        _ => false,
    }
}

/// One time element, written to `out`.
fn time_element(time: &Civil, flags: u32, letter: u8, run: usize, mut push: impl FnMut(u16)) {
    let width = run.min(2);
    let twelve = match time.hour % 12 {
        0 => 12,
        hour => hour,
    };
    match letter {
        b'h' if flags & TIME_FORCE24HOURFORMAT == 0 => push_number(u32::from(twelve), width, push),
        b'h' | b'H' => push_number(u32::from(time.hour), width, push),
        b'm' => push_number(u32::from(time.minute), width, push),
        b's' => push_number(u32::from(time.second), width, push),
        _ => {
            let marker = if time.hour < 12 {
                LOCALE_S1159
            } else {
                LOCALE_S2359
            };
            let text = localeinfo::info(marker).unwrap_or("");
            let text = if run == 1 {
                text.get(..1).unwrap_or("")
            } else {
                text
            };
            text.bytes().for_each(|byte| push(u16::from(byte)));
        }
    }
}

/// The unquoted units of `out` from `from` on dropped: the separators a dropped element takes.
fn drop_separators(out: &mut HeapVec<TimeUnit>, from: usize) {
    let mut kept = from;
    for at in from..out.len() {
        if out[at].quoted {
            out[kept] = out[at];
            kept += 1;
        }
    }
    out.truncate(kept);
}

/// A time in a picture, the TIME_ flags dropping its elements (see the module notes), into `out`.
fn format_time(time: &Civil, flags: u32, picture: &[u16], out: &mut HeapVec<TimeUnit>) {
    // Where the last element written ends; whether the last element met was dropped; whether one
    // was met at all; whether the unquoted characters to come are a leading marker's.
    let mut written_end = None;
    let mut last_dropped = false;
    let mut met = false;
    let mut after_leading_marker = false;
    tokens(picture, b"hHmst", |token| match token {
        Token::Element(letter, run) => {
            if dropped(flags, letter) {
                match (letter, written_end) {
                    (b't', _) if !met => after_leading_marker = true,
                    (b't', Some(end)) if !last_dropped => drop_separators(out, end),
                    (b'm' | b's', Some(end)) => drop_separators(out, end),
                    _ => {}
                }
                last_dropped = true;
            } else {
                after_leading_marker = false;
                time_element(time, flags, letter, run, |unit| {
                    out.push(TimeUnit {
                        unit,
                        quoted: false,
                    })
                });
                written_end = Some(out.len());
                last_dropped = false;
            }
            met = true;
        }
        Token::Literal(unit, quoted) => {
            if after_leading_marker && !quoted {
                return;
            }
            after_leading_marker = false;
            out.push(TimeUnit { unit, quoted });
        }
    });
}

/// GetTimeFormat's work, once its strings are units.
fn get_time_format(
    lcid: u32,
    flags: u32,
    time: Option<SystemTimeWords>,
    picture: Option<&[u16]>,
    out: Text<'_>,
    size: i32,
) -> Result<i32, Failure> {
    check_call(lcid, &out, size)?;
    check_time_flags(flags, picture.is_some())?;
    if let Some(words) = &time {
        check_time(words)?;
    }
    let time = Civil::of(time);
    let mut default = [0u16; 32];
    let picture = picture.unwrap_or_else(|| locale_units(LOCALE_STIMEFORMAT, &mut default));
    // An element writes at most two units a letter.
    let mut units = HeapVec::with_capacity(2 * picture.len() + 1)?;
    format_time(&time, flags, picture, &mut units);
    let mut text = HeapVec::with_capacity(units.len())?;
    text.extend(units.iter().map(|unit| unit.unit));
    deliver(&text, out)
}

/// GetTimeFormatW: the time (the local one for none) in the picture given, or the locale's
/// STIMEFORMAT, as the TIME_ flags have it (see the module notes); the characters written with
/// the terminator, or needed for a size of 0.
///
/// # Safety
///
/// As GetDateFormatW's, `time` a SYSTEMTIME too.
#[unsafe(export_name = "f2k_export_GetTimeFormatW")]
pub unsafe extern "system" fn get_time_format_w(
    lcid: u32,
    flags: u32,
    time: *const SystemTimeWords,
    picture: *const u16,
    buffer: *mut u16,
    size: i32,
) -> i32 {
    if lacks_formats(lcid) {
        let args = [
            lcid,
            flags,
            time as u32,
            picture as u32,
            buffer as u32,
            size as u32,
        ];
        // SAFETY: the caller's arguments, as the export's kinds read them.
        return unsafe { stubbed(&crate::spec::GetTimeFormatW, &args) };
    }
    // SAFETY: as GetDateFormatW's.
    let (time, picture, out) = unsafe {
        (
            In::optional(time),
            InWStr::optional(picture),
            OutBuf::new(buffer, room(size)),
        )
    };
    let time = time.map(|time| time.read());
    let result = wide(picture).and_then(|picture| {
        get_time_format(lcid, flags, time, picture.as_deref(), Text::Wide(out), size)
    });
    answer(result, 0)
}

/// GetTimeFormatA: GetTimeFormatW's, its picture and its answer in the ANSI code page.
///
/// # Safety
///
/// As GetTimeFormatW's, in bytes.
#[unsafe(export_name = "f2k_export_GetTimeFormatA")]
pub unsafe extern "system" fn get_time_format_a(
    lcid: u32,
    flags: u32,
    time: *const SystemTimeWords,
    picture: *const u8,
    buffer: *mut u8,
    size: i32,
) -> i32 {
    if lacks_formats(lcid) {
        let args = [
            lcid,
            flags,
            time as u32,
            picture as u32,
            buffer as u32,
            size as u32,
        ];
        // SAFETY: the caller's arguments, as the export's kinds read them.
        return unsafe { stubbed(&crate::spec::GetTimeFormatA, &args) };
    }
    // SAFETY: as GetDateFormatW's.
    let (time, picture, out) = unsafe {
        (
            In::optional(time),
            InStr::optional(picture),
            OutBuf::new(buffer, room(size)),
        )
    };
    let time = time.map(|time| time.read());
    let result = narrow(picture).and_then(|picture| {
        get_time_format(lcid, flags, time, picture.as_deref(), Text::Ansi(out), size)
    });
    answer(result, 0)
}

// --- Numbers ------------------------------------------------------------------------------------

/// A NUMBERFMT as the caller's structure holds it, its separators the caller's strings (`C` their
/// character).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct NumberFmt<C> {
    pub num_digits: u32,
    pub leading_zero: u32,
    pub grouping: u32,
    pub decimal_sep: *const C,
    pub thousand_sep: *const C,
    pub negative_order: u32,
}

/// The caller's NUMBERFMT, its separators as units (none for a null one).
struct CallerFormat<'a> {
    digits: u32,
    leading_zero: u32,
    grouping: u32,
    decimal: Option<Units<'a>>,
    thousand: Option<Units<'a>>,
    negative: u32,
}

/// The groups of an integer part: their sizes from the decimal point, and whether the last
/// repeats.
#[derive(Clone, Copy)]
struct Grouping {
    sizes: [u8; 10],
    count: usize,
    repeat: bool,
}

impl Grouping {
    /// NUMBERFMT's Grouping: its decimal digits, most significant first, are the sizes; the last
    /// repeats, unless a 0 ends them.
    fn of_number(grouping: u32) -> Grouping {
        let mut digits = [0u8; 10];
        let mut count = 0;
        let mut rest = grouping;
        loop {
            digits[count] = (rest % 10) as u8;
            count += 1;
            rest /= 10;
            if rest == 0 {
                break;
            }
        }
        digits[..count].reverse();
        let mut group = Grouping {
            sizes: [0; 10],
            count: 0,
            repeat: true,
        };
        for &digit in &digits[..count] {
            if digit == 0 {
                group.repeat = false;
                break;
            }
            group.sizes[group.count] = digit;
            group.count += 1;
        }
        group
    }

    /// LOCALE_SGROUPING's string: sizes separated by semicolons, a final 0 making the last one
    /// repeat ("3;0").
    fn of_locale(text: &str) -> Grouping {
        let mut group = Grouping {
            sizes: [0; 10],
            count: 0,
            repeat: false,
        };
        for size in text.split(';').filter_map(|size| size.parse::<u8>().ok()) {
            if size == 0 {
                group.repeat = true;
                break;
            }
            if group.count < group.sizes.len() {
                group.sizes[group.count] = size;
                group.count += 1;
            }
        }
        group
    }

    /// Whether a separator goes between the digits with `right` integer digits to its right.
    fn separates(&self, right: usize) -> bool {
        let mut at = 0;
        for index in 0.. {
            let size = match self.sizes.get(index).filter(|_| index < self.count) {
                Some(&size) => size,
                None if self.repeat && self.count > 0 => self.sizes[self.count - 1],
                None => return false,
            };
            at += usize::from(size);
            if at >= right {
                return at == right;
            }
        }
        false
    }
}

/// The format a number is written in.
struct NumberFormat<'a> {
    digits: usize,
    leading_zero: bool,
    grouping: Grouping,
    decimal: &'a [u16],
    thousand: &'a [u16],
    negative: u32,
}

/// A separator of the caller's judged: present, 1 to 3 characters.
fn separator<'a>(separator: &'a Option<Units<'_>>) -> Result<&'a [u16], Failure> {
    match separator.as_deref() {
        Some(units) if (1..=3).contains(&units.len()) => Ok(units),
        _ => Err(Failure::Error(ERROR_INVALID_PARAMETER)),
    }
}

/// A number string's parts: its sign, and its integer and fraction digits (ASCII); none for a
/// string that is not a number.
fn number_parts(value: &[u16]) -> Option<(bool, &[u16], &[u16])> {
    let (negative, rest) = match value.split_first() {
        Some((&unit, rest)) if unit == u16::from(b'-') => (true, rest),
        _ => (false, value),
    };
    let point = rest.iter().position(|&unit| unit == u16::from(b'.'));
    let (integer, fraction) = match point {
        Some(point) => (&rest[..point], &rest[point + 1..]),
        None => (rest, &[][..]),
    };
    let digits = |part: &[u16]| part.iter().all(|&unit| (0x30..=0x39).contains(&unit));
    (digits(integer) && digits(fraction)).then_some((negative, integer, fraction))
}

/// A number in a format, into `out`; ERROR_INVALID_PARAMETER for a string that is not a number.
fn format_number(
    value: &[u16],
    format: &NumberFormat<'_>,
    out: &mut HeapVec<u16>,
) -> Result<(), Failure> {
    let (negative, integer, fraction) =
        number_parts(value).ok_or(Failure::Error(ERROR_INVALID_PARAMETER))?;
    let integer = &integer[integer.iter().take_while(|&&unit| unit == 0x30).count()..];
    // The digits kept, a slot for a carry first: the integer's, then the fraction's to NumDigits.
    let mut kept = HeapVec::with_capacity(1 + integer.len() + format.digits)?;
    kept.push(0u8);
    kept.extend(integer.iter().map(|&unit| (unit - 0x30) as u8));
    kept.extend(
        (0..format.digits).map(|at| fraction.get(at).map_or(0, |&unit| (unit - 0x30) as u8)),
    );
    if fraction
        .get(format.digits)
        .is_some_and(|&unit| unit >= u16::from(b'5'))
    {
        for digit in kept.iter_mut().rev() {
            if *digit < 9 {
                *digit += 1;
                break;
            }
            *digit = 0;
        }
    }
    let (whole, fraction) = kept.split_at(kept.len() - format.digits);
    let whole = &whole[whole.iter().take_while(|&&digit| digit == 0).count()..];
    let negative = negative && kept.iter().any(|&digit| digit != 0);
    let digit = |digit: u8| u16::from(b'0' + digit);
    if negative {
        match format.negative {
            0 => out.push(u16::from(b'(')),
            1 | 2 => push_info(out, LOCALE_SNEGATIVESIGN),
            _ => {}
        }
        if format.negative == 2 {
            out.push(u16::from(b' '));
        }
    }
    if whole.is_empty() {
        if format.leading_zero || format.digits == 0 {
            out.push(digit(0));
        }
    } else {
        for (at, &value) in whole.iter().enumerate() {
            let right = whole.len() - at;
            if at > 0 && format.grouping.separates(right) {
                out.extend(format.thousand.iter().copied());
            }
            out.push(digit(value));
        }
    }
    if format.digits > 0 {
        out.extend(format.decimal.iter().copied());
        out.extend(fraction.iter().map(|&value| digit(value)));
    }
    if negative {
        match format.negative {
            0 => out.push(u16::from(b')')),
            3 => push_info(out, LOCALE_SNEGATIVESIGN),
            4 => {
                out.push(u16::from(b' '));
                push_info(out, LOCALE_SNEGATIVESIGN);
            }
            _ => {}
        }
    }
    Ok(())
}

/// GetNumberFormat's work, once its strings are units.
fn get_number_format(
    lcid: u32,
    flags: u32,
    value: Option<&[u16]>,
    format: Option<CallerFormat<'_>>,
    out: Text<'_>,
    size: i32,
) -> Result<i32, Failure> {
    check_call(lcid, &out, size)?;
    const VALID: u32 = LOCALE_NOUSEROVERRIDE | LOCALE_USE_CP_ACP;
    if flags & !VALID != 0 || (format.is_some() && flags & LOCALE_NOUSEROVERRIDE != 0) {
        return Err(Failure::Error(ERROR_INVALID_FLAGS));
    }
    let (mut decimal, mut thousand) = ([0u16; 32], [0u16; 32]);
    let format = match &format {
        Some(caller) => {
            let refused = caller.digits > 9 || caller.leading_zero > 1 || caller.negative > 4;
            if refused {
                return Err(Failure::Error(ERROR_INVALID_PARAMETER));
            }
            NumberFormat {
                digits: caller.digits as usize,
                leading_zero: caller.leading_zero == 1,
                grouping: Grouping::of_number(caller.grouping),
                decimal: separator(&caller.decimal)?,
                thousand: separator(&caller.thousand)?,
                negative: caller.negative,
            }
        }
        None => NumberFormat {
            digits: localeinfo::number(LOCALE_IDIGITS).unwrap_or(2) as usize,
            leading_zero: localeinfo::number(LOCALE_ILZERO) == Some(1),
            grouping: Grouping::of_locale(localeinfo::info(LOCALE_SGROUPING).unwrap_or("")),
            decimal: locale_units(LOCALE_SDECIMAL, &mut decimal),
            thousand: locale_units(LOCALE_STHOUSAND, &mut thousand),
            negative: localeinfo::number(LOCALE_INEGNUMBER).unwrap_or(1),
        },
    };
    let value = value.ok_or(Failure::Error(ERROR_INVALID_PARAMETER))?;
    // Each integer digit may take a separator of three; the sign's pattern four more.
    let room = 4 * value.len() + format.digits + 3 + 8;
    let mut text = HeapVec::with_capacity(room)?;
    format_number(value, &format, &mut text)?;
    deliver(&text, out)
}

/// GetNumberFormatW: the number string in the caller's NUMBERFMT, or the locale's format (see the
/// module notes); the characters written with the terminator, or needed for a size of 0.
///
/// # Safety
///
/// `value` is a NUL-terminated string (or null); `format`, when given, a NUMBERFMTW whose
/// separators are NUL-terminated strings (or null); `buffer` holds `size` characters.
#[unsafe(export_name = "f2k_export_GetNumberFormatW")]
pub unsafe extern "system" fn get_number_format_w(
    lcid: u32,
    flags: u32,
    value: *const u16,
    format: *const NumberFmt<u16>,
    buffer: *mut u16,
    size: i32,
) -> i32 {
    if lacks_formats(lcid) {
        let args = [
            lcid,
            flags,
            value as u32,
            format as u32,
            buffer as u32,
            size as u32,
        ];
        // SAFETY: the caller's arguments, as the export's kinds read them.
        return unsafe { stubbed(&crate::spec::GetNumberFormatW, &args) };
    }
    // SAFETY: the caller's value, NUMBERFMT and separators, when given, and its buffer of `size`
    // characters (the contract; a negative size, which the call refuses, holds none).
    let (value, format, out) = unsafe {
        let format = In::optional(format).map(|format| {
            let format = format.read();
            let separators = (
                InWStr::optional(format.decimal_sep),
                InWStr::optional(format.thousand_sep),
            );
            (format, separators)
        });
        (
            InWStr::optional(value),
            format,
            OutBuf::new(buffer, room(size)),
        )
    };
    let result = (|| {
        let value = wide(value)?;
        let format = match format {
            Some((format, (decimal, thousand))) => Some(CallerFormat {
                digits: format.num_digits,
                leading_zero: format.leading_zero,
                grouping: format.grouping,
                decimal: wide(decimal)?,
                thousand: wide(thousand)?,
                negative: format.negative_order,
            }),
            None => None,
        };
        get_number_format(lcid, flags, value.as_deref(), format, Text::Wide(out), size)
    })();
    answer(result, 0)
}

/// GetNumberFormatA: GetNumberFormatW's, its strings and its answer in the ANSI code page.
///
/// # Safety
///
/// As GetNumberFormatW's, in bytes, `format` a NUMBERFMTA.
#[unsafe(export_name = "f2k_export_GetNumberFormatA")]
pub unsafe extern "system" fn get_number_format_a(
    lcid: u32,
    flags: u32,
    value: *const u8,
    format: *const NumberFmt<u8>,
    buffer: *mut u8,
    size: i32,
) -> i32 {
    if lacks_formats(lcid) {
        let args = [
            lcid,
            flags,
            value as u32,
            format as u32,
            buffer as u32,
            size as u32,
        ];
        // SAFETY: the caller's arguments, as the export's kinds read them.
        return unsafe { stubbed(&crate::spec::GetNumberFormatA, &args) };
    }
    // SAFETY: as GetNumberFormatW's.
    let (value, format, out) = unsafe {
        let format = In::optional(format).map(|format| {
            let format = format.read();
            let separators = (
                InStr::optional(format.decimal_sep),
                InStr::optional(format.thousand_sep),
            );
            (format, separators)
        });
        (
            InStr::optional(value),
            format,
            OutBuf::new(buffer, room(size)),
        )
    };
    let result = (|| {
        let value = narrow(value)?;
        let format = match format {
            Some((format, (decimal, thousand))) => Some(CallerFormat {
                digits: format.num_digits,
                leading_zero: format.leading_zero,
                grouping: format.grouping,
                decimal: narrow(decimal)?,
                thousand: narrow(thousand)?,
                negative: format.negative_order,
            }),
            None => None,
        };
        get_number_format(lcid, flags, value.as_deref(), format, Text::Ansi(out), size)
    })();
    answer(result, 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::last_error;

    fn wide(text: &str) -> std::vec::Vec<u16> {
        text.encode_utf16().chain([0]).collect()
    }

    /// A SYSTEMTIME of the locale fixture's: 2001-02-03 (a Saturday) at `hour`:`minute`:`second`.
    fn when(day_of_week: u16, hour: u16, minute: u16, second: u16) -> SystemTimeWords {
        [2001, 2, day_of_week, 3, hour, minute, second, 0]
    }

    fn date(
        flags: u32,
        words: SystemTimeWords,
        picture: Option<&str>,
    ) -> (i32, std::string::String) {
        let picture = picture.map(wide);
        let mut out = [0u16; 128];
        // SAFETY: the test's SYSTEMTIME, picture and buffer of 128 characters.
        let count = unsafe {
            get_date_format_w(
                0x0409,
                flags,
                &words,
                picture.as_ref().map_or(core::ptr::null(), |p| p.as_ptr()),
                out.as_mut_ptr(),
                128,
            )
        };
        let length = (count.max(1) - 1) as usize;
        (count, std::string::String::from_utf16_lossy(&out[..length]))
    }

    fn time(flags: u32, words: SystemTimeWords, picture: Option<&str>) -> std::string::String {
        let picture = picture.map(wide);
        let mut out = [0u16; 128];
        // SAFETY: as in `date`.
        let count = unsafe {
            get_time_format_w(
                0x0409,
                flags,
                &words,
                picture.as_ref().map_or(core::ptr::null(), |p| p.as_ptr()),
                out.as_mut_ptr(),
                128,
            )
        };
        assert!(count > 0, "error {}", last_error());
        std::string::String::from_utf16_lossy(&out[..count as usize - 1])
    }

    fn number(
        value: &str,
        format: Option<(u32, u32, u32, &str, &str, u32)>,
    ) -> std::string::String {
        let value = wide(value);
        let separators = format.map(|(.., decimal, thousand, _)| (wide(decimal), wide(thousand)));
        let format = format.zip(separators.as_ref()).map(
            |((digits, lz, grouping, .., negative), (d, t))| NumberFmt {
                num_digits: digits,
                leading_zero: lz,
                grouping,
                decimal_sep: d.as_ptr(),
                thousand_sep: t.as_ptr(),
                negative_order: negative,
            },
        );
        let mut out = [0u16; 128];
        // SAFETY: the test's value, NUMBERFMT and buffer.
        let count = unsafe {
            get_number_format_w(
                0x0409,
                0,
                value.as_ptr(),
                format.as_ref().map_or(core::ptr::null(), |f| f as *const _),
                out.as_mut_ptr(),
                128,
            )
        };
        if count == 0 {
            return std::format!("error {}", last_error());
        }
        std::string::String::from_utf16_lossy(&out[..count as usize - 1])
    }

    /// The date section's formats and pictures.
    #[test]
    fn dates() {
        let st = when(6, 4, 5, 6);
        assert_eq!(date(0, st, None), (9, "2/3/2001".into()));
        assert_eq!(
            date(DATE_LONGDATE, st, None).1,
            "Saturday, February 03, 2001"
        );
        assert_eq!(date(DATE_YEARMONTH, st, None).1, "February, 2001");
        assert_eq!(date(0, st, Some("ddd d MMM yy")).1, "Sat 3 Feb 01");
        assert_eq!(date(0, st, Some("M/d/y")).1, "2/3/1");
        assert_eq!(date(0, st, Some("d''M")).1, "32");
        assert_eq!(date(0, st, Some("'it''s' yyyy")).1, "it's 2001");
        assert_eq!(date(0, st, Some("gg yyyy")).1, " 2001");
        assert_eq!(
            date(0, st, Some("MMMMM ddddd yyyyy")).1,
            "February Saturday 2001"
        );
        assert_eq!(date(0, st, Some("abc xyz")).1, "abc x1z");
        assert_eq!(date(0, st, Some("")), (1, "".into()));
        assert_eq!(date(0, when(0, 4, 5, 6), Some("dddd")).1, "Saturday");
        let leap = [2000, 2, 2, 29, 12, 0, 0, 0];
        assert_eq!(
            date(DATE_LONGDATE, leap, None).1,
            "Tuesday, February 29, 2000"
        );
        assert_eq!(date(DATE_SHORTDATE | DATE_LONGDATE, st, None).0, 0);
        assert_eq!(last_error(), 1004);
        assert_eq!(date(DATE_SHORTDATE, st, Some("yyyy")).0, 0);
        assert_eq!(last_error(), 1004);
        assert_eq!(date(0, [2001, 2, 5, 30, 4, 5, 6, 7], None).0, 0);
        assert_eq!(last_error(), 87);
    }

    /// The time section's flags and pictures.
    #[test]
    fn times() {
        let morning = when(6, 4, 5, 6);
        let afternoon = when(6, 13, 7, 8);
        assert_eq!(time(0, morning, None), "4:05:06 AM");
        assert_eq!(time(TIME_NOSECONDS, afternoon, None), "1:07 PM");
        assert_eq!(time(TIME_NOMINUTESORSECONDS, morning, None), "4 AM");
        assert_eq!(time(TIME_NOTIMEMARKER, morning, None), "4:05:06");
        assert_eq!(time(TIME_FORCE24HOURFORMAT, afternoon, None), "13:07:08 PM");
        assert_eq!(
            time(TIME_NOMINUTESORSECONDS | TIME_NOTIMEMARKER, afternoon, None),
            "1 "
        );
        assert_eq!(time(0, afternoon, Some("hhh:mmm:sss ttt")), "01:07:08 PM");
        assert_eq!(time(0, morning, Some("h t")), "4 A");
        assert_eq!(time(0, morning, Some("h:mm' o''clock'")), "4:05 o'clock");
        assert_eq!(
            time(0, when(6, 0, 0, 0), Some("h:mm tt H:mm")),
            "12:00 AM 0:00"
        );
        let picture = Some("tt h 'at' m:s");
        assert_eq!(time(TIME_NOSECONDS, afternoon, picture), "PM 1 at 7");
        assert_eq!(time(TIME_NOMINUTESORSECONDS, afternoon, picture), "PM 1at");
        assert_eq!(time(TIME_NOTIMEMARKER, afternoon, picture), "1 at 7:8");
        assert_eq!(
            time(
                TIME_NOMINUTESORSECONDS | TIME_NOTIMEMARKER,
                afternoon,
                picture
            ),
            "1at"
        );
        assert_eq!(
            time(
                TIME_NOMINUTESORSECONDS | TIME_NOTIMEMARKER,
                afternoon,
                Some("hh:mm:ss tt")
            ),
            "01 "
        );
    }

    /// The number section's formats, the locale's and NUMBERFMT's.
    #[test]
    fn numbers() {
        assert_eq!(number("1234567.891", None), "1,234,567.89");
        assert_eq!(number("-0", None), "0.00");
        assert_eq!(number(".5", None), "0.50");
        assert_eq!(number("00012.3400", None), "12.34");
        assert_eq!(
            number("999999999999999999999.99999", None),
            "1,000,000,000,000,000,000,000.00"
        );
        assert_eq!(number("", None), "0.00");
        assert_eq!(number("1.", None), "1.00");
        for bad in [
            "1e5", "12a", " 12", "+12", "1,234", "1.2.3", "--1", "0x10", "1-",
        ] {
            assert_eq!(number(bad, None), "error 87", "{bad}");
        }
        let plain = Some((0, 0, 0, ",", ".", 0));
        assert_eq!(number("-1234567.891", plain), "(1234568)");
        assert_eq!(number("-0.001", plain), "0");
        let wide_sep = Some((5, 0, 3, "<>", " ", 2));
        assert_eq!(number("-1234567.891", wide_sep), "- 1 234 567<>89100");
        assert_eq!(number("0.5", wide_sep), "<>50000");
        let indian = Some((1, 1, 32, ".", ",", 3));
        assert_eq!(number("-1234567.891", indian), "12,34,567.9-");
        assert_eq!(number("9.995", indian), "10.0");
        let swiss = Some((3, 1, 2, ".", "'", 4));
        assert_eq!(number("-1234567.891", swiss), "1'23'45'67.891 -");
        assert_eq!(
            number("-1234.5", Some((2, 1, 10, ".", ",", 1))),
            "-123,4.50"
        );
        assert_eq!(number("1", Some((9, 1, 3, "", "", 1))), "error 87");
        assert_eq!(number("1", Some((2, 1, 3, "dec.", ",", 1))), "error 87");
        assert_eq!(number("1", Some((2, 2, 3, ".", ",", 1))), "error 87");
        assert_eq!(number("1", Some((2, 1, 3, ".", ",", 5))), "error 87");
    }
}
