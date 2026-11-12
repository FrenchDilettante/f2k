//! qsort, rand and srand, abs and labs, time, and the broken-down times: gmtime, localtime, mktime,
//! _tzset and wcsftime.
//!
//! rand is the C runtime's linear congruential generator, per thread: the seed becomes
//! `seed * 214013 + 2531011` and rand answers its bits 16 to 30 (RAND_MAX 32767), the seed 1 until
//! srand sets it (wide's capture: 41, 18467, 6334… without srand and after srand(1)).
//!
//! The broken-down times as MSDN documents them: gmtime and localtime answer NULL for a time before
//! 1970 UTC (a local time in 1969 west of UTC is localtime's answer, as Windows 2000's capture
//! shows), and they and mktime share one `struct tm` per thread. _tzset reads TZ
//! (`tzn[+|-]hh[:mm[:ss]][dzn]`, with the United States' daylight saving rules for a daylight
//! zone), or the system's time zone without it; localtime and mktime read it on their first need
//! when the program has not called _tzset. mktime normalizes the fields it is given and answers -1
//! for a time outside 1970-01-01 00:00:00 UTC to 2038-01-19 03:14:07 UTC. _tzset reads the zone's
//! names too, `%Z`'s in wcsftime: TZ's letters, or the system zone's StandardName and DaylightName.

use core::sync::atomic::Ordering::Relaxed;

use rtl::sync::Locked;
use rtl::time::{civil_from_days, days_from_civil};

use crate::edge::{self, WideUnit};
use crate::imports::{SystemTime, TimeZoneInformation};
use crate::thread::{self, Lock};
use crate::{ctype, kernel32, startup};

/// The comparison qsort calls (cdecl).
pub type Compare = unsafe extern "C" fn(*const u8, *const u8) -> i32;

/// An array of elements of `width` bytes, sorted in place by a comparison of two of them.
struct Elements<'a> {
    bytes: &'a mut [u8],
    width: usize,
    compare: &'a dyn Fn(&[u8], &[u8]) -> i32,
}

impl Elements<'_> {
    /// Element `i`.
    fn at(&self, i: usize) -> &[u8] {
        &self.bytes[i * self.width..][..self.width]
    }

    /// Elements `i` and `j` compared.
    fn order(&self, i: usize, j: usize) -> i32 {
        (self.compare)(self.at(i), self.at(j))
    }

    /// Elements `i` and `j` swapped.
    fn swap(&mut self, i: usize, j: usize) {
        if i != j {
            let (low, high) = (i.min(j), i.max(j));
            let (front, back) = self.bytes.split_at_mut(high * self.width);
            front[low * self.width..][..self.width].swap_with_slice(&mut back[..self.width]);
        }
    }
}

/// qsort: `count` elements of `width` bytes sorted in place by `compare`: a quicksort, its pivot
/// the median of three, short runs sorted by insertion, the smaller side first so the depth stays
/// logarithmic.
///
/// # Safety
///
/// `base` holds `count` elements of `width` bytes; `compare` orders two of them.
#[unsafe(export_name = "f2k_export_qsort")]
pub unsafe extern "C" fn qsort(base: *mut u8, count: usize, width: usize, compare: Compare) {
    if count < 2 || width == 0 {
        return;
    }
    let Some(length) = count.checked_mul(width) else {
        return;
    };
    // SAFETY: the caller's array of `count` elements of `width` bytes, the sort's alone meanwhile.
    let bytes = unsafe { core::slice::from_raw_parts_mut(base, length) };
    let compare = |a: &[u8], b: &[u8]| {
        // SAFETY: the caller's comparison, over two elements of its array (it reads them only).
        unsafe { compare(a.as_ptr(), b.as_ptr()) }
    };
    sort(&mut Elements {
        bytes,
        width,
        compare: &compare,
    });
}

/// The quicksort's body.
fn sort(array: &mut Elements) {
    let width = array.width;
    let mut count = array.bytes.len() / width;
    while count > 8 {
        let (first, middle, last) = (0, count / 2, count - 1);
        // The median of three to the front.
        if array.order(middle, first) < 0 {
            array.swap(middle, first);
        }
        if array.order(last, middle) < 0 {
            array.swap(last, middle);
            if array.order(middle, first) < 0 {
                array.swap(middle, first);
            }
        }
        array.swap(first, middle);
        // Partition the rest around the pivot at the front.
        let (mut low, mut high) = (1, count - 1);
        loop {
            while low <= high && array.order(low, first) < 0 {
                low += 1;
            }
            while high >= low && array.order(high, first) > 0 {
                high -= 1;
            }
            if low >= high {
                break;
            }
            array.swap(low, high);
            low += 1;
            high -= 1;
        }
        array.swap(first, high);
        let (left, right) = (high, count - high - 1);
        // The smaller side sorted first (recursively), the larger by the loop.
        let bytes = core::mem::take(&mut array.bytes);
        let (front, back) = bytes.split_at_mut(high * width);
        let back = &mut back[width..];
        let (smaller, larger) = if left < right {
            (front, back)
        } else {
            (back, front)
        };
        sort(&mut Elements {
            bytes: smaller,
            width,
            compare: array.compare,
        });
        array.bytes = larger;
        count = left.max(right);
    }
    for i in 1..count {
        let mut j = i;
        while j > 0 && array.order(j - 1, j) > 0 {
            array.swap(j - 1, j);
            j -= 1;
        }
    }
}

/// rand: the next pseudo-random number, 0 to 32767.
#[unsafe(export_name = "f2k_export_rand")]
pub extern "C" fn rand() -> i32 {
    thread::with_data(|data| {
        let seed = data
            .seed
            .load(Relaxed)
            .wrapping_mul(214_013)
            .wrapping_add(2_531_011);
        data.seed.store(seed, Relaxed);
        (seed >> 16 & 0x7FFF) as i32
    })
}

/// srand: rand's seed.
#[unsafe(export_name = "f2k_export_srand")]
pub extern "C" fn srand(seed: u32) {
    thread::with_data(|data| data.seed.store(seed, Relaxed));
}

/// abs: the int's absolute value; INT_MIN, which has no positive counterpart, answers itself.
#[unsafe(export_name = "f2k_export_abs")]
pub extern "C" fn abs(value: i32) -> i32 {
    value.wrapping_abs()
}

/// labs: as abs (a long is an int on Win32).
#[unsafe(export_name = "f2k_export_labs")]
pub extern "C" fn labs(value: i32) -> i32 {
    value.wrapping_abs()
}

/// The FILETIME of 1970-01-01 00:00:00 UTC, in 100-nanosecond intervals since 1601.
const UNIX_EPOCH: u64 = 116_444_736_000_000_000;

/// time: the seconds since 1970-01-01 00:00:00 UTC, stored in `timer` too when it is given.
///
/// # Safety
///
/// `timer` is null or a `time_t`'s storage.
#[unsafe(export_name = "f2k_export_time")]
pub unsafe extern "C" fn time(timer: *mut i32) -> i32 {
    let now = kernel32::system_time();
    let seconds = (now.saturating_sub(UNIX_EPOCH) / 10_000_000) as i32;
    if !timer.is_null() {
        // SAFETY: the caller's time_t.
        unsafe { timer.write_unaligned(seconds) };
    }
    seconds
}

/// Seconds in a day and in an hour.
const DAY: i64 = 86_400;
const HOUR: i64 = 3_600;

/// time.h's `struct tm`: the seconds, minutes and hours, the day of the month (1 to 31), the month
/// (0 to 11), the years since 1900, the day of the week (0 Sunday), the day of the year (0 to 365),
/// and whether daylight saving time is in effect.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Tm {
    pub sec: i32,
    pub min: i32,
    pub hour: i32,
    pub mday: i32,
    pub mon: i32,
    pub year: i32,
    pub wday: i32,
    pub yday: i32,
    pub isdst: i32,
}

impl Tm {
    fn fields(&self) -> [i32; 9] {
        [
            self.sec, self.min, self.hour, self.mday, self.mon, self.year, self.wday, self.yday,
            self.isdst,
        ]
    }
}

/// The year `seconds` after 1970-01-01 00:00:00 falls in.
fn year_of(seconds: i64) -> i64 {
    civil_from_days(seconds.div_euclid(DAY)).0
}

/// The broken-down time `seconds` after 1970-01-01 00:00:00, `tm_isdst` 0.
fn broken_down(seconds: i64) -> Tm {
    let days = seconds.div_euclid(DAY);
    let of_day = seconds.rem_euclid(DAY);
    let (year, month, day) = civil_from_days(days);
    Tm {
        sec: (of_day % 60) as i32,
        min: (of_day / 60 % 60) as i32,
        hour: (of_day / HOUR) as i32,
        mday: day as i32,
        mon: month as i32 - 1,
        year: (year - 1900) as i32,
        // 1970-01-01 was a Thursday.
        wday: (days + 4).rem_euclid(7) as i32,
        yday: (days - days_from_civil(year, 1, 1)) as i32,
        isdst: 0,
    }
}

/// The day of a daylight saving change: the `week`th `weekday` (0 Sunday) of the month, 5 the
/// last, every year (a SYSTEMTIME's rule form); or a date, in one year.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Day {
    Nth { week: i64, weekday: i64 },
    Date { year: i64, day: i64 },
}

/// A daylight saving change: its day in `month` (1 to 12), at `time` seconds into the day.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Change {
    month: u32,
    day: Day,
    time: i64,
}

impl Change {
    /// A time zone's change as GetTimeZoneInformation gives it.
    fn from_system(date: &SystemTime) -> Change {
        let day = if date.year == 0 {
            Day::Nth {
                week: i64::from(date.day),
                weekday: i64::from(date.day_of_week),
            }
        } else {
            Day::Date {
                year: i64::from(date.year),
                day: i64::from(date.day),
            }
        };
        Change {
            month: u32::from(date.month),
            day,
            time: i64::from(date.hour) * HOUR
                + i64::from(date.minute) * 60
                + i64::from(date.second),
        }
    }

    /// The change's moment in `year`, in seconds since 1970 of the local time it is given in; none
    /// when the change is another year's.
    fn in_year(&self, year: i64) -> Option<i64> {
        let first = days_from_civil(year, self.month, 1);
        let day = match self.day {
            Day::Date { year: only, day } => {
                if only != year {
                    return None;
                }
                day - 1
            }
            Day::Nth { week, weekday } => {
                let next = if self.month >= 12 {
                    days_from_civil(year + 1, 1, 1)
                } else {
                    days_from_civil(year, self.month + 1, 1)
                };
                let length = next - first;
                let mut day = (weekday - (first + 4)).rem_euclid(7) + (week - 1) * 7;
                while day >= length && day >= 7 {
                    day -= 7;
                }
                day
            }
        };
        Some((first + day) * DAY + self.time)
    }
}

/// A time zone's daylight saving time: the seconds it moves the clock on, the change that starts
/// it (given in standard time) and the one that ends it (given in daylight time).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Daylight {
    shift: i64,
    start: Change,
    end: Change,
}

impl Daylight {
    /// The United States' rules, which MSDN's _tzset says the C runtime assumes for a TZ naming a
    /// daylight zone: an hour on, from the first Sunday of April at 2:00 to the last Sunday of
    /// October at 2:00 (MSVC 6's documentation; the same for every year).
    const UNITED_STATES: Daylight = Daylight {
        shift: HOUR,
        start: Change {
            month: 4,
            day: Day::Nth {
                week: 1,
                weekday: 0,
            },
            time: 2 * HOUR,
        },
        end: Change {
            month: 10,
            day: Day::Nth {
                week: 5,
                weekday: 0,
            },
            time: 2 * HOUR,
        },
    };
}

/// The time zone localtime and mktime convert in: the seconds local standard time is behind UTC
/// (`_timezone`), and its daylight saving time, when it has one (`_daylight`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Zone {
    bias: i64,
    daylight: Option<Daylight>,
}

impl Zone {
    const UTC: Zone = Zone {
        bias: 0,
        daylight: None,
    };

    /// TZ's zone, as MSDN's _tzset reads `tzn[+|-]hh[:mm[:ss]][dzn]`: three letters naming the
    /// zone, the hours (then minutes and seconds) local time is behind UTC (ahead for `-`), and
    /// anything after them naming a daylight zone, which brings the United States' rules.
    pub fn from_tz(text: &[u8]) -> Zone {
        let mut rest = &text[text.len().min(3)..];
        let negative = rest.first() == Some(&b'-');
        if matches!(rest.first(), Some(b'-' | b'+')) {
            rest = &rest[1..];
        }
        let mut seconds = 0i64;
        for (i, unit) in [HOUR, 60, 1].into_iter().enumerate() {
            if i > 0 {
                match rest.strip_prefix(b":") {
                    Some(after) => rest = after,
                    None => break,
                }
            }
            let digits = rest.iter().take_while(|byte| byte.is_ascii_digit()).count();
            let value = rest[..digits].iter().fold(0i64, |value, &digit| {
                value
                    .saturating_mul(10)
                    .saturating_add(i64::from(digit - b'0'))
            });
            seconds = seconds.saturating_add(value.saturating_mul(unit));
            rest = &rest[digits..];
        }
        Zone {
            bias: if negative { -seconds } else { seconds },
            daylight: (!rest.is_empty()).then_some(Daylight::UNITED_STATES),
        }
    }

    /// The system's zone: its bias with the standard bias (UTC is local time plus the bias, in
    /// minutes), and daylight saving time when it has a daylight date, its changes the zone's own.
    pub fn from_system(information: &TimeZoneInformation) -> Zone {
        let standard_bias = i64::from(information.standard_bias);
        let has_daylight =
            information.daylight_date.month != 0 && information.standard_date.month != 0;
        Zone {
            bias: (i64::from(information.bias) + standard_bias) * 60,
            daylight: has_daylight.then(|| Daylight {
                shift: (standard_bias - i64::from(information.daylight_bias)) * 60,
                start: Change::from_system(&information.daylight_date),
                end: Change::from_system(&information.standard_date),
            }),
        }
    }

    /// Whether daylight saving time is in effect at `standard`, seconds since 1970 of local
    /// standard time: from the start of its year's daylight time to its end (taken back to
    /// standard time), or outside the other way round where the end comes first in the year
    /// (the southern hemisphere's).
    fn in_daylight(&self, standard: i64) -> bool {
        let Some(daylight) = self.daylight else {
            return false;
        };
        let year = year_of(standard);
        let (Some(start), Some(end)) = (daylight.start.in_year(year), daylight.end.in_year(year))
        else {
            return false;
        };
        let end = end - daylight.shift;
        if start < end {
            (start..end).contains(&standard)
        } else {
            standard >= start || standard < end
        }
    }

    /// localtime's answer for `time` (seconds since 1970 UTC): the local broken-down time, daylight
    /// saving time applied, in 1969 for the first hours west of UTC; none for a negative time.
    pub fn local(&self, time: i64) -> Option<Tm> {
        if time < 0 {
            return None;
        }
        let standard = time - self.bias;
        let daylight = self.in_daylight(standard);
        let local = standard + self.daylight.filter(|_| daylight).map_or(0, |d| d.shift);
        Some(Tm {
            isdst: daylight as i32,
            ..broken_down(local)
        })
    }

    /// mktime's answer for the local time `tm`: its fields normalized (each out-of-range one
    /// carried into the next, the day of the month walked across months), then `tm_isdst` > 0
    /// taken as daylight time, 0 as standard time, < 0 as the zone's rules say for the time
    /// read as standard time. The time since 1970 UTC and the local time localtime gives for
    /// it; none for a time outside 0 to 2^31-1, whatever the local year (1969-12-31 23:59:59 in
    /// Pacific standard time is 28799).
    pub fn make(&self, tm: &Tm) -> Option<(i64, Tm)> {
        let months = i64::from(tm.year) * 12 + i64::from(tm.mon);
        let (year, month) = (1900 + months.div_euclid(12), months.rem_euclid(12) + 1);
        let days = days_from_civil(year, month as u32, 1) + i64::from(tm.mday) - 1;
        let local =
            days * DAY + i64::from(tm.hour) * HOUR + i64::from(tm.min) * 60 + i64::from(tm.sec);
        let shift = self.daylight.map_or(HOUR, |daylight| daylight.shift);
        let daylight = match tm.isdst {
            0 => false,
            isdst if isdst > 0 => true,
            _ => self.in_daylight(local),
        };
        let time = local - if daylight { shift } else { 0 } + self.bias;
        if !(0..=i64::from(i32::MAX)).contains(&time) {
            return None;
        }
        Some((time, self.local(time)?))
    }
}

/// A time zone's names (`_tzname`'s): the standard time's and the daylight time's, narrow, as
/// many bytes as `_tzname`'s 64-byte strings hold.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZoneNames {
    names: [[u8; 63]; 2],
    lengths: [usize; 2],
}

impl ZoneNames {
    const NONE: ZoneNames = ZoneNames {
        names: [[0; 63]; 2],
        lengths: [0; 2],
    };

    /// The names given, each cut to its room.
    fn of(standard: &[u8], daylight: &[u8]) -> ZoneNames {
        let mut names = ZoneNames::NONE;
        for (i, name) in [standard, daylight].into_iter().enumerate() {
            let length = name.len().min(names.names[i].len());
            names.names[i][..length].copy_from_slice(&name[..length]);
            names.lengths[i] = length;
        }
        names
    }

    /// TZ's names, as MSDN's _tzset reads `tzn[+|-]hh[:mm[:ss]][dzn]`: its first three letters,
    /// and the three after the time for a daylight zone (none without one).
    pub fn from_tz(text: &[u8]) -> ZoneNames {
        let standard = &text[..text.len().min(3)];
        let rest = &text[standard.len()..];
        let time = rest
            .iter()
            .take_while(|&&byte| byte.is_ascii_digit() || matches!(byte, b'+' | b'-' | b':'))
            .count();
        let daylight = &rest[time..];
        ZoneNames::of(standard, &daylight[..daylight.len().min(3)])
    }

    /// The system's names (its StandardName and DaylightName), in the ANSI code page.
    pub fn from_system(information: &TimeZoneInformation) -> ZoneNames {
        let narrow = |name: &[u16; 32], out: &mut [u8; 63]| {
            let length = name
                .iter()
                .position(|&unit| unit == 0)
                .unwrap_or(name.len());
            kernel32::wide_to_multi_byte(CP_ACP, 0, &name[..length], out).0
        };
        let mut names = ZoneNames::NONE;
        names.lengths[0] = narrow(&information.standard_name, &mut names.names[0]);
        names.lengths[1] = narrow(&information.daylight_name, &mut names.names[1]);
        names
    }

    /// The standard time's name, or the daylight time's.
    pub fn name(&self, daylight: bool) -> &[u8] {
        let i = usize::from(daylight);
        &self.names[i][..self.lengths[i]]
    }
}

/// WideCharToMultiByte's ANSI code page.
const CP_ACP: u32 = 0;

/// The time zone as _tzset reads it: the zone localtime and mktime convert in, and its names
/// (strftime's `%Z`).
#[derive(Clone, Copy)]
struct Setting {
    zone: Zone,
    names: ZoneNames,
}

/// The time zone, as _tzset last read it (none before its first read). Its lock is held only to
/// read or set it.
static ZONE: Locked<Option<Setting>, Lock> = Locked::new(Lock::new(), None);

/// The zone _tzset reads: TZ's when the C runtime's environment sets it to something, the system's
/// (GetTimeZoneInformation) otherwise.
fn read_zone() -> Setting {
    let mut value = [0u8; 64];
    match startup::environment_value(b"TZ", &mut value) {
        Some(length) if length > 0 => Setting {
            zone: Zone::from_tz(&value[..length]),
            names: ZoneNames::from_tz(&value[..length]),
        },
        _ => kernel32::time_zone_information().map_or(
            Setting {
                zone: Zone::UTC,
                names: ZoneNames::NONE,
            },
            |information| Setting {
                zone: Zone::from_system(&information),
                names: ZoneNames::from_system(&information),
            },
        ),
    }
}

/// The time zone, read on the first need when the program has not called _tzset.
fn setting() -> Setting {
    if let Some(setting) = ZONE.with(|setting| *setting) {
        return setting;
    }
    let read = read_zone();
    ZONE.with(|setting| *setting.get_or_insert(read))
}

/// The zone localtime and mktime convert in.
fn zone() -> Zone {
    setting().zone
}

/// _tzset: the time zone read again (TZ, else the system's), for localtime, mktime and wcsftime.
#[unsafe(export_name = "f2k_export__tzset")]
pub extern "C" fn tzset() {
    let read = read_zone();
    ZONE.with(|setting| *setting = Some(read));
}

/// `tm` made the calling thread's `struct tm` (the one gmtime, localtime and mktime share): its
/// address.
fn answer(tm: &Tm) -> *mut Tm {
    thread::with_data(|data| {
        for (field, value) in data.tm.iter().zip(tm.fields()) {
            field.store(value, Relaxed);
        }
        // The nine ints, laid out as `struct tm` (both `repr(C)`, an atomic an int's layout); the
        // program reads and writes them through the pointer, the C runtime only atomically.
        core::ptr::from_ref(&data.tm).cast::<Tm>().cast_mut()
    })
}

/// The `time_t` at `timer`.
///
/// # Safety
///
/// `timer` is a `time_t`.
unsafe fn read_time(timer: *const i32) -> i64 {
    // SAFETY: the caller's time_t.
    i64::from(unsafe { timer.read_unaligned() })
}

/// gmtime: the UTC broken-down time of `*timer`, in the calling thread's `struct tm`; NULL for a
/// negative time.
///
/// # Safety
///
/// `timer` is a `time_t`.
#[unsafe(export_name = "f2k_export_gmtime")]
pub unsafe extern "C" fn gmtime(timer: *const i32) -> *mut Tm {
    // SAFETY: the caller's time_t.
    let time = unsafe { read_time(timer) };
    if time < 0 {
        return core::ptr::null_mut();
    }
    answer(&broken_down(time))
}

/// localtime: the local broken-down time of `*timer` ([`Zone::local`]), in the calling thread's
/// `struct tm`; NULL for a negative time.
///
/// # Safety
///
/// `timer` is a `time_t`.
#[unsafe(export_name = "f2k_export_localtime")]
pub unsafe extern "C" fn localtime(timer: *const i32) -> *mut Tm {
    // SAFETY: the caller's time_t.
    let time = unsafe { read_time(timer) };
    zone()
        .local(time)
        .map_or(core::ptr::null_mut(), |tm| answer(&tm))
}

/// mktime: the time of the local time `*tm` ([`Zone::make`]), `*tm` rewritten as localtime gives
/// it (normalized, its day of the week and of the year filled); -1, `*tm` untouched, when its time
/// falls outside 0 to 2^31-1.
///
/// # Safety
///
/// `tm` is a `struct tm`.
#[unsafe(export_name = "f2k_export_mktime")]
pub unsafe extern "C" fn mktime(tm: *mut Tm) -> i32 {
    // SAFETY: the caller's struct tm.
    let given = unsafe { tm.read_unaligned() };
    let Some((time, local)) = zone().make(&given) else {
        return -1;
    };
    // SAFETY: as above.
    unsafe { tm.write_unaligned(local) };
    answer(&local);
    time as i32
}

/// The "C" locale's day and month names, full and abbreviated (their first three letters).
const DAYS: [&[u8]; 7] = [
    b"Sunday",
    b"Monday",
    b"Tuesday",
    b"Wednesday",
    b"Thursday",
    b"Friday",
    b"Saturday",
];
const MONTHS: [&[u8]; 12] = [
    b"January",
    b"February",
    b"March",
    b"April",
    b"May",
    b"June",
    b"July",
    b"August",
    b"September",
    b"October",
    b"November",
    b"December",
];

/// The units a time's text is written into: each one past the room still counted.
struct TimeText<'a> {
    out: &'a mut [WideUnit],
    count: usize,
}

impl TimeText<'_> {
    fn unit(&mut self, unit: u16) {
        if let Some(slot) = self.out.get_mut(self.count) {
            *slot = WideUnit::new(unit);
        }
        self.count += 1;
    }

    /// Narrow text, each byte widened in the LC_CTYPE locale.
    fn text(&mut self, text: &[u8]) {
        text.iter()
            .for_each(|&byte| self.unit(ctype::byte_to_wide(byte)));
    }

    /// A number in `width` digits, zeros before it; in as few as it takes when `trim`.
    fn number(&mut self, value: i32, width: usize, trim: bool) {
        if value < 0 {
            self.unit(u16::from(b'-'));
        }
        let mut digits = [0u8; 10];
        let mut length = 0;
        let mut rest = value.unsigned_abs();
        loop {
            digits[length] = b'0' + (rest % 10) as u8;
            length += 1;
            rest /= 10;
            if rest == 0 {
                break;
            }
        }
        if !trim {
            (length..width).for_each(|_| self.unit(u16::from(b'0')));
        }
        for &digit in digits[..length].iter().rev() {
            self.unit(u16::from(digit));
        }
    }

    /// One name of `names`, by an index the program's `struct tm` gives (nothing out of range).
    fn name(&mut self, names: &[&[u8]], index: i32, abbreviated: bool) {
        if let Some(name) = usize::try_from(index).ok().and_then(|i| names.get(i)) {
            self.text(if abbreviated { &name[..3] } else { name });
        }
    }
}

/// The week of the year (`%U` from Sunday, `%W` from Monday): 0 before its first such day.
fn week(tm: &Tm, first_day: i32) -> i32 {
    (tm.yday + 7 - (tm.wday - first_day).rem_euclid(7)) / 7
}

/// One conversion of `wcsftime`'s format, `#` (`alternate`) taken as MSDN documents it: the long
/// date for `%#c` and `%#x`, no leading zeros for the numbers.
fn convert(out: &mut TimeText, conversion: u16, alternate: bool, tm: &Tm, names: &ZoneNames) {
    let two = |out: &mut TimeText, value| out.number(value, 2, alternate);
    let short_date = |out: &mut TimeText| {
        out.number(tm.mon + 1, 2, false);
        out.unit(u16::from(b'/'));
        out.number(tm.mday, 2, false);
        out.unit(u16::from(b'/'));
        out.number(tm.year.rem_euclid(100), 2, false);
    };
    let long_date = |out: &mut TimeText| {
        out.name(&DAYS, tm.wday, false);
        out.text(b", ");
        out.name(&MONTHS, tm.mon, false);
        out.unit(u16::from(b' '));
        out.number(tm.mday, 2, false);
        out.text(b", ");
        out.number(tm.year + 1900, 4, false);
    };
    let time = |out: &mut TimeText| {
        for (i, value) in [tm.hour, tm.min, tm.sec].into_iter().enumerate() {
            if i > 0 {
                out.unit(u16::from(b':'));
            }
            out.number(value, 2, false);
        }
    };
    let Ok(conversion) = u8::try_from(conversion) else {
        return;
    };
    match conversion {
        b'a' => out.name(&DAYS, tm.wday, true),
        b'A' => out.name(&DAYS, tm.wday, false),
        b'b' => out.name(&MONTHS, tm.mon, true),
        b'B' => out.name(&MONTHS, tm.mon, false),
        b'c' => {
            if alternate {
                long_date(out);
            } else {
                short_date(out);
            }
            out.unit(u16::from(b' '));
            time(out);
        }
        b'x' if alternate => long_date(out),
        b'x' => short_date(out),
        b'X' => time(out),
        b'd' => two(out, tm.mday),
        b'H' => two(out, tm.hour),
        b'I' => two(out, (tm.hour + 11).rem_euclid(12) + 1),
        b'j' => out.number(tm.yday + 1, 3, alternate),
        b'm' => two(out, tm.mon + 1),
        b'M' => two(out, tm.min),
        b'p' => out.text(if tm.hour < 12 { b"AM" } else { b"PM" }),
        b'S' => two(out, tm.sec),
        b'U' => two(out, week(tm, 0)),
        b'w' => out.number(tm.wday, 1, alternate),
        b'W' => two(out, week(tm, 1)),
        b'y' => two(out, tm.year.rem_euclid(100)),
        b'Y' => out.number(tm.year + 1900, 4, alternate),
        b'z' | b'Z' => out.text(names.name(tm.isdst > 0)),
        b'%' => out.unit(u16::from(b'%')),
        _ => {}
    }
}

/// wcsftime's text of `tm` by `format`, into `out`: the units it takes (more than `out` holds when
/// it does not fit).
fn format_time(out: &mut [WideUnit], format: &[WideUnit], tm: &Tm, names: &ZoneNames) -> usize {
    let mut text = TimeText { out, count: 0 };
    let mut units = format.iter().map(|unit| unit.get());
    while let Some(unit) = units.next() {
        if unit != u16::from(b'%') {
            text.unit(unit);
            continue;
        }
        let mut conversion = units.next();
        let alternate = conversion == Some(u16::from(b'#'));
        if alternate {
            conversion = units.next();
        }
        let Some(conversion) = conversion else {
            break;
        };
        convert(&mut text, conversion, alternate, tm, names);
    }
    text.count
}

/// wcsftime: `tm` as `format` writes it, in the "C" locale's names and formats, into `buffer` of
/// `size` units: the units written, its NUL left out. As wide's capture pins it: `%c` is
/// `%m/%d/%y %H:%M:%S`, `%#c` and `%#x` the long date (`%A, %B %d, %Y`), `%x` `%m/%d/%y`, `%X`
/// `%H:%M:%S`, `%I` 12 for hour 0, `%z` the zone's name as `%Z` is (the daylight time's for a
/// `tm_isdst` above 0, the time zone _tzset read), and `#` before a number drops its leading
/// zeros. Text that fills the buffer exactly is written without its NUL and answered; text longer
/// than the buffer answers 0, as the empty text does. An unknown conversion writes nothing.
///
/// # Safety
///
/// `buffer` holds `size` units; `format` is NUL-terminated; `tm` is a `struct tm`.
#[unsafe(export_name = "f2k_export_wcsftime")]
pub unsafe extern "C" fn wcsftime(
    buffer: *mut u16,
    size: usize,
    format: *const u16,
    tm: *const Tm,
) -> usize {
    if !ctype::is_c_category(ctype::LC_TIME) {
        // SAFETY: the call's arguments, as wcsftime's kinds read them.
        unsafe {
            crate::stub::logged(
                &crate::spec::wcsftime,
                "a locale's LC_TIME (the \"C\" locale's names and formats written)",
                &[buffer as u64, size as u64, format as u64, tm as u64],
            )
        };
    }
    // SAFETY: the caller's format, its struct tm and its buffer of `size` units, the call's alone.
    let (format, tm, out) = unsafe {
        (
            edge::wide(format),
            tm.read_unaligned(),
            edge::wide_parts_mut(buffer, size),
        )
    };
    let count = format_time(out, format, &tm, &setting().names);
    if count == 0 || count > size {
        if let Some(first) = out.first_mut() {
            *first = WideUnit::new(0);
        }
        return 0;
    }
    if let Some(end) = out.get_mut(count) {
        *end = WideUnit::new(0);
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" fn by_int(a: *const u8, b: *const u8) -> i32 {
        // SAFETY: two ints of the test's array.
        let (x, y) = unsafe {
            (
                (a as *const i32).read_unaligned(),
                (b as *const i32).read_unaligned(),
            )
        };
        x.cmp(&y) as i32
    }

    /// wide's sort block, and sizes past the insertion sort's.
    #[test]
    fn qsort_sorts() {
        let mut ints = [
            42,
            -7,
            1000,
            0,
            13,
            -2147483647,
            8,
            99,
            2147483647,
            5,
            -1,
            64,
        ];
        // SAFETY: the test's array of ints.
        unsafe { qsort(ints.as_mut_ptr().cast(), 12, 4, by_int) };
        assert_eq!(
            ints,
            [
                -2147483647,
                -7,
                -1,
                0,
                5,
                8,
                13,
                42,
                64,
                99,
                1000,
                2147483647
            ]
        );
        let mut many: Vec<i32> = (0..1000).map(|i| (i * 7919 % 1009) - 500).collect();
        many.extend([3; 50]);
        let mut expected = many.clone();
        expected.sort();
        // SAFETY: as above.
        unsafe { qsort(many.as_mut_ptr().cast(), many.len(), 4, by_int) };
        assert_eq!(many, expected);
    }

    /// wide's rand block.
    #[test]
    fn rand_as_captured() {
        let eight = || (0..8).map(|_| rand()).collect::<Vec<_>>();
        let first = [41, 18467, 6334, 26500, 19169, 15724, 11478, 29358];
        std::thread::spawn(move || {
            assert_eq!(eight(), first);
            srand(1);
            assert_eq!(eight(), first);
            srand(42);
            assert_eq!(eight(), [175, 400, 17869, 30056, 16083, 12879, 8016, 7644]);
        })
        .join()
        .unwrap();
    }

    /// A broken-down time as wide's calendar block prints it.
    fn shown(tm: &Tm) -> String {
        format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02} wday {} yday {} isdst {}",
            tm.year + 1900,
            tm.mon + 1,
            tm.mday,
            tm.hour,
            tm.min,
            tm.sec,
            tm.wday,
            tm.yday,
            tm.isdst
        )
    }

    /// gmtime of known values, through the export: the epoch, a day's last second, a leap day, a
    /// year's last day, 2^31-1; a negative time is NULL.
    #[test]
    fn gmtime_of_known_values() {
        for (time, expected) in [
            (0, "1970-01-01 00:00:00 wday 4 yday 0 isdst 0"),
            (86_399, "1970-01-01 23:59:59 wday 4 yday 0 isdst 0"),
            (86_400, "1970-01-02 00:00:00 wday 5 yday 1 isdst 0"),
            (951_782_400, "2000-02-29 00:00:00 wday 2 yday 59 isdst 0"),
            (978_307_199, "2000-12-31 23:59:59 wday 0 yday 365 isdst 0"),
            (1_004_259_600, "2001-10-28 09:00:00 wday 0 yday 300 isdst 0"),
            (i32::MAX, "2038-01-19 03:14:07 wday 2 yday 18 isdst 0"),
        ] {
            // SAFETY: a time_t; the answer is the thread's struct tm.
            let tm = unsafe { gmtime(&time) };
            assert_eq!(shown(&unsafe { *tm }), expected, "{time}");
        }
        // SAFETY: as above.
        assert!(unsafe { gmtime(&-1) }.is_null());
    }

    /// localtime under TZ=PST8PDT: the United States' rules around 2001's changes (2:00 standard
    /// time jumps to 3:00 on the first Sunday of April; 2:00 daylight time falls back to 1:00 on
    /// the last Sunday of October), the same rules in 2007, and the first hours of 1970 UTC in 1969
    /// local time.
    #[test]
    fn localtime_under_a_fixed_tz() {
        let pacific = Zone::from_tz(b"PST8PDT");
        assert_eq!(
            pacific,
            Zone {
                bias: 8 * HOUR,
                daylight: Some(Daylight::UNITED_STATES)
            }
        );
        let local = |time: i64| pacific.local(time).map(|tm| shown(&tm));
        for (time, expected) in [
            (28_800, "1970-01-01 00:00:00 wday 4 yday 0 isdst 0"),
            (986_119_199, "2001-04-01 01:59:59 wday 0 yday 90 isdst 0"),
            (986_119_200, "2001-04-01 03:00:00 wday 0 yday 90 isdst 1"),
            (992_606_400, "2001-06-15 05:00:00 wday 5 yday 165 isdst 1"),
            (1_004_255_999, "2001-10-28 00:59:59 wday 0 yday 300 isdst 1"),
            (1_004_259_599, "2001-10-28 01:59:59 wday 0 yday 300 isdst 1"),
            (1_004_259_600, "2001-10-28 01:00:00 wday 0 yday 300 isdst 0"),
            (1_174_392_000, "2007-03-20 04:00:00 wday 2 yday 78 isdst 0"),
            (2_147_483_647, "2038-01-18 19:14:07 wday 1 yday 17 isdst 0"),
        ] {
            assert_eq!(local(time).as_deref(), Some(expected), "{time}");
        }
        assert_eq!(
            local(0).as_deref(),
            Some("1969-12-31 16:00:00 wday 3 yday 364 isdst 0")
        );
        assert_eq!(
            local(28_799).as_deref(),
            Some("1969-12-31 23:59:59 wday 3 yday 364 isdst 0")
        );
        assert_eq!(local(-1), None);

        let shifted = |tz: &[u8], time| Zone::from_tz(tz).local(time).map(|tm| shown(&tm));
        assert_eq!(
            shifted(b"EST5", 992_606_400).as_deref(),
            Some("2001-06-15 07:00:00 wday 5 yday 165 isdst 0")
        );
        assert_eq!(
            shifted(b"GMT0", 0).as_deref(),
            Some("1970-01-01 00:00:00 wday 4 yday 0 isdst 0")
        );
        assert_eq!(
            shifted(b"IST-5:30", 0).as_deref(),
            Some("1970-01-01 05:30:00 wday 4 yday 0 isdst 0")
        );
        assert_eq!(
            shifted(b"NST3:30NDT", 992_606_400).as_deref(),
            Some("2001-06-15 09:30:00 wday 5 yday 165 isdst 1")
        );
        assert_eq!(Zone::from_tz(b"XYZ+1:15:30").bias, HOUR + 15 * 60 + 30);
    }

    /// The system's zone, its own changes: a southern one (UTC+10, daylight time from the last
    /// Sunday of October to the last Sunday of March) is in daylight time in January.
    #[test]
    fn the_system_zone_takes_its_own_changes() {
        let date = |month, day, hour| SystemTime {
            month,
            day_of_week: 0,
            day,
            hour,
            ..SystemTime::ZERO
        };
        let southern = Zone::from_system(&TimeZoneInformation {
            bias: -600,
            standard_date: date(3, 5, 3),
            daylight_date: date(10, 5, 2),
            daylight_bias: -60,
            ..TimeZoneInformation::UTC
        });
        let local = |time| southern.local(time).map(|tm| shown(&tm));
        assert_eq!(
            local(978_307_200).as_deref(),
            Some("2001-01-01 11:00:00 wday 1 yday 0 isdst 1")
        );
        assert_eq!(
            local(994_118_400).as_deref(),
            Some("2001-07-03 10:00:00 wday 2 yday 183 isdst 0")
        );
        let pacific = Zone::from_system(&TimeZoneInformation {
            bias: 480,
            standard_date: date(10, 5, 2),
            daylight_date: date(4, 1, 2),
            daylight_bias: -60,
            ..TimeZoneInformation::UTC
        });
        assert_eq!(pacific, Zone::from_tz(b"PST8PDT"));
        assert_eq!(Zone::from_system(&TimeZoneInformation::UTC), Zone::UTC);
    }

    /// mktime under TZ=PST8PDT: out-of-range fields normalized, tm_wday and tm_yday filled, its
    /// tm_isdst answers, and the bounds of the time (0 to 2^31-1 UTC, whatever the local year).
    #[test]
    fn mktime_normalizes_and_bounds() {
        let pacific = Zone::from_tz(b"PST8PDT");
        let make = |year, mon, mday, hour, min, sec, isdst| {
            let tm = Tm {
                year,
                mon,
                mday,
                hour,
                min,
                sec,
                isdst,
                wday: -9,
                yday: -9,
            };
            pacific
                .make(&tm)
                .map(|(time, tm)| format!("{time} {}", shown(&tm)))
        };
        for (fields, expected) in [
            (
                (101, 5, 15, 12, 0, 0, -1),
                "992631600 2001-06-15 12:00:00 wday 5 yday 165 isdst 1",
            ),
            (
                (101, 5, 15, 12, 0, 0, 0),
                "992635200 2001-06-15 13:00:00 wday 5 yday 165 isdst 1",
            ),
            (
                (101, 5, 15, 12, 0, 0, 1),
                "992631600 2001-06-15 12:00:00 wday 5 yday 165 isdst 1",
            ),
            (
                (101, 0, 15, 12, 0, 0, 1),
                "979585200 2001-01-15 11:00:00 wday 1 yday 14 isdst 0",
            ),
            (
                (101, 1, 31, 0, 0, 0, -1),
                "983606400 2001-03-03 00:00:00 wday 6 yday 61 isdst 0",
            ),
            (
                (101, 2, 0, 0, 0, 0, -1),
                "983347200 2001-02-28 00:00:00 wday 3 yday 58 isdst 0",
            ),
            (
                (101, -1, 15, 0, 0, 0, -1),
                "976867200 2000-12-15 00:00:00 wday 5 yday 349 isdst 0",
            ),
            (
                (101, 12, 1, 0, 0, 0, -1),
                "1009872000 2002-01-01 00:00:00 wday 2 yday 0 isdst 0",
            ),
            (
                (101, 0, 1, 0, 0, 90_061, -1),
                "978426061 2001-01-02 01:01:01 wday 2 yday 1 isdst 0",
            ),
            (
                (101, 0, 1, 0, -1, 0, -1),
                "978335940 2000-12-31 23:59:00 wday 0 yday 365 isdst 0",
            ),
            (
                (100, 1, 28, 48, 0, 0, -1),
                "951897600 2000-03-01 00:00:00 wday 3 yday 60 isdst 0",
            ),
            (
                (70, 0, 1, 0, 0, 0, 0),
                "28800 1970-01-01 00:00:00 wday 4 yday 0 isdst 0",
            ),
            (
                (69, 11, 31, 23, 59, 59, 0),
                "28799 1969-12-31 23:59:59 wday 3 yday 364 isdst 0",
            ),
            (
                (70, 0, 0, 23, 59, 59, 0),
                "28799 1969-12-31 23:59:59 wday 3 yday 364 isdst 0",
            ),
            (
                (138, 0, 18, 19, 14, 7, 0),
                "2147483647 2038-01-18 19:14:07 wday 1 yday 17 isdst 0",
            ),
        ] {
            let (year, mon, mday, hour, min, sec, isdst) = fields;
            assert_eq!(
                make(year, mon, mday, hour, min, sec, isdst).as_deref(),
                Some(expected),
                "{fields:?}"
            );
        }
        for fields in [
            (138, 0, 18, 19, 14, 8, 0),
            (139, 0, 1, 0, 0, 0, -1),
            (0, 0, 1, 0, 0, 0, -1),
        ] {
            let (year, mon, mday, hour, min, sec, isdst) = fields;
            assert_eq!(
                make(year, mon, mday, hour, min, sec, isdst),
                None,
                "{fields:?}"
            );
        }
        // East of UTC, the first minutes of 1970 local time are before 1970 UTC.
        let india = Zone::from_tz(b"IST-5:30");
        let tm = |hour, min, sec| Tm {
            year: 70,
            mday: 1,
            hour,
            min,
            sec,
            ..Tm::default()
        };
        assert_eq!(india.make(&tm(5, 30, 0)).map(|(time, _)| time), Some(0));
        assert_eq!(india.make(&tm(5, 29, 59)), None);
    }

    /// strings' abs block: INT_MIN answers itself.
    #[test]
    fn abs_and_labs() {
        for (value, expected) in [
            (0, 0),
            (5, 5),
            (-5, 5),
            (i32::MIN, i32::MIN),
            (i32::MAX, i32::MAX),
        ] {
            assert_eq!((abs(value), labs(value)), (expected, expected), "{value}");
        }
    }

    /// A `struct tm` of the wcsftime block's.
    fn tm_of(date: [i32; 6], wday: i32, yday: i32, isdst: i32) -> Tm {
        let [year, mon, mday, hour, min, sec] = date;
        Tm {
            year: year - 1900,
            mon: mon - 1,
            mday,
            hour,
            min,
            sec,
            wday,
            yday,
            isdst,
        }
    }

    /// The zone names TZ gives: its letters, and a daylight zone's after the time.
    #[test]
    fn zone_names_from_tz() {
        let names = |tz: &[u8]| {
            let names = ZoneNames::from_tz(tz);
            (
                String::from_utf8(names.name(false).to_vec()).unwrap(),
                String::from_utf8(names.name(true).to_vec()).unwrap(),
            )
        };
        assert_eq!(names(b"PST8PDT"), ("PST".into(), "PDT".into()));
        assert_eq!(names(b"NST3:30NDT"), ("NST".into(), "NDT".into()));
        assert_eq!(names(b"IST-5:30"), ("IST".into(), String::new()));
        assert_eq!(names(b"GMT0"), ("GMT".into(), String::new()));
    }

    /// wide's wcsftime block: every conversion under TZ=PST8PDT in the "C" locale.
    #[test]
    fn wcsftime_conversions_as_captured() {
        let pacific = ZoneNames::from_tz(b"PST8PDT");
        let text = |format: &str, tm: &Tm| {
            let format: Vec<WideUnit> = format.encode_utf16().map(WideUnit::new).collect();
            let mut out = [WideUnit::new(0); 256];
            let count = format_time(&mut out, &format, tm, &pacific);
            String::from_utf16(
                &out[..count]
                    .iter()
                    .map(|unit| unit.get())
                    .collect::<Vec<_>>(),
            )
            .unwrap()
        };
        let t1 = tm_of([2001, 2, 3, 4, 5, 6], 6, 33, 0);
        for (format, expected) in [
            ("%a %A %b %B", "Sat Saturday Feb February"),
            ("%c", "02/03/01 04:05:06"),
            ("%#c", "Saturday, February 03, 2001 04:05:06"),
            ("%x", "02/03/01"),
            ("%#x", "Saturday, February 03, 2001"),
            ("%X", "04:05:06"),
            ("%d %H %I %j %m %M %p %S", "03 04 04 034 02 05 AM 06"),
            ("%U %w %W", "04 6 05"),
            ("%y %Y", "01 2001"),
            ("%Z", "PST"),
            ("%z", "PST"),
            ("%%", "%"),
            ("%#d %#H %#I %#j %#m %#M %#S %#y %#U", "3 4 4 34 2 5 6 1 4"),
            ("plain text, no conversions", "plain text, no conversions"),
            ("", ""),
        ] {
            assert_eq!(text(format, &t1), expected, "{format:?}");
        }
        assert_eq!(
            text(
                "%c %Z %j %U %W",
                &tm_of([1999, 12, 31, 23, 59, 59], 5, 364, 0)
            ),
            "12/31/99 23:59:59 PST 365 52 52"
        );
        assert_eq!(
            text(
                "%c %Z %j %U %W %p",
                &tm_of([2000, 7, 4, 12, 0, 0], 2, 185, 1)
            ),
            "07/04/00 12:00:00 PDT 186 27 27 PM"
        );
        assert_eq!(
            text("%#c %I %p %U %W", &tm_of([2000, 1, 1, 0, 30, 0], 6, 0, 0)),
            "Saturday, January 01, 2000 00:30:00 12 AM 00 00"
        );
    }

    /// wide's wcsftime sizes: text that fills the buffer is answered, longer text and the empty
    /// text answer 0.
    #[test]
    fn wcsftime_buffer_sizes_as_captured() {
        let t1 = tm_of([2001, 2, 3, 4, 5, 6], 6, 33, 0);
        let call = |format: &str, size: usize| {
            let format: Vec<u16> = format.encode_utf16().chain([0]).collect();
            let mut out = [0xBEEFu16; 16];
            // SAFETY: a buffer of at least `size` units, a terminated format, a struct tm.
            let count = unsafe { wcsftime(out.as_mut_ptr(), size, format.as_ptr(), &t1) };
            (count, String::from_utf16_lossy(&out[..count]), out[count])
        };
        assert_eq!(call("%Y-%m-%d", 11), (10, "2001-02-03".into(), 0));
        assert_eq!(call("%Y-%m-%d", 10), (10, "2001-02-03".into(), 0xBEEF));
        assert_eq!(call("%H:%M:%S", 9), (8, "04:05:06".into(), 0));
        assert_eq!(call("%H:%M:%S", 8), (8, "04:05:06".into(), 0xBEEF));
        assert_eq!(call("%H:%M:%S", 1).0, 0);
        assert_eq!(call("", 1).0, 0);
        assert_eq!(call("%H", 0), (0, String::new(), 0xBEEF));
    }
}
