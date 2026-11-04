//! What the console and clock built-ins' arguments say, and what they print: `color`'s colours,
//! `date`'s and `time`'s forms (shown with `/T`, set from a value typed), and the directories
//! `pushd` saves for `popd`.

use core::fmt;

use crate::{fold, is_named, trim_blanks, Clock, Date, Text, Time};

/// What `color`'s argument asks for (`color /?`): two hex digits, the background's then the
/// foreground's (one digit is the foreground on black).
#[derive(Debug, PartialEq, Eq)]
pub enum Colour {
    /// No argument: the colours the shell started with.
    Reset,
    /// The attribute to colour the screen with.
    Set(u16),
    /// The same colour for both: refused, the ERRORLEVEL 1.
    Same,
    /// Anything but one or two hex digits.
    Invalid,
}

/// `color`'s argument read.
pub fn colour(argument: &[u16]) -> Colour {
    let argument = trim_blanks(argument);
    let digit = |unit: u16| {
        char::from_u32(u32::from(unit))
            .and_then(|c| c.to_digit(16))
            .map(|digit| digit as u16)
    };
    let (background, foreground) = match argument {
        [] => return Colour::Reset,
        [foreground] => (Some(0), digit(*foreground)),
        [background, foreground] => (digit(*background), digit(*foreground)),
        _ => return Colour::Invalid,
    };
    match (background, foreground) {
        (Some(background), Some(foreground)) if background == foreground => Colour::Same,
        (Some(background), Some(foreground)) => Colour::Set(background << 4 | foreground),
        _ => Colour::Invalid,
    }
}

/// What `date` and `time` are asked: the current value printed (`/T`), or a new value set, the
/// one the argument gives, or, without one, one asked for.
#[derive(Debug, PartialEq, Eq)]
pub enum Clocked<'a> {
    /// `/T`: the value printed, nothing asked.
    Show,
    /// The value to set: the argument's, or None to ask for one.
    Set(Option<&'a [u16]>),
}

/// `date`'s or `time`'s argument read: `/T` alone shows, anything else is a value to set.
pub fn clocked(argument: &[u16]) -> Clocked<'_> {
    let argument = trim_blanks(argument);
    if is_named(argument, "/t") {
        Clocked::Show
    } else {
        Clocked::Set((!argument.is_empty()).then_some(argument))
    }
}

/// What `date /t` prints: the date as `%DATE%` shows it, a blank, then CR LF.
pub struct ShortDate<'a>(pub &'a Time);

impl fmt::Display for ShortDate<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} \r\n", Date(self.0))
    }
}

/// What `time /t` prints: the hour on a 12-hour clock, two digits each, then `AM` or `PM`
/// (`06:31 PM`), then CR LF.
pub struct ShortTime<'a>(pub &'a Time);

impl fmt::Display for ShortTime<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hour = match self.0.hour % 12 {
            0 => 12,
            hour => hour,
        };
        let half = if self.0.hour < 12 { "AM" } else { "PM" };
        write!(f, "{hour:02}:{:02} {half}\r\n", self.0.minute)
    }
}

/// What `date` prints before it asks for a new date.
pub struct CurrentDate<'a>(pub &'a Time);

impl fmt::Display for CurrentDate<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "The current date is: {}\r\n", Date(self.0))
    }
}

/// What `time` prints before it asks for a new time.
pub struct CurrentTime<'a>(pub &'a Time);

impl fmt::Display for CurrentTime<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "The current time is: {}\r\n", Clock(self.0))
    }
}

/// `date`'s question, in the US format.
pub const ENTER_DATE: &str = "Enter the new date: (mm-dd-yy) ";
/// `time`'s question.
pub const ENTER_TIME: &str = "Enter the new time: ";
/// What `date` prints for a date it cannot read or set; it then asks again.
pub const BAD_DATE: &str = "The system cannot accept the date entered.\r\n";
/// What `time` prints for a time it cannot read or set; it then asks again.
pub const BAD_TIME: &str = "The system cannot accept the time entered.\r\n";
/// What `pause` prints, then waits for a key.
pub const PRESS_ANY_KEY: &str = "Press any key to continue . . . ";

/// The decimal numbers `text` holds, separated by any of `separators`, into `numbers`: how many,
/// None for anything else, an empty number included.
fn numbers(text: &[u16], separators: &[u8], numbers: &mut [u32]) -> Option<usize> {
    let mut count = 0;
    for part in text.split(|&unit| separators.iter().any(|&byte| unit == u16::from(byte))) {
        if part.is_empty() || part.len() > 4 {
            return None;
        }
        let mut value = 0;
        for &unit in part {
            value = value * 10 + char::from_u32(u32::from(unit))?.to_digit(10)?;
        }
        *numbers.get_mut(count)? = value;
        count += 1;
    }
    Some(count)
}

/// Whether `year` has a 29th of February.
fn leap(year: u32) -> bool {
    year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
}

/// The days of `month` in `year`.
fn days_in(month: u32, year: u32) -> u32 {
    match month {
        2 if leap(year) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// A date typed in the US format, month, day and year separated by `-`, `/` or `.` (a day's name
/// before it skipped, as `date`'s own output has one): its year, month and day. A year of one or
/// two digits is 1980 to 2079 (80 and above in the 1900s). None for anything else, a date from
/// before 1980 or after 2099 included, as cmd refuses them.
pub fn parse_date(text: &[u16]) -> Option<(u16, u16, u16)> {
    let mut text = trim_blanks(text);
    if text
        .first()
        .is_some_and(|&unit| (u16::from(b'A')..=u16::from(b'Z')).contains(&fold(unit)))
    {
        let blank = text.iter().position(|&unit| crate::is_blank(unit))?;
        text = trim_blanks(&text[blank..]);
    }
    let mut parts = [0; 3];
    if numbers(text, b"-/.", &mut parts)? != 3 {
        return None;
    }
    let [month, day, mut year] = parts;
    let year_digits = text.len()
        - text
            .iter()
            .rposition(|&unit| !(u16::from(b'0')..=u16::from(b'9')).contains(&unit))?
        - 1;
    if year_digits <= 2 {
        year += if year >= 80 { 1900 } else { 2000 };
    }
    let valid = (1980..=2099).contains(&year)
        && (1..=12).contains(&month)
        && (1..=days_in(month, year)).contains(&day);
    valid.then_some((year as u16, month as u16, day as u16))
}

/// A time typed as `h[:m[:s[.cc]]]`, the parts missing 0, an `a` or `p` (`am`, `pm`, in either
/// case) after it for a 12-hour clock: its hour, minute, second and hundredths. None for anything
/// else.
pub fn parse_time(text: &[u16]) -> Option<(u16, u16, u16, u16)> {
    let text = trim_blanks(text);
    let digits_end = text
        .iter()
        .rposition(|&unit| (u16::from(b'0')..=u16::from(b'9')).contains(&unit))?
        + 1;
    let (clock, suffix) = text.split_at(digits_end);
    let suffix = trim_blanks(suffix);
    let half = if suffix.is_empty() {
        None
    } else if is_named(suffix, "a") || is_named(suffix, "am") {
        Some(false)
    } else if is_named(suffix, "p") || is_named(suffix, "pm") {
        Some(true)
    } else {
        return None;
    };
    let mut parts = [0; 4];
    let count = numbers(clock, b":.,", &mut parts)?;
    // The hundredths come after a `.` or `,`, the other parts after a `:`.
    let colons = clock
        .iter()
        .filter(|&&unit| unit == u16::from(b':'))
        .count();
    if count == 4 && colons != 2 || count < 4 && colons != count - 1 {
        return None;
    }
    let [mut hour, minute, second, hundredths] = parts;
    match half {
        Some(pm) => {
            if !(1..=12).contains(&hour) {
                return None;
            }
            hour = hour % 12 + if pm { 12 } else { 0 };
        }
        None if hour > 23 => return None,
        None => {}
    }
    if minute > 59 || second > 59 || hundredths > 99 {
        return None;
    }
    Some((hour as u16, minute as u16, second as u16, hundredths as u16))
}

/// The units the directories `pushd` saves hold together, and how many it saves at most.
pub const SAVED_UNITS: usize = 4096;
pub const SAVED: usize = 64;

/// The directories `pushd` saved, the last first out (`popd`).
pub struct Directories {
    units: [u16; SAVED_UNITS],
    /// Where each directory ends in `units`, the first saved first.
    ends: [u16; SAVED],
    count: usize,
}

impl Default for Directories {
    fn default() -> Self {
        Directories {
            units: [0; SAVED_UNITS],
            ends: [0; SAVED],
            count: 0,
        }
    }
}

/// `pushd` could not save another directory.
#[derive(Debug, PartialEq, Eq)]
pub struct Full;

impl Directories {
    /// How many directories are saved: the prompt's `$+` shows a `+` for each.
    pub fn depth(&self) -> usize {
        self.count
    }

    fn start(&self, index: usize) -> usize {
        index
            .checked_sub(1)
            .map_or(0, |before| usize::from(self.ends[before]))
    }

    /// `directory` saved, last.
    pub fn push(&mut self, directory: &[u16]) -> Result<(), Full> {
        let start = self.start(self.count);
        let end = start + directory.len();
        if self.count == SAVED || end > SAVED_UNITS {
            return Err(Full);
        }
        self.units[start..end].copy_from_slice(directory);
        self.ends[self.count] = end as u16;
        self.count += 1;
        Ok(())
    }

    /// The directory saved last, taken out and copied to the start of `out`: its length, None
    /// when there is none (or it does not fit `out`, where it stays saved).
    pub fn pop(&mut self, out: &mut [u16]) -> Option<usize> {
        let last = self.count.checked_sub(1)?;
        let directory = &self.units[self.start(last)..usize::from(self.ends[last])];
        out.get_mut(..directory.len())?.copy_from_slice(directory);
        self.count = last;
        Some(directory.len())
    }

    /// The saved directories, the last saved first.
    pub fn iter(&self) -> impl Iterator<Item = &[u16]> {
        (0..self.count)
            .rev()
            .map(|index| &self.units[self.start(index)..usize::from(self.ends[index])])
    }
}

/// What `pushd` alone prints for each saved directory: its path, then CR LF.
pub struct Saved<'a>(pub &'a [u16]);

impl fmt::Display for Saved<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}\r\n", Text(self.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().collect()
    }

    #[test]
    fn colours() {
        assert_eq!(colour(&wide("")), Colour::Reset);
        assert_eq!(colour(&wide("  ")), Colour::Reset);
        assert_eq!(colour(&wide("1e")), Colour::Set(0x1E));
        assert_eq!(colour(&wide(" FC ")), Colour::Set(0xFC));
        assert_eq!(colour(&wide("a")), Colour::Set(0x0A));
        assert_eq!(colour(&wide("77")), Colour::Same);
        assert_eq!(colour(&wide("0")), Colour::Same);
        assert_eq!(colour(&wide("xy")), Colour::Invalid);
        assert_eq!(colour(&wide("123")), Colour::Invalid);
    }

    #[test]
    fn date_and_time_forms() {
        assert_eq!(clocked(&wide("/t")), Clocked::Show);
        assert_eq!(clocked(&wide(" /T ")), Clocked::Show);
        assert_eq!(clocked(&wide("")), Clocked::Set(None));
        let value = wide("11-04-26");
        assert_eq!(clocked(&wide("11-04-26 ")), Clocked::Set(Some(&value)));
    }

    fn time(hour: u16, minute: u16) -> Time {
        Time {
            year: 2026,
            month: 11,
            weekday: 3,
            day: 4,
            hour,
            minute,
            second: 5,
            milliseconds: 120,
        }
    }

    #[test]
    fn date_and_time_shown() {
        assert_eq!(ShortDate(&time(9, 5)).to_string(), "Wed 11/04/2026 \r\n");
        assert_eq!(ShortTime(&time(18, 31)).to_string(), "06:31 PM\r\n");
        assert_eq!(ShortTime(&time(0, 5)).to_string(), "12:05 AM\r\n");
        assert_eq!(ShortTime(&time(12, 0)).to_string(), "12:00 PM\r\n");
        assert_eq!(ShortTime(&time(9, 59)).to_string(), "09:59 AM\r\n");
        assert_eq!(
            CurrentDate(&time(9, 5)).to_string(),
            "The current date is: Wed 11/04/2026\r\n"
        );
        assert_eq!(
            CurrentTime(&time(9, 5)).to_string(),
            "The current time is:  9:05:05.12\r\n"
        );
    }

    #[test]
    fn dates_typed() {
        assert_eq!(parse_date(&wide("11-04-26")), Some((2026, 11, 4)));
        assert_eq!(parse_date(&wide("11/04/2026")), Some((2026, 11, 4)));
        assert_eq!(parse_date(&wide("1.2.85")), Some((1985, 1, 2)));
        assert_eq!(parse_date(&wide("Wed 11/04/2026")), Some((2026, 11, 4)));
        assert_eq!(parse_date(&wide("02-29-2024")), Some((2024, 2, 29)));
        assert_eq!(parse_date(&wide("02-29-2025")), None);
        assert_eq!(parse_date(&wide("13-01-2026")), None);
        assert_eq!(parse_date(&wide("01-01-1979")), None);
        assert_eq!(parse_date(&wide("01-01-2100")), None);
        assert_eq!(parse_date(&wide("11-04")), None);
        assert_eq!(parse_date(&wide("x")), None);
        assert_eq!(parse_date(&wide("11--04")), None);
    }

    #[test]
    fn times_typed() {
        assert_eq!(parse_time(&wide("13:45")), Some((13, 45, 0, 0)));
        assert_eq!(parse_time(&wide("9")), Some((9, 0, 0, 0)));
        assert_eq!(parse_time(&wide("23:59:58.99")), Some((23, 59, 58, 99)));
        assert_eq!(parse_time(&wide("1:02:03,04")), Some((1, 2, 3, 4)));
        assert_eq!(parse_time(&wide("2:30p")), Some((14, 30, 0, 0)));
        assert_eq!(parse_time(&wide("12:00 AM")), Some((0, 0, 0, 0)));
        assert_eq!(parse_time(&wide("12:00pm")), Some((12, 0, 0, 0)));
        assert_eq!(parse_time(&wide("24:00")), None);
        assert_eq!(parse_time(&wide("13:00p")), None);
        assert_eq!(parse_time(&wide("10:60")), None);
        assert_eq!(parse_time(&wide("10.30")), None);
        assert_eq!(parse_time(&wide("10:30x")), None);
        assert_eq!(parse_time(&wide("")), None);
    }

    #[test]
    fn directories_saved_last_out_first() {
        let mut saved = Directories::default();
        let mut out = [0; 16];
        assert_eq!(saved.pop(&mut out), None);
        saved.push(&wide("C:\\")).unwrap();
        saved.push(&wide("C:\\WINNT")).unwrap();
        assert_eq!(saved.depth(), 2);
        assert_eq!(
            saved.iter().map(<[u16]>::to_vec).collect::<Vec<_>>(),
            [wide("C:\\WINNT"), wide("C:\\")]
        );
        assert_eq!(saved.pop(&mut out[..3]), None);
        assert_eq!(saved.depth(), 2);
        assert_eq!(saved.pop(&mut out), Some(8));
        assert_eq!(&out[..8], &wide("C:\\WINNT")[..]);
        assert_eq!(saved.pop(&mut out), Some(3));
        assert_eq!(saved.depth(), 0);
    }

    #[test]
    fn directories_fill_up() {
        let mut saved = Directories::default();
        for _ in 0..SAVED {
            saved.push(&wide("C:\\")).unwrap();
        }
        assert_eq!(saved.push(&wide("C:\\")), Err(Full));
        let mut saved = Directories::default();
        assert_eq!(saved.push(&vec![0; SAVED_UNITS + 1]), Err(Full));
        assert_eq!(Saved(&wide("C:\\x")).to_string(), "C:\\x\r\n");
    }
}
