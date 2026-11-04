//! The console and clock built-ins run: `pushd` and `popd`, `title`, `color`, `date`, `time` and
//! `pause`.

use core::sync::atomic::{AtomicU32, Ordering};

use cmd::builtins::console::{self as rules, Clocked, Colour, Saved};
use exe::MAX_PATH;

use super::report;

/// `pushd`: the current directory saved, then the current directory changed to `path` (its quotes
/// dropped); without a path, the saved directories printed, the last saved first. A directory
/// that cannot be changed to prints that the path cannot be found, and fails the command.
#[inline(never)]
pub fn push_directory(path: &[u16], state: &mut cmd::State) {
    if path.is_empty() {
        let mut out = exe::stdout();
        for directory in state.directories.iter() {
            let _ = core::fmt::Write::write_fmt(&mut out, format_args!("{}", Saved(directory)));
        }
        let _ = out.flush();
        return;
    }
    let mut target = [0; MAX_PATH];
    let Some(target) = cmd::program_name(path, &mut target) else {
        let _ = exe::stderr().print(format_args!("{}", cmd::PATH_NOT_FOUND));
        return state.failed();
    };
    let mut current = [0; MAX_PATH];
    let current = match exe::current_directory(&mut current) {
        Ok(current) => current,
        Err(error) => {
            report(error);
            return state.failed();
        }
    };
    if exe::set_current_directory(target).is_err() {
        let _ = exe::stderr().print(format_args!("{}", cmd::PATH_NOT_FOUND));
        return state.failed();
    }
    if state.directories.push(current).is_err() {
        // No room to save it: back where it was, as if nothing happened.
        let _ = exe::set_current_directory(current);
        // ERROR_NOT_ENOUGH_MEMORY's text.
        let _ = exe::stderr().print(format_args!(
            "Not enough storage is available to process this command.\r\n"
        ));
        state.failed();
    }
}

/// `popd`: the current directory changed back to the directory `pushd` saved last, which is
/// forgotten. Nothing saved, nothing done. A directory that cannot be changed to prints that the
/// path cannot be found, and fails the command.
#[inline(never)]
pub fn pop_directory(state: &mut cmd::State) {
    let mut directory = [0; MAX_PATH];
    let Some(length) = state.directories.pop(&mut directory) else {
        return;
    };
    if exe::set_current_directory(&directory[..length]).is_err() {
        let _ = exe::stderr().print(format_args!("{}", cmd::PATH_NOT_FOUND));
        state.failed();
    }
}

/// `title`: the console window's title set to `title`, as typed. It never fails: a console that
/// takes no title keeps its own.
pub fn title(title: &[u16]) {
    let _ = exe::set_title(title);
}

/// The attribute the screen had before the first `color` changed it, which `color` alone puts
/// back; u32::MAX until then.
static FIRST_COLOURS: AtomicU32 = AtomicU32::new(u32::MAX);

/// `color`: the whole screen buffer, and what is written from now on, coloured as the argument
/// says (see [`rules::colour`]): alone, back to the colours the screen had before the first
/// `color`. The same colour for both fails the command, with no message; an argument that is no
/// colour prints the syntax's message and fails it. A standard output that is no console is left
/// as it is.
#[inline(never)]
pub fn colour(argument: &[u16], state: &mut cmd::State) {
    let attribute = match rules::colour(argument) {
        Colour::Set(attribute) => attribute,
        Colour::Reset => match FIRST_COLOURS.load(Ordering::Relaxed) {
            u32::MAX => return,
            first => first as u16,
        },
        Colour::Same => return state.failed(),
        Colour::Invalid => {
            let _ = exe::stderr().print(format_args!("{}", cmd::SYNTAX));
            return state.failed();
        }
    };
    if FIRST_COLOURS.load(Ordering::Relaxed) == u32::MAX {
        if let Ok(Some(first)) = exe::screen_attribute() {
            FIRST_COLOURS.store(u32::from(first), Ordering::Relaxed);
        }
    }
    if let Err(error) = exe::colour_screen(attribute) {
        report(error);
        state.failed();
    }
}

/// The local time, as the shell's formats take it.
fn now() -> cmd::Time {
    let time = exe::local_time();
    cmd::Time {
        year: time.year,
        month: time.month,
        weekday: time.day_of_week,
        day: time.day,
        hour: time.hour,
        minute: time.minute,
        second: time.second,
        milliseconds: time.milliseconds,
    }
}

/// `date`: with `/T`, the date printed; otherwise the date set to the value given, or, without
/// one, to a value asked for after the current date is shown (an empty line keeps it). A value
/// that is no date, or that cannot be set, is refused, and asked for again.
#[inline(never)]
pub fn date(argument: &[u16], state: &mut cmd::State) {
    set_clock(argument, state, &DATE);
}

/// `time`: as `date`, for the time of day.
#[inline(never)]
pub fn time(argument: &[u16], state: &mut cmd::State) {
    set_clock(argument, state, &TIME);
}

/// What tells `date` from `time`.
struct Clock {
    /// What `/T` prints.
    show: fn(&cmd::Time, &mut exe::Writer<exe::Stream>),
    /// What comes before the first question.
    current: fn(&cmd::Time, &mut exe::Writer<exe::Stream>),
    /// The question.
    question: &'static str,
    /// What a value refused prints.
    refused: &'static str,
    /// The local time with the value typed in it: None for a value that is none.
    set: fn(&[u16], exe::SystemTime) -> Option<exe::SystemTime>,
}

const DATE: Clock = Clock {
    show: |time, out| {
        let _ = out.print(format_args!("{}", rules::ShortDate(time)));
    },
    current: |time, out| {
        let _ = out.print(format_args!("{}", rules::CurrentDate(time)));
    },
    question: rules::ENTER_DATE,
    refused: rules::BAD_DATE,
    set: |text, mut local| {
        let (year, month, day) = rules::parse_date(text)?;
        local.year = year;
        local.month = month;
        local.day = day;
        Some(local)
    },
};

const TIME: Clock = Clock {
    show: |time, out| {
        let _ = out.print(format_args!("{}", rules::ShortTime(time)));
    },
    current: |time, out| {
        let _ = out.print(format_args!("{}", rules::CurrentTime(time)));
    },
    question: rules::ENTER_TIME,
    refused: rules::BAD_TIME,
    set: |text, mut local| {
        let (hour, minute, second, hundredths) = rules::parse_time(text)?;
        local.hour = hour;
        local.minute = minute;
        local.second = second;
        local.milliseconds = hundredths * 10;
        Some(local)
    },
};

/// `date` or `time` (see [`date`]).
fn set_clock(argument: &[u16], state: &mut cmd::State, clock: &Clock) {
    match rules::clocked(argument) {
        Clocked::Show => return (clock.show)(&now(), &mut exe::stdout()),
        Clocked::Set(Some(value)) => {
            if set_to(value, clock) {
                return;
            }
        }
        Clocked::Set(None) => (clock.current)(&now(), &mut exe::stdout()),
    }
    let mut line = [0; cmd::LINE];
    loop {
        let _ = exe::stdout().print(format_args!("{}", clock.question));
        let read = match exe::read_line(&mut line) {
            Ok(exe::Input::Line(read)) => cmd::trim(read),
            Ok(exe::Input::Aborted) => {
                let _ = exe::stdout().print(format_args!("\r\n"));
                return;
            }
            Ok(exe::Input::End) => return,
            Err(error) => {
                report(error);
                return state.failed();
            }
        };
        if read.is_empty() || set_to(read, clock) {
            return;
        }
    }
}

/// The clock set to `value`: whether it was; a value refused prints so.
fn set_to(value: &[u16], clock: &Clock) -> bool {
    let set = (clock.set)(value, exe::local_time())
        .is_some_and(|local| exe::set_local_time(&local).is_ok());
    if !set {
        let _ = exe::stderr().print(format_args!("{}", clock.refused));
    }
    set
}

/// `pause`: `Press any key to continue . . . `, one key waited for, then a line break.
#[inline(never)]
pub fn pause() {
    let _ = exe::stdout().print(format_args!("{}", rules::PRESS_ANY_KEY));
    let _ = exe::read_key();
    let _ = exe::stdout().print(format_args!("\r\n"));
}
