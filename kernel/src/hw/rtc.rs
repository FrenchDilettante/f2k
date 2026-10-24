//! The CMOS real-time clock: the wall-clock reading the kernel takes once, at boot.
//!
//! The clock's registers sit behind the index port 0x70 and the data port 0x71: seconds, minutes,
//! hours, day of month, month, year, and (on the platform's firmware) the century at 0x32. Status
//! register B says how they are encoded — BCD or binary, a 12- or 24-hour clock (a 12-hour clock
//! carries PM in the hour's top bit). A read is only consistent outside an update cycle, so it
//! waits for status register A's update-in-progress bit to clear and repeats until two passes
//! agree.
//!
//! The platform keeps the clock in local time; with no time zone configured, local time is UTC.
//!
//! One NVRAM byte beside the clock serves the test harness ([`await_mailbox`]): a boot that pauses
//! for the harness to take a screenshot waits until the harness writes it, through QEMU's monitor.

use super::portio::Io;

const INDEX: u16 = 0x70;
const DATA: u16 = 0x71;

const SECONDS: u8 = 0x00;
const MINUTES: u8 = 0x02;
const HOURS: u8 = 0x04;
const DAY: u8 = 0x07;
const MONTH: u8 = 0x08;
const YEAR: u8 = 0x09;
const STATUS_A: u8 = 0x0A;
const STATUS_B: u8 = 0x0B;
const CENTURY: u8 = 0x32;

/// Status A: an update cycle is in progress.
const UPDATE_IN_PROGRESS: u8 = 0x80;
/// Status B: the clock counts in binary rather than BCD.
const BINARY: u8 = 0x04;
/// Status B: the hours run 0-23 rather than 1-12 with a PM bit.
const HOURS_24: u8 = 0x02;
/// The PM bit of a 12-hour clock's hour register.
const PM: u8 = 0x80;

/// A civil date and time, as the clock reports it (whole seconds).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CivilTime {
    pub year: u16,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
}

/// The raw registers of one pass.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Raw {
    seconds: u8,
    minutes: u8,
    hours: u8,
    day: u8,
    month: u8,
    year: u8,
    century: u8,
}

fn register<IoT: Io>(io: &mut IoT, index: u8) -> u8 {
    // Bit 7 of the index port is the NMI mask: kept clear.
    io.out(INDEX, index & 0x7F);
    io.read(DATA)
}

fn pass<IoT: Io>(io: &mut IoT) -> Raw {
    // Bounded: a clock that never leaves its update cycle is read anyway.
    for _ in 0..100_000 {
        if register(io, STATUS_A) & UPDATE_IN_PROGRESS == 0 {
            break;
        }
    }
    Raw {
        seconds: register(io, SECONDS),
        minutes: register(io, MINUTES),
        hours: register(io, HOURS),
        day: register(io, DAY),
        month: register(io, MONTH),
        year: register(io, YEAR),
        century: register(io, CENTURY),
    }
}

fn from_bcd(value: u8) -> u8 {
    (value >> 4) * 10 + (value & 0x0F)
}

/// Read the clock: two agreeing passes, decoded. None when the reading is not a valid date (no
/// clock, or garbage in its registers).
pub fn read<IoT: Io>(io: &mut IoT) -> Option<CivilTime> {
    let mut raw = pass(io);
    for _ in 0..8 {
        let again = pass(io);
        if again == raw {
            break;
        }
        raw = again;
    }
    decode(raw, register(io, STATUS_B))
}

/// The NVRAM byte the test harness writes to let a paused boot go on: one the platform's firmware
/// leaves alone.
pub const SCREEN_MAILBOX: u8 = 0x7F;

/// Clear the NVRAM byte at `index`, `announce` the wait, then read the byte until it is nonzero,
/// `reads` times at most: whether it was answered. Interrupts may stay masked: nothing but the
/// reads is waited on.
pub fn await_mailbox<IoT: Io>(
    io: &mut IoT,
    index: u8,
    reads: u32,
    announce: impl FnOnce(),
) -> bool {
    io.out(INDEX, index & 0x7F);
    io.out(DATA, 0);
    announce();
    (0..reads).any(|_| register(io, index) != 0)
}

fn decode(raw: Raw, status_b: u8) -> Option<CivilTime> {
    let binary = status_b & BINARY != 0;
    let value = |v: u8| if binary { v } else { from_bcd(v) };
    let pm = raw.hours & PM != 0;
    let mut hour = value(raw.hours & !PM);
    if status_b & HOURS_24 == 0 {
        // 12 AM is hour 0, 12 PM is hour 12.
        hour %= 12;
        if pm {
            hour += 12;
        }
    }
    let short_year = value(raw.year) as u16;
    let century = value(raw.century) as u16;
    let year = if (19..=21).contains(&century) {
        century * 100 + short_year
    } else if short_year < 80 {
        2000 + short_year
    } else {
        1900 + short_year
    };
    let time = CivilTime {
        year,
        month: value(raw.month),
        day: value(raw.day),
        hour,
        minute: value(raw.minutes),
        second: value(raw.seconds),
    };
    let valid = (1..=12).contains(&time.month)
        && (1..=31).contains(&time.day)
        && time.hour < 24
        && time.minute < 60
        && time.second < 60;
    valid.then_some(time)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A simulated CMOS: the register file, the index the last index write selected.
    struct Cmos {
        registers: [u8; 128],
        index: u8,
    }

    impl Io for Cmos {
        fn out(&mut self, port: u16, byte: u8) {
            if port == INDEX {
                self.index = byte;
            } else {
                assert_eq!(port, DATA);
                self.registers[self.index as usize] = byte;
            }
        }

        fn read(&mut self, port: u16) -> u8 {
            assert_eq!(port, DATA);
            self.registers[self.index as usize]
        }

        fn read_word(&mut self, _port: u16) -> u16 {
            unreachable!()
        }
    }

    fn cmos(status_b: u8, values: [(u8, u8); 7]) -> Cmos {
        let mut registers = [0u8; 128];
        registers[STATUS_B as usize] = status_b;
        for (index, value) in values {
            registers[index as usize] = value;
        }
        Cmos {
            registers,
            index: 0,
        }
    }

    /// The firmware default: BCD, 24-hour, the century register set.
    #[test]
    fn a_bcd_24_hour_clock_decodes() {
        let mut io = cmos(
            HOURS_24,
            [
                (SECONDS, 0x59),
                (MINUTES, 0x07),
                (HOURS, 0x23),
                (DAY, 0x31),
                (MONTH, 0x12),
                (YEAR, 0x26),
                (CENTURY, 0x20),
            ],
        );
        assert_eq!(
            read(&mut io),
            Some(CivilTime {
                year: 2026,
                month: 12,
                day: 31,
                hour: 23,
                minute: 7,
                second: 59
            })
        );
    }

    /// A binary 12-hour clock: 12 AM is hour 0, the PM bit adds twelve; no century register falls
    /// back on the two-digit year's window.
    #[test]
    fn a_binary_12_hour_clock_decodes() {
        let at = |hours: u8| {
            let mut io = cmos(
                BINARY,
                [
                    (SECONDS, 1),
                    (MINUTES, 2),
                    (HOURS, hours),
                    (DAY, 3),
                    (MONTH, 4),
                    (YEAR, 5),
                    (CENTURY, 0),
                ],
            );
            read(&mut io).unwrap()
        };
        assert_eq!(at(12).hour, 0);
        assert_eq!(at(12 | PM).hour, 12);
        assert_eq!(at(3 | PM).hour, 15);
        assert_eq!(at(3).year, 2005);
    }

    /// Garbage in the registers is no reading.
    #[test]
    fn an_invalid_reading_is_refused() {
        let mut io = cmos(
            HOURS_24 | BINARY,
            [
                (MONTH, 13),
                (DAY, 1),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
            ],
        );
        assert_eq!(read(&mut io), None);
    }

    /// The mailbox is cleared before the wait is announced, then read until the harness's write
    /// lands; unanswered, the wait gives up after its reads.
    #[test]
    fn the_mailbox_waits_for_its_answer() {
        let mut io = cmos(HOURS_24, [(0, 0); 7]);
        io.registers[SCREEN_MAILBOX as usize] = 9;
        let mut announced = false;
        assert!(!await_mailbox(&mut io, SCREEN_MAILBOX, 1000, || {
            announced = true
        }));
        assert!(announced);
        assert_eq!(io.registers[SCREEN_MAILBOX as usize], 0, "cleared first");
        let mut io = cmos(HOURS_24, [(0, 0); 7]);
        let answered = await_mailbox(&mut io, SCREEN_MAILBOX, 1000, || {});
        assert!(!answered);
        // The answer written between the clear and the reads: the harness's.
        struct Answering(Cmos);
        impl Io for Answering {
            fn out(&mut self, port: u16, byte: u8) {
                self.0.out(port, byte);
            }

            fn read(&mut self, port: u16) -> u8 {
                self.0.registers[SCREEN_MAILBOX as usize] = 1;
                self.0.read(port)
            }

            fn read_word(&mut self, _port: u16) -> u16 {
                unreachable!()
            }
        }
        let mut io = Answering(cmos(HOURS_24, [(0, 0); 7]));
        assert!(await_mailbox(&mut io, SCREEN_MAILBOX, 1000, || {}));
    }
}
