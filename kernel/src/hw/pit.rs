//! 8254 interval timer: channel 0 drives the interval-clock interrupt.
//!
//! Channel 0 is programmed once, at boot, in mode 3 (square wave) with a two-byte divisor; the
//! output gate feeds the timer line and the device reloads itself, so the interrupt service never
//! touches the chip. The divisor is the corpus-captured platform value — the interval a real
//! machine of this family reports as its default time increment.

use crate::hw::portio::Io;

/// The gate frequency the counter divides: 1.193182 MHz.
pub const INPUT_FREQUENCY_HZ: u32 = 1_193_182;

/// Channel 0 data port and the control register.
const CHANNEL0: u16 = 0x40;
const CONTROL: u16 = 0x43;

/// Channel 0, read/write both bytes, mode 3, binary count.
pub const MODE3_LO_HIBYTE: u8 = 0x36;

/// The read-back command for channel 0's status alone (its count not latched).
#[cfg(any(test, feature = "irq-smoke"))]
const READ_BACK_STATUS_CHANNEL0: u8 = 0xE2;

/// The corpus-captured interval divisor: 11949 gate periods = 10.0144 ms, the platform's default
/// tick.
pub const INTERVAL_DIVISOR: u16 = 11_949;

/// The same interval expressed in 100 ns units, the quantity the clock keeps as its time increment.
pub const INTERVAL_100NS: u32 = 100_144;

/// The divisor whose period rounds to `interval_100ns` units of 100 ns. The clock's rate lives in
/// these numbers; the interrupt service stays rate-agnostic.
pub fn divisor_for_100ns(interval_100ns: u32) -> u16 {
    let periods = (interval_100ns as u64 * INPUT_FREQUENCY_HZ as u64 + 5_000_000) / 10_000_000;
    periods as u16
}

/// Program channel 0 with `divisor` (mode 3, both bytes).
pub fn program_interval<IoT: Io>(io: &mut IoT, divisor: u16) {
    io.out(CONTROL, MODE3_LO_HIBYTE);
    io.out(CHANNEL0, (divisor & 0xFF) as u8);
    io.out(CHANNEL0, (divisor >> 8) as u8);
}

/// A channel's programming, as its control word sets it and its read-back status reports it (the
/// low six bits share one layout: access mode, operating mode, BCD).
#[cfg(any(test, feature = "irq-smoke"))]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Programming {
    /// The operating mode, 0-5 (the chip's 6 and 7 are aliases of 2 and 3).
    pub mode: u8,
    /// The access mode: 1 low byte, 2 high byte, 3 low then high byte (0 is the latch command).
    pub access: u8,
    /// A BCD count rather than binary.
    pub bcd: bool,
}

#[cfg(any(test, feature = "irq-smoke"))]
impl Programming {
    /// Decode a control word or a read-back status byte.
    pub fn decode(byte: u8) -> Self {
        let mode = (byte >> 1) & 7;
        Programming {
            mode: if mode >= 6 { mode - 4 } else { mode },
            access: (byte >> 4) & 3,
            bcd: byte & 1 != 0,
        }
    }

    /// The access mode's name.
    pub fn access_name(&self) -> &'static str {
        match self.access {
            0 => "latch",
            1 => "lobyte",
            2 => "hibyte",
            _ => "lobyte/hibyte",
        }
    }
}

/// Channel 0's status, through the read-back command (the irq-smoke diagnostic's).
#[cfg(any(test, feature = "irq-smoke"))]
pub fn read_back_status<IoT: Io>(io: &mut IoT) -> u8 {
    io.out(CONTROL, READ_BACK_STATUS_CHANNEL0);
    io.read(CHANNEL0)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Log {
        writes: Vec<(u16, u8)>,
    }

    impl Io for Log {
        fn out(&mut self, port: u16, byte: u8) {
            self.writes.push((port, byte));
        }

        fn read(&mut self, _port: u16) -> u8 {
            0
        }

        fn read_word(&mut self, _port: u16) -> u16 {
            0
        }
    }

    /// The programming sequence: the mode word, then the divisor low byte, then the high byte, all
    /// on channel 0.
    #[test]
    fn program_interval_writes_mode_then_both_divisor_bytes() {
        let mut log = Log { writes: Vec::new() };
        program_interval(&mut log, INTERVAL_DIVISOR);
        assert_eq!(
            log.writes,
            vec![(CONTROL, 0x36), (CHANNEL0, 0xAD), (CHANNEL0, 0x2E)]
        );
    }

    /// The captured interval round-trips: the platform's 100144-unit time increment resolves to
    /// divisor 11949, whose period rounds back to 100144 units.
    #[test]
    fn the_captured_increment_round_trips_through_the_divisor() {
        assert_eq!(INTERVAL_DIVISOR, 11_949);
        assert_eq!(INTERVAL_100NS, 100_144);
        assert_eq!(divisor_for_100ns(INTERVAL_100NS), INTERVAL_DIVISOR);

        // The period of the captured divisor, rounded to 100 ns units, is the captured increment.
        let period_100ns = (INTERVAL_DIVISOR as u64 * 10_000_000 + INPUT_FREQUENCY_HZ as u64 / 2)
            / INPUT_FREQUENCY_HZ as u64;
        assert_eq!(period_100ns as u32, INTERVAL_100NS);
    }

    /// The control word decodes to the programming the read-back reports: mode 3, both bytes,
    /// binary; a status byte's output and null-count bits and the mode alias leave it unchanged.
    #[test]
    fn the_control_word_and_the_read_back_status_decode_alike() {
        let programmed = Programming::decode(MODE3_LO_HIBYTE);
        assert_eq!(
            programmed,
            Programming {
                mode: 3,
                access: 3,
                bcd: false
            }
        );
        assert_eq!(programmed.access_name(), "lobyte/hibyte");
        assert_eq!(Programming::decode(0x80 | 0x40 | 0x36), programmed);
        assert_eq!(Programming::decode(0x3E), programmed); // mode 7, the alias of 3
        assert_eq!(
            Programming::decode(0x15),
            Programming {
                mode: 2,
                access: 1,
                bcd: true
            }
        );
    }

    /// The read-back: the status command on the control port, then the status from channel 0.
    #[test]
    fn read_back_sends_the_status_command_then_reads_channel_0() {
        let mut log = Log { writes: Vec::new() };
        read_back_status(&mut log);
        assert_eq!(log.writes, vec![(CONTROL, 0xE2)]);
    }

    /// The rate is real: the divisor halves would have to be a two-digit number of milliseconds per
    /// tick, not microseconds.
    #[test]
    fn the_captured_rate_is_in_the_ten_millisecond_band() {
        let hz = INPUT_FREQUENCY_HZ as f64 / INTERVAL_DIVISOR as f64;
        assert!(hz > 99.0 && hz < 101.0, "tick rate {hz} is not ~100 Hz");
    }
}
