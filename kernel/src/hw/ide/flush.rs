//! The cache flush: the drive's write cache written out to the medium, by the command IDENTIFY
//! named (FLUSH CACHE, or FLUSH CACHE EXT on a drive of the 48-bit address feature set), before
//! the machine halts or restarts. A drive that caches writes may otherwise hold the last of them,
//! the volume's clean mark among them, when its power goes.

use super::channel::Channel;
use super::latch::{Completion, Latch};
use super::regs::FLUSH_WAITS;
use super::taskfile::TaskFile;
use crate::hal::Io;
use crate::status::NtStatus;

/// Flush the drive's write cache with `command` (FLUSH CACHE or FLUSH CACHE EXT), a non-data
/// command: the master selected, no parameters, up to [`FLUSH_WAITS`] completion waits. Returns an
/// NT status: success, timeout, or device error (the drive reports a sector it could not write
/// with ERR).
#[must_use]
pub fn flush<IoT: Io, C: Completion<IoT>>(
    channel: &mut Channel<IoT>,
    latch: &Latch,
    completion: &mut C,
    command: u8,
) -> NtStatus {
    channel.non_data(latch, completion, TaskFile::master(), command, FLUSH_WAITS)
}

#[cfg(test)]
mod tests {
    use super::super::regs::{
        ABRT,
        COMMAND,
        DEVICE,
        ERROR,
        FLUSH_CACHE,
        FLUSH_CACHE_EXT,
        PRIMARY_BASE,
        SECTOR_SIZE,
    };
    use super::super::sim::{ready, status_reads, writes, Access, Deliver, SimChannel, DISK};
    use super::super::write::write;
    use super::*;
    use crate::status::{STATUS_IO_DEVICE_ERROR, STATUS_IO_TIMEOUT, STATUS_SUCCESS};

    /// FLUSH CACHE: the master selected, the command written, one interrupt when the drive is
    /// done; the line ends acknowledged, and the drive takes the next command.
    #[test]
    fn a_flush_completes_with_one_interrupt() {
        let mut channel = ready();
        channel.io().log.clear();
        let latch = Latch::new();
        let mut deliver = Deliver { delivered: 0 };
        assert_eq!(
            flush(&mut channel, &latch, &mut deliver, FLUSH_CACHE),
            STATUS_SUCCESS
        );
        assert_eq!(channel.io().flushes, 1);
        assert_eq!(channel.io().commands(), [FLUSH_CACHE]);
        let written = writes(&mut channel);
        assert_eq!(
            &written[written.len() - 2..],
            [
                (PRIMARY_BASE + DEVICE, 0xE0),
                (PRIMARY_BASE + COMMAND, FLUSH_CACHE)
            ]
        );
        assert_eq!(deliver.delivered, 1);
        assert_eq!(status_reads(&mut channel), 1, "the service routine's alone");
        assert!(!channel.io().line());
        assert_eq!(latch.unsolicited(), 0);
        let buffer = vec![0u8; SECTOR_SIZE];
        assert_eq!(
            write(&mut channel, &latch, &mut deliver, DISK, 3, &buffer),
            STATUS_SUCCESS
        );
    }

    /// FLUSH CACHE EXT goes the same way.
    #[test]
    fn a_flush_cache_ext_completes_the_same_way() {
        let mut channel = ready();
        let latch = Latch::new();
        assert_eq!(
            flush(
                &mut channel,
                &latch,
                &mut Deliver { delivered: 0 },
                FLUSH_CACHE_EXT
            ),
            STATUS_SUCCESS
        );
        assert_eq!(channel.io().commands(), [FLUSH_CACHE_EXT]);
        assert_eq!(channel.io().flushes, 1);
    }

    /// A drive slow to write its cache out: the completion waits that give up are waited on,
    /// within the bound, for the same interrupt.
    #[test]
    fn a_slow_flush_is_waited_for() {
        let mut channel = ready();
        let latch = Latch::new();
        let mut slow = Slow {
            empty: FLUSH_WAITS - 1,
            deliver: Deliver { delivered: 0 },
        };
        assert_eq!(
            flush(&mut channel, &latch, &mut slow, FLUSH_CACHE),
            STATUS_SUCCESS
        );
        assert_eq!(slow.deliver.delivered, 1);
        assert_eq!(channel.io().flushes, 1);
    }

    /// A drive that never reports the flush done: a timeout once every wait has given up, the
    /// latch disarmed.
    #[test]
    fn a_flush_never_done_times_out() {
        let mut channel = ready();
        let latch = Latch::new();
        let mut slow = Slow {
            empty: FLUSH_WAITS,
            deliver: Deliver { delivered: 0 },
        };
        assert_eq!(
            flush(&mut channel, &latch, &mut slow, FLUSH_CACHE),
            STATUS_IO_TIMEOUT
        );
        assert_eq!(slow.deliver.delivered, 0);
        assert!(latch.fired(), "disarmed");
    }

    /// A drive that cannot write its cache out ends the command with ERR: the error register is
    /// read, and the flush is a device error.
    #[test]
    fn a_failed_flush_is_a_device_error() {
        let mut sim = SimChannel::with_disk(DISK);
        sim.flush_fails = true;
        let mut channel = super::super::sim::sim_channel(sim);
        channel.enable_interrupt();
        let latch = Latch::new();
        assert_eq!(
            flush(
                &mut channel,
                &latch,
                &mut Deliver { delivered: 0 },
                FLUSH_CACHE
            ),
            STATUS_IO_DEVICE_ERROR
        );
        assert!(channel
            .io()
            .log
            .contains(&Access::Read(PRIMARY_BASE + ERROR, ABRT)));
        assert_eq!(channel.io().flushes, 0);
        assert!(!channel.io().line());
    }

    /// A completion that gives up `empty` times, as a wait that times out before the drive is
    /// done, then delivers the interrupt.
    struct Slow {
        empty: u32,
        deliver: Deliver,
    }

    impl Completion<SimChannel> for Slow {
        fn wait(&mut self, io: &mut SimChannel, latch: &Latch) -> bool {
            if self.empty > 0 {
                self.empty -= 1;
                return false;
            }
            self.deliver.wait(io, latch)
        }
    }
}
