//! The IDE (ATA) disk controller: the primary channel's master disk, LBA28 PIO reads driven by
//! IRQ 14.
//!
//! The register machine — the port layout, the task-file packing, the IDENTIFY decode, the
//! interrupt latch the service routine fills, and the per-command protocol — is generic over
//! [`Io`] and a [`Completion`] wait, so the host tests run it against a simulated channel. The
//! kernel wiring (the interrupt object, the deferred completion, the event the caller blocks on,
//! and the block-read API) is [`disk`].
//!
//! The interrupt discipline: writing the command register deasserts INTRQ, reading the status
//! register acknowledges it, and reading the alternate status does not. The driver therefore polls
//! only the alternate status, so a poll can never swallow an interrupt; the service routine's one
//! status read is the acknowledgment. A data-in command interrupts once per sector, when that
//! sector's data is ready: draining a sector's last word starts the next. The last drain raises
//! nothing, so the caller ends a command with one status read of its own, which also clears an
//! interrupt a device might still hold.
//!
//! [`Io`]: crate::hw::portio::Io

mod channel;
pub mod disk;
mod identify;
mod latch;
mod read;
mod write;
mod regs;
#[cfg(test)]
mod sim;
#[cfg(any(test, feature = "disk-smoke"))]
pub mod smoke;
mod taskfile;
