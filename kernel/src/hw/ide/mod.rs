//! The IDE (ATA) disk controller: the primary channel's master disk, LBA28 reads and writes driven
//! by IRQ 14 — by the controller's bus master (DMA) where it has one, else by PIO — and the write
//! cache's flush.
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
//! status read is the acknowledgment. A data-in command interrupts once per DRQ block (a sector,
//! or the SET MULTIPLE count under READ MULTIPLE), when that block's data is ready: draining a
//! block's last word starts the next. The last drain raises nothing, so the caller ends a command
//! with one status read of its own, which also clears an interrupt a device might still hold. A DMA
//! command interrupts once, when the bus master has moved all its sectors ([`busmaster`]).
//!
//! [`Io`]: crate::hal::Io

pub mod busmaster;
mod channel;
pub mod disk;
mod flush;
mod identify;
mod latch;
mod read;
mod regs;
#[cfg(test)]
mod sim;
#[cfg(any(test, feature = "disk-smoke"))]
pub mod smoke;
mod taskfile;
mod write;
