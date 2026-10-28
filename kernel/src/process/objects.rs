//! The process's own synchronization records that are not objects: the user-APC records
//! QueueUserAPC queues. The records themselves are the dispatcher database's (its APC queues link
//! them by name), each process its own share of them at its record's index. The handle-named
//! objects — events, semaphores, mutexes, timers, threads, mappings, the process itself — and
//! their names are the object manager's ([`crate::ob`]).

use crate::sched::apc::Apc;
use crate::sched::database::USER_APCS;

/// The process's share of the user-APC records: [`USER_APCS`] of them, from `base` on.
pub struct SyncObjects {
    base: u16,
}

impl SyncObjects {
    /// The share of the process record at pool index 0 (the tests build processes this way).
    #[cfg(test)]
    pub const fn empty() -> Self {
        SyncObjects { base: 0 }
    }

    /// Write the share of the process record at pool index `index` at `objects`.
    ///
    /// # Safety
    ///
    /// `objects` is valid for writes and aligned; its previous contents are overwritten, not
    /// dropped.
    pub unsafe fn write_empty(objects: *mut SyncObjects, index: u16) {
        let base = index * USER_APCS as u16;
        // SAFETY: the caller's contract.
        unsafe { objects.write(SyncObjects { base }) };
    }

    /// A user-APC record of the process's that is in no queue, or none (every record is queued).
    pub fn free_apc(&mut self) -> Option<&'static mut Apc> {
        let dispatcher = crate::sched::idle::dispatcher();
        let index = (self.base..self.base + USER_APCS as u16)
            .find(|&index| !dispatcher.user_apc_mut(index).inserted())?;
        Some(dispatcher.user_apc_mut(index))
    }
}
