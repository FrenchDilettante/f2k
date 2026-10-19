//! The process's own synchronization records that are not objects: the user-APC records
//! QueueUserAPC queues. The handle-named objects themselves — events, semaphores, mutexes, timers,
//! threads, mappings, the process itself — and their names are the object manager's
//! ([`crate::ob`]).

use crate::sched::apc::Apc;

/// How many user APCs can be queued at once, across the process's threads.
pub const USER_APCS: usize = 64;

/// The records themselves.
pub struct SyncObjects {
    apcs: [Apc; USER_APCS],
}

impl SyncObjects {
    /// Fresh records, by value (the tests build processes this way).
    #[cfg(test)]
    pub const fn empty() -> Self {
        SyncObjects {
            apcs: [const { Apc::detached() }; USER_APCS],
        }
    }

    /// Write fresh records at `objects`, element by element (by value they would pass through the
    /// caller's stack).
    ///
    /// # Safety
    ///
    /// `objects` is valid for writes, aligned, and the records' final address; its previous
    /// contents are overwritten, not dropped.
    pub unsafe fn write_empty(objects: *mut SyncObjects) {
        use core::ptr::addr_of_mut;
        // SAFETY: the caller's contract; every field is written.
        unsafe {
            let apcs = addr_of_mut!((*objects).apcs) as *mut Apc;
            for index in 0..USER_APCS {
                apcs.add(index).write(Apc::detached());
            }
        }
    }

    /// A user-APC record that is in no queue, or none (every record is queued).
    pub fn free_apc(&mut self) -> Option<&mut Apc> {
        self.apcs.iter_mut().find(|apc| !apc.inserted())
    }
}
