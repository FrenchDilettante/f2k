//! Typed access: a live dispatcher object's body by its name in the dispatcher database, a
//! process's ordinals, and the thread look-ups.

use super::*;
use crate::sched::mutex::MutexId;
use crate::sched::thread::ThreadId;
#[cfg(test)]
use crate::sched::timer::TimerId;
#[cfg(test)]
use crate::sched::wait::WaitableId;

impl Directory {
    // --- Typed access ------------------------------------------------------------------------

    /// The body index of the live dispatcher object `id`, when it is of `kind`.
    fn body_index(&mut self, id: ObjectId, kind: ObjectType) -> Option<u16> {
        let index = id.body_of(kind)?;
        self.is_live(id).then_some(index)
    }

    // The dispatcher objects: the body's name in the dispatcher database, for a live object of
    // the kind (the body itself is reached there, with the dispatch token).

    /// The event object's body: its waitable name.
    #[cfg(test)]
    pub fn event(&mut self, id: ObjectId) -> Option<WaitableId> {
        self.body_index(id, ObjectType::Event)
            .map(WaitableId::Event)
    }

    /// The semaphore object's body: its waitable name.
    #[cfg(test)]
    pub fn semaphore(&mut self, id: ObjectId) -> Option<WaitableId> {
        self.body_index(id, ObjectType::Semaphore)
            .map(WaitableId::Semaphore)
    }

    /// The mutex object's body.
    pub fn mutex(&mut self, id: ObjectId) -> Option<MutexId> {
        self.body_index(id, ObjectType::Mutex).map(MutexId)
    }

    /// The waitable timer object's body.
    #[cfg(test)]
    pub fn timer(&mut self, id: ObjectId) -> Option<TimerId> {
        self.body_index(id, ObjectType::Timer)
            .map(TimerId::Waitable)
    }

    /// The thread object's record.
    pub fn thread(&mut self, id: ObjectId) -> Option<ThreadId> {
        self.body_index(id, ObjectType::Thread).map(ThreadId)
    }

    /// The process object's body: its index in the dispatcher's process-object pool.
    pub fn process(&mut self, id: ObjectId) -> Option<u16> {
        self.body_index(id, ObjectType::Process)
    }

    /// The live process object's thread ordinals.
    pub fn ordinals(&mut self, id: ObjectId) -> Option<&mut crate::process::ordinals::Ordinals> {
        let index = self.body_index(id, ObjectType::Process)?;
        Some(self.ordinals_at(index))
    }

    /// The ordinal the next created thread of the process `process` names takes (see
    /// [`crate::process::ordinals::Ordinals::free`]): its lowest one free, or held by a thread
    /// whose object is gone, else a new one. None when no page is left for a new one, or `process`
    /// names no live process.
    pub fn free_ordinal(&mut self, process: ObjectId) -> Option<u16> {
        let index = self.body_index(process, ObjectType::Process)?;
        let threads = &self.threads;
        let ordinals = self
            .ordinals
            .get_mut(index.into())
            .expect("a process's ordinals made with its object");
        ordinals.free(pages(), |thread| {
            thread.kind == ObjectType::Thread && threads.get(slot_id(thread)).is_some()
        })
    }

    /// Free the process `process`'s lowest ordinal held by a thread whose object is gone, handing
    /// back the pages its thread left mapped (see
    /// [`crate::process::ordinals::Ordinals::vacate`]); none when there is no such ordinal, or
    /// `process` names no live process.
    pub fn vacate_ordinal(
        &mut self,
        process: ObjectId,
    ) -> Option<crate::process::ordinals::Leftover> {
        let index = self.body_index(process, ObjectType::Process)?;
        let threads = &self.threads;
        let ordinals = self
            .ordinals
            .get_mut(index.into())
            .expect("a process's ordinals made with its object");
        ordinals.vacate(|thread| {
            thread.kind == ObjectType::Thread && threads.get(slot_id(thread)).is_some()
        })
    }

    /// The live process object at the lowest process pool index from `from` on, if any: a walk
    /// over every process, a step to a hold, goes from index 0 on, each step from the index after
    /// the last one found. A dying object (its last reference gone) is not live.
    pub fn next_live_process(&self, from: u16) -> Option<ObjectId> {
        self.processes
            .iter_from(from.into())
            .map(|(id, _)| object_id(ObjectType::Process, id))
            .find(|&id| self.is_live(id))
    }

    /// The process `id` names has ended with `exit_status`: its object signals, once, and its
    /// waiters wake (no boost: the end grants none).
    #[cfg(test)]
    pub fn signal_process_end(&mut self, id: ObjectId, exit_status: u32) {
        if let Some(index) = self.body_index(id, ObjectType::Process) {
            signal_process_body(index, exit_status);
        }
    }

    /// The waitable name of a live waitable object (see [`ObjectId::waitable`]); none for an
    /// object no wait can name, or a dead id.
    #[cfg(test)]
    pub fn waitable(&mut self, id: ObjectId) -> Option<WaitableId> {
        if !self.is_live(id) {
            return None;
        }
        id.waitable()
    }

    /// The thread object whose record is `thread`; none for a system thread's record (no object
    /// names one) or one holding no live object.
    pub fn thread_object(&mut self, thread: ThreadId) -> Option<ObjectId> {
        let id = self.threads.id_at(thread.index().into())?;
        let id = object_id(ObjectType::Thread, id);
        self.is_live(id).then_some(id)
    }

    /// The thread object whose client id is `thread_id`, among the threads that have not ended of
    /// the process whose scheduling record is `owner`; none when no such thread has it (a thread of
    /// another process is not the owner's).
    pub fn thread_by_client_id(
        &mut self,
        owner: *const crate::sched::process::SchedProcess,
        thread_id: u32,
    ) -> Option<ObjectId> {
        self.running_thread_by_id(thread_id, |thread| core::ptr::eq(thread.process, owner))
    }

    /// The thread object whose client id is `thread_id`, among the threads that have not ended of
    /// every process (client ids are unique across processes and threads); none when no such
    /// thread has it — as on Windows 2000, an ended thread's id names nothing any more, even while
    /// a handle holds its object.
    pub fn thread_by_id(&mut self, thread_id: u32) -> Option<ObjectId> {
        self.running_thread_by_id(thread_id, |_| true)
    }

    /// The thread object the client-id table ([`crate::process::cid`]) names by `thread_id`, when
    /// it lives, has not ended, and passes `filter`: one look-up, then the thread's state.
    fn running_thread_by_id(
        &mut self,
        thread_id: u32,
        filter: impl FnOnce(&crate::sched::thread::Thread) -> bool,
    ) -> Option<ObjectId> {
        let id = crate::process::cid::lookup(thread_id)?.thread()?;
        let record = self.thread(id)?;
        with_bodies(|bodies| {
            let thread = bodies.thread(record);
            let found = thread.thread_id() == thread_id
                && thread.state() != crate::sched::thread::ThreadState::Terminated
                && filter(thread);
            found.then_some(id)
        })
    }
}

/// Signal the process object whose body is at `index` with `exit_status`, once, waking its waiters
/// (no boost: the end grants none).
pub(super) fn signal_process_body(index: u16, exit_status: u32) {
    with_bodies(|bodies| {
        let process = bodies.process_object_mut(index);
        process.exit_status = exit_status;
        process.waitable.get_mut().signal_state = 1;
        if process.waitable.has_waiters() {
            let waitable = process.waitable.id();
            bodies.satisfy_waiters(waitable, 0);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ob::testkit::*;

    /// Two processes' threads interleave in the pool, any process's thread taking the lowest free
    /// record; a client-id lookup finds only the asking process's own threads.
    #[test]
    fn thread_lookups_by_client_id_stay_within_their_process() {
        use crate::sched::process::SchedProcess;
        let directory = directory();
        let a = Box::leak(Box::new(SchedProcess::new(
            crate::mem::phys::PhysAddr::new(0x0090_0000),
            8,
        ))) as *mut SchedProcess;
        let b = Box::leak(Box::new(SchedProcess::new(
            crate::mem::phys::PhysAddr::new(0x00A0_0000),
            8,
        ))) as *mut SchedProcess;
        // A's main thread, B's main thread, then a created thread of A's: records 3, 4, 5 (past
        // the system threads'), client ids 12, 16, 20 from the client-id table.
        let threads = [a, b, a].map(|owner| {
            let id = directory.create_thread().unwrap();
            let thread = directory.renew_thread(id);
            let client_id = crate::process::cid::reserve().unwrap();
            let mut dispatcher = dispatcher();
            let record = dispatcher.thread_mut(thread);
            record.process = owner;
            record.thread_id = client_id;
            drop(dispatcher);
            crate::process::cid::fill(client_id, crate::process::cid::Named::Object(id));
            id
        });
        assert_eq!(threads.map(|id| id.index), [3, 4, 5]);
        assert_eq!(directory.thread_by_client_id(a, 20), Some(threads[2]));
        assert_eq!(directory.thread_by_client_id(a, 12), Some(threads[0]));
        assert_eq!(directory.thread_by_client_id(b, 16), Some(threads[1]));
        assert_eq!(directory.thread_by_client_id(b, 20), None, "A's thread");
        assert_eq!(directory.thread_by_client_id(a, 16), None, "B's thread");
        assert_eq!(directory.thread_by_id(16), Some(threads[1]));
        assert_eq!(directory.thread_by_id(24), None, "no one's");

        // The thread object's deletion gives its id back, the last freed first out again.
        assert_eq!(directory.dereference(threads[1]), None);
        assert_eq!(directory.thread_by_id(16), None);
        assert_eq!(crate::process::cid::lookup(16), None);
        assert_eq!(crate::process::cid::reserve(), Some(16));
    }

    /// A walk over the processes, a step at a time, finds each live one in index order, and
    /// none whose last reference went.
    #[test]
    fn the_process_walk_steps_in_index_order() {
        let directory = directory();
        let processes: Vec<_> = (0..5)
            .map(|_| directory.create_process().unwrap())
            .collect();
        assert_eq!(directory.dereference(processes[2]), None);
        let mut walked = Vec::new();
        let mut from = 0;
        while let Some(id) = directory.next_live_process(from) {
            walked.push(id);
            from = id.index + 1;
        }
        assert_eq!(
            walked,
            [0, 1, 3, 4].map(|at| processes[at]),
            "the dead one skipped"
        );
    }

    /// A process object: waitable, still active and unsignaled until its end, signaled with its
    /// exit code at the end; the sweep leaves it to its own reference, whose
    /// release frees the record for the next process.
    #[test]
    fn a_process_object_signals_its_end() {
        let directory = directory();
        let mut dispatcher = dispatcher();
        let id = directory.create_process().unwrap();
        assert_eq!(directory.next_live_process(id.index), Some(id));
        assert_eq!(
            directory
                .process(id)
                .map(|body| dispatcher.process_object_mut(body).exit_status),
            Some(STILL_ACTIVE)
        );
        let waitable = directory.waitable(id).expect("a process is waitable");
        assert_eq!(dispatcher.waitable(waitable).signal_state(), 0);
        // A handle to it and the process's own reference.
        assert!(directory.handle_opened(id));
        assert_eq!(sweep(directory).0, 0, "a process object is no leak");
        assert!(directory.is_live(id));
        directory.signal_process_end(id, 3);
        assert_eq!(dispatcher.waitable(waitable).signal_state(), 1);
        assert_eq!(
            directory
                .process(id)
                .map(|body| dispatcher.process_object_mut(body).exit_status),
            Some(3)
        );
        assert_eq!(
            directory.dereference(id),
            None,
            "the process's own reference goes"
        );
        assert!(
            directory.is_live(id),
            "the handle still names the ended process"
        );
        assert_eq!(closed(directory, id), vec![]);
        assert_eq!(
            directory.next_live_process(id.index),
            None,
            "the record is free"
        );
        let reused = directory.create_process().unwrap();
        assert_eq!(reused.index, id.index, "the lowest free record is reused");
        assert_ne!(reused.generation, id.generation);
    }
}
