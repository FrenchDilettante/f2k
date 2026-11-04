//! The dispatcher's facts about its threads, read for a listing of the system's processes
//! (NtQuerySystemInformation's process information): which threads a process has, in creation
//! order. Read-only, inside a borrow of the dispatcher.

use super::dispatcher::Dispatcher;
use super::list;
use super::process::{ProcessRef, ProcessThreads, SchedProcess};
use super::thread::Thread;

/// The threads attached to the process whose scheduling record is at `process`, in creation order:
/// the records its thread list links, as long as the borrow of the dispatcher lasts.
///
/// `process` is a pinned record (a process pool's, or the idle or System process's), alive for the
/// kernel's life, as every thread's owner pointer is: the walk reads its list head through the
/// dispatcher's borrow, as [`Dispatcher::first_thread_except`] does.
pub fn threads_of<'a>(
    dispatcher: &'a Dispatcher,
    process: *mut SchedProcess,
) -> impl Iterator<Item = &'a Thread> + 'a {
    list::iter(dispatcher, ProcessThreads(ProcessRef::of(process)))
        .map(move |thread| dispatcher.thread(thread))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A process's threads come in creation order, each its own record; a process without one
    /// lists none.
    #[test]
    fn a_process_lists_its_threads_in_creation_order() {
        let dispatcher = crate::sched::testkit::dispatcher();
        let process = Box::leak(Box::new(SchedProcess::new(0x0090_0000, 8)));
        let address = process as *mut SchedProcess;
        assert_eq!(threads_of(dispatcher, address).count(), 0);
        let first = crate::sched::testkit::thread(process).id();
        let second = crate::sched::testkit::thread(process).id();
        let listed: std::vec::Vec<_> = threads_of(dispatcher, address)
            .map(|thread| thread.id())
            .collect();
        assert_eq!(listed, [first, second]);
        assert!(threads_of(dispatcher, address).all(|thread| thread.base_priority() == 8));
    }
}
