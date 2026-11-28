//! The queues' lives: made at a thread's first service, ended with it.

use super::*;
use crate::sched::thread::ThreadId;
use crate::win32k::window::{ThreadKey, Windows};

/// The thread record `thread` serves the thread `key`, whose client id is `client_id`: give it its
/// queue, at its first service, or a fresh one when the record served another thread before (that
/// thread's queue ends, see [`detach`]).
pub fn attach(windows: &mut Windows, thread: ThreadId, key: ThreadKey, client_id: u32) {
    let queues = &mut windows.queues;
    let index = thread.0;
    let queue = &queues.queues[index as usize];
    if queue.live && queue.key == Some(key) {
        return;
    }
    if queue.live {
        queues.end_queue(index);
    }
    let queue = &mut queues.queues[index as usize];
    *queue = Queue {
        live: true,
        generation: queue.generation,
        key: Some(key),
        client_id,
        ..Queue::EMPTY
    };
}

/// The thread record `thread`'s thread ended (or its process did): its queue ends with it. What
/// was posted to it goes; what was sent to it and not answered fails its sender; its timers go.
/// A record another thread takes over ends its queue through [`attach`] too.
pub fn detach(windows: &mut Windows, thread: ThreadId) {
    if windows.queues.queue_of(thread).is_some() {
        windows.queues.end_queue(thread.0);
    }
}

/// The queue of the thread whose client id is `client_id` (PostThreadMessage's), and the thread it
/// serves: the thread the client-id table names by it now. A queue whose thread and object went
/// keeps its id until its record goes (a GUI thread that ended above the passive level leaves its
/// queue to its process's reap), and the id may be another thread's by then (client ids are
/// reused, LIFO): that queue is not the id's.
pub fn queue_by_client_id(windows: &Windows, client_id: u32) -> Option<(ThreadId, ThreadKey)> {
    queue_by_client_id_in(windows, client_id, thread_named_by)
}

/// The thread the client-id table names by `client_id` now, as the window manager keys threads;
/// none for an id that names no thread object.
#[cfg(not(test))]
fn thread_named_by(client_id: u32) -> Option<Option<ThreadKey>> {
    let thread = crate::process::cid::lookup(client_id).and_then(|named| named.thread());
    Some(thread.map(|id| ThreadKey {
        index: id.index,
        generation: id.generation,
    }))
}

/// The host tests' queues carry client ids no table hands out: no check (see
/// [`queue_by_client_id_in`]'s own test for the check).
#[cfg(test)]
fn thread_named_by(_: u32) -> Option<Option<ThreadKey>> {
    None
}

/// [`queue_by_client_id`], the id's thread found by `named` (none: no check; some none: the id
/// names no thread).
fn queue_by_client_id_in(
    windows: &Windows,
    client_id: u32,
    named: impl FnOnce(u32) -> Option<Option<ThreadKey>>,
) -> Option<(ThreadId, ThreadKey)> {
    if client_id == 0 {
        return None;
    }
    let current = named(client_id);
    windows
        .queues
        .live_queues()
        .filter(|(_, q)| q.client_id == client_id)
        .filter_map(|(thread, q)| Some((thread, q.key?)))
        .find(|&(_, key)| current.is_none_or(|current| current == Some(key)))
}

/// The client id of the thread the thread record `thread` serves, as its queue keeps it; none for
/// a record with no queue (the window manager's own).
pub fn client_id_of(windows: &Windows, thread: ThreadId) -> Option<u32> {
    let queue = windows.queues.queues.get(thread.0 as usize)?;
    (queue.live && queue.client_id != 0).then_some(queue.client_id)
}

#[cfg(test)]
mod tests {
    use rtl::user::{WM_USER, WS_CHILD};

    use super::*;
    use crate::status::*;
    use crate::win32k::queue::testkit::*;

    /// A GUI thread that ended above the passive level leaves its queue, with its client id, to
    /// its process's reap; client ids are reused LIFO, so the id may name another thread first.
    /// PostThreadMessage's look-up takes the queue of the thread the client-id table names by
    /// the id now, never the ended one's, and none when the id names no thread.
    #[test]
    fn a_reused_client_id_finds_the_new_threads_queue() {
        let (m, _) = manager();
        let ended = thread(m, 1, 0x100);
        let new = thread(m, 2, 0x100);
        let key = |index| ThreadKey {
            index,
            generation: 0,
        };
        let found = |named: Option<Option<ThreadKey>>| {
            queue_by_client_id_in(&m.windows, 0x100, |id| {
                assert_eq!(id, 0x100);
                named
            })
        };
        assert_eq!(found(Some(Some(key(2)))), Some((new, key(2))));
        assert_eq!(found(Some(Some(key(1)))), Some((ended, key(1))));
        assert_eq!(found(Some(None)), None, "the id names no thread");
        assert_eq!(found(Some(Some(key(3)))), None, "another thread, no queue");
        assert_eq!(
            queue_by_client_id_in(&m.windows, 0, |_| panic!("no look-up for 0")),
            None
        );
    }

    /// A thread record's client id is its queue's (GetWindowThreadProcessId's thread id): none for
    /// the window manager's own record, which serves the desktop's windows and has no queue.
    #[test]
    fn a_window_s_thread_is_its_queue_s_client_id() {
        let (m, atom) = manager();
        let t = thread(m, 1, 0x100);
        let h = popup(m, atom, t);
        let id = m.windows.window_from_handle(h).unwrap();
        assert_eq!(
            client_id_of(&m.windows, m.windows.window_thread(id)),
            Some(0x100)
        );
        let desktop = m.windows.thread_desktop_window(t).unwrap();
        assert_eq!(
            client_id_of(&m.windows, m.windows.window_thread(desktop)),
            None
        );
    }

    /// A thread's end, as Windows 2000's thread cleanup: its windows are destroyed (a child of its
    /// window with them, another thread's own window left), its queue ends, and a send waiting on
    /// it — queued, or handed out and not answered — fails its sender (SendMessage 0, 1400) and
    /// goes back to the pool. Later sends to its window find no window. Its record stays, empty,
    /// for its process's end.
    #[test]
    fn a_threads_end_takes_its_windows_and_fails_the_sends_to_it() {
        let (m, atom) = manager();
        let a = thread(m, 1, 0x100);
        let b = thread(m, 2, 0x200);
        let ha = popup(m, atom, a);
        let hb = popup(m, atom, b);
        let child = window_at(m, atom, b, WS_CHILD, hb, 0, 0, 10, 10);
        deliver(m, a);
        deliver(m, b);
        let base = live_sends(m);
        let Ok(Sending::Waiting(handed)) = send(&mut m.windows, a, hb, WM_USER, 1, 0) else {
            panic!("queued");
        };
        let Ok(Sending::Waiting(queued)) = send(&mut m.windows, a, hb, WM_USER, 2, 0) else {
            panic!("queued");
        };
        assert!(matches!(read(m, b, &all(), 0), Taken::Sent(_)));
        m.windows.queues.take_wakes();

        let key = ThreadKey {
            index: 2,
            generation: 0,
        };
        m.end_thread(key);
        assert!(m.windows.window_from_handle(hb).is_none());
        assert!(m.windows.window_from_handle(child).is_none());
        assert!(m.windows.window_from_handle(ha).is_some());
        assert_eq!(m.windows.queues.queue_of(b), None);
        assert!(
            m.windows.queues.take_wakes().contains(a),
            "the sender is woken"
        );
        assert_eq!(await_reply(&mut m.windows, a, handed), Awaited::Failed);
        assert_eq!(await_reply(&mut m.windows, a, queued), Awaited::Failed);
        assert_eq!(live_sends(m), base);
        assert_eq!(
            send(&mut m.windows, a, hb, WM_USER, 3, 0),
            Err(STATUS_INVALID_HANDLE)
        );
        assert!(m.windows.thread(b).live && m.windows.thread(b).window_count == 0);
        m.end_thread(key);

        // A timed-out send abandoned once its receiver ended goes back to the pool too.
        let c = thread(m, 3, 0x300);
        let hc = popup(m, atom, c);
        deliver(m, c);
        let Ok(Sending::Waiting(id)) = send(&mut m.windows, a, hc, WM_USER, 4, 0) else {
            panic!("queued");
        };
        detach(&mut m.windows, c);
        abandon_send(&mut m.windows, a, id);
        assert_eq!(live_sends(m), base);
    }

    /// A process's end ends its threads' queues with their records: a send waiting on one of them
    /// fails.
    #[test]
    fn a_processs_end_ends_its_queues() {
        let (m, atom) = manager();
        register(m, OTHER_OWNER);
        let a = thread(m, 1, 0x100);
        let b = thread_of(m, 2, 0x200, OTHER_OWNER);
        let hb = popup(m, atom, b);
        deliver(m, b);
        let Ok(Sending::Waiting(id)) = send(&mut m.windows, a, hb, WM_USER, 1, 0) else {
            panic!("queued");
        };
        m.end_process(OTHER_OWNER);
        assert_eq!(m.windows.queues.queue_of(b), None);
        assert!(m.windows.window_from_handle(hb).is_none());
        assert_eq!(await_reply(&mut m.windows, a, id), Awaited::Failed);
        assert!(m.windows.queues.queue_of(a).is_some());
    }

    /// A thread whose queue ends while it waits on sends, nested inside one another's delivery,
    /// leaves every one of them answered to nobody.
    #[test]
    fn a_waiting_threads_end_leaves_its_sends_to_nobody() {
        let (m, atom) = manager();
        let a = thread(m, 1, 0x100);
        let b = thread(m, 2, 0x200);
        let hb = popup(m, atom, b);
        deliver(m, b);
        let base = live_sends(m);
        let Ok(Sending::Waiting(outer)) = send(&mut m.windows, a, hb, WM_USER, 1, 0) else {
            panic!("queued");
        };
        let Ok(Sending::Waiting(inner)) = send(&mut m.windows, a, hb, WM_USER, 2, 0) else {
            panic!("queued");
        };
        assert!(matches!(read(m, b, &all(), 0), Taken::Sent(_)));
        detach(&mut m.windows, a);
        assert!(end_sent(&mut m.windows, b, 1));
        assert_eq!(collect_reply(&mut m.windows, a, outer), None);
        assert_eq!(collect_reply(&mut m.windows, a, inner), None);
        assert_eq!(
            deliver(m, b),
            vec![(hb, WM_USER)],
            "the inner one still reaches B"
        );
        assert_eq!(live_sends(m), base);
    }
}
