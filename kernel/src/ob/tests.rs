//! The object manager's pure core: counts, generations, names, the waits' references, and the
//! kinds' teardowns, over a directory of the tests' own.

use super::*;

// The rig: leaked records at their final addresses, as the scheduler's test modules build them.

fn directory() -> &'static mut Directory {
    let mut directory = Box::<Directory>::new_uninit();
    // SAFETY: the box is valid, aligned and the records' final address once leaked.
    unsafe { Directory::write_empty(directory.as_mut_ptr()) };
    // SAFETY: written whole just above.
    Box::leak(unsafe { directory.assume_init() })
}

fn dispatcher() -> &'static mut Dispatcher {
    let d = Box::leak(Box::new(Dispatcher::zeroed()));
    d.init();
    d
}

fn thread() -> &'static mut Thread {
    let process = Box::leak(Box::new(crate::sched::process::SchedProcess::new(0x0090_0000, 8)));
    process.init();
    let thread = Box::leak(Box::new(Thread::empty()));
    // SAFETY: both are leaked at their final addresses.
    unsafe { thread.attach_to(process) };
    thread
}

/// Close a handle to `id`, collecting what the caller must finish.
fn closed(directory: &mut Directory, id: ObjectId, dispatcher: &mut Dispatcher) -> Vec<Followup> {
    let mut followups = Vec::new();
    directory.handle_closed(id, dispatcher, |followup| followups.push(followup));
    followups
}

/// A published object, as a create leaves it: one handle, the creator's reference dropped.
fn published(directory: &mut Directory, id: ObjectId, dispatcher: &mut Dispatcher) {
    assert!(directory.handle_opened(id));
    assert_eq!(directory.dereference(id, dispatcher), None);
}

/// An object lives as long as anything references it: its creator's reference and each handle's
/// count, the last reference deletes it, and its id goes stale with it.
#[test]
fn an_object_lives_while_referenced() {
    let directory = directory();
    let dispatcher = dispatcher();
    let id = directory
        .create_event(EventKind::Notification, false)
        .unwrap();
    assert_eq!(
        directory.counts(id),
        Some((1, 0)),
        "the creator's reference"
    );
    assert!(directory.handle_opened(id));
    assert_eq!(directory.counts(id), Some((2, 1)));
    assert_eq!(directory.dereference(id, dispatcher), None);
    assert_eq!(directory.counts(id), Some((1, 1)), "the handle holds it");
    assert!(directory.reference(id));
    assert_eq!(closed(directory, id, dispatcher), vec![]);
    assert!(
        directory.is_live(id),
        "a reference outlives the last handle"
    );
    assert_eq!(directory.dereference(id, dispatcher), None);
    assert!(!directory.is_live(id), "the last reference deletes it");
    assert_eq!(directory.event(id).map(|_| ()), None);
    assert!(!directory.reference(id), "a stale id names nothing");
    assert!(!directory.handle_opened(id));
}

/// A deleted object's record is reused under a new generation: the old id never resolves to the
/// new object (a wait replayed on the old id cannot land on it).
#[test]
fn a_reused_record_has_a_new_generation() {
    let directory = directory();
    let dispatcher = dispatcher();
    let first = directory.create_semaphore(0, 1).unwrap();
    assert_eq!(directory.dereference(first, dispatcher), None);
    let second = directory.create_semaphore(3, 5).unwrap();
    assert_eq!(first.index, second.index, "the record is reused");
    assert_ne!(first.generation, second.generation);
    assert!(directory.semaphore(first).is_none());
    assert_eq!(directory.semaphore(second).unwrap().count(), 3);
    assert!(directory.waitable(first).is_none());
}

/// The kinds do not mix: an id resolves only through its own kind's accessors.
#[test]
fn ids_resolve_only_as_their_kind() {
    let directory = directory();
    let event = directory
        .create_event(EventKind::Synchronization, true)
        .unwrap();
    let semaphore = directory.create_semaphore(1, 1).unwrap();
    assert!(directory.event(event).is_some());
    assert!(directory.semaphore(event).is_none());
    assert!(directory.event(semaphore).is_none());
    assert!(directory.thread(event).is_none() && directory.process(event).is_none());
    assert!(directory.waitable(event).is_some() && directory.waitable(semaphore).is_some());
}

/// A name binds a live object, compares exactly, and goes with the object's last handle — even
/// while a reference (a wait) keeps the object itself alive.
#[test]
fn a_name_goes_with_the_last_handle() {
    let directory = directory();
    let dispatcher = dispatcher();
    let id = directory.create_semaphore(0, 1).unwrap();
    published(directory, id, dispatcher);
    directory.bind_name(b"F2K.sync.semaphore", id).unwrap();
    assert_eq!(directory.lookup_name(b"F2K.sync.semaphore"), Some(id));
    assert_eq!(
        directory.lookup_name(b"f2k.sync.semaphore"),
        None,
        "case-sensitive"
    );
    assert_eq!(directory.lookup_name(b"F2K.sync"), None);
    assert!(directory.reference(id));
    assert_eq!(closed(directory, id, dispatcher), vec![]);
    assert!(directory.is_live(id));
    assert_eq!(
        directory.lookup_name(b"F2K.sync.semaphore"),
        None,
        "the last handle took the name"
    );
    // The name is free for another object.
    let other = directory
        .create_event(EventKind::Notification, false)
        .unwrap();
    directory.bind_name(b"F2K.sync.semaphore", other).unwrap();
    assert_eq!(directory.lookup_name(b"F2K.sync.semaphore"), Some(other));
}

/// The name table refuses an over-long name and fills at its capacity.
#[test]
fn the_name_table_bounds() {
    let directory = directory();
    let id = directory
        .create_event(EventKind::Notification, false)
        .unwrap();
    assert_eq!(
        directory.bind_name(&[b'x'; MAX_NAME + 1], id),
        Err(NameError::TooLong)
    );
    for index in 0..NAMES {
        directory
            .bind_name(format!("n{index}").as_bytes(), id)
            .unwrap();
    }
    assert_eq!(directory.bind_name(b"one more", id), Err(NameError::Full));
}

/// An object whose last handle closes while a thread waits on it stays live — the wait holds
/// it — and the wait's return releases it: the object is deleted (a timer would leave the timer
/// table) only then.
#[test]
fn a_wait_holds_its_object_through_its_last_handle() {
    let directory = directory();
    let dispatcher = dispatcher();
    let waiter = directory.create_thread_in(1..THREADS).unwrap();
    let event = directory
        .create_event(EventKind::Notification, false)
        .unwrap();
    published(directory, event, dispatcher);

    directory.hold_wait(waiter.index, &[event]);
    assert_eq!(directory.counts(event), Some((2, 1)));
    assert_eq!(
        closed(directory, event, dispatcher),
        vec![],
        "the program closes its handle"
    );
    assert!(directory.is_live(event), "the wait holds it");
    assert!(
        directory.waitable(event).is_some(),
        "still waitable for its waiter"
    );

    let mut followups = Vec::new();
    directory.release_wait(waiter.index, dispatcher, |followup| {
        followups.push(followup)
    });
    assert!(followups.is_empty());
    assert!(
        !directory.is_live(event),
        "the wait's return released the last reference"
    );
}

/// A timer whose last handle closes while a thread waits on it stays armed — the wait holds
/// it — and the wait's return releases it: the timer leaves the timer table only then.
#[test]
fn a_wait_holds_a_timer_through_its_last_handle() {
    let directory = directory();
    let dispatcher = dispatcher();
    let waiter = directory.create_thread_in(1..THREADS).unwrap();
    let timer = directory.create_timer(true).unwrap();
    published(directory, timer, dispatcher);
    let record = directory.timer(timer).unwrap();
    dispatcher.set_waitable_timer(record, 1_000_000, 0, 0, false, 0);
    assert!(directory.timer(timer).unwrap().armed());

    directory.hold_wait(waiter.index, &[timer]);
    assert_eq!(directory.counts(timer), Some((2, 1)));
    assert_eq!(closed(directory, timer, dispatcher), vec![], "the program closes its handle");
    assert!(directory.is_live(timer), "the wait holds it");
    assert!(directory.timer(timer).unwrap().armed(), "still armed for its waiter");

    let mut followups = Vec::new();
    directory.release_wait(waiter.index, dispatcher, |followup| followups.push(followup));
    assert!(followups.is_empty());
    assert!(!directory.is_live(timer), "the wait's return released the last reference");
    assert!(!directory.timers.record(timer.index).armed(), "deletion cancelled it");
}

/// A timer the process's end sweeps (a leaked reference) leaves the timer table with it.
#[test]
fn the_process_end_disarms_a_leaked_timer() {
    let directory = directory();
    let dispatcher = dispatcher();
    let leaked = directory.create_timer(true).unwrap();
    dispatcher.set_waitable_timer(directory.timer(leaked).unwrap(), 1_000_000, 0, 0, false, 0);
    assert_eq!(directory.process_ended(dispatcher, |_| {}), 1);
    assert!(!directory.timers.record(leaked.index).armed(), "the leaked timer left the table");
}

/// A wait's references keep its objects from being recycled while the waiter is away (a
/// suspend unwinds the wait, which replays later): the record cannot go to a new object.
#[test]
fn a_waits_references_keep_records_from_reuse() {
    let directory = directory();
    let dispatcher = dispatcher();
    let waiter = directory.create_thread_in(1..THREADS).unwrap();
    let semaphore = directory.create_semaphore(0, 1).unwrap();
    published(directory, semaphore, dispatcher);
    directory.hold_wait(waiter.index, &[semaphore]);
    assert_eq!(closed(directory, semaphore, dispatcher), vec![]);
    let fresh = directory.create_semaphore(1, 1).unwrap();
    assert_ne!(
        fresh.index, semaphore.index,
        "the held record is not handed out"
    );
    assert!(
        directory.semaphore(semaphore).is_some(),
        "the waiter's object is still its own"
    );
    directory.release_wait(waiter.index, dispatcher, |_| {});
    assert!(!directory.is_live(semaphore));
}

/// A wait over several objects holds each, the same object twice twice.
#[test]
fn a_wait_holds_every_object_it_names() {
    let directory = directory();
    let dispatcher = dispatcher();
    let waiter = directory.create_thread_in(1..THREADS).unwrap();
    let a = directory
        .create_event(EventKind::Notification, false)
        .unwrap();
    let b = directory
        .create_event(EventKind::Notification, false)
        .unwrap();
    directory.hold_wait(waiter.index, &[a, b, a]);
    assert_eq!(directory.counts(a), Some((3, 0)));
    assert_eq!(directory.counts(b), Some((2, 0)));
    directory.release_wait(waiter.index, dispatcher, |_| {});
    assert_eq!(
        directory.counts(a),
        Some((1, 0)),
        "back to the creators' references"
    );
    assert_eq!(directory.counts(b), Some((1, 0)));
}

/// Thread records: created threads never take the main thread's record, the pool exhausts at its
/// capacity, and a record's pointer resolves to its object.
#[test]
fn thread_records_and_their_ranges() {
    let directory = directory();
    let dispatcher = dispatcher();
    let main = directory.create_thread_in(0..1).unwrap();
    assert_eq!(main.index, 0);
    assert_eq!(directory.create_thread_in(0..1), None, "one main thread");
    let mut created = Vec::new();
    while let Some(id) = directory.create_thread_in(1..THREADS) {
        assert_ne!(id.index, 0);
        created.push(id);
    }
    assert_eq!(created.len(), THREADS - 1);
    let last = *created.last().unwrap();
    let record: *const Thread = directory.threads.record(last.index);
    assert_eq!(directory.thread_id_of(record), Some(last));
    assert_eq!(
        directory.thread_id_of(core::ptr::null()),
        None,
        "not a pool record"
    );
    // A thread's own reference released: its record is free again.
    assert_eq!(directory.dereference(last, dispatcher), None);
    assert_eq!(directory.thread_id_of(record), None);
    assert_eq!(
        directory.create_thread_in(1..THREADS).map(|id| id.index),
        Some(last.index)
    );
}

/// The pools refuse past their capacity.
#[test]
fn the_pools_exhaust() {
    let directory = directory();
    for _ in 0..SEMAPHORES {
        assert!(directory.create_semaphore(0, 1).is_some());
    }
    assert_eq!(directory.create_semaphore(0, 1), None);
    assert_eq!(directory.live_objects(), SEMAPHORES);
}

/// A deleted mutex its owner still held leaves the owner's list: the owner's end then has
/// nothing of it to abandon.
#[test]
fn a_deleted_owned_mutex_leaves_its_owner() {
    let directory = directory();
    let dispatcher = dispatcher();
    let owner = thread();
    let id = directory.create_mutex().unwrap();
    crate::sched::mutex::acquire(directory.mutex(id).unwrap(), owner);
    assert!(!owner.owned_mutexes.is_empty());
    assert!(directory.waitable(id).is_some(), "a mutex is waitable");
    assert_eq!(directory.dereference(id, dispatcher), None);
    assert!(owner.owned_mutexes.is_empty(), "the deletion unlinked it");
    dispatcher.abandon_mutexes(owner);
}

/// `\BaseNamedObjects` is made once, at its first need, and is permanent: no process's end
/// deletes it, nor counts it as a leak; no wait can name it.
#[test]
fn the_named_objects_directory_is_permanent() {
    let directory = directory();
    let dispatcher = dispatcher();
    let id = directory.named_objects().unwrap();
    assert_eq!(directory.named_objects(), Some(id), "one directory");
    assert_eq!(directory.waitable(id), None);
    // An open's handle, then its close: the creator's reference stays.
    assert!(directory.handle_opened(id));
    assert_eq!(closed(directory, id, dispatcher), vec![]);
    assert_eq!(directory.counts(id), Some((1, 0)));
    assert_eq!(directory.process_ended(dispatcher, |_| {}), 0);
    assert!(directory.is_live(id), "it outlives every process");
    assert_eq!(directory.named_objects(), Some(id));
}

/// The process's end deletes whatever outlived it (a reference leak, reported) and starts every
/// thread record and name over.
#[test]
fn the_process_end_sweeps_the_directory() {
    let directory = directory();
    let dispatcher = dispatcher();
    let leaked = directory
        .create_event(EventKind::Notification, true)
        .unwrap();
    directory.bind_name(b"left", leaked).unwrap();
    let main = directory.create_thread_in(0..1).unwrap();
    directory.threads.record(main.index).teb_va = 0x0031_0000;
    assert_eq!(directory.process_ended(dispatcher, |_| {}), 2);
    assert_eq!(directory.live_objects(), 0);
    assert!(!directory.is_live(leaked));
    assert_eq!(directory.lookup_name(b"left"), None);
    assert_eq!(
        directory.threads.record(main.index).teb_va(),
        0,
        "records start over"
    );
}

/// One namespace for every kind and both session prefixes: `Global\` and `Local\` name the same
/// object as the bare name, and a name binds one object whatever kind asks.
#[test]
fn the_namespace_is_one_directory() {
    let directory = directory();
    let dispatcher = dispatcher();
    let event = directory
        .create_event(EventKind::Notification, false)
        .unwrap();
    published(directory, event, dispatcher);
    directory.bind_name(b"Global\\F2K.ready", event).unwrap();
    assert_eq!(directory.lookup_name(b"F2K.ready"), Some(event));
    assert_eq!(directory.lookup_name(b"Local\\F2K.ready"), Some(event));
    assert_eq!(directory.lookup_name(b"Global\\F2K.ready"), Some(event));
    assert_eq!(
        directory.lookup_name(b"global\\F2K.ready"),
        None,
        "the prefix as spelled"
    );
    // Another kind finds the same binding: its create sees a kind mismatch.
    let found = directory.lookup_name(b"F2K.ready").unwrap();
    assert_eq!(found.kind, ObjectType::Event);
    assert_eq!(
        namespace_name(b"Local\\"),
        b"",
        "a bare prefix names nothing"
    );
    assert_eq!(namespace_name(b"Session\\1"), b"Session\\1");
}

/// A process object: waitable, still active and unsignaled until its end, signaled with its exit
/// code at the end; the process-end sweep leaves it to its own reference, whose release frees the
/// record for the next process; the pool's capacity is the process pool's.
#[test]
fn a_process_object_signals_its_end() {
    let directory = directory();
    let dispatcher = dispatcher();
    let id = directory.create_process().unwrap();
    assert_eq!(directory.processes_live(id.index), Some(id));
    assert_eq!(
        directory.process(id).map(|process| process.exit_status),
        Some(STILL_ACTIVE)
    );
    let waitable = directory.waitable(id).expect("a process is waitable");
    // SAFETY: the live process object's waitable.
    assert_eq!(unsafe { (*waitable).signal_state() }, 0);
    // A handle to it and the process's own reference.
    assert!(directory.handle_opened(id));
    assert_eq!(
        directory.process_ended(dispatcher, |_| {}),
        0,
        "a process object is no leak"
    );
    assert!(directory.is_live(id));
    directory.signal_process_end(id, 3, dispatcher);
    // SAFETY: as above.
    assert_eq!(unsafe { (*waitable).signal_state() }, 1);
    assert_eq!(
        directory.process(id).map(|process| process.exit_status),
        Some(3)
    );
    assert_eq!(
        directory.dereference(id, dispatcher),
        None,
        "the process's own reference goes"
    );
    assert!(
        directory.is_live(id),
        "the handle still names the ended process"
    );
    assert_eq!(closed(directory, id, dispatcher), vec![]);
    assert_eq!(
        directory.processes_live(id.index),
        None,
        "the record is free"
    );
    let ids: Vec<_> = (0..PROCESSES)
        .map(|_| directory.create_process().unwrap())
        .collect();
    assert_eq!(ids[0].index, id.index, "the lowest free record is reused");
    assert!(
        directory.create_process().is_none(),
        "the pool is the process pool's size"
    );
}

/// A handle-table entry names an object by its id, or a record of the process's own that is not
/// an object: only the first resolves to an object.
#[test]
fn entries_name_objects_or_records() {
    let id = ObjectId {
        kind: ObjectType::Event,
        index: 3,
        generation: 7,
    };
    let entry = Entry::object(id, EVENT_ALL_ACCESS, true);
    assert_eq!(entry.object_id(), Some(id));
    assert!(entry.inherit);
    let file = Entry {
        target: Target::File(2),
        access: FILE_GENERIC_READ,
        inherit: false,
    };
    assert_eq!(file.object_id(), None);
}

/// A section is no waitable; its deletion hands its frames back to the caller, a view's reference
/// keeping it past its last handle, and its record starts over.
#[test]
fn a_deleted_section_hands_back_its_frames() {
    let directory = directory();
    let dispatcher = dispatcher();
    let section = SectionObject {
        size: 3,
        ..SectionObject::none()
    };
    let id = directory.create_section(section).unwrap();
    assert_eq!(directory.waitable(id), None, "a section is not waitable");
    assert_eq!(directory.section(id).map(|section| section.size), Some(3));
    published(directory, id, dispatcher);
    // A view's reference keeps it past its handle.
    assert!(directory.reference(id));
    assert_eq!(closed(directory, id, dispatcher), vec![]);
    assert_eq!(
        directory.dereference(id, dispatcher),
        Some(Followup::Section {
            frames: crate::mem::vm::SectionFrames::empty()
        })
    );
    assert_eq!(
        directory.sections.record(id.index).size,
        0,
        "the record holds no mapping any more"
    );
}
