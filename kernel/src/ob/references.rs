//! References and handles: the counts' changes, an object's deletion, and the references a
//! wait holds.

use super::*;
use crate::sched::mutex::MutexId;
use crate::sched::thread::ThreadId;
use crate::sched::timer::TimerId;

impl Directory {
    // --- Counts --------------------------------------------------------------------------------

    /// Take a reference on `id`, a look-up's (see [`Counts`]); false when it names nothing, or an
    /// object whose last reference went.
    pub fn reference(&mut self, id: ObjectId) -> bool {
        self.header(id).is_some_and(Counts::try_add)
    }

    /// Take another reference on `id` for a holder of one (see [`Counts`]): no look-up, and no
    /// `&mut`, since the holder's reference keeps the object.
    ///
    /// # Panics
    ///
    /// `id` names nothing: the caller holds no reference.
    pub fn reference_held(&self, id: ObjectId) {
        self.header(id).expect("a held object lives").add_held();
    }

    /// Drop a reference on `id`; the last one deletes the object. Returns what the caller must
    /// finish for a deleted object.
    ///
    /// The release is the deletion's first phase, which needs no lock; the deletion itself is the
    /// second, [`Directory::delete_unreferenced`], under the lock. Both run in this one hold.
    pub fn dereference(&mut self, id: ObjectId) -> Option<Followup> {
        let counts = self.header(id)?;
        debug_assert!(
            {
                let (pointers, handles) = counts.snapshot();
                pointers > handles
            },
            "a reference beyond the handles' is held"
        );
        if !counts.release() {
            return None;
        }
        self.delete_unreferenced(id)
    }

    /// The second phase of an object's last release (see [`Counts`]), under the directory's lock:
    /// re-check, then delete. Nothing when `id` names nothing any more (its deletion ran already)
    /// or the object holds a reference again (none of a look-up's can: it refuses a dying object;
    /// the check is the rule's guard).
    fn delete_unreferenced(&mut self, id: ObjectId) -> Option<Followup> {
        if !self.header(id)?.unreferenced() {
            return None;
        }
        self.delete(id)
    }

    /// A handle to `id` was inserted: one handle more, and its reference (a look-up's: false,
    /// nothing counted, for a dying object or a stale id).
    pub fn handle_opened(&mut self, id: ObjectId) -> bool {
        self.header(id).is_some_and(Counts::open_handle)
    }

    /// A handle to `id` was closed: the last handle drops the object's name and cleans up a file
    /// object, and the handle's reference goes with it (the last reference deletes the object).
    /// Returns what the caller must finish, in order.
    pub fn handle_closed(&mut self, id: ObjectId) -> Followups {
        let mut followups = Followups::none();
        let Some(counts) = self.header(id) else {
            return followups;
        };
        if counts.close_handle() {
            self.forget_name(id);
            if let Some(file) = self.file(id) {
                followups.push(Some(Followup::FileCleanup {
                    object: id,
                    context: file.context,
                    access: file.access,
                    share: file.share,
                    delete_on_close: file.delete_on_close,
                }));
            }
        }
        followups.push(self.dereference(id));
        followups
    }

    /// Delete the object `id` names: its kind's teardown, then the record is dead and its id stale.
    /// A section leaves its frames (and a file's section its file object; an image section its
    /// segment's, when it held the segment's last reference) to the caller, a file object its
    /// close; an owned mutex leaves its owner's list. No other kind needs more than the record
    /// going: nothing waits on a waitable whose last reference went; a thread's record stays as it
    /// ended (its pages go when the record is reused); a process's record serves the next process.
    pub(super) fn delete(&mut self, id: ObjectId) -> Option<Followup> {
        let followup = match id.kind {
            ObjectType::Timer => {
                // Nothing may expire or queue an APC for a timer no one can reach.
                with_bodies(|bodies| bodies.cancel_timer(TimerId::Waitable(id.index)));
                None
            }
            ObjectType::Mutex => {
                // An owned mutex leaves its owner's list (the owner's end has nothing to abandon).
                with_bodies(|bodies| bodies.forget_mutex(MutexId(id.index)));
                None
            }
            ObjectType::Section => {
                let section = core::mem::replace(
                    self.section(id).expect("deleting a live section"),
                    SectionObject::none(),
                );
                match section.segment {
                    // An image section's frames and file are its segment's.
                    Some(segment) => self.dereference_segment(segment),
                    None => Some(Followup::Section {
                        frames: section.frames,
                        file_object: section.file_object,
                        parked: None,
                    }),
                }
            }
            ObjectType::File => Some(Followup::FileClose {
                context: self.file(id).expect("deleting a live file object").context,
            }),
            ObjectType::Region => {
                // A large region's rectangles are a block of the pool, which goes with it.
                let region = core::mem::replace(
                    self.region(id).expect("deleting a live region"),
                    crate::win32k::region::Region::none(),
                );
                crate::win32k::region::release_storage(&region);
                None
            }
            ObjectType::Dc => {
                // A DC's clipping regions' blocks go with it, and the states SaveDC saved, one
                // after another (each one's chain taken first, so none deletes the next itself).
                let dc = self.dc(id).expect("deleting a live DC");
                dc.release_regions();
                let mut saved = dc.saved.take();
                while let Some(state) = saved {
                    saved = self.dc(state).and_then(|state| state.saved.take());
                    let followup = self.dereference(state);
                    debug_assert!(
                        followup.is_none(),
                        "a DC's deletion leaves nothing to finish"
                    );
                }
                None
            }
            ObjectType::Thread => {
                // Its client id goes back with it (PspThreadDelete): an ended thread's id names
                // nothing to a look-up already, and goes back to the table only now (see
                // `crate::process::cid`). A record whose creation failed before its id was filled
                // names an id that is not its object's, which the destroy leaves alone.
                let thread_id = with_bodies(|bodies| bodies.thread(ThreadId(id.index)).thread_id());
                crate::process::cid::destroy(thread_id, crate::process::cid::Named::Object(id));
                None
            }
            ObjectType::Process => {
                // Its created threads' ordinals go back to the pool with it: nothing reaches them
                // but through the live object.
                if let Some(ordinals) = self.ordinals.get_mut(id.index.into()) {
                    ordinals.release(pages());
                }
                None
            }
            ObjectType::Event
            | ObjectType::Semaphore
            | ObjectType::Directory
            | ObjectType::WindowStation
            | ObjectType::Desktop
            | ObjectType::Key
            | ObjectType::Brush
            | ObjectType::Pen
            | ObjectType::Bitmap
            | ObjectType::Font
            | ObjectType::Token => None,
        };
        self.forget_name(id);
        // The sweep deletes a leak whatever holds it.
        self.header(id).expect("deleting a live object").clear();
        self.kill(id);
        followup
    }

    // --- Waits -------------------------------------------------------------------------------

    /// The wait thread record `thread` is about to enter holds `objects`, dispatcher objects and
    /// file objects (whose own event it waits on: [`crate::ob::waiting`] keeps another reference
    /// on each, so this one is never its last), for its whole life: a reference on each, released
    /// by [`Directory::release_wait`] when the wait returns — or when the thread ends without
    /// returning. False, and nothing held, when one of them is gone already (a handle another
    /// thread closed meanwhile).
    pub fn hold_wait(&mut self, thread: u16, objects: &[ObjectId]) -> bool {
        debug_assert!(
            self.thread_sides.get(thread.into()).is_some_and(|side| side
                .waits
                .objects
                .iter()
                .all(Option::is_none)),
            "a thread's wait holds nothing before it is entered"
        );
        debug_assert!(
            objects
                .iter()
                .all(|id| id.waitable().is_some() || id.kind == ObjectType::File),
            "a wait holds dispatcher objects and file objects"
        );
        if !objects.iter().all(|&id| self.is_live(id)) {
            return false;
        }
        let held = &mut self.thread_side(thread).waits.objects;
        for (slot, &id) in held.iter_mut().zip(objects) {
            *slot = Some(id);
        }
        for &id in objects {
            self.reference(id);
        }
        true
    }

    /// Release the references thread record `thread`'s wait holds. The objects that go with them
    /// are dispatcher objects, whose deletion leaves nothing to finish.
    pub fn release_wait(&mut self, thread: u16) {
        let held = core::mem::replace(&mut self.thread_side(thread).waits, WaitReferences::none());
        for id in held.objects.iter().flatten() {
            let left = self.dereference(*id);
            assert!(
                left.is_none(),
                "a dispatcher object's deletion leaves nothing"
            );
        }
    }

    /// A thread has ended, or is on its way out: its wait's references (if it ended inside one)
    /// and its own reference on its object go; its record is free once nothing else holds it. The
    /// exit calls this in the hold it retires the thread in: a retired thread waits for nothing.
    pub fn end_thread_references(&mut self, thread: ThreadId) {
        if let Some(id) = self.thread_object(thread) {
            self.release_wait(id.index);
            let left = self.dereference(id);
            debug_assert!(left.is_none(), "a thread object's deletion leaves nothing");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ob::testkit::*;
    use crate::sched::event::EventKind;
    use crate::sched::thread::Thread;

    fn thread() -> crate::sched::testkit::Rec<Thread> {
        let process = Box::leak(Box::new(crate::sched::process::SchedProcess::new(
            crate::mem::phys::PhysAddr::new(0x0090_0000),
            8,
        )));
        crate::sched::testkit::thread(process)
    }

    /// An object lives as long as anything references it: its creator's reference and each handle's
    /// count, the last reference deletes it, and its id goes stale with it.
    #[test]
    fn an_object_lives_while_referenced() {
        let directory = directory();
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
        assert_eq!(directory.dereference(id), None);
        assert_eq!(directory.counts(id), Some((1, 1)), "the handle holds it");
        assert!(directory.reference(id));
        assert_eq!(closed(directory, id), vec![]);
        assert!(
            directory.is_live(id),
            "a reference outlives the last handle"
        );
        assert_eq!(directory.dereference(id), None);
        assert!(!directory.is_live(id), "the last reference deletes it");
        assert_eq!(directory.event(id).map(|_| ()), None);
        assert!(!directory.reference(id), "a stale id names nothing");
        assert!(!directory.handle_opened(id));
    }

    /// An object whose last handle closes while a thread waits on it stays live — the wait holds
    /// it — and the wait's return releases it: the object is deleted (a timer would leave the timer
    /// table) only then.
    #[test]
    fn a_wait_holds_its_object_through_its_last_handle() {
        let directory = directory();
        let waiter = directory.create_thread().unwrap();
        let event = directory
            .create_event(EventKind::Notification, false)
            .unwrap();
        published(directory, event);

        assert!(directory.hold_wait(waiter.index, &[event]));
        assert_eq!(directory.counts(event), Some((2, 1)));
        assert_eq!(
            closed(directory, event),
            vec![],
            "the program closes its handle"
        );
        assert!(directory.is_live(event), "the wait holds it");
        assert!(
            directory.waitable(event).is_some(),
            "still waitable for its waiter"
        );

        directory.release_wait(waiter.index);
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
        let mut dispatcher = dispatcher();
        let waiter = directory.create_thread().unwrap();
        let timer = directory.create_timer(true).unwrap();
        published(directory, timer);
        let record = directory.timer(timer).unwrap();
        dispatcher.set_waitable_timer(record, 1_000_000, 0, 0, false, 0);
        assert!(dispatcher.timer(record).inserted());

        assert!(directory.hold_wait(waiter.index, &[timer]));
        assert_eq!(directory.counts(timer), Some((2, 1)));
        assert_eq!(
            closed(directory, timer),
            vec![],
            "the program closes its handle"
        );
        assert!(directory.is_live(timer), "the wait holds it");
        assert!(
            dispatcher.timer(record).inserted(),
            "still armed for its waiter"
        );

        directory.release_wait(waiter.index);
        assert!(
            !directory.is_live(timer),
            "the wait's return released the last reference"
        );
        assert!(
            !dispatcher.waitable_timer_mut(timer.index).armed(),
            "deletion cancelled it"
        );
    }

    /// A wait's references keep its objects from being recycled while the waiter is away (a
    /// suspend unwinds the wait, which replays later): the record cannot go to a new object.
    #[test]
    fn a_waits_references_keep_records_from_reuse() {
        let directory = directory();
        let waiter = directory.create_thread().unwrap();
        let semaphore = directory.create_semaphore(0, 1).unwrap();
        published(directory, semaphore);
        assert!(directory.hold_wait(waiter.index, &[semaphore]));
        assert_eq!(closed(directory, semaphore), vec![]);
        let fresh = directory.create_semaphore(1, 1).unwrap();
        assert_ne!(
            fresh.index, semaphore.index,
            "the held record is not handed out"
        );
        assert!(
            directory.semaphore(semaphore).is_some(),
            "the waiter's object is still its own"
        );
        directory.release_wait(waiter.index);
        assert!(!directory.is_live(semaphore));
    }

    /// A wait over several objects holds each, the same object twice twice.
    #[test]
    fn a_wait_holds_every_object_it_names() {
        let directory = directory();
        let waiter = directory.create_thread().unwrap();
        let a = directory
            .create_event(EventKind::Notification, false)
            .unwrap();
        let b = directory
            .create_event(EventKind::Notification, false)
            .unwrap();
        assert!(directory.hold_wait(waiter.index, &[a, b, a]));
        assert_eq!(directory.counts(a), Some((3, 0)));
        assert_eq!(directory.counts(b), Some((2, 0)));
        directory.release_wait(waiter.index);
        assert_eq!(
            directory.counts(a),
            Some((1, 0)),
            "back to the creators' references"
        );
        assert_eq!(directory.counts(b), Some((1, 0)));
    }

    /// A wait refuses an object gone before it could hold it (another thread closed its last
    /// handle): it holds nothing then, of that object or the others.
    #[test]
    fn a_wait_refuses_a_gone_object() {
        let directory = directory();
        let waiter = directory.create_thread().unwrap();
        let live = directory
            .create_event(EventKind::Notification, false)
            .unwrap();
        let gone = directory.create_semaphore(0, 1).unwrap();
        assert_eq!(directory.dereference(gone), None);
        assert!(!directory.hold_wait(waiter.index, &[live, gone]));
        assert_eq!(directory.counts(live), Some((1, 0)), "nothing held");
        assert!(
            directory.hold_wait(waiter.index, &[live]),
            "the slot is free"
        );
        directory.release_wait(waiter.index);
    }

    /// A handle's close leaves at most a file object's cleanup and its close, in that order; an
    /// object of another kind its deletion's follow-up alone.
    #[test]
    fn a_close_leaves_its_followups_in_order() {
        let directory = directory();
        let event = directory
            .create_event(EventKind::Notification, false)
            .unwrap();
        published(directory, event);
        assert_eq!(directory.handle_closed(event), Followups::none());
        let data = directory.create_section(SectionObject::none()).unwrap();
        published(directory, data);
        let left: Vec<_> = directory.handle_closed(data).iter().collect();
        assert_eq!(left.len(), 1, "the section's frames");
    }

    /// A deleted mutex its owner still held leaves the owner's list: the owner's end then has
    /// nothing of it to abandon.
    #[test]
    fn a_deleted_owned_mutex_leaves_its_owner() {
        let directory = directory();
        let mut dispatcher = dispatcher();
        let owner = thread();
        let id = directory.create_mutex().unwrap();
        dispatcher.acquire_mutex(directory.mutex(id).unwrap(), owner.id());
        assert!(!owner.owned_mutexes.is_empty());
        assert!(directory.waitable(id).is_some(), "a mutex is waitable");
        assert_eq!(directory.dereference(id), None);
        assert!(owner.owned_mutexes.is_empty(), "the deletion unlinked it");
        dispatcher.abandon_mutexes(owner.id());
    }

    /// A file object's last handle is its cleanup (share access, delete-on-close), and its last
    /// reference its close: a mapping's reference holds it between the two. It is no waitable.
    #[test]
    fn a_file_object_cleans_up_then_closes() {
        use crate::fs::file::{Context, FileRecordId};
        let directory = directory();
        let four = Context::Disk(FileRecordId::at(4));
        let id = directory
            .create_file(
                four,
                crate::fs::file::ACCESS_READ,
                0x8000_0000,
                crate::fs::file::SHARE_ALL,
            )
            .unwrap();
        assert_eq!(
            directory.waitable(id),
            None,
            "a file object is not waitable"
        );
        directory.file(id).unwrap().delete_on_close = true;
        published(directory, id);
        assert!(directory.handle_opened(id), "a duplicate");
        assert_eq!(closed(directory, id), vec![], "another handle remains");
        assert!(directory.reference(id), "a section's");
        assert_eq!(
            closed(directory, id),
            vec![Followup::FileCleanup {
                object: id,
                context: four,
                access: 1,
                share: 7,
                delete_on_close: true,
            }]
        );
        assert_eq!(
            directory.dereference(id),
            Some(Followup::FileClose { context: four })
        );
        // Both at once when nothing else holds it.
        let five = Context::Disk(FileRecordId::at(5));
        let id = directory.create_file(five, 0, 0x80, 0).unwrap();
        published(directory, id);
        assert_eq!(
            closed(directory, id),
            vec![
                Followup::FileCleanup {
                    object: id,
                    context: five,
                    access: 0,
                    share: 0,
                    delete_on_close: false,
                },
                Followup::FileClose { context: five },
            ]
        );
    }

    /// Between an object's last release and its deletion under the lock, the object is dying: no
    /// look-up finds it, by id, by name or for a handle, and its deletion then runs as it would
    /// have in one hold, its name going with it.
    #[test]
    fn a_dying_object_is_gone_to_every_look_up() {
        let directory = directory();
        let id = directory.create_semaphore(0, 1).unwrap();
        directory.bind_name(&w("F2K.dying"), id).unwrap();
        assert!(directory.reference(id));
        assert_eq!(directory.dereference(id), None, "not the last");

        // The first phase, as a release outside the lock would run it.
        assert!(directory.header(id).unwrap().release(), "the last");
        assert!(!directory.is_live(id));
        assert!(!directory.reference(id), "no look-up by id");
        assert!(!directory.handle_opened(id), "no handle");
        assert_eq!(
            directory.lookup_name(&w("F2K.dying"), false),
            None,
            "no name"
        );
        assert_eq!(directory.counts(id), Some((0, 0)), "nothing counted");

        // The second phase, under the lock: the re-check holds, the object goes.
        assert_eq!(directory.delete_unreferenced(id), None, "nothing to finish");
        assert_eq!(directory.counts(id), None);
        assert_eq!(directory.name_of(id), None, "its name went with it");
        let next = directory.create_semaphore(0, 1).unwrap();
        directory.bind_name(&w("F2K.dying"), next).unwrap();
        assert_eq!(directory.lookup_name(&w("F2K.dying"), false), Some(next));
    }

    /// A second phase that comes after the object's deletion (or after its record went to a new
    /// object) finds its id stale and leaves the record's new object alone.
    #[test]
    fn a_late_second_phase_finds_the_object_gone() {
        let directory = directory();
        let id = directory.create_section(SectionObject::none()).unwrap();
        assert!(directory.header(id).unwrap().release());
        assert!(
            directory.delete_unreferenced(id).is_some(),
            "the section's frames"
        );
        let reused = directory.create_section(SectionObject::none()).unwrap();
        assert_eq!(reused.index, id.index, "the record went to a new object");
        assert_eq!(directory.delete_unreferenced(id), None, "a stale id");
        assert_eq!(directory.counts(reused), Some((1, 0)), "untouched");
    }

    /// A holder's reference needs no look-up: it counts like any other, and the holder's release
    /// is not the last.
    #[test]
    fn a_holder_adds_a_reference_without_a_look_up() {
        let directory = directory();
        let id = directory.create_mutex().unwrap();
        directory.reference_held(id);
        assert_eq!(directory.counts(id), Some((2, 0)));
        assert_eq!(directory.dereference(id), None);
        assert_eq!(directory.dereference(id), None);
        assert_eq!(directory.counts(id), None, "the last one deleted it");
    }
}
