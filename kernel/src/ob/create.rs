//! The creates: a new object of each kind, holding its creator's reference.

use super::*;
use crate::process::ordinals::Ordinals;
use crate::sched::event::EventKind;
use crate::sched::thread::ThreadId;
use crate::sched::wait::WaitableId;

impl Directory {
    // --- Creation ----------------------------------------------------------------------------

    /// A fresh event of `kind` at `signaled`, holding its creator's reference; none when no page is
    /// left for its record or its body (see [`create_dispatcher_object`]).
    pub fn create_event(&mut self, kind: EventKind, signaled: bool) -> Option<ObjectId> {
        create_dispatcher_object(&mut self.events, ObjectType::Event, |bodies, index| {
            bodies.renew_event(index, kind, signaled);
        })
    }

    /// A fresh semaphore at `initial` with ceiling `limit`.
    pub fn create_semaphore(&mut self, initial: i32, limit: i32) -> Option<ObjectId> {
        create_dispatcher_object(
            &mut self.semaphores,
            ObjectType::Semaphore,
            |bodies, index| {
                bodies.renew_semaphore(index, initial, limit);
            },
        )
    }

    /// A fresh, free mutex.
    pub fn create_mutex(&mut self) -> Option<ObjectId> {
        create_dispatcher_object(&mut self.mutexes, ObjectType::Mutex, |bodies, index| {
            bodies.renew_mutex(index);
        })
    }

    /// A fresh, unarmed, unsignaled waitable timer.
    pub fn create_timer(&mut self, manual_reset: bool) -> Option<ObjectId> {
        create_dispatcher_object(&mut self.timers, ObjectType::Timer, |bodies, index| {
            bodies.renew_waitable_timer(index, manual_reset);
        })
    }

    /// A thread object for a new thread of any process, main thread or created, at the lowest
    /// free index past the system threads' ([`ThreadIndex`]), holding the thread's own reference,
    /// released when the thread ends. Its records at the index are made first (each the first
    /// time a thread takes the index, and kept): the dispatcher's thread record, returned as it
    /// was left for the caller to renew ([`Directory::renew_thread`]), the directory's own, and
    /// on the target the thread's stand-in for drivers and its pending-descriptor slot. None,
    /// with nothing made, when no page is left for any of them, or every u16 index is in use.
    pub fn create_thread(&mut self) -> Option<ObjectId> {
        let (id, _) = allocate_record(
            &mut self.threads,
            ObjectType::Thread,
            Some(security::null_dacl()?),
        )?;
        let index = id.index;
        let made = self.thread_sides.ensure(index.into(), pages()).is_ok()
            && with_bodies(|bodies| bodies.ensure_thread(ThreadId(index), pages()).is_ok())
            && make_thread_extras(index);
        if !made {
            // Undone before anyone saw the id: the record goes back as a deletion leaves it.
            self.kill(id);
            return None;
        }
        self.thread_side(index).used = true;
        Some(id)
    }

    /// The directory's record of the thread at `index`, made with its object.
    pub(super) fn thread_side(&mut self, index: u16) -> &mut ThreadSide {
        self.thread_sides
            .get_mut(index.into())
            .expect("a thread's record made with its object")
    }

    /// The record of the thread object `id`, started over as fresh as the pool made it: a created
    /// thread's, before its attach. Returns the record's name.
    ///
    /// # Panics
    ///
    /// `id` names no live thread object.
    pub fn renew_thread(&mut self, id: ObjectId) -> ThreadId {
        assert!(
            id.kind == ObjectType::Thread && self.is_live(id),
            "a renewed thread record is a live thread object's"
        );
        let thread = ThreadId(id.index);
        with_bodies(|bodies| {
            bodies.renew_thread(thread);
        });
        thread
    }

    /// A process object for a new process, unsignaled and still active, holding the process's own
    /// reference, with every thread ordinal free, at the lowest free index ([`ProcessIndex`]): the
    /// process record's, never the System process's. None, the record free again, when no page is
    /// left for its record, its ordinals or its body (each made the first time a process takes the
    /// index, and kept), or every u16 index is in use.
    pub fn create_process(&mut self) -> Option<ObjectId> {
        let fallback = security::default_sd(ObjectType::Process)?;
        let (id, _) = allocate_record(&mut self.processes, ObjectType::Process, Some(fallback))?;
        let index = id.index;
        let made = self.ordinals.ensure(index.into(), pages()).is_ok()
            && with_bodies(|bodies| {
                let made = bodies
                    .ensure_body(WaitableId::Process(index), pages())
                    .is_ok();
                if made {
                    bodies.renew_process_object(index);
                }
                made
            });
        if !made {
            // Undone before anyone saw the id: the record goes back as a deletion leaves it.
            self.kill(id);
            return None;
        }
        self.ordinals_at(index).reset(pages());
        Some(id)
    }

    /// The thread ordinals at process `index`, made with its object.
    pub(super) fn ordinals_at(&mut self, index: u16) -> &mut Ordinals {
        self.ordinals
            .get_mut(index.into())
            .expect("a process's ordinals made with its object")
    }

    /// A section object holding `section` (the mapping).
    pub fn create_section(&mut self, section: SectionObject) -> Option<ObjectId> {
        self.insert(section)
    }

    /// A file object open on `context` (a device and its context there), opened for `access` (as
    /// the share check reads it; `granted` the file rights) and allowing `share`.
    pub fn create_file(
        &mut self,
        context: crate::fs::file::Context,
        access: u8,
        granted: u32,
        share: u8,
    ) -> Option<ObjectId> {
        let id = self.insert(crate::fs::file::FileObject::new(
            context, access, granted, share,
        ))?;
        self.file(id).expect("just made").init();
        Some(id)
    }

    /// A window station named `name` with `flags`; none when the pool is exhausted. Its creator's
    /// reference is the caller's: the boot's WinSta0 keeps it, so the window station is permanent.
    pub fn create_window_station(&mut self, name: &'static str, flags: u32) -> Option<ObjectId> {
        self.insert(WindowStationObject { name, flags })
    }

    /// A desktop named `name` with `flags`; none when the pool is exhausted. Its creator's
    /// reference is the caller's, as a window station's.
    pub fn create_desktop(&mut self, name: &'static str, flags: u32) -> Option<ObjectId> {
        self.insert(DesktopObject { name, flags })
    }

    /// A key object naming `body`'s key. The object carries the key's own descriptor when one
    /// was set on it (through any of its objects, see [`Directory::set_security_descriptor`]),
    /// the type's default when none was; none when the pool is exhausted.
    pub fn create_key(&mut self, body: crate::cm::KeyBody) -> Option<ObjectId> {
        let fallback = body
            .key
            .and_then(|key| self.key_sd(key))
            .or_else(|| security::default_sd(ObjectType::Key));
        let (id, record) = allocate_record(&mut self.keys, ObjectType::Key, fallback)?;
        record.body = body;
        Some(id)
    }

    /// A device context in the state `body` holds; none when the pool is exhausted.
    pub fn create_dc(&mut self, body: crate::win32k::dc::Dc) -> Option<ObjectId> {
        self.insert(body)
    }

    /// A brush of `body`'s kind and colors; none when the pool is exhausted.
    pub fn create_brush(&mut self, body: crate::win32k::brush::Brush) -> Option<ObjectId> {
        self.insert(body)
    }

    /// A pen of `body`'s style, width and color; none when the pool is exhausted.
    pub fn create_pen(&mut self, body: crate::win32k::pen::Pen) -> Option<ObjectId> {
        self.insert(body)
    }

    /// A bitmap described by `body`; none when the pool is exhausted.
    pub fn create_bitmap(&mut self, body: crate::win32k::bitmap::Bitmap) -> Option<ObjectId> {
        self.insert(body)
    }

    /// Whether a live DC other than `except` holds the bitmap `bitmap` selected (a state SaveDC
    /// saved counting as its DC's selection).
    pub fn bitmap_selected(&mut self, bitmap: ObjectId, except: Option<ObjectId>) -> bool {
        self.dcs.iter().any(|(dc, record)| {
            let owner = record.body.saved_by.map_or(dc.index, |owner| owner.index);
            except.is_none_or(|except| except.index != owner)
                && record.body.bitmap_object == Some(bitmap)
        })
    }

    /// A region holding `body`'s rectangles (its block, if any, the region's from now on); none
    /// when the pool is exhausted.
    pub fn create_region(&mut self, body: crate::win32k::region::Region) -> Option<ObjectId> {
        self.insert(body)
    }

    /// A font object holding `body`'s LOGFONT; none when the pool is exhausted.
    pub fn create_font(&mut self, body: crate::win32k::fonts::FontObject) -> Option<ObjectId> {
        self.insert(body)
    }

    /// The token the process `process` names holds, if any.
    fn held_token(&self, process: ObjectId) -> Option<ObjectId> {
        self.tokens
            .iter()
            .find(|(_, record)| record.body.owner == Some(process))
            .map(|(id, _)| object_id(ObjectType::Token, id))
    }

    /// The token of the process `process` names: the one it holds, or a new one made for it (none
    /// when no page is left for the pool to grow). A new token's creator's reference is the
    /// process's, which it holds until it lets go of the token
    /// ([`Directory::take_process_token`]).
    pub fn process_token(&mut self, process: ObjectId) -> Option<ObjectId> {
        match self.held_token(process) {
            Some(id) => Some(id),
            None => self.insert(crate::se::TokenBody::of(process)),
        }
    }

    /// A token of no process holding `body` (a duplicate), with its creator's reference; none when
    /// the pool is exhausted.
    pub fn create_token(&mut self, body: crate::se::TokenBody) -> Option<ObjectId> {
        self.insert(body)
    }

    /// The process `process` names lets go of its token, if it holds one: the token no longer
    /// names it, and the process's reference on it is the caller's to drop (the token lives on
    /// while handles to it are open).
    pub fn take_process_token(&mut self, process: ObjectId) -> Option<ObjectId> {
        let id = self.held_token(process)?;
        self.token(id).expect("a live token").owner = None;
        Some(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ob::testkit::*;
    use crate::slots::per_page;

    /// Thread objects: none takes a system thread's index, the pool grows past the fixed pool's old
    /// 128 records with each one's dispatcher record made, the lowest free index is taken first, a
    /// record names its object, and a create that finds no page takes nothing.
    #[test]
    fn thread_objects_grow_past_the_old_cap() {
        let directory = directory();
        let mut created = Vec::new();
        for _ in 0..300 {
            let id = directory.create_thread().unwrap();
            assert!(id.index >= crate::sched::database::SYSTEM_THREADS);
            assert!(dispatcher().has_thread(ThreadId(id.index)));
            created.push(id);
        }
        assert_eq!(created[0].index, crate::sched::database::SYSTEM_THREADS);
        let last = *created.last().unwrap();
        let record = ThreadId(last.index);
        assert_eq!(directory.thread_object(record), Some(last));
        assert_eq!(
            directory.thread_object(crate::sched::database::IDLE_THREAD),
            None,
            "the idle thread's record names no object"
        );
        // A thread's own reference released: its record is free again, and the lowest free.
        let middle = created[100];
        assert_eq!(directory.dereference(middle), None);
        assert_eq!(directory.thread_object(ThreadId(middle.index)), None);
        assert_eq!(directory.dereference(last), None);
        let again = directory.create_thread().unwrap();
        assert_eq!(again.index, middle.index);
        assert_ne!(again, middle, "a new generation");
        // No page for the next chunk of records: nothing taken.
        page_budget(0);
        let taken = until_refused(|| directory.create_thread());
        assert!(
            taken.iter().all(|id| id.index < 320),
            "only the records already made"
        );
        page_budget(usize::MAX);
        assert!(
            directory.create_thread().is_some(),
            "pages again: the pool grows"
        );
    }

    /// The dispatcher kinds grow past the caps they once had (64 semaphores and mutexes, 256 events
    /// and timers), each object's body made at its index; a create is refused only when no page is
    /// left, for the record or for the body, with nothing made.
    #[test]
    fn the_dispatcher_kinds_grow_until_no_page_is_left() {
        let directory = directory();
        let makers: [fn(&mut Directory) -> Option<ObjectId>; 4] = [
            |d| d.create_event(EventKind::Notification, false),
            |d| d.create_semaphore(0, 1),
            |d| d.create_mutex(),
            |d| d.create_timer(true),
        ];
        let mut made = Vec::new();
        for make in makers {
            for _ in 0..300 {
                let id = make(directory).unwrap();
                let body = id.waitable().unwrap();
                assert_eq!(dispatcher().waitable(body).id(), body, "{id:?}'s own body");
                made.push(id);
            }
        }
        page_budget(0);
        for make in makers {
            made.extend(until_refused(|| make(directory)));
            assert_eq!(make(directory), None);
        }
        assert_eq!(
            directory.live_objects(),
            made.len(),
            "the refusals made nothing"
        );
    }

    /// A create whose record is made but whose body finds no page is undone: nothing lives, the
    /// record's id goes stale, and once a page is there again the record serves the next create.
    #[test]
    fn a_body_without_a_page_undoes_its_record() {
        let directory = directory();
        // Fill the bodies' first page; as long as that count does not fill the records' pages
        // exactly, the last record page has a record left, so the next create needs a page for
        // its body alone.
        let per = crate::slots::entries_per_page::<crate::sched::event::Event>();
        assert_ne!(per % per_page::<ObRecord<EventObject>>(), 0);
        let events: Vec<_> = (0..per)
            .map(|_| {
                directory
                    .create_event(EventKind::Notification, false)
                    .unwrap()
            })
            .collect();
        page_budget(0);
        assert_eq!(directory.create_event(EventKind::Notification, false), None);
        assert_eq!(directory.live_objects(), events.len(), "nothing made");
        page_budget(usize::MAX);
        let next = directory
            .create_event(EventKind::Notification, true)
            .unwrap();
        assert_eq!(usize::from(next.index), per, "the undone record serves it");
        assert_eq!(next.generation, 2, "the undone id is stale");
        assert_eq!(
            dispatcher()
                .waitable(next.waitable().unwrap())
                .signal_state(),
            1
        );
    }

    /// A deleted timer's record serves the next create, disarmed and unsignaled.
    #[test]
    fn a_deleted_timer_s_record_is_reused_disarmed() {
        let directory = directory();
        let mut dispatcher = dispatcher();
        let timers: Vec<_> = (0..300)
            .map(|_| directory.create_timer(true).unwrap())
            .collect();
        let freed = timers[150];
        dispatcher.set_waitable_timer(directory.timer(freed).unwrap(), 1_000_000, 0, 0, false, 0);
        assert_eq!(directory.dereference(freed), None);
        let reused = directory.create_timer(false).unwrap();
        assert_eq!(reused.index, freed.index, "the freed record is reused");
        assert!(directory.timer(freed).is_none(), "under a new generation");
        assert!(!dispatcher.waitable_timer_mut(reused.index).armed());
    }

    /// The process table grows past the 64 it once held, from index 1 (the System process's is
    /// no program's), and refuses a create only when no page is left for it, nothing made. A
    /// process object whose creator's reference was its only one goes with it (a create whose
    /// record the pool could not make undoes so), and the lowest free record serves the next
    /// create, as the fixed pool's did.
    #[test]
    fn the_process_table_grows_and_reuses() {
        let directory = directory();
        let mut processes: Vec<_> = (0..100)
            .map(|_| directory.create_process().unwrap())
            .collect();
        assert_eq!(processes[0].index, SYSTEM_PROCESS_INDEX + 1);
        assert!(
            processes
                .iter()
                .all(|process| process.index != SYSTEM_PROCESS_INDEX),
            "the System process's index is no program's"
        );
        page_budget(0);
        processes.extend(until_refused(|| directory.create_process()));
        assert_eq!(directory.create_process(), None, "no page is left");
        assert_eq!(
            directory.live_objects(),
            processes.len(),
            "the refusal made nothing"
        );

        let (lower, higher) = (processes[70], processes[40]);
        for undone in [lower, higher] {
            assert_eq!(directory.dereference(undone), None, "nothing to finish");
            assert!(!directory.is_live(undone));
        }
        let reused = directory.create_process().unwrap();
        assert_eq!(reused.index, higher.index, "the lowest free record first");
        assert_ne!(reused.generation, higher.generation);
        assert_eq!(directory.create_process().unwrap().index, lower.index);
        assert_eq!(directory.create_process(), None, "no page is left still");
    }

    /// The section table grows past the 128 it once held, refuses a create only when no page is
    /// left for it — nothing made — and a deleted section's record serves the next create.
    #[test]
    fn the_section_table_fills_and_reuses() {
        let directory = directory();
        let mut sections: Vec<_> = (0..300)
            .map(|_| directory.create_section(SectionObject::none()).unwrap())
            .collect();
        page_budget(0);
        sections.extend(until_refused(|| {
            directory.create_section(SectionObject::none())
        }));
        assert_eq!(directory.create_section(SectionObject::none()), None);
        assert_eq!(
            directory.live_objects(),
            sections.len(),
            "the refusal made nothing"
        );

        let freed = sections[150];
        assert!(directory.dereference(freed).is_some(), "its frames go back");
        let reused = directory.create_section(SectionObject::none()).unwrap();
        assert_eq!(reused.index, freed.index, "the freed record is reused");
        assert!(directory.section(freed).is_none(), "under a new generation");
        assert_eq!(directory.create_section(SectionObject::none()), None);
    }

    /// The file-object table grows past the 512 it once held, refuses an open only when no page is
    /// left for it — nothing made — and a file object's close frees its record for the next open.
    #[test]
    fn the_file_object_table_fills_and_reuses() {
        use crate::fs::file::{Context, FileRecordId, ACCESS_READ, SHARE_ALL};
        let directory = directory();
        let open = |directory: &mut Directory, record: u16| {
            directory.create_file(
                Context::Disk(FileRecordId::at(record)),
                ACCESS_READ,
                0,
                SHARE_ALL,
            )
        };
        let mut files: Vec<_> = (0..600)
            .map(|record| open(directory, record).unwrap())
            .collect();
        page_budget(0);
        files.extend(until_refused(|| open(directory, 0)));
        assert_eq!(open(directory, 0), None, "the table is full");
        assert_eq!(
            directory.live_objects(),
            files.len(),
            "the refusal made nothing"
        );

        let freed = files[300];
        published(directory, freed);
        assert_eq!(
            closed(directory, freed).len(),
            2,
            "its cleanup, then its close"
        );
        let reused = open(directory, 0).unwrap();
        assert_eq!(reused.index, freed.index, "the freed record is reused");
        assert!(directory.file(freed).is_none(), "under a new generation");
        assert_eq!(open(directory, 1), None, "full again");
    }

    /// A window station and its desktop, as the boot makes WinSta0 and Default: typed, never
    /// waited on, and permanent through their creator's reference: a process's handles come and
    /// go, and no sweep deletes them or counts them as leaks.
    #[test]
    fn window_stations_and_desktops_are_permanent() {
        let directory = directory();
        let station = directory.create_window_station("WinSta0", 1).unwrap();
        let desktop = directory.create_desktop("Default", 0).unwrap();
        assert_eq!(directory.window_station(station).unwrap().name, "WinSta0");
        assert_eq!(directory.window_station(station).unwrap().flags, 1);
        let record = directory.desktop(desktop).unwrap();
        assert_eq!((record.name, record.flags), ("Default", 0));
        assert!(directory.window_station(desktop).is_none(), "typed");
        assert!(directory.desktop(station).is_none(), "typed");
        assert_eq!(directory.waitable(station), None);
        assert_eq!(directory.waitable(desktop), None);
        let other = directory.create_window_station("Other", 0).unwrap();
        assert_ne!(other, station, "another is its own object");
        assert_eq!(directory.dereference(other), None);
        for id in [station, desktop] {
            assert!(directory.handle_opened(id));
            assert_eq!(closed(directory, id), vec![]);
            assert_eq!(directory.counts(id), Some((1, 0)));
        }
        assert_eq!(sweep(directory).0, 0);
        assert!(directory.is_live(station) && directory.is_live(desktop));
    }

    /// A device context, as win32k's services make one: typed, never waited on, its state the
    /// body's; its handle's close deletes it, its id going stale; one a process left behind is a
    /// leak the sweep takes; the pool refuses a DC only when no page is left for it.
    #[test]
    fn a_dc_lives_while_its_handle_does() {
        use crate::win32k::dc::Dc;
        let directory = directory();
        let id = directory.create_dc(Dc::screen(640, 480)).unwrap();
        assert_eq!(id.kind, ObjectType::Dc);
        assert_eq!(directory.waitable(id), None);
        assert_eq!(directory.dc(id).copied(), Some(Dc::screen(640, 480)));
        assert!(directory.key(id).is_none(), "typed");
        published(directory, id);
        directory.dc(id).unwrap().text_color = 0xFF;
        assert_eq!(
            directory.dc(id).unwrap().text_color,
            0xFF,
            "the body holds the state"
        );
        assert_eq!(directory.counts(id), Some((1, 1)));
        assert_eq!(
            closed(directory, id),
            vec![],
            "nothing outside the directory"
        );
        assert!(!directory.is_live(id));
        assert!(directory.dc(id).is_none(), "the id is stale");

        let leaked = directory.create_dc(Dc::screen(640, 480)).unwrap();
        published(directory, leaked);
        assert_eq!(sweep(directory), (1, vec![]), "a DC left behind is a leak");
        assert!(!directory.is_live(leaked));

        let mut made: Vec<_> = (0..100)
            .map(|_| directory.create_dc(Dc::screen(1, 1)).unwrap())
            .collect();
        page_budget(0);
        made.extend(until_refused(|| directory.create_dc(Dc::screen(1, 1))));
        assert_eq!(
            directory.create_dc(Dc::screen(1, 1)),
            None,
            "the pool is full"
        );
        for id in made {
            assert_eq!(directory.dereference(id), None);
        }
    }

    /// A process's token is made at the first ask and found again after; its handles keep it
    /// once the process lets go of it, and the last one deletes it. Another process gets a token
    /// of its own.
    #[test]
    fn a_process_token_is_made_once_and_outlives_its_process() {
        let directory = directory();
        let process = |index| ObjectId {
            kind: ObjectType::Process,
            index,
            generation: 0,
        };
        let token = directory.process_token(process(1)).unwrap();
        assert_eq!(token.kind, ObjectType::Token);
        assert_eq!(directory.process_token(process(1)), Some(token));
        assert_ne!(directory.process_token(process(2)), Some(token));
        assert!(directory.handle_opened(token));
        assert_eq!(directory.counts(token), Some((2, 1)));
        assert_eq!(directory.take_process_token(process(1)), Some(token));
        assert_eq!(directory.take_process_token(process(1)), None, "once");
        assert_eq!(directory.dereference(token), None);
        assert!(directory.is_live(token), "its handle holds it");
        assert!(closed(directory, token).is_empty());
        assert!(!directory.is_live(token));
        // A new ask after the process let go makes a new token.
        let again = directory.process_token(process(1)).unwrap();
        assert_ne!(again, token);
    }
}
