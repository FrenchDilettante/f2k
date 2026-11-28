//! The directory: every kind's pool, built from the pools' table, the typed bodies' table, and
//! an object's liveness and counts.

use sdcache::SdRef;

use super::*;
use crate::process::ordinals::Ordinals;
use crate::sched::wait::MAXIMUM_WAIT_OBJECTS;
use crate::slots::{entries_per_page, per_page, KernelId, Record, SideTable, Slots};

/// The references one thread's current wait holds: the objects it waits on.
#[derive(Clone, Copy)]
pub(super) struct WaitReferences {
    pub(super) objects: [Option<ObjectId>; MAXIMUM_WAIT_OBJECTS],
}

impl WaitReferences {
    pub(super) const fn none() -> Self {
        WaitReferences {
            objects: [None; MAXIMUM_WAIT_OBJECTS],
        }
    }
}

/// The directory's own record of a thread, at its object's index: its wait's references, and
/// whether a thread object was handed the index since the last sweep's end (only those records
/// the sweep's end starts over, see [`Directory::sweep_end`]).
pub(super) struct ThreadSide {
    pub(super) waits: WaitReferences,
    pub(super) used: bool,
}

// SAFETY: writes a whole record.
unsafe impl Record for ThreadSide {
    unsafe fn write_fresh(at: *mut Self, _: u32) {
        // SAFETY: the caller's contract.
        unsafe {
            at.write(ThreadSide {
                waits: WaitReferences::none(),
                used: false,
            })
        };
    }
}

/// The kinds' pools: each row the kind, its pool's field, its body and how a fresh body is made (a
/// marker for the dispatcher kinds, whose bodies are the dispatcher database's), and its codec when
/// not the kernel ids' ([`ThreadIndex`], [`ProcessIndex`]); a chunk is a page of records. The table
/// makes the [`Directory`]'s pools, its in-place builder, and the matches through which the untyped
/// paths (an object's counts by id, its deletion, the sweep) reach a kind's pool.
macro_rules! pools {
    // A slot row's codec: its own, or the kernel ids' (FIFO reuse from index 0).
    (@codec $sbody:ty) => { KernelId<$sbody> };
    (@codec $sbody:ty, $codec:ty) => { $codec };
    (
        $($skind:ident => $spool:ident: $sbody:ty = $sfresh:expr $(, in $codec:ty)?;)*
    ) => {
        $(
            // SAFETY: writes a whole record.
            unsafe impl Record for ObRecord<$sbody> {
                unsafe fn write_fresh(at: *mut Self, _: u32) {
                    // SAFETY: the caller's contract.
                    unsafe {
                        at.write(ObRecord {
                            counts: Counts::none(),
                            sd: SdRef::NONE,
                            body: $sfresh,
                        })
                    };
                }
            }
        )*

        /// Every object, by kind, with the image segments, the namespace and the waits'
        /// references. The dispatcher objects' pools hold their counts alone: the bodies are the
        /// dispatcher database's, at the same index.
        pub struct Directory {
            $(pub(super) $spool: Slots<
                ObRecord<$sbody>,
                pools!(@codec $sbody $(, $codec)?),
                { per_page::<ObRecord<$sbody>>() },
            >,)*
            pub(super) segments: ObSlots<ImageSegment, { per_page::<ObRecord<ImageSegment>>() }>,
            pub(super) names: Names,
            pub(super) key_sds: KeySds,
            /// Each process's thread ordinals, at its process object's index, made with the
            /// object: kept here, since which of them are free is its thread objects' lives.
            pub(super) ordinals: SideTable<Ordinals, { entries_per_page::<Ordinals>() }>,
            /// Each thread's wait references, at its thread object's index, made with the object.
            pub(super) thread_sides: SideTable<ThreadSide, { entries_per_page::<ThreadSide>() }>,
        }

        impl Directory {
            /// Write an empty directory at `directory`: every pool empty, no names, no waits.
            ///
            /// # Safety
            ///
            /// `directory` is valid for writes, aligned, and the records' final address; its
            /// previous contents are overwritten, not dropped.
            pub unsafe fn write_empty(directory: *mut Directory) {
                use core::ptr::addr_of_mut;
                // SAFETY: the caller's contract; every field is written.
                unsafe {
                    $(addr_of_mut!((*directory).$spool).write(Slots::new());)*
                    addr_of_mut!((*directory).segments).write(Slots::new());
                    addr_of_mut!((*directory).names).write(Slots::new());
                    addr_of_mut!((*directory).key_sds).write(Slots::new());
                    addr_of_mut!((*directory).ordinals).write(SideTable::new());
                    addr_of_mut!((*directory).thread_sides).write(SideTable::new());
                }
            }

            /// The counts of the object `id` names, live or dying (see [`Counts`]); none for an
            /// id that names nothing.
            pub(super) fn header(&self, id: ObjectId) -> Option<&Counts> {
                match id.kind {
                    $(ObjectType::$skind => self
                        .$spool
                        .get(slot_id(id))
                        .map(|record| &record.counts),)*
                }
            }

            /// The security descriptor cell of the live object `id` names; none for an id that
            /// names nothing.
            pub(super) fn sd_cell(&mut self, id: ObjectId) -> Option<&mut SdRef> {
                match id.kind {
                    $(ObjectType::$skind => self
                        .$spool
                        .get_mut(slot_id(id))
                        .map(|record| &mut record.sd),)*
                }
            }

            /// The lowest live object of `kind`.
            pub(super) fn lowest_live(&mut self, kind: ObjectType) -> Option<ObjectId> {
                match kind {
                    $(ObjectType::$skind => self
                        .$spool
                        .iter()
                        .next()
                        .map(|(id, _)| object_id(kind, id)),)*
                }
            }

            /// The live object `id` names is gone: its record is free, its id stale, and the
            /// descriptor's reference released with it (a freed record is overwritten, not
            /// dropped, so its handle is let go here).
            pub(super) fn kill(&mut self, id: ObjectId) {
                match id.kind {
                    $(ObjectType::$skind => {
                        if let Some(record) = self.$spool.get_mut(slot_id(id)) {
                            record.sd = SdRef::NONE;
                        }
                        let freed = self.$spool.free(slot_id(id));
                        debug_assert!(freed, "a live object's record");
                    })*
                }
            }

            /// How many objects are live, of every kind.
            #[cfg(test)]
            pub fn live_objects(&self) -> usize {
                0 $(+ self.$spool.live() as usize)*
            }
        }
    };
}

pools! {
    Thread => threads: ThreadRecord = ThreadRecord, in ThreadIndex;
    Process => processes: ProcessRecord = ProcessRecord, in ProcessIndex;
    Event => events: EventObject = EventObject;
    Semaphore => semaphores: SemaphoreObject = SemaphoreObject;
    Mutex => mutexes: MutexObject = MutexObject;
    Timer => timers: TimerObject = TimerObject;
    Section => sections: SectionObject = SectionObject::none();
    File => files: crate::fs::file::FileObject = crate::fs::file::FileObject::none();
    Directory => directories: DirectoryObject = DirectoryObject;
    WindowStation => window_stations: WindowStationObject = WindowStationObject::none();
    Desktop => desktops: DesktopObject = DesktopObject::none();
    Key => keys: crate::cm::KeyBody = crate::cm::KeyBody::none();
    Dc => dcs: crate::win32k::dc::Dc = crate::win32k::dc::Dc::none();
    Brush => brushes: crate::win32k::brush::Brush = crate::win32k::brush::Brush::none();
    Pen => pens: crate::win32k::pen::Pen = crate::win32k::pen::Pen::none();
    Bitmap => bitmaps: crate::win32k::bitmap::Bitmap = crate::win32k::bitmap::Bitmap::none();
    Font => fonts: crate::win32k::fonts::FontObject =
        crate::win32k::fonts::FontObject::none();
    Region => regions: crate::win32k::region::Region = crate::win32k::region::Region::none();
    Token => tokens: crate::se::TokenBody = crate::se::TokenBody::none();
}

// SAFETY: writes a whole record.
unsafe impl Record for ObRecord<ImageSegment> {
    unsafe fn write_fresh(at: *mut Self, _: u32) {
        // SAFETY: the caller's contract.
        unsafe {
            at.write(ObRecord {
                counts: Counts::none(),
                sd: SdRef::NONE,
                body: ImageSegment::none(),
            })
        };
    }
}

// SAFETY: the directory's raw pointers are the links of the file objects' embedded lock headers,
// which name waitable headers and threads of the dispatcher database, reached there only with the
// dispatch token, and the slot pools' chunk pointers, which only the directory's holder follows.
// One processor, and the directory is reached only through its lock, so whichever kernel thread
// holds it is the only one reaching its records.
unsafe impl Send for Directory {}

/// A kind whose body the directory holds in a slot pool (no dispatcher object's, nor a
/// process's): its kind, and its pool's records.
pub trait Body: Sized {
    const KIND: ObjectType;

    /// The record of the live object of the kind `id` names in `directory`.
    fn record(directory: &mut Directory, id: ObjectId) -> Option<&mut ObRecord<Self>>;

    /// A new object's record in `directory`, holding its creator's reference (see
    /// [`allocate_record`]).
    fn allocate(directory: &mut Directory) -> Option<(ObjectId, &mut ObRecord<Self>)>;
}

/// The bodies' table: each body type, its kind, its pool, and the name of its typed accessor.
macro_rules! bodies {
    ($($body:ty => $kind:ident, $pool:ident, $accessor:ident;)*) => {
        $(
            impl Body for $body {
                const KIND: ObjectType = ObjectType::$kind;

                fn record(directory: &mut Directory, id: ObjectId) -> Option<&mut ObRecord<Self>> {
                    directory.$pool.get_mut(slot_id(id))
                }

                fn allocate(directory: &mut Directory) -> Option<(ObjectId, &mut ObRecord<Self>)> {
                    allocate_record(
                        &mut directory.$pool,
                        Self::KIND,
                        security::default_sd(Self::KIND),
                    )
                }
            }
        )*

        impl Directory {
            $(
                #[doc = concat!("The live ", stringify!($kind), " object's body `id` names.")]
                pub fn $accessor(&mut self, id: ObjectId) -> Option<&mut $body> {
                    self.body(id)
                }
            )*
        }
    };
}

bodies! {
    SectionObject => Section, sections, section;
    crate::fs::file::FileObject => File, files, file;
    WindowStationObject => WindowStation, window_stations, window_station;
    DesktopObject => Desktop, desktops, desktop;
    crate::cm::KeyBody => Key, keys, key;
    crate::win32k::dc::Dc => Dc, dcs, dc;
    crate::win32k::brush::Brush => Brush, brushes, brush;
    crate::win32k::pen::Pen => Pen, pens, pen;
    crate::win32k::bitmap::Bitmap => Bitmap, bitmaps, bitmap;
    crate::win32k::fonts::FontObject => Font, fonts, font;
    crate::win32k::region::Region => Region, regions, region;
    crate::se::TokenBody => Token, tokens, token;
}

impl Directory {
    /// Whether `id` names a live object: not a dying one, whose last reference went (see
    /// [`Counts`]).
    pub fn is_live(&self, id: ObjectId) -> bool {
        self.header(id).is_some_and(|counts| !counts.unreferenced())
    }

    /// Claim the deletion of the live process object `id` names when its process's own reference
    /// alone holds it — no handle, and no reference beside that one (see
    /// [`crate::process::Process`]'s object) — taking a reference for the deletion in the same
    /// hold: no second caller finds the object so meanwhile, and the object, with its record,
    /// outlives the deletion's work. Whether it was claimed.
    pub fn claim_deletion(&mut self, id: ObjectId) -> bool {
        if id.kind != ObjectType::Process {
            return false;
        }
        self.header(id).is_some_and(Counts::claim_sole)
    }

    /// A deletion claimed by [`Directory::claim_deletion`] is done: the process's own reference and
    /// the claim's go in one hold, and the object with them (a process object's deletion leaves
    /// nothing to finish).
    pub fn end_claimed_deletion(&mut self, id: ObjectId) {
        debug_assert_eq!(
            self.counts(id),
            Some((2, 0)),
            "a claimed deletion holds the object"
        );
        assert_eq!(self.dereference(id), None);
        assert_eq!(self.dereference(id), None);
    }

    /// An object's (pointer, handle) counts; none for an id that names nothing.
    pub fn counts(&self, id: ObjectId) -> Option<(u32, u32)> {
        self.header(id).map(Counts::snapshot)
    }

    /// The body of the live object `id` names, when it is of `T`'s kind.
    pub fn body<T: Body>(&mut self, id: ObjectId) -> Option<&mut T> {
        if id.kind != T::KIND {
            return None;
        }
        T::record(self, id).map(|record| &mut record.body)
    }

    /// A new object of `T`'s kind holding `body`, with its creator's reference; none when no page
    /// is left for its pool to grow.
    pub(super) fn insert<T: Body>(&mut self, body: T) -> Option<ObjectId> {
        let (id, record) = T::allocate(self)?;
        record.body = body;
        Some(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ob::testkit::*;
    use crate::sched::event::EventKind;

    /// A deleted object's record is reused under a new generation: the old id never resolves to the
    /// new object (a wait replayed on the old id cannot land on it).
    #[test]
    fn a_reused_record_has_a_new_generation() {
        let directory = directory();
        let first = directory.create_semaphore(0, 1).unwrap();
        assert_eq!(directory.dereference(first), None);
        let second = directory.create_semaphore(3, 5).unwrap();
        assert_eq!(first.index, second.index, "the record is reused");
        assert_ne!(first.generation, second.generation);
        assert!(directory.semaphore(first).is_none());
        let body = directory.semaphore(second).unwrap();
        assert_eq!(dispatcher().waitable(body).signal_state(), 3);
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

    /// Every kind on a slot pool: a new object's generation is 1, never 0; an id never handed out
    /// (generation 0, or an index past every made record) names nothing; the deletion makes the
    /// id stale at once, and the record serves the kind's next create under the next generation.
    #[test]
    fn slot_kinds_name_only_their_live_objects() {
        use crate::fs::file::{Context, FileRecordId};
        let directory = directory();
        let makers: [fn(&mut Directory) -> Option<ObjectId>; 15] = [
            |d| d.create_event(EventKind::Notification, false),
            |d| d.create_semaphore(0, 1),
            |d| d.create_mutex(),
            |d| d.create_timer(true),
            |d| d.create_section(SectionObject::none()),
            |d| d.create_file(Context::Disk(FileRecordId::at(1)), 0, 0, 0),
            |d| d.create_window_station("W", 0),
            |d| d.create_desktop("D", 0),
            |d| d.create_key(crate::cm::KeyBody::none()),
            |d| d.create_dc(crate::win32k::dc::Dc::none()),
            |d| d.create_brush(crate::win32k::brush::Brush::none()),
            |d| d.create_pen(crate::win32k::pen::Pen::none()),
            |d| d.create_bitmap(crate::win32k::bitmap::Bitmap::none()),
            |d| d.create_font(crate::win32k::fonts::FontObject::none()),
            |d| d.create_token(crate::se::TokenBody::none()),
        ];
        for make in makers {
            let first = make(directory).unwrap();
            assert_eq!(first.generation, 1, "{:?}'s first", first.kind);
            assert!(directory.is_live(first));
            let never = [
                ObjectId {
                    generation: 0,
                    ..first
                },
                ObjectId {
                    generation: 2,
                    ..first
                },
                ObjectId {
                    index: first.index + 5000,
                    ..first
                },
            ];
            for id in never {
                assert!(!directory.reference(id), "{id:?} was never handed out");
                assert_eq!(directory.counts(id), None);
            }
            let _ = directory.dereference(first);
            assert!(!directory.is_live(first), "{:?}'s id is stale", first.kind);
            assert!(!directory.reference(first));
            let second = make(directory).unwrap();
            assert_eq!(
                second.index, first.index,
                "{:?}'s record reused",
                first.kind
            );
            assert_eq!(second.generation, 2);
            assert!(!directory.is_live(first));
            let _ = directory.dereference(second);
        }
        assert_eq!(directory.live_objects(), 0);
    }

    /// A process object's deletion is claimed while its own reference alone holds it: the moment
    /// a process that never had a thread, or one reaped, is deleted. A handle or another reference
    /// holds it, and no other kind is a process's. The claim takes a reference, so a second claim
    /// finds the object held, until the deletion's end drops both at once.
    #[test]
    fn a_process_objects_deletion_is_claimed_once_its_own_reference_alone_holds_it() {
        let directory = directory();
        let id = directory.create_process().unwrap();
        assert!(directory.handle_opened(id));
        assert!(!directory.claim_deletion(id), "a handle holds it");
        assert!(directory.reference(id));
        assert!(directory.handle_closed(id).iter().next().is_none());
        assert!(!directory.claim_deletion(id), "a reference holds it");
        assert_eq!(directory.dereference(id), None);
        let event = directory.create_event(EventKind::Notification, false);
        assert!(event.is_some_and(|event| !directory.claim_deletion(event)));
        assert!(directory.claim_deletion(id), "its own reference alone");
        assert_eq!(directory.counts(id), Some((2, 0)), "the claim's reference");
        assert!(!directory.claim_deletion(id), "claimed once");
        // The deletion's end drops the process's own reference and the claim's: the object goes.
        directory.end_claimed_deletion(id);
        assert!(
            !directory.is_live(id) && !directory.claim_deletion(id),
            "gone"
        );
    }
}
