//! Image segments: their references, the image cache and its purges.

use sdcache::SdRef;

use super::*;

impl Directory {
    /// An image segment holding `segment`, with one reference: its creator's (the image section
    /// made with it). None when no page is left for the pool to grow.
    pub fn create_segment(&mut self, segment: ImageSegment) -> Option<SegmentId> {
        let (id, record) = self.segments.allocate_or_grow(0, pages()).ok()?;
        record.counts = Counts::created();
        // A segment is no object a handle names: no captured descriptor, the default.
        record.sd = security::null_dacl()?;
        record.body = segment;
        Some(SegmentId {
            index: id.index,
            generation: id.uniq,
        })
    }

    /// The live image segment `id` names.
    pub fn segment(&mut self, id: SegmentId) -> Option<&mut ImageSegment> {
        self.segments
            .get_mut(segment_slot(id))
            .map(|record| &mut record.body)
    }

    /// Take a reference on the image segment `id`, cached or not; false when it names nothing.
    pub fn reference_segment(&mut self, id: SegmentId) -> bool {
        self.segment_header(id).map(Counts::revive).is_some()
    }

    /// Drop a reference on the image segment `id`. The last one leaves it cached, its frames for
    /// the caller to park ([`Followup::Park`]); a detached segment's deletes it, its frames and the
    /// file object it held left to the caller.
    ///
    /// The last reference's release is the first phase; the second re-checks, as an object's
    /// deletion does ([`Directory::delete_unreferenced`]): an active segment (one a look-up took
    /// back, [`Directory::reference_segment`]) is neither cached nor deleted. A segment's count
    /// changes only under the lock (see [`Counts`]), so both phases share this hold.
    pub fn dereference_segment(&mut self, id: SegmentId) -> Option<Followup> {
        if !self.segment_header(id)?.release() {
            return None;
        }
        self.segment_unreferenced(id)
    }

    /// The second phase of an image segment's last release, under the directory's lock: unless
    /// it was taken back meanwhile (or deleted: a purge), it is cached or, detached, deleted.
    fn segment_unreferenced(&mut self, id: SegmentId) -> Option<Followup> {
        if !self.segment_header(id)?.unreferenced() {
            return None;
        }
        if self.segment(id)?.detached {
            return Some(self.delete_segment(id));
        }
        let cached_at = self.cached_segments().map(|(_, at)| at + 1).max();
        self.segment(id)?.cached_at = cached_at.unwrap_or(0);
        Some(Followup::Park(id))
    }

    /// The cached segments (live, no reference): their ids and when they were cached.
    fn cached_segments(&self) -> impl Iterator<Item = (SegmentId, u32)> + '_ {
        self.segments
            .iter()
            .filter(|(_, record)| record.counts.unreferenced())
            .map(|(id, record)| {
                let id = SegmentId {
                    index: id.index,
                    generation: id.uniq,
                };
                (id, record.body.cached_at)
            })
    }

    /// Whether `id` names a cached segment: its file's still, no reference holding it.
    pub fn segment_cached(&mut self, id: SegmentId) -> bool {
        self.segment_header(id).is_some_and(Counts::unreferenced)
    }

    /// Purge the image segment `id` because its file changes (Windows 2000's
    /// MmFlushImageSection): a cached one is deleted, its frames and file left to the caller; an
    /// active one is detached from its file, deleted with its last reference (see
    /// [`ImageSegment`]).
    pub fn purge_segment(&mut self, id: SegmentId) -> Option<Followup> {
        if self.segment_header(id)?.unreferenced() {
            return Some(self.delete_segment(id));
        }
        self.segment(id)?.detached = true;
        None
    }

    /// Whether the image cache may outlive quiescence: every cached segment's file object is the
    /// segment's alone (one reference, no handle) and `record_settled` holds for it (its file's
    /// record held by that object alone). Anything else holding a cached image's file is a leak,
    /// for the sweep to find once the cache is purged.
    pub fn image_cache_settled(
        &self,
        mut record_settled: impl FnMut(&crate::fs::file::FileObject) -> bool,
    ) -> bool {
        self.cached_files().all(|file| {
            self.files.get(slot_id(file)).is_some_and(|record| {
                record.counts.snapshot() == (1, 0) && record_settled(&record.body)
            })
        })
    }

    /// The file objects the cached segments hold.
    pub(super) fn cached_files(&self) -> impl Iterator<Item = ObjectId> + '_ {
        self.segments
            .iter()
            .filter(|(_, record)| record.counts.unreferenced())
            .map(|(_, record)| record.body.file_object)
    }

    /// Whether a cached segment holds the file record `record` open (through its file object):
    /// the record outlives quiescence with the cache.
    pub fn caches_record(&self, record: crate::fs::file::FileRecordId) -> bool {
        self.cached_files().any(|file| {
            self.files
                .get(slot_id(file))
                .is_some_and(|object| object.body.disk() == Some(record))
        })
    }

    /// The frames the cached segments hold outside the allocator's lists, once each is parked (as
    /// every one is at quiescence: its caching's follow-up parks it): their frame tables. The
    /// frames they parked wait on Standby, which the allocator counts as available.
    pub fn cached_frames(&self) -> u32 {
        self.segments
            .iter()
            .filter(|(_, record)| record.counts.unreferenced())
            .map(|(_, record)| record.body.frames.tables_held())
            .sum()
    }

    /// Purge the next cached segment (at quiescence, or a volume's end), none once none is left.
    pub fn purge_next_cached(&mut self) -> Option<Followup> {
        let (id, _) = self.cached_segments().next()?;
        Some(self.delete_segment(id))
    }

    /// Make room for a new segment once [`SEGMENTS`] are live, the image cache's bound: the least
    /// recently cached segment is purged, its frames and file left to the caller. None while
    /// fewer are live, or when every segment is active (the new one is made all the same: the
    /// pool grows).
    pub fn make_room_for_segment(&mut self) -> Option<Followup> {
        if (self.segments.live() as usize) < SEGMENTS {
            return None;
        }
        let (id, _) = self.cached_segments().min_by_key(|&(_, at)| at)?;
        Some(self.delete_segment(id))
    }

    /// Delete the live image segment `id`: its record is free and its ids stale.
    pub(super) fn delete_segment(&mut self, id: SegmentId) -> Followup {
        let record = self
            .segments
            .get_mut(segment_slot(id))
            .expect("deleting a live segment");
        let segment = core::mem::replace(&mut record.body, ImageSegment::none());
        record.counts = Counts::none();
        // The freed record is overwritten, not dropped, so its descriptor's reference goes here.
        record.sd = SdRef::NONE;
        self.segments.free(segment_slot(id));
        Followup::Section {
            frames: segment.frames,
            file_object: Some(segment.file_object),
            parked: segment.parked.then(|| segment.pages()),
        }
    }

    fn segment_header(&self, id: SegmentId) -> Option<&Counts> {
        self.segments
            .get(segment_slot(id))
            .map(|record| &record.counts)
    }

    /// A view went: drop its reference on what it mapped (the last one deletes it).
    pub fn release_mapping(&mut self, mapping: Mapping) -> Option<Followup> {
        match mapping {
            Mapping::Section(id) => self.dereference(id),
            Mapping::Image(id) => self.dereference_segment(id),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ob::testkit::*;

    /// Past the image cache's bound, a cached segment gives its record up to the next, the least
    /// recently cached first; an active one never does.
    #[test]
    fn the_segment_table_fills_and_reuses() {
        let directory = directory();
        let segment = |index: u16| {
            ImageSegment::new(
                ObjectId {
                    kind: ObjectType::File,
                    index,
                    generation: 0,
                },
                0x1000_0000,
                0x3000,
            )
        };
        let segments: Vec<_> = (0..SEGMENTS as u16)
            .map(|index| directory.create_segment(segment(index)).unwrap())
            .collect();
        assert_eq!(directory.segments.live() as usize, SEGMENTS);

        assert_eq!(
            directory.make_room_for_segment(),
            None,
            "an active segment is never evicted"
        );

        // Two segments are cached, the later one first.
        let (older, newer) = (segments[SEGMENTS / 2], segments[3]);
        assert_eq!(
            directory.dereference_segment(older),
            Some(Followup::Park(older))
        );
        assert_eq!(
            directory.dereference_segment(newer),
            Some(Followup::Park(newer))
        );
        assert!(directory.segment_cached(older) && directory.segment_cached(newer));
        // Room is made from the least recently cached.
        let evicted = directory.make_room_for_segment();
        assert_eq!(
            evicted,
            Some(Followup::Section {
                frames: crate::mem::vm::SectionFrames::empty(),
                file_object: Some(segment(SEGMENTS as u16 / 2).file_object),
                parked: None,
            }),
            "its file goes back"
        );
        assert!(directory.segment(older).is_none(), "its id is stale");
        let reused = directory.create_segment(segment(0)).unwrap();
        assert_eq!(reused.index, older.index, "the evicted record is reused");
        assert!(directory.segment_cached(newer), "the newer stays cached");
        assert_eq!(
            directory.make_room_for_segment().map(|_| ()),
            Some(()),
            "then it goes"
        );
        assert!(directory.segment(newer).is_none());
        assert_eq!(
            directory.make_room_for_segment(),
            None,
            "room, so nothing goes"
        );
    }

    /// While every segment is active, a new one is made past the image cache's bound all the
    /// same (the table grows); once one is cached, it is the one room is made from, and only a
    /// pool with no page left refuses a segment.
    #[test]
    fn the_segment_table_grows_past_the_cache_bound() {
        let directory = directory();
        let segment = |index: u16| {
            ImageSegment::new(
                ObjectId {
                    kind: ObjectType::File,
                    index,
                    generation: 1,
                },
                0x1000_0000,
                0x1000,
            )
        };
        let segments: Vec<_> = (0..SEGMENTS as u16 + 40)
            .map(|index| {
                assert_eq!(directory.make_room_for_segment(), None, "all active");
                directory.create_segment(segment(index)).unwrap()
            })
            .collect();
        assert_eq!(directory.segments.live() as usize, SEGMENTS + 40);
        let cached = segments[7];
        assert_eq!(
            directory.dereference_segment(cached),
            Some(Followup::Park(cached))
        );
        assert!(directory.make_room_for_segment().is_some());
        assert!(directory.segment(cached).is_none(), "the cached one went");
        assert_eq!(directory.make_room_for_segment(), None, "all active again");
        page_budget(0);
        let more = until_refused(|| directory.create_segment(segment(0)));
        assert!(directory.create_segment(segment(0)).is_none(), "no page");
        assert_eq!(
            directory.segments.live() as usize,
            SEGMENTS + 39 + more.len()
        );
    }

    /// A section is no waitable; its deletion hands its frames (and a file's section its file
    /// object) back to the caller, a view's reference keeping it past its last handle, and its
    /// record starts over.
    #[test]
    fn a_deleted_section_hands_back_its_frames() {
        let directory = directory();
        let file_object = ObjectId {
            kind: ObjectType::File,
            index: 2,
            generation: 5,
        };
        let section = SectionObject {
            size: 3,
            paging_file: false,
            file_object: Some(file_object),
            ..SectionObject::none()
        };
        let id = directory.create_section(section).unwrap();
        assert_eq!(directory.waitable(id), None, "a section is not waitable");
        assert_eq!(directory.section(id).map(|section| section.size), Some(3));
        published(directory, id);
        // A view's reference keeps it past its handle.
        assert!(directory.reference(id));
        assert_eq!(closed(directory, id), vec![]);
        assert_eq!(
            directory.dereference(id),
            Some(Followup::Section {
                frames: crate::mem::vm::SectionFrames::empty(),
                file_object: Some(file_object),
                parked: None,
            })
        );
        let record = directory.sections.address(id.index.into()).unwrap();
        // SAFETY: a made chunk's record, which nothing changes meanwhile.
        let size = unsafe { record.as_ref() }.body.size;
        assert_eq!(size, 0, "the record holds no mapping any more");
    }

    /// An image section of `segment`, as NtCreateSection makes one and publishes it (one handle).
    fn image_section(directory: &mut Directory, segment: SegmentId) -> ObjectId {
        let id = directory
            .create_section(SectionObject {
                size: 0x3000,
                image_base: 0x1000_0000,
                segment: Some(segment),
                ..SectionObject::none()
            })
            .unwrap();
        published(directory, id);
        id
    }

    /// An image file's segment is shared: every image section of the file and every view holds
    /// it, a view's section can be closed at once, and only the last of them hands its frames and
    /// its file object back — once. Its id goes stale with it.
    #[test]
    fn an_image_segment_lives_while_a_section_or_view_holds_it() {
        let directory = directory();
        let file_object = ObjectId {
            kind: ObjectType::File,
            index: 7,
            generation: 2,
        };
        let segment = directory
            .create_segment(ImageSegment::new(file_object, 0x1000_0000, 0x3000))
            .unwrap();
        // The first process's loader: its section made the segment (the creator's reference is
        // the section's), its view holds the segment, and its handle closes.
        let first = image_section(directory, segment);
        let view = Mapping::Image(segment);
        assert!(directory.reference_segment(segment), "the first view");
        assert_eq!(closed(directory, first), vec![]);
        assert!(
            !directory.is_live(first),
            "the view does not hold the section"
        );
        assert!(
            directory.segment(segment).is_some(),
            "the view holds the segment"
        );
        // A second process shares the segment.
        assert!(directory.reference_segment(segment), "the second section");
        let second = image_section(directory, segment);
        assert!(directory.reference_segment(segment), "the second view");
        assert_eq!(closed(directory, second), vec![]);
        assert_eq!(directory.release_mapping(view), None);
        assert_eq!(directory.segments.live(), 1, "one segment for the file");
        // The last view leaves it cached, its frames to park, and a later section revives it.
        assert_eq!(
            directory.release_mapping(view),
            Some(Followup::Park(segment))
        );
        assert!(
            directory.segment_cached(segment),
            "cached, its file's still"
        );
        assert!(directory.reference_segment(segment), "revived");
        assert!(!directory.segment_cached(segment));
        assert_eq!(
            directory.dereference_segment(segment),
            Some(Followup::Park(segment))
        );
        // The file changes: the cached segment is purged, its frames and file given back.
        let gone = Followup::Section {
            frames: crate::mem::vm::SectionFrames::empty(),
            file_object: Some(file_object),
            parked: None,
        };
        assert_eq!(directory.purge_segment(segment), Some(gone));
        assert!(directory.segment(segment).is_none(), "its id is stale");
        assert!(!directory.reference_segment(segment));
        assert_eq!(directory.purge_segment(segment), None);
        assert_eq!(directory.release_mapping(view), None);
        // A section that outlives the views is the last holder in its turn.
        let again = directory
            .create_segment(ImageSegment::new(file_object, 0x1000_0000, 0x3000))
            .unwrap();
        assert_eq!(again.index, segment.index, "the record is reused");
        assert_ne!(again, segment, "under a new generation");
        let section = image_section(directory, again);
        assert!(directory.reference_segment(again), "a view");
        assert_eq!(directory.release_mapping(Mapping::Image(again)), None);
        assert_eq!(closed(directory, section), vec![Followup::Park(again)]);
        // A segment whose file changes while it is active is detached: its last reference deletes
        // it.
        assert!(directory.reference_segment(again), "revived");
        assert_eq!(directory.purge_segment(again), None, "detached");
        assert!(directory.segment(again).is_some(), "still mapped");
        assert_eq!(directory.dereference_segment(again), Some(gone));
        assert!(directory.segment(again).is_none());
        // A data view holds its section, as before.
        let data = directory.create_section(SectionObject::none()).unwrap();
        assert_eq!(
            directory.release_mapping(Mapping::Section(data)),
            Some(Followup::Section {
                frames: crate::mem::vm::SectionFrames::empty(),
                file_object: None,
                parked: None,
            })
        );
    }

    /// The sweep at quiescence deletes a segment left behind as a leak, handing its frames and
    /// file object back; one a leaked image section held goes with the section.
    #[test]
    fn the_sweep_takes_leaked_segments() {
        let directory = directory();
        let segment = |directory: &mut Directory, index| {
            directory
                .create_segment(ImageSegment::new(
                    ObjectId {
                        kind: ObjectType::File,
                        index,
                        generation: 0,
                    },
                    0x1000_0000,
                    0x1000,
                ))
                .unwrap()
        };
        let held = segment(directory, 1);
        image_section(directory, held);
        segment(directory, 2);
        // A cached segment is no leak: it, and the file object it holds, outlive the sweep.
        let (cached, file) = cached_image(directory, 9);
        assert!(directory.image_cache_settled(|_| true));
        let (leaks, followups) = sweep(directory);
        assert_eq!(leaks, 2, "the section and the lone segment");
        assert_eq!(followups.len(), 2);
        assert!(
            followups
                .iter()
                .all(|followup| matches!(followup, Followup::Section { .. })),
            "the leaked section's segment goes with it, not into the cache"
        );
        assert_eq!(directory.segments.live(), 1, "the cached one");
        assert!(directory.segment_cached(cached));
        assert!(directory.is_live(file), "its file object stays open");
        // Purged (a shutdown), it gives its file object back.
        assert!(directory.purge_next_cached().is_some());
        assert_eq!(directory.purge_next_cached(), None);
    }

    /// A cached image of the file whose record is `record`, as a process's end leaves it: a file
    /// object (its handle closed) held by the segment alone, the segment cached. The segment
    /// and the file object.
    fn cached_image(directory: &mut Directory, record: u16) -> (SegmentId, ObjectId) {
        use crate::fs::file::{Context, FileRecordId};
        let context = Context::Disk(FileRecordId::at(record));
        let file = directory.create_file(context, 1, 0x8000_0000, 1).unwrap();
        let segment = directory
            .create_segment(ImageSegment::new(file, 0x1000_0000, 0x1000))
            .unwrap();
        assert!(directory.reference(file), "the segment's");
        assert_eq!(directory.dereference(file), None, "the open's, gone");
        assert_eq!(
            directory.dereference_segment(segment),
            Some(Followup::Park(segment))
        );
        (segment, file)
    }

    /// The image cache outlives quiescence only while its file objects are its own: one held by
    /// anything else (a leaked reference or handle), or a file record that something else holds,
    /// unsettles it. A cached segment names its file's record.
    #[test]
    fn the_image_cache_settles_when_only_it_holds_its_files() {
        use crate::fs::file::FileRecordId;
        let directory = directory();
        assert!(directory.image_cache_settled(|_| false), "no cache");
        let (_, file) = cached_image(directory, 4);
        assert!(directory.caches_record(FileRecordId::at(4)));
        assert!(!directory.caches_record(FileRecordId::at(5)));
        assert!(
            directory.image_cache_settled(|object| { object.disk() == Some(FileRecordId::at(4)) })
        );
        assert!(
            !directory.image_cache_settled(|_| false),
            "its record held elsewhere"
        );
        assert!(directory.reference(file), "a leaked reference");
        assert!(!directory.image_cache_settled(|_| true));
        assert_eq!(directory.dereference(file), None);
        assert!(directory.handle_opened(file), "a leaked handle");
        assert!(!directory.image_cache_settled(|_| true));
        // The sweep then takes the leak (the cache purged first, as the reap does).
        assert!(directory.purge_next_cached().is_some());
        let (leaks, _) = sweep(directory);
        assert_eq!(leaks, 1, "the file object");
        assert!(!directory.caches_record(FileRecordId::at(4)));
    }

    /// An image segment's last reference caches it; a look-up may take it back from the cache
    /// between the release and the second phase, which then leaves it active: neither cached nor
    /// deleted. Its next last release caches it.
    #[test]
    fn a_segment_taken_back_before_the_second_phase_stays_active() {
        let directory = directory();
        let file = ObjectId {
            kind: ObjectType::File,
            index: 0,
            generation: 1,
        };
        let id = directory
            .create_segment(ImageSegment::new(file, 0x1000_0000, 0x1000))
            .unwrap();
        assert!(directory.segment_header(id).unwrap().release());
        assert!(directory.reference_segment(id), "taken back");
        assert_eq!(directory.segment_unreferenced(id), None);
        assert!(!directory.segment_cached(id), "active");
        assert_eq!(directory.dereference_segment(id), Some(Followup::Park(id)));
        assert!(directory.segment_cached(id));
    }
}
