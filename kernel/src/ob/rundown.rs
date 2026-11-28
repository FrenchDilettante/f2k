//! Rundown: a thread's timers, a process's end, the sweep at quiescence, and the permanent
//! named objects' directory.

use super::*;
use crate::sched::thread::ThreadId;
use crate::sched::timer::TimerId;

impl Directory {
    // --- Rundown -----------------------------------------------------------------------------

    /// Cancel every live timer whose completion APC targets `thread` (it is ending: nothing may
    /// queue to it any more).
    pub fn run_down_timers(&mut self, thread: ThreadId) {
        with_bodies(|bodies| {
            for (timer, _) in self.timers.iter() {
                if bodies.waitable_timer_mut(timer.index).apc_thread() == Some(thread) {
                    bodies.cancel_timer(TimerId::Waitable(timer.index));
                }
            }
        });
    }

    /// The process whose scheduling record is `owner` is gone: the records its threads left start
    /// over (their pages went with its address space). Its handles are closed and its threads
    /// ended by now, so every object only it held went with its last reference; one still live is
    /// another process's too, or a leak only the sweep at quiescence can tell
    /// ([`Directory::sweep_next`]). A thread record whose object still lives (another process holds
    /// a handle to it) stays as it ended: still waitable, its exit code still readable.
    pub fn process_ended(&mut self, owner: *const crate::sched::process::SchedProcess) {
        // The records a thread object ever took: the system threads' never end, and no index
        // past the pool's high-water mark was handed out.
        let end = self.threads.high_water();
        with_bodies(|bodies| {
            for index in u32::from(crate::sched::database::SYSTEM_THREADS)..end {
                let thread = ThreadId(index as u16);
                let left = self.threads.id_at(index).is_none()
                    && bodies.has_thread(thread)
                    && core::ptr::eq(bodies.thread(thread).process, owner);
                if left {
                    bodies.renew_thread(thread);
                }
            }
        });
    }

    /// One step of the sweep at quiescence, once every process is torn down: every reference a
    /// process held went with its end, so every object (and image segment) still live is a leak.
    /// Each step deletes one, objects first, then a segment no object took with it; none once
    /// nothing is left. Not swept: process objects (the reaped process's own reference takes its
    /// object at its teardown's end) and the permanent directory, window station and desktop. The
    /// caller finishes what each step leaves (a leaked section's or segment's frames) before the
    /// next, then ends the sweep ([`Directory::sweep_end`]).
    pub fn sweep_next(&mut self) -> Option<Leak> {
        for kind in [
            ObjectType::Event,
            ObjectType::Semaphore,
            ObjectType::Mutex,
            ObjectType::Timer,
            ObjectType::Thread,
            ObjectType::Section,
            ObjectType::File,
            ObjectType::Key,
            ObjectType::Dc,
            ObjectType::Brush,
            ObjectType::Pen,
            ObjectType::Bitmap,
            ObjectType::Font,
            ObjectType::Region,
            ObjectType::Token,
        ] {
            // A cached image's file object is the cache's, not a leak (see
            // `image_cache_settled`).
            let lowest = match kind {
                ObjectType::File => self
                    .files
                    .iter()
                    .map(|(id, _)| object_id(kind, id))
                    .find(|&id| !self.cached_files().any(|file| file == id)),
                kind => self.lowest_live(kind),
            };
            if let Some(id) = lowest {
                // A leaked image section's segment goes with it, not into the cache.
                let followup = match self.delete(id) {
                    Some(Followup::Park(segment)) => Some(self.delete_segment(segment)),
                    followup => followup,
                };
                return Some(Leak { followup });
            }
        }
        // The image sections went above, and every view with its process: an active segment left
        // is a leak too (a cached one is the image cache's).
        let (segment, _) = self
            .segments
            .iter()
            .find(|(_, record)| !record.counts.unreferenced())?;
        let segment = SegmentId {
            index: segment.index,
            generation: segment.uniq,
        };
        Some(Leak {
            followup: Some(self.delete_segment(segment)),
        })
    }

    /// The sweep's end: every thread record starts over, and every wait's references and every
    /// name are freed.
    ///
    /// Only the records a thread object was handed since the last sweep's end are renewed: the
    /// others have had no thread since that renewal (or the boot's empty pool), so they are as it
    /// left them, and only a thread's wait holds references. A renewal rewrites a whole record
    /// (its wait blocks, its floating-point state), so renewing all of them took about 4 ms under
    /// QEMU at every quiescent reap, most of a small process's teardown.
    pub fn sweep_end(&mut self) {
        let end = self.threads.high_water();
        with_bodies(|bodies| {
            for index in u32::from(crate::sched::database::SYSTEM_THREADS)..end {
                let Some(side) = self.thread_sides.get_mut(index) else {
                    continue;
                };
                if core::mem::replace(&mut side.used, false) {
                    side.waits = WaitReferences::none();
                    bodies.renew_thread(ThreadId(index as u16));
                }
            }
        });
        self.names.drain(|_, _| ());
    }

    /// `\BaseNamedObjects`, the named objects' directory: made at its first open and permanent
    /// (its creator's reference is never dropped, so no process's end deletes it).
    pub fn named_objects(&mut self) -> Option<ObjectId> {
        if let Some((id, _)) = self.directories.iter().next() {
            return Some(object_id(ObjectType::Directory, id));
        }
        allocate_record(
            &mut self.directories,
            ObjectType::Directory,
            security::default_sd(ObjectType::Directory),
        )
        .map(|(id, _)| id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ob::testkit::*;
    use crate::sched::event::EventKind;
    use crate::sched::testkit::record;

    /// A timer the sweep at quiescence deletes (a leaked reference) leaves the timer table with it.
    #[test]
    fn the_sweep_disarms_a_leaked_timer() {
        let directory = directory();
        let mut dispatcher = dispatcher();
        let leaked = directory.create_timer(true).unwrap();
        dispatcher.set_waitable_timer(directory.timer(leaked).unwrap(), 1_000_000, 0, 0, false, 0);
        assert_eq!(sweep(directory).0, 1);
        assert!(
            !dispatcher.waitable_timer_mut(leaked.index).armed(),
            "the leaked timer left the table"
        );
    }

    /// `\BaseNamedObjects` is made once, at its first need, and is permanent: no sweep
    /// deletes it, nor counts it as a leak; no wait can name it.
    #[test]
    fn the_named_objects_directory_is_permanent() {
        let directory = directory();
        let id = directory.named_objects().unwrap();
        assert_eq!(directory.named_objects(), Some(id), "one directory");
        assert_eq!(directory.waitable(id), None);
        // An open's handle, then its close: the creator's reference stays.
        assert!(directory.handle_opened(id));
        assert_eq!(closed(directory, id), vec![]);
        assert_eq!(directory.counts(id), Some((1, 0)));
        assert_eq!(sweep(directory).0, 0);
        assert!(directory.is_live(id), "it outlives every process");
        assert_eq!(directory.named_objects(), Some(id));
    }

    /// The sweep at quiescence deletes whatever outlived its process (a reference leak, reported)
    /// and starts every thread record and name over.
    #[test]
    fn the_sweep_clears_the_directory() {
        let directory = directory();
        let leaked = directory
            .create_event(EventKind::Notification, true)
            .unwrap();
        directory.bind_name(&w("left"), leaked).unwrap();
        let main = directory.create_thread().unwrap();
        record(ThreadId(main.index)).teb_va = 0x7FFD_E000;
        assert_eq!(sweep(directory).0, 2);
        assert_eq!(directory.live_objects(), 0);
        assert!(!directory.is_live(leaked));
        assert_eq!(directory.lookup_name(&w("left"), false), None);
        assert_eq!(
            record(ThreadId(main.index)).teb_va(),
            0,
            "records start over"
        );
    }

    /// The sweep's end starts over the records thread objects were handed since the last one,
    /// and only those: a record no thread had since is as that sweep left it.
    #[test]
    fn the_sweep_renews_the_records_handed_out_since_the_last() {
        let directory = directory();
        let first = directory.create_thread().unwrap();
        record(ThreadId(first.index)).teb_va = 0x7FFD_E000;
        assert_eq!(directory.dereference(first), None);
        // A record no thread object was handed: written here as nothing in the kernel would.
        record(ThreadId(5)).teb_va = 0x7FFD_D000;
        assert_eq!(sweep(directory).0, 0);
        assert_eq!(record(ThreadId(first.index)).teb_va(), 0, "renewed");
        assert_eq!(record(ThreadId(5)).teb_va(), 0x7FFD_D000, "not renewed");

        // The next sweep renews only what was handed out after this one: the first record again,
        // and none other.
        let again = directory.create_thread().unwrap();
        assert_eq!(again.index, first.index);
        record(ThreadId(again.index)).teb_va = 0x7FFD_C000;
        assert_eq!(directory.dereference(again), None);
        let other = directory.create_thread().unwrap();
        record(ThreadId(other.index)).teb_va = 0x7FFD_B000;
        assert_eq!(sweep(directory).0, 1, "the thread object still held");
        assert_eq!(record(ThreadId(again.index)).teb_va(), 0);
        assert_eq!(record(ThreadId(other.index)).teb_va(), 0);
        assert_eq!(record(ThreadId(5)).teb_va(), 0x7FFD_D000);
        assert_eq!(sweep(directory).0, 0);
    }

    /// A process for the two-process tests: its scheduling record at its final address.
    fn sched_process(dir: u32) -> &'static mut crate::sched::process::SchedProcess {
        let process = Box::leak(Box::new(crate::sched::process::SchedProcess::new(
            crate::mem::phys::PhysAddr::new(dir),
            8,
        )));
        process
    }

    /// A thread of `process` on a pooled record, with its TEB at `teb`.
    fn pooled_thread(
        directory: &mut Directory,
        process: &mut crate::sched::process::SchedProcess,
        teb: u32,
    ) -> ObjectId {
        let id = directory.create_thread().unwrap();
        let thread = directory.renew_thread(id);
        dispatcher().thread_mut(thread).teb_va = teb;
        // SAFETY: the process is leaked at its final address.
        unsafe { dispatcher().attach(ThreadId(id.index), process) };
        id
    }

    /// Two processes' objects share the pools: the first one's end — its handles closed, its
    /// threads' own references gone, then its records reset — takes only what it alone held. The
    /// other's objects, its name and its running thread stay whole, an object both held included;
    /// once the second ends too, nothing is left for the sweep.
    #[test]
    fn a_process_end_takes_only_its_own() {
        let directory = directory();
        let (a, b) = (sched_process(0x0090_0000), sched_process(0x00A0_0000));
        let a_main = pooled_thread(directory, a, 0x7FFD_E000);
        let a_child = pooled_thread(directory, a, 0x7FFD_D000);
        let b_thread = pooled_thread(directory, b, 0x7FFD_C000);
        let a_event = directory
            .create_event(EventKind::Notification, false)
            .unwrap();
        published(directory, a_event);
        directory.bind_name(&w("F2K.a"), a_event).unwrap();
        let b_semaphore = directory.create_semaphore(0, 1).unwrap();
        published(directory, b_semaphore);
        directory.bind_name(&w("F2K.b"), b_semaphore).unwrap();
        // The first process opens the second's semaphore by its name.
        assert!(directory.handle_opened(b_semaphore));

        // The first process ends.
        for id in [a_event, b_semaphore] {
            assert_eq!(closed(directory, id), vec![]);
        }
        for id in [a_main, a_child] {
            assert_eq!(directory.dereference(id), None);
        }
        directory.process_ended(a);
        assert!(!directory.is_live(a_event), "its own went with its handle");
        assert_eq!(directory.lookup_name(&w("F2K.a"), false), None);
        for id in [a_main, a_child] {
            let ended = record(ThreadId(id.index));
            assert!(ended.process.is_null() && ended.teb_va() == 0, "reset");
        }
        assert_eq!(directory.counts(b_semaphore), Some((1, 1)), "the other's");
        assert_eq!(directory.lookup_name(&w("F2K.b"), false), Some(b_semaphore));
        assert!(directory.is_live(b_thread));
        let b_record = record(ThreadId(b_thread.index));
        assert!(core::ptr::eq(b_record.process, b) && b_record.teb_va() == 0x7FFD_C000);

        // The second ends: quiescence, and nothing leaked.
        assert_eq!(closed(directory, b_semaphore), vec![]);
        assert_eq!(directory.dereference(b_thread), None);
        directory.process_ended(b);
        assert_eq!(record(ThreadId(b_thread.index)).teb_va(), 0);
        assert_eq!(sweep(directory).0, 0);
        assert_eq!(directory.live_objects(), 0);
    }

    /// A process's end cannot tell a leaked reference from another process's: the object stays
    /// live, and so does a thread record whose object something still holds. The sweep at
    /// quiescence catches the leak, deletes it and reports it.
    #[test]
    fn the_sweep_at_quiescence_catches_a_leak() {
        let directory = directory();
        let (a, b) = (sched_process(0x0090_0000), sched_process(0x00A0_0000));
        let a_main = pooled_thread(directory, a, 0x7FFD_E000);
        let b_thread = pooled_thread(directory, b, 0x7FFD_C000);
        let leaked = directory
            .create_event(EventKind::Notification, false)
            .unwrap();
        published(directory, leaked);
        // A reference the first process takes and never releases (a kernel bug), and one on its
        // own thread object.
        assert!(directory.reference(leaked));
        assert!(directory.reference(a_main));

        assert_eq!(closed(directory, leaked), vec![]);
        assert_eq!(directory.dereference(a_main), None);
        directory.process_ended(a);
        assert!(
            directory.is_live(leaked),
            "not the first process's end to judge"
        );
        assert!(directory.is_live(a_main));
        assert_eq!(
            record(ThreadId(a_main.index)).teb_va(),
            0x7FFD_E000,
            "a held thread's record stays as it ended"
        );

        assert_eq!(directory.dereference(b_thread), None);
        directory.process_ended(b);
        assert_eq!(sweep(directory).0, 2, "the event and the thread");
        assert_eq!(directory.live_objects(), 0);
        assert_eq!(record(ThreadId(a_main.index)).teb_va(), 0);
    }
}
