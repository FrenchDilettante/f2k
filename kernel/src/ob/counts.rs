//! An object's pointer and handle counts, and the protocol every change to them follows.

use core::sync::atomic::{fence, AtomicU32, Ordering};

/// An object's counts: every reference (the pointer count), and the handles among them.
///
/// Both are atomic, as Windows 2000 changes PointerCount with interlocked operations
/// (ObReferenceObject, ObDereferenceObject; from memory). Every change goes through one method:
///
/// - **A holder's reference** ([`Counts::add_held`]): a holder may take another without the
///   directory's lock; the count is at least the holder's, so it cannot reach zero meanwhile.
/// - **A look-up's reference** ([`Counts::try_add`]): a reference found by id, handle or name is
///   taken under the directory's lock, which keeps the record the object's (its generation), and
///   refuses a zero count. An object whose last reference went is *dying*: its deleter is on its
///   way to the lock, and to every look-up it is gone already (Windows XP's ObReferenceObjectSafe's
///   rule). Nothing brings a dying object back, so exactly one thread sees the count reach zero.
/// - **A release** ([`Counts::release`]): a decrement, with Release ordering, that needs no lock
///   unless it is the last. The last one is the deletion's first phase; its second runs under the
///   directory's lock ([`Directory::delete_unreferenced`]), which re-checks before deleting: the id
///   still names the record's object (no one deleted it first) and its count is still zero (an
///   image segment's, which a look-up may take back from its cache, [`Counts::revive`], may not
///   be).
/// - **An image segment's** count changes only under the directory's lock: a cached segment is live
///   at zero, and a look-up takes it back ([`Counts::revive`]), so its zero is seen more than once
///   and only the lock orders those sightings with its caching.
/// - **Handles** change only under the directory's lock, with the handle table's insert or close
///   (Windows 2000 changes HandleCount under its object-type mutex; from memory): a handle's
///   reference is a look-up's, and the last close decides the name's and a file object's cleanup in
///   the same hold. They are atomic so a reader outside the lock sees a whole value.
///
/// Today every caller is inside the directory's lock, so a deletion's two phases run in one hold.
/// Taking a holder's reference, or dropping one that is not the last, outside it needs the counts
/// reachable without the directory's `&mut` (multicore phase 1); the protocol already allows it.
#[derive(Debug)]
pub(super) struct Counts {
    pointers: AtomicU32,
    handles: AtomicU32,
}

impl Counts {
    pub(super) const fn new(pointers: u32, handles: u32) -> Counts {
        Counts {
            pointers: AtomicU32::new(pointers),
            handles: AtomicU32::new(handles),
        }
    }

    /// A new object's: its creator's reference, no handle.
    pub(super) const fn created() -> Counts {
        Counts::new(1, 0)
    }

    /// A free record's.
    pub(super) const fn none() -> Counts {
        Counts::new(0, 0)
    }

    /// A deleted object's record counts nothing, whatever held it (the sweep deletes leaks).
    pub(super) fn clear(&self) {
        self.pointers.store(0, Ordering::Relaxed);
        self.handles.store(0, Ordering::Relaxed);
    }

    /// The (pointer, handle) counts as they stand.
    pub(super) fn snapshot(&self) -> (u32, u32) {
        (
            self.pointers.load(Ordering::Acquire),
            self.handles.load(Ordering::Acquire),
        )
    }

    /// Whether the last reference went: the object is dying (or, for an image segment, cached).
    pub(super) fn unreferenced(&self) -> bool {
        self.pointers.load(Ordering::Acquire) == 0
    }

    /// Take another reference for a holder of one: no lock needed.
    pub(super) fn add_held(&self) {
        let before = self.pointers.fetch_add(1, Ordering::Relaxed);
        debug_assert!(
            before != 0,
            "only a holder adds a reference without a look-up"
        );
        debug_assert!(before != u32::MAX, "the pointer count overflows");
    }

    /// Take a reference for a look-up, under the directory's lock: none for a dying object.
    pub(super) fn try_add(&self) -> bool {
        let mut count = self.pointers.load(Ordering::Relaxed);
        loop {
            if count == 0 {
                return false;
            }
            debug_assert!(count != u32::MAX, "the pointer count overflows");
            match self.pointers.compare_exchange_weak(
                count,
                count + 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(now) => count = now,
            }
        }
    }

    /// Take a reference on an image segment, cached (no reference) or not, under the directory's
    /// lock: a cached segment is live, its record kept for its file's next image section.
    pub(super) fn revive(&self) {
        let before = self.pointers.fetch_add(1, Ordering::Relaxed);
        debug_assert!(before != u32::MAX, "the pointer count overflows");
    }

    /// Take the deletion of a process object whose own reference alone holds it (no handle, no
    /// other reference): its count goes from one to two, the claim's reference. Under the
    /// directory's lock (the handles are stable there); false when anything else holds it.
    pub(super) fn claim_sole(&self) -> bool {
        self.handles.load(Ordering::Relaxed) == 0
            && self
                .pointers
                .compare_exchange(1, 2, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
    }

    /// Drop a reference: whether it was the last. The decrement orders the holder's writes before
    /// it (Release), and the last one sees every other holder's (Acquire), as the deletion that
    /// follows must.
    #[must_use = "the last reference's release deletes the object"]
    pub(super) fn release(&self) -> bool {
        let before = self.pointers.fetch_sub(1, Ordering::Release);
        debug_assert!(before != 0, "a reference is released once");
        if before != 1 {
            return false;
        }
        fence(Ordering::Acquire);
        true
    }

    /// A handle was opened on the object, under the directory's lock: one handle more, and its
    /// reference (a look-up's: none for a dying object).
    pub(super) fn open_handle(&self) -> bool {
        if !self.try_add() {
            return false;
        }
        self.handles.fetch_add(1, Ordering::Relaxed);
        true
    }

    /// A handle was closed, under the directory's lock: whether it was the last. Its reference is
    /// the caller's to release next.
    #[must_use = "the last handle's close drops the name"]
    pub(super) fn close_handle(&self) -> bool {
        let before = self.handles.fetch_sub(1, Ordering::Relaxed);
        debug_assert!(before != 0, "a handle closes once");
        before == 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- The counts' protocol (see `Counts`) --------------------------------------------------

    /// Holders on several processors take and drop references while look-ups try to take theirs:
    /// exactly one release is the last, and once it is, no look-up takes the object back.
    #[test]
    fn the_last_release_is_seen_once_across_processors() {
        use std::sync::atomic::{AtomicBool, AtomicUsize};
        let rounds = if cfg!(miri) { 2 } else { 200 };
        let turns = if cfg!(miri) { 4 } else { 50 };
        const HOLDERS: u32 = 4;
        for _ in 0..rounds {
            let counts = Counts::new(HOLDERS, 0);
            let lasts = AtomicUsize::new(0);
            let dead = AtomicBool::new(false);
            let (counts, lasts, dead) = (&counts, &lasts, &dead);
            let release = move || {
                if counts.release() {
                    assert!(!dead.swap(true, Ordering::Relaxed), "one last release");
                    lasts.fetch_add(1, Ordering::Relaxed);
                }
            };
            std::thread::scope(|scope| {
                for _ in 0..HOLDERS {
                    scope.spawn(move || {
                        for _ in 0..turns {
                            counts.add_held();
                            release();
                        }
                        release();
                    });
                }
                for _ in 0..2 {
                    scope.spawn(move || {
                        for _ in 0..turns {
                            if counts.try_add() {
                                assert!(!dead.load(Ordering::Relaxed), "a dying object revived");
                                release();
                            } else {
                                assert!(counts.unreferenced(), "refused only once dying");
                            }
                        }
                    });
                }
            });
            assert_eq!(lasts.load(Ordering::Relaxed), 1);
            assert!(dead.load(Ordering::Relaxed));
            assert!(!counts.try_add(), "a dying object stays dying");
            assert_eq!(counts.snapshot(), (0, 0));
        }
    }
}
