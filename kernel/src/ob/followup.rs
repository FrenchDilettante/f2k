//! What an object's last handle or last reference leaves its caller to finish outside the
//! directory's lock.

use rtl::array_vec::ArrayVec;

use super::*;

/// What a caller must finish once an object's last handle or last reference went: the work outside
/// the object manager's reach, finished once the directory's lock is released ([`finish`]).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Followup {
    /// A section or an image segment was deleted: its frames (taken out of its record) and the
    /// file object a file's section or a segment held are the caller's to release. A cached
    /// segment's frames are parked: `parked` is then its image's page count.
    Section {
        frames: crate::mem::vm::SectionFrames,
        file_object: Option<ObjectId>,
        parked: Option<u32>,
    },
    /// An image segment's last reference went: it stays cached, its frames to park on Standby
    /// (unless it is referenced again first).
    Park(SegmentId),
    /// A file object's last handle closed (its cleanup), for the device it is open on: a disk
    /// file's share access leaves the file's record, the byte-range locks the object holds go, its
    /// delete-on-close marks the file delete-pending, and the last cleanup of a delete-pending
    /// file deletes it.
    FileCleanup {
        object: ObjectId,
        context: crate::fs::file::Context,
        access: u8,
        share: u8,
        delete_on_close: bool,
    },
    /// A file object was deleted (its close), for the device it is open on: a disk file's
    /// reference on its record goes.
    FileClose { context: crate::fs::file::Context },
}

/// The most follow-ups one handle's close leaves: a file object's cleanup, then what the object's
/// deletion leaves (its close, or a section's frames).
pub const MOST_FOLLOWUPS: usize = 2;

/// The follow-ups one directory operation leaves its caller, in the order they are finished.
#[derive(Clone, Copy, Default, PartialEq, Debug)]
pub struct Followups(ArrayVec<Option<Followup>, MOST_FOLLOWUPS>);

impl Followups {
    /// No follow-up.
    pub fn none() -> Self {
        Followups(ArrayVec::new())
    }

    /// `followup` added at the end, when there is one.
    pub(super) fn push(&mut self, followup: Option<Followup>) {
        if followup.is_some() {
            self.0.push(followup);
        }
    }

    /// The follow-ups, in order.
    pub fn iter(&self) -> impl Iterator<Item = Followup> + '_ {
        self.0.iter().flatten().copied()
    }

    /// Finish every follow-up, in order (see [`finish`]): the directory's lock is released by now.
    #[cfg(target_arch = "x86")]
    pub fn finish(self) {
        for followup in self.iter() {
            finish(followup);
        }
    }
}

/// One object or image segment the sweep at quiescence deleted ([`Directory::sweep_next`]), with
/// what its deletion leaves.
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Leak {
    pub followup: Option<Followup>,
}
