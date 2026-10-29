//! A process's thread ordinals: which of its threads holds which TEB page.
//!
//! The ledger is kept with the process's object, in the object directory ([`crate::ob`]): whether
//! an ordinal is free is whether its holder's thread object still lives, so it is read and taken in
//! the directory's one hold, with the thread object the new thread takes.
//!
//! A thread's ordinal is its place among its own process's threads: it places the thread's TEB
//! page ([`crate::user::thread_teb_va`], downwards from the main thread's, as Windows places a
//! process's TEBs), and its slot here names the user-stack reservation its creator made. Each
//! process numbers its threads on its own: the main thread holds ordinal 0 for the process's life,
//! a created thread the lowest free ordinal from 1. A thread's record in the object manager's pool
//! is a separate thing, taken from the whole pool by any process's thread, and says nothing about
//! the ordinal beyond carrying it.
//!
//! A terminated thread's pages stay mapped after its end. Once nothing references its object any
//! more, its slot is a terminated holder's: the ordinal is free to reuse, its pages still mapped.
//! The next thread to take the ordinal has them released first, inside the ordinal's own process:
//! the pages are found here, never through a thread record that another process's thread may have
//! taken over since.

use crate::ob::ObjectId;

/// How many ordinals a process has: its main thread's and one per created thread it can hold.
pub const ORDINALS: usize = 1 + super::CHILD_THREADS;

/// The main thread's ordinal: its TEB is the process's fixed TEB page.
pub const MAIN: u16 = 0;

/// One ordinal's holder.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Slot {
    /// Never taken since the process started: nothing of it is mapped.
    Free,
    /// Taken by the thread object `thread`: the TEB page at the ordinal and the user-stack
    /// reservation at `stack` (zero: none of its own, as the main thread's stack is a system
    /// region) are mapped in the process. Once the object is gone, a terminated holder's.
    Held { thread: ObjectId, stack: u32 },
}

/// The pages a reused ordinal's previous thread left mapped: its process releases them before the
/// new thread's are mapped.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Leftover {
    /// The TEB page.
    pub teb: u32,
    /// The user-stack reservation's base; zero for none.
    pub stack: u32,
}

/// A process's ordinal ledger.
pub struct Ordinals {
    slots: [Slot; ORDINALS],
}

impl Ordinals {
    /// A fresh process's ledger: every ordinal free.
    pub const fn empty() -> Self {
        Ordinals {
            slots: [Slot::Free; ORDINALS],
        }
    }

    /// Every ordinal free again, in place: a process record taken for a new process.
    pub fn reset(&mut self) {
        self.slots.fill(Slot::Free);
    }

    /// The main thread's object, its thread live or terminated; none before the process has one.
    pub fn main(&self) -> Option<ObjectId> {
        match self.slots[MAIN as usize] {
            Slot::Free => None,
            Slot::Held { thread, .. } => Some(thread),
        }
    }

    /// The main thread `thread` takes ordinal 0, for the process's life, over the user-stack
    /// reservation at `stack` (zero: a boot's program's, whose stack is a system region).
    ///
    /// # Panics
    ///
    /// The process already has a main thread.
    pub fn hold_main(&mut self, thread: ObjectId, stack: u32) {
        let slot = &mut self.slots[MAIN as usize];
        assert_eq!(*slot, Slot::Free, "a process has one main thread");
        *slot = Slot::Held { thread, stack };
    }

    /// Whether the main thread's ordinal is taken: a process another process created has none
    /// until its first thread.
    pub fn has_main(&self) -> bool {
        self.slots[MAIN as usize] != Slot::Free
    }

    /// The ordinal the next created thread takes: the lowest one never taken, or held by a
    /// thread whose object is gone (`live` says whether an object lives). None when every created
    /// thread's ordinal is held by a thread something still references.
    pub fn free(&self, mut live: impl FnMut(ObjectId) -> bool) -> Option<u16> {
        (MAIN as usize + 1..ORDINALS)
            .find(|&ordinal| match self.slots[ordinal] {
                Slot::Free => true,
                Slot::Held { thread, .. } => !live(thread),
            })
            .map(|ordinal| ordinal as u16)
    }

    /// The created thread `thread`, whose user stack is the reservation at `stack`, takes
    /// `ordinal` (one [`Ordinals::free`] gave). Returns the pages its previous holder left mapped,
    /// for the caller to release in this process first.
    pub fn hold(&mut self, ordinal: u16, thread: ObjectId, stack: u32) -> Option<Leftover> {
        assert_ne!(ordinal, MAIN, "the main thread's ordinal is never reused");
        let slot = &mut self.slots[ordinal as usize];
        let previous = core::mem::replace(slot, Slot::Held { thread, stack });
        match previous {
            Slot::Free => None,
            Slot::Held { stack, .. } => Some(Leftover {
                teb: crate::user::thread_teb_va(ordinal as u32),
                stack,
            }),
        }
    }

    /// The thread object holding `ordinal`, its thread live or terminated; none for an ordinal
    /// never taken.
    #[cfg(test)]
    pub fn holder(&self, ordinal: u16) -> Option<ObjectId> {
        match self.slots.get(ordinal as usize)? {
            Slot::Free => None,
            Slot::Held { thread, .. } => Some(*thread),
        }
    }

    /// Every ordinal whose TEB page is mapped, as (ordinal, TEB address), in ordinal order: the
    /// main thread's, then each created thread's, terminated ones too (their pages stay mapped
    /// until the ordinal is reused).
    pub fn tebs(&self) -> impl Iterator<Item = (u32, u32)> + '_ {
        self.slots
            .iter()
            .enumerate()
            .filter(|(_, slot)| **slot != Slot::Free)
            .map(|(ordinal, _)| (ordinal as u32, crate::user::thread_teb_va(ordinal as u32)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ob::ObjectType;
    use crate::user::{thread_teb_va, TEB_PAGE};

    fn thread(index: u16, generation: u16) -> ObjectId {
        ObjectId {
            kind: ObjectType::Thread,
            index,
            generation,
        }
    }

    /// The main thread holds ordinal 0 and the fixed TEB page; created threads take the lowest
    /// free ordinal from 1, never 0, and run out past the process's capacity.
    #[test]
    fn the_main_thread_holds_ordinal_zero_and_created_threads_count_from_one() {
        let mut ordinals = Ordinals::empty();
        ordinals.hold_main(thread(5, 0), 0);
        assert_eq!(ordinals.holder(MAIN), Some(thread(5, 0)));
        assert_eq!(ordinals.tebs().collect::<Vec<_>>(), vec![(0, TEB_PAGE)]);
        for index in 1..ORDINALS as u16 {
            let ordinal = ordinals.free(|_| true).unwrap();
            assert_eq!(ordinal, index);
            assert_eq!(
                ordinals.hold(ordinal, thread(100 + index, 0), 0x0050_0000),
                None
            );
        }
        assert_eq!(ordinals.free(|_| true), None, "every ordinal held");
        // Even with every thread gone, ordinal 0 stays the main thread's.
        assert_eq!(ordinals.free(|_| false), Some(1));
    }

    /// A process another process created has no main thread until its first thread takes
    /// ordinal 0, over the stack its creator reserved; created threads still count from 1.
    #[test]
    fn a_created_process_has_no_main_thread_until_its_first() {
        let mut ordinals = Ordinals::empty();
        assert!(!ordinals.has_main());
        assert_eq!(ordinals.tebs().count(), 0);
        ordinals.hold_main(thread(3, 0), 0x0003_0000);
        assert!(ordinals.has_main());
        assert_eq!(ordinals.tebs().collect::<Vec<_>>(), vec![(0, TEB_PAGE)]);
        assert_eq!(ordinals.free(|_| true), Some(1));
    }

    /// One main thread per process.
    #[test]
    #[should_panic(expected = "a process has one main thread")]
    fn a_second_main_thread_is_refused() {
        let mut ordinals = Ordinals::empty();
        ordinals.hold_main(thread(0, 0), 0);
        ordinals.hold_main(thread(1, 0), 0);
    }

    /// Two processes whose threads' records interleave in the pool number their threads
    /// independently: each its own ordinals from 1, each thread's TEB at its own ordinal's page —
    /// the same addresses in both processes, in their own address spaces.
    #[test]
    fn two_processes_number_their_threads_independently() {
        let (mut a, mut b) = (Ordinals::empty(), Ordinals::empty());
        // The pool hands out records 0, 1, 2, 3 ... alternately to the two processes.
        a.hold_main(thread(0, 0), 0);
        b.hold_main(thread(1, 0), 0);
        let mut records = 2..;
        let mut take = |ordinals: &mut Ordinals| {
            let ordinal = ordinals.free(|_| true).unwrap();
            let record = records.next().unwrap();
            assert_eq!(ordinals.hold(ordinal, thread(record, 0), 0), None);
            (ordinal, record)
        };
        assert_eq!(take(&mut a), (1, 2));
        assert_eq!(take(&mut b), (1, 3));
        assert_eq!(take(&mut b), (2, 4));
        assert_eq!(take(&mut a), (2, 5));
        let expected = vec![(0, TEB_PAGE), (1, thread_teb_va(1)), (2, thread_teb_va(2))];
        assert_eq!(a.tebs().collect::<Vec<_>>(), expected);
        assert_eq!(b.tebs().collect::<Vec<_>>(), expected);
        assert_eq!(
            thread_teb_va(1),
            0x7FFD_D000,
            "Windows 2000's second thread's TEB"
        );
        assert_eq!(a.holder(2), Some(thread(5, 0)));
        assert_eq!(b.holder(2), Some(thread(4, 0)));
    }

    /// A terminated thread's ordinal is reused only once its object is gone, and the reuse hands
    /// back its pages for release — in the ordinal's own process, even when another process's
    /// thread has taken the dead thread's record since: the other process's ledger is untouched.
    #[test]
    fn a_reused_ordinal_releases_its_pages_in_its_own_process() {
        let (mut a, mut b) = (Ordinals::empty(), Ordinals::empty());
        a.hold_main(thread(0, 0), 0);
        b.hold_main(thread(1, 0), 0);
        let first = thread(2, 0);
        let ordinal = a.free(|_| true).unwrap();
        assert_eq!(a.hold(ordinal, first, 0x0060_0000), None);

        // The thread ended but a handle still references it: its ordinal stays held.
        assert_eq!(a.free(|id| id == first), Some(2));
        // Its object is gone: the record goes to process B's next thread (generation 1), and the
        // ordinal is A's to reuse.
        let reborn = thread(2, 1);
        let live = |id: ObjectId| id != first;
        let b_ordinal = b.free(live).unwrap();
        assert_eq!(
            b.hold(b_ordinal, reborn, 0x0070_0000),
            None,
            "B's pages are fresh"
        );
        assert_eq!(a.free(live), Some(1));
        let left = a.hold(1, thread(6, 0), 0x0080_0000);
        assert_eq!(
            left,
            Some(Leftover {
                teb: thread_teb_va(1),
                stack: 0x0060_0000,
            }),
            "A's own pages, at A's ordinal"
        );
        assert_eq!(b.holder(1), Some(reborn), "B keeps its thread and pages");
    }
}
