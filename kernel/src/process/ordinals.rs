//! A process's thread ordinals: which of its threads holds which TEB page.
//!
//! The ledger is kept with the process's object, in the object directory ([`crate::ob`]'s side
//! table at the object's index, made with it): whether
//! an ordinal is free is whether its holder's thread object still lives, so it is read and taken in
//! the directory's one hold, with the thread object the new thread takes.
//!
//! A thread's ordinal is its place among its own process's threads: its slot here names the TEB
//! page and the user-stack reservation the thread holds. Each process numbers its threads on its
//! own: the main thread holds ordinal 0 for the process's life, over the fixed TEB page
//! ([`crate::user::TEB_PAGE`]); a created thread the lowest free ordinal from 1, over the TEB its
//! creation placed as Windows 2000's MmCreateTeb does, the highest free page below the PEB
//! ([`crate::user::reserve_teb`]). A thread's record in the object manager's pool is a separate
//! thing, taken from the whole pool by any process's thread, and says nothing about the ordinal
//! beyond carrying it.
//!
//! The created threads' slots grow with the process's threads, a chunk of the pool at a time
//! ([`crate::slots::Records`]), kept at their peak for the process's life and given back with its
//! object: nothing but memory bounds a process's threads, as on Windows 2000. (An ordinal is a u16,
//! a representation limit no process reaches: every thread holds a user-stack reservation of at
//! least the 64 KiB granularity, and 2 GiB of user space holds fewer than 32,768 of them.)
//!
//! A terminated thread's pages stay mapped after its end. Once nothing references its object any
//! more, its slot is a terminated holder's: the ordinal is free to reuse, its pages still mapped.
//! The process's next thread creation releases them first ([`Ordinals::vacate`]), so the new TEB
//! is placed as Windows 2000 places it, where the TEBs freed at their threads' ends left room; the
//! pages are released inside the ordinal's own process, found here, never through a thread record
//! that another process's thread may have taken over since.

use crate::ob::ObjectId;
use crate::slots::{entries_per_page, Pages, Records};

/// The main thread's ordinal: its TEB is the process's fixed TEB page.
pub const MAIN: u16 = 0;

/// One ordinal's holder.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Slot {
    /// Not held: nothing of it is mapped (never taken, or vacated).
    Free,
    /// Taken by the thread object `thread`: the TEB page at `teb` and the user-stack reservation
    /// at `stack` (zero: none of its own, as the main thread's stack is a system region) are
    /// mapped in the process. Once the object is gone, a terminated holder's.
    Held {
        thread: ObjectId,
        stack: u32,
        teb: u32,
    },
}

// SAFETY: writes a whole record.
unsafe impl crate::slots::Record for Slot {
    unsafe fn write_fresh(at: *mut Self, _: u32) {
        // SAFETY: the caller's contract.
        unsafe { at.write(Slot::Free) };
    }
}

/// The created threads' slots a chunk holds: a page's worth.
const PER: usize = entries_per_page::<Slot>();

/// The pages a reused ordinal's previous thread left mapped: its process releases them before the
/// new thread's are mapped.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Leftover {
    /// The TEB page: a region of its own.
    pub teb: u32,
    /// The user-stack reservation's base; zero for none.
    pub stack: u32,
}

/// A process's ordinal ledger.
pub struct Ordinals {
    /// Ordinal 0's.
    main: Slot,
    /// The created threads' slots, ordinal `n` at `n - 1`, made a chunk at a time.
    created: Records<Slot, PER>,
    /// Whether the process takes no new thread: its end is decided, or its last thread is ending
    /// it (Windows 2000's process-delete mark, which PspCreateThread refuses with
    /// STATUS_PROCESS_IS_TERMINATING). Set in the directory hold that decides it, so a create,
    /// whose ordinal and attach are one hold too, either comes before it or is refused.
    closed: bool,
}

// SAFETY: writes a whole record.
unsafe impl crate::slots::Record for Ordinals {
    unsafe fn write_fresh(at: *mut Self, _: u32) {
        // SAFETY: the caller's contract.
        unsafe { at.write(Ordinals::empty()) };
    }
}

impl Ordinals {
    /// A fresh process's ledger: every ordinal free, no page held.
    pub const fn empty() -> Self {
        Ordinals {
            main: Slot::Free,
            created: Records::new(),
            closed: false,
        }
    }

    /// Every ordinal free again, in place, the created threads' slots given back to `pages`: a
    /// process record taken for a new process.
    pub fn reset(&mut self, pages: &impl Pages) {
        self.release(pages);
        self.main = Slot::Free;
        self.closed = false;
    }

    /// Give the created threads' slots back to `pages` (whence they came), every created ordinal
    /// free: the process's object is gone.
    pub fn release(&mut self, pages: &impl Pages) {
        // SAFETY: the slots are reached only through this ledger, which hands out no address, and
        // `&mut self` makes this the only use; every chunk came from `pages`.
        unsafe { self.created.release(pages) };
    }

    /// The process takes no new thread from here on.
    pub fn close(&mut self) {
        self.closed = true;
    }

    /// Whether the process takes no new thread (see [`Ordinals::close`]).
    pub fn closed(&self) -> bool {
        self.closed
    }

    /// The main thread's object, its thread live or terminated; none before the process has one.
    pub fn main(&self) -> Option<ObjectId> {
        match self.main {
            Slot::Free => None,
            Slot::Held { thread, .. } => Some(thread),
        }
    }

    /// The main thread `thread` takes ordinal 0, for the process's life, over the fixed TEB page
    /// and the user-stack reservation at `stack` (zero: a boot's program's, whose stack is a
    /// system region).
    ///
    /// # Panics
    ///
    /// The process already has a main thread.
    pub fn hold_main(&mut self, thread: ObjectId, stack: u32) {
        assert_eq!(self.main, Slot::Free, "a process has one main thread");
        self.main = Slot::Held {
            thread,
            stack,
            teb: crate::user::TEB_PAGE,
        };
    }

    /// Whether the main thread's ordinal is taken: a process another process created has none
    /// until its first thread.
    pub fn has_main(&self) -> bool {
        self.main != Slot::Free
    }

    /// The ordinal the next created thread takes: the lowest one free, or held by a thread whose
    /// object is gone (`live` says whether an object lives); past every one made, the next, its
    /// chunk made with a page from `pages`. None when every made ordinal is held by a thread
    /// something still references and no page is left for more.
    pub fn free(
        &mut self,
        pages: &impl Pages,
        mut live: impl FnMut(ObjectId) -> bool,
    ) -> Option<u16> {
        let found = self.created.iter().position(|slot| match *slot {
            Slot::Free => true,
            Slot::Held { thread, .. } => !live(thread),
        });
        let index = match found {
            Some(index) => index,
            None => {
                let index = self.created.len();
                self.created.ensure(index as u32, pages).ok()?;
                index
            }
        };
        u16::try_from(index + 1).ok()
    }

    /// The created thread `thread`, whose TEB is the page at `teb` and whose user stack is the
    /// reservation at `stack`, takes `ordinal` (one [`Ordinals::free`] gave). Returns the pages
    /// its previous holder left mapped, for the caller to release in this process.
    pub fn hold(
        &mut self,
        ordinal: u16,
        thread: ObjectId,
        stack: u32,
        teb: u32,
    ) -> Option<Leftover> {
        assert_ne!(ordinal, MAIN, "the main thread's ordinal is never reused");
        let slot = self
            .created
            .get_mut(ordinal as usize - 1)
            .expect("an ordinal `free` made");
        let previous = core::mem::replace(slot, Slot::Held { thread, stack, teb });
        match previous {
            Slot::Free => None,
            Slot::Held { stack, teb, .. } => Some(Leftover { teb, stack }),
        }
    }

    /// Free the lowest created ordinal held by a thread whose object is gone (`live` says whether
    /// an object lives), returning the pages its thread left mapped for the caller to release in
    /// this process; none when no such ordinal is left. A thread creation vacates them all before
    /// it places its TEB, so the TEBs Windows 2000 would have freed at their threads' ends are
    /// free to it.
    pub fn vacate(&mut self, mut live: impl FnMut(ObjectId) -> bool) -> Option<Leftover> {
        self.created.iter_mut().find_map(|slot| match *slot {
            Slot::Held { thread, stack, teb } if !live(thread) => {
                *slot = Slot::Free;
                Some(Leftover { teb, stack })
            }
            _ => None,
        })
    }

    /// The thread object holding `ordinal`, its thread live or terminated; none for an ordinal
    /// not held.
    #[cfg(test)]
    pub fn holder(&self, ordinal: u16) -> Option<ObjectId> {
        let slot = match ordinal {
            MAIN => &self.main,
            ordinal => self.created.get(ordinal as usize - 1)?,
        };
        match slot {
            Slot::Free => None,
            Slot::Held { thread, .. } => Some(*thread),
        }
    }

    /// Every ordinal whose TEB page is mapped, as (ordinal, TEB address), in ordinal order: the
    /// main thread's, then each created thread's, terminated ones too (their pages stay mapped
    /// until the ordinal is vacated or reused).
    pub fn tebs(&self) -> impl Iterator<Item = (u32, u32)> + '_ {
        core::iter::once(&self.main)
            .chain(self.created.iter())
            .enumerate()
            .filter_map(|(ordinal, slot)| match *slot {
                Slot::Free => None,
                Slot::Held { teb, .. } => Some((ordinal as u32, teb)),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ob::ObjectType;
    use crate::slots::HostPages;
    use crate::user::TEB_PAGE;

    fn thread(index: u16, generation: u16) -> ObjectId {
        ObjectId {
            kind: ObjectType::Thread,
            index,
            generation,
        }
    }

    /// A created thread's TEB as the tests place them: one page down per ordinal.
    fn teb(ordinal: u16) -> u32 {
        TEB_PAGE - ordinal as u32 * 4096
    }

    /// Take the next ordinal for `holder`, its TEB the test's.
    fn take(ordinals: &mut Ordinals, pages: &HostPages, holder: ObjectId) -> u16 {
        let ordinal = ordinals.free(pages, |_| true).unwrap();
        assert_eq!(
            ordinals.hold(ordinal, holder, 0x0050_0000, teb(ordinal)),
            None
        );
        ordinal
    }

    /// The main thread holds ordinal 0 and the fixed TEB page; created threads take the lowest
    /// free ordinal from 1, never 0, past a chunk's worth and on, as long as pages last; a
    /// process with only its main thread holds no page.
    #[test]
    fn the_main_thread_holds_ordinal_zero_and_created_threads_count_from_one() {
        let pages = HostPages::new();
        let mut ordinals = Box::new(Ordinals::empty());
        ordinals.hold_main(thread(5, 0), 0);
        assert_eq!(ordinals.holder(MAIN), Some(thread(5, 0)));
        assert_eq!(ordinals.tebs().collect::<Vec<_>>(), vec![(0, TEB_PAGE)]);
        assert_eq!(pages.held(), 0, "the main thread's ordinal is inline");
        let many = 3 * PER as u16 + 7;
        for index in 1..=many {
            assert_eq!(take(&mut ordinals, &pages, thread(100 + index, 0)), index);
        }
        assert_eq!(
            pages.held(),
            4 + 1,
            "a chunk of the pool per page's worth of threads, and a directory page past one"
        );
        assert_eq!(ordinals.tebs().count(), many as usize + 1);
        assert_eq!(ordinals.tebs().last(), Some((many as u32, teb(many))));
        // No page for more: the next creation fails, the ordinals held stay.
        pages.set_budget(0);
        let full = (PER * 4) as u16;
        for index in many + 1..=full {
            assert_eq!(take(&mut ordinals, &pages, thread(1, index)), index);
        }
        assert_eq!(ordinals.free(&pages, |_| true), None, "no page left");
        // Even with every thread gone, ordinal 0 stays the main thread's.
        assert_eq!(ordinals.free(&pages, |_| false), Some(1));
        // The process's object gone: every page back.
        ordinals.release(&pages);
        assert_eq!(pages.held(), 0);
        assert_eq!(ordinals.tebs().count(), 1);
    }

    /// A created process has no main thread until its first thread takes ordinal 0, over the
    /// stack its creator reserved; created threads still count from 1. A process record taken
    /// again starts over, its pages back.
    #[test]
    fn a_created_process_has_no_main_thread_until_its_first() {
        let pages = HostPages::new();
        let mut ordinals = Box::new(Ordinals::empty());
        assert!(!ordinals.has_main());
        assert_eq!(ordinals.tebs().count(), 0);
        ordinals.hold_main(thread(3, 0), 0x0003_0000);
        assert!(ordinals.has_main());
        assert_eq!(ordinals.tebs().collect::<Vec<_>>(), vec![(0, TEB_PAGE)]);
        assert_eq!(take(&mut ordinals, &pages, thread(4, 0)), 1);
        ordinals.close();
        ordinals.reset(&pages);
        assert_eq!(pages.held(), 0);
        assert!(!ordinals.has_main() && !ordinals.closed());
        assert_eq!(ordinals.tebs().count(), 0);
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
    /// independently: each its own ordinals from 1, each thread's TEB the one its creation
    /// placed in its own address space.
    #[test]
    fn two_processes_number_their_threads_independently() {
        let pages = HostPages::new();
        let (mut a, mut b) = (Box::new(Ordinals::empty()), Box::new(Ordinals::empty()));
        // The pool hands out records 0, 1, 2, 3 ... alternately to the two processes.
        a.hold_main(thread(0, 0), 0);
        b.hold_main(thread(1, 0), 0);
        let mut records = 2..;
        let mut next = |ordinals: &mut Ordinals| {
            let record = records.next().unwrap();
            (take(ordinals, &pages, thread(record, 0)), record)
        };
        assert_eq!(next(&mut a), (1, 2));
        assert_eq!(next(&mut b), (1, 3));
        assert_eq!(next(&mut b), (2, 4));
        assert_eq!(next(&mut a), (2, 5));
        let expected = vec![(0, TEB_PAGE), (1, teb(1)), (2, teb(2))];
        assert_eq!(a.tebs().collect::<Vec<_>>(), expected);
        assert_eq!(b.tebs().collect::<Vec<_>>(), expected);
        assert_eq!(a.holder(2), Some(thread(5, 0)));
        assert_eq!(b.holder(2), Some(thread(4, 0)));
        a.release(&pages);
        b.release(&pages);
    }

    /// A terminated thread's ordinal is vacated or reused only once its object is gone, and
    /// hands back its pages for release — in the ordinal's own process, even when another
    /// process's thread has taken the dead thread's record since: the other process's ledger is
    /// untouched.
    #[test]
    fn a_reused_ordinal_releases_its_pages_in_its_own_process() {
        let pages = HostPages::new();
        let (mut a, mut b) = (Box::new(Ordinals::empty()), Box::new(Ordinals::empty()));
        a.hold_main(thread(0, 0), 0);
        b.hold_main(thread(1, 0), 0);
        let first = thread(2, 0);
        assert_eq!(a.free(&pages, |_| true), Some(1));
        assert_eq!(a.hold(1, first, 0x0060_0000, 0x7FFD_D000), None);

        // The thread ended but a handle still references it: its ordinal stays held.
        assert_eq!(a.free(&pages, |id| id == first), Some(2));
        assert_eq!(a.vacate(|id| id == first), None);
        // Its object is gone: the record goes to process B's next thread (generation 1), and the
        // ordinal is A's to reuse.
        let reborn = thread(2, 1);
        let live = |id: ObjectId| id != first;
        let b_ordinal = b.free(&pages, live).unwrap();
        assert_eq!(
            b.hold(b_ordinal, reborn, 0x0070_0000, 0x7FFD_D000),
            None,
            "B's pages are fresh"
        );
        assert_eq!(a.free(&pages, live), Some(1));
        let left = a.hold(1, thread(6, 0), 0x0080_0000, 0x7FFD_C000);
        assert_eq!(
            left,
            Some(Leftover {
                teb: 0x7FFD_D000,
                stack: 0x0060_0000,
            }),
            "A's own pages, at A's ordinal"
        );
        assert_eq!(b.holder(1), Some(reborn), "B keeps its thread and pages");
        a.release(&pages);
        b.release(&pages);
    }

    /// A creation vacates every ordinal whose thread's object is gone, lowest first, handing
    /// back each one's pages once; the live ones and the main thread's stay.
    #[test]
    fn vacating_frees_the_gone_threads_ordinals() {
        let pages = HostPages::new();
        let mut ordinals = Box::new(Ordinals::empty());
        ordinals.hold_main(thread(0, 0), 0);
        for index in 1..=4 {
            take(&mut ordinals, &pages, thread(index, 0));
        }
        // The threads of records 1 and 3 are gone.
        let live = |id: ObjectId| id.index % 2 == 0;
        let mut left = Vec::new();
        while let Some(leftover) = ordinals.vacate(live) {
            left.push(leftover.teb);
        }
        assert_eq!(left, vec![teb(1), teb(3)]);
        assert_eq!(ordinals.holder(MAIN), Some(thread(0, 0)));
        assert_eq!(
            ordinals
                .tebs()
                .map(|(ordinal, _)| ordinal)
                .collect::<Vec<_>>(),
            vec![0, 2, 4]
        );
        assert_eq!(ordinals.free(&pages, |_| true), Some(1));
        ordinals.release(&pages);
    }
}
