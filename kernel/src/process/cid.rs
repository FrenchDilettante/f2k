//! The client-id table: every process id and thread id, from one table (Windows 2000's
//! PspCidTable).
//!
//! PspCidTable is a handle table whose entries name processes and threads, so their ids are one
//! namespace: an id is its slot's index shifted left two, a multiple of four, and a process and a
//! thread never share one. Slots 0 to 2 are never handed out — 0 is the idle process's id, 4 no
//! one's and 8 the System process's — so the first id is 12. The slot freed last is handed out
//! first (ExDestroyHandle pushes on its free list's head), the order `manyproc`'s capture shows.
//!
//! An entry names its process or thread object by id ([`Named::Object`]), or a system thread
//! (which no object names: [`Named::SystemThread`]); an entry is reserved before its object's
//! creation can no longer fail, and filled once it cannot ([`reserve`], [`fill`]), so a create that
//! fails takes no id. A look-up ([`lookup`]) is one slot read: what the entry names, which its
//! caller checks is live and has not ended — an ended process's or thread's id names nothing,
//! whatever still holds its object.
//!
//! When an id goes back ([`destroy`]), as Windows 2000's own order shows it (`manyproc`'s capture:
//! the next process takes an ended one's thread id as its process id, and its thread the ended
//! process's id, so the process id went back first, while a handle still held both objects):
//!
//! - a process's id at its end's teardown (`crate::process::reap`), once its GDI objects and its
//!   windows have gone (Windows 2000 frees the process's CID entry after win32k's process callout,
//!   at its end; Windows XP moved it to the object's deletion): the GDI table names an object's
//!   owner by its process id ([`crate::win32k::gdi`]), so a process that took the id while an entry
//!   still named it would own another's objects. A process that never had a thread, and so is never
//!   reaped, gives its id back at its deletion;
//! - a thread's id at its object's deletion (PspThreadDelete): after its process's, when a handle
//!   holds the thread's object past the reap, as the capture's does.
//!
//! Every destroy names the object it expects, and does nothing when the id names something else:
//! a second destroy of a process's id (the reap, then the deletion) finds the id free, or another
//! process's.
//!
//! The table grows a page of slots at a time, and keeps its peak, as Windows 2000's handle tables
//! do. Its limit is the format's — 2^24 − 1 ids, a representation limit far past the 65,535
//! processes and threads the object manager's u16 indices hold — and a create past it, or one
//! that finds no page for the table, fails with STATUS_INSUFFICIENT_RESOURCES. The table is
//! dispatch-level state ([`crate::level::LevelCell`]), so every caller reaches it: the creates
//! at the passive level, the thread deletion inside the object directory's lock, the reap on the
//! idle thread; its pages come from the nonpaged pool, legal there.

use crate::level::{raised, Dispatch, LevelCell};
use crate::ob::ObjectId;
use crate::slots::{per_page, ClientId, Codec, Record, Slots};

/// What a client id names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Named {
    /// A process or thread object (its kind says which).
    Object(ObjectId),
    /// One of the kernel's system threads, which no object names: a look-up finds nothing to
    /// open.
    SystemThread,
}

impl Named {
    /// The process object named, if a process is.
    pub fn process(self) -> Option<ObjectId> {
        match self {
            Named::Object(id) if id.kind == crate::ob::ObjectType::Process => Some(id),
            _ => None,
        }
    }

    /// The thread object named, if a thread object is.
    pub fn thread(self) -> Option<ObjectId> {
        match self {
            Named::Object(id) if id.kind == crate::ob::ObjectType::Thread => Some(id),
            _ => None,
        }
    }
}

/// A slot's record: what its id names while the slot is live (the pool's state says which are).
#[derive(Clone, Copy)]
struct Held(Option<Named>);

// SAFETY: `write_fresh` writes the whole record.
unsafe impl Record for Held {
    unsafe fn write_fresh(at: *mut Self, _: u32) {
        // SAFETY: the caller's contract.
        unsafe { at.write(Held(None)) };
    }
}

/// Slots to a chunk: one page's worth (a 6-byte entry in a 16-byte slot).
const PER: usize = per_page::<Held>();

type Table = Slots<Held, ClientId, PER>;

const _: () = assert!(PER == 256 && Table::CHUNK_PAGES == 1);

// The first slot handed out is the first client id; the System process's id is the reserved slot
// below it.
const _: () = assert!(
    <ClientId as Codec>::RESERVED_LOW * super::CLIENT_ID_STEP == super::FIRST_CLIENT_ID
        && super::FIRST_CLIENT_ID - super::CLIENT_ID_STEP == super::SYSTEM_PROCESS_ID
);

/// The pages the table grows from: the nonpaged pool on target, the host allocator in tests.
#[cfg(target_arch = "x86")]
type KernelPages = crate::slots::NonpagedPages;
#[cfg(not(target_arch = "x86"))]
type KernelPages = crate::slots::HostPages;

/// The table (see the module notes).
pub struct ClientIds {
    slots: Table,
    pages: &'static KernelPages,
}

impl ClientIds {
    /// An empty table, holding no page: its first reservation makes its first.
    pub const fn new() -> Self {
        Self::on(&crate::slots::KERNEL_PAGES)
    }

    /// An empty table growing from `pages`.
    const fn on(pages: &'static KernelPages) -> Self {
        ClientIds {
            slots: Slots::new(),
            pages,
        }
    }

    /// A fresh id, naming nothing until [`ClientIds::fill`]: the one freed last, or the lowest
    /// never handed out. None at the table's limit, or with no page for its next chunk.
    pub fn reserve(&mut self) -> Option<u32> {
        self.slots.reserve_or_grow(0, self.pages).ok()
    }

    /// The reserved `id` names `named` from now on.
    ///
    /// # Panics
    ///
    /// `id` is not reserved.
    pub fn fill(&mut self, id: u32, named: Named) {
        let held = self
            .slots
            .fill(id)
            .expect("a client id filled once reserved");
        *held = Held(Some(named));
    }

    /// A reservation dropped: `id` goes back, first in line for the next reservation.
    pub fn unreserve(&mut self, id: u32) {
        let dropped = self.slots.unreserve(id);
        debug_assert!(dropped, "a client id unreserved once reserved");
    }

    /// What `id` names; none for an id no process or thread holds.
    pub fn lookup(&self, id: u32) -> Option<Named> {
        self.slots.get(id).and_then(|held| held.0)
    }

    /// `id` goes back, if it names `named`: false when it names nothing, or something else.
    pub fn destroy(&mut self, id: u32, named: Named) -> bool {
        if self.lookup(id) != Some(named) {
            return false;
        }
        self.slots.free(id)
    }

    /// The ids that name a process or thread object: none left once every process is gone.
    pub fn objects(&self) -> usize {
        self.slots
            .iter()
            .filter(|(_, held)| matches!(held.0, Some(Named::Object(_))))
            .count()
    }
}

impl Default for ClientIds {
    fn default() -> Self {
        Self::new()
    }
}

/// The kernel's table.
#[cfg(target_arch = "x86")]
static TABLE: LevelCell<Dispatch, ClientIds> = LevelCell::new(ClientIds::new());

#[cfg(target_arch = "x86")]
fn table() -> &'static LevelCell<Dispatch, ClientIds> {
    &TABLE
}

/// The host builds have no boot: each test thread has a table of its own.
#[cfg(not(target_arch = "x86"))]
fn table() -> &'static LevelCell<Dispatch, ClientIds> {
    extern crate std;
    std::thread_local! {
        static TABLE: &'static LevelCell<Dispatch, ClientIds> =
            std::boxed::Box::leak(std::boxed::Box::new(LevelCell::new(ClientIds::new())));
    }
    TABLE.with(|table| *table)
}

/// Run `f` on the table, at the dispatch level.
fn with_table<R>(f: impl FnOnce(&mut ClientIds) -> R) -> R {
    raised::<Dispatch, _>(|dispatch| f(table().get(dispatch)))
}

/// A fresh id for a process or thread about to be made ([`ClientIds::reserve`]); none when the
/// table can't grow (STATUS_INSUFFICIENT_RESOURCES to the create).
pub fn reserve() -> Option<u32> {
    with_table(ClientIds::reserve)
}

/// The reserved `id` names `named` ([`ClientIds::fill`]).
pub fn fill(id: u32, named: Named) {
    with_table(|table| table.fill(id, named));
}

/// A reservation dropped by a create that failed ([`ClientIds::unreserve`]).
pub fn unreserve(id: u32) {
    with_table(|table| table.unreserve(id));
}

/// A fresh id naming `named` at once: a system thread's, which nothing undoes.
///
/// # Panics
///
/// The table can't grow (at boot: the nonpaged pool spent before the first process).
pub fn create(named: Named) -> u32 {
    with_table(|table| {
        let id = table.reserve().expect("a client id for a system thread");
        table.fill(id, named);
        id
    })
}

/// What `id` names ([`ClientIds::lookup`]).
pub fn lookup(id: u32) -> Option<Named> {
    with_table(|table| table.lookup(id))
}

/// `id` goes back if it names `named` ([`ClientIds::destroy`]).
pub fn destroy(id: u32, named: Named) -> bool {
    with_table(|table| table.destroy(id, named))
}

/// The ids naming objects ([`ClientIds::objects`]): the quiescent audit's count of ids an ended
/// process or thread kept.
pub fn objects() -> usize {
    with_table(|table| table.objects())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ob::ObjectType;
    use crate::slots::HostPages;

    fn object(kind: ObjectType, index: u16) -> Named {
        Named::Object(ObjectId {
            kind,
            index,
            generation: 1,
        })
    }

    fn process(index: u16) -> Named {
        object(ObjectType::Process, index)
    }

    fn thread(index: u16) -> Named {
        object(ObjectType::Thread, index)
    }

    /// Reserve and fill in one step.
    fn create(table: &mut ClientIds, named: Named) -> u32 {
        let id = table.reserve().unwrap();
        table.fill(id, named);
        id
    }

    /// Processes and threads share one namespace of multiples of four, from 12 (0, 4 and 8 never
    /// handed out: the idle process, no one, the System process).
    #[test]
    fn ids_are_one_namespace_from_12_by_fours() {
        let mut table = ClientIds::new();
        let ids = [process(1), thread(1), thread(2), process(2)].map(|n| create(&mut table, n));
        assert_eq!(ids, [12, 16, 20, 24]);
        assert_eq!(table.lookup(12), Some(process(1)));
        assert_eq!(table.lookup(16), Some(thread(1)));
        assert_eq!(
            table.lookup(24).and_then(Named::process).map(|id| id.index),
            Some(2)
        );
        assert_eq!(
            table.lookup(24).and_then(Named::thread),
            None,
            "a process's id"
        );
        assert_eq!(
            table.lookup(16).and_then(Named::process),
            None,
            "a thread's id"
        );
        for id in [0, 4, 8, 28, 0x1000] {
            assert_eq!(table.lookup(id), None);
        }
        assert_eq!(
            table.lookup(13),
            Some(process(1)),
            "the low two bits ignored"
        );
    }

    /// The id freed last comes back first: `manyproc`'s `reuse` — the ended process's id freed at
    /// its teardown, its thread's at the thread object's deletion after — gives the next process
    /// the thread's id, and its thread the process's.
    #[test]
    fn the_id_freed_last_comes_back_first() {
        let mut table = ClientIds::new();
        let parent = create(&mut table, process(1));
        let pid = create(&mut table, process(2));
        let tid = create(&mut table, thread(1));
        assert!(table.destroy(pid, process(2)), "at the reap");
        assert!(table.destroy(tid, thread(1)), "at the thread's deletion");
        assert_eq!(table.lookup(pid), None);
        let next_pid = create(&mut table, process(3));
        let next_tid = create(&mut table, thread(2));
        assert_eq!((next_pid, next_tid), (tid, pid));
        assert_eq!(
            create(&mut table, thread(3)),
            24,
            "then the lowest never handed out"
        );
        assert_eq!(table.lookup(parent), Some(process(1)));
    }

    /// An id goes back only from what it names: the process's second destroy (its deletion after
    /// its reap) leaves the process that took its id meanwhile alone.
    #[test]
    fn a_destroy_names_what_it_frees() {
        let mut table = ClientIds::new();
        let id = create(&mut table, process(2));
        assert!(table.destroy(id, process(2)));
        assert!(!table.destroy(id, process(2)), "already free");
        let again = create(&mut table, process(3));
        assert_eq!(again, id);
        assert!(!table.destroy(id, process(2)), "another process's now");
        assert!(!table.destroy(id, thread(2)));
        assert_eq!(table.lookup(id), Some(process(3)));
    }

    /// A reserved id names nothing until filled, and a dropped reservation is the next one's.
    #[test]
    fn a_reservation_names_nothing_until_filled() {
        let mut table = ClientIds::new();
        let id = table.reserve().unwrap();
        assert_eq!(table.lookup(id), None);
        assert!(!table.destroy(id, process(1)));
        table.unreserve(id);
        assert_eq!(table.reserve(), Some(id));
        table.fill(id, thread(4));
        assert_eq!(table.lookup(id), Some(thread(4)));
        assert_eq!(table.objects(), 1);
    }

    /// A system thread's id names no object: nothing to open, and no object the audit counts.
    #[test]
    fn a_system_threads_id_names_no_object() {
        let mut table = ClientIds::new();
        let id = create(&mut table, Named::SystemThread);
        assert_eq!(table.lookup(id), Some(Named::SystemThread));
        assert_eq!(table.lookup(id).and_then(Named::thread), None);
        assert_eq!(table.objects(), 0);
    }

    /// The table grows a page at a time past any count the old counter's users met, and keeps its
    /// peak; with no page left a reservation fails, the table as it was.
    #[test]
    fn the_table_grows_and_refuses_without_a_page() {
        // Three one-page chunks, and the directory page the second one's publication adds.
        let pages: &'static HostPages = Box::leak(Box::new(HostPages::with_budget(4)));
        let mut table = ClientIds::on(pages);
        let count = 3 * PER - 3;
        let ids: Vec<u32> = (0..count)
            .map(|i| create(&mut table, thread(i as u16)))
            .collect();
        assert_eq!(ids.last(), Some(&((3 * PER as u32 - 1) << 2)));
        assert_eq!(table.reserve(), None, "no page for a fourth chunk");
        assert!(table.destroy(ids[100], thread(100)));
        assert_eq!(table.reserve(), Some(ids[100]), "a freed id needs no page");
        assert_eq!(table.objects(), count - 1);
    }

    /// The module's functions reach the test thread's own table.
    #[test]
    fn the_functions_reach_this_threads_table() {
        let id = reserve().unwrap();
        fill(id, process(7));
        assert_eq!(lookup(id), Some(process(7)));
        assert!(destroy(id, process(7)));
        assert_eq!(lookup(id), None);
        assert_eq!(super::create(Named::SystemThread), id);
    }
}
