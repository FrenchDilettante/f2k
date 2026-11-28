//! The handle table: the per-process indirection between the Win32 handle values programs pass
//! around and the kernel's objects.
//!
//! One table per process, a slot pool ([`crate::slots::Slots`] on the [`NtHandle`] codec): each
//! slot holds an entry — what the handle names (an object, by its id), the access it was granted,
//! and whether it is inherited — or nothing. The handle value encodes its slot as the index
//! shifted left two — the platform's documented shape, a multiple of four with the low tag bits
//! ignored on lookup — and slot zero is never handed out, so the first handle is 4 and no valid
//! handle is zero or the all-ones pseudo-handle. Freed slots are reused most-recently-freed-first,
//! before any slot never used (Windows 2000's free list: ExDestroyHandle pushes on its head).
//!
//! The table grows a page of slots at a time as inserts need them, with no cap but the format's:
//! 2^24 − 1 handles, Windows' own per process; memory runs out long before. It keeps its peak
//! while its process lives, as Windows 2000's does, and gives every page back when the process's
//! exit empties it ([`HandleTable::drain`]).
//!
//! A slot can be reserved before what it will name exists (a create that must not fail once its
//! object is made takes its slot first): a reserved slot names nothing — a lookup or a close of its
//! handle misses — and no insert hands it out, until its entry fills it or the reservation is
//! dropped.
//!
//! The table keeps only the slot discipline: the objects' counts are the object manager's (see
//! [`crate::ob`]), which the process keeps in step with every insert and close. The table's owner
//! is the process record, whose handle lock guards it (growing under it is legal: it is a short
//! lock at the passive level); the process's exit closes every handle through the object manager.

use crate::ob::Entry;
use crate::slots::{per_page, NtHandle, Record, Slots};

/// A handle's slot index: the value shifted right two (the low two tag bits are ignored on decode).
pub const HANDLE_SHIFT: u32 = 2;

/// The lowest slot a handle names: slot 0 is never handed out.
pub const FIRST_HANDLE_INDEX: u32 = 1;

/// The pages the table grows from: the nonpaged pool on target, the host allocator in tests.
#[cfg(target_arch = "x86")]
type KernelPages = crate::slots::NonpagedPages;
#[cfg(not(target_arch = "x86"))]
type KernelPages = crate::slots::HostPages;

/// A slot's record: its entry while the slot is live (the pool's state says which slots are).
#[derive(Clone, Copy)]
struct Held(Option<Entry>);

// SAFETY: `write_fresh` writes the whole record.
unsafe impl Record for Held {
    unsafe fn write_fresh(at: *mut Self, _: u32) {
        // SAFETY: the caller's contract.
        unsafe { at.write(Held(None)) };
    }
}

/// Slots to a chunk: one page's worth (a 12-byte entry in a 20-byte slot).
pub const SLOTS_PER_PAGE: usize = per_page::<Held>();
const PER: usize = SLOTS_PER_PAGE;

type Table = Slots<Held, NtHandle, PER>;

const _: () = assert!(PER == 204 && Table::CHUNK_PAGES == 1);

/// A process's handle table (see the module notes).
pub struct HandleTable {
    slots: Table,
    pages: &'static KernelPages,
}

impl HandleTable {
    /// An empty table, holding no page: its first insert makes its first.
    pub const fn new() -> Self {
        HandleTable {
            slots: Slots::new(),
            pages: &crate::slots::KERNEL_PAGES,
        }
    }

    /// An empty table growing from `pages`: a test's, whose budget makes the table refuse.
    #[cfg(not(target_arch = "x86"))]
    pub const fn on(pages: &'static KernelPages) -> Self {
        HandleTable {
            slots: Slots::new(),
            pages,
        }
    }

    /// Make the table the empty one again, every page given back.
    pub fn reset(&mut self) {
        // SAFETY: every chunk came from `self.pages`; the entries are copies, so nothing refers
        // into a record, and the table's owner holds it exclusively (its lock) meanwhile.
        unsafe { self.slots.reset(self.pages) };
    }

    /// Insert `entry`, returning its handle. Null when no slot is to be had: the table's next one
    /// needs a page and none is left (or, never in practice, the format's 2^24 − 1 are taken).
    pub fn insert(&mut self, entry: Entry) -> u32 {
        match self.slots.allocate_or_grow(0, self.pages) {
            Ok((handle, held)) => {
                *held = Held(Some(entry));
                handle
            }
            Err(_) => 0,
        }
    }

    /// Reserve a slot for an entry to come (see the module notes), returning its handle. Null when
    /// no slot is to be had, as for an insert.
    pub fn reserve(&mut self) -> u32 {
        self.slots.reserve_or_grow(0, self.pages).unwrap_or(0)
    }

    /// Fill the slot `handle` reserved with `entry`. False, nothing filled, when the handle names
    /// no reservation (the table was emptied since: a drain or a reset drops the reservations).
    pub fn fill(&mut self, handle: u32, entry: Entry) -> bool {
        let Some(held) = self.slots.fill(handle) else {
            return false;
        };
        *held = Held(Some(entry));
        true
    }

    /// Drop the reservation `handle` names: its slot is free again. False when it names none.
    pub fn unreserve(&mut self, handle: u32) -> bool {
        self.slots.unreserve(handle)
    }

    /// Whether the next insert would return no handle: no slot is free and the page the next one
    /// lies in cannot be made. The page, made, is kept for that insert.
    pub fn is_full(&mut self) -> bool {
        match self.slots.reserve_or_grow(0, self.pages) {
            Ok(handle) => {
                // Back on the free list's head: the next insert takes this slot again.
                self.slots.unreserve(handle);
                false
            }
            Err(_) => true,
        }
    }

    /// The entry a handle names, or none. The low tag bits are ignored; a closed, reserved or
    /// out-of-range handle is a miss.
    pub fn lookup(&self, handle: u32) -> Option<Entry> {
        self.slots.get(handle)?.0
    }

    /// Change the entry a handle names in place with `change`; false when the handle names
    /// nothing (the low tag bits ignored, as on lookup).
    pub fn update(&mut self, handle: u32, change: impl FnOnce(Entry) -> Entry) -> bool {
        let Some(Held(Some(entry))) = self.slots.get_mut(handle) else {
            return false;
        };
        *entry = change(*entry);
        true
    }

    /// Release the slot a handle names, returning what it held. None when the handle names nothing
    /// (a double close, a foreign value). What the entry named is the caller's to release.
    pub fn close(&mut self, handle: u32) -> Option<Entry> {
        let entry = self.lookup(handle)?;
        self.slots.free(handle);
        Some(entry)
    }

    /// Empty the table, handing every entry it held to `release` (the process-exit step: every
    /// handle closes at once). The table starts over afterwards, its pages given back.
    pub fn drain(&mut self, mut release: impl FnMut(Entry)) {
        self.slots.drain(|_, held| {
            if let Some(entry) = held.0.take() {
                release(entry);
            }
        });
        self.reset();
    }

    /// One step of an inheritance walked by the caller in slot order, as a child process's table
    /// inherits its creator's inheritable handles (the documented inheritance: same values, same
    /// access): this table, a fresh one, takes `entry` in slot `index`, the parent's, so it has the
    /// same handle value. False, nothing taken, when no page is left for the slot.
    /// [`HandleTable::end_inheritance`] follows the last step.
    ///
    /// # Panics
    ///
    /// The table is not being filled in slot order: a slot was handed out, or one at or past
    /// `index` was taken already.
    pub fn inherit_entry(&mut self, index: u32, entry: Entry) -> bool {
        assert!(
            index >= self.slots.high_water(),
            "a table inherits only while fresh, in slot order"
        );
        match self.slots.place(index, self.pages) {
            Ok((_, held)) => {
                *held = Held(Some(entry));
                true
            }
            Err(_) => false,
        }
    }

    /// End an inheritance: the slots left free below the highest one taken go first to the table's
    /// next inserts, lowest first.
    pub fn end_inheritance(&mut self) {
        self.slots.seal_placed();
    }

    /// How many slots hold an entry `which` accepts.
    pub fn count(&self, which: impl Fn(&Entry) -> bool) -> usize {
        self.slots
            .iter()
            .filter_map(|(_, held)| held.0)
            .filter(|entry| which(entry))
            .count()
    }

    /// How many slots hold an entry.
    pub fn live(&self) -> usize {
        self.slots.live() as usize
    }

    /// One past the highest slot index ever handed out since the table was last emptied: a walk
    /// of every handle stops there.
    pub fn high_water(&self) -> u32 {
        self.slots.high_water()
    }
}

impl Default for HandleTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ob::{ObjectId, ObjectType};
    use crate::slots::HostPages;

    fn event_entry() -> Entry {
        Entry::object(
            ObjectId {
                kind: ObjectType::Event,
                index: 0,
                generation: 0,
            },
            0,
            false,
        )
    }

    fn file_entry(index: u16, access: u32, inherit: bool) -> Entry {
        Entry::object(
            ObjectId {
                kind: ObjectType::File,
                index,
                generation: 0,
            },
            access,
            inherit,
        )
    }

    /// Pages of this test's own, `budget` of them.
    fn budget(pages: usize) -> &'static HostPages {
        Box::leak(Box::new(HostPages::with_budget(pages)))
    }

    /// The slots one page holds that a handle can name: slot 0 never does.
    const FIRST_PAGE: usize = PER - 1;

    /// Fill `child`, a fresh table, with `parent`'s entries `admit` takes, each at its own index,
    /// as the process's inheritance walks it.
    fn inherit(child: &mut HandleTable, parent: &HandleTable, admit: impl Fn(&Entry) -> bool) {
        for index in FIRST_HANDLE_INDEX..parent.high_water() {
            if let Some(entry) = parent.lookup(index << HANDLE_SHIFT).filter(|e| admit(e)) {
                assert!(child.inherit_entry(index, entry));
            }
        }
        child.end_inheritance();
    }

    // --- Group A: encoding, allocation, reuse -------------------------------

    /// The encoding: handles are multiples of four, slot zero is never handed out (the first handle
    /// is 4), and no valid handle collides with zero or the all-ones pseudo-handle.
    #[test]
    fn handles_are_index_shifted_left_two() {
        let mut table = HandleTable::new();
        let h1 = table.insert(event_entry());
        let h2 = table.insert(event_entry());
        assert_eq!(h1, 4);
        assert_eq!(h2, 8);
        assert_eq!(h1 & 0x3, 0);
        assert_ne!(h1, 0);
        assert_ne!(h1, u32::MAX);
        assert_eq!(table.live(), 2);
        table.reset();
    }

    /// A used table, reset, is the empty table, its pages given back.
    #[test]
    fn a_reset_table_is_empty() {
        let pages = budget(usize::MAX);
        let mut table = HandleTable::on(pages);
        assert_eq!(pages.held(), 0, "a new table holds no page");
        table.insert(event_entry());
        table.close(4);
        table.insert(event_entry());
        assert_eq!(pages.held(), 1);
        table.reset();
        assert_eq!(pages.held(), 0);
        assert_eq!(table.live(), 0);
        assert_eq!(table.lookup(4), None);
        assert_eq!(table.insert(event_entry()), 4);
        assert_eq!(table.insert(event_entry()), 8);
        table.reset();
    }

    /// A freed slot is reused before a fresh one, the most recently freed first; the closed value
    /// decodes to nothing in between.
    #[test]
    fn freed_slots_reuse_most_recently_freed_first() {
        let mut table = HandleTable::new();
        let h1 = table.insert(event_entry());
        let h2 = table.insert(event_entry());
        let h3 = table.insert(event_entry());
        assert_eq!((h1, h2, h3), (4, 8, 12));

        assert!(table.close(h2).is_some());
        assert!(table.close(h1).is_some());
        assert_eq!(table.lookup(h1), None, "the closed value is a miss");
        assert_eq!(table.lookup(h2), None);

        // Most recently freed (h1's slot) comes back first.
        assert_eq!(table.insert(event_entry()), h1);
        assert_eq!(table.insert(event_entry()), h2);
        // Then fresh indices continue.
        assert_eq!(table.insert(event_entry()), h3 + 4);
        assert_eq!(table.live(), 4);
        table.reset();
    }

    /// The table grows a page at a time past the old fixed 1,024 slots, every handle a distinct
    /// multiple of four in order; it keeps its peak when its handles close, reusing the slot freed
    /// last first across pages, and gives the pages back only when emptied.
    #[test]
    fn the_table_grows_and_keeps_its_peak() {
        let pages = budget(usize::MAX);
        let mut table = HandleTable::on(pages);
        let count = 5_000u32;
        for index in 1..=count {
            assert_eq!(table.insert(event_entry()), index << HANDLE_SHIFT);
        }
        assert_eq!(table.live(), count as usize);
        // A page a chunk, and the directory's own over them.
        let made = pages.held();
        assert!(made > (count as usize + 1).div_ceil(PER));
        for index in 1..=count {
            assert!(table.close(index << HANDLE_SHIFT).is_some());
        }
        assert_eq!(table.live(), 0);
        assert_eq!(pages.held(), made, "the peak is kept");
        assert_eq!(table.insert(event_entry()), count << HANDLE_SHIFT);
        assert_eq!(table.insert(event_entry()), (count - 1) << HANDLE_SHIFT);
        assert_eq!(pages.held(), made);
        let mut released = 0;
        table.drain(|_| released += 1);
        assert_eq!(released, 2);
        assert_eq!(pages.held(), 0, "an emptied table gives its pages back");
        assert_eq!(table.insert(event_entry()), 4);
        table.reset();
    }

    /// A child's table inherits its creator's inheritable handles at their own values, with their
    /// access, and nothing else; its own handles then fill the gaps below them, lowest first,
    /// before fresh slots past them (the spawn fixture's probe: placeholders left out of the
    /// inheritance leave room below the inherited handle for the child's own).
    #[test]
    fn a_child_inherits_the_inheritable_handles_at_their_values() {
        let mut parent = HandleTable::new();
        let hole = parent.insert(event_entry());
        let kept = parent.insert(file_entry(1, 0x8000_0000, true));
        let left = parent.insert(file_entry(2, 0x4000_0000, false));
        let last = parent.insert(file_entry(3, 0x0012_0089, true));
        assert_eq!((hole, kept, left, last), (4, 8, 12, 16));
        let mut child = HandleTable::new();
        inherit(&mut child, &parent, |entry| entry.inherit);
        assert_eq!(child.lookup(kept), parent.lookup(kept));
        assert_eq!(child.lookup(last), Some(file_entry(3, 0x0012_0089, true)));
        assert_eq!(child.lookup(hole), None);
        assert_eq!(child.lookup(left), None);
        assert_eq!(child.live(), 2);
        // The child's own: the gaps below, lowest first, then past the inherited ones.
        assert_eq!(child.insert(event_entry()), hole);
        assert_eq!(child.insert(event_entry()), left);
        assert_eq!(child.insert(event_entry()), last + 4);
        parent.reset();
        child.reset();
    }

    /// An inherited handle past the first pages keeps its value: the child's table grows to it,
    /// and the gaps below go to the child's own handles lowest first.
    #[test]
    fn an_inherited_handle_past_the_first_pages_keeps_its_value() {
        let mut parent = HandleTable::new();
        for _ in 0..3 * PER {
            parent.insert(event_entry());
        }
        let far = parent.insert(file_entry(7, 1, true));
        assert_eq!(far, ((3 * PER + 1) as u32) << HANDLE_SHIFT);
        let mut child = HandleTable::new();
        inherit(&mut child, &parent, |entry| entry.inherit);
        assert_eq!(child.live(), 1);
        assert_eq!(child.lookup(far), Some(file_entry(7, 1, true)));
        assert_eq!(child.insert(event_entry()), 4);
        assert_eq!(child.insert(event_entry()), 8);
        parent.reset();
        child.reset();
    }

    /// An inheritance that finds no page for a slot takes nothing there, and says so.
    #[test]
    fn an_inheritance_without_a_page_is_refused() {
        let mut child = HandleTable::on(budget(1));
        assert!(child.inherit_entry(5, event_entry()));
        assert!(!child.inherit_entry(PER as u32, event_entry()));
        child.end_inheritance();
        assert_eq!(child.live(), 1);
        assert_eq!(child.insert(event_entry()), 4, "the gaps still go first");
        child.reset();
    }

    /// Nothing inheritable: the child's table is a fresh one.
    #[test]
    fn a_child_with_nothing_to_inherit_starts_fresh() {
        let mut parent = HandleTable::new();
        parent.insert(event_entry());
        let mut child = HandleTable::new();
        inherit(&mut child, &parent, |entry| entry.inherit);
        assert_eq!(child.live(), 0);
        assert_eq!(child.insert(event_entry()), 4);
        parent.reset();
        child.reset();
    }

    /// Lookup: the low two tag bits are ignored, a miss is a miss — zero, a slot never handed out,
    /// one in a page never made, past the format's 2^24 − 1, and the all-ones pseudo-handle all
    /// name nothing.
    #[test]
    fn lookup_ignores_tag_bits_and_misses_cleanly() {
        let mut table = HandleTable::new();
        let handle = table.insert(event_entry());
        assert!(table.lookup(handle).is_some());
        assert!(
            table.lookup(handle | 0x3).is_some(),
            "the tag bits are ignored"
        );
        assert_eq!(table.lookup(0), None);
        assert_eq!(table.lookup(handle + 4), None);
        assert_eq!(table.lookup(1024 << HANDLE_SHIFT), None);
        assert_eq!(table.lookup(1 << 26), None);
        assert_eq!(table.lookup(u32::MAX), None);
        assert_eq!(table.close(u32::MAX), None);
        table.reset();
    }

    /// Exhaustion: with no page left for the next slot, a create returns no handle and the table
    /// stays consistent (closes keep working, and a freed slot is taken again).
    #[test]
    fn a_full_table_refuses_inserts() {
        let mut table = HandleTable::on(budget(1));
        assert!(!table.is_full());
        for _ in 0..FIRST_PAGE {
            assert_ne!(table.insert(event_entry()), 0);
        }
        assert_eq!(table.live(), FIRST_PAGE, "slot 0 never allocated");
        assert!(table.is_full());
        assert_eq!(table.insert(event_entry()), 0, "exhausted: no handle");

        // A close frees a slot again.
        assert!(table.close(4).is_some());
        assert!(!table.is_full());
        assert_eq!(table.insert(event_entry()), 4);
        assert!(table.is_full());
        table.reset();
    }

    /// A reserved slot names nothing and no insert takes it; filled, it names its entry; dropped,
    /// it is the next insert's. A reservation in a full table is refused as an insert is, and the
    /// last slot reserved fills the table (an insert between the check and the fill used to find it
    /// taken, and its caller panicked on the null handle).
    #[test]
    fn a_reserved_slot_waits_for_its_entry() {
        let mut table = HandleTable::new();
        let reserved = table.reserve();
        assert_eq!(reserved, 4);
        assert_eq!(table.lookup(reserved), None);
        assert_eq!(table.close(reserved), None);
        assert_eq!(table.live(), 0);
        let other = table.insert(event_entry());
        assert_eq!(other, 8);
        assert!(table.fill(reserved, file_entry(1, 2, true)));
        assert_eq!(table.lookup(reserved), Some(file_entry(1, 2, true)));
        assert!(
            !table.fill(reserved, event_entry()),
            "a reservation fills once"
        );
        assert!(!table.unreserve(reserved));
        let again = table.reserve();
        assert!(table.unreserve(again));
        assert!(!table.unreserve(again));
        assert_eq!(table.insert(event_entry()), again);
        table.reset();

        let mut full = HandleTable::on(budget(1));
        for _ in 0..FIRST_PAGE - 1 {
            assert_ne!(full.insert(event_entry()), 0);
        }
        let last = full.reserve();
        assert_ne!(last, 0);
        assert!(full.is_full());
        assert_eq!(full.insert(event_entry()), 0);
        assert_eq!(full.reserve(), 0);
        assert!(full.fill(last, event_entry()));
        full.reset();

        let mut drained = HandleTable::new();
        let lost = drained.reserve();
        drained.drain(|_| {});
        assert!(!drained.fill(lost, event_entry()));
        assert!(!drained.unreserve(lost));
    }

    /// The process-exit step: the table hands every entry back and empties in one step.
    #[test]
    fn drain_hands_back_every_entry() {
        let mut table = HandleTable::new();
        table.insert(event_entry());
        table.insert(file_entry(3, 1, false));
        let mut released = Vec::new();
        table.drain(|entry| released.push(entry.target));
        assert_eq!(released.len(), 2);
        assert!(released.contains(&file_entry(3, 0, false).target));
        assert_eq!(table.live(), 0);
        assert_eq!(table.lookup(4), None);
        // And the table works again after.
        assert_eq!(table.insert(event_entry()), 4);
        table.reset();
    }

    /// A double close is refused: the slot was already released.
    #[test]
    fn a_double_close_is_refused() {
        let mut table = HandleTable::new();
        let handle = table.insert(event_entry());
        assert!(table.close(handle).is_some());
        assert_eq!(table.close(handle), None, "the second close finds nothing");
        table.reset();
    }

    /// An update changes the entry in place, at its value; a handle naming nothing is refused.
    #[test]
    fn an_entry_is_updated_in_place() {
        let mut table = HandleTable::new();
        let handle = table.insert(file_entry(1, 0x8000_0000, false));
        assert!(table.update(handle | 3, |entry| Entry {
            inherit: true,
            ..entry
        }));
        assert_eq!(table.lookup(handle), Some(file_entry(1, 0x8000_0000, true)));
        assert!(!table.update(handle + 4, |entry| entry));
        table.close(handle);
        assert!(!table.update(handle, |entry| entry), "a closed handle");
        table.reset();
    }

    // --- Group B: entries ----------------------------------------------------

    /// An entry carries its access and inheritance with what it names, and the count finds the
    /// entries naming one record.
    #[test]
    fn entries_carry_access_and_inheritance() {
        let mut table = HandleTable::new();
        let file = table.insert(file_entry(3, 0x8000_0000, true));
        let again = table.insert(file_entry(3, 0x4000_0000, false));
        table.insert(event_entry());
        let entry = table.lookup(file | 0x3).unwrap();
        assert_eq!((entry.access, entry.inherit), (0x8000_0000, true));
        let target = file_entry(3, 0, false).target;
        assert_eq!(table.count(|entry| entry.target == target), 2);
        table.close(again);
        assert_eq!(table.count(|entry| entry.target == target), 1);
        assert_eq!(
            entry.object_id(),
            Some(ObjectId {
                kind: ObjectType::File,
                index: 3,
                generation: 0
            })
        );
        table.reset();
    }
}
