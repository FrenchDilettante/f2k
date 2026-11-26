//! The GDI handle table: one system-wide table of the GDI objects every process made (DCs,
//! brushes, bitmaps, fonts, regions), as Windows 2000's GDI keeps its own handle table beside the
//! processes' object handle tables.
//!
//! A GDI object is an object of the object manager ([`crate::ob`]'s Dc, Brush, Bitmap, Font and
//! Region types), and the table's entry holds its creator's reference on it, never a handle in its
//! process's handle table: CloseHandle and DuplicateHandle know nothing of GDI objects, and a
//! process's handle count does not include them, as on Windows 2000. The entry names its owner,
//! the process that made the object, and only the owner finds it: a handle another process
//! passes along names nothing there (STATUS_INVALID_HANDLE, as Windows 2000's GDI handles are
//! valid in their own process alone). The stock objects and the other global objects
//! ([`rtl::gdi::global_object_kind`]) are not in the table: their handles are constants every
//! process names alike.
//!
//! A handle is [`GdiHandle`]'s shape: the slot's index in the low word, the object's kind in bits
//! 16-19 ([`rtl::gdi::object_handle`]; a DC's clear), the stock bit (23) clear, and the slot's
//! uniqueness in bits 24-31, so a deleted object's handle names nothing even once its slot is
//! taken again (the slot comes back with a uniqueness one more). The slot freed last is reused
//! first. 16,384 slots at most, Windows 2000's own ceiling, in chunks of one page made as the
//! table grows and kept at its peak.
//!
//! DeleteObject frees the entry and drops its reference ([`delete`]); the process's teardown frees
//! every entry the process still owns and drops their references ([`end_process`]), as Windows
//! 2000 frees a process's GDI objects at its end.
//!
//! Lock order: the table's lock is taken alone. A look-up copies the object's id out and
//! references it after the release, by id: an object deleted between the two is a reference that
//! fails (its id's generation moved on), so nothing the table hands out ever names another object.

use rtl::dib::OBJ_BITMAP;
use rtl::gdi::{object_handle, OBJ_BRUSH, OBJ_FONT, OBJ_REGION};

use crate::ob::{ObjectId, ObjectType};
use crate::slots::{per_page, Codec, GdiHandle, Inline, Pages, Record, Slots};

/// A DC's kind in its handle's bits: none (rtl::gdi's object_of tells a DC by their absence).
pub const DC_KIND: u32 = 0;

/// The bits of a handle's high word below the uniqueness: the kind, the rest of the type field
/// and the stock bit.
const TYPE_BITS: u32 = 0x00FF_0000;

/// A table entry: the object (its creator's reference, which the entry holds) and its owner, the
/// process that made it, by its object's index.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GdiEntry {
    object: ObjectId,
    owner: u16,
}

// SAFETY: writes a whole entry (an id that names nothing, generation 0).
unsafe impl Record for GdiEntry {
    unsafe fn write_fresh(at: *mut Self, _: u32) {
        // SAFETY: the caller's contract.
        unsafe {
            at.write(GdiEntry {
                object: ObjectId {
                    kind: ObjectType::Dc,
                    index: 0,
                    generation: 0,
                },
                owner: 0,
            })
        };
    }
}

/// Entries in a chunk: one page's (16-byte slots).
const PER: usize = per_page::<GdiEntry>();

/// Chunks at most: Windows 2000's 16,384 entries.
const CHUNKS: usize = (GdiHandle::MAX_INDEX as usize + 1).div_ceil(PER);

const _: () = assert!(PER == 256 && CHUNKS == 64);

/// The kind bits of an object of `kind`'s handles; none for a kind that is no GDI object.
pub const fn kind_bits(kind: ObjectType) -> Option<u32> {
    match kind {
        ObjectType::Dc => Some(DC_KIND),
        ObjectType::Brush => Some(OBJ_BRUSH),
        ObjectType::Bitmap => Some(OBJ_BITMAP),
        ObjectType::Font => Some(OBJ_FONT),
        ObjectType::Region => Some(OBJ_REGION),
        _ => None,
    }
}

/// The GDI handle table.
pub struct GdiTable {
    slots: Slots<GdiEntry, GdiHandle, PER, Inline<CHUNKS>>,
}

impl Default for GdiTable {
    fn default() -> Self {
        Self::new()
    }
}

impl GdiTable {
    /// An empty table: no chunk made.
    pub const fn new() -> Self {
        GdiTable {
            slots: Slots::new(),
        }
    }

    /// An entry for `object` (a GDI object's, holding its creator's reference from now on) owned
    /// by the process `owner`: its handle, the object's kind in its bits. None when the table is
    /// full or no page is left for its next chunk.
    ///
    /// # Panics
    ///
    /// `object` is no GDI object's.
    pub fn insert(&mut self, owner: u16, object: ObjectId, pages: &impl Pages) -> Option<u32> {
        let kind = kind_bits(object.kind).expect("a GDI object");
        let (id, entry) = self.slots.allocate_or_grow(0, pages).ok()?;
        *entry = GdiEntry { object, owner };
        Some(object_handle(kind, id))
    }

    /// The object `handle` names for the process `owner`: an entry it owns whose kind and
    /// uniqueness the handle carries exactly. None for any other handle: another process's, a
    /// deleted object's, a global object's, or one past the table.
    pub fn find(&self, owner: u16, handle: u32) -> Option<ObjectId> {
        let entry = self.slots.get(handle)?;
        let kind = kind_bits(entry.object.kind)?;
        (entry.owner == owner && handle & TYPE_BITS == object_handle(kind, 0))
            .then_some(entry.object)
    }

    /// Free the entry `handle` names for `owner` (see [`GdiTable::find`]): the object whose
    /// reference it held, which the caller now holds. None when it names none.
    pub fn remove(&mut self, owner: u16, handle: u32) -> Option<ObjectId> {
        let object = self.find(owner, handle)?;
        self.slots.free(handle);
        Some(object)
    }

    /// Free up to `out.len()` of the entries `owner` owns, in slot order, their objects (the
    /// references they held, which the caller now holds) into `out`: how many. Fewer than
    /// `out.len()` when no entry of `owner` is left.
    pub fn take_owned(&mut self, owner: u16, out: &mut [Option<ObjectId>]) -> usize {
        let mut handles = [0u32; TAKE_STEP];
        let room = out.len().min(TAKE_STEP);
        let mut count = 0;
        for (id, entry) in self.slots.iter() {
            if count == room {
                break;
            }
            if entry.owner == owner {
                handles[count] = id;
                out[count] = Some(entry.object);
                count += 1;
            }
        }
        for &handle in &handles[..count] {
            self.slots.free(handle);
        }
        count
    }

    /// The entries live: every process's GDI objects.
    pub fn live(&self) -> u32 {
        self.slots.live()
    }

    /// The entries `owner` owns.
    #[cfg(test)]
    pub fn owned(&self, owner: u16) -> usize {
        self.slots
            .iter()
            .filter(|(_, entry)| entry.owner == owner)
            .count()
    }
}

/// The entries a teardown takes out of the table in one hold (see [`end_process`]).
pub const TAKE_STEP: usize = 32;

// --- The kernel's table --------------------------------------------------------------------------

#[cfg(target_arch = "x86")]
mod target {
    use super::*;
    use crate::slots::KERNEL_PAGES;
    use crate::sync::ShortLock;

    /// The kernel's GDI table, behind its short lock.
    static TABLE: ShortLock<GdiTable> = ShortLock::new(GdiTable::new());

    /// Run `f` on the locked table (the bridge for code without a passive token: see
    /// `crate::win32k::window::locked`). Nothing else is locked inside.
    fn with_table<R>(f: impl FnOnce(&mut GdiTable) -> R) -> R {
        assert_eq!(
            crate::pcr::pcr().current(),
            crate::interrupt::irql::PASSIVE,
            "the GDI table's bridge entered above the passive level"
        );
        // SAFETY: a passive entry (see `At::enter`): the ledger reads the passive level, and the
        // token stays on this thread, dropped with this frame.
        let mut passive = unsafe { crate::level::At::<crate::level::Passive>::enter() };
        let mut table = TABLE.lock(&mut passive);
        f(&mut table)
    }

    /// The calling process, as the table names an owner: its object's index.
    fn owner() -> u16 {
        crate::process::current().object().index
    }

    /// Publish a new GDI object `object` for the calling process: an entry holding its creator's
    /// reference, its handle answered. A full table takes the object back with it (none).
    pub fn insert(object: ObjectId) -> Option<u32> {
        let owner = owner();
        let handle = with_table(|table| table.insert(owner, object, &KERNEL_PAGES));
        if handle.is_none() {
            crate::ob::release(object);
        }
        handle
    }

    /// The object of `kind` (its handle's kind bits: [`DC_KIND`], OBJ_BRUSH...) the calling
    /// process's `handle` names; none for a handle naming nothing of that kind there.
    pub fn object(handle: u32, kind: u32) -> Option<ObjectId> {
        let owner = owner();
        with_table(|table| table.find(owner, handle))
            .filter(|object| kind_bits(object.kind) == Some(kind))
    }

    /// [`object`], referenced for as long as the caller keeps the reference (none when it went
    /// meanwhile).
    pub fn reference(handle: u32, kind: u32) -> Option<crate::ob::ObRef> {
        crate::ob::reference(object(handle, kind)?)
    }

    /// Whether the calling process's `handle` names a GDI object of any kind.
    pub fn names(handle: u32) -> bool {
        let owner = owner();
        with_table(|table| table.find(owner, handle)).is_some()
    }

    /// DeleteObject's step: the calling process's `handle`, when it names an object of `kind`,
    /// freed and its reference dropped (the object goes with its last reference). False when it
    /// names none.
    pub fn delete(handle: u32, kind: u32) -> bool {
        let owner = owner();
        let object = with_table(|table| {
            let object = table.find(owner, handle)?;
            if kind_bits(object.kind) != Some(kind) {
                return None;
            }
            table.remove(owner, handle)
        });
        match object {
            Some(object) => {
                crate::ob::release(object);
                true
            }
            None => false,
        }
    }

    /// The process `owner` (its object's index) has ended: every GDI object it still owns is freed,
    /// a step of [`TAKE_STEP`] entries out of the table in one hold and their references dropped
    /// after it.
    pub fn end_process(owner: u16) {
        loop {
            let mut step = [None; TAKE_STEP];
            let taken = with_table(|table| table.take_owned(owner, &mut step));
            for object in step.into_iter().flatten() {
                crate::ob::release(object);
            }
            if taken < TAKE_STEP {
                break;
            }
        }
    }

    /// The table's live entries: every process's GDI objects (the quiescent audit's count, 0 with
    /// no process left).
    pub fn live() -> u32 {
        with_table(|table| table.live())
    }
}

#[cfg(target_arch = "x86")]
pub use target::*;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::slots::HostPages;

    fn object(kind: ObjectType, index: u16) -> ObjectId {
        ObjectId {
            kind,
            index,
            generation: 1,
        }
    }

    const ONE: u16 = 3;
    const OTHER: u16 = 5;

    /// A handle carries its slot in the low word, its kind in bits 16-19 (a DC's clear) and its
    /// uniqueness, from 1, in bits 24-31, the stock bit clear; rtl::gdi reads its kind back.
    #[test]
    fn handles_carry_their_slot_kind_and_uniqueness() {
        let pages = HostPages::new();
        let mut table = GdiTable::new();
        let dc = table
            .insert(ONE, object(ObjectType::Dc, 1), &pages)
            .unwrap();
        let brush = table
            .insert(ONE, object(ObjectType::Brush, 1), &pages)
            .unwrap();
        let font = table
            .insert(ONE, object(ObjectType::Font, 1), &pages)
            .unwrap();
        let bitmap = table
            .insert(ONE, object(ObjectType::Bitmap, 1), &pages)
            .unwrap();
        let region = table
            .insert(ONE, object(ObjectType::Region, 1), &pages)
            .unwrap();
        assert_eq!(dc, 0x0100_0001);
        assert_eq!(brush, 0x0102_0002);
        assert_eq!(font, 0x0106_0003);
        assert_eq!(bitmap, 0x0107_0004);
        assert_eq!(region, 0x0108_0005, "OBJ_REGION, 8: the kind bits' widest");
        assert_eq!(
            rtl::gdi::object_of(dc),
            None,
            "a DC's handle has no kind bits"
        );
        assert_eq!(rtl::gdi::object_kind(brush), Some(OBJ_BRUSH));
        assert_eq!(rtl::gdi::object_kind(font), Some(OBJ_FONT));
        assert_eq!(rtl::gdi::object_kind(bitmap), Some(OBJ_BITMAP));
        assert_eq!(rtl::gdi::object_kind(region), Some(OBJ_REGION));
        for handle in [dc, brush, font, bitmap, region] {
            assert_eq!(handle & crate::slots::GDI_STOCK, 0);
            assert_eq!(rtl::gdi::global_object_kind(handle), None);
        }
    }

    /// Only the owner finds its objects: another process's look-up, its delete and its teardown
    /// leave them be.
    #[test]
    fn another_process_finds_nothing() {
        let pages = HostPages::new();
        let mut table = GdiTable::new();
        let brush = object(ObjectType::Brush, 7);
        let handle = table.insert(ONE, brush, &pages).unwrap();
        assert_eq!(table.find(ONE, handle), Some(brush));
        assert_eq!(table.find(OTHER, handle), None);
        assert_eq!(table.remove(OTHER, handle), None);
        let mut out = [None; 4];
        assert_eq!(table.take_owned(OTHER, &mut out), 0);
        assert_eq!(table.find(ONE, handle), Some(brush));
        assert_eq!(table.remove(ONE, handle), Some(brush));
    }

    /// A deleted object's handle names nothing, even once its slot is taken again: the slot freed
    /// last comes back first, its uniqueness one more.
    #[test]
    fn a_deleted_objects_handle_goes_stale() {
        let pages = HostPages::new();
        let mut table = GdiTable::new();
        let first = table
            .insert(ONE, object(ObjectType::Brush, 1), &pages)
            .unwrap();
        let kept = table
            .insert(ONE, object(ObjectType::Brush, 2), &pages)
            .unwrap();
        assert_eq!(table.remove(ONE, first), Some(object(ObjectType::Brush, 1)));
        assert_eq!(table.find(ONE, first), None);
        assert_eq!(
            table.remove(ONE, first),
            None,
            "a second delete finds nothing"
        );
        let again = table
            .insert(ONE, object(ObjectType::Brush, 3), &pages)
            .unwrap();
        assert_eq!(again & 0xFFFF, first & 0xFFFF, "the slot freed last");
        assert_eq!(again >> 24, (first >> 24) + 1);
        assert_eq!(table.find(ONE, first), None);
        assert_eq!(table.find(ONE, again), Some(object(ObjectType::Brush, 3)));
        assert_eq!(table.find(ONE, kept), Some(object(ObjectType::Brush, 2)));
    }

    /// A handle whose kind bits are another kind's, whose stock bit or type bits are set, or whose
    /// uniqueness is 0 or another, names nothing; stock objects' handles name no entry.
    #[test]
    fn forged_handles_name_nothing() {
        let pages = HostPages::new();
        let mut table = GdiTable::new();
        let handle = table
            .insert(ONE, object(ObjectType::Brush, 1), &pages)
            .unwrap();
        let slot = handle & 0xFFFF;
        for forged in [
            slot,
            slot | 0x0002_0000,
            rtl::gdi::object_handle(OBJ_FONT, handle),
            handle & !0x0007_0000,
            handle | crate::slots::GDI_STOCK,
            handle | 0x0008_0000,
            handle + 0x0100_0000,
            0,
            0xFFFF_FFFF,
        ] {
            assert_eq!(table.find(ONE, forged), None, "{forged:#x}");
        }
        for index in 0..=rtl::gdi::DEFAULT_GUI_FONT {
            if let Some(stock) = rtl::gdi::stock_handle(index) {
                assert_eq!(table.find(ONE, stock), None);
                assert_eq!(table.find(0, stock), None);
            }
        }
        assert_eq!(table.find(ONE, handle), Some(object(ObjectType::Brush, 1)));
    }

    /// A process's end takes every entry it owns, a step at a time, and no other process's.
    #[test]
    fn the_teardown_sweep_takes_the_owners_entries() {
        let pages = HostPages::new();
        let mut table = GdiTable::new();
        let kinds = [
            ObjectType::Dc,
            ObjectType::Brush,
            ObjectType::Bitmap,
            ObjectType::Font,
            ObjectType::Region,
        ];
        let mut others = std::vec::Vec::new();
        for index in 0..(TAKE_STEP as u16 * 2 + 5) {
            let kind = kinds[index as usize % kinds.len()];
            table.insert(ONE, object(kind, index), &pages).unwrap();
            let other = object(kind, 1000 + index);
            others.push((table.insert(OTHER, other, &pages).unwrap(), other));
        }
        assert_eq!(table.owned(ONE), TAKE_STEP * 2 + 5);
        let mut taken = std::vec::Vec::new();
        loop {
            let mut step = [None; TAKE_STEP];
            let count = table.take_owned(ONE, &mut step);
            taken.extend(step.into_iter().flatten());
            if count < TAKE_STEP {
                break;
            }
        }
        assert_eq!(taken.len(), TAKE_STEP * 2 + 5);
        assert!(taken.iter().all(|object| object.index < 1000));
        assert_eq!(table.owned(ONE), 0);
        assert_eq!(table.live() as usize, others.len());
        for (handle, other) in others {
            assert_eq!(table.find(OTHER, handle), Some(other));
        }
    }

    /// The table stops at Windows 2000's 16,384 entries (slot 0 never handed out), and grows a
    /// page at a time on the way; a failed page leaves it as it was.
    #[test]
    fn the_table_fills_at_its_ceiling() {
        let pages = HostPages::with_budget(1);
        let mut table = GdiTable::new();
        let mut handles = std::vec::Vec::new();
        while let Some(handle) = table.insert(ONE, object(ObjectType::Brush, 1), &pages) {
            handles.push(handle);
        }
        assert_eq!(handles.len(), PER - 1, "one page's slots, slot 0 reserved");
        pages.set_budget(CHUNKS);
        while let Some(handle) = table.insert(ONE, object(ObjectType::Brush, 1), &pages) {
            handles.push(handle);
        }
        assert_eq!(handles.len(), 0x3FFF);
        assert_eq!(handles.last().map(|handle| handle & 0xFFFF), Some(0x3FFF));
        assert_eq!(table.live(), 0x3FFF);
        assert!(handles
            .iter()
            .all(|&handle| table.find(ONE, handle).is_some()));
    }
}
