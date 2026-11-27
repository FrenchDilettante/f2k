//! The GDI handle table: one system-wide table of the GDI objects every process made (DCs,
//! brushes, bitmaps, fonts, regions), as Windows 2000's GDI keeps its own handle table beside the
//! processes' object handle tables.
//!
//! A GDI object is an object of the object manager ([`crate::ob`]'s Dc, Brush, Pen, Bitmap, Font
//! and Region types), and the table's entry holds its creator's reference on it, never a handle in
//! its process's handle table: CloseHandle and DuplicateHandle know nothing of GDI objects, and a
//! process's handle count does not include them, as on Windows 2000. The entry names its owner,
//! the process that made the object, and only the owner finds it: a handle another process
//! passes along names nothing there (STATUS_INVALID_HANDLE, as Windows 2000's GDI handles are
//! valid in their own process alone). The stock objects and the other global objects
//! ([`rtl::gdi::global_object_kind`]) are not in the table: their handles are constants every
//! process names alike.
//!
//! A handle is [`GdiHandle`]'s shape: the slot's index in the low word, the object's kind in bits
//! 16-19 ([`rtl::gdi::object_handle`]; a DC's clear; the entry keeps it, as a pen's is OBJ_PEN or
//! OBJ_EXTPEN by how it was made), the stock bit (23) clear, and the slot's
//! uniqueness in bits 24-31, so a deleted object's handle names nothing even once its slot is
//! taken again (the slot comes back with a uniqueness one more). The slot freed last is reused
//! first. 16,384 slots at most, Windows 2000's own ceiling, in chunks of one page made as the
//! table grows and kept at its peak.
//!
//! DeleteObject frees the entry and drops its reference ([`delete`]); the process's teardown frees
//! every entry the process still owns and drops their references ([`end_process`]), as Windows
//! 2000 frees a process's GDI objects at its end.
//!
//! Each process's GDI objects are counted in its win32k record ([`super::process`]'s
//! `gdi_objects`) from the insert to the delete or the teardown, under the table's lock, and a
//! process holding its quota's worth ([`super::quota::gdi_process_handle_quota`]:
//! GDIProcessHandleQuota, 10,000 by default) gets no entry. A create refused by the quota, by the
//! table's ceiling or for want of a page answers NULL with ERROR_NOT_ENOUGH_MEMORY (8,
//! [`Refusal::status`]): GDI has no error of its own for a full table (`manygdi`'s `quota`
//! predicts it; to confirm). The stock objects are no process's: in no entry, they count for
//! none.
//!
//! Lock order: the table's lock is taken alone. A look-up copies the object's id out and
//! references it after the release, by id: an object deleted between the two is a reference that
//! fails (its id's generation moved on), so nothing the table hands out ever names another object.

use rtl::dib::OBJ_BITMAP;
use rtl::gdi::{object_handle, OBJ_BRUSH, OBJ_FONT, OBJ_PEN, OBJ_REGION};

use super::process::{self, Objects, W32Processes};
use crate::ob::{ObjectId, ObjectType};
use crate::slots::{per_page, Codec, Full, GdiHandle, Inline, Pages, Record, Slots};
use crate::status::{NtStatus, STATUS_NO_MEMORY};

/// A DC's kind in its handle's bits: none (rtl::gdi's object_of tells a DC by their absence).
pub const DC_KIND: u32 = 0;

/// The bits of a handle's high word below the uniqueness: the kind, the rest of the type field
/// and the stock bit.
const TYPE_BITS: u32 = 0x00FF_0000;

/// A table entry: the object (its creator's reference, which the entry holds), its owner, the
/// process that made it, by its object's index (the low byte: a process's index is below 64), and
/// the kind its handle carries (the high byte), in one word so an entry keeps to its 16-byte slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GdiEntry {
    object: ObjectId,
    owner_kind: u16,
}

impl GdiEntry {
    fn owner(&self) -> u16 {
        self.owner_kind & 0xFF
    }

    fn kind(&self) -> u32 {
        u32::from(self.owner_kind >> 8)
    }
}

const _: () = assert!(crate::process::MAX_PROCESSES <= 0x100);

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
                owner_kind: 0,
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
        ObjectType::Pen => Some(OBJ_PEN),
        ObjectType::Bitmap => Some(OBJ_BITMAP),
        ObjectType::Font => Some(OBJ_FONT),
        ObjectType::Region => Some(OBJ_REGION),
        _ => None,
    }
}

/// Why an insert gave no handle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The process holds its quota's worth of GDI objects.
    Quota,
    /// The table holds its 16,384 entries.
    Ceiling,
    /// No page was left for the table's next chunk or the process's record.
    NoMemory,
}

impl Refusal {
    /// The status the create answers: STATUS_NO_MEMORY for each, which gdi32 makes
    /// ERROR_NOT_ENOUGH_MEMORY (8), as Windows 2000's GDI answers a create it has no handle for
    /// (from memory: `manygdi`'s `quota` predicts it, and may find the last error untouched).
    pub const fn status(self) -> NtStatus {
        STATUS_NO_MEMORY
    }
}

/// The GDI handle table.
pub struct GdiTable {
    slots: Slots<GdiEntry, GdiHandle, PER, Inline<CHUNKS>>,
    /// The processes' records, where each one's count of the GDI objects it holds is kept (the
    /// kernel's, shared with the user handle table: [`process::processes`]).
    processes: &'static W32Processes,
}

impl GdiTable {
    /// An empty table, counting in `processes`: no chunk made.
    pub const fn on(processes: &'static W32Processes) -> Self {
        GdiTable {
            slots: Slots::new(),
            processes,
        }
    }

    /// An entry for `object` (a GDI object's, holding its creator's reference from now on) owned
    /// by the process `owner`, counted against its quota: its handle, the object's kind in its
    /// bits. [`Refusal::Quota`] when `owner` holds its quota's worth
    /// ([`super::quota::gdi_process_handle_quota`]), [`Refusal::Ceiling`] when the table is full,
    /// [`Refusal::NoMemory`] when no page is left for its next chunk or the process's record.
    ///
    /// # Panics
    ///
    /// `object` is no GDI object's.
    pub fn insert(
        &mut self,
        owner: u16,
        object: ObjectId,
        pages: &impl Pages,
    ) -> Result<u32, Refusal> {
        let kind = kind_bits(object.kind).expect("a GDI object");
        self.insert_as(owner, object, kind, pages)
    }

    /// [`GdiTable::insert`], the handle carrying the kind `kind` (an extended pen's OBJ_EXTPEN,
    /// where its object's type says OBJ_PEN). An owner or a kind past the entry's byte is
    /// [`Refusal::Ceiling`]'s (neither happens: process indices stay below 0x100, kinds below 16).
    pub fn insert_as(
        &mut self,
        owner: u16,
        object: ObjectId,
        kind: u32,
        pages: &impl Pages,
    ) -> Result<u32, Refusal> {
        if owner > 0xFF || kind > 0xFF {
            return Err(Refusal::Ceiling);
        }
        let quota = super::quota::gdi_process_handle_quota();
        self.processes
            .may_take(Objects::Gdi, owner, quota, pages)
            .map_err(|refusal| match refusal {
                process::Refusal::Quota => Refusal::Quota,
                process::Refusal::NoMemory => Refusal::NoMemory,
            })?;
        let (id, entry) = self
            .slots
            .allocate_or_grow(0, pages)
            .map_err(|full| match full {
                Full::Limit => Refusal::Ceiling,
                Full::NoChunk => Refusal::NoMemory,
            })?;
        *entry = GdiEntry {
            object,
            owner_kind: owner | ((kind as u16) << 8),
        };
        self.processes.took(Objects::Gdi, owner);
        Ok(object_handle(kind, id))
    }

    /// The object `handle` names for the process `owner`: an entry it owns whose kind and
    /// uniqueness the handle carries exactly. None for any other handle: another process's, a
    /// deleted object's, a global object's, or one past the table.
    pub fn find(&self, owner: u16, handle: u32) -> Option<ObjectId> {
        let entry = self.slots.get(handle)?;
        let kind = entry.kind();
        (entry.owner() == owner && handle & TYPE_BITS == object_handle(kind, 0))
            .then_some(entry.object)
    }

    /// Free the entry `handle` names for `owner` (see [`GdiTable::find`]): the object whose
    /// reference it held, which the caller now holds. None when it names none.
    pub fn remove(&mut self, owner: u16, handle: u32) -> Option<ObjectId> {
        let object = self.find(owner, handle)?;
        self.slots.free(handle);
        self.processes.gave(Objects::Gdi, owner);
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
            if entry.owner() == owner {
                handles[count] = id;
                out[count] = Some(entry.object);
                count += 1;
            }
        }
        for &handle in &handles[..count] {
            self.slots.free(handle);
            self.processes.gave(Objects::Gdi, owner);
        }
        if count < room {
            // The last of the owner's entries: its count starts afresh for the next process at
            // its index.
            self.processes.end(Objects::Gdi, owner);
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
            .filter(|(_, entry)| entry.owner() == owner)
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

    /// The kernel's GDI table, behind its short lock, counting in the kernel's records.
    static TABLE: ShortLock<GdiTable> = ShortLock::new(GdiTable::on(&process::PROCESSES));

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
    /// reference, its handle answered. A refusal (the process's quota, the table's ceiling, no
    /// page: [`Refusal`]) takes the object back with it, its status answered (STATUS_NO_MEMORY,
    /// ERROR_NOT_ENOUGH_MEMORY's).
    pub fn insert(object: ObjectId) -> Result<u32, NtStatus> {
        let owner = owner();
        let handle = with_table(|table| table.insert(owner, object, &KERNEL_PAGES));
        handle.map_err(|refusal| {
            crate::ob::release(object);
            refusal.status()
        })
    }

    /// [`insert`], the handle carrying the kind `kind` ([`GdiTable::insert_as`]).
    pub fn insert_as(object: ObjectId, kind: u32) -> Result<u32, NtStatus> {
        let owner = owner();
        let handle = with_table(|table| table.insert_as(owner, object, kind, &KERNEL_PAGES));
        handle.map_err(|refusal| {
            crate::ob::release(object);
            refusal.status()
        })
    }

    /// The object of `kind` (its handle's kind bits: [`DC_KIND`], OBJ_BRUSH...) the calling
    /// process's `handle` names; none for a handle naming nothing of that kind there.
    pub fn object(handle: u32, kind: u32) -> Option<ObjectId> {
        if handle & TYPE_BITS != object_handle(kind, 0) {
            return None;
        }
        let owner = owner();
        with_table(|table| table.find(owner, handle))
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
        if handle & TYPE_BITS != object_handle(kind, 0) {
            return false;
        }
        let object = with_table(|table| table.remove(owner, handle));
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

    /// An empty table counting in records of its own.
    fn table() -> GdiTable {
        GdiTable::on(process::processes())
    }

    const ONE: u16 = 3;
    const OTHER: u16 = 5;

    /// A handle carries its slot in the low word, its kind in bits 16-19 (a DC's clear) and its
    /// uniqueness, from 1, in bits 24-31, the stock bit clear; rtl::gdi reads its kind back.
    #[test]
    fn handles_carry_their_slot_kind_and_uniqueness() {
        let pages = HostPages::new();
        let mut table = table();
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

    /// A pen's handle carries the kind it was made as: OBJ_PEN for CreatePen's, OBJ_EXTPEN for
    /// ExtCreatePen's, both of the Pen type; the other kind's bits name nothing.
    #[test]
    fn a_pens_handle_carries_its_kind() {
        let pages = HostPages::new();
        let mut table = table();
        let pen = object(ObjectType::Pen, 1);
        let plain = table.insert(ONE, pen, &pages).unwrap();
        let extended = table
            .insert_as(ONE, pen, rtl::gdi::OBJ_EXTPEN, &pages)
            .unwrap();
        assert_eq!(rtl::gdi::object_kind(plain), Some(OBJ_PEN));
        assert_eq!(rtl::gdi::object_kind(extended), Some(rtl::gdi::OBJ_EXTPEN));
        assert_eq!(table.find(ONE, extended), Some(pen));
        let swapped = rtl::gdi::object_handle(OBJ_PEN, extended & 0xFF00_FFFF);
        assert_eq!(table.find(ONE, swapped), None);
    }

    /// Only the owner finds its objects: another process's look-up, its delete and its teardown
    /// leave them be.
    #[test]
    fn another_process_finds_nothing() {
        let pages = HostPages::new();
        let mut table = table();
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
        let mut table = table();
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
        let mut table = table();
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
        let mut table = table();
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

    /// Each process's entries are counted from the insert to the delete; at its quota's worth
    /// (10,000) the next insert is refused, ERROR_NOT_ENOUGH_MEMORY's status, the table and the
    /// count as they were; one deleted makes room for one more (its slot), and another process
    /// is not held back.
    #[test]
    fn a_process_is_refused_at_its_quota() {
        let pages = HostPages::new();
        let mut table = table();
        let quota = super::super::quota::GDI_PROCESS_HANDLE_QUOTA;
        let mut handles = std::vec::Vec::new();
        for index in 0..quota {
            let kind = if index % 2 == 0 {
                ObjectType::Brush
            } else {
                ObjectType::Region
            };
            handles.push(table.insert(ONE, object(kind, 1), &pages).unwrap());
            assert_eq!(table.processes.gdi_objects(ONE), index + 1);
        }
        assert_eq!(
            table.insert(ONE, object(ObjectType::Brush, 1), &pages),
            Err(Refusal::Quota)
        );
        assert_eq!(Refusal::Quota.status(), STATUS_NO_MEMORY);
        assert_eq!(rtl::status::dos_error(Refusal::Quota.status().0), 8);
        assert_eq!(table.processes.gdi_objects(ONE), quota);
        assert_eq!(table.live(), quota);
        assert!(table
            .insert(OTHER, object(ObjectType::Font, 1), &pages)
            .is_ok());
        assert_eq!(table.processes.gdi_objects(OTHER), 1);

        let last = handles.pop().unwrap();
        assert!(table.remove(ONE, last).is_some());
        assert_eq!(table.processes.gdi_objects(ONE), quota - 1);
        let again = table
            .insert(ONE, object(ObjectType::Brush, 2), &pages)
            .unwrap();
        assert_eq!(again & 0xFFFF, last & 0xFFFF, "the freed slot");
        assert_eq!(
            table.insert(ONE, object(ObjectType::Brush, 3), &pages),
            Err(Refusal::Quota)
        );
        handles.push(again);
        for handle in handles {
            assert!(table.remove(ONE, handle).is_some());
        }
        assert_eq!(table.processes.gdi_objects(ONE), 0, "every one given back");
    }

    /// A delete by another process, or of a stale handle, gives no count back; the teardown's
    /// sweep gives back the owner's whole count, and no other process's.
    #[test]
    fn the_count_follows_deletes_and_the_teardown() {
        let pages = HostPages::new();
        let mut table = table();
        let first = table
            .insert(ONE, object(ObjectType::Brush, 1), &pages)
            .unwrap();
        for index in 0..(TAKE_STEP as u16 + 3) {
            table
                .insert(ONE, object(ObjectType::Bitmap, index), &pages)
                .unwrap();
        }
        table
            .insert(OTHER, object(ObjectType::Dc, 1), &pages)
            .unwrap();
        assert_eq!(table.processes.gdi_objects(ONE), TAKE_STEP as u32 + 4);
        assert_eq!(table.remove(OTHER, first), None);
        assert_eq!(table.processes.gdi_objects(ONE), TAKE_STEP as u32 + 4);
        assert!(table.remove(ONE, first).is_some());
        assert_eq!(table.remove(ONE, first), None, "stale");
        assert_eq!(table.processes.gdi_objects(ONE), TAKE_STEP as u32 + 3);
        let mut step = [None; TAKE_STEP];
        assert_eq!(table.take_owned(ONE, &mut step), TAKE_STEP);
        assert_eq!(table.processes.gdi_objects(ONE), 3);
        assert_eq!(table.take_owned(ONE, &mut step), 3);
        assert_eq!(table.processes.gdi_objects(ONE), 0);
        assert_eq!(table.processes.gdi_objects(OTHER), 1);
    }

    /// The stock objects are no process's: their handles name no entry, so a delete gives no
    /// count back, and making them costs none (they are never inserted).
    #[test]
    fn stock_objects_count_for_nobody() {
        let pages = HostPages::new();
        let mut table = table();
        table
            .insert(ONE, object(ObjectType::Brush, 1), &pages)
            .unwrap();
        for index in 0..=rtl::gdi::DEFAULT_GUI_FONT {
            if let Some(stock) = rtl::gdi::stock_handle(index) {
                assert_eq!(table.remove(ONE, stock), None);
            }
        }
        assert_eq!(table.processes.gdi_objects(ONE), 1);
        assert_eq!(table.live(), 1);
    }

    /// The table stops at Windows 2000's 16,384 entries (slot 0 never handed out), and grows a
    /// page at a time on the way; a failed page leaves it as it was. Two processes fill it, each
    /// short of its quota.
    #[test]
    fn the_table_fills_at_its_ceiling() {
        let mut table = table();
        for owner in [ONE, OTHER] {
            // The processes' records made beforehand, out of the budget below.
            let quota = super::super::quota::GDI_PROCESS_HANDLE_QUOTA;
            let records = HostPages::new();
            assert_eq!(
                table
                    .processes
                    .may_take(Objects::Gdi, owner, quota, &records),
                Ok(())
            );
        }
        let pages = HostPages::with_budget(1);
        let mut handles = std::vec::Vec::new();
        let refusal = loop {
            match table.insert(ONE, object(ObjectType::Brush, 1), &pages) {
                Ok(handle) => handles.push(handle),
                Err(refusal) => break refusal,
            }
        };
        assert_eq!(handles.len(), PER - 1, "one page's slots, slot 0 reserved");
        assert_eq!(refusal, Refusal::NoMemory);
        assert_eq!(table.processes.gdi_objects(ONE), PER as u32 - 1);
        pages.set_budget(CHUNKS);
        let refusal = loop {
            let owner = if handles.len() < 8_000 { ONE } else { OTHER };
            match table.insert(owner, object(ObjectType::Brush, 1), &pages) {
                Ok(handle) => handles.push(handle),
                Err(refusal) => break refusal,
            }
        };
        assert_eq!(refusal, Refusal::Ceiling);
        assert_eq!(handles.len(), 0x3FFF);
        assert_eq!(handles.last().map(|handle| handle & 0xFFFF), Some(0x3FFF));
        assert_eq!(table.live(), 0x3FFF);
        assert_eq!(
            table.processes.gdi_objects(ONE) + table.processes.gdi_objects(OTHER),
            0x3FFF
        );
        assert_eq!(
            Refusal::Ceiling.status(),
            STATUS_NO_MEMORY,
            "the ceiling answers ERROR_NOT_ENOUGH_MEMORY too"
        );
    }
}
