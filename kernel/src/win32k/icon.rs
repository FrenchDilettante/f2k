//! Cursors and icons: the records behind HCURSORs and HICONs, and the services LoadIcon,
//! LoadCursor, CopyIcon and DestroyIcon come through. Data only: an icon holds its size, its depth
//! and where it was loaded from, not its bits, and nothing draws one yet.
//!
//! A cursor or icon is a record in the table ([`CursorTable`]), named by a generation-tagged id
//! ([`CursorId`]), the object manager's pattern, with a handle into the user handle table
//! ([`super::handle`]). The table is the class registry's ([`super::class::Registry`]): a class
//! holds its icon, small icon and cursor locked, and registering a class validates their handles
//! here. A record made for a process belongs to it and goes at its end; a record the class
//! registry synthesizes (a class's small icon) is the class's, and secret: GetClassInfo hides it.
//!
//! LoadIcon, as Windows 2000's user32 runs it, picks the image of a module's group icon and asks
//! for the icon already loaded from that resource at that size (NtUserFindExistingCursorIcon);
//! failing one, it has an empty record made (NtUserCallNoParam's NO_PARAM_CREATE_EMPTY_CURSOR) and
//! fills it in (NtUserSetCursorIconData), shared (LR_SHARED): the one icon of its resource and
//! size, which LoadIcon answers again.
//!
//! The stock cursors (IDC_*) and icons (IDI_*) are records of the system's, made at the boot
//! ([`CursorTable::make_stock`]), with handles of the table as every other object's: Windows 2000
//! loads them from user32's own resources into shared objects of the system's, which LoadCursor
//! and LoadIcon with no module find (FindExistingCursorIcon on user32's module). F2K's user32 has
//! no such resources: the records hold no image, the module 0 names the system's, and their
//! resource is the IDC_ or IDI_ id. No process owns them and none destroys them.
//!
//! The services (F2K's argument lists, see [`crate::win32k`]; Windows 2000's numbers):
//!
//! - NtUserFindExistingCursorIcon (0x116F): the shared icon or cursor of a module's resource at a
//!   size, or a stock one;
//! - NtUserSetCursorIconData (0x11EE): an empty record filled in (rtl::icon's CursorData);
//! - NtUserGetIconInfo (0x118C): what a record holds, as rtl::icon's CursorData (CopyIcon's
//!   source);
//! - NtUserDestroyCursor (0x1156): DestroyIcon's and DestroyCursor's record destroyed.
//!
//! Seams recorded: the bits. Drawing an icon (DrawIconEx, a Static control's SS_ICON) needs its
//! color image and its mask, which the record will hold in a pool block when drawing lands.

use rtl::icon::{CursorData, ICON_SIZE, RT_CURSOR, RT_ICON, STOCK_CURSORS, STOCK_ICONS};

use super::class::Owner;
use super::handle::{UserHandles, UserObject};
use crate::slots::{Id, LowestFirst, Record, Slots};
use crate::status::*;

/// A handle naming no cursor or icon: ERROR_INVALID_CURSOR_HANDLE (1402), the Win32 error itself
/// in a FACILITY_NTWIN32 status, which user32 hands to GetLastError as is.
pub const INVALID_CURSOR_HANDLE: NtStatus =
    NtStatus::from_win32(rtl::winerror::ERROR_INVALID_CURSOR_HANDLE);

/// The cursor table's kind of id.
pub enum CursorTag {}

/// A cursor or icon's id: its slot in the table and the slot's uniqueness count, which moves on
/// when the record is destroyed, so a destroyed cursor's id names nothing.
pub type CursorId = Id<CursorTag>;

impl CursorId {
    /// The id of the slot `index`, its first count (the handle table's tests).
    #[cfg(test)]
    pub const fn for_tests(index: u16) -> Self {
        Id::new(index, 1)
    }
}

/// One cursor or icon record.
#[derive(Clone, Copy)]
struct Cursor {
    handle: u32,
    locks: u32,
    /// A system-created copy, which apps never see (hidden as null by GetClassInfo).
    secret: bool,
    is_icon: bool,
    /// The process it was made for; none for a record the class registry made.
    owner: Option<Owner>,
    /// What NtUserSetCursorIconData filled in (all zero for an empty record).
    data: CursorData,
}

impl Cursor {
    const EMPTY: Self = Cursor {
        handle: 0,
        locks: 0,
        secret: false,
        is_icon: false,
        owner: None,
        data: CursorData {
            is_icon: 0,
            width: 0,
            height: 0,
            hotspot_x: 0,
            hotspot_y: 0,
            bits_per_pixel: 0,
            module: 0,
            resource: 0,
            shared: 0,
        },
    };
}

// SAFETY: `write_fresh` writes a whole record.
unsafe impl Record for Cursor {
    unsafe fn write_fresh(at: *mut Self, _: u32) {
        // SAFETY: the caller's contract.
        unsafe { at.write(Cursor::EMPTY) };
    }
}

/// Cursor records to a chunk: one page's worth.
const CURSORS_PER_CHUNK: usize = crate::slots::per_page::<Cursor>();

const _: () = assert!(Slots::<Cursor, LowestFirst<CursorTag>, CURSORS_PER_CHUNK>::CHUNK_PAGES == 1);

/// The cursor and icon records, in slots of the slot pool ([`crate::slots`]) grown a page at a
/// time under the window manager's lock, taken lowest free first as the fixed array was; every
/// lookup checked. Their handles are the user handle table's ([`UserHandles`], the window
/// registry's), which the calls that make, find or destroy a record are lent.
pub struct CursorTable {
    slots: Slots<Cursor, LowestFirst<CursorTag>, CURSORS_PER_CHUNK>,
}

impl CursorTable {
    /// Write an empty table at `table`.
    ///
    /// # Safety
    ///
    /// `table` is valid for writes and aligned; its previous contents are overwritten, not
    /// dropped.
    pub unsafe fn write_empty(table: *mut CursorTable) {
        // SAFETY: the caller's contract.
        unsafe {
            table.write(CursorTable {
                slots: Slots::new(),
            })
        };
    }

    /// The record `id` names: a destroyed cursor's reads as the empty record its destroy left,
    /// as it did in the fixed array (a class may still hold the id), never as the slot's next
    /// record.
    fn at(&self, id: CursorId) -> &Cursor {
        self.slots.get(id).unwrap_or(&Cursor::EMPTY)
    }

    /// The live record `id` names, to change. Only for an id just made or validated.
    fn at_mut(&mut self, id: CursorId) -> &mut Cursor {
        self.slots.get_mut(id).expect("a live cursor id")
    }

    /// The lock count of `id`'s record, when it is live: a destroyed record's locks are nobody's.
    fn locks_mut(&mut self, id: CursorId) -> Option<&mut u32> {
        self.slots.get_mut(id).map(|record| &mut record.locks)
    }

    /// A new cursor or icon record with its handle in `handles`; none when the handle table is
    /// full or no page is left for the record.
    pub fn make(
        &mut self,
        handles: &mut UserHandles,
        is_icon: bool,
        secret: bool,
    ) -> Option<(CursorId, u32)> {
        let (id, record) = self.slots.allocate_or_grow(0, super::pages()).ok()?;
        let handle = handles.insert(UserObject::Cursor(id));
        if handle == 0 {
            self.slots.free(id);
            return None;
        }
        *record = Cursor {
            handle,
            secret,
            is_icon,
            ..Cursor::EMPTY
        };
        Some((id, handle))
    }

    /// The cursor or icon `handle` names in `handles`, when the handle is live (its record's
    /// count matches); none otherwise (another kind's handle among them).
    pub fn validate(&self, handles: &UserHandles, handle: u32) -> Option<CursorId> {
        let id = handles.cursor(handle)?;
        self.slots.get(id).map(|_| id)
    }

    /// The same, for an old handle about to be answered: a cursor destroyed meanwhile answers
    /// none.
    pub fn revalidate(&self, handles: &UserHandles, handle: u32) -> Option<CursorId> {
        self.validate(handles, handle)
    }

    /// The handle of `id` (0 for none): the inverse of [`CursorTable::validate`].
    pub fn handle_of(&self, id: Option<CursorId>) -> u32 {
        id.map_or(0, |id| self.at(id).handle)
    }

    /// Lock `id` (its reference count up), for a class holding it.
    pub fn lock(&mut self, id: CursorId) {
        if let Some(locks) = self.locks_mut(id) {
            *locks += 1;
        }
    }

    /// Set `slot` to `id`: the old value is unlocked, the new one locked; the slot's previous
    /// value.
    pub fn lock_slot(
        &mut self,
        slot: &mut Option<CursorId>,
        id: Option<CursorId>,
    ) -> Option<CursorId> {
        let old = *slot;
        *slot = id;
        if let Some(old) = old {
            if let Some(locks) = self.locks_mut(old) {
                *locks = locks.saturating_sub(1);
            }
        }
        if let Some(id) = id {
            self.lock(id);
        }
        old
    }

    /// Unlock `slot` (its reference count down), clearing it.
    pub fn unlock_slot(&mut self, slot: &mut Option<CursorId>) {
        if let Some(id) = *slot {
            if let Some(locks) = self.locks_mut(id) {
                *locks = locks.saturating_sub(1);
            }
        }
        *slot = None;
    }

    /// Destroy `id`: its record goes, its handle with it.
    pub fn destroy(&mut self, handles: &mut UserHandles, id: CursorId) {
        let Some(record) = self.slots.get_mut(id) else {
            return;
        };
        let handle = record.handle;
        *record = Cursor::EMPTY;
        handles.close(handle);
        self.slots.free(id);
    }

    /// A copy of `id`'s image as a small icon: a synthesized record, hidden from apps; none when
    /// the pool is full (the lock then simply does not land).
    pub fn copy_image(
        &mut self,
        handles: &mut UserHandles,
        id: CursorId,
        as_icon: bool,
    ) -> Option<CursorId> {
        let _ = id;
        self.make(handles, as_icon, true).map(|(id, _)| id)
    }

    pub fn secret(&self, id: CursorId) -> bool {
        self.at(id).secret
    }

    pub fn is_icon(&self, id: CursorId) -> bool {
        self.at(id).is_icon
    }

    /// How many locks `id` holds (the tests read this).
    #[cfg(test)]
    pub fn locks(&self, id: CursorId) -> u32 {
        self.at(id).locks
    }

    // --- LoadIcon's records

    /// The stock cursors and icons, the system's records, made once at the boot (after the boot's
    /// windows, whose handles come first): one record of each IDC_ and IDI_ id, as large as
    /// LoadCursor and LoadIcon ask for (SM_CXCURSOR and SM_CXICON, 32 by 32), shared. A desktop
    /// booted after the first finds them made. False when the tables were too full.
    pub fn make_stock(&mut self, handles: &mut UserHandles) -> bool {
        let arrow = u32::from(STOCK_CURSORS[0]);
        let cursor = u32::from(RT_CURSOR);
        if self
            .find_existing(0, 0, arrow, ICON_SIZE, ICON_SIZE, cursor)
            .is_some()
        {
            return true;
        }
        let stock = STOCK_CURSORS
            .iter()
            .map(|&id| (false, id))
            .chain(STOCK_ICONS.iter().map(|&id| (true, id)));
        for (is_icon, resource) in stock {
            let Some((id, _)) = self.make(handles, is_icon, false) else {
                return false;
            };
            self.at_mut(id).data = CursorData {
                is_icon: u32::from(is_icon),
                width: ICON_SIZE,
                height: ICON_SIZE,
                hotspot_x: if is_icon { ICON_SIZE / 2 } else { 0 },
                hotspot_y: if is_icon { ICON_SIZE / 2 } else { 0 },
                bits_per_pixel: 0,
                module: 0,
                resource: u32::from(resource),
                shared: 1,
            };
        }
        true
    }

    /// An empty record of the process `owner`, which NtUserSetCursorIconData fills in: its handle;
    /// STATUS_NO_MEMORY when the table is full.
    pub fn create_empty(
        &mut self,
        handles: &mut UserHandles,
        owner: Owner,
    ) -> Result<u32, NtStatus> {
        let (id, handle) = self.make(handles, false, false).ok_or(STATUS_NO_MEMORY)?;
        self.at_mut(id).owner = Some(owner);
        Ok(handle)
    }

    /// Fill in the record `handle` names with `data`: the process's own record, made empty for it;
    /// [`INVALID_CURSOR_HANDLE`] for a handle naming none.
    pub fn set_data(
        &mut self,
        handles: &UserHandles,
        owner: Owner,
        handle: u32,
        data: &CursorData,
    ) -> Result<(), NtStatus> {
        let id = self
            .validate(handles, handle)
            .ok_or(INVALID_CURSOR_HANDLE)?;
        let record = self.at_mut(id);
        if record.owner != Some(owner) {
            return Err(INVALID_CURSOR_HANDLE);
        }
        record.is_icon = data.is_icon != 0;
        record.data = *data;
        Ok(())
    }

    /// The shared icon or cursor (`kind` RT_ICON or RT_CURSOR) the process `owner` loaded from the
    /// module's resource at the size `width` by `height`, or with the module 0 the stock one
    /// whose IDC_ or IDI_ id `resource` is: its handle.
    pub fn find_existing(
        &self,
        owner: Owner,
        module: u32,
        resource: u32,
        width: i32,
        height: i32,
        kind: u32,
    ) -> Option<u32> {
        let is_icon = match u16::try_from(kind) {
            Ok(RT_ICON) => 1,
            Ok(RT_CURSOR) => 0,
            _ => return None,
        };
        let holder = if module == 0 { None } else { Some(owner) };
        self.slots
            .iter()
            .map(|(_, record)| record)
            .find(|record| {
                record.owner == holder
                    && !record.secret
                    && record.data.shared != 0
                    && record.data.is_icon == is_icon
                    && record.data.module == module
                    && record.data.resource == resource
                    && record.data.width == width
                    && record.data.height == height
            })
            .map(|record| record.handle)
    }

    /// What the record `id` holds (CopyIcon's source).
    pub fn data(&self, id: CursorId) -> CursorData {
        self.at(id).data
    }

    /// DestroyIcon and DestroyCursor of `id` by the process `owner`: the record destroyed, unless
    /// it is shared (LoadIcon's, LoadCursor's, a stock one), which stays while its module does, or
    /// a class holds it, which leaves it to the process's end; TRUE in every case.
    pub fn destroy_by(&mut self, handles: &mut UserHandles, owner: Owner, id: CursorId) {
        let record = self.at(id);
        if record.data.shared != 0 || record.locks > 0 || record.owner != Some(owner) {
            return;
        }
        self.destroy(handles, id);
    }

    /// Destroy every record of the process `owner`, at its end (its classes, which held some, gone
    /// first).
    pub fn destroy_owner(&mut self, handles: &mut UserHandles, owner: Owner) {
        for index in 0..self.slots.high_water() {
            let Some(id) = self.slots.id_at(index) else {
                continue;
            };
            if self.at(id).owner == Some(owner) {
                self.destroy(handles, id);
            }
        }
    }

    /// How many records processes hold.
    pub fn process_records(&self) -> usize {
        self.slots
            .iter()
            .filter(|(_, record)| record.owner.is_some())
            .count()
    }
}

// --- The services
// --------------------------------------------------------------------------------------

#[cfg(target_arch = "x86")]
mod services {
    use super::*;
    use crate::nt::call::{Handle, NtCall, NtResult, UserAddr, UserPtr};
    use crate::win32k::queue::with_manager;
    use crate::win32k::winsta::gui_thread;

    /// NtUserFindExistingCursorIcon(Module, Resource, Size, Kind, Cursor): the shared icon or
    /// cursor (`kind` RT_ICON or RT_CURSOR) the caller's process loaded from the module's resource
    /// (its data's address) at the size (the width in the low word, the height in the high), or
    /// with the module 0 the stock one of the IDC_ or IDI_ id `resource`, into `cursor`; 0 for
    /// none.
    pub fn find_existing_cursor_icon(
        call: &mut NtCall,
        module: u32,
        resource: u32,
        size: u32,
        kind: u32,
        cursor: UserPtr<u32>,
    ) -> NtResult {
        let owner = gui_thread(call)?.owner;
        let (width, height) = (i32::from(size as u16), i32::from((size >> 16) as u16));
        let found = with_manager(call.passive(), |m| {
            m.classes
                .cursors
                .find_existing(owner, module, resource, width, height, kind)
        });
        cursor.write(found.unwrap_or(0))?;
        Ok(STATUS_SUCCESS)
    }

    /// NtUserSetCursorIconData(Cursor, Data): the empty record filled in from the CursorData at
    /// `data`.
    pub fn set_cursor_icon_data(call: &mut NtCall, cursor: Handle, data: UserAddr) -> NtResult {
        let owner = gui_thread(call)?.owner;
        let data = data.cast::<CursorData>().read()?;
        with_manager(call.passive(), |m| {
            m.classes
                .cursors
                .set_data(&m.windows.handles, owner, cursor.raw(), &data)
        })?;
        Ok(STATUS_SUCCESS)
    }

    /// NtUserGetIconInfo(Cursor, Data): what the record holds, as a CursorData, into `data`;
    /// [`INVALID_CURSOR_HANDLE`] for a handle naming no cursor or icon.
    pub fn get_icon_info(call: &mut NtCall, cursor: Handle, data: UserAddr) -> NtResult {
        gui_thread(call)?;
        let held = with_manager(call.passive(), |m| {
            let cursors = &m.classes.cursors;
            let id = cursors.validate(&m.windows.handles, cursor.raw());
            id.map(|id| cursors.data(id))
        })
        .ok_or(INVALID_CURSOR_HANDLE)?;
        data.cast::<CursorData>().write(held)?;
        Ok(STATUS_SUCCESS)
    }

    /// NtUserDestroyCursor(Cursor): DestroyIcon's and DestroyCursor's record destroyed (a shared
    /// one stays, [`CursorTable::destroy_by`]); [`INVALID_CURSOR_HANDLE`] for a handle naming no
    /// cursor or icon.
    pub fn destroy_cursor(call: &mut NtCall, cursor: Handle) -> NtResult {
        let owner = gui_thread(call)?.owner;
        with_manager(call.passive(), |m| {
            let handles = &mut m.windows.handles;
            let cursors = &mut m.classes.cursors;
            let id = cursors
                .validate(handles, cursor.raw())
                .ok_or(INVALID_CURSOR_HANDLE)?;
            cursors.destroy_by(handles, owner, id);
            Ok::<(), NtStatus>(())
        })?;
        Ok(STATUS_SUCCESS)
    }
}

// The host builds have no processes and no user memory: the services answer nothing (the host
// tests drive the table itself).
#[cfg(not(target_arch = "x86"))]
mod services {
    use super::*;
    use crate::nt::call::{Handle, NtCall, NtResult, UserAddr, UserPtr};

    pub fn find_existing_cursor_icon(
        _: &mut NtCall,
        _: u32,
        _: u32,
        _: u32,
        _: u32,
        _: UserPtr<u32>,
    ) -> NtResult {
        Err(STATUS_NOT_IMPLEMENTED)
    }

    pub fn set_cursor_icon_data(_: &mut NtCall, _: Handle, _: UserAddr) -> NtResult {
        Err(STATUS_NOT_IMPLEMENTED)
    }

    pub fn get_icon_info(_: &mut NtCall, _: Handle, _: UserAddr) -> NtResult {
        Err(STATUS_NOT_IMPLEMENTED)
    }

    pub fn destroy_cursor(_: &mut NtCall, _: Handle) -> NtResult {
        Err(STATUS_NOT_IMPLEMENTED)
    }
}

pub use services::{
    destroy_cursor,
    find_existing_cursor_icon,
    get_icon_info,
    set_cursor_icon_data,
};

#[cfg(test)]
mod tests {
    use std::boxed::Box;

    use super::*;

    const OWNER: Owner = 3;

    fn table() -> (Box<CursorTable>, Box<UserHandles>) {
        let mut boxed = Box::<CursorTable>::new_uninit();
        let mut handles = Box::<UserHandles>::new_uninit();
        // SAFETY: the boxes' memory, valid and aligned, written whole before it is assumed.
        unsafe {
            CursorTable::write_empty(boxed.as_mut_ptr());
            UserHandles::write_empty(handles.as_mut_ptr());
            (boxed.assume_init(), handles.assume_init())
        }
    }

    fn icon(module: u32, resource: u32) -> CursorData {
        CursorData {
            is_icon: 1,
            width: 32,
            height: 32,
            hotspot_x: 16,
            hotspot_y: 16,
            bits_per_pixel: 4,
            module,
            resource,
            shared: 1,
        }
    }

    const ICON: u32 = RT_ICON as u32;
    const CURSOR: u32 = RT_CURSOR as u32;

    /// LoadIcon's records: made empty, filled in, found again by resource and size, the process's
    /// own; gone at its end.
    #[test]
    fn shared_icons_are_found_again() {
        let (mut t, mut h) = table();
        let handle = t.create_empty(&mut h, OWNER).unwrap();
        assert_eq!(t.process_records(), 1);
        t.set_data(&h, OWNER, handle, &icon(0x40_0000, 0x40_A000))
            .unwrap();
        assert_eq!(
            t.set_data(&h, OWNER + 1, handle, &icon(1, 2)),
            Err(INVALID_CURSOR_HANDLE)
        );
        assert_eq!(
            t.find_existing(OWNER, 0x40_0000, 0x40_A000, 32, 32, ICON),
            Some(handle)
        );
        assert_eq!(
            t.find_existing(OWNER, 0x40_0000, 0x40_A000, 16, 16, ICON),
            None
        );
        assert_eq!(
            t.find_existing(OWNER, 0x40_0000, 0x40_A000, 32, 32, CURSOR),
            None
        );
        assert_eq!(
            t.find_existing(OWNER + 1, 0x40_0000, 0x40_A000, 32, 32, ICON),
            None
        );
        let id = t.validate(&h, handle).unwrap();
        assert!(t.is_icon(id));
        t.destroy_by(&mut h, OWNER, id);
        assert_eq!(t.validate(&h, handle), Some(id), "a shared icon stays");
        let (secret, _) = t.make(&mut h, true, true).unwrap();
        t.destroy_owner(&mut h, OWNER);
        assert_eq!(t.validate(&h, handle), None);
        assert_eq!(t.process_records(), 0);
        assert!(
            t.validate(&h, t.handle_of(Some(secret))).is_some(),
            "the class registry's own"
        );
    }

    /// More records than the old fixed table's 128, each its own; a destroyed one's id and handle
    /// name nothing, its lock and handle read as none, and the next record takes the lowest free
    /// slot with its count moved on; a process's end takes all of its own.
    #[test]
    fn the_table_grows_and_a_destroyed_id_names_nothing() {
        let (mut t, mut h) = table();
        let made: Vec<_> = (0..200)
            .map(|_| t.create_empty(&mut h, OWNER).unwrap())
            .collect();
        assert_eq!(t.process_records(), 200);
        let ids: Vec<_> = made
            .iter()
            .map(|&handle| t.validate(&h, handle).unwrap())
            .collect();
        let (first, last) = (ids[0], ids[199]);
        t.destroy_by(&mut h, OWNER, last);
        t.destroy_by(&mut h, OWNER, first);
        assert_eq!(t.validate(&h, made[0]), None);
        assert_eq!(t.handle_of(Some(first)), 0);
        t.lock(first);
        assert_eq!(t.locks(first), 0, "a destroyed record's locks are nobody's");
        let again = t.create_empty(&mut h, OWNER).unwrap();
        let id = t.validate(&h, again).unwrap();
        assert_eq!((id.index, id.uniq), (first.index, first.uniq + 1));
        assert_eq!(t.locks(id), 0);
        assert_eq!(
            t.validate(&h, made[0]),
            None,
            "the old handle is not the new"
        );
        assert_eq!(
            t.handle_of(Some(CursorId::new(id.index, 0))),
            0,
            "a forged id"
        );
        t.destroy_owner(&mut h, OWNER);
        assert_eq!(t.process_records(), 0);
    }

    /// The stock cursors and icons: the system's records, each of its own handle, found with the
    /// module 0 by their id and kind (IDC_ARROW's and IDI_APPLICATION's ids are the same), and
    /// never destroyed. A copy of one (CopyIcon's) is the process's, and DestroyIcon takes it.
    #[test]
    fn the_stock_ones_are_records_of_their_own() {
        let (mut t, mut h) = table();
        assert!(t.make_stock(&mut h));
        let arrow = t.find_existing(OWNER, 0, 32512, 32, 32, CURSOR).unwrap();
        let application = t.find_existing(OWNER, 0, 32512, 32, 32, ICON).unwrap();
        assert_ne!(arrow & 0xFFFF, application & 0xFFFF);
        assert_eq!(t.find_existing(OWNER, 0, 32767, 32, 32, CURSOR), None);
        assert_eq!(t.process_records(), 0);
        let id = t.validate(&h, application).unwrap();
        t.destroy_by(&mut h, OWNER, id);
        assert_eq!(t.validate(&h, application), Some(id));

        let copy = t.create_empty(&mut h, OWNER).unwrap();
        let data = CursorData {
            shared: 0,
            ..t.data(id)
        };
        t.set_data(&h, OWNER, copy, &data).unwrap();
        assert_eq!(
            t.find_existing(OWNER, 0, 32512, 32, 32, ICON),
            Some(application),
            "the copy is no shared icon"
        );
        let copy_id = t.validate(&h, copy).unwrap();
        t.destroy_by(&mut h, OWNER + 1, copy_id);
        assert!(
            t.validate(&h, copy).is_some(),
            "another process's copy stays"
        );
        t.destroy_by(&mut h, OWNER, copy_id);
        assert_eq!(t.validate(&h, copy), None);
    }
}
