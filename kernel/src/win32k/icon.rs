//! Cursors and icons: the records behind HCURSORs and HICONs, the handle table over them, and the
//! services LoadIcon comes through. Data only: an icon holds its size, its depth and where it was
//! loaded from, not its bits, and nothing draws one yet.
//!
//! A cursor or icon is a record in the table ([`CursorTable`]), named by a generation-tagged id
//! ([`CursorId`]), the object manager's pattern, with a handle into the table's handle table. The
//! table is the class registry's ([`super::class::Registry`]): a class holds its icon, small icon
//! and cursor locked, and registering a class validates their handles here. A record made for a
//! process belongs to it and goes at its end; a record the class registry synthesizes (a class's
//! small icon) is the class's, and secret: GetClassInfo hides it.
//!
//! LoadIcon, as Windows 2000's user32 runs it, picks the image of a module's group icon and asks
//! for the icon already loaded from that resource at that size (NtUserFindExistingCursorIcon);
//! failing one, it has an empty record made (NtUserCallNoParam's NO_PARAM_CREATE_EMPTY_CURSOR) and
//! fills it in (NtUserSetCursorIconData), shared (LR_SHARED): the one icon of its resource and
//! size, which LoadIcon answers again. The stock icons (IDI_*) are user32's own constant handles,
//! as its stock cursors are (user32's class module): no record holds them, and a class names them
//! to the kernel as none.
//!
//! The services (F2K's argument lists, see [`crate::win32k`]; Windows 2000's numbers):
//!
//! - NtUserFindExistingCursorIcon (0x116F): the shared icon of a module's resource at a size;
//! - NtUserSetCursorIconData (0x11EE): an empty record filled in (rtl::icon's CursorData).
//!
//! Seams recorded: the bits. Drawing an icon (DrawIconEx, a Static control's SS_ICON) needs its
//! color image and its mask, which the record will hold in a pool block when drawing lands.

use rtl::icon::CursorData;

use super::class::Owner;
use crate::status::*;

/// How many cursor and icon records the table holds.
pub const CURSORS: usize = 64;

/// The high word of a cursor's or icon's handle: the handle table's value in the low word, this
/// tag above it, so no icon handle is a window's, a menu's or an accelerator table's. (user32's
/// stock cursors and icons are 0x0001xxxx and 0x0002xxxx.)
const CURSOR_TAG: u32 = 0x0005_0000;

/// A cursor or icon's id: its record in the pool and the record's generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CursorId {
    index: u16,
    generation: u16,
}

/// One cursor/icon record's header.
#[derive(Clone, Copy)]
struct CursorHeader {
    live: bool,
    generation: u16,
}

impl CursorHeader {
    const DEAD: Self = CursorHeader {
        live: false,
        generation: 0,
    };
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

/// A handle-table entry naming a cursor or icon.
#[derive(Clone, Copy)]
struct CursorEntry {
    id: CursorId,
}

/// The cursor/icon handle table: records behind generation-tagged ids, handles over them (the
/// object manager's handle-table shape).
pub struct CursorTable {
    headers: [CursorHeader; CURSORS],
    records: [Cursor; CURSORS],
    handles: crate::sched::object::HandleTable<CursorEntry>,
}

impl CursorTable {
    /// Write an empty table at `table`, element by element (by value it would pass through the
    /// stack, which is smaller than it).
    ///
    /// # Safety
    ///
    /// `table` is valid for writes and aligned; its previous contents are overwritten, not
    /// dropped.
    pub unsafe fn write_empty(table: *mut CursorTable) {
        use core::ptr::addr_of_mut;
        // SAFETY: the caller's contract; every field is written, the arrays element by element.
        unsafe {
            let headers = addr_of_mut!((*table).headers) as *mut CursorHeader;
            let records = addr_of_mut!((*table).records) as *mut Cursor;
            for index in 0..CURSORS {
                headers.add(index).write(CursorHeader::DEAD);
                records.add(index).write(Cursor::EMPTY);
            }
            crate::sched::object::HandleTable::write_empty(addr_of_mut!((*table).handles));
        }
    }

    /// A new cursor or icon record with its handle; none when the pool is full.
    pub fn make(&mut self, is_icon: bool, secret: bool) -> Option<(CursorId, u32)> {
        let index = self.headers.iter().position(|h| !h.live)?;
        if self.handles.is_full() {
            return None;
        }
        let header = &mut self.headers[index];
        header.live = true;
        let id = CursorId {
            index: index as u16,
            generation: header.generation,
        };
        let handle = self.handles.insert(CursorEntry { id }) | CURSOR_TAG;
        self.records[index] = Cursor {
            handle,
            secret,
            is_icon,
            ..Cursor::EMPTY
        };
        Some((id, handle))
    }

    /// The cursor or icon `handle` names, when the handle is live (its record's generation
    /// matches); none otherwise.
    pub fn validate(&self, handle: u32) -> Option<CursorId> {
        if handle & 0xFFFF_0000 != CURSOR_TAG {
            return None;
        }
        let entry = self.handles.lookup(handle & 0xFFFF)?;
        let header = self.headers.get(entry.id.index as usize)?;
        (header.live && header.generation == entry.id.generation).then_some(entry.id)
    }

    /// The same, for an old handle about to be answered: a cursor destroyed meanwhile answers
    /// none.
    pub fn revalidate(&self, handle: u32) -> Option<CursorId> {
        self.validate(handle)
    }

    /// The handle of `id` (0 for none): the inverse of [`CursorTable::validate`].
    pub fn handle_of(&self, id: Option<CursorId>) -> u32 {
        id.map_or(0, |id| self.records[id.index as usize].handle)
    }

    /// Lock `id` (its reference count up), for a class holding it.
    pub fn lock(&mut self, id: CursorId) {
        self.records[id.index as usize].locks += 1;
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
            let locks = &mut self.records[old.index as usize].locks;
            *locks = locks.saturating_sub(1);
        }
        if let Some(id) = id {
            self.lock(id);
        }
        old
    }

    /// Unlock `slot` (its reference count down), clearing it.
    pub fn unlock_slot(&mut self, slot: &mut Option<CursorId>) {
        if let Some(id) = *slot {
            let locks = &mut self.records[id.index as usize].locks;
            *locks = locks.saturating_sub(1);
        }
        *slot = None;
    }

    /// Destroy `id`: its record goes, its handle with it.
    pub fn destroy(&mut self, id: CursorId) {
        let handle = self.records[id.index as usize].handle;
        self.handles.close(handle & 0xFFFF);
        self.records[id.index as usize] = Cursor::EMPTY;
        let header = &mut self.headers[id.index as usize];
        header.live = false;
        header.generation = header.generation.wrapping_add(1);
    }

    /// A copy of `id`'s image as a small icon: a synthesized record, hidden from apps; none when
    /// the pool is full (the lock then simply does not land).
    pub fn copy_image(&mut self, id: CursorId, as_icon: bool) -> Option<CursorId> {
        let _ = id;
        self.make(as_icon, true).map(|(id, _)| id)
    }

    pub fn secret(&self, id: CursorId) -> bool {
        self.records[id.index as usize].secret
    }

    pub fn is_icon(&self, id: CursorId) -> bool {
        self.records[id.index as usize].is_icon
    }

    /// How many locks `id` holds (the tests read this).
    #[cfg(test)]
    pub fn locks(&self, id: CursorId) -> u32 {
        self.records[id.index as usize].locks
    }

    // --- LoadIcon's records

    /// An empty record of the process `owner`, which NtUserSetCursorIconData fills in: its handle;
    /// STATUS_NO_MEMORY when the table is full.
    pub fn create_empty(&mut self, owner: Owner) -> Result<u32, NtStatus> {
        let (id, handle) = self.make(false, false).ok_or(STATUS_NO_MEMORY)?;
        self.records[id.index as usize].owner = Some(owner);
        Ok(handle)
    }

    /// Fill in the record `handle` names with `data`: the process's own record, made empty for it;
    /// STATUS_INVALID_HANDLE for a handle naming none.
    pub fn set_data(
        &mut self,
        owner: Owner,
        handle: u32,
        data: &CursorData,
    ) -> Result<(), NtStatus> {
        let id = self.validate(handle).ok_or(STATUS_INVALID_HANDLE)?;
        let record = &mut self.records[id.index as usize];
        if record.owner != Some(owner) {
            return Err(STATUS_INVALID_HANDLE);
        }
        record.is_icon = data.is_icon != 0;
        record.data = *data;
        Ok(())
    }

    /// The shared icon or cursor the process `owner` loaded from the module's resource at the
    /// size `width` by `height`: its handle.
    pub fn find_existing(
        &self,
        owner: Owner,
        module: u32,
        resource: u32,
        width: i32,
        height: i32,
    ) -> Option<u32> {
        (0..CURSORS)
            .find(|&index| {
                let record = &self.records[index];
                self.headers[index].live
                    && record.owner == Some(owner)
                    && record.data.shared != 0
                    && record.data.module == module
                    && record.data.resource == resource
                    && record.data.width == width
                    && record.data.height == height
            })
            .map(|index| self.records[index].handle)
    }

    /// Destroy every record of the process `owner`, at its end (its classes, which held some, gone
    /// first).
    pub fn destroy_owner(&mut self, owner: Owner) {
        for index in 0..CURSORS {
            if self.headers[index].live && self.records[index].owner == Some(owner) {
                let id = CursorId {
                    index: index as u16,
                    generation: self.headers[index].generation,
                };
                self.destroy(id);
            }
        }
    }

    /// How many records processes hold.
    pub fn process_records(&self) -> usize {
        (0..CURSORS)
            .filter(|&index| self.headers[index].live && self.records[index].owner.is_some())
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

    /// NtUserFindExistingCursorIcon(Module, Resource, Size, Cursor): the shared icon the caller's
    /// process loaded from the module's resource (its data's address) at the size (the width in the
    /// low word, the height in the high) into `cursor`; 0 for none.
    pub fn find_existing_cursor_icon(
        call: &mut NtCall,
        module: u32,
        resource: u32,
        size: u32,
        cursor: UserPtr<u32>,
    ) -> NtResult {
        let owner = gui_thread(call)?.owner;
        let (width, height) = (i32::from(size as u16), i32::from((size >> 16) as u16));
        let found = with_manager(call.passive(), |m| {
            m.classes
                .cursors
                .find_existing(owner, module, resource, width, height)
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
            m.classes.cursors.set_data(owner, cursor.raw(), &data)
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
        _: UserPtr<u32>,
    ) -> NtResult {
        Err(STATUS_NOT_IMPLEMENTED)
    }

    pub fn set_cursor_icon_data(_: &mut NtCall, _: Handle, _: UserAddr) -> NtResult {
        Err(STATUS_NOT_IMPLEMENTED)
    }
}

pub use services::{find_existing_cursor_icon, set_cursor_icon_data};

#[cfg(test)]
mod tests {
    use std::boxed::Box;

    use super::*;

    const OWNER: Owner = 3;

    fn table() -> Box<CursorTable> {
        let mut boxed = Box::<CursorTable>::new_uninit();
        // SAFETY: the box's memory, valid and aligned, written whole before it is assumed.
        unsafe {
            CursorTable::write_empty(boxed.as_mut_ptr());
            boxed.assume_init()
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

    /// LoadIcon's records: made empty, filled in, found again by resource and size, the process's
    /// own; gone at its end.
    #[test]
    fn shared_icons_are_found_again() {
        let mut t = table();
        let handle = t.create_empty(OWNER).unwrap();
        assert_eq!(t.process_records(), 1);
        t.set_data(OWNER, handle, &icon(0x40_0000, 0x40_A000))
            .unwrap();
        assert_eq!(
            t.set_data(OWNER + 1, handle, &icon(1, 2)),
            Err(STATUS_INVALID_HANDLE)
        );
        assert_eq!(
            t.find_existing(OWNER, 0x40_0000, 0x40_A000, 32, 32),
            Some(handle)
        );
        assert_eq!(t.find_existing(OWNER, 0x40_0000, 0x40_A000, 16, 16), None);
        assert_eq!(
            t.find_existing(OWNER + 1, 0x40_0000, 0x40_A000, 32, 32),
            None
        );
        let id = t.validate(handle).unwrap();
        assert!(t.is_icon(id));
        let (secret, _) = t.make(true, true).unwrap();
        t.destroy_owner(OWNER);
        assert_eq!(t.validate(handle), None);
        assert_eq!(t.process_records(), 0);
        assert!(
            t.validate(t.handle_of(Some(secret))).is_some(),
            "the class registry's own"
        );
        assert_eq!(t.validate(4), None, "no window's handle");
    }
}
