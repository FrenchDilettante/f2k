//! The section services: NtCreateSection, NtOpenSection, NtMapViewOfSection and
//! NtUnmapViewOfSection. kernel32's CreateFileMappingA, OpenFileMappingA, MapViewOfFile and
//! UnmapViewOfFile are Win32 code over these, as on Windows 2000.
//!
//! A section is of the paging file (no file handle): a file's comes with the file objects, and
//! until then a file handle is STATUS_NOT_IMPLEMENTED. A section owns its frames
//! (`mem::vm::SectionFrames`), made zeroed as views first need them, and every view maps them, so
//! a write through one view shows in all of them; a PAGE_WRITECOPY view maps them copy-on-write,
//! its writes its own. A view is a reservation of its own in the process's address space
//! (MEM_MAPPED), on the 64 KiB allocation granularity. A section is an object (see [`crate::ob`]),
//! named in `\BaseNamedObjects` through the shared create and open (`nt::sync`): it lives while a
//! handle or a view references it, its frames while it or a view holds them.
//!
//! A view's protection needs the section handle's access, as Windows 2000 checks it when it
//! references the handle (SECTION_MAP_WRITE for a read-write view, SECTION_MAP_READ for the others:
//! STATUS_ACCESS_DENIED), and a read-write view needs a section made read-write
//! (STATUS_SECTION_PROTECTION). Data sections only: SEC_IMAGE is not supported.

use super::call::Status;
use super::memory::{STATUS_INVALID_PAGE_PROTECTION, STATUS_INVALID_PARAMETER_4};

pub const STATUS_ACCESS_DENIED: Status = Status(0xC000_0022);
const STATUS_NOT_IMPLEMENTED: Status = Status(0xC000_0002);
const STATUS_NOT_MAPPED_VIEW: Status = Status(0xC000_0019);
const STATUS_INVALID_VIEW_SIZE: Status = Status(0xC000_001F);
const STATUS_SECTION_TOO_BIG: Status = Status(0xC000_0040);
const STATUS_SECTION_PROTECTION: Status = Status(0xC000_004E);
const STATUS_INVALID_PARAMETER_6: Status = Status(0xC000_00F4);
const STATUS_INVALID_PARAMETER_8: Status = Status(0xC000_00F6);
const STATUS_INVALID_PARAMETER_9: Status = Status(0xC000_00F7);
const STATUS_MAPPED_ALIGNMENT: Status = Status(0xC000_0220);

/// The page protections a section and a view take.
const PAGE_NOACCESS: u32 = 0x01;
const PAGE_READONLY: u32 = 0x02;
const PAGE_READWRITE: u32 = 0x04;
const PAGE_WRITECOPY: u32 = 0x08;

/// NtCreateSection's allocation attributes.
const SEC_FILE: u32 = 0x0080_0000;
const SEC_IMAGE: u32 = 0x0100_0000;
const SEC_RESERVE: u32 = 0x0400_0000;
const SEC_COMMIT: u32 = 0x0800_0000;
const SEC_NOCACHE: u32 = 0x1000_0000;

/// NtMapViewOfSection's inherit dispositions, and the allocation types it takes: top-down (a hint,
/// never honored) and SEC_NO_CHANGE (the view's protection fixed; not enforced).
const VIEW_SHARE: u32 = 1;
const VIEW_UNMAP: u32 = 2;
const MEM_TOP_DOWN: u32 = 0x10_0000;
const SEC_NO_CHANGE: u32 = 0x40_0000;

/// The section access rights a view's protection needs, and the generic rights' mapping onto them.
const SECTION_QUERY: u32 = 0x0001;
const SECTION_MAP_WRITE: u32 = 0x0002;
const SECTION_MAP_READ: u32 = 0x0004;
const SECTION_MAP_EXECUTE: u32 = 0x0008;
const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const GENERIC_EXECUTE: u32 = 0x2000_0000;
const GENERIC_ALL: u32 = 0x1000_0000;
const MAXIMUM_ALLOWED: u32 = 0x0200_0000;

/// The allocation granularity: views start on it, and view offsets are multiples of it.
const GRANULARITY: u32 = crate::mem::vm::GRANULARITY;

/// What a section's creation settles on: its size, and whether its views may write it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Plan {
    pub size: u32,
    pub writable: bool,
}

/// NtCreateSection's rules, over the maximum size asked for, the page protection, the allocation
/// attributes and whether a file was named. The paging file's section needs a size (zero or none:
/// STATUS_INVALID_PARAMETER_4); a file's is not served yet (STATUS_NOT_IMPLEMENTED). A
/// section's frames are named within what its frame tables can hold
/// (STATUS_SECTION_TOO_BIG past it).
pub fn plan(maximum: Option<u64>, protect: u32, allocation: u32, file: bool) -> Result<Plan, Status> {
    if allocation & !(SEC_FILE | SEC_IMAGE | SEC_RESERVE | SEC_COMMIT | SEC_NOCACHE) != 0
        || allocation & (SEC_IMAGE | SEC_RESERVE | SEC_COMMIT) == 0
        || allocation & (SEC_RESERVE | SEC_COMMIT) == SEC_RESERVE | SEC_COMMIT
    {
        return Err(STATUS_INVALID_PARAMETER_6);
    }
    if allocation & SEC_IMAGE != 0 {
        return Err(STATUS_NOT_IMPLEMENTED);
    }
    let writable = match protect {
        PAGE_READONLY | PAGE_WRITECOPY => false,
        PAGE_READWRITE => true,
        _ => return Err(STATUS_INVALID_PAGE_PROTECTION),
    };
    if file {
        return Err(STATUS_NOT_IMPLEMENTED);
    }
    let size = match maximum.filter(|&size| size != 0) {
        None => return Err(STATUS_INVALID_PARAMETER_4),
        Some(size) if size > u32::MAX as u64 => return Err(STATUS_INVALID_PARAMETER_4),
        Some(size) => size as u32,
    };
    if size as u64 > crate::mem::vm::SECTION_MAX {
        return Err(STATUS_SECTION_TOO_BIG);
    }
    Ok(Plan { size, writable })
}

/// The section access a handle's granted access amounts to, its generic rights mapped as the
/// section type maps them.
fn section_access(access: u32) -> u32 {
    let mut granted = access & 0x00FF_FFFF;
    if access & (GENERIC_ALL | MAXIMUM_ALLOWED) != 0 {
        granted |= crate::ob::SECTION_ALL_ACCESS;
    }
    if access & GENERIC_READ != 0 {
        granted |= SECTION_QUERY | SECTION_MAP_READ;
    }
    if access & GENERIC_WRITE != 0 {
        granted |= SECTION_MAP_WRITE;
    }
    if access & GENERIC_EXECUTE != 0 {
        granted |= SECTION_MAP_EXECUTE;
    }
    granted
}

/// A view of `bytes` (zero: to the section's end) from `offset`, at `base` (zero: anywhere), with
/// `protect`, of a section of `size` bytes, `writable` or not, through a handle granted `access`:
/// the view's size in bytes. NtMapViewOfSection's rules.
pub fn view(
    access: u32,
    protect: u32,
    size: u32,
    writable: bool,
    base: u32,
    offset: u64,
    bytes: u32,
) -> Result<u32, Status> {
    let needs = if protect == PAGE_READWRITE {
        SECTION_MAP_WRITE
    } else {
        SECTION_MAP_READ
    };
    if section_access(access) & needs == 0 {
        return Err(STATUS_ACCESS_DENIED);
    }
    if protect == PAGE_READWRITE && !writable {
        return Err(STATUS_SECTION_PROTECTION);
    }
    if offset % GRANULARITY as u64 != 0 || base % GRANULARITY != 0 {
        return Err(STATUS_MAPPED_ALIGNMENT);
    }
    if offset >= size as u64 {
        return Err(STATUS_INVALID_VIEW_SIZE);
    }
    let rest = size - offset as u32;
    match bytes {
        0 => Ok(rest),
        bytes if bytes > rest => Err(STATUS_INVALID_VIEW_SIZE),
        bytes => Ok(bytes),
    }
}

/// NtMapViewOfSection's own argument checks, before the handle is looked at: the inherit
/// disposition, the allocation type and the view's protection.
pub fn view_arguments(inherit: u32, allocation: u32, protect: u32) -> Result<(), Status> {
    if inherit != VIEW_SHARE && inherit != VIEW_UNMAP {
        return Err(STATUS_INVALID_PARAMETER_8);
    }
    if allocation & !(MEM_TOP_DOWN | SEC_NO_CHANGE) != 0 {
        return Err(STATUS_INVALID_PARAMETER_9);
    }
    if !matches!(
        protect,
        PAGE_NOACCESS | PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY
    ) {
        return Err(STATUS_INVALID_PAGE_PROTECTION);
    }
    Ok(())
}

/// Map `pages` pages of `frames` from section page `first` at `base` (a fresh view reservation of
/// `space`) with `protect`, each made zeroed when no view needed it yet. ERROR_NOT_ENOUGH_MEMORY
/// without a frame: the caller releases the reservation, and the pages mapped so far with it.
pub fn map_frames(
    space: &mut crate::mem::vm::AddressSpace,
    pages: &mut impl crate::mem::vm::Pages,
    frames: &mut crate::mem::vm::SectionFrames,
    base: u32,
    first: u32,
    count: u32,
    protect: u32,
) -> Result<(), crate::mem::vm::VmError> {
    use crate::mem::vm::PAGE;
    for page in 0..count {
        let frame = frames.frame(pages, first + page, |_| ())?;
        space.map_shared(pages, base + page * PAGE, frame, protect)?;
    }
    Ok(())
}

#[cfg(target_arch = "x86")]
pub use target::*;

#[cfg(target_arch = "x86")]
mod target {
    use super::*;
    use crate::mem::vm::{CurrentPages, Kind, PAGE};
    use crate::nt::call::{
        calling_process, Handle, NtCall, NtResult, UserAddr, UserPtr, STATUS_INVALID_HANDLE,
        STATUS_SUCCESS,
    };
    use crate::nt::memory::{
        capture, with_space, STATUS_CONFLICTING_ADDRESSES, STATUS_INVALID_PARAMETER_2,
        STATUS_NO_MEMORY,
    };
    use crate::nt::object::is_console_handle;
    use crate::nt::sync;
    use crate::ob::{self, ObjectId, ObjectType};

    /// A section is gone: it drops its hold on its frames.
    pub fn release_frames(mut frames: crate::mem::vm::SectionFrames) {
        frames.release(&mut CurrentPages);
    }

    /// NtCreateSection (see [`plan`]): a section of the paging file, named or not (see `sync`'s
    /// create). Its frames are made as views need them.
    #[allow(clippy::too_many_arguments)]
    pub fn create_section(
        _call: &mut NtCall,
        slot: UserPtr<u32>,
        access: u32,
        attributes: UserAddr,
        maximum: UserPtr<u64>,
        protect: u32,
        allocation: u32,
        file: Handle,
    ) -> NtResult {
        let maximum = if maximum.is_null() {
            None
        } else {
            Some(maximum.read()?)
        };
        let plan = plan(maximum, protect, allocation, file.raw() != 0)?;
        let section = ob::SectionObject {
            size: plan.size,
            writable: plan.writable,
            ..ob::SectionObject::none()
        };
        sync::create(slot, access, attributes, ObjectType::Section, || {
            ob::directory().create_section(section)
        })
    }

    /// NtOpenSection: a new handle to the live section the name binds (see `sync`'s open).
    pub fn open_section(
        _call: &mut NtCall,
        slot: UserPtr<u32>,
        access: u32,
        attributes: UserAddr,
    ) -> NtResult {
        sync::open(slot, access, attributes, ObjectType::Section)
    }

    /// The section a handle names, referenced, with the access the handle was granted.
    fn section_of(handle: u32) -> Result<(ob::ObRef, u32), Status> {
        if is_console_handle(handle) {
            return Err(STATUS_INVALID_HANDLE);
        }
        let entry = calling_process()
            .handles()
            .lookup(handle)
            .ok_or(STATUS_INVALID_HANDLE)?;
        let id = entry.object_id().ok_or(STATUS_INVALID_HANDLE)?;
        if id.kind != ObjectType::Section {
            return Err(crate::nt::attributes::STATUS_OBJECT_TYPE_MISMATCH);
        }
        Ok((ob::reference(id).ok_or(STATUS_INVALID_HANDLE)?, entry.access))
    }

    /// NtMapViewOfSection (see [`view`]): a view of the section in the calling process, at the base
    /// asked for or anywhere, its pages the section's frames (made zeroed when no view needed them
    /// yet) — read-write for PAGE_READWRITE, copy-on-write for PAGE_WRITECOPY, read-only or
    /// no-access otherwise. The base, the offset and the view's size (whole pages) written back. The
    /// commit size is not used (a view's pages are all committed).
    #[allow(clippy::too_many_arguments)]
    pub fn map_view_of_section(
        call: &mut NtCall,
        section: Handle,
        process: Handle,
        base: UserPtr<u32>,
        _zero_bits: u32,
        _commit_size: u32,
        offset: UserPtr<u64>,
        size: UserPtr<u32>,
        inherit: u32,
        allocation: u32,
        protect: u32,
    ) -> NtResult {
        view_arguments(inherit, allocation, protect)?;
        let requested = capture(base)?;
        let at = if offset.is_null() {
            0
        } else {
            let at = offset.read()?;
            offset.write(at)?;
            at
        };
        let length = capture(size)?;
        let (object, access) = section_of(section.raw())?;
        let record = *object.section();
        let bytes = view(
            access,
            protect,
            record.size,
            record.writable,
            requested,
            at,
            length,
        )?;
        let mapped = with_space(call, process, |space, pages| {
            map_view(space, pages, object.id(), requested, at as u32, bytes, protect)
        })?;
        base.write(mapped)?;
        size.write(bytes.next_multiple_of(PAGE))?;
        Ok(STATUS_SUCCESS)
    }

    /// Map `bytes` of the section `object` names from `offset` as a reservation of its own (at
    /// `requested`, or the lowest free range), its pages the section's frames.
    fn map_view(
        space: &mut crate::mem::vm::AddressSpace,
        table: &mut CurrentPages,
        object: ObjectId,
        requested: u32,
        offset: u32,
        bytes: u32,
        protect: u32,
    ) -> Result<u32, Status> {
        if !space.has_view_room() {
            return Err(STATUS_NO_MEMORY);
        }
        let directory = ob::directory();
        let section = directory
            .section(object)
            .expect("the caller holds the section");
        let pages = bytes.div_ceil(PAGE);
        let section_protect = if section.writable {
            PAGE_READWRITE
        } else {
            PAGE_READONLY
        };
        let base = space
            .reserve(
                (requested != 0).then_some(requested),
                pages * PAGE,
                section_protect,
                Kind::Mapped,
            )
            .map_err(|error| match error {
                crate::mem::vm::VmError::InvalidAddress => STATUS_CONFLICTING_ADDRESSES,
                crate::mem::vm::VmError::InvalidParameter => STATUS_INVALID_PARAMETER_2,
                crate::mem::vm::VmError::NoMemory => STATUS_NO_MEMORY,
            })?;
        let mapped = map_frames(
            space,
            table,
            &mut section.frames,
            base,
            offset / PAGE,
            pages,
            protect,
        );
        if mapped.is_err() {
            let _ = space.release(table, base);
            return Err(STATUS_NO_MEMORY);
        }
        let recorded = space.add_view(base, object);
        debug_assert!(recorded, "the view table had room");
        // The view holds its section for as long as it is mapped.
        let held = directory.reference(object);
        debug_assert!(held, "a section being mapped lives");
        Ok(base)
    }

    /// NtUnmapViewOfSection: unmap the view holding the address — any address inside it names it,
    /// as on Windows 2000 — (a section nothing names any more goes with its last view);
    /// STATUS_NOT_MAPPED_VIEW for an address no view holds.
    pub fn unmap_view_of_section(call: &mut NtCall, process: Handle, address: UserAddr) -> NtResult {
        let object = with_space(call, process, |space, pages| {
            let base = space
                .region_at(address.raw())
                .filter(|region| region.kind == Kind::Mapped)
                .ok_or(STATUS_NOT_MAPPED_VIEW)?
                .base;
            let object = space.take_view(base).ok_or(STATUS_NOT_MAPPED_VIEW)?;
            let _ = space.release(pages, base);
            Ok(object)
        })?;
        // The view's reference goes; a section nothing else references goes with it.
        ob::release(object);
        Ok(STATUS_SUCCESS)
    }
}

#[cfg(not(target_arch = "x86"))]
pub use host::*;

/// The host builds' section services (see `nt::unserved`): they run against the target's object
/// manager and address space.
#[cfg(not(target_arch = "x86"))]
mod host {
    use crate::nt::call::{Handle, NtCall, NtResult, UserAddr, UserPtr};

    /// A section is gone: the host has no frames to give back.
    pub fn release_frames(_frames: crate::mem::vm::SectionFrames) {}

    unserved! {
        create_section(UserPtr<u32>, u32, UserAddr, UserPtr<u64>, u32, u32, Handle);
        open_section(UserPtr<u32>, u32, UserAddr);
        map_view_of_section(Handle, Handle, UserPtr<u32>, u32, u32, UserPtr<u64>, UserPtr<u32>, u32, u32, u32);
        unmap_view_of_section(Handle, UserAddr);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn error<T: core::fmt::Debug>(result: Result<T, Status>) -> u32 {
        rtl::status::dos_error(result.expect_err("the call fails").0)
    }

    /// The paging file's sections (memory/mapping's): a read-write one of a size; the refusals map
    /// to the errors the captures print. A file's section is not served yet.
    #[test]
    fn the_section_rules() {
        let commit = SEC_COMMIT;
        assert_eq!(
            plan(Some(0x10_0000), PAGE_READWRITE, commit, false),
            Ok(Plan {
                size: 0x10_0000,
                writable: true
            })
        );
        assert_eq!(
            plan(Some(0x1000), PAGE_WRITECOPY, SEC_RESERVE, false).map(|plan| plan.writable),
            Ok(false)
        );
        assert_eq!(
            error(plan(None, PAGE_READWRITE, commit, false)),
            87,
            "the paging file needs a size"
        );
        assert_eq!(error(plan(Some(0), PAGE_READWRITE, commit, false)), 87);
        assert_eq!(
            error(plan(Some(0x1000), 0x10, commit, false)),
            87,
            "PAGE_EXECUTE"
        );
        assert_eq!(
            error(plan(Some(0x1000), PAGE_READONLY, 0, false)),
            87,
            "no allocation attribute"
        );
        assert_eq!(
            error(plan(Some(0x1000), PAGE_READONLY, SEC_RESERVE | SEC_COMMIT, false)),
            87
        );
        assert_eq!(error(plan(Some(1 << 32), PAGE_READWRITE, commit, false)), 87);
        assert_eq!(
            plan(Some(0x1000), PAGE_READONLY, commit, true),
            Err(STATUS_NOT_IMPLEMENTED),
            "a file's section is not served yet"
        );
        assert_eq!(
            plan(Some(0x1000), PAGE_READONLY, SEC_IMAGE, false),
            Err(STATUS_NOT_IMPLEMENTED)
        );
        assert_eq!(
            error(plan(Some(crate::mem::vm::SECTION_MAX + 1), PAGE_READWRITE, commit, false)),
            8
        );
    }

    /// The views' refusals: a read-write view needs SECTION_MAP_WRITE (ERROR_ACCESS_DENIED) and a
    /// read-write section; offsets are on the granularity (ERROR_MAPPED_ALIGNMENT); a view stays
    /// inside the section.
    #[test]
    fn the_view_rules() {
        let read_only_handle = 0x000F_0005;
        assert_eq!(
            error(view(read_only_handle, PAGE_READWRITE, 0x2_0000, false, 0, 0, 0)),
            5
        );
        assert_eq!(
            view(read_only_handle, PAGE_READONLY, 0x2_0000, false, 0, 0, 0),
            Ok(0x2_0000)
        );
        assert_eq!(
            view(read_only_handle, PAGE_READONLY, 0x2_0000, false, 0, 0x1_0000, 1000),
            Ok(1000)
        );
        assert_eq!(
            error(view(read_only_handle, PAGE_READONLY, 0x2_0000, false, 0, 0x1000, 1000)),
            1132
        );
        assert_eq!(
            error(view(
                crate::ob::SECTION_ALL_ACCESS,
                PAGE_READWRITE,
                0x2_0000,
                false,
                0,
                0,
                0
            )),
            87
        );
        assert_eq!(
            error(view(read_only_handle, PAGE_READONLY, 0x2_0000, false, 0, 0x2_0000, 0)),
            5,
            "past the end"
        );
        assert_eq!(
            error(view(read_only_handle, PAGE_READONLY, 0x2_0000, false, 0, 0x1_0000, 0x1_0001)),
            5
        );
        assert_eq!(
            view(GENERIC_WRITE, PAGE_READWRITE, 0x1000, true, 0, 0, 0),
            Ok(0x1000),
            "generic rights map"
        );
        assert_eq!(
            error(view(SECTION_QUERY, PAGE_READONLY, 0x1000, true, 0, 0, 0)),
            5
        );
        assert_eq!(
            view(SECTION_QUERY | SECTION_MAP_READ, PAGE_WRITECOPY, 0x1000, true, 0, 0, 0),
            Ok(0x1000),
            "a copy-on-write view reads the section"
        );
        assert_eq!(error(view_arguments(0, 0, PAGE_READONLY)), 87);
        assert_eq!(error(view_arguments(VIEW_SHARE, 0x1000, PAGE_READONLY)), 87);
        assert_eq!(error(view_arguments(VIEW_SHARE, 0, 0x40)), 87);
        assert_eq!(view_arguments(VIEW_UNMAP, MEM_TOP_DOWN, PAGE_NOACCESS), Ok(()));
    }
}
