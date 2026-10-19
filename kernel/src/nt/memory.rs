//! The virtual-memory services: NtAllocateVirtualMemory, NtFreeVirtualMemory,
//! NtProtectVirtualMemory and NtQueryVirtualMemory, over the calling process's address space
//! (`mem::vm`), answering Windows 2000's statuses. kernel32's VirtualAlloc, VirtualFree,
//! VirtualProtect and VirtualQuery are Win32 code over these, as on Windows 2000.
//!
//! Only the calling process's own space is served: its pseudo-handle (NtCurrentProcess, -1) or a
//! handle to its object (there is no other process to name). The address and size arguments are in/out,
//! as on Windows 2000: probed for writing before the call acts, and the base and the size the call
//! settled on written back. The rules are functions over an [`AddressSpace`] and its [`Pages`]
//! (host-tested); the services move their arguments through user memory.

use super::call::{
    Handle, NtCall, NtResult, Status, UserAddr, UserPtr, STATUS_INVALID_HANDLE,
    STATUS_INVALID_PARAMETER, STATUS_SUCCESS,
};
use crate::mem::vm::{
    self, AddressSpace, Kind, Pages, VmError, MEM_COMMIT, MEM_RESERVE, PAGE, USER_HIGH,
};

pub const STATUS_INVALID_INFO_CLASS: Status = Status(0xC000_0003);
pub const STATUS_INFO_LENGTH_MISMATCH: Status = Status(0xC000_0004);
pub const STATUS_NO_MEMORY: Status = Status(0xC000_0017);
pub const STATUS_CONFLICTING_ADDRESSES: Status = Status(0xC000_0018);
const STATUS_NOT_COMMITTED: Status = Status(0xC000_002D);
pub const STATUS_INVALID_PAGE_PROTECTION: Status = Status(0xC000_0045);
const STATUS_FREE_VM_NOT_AT_BASE: Status = Status(0xC000_009F);
const STATUS_MEMORY_NOT_ALLOCATED: Status = Status(0xC000_00A0);
pub const STATUS_INVALID_PARAMETER_2: Status = Status(0xC000_00F0);
const STATUS_INVALID_PARAMETER_3: Status = Status(0xC000_00F1);
pub const STATUS_INVALID_PARAMETER_4: Status = Status(0xC000_00F2);
const STATUS_INVALID_PARAMETER_5: Status = Status(0xC000_00F3);

/// NtAllocateVirtualMemory's other allocation types: allocate top-down (taken as a hint, never
/// honored), and reset (the pages' contents no longer matter; nothing to do without a paging file).
const MEM_TOP_DOWN: u32 = 0x10_0000;
const MEM_RESET: u32 = 0x8_0000;
/// NtFreeVirtualMemory's operations.
const MEM_DECOMMIT: u32 = 0x4000;
const MEM_RELEASE: u32 = 0x8000;

/// MemoryBasicInformation, and its structure's size.
const MEMORY_BASIC_INFORMATION: u32 = 0;
const MEMORY_BASIC_INFORMATION_SIZE: u32 = 28;

/// The first page of `address`, and the end of the pages `[address, address + size)` covers.
fn page_span(address: u32, size: u32) -> (u32, u64) {
    let start = address & !(PAGE - 1);
    (
        start,
        (address as u64 + size as u64).next_multiple_of(PAGE as u64),
    )
}

/// NtAllocateVirtualMemory's rules: a reservation (committed whole when MEM_COMMIT rides along),
/// or a commit inside a private one (a commit without an address reserves too). The base and the
/// size the call settled on: the reservation's, or the committed pages'.
pub fn allocate(
    space: &mut AddressSpace,
    pages: &mut impl Pages,
    address: u32,
    size: u32,
    kind: u32,
    protect: u32,
) -> Result<(u32, u32), Status> {
    let known = MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN | MEM_RESET;
    if kind & !known != 0 || kind & (MEM_COMMIT | MEM_RESERVE) == 0 {
        return Err(STATUS_INVALID_PARAMETER_5);
    }
    if !vm::valid_protect(protect) {
        return Err(STATUS_INVALID_PAGE_PROTECTION);
    }
    if address >= USER_HIGH {
        return Err(STATUS_INVALID_PARAMETER_2);
    }
    if size == 0 {
        return Err(STATUS_INVALID_PARAMETER_4);
    }
    let refused = |error| match error {
        VmError::InvalidAddress => STATUS_CONFLICTING_ADDRESSES,
        VmError::InvalidParameter => STATUS_INVALID_PARAMETER_2,
        VmError::NoMemory => STATUS_NO_MEMORY,
    };
    if kind & MEM_RESERVE != 0 || address == 0 {
        let base = space
            .reserve(
                (address != 0).then_some(address),
                size,
                protect,
                Kind::Private,
            )
            .map_err(refused)?;
        let region = space.region_at(base).expect("just reserved");
        if kind & MEM_COMMIT != 0 {
            if let Err(error) = space.commit(pages, base, region.size, protect) {
                let _ = space.release(pages, base);
                return Err(refused(error));
            }
        }
        return Ok((base, region.size));
    }
    match space.region_at(address) {
        Some(region) if region.kind == Kind::Private => {}
        _ => return Err(STATUS_CONFLICTING_ADDRESSES),
    }
    let start = space
        .commit(pages, address, size, protect)
        .map_err(refused)?;
    let (_, end) = page_span(address, size);
    Ok((start, (end - start as u64) as u32))
}

/// NtFreeVirtualMemory's rules: a release names a private region's base with no size; a decommit
/// any pages of one (no size: the whole region, from its base). The base and the size released or
/// decommitted. A view or an image is not private memory: as an address no allocation holds, it is
/// STATUS_MEMORY_NOT_ALLOCATED.
pub fn free(
    space: &mut AddressSpace,
    pages: &mut impl Pages,
    address: u32,
    size: u32,
    kind: u32,
) -> Result<(u32, u32), Status> {
    if kind != MEM_RELEASE && kind != MEM_DECOMMIT {
        return Err(STATUS_INVALID_PARAMETER_4);
    }
    // A release frees a whole reservation: no partial releases (kernel32 refuses a size with
    // MEM_RELEASE before the call, as Windows 2000's does).
    if kind == MEM_RELEASE && size != 0 {
        return Err(STATUS_INVALID_PARAMETER_3);
    }
    let region = space
        .region_at(address)
        .ok_or(STATUS_MEMORY_NOT_ALLOCATED)?;
    if region.kind != Kind::Private {
        return Err(STATUS_MEMORY_NOT_ALLOCATED);
    }
    if size == 0 {
        if region.base != address {
            return Err(STATUS_FREE_VM_NOT_AT_BASE);
        }
        if kind == MEM_RELEASE {
            space
                .release(pages, address)
                .map_err(|_| STATUS_MEMORY_NOT_ALLOCATED)?;
        } else {
            space
                .decommit(pages, address, 0)
                .map_err(|_| STATUS_MEMORY_NOT_ALLOCATED)?;
        }
        return Ok((region.base, region.size));
    }
    space
        .decommit(pages, address, size)
        .map_err(|_| STATUS_MEMORY_NOT_ALLOCATED)?;
    let (start, end) = page_span(address, size);
    Ok((start, (end - start as u64) as u32))
}

/// NtProtectVirtualMemory's rules: a valid protection over committed pages of one region. The
/// first page, the span's size, and the first page's old protection. Pages outside every region
/// are STATUS_CONFLICTING_ADDRESSES, reserved ones STATUS_NOT_COMMITTED.
pub fn protect(
    space: &mut AddressSpace,
    pages: &mut impl Pages,
    address: u32,
    size: u32,
    protect: u32,
) -> Result<(u32, u32, u32), Status> {
    if !vm::valid_protect(protect) {
        return Err(STATUS_INVALID_PAGE_PROTECTION);
    }
    if address >= USER_HIGH {
        return Err(STATUS_INVALID_PARAMETER_2);
    }
    let (start, end) = page_span(address, size.max(1));
    match space.region_at(start) {
        Some(region) if end <= region.base as u64 + region.size as u64 => {}
        _ => return Err(STATUS_CONFLICTING_ADDRESSES),
    }
    let old = space
        .protect(pages, address, size, protect)
        .map_err(|_| STATUS_NOT_COMMITTED)?;
    Ok((start, (end - start as u64) as u32, old))
}

/// NtQueryVirtualMemory's rules: the application range only.
pub fn query(space: &AddressSpace, pages: &impl Pages, address: u32) -> Result<vm::Info, Status> {
    if address >= USER_HIGH {
        return Err(STATUS_INVALID_PARAMETER);
    }
    Ok(space.query(pages, address))
}

/// An in/out argument, probed for writing as the platform probes it (read, and written back)
/// before the call acts: its value.
pub fn capture(at: UserPtr<u32>) -> Result<u32, Status> {
    let value = at.read()?;
    at.write(value)?;
    Ok(value)
}

/// Run `body` over the calling process's address space and page tables; STATUS_INVALID_HANDLE for
/// a process handle naming another process, or nothing.
#[cfg(target_arch = "x86")]
pub fn with_space<R>(
    call: &mut NtCall,
    process: Handle,
    body: impl FnOnce(&mut AddressSpace, &mut vm::CurrentPages) -> Result<R, Status>,
) -> Result<R, Status> {
    if !super::object::names_current_process(process.raw()) {
        return Err(STATUS_INVALID_HANDLE);
    }
    body(call.process().vm(), &mut vm::CurrentPages)
}

/// Host builds have no process: the services run on the target only.
#[cfg(not(target_arch = "x86"))]
pub fn with_space<R>(
    _call: &mut NtCall,
    process: Handle,
    _body: impl FnOnce(&mut AddressSpace, &mut NoPages) -> Result<R, Status>,
) -> Result<R, Status> {
    let _ = process;
    Err(STATUS_INVALID_HANDLE)
}

#[cfg(not(target_arch = "x86"))]
pub struct NoPages;

#[cfg(not(target_arch = "x86"))]
impl Pages for NoPages {
    fn entry(&self, _va: u32) -> u32 {
        0
    }
    fn set_entry(&mut self, _va: u32, _entry: u32) {}
    fn zeroed_frame(&mut self) -> Option<u32> {
        None
    }
    fn free_frame(&mut self, _frame: u32) {}
    fn share_frame(&mut self, _frame: u32) {}
    fn frame_shared(&self, _frame: u32) -> bool {
        false
    }
    fn copy_frame(&mut self, _from: u32, _to: u32) {}
    fn frame_word(&self, _frame: u32, _index: u32) -> u32 {
        0
    }
    fn set_frame_word(&mut self, _frame: u32, _index: u32, _value: u32) {}
}

/// NtAllocateVirtualMemory (see [`allocate`]); the zero-bits constraint is not applied.
pub fn allocate_virtual_memory(
    call: &mut NtCall,
    process: Handle,
    base: UserPtr<u32>,
    _zero_bits: u32,
    size: UserPtr<u32>,
    kind: u32,
    protect: u32,
) -> NtResult {
    let (address, length) = (capture(base)?, capture(size)?);
    let (start, extent) = with_space(call, process, |space, pages| {
        allocate(space, pages, address, length, kind, protect)
    })?;
    base.write(start)?;
    size.write(extent)?;
    Ok(STATUS_SUCCESS)
}

/// NtFreeVirtualMemory (see [`free`]).
pub fn free_virtual_memory(
    call: &mut NtCall,
    process: Handle,
    base: UserPtr<u32>,
    size: UserPtr<u32>,
    kind: u32,
) -> NtResult {
    let (address, length) = (capture(base)?, capture(size)?);
    let (start, extent) = with_space(call, process, |space, pages| {
        free(space, pages, address, length, kind)
    })?;
    base.write(start)?;
    size.write(extent)?;
    Ok(STATUS_SUCCESS)
}

/// NtProtectVirtualMemory (see [`protect`]): the old protection into `old`, which is probed with
/// the in/out arguments before the protection changes.
pub fn protect_virtual_memory(
    call: &mut NtCall,
    process: Handle,
    base: UserPtr<u32>,
    size: UserPtr<u32>,
    new_protect: u32,
    old: UserPtr<u32>,
) -> NtResult {
    if !vm::valid_protect(new_protect) {
        return Err(STATUS_INVALID_PAGE_PROTECTION);
    }
    let (address, length) = (capture(base)?, capture(size)?);
    capture(old)?;
    let (start, extent, was) = with_space(call, process, |space, pages| {
        protect(space, pages, address, length, new_protect)
    })?;
    base.write(start)?;
    size.write(extent)?;
    old.write(was)?;
    Ok(STATUS_SUCCESS)
}

/// NtQueryVirtualMemory: MemoryBasicInformation of the page holding `address` (see [`query`]).
/// STATUS_INVALID_INFO_CLASS for another class, STATUS_INFO_LENGTH_MISMATCH for a buffer shorter
/// than the structure.
pub fn query_virtual_memory(
    call: &mut NtCall,
    process: Handle,
    address: u32,
    class: u32,
    information: UserAddr,
    length: u32,
    return_length: UserPtr<u32>,
) -> NtResult {
    if class != MEMORY_BASIC_INFORMATION {
        return Err(STATUS_INVALID_INFO_CLASS);
    }
    if length < MEMORY_BASIC_INFORMATION_SIZE {
        return Err(STATUS_INFO_LENGTH_MISMATCH);
    }
    let info = with_space(call, process, |space, pages| query(space, pages, address))?;
    information.write(&info.to_bytes())?;
    return_length.write_optional(MEMORY_BASIC_INFORMATION_SIZE)?;
    Ok(STATUS_SUCCESS)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    #[derive(Default)]
    struct Fake {
        entries: HashMap<u32, u32>,
        next: u32,
    }

    impl Pages for Fake {
        fn entry(&self, va: u32) -> u32 {
            self.entries.get(&va).copied().unwrap_or(0)
        }
        fn set_entry(&mut self, va: u32, entry: u32) {
            self.entries.insert(va, entry);
        }
        fn zeroed_frame(&mut self) -> Option<u32> {
            self.next += 1;
            Some(0x10_0000 + self.next * PAGE)
        }
        fn free_frame(&mut self, _frame: u32) {}
        fn share_frame(&mut self, _frame: u32) {}
        fn frame_shared(&self, _frame: u32) -> bool {
            false
        }
        fn copy_frame(&mut self, _from: u32, _to: u32) {}
        fn frame_word(&self, _frame: u32, _index: u32) -> u32 {
            0
        }
        fn set_frame_word(&mut self, _frame: u32, _index: u32, _value: u32) {}
    }

    /// The Win32 error a failure's status maps to (the error the memory fixture prints).
    fn error<T>(result: Result<T, Status>) -> u32 {
        match result {
            Ok(_) => panic!("the call succeeds"),
            Err(Status(status)) => rtl::status::dos_error(status),
        }
    }

    /// The memory fixture's invalid requests (memory/virtual): their statuses map to the errors
    /// the capture prints.
    #[test]
    fn the_captured_refusals() {
        let (mut space, mut pages) = (AddressSpace::new(), Fake::default());
        let rw = vm::PAGE_READWRITE;
        assert_eq!(
            allocate(&mut space, &mut pages, 0, 0, MEM_RESERVE, rw),
            Err(STATUS_INVALID_PARAMETER_4)
        );
        assert_eq!(
            error(allocate(&mut space, &mut pages, 0, 0, MEM_RESERVE, rw)),
            87
        );
        assert_eq!(
            allocate(&mut space, &mut pages, 0, 4096, MEM_RESERVE, 7),
            Err(STATUS_INVALID_PAGE_PROTECTION)
        );
        assert_eq!(
            error(allocate(&mut space, &mut pages, 0, 4096, MEM_RESERVE, 7)),
            87
        );
        assert_eq!(
            error(allocate(
                &mut space,
                &mut pages,
                0x8000_0000,
                4096,
                MEM_RESERVE,
                rw
            )),
            87
        );
        assert_eq!(
            error(allocate(
                &mut space,
                &mut pages,
                0x4000_0000,
                4096,
                MEM_COMMIT,
                rw
            )),
            487
        );
        assert_eq!(error(query(&space, &pages, 0x8000_0000)), 87);
        let (big, size) = allocate(&mut space, &mut pages, 0, 0x10_0000, MEM_RESERVE, rw).unwrap();
        assert_eq!(size, 0x10_0000);
        assert_eq!(
            error(free(&mut space, &mut pages, big + 0x1_0000, 0, MEM_RELEASE)),
            487,
            "not at the base"
        );
        assert_eq!(
            free(&mut space, &mut pages, big, 0, MEM_RELEASE),
            Ok((big, 0x10_0000))
        );
        assert_eq!(
            allocate(
                &mut space,
                &mut pages,
                0x2000_0000,
                0x1_0000,
                MEM_RESERVE,
                rw
            ),
            Ok((0x2000_0000, 0x1_0000))
        );
        assert_eq!(
            error(allocate(
                &mut space,
                &mut pages,
                0x2000_0000,
                0x1_0000,
                MEM_RESERVE,
                rw
            )),
            487
        );
        // A reservation with a commit at an unaligned address: the granularity's base, the region
        // to the last page the request touches.
        assert_eq!(
            allocate(
                &mut space,
                &mut pages,
                0x3000_1234,
                0x1000,
                MEM_RESERVE | MEM_COMMIT,
                rw
            ),
            Ok((0x3000_0000, 0x3000))
        );
    }

    /// A commit inside a reservation settles on the pages it covers; a decommit gives them back.
    #[test]
    fn commits_and_decommits_report_their_pages() {
        let (mut space, mut pages) = (AddressSpace::new(), Fake::default());
        let rw = vm::PAGE_READWRITE;
        let (base, _) = allocate(&mut space, &mut pages, 0, 0x10_0000, MEM_RESERVE, rw).unwrap();
        assert_eq!(
            allocate(
                &mut space,
                &mut pages,
                base + 0x1_0010,
                0x1000,
                MEM_COMMIT,
                rw
            ),
            Ok((base + 0x1_0000, 0x2000))
        );
        assert_eq!(
            query(&space, &pages, base + 0x1_0000).map(|info| (info.state, info.size)),
            Ok((MEM_COMMIT, 0x2000))
        );
        assert_eq!(
            free(
                &mut space,
                &mut pages,
                base + 0x1_0000,
                0x2000,
                MEM_DECOMMIT
            ),
            Ok((base + 0x1_0000, 0x2000))
        );
        assert_eq!(
            query(&space, &pages, base).map(|info| (info.state, info.size)),
            Ok((MEM_RESERVE, 0x10_0000))
        );
        assert_eq!(
            error(free(&mut space, &mut pages, base, 0x1000, MEM_RELEASE)),
            87,
            "a release takes no size"
        );
        assert_eq!(error(free(&mut space, &mut pages, base, 0, 0)), 87);
        assert_eq!(
            error(free(&mut space, &mut pages, 0x6000_0000, 0, MEM_RELEASE)),
            487,
            "nothing there"
        );
    }

    /// Protections (memory/protect): each change reports the old one; past the commit fails with
    /// the capture's 487.
    #[test]
    fn protections_report_the_old_one() {
        let (mut space, mut pages) = (AddressSpace::new(), Fake::default());
        let (p, _) = allocate(
            &mut space,
            &mut pages,
            0,
            0x3000,
            MEM_RESERVE | MEM_COMMIT,
            vm::PAGE_READWRITE,
        )
        .unwrap();
        assert_eq!(
            protect(&mut space, &mut pages, p, 0x1000, vm::PAGE_READONLY),
            Ok((p, 0x1000, vm::PAGE_READWRITE))
        );
        assert_eq!(
            query(&space, &pages, p).map(|info| info.protect),
            Ok(vm::PAGE_READONLY)
        );
        assert_eq!(
            protect(
                &mut space,
                &mut pages,
                p + 0x1800,
                0x1000,
                vm::PAGE_NOACCESS
            ),
            Ok((p + 0x1000, 0x2000, 4))
        );
        assert_eq!(
            protect(&mut space, &mut pages, p, 0x1_0000, vm::PAGE_READWRITE),
            Err(STATUS_CONFLICTING_ADDRESSES)
        );
        let (q, _) = allocate(
            &mut space,
            &mut pages,
            0,
            0x2000,
            MEM_RESERVE,
            vm::PAGE_READWRITE,
        )
        .unwrap();
        assert_eq!(
            protect(&mut space, &mut pages, q, 0x1000, vm::PAGE_READONLY),
            Err(STATUS_NOT_COMMITTED)
        );
        assert_eq!(
            error(protect(
                &mut space,
                &mut pages,
                q,
                0x1000,
                vm::PAGE_READONLY
            )),
            487
        );
        assert_eq!(
            error(protect(&mut space, &mut pages, p, 0x1000, 0x3)),
            87,
            "a bad protection"
        );
    }
}
